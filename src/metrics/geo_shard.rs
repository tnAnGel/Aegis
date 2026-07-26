//! Cross-worker GeoIP country aggregation (shard + merge-on-read).
//!
//! Under `SO_REUSEPORT` each worker process maintains its own
//! [`RuntimeMetrics::by_country`] DashMap, so any single worker only sees
//! the slice of requests the kernel happened to hand it. The dashboard
//! world-map + Top-Countries widget poll one worker's admin handler, so
//! the dot counts fluctuate poll-to-poll depending on which worker answers.
//!
//! This module applies the same shard+merge pattern the Site Map uses
//! (see [`crate::site_map`]): each worker acquires a slot via a
//! non-blocking advisory `flock` on `.slot-<n>.lock`, then periodically
//! writes its own `by_country` snapshot to `shard-<slot>.json`. The admin
//! read path (`top_countries`) reads **all** shards and sums totals/denied
//! per country, producing a stable aggregate regardless of which worker
//! answers — and surviving restarts because each worker reloads its own
//! shard at boot.
//!
//! Default directory: `/var/lib/aegis/geo` (override via `AEGIS_GEO_DIR`).

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

/// Max number of slot files probed when acquiring a worker slot. Matches
/// the Site Map's `MAX_SLOTS`; one slot per SO_REUSEPORT worker.
const MAX_SLOTS: u32 = 16;

/// Shards older than this (by `written_at_unix_secs` or file mtime) are
/// treated as orphaned writers and skipped on merge.
pub const SHARD_MAX_AGE_SECS: u64 = 900;

/// One country row as stored in / returned from a geo shard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CountryRow {
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// Total requests resolved to this country.
    pub total: u64,
    /// Subset of `total` that were denied.
    pub denied: u64,
    /// Subset of `total` that were challenged.
    pub challenged: u64,
}

/// Full per-worker geo snapshot serialised to `shard-<slot>.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoSnapshot {
    /// Unix timestamp when this snapshot was written. The merge skips
    /// shards whose writer has exited (stale timestamp).
    pub written_at_unix_secs: u64,
    pub countries: Vec<CountryRow>,
}

/// Per-worker geo persistence handle. Owned by `RuntimeMetrics` (in an
/// `Option`, `None` when persistence was never configured). Holds the
/// shard path and the advisory flock for the process lifetime.
pub struct GeoShard {
    /// Path to this worker's shard file, e.g. `…/shard-0.json`.
    shard_path: PathBuf,
    /// Holds the advisory flock on `.slot-<n>.lock`; dropping it releases
    /// the slot for the next worker. Kept alive for the process lifetime.
    #[allow(dead_code)]
    slot_lock: File,
}

impl GeoShard {
    /// Acquire a worker slot under `dir` and return a `GeoShard` bound to
    /// `shard-<slot>.json`. Creates `dir` if missing. Returns `None` (and
    /// logs a warning) when the directory can't be created or all
    /// `MAX_SLOTS` slots are occupied — in which case the caller runs
    /// without geo persistence (per-worker counters only).
    pub fn acquire(dir: PathBuf) -> Option<Self> {
        if let Err(e) = fs::create_dir_all(&dir) {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "geo_shard: cannot create shard directory — running without cross-worker aggregation"
            );
            return None;
        }
        match acquire_slot(&dir, MAX_SLOTS) {
            None => {
                tracing::warn!(
                    dir = %dir.display(),
                    "geo_shard: no free slot in {} tries — running without cross-worker aggregation",
                    MAX_SLOTS
                );
                None
            }
            Some((slot, lock_file)) => {
                let shard_path = dir.join(format!("shard-{slot}.json"));
                Some(Self {
                    shard_path,
                    slot_lock: lock_file,
                })
            }
        }
    }

    /// Path to this worker's shard file.
    pub fn shard_path(&self) -> &Path {
        &self.shard_path
    }

    /// Atomically write `snap` to this worker's shard file. Errors are
    /// logged as warnings — a failed flush never aborts serving.
    pub fn flush(&self, snap: &GeoSnapshot) {
        if let Err(e) = write_snapshot_to(&self.shard_path, snap) {
            tracing::warn!(
                path = %self.shard_path.display(),
                error = %e,
                "geo_shard: failed to flush shard"
            );
        }
    }

    /// Load this worker's own shard back (used at boot to restore counters
    /// across restarts). `None` when the file is missing or unparseable.
    pub fn load_own(&self) -> Option<GeoSnapshot> {
        load_shard_from(&self.shard_path)
    }
}

/// Merge all shards in `dir` into one country→row map (summing counters),
/// skipping shards older than `max_age_secs`. Used by the admin read path
/// so the aggregate is stable regardless of which worker answers. Returns
/// a map keyed by ISO country code.
pub fn merge_all_shards(dir: &Path, max_age_secs: u64) -> HashMap<String, CountryRow> {
    merge_all_shards_excluding(dir, Path::new(""), max_age_secs)
}

/// Like [`merge_all_shards`] but skips the shard file at `exclude` (used so
/// the owning worker can fold in its fresher in-memory counters separately
/// without double-counting its own on-disk shard). Pass an empty path to
/// exclude nothing.
pub fn merge_all_shards_excluding(
    dir: &Path,
    exclude: &Path,
    max_age_secs: u64,
) -> HashMap<String, CountryRow> {
    let cutoff = unix_now().saturating_sub(max_age_secs);
    let mut merged: HashMap<String, CountryRow> = HashMap::new();

    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return merged,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path == exclude {
            continue;
        }
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        if !name.starts_with("shard-") || !name.ends_with(".json") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                let mtime_secs = mtime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if mtime_secs < cutoff {
                    continue;
                }
            }
        }
        let Some(snap) = load_shard_from(&path) else {
            continue;
        };
        if snap.written_at_unix_secs < cutoff {
            continue;
        }
        for row in snap.countries {
            let e = merged
                .entry(row.country.clone())
                .or_insert_with(|| CountryRow {
                    country: row.country.clone(),
                    total: 0,
                    denied: 0,
                    challenged: 0,
                });
            e.total += row.total;
            e.denied += row.denied;
            e.challenged += row.challenged;
        }
    }
    merged
}

// ── Free functions: slot acquisition + disk I/O ─────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Try a non-blocking exclusive flock on `path`.
fn try_flock_nb(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .ok()?;
    let fd = file.as_raw_fd();
    // SAFETY: flock(2) is always safe to call with a valid fd.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 { Some(file) } else { None }
}

/// Probe `.slot-0.lock` .. `.slot-<max_slots-1>.lock`, returning the first
/// free slot index + its lock `File`. The caller MUST keep the `File` alive.
fn acquire_slot(dir: &Path, max_slots: u32) -> Option<(u32, File)> {
    for slot in 0..max_slots {
        let lock_path = dir.join(format!(".slot-{slot}.lock"));
        if let Some(f) = try_flock_nb(&lock_path) {
            return Some((slot, f));
        }
    }
    None
}

/// Deserialise a `GeoSnapshot` from `path`. `None` on any error.
fn load_shard_from(path: &Path) -> Option<GeoSnapshot> {
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Atomically write `snap` to `path` (tmp sibling + rename), perms 0o640.
fn write_snapshot_to(path: &Path, snap: &GeoSnapshot) -> std::io::Result<()> {
    let json = serde_json::to_string(snap).map_err(|e| std::io::Error::other(e))?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.flush()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cc: &str, total: u64, denied: u64) -> CountryRow {
        CountryRow {
            country: cc.to_string(),
            total,
            denied,
            challenged: 0,
        }
    }

    #[test]
    fn merge_sums_per_country_across_shards() {
        let dir = std::env::temp_dir().join(format!("aegis_geo_merge_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test dir");
        let now = unix_now();

        let a = GeoSnapshot {
            written_at_unix_secs: now,
            countries: vec![row("US", 10, 2), row("DE", 5, 1)],
        };
        let b = GeoSnapshot {
            written_at_unix_secs: now,
            countries: vec![row("US", 7, 3), row("FR", 4, 0)],
        };
        write_snapshot_to(&dir.join("shard-0.json"), &a).expect("write a");
        write_snapshot_to(&dir.join("shard-1.json"), &b).expect("write b");

        let merged = merge_all_shards(&dir, 900);
        assert_eq!(merged.get("US").unwrap().total, 17, "US totals summed");
        assert_eq!(merged.get("US").unwrap().denied, 5, "US denied summed");
        assert_eq!(merged.get("DE").unwrap().total, 5);
        assert_eq!(merged.get("FR").unwrap().total, 4);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_skips_stale_shards() {
        let dir = std::env::temp_dir().join(format!("aegis_geo_stale_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test dir");
        let now = unix_now();

        let fresh = GeoSnapshot {
            written_at_unix_secs: now,
            countries: vec![row("US", 10, 0)],
        };
        let stale = GeoSnapshot {
            written_at_unix_secs: now.saturating_sub(2000),
            countries: vec![row("CN", 99, 0)],
        };
        write_snapshot_to(&dir.join("shard-0.json"), &fresh).expect("write fresh");
        write_snapshot_to(&dir.join("shard-1.json"), &stale).expect("write stale");

        let merged = merge_all_shards(&dir, 900);
        assert!(merged.contains_key("US"), "fresh shard merged");
        assert!(
            !merged.contains_key("CN"),
            "stale shard (2000s old) skipped"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shard_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("aegis_geo_rt_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("shard-0.json");
        let snap = GeoSnapshot {
            written_at_unix_secs: 1234,
            countries: vec![row("US", 1, 0), row("DE", 2, 1)],
        };
        write_snapshot_to(&path, &snap).expect("write");
        let back = load_shard_from(&path).expect("read");
        assert_eq!(back.written_at_unix_secs, 1234);
        assert_eq!(back.countries.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
