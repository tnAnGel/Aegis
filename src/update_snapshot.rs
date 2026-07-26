//! V209 — Phase 2: pre-update snapshot + restore.
//!
//! Before any update is applied the [SnapshotManager] copies every
//! operator-owned config + daemon-managed state file to a
//! timestamped directory under `/var/lib/aegis/snapshots/`. If the
//! update fails (binary doesn't start, panel reports problem) the
//! operator can restore the snapshot atomically.
//!
//! ## What gets snapshotted
//!
//! | Path                                | Why |
//! |-------------------------------------|-----|
//! | `/etc/aegis/aegis.conf`             | Main config (DSL or TOML) |
//! | `/etc/aegis/sites-enabled/*.conf`   | Per-site configs |
//! | `/etc/aegis/aegis.env`              | systemd env file |
//! | `/etc/aegis/admin-token`            | Operator must NEVER lose this |
//! | `/etc/aegis/hmac-secret`            | Challenge token secret |
//! | `/etc/aegis/certs/*`                | TLS certs |
//! | `/var/lib/aegis/sites.d/*.conf`     | UI-managed site files |
//! | `/var/lib/aegis/web.json`           | Web admin state |
//! | `/var/lib/aegis/honeypots.json`     | Honeypot pack toggles |
//! | `/var/lib/aegis/runtime-toggles.json` | V160 filter on/off state |
//! | `/var/lib/aegis/domain-policy.json` | V162 per-domain overrides |
//!
//! Skipped: log files, training samples, mined-signatures cache —
//! reproducible / huge / churning.
//!
//! ## Layout
//!
//! ```text
//! /var/lib/aegis/snapshots/
//!   2026-05-22T12-00-00_pre-v0.2.0/
//!     manifest.json                 ← what was snapshotted, when, why
//!     etc/
//!       aegis.conf
//!       aegis.env
//!       admin-token
//!       hmac-secret
//!       sites-enabled/example.com.conf
//!       certs/...
//!     var/
//!       web.json
//!       honeypots.json
//!       runtime-toggles.json
//!       domain-policy.json
//!       sites.d/...
//! ```
//!
//! ## GC policy
//!
//! Keep last `keep_count` snapshots (default 5). When applying a new
//! snapshot the GC drops the oldest if over limit.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const DEFAULT_SNAPSHOT_ROOT: &str = "/var/lib/aegis/snapshots";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub created_at: String,
    pub created_at_unix: u64,
    pub reason: String,
    pub aegis_version: String,
    pub files: Vec<SnapshotFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub source: String,
    pub target_relative: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub id: String, // dir basename
    pub created_at_unix: u64,
    pub reason: String,
    pub aegis_version: String,
    pub file_count: usize,
    pub total_bytes: u64,
}

pub struct SnapshotManager {
    root: PathBuf,
    etc_dir: PathBuf,
    var_dir: PathBuf,
    keep_count: usize,
}

impl SnapshotManager {
    pub fn new(
        root: impl Into<PathBuf>,
        etc_dir: impl Into<PathBuf>,
        var_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            root: root.into(),
            etc_dir: etc_dir.into(),
            var_dir: var_dir.into(),
            keep_count: 5,
        }
    }

    pub fn with_keep_count(mut self, n: usize) -> Self {
        self.keep_count = n.max(1);
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create a new snapshot. Returns the snapshot ID (directory
    /// basename). `reason` is recorded in manifest.json for audit.
    pub fn create(&self, reason: impl Into<String>) -> io::Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("time"))?
            .as_secs();
        let reason = reason.into();
        let id = format!("{}_{}", iso_compact(now), slug(&reason));
        let target = self.root.join(&id);
        fs::create_dir_all(&target)?;

        let mut files = Vec::new();
        // /etc/aegis/* — copy each known file individually so we
        // don't snapshot e.g. a stray editor swapfile.
        let etc_paths = &["aegis.conf", "aegis.env", "admin-token", "hmac-secret"];
        for rel in etc_paths {
            let src = self.etc_dir.join(rel);
            if src.exists() {
                let dst = target.join("etc").join(rel);
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&src, &dst)?;
                files.push(SnapshotFile {
                    source: src.display().to_string(),
                    target_relative: format!("etc/{rel}"),
                    size: fs::metadata(&dst).map(|m| m.len()).unwrap_or(0),
                });
            }
        }
        // /etc/aegis/sites-enabled/*.conf — directory copy with
        // *.conf filter.
        copy_dir_filtered(
            &self.etc_dir.join("sites-enabled"),
            &target.join("etc/sites-enabled"),
            &["conf"],
            &mut files,
            "etc/sites-enabled",
        )?;
        copy_dir_filtered(
            &self.etc_dir.join("certs"),
            &target.join("etc/certs"),
            &["crt", "key", "pem"],
            &mut files,
            "etc/certs",
        )?;
        // /var/lib/aegis/* — state files daemon manages.
        let var_paths = &[
            "web.json",
            "honeypots.json",
            "runtime-toggles.json",
            "domain-policy.json",
        ];
        for rel in var_paths {
            let src = self.var_dir.join(rel);
            if src.exists() {
                let dst = target.join("var").join(rel);
                if let Some(parent) = dst.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&src, &dst)?;
                files.push(SnapshotFile {
                    source: src.display().to_string(),
                    target_relative: format!("var/{rel}"),
                    size: fs::metadata(&dst).map(|m| m.len()).unwrap_or(0),
                });
            }
        }
        copy_dir_filtered(
            &self.var_dir.join("sites.d"),
            &target.join("var/sites.d"),
            &["conf"],
            &mut files,
            "var/sites.d",
        )?;

        let manifest = SnapshotManifest {
            created_at: iso_long(now),
            created_at_unix: now,
            reason,
            aegis_version: env!("CARGO_PKG_VERSION").to_string(),
            files,
        };
        let manifest_path = target.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| io::Error::other(format!("manifest json: {e}")))?;
        fs::write(&manifest_path, manifest_json)?;

        // GC oldest if over keep_count.
        self.gc()?;
        Ok(id)
    }

    pub fn list(&self) -> io::Result<Vec<SnapshotEntry>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for e in fs::read_dir(&self.root)? {
            let e = e?;
            if !e.file_type()?.is_dir() {
                continue;
            }
            let id = e.file_name().to_string_lossy().to_string();
            let manifest_path = e.path().join("manifest.json");
            if let Ok(text) = fs::read_to_string(&manifest_path)
                && let Ok(m) = serde_json::from_str::<SnapshotManifest>(&text)
            {
                let total: u64 = m.files.iter().map(|f| f.size).sum();
                entries.push(SnapshotEntry {
                    id,
                    created_at_unix: m.created_at_unix,
                    reason: m.reason,
                    aegis_version: m.aegis_version,
                    file_count: m.files.len(),
                    total_bytes: total,
                });
            }
        }
        entries.sort_by(|a, b| b.created_at_unix.cmp(&a.created_at_unix));
        Ok(entries)
    }

    /// Restore a snapshot. Existing files are overwritten in-place.
    /// Returns the number of files restored.
    pub fn restore(&self, snapshot_id: &str) -> io::Result<usize> {
        let src = self.root.join(snapshot_id);
        if !src.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("snapshot {snapshot_id} not found"),
            ));
        }
        let manifest: SnapshotManifest = {
            let text = fs::read_to_string(src.join("manifest.json"))?;
            serde_json::from_str(&text).map_err(|e| io::Error::other(format!("manifest: {e}")))?
        };
        let mut restored = 0;
        for entry in &manifest.files {
            let snapshot_file = src.join(&entry.target_relative);
            // Map snapshot-relative back to absolute target.
            let dest = if let Some(rest) = entry.target_relative.strip_prefix("etc/") {
                self.etc_dir.join(rest)
            } else if let Some(rest) = entry.target_relative.strip_prefix("var/") {
                self.var_dir.join(rest)
            } else {
                continue;
            };
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&snapshot_file, &dest)?;
            restored += 1;
        }
        Ok(restored)
    }

    pub fn delete(&self, snapshot_id: &str) -> io::Result<()> {
        let path = self.root.join(snapshot_id);
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("snapshot {snapshot_id} not found"),
            ));
        }
        fs::remove_dir_all(&path)?;
        Ok(())
    }

    fn gc(&self) -> io::Result<usize> {
        let entries = self.list()?;
        if entries.len() <= self.keep_count {
            return Ok(0);
        }
        let mut q: VecDeque<_> = entries.into_iter().collect();
        let mut dropped = 0;
        while q.len() > self.keep_count {
            let Some(oldest) = q.pop_back() else { break };
            let _ = self.delete(&oldest.id);
            dropped += 1;
        }
        Ok(dropped)
    }
}

fn copy_dir_filtered(
    src: &Path,
    dst: &Path,
    extensions: &[&str],
    files: &mut Vec<SnapshotFile>,
    rel_prefix: &str,
) -> io::Result<()> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        let path = e.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !extensions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(ext))
        {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let dest = dst.join(name);
        fs::copy(&path, &dest)?;
        files.push(SnapshotFile {
            source: path.display().to_string(),
            target_relative: format!("{rel_prefix}/{name}"),
            size: fs::metadata(&dest).map(|m| m.len()).unwrap_or(0),
        });
    }
    Ok(())
}

fn iso_compact(unix: u64) -> String {
    // YYYY-MM-DD'T'HH-MM-SS — filesystem-safe.
    let (y, mo, d) = days_to_ymd((unix / 86_400) as i64);
    let sod = unix % 86_400;
    let h = sod / 3600;
    let mi = (sod % 3600) / 60;
    let s = sod % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}-{mi:02}-{s:02}")
}

fn iso_long(unix: u64) -> String {
    let (y, mo, d) = days_to_ymd((unix / 86_400) as i64);
    let sod = unix % 86_400;
    let h = sod / 3600;
    let mi = (sod % 3600) / 60;
    let s = sod % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 {
        mp as u32 + 3
    } else {
        mp as u32 - 9
    };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().take(40) {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if matches!(c, ' ' | '-' | '_' | '.' | ':') {
            out.push('-');
        }
    }
    let trimmed: String = out.trim_matches('-').chars().collect();
    if trimmed.is_empty() {
        "manual".into()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("aegis-snap-{pid}-{nanos}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn setup() -> (PathBuf, PathBuf, PathBuf, SnapshotManager) {
        let root = temp_root();
        let etc = root.join("etc");
        let var = root.join("var");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(&var).unwrap();
        let mgr = SnapshotManager::new(root.join("snapshots"), &etc, &var);
        (root, etc, var, mgr)
    }

    #[test]
    fn create_round_trips_through_list() {
        let (_root, etc, var, mgr) = setup();
        fs::write(etc.join("aegis.conf"), b"# config").unwrap();
        fs::write(var.join("web.json"), b"{}").unwrap();
        let id = mgr.create("pre-test").unwrap();
        let entries = mgr.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].file_count, 2);
        assert_eq!(entries[0].reason, "pre-test");
    }

    #[test]
    fn restore_overwrites_existing_files() {
        let (_root, etc, var, mgr) = setup();
        fs::write(etc.join("aegis.conf"), b"original").unwrap();
        let id = mgr.create("pre-edit").unwrap();
        fs::write(etc.join("aegis.conf"), b"corrupted").unwrap();
        let _ = var; // silence unused
        let n = mgr.restore(&id).unwrap();
        assert_eq!(n, 1);
        assert_eq!(fs::read(etc.join("aegis.conf")).unwrap(), b"original");
    }

    #[test]
    fn sites_enabled_directory_copied_with_filter() {
        let (_root, etc, _var, mgr) = setup();
        let sites = etc.join("sites-enabled");
        fs::create_dir_all(&sites).unwrap();
        fs::write(sites.join("a.conf"), b"a").unwrap();
        fs::write(sites.join("b.conf"), b"b").unwrap();
        fs::write(sites.join("note.txt"), b"skip").unwrap();
        let id = mgr.create("sites-test").unwrap();
        let manifest_text = fs::read_to_string(mgr.root.join(&id).join("manifest.json")).unwrap();
        let manifest: SnapshotManifest = serde_json::from_str(&manifest_text).unwrap();
        let conf_count = manifest
            .files
            .iter()
            .filter(|f| f.target_relative.ends_with(".conf"))
            .count();
        let txt_count = manifest
            .files
            .iter()
            .filter(|f| f.target_relative.ends_with(".txt"))
            .count();
        assert_eq!(conf_count, 2);
        assert_eq!(txt_count, 0);
    }

    #[test]
    fn gc_drops_oldest_when_over_limit() {
        let (_root, etc, _var, mgr) = setup();
        let mgr = mgr.with_keep_count(2);
        fs::write(etc.join("aegis.conf"), b"x").unwrap();
        let ids = (0..4)
            .map(|i| {
                std::thread::sleep(std::time::Duration::from_millis(1100));
                mgr.create(format!("step-{i}")).unwrap()
            })
            .collect::<Vec<_>>();
        let entries = mgr.list().unwrap();
        assert_eq!(entries.len(), 2);
        // Newest two should remain.
        assert!(entries.iter().any(|e| e.id == ids[3]));
        assert!(entries.iter().any(|e| e.id == ids[2]));
        assert!(entries.iter().all(|e| e.id != ids[0]));
    }

    #[test]
    fn restore_missing_snapshot_errors_cleanly() {
        let (_root, _etc, _var, mgr) = setup();
        let err = mgr.restore("nonexistent").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn delete_removes_snapshot_directory() {
        let (_root, etc, _var, mgr) = setup();
        fs::write(etc.join("aegis.conf"), b"x").unwrap();
        let id = mgr.create("to-delete").unwrap();
        mgr.delete(&id).unwrap();
        assert!(mgr.list().unwrap().is_empty());
    }

    #[test]
    fn empty_source_dirs_produce_zero_file_snapshot() {
        let (_root, _etc, _var, mgr) = setup();
        let id = mgr.create("empty").unwrap();
        let entries = mgr.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].file_count, 0);
    }

    #[test]
    fn slug_strips_unsafe_chars() {
        let s = slug("pre-update v0.2.0!");
        // Spaces → '-', '.' → '-', '!' dropped, lowercased.
        assert_eq!(s, "pre-update-v0-2-0");
        assert_eq!(slug("@@@$$$"), "manual");
        assert_eq!(slug("hello"), "hello");
    }

    #[test]
    fn iso_compact_format_is_filesystem_safe() {
        let s = iso_compact(1_716_000_000);
        // No colons (would break some path tooling) — uses '-'.
        assert!(!s.contains(':'));
        // Has T separator.
        assert!(s.contains('T'));
    }
}
