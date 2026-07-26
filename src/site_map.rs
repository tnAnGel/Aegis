//! V119 — Site cartography: auto-discover endpoints from live traffic.
//!
//! Operators add a new domain to Aegis, point DNS, and traffic starts
//! flowing. Within minutes the proxy has seen the site's real endpoint
//! shape — what paths are hit, with what methods, what status mixes,
//! what hot spots. V119 captures that shape into a per-host
//! [SiteMap] the admin UI surfaces, so the operator can apply
//! per-endpoint policy without having to enumerate the API by hand.
//!
//! Key design properties:
//!
//! * **Path generalisation** — `/api/users/12345` and
//!   `/api/users/67890` collapse to `/api/users/:id` so the map
//!   doesn't explode under high-cardinality URLs. Generalisation is
//!   rule-based (digits, UUIDs, hex tokens) with operator-overridable
//!   patterns.
//! * **Method-aware** — `/api/users` GET and POST are tracked as
//!   distinct entries with distinct stats.
//! * **Bounded memory** — per-host LRU cap (default 1024 endpoints).
//!   New endpoints evict the least-recently-seen. Operators tighten
//!   for low-cardinality sites or expand for big APIs.
//! * **Hot-path safe** — single `observe()` call per request. The
//!   inner store is a sharded [`DashMap`] keyed on
//!   `(host, method, pattern)`, so concurrent writers from different
//!   workers hit different shards and don't serialise on a global
//!   lock. The previous nested `RwLock<HashMap>` design serialised
//!   every first-touch insert across all workers — including
//!   first-touches of a brand-new host, which is exactly when traffic
//!   for a freshly added domain ramps fastest.
//!
//! Surface for V120 UI:
//!
//!   GET /admin/api/site_map/<host>
//!   → JSON: `{endpoints: [{method, path_pattern, hits, last_seen,
//!            status_2xx, status_4xx, status_5xx, p99_ms}]}`
//!
//! Operator UI consumer: per-domain edit page renders the table,
//! adds a "Apply rule" button per row (which jumps into the
//! existing per-endpoint policy editor with the path/method
//! prefilled).
//!
//! # Persistence (V240+)
//!
//! Each SO_REUSEPORT worker acquires a slot via flock on
//! `.slot-<n>.lock` files in AEGIS_SITEMAP_DIR (default
//! `/var/lib/aegis/site-map`). Every 30 s it atomically writes its
//! own shard snapshot (`shard-<slot>.json`). On restart it reloads
//! from its shard. The admin API reads **all** shards and merges them
//! (union keys; sum counters; max last_seen) so responses are stable
//! regardless of which worker answers.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Default max endpoint entries per host. ~64 KiB per host at 64 bytes
/// per entry — fine for thousands of sites.
const DEFAULT_PER_HOST_CAP: usize = 1024;

/// Cardinality caps applied at snapshot/flush time.
const SNAPSHOT_HOST_CAP: usize = 200;
const SNAPSHOT_ENDPOINT_CAP: usize = 500;
/// Max number of slot files probed when acquiring a worker slot.
const MAX_SLOTS: u32 = 16;

/// Per-host endpoint snapshot returned to the admin UI.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    pub method: String,
    pub path_pattern: String,
    pub hits: u64,
    pub last_seen_unix_secs: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

// ── Serde types for disk persistence ─────────────────────────────────────────

/// One endpoint row as stored/returned in the shard JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedEndpoint {
    pub method: String,
    pub path_pattern: String,
    pub hits: u64,
    pub last_seen_unix_secs: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

/// Per-host summary row inside a `SiteMapSnapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub host: String,
    /// Sum of `hits` across all endpoints for this host.
    pub total_hits: u64,
    /// Most-recent `last_seen_unix_secs` across all endpoints.
    pub last_seen: u64,
    /// Endpoints sorted by hits descending.
    pub endpoints: Vec<PersistedEndpoint>,
}

/// Full tree snapshot — serialised to `shard-<slot>.json` on disk and
/// returned by `export_snapshot` / `merge_snapshots`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMapSnapshot {
    /// Unix timestamp when this snapshot was written. Used by the admin
    /// merge to skip orphaned shards whose writer has exited.
    pub written_at_unix_secs: u64,
    /// All observed hosts.
    pub hosts: Vec<HostSnapshot>,
}

/// Per-(host, method, pattern) tracker. All counters atomic so observe()
/// can run without taking any exclusive lock on the shared map.
struct EndpointEntry {
    method: String,
    path_pattern: String,
    hits: AtomicU64,
    last_seen: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
}

impl EndpointEntry {
    fn snapshot(&self) -> EndpointStats {
        EndpointStats {
            method: self.method.clone(),
            path_pattern: self.path_pattern.clone(),
            hits: self.hits.load(Ordering::Relaxed),
            last_seen_unix_secs: self.last_seen.load(Ordering::Relaxed),
            status_2xx: self.status_2xx.load(Ordering::Relaxed),
            status_3xx: self.status_3xx.load(Ordering::Relaxed),
            status_4xx: self.status_4xx.load(Ordering::Relaxed),
            status_5xx: self.status_5xx.load(Ordering::Relaxed),
        }
    }
}

/// Flat key: (host, method, path_pattern). Hashing fans out across
/// DashMap shards so unrelated hosts don't contend.
type EndpointKey = (String, String, String);

pub struct SiteMap {
    per_host_cap: usize,
    /// (host, method, pattern) → entry. Sharded for write concurrency.
    inner: DashMap<EndpointKey, EndpointEntry>,
    // ── Persistence ──────────────────────────────────────────────────────────
    /// Path to this worker's shard file, e.g. `…/shard-0.json`.
    /// `None` when persistence is disabled (slot acquisition failed, or
    /// `with_persistence` was never called — safe for tests).
    shard_path: Option<PathBuf>,
    /// Holds the advisory flock on `.slot-<n>.lock` for the lifetime of
    /// this process. Dropping releases the lock so the next worker can
    /// claim the slot.
    #[allow(dead_code)]
    slot_lock: Option<File>,
}

impl Default for SiteMap {
    fn default() -> Self {
        Self {
            per_host_cap: DEFAULT_PER_HOST_CAP,
            // V230 — boost shard count for high concurrent per-endpoint write parallelism.
            inner: DashMap::with_shard_amount(128),
            shard_path: None,
            slot_lock: None,
        }
    }
}

impl SiteMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_per_host_cap(mut self, cap: usize) -> Self {
        self.per_host_cap = cap.max(8);
        self
    }

    // ── Persistence: builder ─────────────────────────────────────────────────

    /// Enable disk persistence. Acquires a worker slot (via non-blocking
    /// flock on `.slot-<n>.lock`) and loads any prior shard back into the
    /// in-memory map. Call once at startup, before the worker begins
    /// serving traffic. Returns `self` for chaining.
    ///
    /// If slot acquisition fails (all 16 slots occupied), logs a warning
    /// and falls back to in-memory-only mode — `flush_shard` becomes a
    /// no-op and `shard_path()` returns `None`.
    pub fn with_persistence(mut self, dir: PathBuf) -> Self {
        if let Err(e) = fs::create_dir_all(&dir) {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "site_map: cannot create shard directory — running without persistence"
            );
            return self;
        }
        match acquire_slot(&dir, MAX_SLOTS) {
            None => {
                tracing::warn!(
                    dir = %dir.display(),
                    "site_map: no free slot in {} tries — running without persistence",
                    MAX_SLOTS
                );
            }
            Some((slot, lock_file)) => {
                let shard = dir.join(format!("shard-{slot}.json"));
                // Bootstrap from prior shard — restores our own counters.
                if let Some(snap) = load_shard_from(&shard) {
                    self.import_merge(&snap);
                    tracing::info!(
                        slot,
                        path = %shard.display(),
                        hosts = snap.hosts.len(),
                        "site_map: restored shard from disk"
                    );
                }
                self.shard_path = Some(shard);
                self.slot_lock = Some(lock_file);
            }
        }
        self
    }

    /// Path to this worker's shard file, if persistence is enabled.
    pub fn shard_path(&self) -> Option<&Path> {
        self.shard_path.as_deref()
    }

    // ── Persistence: snapshot API ────────────────────────────────────────────

    /// Export the full in-memory tree as a `SiteMapSnapshot`, applying
    /// cardinality caps (top `SNAPSHOT_HOST_CAP` hosts by total hits;
    /// top `SNAPSHOT_ENDPOINT_CAP` endpoints per host). Staleness pruning
    /// is NOT applied here — callers use `evict_idle` for that.
    pub fn export_snapshot(&self) -> SiteMapSnapshot {
        let now = unix_now();
        // Collect (host, PersistedEndpoint) pairs from the DashMap.
        let mut by_host: HashMap<String, Vec<PersistedEndpoint>> = HashMap::new();
        for entry in self.inner.iter() {
            let host = entry.key().0.clone();
            let e = entry.value();
            by_host.entry(host).or_default().push(PersistedEndpoint {
                method: e.method.clone(),
                path_pattern: e.path_pattern.clone(),
                hits: e.hits.load(Ordering::Relaxed),
                last_seen_unix_secs: e.last_seen.load(Ordering::Relaxed),
                status_2xx: e.status_2xx.load(Ordering::Relaxed),
                status_3xx: e.status_3xx.load(Ordering::Relaxed),
                status_4xx: e.status_4xx.load(Ordering::Relaxed),
                status_5xx: e.status_5xx.load(Ordering::Relaxed),
            });
        }
        build_snapshot(now, by_host)
    }

    /// Merge `snap` INTO this `SiteMap` (union keys; sum hit/status
    /// counters; take the max `last_seen`). Used for boot-load from a prior
    /// shard so counters accumulate correctly across restarts.
    pub fn import_merge(&self, snap: &SiteMapSnapshot) {
        for hs in &snap.hosts {
            for ep in &hs.endpoints {
                let key: EndpointKey =
                    (hs.host.clone(), ep.method.clone(), ep.path_pattern.clone());
                let entry = self
                    .inner
                    .entry(key.clone())
                    .or_insert_with(|| EndpointEntry {
                        method: ep.method.clone(),
                        path_pattern: ep.path_pattern.clone(),
                        hits: AtomicU64::new(0),
                        // Start at 0 so the CAS-max below correctly picks up
                        // ep.last_seen_unix_secs even for old timestamps.
                        last_seen: AtomicU64::new(0),
                        status_2xx: AtomicU64::new(0),
                        status_3xx: AtomicU64::new(0),
                        status_4xx: AtomicU64::new(0),
                        status_5xx: AtomicU64::new(0),
                    });
                entry.hits.fetch_add(ep.hits, Ordering::Relaxed);
                entry.status_2xx.fetch_add(ep.status_2xx, Ordering::Relaxed);
                entry.status_3xx.fetch_add(ep.status_3xx, Ordering::Relaxed);
                entry.status_4xx.fetch_add(ep.status_4xx, Ordering::Relaxed);
                entry.status_5xx.fetch_add(ep.status_5xx, Ordering::Relaxed);
                // CAS-max for last_seen.
                let mut cur = entry.last_seen.load(Ordering::Relaxed);
                while ep.last_seen_unix_secs > cur {
                    match entry.last_seen.compare_exchange_weak(
                        cur,
                        ep.last_seen_unix_secs,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => cur = actual,
                    }
                }
            }
        }
    }

    // ── Persistence: static merge ────────────────────────────────────────────

    /// Pure merge of multiple shard snapshots into one aggregated snapshot
    /// (union keys; sum counters; max last_seen), with the cardinality cap
    /// re-applied. Used by the admin API to produce a stable aggregate
    /// regardless of which worker handles the request.
    pub fn merge_snapshots(snaps: &[SiteMapSnapshot]) -> SiteMapSnapshot {
        let now = unix_now();
        let mut by_host: HashMap<String, HashMap<(String, String), PersistedEndpoint>> =
            HashMap::new();

        for snap in snaps {
            for hs in &snap.hosts {
                let host_map = by_host.entry(hs.host.clone()).or_default();
                for ep in &hs.endpoints {
                    let key = (ep.method.clone(), ep.path_pattern.clone());
                    match host_map.get_mut(&key) {
                        Some(existing) => {
                            existing.hits += ep.hits;
                            existing.status_2xx += ep.status_2xx;
                            existing.status_3xx += ep.status_3xx;
                            existing.status_4xx += ep.status_4xx;
                            existing.status_5xx += ep.status_5xx;
                            existing.last_seen_unix_secs =
                                existing.last_seen_unix_secs.max(ep.last_seen_unix_secs);
                        }
                        None => {
                            host_map.insert(key, ep.clone());
                        }
                    }
                }
            }
        }

        // Flatten into the same HashMap format accepted by `build_snapshot`.
        let flat: HashMap<String, Vec<PersistedEndpoint>> = by_host
            .into_iter()
            .map(|(host, ep_map)| (host, ep_map.into_values().collect()))
            .collect();

        build_snapshot(now, flat)
    }

    // ── Persistence: disk I/O ────────────────────────────────────────────────

    /// Serialize the full in-memory tree (capped) to disk atomically.
    /// No-op when `shard_path` is `None` (persistence disabled).
    /// Write errors are logged as warnings — we never abort serving.
    pub fn flush_shard(&self) {
        let Some(shard_path) = &self.shard_path else {
            return;
        };
        let snap = self.export_snapshot();
        if let Err(e) = write_snapshot_to(shard_path, &snap) {
            tracing::warn!(
                path = %shard_path.display(),
                error = %e,
                "site_map: failed to flush shard"
            );
        }
    }

    // ── Persistence: directory-level helpers (static) ────────────────────────

    /// Load this worker's own shard from disk. Returns `None` if the file
    /// does not exist, is unreadable, or fails to parse.
    pub fn load_shard(dir: &Path, slot: u32) -> Option<SiteMapSnapshot> {
        load_shard_from(&dir.join(format!("shard-{slot}.json")))
    }

    /// Write `snap` as this slot's shard file, atomically.
    pub fn write_shard(dir: &Path, slot: u32, snap: &SiteMapSnapshot) -> std::io::Result<()> {
        write_snapshot_to(&dir.join(format!("shard-{slot}.json")), snap)
    }

    /// Read all valid shard files in `dir`, skipping any whose
    /// `written_at_unix_secs` is older than `max_age_secs` seconds ago.
    /// Returns one `SiteMapSnapshot` per shard that passes the age check.
    pub fn read_all_shards(dir: &Path, max_age_secs: u64) -> Vec<SiteMapSnapshot> {
        read_all_shards_impl(dir, max_age_secs)
    }

    /// Non-blocking flock slot acquisition. Returns `(slot_index,
    /// lock_file_handle)` or `None` if all `max_slots` are occupied.
    /// The returned `File` MUST be kept alive for the process lifetime.
    pub fn acquire_slot(dir: &Path, max_slots: u32) -> Option<(u32, File)> {
        acquire_slot(dir, max_slots)
    }

    /// Hot-path observation. Called once per request in the
    /// `logging` phase with the final status code.
    pub fn observe(&self, host: &str, method: &str, path: &str, status: u16) {
        if host.is_empty() {
            return;
        }
        let pattern = generalise_path(path);
        let method_up = method.to_ascii_uppercase();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Fast path: lookup-only, no allocation of the owned key.
        // DashMap::get takes a `&Q` where `EndpointKey: Borrow<Q>`,
        // and (String,String,String) only borrows as itself, so we
        // still build the tuple — but it's a stack tuple of three
        // borrows-turned-owned-string-clones, cheaper than locking
        // and far cheaper than the slow path.
        //
        // We construct the key once and reuse it on the slow path
        // if we need to insert.
        let key: EndpointKey = (host.to_string(), method_up, pattern);

        if let Some(entry) = self.inner.get(&key) {
            entry.hits.fetch_add(1, Ordering::Relaxed);
            entry.last_seen.store(now, Ordering::Relaxed);
            bump_status(entry.value(), status);
            return;
        }

        // Slow path: insert. Enforce per-host cap before adding.
        // Cap enforcement scans only this host's keys; for many
        // hosts with low cap this is bounded. We do it before the
        // entry() call to avoid holding a shard lock during the scan.
        self.enforce_host_cap(&key.0);

        // entry().or_insert_with() handles the race where two
        // workers both miss on the get() above and try to insert
        // the same key.
        let inserted = self
            .inner
            .entry(key.clone())
            .or_insert_with(|| EndpointEntry {
                method: key.1.clone(),
                path_pattern: key.2.clone(),
                hits: AtomicU64::new(0),
                last_seen: AtomicU64::new(now),
                status_2xx: AtomicU64::new(0),
                status_3xx: AtomicU64::new(0),
                status_4xx: AtomicU64::new(0),
                status_5xx: AtomicU64::new(0),
            });
        inserted.hits.fetch_add(1, Ordering::Relaxed);
        inserted.last_seen.store(now, Ordering::Relaxed);
        bump_status(inserted.value(), status);
    }

    /// Evict the oldest endpoint for `host` if it's already at the
    /// cap. Best-effort: we scan, pick the coldest, then remove. If
    /// a racing writer adds another endpoint between the scan and
    /// the remove we may briefly exceed the cap by one — acceptable.
    fn enforce_host_cap(&self, host: &str) {
        let mut count = 0usize;
        let mut oldest_key: Option<EndpointKey> = None;
        let mut oldest_seen: u64 = u64::MAX;
        for entry in self.inner.iter() {
            if entry.key().0 != host {
                continue;
            }
            count += 1;
            let seen = entry.value().last_seen.load(Ordering::Relaxed);
            if seen < oldest_seen {
                oldest_seen = seen;
                oldest_key = Some(entry.key().clone());
            }
        }
        if count >= self.per_host_cap
            && let Some(k) = oldest_key
        {
            self.inner.remove(&k);
        }
    }

    /// Snapshot all endpoints for one host, sorted by hits descending.
    pub fn snapshot(&self, host: &str) -> Vec<EndpointStats> {
        let mut out: Vec<EndpointStats> = self
            .inner
            .iter()
            .filter(|e| e.key().0 == host)
            .map(|e| e.value().snapshot())
            .collect();
        out.sort_by(|a, b| b.hits.cmp(&a.hits));
        out
    }

    /// List all hosts that have any tracked endpoint.
    pub fn hosts(&self) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::new();
        for entry in self.inner.iter() {
            seen.insert(entry.key().0.clone());
        }
        seen.into_iter().collect()
    }

    /// Total endpoints tracked across all hosts. Diagnostic.
    pub fn total_endpoints(&self) -> usize {
        self.inner.len()
    }

    /// Periodic eviction of cold endpoints — drops entries not seen
    /// for `idle` duration. Caller wires into PingoraBackground tick.
    pub fn evict_idle(&self, idle: Duration) {
        let cutoff = SystemTime::now()
            .checked_sub(idle)
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if cutoff == 0 {
            return;
        }
        self.inner
            .retain(|_, e| e.last_seen.load(Ordering::Relaxed) >= cutoff);
    }
}

fn bump_status(e: &EndpointEntry, status: u16) {
    match status / 100 {
        2 => &e.status_2xx,
        3 => &e.status_3xx,
        4 => &e.status_4xx,
        5 => &e.status_5xx,
        _ => return,
    }
    .fetch_add(1, Ordering::Relaxed);
}

// ── Persistence free functions ────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build a `SiteMapSnapshot` from a raw host→endpoints map, applying
/// cardinality caps (top `SNAPSHOT_HOST_CAP` hosts by total hits,
/// top `SNAPSHOT_ENDPOINT_CAP` endpoints per host, endpoints sorted by
/// hits descending).
fn build_snapshot(
    written_at: u64,
    mut by_host: HashMap<String, Vec<PersistedEndpoint>>,
) -> SiteMapSnapshot {
    // Sort each host's endpoints by hits desc, apply per-host cap.
    for eps in by_host.values_mut() {
        eps.sort_unstable_by(|a, b| b.hits.cmp(&a.hits));
        eps.truncate(SNAPSHOT_ENDPOINT_CAP);
    }

    // Compute per-host total_hits for sorting and cap enforcement.
    let mut host_totals: Vec<(String, u64, u64)> = by_host
        .iter()
        .map(|(host, eps)| {
            let total = eps.iter().map(|e| e.hits).sum::<u64>();
            let last = eps.iter().map(|e| e.last_seen_unix_secs).max().unwrap_or(0);
            (host.clone(), total, last)
        })
        .collect();

    // Sort by total_hits desc, keep top SNAPSHOT_HOST_CAP.
    host_totals.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    host_totals.truncate(SNAPSHOT_HOST_CAP);

    let hosts = host_totals
        .into_iter()
        .map(|(host, total_hits, last_seen)| {
            let endpoints = by_host.remove(&host).unwrap_or_default();
            HostSnapshot {
                host,
                total_hits,
                last_seen,
                endpoints,
            }
        })
        .collect();

    SiteMapSnapshot {
        written_at_unix_secs: written_at,
        hosts,
    }
}

/// Try to acquire a non-blocking exclusive flock on `path`.
fn try_flock_nb(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        // Lock file: opened only to hold a flock, never rewritten.
        .truncate(false)
        .open(path)
        .ok()?;
    let fd = file.as_raw_fd();
    // SAFETY: flock(2) is always safe to call with a valid fd.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 { Some(file) } else { None }
}

/// Probe `.slot-0.lock` .. `.slot-<max_slots-1>.lock` in `dir`, returning
/// the first slot index and its lock `File` on success. The caller MUST
/// keep the returned `File` alive for the process lifetime.
fn acquire_slot(dir: &Path, max_slots: u32) -> Option<(u32, File)> {
    for slot in 0..max_slots {
        let lock_path = dir.join(format!(".slot-{slot}.lock"));
        if let Some(f) = try_flock_nb(&lock_path) {
            return Some((slot, f));
        }
    }
    None
}

/// Deserialise a `SiteMapSnapshot` from `path`. Returns `None` on any error.
fn load_shard_from(path: &Path) -> Option<SiteMapSnapshot> {
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Atomically write `snap` to `path` (write to a `.tmp` sibling, then
/// rename). Sets permissions to 0o640. Errors are propagated.
fn write_snapshot_to(path: &Path, snap: &SiteMapSnapshot) -> std::io::Result<()> {
    let json = serde_json::to_string(snap).map_err(|e| std::io::Error::other(e))?;

    // Sibling tmp file in the same directory → same filesystem → rename is atomic.
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
    // Set permissions before rename so the target is never world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read all `shard-*.json` files from `dir`, skipping any whose
/// `written_at_unix_secs` is older than `max_age_secs` seconds ago (or
/// whose file mtime is older, as a belt-and-suspenders check).
/// Returns one `SiteMapSnapshot` per shard that passes both checks.
fn read_all_shards_impl(dir: &Path, max_age_secs: u64) -> Vec<SiteMapSnapshot> {
    let cutoff = unix_now().saturating_sub(max_age_secs);
    let mut out = Vec::new();

    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return out,
    };

    for entry in read_dir.flatten() {
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        // Only process files matching shard-<digits>.json.
        if !name.starts_with("shard-") || !name.ends_with(".json") {
            continue;
        }
        // Belt-and-suspenders: also check file mtime.
        if let Ok(meta) = entry.metadata() {
            if let Ok(mtime) = meta.modified() {
                let mtime_secs = mtime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if mtime_secs < cutoff {
                    continue; // orphan: file itself is too old
                }
            }
        }
        let Some(snap) = load_shard_from(&entry.path()) else {
            continue;
        };
        if snap.written_at_unix_secs < cutoff {
            continue; // snapshot timestamp says it's stale
        }
        out.push(snap);
    }
    out
}

/// V119 — path generalisation. Maps high-cardinality path segments
/// to type-named placeholders so distinct user IDs collapse into one
/// endpoint pattern.
///
/// Recognised segment shapes (checked in order):
/// * UUID v4 (8-4-4-4-12 hex) → `:uuid`
/// * pure digits (≥1 char) → `:id`
/// * 24-char hex (MongoDB ObjectId) → `:oid`
/// * 8+ hex (token-shaped) → `:token`
/// * Otherwise verbatim.
///
/// Query string and fragment are dropped (we map structure, not
/// parameters; per-query analytics belongs in hot-URI tracker).
pub fn generalise_path(p: &str) -> String {
    let bare = p.split(&['?', '#'][..]).next().unwrap_or(p);
    let mut out = String::with_capacity(bare.len());
    let mut first = true;
    for seg in bare.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        if seg.is_empty() {
            continue;
        }
        out.push_str(classify_segment(seg));
    }
    out
}

fn classify_segment(seg: &str) -> &str {
    if looks_like_uuid(seg) {
        return ":uuid";
    }
    if seg.chars().all(|c| c.is_ascii_digit()) && !seg.is_empty() {
        return ":id";
    }
    if seg.len() == 24 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return ":oid";
    }
    if seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return ":token";
    }
    // Date-like: 2025-01-15 → :date
    // V233 — index the byte slice, not the &str. `seg.len() == 10` is a
    // BYTE-length guard; a 10-byte segment can still contain a multi-byte
    // UTF-8 char (e.g. "123456789é"), and `&seg[4..5]` / `seg[8..]` would
    // then fall on a non-char-boundary and panic (worker SIGABRT under
    // `panic = "abort"`). Byte-slice indexing never has a boundary panic.
    let b = seg.as_bytes();
    if b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..].iter().all(u8::is_ascii_digit)
    {
        return ":date";
    }
    seg
}

fn looks_like_uuid(s: &str) -> bool {
    // V233 — same hazard as classify_segment's date check: `s.len() == 36`
    // is a byte-length guard, and a 36-byte string may contain multi-byte
    // UTF-8 chars, so `&s[8..9]` etc. could land off a char boundary and
    // panic. Index the byte slice instead — boundary-panic-free, and the
    // result is identical for valid input (hyphens + hex are all ASCII).
    let b = s.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b.iter().filter(|&&c| c != b'-').all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalise_id_segment() {
        assert_eq!(generalise_path("/api/users/12345"), "/api/users/:id");
        assert_eq!(
            generalise_path("/api/users/12345/posts/678"),
            "/api/users/:id/posts/:id"
        );
    }

    #[test]
    fn generalise_uuid_segment() {
        assert_eq!(
            generalise_path("/api/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/api/orders/:uuid"
        );
    }

    #[test]
    fn generalise_objectid_and_token() {
        assert_eq!(
            generalise_path("/api/doc/507f1f77bcf86cd799439011"),
            "/api/doc/:oid"
        );
        assert_eq!(
            generalise_path("/api/session/abcdef0123456789abcdef01"),
            "/api/session/:oid"
        );
        assert_eq!(
            generalise_path("/auth/token/abcdef0123456789"),
            "/auth/token/:token"
        );
    }

    #[test]
    fn generalise_date_segment() {
        assert_eq!(
            generalise_path("/posts/2025-01-15/comments"),
            "/posts/:date/comments"
        );
    }

    // V233 — a 10-byte segment that is NOT 10 chars (multi-byte UTF-8)
    // must not panic the date-detection slicing. Before V233 this hit a
    // non-char-boundary index → panic → worker SIGABRT.
    #[test]
    fn classify_segment_multibyte_10_bytes_no_panic() {
        // "1234é6789" — 4 ASCII + 'é' (2 bytes, occupying byte indices
        // 4-5) + 4 ASCII = 10 bytes. The date-detection slice `[4..5]`
        // therefore cuts mid-codepoint — pre-V233 that panicked
        // ("byte index 5 is not a char boundary"). Must classify as
        // verbatim, not panic.
        let s = "1234é6789";
        assert_eq!(
            s.len(),
            10,
            "must be a 10-byte segment to exercise the guard"
        );
        assert_eq!(classify_segment(s), s);
        assert_eq!(
            generalise_path("/posts/1234é6789/comments"),
            "/posts/1234é6789/comments"
        );
    }

    // V233 — looks_like_uuid had the identical byte-vs-char hazard at len 36.
    #[test]
    fn looks_like_uuid_multibyte_36_bytes_no_panic() {
        // 34 ASCII bytes + 'é' (2 bytes) = 36 bytes; not a real UUID, must
        // return false without panicking on the hyphen-position checks.
        let s = "550e8400-e29b-41d4-a716-4466554400é";
        assert_eq!(
            s.len(),
            36,
            "must be a 36-byte segment to exercise the guard"
        );
        assert!(!looks_like_uuid(s));
        // And a path carrying it must generalise without panic.
        assert_eq!(
            generalise_path(&format!("/api/orders/{s}")),
            format!("/api/orders/{s}")
        );
    }

    #[test]
    fn generalise_strips_query_and_fragment() {
        assert_eq!(generalise_path("/api/users?page=1"), "/api/users");
        assert_eq!(generalise_path("/api/users#section"), "/api/users");
        assert_eq!(generalise_path("/api/users/42?x=1#y"), "/api/users/:id");
    }

    #[test]
    fn observe_groups_by_pattern() {
        let m = SiteMap::new();
        m.observe("example.com", "GET", "/api/users/1", 200);
        m.observe("example.com", "GET", "/api/users/2", 200);
        m.observe("example.com", "GET", "/api/users/3", 404);
        let snap = m.snapshot("example.com");
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].path_pattern, "/api/users/:id");
        assert_eq!(snap[0].hits, 3);
        assert_eq!(snap[0].status_2xx, 2);
        assert_eq!(snap[0].status_4xx, 1);
    }

    #[test]
    fn method_separates_entries() {
        let m = SiteMap::new();
        m.observe("example.com", "GET", "/api/users", 200);
        m.observe("example.com", "POST", "/api/users", 201);
        let snap = m.snapshot("example.com");
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|e| e.method == "GET"));
        assert!(snap.iter().any(|e| e.method == "POST"));
    }

    #[test]
    fn host_separates_entries() {
        let m = SiteMap::new();
        m.observe("a.example", "GET", "/", 200);
        m.observe("b.example", "GET", "/", 200);
        assert_eq!(m.hosts().len(), 2);
        assert_eq!(m.snapshot("a.example").len(), 1);
        assert_eq!(m.snapshot("b.example").len(), 1);
    }

    #[test]
    fn per_host_cap_evicts_oldest() {
        let m = SiteMap::new().with_per_host_cap(8);
        // 10 distinct paths → 2 oldest get evicted.
        for i in 0..10 {
            m.observe("example.com", "GET", &format!("/distinct{i}/x/y"), 200);
        }
        let snap = m.snapshot("example.com");
        assert!(snap.len() <= 8, "should respect cap, got {}", snap.len());
    }

    #[test]
    fn empty_host_ignored() {
        let m = SiteMap::new();
        m.observe("", "GET", "/", 200);
        assert!(m.snapshot("").is_empty());
        assert!(m.hosts().is_empty());
    }

    #[test]
    fn snapshot_sorted_by_hits_desc() {
        let m = SiteMap::new();
        for _ in 0..5 {
            m.observe("h", "GET", "/cold", 200);
        }
        for _ in 0..20 {
            m.observe("h", "GET", "/hot", 200);
        }
        let snap = m.snapshot("h");
        assert_eq!(snap[0].path_pattern, "/hot");
        assert_eq!(snap[1].path_pattern, "/cold");
    }

    // ── Persistence tests ─────────────────────────────────────────────────────

    fn make_ep(method: &str, pattern: &str, hits: u64, last_seen: u64) -> PersistedEndpoint {
        PersistedEndpoint {
            method: method.to_string(),
            path_pattern: pattern.to_string(),
            hits,
            last_seen_unix_secs: last_seen,
            status_2xx: hits,
            status_3xx: 0,
            status_4xx: 0,
            status_5xx: 0,
        }
    }

    /// export_snapshot / serde round-trip preserves all fields.
    #[test]
    fn snapshot_round_trip() {
        let m = SiteMap::new();
        m.observe("a.test", "GET", "/foo", 200);
        m.observe("a.test", "GET", "/foo", 200);
        m.observe("a.test", "POST", "/bar", 201);
        m.observe("b.test", "DELETE", "/x", 404);

        let snap = m.export_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let snap2: SiteMapSnapshot = serde_json::from_str(&json).expect("deserialize");

        // host set preserved
        let hosts: HashSet<_> = snap2.hosts.iter().map(|h| h.host.clone()).collect();
        assert!(hosts.contains("a.test"), "a.test missing");
        assert!(hosts.contains("b.test"), "b.test missing");

        // a.test has 2 endpoints
        let a = snap2.hosts.iter().find(|h| h.host == "a.test").unwrap();
        assert_eq!(a.endpoints.len(), 2);
        // sorted by hits desc: /foo (2 hits) before /bar (1 hit)
        assert_eq!(a.endpoints[0].path_pattern, "/foo");
        assert_eq!(a.endpoints[0].hits, 2);
        assert_eq!(a.endpoints[1].hits, 1);

        // total_hits aggregated correctly
        assert_eq!(a.total_hits, 3);

        // b.test
        let b = snap2.hosts.iter().find(|h| h.host == "b.test").unwrap();
        assert_eq!(b.endpoints.len(), 1);
        assert_eq!(b.endpoints[0].method, "DELETE");
    }

    /// merge_snapshots sums hits, unions hosts, takes max last_seen.
    #[test]
    fn merge_sums_hits_unions_hosts_maxes_last_seen() {
        let snap_a = SiteMapSnapshot {
            written_at_unix_secs: 1000,
            hosts: vec![HostSnapshot {
                host: "a.test".to_string(),
                total_hits: 5,
                last_seen: 1000,
                endpoints: vec![make_ep("GET", "/api", 5, 1000)],
            }],
        };
        let snap_b = SiteMapSnapshot {
            written_at_unix_secs: 1001,
            hosts: vec![
                HostSnapshot {
                    host: "a.test".to_string(),
                    total_hits: 3,
                    last_seen: 2000,
                    endpoints: vec![make_ep("GET", "/api", 3, 2000)],
                },
                HostSnapshot {
                    host: "b.test".to_string(),
                    total_hits: 7,
                    last_seen: 1500,
                    endpoints: vec![make_ep("POST", "/x", 7, 1500)],
                },
            ],
        };
        let merged = SiteMap::merge_snapshots(&[snap_a, snap_b]);

        let hosts: HashSet<_> = merged.hosts.iter().map(|h| h.host.clone()).collect();
        assert!(
            hosts.contains("a.test") && hosts.contains("b.test"),
            "both hosts must be present"
        );

        let a = merged.hosts.iter().find(|h| h.host == "a.test").unwrap();
        assert_eq!(a.endpoints.len(), 1);
        assert_eq!(a.endpoints[0].hits, 8, "hits should be summed: 5+3=8");
        assert_eq!(
            a.endpoints[0].last_seen_unix_secs, 2000,
            "should keep max last_seen"
        );
        assert_eq!(a.endpoints[0].status_2xx, 8, "status_2xx should be summed");

        let b = merged.hosts.iter().find(|h| h.host == "b.test").unwrap();
        assert_eq!(b.endpoints[0].hits, 7);
    }

    /// The cardinality cap evicts lowest-hit hosts/endpoints.
    #[test]
    fn cap_evicts_lowest() {
        // Build a snapshot with more hosts than SNAPSHOT_HOST_CAP and
        // more endpoints per host than SNAPSHOT_ENDPOINT_CAP.
        // Rather than pushing hundreds of entries into a live SiteMap
        // (slow), call build_snapshot directly.
        let mut by_host: HashMap<String, Vec<PersistedEndpoint>> = HashMap::new();

        // 210 hosts (10 over the 200-host cap). Host "host-0" has 0 hits
        // and should be evicted; "host-209" has 209 hits and should survive.
        for i in 0..210usize {
            let eps = vec![make_ep("GET", "/", i as u64, 1000)];
            by_host.insert(format!("host-{i}"), eps);
        }
        // One host with 600 endpoints (100 over the 500-ep cap).
        let big_eps: Vec<PersistedEndpoint> = (0..600usize)
            .map(|i| make_ep("GET", &format!("/ep-{i}"), i as u64, 1000))
            .collect();
        by_host.insert("big.test".to_string(), big_eps);

        let snap = build_snapshot(1000, by_host);

        // Total hosts: 210 original + 1 big = 211. After cap: ≤ 200.
        assert!(
            snap.hosts.len() <= SNAPSHOT_HOST_CAP,
            "host count {} exceeds cap {}",
            snap.hosts.len(),
            SNAPSHOT_HOST_CAP
        );

        // The lowest-hit host (host-0, 0 hits) must be gone.
        assert!(
            !snap.hosts.iter().any(|h| h.host == "host-0"),
            "host-0 (0 hits) should have been evicted"
        );

        // big.test endpoints are capped.
        if let Some(big) = snap.hosts.iter().find(|h| h.host == "big.test") {
            assert!(
                big.endpoints.len() <= SNAPSHOT_ENDPOINT_CAP,
                "endpoint count {} exceeds cap {}",
                big.endpoints.len(),
                SNAPSHOT_ENDPOINT_CAP
            );
            // Highest-hit endpoint (ep-599, 599 hits) should survive.
            assert!(
                big.endpoints.iter().any(|e| e.path_pattern == "/ep-599"),
                "highest-hit endpoint must survive cap"
            );
        }
    }

    /// import_merge restores counters into a fresh SiteMap.
    #[test]
    fn import_merge_restores() {
        let snap = SiteMapSnapshot {
            written_at_unix_secs: 500,
            hosts: vec![HostSnapshot {
                host: "restore.test".to_string(),
                total_hits: 42,
                last_seen: 9999,
                endpoints: vec![PersistedEndpoint {
                    method: "GET".to_string(),
                    path_pattern: "/api".to_string(),
                    hits: 42,
                    last_seen_unix_secs: 9999,
                    status_2xx: 40,
                    status_3xx: 1,
                    status_4xx: 1,
                    status_5xx: 0,
                }],
            }],
        };

        let m = SiteMap::new();
        m.import_merge(&snap);

        let endpoints = m.snapshot("restore.test");
        assert_eq!(endpoints.len(), 1);
        let ep = &endpoints[0];
        assert_eq!(ep.hits, 42);
        assert_eq!(ep.status_2xx, 40);
        assert_eq!(ep.status_3xx, 1);
        assert_eq!(ep.status_4xx, 1);
        assert_eq!(ep.status_5xx, 0);
        assert_eq!(ep.last_seen_unix_secs, 9999);

        // New observations accumulate on top.
        m.observe("restore.test", "GET", "/api", 200);
        let ep2 = &m.snapshot("restore.test")[0];
        assert_eq!(ep2.hits, 43, "new hit should add to restored counter");
        assert_eq!(ep2.status_2xx, 41);
    }

    /// read_all_shards skips stale snapshots.
    #[test]
    fn read_all_shards_skips_stale() {
        // Use a unique temp subdirectory per test run (process-id + function
        // name literal). Cleanup is best-effort; the OS reclaims it eventually.
        let dir =
            std::env::temp_dir().join(format!("aegis_sitemap_read_all_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test dir");
        let dir_path = dir.as_path();

        let now = unix_now();

        // Write a fresh shard (slot 0).
        let fresh = SiteMapSnapshot {
            written_at_unix_secs: now,
            hosts: vec![HostSnapshot {
                host: "fresh.test".to_string(),
                total_hits: 1,
                last_seen: now,
                endpoints: vec![make_ep("GET", "/", 1, now)],
            }],
        };
        SiteMap::write_shard(dir_path, 0, &fresh).expect("write fresh shard");

        // Write a stale shard (slot 1): timestamp in the past.
        let stale = SiteMapSnapshot {
            written_at_unix_secs: now.saturating_sub(2000),
            hosts: vec![HostSnapshot {
                host: "stale.test".to_string(),
                total_hits: 99,
                last_seen: 0,
                endpoints: vec![make_ep("GET", "/old", 99, 0)],
            }],
        };
        SiteMap::write_shard(dir_path, 1, &stale).expect("write stale shard");

        // max_age_secs = 900: the stale shard (2000 s old) must be skipped.
        let snaps = SiteMap::read_all_shards(dir_path, 900);
        assert_eq!(snaps.len(), 1, "only the fresh shard should be loaded");
        assert_eq!(snaps[0].hosts[0].host, "fresh.test");
    }
}
