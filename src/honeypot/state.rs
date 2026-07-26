//! Persistent honeypot state shared between the daemon and the admin
//! API.
//!
//! Lives in a single JSON file (default `/var/lib/aegis/honeypots.json`)
//! so the React panel can toggle packs per host without a config
//! reload. The daemon stats the file on every honeypot-filter
//! evaluation and rebuilds its compiled matchers when the mtime
//! changes, so changes apply within seconds.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{Duration, SystemTime},
};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::{matcher::HoneypotMatcher, packs};

pub const DEFAULT_STATE_PATH: &str = "/var/lib/aegis/honeypots.json";

/// Wire-format state — what's on disk and what the admin API reads /
/// writes verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotState {
    /// Master kill switch. When false the filter is a no-op
    /// regardless of per-pack toggles.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Pack ID → enabled. Missing entries default to true so a fresh
    /// install ships with everything on. Operators turn packs off
    /// only when they actually run the matching software.
    #[serde(default)]
    pub packs: HashMap<String, bool>,
    /// Per-host (Host: header value) overrides. `host -> pack_id ->
    /// enabled`. Anything not specified falls back to the global
    /// `packs` map. Star (`*`) hostname applies to everything.
    #[serde(default)]
    pub per_host: HashMap<String, HashMap<String, bool>>,
    /// Extra paths beyond the built-in packs. Same `/exact`,
    /// `/prefix/*`, `*/suffix` syntax as pack-internal patterns.
    #[serde(default)]
    pub custom_paths: Vec<String>,
    /// Tarpit response duration in seconds. 0 → reply with a normal
    /// 444/410 instead of holding the connection. Default 30 s.
    #[serde(default = "default_tarpit_seconds")]
    pub tarpit_seconds: u64,
    /// Bytes per tarpit chunk. The body emits one chunk every 5 s
    /// until the duration elapses. Default 50 — large enough to look
    /// like real progress, small enough to be cheap.
    #[serde(default = "default_tarpit_chunk_bytes")]
    pub tarpit_chunk_bytes: usize,
    /// Score added to the threat scorer on every honeypot hit.
    /// Default 50 — high enough to push a known-bad IP past the
    /// challenge threshold on its first hit.
    #[serde(default = "default_score_bump")]
    pub score_bump: u32,
    /// After this many honeypot hits from the same IP, automatically
    /// push the IP into the XDP deny set so future SYNs get dropped
    /// at line rate. 0 disables the auto-deny. Default 3.
    #[serde(default = "default_auto_xdp_deny_threshold")]
    pub auto_xdp_deny_threshold: u32,
    /// Fake banner emitted as `Server:` header on the tarpit response.
    /// Mimics vulnerable software to encourage the scanner to keep
    /// waiting for an exploit reply. Default: looks like an old
    /// Apache that hasn't been patched.
    #[serde(default = "default_server_header")]
    pub server_header: String,
    /// Hosts (lowercased) for which the honeypot filter is entirely
    /// bypassed, regardless of pack configuration. Use this for
    /// operator-owned WordPress or phpMyAdmin installations that would
    /// otherwise hit the built-in honeypot paths.
    ///
    /// The admin API writes to this via
    /// `PUT /admin/api/honeypots/host-enabled`. Absent in older JSON
    /// files — `#[serde(default)]` gives an empty set on load, so no
    /// migration is required.
    #[serde(default)]
    pub host_disabled: HashSet<String>,
}

fn default_true() -> bool {
    true
}
fn default_tarpit_seconds() -> u64 {
    30
}
fn default_tarpit_chunk_bytes() -> usize {
    50
}
fn default_score_bump() -> u32 {
    50
}
fn default_auto_xdp_deny_threshold() -> u32 {
    3
}
fn default_server_header() -> String {
    "Apache/2.4.41 (Ubuntu)".to_string()
}

impl Default for HoneypotState {
    fn default() -> Self {
        let mut packs = HashMap::new();
        for p in packs::BUILTIN_PACKS {
            packs.insert(p.id.to_string(), true);
        }
        Self {
            enabled: true,
            packs,
            per_host: HashMap::new(),
            custom_paths: Vec::new(),
            tarpit_seconds: default_tarpit_seconds(),
            tarpit_chunk_bytes: default_tarpit_chunk_bytes(),
            score_bump: default_score_bump(),
            auto_xdp_deny_threshold: default_auto_xdp_deny_threshold(),
            server_header: default_server_header(),
            host_disabled: HashSet::new(),
        }
    }
}

/// Compiled per-host view of the state — what the filter actually
/// queries on every request. Rebuilt whenever the state file changes.
struct Compiled {
    state: HoneypotState,
    /// host → matcher for the union of pack patterns enabled on that
    /// host. The empty-string key carries the matcher for hosts that
    /// have no specific overrides (i.e. inherit the global config).
    per_host_matchers: HashMap<String, HoneypotMatcher>,
    default_matcher: HoneypotMatcher,
}

impl Compiled {
    fn build(state: HoneypotState) -> Self {
        let default_matcher = compile_matcher_for_host(&state, None);
        let mut per_host_matchers = HashMap::new();
        for host in state.per_host.keys() {
            let m = compile_matcher_for_host(&state, Some(host));
            per_host_matchers.insert(host.clone(), m);
        }
        Self {
            state,
            per_host_matchers,
            default_matcher,
        }
    }

    fn matcher_for(&self, host: &str) -> &HoneypotMatcher {
        let host_lower = host.to_ascii_lowercase();
        self.per_host_matchers
            .get(&host_lower)
            .unwrap_or(&self.default_matcher)
    }
}

fn compile_matcher_for_host(state: &HoneypotState, host: Option<&str>) -> HoneypotMatcher {
    let host_overrides = host
        .and_then(|h| state.per_host.get(&h.to_ascii_lowercase()))
        .cloned()
        .unwrap_or_default();
    let mut patterns: Vec<String> = Vec::new();
    for p in packs::BUILTIN_PACKS {
        // Per-host override wins, then global, then default-on.
        let enabled = host_overrides
            .get(p.id)
            .copied()
            .or_else(|| state.packs.get(p.id).copied())
            .unwrap_or(true);
        if !enabled {
            continue;
        }
        for path in p.paths {
            patterns.push((*path).to_string());
        }
    }
    for p in &state.custom_paths {
        patterns.push(p.clone());
    }
    HoneypotMatcher::from_patterns(patterns)
}

/// Live store wrapping the on-disk JSON. mtime-checked per public
/// call so out-of-band edits (admin API, manual nano) reflect in the
/// next request.
pub struct HoneypotStore {
    path: PathBuf,
    inner: RwLock<Compiled>,
    last_mtime: Mutex<Option<SystemTime>>,
    /// V229 — refresh throttle. The previous impl ran `fs::metadata` +
    /// `meta.modified()` on every request (HoneypotFilter::check is on
    /// the per-request hot path). CPU profile on the stand showed
    /// `statx` at 24% of syscall time with ~12 calls/req; this was
    /// one of them. The atomic stores a microsecond timestamp of the
    /// last refresh; reads within the throttle window skip the stat
    /// entirely. 1s is fine — admin-API edits land within the next
    /// second window which is the same SLA the panel already shows.
    last_refresh_micros: std::sync::atomic::AtomicU64,
    refresh_start: std::time::Instant,
    /// Per-IP hit counter — backs the auto-XDP-deny path. V230 — was
    /// `Mutex<HashMap>`; replaced with a 16-shard `DashMap` so two
    /// concurrent scanners hitting the proxy from different IPs don't
    /// serialize on a single mutex during a burst. Hits are still
    /// relatively rare (only on actual honeypot matches), so 16 shards
    /// — rather than the 128 used by the hot-path maps in
    /// `threat_analytics`/`ja4_churn` — keeps the memory footprint
    /// small while still giving us shard-level contention isolation.
    hits_by_ip: DashMap<std::net::IpAddr, HitTally>,
}

const HONEYPOT_REFRESH_INTERVAL_MICROS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy)]
struct HitTally {
    count: u32,
    last_seen: std::time::Instant,
}

impl HoneypotStore {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).ok();
        }
        let state = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            let s = HoneypotState::default();
            write_atomic(&path, &s)?;
            s
        };
        let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        Ok(Self {
            path,
            inner: RwLock::new(Compiled::build(state)),
            last_mtime: Mutex::new(mtime),
            last_refresh_micros: std::sync::atomic::AtomicU64::new(0),
            refresh_start: std::time::Instant::now(),
            // V230 — 16 shards for the rare-hit map; see field doc.
            hits_by_ip: DashMap::with_shard_amount(16),
        })
    }

    fn refresh(&self) {
        // V229 — throttle the stat-and-reload to once per second. The
        // hot path (`check`) calls this on every request; without the
        // gate we burn ~1 statx syscall per request just to discover
        // the mtime didn't change. Atomic compare-exchange keeps the
        // common path lock-free.
        let now_micros = self.refresh_start.elapsed().as_micros() as u64;
        let last = self
            .last_refresh_micros
            .load(std::sync::atomic::Ordering::Relaxed);
        if now_micros.saturating_sub(last) < HONEYPOT_REFRESH_INTERVAL_MICROS {
            return;
        }
        // Even if multiple threads race here, the worst case is two
        // stat syscalls in the same window — still vastly cheaper than
        // one per request. Update first so concurrent waiters bail.
        self.last_refresh_micros
            .store(now_micros, std::sync::atomic::Ordering::Relaxed);

        let current = fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        let mut cached = self.last_mtime.lock().unwrap();
        if *cached == current {
            return;
        }
        if let Ok(raw) = fs::read_to_string(&self.path)
            && let Ok(state) = serde_json::from_str::<HoneypotState>(&raw)
        {
            let compiled = Compiled::build(state);
            *self.inner.write().unwrap() = compiled;
            *cached = current;
        }
    }

    /// True iff `path` for `host` should trigger the tarpit response.
    /// Returns None when honeypots are globally disabled or when the
    /// compiled matcher for this host is empty.
    pub fn check(&self, host: &str, path: &str) -> Option<HoneypotDecision> {
        self.refresh();
        let guard = self.inner.read().unwrap();
        // Fast path 1 — master kill switch. Already before any matcher
        // work, so no need to resolve `matcher_for` at all.
        if !guard.state.enabled {
            return None;
        }
        // Fast path 2 — per-host bypass. Operators who run their own
        // WordPress / phpMyAdmin mark those domains as trusted via
        // `PUT /admin/api/honeypots/host/enabled` (enabled=false). The
        // check is O(1) under the read lock already held above — no
        // extra synchronisation needed. `host` already arrives bare
        // and case-preserved from build_ctx (V238 normalises HTTP/2
        // :authority and HTTP/1.1 host:port both into the bare name);
        // lowercase here for case-insensitive membership.
        if guard
            .state
            .host_disabled
            .contains(&host.to_ascii_lowercase())
        {
            return None;
        }
        let matcher = guard.matcher_for(host);
        // Fast path 3 — empty matcher (all packs disabled for this host).
        // Skips `matcher.matches(path)` which calls `canonical_path`
        // (multi-pass percent-decode + dot-segment collapse) on every
        // request. In the default config all packs are ON so the matcher
        // is non-empty and this branch is never taken; it benefits
        // deployments that have disabled every pack for a given host or
        // globally.
        if matcher.is_empty() {
            return None;
        }
        if matcher.matches(path) {
            Some(HoneypotDecision {
                tarpit_seconds: guard.state.tarpit_seconds,
                tarpit_chunk_bytes: guard.state.tarpit_chunk_bytes,
                server_header: guard.state.server_header.clone(),
                score_bump: guard.state.score_bump,
                auto_xdp_deny_threshold: guard.state.auto_xdp_deny_threshold,
            })
        } else {
            None
        }
    }

    /// Record a hit from `ip`. Returns true when the per-IP hit count
    /// has crossed the auto-XDP-deny threshold — caller should add
    /// the IP to the XDP deny map.
    pub fn record_hit(&self, ip: std::net::IpAddr, threshold: u32) -> bool {
        if threshold == 0 {
            return false;
        }
        let now = std::time::Instant::now();
        // V230 — peek-first fast path. Once an IP has crossed threshold
        // it tends to keep hitting (that's the whole point of recording
        // hits — repeat offenders). `get_mut` only acquires the
        // shard's write lock on a HIT in the map, skipping the entry
        // API's vacant-slot bookkeeping for the common case. Falls
        // through to `entry` for first-time IPs.
        if let Some(mut tally) = self.hits_by_ip.get_mut(&ip) {
            tally.count = tally.count.saturating_add(1);
            tally.last_seen = now;
            return tally.count >= threshold;
        }
        // First-time IP — take the entry path. We re-check the slot
        // under the entry guard so a racing inserter doesn't lose a
        // hit (e.g. two concurrent hits from a brand-new IP).
        use dashmap::mapref::entry::Entry;
        match self.hits_by_ip.entry(ip) {
            Entry::Occupied(mut e) => {
                let tally = e.get_mut();
                tally.count = tally.count.saturating_add(1);
                tally.last_seen = now;
                tally.count >= threshold
            }
            Entry::Vacant(e) => {
                e.insert(HitTally {
                    count: 1,
                    last_seen: now,
                });
                1 >= threshold
            }
        }
    }

    /// Drop hit tallies older than `stale`. Called from the existing
    /// background cleanup task so the map doesn't accumulate stale
    /// IPs forever. V230 — confirmed off the per-request hot path:
    /// only the periodic GC task invokes this (see the spawn site in
    /// the daemon bootstrap), so it's safe for it to walk every shard
    /// and take per-shard write locks as `DashMap::retain` does.
    pub fn cleanup_stale(&self, now: std::time::Instant, stale: Duration) {
        self.hits_by_ip
            .retain(|_, tally| now.duration_since(tally.last_seen) <= stale);
    }

    /// Whole-state snapshot — for the admin API `GET /honeypots`.
    pub fn snapshot(&self) -> HoneypotState {
        self.refresh();
        self.inner.read().unwrap().state.clone()
    }

    /// Replace the whole state at once. Atomic file rename keeps the
    /// daemon from reading a half-written file.
    pub fn replace(&self, state: HoneypotState) -> anyhow::Result<()> {
        write_atomic(&self.path, &state)?;
        let mtime = fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok());
        *self.last_mtime.lock().unwrap() = mtime;
        *self.inner.write().unwrap() = Compiled::build(state);
        Ok(())
    }

    /// Toggle one pack at the global level.
    pub fn set_global_pack(&self, pack_id: &str, enabled: bool) -> anyhow::Result<()> {
        let mut snap = self.snapshot();
        snap.packs.insert(pack_id.to_string(), enabled);
        self.replace(snap)
    }

    /// Toggle one pack for a specific host.
    pub fn set_host_pack(&self, host: &str, pack_id: &str, enabled: bool) -> anyhow::Result<()> {
        let mut snap = self.snapshot();
        snap.per_host
            .entry(host.to_ascii_lowercase())
            .or_default()
            .insert(pack_id.to_string(), enabled);
        self.replace(snap)
    }

    /// Drop a per-host override entirely (host falls back to global).
    pub fn clear_host_override(&self, host: &str) -> anyhow::Result<()> {
        let mut snap = self.snapshot();
        snap.per_host.remove(&host.to_ascii_lowercase());
        self.replace(snap)
    }

    /// Enable or disable the honeypot filter for a specific host.
    ///
    /// `enabled = false` inserts the lowercased host into
    /// `HoneypotState.host_disabled`, causing `check()` to return
    /// `None` for that host without reaching the matcher. This is
    /// persisted to the on-disk JSON immediately via `replace()`.
    ///
    /// `enabled = true` removes the host from `host_disabled`,
    /// restoring the normal matcher-based evaluation.
    pub fn set_host_enabled(&self, host: &str, enabled: bool) -> anyhow::Result<()> {
        let mut snap = self.snapshot();
        let host_lower = host.to_ascii_lowercase();
        if enabled {
            snap.host_disabled.remove(&host_lower);
        } else {
            snap.host_disabled.insert(host_lower);
        }
        self.replace(snap)
    }

    /// Returns true when the honeypot filter is active for `host`
    /// (i.e. the host is NOT in the disabled set). This is the
    /// complement of a membership test on `host_disabled`.
    pub fn is_host_enabled(&self, host: &str) -> bool {
        self.refresh();
        let guard = self.inner.read().unwrap();
        !guard
            .state
            .host_disabled
            .contains(&host.to_ascii_lowercase())
    }

    /// Sorted list of hosts that have had the honeypot filter disabled
    /// via `set_host_enabled(host, false)`. For the admin API response.
    pub fn host_disabled_list(&self) -> Vec<String> {
        self.refresh();
        let guard = self.inner.read().unwrap();
        let mut list: Vec<String> = guard.state.host_disabled.iter().cloned().collect();
        list.sort();
        list
    }
}

#[derive(Debug, Clone)]
pub struct HoneypotDecision {
    pub tarpit_seconds: u64,
    pub tarpit_chunk_bytes: usize,
    pub server_header: String,
    pub score_bump: u32,
    pub auto_xdp_deny_threshold: u32,
}

fn write_atomic(path: &Path, state: &HoneypotState) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let raw = serde_json::to_string_pretty(state)?;
    fs::write(&tmp, raw)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-honeypot-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn fresh_install_blocks_built_in_paths() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        assert!(s.check("example.com", "/wp-login.php").is_some());
        assert!(s.check("example.com", "/.env").is_some());
        assert!(s.check("example.com", "/legitimate-page").is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn global_pack_disable() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        s.set_global_pack("wordpress", false).unwrap();
        assert!(s.check("any.example", "/wp-login.php").is_none());
        assert!(s.check("any.example", "/.env").is_some()); // secrets still on
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn per_host_override_wins_over_global() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        // global: wordpress ON. per-host: wordpress OFF for myblog.com.
        s.set_host_pack("myblog.com", "wordpress", false).unwrap();
        assert!(s.check("myblog.com", "/wp-login.php").is_none());
        assert!(s.check("other.com", "/wp-login.php").is_some());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        s.set_host_pack("MyBlog.com", "wordpress", false).unwrap();
        assert!(s.check("myblog.com", "/wp-login.php").is_none());
        assert!(s.check("MYBLOG.COM", "/wp-login.php").is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn custom_path_works() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        let mut snap = s.snapshot();
        snap.custom_paths.push("/super-secret".to_string());
        s.replace(snap).unwrap();
        assert!(s.check("x.com", "/super-secret").is_some());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn disabling_master_switch_turns_off_everything() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        let mut snap = s.snapshot();
        snap.enabled = false;
        s.replace(snap).unwrap();
        assert!(s.check("x.com", "/wp-login.php").is_none());
        assert!(s.check("x.com", "/.env").is_none());
        let _ = fs::remove_file(&p);
    }

    /// V236 — empty-matcher fast path: when every pack is disabled for a
    /// host the compiled matcher is empty and `check` must return `None`
    /// without calling `matcher.matches()` (which would otherwise run
    /// `canonical_path` on every request).
    #[test]
    fn empty_matcher_skips_match_work() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        // Disable every built-in pack at the global level. The resulting
        // default matcher is empty (no patterns). custom_paths is also
        // empty, so the matcher truly has nothing.
        let mut snap = s.snapshot();
        for key in snap.packs.keys().cloned().collect::<Vec<_>>() {
            snap.packs.insert(key, false);
        }
        s.replace(snap).unwrap();
        // Paths that would normally match must now return None.
        assert!(s.check("example.com", "/wp-login.php").is_none());
        assert!(s.check("example.com", "/.env").is_none());
        assert!(s.check("example.com", "/phpmyadmin/").is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn hit_threshold_returns_true_once_crossed() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        let ip = "1.2.3.4".parse().unwrap();
        assert!(!s.record_hit(ip, 3));
        assert!(!s.record_hit(ip, 3));
        assert!(s.record_hit(ip, 3));
        assert!(s.record_hit(ip, 3)); // stays true after crossing
        let _ = fs::remove_file(&p);
    }

    // ── V237 — host_disabled bypass ──────────────────────────────────

    /// A host in `host_disabled` must return None from check() even
    /// when its path would normally match a built-in pack pattern.
    #[test]
    fn host_disabled_returns_none() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        // Verify the path matches before disabling.
        assert!(s.check("blog.example.com", "/wp-login.php").is_some());
        s.set_host_enabled("blog.example.com", false).unwrap();
        assert!(s.check("blog.example.com", "/wp-login.php").is_none());
        // Case-insensitive: the stored key is lowercased.
        assert!(s.check("BLOG.EXAMPLE.COM", "/wp-login.php").is_none());
        assert!(s.check("Blog.Example.Com", "/.env").is_none());
        let _ = fs::remove_file(&p);
    }

    /// Disabling one host must not affect the matcher for other hosts.
    #[test]
    fn host_disabled_only_affects_that_host() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        s.set_host_enabled("trusted.example.com", false).unwrap();
        // Disabled host is bypassed.
        assert!(s.check("trusted.example.com", "/wp-login.php").is_none());
        // Other hosts still evaluated normally.
        assert!(s.check("other.example.com", "/wp-login.php").is_some());
        assert!(s.check("other.example.com", "/.env").is_some());
        let _ = fs::remove_file(&p);
    }

    /// JSON round-trip: `host_disabled` is serialised and deserialised
    /// correctly. An older JSON without the field loads as an empty set.
    #[test]
    fn host_disabled_json_round_trip() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        s.set_host_enabled("wp.example.com", false).unwrap();
        s.set_host_enabled("cms.example.com", false).unwrap();
        // Re-enable one of them.
        s.set_host_enabled("cms.example.com", true).unwrap();
        // Reload from disk into a fresh store.
        let s2 = HoneypotStore::open(p.clone()).unwrap();
        let disabled = s2.host_disabled_list();
        assert_eq!(disabled, vec!["wp.example.com".to_string()]);
        assert!(!s2.is_host_enabled("wp.example.com"));
        assert!(s2.is_host_enabled("cms.example.com"));
        // Older JSON without `host_disabled` field deserialises fine.
        let legacy_json = r#"{"enabled":true,"packs":{},"per_host":{},"custom_paths":[],"tarpit_seconds":30,"tarpit_chunk_bytes":50,"score_bump":50,"auto_xdp_deny_threshold":3,"server_header":"Apache/2.4.41 (Ubuntu)"}"#;
        let legacy_state: HoneypotState = serde_json::from_str(legacy_json).unwrap();
        assert!(legacy_state.host_disabled.is_empty());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn external_edit_reloads_on_mtime_change() {
        let p = tmp();
        let s = HoneypotStore::open(p.clone()).unwrap();
        assert!(s.check("x.com", "/wp-login.php").is_some());
        // Simulate an out-of-band edit.
        let mut snap = s.snapshot();
        snap.enabled = false;
        let raw = serde_json::to_string_pretty(&snap).unwrap();
        fs::write(&p, raw).unwrap();
        // V229 — the refresh path is throttled to once per second so the
        // hot path doesn't issue a statx syscall on every request. Wait
        // past the throttle window so the next check picks up the new
        // mtime and disables the filter.
        std::thread::sleep(Duration::from_millis(1100));
        assert!(s.check("x.com", "/wp-login.php").is_none());
        let _ = fs::remove_file(&p);
    }
}
