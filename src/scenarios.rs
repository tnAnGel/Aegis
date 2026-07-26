//! V199 — CrowdSec-style leaky-bucket scenario DSL.
//!
//! Today Aegis's rate-limit knobs are flat (`rps`, `burst`,
//! `per-host`). Expressing "10 distinct 4xx responses from one IP
//! within 10 seconds" requires writing Rust. CrowdSec showed that
//! a tiny YAML DSL covers 90% of behavioural detection without
//! code changes.
//!
//! ## Grammar (subset we ship)
//!
//! ```yaml
//! name: http_login_brute
//! description: "Many 401s to /login from one IP"
//! filter:
//!   path_prefix: /login
//!   status_min: 400
//!   status_max: 499
//! groupby: client_ip       # bucket key
//! distinct: path           # optional — count only unique values
//! capacity: 10             # bucket size
//! leak_speed: 10s          # one token leaks every 10s
//! blackhole: 5m            # block target for 5 min
//! action: block            # block | challenge | tarpit | log
//! ```
//!
//! Buckets are per (`scenario_name`, `groupby_value`). Each
//! matching event adds 1 token (or 1 only when `distinct` value
//! hasn't been seen in this bucket yet). When tokens >= capacity,
//! the scenario fires: `action` is dispatched against `groupby_value`
//! via the V197 actuator framework with the configured `blackhole`
//! TTL.
//!
//! ## Events
//!
//! Scenarios match against a [ScenarioEvent] — caller (proxy
//! request-filter / logging phase) populates the fields it has and
//! the engine evaluates every loaded scenario against the event.
//! Unknown fields in the filter cause the predicate to short-circuit
//! `false` (safe default — under-blocks rather than over-blocks).
//!
//! ## Why not just wirefilter for the filter
//!
//! Wirefilter is great for raw HTTP matching but doesn't carry the
//! stateful "N events in T time" semantics. The DSL composes:
//! `filter` is the event-predicate (can be a wirefilter expression
//! string in a future revision; today it's a typed struct), and the
//! bucket layer adds the time-window state.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct ScenarioConfig {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub filter: ScenarioFilter,
    pub groupby: GroupBy,
    #[serde(default)]
    pub distinct: Option<DistinctField>,
    pub capacity: u32,
    #[serde(deserialize_with = "deserialize_duration")]
    pub leak_speed: Duration,
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub blackhole: Option<Duration>,
    pub action: ScenarioAction,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
#[serde(default)]
pub struct ScenarioFilter {
    pub method: Option<String>,
    pub path_prefix: Option<String>,
    pub path_contains: Option<String>,
    pub path_suffix: Option<String>,
    pub host: Option<String>,
    pub user_agent_contains: Option<String>,
    pub status: Option<u16>,
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
    pub asn: Option<u32>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    ClientIp,
    ClientIpUserAgent,
    Host,
    HostPath,
    UserAgent,
    Asn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DistinctField {
    Path,
    UserAgent,
    Host,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioAction {
    Block,
    Challenge,
    Tarpit,
    Log,
}

#[derive(Debug, Clone)]
pub struct ScenarioEvent {
    pub client_ip: IpAddr,
    pub method: String,
    pub host: String,
    pub path: String,
    pub user_agent: Option<String>,
    pub status: Option<u16>,
    pub asn: Option<u32>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FireOutcome {
    Quiet,
    Bucketed {
        tokens: u32,
        capacity: u32,
    },
    Fired {
        target: String,
        action: ScenarioAction,
        blackhole: Option<Duration>,
    },
}

#[derive(Debug)]
struct BucketState {
    tokens: u32,
    last_observed: Instant,
    last_leak: Instant,
    distinct_seen: HashSet<String>,
    recent: VecDeque<Instant>,
}

#[derive(Debug, Default)]
pub struct ScenarioStats {
    pub events_observed: AtomicU64,
    pub events_matched: AtomicU64,
    pub events_bucketed: AtomicU64,
    pub buckets_fired: AtomicU64,
}

pub struct ScenarioEngine {
    scenarios: RwLock<Vec<ScenarioConfig>>,
    // DashMap gives per-shard locking — no global write barrier when
    // two different bucket keys hit the engine in parallel.
    buckets: DashMap<(String, String), BucketState>,
    stats: ScenarioStats,
    // Fast empty-gate: flipped to true on the first `load`/`load_many`.
    // Lets `observe()` short-circuit with a single relaxed atomic
    // load in the default no-scenarios-configured case (the hot
    // logging path runs per request).
    loaded: AtomicBool,
    // V246 — cross-worker persistence (mirrors the V245 challenge-config
    // pattern). When set, `save_yaml` writes the operator's raw YAML
    // atomically and `maybe_reload` mtime-polls it, so a panel "load" on
    // one SO_REUSEPORT worker converges across the whole fleet and
    // survives restart. None = in-memory only (legacy behaviour).
    persist_path: RwLock<Option<PathBuf>>,
    last_mtime: Mutex<Option<SystemTime>>,
}

impl Default for ScenarioEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScenarioEngine {
    pub fn new() -> Self {
        Self {
            scenarios: RwLock::new(Vec::new()),
            // V230 — 128 shards (default is ~4*ncpu, typically 16-64). Bucket
            // keys are (scenario_name, groupby_value); a busy edge sees
            // thousands of distinct client_ip groups hammering the same map.
            // More shards => narrower critical sections under heavy
            // observe() concurrency.
            buckets: DashMap::with_shard_amount(128),
            stats: ScenarioStats::default(),
            loaded: AtomicBool::new(false),
            persist_path: RwLock::new(None),
            last_mtime: Mutex::new(None),
        }
    }

    pub fn load(&self, cfg: ScenarioConfig) {
        self.scenarios.write().unwrap().push(cfg);
        self.loaded.store(true, Ordering::Relaxed);
    }

    /// V246 — REPLACE the scenario set with `cfgs` (was append/extend,
    /// which duplicated rules every time the panel re-loaded and made an
    /// empty load a no-op instead of a clear). The panel "Load" submits
    /// the full desired set, so replace is the correct semantic.
    pub fn load_many(&self, cfgs: Vec<ScenarioConfig>) {
        let has = !cfgs.is_empty();
        *self.scenarios.write().unwrap() = cfgs;
        self.loaded.store(has, Ordering::Relaxed);
    }

    /// V246 — wire a disk file for cross-worker persistence + restart
    /// durability. Loads any existing file immediately; thereafter each
    /// worker mtime-reloads it via `maybe_reload` on the background tick.
    /// Call once at startup (bin/aegis-pingora.rs), like the V245 challenge
    /// persistence.
    pub fn set_persistence(&self, path: PathBuf) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        *self.persist_path.write().unwrap() = Some(path);
        self.reload_from_disk(true);
    }

    /// Persist the operator's RAW YAML atomically. We store the source
    /// text (not the parsed structs) because `leak_speed`/`blackhole`
    /// deserialize from human strings ("10s") but would serialize to
    /// `{secs,nanos}`, which the YAML parser then rejects on reload.
    /// No-op when no persistence path is wired.
    pub fn save_yaml(&self, yaml: &str) {
        let Some(path) = self.persist_path.read().unwrap().clone() else {
            return;
        };
        let tmp = path.with_extension("yaml.tmp");
        if std::fs::write(&tmp, yaml.as_bytes()).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            if let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) {
                *self.last_mtime.lock().unwrap() = Some(m);
            }
        }
    }

    /// mtime-poll the persistence file and REPLACE the in-memory set when
    /// it changed. Cheap stat() on the common no-change path. Called from
    /// the background tick in every worker so a panel "Load" on one worker
    /// propagates to the whole REUSEPORT fleet within one polling window.
    pub fn maybe_reload(&self) -> bool {
        self.reload_from_disk(false)
    }

    fn reload_from_disk(&self, force: bool) -> bool {
        let Some(path) = self.persist_path.read().unwrap().clone() else {
            return false;
        };
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if !force && mtime == *self.last_mtime.lock().unwrap() {
            return false;
        }
        let Ok(yaml) = std::fs::read_to_string(&path) else {
            return false;
        };
        match Self::parse_yaml(&yaml) {
            Ok(cfgs) => {
                let has = !cfgs.is_empty();
                *self.scenarios.write().unwrap() = cfgs;
                self.loaded.store(has, Ordering::Relaxed);
                *self.last_mtime.lock().unwrap() = mtime;
                true
            }
            Err(_) => false,
        }
    }

    /// Fast-path query: have any scenarios been loaded? Single
    /// relaxed atomic load — callers on hot paths can skip the full
    /// `observe()` cost (RwLock acquisition + per-scenario loop)
    /// when the default empty-config state is active.
    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Relaxed)
    }

    pub fn parse_yaml(yaml: &str) -> Result<Vec<ScenarioConfig>, String> {
        // Allow either a single scenario or a list.
        if let Ok(list) = serde_yml::from_str::<Vec<ScenarioConfig>>(yaml) {
            return Ok(list);
        }
        serde_yml::from_str::<ScenarioConfig>(yaml)
            .map(|s| vec![s])
            .map_err(|e| format!("yaml: {e}"))
    }

    pub fn scenarios(&self) -> Vec<ScenarioConfig> {
        self.scenarios.read().unwrap().clone()
    }

    /// V230 — cheap emptiness check that avoids cloning the inner
    /// `Vec<ScenarioConfig>`. Callers like the request-filter pipeline
    /// used `arsenal.scenarios.scenarios().is_empty()`, which cloned
    /// every loaded `ScenarioConfig` just to read `.is_empty()`. Reads
    /// the atomic `loaded` gate directly: until `load`/`load_many`
    /// fires, the inner Vec is guaranteed empty; afterwards it is
    /// guaranteed non-empty (we never remove). Single relaxed atomic
    /// load, no RwLock acquisition, no allocation.
    pub fn is_empty(&self) -> bool {
        !self.loaded.load(Ordering::Relaxed)
    }

    /// V230 — cheap count accessor. Falls back to the RwLock only
    /// when the empty-gate says scenarios exist; the hot
    /// no-scenarios-configured path stays allocation-free.
    pub fn len(&self) -> usize {
        if !self.loaded.load(Ordering::Relaxed) {
            return 0;
        }
        self.scenarios.read().unwrap().len()
    }

    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            events_observed: self.stats.events_observed.load(Ordering::Relaxed),
            events_matched: self.stats.events_matched.load(Ordering::Relaxed),
            events_bucketed: self.stats.events_bucketed.load(Ordering::Relaxed),
            buckets_fired: self.stats.buckets_fired.load(Ordering::Relaxed),
        }
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Run an event through every loaded scenario. Returns a vector
    /// of outcomes in scenario load order — non-matches included as
    /// [FireOutcome::Quiet] so caller can correlate by index.
    pub fn observe(&self, event: &ScenarioEvent) -> Vec<FireOutcome> {
        // Fast path: no scenarios configured. The hot logging path
        // calls this per request; bail before touching the RwLock or
        // cloning the Vec<ScenarioConfig>. Single relaxed atomic load.
        if !self.loaded.load(Ordering::Relaxed) {
            return Vec::new();
        }
        self.stats.events_observed.fetch_add(1, Ordering::Relaxed);
        // V230 — borrow the inner Vec under the read guard instead of
        // cloning it. The previous code did `self.scenarios.read().unwrap().clone()`,
        // duplicating every ScenarioConfig (each carrying heap strings
        // for `name`, `description`, filter fields) on every request.
        // We hold the RwLock read guard for the duration of the loop;
        // nothing inside touches `self.scenarios`, so there is no
        // re-entrant lock risk. Concurrent observe() callers all take
        // shared read locks and proceed in parallel. The only loser is
        // a concurrent `load`/`load_many` writer, which is a config
        // path and not hot.
        let guard = self.scenarios.read().unwrap();
        let scenarios: &[ScenarioConfig] = guard.as_slice();
        let mut out = Vec::with_capacity(scenarios.len());
        for sc in scenarios {
            if !filter_matches(&sc.filter, event) {
                out.push(FireOutcome::Quiet);
                continue;
            }
            self.stats.events_matched.fetch_add(1, Ordering::Relaxed);
            let group_key = group_value(sc.groupby, event);
            // V230 — build the bucket key with a single fresh String pair
            // and pass ownership straight into `entry`. The previous code
            // bound `bucket_key` to a local and then cloned it again at
            // the `entry()` call site, doubling the (String, String)
            // allocation per matched event. `sc.name.clone()` is one
            // unavoidable owned-String cost (DashMap needs an owned key);
            // we clone `group_key` because we still need it later for
            // `FireOutcome::Fired { target: group_key, .. }`.
            let distinct_value = sc
                .distinct
                .map(|d| distinct_value(d, event))
                .unwrap_or_default();

            // DashMap entry pattern: only this bucket's shard is
            // contended, not the whole map. Returns a RefMut guard
            // we can mutate directly.
            let mut state = self
                .buckets
                .entry((sc.name.clone(), group_key.clone()))
                .or_insert_with(|| BucketState {
                    tokens: 0,
                    last_observed: Instant::now(),
                    last_leak: Instant::now(),
                    distinct_seen: HashSet::new(),
                    recent: VecDeque::new(),
                });
            // Leak first — every full leak_speed tick drops a token.
            let elapsed = Instant::now().saturating_duration_since(state.last_leak);
            let leak_ticks = (elapsed.as_secs_f64() / sc.leak_speed.as_secs_f64()).floor() as u32;
            if leak_ticks > 0 {
                state.tokens = state.tokens.saturating_sub(leak_ticks);
                state.last_leak = Instant::now();
            }
            state.last_observed = Instant::now();
            // Distinct: only count if value not seen before in this
            // bucket window.
            // NOTE: `distinct_seen.insert()` is load-bearing — it both tests
            // membership and records it. Do not "simplify" this to
            // `sc.distinct.is_none()`: that drops the side effect and makes a
            // scenario with `distinct` set never count anything.
            #[allow(clippy::match_like_matches_macro)]
            let should_count = match sc.distinct {
                Some(_) if !state.distinct_seen.insert(distinct_value) => false,
                _ => true,
            };
            if should_count {
                state.tokens = state.tokens.saturating_add(1);
                state.recent.push_back(Instant::now());
                if state.recent.len() > 256 {
                    state.recent.pop_front();
                }
                self.stats.events_bucketed.fetch_add(1, Ordering::Relaxed);
            }
            let tokens = state.tokens;
            let cap = sc.capacity;
            // Fire when tokens hit capacity. Operator-friendly
            // semantic: `capacity: 10` means "10 strikes and you're
            // out" (CrowdSec's docs use OVERFLOW = exceeded, we use
            // saturated; if operators want overflow-only behaviour
            // they bump capacity by 1).
            if tokens >= cap {
                // Reset on fire so we don't fire every event after
                // overflow until the leak catches up — operator wants
                // the action applied once with the blackhole TTL.
                state.tokens = 0;
                state.distinct_seen.clear();
                state.recent.clear();
                // Release the per-bucket shard lock before bumping
                // shared counters / pushing the result.
                drop(state);
                self.stats.buckets_fired.fetch_add(1, Ordering::Relaxed);
                out.push(FireOutcome::Fired {
                    target: group_key,
                    action: sc.action,
                    blackhole: sc.blackhole,
                });
            } else {
                drop(state);
                out.push(FireOutcome::Bucketed {
                    tokens,
                    capacity: cap,
                });
            }
        }
        out
    }

    /// GC stale buckets (no observations within `idle`).
    pub fn gc(&self, idle: Duration) -> usize {
        let now = Instant::now();
        let before = self.buckets.len();
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.last_observed) < idle);
        before - self.buckets.len()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StatsSnapshot {
    pub events_observed: u64,
    pub events_matched: u64,
    pub events_bucketed: u64,
    pub buckets_fired: u64,
}

fn filter_matches(f: &ScenarioFilter, event: &ScenarioEvent) -> bool {
    if let Some(m) = &f.method
        && !event.method.eq_ignore_ascii_case(m)
    {
        return false;
    }
    if let Some(prefix) = &f.path_prefix
        && !event.path.starts_with(prefix)
    {
        return false;
    }
    if let Some(c) = &f.path_contains
        && !event.path.contains(c)
    {
        return false;
    }
    if let Some(s) = &f.path_suffix
        && !event.path.ends_with(s)
    {
        return false;
    }
    if let Some(h) = &f.host
        && !event.host.eq_ignore_ascii_case(h)
    {
        return false;
    }
    if let Some(uac) = &f.user_agent_contains {
        let ua = event.user_agent.as_deref().unwrap_or("");
        if !ua.to_ascii_lowercase().contains(&uac.to_ascii_lowercase()) {
            return false;
        }
    }
    if let Some(s) = f.status
        && event.status != Some(s)
    {
        return false;
    }
    if let Some(min) = f.status_min
        && event.status.is_none_or(|s| s < min)
    {
        return false;
    }
    if let Some(max) = f.status_max
        && event.status.is_none_or(|s| s > max)
    {
        return false;
    }
    if let Some(asn) = f.asn
        && event.asn != Some(asn)
    {
        return false;
    }
    if let Some(c) = &f.country
        && event.country.as_deref() != Some(c.as_str())
    {
        return false;
    }
    true
}

fn group_value(by: GroupBy, event: &ScenarioEvent) -> String {
    match by {
        GroupBy::ClientIp => event.client_ip.to_string(),
        GroupBy::ClientIpUserAgent => {
            let ua = event.user_agent.as_deref().unwrap_or("");
            format!("{}|{}", event.client_ip, ua)
        }
        GroupBy::Host => event.host.clone(),
        GroupBy::HostPath => format!("{}|{}", event.host, event.path),
        GroupBy::UserAgent => event.user_agent.clone().unwrap_or_default(),
        GroupBy::Asn => event.asn.map(|a| a.to_string()).unwrap_or_default(),
    }
}

fn distinct_value(field: DistinctField, event: &ScenarioEvent) -> String {
    match field {
        DistinctField::Path => event.path.clone(),
        DistinctField::UserAgent => event.user_agent.clone().unwrap_or_default(),
        DistinctField::Host => event.host.clone(),
        DistinctField::Status => event.status.map(|s| s.to_string()).unwrap_or_default(),
    }
}

fn deserialize_duration<'de, D>(de: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(de)?;
    parse_duration_str(&s).map_err(serde::de::Error::custom)
}

fn deserialize_optional_duration<'de, D>(de: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt {
        None => Ok(None),
        Some(s) => parse_duration_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

fn parse_duration_str(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        return num
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| e.to_string());
    }
    let (num_part, mult) = if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400)
    } else {
        (s, 1) // bare seconds
    };
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("parse {num_part:?}: {e}"))?;
    Ok(Duration::from_secs(n * mult))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn evt() -> ScenarioEvent {
        ScenarioEvent {
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            method: "POST".into(),
            host: "x.com".into(),
            path: "/login".into(),
            user_agent: Some("curl/8".into()),
            status: Some(401),
            asn: Some(12345),
            country: Some("US".into()),
        }
    }

    fn parse(yaml: &str) -> ScenarioConfig {
        ScenarioEngine::parse_yaml(yaml)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn yaml_parses_typical_scenario() {
        let yaml = r#"
name: http_login_brute
filter:
  path_prefix: /login
  status_min: 400
  status_max: 499
groupby: client_ip
distinct: path
capacity: 10
leak_speed: 10s
blackhole: 5m
action: block
"#;
        let s = parse(yaml);
        assert_eq!(s.name, "http_login_brute");
        assert_eq!(s.capacity, 10);
        assert_eq!(s.leak_speed, Duration::from_secs(10));
        assert_eq!(s.blackhole, Some(Duration::from_secs(300)));
        assert_eq!(s.distinct, Some(DistinctField::Path));
        assert_eq!(s.action, ScenarioAction::Block);
    }

    #[test]
    fn fires_when_capacity_reached() {
        let yaml = r#"
name: q
filter:
  path_prefix: /login
groupby: client_ip
capacity: 3
leak_speed: 1h
blackhole: 5m
action: block
"#;
        let e = ScenarioEngine::new();
        e.load(parse(yaml));
        let r1 = &e.observe(&evt())[0];
        assert!(matches!(r1, FireOutcome::Bucketed { tokens: 1, .. }));
        let r2 = &e.observe(&evt())[0];
        assert!(matches!(r2, FireOutcome::Bucketed { tokens: 2, .. }));
        let r3 = &e.observe(&evt())[0];
        match r3 {
            FireOutcome::Fired {
                target,
                action,
                blackhole,
            } => {
                assert_eq!(target, "10.0.0.1");
                assert_eq!(*action, ScenarioAction::Block);
                assert_eq!(*blackhole, Some(Duration::from_secs(300)));
            }
            other => panic!("expected Fired, got {other:?}"),
        }
    }

    #[test]
    fn distinct_dedups_repeats_in_window() {
        let yaml = r#"
name: q
filter:
  path_prefix: /
groupby: client_ip
distinct: path
capacity: 3
leak_speed: 1h
blackhole: 5m
action: block
"#;
        let e = ScenarioEngine::new();
        e.load(parse(yaml));
        let mut ev = evt();
        ev.path = "/a".into();
        e.observe(&ev);
        e.observe(&ev);
        e.observe(&ev);
        let last = &e.observe(&ev)[0];
        assert!(matches!(last, FireOutcome::Bucketed { tokens: 1, .. }));
        ev.path = "/b".into();
        e.observe(&ev); // tokens=2
        ev.path = "/c".into();
        let fire = &e.observe(&ev)[0]; // tokens=3 → fires (>=)
        assert!(matches!(fire, FireOutcome::Fired { .. }));
    }

    #[test]
    fn filter_status_range_excludes_2xx() {
        let yaml = r#"
name: q
filter:
  status_min: 400
  status_max: 499
groupby: client_ip
capacity: 1
leak_speed: 1h
action: block
"#;
        let e = ScenarioEngine::new();
        e.load(parse(yaml));
        let mut ev = evt();
        ev.status = Some(200);
        assert!(matches!(e.observe(&ev)[0], FireOutcome::Quiet));
        ev.status = Some(401);
        assert!(matches!(e.observe(&ev)[0], FireOutcome::Fired { .. }));
    }

    #[test]
    fn groupby_isolates_buckets_per_ip() {
        let yaml = r#"
name: q
filter:
  path_prefix: /
groupby: client_ip
capacity: 2
leak_speed: 1h
action: block
"#;
        let e = ScenarioEngine::new();
        e.load(parse(yaml));
        let mut ev1 = evt();
        ev1.client_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mut ev2 = evt();
        ev2.client_ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        // capacity=2, semantic >=: 2nd obs fires.
        let r1 = &e.observe(&ev1)[0];
        assert!(matches!(r1, FireOutcome::Bucketed { tokens: 1, .. }));
        let fire = &e.observe(&ev1)[0];
        assert!(matches!(fire, FireOutcome::Fired { target, .. } if target == "1.1.1.1"));
        // ev2's bucket: independent state, 1 token after first obs.
        let r2 = &e.observe(&ev2)[0];
        assert!(matches!(r2, FireOutcome::Bucketed { tokens: 1, .. }));
        assert_eq!(e.bucket_count(), 2);
    }

    #[test]
    fn leak_drains_tokens_over_time() {
        let yaml = r#"
name: q
filter:
  path_prefix: /
groupby: client_ip
capacity: 3
leak_speed: 50ms
action: block
"#;
        let e = ScenarioEngine::new();
        e.load(parse(yaml));
        e.observe(&evt());
        e.observe(&evt());
        std::thread::sleep(Duration::from_millis(120));
        let r = &e.observe(&evt())[0];
        // Two leaked, +1 new = should be 1 token, NOT 3.
        assert!(matches!(r, FireOutcome::Bucketed { tokens: 1, .. }));
    }

    #[test]
    fn parse_duration_supports_units() {
        assert_eq!(
            parse_duration_str("100ms").unwrap(),
            Duration::from_millis(100)
        );
        assert_eq!(parse_duration_str("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration_str("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration_str("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(
            parse_duration_str("1d").unwrap(),
            Duration::from_secs(86_400)
        );
        assert_eq!(parse_duration_str("30").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn yaml_list_parses_multiple_scenarios() {
        let yaml = r#"
- name: a
  filter:
    path_prefix: /a
  groupby: client_ip
  capacity: 5
  leak_speed: 10s
  action: block
- name: b
  filter:
    path_prefix: /b
  groupby: host
  capacity: 100
  leak_speed: 1m
  action: challenge
"#;
        let v = ScenarioEngine::parse_yaml(yaml).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "a");
        assert_eq!(v[1].action, ScenarioAction::Challenge);
    }

    #[test]
    fn gc_drops_idle_buckets() {
        let yaml = r#"
name: q
filter:
  path_prefix: /
groupby: client_ip
capacity: 100
leak_speed: 1h
action: block
"#;
        let e = ScenarioEngine::new();
        e.load(parse(yaml));
        e.observe(&evt());
        assert_eq!(e.bucket_count(), 1);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(e.gc(Duration::from_millis(20)), 1);
        assert_eq!(e.bucket_count(), 0);
    }

    #[test]
    fn observe_short_circuits_when_no_scenarios_loaded() {
        // Empty-gate fast path: nothing loaded → no stats bumped,
        // no buckets created, empty Vec returned.
        let e = ScenarioEngine::new();
        assert!(!e.is_loaded());
        let out = e.observe(&evt());
        assert!(out.is_empty());
        let s = e.stats();
        assert_eq!(s.events_observed, 0);
        assert_eq!(s.events_matched, 0);
        assert_eq!(e.bucket_count(), 0);
    }

    #[test]
    fn is_loaded_flips_on_load() {
        let e = ScenarioEngine::new();
        assert!(!e.is_loaded());
        let yaml = r#"
name: q
groupby: client_ip
capacity: 1
leak_speed: 1h
action: block
"#;
        e.load(parse(yaml));
        assert!(e.is_loaded());
    }
}
