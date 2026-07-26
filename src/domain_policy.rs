//! V162 — per-domain policy overrides.
//!
//! Until now every filter was globally on/off via the V160
//! RuntimeToggles. Real operators want different policy per host:
//!   * "api.example.com" enforces WAF + rate limit but no challenge
//!   * "admin.example.com" runs every filter on max
//!   * "static.example.com" disables WAF (no user input there)
//!
//! [DomainPolicyStore] holds per-host overrides; the filter engine
//! checks it before falling back to the global RuntimeToggles. Per-
//! endpoint controls (V166) are a separate layer that sits on top of
//! this — same shape, finer grain.
//!
//! ## Storage shape
//!
//! ```text
//!   host → DomainPolicy {
//!       filter_enabled: HashMap<filter_name, bool>,    // overrides
//!       ...future fields (custom rules, captcha provider choice, etc.)
//!   }
//! ```
//!
//! Lookup is `O(1)` hashmap on the request's Host header; missing
//! entry = no override = fall through to global.
//!
//! ## Persistence
//!
//! In-memory only for V162. Operators that want survival edit the
//! site's managed `.conf` and the next reload re-applies. V164 adds
//! a JSON-on-disk persistence layer alongside the in-memory store
//! so admin-UI mutations survive process restart without a manual
//! config edit.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// V166 — per-endpoint decision short-circuit. When set on a host,
/// requests whose path matches `pattern` get the corresponding action
/// applied BEFORE the regular filter chain. Use cases:
///   * `Block` on `/wp-admin/*` for a non-WordPress site
///   * `Challenge` on `/login` to gate auth attempts via the ladder
///   * `Tarpit` on `/.env` so scanners get slow-streamed garbage
///   * `Allow` on `/health` to skip the chain entirely for monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAction {
    /// Bypass the filter chain — request gets through unconditionally
    /// (still subject to upstream behaviour).
    Allow,
    /// Hard 403 — never touches upstream, never challenges.
    Block,
    /// Force the V42 challenge ladder for this path even if challenge
    /// is otherwise disabled. Effective for gating /login, /admin/*,
    /// password-reset endpoints.
    Challenge,
    /// Route into the V147 poisoned tarpit (5s Markov page). Hot
    /// favourite for /.git/config, /.env, /wp-config.php traffic
    /// that's never legitimate.
    Tarpit,
}

impl EndpointAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Challenge => "challenge",
            Self::Tarpit => "tarpit",
        }
    }
}

/// V234 — per-host rate-limit override carried in [`DomainPolicy`].
/// `rps` is the steady-state token refill rate (requests/sec) and
/// `burst` is the bucket capacity (max instantaneous spend). Both are
/// per-IP, matching the global filter's semantics. Stored as `u64`
/// because the panel and config both express limits as whole requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitOverride {
    pub rps: u64,
    pub burst: u64,
}

/// One host's policy bundle. Empty by default — every field is an
/// override that, when None, falls back to global config.
///
/// V230 — manual `Clone` impl (instead of derived) so the
/// `sorted_matchers` cache resets on clone rather than depending on
/// `OnceLock<T>: Clone` (only stable since Rust 1.85). Resetting the
/// cache on clone is also semantically right: an independent copy of
/// the policy should rebuild its own matcher list from its own
/// `endpoint_policies` rather than share a borrowed cache.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DomainPolicy {
    /// Per-filter on/off override. Filter name → enabled. Missing key
    /// means "no override, use global". Filter names match the same
    /// `&'static str` identifiers TrafficFilter::name() returns
    /// (e.g., "waf", "bot", "challenge", "rate_limit").
    #[serde(default)]
    pub filter_enabled: std::collections::HashMap<String, bool>,
    /// V166 — per-endpoint short-circuit actions. Patterns support:
    ///   * `/foo`     — exact match
    ///   * `/foo/*`   — prefix match (anything under `/foo/`)
    ///   * `*/foo`    — suffix match (e.g. `*/.env` matches any path
    ///                  ending in `/.env`)
    /// First match wins; lookup is linear over the host's pattern set
    /// (operators typically have O(10²) per host, which is fine).
    #[serde(default)]
    pub endpoint_policies: std::collections::HashMap<String, EndpointAction>,
    /// V234 — per-host rate-limit override. When `Some`, this host's
    /// requests are throttled at `(rps, burst)` instead of the global
    /// `[filters.rate_limit]` defaults (or any static `domain_limits`
    /// entry). `None` means "no override, use global/static config".
    ///
    /// This is the runtime overlay path that works for ops-managed
    /// sites too: unlike `[rate_limit]` in a `.conf`, it is set through
    /// the admin API (`PUT /admin/api/sites/<host>/policy`) and is
    /// disk-backed + cross-worker, so the panel can change a per-host
    /// limit without editing (read-only) site config files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitOverride>,
    /// V230 — lazily-built sorted matcher cache. `endpoint_action`
    /// previously sorted `endpoint_policies.keys()` and called `format!`
    /// inside `path_matches` on every request. Now the sort happens
    /// once (first call) and the result is stored here as
    /// `Arc<Vec<(pattern, action, kind)>>` with prefix-slashes already
    /// stitched. Reads are zero-alloc after the first hit.
    ///
    /// `#[serde(skip)]` because the cache is derived from
    /// `endpoint_policies`; it must never be persisted (and reloaded
    /// stores reset it via `Default::default()`).
    #[serde(skip, default)]
    pub(crate) sorted_matchers: OnceLock<Arc<Vec<CompiledMatcher>>>,
}

/// V230 — compiled endpoint pattern. `kind` records which arm of
/// `path_matches` to take so we don't re-parse the pattern string on
/// every request. `needle` is the body of the pattern with the prefix
/// or suffix sigil stripped and the joining slash pre-formatted (so
/// the request-time check is a single `starts_with` / `ends_with` /
/// `==` against an already-owned `String`).
#[derive(Debug, Clone)]
pub(crate) struct CompiledMatcher {
    /// Pre-formatted needle. For `Prefix`, this is the path WITH the
    /// trailing slash already stitched on (so the runtime check is a
    /// single `path.starts_with(&needle)` — no `format!("{prefix}/")`
    /// per request). For `Suffix`, this is `/{suffix}` so `ends_with`
    /// matches directly. For `Exact`, the literal pattern.
    needle: String,
    /// Extra equality candidate. For `Prefix`, the bare prefix without
    /// the trailing slash (so `/foo/*` matches `/foo` exactly as well
    /// as `/foo/...`). For `Suffix`, the bare suffix (so `*/foo` also
    /// matches a path equal to just `foo`). None for `Exact`.
    exact_alias: Option<String>,
    kind: MatchKind,
    action: EndpointAction,
}

/// V230 — match arm tag. Keeps the per-request branch simple and avoids
/// reparsing the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    /// Pattern is `/foo` — request path must equal `needle`.
    Exact,
    /// Pattern is `/foo/*` — request matches if `path == exact_alias`
    /// OR `path.starts_with(needle)` (where `needle = "/foo/"`).
    Prefix,
    /// Pattern is `*/foo` — request matches if `path.ends_with(needle)`
    /// (where `needle = "/foo"`) OR equals the bare `foo` portion.
    Suffix,
}

impl Clone for DomainPolicy {
    /// V230 — `sorted_matchers` is a derived cache, not state. Clones
    /// start with an empty `OnceLock` and re-compile on first
    /// `endpoint_action` call. This also keeps us off
    /// `OnceLock<T>: Clone` (Rust 1.85+) so the file compiles on
    /// edition-2024 toolchains without depending on that very recent
    /// std impl.
    fn clone(&self) -> Self {
        Self {
            filter_enabled: self.filter_enabled.clone(),
            endpoint_policies: self.endpoint_policies.clone(),
            rate_limit: self.rate_limit,
            sorted_matchers: OnceLock::new(),
        }
    }
}

impl DomainPolicy {
    pub fn is_empty(&self) -> bool {
        self.filter_enabled.is_empty()
            && self.endpoint_policies.is_empty()
            && self.rate_limit.is_none()
    }

    /// Lookup the override for `filter_name` if any.
    pub fn filter_override(&self, filter_name: &str) -> Option<bool> {
        self.filter_enabled.get(filter_name).copied()
    }

    /// V166 — resolve a path against the per-endpoint policy map.
    /// Returns Some(action) on the first matching pattern, None
    /// when no pattern matches. Deterministic by sorting patterns
    /// alphabetically so the choice doesn't depend on insertion order.
    ///
    /// V230 — uses a lazily-built sorted matcher cache instead of
    /// sorting + reformatting per call. First call compiles the
    /// `endpoint_policies` map into `Arc<Vec<CompiledMatcher>>` (sorted
    /// once, slashes pre-stitched); subsequent calls just iterate the
    /// cached slice. Hot path is zero-alloc.
    pub fn endpoint_action(&self, path: &str) -> Option<EndpointAction> {
        if self.endpoint_policies.is_empty() {
            return None;
        }
        // V233 — match against the canonical path, not the raw request
        // path. `/%61dmin/users` decodes to `/admin/users` and
        // `/public/..%2finternal` collapses to `/internal`; without
        // this the upstream serves a path that bypassed the matched
        // rule (auth-bypass / path-traversal). `compile_matcher`
        // canonicalises the pattern body to match, so both sides of the
        // comparison are normalised the same way.
        let canon = crate::normalisation::canonical_path(path);
        let path = canon.as_str();
        let matchers = self.compile_endpoint_matchers();
        for m in matchers.iter() {
            match m.kind {
                MatchKind::Exact => {
                    if path == m.needle {
                        return Some(m.action);
                    }
                }
                MatchKind::Prefix => {
                    if path.starts_with(&m.needle) || m.exact_alias.as_deref() == Some(path) {
                        return Some(m.action);
                    }
                }
                MatchKind::Suffix => {
                    if path.ends_with(&m.needle) || m.exact_alias.as_deref() == Some(path) {
                        return Some(m.action);
                    }
                }
            }
        }
        None
    }

    /// V230 — return (and lazily build) the sorted, pre-compiled
    /// endpoint matcher list. Crate-internal: `CompiledMatcher` is
    /// an implementation detail. First call sorts patterns
    /// alphabetically and pre-stitches slashes; subsequent calls
    /// return the cached `Arc` via `OnceLock::get_or_init`.
    pub(crate) fn compile_endpoint_matchers(&self) -> Arc<Vec<CompiledMatcher>> {
        self.sorted_matchers
            .get_or_init(|| {
                let mut entries: Vec<(&String, &EndpointAction)> =
                    self.endpoint_policies.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let compiled: Vec<CompiledMatcher> = entries
                    .into_iter()
                    .map(|(pat, &action)| compile_matcher(pat, action))
                    .collect();
                Arc::new(compiled)
            })
            .clone()
    }
}

/// V230 — translate one raw pattern into a [`CompiledMatcher`]. Done
/// once per (host, pattern) on first use, then cached.
///
/// V233 — the pattern body is run through `canonical_path` so it is
/// normalised the same way the request path is in `endpoint_action`
/// (percent-decoded, dot-segments collapsed, lower-cased). Without this
/// a request canonicalised to `/admin/users` would fail to match a
/// pattern still stored as raw `/Admin/users`. The `/*` and `*/`
/// sigils are stripped *before* canonicalisation so the wildcard
/// markers are never themselves collapsed or folded.
fn compile_matcher(pat: &str, action: EndpointAction) -> CompiledMatcher {
    if let Some(prefix) = pat.strip_suffix("/*") {
        // `/foo/*` → starts_with("/foo/") OR == "/foo".
        let prefix = crate::normalisation::canonical_path(prefix);
        return CompiledMatcher {
            needle: format!("{prefix}/"),
            exact_alias: Some(prefix),
            kind: MatchKind::Prefix,
            action,
        };
    }
    if let Some(suffix) = pat.strip_prefix("*/") {
        // `*/foo` → ends_with("/foo") OR == "foo". The suffix has no
        // leading slash, so canonicalise it as `/{suffix}` then keep
        // both the slashed needle and the bare-segment alias.
        let slashed = crate::normalisation::canonical_path(&format!("/{suffix}"));
        let bare = slashed.strip_prefix('/').unwrap_or(&slashed).to_string();
        return CompiledMatcher {
            needle: slashed,
            exact_alias: Some(bare),
            kind: MatchKind::Suffix,
            action,
        };
    }
    CompiledMatcher {
        needle: crate::normalisation::canonical_path(pat),
        exact_alias: None,
        kind: MatchKind::Exact,
        action,
    }
}

/// Match a request path against a pattern. Supports `/foo` (exact),
/// `/foo/*` (prefix), `*/foo` (suffix). Stripped down compared to the
/// honeypot matcher (no internal-star wildcards) because per-endpoint
/// policies want simple, auditable rules.
///
/// V233 — both the request path and the pattern body are canonicalised
/// (`crate::normalisation::canonical_path`) before comparison so an
/// encoded / dot-segmented request can't slip past a rule the upstream
/// would still honour. The `/*` and `*/` sigils are stripped before
/// canonicalisation so the wildcard markers survive intact.
pub fn path_matches(path: &str, pattern: &str) -> bool {
    let path = crate::normalisation::canonical_path(path);
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let prefix = crate::normalisation::canonical_path(prefix);
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if let Some(suffix) = pattern.strip_prefix("*/") {
        let slashed = crate::normalisation::canonical_path(&format!("/{suffix}"));
        let bare = slashed.strip_prefix('/').unwrap_or(&slashed);
        return path.ends_with(&slashed) || path == bare;
    }
    path == crate::normalisation::canonical_path(pattern)
}

/// On-disk snapshot for V168 cross-worker persistence. Wraps the
/// whole DashMap into a single JSON object so atomic file rename
/// gives all workers a consistent view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedSnapshot {
    /// Maps lower-case host → policy. Matches the live in-memory shape.
    #[serde(default)]
    entries: std::collections::HashMap<String, DomainPolicy>,
}

/// Cheap clone via shared inner. Read paths fan out via shard locks
/// inside DashMap; write paths take per-shard write locks briefly.
#[derive(Clone, Default)]
pub struct DomainPolicyStore {
    inner: Arc<DashMap<String, DomainPolicy>>,
    /// V168 — optional on-disk path for cross-worker sync. When Some,
    /// every mutation writes the full snapshot atomically; reads call
    /// `refresh()` to mtime-poll and reload if another worker updated.
    path: Arc<Mutex<Option<PathBuf>>>,
    /// V168 — last-seen mtime, used by refresh() to skip reads when
    /// the file hasn't changed.
    last_mtime: Arc<Mutex<Option<SystemTime>>>,
    /// V229 — atomic empty-gate. Most deployments have zero per-domain
    /// overrides — the default policy applies. Reads called this
    /// store 7-8x per request (each filter checks its override), and
    /// every call took two Mutex locks (refresh) + a `to_ascii_lowercase`
    /// allocation. With the gate set to `false`, the lookup short-
    /// circuits before any lock or alloc.
    has_entries: Arc<std::sync::atomic::AtomicBool>,
    /// V229 — true when persistence is attached; lets reads skip the
    /// inner Mutex on `path` when nobody's configured a path. Without
    /// this flag, every refresh() took a Mutex lock just to read None.
    persistence_attached: Arc<std::sync::atomic::AtomicBool>,
}

impl DomainPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// V168 — attach a disk path for persistence. On call:
    /// * loads existing entries from `path` if present
    /// * subsequent mutations write the file atomically
    /// * other workers that share the path see updates on next reload
    ///
    /// Operator wires this via `cfg.admin.domain_policy_path` or env.
    /// Mutates through the shared Arc so a handle obtained earlier
    /// (e.g., from FilterEngine.domain_policy()) starts persisting too.
    pub fn attach_persistence(&self, path: PathBuf) -> anyhow::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).ok();
        }
        if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let snap: PersistedSnapshot = serde_json::from_str(&raw).unwrap_or_default();
            for (host, policy) in snap.entries {
                self.inner.insert(host, policy);
            }
            if !self.inner.is_empty() {
                self.has_entries
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        *self.path.lock().expect("policy path mutex") = Some(path);
        *self.last_mtime.lock().expect("policy mtime mutex") = mtime;
        self.persistence_attached
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Reload from disk if another worker updated the file. Called
    /// from every read path; cheap when file hasn't changed (single
    /// stat() syscall).
    fn refresh(&self) {
        // V229 — atomic short-circuit: when no path is attached the
        // refresh is a no-op. Previously we locked a Mutex on every
        // read just to discover that fact, which serialized N workers
        // through one global lock under heavy traffic.
        if !self
            .persistence_attached
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        let path_guard = self.path.lock().expect("policy path mutex");
        let Some(path) = path_guard.clone() else {
            return;
        };
        drop(path_guard);
        let current = fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        let mut cached = self.last_mtime.lock().expect("policy mtime mutex");
        if *cached == current {
            return;
        }
        if let Ok(raw) = fs::read_to_string(&path)
            && let Ok(snap) = serde_json::from_str::<PersistedSnapshot>(&raw)
        {
            // Replace inner atomically: clear + re-insert. The clear
            // window is shorter than the read traffic so a request
            // racing during reload sees at worst a stale value, never
            // a partial map.
            self.inner.clear();
            for (host, policy) in snap.entries {
                self.inner.insert(host, policy);
            }
            // V229 — refresh the empty-gate after reload so the next
            // read short-circuits when the disk snapshot is empty.
            self.has_entries
                .store(!self.inner.is_empty(), std::sync::atomic::Ordering::Relaxed);
            *cached = current;
        }
    }

    /// Write the current state to disk atomically. No-op when no path
    /// configured. Mutations call this after updating the DashMap.
    fn persist(&self) {
        let path_guard = self.path.lock().expect("policy path mutex");
        let Some(path) = path_guard.clone() else {
            return;
        };
        drop(path_guard);
        let snap = PersistedSnapshot {
            entries: self
                .inner
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect(),
        };
        if let Err(e) = write_atomic(&path, &snap) {
            tracing::warn!(error = %e, path = %path.display(),
                "domain_policy: persist failed");
            return;
        }
        if let Ok(meta) = fs::metadata(&path)
            && let Ok(m) = meta.modified()
        {
            *self.last_mtime.lock().expect("policy mtime mutex") = Some(m);
        }
    }

    /// Resolve a filter's enabled state for `host`, returning Some
    /// when the host has an explicit override, None otherwise. Caller
    /// (filter engine) falls back to global RuntimeToggles when None.
    /// Host lookup is case-insensitive via lower-casing — matches
    /// what RFC 9110 §5.5 says about Host header normalisation.
    ///
    /// V230 — back-compat single-filter lookup. New call sites should
    /// prefer [`Self::filter_overrides_for`] which returns the whole
    /// per-host map in one shot and amortises the lowercase alloc + the
    /// DashMap shard lock across all filters in the chain.
    pub fn filter_override(&self, host: &str, filter_name: &str) -> Option<bool> {
        self.filter_overrides_for(host)
            .and_then(|map| map.get(filter_name).copied())
    }

    /// V230 — batched per-host filter-override lookup. The filter
    /// engine calls `filter_override` 7-8× per request (one per
    /// registered filter). Each call previously did:
    ///   * `host.to_ascii_lowercase()` heap alloc
    ///   * DashMap shard read-lock (`get`)
    ///   * Optional `refresh()` (Mutex locks when persistence attached)
    ///
    /// This API folds all of that into one call: one alloc, one shard
    /// lock, one cloned `Arc<HashMap>`. The caller (V230 filter engine
    /// hot-path) stashes the Arc per request and queries each filter's
    /// name against it locally.
    ///
    /// Returns None when the host has no override entry. The empty-
    /// gate fast path means a zero-override deployment costs one
    /// relaxed atomic load.
    pub fn filter_overrides_for(
        &self,
        host: &str,
    ) -> Option<Arc<std::collections::HashMap<String, bool>>> {
        // V229 — atomic empty-gate fast path. Gate only applies when
        // persistence is detached: a disk-backed store may have
        // entries another worker wrote that our local DashMap doesn't
        // yet know about, so we still need to refresh() in that case.
        let persistence = self
            .persistence_attached
            .load(std::sync::atomic::Ordering::Relaxed);
        if !persistence && !self.has_entries.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.refresh();
        // only allocate when the host actually contains uppercase bytes
        let lower;
        let key: &str = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = host.to_ascii_lowercase();
            &lower
        } else {
            host
        };
        self.inner
            .get(key)
            .map(|p| Arc::new(p.filter_enabled.clone()))
    }

    /// V234 — resolve the per-host rate-limit override for `host`.
    /// Returns `Some((rps, burst))` when the host has an explicit
    /// override, `None` otherwise (caller falls back to the global /
    /// static-config limits). Shares the same empty-gate + refresh +
    /// case-insensitive lookup machinery as `filter_overrides_for`, so a
    /// zero-override deployment costs one relaxed atomic load.
    pub fn rate_limit_for(&self, host: &str) -> Option<(u64, u64)> {
        let persistence = self
            .persistence_attached
            .load(std::sync::atomic::Ordering::Relaxed);
        if !persistence && !self.has_entries.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.refresh();
        let lower;
        let key: &str = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = host.to_ascii_lowercase();
            &lower
        } else {
            host
        };
        self.inner
            .get(key)
            .and_then(|p| p.rate_limit.map(|r| (r.rps, r.burst)))
    }

    /// Replace the full policy for `host`. Empty policy = remove entry.
    pub fn put(&self, host: &str, policy: DomainPolicy) {
        let key = host.to_ascii_lowercase();
        if policy.is_empty() {
            self.inner.remove(&key);
        } else {
            self.inner.insert(key, policy);
        }
        // V229 — flip the empty-gate to mirror current state. Cheap
        // (one atomic store) and lets read paths short-circuit when
        // the store goes back to empty.
        self.has_entries
            .store(!self.inner.is_empty(), std::sync::atomic::Ordering::Relaxed);
        self.persist();
    }

    /// Snapshot for one host (None when no policy registered).
    pub fn get(&self, host: &str) -> Option<DomainPolicy> {
        let persistence = self
            .persistence_attached
            .load(std::sync::atomic::Ordering::Relaxed);
        if !persistence && !self.has_entries.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.refresh();
        self.inner
            .get(&host.to_ascii_lowercase())
            .map(|p| p.clone())
    }

    /// V166 — resolve a per-endpoint action for (host, path). Returns
    /// None when the host has no policy or no pattern matches.
    pub fn endpoint_action(&self, host: &str, path: &str) -> Option<EndpointAction> {
        // V229 — same empty-gate fast path as filter_override. Called
        // once per request from the filter engine; empty-store is the
        // common case and now costs one relaxed atomic load.
        let persistence = self
            .persistence_attached
            .load(std::sync::atomic::Ordering::Relaxed);
        if !persistence && !self.has_entries.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        self.refresh();
        // only allocate when the host actually contains uppercase bytes
        let lower;
        let key: &str = if host.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = host.to_ascii_lowercase();
            &lower
        } else {
            host
        };
        self.inner.get(key).and_then(|p| p.endpoint_action(path))
    }

    /// Snapshot of every host with a policy. Used by the admin API
    /// listing endpoint.
    pub fn snapshot(&self) -> Vec<(String, DomainPolicy)> {
        self.refresh();
        let mut out: Vec<_> = self
            .inner
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn remove(&self, host: &str) -> Option<DomainPolicy> {
        let prior = self
            .inner
            .remove(&host.to_ascii_lowercase())
            .map(|(_, v)| v);
        if prior.is_some() {
            // V229 — keep the empty-gate in sync after removal.
            self.has_entries
                .store(!self.inner.is_empty(), std::sync::atomic::Ordering::Relaxed);
            self.persist();
        }
        prior
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// V168 — atomic JSON write. Temp file + rename so concurrent reads
/// never see a half-written file. Same pattern as honeypot/state.rs.
fn write_atomic(path: &Path, snap: &PersistedSnapshot) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let raw = serde_json::to_string_pretty(snap)?;
    fs::write(&tmp, raw)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(filters: &[(&str, bool)]) -> DomainPolicy {
        // V230 — struct-update syntax so adding non-public cache fields
        // (e.g. `sorted_matchers`) doesn't break this helper.
        DomainPolicy {
            filter_enabled: filters.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            endpoint_policies: std::collections::HashMap::new(),
            ..DomainPolicy::default()
        }
    }

    #[test]
    fn empty_store_returns_no_override() {
        let s = DomainPolicyStore::new();
        assert!(s.filter_override("a.example", "waf").is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn put_then_lookup_roundtrips() {
        let s = DomainPolicyStore::new();
        s.put(
            "api.example.com",
            pol(&[("waf", true), ("challenge", false)]),
        );
        assert_eq!(s.filter_override("api.example.com", "waf"), Some(true));
        assert_eq!(
            s.filter_override("api.example.com", "challenge"),
            Some(false)
        );
        // Missing filter → no override.
        assert_eq!(s.filter_override("api.example.com", "bot"), None);
    }

    #[test]
    fn host_lookup_case_insensitive() {
        let s = DomainPolicyStore::new();
        s.put("Api.Example.COM", pol(&[("waf", false)]));
        assert_eq!(s.filter_override("api.example.com", "waf"), Some(false));
        assert_eq!(s.filter_override("API.EXAMPLE.COM", "waf"), Some(false));
    }

    #[test]
    fn put_empty_policy_removes_entry() {
        let s = DomainPolicyStore::new();
        s.put("a.example", pol(&[("waf", true)]));
        assert_eq!(s.len(), 1);
        s.put("a.example", DomainPolicy::default());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn remove_returns_prior_value() {
        let s = DomainPolicyStore::new();
        s.put("a.example", pol(&[("waf", true)]));
        let prev = s.remove("a.example").unwrap();
        assert_eq!(prev.filter_override("waf"), Some(true));
        assert!(s.is_empty());
    }

    #[test]
    fn snapshot_sorted_by_host() {
        let s = DomainPolicyStore::new();
        s.put("b.example", pol(&[("waf", true)]));
        s.put("a.example", pol(&[("waf", false)]));
        s.put("c.example", pol(&[("waf", true)]));
        let snap = s.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].0, "a.example");
        assert_eq!(snap[1].0, "b.example");
        assert_eq!(snap[2].0, "c.example");
    }

    #[test]
    fn policy_is_empty_check() {
        let p = DomainPolicy::default();
        assert!(p.is_empty());
        let p = pol(&[("waf", true)]);
        assert!(!p.is_empty());
    }

    // ── V166 endpoint policy tests ────────────────────────────────

    #[test]
    fn path_matcher_exact_prefix_suffix() {
        assert!(path_matches("/foo", "/foo"));
        assert!(!path_matches("/foobar", "/foo"));
        assert!(path_matches("/foo/bar", "/foo/*"));
        assert!(path_matches("/foo", "/foo/*"));
        assert!(!path_matches("/other", "/foo/*"));
        assert!(path_matches("/anything/.env", "*/.env"));
        assert!(path_matches("/.env", "*/.env"));
        assert!(!path_matches("/.env.bak", "*/.env"));
    }

    #[test]
    fn endpoint_action_first_alpha_match_wins() {
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/admin/*".to_string(), EndpointAction::Block);
        p.endpoint_policies
            .insert("/login".to_string(), EndpointAction::Challenge);
        assert_eq!(p.endpoint_action("/login"), Some(EndpointAction::Challenge));
        assert_eq!(
            p.endpoint_action("/admin/users"),
            Some(EndpointAction::Block)
        );
        assert_eq!(p.endpoint_action("/other"), None);
    }

    #[test]
    fn store_endpoint_action_per_host() {
        let s = DomainPolicyStore::new();
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/login".to_string(), EndpointAction::Challenge);
        p.endpoint_policies
            .insert("/.env".to_string(), EndpointAction::Tarpit);
        s.put("api.example", p);
        assert_eq!(
            s.endpoint_action("api.example", "/login"),
            Some(EndpointAction::Challenge),
        );
        assert_eq!(
            s.endpoint_action("api.example", "/.env"),
            Some(EndpointAction::Tarpit),
        );
        assert_eq!(s.endpoint_action("api.example", "/other"), None);
        assert_eq!(s.endpoint_action("other.example", "/login"), None);
    }

    #[test]
    fn endpoint_action_str_round_trip() {
        for a in [
            EndpointAction::Allow,
            EndpointAction::Block,
            EndpointAction::Challenge,
            EndpointAction::Tarpit,
        ] {
            assert!(!a.as_str().is_empty());
        }
    }

    fn tmp_path(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "aegis-domain-policy-{}-{}-{}-{}.json",
            label,
            std::process::id(),
            now,
            n,
        ))
    }

    #[test]
    fn persistence_roundtrip_via_attach() {
        let path = tmp_path("rt");
        let s = DomainPolicyStore::new();
        s.attach_persistence(path.clone()).unwrap();
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/login".to_string(), EndpointAction::Challenge);
        s.put("api.example", p);
        // Second store reads the same file → sees the entry.
        let s2 = DomainPolicyStore::new();
        s2.attach_persistence(path.clone()).unwrap();
        assert_eq!(
            s2.endpoint_action("api.example", "/login"),
            Some(EndpointAction::Challenge),
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cross_worker_refresh_picks_up_changes() {
        // Worker A writes, worker B's store on disk reflects, B's
        // refresh() on next read picks up the change.
        let path = tmp_path("xw");
        let a = DomainPolicyStore::new();
        a.attach_persistence(path.clone()).unwrap();
        let b = DomainPolicyStore::new();
        b.attach_persistence(path.clone()).unwrap();
        // A writes.
        let mut p = DomainPolicy::default();
        p.filter_enabled.insert("waf".to_string(), false);
        a.put("api.example", p);
        // Force mtime to differ by at least 10ms (some filesystems
        // have second-resolution mtime; we don't depend on that for
        // determinism in this test — instead force a fresh metadata
        // read by sleeping).
        std::thread::sleep(std::time::Duration::from_millis(50));
        // B's read should pick up the new entry.
        assert_eq!(b.filter_override("api.example", "waf"), Some(false),);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn remove_persists_through_disk() {
        let path = tmp_path("rm");
        let a = DomainPolicyStore::new();
        a.attach_persistence(path.clone()).unwrap();
        let mut p = DomainPolicy::default();
        p.filter_enabled.insert("waf".to_string(), false);
        a.put("api.example", p);
        let b = DomainPolicyStore::new();
        b.attach_persistence(path.clone()).unwrap();
        assert_eq!(b.filter_override("api.example", "waf"), Some(false));
        // Remove from A.
        a.remove("api.example");
        std::thread::sleep(std::time::Duration::from_millis(50));
        // B should see the removal.
        assert_eq!(b.filter_override("api.example", "waf"), None);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn endpoint_action_serializes_snake_case() {
        let s = serde_json::to_string(&EndpointAction::Challenge).unwrap();
        assert_eq!(s, "\"challenge\"");
        let back: EndpointAction = serde_json::from_str("\"tarpit\"").unwrap();
        assert_eq!(back, EndpointAction::Tarpit);
    }

    #[test]
    fn json_roundtrip_via_serde() {
        let p = pol(&[("waf", true), ("bot", false)]);
        let j = serde_json::to_string(&p).unwrap();
        let back: DomainPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(back.filter_enabled.len(), 2);
        assert_eq!(back.filter_override("waf"), Some(true));
    }

    // ── V230 batched lookup + sorted matcher cache ───────────────────

    #[test]
    fn filter_overrides_for_empty_store_is_none() {
        let s = DomainPolicyStore::new();
        // V230 — empty-gate short-circuit returns None without any
        // refresh/lowercase work.
        assert!(s.filter_overrides_for("api.example.com").is_none());
    }

    #[test]
    fn filter_overrides_for_returns_full_map() {
        let s = DomainPolicyStore::new();
        s.put(
            "api.example.com",
            pol(&[("waf", true), ("challenge", false), ("bot", true)]),
        );
        let overrides = s
            .filter_overrides_for("api.example.com")
            .expect("host should have overrides");
        assert_eq!(overrides.len(), 3);
        assert_eq!(overrides.get("waf").copied(), Some(true));
        assert_eq!(overrides.get("challenge").copied(), Some(false));
        assert_eq!(overrides.get("bot").copied(), Some(true));
        assert!(overrides.get("rate_limit").is_none());
    }

    #[test]
    fn filter_overrides_for_case_insensitive() {
        // V230 — host normalisation matches the existing
        // filter_override semantics.
        let s = DomainPolicyStore::new();
        s.put("Api.Example.COM", pol(&[("waf", false)]));
        let map = s
            .filter_overrides_for("api.example.com")
            .expect("case-insensitive lookup");
        assert_eq!(map.get("waf").copied(), Some(false));
    }

    #[test]
    fn filter_override_back_compat_via_batched() {
        // V230 — the legacy single-filter API now delegates to the
        // batched lookup; existing callers see no behaviour change.
        let s = DomainPolicyStore::new();
        s.put("api.example.com", pol(&[("waf", true)]));
        assert_eq!(s.filter_override("api.example.com", "waf"), Some(true));
        assert_eq!(s.filter_override("api.example.com", "bot"), None);
        assert_eq!(s.filter_override("missing.example.com", "waf"), None);
    }

    #[test]
    fn filter_overrides_for_unknown_host_is_none() {
        let s = DomainPolicyStore::new();
        s.put("api.example.com", pol(&[("waf", true)]));
        assert!(s.filter_overrides_for("other.example.com").is_none());
    }

    #[test]
    fn compile_endpoint_matchers_caches_and_reuses() {
        // V230 — second call returns the same Arc as the first (cache
        // is populated and not rebuilt).
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/admin/*".to_string(), EndpointAction::Block);
        p.endpoint_policies
            .insert("/login".to_string(), EndpointAction::Challenge);
        let first = p.compile_endpoint_matchers();
        let second = p.compile_endpoint_matchers();
        assert!(Arc::ptr_eq(&first, &second));
        // Sorted alphabetically, so /admin/* sorts before /login.
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].action, EndpointAction::Block);
        assert_eq!(first[1].action, EndpointAction::Challenge);
    }

    #[test]
    fn endpoint_action_v230_matches_v166_semantics() {
        // V230 — the precompiled matcher path must reproduce the
        // exact match decisions of the old per-call sort path.
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/foo".to_string(), EndpointAction::Allow);
        p.endpoint_policies
            .insert("/admin/*".to_string(), EndpointAction::Block);
        p.endpoint_policies
            .insert("*/.env".to_string(), EndpointAction::Tarpit);
        assert_eq!(p.endpoint_action("/foo"), Some(EndpointAction::Allow));
        assert_eq!(p.endpoint_action("/foobar"), None);
        assert_eq!(p.endpoint_action("/admin"), Some(EndpointAction::Block));
        assert_eq!(
            p.endpoint_action("/admin/users"),
            Some(EndpointAction::Block),
        );
        assert_eq!(
            p.endpoint_action("/path/.env"),
            Some(EndpointAction::Tarpit),
        );
        assert_eq!(p.endpoint_action("/other"), None);
    }

    #[test]
    fn clone_resets_matcher_cache() {
        // V230 — cloning a policy must not share the OnceLock-cached
        // matcher list; the clone rebuilds on first use.
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/login".to_string(), EndpointAction::Challenge);
        let _ = p.compile_endpoint_matchers(); // prime original
        let q = p.clone();
        let q_first = q.compile_endpoint_matchers();
        let p_first = p.compile_endpoint_matchers();
        assert!(!Arc::ptr_eq(&p_first, &q_first));
    }

    // ── V233 — canonical-path matching (auth-bypass fix) ─────────────

    #[test]
    fn endpoint_action_matches_percent_encoded_path() {
        // `/%61dmin/users` (`%61`=`a`) must hit `/admin/*` — the
        // upstream resolves the decoded path, so the Block must too.
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/admin/*".to_string(), EndpointAction::Block);
        assert_eq!(
            p.endpoint_action("/%61dmin/users"),
            Some(EndpointAction::Block),
        );
        assert_eq!(p.endpoint_action("/%61dmin"), Some(EndpointAction::Block),);
    }

    #[test]
    fn endpoint_action_collapses_dot_segments() {
        // `/public/..%2finternal/secret` resolves to
        // `/internal/secret` — a Block on `/internal/*` must fire.
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/internal/*".to_string(), EndpointAction::Block);
        assert_eq!(
            p.endpoint_action("/public/..%2finternal/secret"),
            Some(EndpointAction::Block),
        );
    }

    #[test]
    fn endpoint_action_canonicalises_exact_and_suffix() {
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/login".to_string(), EndpointAction::Challenge);
        p.endpoint_policies
            .insert("*/.env".to_string(), EndpointAction::Tarpit);
        // Encoded exact path.
        assert_eq!(
            p.endpoint_action("/%6cogin"),
            Some(EndpointAction::Challenge),
        );
        // Encoded `.` in the suffix + a dot-segment.
        assert_eq!(
            p.endpoint_action("/app/../sub/%2eenv"),
            Some(EndpointAction::Tarpit),
        );
    }

    #[test]
    fn path_matches_canonicalises_both_sides() {
        // Encoded request path against a plain pattern.
        assert!(path_matches("/%61dmin/users", "/admin/*"));
        assert!(path_matches("/a/../b", "/b"));
        assert!(path_matches("/a//b", "/a/b"));
        // Encoded pattern body still matches a plain path.
        assert!(path_matches("/admin", "/%61dmin"));
        // Non-match still rejected after canonicalisation.
        assert!(!path_matches("/%61dmin/users", "/internal/*"));
    }

    #[test]
    fn endpoint_action_no_panic_on_malformed_path() {
        let mut p = DomainPolicy::default();
        p.endpoint_policies
            .insert("/admin/*".to_string(), EndpointAction::Block);
        for path in ["/%", "/admin/%zz", "/%c0%ae", "", "/../../.."] {
            let _ = p.endpoint_action(path); // must not panic
        }
    }
}
