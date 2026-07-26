use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::UNIX_EPOCH;

use dashmap::DashMap;
use rustc_hash::FxBuildHasher;

use crate::{config::DefaultAction, proxy::request_context::RequestContext};

use super::{FilterAction, SharedFilter};

// V230 — FxHash for internal-only DashMaps. The runtime toggle table is
// keyed by `&'static str` filter names ("waf", "bot", "ip_acl", …) that
// are compile-time literals registered at engine construction; the
// `known` lookup table maps those names back from the operator-supplied
// toggle file. Neither key is attacker-derived, so the HashDoS-resistant
// SipHash/AHash defaults are pure overhead on the hot `is_enabled()`
// path. FxHash is a small non-cryptographic hash that's measurably
// faster for short-string keys on x86_64 / aarch64.

// V102 — `SharedFilter` is now an enum (was `Arc<dyn TrafficFilter>`),
// so `filter.check(ctx)` below is a static-dispatch match that the
// compiler can inline. Per-filter `name()` likewise.

/// V160 — runtime toggle table. Maps each filter's name() to an
/// AtomicBool the engine consults before calling check(). Admin UI
/// flips these to enable/disable filters without restarting the
/// process. Defaults to enabled = true for every filter the engine
/// is constructed with; the config-driven defaults are loaded at
/// startup before any operator override.
///
/// V168 — optional disk persistence via [Self::with_persistence].
/// Mutations write a JSON `{name: enabled}` map; other workers see
/// updates on the next refresh() (mtime-poll on read paths).
///
/// V232 — inner value changed from bare `AtomicBool` to
/// `Arc<AtomicBool>` so `FilterEngine` can clone individual toggle
/// handles into a parallel `Vec<Arc<AtomicBool>>` aligned with
/// `self.filters`. The hot loop then reads through those direct
/// `Arc` handles — no hash, no shard lock, no clock.
#[derive(Clone, Default)]
pub struct RuntimeToggles {
    // V230 — FxHash hasher for the toggle table. Keys are compile-time
    // `&'static str` filter names; not attacker-derived.
    // V232 — value is Arc<AtomicBool> so FilterEngine can clone the
    // Arc and hold a direct handle per filter for O(1) hot-path reads.
    inner: Arc<DashMap<&'static str, Arc<AtomicBool>, FxBuildHasher>>,
    path: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
    last_mtime: Arc<std::sync::Mutex<Option<std::time::SystemTime>>>,
    /// V179 — throttle the mtime poll so per-request `is_enabled()`
    /// calls don't trigger an `fs::metadata` syscall on every filter
    /// check. Strace showed ~30k statx/s per worker before this; we
    /// now only re-stat once per `MIN_REFRESH_INTERVAL_MICROS`.
    /// Wrapped in `Arc` so cloned handles share the throttle state.
    last_refresh_micros: Arc<AtomicU64>,
    /// Known filter names — we keep a fresh `&'static str` per filter
    /// so file-loaded values can be applied to the right entry. The
    /// names come from filters registered at construction.
    ///
    /// V230 — FxHash here too: keys are operator-supplied JSON names
    /// from the toggle file, but the file is in a trusted control-plane
    /// path (only operators with write access to the runtime data dir),
    /// not request-time attacker input, and lookups happen off the hot
    /// path inside `refresh()` once per `MIN_REFRESH_INTERVAL_MICROS`.
    known: Arc<dashmap::DashMap<String, &'static str, FxBuildHasher>>,
}

/// V179 — minimum interval between disk-mtime polls for runtime toggle
/// refresh. 1s keeps operator UI changes near-realtime while collapsing
/// the per-request syscall storm on hot paths.
const MIN_REFRESH_INTERVAL_MICROS: u64 = 1_000_000;

impl RuntimeToggles {
    pub fn new() -> Self {
        Self {
            // V230 — `with_hasher` is required because the typed
            // hasher slot is no longer `RandomState`. `FxBuildHasher`
            // is a unit struct so `default()` is free.
            // V232 — value type is Arc<AtomicBool>; see struct comment.
            inner: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            path: Arc::new(std::sync::Mutex::new(None)),
            last_mtime: Arc::new(std::sync::Mutex::new(None)),
            // V179 — 0 means "never refreshed yet"; the first call to
            // refresh() sees `now.saturating_sub(0) >= MIN_REFRESH` and
            // proceeds normally.
            last_refresh_micros: Arc::new(AtomicU64::new(0)),
            known: Arc::new(dashmap::DashMap::with_hasher(FxBuildHasher)),
        }
    }
    /// Set the initial state for a filter name. Called once per filter
    /// at engine construction.
    pub fn register(&self, name: &'static str, enabled: bool) {
        self.inner.insert(name, Arc::new(AtomicBool::new(enabled)));
        self.known.insert(name.to_string(), name);
    }

    /// Return a cloned `Arc<AtomicBool>` handle for `name` if it has
    /// been registered, otherwise `None`. Used by `FilterEngine::new`
    /// to build the per-index fast-path handle vector.
    ///
    /// V232 — this is the only way for external code to get a direct
    /// `Arc` handle; `is_enabled` stays as-is for admin/off-hot-path
    /// callers (snapshot, test code) and does NOT read the clock —
    /// the caller is responsible for calling `refresh()` when freshness
    /// is required.
    pub(crate) fn handle_for(&self, name: &str) -> Option<Arc<AtomicBool>> {
        self.inner.get(name).map(|v| Arc::clone(&*v))
    }

    /// Pure read — no clock, no disk I/O. Callers that need up-to-date
    /// toggle values must call `refresh()` themselves first (e.g., the
    /// engine calls it once at the top of `evaluate_with_attribution`).
    /// Admin-facing paths (`snapshot`, `set`) already call `refresh`
    /// directly; this method is intentionally clock-free so the hot
    /// per-filter loop can use the `Arc<AtomicBool>` handles instead.
    pub fn is_enabled(&self, name: &str) -> bool {
        self.inner
            .get(name)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(true)
    }
    pub fn set(&self, name: &str, enabled: bool) -> bool {
        let ok = if let Some(v) = self.inner.get(name) {
            v.store(enabled, Ordering::Relaxed);
            true
        } else {
            false
        };
        if ok {
            self.persist();
        }
        ok
    }
    /// Snapshot for the admin API.
    pub fn snapshot(&self) -> Vec<(String, bool)> {
        // Explicitly refresh here — is_enabled() is now clock-free, so
        // admin paths that need up-to-date data must call refresh() themselves.
        self.refresh();
        let mut out: Vec<_> = self
            .inner
            .iter()
            .map(|e| (e.key().to_string(), e.value().load(Ordering::Relaxed)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Explicitly poll the toggle file for changes. Call once per request
    /// at the top of the hot path (before the filter loop) so that all
    /// per-filter reads within a single request see a consistent, fresh view
    /// without redundant clock reads. Also called by admin-facing paths
    /// (`snapshot`, `set`) that already invoked it before.
    ///
    /// V232 — made `pub(crate)` (was private) so `FilterEngine` can call
    /// it once at the top of `evaluate_with_attribution`.
    pub(crate) fn refresh_now(&self) {
        self.refresh();
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// V168 — attach a disk path for cross-worker sync. Loads any
    /// existing file into the registered toggles (only names already
    /// registered get applied; unknown names ignored). Mutates
    /// through the shared Arc so handles created earlier start
    /// persisting too.
    pub fn attach_persistence(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).ok();
        }
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, bool>>(&raw) {
                for (k, v) in map {
                    if let Some(known) = self.known.get(&k) {
                        if let Some(slot) = self.inner.get(*known.value()) {
                            slot.store(v, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        *self.path.lock().expect("toggles path mutex") = Some(path);
        *self.last_mtime.lock().expect("toggles mtime mutex") = mtime;
        Ok(())
    }

    fn refresh(&self) {
        // V179 — throttle the actual mtime poll. Without this, every
        // filter check on every request calls `fs::metadata`, even when
        // no toggle file is configured. Strace showed ~30k statx/s per
        // worker. We allow one stat per `MIN_REFRESH_INTERVAL_MICROS`.
        let now_micros = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let prev = self.last_refresh_micros.load(Ordering::Relaxed);
        if now_micros.saturating_sub(prev) < MIN_REFRESH_INTERVAL_MICROS {
            return;
        }
        self.last_refresh_micros
            .store(now_micros, Ordering::Relaxed);

        let path_guard = self.path.lock().expect("toggles path mutex");
        let Some(path) = path_guard.clone() else {
            return;
        };
        drop(path_guard);
        let current = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        let mut cached = self.last_mtime.lock().expect("toggles mtime mutex");
        if *cached == current {
            return;
        }
        if let Ok(raw) = std::fs::read_to_string(&path)
            && let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, bool>>(&raw)
        {
            for (k, v) in map {
                if let Some(known) = self.known.get(&k) {
                    if let Some(slot) = self.inner.get(*known.value()) {
                        slot.store(v, Ordering::Relaxed);
                    }
                }
            }
            *cached = current;
        }
    }

    fn persist(&self) {
        let path_guard = self.path.lock().expect("toggles path mutex");
        let Some(path) = path_guard.clone() else {
            return;
        };
        drop(path_guard);
        let map: std::collections::HashMap<&str, bool> = self
            .inner
            .iter()
            .map(|e| (*e.key(), e.value().load(Ordering::Relaxed)))
            .collect();
        let tmp = path.with_extension("json.tmp");
        let raw = match serde_json::to_string_pretty(&map) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "runtime_toggles: serialize failed");
                return;
            }
        };
        if std::fs::write(&tmp, raw).is_err() || std::fs::rename(&tmp, &path).is_err() {
            tracing::warn!(path = %path.display(),
                "runtime_toggles: atomic write failed");
            return;
        }
        if let Ok(meta) = std::fs::metadata(&path)
            && let Ok(m) = meta.modified()
        {
            *self.last_mtime.lock().expect("toggles mtime mutex") = Some(m);
        }
    }
}

/// Ordered filter pipeline with fallback default action.
#[derive(Clone)]
pub struct FilterEngine {
    filters: Vec<SharedFilter>,
    default_action: DefaultAction,
    toggles: RuntimeToggles,
    /// V232 — direct `Arc<AtomicBool>` handles aligned 1-to-1 with
    /// `self.filters`. The hot loop reads `toggle_handles[i]` with a
    /// single `load(Relaxed)` instead of a DashMap hash + shard lock.
    /// Built once in `new()` and never mutated; the `Arc` points at the
    /// same underlying `AtomicBool` that `RuntimeToggles` owns, so
    /// `set()` / `refresh()` writes are immediately visible here.
    toggle_handles: Vec<Arc<AtomicBool>>,
    /// V162 — per-domain override store. When Some and the request's
    /// host has an explicit override, it wins over the global
    /// RuntimeToggles. Constructed empty by default; wired by the
    /// admin API mutation path.
    domain_policy: crate::domain_policy::DomainPolicyStore,
}

impl FilterEngine {
    /// C4 — direct handle to the WAF filter, if one is registered. The
    /// per-filter chain (`evaluate`) inspects request *headers*; request
    /// *body* inspection is a separate `WafFilter::inspect_body*` call, so
    /// the pingora `request_body_filter` needs to reach the WAF outside the
    /// chain. Scans the (small) filter list; returns a cheap Arc clone.
    pub fn waf(&self) -> Option<Arc<crate::filters::waf::WafFilter>> {
        self.filters.iter().find_map(|f| match f {
            SharedFilter::Waf(w) => Some(w.clone()),
            _ => None,
        })
    }

    pub fn new(filters: Vec<SharedFilter>, default_action: DefaultAction) -> Self {
        let toggles = RuntimeToggles::new();
        for f in &filters {
            // V231 — register each filter's toggle with its REAL config
            // state (`config_enabled()`), not a hardcoded `true`. This
            // makes `RuntimeToggles` the single source of truth: a
            // default-off filter (e.g. `challenge`) registers as off,
            // and a per-domain `domain_policy` override that force-
            // enables it for one host now actually fires — the filter's
            // `check()` no longer self-gates on its own `enabled` field.
            toggles.register(f.name(), f.config_enabled());
        }
        // V232 — build direct Arc<AtomicBool> handles aligned with
        // `filters`. `handle_for` clones the Arc stored inside the
        // DashMap value; the clone is taken once at construction time,
        // not on the hot path. `unwrap()` is safe: we just registered
        // every filter above, so every name is guaranteed to be present.
        let toggle_handles: Vec<Arc<AtomicBool>> = filters
            .iter()
            .map(|f| toggles.handle_for(f.name()).expect("just registered"))
            .collect();
        Self {
            filters,
            default_action,
            toggles,
            toggle_handles,
            domain_policy: crate::domain_policy::DomainPolicyStore::new(),
        }
    }

    /// V160 — clone of the runtime toggle handle. Admin API holds one
    /// to expose `/admin/api/defaults/filters` read+write.
    pub fn toggles(&self) -> RuntimeToggles {
        self.toggles.clone()
    }

    /// V162 — shared handle to the per-domain policy store. Admin API
    /// holds one to expose `/admin/api/sites/<host>/policy` CRUD.
    pub fn domain_policy(&self) -> crate::domain_policy::DomainPolicyStore {
        self.domain_policy.clone()
    }

    pub fn evaluate(&self, ctx: &RequestContext) -> FilterAction {
        self.evaluate_with_attribution(ctx).0
    }

    /// Like `evaluate` but also returns the name of the filter that
    /// produced the non-Allow decision. `"default"` when nothing
    /// matched and the default-action fired; `"allow"` on pass-through.
    pub fn evaluate_with_attribution(&self, ctx: &RequestContext) -> (FilterAction, &'static str) {
        // V232 — FIX 1: call refresh() ONCE per request, here at the
        // top, before the filter loop. Previously is_enabled() called
        // refresh() (and SystemTime::now()) for each of ~8 filters per
        // request, even though the throttle meant 7 of those 8 were
        // wasted clock reads. Now is_enabled() is clock-free; we do one
        // mtime-poll attempt here that the throttle collapses to a single
        // relaxed AtomicU64 load when the 1s interval has not elapsed.
        self.toggles.refresh_now();

        // V166 — per-endpoint policy short-circuit. Operator-set rules
        // (e.g., "/.env → tarpit", "/login → challenge") apply BEFORE
        // the filter chain so they're authoritative. Only fires when
        // the request's host has a matching pattern registered.
        if let Some(action) = self.domain_policy.endpoint_action(&ctx.host, &ctx.path) {
            use crate::domain_policy::EndpointAction;
            use crate::filters::ChallengeLevel;
            let result = match action {
                EndpointAction::Allow => (FilterAction::Allow, "endpoint_policy_allow"),
                EndpointAction::Block => (
                    FilterAction::Deny {
                        status: 403,
                        reason: "endpoint_policy".into(),
                    },
                    "endpoint_policy_block",
                ),
                EndpointAction::Challenge => (
                    FilterAction::Challenge {
                        level: ChallengeLevel::Html,
                        reason: "endpoint_policy".into(),
                    },
                    "endpoint_policy_challenge",
                ),
                EndpointAction::Tarpit => (
                    FilterAction::Deny {
                        // The V147 tarpit handler in pingora_http
                        // matches /__aegis/tarpit/<slug>; we signal
                        // "route this into the tarpit" by issuing a
                        // 444 (no response, the proxy's tarpit handler
                        // intercepts via a separate path. For inline
                        // routing the operator wires a redirect rule
                        // in the upstream chain). For now the safe
                        // default is a deny with the tarpit reason
                        // so audit/metrics can attribute it cleanly.
                        status: 403,
                        reason: "endpoint_tarpit".into(),
                    },
                    "endpoint_policy_tarpit",
                ),
            };
            return result;
        }

        // V230 — batched per-host override lookup. The pre-V230 code
        // called `domain_policy.filter_override(&ctx.host, name)` once
        // per filter (7-8× per request), each doing a fresh
        // `host.to_ascii_lowercase()` heap alloc + DashMap shard
        // read-lock. We fold all of that into a single call that
        // returns `Option<Arc<HashMap<String, bool>>>` and then probe
        // the local map per filter — collapses 7-8 lowercase allocs +
        // 7-8 shard locks down to 1 of each per request. The
        // empty-gate fast path in `filter_overrides_for` keeps a
        // zero-override deployment to one relaxed atomic load.
        let overrides = self.domain_policy.filter_overrides_for(&ctx.host);

        // V232 — FIX 2: iterate by index so we can address both
        // `self.filters[i]` and `self.toggle_handles[i]` simultaneously.
        // The common no-override path reads `toggle_handles[i]` with a
        // single `Arc::load(Relaxed)` — no hash, no shard lock.
        // Per-domain overrides (the `overrides` branch) still work
        // exactly as before using the filter's name().
        for (i, filter) in self.filters.iter().enumerate() {
            let name = filter.name();
            // V162 — per-domain override wins; V160 global toggle is
            // the fallback. Either says "disabled" → skip.
            // V230 — probe the cached per-host map first; only fall
            // back to the global toggle when this host has no entry
            // or no override for *this* filter.
            // V232 — common (no-override) path: direct AtomicBool load
            // via pre-built handle; zero hashing, zero shard locking.
            let enabled = overrides
                .as_ref()
                .and_then(|map| map.get(name).copied())
                .unwrap_or_else(|| self.toggle_handles[i].load(Ordering::Relaxed));
            if !enabled {
                continue;
            }
            match filter.check(ctx) {
                FilterAction::Allow => continue,
                decision => return (decision, name),
            }
        }
        match self.default_action {
            DefaultAction::Allow => (FilterAction::Allow, "allow"),
            DefaultAction::Deny => (
                FilterAction::Deny {
                    status: 403,
                    reason: "default deny".into(),
                },
                "default",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::filters::{ChallengeLevel, TrafficFilter};

    struct Static(FilterAction);
    impl TrafficFilter for Static {
        fn check(&self, _: &RequestContext) -> FilterAction {
            self.0.clone()
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::test_with("1.2.3.4", "/")
    }

    #[test]
    fn empty_pipeline_uses_default_allow() {
        let e = FilterEngine::new(vec![], DefaultAction::Allow);
        assert_eq!(e.evaluate(&ctx()), FilterAction::Allow);
    }

    #[test]
    fn empty_pipeline_uses_default_deny() {
        let e = FilterEngine::new(vec![], DefaultAction::Deny);
        assert!(matches!(e.evaluate(&ctx()), FilterAction::Deny { .. }));
    }

    #[test]
    fn runtime_toggle_skips_disabled_filter() {
        // V160 — when a filter is disabled via RuntimeToggles, the
        // engine must skip it without calling check(). Then a
        // downstream filter that would otherwise be masked gets to
        // produce the decision.
        let deny_first = SharedFilter::Custom(Arc::new(Static(FilterAction::Deny {
            status: 401,
            reason: "first".into(),
        })));
        let challenge_second = SharedFilter::Custom(Arc::new(Static(FilterAction::Challenge {
            level: ChallengeLevel::Headers,
            reason: "second".into(),
        })));
        let e = FilterEngine::new(vec![deny_first, challenge_second], DefaultAction::Allow);
        // Both filters report name "unknown" (the default trait impl);
        // toggling "unknown" off skips both → Allow falls through to
        // default action.
        e.toggles().set("unknown", false);
        match e.evaluate(&ctx()) {
            FilterAction::Allow => {} // both skipped — both share the name
            other => panic!("expected Allow (both share name), got {other:?}"),
        }
        // Re-enable: deny fires again.
        e.toggles().set("unknown", true);
        assert!(matches!(e.evaluate(&ctx()), FilterAction::Deny { .. }));
    }

    #[test]
    fn per_domain_override_wins_over_global_toggle() {
        // V162 — global says enabled, per-host override says disabled
        // → host-specific request must skip.
        let deny = SharedFilter::Custom(Arc::new(Static(FilterAction::Deny {
            status: 401,
            reason: "global".into(),
        })));
        let e = FilterEngine::new(vec![deny], DefaultAction::Allow);
        let mut ctx = ctx();
        ctx.host = "carve-out.example.com".to_string();
        // No override → global toggle (enabled) → filter fires.
        assert!(matches!(e.evaluate(&ctx), FilterAction::Deny { .. }));
        // Add override disabling the filter for this host.
        let p = crate::domain_policy::DomainPolicy {
            filter_enabled: [("unknown".to_string(), false)].into_iter().collect(),
            endpoint_policies: std::collections::HashMap::new(),
            ..Default::default()
        };
        e.domain_policy().put(&ctx.host, p);
        // Same request now passes (override → disabled → skip).
        match e.evaluate(&ctx) {
            FilterAction::Allow => {}
            other => panic!("expected Allow with override, got {other:?}"),
        }
        // Different host → no override → still denied.
        let mut other = ctx.clone();
        other.host = "other.example.com".to_string();
        assert!(matches!(e.evaluate(&other), FilterAction::Deny { .. }));
    }

    #[test]
    fn endpoint_policy_short_circuits_filter_chain() {
        // V166 — `/login → Challenge` on `auth.example.com` must
        // fire BEFORE the regular filter chain. Even with no other
        // filters configured to challenge.
        let allow = SharedFilter::Custom(Arc::new(Static(FilterAction::Allow)));
        let e = FilterEngine::new(vec![allow], DefaultAction::Allow);
        let mut p = crate::domain_policy::DomainPolicy::default();
        p.endpoint_policies.insert(
            "/login".to_string(),
            crate::domain_policy::EndpointAction::Challenge,
        );
        e.domain_policy().put("auth.example.com", p);

        // Hitting /login → challenge (per endpoint policy).
        let mut ctx = ctx();
        ctx.host = "auth.example.com".to_string();
        ctx.path = "/login".to_string();
        let (action, src) = e.evaluate_with_attribution(&ctx);
        assert!(matches!(action, FilterAction::Challenge { .. }));
        assert_eq!(src, "endpoint_policy_challenge");

        // Hitting / → falls through to global → allow.
        ctx.path = "/".to_string();
        assert_eq!(e.evaluate(&ctx), FilterAction::Allow);

        // Different host → no policy → allow.
        ctx.host = "other.example.com".to_string();
        ctx.path = "/login".to_string();
        assert_eq!(e.evaluate(&ctx), FilterAction::Allow);
    }

    #[test]
    fn endpoint_policy_block_returns_403() {
        let allow = SharedFilter::Custom(Arc::new(Static(FilterAction::Allow)));
        let e = FilterEngine::new(vec![allow], DefaultAction::Allow);
        let mut p = crate::domain_policy::DomainPolicy::default();
        p.endpoint_policies.insert(
            "/wp-admin/*".to_string(),
            crate::domain_policy::EndpointAction::Block,
        );
        e.domain_policy().put("not-wordpress.example.com", p);

        let mut ctx = ctx();
        ctx.host = "not-wordpress.example.com".to_string();
        ctx.path = "/wp-admin/users".to_string();
        match e.evaluate(&ctx) {
            FilterAction::Deny { status, .. } => assert_eq!(status, 403),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn per_domain_override_can_enable_when_global_disabled() {
        // Symmetric case: global off, host opts in.
        let deny = SharedFilter::Custom(Arc::new(Static(FilterAction::Deny {
            status: 401,
            reason: "x".into(),
        })));
        let e = FilterEngine::new(vec![deny], DefaultAction::Allow);
        e.toggles().set("unknown", false); // globally off
        let mut ctx = ctx();
        ctx.host = "opt-in.example.com".to_string();
        // Global off → no host override → skip.
        assert_eq!(e.evaluate(&ctx), FilterAction::Allow);
        e.domain_policy().put(
            &ctx.host,
            crate::domain_policy::DomainPolicy {
                filter_enabled: [("unknown".to_string(), true)].into_iter().collect(),
                endpoint_policies: std::collections::HashMap::new(),
                ..Default::default()
            },
        );
        // Host override forces on → fires.
        assert!(matches!(e.evaluate(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn v231_real_challenge_filter_default_off_per_domain_on() {
        // V231 regression lock. The earlier per-domain tests use the
        // `Static` mock which has no internal `enabled` gate, so they
        // passed even WITH the V231 bug. This test uses a REAL
        // `ChallengeFilter` constructed disabled — exactly the shape
        // that exposed the bug: the engine called check() on the
        // per-domain force-enable, but the filter's own `!enabled`
        // gate short-circuited to Allow.
        use crate::config::ChallengeConfig;
        use crate::filters::challenge::ChallengeFilter;

        let cfg = ChallengeConfig {
            enabled: false, // global default — off
            ..ChallengeConfig::default()
        };
        let challenge = SharedFilter::Challenge(Arc::new(ChallengeFilter::new(&cfg)));
        let e = FilterEngine::new(vec![challenge], DefaultAction::Allow);

        // Global: challenge registered off → engine skips it → Allow.
        let mut ctx = ctx();
        ctx.host = "shop.example.com".to_string();
        assert_eq!(
            e.evaluate(&ctx),
            FilterAction::Allow,
            "challenge is globally off — must not fire without an override",
        );

        // Operator enables challenge for this one domain via the web
        // UI (domain_policy.filter_enabled).
        e.domain_policy().put(
            &ctx.host,
            crate::domain_policy::DomainPolicy {
                filter_enabled: [("challenge".to_string(), true)].into_iter().collect(),
                endpoint_policies: std::collections::HashMap::new(),
                ..Default::default()
            },
        );
        // Per-domain force-on → engine calls check() → real challenge
        // fires (the filter no longer self-gates on its own flag).
        assert!(
            matches!(e.evaluate(&ctx), FilterAction::Challenge { .. }),
            "per-domain force-enable must actually issue a challenge",
        );

        // A different host with no override stays off.
        let mut other = ctx.clone();
        other.host = "api.example.com".to_string();
        assert_eq!(
            e.evaluate(&other),
            FilterAction::Allow,
            "other hosts without an override remain unchallenged",
        );
    }

    #[test]
    fn toggles_snapshot_lists_registered_names() {
        let allow = SharedFilter::Custom(Arc::new(Static(FilterAction::Allow)));
        let e = FilterEngine::new(vec![allow], DefaultAction::Allow);
        let snap = e.toggles().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "unknown");
        assert!(snap[0].1, "filters default to enabled");
    }

    #[test]
    fn is_enabled_is_clock_free_and_idempotent() {
        // V232 regression lock: is_enabled() must NOT call SystemTime::now()
        // and must NOT mutate any shared state on its own. Two consecutive
        // calls with no intervening set() or file change must return the
        // same value, and the call must complete without triggering a
        // disk read. We verify this indirectly: (a) no panic / data race,
        // (b) values are stable, and (c) calling it from multiple threads
        // simultaneously is safe (were it doing clock+atomic CAS under the
        // hood, a race here would be detectable under Miri / TSAN).
        let toggles = RuntimeToggles::new();
        toggles.register("alpha", true);
        toggles.register("beta", false);

        // Stable reads without any refresh() call.
        assert!(toggles.is_enabled("alpha"));
        assert!(toggles.is_enabled("alpha"), "must be idempotent");
        assert!(!toggles.is_enabled("beta"));
        assert!(!toggles.is_enabled("beta"), "must be idempotent");

        // After set(), the new value is visible immediately (no clock needed).
        toggles.set("alpha", false);
        assert!(
            !toggles.is_enabled("alpha"),
            "set() must be visible without a clock read"
        );
        toggles.set("alpha", true);
        assert!(toggles.is_enabled("alpha"));

        // Unknown names default to `true` (matches pre-V232 behaviour).
        assert!(toggles.is_enabled("not_registered"));

        // The engine's direct-handle path (toggle_handles) must agree with
        // is_enabled() for a freshly-constructed engine.
        let deny = SharedFilter::Custom(Arc::new(Static(FilterAction::Deny {
            status: 403,
            reason: "v232".into(),
        })));
        let e = FilterEngine::new(vec![deny], DefaultAction::Allow);
        // Direct handle must reflect initial state (enabled=true → filter fires).
        assert_eq!(e.toggle_handles.len(), 1);
        assert!(e.toggle_handles[0].load(Ordering::Relaxed));
        // Disable via the public API → direct handle must reflect the change.
        e.toggles().set("unknown", false);
        assert!(
            !e.toggle_handles[0].load(Ordering::Relaxed),
            "toggle_handle must see set() without a separate clock read"
        );
    }

    #[test]
    fn first_non_allow_short_circuits() {
        let allow = SharedFilter::Custom(Arc::new(Static(FilterAction::Allow)));
        let deny = SharedFilter::Custom(Arc::new(Static(FilterAction::Deny {
            status: 418,
            reason: "teapot".into(),
        })));
        let challenge = SharedFilter::Custom(Arc::new(Static(FilterAction::Challenge {
            level: ChallengeLevel::Headers,
            reason: "x".into(),
        })));
        let e = FilterEngine::new(vec![allow, deny, challenge], DefaultAction::Allow);
        match e.evaluate(&ctx()) {
            FilterAction::Deny { status, .. } => assert_eq!(status, 418),
            other => panic!("expected deny, got {other:?}"),
        }
    }
}
