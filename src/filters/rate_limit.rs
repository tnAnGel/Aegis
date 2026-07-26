use std::{
    collections::{HashMap, VecDeque, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::proxy::request_context::RequestContext;

use super::{FilterAction, TrafficFilter};

/// Composite bucket key — replaces the previous `String` of
/// `"scope|ip|host"` which cost one `format!()` allocation per check.
/// Fixed-size + derives `Hash`/`Eq` so DashMap lookups stay O(1) with
/// no string hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RateKey {
    scope: u8,
    ip: IpAddr,
    /// 64-bit FNV-style hash of the host name. Collisions across
    /// different hosts would silently share a bucket, but probability
    /// is ~1/2^64 — small enough to ignore for rate-limit purposes
    /// (worst case: two unrelated hosts share quota for a single
    /// bucket window, which already happens for global rate when
    /// `domain_limits` is empty).
    host_hash: u64,
}

/// Prefix length used for the per-IP bucket key when the client is
/// IPv6. A single end host is routinely handed a whole /64 (SLAAC), so
/// keying the "per-IP" bucket on the full /128 lets an attacker rotate
/// freely within their own /64 to dodge per-IP limits. Collapsing to
/// /64 makes the per-IP bucket actually per-allocation for v6. IPv4
/// stays full /32 (one host == one address).
const IPV6_PER_IP_PREFIX: u8 = 64;

impl RateKey {
    fn ip(ip: IpAddr, host_hash: u64) -> Self {
        // IPv4 keeps the full /32 (a single host is one address). IPv6
        // is truncated to a /64 so a client can't rotate within its own
        // allocation to evade the per-IP bucket (see IPV6_PER_IP_PREFIX).
        let ip = match ip {
            IpAddr::V4(_) => ip,
            IpAddr::V6(v6) => IpAddr::V6(v6_prefix(v6, IPV6_PER_IP_PREFIX)),
        };
        Self {
            scope: 0,
            ip,
            host_hash,
        }
    }
    fn subnet24(ip: IpAddr, host_hash: u64) -> Self {
        let ip = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
            }
            IpAddr::V6(v6) => IpAddr::V6(v6_prefix(v6, 48)),
        };
        Self {
            scope: 1,
            ip,
            host_hash,
        }
    }
    fn subnet16(ip: IpAddr, host_hash: u64) -> Self {
        let ip = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpAddr::V4(Ipv4Addr::new(o[0], o[1], 0, 0))
            }
            IpAddr::V6(v6) => IpAddr::V6(v6_prefix(v6, 32)),
        };
        Self {
            scope: 2,
            ip,
            host_hash,
        }
    }
}

/// Stable hash of a host string. Used as the host_hash slot in
/// `RateKey`. Same hasher as DashMap so values don't need re-hashing.
fn host_hash(host: &str) -> u64 {
    let mut h = DefaultHasher::new();
    host.hash(&mut h);
    h.finish()
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Aggregation level for a rate-limit key. We keep them split so a
/// single noisy IP can't poison its whole /24 and a single noisy /24
/// can't poison its whole /16. (Now superseded by `RateKey.scope`
/// numeric discriminator — kept here in case future tests want the
/// human label.)
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum Scope {
    Ip,
    Subnet24,
    Subnet16,
}

impl Scope {
    #[allow(dead_code)]
    fn prefix(self) -> &'static str {
        match self {
            Scope::Ip => "ip",
            Scope::Subnet24 => "s24",
            Scope::Subnet16 => "s16",
        }
    }
}

/// Hard cap on live entries in the per-IP/subnet `state` map. The
/// deployed pingora path never wires `cleanup_stale` into a background
/// loop, so without a cap an attacker rotating source addresses (or
/// /64s) grows the map without bound — a slow memory-exhaustion DoS.
/// When the map crosses this, an insert evicts the single
/// oldest-`last_refill` entry first (LRU-ish), mirroring the
/// `max_trusted` / `evict_lru` pattern in `dynamic_trust.rs`. Sized
/// generously so legitimate traffic never trips it; only a deliberate
/// flood reaches it.
const MAX_STATE_ENTRIES: usize = 1_048_576;
/// Same hard cap for the URI-budget `uri_state` map. Smaller because
/// only paths that match a configured budget ever land here.
const MAX_URI_STATE_ENTRIES: usize = 262_144;

pub struct RateLimitFilter {
    enabled: bool,
    rate: f64,
    burst: f64,
    /// Per-IP / per-subnet bucket store. Typed `RateKey` instead of
    /// `String` avoids `format!()` + per-key allocations on every
    /// request — measurably cheaper at 100k+ RPS where every alloc
    /// shows up in profile.
    state: Arc<DashMap<RateKey, Bucket>>,
    /// URI-budget overrides keep a separate `String`-keyed store —
    /// matcher identity is the natural key here and it's only consulted
    /// for paths that hit a configured budget (rare path).
    uri_state: Arc<DashMap<String, Bucket>>,
    stale_after: Duration,
    domain_limits: HashMap<String, (f64, f64)>,
    subnet_buckets: bool,
    subnet_24_multiplier: f64,
    subnet_16_multiplier: f64,
    /// Compiled URI-budget overrides — `(matcher, rate, burst)`.
    /// First match wins so operators can order specific paths before
    /// catch-all globs.
    uri_budgets: Vec<(UriMatcher, f64, f64)>,
    /// Per-URI hits-per-second tracker. None when disabled.
    hot_uri: Option<HotUriTracker>,
    /// V234 — shared handle to the runtime per-host policy overlay.
    /// When attached (`attach_domain_policy`), `check()` consults it for
    /// a per-host `rate_limit` override BEFORE falling back to the
    /// static `domain_limits` / global defaults. This is the path that
    /// lets the panel set a per-host limit for ops-managed sites (whose
    /// `.conf` is read-only) — the override is disk-backed + cross-worker
    /// via the same store the admin API writes to. Set once at startup;
    /// `None`/empty store ⇒ behaviour identical to before.
    domain_policy: std::sync::OnceLock<crate::domain_policy::DomainPolicyStore>,
}

/// Pattern types accepted in `uri_budgets`: exact path, prefix glob
/// ending in `*`, or "all". Kept tiny on purpose — anything fancier
/// belongs in WAF rules where the operator has the full request
/// context.
#[derive(Debug, Clone)]
enum UriMatcher {
    Exact(String),
    Prefix(String),
}

impl UriMatcher {
    fn from_pattern(p: &str) -> Self {
        if let Some(prefix) = p.strip_suffix('*') {
            Self::Prefix(prefix.to_string())
        } else {
            Self::Exact(p.to_string())
        }
    }
    fn matches(&self, path: &str) -> bool {
        match self {
            UriMatcher::Exact(s) => s == path,
            UriMatcher::Prefix(p) => path.starts_with(p),
        }
    }
    fn key(&self) -> &str {
        match self {
            UriMatcher::Exact(s) => s,
            UriMatcher::Prefix(p) => p,
        }
    }
}

/// Rolling per-URI hit counter. Each path keeps the timestamps of the
/// last `THRESHOLD` requests; when the oldest is < 1s old we've seen
/// `THRESHOLD` hits in the last second → log a warning. The map is
/// bounded by a periodic cleanup so attackers can't exhaust memory by
/// rotating URIs.
struct HotUriTracker {
    /// `VecDeque` (not `Vec`) so expiring the oldest timestamps is an
    /// O(1) `pop_front()` instead of `Vec::remove(0)`'s O(n) shift —
    /// under a flood the inner buffer can hold `threshold` entries and
    /// the front-pop happens on every hit.
    state: DashMap<String, VecDeque<Instant>>,
    threshold: usize,
    window: Duration,
}

impl HotUriTracker {
    fn new(threshold: u64) -> Self {
        Self {
            state: DashMap::new(),
            threshold: threshold as usize,
            window: Duration::from_secs(1),
        }
    }
    fn observe(&self, path: &str, now: Instant) -> bool {
        let mut e = self.state.entry(path.to_string()).or_default();
        e.push_back(now);
        while e
            .front()
            .map(|t| now.duration_since(*t) > self.window)
            .unwrap_or(false)
        {
            e.pop_front();
        }
        e.len() >= self.threshold
    }
    fn cleanup_stale(&self, now: Instant) {
        // Drop URIs with no recent hits.
        self.state.retain(|_, v| {
            v.back()
                .map(|t| now.duration_since(*t) < Duration::from_secs(60))
                .unwrap_or(false)
        });
    }
    fn top(&self, limit: usize) -> Vec<(String, usize)> {
        let mut all: Vec<_> = self
            .state
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().len()))
            .collect();
        all.sort_by_key(|b| std::cmp::Reverse(b.1));
        all.truncate(limit);
        all
    }
}

impl RateLimitFilter {
    pub fn new(
        enabled: bool,
        requests_per_second: u64,
        burst: u64,
        domain_limits: HashMap<String, (u64, u64)>,
    ) -> Self {
        Self::with_subnets(
            enabled,
            requests_per_second,
            burst,
            domain_limits,
            false,
            8,
            64,
        )
    }

    pub fn with_subnets(
        enabled: bool,
        requests_per_second: u64,
        burst: u64,
        domain_limits: HashMap<String, (u64, u64)>,
        subnet_buckets: bool,
        subnet_24_multiplier: u64,
        subnet_16_multiplier: u64,
    ) -> Self {
        Self::with_full_config(
            enabled,
            requests_per_second,
            burst,
            domain_limits,
            subnet_buckets,
            subnet_24_multiplier,
            subnet_16_multiplier,
            Vec::new(),
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_full_config(
        enabled: bool,
        requests_per_second: u64,
        burst: u64,
        domain_limits: HashMap<String, (u64, u64)>,
        subnet_buckets: bool,
        subnet_24_multiplier: u64,
        subnet_16_multiplier: u64,
        uri_budgets: Vec<crate::config::UriBudget>,
        hot_uri_rps_threshold: u64,
    ) -> Self {
        let domain_limits = domain_limits
            .into_iter()
            .map(|(k, (r, b))| (k, (r as f64, b as f64)))
            .collect();
        let uri_budgets = uri_budgets
            .into_iter()
            .map(|b| {
                (
                    UriMatcher::from_pattern(&b.pattern),
                    b.requests_per_second as f64,
                    b.burst as f64,
                )
            })
            .collect();
        let hot_uri = if hot_uri_rps_threshold > 0 {
            Some(HotUriTracker::new(hot_uri_rps_threshold))
        } else {
            None
        };
        Self {
            enabled,
            rate: requests_per_second as f64,
            burst: burst as f64,
            // V230 — boost shard count on rate limiter state for per-IP token bucket parallelism
            state: Arc::new(DashMap::with_shard_amount(128)),
            // V230 — boost shard count on rate limiter state for per-URI token bucket parallelism
            uri_state: Arc::new(DashMap::with_shard_amount(128)),
            stale_after: Duration::from_secs(300),
            domain_limits,
            subnet_buckets,
            subnet_24_multiplier: subnet_24_multiplier.max(1) as f64,
            subnet_16_multiplier: subnet_16_multiplier.max(1) as f64,
            uri_budgets,
            hot_uri,
            domain_policy: std::sync::OnceLock::new(),
        }
    }

    /// V234 — attach the shared per-host policy overlay so `check()` can
    /// honour per-host `rate_limit` overrides set through the admin API.
    /// Called once at startup, after the `FilterEngine` (which owns the
    /// store) is built, with `engine.domain_policy()`. Idempotent: a
    /// second call is ignored (OnceLock).
    pub fn attach_domain_policy(&self, store: crate::domain_policy::DomainPolicyStore) {
        let _ = self.domain_policy.set(store);
    }

    /// V231 — config-time enable flag, read by `FilterEngine` when it
    /// registers this filter's `RuntimeToggle`. `check()` no longer
    /// self-gates on `enabled`; the engine's `RuntimeToggles` /
    /// per-domain `domain_policy` is now the single source of truth, so
    /// per-domain overrides aren't silently double-gated.
    pub fn config_enabled(&self) -> bool {
        self.enabled
    }

    /// First matching URI budget for `path`, or None for default.
    fn uri_budget_for(&self, path: &str) -> Option<&(UriMatcher, f64, f64)> {
        self.uri_budgets.iter().find(|(m, _, _)| m.matches(path))
    }

    pub fn hot_uris(&self, limit: usize) -> Vec<(String, usize)> {
        self.hot_uri
            .as_ref()
            .map(|t| t.top(limit))
            .unwrap_or_default()
    }

    fn limits_for_host(&self, host: &str) -> (f64, f64) {
        // Exact host match wins. Otherwise honour a single leading
        // dot in the configured key as a suffix-glob: `.example.com`
        // matches `api.example.com` and `www.example.com` so admins
        // can budget a whole apex+subdomains tree under one bucket.
        // Falls back to the global default rate/burst.
        if let Some(v) = self.domain_limits.get(host) {
            return *v;
        }
        for (pattern, v) in &self.domain_limits {
            if let Some(suffix) = pattern.strip_prefix('.')
                && host.ends_with(suffix)
            {
                return *v;
            }
        }
        (self.rate, self.burst)
    }

    /// Evict the single oldest-`last_refill` entry from `state` to keep
    /// the map under `MAX_STATE_ENTRIES`. Called only when a brand-new
    /// key would push the map over the cap, so it stays off the hot path
    /// for established clients. Cheap-ish: one O(n) scan for a victim,
    /// matching `dynamic_trust::evict_lru`. Must NOT hold any `entry()`
    /// guard on `state` when called — `iter()`/`remove()` take shard
    /// locks and would deadlock against a held entry on the same shard.
    fn evict_oldest_state(&self) {
        let mut oldest: Option<(RateKey, Instant)> = None;
        for kv in self.state.iter() {
            match oldest {
                Some((_, t)) if t <= kv.value().last_refill => {}
                _ => oldest = Some((*kv.key(), kv.value().last_refill)),
            }
        }
        if let Some((k, _)) = oldest {
            self.state.remove(&k);
        }
    }

    /// `evict_oldest_state` for the URI-budget map.
    fn evict_oldest_uri_state(&self) {
        let mut oldest: Option<(String, Instant)> = None;
        for kv in self.uri_state.iter() {
            match oldest {
                Some((_, t)) if t <= kv.value().last_refill => {}
                _ => oldest = Some((kv.key().clone(), kv.value().last_refill)),
            }
        }
        if let Some((k, _)) = oldest {
            self.uri_state.remove(&k);
        }
    }

    fn allow_typed(&self, key: RateKey, now: Instant, rate: f64, burst: f64) -> bool {
        // Bound memory: if this would be a new key and we're at the cap,
        // make room first. `contains_key` + `len` are cheap relative to
        // the eviction scan, which only runs while over the cap. Done
        // before taking the `entry()` shard lock to avoid deadlock.
        if self.state.len() >= MAX_STATE_ENTRIES && !self.state.contains_key(&key) {
            self.evict_oldest_state();
        }
        let mut entry = self.state.entry(key).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rate).min(burst);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn allow_uri(&self, key: &str, now: Instant, rate: f64, burst: f64) -> bool {
        if self.uri_state.len() >= MAX_URI_STATE_ENTRIES && !self.uri_state.contains_key(key) {
            self.evict_oldest_uri_state();
        }
        let mut entry = self.uri_state.entry(key.to_string()).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * rate).min(burst);
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn cleanup_stale(&self, now: Instant) {
        self.state
            .retain(|_, b| now.duration_since(b.last_refill) <= self.stale_after);
        self.uri_state
            .retain(|_, b| now.duration_since(b.last_refill) <= self.stale_after);
        if let Some(h) = &self.hot_uri {
            h.cleanup_stale(now);
        }
    }
}

/// Truncate IPv6 to a prefix of `bits` bits, zeroing the rest.
fn v6_prefix(ip: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let segments = ip.segments();
    let mut out = [0u16; 8];
    let full_seg = (bits / 16) as usize;
    let remainder_bits = bits % 16;
    for (i, &seg) in segments.iter().enumerate().take(full_seg) {
        out[i] = seg;
    }
    if remainder_bits > 0 && full_seg < segments.len() {
        let mask = !((1u16 << (16 - remainder_bits)) - 1);
        out[full_seg] = segments[full_seg] & mask;
    }
    Ipv6Addr::from(out)
}

impl TrafficFilter for RateLimitFilter {
    fn name(&self) -> &'static str {
        "rate_limit"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // V231 — no `self.enabled` gate here: the `FilterEngine`'s
        // `RuntimeToggles` / per-domain `domain_policy` decides whether
        // this filter runs. Gating again here would double-gate and
        // break per-domain overrides.
        // Dynamic-trust skip: an IP that earned reputation through
        // clean traffic short-circuits the rate-limit. Throttling
        // exists to defend against bursty/unknown clients; trusted
        // clients have already paid that audit cost.
        if ctx.is_trusted {
            return FilterAction::Allow;
        }
        // `ctx.host` is pre-extracted at request ingress (see
        // `ProxyHttpHandler::handle_collected`) — avoids re-hashing
        // the HeaderMap key on every filter that needs Host.
        let host = if ctx.host.is_empty() {
            "_unknown"
        } else {
            ctx.host.as_str()
        };
        // V234 — per-host runtime override (set via admin API, works for
        // ops-managed sites) wins over static `domain_limits` / global
        // defaults. The store has its own empty-gate fast path, so this
        // is a single relaxed atomic load when no overrides exist.
        let (rate, burst) = self
            .domain_policy
            .get()
            .and_then(|store| store.rate_limit_for(host))
            .map(|(r, b)| (r as f64, b as f64))
            .unwrap_or_else(|| self.limits_for_host(host));
        // Hash host once — all RateKey constructors use the same hash.
        let h_hash = host_hash(host);

        // URI-budget override: when a per-URI bucket is configured for
        // this path, charge against it FIRST. We still bill the
        // per-IP/subnet buckets below so the same client can't pivot
        // between matched URIs and burn the whole connection budget.
        let path = ctx.path.split('?').next().unwrap_or(&ctx.path);
        if let Some((matcher, uri_rate, uri_burst)) = self.uri_budget_for(path) {
            // URI budget keys stay String — different matchers can share
            // the same composite (host, ip) but should NOT share a bucket
            // because the matcher identity (pattern) is the bucket
            // discriminator. Only allocates on configured-budget hits
            // which are rare relative to total request volume.
            let uri_key = format!("uri|{}|{host}|{}", matcher.key(), ctx.client_ip);
            if !self.allow_uri(&uri_key, ctx.timestamp, *uri_rate, *uri_burst) {
                return FilterAction::Deny {
                    status: 429,
                    reason: format!("uri rate limit exceeded ({})", matcher.key()).into(),
                };
            }
        }

        if let Some(tracker) = &self.hot_uri
            && tracker.observe(path, ctx.timestamp)
        {
            tracing::warn!(uri = path, "hot URI detected (> threshold rps)");
        }

        // Per-IP bucket — primary spend. Zero-alloc lookup via RateKey.
        let ip_key = RateKey::ip(ctx.client_ip, h_hash);
        if !self.allow_typed(ip_key, ctx.timestamp, rate, burst) {
            return FilterAction::Deny {
                status: 429,
                reason: "rate limit exceeded".into(),
            };
        }

        // Subnet buckets: a botnet that uses 256 different /32s in the
        // same /24 still shares one /24 budget. The multipliers stop
        // legit shared NAT pools from looking like one screamy client.
        if self.subnet_buckets {
            let s24_key = RateKey::subnet24(ctx.client_ip, h_hash);
            if !self.allow_typed(
                s24_key,
                ctx.timestamp,
                rate * self.subnet_24_multiplier,
                burst * self.subnet_24_multiplier,
            ) {
                return FilterAction::Deny {
                    status: 429,
                    reason: "subnet /24 rate limit exceeded".into(),
                };
            }
            let s16_key = RateKey::subnet16(ctx.client_ip, h_hash);
            if !self.allow_typed(
                s16_key,
                ctx.timestamp,
                rate * self.subnet_16_multiplier,
                burst * self.subnet_16_multiplier,
            ) {
                return FilterAction::Deny {
                    status: 429,
                    reason: "subnet /16 rate limit exceeded".into(),
                };
            }
        }

        FilterAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(rps: u64, burst: u64) -> RateLimitFilter {
        RateLimitFilter::new(true, rps, burst, HashMap::new())
    }

    fn make_with_subnets(rps: u64, burst: u64, m24: u64, m16: u64) -> RateLimitFilter {
        RateLimitFilter::with_subnets(true, rps, burst, HashMap::new(), true, m24, m16)
    }

    #[test]
    fn disabled_filter_reports_config_disabled() {
        // V231 — `check()` no longer self-gates on the config-enabled
        // flag (the `FilterEngine` decides whether to run the filter).
        // A filter built disabled simply reports `config_enabled()`
        // false; the engine reads that when registering the toggle.
        let f = RateLimitFilter::new(false, 0, 0, HashMap::new());
        assert!(!f.config_enabled());
    }

    #[test]
    fn burst_drained_then_denied() {
        let f = make(0, 3);
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_header("host", "x");
        for _ in 0..3 {
            assert_eq!(f.check(&ctx), FilterAction::Allow);
        }
        assert!(matches!(
            f.check(&ctx),
            FilterAction::Deny { status: 429, .. }
        ));
    }

    #[test]
    fn refills_over_time() {
        let f = make(1000, 1);
        let mut ctx = RequestContext::test_with("1.1.1.1", "/").with_header("host", "x");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
        ctx.timestamp += Duration::from_millis(50);
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }

    #[test]
    fn per_domain_overrides_default() {
        let mut domain = HashMap::new();
        domain.insert("strict.example".to_string(), (0u64, 1u64));
        let f = RateLimitFilter::new(true, 100, 100, domain);
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_header("host", "strict.example");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn domain_policy_overlay_overrides_global_per_host() {
        // V234 — the runtime per-host overlay (set via admin API, works
        // for ops-managed sites) must win over the generous global
        // limits, and must NOT affect hosts without an override.
        let f = RateLimitFilter::new(true, 1000, 1000, HashMap::new());
        let store = crate::domain_policy::DomainPolicyStore::new();
        store.put(
            "tight.example",
            crate::domain_policy::DomainPolicy {
                rate_limit: Some(crate::domain_policy::RateLimitOverride { rps: 0, burst: 1 }),
                ..Default::default()
            },
        );
        f.attach_domain_policy(store);

        // Host WITH override: burst=1 → first allow, second denied.
        let tight = RequestContext::test_with("9.9.9.9", "/").with_header("host", "tight.example");
        assert_eq!(f.check(&tight), FilterAction::Allow);
        assert!(matches!(
            f.check(&tight),
            FilterAction::Deny { status: 429, .. }
        ));

        // Host WITHOUT override: rides the generous global burst=1000.
        let loose = RequestContext::test_with("8.8.8.8", "/").with_header("host", "loose.example");
        for _ in 0..50 {
            assert_eq!(f.check(&loose), FilterAction::Allow);
        }
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let f = make(10, 5);
        let now = Instant::now();
        f.allow_typed(RateKey::ip("1.1.1.1".parse().unwrap(), 1), now, 10.0, 5.0);
        f.allow_typed(RateKey::ip("1.1.1.2".parse().unwrap(), 1), now, 10.0, 5.0);
        assert_eq!(f.state.len(), 2);
        f.cleanup_stale(now + Duration::from_secs(3600));
        assert_eq!(f.state.len(), 0);
    }

    #[test]
    fn subnet_bucket_blocks_botnet_within_24() {
        // per-IP burst=2, /24 multiplier=2 → /24 budget = 4 tokens.
        // Four distinct IPs in 10.0.0.0/24 should be fine; the fifth
        // request hitting any of them blows the /24 bucket.
        let f = make_with_subnets(0, 2, 2, 8);
        let now = Instant::now();
        for i in 1..=4 {
            let ip = format!("10.0.0.{i}");
            let ctx = RequestContext::test_with(&ip, "/").with_header("host", "x");
            let mut ctx = ctx;
            ctx.timestamp = now;
            assert_eq!(f.check(&ctx), FilterAction::Allow, "ip {i} should pass");
        }
        let ctx5 = RequestContext::test_with("10.0.0.99", "/").with_header("host", "x");
        let mut ctx5 = ctx5;
        ctx5.timestamp = now;
        match f.check(&ctx5) {
            FilterAction::Deny { reason, .. } => assert!(reason.contains("/24")),
            other => panic!("expected /24 deny, got {other:?}"),
        }
    }

    #[test]
    fn subnet_bucket_blocks_botnet_within_16() {
        // 4 hits per /24 (burst=2, mul24=2) = 4 hits used.
        // /16 budget = burst*mul16 = 2*4 = 8. So after 8 total hits
        // anywhere in 10.0.0.0/16, the 9th must hit /16 deny.
        let f = make_with_subnets(0, 2, 2, 4);
        let now = Instant::now();
        // Spread across /24s so /24 budget never depletes; only /16
        // bucket should be the bottleneck.
        let mut count = 0;
        for sub in 0..4u8 {
            for last in 1..=2u8 {
                let ip = format!("10.0.{sub}.{last}");
                let ctx = RequestContext::test_with(&ip, "/").with_header("host", "x");
                let mut ctx = ctx;
                ctx.timestamp = now;
                if matches!(f.check(&ctx), FilterAction::Allow) {
                    count += 1;
                }
            }
        }
        // Burst was 8 — all 8 should have passed.
        assert_eq!(count, 8);
        let ctx9 = RequestContext::test_with("10.0.9.1", "/").with_header("host", "x");
        let mut ctx9 = ctx9;
        ctx9.timestamp = now;
        match f.check(&ctx9) {
            FilterAction::Deny { reason, .. } => {
                assert!(reason.contains("/16"), "got {reason}")
            }
            other => panic!("expected /16 deny, got {other:?}"),
        }
    }

    #[test]
    fn uri_budget_overrides_default_for_matching_path() {
        let cfg_budgets = vec![crate::config::UriBudget {
            pattern: "/api/expensive".to_string(),
            requests_per_second: 0,
            burst: 1,
        }];
        let f = RateLimitFilter::with_full_config(
            true,
            100,
            100,
            HashMap::new(),
            false,
            8,
            64,
            cfg_budgets,
            0,
        );
        let mut ctx =
            RequestContext::test_with("1.1.1.1", "/api/expensive").with_header("host", "x");
        // burst 1 → first allowed, second denied with uri-specific reason.
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        ctx.timestamp += Duration::from_micros(1);
        match f.check(&ctx) {
            FilterAction::Deny { reason, .. } => assert!(reason.contains("uri")),
            other => panic!("expected uri deny, got {other:?}"),
        }
    }

    #[test]
    fn uri_budget_prefix_glob_works() {
        let f = RateLimitFilter::with_full_config(
            true,
            100,
            100,
            HashMap::new(),
            false,
            8,
            64,
            vec![crate::config::UriBudget {
                pattern: "/api/*".to_string(),
                requests_per_second: 0,
                burst: 1,
            }],
            0,
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/api/v1/users").with_header("host", "x");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        assert!(matches!(
            f.check(&ctx),
            FilterAction::Deny { reason, .. } if reason.contains("uri")
        ));
    }

    #[test]
    fn hot_uri_tracker_surfaces_top_paths() {
        let f = RateLimitFilter::with_full_config(
            true,
            1000,
            1000,
            HashMap::new(),
            false,
            8,
            64,
            vec![],
            3, // threshold = 3 hits/sec
        );
        let ctx = RequestContext::test_with("1.1.1.1", "/expensive").with_header("host", "x");
        for _ in 0..5 {
            f.check(&ctx);
        }
        let top = f.hot_uris(5);
        assert!(top.iter().any(|(u, _)| u == "/expensive"));
    }

    #[test]
    fn ipv6_subnet_keys_distinguish_prefixes() {
        // Both addresses are in 2001:db8:1234::/48 — different 4th
        // segment, same first three. Subnet24 keys (now typed) must
        // compare equal because the truncated IPv6 prefix is identical.
        let h = host_hash("x");
        let a = RateKey::subnet24("2001:db8:1234:5678::1".parse().unwrap(), h);
        let b = RateKey::subnet24("2001:db8:1234:9999::1".parse().unwrap(), h);
        assert_eq!(a, b);
        // Different /48 → distinct key.
        let c = RateKey::subnet24("2001:db8:abcd:5678::1".parse().unwrap(), h);
        assert_ne!(a, c);
    }

    #[test]
    fn ipv6_per_ip_key_collapses_same_64() {
        // H3 — two addresses sharing a /64 (same first four segments,
        // different host bits) must collapse to one per-IP bucket key so
        // an attacker can't rotate within their own /64 to dodge the
        // per-IP limit.
        let h = host_hash("x");
        let a = RateKey::ip("2001:db8:1:2::1".parse().unwrap(), h);
        let b = RateKey::ip("2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap(), h);
        assert_eq!(a, b, "same /64 must share the per-IP bucket");
        // A different /64 stays distinct.
        let c = RateKey::ip("2001:db8:1:3::1".parse().unwrap(), h);
        assert_ne!(a, c);
        // IPv4 still keyed on the full /32.
        let v4a = RateKey::ip("1.2.3.4".parse().unwrap(), h);
        let v4b = RateKey::ip("1.2.3.5".parse().unwrap(), h);
        assert_ne!(v4a, v4b);
    }

    #[test]
    fn ipv6_rotation_within_64_shares_quota() {
        // End-to-end view of H3: burst=1 per-IP, two distinct /128s in
        // the same /64 → second request denied (shared bucket).
        let f = make(0, 1);
        let now = Instant::now();
        let mut a = RequestContext::test_with("2001:db8:aa:bb::1", "/").with_header("host", "x");
        a.timestamp = now;
        let mut b = RequestContext::test_with("2001:db8:aa:bb::2", "/").with_header("host", "x");
        b.timestamp = now;
        assert_eq!(f.check(&a), FilterAction::Allow);
        assert!(matches!(
            f.check(&b),
            FilterAction::Deny { status: 429, .. }
        ));
    }

    #[test]
    fn state_map_evicts_when_over_cap() {
        // H2(a) — the per-IP/subnet map is bounded: once at the cap a
        // new key evicts the oldest entry instead of growing forever.
        let f = make(10, 5);
        let now = Instant::now();
        // Seed exactly at the cap with monotonically newer last_refill,
        // so entry #0 (the oldest) is the eviction victim.
        for i in 0..MAX_STATE_ENTRIES {
            let key = RateKey::ip(IpAddr::V4(Ipv4Addr::from(i as u32)), 0);
            f.allow_typed(key, now + Duration::from_nanos(i as u64), 10.0, 5.0);
        }
        assert_eq!(f.state.len(), MAX_STATE_ENTRIES);
        let oldest = RateKey::ip(IpAddr::V4(Ipv4Addr::from(0u32)), 0);
        assert!(f.state.contains_key(&oldest));
        // One more distinct key trips eviction; len stays at the cap and
        // the oldest entry is gone.
        let fresh = RateKey::ip(IpAddr::V4(Ipv4Addr::from(u32::MAX)), 0);
        f.allow_typed(fresh, now + Duration::from_secs(1), 10.0, 5.0);
        assert_eq!(f.state.len(), MAX_STATE_ENTRIES);
        assert!(!f.state.contains_key(&oldest), "oldest entry was evicted");
        assert!(f.state.contains_key(&fresh));
    }
}
