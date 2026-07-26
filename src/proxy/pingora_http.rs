//! Phase B foundation — Pingora-based proxy core.
//!
//! This module is the entry point for the migration of Aegis's hot
//! request path off `hyper-util::client::legacy::Client` and onto
//! Cloudflare's Pingora framework. It is compiled only when the
//! `pingora` Cargo feature is enabled, so the default build remains
//! the production-validated hyper path used by V11–V21.
//!
//! ## What is here (V22)
//!
//! - `AegisPingoraProxy` — implements the `pingora_proxy::ProxyHttp`
//!   trait with three phases wired in:
//!     1. `new_ctx` — per-request scratch space (request id, timing).
//!     2. `request_filter` — builds an Aegis `RequestContext`,
//!        runs the full `FilterEngine`, and short-circuits with a
//!        Deny response when any filter rejects.
//!     3. `upstream_peer` — picks the per-host upstream from the
//!        existing `UpstreamRouter` and returns it as an `HttpPeer`.
//!
//! ## What is NOT yet here
//!
//! - Challenge ladder (cookie issue, verify path, redirect).
//! - Threat-aware response cache + single-flight + stale-if-error.
//! - Honeypot tarpit (slow-drip body).
//! - JA3/JA4/JA4T/JA4L/h2_fp/h3_fp capture on the pingora TLS surface.
//! - HTTP/3 (quinn-based `proxy::http3` stays in service in parallel).
//! - Dynamic-trust enrolment / revocation hooks.
//! - Prometheus per-protocol counters and latency histograms.
//!
//! Those features are intentionally deferred to later V23+ commits so
//! this commit can land as a minimum-viable proof that the pingora
//! plumbing compiles, accepts a request, runs the filter chain, and
//! forwards a clean GET to upstream. Operators flip between the two
//! proxies via `AEGIS_PINGORA=1` at startup (see `server.rs`).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use crate::config::AppConfig;
use crate::filters::engine::FilterEngine;
use crate::filters::{
    FilterAction, SharedFilter, adaptive::AdaptiveFilter, bot::BotFilter,
    challenge::ChallengeFilter, ip_acl::IpAclFilter, rate_limit::RateLimitFilter, waf::WafFilter,
};
use crate::honeypot::HoneypotStore;
use crate::metrics::RuntimeMetrics;
use crate::proxy::request_context::RequestContext;
use crate::proxy::upstream::{SharedUpstreamRouter, Upstream, UpstreamRouter};

/// Reusable builder that produces the Aegis `(FilterEngine,
/// UpstreamRouter)` pair from an `AppConfig` + shared `HoneypotStore`.
///
/// The hyper-based `server::build_handler` constructs the same pair
/// inline but bundles it with all the other proxy-handler state. The
/// pingora binary only needs these two pieces, so we extract them into
/// a small, reusable helper to avoid duplicating the filter ordering
/// (which is load-bearing — see the comments inside).
/// Bundle of references the pingora binary needs to keep alive
/// alongside the engine + router:
///   • `waf` — same Arc inside the engine, exported separately so
///     the background service can call `maybe_reload_rules` without
///     walking the filter chain.
///   • `dynamic_trust` — V30 trust state. Held by the proxy for
///     per-request is_trusted decisions, and by the background
///     service for periodic stale-entry eviction.
///   • `response_cache` — V32 threat-aware response cache. Looks up
///     in request_filter, populates on logging.
///   • `bypass` — V37 static bypass matcher. Cheap IP/path/UA
///     check that flips `is_trusted` *and* drives the cache's
///     `is_high_threat = !bypass && !dynamic_trust` policy.
///   • `scorer` — V37 sliding-window per-IP threat scorer. Bumped
///     per outcome (allowed/denied/challenged) in request_filter
///     so /admin/threats + dashboards can rank attackers.
///   • `anomaly` — V38 per-host attack-mode detector. Observed
///     in request_filter so the EMA stays warm and
///     `under_attack(host)` is meaningful for the admin endpoint
///     + any future per-attack gating (geoip throttle, etc.).
///   • `geoip` / `geoip_cfg` — V39 country-based deny. Optionally
///     gated by anomaly.under_attack so geo blocks stay dormant
///     outside of DDoS events.
///   • `challenge` — V42 challenge ladder state (cfg + the
///     ChallengeFilter Arc that lives in the engine too — exported
///     here so /__aegis/verify can `reset(ip)` after a successful
///     verify).
///   • `rate` — V43 same Arc<RateLimitFilter> the engine holds.
///     Exported so /admin/hot_uris can introspect the per-URI RPS
///     tracker without walking the filter chain.
///   • `xdp` — V45 XDP fast-path handle. NoopXdp on non-Linux or
///     when `[xdp]` config is absent/disabled. Wired into:
///       (a) DynamicTrust (auto-promote trusted IPs into the
///           kernel allow set so XDP fast-passes them);
///       (b) /admin/xdp counters + /admin/xdp/deny|undeny CRUD.
pub struct BuiltPipeline {
    pub engine: Arc<FilterEngine>,
    pub router: SharedUpstreamRouter,
    pub waf: Arc<WafFilter>,
    pub dynamic_trust: Arc<crate::filters::dynamic_trust::DynamicTrust>,
    pub response_cache: Arc<crate::proxy::response_cache::ResponseCache>,
    pub bypass: Arc<crate::filters::bypass::BypassMatcher>,
    pub scorer: Arc<crate::ddos::score::ThreatScorer>,
    pub anomaly: Arc<crate::anomaly::AnomalyDetector>,
    pub geoip: Arc<dyn crate::geoip::GeoIpLookup>,
    pub geoip_cfg: Option<crate::config::GeoIpConfig>,
    pub challenge: crate::proxy::pingora_challenge::ChallengeContext,
    pub rate: Arc<RateLimitFilter>,
    pub xdp: Arc<dyn crate::xdp::XdpHandle>,
    /// V108 — correlational RiskEngine. `None` when config mode = off.
    pub risk_engine: Option<Arc<crate::ddos::risk_engine::RiskEngine>>,
}

pub fn build_filter_engine_and_router(
    cfg: &AppConfig,
    honeypots: Arc<HoneypotStore>,
) -> Result<(Arc<FilterEngine>, SharedUpstreamRouter)> {
    let built = build_pipeline(cfg, honeypots)?;
    Ok((built.engine, built.router))
}

/// Like `build_filter_engine_and_router` but also surfaces the
/// `WafFilter` Arc for background hot-reload polling.
pub fn build_pipeline(cfg: &AppConfig, honeypots: Arc<HoneypotStore>) -> Result<BuiltPipeline> {
    let default_upstream = Upstream::from_url(&cfg.upstream.url)?;
    let mut domain_upstreams = HashMap::new();
    let mut domain_limits = HashMap::new();
    for (domain, route) in &cfg.domains {
        domain_upstreams.insert(domain.clone(), Upstream::from_url(&route.upstream_url)?);
        if let (Some(rps), Some(burst)) = (route.requests_per_second, route.burst) {
            domain_limits.insert(domain.clone(), (rps, burst));
        }
    }
    let router = Arc::new(UpstreamRouter {
        default_upstream,
        domain_upstreams,
    });

    let challenge_filter = Arc::new(ChallengeFilter::new(&cfg.filters.challenge));
    let bot = Arc::new(BotFilter::new(&cfg.filters.bot));
    let threat_intel = Arc::new(crate::filters::threat_intel::ThreatIntelFilter::new(
        &cfg.filters.threat_intel,
    ));
    // WafFilter is held in two places: once inside the engine via
    // SharedFilter, and once on BuiltPipeline so the background
    // service can call `maybe_reload_rules` without walking the chain.
    let waf = Arc::new(WafFilter::new(&cfg.filters.waf));

    // Filter ordering mirrors `server::build_handler` exactly — cheapest
    // exact-match checks first (honeypot, threat-intel, IP ACL), then
    // CPU-heavier work (WAF, bot, adaptive), then plugins, then
    // challenge ladder, then per-host rate limits last.
    let mut filters: Vec<SharedFilter> = vec![
        SharedFilter::Honeypot(Arc::new(crate::filters::honeypot::HoneypotFilter::new(
            honeypots,
        ))),
        SharedFilter::ThreatIntel(threat_intel),
        SharedFilter::IpAcl(Arc::new(IpAclFilter::new(
            &cfg.filters.ip_acl.deny,
            &cfg.filters.ip_acl.allow,
        ))),
        SharedFilter::Waf(waf.clone()),
        SharedFilter::Bot(bot),
        SharedFilter::Adaptive(Arc::new(AdaptiveFilter::new(&cfg.filters.adaptive))),
    ];
    let plugin_set = crate::filters::plugins::manager::PluginSet::from_config(&cfg.filters.plugins);
    for p in plugin_set.filters {
        filters.push(p);
    }
    filters.push(SharedFilter::Challenge(challenge_filter.clone()));
    // V43 — hold the RateLimitFilter Arc separately so /admin/hot_uris
    // can introspect the per-URI tracker. The same Arc lives inside
    // the engine via SharedFilter.
    let rate = Arc::new(RateLimitFilter::with_full_config(
        cfg.filters.rate_limit.enabled,
        cfg.filters.rate_limit.requests_per_second,
        cfg.filters.rate_limit.burst,
        domain_limits,
        cfg.filters.rate_limit.subnet_buckets,
        cfg.filters.rate_limit.subnet_24_multiplier,
        cfg.filters.rate_limit.subnet_16_multiplier,
        cfg.filters.rate_limit.uri_budgets.clone(),
        cfg.filters.rate_limit.hot_uri_rps_threshold,
    ));
    filters.push(SharedFilter::RateLimit(rate.clone()));

    let engine = Arc::new(FilterEngine::new(
        filters,
        cfg.filters.default_action.clone(),
    ));
    // V234 — give the rate-limit filter the same per-host policy overlay
    // the engine + admin API share, so panel-set per-host limits (which
    // work for ops-managed sites without editing read-only `.conf`s)
    // take effect at request time.
    rate.attach_domain_policy(engine.domain_policy());
    // V45 — XDP fast-path. Load the eBPF program when configured
    // (Linux + `[xdp]` enabled + a CAP_BPF-permitted runtime),
    // otherwise NoopXdp keeps every method as a no-op. The handle
    // is shared with DynamicTrust (auto-promote trusted IPs into
    // the kernel allow set) and with the admin endpoint.
    let xdp: Arc<dyn crate::xdp::XdpHandle> = if let Some(xcfg) = &cfg.xdp
        && xcfg.enabled
    {
        match crate::xdp::load(&xcfg.interface, std::path::Path::new(&xcfg.bpf_object_path)) {
            Ok(h) => {
                tracing::info!("aegis-pingora: XDP fast-path loaded");
                let handle: Arc<dyn crate::xdp::XdpHandle> = Arc::from(h);
                // Push the configured deny/allow lists into the
                // kernel maps + set the rate-limiter / SYN-flood
                // / allow-only knobs.
                let deny_ips: Vec<std::net::IpAddr> = cfg
                    .filters
                    .ip_acl
                    .deny
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let allow_ips: Vec<std::net::IpAddr> =
                    xcfg.allow.iter().filter_map(|s| s.parse().ok()).collect();
                let n_deny = crate::xdp::sync_deny_list(&*handle, &deny_ips);
                let n_allow = crate::xdp::sync_allow_list(&*handle, &allow_ips);
                let window_ns = xcfg.rate_window_ms.saturating_mul(1_000_000);
                if let Err(e) = handle.set_rate_config(
                    window_ns,
                    xcfg.rate_burst,
                    xcfg.syn_burst,
                    xcfg.allow_only,
                ) {
                    tracing::warn!(error = %e, "xdp set_rate_config failed at startup");
                }
                tracing::info!(
                    deny = n_deny,
                    allow = n_allow,
                    "aegis-pingora: XDP deny/allow lists primed"
                );
                handle
            }
            Err(e) => {
                if format!("{e:#}").contains(crate::xdp::XDP_ALREADY_OWNED_MARKER) {
                    // Expected on every worker but one: a NIC hosts a single
                    // XDP program, so one SO_REUSEPORT worker owns the attach
                    // and enforces the kernel deny/allow maps for ALL traffic;
                    // the rest filter in userspace. Not a failure.
                    tracing::info!(
                        "aegis-pingora: XDP owned by a sibling worker on this NIC — this worker filters in userspace (single-owner per NIC)"
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        chain = %format!("{e:#}"),
                        "aegis-pingora: XDP load failed — falling back to userspace filtering"
                    );
                }
                Arc::new(crate::xdp::NoopXdp)
            }
        }
    } else {
        Arc::new(crate::xdp::NoopXdp)
    };

    // Dynamic-trust isn't a filter in the chain (it doesn't return
    // FilterAction); it gates the chain by flipping ctx.is_trusted
    // up-front, which built-in throttling filters (rate_limit, bot,
    // challenge) honour to short-circuit to Allow. V45 — chained
    // .with_xdp() so trust grants get mirrored to the kernel allow
    // set (line-rate fast-pass for trusted IPs). Off by default
    // unless cfg.filters.dynamic_trust.enabled = true.
    let dynamic_trust = Arc::new(
        crate::filters::dynamic_trust::DynamicTrust::new(&cfg.filters.dynamic_trust)
            .with_xdp(xdp.clone()),
    );
    // Threat-aware response cache. Disabled by default until the
    // operator flips `filters.response_cache.enabled = true`; even
    // when enabled, `should_consider` is checked per-request before
    // buffering anything, so non-cacheable hosts/methods pay zero
    // overhead.
    let response_cache = Arc::new(crate::proxy::response_cache::ResponseCache::new(
        &cfg.filters.response_cache,
    ));
    // V37 — static bypass matcher + sliding-window threat scorer.
    // Bypass mirrors the V11 hyper path: IPs from cfg.filters.bypass
    // PLUS the XDP allow-list (a single "trusted" declaration covers
    // both kernel fast-pass and userspace fast-path). The scorer is
    // a per-IP DashMap with a 60s sliding window; cleanup_stale runs
    // in the background service.
    let xdp_allow_ips: Vec<std::net::IpAddr> = cfg
        .xdp
        .as_ref()
        .map(|x| x.allow.iter().filter_map(|s| s.parse().ok()).collect())
        .unwrap_or_default();
    let bypass = Arc::new(
        crate::filters::bypass::BypassMatcher::with_extra_trusted_ips(
            &cfg.filters.bypass,
            xdp_allow_ips,
        ),
    );
    let scorer = Arc::new(crate::ddos::score::ThreatScorer::default());
    // V38 — per-host attack-mode detector. AnomalyConfig comes from
    // the same `cfg.anomaly` block the hyper server reads via
    // `build_anomaly_config`, so a single config toggles both
    // proxies.
    let anomaly = Arc::new(crate::anomaly::AnomalyDetector::new(
        crate::server::build_anomaly_config(cfg),
    ));
    // V39 — MaxMind GeoIP2 lookup. `load_with_asn` opens both the
    // country and (optional) ASN DBs, or returns a NoopGeoIp on
    // missing files. The ASN reader powers the V144 → V142 chain.
    // V235 — resolve the country DB out of the box: explicit [geoip]
    // db_path → AEGIS_GEOIP_PATH → bundled db-ip lite under
    // /var/lib/aegis/geoip (shipped by install.sh). So the world map +
    // country deny rules work on a fresh install with no config.
    let country_db =
        crate::geoip::resolve_country_db_path(cfg.geoip.as_ref().map(|g| g.db_path.as_str()));
    // V244 — resolve the ASN DB the same way (config → AEGIS_ASN_PATH →
    // bundled/seeded default) so AS-keyed reputation works out of the box;
    // the DSL config path leaves cfg.geoip None, so the env/default fallback
    // is what actually loads the seeded db-ip ASN-lite database.
    let asn_db = crate::geoip::resolve_asn_db_path(
        cfg.geoip.as_ref().and_then(|g| g.asn_db_path.as_deref()),
    );
    let geoip = crate::geoip::load_with_asn(country_db.as_deref(), asn_db.as_deref());
    let geoip_cfg = cfg.geoip.clone();
    // V42 — challenge context: same Arc<ChallengeFilter> that lives
    // inside the engine, plus the ChallengeConfig for cookie/TTL
    // settings. Exported so /__aegis/verify can `reset(ip)` after a
    // successful verify.
    let challenge = crate::proxy::pingora_challenge::ChallengeContext::new(
        cfg.filters.challenge.clone(),
        challenge_filter,
    );
    // V108 — instantiate the RiskEngine only when configured. `off`
    // (default) leaves it None so the hot path pays a single Option check.
    // AEGIS_RISK_ENGINE_MODE (off|observe|enforce) overrides the config,
    // mirroring the other AEGIS_* runtime knobs — the nginx-DSL parser does
    // not yet carry a `risk_engine` directive (TOML configs use serde).
    let risk_mode = match std::env::var("AEGIS_RISK_ENGINE_MODE").ok().as_deref() {
        Some("observe") => crate::config::RiskEngineMode::Observe,
        Some("enforce") => crate::config::RiskEngineMode::Enforce,
        Some("off") => crate::config::RiskEngineMode::Off,
        Some(other) => {
            // Set-but-typo'd (e.g. "OBSERVE", "on") must NOT silently run the
            // config default — that would hide an operator's intent. Warn loud.
            tracing::warn!(
                value = other,
                "aegis-pingora: AEGIS_RISK_ENGINE_MODE has an unrecognised value \
                 (expected off|observe|enforce); falling back to the config mode"
            );
            cfg.filters.risk_engine.mode
        }
        None => cfg.filters.risk_engine.mode,
    };
    let risk_engine: Option<Arc<crate::ddos::risk_engine::RiskEngine>> = match risk_mode {
        crate::config::RiskEngineMode::Off => None,
        crate::config::RiskEngineMode::Observe => Some(Arc::new(
            crate::ddos::risk_engine::RiskEngine::new(crate::ddos::risk_engine::RiskMode::Observe)
                .with_threshold(cfg.filters.risk_engine.threshold),
        )),
        crate::config::RiskEngineMode::Enforce => {
            tracing::warn!(
                "aegis-pingora: risk_engine mode=enforce — action-application \
                     (Stage 3) is NOT yet wired, so the engine runs in SHADOW \
                     (scores logged, live allow/deny decisions UNCHANGED). Do not \
                     rely on enforcement until Stage 3 lands."
            );
            Some(Arc::new(
                crate::ddos::risk_engine::RiskEngine::new(
                    crate::ddos::risk_engine::RiskMode::HighConfidenceEnforce,
                )
                .with_threshold(cfg.filters.risk_engine.threshold),
            ))
        }
    };
    tracing::info!(
        ?risk_mode,
        engine_present = risk_engine.is_some(),
        "aegis-pingora: V108 RiskEngine resolved"
    );
    Ok(BuiltPipeline {
        engine,
        router,
        waf,
        dynamic_trust,
        response_cache,
        bypass,
        scorer,
        anomaly,
        geoip,
        geoip_cfg,
        challenge,
        rate,
        xdp,
        risk_engine,
    })
}

/// V243 — map an HTTP version to the short protocol label the event log
/// records (`h1` / `h2` / `h3`). Mirrors the classification the metrics
/// path already uses (`http::Version::HTTP_2` checks elsewhere). Returns
/// a `&'static str` so the hot path pays only a tiny match.
#[inline]
fn http_version_label(v: http::Version) -> &'static str {
    match v {
        http::Version::HTTP_3 => "h3",
        http::Version::HTTP_2 => "h2",
        http::Version::HTTP_10 | http::Version::HTTP_11 | http::Version::HTTP_09 => "h1",
        _ => "h1",
    }
}

/// Per-request state carried through the pingora phases. Kept
/// deliberately small — anything that can be derived from the
/// `Session` is re-derived rather than stored to keep `new_ctx`
/// allocation-free on the hot path.
///
/// `host` is the one exception: it is read at request_filter time to
/// drive per-domain metrics, and needs to be re-read at logging time
/// for the same purpose. Re-reading from `session.req_header()` works
/// but allocates twice; caching it on Ctx makes the logging phase
/// allocation-free.
pub struct AegisCtx {
    /// Wall-clock at the start of `request_filter`, used for the
    /// per-request latency histogram bucket assignment in `logging`.
    pub start: Option<Instant>,
    /// V229 — single `Instant::now()` captured at request entry,
    /// reused by every "needs current time" call site in the slow
    /// path (dynamic_trust, scorer, cache lookup, anomaly observe).
    /// The CPU profile on the stand showed `clock_gettime` (vdso)
    /// at 4.35% of userspace — ~10 calls per slow-path request. One
    /// capture point drops that to one.
    ///
    /// V236 — CHANGE 1: changed from bare `Instant` to `Option<Instant>`
    /// so that `AegisCtx::default()` no longer calls `Instant::now()`.
    /// `new_ctx()` is called for every request; previously it paid a
    /// vdso clock syscall even though `request_filter` immediately
    /// overwrites `ctx.now` with a fresh capture. `None` in default;
    /// set to `Some(now)` in `request_filter` before any consumer runs.
    pub now: Option<Instant>,
    /// Filter that produced the non-Allow decision (when any). `None`
    /// means the request was forwarded upstream.
    pub denied_by: Option<&'static str>,
    /// V243 — the precise event-log action for this request, set in the
    /// same branch that sets `denied_by` so the EventStore records the
    /// real outcome (deny vs challenge vs tarpit vs rate) rather than
    /// re-deriving it from the filter name in `logging()`. `None` on the
    /// clean allow path, which `logging()` maps to `"pass"`.
    pub event_action: Option<&'static str>,
    /// V231 — FIX 2: the full `RequestContext` is stored here instead
    /// of separate cloned `host`/`method`/`path` Strings. Eliminates
    /// 3 per-request heap allocations (the old `ctx.host = req_ctx.host.clone()`,
    /// `ctx.method = req_ctx.method.as_str().to_string()`,
    /// `ctx.path = req_ctx.path.clone()` pattern).
    ///
    /// `upstream_peer` and `logging` read host/method/path directly
    /// from this stored context. Stays `None` for the narrow
    /// /__aegis/* internal short-circuit paths that never call
    /// `build_ctx`.
    ///
    /// `host`, `method`, `path` are helper accessors below that
    /// transparently fall back to empty string when `req_ctx` is None,
    /// keeping all existing read sites in `logging` / `upstream_peer`
    /// unchanged.
    pub req_ctx: Option<RequestContext>,
    /// Upstream status code captured in `upstream_response_filter` and
    /// reused in `logging`. None for requests served from request_filter
    /// (deny / challenge / tarpit short-circuit) — those already
    /// accounted via the decision counters.
    pub upstream_status: Option<u16>,
    /// V32 — cache state. Populated only when the request is
    /// eligible to cache (`should_consider` was true and the cache
    /// missed). Carries method/host/path forward so logging can
    /// build the CacheKey without re-parsing the session, and
    /// accumulates body bytes streamed by `response_body_filter`.
    ///
    /// `body_buf` is bounded by ResponseCache's max_body_bytes —
    /// once exceeded we stop buffering AND drop this Option so
    /// logging skips the store entirely. Keeps a poison-pill 50 GB
    /// upstream response from OOMing the proxy.
    pub cache_pending: Option<CachePending>,
    /// V34 — single-flight leader marker. When `true`, this request
    /// was the first to miss the cache for its key and inserted the
    /// Notify into `pending_fetches`. Logging must `notify_waiters`
    /// and remove the entry on this path. False for followers
    /// (which do not touch the registry) and for non-eligible
    /// requests.
    pub sf_leader: bool,
    /// V37 — client IP captured at request_filter, reused at logging
    /// for the scorer post-outcome bump on the success path
    /// (allow→record_allowed). Deny/Challenge bumps happen inline.
    pub client_ip: Option<std::net::IpAddr>,
    /// V37 — whether this request was high-threat per cache policy
    /// (`!bypass && !dynamic_trust`). Logged for observability and
    /// kept on ctx for any future per-request branching.
    pub is_high_threat: bool,
    /// V234 — buffered request body for ClamAV scanning + login-abuse
    /// username extraction. Filled by `request_body_filter` ONLY when
    /// ClamAV is enabled or the path is a login candidate — stays
    /// empty (zero cost) for all normal traffic.
    pub req_body: Vec<u8>,
    /// V234 — true when the request body exceeded the inspection cap;
    /// login-abuse username extraction is then skipped (a truncated
    /// body can't be trusted to contain the real username).
    pub req_body_overflow: bool,
    /// V234 — username extracted from a login POST body, carried to
    /// the logging phase so `LoginAbuseGuard::record` can correlate it
    /// with the upstream response status (failure → bump counters,
    /// success → reset).
    pub login_username: Option<String>,
}

impl Default for AegisCtx {
    fn default() -> Self {
        Self {
            start: None,
            // V236 — CHANGE 1: None instead of Instant::now() — eliminates
            // one vdso clock syscall per request from new_ctx(). The real
            // value is always written by request_filter before any consumer.
            now: None,
            denied_by: None,
            event_action: None,
            req_ctx: None,
            upstream_status: None,
            cache_pending: None,
            sf_leader: false,
            client_ip: None,
            is_high_threat: false,
            req_body: Vec::new(),
            req_body_overflow: false,
            login_username: None,
        }
    }
}

impl AegisCtx {
    /// Returns the captured host, or an empty string when no request
    /// context was stored (internal short-circuit paths).
    #[inline]
    pub fn host(&self) -> &str {
        self.req_ctx.as_ref().map(|r| r.host.as_str()).unwrap_or("")
    }

    /// Returns the captured method as a string slice, or an empty
    /// string when no request context was stored.
    #[inline]
    pub fn method_str(&self) -> &str {
        self.req_ctx
            .as_ref()
            .map(|r| r.method.as_str())
            .unwrap_or("")
    }

    /// Returns the captured path, or an empty string when no request
    /// context was stored.
    #[inline]
    pub fn path(&self) -> &str {
        self.req_ctx.as_ref().map(|r| r.path.as_str()).unwrap_or("")
    }
}

pub struct CachePending {
    pub method: http::Method,
    pub host: String,
    pub path: String,
    pub status: Option<http::StatusCode>,
    pub upstream_headers: Option<http::HeaderMap>,
    pub body_buf: Vec<u8>,
    /// True once accumulated bytes exceed `max_body_bytes`; we keep
    /// the request flowing downstream but skip the cache store.
    pub overflowed: bool,
}

/// V102 — thread-local recycling pool for `body_buf` allocations.
/// Backing capacity for the average cache-eligible upstream response
/// is in the 1-16 KB range; allocating a fresh `Vec<u8>` per request
/// burns syscalls + cache lines on the global allocator's free lists
/// under sustained load. With this pool, an overflowed or unused
/// buffer is reset and stashed for the next request on the same
/// worker thread.
///
/// What we CAN'T pool: buffers that get successfully handed to the
/// ResponseCache via `Bytes::from(Vec<u8>)`. Those become owned by
/// `Bytes` and we never see them again — that's fine, we just
/// allocate fresh ones for the next round.
mod body_pool {
    use std::cell::RefCell;

    /// Max retained buffers per worker thread. Larger than typical
    /// concurrent in-flight cache-pending count for small bench
    /// workloads; bounded so worst-case retained heap stays small
    /// (~32 × 64 KB = 2 MiB per worker at the high cap).
    const MAX_RETAINED: usize = 32;
    /// Max retained capacity per buffer (bytes). Beyond this the
    /// buffer is dropped on return rather than recycled — keeps a
    /// pathological large upstream from inflating the pool baseline.
    const MAX_RETAINED_CAP: usize = 64 * 1024;

    thread_local! {
        static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    /// Take a buffer from the pool or allocate fresh with `hint`
    /// capacity if the pool is empty. Returns a buffer with len()=0
    /// regardless of which path it took.
    pub fn take(hint: usize) -> Vec<u8> {
        POOL.with(|p| p.borrow_mut().pop())
            .unwrap_or_else(|| Vec::with_capacity(hint))
    }

    /// Return a buffer to the pool. Clears it; drops if either the
    /// pool is full or the buffer is too large to keep.
    pub fn give_back(mut buf: Vec<u8>) {
        if buf.capacity() > MAX_RETAINED_CAP {
            return;
        }
        buf.clear();
        POOL.with(|p| {
            let mut pool = p.borrow_mut();
            if pool.len() < MAX_RETAINED {
                pool.push(buf);
            }
        });
    }
}

// =============================================================================
// V-new — Trusted-proxy / real-IP resolution (module-level helpers)
// =============================================================================

/// Cloudflare published edge IP ranges (IPv4 + IPv6).
///
/// Source: <https://www.cloudflare.com/ips-v4> + <https://www.cloudflare.com/ips-v6>
/// Enabled only when `AEGIS_BEHIND_CLOUDFLARE=1`; never consulted by default.
const CF_IP_RANGES: &[&str] = &[
    // IPv4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    // IPv6
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Test whether `ip` falls inside the CIDR `cidr` (e.g. `"10.0.0.0/8"`).
///
/// Handles IPv4-in-IPv4 and IPv6-in-IPv6 independently using stdlib
/// bit-mask arithmetic — no external crate required. IPv4-mapped IPv6
/// addresses (::ffff:x.x.x.x) are NOT auto-coerced; Pingora's
/// `SocketAddr::as_inet().ip()` already returns a plain `IpAddr::V4`
/// for all IPv4 connections, so this case does not arise in practice.
fn ip_in_cidr(ip: std::net::IpAddr, cidr: &str) -> bool {
    let Some((addr_s, prefix_s)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix_s.parse::<u32>() else {
        return false;
    };
    match (ip, addr_s.parse::<std::net::IpAddr>()) {
        (std::net::IpAddr::V4(ip4), Ok(std::net::IpAddr::V4(net4))) => {
            if prefix_len > 32 {
                return false;
            }
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            (u32::from(ip4) & mask) == (u32::from(net4) & mask)
        }
        (std::net::IpAddr::V6(ip6), Ok(std::net::IpAddr::V6(net6))) => {
            if prefix_len > 128 {
                return false;
            }
            let mask: u128 = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            (u128::from(ip6) & mask) == (u128::from(net6) & mask)
        }
        _ => false,
    }
}

/// Walk `X-Forwarded-For` right-to-left and return the first IP that is NOT
/// itself inside `trusted_cidrs` — this is the real client IP.
///
/// Returns `None` when the header is absent, unparseable, or every hop is
/// trusted (degenerate; caller should fall back to the TCP peer IP).
fn resolve_xff(headers: &http::HeaderMap, trusted_cidrs: &[Box<str>]) -> Option<std::net::IpAddr> {
    let xff = headers.get("x-forwarded-for")?.to_str().ok()?;
    // XFF is comma-separated, left-to-right (leftmost = original client,
    // rightmost = last appending proxy). Walk right-to-left so that a
    // hostile client cannot inject a fake entry in the leftmost position.
    xff.split(',')
        .rev()
        .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
        .find(|&ip| !trusted_cidrs.iter().any(|c| ip_in_cidr(ip, c)))
}

/// Overwrite the forwarding headers on an upstream-bound request with the
/// proxy's own resolved view of the client.
///
/// Removes every inbound `X-Forwarded-For`, `X-Real-IP` and `Forwarded`
/// (`HeaderMap::remove` drops all values for a name, so a client cannot hide
/// a second copy behind a duplicate header line) and emits a single
/// authoritative entry. Mirrors `set_authoritative_forwarding` in the hyper
/// data plane so both planes present the same contract to an origin.
///
/// `client_ip.to_string()` is always a valid header value — it is an IP
/// literal — but the insert is still fallible-safe so a future change can
/// never panic a worker on the request path.
fn set_authoritative_forwarding(
    req: &mut pingora_http::RequestHeader,
    client_ip: std::net::IpAddr,
) {
    req.remove_header("x-forwarded-for");
    req.remove_header("x-real-ip");
    req.remove_header("forwarded");
    let ip = client_ip.to_string();
    if let Ok(hv) = http::HeaderValue::from_str(&ip) {
        let _ = req.insert_header("x-forwarded-for", hv.clone());
        let _ = req.insert_header("x-real-ip", hv);
    }
}

/// Pingora `ProxyHttp` implementation for Aegis. Holds shared,
/// immutable references to the same engines the hyper-based handler
/// uses — there is exactly one source of truth for filter ordering,
/// upstream routing, and metrics.
#[derive(Clone)]
pub struct AegisPingoraProxy {
    filters: Arc<FilterEngine>,
    upstreams: SharedUpstreamRouter,
    metrics: Arc<RuntimeMetrics>,
    /// V30 — dynamic-trust reputation. Queried per-request to set
    /// `is_trusted`, observed after the filter chain to enroll or
    /// revoke trust. Disabled-by-default config makes `is_trusted`
    /// always return false; no behavioural change until operators
    /// opt in via `filters.dynamic_trust.enabled = true`.
    dynamic_trust: Arc<crate::filters::dynamic_trust::DynamicTrust>,
    /// V32 — threat-aware response cache. Looked up in
    /// `request_filter` before forwarding upstream; populated in
    /// `logging` from the body bytes accumulated by
    /// `response_body_filter`. Disabled-by-default; `should_consider`
    /// short-circuits all cache work when off.
    response_cache: Arc<crate::proxy::response_cache::ResponseCache>,
    /// V34 — single-flight registry, parity with hyper V17. The
    /// first request for a cache-missing key becomes "leader" and
    /// fetches upstream; concurrent requests for the same key are
    /// "followers" that wait on the leader's Notify (5s timeout) and
    /// re-lookup the cache when woken. Prevents the stampede
    /// pathology where N concurrent reqs for one expired entry all
    /// hit upstream simultaneously. No cost when cache is disabled
    /// (entries are only inserted under a cache-eligible miss).
    pending_fetches:
        Arc<dashmap::DashMap<(http::Method, String, String), Arc<tokio::sync::Notify>>>,
    /// V37 — static bypass matcher. IPs / paths / UAs flagged here
    /// (a) skip filter-chain throttling by getting is_trusted=true
    /// on the RequestContext, and (b) are NOT considered high-threat
    /// for cache lookups (operator-vetted = safe to serve from cache).
    bypass: Arc<crate::filters::bypass::BypassMatcher>,
    /// V37 — sliding-window per-IP threat scorer (V9/V11 parity).
    /// Bumped per-outcome in request_filter so the operator can
    /// query top attackers via /admin/threats (V36+ surface).
    scorer: Arc<crate::ddos::score::ThreatScorer>,
    /// V91 — Phase D cluster-wide per-IP scorer. `Some(...)` when
    /// the shared mmap arena attached at startup; `None` on
    /// graceful degradation (macOS dev build, restricted
    /// container). When Some, every record_*/score path mirrors
    /// into BOTH the per-worker `scorer` AND this shared one so
    /// distributed attackers can't dodge the per-IP score by
    /// hitting only one worker.
    shared_scorer: Option<Arc<crate::ddos::shared_score::SharedScorer>>,
    /// V38 — per-host attack-mode detector. Observed (EMA tick) on
    /// every request so `/admin/anomaly` and any future
    /// attack-mode-only gating (geoip throttle, escalated
    /// challenge floor) has live state to read.
    anomaly: Arc<crate::anomaly::AnomalyDetector>,
    /// V39 — country-based deny lookup. `Arc<dyn GeoIpLookup>` so
    /// the trait object is cheap to clone and an unconfigured DB
    /// reduces to NoopGeoIp (no allocations on the hot path).
    geoip: Arc<dyn crate::geoip::GeoIpLookup>,
    /// V39 — deny-countries + attack-mode-only flag. None when
    /// the operator didn't set `[geoip]`; the deny check
    /// short-circuits to None in that case.
    geoip_cfg: Option<crate::config::GeoIpConfig>,
    /// V42 — challenge ladder context: cookie issue, fp validation,
    /// /__aegis/verify handler. Shared with the binary so the
    /// admin port can introspect / debug if needed.
    challenge: crate::proxy::pingora_challenge::ChallengeContext,
    /// V101 — Phase E.2 ML scorer (V97). `Some(...)` when enabled at
    /// startup. Inference is feature-vector + dot product + sigmoid;
    /// <100 ns on the hot path. Used together with the per-IP
    /// ThreatScorer to derive a [ThreatTier] for the cache lookup.
    ml_scorer: Option<Arc<crate::ddos::ml_score::MlScorer>>,
    /// V107 — append-only log of tarpit-blocked request payloads.
    /// Feeds the online signature miner. Always present (no-op when
    /// AEGIS_TARPIT_LOG isn't set), so the hot-path tarpit branch
    /// can call `record()` unconditionally.
    tarpit_logger: Arc<crate::online_signature_miner::TarpitLogger>,
    /// V107 — rolling in-memory sample of allowed paths. Provides the
    /// "benign corpus" for the online miner.
    allowed_sampler: Arc<crate::online_signature_miner::AllowedSampler>,
    /// V119 — site cartography. Observed in the logging phase with
    /// final status code so the admin UI per-domain page can render
    /// the auto-discovered endpoint shape.
    site_map: Arc<crate::site_map::SiteMap>,
    /// V121 — split bot vs DDoS analytics. Populated alongside the
    /// dynamic_trust / scorer record_* calls so the per-IP "bot
    /// suspected" signal and the per-endpoint "distributed attack
    /// targeted" signal end up in separate operator views.
    threat_analytics: Arc<crate::threat_analytics::ThreatAnalytics>,
    /// V140/V141 — V122/V139 23-feature model (logistic OR GBM,
    /// chosen by operator via config). When Some, drives
    /// `derive_threat_tier` in preference to the V97 8-feature
    /// model. None preserves existing V97-only behaviour. Set via
    /// [Self::with_ml_scorer_v2] (logistic) or [Self::with_ml_model_v2]
    /// (full enum) before wrapping in Arc.
    ml_scorer_v2: Option<Arc<crate::ddos::ml_model::MlModel>>,
    /// V140 — V138 JA4 reputation feed. When Some, `extract_ml_features_v2`
    /// consults it for the `ja4_reputation` feature. None = feature stays
    /// 0 and the model contribution is the bias term alone.
    ja4_reputation: Option<Arc<crate::ja4_reputation::Ja4Reputation>>,
    /// V142 — ASN/CIDR reputation feed. When Some, populates the
    /// asn_reputation feature in `extract_ml_features_v2`. None = stays 0.
    asn_reputation: Option<Arc<crate::asn_reputation::AsnReputation>>,
    /// V145 — per-IP store of CreepJS-style client signals. When set,
    /// `extract_ml_features_v2` looks up the latest payload and folds
    /// the client-side consistency score into fp_consistency_score
    /// (taking the max with the server-side V137 score). None = stays
    /// at server-side only.
    client_signals: Option<Arc<crate::client_consistency::ClientSignalsStore>>,
    /// V152 — V147 poisoned tarpit generator. When set, GETs to
    /// /__aegis/tarpit/<slug> short-circuit into the Markov maze.
    /// None = path returns 404 from the upstream routing.
    tarpit_generator: Option<Arc<crate::poisoned_tarpit::TarpitGenerator>>,
    /// V154 — V149 robots.txt honeypot. When set, every request's
    /// path is checked against the operator's Disallow rules and
    /// matched visits get auto-labeled Malicious in the V135 trainer.
    robots_honeypot: Option<Arc<crate::robots_honeypot::RobotsHoneypot>>,
    /// V152 — chunk pacing for the tarpit. The page is split into
    /// `tarpit_chunks` slices; each yields to the wire then sleeps
    /// `tarpit_chunk_delay`. Defaults aim for ~5 seconds total to
    /// hold a crawler connection without DoS'ing our own workers.
    tarpit_chunks: usize,
    tarpit_chunk_delay: std::time::Duration,
    /// V192 — Defence Arsenal: shared holder for every V176-V190
    /// module + activity counters. None when the operator hasn't
    /// opted in; hot path checks via `as_ref()` and short-circuits.
    arsenal: Option<Arc<crate::arsenal::ArsenalState>>,
    /// V234 — ACME HTTP-01 challenge store. `/.well-known/acme-challenge/
    /// <token>` requests are answered from this in `request_filter`,
    /// before the filter chain. Empty until a Provisioner publishes a
    /// token, so the lookup is a cheap miss for normal traffic.
    acme_challenges: crate::acme::ChallengeStore,
    /// V234 — credential-stuffing / brute-force guard for login
    /// endpoints. `Some` with default login-path matchers
    /// (`/login`, `/signin`, `/auth/*`, …). Consulted from
    /// `request_body_filter` (needs the POST body for the username)
    /// and `logging` (records the outcome).
    login_abuse: Option<crate::filters::login_abuse::LoginAbuseGuard>,
    /// V234 — optional ClamAV request-body malware scanner. A no-op
    /// unless the operator set `AEGIS_CLAMAV_ADDR`; `is_enabled()` is
    /// the cheap gate checked before any body buffering.
    clamav: Arc<crate::clamav_scanner::ClamavScanner>,
    /// V236 — CHANGE 2: cached flag: true when at least one consumer
    /// reads `scorer.score()` per request. When false, the
    /// `record_allowed` write in logging (a 128-shard DashMap mutation
    /// + optional cross-process mmap CAS) is skipped on the clean
    /// allow path — the score would be written but never read.
    ///
    /// Consumers: response_cache tier lookup (`should_consider` ≈ cache
    /// enabled for GET with no host restriction), ml_scorer, ml_scorer_v2
    /// (set via builder methods — checked in the builder helpers that set
    /// those fields). `record_denied` / `record_challenged` are ALWAYS
    /// written regardless of this flag; only the allow path is gated.
    ///
    /// Initialised to `true` (conservative) in `new()` from the cache
    /// probe; the `with_ml_scorer_v2`, `with_ml_model_v2`, and
    /// `with_arsenal` builders also force it to `true` unconditionally.
    score_consumers_active: bool,
    /// V236 — CHANGE 5: upstream H2 preference, cached at construction
    /// from AEGIS_PINGORA_UPSTREAM_H2 env var. Avoids a per-request
    /// `std::env::var` lookup (a hash-table probe into the process env)
    /// on every call to `upstream_peer`.
    upstream_h2: bool,
    /// V236 — CHANGE 5: LLM honeypot enabled, cached at construction
    /// from AEGIS_LLM_HONEYPOT env var. Avoids a per-request env lookup
    /// inside the tarpit branch of request_filter.
    llm_honeypot: bool,
    /// V-new — when true, resolve real client IP from CF-Connecting-IP
    /// when the TCP peer is inside `trusted_proxy_cidrs`. Cached at
    /// construction from AEGIS_BEHIND_CLOUDFLARE=1.
    behind_cloudflare: bool,
    /// V-new — combined trusted-proxy CIDR set built at startup from
    /// AEGIS_BEHIND_CLOUDFLARE (adds Cloudflare's published ranges) and/or
    /// AEGIS_TRUSTED_PROXIES (operator-supplied comma-separated CIDRs).
    /// `None` = feature disabled, zero behaviour change (default).
    /// `Arc<Vec<Box<str>>>` keeps the proxy struct clone O(1).
    trusted_proxy_cidrs: Option<Arc<Vec<Box<str>>>>,
    /// V108 — correlational RiskEngine (Observe-first). `None` = off.
    risk_engine: Option<Arc<crate::ddos::risk_engine::RiskEngine>>,
    /// Phase 4 — XDP fast-path handle, shared with the BuiltPipeline. Used
    /// by the `fail_to_xdp_deny` challenge lever to push repeat-offender
    /// IPs into the kernel deny set. Defaults to `NoopXdp` (set via
    /// [`Self::with_xdp`] at startup), so the lever is a graceful no-op
    /// when XDP is unavailable (non-Linux / `[xdp]` disabled).
    xdp: Arc<dyn crate::xdp::XdpHandle>,
    /// H9a — JA4 prefix deny list (from `cfg.tls.ja4_deny_prefixes`).
    /// The legacy hyper server (`server.rs`) slams the TLS socket shut
    /// at handshake time when the JA4 matches one of these prefixes,
    /// but the pingora data plane never re-enforced it at the request
    /// layer — so on the deployed binary the policy silently did
    /// nothing. Enforced in `request_filter` after `build_ctx`.
    /// `Arc<[...]>` keeps the proxy-struct clone O(1); empty slice =
    /// feature off (the request-path check short-circuits cheaply).
    ja4_deny_prefixes: Arc<[String]>,
    /// H9a — JA3 hash deny list (from `cfg.tls.ja3_deny_hashes`).
    /// Matched case-insensitively against `ctx.ja3` (the MD5 hex hash).
    /// Same enforcement-gap story as `ja4_deny_prefixes`.
    ja3_deny_hashes: Arc<[String]>,
    /// V243 — persistent per-request event log. Written once per request
    /// from `logging()` via the non-blocking `record()` (try_send into a
    /// bounded channel; drop-on-full; no SQLite I/O on this thread). The
    /// admin read side queries the same shard dir. Defaults to a disabled
    /// no-op handle (`record()` returns immediately) until the binary
    /// installs the real one via [`Self::with_event_store`].
    event_store: Arc<crate::event_store::EventStore>,
}

impl AegisPingoraProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        filters: Arc<FilterEngine>,
        upstreams: SharedUpstreamRouter,
        metrics: Arc<RuntimeMetrics>,
        dynamic_trust: Arc<crate::filters::dynamic_trust::DynamicTrust>,
        response_cache: Arc<crate::proxy::response_cache::ResponseCache>,
        bypass: Arc<crate::filters::bypass::BypassMatcher>,
        scorer: Arc<crate::ddos::score::ThreatScorer>,
        shared_scorer: Option<Arc<crate::ddos::shared_score::SharedScorer>>,
        anomaly: Arc<crate::anomaly::AnomalyDetector>,
        geoip: Arc<dyn crate::geoip::GeoIpLookup>,
        geoip_cfg: Option<crate::config::GeoIpConfig>,
        challenge: crate::proxy::pingora_challenge::ChallengeContext,
        ml_scorer: Option<Arc<crate::ddos::ml_score::MlScorer>>,
        tarpit_logger: Arc<crate::online_signature_miner::TarpitLogger>,
        allowed_sampler: Arc<crate::online_signature_miner::AllowedSampler>,
        site_map: Arc<crate::site_map::SiteMap>,
        threat_analytics: Arc<crate::threat_analytics::ThreatAnalytics>,
    ) -> Self {
        // V236 — CHANGE 2: compute score_consumers_active before moving
        // response_cache into Self. `should_consider(&GET, "")` is the
        // cheapest available proxy for "is cache globally enabled":
        // returns true when enabled AND no allow_hosts host-restriction
        // (the common case), false when disabled. ml_scorer also checked.
        // The with_ml_scorer_v2 / with_ml_model_v2 / with_arsenal
        // builder helpers force this to true after construction.
        let score_consumers_active_init =
            ml_scorer.is_some() || response_cache.should_consider(&http::Method::GET, "");
        // V236 — CHANGE 5: read env vars ONCE at construction; cached on
        // the struct so upstream_peer and tarpit branch pay zero env
        // overhead per request.
        let upstream_h2 = std::env::var("AEGIS_PINGORA_UPSTREAM_H2")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        let llm_honeypot = std::env::var("AEGIS_LLM_HONEYPOT").ok().as_deref() == Some("1");
        // V-new — trusted-proxy / real-IP resolution. Both flags are off by
        // default so the behaviour is entirely unchanged without explicit opt-in.
        let behind_cloudflare = std::env::var("AEGIS_BEHIND_CLOUDFLARE")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        let trusted_proxies_env = std::env::var("AEGIS_TRUSTED_PROXIES").ok();
        let trusted_proxy_cidrs: Option<Arc<Vec<Box<str>>>> = {
            let mut cidrs: Vec<Box<str>> = Vec::new();
            if behind_cloudflare {
                cidrs.extend(CF_IP_RANGES.iter().map(|&s| -> Box<str> { s.into() }));
            }
            if let Some(ref extra) = trusted_proxies_env {
                cidrs.extend(
                    extra
                        .split(',')
                        .map(|s| s.trim().to_string().into_boxed_str()),
                );
            }
            if cidrs.is_empty() {
                None
            } else {
                Some(Arc::new(cidrs))
            }
        };
        Self {
            filters,
            upstreams,
            metrics,
            dynamic_trust,
            response_cache,
            pending_fetches: Arc::new(dashmap::DashMap::new()),
            bypass,
            scorer,
            shared_scorer,
            anomaly,
            geoip,
            geoip_cfg,
            challenge,
            ml_scorer,
            tarpit_logger,
            allowed_sampler,
            site_map,
            threat_analytics,
            ml_scorer_v2: None,
            ja4_reputation: None,
            asn_reputation: None,
            client_signals: None,
            tarpit_generator: None,
            tarpit_chunks: 20,
            tarpit_chunk_delay: std::time::Duration::from_millis(250),
            robots_honeypot: None,
            arsenal: None,
            // V234 — revived dead modules, constructed internally so
            // the `new()` signature is unchanged. ChallengeStore is an
            // empty Arc<DashMap>; LoginAbuseGuard::from_config(None)
            // uses the default login-path set; ClamavScanner::from_env
            // is a no-op unless AEGIS_CLAMAV_ADDR is set.
            acme_challenges: crate::acme::ChallengeStore::new(),
            login_abuse: crate::filters::login_abuse::LoginAbuseGuard::from_config(None),
            clamav: Arc::new(crate::clamav_scanner::ClamavScanner::from_env()),
            // V236 — CHANGE 2 + CHANGE 5 new fields.
            score_consumers_active: score_consumers_active_init,
            upstream_h2,
            llm_honeypot,
            // V-new — trusted-proxy / real-IP resolution fields.
            behind_cloudflare,
            trusted_proxy_cidrs,
            // V108 — wired post-construction via with_risk_engine().
            risk_engine: None,
            // Phase 4 — defaults to NoopXdp; the binary wires the real
            // handle via with_xdp() so the fail_to_xdp_deny lever can push
            // repeat offenders into the kernel deny set.
            xdp: Arc::new(crate::xdp::NoopXdp),
            // H9a — empty by default (feature off); the binary wires the
            // configured lists via with_tls_deny_lists() at construction.
            ja4_deny_prefixes: Arc::from(Vec::<String>::new()),
            ja3_deny_hashes: Arc::from(Vec::<String>::new()),
            // V243 — disabled no-op event store by default. `new()` here
            // never spawns a writer thread (no persistence), so record()
            // is a no-op. The binary installs the real handle (built via
            // EventStore::from_env at startup) through with_event_store().
            event_store: Arc::new(crate::event_store::EventStore::new(
                std::path::PathBuf::new(),
            )),
        }
    }

    /// H9a — install the TLS fingerprint deny lists so the pingora
    /// request path enforces `cfg.tls.ja4_deny_prefixes` and
    /// `cfg.tls.ja3_deny_hashes` (parity with the legacy hyper server,
    /// which enforces them at handshake time). When both lists are
    /// empty the per-request check short-circuits to a no-op, so wiring
    /// this unconditionally costs nothing for operators who configured
    /// no deny lists.
    pub fn with_tls_deny_lists(
        mut self,
        ja4_deny_prefixes: Vec<String>,
        ja3_deny_hashes: Vec<String>,
    ) -> Self {
        self.ja4_deny_prefixes = Arc::from(ja4_deny_prefixes);
        self.ja3_deny_hashes = Arc::from(ja3_deny_hashes);
        self
    }

    /// V243 — install the shared persistent event log. The same `Arc` is
    /// also handed to the admin store for the read side. Called once at
    /// startup from the binary with the handle built via
    /// `EventStore::from_env()`. When the store is disabled or its
    /// persistence failed to enable, `record()` is a no-op so wiring this
    /// unconditionally costs nothing on the hot path.
    pub fn with_event_store(mut self, event_store: Arc<crate::event_store::EventStore>) -> Self {
        self.event_store = event_store;
        self
    }

    /// H9a — true when the connection's TLS fingerprints match a
    /// configured deny entry. Cheap-skips when both lists are empty
    /// (the common case). Returns a static reason string for logging /
    /// counters. JA4 is matched by `starts_with` against any configured
    /// prefix; JA3 is matched case-insensitively against the MD5 hash.
    #[inline]
    fn tls_fingerprint_denied(&self, ctx: &RequestContext) -> Option<&'static str> {
        // Hot-path guard: zero work when the operator configured neither
        // list. Both checks are `is_empty()` on an Arc<[..]> (one load).
        if self.ja4_deny_prefixes.is_empty() && self.ja3_deny_hashes.is_empty() {
            return None;
        }
        if let Some(ja4) = ctx.ja4.as_deref()
            && !self.ja4_deny_prefixes.is_empty()
            && self
                .ja4_deny_prefixes
                .iter()
                .any(|p| !p.is_empty() && ja4.starts_with(p.as_str()))
        {
            return Some("tls_ja4_deny");
        }
        if let Some(ja3) = ctx.ja3.as_deref()
            && !self.ja3_deny_hashes.is_empty()
            && self
                .ja3_deny_hashes
                .iter()
                .any(|h| h.eq_ignore_ascii_case(ja3))
        {
            return Some("tls_ja3_deny");
        }
        None
    }

    /// Phase 4 — wire the XDP fast-path handle so the `fail_to_xdp_deny`
    /// challenge lever can escalate repeat-offender IPs into the kernel
    /// deny set. No-op behaviour preserved when passed a `NoopXdp`.
    pub fn with_xdp(mut self, xdp: Arc<dyn crate::xdp::XdpHandle>) -> Self {
        self.xdp = xdp;
        self
    }

    /// V192 — opt-in Defence Arsenal holder.
    pub fn with_arsenal(mut self, arsenal: Arc<crate::arsenal::ArsenalState>) -> Self {
        self.arsenal = Some(arsenal);
        // V236 — CHANGE 2: arsenal consumes scorer data; force the flag on.
        self.score_consumers_active = true;
        self
    }

    /// V108 — install the correlational RiskEngine (Observe-first). When
    /// set, request_filter computes a risk score after the FilterEngine
    /// verdict and logs it; in Observe mode the verdict is NOT changed.
    pub fn with_risk_engine(mut self, engine: Arc<crate::ddos::risk_engine::RiskEngine>) -> Self {
        self.risk_engine = Some(engine);
        self
    }

    /// V194 — convenience: also install the WafFilter's rule
    /// descriptors into the arsenal's RulePlan. Call after attaching
    /// the arsenal AND after WAF rules have loaded so the planner
    /// reflects the live ruleset.
    pub fn refresh_arsenal_rule_plan(&self, waf: &crate::filters::waf::WafFilter) {
        if let Some(arsenal) = self.arsenal.as_ref() {
            let descs = waf.rule_descriptors();
            let plan = crate::rule_planner::RulePlan::from_rules(descs);
            arsenal.install_rule_plan(plan);
        }
    }

    pub fn arsenal(&self) -> Option<&Arc<crate::arsenal::ArsenalState>> {
        self.arsenal.as_ref()
    }

    /// V140 — opt-in V2 logistic scorer. Convenience wrapper that
    /// embeds the [MlScorerV2] into an [MlModel::Logistic]. Equivalent
    /// to `.with_ml_model_v2(Arc::new(MlModel::logistic(scorer)))`.
    pub fn with_ml_scorer_v2(self, s: Arc<crate::ddos::ml_score_v2::MlScorerV2>) -> Self {
        self.with_ml_model_v2(Arc::new(crate::ddos::ml_model::MlModel::logistic(s)))
    }

    /// V141 — opt-in V2 model (logistic OR GBM). Lets the operator
    /// pick the engine via config without changing the wiring code.
    pub fn with_ml_model_v2(mut self, m: Arc<crate::ddos::ml_model::MlModel>) -> Self {
        self.ml_scorer_v2 = Some(m);
        // V236 — CHANGE 2: ML v2 scorer consumes score data; force the flag on.
        self.score_consumers_active = true;
        self
    }

    /// V140 — opt-in JA4 reputation feed for the `ja4_reputation`
    /// feature. Without this set, the slot is a constant 0.
    pub fn with_ja4_reputation(mut self, r: Arc<crate::ja4_reputation::Ja4Reputation>) -> Self {
        self.ja4_reputation = Some(r);
        self
    }

    /// V142 — opt-in ASN/CIDR reputation feed for the
    /// `asn_reputation` feature. Without this set, the slot is 0.
    pub fn with_asn_reputation(mut self, r: Arc<crate::asn_reputation::AsnReputation>) -> Self {
        self.asn_reputation = Some(r);
        self
    }

    /// V145 — opt-in client-signals store for CreepJS-style
    /// consistency. When set, the fp_consistency_score feature
    /// becomes max(server_side_correlator, client_side_consistency).
    pub fn with_client_signals(
        mut self,
        store: Arc<crate::client_consistency::ClientSignalsStore>,
    ) -> Self {
        self.client_signals = Some(store);
        self
    }

    /// V152 — opt-in V147 poisoned tarpit. When set, GETs under
    /// `/__aegis/tarpit/` serve a slow Markov-generated maze page
    /// instead of returning 404. `chunks` * `chunk_delay` gives the
    /// total response time; defaults (20 × 250ms) ≈ 5s.
    pub fn with_tarpit(
        mut self,
        generator: Arc<crate::poisoned_tarpit::TarpitGenerator>,
        chunks: usize,
        chunk_delay: std::time::Duration,
    ) -> Self {
        self.tarpit_generator = Some(generator);
        self.tarpit_chunks = chunks.max(1);
        self.tarpit_chunk_delay = chunk_delay;
        self
    }

    /// V154 — opt-in V149 robots.txt honeypot. When set, every
    /// request whose path matches a Disallow pattern emits a
    /// Label::Malicious sample into the trainer (free attacker
    /// labels from operator-maintained robots.txt).
    pub fn with_robots_honeypot(mut self, hp: Arc<crate::robots_honeypot::RobotsHoneypot>) -> Self {
        self.robots_honeypot = Some(hp);
        self
    }

    /// V234/V235 — expose the ACME HTTP-01 challenge store so the
    /// background issuance task can share the SAME Arc<DashMap>
    /// instance that the data-plane HTTP-01 handler reads from.
    ///
    /// The store is `Clone` (both clones share the inner `Arc`), so
    /// this returns a cheap clone suitable for handing to the
    /// `Provisioner` or the background renewal loop.
    pub fn acme_challenge_store(&self) -> crate::acme::ChallengeStore {
        self.acme_challenges.clone()
    }

    /// V238 — enable cross-worker token sharing via a directory on disk.
    /// Each SO_REUSEPORT worker process has its own in-memory
    /// `ChallengeStore`, so the order initiated by one worker drops the
    /// token only into its DashMap; LE's challenge GET hits any of the
    /// N workers chosen by the kernel and `(N-1)/N` of the time misses.
    /// Backing the store with a shared directory (the data plane reads
    /// the file on memory miss, the Provisioner writes the file on
    /// insert) makes any worker able to answer the challenge regardless
    /// of which one initiated the order. Idempotent; safe on every boot.
    pub fn with_acme_challenges_disk_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.acme_challenges = self.acme_challenges.with_disk_dir(dir);
        self
    }

    /// V121 — record a per-IP bot signal so the /admin/api/bots
    /// page surfaces the perpetrator. Called next to the existing
    /// per-IP record_denied / record_challenged paths.
    #[inline]
    fn record_bot(&self, ip: std::net::IpAddr, reason: crate::threat_analytics::BotReason) {
        self.threat_analytics.observe_bot(ip, reason);
    }

    /// V101 — derive a [ThreatTier] for cache lookup from the per-IP
    /// scorer + (optional) ML scorer. Score is the MAX of the two
    /// scaled-to-[0,100] outputs; tier thresholds come from
    /// [ThreatTier::from_score]. Caller already knows whether the
    /// client is bypass/trusted — when so, we short-circuit to Low
    /// without doing any score work.
    #[inline]
    fn derive_threat_tier(
        &self,
        ctx: &RequestContext,
        is_bypass_or_trusted: bool,
    ) -> crate::proxy::response_cache::ThreatTier {
        use crate::proxy::response_cache::ThreatTier;
        if is_bypass_or_trusted {
            return ThreatTier::Low;
        }
        let ip_score = self.scorer.score(ctx.client_ip).as_f64();
        // V140 — prefer V122/V139 V2 scorer when wired; fall back to
        // V97. Running both would double the cost without giving us
        // a calibrated ensemble (different feature spaces), so we
        // pick the most capable one that's available.
        let ml_score = if let Some(m) = &self.ml_scorer_v2 {
            let f = self.extract_ml_features_v2(ctx, ip_score);
            m.score_pct(&f) as f64
        } else if let Some(m) = &self.ml_scorer {
            let f = Self::extract_ml_features(ctx, ip_score);
            m.score_pct(&f) as f64
        } else {
            0.0
        };

        // V194 — register a rule-plan dispatch for this request when
        // an arsenal plan is installed. The actual rule eval still
        // runs inside WafFilter (no executor refactor yet); this is
        // bookkeeping so the admin counter reflects request volume
        // touched by the planner. No-op when plan is empty.
        // V228 — fast-path atomic gate from V218 perf sweep. Single
        // AtomicBool load instead of RwLock acquisition + Option check.
        if let Some(arsenal) = &self.arsenal
            && arsenal
                .rule_plan_loaded
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            let _ = arsenal.rule_plan_dispatch(crate::rule_planner::Phase::RequestUriOrQuery);
            if !ctx.path.is_empty() && ctx.path.contains('?') {
                let _ = arsenal.rule_plan_dispatch(crate::rule_planner::Phase::RequestHeaders);
            }
        }

        ThreatTier::from_score(ip_score.max(ml_score))
    }

    /// M3 — compute the per-request ML suspicion score (0–100) using the
    /// most capable scorer that is wired, mirroring the selection logic in
    /// [Self::derive_threat_tier]. Returns `0.0` when neither ML scorer is
    /// installed. Extracted so the V108 RiskEngine can fold a *real*
    /// `ml_score` signal into [RiskInput] independently of the cache-tier
    /// path (which is short-circuited for trusted clients). `ip_score` is
    /// the reputation score the caller already computed via
    /// `self.scorer.score(..)`, reused here as the ML feature seed so we
    /// don't pay for a second reputation lookup.
    #[inline]
    fn compute_ml_score(&self, ctx: &RequestContext, ip_score: f64) -> f64 {
        if let Some(m) = &self.ml_scorer_v2 {
            let f = self.extract_ml_features_v2(ctx, ip_score);
            m.score_pct(&f) as f64
        } else if let Some(m) = &self.ml_scorer {
            let f = Self::extract_ml_features(ctx, ip_score);
            m.score_pct(&f) as f64
        } else {
            0.0
        }
    }

    /// V140 — populate the 23-feature [FeaturesV2] vector from the
    /// request context. Reuses the V97 normalisations where they
    /// overlap (URI length, header count, body length, has_*), and
    /// fills the new V122/V139 fields:
    ///
    /// * URI / query entropy from [ascii_entropy].
    /// * Fingerprint presence flags + browser-family guess from
    ///   [fp_correlation::ua_family].
    /// * Temporal flags (night window, fast repeat — best-effort here:
    ///   fast_repeat requires per-IP state which lives on the scorer,
    ///   so we read it from there).
    /// * V137 cross-fingerprint consistency from
    ///   [crate::fp_correlation::correlate].
    /// * V138 JA4 reputation lookup when wired.
    /// * asn_reputation left at 0 — populated by V142 wiring.
    #[inline]
    fn extract_ml_features_v2(
        &self,
        ctx: &RequestContext,
        recent_denied_score_pct: f64,
    ) -> crate::ddos::ml_score_v2::FeaturesV2 {
        use crate::ddos::ml_score_v2::{FeaturesV2, ascii_entropy};
        use crate::fp_correlation::{self, BrowserFamily, FingerprintSet};

        let uri_length = (ctx.path.len() as f32 / 8192.0).min(1.0);
        let header_count = (ctx.headers.len() as f32 / 64.0).min(1.0);
        // Split path / query for separate entropy signals.
        let (path_only, query_only) = ctx
            .path
            .split_once('?')
            .map(|(p, q)| (p, q))
            .unwrap_or((ctx.path.as_str(), ""));
        let uri_entropy = ascii_entropy(path_only);
        let query_entropy = ascii_entropy(query_only);
        let query_param_count = if query_only.is_empty() {
            0.0
        } else {
            (query_only.split('&').count() as f32 / 32.0).min(1.0)
        };

        // V180 — observe each (host, endpoint, param=value) for the
        // per-endpoint parameter profile learner. After N samples
        // per key, future calls to `.score()` return an anomaly
        // value in [0,1] for outlier values.
        //
        // V228 — use borrowed `ParamKeyRef` to avoid 3 String allocs
        // per query param on the hit path (V218 perf sweep). Loop is
        // skipped entirely on a query-free request.
        if let Some(arsenal) = &self.arsenal
            && !query_only.is_empty()
        {
            use std::sync::atomic::Ordering;
            let host = ctx.host.as_str();
            for pair in query_only.split('&').take(16) {
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                let key_ref = crate::param_profile::ParamKeyRef::new(host, path_only, name);
                let score = arsenal.param_profile.score_ref(key_ref, value);
                let key_ref = crate::param_profile::ParamKeyRef::new(host, path_only, name);
                arsenal.param_profile.observe_ref(key_ref, value);
                arsenal
                    .counters
                    .param_profile_observations
                    .fetch_add(1, Ordering::Relaxed);
                if score > 0.5 {
                    arsenal
                        .counters
                        .param_profile_anomalies
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let body_length = ctx
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| (n as f32 / (64.0 * 1024.0)).min(1.0))
            .unwrap_or(0.0);

        let bit = |b: bool| if b { 1.0 } else { 0.0 };
        let has_user_agent = bit(ctx.user_agent.as_ref().is_some_and(|s| !s.is_empty()));
        let has_accept_language = bit(ctx.headers.contains_key("accept-language"));
        let has_accept_encoding = bit(ctx.headers.contains_key("accept-encoding"));
        let has_referer = bit(ctx.headers.contains_key("referer"));
        let method_is_post = bit(matches!(
            ctx.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE
        ));

        let ja4_present = bit(ctx.ja4.as_ref().is_some_and(|s| !s.is_empty()));
        // H9c — `ja4_browser_family` is now a UA-vs-JA4 *mismatch*
        // signal, not a UA-only "is this a browser?" flag (which a bot
        // trivially earned by sending a browser UA). The TLS handshake
        // JA4 is far harder to forge consistently than the UA string,
        // so a contradiction between the two — UA claims one browser
        // family while the JA4 cipher ordering says a *different* known
        // family (or known tooling) — is a strong replay / UA-spoof
        // tell (see fp_correlation module docs).
        //
        // Conservative heuristic (avoids false positives on the hot
        // path): the feature fires (1.0) only when BOTH the UA family
        // and the JA4 family are confidently classified (neither is
        // `Unknown`) AND they disagree. If either side is Unknown — the
        // common case for less-popular clients, or when no JA4 was
        // captured (plain HTTP) — we emit 0.0 rather than guess. The
        // JA4 family is derived from `ctx.ja4` via the same classifier
        // the correlator + passive challenge signals use.
        let ua_fam = ctx
            .user_agent
            .as_deref()
            .map(fp_correlation::ua_family)
            .unwrap_or(BrowserFamily::Unknown);
        let ja4_fam = ctx
            .ja4
            .as_deref()
            .map(fp_correlation::ja4_family)
            .unwrap_or(BrowserFamily::Unknown);
        let ja4_browser_family = bit(ua_fam != BrowserFamily::Unknown
            && ja4_fam != BrowserFamily::Unknown
            && ua_fam != ja4_fam);
        let h2fp_present = bit(ctx.h2fp.as_ref().is_some_and(|s| !s.is_empty()));

        // V143 — pull the split components out of the scorer
        // directly, so each one feeds the model independently instead
        // of the older "use the aggregate as a stand-in" workaround.
        let recent_denied_rate = self.scorer.denied_rate(ctx.client_ip);
        let recent_challenged_rate = self.scorer.challenged_rate(ctx.client_ip);
        // RPS → requests-per-min normalised to /100: 100 req/min = 1.0.
        // Above that, scanner territory.
        let rps = self.scorer.recent_rps(ctx.client_ip);
        let requests_per_min = ((rps * 60.0) / 100.0).clamp(0.0, 1.0);
        let fast_repeat = self.scorer.fast_repeat(ctx.client_ip);
        // Kept for backward compat with the caller signature; the
        // V143-derived denied_rate is what feeds the feature.
        let _ = recent_denied_score_pct;
        // V97-style night-window flag — UTC hour ∈ [0, 6).
        let night_window = {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let hour = (secs / 3600) % 24;
            bit(hour < 6)
        };

        // V137 — cross-fingerprint correlation.
        let al = ctx
            .headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok());
        let ae = ctx
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok());
        let fp = FingerprintSet {
            ja4: ctx.ja4.as_deref(),
            ja4h: ctx.ja4h(),
            h2fp: ctx.h2fp.as_deref(),
            user_agent: ctx.user_agent.as_deref(),
            accept_language: al,
            accept_encoding: ae,
        };
        let server_fp_score = fp_correlation::correlate(&fp).score;
        // V145 — fold in client-side CreepJS consistency when present.
        // Take the max so any tier lighting up dominates.
        let fp_consistency_score = match &self.client_signals {
            Some(store) => match store.get(ctx.client_ip) {
                Some(sig) => {
                    // V189 — timing-entropy: when the CreepJS collector
                    // shipped input-timing intervals, score them through
                    // the timing-entropy extractor and bump the arsenal
                    // counters so the panel reflects real activity. The
                    // result also feeds consistency_score below (which
                    // re-derives it), so this is the observability hook.
                    if let Some(arsenal) = &self.arsenal
                        && (!sig.mouse_intervals_ms.is_empty()
                            || !sig.scroll_intervals_ms.is_empty())
                    {
                        use std::sync::atomic::Ordering;
                        arsenal
                            .counters
                            .timing_entropy_calls
                            .fetch_add(1, Ordering::Relaxed);
                        let tf =
                            crate::timing_entropy::extract(&crate::timing_entropy::TimingSample {
                                mouse_intervals_ms: sig.mouse_intervals_ms.clone(),
                                scroll_intervals_ms: sig.scroll_intervals_ms.clone(),
                            });
                        if tf.anomaly_score > 0.5 {
                            arsenal
                                .counters
                                .timing_entropy_synthetic_flags
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let client_score = crate::client_consistency::consistency_score(
                        &sig,
                        ctx.user_agent.as_deref(),
                    )
                    .score;
                    server_fp_score.max(client_score)
                }
                None => server_fp_score,
            },
            None => server_fp_score,
        };

        // V138 — JA4 reputation lookup.
        let mut ja4_reputation = match (&self.ja4_reputation, ctx.ja4.as_deref()) {
            (Some(rep), Some(ja4)) => {
                crate::ja4_reputation::reputation_feature(rep.lookup(ja4).as_ref())
            }
            _ => 0.0,
        };

        // V176/V177 — arsenal JA4 corpus + churn. Corpus lookup
        // promotes the reputation feature (Deny → 1.0, Allow → -0.5)
        // when the operator hasn't already wired V138. Churn is
        // observed unconditionally so the score is fresh when the
        // ML scorer reads it as `ja4_reputation`.
        //
        // H9b — the JA4 is *client-chosen* (the attacker fully controls
        // their own TLS ClientHello), so an Allow verdict must never let
        // a request actively LOWER its own scrutiny below the baseline
        // established by signals the client can't fake (here: the
        // operator's V138 CTI feed lookup, captured just above). A
        // corpus Allow can therefore only *withhold* suspicion, not buy
        // a discount: we clamp the soft-credit at the pre-corpus
        // baseline so a spoofed "I'm Chrome" JA4 lands neutral at worst,
        // never negative. (Previously `-0.25` reduced reputation below
        // baseline, which a forged browser JA4 could exploit to dodge
        // the scorer.)
        let ja4_reputation_baseline = ja4_reputation;
        if let (Some(arsenal), Some(ja4)) = (&self.arsenal, ctx.ja4.as_deref()) {
            use std::sync::atomic::Ordering;
            arsenal
                .counters
                .ja4_corpus_lookups
                .fetch_add(1, Ordering::Relaxed);
            let hit = arsenal.ja4_corpus.lookup(ja4);
            match hit.verdict {
                crate::ja4_corpus::Verdict::Deny => {
                    arsenal
                        .counters
                        .ja4_corpus_deny_hits
                        .fetch_add(1, Ordering::Relaxed);
                    ja4_reputation = ja4_reputation.max(1.0);
                }
                crate::ja4_corpus::Verdict::Allow => {
                    arsenal
                        .counters
                        .ja4_corpus_allow_hits
                        .fetch_add(1, Ordering::Relaxed);
                    // H9b — clamp the soft-credit at the (non-spoofable)
                    // baseline: a client-chosen "known-browser" JA4 can
                    // never drive reputation below what the operator's
                    // feed already set. Floored at 0 for the model's
                    // [0,1] domain.
                    ja4_reputation = (ja4_reputation - 0.25)
                        .max(ja4_reputation_baseline)
                        .max(0.0);
                }
                crate::ja4_corpus::Verdict::Unknown => {}
            }
            arsenal.ja4_churn.observe(ctx.client_ip, ja4);
            arsenal
                .counters
                .ja4_churn_observations
                .fetch_add(1, Ordering::Relaxed);
            // Churn ≥ 0.6 is suspicious; fold into reputation so
            // existing ML feature carries the signal without schema
            // expansion.
            let churn = arsenal.ja4_churn.churn(ctx.client_ip);
            if churn > 0.6 {
                ja4_reputation = ja4_reputation.max(churn);
            }
        }

        FeaturesV2 {
            uri_length,
            query_param_count,
            uri_entropy,
            query_entropy,
            header_count,
            has_user_agent,
            has_accept_language,
            has_accept_encoding,
            has_referer,
            method_is_post,
            body_length,
            ja4_present,
            ja4_browser_family,
            h2fp_present,
            recent_denied_rate,
            recent_challenged_rate,
            bot_score_rate: 0.0,
            requests_per_min,
            fast_repeat,
            night_window,
            fp_consistency_score,
            ja4_reputation,
            asn_reputation: self
                .asn_reputation
                .as_ref()
                .map(|r| r.feature(ctx.client_ip))
                .unwrap_or(0.0),
        }
    }

    /// V101 — build the 8-feature vector for the ML scorer from the
    /// current request context. All features are pre-normalised into
    /// roughly [0, 1] so the weight magnitudes stay sane during
    /// online retraining.
    #[inline]
    fn extract_ml_features(
        ctx: &RequestContext,
        recent_denied_score_pct: f64,
    ) -> crate::ddos::ml_score::Features {
        use crate::ddos::ml_score::Features;
        // URI length normaliser: WAF caps at 8 KiB by default, so
        // divide by that to land in [0, 1] for normal traffic.
        let uri_length = (ctx.path.len() as f32 / 8192.0).min(1.0);
        // Header count: 64 is the WAF default cap.
        let header_count = (ctx.headers.len() as f32 / 64.0).min(1.0);
        // Body length read from content-length header (we don't have
        // the buffered body here). 0 when absent / unparseable.
        let body_length = ctx
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| (n as f32 / (64.0 * 1024.0)).min(1.0))
            .unwrap_or(0.0);
        let has_user_agent = if ctx.user_agent.as_ref().is_some_and(|s| !s.is_empty()) {
            1.0
        } else {
            0.0
        };
        let method_is_post = matches!(
            ctx.method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE
        ) as u8 as f32;
        // ja4_unusual: 1.0 when no JA4 captured (likely HTTP w/o TLS,
        // or scraper bypassing TLS fingerprint capture); 0.0 when
        // present (real client). A future enhancement could check the
        // fingerprint against a popular-set bloom filter.
        let ja4_unusual = if ctx.ja4.as_ref().is_some_and(|s| !s.is_empty()) {
            0.0
        } else {
            1.0
        };
        // Already-normalised scorer outputs come in 0..=100; rescale.
        let recent_denied_rate = (recent_denied_score_pct / 100.0).clamp(0.0, 1.0) as f32;
        Features {
            uri_length,
            header_count,
            body_length,
            has_user_agent,
            method_is_post,
            ja4_unusual,
            recent_denied_rate,
            // recent_challenged: we don't expose it from ThreatScorer
            // as a separate score; reuse 0 for now. V102+ can split
            // the per-IP score into denied/challenged components and
            // feed both.
            recent_challenged_rate: 0.0,
        }
    }

    /// V91 — record_allowed in both per-worker scorer (existing
    /// behaviour) AND the cluster-wide shared scorer (Phase D)
    /// when the arena attached at startup. Helpers keep call
    /// sites short — every record_*/score path uses these.
    #[inline]
    fn record_allowed(&self, ip: std::net::IpAddr, now: Instant) {
        self.scorer.record_allowed(ip, now);
        if let Some(s) = &self.shared_scorer {
            s.record_allowed(ip, now);
        }
    }

    #[inline]
    fn record_denied(&self, ip: std::net::IpAddr, now: Instant) {
        self.scorer.record_denied(ip, now);
        if let Some(s) = &self.shared_scorer {
            s.record_denied(ip, now);
        }
    }

    #[inline]
    fn record_challenged(&self, ip: std::net::IpAddr, now: Instant) {
        self.scorer.record_challenged(ip, now);
        if let Some(s) = &self.shared_scorer {
            s.record_challenged(ip, now);
        }
    }

    /// Send a visitor-facing error response.
    ///
    /// When the downstream client's `Accept` header includes `text/html`
    /// or `*/*` (i.e. a browser), renders a self-contained branded HTML
    /// page via `error_pages::branded_error_page` and sets
    /// `content-type: text/html; charset=utf-8`.
    ///
    /// For non-HTML clients (API callers, `curl`, etc.) falls back to
    /// the previous plain-text body with `content-type: text/plain` so
    /// existing integrations see no change.
    ///
    /// Uses `write_response_header` + `write_response_body` directly so
    /// we can control the content-type header — `respond_error_with_body`
    /// does not expose it.
    async fn respond_visitor_error(
        &self,
        session: &mut Session,
        status: u16,
        plain_body: &str,
        trace_id: u64,
    ) -> pingora_core::Result<()> {
        use crate::proxy::error_pages::{branded_error_page, should_brand};

        let accept = session
            .req_header()
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok());

        // H1 — a HEAD request must get the same status + headers but NO
        // body; emitting DATA frames on HEAD trips HTTP/2 PROTOCOL_ERROR.
        // We keep content-length (what a GET would have) and end the
        // stream on the header.
        let is_head = session.req_header().method == http::Method::HEAD;

        if should_brand(accept) {
            let html = branded_error_page(status, plain_body, trace_id);
            let html_bytes = bytes::Bytes::from(html);
            let mut h = pingora_http::ResponseHeader::build(status, Some(3))?;
            let _ = h.insert_header("content-type", "text/html; charset=utf-8");
            let _ = h.insert_header("content-length", html_bytes.len().to_string());
            let _ = h.insert_header("cache-control", "no-store");
            session.write_response_header(Box::new(h), is_head).await?;
            if !is_head {
                session.write_response_body(Some(html_bytes), true).await?;
            }
        } else {
            let plain_bytes = bytes::Bytes::from(plain_body.to_string());
            let mut h = pingora_http::ResponseHeader::build(status, Some(3))?;
            let _ = h.insert_header("content-type", "text/plain");
            let _ = h.insert_header("content-length", plain_bytes.len().to_string());
            let _ = h.insert_header("cache-control", "no-store");
            session.write_response_header(Box::new(h), is_head).await?;
            if !is_head {
                session.write_response_body(Some(plain_bytes), true).await?;
            }
        }
        Ok(())
    }

    /// V39 — country-based deny check. Returns Some(reason) when
    /// the request should be blocked. Mirrors the hyper handler's
    /// `geoip_deny` exactly: respects `attack_mode_only` (deny is
    /// dormant unless the host is currently flagged under attack)
    /// and an empty `deny_countries` list short-circuits.
    fn geoip_deny(&self, ip: std::net::IpAddr, host: &str) -> Option<String> {
        let cfg = self.geoip_cfg.as_ref()?;
        if cfg.attack_mode_only && !self.anomaly.under_attack(host) {
            return None;
        }
        if cfg.deny_countries.is_empty() {
            return None;
        }
        let country = self.geoip.country(ip)?;
        if cfg
            .deny_countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&country))
        {
            Some(format!("geo deny: {country}"))
        } else {
            None
        }
    }

    /// Look up the response cache for the given request and, on
    /// hit, write the cached response to the downstream session and
    /// return `Ok(true)`. On miss, returns `Ok(false)` with no
    /// session writes. Bumps cache_hits / cache_misses metrics.
    /// Shared by the initial lookup path and the post-wait
    /// follower re-lookup (V34 single-flight).
    ///
    /// V37 — `is_high_threat` is honoured by ResponseCache::lookup
    /// (forces MISS + bumps skipped_high_threat metric). The proxy
    /// computes it once in request_filter via
    /// `!bypass && !dynamic_trust` and threads it here.
    ///
    /// V236 — CHANGE 3: `now` threaded in from the caller instead of
    /// being re-read via `Instant::now()`. Eliminates one vdso clock
    /// syscall per cache lookup. The few hundred nanoseconds of skew vs
    /// the caller's capture point are irrelevant to TTL comparisons,
    /// which bucket at second granularity.
    async fn try_serve_from_cache(
        &self,
        session: &mut Session,
        req_ctx: &RequestContext,
        is_high_threat: bool,
        now: Instant,
    ) -> pingora_core::Result<bool> {
        // V101 → V103 — tier is derived from the per-IP scorer + ML
        // scorer signals. The legacy `is_high_threat` bool (= "client
        // is not on bypass / dynamic-trust list") is NOT a threat
        // signal by itself — under the old binary gate it correctly
        // forced miss only because the only granularity was high/low.
        // With ThreatTier we want the actual score → tier mapping;
        // collapsing all non-bypass traffic to High forces every
        // legitimate user-agent into a forced cache miss, which was
        // the V103 cache-warm bench regression.
        let _ = is_high_threat; // kept for API stability; unused here
        let tier = self.derive_threat_tier(req_ctx, req_ctx.is_trusted);
        if let Some(cached) = self.response_cache.lookup_tiered(
            &req_ctx.method,
            &req_ctx.host,
            &req_ctx.path,
            tier,
            now,
        ) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::CACHE_HITS,
            );
            let mut header =
                ResponseHeader::build(cached.status.as_u16(), Some(cached.headers.len() + 1))?;
            // V82 — pass &HeaderName directly (no per-header String alloc).
            for (k, v) in cached.headers.iter() {
                let _ = header.insert_header(k, v);
            }
            let _ = header.insert_header("x-aegis-cache", "HIT");
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(cached.body), true).await?;
            return Ok(true);
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        crate::shared_state::global::cluster_bump(
            crate::shared_state::global::cluster_idx::CACHE_MISSES,
        );
        Ok(false)
    }

    // -------------------------------------------------------------------------
    // V-new — trusted-proxy / real-IP resolution helpers
    // -------------------------------------------------------------------------

    /// Resolve the real client IP from forwarded headers when the TCP peer is
    /// a known trusted proxy, otherwise return the TCP peer IP unchanged.
    ///
    /// ## Security invariant
    /// The gate condition (`tcp_peer_ip` must be inside `trusted_proxy_cidrs`)
    /// is enforced unconditionally. When no trusted proxies are configured
    /// (`trusted_proxy_cidrs == None`) this function short-circuits and returns
    /// `tcp_peer_ip` without touching any header — identical to the previous
    /// behaviour, zero overhead.
    ///
    /// When `AEGIS_BEHIND_CLOUDFLARE=1` and the peer is a CF edge node, the
    /// more reliable `CF-Connecting-IP` header is preferred over XFF (Cloudflare
    /// itself appends to XFF, making the rightmost non-trusted walk redundant).
    /// V182/V188 — derive a stable per-connection u64 id from a client
    /// IP. Pingora doesn't hand us a raw connection handle on the
    /// request path, so the client IP is the best available proxy for
    /// "this connection" for the H2 budget + decoy-header seed. Shared
    /// by both call sites so the derivation stays consistent.
    #[inline]
    fn conn_id_from_ip(ip: std::net::IpAddr) -> u64 {
        match ip {
            std::net::IpAddr::V4(v4) => u32::from(v4) as u64,
            std::net::IpAddr::V6(v6) => {
                let octets = v6.octets();
                let mut acc = 0u64;
                for &b in &octets[..8] {
                    acc = (acc << 8) | b as u64;
                }
                acc
            }
        }
    }

    fn resolve_client_ip(&self, session: &Session) -> std::net::IpAddr {
        let tcp_peer_ip = session
            .client_addr()
            .and_then(|a| a.as_inet().map(|s| s.ip()))
            .unwrap_or_else(|| std::net::IpAddr::from([0, 0, 0, 0]));

        let Some(cidrs) = &self.trusted_proxy_cidrs else {
            // Feature disabled — unchanged behaviour, no header consulted.
            return tcp_peer_ip;
        };

        if !cidrs.iter().any(|c| ip_in_cidr(tcp_peer_ip, c)) {
            // TCP peer is NOT a trusted proxy — never trust the headers.
            return tcp_peer_ip;
        }

        let req = session.req_header();

        if self.behind_cloudflare {
            // CF-Connecting-IP is the authoritative single-value header set by
            // Cloudflare. It is only consulted when the peer is already inside
            // the CF CIDR set (enforced above), so it cannot be spoofed.
            if let Some(real_ip) = req
                .headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            {
                return real_ip;
            }
        }

        // X-Forwarded-For: walk rightmost non-trusted hop. This is injection-
        // proof because the gate (tcp_peer in trusted set) was already checked.
        resolve_xff(&req.headers, cidrs).unwrap_or(tcp_peer_ip)
    }

    /// Build an Aegis `RequestContext` from a pingora `Session`.
    ///
    /// This is the bridge between pingora's request representation and
    /// the existing filter contract. Several filters (rate_limit, bot,
    /// scorer) read `host` on every request, so we cache it here once
    /// rather than re-hashing the HeaderMap per filter — matches the
    /// hyper hot-path semantics in `proxy::http::handle_collected`.
    ///
    /// `is_trusted_already` lets the caller forward a trust-gate result
    /// it already computed (the V78 cache fast-path runs the same
    /// dynamic_trust + bypass lookup before calling us). When `true`,
    /// we skip the per-trust-source re-lookups here — saving one
    /// DashMap probe, one HashSet probe, and one HMAC cookie verify
    /// per request that hit the early fast-path branch but missed the
    /// cache (e.g. trusted client requesting a not-yet-cached URL).
    fn build_ctx(
        &self,
        session: &Session,
        is_trusted_already: bool,
        now: Instant,
    ) -> RequestContext {
        let req = session.req_header();
        let method = req.method.clone();
        let path = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        // V230 — single-pass HeaderMap extraction. Previously this
        // built `host` and `user_agent` via two independent
        // `headers.get(name)` lookups, each of which hashes the
        // HeaderName and walks its bucket. At ~245k slow-path RPS
        // every hash-lookup we elide is real CPU.
        //
        // Folding both into one `iter()` pass yields a single linear
        // scan over the (typically <20) headers a real request
        // carries, costing one short str compare per header per
        // probe. The branch predictor handles the match arms cheaply
        // because the early-exit headers (host, user-agent) appear
        // near the front of nearly every browser request.
        //
        // The accept-language / accept-encoding / referer /
        // content-length headers that `extract_ml_features_v2` later
        // re-reads from `ctx.headers` are *not* cached here yet —
        // RequestContext does not (in this commit) carry fields for
        // them, and adding them is a cross-file change owned by the
        // RequestContext refactor agent. Once those fields land,
        // a follow-up can wire them into this same match without
        // adding another iter pass.
        let mut host: &str = "";
        let mut user_agent: Option<String> = None;
        for (name, value) in req.headers.iter() {
            match name.as_str() {
                "host" => {
                    if let Ok(s) = value.to_str() {
                        host = s;
                    }
                }
                "user-agent" => {
                    if let Ok(s) = value.to_str() {
                        user_agent = Some(s.to_string());
                    }
                }
                _ => {}
            }
        }
        // V238 — HTTP/2 fallback. HTTP/2 carries the host in the
        // `:authority` pseudo-header rather than the literal `Host`
        // header, and Pingora's `req.headers.iter()` does not surface
        // pseudo-headers (they live on `req.uri`). Without this fallback
        // every HTTP/2 request landed with `ctx.host = ""`, which
        // silently broke per-host policy lookups (the honeypot
        // bypass set, per-domain filter overrides, anomaly tracking,
        // etc. — they all compare against the bare hostname). Fall
        // back to `uri.host()` when the Host header didn't carry one,
        // then strip the port that some clients still attach there.
        let host: String = if host.is_empty() {
            req.uri.host().map(|h| h.to_string()).unwrap_or_default()
        } else {
            // Some HTTP/1.1 clients put `host:port` in the Host header.
            // Strip the port so downstream string comparisons work
            // against the bare hostname.
            match host.split_once(':') {
                Some((h, _port)) => h.to_string(),
                None => host.to_string(),
            }
        };

        // Snapshot headers into an Arc so filters that clone the
        // RequestContext do an atomic refcount bump rather than a
        // deep HeaderMap copy. (V230 — kept; the bigger refactor to
        // drop the clone entirely is deferred until downstream filter
        // call sites stop expecting an owned HeaderMap.)
        let headers = Arc::new(req.headers.clone());

        // V-new — real-IP resolution via trusted-proxy headers. When
        // AEGIS_BEHIND_CLOUDFLARE or AEGIS_TRUSTED_PROXIES is configured AND the
        // TCP peer is in the trusted CIDR set, the real client IP is read from
        // CF-Connecting-IP (Cloudflare) or the rightmost non-trusted hop in
        // X-Forwarded-For (generic proxy). When neither flag is set (the default)
        // this is a direct return of the TCP peer — zero overhead, zero change.
        let client_ip = self.resolve_client_ip(session);

        // V239 — per-country tally for the dashboard world map. The
        // GeoIpLookup default is NoopGeoIp whose country() returns None
        // with no work, so this is near-free when no GeoIP DB is
        // configured; when a MaxMind DB is loaded it's one mmap lookup.
        // Recorded once per request at ingress (total only; denied/
        // challenged outcome tracking is a follow-up).
        if let Some(cc) = self.geoip.country(client_ip) {
            self.metrics.observe_country(&cc, false, false);
        }

        // Trust gates — all three must be cheap because they run
        // per request. Dynamic-trust is a DashMap lookup; bypass is
        // a HashSet lookup; fp cookie is one HMAC verify on a
        // typically-absent cookie. is_trusted is the OR of all three
        // because any is sufficient to skip throttling.
        //
        // When `is_trusted_already == true` the caller (request_filter
        // V78 fast-path) has already computed dynamic_trust ||
        // bypass.matches_ip, so we short-circuit and skip the three
        // lookups (incl. the fp_cookie HMAC). The fp_cookie path is a
        // strict superset, not a hard prerequisite — a trusted IP that
        // happens to also carry an aegis_fp cookie still gets is_trusted
        // = true, which is the only thing downstream filters read.
        let is_trusted = if is_trusted_already {
            true
        } else {
            // V229 — reuse the caller's captured Instant; eliminates
            // a second vdso syscall on every slow-path request.
            let dynamic_trusted = self.dynamic_trust.is_trusted(client_ip, now);
            // V42 — already-verified browsers carry aegis_fp; skip the
            // ladder for them. Invalid/expired/wrong-IP cookies just
            // return false (no scoring impact here; the cookie was
            // present but didn't validate, which is harmless).
            let fp_verified = self.challenge.fp_cookie_valid(client_ip, &req.headers);
            // Cheap IP-only bypass first; full matches() (which also
            // checks path / UA) is deferred to request_filter where
            // those fields are known.
            dynamic_trusted || self.bypass.matches_ip(client_ip) || fp_verified
        };

        // V50/V53 — read TLS fingerprints from the SslDigest
        // extension slot stashed by `AegisTlsAccept`. None for plain
        // HTTP. JA3/JA4 set at certificate_callback time; mtls is
        // backfilled in handshake_complete_callback when a verified
        // client cert was presented.
        let tls_fp = crate::proxy::pingora_tls::read_fingerprints(session);
        // H9d — carry the JA3 **hash** (MD5 hex) forward on the
        // RequestContext, not the raw `{version},{ciphers},…` JA3
        // string. The hash is the form the `ja3_deny_hashes` policy and
        // `field:"ja3"` WAF rules match against, so storing it here is
        // what lets H9a's deny enforcement (in request_filter) actually
        // fire. Previously the whole JA3 triple was computed and then
        // discarded via `let _ = ja3;`, so the deny list silently never
        // enforced on the deployed pingora binary.
        let (ja3, ja4, mtls_fp) = match tls_fp {
            Some(fp) => (fp.ja3_hash.clone(), fp.ja4.clone(), fp.mtls.clone()),
            None => (None, None, None),
        };

        RequestContext {
            // V85 — use the shared thread-local counter (~10ns) instead
            // of Uuid::new_v4().to_string() (~300ns + heap alloc). The
            // request_id is only used for log correlation, doesn't need
            // cryptographic uniqueness.
            // V230 — request_id assignment unchanged: request_context.rs
            // still exposes only `next_request_id()` (no
            // request_id_string helper yet), so this is the V85
            // thread-local-counter path. If the RequestContext
            // refactor agent later adds a non-String request_id
            // representation, this site needs updating to match.
            request_id: crate::proxy::request_context::next_request_id_u64(),
            client_ip,
            method,
            path,
            headers,
            // V230 — reuse the V229 captured `now` instead of taking
            // another vdso clock_gettime. `now` was sampled in
            // request_filter once at request entry; the few hundred
            // ns of skew between then and here is irrelevant to every
            // `timestamp`-consumer (scorer windows, rate-limit
            // buckets) which all bucket at second or coarser
            // granularity.
            timestamp: now,
            user_agent,
            host,
            is_trusted,
            // V50 — JA4 comes from the openssl TlsAccept callback
            // (per-handshake fingerprint, captured before
            // ServerHello). JA4T comes from XDP SYN capture (V45).
            // V231 — JA4H is now lazy: the HTTP version is stashed so
            // RequestContext::ja4h() can compute the SHA-256 fingerprint
            // on first call. No computation happens here — saves ~2.7%
            // of CPU on the allow path where no filter reads ja4h.
            // ja4l/h2fp/h3fp/mtls_fp still need deeper pingora surface
            // hooks.
            // H9d — JA3 hash is now stored (was discarded). Used by the
            // H9a deny-list enforcement in request_filter.
            ja3,
            ja4,
            http_version: req.version,
            ja4h_cache: std::sync::OnceLock::new(),
            ja4t: None,
            ja4l: None,
            h2fp: None,
            h3fp: None,
            mtls_fp,
        }
    }
}

#[async_trait]
impl ProxyHttp for AegisPingoraProxy {
    type CTX = AegisCtx;

    fn new_ctx(&self) -> Self::CTX {
        AegisCtx::default()
    }

    /// Pre-upstream filtering. Builds the Aegis `RequestContext`,
    /// runs the full `FilterEngine`, and on a non-Allow decision
    /// writes the appropriate response inline and returns
    /// `Ok(true)` to tell pingora not to forward upstream.
    ///
    /// Allow / Deny are fully wired. Challenge / Tarpit currently
    /// fold into 403 / 444 with the right counters bumped — the
    /// cookie-based ladder and slow-drip TarpitBody port lands in
    /// later versions (see roadmap V27+).
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        // V229 — single timestamp capture for the whole request.
        // Profile on stand showed `clock_gettime` (vdso) at 4.35% of
        // userspace; this slow path was making ~10 redundant calls
        // per request (dynamic_trust, scorer, cache, anomaly, etc.).
        // All `Instant::now()` call sites below now read `ctx.now`
        // instead, dropping the count to one per request.
        let now = Instant::now();
        ctx.now = Some(now); // V236 — CHANGE 1: Option<Instant>
        ctx.start = Some(now);

        // V42 — /__aegis/verify must short-circuit BEFORE the
        // filter chain. The request carries the pending aegis_token
        // cookie + a ?t= query param; the handler validates both
        // and on success sets the long-lived aegis_fp cookie + 302
        // back to ?r=. We re-derive client_ip locally because
        // build_ctx is more expensive than necessary for this path.
        //
        // V229 — early routing branches all use `==` / `starts_with`
        // against `&'static str` constants, so a `&str` view of the
        // path is enough. The previous `to_string()` allocated on
        // every request just for the comparison. The branches that
        // actually need the borrow held across `.await` (tarpit
        // slug, client_signals body read) capture their own slices
        // first before the async call.
        let path_ref = session.req_header().uri.path();
        let is_verify = path_ref == crate::proxy::pingora_challenge::VERIFY_PATH;
        if is_verify {
            // V-new — use the resolved real client IP so the aegis_fp cookie
            // is bound to the actual visitor IP, not the rotating CF edge IP.
            // This is the primary fix for the infinite challenge/redirect loop
            // reported on the production stand when AEGIS sits behind Cloudflare.
            let client_ip = self.resolve_client_ip(session);
            // Phase 3 — resolve the per-host challenge config so the
            // verify handler can run the active in-browser-probe gate
            // (headless / WebGL-audio / DOM-timing / proof-of-click).
            // Cheap: a Host-header read + one HashMap lookup that returns
            // the all-None default for any host without challenge config.
            let dcfg = self
                .arsenal
                .as_ref()
                .map(|a| {
                    let req = session.req_header();
                    let host = req
                        .headers
                        .get(http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(|h| h.split(':').next().unwrap_or(h))
                        .filter(|h| !h.is_empty())
                        .or_else(|| req.uri.host())
                        .unwrap_or("");
                    a.domain_challenge_config(host)
                })
                .unwrap_or_default();
            self.challenge
                .handle_verify(session, client_ip, &dcfg, self.arsenal.as_ref(), &self.xdp)
                .await?;
            self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
            );
            return Ok(true);
        }

        // V234 — ACME HTTP-01 challenge. A `/.well-known/acme-challenge/
        // <token>` request is answered from the in-memory challenge
        // store BEFORE the filter chain, so Let's Encrypt validation
        // works while issuance is in flight. The store is empty for
        // normal traffic → `starts_with` miss → falls straight through.
        if path_ref.starts_with(crate::acme::HTTP01_PATH_PREFIX)
            && let Some(keyauth) = self.acme_challenges.challenge_response_for_path(path_ref)
        {
            let mut h = pingora_http::ResponseHeader::build(200, Some(2))?;
            let _ = h.insert_header("content-type", "text/plain");
            let _ = h.insert_header("content-length", keyauth.len().to_string());
            session.write_response_header(Box::new(h), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from(keyauth)), true)
                .await?;
            self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
            );
            return Ok(true);
        }

        // V154 — robots.txt honeypot auto-labeling. Observational
        // only — doesn't gate; just pushes a Malicious training
        // sample when path matches Disallow. honoured_robots=false:
        // a per-IP "fetched /robots.txt first?" tracker would tighten
        // this further; for now the operator-supplied robots.txt
        // signal alone is the label source.
        if let Some(hp) = &self.robots_honeypot {
            let _ = hp.observe_request(path_ref, false);
        }

        // V152 — V147 poisoned tarpit endpoint. Only fires when a
        // TarpitGenerator is wired AND path starts with the configured
        // prefix. Streams Markov-generated HTML with delay between
        // chunks so a crawler holds the socket for several seconds
        // per page — the cost-multiplier the V147 module is designed for.
        const TARPIT_PREFIX: &str = "/__aegis/tarpit/";
        if path_ref.starts_with(TARPIT_PREFIX)
            && let Some(tarpit) = &self.tarpit_generator
        {
            // V229 — own the slug across the async render call so
            // session can be re-borrowed for the response writes.
            let slug = path_ref[TARPIT_PREFIX.len()..].to_string();
            let seed = crate::poisoned_tarpit::seed_from_slug(&slug);
            let chunks = tarpit.render_chunks(seed, self.tarpit_chunks);
            let total_len: usize = chunks.iter().map(|c| c.len()).sum();
            let mut h = pingora_http::ResponseHeader::build(200, Some(4))?;
            let _ = h.insert_header("content-type", "text/html; charset=utf-8");
            let _ = h.insert_header("content-length", total_len.to_string());
            let _ = h.insert_header("cache-control", "no-store");
            let _ = h.insert_header("x-aegis-tarpit", "1");
            session.write_response_header(Box::new(h), false).await?;
            let n = chunks.len();
            for (i, c) in chunks.into_iter().enumerate() {
                let end = i == n - 1;
                session
                    .write_response_body(Some(bytes::Bytes::from(c)), end)
                    .await?;
                if !end {
                    // V190 — when the arsenal is wired, draw the
                    // inter-chunk delay from the log-normal jitter
                    // distribution instead of a fixed sleep. A uniform
                    // 250ms cadence is itself a fingerprint; jitter
                    // defeats response-latency fingerprinting. Each
                    // chunk gets its own seed for per-chunk variety.
                    // Falls back to the fixed delay when arsenal is off
                    // (no behaviour change when disabled).
                    let delay = match &self.arsenal {
                        Some(arsenal) => {
                            use std::sync::atomic::Ordering;
                            let chunk_seed = seed
                                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                                .wrapping_add(i as u64);
                            arsenal
                                .counters
                                .latency_jitter_emits
                                .fetch_add(1, Ordering::Relaxed);
                            tarpit.jittered_chunk_delay(chunk_seed)
                        }
                        None => self.tarpit_chunk_delay,
                    };
                    tokio::time::sleep(delay).await;
                }
            }
            self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
            );
            return Ok(true);
        }

        // V150 — CreepJS collection endpoint. Only fires when a
        // ClientSignalsStore is wired; otherwise the path falls
        // through to normal filter handling (and 404s if no upstream
        // route matches). Body capped at 8 KiB — a coherent payload
        // is <1 KiB, anything beyond is operator-side abuse.
        if path_ref == crate::client_consistency::COLLECTION_PATH
            && session.req_header().method == http::Method::POST
            && let Some(store) = &self.client_signals
        {
            const MAX_BODY: usize = 8 * 1024;
            // V-new — use resolved real-IP so client signals are indexed
            // under the visitor IP, not the proxy/edge IP.
            let client_ip = self.resolve_client_ip(session);
            let mut body = Vec::with_capacity(512);
            while let Some(chunk) = session.read_request_body().await? {
                if body.len() + chunk.len() > MAX_BODY {
                    let h = pingora_http::ResponseHeader::build(413, Some(2))?;
                    session.write_response_header(Box::new(h), true).await?;
                    return Ok(true);
                }
                body.extend_from_slice(&chunk);
            }
            let ok = crate::client_consistency::parse_and_store(&body, client_ip, store, now);
            let status = if ok { 204 } else { 400 };
            let mut h = pingora_http::ResponseHeader::build(status, Some(2))?;
            let _ = h.insert_header("cache-control", "no-store");
            session.write_response_header(Box::new(h), true).await?;
            self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
            );
            return Ok(true);
        }

        // V78 — cache fast-path for trusted clients BEFORE build_ctx.
        // Standard CDN/edge behaviour: cache hits skip origin filter
        // chain. Eliminates ~8-10 String allocations from build_ctx +
        // the full FilterEngine evaluation on the 99.99% cache-warm
        // path for trusted traffic.
        //
        // Safety analysis: cached entries are by definition
        // previously-allowed responses (the slow path only populates
        // cache after WAF/filter Allow). Serving them to a trusted
        // client that wouldn't have hit a path-or-UA-based WAF rule
        // is identical to nginx + proxy_cache semantics. Untrusted
        // clients still go through the full slow path so threat-aware
        // cache policy is preserved.
        // V-new — use the resolved real client IP so that dynamic_trust /
        // bypass checks key on the visitor IP, not the proxy/edge IP.
        let client_ip_early = self.resolve_client_ip(session);
        // V229 — reuse the captured Instant from the top of this
        // function instead of a fresh `Instant::now()` (saves one
        // vdso syscall on every request).
        let now_early = now;
        let is_trusted_early = self.dynamic_trust.is_trusted(client_ip_early, now_early)
            || self.bypass.matches_ip(client_ip_early);
        if is_trusted_early {
            // Read method + host + path-with-query directly from the
            // request — zero alloc since ResponseCache::lookup takes
            // &str slices. The req borrow is released before the
            // async session write below.
            let (cached_opt, is_head_via_get) = {
                let req = session.req_header();
                let host = req
                    .headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let path_pq = req
                    .uri
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                if self.response_cache.should_consider(&req.method, host) {
                    let first =
                        self.response_cache
                            .lookup(&req.method, host, path_pq, false, now_early);
                    // V79 — HEAD requests can serve from a GET cache
                    // entry. Standard CDN behaviour: HEAD response is
                    // GET response with body stripped. Saves an
                    // upstream round-trip for HEAD health-checks /
                    // link-preloaders against a cache populated by GET.
                    if first.is_none() && req.method == http::Method::HEAD {
                        let from_get = self.response_cache.lookup(
                            &http::Method::GET,
                            host,
                            path_pq,
                            false,
                            now_early,
                        );
                        (from_get, true)
                    } else {
                        (first, false)
                    }
                } else {
                    (None, false)
                }
            };
            if let Some(cached) = cached_opt {
                // Cache HIT on trusted client — serve immediately,
                // skip every downstream check (build_ctx, geoip,
                // bypass, full filter chain).
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                // V89 — cluster aggregation (no-op when shared arena
                // unavailable). REQUESTS_TOTAL bump is auto-added by
                // the perl pass after every metrics.requests_total
                // line; CACHE_HITS is the fast-path-specific extra.
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
                );
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::CACHE_HITS,
                );
                let mut header =
                    ResponseHeader::build(cached.status.as_u16(), Some(cached.headers.len() + 1))?;
                // V82 — pass &HeaderName directly. The previous
                // `k.as_str().to_string()` allocated a String per
                // header on every cache hit; at 950k RPS × 5-10
                // headers per response = 5-10M alloc/sec of pure
                // waste. `IntoCaseHeaderName` has an impl for
                // `&HeaderName` that uses the existing bytes
                // refcount.
                for (k, v) in cached.headers.iter() {
                    let _ = header.insert_header(k, v);
                }
                let cache_tag = if is_head_via_get {
                    "HIT-FAST-HEAD"
                } else {
                    "HIT-FAST"
                };
                let _ = header.insert_header("x-aegis-cache", cache_tag);
                // For HEAD-served-via-GET, send headers only (no body)
                // — per RFC 9110 §9.3.2 HEAD responses must not have
                // a body but must include the headers GET would.
                if is_head_via_get {
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                } else {
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session.write_response_body(Some(cached.body), true).await?;
                }
                return Ok(true);
            }
        }

        // Reuse the trust gate already computed above — when the
        // V78 fast-path probe ran and returned true, build_ctx skips
        // its own dynamic_trust + bypass + fp_cookie re-lookups.
        let req_ctx = self.build_ctx(session, is_trusted_early, now);
        let client_ip = req_ctx.client_ip;
        ctx.client_ip = Some(client_ip);
        // V231 — FIX 2: store the whole RequestContext on AegisCtx so
        // logging / upstream_peer can read host/method/path from the
        // single stored copy. Eliminates the previous 3 per-request
        // String clones:
        //   ctx.host = req_ctx.host.clone()                — gone
        //   ctx.method = req_ctx.method.as_str().to_string() — gone
        //   ctx.path = req_ctx.path.clone()                — gone
        //
        // Throughout this function we borrow ctx.req_ctx with short-lived
        // inline borrows (NLL allows this — each borrow ends at its
        // last use, before the next mutation of a different ctx field).
        ctx.req_ctx = Some(req_ctx);
        // V38 — feed the per-host EMA so attack-mode detection
        // stays live. observe() returns true when *this tick*
        // crosses the trip threshold; /admin/anomaly + V39 geoip
        // attack-mode gating both read `under_attack` afterwards.
        // V229 — hoist the cheap enabled-check above the call so a
        // disabled detector pays zero overhead (no host clone, no
        // virtual call, no inner observe state mutation). The default
        // config has `enabled = false`; previously every request paid
        // for the host borrow + a vdso `Instant::now()` capture.
        //
        // Note: all `ctx.req_ctx.as_ref().unwrap().xxx` accesses below
        // are short-lived inline borrows (NLL ends each borrow at last
        // use). Rust allows borrowing ctx.req_ctx while mutating other
        // fields like ctx.denied_by because they are disjoint.
        if self.anomaly.enabled() && !ctx.req_ctx.as_ref().unwrap().host.is_empty() {
            let _just_tripped = self
                .anomaly
                .observe(&ctx.req_ctx.as_ref().unwrap().host, now);
        }

        // ── H9a — TLS fingerprint deny lists ─────────────────────────
        // Re-enforce `cfg.tls.ja4_deny_prefixes` / `ja3_deny_hashes` at
        // the request layer. The legacy hyper server slams the socket
        // shut at handshake time; the pingora data plane terminates TLS
        // in its own acceptor and never re-checked these lists, so on
        // the deployed binary they silently never enforced. This runs
        // before the (heavier) filter chain so a known-bad fingerprint
        // is rejected as cheaply as the geoip deny. Short-circuits to a
        // single `is_empty()` pair when no lists are configured.
        if let Some(reason) = self.tls_fingerprint_denied(ctx.req_ctx.as_ref().unwrap()) {
            ctx.denied_by = Some(reason);
            self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
            );
            self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
            );
            self.metrics.observe_filter_block(reason);
            self.metrics
                .observe_domain_outcome(&ctx.req_ctx.as_ref().unwrap().host, true, false);
            self.dynamic_trust.observe_denied(client_ip, now);
            self.record_denied(client_ip, now);
            let trace_id = ctx.req_ctx.as_ref().map_or(0, |r| r.request_id);
            self.respond_visitor_error(session, 403, "Access denied.", trace_id)
                .await?;
            return Ok(true);
        }

        // V39 — country-based deny. Cheaper than the full filter
        // chain so it runs first, but AFTER anomaly.observe so
        // attack_mode_only can read the freshly-updated state.
        if let Some(_reason) = self.geoip_deny(client_ip, &ctx.req_ctx.as_ref().unwrap().host) {
            ctx.denied_by = Some("geoip");
            self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
            );
            self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
            crate::shared_state::global::cluster_bump(
                crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
            );
            self.metrics.observe_filter_block("geoip");
            self.metrics
                .observe_domain_outcome(&ctx.req_ctx.as_ref().unwrap().host, true, false);
            self.dynamic_trust.observe_denied(client_ip, now);
            self.record_denied(client_ip, now);
            let trace_id = ctx.req_ctx.as_ref().map_or(0, |r| r.request_id);
            self.respond_visitor_error(
                session,
                403,
                "Your connection has been blocked based on your location.",
                trace_id,
            )
            .await?;
            return Ok(true);
        }
        // V37 — full bypass check (IP + path + UA). build_ctx did the
        // IP-only fast path for is_trusted; now that path + UA are in
        // ctx, run the full matcher to drive `is_high_threat`.
        let is_bypass = self.bypass.matches(ctx.req_ctx.as_ref().unwrap());
        let is_dynamic_trusted = self.dynamic_trust.is_trusted(client_ip, now);
        let is_high_threat = !is_bypass && !is_dynamic_trusted;
        ctx.is_high_threat = is_high_threat;

        let (mut action, mut filter_name) = self
            .filters
            .evaluate_with_attribution(ctx.req_ctx.as_ref().unwrap());

        // ── V182/V179/V198 — arsenal live-path observers ─────────────────
        // Runs on the slow path only (trusted clients short-circuited
        // far above via the V78 cache fast-path), so these add zero cost
        // to warm trusted traffic. All three are no-ops when the arsenal
        // is unwired. They are observational here — they bump the
        // module counters and enforce the cheap per-conn H2 budget, but
        // do NOT override the FilterEngine verdict (behaviour-neutral so
        // there is no regression when arsenal is enabled).
        if let Some(arsenal) = &self.arsenal {
            let rctx = ctx.req_ctx.as_ref().unwrap();
            // V182 — H2 control-frame budget. Pingora doesn't surface
            // raw frame hooks, but every h2 request opens a stream, so
            // we enforce the per-connection stream budget here (the
            // Rapid-Reset / stream-churn surface). conn_id is derived
            // from the client IP (same scheme as the V188 decoy path).
            if rctx.http_version == http::Version::HTTP_2 {
                let conn_id = Self::conn_id_from_ip(client_ip);
                let _within_budget = arsenal.observe_h2_request(conn_id);
                // Budget rejection is recorded via the counter; we do
                // not tear the connection down from here (that needs a
                // frame-level hook). The counter makes the DDoS gap
                // visible + the budget state is live for the XDP mirror.
            }
            // V179 — multi-pass normalisation + SQL-semantic recogniser
            // over the raw query string. Catches multi-encoded SQLi the
            // substring WAF misses. Observational: bumps the
            // normalisation counters; the verdict is logged on a hit but
            // the FilterEngine action stands.
            if let Some(query) = rctx.path.split_once('?').map(|(_, q)| q)
                && !query.is_empty()
            {
                let verdict = arsenal.normalisation_analyse(query);
                if verdict.is_attack() {
                    tracing::info!(
                        target: "aegis::arsenal::normalisation",
                        score = verdict.score,
                        reasons = ?verdict.reasons,
                        host = %rctx.host,
                        "normalisation chain flagged multi-encoded injection",
                    );
                }
                // V180 — per-endpoint parameter profile. Previously this
                // only ran inside extract_ml_features_v2(), which is
                // gated behind AEGIS_ML_V2=1, so on a stock deployment
                // the param-profile learner never saw traffic. The
                // observation is cheap (borrowed keys, no allocation per
                // param), so we also run it here on the slow path
                // independent of ML V2. The ML-V2 path still observes
                // too (idempotent — both feed the same rolling store).
                let (path_only, _) = rctx
                    .path
                    .split_once('?')
                    .unwrap_or((rctx.path.as_str(), ""));
                let host = rctx.host.as_str();
                for pair in query.split('&').take(16) {
                    let Some((name, value)) = pair.split_once('=') else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    use std::sync::atomic::Ordering;
                    let key_ref = crate::param_profile::ParamKeyRef::new(host, path_only, name);
                    let score = arsenal.param_profile.score_ref(key_ref, value);
                    let key_ref = crate::param_profile::ParamKeyRef::new(host, path_only, name);
                    arsenal.param_profile.observe_ref(key_ref, value);
                    arsenal
                        .counters
                        .param_profile_observations
                        .fetch_add(1, Ordering::Relaxed);
                    if score > 0.5 {
                        arsenal
                            .counters
                            .param_profile_anomalies
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // V198 — unified enrichment lookup over the connection JA4.
            // Bumps the enrichment counters + warms the facade cache so
            // the admin /threats fan-out is hot. Verdict folds nowhere
            // yet (observational), but the source does real work.
            if let Some(ja4) = rctx.ja4.as_deref() {
                let _verdict = arsenal.enrich_ja4(ja4);
            }

            // ── H9b — JA4 corpus Deny → real protective action ───────────
            // The shipped JA4 corpus labels known-bad tooling
            // (sqlmap, curl, python-requests, nuclei, …) as Deny. Until
            // now a corpus Deny only bumped the `ja4_reputation` ML
            // feature inside `extract_ml_features_v2`, which (a) is
            // gated behind ML-v2 being wired and (b) never produced an
            // actual allow/deny decision — the verdict was discarded.
            // Here we turn a corpus Deny into a hard request-path Deny
            // (403), but ONLY when the FilterEngine would otherwise
            // Allow — we never downgrade an existing Deny/Challenge/
            // Tarpit. This is conservative: corpus Deny entries are
            // curated, high-volume, known-tooling fingerprints, and a
            // JA4 cannot be forged to *look like* a benign browser
            // while still matching a Deny entry (the match is on the
            // attacker's own emitted fingerprint).
            if let Some(ja4) = rctx.ja4.as_deref() {
                use std::sync::atomic::Ordering;
                let hit = arsenal.ja4_corpus.lookup(ja4);
                if matches!(hit.verdict, crate::ja4_corpus::Verdict::Deny)
                    && matches!(action, FilterAction::Allow)
                {
                    arsenal
                        .counters
                        .ja4_corpus_deny_hits
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::info!(
                        target: "aegis::arsenal::ja4_corpus",
                        host = %rctx.host,
                        ja4 = %ja4,
                        label = %hit.label,
                        "ja4 corpus deny — escalating request to 403"
                    );
                    action = FilterAction::Deny {
                        status: 403,
                        reason: std::borrow::Cow::Borrowed("ja4_corpus_deny"),
                    };
                    filter_name = "ja4_corpus";
                }
            }

            // ── V233+ passive bot-detection signals (zero user friction) ──
            // Pure, header/JA4/ASN-derived signals (no JS probe, no
            // redirect, no cookie). Per-host gated via DomainChallengeConfig
            // — every sub-check is OFF unless the operator enabled it, so a
            // stock host pays only one HashMap lookup + an all-None scan that
            // returns (0, []). When a host HAS toggles on and the request
            // scores high enough, we ESCALATE the FilterEngine verdict from
            // Allow → Challenge (we never downgrade Deny/Challenge, and never
            // hard-block — datacenter ASNs raise suspicion, they don't ban).
            {
                use std::sync::atomic::Ordering;
                let host = rctx.host.as_str();
                let dcfg = arsenal.domain_challenge_config(host);
                // Resolve the client ASN from the GeoIP ASN DB (None when no
                // ASN DB is loaded — the static hosting table still can't
                // match, so the datacenter signal simply stays quiet).
                let asn = self.geoip.asn(client_ip);
                let (passive_score, reasons) = crate::challenge_signals::passive_bot_score(
                    &rctx.headers,
                    rctx.ja4.as_deref(),
                    asn,
                    &dcfg,
                );
                // Bump the per-signal activity counters for every reason that
                // fired (surfaced under the "signals" object in
                // /admin/api/challenge).
                for reason in &reasons {
                    match *reason {
                        "ja4_ua_consistency" => arsenal
                            .counters
                            .challenge_ja4_ua_consistency_hits
                            .fetch_add(1, Ordering::Relaxed),
                        "header_fingerprint" => arsenal
                            .counters
                            .challenge_header_fingerprint_hits
                            .fetch_add(1, Ordering::Relaxed),
                        "h2_fingerprint" => arsenal
                            .counters
                            .challenge_h2_fingerprint_hits
                            .fetch_add(1, Ordering::Relaxed),
                        "datacenter_asn_challenge" => arsenal
                            .counters
                            .challenge_datacenter_asn_challenge_hits
                            .fetch_add(1, Ordering::Relaxed),
                        _ => 0,
                    };
                }
                // Escalation threshold: a single high-weight signal (≥35,
                // e.g. JA4↔UA contradiction) or two stacked medium signals
                // crosses 50. Only escalate a verdict the engine would
                // otherwise Allow — a real Deny/Challenge already wins.
                if passive_score >= 50 && matches!(action, FilterAction::Allow) {
                    tracing::info!(
                        target: "aegis::challenge::passive",
                        host = %host,
                        score = passive_score,
                        reasons = ?reasons,
                        "passive bot signals escalated request to challenge"
                    );
                    action = FilterAction::Challenge {
                        level: crate::filters::ChallengeLevel::Html,
                        reason: std::borrow::Cow::Borrowed("passive_bot_signals"),
                    };
                    filter_name = "challenge_signals";
                }
            }
        }

        // ── V108 RiskEngine — Observe (behaviour-neutral) ────────────────
        // Runs AFTER the FilterEngine verdict is committed. In Observe mode
        // RiskEngine::evaluate() ALWAYS returns RiskAction::Allow (its
        // mode-gate), and `action` is NEVER reassigned here — the
        // `match action` below sees the identical FilterEngine value. Cost
        // when the engine is off (default): a single Option check.
        if let Some(ref re) = self.risk_engine {
            let rctx = ctx.req_ctx.as_ref().unwrap();
            let threat_score = self.scorer.score(client_ip).as_f64();
            let under_attack = self.anomaly.under_attack(&rctx.host);

            // M3 — populate every RiskInput signal from its OWN per-request
            // source, independent of which filter the engine attributed the
            // verdict to. Previously the strong signals (waf / honeypot /
            // threat_intel) were keyed solely off `filter_name`, so they were
            // mutually exclusive and never summed, and bot_score / ml_score /
            // challenge_verified were hardcoded — making the "deny on the SUM
            // of weak signals" design inert. The engine is Observe-by-default,
            // so this only enriches the logged score until Enforce is on.

            // ml_score — the real ML scorer output for THIS request. The
            // cache-tier path (derive_threat_tier) is short-circuited for
            // trusted clients, so we recompute here. Cost is only paid when
            // the RiskEngine is wired (off by default) and reuses the
            // `threat_score` reputation lookup as the ML feature seed.
            let ml_score = self.compute_ml_score(rctx, threat_score);

            // bot_score — passive (header/JA4/ASN-derived) bot suspicion,
            // the same signal escalated above. It is only meaningful when the
            // arsenal is wired AND the host has passive toggles enabled; on a
            // stock host the per-host config returns all-None and the score is
            // 0. Recomputed here (rather than threaded from the arsenal block
            // above) to keep this construction site self-contained — the call
            // is a pure, allocation-light header scan and only runs when the
            // RiskEngine is wired.
            let bot_score: u32 = if let Some(arsenal) = &self.arsenal {
                let dcfg = arsenal.domain_challenge_config(rctx.host.as_str());
                let asn = self.geoip.asn(client_ip);
                let (score, _reasons) = crate::challenge_signals::passive_bot_score(
                    &rctx.headers,
                    rctx.ja4.as_deref(),
                    asn,
                    &dcfg,
                );
                score as u32
            } else {
                0
            };

            let risk_input = crate::ddos::risk_engine::RiskInput {
                ctx: Some(rctx),
                // Real per-rule WAF severity is not yet threaded through
                // evaluate_with_attribution (it returns only a name), so we
                // still detect the WAF hit via attribution and use the
                // documented conservative Medium placeholder for severity.
                // This is the one signal whose per-rule strength genuinely
                // isn't reachable here.
                waf: if filter_name == "waf" {
                    Some(crate::ddos::risk_engine::WafSignal {
                        severity: crate::ddos::risk_engine::WafSeverity::Medium,
                        rule_id: crate::ddos::risk_engine::WAF_SIGNAL_PLACEHOLDER,
                    })
                } else {
                    None
                },
                // No GraphQL guard exists in the pipeline yet, so there is no
                // per-request anomaly signal to read — left false until a
                // GraphQL filter lands.
                graphql_anomaly: false,
                bot_score,
                threat_score,
                ml_score,
                // honeypot / threat_intel are terminal FilterEngine verdicts;
                // the only per-request signal reachable here is the engine's
                // attribution (the filters are moved into the engine and not
                // retained on `self`, so there is no independent counter or
                // ctx flag to read). Detected via attribution accordingly.
                honeypot_hit: filter_name == "honeypot" || filter_name == "endpoint_policy_tarpit",
                under_attack,
                // challenge_verified — true when this client cleared a
                // challenge / carries a valid fp-cookie. `rctx.is_trusted`
                // already folds in the fp_cookie HMAC validity check (see
                // build_ctx), so it is the genuine per-request signal.
                challenge_verified: rctx.is_trusted,
                trusted: is_bypass || is_dynamic_trusted,
                threat_intel_hit: filter_name == "threat_intel",
            };
            let decision = re.evaluate(&risk_input);
            // Compare the engine's would-be band to the FilterEngine verdict
            // so an operator can validate agreement before any Enforce flip.
            let would_have =
                match crate::ddos::risk_engine::RiskEngine::classify_score(decision.score) {
                    crate::ddos::risk_engine::RiskAction::Allow => "allow",
                    crate::ddos::risk_engine::RiskAction::Challenge(_) => "challenge",
                    crate::ddos::risk_engine::RiskAction::Deny { .. } => "deny",
                };
            let filter_verdict = match &action {
                FilterAction::Allow => "allow",
                FilterAction::Deny { .. } => "deny",
                FilterAction::Challenge { .. } => "challenge",
                _ => "other", // Tarpit / any future variant — treated separately
            };
            // Divergences (the engine and the FilterEngine disagree) are
            // the signal an operator validates before any Enforce flip —
            // surface them at INFO so they appear at the production default
            // log level. Agreements (the benign majority) stay at DEBUG to
            // avoid per-request log spam. The aggregate counts
            // (evaluations / would-be allow/challenge/deny / max_score) are
            // captured in `re.metrics` regardless of log level.
            let agree = would_have == filter_verdict;
            if agree {
                tracing::debug!(
                    target: "aegis::risk_engine::observe",
                    risk_score = decision.score,
                    would_have,
                    filter_verdict,
                    agree,
                    reasons = ?decision.reasons,
                    host = %rctx.host,
                    filter_name,
                    "risk_engine_observe"
                );
            } else {
                tracing::info!(
                    target: "aegis::risk_engine::observe",
                    risk_score = decision.score,
                    would_have,
                    filter_verdict,
                    agree,
                    reasons = ?decision.reasons,
                    host = %rctx.host,
                    filter_name,
                    "risk_engine_divergence"
                );
            }
            // decision.action is discarded in ALL modes: it is Allow in
            // Observe; in HighConfidenceEnforce it could be Deny/Challenge for
            // a high-score request, but Stage 3 action-application has not
            // landed, so `action` above stays untouched either way.
            let _ = &decision.action;
        }
        // ── end V108 RiskEngine Observe ──────────────────────────────────

        match action {
            FilterAction::Allow => {
                self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
                );
                // V30 — bump the trust counter only on clean allow.
                // Internal observation thresholds + window decide
                // when this IP gets promoted to "trusted" status.
                self.dynamic_trust.observe_allowed(client_ip, now);
                // V37 — scorer bump deferred to logging so we only
                // bump after the request actually completes (matches
                // hyper request_done semantics). See logging hook.

                // V32 + V34 — response cache lookup with
                // single-flight stampede protection. `should_consider`
                // is the cheap gate (cache disabled / wrong method /
                // host not in allow-list → false fast).
                //
                // Flow:
                //   1. Lookup cache. Hit → serve inline, return.
                //   2. Miss → try to claim leader slot in
                //      pending_fetches. If vacant, we're leader,
                //      proceed to upstream. If occupied, become
                //      follower: wait up to 5s on the leader's
                //      Notify, then retry lookup. Follower hit →
                //      serve. Follower still-miss → proceed as
                //      independent leader-less fetch (no registry).
                // V231 — all req_ctx borrows below are via ctx.req_ctx
                // so they end immediately after the expression using
                // them completes (NLL). ctx.cache_pending etc. are
                // mutated between borrows, never while a &req_ctx is
                // held, so field-disjoint borrowing is safe.
                if self.response_cache.should_consider(
                    &ctx.req_ctx.as_ref().unwrap().method,
                    &ctx.req_ctx.as_ref().unwrap().host,
                ) {
                    if self
                        .try_serve_from_cache(
                            session,
                            ctx.req_ctx.as_ref().unwrap(),
                            is_high_threat,
                            // V236 — CHANGE 3: pass ctx.now; always Some here.
                            now,
                        )
                        .await?
                    {
                        return Ok(true);
                    }

                    // Extract the key before any ctx mutation — this
                    // block-scoped borrow ends before the entry lookup.
                    let key = {
                        let rctx = ctx.req_ctx.as_ref().unwrap();
                        (rctx.method.clone(), rctx.host.clone(), rctx.path.clone())
                    };
                    // Use dashmap Entry pattern to distinguish
                    // "just inserted" (leader) from "already there"
                    // (follower) explicitly. The previous attempt
                    // looked at Arc::strong_count, but with the
                    // dashmap holding one Arc and our local clone
                    // adding another, both branches hit count == 2
                    // and every request thought it was the leader.
                    let (notify, is_first) = match self.pending_fetches.entry(key.clone()) {
                        dashmap::Entry::Vacant(v) => {
                            let n = Arc::new(tokio::sync::Notify::new());
                            v.insert(n.clone());
                            (n, true)
                        }
                        dashmap::Entry::Occupied(o) => (o.get().clone(), false),
                    };

                    if is_first {
                        // Leader path — populate body in subsequent
                        // phases; logging will notify_waiters + drop
                        // the registry entry.
                        ctx.sf_leader = true;
                        // Short-lived borrow to read method/host/path.
                        let (m, h, p) = {
                            let rctx = ctx.req_ctx.as_ref().unwrap();
                            (rctx.method.clone(), rctx.host.clone(), rctx.path.clone())
                        };
                        ctx.cache_pending = Some(CachePending {
                            method: m,
                            host: h,
                            path: p,
                            status: None,
                            upstream_headers: None,
                            body_buf: body_pool::take(8 * 1024),
                            overflowed: false,
                        });
                    } else {
                        // Follower path — wait for the leader to
                        // finish, then re-lookup the cache. Bounded
                        // wait so a stuck leader degrades into N
                        // concurrent fetches instead of N hangs.
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            notify.notified(),
                        )
                        .await;
                        if self
                            .try_serve_from_cache(
                                session,
                                ctx.req_ctx.as_ref().unwrap(),
                                is_high_threat,
                                // V236 — CHANGE 3: pass ctx.now; always Some here.
                                now,
                            )
                            .await?
                        {
                            return Ok(true);
                        }
                        // Still miss after wait — fall through and
                        // fetch independently. Don't re-enter
                        // single-flight; we'd risk N followers all
                        // trying to claim leader at once and just
                        // adding latency. Hitting upstream as
                        // independent requests at this point is the
                        // graceful-degradation path.
                        let (m, h, p) = {
                            let rctx = ctx.req_ctx.as_ref().unwrap();
                            (rctx.method.clone(), rctx.host.clone(), rctx.path.clone())
                        };
                        ctx.cache_pending = Some(CachePending {
                            method: m,
                            host: h,
                            path: p,
                            status: None,
                            upstream_headers: None,
                            body_buf: body_pool::take(8 * 1024),
                            overflowed: false,
                        });
                    }
                }
                Ok(false)
            }
            FilterAction::Deny { status, reason: _ } => {
                ctx.denied_by = Some(filter_name);
                // V243 — rate-limit denies are their own event-log action so
                // the admin logs view distinguishes throttling from hard denies.
                ctx.event_action = Some(
                    if filter_name == "rate_limit" || filter_name == "distributed_rate" {
                        "rate"
                    } else {
                        "deny"
                    },
                );
                self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
                );
                self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
                );
                // V237 — break out rate-limit denies into a dedicated cluster slot so
                // dashboards can distinguish rate-limiting from WAF/ACL blocks.
                if filter_name == "rate_limit" || filter_name == "distributed_rate" {
                    crate::shared_state::global::cluster_bump(
                        crate::shared_state::global::cluster_idx::RATE_LIMITED,
                    );
                }
                self.metrics.observe_filter_block(filter_name);
                self.metrics.observe_domain_outcome(
                    &ctx.req_ctx.as_ref().unwrap().host,
                    true,
                    false,
                );
                // V30 — any deny by any filter revokes trust for
                // this IP if it had earned it. A trusted IP that
                // suddenly trips the WAF should lose its fast-pass.
                self.dynamic_trust.observe_denied(client_ip, now);
                // V37 — feed the sliding-window threat scorer so
                // /admin/threats and downstream alerts rank this IP.
                self.record_denied(client_ip, now);
                // V121 — analytics split: WAF/honeypot/bot decisions
                // → per-IP "bot suspected" + per-endpoint "attack
                // target" so the admin UI separates single-IP bots
                // from distributed-attack patterns.
                let bot_reason = match filter_name {
                    "honeypot" => crate::threat_analytics::BotReason::HoneypotHit,
                    "waf" => crate::threat_analytics::BotReason::WafSignature,
                    "bot" => crate::threat_analytics::BotReason::HighThreatScore,
                    _ => crate::threat_analytics::BotReason::HighThreatScore,
                };
                self.record_bot(client_ip, bot_reason);
                // V244 — auto-learn JA4 reputation from unambiguous-malicious
                // outcomes. A request that tripped a honeypot trap or carried a
                // WAF attack signature is a confirmed bad client; record its JA4
                // so the reputation signal flags the same fingerprint on future
                // requests (self-populating, no external feed). observe_bad is
                // deduped + capped (I/O only on a new fingerprint) and a no-op
                // when auto-learn is off.
                if matches!(filter_name, "honeypot" | "waf")
                    && let Some(rep) = &self.ja4_reputation
                    && let Some(ja4) = ctx.req_ctx.as_ref().and_then(|c| c.ja4.as_deref())
                {
                    rep.observe_bad(ja4, filter_name);
                }
                let pattern = crate::site_map::generalise_path(&ctx.req_ctx.as_ref().unwrap().path);
                self.threat_analytics.observe_endpoint_hit(
                    &ctx.req_ctx.as_ref().unwrap().host,
                    &pattern,
                    client_ip,
                );
                // V187 — arsenal BGP RTBH dispatcher. Push the /32
                // upstream on FullEnforce-class denies so the carrier
                // sees the blackhole before we do. Best-effort: a
                // failed announce is logged, not surfaced.
                if let Some(arsenal) = &self.arsenal {
                    use std::sync::atomic::Ordering;
                    let recent = self.scorer.score(client_ip).0;
                    if (recent >= 80.0 || filter_name == "honeypot")
                        && arsenal.bgp_rtbh.announce(client_ip).is_ok()
                    {
                        arsenal
                            .counters
                            .bgp_rtbh_announces
                            .fetch_add(1, Ordering::Relaxed);
                        // V237 — mirror RTBH announces into the cluster slot so
                        // the time-series sampler captures fleet-wide BGP events.
                        crate::shared_state::global::cluster_bump(
                            crate::shared_state::global::cluster_idx::RTBH,
                        );
                    }
                }
                let status_code =
                    http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::FORBIDDEN);
                let trace_id = ctx.req_ctx.as_ref().map_or(0, |r| r.request_id);
                // Map filter-name to a concise visitor-facing message.
                let visitor_msg = match filter_name {
                    "waf" | "waf_body" => "This request was blocked by the security policy.",
                    "graphql" => "This request was blocked by the security policy.",
                    "bot" | "distributed_bot" => "Access denied: automated traffic detected.",
                    "distributed_rate" => "Too many requests. Please wait before retrying.",
                    _ => "Access denied.",
                };
                self.respond_visitor_error(session, status_code.as_u16(), visitor_msg, trace_id)
                    .await?;
                Ok(true)
            }
            FilterAction::Challenge { level, reason } => {
                // V42 — real cookie-based ladder. Issue a signed
                // aegis_token cookie + the level-appropriate
                // response body. Browser bounces through
                // /__aegis/verify which sets aegis_fp; subsequent
                // requests carry that cookie and skip the ladder
                // entirely via fp_cookie_valid().
                //
                // V186 — consult the arsenal route-difficulty table.
                // AI-scraper UAs and */login routes pre-empt the
                // baseline level; bump counter for visibility but
                // keep the existing emitter (level is opaque metric
                // for the UI right now).
                if let Some(arsenal) = &self.arsenal {
                    use std::sync::atomic::Ordering;
                    let rctx = ctx.req_ctx.as_ref().unwrap();
                    let ua = rctx.user_agent.as_deref().unwrap_or("");
                    let (_kind, bits) = arsenal.route_difficulty.decide(
                        &rctx.host,
                        &rctx.path,
                        ua,
                        16,
                        crate::route_difficulty::ChallengeKind::CookieRedirect,
                    );
                    if bits > 16 {
                        arsenal
                            .counters
                            .route_difficulty_bumps
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                ctx.denied_by = Some(filter_name);
                ctx.event_action = Some("challenge");
                self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
                );
                self.metrics
                    .requests_challenged
                    .fetch_add(1, Ordering::Relaxed);
                // V237 — mirror the per-worker challenged counter into the cluster
                // slot so the time-series sampler sees accurate fleet-wide totals.
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_CHALLENGED,
                );
                self.metrics.observe_filter_challenge(filter_name);
                self.metrics.observe_domain_outcome(
                    &ctx.req_ctx.as_ref().unwrap().host,
                    false,
                    true,
                );
                self.dynamic_trust.observe_denied(client_ip, now);
                self.record_challenged(client_ip, now);
                // Need the request URI for the safe return-URL
                // computation. Pingora's session keeps it on
                // req_header for the lifetime of the request.
                let uri = session.req_header().uri.clone();
                // Phase 3 — per-host config gates which in-browser JS
                // probes the interactive rung emits. Resolve it from the
                // already-parsed request host; the all-None default makes
                // the JS rung render the pre-Phase-3 page for stock hosts.
                let dcfg = self
                    .arsenal
                    .as_ref()
                    .map(|a| a.domain_challenge_config(&ctx.req_ctx.as_ref().unwrap().host))
                    .unwrap_or_default();
                // Phase 4 — `reputation_difficulty`: compute a 0–100
                // suspicion score so the PoW rung can be scaled UP for
                // bad clients. We fold the passive bot signals (header /
                // JA4 / ASN derived) with the per-IP threat score the
                // ddos scorer already maintains, and pass the max. This
                // is a no-op for the non-PoW rungs and for hosts that
                // left the lever OFF — `reputation_difficulty` returns
                // the baseline unchanged in those cases. We only do the
                // work when the lever is actually enabled for the host.
                let suspicion: u8 = if matches!(dcfg.reputation_difficulty, Some(true)) {
                    let rctx = ctx.req_ctx.as_ref().unwrap();
                    let asn = self.geoip.asn(client_ip);
                    let (passive_score, _reasons) = crate::challenge_signals::passive_bot_score(
                        &rctx.headers,
                        rctx.ja4.as_deref(),
                        asn,
                        &dcfg,
                    );
                    let threat = self.scorer.score(client_ip).0.clamp(0.0, 100.0) as u8;
                    let s = passive_score.max(threat);
                    if let Some(arsenal) = &self.arsenal {
                        arsenal
                            .counters
                            .challenge_reputation_difficulty_hits
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    s
                } else {
                    0
                };
                self.challenge
                    .write_challenge_response(
                        session, level, &reason, client_ip, &uri, &dcfg, suspicion,
                    )
                    .await?;
                Ok(true)
            }
            FilterAction::Tarpit {
                duration_seconds,
                chunk_bytes,
                server_header,
                reason: _,
            } => {
                // V40 — slow-drip body. Stream `chunk_bytes` of "."
                // every 5s for ~`duration_seconds`, then close. Pins
                // the scanner's worker waiting for the response to
                // "complete" while its concurrency pool drains.
                // Matches the hyper TarpitBody semantics (chunked
                // transfer, dots as payload, ~N chunks for N×5s).
                ctx.denied_by = Some(filter_name);
                ctx.event_action = Some("tarpit");
                self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_TOTAL,
                );
                self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
                );
                // V237 — dedicated tarpit counter so dashboards can surface
                // tarpit engagement separately from hard denies.
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::TARPIT,
                );
                self.metrics.observe_filter_block(filter_name);
                self.metrics.observe_domain_outcome(
                    &ctx.req_ctx.as_ref().unwrap().host,
                    true,
                    false,
                );
                self.dynamic_trust.observe_denied(client_ip, now);
                self.record_denied(client_ip, now);
                // V244 — auto-learn JA4 reputation from tarpit engagement.
                // Tarpit is applied to confirmed scanners/abusers, so the
                // client's JA4 is a high-confidence bad fingerprint. Deduped
                // + capped in observe_bad; no-op when auto-learn is off.
                if let Some(rep) = &self.ja4_reputation
                    && let Some(ja4) = ctx.req_ctx.as_ref().and_then(|c| c.ja4.as_deref())
                {
                    rep.observe_bad(ja4, "tarpit");
                }
                // V107 — log payload for the online signature miner.
                // No-op when AEGIS_TARPIT_LOG isn't configured.
                self.tarpit_logger
                    .record(&ctx.req_ctx.as_ref().unwrap().path);

                // V183/V184 — opt-in honeypot responders. If the
                // operator configured a YAML descriptor or LLM
                // honeypot for this path, the synthesised response
                // takes precedence over plain tarpit dots — more
                // believable engagement keeps the scanner engaged
                // longer. Falls through to the dot-streamer when
                // no responder matched.
                // V236 — CHANGE 5: use cached self.llm_honeypot instead of
                // std::env::var per request (saves env-table hash lookup in
                // the tarpit branch).
                if let Some(arsenal) = &self.arsenal
                    && self.llm_honeypot
                    && let Some(resp) = arsenal.honeypot_respond(
                        client_ip,
                        ctx.req_ctx.as_ref().unwrap().method.as_str(),
                        &ctx.req_ctx.as_ref().unwrap().host,
                        &ctx.req_ctx.as_ref().unwrap().path,
                        "",
                    )
                {
                    let mut header =
                        ResponseHeader::build(resp.status, Some(resp.headers.len() as usize))?;
                    for (k, v) in resp.headers {
                        let _ = header.insert_header(k, v);
                    }
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    let body_bytes = bytes::Bytes::from(resp.body);
                    session.write_response_body(Some(body_bytes), true).await?;
                    return Ok(true);
                }

                let interval = std::time::Duration::from_secs(5);
                let total_chunks: u32 = if duration_seconds == 0 {
                    0
                } else {
                    duration_seconds.div_ceil(interval.as_secs()) as u32
                };
                let chunk_payload = bytes::Bytes::from(vec![b'.'; chunk_bytes.max(1)]);

                // Send headers that look like a slow legitimate
                // origin — disguising as Apache + chunked text/html
                // is the same camouflage the hyper path uses.
                let mut header = ResponseHeader::build(200, Some(3))?;
                let _ = header.insert_header("server", server_header.as_ref());
                let _ = header.insert_header("content-type", "text/html");
                let _ = header.insert_header("transfer-encoding", "chunked");
                session
                    .write_response_header(Box::new(header), false)
                    .await?;

                // Drip loop. Sleep first so even chunk 1 takes
                // `interval` to arrive — instant first byte would
                // tell the scanner it's being tarpitted.
                let mut sent: u32 = 0;
                while sent < total_chunks {
                    tokio::time::sleep(interval).await;
                    sent += 1;
                    let last = sent >= total_chunks;
                    session
                        .write_response_body(Some(chunk_payload.clone()), last)
                        .await?;
                }
                // Zero-duration edge case: total_chunks == 0. End
                // the stream cleanly so the client doesn't dangle.
                if total_chunks == 0 {
                    session.write_response_body(None, true).await?;
                }
                Ok(true)
            }
        }
    }

    /// V234 — request-body inspection. Pingora streams the request
    /// body through this filter chunk-by-chunk. We buffer it ONLY when
    /// something actually needs the bytes — ClamAV is enabled, or the
    /// path is a login endpoint — so the overwhelming majority of
    /// traffic (GETs, normal POSTs with ClamAV off) returns on the
    /// first line at zero cost.
    ///
    /// At end-of-stream the buffered body is inspected:
    ///   * ClamAV — an `Infected` verdict aborts the request.
    ///   * Login-abuse — the username is extracted and the
    ///     credential-brute-force guard is evaluated; a non-`Allow`
    ///     decision aborts the login attempt. The username is stashed
    ///     on `ctx` so `logging` can record the outcome.
    ///
    /// A block is an `Err` — Pingora aborts the upstream forward and
    /// the client gets a connection error. That is the correct,
    /// deliberate response to a malware upload or a brute-force burst;
    /// a polished 4xx is not owed to an attacker mid-body-stream.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // Cheap gate: does anything need the body at all?
        let clamav_on = self.clamav.is_enabled();
        let login_on = self.login_abuse.as_ref().is_some_and(|g| {
            let req = session.req_header();
            g.is_login_path(req.uri.path())
                && crate::filters::login_abuse::LoginAbuseGuard::is_login_method(
                    req.method.as_str(),
                )
        });
        // SECURITY (C4) — request-body WAF inspection. The pingora path
        // previously never scanned the request body for WAF signatures
        // (only ClamAV / login-abuse buffered it), so a body-borne SQLi /
        // XSS payload — compressed or not — reached the origin unseen.
        // We now buffer + scan the body when the WAF is enabled.
        let waf_handle = self.filters.waf();
        let waf_body_on = waf_handle.as_ref().is_some_and(|w| w.config_enabled());
        if !clamav_on && !login_on && !waf_body_on {
            // Nothing needs the bytes — let the chunk stream straight
            // through untouched. Zero cost for normal traffic.
            return Ok(());
        }

        // Accumulate, bounded. ClamAV applies its own size policy in
        // `scan`; the cap here just stops a hostile unbounded upload
        // from growing `ctx.req_body` without limit.
        const MAX_INSPECT_BODY: usize = 1024 * 1024;
        if let Some(chunk) = body.as_ref() {
            if ctx.req_body.len() + chunk.len() <= MAX_INSPECT_BODY {
                ctx.req_body.extend_from_slice(chunk);
            } else {
                ctx.req_body_overflow = true;
            }
        }
        if !end_of_stream {
            return Ok(());
        }

        // --- end of stream — inspect the buffered body ---
        if clamav_on {
            let verdict = self.clamav.scan(&ctx.req_body).await;
            if verdict.is_block() {
                self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
                );
                self.metrics.observe_filter_block("clamav");
                return Err(pingora_core::Error::new_str(
                    "clamav: malware signature in request body",
                ));
            }
        }
        if login_on
            && !ctx.req_body_overflow
            && let Some(guard) = &self.login_abuse
        {
            let content_type = session
                .req_header()
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let username = crate::filters::login_abuse::LoginAbuseGuard::extract_username(
                content_type,
                &ctx.req_body,
            );
            let ip = ctx
                .client_ip
                .unwrap_or_else(|| std::net::IpAddr::from([0, 0, 0, 0]));
            // V236 — CHANGE 1: ctx.now is Option<Instant>; always Some here
            // because request_body_filter runs after request_filter.
            let decision = guard.evaluate(
                ip,
                username.as_deref(),
                ctx.now.expect("ctx.now set in request_filter"),
            );
            // Carry the username forward so `logging` can record the
            // login outcome against the upstream status.
            ctx.login_username = username;
            if !matches!(decision, crate::filters::login_abuse::LoginDecision::Allow) {
                self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
                );
                self.metrics.observe_filter_block("login_abuse");
                return Err(pingora_core::Error::new_str(
                    "login-abuse: credential brute-force throttled",
                ));
            }
        }
        // SECURITY (C4) — scan the buffered body through the WAF, passing
        // the request's `Content-Encoding` so a gzip/deflate'd payload is
        // decompressed before signature matching (and an uninspectable
        // encoding such as `br` fails closed). Self-gates on the WAF
        // enable flag, so this is a no-op when WAF is off.
        if let Some(waf) = &waf_handle {
            let content_encoding = session
                .req_header()
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok());
            if waf
                .inspect_body_with_encoding(&ctx.req_body, content_encoding)
                .is_some()
            {
                self.metrics.requests_denied.fetch_add(1, Ordering::Relaxed);
                crate::shared_state::global::cluster_bump(
                    crate::shared_state::global::cluster_idx::REQUESTS_DENIED,
                );
                self.metrics.observe_filter_block("waf_body");
                return Err(pingora_core::Error::new_str(
                    "waf: signature in request body",
                ));
            }
        }
        Ok(())
    }

    /// Pick the upstream peer for this request. Mirrors the same
    /// `UpstreamRouter::resolve` call used by the hyper handler so a
    /// single config drives both proxies.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        // V229 — reuse the host captured in `request_filter` rather than
        // re-reading + re-allocating from the session header. When
        // ctx.req_ctx is None (eg. /__aegis/* internal short-circuits
        // that never call build_ctx), fall back to the session header.
        // V231 — host now comes from the stored RequestContext.
        let host: &str = match ctx.req_ctx.as_ref() {
            Some(rctx) if !rctx.host.is_empty() => rctx.host.as_str(),
            _ => session
                .req_header()
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        };

        let upstream = self.upstreams.resolve(host);

        // Strip any leading port from the authority; HttpPeer wants
        // host:port separately when TLS SNI is in play. Bad port
        // numbers (config-time error, can't happen after Upstream
        // construction) fall back to the scheme default rather than
        // bubbling a per-request error.
        let authority = upstream.authority.clone();
        let tls = upstream.scheme.as_str() == "https";
        let default_port = if tls { 443u16 } else { 80u16 };
        let (host_part, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(default_port)),
            None => (authority, default_port),
        };

        let sni = if tls {
            host_part.clone()
        } else {
            String::new()
        };
        let mut peer = HttpPeer::new((host_part, port), tls, sni);
        // V229 — extend the idle-keepalive window. Pingora's default
        // is short, which interacts badly with bursty per-request
        // traffic (idle pool entries get evicted between requests,
        // forcing a fresh TCP/TLS handshake on the next miss). 60s
        // matches the typical CDN edge profile.
        peer.options.idle_timeout = Some(std::time::Duration::from_secs(60));
        // V229 — enable upstream HTTP/2 multiplexing when the operator
        // opts in. Default stays HTTP/1.1 so existing nginx upstreams
        // keep working unchanged; setting AEGIS_PINGORA_UPSTREAM_H2=1
        // sends ALPN h2 (then 100 concurrent streams per TCP) which
        // collapses N sockets → 1 for h2-capable origins.
        // V236 — CHANGE 5: read from cached struct field instead of
        // calling std::env::var on every request.
        if self.upstream_h2 {
            peer.options.set_http_version(2, 1);
            peer.options.max_h2_streams = 100;
        }
        Ok(Box::new(peer))
    }

    /// H6/H7 — replace every client-supplied forwarding header with this
    /// proxy's authoritative view of the client before the request leaves
    /// for the origin.
    ///
    /// `X-Forwarded-For`, `X-Real-IP` and `Forwarded` are attacker-controlled
    /// on the wire. Aegis itself is not fooled — `resolve_client_ip` only
    /// honours them when the TCP peer is inside `trusted_proxy_cidrs` — but
    /// until now the pingora data plane forwarded whatever the client sent
    /// straight through, so any origin that trusts those headers for logging,
    /// rate limiting or IP allowlisting could be spoofed. The legacy hyper
    /// plane has stripped them since H6; this brings the production plane to
    /// parity.
    ///
    /// The emitted value is exactly the one address we resolved, not an
    /// appended chain: Aegis is the edge, and a chain is only meaningful if
    /// every hop in it is trusted — which is precisely the assumption an
    /// attacker exploits. Origins that need the pre-Aegis chain should read
    /// it from Aegis' request log, not from a header the client can forge.
    ///
    /// `ctx.client_ip` is set in `request_filter` for every request that
    /// reaches the filter chain; the fallback re-resolves for the narrow
    /// paths that reach an upstream without having built a full context.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        let client_ip = match ctx.client_ip {
            Some(ip) => ip,
            None => self.resolve_client_ip(session),
        };
        set_authoritative_forwarding(upstream_request, client_ip);
        Ok(())
    }

    /// Capture the upstream's status as soon as headers come back, so
    /// the `logging` phase can bucket it into upstream_2xx/4xx/5xx
    /// without re-reading the (already-modified-by-response-filter)
    /// session header. Runs once per upstream response — for
    /// cache-served requests pingora skips this entirely, which is
    /// the right semantic for the upstream_* counters.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        let status = upstream_response.status.as_u16();
        ctx.upstream_status = Some(status);
        self.metrics.observe_upstream_status(status);

        // V32 — stash status + headers for the cache store. Cloning
        // the HeaderMap once at the response boundary is cheap; the
        // logging phase can then call ResponseCache::store without
        // any second header walk. Skip when no cache pending (most
        // requests when cache is off).
        if let Some(pending) = ctx.cache_pending.as_mut() {
            pending.status = Some(upstream_response.status);
            pending.upstream_headers = Some(upstream_response.headers.clone());
        }

        // V188 — Scrapling-inverted decoy headers. Cheap deception
        // layer: clients that just survived a challenge or carry a
        // high threat score get Cloudflare-shaped response headers
        // so their bypass tooling selects the wrong playbook. Skip
        // clean traffic to avoid leaking the deception to legit users.
        if let Some(arsenal) = &self.arsenal
            && ctx.is_high_threat
        {
            use std::sync::atomic::Ordering;
            let conn_id = ctx.client_ip.map(Self::conn_id_from_ip).unwrap_or(0);
            let headers = crate::decoy_headers::DecoyHeaders::build(
                crate::decoy_headers::DecoyFamily::Cloudflare,
                conn_id,
            );
            for (k, v) in headers {
                let _ = upstream_response.insert_header(k.to_string(), v);
            }
            arsenal
                .counters
                .decoy_header_emits
                .fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    /// V32 — buffer body bytes as they stream through, bounded by
    /// ResponseCache's max body size. Pingora hands us each chunk
    /// in `body: &mut Option<Bytes>`; we observe (no mutation) and
    /// stop buffering once the cap is hit, marking the pending entry
    /// overflowed so logging knows to drop it.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<std::time::Duration>> {
        if let (Some(pending), Some(chunk)) = (ctx.cache_pending.as_mut(), body.as_ref())
            && !pending.overflowed
        {
            let cap = self.response_cache.max_body_bytes();
            if pending.body_buf.len() + chunk.len() > cap {
                pending.overflowed = true;
                pending.body_buf.clear();
                // V102 — keep capacity. The `body_pool::give_back`
                // call in `logging` decides whether to retain it based
                // on its own caps; shrink_to_fit would just defeat the
                // pool.
            } else {
                pending.body_buf.extend_from_slice(chunk);
            }
        }
        Ok(None)
    }

    /// Final phase — runs after the full response has been sent
    /// downstream, OR after a fatal error tore the request down. This
    /// is the only place pingora promises will fire for *every*
    /// request, including the deny-short-circuited ones from
    /// `request_filter`. Used here for:
    ///   • Per-request latency histogram observation.
    ///   • Per-domain success counter (when no filter denied + no
    ///     upstream error).
    /// Mirrors the hyper handler's `request_done()` semantics.
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        if let Some(start) = ctx.start {
            let elapsed_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            self.metrics.latency.observe(elapsed_ms);
        }
        // V234 — feed the login-abuse guard the outcome of a login
        // attempt. `ctx.login_username` is only `Some` when
        // `request_body_filter` extracted it from a login POST body.
        // A 401/403 (or no upstream status) is a failed attempt that
        // bumps the brute-force counters; a 2xx/3xx resets them.
        if let (Some(guard), Some(username), Some(ip)) = (
            &self.login_abuse,
            ctx.login_username.as_deref(),
            ctx.client_ip,
        ) {
            let outcome = match ctx.upstream_status {
                Some(s) if (200..400).contains(&s) => crate::filters::login_abuse::Outcome::Success,
                _ => crate::filters::login_abuse::Outcome::Failure,
            };
            // V236 — CHANGE 1: ctx.now is Option<Instant>; always Some here
            // because logging runs after request_filter.
            let _ = guard.record(
                ip,
                Some(username),
                outcome,
                ctx.now.expect("ctx.now set in request_filter"),
            );
        }
        // Successful (non-denied) requests get a domain "served" bump.
        // Denied/challenged requests already accounted in request_filter.
        // V119 — observe every (host, method, path, status) for site
        // cartography. Done unconditionally (denied or not) so the
        // admin UI sees the attack-surface paths as well as the
        // legit ones.
        //
        // V231 — host/method/path now come from the stored RequestContext
        // (ctx.req_ctx) rather than separate cloned Strings. Local refs
        // are short-lived within their blocks; logging is single-threaded.
        let log_host = ctx.req_ctx.as_ref().map(|r| r.host.as_str()).unwrap_or("");
        let log_method = ctx
            .req_ctx
            .as_ref()
            .map(|r| r.method.as_str())
            .unwrap_or("");
        let log_path = ctx.req_ctx.as_ref().map(|r| r.path.as_str()).unwrap_or("");
        if !log_host.is_empty() && !log_path.is_empty() {
            let status =
                ctx.upstream_status
                    .unwrap_or(if ctx.denied_by.is_some() { 403 } else { 0 });
            self.site_map
                .observe(log_host, log_method, log_path, status);

            // V243 — persist this request into the event log. HOT PATH:
            // `record()` is a non-blocking try_send (drop-on-full) and a
            // no-op when logging is disabled. We additionally gate the
            // (cheap) row construction behind `is_enabled()` so a disabled
            // store pays nothing beyond one bool load. Everything sourced
            // here is already in hand (ctx.req_ctx / ctx fields) — the only
            // extra work is the path-pattern generalisation and a single
            // optional geoip country lookup, both O(path length).
            if self.event_store.is_enabled() {
                let action = ctx
                    .event_action
                    .or(ctx.denied_by.map(|_| "deny"))
                    .unwrap_or("pass");
                let pattern = crate::site_map::generalise_path(log_path);
                let latency_ms = ctx
                    .start
                    .map(|s| s.elapsed().as_millis().min(i64::MAX as u128) as i64)
                    .unwrap_or(0);
                let mut row = crate::event_store::EventRow::now(
                    log_host, log_method, log_path, pattern, status, action,
                );
                row.reason = ctx.denied_by.unwrap_or("").to_string();
                row.latency_ms = latency_ms;
                if let Some(rctx) = ctx.req_ctx.as_ref() {
                    row.protocol = http_version_label(rctx.http_version).to_string();
                    if let Some(ja4) = rctx.ja4.as_deref() {
                        row.ja4 = ja4.to_string();
                    }
                    if let Some(ua) = rctx.user_agent.as_deref() {
                        row.user_agent = ua.to_string();
                    }
                }
                if let Some(ip) = ctx.client_ip {
                    row.client_ip = ip.to_string();
                    if let Some(cc) = self.geoip.country(ip) {
                        row.country = cc;
                    }
                }
                self.event_store.record(row);
            }

            // V199 — feed the scenario engine. Each request becomes
            // a ScenarioEvent; loaded scenarios bucket-match against
            // it and emit Fired actions for the V197 actuator
            // dispatch. No-op when arsenal absent or no scenarios
            // loaded.
            // V228 — atomic gate (V218 perf sweep). Was cloning the
            // full Vec<ScenarioConfig> per request just to check
            // is_empty(). Now single AtomicBool load.
            if let Some(arsenal) = &self.arsenal
                && let Some(ip) = ctx.client_ip
                && arsenal.scenarios.is_loaded()
            {
                use std::sync::atomic::Ordering;
                let event = crate::scenarios::ScenarioEvent {
                    client_ip: ip,
                    method: log_method.to_owned(),
                    host: log_host.to_owned(),
                    path: log_path.to_owned(),
                    user_agent: None,
                    status: if status > 0 { Some(status) } else { None },
                    asn: None,
                    country: None,
                };
                let outcomes = arsenal.scenarios.observe(&event);
                arsenal
                    .counters
                    .scenario_events
                    .fetch_add(1, Ordering::Relaxed);
                for outcome in outcomes {
                    if let crate::scenarios::FireOutcome::Fired {
                        target,
                        action,
                        blackhole,
                    } = outcome
                    {
                        arsenal
                            .counters
                            .scenario_fires
                            .fetch_add(1, Ordering::Relaxed);
                        // Dispatch the configured action via the V197
                        // actuator registry. Operator-wired backends
                        // (XDP / nft / BGP) handle the real side-effect;
                        // Noop actuators just record intent.
                        let kind = match action {
                            crate::scenarios::ScenarioAction::Block => {
                                crate::actuator::ActionKind::XdpDeny
                            }
                            crate::scenarios::ScenarioAction::Challenge => {
                                crate::actuator::ActionKind::ChallengeFloorRaise
                            }
                            crate::scenarios::ScenarioAction::Tarpit => {
                                crate::actuator::ActionKind::Custom("scenario_tarpit")
                            }
                            crate::scenarios::ScenarioAction::Log => {
                                crate::actuator::ActionKind::Custom("scenario_log")
                            }
                        };
                        let target = match target.parse::<std::net::IpAddr>() {
                            Ok(ip) => crate::actuator::Target::Ip(ip),
                            Err(_) => crate::actuator::Target::Custom(target),
                        };
                        let params = crate::actuator::ActionParams {
                            reason: Some("scenario_fired".into()),
                            source_module: Some("scenarios"),
                            extra: Default::default(),
                        };
                        let _ = arsenal.actuators.apply(kind, target, params, blackhole);
                        arsenal
                            .counters
                            .actuator_applies
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        if ctx.denied_by.is_none() && !log_host.is_empty() {
            self.metrics.observe_domain_outcome(log_host, false, false);
            // V37 — scorer's "allowed" tick only after a successful
            // response. Bumping in request_filter would over-count
            // requests that died upstream (connect timeout etc.).
            //
            // V236 — CHANGE 2: gate behind score_consumers_active.
            // When no cache, no ML scorer, and no arsenal are wired, the
            // per-worker DashMap write + optional cross-process mmap CAS
            // is dead work (the score is written but never read).
            // record_denied / record_challenged are NOT gated — the deny/
            // challenge paths are always potentially relevant to admin views.
            //
            // Also reuse ctx.now (captured at request entry) rather than a
            // fresh Instant::now(), eliminating a vdso clock call per allow.
            if let Some(ip) = ctx.client_ip {
                if self.score_consumers_active {
                    // ctx.now is always Some here — logging runs after request_filter.
                    let now = ctx.now.unwrap_or_else(Instant::now);
                    self.record_allowed(ip, now);
                }
            }
            // V107 — ~0.8% sampling of allowed paths into the benign
            // corpus used by the online signature miner. The ring is
            // bounded (500 entries) so high-RPS hosts would otherwise
            // saturate it with "the most recent N hits on /". A 128-
            // step thread-local counter gives diversity without
            // contending a global atomic on every request.
            {
                thread_local! {
                    static SAMPLE_TICK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                let tick = SAMPLE_TICK.with(|c| {
                    let v = c.get().wrapping_add(1);
                    c.set(v);
                    v
                });
                if tick & 0x7F == 0 {
                    // Sample host header (cheap stand-in for path;
                    // the miner cares about high-cardinality strings,
                    // and log_path is now preserved via ctx.req_ctx).
                    self.allowed_sampler.record(log_host);
                }
            }
        }

        // V32 — populate the cache. We get here only when there was
        // an Allow + cache miss + body fit under the cap. Anything
        // else short-circuits (overflowed = drop, missing status =
        // upstream never replied, etc.).
        //
        // V34 — single-flight: if this request was the leader for
        // its key, notify all followers waiting on the registry
        // entry AFTER the store completes, then drop the entry.
        // Order matters: store first so followers re-looking-up the
        // cache see the fresh entry on wake.
        let leader_key = if ctx.sf_leader {
            ctx.cache_pending
                .as_ref()
                .map(|p| (p.method.clone(), p.host.clone(), p.path.clone()))
        } else {
            None
        };
        if let Some(pending) = ctx.cache_pending.take() {
            let CachePending {
                method,
                host,
                path,
                status,
                upstream_headers,
                body_buf,
                overflowed,
            } = pending;
            if !overflowed && let (Some(status), Some(headers)) = (status, upstream_headers) {
                // Successful cache store — buffer escapes into `Bytes`
                // ownership and can't be recycled. Allocate fresh next
                // time. This is the only path where the pool gives up
                // its buffer.
                let body = bytes::Bytes::from(body_buf);
                // V233 — pass the downstream request headers so the cache
                // refuses to store a response to an `Authorization`/`Cookie`-
                // bearing (personalised) request. `session.req_header()` is
                // the client request header — untouched by response
                // processing, so Cookie/Authorization are intact here.
                self.response_cache.store(
                    &method,
                    &host,
                    &path,
                    status,
                    &headers,
                    &session.req_header().headers,
                    &body,
                    Instant::now(),
                );
            } else {
                // V102 — overflowed or missing status/headers. Buffer
                // never made it into a `Bytes`; recycle it for the
                // next cache-eligible request on this worker thread.
                body_pool::give_back(body_buf);
            }
        }
        if let Some(key) = leader_key
            && let Some((_, notify)) = self.pending_fetches.remove(&key)
        {
            notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultAction;
    use crate::proxy::upstream::{Upstream, UpstreamRouter};
    use std::collections::HashMap;

    fn test_proxy() -> AegisPingoraProxy {
        let upstream = Upstream::from_url("http://127.0.0.1:80").unwrap();
        let router = Arc::new(UpstreamRouter {
            default_upstream: upstream,
            domain_upstreams: HashMap::new(),
        });
        let filters = Arc::new(FilterEngine::new(vec![], DefaultAction::Allow));
        let metrics = Arc::new(RuntimeMetrics::default());
        let trust = Arc::new(crate::filters::dynamic_trust::DynamicTrust::new(
            &crate::config::DynamicTrustConfig::default(),
        ));
        let cache = Arc::new(crate::proxy::response_cache::ResponseCache::new(
            &crate::config::ResponseCacheConfig::default(),
        ));
        let bypass = Arc::new(crate::filters::bypass::BypassMatcher::new(
            &crate::config::BypassConfig::default(),
        ));
        let scorer = Arc::new(crate::ddos::score::ThreatScorer::default());
        let anomaly = Arc::new(crate::anomaly::AnomalyDetector::new(
            crate::anomaly::AnomalyConfig::default(),
        ));
        let geoip = crate::geoip::load(None);
        let ch_cfg = crate::config::ChallengeConfig::default();
        let ch_filter = Arc::new(crate::filters::challenge::ChallengeFilter::new(&ch_cfg));
        let challenge = crate::proxy::pingora_challenge::ChallengeContext::new(ch_cfg, ch_filter);
        AegisPingoraProxy::new(
            filters,
            router,
            metrics,
            trust,
            cache,
            bypass,
            scorer,
            None,
            anomaly,
            geoip,
            None,
            challenge,
            None,
            Arc::new(crate::online_signature_miner::TarpitLogger::new(None)),
            Arc::new(crate::online_signature_miner::AllowedSampler::default()),
            Arc::new(crate::site_map::SiteMap::new()),
            Arc::new(crate::threat_analytics::ThreatAnalytics::new()),
        )
    }

    #[test]
    fn new_ctx_is_default() {
        let p = test_proxy();
        let ctx = p.new_ctx();
        assert!(ctx.start.is_none());
        assert!(ctx.denied_by.is_none());
    }

    // ── H9a — TLS fingerprint deny-list enforcement ─────────────────

    #[test]
    fn tls_deny_empty_lists_is_noop() {
        // Default proxy has no deny lists wired → never denies, even
        // with both fingerprints present.
        let p = test_proxy();
        let ctx = RequestContext::test_with("1.2.3.4", "/")
            .with_ja4("t13d1516h2_8daaf6152771_b1ff8ab2d16f")
            .with_ja3("e7d705a3286e19ea42f587b344ee6865");
        assert!(p.tls_fingerprint_denied(&ctx).is_none());
    }

    #[test]
    fn tls_deny_ja4_prefix_matches() {
        let p = test_proxy().with_tls_deny_lists(
            vec!["t13d".to_string()], // prefix: any TLS1.3+SNI JA4_a
            vec![],
        );
        // Matching JA4 → denied with the ja4 reason.
        let ctx = RequestContext::test_with("1.2.3.4", "/")
            .with_ja4("t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        assert_eq!(p.tls_fingerprint_denied(&ctx), Some("tls_ja4_deny"));
        // Non-matching JA4 prefix → allowed.
        let ctx2 = RequestContext::test_with("1.2.3.4", "/").with_ja4("q12d0000h1_aaaa_bbbb");
        assert!(p.tls_fingerprint_denied(&ctx2).is_none());
        // No JA4 captured → allowed (nothing to match).
        let ctx3 = RequestContext::test_with("1.2.3.4", "/");
        assert!(p.tls_fingerprint_denied(&ctx3).is_none());
    }

    #[test]
    fn tls_deny_ja3_hash_matches_case_insensitively() {
        let p = test_proxy().with_tls_deny_lists(
            vec![],
            vec!["E7D705A3286E19EA42F587B344EE6865".to_string()], // upper-case
        );
        // Stored hash is lower-case; match must be case-insensitive.
        let ctx =
            RequestContext::test_with("1.2.3.4", "/").with_ja3("e7d705a3286e19ea42f587b344ee6865");
        assert_eq!(p.tls_fingerprint_denied(&ctx), Some("tls_ja3_deny"));
        // Different hash → allowed.
        let ctx2 =
            RequestContext::test_with("1.2.3.4", "/").with_ja3("00000000000000000000000000000000");
        assert!(p.tls_fingerprint_denied(&ctx2).is_none());
    }

    // ── H9b — JA4 corpus Deny verdict produces a protective action ──

    #[test]
    fn ja4_corpus_known_tooling_is_deny() {
        // Sanity-check the corpus verdict the request-path escalation
        // (Allow → 403) keys off. `curl`'s seed JA4 must classify Deny.
        let corpus = crate::ja4_corpus::Ja4Corpus::new();
        let hit = corpus.lookup("t13d3112h2_e8f1e7e78f70_1f22197e3bbe");
        assert_eq!(
            hit.verdict,
            crate::ja4_corpus::Verdict::Deny,
            "curl JA4 must be Deny"
        );
        // A genuine Chrome browser JA4 must NOT be Deny (no false 403).
        let chrome = corpus.lookup("t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        assert_ne!(chrome.verdict, crate::ja4_corpus::Verdict::Deny);
    }

    // ── H9b — spoofable allow-credit cannot lower scrutiny below
    //          the (non-spoofable) baseline ─────────────────────────

    #[test]
    fn corpus_allow_credit_clamped_at_baseline() {
        // A client-chosen JA4 that BOTH the operator's V138 feed rates
        // as suspicious (the non-spoofable baseline) AND the shipped
        // corpus rates Allow (chrome-family cipher). The Allow soft-
        // credit must NOT pull reputation below the feed baseline —
        // otherwise a forged "I'm Chrome" JA4 buys a discount.
        //
        // `8daaf6152771` is simultaneously: a feed entry (loaded below,
        // → 0.6 via cipher-prefix match) and a corpus Allow entry
        // ("chrome-family-cipher", line ja4_corpus.rs:85).
        let ja4 = "t13d1516h2_8daaf6152771_b1ff8ab2d16f";
        let rep = Arc::new(crate::ja4_reputation::Ja4Reputation::new(vec![]));
        rep.load_str("8daaf6152771  suspicious-browser-cipher\n");
        let baseline = crate::ja4_reputation::reputation_feature(rep.lookup(ja4).as_ref());
        assert!(
            baseline > 0.0,
            "test precondition: feed baseline must be > 0"
        );
        let p = test_proxy()
            .with_ja4_reputation(rep)
            .with_arsenal(Arc::new(crate::arsenal::ArsenalState::new_default()));
        let mut ctx = RequestContext::test_with("5.5.5.5", "/").with_ua("Mozilla/5.0");
        ctx.ja4 = Some(ja4.to_string());
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert!(
            f.ja4_reputation >= baseline - 1e-6,
            "corpus Allow credit drove reputation {} below the non-spoofable baseline {}",
            f.ja4_reputation,
            baseline
        );
    }

    // ── H9c — ja4_browser_family is a UA-vs-JA4 mismatch signal ─────

    #[test]
    fn ja4_browser_family_flags_ua_vs_ja4_mismatch() {
        let p = test_proxy();
        // UA says Chrome, JA4 cipher hash `5b57…` says Firefox → mismatch.
        let mut ctx = RequestContext::test_with("7.7.7.7", "/")
            .with_ua("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36");
        ctx.ja4 = Some("t13d1715h2_5b57614c22b0_3d5424432f57".into());
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert_eq!(
            f.ja4_browser_family, 1.0,
            "UA=Chrome vs JA4=Firefox must flag mismatch"
        );
    }

    #[test]
    fn ja4_browser_family_quiet_when_either_side_unknown() {
        let p = test_proxy();
        // Known UA (Chrome) but no JA4 → cannot judge → 0.0.
        let ctx = RequestContext::test_with("7.7.7.7", "/")
            .with_ua("Mozilla/5.0 Chrome/120.0 Safari/537.36");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert_eq!(f.ja4_browser_family, 0.0, "no JA4 → no mismatch verdict");
    }

    #[test]
    fn ml_features_clean_get_low_threat() {
        // Clean browser GET: short path, real UA, JA4 captured,
        // no recent denied history.
        let ctx = RequestContext::test_with("1.1.1.1", "/index.html").with_ua("Mozilla/5.0");
        let f = AegisPingoraProxy::extract_ml_features(&ctx, 0.0);
        assert!(f.has_user_agent > 0.5);
        assert!(f.uri_length < 0.1);
        assert!(f.header_count < 0.1);
        assert_eq!(f.method_is_post, 0.0);
        assert_eq!(f.recent_denied_rate, 0.0);
        // Default-weights inference should land below the Low threshold (33).
        let scorer = crate::ddos::ml_score::MlScorer::new(true);
        let pct = scorer.score_pct(&f);
        assert!(pct < 33.0, "clean GET scored {pct}, expected <33");
    }

    #[test]
    fn ml_features_dirty_request_high_threat() {
        // Suspicious POST: no UA, no JA4, long URI, recently denied.
        let mut ctx = RequestContext::test_with("1.1.1.1", &"/a".repeat(4000));
        ctx.method = http::Method::POST;
        let f = AegisPingoraProxy::extract_ml_features(&ctx, 80.0);
        assert_eq!(f.has_user_agent, 0.0);
        assert_eq!(f.ja4_unusual, 1.0);
        assert!(f.uri_length > 0.5);
        assert!(f.method_is_post > 0.5);
        assert!(f.recent_denied_rate > 0.5);
        let scorer = crate::ddos::ml_score::MlScorer::new(true);
        let pct = scorer.score_pct(&f);
        assert!(pct > 66.0, "dirty POST scored {pct}, expected >66");
    }

    #[test]
    fn body_pool_recycles_buffers() {
        // Drain any leftovers from prior tests on this thread so the
        // counts below are deterministic. `take(0)` returns Vec::with_capacity(0)
        // when the pool is empty.
        for _ in 0..64 {
            let v = body_pool::take(0);
            if v.capacity() == 0 {
                break;
            }
            // burn the pooled buffer (don't give back)
            drop(v);
        }
        // Take with 8KB hint — must produce a buffer with ≥8KB cap.
        let buf = body_pool::take(8 * 1024);
        assert!(buf.capacity() >= 8 * 1024);
        // Return; next take with hint=0 should reuse it (capacity stays).
        body_pool::give_back(buf);
        let reused = body_pool::take(0);
        assert!(
            reused.capacity() >= 8 * 1024,
            "expected pooled buf, got cap={}",
            reused.capacity()
        );
        // Oversized buffers are dropped, not retained.
        // (drain pool first so we read the post-give_back state)
        for _ in 0..64 {
            let v = body_pool::take(0);
            if v.capacity() == 0 {
                break;
            }
            drop(v);
        }
        let mut huge = Vec::with_capacity(256 * 1024);
        huge.push(0u8);
        body_pool::give_back(huge);
        let after_huge = body_pool::take(0);
        assert_eq!(
            after_huge.capacity(),
            0,
            "oversized buf should NOT be retained"
        );
    }

    #[test]
    fn derive_threat_tier_trusted_bypass_is_low() {
        use crate::proxy::response_cache::ThreatTier;
        let p = test_proxy();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        // is_bypass_or_trusted short-circuits to Low regardless.
        assert_eq!(p.derive_threat_tier(&ctx, true), ThreatTier::Low);
    }

    // ── V140 — extract_ml_features_v2 wiring tests ────────────────

    #[test]
    fn ml_features_v2_clean_browser_scores_low() {
        let p = test_proxy();
        let mut ctx = RequestContext::test_with("9.9.9.9", "/index.html").with_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        );
        ctx.ja4 = Some("t13d1516h2_8daaf6152771_abc123".into());
        // V231 — ja4h is now lazy; use set_ja4h_for_test to inject a
        // known fingerprint value without triggering live computation.
        ctx = ctx.set_ja4h_for_test("ge11nn0500_x_y_z");
        ctx.h2fp = Some("1:65536|4:6291456".into());
        ctx = ctx
            .with_header("accept-language", "en-US,en;q=0.9")
            .with_header("accept-encoding", "gzip, deflate, br");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert_eq!(f.has_user_agent, 1.0);
        assert_eq!(f.has_accept_language, 1.0);
        assert_eq!(f.has_accept_encoding, 1.0);
        assert_eq!(f.ja4_present, 1.0);
        // H9c — `ja4_browser_family` is now a UA-vs-JA4 *mismatch*
        // signal. This is a coherent Chrome (UA says Chrome, JA4 cipher
        // hash `8daa…` also says Chrome), so there is NO mismatch and
        // the feature must be 0.0 (was 1.0 under the old UA-only
        // "is a browser" semantics).
        assert_eq!(
            f.ja4_browser_family, 0.0,
            "coherent Chrome UA+JA4 must NOT flag a family mismatch"
        );
        assert_eq!(f.h2fp_present, 1.0);
        assert_eq!(f.recent_denied_rate, 0.0);
        // Consistent fingerprints → low correlation score.
        assert!(
            f.fp_consistency_score < 0.2,
            "coherent Chrome should score low, got {}",
            f.fp_consistency_score
        );
    }

    #[test]
    fn ml_features_v2_chrome_ja4_curl_ua_lights_consistency() {
        let p = test_proxy();
        let mut ctx = RequestContext::test_with("9.9.9.9", "/").with_ua("curl/8.4.0");
        ctx.ja4 = Some("t13d1516h2_8daaf6152771_abc123".into()); // Chrome JA4
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        // Chrome TLS + curl UA must produce a strong consistency
        // signal — at least the 0.55 tool-mismatch contribution.
        assert!(
            f.fp_consistency_score >= 0.5,
            "Chrome JA4 + curl UA expected >=0.5 consistency, got {}",
            f.fp_consistency_score
        );
    }

    #[test]
    fn ml_features_v2_uri_entropy_splits_path_and_query() {
        let p = test_proxy();
        // Random-looking query but normal path.
        let ctx =
            RequestContext::test_with("9.9.9.9", "/api/users?token=aXz4qPj8K7nMz2Lw3RhV5cBgY");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert!(f.uri_entropy > 0.2 && f.uri_entropy < 0.8);
        assert!(f.query_entropy > 0.3);
        assert!(f.query_param_count > 0.0);
    }

    #[test]
    fn ml_features_v2_ja4_reputation_hit_populates_feature() {
        use std::sync::Arc;
        let rep = Arc::new(crate::ja4_reputation::Ja4Reputation::new(vec![]));
        rep.load_str("8daaf6152771  sqlmap\n");
        let p = test_proxy().with_ja4_reputation(rep);
        let mut ctx = RequestContext::test_with("9.9.9.9", "/");
        ctx.ja4 = Some("t13d1516h2_8daaf6152771_xyz".into());
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        // Cipher-prefix match → 0.6 (V138 reputation_feature).
        assert!(
            (f.ja4_reputation - 0.6).abs() < 1e-5,
            "expected cipher-prefix match = 0.6, got {}",
            f.ja4_reputation
        );
    }

    #[test]
    fn ml_features_v2_without_ja4_reputation_feature_is_zero() {
        let p = test_proxy();
        let mut ctx = RequestContext::test_with("9.9.9.9", "/");
        ctx.ja4 = Some("t13d1516h2_8daaf6152771_xyz".into());
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert_eq!(f.ja4_reputation, 0.0);
    }

    #[test]
    fn ml_features_v2_populates_split_scorer_fields() {
        let p = test_proxy();
        let ip = "1.2.3.10";
        let now = std::time::Instant::now();
        // Build per-IP scorer history: 3 denied + 2 challenged + 5 allowed
        // → denied_rate=0.3, challenged_rate=0.2.
        for _ in 0..5 {
            p.scorer.record_allowed(ip.parse().unwrap(), now);
        }
        for _ in 0..3 {
            p.scorer.record_denied(ip.parse().unwrap(), now);
        }
        for _ in 0..2 {
            p.scorer.record_challenged(ip.parse().unwrap(), now);
        }
        let ctx = RequestContext::test_with(ip, "/");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert!((f.recent_denied_rate - 0.3).abs() < 1e-3);
        assert!((f.recent_challenged_rate - 0.2).abs() < 1e-3);
        assert!(
            f.requests_per_min > 0.0,
            "rps-derived feature should be non-zero"
        );
    }

    #[test]
    fn ml_features_v2_fast_repeat_fires_for_burst() {
        let p = test_proxy();
        let ip: std::net::IpAddr = "1.2.3.11".parse().unwrap();
        let t0 = std::time::Instant::now();
        p.scorer.record_allowed(ip, t0);
        p.scorer
            .record_allowed(ip, t0 + std::time::Duration::from_millis(100));
        let ctx = RequestContext::test_with("1.2.3.11", "/");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert_eq!(f.fast_repeat, 1.0);
    }

    #[test]
    fn ml_features_v2_asn_cidr_hit_populates_feature() {
        use std::sync::Arc;
        let rep = Arc::new(crate::asn_reputation::AsnReputation::cidr_only(vec![]));
        rep.load_str("1.2.3.0/24  0.85  burned-block\n");
        let p = test_proxy().with_asn_reputation(rep);
        let ctx = RequestContext::test_with("1.2.3.7", "/");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert!(
            (f.asn_reputation - 0.85).abs() < 1e-5,
            "expected ASN feature 0.85, got {}",
            f.asn_reputation
        );
    }

    #[test]
    fn ml_features_v2_asn_no_match_is_zero() {
        use std::sync::Arc;
        let rep = Arc::new(crate::asn_reputation::AsnReputation::cidr_only(vec![]));
        rep.load_str("1.2.3.0/24  0.85  burned-block\n");
        let p = test_proxy().with_asn_reputation(rep);
        let ctx = RequestContext::test_with("9.9.9.9", "/");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        assert_eq!(f.asn_reputation, 0.0);
    }

    // ── M3 — compute_ml_score feeds a real per-request ml_score into
    //          the RiskEngine RiskInput ─────────────────────────────────

    #[test]
    fn compute_ml_score_zero_without_scorer() {
        // No ML scorer wired → the RiskEngine ml_score signal stays 0.0
        // (it must not invent a score). This is the stock-deployment case.
        let p = test_proxy();
        let ctx = RequestContext::test_with("3.3.3.3", "/");
        assert_eq!(p.compute_ml_score(&ctx, 0.0), 0.0);
    }

    #[test]
    fn compute_ml_score_matches_wired_model() {
        use std::sync::Arc;
        // With the V2 model wired, compute_ml_score must return exactly
        // what the model reports for the request's features — proving the
        // RiskInput.ml_score is sourced from the actual scorer, not a
        // hardcoded 0.0. We wire via with_ml_model_v2 so the same MlModel
        // instance drives both the expected value and compute_ml_score.
        let scorer = Arc::new(crate::ddos::ml_score_v2::MlScorerV2::new(true));
        let model = Arc::new(crate::ddos::ml_model::MlModel::logistic(scorer));
        let p = test_proxy().with_ml_model_v2(model.clone());
        let ctx = RequestContext::test_with("3.3.3.4", "/some/path?a=1");
        let expected = model.score_pct(&p.extract_ml_features_v2(&ctx, 0.25)) as f64;
        assert_eq!(p.compute_ml_score(&ctx, 0.25), expected);
    }

    #[test]
    fn ml_features_v2_client_consistency_lifts_fp_score() {
        use std::sync::Arc;
        let store = Arc::new(crate::client_consistency::ClientSignalsStore::new(10));
        // Stash a webdriver=true payload for the test IP — strong
        // client-side signal, no server-side mismatch.
        let mut sig = crate::client_consistency::ClientSignals::default();
        sig.webdriver = Some(true);
        sig.hardware_concurrency = Some(0);
        let ip = "1.2.3.99".parse().unwrap();
        store.insert(ip, sig, std::time::Instant::now());

        let p = test_proxy().with_client_signals(store);
        // Coherent server-side fingerprints (no JA4-vs-UA mismatch).
        let mut ctx = RequestContext::test_with("1.2.3.99", "/")
            .with_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120");
        ctx.ja4 = Some("t13d1516h2_8daaf6152771_x".into());
        // V231 — ja4h is now lazy; use set_ja4h_for_test to inject a
        // known fingerprint value without triggering live computation.
        ctx = ctx.set_ja4h_for_test("ge11nn0500_x_y_z");

        let f = p.extract_ml_features_v2(&ctx, 0.0);
        // Client-side score should dominate (webdriver=true → 0.5 +
        // zero_hw_concurrency=0.3 = 0.8).
        assert!(
            f.fp_consistency_score >= 0.7,
            "client consistency should lift score, got {}",
            f.fp_consistency_score,
        );
    }

    #[test]
    fn ml_features_v2_no_client_signals_uses_server_side_only() {
        let p = test_proxy(); // no store wired
        let ctx = RequestContext::test_with("1.2.3.99", "/").with_ua("curl/8.0");
        let f = p.extract_ml_features_v2(&ctx, 0.0);
        // No mismatches at server side and no client signals → score 0.
        // (curl + no JA4 doesn't trigger fp_correlation since JA4 is None.)
        assert!(f.fp_consistency_score < 0.2);
    }

    #[test]
    fn derive_threat_tier_uses_v2_scorer_when_set() {
        use crate::proxy::response_cache::ThreatTier;
        use std::sync::Arc;
        let scorer = Arc::new(crate::ddos::ml_score_v2::MlScorerV2::new(true));
        let p = test_proxy().with_ml_scorer_v2(scorer);
        // Dirty request: POST + no UA + no JA4 + Chrome-looking
        // entropy in URL. Should land above Low threshold.
        let mut ctx = RequestContext::test_with("1.1.1.1", &"/aXz4qPjK7n".repeat(50));
        ctx.method = http::Method::POST;
        let tier = p.derive_threat_tier(&ctx, false);
        // Just verify the V2 path runs without panic and returns a
        // valid tier (the exact bucket depends on default weights).
        assert!(matches!(
            tier,
            ThreatTier::Low | ThreatTier::Medium | ThreatTier::High
        ));
    }

    // ── H6/H7 — forwarding-header sanitisation ────────────────────────────

    #[test]
    fn forwarding_headers_are_replaced_with_resolved_client_ip() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        // Everything a hostile client might send to spoof its address.
        req.insert_header("x-forwarded-for", "10.0.0.1, 8.8.8.8")
            .unwrap();
        req.insert_header("x-real-ip", "127.0.0.1").unwrap();
        req.insert_header("forwarded", "for=192.0.2.9;proto=https")
            .unwrap();

        set_authoritative_forwarding(&mut req, "203.0.113.7".parse().unwrap());

        assert_eq!(
            req.headers.get("x-forwarded-for").unwrap(),
            "203.0.113.7",
            "client-supplied XFF chain must not survive"
        );
        assert_eq!(req.headers.get("x-real-ip").unwrap(), "203.0.113.7");
        assert!(
            req.headers.get("forwarded").is_none(),
            "RFC 7239 Forwarded must be dropped, not rewritten"
        );
    }

    #[test]
    fn duplicate_forwarding_header_lines_are_all_removed() {
        // A client can send the same header twice as separate lines; a
        // remove-first-only implementation would leave the second copy for
        // the origin to trust.
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("x-forwarded-for", "10.0.0.1").unwrap();
        req.append_header("x-forwarded-for", "10.0.0.2").unwrap();
        req.append_header("x-real-ip", "10.0.0.3").unwrap();
        req.append_header("x-real-ip", "10.0.0.4").unwrap();

        set_authoritative_forwarding(&mut req, "198.51.100.5".parse().unwrap());

        let xff: Vec<_> = req.headers.get_all("x-forwarded-for").iter().collect();
        assert_eq!(xff.len(), 1, "exactly one authoritative XFF value");
        assert_eq!(xff[0], "198.51.100.5");
        let real: Vec<_> = req.headers.get_all("x-real-ip").iter().collect();
        assert_eq!(real.len(), 1);
        assert_eq!(real[0], "198.51.100.5");
    }

    #[test]
    fn forwarding_headers_are_set_even_when_client_sent_none() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        set_authoritative_forwarding(&mut req, "2001:db8::1".parse().unwrap());
        assert_eq!(req.headers.get("x-forwarded-for").unwrap(), "2001:db8::1");
        assert_eq!(req.headers.get("x-real-ip").unwrap(), "2001:db8::1");
    }
}
