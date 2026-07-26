use crate::{
    RuntimeState,
    admin_auth::{AuditLog, TokenRegistry, required_role_for},
    config::AppConfig,
    ddos::score::ThreatScorer,
    domains,
    filters::{
        SharedFilter, adaptive::AdaptiveFilter, bot::BotFilter, challenge::ChallengeFilter,
        engine::FilterEngine, ip_acl::IpAclFilter, rate_limit::RateLimitFilter, waf::WafFilter,
    },
    metrics::RuntimeMetrics,
    proxy::{
        health::UpstreamHealth,
        http::ProxyHttpHandler,
        http3,
        upstream::{Upstream, UpstreamRouter},
    },
    shutdown::wait_for_shutdown_signal,
    state::reputation::ReputationStore,
    tls_sni::SniResolver,
    xdp,
};
use anyhow::{Context, Result};
use http_body_util::BodyExt;
use hyper::{Method, Request, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::ServerConfig as RustlsServerConfig;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{RwLock, broadcast},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Shared rebuild context used by `/admin/reload` to swap the live
/// handler and upstream health checker without restarting the process.
pub struct Reloader {
    metrics: Arc<RuntimeMetrics>,
    scorer: Arc<ThreatScorer>,
    fingerprints: Arc<crate::state::fingerprint::FingerprintCache>,
    honeypots: Arc<crate::honeypot::HoneypotStore>,
    handler: Arc<RwLock<ProxyHttpHandler>>,
    health_state: Arc<RwLock<Arc<UpstreamHealth>>>,
    xdp_handle: Arc<dyn xdp::XdpHandle>,
    xdp_deny_set: std::sync::Mutex<std::collections::HashSet<IpAddr>>,
    xdp_allow_set: std::sync::Mutex<std::collections::HashSet<IpAddr>>,
}

impl Reloader {
    pub async fn reload(&self, cfg: &AppConfig) -> Result<()> {
        let (new_handler, _rate, new_health, _bot, _challenge, _threat) = build_handler(
            cfg,
            self.metrics.clone(),
            self.scorer.clone(),
            self.fingerprints.clone(),
            self.honeypots.clone(),
            self.xdp_handle.clone(),
        )
        .await?;
        new_health.spawn_checker();
        *self.health_state.write().await = new_health;
        *self.handler.write().await = new_handler;
        self.sync_xdp_from(cfg);
        Ok(())
    }

    /// Reconcile both XDP deny and allow maps against the live config
    /// and push the rate-limit / allow_only knobs to the kernel.
    pub fn sync_xdp_from(&self, cfg: &AppConfig) {
        self.sync_xdp(&cfg.filters.ip_acl.deny);
        if let Some(xcfg) = &cfg.xdp {
            self.sync_xdp_allow(&xcfg.allow);
            let window_ns = xcfg.rate_window_ms.saturating_mul(1_000_000);
            if let Err(e) = self.xdp_handle.set_rate_config(
                window_ns,
                xcfg.rate_burst,
                xcfg.syn_burst,
                xcfg.allow_only,
            ) {
                tracing::warn!(error = %e, "xdp set_rate_config failed");
            }
        }
    }

    /// Reconcile the XDP deny BPF map with the configured deny list:
    /// removed IPs get undeny()'d, added IPs get deny_v4/v6'd. Tracks
    /// the previously applied set so we don't have to walk the kernel
    /// map each time.
    pub fn sync_xdp(&self, deny: &[String]) {
        let desired: std::collections::HashSet<IpAddr> =
            deny.iter().filter_map(|s| s.parse().ok()).collect();
        let mut prev = self.xdp_deny_set.lock().unwrap();
        let removed_count = prev.difference(&desired).count();
        for removed in prev.difference(&desired) {
            if let Err(e) = self.xdp_handle.undeny(*removed) {
                tracing::warn!(error = %e, ip = %removed, "xdp undeny failed");
            }
        }
        let added: Vec<IpAddr> = desired.difference(&prev).copied().collect();
        let n = xdp::sync_deny_list(&*self.xdp_handle, &added);
        tracing::info!(
            added = n,
            removed = removed_count,
            "xdp deny set reconciled"
        );
        *prev = desired;
    }

    /// Same shape as `sync_xdp` for the allow-list map.
    pub fn sync_xdp_allow(&self, allow: &[String]) {
        let desired: std::collections::HashSet<IpAddr> =
            allow.iter().filter_map(|s| s.parse().ok()).collect();
        let mut prev = self.xdp_allow_set.lock().unwrap();
        let removed_count = prev.difference(&desired).count();
        for removed in prev.difference(&desired) {
            if let Err(e) = self.xdp_handle.unallow(*removed) {
                tracing::warn!(error = %e, ip = %removed, "xdp unallow failed");
            }
        }
        let added: Vec<IpAddr> = desired.difference(&prev).copied().collect();
        let n = xdp::sync_allow_list(&*self.xdp_handle, &added);
        tracing::info!(
            added = n,
            removed = removed_count,
            "xdp allow set reconciled"
        );
        *prev = desired;
    }
}

pub fn build_anomaly_config(cfg: &AppConfig) -> crate::anomaly::AnomalyConfig {
    let Some(a) = cfg.anomaly.as_ref() else {
        return crate::anomaly::AnomalyConfig::default();
    };
    let level = match a.min_challenge_level.to_ascii_lowercase().as_str() {
        "headers" => crate::filters::ChallengeLevel::Headers,
        "html" => crate::filters::ChallengeLevel::Html,
        "iframe" => crate::filters::ChallengeLevel::Iframe,
        "captcha" => crate::filters::ChallengeLevel::Captcha,
        _ => crate::filters::ChallengeLevel::Javascript,
    };
    crate::anomaly::AnomalyConfig {
        enabled: a.enabled,
        window: Duration::from_secs(a.window_secs.max(1)),
        multiplier: a.multiplier.max(1.0),
        min_baseline_rps: a.min_baseline_rps.max(0.0),
        attack_duration: Duration::from_secs(a.attack_duration_secs.max(1)),
        min_challenge_level: level,
    }
}

async fn build_handler(
    cfg: &AppConfig,
    metrics: Arc<RuntimeMetrics>,
    scorer: Arc<ThreatScorer>,
    fingerprints: Arc<crate::state::fingerprint::FingerprintCache>,
    honeypots: Arc<crate::honeypot::HoneypotStore>,
    xdp_handle: Arc<dyn xdp::XdpHandle>,
) -> Result<(
    ProxyHttpHandler,
    Arc<RateLimitFilter>,
    Arc<UpstreamHealth>,
    Arc<BotFilter>,
    Arc<ChallengeFilter>,
    Arc<crate::filters::threat_intel::ThreatIntelFilter>,
)> {
    let alt_svc = cfg.tls.as_ref().and_then(|tls| {
        if !tls.h3_enabled {
            return None;
        }
        // Port advertised to clients — parse from h3_listen (or tls.listen)
        let listen = tls.h3_listen.as_deref().unwrap_or(&tls.listen);
        let port = listen
            .rsplit(':')
            .next()
            .and_then(|s| s.parse::<u16>().ok())?;
        Some(format!("h3=\":{port}\"; ma=86400"))
    });
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

    let challenge = Arc::new(ChallengeFilter::new(&cfg.filters.challenge));
    let bot = Arc::new(BotFilter::new(&cfg.filters.bot));
    let threat_intel = Arc::new(crate::filters::threat_intel::ThreatIntelFilter::new(
        &cfg.filters.threat_intel,
    ));
    // Ordering matters. Threat-intel + IP ACL are cheap exact-match
    // checks — they belong before anything CPU-heavier so we don't
    // waste WAF time on already-banned IPs. WAF runs next because
    // most attack traffic gets caught here. Bot reputation is a
    // little more expensive (DashMap entry per fingerprint). Then
    // adaptive (RPS counters), then challenge ladder which is the
    // last line before per-host rate limits below.
    let mut filters: Vec<SharedFilter> = vec![
        // Honeypot first — cheapest exact-path lookup, highest-signal
        // hit. Saves WAF / bot / adaptive from processing requests
        // that scanners send to known bait paths.
        SharedFilter::Honeypot(Arc::new(crate::filters::honeypot::HoneypotFilter::new(
            honeypots.clone(),
        ))),
        SharedFilter::ThreatIntel(threat_intel.clone()),
        SharedFilter::IpAcl(Arc::new(IpAclFilter::new(
            &cfg.filters.ip_acl.deny,
            &cfg.filters.ip_acl.allow,
        ))),
        SharedFilter::Waf(Arc::new(WafFilter::new(&cfg.filters.waf))),
        SharedFilter::Bot(bot.clone()),
        SharedFilter::Adaptive(Arc::new(AdaptiveFilter::new(&cfg.filters.adaptive))),
    ];
    // User plugins run after the built-in WAF / bot / adaptive
    // gates but before the challenge ladder — so an operator's
    // custom rule can return Deny/Challenge with confidence that
    // it's the last word before the request reaches challenge.
    let plugin_set = crate::filters::plugins::manager::PluginSet::from_config(&cfg.filters.plugins);
    for p in plugin_set.filters {
        filters.push(p);
    }
    filters.push(SharedFilter::Challenge(challenge.clone()));
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
    let health = Arc::new(UpstreamHealth::new(router.clone()));
    let store = cfg
        .storage
        .as_ref()
        .and_then(|s| ReputationStore::new(&s.redis_url).ok());
    let geoip = crate::geoip::load_with_asn(
        cfg.geoip.as_ref().map(|g| g.db_path.as_str()),
        cfg.geoip.as_ref().and_then(|g| g.asn_db_path.as_deref()),
    );
    let anomaly_cfg = build_anomaly_config(cfg);
    let anomaly = Arc::new(crate::anomaly::AnomalyDetector::new(anomaly_cfg));
    Ok((
        ProxyHttpHandler::new(
            router,
            engine,
            metrics,
            scorer,
            cfg.filters.challenge.clone(),
            challenge.clone(),
            cfg.filters.bot.clone(),
            cfg.filters.rate_limit.clone(),
            &cfg.filters.waf,
            &cfg.filters.graphql,
            &cfg.filters.bypass,
            health.clone(),
            fingerprints,
            honeypots.clone(),
            xdp_handle.clone(),
            store,
            geoip,
            cfg.geoip.clone(),
            anomaly,
            alt_svc,
            cfg.server.body_read_timeout_ms,
            cfg.upstream.protocol,
            // Mirror XDP allow list into BypassMatcher so trusted IPs
            // get the userspace fast-path (skip filter chain) on top
            // of the kernel fast-pass. See `BypassMatcher::with_extra_trusted_ips`.
            cfg.xdp
                .as_ref()
                .map(|x| x.allow.iter().filter_map(|s| s.parse().ok()).collect())
                .unwrap_or_default(),
            &cfg.filters.dynamic_trust,
            &cfg.filters.response_cache,
        ),
        rate,
        health,
        bot,
        challenge,
        threat_intel,
    ))
}

fn load_tls_acceptor(cfg: &AppConfig) -> Result<Option<(SocketAddr, TlsAcceptor)>> {
    let Some(tls) = &cfg.tls else { return Ok(None) };
    if !tls.enabled {
        return Ok(None);
    }

    let resolver = SniResolver::build(&tls.cert_path, &tls.key_path, &tls.sni)
        .context("SNI resolver setup failed")?;
    let mut tls_cfg = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let addr: SocketAddr = tls.listen.parse().context("invalid tls.listen")?;
    Ok(Some((addr, TlsAcceptor::from(Arc::new(tls_cfg)))))
}

/// Bind a TcpListener with `SO_REUSEPORT` enabled — Phase 2A-lite
/// foundation for multi-process aegis. With reuseport set, multiple
/// aegis processes can bind the same port; the kernel distributes
/// incoming connections across them (per-process accept queues,
/// no userspace coordination). Operators run them via a systemd
/// template unit (`aegis@N.service`). Single-process aegis is
/// unaffected — reuseport is transparent when only one process
/// holds the port.
///
/// `SO_REUSEADDR` is also set so a fresh start doesn't have to wait
/// out TIME_WAIT after a previous run.
///
/// Backlog 1024 — large enough to absorb burst accepts even on a
/// slow worker; kernel default is often 128 which can drop on
/// flash crowds.
/// V230 — apply per-connection TCP tuning to a freshly-accepted
/// stream. Right now that's just TCP_NODELAY (disable Nagle's
/// algorithm) when `cfg.server.tcp_nodelay` is on — which is the
/// default. Disabling Nagle matters for low-latency request/response
/// workloads (typical HTTP) because the kernel otherwise holds small
/// writes for up to 200 ms hoping to coalesce them. We log + ignore
/// failure rather than dropping the connection: at worst the client
/// pays a few hundred ms of extra latency on the first request.
///
/// Hyper's `serve_connection` consumes the stream by-value, so this
/// must be called BEFORE we hand the socket to TLS accept / hyper.
fn apply_stream_tuning(stream: &tokio::net::TcpStream, tcp_nodelay: bool) {
    if tcp_nodelay && let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "set_nodelay failed");
    }
}

fn bind_reuseport(addr: SocketAddr) -> Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .context("create TcpSocket")?;
    socket.set_reuseaddr(true).context("set SO_REUSEADDR")?;
    // set_reuseport may fail on non-Linux platforms (eg macOS without
    // the right kernel flag, or hardened containers). We treat it as
    // best-effort — log on failure but proceed without it. Single-
    // process mode still works fine.
    if let Err(e) = socket.set_reuseport(true) {
        tracing::warn!(error = %e, "SO_REUSEPORT not available — multi-process aegis on same port will fail");
    }
    socket.bind(addr).with_context(|| format!("bind {addr}"))?;
    socket.listen(1024).context("listen")
}

pub async fn run_server(config_path: PathBuf, mut cfg: AppConfig) -> Result<()> {
    // V19.1+V19.2 — multi-process env-var overrides.
    // Operators running aegis@1..N.service via systemd template
    // need distinct ports per instance without editing the shared
    // /etc/aegis/aegis.conf. These env vars take precedence over
    // config-file values:
    //   AEGIS_LISTEN=0.0.0.0:8080          → main HTTP/HTTPS port
    //   AEGIS_LISTEN_TLS=0.0.0.0:8443      → TLS-only port
    //   AEGIS_ADMIN_LISTEN=0.0.0.0:6281    → admin port
    //   AEGIS_HONEYPOT_STATE=/var/lib/aegis-w2/honeypots.json
    //   AEGIS_WEB_STATE=/var/lib/aegis-w2/web.json
    // Anything unset → config-file value kept.
    if let Ok(v) = std::env::var("AEGIS_LISTEN") {
        cfg.server.listen = v;
    }
    if let Ok(v) = std::env::var("AEGIS_LISTEN_TLS")
        && let Some(t) = cfg.tls.as_mut()
    {
        t.listen = v;
    }
    if let Some(admin) = cfg.admin.as_mut() {
        if let Ok(v) = std::env::var("AEGIS_ADMIN_LISTEN") {
            admin.listen = v;
        }
        if let Ok(v) = std::env::var("AEGIS_HONEYPOT_STATE") {
            admin.honeypot_state_path = Some(v);
        }
        if let Ok(v) = std::env::var("AEGIS_WEB_STATE") {
            admin.web_state_path = Some(v);
        }
    }

    let addr: SocketAddr = cfg
        .server
        .listen
        .parse()
        .context("invalid listen address")?;
    let listener =
        bind_reuseport(addr).with_context(|| format!("bind plain listener on {addr}"))?;

    let tls_cfg = load_tls_acceptor(&cfg)?;
    let tls_listener = if let Some((tls_addr, acceptor)) = tls_cfg {
        let l =
            bind_reuseport(tls_addr).with_context(|| format!("bind TLS listener on {tls_addr}"))?;
        Some((l, acceptor))
    } else {
        None
    };

    let (shutdown_tx, _) = broadcast::channel(16);
    let active_cfg = Arc::new(RwLock::new(cfg.clone()));
    let metrics = Arc::new(RuntimeMetrics::default());
    let scorer = Arc::new(ThreatScorer::default());

    let xdp_handle: Arc<dyn xdp::XdpHandle> = if let Some(xcfg) = &cfg.xdp
        && xcfg.enabled
    {
        match xdp::load(&xcfg.interface, std::path::Path::new(&xcfg.bpf_object_path)) {
            Ok(h) => {
                tracing::info!("XDP fast-path loaded");
                Arc::from(h)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    chain = %format!("{e:#}"),
                    "XDP load failed — falling back to userspace filtering"
                );
                Arc::new(xdp::NoopXdp)
            }
        }
    } else {
        Arc::new(xdp::NoopXdp)
    };

    let persister = domains::spawn_persister(metrics.clone(), Duration::from_secs(30));
    let admin_listen = cfg
        .admin
        .as_ref()
        .map(|a| a.listen.clone())
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    let env_token = std::env::var("AEGIS_ADMIN_TOKEN").ok();
    let configured_tokens: Vec<_> = cfg
        .admin
        .as_ref()
        .map(|a| a.tokens.clone())
        .unwrap_or_default();
    let registry = TokenRegistry::from_sources(env_token, &configured_tokens);
    if registry.is_empty() {
        tracing::warn!(
            "no admin tokens configured (AEGIS_ADMIN_TOKEN or [[admin.tokens]]) — /admin/* will reject all requests"
        );
    }
    let audit_log = AuditLog::new(
        cfg.admin
            .as_ref()
            .and_then(|a| a.audit_log_path.clone())
            .map(std::path::PathBuf::from),
    );

    let fingerprints = Arc::new(crate::state::fingerprint::FingerprintCache::new());
    // Honeypot state — backed by a JSON file the admin UI can write
    // without a config reload. Defaults to all-built-in-packs-on if
    // the file doesn't exist on first boot.
    let honeypot_state_path = std::path::PathBuf::from(
        cfg.admin
            .as_ref()
            .and_then(|a| a.honeypot_state_path.clone())
            .unwrap_or_else(|| crate::honeypot::state::DEFAULT_STATE_PATH.to_string()),
    );
    let honeypots = Arc::new(crate::honeypot::HoneypotStore::open(honeypot_state_path)?);
    let (handler, rate, health, bot, challenge, threat_intel) = build_handler(
        &cfg,
        metrics.clone(),
        scorer.clone(),
        fingerprints.clone(),
        honeypots.clone(),
        xdp_handle.clone(),
    )
    .await?;
    health.spawn_checker();
    let health_state = Arc::new(RwLock::new(health));
    let handler = Arc::new(RwLock::new(handler));

    let reloader = Arc::new(Reloader {
        metrics: metrics.clone(),
        scorer: scorer.clone(),
        fingerprints: fingerprints.clone(),
        honeypots: honeypots.clone(),
        handler: handler.clone(),
        health_state: health_state.clone(),
        xdp_handle: xdp_handle.clone(),
        xdp_deny_set: std::sync::Mutex::new(std::collections::HashSet::new()),
        xdp_allow_set: std::sync::Mutex::new(std::collections::HashSet::new()),
    });
    // Initial XDP sync — deny set, allow set, rate config (primes the
    // diff baselines for later /admin/reload calls).
    reloader.sync_xdp_from(&cfg);
    let web_state_path: std::path::PathBuf = cfg
        .admin
        .as_ref()
        .and_then(|a| a.web_state_path.clone())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(crate::web_admin::DEFAULT_STATE_PATH));
    let web_admin = Arc::new(crate::web_admin::WebAdminStore::open(web_state_path)?);
    let state = RuntimeState {
        config_path: config_path.clone(),
        active_cfg: active_cfg.clone(),
        shutdown_tx: shutdown_tx.clone(),
        reloader,
        started_at: std::time::Instant::now(),
        web_admin,
        fingerprints: fingerprints.clone(),
        honeypots: honeypots.clone(),
    };

    let admin_task = tokio::spawn(run_admin(
        admin_listen,
        registry,
        audit_log,
        state.clone(),
        metrics.clone(),
        scorer.clone(),
        xdp_handle.clone(),
        health_state.clone(),
        rate.clone(),
        handler.clone(),
    ));

    let h3_task = if let Some(tls) = &cfg.tls
        && tls.enabled
        && tls.h3_enabled
    {
        let h3_listen = tls.h3_listen.clone().unwrap_or_else(|| tls.listen.clone());
        let addr: SocketAddr = h3_listen.parse().context("invalid tls.h3_listen")?;
        match http3::build_endpoint(addr, &tls.cert_path, &tls.key_path, &tls.sni) {
            Ok(endpoint) => {
                tracing::info!(%addr, "HTTP/3 listener started");
                Some(http3::spawn_server(
                    endpoint,
                    handler.clone(),
                    fingerprints.clone(),
                ))
            }
            Err(e) => {
                tracing::warn!(error = %e, "HTTP/3 listener disabled");
                None
            }
        }
    } else {
        None
    };

    // Threat-intel feed refresher — re-reads every configured local
    // feed file on a fixed interval and atomically swaps the deny
    // set. No-op when no feeds are configured.
    let threat_refresh_secs = cfg.filters.threat_intel.refresh_secs.max(30);
    let threat_intel_clone = threat_intel.clone();
    let threat_task = if threat_intel.is_active() {
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(threat_refresh_secs));
            // First tick fires immediately — but we already loaded on
            // construction, so skip it.
            interval.tick().await;
            loop {
                interval.tick().await;
                threat_intel_clone.reload();
            }
        }))
    } else {
        None
    };

    let cleanup_rate = rate.clone();
    let cleanup_scorer = scorer.clone();
    let cleanup_bot = bot.clone();
    let cleanup_challenge = challenge.clone();
    let cleanup_fingerprints = fingerprints.clone();
    let cleanup_xdp = xdp_handle.clone();
    let cleanup_honeypots = honeypots.clone();
    // V19.3 — handler clone for WAF rule-file hot-reload polling.
    // The background task wakes every 30 s and triggers
    // `waf_maybe_reload()`; if any rule file's mtime changed since
    // last poll, the WAF atomically swaps in the new rule set via
    // ArcSwap (hot path readers are never blocked).
    let cleanup_handler = handler.clone();
    let cleanup_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        // Keep bot reputation 1 h after last hit, challenge ladder 5
        // min — those are well past the natural session windows so
        // legitimate users never lose state.
        let bot_stale = Duration::from_secs(3600);
        let challenge_stale = Duration::from_secs(300);
        loop {
            interval.tick().await;
            let now = std::time::Instant::now();
            cleanup_rate.cleanup_stale(now);
            cleanup_scorer.cleanup_stale(now);
            cleanup_bot.cleanup_stale(now, bot_stale);
            cleanup_challenge.cleanup_stale(now, challenge_stale);
            // TLS connections are short-lived; 5 min is plenty of
            // buffer between the handshake and the last request on
            // a keep-alive.
            cleanup_fingerprints.cleanup_stale(now, Duration::from_secs(300));
            // XDP JA4T map: evict entries older than 60s. The TCP
            // handshake is sub-millisecond; if userspace hasn't
            // accept()'d the connection within a minute we can safely
            // drop the SYN fingerprint.
            if let Err(e) = cleanup_xdp.evict_ja4t_v4(60 * 1_000_000_000) {
                tracing::debug!(error = %e, "ja4t map evict failed");
            }
            // Honeypot per-IP hit tallies — keep 1 h sliding window so
            // a single hit doesn't permanently mark an IP, but a
            // scanner sweeping a hundred paths over five minutes still
            // accumulates threshold and gets auto-XDP-denied.
            cleanup_honeypots.cleanup_stale(now, Duration::from_secs(3600));
            // V19.3 — WAF rule hot-reload check. Cheap (mtime stat
            // per file); only does work on actual changes.
            let h = cleanup_handler.read().await.clone();
            let _ = h.waf_maybe_reload();
            // V21 — cross-worker cache purge broadcast. If sibling
            // worker (or this one earlier) hit /admin/cache/purge,
            // the broadcast file's mtime advances; we drop our local
            // cache to follow.
            let dropped = h.cache_check_broadcast_purge();
            if dropped > 0 {
                tracing::info!(
                    count = dropped,
                    "cross-worker cache purge broadcast applied"
                );
            }
        }
    });

    let tracker = TaskTracker::new();
    let cancel = CancellationToken::new();

    let mut signal = Box::pin(wait_for_shutdown_signal());
    let mut rx = shutdown_tx.subscribe();
    loop {
        tokio::select! {
            _ = &mut signal => break,
            _ = rx.recv() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                // V230 — disable Nagle (and any future per-socket tuning)
                // before the stream is consumed by PROXY-header parsing /
                // hyper. cfg.server snapshot is read on the accept thread
                // so each connection sees the active reload value.
                apply_stream_tuning(&stream, cfg.server.tcp_nodelay);
                let handler_ref = handler.clone();
                let cfg_ref = active_cfg.clone();
                let health_ref = health_state.clone();
                let cancel_ref = cancel.clone();
                let fingerprints_clone = fingerprints.clone();
                let xdp_for_ja4t = xdp_handle.clone();
                let proxy_mode = cfg.server.proxy_protocol;
                tracker.spawn(async move {
                    let fingerprints = fingerprints_clone;
                    let (stream, client_ip) = match strip_proxy_header(stream, peer.ip(), proxy_mode).await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::debug!(error = %e, peer = %peer, "PROXY header parse failed");
                            return;
                        }
                    };
                    // JA4T: prefer the XDP SYN capture (full
                    // window+options+mss+wscale) when the fast-path
                    // is loaded; fall back to TCP_INFO when it isn't.
                    if let Some(ja4t) =
                        crate::tcp_info::capture_with_xdp(&stream, peer.port(), &*xdp_for_ja4t, peer.ip())
                    {
                        fingerprints.record_ja4t(client_ip, peer.port(), ja4t);
                    }
                    serve_plain(stream, client_ip, peer.port(), handler_ref, cfg_ref, health_ref, cancel_ref).await;
                });
            },
            tls_accepted = async {
                match &tls_listener {
                    Some((l, _)) => l.accept().await.ok(),
                    None => None,
                }
            }, if tls_listener.is_some() => {
                if let Some((stream, peer)) = tls_accepted {
                    // V230 — TCP tuning must run on the raw socket
                    // before the TLS acceptor takes ownership; once
                    // the stream is wrapped in TlsStream we no longer
                    // have direct access to set_nodelay().
                    apply_stream_tuning(&stream, cfg.server.tcp_nodelay);
                    let handler_ref = handler.clone();
                    let cfg_ref = active_cfg.clone();
                    let health_ref = health_state.clone();
                    let cancel_ref = cancel.clone();
                    let acceptor = tls_listener.as_ref().expect("tls cfg").1.clone();
                    let ja3_deny: Vec<String> = cfg
                        .tls
                        .as_ref()
                        .map(|t| t.ja3_deny_hashes.clone())
                        .unwrap_or_default();
                    let ja4_deny: Vec<String> = cfg
                        .tls
                        .as_ref()
                        .map(|t| t.ja4_deny_prefixes.clone())
                        .unwrap_or_default();
                    let fingerprints = fingerprints.clone();
                    let xdp_for_ja4t = xdp_handle.clone();
                    let proxy_mode = cfg.server.proxy_protocol;
                    tracker.spawn(async move {
                        // PROXY protocol must be consumed BEFORE the TLS
                        // handshake — the LB writes its header first, then
                        // the client's TLS ClientHello.
                        let (stream, client_ip) = match strip_proxy_header(stream, peer.ip(), proxy_mode).await {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::debug!(error = %e, peer = %peer, "PROXY header parse failed");
                                return;
                            }
                        };
                        // JA3 / JA4 sniff: peek the first record, compute
                        // both fingerprints, slam the door if either is
                        // on its respective deny list, then stash the JA4
                        // string in the per-connection cache so the
                        // handler can attach it to each request.
                        let peer_port = peer.port();
                        // JA4L: measure round-trip from ClientHello
                        // observation to TLS handshake completion.
                        // Captured at sniff time so we don't pay for
                        // an extra clock read when handshake fails.
                        let sniff_at_ms = now_ms();
                        if let Some((ja3_hash, ja4)) = sniff_fingerprints(&stream).await {
                            if !ja3_deny.is_empty()
                                && ja3_deny.iter().any(|h| h.eq_ignore_ascii_case(&ja3_hash))
                            {
                                tracing::warn!(%client_ip, ja3 = %ja3_hash, "TLS connection rejected by JA3 deny list");
                                return;
                            }
                            if !ja4_deny.is_empty()
                                && ja4_deny.iter().any(|p| ja4.full.starts_with(p.as_str()))
                            {
                                tracing::warn!(%client_ip, ja4 = %ja4.full, "TLS connection rejected by JA4 deny list");
                                return;
                            }
                            fingerprints.record_ja4(client_ip, peer_port, ja4.full);
                        }
                        // JA4T capture on the underlying TCP socket
                        // — same priority as the plain-HTTP path:
                        // XDP first, TCP_INFO fallback.
                        if let Some(ja4t) =
                            crate::tcp_info::capture_with_xdp(&stream, peer_port, &*xdp_for_ja4t, peer.ip())
                        {
                            fingerprints.record_ja4t(client_ip, peer_port, ja4t);
                        }
                        // JA4L "client_to_server" half = kernel-
                        // smoothed TCP RTT (µs). Capture from
                        // TCP_INFO BEFORE we move stream into the
                        // TLS acceptor — once accept() consumes the
                        // stream we lose access to the underlying fd.
                        let client_to_server_us = crate::tcp_info::smoothed_rtt_us(&stream);
                        let sniff_at_us = sniff_at_ms.saturating_mul(1_000);
                        let Ok(tls_stream) = acceptor.accept(stream).await else { return; };
                        // JA4L "server_to_client" half = our local
                        // TLS-stack latency from sniff-time to
                        // handshake-done. Reflects our CPU cost +
                        // the wait for client's encrypted Finished
                        // round-trip; large values indicate slow
                        // clients (cloud-proxied scrapers, embedded
                        // devices).
                        let server_to_client_us = now_ms()
                            .saturating_mul(1_000)
                            .saturating_sub(sniff_at_us);
                        fingerprints.record_ja4l(
                            client_ip,
                            peer_port,
                            crate::ja4::compute_ja4l_pair(&crate::ja4::Ja4lInput {
                                client_to_server_us,
                                server_to_client_us,
                            }),
                        );
                        // mTLS: when client presented a verified
                        // certificate, compute the JA4-style mTLS
                        // fingerprint. Requires rustls to have client
                        // auth enabled in TlsConfig.
                        if let Some(mfp) = extract_mtls_fp(&tls_stream) {
                            fingerprints.record_mtls_fp(client_ip, peer_port, mfp);
                        }
                        // HTTP/2 sniff: only run when ALPN negotiated
                        // "h2" — otherwise the read loop sits the full
                        // 500 ms deadline waiting for a preface that
                        // never arrives on an HTTP/1.1 connection.
                        // ALPN is set on the TlsStream's
                        // ServerConnection after acceptor.accept() ↑.
                        let is_h2 = {
                            let (_io, conn) = tls_stream.get_ref();
                            conn.alpn_protocol() == Some(b"h2")
                        };
                        if is_h2 {
                            let fingerprints_capture = fingerprints.clone();
                            let (sniffed_stream, h2fp) =
                                sniff_h2_fingerprint(tls_stream).await;
                            if let Some(fp) = h2fp {
                                fingerprints_capture.record_h2fp(client_ip, peer_port, fp);
                            }
                            serve_inner(TokioIo::new(sniffed_stream), client_ip, peer_port, handler_ref, cfg_ref, health_ref, cancel_ref).await;
                        } else {
                            serve_inner(TokioIo::new(tls_stream), client_ip, peer_port, handler_ref, cfg_ref, health_ref, cancel_ref).await;
                        }
                    });
                }
            }
        }
    }

    let drain = Duration::from_secs(cfg.server.graceful_shutdown_secs);
    tracing::info!(
        ?drain,
        "shutdown signal received — draining inflight connections"
    );
    drop(listener);
    if let Some((l, _)) = tls_listener {
        drop(l);
    }
    tracker.close();
    let timed_out = tokio::time::timeout(drain, tracker.wait()).await.is_err();
    if timed_out {
        tracing::warn!("drain window exceeded — cancelling remaining connections");
        cancel.cancel();
        // Give the cancel-aware paths a final 500ms to flush headers.
        let _ = tokio::time::timeout(Duration::from_millis(500), tracker.wait()).await;
    }

    cleanup_task.abort();
    if let Some(t) = threat_task {
        t.abort();
    }
    admin_task.abort();
    persister.abort();
    if let Some(h) = h3_task {
        h.abort();
    }
    Ok(())
}

/// Consume an optional PROXY protocol header from the start of a
/// freshly-accepted TCP stream. Returns the (possibly trimmed) stream
/// plus the client IP — either the one the LB asserted in the PROXY
/// header, or the TCP peer when proxy_protocol is off / the header
/// signals UNSPECIFIED.
async fn strip_proxy_header(
    mut stream: tokio::net::TcpStream,
    peer_ip: IpAddr,
    mode: crate::config::ProxyProtocolMode,
) -> Result<(tokio::net::TcpStream, IpAddr)> {
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, timeout};

    if mode == crate::config::ProxyProtocolMode::Off {
        return Ok((stream, peer_ip));
    }

    // The header is at most 108 bytes (v1) or ~216 bytes (v2 with
    // TLVs); read up to 1 KiB to be safe. Bounded by a tight timeout
    // so a stalled LB can't pin an accept worker.
    let mut buf = vec![0u8; 1024];
    let mut filled = 0;
    let header_len = loop {
        let chunk = timeout(Duration::from_millis(500), stream.peek(&mut buf[filled..]))
            .await
            .map_err(|_| anyhow::anyhow!("PROXY header read timed out"))??;
        if chunk == 0 {
            return Err(anyhow::anyhow!("connection closed before PROXY header"));
        }
        filled = chunk; // peek always re-reads from offset 0
        match crate::proxy_proto::parse(&buf[..filled], mode)? {
            Some(p) => break p.consumed,
            None => {
                if filled >= buf.len() {
                    return Err(anyhow::anyhow!("PROXY header longer than 1 KiB"));
                }
            }
        }
    };

    // Drain exactly the header bytes off the socket so the next reader
    // (TLS / hyper) sees the real payload.
    if header_len > 0 {
        let mut sink = vec![0u8; header_len];
        stream.read_exact(&mut sink).await?;
    }

    let client_ip = match crate::proxy_proto::parse(&buf[..filled], mode)?.map(|p| p.client_ip) {
        Some(ip) if !ip.is_unspecified() => ip,
        _ => peer_ip,
    };
    Ok((stream, client_ip))
}

/// Peek the ClientHello bytes from a freshly-accepted TCP stream and
/// compute the JA3 hash. Times out fast — slow clients aren't worth
/// the wait. Returns None on truncation, non-handshake bytes or
/// timeout; the caller falls through to a normal TLS handshake either
/// way (so a half-baked sniff never breaks legit clients).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute the mTLS client-cert fingerprint when the TLS handshake
/// resolved a verified client certificate. Returns None for the
/// common case (no client auth configured / no cert presented).
fn extract_mtls_fp<IO>(tls: &tokio_rustls::server::TlsStream<IO>) -> Option<String> {
    let (_io, conn) = tls.get_ref();
    let chain = conn.peer_certificates()?;
    if chain.is_empty() {
        return None;
    }
    let leaf_der = chain[0].as_ref().to_vec();
    // V55 — DER parsers moved to `mtls_fp` so the hyper + pingora
    // paths produce byte-identical fingerprints from the same cert.
    let mtls_chain = crate::mtls_fp::MtlsChain {
        leaf_der: leaf_der.clone(),
        chain_len: chain.len(),
        san_count: crate::mtls_fp::count_san_entries(chain[0].as_ref()),
        key_type: crate::mtls_fp::classify_key_type(&leaf_der),
        issuer_dn: crate::mtls_fp::extract_issuer_dn(&leaf_der),
    };
    Some(crate::mtls_fp::compute(&mtls_chain).full)
}

/// Read the first ~2 KiB of the TLS-decrypted stream, parse it as
/// the HTTP/2 connection preface + SETTINGS + WINDOW_UPDATE + first
/// HEADERS frame, and return both the captured fingerprint (when
/// the bytes are HTTP/2) and a wrapped stream that replays the
/// captured bytes for hyper.
///
/// 2 KiB covers Chrome / Firefox / curl preludes (which fit in
/// ~150 bytes) plus a healthy slack for clients that send a fat
/// initial HEADERS frame. We bound the read with a 1 s timeout so
/// HTTP/1.x connections that don't send anything immediately don't
/// stall.
async fn sniff_h2_fingerprint<IO>(
    mut tls: tokio_rustls::server::TlsStream<IO>,
) -> (
    crate::h2_fp::SniffedStream<tokio_rustls::server::TlsStream<IO>>,
    Option<String>,
)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, Instant, timeout_at};

    // Read up to 8 KiB across multiple flights — Chrome packs the
    // preface + SETTINGS + WU + HEADERS into one TLS record, curl /
    // h2load split them across writes. Stop early as soon as
    // parse_prefix returns a complete fingerprint (i.e. the HEADERS
    // frame has been consumed).
    //
    // 250 ms deadline. RFC 7540 §3.4 REQUIRES the client to send
    // its preface as the first application data of the TLS
    // connection, without waiting for the server's SETTINGS — so
    // any client that hasn't sent within 250 ms is either dead or
    // non-compliant. Earlier prototype tried pre-emitting an empty
    // server SETTINGS frame to unblock hypothetical
    // wait-for-server clients; it introduced a race with hyper's
    // own SETTINGS write that occasionally clobbered the
    // fingerprint capture, and the underlying problem isn't real
    // per spec, so the simpler "just bound the wait" approach won.
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 2048];
    let mut fp_complete: Option<crate::h2_fp::H2Fingerprint> = None;
    loop {
        let read = timeout_at(deadline, tls.read(&mut tmp)).await;
        match read {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(fp) = crate::h2_fp::parse_prefix(&buf) {
                    let has_headers = !fp.pseudo_order.is_empty();
                    fp_complete = Some(fp);
                    if has_headers || buf.len() >= 8 * 1024 {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    let fp_string = fp_complete.map(|fp| fp.full());
    let wrapped = crate::h2_fp::SniffedStream::new(tls, buf);
    (wrapped, fp_string)
}

/// Peek the TLS ClientHello once and produce BOTH the JA3 md5 hash
/// and the JA4 structured fingerprint. Two for the price of one peek
/// — avoids a second read on the socket. Returns None if the buffer
/// isn't a parseable ClientHello, which the caller treats as
/// "fall through to a normal TLS handshake" so half-baked sniffs
/// never break legit clients.
async fn sniff_fingerprints(
    stream: &tokio::net::TcpStream,
) -> Option<(String, crate::ja4::Ja4Fingerprint)> {
    use tokio::time::{Duration, timeout};
    let mut buf = vec![0u8; 4096];
    let read = timeout(Duration::from_millis(250), stream.peek(&mut buf))
        .await
        .ok()?
        .ok()?;
    if read == 0 {
        return None;
    }
    let (_ja3, ja3_hash) = crate::ja3::compute_ja3(&buf[..read])?;
    let ja4 = crate::ja4::compute_ja4(&buf[..read], false)?;
    Some((ja3_hash, ja4))
}

async fn serve_plain(
    stream: tokio::net::TcpStream,
    client_ip: IpAddr,
    peer_port: u16,
    handler: Arc<RwLock<ProxyHttpHandler>>,
    cfg: Arc<RwLock<AppConfig>>,
    health: Arc<RwLock<Arc<UpstreamHealth>>>,
    cancel: CancellationToken,
) {
    serve_inner(
        TokioIo::new(stream),
        client_ip,
        peer_port,
        handler,
        cfg,
        health,
        cancel,
    )
    .await
}

async fn serve_inner<I>(
    io: I,
    client_ip: IpAddr,
    peer_port: u16,
    handler: Arc<RwLock<ProxyHttpHandler>>,
    cfg: Arc<RwLock<AppConfig>>,
    health: Arc<RwLock<Arc<UpstreamHealth>>>,
    cancel: CancellationToken,
) where
    I: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let cfg_for_builder = cfg.clone();
    let service = service_fn(move |req| {
        let handler = handler.clone();
        let cfg = cfg.clone();
        let health = health.clone();
        async move {
            // Circuit-breaker check now lives inside ProxyHttpHandler
            // (after the filter pipeline) so a denied request still
            // gets a meaningful 4xx instead of a generic 503 when the
            // backend happens to be circuit-open at the time.
            let _ = &health;
            let req_timeout = {
                let c = cfg.read().await;
                Duration::from_millis(c.server.request_timeout_ms)
            };
            let h = handler.read().await.clone();
            match timeout(req_timeout, h.handle(client_ip, peer_port, req)).await {
                Ok(resp) => resp,
                Err(_) => {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::REQUEST_TIMEOUT)
                        .body(
                            http_body_util::Full::new(bytes::Bytes::from("request timeout"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("timeout response");
                    Ok::<_, std::convert::Infallible>(resp)
                }
            }
        }
    });
    let snapshot = cfg_for_builder.read().await.server.clone();
    let mut builder = Builder::new(TokioExecutor::new());
    // hyper's timeouts (header_read, keepalive, etc.) require a Timer
    // to be wired up explicitly — without this the worker panics the
    // first time the timeout fires with "no timer set". Found by the
    // e2e harness; the production binary needs this just as badly.
    builder.http1().timer(hyper_util::rt::TokioTimer::new());
    builder.http2().timer(hyper_util::rt::TokioTimer::new());
    // Slowloris guard: refuse connections that drag header reads past
    // header_read_timeout_ms (default 5s). hyper drops the connection
    // outright when this trips — no upstream resources held.
    builder
        .http1()
        .header_read_timeout(Duration::from_millis(snapshot.header_read_timeout_ms));
    // HTTP/2 Rapid Reset mitigation (CVE-2023-44487). Cap concurrent
    // streams + total pending-reset streams; hyper closes the
    // connection with GOAWAY when either is exceeded, so an attacker
    // can't burn CPU by opening + RST'ing streams in a tight loop.
    //
    // V230 — also pin flow-control windows + frame size so behaviour
    // matches the pingora-side listener (single source of truth lives
    // in `crate::config::ServerConfig`). Larger stream/connection
    // windows reduce WINDOW_UPDATE round-trips for big responses; the
    // 16 KiB MAX_FRAME_SIZE keeps us at the H2 protocol minimum (and
    // therefore the safest default — clients can negotiate higher).
    //
    // TODO(v231): expose `h2_max_frame_size` as a config knob too.
    // Until then we hardcode the H2 spec minimum (16_384) — anything
    // smaller is invalid, anything larger should be opt-in because
    // bigger frames mean coarser cancellation granularity.
    builder
        .http2()
        .max_concurrent_streams(snapshot.h2_max_concurrent_streams)
        .max_pending_accept_reset_streams(Some(snapshot.h2_max_reset_streams))
        .initial_stream_window_size(snapshot.h2_initial_window_size)
        .initial_connection_window_size(snapshot.h2_initial_connection_window_size)
        .max_frame_size(16_384u32);
    let conn = builder.serve_connection(io, service);
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {},
        _ = cancel.cancelled() => {
            conn.as_mut().graceful_shutdown();
            let _ = conn.await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_admin(
    listen: String,
    registry: TokenRegistry,
    audit: AuditLog,
    state: RuntimeState,
    metrics: Arc<RuntimeMetrics>,
    scorer: Arc<ThreatScorer>,
    xdp_handle: Arc<dyn xdp::XdpHandle>,
    health_state: Arc<RwLock<Arc<UpstreamHealth>>>,
    rate: Arc<RateLimitFilter>,
    handler: Arc<RwLock<ProxyHttpHandler>>,
) {
    let listener = match listen
        .parse::<SocketAddr>()
        .ok()
        .and_then(|a| bind_reuseport(a).ok())
    {
        Some(v) => v,
        None => return,
    };
    loop {
        let Ok((stream, peer_addr)) = listener.accept().await else {
            continue;
        };
        // V230 — admin panel is always low-latency tier (CLI calls,
        // health probes, browser fetches), so we unconditionally
        // disable Nagle here rather than threading `cfg` through the
        // `run_admin` signature. Keeping the signature stable matters
        // for the in-tree callers and the public-API contract.
        apply_stream_tuning(&stream, true);
        let io = TokioIo::new(stream);
        let state_cloned = state.clone();
        let metrics_cloned = metrics.clone();
        let registry_cloned = registry.clone();
        let audit_cloned = audit.clone();
        let scorer_cloned = scorer.clone();
        let xdp_cloned = xdp_handle.clone();
        let health_cloned = health_state.clone();
        let rate_cloned = rate.clone();
        let handler_cloned = handler.clone();
        let peer = peer_addr.to_string();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state_cloned.clone();
                let metrics = metrics_cloned.clone();
                let registry = registry_cloned.clone();
                let audit = audit_cloned.clone();
                let scorer = scorer_cloned.clone();
                let xdp_h = xdp_cloned.clone();
                let health = health_cloned.clone();
                let rate = rate_cloned.clone();
                let handler = handler_cloned.clone();
                let peer = peer.clone();
                async move {
                    let path = req.uri().path().to_string();
                    // Pull query string separately — `uri().path()`
                    // strips it. Phase 3Y.2 cache-purge endpoint reads
                    // ?all / ?host / ?prefix filters from here.
                    let query = req.uri().query().unwrap_or("").to_string();
                    let method = req.method().clone();
                    let mut status = http::StatusCode::OK;

                    // Hard kill switch for the web panel — when an
                    // operator runs `aegis web stop`, every UI + API
                    // path returns 503 regardless of credentials. The
                    // plain-text /admin/* ops endpoints (reload,
                    // health, threats, …) remain reachable so
                    // `systemctl reload aegis` keeps working.
                    let is_web_path = path == "/"
                        || path == "/admin/ui"
                        || path.starts_with("/admin/ui/")
                        || path.starts_with("/admin/api/");
                    if is_web_path && !state.web_admin.enabled() {
                        audit.record(
                            &peer,
                            method.as_str(),
                            &path,
                            None,
                            http::StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        );
                        let resp = http::Response::builder()
                            .status(http::StatusCode::SERVICE_UNAVAILABLE)
                            .header("content-type", "application/json")
                            .body(
                                http_body_util::Full::new(bytes::Bytes::from(
                                    r#"{"error":"web panel is disabled (aegis web start to enable)"}"#,
                                ))
                                .map_err(|never| match never {})
                                .boxed(),
                            )
                            .expect("web disabled response");
                        return Ok::<_, std::convert::Infallible>(resp);
                    }

                    let required = required_role_for(method.as_str(), &path);
                    let supplied = req
                        .headers()
                        .get("x-admin-token")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("");
                    // Token resolution order: web session token first
                    // (the panel's own login), then the static config
                    // tokens (used by CLI / systemctl reload). A
                    // session always grants Admin role inside the
                    // panel — coarser-grained, but the panel itself
                    // doesn't currently distinguish read vs write
                    // users.
                    let granted = if supplied.is_empty() {
                        None
                    } else if state.web_admin.validate(supplied).is_some() {
                        Some(crate::config::AdminRole::Admin)
                    } else {
                        registry.authenticate(supplied)
                    };

                    if let Some(need) = required {
                        match granted {
                            Some(role) if role >= need => {}
                            _ => {
                                audit.record(
                                    &peer,
                                    method.as_str(),
                                    &path,
                                    granted,
                                    http::StatusCode::UNAUTHORIZED.as_u16(),
                                );
                                let body = if registry.is_empty() {
                                    "admin disabled (no tokens configured)"
                                } else if granted.is_none() {
                                    "unauthorized"
                                } else {
                                    "insufficient role"
                                };
                                let resp = http::Response::builder()
                                    .status(http::StatusCode::UNAUTHORIZED)
                                    .body(
                                        http_body_util::Full::new(bytes::Bytes::from(body))
                                            .map_err(|never| match never {})
                                            .boxed(),
                                    )
                                    .expect("admin auth response");
                                return Ok::<_, std::convert::Infallible>(resp);
                            }
                        }
                    }

                    // UI + JSON API routes return their own
                    // Response<RespBody> so they can set the right
                    // Content-Type. Dispatched before the plain-text
                    // body handler below.
                    if let Some(resp) =
                        handle_ui_route(method.as_str(), &path, &state, granted).await
                    {
                        audit.record(
                            &peer,
                            method.as_str(),
                            &path,
                            granted,
                            resp.status().as_u16(),
                        );
                        return Ok::<_, std::convert::Infallible>(resp);
                    }
                    if let Some(resp) =
                        handle_api_route(method.as_str(), &path, &state, granted, req).await
                    {
                        audit.record(
                            &peer,
                            method.as_str(),
                            &path,
                            granted,
                            resp.status().as_u16(),
                        );
                        return Ok::<_, std::convert::Infallible>(resp);
                    }

                    let body = if method == Method::GET && path == "/metrics" {
                        // Base runtime metrics + XDP fast-path counters
                        // appended. Single scrape covers both layers.
                        let mut out = metrics.render_prometheus();
                        let c = xdp_h.counters().unwrap_or_default();
                        out.push_str(&format!(
                            "# HELP aegis_xdp_pass Packets passed to userspace by XDP.\n# TYPE aegis_xdp_pass counter\naegis_xdp_pass {}\n\
                             # HELP aegis_xdp_drop_deny Packets dropped by XDP deny-list.\n# TYPE aegis_xdp_drop_deny counter\naegis_xdp_drop_deny {}\n\
                             # HELP aegis_xdp_drop_rate Packets dropped by XDP per-IP token bucket.\n# TYPE aegis_xdp_drop_rate counter\naegis_xdp_drop_rate {}\n\
                             # HELP aegis_xdp_drop_allowonly Packets dropped by XDP allow-only whitelist mode.\n# TYPE aegis_xdp_drop_allowonly counter\naegis_xdp_drop_allowonly {}\n\
                             # HELP aegis_xdp_drop_syn Packets dropped by XDP SYN-flood guard.\n# TYPE aegis_xdp_drop_syn counter\naegis_xdp_drop_syn {}\n\
                             # HELP aegis_xdp_drop_waf Packets dropped by Phase 3X inline eBPF WAF (scanner paths).\n# TYPE aegis_xdp_drop_waf counter\naegis_xdp_drop_waf {}\n",
                            c.pass, c.drop_deny, c.drop_rate, c.drop_allowonly, c.drop_syn, c.drop_waf,
                        ));
                        out
                    } else if method == Method::GET && path == "/admin/threats" {
                        let mut out = String::new();
                        for (ip, s) in scorer.top(50) {
                            out.push_str(&format!("{ip} {:.2}\n", s.as_f64()));
                        }
                        out
                    } else if method == Method::GET && path == "/admin/health" {
                        let h = health.read().await.clone();
                        let mut out = String::new();
                        let snap = h.snapshot();
                        if snap.is_empty() {
                            out.push_str("all_upstreams_healthy\n");
                        } else {
                            for (host, since) in snap {
                                out.push_str(&format!(
                                    "unhealthy {host} since_ms={}\n",
                                    since.as_millis()
                                ));
                            }
                        }
                        out
                    } else if method == Method::GET && path == "/admin/hot_uris" {
                        let mut out = String::new();
                        for (uri, count) in rate.hot_uris(20) {
                            out.push_str(&format!("{uri} {count}\n"));
                        }
                        if out.is_empty() {
                            out.push_str("none\n");
                        }
                        out
                    } else if method == Method::GET && path == "/admin/anomaly" {
                        let h = handler.read().await.clone();
                        let mut out = String::new();
                        for (host, remaining_ms) in h.anomaly_snapshot() {
                            out.push_str(&format!("{host} attack_remaining_ms={remaining_ms}\n"));
                        }
                        if out.is_empty() {
                            out.push_str("no_active_attacks\n");
                        }
                        out
                    } else if method == Method::POST && path == "/admin/waf/reload" {
                        // V19.3 — manual trigger for WAF rule file
                        // hot-reload. The background watcher also polls
                        // every 30 s; this endpoint lets ops force an
                        // immediate reload after editing a file (no
                        // need to wait for the next poll tick).
                        let h = handler.read().await.clone();
                        let n = h.waf_maybe_reload();
                        format!("reloaded {n} file(s)\n")
                    } else if method == Method::GET && path == "/admin/cache" {
                        // Phase 3Y.2 — response cache stats (hits, misses,
                        // 304s, evictions, threat-skipped). Operator-essential
                        // for tuning TTLs + verifying threat policy is firing.
                        let h = handler.read().await.clone();
                        let s = h.cache_stats();
                        let total = s.hits + s.misses;
                        let hit_ratio = if total > 0 {
                            (s.hits as f64) * 100.0 / (total as f64)
                        } else {
                            0.0
                        };
                        format!(
                            "cache_hits {}\ncache_misses {}\ncache_not_modified {}\ncache_stores {}\ncache_evictions {}\ncache_skipped_high_threat {}\ncache_skipped_uncacheable {}\ncache_hit_ratio_pct {:.2}\n",
                            s.hits,
                            s.misses,
                            s.not_modified,
                            s.stores,
                            s.evictions,
                            s.skipped_high_threat,
                            s.skipped_uncacheable,
                            hit_ratio,
                        )
                    } else if method == Method::GET && path == "/admin/cache/dump" {
                        // Phase 3Y.5c — list cached entries (capped at 200)
                        // for operator debugging. No body content surfaced
                        // (could contain PII / secrets) — just key + size +
                        // expiry. Sorted by host then path for readability.
                        let h = handler.read().await.clone();
                        let mut entries = h.cache_dump(200);
                        entries.sort_by(|a, b| a.host.cmp(&b.host).then(a.path.cmp(&b.path)));
                        if entries.is_empty() {
                            "no cached entries\n".to_string()
                        } else {
                            let mut out = String::with_capacity(entries.len() * 80);
                            out.push_str("method host path status body_bytes expires_in_secs\n");
                            for e in entries {
                                out.push_str(&format!(
                                    "{} {} {} {} {} {}\n",
                                    e.method,
                                    e.host,
                                    e.path,
                                    e.status,
                                    e.body_bytes,
                                    e.expires_in_secs,
                                ));
                            }
                            out
                        }
                    } else if method == Method::POST && path == "/admin/cache/purge" {
                        // Phase 3Y.2 — invalidate cache. Query string drives
                        // the filter:
                        //   ?all=1                 → drop everything
                        //   ?host=foo.example      → drop entries for that host
                        //   ?prefix=/api/v1/       → drop entries whose path
                        //                            starts with the prefix
                        //   ?host=...&prefix=...   → both must match
                        // Returns plain-text count of removed entries.
                        let q = query.as_str();
                        let mut host_filter: Option<String> = None;
                        let mut prefix_filter: Option<String> = None;
                        let mut purge_all = false;
                        for pair in q.split('&').filter(|s| !s.is_empty()) {
                            if let Some((k, v)) = pair.split_once('=') {
                                let decoded = urlencoding::decode(v)
                                    .map(|c| c.into_owned())
                                    .unwrap_or_else(|_| v.to_string());
                                match k {
                                    "all" if decoded == "1" || decoded == "true" => {
                                        purge_all = true;
                                    }
                                    "host" => host_filter = Some(decoded),
                                    "prefix" | "path_prefix" => {
                                        prefix_filter = Some(decoded);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        if !purge_all && host_filter.is_none() && prefix_filter.is_none() {
                            status = http::StatusCode::BAD_REQUEST;
                            "missing filter — use ?all=1 or ?host=... or ?prefix=...\n".to_string()
                        } else {
                            let h = handler.read().await.clone();
                            let removed = if purge_all {
                                h.purge_cache(None, None)
                            } else {
                                h.purge_cache(host_filter.as_deref(), prefix_filter.as_deref())
                            };
                            // V21 — also broadcast so other workers
                            // (multi-process deploys) follow within
                            // ~30s via the cleanup-task watch.
                            crate::proxy::response_cache::ResponseCache::broadcast_purge();
                            format!("purged {removed}\n")
                        }
                    } else if method == Method::GET && path == "/admin/xdp" {
                        let c = xdp_h.counters().unwrap_or_default();
                        format!(
                            "xdp_pass {}\nxdp_drop_deny {}\nxdp_drop_rate {}\nxdp_drop_allowonly {}\nxdp_drop_syn {}\nxdp_drop_waf {}\n",
                            c.pass,
                            c.drop_deny,
                            c.drop_rate,
                            c.drop_allowonly,
                            c.drop_syn,
                            c.drop_waf,
                        )
                    } else if method == Method::POST
                        && let Some(ip_str) = path.strip_prefix("/admin/xdp/deny/")
                    {
                        match ip_str.parse::<std::net::IpAddr>() {
                            Ok(std::net::IpAddr::V4(v4)) => match xdp_h.deny_v4(v4) {
                                Ok(()) => "denied v4".to_string(),
                                Err(e) => {
                                    status = http::StatusCode::INTERNAL_SERVER_ERROR;
                                    format!("xdp insert failed: {e}")
                                }
                            },
                            Ok(std::net::IpAddr::V6(v6)) => match xdp_h.deny_v6(v6) {
                                Ok(()) => "denied v6".to_string(),
                                Err(e) => {
                                    status = http::StatusCode::INTERNAL_SERVER_ERROR;
                                    format!("xdp insert failed: {e}")
                                }
                            },
                            Err(_) => {
                                status = http::StatusCode::BAD_REQUEST;
                                "invalid ip".to_string()
                            }
                        }
                    } else if method == Method::POST
                        && let Some(ip_str) = path.strip_prefix("/admin/xdp/undeny/")
                    {
                        match ip_str.parse::<std::net::IpAddr>() {
                            Ok(ip) => match xdp_h.undeny(ip) {
                                Ok(()) => "undenied".to_string(),
                                Err(e) => {
                                    status = http::StatusCode::INTERNAL_SERVER_ERROR;
                                    format!("xdp remove failed: {e}")
                                }
                            },
                            Err(_) => {
                                status = http::StatusCode::BAD_REQUEST;
                                "invalid ip".to_string()
                            }
                        }
                    } else if method == Method::POST && path == "/admin/reload" {
                        // Auto-detect format by extension via dsl::load_any.
                        // If parse/validate fails the live runtime keeps
                        // its previous handler — atomic Reloader::reload
                        // never swaps unless build_handler succeeds.
                        match crate::dsl::load_any(&state.config_path) {
                            Ok((cfg, _summary)) => match state.reloader.reload(&cfg).await {
                                Ok(()) => {
                                    *state.active_cfg.write().await = cfg;
                                    "reloaded".to_string()
                                }
                                Err(e) => {
                                    status = http::StatusCode::INTERNAL_SERVER_ERROR;
                                    format!(
                                        "reload failed: {e}\n\nCurrent runtime config was not changed."
                                    )
                                }
                            },
                            Err(e) => {
                                status = http::StatusCode::BAD_REQUEST;
                                format!(
                                    "config invalid: {e}\n\nCurrent runtime config was not changed."
                                )
                            }
                        }
                    } else if method == Method::POST && path == "/admin/stop" {
                        let _ = state.shutdown_tx.send(());
                        "stopping".to_string()
                    } else {
                        status = http::StatusCode::NOT_FOUND;
                        "not found".to_string()
                    };

                    audit.record(&peer, method.as_str(), &path, granted, status.as_u16());
                    let resp = http::Response::builder()
                        .status(status)
                        .body(
                            http_body_util::Full::new(bytes::Bytes::from(body))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("admin response");
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });
            let _ = Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await;
        });
    }
}

// ─── Web UI + JSON API ───────────────────────────────────────────────

/// Body type matching the admin handler's existing Response<…> shape.
type AdminBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn admin_resp(status: http::StatusCode, ct: &str, body: bytes::Bytes) -> http::Response<AdminBody> {
    use http_body_util::BodyExt;
    http::Response::builder()
        .status(status)
        .header("content-type", ct)
        .header("cache-control", "no-store")
        .body(
            http_body_util::Full::new(body)
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("admin ui response")
}

/// Static-asset routes. Auth-free — the HTML+JS are public, the API
/// calls underneath enforce role + token.
async fn handle_ui_route(
    method: &str,
    path: &str,
    _state: &RuntimeState,
    _granted: Option<crate::config::AdminRole>,
) -> Option<http::Response<AdminBody>> {
    if method != "GET" {
        return None;
    }
    // The Vite bundle is built with `base: "/admin/ui/"`, so all asset
    // URLs are absolute under that prefix. Bare `/` and `/admin/ui`
    // (no trailing slash) get a 301 to `/admin/ui/` so the bundle and
    // its assets load via a single canonical path.
    if path == "/" || path == "/admin/ui" {
        let resp = http::Response::builder()
            .status(http::StatusCode::MOVED_PERMANENTLY)
            .header("location", "/admin/ui/")
            .header("cache-control", "no-store")
            .body(
                http_body_util::Full::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .expect("admin ui redirect");
        return Some(resp);
    }
    if !path.starts_with("/admin/ui") {
        return None;
    }
    // Hashed asset paths under /admin/ui/assets/* hit the embedded
    // dist directly; unknown paths fall back to index.html so deep
    // links into client-side router routes (/admin/ui/sites, …)
    // reload without 404ing.
    let (bytes, ct) = crate::admin_ui::web_asset(path)?;
    Some(admin_resp(
        http::StatusCode::OK,
        ct,
        bytes::Bytes::from_static(bytes),
    ))
}

async fn handle_api_route(
    method: &str,
    path: &str,
    state: &RuntimeState,
    granted: Option<crate::config::AdminRole>,
    req: hyper::Request<hyper::body::Incoming>,
) -> Option<http::Response<AdminBody>> {
    use crate::config::AdminRole;
    use http_body_util::BodyExt;

    if !path.starts_with("/admin/api/") {
        return None;
    }

    // All /admin/api/* require at least Read; mutating endpoints need Write.
    let role_ok = |need: AdminRole| -> bool { matches!(granted, Some(r) if r >= need) };
    let unauthorized = || {
        admin_resp(
            http::StatusCode::UNAUTHORIZED,
            "application/json",
            bytes::Bytes::from(r#"{"error":"unauthorized"}"#),
        )
    };

    // ── Auth endpoints (no role required; verified inline) ──────────
    if method == "POST" && path == "/admin/api/login" {
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        #[derive(serde::Deserialize)]
        struct LoginReq {
            email: String,
            password: String,
        }
        let req: LoginReq = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"invalid JSON"}"#),
                ));
            }
        };
        return Some(match state.web_admin.login(&req.email, &req.password) {
            Some((token, must_change)) => {
                let body = serde_json::json!({
                    "token": token,
                    "email": req.email,
                    "must_change": must_change,
                })
                .to_string();
                admin_resp(
                    http::StatusCode::OK,
                    "application/json",
                    bytes::Bytes::from(body),
                )
            }
            None => admin_resp(
                http::StatusCode::UNAUTHORIZED,
                "application/json",
                bytes::Bytes::from(r#"{"error":"invalid credentials"}"#),
            ),
        });
    }

    if method == "POST" && path == "/admin/api/logout" {
        let supplied = req
            .headers()
            .get("x-admin-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if !supplied.is_empty() {
            state.web_admin.logout(supplied);
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(r#"{"ok":true}"#),
        ));
    }

    if method == "GET" && path == "/admin/api/me" {
        let supplied = req
            .headers()
            .get("x-admin-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        return Some(match state.web_admin.validate(supplied) {
            Some((email, must_change)) => {
                let body = serde_json::json!({
                    "email": email,
                    "must_change": must_change,
                    "auth": "session",
                })
                .to_string();
                admin_resp(
                    http::StatusCode::OK,
                    "application/json",
                    bytes::Bytes::from(body),
                )
            }
            None if !supplied.is_empty()
                && matches!(
                    granted,
                    Some(AdminRole::Read) | Some(AdminRole::Write) | Some(AdminRole::Admin)
                ) =>
            {
                // A valid config token also counts as "logged in"
                // for the panel, but without an email / must_change
                // signal — we expose a synthetic identity so the UI
                // doesn't bounce CLI-token users to /login.
                let body = serde_json::json!({
                    "email": "config-token",
                    "must_change": false,
                    "auth": "config_token",
                })
                .to_string();
                admin_resp(
                    http::StatusCode::OK,
                    "application/json",
                    bytes::Bytes::from(body),
                )
            }
            _ => admin_resp(
                http::StatusCode::UNAUTHORIZED,
                "application/json",
                bytes::Bytes::from(r#"{"error":"not logged in"}"#),
            ),
        });
    }

    if method == "POST" && path == "/admin/api/change-credentials" {
        let supplied = req
            .headers()
            .get("x-admin-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        #[derive(serde::Deserialize)]
        struct ChangeReq {
            current_password: String,
            new_email: String,
            new_password: String,
        }
        let creq: ChangeReq = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"invalid JSON"}"#),
                ));
            }
        };
        return Some(
            match state.web_admin.change_credentials(
                &supplied,
                &creq.current_password,
                &creq.new_email,
                &creq.new_password,
            ) {
                Ok(new_token) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "token": new_token,
                        "email": creq.new_email,
                    })
                    .to_string();
                    admin_resp(
                        http::StatusCode::OK,
                        "application/json",
                        bytes::Bytes::from(body),
                    )
                }
                Err(e) => admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e))),
                ),
            },
        );
    }

    let managed = active_managed_dir(state).await;
    let ops = active_ops_dir(state).await;

    if method == "GET" && path == "/admin/api/sites" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let sites = crate::admin_ui::list_sites(managed.as_deref(), ops.as_deref());
        let body = serde_json::json!({ "sites": sites }).to_string();
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(body),
        ));
    }

    if method == "POST" && path == "/admin/api/sites" {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let Some(managed_dir) = managed.clone() else {
            return Some(admin_resp(
                http::StatusCode::CONFLICT,
                "application/json",
                bytes::Bytes::from(r#"{"error":"admin.managed_sites_dir is not configured"}"#),
            ));
        };
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        let site: crate::admin_ui::NewSite = match serde_json::from_slice(&body) {
            Ok(s) => s,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
                ));
            }
        };
        let dsl = match crate::admin_ui::render_site(&site) {
            Ok(d) => d,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"{}"}}"#, json_escape(&e))),
                ));
            }
        };
        let written = match crate::admin_ui::write_site(&managed_dir, &site) {
            Ok(p) => p,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"{}"}}"#, json_escape(&e))),
                ));
            }
        };
        // Trigger reload — if it fails, roll the file back so the
        // running config matches what aegis thinks is on disk.
        if let Err(e) = reload_from_disk(state).await {
            let _ = std::fs::remove_file(&written);
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"error":"reload failed, change rolled back: {}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        let body = serde_json::json!({
            "ok": true,
            "host": site.host,
            "path": written.to_string_lossy(),
            "dsl_snippet": dsl,
        })
        .to_string();
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(body),
        ));
    }

    if method == "DELETE"
        && let Some(host) = path.strip_prefix("/admin/api/sites/")
    {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let Some(managed_dir) = managed.clone() else {
            return Some(admin_resp(
                http::StatusCode::CONFLICT,
                "application/json",
                bytes::Bytes::from(r#"{"error":"admin.managed_sites_dir is not configured"}"#),
            ));
        };
        let host = urlencoding::decode(host).unwrap_or_default().into_owned();
        if let Err(e) = crate::admin_ui::delete_site(&managed_dir, &host) {
            return Some(admin_resp(
                http::StatusCode::BAD_REQUEST,
                "application/json",
                bytes::Bytes::from(format!(r#"{{"error":"{}"}}"#, json_escape(&e))),
            ));
        }
        if let Err(e) = reload_from_disk(state).await {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"error":"reload failed: {}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(format!(r#"{{"ok":true,"host":"{}"}}"#, json_escape(&host))),
        ));
    }

    if method == "GET" && path == "/admin/api/filters" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let cfg = state.active_cfg.read().await;
        let body = serde_json::json!({
            "filters": {
                "waf":                      { "enabled": cfg.filters.waf.enabled },
                "bot_fingerprint":          { "enabled": cfg.filters.bot.enabled },
                "adaptive_spike_detection": { "enabled": cfg.filters.adaptive.enabled },
                "challenge_ladder":         { "enabled": cfg.filters.challenge.enabled },
                "geoip":                    { "enabled": cfg.geoip.is_some() },
                "xdp":                      { "enabled": cfg.xdp.as_ref().map(|x| x.enabled).unwrap_or(false) },
            }
        })
        .to_string();
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(body),
        ));
    }

    if method == "GET" && path == "/admin/api/audit" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let cfg = state.active_cfg.read().await;
        let log_path = cfg.admin.as_ref().and_then(|a| a.audit_log_path.clone());
        let text = match log_path {
            Some(p) => crate::admin_ui::tail_audit(std::path::Path::new(&p), 200),
            None => String::new(),
        };
        return Some(admin_resp(
            http::StatusCode::OK,
            "text/plain; charset=utf-8",
            bytes::Bytes::from(text),
        ));
    }

    if method == "GET" && path == "/admin/api/config/raw" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let text = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        return Some(admin_resp(
            http::StatusCode::OK,
            "text/plain; charset=utf-8",
            bytes::Bytes::from(text),
        ));
    }

    if method == "PUT" && path == "/admin/api/config/raw" {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        #[derive(serde::Deserialize)]
        struct Wrap {
            content: String,
        }
        let payload: Wrap = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
                ));
            }
        };
        // Dry-run parse against a sibling temp file so a syntax error
        // doesn't corrupt the live config.
        let probe = state.config_path.with_extension("conf.probe");
        if let Err(e) = std::fs::write(&probe, &payload.content) {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"error":"probe write: {}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        let parse_result = crate::dsl::parser::parse_file(&probe);
        let _ = std::fs::remove_file(&probe);
        if let Err(e) = parse_result {
            return Some(admin_resp(
                http::StatusCode::BAD_REQUEST,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"ok":false,"error":"{}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        let path_buf = state.config_path.clone();
        let tmp = path_buf.with_extension("conf.tmp");
        if let Err(e) = std::fs::write(&tmp, &payload.content) {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"error":"write tmp: {}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        if let Err(e) = std::fs::rename(&tmp, &path_buf) {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"error":"rename: {}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(r#"{"ok":true}"#),
        ));
    }

    if method == "POST" && path == "/admin/api/config/test" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        #[derive(serde::Deserialize)]
        struct Wrap {
            content: String,
        }
        let payload: Wrap = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
                ));
            }
        };
        let probe = state.config_path.with_extension("conf.probe");
        let resp = match std::fs::write(&probe, &payload.content) {
            Ok(()) => {
                let r = crate::dsl::parser::parse_file(&probe);
                let _ = std::fs::remove_file(&probe);
                match r {
                    Ok(_) => r#"{"ok":true}"#.to_string(),
                    Err(e) => format!(
                        r#"{{"ok":false,"error":"{}"}}"#,
                        json_escape(&e.to_string())
                    ),
                }
            }
            Err(e) => format!(
                r#"{{"ok":false,"error":"probe write: {}"}}"#,
                json_escape(&e.to_string())
            ),
        };
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(resp),
        ));
    }

    if method == "GET" && path == "/admin/api/runtime/status" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let cfg = state.active_cfg.read().await;
        let mut listeners: Vec<String> = vec![format!("http://{}", cfg.server.listen)];
        if let Some(tls) = &cfg.tls
            && tls.enabled
        {
            listeners.push(format!("https://{}", tls.listen));
            if tls.h3_enabled
                && let Some(h3) = &tls.h3_listen
            {
                listeners.push(format!("h3://{h3}"));
            }
        }
        if let Some(admin) = &cfg.admin {
            listeners.push(format!("admin://{}", admin.listen));
        }
        let sites = crate::admin_ui::list_sites(managed.as_deref(), ops.as_deref());
        let uptime_sec = state.started_at.elapsed().as_secs();
        let body = serde_json::json!({
            "aegis_version": env!("CARGO_PKG_VERSION"),
            "config_path": state.config_path.to_string_lossy(),
            "sites_count": sites.len(),
            "uptime_sec": uptime_sec,
            "listeners": listeners,
        })
        .to_string();
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(body),
        ));
    }

    // ── Honeypot management endpoints ───────────────────────────────
    if method == "GET" && path == "/admin/api/honeypots/builtin" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let packs: Vec<_> = crate::honeypot::BUILTIN_PACKS
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "path_count": p.path_count(),
                })
            })
            .collect();
        let body = serde_json::json!({ "packs": packs }).to_string();
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(body),
        ));
    }

    if method == "GET" && path == "/admin/api/honeypots" {
        if !role_ok(AdminRole::Read) {
            return Some(unauthorized());
        }
        let snap = state.honeypots.snapshot();
        let body = serde_json::to_string(&snap).unwrap_or_else(|_| "{}".to_string());
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(body),
        ));
    }

    if method == "PUT" && path == "/admin/api/honeypots" {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        let new_state: crate::honeypot::HoneypotState = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
                ));
            }
        };
        if let Err(e) = state.honeypots.replace(new_state) {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(
                    r#"{{"error":"write: {}"}}"#,
                    json_escape(&e.to_string())
                )),
            ));
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(r#"{"ok":true}"#),
        ));
    }

    if method == "PUT" && path == "/admin/api/honeypots/global" {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        #[derive(serde::Deserialize)]
        struct Req {
            pack_id: String,
            enabled: bool,
        }
        let r: Req = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
                ));
            }
        };
        if let Err(e) = state.honeypots.set_global_pack(&r.pack_id, r.enabled) {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string()))),
            ));
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(r#"{"ok":true}"#),
        ));
    }

    if method == "PUT" && path == "/admin/api/honeypots/host" {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(r#"{"error":"failed to read body"}"#),
                ));
            }
        };
        #[derive(serde::Deserialize)]
        struct Req {
            host: String,
            pack_id: String,
            enabled: bool,
        }
        let r: Req = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return Some(admin_resp(
                    http::StatusCode::BAD_REQUEST,
                    "application/json",
                    bytes::Bytes::from(format!(r#"{{"error":"invalid JSON: {e}"}}"#)),
                ));
            }
        };
        if let Err(e) = state
            .honeypots
            .set_host_pack(&r.host, &r.pack_id, r.enabled)
        {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string()))),
            ));
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(r#"{"ok":true}"#),
        ));
    }

    if method == "DELETE"
        && let Some(host) = path.strip_prefix("/admin/api/honeypots/host/")
    {
        if !role_ok(AdminRole::Write) {
            return Some(unauthorized());
        }
        let host = urlencoding::decode(host).unwrap_or_default().into_owned();
        if let Err(e) = state.honeypots.clear_host_override(&host) {
            return Some(admin_resp(
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                bytes::Bytes::from(format!(r#"{{"error":"{}"}}"#, json_escape(&e.to_string()))),
            ));
        }
        return Some(admin_resp(
            http::StatusCode::OK,
            "application/json",
            bytes::Bytes::from(r#"{"ok":true}"#),
        ));
    }

    Some(admin_resp(
        http::StatusCode::NOT_FOUND,
        "application/json",
        bytes::Bytes::from(r#"{"error":"unknown api endpoint"}"#),
    ))
}

async fn active_managed_dir(state: &RuntimeState) -> Option<std::path::PathBuf> {
    let cfg = state.active_cfg.read().await;
    cfg.admin
        .as_ref()
        .and_then(|a| a.managed_sites_dir.clone())
        .map(std::path::PathBuf::from)
}

async fn active_ops_dir(state: &RuntimeState) -> Option<std::path::PathBuf> {
    let cfg = state.active_cfg.read().await;
    cfg.admin
        .as_ref()
        .and_then(|a| a.ops_sites_dir.clone())
        .map(std::path::PathBuf::from)
}

async fn reload_from_disk(state: &RuntimeState) -> anyhow::Result<()> {
    let (cfg, _summary) = crate::dsl::load_any(&state.config_path)?;
    state.reloader.reload(&cfg).await?;
    *state.active_cfg.write().await = cfg;
    Ok(())
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
