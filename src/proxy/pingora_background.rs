//! V29 — Background maintenance for aegis-pingora.
//!
//! The hyper server's `cleanup_task` (`server.rs`) does periodic
//! housekeeping that doesn't fit any per-request hook: WAF rule file
//! mtime polling, response-cache broadcast-purge polling, honeypot
//! cleanup, dynamic-trust pruning, etc. aegis-pingora needs the same
//! cadence but pingora owns its runtime, so the work lives in a
//! `BackgroundService` registered alongside the proxy services.
//!
//! Today's scope:
//!
//!   • WAF rule file mtime poll → `WafFilter::maybe_reload_rules()`.
//!     Operators can drop a new rule file in place and see it picked
//!     up within one tick without restarting the worker.
//!   • Dynamic-trust stale-entry eviction → `DynamicTrust::cleanup_stale`.
//!     Trust grants and per-IP observation buckets expire after the
//!     configured window; without this the dashmap would grow
//!     unboundedly under churn.
//!   • V33 — Cross-worker cache purge broadcast →
//!     `ResponseCache::check_broadcast_purge` + `purge_all`.
//!     Multi-process aegis-pingora workers share the cache-broadcast
//!     file (AEGIS_CACHE_BROADCAST); one worker calling
//!     `ResponseCache::broadcast_purge()` bumps the file mtime, all
//!     other workers notice on their next tick and drop their local
//!     cache so the cluster converges within one polling window.
//!
//! Deliberately not implemented yet:
//!   • Honeypot state refresh — `HoneypotStore::check` already
//!     refreshes inline on every request, no background task needed.
//!   • Reputation store flush.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;

use crate::ddos::score::ThreatScorer;
use crate::filters::dynamic_trust::DynamicTrust;
use crate::filters::waf::WafFilter;
use crate::metrics::{RuntimeMetrics, TimeSeriesStore};
use crate::proxy::response_cache::ResponseCache;
use crate::site_map::SiteMap;

/// Polls hot-reload sources on a fixed interval until shutdown.
/// The tick is intentionally coarse (30s by default) — these checks
/// are mtime stat()s and a possible filesystem read, cheap but not
/// free, and an operator dropping a rule file does not need
/// sub-second latency to see it picked up.
pub struct PingoraBackground {
    waf: Arc<WafFilter>,
    trust: Arc<DynamicTrust>,
    cache: Arc<ResponseCache>,
    /// V37 — sliding-window scorer. Stale per-IP buckets get
    /// dropped on each tick so the dashmap stays bounded under
    /// long-lived high-churn traffic.
    scorer: Arc<ThreatScorer>,
    /// V94 — cluster scorer compaction. When Some, each tick walks
    /// both shared v4+v6 maps and tombstones entries idle past
    /// `5 × window` seconds. Bounded slot reclamation under long-lived
    /// daemons. None when SharedScorer isn't wired (non-Linux dev,
    /// arena init failed).
    shared_scorer: Option<Arc<crate::ddos::shared_score::SharedScorer>>,
    /// V107 — online signature miner. None when not wired (always
    /// constructed by `aegis-pingora.rs`; the inner TarpitLogger is
    /// no-op when AEGIS_TARPIT_LOG isn't set, so leaving Some is safe).
    online_miner: Option<Arc<crate::online_signature_miner::OnlineMiner>>,
    /// V60 — TLS cert/key mtime poller. None for HTTP-only
    /// deploys (no AegisTlsAccept built). When Some, the
    /// background tick stat()s every cert/key path and atomically
    /// swaps the in-memory CertStore when any mtime advanced.
    tls: Option<Arc<crate::proxy::pingora_tls::AegisTlsAccept>>,
    /// V140 — JA4 reputation feed reload. When Some, every tick checks
    /// the configured feed paths' mtime and reloads the in-memory
    /// index if any changed. None when AEGIS_JA4_REPUTATION isn't set.
    ja4_reputation: Option<Arc<crate::ja4_reputation::Ja4Reputation>>,
    /// V142 — ASN/CIDR reputation feed reload. Same shape as
    /// ja4_reputation. None when AEGIS_ASN_REPUTATION isn't set.
    asn_reputation: Option<Arc<crate::asn_reputation::AsnReputation>>,
    /// V151 — adversarial loop. When Some, fires every Nth tick
    /// (see [Self::adversarial_every_n_ticks]) and feeds bypass
    /// samples into the V135 MlTrainer.
    adversarial: Option<Arc<crate::ml_adversarial::AdversarialLoop>>,
    /// How many ticks between adversarial runs. Adversarial is
    /// heavier than the other tick work (runs hundreds of mutations);
    /// default = 10 so at the standard 30s tick it fires every 5 min.
    adversarial_every_n_ticks: u32,
    /// Tick counter for the adversarial scheduler.
    tick_counter: std::sync::atomic::AtomicU32,
    interval: Duration,
    /// V197/V199 — optional arsenal handle so the tick can drive
    /// the actuator timer wheel (revert expired actions) and GC
    /// stale scenario buckets.
    arsenal: Option<Arc<crate::arsenal::ArsenalState>>,
    /// TS — fleet-wide time-series sampler. When Some and this worker
    /// holds the advisory writer lock, `sample_once()` is called every
    /// 2nd tick (i.e. every 60 s at the default 30 s tick cadence).
    /// Workers that are not the designated writer call `sample_once()`
    /// and no-op silently. The store is constructed once in `main()`
    /// and cloned via Arc so all services share the same file handles.
    timeseries: Option<Arc<TimeSeriesStore>>,
    /// Parity counter: `sample_once` fires on every 2nd 30 s tick.
    ts_tick_parity: std::sync::atomic::AtomicU8,
    /// V240 — site-map shard flusher. When Some, each tick serialises
    /// this worker's in-memory SiteMap snapshot to its shard file
    /// (`shard-<slot>.json`) so the admin API can aggregate all workers
    /// and the data survives a restart. The SiteMap already holds the
    /// shard path (set via `with_persistence` at startup); flush_shard()
    /// is a no-op when persistence wasn't acquired.
    site_map: Option<Arc<SiteMap>>,
    /// V242 — runtime metrics handle so the tick can flush this worker's
    /// per-country slice to its geo shard (`shard-<slot>.json`) for the
    /// cross-worker world-map aggregation. `flush_geo_shard()` is a no-op
    /// when geo persistence wasn't configured, so this is always safe.
    metrics: Option<Arc<RuntimeMetrics>>,
    /// H2 — rate-limiter stale-entry eviction. The deployed pingora path
    /// previously never called `RateLimitFilter::cleanup_stale`, so the
    /// per-IP / per-URI maps only shed memory via their hard caps. When
    /// Some, each tick prunes idle buckets so memory is released after a
    /// flood subsides. None is safe (no cleanup, caps still bound growth).
    rate: Option<Arc<crate::filters::rate_limit::RateLimitFilter>>,
}

impl PingoraBackground {
    pub fn new(
        waf: Arc<WafFilter>,
        trust: Arc<DynamicTrust>,
        cache: Arc<ResponseCache>,
        scorer: Arc<ThreatScorer>,
    ) -> Self {
        Self {
            waf,
            trust,
            cache,
            scorer,
            shared_scorer: None,
            online_miner: None,
            tls: None,
            ja4_reputation: None,
            asn_reputation: None,
            adversarial: None,
            adversarial_every_n_ticks: 10,
            tick_counter: std::sync::atomic::AtomicU32::new(0),
            interval: Duration::from_secs(30),
            arsenal: None,
            timeseries: None,
            ts_tick_parity: std::sync::atomic::AtomicU8::new(0),
            site_map: None,
            metrics: None,
            rate: None,
        }
    }

    /// H2 — register the rate-limiter so the tick can evict its stale
    /// per-IP / per-URI buckets (the deployed pingora path otherwise never
    /// calls `cleanup_stale`). No-op-safe when omitted.
    pub fn with_rate(mut self, rate: Arc<crate::filters::rate_limit::RateLimitFilter>) -> Self {
        self.rate = Some(rate);
        self
    }

    pub fn with_arsenal(mut self, arsenal: Arc<crate::arsenal::ArsenalState>) -> Self {
        self.arsenal = Some(arsenal);
        self
    }

    /// TS — register the fleet-wide time-series store for periodic
    /// sampling. The background tick calls `store.sample_once()` every
    /// 60 s (every 2nd 30 s tick). Only the worker holding the advisory
    /// writer lock persists; the rest no-op silently.
    pub fn with_timeseries(mut self, store: Arc<TimeSeriesStore>) -> Self {
        self.timeseries = Some(store);
        self
    }

    /// V151 — register the adversarial loop. Fires every
    /// `every_n_ticks` ticks (10 at default 30s tick → 5 min cadence).
    pub fn with_adversarial(
        mut self,
        loop_: Arc<crate::ml_adversarial::AdversarialLoop>,
        every_n_ticks: u32,
    ) -> Self {
        self.adversarial = Some(loop_);
        self.adversarial_every_n_ticks = every_n_ticks.max(1);
        self
    }

    /// V140 — register the JA4 reputation feed for periodic mtime
    /// polling. Each tick reloads the feed if any configured file
    /// changed; misses preserve the prior in-memory index (safe
    /// against reload races).
    pub fn with_ja4_reputation(mut self, r: Arc<crate::ja4_reputation::Ja4Reputation>) -> Self {
        self.ja4_reputation = Some(r);
        self
    }

    /// V142 — register the ASN/CIDR reputation feed for periodic
    /// mtime polling. Same reload-race safety as V140.
    pub fn with_asn_reputation(mut self, r: Arc<crate::asn_reputation::AsnReputation>) -> Self {
        self.asn_reputation = Some(r);
        self
    }

    /// V94 — register the cluster-wide SharedScorer for periodic
    /// compaction. When unset, the per-worker scorer still gets
    /// cleaned on each tick; only the shared-map tombstone reclamation
    /// is skipped.
    pub fn with_shared_scorer(mut self, s: Arc<crate::ddos::shared_score::SharedScorer>) -> Self {
        self.shared_scorer = Some(s);
        self
    }

    /// V107 — register the online signature miner. Each background
    /// tick runs `OnlineMiner::run_once()` (cheap: tails the tarpit
    /// log + snapshots the benign sampler + runs the miner once).
    /// When the tarpit log isn't configured this is effectively a
    /// no-op (TarpitLogger::tail returns empty on a None path).
    pub fn with_online_miner(mut self, m: Arc<crate::online_signature_miner::OnlineMiner>) -> Self {
        self.online_miner = Some(m);
        self
    }

    /// V60 — register an AegisTlsAccept for periodic cert mtime
    /// polling. Returns self so the binary can chain it before
    /// handing the service to pingora.
    pub fn with_tls(mut self, tls: Arc<crate::proxy::pingora_tls::AegisTlsAccept>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// V240 — register the SiteMap for periodic shard flushing.
    /// Each 30 s tick serialises the worker's in-memory snapshot to
    /// its slot file so the admin API can produce a stable aggregate
    /// across all SO_REUSEPORT workers. The SiteMap must already have
    /// had `with_persistence` called on it (done in `aegis-pingora.rs`
    /// at startup); if persistence was not acquired `flush_shard()` is
    /// a no-op, so registering here is always safe.
    pub fn with_site_map(mut self, sm: Arc<SiteMap>) -> Self {
        self.site_map = Some(sm);
        self
    }

    /// V242 — register the RuntimeMetrics so the tick flushes this worker's
    /// per-country counters to its geo shard for cross-worker world-map
    /// aggregation. The metrics must already have had `with_geo_persistence`
    /// called on it (done in `aegis-pingora.rs` at startup); if geo
    /// persistence was not acquired `flush_geo_shard()` is a no-op, so
    /// registering here is always safe.
    pub fn with_metrics(mut self, metrics: Arc<RuntimeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Override the tick interval (used by tests; production uses
    /// the 30s default which matches the hyper server's cleanup_task).
    #[cfg(test)]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

#[async_trait]
impl BackgroundService for PingoraBackground {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut ticker = tokio::time::interval(self.interval);
        // The default tokio MissedTickBehavior::Burst would fire
        // back-to-back if the runtime falls behind, which would mean
        // a flurry of redundant maybe_reload checks. Delay catches
        // up by skipping missed ticks instead — strictly safer for
        // mtime polling.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // V230 — cache env-gated feature flags at startup so the
        // per-tick branches can skip idle work without a syscall
        // (env::var per tick is itself wasteful). The inner methods
        // are already no-ops when the env isn't set, but gating at
        // the call site means we don't even take the function call,
        // an Arc deref, and any allocator chatter inside.
        let tarpit_log_enabled = std::env::var("AEGIS_TARPIT_LOG")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let cache_broadcast_enabled = std::env::var("AEGIS_CACHE_BROADCAST")
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::debug!("aegis-pingora background service: shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let reloaded = self.waf.maybe_reload_rules();
                    if reloaded > 0 {
                        tracing::info!(
                            files = reloaded,
                            "aegis-pingora WAF rules reloaded via mtime poll"
                        );
                    }
                    // V30 — bound dynamic-trust memory growth. Stale
                    // observation buckets + expired trust grants get
                    // dropped from the dashmap each tick; no-op when
                    // dynamic_trust is disabled in config (cleanup
                    // walks an empty map).
                    self.trust.cleanup_stale(Instant::now());

                    // H2 — release rate-limiter buckets idle past the
                    // stale window. No-op when not wired; hard caps still
                    // bound growth regardless.
                    if let Some(rate) = &self.rate {
                        rate.cleanup_stale(Instant::now());
                    }

                    // V197/V199 — arsenal-side maintenance: drive
                    // the actuator timer wheel and GC stale scenario
                    // buckets. Both are no-ops when arsenal unset.
                    if let Some(arsenal) = &self.arsenal {
                        use std::sync::atomic::Ordering;
                        let reverted = arsenal.actuators.tick();
                        if reverted > 0 {
                            arsenal
                                .counters
                                .actuator_reverts_expired
                                .fetch_add(reverted as u64, Ordering::Relaxed);
                        }
                        // Scenario buckets idle > 10 min get dropped.
                        let _ = arsenal.scenarios.gc(Duration::from_secs(600));
                        // V246 — cross-worker scenario propagation: a panel
                        // "Load" writes the YAML on one worker; every other
                        // worker picks it up here via mtime poll.
                        let _ = arsenal.scenarios.maybe_reload();
                    }

                    // V33 — cross-worker cache purge broadcast.
                    // `check_broadcast_purge` returns true iff another
                    // worker bumped the broadcast file mtime since we
                    // last checked; on true, drop the entire local
                    // cache so the cluster converges within one tick.
                    // V230 — gated on AEGIS_CACHE_BROADCAST at startup
                    // so we skip the stat() syscall entirely when the
                    // broadcast file isn't configured (previously we
                    // relied on the inner method returning false, but
                    // that still cost a method call + path check per
                    // tick across every worker).
                    if cache_broadcast_enabled && self.cache.check_broadcast_purge() {
                        let dropped = self.cache.purge_all();
                        tracing::info!(
                            entries = dropped,
                            "aegis-pingora cache purged via cross-worker broadcast"
                        );
                    }

                    // V37 — bound the scorer dashmap. IPs that
                    // haven't sent traffic in 5× the sliding window
                    // get dropped; live IPs keep their scores. Cheap
                    // walk + retain.
                    self.scorer.cleanup_stale(Instant::now());

                    // V94 — same compaction discipline for the cluster
                    // SharedScorer. Each worker ticks every 30s, so the
                    // 4-worker REUSEPORT deployment hits compaction ~7s
                    // per worker on average — well under the operational
                    // need (sliding window is 60s).
                    if let Some(ss) = &self.shared_scorer {
                        let removed = ss.cleanup_stale(Instant::now());
                        if removed > 0 {
                            tracing::debug!(
                                removed,
                                "aegis-pingora SharedScorer compacted stale entries"
                            );
                            crate::shared_state::global::cluster_bump_n(
                                crate::shared_state::global::cluster_idx::COMPACTIONS_REMOVED,
                                removed as u64,
                            );
                        }
                        crate::shared_state::global::cluster_bump(
                            crate::shared_state::global::cluster_idx::COMPACTIONS_TOTAL,
                        );
                    }

                    // V107 — online signature miner. Tails the tarpit
                    // log + mines against benign sample.
                    // V230 — gated on AEGIS_TARPIT_LOG at startup so
                    // we skip the Arc deref + miner method call + the
                    // TarpitLogger::tail no-op walk entirely when the
                    // tarpit log isn't configured. Previously the inner
                    // run_once() returned 0 quickly but still allocated
                    // the empty Vec and locked the benign sampler.
                    if tarpit_log_enabled {
                        if let Some(m) = &self.online_miner {
                            let n = m.run_once();
                            if n > 0 {
                                tracing::info!(
                                    candidates = n,
                                    "online_signature_miner: produced candidates"
                                );
                            }
                        }
                    }

                    // V60 — cert/key mtime poll. When the operator
                    // overwrites a cert file on disk (Let's Encrypt
                    // renew, manual rotation, etc.) the swap takes
                    // effect on the next handshake without process
                    // restart. No-op when there's no TLS listener.
                    if let Some(tls) = &self.tls {
                        let _ = tls.maybe_reload_certs();
                    }

                    // V140 — JA4 reputation feed reload. Cheap walk +
                    // file read on tick; reload() is mtime-aware
                    // internally so a no-change cycle is essentially
                    // a stat() per configured path.
                    if let Some(rep) = &self.ja4_reputation {
                        rep.reload();
                    }

                    // V142 — ASN/CIDR reputation feed reload.
                    if let Some(rep) = &self.asn_reputation {
                        rep.reload();
                    }

                    // V151 — adversarial loop, fired every Nth tick.
                    // Heavier than the rest of the tick work (runs
                    // hundreds of mutations); the per-tick gating
                    // keeps CPU steady. Bypasses go into the V135
                    // trainer; operator triggers retrain on schedule.
                    if let Some(adv) = &self.adversarial {
                        let n = self
                            .tick_counter
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if n % self.adversarial_every_n_ticks == 0 {
                            let _ = adv.run_once();
                        }
                    }

                    // TS — fleet-wide time-series sampler. Fires every
                    // 2nd 30 s tick (= 60 s) so the 1-minute ring gets
                    // one record per minute. `sample_once()` is a no-op
                    // on workers that don't hold the writer lock — safe
                    // to call unconditionally on all workers.
                    if let Some(ts) = &self.timeseries {
                        let parity = self.ts_tick_parity
                            .fetch_xor(1, std::sync::atomic::Ordering::Relaxed);
                        if parity == 0 {
                            ts.sample_once();
                        }
                    }

                    // V240 — site-map shard flush. Each worker writes its
                    // own snapshot to shard-<slot>.json every tick (~30 s).
                    // The admin API reads all shards and merges them so the
                    // aggregate is stable regardless of which worker answers.
                    // flush_shard() is a no-op when persistence was not
                    // acquired (slot acquisition failed or never called).
                    if let Some(sm) = &self.site_map {
                        sm.flush_shard();
                    }

                    // V242 — geo-shard flush. Each worker writes its own
                    // by_country slice to shard-<slot>.json every tick so the
                    // admin geo/top endpoint can merge all workers and the
                    // world-map dot counts stay stable poll-to-poll under
                    // SO_REUSEPORT. No-op when geo persistence wasn't acquired.
                    if let Some(m) = &self.metrics {
                        m.flush_geo_shard();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafConfig;

    #[test]
    fn builder_holds_supplied_deps() {
        let waf = Arc::new(WafFilter::new(&WafConfig::default()));
        let trust = Arc::new(DynamicTrust::new(
            &crate::config::DynamicTrustConfig::default(),
        ));
        let cache = Arc::new(ResponseCache::new(
            &crate::config::ResponseCacheConfig::default(),
        ));
        let scorer = Arc::new(ThreatScorer::default());
        let bg = PingoraBackground::new(waf.clone(), trust.clone(), cache.clone(), scorer.clone())
            .with_interval(Duration::from_millis(10));
        assert!(Arc::ptr_eq(&waf, &bg.waf));
        assert!(Arc::ptr_eq(&trust, &bg.trust));
        assert!(Arc::ptr_eq(&cache, &bg.cache));
        assert!(Arc::ptr_eq(&scorer, &bg.scorer));
        assert_eq!(bg.interval, Duration::from_millis(10));
    }
}
