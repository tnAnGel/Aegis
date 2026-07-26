use super::{ChallengeLevel, FilterAction, TrafficFilter};
use crate::{config::AdaptiveConfig, proxy::request_context::RequestContext};
use dashmap::DashMap;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

type AdaptiveEntry = (u64, Instant, Option<Instant>);

/// Exempt path matcher: `/foo` exact or `/foo/*` prefix.
enum PathMatcher {
    Exact(String),
    Prefix(String),
}

impl PathMatcher {
    fn from(p: &str) -> Self {
        if let Some(prefix) = p.strip_suffix('*') {
            Self::Prefix(prefix.to_string())
        } else {
            Self::Exact(p.to_string())
        }
    }
    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(s) => s == path,
            Self::Prefix(p) => path.starts_with(p),
        }
    }
}

pub struct AdaptiveFilter {
    enabled: bool,
    threshold: u64,
    penalty: Duration,
    exempt: Vec<PathMatcher>,
    state: Arc<DashMap<IpAddr, AdaptiveEntry>>,
}

impl AdaptiveFilter {
    pub fn new(cfg: &AdaptiveConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            threshold: cfg.suspicious_rps_threshold,
            penalty: Duration::from_secs(cfg.penalty_seconds),
            exempt: cfg
                .exempt_paths
                .iter()
                .map(|s| PathMatcher::from(s))
                .collect(),
            // V230 — boost shard count to reduce contention under high concurrency
            state: Arc::new(DashMap::with_shard_amount(128)),
        }
    }

    /// V231 — exposes the static config enable flag so `FilterEngine::new`
    /// can register this filter's `RuntimeToggles` entry with the real
    /// config state. `RuntimeToggles`/per-domain `domain_policy` are now the
    /// single source of truth for enable/disable; `check()` no longer self-gates.
    pub fn config_enabled(&self) -> bool {
        self.enabled
    }
}

impl TrafficFilter for AdaptiveFilter {
    fn name(&self) -> &'static str {
        "adaptive"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // V231 — no `self.enabled` gate here: RuntimeToggles/domain_policy
        // own enable/disable. `config_enabled()` feeds the toggle registry.
        // Exempt paths bypass the RPS gate entirely — typically
        // monitoring endpoints (/health, /metrics) that legitimately
        // get hit by load balancers many times per second.
        let bare = ctx.path.split('?').next().unwrap_or(&ctx.path);
        if self.exempt.iter().any(|m| m.matches(bare)) {
            return FilterAction::Allow;
        }
        let now = ctx.timestamp;
        let mut entry = self.state.entry(ctx.client_ip).or_insert((0, now, None));
        if let Some(until) = entry.2
            && until > now
        {
            return FilterAction::Challenge {
                level: ChallengeLevel::Javascript,
                reason: "adaptive challenge".into(),
            };
        }
        if now.duration_since(entry.1) >= Duration::from_secs(1) {
            entry.0 = 0;
            entry.1 = now;
            entry.2 = None;
        }
        entry.0 += 1;
        if entry.0 > self.threshold {
            entry.2 = Some(now + self.penalty);
            return FilterAction::Challenge {
                level: ChallengeLevel::Javascript,
                reason: "adaptive challenge".into(),
            };
        }
        FilterAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(threshold: u64) -> AdaptiveFilter {
        AdaptiveFilter::new(&AdaptiveConfig {
            enabled: true,
            suspicious_rps_threshold: threshold,
            penalty_seconds: 10,
            exempt_paths: Vec::new(),
        })
    }

    #[test]
    fn under_threshold_allows() {
        let f = make(100);
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        for _ in 0..10 {
            assert_eq!(f.check(&ctx), FilterAction::Allow);
        }
    }

    #[test]
    fn spike_triggers_challenge() {
        let f = make(5);
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        for _ in 0..5 {
            f.check(&ctx);
        }
        assert!(matches!(f.check(&ctx), FilterAction::Challenge { .. }));
    }

    #[test]
    fn exempt_path_bypasses_threshold() {
        let f = AdaptiveFilter::new(&AdaptiveConfig {
            enabled: true,
            suspicious_rps_threshold: 1,
            penalty_seconds: 10,
            exempt_paths: vec!["/health".to_string(), "/metrics/*".to_string()],
        });
        let ctx1 = RequestContext::test_with("1.1.1.1", "/health");
        for _ in 0..100 {
            assert_eq!(f.check(&ctx1), FilterAction::Allow);
        }
        let ctx2 = RequestContext::test_with("1.1.1.1", "/metrics/cpu");
        for _ in 0..100 {
            assert_eq!(f.check(&ctx2), FilterAction::Allow);
        }
        // Non-exempt path still throttles.
        let ctx3 = RequestContext::test_with("1.1.1.1", "/api");
        f.check(&ctx3);
        assert!(matches!(f.check(&ctx3), FilterAction::Challenge { .. }));
    }

    #[test]
    fn disabled_reports_config_disabled() {
        // V231 — `check()` no longer self-gates on the enable flag; the
        // engine's RuntimeToggles owns enable/disable. Assert the static
        // config flag is surfaced via `config_enabled()` instead.
        let f = AdaptiveFilter::new(&AdaptiveConfig {
            enabled: false,
            suspicious_rps_threshold: 1,
            penalty_seconds: 10,
            exempt_paths: Vec::new(),
        });
        assert!(!f.config_enabled());
    }
}
