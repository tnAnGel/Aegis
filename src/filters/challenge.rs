use super::{ChallengeLevel, FilterAction, TrafficFilter};
use crate::{config::ChallengeConfig, proxy::request_context::RequestContext};
use dashmap::DashMap;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

/// Tracks per-IP challenge attempts and decides which rung of the
/// ladder to serve next. Verification itself lives in
/// `ProxyHttpHandler::challenge_verified` (signed-token + nonce check).
/// This filter is intentionally ignorant of any "I'm verified" header —
/// trusting a self-asserted header would let bots skip the whole ladder
/// with one line.
pub struct ChallengeFilter {
    enabled: bool,
    ttl: Duration,
    /// Keyed by (IP, UA-prefix-hash) so a misbehaving client can't
    /// reset the ladder by closing the keep-alive and reconnecting.
    /// A fresh IP starts at level 0; a fresh UA from the same IP
    /// does not — the operator's intent is "this client is being
    /// difficult", which UA rotation doesn't change.
    state: Arc<DashMap<FpKey, (u8, Instant)>>,
}

type FpKey = (IpAddr, u64);

fn fp_key(ctx: &RequestContext) -> FpKey {
    let ua_prefix = ctx
        .user_agent
        .as_deref()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let mut h = DefaultHasher::new();
    ua_prefix.hash(&mut h);
    (ctx.client_ip, h.finish())
}

impl ChallengeFilter {
    pub fn new(cfg: &ChallengeConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            ttl: Duration::from_secs(cfg.token_ttl_secs),
            // V230 — boost shard count to reduce contention under load.
            state: Arc::new(DashMap::with_shard_amount(128)),
        }
    }

    /// V231 — the configured (`ChallengeConfig.enabled`) state, false by
    /// default. `FilterEngine::new` seeds the engine's `RuntimeToggles`
    /// challenge toggle from this so the per-domain override
    /// (`domain_policy.filter_enabled["challenge"]`) can flip the engine
    /// gate. The filter itself no longer self-gates on `enabled` — the
    /// engine toggle is the single source of truth.
    pub fn config_enabled(&self) -> bool {
        self.enabled
    }

    /// Forget all escalation history for `ip`. Called by the handler
    /// after a successful signed-token verification so a human that
    /// solved the challenge starts fresh on the next escalation window.
    /// Resets every UA fingerprint for this IP — the verification
    /// proves a real browser is at the wheel.
    pub fn reset(&self, ip: IpAddr) {
        self.state.retain(|k, _| k.0 != ip);
    }

    /// Snapshot of the current escalation level for `ip`, useful for
    /// telemetry and tests. None means no in-flight challenge.
    #[allow(dead_code)]
    pub fn level_for(&self, ip: IpAddr, now: Instant) -> Option<ChallengeLevel> {
        let max = self
            .state
            .iter()
            .filter(|kv| kv.key().0 == ip && now.duration_since(kv.value().1) <= self.ttl)
            .map(|kv| kv.value().0)
            .max()?;
        Some(Self::level_from_count(max))
    }

    /// Drop entries that haven't been touched in `stale`. Called from
    /// the background cleanup task so escalation state doesn't
    /// accumulate forever.
    pub fn cleanup_stale(&self, now: Instant, stale: Duration) {
        self.state.retain(|_, v| now.duration_since(v.1) <= stale);
    }

    fn level_from_count(count: u8) -> ChallengeLevel {
        match count {
            0..=1 => ChallengeLevel::Headers,
            2..=3 => ChallengeLevel::Html,
            4..=5 => ChallengeLevel::Iframe,
            6..=7 => ChallengeLevel::Javascript,
            _ => ChallengeLevel::Captcha,
        }
    }
}

impl TrafficFilter for ChallengeFilter {
    fn name(&self) -> &'static str {
        "challenge"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // V231 — no internal `enabled` gate: the engine's RuntimeToggles
        // (seeded from `config_enabled()`) decides whether `check()` runs
        // at all, so the per-domain override actually takes effect.
        // Dynamic-trust IPs don't need re-challenging — they've already
        // demonstrated long-term clean behaviour. WAF/honeypot still
        // run, so an attack is caught regardless of trust state.
        if ctx.is_trusted {
            return FilterAction::Allow;
        }
        let now = ctx.timestamp;
        let mut e = self.state.entry(fp_key(ctx)).or_insert((0, now));
        if now.duration_since(e.1) > self.ttl {
            e.0 = 0;
            e.1 = now;
        }
        e.0 = e.0.saturating_add(1);
        e.1 = now;
        let level = Self::level_from_count(e.0);
        FilterAction::Challenge {
            level: level.clone(),
            reason: format!("challenge level {:?}", level).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make() -> ChallengeFilter {
        ChallengeFilter::new(&ChallengeConfig {
            enabled: true,
            token_ttl_secs: 300,
            hmac_secret: "x".to_string(),
            captcha_site_key: None,
            captcha_secret: None,
            fp_ttl_secs: 86_400,
            cookie_secure: false,
        })
    }

    #[test]
    fn unverified_request_always_gets_a_challenge() {
        let f = make();
        // No more spoofable "verified" header — only signed tokens count.
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_header("x-aegis-verify", "ok");
        assert!(matches!(f.check(&ctx), FilterAction::Challenge { .. }));
    }

    #[test]
    fn levels_escalate_with_attempts() {
        let f = make();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        let first = f.check(&ctx);
        for _ in 0..10 {
            f.check(&ctx);
        }
        let last = f.check(&ctx);
        match (first, last) {
            (
                FilterAction::Challenge { level: l1, .. },
                FilterAction::Challenge { level: l2, .. },
            ) => assert!(matches!(
                (l1, l2),
                (ChallengeLevel::Headers, ChallengeLevel::Captcha)
            )),
            other => panic!("expected escalation, got {other:?}"),
        }
    }

    #[test]
    fn reset_drops_escalation_history() {
        let f = make();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        for _ in 0..6 {
            f.check(&ctx);
        }
        f.reset(ctx.client_ip);
        match f.check(&ctx) {
            FilterAction::Challenge { level, .. } => {
                assert!(matches!(level, ChallengeLevel::Headers))
            }
            other => panic!("expected fresh ladder, got {other:?}"),
        }
    }

    #[test]
    fn disabled_config_reports_disabled() {
        // V231 — a disabled config no longer self-gates `check()`; the
        // engine toggle (seeded from `config_enabled()`) gates instead.
        // So we assert the reported config state, not `check()`'s output.
        let f = ChallengeFilter::new(&ChallengeConfig {
            enabled: false,
            token_ttl_secs: 1,
            hmac_secret: "x".to_string(),
            captcha_site_key: None,
            captcha_secret: None,
            fp_ttl_secs: 86_400,
            cookie_secure: false,
        });
        assert!(!f.config_enabled());
    }
}
