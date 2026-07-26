use super::{ChallengeLevel, FilterAction, TrafficFilter};
use crate::{config::BotConfig, proxy::request_context::RequestContext};
use dashmap::DashMap;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, Instant},
};

/// Hard cap on the per-fingerprint reputation table — beyond this we
/// drop the oldest entries to prevent a fingerprint-rotating attacker
/// from blowing memory. Sized so each entry is ~40 bytes → ~4 MiB at
/// 100k entries, comfortable on any production box.
const MAX_REP_ENTRIES: usize = 100_000;
const EVICT_BATCH: usize = 8_192;

#[derive(Debug, Clone)]
struct RepEntry {
    score: u32,
    deny_until: Option<Instant>,
    last_seen: Instant,
}

pub struct BotFilter {
    enabled: bool,
    challenge_score: u32,
    deny_score: u32,
    penalty: Duration,
    rep: Arc<DashMap<u64, RepEntry>>,
}

impl BotFilter {
    pub fn new(cfg: &BotConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            challenge_score: cfg.challenge_score,
            deny_score: cfg.deny_score,
            penalty: Duration::from_secs(cfg.penalty_seconds),
            // V230 — boost shard count to reduce contention on hot reputation map.
            rep: Arc::new(DashMap::with_shard_amount(128)),
        }
    }

    /// V231 — config-time enable state, recorded into `RuntimeToggles` by
    /// `FilterEngine::new`. `check()` no longer self-gates on `enabled`;
    /// the engine's `RuntimeToggles` (+ per-domain `domain_policy`) is the
    /// single source of truth so per-domain force-enable overrides work.
    pub fn config_enabled(&self) -> bool {
        self.enabled
    }

    /// Cap unbounded growth. Called from the background cleanup task —
    /// drops entries whose `last_seen` is older than `stale` and, if
    /// the table is still over `MAX_REP_ENTRIES`, drops the oldest
    /// EVICT_BATCH entries (cheap approximation of LRU eviction).
    pub fn cleanup_stale(&self, now: Instant, stale: Duration) {
        self.rep
            .retain(|_, e| now.duration_since(e.last_seen) <= stale);
        if self.rep.len() > MAX_REP_ENTRIES {
            let mut by_age: Vec<(u64, Instant)> = self
                .rep
                .iter()
                .map(|kv| (*kv.key(), kv.value().last_seen))
                .collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (k, _) in by_age.iter().take(EVICT_BATCH) {
                self.rep.remove(k);
            }
        }
    }

    /// Stable per-client fingerprint. Intentionally excludes `path` —
    /// a botnet that rotates URLs wouldn't accumulate reputation
    /// otherwise. UA-major version + language family + encoding set is
    /// stable across a session even when query strings vary.
    fn fp(ctx: &RequestContext) -> u64 {
        // Hash the four discriminator pieces directly into the same
        // hasher — saves one `format!()` allocation per request (was
        // a hot-path string build before).
        let ua = ctx.user_agent.as_deref().unwrap_or("");
        let ua_prefix = ua.split('/').next().unwrap_or(ua);
        let lang = ctx
            .headers
            .get("accept-language")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .split(',')
            .next()
            .unwrap_or("")
            .trim();
        let enc = ctx
            .headers
            .get("accept-encoding")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let mut h = DefaultHasher::new();
        ctx.client_ip.hash(&mut h);
        ua_prefix.hash(&mut h);
        lang.hash(&mut h);
        enc.hash(&mut h);
        h.finish()
    }

    fn score(ctx: &RequestContext) -> u32 {
        let mut s = 0;
        let ua = ctx.user_agent.as_deref().unwrap_or("").to_ascii_lowercase();
        if ua.is_empty() {
            s += 25;
        }
        for b in [
            "curl",
            "python-requests",
            "sqlmap",
            "nikto",
            "nmap",
            "wget",
            "httpclient",
        ] {
            if ua.contains(b) {
                s += 35;
            }
        }
        if ctx.path.len() > 2048 {
            s += 20;
        }
        let p = ctx.path.to_ascii_lowercase();
        for pat in [
            "union select",
            " or 1=1",
            "<script",
            "../",
            "/etc/passwd",
            "cmd=",
        ] {
            if p.contains(pat) {
                s += 30;
            }
        }
        s
    }
}

impl TrafficFilter for BotFilter {
    fn name(&self) -> &'static str {
        "bot"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // Bot reputation tracking is throttling-class — a trusted IP
        // (earned via dynamic-trust) bypasses it. The WAF still runs
        // for trusted IPs so an attack would still be caught.
        if ctx.is_trusted {
            return FilterAction::Allow;
        }
        let fp = Self::fp(ctx);
        let base = Self::score(ctx);
        let now = ctx.timestamp;
        let mut e = self.rep.entry(fp).or_insert(RepEntry {
            score: 0,
            deny_until: None,
            last_seen: now,
        });
        e.last_seen = now;
        if let Some(until) = e.deny_until
            && until > now
        {
            return FilterAction::Deny {
                status: 403,
                reason: "bot reputation denied".into(),
            };
        }
        e.score = e.score.saturating_add(base);
        if e.score >= self.deny_score {
            e.deny_until = Some(now + self.penalty);
            return FilterAction::Deny {
                status: 403,
                reason: "bot reputation denied".into(),
            };
        }
        if e.score >= self.challenge_score {
            return FilterAction::Challenge {
                level: ChallengeLevel::Javascript,
                reason: "bot challenge".into(),
            };
        }
        FilterAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(challenge: u32, deny: u32) -> BotFilter {
        BotFilter::new(&BotConfig {
            enabled: true,
            challenge_score: challenge,
            deny_score: deny,
            penalty_seconds: 60,
        })
    }

    #[test]
    fn known_bot_ua_eventually_denies() {
        let f = make(60, 90);
        // sqlmap UA adds 35 per hit, accumulates across requests
        for _ in 0..2 {
            let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("sqlmap/1.0");
            f.check(&ctx);
        }
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("sqlmap/1.0");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn benign_browser_allowed() {
        let f = make(60, 90);
        let ctx = RequestContext::test_with("1.1.1.1", "/")
            .with_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X)");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }

    #[test]
    fn disabled_reports_config_state() {
        // V231 — `check()` no longer self-gates; the engine's
        // `RuntimeToggles` owns enable/disable. A disabled filter must
        // still report its config state via `config_enabled()`.
        let f = BotFilter::new(&BotConfig {
            enabled: false,
            challenge_score: 1,
            deny_score: 2,
            penalty_seconds: 1,
        });
        assert!(!f.config_enabled());
    }

    #[test]
    fn challenge_threshold_triggers() {
        let f = make(35, 100);
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("curl/8.0");
        assert!(matches!(f.check(&ctx), FilterAction::Challenge { .. }));
    }
}
