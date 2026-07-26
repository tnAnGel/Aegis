//! V108 — Unified Risk Engine.
//!
//! Architectural shift: pre-V108 every filter (WAF, bot, adaptive,
//! challenge, ml_scorer, threat_intel, honeypot) made an independent
//! `Allow / Deny / Challenge` decision and short-circuited the
//! pipeline. That is fast but blind to L7 attacks that are visible
//! only as the *sum* of weak signals — rare JA4 + empty Accept-Language
//! + URI entropy + 404 burst etc.
//!
//! V108 introduces [RiskEngine]: a single explainable scoring
//! component that takes all signals as input and emits
//! `RiskDecision { score, action, reasons }`. Operators see WHY a
//! request was challenged or denied (the reasons vector), which closes
//! the V99/V107 self-improving loop with human-interpretable evidence.
//!
//! Phasing — info.md prescribes three rollout stages:
//!
//! 1. **observe-only** — score computed + logged, action NOT applied.
//!    This is the default. Operators eyeball metrics for a week.
//! 2. **high-confidence enforcement** — only score ≥ ENFORCE_THRESHOLD
//!    flips the request to deny. Lower scores fall through to legacy
//!    per-filter decisions.
//! 3. **full enforcement** — risk action replaces all per-filter
//!    short-circuits. This is V109+ scope once shadow mode (also V109)
//!    proves the rules don't cause regressions.
//!
//! V108 ships stages 1 + 2. Stage 3 is gated on the WAF shadow
//! mode + per-rule metrics from V109.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    filters::{ChallengeLevel, FilterAction},
    proxy::request_context::RequestContext,
};

/// Default enforcement threshold. Scores ≥ this trigger the risk
/// engine's action. Below threshold the engine logs but returns
/// `RiskAction::Allow` so the legacy per-filter pipeline runs.
pub const DEFAULT_ENFORCE_THRESHOLD: u8 = 90;

/// Stable placeholder `rule_id` used while Observe-mode wiring is in place
/// but per-rule WAF severity is not yet threaded through (the WAF filter
/// currently exposes only a fired/not-fired name via
/// `evaluate_with_attribution`, not a severity). Lets operators filter
/// this label out of SIEM aggregation during the Observe phase; it is
/// replaced by real rule ids when `WafFilter::last_match_signal()` lands.
pub const WAF_SIGNAL_PLACEHOLDER: &str = "waf_placeholder_v108";

/// Aggregated input signals. All fields are Optional so the engine
/// can be called with partial state (e.g. WAF didn't run because
/// the request was already short-circuited at IP ACL).
#[derive(Debug, Default, Clone)]
pub struct RiskInput<'a> {
    /// Per-request context — gives the engine access to fingerprints,
    /// UA, headers, client IP for fingerprint-mismatch checks.
    pub ctx: Option<&'a RequestContext>,
    /// WAF outcome signal — `Some(severity, rule_id)` when the WAF
    /// matched; None when WAF didn't fire or wasn't run.
    pub waf: Option<WafSignal>,
    /// GraphQL cheap-guard signal.
    pub graphql_anomaly: bool,
    /// Bot reputation score 0..100 from V37 BotFilter.
    pub bot_score: u32,
    /// Per-IP threat score 0..100 from V37 ThreatScorer (already cluster-wide via V90+).
    pub threat_score: f64,
    /// ML inference output 0..100 from V97 MlScorer.
    pub ml_score: f64,
    /// True when the request hit a honeypot path / pack.
    pub honeypot_hit: bool,
    /// True when this host is in attack-mode per V38 AnomalyDetector.
    pub under_attack: bool,
    /// True when a challenge cookie / fp cookie validated.
    pub challenge_verified: bool,
    /// True when the request came from a bypass/dynamic-trust source.
    pub trusted: bool,
    /// True when a threat-intel feed flagged the source IP.
    pub threat_intel_hit: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct WafSignal {
    pub severity: WafSeverity,
    /// Rule id that fired. Static str for cheap propagation; rule
    /// definitions outlive the request.
    pub rule_id: &'static str,
}

/// V109 will read this from per-rule metadata; V108 defaults to
/// `Medium` for any WAF match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Engine output. `reasons` are short stable strings for log
/// aggregation + Prometheus reason-counter labels (cardinality bounded
/// by the static set we emit — no IPs/paths/fingerprints leak in).
#[derive(Debug, Clone)]
pub struct RiskDecision {
    pub score: u8,
    pub action: RiskAction,
    pub reasons: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskAction {
    Allow,
    Challenge(ChallengeLevel),
    Deny { status: u16 },
}

impl RiskAction {
    /// Adapter for callers that need a [FilterAction].
    pub fn into_filter_action(self, reason: String) -> FilterAction {
        // V229 — wrap caller-provided dynamic strings into Cow::Owned.
        // This is the dynamic case (RiskEngine reasons are computed from
        // signal weights), so the String alloc already happened upstream.
        let reason: std::borrow::Cow<'static, str> = reason.into();
        match self {
            RiskAction::Allow => FilterAction::Allow,
            RiskAction::Challenge(level) => FilterAction::Challenge { level, reason },
            RiskAction::Deny { status } => FilterAction::Deny { status, reason },
        }
    }
}

/// Mode selector for V108's gradual rollout strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RiskMode {
    /// Compute + log score, NEVER apply action. Always returns Allow.
    /// Safe default for fresh installs.
    #[default]
    Observe,
    /// Apply action ONLY when score ≥ ENFORCE_THRESHOLD. Below
    /// threshold returns Allow and lets legacy per-filter decisions
    /// stand. This is the recommended production mode until operators
    /// validate the score distribution against their traffic.
    HighConfidenceEnforce,
    /// Apply whatever the engine decided regardless of score. Use only
    /// after extended observation + shadow-mode validation (V109+).
    FullEnforce,
}

/// Lightweight metrics rolled up across all engine invocations.
/// Fields are `AtomicU64` so the engine itself can be `&self`.
#[derive(Default)]
pub struct RiskEngineMetrics {
    pub evaluations_total: AtomicU64,
    pub decisions_allow: AtomicU64,
    pub decisions_challenge: AtomicU64,
    pub decisions_deny: AtomicU64,
    /// Highest score seen since startup — diagnostic, helps operators
    /// pick a reasonable enforcement threshold.
    pub max_score: AtomicU64,
}

pub struct RiskEngine {
    mode: RiskMode,
    enforce_threshold: u8,
    pub metrics: RiskEngineMetrics,
}

impl RiskEngine {
    pub fn new(mode: RiskMode) -> Self {
        Self {
            mode,
            enforce_threshold: DEFAULT_ENFORCE_THRESHOLD,
            metrics: RiskEngineMetrics::default(),
        }
    }

    pub fn with_threshold(mut self, t: u8) -> Self {
        self.enforce_threshold = t;
        self
    }

    pub fn mode(&self) -> RiskMode {
        self.mode
    }

    /// Evaluate `input` and return a decision. The decision's `score`
    /// + `reasons` are always populated regardless of mode; `action`
    /// is gated by the configured [RiskMode].
    pub fn evaluate(&self, input: &RiskInput<'_>) -> RiskDecision {
        let mut score: i32 = 0;
        let mut reasons: Vec<&'static str> = Vec::with_capacity(8);

        // ── Trust shortcut ────────────────────────────────────────
        // Trusted (bypass / dynamic-trust / fp-cookie verified) clients
        // get a strong negative bias. Even if they trigger some flags
        // we want operator override to dominate.
        if input.trusted {
            score -= 40;
            reasons.push("trusted");
        }
        if input.challenge_verified {
            score -= 20;
            reasons.push("challenge_verified");
        }

        // ── High-confidence single signals ───────────────────────
        if input.honeypot_hit {
            score += 80;
            reasons.push("honeypot_hit");
        }
        if input.threat_intel_hit {
            score += 60;
            reasons.push("threat_intel_hit");
        }
        if let Some(w) = input.waf {
            let w_score = match w.severity {
                WafSeverity::Critical => 80,
                WafSeverity::High => 50,
                WafSeverity::Medium => 25,
                WafSeverity::Low => 10,
            };
            score += w_score;
            reasons.push(match w.severity {
                WafSeverity::Critical => "waf_critical",
                WafSeverity::High => "waf_high",
                WafSeverity::Medium => "waf_medium",
                WafSeverity::Low => "waf_low",
            });
        }

        // ── Behavioural / cluster signals ─────────────────────────
        // ThreatScorer 0..=100 → 0..=40 contribution.
        if input.threat_score > 0.0 {
            let contrib = (input.threat_score * 0.4) as i32;
            if contrib > 0 {
                score += contrib;
                if contrib >= 30 {
                    reasons.push("threat_score_high");
                } else if contrib >= 15 {
                    reasons.push("threat_score_medium");
                }
            }
        }
        // ML scorer 0..=100 → 0..=30 contribution. Capped lower than
        // ThreatScorer because ML is heuristic; we don't want it to
        // dominate established history.
        if input.ml_score > 0.0 {
            let contrib = (input.ml_score * 0.3) as i32;
            if contrib > 0 {
                score += contrib;
                if contrib >= 20 {
                    reasons.push("ml_high");
                }
            }
        }
        // Bot reputation 0..=100 → 0..=20 contribution.
        if input.bot_score > 0 {
            let contrib = (input.bot_score as i32) * 20 / 100;
            if contrib > 0 {
                score += contrib;
                if contrib >= 15 {
                    reasons.push("bot_reputation_high");
                }
            }
        }

        if input.graphql_anomaly {
            score += 30;
            reasons.push("graphql_anomaly");
        }
        if input.under_attack {
            // Site-wide attack-mode raises the floor for ALL requests
            // — under attack everything is more suspicious by default.
            score += 20;
            reasons.push("under_attack");
        }

        // ── Header-shape heuristics on the context ────────────────
        if let Some(ctx) = input.ctx {
            // Browser UA without Accept-Language is a classic bot tell.
            if let Some(ua) = ctx.user_agent.as_deref()
                && looks_like_browser_ua(ua)
                && !ctx
                    .headers
                    .get("accept-language")
                    .is_some_and(|v| !v.is_empty())
            {
                score += 12;
                reasons.push("browser_ua_no_accept_language");
            }
            // Missing User-Agent entirely on a non-trusted request —
            // not by itself a deny signal, but adds to the pile.
            if ctx.user_agent.as_deref().unwrap_or("").is_empty() && !input.trusted {
                score += 8;
                reasons.push("no_user_agent");
            }
        }

        // ── Clamp, classify ──────────────────────────────────────
        let score = score.max(0).min(255) as u8;
        let action = self.classify(score);

        // Metrics rollup.
        self.metrics
            .evaluations_total
            .fetch_add(1, Ordering::Relaxed);
        let cur_max = self.metrics.max_score.load(Ordering::Relaxed);
        if (score as u64) > cur_max {
            // Lossy update — racing writers may underwrite, fine for a
            // diagnostic gauge.
            self.metrics
                .max_score
                .store(score as u64, Ordering::Relaxed);
        }
        match action {
            RiskAction::Allow => {
                self.metrics.decisions_allow.fetch_add(1, Ordering::Relaxed);
            }
            RiskAction::Challenge(_) => {
                self.metrics
                    .decisions_challenge
                    .fetch_add(1, Ordering::Relaxed);
            }
            RiskAction::Deny { .. } => {
                self.metrics.decisions_deny.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Gate the returned action by mode.
        let final_action = match self.mode {
            RiskMode::Observe => RiskAction::Allow,
            RiskMode::HighConfidenceEnforce => {
                if score >= self.enforce_threshold {
                    action
                } else {
                    RiskAction::Allow
                }
            }
            RiskMode::FullEnforce => action,
        };

        RiskDecision {
            score,
            action: final_action,
            reasons,
        }
    }

    /// Static classification band as an associated fn (no `self`) so
    /// Observe-mode callers can compute the "would-have" action from a
    /// score without holding the engine. MUST mirror `classify` below.
    // Currently uncalled: the proxy reports the risk score but does not act on
    // the engine's would-be action (see the security model's "risk engine is
    // observe-only" note). Kept as the single source of truth for the bands so
    // enforcement can be wired without re-deriving them.
    #[allow(dead_code)]
    pub(crate) fn classify_score(score: u8) -> RiskAction {
        if score >= 90 {
            RiskAction::Deny { status: 403 }
        } else if score >= 70 {
            RiskAction::Challenge(ChallengeLevel::Captcha)
        } else if score >= 50 {
            RiskAction::Challenge(ChallengeLevel::Javascript)
        } else if score >= 30 {
            RiskAction::Challenge(ChallengeLevel::Headers)
        } else {
            RiskAction::Allow
        }
    }

    /// Static classification curve. Tuned to be conservative — high
    /// scores require multiple confirming signals.
    fn classify(&self, score: u8) -> RiskAction {
        if score >= 90 {
            RiskAction::Deny { status: 403 }
        } else if score >= 70 {
            RiskAction::Challenge(ChallengeLevel::Captcha)
        } else if score >= 50 {
            RiskAction::Challenge(ChallengeLevel::Javascript)
        } else if score >= 30 {
            RiskAction::Challenge(ChallengeLevel::Headers)
        } else {
            RiskAction::Allow
        }
    }
}

/// Best-effort browser-UA detector. False-positives are bounded
/// — we only use this to decide whether a missing Accept-Language is
/// suspicious. Real bot detection lives in V110 (UA vs JA4 mismatch).
fn looks_like_browser_ua(ua: &str) -> bool {
    let lower = ua.to_ascii_lowercase();
    lower.contains("mozilla")
        || lower.contains("chrome")
        || lower.contains("safari")
        || lower.contains("firefox")
        || lower.contains("edge")
        || lower.contains("opera")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input<'a>() -> RiskInput<'a> {
        RiskInput::default()
    }

    #[test]
    fn observe_mode_never_enforces() {
        let e = RiskEngine::new(RiskMode::Observe);
        let mut input = empty_input();
        input.honeypot_hit = true;
        input.threat_intel_hit = true;
        let d = e.evaluate(&input);
        assert!(d.score >= 90, "score should be high, got {}", d.score);
        assert_eq!(d.action, RiskAction::Allow, "observe mode must allow");
        assert!(d.reasons.contains(&"honeypot_hit"));
        assert!(d.reasons.contains(&"threat_intel_hit"));
    }

    #[test]
    fn high_confidence_enforce_below_threshold_allows() {
        let e = RiskEngine::new(RiskMode::HighConfidenceEnforce);
        let mut input = empty_input();
        input.bot_score = 50; // → +10
        input.ml_score = 60.0; // → +18
        let d = e.evaluate(&input);
        // Total ~28, below 90 default threshold.
        assert!(d.score < 90);
        assert_eq!(d.action, RiskAction::Allow);
    }

    #[test]
    fn high_confidence_enforce_above_threshold_denies() {
        let e = RiskEngine::new(RiskMode::HighConfidenceEnforce);
        let mut input = empty_input();
        input.honeypot_hit = true;
        input.waf = Some(WafSignal {
            severity: WafSeverity::Critical,
            rule_id: "test-critical",
        });
        let d = e.evaluate(&input);
        // 80 + 80 = 160 → clamped to 255, definitely ≥ 90.
        assert!(d.score >= 90);
        assert!(matches!(d.action, RiskAction::Deny { status: 403 }));
    }

    #[test]
    fn full_enforce_returns_classification() {
        let e = RiskEngine::new(RiskMode::FullEnforce);
        let mut input = empty_input();
        input.threat_score = 80.0; // → +32
        input.bot_score = 60; // → +12
        let d = e.evaluate(&input);
        // ~44 → headers challenge band
        assert!(matches!(
            d.action,
            RiskAction::Challenge(ChallengeLevel::Headers)
        ));
    }

    #[test]
    fn trusted_overrides_signals() {
        let e = RiskEngine::new(RiskMode::FullEnforce);
        let mut input = empty_input();
        input.trusted = true;
        input.waf = Some(WafSignal {
            severity: WafSeverity::Medium,
            rule_id: "test-medium",
        });
        let d = e.evaluate(&input);
        // -40 (trusted) + 25 (waf_medium) = -15 clamp to 0 → Allow.
        assert_eq!(d.score, 0);
        assert_eq!(d.action, RiskAction::Allow);
        assert!(d.reasons.contains(&"trusted"));
        assert!(d.reasons.contains(&"waf_medium"));
    }

    #[test]
    fn classify_bands() {
        let e = RiskEngine::new(RiskMode::FullEnforce);
        assert_eq!(e.classify(0), RiskAction::Allow);
        assert_eq!(e.classify(29), RiskAction::Allow);
        assert!(matches!(e.classify(30), RiskAction::Challenge(_)));
        assert!(matches!(e.classify(49), RiskAction::Challenge(_)));
        assert!(matches!(e.classify(50), RiskAction::Challenge(_)));
        assert!(matches!(e.classify(89), RiskAction::Challenge(_)));
        assert!(matches!(e.classify(90), RiskAction::Deny { status: 403 }));
        assert!(matches!(e.classify(255), RiskAction::Deny { status: 403 }));
    }

    #[test]
    fn metrics_rollup() {
        let e = RiskEngine::new(RiskMode::FullEnforce);
        let mut benign = empty_input();
        benign.trusted = true;
        let mut hostile = empty_input();
        hostile.honeypot_hit = true;
        hostile.waf = Some(WafSignal {
            severity: WafSeverity::Critical,
            rule_id: "x",
        });
        e.evaluate(&benign);
        e.evaluate(&benign);
        e.evaluate(&hostile);
        assert_eq!(e.metrics.evaluations_total.load(Ordering::Relaxed), 3);
        assert_eq!(e.metrics.decisions_allow.load(Ordering::Relaxed), 2);
        assert_eq!(e.metrics.decisions_deny.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn browser_ua_without_accept_language_adds_signal() {
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("Mozilla/5.0 (Chrome)");
        let e = RiskEngine::new(RiskMode::Observe);
        let mut input = empty_input();
        input.ctx = Some(&ctx);
        let d = e.evaluate(&input);
        assert!(
            d.reasons.contains(&"browser_ua_no_accept_language"),
            "expected the heuristic reason, got {:?}",
            d.reasons
        );
    }
}
