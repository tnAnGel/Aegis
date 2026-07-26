//! V116 — Structured SecurityEvent + per-decision metrics (info.md P2).
//!
//! Pre-V116 every filter logged its decision in its own ad-hoc shape
//! (waf rule x denied, rate limit hit, honeypot triggered, …). For
//! SIEM ingest + Grafana dashboards + automated post-incident review
//! the operator wants one consistent shape per security decision.
//!
//! [SecurityEvent] is that shape — small, JSON-serialisable, free of
//! high-cardinality fields (no raw IPs in metric labels, just in the
//! event body). [SecurityEventEmitter] writes events to:
//!
//!   1. structured tracing log (`target = "aegis::security_event"`)
//!      → operator pipes through their log aggregator.
//!   2. cardinality-bounded Prometheus counters
//!      (`aegis_security_decisions_total{action, reason}`).
//!
//! Reasons are static `&'static str`s reused across the codebase —
//! same set V108 RiskEngine + V109 WAF severity + V110 UA/JA4
//! mismatch produce. That gives bounded label cardinality (~30
//! distinct values).
//!
//! Operator dashboards then trivially split:
//!
//!   sum(rate(aegis_security_decisions_total{action="deny"}[5m]))
//!   topk(10, sum by (reason)(rate(aegis_security_decisions_total[5m])))
//!
//! Replaces N ad-hoc tracing!() calls scattered across filters with
//! one canonical sink.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::Serialize;

/// Decision categories emitted to the structured log + metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Challenge,
    Deny,
    Throttle,
    /// Match-but-don't-act — V109 shadow-mode WAF, V108 observe-mode
    /// Risk Engine. Surfaced separately so dashboards can distinguish
    /// "would have blocked" from "did block".
    Observed,
}

/// One security decision as it appears in logs + JSON exports.
/// Fields are deliberately small + non-PII. Operator can correlate
/// to the full request via `request_id` if they keep an access log.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub action: DecisionKind,
    pub reason: &'static str,
    pub request_id: String,
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    /// Optional risk score (0..=255) from V108 RiskEngine. None when
    /// the engine wasn't consulted (e.g. early XDP drop).
    pub risk_score: Option<u8>,
    /// Optional extra reasons (V108 RiskEngine reasons vector,
    /// excluding the primary one already in `reason`).
    pub extra_reasons: Vec<&'static str>,
    /// Optional WAF rule id if a WAF rule triggered.
    pub waf_rule_id: Option<String>,
    /// Optional JA4 — useful for SIEM clustering. Truncated to 12
    /// chars to keep log size predictable.
    pub ja4_prefix: Option<String>,
}

impl SecurityEvent {
    pub fn new(
        action: DecisionKind,
        reason: &'static str,
        request_id: impl Into<String>,
        host: impl Into<String>,
        client_ip: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            action,
            reason,
            request_id: request_id.into(),
            host: host.into(),
            client_ip: client_ip.into(),
            method: method.into(),
            path: path.into(),
            risk_score: None,
            extra_reasons: Vec::new(),
            waf_rule_id: None,
            ja4_prefix: None,
        }
    }

    pub fn with_risk(mut self, score: u8, extras: Vec<&'static str>) -> Self {
        self.risk_score = Some(score);
        self.extra_reasons = extras;
        self
    }

    pub fn with_waf_rule(mut self, id: impl Into<String>) -> Self {
        self.waf_rule_id = Some(id.into());
        self
    }

    pub fn with_ja4(mut self, ja4: &str) -> Self {
        // Trim to first 12 chars (the JA4_a family identifier) so logs
        // don't bloat with full 36-char fingerprints.
        let prefix = ja4.chars().take(12).collect::<String>();
        if !prefix.is_empty() {
            self.ja4_prefix = Some(prefix);
        }
        self
    }
}

/// Cardinality-bounded counters keyed on `(action, reason)`. Values
/// are `AtomicU64`. `reason` is always `&'static str` so the map
/// can't grow beyond the static set defined across the codebase.
pub struct SecurityEventEmitter {
    counters: DashMap<(DecisionKind, &'static str), AtomicU64>,
    total: AtomicU64,
}

impl Default for SecurityEventEmitter {
    fn default() -> Self {
        Self {
            counters: DashMap::new(),
            total: AtomicU64::new(0),
        }
    }
}

impl SecurityEventEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit one event. Hot-path-safe (atomic increment + structured
    /// log line).
    pub fn emit(&self, ev: &SecurityEvent) {
        // Metrics first — must not fail on log serialisation issues.
        self.total.fetch_add(1, Ordering::Relaxed);
        self.counters
            .entry((ev.action, ev.reason))
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // Structured log line. tracing collapses to a single event with
        // typed fields the operator's pipeline can split on.
        tracing::info!(
            target: "aegis::security_event",
            action = ?ev.action,
            reason = %ev.reason,
            request_id = %ev.request_id,
            host = %ev.host,
            client_ip = %ev.client_ip,
            method = %ev.method,
            path = %ev.path,
            risk_score = ?ev.risk_score,
            waf_rule_id = ?ev.waf_rule_id,
            ja4_prefix = ?ev.ja4_prefix,
            "security_decision"
        );
    }

    /// Render Prometheus text exposition for the security counters.
    /// One line per (action, reason) pair plus a total. Caller injects
    /// the produced text into the existing /metrics body.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(self.counters.len() * 64 + 128);
        out.push_str(
            "# HELP aegis_security_decisions_total Per-action per-reason security decisions.\n",
        );
        out.push_str("# TYPE aegis_security_decisions_total counter\n");
        for entry in self.counters.iter() {
            let (action, reason) = entry.key();
            let v = entry.value().load(Ordering::Relaxed);
            let action_str = match action {
                DecisionKind::Allow => "allow",
                DecisionKind::Challenge => "challenge",
                DecisionKind::Deny => "deny",
                DecisionKind::Throttle => "throttle",
                DecisionKind::Observed => "observed",
            };
            // Reasons are already cardinality-bounded static strs but
            // we still escape `"` and `\\` to satisfy Prometheus text
            // format strictness.
            let safe_reason = reason.replace('\\', "\\\\").replace('"', "\\\"");
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "aegis_security_decisions_total{{action=\"{action_str}\",reason=\"{safe_reason}\"}} {v}\n"
                ),
            );
        }
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "# HELP aegis_security_events_total Total SecurityEvent emissions since start.\n# TYPE aegis_security_events_total counter\naegis_security_events_total {}\n",
                self.total.load(Ordering::Relaxed)
            ),
        );
        out
    }

    /// Snapshot of counters for /admin/api JSON endpoints.
    pub fn snapshot(&self) -> Vec<((DecisionKind, &'static str), u64)> {
        self.counters
            .iter()
            .map(|e| (*e.key(), e.value().load(Ordering::Relaxed)))
            .collect()
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_increments_counters() {
        let e = SecurityEventEmitter::new();
        let ev = SecurityEvent::new(
            DecisionKind::Deny,
            "waf_critical",
            "req-1",
            "example.com",
            "1.2.3.4",
            "GET",
            "/admin",
        );
        e.emit(&ev);
        e.emit(&ev);
        assert_eq!(e.total(), 2);
        let snap = e.snapshot();
        assert_eq!(
            snap.iter()
                .find(|(k, _)| *k == (DecisionKind::Deny, "waf_critical"))
                .map(|(_, v)| *v),
            Some(2)
        );
    }

    #[test]
    fn different_reasons_get_separate_buckets() {
        let e = SecurityEventEmitter::new();
        for reason in ["waf_critical", "honeypot_hit", "rate_limit_exceeded"] {
            let ev = SecurityEvent::new(DecisionKind::Deny, reason, "r", "h", "i", "GET", "/p");
            e.emit(&ev);
        }
        assert_eq!(e.snapshot().len(), 3);
    }

    #[test]
    fn prometheus_render_contains_all_buckets() {
        let e = SecurityEventEmitter::new();
        e.emit(&SecurityEvent::new(
            DecisionKind::Allow,
            "trusted",
            "r",
            "h",
            "i",
            "GET",
            "/p",
        ));
        e.emit(&SecurityEvent::new(
            DecisionKind::Deny,
            "waf_critical",
            "r",
            "h",
            "i",
            "GET",
            "/p",
        ));
        let body = e.render_prometheus();
        assert!(body.contains("action=\"allow\""));
        assert!(body.contains("action=\"deny\""));
        assert!(body.contains("reason=\"trusted\""));
        assert!(body.contains("reason=\"waf_critical\""));
        assert!(body.contains("aegis_security_events_total 2"));
    }

    #[test]
    fn risk_score_and_extras_attached() {
        let ev = SecurityEvent::new(
            DecisionKind::Challenge,
            "ml_high",
            "r",
            "h",
            "i",
            "POST",
            "/login",
        )
        .with_risk(
            85,
            vec!["browser_ua_no_accept_language", "threat_score_high"],
        )
        .with_waf_rule("custom-001")
        .with_ja4("t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        assert_eq!(ev.risk_score, Some(85));
        assert_eq!(ev.extra_reasons.len(), 2);
        assert_eq!(ev.waf_rule_id.as_deref(), Some("custom-001"));
        assert_eq!(ev.ja4_prefix.as_deref(), Some("t13d1516h2_8"));
    }

    #[test]
    fn cardinality_bounded_by_static_reasons() {
        // The map key uses &'static str — even if a caller tried to
        // construct dynamic strings, the type system prevents it.
        // This test documents the contract.
        let e = SecurityEventEmitter::new();
        // 4 distinct (action, reason) pairs from a long event series.
        for _ in 0..1000 {
            for action in [
                DecisionKind::Allow,
                DecisionKind::Deny,
                DecisionKind::Challenge,
                DecisionKind::Throttle,
            ] {
                e.emit(&SecurityEvent::new(
                    action,
                    "test_reason",
                    "r",
                    "h",
                    "i",
                    "GET",
                    "/p",
                ));
            }
        }
        assert_eq!(e.snapshot().len(), 4, "should only have 4 buckets");
        assert_eq!(e.total(), 4000);
    }
}
