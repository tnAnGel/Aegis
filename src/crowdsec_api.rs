//! V157 — CrowdSec-compatible Local API (LAPI) decisions endpoint.
//!
//! CrowdSec has the largest open-source ecosystem of bouncers
//! (nginx, HAProxy, Cloudflare worker, firewall-iptables, Caddy
//! plugin, kubernetes-ingress, etc.). They all speak the CrowdSec
//! LAPI's `/v1/decisions` and `/v1/decisions/stream` shape. If
//! Aegis serves that shape, every existing bouncer becomes an
//! Aegis decision enforcer.
//!
//! V157 ships the wire types + adapter that converts Aegis's
//! internal denial state (V108 RiskEngine outputs, V30 DynamicTrust
//! revocations, the cluster scorer's high-risk IPs) into the
//! CrowdSec decision shape. Operator wires the actual HTTP route
//! handler — typical mounting:
//!
//!     GET /v1/decisions
//!     GET /v1/decisions/stream?startup=true
//!
//! both authed via `X-Api-Key: <bouncer-key>` header. Aegis
//! validates the key against an operator-configured registry
//! (same shape as `AdminTokenRegistry`).
//!
//! ## Why not consume CrowdSec instead?
//!
//! Both directions are useful, but expose-first is the higher-
//! impact play:
//! * Operators with existing CrowdSec investment can drop Aegis
//!   in as the decision source without re-engineering enforcement.
//! * Aegis's L7 signal surface (JA4 family, fp_correlation, ML
//!   scoring, robots honeypot) is RICHER than CrowdSec scenarios,
//!   so feeding decisions out adds real value to that ecosystem.
//! * The consume direction is a small follow-up — periodically GET
//!   from a CrowdSec LAPI and add the IPs to `threat_intel.rs`.

use std::{net::IpAddr, time::Duration};

use serde::{Deserialize, Serialize};

/// One decision in the LAPI wire format.
///
/// Schema reference: https://docs.crowdsec.net/docs/local_api/intro
/// We implement the subset bouncers actually consume (id, value,
/// type, scope, duration, scenario, origin). Future fields can be
/// added via #[serde(default)] without breaking compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// Monotonically-increasing identifier. Bouncers use this to
    /// deduplicate across stream-poll cycles.
    pub id: u64,
    /// Decision verb — "ban" / "captcha" / "throttle". Aegis maps
    /// its internal verdicts to these CrowdSec types.
    #[serde(rename = "type")]
    pub kind: String,
    /// Scope of the value field. "Ip" = single address; "Range" =
    /// CIDR; "Country" = ISO-3166 alpha-2 code; others are CrowdSec
    /// extensions we don't emit.
    pub scope: String,
    /// The thing being blocked (e.g., "1.2.3.4", "1.2.3.0/24", "RU").
    pub value: String,
    /// Human-readable duration string per CrowdSec convention
    /// ("4h", "30m", "1d"). Bouncers parse this as a relative TTL.
    pub duration: String,
    /// Which Aegis signal produced this decision — surfaces in the
    /// bouncer logs so operators can attribute. Format mirrors the
    /// CrowdSec convention: `crowdsecurity/<scenario-name>`.
    pub scenario: String,
    /// Always "aegis" for decisions Aegis emits. Bouncers display
    /// the origin so operators see whose verdict they're enforcing.
    pub origin: String,
}

/// Wire shape of GET /v1/decisions/stream. Bouncers poll this
/// periodically (default 10s) and apply `new` / clear `deleted`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionStream {
    pub new: Vec<Decision>,
    pub deleted: Vec<Decision>,
}

/// Aegis's internal decision shape that the adapter converts FROM.
/// Operator's adapter code builds these from the runtime state
/// (DynamicTrust, ResponseCache, RiskEngine, ML scorer).
#[derive(Debug, Clone)]
pub struct AegisDecision {
    pub ip: IpAddr,
    pub kind: AegisDecisionKind,
    pub ttl: Duration,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AegisDecisionKind {
    /// Block the IP entirely (V36 deny / V30 DynamicTrust revoke).
    Ban,
    /// Force a CAPTCHA / challenge (V42 challenge ladder).
    Captcha,
    /// Reduce throughput (V197 rate limit).
    Throttle,
}

impl AegisDecisionKind {
    pub fn as_crowdsec_str(self) -> &'static str {
        match self {
            Self::Ban => "ban",
            Self::Captcha => "captcha",
            Self::Throttle => "throttle",
        }
    }
}

/// CrowdSec-compatible duration string. Days first, then hours,
/// then minutes — matches CrowdSec's `time.ParseDuration` consumer
/// (`go-yaml/yaml.v3` extension `1d4h30m`). Operators sometimes
/// pin this to a config-tunable lower bound.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 86_400 {
        let days = secs / 86_400;
        let h = (secs % 86_400) / 3600;
        if h > 0 {
            format!("{days}d{h}h")
        } else {
            format!("{days}d")
        }
    } else if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 {
            format!("{h}h{m}m")
        } else {
            format!("{h}h")
        }
    } else if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        if s > 0 {
            format!("{m}m{s}s")
        } else {
            format!("{m}m")
        }
    } else {
        format!("{secs}s")
    }
}

/// Convert an [AegisDecision] into a CrowdSec [Decision] with the
/// supplied id (caller manages monotonic id assignment).
pub fn aegis_to_crowdsec(d: &AegisDecision, id: u64) -> Decision {
    Decision {
        id,
        kind: d.kind.as_crowdsec_str().to_string(),
        scope: "Ip".to_string(),
        value: d.ip.to_string(),
        duration: format_duration(d.ttl),
        scenario: format!("aegis/{}", d.reason),
        origin: "aegis".to_string(),
    }
}

/// Run the conversion over a batch of decisions, assigning
/// sequential ids starting at `start_id`. Returns the resulting
/// [DecisionStream] with the new entries; deleted left empty
/// (caller fills from its tracked-removed set).
pub fn build_stream(decisions: &[AegisDecision], start_id: u64) -> DecisionStream {
    let new: Vec<Decision> = decisions
        .iter()
        .enumerate()
        .map(|(i, d)| aegis_to_crowdsec(d, start_id + i as u64))
        .collect();
    DecisionStream {
        new,
        deleted: vec![],
    }
}

/// Validate an `X-Api-Key` bouncer key against an operator-supplied
/// allow-set. Returns Some(label) on match (label is operator-set
/// for audit logs) or None on failure. Constant-time compare keeps
/// timing-side-channel risk minimal even though the keys are
/// high-entropy.
pub fn validate_bouncer_key(
    presented: &str,
    registry: &[(String, String)], // (key, label)
) -> Option<String> {
    for (k, label) in registry {
        if k.len() == presented.len() && ct_eq(k.as_bytes(), presented.as_bytes()) {
            return Some(label.clone());
        }
    }
    None
}

/// Constant-time byte slice equality. Assumes `a.len() == b.len()`
/// (caller checks). Eliminates timing-side-channel risk on
/// bouncer-key compare.
#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aegis_d(ip: &str, kind: AegisDecisionKind, ttl_secs: u64) -> AegisDecision {
        AegisDecision {
            ip: ip.parse().unwrap(),
            kind,
            ttl: Duration::from_secs(ttl_secs),
            reason: "test",
        }
    }

    #[test]
    fn aegis_kind_string_mapping() {
        assert_eq!(AegisDecisionKind::Ban.as_crowdsec_str(), "ban");
        assert_eq!(AegisDecisionKind::Captcha.as_crowdsec_str(), "captcha");
        assert_eq!(AegisDecisionKind::Throttle.as_crowdsec_str(), "throttle");
    }

    #[test]
    fn duration_formatter_days_dominant() {
        assert_eq!(format_duration(Duration::from_secs(86_400)), "1d");
        assert_eq!(
            format_duration(Duration::from_secs(86_400 * 3 + 3600 * 5)),
            "3d5h"
        );
    }

    #[test]
    fn duration_formatter_hours() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(
            format_duration(Duration::from_secs(3600 * 4 + 60 * 30)),
            "4h30m"
        );
    }

    #[test]
    fn duration_formatter_minutes() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration(Duration::from_secs(60 * 5 + 30)), "5m30s");
    }

    #[test]
    fn duration_formatter_seconds() {
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    }

    #[test]
    fn aegis_to_crowdsec_translates_ban_correctly() {
        let d = aegis_d("1.2.3.4", AegisDecisionKind::Ban, 3600);
        let c = aegis_to_crowdsec(&d, 42);
        assert_eq!(c.id, 42);
        assert_eq!(c.kind, "ban");
        assert_eq!(c.scope, "Ip");
        assert_eq!(c.value, "1.2.3.4");
        assert_eq!(c.duration, "1h");
        assert_eq!(c.scenario, "aegis/test");
        assert_eq!(c.origin, "aegis");
    }

    #[test]
    fn aegis_to_crowdsec_translates_captcha_and_throttle() {
        let cap = aegis_to_crowdsec(&aegis_d("1.1.1.1", AegisDecisionKind::Captcha, 600), 1);
        assert_eq!(cap.kind, "captcha");
        let thr = aegis_to_crowdsec(&aegis_d("2.2.2.2", AegisDecisionKind::Throttle, 60), 2);
        assert_eq!(thr.kind, "throttle");
    }

    #[test]
    fn ipv6_renders_in_value_field() {
        let d = aegis_d("2001:db8::1", AegisDecisionKind::Ban, 3600);
        let c = aegis_to_crowdsec(&d, 1);
        assert_eq!(c.value, "2001:db8::1");
    }

    #[test]
    fn build_stream_assigns_sequential_ids() {
        let ds = vec![
            aegis_d("1.1.1.1", AegisDecisionKind::Ban, 60),
            aegis_d("2.2.2.2", AegisDecisionKind::Captcha, 120),
            aegis_d("3.3.3.3", AegisDecisionKind::Throttle, 180),
        ];
        let s = build_stream(&ds, 100);
        assert_eq!(s.new.len(), 3);
        assert_eq!(s.new[0].id, 100);
        assert_eq!(s.new[1].id, 101);
        assert_eq!(s.new[2].id, 102);
        assert!(s.deleted.is_empty());
    }

    #[test]
    fn stream_serializes_to_crowdsec_compatible_json() {
        let ds = vec![aegis_d("1.2.3.4", AegisDecisionKind::Ban, 3600)];
        let s = build_stream(&ds, 1);
        let json = serde_json::to_string(&s).unwrap();
        // Must contain the field names CrowdSec bouncers expect.
        assert!(json.contains("\"new\""));
        assert!(json.contains("\"deleted\""));
        assert!(json.contains("\"type\":\"ban\""));
        assert!(json.contains("\"scope\":\"Ip\""));
        assert!(json.contains("\"value\":\"1.2.3.4\""));
        assert!(json.contains("\"duration\":\"1h\""));
        assert!(json.contains("\"origin\":\"aegis\""));
    }

    #[test]
    fn stream_roundtrips_via_serde() {
        let ds = vec![aegis_d("9.9.9.9", AegisDecisionKind::Ban, 3600)];
        let s = build_stream(&ds, 5);
        let json = serde_json::to_string(&s).unwrap();
        let back: DecisionStream = serde_json::from_str(&json).unwrap();
        assert_eq!(s.new[0], back.new[0]);
    }

    #[test]
    fn validate_bouncer_key_matches_correct_key() {
        let reg = vec![
            ("abcdef1234567890".to_string(), "nginx-prod".to_string()),
            ("zyxwvu0987654321".to_string(), "haproxy-edge".to_string()),
        ];
        assert_eq!(
            validate_bouncer_key("abcdef1234567890", &reg).as_deref(),
            Some("nginx-prod"),
        );
        assert_eq!(
            validate_bouncer_key("zyxwvu0987654321", &reg).as_deref(),
            Some("haproxy-edge"),
        );
    }

    #[test]
    fn validate_bouncer_key_rejects_wrong_or_missing() {
        let reg = vec![("abcdef1234567890".to_string(), "x".to_string())];
        assert!(validate_bouncer_key("wrong-key-here-1", &reg).is_none());
        assert!(validate_bouncer_key("", &reg).is_none());
        assert!(validate_bouncer_key("abc", &reg).is_none()); // length mismatch
    }

    #[test]
    fn empty_decisions_yields_empty_stream() {
        let s = build_stream(&[], 0);
        assert!(s.new.is_empty());
        assert!(s.deleted.is_empty());
    }
}
