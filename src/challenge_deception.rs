//! V203 — Challenge ladder deception layer: decoy CAPTCHA + honeypot
//! form fields + varied error pages.
//!
//! Three small but high-leverage tactics:
//!
//! 1. **Decoy CAPTCHA** — present a CAPTCHA form to clients with very
//!    high suspicion scores, accept nothing (or accept only after a
//!    secret invisible-token). Wastes attacker's 2captcha quota and
//!    burns wall-clock without ever letting them through.
//!
//! 2. **Honeypot form fields** — inject hidden fields into challenge
//!    forms (`display: none` + tab-index 0). Real users never fill
//!    them; automation fills every field. Submitting a non-empty
//!    honeypot value = instant deny.
//!
//! 3. **Varied error pages** — instead of "blocked: reason", render
//!    rotating "Origin DNS error" / "Service Unavailable" /
//!    "Gateway Timeout" pages so the attacker can't tell whether
//!    Aegis caught them or the site is down. Slows reverse-engineering.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyVerdict {
    /// Decoy is in play; reject every submission (the operator's
    /// existing accept_token, if any, would unlock — but for decoy
    /// mode we never honor it).
    BlackHole,
    /// Standard mode; honor a correct submission.
    PassThrough,
}

pub fn build_decoy_form_html(scenario_id: &str, salt: u64) -> String {
    // Random-feeling layout based on salt — same client (= same
    // suspicion fingerprint) sees same form across retries to look
    // like a real captcha.
    let captcha_token = format!("{:016x}", scrambled(salt));
    let honeypot_fields = build_honeypot_fields(salt);
    format!(
        r#"<!doctype html>
<html><head><title>Verify access</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;color:#222}}
.captcha{{padding:24px;border:1px solid #ddd;border-radius:8px}}
.honeypot{{position:absolute;left:-9999px;width:0;height:0;opacity:0}}
input[type=text]{{width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;font-family:monospace}}
button{{margin-top:12px;padding:10px 16px;background:#0066cc;color:#fff;border:0;border-radius:4px;cursor:pointer}}
</style></head>
<body><div class="captcha">
<h2>Please verify you're a human</h2>
<form method="post" action="/__aegis/verify/{scenario_id}">
<input type="hidden" name="t" value="{captcha_token}">
{honeypot_fields}
<label for="answer">Enter the characters shown:</label>
<div style="background:#f0f0f0;padding:16px;font-size:24px;letter-spacing:8px;text-align:center;font-family:monospace">{captcha_token}</div>
<input type="text" id="answer" name="answer" autocomplete="off" required>
<button type="submit">Submit</button>
</form>
<p style="font-size:11px;color:#888;margin-top:24px">Request ID: {captcha_token}</p>
</div></body></html>"#
    )
}

fn build_honeypot_fields(salt: u64) -> String {
    // Pick 2-3 plausible-looking field names from a rotating pool.
    // Real users never fill these (CSS hides + tabindex makes them
    // skip during keyboard nav); automation that fills every input
    // trips them.
    const NAMES: &[&str] = &[
        "email_confirm",
        "phone_number",
        "zip_code",
        "company",
        "fax",
    ];
    let mut out = String::new();
    let pick = (salt as usize) % NAMES.len();
    for i in 0..2 {
        let name = NAMES[(pick + i) % NAMES.len()];
        out.push_str(&format!(
            r#"<div class="honeypot"><input type="text" name="{name}" tabindex="-1" autocomplete="off"></div>"#
        ));
    }
    out
}

/// Inspect a submitted form (`Vec<(name, value)>`) and return
/// `true` iff any honeypot field was filled. Operators wire this
/// into their /__aegis/verify POST handler.
pub fn detect_honeypot_fill(fields: &[(String, String)]) -> bool {
    const NAMES: &[&str] = &[
        "email_confirm",
        "phone_number",
        "zip_code",
        "company",
        "fax",
    ];
    fields
        .iter()
        .any(|(name, value)| NAMES.contains(&name.as_str()) && !value.trim().is_empty())
}

fn scrambled(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0xA5A5_5A5A_5A5A_A5A5);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// V203 — error-page variation. Each rendering rotates through a
/// pool of plausible-looking failure pages so the attacker's tool
/// doesn't see "blocked" verbatim. Real operators worry about
/// support-volume increase, so we limit variation to a curated
/// pool with predictable shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorMask {
    OriginDnsError,
    GatewayTimeout,
    ServiceUnavailable,
    ConnectionReset,
    UpstreamProtocolError,
}

impl ErrorMask {
    pub fn from_salt(salt: u64) -> Self {
        match salt % 5 {
            0 => Self::OriginDnsError,
            1 => Self::GatewayTimeout,
            2 => Self::ServiceUnavailable,
            3 => Self::ConnectionReset,
            _ => Self::UpstreamProtocolError,
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::OriginDnsError => 502,
            Self::GatewayTimeout => 504,
            Self::ServiceUnavailable => 503,
            Self::ConnectionReset => 502,
            Self::UpstreamProtocolError => 502,
        }
    }

    pub fn render_body(self, request_id: &str) -> String {
        let (title, body) = match self {
            Self::OriginDnsError => (
                "Origin DNS Error",
                "The origin server cannot be resolved. Please try again in a few minutes.",
            ),
            Self::GatewayTimeout => (
                "Gateway Timeout",
                "The origin server did not respond in time. Try again shortly.",
            ),
            Self::ServiceUnavailable => (
                "Service Unavailable",
                "The service is temporarily unavailable. Please retry shortly.",
            ),
            Self::ConnectionReset => (
                "Connection Reset",
                "The connection to the origin was reset. Please retry.",
            ),
            Self::UpstreamProtocolError => (
                "Upstream Protocol Error",
                "The origin server returned an invalid response. Please retry.",
            ),
        };
        format!(
            r#"<!doctype html><html><head><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;text-align:center;padding:60px;color:#444}}</style></head>
<body><h1>{title}</h1><p>{body}</p>
<p style="color:#aaa;margin-top:40px;font-size:11px">Request ID: {request_id}</p>
</body></html>"#
        )
    }
}

#[derive(Debug, Default)]
pub struct DeceptionStats {
    pub decoy_forms_rendered: AtomicU64,
    pub honeypot_fills_detected: AtomicU64,
    pub varied_errors_rendered: AtomicU64,
}

impl DeceptionStats {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.decoy_forms_rendered.load(Ordering::Relaxed),
            self.honeypot_fills_detected.load(Ordering::Relaxed),
            self.varied_errors_rendered.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_form_contains_honeypot_fields() {
        let html = build_decoy_form_html("test123", 42);
        assert!(html.contains("class=\"honeypot\""));
        assert!(html.contains("tabindex=\"-1\""));
    }

    #[test]
    fn detect_honeypot_fill_catches_filled_value() {
        let fields = vec![
            ("answer".into(), "user typed this".into()),
            ("email_confirm".into(), "bot@evil.example".into()),
        ];
        assert!(detect_honeypot_fill(&fields));
    }

    #[test]
    fn detect_honeypot_fill_ignores_empty_strings() {
        let fields = vec![
            ("answer".into(), "user typed".into()),
            ("email_confirm".into(), "".into()),
            ("zip_code".into(), "   ".into()),
        ];
        assert!(!detect_honeypot_fill(&fields));
    }

    #[test]
    fn error_mask_distributes_across_pool() {
        let mut seen = std::collections::HashSet::new();
        for salt in 0..20u64 {
            seen.insert(ErrorMask::from_salt(salt));
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn error_mask_renders_request_id() {
        let body = ErrorMask::GatewayTimeout.render_body("abc123");
        assert!(body.contains("Gateway Timeout"));
        assert!(body.contains("abc123"));
    }

    #[test]
    fn decoy_form_deterministic_per_salt() {
        let a = build_decoy_form_html("x", 100);
        let b = build_decoy_form_html("x", 100);
        let c = build_decoy_form_html("x", 101);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn http_status_in_5xx_range() {
        for mask in [
            ErrorMask::OriginDnsError,
            ErrorMask::GatewayTimeout,
            ErrorMask::ServiceUnavailable,
            ErrorMask::ConnectionReset,
            ErrorMask::UpstreamProtocolError,
        ] {
            assert!((500..600).contains(&mask.http_status()));
        }
    }
}
