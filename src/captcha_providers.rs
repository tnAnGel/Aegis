//! V132 — External CAPTCHA provider abstraction (hCaptcha, Cloudflare
//! Turnstile, Google reCAPTCHA v2/v3).
//!
//! Synapse parity. All three providers share the same shape:
//!
//! 1. Operator embeds a widget on the challenge page using `site_key`.
//! 2. Widget puts a token in a form field (or invisible v3 ranking).
//! 3. Server POSTs `{secret, response, remoteip?}` form-urlencoded to
//!    a per-provider `siteverify` endpoint.
//! 4. Endpoint returns JSON `{"success": bool, ...}` with extras like
//!    `score`, `action`, `challenge_ts`, `error-codes`.
//!
//! We model this as the [CaptchaProvider] trait. Each provider knows
//! its own endpoint URL, how to build the request body, and how to
//! parse the response. The actual HTTP transport is injected via the
//! [HttpPoster] trait so callers can use whichever HTTPS client they
//! prefer (hyper-rustls, reqwest, ureq) — the Aegis core doesn't ship
//! one for outbound HTTPS yet, see `proxy/http.rs:696`.
//!
//! Operator picks a provider in config; V131 PoW remains the
//! self-contained tier and these three are the third-party tiers.
//!
//! ### Why an abstraction?
//!
//! Operators have strong preferences here (Cloudflare shop → Turnstile,
//! Google Workspace → reCAPTCHA, privacy-conscious → hCaptcha). A
//! single hard-coded provider would force a rewrite per shop. The
//! abstraction is tiny: 3 trait methods, ~10 lines per impl.

use std::time::Duration;

use anyhow::Result;
#[cfg(test)]
use anyhow::anyhow;
use serde::Deserialize;

/// Provider verdict normalised across the three vendors.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptchaVerdict {
    pub success: bool,
    /// reCAPTCHA v3 returns 0.0..=1.0 risk score; hCaptcha and
    /// Turnstile do not. None when the provider doesn't supply one.
    pub score: Option<f32>,
    /// Action tag (reCAPTCHA v3 only) — the SPA's per-page label.
    pub action: Option<String>,
    /// Hostname the widget was served on. Operator can pin this to
    /// their domain to reject reused tokens from elsewhere.
    pub hostname: Option<String>,
    /// Provider-specific error codes (e.g. "invalid-input-secret").
    pub error_codes: Vec<String>,
}

impl CaptchaVerdict {
    pub fn failure_with_codes(codes: Vec<String>) -> Self {
        Self {
            success: false,
            score: None,
            action: None,
            hostname: None,
            error_codes: codes,
        }
    }
}

/// Operator-injected HTTPS-capable POST transport. Decouples the
/// provider modules from any specific HTTP-client crate. Real
/// deployments wire this to hyper-rustls / reqwest; tests use a
/// hand-rolled stub.
#[async_trait::async_trait]
pub trait HttpPoster: Send + Sync {
    /// POST form-urlencoded `body` to `url`. Returns response body
    /// bytes on 2xx, Err on non-2xx or transport failure.
    async fn post_form(&self, url: &str, body: &str, timeout: Duration) -> Result<Vec<u8>>;
}

/// One CAPTCHA backend (hCaptcha, Turnstile, reCAPTCHA).
#[async_trait::async_trait]
pub trait CaptchaProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn siteverify_url(&self) -> &'static str;
    /// Verify the user's token, optionally tagging the request with
    /// `remote_ip` (some providers use it for risk scoring).
    async fn verify(
        &self,
        client: &dyn HttpPoster,
        response_token: &str,
        remote_ip: Option<&str>,
    ) -> CaptchaVerdict;
}

/// Shared upstream JSON shape — all three providers stick to this.
/// Unknown fields are dropped.
#[derive(Debug, Deserialize, Default)]
struct SiteVerifyResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    score: Option<f32>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default, rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

pub(crate) fn parse_siteverify(raw: &[u8]) -> CaptchaVerdict {
    match serde_json::from_slice::<SiteVerifyResponse>(raw) {
        Ok(r) => CaptchaVerdict {
            success: r.success,
            score: r.score,
            action: r.action,
            hostname: r.hostname,
            error_codes: r.error_codes.unwrap_or_default(),
        },
        Err(_) => CaptchaVerdict::failure_with_codes(vec!["malformed-upstream-json".to_string()]),
    }
}

/// Form-urlencoded body builder. The three vendors all accept the
/// same `secret=…&response=…&remoteip=…` shape so we share it.
pub(crate) fn build_siteverify_body(
    secret: &str,
    response: &str,
    remote_ip: Option<&str>,
) -> String {
    let mut s = String::with_capacity(secret.len() + response.len() + 64);
    s.push_str("secret=");
    s.push_str(&urlencode(secret));
    s.push_str("&response=");
    s.push_str(&urlencode(response));
    if let Some(ip) = remote_ip {
        s.push_str("&remoteip=");
        s.push_str(&urlencode(ip));
    }
    s
}

fn urlencode(s: &str) -> String {
    // application/x-www-form-urlencoded — percent-encode anything
    // outside the unreserved set. Cheap inline encoder; we don't need
    // a full URL crate just for this.
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

// ──────────────────────────────────────────────────────────────────
// hCaptcha
// ──────────────────────────────────────────────────────────────────

pub struct HCaptcha {
    pub secret: String,
}

impl HCaptcha {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

#[async_trait::async_trait]
impl CaptchaProvider for HCaptcha {
    fn name(&self) -> &'static str {
        "hcaptcha"
    }
    fn siteverify_url(&self) -> &'static str {
        "https://hcaptcha.com/siteverify"
    }

    async fn verify(
        &self,
        client: &dyn HttpPoster,
        response_token: &str,
        remote_ip: Option<&str>,
    ) -> CaptchaVerdict {
        let body = build_siteverify_body(&self.secret, response_token, remote_ip);
        match client
            .post_form(self.siteverify_url(), &body, VERIFY_TIMEOUT)
            .await
        {
            Ok(raw) => parse_siteverify(&raw),
            Err(e) => {
                tracing::warn!(provider = "hcaptcha", error = %e, "siteverify failed");
                CaptchaVerdict::failure_with_codes(vec!["transport-error".to_string()])
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────
// Cloudflare Turnstile
// ──────────────────────────────────────────────────────────────────

pub struct Turnstile {
    pub secret: String,
}

impl Turnstile {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
        }
    }
}

#[async_trait::async_trait]
impl CaptchaProvider for Turnstile {
    fn name(&self) -> &'static str {
        "turnstile"
    }
    fn siteverify_url(&self) -> &'static str {
        "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    }

    async fn verify(
        &self,
        client: &dyn HttpPoster,
        response_token: &str,
        remote_ip: Option<&str>,
    ) -> CaptchaVerdict {
        let body = build_siteverify_body(&self.secret, response_token, remote_ip);
        match client
            .post_form(self.siteverify_url(), &body, VERIFY_TIMEOUT)
            .await
        {
            Ok(raw) => parse_siteverify(&raw),
            Err(e) => {
                tracing::warn!(provider = "turnstile", error = %e, "siteverify failed");
                CaptchaVerdict::failure_with_codes(vec!["transport-error".to_string()])
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────
// Google reCAPTCHA (v2 + v3 share the same endpoint)
// ──────────────────────────────────────────────────────────────────

pub struct ReCaptcha {
    pub secret: String,
    /// Minimum acceptable v3 score. Ignored for v2 tokens (no score).
    /// 0.5 is Google's documented default cutoff between bot and
    /// human; raise to 0.7 for hardened deployments.
    pub min_score: f32,
}

impl ReCaptcha {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            min_score: 0.5,
        }
    }
    pub fn with_min_score(mut self, score: f32) -> Self {
        self.min_score = score;
        self
    }
}

#[async_trait::async_trait]
impl CaptchaProvider for ReCaptcha {
    fn name(&self) -> &'static str {
        "recaptcha"
    }
    fn siteverify_url(&self) -> &'static str {
        "https://www.google.com/recaptcha/api/siteverify"
    }

    async fn verify(
        &self,
        client: &dyn HttpPoster,
        response_token: &str,
        remote_ip: Option<&str>,
    ) -> CaptchaVerdict {
        let body = build_siteverify_body(&self.secret, response_token, remote_ip);
        let raw = match client
            .post_form(self.siteverify_url(), &body, VERIFY_TIMEOUT)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(provider = "recaptcha", error = %e, "siteverify failed");
                return CaptchaVerdict::failure_with_codes(vec!["transport-error".to_string()]);
            }
        };
        let mut v = parse_siteverify(&raw);
        // For v3, demote success when the risk score is below the
        // configured threshold. v2 tokens have no score field so this
        // is a no-op for them.
        if let Some(score) = v.score
            && score < self.min_score
        {
            v.success = false;
            v.error_codes.push(format!("score-below-threshold:{score}"));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test stub: captures the last POST and returns a canned body.
    struct StubPoster {
        canned: Vec<u8>,
        last: Mutex<Option<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl HttpPoster for StubPoster {
        async fn post_form(&self, url: &str, body: &str, _t: Duration) -> Result<Vec<u8>> {
            *self.last.lock().unwrap() = Some((url.to_string(), body.to_string()));
            Ok(self.canned.clone())
        }
    }

    fn stub(canned: &str) -> StubPoster {
        StubPoster {
            canned: canned.as_bytes().to_vec(),
            last: Mutex::new(None),
        }
    }

    #[test]
    fn url_encode_handles_specials() {
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("hello+world"), "hello%2Bworld");
        assert_eq!(urlencode("safe-._~"), "safe-._~");
        assert_eq!(urlencode("привет"), "%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82");
    }

    #[test]
    fn body_builder_includes_remoteip_when_set() {
        let b = build_siteverify_body("sek", "tok", Some("1.2.3.4"));
        assert_eq!(b, "secret=sek&response=tok&remoteip=1.2.3.4");
        let b = build_siteverify_body("sek", "tok", None);
        assert_eq!(b, "secret=sek&response=tok");
    }

    #[test]
    fn parser_extracts_full_response() {
        let raw = br#"{"success":true,"score":0.9,"action":"login","hostname":"ex.com","error-codes":["x"]}"#;
        let v = parse_siteverify(raw);
        assert!(v.success);
        assert_eq!(v.score, Some(0.9));
        assert_eq!(v.action.as_deref(), Some("login"));
        assert_eq!(v.hostname.as_deref(), Some("ex.com"));
        assert_eq!(v.error_codes, vec!["x".to_string()]);
    }

    #[test]
    fn parser_handles_missing_optionals() {
        let raw = br#"{"success":true}"#;
        let v = parse_siteverify(raw);
        assert!(v.success);
        assert!(v.score.is_none());
        assert!(v.error_codes.is_empty());
    }

    #[test]
    fn parser_returns_failure_on_malformed_json() {
        let v = parse_siteverify(b"not json");
        assert!(!v.success);
        assert!(
            v.error_codes
                .contains(&"malformed-upstream-json".to_string())
        );
    }

    #[tokio::test]
    async fn hcaptcha_uses_correct_endpoint_and_body() {
        let p = stub(r#"{"success":true}"#);
        let c = HCaptcha::new("my-secret");
        let v = c.verify(&p, "user-token", Some("9.9.9.9")).await;
        assert!(v.success);
        let last = p.last.lock().unwrap().clone().unwrap();
        assert_eq!(last.0, "https://hcaptcha.com/siteverify");
        assert_eq!(
            last.1,
            "secret=my-secret&response=user-token&remoteip=9.9.9.9"
        );
    }

    #[tokio::test]
    async fn turnstile_uses_correct_endpoint() {
        let p = stub(r#"{"success":true}"#);
        let c = Turnstile::new("ts-secret");
        let v = c.verify(&p, "tok", None).await;
        assert!(v.success);
        let last = p.last.lock().unwrap().clone().unwrap();
        assert_eq!(
            last.0,
            "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        );
    }

    #[tokio::test]
    async fn recaptcha_demotes_low_score() {
        // v3 token with score 0.2; configured threshold 0.5 → fail.
        let p = stub(r#"{"success":true,"score":0.2,"action":"login"}"#);
        let c = ReCaptcha::new("g-secret");
        let v = c.verify(&p, "tok", None).await;
        assert!(!v.success);
        assert!(
            v.error_codes
                .iter()
                .any(|e| e.starts_with("score-below-threshold"))
        );
    }

    #[tokio::test]
    async fn recaptcha_accepts_score_above_threshold() {
        let p = stub(r#"{"success":true,"score":0.9,"action":"login"}"#);
        let c = ReCaptcha::new("g-secret").with_min_score(0.7);
        let v = c.verify(&p, "tok", None).await;
        assert!(v.success);
    }

    #[tokio::test]
    async fn recaptcha_v2_no_score_passes_through() {
        // v2 tokens never include score → no demotion path triggers.
        let p = stub(r#"{"success":true}"#);
        let c = ReCaptcha::new("g-secret");
        let v = c.verify(&p, "tok", None).await;
        assert!(v.success);
    }

    struct ErrPoster;
    #[async_trait::async_trait]
    impl HttpPoster for ErrPoster {
        async fn post_form(&self, _u: &str, _b: &str, _t: Duration) -> Result<Vec<u8>> {
            Err(anyhow!("network down"))
        }
    }

    #[tokio::test]
    async fn transport_error_produces_failure_verdict() {
        let c = HCaptcha::new("s");
        let v = c.verify(&ErrPoster, "tok", None).await;
        assert!(!v.success);
        assert!(v.error_codes.contains(&"transport-error".to_string()));
    }
}
