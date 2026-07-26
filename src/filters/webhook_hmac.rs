//! V114 — Webhook HMAC verification (info.md P2).
//!
//! V230 — Audited for per-request allocations. Verdict is a Copy enum
//! (no String reasons; this filter never emits FilterAction::Deny — it
//! returns a verdict the caller maps). The only required heap allocs
//! on the hot path are the Stripe/Slack signing-string Vecs (which
//! prepend timestamps to body bytes — fundamental to the schemes).
//! Removed the per-call Vec allocation in `decode_hex` by switching
//! the verification path to a stack-buffered decoder.
//!
//! Operators commonly need to bypass WAF / rate-limit on inbound
//! webhook endpoints (GitHub, Stripe, Slack, GitLab, etc.) because
//! those POSTs look like attack traffic to a generic edge:
//!
//! * non-browser User-Agents,
//! * high body-content variance,
//! * sometimes non-2xx Content-Type values,
//! * bursts during platform incidents.
//!
//! The current `BypassMatcher` allows operators to do this via
//! IP/UA/path matching — but that's brittle (UA can be spoofed by
//! anyone) and dangerous (path match means the attacker only needs
//! the URL). HMAC verification fixes it: only requests carrying a
//! valid signature (HMAC over body with a shared secret) bypass.
//!
//! Supported provider templates (built-in shapes):
//!
//! * GitHub: `X-Hub-Signature-256: sha256=<hex>` over the body.
//! * Stripe: `Stripe-Signature: t=<ts>,v1=<hex>` over `<ts>.<body>`,
//!   timestamp must be within 5 min skew.
//! * Slack: `X-Slack-Signature: v0=<hex>` over `v0:<ts>:<body>`,
//!   with `X-Slack-Request-Timestamp` header.
//! * GitLab: `X-Gitlab-Token: <token>` exact-match (not HMAC, but
//!   the typical GitLab webhook auth shape).
//! * Generic: `<header>: <hex>` over body, operator-supplied header
//!   name + algorithm (`sha256` / `sha1` / `sha512`).
//!
//! Each rule binds {provider template, secret, host filter, path filter}.
//! Verification short-circuits the request as `Trusted` for the
//! filter pipeline; failure means the bypass is denied and the
//! request continues through the normal filter chain (it's not
//! itself a deny — the legitimate upstream will reject the bad
//! signature anyway, but if it's a probe the WAF / threat scorer
//! will see it).

use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Sha256, Sha512};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum skew between a webhook signature timestamp and our local
/// clock. 5 minutes matches Stripe + Slack documented tolerances.
const TS_SKEW_TOLERANCE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub enum HmacRule {
    GitHub {
        secret: String,
    },
    Stripe {
        secret: String,
    },
    Slack {
        secret: String,
    },
    GitLab {
        token: String,
    },
    Generic {
        header: String,
        algorithm: GenericAlgo,
        secret: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericAlgo {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// HMAC signature matched; caller should treat request as Trusted
    /// for the filter pipeline (skip WAF / rate-limit / challenge).
    Trusted,
    /// No matching rule fired — request continues through normal
    /// pipeline. NOT a deny.
    NoMatch,
    /// A rule was supposed to apply (header present / path matched)
    /// but the signature didn't verify. Operator-defined: callers
    /// SHOULD reject these (the upstream would also reject).
    InvalidSignature,
}

pub struct WebhookHmac {
    rules: Vec<HmacRule>,
}

impl WebhookHmac {
    pub fn new(rules: Vec<HmacRule>) -> Self {
        Self { rules }
    }

    /// Walk every configured rule against the request. Returns the
    /// first matching verdict (rules are evaluated in registration
    /// order). Body is the raw request body bytes — caller must have
    /// already buffered it (typical webhook bodies are <64 KiB).
    pub fn verify(&self, headers: &HeaderMap, body: &[u8]) -> Verdict {
        for r in &self.rules {
            match r {
                HmacRule::GitHub { secret } => {
                    if let Some(sig) = header_str(headers, "x-hub-signature-256")
                        && let Some(hex) = sig.strip_prefix("sha256=")
                    {
                        return verify_hex_hmac_sha256(secret.as_bytes(), body, hex);
                    }
                }
                HmacRule::Stripe { secret } => {
                    if let Some(sig) = header_str(headers, "stripe-signature")
                        && let Some((ts, v1)) = parse_stripe_sig(sig)
                    {
                        if !timestamp_within_skew(ts) {
                            return Verdict::InvalidSignature;
                        }
                        let mut msg = Vec::with_capacity(body.len() + 32);
                        msg.extend_from_slice(ts.as_bytes());
                        msg.push(b'.');
                        msg.extend_from_slice(body);
                        return verify_hex_hmac_sha256(secret.as_bytes(), &msg, v1);
                    }
                }
                HmacRule::Slack { secret } => {
                    if let (Some(sig), Some(ts)) = (
                        header_str(headers, "x-slack-signature"),
                        header_str(headers, "x-slack-request-timestamp"),
                    ) && let Some(hex) = sig.strip_prefix("v0=")
                    {
                        if !timestamp_within_skew(ts) {
                            return Verdict::InvalidSignature;
                        }
                        let mut msg = Vec::with_capacity(body.len() + 16);
                        msg.extend_from_slice(b"v0:");
                        msg.extend_from_slice(ts.as_bytes());
                        msg.push(b':');
                        msg.extend_from_slice(body);
                        return verify_hex_hmac_sha256(secret.as_bytes(), &msg, hex);
                    }
                }
                HmacRule::GitLab { token } => {
                    if let Some(supplied) = header_str(headers, "x-gitlab-token") {
                        if constant_time_eq(supplied.as_bytes(), token.as_bytes()) {
                            return Verdict::Trusted;
                        } else {
                            return Verdict::InvalidSignature;
                        }
                    }
                }
                HmacRule::Generic {
                    header,
                    algorithm,
                    secret,
                } => {
                    if let Some(sig) = header_str(headers, header) {
                        return match algorithm {
                            GenericAlgo::Sha256 => {
                                verify_hex_hmac_sha256(secret.as_bytes(), body, sig)
                            }
                            GenericAlgo::Sha512 => {
                                verify_hex_hmac_sha512(secret.as_bytes(), body, sig)
                            }
                        };
                    }
                }
            }
        }
        Verdict::NoMatch
    }
}

/// Cheap header lookup that lowercases the name once.
fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn parse_stripe_sig(sig: &str) -> Option<(&str, &str)> {
    // Format: "t=1492774577,v1=abc...,v0=..." — multiple v1 entries
    // possible during key rotation; take the first.
    let mut ts = None;
    let mut v1 = None;
    for part in sig.split(',') {
        let trimmed = part.trim();
        if let Some(v) = trimmed.strip_prefix("t=") {
            ts = Some(v);
        } else if let Some(v) = trimmed.strip_prefix("v1=")
            && v1.is_none()
        {
            v1 = Some(v);
        }
    }
    Some((ts?, v1?))
}

fn timestamp_within_skew(ts: &str) -> bool {
    let Ok(t) = ts.parse::<u64>() else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now_s = now.as_secs();
    let skew = now_s.abs_diff(t);
    Duration::from_secs(skew) <= TS_SKEW_TOLERANCE
}

fn verify_hex_hmac_sha256(secret: &[u8], msg: &[u8], expected_hex: &str) -> Verdict {
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(secret) else {
        return Verdict::InvalidSignature;
    };
    mac.update(msg);
    cmp_hex_against_mac(&mac.finalize().into_bytes(), expected_hex)
}

fn verify_hex_hmac_sha512(secret: &[u8], msg: &[u8], expected_hex: &str) -> Verdict {
    let Ok(mut mac) = <Hmac<Sha512> as Mac>::new_from_slice(secret) else {
        return Verdict::InvalidSignature;
    };
    mac.update(msg);
    cmp_hex_against_mac(&mac.finalize().into_bytes(), expected_hex)
}

// V230 — HMAC outputs are bounded: SHA256=32B, SHA512=64B. Decoded
// signatures will never exceed 64 bytes; use a stack buffer so the
// hot verification path allocates zero Vecs per request.
const MAX_DECODED_HEX: usize = 64;

fn cmp_hex_against_mac(actual: &[u8], expected_hex: &str) -> Verdict {
    // V230 — stack-allocated decode buffer, no per-request heap allocation.
    let mut buf = [0u8; MAX_DECODED_HEX];
    let Ok(decoded_len) = decode_hex_into(expected_hex, &mut buf) else {
        return Verdict::InvalidSignature;
    };
    let expected_bytes = &buf[..decoded_len];
    if expected_bytes.len() != actual.len() {
        return Verdict::InvalidSignature;
    }
    if constant_time_eq(expected_bytes, actual) {
        Verdict::Trusted
    } else {
        Verdict::InvalidSignature
    }
}

// V230 — decode into a caller-provided buffer to avoid Vec allocation
// on every signature check. Returns the number of bytes written.
fn decode_hex_into(s: &str, out: &mut [u8]) -> Result<usize, ()> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(());
    }
    let need = s.len() / 2;
    if need > out.len() {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut j = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out[j] = (hi << 4) | lo;
        j += 1;
        i += 2;
    }
    Ok(need)
}

// V230 — retained Vec-returning helper for the test module's API expectations.
#[cfg(test)]
fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let mut buf = [0u8; MAX_DECODED_HEX];
    let n = decode_hex_into(s, &mut buf)?;
    Ok(buf[..n].to_vec())
}

fn hex_val(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(10 + c - b'a'),
        b'A'..=b'F' => Ok(10 + c - b'A'),
        _ => Err(()),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for i in 0..a.len() {
        x |= a[i] ^ b[i];
    }
    x == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn hmac_hex(secret: &[u8], msg: &[u8]) -> String {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
        m.update(msg);
        let bytes = m.finalize().into_bytes();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn hmac_sha512_hex(secret: &[u8], msg: &[u8]) -> String {
        let mut m = <Hmac<Sha512> as Mac>::new_from_slice(secret).unwrap();
        m.update(msg);
        let bytes = m.finalize().into_bytes();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn now_ts() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[test]
    fn github_valid_signature_trusts() {
        let body = b"{\"action\":\"opened\"}";
        let sig = format!("sha256={}", hmac_hex(b"secret", body));
        let mut h = HeaderMap::new();
        h.insert("x-hub-signature-256", HeaderValue::from_str(&sig).unwrap());
        let w = WebhookHmac::new(vec![HmacRule::GitHub {
            secret: "secret".to_string(),
        }]);
        assert_eq!(w.verify(&h, body), Verdict::Trusted);
    }

    #[test]
    fn github_invalid_signature_rejects() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-hub-signature-256",
            HeaderValue::from_static(
                "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ),
        );
        let w = WebhookHmac::new(vec![HmacRule::GitHub {
            secret: "secret".to_string(),
        }]);
        assert_eq!(w.verify(&h, b"body"), Verdict::InvalidSignature);
    }

    #[test]
    fn stripe_signature_with_skewed_ts_rejects() {
        let body = b"{}";
        let stale_ts = "1000000000"; // 2001
        let v1 = hmac_hex(b"sec", format!("{stale_ts}.{}", "{}").as_bytes());
        let mut h = HeaderMap::new();
        h.insert(
            "stripe-signature",
            HeaderValue::from_str(&format!("t={stale_ts},v1={v1}")).unwrap(),
        );
        let w = WebhookHmac::new(vec![HmacRule::Stripe {
            secret: "sec".to_string(),
        }]);
        assert_eq!(w.verify(&h, body), Verdict::InvalidSignature);
    }

    #[test]
    fn stripe_valid_signature_trusts() {
        let body = b"{}";
        let ts = now_ts();
        let msg = format!("{ts}.{}", std::str::from_utf8(body).unwrap());
        let v1 = hmac_hex(b"sec", msg.as_bytes());
        let mut h = HeaderMap::new();
        h.insert(
            "stripe-signature",
            HeaderValue::from_str(&format!("t={ts},v1={v1}")).unwrap(),
        );
        let w = WebhookHmac::new(vec![HmacRule::Stripe {
            secret: "sec".to_string(),
        }]);
        assert_eq!(w.verify(&h, body), Verdict::Trusted);
    }

    #[test]
    fn slack_valid_signature_trusts() {
        let body = b"token=xyz&team_id=T0001";
        let ts = now_ts();
        let basestring = format!("v0:{ts}:{}", std::str::from_utf8(body).unwrap());
        let hex = hmac_hex(b"sk", basestring.as_bytes());
        let mut h = HeaderMap::new();
        h.insert(
            "x-slack-signature",
            HeaderValue::from_str(&format!("v0={hex}")).unwrap(),
        );
        h.insert(
            "x-slack-request-timestamp",
            HeaderValue::from_str(&ts).unwrap(),
        );
        let w = WebhookHmac::new(vec![HmacRule::Slack {
            secret: "sk".to_string(),
        }]);
        assert_eq!(w.verify(&h, body), Verdict::Trusted);
    }

    #[test]
    fn gitlab_token_trusts() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-gitlab-token",
            HeaderValue::from_static("super-secret-token"),
        );
        let w = WebhookHmac::new(vec![HmacRule::GitLab {
            token: "super-secret-token".to_string(),
        }]);
        assert_eq!(w.verify(&h, b"any body"), Verdict::Trusted);
    }

    #[test]
    fn gitlab_wrong_token_rejects() {
        let mut h = HeaderMap::new();
        h.insert("x-gitlab-token", HeaderValue::from_static("wrong-token"));
        let w = WebhookHmac::new(vec![HmacRule::GitLab {
            token: "right-token".to_string(),
        }]);
        assert_eq!(w.verify(&h, b""), Verdict::InvalidSignature);
    }

    #[test]
    fn no_rule_header_returns_nomatch() {
        let h = HeaderMap::new();
        let w = WebhookHmac::new(vec![HmacRule::GitHub {
            secret: "secret".to_string(),
        }]);
        assert_eq!(w.verify(&h, b"body"), Verdict::NoMatch);
    }

    #[test]
    fn generic_sha512_provider_works() {
        let body = b"payload";
        let hex = hmac_sha512_hex(b"k", body);
        let mut h = HeaderMap::new();
        h.insert("x-my-sig", HeaderValue::from_str(&hex).unwrap());
        let w = WebhookHmac::new(vec![HmacRule::Generic {
            header: "x-my-sig".to_string(),
            algorithm: GenericAlgo::Sha512,
            secret: "k".to_string(),
        }]);
        assert_eq!(w.verify(&h, body), Verdict::Trusted);
    }

    #[test]
    fn constant_time_eq_correct() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn decode_hex_handles_case() {
        assert_eq!(decode_hex("aB0F").unwrap(), vec![0xAB, 0x0F]);
        assert!(decode_hex("not-hex").is_err());
        assert!(decode_hex("abc").is_err()); // odd length
    }
}
