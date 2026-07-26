//! HTTP/3 / QUIC fingerprint.
//!
//! True JA4Q (FoxIO's QUIC variant) needs the raw Initial-packet
//! bytes — Initial header length, encrypted CRYPTO frame layout,
//! and the order of transport_parameters inside the inner
//! ClientHello. quinn doesn't expose those to user-space callers
//! (it consumes them in the inside of the handshake state machine),
//! so we approximate with what quinn *does* surface after the
//! handshake completes:
//!
//!   - QUIC version negotiated (e.g. `00000001` = RFC 9000)
//!   - ALPN string (`h3`, `h3-29`, …)
//!   - Set of peer transport-parameter values quinn exposes
//!     (max_idle_timeout, max_data, max_streams_uni, etc.)
//!
//! Hashed together into the JA4 family format:
//!
//!   `q{version}{alpn_tag}_{params_sha12}`
//!
//! Operators get a coarse-grained fingerprint that distinguishes
//! major QUIC implementations (chromium / firefox / cronet / quiche /
//! msquic) — enough to fingerprint scraper fleets even when JA3/JA4
//! are spoofed.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct H3Capture {
    /// QUIC version as a u32 — `0x00000001` is RFC 9000.
    pub version: u32,
    /// Negotiated ALPN (`h3`, `h3-29`, etc.). Empty when unknown.
    pub alpn: String,
    /// Subset of peer transport parameters quinn exposes after
    /// handshake. Stored as `(parameter_id, value)` pairs; we sort
    /// before hashing so frame-order differences don't matter.
    pub params: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Fingerprint {
    pub full: String,
    pub a: String,
    pub b: String,
}

pub fn compute(cap: &H3Capture) -> H3Fingerprint {
    let version_tag = format!("{:08x}", cap.version);
    let alpn_tag = alpn_two(&cap.alpn);
    let a = format!("q{version_tag}{alpn_tag}");
    let mut params = cap.params.clone();
    params.sort_unstable();
    let mut s = String::new();
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{k:x}:{v:x}"));
    }
    let b = sha_prefix12(s.as_bytes());
    H3Fingerprint {
        full: format!("{a}_{b}"),
        a,
        b,
    }
}

/// Same first-char + last-char ALPN tag JA4 uses, so a Chrome-h3
/// connection lines up with its Chrome-h2 counterpart.
fn alpn_two(alpn: &str) -> String {
    if alpn.is_empty() {
        return "00".to_string();
    }
    let bytes = alpn.as_bytes();
    let first = bytes[0];
    let last = *bytes.last().unwrap();
    format!("{}{}", char_or_hex(first), char_or_hex(last))
}

fn char_or_hex(b: u8) -> String {
    if b.is_ascii_graphic() {
        (b as char).to_ascii_lowercase().to_string()
    } else {
        format!("{b:02x}")
    }
}

fn sha_prefix12(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    let digest = h.finalize();
    let mut out = String::with_capacity(12);
    for x in digest.iter().take(6) {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_like_h3_fingerprint() {
        let cap = H3Capture {
            version: 0x0000_0001,
            alpn: "h3".to_string(),
            params: vec![
                (0x01, 30_000),     // max_idle_timeout
                (0x04, 12_582_912), // initial_max_data
                (0x08, 100),        // initial_max_streams_bidi
                (0x09, 100),        // initial_max_streams_uni
            ],
        };
        let fp = compute(&cap);
        assert!(fp.a.starts_with("q00000001"));
        assert!(fp.a.ends_with("h3"));
        assert_eq!(fp.b.len(), 12);
    }

    #[test]
    fn empty_alpn_uses_zero_tag() {
        let cap = H3Capture {
            version: 0x0000_0001,
            alpn: "".to_string(),
            params: vec![],
        };
        let fp = compute(&cap);
        assert!(fp.a.ends_with("00"));
    }

    #[test]
    fn param_order_doesnt_change_hash() {
        let a = compute(&H3Capture {
            version: 1,
            alpn: "h3".into(),
            params: vec![(1, 100), (4, 200)],
        });
        let b = compute(&H3Capture {
            version: 1,
            alpn: "h3".into(),
            params: vec![(4, 200), (1, 100)],
        });
        assert_eq!(a.b, b.b);
    }
}
