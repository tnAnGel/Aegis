//! V178 — utls GREASE anomaly detector.
//!
//! Idea: TLS clients that claim to be Chrome via JA4 should *also*
//! have Chrome-shaped GREASE values in the right positions. utls
//! (refraction-networking) and curl-impersonate can spoof JA4 but
//! often hardcode one GREASE permutation, while real Chrome varies
//! the GREASE positions by build:
//!
//! * Chrome puts a GREASE extension at index 0 of the extension list.
//! * Chrome puts a GREASE cipher suite at index 0 of the cipher list.
//! * Chrome's GREASE supported_versions value sits at the head of
//!   that extension's payload.
//!
//! Genuine Chrome ClientHellos have GREASE in all three positions
//! simultaneously. utls-spoofed Chrome typically gets two-out-of-three
//! or wrong-position GREASE.
//!
//! GREASE values are 0x{n}A{n}A for n ∈ {0..F}. Detection:
//! * Check first cipher suite — is it 0x{n}A{n}A pattern?
//! * Check first extension type — is it 0x{n}A{n}A pattern?
//! * Check supported_versions payload — does it start with 0x{n}A{n}A?
//!
//! Score:
//!
//!     score = (1 - matches/3) when client claims Chrome JA4
//!           = 0 when client doesn't claim Chrome
//!
//! Feeds the V139 ML scorer as `grease_anomaly`. Also feeds the V108
//! RiskEngine as a strong "anti-detect lying about being Chrome"
//! signal.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GreaseObservation {
    pub first_cipher_is_grease: bool,
    pub first_extension_is_grease: bool,
    pub supported_versions_starts_with_grease: bool,
}

impl GreaseObservation {
    /// 0.0 = looks like real Chrome (all three slots GREASE'd).
    /// 1.0 = none of the slots GREASE'd despite Chrome-shaped JA4.
    pub fn anomaly_score(&self) -> f32 {
        let hits = self.first_cipher_is_grease as u8
            + self.first_extension_is_grease as u8
            + self.supported_versions_starts_with_grease as u8;
        1.0 - (hits as f32 / 3.0)
    }

    pub fn looks_genuine(&self) -> bool {
        self.first_cipher_is_grease
            && self.first_extension_is_grease
            && self.supported_versions_starts_with_grease
    }
}

/// RFC 8701: GREASE values are `0x{n}A{n}A` for n ∈ {0..=F}.
/// Cipher suites: 0x0A0A, 0x1A1A, 0x2A2A, …, 0xFAFA.
/// Extensions / versions / named groups: same.
pub fn is_grease_u16(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Score an observation against a claimed JA4. If the JA4 doesn't
/// look Chrome-shaped, returns 0 (we can't expect GREASE from
/// non-Chrome clients).
pub fn score_against_ja4(obs: &GreaseObservation, ja4: &str) -> f32 {
    if !ja4_looks_like_chrome(ja4) {
        return 0.0;
    }
    obs.anomaly_score()
}

/// Cheap heuristic. Real implementation would consult V176 Ja4Corpus.
/// Chrome JA4s start `t13d15` or `t13d16` (TLS 1.3, 15-16 ciphers).
pub fn ja4_looks_like_chrome(ja4: &str) -> bool {
    let cipher_count_ok = ja4.starts_with("t13d15") || ja4.starts_with("t13d16");
    // Chrome family cipher hash from V176 seed.
    let cipher_hash_match = ja4.contains("_8daaf6152771_");
    cipher_count_ok || cipher_hash_match
}

/// Build observation from raw parsed ClientHello parts. Used by
/// callers wired into the TLS layer; tests construct directly.
pub fn observe(
    first_cipher: Option<u16>,
    first_extension: Option<u16>,
    supported_versions_head: Option<u16>,
) -> GreaseObservation {
    GreaseObservation {
        first_cipher_is_grease: first_cipher.is_some_and(is_grease_u16),
        first_extension_is_grease: first_extension.is_some_and(is_grease_u16),
        supported_versions_starts_with_grease: supported_versions_head.is_some_and(is_grease_u16),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_pattern_recognised() {
        assert!(is_grease_u16(0x0a0a));
        assert!(is_grease_u16(0x1a1a));
        assert!(is_grease_u16(0xfafa));
        assert!(!is_grease_u16(0x1301));
        assert!(!is_grease_u16(0x0a0b));
        assert!(!is_grease_u16(0x1a1b));
    }

    #[test]
    fn full_grease_means_genuine() {
        let obs = observe(Some(0x0a0a), Some(0x1a1a), Some(0x2a2a));
        assert!(obs.looks_genuine());
        assert_eq!(obs.anomaly_score(), 0.0);
    }

    #[test]
    fn no_grease_max_anomaly() {
        let obs = observe(Some(0x1301), Some(0x0017), Some(0x0304));
        assert!(!obs.looks_genuine());
        assert!((obs.anomaly_score() - 1.0).abs() < 0.01);
    }

    #[test]
    fn partial_grease_partial_score() {
        let obs = observe(Some(0x0a0a), Some(0x0017), Some(0x0304));
        let s = obs.anomaly_score();
        assert!((s - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn non_chrome_ja4_returns_zero_score() {
        let obs = observe(Some(0x1301), Some(0x0017), Some(0x0304));
        let s = score_against_ja4(&obs, "t13d3112h2_e8f1e7e78f70_1f22197e3bbe");
        assert_eq!(s, 0.0);
    }

    #[test]
    fn chrome_ja4_with_no_grease_flags() {
        let obs = observe(Some(0x1301), Some(0x0017), Some(0x0304));
        let s = score_against_ja4(&obs, "t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        assert!(s > 0.95);
    }
}
