//! V137 — Cross-fingerprint correlation score.
//!
//! Aegis computes 8 fingerprints per request (JA4, JA4H, JA4T, JA4L,
//! H2FP, H3FP, mTLS_FP, JA3 legacy). Each one in isolation is useful;
//! the *combination* is more useful because real browsers produce
//! *consistent* tuples. A bot using a Chrome JA4 but a Firefox User-
//! Agent header is a stronger signal than either fingerprint alone.
//!
//! This module turns the fingerprint set into a single
//! [CorrelationScore] in [0.0, 1.0] where 0 means "all signals agree"
//! and 1 means "fingerprints contradict each other — almost certainly
//! a tool impersonating a browser".
//!
//! ## Detected mismatches
//!
//! * **JA4 family ≠ UA family**: TLS handshake says Chrome, UA says
//!   Firefox / curl / Go. Almost always a request-replay or UA-spoof
//!   bot. (Strongest signal.)
//! * **H2FP family ≠ JA4 family**: TLS says one browser, HTTP/2
//!   SETTINGS frame says another. Real browsers ship matched stacks.
//! * **JA4 present + JA4H missing**: TLS terminated through Aegis but
//!   no parsable HTTP/2 request — usually a probe.
//! * **UA claims Chrome but no Accept-Language**: real Chrome always
//!   sends Accept-Language; absence is a strong tool tell.
//!
//! The score is used as a feature for the ML scorer (V122 / V136) and
//! as a standalone signal for the WAF risk engine (V108).
//!
//! ## Why a *score* and not a hard rule?
//!
//! Legitimate edge cases exist: corporate MITM proxies rewrite TLS
//! and UA independently, mobile networks compress headers, browser
//! extensions add custom UAs. A hard "mismatch → deny" rule would
//! false-positive on those. A score lets the risk engine combine it
//! with other signals before deciding.

/// Bundle of fingerprints + UA the correlator inspects. All fields
/// optional — missing fingerprints just don't contribute to the score.
#[derive(Debug, Clone, Default)]
pub struct FingerprintSet<'a> {
    pub ja4: Option<&'a str>,
    pub ja4h: Option<&'a str>,
    pub h2fp: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub accept_language: Option<&'a str>,
    pub accept_encoding: Option<&'a str>,
}

/// Coarse browser family inferred from JA4, UA, or H2FP. "Unknown"
/// catches tooling fingerprints (curl, Go, Python requests, custom
/// async clients).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserFamily {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Tool, // curl, wget, python, go, java, rust, ...
    Unknown,
}

/// Computed correlation result. `score` near 0 = consistent; near 1
/// = strong mismatch. `reasons` is a stable list of `&'static str`
/// tags safe to emit as Prometheus labels.
#[derive(Debug, Clone)]
pub struct CorrelationScore {
    pub score: f32,
    pub reasons: Vec<&'static str>,
    pub ja4_family: BrowserFamily,
    pub ua_family: BrowserFamily,
    pub h2fp_family: BrowserFamily,
}

impl CorrelationScore {
    pub fn consistent() -> Self {
        Self {
            score: 0.0,
            reasons: vec![],
            ja4_family: BrowserFamily::Unknown,
            ua_family: BrowserFamily::Unknown,
            h2fp_family: BrowserFamily::Unknown,
        }
    }
}

/// JA4 strings start with a 5-char info block (e.g. `t13d1516h2_…`),
/// then `_` separators. The detection here is community-derived
/// (FoxIO / JA4 cookbook) — Chrome uses specific GREASE-cleansed
/// cipher orderings that produce stable prefixes; same for Firefox.
/// Future improvement: pull a JA4 → family map from a reputation feed
/// (V138 wires that infrastructure).
///
/// `pub` so the passive challenge-signal evaluator
/// ([`crate::challenge_signals`]) can reuse the same JA4→family
/// classifier the correlator uses, rather than maintaining a second
/// copy of the prefix table.
pub fn ja4_family(ja4: &str) -> BrowserFamily {
    // Prefix patterns observed in published JA4 fingerprint DBs.
    // We match on the first hash block (after the info prefix) which
    // is the cipher list hash — the most stable browser identifier.
    let parts: Vec<&str> = ja4.split('_').collect();
    if parts.len() < 3 {
        return BrowserFamily::Unknown;
    }
    let cipher_hash = parts[1];
    // Known browser cipher-hash prefixes (truncated, illustrative).
    // Real deployment overrides via reputation feed (V138).
    match cipher_hash.get(..4).unwrap_or("") {
        "8daa" | "9b0f" | "1f4f" => BrowserFamily::Chrome,
        "5b57" | "2a35" => BrowserFamily::Firefox,
        "f4eb" => BrowserFamily::Safari,
        "f4be" => BrowserFamily::Edge,
        _ => BrowserFamily::Unknown,
    }
}

/// Coarse UA-substring classifier. Real implementations use the
/// `woothee` / `uap-rs` crates, but for the correlator we only need
/// the family bucket, not the version. Tool detection catches the
/// common automation suspects so a curl-with-Chrome-JA4 lights up.
pub fn ua_family(ua: &str) -> BrowserFamily {
    let u = ua.to_ascii_lowercase();
    // Tool signatures — these are almost always bots regardless of
    // any JA4 they manage to spoof.
    if u.contains("curl")
        || u.contains("wget")
        || u.contains("python")
        || u.starts_with("go-http")
        || u.contains("java/")
        || u.contains("okhttp")
        || u.contains("aiohttp")
        || u.contains("postmanruntime")
        || u.contains("rust-")
        || u.contains("libwww")
        || u.contains("scrapy")
        || u.contains("httpx")
    {
        return BrowserFamily::Tool;
    }
    // Order matters: Edge UA contains "Chrome", Chrome doesn't contain
    // "Edge". Check Edge first.
    if u.contains("edg/") || u.contains("edge/") {
        return BrowserFamily::Edge;
    }
    if u.contains("firefox/") {
        return BrowserFamily::Firefox;
    }
    if u.contains("chrome/") || u.contains("chromium/") {
        return BrowserFamily::Chrome;
    }
    // Safari UA contains "Safari" but NOT "Chrome" — Chrome's UA has
    // both. So only treat as Safari if not Chrome.
    if u.contains("safari/") && !u.contains("chrome/") {
        return BrowserFamily::Safari;
    }
    BrowserFamily::Unknown
}

/// H2FP family detection. Chrome / Firefox / Safari each ship
/// distinctive HTTP/2 SETTINGS values + pseudo-header orderings.
/// The full H2FP string is a hash; here we recognise canonical
/// prefixes for the major browsers. Like JA4, real deployments back
/// this with a reputation feed.
fn h2fp_family(h2fp: &str) -> BrowserFamily {
    // H2FP encodes settings as `setting1:val1|setting2:val2;...`.
    // Chrome uses SETTINGS_HEADER_TABLE_SIZE=65536 + INITIAL_WINDOW=
    // 6291456. Firefox uses 65536 + 131072. Safari uses 4096 + 65536.
    let lower = h2fp.to_ascii_lowercase();
    if lower.contains("1:65536") && lower.contains("4:6291456") {
        return BrowserFamily::Chrome;
    }
    if lower.contains("1:65536") && lower.contains("4:131072") {
        return BrowserFamily::Firefox;
    }
    if lower.contains("1:4096") {
        return BrowserFamily::Safari;
    }
    BrowserFamily::Unknown
}

/// Run the correlator over a request's fingerprint bundle.
pub fn correlate(fp: &FingerprintSet<'_>) -> CorrelationScore {
    let ja4_fam = fp.ja4.map(ja4_family).unwrap_or(BrowserFamily::Unknown);
    let ua_fam = fp
        .user_agent
        .map(ua_family)
        .unwrap_or(BrowserFamily::Unknown);
    let h2_fam = fp.h2fp.map(h2fp_family).unwrap_or(BrowserFamily::Unknown);

    let mut score = 0.0_f32;
    let mut reasons: Vec<&'static str> = vec![];

    // Strongest signal: TLS family disagrees with UA family. Each
    // disagreement adds 0.45 so a single mismatch puts us well above
    // 0.5 while leaving room for stacked mismatches to clip at 1.0.
    if ja4_fam != BrowserFamily::Unknown && ua_fam != BrowserFamily::Unknown && ja4_fam != ua_fam {
        // Tool UA + browser JA4: the canonical "evilginx / proxy"
        // pattern. Weight slightly higher.
        if ua_fam == BrowserFamily::Tool {
            score += 0.55;
            reasons.push("ja4_browser_ua_tool");
        } else {
            score += 0.45;
            reasons.push("ja4_ua_family_mismatch");
        }
    }

    // H2FP vs JA4 disagreement: TLS and HTTP/2 stacks should match.
    if ja4_fam != BrowserFamily::Unknown && h2_fam != BrowserFamily::Unknown && ja4_fam != h2_fam {
        score += 0.35;
        reasons.push("ja4_h2fp_family_mismatch");
    }

    // UA claims a browser but Accept-Language missing: real browsers
    // always include it. Mild signal because some privacy extensions
    // strip headers.
    let claims_browser = matches!(
        ua_fam,
        BrowserFamily::Chrome
            | BrowserFamily::Firefox
            | BrowserFamily::Safari
            | BrowserFamily::Edge
    );
    if claims_browser && fp.accept_language.is_none() {
        score += 0.15;
        reasons.push("browser_ua_no_accept_language");
    }
    if claims_browser && fp.accept_encoding.is_none() {
        score += 0.10;
        reasons.push("browser_ua_no_accept_encoding");
    }

    // JA4 present + JA4H missing: TLS but no parsable HTTP request —
    // protocol probe.
    if fp.ja4.is_some() && fp.ja4h.is_none() {
        score += 0.10;
        reasons.push("ja4_present_ja4h_missing");
    }

    CorrelationScore {
        score: score.clamp(0.0, 1.0),
        reasons,
        ja4_family: ja4_fam,
        ua_family: ua_fam,
        h2fp_family: h2_fam,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_unknown_inputs_score_zero() {
        let fp = FingerprintSet::default();
        let r = correlate(&fp);
        assert_eq!(r.score, 0.0);
        assert!(r.reasons.is_empty());
    }

    #[test]
    fn coherent_chrome_request_scores_low() {
        let fp = FingerprintSet {
            ja4: Some("t13d1516h2_8daaf6152771_b186095e22b6"),
            ja4h: Some("ge11nn0500_xxx_yyy_zzz"),
            h2fp: Some("1:65536|4:6291456"),
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ),
            accept_language: Some("en-US,en;q=0.9"),
            accept_encoding: Some("gzip, deflate, br"),
        };
        let r = correlate(&fp);
        assert!(
            r.score < 0.1,
            "coherent Chrome should score near 0, got {}",
            r.score
        );
        assert_eq!(r.ja4_family, BrowserFamily::Chrome);
        assert_eq!(r.ua_family, BrowserFamily::Chrome);
        assert_eq!(r.h2fp_family, BrowserFamily::Chrome);
    }

    #[test]
    fn chrome_ja4_with_curl_ua_scores_high() {
        let fp = FingerprintSet {
            ja4: Some("t13d1516h2_8daaf6152771_b186095e22b6"),
            user_agent: Some("curl/8.4.0"),
            ..Default::default()
        };
        let r = correlate(&fp);
        assert!(
            r.score >= 0.5,
            "Chrome TLS + curl UA must score >=0.5, got {}",
            r.score
        );
        assert!(r.reasons.contains(&"ja4_browser_ua_tool"));
    }

    #[test]
    fn chrome_tls_with_firefox_ua_lights_up() {
        let fp = FingerprintSet {
            ja4: Some("t13d1516h2_8daaf6152771_xxxxx"),
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
            ),
            ..Default::default()
        };
        let r = correlate(&fp);
        assert!(r.score >= 0.4);
        assert!(r.reasons.contains(&"ja4_ua_family_mismatch"));
        assert_eq!(r.ja4_family, BrowserFamily::Chrome);
        assert_eq!(r.ua_family, BrowserFamily::Firefox);
    }

    #[test]
    fn ja4_h2fp_disagreement_scores_mid() {
        let fp = FingerprintSet {
            ja4: Some("t13d1516h2_8daaf6152771_xxx"), // Chrome
            h2fp: Some("1:65536|4:131072"),           // Firefox
            user_agent: Some(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 Chrome/120.0.0.0 Safari/537.36",
            ),
            ..Default::default()
        };
        let r = correlate(&fp);
        assert!(r.score >= 0.3);
        assert!(r.reasons.contains(&"ja4_h2fp_family_mismatch"));
    }

    #[test]
    fn ua_classifier_detects_all_major_families() {
        assert_eq!(ua_family("Mozilla/5.0 Chrome/120.0"), BrowserFamily::Chrome);
        assert_eq!(
            ua_family("Mozilla/5.0 Firefox/121.0"),
            BrowserFamily::Firefox
        );
        assert_eq!(ua_family("Mozilla/5.0 Safari/605.0"), BrowserFamily::Safari);
        // Edge UA contains "Chrome" — must be detected as Edge first.
        assert_eq!(
            ua_family("Mozilla/5.0 Chrome/120 Edg/120"),
            BrowserFamily::Edge
        );
        assert_eq!(ua_family("curl/8.4.0"), BrowserFamily::Tool);
        assert_eq!(ua_family("python-requests/2.31"), BrowserFamily::Tool);
        assert_eq!(ua_family("Go-http-client/1.1"), BrowserFamily::Tool);
        assert_eq!(ua_family("okhttp/4.9.3"), BrowserFamily::Tool);
        assert_eq!(ua_family(""), BrowserFamily::Unknown);
        assert_eq!(ua_family("MysteryBot/1.0"), BrowserFamily::Unknown);
    }

    #[test]
    fn browser_ua_without_accept_language_adds_signal() {
        let fp = FingerprintSet {
            user_agent: Some("Mozilla/5.0 Chrome/120"),
            ..Default::default()
        };
        let r = correlate(&fp);
        assert!(r.reasons.contains(&"browser_ua_no_accept_language"));
        assert!(r.score >= 0.1);
    }

    #[test]
    fn ja4_present_without_ja4h_adds_signal() {
        let fp = FingerprintSet {
            ja4: Some("t13d1516h2_8daaf6152771_xxx"),
            ..Default::default()
        };
        let r = correlate(&fp);
        assert!(r.reasons.contains(&"ja4_present_ja4h_missing"));
    }

    #[test]
    fn score_clips_at_one() {
        // Stack every mismatch to ensure clamping.
        let fp = FingerprintSet {
            ja4: Some("t13d1516h2_8daaf6152771_xxx"), // Chrome
            h2fp: Some("1:65536|4:131072"),           // Firefox
            user_agent: Some("curl/8.4.0"),
            accept_language: None,
            accept_encoding: None,
            ..Default::default()
        };
        let r = correlate(&fp);
        assert!(r.score <= 1.0);
        assert!(r.score >= 0.8, "stacked mismatches should be near 1.0");
    }
}
