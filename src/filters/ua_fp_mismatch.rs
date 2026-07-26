//! V110 — UA vs TLS fingerprint mismatch detector.
//!
//! Info.md P1: "UA easy to fake; TLS/H2/H3 fingerprints + header
//! order much harder to fake at scale". This detector cross-checks
//! the User-Agent string against the JA4 (or JA4H) fingerprint family
//! and flags requests where a "browser" UA carries a non-browser
//! fingerprint — a strong-confidence bot signal.
//!
//! Output: a [Mismatch] kind that callers feed into the V108 RiskEngine
//! via the `bot_score` or as a custom reason. Not a stand-alone filter
//! that returns Deny — V108 prescribes "single signals never enforce,
//! combinations do".
//!
//! Heuristics (intentionally conservative — we want zero false-positives
//! on real browser traffic):
//!
//! * UA claims Chrome/Edge → JA4 should start with "t13d" (TLS 1.3
//!   with server-name SNI) and JA4_b should be in the Chromium-like
//!   cipher families. JA4 starting with "go" / "py" / "ja4_curl-like"
//!   is mismatch.
//! * UA claims Safari → JA4 "t13d" + Safari-like ALPN ordering.
//! * UA claims Firefox → JA4 "t13d" + Firefox-distinct cipher prefix.
//! * UA is curl/python/go but JA4 looks Chrome-like → likely a tool
//!   masquerading; weaker mismatch (low confidence).
//! * No JA4 captured (plain HTTP, or capture failed) → not a mismatch
//!   signal (we don't penalise absence; V97 ML already factors that
//!   via `ja4_unusual=1.0`).
//!
//! The taxonomy of known fingerprint prefixes is a compile-time list
//! curated from public JA4 datasets (Cloudflare, FoxIO). It is NOT
//! a full TLS fingerprint database — that lives in the upcoming JA4
//! reputation feed (V113-adjacent). The check here is just
//! "does the family match what the UA claims".

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Anchored, Input, StartKind};

use crate::proxy::request_context::RequestContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// No mismatch detected (clean or insufficient data).
    None,
    /// UA claims a major browser but the JA4 family doesn't match.
    /// High-confidence bot indicator.
    BrowserUaNonBrowserFp,
    /// UA claims a known automation tool but the JA4 family looks
    /// browser-like. Lower confidence — could be a tool that
    /// deliberately mimics a browser TLS stack (Cycle TLS, etc.).
    ToolUaBrowserFp,
    /// UA is empty AND a JA4 was captured. Common with scrapers
    /// that strip headers but still complete the TLS handshake.
    NoUaWithFp,
}

impl Mismatch {
    /// Rough risk contribution for the V108 RiskEngine. Plumbed via a
    /// new RiskInput field in V108-followup; until then callers can
    /// `into_bot_score()` and merge into the existing bot_score
    /// signal.
    pub fn risk_contribution(self) -> u8 {
        match self {
            Mismatch::None => 0,
            Mismatch::BrowserUaNonBrowserFp => 35,
            Mismatch::ToolUaBrowserFp => 15,
            Mismatch::NoUaWithFp => 12,
        }
    }

    /// Stable reason string for logs / Prometheus labels.
    pub fn reason_str(self) -> &'static str {
        match self {
            Mismatch::None => "ua_fp_match",
            Mismatch::BrowserUaNonBrowserFp => "ua_fp_mismatch_browser_ua",
            Mismatch::ToolUaBrowserFp => "ua_fp_mismatch_tool_ua",
            Mismatch::NoUaWithFp => "ua_fp_no_ua_with_fp",
        }
    }
}

/// Classify a request. Conservative — when in doubt, returns None.
pub fn classify(ctx: &RequestContext) -> Mismatch {
    let ua = ctx.user_agent.as_deref().unwrap_or("");
    let ja4 = ctx.ja4.as_deref().unwrap_or("");

    // No JA4 captured → can't decide. V97 ML scorer already factors
    // "ja4 absent" via its ja4_unusual feature; we don't double-count.
    if ja4.is_empty() {
        return Mismatch::None;
    }

    // Empty UA but JA4 present — typical for scrapers that strip
    // request headers. Weaker than full mismatch.
    if ua.is_empty() {
        return Mismatch::NoUaWithFp;
    }

    let ua_lower = ua.to_ascii_lowercase();
    let ua_kind = classify_ua(&ua_lower);
    let fp_kind = classify_ja4(ja4);

    match (ua_kind, fp_kind) {
        // Browser UA + non-browser JA4 → high-confidence mismatch.
        (UaKind::Browser, FpKind::Tool | FpKind::Unknown) => Mismatch::BrowserUaNonBrowserFp,
        // Tool UA + browser-like JA4 → tool emulating browser TLS.
        (UaKind::Tool, FpKind::Browser) => Mismatch::ToolUaBrowserFp,
        // Everything else matches or is undecidable.
        _ => Mismatch::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UaKind {
    Browser,
    Tool,
    /// UA neither resembles a browser nor a known tool. Could be a
    /// mobile app, IoT device, internal service; do not flag.
    Other,
}

// V230 — Tool / browser substring sets. Kept as `const` arrays so the
// pattern lists stay reviewable in source; the Aho-Corasick automatons
// below are built once on first use and reused for the process lifetime.
// Tools come first because "curl/8.0 Mozilla/5.0-compatible" is (rare
// but) ambiguous; treat the tool token as authoritative.
const TOOL_SUBSTRINGS: &[&str] = &[
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "java/",
    "okhttp/",
    "ruby",
    "perl/",
    "axios",
    "node-fetch",
    "httpx/",
    "aegis-distbench",
];
const BROWSER_SUBSTRINGS: &[&str] = &[
    "chrome/",
    "chromium/",
    "firefox/",
    "safari/",
    "edge/",
    "edg/",
    "opera/",
    "opr/",
];

/// V230 — single-pass Aho-Corasick over [`TOOL_SUBSTRINGS`]. Built
/// once on first request; replaces the per-call linear `.contains` scan
/// with one Teddy-SIMD pass over the (already lowercased) UA string.
fn tool_ua_automaton() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .build(TOOL_SUBSTRINGS)
            .expect("build UA tool-substring automaton")
    })
}

/// V230 — single-pass Aho-Corasick over [`BROWSER_SUBSTRINGS`]. Same
/// rationale as `tool_ua_automaton`; consulted only when the tool scan
/// did not match so the ordering semantics of the old function are
/// preserved exactly.
fn browser_ua_automaton() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .build(BROWSER_SUBSTRINGS)
            .expect("build UA browser-substring automaton")
    })
}

fn classify_ua(ua_lower: &str) -> UaKind {
    if tool_ua_automaton().is_match(ua_lower) {
        return UaKind::Tool;
    }
    if browser_ua_automaton().is_match(ua_lower) {
        return UaKind::Browser;
    }
    UaKind::Other
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpKind {
    Browser,
    Tool,
    /// JA4 family not recognised. With curated lists this is the
    /// long tail of legitimate-but-rare clients (older mobile
    /// browsers, embedded systems); we treat it as Unknown to avoid
    /// flagging.
    Unknown,
}

// V230 — Known-tool JA4 prefixes from public datasets. Go's net/http,
// curl, Python requests have very characteristic JA4 strings.
const JA4_TOOL_PREFIXES: &[&str] = &[
    "t13d191000_", // go net/http default — example from FoxIO dataset
    "t13d301400_", // python requests + urllib3 default
    "t12d1714h2_", // curl 8.x typical
    "t13d301300_", // python-aiohttp default
];

/// V230 — anchored Aho-Corasick over [`JA4_TOOL_PREFIXES`]. Built once,
/// then a single Teddy/NFA pass per request replaces the linear chain
/// of `starts_with` calls. `StartKind::Anchored` + `Anchored::Yes` on
/// the input forces matches to begin at offset 0, preserving the exact
/// `starts_with` semantics of the previous implementation.
fn ja4_tool_prefix_automaton() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .start_kind(StartKind::Anchored)
            .build(JA4_TOOL_PREFIXES)
            .expect("build JA4 tool-prefix automaton")
    })
}

/// Classify by JA4 prefix. The leading nibble + cipher-family bytes
/// distinguish browsers from tools fairly reliably in the public
/// datasets. We list specific known TOOL prefixes (high precision)
/// and treat the rest of "browser-looking" JA4 as Browser.
fn classify_ja4(ja4: &str) -> FpKind {
    let lower = ja4.to_ascii_lowercase();
    if ja4_tool_prefix_automaton().is_match(Input::new(lower.as_str()).anchored(Anchored::Yes)) {
        return FpKind::Tool;
    }
    // Browser-like: starts with t13d (TLS 1.3 + SNI) AND ALPN includes h2.
    // JA4_a format: t<tls_ver><dom_sni><n_ciphers><n_exts><alpn>_<...>_<...>
    // so ALPN is the trailing field of the first segment before the
    // first underscore. We look for "h2_" (h2 immediately followed by
    // the segment separator) OR "h2_" at any position covering h2 ALPN
    // plus the h2c / h2-prior-knowledge variants.
    if lower.starts_with("t13d") && lower.contains("h2_") {
        return FpKind::Browser;
    }
    FpKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(ua: Option<&str>, ja4: Option<&str>) -> RequestContext {
        let mut c = RequestContext::test_with("1.2.3.4", "/");
        if let Some(u) = ua {
            c = c.with_ua(u);
        }
        c.ja4 = ja4.map(String::from);
        c
    }

    #[test]
    fn chrome_ua_with_browser_ja4_is_match() {
        let c = ctx_with(
            Some("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"),
            Some("t13d1516h2_8daaf6152771_b1ff8ab2d16f"),
        );
        assert_eq!(classify(&c), Mismatch::None);
    }

    #[test]
    fn chrome_ua_with_go_ja4_is_browser_mismatch() {
        let c = ctx_with(
            Some("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"),
            Some("t13d191000_aabbccddeeff_001122334455"),
        );
        assert_eq!(classify(&c), Mismatch::BrowserUaNonBrowserFp);
    }

    #[test]
    fn curl_ua_with_browser_ja4_is_tool_mismatch() {
        let c = ctx_with(
            Some("curl/8.0.1"),
            Some("t13d1516h2_8daaf6152771_b1ff8ab2d16f"),
        );
        assert_eq!(classify(&c), Mismatch::ToolUaBrowserFp);
    }

    #[test]
    fn empty_ua_with_ja4_is_no_ua_signal() {
        let c = ctx_with(None, Some("t13d1516h2_8daaf6152771_b1ff8ab2d16f"));
        assert_eq!(classify(&c), Mismatch::NoUaWithFp);
    }

    #[test]
    fn no_ja4_is_none_regardless() {
        let c = ctx_with(Some("Mozilla/5.0 Chrome/120.0.0.0"), None);
        assert_eq!(classify(&c), Mismatch::None);
    }

    #[test]
    fn mobile_app_ua_is_not_flagged_unknown_fp() {
        // Some embedded mobile WebView with unrecognised TLS stack.
        let c = ctx_with(
            Some("MyApp/1.0 (iOS 17)"),
            Some("t12d1100_unknown_fingerprint"),
        );
        // UA = Other (no "chrome/", no tool token) → no mismatch.
        assert_eq!(classify(&c), Mismatch::None);
    }

    #[test]
    fn reason_strings_unique() {
        let all = [
            Mismatch::None,
            Mismatch::BrowserUaNonBrowserFp,
            Mismatch::ToolUaBrowserFp,
            Mismatch::NoUaWithFp,
        ];
        let mut s: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for m in all {
            assert!(s.insert(m.reason_str()), "duplicate reason: {m:?}");
        }
    }

    #[test]
    fn risk_contributions_ordered() {
        assert!(
            Mismatch::BrowserUaNonBrowserFp.risk_contribution()
                > Mismatch::ToolUaBrowserFp.risk_contribution()
        );
        assert!(
            Mismatch::ToolUaBrowserFp.risk_contribution()
                > Mismatch::NoUaWithFp.risk_contribution()
        );
        assert!(Mismatch::NoUaWithFp.risk_contribution() > Mismatch::None.risk_contribution());
    }
}
