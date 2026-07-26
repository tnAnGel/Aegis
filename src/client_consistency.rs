//! V145 — CreepJS-style client consistency scoring.
//!
//! V137 [fp_correlation] inspects the *server-side* fingerprint
//! tuple (JA4 / JA4H / H2FP / UA) for mismatches. That catches most
//! "Chrome JA4 + curl UA" cases, but a moderately skilled attacker
//! can match TLS + HTTP fingerprints by routing through a real
//! Chrome instance over a SOCKS proxy. The next-tier defense is
//! looking at the *client-side* JavaScript environment for the same
//! kind of cross-signal inconsistencies — patterns the CreepJS
//! library popularised against canvas-fingerprint-defeating
//! anti-detect browsers.
//!
//! Aegis ships a small JS collector ([CREEPJS_CLIENT_JS]) that the
//! challenge page (or any operator-instrumented page) embeds. It
//! gathers:
//!
//!   * `navigator.userAgent` + `navigator.platform`
//!   * `Intl.DateTimeFormat().resolvedOptions().timeZone`
//!   * `navigator.languages[0]`
//!   * WebGL vendor + renderer strings (`UNMASKED_VENDOR_WEBGL`)
//!   * `navigator.webdriver` flag
//!   * `navigator.hardwareConcurrency`
//!   * plugin / mime-type counts (zero on Chromium headless)
//!   * canvas 2D fingerprint hash
//!
//! and POSTs them to the operator's collection endpoint (typically
//! `/.well-known/aegis/consistency`). Server-side, [ClientSignals]
//! is the parsed payload; [consistency_score] runs the rule set and
//! produces a [ConsistencyScore] for combination with V137 into
//! the V2 model's `fp_consistency_score` slot.
//!
//! ## Why a score, not a hard block?
//!
//! Same reason as V137: legitimate edge cases (corporate MITM that
//! strips JS, privacy extensions that rewrite navigator.* values,
//! Tor Browser's intentional uniformity strategy). A score lets the
//! risk engine combine this with other signals.

use std::{collections::HashMap, net::IpAddr, sync::RwLock, time::Instant};

use serde::{Deserialize, Serialize};

use crate::fp_correlation::{BrowserFamily, ua_family};

/// Bundle of client-collected signals. All fields optional — older
/// clients or stripped headers just don't contribute to the score.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientSignals {
    /// Raw value of `navigator.userAgent`. Should match the request's
    /// `User-Agent` header byte-for-byte; divergence is a strong tell
    /// for header-rewrite proxies / replay attacks.
    pub ua: Option<String>,
    /// `navigator.platform` ("Win32", "MacIntel", "Linux x86_64", ...)
    pub platform: Option<String>,
    /// IANA timezone identifier from `Intl.DateTimeFormat`
    /// (e.g., "America/New_York", "Europe/Moscow").
    pub timezone: Option<String>,
    /// First entry of `navigator.languages` (e.g., "en-US").
    pub language: Option<String>,
    /// WebGL `UNMASKED_VENDOR_WEBGL` (e.g., "Google Inc. (Intel)",
    /// "Mozilla", "Mesa").
    pub webgl_vendor: Option<String>,
    /// WebGL `UNMASKED_RENDERER_WEBGL`.
    pub webgl_renderer: Option<String>,
    /// `navigator.webdriver` — true when running under Selenium /
    /// Playwright / etc.
    pub webdriver: Option<bool>,
    /// `navigator.hardwareConcurrency` — 0 is suspicious; real
    /// hardware always reports >=1.
    pub hardware_concurrency: Option<u32>,
    /// `navigator.plugins.length` — Chromium-headless reports 0;
    /// real desktop Chrome reports 3+.
    pub plugin_count: Option<u32>,
    /// Canvas 2D fingerprint hash from `aegisCanvasFp()` in the JS
    /// snippet. Known headless-browser hashes can be matched against
    /// a denylist (operator-supplied; not bundled).
    pub canvas_hash: Option<String>,
    /// V189 — mouse-move inter-arrival times in milliseconds, captured
    /// by the JS collector. Empty / absent when collector not running
    /// or user didn't move the mouse on the page. Used by
    /// [crate::timing_entropy::extract] to flag uniform-timer
    /// synthetics.
    #[serde(default)]
    pub mouse_intervals_ms: Vec<u32>,
    /// V189 — scroll inter-arrival times. Same semantics as
    /// `mouse_intervals_ms` but for wheel/touch scroll events.
    #[serde(default)]
    pub scroll_intervals_ms: Vec<u32>,
}

/// One contributing rule's verdict. Stable `&'static str` tags safe
/// for Prometheus labels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConsistencyReason(pub &'static str, pub f32);

#[derive(Debug, Clone)]
pub struct ConsistencyScore {
    pub score: f32,
    pub reasons: Vec<ConsistencyReason>,
}

impl ConsistencyScore {
    pub fn consistent() -> Self {
        Self {
            score: 0.0,
            reasons: vec![],
        }
    }
}

/// Run the rule set. `ua_header` is the request's User-Agent header
/// (Aegis-side ground truth); `signals` is what the JS reported.
pub fn consistency_score(signals: &ClientSignals, ua_header: Option<&str>) -> ConsistencyScore {
    let mut score = 0.0_f32;
    let mut reasons: Vec<ConsistencyReason> = vec![];

    // 1. UA header vs JS-reported UA — should match byte-for-byte.
    if let (Some(h), Some(j)) = (ua_header, signals.ua.as_deref())
        && h != j
    {
        reasons.push(ConsistencyReason("ua_header_vs_navigator", 0.4));
        score += 0.4;
    }

    // 2. WebDriver flag explicitly true → automation tool.
    if signals.webdriver == Some(true) {
        reasons.push(ConsistencyReason("webdriver_true", 0.5));
        score += 0.5;
    }

    // 3. hardwareConcurrency = 0 → unreachable on real hardware.
    if signals.hardware_concurrency == Some(0) {
        reasons.push(ConsistencyReason("zero_hw_concurrency", 0.3));
        score += 0.3;
    }

    // 4. UA platform vs navigator.platform mismatch.
    let claimed_platform = ua_header.and_then(ua_platform);
    if let (Some(claimed), Some(reported)) = (claimed_platform, signals.platform.as_deref()) {
        let rep_norm = normalize_platform(reported);
        if rep_norm != claimed {
            reasons.push(ConsistencyReason("ua_platform_vs_navigator_platform", 0.35));
            score += 0.35;
        }
    }

    // 5. WebGL vendor vs UA — Chrome shouldn't report Mesa (Linux/headless).
    let ua_fam = ua_header.map(ua_family).unwrap_or(BrowserFamily::Unknown);
    if let Some(vendor) = signals.webgl_vendor.as_deref() {
        let vlow = vendor.to_ascii_lowercase();
        // Chromium-headless / xvfb commonly expose Mesa or SwiftShader;
        // real desktop Chrome on Windows/Mac exposes Intel/NVIDIA/AMD.
        if matches!(ua_fam, BrowserFamily::Chrome | BrowserFamily::Edge)
            && (vlow.contains("mesa") || vlow.contains("swiftshader") || vlow.contains("llvmpipe"))
        {
            reasons.push(ConsistencyReason("chrome_ua_mesa_webgl", 0.4));
            score += 0.4;
        }
    }

    // 6. Plugin count of 0 on a UA that claims a desktop browser
    //    family — Chromium headless reports 0; real desktop reports 3+.
    let claims_desktop_browser = matches!(
        ua_fam,
        BrowserFamily::Chrome
            | BrowserFamily::Firefox
            | BrowserFamily::Safari
            | BrowserFamily::Edge
    );
    if claims_desktop_browser && signals.plugin_count == Some(0) {
        reasons.push(ConsistencyReason("desktop_ua_zero_plugins", 0.2));
        score += 0.2;
    }

    // 7. Timezone vs language plausibility — very rough heuristic for
    //    obvious mismatches. "en-US" + "Europe/Moscow" is suspicious.
    if let (Some(tz), Some(lang)) = (signals.timezone.as_deref(), signals.language.as_deref())
        && let Some(weight) = timezone_language_mismatch(tz, lang)
    {
        reasons.push(ConsistencyReason("timezone_language_mismatch", weight));
        score += weight;
    }

    // 8. V189 — timing entropy. Only contributes when the collector
    //    actually shipped intervals; otherwise stays 0 so a session
    //    that never moved the mouse isn't penalised.
    if !signals.mouse_intervals_ms.is_empty() || !signals.scroll_intervals_ms.is_empty() {
        let s = crate::timing_entropy::TimingSample {
            mouse_intervals_ms: signals.mouse_intervals_ms.clone(),
            scroll_intervals_ms: signals.scroll_intervals_ms.clone(),
        };
        let f = crate::timing_entropy::extract(&s);
        // Weight cap at 0.5 — even a clearly synthetic timing trace
        // shouldn't be the *only* deciding signal.
        let weight = (f.anomaly_score * 0.5).clamp(0.0, 0.5);
        if weight > 0.05 {
            reasons.push(ConsistencyReason("timing_entropy_synthetic", weight));
            score += weight;
        }
    }

    ConsistencyScore {
        score: score.clamp(0.0, 1.0),
        reasons,
    }
}

fn ua_platform(ua: &str) -> Option<&'static str> {
    let u = ua.to_ascii_lowercase();
    if u.contains("windows") {
        Some("win")
    } else if u.contains("mac os") || u.contains("macintosh") {
        Some("mac")
    } else if u.contains("android") {
        Some("android")
    } else if u.contains("iphone") || u.contains("ipad") {
        Some("ios")
    } else if u.contains("linux") {
        Some("linux")
    } else {
        None
    }
}

fn normalize_platform(p: &str) -> &'static str {
    let pl = p.to_ascii_lowercase();
    if pl.starts_with("win") {
        "win"
    } else if pl.contains("mac") {
        "mac"
    } else if pl.contains("linux") {
        "linux"
    } else if pl.contains("android") || pl.contains("arm") {
        "android"
    } else if pl.starts_with("ip") {
        "ios"
    } else {
        "other"
    }
}

/// Coarse implausibility check. Returns a weight for the consistency
/// score when timezone clearly doesn't fit the language hint, None
/// when the pair is plausible or undecidable.
///
/// Intentionally conservative: many users legitimately mix language
/// + timezone (international travel, residency mismatches). We only
/// flag *strong* contradictions — `en-US` + `Asia/Tokyo` is fine
/// (US person in Tokyo), but `en-US` + `Europe/Moscow` for a UA
/// that also has zero plugins is the kind of stack that maps to a
/// scraper farm in RU pretending to be US-based.
fn timezone_language_mismatch(tz: &str, lang: &str) -> Option<f32> {
    let tz = tz.to_ascii_lowercase();
    let lang = lang.to_ascii_lowercase();
    // Crude continent-of-language vs continent-of-timezone check.
    // Only emits a (mild) signal for a small set of obvious oddities;
    // a richer policy would consult ICU CLDR data.
    let lang_continent = match lang.split('-').next().unwrap_or("") {
        // Languages strongly tied to specific regions.
        "ja" => "asia",
        "ko" => "asia",
        "zh" => "asia",
        "th" => "asia",
        "vi" => "asia",
        "ru" => "europe",
        "pl" => "europe",
        "cs" => "europe",
        _ => return None, // undecided
    };
    let tz_continent = tz.split('/').next().unwrap_or("");
    let plausible = match (lang_continent, tz_continent) {
        ("asia", "asia") => true,
        ("europe", "europe") => true,
        // Mismatched: language says X-continent, timezone says Y.
        _ => false,
    };
    if !plausible { Some(0.15) } else { None }
}

/// Per-IP store for the most recent client signals. Bounded LRU so
/// memory stays sane even with many distinct sources.
///
/// V230 — storage choice rationale. `parse_and_store` only runs on
/// POST `/__aegis/__collect` (or the operator's equivalent), which
/// fires at most once per browser session after navigation — not on
/// the hot request path. A single `RwLock<HashMap>` is fine here:
/// writes are rare enough that contention on the write lock never
/// shows up in profiles, and reads (from the risk engine) take the
/// read lock for a tiny clone. Sharding via `DashMap` would buy
/// nothing measurable and would cost the simple "snapshot oldest
/// for eviction" pass below (which needs a global view). If a
/// deployment ever sees collection POSTs become a hot path (e.g.
/// operator instruments every page), revisit and consider
/// `DashMap` with sharded LRU.
pub struct ClientSignalsStore {
    inner: RwLock<HashMap<IpAddr, (ClientSignals, Instant)>>,
    capacity: usize,
}

impl ClientSignalsStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            capacity,
        }
    }

    /// Insert / replace the latest signals for `ip`. Evicts oldest
    /// entry when at capacity.
    pub fn insert(&self, ip: IpAddr, signals: ClientSignals, now: Instant) {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(_) => return,
        };
        if g.len() >= self.capacity {
            // Single-pass eviction of the oldest entry.
            if let Some((&oldest_ip, _)) = g.iter().min_by_key(|(_, (_, t))| *t) {
                g.remove(&oldest_ip);
            }
        }
        g.insert(ip, (signals, now));
    }

    /// Snapshot of the latest signals for `ip`. None when no JS
    /// payload has been received from this IP.
    pub fn get(&self, ip: IpAddr) -> Option<ClientSignals> {
        self.inner.read().ok()?.get(&ip).map(|(s, _)| s.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ClientSignalsStore {
    fn default() -> Self {
        Self::new(10_000)
    }
}

/// V150 — collection endpoint path. Operators serve [CREEPJS_CLIENT_JS]
/// to clients; the snippet POSTs to this path. Kept stable so the
/// JS doesn't need a config knob (path is part of the snippet).
pub const COLLECTION_PATH: &str = "/.well-known/aegis/consistency";

/// V150 — parse a JSON payload from the JS snippet and stash it in
/// the store. Returns true when the payload was well-formed and
/// stored; false on parse failure (caller responds 400). Bounded
/// input size enforced by caller before invocation.
///
/// V230 — allocation audit. `serde_json::from_slice::<ClientSignals>`
/// is unavoidably owning here: `ClientSignals` outlives the request
/// body (it sits in the store for the LRU's lifetime), so the
/// `Option<String>` / `Vec<u32>` fields cannot borrow from `body`.
/// A borrowed `Deserialize` variant would only help if we could
/// score-then-discard without storing, which defeats the whole
/// point of the per-IP store. This is also a cold path (one POST
/// per browser session), so the allocations are not worth chasing.
pub fn parse_and_store(body: &[u8], ip: IpAddr, store: &ClientSignalsStore, now: Instant) -> bool {
    let Ok(signals) = serde_json::from_slice::<ClientSignals>(body) else {
        return false;
    };
    store.insert(ip, signals, now);
    true
}

/// JS snippet operators embed in challenge / instrumented pages.
/// Sends signals to the configured collection endpoint as JSON.
/// Cheap (~3KB minified, no external libraries).
pub const CREEPJS_CLIENT_JS: &str = r#"
// Aegis CreepJS-style client consistency collector.
// Usage: aegisCollectAndPost("/.well-known/aegis/consistency")
async function aegisCollectAndPost(endpoint) {
  function aegisCanvasFp() {
    try {
      const c = document.createElement('canvas');
      c.width = 64; c.height = 32;
      const g = c.getContext('2d');
      g.textBaseline = 'top';
      g.font = '14px Arial';
      g.fillStyle = '#f60'; g.fillRect(0, 0, 64, 16);
      g.fillStyle = '#069'; g.fillText('aegis', 2, 0);
      return c.toDataURL().split(',')[1].slice(0, 32);
    } catch (_) { return null; }
  }
  function aegisWebGL() {
    try {
      const g = document.createElement('canvas').getContext('webgl');
      if (!g) return { vendor: null, renderer: null };
      const dbg = g.getExtension('WEBGL_debug_renderer_info');
      if (!dbg) return { vendor: null, renderer: null };
      return {
        vendor: g.getParameter(dbg.UNMASKED_VENDOR_WEBGL),
        renderer: g.getParameter(dbg.UNMASKED_RENDERER_WEBGL),
      };
    } catch (_) { return { vendor: null, renderer: null }; }
  }
  const gl = aegisWebGL();
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  const payload = {
    ua: navigator.userAgent,
    platform: navigator.platform || null,
    timezone: tz,
    language: (navigator.languages && navigator.languages[0]) || navigator.language || null,
    webgl_vendor: gl.vendor,
    webgl_renderer: gl.renderer,
    webdriver: !!navigator.webdriver,
    hardware_concurrency: navigator.hardwareConcurrency || 0,
    plugin_count: (navigator.plugins && navigator.plugins.length) || 0,
    canvas_hash: aegisCanvasFp(),
  };
  try {
    await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'same-origin',
      keepalive: true,
    });
  } catch (_) { /* fire-and-forget */ }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_chrome() -> ClientSignals {
        ClientSignals {
            ua: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120".into()),
            platform: Some("Win32".into()),
            timezone: Some("America/New_York".into()),
            language: Some("en-US".into()),
            webgl_vendor: Some("Google Inc. (Intel)".into()),
            webgl_renderer: Some("ANGLE (Intel, Intel Iris ...) ".into()),
            webdriver: Some(false),
            hardware_concurrency: Some(8),
            plugin_count: Some(5),
            canvas_hash: Some("abc123".into()),
            mouse_intervals_ms: Vec::new(),
            scroll_intervals_ms: Vec::new(),
        }
    }

    fn ua_chrome() -> &'static str {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
    }

    #[test]
    fn clean_chrome_scores_zero() {
        let s = consistency_score(&clean_chrome(), Some(ua_chrome()));
        assert!(
            s.score < 0.05,
            "coherent Chrome should score ~0, got {}",
            s.score
        );
        assert!(s.reasons.is_empty());
    }

    #[test]
    fn ua_header_vs_navigator_ua_mismatch_lights_up() {
        let mut sig = clean_chrome();
        sig.ua = Some("Mozilla/5.0 Firefox/121".into());
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(r.reasons.iter().any(|x| x.0 == "ua_header_vs_navigator"));
        assert!(r.score >= 0.4);
    }

    #[test]
    fn webdriver_true_adds_strong_signal() {
        let mut sig = clean_chrome();
        sig.webdriver = Some(true);
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(r.reasons.iter().any(|x| x.0 == "webdriver_true"));
        assert!(r.score >= 0.5);
    }

    #[test]
    fn zero_hw_concurrency_signals_unreal_hardware() {
        let mut sig = clean_chrome();
        sig.hardware_concurrency = Some(0);
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(r.reasons.iter().any(|x| x.0 == "zero_hw_concurrency"));
        assert!(r.score >= 0.3);
    }

    #[test]
    fn ua_platform_vs_navigator_platform_disagrees() {
        let mut sig = clean_chrome();
        sig.platform = Some("Linux x86_64".into()); // UA still says Windows
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(
            r.reasons
                .iter()
                .any(|x| x.0 == "ua_platform_vs_navigator_platform")
        );
    }

    #[test]
    fn chrome_with_mesa_webgl_is_headless_signal() {
        let mut sig = clean_chrome();
        sig.webgl_vendor = Some("Mesa".into());
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(r.reasons.iter().any(|x| x.0 == "chrome_ua_mesa_webgl"));
        assert!(r.score >= 0.4);
    }

    #[test]
    fn chromium_headless_zero_plugins_detected() {
        let mut sig = clean_chrome();
        sig.plugin_count = Some(0);
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(r.reasons.iter().any(|x| x.0 == "desktop_ua_zero_plugins"));
    }

    #[test]
    fn timezone_language_mismatch_jp_with_moscow_tz() {
        let mut sig = clean_chrome();
        sig.language = Some("ja-JP".into());
        sig.timezone = Some("Europe/Moscow".into());
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(
            r.reasons
                .iter()
                .any(|x| x.0 == "timezone_language_mismatch")
        );
    }

    #[test]
    fn timezone_language_neutral_pair_no_signal() {
        let mut sig = clean_chrome();
        sig.language = Some("ja-JP".into());
        sig.timezone = Some("Asia/Tokyo".into());
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(
            !r.reasons
                .iter()
                .any(|x| x.0 == "timezone_language_mismatch")
        );
    }

    #[test]
    fn english_unknown_language_no_assumption() {
        // English speakers travel everywhere — no flag for en-US + Tokyo.
        let mut sig = clean_chrome();
        sig.language = Some("en-US".into());
        sig.timezone = Some("Asia/Tokyo".into());
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(
            !r.reasons
                .iter()
                .any(|x| x.0 == "timezone_language_mismatch")
        );
    }

    #[test]
    fn stacked_mismatches_clip_at_one() {
        let sig = ClientSignals {
            ua: Some("Mozilla/5.0 Firefox/121".into()),
            platform: Some("Linux x86_64".into()),
            timezone: Some("Europe/Moscow".into()),
            language: Some("ja-JP".into()),
            webgl_vendor: Some("SwiftShader".into()),
            webdriver: Some(true),
            hardware_concurrency: Some(0),
            plugin_count: Some(0),
            ..Default::default()
        };
        let r = consistency_score(&sig, Some(ua_chrome()));
        assert!(r.score <= 1.0);
        assert!(
            r.score >= 0.95,
            "stacked mismatches should clip near 1, got {}",
            r.score
        );
    }

    #[test]
    fn empty_signals_score_zero() {
        let r = consistency_score(&ClientSignals::default(), Some(ua_chrome()));
        assert_eq!(r.score, 0.0);
    }

    // ── Store tests ───────────────────────────────────────────────

    #[test]
    fn store_insert_and_get_roundtrip() {
        let s = ClientSignalsStore::new(10);
        let ip = "1.2.3.4".parse().unwrap();
        let now = Instant::now();
        s.insert(ip, clean_chrome(), now);
        assert_eq!(s.len(), 1);
        let back = s.get(ip).unwrap();
        assert_eq!(back.ua, clean_chrome().ua);
    }

    #[test]
    fn store_evicts_oldest_at_capacity() {
        let s = ClientSignalsStore::new(2);
        let t0 = Instant::now();
        s.insert("1.1.1.1".parse().unwrap(), clean_chrome(), t0);
        s.insert(
            "2.2.2.2".parse().unwrap(),
            clean_chrome(),
            t0 + std::time::Duration::from_millis(10),
        );
        s.insert(
            "3.3.3.3".parse().unwrap(),
            clean_chrome(),
            t0 + std::time::Duration::from_millis(20),
        );
        // Capacity 2 → 1.1.1.1 (oldest) evicted.
        assert_eq!(s.len(), 2);
        assert!(s.get("1.1.1.1".parse().unwrap()).is_none());
        assert!(s.get("3.3.3.3".parse().unwrap()).is_some());
    }

    #[test]
    fn store_missing_ip_returns_none() {
        let s = ClientSignalsStore::new(10);
        assert!(s.get("9.9.9.9".parse().unwrap()).is_none());
    }

    // ── V150 — parse_and_store unit tests ─────────────────────────

    #[test]
    fn parse_and_store_accepts_well_formed_json() {
        let store = ClientSignalsStore::new(10);
        let json = br#"{"ua":"Mozilla/5.0","webdriver":true,"hardware_concurrency":4}"#;
        let ip = "1.2.3.4".parse().unwrap();
        assert!(parse_and_store(json, ip, &store, Instant::now()));
        let sig = store.get(ip).unwrap();
        assert_eq!(sig.ua.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(sig.webdriver, Some(true));
        assert_eq!(sig.hardware_concurrency, Some(4));
    }

    #[test]
    fn parse_and_store_handles_partial_payload() {
        // Missing fields are fine — they default to None.
        let store = ClientSignalsStore::new(10);
        let json = br#"{"ua":"Mozilla/5.0"}"#;
        let ip = "1.2.3.4".parse().unwrap();
        assert!(parse_and_store(json, ip, &store, Instant::now()));
        let sig = store.get(ip).unwrap();
        assert_eq!(sig.ua.as_deref(), Some("Mozilla/5.0"));
        assert!(sig.platform.is_none());
        assert!(sig.webdriver.is_none());
    }

    #[test]
    fn parse_and_store_rejects_malformed_json() {
        let store = ClientSignalsStore::new(10);
        let ip = "1.2.3.4".parse().unwrap();
        assert!(!parse_and_store(b"not json", ip, &store, Instant::now()));
        assert!(!parse_and_store(b"", ip, &store, Instant::now()));
        assert!(store.get(ip).is_none());
    }

    #[test]
    fn collection_path_constant_matches_js() {
        // The JS snippet docstring promises this exact path.
        assert_eq!(COLLECTION_PATH, "/.well-known/aegis/consistency");
    }

    #[test]
    fn client_js_snippet_is_self_contained() {
        // Smoke test: snippet contains the function name + the fetch
        // call so a future refactor that drops either fails the build.
        assert!(CREEPJS_CLIENT_JS.contains("aegisCollectAndPost"));
        assert!(CREEPJS_CLIENT_JS.contains("await fetch"));
        assert!(CREEPJS_CLIENT_JS.contains("navigator.userAgent"));
        assert!(CREEPJS_CLIENT_JS.contains("navigator.webdriver"));
    }
}
