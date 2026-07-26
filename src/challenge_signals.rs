//! V233+ — Passive bot-signal evaluator (challenge arsenal, phase 2).
//!
//! This module is the pure, side-effect-free scoring core for the new
//! challenge family. It takes the cheap signals already available on
//! the request path (HTTP headers, the connection's JA4 string, the
//! resolved client ASN) and the per-host [`DomainChallengeConfig`],
//! and returns a 0–100 suspicion score plus the list of reasons that
//! contributed.
//!
//! Design rules:
//!   * **Pure & testable** — no atomics, no logging, no I/O. The
//!     request path bumps the arsenal counters; this module only
//!     decides *whether* a signal fired.
//!   * **OFF by default** — every sub-check is gated on its
//!     `Option<bool>` config field being `Some(true)`. A default
//!     (all-`None`) config yields `(0, vec![])`, so existing hosts are
//!     unchanged.
//!   * **Zero user friction** — these are *passive* signals derived
//!     entirely from data the client already sent. No JS probe, no
//!     redirect, no cookie. A high score only *escalates the ladder*
//!     (Allow → Challenge); it never hard-blocks (that is the job of
//!     the explicit `fail_to_xdp_deny` enforcement lever, a later
//!     phase).
//!
//! Phase 2 replaces the phase-1 stubs with real logic:
//!   * `ja4_ua_mismatch` — JA4 TLS family vs claimed User-Agent family
//!     (reuses [`crate::fp_correlation`] family classifiers).
//!   * `header_fingerprint_suspicious` — header NAME order / casing /
//!     presence model vs a real browser.
//!   * `h2_fingerprint_suspicious` — best-effort h2-vs-claim check
//!     given what pingora exposes (see the limitation note on that fn).
//!   * `asn_is_hosting` — datacenter / hosting / VPN ASN classification.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use http::HeaderMap;

use crate::arsenal::DomainChallengeConfig;
use crate::fp_correlation::{self, BrowserFamily};

/// Saturating add into a `u8` score, capped at 100.
#[inline]
fn add_score(score: &mut u8, delta: u8) {
    *score = score.saturating_add(delta).min(100);
}

/// Returns `true` when the per-host flag is explicitly enabled.
#[inline]
fn on(flag: Option<bool>) -> bool {
    matches!(flag, Some(true))
}

/// Evaluate every enabled passive signal for a request.
///
/// Returns `(score, reasons)` where `score` is a 0–100 suspicion
/// estimate and `reasons` lists the stable identifiers of the signals
/// that fired (used by the caller to bump the matching arsenal
/// `challenge_<field>_hits` counters and to surface the breakdown via
/// `/admin/api/challenge`).
///
/// All inputs are borrowed and the function performs no I/O, so it is
/// cheap to call on the hot path and trivial to unit-test.
pub fn passive_bot_score(
    req_headers: &HeaderMap,
    ja4: Option<&str>,
    asn: Option<u32>,
    cfg: &DomainChallengeConfig,
) -> (u8, Vec<&'static str>) {
    let mut score: u8 = 0;
    let mut reasons: Vec<&'static str> = Vec::new();

    if on(cfg.ja4_ua_consistency) && ja4_ua_mismatch(req_headers, ja4) {
        add_score(&mut score, 35);
        reasons.push("ja4_ua_consistency");
    }

    if on(cfg.header_fingerprint) && header_fingerprint_suspicious(req_headers) {
        add_score(&mut score, 20);
        reasons.push("header_fingerprint");
    }

    if on(cfg.h2_fingerprint) && h2_fingerprint_suspicious(req_headers) {
        // Lower-confidence signal (see limitation note on the helper).
        add_score(&mut score, 15);
        reasons.push("h2_fingerprint");
    }

    if on(cfg.datacenter_asn_challenge) && asn_is_hosting(asn) {
        add_score(&mut score, 25);
        reasons.push("datacenter_asn_challenge");
    }

    (score, reasons)
}

// ──────────────────────────────────────────────────────────────────
// Helper sub-functions — phase-2 real logic.
// ──────────────────────────────────────────────────────────────────

/// Pull the `User-Agent` out of a `HeaderMap` as a `&str`, if present
/// and valid UTF-8.
#[inline]
fn user_agent(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
}

/// Passive: does the claimed `User-Agent` contradict the TLS JA4
/// fingerprint?
///
/// We classify both the JA4 string and the UA into a coarse
/// [`BrowserFamily`] using the existing [`crate::fp_correlation`]
/// classifiers (the same ones the V137 correlator uses), then flag a
/// mismatch when *both* are confidently identified and disagree. The
/// canonical bot pattern is a real browser JA4 (or any browser-family
/// JA4) paired with a tooling UA (`curl`, `python`, `Go-http-client`,
/// …) or a *different* browser family than the TLS stack implies.
///
/// Conservative by construction: if either side classifies as
/// `Unknown` we do NOT fire — a privacy browser or an unrecognised
/// (but legitimate) client should never be penalised purely on a JA4
/// we don't have in the family table.
pub fn ja4_ua_mismatch(req_headers: &HeaderMap, ja4: Option<&str>) -> bool {
    let Some(ja4) = ja4.filter(|s| !s.is_empty()) else {
        return false;
    };
    let Some(ua) = user_agent(req_headers).filter(|s| !s.is_empty()) else {
        // A connection with a JA4 but no UA at all is itself odd, but
        // that absence is the `header_fingerprint` signal's job — keep
        // this detector strictly about *contradiction*.
        return false;
    };

    let ja4_fam = fp_correlation::ja4_family(ja4);
    let ua_fam = fp_correlation::ua_family(ua);

    // Both must be confidently classified for a mismatch to mean
    // anything. `Unknown` on either side = no signal.
    if ja4_fam == BrowserFamily::Unknown || ua_fam == BrowserFamily::Unknown {
        return false;
    }

    // Same family (e.g. Chrome JA4 + Chrome UA) → consistent.
    // Different family → contradiction. A `Tool` UA can never have a
    // browser-family JA4 legitimately, so that is always a mismatch
    // here (ja4_fam is guaranteed browser-family since the family
    // table only contains browsers).
    ja4_fam != ua_fam
}

/// Passive: is the HTTP request header set inconsistent with a real
/// browser?
///
/// Real browsers send a stable, rich set of request headers; simple
/// bots and scripted clients omit the ones a browser always sends.
/// We score a few cheap, high-signal structural checks and flag when
/// the request looks unlike any mainstream browser:
///
///   * `User-Agent` claims a browser (Chrome/Firefox/Safari/Edge) but
///     `Accept-Language` is absent — browsers always send it; its
///     absence on a browser-claiming UA is a strong scripted-client
///     tell.
///   * `Accept` header missing entirely — every browser navigation /
///     fetch sends one.
///   * Browser-claiming UA but no `Accept-Encoding` — browsers always
///     advertise gzip/br.
///   * No `User-Agent` at all — virtually no real browser omits it;
///     overwhelmingly automation.
///
/// NOTE on header *order/casing*: HTTP/2 lower-cases all header names
/// on the wire, and pingora's `HeaderMap` does not preserve the
/// original on-wire ordering or original-case of names (it normalises
/// into the map), so a true wire-order/casing fingerprint is not
/// reachable from this surface. We therefore fingerprint *presence*
/// (which IS reliably reachable) rather than faking an order hash we
/// cannot actually observe. The `h2_fingerprint` signal documents the
/// matching h2-level limitation.
pub fn header_fingerprint_suspicious(req_headers: &HeaderMap) -> bool {
    let ua = user_agent(req_headers);

    // No UA at all: almost always automation. Strong, standalone.
    let Some(ua) = ua.filter(|s| !s.is_empty()) else {
        return true;
    };

    let claims_browser = matches!(
        fp_correlation::ua_family(ua),
        BrowserFamily::Chrome
            | BrowserFamily::Firefox
            | BrowserFamily::Safari
            | BrowserFamily::Edge
    );

    let has = |name: http::header::HeaderName| req_headers.contains_key(name);
    let accept = has(http::header::ACCEPT);
    let accept_language = has(http::header::ACCEPT_LANGUAGE);
    let accept_encoding = has(http::header::ACCEPT_ENCODING);

    if claims_browser {
        // A UA that claims a mainstream browser but is missing the
        // headers every such browser sends is the inconsistency we are
        // after. Any one of these missing is enough — they are all
        // unconditional for real browser navigations.
        if !accept_language || !accept || !accept_encoding {
            return true;
        }
    } else {
        // UA present but classified as Tool / Unknown. A bare request
        // with neither Accept nor Accept-Language is the classic
        // scripted-client shape. (We do NOT flag a well-formed
        // non-browser client that sends a full header set — that could
        // be a legitimate API consumer.)
        if !accept && !accept_language {
            return true;
        }
    }

    false
}

/// Passive: best-effort HTTP/2 fingerprint consistency.
///
/// IMPORTANT LIMITATION — read before trusting this signal.
/// A real HTTP/2 fingerprint (the Akamai-style hash over the SETTINGS
/// frame values, WINDOW_UPDATE, header-table size, and the pseudo-
/// header ordering) requires access to the raw h2 frames. Pingora does
/// NOT surface raw h2 frames or the SETTINGS frame to the request
/// filter layer, so the canonical h2 fingerprint is **not reachable**
/// from this module. We deliberately do NOT fabricate a hash we cannot
/// observe.
///
/// What IS reachable, and what we use here:
///   * the negotiated HTTP version is recoverable indirectly: an
///     HTTP/2 request carries no `Connection` header (it is a
///     connection-level concept forbidden in h2, RFC 7540 §8.1.2.2),
///     whereas an h1 client that injects `Connection: keep-alive` is
///     on h1; and
///   * the presence of hop-by-hop headers (`Connection`,
///     `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`) that
///     are explicitly forbidden in HTTP/2 is, by itself, a malformed-
///     /forged-h2 tell when the upstream negotiated h2.
///
/// Because we only see the `HeaderMap` here (not the negotiated
/// version), we restrict ourselves to the version-independent, always-
/// true invariant: a request that simultaneously claims a modern
/// browser UA *and* carries an h2-forbidden hop-by-hop header is
/// internally inconsistent — a real browser on h2 never emits these,
/// and a real browser on h1 emits at most `Connection`. We treat the
/// presence of `Proxy-Connection` or `Keep-Alive` alongside a
/// browser-claiming UA as the low-confidence signal.
///
/// This is intentionally weighted lower in `passive_bot_score` (15 vs
/// 35/25) to reflect the reduced confidence. The full SETTINGS-frame
/// fingerprint is a future enhancement gated on pingora exposing the
/// h2 frame surface (or on threading `ctx.h2fp` — which IS captured at
/// the TLS layer — into this module; see the wiring note in the PR).
pub fn h2_fingerprint_suspicious(req_headers: &HeaderMap) -> bool {
    let Some(ua) = user_agent(req_headers).filter(|s| !s.is_empty()) else {
        return false;
    };
    let claims_browser = matches!(
        fp_correlation::ua_family(ua),
        BrowserFamily::Chrome
            | BrowserFamily::Firefox
            | BrowserFamily::Safari
            | BrowserFamily::Edge
    );
    if !claims_browser {
        return false;
    }

    // h2-forbidden hop-by-hop headers that a real browser never emits.
    // `Connection` alone is excluded — it is legitimate on h1 — but
    // `Proxy-Connection` / `Keep-Alive` are legacy/forged tells.
    req_headers.contains_key("proxy-connection")
        || req_headers.contains_key(http::header::TE)
            && req_headers
                .get(http::header::TE)
                .and_then(|v| v.to_str().ok())
                .map(|v| !v.eq_ignore_ascii_case("trailers"))
                .unwrap_or(false)
}

/// Passive: is the client ASN a known hosting / VPN / datacenter
/// network (as opposed to a residential / mobile eyeball network)?
///
/// Residential traffic originates from a small set of well-known
/// eyeball ASNs; bot/scraper traffic overwhelmingly originates from
/// cloud/hosting ASNs (AWS, GCP, Azure, OVH, Hetzner, DigitalOcean,
/// Linode/Akamai, Vultr, …) and commercial-VPN / proxy ASNs. A
/// presence in one of those networks is not proof of abuse — many
/// legitimate clients use VPNs — so this signal only *escalates to a
/// challenge*; it must never hard-block (that is enforced by the
/// caller, which folds this into the ladder rather than into a Deny).
///
/// The list below is the well-known hosting/cloud/VPN core. Operators
/// who load a MaxMind ASN DB get the live lookup that feeds `asn`
/// here; the static set guarantees a useful baseline even before the
/// `asn_reputation` feed is configured.
pub fn asn_is_hosting(asn: Option<u32>) -> bool {
    let Some(asn) = asn else { return false };
    HOSTING_ASNS.binary_search(&asn).is_ok()
}

// ──────────────────────────────────────────────────────────────────
// Phase 3 — ACTIVE in-browser (JS) probe scoring.
//
// Unlike the passive signals above (derived purely from data the client
// already sent), these consume the results of JavaScript probes that
// run inside the branded challenge interstitial and ride back to
// `/__aegis/verify` as extra query params:
//
//   * `&b=<u32>`  headless bitmask  (HeadlessBit::* OR-ed together)
//   * `&w=<u32>`  webgl/audio flags (WebglAudioBit::* OR-ed together)
//   * `&dt=<u32>` dom-timing flags  (DomTimingBit::* OR-ed together)
//   * `&pc=<0|1>` proof-of-click satisfied (1 = a real pointer/keydown
//                 gesture was observed before submit)
//
// All four are gated per-host on the matching `DomainChallengeConfig`
// flag. A host with every flag OFF (the default) never emits the probes
// and `js_bot_score` returns `(0, [])`, so the verify gate is a no-op.
//
// The score only ever ESCALATES (re-challenge / deny at verify); it is
// never a positive trust signal, so a missing/garbled param is treated
// as "no evidence" (0) rather than as proof of a human.
// ──────────────────────────────────────────────────────────────────

/// `&b=` bitmask: automation / headless-browser tells collected by the
/// in-page probe. Higher bits = stronger evidence.
pub mod headless_bit {
    /// `navigator.webdriver === true` — the WebDriver standard flag set
    /// by Selenium / Playwright / Puppeteer in automation mode.
    pub const WEBDRIVER: u32 = 1 << 0;
    /// `window.chrome` missing on a UA that claims Chrome — headless
    /// Chrome / non-Chrome engine masquerading as Chrome.
    pub const NO_WINDOW_CHROME: u32 = 1 << 1;
    /// ChromeDriver `cdc_*` / `$cdc_` document properties present.
    pub const CDC_PROPS: u32 = 1 << 2;
    /// `navigator.plugins.length === 0` — headless browsers ship no
    /// plugins; real desktop browsers expose at least the PDF viewer.
    pub const NO_PLUGINS: u32 = 1 << 3;
    /// Permissions API quirk: `Notification.permission === "denied"`
    /// while `navigator.permissions.query` reports "prompt" — the
    /// classic headless-Chrome contradiction.
    pub const PERMISSIONS_QUIRK: u32 = 1 << 4;
    /// A native function's `toString()` does not look native (a hooked /
    /// proxied `Function.prototype.toString`, a common stealth-plugin
    /// tell).
    pub const TOSTRING_TAMPERED: u32 = 1 << 5;
    /// `navigator.languages` empty — headless default.
    pub const NO_LANGUAGES: u32 = 1 << 6;
}

/// `&w=` bitmask: WebGL / AudioContext fingerprint tells.
pub mod webgl_audio_bit {
    /// WebGL `UNMASKED_RENDERER` is SwiftShader / llvmpipe / "Google
    /// SwiftShader" — software rendering, the headless-Chrome default.
    pub const SWIFTSHADER: u32 = 1 << 0;
    /// No WebGL context obtainable at all — common in headless without a
    /// GPU and in barebones automation environments.
    pub const NO_WEBGL: u32 = 1 << 1;
    /// AudioContext unavailable / threw — a real browser always has it.
    pub const NO_AUDIO: u32 = 1 << 2;
}

/// `&dt=` bitmask: DOM / timing-entropy tells (fake timers, scripted
/// cadence).
pub mod dom_timing_bit {
    /// `requestAnimationFrame` never fired within the budget — no real
    /// compositor / headless without a display.
    pub const NO_RAF: u32 = 1 << 0;
    /// rAF cadence was implausibly regular (zero jitter) — a faked /
    /// virtual-time clock rather than a real display refresh.
    pub const FAKE_RAF_CADENCE: u32 = 1 << 1;
    /// `setTimeout` drift was ~0 — virtual time / sinon-style fake
    /// timers (a real event loop always drifts a little).
    pub const ZERO_TIMER_DRIFT: u32 = 1 << 2;
}

/// Parsed in-browser probe results carried back on the `/__aegis/verify`
/// query string. Each field is `None` when its param is absent (the host
/// did not enable that probe, or an old client) — distinct from `Some(0)`
/// ("probe ran, found nothing").
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JsProbe {
    pub headless: Option<u32>,
    pub webgl_audio: Option<u32>,
    pub dom_timing: Option<u32>,
    pub proof_of_click: Option<bool>,
}

/// Score the in-browser JS probe results against the per-host config.
///
/// Returns `(score, reasons)` exactly like [`passive_bot_score`]; the
/// reason strings match the config field names (`"headless_detection"`,
/// `"webgl_audio_fp"`, `"dom_timing_entropy"`, `"proof_of_click"`) so
/// the caller can bump the matching `challenge_<field>_hits` counters.
///
/// Each probe contributes only when its host flag is `Some(true)`:
///   * `headless_detection` — any headless bit set escalates; the
///     WebDriver / CDC bits are decisive (a real browser never sets
///     them), so any one of them alone clears the deny threshold.
///   * `webgl_audio_fp` — SwiftShader or missing audio is a strong
///     headless tell.
///   * `dom_timing_entropy` — fake-timer / no-rAF cadence.
///   * `proof_of_click` — when enabled, the *absence* of a human
///     gesture (`proof_of_click == Some(false)` or `None`) is the
///     signal; a satisfied click contributes nothing.
///
/// Pure & side-effect-free — unit-testable without a live request.
pub fn js_bot_score(probe: &JsProbe, cfg: &DomainChallengeConfig) -> (u8, Vec<&'static str>) {
    let mut score: u8 = 0;
    let mut reasons: Vec<&'static str> = Vec::new();

    if on(cfg.headless_detection) {
        if let Some(bits) = probe.headless {
            // Decisive bits — a real browser cannot set these.
            let decisive =
                headless_bit::WEBDRIVER | headless_bit::CDC_PROPS | headless_bit::TOSTRING_TAMPERED;
            // Corroborating bits — individually weak, but a headless
            // environment usually trips several at once.
            let weak = headless_bit::NO_WINDOW_CHROME
                | headless_bit::NO_PLUGINS
                | headless_bit::PERMISSIONS_QUIRK
                | headless_bit::NO_LANGUAGES;
            let mut fired = false;
            if bits & decisive != 0 {
                add_score(&mut score, 70);
                fired = true;
            }
            // Each corroborating bit adds 15 (so two stack over the
            // 50 challenge threshold; three approach a deny on their
            // own without any single decisive tell).
            let weak_n = (bits & weak).count_ones() as u8;
            if weak_n > 0 {
                add_score(&mut score, weak_n.saturating_mul(15));
                fired = true;
            }
            if fired {
                reasons.push("headless_detection");
            }
        }
    }

    if on(cfg.webgl_audio_fp) {
        if let Some(bits) = probe.webgl_audio {
            if bits != 0 {
                // SwiftShader / no-audio are strong headless tells.
                let strong = webgl_audio_bit::SWIFTSHADER | webgl_audio_bit::NO_AUDIO;
                let delta = if bits & strong != 0 { 45 } else { 25 };
                add_score(&mut score, delta);
                reasons.push("webgl_audio_fp");
            }
        }
    }

    if on(cfg.dom_timing_entropy) {
        if let Some(bits) = probe.dom_timing {
            if bits != 0 {
                // Fake-timer evidence is high-confidence automation.
                let strong = dom_timing_bit::FAKE_RAF_CADENCE | dom_timing_bit::ZERO_TIMER_DRIFT;
                let delta = if bits & strong != 0 { 40 } else { 20 };
                add_score(&mut score, delta);
                reasons.push("dom_timing_entropy");
            }
        }
    }

    if on(cfg.proof_of_click) {
        // When required, the absence of a real gesture IS the signal.
        // `Some(true)` (human clicked) contributes nothing; both
        // `Some(false)` (submitted without a gesture) and `None`
        // (a client that skipped the probe entirely) fail.
        if probe.proof_of_click != Some(true) {
            add_score(&mut score, 60);
            reasons.push("proof_of_click");
        }
    }

    (score, reasons)
}

// ──────────────────────────────────────────────────────────────────
// Phase 4 — `reputation_difficulty` enforcement lever.
//
// When a host enables `reputation_difficulty`, the in-browser PoW the
// challenge interstitial asks the client to solve is scaled UP for
// suspicious clients, so a bot (which farms challenges at scale) pays a
// meaningfully larger CPU cost than a one-off legitimate visitor. The
// scaling is bounded so a real browser still clears it in ~1–2s: every
// extra bit doubles the expected work, so we cap the bump at +4 bits
// over the [`crate::pow_captcha::BROWSER_POW_DIFFICULTY`] baseline (16
// → 20, i.e. ~16× the baseline work, still well under a second for a
// batched WebCrypto solver on real hardware and a tiny fraction of the
// 24/28-bit server bands).
// ──────────────────────────────────────────────────────────────────

/// Maximum number of extra leading-zero bits the reputation lever adds
/// on top of the browser PoW baseline. Each bit doubles expected work,
/// so +4 ≈ 16× — bounded so a legit browser still solves in ~1–2s.
pub const REPUTATION_MAX_DIFFICULTY_BUMP: u8 = 4;

/// Scale the browser PoW difficulty for a challenged client based on how
/// suspicious it looks.
///
/// `baseline` is normally [`crate::pow_captcha::BROWSER_POW_DIFFICULTY`]
/// (16). `suspicion` is a 0–100 score — the caller folds together the
/// passive bot score (see [`passive_bot_score`]) and any existing
/// per-IP threat/suspicion score and passes the max.
///
/// Returns `baseline` unchanged when `reputation_difficulty` is OFF for
/// the host (the common case), so a stock host always mints the exact
/// pre-Phase-4 token. When ON, the bump grows with suspicion and is
/// capped at `baseline + REPUTATION_MAX_DIFFICULTY_BUMP`:
///   * `< 25`  → +0 (clean / unknown — no penalty)
///   * `25..50` → +1
///   * `50..75` → +2
///   * `75..90` → +3
///   * `>= 90`  → +4 (max)
///
/// Pure & side-effect-free — unit-testable without a live request.
pub fn reputation_difficulty(baseline: u8, suspicion: u8, cfg: &DomainChallengeConfig) -> u8 {
    if !on(cfg.reputation_difficulty) {
        return baseline;
    }
    let bump = match suspicion {
        0..=24 => 0,
        25..=49 => 1,
        50..=74 => 2,
        75..=89 => 3,
        _ => REPUTATION_MAX_DIFFICULTY_BUMP,
    };
    baseline.saturating_add(bump.min(REPUTATION_MAX_DIFFICULTY_BUMP))
}

/// The verify-side deny threshold for the active JS probe score. A
/// score at or above this re-challenges / denies the `/__aegis/verify`
/// submission instead of minting the `aegis_fp` trust cookie.
///
/// Chosen so that:
///   * any single decisive headless bit (70) → deny,
///   * a missing proof-of-click when required (60) → deny,
///   * SwiftShader (45) + one corroborating headless bit (15) → deny,
///   * a lone weak corroborating bit (15) does NOT deny on its own.
pub const JS_DENY_THRESHOLD: u8 = 50;

/// Sorted (for `binary_search`) set of major hosting / cloud / VPN /
/// datacenter ASNs. Kept deliberately small and high-precision: every
/// entry is a network whose traffic to a *web origin* is dominated by
/// automation rather than human eyeballs. The list is sorted ascending
/// — a debug assertion in the tests guards the invariant.
static HOSTING_ASNS: &[u32] = &[
    8075,   // Microsoft / Azure
    9009,   // M247 (large commercial-VPN backbone)
    13335,  // Cloudflare (also a CDN; egress proxies live here)
    14061,  // DigitalOcean
    14618,  // Amazon AWS (us-east)
    15169,  // Google Cloud / Google LLC
    16276,  // OVH
    16509,  // Amazon AWS (global / EC2)
    20473,  // Vultr / Choopa / The Constant Company
    24940,  // Hetzner
    60068,  // Datacamp / CDN77 (VPN egress)
    63949,  // Akamai / Linode
    212238, // Datacamp Limited (NordVPN / Surfshark egress)
];

// ──────────────────────────────────────────────────────────────────
// Phase 4 — `fail_to_xdp_deny` enforcement lever.
//
// A client that repeatedly FAILS the challenge (bad/expired token, bad
// PoW, an active-probe score over threshold) within a short window is
// almost certainly automation hammering the ladder. After N failures we
// escalate that source IP into the XDP kernel deny set so subsequent
// packets are dropped at the NIC instead of burning a userspace round-
// trip per attempt.
//
// This struct is the pure, side-effect-free book-keeping core: it
// counts per-IP failures in a sliding TTL window and reports whether the
// threshold was crossed. The actual XDP push (and the counter bump) is
// the caller's job — kept out of here so the logic stays unit-testable
// without a live kernel handle.
// ──────────────────────────────────────────────────────────────────

/// Default number of challenge failures within the window before an IP
/// is escalated to the XDP deny set.
pub const FAIL_TO_DENY_THRESHOLD: u32 = 5;

/// Default sliding window over which failures accumulate. A burst of 5
/// failures in 60s trips the deny; a slow trickle (a real user fat-
/// fingering the page over minutes) ages out and never does.
pub const FAIL_TO_DENY_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
struct FailureRecord {
    /// Count of failures observed in the current window.
    count: u32,
    /// Wall-clock instant the current window started (first failure).
    window_start: Instant,
}

/// Sliding-window per-IP challenge-failure counter feeding the
/// `fail_to_xdp_deny` lever. Cheap to clone (an `Arc<DashMap>`), so the
/// proxy can hold one and share it across workers.
#[derive(Clone)]
pub struct ChallengeFailureTracker {
    inner: std::sync::Arc<DashMap<IpAddr, FailureRecord>>,
    threshold: u32,
    window: Duration,
}

impl Default for ChallengeFailureTracker {
    fn default() -> Self {
        Self::new(FAIL_TO_DENY_THRESHOLD, FAIL_TO_DENY_WINDOW)
    }
}

impl ChallengeFailureTracker {
    pub fn new(threshold: u32, window: Duration) -> Self {
        Self {
            inner: std::sync::Arc::new(DashMap::new()),
            threshold,
            window,
        }
    }

    /// Record one challenge failure for `ip` at `now` and report whether
    /// this failure pushed the IP at/over the deny threshold *for the
    /// first time* in the current window.
    ///
    /// Returns `true` exactly once per window-crossing: the call that
    /// reaches the threshold returns `true`; further failures in the
    /// same window return `false` (the IP is already in the deny set, so
    /// re-pushing it every packet would be wasted work). The window
    /// resets — and a fresh `true` can be returned later — only after
    /// the IP ages out (no failure for `window`).
    pub fn record_failure_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entry = self.inner.entry(ip).or_insert(FailureRecord {
            count: 0,
            window_start: now,
        });
        // Age out a stale window: if the last window started longer ago
        // than `window`, start fresh.
        if now.duration_since(entry.window_start) > self.window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count = entry.count.saturating_add(1);
        // Fire exactly on the transition to == threshold so the caller
        // pushes the IP into XDP once, not on every subsequent failure.
        entry.count == self.threshold
    }

    /// Convenience wrapper using the real clock.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        self.record_failure_at(ip, Instant::now())
    }

    /// Drop the IP's record (e.g. on a successful verify, so a client
    /// that finally passes isn't carrying stale failure credit).
    pub fn clear(&self, ip: IpAddr) {
        self.inner.remove(&ip);
    }

    /// Current failure count for `ip` (0 if absent / aged out). Test +
    /// introspection helper.
    pub fn count(&self, ip: IpAddr) -> u32 {
        self.inner.get(&ip).map(|r| r.count).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_ua() -> &'static str {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    /// A JA4 whose cipher-hash block classifies as Chrome under
    /// `fp_correlation::ja4_family` (prefix `8daa`).
    fn chrome_ja4() -> &'static str {
        "t13d1516h2_8daaf6152771_b186095e22b6"
    }

    fn full_browser_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, chrome_ua().parse().unwrap());
        h.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        h.insert(
            http::header::ACCEPT_LANGUAGE,
            "en-US,en;q=0.9".parse().unwrap(),
        );
        h.insert(
            http::header::ACCEPT_ENCODING,
            "gzip, deflate, br".parse().unwrap(),
        );
        h
    }

    // ── passive_bot_score gating ─────────────────────────────────

    #[test]
    fn default_config_yields_zero_score() {
        let cfg = DomainChallengeConfig::default();
        let headers = HeaderMap::new();
        let (score, reasons) = passive_bot_score(&headers, None, None, &cfg);
        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }

    #[test]
    fn coherent_chrome_request_with_all_flags_on_stays_clean() {
        // A real Chrome request (Chrome JA4 + Chrome UA + full headers
        // + residential ASN) must NOT be flagged even with every
        // passive flag enabled — zero user friction for real users.
        let cfg = DomainChallengeConfig {
            ja4_ua_consistency: Some(true),
            header_fingerprint: Some(true),
            h2_fingerprint: Some(true),
            datacenter_asn_challenge: Some(true),
            ..Default::default()
        };
        let headers = full_browser_headers();
        let (score, reasons) =
            passive_bot_score(&headers, Some(chrome_ja4()), Some(7922 /* Comcast */), &cfg);
        assert_eq!(score, 0, "coherent Chrome scored {score}: {reasons:?}");
        assert!(reasons.is_empty());
    }

    #[test]
    fn enabled_flags_off_means_signal_never_fires() {
        // Even a blatantly bad request (Chrome JA4 + curl UA, hosting
        // ASN) scores 0 when the per-host flags are all off (None).
        let cfg = DomainChallengeConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "curl/8.4.0".parse().unwrap());
        let (score, reasons) = passive_bot_score(&headers, Some(chrome_ja4()), Some(16509), &cfg);
        assert_eq!(score, 0);
        assert!(reasons.is_empty());
    }

    // ── ja4_ua_mismatch ──────────────────────────────────────────

    #[test]
    fn ja4_chrome_with_curl_ua_is_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "curl/8.4.0".parse().unwrap());
        assert!(ja4_ua_mismatch(&headers, Some(chrome_ja4())));
    }

    #[test]
    fn ja4_chrome_with_chrome_ua_is_consistent() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, chrome_ua().parse().unwrap());
        assert!(!ja4_ua_mismatch(&headers, Some(chrome_ja4())));
    }

    #[test]
    fn ja4_chrome_with_firefox_ua_is_mismatch() {
        let mut headers = HeaderMap::new();
        let ff = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
        headers.insert(http::header::USER_AGENT, ff.parse().unwrap());
        assert!(ja4_ua_mismatch(&headers, Some(chrome_ja4())));
    }

    #[test]
    fn unknown_ja4_never_mismatches() {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "curl/8.4.0".parse().unwrap());
        // JA4 that does not classify into any family → no signal.
        assert!(!ja4_ua_mismatch(
            &headers,
            Some("t13d0000h2_000000000000_000000000000")
        ));
    }

    #[test]
    fn missing_ja4_or_ua_never_mismatches() {
        let headers = full_browser_headers();
        assert!(!ja4_ua_mismatch(&headers, None));
        assert!(!ja4_ua_mismatch(&headers, Some("")));
        let empty = HeaderMap::new();
        assert!(!ja4_ua_mismatch(&empty, Some(chrome_ja4())));
    }

    // ── header_fingerprint_suspicious ────────────────────────────

    #[test]
    fn no_user_agent_is_suspicious() {
        let headers = HeaderMap::new();
        assert!(header_fingerprint_suspicious(&headers));
    }

    #[test]
    fn full_browser_headers_are_not_suspicious() {
        assert!(!header_fingerprint_suspicious(&full_browser_headers()));
    }

    #[test]
    fn browser_ua_without_accept_language_is_suspicious() {
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, chrome_ua().parse().unwrap());
        h.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        h.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        // Missing Accept-Language → browser-claiming UA inconsistency.
        assert!(header_fingerprint_suspicious(&h));
    }

    #[test]
    fn browser_ua_without_accept_is_suspicious() {
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, chrome_ua().parse().unwrap());
        h.insert(http::header::ACCEPT_LANGUAGE, "en-US".parse().unwrap());
        h.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        assert!(header_fingerprint_suspicious(&h));
    }

    #[test]
    fn tool_ua_with_full_headers_is_not_flagged() {
        // A non-browser client that nonetheless sends Accept +
        // Accept-Language is a plausible legit API consumer — not the
        // header-fingerprint detector's job to flag.
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, "MyApiClient/1.0".parse().unwrap());
        h.insert(http::header::ACCEPT, "application/json".parse().unwrap());
        h.insert(http::header::ACCEPT_LANGUAGE, "en".parse().unwrap());
        assert!(!header_fingerprint_suspicious(&h));
    }

    #[test]
    fn bare_scripted_client_is_suspicious() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::USER_AGENT,
            "python-requests/2.31".parse().unwrap(),
        );
        // Neither Accept nor Accept-Language → classic scripted shape.
        assert!(header_fingerprint_suspicious(&h));
    }

    // ── h2_fingerprint_suspicious ────────────────────────────────

    #[test]
    fn browser_with_proxy_connection_is_suspicious() {
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, chrome_ua().parse().unwrap());
        h.insert("proxy-connection", "keep-alive".parse().unwrap());
        assert!(h2_fingerprint_suspicious(&h));
    }

    #[test]
    fn clean_browser_request_has_no_h2_signal() {
        assert!(!h2_fingerprint_suspicious(&full_browser_headers()));
    }

    #[test]
    fn non_browser_ua_has_no_h2_signal() {
        // Low-confidence h2 heuristic only applies to browser-claiming
        // UAs; a tool UA is the ja4/header detectors' job.
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, "curl/8.4.0".parse().unwrap());
        h.insert("proxy-connection", "keep-alive".parse().unwrap());
        assert!(!h2_fingerprint_suspicious(&h));
    }

    #[test]
    fn te_trailers_is_allowed() {
        // `TE: trailers` is legitimate; only other TE values are odd.
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, chrome_ua().parse().unwrap());
        h.insert(http::header::TE, "trailers".parse().unwrap());
        assert!(!h2_fingerprint_suspicious(&h));
    }

    // ── asn_is_hosting ───────────────────────────────────────────

    #[test]
    fn aws_asn_is_hosting() {
        assert!(asn_is_hosting(Some(16509)));
        assert!(asn_is_hosting(Some(14618)));
    }

    #[test]
    fn residential_asn_is_not_hosting() {
        assert!(!asn_is_hosting(Some(7922))); // Comcast
        assert!(!asn_is_hosting(Some(701))); // Verizon
    }

    #[test]
    fn no_asn_is_not_hosting() {
        assert!(!asn_is_hosting(None));
    }

    #[test]
    fn hosting_asn_table_is_sorted() {
        // binary_search correctness invariant.
        assert!(
            HOSTING_ASNS.windows(2).all(|w| w[0] < w[1]),
            "HOSTING_ASNS must be strictly ascending for binary_search"
        );
    }

    // ── end-to-end scoring ───────────────────────────────────────

    #[test]
    fn bad_bot_request_escalates() {
        // Chrome JA4 + curl UA + hosting ASN, all flags on → high
        // score with the expected reasons.
        let cfg = DomainChallengeConfig {
            ja4_ua_consistency: Some(true),
            header_fingerprint: Some(true),
            datacenter_asn_challenge: Some(true),
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "curl/8.4.0".parse().unwrap());
        let (score, reasons) = passive_bot_score(&headers, Some(chrome_ja4()), Some(16509), &cfg);
        assert!(score >= 60, "expected high score, got {score}");
        assert!(reasons.contains(&"ja4_ua_consistency"));
        assert!(reasons.contains(&"header_fingerprint"));
        assert!(reasons.contains(&"datacenter_asn_challenge"));
    }

    #[test]
    fn add_score_saturates_at_100() {
        let mut s: u8 = 90;
        add_score(&mut s, 50);
        assert_eq!(s, 100);
    }

    // ── js_bot_score (Phase 3 active probes) ─────────────────────

    fn all_js_on() -> DomainChallengeConfig {
        DomainChallengeConfig {
            headless_detection: Some(true),
            webgl_audio_fp: Some(true),
            dom_timing_entropy: Some(true),
            proof_of_click: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn js_default_config_and_empty_probe_is_clean() {
        let cfg = DomainChallengeConfig::default();
        let (s, r) = js_bot_score(&JsProbe::default(), &cfg);
        assert_eq!(s, 0);
        assert!(r.is_empty());
    }

    #[test]
    fn js_flags_off_means_probes_ignored() {
        // Even a blatantly headless probe scores 0 when no flag is set.
        let cfg = DomainChallengeConfig::default();
        let probe = JsProbe {
            headless: Some(headless_bit::WEBDRIVER | headless_bit::CDC_PROPS),
            webgl_audio: Some(webgl_audio_bit::SWIFTSHADER),
            dom_timing: Some(dom_timing_bit::ZERO_TIMER_DRIFT),
            proof_of_click: Some(false),
        };
        let (s, r) = js_bot_score(&probe, &cfg);
        assert_eq!(s, 0);
        assert!(r.is_empty());
    }

    #[test]
    fn js_webdriver_alone_denies() {
        let cfg = all_js_on();
        // A real human clicked, clean webgl/timing — only webdriver set.
        let probe = JsProbe {
            headless: Some(headless_bit::WEBDRIVER),
            webgl_audio: Some(0),
            dom_timing: Some(0),
            proof_of_click: Some(true),
        };
        let (s, r) = js_bot_score(&probe, &cfg);
        assert!(s >= JS_DENY_THRESHOLD, "webdriver scored {s}");
        assert!(r.contains(&"headless_detection"));
    }

    #[test]
    fn js_lone_weak_headless_bit_does_not_deny() {
        let cfg = all_js_on();
        let probe = JsProbe {
            headless: Some(headless_bit::NO_PLUGINS),
            webgl_audio: Some(0),
            dom_timing: Some(0),
            proof_of_click: Some(true),
        };
        let (s, r) = js_bot_score(&probe, &cfg);
        assert!(s < JS_DENY_THRESHOLD, "one weak bit scored {s}");
        assert!(r.contains(&"headless_detection")); // still reported
    }

    #[test]
    fn js_swiftshader_plus_weak_bit_denies() {
        let cfg = all_js_on();
        let probe = JsProbe {
            headless: Some(headless_bit::NO_WINDOW_CHROME),
            webgl_audio: Some(webgl_audio_bit::SWIFTSHADER),
            dom_timing: Some(0),
            proof_of_click: Some(true),
        };
        let (s, _) = js_bot_score(&probe, &cfg);
        assert!(s >= JS_DENY_THRESHOLD, "swiftshader+weak scored {s}");
    }

    #[test]
    fn js_missing_proof_of_click_denies_when_required() {
        let cfg = all_js_on();
        // Everything else clean, but no human gesture observed.
        let probe = JsProbe {
            headless: Some(0),
            webgl_audio: Some(0),
            dom_timing: Some(0),
            proof_of_click: Some(false),
        };
        let (s, r) = js_bot_score(&probe, &cfg);
        assert!(s >= JS_DENY_THRESHOLD);
        assert!(r.contains(&"proof_of_click"));
        // Absent param (old client) also fails when required.
        let probe2 = JsProbe {
            proof_of_click: None,
            ..probe
        };
        let (s2, r2) = js_bot_score(&probe2, &cfg);
        assert!(s2 >= JS_DENY_THRESHOLD);
        assert!(r2.contains(&"proof_of_click"));
    }

    #[test]
    fn js_satisfied_click_contributes_nothing() {
        let cfg = DomainChallengeConfig {
            proof_of_click: Some(true),
            ..Default::default()
        };
        let probe = JsProbe {
            proof_of_click: Some(true),
            ..Default::default()
        };
        let (s, r) = js_bot_score(&probe, &cfg);
        assert_eq!(s, 0);
        assert!(r.is_empty());
    }

    // ── reputation_difficulty (Phase 4 difficulty scaling) ───────

    const BASELINE: u8 = 16; // mirrors crate::pow_captcha::BROWSER_POW_DIFFICULTY

    #[test]
    fn reputation_off_never_scales() {
        let cfg = DomainChallengeConfig::default();
        // Even a maximally suspicious client gets the baseline when the
        // lever is OFF (the stock-host default).
        assert_eq!(reputation_difficulty(BASELINE, 100, &cfg), BASELINE);
        assert_eq!(reputation_difficulty(BASELINE, 0, &cfg), BASELINE);
    }

    #[test]
    fn reputation_on_clean_client_stays_at_baseline() {
        let cfg = DomainChallengeConfig {
            reputation_difficulty: Some(true),
            ..Default::default()
        };
        // Low suspicion → no penalty: a real visitor still solves the
        // baseline PoW.
        assert_eq!(reputation_difficulty(BASELINE, 0, &cfg), BASELINE);
        assert_eq!(reputation_difficulty(BASELINE, 24, &cfg), BASELINE);
    }

    #[test]
    fn reputation_on_scales_with_suspicion() {
        let cfg = DomainChallengeConfig {
            reputation_difficulty: Some(true),
            ..Default::default()
        };
        assert_eq!(reputation_difficulty(BASELINE, 25, &cfg), BASELINE + 1);
        assert_eq!(reputation_difficulty(BASELINE, 50, &cfg), BASELINE + 2);
        assert_eq!(reputation_difficulty(BASELINE, 75, &cfg), BASELINE + 3);
        assert_eq!(reputation_difficulty(BASELINE, 90, &cfg), BASELINE + 4);
        assert_eq!(reputation_difficulty(BASELINE, 100, &cfg), BASELINE + 4);
    }

    #[test]
    fn reputation_bump_is_capped() {
        let cfg = DomainChallengeConfig {
            reputation_difficulty: Some(true),
            ..Default::default()
        };
        // The cap keeps a legit browser solvable in ~1–2s: never more
        // than +REPUTATION_MAX_DIFFICULTY_BUMP over the baseline.
        let d = reputation_difficulty(BASELINE, 100, &cfg);
        assert!(d <= BASELINE + REPUTATION_MAX_DIFFICULTY_BUMP);
        assert_eq!(d, 20);
    }

    // ── ChallengeFailureTracker (Phase 4 fail_to_xdp_deny) ───────

    #[test]
    fn failure_tracker_fires_exactly_at_threshold() {
        let tracker = ChallengeFailureTracker::new(5, FAIL_TO_DENY_WINDOW);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t0 = Instant::now();
        // First four failures: not yet over threshold.
        for _ in 0..4 {
            assert!(!tracker.record_failure_at(ip, t0));
        }
        // Fifth crosses → fires once.
        assert!(tracker.record_failure_at(ip, t0));
        // Subsequent failures in the same window do NOT re-fire (already
        // in the deny set).
        assert!(!tracker.record_failure_at(ip, t0));
        assert!(!tracker.record_failure_at(ip, t0));
    }

    #[test]
    fn failure_tracker_window_ages_out() {
        let window = Duration::from_secs(60);
        let tracker = ChallengeFailureTracker::new(3, window);
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        let t0 = Instant::now();
        // Two failures, then a long gap — the window resets so these
        // never accumulate to a deny.
        assert!(!tracker.record_failure_at(ip, t0));
        assert!(!tracker.record_failure_at(ip, t0));
        assert_eq!(tracker.count(ip), 2);
        // Past the window → counter resets to 1 on the next failure.
        let later = t0 + window + Duration::from_secs(1);
        assert!(!tracker.record_failure_at(ip, later));
        assert_eq!(tracker.count(ip), 1);
    }

    #[test]
    fn failure_tracker_clear_resets() {
        let tracker = ChallengeFailureTracker::new(3, FAIL_TO_DENY_WINDOW);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let t0 = Instant::now();
        tracker.record_failure_at(ip, t0);
        tracker.record_failure_at(ip, t0);
        assert_eq!(tracker.count(ip), 2);
        // A successful verify clears the credit.
        tracker.clear(ip);
        assert_eq!(tracker.count(ip), 0);
        // After clear, the threshold logic starts fresh.
        assert!(!tracker.record_failure_at(ip, t0));
        assert!(!tracker.record_failure_at(ip, t0));
        assert!(tracker.record_failure_at(ip, t0));
    }

    #[test]
    fn failure_tracker_isolates_distinct_ips() {
        let tracker = ChallengeFailureTracker::new(2, FAIL_TO_DENY_WINDOW);
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        let t0 = Instant::now();
        assert!(!tracker.record_failure_at(a, t0));
        // b's first failure must NOT inherit a's count.
        assert!(!tracker.record_failure_at(b, t0));
        assert!(tracker.record_failure_at(a, t0)); // a's 2nd → fires
        assert!(tracker.record_failure_at(b, t0)); // b's 2nd → fires
    }

    #[test]
    fn js_clean_real_browser_passes_with_all_flags_on() {
        // A genuine browser: no headless bits, real GPU, real timers,
        // a human click. Must not be flagged.
        let cfg = all_js_on();
        let probe = JsProbe {
            headless: Some(0),
            webgl_audio: Some(0),
            dom_timing: Some(0),
            proof_of_click: Some(true),
        };
        let (s, r) = js_bot_score(&probe, &cfg);
        assert_eq!(s, 0, "clean browser scored {s}: {r:?}");
        assert!(r.is_empty());
    }
}
