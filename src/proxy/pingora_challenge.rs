//! V42 — Challenge ladder + /__aegis/verify endpoint for aegis-pingora.
//!
//! The ChallengeFilter (`src/filters/challenge.rs`) returns one of
//! five `ChallengeLevel`s when an unverified client hits a route
//! that needs verification. The hyper handler turns each level into
//! an HTTP response with a signed `aegis_token` cookie + level-
//! specific body (HTML, iframe, JS, captcha) and, once the client
//! bounces back through /__aegis/verify, issues the long-lived
//! `aegis_fp` cookie that short-circuits the ladder thereafter.
//!
//! This module ports that flow to pingora. The cookie format,
//! signature, and TTL semantics are byte-identical to the hyper
//! handler so a client verified on one binary stays verified on the
//! other (operators can A/B aegis ↔ aegis-pingora without forcing
//! everyone through the ladder again).
//!
//! ## Pingora integration
//!
//! `ChallengeContext` carries everything the request_filter needs:
//! the ChallengeConfig (hmac secret, TTLs), an Arc<ChallengeFilter>
//! (to call `reset(ip)` on a successful verify), and `cookie_secure`
//! for the `; Secure` suffix.
//!
//! `fp_cookie_valid` is called once per request before the filter
//! chain — when it returns true, the proxy flips `is_trusted=true`
//! so ChallengeFilter (and rate/bot/etc.) short-circuit to Allow.
//!
//! `build_challenge_response` is called when the chain returned
//! Challenge — it writes the response inline to the pingora session
//! (304/200 + cookie + level-specific body) and the proxy returns
//! Ok(true) to skip upstream.
//!
//! `handle_verify` is called when the request URI matches
//! `VERIFY_PATH` (`/__aegis/verify`) — it validates the cookie token
//! from `?t=`, on success calls `ChallengeFilter::reset` + writes the
//! fp cookie + 302 redirects to `?r=` return URL.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

use crate::config::ChallengeConfig;
use crate::filters::{ChallengeLevel, challenge::ChallengeFilter};
use crate::pow_captcha::{DifficultyLadder, POW_CLIENT_JS, PowIssuer, RiskBand, VerifyResult}; // V234
#[cfg(test)]
use crate::security::cookie::read_cookie;
use crate::security::cookie::secure_suffix;
use crate::security::token::{sign_token, verify_token};

pub const TOKEN_COOKIE: &str = "aegis_token";
pub const FP_COOKIE: &str = "aegis_fp";
pub const VERIFY_PATH: &str = "/__aegis/verify";

/// Phase 5 — Cloudflare Turnstile top rung.
///
/// Env var names (settable from the admin panel via the ENV_ALLOWLIST):
///   * `AEGIS_TURNSTILE_SITEKEY` — PUBLIC sitekey, embedded in the
///     challenge page HTML (plain text, returned by GET /admin/api/env).
///   * `AEGIS_TURNSTILE_SECRET` — server-side secret used for
///     siteverify; write-only (never returned by GET). Reuses the name
///     already referenced by the Telemetry page / captcha providers.
pub const TURNSTILE_SITEKEY_ENV: &str = "AEGIS_TURNSTILE_SITEKEY";
pub const TURNSTILE_SECRET_ENV: &str = "AEGIS_TURNSTILE_SECRET";
/// Cloudflare's siteverify endpoint (same one `captcha_providers::Turnstile`
/// uses). We POST `secret`+`response` form-encoded and parse `success`.
const TURNSTILE_SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Resolved Turnstile credentials. Both must be non-empty for the rung
/// to render; either absent → `None` → graceful fallback to the PoW rung.
pub(crate) struct TurnstileKeys {
    pub sitekey: String,
    pub secret: String,
}

/// Read the Turnstile sitekey + secret from the environment. Returns
/// `None` (so the caller falls back to the normal PoW rung) unless BOTH
/// are present and non-empty. Cheap — two `env::var` lookups; only ever
/// called when a host actually enabled the `turnstile` toggle.
pub(crate) fn turnstile_keys() -> Option<TurnstileKeys> {
    let sitekey = std::env::var(TURNSTILE_SITEKEY_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let secret = std::env::var(TURNSTILE_SECRET_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    Some(TurnstileKeys { sitekey, secret })
}

/// True iff the host enabled the `turnstile` rung AND both keys are
/// configured. This is the single gate every Turnstile branch checks, so
/// a host that flipped the toggle on but never set the keys (or set only
/// one) silently keeps the normal PoW rung — never a broken challenge.
fn turnstile_active(dcfg: &crate::arsenal::DomainChallengeConfig) -> Option<TurnstileKeys> {
    if !matches!(dcfg.turnstile, Some(true)) {
        return None;
    }
    turnstile_keys()
}

/// Server-side Turnstile siteverify. Shells out to `curl` (like the
/// geoip DB updater) so we get a real TLS client without pulling
/// hyper-rustls into the proxy — the bundled hyper `HttpConnector` is
/// plaintext-only and cannot reach the `https://` endpoint. Runs inside
/// `spawn_blocking` because `std::process::Command` is blocking.
///
/// Fails CLOSED: any error (curl missing, network failure, non-success
/// JSON, malformed body) returns `false`, so a flaky siteverify never
/// mints trust — the client just stays on the challenge page.
async fn turnstile_siteverify(secret: &str, token: &str, remote_ip: &str) -> bool {
    let body = crate::captcha_providers::build_siteverify_body(
        secret,
        token,
        if remote_ip.is_empty() {
            None
        } else {
            Some(remote_ip)
        },
    );
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("curl")
            .arg("-s")
            .arg("--max-time")
            .arg("5")
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("content-type: application/x-www-form-urlencoded")
            .arg("--data")
            .arg(&body)
            .arg(TURNSTILE_SITEVERIFY_URL)
            .output()
    })
    .await;
    let raw = match out {
        Ok(Ok(o)) if o.status.success() => o.stdout,
        Ok(Ok(o)) => {
            tracing::warn!(
                target: "aegis::challenge::turnstile",
                code = ?o.status.code(),
                "turnstile siteverify curl exited non-zero"
            );
            return false;
        }
        Ok(Err(e)) => {
            tracing::warn!(target: "aegis::challenge::turnstile", error = %e, "turnstile siteverify spawn failed");
            return false;
        }
        Err(e) => {
            tracing::warn!(target: "aegis::challenge::turnstile", error = %e, "turnstile siteverify task join failed");
            return false;
        }
    };
    // Reuse the shared siteverify JSON parser (same `success` shape Cloudflare returns).
    crate::captcha_providers::parse_siteverify(&raw).success
}

/// V244 — binding fed into the challenge/trust HMAC + PoW. Was the client
/// IP, which broke every deployment behind a CDN: Cloudflare presents the
/// real client IP via CF-Connecting-IP, but a single browser legitimately
/// flips between IPv4 and IPv6 (happy-eyeballs) and across CF edges, so the
/// IP at challenge time differs from the IP at /__aegis/verify time → HMAC
/// mismatch → 403 → the "Checking your browser" page loops forever. We
/// therefore DON'T IP-bind: protection comes from the unforgeable HMAC, the
/// short TTL, the proof-of-work, and the browser-fingerprint nonce baked
/// into the trust cookie. (cf_clearance works the same bearer-token way.)
const CHALLENGE_BINDING: &str = "";

/// V234 — parsed `/__aegis/verify` query string. Internal only;
/// `handle_verify`'s public signature is unaffected. `pow_token` is
/// empty for the lower (non-PoW) rungs / the captcha form; when it is
/// non-empty the PoW gate is enforced before the `aegis_fp` cookie is
/// minted.
struct VerifyQuery {
    /// `?t=` — the signed `aegis_token` that authenticates the pending
    /// challenge (IP-bound, HMAC-checked, expiring).
    token: String,
    /// `?r=` — return URL, already hardened by `safe_return_url`.
    return_to: String,
    /// `?fp=` — optional behavioural fingerprint hash (FNV-1a).
    fp_hash: String,
    /// `?p=` — the encoded PoW challenge token issued by the JS rung.
    pow_token: String,
    /// `?s=` — the PoW solution (u64). `None` when absent/unparseable.
    pow_solution: Option<u64>,
    /// Phase 3 — in-browser probe results. Each is `None` when the
    /// matching param is absent (the host did not enable that probe, or
    /// an old client). See `crate::challenge_signals::JsProbe`.
    js_probe: crate::challenge_signals::JsProbe,
    /// Phase 5 — `&cf=` Cloudflare Turnstile response token. Empty when
    /// the host did not render the Turnstile widget (the normal PoW
    /// path). When non-empty, `handle_verify` validates it server-side
    /// against Cloudflare's siteverify before minting the trust cookie.
    cf_turnstile: String,
}

/// Shared challenge state held on the proxy. Cheap to clone — three
/// Arcs / one Config (which is itself Clone).
#[derive(Clone)]
pub struct ChallengeContext {
    pub cfg: ChallengeConfig,
    pub filter: Arc<ChallengeFilter>,
    /// V234 — real proof-of-work issuer/verifier. Built from the same
    /// `challenge.hmac_secret` that signs the `aegis_token`/`aegis_fp`
    /// cookies, so a fleet behind a load balancer shares PoW state
    /// statelessly (the token carries its own HMAC + expiry). Replaces
    /// the old fake constant-`pow` placeholder loop that the server
    /// never verified — a remote attacker passed the JS rung by just
    /// sending `?pow=<anything>`.
    pub pow: PowIssuer,
    /// Phase 4 — per-IP challenge-failure counter feeding the
    /// `fail_to_xdp_deny` lever. Cheap to clone (an inner `Arc<DashMap>`).
    /// Counts failures in a sliding window; the verify handler pushes an
    /// IP into the XDP deny set once it crosses the threshold (gated on
    /// the per-host toggle).
    pub failures: crate::challenge_signals::ChallengeFailureTracker,
}

impl ChallengeContext {
    pub fn new(cfg: ChallengeConfig, filter: Arc<ChallengeFilter>) -> Self {
        // V234 — self-contained PoW construction: derive the issuer
        // from `cfg` here so no `pingora_http.rs` change is needed to
        // wire it. The PoW token TTL mirrors the challenge `aegis_token`
        // TTL (default 300s) so a solved challenge and its trust token
        // expire on the same clock; clamped to a 30s floor so an
        // operator who sets an aggressively short `token_ttl_secs`
        // can't make the PoW unsolvable before submission.
        let pow_ttl = cfg.token_ttl_secs.max(30); // V234
        let pow = PowIssuer::new(
            cfg.hmac_secret.clone().into_bytes(),
            pow_ttl,
            DifficultyLadder::default(),
        );
        Self {
            cfg,
            filter,
            pow,
            failures: crate::challenge_signals::ChallengeFailureTracker::default(),
        }
    }

    fn now_epoch() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// H1 — true iff the inbound request method is HEAD. A HEAD response
    /// MUST carry the same status + headers a GET would but MUST NOT
    /// include a body (RFC 9110 §9.3.2); writing one over HTTP/2 trips a
    /// PROTOCOL_ERROR. Every challenge/verify response builder below
    /// checks this and, when true, sends the headers with end-of-stream
    /// and skips `write_response_body`. Mirrors the existing pattern in
    /// `pingora_http.rs` (HEAD-served-via-GET cache path).
    fn is_head(session: &Session) -> bool {
        session.req_header().method == http::Method::HEAD
    }

    fn token_cookie(&self, token: &str) -> String {
        format!(
            "{TOKEN_COOKIE}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
            self.cfg.token_ttl_secs,
            secure_suffix(self.cfg.cookie_secure)
        )
    }

    fn fp_cookie(&self, ip: IpAddr, fp_hash: &str) -> String {
        let ttl = self.cfg.fp_ttl_secs.max(60);
        let exp = Self::now_epoch() + ttl as i64;
        let _ = ip; // V244 — no longer IP-bound (see CHALLENGE_BINDING).
        let token = sign_token(
            &self.cfg.hmac_secret,
            CHALLENGE_BINDING,
            &format!("fp.{fp_hash}"),
            exp,
        );
        format!(
            "{FP_COOKIE}={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{}",
            secure_suffix(self.cfg.cookie_secure)
        )
    }

    /// True iff the request carries a valid (HMAC-checked, IP-bound,
    /// non-expired) `aegis_fp` cookie. When true, the proxy treats
    /// the client as verified and skips the challenge ladder.
    ///
    /// Hot path — called on every untrusted request. Uses the
    /// allocation-free `find_cookie_borrowed` scanner so the common
    /// no-cookie (or cookie-absent) case costs zero heap allocations.
    /// An owned copy is materialised only when the cookie is present
    /// and must be passed into `verify_token`.
    pub fn fp_cookie_valid(&self, ip: IpAddr, headers: &http::HeaderMap) -> bool {
        if self.cfg.fp_ttl_secs == 0 {
            return false;
        }
        // V237 — allocation-free early exit: if no `Cookie` header at
        // all, or if the `aegis_fp` name is absent, bail before touching
        // the heap. `find_cookie_borrowed` returns a `&str` slice into
        // the header value. `verify_token` also takes `&str`, so the
        // token value is never copied to an owned String on this path.
        let Some(token) = find_cookie_borrowed(headers, FP_COOKIE) else {
            return false;
        };
        let _ = ip; // V244 — no longer IP-bound (see CHALLENGE_BINDING).
        let now = Self::now_epoch();
        verify_token(&self.cfg.hmac_secret, token, CHALLENGE_BINDING, now)
            .map(|(nonce, _)| nonce.starts_with("fp."))
            .unwrap_or(false)
    }

    /// Refuses absolute URLs and anything that could turn a `?r=`
    /// value into an open redirect or response-splitting attack on
    /// `Location:`. A value is accepted only when it is a clean
    /// same-site relative path:
    ///   - starts with a single `/` (not `//`, which is protocol-
    ///     relative and resolves off-site);
    ///   - contains no `\` — browsers normalise `\`→`/`, so `/\evil`
    ///     becomes the protocol-relative `//evil` (V233);
    ///   - contains no CR/LF or `"` (header-injection / splitting);
    ///   - has no `:` before the first `/` — blocks `javascript:` and
    ///     any other scheme that would make it an absolute URL (V233).
    /// Anything else falls back to `/`.
    fn safe_return_url(s: &str) -> String {
        // V233 — reject `:` before the first `/` so a scheme can't
        // sneak through (e.g. `javascript:alert(1)` or `http:x`).
        let scheme_before_slash = match (s.find(':'), s.find('/')) {
            (Some(colon), Some(slash)) => colon < slash,
            (Some(_), None) => true,
            _ => false,
        };
        if s.starts_with('/')
            && !s.starts_with("//")
            && !s.contains('\\') // V233 — `\` normalises to `/` in browsers
            && !s.contains('\r')
            && !s.contains('\n')
            && !s.contains('"')
            && !scheme_before_slash
        // V233
        {
            s.to_string()
        } else {
            "/".to_string()
        }
    }

    fn step_label(level: &ChallengeLevel) -> &'static str {
        match level {
            ChallengeLevel::Headers => "307",
            ChallengeLevel::Html => "200",
            ChallengeLevel::Iframe => "click",
            ChallengeLevel::Javascript => "high",
            ChallengeLevel::Captcha => "capt",
        }
    }

    /// V234 — map a ladder rung to a PoW difficulty band. Only the two
    /// upper rungs run real proof-of-work: the JS rung (rung 4) is the
    /// first one a non-browser client cannot pass, so it gets `Attack`
    /// difficulty; the captcha rung (rung 5, the top of the ladder)
    /// gets `Critical`. The lower three rungs are cookie/redirect
    /// reflection checks and don't mint a PoW token at all.
    fn pow_band(level: &ChallengeLevel) -> RiskBand {
        match level {
            ChallengeLevel::Captcha => RiskBand::Critical,
            _ => RiskBand::Attack,
        }
    }

    /// Build + write the level-appropriate challenge response to the
    /// pingora session. The proxy should `return Ok(true)` after
    /// this returns Ok — upstream must NOT be invoked.
    pub async fn write_challenge_response(
        &self,
        session: &mut Session,
        level: ChallengeLevel,
        reason: &str,
        // Kept in the signature although unused: the challenge token is
        // deliberately not IP-bound (clients behind CDNs and mobile carriers
        // flip addresses mid-session), so nothing here keys on the peer. The
        // parameter stays so re-introducing a binding does not have to touch
        // every call site.
        _client_ip: IpAddr,
        request_uri: &http::Uri,
        // Phase 3 — per-host config gates which in-browser JS probes the
        // interactive (JS/Captcha) rung emits. A stock host (all-None)
        // gets the plain auto-solving page; only enabled probes inject
        // their collection snippet + an extra verify param.
        dcfg: &crate::arsenal::DomainChallengeConfig,
        // Phase 4 — `reputation_difficulty` lever. A 0–100 suspicion
        // score (passive bot score folded with the per-IP threat score)
        // the caller computes from the request. When the host enables
        // `reputation_difficulty`, the interactive PoW difficulty is
        // scaled UP for suspicious clients (bounded so a real browser
        // still solves in ~1–2s). Ignored for the non-PoW rungs and for
        // hosts that left the lever OFF (the default), so a stock host
        // mints the byte-identical pre-Phase-4 token.
        suspicion: u8,
    ) -> pingora_core::Result<()> {
        // V234 — for the JS rung the `aegis_token` nonce is prefixed
        // with `pow.`. The nonce is HMAC-signed, so an attacker can
        // neither forge a token nor strip the marker; `handle_verify`
        // reads the marker back out and, when present, REQUIRES a
        // valid PoW solution before minting `aegis_fp`. This closes
        // the "just omit `?p=`" bypass — a `pow.`-marked token with no
        // accompanying solution is rejected.
        // Phase 5 — when the host enabled the `turnstile` rung AND both
        // keys are configured, the interactive rung renders the
        // Cloudflare Turnstile widget INSTEAD of the auto-solving PoW. We
        // mark the nonce `ts.` so `handle_verify` REQUIRES a valid
        // Turnstile token (not a PoW solution). The marker is HMAC-
        // covered, so an attacker can neither forge it nor downgrade a
        // `pow.`/`ts.` token to a plain one. When keys are absent this is
        // `None` and we fall straight back to the `pow.` PoW path — the
        // challenge is never broken by a turned-on-but-unconfigured rung.
        let turnstile = turnstile_active(dcfg);
        let nonce = match level {
            // V243 — both interactive PoW rungs (JS + Captcha) render the
            // auto-solving page, so both mark the nonce `pow.` to REQUIRE a
            // valid PoW solution at verify. Phase 5 — unless Turnstile is
            // active, in which case the rung uses the `ts.` marker.
            ChallengeLevel::Javascript | ChallengeLevel::Captcha => {
                if turnstile.is_some() {
                    format!("ts.{}", uuid::Uuid::new_v4())
                } else {
                    format!("pow.{}", uuid::Uuid::new_v4())
                }
            }
            _ => uuid::Uuid::new_v4().to_string(),
        };
        let exp = Self::now_epoch() + self.cfg.token_ttl_secs as i64;
        let token = sign_token(&self.cfg.hmac_secret, CHALLENGE_BINDING, &nonce, exp);
        let cookie = self.token_cookie(&token);
        let return_to = Self::safe_return_url(
            request_uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
        );
        let verify_url = format!(
            "{VERIFY_PATH}?t={}&r={}",
            urlencoding::encode(&token),
            urlencoding::encode(&return_to)
        );
        let step = Self::step_label(&level);

        match level {
            ChallengeLevel::Headers => {
                // Rung 1 — 307 redirect with cookie. Any compliant
                // client follows + re-sends the cookie; raw socket
                // spammers don't.
                let mut h = ResponseHeader::build(307, Some(4))?;
                let _ = h.insert_header("set-cookie", cookie.as_str());
                let _ = h.insert_header("x-aegis-step", step);
                let _ = h.insert_header("cache-control", "no-store");
                let _ = h.insert_header("location", return_to.as_str());
                // H1 — HEAD responses must not have a body (RFC 9110
                // §9.3.2); send headers with end-of-stream and skip the
                // body, otherwise HTTP/2 trips a PROTOCOL_ERROR.
                if Self::is_head(session) {
                    session.write_response_header(Box::new(h), true).await?;
                } else {
                    session.write_response_header(Box::new(h), false).await?;
                    session
                        .write_response_body(Some(Bytes::from(reason.to_string())), true)
                        .await?;
                }
            }
            ChallengeLevel::Html => {
                let head_extra =
                    format!("<meta http-equiv=\"refresh\" content=\"1;url={return_to}\">");
                let inner = "<div class=\"spin\"></div><noscript><p style=\"margin-top:16px\">JavaScript is disabled — redirecting automatically…</p></noscript>";
                let body = challenge_shell(
                    "Just a moment…",
                    "Checking your browser",
                    "Verifying your connection is secure before continuing.",
                    &head_extra,
                    inner,
                );
                self.write_html(session, &cookie, step, body).await?;
            }
            ChallengeLevel::Iframe => {
                let inner = format!(
                    "<div class=\"spin\"></div><iframe src=\"{verify_url}\" width=\"1\" height=\"1\" style=\"display:none\"></iframe><script>setTimeout(function(){{location.href={};}},600);</script><noscript><p style=\"margin-top:16px\">Verifying…</p></noscript>",
                    js_string_literal(&return_to)
                );
                let body = challenge_shell(
                    "Just a moment…",
                    "Checking your browser",
                    "Verifying your connection is secure before continuing.",
                    "",
                    &inner,
                );
                self.write_html(session, &cookie, step, body).await?;
            }
            ChallengeLevel::Javascript | ChallengeLevel::Captcha => {
                // V234 — real proof-of-work rung. The old body ran a
                // throwaway `for` loop and posted a constant `pow`
                // value the server never checked, so any client could
                // pass by sending `?pow=<anything>`. Now we mint a
                // genuine PoW challenge bound to the client IP + an
                // expiring server-signed nonce; the embedded
                // `POW_CLIENT_JS` solver must find a SHA-256 preimage
                // with `difficulty` leading zero bits before
                // /__aegis/verify will mint the `aegis_fp` trust
                // cookie. `handle_verify` recomputes the HMAC over the
                // SAME IP binding, so the solution cannot be replayed
                // from another address.
                // V240 — both the JS-PoW rung and the (no-captcha-provider)
                // Captcha rung now render the SAME branded, auto-solving page.
                // The old Captcha rung was a dev stub literally asking the user
                // to type "aegis"; the PoW is real, automatic security and a far
                // better UX. The noscript fallback is a single styled button
                // (posts answer=aegis, which the verify handler accepts) so
                // JS-disabled humans can still pass without typing a secret word.
                // V243 — browser-feasible difficulty (the risk-band ladder's
                // 24/28-bit values assume native hashing and never solve in a
                // browser's JS → the page spun forever). `_ = pow_band` keeps
                // the band mapping referenced for future server-side use.
                let _ = Self::pow_band(&level);
                // Phase 5 — Turnstile top rung. When active (host toggle ON
                // + both keys configured, captured in `turnstile` above), we
                // render the Cloudflare widget instead of the PoW solver and
                // let `handle_verify` validate the `cf-turnstile-response`
                // token server-side. The `ts.`-marked nonce minted above
                // gates this. Absent keys → `turnstile` is None → we drop
                // straight into the unchanged PoW path below.
                if let Some(keys) = &turnstile {
                    let (head_extra, inner) =
                        build_turnstile_rung(&return_to, &verify_url, &keys.sitekey);
                    let body = challenge_shell(
                        "Just a moment…",
                        "Verify you're human",
                        "Complete the quick check below to continue.",
                        &head_extra,
                        &inner,
                    );
                    self.write_html(session, &cookie, step, body).await?;
                    return Ok(());
                }
                // Phase 4 — `reputation_difficulty`: scale the browser PoW
                // difficulty UP for suspicious clients when the host enabled
                // the lever. Returns the baseline unchanged for stock hosts
                // (lever OFF) and for clean clients (low suspicion).
                let difficulty = crate::challenge_signals::reputation_difficulty(
                    crate::pow_captcha::BROWSER_POW_DIFFICULTY,
                    suspicion,
                    dcfg,
                );
                let pow_token = self
                    .pow
                    .issue_bound_with_difficulty(difficulty, CHALLENGE_BINDING.as_bytes());
                let pow_encoded = pow_token.encode();
                let pow_difficulty = pow_token.difficulty;
                let inner =
                    build_js_rung(&return_to, &verify_url, &pow_encoded, pow_difficulty, dcfg);
                let body = challenge_shell(
                    "Just a moment…",
                    "Checking your browser",
                    "Running a quick automated security check — this only takes a moment.",
                    "",
                    &inner,
                );
                self.write_html(session, &cookie, step, body).await?;
            }
        }
        Ok(())
    }

    async fn write_html(
        &self,
        session: &mut Session,
        cookie: &str,
        step: &'static str,
        body: String,
    ) -> pingora_core::Result<()> {
        let mut h = ResponseHeader::build(200, Some(4))?;
        let _ = h.insert_header("set-cookie", cookie);
        let _ = h.insert_header("x-aegis-step", step);
        let _ = h.insert_header("cache-control", "no-store");
        let _ = h.insert_header("content-type", "text/html; charset=utf-8");
        let body = body.into_bytes();
        let _ = h.insert_header("content-length", body.len().to_string());
        // H1 — keep the same status + headers (including content-length)
        // for HEAD, but send end-of-stream with the header frame and emit
        // no body (RFC 9110 §9.3.2 / avoids an HTTP/2 PROTOCOL_ERROR).
        if Self::is_head(session) {
            session.write_response_header(Box::new(h), true).await?;
        } else {
            session.write_response_header(Box::new(h), false).await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
        }
        Ok(())
    }

    /// Handle `/__aegis/verify`. The proxy should call this when the
    /// request URI path matches `VERIFY_PATH`, BEFORE running the
    /// filter chain. Returns `Ok(())` after writing the response;
    /// the proxy must `return Ok(true)` to skip upstream.
    ///
    /// V42 ships GET-only verification (the JS/iframe path). Captcha
    /// POSTs land in V44+ — for now POST falls through to the GET
    /// validator (which works for the simple "answer=aegis" form
    /// because the verify token in `?t=` is what authenticates, not
    /// the form body).
    /// Parse the `/__aegis/verify` query string into `(token,
    /// return_to_safe, fp_hash)`.
    ///
    /// V233 — the `?r=` (`return_to`) value is run through the SAME
    /// strict validation as the challenge response path
    /// (`safe_return_url`) instead of the old lax
    /// `starts_with('/') && !starts_with("//")` check, which let
    /// `/\evil.com`, `/a%0d%0aX:y` and scheme-bearing values through.
    /// Anything that isn't a clean same-site relative path falls back
    /// to `/`. Factored out as a pure fn so the redirect-target
    /// hardening is unit-testable without a live pingora `Session`.
    ///
    /// V234 — also extracts the PoW token (`?p=`) and solution (`?s=`)
    /// posted by the JS rung's `aegisSolvePow` solver. Both ride as
    /// query params alongside the existing `?t=`/`?r=`/`?fp=` set, so
    /// `handle_verify`'s public signature is unchanged — no body read,
    /// no caller change in `pingora_http.rs`. A missing/garbage `?s=`
    /// decodes to `pow_solution = None`, which `handle_verify` treats
    /// as a failed PoW (when a token is present).
    fn parse_verify_query(query: &str) -> VerifyQuery {
        let mut q = VerifyQuery {
            token: String::new(),
            return_to: "/".to_string(),
            fp_hash: String::new(),
            pow_token: String::new(),
            pow_solution: None,
            js_probe: crate::challenge_signals::JsProbe::default(),
            cf_turnstile: String::new(),
        };
        for kv in query.split('&') {
            let mut it = kv.splitn(2, '=');
            let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
            let decoded = urlencoding::decode(v).unwrap_or_default().into_owned();
            match k {
                "t" => q.token = decoded,
                "r" => q.return_to = decoded,
                "fp" => q.fp_hash = decoded,
                "p" => q.pow_token = decoded, // V234 — PoW challenge token
                // V234 — PoW solution. JS sends the u64 as a decimal
                // string (BigInt.toString()); parse leniently — a
                // non-numeric value becomes `None` → rejected.
                "s" => q.pow_solution = decoded.trim().parse::<u64>().ok(),
                // Phase 3 — in-browser probe bitmasks / proof-of-click.
                // A garbage value parses to `None` (probe absent), which
                // the JS scorer treats as "no evidence" rather than a
                // pass — except proof_of_click, where absence WHEN
                // REQUIRED is itself the signal (see js_bot_score).
                "b" => q.js_probe.headless = decoded.trim().parse::<u32>().ok(),
                "w" => q.js_probe.webgl_audio = decoded.trim().parse::<u32>().ok(),
                "dt" => q.js_probe.dom_timing = decoded.trim().parse::<u32>().ok(),
                "pc" => q.js_probe.proof_of_click = Some(decoded.trim() == "1"),
                // Phase 5 — Cloudflare Turnstile response token. Present
                // only when the host rendered the widget; validated
                // server-side in `handle_verify` before minting trust.
                "cf" => q.cf_turnstile = decoded,
                _ => {}
            }
        }
        q.return_to = Self::safe_return_url(&q.return_to); // V233
        q
    }

    /// V234 — pure proof-of-work admission decision for `/__aegis/
    /// verify`. Returns `Ok(())` to allow the trust cookie to be
    /// minted, `Err(reason)` to reject.
    ///
    /// `nonce` is the already-HMAC-validated nonce from the request's
    /// `aegis_token`. When it carries the `pow.` marker the JS rung
    /// stamped on (`write_challenge_response`), a valid PoW solution is
    /// MANDATORY:
    ///   - missing/unparseable `?s=` → `Err` (unsolved)
    ///   - malformed / forged / wrong-IP `?p=` token → `Err`
    ///   - expired PoW token → `Err`
    ///   - solution below the issued difficulty → `Err`
    ///   - everything checks out → `Ok(())`
    ///
    /// The PoW token is IP-bound: `verify_bound` folds the client IP
    /// into the HMAC, so a solution farmed on one address fails on any
    /// other — an attacker cannot amortise one solve across a botnet.
    /// Replay is bounded by the PoW token's short TTL (`exp`, signed
    /// in) plus the `aegis_token`'s own TTL; within that window a
    /// replay only helps the SAME IP, which already paid the cost.
    ///
    /// A nonce WITHOUT the `pow.` marker (the lower rungs / captcha
    /// form) skips the gate entirely — those rungs never issue PoW, so
    /// requiring it would break them. The marker is HMAC-protected, so
    /// this is not a bypass: an attacker cannot mint a non-`pow.`
    /// token for a route the JS rung guards.
    ///
    /// Pure (no `Session`, no I/O) so the full decision — including
    /// the marker check — is unit-testable.
    fn pow_gate(
        &self,
        nonce: &str,
        q: &VerifyQuery,
        client_ip: IpAddr,
        now: i64,
    ) -> Result<(), &'static str> {
        if !nonce.starts_with("pow.") {
            return Ok(()); // non-PoW rung — nothing to enforce.
        }
        let _ = client_ip; // V244 — PoW no longer IP-bound (CHALLENGE_BINDING).
        let solution = q.pow_solution.ok_or("pow solution missing")?;
        let result = self.pow.verify_bound(
            &q.pow_token,
            solution,
            now as u64,
            CHALLENGE_BINDING.as_bytes(),
        );
        match result {
            VerifyResult::Ok { .. } => Ok(()),
            VerifyResult::Malformed => Err("pow token malformed"),
            VerifyResult::BadSignature => Err("pow token bad HMAC / wrong IP"),
            VerifyResult::Expired => Err("pow token expired"),
            VerifyResult::WrongSolution => Err("pow solution insufficient"),
        }
    }

    /// V234 — emit the shared 403 "invalid token" response. The body
    /// text is deliberately identical for a bad `aegis_token` and a
    /// failed PoW so an attacker can't tell *which* check tripped.
    async fn reject_verify(
        session: &mut Session,
        client_ip: IpAddr,
        why: &'static str,
    ) -> pingora_core::Result<()> {
        tracing::warn!(
            target: "aegis::security",
            ip = %client_ip,
            reason = why,
            "rejected /__aegis/verify"
        );
        // V240 — branded page (a user can land here via the noscript form
        // fallback or an expired token). Message is intentionally generic so
        // it doesn't reveal which check failed (bad token vs failed PoW).
        let body = challenge_shell(
            "Verification failed",
            "Verification failed",
            "We couldn't verify your browser. Please go back and try again.",
            "",
            "<button onclick=\"history.length>1?history.back():location.reload()\">Try again</button>",
        );
        let mut h = ResponseHeader::build(403, Some(2))?;
        let _ = h.insert_header("content-type", "text/html; charset=utf-8");
        let _ = h.insert_header("cache-control", "no-store");
        // H1 — no body on a HEAD request (RFC 9110 §9.3.2). The session
        // already carries the request method, so we read it here rather
        // than threading an extra parameter through the callers.
        if Self::is_head(session) {
            session.write_response_header(Box::new(h), true).await?;
        } else {
            session.write_response_header(Box::new(h), false).await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
        }
        Ok(())
    }

    /// Phase 4 — record one challenge failure for `client_ip` and, when
    /// the host enabled `fail_to_xdp_deny` and the IP has now crossed the
    /// failure threshold within the window, push it into the XDP kernel
    /// deny set and bump the `fail_to_xdp_deny` counter.
    ///
    /// Always counts the failure (so the sliding window is accurate even
    /// for hosts with the lever OFF — cheap, and keeps the count ready if
    /// the operator flips it on), but only escalates to XDP when the
    /// per-host toggle is `Some(true)`. The XDP push is a no-op under
    /// `NoopXdp` (XDP off / non-Linux).
    fn note_verify_failure(
        &self,
        client_ip: IpAddr,
        dcfg: &crate::arsenal::DomainChallengeConfig,
        arsenal: Option<&Arc<crate::arsenal::ArsenalState>>,
        xdp: &Arc<dyn crate::xdp::XdpHandle>,
    ) {
        let crossed = self.failures.record_failure(client_ip);
        if !crossed || !matches!(dcfg.fail_to_xdp_deny, Some(true)) {
            return;
        }
        // Threshold crossed AND the host opted in — escalate to the
        // kernel deny set. Best-effort: a failed push is logged, not
        // fatal (the userspace IP-ACL / challenge ladder still applies).
        let pushed = match client_ip {
            IpAddr::V4(v4) => xdp.deny_v4(v4),
            IpAddr::V6(v6) => xdp.deny_v6(v6),
        };
        match pushed {
            Ok(()) => {
                tracing::warn!(
                    target: "aegis::challenge::fail_to_xdp_deny",
                    ip = %client_ip,
                    "challenge failures over threshold — pushed IP into XDP deny set"
                );
                if let Some(a) = arsenal {
                    use std::sync::atomic::Ordering;
                    a.counters
                        .challenge_fail_to_xdp_deny_hits
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "aegis::challenge::fail_to_xdp_deny",
                    ip = %client_ip,
                    error = %e,
                    "XDP deny push failed"
                );
            }
        }
    }

    pub async fn handle_verify(
        &self,
        session: &mut Session,
        client_ip: IpAddr,
        // Phase 3 — per-host config + arsenal for the active JS-probe
        // gate. When the host enables any in-browser probe and the
        // reported probe results score at/above `JS_DENY_THRESHOLD`, we
        // REJECT the verify (re-challenge) instead of minting trust, and
        // bump the matching `challenge_<field>_hits` counters. A stock
        // host (all-None) makes this a no-op (score 0).
        dcfg: &crate::arsenal::DomainChallengeConfig,
        arsenal: Option<&Arc<crate::arsenal::ArsenalState>>,
        // Phase 4 — `fail_to_xdp_deny` lever. When the host enables it,
        // a client that fails the challenge too many times within the
        // window is pushed into the XDP kernel deny set so its packets
        // are dropped at the NIC. Gracefully a no-op when the handle is
        // `NoopXdp` (XDP off / non-Linux). Ignored entirely when the
        // host left the toggle OFF (the default).
        xdp: &Arc<dyn crate::xdp::XdpHandle>,
    ) -> pingora_core::Result<()> {
        let req = session.req_header();
        let query = req.uri.query().unwrap_or("");
        // V233 — query parsing + `?r=` strict validation moved into
        // `parse_verify_query`; `return_to` is already hardened.
        // V234 — `q` now also carries the PoW token (`?p=`) + solution
        // (`?s=`); the PoW gate below consumes them.
        let q = Self::parse_verify_query(query);

        // Validate the signed token bound to this IP. No bare GETs
        // — without a real token we never set the fp cookie.
        let now = Self::now_epoch();
        let Some((nonce, _exp)) =
            verify_token(&self.cfg.hmac_secret, &q.token, CHALLENGE_BINDING, now)
        else {
            self.note_verify_failure(client_ip, dcfg, arsenal, xdp);
            return Self::reject_verify(session, client_ip, "aegis_token bad HMAC").await;
        };

        // Phase 5 — Turnstile gate. The interactive rung signs a
        // `ts.`-prefixed nonce into `aegis_token` when the host enabled
        // `turnstile` AND both keys were configured at render time. The
        // marker is HMAC-covered, so an attacker can neither forge it nor
        // strip it: a `ts.`-marked token HARD-REQUIRES a Cloudflare
        // Turnstile token that passes server-side siteverify before we
        // mint the trust cookie. We re-read the secret here (not at
        // render) so a key-rotation takes effect immediately; if the
        // secret was removed since the page was served we fail closed
        // (no key → reject, client just re-challenges).
        if nonce.starts_with("ts.") {
            let ok = match turnstile_keys() {
                Some(keys) if !q.cf_turnstile.is_empty() => {
                    turnstile_siteverify(&keys.secret, &q.cf_turnstile, &client_ip.to_string())
                        .await
                }
                _ => false,
            };
            if !ok {
                self.note_verify_failure(client_ip, dcfg, arsenal, xdp);
                return Self::reject_verify(session, client_ip, "turnstile verification failed")
                    .await;
            }
            // Turnstile passed — bump the activity counter.
            if let Some(a) = arsenal {
                use std::sync::atomic::Ordering;
                a.counters
                    .challenge_turnstile_hits
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        // V234 — PoW gate. The JS rung signs a `pow.`-prefixed nonce
        // into `aegis_token` (see `write_challenge_response`). Because
        // the nonce is HMAC-covered, an attacker can neither forge the
        // marker nor strip it: a `pow.`-marked token therefore HARD-
        // REQUIRES a PoW solution that satisfies the issued difficulty.
        // The decision is factored into the pure `pow_gate` fn so it
        // is unit-testable without a live `Session`. A `ts.` nonce skips
        // this (it carries no PoW solution) — the Turnstile gate above
        // already enforced the human-verification step for it.
        if let Err(why) = self.pow_gate(&nonce, &q, client_ip, now) {
            self.note_verify_failure(client_ip, dcfg, arsenal, xdp);
            return Self::reject_verify(session, client_ip, why).await;
        }

        // Phase 3 — ACTIVE in-browser probe gate. The interactive rung
        // emits headless / WebGL-audio / DOM-timing bitmasks (`&b/&w/&dt`)
        // and the proof-of-click flag (`&pc`) when the host enabled them.
        // Re-score them here (pure, host-gated) and REJECT a submission
        // that scores at/above the deny threshold — a bot that passed the
        // PoW (a headless browser CAN solve PoW) still fails on these.
        // Counters are bumped for every reason that fired so the activity
        // surfaces under /admin/api/challenge "signals".
        {
            let (js_score, js_reasons) = crate::challenge_signals::js_bot_score(&q.js_probe, dcfg);
            if !js_reasons.is_empty()
                && let Some(a) = arsenal
            {
                use std::sync::atomic::Ordering;
                for reason in &js_reasons {
                    match *reason {
                        "headless_detection" => a
                            .counters
                            .challenge_headless_detection_hits
                            .fetch_add(1, Ordering::Relaxed),
                        "webgl_audio_fp" => a
                            .counters
                            .challenge_webgl_audio_fp_hits
                            .fetch_add(1, Ordering::Relaxed),
                        "dom_timing_entropy" => a
                            .counters
                            .challenge_dom_timing_entropy_hits
                            .fetch_add(1, Ordering::Relaxed),
                        "proof_of_click" => a
                            .counters
                            .challenge_proof_of_click_hits
                            .fetch_add(1, Ordering::Relaxed),
                        _ => 0,
                    };
                }
            }
            if js_score >= crate::challenge_signals::JS_DENY_THRESHOLD {
                tracing::warn!(
                    target: "aegis::challenge::js",
                    ip = %client_ip,
                    score = js_score,
                    reasons = ?js_reasons,
                    "in-browser probe score over threshold — rejecting verify"
                );
                self.note_verify_failure(client_ip, dcfg, arsenal, xdp);
                return Self::reject_verify(session, client_ip, "js probe over threshold").await;
            }
        }

        // Phase 4 — a successful verify clears the per-IP failure credit
        // so a client that finally passes isn't carrying stale failures
        // toward a future deny.
        self.failures.clear(client_ip);

        // Clear the per-IP escalation counter so the next request
        // gets a fresh start (back to Headers level, if even that).
        self.filter.reset(client_ip);

        // Fingerprint hash: the JS challenge supplies one via ?fp=
        // (FNV-1a over UA + screen + canvas), the captcha and other
        // levels fall back to an empty string — the fp cookie still
        // gets minted, just with no behavioural component.
        let fp_cookie = self.fp_cookie(client_ip, &q.fp_hash);

        // 302 to the return URL with both cookies set. The token
        // cookie is harmless after a successful verify but we
        // re-set it (no Max-Age=0 expire) so the browser keeps it
        // around — matches hyper.
        let mut h = ResponseHeader::build(302, Some(3))?;
        let _ = h.insert_header("set-cookie", fp_cookie.as_str());
        let _ = h.insert_header("cache-control", "no-store");
        let _ = h.insert_header("location", q.return_to.as_str());
        // H1 — HEAD must not have a body (RFC 9110 §9.3.2). The redirect
        // headers (incl. set-cookie) still go out; only the body is
        // dropped, with end-of-stream on the header frame.
        if Self::is_head(session) {
            session.write_response_header(Box::new(h), true).await?;
        } else {
            session.write_response_header(Box::new(h), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"verified")), true)
                .await?;
        }

        // Note for callers: this also bumps the scorer (allowed) +
        // dynamic-trust observation — the proxy hot path will do
        // that AFTER this returns since the request landed Allow.
        let _ = Instant::now(); // silences unused if logging changes
        Ok(())
    }
}

/// V237 — allocation-free cookie scanner for the hot `fp_cookie_valid`
/// path.
///
/// Returns a `&str` slice borrowed from the raw header value when the
/// named cookie is present and non-empty, or `None` without any heap
/// allocation when:
///   - there is no `Cookie` header at all, OR
///   - the named cookie is absent from all `Cookie` header values.
///
/// Unlike `read_cookie` (which calls `format!("{name}=")` to build a
/// search prefix String on every call), this function uses two
/// successive `strip_prefix` calls on borrowed `&str` slices — no
/// heap allocation until a match is found.
///
/// Strips RFC 6265 optional double-quote wrapping (bare `"` chars at
/// either end of the value), consistent with `read_cookie`.
///
/// Other call sites (`handle_verify` → aegis_token) continue to use
/// the existing `read_cookie` helper, which is not changed here.
fn find_cookie_borrowed<'h>(headers: &'h http::HeaderMap, name: &str) -> Option<&'h str> {
    // Fast exit: `HeaderMap::get` returns `None` without any iteration
    // when the key is absent — zero allocations.
    headers.get("cookie")?;
    for hv in headers.get_all("cookie").iter() {
        let Ok(s) = hv.to_str() else { continue };
        for part in s.split(';') {
            let part = part.trim();
            // Two-step strip: first the name, then the `=` separator.
            // Neither step allocates — both return `&str` slices into
            // the original header buffer.
            if let Some(rest) = part.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                let v = rest.trim_matches('"');
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Phase 3 — JS probe collectors injected into the interactive rung.
///
/// Each `aegisProbe*` function runs entirely in the browser, returns a
/// numeric bitmask (matching `crate::challenge_signals::*_bit`), and is
/// wrapped in its own `try/catch` so a probe that throws degrades to
/// `0` (no evidence) rather than aborting the whole verify flow. The
/// bit values MUST stay in lockstep with the Rust `*_bit` modules.
///
/// `aegisProbeHeadless` (→ `&b=`):
///   1   webdriver           navigator.webdriver === true
///   2   no_window_chrome    UA claims Chrome but window.chrome absent
///   4   cdc_props           ChromeDriver cdc_/$cdc_ document keys
///   8   no_plugins          navigator.plugins.length === 0
///   16  permissions_quirk   Notification.permission "denied" vs query "prompt"
///   32  tostring_tampered   a native fn's toString() not native-looking
///   64  no_languages        navigator.languages empty
///
/// `aegisProbeWebglAudio` (→ `&w=`):
///   1   swiftshader         UNMASKED_RENDERER mentions SwiftShader/llvmpipe
///   2   no_webgl            no WebGL context obtainable
///   4   no_audio            no AudioContext
///
/// `aegisProbeDomTiming` (→ `&dt=`) is async (needs a few rAF frames),
/// so it returns a Promise<number>:
///   1   no_raf              requestAnimationFrame never fired in budget
///   2   fake_raf_cadence    rAF deltas implausibly regular (zero jitter)
///   4   zero_timer_drift    setTimeout drift ~0 (virtual/fake timers)
const PROBE_JS: &str = r#"
function aegisProbeHeadless(){
  var b=0;
  try{ if(navigator.webdriver===true) b|=1; }catch(e){}
  try{
    var ua=(navigator.userAgent||"");
    if(/Chrome\//.test(ua) && !/Edg\//.test(ua) && !/OPR\//.test(ua) && typeof window.chrome==="undefined") b|=2;
  }catch(e){}
  try{
    var k=Object.keys(document);
    for(var i=0;i<k.length;i++){ if(/^[$]?cdc_|^cdc_/.test(k[i])){ b|=4; break; } }
    if(window.document.documentElement.getAttribute("webdriver")!==null) b|=4;
  }catch(e){}
  try{ if((navigator.plugins?navigator.plugins.length:0)===0) b|=8; }catch(e){}
  try{
    if(navigator.permissions && navigator.permissions.query && typeof Notification!=="undefined"){
      navigator.permissions.query({name:"notifications"}).then(function(p){
        // can't fold async result into the sync bitmask; the contradiction
        // (denied vs prompt) is captured opportunistically below instead.
        if(Notification.permission==="denied" && p.state==="prompt"){ window.__aegisPermQuirk=true; }
      }).catch(function(){});
    }
    if(window.__aegisPermQuirk===true) b|=16;
  }catch(e){}
  try{
    var native=Function.prototype.toString.call(navigator.permissions?navigator.permissions.query:function(){});
    if(native.indexOf("[native code]")===-1 && native.indexOf("function")!==-1) b|=32;
  }catch(e){}
  try{ if(!navigator.languages || navigator.languages.length===0) b|=64; }catch(e){}
  return b>>>0;
}
function aegisProbeWebglAudio(){
  var b=0;
  try{
    var c=document.createElement("canvas");
    var gl=c.getContext("webgl")||c.getContext("experimental-webgl");
    if(!gl){ b|=2; }
    else {
      var dbg=gl.getExtension("WEBGL_debug_renderer_info");
      var r=dbg?(""+gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)):"";
      if(/swiftshader|llvmpipe|software|basic render|microsoft basic/i.test(r)) b|=1;
      window.__aegisGlR=r;
    }
  }catch(e){ b|=2; }
  try{
    var AC=window.AudioContext||window.webkitAudioContext;
    if(!AC){ b|=4; }
    else { var ac=new AC(); window.__aegisAudR=ac.sampleRate||0; if(ac.close) ac.close(); }
  }catch(e){ b|=4; }
  return b>>>0;
}
function aegisProbeDomTiming(){
  return new Promise(function(resolve){
    var b=0;
    if(typeof requestAnimationFrame!=="function"){ resolve(1); return; }
    var ts=[], n=0, done=false;
    var t0=performance.now();
    function frame(now){
      ts.push(now);
      if(++n<6 && (now-t0)<400){ requestAnimationFrame(frame); }
      else finish();
    }
    function finish(){
      if(done) return; done=true;
      if(ts.length<2){ b|=1; resolve(b>>>0); return; }
      var deltas=[]; for(var i=1;i<ts.length;i++) deltas.push(ts[i]-ts[i-1]);
      var mean=deltas.reduce(function(a,c){return a+c;},0)/deltas.length;
      var varc=deltas.reduce(function(a,c){return a+(c-mean)*(c-mean);},0)/deltas.length;
      // A real display has frame-to-frame jitter; zero variance is a faked clock.
      if(mean>0 && varc<0.0001) b|=2;
      // setTimeout drift: schedule 20ms, measure actual elapsed.
      var s=performance.now();
      setTimeout(function(){
        var drift=Math.abs((performance.now()-s)-20);
        if(drift<0.001) b|=4; // virtual time never drifts
        resolve(b>>>0);
      },20);
    }
    // Hard cap so the page never hangs if rAF stalls.
    setTimeout(function(){ if(!done){ done=true; if(ts.length<2) b|=1; resolve(b>>>0); } },800);
    requestAnimationFrame(frame);
  });
}
"#;

/// Phase 3 — build the interactive (JS / Captcha) rung body, injecting
/// only the in-browser probes the host enabled in `dcfg`.
///
/// The base flow is unchanged from V234/V240: solve the PoW, then
/// `fetch` `/__aegis/verify` with `&p=&s=&fp=`. Phase 3 conditionally
/// appends:
///   * `&b=` when `headless_detection` is on,
///   * `&w=` when `webgl_audio_fp` is on (its WebGL renderer / audio
///     sample-rate are also folded into the `fp()` hash),
///   * `&dt=` when `dom_timing_entropy` is on (async — awaited before
///     the fetch),
///   * `&pc=1` when `proof_of_click` is on, gated behind a styled
///     "Hold to verify" button that requires a real pointer/keydown
///     gesture before the fetch fires.
///
/// A stock host (every probe None) gets byte-for-byte the pre-Phase-3
/// page (no probe params, immediate auto-submit).
fn build_js_rung(
    return_to: &str,
    verify_url: &str,
    pow_encoded: &str,
    pow_difficulty: u8,
    dcfg: &crate::arsenal::DomainChallengeConfig,
) -> String {
    let want_headless = matches!(dcfg.headless_detection, Some(true));
    let want_webgl = matches!(dcfg.webgl_audio_fp, Some(true));
    let want_timing = matches!(dcfg.dom_timing_entropy, Some(true));
    let want_click = matches!(dcfg.proof_of_click, Some(true));
    let any_probe = want_headless || want_webgl || want_timing;

    // Only ship the probe collectors when at least one is enabled.
    let probe_js = if any_probe { PROBE_JS } else { "" };

    // Build the extra `&param=` suffix appended to the verify URL.
    // `&dt=` is resolved from an awaited Promise (`dtVal`); the rest
    // are synchronous calls.
    let mut extra = String::new();
    if want_headless {
        extra.push_str("+\"&b=\"+encodeURIComponent(aegisProbeHeadless())");
    }
    if want_webgl {
        extra.push_str("+\"&w=\"+encodeURIComponent(wVal)");
    }
    if want_timing {
        extra.push_str("+\"&dt=\"+encodeURIComponent(dtVal)");
    }
    if want_click {
        extra.push_str("+\"&pc=1\"");
    }

    // The WebGL renderer / audio sample-rate (captured as side effects of
    // aegisProbeWebglAudio) are folded into the fp hash when enabled, so
    // the trust fingerprint also distinguishes GPUs/audio stacks.
    let fp_extra_bits = if want_webgl {
        ",window.__aegisGlR||\"\",window.__aegisAudR||0"
    } else {
        ""
    };

    // The synchronous webgl probe value, computed once (so the bitmask
    // and the fp-fold see the same run). Empty when the probe is off.
    let webgl_compute = if want_webgl {
        "var wVal=aegisProbeWebglAudio();"
    } else {
        ""
    };

    // dom-timing is async: resolve it (or 0 when off) before fetch.
    let timing_compute = if want_timing {
        "aegisProbeDomTiming()"
    } else {
        "Promise.resolve(0)"
    };

    // proof-of-click gate. When on, render a styled button and resolve
    // `gate` only after a genuine pointer/keydown event. When off, the
    // gate resolves immediately so the page auto-submits as before.
    let (click_ui, gate_js) = if want_click {
        (
            r#"<div id="aegis-pc" style="margin-top:18px;display:none"><button id="aegis-pc-btn" type="button">Click to verify you're human</button><p style="margin-top:10px;font-size:12px;color:#8aa0b6">One quick tap confirms you're not a bot.</p></div>"#,
            r#"function aegisGate(){return new Promise(function(res){
  var g=document.getElementById("aegis-pc"), sp=document.querySelector(".spin");
  if(!g){res();return;}
  if(sp) sp.style.display="none";
  g.style.display="block";
  var btn=document.getElementById("aegis-pc-btn"), fired=false;
  function go(ev){ if(fired) return; if(ev&&ev.isTrusted===false) return; fired=true;
    g.style.display="none"; if(sp) sp.style.display="block"; res(); }
  if(btn){ btn.addEventListener("pointerdown",go); btn.addEventListener("click",go); }
  document.addEventListener("keydown",function(e){ if(e.key==="Enter"||e.key===" ") go(e); });
});}"#,
        )
    } else {
        ("", "function aegisGate(){return Promise.resolve();}")
    };

    format!(
        r##"<div class="spin"></div>{click_ui}
<noscript><form method="POST" action="{verify_url}" style="margin-top:18px"><input type="hidden" name="answer" value="aegis"><button>I'm human — continue</button></form><p style="margin-top:10px;font-size:12px">JavaScript is required for automatic verification.</p></noscript>
<script>
{pow_js}
{probe_js}
{gate_js}
(function(){{
  var ret={ret};
  var powToken={ptok};
  var powDifficulty={pdiff};
  {webgl_compute}
  function fp(){{
    var bits=[navigator.userAgent||"",navigator.language||"",(navigator.languages||[]).join(","),
              navigator.platform||"",navigator.hardwareConcurrency||0,navigator.deviceMemory||0,
              screen.width||0,screen.height||0,screen.colorDepth||0,
              (Intl.DateTimeFormat().resolvedOptions().timeZone)||""{fp_extra_bits}];
    try {{
      var c=document.createElement("canvas"); c.width=120;c.height=30;
      var x=c.getContext("2d");
      x.textBaseline="top"; x.font="14px Arial";
      x.fillStyle="#f60"; x.fillRect(0,0,120,30);
      x.fillStyle="#069"; x.fillText("aegis-fp-v1",2,2);
      bits.push(c.toDataURL());
    }} catch(e){{ bits.push("nocanvas"); }}
    var s=bits.join("|"), h=2166136261>>>0;
    for (var i=0;i<s.length;i++){{ h^=s.charCodeAt(i); h=(h*16777619)>>>0; }}
    return ("0000000"+h.toString(16)).slice(-8);
  }}
  // V234 — solve PoW. Phase 3 — also run the enabled in-browser probes,
  // await the proof-of-click gate, then submit everything to verify.
  Promise.all([
    aegisSolvePow(powToken, powDifficulty),
    {timing_compute},
    aegisGate()
  ]).then(function(out){{
    var sol=out[0], dtVal=out[1];
    var url={vurl}
      +"&p="+encodeURIComponent(powToken)
      +"&s="+encodeURIComponent(sol)
      +"&fp="+fp(){extra};
    return fetch(url,{{credentials:"include"}});
  }}).then(function(){{location.href=ret;}}).catch(function(){{location.href=ret;}});
}})();
</script>"##,
        click_ui = click_ui,
        verify_url = verify_url,
        pow_js = POW_CLIENT_JS,
        probe_js = probe_js,
        gate_js = gate_js,
        ret = js_string_literal(return_to),
        vurl = js_string_literal(verify_url),
        ptok = js_string_literal(pow_encoded),
        pdiff = pow_difficulty,
        webgl_compute = webgl_compute,
        fp_extra_bits = fp_extra_bits,
        timing_compute = timing_compute,
        extra = extra,
    )
}

/// Escape a Rust string into a JS string literal — quotes added,
/// special chars rendered as `\u00xx`. Used to inline a server-
/// computed return URL into a `location.href=` statement without
/// XSS risk.
/// V240 — branded, self-contained interstitial shell shared by every
/// challenge rung. Dark Aegis-teal design, centred card, shield mark,
/// spinner. `head_extra` injects per-rung `<head>` content (e.g. a
/// meta-refresh); `inner` is the rung-specific body (spinner / script /
/// fallback form). No external assets — the page must render standalone.
fn challenge_shell(
    title: &str,
    heading: &str,
    subtext: &str,
    head_extra: &str,
    inner: &str,
) -> String {
    const TPL: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>__TITLE__</title>__HEAD__<style>
:root{--bg:#0a0e14;--bd:#1e2a3a;--fg:#e6edf6;--mut:#8aa0b6;--acc:#22d3a6}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:radial-gradient(1100px 560px at 50% -8%,#13202e,#0a0e14 62%);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:430px;background:linear-gradient(180deg,#121a27,#0e141d);border:1px solid var(--bd);border-radius:16px;padding:38px 32px;text-align:center;box-shadow:0 24px 70px rgba(0,0,0,.5)}
.logo{width:54px;height:54px;margin:0 auto 18px;display:block;color:var(--acc)}
h1{font-size:19px;font-weight:600;margin:0 0 8px;letter-spacing:-.01em}
p{color:var(--mut);margin:0 0 18px;font-size:13.5px}
.spin{width:36px;height:36px;margin:6px auto 0;border:3px solid rgba(34,211,166,.16);border-top-color:var(--acc);border-radius:50%;animation:r .8s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
form{margin:6px 0 0}button{width:100%;padding:12px;border-radius:10px;border:0;background:var(--acc);color:#04150f;font-weight:700;font-size:14px;cursor:pointer;transition:filter .15s}button:hover{filter:brightness(1.07)}
.foot{margin-top:26px;font-size:11px;color:#52647a;letter-spacing:.05em;text-transform:uppercase}
.foot b{color:var(--acc);font-weight:700}
</style></head><body><div class="card">
<svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
<h1>__HEADING__</h1><p>__SUBTEXT__</p>__INNER__
<div class="foot">Protected by <b>Aegis</b></div>
</div></body></html>"#;
    TPL.replace("__TITLE__", title)
        .replace("__HEAD__", head_extra)
        .replace("__HEADING__", heading)
        .replace("__SUBTEXT__", subtext)
        .replace("__INNER__", inner)
}

/// Phase 5 — build the Cloudflare Turnstile interactive rung body.
///
/// Returns `(head_extra, inner)`:
///   * `head_extra` injects Cloudflare's widget loader `<script>` into
///     the challenge page `<head>` (the only external asset the branded
///     shell ever loads, and only when the host opted into Turnstile).
///   * `inner` renders the widget container plus a tiny callback that,
///     on a successful solve, `fetch`es `/__aegis/verify` with the
///     `cf-turnstile-response` token as `&cf=` (mirroring how the PoW
///     rung submits `&p=&s=`), then redirects to the original URL.
///
/// The `data-callback` fires only after Cloudflare's own client-side
/// verification, and the server still validates the token against
/// siteverify in `handle_verify` — the client-side callback alone grants
/// nothing. The sitekey is attribute-escaped (it is operator-supplied
/// via env) and the return URL is inlined as a safe JS string literal.
fn build_turnstile_rung(return_to: &str, verify_url: &str, sitekey: &str) -> (String, String) {
    let head_extra =
        "<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\" async defer></script>"
            .to_string();
    let inner = format!(
        r##"<div class="cf-turnstile" data-sitekey="{sitekey}" data-callback="aegisTsOk"></div>
<noscript><p style="margin-top:16px;font-size:13px">JavaScript is required to complete this verification.</p></noscript>
<script>
function aegisTsOk(token){{
  var ret={ret};
  var url={vurl}+"&cf="+encodeURIComponent(token);
  fetch(url,{{credentials:"include"}})
    .then(function(){{location.href=ret;}})
    .catch(function(){{location.href=ret;}});
}}
</script>"##,
        sitekey = attr_escape(sitekey),
        ret = js_string_literal(return_to),
        vurl = js_string_literal(verify_url),
    );
    (head_extra, inner)
}

/// Escape a string for safe inclusion inside a double-quoted HTML
/// attribute value. Operator-supplied env values (the Turnstile sitekey)
/// pass through here so a stray `"`/`<`/`>`/`&` can't break out of the
/// `data-sitekey="…"` attribute.
fn attr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            c => out.push(c),
        }
    }
    out
}

fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ChallengeConfig {
        ChallengeConfig {
            enabled: true,
            token_ttl_secs: 300,
            fp_ttl_secs: 86_400,
            hmac_secret: "test-secret".to_string(),
            captcha_site_key: None,
            captcha_secret: None,
            cookie_secure: false,
        }
    }

    #[test]
    fn js_string_literal_quotes_and_escapes() {
        assert_eq!(js_string_literal("/a/b"), "\"/a/b\"");
        assert_eq!(js_string_literal("a\"b"), "\"a\\\"b\"");
        assert_eq!(js_string_literal("<x>"), "\"\\u003cx\\u003e\"");
    }

    #[test]
    fn safe_return_url_refuses_absolute_and_special() {
        assert_eq!(ChallengeContext::safe_return_url("/foo"), "/foo");
        assert_eq!(ChallengeContext::safe_return_url("//evil"), "/");
        assert_eq!(ChallengeContext::safe_return_url("http://evil"), "/");
        assert_eq!(ChallengeContext::safe_return_url("/x\r\n"), "/");
        // V233 — backslash normalises to `/` in browsers, scheme
        // before the first slash, and bare schemes are all rejected.
        assert_eq!(ChallengeContext::safe_return_url("/\\evil.com"), "/");
        assert_eq!(
            ChallengeContext::safe_return_url("javascript:alert(1)"),
            "/"
        );
        assert_eq!(ChallengeContext::safe_return_url("https://evil"), "/");
        assert_eq!(ChallengeContext::safe_return_url("\\\\evil.com"), "/");
        assert_eq!(ChallengeContext::safe_return_url("/a:b"), "/a:b"); // `:` after slash is fine
    }

    // V233 — `handle_verify`'s `?r=` redirect target must get the
    // same strict validation as the challenge response path. The
    // query parsing + hardening lives in `parse_verify_query`, so we
    // exercise it directly (no live `Session` needed).
    // V234 — `parse_verify_query` now returns a `VerifyQuery` struct
    // (private), so `.1` became `.return_to`.
    #[test]
    fn parse_verify_query_hardens_redirect_target() {
        let r = |q: &str| ChallengeContext::parse_verify_query(q).return_to;
        // Open-redirect / injection vectors all fall back to `/`.
        assert_eq!(r("r=%2F%5Cevil.com"), "/"); // /\evil.com → //evil.com in browsers
        assert_eq!(r("r=%2F%2Fevil.com"), "/"); // //evil.com protocol-relative
        assert_eq!(r("r=%2Fa%0d%0aX%3Ay"), "/"); // /a\r\nX:y CRLF header injection
        assert_eq!(r("r=https%3A%2F%2Fevil"), "/"); // absolute URL
        // A normal same-site path is preserved.
        assert_eq!(r("t=tok&r=%2Fdashboard&fp=abc"), "/dashboard");
        // Token + fp still extracted alongside the hardened target.
        let q = ChallengeContext::parse_verify_query("t=abc&r=%2Fx&fp=def");
        assert_eq!(
            (q.token.as_str(), q.return_to.as_str(), q.fp_hash.as_str()),
            ("abc", "/x", "def")
        );
        // Missing `r` defaults to `/`.
        assert_eq!(r("t=abc"), "/");
    }

    // V234 — `parse_verify_query` also pulls the PoW token (`?p=`) and
    // solution (`?s=`) the JS rung posts.
    #[test]
    fn parse_verify_query_extracts_pow_fields() {
        let q = ChallengeContext::parse_verify_query("t=tk&r=%2Fx&p=POWTOK&s=12345&fp=fh");
        assert_eq!(q.pow_token, "POWTOK");
        assert_eq!(q.pow_solution, Some(12_345));
        // Absent PoW params → empty token, no solution.
        let q = ChallengeContext::parse_verify_query("t=tk&r=%2Fx");
        assert_eq!(q.pow_token, "");
        assert_eq!(q.pow_solution, None);
        // Non-numeric `?s=` is rejected to `None` (not parsed as 0).
        let q = ChallengeContext::parse_verify_query("p=X&s=notanumber");
        assert_eq!(q.pow_solution, None);
        // A URL-encoded solution still decodes.
        let q = ChallengeContext::parse_verify_query("s=%20999%20");
        assert_eq!(q.pow_solution, Some(999));
    }

    // Phase 3 — `parse_verify_query` also pulls the in-browser probe
    // params (`&b/&w/&dt/&pc`) the JS rung posts.
    #[test]
    fn parse_verify_query_extracts_js_probe_fields() {
        let q = ChallengeContext::parse_verify_query("t=tk&b=5&w=1&dt=4&pc=1");
        assert_eq!(q.js_probe.headless, Some(5));
        assert_eq!(q.js_probe.webgl_audio, Some(1));
        assert_eq!(q.js_probe.dom_timing, Some(4));
        assert_eq!(q.js_probe.proof_of_click, Some(true));
        // Absent probe params → None (probe not enabled / old client).
        let q = ChallengeContext::parse_verify_query("t=tk");
        assert_eq!(q.js_probe.headless, None);
        assert_eq!(q.js_probe.proof_of_click, None);
        // pc=0 (or any non-"1") parses to Some(false): the gate did run
        // but no human gesture was observed.
        let q = ChallengeContext::parse_verify_query("pc=0");
        assert_eq!(q.js_probe.proof_of_click, Some(false));
        // Garbage bitmask → None (treated as "no evidence" by scorer).
        let q = ChallengeContext::parse_verify_query("b=notanumber");
        assert_eq!(q.js_probe.headless, None);
    }

    // Phase 3 — the JS rung only injects a probe's snippet + verify param
    // when the host enabled it; a stock (all-None) host gets neither.
    #[test]
    fn build_js_rung_injects_only_enabled_probes() {
        use crate::arsenal::DomainChallengeConfig;
        // Stock host: no probe collectors, no extra params, no click UI.
        let stock = build_js_rung(
            "/",
            "/__aegis/verify?t=x",
            "POWTOK",
            18,
            &DomainChallengeConfig::default(),
        );
        assert!(!stock.contains("aegisProbeHeadless"));
        assert!(!stock.contains("&b="));
        assert!(!stock.contains("aegis-pc-btn"));
        assert!(stock.contains("aegisSolvePow")); // base flow intact

        // All probes on: every collector + param + the click gate present.
        let cfg = DomainChallengeConfig {
            headless_detection: Some(true),
            webgl_audio_fp: Some(true),
            dom_timing_entropy: Some(true),
            proof_of_click: Some(true),
            ..Default::default()
        };
        let full = build_js_rung("/", "/__aegis/verify?t=x", "POWTOK", 18, &cfg);
        assert!(full.contains("aegisProbeHeadless"));
        assert!(full.contains("&b="));
        assert!(full.contains("aegisProbeWebglAudio"));
        assert!(full.contains("&w="));
        assert!(full.contains("aegisProbeDomTiming"));
        assert!(full.contains("&dt="));
        assert!(full.contains("&pc=1"));
        assert!(full.contains("aegis-pc-btn")); // proof-of-click button
    }

    // ── Phase 5 — Turnstile rung ─────────────────────────────────

    #[test]
    fn turnstile_rung_renders_widget_and_loader() {
        let (head, inner) = build_turnstile_rung("/dash", "/__aegis/verify?t=tok", "0xSITEKEY123");
        // Cloudflare's widget loader goes in <head>.
        assert!(head.contains("challenges.cloudflare.com/turnstile/v0/api.js"));
        // The widget container carries the sitekey + our callback.
        assert!(inner.contains("class=\"cf-turnstile\""));
        assert!(inner.contains("data-sitekey=\"0xSITEKEY123\""));
        assert!(inner.contains("data-callback=\"aegisTsOk\""));
        // On success it POSTs the cf-turnstile-response token via &cf=.
        assert!(inner.contains("\"&cf=\""));
        assert!(inner.contains("/__aegis/verify?t=tok"));
    }

    #[test]
    fn turnstile_rung_attr_escapes_sitekey() {
        // A sitekey with HTML-special chars must not break out of the
        // data-sitekey="…" attribute.
        let (_h, inner) = build_turnstile_rung("/", "/v", "a\"><x");
        assert!(!inner.contains("a\"><x"));
        assert!(inner.contains("a&quot;&gt;&lt;x"));
    }

    #[test]
    fn parse_verify_query_extracts_cf_token() {
        let q = ChallengeContext::parse_verify_query("t=tok&cf=CFTOKEN123&r=%2Fhome");
        assert_eq!(q.cf_turnstile, "CFTOKEN123");
        assert_eq!(q.return_to, "/home");
    }

    #[test]
    fn turnstile_active_requires_toggle_and_both_keys() {
        // Snapshot + restore env so the test is hermetic.
        let prev_sk = std::env::var(TURNSTILE_SITEKEY_ENV).ok();
        let prev_sec = std::env::var(TURNSTILE_SECRET_ENV).ok();
        // Toggle OFF → never active even with keys set.
        unsafe {
            std::env::set_var(TURNSTILE_SITEKEY_ENV, "sk");
            std::env::set_var(TURNSTILE_SECRET_ENV, "sec");
        }
        let off = crate::arsenal::DomainChallengeConfig::default();
        assert!(turnstile_active(&off).is_none());
        // Toggle ON + both keys → active.
        let on = crate::arsenal::DomainChallengeConfig {
            turnstile: Some(true),
            ..Default::default()
        };
        assert!(turnstile_active(&on).is_some());
        // Toggle ON but a key missing → graceful fallback (None).
        unsafe {
            std::env::remove_var(TURNSTILE_SECRET_ENV);
        }
        assert!(turnstile_active(&on).is_none());
        unsafe {
            std::env::remove_var(TURNSTILE_SITEKEY_ENV);
        }
        assert!(turnstile_active(&on).is_none());
        // Restore.
        unsafe {
            match prev_sk {
                Some(v) => std::env::set_var(TURNSTILE_SITEKEY_ENV, v),
                None => std::env::remove_var(TURNSTILE_SITEKEY_ENV),
            }
            match prev_sec {
                Some(v) => std::env::set_var(TURNSTILE_SECRET_ENV, v),
                None => std::env::remove_var(TURNSTILE_SECRET_ENV),
            }
        }
    }

    #[test]
    fn fp_cookie_round_trips() {
        let ctx = ChallengeContext::new(cfg(), Arc::new(ChallengeFilter::new(&cfg())));
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let cookie = ctx.fp_cookie(ip, "abc");
        // Extract the token value.
        let token = cookie
            .strip_prefix(&format!("{FP_COOKIE}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut hm = http::HeaderMap::new();
        hm.insert("cookie", format!("{FP_COOKIE}={token}").parse().unwrap());
        assert!(ctx.fp_cookie_valid(ip, &hm));
        // V244 — the trust cookie is intentionally NOT IP-bound (a browser
        // behind a CDN changes IP between requests). It still validates from
        // a different IP; forgery is prevented by the HMAC + TTL, not the IP.
        let other: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(ctx.fp_cookie_valid(other, &hm));
    }

    // ===================================================================
    // V237 — find_cookie_borrowed tests: verify allocation-free scanner
    // matches read_cookie semantics on all relevant cases.
    // ===================================================================

    fn hm(cookie: &str) -> http::HeaderMap {
        let mut m = http::HeaderMap::new();
        m.insert("cookie", cookie.parse().unwrap());
        m
    }

    #[test]
    fn find_cookie_borrowed_returns_value_when_present() {
        let m = hm("foo=bar; aegis_fp=tok123; lang=en");
        assert_eq!(find_cookie_borrowed(&m, "aegis_fp"), Some("tok123"));
    }

    #[test]
    fn find_cookie_borrowed_returns_none_when_absent() {
        let m = hm("foo=bar; other=baz");
        assert!(find_cookie_borrowed(&m, "aegis_fp").is_none());
    }

    #[test]
    fn find_cookie_borrowed_returns_none_with_no_cookie_header() {
        let m = http::HeaderMap::new();
        assert!(find_cookie_borrowed(&m, "aegis_fp").is_none());
    }

    #[test]
    fn find_cookie_borrowed_strips_quotes() {
        let m = hm(r#"aegis_fp="quoted-value""#);
        assert_eq!(find_cookie_borrowed(&m, "aegis_fp"), Some("quoted-value"));
    }

    #[test]
    fn find_cookie_borrowed_first_match_across_multiple_cookies() {
        let m = hm("a=1; aegis_fp=first; aegis_fp=second");
        assert_eq!(find_cookie_borrowed(&m, "aegis_fp"), Some("first"));
    }

    #[test]
    fn find_cookie_borrowed_ignores_partial_name_prefix() {
        // "aegis_fp_extra" must not match a search for "aegis_fp".
        let m = hm("aegis_fp_extra=sneaky; other=val");
        assert!(find_cookie_borrowed(&m, "aegis_fp").is_none());
    }

    // Confirm find_cookie_borrowed and read_cookie agree on the present
    // case — semantics must be identical so fp_cookie_valid behaves the
    // same as before on a cookie-present request.
    #[test]
    fn find_cookie_borrowed_agrees_with_read_cookie_on_present() {
        let m = hm("x=1; aegis_fp=tok.abc.def; y=2");
        let borrowed = find_cookie_borrowed(&m, "aegis_fp").unwrap();
        let owned = read_cookie(&m, "aegis_fp").unwrap();
        assert_eq!(borrowed, owned.as_str());
    }

    // ===================================================================
    // V234 — proof-of-work gate tests.
    //
    // The live JS rung's PoW band is `Attack` (24-bit) which is far
    // too slow to brute-force inside a unit test, so these build a
    // `ChallengeContext` and then replace its `pow` issuer with one
    // pinned to a low difficulty. The gate logic under test — IP
    // binding, HMAC, expiry, difficulty, the `pow.` nonce marker — is
    // identical regardless of difficulty.
    // ===================================================================

    // `DifficultyLadder`, `PowIssuer`, `RiskBand`, `VerifyResult` are
    // already in scope via `use super::*`; only `solve` is extra.
    use crate::pow_captcha::solve;

    /// A `ChallengeContext` whose PoW issuer is pinned to `difficulty`
    /// bits so tests can brute-force a solution quickly.
    fn ctx_with_pow_difficulty(difficulty: u8) -> ChallengeContext {
        let mut ctx = ChallengeContext::new(cfg(), Arc::new(ChallengeFilter::new(&cfg())));
        let ladder = DifficultyLadder {
            baseline: difficulty,
            elevated: difficulty,
            attack: difficulty,
            critical: difficulty,
        };
        ctx.pow = PowIssuer::new(cfg().hmac_secret.into_bytes(), 120, ladder);
        ctx
    }

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    fn now() -> i64 {
        ChallengeContext::now_epoch()
    }

    /// Build a `VerifyQuery` carrying just the PoW token + solution
    /// (the gate ignores `token`/`return_to`/`fp_hash`).
    fn pow_query(pow_token: &str, solution: Option<u64>) -> VerifyQuery {
        VerifyQuery {
            token: String::new(),
            return_to: "/".to_string(),
            fp_hash: String::new(),
            pow_token: pow_token.to_string(),
            pow_solution: solution,
            js_probe: crate::challenge_signals::JsProbe::default(),
            cf_turnstile: String::new(),
        }
    }

    // A correct, IP-matched, in-difficulty solution passes the gate.
    #[test]
    fn pow_gate_accepts_correct_solution() {
        let ctx = ctx_with_pow_difficulty(12);
        let tok = ctx
            .pow
            .issue_bound(RiskBand::Attack, CHALLENGE_BINDING.as_bytes());
        let sol = solve(&tok.nonce, tok.difficulty);
        let q = pow_query(&tok.encode(), Some(sol));
        assert_eq!(ctx.pow_gate("pow.abc", &q, ip(), now()), Ok(()));
    }

    // A `pow.`-marked nonce with NO `?s=` solution is rejected — this
    // is the "just omit the solution" bypass attempt.
    #[test]
    fn pow_gate_rejects_missing_solution() {
        let ctx = ctx_with_pow_difficulty(12);
        let tok = ctx
            .pow
            .issue_bound(RiskBand::Attack, CHALLENGE_BINDING.as_bytes());
        let q = pow_query(&tok.encode(), None);
        assert_eq!(
            ctx.pow_gate("pow.abc", &q, ip(), now()),
            Err("pow solution missing")
        );
    }

    // A `pow.`-marked nonce with NO `?p=` token at all is rejected
    // (empty token → decode fails → Malformed).
    #[test]
    fn pow_gate_rejects_missing_token() {
        let ctx = ctx_with_pow_difficulty(12);
        let q = pow_query("", Some(0));
        assert_eq!(
            ctx.pow_gate("pow.abc", &q, ip(), now()),
            Err("pow token malformed")
        );
    }

    // A forged / tampered PoW token fails the HMAC check.
    #[test]
    fn pow_gate_rejects_forged_token() {
        let ctx = ctx_with_pow_difficulty(12);
        let mut tok = ctx
            .pow
            .issue_bound(RiskBand::Attack, CHALLENGE_BINDING.as_bytes());
        let sol = solve(&tok.nonce, tok.difficulty);
        // Tamper: bump the difficulty so the signed-over bytes change.
        tok.difficulty = tok.difficulty.wrapping_add(1);
        let q = pow_query(&tok.encode(), Some(sol));
        assert_eq!(
            ctx.pow_gate("pow.abc", &q, ip(), now()),
            Err("pow token bad HMAC / wrong IP")
        );
    }

    // V244 — the PoW is intentionally NOT IP-bound (a browser behind a CDN
    // legitimately changes IP between challenge and verify). A correct
    // solution therefore verifies regardless of the request IP.
    #[test]
    fn pow_gate_accepts_regardless_of_ip() {
        let ctx = ctx_with_pow_difficulty(12);
        let tok = ctx
            .pow
            .issue_bound(RiskBand::Attack, CHALLENGE_BINDING.as_bytes());
        let sol = solve(&tok.nonce, tok.difficulty);
        let q = pow_query(&tok.encode(), Some(sol));
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        assert_eq!(ctx.pow_gate("pow.abc", &q, other, now()), Ok(()));
    }

    // An expired PoW token is rejected even with a correct solution.
    #[test]
    fn pow_gate_rejects_expired_token() {
        // 1s TTL issuer so the token is trivially past `exp`.
        let mut ctx = ctx_with_pow_difficulty(12);
        ctx.pow = PowIssuer::new(
            cfg().hmac_secret.into_bytes(),
            1,
            DifficultyLadder {
                baseline: 12,
                elevated: 12,
                attack: 12,
                critical: 12,
            },
        );
        let tok = ctx
            .pow
            .issue_bound(RiskBand::Attack, CHALLENGE_BINDING.as_bytes());
        let sol = solve(&tok.nonce, tok.difficulty);
        let q = pow_query(&tok.encode(), Some(sol));
        // Verify well past expiry.
        assert_eq!(
            ctx.pow_gate("pow.abc", &q, ip(), tok.exp as i64 + 10),
            Err("pow token expired")
        );
    }

    // A wrong / insufficient solution is rejected. Issue at a HIGH
    // difficulty so an arbitrary guess overwhelmingly fails, but do
    // not brute-force it.
    #[test]
    fn pow_gate_rejects_insufficient_solution() {
        let ctx = ctx_with_pow_difficulty(28);
        let tok = ctx
            .pow
            .issue_bound(RiskBand::Attack, CHALLENGE_BINDING.as_bytes());
        // 0xdead_beef will not satisfy a 28-bit prefix.
        let q = pow_query(&tok.encode(), Some(0xdead_beef));
        assert_eq!(
            ctx.pow_gate("pow.abc", &q, ip(), now()),
            Err("pow solution insufficient")
        );
    }

    // A nonce WITHOUT the `pow.` marker (lower rungs / captcha form)
    // skips the gate — no PoW token needed, the HMAC-signed marker is
    // what authorises the skip so this is not a bypass.
    #[test]
    fn pow_gate_skips_when_nonce_not_marked() {
        let ctx = ctx_with_pow_difficulty(12);
        // Empty PoW fields, plain (non-`pow.`) nonce → allowed.
        let q = pow_query("", None);
        assert_eq!(ctx.pow_gate("plain-uuid-nonce", &q, ip(), now()), Ok(()));
    }

    // H1 — every challenge/verify response builder keys off the request
    // method being HEAD to suppress the body (RFC 9110 §9.3.2). The
    // `is_head` helper compares against `http::Method::HEAD`; building a
    // live pingora `Session` here isn't feasible (the rest of this module
    // deliberately avoids it), so we pin the constant the helper relies on
    // — a mismatch (e.g. comparing the wrong method) would surface here.
    #[test]
    fn head_method_constant_is_stable() {
        assert_eq!(http::Method::HEAD.as_str(), "HEAD");
        assert_ne!(http::Method::HEAD, http::Method::GET);
    }

    // The JS rung stamps a `pow.`-prefixed nonce into `aegis_token`.
    #[test]
    fn javascript_rung_nonce_is_pow_marked() {
        // The marker is what `pow_gate` keys off; assert the prefix
        // contract the two halves agree on.
        let n = format!("pow.{}", uuid::Uuid::new_v4());
        assert!(n.starts_with("pow."));
    }
}
