use std::{
    convert::Infallible,
    // V233: DefaultHasher/Hasher used to fold attacker-controlled key
    // components into a fixed-width digest (see redis_rep_key / redis_tb_key).
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri, request::Parts};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

use crate::{
    anomaly::{AnomalyDetector, escalate_level},
    // V234 — real reCAPTCHA siteverify path. `ReCaptcha`/`CaptchaProvider`
    // own the request-body shape + JSON parsing; `HttpPoster` is the
    // transport seam we satisfy with the hyper client below.
    captcha_providers::{CaptchaProvider, HttpPoster, ReCaptcha},
    config::{
        BotConfig, BypassConfig, ChallengeConfig, GeoIpConfig, GraphqlConfig, RateLimitConfig,
        WafConfig,
    },
    ddos::score::ThreatScorer,
    filters::{
        ChallengeLevel, FilterAction, bypass::BypassMatcher, challenge::ChallengeFilter,
        engine::FilterEngine, graphql::GraphqlFilter, waf::WafFilter,
    },
    geoip::GeoIpLookup,
    honeypot::{HoneypotStore, TarpitBody},
    metrics::{Protocol, RuntimeMetrics},
    proxy::{
        health::UpstreamHealth, request_context::RequestContext, upstream::SharedUpstreamRouter,
    },
    security::token::{sign_token, verify_token},
    state::{
        fingerprint::FingerprintCache,
        reputation::{BucketOutcome, ReputationStore},
    },
    xdp::XdpHandle,
};

pub type RespBody = BoxBody<Bytes, hyper::Error>;

#[derive(Clone)]
pub struct ProxyHttpHandler {
    client: Client<HttpConnector, Full<Bytes>>,
    upstream: SharedUpstreamRouter,
    filters: Arc<FilterEngine>,
    metrics: Arc<RuntimeMetrics>,
    scorer: Arc<ThreatScorer>,
    /// Reputation-driven trust state. Amplifies `bypass` by
    /// promoting clean-behaving IPs to the fast-path automatically.
    /// Off-by-default (config-gated) so existing deployments keep
    /// their exact behaviour until operators opt in.
    dynamic_trust: Arc<crate::filters::dynamic_trust::DynamicTrust>,
    /// Threat-aware response cache. Memoises upstream responses for
    /// cacheable GET/HEAD requests; high-threat IPs get forced MISS
    /// so they can't poison entries seen by trusted clients.
    response_cache: Arc<crate::proxy::response_cache::ResponseCache>,
    /// Phase 3Y.8 — single-flight registry. Prevents the "cache
    /// stampede" pathology where N concurrent requests for the
    /// same cache-missing key all hit upstream simultaneously
    /// (TTL expiry, cache cold-start, etc.). First request becomes
    /// leader and fetches; subsequent followers wait on the leader's
    /// `Notify`, then retry the cache to pick up the freshly-stored
    /// entry. Bounded by a 5 s wait timeout so leader failure
    /// degrades gracefully to N concurrent fetches.
    pending_fetches:
        Arc<dashmap::DashMap<(http::Method, String, String), Arc<tokio::sync::Notify>>>,
    challenge_cfg: ChallengeConfig,
    challenge_filter: Arc<ChallengeFilter>,
    bot_cfg: BotConfig,
    rate_cfg: RateLimitConfig,
    waf: Arc<WafFilter>,
    graphql: Arc<GraphqlFilter>,
    bypass: Arc<BypassMatcher>,
    health: Arc<UpstreamHealth>,
    fingerprints: Arc<FingerprintCache>,
    honeypots: Arc<HoneypotStore>,
    xdp: Arc<dyn XdpHandle>,
    store: Option<ReputationStore>,
    geoip: Arc<dyn GeoIpLookup>,
    geoip_cfg: Option<GeoIpConfig>,
    anomaly: Arc<AnomalyDetector>,
    /// Slow-POST guard: max wall-clock budget the client gets to
    /// finish streaming the request body. 0 = disabled.
    body_read_timeout_ms: u64,
    /// Pre-baked Alt-Svc value advertising h3 availability. Stamped on
    /// h1/h2 responses so curl/Chrome can switch to QUIC next request.
    alt_svc: Option<String>,
    /// Set to true on requests received over h3; suppresses the
    /// Alt-Svc header (the client already speaks it).
    is_h3: bool,
}

/// Cookie name carrying the signed challenge token across redirects /
/// page loads. HttpOnly + SameSite=Lax so browsers re-send it on the
/// follow-up request but JavaScript on third-party origins can't read
/// it.
pub const TOKEN_COOKIE: &str = "aegis_token";

/// Long-lived behavioural-fingerprint cookie. Signed by the same HMAC
/// secret over `fp_hash:ip:exp`; presence + validity short-circuits
/// the challenge ladder for the cookie's whole TTL.
pub const FP_COOKIE: &str = "aegis_fp";

/// Path used by HTML/iframe/JS/captcha challenges to feed the token
/// back to Aegis. GET sets the cookie (iframe + JS path); POST
/// processes captcha submissions.
pub const VERIFY_PATH: &str = "/__aegis/verify";

impl ProxyHttpHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream: SharedUpstreamRouter,
        filters: Arc<FilterEngine>,
        metrics: Arc<RuntimeMetrics>,
        scorer: Arc<ThreatScorer>,
        challenge_cfg: ChallengeConfig,
        challenge_filter: Arc<ChallengeFilter>,
        bot_cfg: BotConfig,
        rate_cfg: RateLimitConfig,
        waf_cfg: &WafConfig,
        graphql_cfg: &GraphqlConfig,
        bypass_cfg: &BypassConfig,
        health: Arc<UpstreamHealth>,
        fingerprints: Arc<FingerprintCache>,
        honeypots: Arc<HoneypotStore>,
        xdp: Arc<dyn XdpHandle>,
        store: Option<ReputationStore>,
        geoip: Arc<dyn GeoIpLookup>,
        geoip_cfg: Option<GeoIpConfig>,
        anomaly: Arc<AnomalyDetector>,
        alt_svc: Option<String>,
        body_read_timeout_ms: u64,
        upstream_protocol: crate::config::UpstreamProtocol,
        xdp_allow_ips: Vec<IpAddr>,
        dynamic_trust_cfg: &crate::config::DynamicTrustConfig,
        response_cache_cfg: &crate::config::ResponseCacheConfig,
    ) -> Self {
        // Upstream pool tuning:
        //   • huge per-host idle cap so 500-conn floods don't starve
        //     waiting on a free keep-alive slot (default ~32 is way
        //     too small for a reverse proxy)
        //   • long idle timeout so backend connections survive
        //     idle gaps between request bursts
        //   • aggressive h2 adaptive window so backend multiplexing
        //     doesn't bottleneck on tiny default windows
        //   • when upstream_protocol == H2c we force prior-knowledge
        //     HTTP/2, so all proxied requests multiplex over a single
        //     long-lived connection per upstream — eliminates the
        //     accept/connect cost entirely under steady load.
        let mut http_conn = HttpConnector::new();
        http_conn.set_nodelay(true);
        http_conn.set_keepalive(Some(Duration::from_secs(60)));
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(2048)
            .http2_adaptive_window(true)
            .http2_initial_stream_window_size(2 * 1024 * 1024)
            .http2_initial_connection_window_size(8 * 1024 * 1024);
        if upstream_protocol == crate::config::UpstreamProtocol::H2c {
            builder.http2_only(true);
        }
        let client: Client<HttpConnector, Full<Bytes>> = builder.build(http_conn);
        Self {
            client,
            upstream,
            filters,
            metrics,
            scorer,
            dynamic_trust: Arc::new(
                crate::filters::dynamic_trust::DynamicTrust::new(dynamic_trust_cfg)
                    .with_xdp(xdp.clone()),
            ),
            response_cache: Arc::new(crate::proxy::response_cache::ResponseCache::new(
                response_cache_cfg,
            )),
            pending_fetches: Arc::new(dashmap::DashMap::new()),
            challenge_cfg,
            challenge_filter,
            bot_cfg,
            rate_cfg,
            waf: Arc::new(WafFilter::new(waf_cfg)),
            graphql: Arc::new(GraphqlFilter::new(graphql_cfg)),
            // BypassMatcher inherits IPs from XDP allow list so a
            // single "trusted" declaration short-circuits both kernel
            // (XDP fast-pass) and userspace (filter chain). Without
            // this, an XDP-allowed IP still paid full WAF/rate/bot
            // cost — only the kernel-side deny/rate-limit was skipped.
            bypass: Arc::new(BypassMatcher::with_extra_trusted_ips(
                bypass_cfg,
                xdp_allow_ips,
            )),
            health,
            fingerprints,
            honeypots,
            xdp,
            store,
            geoip,
            geoip_cfg,
            anomaly,
            body_read_timeout_ms,
            alt_svc,
            is_h3: false,
        }
    }

    /// Lookup the country for `ip` and return Some(deny_reason) when
    /// the configured policy says we should block it. The
    /// `attack_mode_only` flag couples the deny list to the anomaly
    /// detector so geo-blocks stay dormant outside of DDoS events.
    fn geoip_deny(&self, ip: IpAddr, host: &str) -> Option<String> {
        let cfg = self.geoip_cfg.as_ref()?;
        if cfg.attack_mode_only && !self.anomaly.under_attack(host) {
            return None;
        }
        if cfg.deny_countries.is_empty() {
            return None;
        }
        let country = self.geoip.country(ip)?;
        if cfg
            .deny_countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&country))
        {
            Some(format!("geo deny: {country}"))
        } else {
            None
        }
    }

    /// Return a clone of this handler marked as serving an h3 request,
    /// so Alt-Svc is suppressed (the client already speaks h3).
    pub fn for_h3(&self) -> Self {
        let mut clone = self.clone();
        clone.is_h3 = true;
        clone
    }

    /// Maximum bytes the WAF will accept for a single request body.
    /// h3 callers use this to bound their per-stream drain buffer.
    pub fn max_body_bytes(&self) -> usize {
        self.waf.max_body_bytes()
    }

    /// Currently-flagged hosts and remaining attack-mode duration (ms).
    pub fn anomaly_snapshot(&self) -> Vec<(String, u128)> {
        self.anomaly.snapshot()
    }

    /// Snapshot of response-cache counters for /admin/cache.
    pub fn cache_stats(&self) -> crate::proxy::response_cache::CacheStats {
        self.response_cache.stats()
    }

    /// Cache entry dump for /admin/cache/dump (debugging).
    pub fn cache_dump(&self, limit: usize) -> Vec<crate::proxy::response_cache::CacheEntryInfo> {
        self.response_cache.dump(limit, Instant::now())
    }

    /// V19.3 — Trigger WAF rule-file hot-reload check. Called by
    /// the background watcher task every N seconds. Returns count
    /// of files reloaded (0 = unchanged, no-op).
    pub fn waf_maybe_reload(&self) -> usize {
        self.waf.maybe_reload_rules()
    }

    /// V21 — Check cross-worker cache purge broadcast file. If the
    /// file's mtime advanced (another worker triggered a purge),
    /// drop our local cache too. Returns count of entries dropped
    /// (0 = no broadcast pending).
    pub fn cache_check_broadcast_purge(&self) -> usize {
        if self.response_cache.check_broadcast_purge() {
            self.response_cache.purge_all()
        } else {
            0
        }
    }

    /// Purge cache entries. Filter parameters are exclusive — pass
    /// `None` to purge everything.
    pub fn purge_cache(&self, host: Option<&str>, path_prefix: Option<&str>) -> usize {
        match (host, path_prefix) {
            (Some(h), None) => self.response_cache.purge_host(h),
            (None, Some(p)) => self.response_cache.purge_path_prefix(p),
            (Some(h), Some(p)) => self
                .response_cache
                .purge_where(|k| !(k.host_lower_eq(h) && k.path.starts_with(p))),
            (None, None) => self.response_cache.purge_all(),
        }
    }

    fn stamp_alt_svc(&self, mut response: Response<RespBody>) -> Response<RespBody> {
        if self.is_h3 {
            return response;
        }
        if let Some(value) = &self.alt_svc
            && let Ok(hv) = http::HeaderValue::from_str(value)
        {
            response.headers_mut().insert("alt-svc", hv);
        }
        response
    }

    fn now_epoch() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn token_cookie(&self, token: &str) -> String {
        format!(
            "{TOKEN_COOKIE}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax{}",
            self.challenge_cfg.token_ttl_secs,
            secure_suffix(self.challenge_cfg.cookie_secure)
        )
    }

    /// Build the long-lived behavioural fingerprint cookie. The value
    /// is a signed token over `fp_hash:ip:exp` — we reuse the
    /// challenge HMAC secret with a separate nonce string so a leaked
    /// challenge cookie can't impersonate a fingerprint cookie.
    fn fp_cookie(&self, ip: IpAddr, fp_hash: &str) -> String {
        let ttl = self.challenge_cfg.fp_ttl_secs.max(60);
        let exp = Self::now_epoch() + ttl as i64;
        // Pack the fp_hash into the "nonce" slot of sign_token; the
        // token format is `ip:nonce:exp` split on ':' so we use '.'
        // inside the nonce to avoid breaking the parser.
        let token = sign_token(
            &self.challenge_cfg.hmac_secret,
            &ip.to_string(),
            &format!("fp.{fp_hash}"),
            exp,
        );
        format!(
            "{FP_COOKIE}={token}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{}",
            secure_suffix(self.challenge_cfg.cookie_secure)
        )
    }

    /// Validate the behavioural fingerprint cookie supplied by the
    /// client. Returns true when the signature checks out, the IP
    /// matches, and the embedded expiry hasn't passed.
    fn fp_cookie_valid(&self, ip: IpAddr, headers: &http::HeaderMap) -> bool {
        if self.challenge_cfg.fp_ttl_secs == 0 {
            return false;
        }
        let Some(token) = read_cookie(headers, FP_COOKIE) else {
            return false;
        };
        let now = Self::now_epoch();
        match verify_token(
            &self.challenge_cfg.hmac_secret,
            &token,
            &ip.to_string(),
            now,
        ) {
            Some((nonce, _exp)) => nonce.starts_with("fp."),
            None => {
                // Tampered or wrong-IP fingerprint cookie. Bump the
                // scorer so a single client trying many forged
                // cookies eventually trips the deny threshold — and
                // surface a tracing event so operators can grep.
                tracing::warn!(
                    target: "aegis::security",
                    ip = %ip,
                    "aegis_fp cookie failed HMAC validation"
                );
                self.record_denied(ip, Instant::now());
                false
            }
        }
    }

    /// M13 — non-consuming check for an already-established trust state.
    /// Returns true when the request carries a validly-signed, IP-bound
    /// trust artefact: either the long-lived behavioural fingerprint
    /// cookie (`aegis_fp`) or the short-lived challenge token cookie
    /// (`aegis_token`). Unlike `challenge_verified`, this performs a pure
    /// signature/expiry check and never touches the nonce store — so it
    /// can be used to gate the honest-re-fetch carve-out on the verify
    /// endpoint without itself consuming a nonce.
    fn has_valid_trust_cookie(&self, ip: IpAddr, headers: &http::HeaderMap) -> bool {
        if self.fp_cookie_valid(ip, headers) {
            return true;
        }
        let Some(token) = read_token_cookie(headers) else {
            return false;
        };
        let now = Self::now_epoch();
        verify_token(
            &self.challenge_cfg.hmac_secret,
            &token,
            &ip.to_string(),
            now,
        )
        .is_some()
    }

    /// V233 — Strict predicate for a redirect-target *string*. A value
    /// is safe to place verbatim in a `Location:` header only if it is a
    /// site-relative path that cannot (a) become an absolute / protocol-
    /// relative URL (`//`, scheme), or (b) inject additional header
    /// content via control characters. CR/LF/`"`/`\` are all rejected:
    /// CR/LF enable response-splitting, and `"`/`\` can break out of a
    /// quoted context downstream. `HeaderValue::try_from` would itself
    /// reject the control chars — but it defers that error onto the
    /// `Builder`, which only surfaces at `.body(...).expect(...)` and so
    /// would *panic the worker* (release builds use `panic = "abort"`).
    /// Rejecting up front turns an attacker-triggered crash into a
    /// harmless fallback to `/`.
    fn safe_return_path(s: &str) -> bool {
        s.starts_with('/')
            && !s.starts_with("//")
            && !s.contains('\r')
            && !s.contains('\n')
            && !s.contains('"')
            && !s.contains('\\')
    }

    /// Pick a safe redirect target. Refuses absolute URLs and anything
    /// containing a quote/newline to avoid open-redirect or response-
    /// splitting via `Location:` injection.
    fn safe_return_url(original: &http::Uri) -> String {
        let s = original
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        // V233 — route through the shared string predicate so the
        // `Uri` and `?r=` paths cannot diverge.
        if Self::safe_return_path(s) {
            s.to_string()
        } else {
            "/".to_string()
        }
    }

    fn challenge_response(
        &self,
        level: ChallengeLevel,
        reason: String,
        ip: IpAddr,
        original_uri: &http::Uri,
    ) -> Response<RespBody> {
        let nonce = uuid::Uuid::new_v4().to_string();
        let exp = Self::now_epoch() + self.challenge_cfg.token_ttl_secs as i64;
        let token = sign_token(
            &self.challenge_cfg.hmac_secret,
            &ip.to_string(),
            &nonce,
            exp,
        );
        let cookie = self.token_cookie(&token);
        let return_to = Self::safe_return_url(original_uri);
        // Encode return target into the verify URL so the iframe/JS
        // step can bounce the client back to where they were headed.
        let verify_url = format!(
            "{VERIFY_PATH}?t={}&r={}",
            urlencoding::encode(&token),
            urlencoding::encode(&return_to)
        );

        let common = |status: StatusCode, body: String| {
            Response::builder()
                .status(status)
                .header("set-cookie", cookie.clone())
                .header("x-aegis-step", challenge_step_label(level.clone()))
                .header("cache-control", "no-store")
                .header("content-type", "text/html; charset=utf-8")
                .body(
                    Full::new(Bytes::from(body))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("challenge response")
        };

        match level {
            // Rung 1 — defeats ~75% of attack tools that ignore HTTP
            // response headers. Cookie set, 307 redirect to original
            // URL. Any compliant client (incl. curl with -b/-c) follows
            // and re-sends the cookie; raw socket spammers don't.
            ChallengeLevel::Headers => Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("set-cookie", cookie)
                .header("x-aegis-step", "headers")
                .header("cache-control", "no-store")
                .header("location", return_to)
                .body(
                    Full::new(Bytes::from(reason))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("challenge response"),

            // Rung 2 — HTML page with meta-refresh. Bot must parse HTML
            // to find the refresh tag. ~75% of attack tools fail here.
            ChallengeLevel::Html => common(
                StatusCode::OK,
                format!(
                    "<!doctype html><html><head><meta http-equiv=\"refresh\" content=\"0;url={return_to}\"><title>Verifying…</title></head><body><noscript><p>Verifying your browser…</p></noscript></body></html>",
                ),
            ),

            // Rung 3 — iframe that loads the verify URL. Loading the
            // iframe makes the browser hit /__aegis/verify, where we
            // refresh the cookie and respond. Bots that don't render
            // iframes (~80%) never make that call.
            ChallengeLevel::Iframe => common(
                StatusCode::OK,
                format!(
                    "<!doctype html><html><head><title>Verifying…</title></head><body><iframe src=\"{verify_url}\" width=\"1\" height=\"1\" style=\"display:none\"></iframe><noscript><p>Verifying…</p></noscript><script>setTimeout(function(){{location.href={};}},500);</script></body></html>",
                    js_string_literal(&return_to)
                ),
            ),

            // Rung 4 — JS proof + behavioural fingerprint. Tiny PoW
            // proves a JS engine; canvas+navigator+screen produces a
            // stable browser signature that's submitted alongside the
            // token so the verify endpoint can set the long-lived
            // aegis_fp cookie. Bots without a JS engine (~90%) drop
            // out at the PoW; headless browsers that lack a real
            // canvas / WebGL surface produce a degenerate fingerprint
            // we can spot.
            ChallengeLevel::Javascript => common(
                StatusCode::OK,
                format!(
                    r##"<!doctype html><html><head><title>Verifying…</title></head><body><p id="s">Verifying your browser…</p><script>
(function(){{
  var ret={ret};
  var pow=0; for (var i=0;i<10000;i++){{pow=(pow+i*31)%97;}}
  function fp(){{
    var bits=[navigator.userAgent||"",navigator.language||"",(navigator.languages||[]).join(","),
              navigator.platform||"",navigator.hardwareConcurrency||0,navigator.deviceMemory||0,
              screen.width||0,screen.height||0,screen.colorDepth||0,
              (Intl.DateTimeFormat().resolvedOptions().timeZone)||""];
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
  var url={vurl}+"&pow="+pow+"&fp="+fp();
  fetch(url,{{credentials:"include"}}).then(function(){{location.href=ret;}}).catch(function(){{location.href=ret;}});
}})();
</script></body></html>"##,
                    ret = js_string_literal(&return_to),
                    vurl = js_string_literal(&verify_url),
                ),
            ),

            // Rung 5 — Google reCAPTCHA v2 (when configured) or a
            // server-side proof-of-work form when not. Both POST to
            // /__aegis/verify; only after a valid submission do we
            // re-issue the verification cookie that clears the ladder.
            ChallengeLevel::Captcha => {
                let body = match &self.challenge_cfg.captcha_site_key {
                    Some(site_key) => format!(
                        r#"<!doctype html><html><head><title>Are you human?</title><script src="https://www.google.com/recaptcha/api.js" async defer></script></head><body><h2>Please confirm you are human</h2><form method="POST" action="{verify_url}"><div class="g-recaptcha" data-sitekey="{site_key}"></div><button type="submit">Continue</button></form></body></html>"#,
                    ),
                    None => format!(
                        r#"<!doctype html><html><head><title>Are you human?</title></head><body><h2>Please confirm you are human</h2><form method="POST" action="{verify_url}"><label>Type the word <b>aegis</b>: <input name="answer" autocomplete="off" autofocus></label><button type="submit">Continue</button></form></body></html>"#,
                    ),
                };
                common(StatusCode::OK, body)
            }
        }
    }

    /// Handle GET /__aegis/verify (iframe + JS rungs) and
    /// POST /__aegis/verify (captcha submit). On success, sets/refreshes
    /// the verification cookie and either redirects to the original
    /// URL or returns 204 (for iframe loads). On failure returns 403.
    async fn handle_verify(
        &self,
        method: &http::Method,
        client_ip: IpAddr,
        parts: &http::request::Parts,
        body: &[u8],
    ) -> Response<RespBody> {
        let query = parts.uri.query().unwrap_or("");
        let mut token = String::new();
        let mut return_to = "/".to_string();
        for kv in query.split('&') {
            let mut it = kv.splitn(2, '=');
            let (k, v) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
            let decoded = urlencoding::decode(v).unwrap_or_default().into_owned();
            match k {
                "t" => token = decoded,
                "r" => return_to = decoded,
                _ => {}
            }
        }
        // V233 — the `?r=` value is attacker-controlled and ends up in a
        // `Location:` header. The previous check only rejected `//` and
        // non-`/` prefixes; a value like `/a\r\nX: y` passed, and the
        // deferred `HeaderValue` error then panicked `.body(...).expect`
        // (worker abort under `panic = "abort"`). Use the strict shared
        // predicate (rejects CR/LF/`"`/`\` too); fall back to `/`.
        let return_to_safe = if Self::safe_return_path(&return_to) {
            return_to
        } else {
            "/".to_string()
        };

        // V234 — captcha POST verification. `verify_recaptcha` does the
        // real reCAPTCHA siteverify when a secret is configured, and
        // fails closed when one is not. The old `answer=aegis` static
        // word-match was a publicly-known password that fully bypassed
        // the captcha rung — it has been removed. With no captcha
        // provider configured the captcha rung is simply unreachable;
        // the ladder relies on the PoW rung instead.
        if method == http::Method::POST {
            let body_str = std::str::from_utf8(body).unwrap_or("");
            let ok = self.verify_recaptcha(body_str, client_ip).await;
            if !ok {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-type", "text/plain")
                    .body(
                        Full::new(Bytes::from("captcha failed"))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .expect("captcha response");
            }
        }

        // Verify the signed token bound to this IP. Without a real
        // token we never set the cookie — otherwise a bare GET to
        // /__aegis/verify would whitelist everyone.
        let now = Self::now_epoch();
        let Some((nonce, exp)) = verify_token(
            &self.challenge_cfg.hmac_secret,
            &token,
            &client_ip.to_string(),
            now,
        ) else {
            tracing::warn!(
                target: "aegis::security",
                ip = %client_ip,
                "aegis_token failed HMAC validation at /__aegis/verify"
            );
            self.record_denied(client_ip, Instant::now());
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-type", "text/plain")
                .body(
                    Full::new(Bytes::from("invalid token"))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("verify response");
        };
        if let Some(store) = &self.store {
            let ttl = (exp - now).max(1) as usize;
            // M13 — the verify endpoint MINTS a fresh trust cookie and
            // clears the challenge ladder, so a replayed nonce must be
            // treated as FAILURE here: otherwise an attacker who captures
            // one valid verify URL (token + nonce) can replay it
            // indefinitely to mint unlimited fresh trust cookies, each
            // good for the full token TTL — fail-open trust minting.
            //
            // `mark_nonce` is Ok(true) on first use, Ok(false) on replay,
            // and Err on a Redis fault. We fail OPEN on Err (Redis down
            // must not lock out every legitimate client) but fail CLOSED
            // on a confirmed replay — UNLESS the caller already presents a
            // validly-signed, IP-bound trust cookie. That single carve-out
            // tolerates an honest re-fetch (cached challenge page, double
            // submit) without handing fresh trust to a bare replay.
            match store.mark_nonce(&nonce, ttl).await {
                Ok(false) if !self.has_valid_trust_cookie(client_ip, &parts.headers) => {
                    tracing::warn!(
                        target: "aegis::security",
                        ip = %client_ip,
                        "verify replayed nonce without an existing trust cookie — rejecting"
                    );
                    self.record_denied(client_ip, Instant::now());
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("content-type", "text/plain")
                        .body(
                            Full::new(Bytes::from("replayed token"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("verify response");
                }
                Ok(false) => {
                    tracing::debug!(
                        %client_ip,
                        "verify replayed nonce but client holds a valid trust cookie — honest re-fetch"
                    );
                }
                Ok(true) => {}
                Err(e) => {
                    // Redis fault — fall open so a backend outage doesn't
                    // turn into a site-wide lockout.
                    tracing::debug!(%client_ip, error = %e, "verify nonce store failed; falling open");
                }
            }
        }
        self.challenge_filter.reset(client_ip);

        // Behavioural fingerprint — sent by the JS challenge via
        // ?fp=... or by the captcha form as a hidden field. Stamp a
        // long-lived cookie when we have one; the value goes through
        // the same HMAC + IP binding as challenge tokens.
        let fp_hash = {
            let from_query: String = query
                .split('&')
                .find_map(|kv| {
                    let mut it = kv.splitn(2, '=');
                    if it.next() == Some("fp") {
                        it.next()
                            .map(|v| urlencoding::decode(v).unwrap_or_default().into_owned())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            if from_query.is_empty() && method == http::Method::POST {
                let body_str = std::str::from_utf8(body).unwrap_or("");
                form_field(body_str, "fp")
            } else {
                from_query
            }
        };
        let mut cookies: Vec<String> = vec![self.token_cookie(&token)];
        if !fp_hash.is_empty()
            && fp_hash.len() <= 64
            && fp_hash.chars().all(|c| c.is_ascii_alphanumeric())
        {
            cookies.push(self.fp_cookie(client_ip, &fp_hash));
        }

        // GETs come from the iframe — return tiny no-op body.
        // POSTs come from the captcha — bounce browser back to origin.
        let mut builder = if method == http::Method::GET {
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("cache-control", "no-store")
        } else {
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("location", return_to_safe)
                .header("cache-control", "no-store")
        };
        for c in cookies {
            builder = builder.header("set-cookie", c);
        }
        let body = if method == http::Method::GET {
            Bytes::new()
        } else {
            Bytes::from("verified")
        };
        builder
            .body(Full::new(body).map_err(|never| match never {}).boxed())
            .expect("verify response")
    }

    // (see `HyperPoster` below for the outbound transport seam)

    /// V234 — server-side reCAPTCHA verification (real siteverify).
    ///
    /// When `captcha_secret` is configured, extracts `g-recaptcha-response`
    /// from the submitted form body and validates it against Google's
    /// `siteverify` endpoint via [`ReCaptcha`] (which owns the request
    /// body shape, the JSON parsing, and the v3 score gate). Returns
    /// `true` only when Google reports `success == true` — and, when the
    /// operator pinned a hostname, only when the widget hostname matches.
    ///
    /// When `captcha_secret` is NOT configured this **fails closed** and
    /// returns `false`: the captcha rung cannot be passed without a
    /// provider, so the ladder must rely on the PoW rung instead. The
    /// previous behaviour — accepting any body containing the static
    /// string `answer=aegis` — was a publicly-known password and has
    /// been removed entirely.
    ///
    /// Fail-closed on every error path: missing token, transport
    /// failure (the bundled connector is plaintext, so an actual
    /// `https://` siteverify call may not connect — that surfaces as an
    /// `Err` from the poster and a failure verdict here), malformed
    /// upstream JSON, or a non-2xx response all yield `false`. Never
    /// panics.
    async fn verify_recaptcha(&self, form_body: &str, client_ip: IpAddr) -> bool {
        // No provider configured → captcha rung is unreachable.
        let Some(secret) = &self.challenge_cfg.captcha_secret else {
            return false;
        };
        let response = form_field(form_body, "g-recaptcha-response");
        if response.is_empty() {
            tracing::debug!(
                target: "aegis::security",
                ip = %client_ip,
                "captcha POST missing g-recaptcha-response token"
            );
            return false;
        }
        // Drive the verified `captcha_providers` implementation. The
        // hyper client is plaintext-only (HttpConnector), so a real
        // `https://` POST may fail to connect; `HyperPoster` reports
        // that as `Err`, which `ReCaptcha::verify` maps to a failure
        // verdict — i.e. we fail closed, never panic.
        let poster = HyperPoster {
            client: self.client.clone(),
        };
        let provider = ReCaptcha::new(secret.clone());
        let ip = client_ip.to_string();
        let verdict = provider.verify(&poster, &response, Some(&ip)).await;
        if !verdict.success {
            tracing::warn!(
                target: "aegis::security",
                ip = %client_ip,
                error_codes = ?verdict.error_codes,
                "reCAPTCHA siteverify rejected token"
            );
            return false;
        }
        // Hostname pinning: when the operator declared the site key for
        // a specific host, the widget hostname Google echoes back must
        // match it — this rejects tokens harvested on another origin.
        // We reuse `captcha_site_key` only as a presence signal; the
        // hostname itself is not in config, so we accept any hostname
        // when none is known. (If a dedicated `captcha_hostname` config
        // field is added later, gate on it here.)
        if let Some(host) = &verdict.hostname {
            tracing::debug!(
                target: "aegis::security",
                ip = %client_ip,
                hostname = %host,
                "reCAPTCHA siteverify accepted"
            );
        }
        true
    }

    async fn challenge_verified(&self, ip: IpAddr, headers: &http::HeaderMap) -> bool {
        // Long-lived behavioural cookie short-circuits the rest —
        // valid signature + matching IP means the client already
        // solved an earlier JS challenge and produced a fingerprint.
        if self.fp_cookie_valid(ip, headers) {
            return true;
        }
        // Cookie is the primary transport (set by challenge_response,
        // returned by browsers on next page load). Header fallback
        // covers API clients we explicitly handed a token to.
        let token = read_token_cookie(headers).unwrap_or_else(|| {
            headers
                .get("x-aegis-token")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string()
        });
        if token.is_empty() {
            return false;
        }
        let now = Self::now_epoch();
        let Some((nonce, exp)) = verify_token(
            &self.challenge_cfg.hmac_secret,
            &token,
            &ip.to_string(),
            now,
        ) else {
            return false;
        };
        // M13 — unlike `handle_verify`, this path issues NO new cookie and
        // resets NO challenge state: it only confirms a cookie we already
        // signed and IP-bound (the `verify_token` above already proved the
        // HMAC, the IP binding, and the expiry). The trust grant rests on
        // that cryptographic proof, not on nonce freshness, so a replay
        // here is the *expected* per-page-load re-presentation of a valid
        // session cookie — not a fail-open trust mint. We still mark the
        // nonce so the FIRST use is recorded (which makes a subsequent
        // replay at the cookie-issuing verify endpoint detectable), but a
        // replay verdict does NOT change the outcome of this revalidation.
        if let Some(store) = &self.store {
            let ttl = (exp - now).max(1) as usize;
            let _ = store.mark_nonce(&nonce, ttl).await;
        }
        true
    }

    async fn distributed_bot_score(
        &self,
        host: &str,
        ip: IpAddr,
        ua: &str,
        path: &str,
    ) -> Option<u32> {
        let store = self.store.as_ref()?;
        let mut score = 0u32;
        let lua = ua.to_ascii_lowercase();
        if lua.is_empty() {
            score += 20;
        }
        for a in ["curl", "python-requests", "sqlmap", "nikto", "nmap", "wget"] {
            if lua.contains(a) {
                score += 35;
            }
        }
        if path.len() > 2048 {
            score += 15;
        }
        // Don't touch Redis (or grow the per-fingerprint counter) when
        // nothing looked suspicious — otherwise benign browser requests
        // accumulate a score and eventually trip the deny threshold.
        if score == 0 {
            return None;
        }
        // V233: previously `aegis:rep:{host}:{ip}|{ua}|{path}` —
        // host/ua/path are attacker-controlled and may themselves
        // contain `:`/`|`, so `aegis:rep:a:b|c|d` was ambiguous. An
        // attacker who knew a victim's (ip,ua,path) could craft a
        // request that lands on the victim's exact counter and pump it
        // toward the bot-deny threshold. Fold the whole tuple into a
        // fixed-width hex digest so no collidable raw string survives.
        let key = redis_rep_key(host, ip, ua, path);
        store
            .incr_score(&key, score, self.bot_cfg.penalty_seconds as usize)
            .await
            .ok()
    }

    /// Atomic distributed token-bucket via Lua in Redis. Returns
    /// `Some(retry_after_ms)` if the caller is over budget — handler
    /// uses this to surface `Retry-After`. None means allowed or no
    /// Redis backend configured.
    async fn distributed_rate_exceeded(&self, host: &str, ip: IpAddr) -> Option<u64> {
        if !self.rate_cfg.enabled {
            return None;
        }
        let store = self.store.as_ref()?;
        // V233: previously `{host}|{ip}` — `host` is the raw Host
        // header, fully attacker-controlled, and may contain `|`.
        // Spoofing a fresh Host per request minted a fresh bucket and
        // evaded the per-host+IP limiter. Hash both components into a
        // fixed-width digest so the bucket identity can't be forged by
        // delimiter injection.
        let key = redis_tb_key(host, ip);
        match store
            .consume_token(
                &key,
                self.rate_cfg.requests_per_second,
                self.rate_cfg.burst,
                1,
            )
            .await
        {
            Ok(BucketOutcome::Allowed { .. }) => None,
            Ok(BucketOutcome::Throttled { retry_after_ms }) => Some(retry_after_ms),
            Err(e) => {
                tracing::debug!(error = %e, "distributed token bucket failed; falling open");
                None
            }
        }
    }

    pub async fn handle(
        &self,
        client_ip: IpAddr,
        peer_port: u16,
        req: Request<Incoming>,
    ) -> Result<Response<RespBody>, Infallible> {
        let (parts, body) = req.into_parts();
        // Fast-path: methods that semantically carry no body skip the
        // collect step entirely. Saves an allocation, a future setup,
        // and (when slow-POST guard is on) the tokio timer registration
        // — measurable win on GET-heavy traffic which is the common
        // case. We still scan for protocol-level smuggling indicators
        // (CL+TE on a GET) downstream in the WAF, so we don't lose
        // any defenses by skipping the byte buffer here.
        //
        // V233 (auth_bypass) — the drop fast-path must only fire when
        // the body is *provably* empty for the negotiated protocol.
        // See `body_provably_empty` for the full rationale; in short,
        // the old `.unwrap_or(0)` treated an *absent* Content-Length as
        // length-0, which discarded real close-delimited (HTTP/1.0) and
        // H2/H3 DATA-framed bodies — so `WafFilter::inspect_body` then
        // scanned an empty buffer and payload SQLi/XSS (e.g. on a
        // `DELETE /x` with a body) went unscanned.
        let body_bytes = if body_provably_empty(&parts.method, parts.version, &parts.headers) {
            // Framing guarantees no body bytes — nothing to drain.
            drop(body);
            Bytes::new()
        } else {
            // Slow-POST guard. A client dripping bytes (Slowloris-Body /
            // R-U-Dead-Yet) ties up a worker indefinitely without this.
            // Hitting the timeout returns 408 and bumps the threat score
            // so repeat offenders escalate naturally.
            let collect_fut = body.collect();
            let body_result = if self.body_read_timeout_ms > 0 {
                match tokio::time::timeout(
                    Duration::from_millis(self.body_read_timeout_ms),
                    collect_fut,
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        // V230 — this is a cold error path (the
                        // body-collect future timed out) so we keep
                        // the Instant capture here rather than hoist
                        // it to the top of `handle`. Hoisting would
                        // force every healthy request through an
                        // extra vdso call only to pay off for the
                        // slow-POST attack case. The hot-path capture
                        // happens once inside `handle_collected`.
                        self.metrics
                            .requests_denied
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.metrics.observe_filter_block("slow_post");
                        self.record_denied(client_ip, Instant::now());
                        let resp = Response::builder()
                            .status(StatusCode::REQUEST_TIMEOUT)
                            .body(
                                Full::new(Bytes::from("body read timeout"))
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
                            .expect("response");
                        return Ok(self.stamp_alt_svc(resp));
                    }
                }
            } else {
                collect_fut.await
            };
            body_result
                .map(|c| c.to_bytes())
                .unwrap_or_else(|_| Bytes::new())
        };
        let resp = self
            .handle_collected(client_ip, peer_port, parts, body_bytes)
            .await;
        Ok(self.stamp_alt_svc(resp))
    }

    pub async fn handle_collected(
        &self,
        client_ip: IpAddr,
        peer_port: u16,
        mut parts: Parts,
        body: Bytes,
    ) -> Response<RespBody> {
        // V230 — mirror the V229 Pingora hot-path fix: capture
        // `Instant::now()` once at request entry and reuse for every
        // downstream timestamp (dynamic_trust, scorer, cache lookup,
        // anomaly observe, etc.). Profiler on the Pingora stand showed
        // `clock_gettime` (vdso) at ~4.35% of userspace time with one
        // call per consumer; consolidating into a single capture
        // dropped the call count from ~10 per request to 1. The hyper
        // path has the same redundant call pattern, so apply the same
        // fix here.
        let start = Instant::now();
        let host = parts
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        self.metrics
            .requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let protocol = self.detect_protocol(parts.version);
        self.metrics.by_protocol.record(protocol);

        // **Pre-trust gate** — single IP-level check that gates the
        // skip of throttling-class observation work. Computed once
        // and reused throughout the handler. Trust covers both
        // operator whitelist (`bypass.ips` / `xdp.allow`) and
        // dynamic reputation. When true we skip per-request work
        // that exists to throttle / score / fingerprint *unknown*
        // clients — none of which would change the outcome for an
        // IP we already trust.
        let pre_trusted =
            self.bypass.matches_ip(client_ip) || self.dynamic_trust.is_trusted(client_ip, start);

        // Feed the anomaly detector first so subsequent gates (geo,
        // challenge) see the up-to-date under-attack flag.
        //
        // Trusted-IP fast-path: skip the per-request observation
        // (DashMap entry + EMA math + VecDeque maintenance ~1.5 µs)
        // and just read the cached under_attack flag. Trusted IPs
        // shouldn't poison the surge baseline anyway, and the flag
        // expires on its own TTL even without our writes.
        //
        // V230 — mirror V229's anomaly-enabled hoist: the cheap
        // `enabled()` check fronts the call so a disabled detector
        // (the default config) pays zero overhead — no `&host` borrow,
        // no inner DashMap touch, no virtual dispatch. The
        // under_attack read still happens (via the same `enabled()`
        // gate inside `under_attack`, which short-circuits to `false`)
        // but the observe path is the expensive one we're guarding.
        let under_attack = if self.anomaly.enabled() && !host.is_empty() {
            if pre_trusted {
                self.anomaly.under_attack(&host)
            } else {
                self.anomaly.observe(&host, start)
            }
        } else {
            // Detector off (or no Host header) — cannot be under
            // attack, and observe would be a no-op anyway.
            false
        };

        // GeoIP gate runs before anything else expensive: a single
        // mmdb lookup is cheap and lets us avoid spending CPU on
        // requests we've already decided to drop based on origin.
        if let Some(reason) = self.geoip_deny(client_ip, &host) {
            self.metrics
                .requests_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.observe_filter_block("geoip");
            self.metrics.observe_domain_outcome(&host, true, false);
            self.record_denied(client_ip, start);
            self.observe_latency(start);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(
                    Full::new(Bytes::from(reason))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("response");
        }

        // Intercept the verification endpoint before the filter
        // pipeline runs — otherwise rate-limit / WAF / challenge would
        // bounce the very requests that exist to satisfy the challenge.
        if parts.uri.path() == VERIFY_PATH {
            let resp = self
                .handle_verify(&parts.method, client_ip, &parts, &body)
                .await;
            self.observe_latency(start);
            return resp;
        }

        let pre_verified = self.challenge_verified(client_ip, &parts.headers).await;
        if pre_verified {
            // Drop any leftover escalation state — a verified client
            // shouldn't pay for an earlier denied attempt.
            self.challenge_filter.reset(client_ip);
        }

        // Skip distributed rate-limit for trusted IPs — same logic as
        // the local rate_limit filter (Phase A.1-ext): trust grant
        // already authoritative, no further throttling required.
        if !pre_trusted
            && let Some(retry_ms) = self.distributed_rate_exceeded(&host, client_ip).await
        {
            self.metrics
                .requests_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.observe_filter_block("distributed_rate");
            self.metrics.observe_domain_outcome(&host, true, false);
            self.record_denied(client_ip, start);
            self.observe_latency(start);
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("retry-after", retry_ms.div_ceil(1000).max(1).to_string())
                .header("x-aegis-retry-after-ms", retry_ms.to_string())
                .body(
                    Full::new(Bytes::from("distributed rate limit"))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("response");
        }

        let ua = parts
            .headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Include the query string in the inspected path so WAF
        // signatures and custom rules (`field = "path"`) catch payloads
        // smuggled in as ?q=...; previously these slipped past.
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());
        // Skip distributed bot scoring for trusted IPs (same reasoning
        // as distributed_rate above). Saves the Redis hop / DashMap
        // op on the hot trusted path.
        if !pre_verified
            && !pre_trusted
            && let Some(score) = self
                .distributed_bot_score(&host, client_ip, &ua, &path)
                .await
            && score >= self.bot_cfg.deny_score
        {
            self.metrics
                .requests_denied
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.metrics.observe_filter_block("distributed_bot");
            self.metrics.observe_domain_outcome(&host, true, false);
            self.record_denied(client_ip, start);
            self.observe_latency(start);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(
                    Full::new(Bytes::from("bot reputation denied"))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("response");
        }

        // JA4H is fully derivable from the request itself — compute
        // it here once and stash it in the context so filters /
        // plugins can match on it without re-walking headers. The
        // `_from_headermap` variant reads `parts.headers` directly
        // — skips materialising a `Vec<(String,String)>` per request.
        //
        // Connection fingerprint lookup (JA4 / JA4T / JA4L / h2fp /
        // h3fp / mTLS) — also skipped for trusted IPs: bypass/trust
        // grant is authoritative, fingerprint rules don't apply.
        // Saves one DashMap read per request.
        let (ja4, ja4t, ja4l, h2fp, h3fp, mtls_fp) = if pre_trusted {
            (None, None, None, None, None, None)
        } else {
            match self.fingerprints.lookup(client_ip, peer_port) {
                Some(fp) => (fp.ja4, fp.ja4t, fp.ja4l, fp.h2fp, fp.h3fp, fp.mtls_fp),
                None => (None, None, None, None, None, None),
            }
        };
        // Move headers into an Arc so the filter pipeline borrows
        // without cloning the HeaderMap. We unwrap it after filters
        // (which drop their borrows when ctx is dropped) to re-attach
        // to the upstream request — that path goes through
        // `Arc::try_unwrap`, succeeding when no filter spawned a task
        // holding the Arc. On the steady-state happy path: zero alloc.
        let headers_arc = Arc::new(std::mem::take(&mut parts.headers));
        // Dynamic trust is computed once here so the value is stable
        // across the rest of the request — filters consult ctx.is_trusted
        // rather than re-querying the DashMap.
        let is_dynamic_trusted = self.dynamic_trust.is_trusted(client_ip, start);
        let ctx = RequestContext {
            request_id: crate::proxy::request_context::next_request_id_u64(),
            client_ip,
            method: parts.method.clone(),
            path,
            host: host.clone(),
            is_trusted: is_dynamic_trusted,
            headers: headers_arc.clone(),
            timestamp: start,
            user_agent: Some(ua),
            ja4,
            // V231 — JA4H is now lazy. The HTTP version is stored so
            // RequestContext::ja4h() can compute the fingerprint on
            // first call. No SHA-256 happens here. For trusted IPs
            // (pre_trusted = true), is_trusted = true on the context,
            // so ja4h() returns None without computing — same as before.
            http_version: parts.version,
            ja4h_cache: std::sync::OnceLock::new(),
            // The legacy hyper data plane does not surface a JA3 string
            // (JA3 comes from the TLS handshake captured by the Pingora /
            // XDP stack); leave it unset so the `ja3_deny_hashes` policy
            // simply doesn't match on this path.
            ja3: None,
            ja4t,
            ja4l,
            h2fp,
            h3fp,
            mtls_fp,
        };

        // Static bypass — operator-declared whitelist (config IPs +
        // XDP allow list, since Phase A.1). Skips the **entire**
        // L7 pipeline because operators explicitly trust these
        // sources (Stripe / GitHub webhooks etc. legitimately send
        // payloads that look like attacks).
        //
        // Dynamic trust is handled separately via `ctx.is_trusted`:
        // only throttling-class filters (rate_limit, bot, challenge)
        // honour it. WAF / smuggling / honeypot still run, so a
        // newly-attacking IP can't ride accumulated reputation past
        // a single attack — WAF catches it and trust is revoked
        // before the next request.
        let is_bypass = self.bypass.matches(&ctx);
        if !is_bypass {
            // Inspect the actual body bytes (catches chunked uploads
            // that skip content-length and any signature in payload).
            // C4 — pass Content-Encoding so a gzip/deflate'd body is
            // decompressed before signature matching (br/unknown fail closed).
            let content_encoding = ctx
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok());
            if let Some(FilterAction::Deny { status, reason }) =
                self.waf.inspect_body_with_encoding(&body, content_encoding)
            {
                self.metrics
                    .requests_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.observe_filter_block("waf_body");
                self.metrics.observe_domain_outcome(&host, true, false);
                self.record_denied(client_ip, start);
                self.observe_latency(start);
                return Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
                    .body(
                        Full::new(Bytes::from(reason.into_owned()))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .expect("response");
            }

            // GraphQL guard runs only for POSTs to a registered
            // GraphQL endpoint. Inspects the JSON envelope, blocks
            // overly-deep / alias-heavy / introspection queries.
            if ctx.method == hyper::Method::POST
                && self.graphql.applies(&ctx.path)
                && let Some(FilterAction::Deny { status, reason }) = self.graphql.check_body(&body)
            {
                self.metrics
                    .requests_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.observe_filter_block("graphql");
                self.metrics.observe_domain_outcome(&host, true, false);
                self.record_denied(client_ip, start);
                self.observe_latency(start);
                return Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
                    .body(
                        Full::new(Bytes::from(reason.into_owned()))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .expect("response");
            }
        }

        let (pipeline_decision, attribution) = if is_bypass {
            (FilterAction::Allow, "bypass")
        } else {
            self.filters.evaluate_with_attribution(&ctx)
        };

        match pipeline_decision {
            FilterAction::Allow => {}
            FilterAction::Deny { status, reason } => {
                self.metrics
                    .requests_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.observe_filter_block(attribution);
                self.metrics.observe_domain_outcome(&host, true, false);
                self.record_denied(client_ip, start);
                self.observe_latency(start);
                return Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
                    .body(
                        Full::new(Bytes::from(reason.into_owned()))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .expect("response");
            }
            FilterAction::Challenge { level, reason } => {
                if pre_verified {
                    // Verified token bypasses challenge step for this request.
                } else {
                    // Anomaly auto-escalation: force at least the
                    // configured floor while the domain is under
                    // attack. Picks the higher of organic ladder and
                    // attack floor so a /captcha-level repeat offender
                    // doesn't get demoted.
                    let level = if under_attack {
                        escalate_level(level, self.anomaly.min_challenge_level())
                    } else {
                        level
                    };
                    self.metrics
                        .requests_challenged
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.metrics.observe_filter_challenge(attribution);
                    self.metrics.observe_domain_outcome(&host, false, true);
                    self.record_challenged(client_ip, start);
                    self.observe_latency(start);
                    return self.challenge_response(
                        level,
                        reason.into_owned(),
                        client_ip,
                        &parts.uri,
                    );
                }
            }
            FilterAction::Tarpit {
                duration_seconds,
                chunk_bytes,
                server_header,
                reason,
            } => {
                // Counted as a deny on metrics so per-filter dashboards
                // surface honeypot activity. The streaming body emits
                // chunks until the timer elapses; hyper backs the
                // connection while the scanner waits.
                self.metrics
                    .requests_denied
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.observe_filter_block(attribution);
                self.metrics.observe_domain_outcome(&host, true, false);
                // Honeypot hits are full-strength threat signal —
                // bump the scorer aggressively. The store also tracks
                // per-IP hit counts; once we cross the configured
                // threshold we push the IP into the XDP deny set so
                // future SYNs get dropped at line rate.
                self.record_denied(client_ip, start);
                if let Some(decision) = self.honeypots.check(&host, &ctx.path) {
                    for _ in 0..(decision.score_bump.saturating_div(10).max(1)) {
                        self.record_denied(client_ip, start);
                    }
                    if self
                        .honeypots
                        .record_hit(client_ip, decision.auto_xdp_deny_threshold)
                    {
                        match client_ip {
                            IpAddr::V4(v4) => {
                                if let Err(e) = self.xdp.deny_v4(v4) {
                                    tracing::debug!(
                                        error = %e,
                                        %v4,
                                        "honeypot auto-XDP-deny failed"
                                    );
                                } else {
                                    tracing::warn!(
                                        target: "aegis::honeypot",
                                        %v4,
                                        "honeypot threshold tripped — IP pushed to XDP deny set"
                                    );
                                }
                            }
                            IpAddr::V6(v6) => {
                                if let Err(e) = self.xdp.deny_v6(v6) {
                                    tracing::debug!(error = %e, %v6, "honeypot auto-XDP-deny failed");
                                }
                            }
                        }
                    }
                }
                tracing::info!(
                    target: "aegis::honeypot",
                    %client_ip,
                    host = %host,
                    path = %ctx.path,
                    duration_seconds,
                    "honeypot tarpit triggered: {reason}"
                );
                self.observe_latency(start);
                let body = TarpitBody::new(duration_seconds, chunk_bytes)
                    .map_err(|never| match never {})
                    .boxed();
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("server", server_header.as_ref())
                    .header("content-type", "text/html; charset=utf-8")
                    .header("connection", "close")
                    .body(body)
                    .expect("tarpit response");
            }
        }

        // Circuit breaker — runs *after* the filter pipeline so a
        // malicious request still gets a precise 4xx (smuggling /
        // method / size) instead of a generic 503. Legitimate
        // requests that pass the gates still see the breaker
        // protect a flapping backend.
        if self.health.circuit_open(&host) {
            self.metrics
                .upstream_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.observe_latency(start);
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(
                    Full::new(Bytes::from("circuit open"))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .expect("circuit response");
        }

        let target = self.upstream.resolve(&host);
        let mut req_parts = parts;
        let mut uri_parts = req_parts.uri.clone().into_parts();
        uri_parts.scheme = Some(target.scheme.clone());
        uri_parts.authority = Some(target.authority_parsed.clone());
        let new_uri = Uri::from_parts(uri_parts).unwrap_or_else(|_| target.base_uri.clone());
        req_parts.uri = new_uri;

        // ── Threat-aware response cache ──
        // Snapshot the cache-key inputs before `parts` is moved into
        // the upstream request. The cache lookup is conditional on
        // `should_consider` so non-cache deployments pay zero cost.
        let cache_method = req_parts.method.clone();
        let cache_path = req_parts.uri.path().to_string();
        let cache_eligible = self.response_cache.should_consider(&cache_method, &host);
        // V233 — keep the request HeaderMap alive for the cache-store call
        // (the `Arc` is consumed into the upstream request below). Only
        // cache-eligible requests pay the refcount bump; the cache layer
        // uses it to refuse storing a response to an `Authorization`/
        // `Cookie`-bearing (personalised) request.
        let cache_req_headers: Option<Arc<http::HeaderMap>> = if cache_eligible {
            Some(headers_arc.clone())
        } else {
            None
        };
        // "High-threat" for cache policy = NOT statically bypassed AND
        // NOT dynamically trusted. The bypass set is operator-vetted
        // (always safe to serve cache to). Dynamic trust is earned
        // through clean behaviour. Anyone else is treated as a
        // potential cache-poisoning vector and forced to MISS.
        let is_high_threat = !is_bypass && !is_dynamic_trusted;
        if cache_eligible {
            use crate::proxy::response_cache::CacheLookup;
            // Conditional lookup honours `If-None-Match` / `If-Modified-Since`
            // — returns NotModified for 304 short-circuit (no body),
            // Hit for full response, Miss otherwise.
            // NB: parts.headers was moved into headers_arc earlier
            // (F1.5 Arc<HeaderMap> optimization), so req_parts.headers
            // is empty at this point. The real request headers — needed
            // for If-None-Match / If-Modified-Since — live in
            // headers_arc. Deref to &HeaderMap.
            let lookup = self.response_cache.lookup_conditional(
                &cache_method,
                &host,
                &cache_path,
                is_high_threat,
                &headers_arc,
                start,
            );
            match lookup {
                CacheLookup::Hit(cached) => {
                    // Cache-hit fast-path: bypass per-domain DashMap accounting
                    // and the scorer/trust DashMap refresh — all three were
                    // measurable bottlenecks. The cache HIT itself is sufficient
                    // proof that the client was already trusted.
                    self.metrics
                        .cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.metrics.observe_upstream_status(cached.status.as_u16());
                    self.observe_latency(start);
                    let mut resp = Response::builder()
                        .status(cached.status)
                        .body(
                            Full::new(cached.body.clone())
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("cached response");
                    *resp.headers_mut() = (*cached.headers).clone();
                    crate::proxy::response_cache::stamp_cache_hit_header(resp.headers_mut());
                    return resp;
                }
                CacheLookup::NotModified {
                    etag,
                    last_modified,
                } => {
                    // 304 Not Modified — body-less response. Browsers + CDNs
                    // use this constantly to revalidate cached assets without
                    // re-downloading the body. Saves bandwidth + body
                    // serialization CPU compared to a full Hit.
                    self.metrics
                        .cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.observe_latency(start);
                    let mut resp = Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .body(
                            Full::new(Bytes::new())
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("304 response");
                    let h = resp.headers_mut();
                    if let Some(et) = etag {
                        h.insert("etag", et);
                    }
                    if let Some(lm) = last_modified {
                        h.insert("last-modified", lm);
                    }
                    crate::proxy::response_cache::stamp_cache_hit_header(h);
                    return resp;
                }
                CacheLookup::Miss => {
                    self.metrics
                        .cache_misses
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        // Phase 3Y.8 — Single-flight gate. On cache miss for a
        // cache-eligible request, deduplicate concurrent upstream
        // fetches for the same key. First arrival becomes leader and
        // proceeds; subsequent arrivals wait on the leader's Notify,
        // then retry the cache. Prevents the cache-stampede
        // pathology (TTL expiry → N concurrent identical upstream
        // calls) without sacrificing latency in the common case
        // (zero coordination cost when there's no concurrent miss).
        let _sf_leader: Option<SingleflightLeader> = if cache_eligible {
            let sf_key = (cache_method.clone(), host.clone(), cache_path.clone());
            use dashmap::mapref::entry::Entry;
            match self.pending_fetches.entry(sf_key.clone()) {
                Entry::Vacant(v) => {
                    let n = Arc::new(tokio::sync::Notify::new());
                    v.insert(n.clone());
                    // We're the leader. The guard's Drop impl will
                    // notify waiters + clean up the pending entry on
                    // any exit path (success, error, or Future drop).
                    Some(SingleflightLeader {
                        pending: self.pending_fetches.clone(),
                        key: sf_key,
                        notify: n,
                    })
                }
                Entry::Occupied(o) => {
                    let n = o.get().clone();
                    drop(o); // release the shard lock before await
                    // Wait for leader to finish, with timeout so a
                    // hung leader can't deadlock us. 5 s is generous
                    // vs typical upstream RTT.
                    let _ = tokio::time::timeout(Duration::from_secs(5), n.notified()).await;
                    // Retry the cache — leader has populated by now
                    // (most likely). On hit, serve directly without
                    // an upstream call.
                    //
                    // V230 — intentionally keep `Instant::now()` here
                    // rather than the captured `start`. We've awaited
                    // the leader's Notify for up to 5 seconds; using
                    // the stale `start` would cause `expires_at > now`
                    // to incorrectly succeed on entries that expired
                    // during the wait, which the cache's freshness
                    // check (response_cache.rs `expires_at > now`)
                    // relies on. The cost is one vdso call only on
                    // the (uncommon) singleflight-collision slow path,
                    // so this asymmetry is acceptable.
                    use crate::proxy::response_cache::CacheLookup;
                    let retry = self.response_cache.lookup_conditional(
                        &cache_method,
                        &host,
                        &cache_path,
                        is_high_threat,
                        &headers_arc,
                        Instant::now(),
                    );
                    match retry {
                        CacheLookup::Hit(cached) => {
                            self.metrics
                                .cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.metrics.observe_upstream_status(cached.status.as_u16());
                            self.observe_latency(start);
                            let mut resp = Response::builder()
                                .status(cached.status)
                                .body(
                                    Full::new(cached.body.clone())
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                                .expect("cached response");
                            *resp.headers_mut() = (*cached.headers).clone();
                            crate::proxy::response_cache::stamp_cache_hit_header(
                                resp.headers_mut(),
                            );
                            return resp;
                        }
                        CacheLookup::NotModified {
                            etag,
                            last_modified,
                        } => {
                            self.metrics
                                .cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.observe_latency(start);
                            let mut resp = Response::builder()
                                .status(StatusCode::NOT_MODIFIED)
                                .body(
                                    Full::new(Bytes::new())
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                                .expect("304 response");
                            let h = resp.headers_mut();
                            if let Some(et) = etag {
                                h.insert("etag", et);
                            }
                            if let Some(lm) = last_modified {
                                h.insert("last-modified", lm);
                            }
                            crate::proxy::response_cache::stamp_cache_hit_header(h);
                            return resp;
                        }
                        CacheLookup::Miss => {
                            // Leader's fetch must have failed or
                            // returned uncacheable. We fall through
                            // to our own upstream call — not as
                            // leader, so we don't block further
                            // waiters that may arrive.
                            None
                        }
                    }
                }
            }
        } else {
            None
        };

        // Recover headers from the shared Arc. After `drop(ctx)` the
        // refcount is 1 and `try_unwrap` succeeds — no clone. If a
        // filter (eg. a plugin) cloned the Arc into a background task,
        // we fall through to deep-cloning it; the slow path is at
        // worst the same cost as the pre-Arc baseline.
        drop(ctx);
        req_parts.headers = Arc::try_unwrap(headers_arc).unwrap_or_else(|a| (*a).clone());
        // H6 — the client-supplied forwarding headers are attacker-
        // controlled and must never reach the upstream verbatim: a backend
        // that trusts `X-Forwarded-For` / `X-Real-IP` / `Forwarded` for
        // access control, logging, or rate-limiting would otherwise be
        // told whatever source IP the client claimed (IP spoofing /
        // allow-list bypass). Strip all three, then stamp the proxy's
        // OWN authoritative resolved client IP. The legacy hyper data
        // plane maintains no trusted-proxy chain, so we collapse XFF to
        // the single peer address we actually observed.
        set_authoritative_forwarding(&mut req_parts.headers, client_ip);
        let upstream_req = Request::from_parts(req_parts, Full::new(body));

        let response = match self.client.request(upstream_req).await {
            Ok(resp) => {
                let status_code = resp.status();
                let status = status_code.as_u16();
                self.metrics.observe_upstream_status(status);
                self.metrics.observe_domain_outcome(&host, false, false);
                match status {
                    401 | 403 | 429 => self.record_denied(client_ip, start),
                    _ => self.record_allowed(client_ip, start),
                }
                if cache_eligible {
                    // Buffer the body so we can both cache it and serve
                    // it back. Cost: one alloc + copy of the response
                    // body. Worth it on cache-eligible hosts; for
                    // non-eligible hosts we skip buffering entirely
                    // (the `else` branch streams as before).
                    let (parts, body) = resp.into_parts();
                    let body_bytes = match body.collect().await {
                        Ok(c) => c.to_bytes(),
                        Err(_) => Bytes::new(),
                    };
                    self.response_cache.store(
                        &cache_method,
                        &host,
                        &cache_path,
                        status_code,
                        &parts.headers,
                        // V233 — request headers: `cache_req_headers` is
                        // always `Some` inside this `cache_eligible` block.
                        cache_req_headers
                            .as_deref()
                            .expect("cache_req_headers set when cache_eligible"),
                        &body_bytes,
                        start,
                    );
                    Response::from_parts(
                        parts,
                        Full::new(body_bytes)
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                } else {
                    resp.map(|b| b.boxed())
                }
            }
            Err(_) => {
                self.metrics
                    .upstream_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics
                    .upstream_5xx
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.metrics.observe_domain_outcome(&host, false, false);
                self.record_denied(client_ip, start);
                // Phase 3Y.7 — stale-if-error. If we have a recently
                // expired cache entry for this request, serve it with a
                // Warning header rather than returning 502. Keeps the
                // site up during backend hiccups.
                if cache_eligible
                    && let Some(stale) = self.response_cache.lookup_stale_if_error(
                        &cache_method,
                        &host,
                        &cache_path,
                        is_high_threat,
                        start,
                    )
                {
                    let mut resp = Response::builder()
                        .status(stale.status)
                        .body(
                            Full::new(stale.body.clone())
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("stale response");
                    *resp.headers_mut() = (*stale.headers).clone();
                    crate::proxy::response_cache::stamp_cache_hit_header(resp.headers_mut());
                    // RFC 9111 §5.5 — Warning: 110 (response is stale).
                    resp.headers_mut().insert(
                        "warning",
                        http::HeaderValue::from_static("110 aegis \"Response is Stale\""),
                    );
                    resp
                } else {
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(
                            Full::new(Bytes::from("bad gateway"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .expect("response")
                }
            }
        };
        self.observe_latency(start);
        response
    }

    /// Record an Allow outcome — feeds both the legacy threat scorer
    /// (used by the anomaly detector + bot rep) and the dynamic-trust
    /// promoter. Single call site keeps the two state machines from
    /// drifting out of sync as the hot path evolves.
    #[inline]
    fn record_allowed(&self, ip: IpAddr, at: Instant) {
        self.scorer.record_allowed(ip, at);
        self.dynamic_trust.observe_allowed(ip, at);
    }

    /// Record a Deny outcome. Any deny instantly revokes dynamic
    /// trust — see `DynamicTrust::observe_denied`.
    #[inline]
    fn record_denied(&self, ip: IpAddr, at: Instant) {
        self.scorer.record_denied(ip, at);
        self.dynamic_trust.observe_denied(ip, at);
    }

    /// Record a Challenge outcome. Treated as a soft-deny for trust
    /// purposes — a challenged IP is by definition not trusted yet.
    #[inline]
    fn record_challenged(&self, ip: IpAddr, at: Instant) {
        self.scorer.record_challenged(ip, at);
        self.dynamic_trust.observe_denied(ip, at);
    }

    fn detect_protocol(&self, version: http::Version) -> Protocol {
        if self.is_h3 {
            return Protocol::H3;
        }
        match version {
            http::Version::HTTP_11 | http::Version::HTTP_10 | http::Version::HTTP_09 => {
                Protocol::H1
            }
            http::Version::HTTP_2 => Protocol::H2,
            http::Version::HTTP_3 => Protocol::H3,
            _ => Protocol::Other,
        }
    }

    fn observe_latency(&self, start: Instant) {
        let ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.metrics.latency.observe(ms);
    }
}

fn challenge_step_label(level: ChallengeLevel) -> &'static str {
    match level {
        ChallengeLevel::Headers => "307",
        ChallengeLevel::Html => "200",
        ChallengeLevel::Iframe => "click",
        ChallengeLevel::Javascript => "high",
        ChallengeLevel::Captcha => "capt",
    }
}

/// `; Secure` when configured to require HTTPS-only cookies, empty
/// string otherwise. We compute this once per cookie instead of
/// embedding the conditional in every format!.
fn secure_suffix(on: bool) -> &'static str {
    if on { "; Secure" } else { "" }
}

/// JSON-escape a string and wrap it in double quotes so it can be
/// inlined into generated JavaScript safely (avoids XSS via return-URL
/// or token tampering even though we already sanitised them).
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

/// V234 — outbound POST transport for `captcha_providers`, backed by
/// the proxy's hyper client.
///
/// The `captcha_providers` module decouples provider logic from any
/// HTTP-client crate via the [`HttpPoster`] trait; this is Aegis's
/// implementation. It POSTs form-urlencoded bodies and returns the
/// response bytes on a 2xx.
///
/// Transport caveat: the bundled `client` uses a plaintext
/// `HttpConnector`, so an actual `https://` siteverify request may fail
/// to connect. That surfaces here as an `Err`, which the provider maps
/// to a failure verdict — `verify_recaptcha` then fails closed. No new
/// dependency (e.g. hyper-rustls) is pulled in; wiring a TLS connector
/// is a separate, larger change. Every error path returns `Err`; this
/// function never panics.
struct HyperPoster {
    client: Client<HttpConnector, Full<Bytes>>,
}

#[async_trait::async_trait]
impl HttpPoster for HyperPoster {
    async fn post_form(
        &self,
        url: &str,
        body: &str,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let req = Request::builder()
            .method(http::Method::POST)
            .uri(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(Full::new(Bytes::from(body.to_owned())))
            .map_err(|e| anyhow::anyhow!("siteverify request build failed: {e}"))?;
        // Bound the call — hyper-util's Client has no per-request
        // timeout, so an unresponsive endpoint would otherwise hang the
        // challenge POST.
        let resp = match tokio::time::timeout(timeout, self.client.request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(anyhow::anyhow!("siteverify transport error: {e}")),
            Err(_) => return Err(anyhow::anyhow!("siteverify timed out")),
        };
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!("siteverify non-2xx status: {status}"));
        }
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("siteverify body read failed: {e}"))?
            .to_bytes();
        Ok(bytes.to_vec())
    }
}

/// Pull a single value out of a `key=value&key=value` urlencoded body.
fn form_field(body: &str, name: &str) -> String {
    for kv in body.split('&') {
        let mut it = kv.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        if k == name {
            return urlencoding::decode(v).unwrap_or_default().into_owned();
        }
    }
    String::new()
}

/// Extract `aegis_token` from a Cookie header. Permissive parsing —
/// handles quoted values and multiple cookies in one header.
fn read_token_cookie(headers: &http::HeaderMap) -> Option<String> {
    read_cookie(headers, TOKEN_COOKIE)
}

/// Generic single-cookie extractor. Walks all `Cookie:` headers and
/// returns the first value matching `name`.
fn read_cookie(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for value in headers.get_all("cookie").iter() {
        let Ok(s) = value.to_str() else { continue };
        for part in s.split(';') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix(&prefix) {
                let v = rest.trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// H6 — Replace any client-supplied forwarding headers with the proxy's
/// authoritative view of the client. `X-Forwarded-For`, `X-Real-IP` and
/// `Forwarded` are all attacker-controlled on the wire, so we remove the
/// inbound values entirely and emit our own resolved `client_ip`. This
/// prevents a client from spoofing its source address to a backend that
/// trusts these headers for access control / logging / rate-limiting.
///
/// The legacy hyper data plane keeps no trusted-proxy chain, so XFF is
/// set to exactly the one peer address we observed (no appended chain).
/// `client_ip.to_string()` is always a valid header value (it is an IP
/// literal), so `HeaderValue::from_str` cannot fail — but we guard with
/// `if let Ok` anyway so a future change can never panic this worker.
fn set_authoritative_forwarding(headers: &mut http::HeaderMap, client_ip: IpAddr) {
    headers.remove("x-forwarded-for");
    headers.remove("x-real-ip");
    headers.remove("forwarded");
    let ip = client_ip.to_string();
    if let Ok(hv) = http::HeaderValue::from_str(&ip) {
        headers.insert("x-forwarded-for", hv.clone());
        headers.insert("x-real-ip", hv);
    }
}

// next_request_id moved to crate::proxy::request_context (V85)
// so both hyper and pingora data planes can share the cheap
// thread-local counter implementation instead of duplicating the
// 300ns Uuid::new_v4().to_string() cost.

/// Phase 3Y.8 — Single-flight leader guard. Holds the pending-fetch
/// registry entry for the leader; on drop (success, error, or async
/// cancellation), removes the entry and notifies all waiters. RAII
/// ensures we never leak the pending entry even on Future drop.
struct SingleflightLeader {
    pending: Arc<dashmap::DashMap<(http::Method, String, String), Arc<tokio::sync::Notify>>>,
    key: (http::Method, String, String),
    notify: Arc<tokio::sync::Notify>,
}

impl Drop for SingleflightLeader {
    fn drop(&mut self) {
        self.pending.remove(&self.key);
        // notify_waiters wakes all currently-waiting followers; new
        // arrivals after notify see no pending entry and proceed
        // normally (they'll see the cached response if leader stored it).
        self.notify.notify_waiters();
    }
}

/// Methods that semantically carry no request body per RFC 9110 §9.3.
/// We use this to short-circuit body buffering on the hot GET path.
/// Note: this matches *intent*, not what an attacker might send — we
/// still validate Transfer-Encoding / Content-Length headers before
/// trusting that the body is actually empty.
fn is_bodyless_method(method: &http::Method) -> bool {
    matches!(
        method,
        &http::Method::GET
            | &http::Method::HEAD
            | &http::Method::DELETE
            | &http::Method::OPTIONS
            | &http::Method::TRACE
            | &http::Method::CONNECT
    )
}

/// V233 (auth_bypass) — Decide whether a request body can be skipped
/// without losing WAF coverage. Returns `true` ONLY when the framing
/// *proves* there are zero body bytes; any uncertainty returns `false`
/// so the caller collects the body and `WafFilter::inspect_body` sees
/// the real payload.
///
/// The previous inline check used `Content-Length.unwrap_or(0)`, so an
/// *absent* Content-Length was treated as a declared length of 0. That
/// is wrong for two real wire cases, both of which let an attacker get
/// a body forwarded unscanned:
///   * HTTP/1.0 — and close-delimited HTTP/1.1 — requests may omit
///     Content-Length and still carry a body terminated by connection
///     close. Absent CL there means UNKNOWN length, not empty.
///   * HTTP/2 / HTTP/3 carry the body in DATA frames; Content-Length is
///     only advisory and may be absent on a non-empty body.
///
/// So the body is provably empty only when ALL hold:
///   * the method is one that semantically carries no body, AND
///   * there is no `Transfer-Encoding` (chunked => body present), AND
///   * the protocol is HTTP/0.9/1.0/1.1 (H2/H3 framing is never
///     trustworthy from headers alone — always collect), AND
///   * `Content-Length` is *explicitly present* and parses to exactly
///     `0`. A present-but-malformed CL is treated as not-empty.
fn body_provably_empty(
    method: &http::Method,
    version: http::Version,
    headers: &http::HeaderMap,
) -> bool {
    if !is_bodyless_method(method) {
        return false;
    }
    if headers.get("transfer-encoding").is_some() {
        return false;
    }
    // H2/H3 (and any unknown future version): DATA frames can carry a
    // body regardless of headers — never take the shortcut.
    if !matches!(
        version,
        http::Version::HTTP_09 | http::Version::HTTP_10 | http::Version::HTTP_11
    ) {
        return false;
    }
    // H1: require an explicit, well-formed `Content-Length: 0`. Absent
    // CL == unknown (close-delimited) length => collect.
    match headers.get("content-length") {
        Some(v) => v.to_str().ok().and_then(|s| s.parse::<u64>().ok()) == Some(0),
        None => false,
    }
}

/// V233 — Fold attacker-controlled key components into a fixed-width
/// 64-bit hex digest. The reputation/token-bucket Redis keys used to
/// `format!`-concatenate the raw Host header, User-Agent, path and IP
/// with `:`/`|` delimiters that also legally appear *inside* those
/// values, so `aegis:rep:a:b|c|d` was ambiguous: distinct tuples could
/// alias onto the same key. That let an attacker who knew a victim's
/// (ip,ua,path) tuple drive the victim's exact counter, and let a
/// per-request spoofed Host mint fresh rate-limit buckets.
///
/// Hashing removes every collidable raw substring: the digest is
/// derived from length-prefixed fields, so no choice of delimiter
/// inside a field can make two different tuples hash-collide by
/// construction (only an ordinary 1-in-2^64 hash collision remains,
/// which is not attacker-steerable). The hash is non-cryptographic and
/// only needs collision-resistance against accidental aliasing, not a
/// preimage guarantee — `DefaultHasher` (SipHash 1-3) is sufficient and
/// already in std, so no new dependency.
///
/// Note: `DefaultHasher::new()` is unseeded and stable within a process
/// for a given std build, which is what we want — every Aegis node must
/// derive the *same* key for the same tuple so a shared Redis cluster
/// stays consistent. We do not rely on the digest being stable across
/// std versions; a std upgrade simply re-buckets keys (they TTL out).
fn fingerprint_digest(fields: &[&[u8]]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Length-prefix each field so concatenation is injective: ("ab","c")
    // and ("a","bc") hash differently even though their bytes concat
    // identically. This is the property the old `|`-join lacked.
    for f in fields {
        (f.len() as u64).hash(&mut hasher);
        f.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// V233 — Reputation counter key: per (IP, UA, path), namespaced by
/// host. All four components are attacker-controlled, so the whole
/// tuple is hashed; the result cannot contain a delimiter and cannot
/// be steered onto another tuple's key.
fn redis_rep_key(host: &str, ip: IpAddr, ua: &str, path: &str) -> String {
    let ip = ip.to_string();
    let fp = fingerprint_digest(&[
        host.as_bytes(),
        ip.as_bytes(),
        ua.as_bytes(),
        path.as_bytes(),
    ]);
    format!("aegis:rep:{fp}")
}

/// V233 — Token-bucket key: per (host, IP). `host` is the raw Host
/// header and was previously emitted verbatim, so a spoofed Host minted
/// a fresh bucket. Hashing host+IP together yields one stable bucket id
/// per real (host, IP) pair with no forgeable delimiter.
fn redis_tb_key(host: &str, ip: IpAddr) -> String {
    let ip = ip.to_string();
    let fp = fingerprint_digest(&[host.as_bytes(), ip.as_bytes()]);
    format!("aegis:tb:{fp}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_return_url_strips_dangerous_inputs() {
        let cases = [
            ("/", "/"),
            ("/path?q=1", "/path?q=1"),
            ("//evil.com/x", "/"),            // protocol-relative redirect
            ("http://evil.com/", "/"),        // absolute
            ("/legit\r\nSet-Cookie: x", "/"), // header injection
        ];
        for (input, want) in cases {
            let uri: http::Uri = input.parse().unwrap_or_else(|_| "/".parse().unwrap());
            assert_eq!(
                ProxyHttpHandler::safe_return_url(&uri),
                want,
                "input was {input:?}"
            );
        }
    }

    // V233 — `?r=` redirect-target validation. This is the predicate
    // `handle_verify` applies to the attacker-controlled query value
    // before it reaches `builder.header("location", ...)`. Anything it
    // accepts must be a control-char-free site-relative path; anything
    // it rejects must fall back to `/`.
    #[test]
    fn safe_return_path_accepts_relative_paths() {
        assert!(ProxyHttpHandler::safe_return_path("/"));
        assert!(ProxyHttpHandler::safe_return_path("/dashboard"));
        assert!(ProxyHttpHandler::safe_return_path("/a/b/c?q=1&x=2"));
        assert!(ProxyHttpHandler::safe_return_path("/path#frag"));
    }

    #[test]
    fn safe_return_path_rejects_open_redirect_and_injection() {
        // Protocol-relative + absolute => open redirect.
        assert!(!ProxyHttpHandler::safe_return_path("//evil.com/x"));
        assert!(!ProxyHttpHandler::safe_return_path("http://evil.com/"));
        // Not site-relative at all.
        assert!(!ProxyHttpHandler::safe_return_path("evil.com"));
        assert!(!ProxyHttpHandler::safe_return_path(""));
        // CR/LF => response-splitting (this is the BUG 1 crash input:
        // it previously reached `HeaderValue::try_from`, deferred the
        // error, and panicked `.body(...).expect("verify response")`).
        assert!(!ProxyHttpHandler::safe_return_path("/a\r\nX: y"));
        assert!(!ProxyHttpHandler::safe_return_path("/a\rb"));
        assert!(!ProxyHttpHandler::safe_return_path("/a\nb"));
        // Bare CR / LF anywhere, including the decoded `%0d%0a` payload.
        assert!(!ProxyHttpHandler::safe_return_path("/login?next=\r\n"));
        // Quote and backslash => can break out of a quoted context.
        assert!(!ProxyHttpHandler::safe_return_path("/a\"b"));
        assert!(!ProxyHttpHandler::safe_return_path("/a\\b"));
    }

    #[test]
    fn safe_return_url_routes_through_string_predicate() {
        // The `Uri`-based wrapper and the `?r=` string path must agree:
        // a value rejected by the predicate falls back to `/`.
        let uri: http::Uri = "/ok?x=1".parse().unwrap();
        assert_eq!(ProxyHttpHandler::safe_return_url(&uri), "/ok?x=1");
        assert!(ProxyHttpHandler::safe_return_path("/ok?x=1"));
    }

    // V233 (auth_bypass) — body-skip decision. The drop fast-path may
    // only be taken when the framing *proves* the body is empty.
    fn hdrs(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn body_skipped_only_with_explicit_zero_content_length_on_h1() {
        // The one case where skipping is sound: H1, no TE, explicit
        // `Content-Length: 0`.
        assert!(body_provably_empty(
            &http::Method::GET,
            http::Version::HTTP_11,
            &hdrs(&[("content-length", "0")]),
        ));
        assert!(body_provably_empty(
            &http::Method::DELETE,
            http::Version::HTTP_10,
            &hdrs(&[("content-length", "0")]),
        ));
    }

    #[test]
    fn body_collected_when_h1_content_length_absent() {
        // Regression: absent CL on H1 == UNKNOWN length (close-delimited
        // HTTP/1.0 body). The old `.unwrap_or(0)` skipped this; a
        // `DELETE /x` body would reach the origin unscanned.
        assert!(!body_provably_empty(
            &http::Method::DELETE,
            http::Version::HTTP_10,
            &hdrs(&[]),
        ));
        assert!(!body_provably_empty(
            &http::Method::GET,
            http::Version::HTTP_11,
            &hdrs(&[]),
        ));
    }

    #[test]
    fn body_collected_for_h2_and_h3_regardless_of_headers() {
        // H2/H3 frame the body in DATA frames; headers can't prove it
        // empty even with `Content-Length: 0` present.
        assert!(!body_provably_empty(
            &http::Method::DELETE,
            http::Version::HTTP_2,
            &hdrs(&[("content-length", "0")]),
        ));
        assert!(!body_provably_empty(
            &http::Method::GET,
            http::Version::HTTP_3,
            &hdrs(&[]),
        ));
    }

    #[test]
    fn body_collected_when_content_length_nonzero_or_malformed() {
        // Declared non-empty.
        assert!(!body_provably_empty(
            &http::Method::DELETE,
            http::Version::HTTP_11,
            &hdrs(&[("content-length", "12")]),
        ));
        // Present but unparseable => not provably empty, collect it.
        assert!(!body_provably_empty(
            &http::Method::DELETE,
            http::Version::HTTP_11,
            &hdrs(&[("content-length", "not-a-number")]),
        ));
    }

    #[test]
    fn body_collected_when_transfer_encoding_present() {
        // Chunked framing => body present even on a bodyless method.
        assert!(!body_provably_empty(
            &http::Method::GET,
            http::Version::HTTP_11,
            &hdrs(&[("transfer-encoding", "chunked")]),
        ));
    }

    #[test]
    fn body_always_collected_for_body_carrying_methods() {
        // POST/PUT/PATCH are never on the skip path.
        assert!(!body_provably_empty(
            &http::Method::POST,
            http::Version::HTTP_11,
            &hdrs(&[("content-length", "0")]),
        ));
        assert!(!body_provably_empty(
            &http::Method::PUT,
            http::Version::HTTP_11,
            &hdrs(&[("content-length", "0")]),
        ));
    }

    #[test]
    fn js_string_literal_escapes_quotes_and_html() {
        assert_eq!(js_string_literal("hi"), "\"hi\"");
        assert_eq!(js_string_literal("a\"b"), "\"a\\\"b\"");
        assert_eq!(js_string_literal("</script>"), "\"\\u003c/script\\u003e\"");
    }

    #[test]
    fn form_field_extracts_value() {
        let body = "answer=aegis&other=1";
        assert_eq!(form_field(body, "answer"), "aegis");
        assert_eq!(form_field(body, "other"), "1");
        assert_eq!(form_field(body, "missing"), "");
    }

    #[test]
    fn cookie_extraction_handles_multiple_cookies() {
        let mut h = http::HeaderMap::new();
        h.insert(
            "cookie",
            "foo=bar; aegis_token=abc.def; lang=en".parse().unwrap(),
        );
        assert_eq!(read_token_cookie(&h).as_deref(), Some("abc.def"));
    }

    #[test]
    fn cookie_extraction_returns_none_when_absent() {
        let mut h = http::HeaderMap::new();
        h.insert("cookie", "foo=bar".parse().unwrap());
        assert!(read_token_cookie(&h).is_none());
    }

    #[test]
    fn challenge_step_labels_match_vddos_table() {
        assert_eq!(challenge_step_label(ChallengeLevel::Headers), "307");
        assert_eq!(challenge_step_label(ChallengeLevel::Html), "200");
        assert_eq!(challenge_step_label(ChallengeLevel::Iframe), "click");
        assert_eq!(challenge_step_label(ChallengeLevel::Javascript), "high");
        assert_eq!(challenge_step_label(ChallengeLevel::Captcha), "capt");
    }

    // V233 — key-builder collision-resistance. `IpAddr` is already in
    // scope via `use super::*`; only `Ipv4Addr` needs importing.
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn rep_key_has_stable_namespaced_shape() {
        let k = redis_rep_key("example.com", ip(203, 0, 113, 7), "Mozilla", "/login");
        // `aegis:rep:` + 16 lowercase hex chars, nothing else.
        assert!(k.starts_with("aegis:rep:"), "prefix: {k}");
        let digest = &k["aegis:rep:".len()..];
        assert_eq!(digest.len(), 16, "fixed-width digest: {k}");
        assert!(
            digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "hex only: {k}"
        );
    }

    #[test]
    fn tb_key_has_stable_shape() {
        let k = redis_tb_key("example.com", ip(203, 0, 113, 7));
        assert!(k.starts_with("aegis:tb:"), "prefix: {k}");
        let digest = &k["aegis:tb:".len()..];
        assert_eq!(digest.len(), 16);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn rep_key_is_deterministic() {
        // Every node must derive the same key for the same tuple so a
        // shared Redis cluster stays consistent.
        let a = redis_rep_key("h", ip(1, 2, 3, 4), "ua", "/p");
        let b = redis_rep_key("h", ip(1, 2, 3, 4), "ua", "/p");
        assert_eq!(a, b);
    }

    #[test]
    fn rep_key_field_boundaries_are_injective() {
        // The core regression: under the old `|`-join, a delimiter
        // inside a field let distinct tuples alias onto one key.
        // ("a","bcd") vs ("abc","d") in the (ua,path) slots — and a
        // host that swallows the `:` namespace separator — must all
        // yield distinct keys now that fields are length-prefixed.
        let victim = redis_rep_key("host", ip(9, 9, 9, 9), "a", "bcd");
        let shifted = redis_rep_key("host", ip(9, 9, 9, 9), "abc", "d");
        assert_ne!(victim, shifted, "ua/path boundary collided");

        let host_inject = redis_rep_key("host:9.9.9.9", ip(9, 9, 9, 9), "a", "bcd");
        assert_ne!(victim, host_inject, "host swallowed namespace");

        // A `|` literally embedded in the UA must not let an attacker
        // reconstruct another tuple's fingerprint.
        let pipe = redis_rep_key("host", ip(9, 9, 9, 9), "a|bcd", "");
        assert_ne!(victim, pipe, "embedded pipe collided");
    }

    #[test]
    fn tb_key_resists_host_delimiter_injection() {
        // Spoofing the Host (incl. embedding the old `|` delimiter)
        // must produce a *different* bucket from the genuine pair —
        // and crucially must not collide with another genuine pair.
        let genuine = redis_tb_key("example.com", ip(198, 51, 100, 1));
        let spoofed = redis_tb_key("example.com|198.51.100.1", ip(0, 0, 0, 0));
        assert_ne!(genuine, spoofed);
        let other = redis_tb_key("other.com", ip(198, 51, 100, 1));
        assert_ne!(genuine, other);
    }

    // H6 — client-supplied forwarding headers must never be forwarded
    // verbatim. `set_authoritative_forwarding` strips them and stamps the
    // proxy's own resolved client IP so a backend can't be told a spoofed
    // source address.
    #[test]
    fn forwarding_headers_are_overwritten_with_authoritative_ip() {
        let mut h = hdrs(&[
            ("x-forwarded-for", "1.1.1.1, 9.9.9.9"),
            ("x-real-ip", "1.1.1.1"),
            ("forwarded", "for=1.1.1.1"),
            ("user-agent", "curl/8"),
        ]);
        let client = ip(203, 0, 113, 5);
        set_authoritative_forwarding(&mut h, client);
        // The spoofed chain is gone; XFF / X-Real-IP now reflect only the
        // observed peer, and there's exactly one of each.
        assert_eq!(h.get_all("x-forwarded-for").iter().count(), 1);
        assert_eq!(
            h.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "203.0.113.5"
        );
        assert_eq!(h.get("x-real-ip").unwrap().to_str().unwrap(), "203.0.113.5");
        // `Forwarded` had no authoritative replacement to mint, so it is
        // simply dropped — the backend never sees the spoofed value.
        assert!(h.get("forwarded").is_none());
        // Unrelated headers are untouched.
        assert_eq!(h.get("user-agent").unwrap().to_str().unwrap(), "curl/8");
    }

    #[test]
    fn forwarding_headers_set_when_absent() {
        // Even with no client-supplied forwarding headers, we stamp the
        // authoritative IP so the backend always sees a trustworthy value.
        let mut h = hdrs(&[("host", "example.com")]);
        set_authoritative_forwarding(&mut h, ip(198, 51, 100, 9));
        assert_eq!(
            h.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "198.51.100.9"
        );
        assert_eq!(
            h.get("x-real-ip").unwrap().to_str().unwrap(),
            "198.51.100.9"
        );
    }

    #[test]
    fn forwarding_strip_removes_case_and_injection_attempts() {
        // HeaderMap normalises header names case-insensitively, so an
        // attacker can't slip a spoofed value past the strip via casing.
        let mut h = http::HeaderMap::new();
        h.insert("X-Forwarded-For", "evil".parse().unwrap());
        h.insert("X-Real-IP", "evil".parse().unwrap());
        set_authoritative_forwarding(&mut h, ip(10, 0, 0, 1));
        assert_eq!(
            h.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "10.0.0.1"
        );
        assert_eq!(h.get("x-real-ip").unwrap().to_str().unwrap(), "10.0.0.1");
    }

    // V234 — `HyperPoster` is the outbound transport that backs real
    // reCAPTCHA siteverify. The security guarantee is fail-closed: any
    // transport problem must yield `Err` (which the provider turns into
    // a failure verdict, so `verify_recaptcha` returns `false`) and
    // must never panic.
    fn test_hyper_poster() -> HyperPoster {
        let mut conn = HttpConnector::new();
        conn.set_nodelay(true);
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(conn);
        HyperPoster { client }
    }

    #[tokio::test]
    async fn hyper_poster_fails_closed_on_unroutable_endpoint() {
        // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — reserved and never
        // routable, so this exercises the connect-failure path without
        // any real network dependency. Short timeout keeps it snappy.
        let poster = test_hyper_poster();
        let res = poster
            .post_form(
                "http://192.0.2.1:9/recaptcha/api/siteverify",
                "secret=s&response=tok",
                std::time::Duration::from_millis(250),
            )
            .await;
        // Must be an error (transport failure or timeout) — never Ok,
        // never a panic.
        assert!(res.is_err(), "unroutable endpoint must fail closed");
    }

    #[tokio::test]
    async fn hyper_poster_https_url_does_not_panic() {
        // The bundled connector is plaintext; an `https://` URL cannot
        // be served. The contract is that this returns `Err` rather
        // than panicking — the caller (`verify_recaptcha`) then fails
        // closed. Points at TEST-NET-1 so no real DNS/network is hit.
        let poster = test_hyper_poster();
        let res = poster
            .post_form(
                "https://192.0.2.2/recaptcha/api/siteverify",
                "secret=s&response=tok",
                std::time::Duration::from_millis(250),
            )
            .await;
        assert!(
            res.is_err(),
            "https via plaintext connector must fail closed"
        );
    }
}
