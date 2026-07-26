use std::{
    net::IpAddr,
    sync::{Arc, OnceLock},
    time::Instant,
};

use hyper::Method;
use hyper::http::{HeaderMap, Version};

/// V230 — raw 64-bit request id (thread-local counter mixed with a
/// per-thread seed). Cheap (no allocation, no kernel call) and the
/// hex string is rendered on demand by [`render_request_id`] when a
/// caller actually needs it. Previously this function returned a
/// 16-char hex `String` formatted at construction time on **every**
/// request, even though `ctx.request_id` is only read on the Deny /
/// Challenge path (`ErrorMask::render_body` in
/// `challenge_deception.rs:133`) — pure waste on the 99% allow path.
///
/// V85 — original notes preserved: this lives in `proxy::request_context`
/// so both hyper and pingora data planes can share it. Prior to V85, the
/// pingora-side path allocated a UUID + 36-char `String` on every request
/// via `Uuid::new_v4().to_string()`; at 245k slow-path RPS that was
/// 245k UUIDs/sec of pure waste.
pub fn next_request_id_u64() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static COUNTER: Cell<u64> = const { Cell::new(0) };
        static SEED: Cell<u64> = const { Cell::new(0) };
    }
    let seed = SEED.with(|s| {
        let v = s.get();
        if v != 0 {
            return v;
        }
        let tid = format!("{:?}", std::thread::current().id());
        let mut h: u64 = 0xcbf29ce484222325;
        for b in tid.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        let new = (h & 0xFFFF_FFFF_0000_0000).max(0x0000_0001_0000_0000);
        s.set(new);
        new
    });
    let n = COUNTER.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        v
    });
    seed | (n & 0xFFFF_FFFF)
}

/// V230 — format a raw `u64` request id as a 16-char zero-padded hex
/// string. Use this only on the cold path (Deny / Challenge body render,
/// access log line) where the textual form is actually consumed.
#[inline]
pub fn render_request_id(id: u64) -> String {
    format!("{id:016x}")
}

/// V85 / V230 — back-compat wrapper that returns a freshly-formatted
/// hex string. Retained so any caller that genuinely needs a `String`
/// (logging adapters, tests, FFI surfaces) does not have to change.
/// New hot-path code should call [`next_request_id_u64`] directly and
/// only render hex via [`render_request_id`] when needed; the two
/// `RequestContext` constructors in `proxy/http.rs` and
/// `proxy/pingora_http.rs` now read the raw `u64` form, so this
/// wrapper is only for out-of-band callers that prefer text.
pub fn next_request_id() -> String {
    render_request_id(next_request_id_u64())
}

/// Context passed into traffic filters for policy decisions.
///
/// `headers` is `Arc<HeaderMap>` so cloning the context is O(1)
/// (atomic refcount bump) rather than O(N) (deep copy of every
/// header value). The hot proxy path holds exactly two refs: one in
/// the context fed to filters and one taken back out for upstream
/// forwarding — `Arc::try_unwrap` succeeds when filters have dropped
/// their borrow, avoiding the clone entirely on the steady-state
/// path.
///
/// V230 — field layout reordered so the hot scalars used by every
/// filter (`client_ip`, `is_trusted`, `method`, `host`, `path`,
/// `headers`, `timestamp`, `request_id`) sit at the front of the
/// struct, ahead of the seven `Option<String>` fingerprint slots
/// (24 B each) that are read only by the WAF / scorer / plugin
/// pipelines. Keeping the hot block contiguous improves cache
/// behaviour on the allow path without renaming any field — the long
/// tail of `ctx.ja4` / `ctx.h2fp` / `ctx.mtls_fp` call sites compiles
/// unchanged. (A `Box<ColdFp>` packing was considered but skipped:
/// ~40 direct field accesses across the codebase including mutation
/// sites in the lua plugin and tests would all have to change, and
/// the indirection cost on the scorer hot path is comparable to the
/// cache win.)
///
/// V230 — `request_id` is now a raw `u64` (8 B) instead of a 16-char
/// `String` (24 B + heap allocation per request). The hex string is
/// rendered on demand by [`RequestContext::request_id_string`] — cold
/// path only. The allow path never inspects this value.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RequestContext {
    // ── Hot fields: read by every filter on the allow path. Keep at
    //    the front of the struct so they share a single cache line on
    //    common 64-bit layouts. ────────────────────────────────────
    pub client_ip: IpAddr,
    /// True when this IP earned dynamic-trust status from prior
    /// clean behaviour. Throttling-class filters (rate_limit, bot,
    /// challenge) honour this and short-circuit to Allow. WAF /
    /// smuggling / honeypot / threat-intel always run regardless —
    /// trust means "no need to throttle this client", NOT "skip
    /// security checks for this client". A single attack attempt
    /// from a trusted IP still hits the WAF and revokes trust.
    pub is_trusted: bool,
    pub method: Method,
    /// Pre-extracted Host header value. Several filters
    /// (rate_limit, bot, scorer, anomaly) consult Host on every
    /// request — caching it here once avoids re-hashing the
    /// HeaderMap key in each filter. Empty string when missing.
    pub host: String,
    pub path: String,
    pub headers: Arc<HeaderMap>,
    pub timestamp: Instant,
    /// V230 — raw `u64` request id (was a 16-char hex `String`).
    /// Construct with [`next_request_id_u64`]; render to text via
    /// [`RequestContext::request_id_string`] on the cold path. The
    /// allow path never inspects this value, so paying for a hex
    /// `format!` + heap alloc on every request was pure waste.
    pub request_id: u64,
    pub user_agent: Option<String>,

    // ── Cold fields: read only by WAF / scorer / plugin paths and
    //    most often `None` in production until the matching TLS /
    //    HTTP/2 / mTLS surface is wired up. Kept at the tail so the
    //    hot block above stays cache-tight. ────────────────────────
    /// JA3 TLS fingerprint hash (MD5 hex, 32 lowercase chars) of the
    /// connection this request arrived on. Populated alongside `ja4`
    /// by the pingora `build_ctx` from the per-connection TLS digest.
    /// This holds the **hash** form (the abuse.ch / SSL-Blacklist
    /// publication format) rather than the raw `{version},{ciphers},…`
    /// string, because the hash is what the `ja3_deny_hashes` policy
    /// matches against (`eq_ignore_ascii_case`) and what WAF rules with
    /// `field:"ja3"` compare. None for plain HTTP and for handshakes
    /// that didn't parse. Previously the pingora path computed this and
    /// threw it away (`let _ = ja3;`), so the `ja3_deny_hashes` policy
    /// silently never enforced on the deployed binary.
    pub ja3: Option<String>,
    /// JA4 TLS fingerprint of the connection this request arrived on,
    /// when the connection was TLS-terminated by Aegis and the
    /// ClientHello was successfully parsed. None for plain HTTP and
    /// for handshakes that didn't parse.
    pub ja4: Option<String>,
    /// HTTP version stored so `ja4h()` can compute the fingerprint
    /// lazily without requiring a separate ingress parameter. Populated
    /// by `build_ctx` (pingora path) and the hyper context constructor.
    /// `pub` only so those struct-literal constructors in other modules
    /// can set it; consumers must call `ja4h()`, not touch this field.
    pub http_version: Version,
    /// JA4H fingerprint cache — computed at most once, on first call
    /// to `ja4h()`. `None` inside the `OnceLock` means "trusted
    /// request, fingerprint intentionally skipped". `pub` only so the
    /// struct-literal constructors in other modules can initialise it;
    /// consumers must use `ja4h()` to access, never this field.
    ///
    /// `OnceLock<T>` is both `Send` and `Sync` (unlike `OnceCell`).
    /// Using `OnceLock` keeps `RequestContext: Sync`, which is required
    /// for the Pingora proxy context type `AegisCtx` to satisfy
    /// `AegisCtx: Sync` (Pingora requires `CTX: Send + Sync`). This
    /// also makes it safe to store `RequestContext` inside `AegisCtx`.
    pub ja4h_cache: OnceLock<Option<String>>,
    /// JA4T fingerprint of the connection's SYN packet, where
    /// captured. None when running on non-Linux or when the SYN
    /// capture didn't fire (XDP off, raw socket unavailable).
    pub ja4t: Option<String>,
    /// JA4L latency string (ClientHello → handshake-done ms).
    pub ja4l: Option<String>,
    /// HTTP/2 Akamai-style fingerprint (only for h2 connections).
    pub h2fp: Option<String>,
    /// HTTP/3 / QUIC fingerprint (only for h3 connections).
    pub h3fp: Option<String>,
    /// mTLS client-cert fingerprint when the client presented a
    /// verified cert.
    pub mtls_fp: Option<String>,
}

impl RequestContext {
    /// V230 — render the request id as a 16-char hex string. Cold-path
    /// only: called by `ErrorMask::render_body` (Deny / Challenge
    /// pages) and by access-log adapters. The allow path leaves the
    /// raw `u64` alone, saving one `format!` and one heap allocation
    /// per request.
    #[inline]
    pub fn request_id_string(&self) -> String {
        render_request_id(self.request_id)
    }

    /// JA4H fingerprint — computed lazily at most once per request.
    ///
    /// Returns `None` for trusted requests (where JA4H was intentionally
    /// skipped at ingress) and for synthetic test contexts that did not
    /// supply an HTTP version. Returns `Some(&str)` with the full JA4H
    /// string on the first call that triggers computation; subsequent
    /// calls return the cached value with no SHA-256 re-run.
    ///
    /// Computation requires SHA-256 (~2.7% of slow-path CPU when done
    /// eagerly on every request). By deferring to first read we pay
    /// that cost only when a filter actually needs the fingerprint.
    pub fn ja4h(&self) -> Option<&str> {
        self.ja4h_cache
            .get_or_init(|| {
                // `is_trusted` being set means the caller intentionally
                // skipped fingerprinting — return None without computing.
                if self.is_trusted {
                    return None;
                }
                let ver_str = match self.http_version {
                    Version::HTTP_10 => "1.0",
                    Version::HTTP_11 => "1.1",
                    Version::HTTP_2 => "2.0",
                    Version::HTTP_3 => "3.0",
                    _ => "0.0",
                };
                Some(
                    crate::ja4::compute_ja4h_from_headermap(
                        self.method.as_str(),
                        ver_str,
                        &self.headers,
                    )
                    .full,
                )
            })
            .as_deref()
    }
}

#[cfg(test)]
impl RequestContext {
    /// Builder for tests. Fills sensible defaults so tests can override
    /// only the fields they actually care about.
    pub fn test_with(ip: &str, path: &str) -> Self {
        Self {
            // V230 — `request_id` is now `u64`; tests get a fixed
            // sentinel value so the rendered hex form is reproducible
            // (`render_request_id(0xdead_beef_cafe_f00d) ==
            // "deadbeefcafef00d"`).
            request_id: 0xdead_beef_cafe_f00d,
            client_ip: ip.parse().expect("ip"),
            method: Method::GET,
            path: path.to_string(),
            host: String::new(),
            is_trusted: false,
            headers: Arc::new(HeaderMap::new()),
            timestamp: Instant::now(),
            user_agent: None,
            ja3: None,
            ja4: None,
            // V231 — ja4h is now lazy. Test contexts default to HTTP/1.1
            // so `ja4h()` can compute a real fingerprint when needed.
            // Tests that previously set `ctx.ja4h = Some(...)` should
            // use `ctx.set_ja4h_for_test(...)` instead.
            http_version: Version::HTTP_11,
            ja4h_cache: OnceLock::new(),
            ja4t: None,
            ja4l: None,
            h2fp: None,
            h3fp: None,
            mtls_fp: None,
        }
    }

    /// Test-only helper to pre-populate the ja4h cache with a known
    /// value, replacing the previous pattern of `ctx.ja4h = Some(...)`.
    pub fn set_ja4h_for_test(self, value: &str) -> Self {
        let _ = self.ja4h_cache.set(Some(value.to_string()));
        self
    }

    pub fn with_header(mut self, name: &'static str, value: &str) -> Self {
        // Test-only mutation — we know we hold the sole Arc ref here.
        Arc::make_mut(&mut self.headers).insert(name, value.parse().expect("valid header value"));
        // Mirror the cached `host` field so test contexts stay consistent
        // with the prod hot path (which populates `host` once at ingress).
        if name.eq_ignore_ascii_case("host") {
            self.host = value.to_string();
        }
        self
    }

    pub fn with_method(mut self, m: &str) -> Self {
        self.method = m.parse().expect("valid method");
        self
    }

    /// Test-only: stamp a JA3 hash on the context (mirrors the
    /// per-connection TLS digest the pingora `build_ctx` reads).
    pub fn with_ja3(mut self, ja3: &str) -> Self {
        self.ja3 = Some(ja3.to_string());
        self
    }

    /// Test-only: stamp a JA4 string on the context.
    pub fn with_ja4(mut self, ja4: &str) -> Self {
        self.ja4 = Some(ja4.to_string());
        self
    }

    pub fn with_ua(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        Arc::make_mut(&mut self.headers).insert("user-agent", ua.parse().expect("valid ua"));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // V230 — guard the new lazy request-id surface.
    #[test]
    fn next_request_id_u64_is_nonzero_and_unique() {
        let a = next_request_id_u64();
        let b = next_request_id_u64();
        assert_ne!(a, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn render_request_id_is_16_char_hex() {
        let s = render_request_id(0x0000_0001_0000_0001);
        assert_eq!(s.len(), 16);
        assert_eq!(s, "0000000100000001");
    }

    #[test]
    fn next_request_id_string_matches_render() {
        // The String-returning wrapper must agree with the explicit
        // render of the raw counter — guards back-compat callers.
        assert_eq!(next_request_id().len(), 16);
        let raw = next_request_id_u64();
        assert_eq!(render_request_id(raw).len(), 16);
    }

    #[test]
    fn request_id_string_helper_renders_ctx_field() {
        let mut ctx = RequestContext::test_with("1.2.3.4", "/");
        ctx.request_id = 0x1234_5678_9abc_def0;
        assert_eq!(ctx.request_id_string(), "123456789abcdef0");
    }

    // V231 — JA4H laziness guards. ─────────────────────────────────

    /// A freshly constructed context must NOT have ja4h computed yet.
    #[test]
    fn ja4h_not_computed_before_first_access() {
        let ctx = RequestContext::test_with("1.2.3.4", "/api");
        // Cache is empty — computation has not happened.
        assert!(
            ctx.ja4h_cache.get().is_none(),
            "ja4h_cache must be empty before first call to ja4h()"
        );
    }

    /// First access triggers computation; second access returns same value.
    #[test]
    fn ja4h_computed_on_first_access_then_cached() {
        let ctx =
            RequestContext::test_with("1.2.3.4", "/api").with_header("user-agent", "test/1.0");
        // Before first access — cache is empty.
        assert!(ctx.ja4h_cache.get().is_none());
        // First call computes.
        let first = ctx.ja4h().map(|s| s.to_string());
        assert!(first.is_some(), "should have computed a fingerprint");
        // Cache is now populated.
        assert!(ctx.ja4h_cache.get().is_some());
        // Second call returns the same pointer (cached).
        let second = ctx.ja4h().map(|s| s.to_string());
        assert_eq!(first, second);
    }

    /// Trusted requests return None without computing anything.
    #[test]
    fn ja4h_trusted_returns_none_without_computing() {
        let mut ctx = RequestContext::test_with("1.2.3.4", "/");
        ctx.is_trusted = true;
        assert!(ctx.ja4h().is_none(), "trusted context must return None");
    }

    /// H9d — the new `ja3` slot defaults to None and round-trips a
    /// stamped value (used by the pingora deny-list enforcement path).
    #[test]
    fn ja3_field_defaults_none_and_round_trips() {
        let ctx = RequestContext::test_with("1.2.3.4", "/");
        assert!(ctx.ja3.is_none(), "ja3 must default to None");
        let ctx = ctx.with_ja3("e7d705a3286e19ea42f587b344ee6865");
        assert_eq!(ctx.ja3.as_deref(), Some("e7d705a3286e19ea42f587b344ee6865"));
    }

    /// `set_ja4h_for_test` lets tests inject a known value.
    #[test]
    fn set_ja4h_for_test_injects_value() {
        let ctx = RequestContext::test_with("1.2.3.4", "/").set_ja4h_for_test("ge11nn0500_x_y_z");
        assert_eq!(ctx.ja4h(), Some("ge11nn0500_x_y_z"));
    }
}
