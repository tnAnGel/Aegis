//! V129 — ClamAV TCP scanner for body content (Synapse parity).
//!
//! WAF body inspection (V20-era) catches SQLi / XSS / cmd injection
//! signatures in `application/x-www-form-urlencoded` / JSON bodies.
//! It does NOT catch malware payloads in `multipart/form-data` file
//! uploads — that's ClamAV's job. V129 wires Aegis to a running
//! `clamd` daemon via its INSTREAM TCP API.
//!
//! Operator config (env or DSL block — V130+ adds DSL):
//!
//!     AEGIS_CLAMAV_ADDR=127.0.0.1:3310
//!     AEGIS_CLAMAV_MAX_BODY_BYTES=26214400   # 25MB
//!     AEGIS_CLAMAV_TIMEOUT_MS=5000
//!
//! Disabled by default — `AEGIS_CLAMAV_ADDR` unset = no-op. clamd
//! runs in the operator's network; we don't bundle the daemon.
//!
//! Hot-path safety:
//! * Scan only fires for `should_scan(content_type, content_length)`
//!   = true, gated by the proxy's body-buffering logic.
//! * Bounded body cap (`max_body_bytes`) — beyond that we skip scan
//!   and let WAF body cap take over.
//! * Fail-open on connect timeout / clamd error — operator deploys
//!   redundant clamd; a single instance going down shouldn't block
//!   every upload. Counted as `aegis_clamav_scan_errors` for
//!   monitoring.
//!
//! V234 — revival wiring contract.
//! This module was fully built at V129 but never had a live caller,
//! so uploaded-body malware scanning was dormant. V234 makes it
//! cleanly revivable without changing behaviour:
//!
//! Lifecycle (one shared instance per process):
//! ```ignore
//!   // at startup, build once:
//!   let scanner = Arc::new(ClamavScanner::from_env());
//!   // ...store the Arc on the proxy handler, clone the Arc freely.
//! ```
//! `ClamavScanner` is also `Clone` (it holds only a cheap `Clone`
//! config) so it can be shared by value too — but `Arc` matches the
//! handler's other services (`Arc<WafFilter>`, `Arc<AnomalyDetector>`).
//!
//! Per-request call-site (after the WAF has buffered the body):
//! ```ignore
//!   // 1. cheap opt-in gate — skip ALL work when unconfigured:
//!   if scanner.is_enabled()
//!       && scanner.should_scan(content_type, body.len())
//!   {
//!       // 2. the one async call; bounded by max_body_bytes + timeout:
//!       if let ScanVerdict::Infected { signature } =
//!           scanner.scan(&body).await
//!       {
//!           // ...only Infected blocks — deny/403 here.
//!       }
//!   }
//! ```
//! Fail direction (explicit, operator policy — see `ScanVerdict`):
//! Clean / Skipped / Error all ALLOW the request through. ONLY
//! `ScanVerdict::Infected` blocks. A connect failure, timeout, or
//! malformed clamd reply yields `Error` and the body is let through
//! (fail-open) — by design, so a clamd outage cannot wedge uploads.
//! Operators wanting fail-closed must treat `Error` as a deny at the
//! call-site; this module never does.

use std::time::Duration;

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// Operator-tunable knobs. Defaults match clamd's default
/// `MaxFileSize`.
#[derive(Debug, Clone)]
pub struct ClamavConfig {
    pub addr: Option<String>,
    pub max_body_bytes: usize,
    pub timeout: Duration,
    /// `application/*` types that should be scanned. Other types
    /// (text/*, image/*) skip the scan unless explicitly listed.
    pub scan_content_types: Vec<String>,
}

impl Default for ClamavConfig {
    fn default() -> Self {
        Self {
            addr: None,
            max_body_bytes: 25 * 1024 * 1024,
            timeout: Duration::from_secs(5),
            // Most malicious payloads land in multipart uploads or
            // octet-stream blobs. application/json is dropped on
            // purpose — clamd has nothing to find there.
            scan_content_types: vec![
                "multipart/form-data".to_string(),
                "application/octet-stream".to_string(),
                "application/zip".to_string(),
                "application/x-rar-compressed".to_string(),
                "application/x-7z-compressed".to_string(),
                "application/x-tar".to_string(),
                "application/x-bzip2".to_string(),
                "application/pdf".to_string(),
                "application/msword".to_string(),
                "application/vnd.openxmlformats-officedocument".to_string(),
            ],
        }
    }
}

/// Scan verdict. Operator's WAF translates these into FilterAction.
///
/// V234 — block semantics: ONLY [`ScanVerdict::Infected`] is a block.
/// `Clean`, `Skipped`, and `Error` all mean "allow the request". The
/// call-site should `match` on `Infected` and deny; everything else
/// falls through. See the module header for the fail-open rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanVerdict {
    /// Body scanned cleanly. ALLOW the request.
    Clean,
    /// clamd found a signature match. The ONLY blocking verdict —
    /// the call-site must deny the request. `signature` carries the
    /// match name (e.g. "Eicar-Test-Signature") for logging/metrics.
    Infected { signature: String },
    /// Scan skipped (content-type not in scan list, body empty, body
    /// over `max_body_bytes`, or clamd not configured). ALLOW.
    Skipped,
    /// clamd unreachable, timed out, or returned a malformed
    /// response. ALLOW (fail-open) — this module never blocks on a
    /// scan failure. Operators wanting fail-closed must treat this
    /// variant as a deny at their own call-site. Count for the
    /// `aegis_clamav_scan_errors` metric.
    Error,
}

impl ScanVerdict {
    /// V234 — the single source of truth for "does this verdict block
    /// the request?". Returns `true` only for [`ScanVerdict::Infected`].
    /// Call-sites should prefer this over re-deriving the rule, so the
    /// fail-open policy stays in one place.
    pub fn is_block(&self) -> bool {
        matches!(self, ScanVerdict::Infected { .. })
    }
}

/// Shared, process-wide malware scanner. Holds only a cheap-to-clone
/// [`ClamavConfig`] — no sockets, no pools — so `Clone` is trivial.
/// V234: wrap one instance in `Arc<ClamavScanner>` at startup (to
/// match the proxy handler's other services) or clone by value; both
/// are cheap. There is no per-instance state to keep coherent.
#[derive(Debug, Clone)]
pub struct ClamavScanner {
    cfg: ClamavConfig,
}

impl ClamavScanner {
    /// Build a scanner from an explicit config. A config with
    /// `addr == None` produces a permanently-disabled no-op scanner
    /// (`is_enabled()` is false; `scan` returns `Skipped`).
    pub fn new(cfg: ClamavConfig) -> Self {
        Self { cfg }
    }

    /// V234 — startup constructor for the revival path. Reads
    /// `AEGIS_CLAMAV_ADDR` / `AEGIS_CLAMAV_MAX_BODY_BYTES` /
    /// `AEGIS_CLAMAV_TIMEOUT_MS` from the environment. When
    /// `AEGIS_CLAMAV_ADDR` is unset the scanner is a no-op, so this is
    /// safe to call unconditionally at boot: build it once, wrap in
    /// `Arc`, store on the proxy handler.
    pub fn from_env() -> Self {
        let addr = std::env::var("AEGIS_CLAMAV_ADDR").ok();
        let max_body_bytes = std::env::var("AEGIS_CLAMAV_MAX_BODY_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(25 * 1024 * 1024);
        let timeout_ms = std::env::var("AEGIS_CLAMAV_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5000);
        let mut cfg = ClamavConfig {
            addr,
            max_body_bytes,
            timeout: Duration::from_millis(timeout_ms),
            ..ClamavConfig::default()
        };
        // Preserve default scan_content_types.
        cfg.scan_content_types = ClamavConfig::default().scan_content_types;
        Self::new(cfg)
    }

    /// V234 — the opt-in gate. `true` only when the operator
    /// configured a clamd address (`AEGIS_CLAMAV_ADDR` / config
    /// field). The hot-path call-site MUST check this first: when it
    /// is `false` the scanner does nothing, so the caller can skip
    /// `should_scan` / `scan` and avoid all body-handling work.
    /// O(1), no allocation, no I/O.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.cfg.addr.is_some()
    }

    /// Back-compat alias of [`Self::is_enabled`]. Prefer `is_enabled`
    /// in new call-sites (idiomatic `is_` predicate naming).
    #[inline]
    pub fn enabled(&self) -> bool {
        self.is_enabled()
    }

    /// Cheap pre-filter — answers "should we even bother sending this
    /// body to clamd?" without blocking. Hot-path callers gate on this
    /// before buffering the body for scan. Returns `false` (skip) when
    /// the scanner is disabled, the body is empty, the body exceeds
    /// `max_body_bytes`, or the content-type is not in the scan list.
    pub fn should_scan(&self, content_type: &str, content_length: usize) -> bool {
        if !self.enabled() {
            return false;
        }
        if content_length == 0 || content_length > self.cfg.max_body_bytes {
            return false;
        }
        let ct_lower = content_type.to_ascii_lowercase();
        let bare = ct_lower.split(';').next().unwrap_or(&ct_lower).trim();
        for accepted in &self.cfg.scan_content_types {
            if bare.starts_with(accepted) {
                return true;
            }
        }
        false
    }

    /// V234 — the per-request entry point. Stream `body` to clamd over
    /// its INSTREAM TCP API and return a [`ScanVerdict`].
    ///
    /// Call this only after [`Self::is_enabled`] (and normally
    /// [`Self::should_scan`]) returned true. It is still safe to call
    /// unconditionally — a disabled scanner returns `Skipped` — but
    /// the caller then pays the buffering cost for nothing.
    ///
    /// Bounds (all enforced here, independent of `should_scan`):
    /// * empty body          → `Skipped` (nothing to scan)
    /// * body > `max_body_bytes` → `Skipped` (the body is let through;
    ///   the WAF's own body cap is the backstop — we do NOT scan a
    ///   prefix, matching V129 behaviour)
    /// * `timeout` ceiling around the whole clamd exchange
    /// * the INSTREAM reply is capped (V233) so a rogue clamd cannot
    ///   OOM the worker
    ///
    /// Fail direction (V234, explicit): connect failure, timeout, and
    /// malformed/oversized replies all yield `ScanVerdict::Error`,
    /// which is an ALLOW — this function never blocks on a scan
    /// failure (fail-open). Only `ScanVerdict::Infected` indicates the
    /// caller should deny; use [`ScanVerdict::is_block`].
    ///
    /// See clamd protocol docs:
    ///   https://docs.clamav.net/manual/Usage/Scanning.html#instream
    pub async fn scan(&self, body: &[u8]) -> ScanVerdict {
        // V234: not configured → no-op skip. Mirrors `is_enabled()`
        // so an unconditional caller is still cheap and correct.
        let Some(addr) = self.cfg.addr.as_deref() else {
            return ScanVerdict::Skipped;
        };
        // V234: empty or over-cap bodies are skipped (allowed), never
        // scanned as a prefix — keeps the V129 contract explicit.
        if body.is_empty() || body.len() > self.cfg.max_body_bytes {
            return ScanVerdict::Skipped;
        }
        match timeout(self.cfg.timeout, self.scan_inner(addr, body)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "clamav: scan failed");
                ScanVerdict::Error
            }
            Err(_) => {
                tracing::warn!("clamav: scan timeout");
                ScanVerdict::Error
            }
        }
    }

    async fn scan_inner(&self, addr: &str, body: &[u8]) -> Result<ScanVerdict> {
        let mut stream = TcpStream::connect(addr).await?;
        // INSTREAM protocol:
        //   "zINSTREAM\0" (z prefix = null-terminated command)
        //   then repeating: <chunksize: u32 big-endian> <chunkbytes>
        //   finally: <0u32> to signal end
        //   response: "stream: <signame> FOUND\0" or "stream: OK\0"
        stream.write_all(b"zINSTREAM\0").await?;
        // Send body in 64 KiB chunks (clamd's CHUNKSIZE).
        const CHUNK: usize = 64 * 1024;
        for slice in body.chunks(CHUNK) {
            let len = slice.len() as u32;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(slice).await?;
        }
        // Terminator.
        stream.write_all(&0u32.to_be_bytes()).await?;

        // Read response until NUL.
        // V233: clamd INSTREAM replies are tiny ("stream: OK\0",
        // "stream: <sig> FOUND\0", short error lines) — well under
        // 512 bytes. Cap the buffer so a malicious/compromised clamd
        // (or any process squatting the configured socket) cannot
        // stream gigabytes of non-NUL bytes and OOM the worker.
        const RESP_CAP: usize = 4096;
        let mut buf = Vec::with_capacity(128);
        let mut tmp = [0u8; 256];
        let mut found_nul = false;
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            // V233: scan only the freshly-read slice for the NUL
            // terminator — `buf.contains(&0)` rescanned the whole
            // buffer every iteration (O(n^2) on the accumulated len).
            if tmp[..n].contains(&0) {
                found_nul = true;
            }
            buf.extend_from_slice(&tmp[..n]);
            if found_nul {
                break;
            }
            // V233: bail before the buffer can grow without bound.
            if buf.len() > RESP_CAP {
                anyhow::bail!("clamd response exceeded {RESP_CAP} bytes without NUL terminator");
            }
        }
        // Trim trailing NUL.
        if let Some(nul) = buf.iter().position(|&b| b == 0) {
            buf.truncate(nul);
        }
        let resp = String::from_utf8_lossy(&buf).into_owned();
        Ok(parse_response(&resp))
    }
}

/// Parse a clamd INSTREAM response line.
/// Examples:
///   "stream: OK"                        → Clean
///   "stream: Eicar-Test-Signature FOUND" → Infected
///   "INSTREAM size limit exceeded ..."  → Error
fn parse_response(s: &str) -> ScanVerdict {
    // Strip trailing NUL too — clamd terminates responses with \0
    // and our caller doesn't always strip it before forwarding.
    let trimmed = s.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
    let trimmed = trimmed.trim();
    // V233: check FOUND first and independently. The old code
    // classified Clean on a loose `ends_with(" OK")`, so a crafted
    // body whose signature name ended in " OK" — or any response
    // shaped like "... FOUND ... OK" — would fail open and let real
    // malware through. A FOUND verdict must never be downgradable.
    if let Some(name) = trimmed.strip_suffix(" FOUND")
        && let Some(after_colon) = name.split_once(": ").map(|x| x.1)
    {
        return ScanVerdict::Infected {
            signature: after_colon.to_string(),
        };
    }
    // V233: the clean verdict is exactly the line "stream: OK" —
    // anchor on a full-string match, not a suffix, so nothing can
    // be appended to spoof it.
    if trimmed == "stream: OK" {
        return ScanVerdict::Clean;
    }
    ScanVerdict::Error
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_enabled() -> ClamavConfig {
        let mut c = ClamavConfig::default();
        c.addr = Some("127.0.0.1:3310".to_string());
        c
    }

    #[test]
    fn disabled_scanner_skips_everything() {
        let s = ClamavScanner::new(ClamavConfig::default());
        assert!(!s.should_scan("multipart/form-data", 1000));
    }

    // V234: the opt-in gate. A scanner with no addr is disabled; one
    // with an addr is enabled. `enabled()` stays as a back-compat
    // alias of `is_enabled()`.
    #[test]
    fn is_enabled_reflects_configured_addr() {
        let off = ClamavScanner::new(ClamavConfig::default());
        assert!(!off.is_enabled());
        assert!(!off.enabled());

        let on = ClamavScanner::new(cfg_enabled());
        assert!(on.is_enabled());
        assert!(on.enabled());
    }

    // V234: only Infected is a block; Clean/Skipped/Error all allow
    // (fail-open). `is_block()` is the single source of truth.
    #[test]
    fn only_infected_verdict_blocks() {
        assert!(
            ScanVerdict::Infected {
                signature: "X".to_string()
            }
            .is_block()
        );
        assert!(!ScanVerdict::Clean.is_block());
        assert!(!ScanVerdict::Skipped.is_block());
        assert!(!ScanVerdict::Error.is_block());
    }

    // V234: the scanner is cheaply Clone-able so one instance can be
    // shared (directly or behind Arc) across the proxy.
    #[test]
    fn scanner_is_clone_and_shares_config() {
        let s = ClamavScanner::new(cfg_enabled());
        let c = s.clone();
        assert!(c.is_enabled());
        assert!(c.should_scan("application/pdf", 2048));
    }

    // V234: an over-cap body is skipped (allowed), not scanned as a
    // prefix and not blocked.
    #[tokio::test]
    async fn scan_skips_body_over_max_bytes() {
        let mut c = cfg_enabled();
        c.max_body_bytes = 16;
        let s = ClamavScanner::new(c);
        let v = s.scan(&[0u8; 64]).await;
        assert_eq!(v, ScanVerdict::Skipped);
        assert!(!v.is_block());
    }

    #[test]
    fn should_scan_multipart_form_data() {
        let s = ClamavScanner::new(cfg_enabled());
        assert!(s.should_scan("multipart/form-data; boundary=---", 1024));
        assert!(s.should_scan("application/octet-stream", 1024));
        assert!(s.should_scan("application/pdf", 1024));
    }

    #[test]
    fn should_skip_text_and_json() {
        let s = ClamavScanner::new(cfg_enabled());
        assert!(!s.should_scan("text/html", 1024));
        assert!(!s.should_scan("application/json", 1024));
        assert!(!s.should_scan("text/plain; charset=utf-8", 1024));
    }

    #[test]
    fn should_skip_empty_and_oversized() {
        let s = ClamavScanner::new(cfg_enabled());
        assert!(!s.should_scan("multipart/form-data", 0));
        assert!(!s.should_scan("multipart/form-data", 100 * 1024 * 1024));
    }

    #[test]
    fn parse_clean_response() {
        assert_eq!(parse_response("stream: OK"), ScanVerdict::Clean);
        assert_eq!(parse_response("stream: OK\0"), ScanVerdict::Clean);
    }

    #[test]
    fn parse_infected_response() {
        let v = parse_response("stream: Eicar-Test-Signature FOUND");
        assert_eq!(
            v,
            ScanVerdict::Infected {
                signature: "Eicar-Test-Signature".to_string()
            }
        );
    }

    #[test]
    fn parse_error_response() {
        assert_eq!(parse_response("INSTREAM size limit"), ScanVerdict::Error);
        assert_eq!(parse_response(""), ScanVerdict::Error);
    }

    // V233: only the exact line "stream: OK" is Clean. A response
    // with anything appended must not be downgraded to clean.
    #[test]
    fn parse_only_exact_stream_ok_is_clean() {
        assert_eq!(parse_response("stream: OK"), ScanVerdict::Clean);
        assert_eq!(parse_response("  stream: OK \0"), ScanVerdict::Clean);
        // Loose suffixes that the old `ends_with(" OK")` accepted
        // must now fall through to Error, not Clean.
        assert_eq!(parse_response("evil: OK"), ScanVerdict::Error);
        assert_eq!(parse_response("stream: something OK"), ScanVerdict::Error);
        assert_eq!(parse_response("stream: OK extra"), ScanVerdict::Error);
    }

    // V233: a real FOUND verdict must never be downgraded by a
    // crafted suffix shaped to satisfy the old clean check.
    #[test]
    fn parse_found_is_never_downgraded_to_clean() {
        let v = parse_response("stream: Win.Trojan.X FOUND");
        assert_eq!(
            v,
            ScanVerdict::Infected {
                signature: "Win.Trojan.X".to_string()
            }
        );
        // A signature name that itself ends in " OK" still resolves
        // to Found — FOUND is checked first and independently.
        let v = parse_response("stream: Malware.Looks OK FOUND");
        assert_eq!(
            v,
            ScanVerdict::Infected {
                signature: "Malware.Looks OK".to_string()
            }
        );
    }

    // V233: an oversized clamd response (no NUL within the cap) is
    // rejected with an error rather than growing the buffer until
    // OOM. We exercise scan_inner against a local TCP server that
    // streams non-NUL bytes forever.
    #[tokio::test]
    async fn oversized_response_is_rejected_not_oom() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: accept, drain the INSTREAM upload, then flood the
        // client with non-NUL bytes (no terminator, ever).
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut sink = [0u8; 1024];
            let _ = sock.read(&mut sink).await; // zINSTREAM + framing
            let flood = [b'A'; 4096];
            // Far more than RESP_CAP — the client must bail well
            // before this completes.
            for _ in 0..256 {
                if sock.write_all(&flood).await.is_err() {
                    break;
                }
            }
        });

        let scanner = ClamavScanner::new(cfg_enabled());
        let res = scanner.scan_inner(&addr.to_string(), b"payload").await;
        assert!(
            res.is_err(),
            "oversized NUL-less response must be a hard error, got {res:?}"
        );

        // Public scan() wraps the same error into ScanVerdict::Error.
        let mut c = cfg_enabled();
        c.addr = Some(addr.to_string());
        let v = ClamavScanner::new(c).scan(b"payload").await;
        // Server may already be gone (client bailed early); accept
        // Error from either the cap or a follow-on connection error.
        assert_eq!(v, ScanVerdict::Error);

        server.abort();
    }

    #[tokio::test]
    async fn scan_with_no_addr_returns_skipped() {
        let s = ClamavScanner::new(ClamavConfig::default());
        let v = s.scan(b"some body content").await;
        assert_eq!(v, ScanVerdict::Skipped);
    }

    #[tokio::test]
    async fn scan_with_unreachable_clamd_returns_error() {
        let mut c = cfg_enabled();
        c.addr = Some("127.0.0.1:1".to_string()); // port unlikely to host clamd
        c.timeout = Duration::from_millis(200);
        let s = ClamavScanner::new(c);
        let v = s.scan(b"body").await;
        // Either Error (connect refused) or Skipped (length-zero skip) —
        // we always send non-empty so Error is the expected result.
        assert_eq!(v, ScanVerdict::Error);
    }
}
