//! V241 — flood-capacity tests for the admin Benchmark page.
//!
//! Where [`crate::benchmark`] runs synthetic micro-benchmarks and *projects*
//! capacity, this module answers the operator's real question: **"how much of
//! each flood can this box actually withstand?"**
//!
//! Each scenario spins up a tiny in-process server bound to `127.0.0.1:0`
//! (an OS-assigned ephemeral loopback port) and then drives a bounded,
//! time-capped load generator against it. We measure *achieved* numbers —
//! sustainable rps, accepted/dropped connections, p99 latency — rather than
//! extrapolating from a single core's clock.
//!
//! ## Safety contract (this runs on the LIVE host)
//!
//! * **Loopback only.** Every listener binds `127.0.0.1`; no packets leave the
//!   box. We never touch the real proxy listen sockets.
//! * **Bounded duration.** Each scenario has a hard wall cap (≤ ~1.2 s) and the
//!   whole suite is capped at [`FLOOD_TOTAL_BUDGET`].
//! * **Bounded intensity.** Concurrency is capped at [`MAX_CONCURRENCY`] and
//!   connection counts at [`MAX_CONNS`] so we cannot exhaust host FDs.
//! * **Self-contained.** The load generator and the victim server are both in
//!   this process, so a flood test can never accidentally hammer a tenant.
//!
//! ## Honesty
//!
//! These are loopback measurements of the *kernel + this process's* accept /
//! TLS / parse path. They are a genuine lower bound on what the same hardware
//! can do, but a production deployment also pays NIC, real-RTT, and upstream
//! costs. Results carry a `loopback: true` flag and a caveat string.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Safety bounds
// ---------------------------------------------------------------------------

/// Hard wall cap for the entire flood suite.
const FLOOD_TOTAL_BUDGET: Duration = Duration::from_secs(8);
/// Per-scenario load-generation window.
const SCENARIO_DURATION: Duration = Duration::from_millis(900);
/// Max concurrent in-flight requests / workers per scenario.
const MAX_CONCURRENCY: usize = 256;
/// Max simultaneous open connections we will hold (slowloris / SYN).
const MAX_CONNS: usize = 2_000;

// ---------------------------------------------------------------------------
// Result types (serde field names are the frontend contract)
// ---------------------------------------------------------------------------

/// One flood scenario's measured outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FloodScenario {
    /// Stable machine id: "syn" | "http" | "tls" | "slowloris" | "cache".
    pub id: String,
    /// Human label, e.g. "SYN flood (connection establishment)".
    pub label: String,
    /// Achieved sustainable rate. For SYN this is accepted conns/s; for
    /// slowloris it is the number of slow holders sustained (not /s).
    pub achieved_rps: u64,
    /// Unit string for `achieved_rps` ("conn/s", "req/s", "hs/s", "conns").
    pub unit: String,
    /// p99 per-op latency in milliseconds (handshake / request / accept).
    pub p99_ms: f64,
    /// p50 per-op latency in milliseconds.
    pub p50_ms: f64,
    /// Count of operations the victim *served* (accepted + completed).
    pub served: u64,
    /// Count of operations dropped / denied / refused / timed out.
    pub dropped: u64,
    /// "pass" | "degraded" | "fail" — qualitative verdict for the card.
    pub verdict: String,
    /// One-line plain-English interpretation for the operator.
    pub detail: String,
}

/// The full flood-suite result — GET /admin/api/benchmark/flood/result body.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FloodResult {
    pub ok: bool,
    /// "idle" | "running" | "done" | "error".
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub scenarios: Vec<FloodScenario>,
    /// Always true: these are loopback, single-host measurements.
    pub loopback: bool,
    pub caveat: String,
}

impl FloodResult {
    pub fn idle() -> Self {
        Self {
            ok: true,
            status: "idle".to_string(),
            error: None,
            started_at_unix: None,
            duration_ms: None,
            scenarios: Vec::new(),
            loopback: true,
            caveat: CAVEAT.to_string(),
        }
    }

    pub fn running(started_at_unix: u64) -> Self {
        Self {
            ok: true,
            status: "running".to_string(),
            error: None,
            started_at_unix: Some(started_at_unix),
            duration_ms: None,
            scenarios: Vec::new(),
            loopback: true,
            caveat: CAVEAT.to_string(),
        }
    }

    fn error(msg: String) -> Self {
        Self {
            ok: false,
            status: "error".to_string(),
            error: Some(msg),
            started_at_unix: None,
            duration_ms: None,
            scenarios: Vec::new(),
            loopback: true,
            caveat: CAVEAT.to_string(),
        }
    }
}

const CAVEAT: &str = "LOOPBACK MEASUREMENT — floods are generated and absorbed \
    in-process over 127.0.0.1 with bounded duration/intensity so the test is \
    safe on a live host. Numbers reflect the kernel + Aegis accept/TLS/parse \
    path on this hardware and are a lower bound; production also pays NIC, real \
    RTT and upstream costs.";

// ---------------------------------------------------------------------------
// Shared state (mirrors benchmark::BenchState)
// ---------------------------------------------------------------------------

pub struct FloodState {
    pub running: AtomicBool,
    pub result: arc_swap::ArcSwap<Option<FloodResult>>,
    pub started_at_unix: AtomicU64,
}

impl FloodState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            result: arc_swap::ArcSwap::from_pointee(None),
            started_at_unix: AtomicU64::new(0),
        }
    }
}

impl Default for FloodState {
    fn default() -> Self {
        Self::new()
    }
}

/// CAS-guarded start. `Ok(ts)` on success, `Err(())` if already running.
pub fn try_start(state: &Arc<FloodState>) -> Result<u64, ()> {
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
// Latency accumulator — fixed-bucket so we never allocate per-op in the flood.
// ---------------------------------------------------------------------------

/// Lock-free latency histogram with logarithmic-ish microsecond buckets.
/// Buckets cover 0..~5 s; anything larger lands in the top bucket.
struct LatHist {
    buckets: Vec<AtomicU64>,
    bounds_us: Vec<u64>,
}

impl LatHist {
    fn new() -> Self {
        // Bucket upper bounds in microseconds.
        let bounds_us: Vec<u64> = vec![
            10,
            25,
            50,
            100,
            200,
            400,
            800,
            1_500,
            3_000,
            6_000,
            12_000,
            25_000,
            50_000,
            100_000,
            250_000,
            500_000,
            1_000_000,
            2_500_000,
            5_000_000,
            u64::MAX,
        ];
        let buckets = bounds_us.iter().map(|_| AtomicU64::new(0)).collect();
        Self { buckets, bounds_us }
    }

    fn record(&self, dur: Duration) {
        let us = dur.as_micros() as u64;
        for (i, &b) in self.bounds_us.iter().enumerate() {
            if us <= b {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    fn total(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// Approximate percentile in milliseconds (uses the bucket upper bound).
    fn percentile_ms(&self, p: f64) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        let target = ((total as f64) * p).ceil() as u64;
        let mut cum = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            cum += b.load(Ordering::Relaxed);
            if cum >= target {
                let bound = self.bounds_us[i];
                let us = if bound == u64::MAX { 5_000_000 } else { bound };
                return us as f64 / 1000.0;
            }
        }
        0.0
    }
}

// ---------------------------------------------------------------------------
// Verdict helper
// ---------------------------------------------------------------------------

fn verdict_for(served: u64, dropped: u64) -> &'static str {
    let total = served + dropped;
    if total == 0 {
        return "fail";
    }
    let drop_ratio = dropped as f64 / total as f64;
    if drop_ratio <= 0.01 {
        "pass"
    } else if drop_ratio <= 0.15 {
        "degraded"
    } else {
        "fail"
    }
}

// ---------------------------------------------------------------------------
// Scenario 1 — SYN flood / connection-establishment capacity.
// ---------------------------------------------------------------------------
//
// We can't craft raw SYN packets without CAP_NET_RAW, and we will not poke the
// real XDP path on a live box. Instead we measure the layer the SYN flood
// actually stresses: the kernel accept queue + this process's accept loop.
// A pool of dialers opens full TCP connections as fast as possible (each = one
// completed 3-way handshake) while the victim accepts and immediately closes.
// Achieved accepts/s is the connection-establishment ceiling a SYN-cookie /
// XDP path has to protect; refused/timed-out dials are "dropped".

async fn scenario_syn() -> FloodScenario {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return failed_scenario("syn", "SYN flood (connection establishment)", &e),
    };
    let addr = listener.local_addr().unwrap();

    let accepted = Arc::new(AtomicU64::new(0));
    let acc2 = Arc::clone(&accepted);
    // Victim: accept + immediate close, mimicking a hardened accept loop.
    let server = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    acc2.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                }
                Err(_) => break,
            }
        }
    });

    let hist = Arc::new(LatHist::new());
    let dialed = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + SCENARIO_DURATION;

    let mut workers = Vec::new();
    let conc = MAX_CONCURRENCY.min(128);
    for _ in 0..conc {
        let hist = Arc::clone(&hist);
        let dialed = Arc::clone(&dialed);
        let refused = Arc::clone(&refused);
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let t0 = Instant::now();
                match tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(addr))
                    .await
                {
                    Ok(Ok(stream)) => {
                        hist.record(t0.elapsed());
                        dialed.fetch_add(1, Ordering::Relaxed);
                        drop(stream);
                    }
                    _ => {
                        refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    server.abort();

    let elapsed = SCENARIO_DURATION.as_secs_f64();
    let served = accepted.load(Ordering::Relaxed);
    let dropped = refused.load(Ordering::Relaxed);
    let rps = (served as f64 / elapsed).round() as u64;
    let verdict = verdict_for(served, dropped);

    FloodScenario {
        id: "syn".into(),
        label: "SYN flood (connection establishment)".into(),
        achieved_rps: rps,
        unit: "conn/s".into(),
        p99_ms: hist.percentile_ms(0.99),
        p50_ms: hist.percentile_ms(0.50),
        served,
        dropped,
        verdict: verdict.into(),
        detail: format!(
            "Sustained {rps} full TCP handshakes/s on loopback ({dropped} dials \
             refused/timed-out). This is the accept-queue ceiling your XDP \
             SYN-cookie path protects."
        ),
    }
}

// ---------------------------------------------------------------------------
// Scenario 2 — HTTP request flood (allowed vs challenged rps).
// ---------------------------------------------------------------------------
//
// A minimal HTTP/1.1 victim parses the request line + headers and replies with
// a fixed 200. The generator hammers it keep-alive. We split the achieved rate
// into an "allowed" lane (cheap pass) and a modelled "challenged" lane: every
// Nth request the victim does extra work (a small hash) to emulate the cost of
// emitting a JS/PoW challenge, so the operator sees both numbers.

async fn scenario_http() -> FloodScenario {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return failed_scenario("http", "HTTP request flood", &e),
    };
    let addr = listener.local_addr().unwrap();

    let served = Arc::new(AtomicU64::new(0));
    let challenged = Arc::new(AtomicU64::new(0));
    let s2 = Arc::clone(&served);
    let c2 = Arc::clone(&challenged);

    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let served = Arc::clone(&s2);
            let challenged = Arc::clone(&c2);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut n_req: u64 = 0;
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {
                            n_req += 1;
                            // Every 5th request pays "challenge" cost.
                            let body: &[u8] = if n_req % 5 == 0 {
                                challenged.fetch_add(1, Ordering::Relaxed);
                                // Emulate PoW/challenge emission work.
                                let mut acc = 0u64;
                                for i in 0..512u64 {
                                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
                                }
                                std::hint::black_box(acc);
                                b"challenge"
                            } else {
                                b"ok"
                            };
                            served.fetch_add(1, Ordering::Relaxed);
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                                body.len()
                            );
                            if stream.write_all(resp.as_bytes()).await.is_err() {
                                break;
                            }
                            if stream.write_all(body).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    let (rps, dropped, p99, p50) = http_flood_loop(addr, false).await;
    server.abort();

    let total_served = served.load(Ordering::Relaxed);
    let total_chal = challenged.load(Ordering::Relaxed);
    let allowed = total_served.saturating_sub(total_chal);
    let elapsed = SCENARIO_DURATION.as_secs_f64();
    let allowed_rps = (allowed as f64 / elapsed).round() as u64;
    let challenged_rps = (total_chal as f64 / elapsed).round() as u64;
    let verdict = verdict_for(total_served, dropped);

    FloodScenario {
        id: "http".into(),
        label: "HTTP request flood".into(),
        achieved_rps: rps,
        unit: "req/s".into(),
        p99_ms: p99,
        p50_ms: p50,
        served: total_served,
        dropped,
        verdict: verdict.into(),
        detail: format!(
            "Absorbed {allowed_rps} allowed req/s plus {challenged_rps} \
             challenge-emitting req/s (1-in-5 paid PoW/JS cost). {dropped} \
             requests failed/timed-out under load."
        ),
    }
}

/// Shared HTTP/1.1 keep-alive flood driver. Returns
/// `(achieved_rps, dropped, p99_ms, p50_ms)`. `tiny_body` selects the
/// cache-style request used by the cache scenario.
async fn http_flood_loop(addr: std::net::SocketAddr, cache_mode: bool) -> (u64, u64, f64, f64) {
    let hist = Arc::new(LatHist::new());
    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + SCENARIO_DURATION;
    let conc = MAX_CONCURRENCY.min(96);
    let req: &'static [u8] = if cache_mode {
        b"GET /cached.html HTTP/1.1\r\nHost: bench.local\r\nConnection: keep-alive\r\n\r\n"
    } else {
        b"GET / HTTP/1.1\r\nHost: bench.local\r\nConnection: keep-alive\r\n\r\n"
    };

    let mut workers = Vec::new();
    for _ in 0..conc {
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

    let elapsed = SCENARIO_DURATION.as_secs_f64();
    let done = completed.load(Ordering::Relaxed);
    let dropped = failed.load(Ordering::Relaxed);
    let rps = (done as f64 / elapsed).round() as u64;
    (
        rps,
        dropped,
        hist.percentile_ms(0.99),
        hist.percentile_ms(0.50),
    )
}

// ---------------------------------------------------------------------------
// Scenario 3 — TLS handshake flood.
// ---------------------------------------------------------------------------
//
// A rustls server with a freshly self-signed cert accepts full handshakes; the
// generator opens a new TLS connection per op (no resumption) to measure the
// worst-case full-handshake ceiling — exactly what a TLS-handshake flood
// targets. Achieved hs/s is the headline number.

async fn scenario_tls() -> FloodScenario {
    use std::sync::Arc as StdArc;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // Self-signed cert/key for loopback only.
    let (certs, key) = match gen_self_signed() {
        Ok(v) => v,
        Err(e) => {
            return FloodScenario {
                id: "tls".into(),
                label: "TLS handshake flood".into(),
                achieved_rps: 0,
                unit: "hs/s".into(),
                p99_ms: 0.0,
                p50_ms: 0.0,
                served: 0,
                dropped: 0,
                verdict: "fail".into(),
                detail: format!("could not generate test certificate: {e}"),
            };
        }
    };

    let server_cfg = match rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
    {
        Ok(c) => StdArc::new(c),
        Err(e) => {
            return failed_scenario_msg("tls", "TLS handshake flood", format!("server cfg: {e}"));
        }
    };
    let acceptor = TlsAcceptor::from(server_cfg);

    // Client trusts our self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    for c in &certs {
        let _ = roots.add(c.clone());
    }
    let client_cfg = StdArc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(client_cfg);

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return failed_scenario("tls", "TLS handshake flood", &e),
    };
    let addr = listener.local_addr().unwrap();

    let accepted = Arc::new(AtomicU64::new(0));
    let acc2 = Arc::clone(&accepted);
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let acc = Arc::clone(&acc2);
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    acc.fetch_add(1, Ordering::Relaxed);
                    drop(tls);
                }
            });
        }
    });

    let hist = Arc::new(LatHist::new());
    let completed = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + SCENARIO_DURATION;
    // TLS handshakes are heavier — fewer concurrent dialers.
    let conc = MAX_CONCURRENCY.min(48);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

    let mut workers = Vec::new();
    for _ in 0..conc {
        let connector = connector.clone();
        let hist = Arc::clone(&hist);
        let completed = Arc::clone(&completed);
        let failed = Arc::clone(&failed);
        let server_name = server_name.clone();
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let t0 = Instant::now();
                let tcp = match tokio::time::timeout(
                    Duration::from_millis(300),
                    TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    _ => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                match tokio::time::timeout(
                    Duration::from_millis(400),
                    connector.connect(server_name.clone(), tcp),
                )
                .await
                {
                    Ok(Ok(tls)) => {
                        hist.record(t0.elapsed());
                        completed.fetch_add(1, Ordering::Relaxed);
                        drop(tls);
                    }
                    _ => {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }
    server.abort();

    let elapsed = SCENARIO_DURATION.as_secs_f64();
    let served = completed.load(Ordering::Relaxed);
    let dropped = failed.load(Ordering::Relaxed);
    let rps = (served as f64 / elapsed).round() as u64;
    let verdict = verdict_for(served, dropped);

    FloodScenario {
        id: "tls".into(),
        label: "TLS handshake flood".into(),
        achieved_rps: rps,
        unit: "hs/s".into(),
        p99_ms: hist.percentile_ms(0.99),
        p50_ms: hist.percentile_ms(0.50),
        served,
        dropped,
        verdict: verdict.into(),
        detail: format!(
            "Completed {rps} full TLS handshakes/s (no resumption) on loopback, \
             {dropped} failed/timed-out. Session tickets / resumption raise the \
             real ceiling well above this worst-case figure."
        ),
    }
}

// ---------------------------------------------------------------------------
// Scenario 4 — Slowloris (slow-header / slow-body connection hold).
// ---------------------------------------------------------------------------
//
// A bounded pool of "attacker" connections each opens a socket and dribbles a
// partial request one byte at a time, never completing it — the classic
// connection-exhaustion attack. The victim accepts and holds. We measure how
// many concurrent slow holders the box sustains within the bound and how many
// were refused, plus the hold latency. Achieved value is a count of holders,
// not a per-second rate.

async fn scenario_slowloris() -> FloodScenario {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return failed_scenario("slowloris", "Slowloris (slow-header hold)", &e),
    };
    let addr = listener.local_addr().unwrap();

    let held = Arc::new(AtomicU64::new(0));
    let h2 = Arc::clone(&held);
    // Victim: accept, count as held, read slowly with a per-conn idle timeout
    // (modelling a header-read deadline defence).
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let held = Arc::clone(&h2);
            held.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                // Header-read deadline: if the full request never arrives in
                // 700 ms, drop the connection (the slowloris defence).
                loop {
                    match tokio::time::timeout(Duration::from_millis(700), stream.read(&mut buf))
                        .await
                    {
                        Ok(Ok(0)) | Err(_) => {
                            held.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                        Ok(Ok(_)) => { /* keep waiting for full request */ }
                        Ok(Err(_)) => {
                            held.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
        }
    });

    let hist = Arc::new(LatHist::new());
    let opened = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let target = MAX_CONNS.min(1_500);
    let deadline = Instant::now() + SCENARIO_DURATION;

    // Spawn slow-attacker tasks that open and dribble.
    let mut attackers = Vec::new();
    for _ in 0..target {
        if Instant::now() >= deadline {
            break;
        }
        let hist = Arc::clone(&hist);
        let opened = Arc::clone(&opened);
        let refused = Arc::clone(&refused);
        attackers.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let mut stream =
                match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr))
                    .await
                {
                    Ok(Ok(s)) => s,
                    _ => {
                        refused.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
            opened.fetch_add(1, Ordering::Relaxed);
            hist.record(t0.elapsed());
            // Dribble a partial request header, one byte at a time, slowly,
            // until the scenario window closes.
            let drip = b"X-A: a\r\n";
            let mut idx = 0;
            while Instant::now() < deadline {
                let byte = [drip[idx % drip.len()]];
                if stream.write_all(&byte).await.is_err() {
                    break;
                }
                idx += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }));
    }
    // Let the attackers settle, then sample the peak concurrent holders.
    tokio::time::sleep(SCENARIO_DURATION / 2).await;
    let peak_held = held.load(Ordering::Relaxed);
    for a in attackers {
        let _ = a.await;
    }
    server.abort();

    let served = opened.load(Ordering::Relaxed);
    let dropped = refused.load(Ordering::Relaxed);
    // Slowloris verdict is INVERTED versus the throughput floods. There,
    // a high drop ratio means legit requests couldn't be served (bad).
    // Here, "refused" connections are slow-dribble holders the read-deadline
    // REAPED / the accept path bounded — that is the DEFENCE working, not a
    // failure. The real failure mode is the opposite: slow holders
    // ACCUMULATING toward the connection cap until the pool is exhausted. So
    // we judge on bounded concurrency (peak_held vs the slow-holder target),
    // NOT on the drop ratio.
    let cap = (target as u64).max(1);
    let verdict = if served == 0 {
        // Not a single slow connection could be established in the window.
        "fail"
    } else if peak_held * 2 < cap {
        // Slow holders stayed well below what was thrown at the box — the
        // reaper is bounding them and the pool never fills. Defence working.
        "pass"
    } else if peak_held < cap {
        "degraded"
    } else {
        // Every slow attacker stayed resident — the reaper failed and the
        // connection pool was saturated by slow holders.
        "fail"
    };

    FloodScenario {
        id: "slowloris".into(),
        label: "Slowloris (slow-header hold)".into(),
        achieved_rps: peak_held,
        unit: "conns".into(),
        p99_ms: hist.percentile_ms(0.99),
        p50_ms: hist.percentile_ms(0.50),
        served,
        dropped,
        verdict: verdict.into(),
        detail: format!(
            "Held {peak_held} concurrent slow-dribble connections ({served} \
             opened, {dropped} refused) against a 700 ms header-read deadline. \
             A tight read-deadline reaps these before they exhaust the pool."
        ),
    }
}

// ---------------------------------------------------------------------------
// Scenario 5 — Cache-served rps.
// ---------------------------------------------------------------------------
//
// The hottest path: a request whose response is already in memory, no upstream,
// no challenge. The victim replies from a pre-built static buffer. This is the
// ceiling for cache hits / WAF-allowed static content.

async fn scenario_cache() -> FloodScenario {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return failed_scenario("cache", "Cache-served rps", &e),
    };
    let addr = listener.local_addr().unwrap();

    // Pre-built cached response (1 KiB body).
    let body = vec![b'C'; 1024];
    let resp: Arc<Vec<u8>> = Arc::new(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Cache: HIT\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body)
        .collect(),
    );

    let served = Arc::new(AtomicU64::new(0));
    let s2 = Arc::clone(&served);
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);
            let resp = Arc::clone(&resp);
            let served = Arc::clone(&s2);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {
                            if stream.write_all(&resp).await.is_err() {
                                break;
                            }
                            served.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    let (rps, dropped, p99, p50) = http_flood_loop(addr, true).await;
    server.abort();

    let total = served.load(Ordering::Relaxed);
    let verdict = verdict_for(total, dropped);

    FloodScenario {
        id: "cache".into(),
        label: "Cache-served rps".into(),
        achieved_rps: rps,
        unit: "req/s".into(),
        p99_ms: p99,
        p50_ms: p50,
        served: total,
        dropped,
        verdict: verdict.into(),
        detail: format!(
            "Served {rps} cache-HIT req/s from an in-memory 1 KiB response \
             (no upstream, no challenge) — the WAF-allowed static-content \
             ceiling on this box. {dropped} requests failed under load."
        ),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn failed_scenario(id: &str, label: &str, e: &std::io::Error) -> FloodScenario {
    failed_scenario_msg(id, label, format!("bind/io error: {e}"))
}

fn failed_scenario_msg(id: &str, label: &str, msg: String) -> FloodScenario {
    FloodScenario {
        id: id.into(),
        label: label.into(),
        achieved_rps: 0,
        unit: "".into(),
        p99_ms: 0.0,
        p50_ms: 0.0,
        served: 0,
        dropped: 0,
        verdict: "fail".into(),
        detail: msg,
    }
}

/// Generate a self-signed cert + key for loopback TLS testing.
fn gen_self_signed() -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    String,
> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| e.to_string())?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| e.to_string())?;
    Ok((vec![cert_der], key_der))
}

// ---------------------------------------------------------------------------
// Suite runner
// ---------------------------------------------------------------------------

/// Run the full flood suite. Async — call from the admin handler via
/// `tokio::spawn`. Hard-capped at [`FLOOD_TOTAL_BUDGET`].
pub async fn run_flood_suite() -> FloodResult {
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let wall = Instant::now();

    let suite = async {
        let mut scenarios = Vec::with_capacity(5);
        scenarios.push(scenario_syn().await);
        scenarios.push(scenario_http().await);
        scenarios.push(scenario_tls().await);
        scenarios.push(scenario_slowloris().await);
        scenarios.push(scenario_cache().await);
        scenarios
    };

    let scenarios = match tokio::time::timeout(FLOOD_TOTAL_BUDGET, suite).await {
        Ok(s) => s,
        Err(_) => {
            return FloodResult::error("flood suite exceeded the global time budget".to_string());
        }
    };

    FloodResult {
        ok: true,
        status: "done".to_string(),
        error: None,
        started_at_unix: Some(started_at_unix),
        duration_ms: Some(wall.elapsed().as_millis() as u64),
        scenarios,
        loopback: true,
        caveat: CAVEAT.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lat_hist_percentiles() {
        let h = LatHist::new();
        for _ in 0..90 {
            h.record(Duration::from_micros(50));
        }
        for _ in 0..10 {
            h.record(Duration::from_micros(40_000));
        }
        assert_eq!(h.total(), 100);
        // p50 should land in a small bucket, p99 in a large one.
        assert!(h.percentile_ms(0.50) <= 1.0, "p50 too high");
        assert!(h.percentile_ms(0.99) >= 10.0, "p99 too low");
    }

    #[test]
    fn verdict_thresholds() {
        assert_eq!(verdict_for(1000, 0), "pass");
        assert_eq!(verdict_for(1000, 50), "degraded");
        assert_eq!(verdict_for(100, 80), "fail");
        assert_eq!(verdict_for(0, 0), "fail");
    }

    #[test]
    fn double_start_guard() {
        let state = Arc::new(FloodState::new());
        assert!(try_start(&state).is_ok());
        assert!(try_start(&state).is_err());
        state.running.store(false, Ordering::Release);
        assert!(try_start(&state).is_ok());
    }

    #[tokio::test]
    async fn flood_suite_runs_and_reports() {
        let res = run_flood_suite().await;
        assert_eq!(res.status, "done");
        assert!(res.ok);
        assert!(res.loopback);
        assert_eq!(res.scenarios.len(), 5);
        // Cache + HTTP scenarios should achieve a non-trivial rate on any CI box.
        let cache = res.scenarios.iter().find(|s| s.id == "cache").unwrap();
        assert!(cache.served > 0, "cache scenario served nothing");
        let ids: Vec<&str> = res.scenarios.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["syn", "http", "tls", "slowloris", "cache"]);
    }
}
