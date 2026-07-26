//! V240 — server hardware benchmark + capacity projection for the admin panel.
//!
//! Runs three micro-benchmarks (CPU integer, SHA-256 throughput, memory
//! bandwidth) against a hard ~2.5-second wall cap, then projects expected
//! forwarding / TLS / WAF RPS using calibration constants measured against
//! a known 8-core reference box.
//!
//! ## Accuracy caveat
//!
//! ALL numbers are marked `estimate: true`. The projections scale linearly
//! from micro-benchmark scores and do NOT account for request mix, upstream
//! latency, NIC headroom, kernel scheduling, TLS session-resumption ratio or
//! real load distribution. Use them as a rough order-of-magnitude baseline,
//! not a capacity SLA.
//!
//! ## Concurrency model
//!
//! [`BenchState`] holds an [`AtomicBool`] CAS gate so only one benchmark
//! runs at a time. [`run_benchmark`] is a synchronous function meant to be
//! called from `tokio::task::spawn_blocking`. The caller (admin handler)
//! stores the result via [`arc_swap::ArcSwap`] so readers never block.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Capacity-model constants (matched to pow_captcha.rs reference measurement)
// ---------------------------------------------------------------------------

/// Reference single-core SHA-256 throughput for the 8-core calibration box
/// (matches `pow_captcha.rs` reference, MH/s per core).
const REF_SHA256_MHS: f64 = 30.0;

/// Forwarding RPS per core at the reference clock speed (8-core midpoint).
const K_FWD_PER_CORE: f64 = 55_000.0;

/// TLS full-handshake RPS per core at the reference clock speed.
const REF_TLS_HS_PER_CORE: f64 = 3_700.0;

/// Calibration note appended to every result.
const CALIBRATION_NOTE: &str = "ESTIMATE — projected from micro-benchmark \
    scores against a measured 8-core reference; real throughput depends on \
    request mix, TLS ratio, upstream latency and load.";

// ---------------------------------------------------------------------------
// Result structs (serde field names must match the frontend contract exactly)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct HardwareFacts {
    pub cpu_model: String,
    pub cpu_count: usize,
    pub ram_total_mb: u64,
    pub ram_available_mb: u64,
    pub arch: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchScores {
    pub cpu_integer_gops: f64,
    pub sha256_mhash_per_sec: f64,
    pub mem_bw_gbps: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchProjections {
    pub est_fwd_rps: u64,
    pub est_tls_rps: u64,
    pub est_waf_rps: u64,
    /// One of: "throughput_optimal" | "clock_bound" | "core_count" | "reuseport_off"
    pub bottleneck: String,
    pub bottleneck_detail: String,
    pub reuseport_factor: f64,
}

/// The full benchmark result — serialised as the GET /admin/api/benchmark/result body.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkResult {
    pub ok: bool,
    /// "idle" | "running" | "done" | "error"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<HardwareFacts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<BenchScores>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projections: Option<BenchProjections>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calibration_note: Option<String>,
    pub estimate: bool,
}

impl BenchmarkResult {
    /// Construct the "idle" sentinel (never run / not running).
    pub fn idle() -> Self {
        Self {
            ok: true,
            status: "idle".to_string(),
            error: None,
            started_at_unix: None,
            duration_ms: None,
            hardware: None,
            scores: None,
            projections: None,
            calibration_note: None,
            estimate: true,
        }
    }

    /// Construct the "running" sentinel (poll again shortly).
    pub fn running(started_at_unix: u64) -> Self {
        Self {
            ok: true,
            status: "running".to_string(),
            error: None,
            started_at_unix: Some(started_at_unix),
            duration_ms: None,
            hardware: None,
            scores: None,
            projections: None,
            calibration_note: None,
            estimate: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared state — one per AdminProxy clone tree
// ---------------------------------------------------------------------------

/// Shared benchmark state. Wrap in `Arc<BenchState>` and clone into every
/// admin handler.
pub struct BenchState {
    /// CAS guard: `true` while a benchmark is in progress.
    pub running: AtomicBool,
    /// Most-recent result. `None` = never run.
    pub result: ArcSwap<Option<BenchmarkResult>>,
    /// Unix-second timestamp of the most recent `run` call (set before the
    /// heavy work starts so the "running" response can surface it).
    pub started_at: AtomicBool, // reused as a "we have a timestamp" flag
    pub started_at_unix: std::sync::atomic::AtomicU64,
}

impl BenchState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            result: ArcSwap::from_pointee(None),
            started_at: AtomicBool::new(false),
            started_at_unix: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for BenchState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// /proc/meminfo parser (Linux only)
// ---------------------------------------------------------------------------

/// Returns `(total_mb, available_mb)`. Falls back to `(0, 0)` on non-Linux
/// or when `/proc/meminfo` is unreadable.
fn parse_meminfo() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let raw = match std::fs::read_to_string("/proc/meminfo") {
            Ok(r) => r,
            Err(_) => return (0, 0),
        };
        let mut total_kb: u64 = 0;
        let mut avail_kb: u64 = 0;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                total_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                avail_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        (total_kb / 1024, avail_kb / 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (0, 0)
    }
}

// ---------------------------------------------------------------------------
// Micro-benchmarks
// ---------------------------------------------------------------------------

/// CPU integer throughput. Runs a tight `u64` XOR+rotate loop for `ms`
/// milliseconds and returns giga-operations per second.
pub fn bench_cpu_integer(ms: u64) -> f64 {
    let deadline = Duration::from_millis(ms);
    let start = Instant::now();
    let mut x: u64 = 0xDEAD_BEEF_CAFE_1234;
    let mut ops: u64 = 0;
    // Inner batch: 1024 iterations per check to amortise `Instant::now()` cost.
    const BATCH: u64 = 1024;
    loop {
        for _ in 0..BATCH {
            x ^= x.wrapping_shl(13);
            x ^= x.wrapping_shr(7);
            x ^= x.wrapping_shl(17);
            x = x.rotate_left(32);
        }
        ops += BATCH * 4; // 4 ops per iteration
        if start.elapsed() >= deadline {
            break;
        }
    }
    // Prevent optimising away x.
    let _ = std::hint::black_box(x);
    let secs = start.elapsed().as_secs_f64().max(1e-9);
    (ops as f64) / secs / 1e9
}

/// SHA-256 throughput. Digests a 64-byte buffer in a tight loop for `ms`
/// milliseconds and returns MH/s (mega-hashes per second).
pub fn bench_sha256(ms: u64) -> f64 {
    let deadline = Duration::from_millis(ms);
    let start = Instant::now();
    let buf = [0xAB_u8; 64];
    let mut hashes: u64 = 0;
    const BATCH: u64 = 256;
    loop {
        for _ in 0..BATCH {
            let _ = std::hint::black_box(Sha256::digest(std::hint::black_box(&buf)));
        }
        hashes += BATCH;
        if start.elapsed() >= deadline {
            break;
        }
    }
    let secs = start.elapsed().as_secs_f64().max(1e-9);
    (hashes as f64) / secs / 1e6
}

/// Memory bandwidth benchmark. Allocates a ~64 MiB `Vec<u64>`, performs a
/// sequential write pass followed by a read-back pass, and returns GB/s.
pub fn bench_memory_bw() -> f64 {
    const ELEM: usize = 8 * 1024 * 1024; // 8M u64 = 64 MiB
    let mut buf: Vec<u64> = vec![0u64; ELEM];

    let start = Instant::now();
    // Write pass.
    for (i, v) in buf.iter_mut().enumerate() {
        *v = i as u64;
    }
    // Read-back pass (prevent elision).
    let mut sink: u64 = 0;
    for v in &buf {
        sink ^= v;
    }
    let _ = std::hint::black_box(sink);
    let elapsed = start.elapsed().as_secs_f64().max(1e-9);

    // Two passes × 64 MiB each = 128 MiB total IO.
    let bytes = (ELEM * std::mem::size_of::<u64>() * 2) as f64;
    bytes / elapsed / 1e9
}

// ---------------------------------------------------------------------------
// Projection model
// ---------------------------------------------------------------------------

/// Detect the REUSEPORT factor from environment / worker count heuristic.
///
/// Returns `(factor, reuseport_on)`:
/// - `0.90` when REUSEPORT appears active (env `AEGIS_PINGORA_REUSEPORT=1` or
///   multiple live worker processes detected via topology).
/// - `0.35` when REUSEPORT appears off (single-socket-lock contention).
fn detect_reuseport() -> (f64, bool) {
    // Explicit env-var override.
    if let Ok(v) = std::env::var("AEGIS_PINGORA_REUSEPORT") {
        let on = matches!(v.trim(), "1" | "true" | "yes");
        let factor = if on { 0.90 } else { 0.35 };
        return (factor, on);
    }
    // Fallback: count live aegis-pingora workers via topology.
    #[cfg(target_os = "linux")]
    {
        let workers = crate::topology::enumerate_workers();
        if workers.len() > 1 {
            return (0.90, true);
        }
    }
    // Default: assume REUSEPORT on (most deployments use it).
    (0.90, true)
}

fn compute_projections(
    scores: &BenchScores,
    cpu_count: usize,
    running_workers: usize,
) -> BenchProjections {
    let (reuseport_factor, reuseport_on) = detect_reuseport();

    let clock_ratio = scores.sha256_mhash_per_sec / REF_SHA256_MHS;
    let n = cpu_count as f64;

    let est_fwd_rps = (K_FWD_PER_CORE * clock_ratio * n * 0.93 * reuseport_factor).round() as u64;
    let est_tls_rps = (REF_TLS_HS_PER_CORE * clock_ratio * n * reuseport_factor).round() as u64;
    let est_waf_rps = (est_fwd_rps as f64 * 0.85).round() as u64;

    // Bottleneck classification (in priority order).
    let (bottleneck, bottleneck_detail) = if !reuseport_on && running_workers > 1 {
        (
            "reuseport_off".to_string(),
            format!(
                "REUSEPORT appears disabled with {running_workers} workers — \
                 all workers compete for a single accept lock (factor {reuseport_factor:.2}). \
                 Enable SO_REUSEPORT to recover ~2.5× throughput."
            ),
        )
    } else if running_workers < cpu_count && running_workers > 0 {
        (
            "core_count".to_string(),
            format!(
                "{running_workers} running workers on {cpu_count} cores — \
                 {} core(s) sitting idle. Add workers to match core count.",
                cpu_count - running_workers
            ),
        )
    } else if scores.sha256_mhash_per_sec < 18.0 {
        (
            "clock_bound".to_string(),
            format!(
                "SHA-256 score {:.1} MH/s is below 18 MH/s threshold — \
                 CPU is heavily throttled, shared/virtualised, or turbo-boost \
                 is off. Clock-limited projections may be pessimistic.",
                scores.sha256_mhash_per_sec
            ),
        )
    } else {
        (
            "throughput_optimal".to_string(),
            format!(
                "Layout looks optimal: {cpu_count} cores, REUSEPORT factor {reuseport_factor:.2}, \
                 clock ratio {clock_ratio:.2}×."
            ),
        )
    };

    BenchProjections {
        est_fwd_rps,
        est_tls_rps,
        est_waf_rps,
        bottleneck,
        bottleneck_detail,
        reuseport_factor,
    }
}

// ---------------------------------------------------------------------------
// Main benchmark runner
// ---------------------------------------------------------------------------

/// Run all three micro-benchmarks and return a complete [`BenchmarkResult`]
/// with `status = "done"`. Hard wall cap: ~2.5 s total.
///
/// Intended to be called from `tokio::task::spawn_blocking`.
/// V242 — clear the CPU-affinity pin inherited from the data-plane worker.
/// The SO_REUSEPORT workers are pinned to ONE core each (CPUAffinity); a
/// benchmark thread spawned inside that worker would otherwise be confined
/// to that single core, so N benchmark threads would oversubscribe one core
/// (4× slower per thread, ~25% total CPU) instead of spreading across the
/// machine. Resetting affinity to all online CPUs lets the benchmark use
/// the whole box — visible load + correct per-core numbers.
#[cfg(target_os = "linux")]
fn unpin_to_all_cores() {
    unsafe {
        let ncpu = libc::sysconf(libc::_SC_NPROCESSORS_ONLN);
        if ncpu <= 0 {
            return;
        }
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        let n = (ncpu as usize).min(libc::CPU_SETSIZE as usize);
        for i in 0..n {
            libc::CPU_SET(i, &mut set);
        }
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}
#[cfg(not(target_os = "linux"))]
fn unpin_to_all_cores() {}

/// V242 — run `f` on every core concurrently and return the AVERAGE
/// per-core result. The previous benchmark ran a single (pinned) core for
/// ~2 s, so on a multi-core host the CPU graph barely moved and operators
/// thought the test "did nothing". Each thread un-pins itself first so the
/// pool genuinely spreads across all cores: the work is visible AND reflects
/// real machine capacity, while averaging keeps the per-core score the
/// throughput projections are calibrated against (est_*_rps already scale by
/// core count + reuseport factor, so the per-core figure must stay per-core).
fn parallel_avg_per_core<F>(cores: usize, f: F) -> f64
where
    F: Fn() -> f64 + Send + Sync + Copy,
{
    let cores = cores.max(1);
    let results: Vec<f64> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..cores)
            .map(|_| {
                s.spawn(move || {
                    unpin_to_all_cores();
                    f()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(0.0))
            .collect()
    });
    results.iter().sum::<f64>() / cores as f64
}

pub fn run_benchmark() -> BenchmarkResult {
    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let wall_start = Instant::now();

    // --- Hardware facts ---
    let (ram_total_mb, ram_available_mb) = parse_meminfo();
    let arch = std::env::consts::ARCH.to_string();

    // Try topology module for CPU facts, fall back to /proc/cpuinfo.
    let host = crate::topology::host_info();
    let cpu_count = host.cpu_count;
    let cpu_model = host.cpu_model.clone();

    let hardware = HardwareFacts {
        cpu_model,
        cpu_count,
        ram_total_mb,
        ram_available_mb,
        arch,
    };

    // --- Time budget: ~2500 ms total, split across the passes ---
    // cpu_integer: 700 ms, sha256: 1000 ms, mem_bw: 1 pass (no time limit).
    // V242 — CPU + SHA passes run on ALL cores at once (visible load +
    // whole-machine measurement); the reported figure is the per-core
    // average so the throughput projections stay calibrated.
    let cpu_integer_gops = parallel_avg_per_core(cpu_count, || bench_cpu_integer(700));
    let sha256_mhash_per_sec = parallel_avg_per_core(cpu_count, || bench_sha256(1000));
    let mem_bw_gbps = bench_memory_bw();

    let duration_ms = wall_start.elapsed().as_millis() as u64;

    let scores = BenchScores {
        cpu_integer_gops,
        sha256_mhash_per_sec,
        mem_bw_gbps,
    };

    // Running worker count for bottleneck detection.
    #[cfg(target_os = "linux")]
    let running_workers = crate::topology::enumerate_workers().len();
    #[cfg(not(target_os = "linux"))]
    let running_workers = cpu_count; // assume optimal on non-Linux

    let projections = compute_projections(&scores, cpu_count, running_workers);

    BenchmarkResult {
        ok: true,
        status: "done".to_string(),
        error: None,
        started_at_unix: Some(started_at_unix),
        duration_ms: Some(duration_ms),
        hardware: Some(hardware),
        scores: Some(scores),
        projections: Some(projections),
        calibration_note: Some(CALIBRATION_NOTE.to_string()),
        estimate: true,
    }
}

// ---------------------------------------------------------------------------
// CAS-guarded start helper used by the admin handler
// ---------------------------------------------------------------------------

/// Try to start a benchmark. Returns `Ok(started_at_unix)` on success, or
/// `Err(())` when another benchmark is already running (caller should 409).
pub fn try_start(state: &Arc<BenchState>) -> Result<u64, ()> {
    state
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| ())?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    state.started_at_unix.store(ts, Ordering::Release);
    state.started_at.store(true, Ordering::Release);
    Ok(ts)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_bench_positive() {
        // 100 ms is plenty to get a non-zero result even on slow CI.
        let mhs = bench_sha256(100);
        assert!(mhs > 0.0, "sha256 bench returned {mhs} — expected > 0");
        // Sanity upper bound: no realistic machine exceeds 10 000 MH/s
        // single-threaded with the sha2 crate (it's not GPU-optimised).
        assert!(
            mhs < 10_000.0,
            "sha256 bench returned {mhs} MH/s — suspiciously high"
        );
    }

    #[test]
    fn run_benchmark_done() {
        let result = run_benchmark();
        assert_eq!(result.status, "done");
        assert!(result.ok);
        assert!(result.hardware.is_some());
        assert!(result.scores.is_some());
        assert!(result.projections.is_some());
        assert!(result.estimate);
        let scores = result.scores.unwrap();
        assert!(scores.sha256_mhash_per_sec > 0.0);
        assert!(scores.cpu_integer_gops > 0.0);
        assert!(scores.mem_bw_gbps > 0.0);
    }

    #[test]
    fn double_run_guard() {
        let state = Arc::new(BenchState::new());
        // First start must succeed.
        assert!(try_start(&state).is_ok());
        // Second start must be rejected while the first is still "running".
        assert!(try_start(&state).is_err());
        // Simulate completion by clearing the flag.
        state.running.store(false, Ordering::Release);
        // Now a third start must succeed again.
        assert!(try_start(&state).is_ok());
    }
}
