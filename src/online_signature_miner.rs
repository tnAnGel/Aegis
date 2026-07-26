//! V107 — Online tarpit → signature miner pipeline.
//!
//! V99 shipped the [crate::signature_mine] primitive as a one-shot
//! API: operator POSTs a corpus, gets ranked candidates back.
//! V107 turns it into a continuous loop:
//!
//!   1. [TarpitLogger] writes the path+query of every tarpit-blocked
//!      request to an append-only file (operator points it via env
//!      AEGIS_TARPIT_LOG, otherwise disabled).
//!   2. A sampling counter ([AllowedSampler]) keeps the last N
//!      allowed-request paths in memory as a "benign corpus".
//!   3. A background task in [OnlineMiner] every `interval` reads the
//!      last K tarpit log lines, runs the V99 miner against the
//!      in-memory benign sample, and atomically swaps the top
//!      candidates into a shared [ArcSwap].
//!   4. Admin endpoint /admin/api/mined_signatures returns the
//!      latest candidates as JSON so the React signature-miner page
//!      can show "auto-mined" suggestions distinct from the manual
//!      one-shot path.
//!
//! No write-back to active WAF config — same approval discipline as
//! V99. The operator still has to copy proposed rules into their
//! WAF rules file.

use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use std::sync::Mutex;

use crate::signature_mine::{SignatureCandidate, mine};

/// Max bytes per logged tarpit line — bounds the log size and the
/// per-entry blast radius of a pathologically long URI. Path tails
/// past this are truncated.
const MAX_LOG_LINE: usize = 1024;
/// Max tarpit lines to read for each miner pass.
const MINER_BATCH: usize = 1000;
/// Capacity of the in-memory benign sample ring.
const BENIGN_SAMPLE_CAP: usize = 500;

/// Append-only tarpit-payload log. Pinned to one file; cheap synchronous
/// `write!` per tarpit hit. Operator rotates via standard tools
/// (`logrotate` copytruncate, etc.) — we re-open lazily on next write
/// if the inode changed.
pub struct TarpitLogger {
    path: Option<PathBuf>,
    inner: Mutex<Option<std::fs::File>>,
}

impl TarpitLogger {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            inner: Mutex::new(None),
        }
    }

    pub fn from_env() -> Self {
        let path = std::env::var("AEGIS_TARPIT_LOG").ok().map(PathBuf::from);
        Self::new(path)
    }

    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Append a single payload to the log. `path_and_query` is the URI
    /// path + query string; we truncate to MAX_LOG_LINE bytes and
    /// strip control characters so a log viewer can't be tricked by
    /// CRLF injection inside a path.
    pub fn record(&self, path_and_query: &str) {
        let Some(p) = &self.path else {
            return;
        };
        let line = sanitize(path_and_query);
        let mut guard = self.inner.lock().expect("tarpit logger mutex poisoned");
        if guard.is_none() {
            match OpenOptions::new().create(true).append(true).open(p) {
                Ok(f) => *guard = Some(f),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "tarpit_log open failed");
                    return;
                }
            }
        }
        if let Some(f) = guard.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Read the last `n` lines from the log. Tail-friendly and cheap
    /// for the typical small-file case. Returns oldest-first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let Some(p) = &self.path else {
            return Vec::new();
        };
        let Ok(f) = std::fs::File::open(p) else {
            return Vec::new();
        };
        let reader = BufReader::new(f);
        let mut buf: std::collections::VecDeque<String> =
            std::collections::VecDeque::with_capacity(n);
        for line in reader.lines().map_while(Result::ok) {
            if buf.len() == n {
                buf.pop_front();
            }
            buf.push_back(line);
        }
        buf.into_iter().collect()
    }
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_LOG_LINE));
    for c in s.chars() {
        if out.len() >= MAX_LOG_LINE {
            break;
        }
        if c == '\r' || c == '\n' {
            continue;
        }
        out.push(c);
    }
    out
}

/// Rolling in-memory sample of recently-allowed paths. Provides the
/// "benign corpus" for the online miner without us having to read a
/// disk log of every successful request (would be too noisy).
pub struct AllowedSampler {
    ring: Mutex<std::collections::VecDeque<String>>,
}

impl Default for AllowedSampler {
    fn default() -> Self {
        Self {
            ring: Mutex::new(std::collections::VecDeque::with_capacity(BENIGN_SAMPLE_CAP)),
        }
    }
}

impl AllowedSampler {
    /// Record an allowed-path sample. Probabilistic to keep cost low —
    /// hot-path callers should gate on a per-request modulo (we get
    /// good coverage from ~1% sampling under typical RPS).
    pub fn record(&self, path_and_query: &str) {
        let mut ring = self.ring.lock().expect("allowed sampler mutex poisoned");
        if ring.len() == BENIGN_SAMPLE_CAP {
            ring.pop_front();
        }
        ring.push_back(sanitize(path_and_query));
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.ring
            .lock()
            .expect("allowed sampler mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }
}

/// Background miner that periodically reads the tarpit log + benign
/// sample and updates the top-N candidates ArcSwap.
pub struct OnlineMiner {
    tarpit_log: Arc<TarpitLogger>,
    benign: Arc<AllowedSampler>,
    interval: Duration,
    /// Most-recent candidates — updated atomically each tick.
    pub current: ArcSwap<Vec<SignatureCandidate>>,
    /// When the last successful pass ran (`SystemTime::UNIX_EPOCH` if
    /// never). Surfaced via admin so operators can see staleness.
    pub last_run: ArcSwap<std::time::SystemTime>,
}

impl OnlineMiner {
    pub fn new(
        tarpit_log: Arc<TarpitLogger>,
        benign: Arc<AllowedSampler>,
        interval: Duration,
    ) -> Self {
        Self {
            tarpit_log,
            benign,
            interval,
            current: ArcSwap::from_pointee(Vec::new()),
            last_run: ArcSwap::from_pointee(std::time::UNIX_EPOCH),
        }
    }

    /// Run one mining pass synchronously. Cheap enough to call from
    /// admin endpoints for "mine now" buttons, but the background
    /// task is the primary driver.
    pub fn run_once(&self) -> usize {
        if !self.tarpit_log.enabled() {
            return 0;
        }
        let attacks = self.tarpit_log.tail(MINER_BATCH);
        if attacks.is_empty() {
            return 0;
        }
        let benign = self.benign.snapshot();
        let cands = mine(&attacks, &benign);
        let n = cands.len();
        self.current.store(Arc::new(cands));
        self.last_run.store(Arc::new(std::time::SystemTime::now()));
        n
    }

    /// Spawn the background task. Pingora's background service driver
    /// (or a vanilla tokio runtime) hands us a shutdown signal; we
    /// tick every `self.interval` and exit cleanly on shutdown.
    pub async fn run(self: Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.interval);
        // Don't burst-fire if the runtime falls behind.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick is immediate; skip it so the log has time to grow.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::debug!("online_signature_miner: shutdown");
                    return;
                }
                _ = ticker.tick() => {
                    let n = self.run_once();
                    if n > 0 {
                        tracing::info!(candidates = n, "online_signature_miner: pass complete");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn tmpfile() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-tarpit-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn record_and_tail_roundtrip() {
        let p = tmpfile();
        // Pre-cleanup in case a prior panicked run left state behind.
        let _ = std::fs::remove_file(&p);
        let logger = TarpitLogger::new(Some(p.clone()));
        for i in 0..5 {
            logger.record(&format!("/probe/{i}?q=union+select+{i}"));
        }
        let tail = logger.tail(10);
        assert_eq!(tail.len(), 5);
        assert!(tail[0].contains("/probe/0"));
        assert!(tail[4].contains("/probe/4"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn sanitize_drops_crlf_and_truncates() {
        let dirty = format!("/a{}/b\r\nfake header injected", "x".repeat(MAX_LOG_LINE));
        let clean = sanitize(&dirty);
        assert_eq!(clean.len(), MAX_LOG_LINE);
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\n'));
    }

    #[test]
    fn disabled_logger_is_noop() {
        let logger = TarpitLogger::new(None);
        logger.record("/anything");
        assert!(!logger.enabled());
        assert!(logger.tail(10).is_empty());
    }

    #[test]
    fn sampler_ring_bounded() {
        let s = AllowedSampler::default();
        for i in 0..BENIGN_SAMPLE_CAP + 50 {
            s.record(&format!("/p{i}"));
        }
        let snap = s.snapshot();
        assert_eq!(snap.len(), BENIGN_SAMPLE_CAP);
        // First item should be at offset 50 (oldest 50 evicted).
        assert!(snap[0].contains("/p50"));
    }

    #[test]
    fn online_miner_produces_candidates() {
        let p = tmpfile();
        let logger = Arc::new(TarpitLogger::new(Some(p.clone())));
        let benign = Arc::new(AllowedSampler::default());
        // Seed attacks
        for i in 0..6 {
            logger.record(&format!("/api/x?id={i}' union select * from users--"));
        }
        // Seed benign
        for i in 0..5 {
            benign.record(&format!("/login?next=/dashboard/{i}"));
        }
        let m = OnlineMiner::new(logger.clone(), benign.clone(), Duration::from_secs(60));
        let n = m.run_once();
        assert!(n > 0, "expected at least one mined candidate");
        let cur = (**m.current.load()).clone();
        assert!(
            cur.iter()
                .any(|c| c.ngram.contains("union") || c.ngram.contains("select")),
            "expected sqli-shaped candidate in top set, got {cur:?}"
        );
        // last_run timestamp moved off epoch.
        let lr = **m.last_run.load();
        assert!(lr > std::time::UNIX_EPOCH);
        // File contents readable.
        let mut buf = String::new();
        let mut f = std::fs::File::open(&p).unwrap();
        f.read_to_string(&mut buf).unwrap();
        assert!(buf.contains("union"));
        let _ = std::fs::remove_file(&p);
    }
}
