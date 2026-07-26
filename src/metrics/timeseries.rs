//! Persistent fleet-wide time-series for the Aegis admin dashboard.
//!
//! # Architecture
//!
//! One [`TimeSeriesStore`] instance lives in each REUSEPORT worker process.
//! All workers read from the cluster mmap (via `snapshot_cluster()`), but
//! only the one that holds an advisory `flock(LOCK_EX | LOCK_NB)` on
//! `.sampler.lock` actually samples and writes. The other workers' counter
//! increments are already visible in the cluster mmap, so a single writer
//! captures the whole fleet — no double-counting.
//!
//! # On-disk layout
//!
//! `$AEGIS_METRICS_DIR` (default `$AEGIS_HOME/metrics`,
//! default `/var/lib/aegis/metrics`):
//!
//! ```text
//! series_1m.bin  — 1-minute resolution, 2880 records (48 h)
//! series_1h.bin  — 1-hour   resolution, 2160 records (90 d)
//! .sampler.lock  — advisory flock, held by the writer worker
//! ```
//!
//! Each file starts with a 16-byte versioned header followed by fixed-size
//! 96-byte records stored as a ring buffer. The `head` field in the header
//! is the index of the *next slot to write* (mod capacity).
//!
//! ## Header (`FileHeader`, 16 bytes)
//!
//! | Offset | Size | Field      |
//! |--------|------|------------|
//! | 0      | 8    | magic      |  `b"AEGISTS1"` (v1)
//! | 8      | 4    | version    |  `1u32` LE
//! | 12     | 4    | head       |  `u32` LE — next-write slot index
//!
//! ## Record (`Point`, 96 bytes, all `u64` LE)
//!
//! `t_unix`, `requests`, `denied`, `challenged`, `rate_limited`, `tarpit`,
//! `rtbh`, `cache_hits`, `cache_misses`, `upstream_2xx`, `upstream_4xx`,
//! `upstream_5xx` — 12 × 8 = 96 bytes.
//!
//! All fields are **delta** counters for the bucket (not cumulative). The
//! query layer computes `allow = max(0, requests − (denied + challenged +
//! rate_limited + tarpit + rtbh))` at read time.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::shared_state::global::{cluster_idx, snapshot_cluster};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every ring file. Changing this forces
/// all existing files to be re-created (migration-safe tombstone).
const FILE_MAGIC: &[u8; 8] = b"AEGISTS1";
/// Format version stored in the header.
const FILE_VERSION: u32 = 1;
/// Size of the binary file header in bytes.
const HEADER_BYTES: u64 = 16;
/// Size of one `Point` record in bytes (12 × u64).
const RECORD_BYTES: u64 = 96;

/// Capacity of the 1-minute ring: 2880 records ≙ 48 hours.
pub const RING_1M_CAPACITY: u32 = 2880;
/// Capacity of the 1-hour ring: 2160 records ≙ 90 days.
pub const RING_1H_CAPACITY: u32 = 2160;

/// Maximum number of data points returned in a single query response.
pub const MAX_RESPONSE_POINTS: usize = 300;

// ── Point ─────────────────────────────────────────────────────────────────────

/// One time-series data point (a single bucket). All counter fields are
/// **deltas** (increments during the bucket interval, not running totals).
///
/// Stored as 12 consecutive little-endian `u64` values on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Point {
    /// Unix timestamp (seconds) of the bucket start.
    pub t_unix: u64,
    /// Total inbound requests during the bucket.
    pub requests: u64,
    /// Requests denied by the filter pipeline.
    pub denied: u64,
    /// Requests answered with a challenge.
    pub challenged: u64,
    /// Requests denied specifically by the rate-limit filter.
    pub rate_limited: u64,
    /// Requests handled by the tarpit.
    pub tarpit: u64,
    /// BGP RTBH announcements triggered.
    pub rtbh: u64,
    /// Threat-aware cache hits.
    pub cache_hits: u64,
    /// Cache misses (fell through to upstream).
    pub cache_misses: u64,
    /// Upstream 2xx responses.
    pub upstream_2xx: u64,
    /// Upstream 4xx responses.
    pub upstream_4xx: u64,
    /// Upstream 5xx responses.
    pub upstream_5xx: u64,
}

impl Point {
    /// Derived field: requests that were **allowed** through to the upstream.
    /// Computed as `requests − (denied + challenged + rate_limited + tarpit + rtbh)`,
    /// floored at zero (protects against transient counter skew).
    pub fn allow(&self) -> u64 {
        let blocked = self
            .denied
            .saturating_add(self.challenged)
            .saturating_add(self.rate_limited)
            .saturating_add(self.tarpit)
            .saturating_add(self.rtbh);
        self.requests.saturating_sub(blocked)
    }

    fn to_bytes(self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        let fields: [u64; 12] = [
            self.t_unix,
            self.requests,
            self.denied,
            self.challenged,
            self.rate_limited,
            self.tarpit,
            self.rtbh,
            self.cache_hits,
            self.cache_misses,
            self.upstream_2xx,
            self.upstream_4xx,
            self.upstream_5xx,
        ];
        for (i, &v) in fields.iter().enumerate() {
            buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        buf
    }

    fn from_bytes(buf: &[u8; 96]) -> Self {
        let u = |i: usize| u64::from_le_bytes(buf[i * 8..(i + 1) * 8].try_into().unwrap());
        Self {
            t_unix: u(0),
            requests: u(1),
            denied: u(2),
            challenged: u(3),
            rate_limited: u(4),
            tarpit: u(5),
            rtbh: u(6),
            cache_hits: u(7),
            cache_misses: u(8),
            upstream_2xx: u(9),
            upstream_4xx: u(10),
            upstream_5xx: u(11),
        }
    }
}

// ── QueryPoint ────────────────────────────────────────────────────────────────

/// A [`Point`] enriched with the derived `allow` field, ready for JSON
/// serialisation and return to the admin panel.
#[derive(Debug, Clone, Serialize)]
pub struct QueryPoint {
    pub t_unix: u64,
    pub requests: u64,
    pub denied: u64,
    pub challenged: u64,
    pub rate_limited: u64,
    pub tarpit: u64,
    pub rtbh: u64,
    /// Requests allowed through to upstream (derived, floored at 0).
    pub allow: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_2xx: u64,
    pub upstream_4xx: u64,
    pub upstream_5xx: u64,
}

impl From<Point> for QueryPoint {
    fn from(p: Point) -> Self {
        Self {
            t_unix: p.t_unix,
            requests: p.requests,
            denied: p.denied,
            challenged: p.challenged,
            rate_limited: p.rate_limited,
            tarpit: p.tarpit,
            rtbh: p.rtbh,
            allow: p.allow(),
            cache_hits: p.cache_hits,
            cache_misses: p.cache_misses,
            upstream_2xx: p.upstream_2xx,
            upstream_4xx: p.upstream_4xx,
            upstream_5xx: p.upstream_5xx,
        }
    }
}

// ── SeriesResponse ────────────────────────────────────────────────────────────

/// JSON-serialisable response for `GET /admin/api/metrics/series?range=…`.
#[derive(Debug, Serialize)]
pub struct SeriesResponse {
    /// `"1m"` when the 1-minute ring was used, `"1h"` for the 1-hour ring.
    pub resolution: &'static str,
    pub points: Vec<QueryPoint>,
}

// ── RingFile ──────────────────────────────────────────────────────────────────

/// A fixed-size binary ring-buffer file with a versioned header.
struct RingFile {
    file: File,
    capacity: u32,
    head: u32,
}

impl RingFile {
    /// Open or create a ring file at `path`. If the file exists but has a
    /// wrong magic/version it is truncated and re-initialised (safe across
    /// format upgrades).
    fn open_or_create(path: &Path, capacity: u32) -> std::io::Result<Self> {
        let file_size = HEADER_BYTES + RECORD_BYTES * u64::from(capacity);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Explicitly NOT truncating: this is a fixed-size ring buffer that
            // is re-validated from its header below. Truncating on open would
            // discard every recorded sample on restart.
            .truncate(false)
            .open(path)?;

        // Try to read + validate existing header.
        let head = Self::read_head_validated(&mut file, capacity)?;

        // If the file is smaller than expected, pre-allocate with zeros.
        let current_len = file.metadata()?.len();
        if current_len < file_size {
            // seek to the last byte and write a zero to extend the file.
            file.seek(SeekFrom::Start(file_size - 1))?;
            file.write_all(&[0u8])?;
            file.flush()?;
        }

        Ok(Self {
            file,
            capacity,
            head,
        })
    }

    /// Read the header and validate it. If invalid or the file is too small,
    /// write a fresh header and return head=0.
    fn read_head_validated(file: &mut File, capacity: u32) -> std::io::Result<u32> {
        let meta = file.metadata()?;

        if meta.len() >= HEADER_BYTES {
            let mut hdr = [0u8; 16];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut hdr)?;

            let magic_ok = &hdr[..8] == FILE_MAGIC;
            let version_ok = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) == FILE_VERSION;
            let head = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
            let head_ok = head < capacity;

            if magic_ok && version_ok && head_ok {
                return Ok(head);
            }
        }

        // Fresh initialisation.
        file.seek(SeekFrom::Start(0))?;
        let mut hdr = [0u8; HEADER_BYTES as usize];
        hdr[..8].copy_from_slice(FILE_MAGIC);
        hdr[8..12].copy_from_slice(&FILE_VERSION.to_le_bytes());
        hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
        file.write_all(&hdr)?;
        file.flush()?;
        Ok(0)
    }

    /// Append a record, advancing the head. Overwrites the oldest entry when
    /// the ring is full (standard ring-buffer semantics).
    fn append(&mut self, point: Point) -> std::io::Result<()> {
        let slot = self.head;
        let offset = HEADER_BYTES + RECORD_BYTES * u64::from(slot);
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&point.to_bytes())?;

        // Advance head and persist it.
        self.head = (slot + 1) % self.capacity;
        self.flush_head()?;
        Ok(())
    }

    fn flush_head(&mut self) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(12))?;
        self.file.write_all(&self.head.to_le_bytes())?;
        self.file.flush()
    }

    /// Read up to `n` most-recent records (in chronological order).
    /// Returns fewer records if the ring is not yet full.
    fn read_recent(&mut self, n: usize) -> std::io::Result<Vec<Point>> {
        let cap = self.capacity as usize;
        let n = n.min(cap);

        // Read the whole ring to avoid multiple seeks.
        let file_size = HEADER_BYTES + RECORD_BYTES * self.capacity as u64;
        let mut raw = vec![0u8; file_size as usize];
        self.file.seek(SeekFrom::Start(0))?;
        let read = self.file.read(&mut raw)?;
        let raw = &raw[..read];

        let data_start = HEADER_BYTES as usize;
        let available_bytes = raw.len().saturating_sub(data_start);
        let available_records = (available_bytes / RECORD_BYTES as usize).min(cap);

        if available_records == 0 {
            return Ok(vec![]);
        }

        let head = self.head as usize;

        // Build ordered slice: oldest first.
        let mut records = Vec::with_capacity(n.min(available_records));
        for i in 0..available_records {
            // Start from head (oldest), wrap around.
            let slot = (head + i) % available_records;
            let off = data_start + slot * RECORD_BYTES as usize;
            if off + RECORD_BYTES as usize > raw.len() {
                break;
            }
            let mut buf = [0u8; 96];
            buf.copy_from_slice(&raw[off..off + RECORD_BYTES as usize]);
            let p = Point::from_bytes(&buf);
            if p.t_unix > 0 {
                records.push(p);
            }
        }

        // Take the most-recent `n` from chronological order.
        let start = records.len().saturating_sub(n);
        Ok(records[start..].to_vec())
    }
}

// ── Single-writer lock ────────────────────────────────────────────────────────

/// Try to acquire an exclusive non-blocking advisory lock on `path`.
/// Returns `Some(File)` if this process is the writer, `None` if another
/// process already holds it.
fn try_acquire_writer_lock(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        // Lock file: opened only to hold a flock, never rewritten.
        .truncate(false)
        .open(path)
        .ok()?;

    let fd = file.as_raw_fd();
    // LOCK_EX | LOCK_NB: exclusive, non-blocking.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 { Some(file) } else { None }
}

// ── TimeSeriesStore ───────────────────────────────────────────────────────────

/// Inner mutable state of the sampler, protected by a `Mutex`.
struct SamplerState {
    /// The lock file handle. While this `File` is open and locked, this
    /// worker is the writer. When dropped the lock is released.
    _lock: File,
    ring_1m: RingFile,
    ring_1h: RingFile,
    /// Previous cluster counter snapshot (for delta computation).
    prev_snapshot: Vec<u64>,
    /// In-progress accumulator for the 1h bucket.
    hour_accum: Point,
    /// Number of 1m samples accumulated into `hour_accum`.
    hour_samples: u32,
    /// Unix timestamp (seconds) of the hour in progress.
    hour_start: u64,
}

/// Fleet-wide persistent time-series store.
///
/// Instantiate once per process, then call [`sample_once`] every 60 seconds
/// from the background tick. Only the worker that wins the advisory lock
/// actually writes; the others call `sample_once` and silently no-op.
///
/// Call [`query`] from the admin API handler to retrieve data.
pub struct TimeSeriesStore {
    dir: PathBuf,
    /// `None` when this worker is not the designated writer.
    state: Mutex<Option<SamplerState>>,
}

impl TimeSeriesStore {
    /// Create or open the store. `dir` is created if it does not exist.
    ///
    /// Immediately tries to acquire the advisory writer lock. If another
    /// process already holds it this instance operates in read-only mode
    /// (`sample_once` is a no-op, `query` still reads the files written by
    /// the writer).
    pub fn new(dir: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(&dir)?;

        let lock_path = dir.join(".sampler.lock");
        let ring1m_path = dir.join("series_1m.bin");
        let ring1h_path = dir.join("series_1h.bin");

        let state = if let Some(lock) = try_acquire_writer_lock(&lock_path) {
            let ring_1m = RingFile::open_or_create(&ring1m_path, RING_1M_CAPACITY)?;
            let ring_1h = RingFile::open_or_create(&ring1h_path, RING_1H_CAPACITY)?;
            Some(SamplerState {
                _lock: lock,
                ring_1m,
                ring_1h,
                prev_snapshot: vec![0u64; cluster_idx::SLOTS],
                hour_accum: Point::default(),
                hour_samples: 0,
                hour_start: current_hour_start(),
            })
        } else {
            None // reader-only mode
        };

        Ok(Self {
            dir,
            state: Mutex::new(state),
        })
    }

    /// Return the store directory (used in tests and diagnostics).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// True when this instance is the designated writer (holds the lock).
    pub fn is_writer(&self) -> bool {
        self.state.lock().unwrap().as_ref().is_some()
    }

    /// Sample the cluster counters and persist the delta.
    ///
    /// Should be called every 60 seconds. The call is a no-op if this worker
    /// is not the writer (i.e. another worker holds the lock). Never panics.
    pub fn sample_once(&self) {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(error = %e, "timeseries: mutex poisoned, skipping sample");
                return;
            }
        };
        let Some(state) = guard.as_mut() else { return };

        let snap = snapshot_cluster();
        if snap.len() < cluster_idx::SLOTS {
            // Arena not yet initialised — skip this tick.
            return;
        }

        let now = unix_now();

        // Compute deltas vs. the previous sample.
        let delta = |idx: usize| -> u64 {
            if idx < snap.len() && idx < state.prev_snapshot.len() {
                snap[idx].wrapping_sub(state.prev_snapshot[idx])
            } else {
                0
            }
        };

        let point = Point {
            t_unix: now,
            requests: delta(cluster_idx::REQUESTS_TOTAL),
            denied: delta(cluster_idx::REQUESTS_DENIED),
            challenged: delta(cluster_idx::REQUESTS_CHALLENGED),
            rate_limited: delta(cluster_idx::RATE_LIMITED),
            tarpit: delta(cluster_idx::TARPIT),
            rtbh: delta(cluster_idx::RTBH),
            cache_hits: delta(cluster_idx::CACHE_HITS),
            cache_misses: delta(cluster_idx::CACHE_MISSES),
            upstream_2xx: delta(cluster_idx::UPSTREAM_2XX),
            upstream_4xx: delta(cluster_idx::UPSTREAM_4XX),
            upstream_5xx: delta(cluster_idx::UPSTREAM_5XX),
        };

        // Persist the previous snapshot for the next delta.
        state.prev_snapshot = snap;

        // Write to the 1-minute ring.
        if let Err(e) = state.ring_1m.append(point) {
            tracing::warn!(error = %e, "timeseries: failed to write 1m ring");
        }

        // Accumulate into the 1-hour bucket.
        let hour_now = current_hour_start();
        if hour_now != state.hour_start {
            // Hour rolled over: flush the completed accumulator.
            if state.hour_samples > 0 {
                state.hour_accum.t_unix = state.hour_start;
                let flush = state.hour_accum;
                if let Err(e) = state.ring_1h.append(flush) {
                    tracing::warn!(error = %e, "timeseries: failed to write 1h ring");
                }
            }
            // Reset accumulator for the new hour.
            state.hour_start = hour_now;
            state.hour_samples = 0;
            state.hour_accum = Point::default();
        }

        add_to_accum(&mut state.hour_accum, &point);
        state.hour_samples += 1;
    }

    /// Query the time-series data for the requested range.
    ///
    /// - `range_secs <= 172800` (48 h) → reads from the 1-minute ring.
    /// - `range_secs > 172800` → reads from the 1-hour ring.
    ///
    /// Results are downsampled to at most [`MAX_RESPONSE_POINTS`] buckets.
    pub fn query(&self, range_secs: u64) -> std::io::Result<SeriesResponse> {
        let use_1m = range_secs <= 172_800; // ≤ 48 h
        let (resolution, path, capacity) = if use_1m {
            ("1m", self.dir.join("series_1m.bin"), RING_1M_CAPACITY)
        } else {
            ("1h", self.dir.join("series_1h.bin"), RING_1H_CAPACITY)
        };

        // Open the file read-only (works in both writer and reader workers).
        let mut ring = RingFile::open_or_create(&path, capacity)?;

        // Number of records covering the requested range.
        let bucket_secs: u64 = if use_1m { 60 } else { 3600 };
        let requested_records = range_secs.div_ceil(bucket_secs) as usize;
        let records_to_read = requested_records.min(capacity as usize);

        let records = ring.read_recent(records_to_read)?;

        // Filter to only records within the range.
        let cutoff = unix_now().saturating_sub(range_secs);
        let records: Vec<Point> = records.into_iter().filter(|p| p.t_unix >= cutoff).collect();

        // Downsample to at most MAX_RESPONSE_POINTS.
        let points = downsample(records, MAX_RESPONSE_POINTS);

        Ok(SeriesResponse { resolution, points })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The Unix timestamp of the start of the current UTC hour.
fn current_hour_start() -> u64 {
    let now = unix_now();
    now - (now % 3600)
}

/// Accumulate a delta point into an aggregator (field-wise saturating add).
fn add_to_accum(accum: &mut Point, delta: &Point) {
    accum.requests = accum.requests.saturating_add(delta.requests);
    accum.denied = accum.denied.saturating_add(delta.denied);
    accum.challenged = accum.challenged.saturating_add(delta.challenged);
    accum.rate_limited = accum.rate_limited.saturating_add(delta.rate_limited);
    accum.tarpit = accum.tarpit.saturating_add(delta.tarpit);
    accum.rtbh = accum.rtbh.saturating_add(delta.rtbh);
    accum.cache_hits = accum.cache_hits.saturating_add(delta.cache_hits);
    accum.cache_misses = accum.cache_misses.saturating_add(delta.cache_misses);
    accum.upstream_2xx = accum.upstream_2xx.saturating_add(delta.upstream_2xx);
    accum.upstream_4xx = accum.upstream_4xx.saturating_add(delta.upstream_4xx);
    accum.upstream_5xx = accum.upstream_5xx.saturating_add(delta.upstream_5xx);
}

/// Downsample `records` to at most `max_points` by merging consecutive
/// buckets. When `records.len() <= max_points` returns them verbatim
/// (as `QueryPoint`s). Otherwise, groups records into `max_points` bins
/// and sums each bin, using the first record's timestamp as the bin's `t`.
fn downsample(records: Vec<Point>, max_points: usize) -> Vec<QueryPoint> {
    if records.is_empty() {
        return vec![];
    }
    if records.len() <= max_points {
        return records.into_iter().map(QueryPoint::from).collect();
    }

    let mut out = Vec::with_capacity(max_points);
    let n = records.len();
    let bin_size_f = n as f64 / max_points as f64;

    for bin_idx in 0..max_points {
        let start = (bin_idx as f64 * bin_size_f).round() as usize;
        let end = ((bin_idx + 1) as f64 * bin_size_f).round() as usize;
        let end = end.min(n);
        if start >= end {
            continue;
        }
        let mut accum = Point::default();
        accum.t_unix = records[start].t_unix;
        for p in &records[start..end] {
            add_to_accum(&mut accum, p);
        }
        out.push(QueryPoint::from(accum));
    }

    out
}

// ── Default store directory ───────────────────────────────────────────────────

/// Resolve the store directory from environment variables with a fallback.
///
/// Priority: `AEGIS_METRICS_DIR` → `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics`.
pub fn default_store_dir() -> PathBuf {
    if let Ok(v) = std::env::var("AEGIS_METRICS_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    let home = std::env::var("AEGIS_HOME").unwrap_or_else(|_| "/var/lib/aegis".to_string());
    PathBuf::from(home).join("metrics")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a temp directory under `/tmp` with a unique suffix derived from
    /// the test function name. No external crate needed.
    fn tmp_dir_path(name: &str) -> PathBuf {
        let base =
            std::env::temp_dir().join(format!("aegis_ts_test_{name}_{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    // ── Record round-trip ──────────────────────────────────────────────────

    #[test]
    fn point_round_trip() {
        let p = Point {
            t_unix: 1_700_000_000,
            requests: 1234,
            denied: 56,
            challenged: 7,
            rate_limited: 8,
            tarpit: 9,
            rtbh: 2,
            cache_hits: 100,
            cache_misses: 50,
            upstream_2xx: 1000,
            upstream_4xx: 20,
            upstream_5xx: 5,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), 96);
        let p2 = Point::from_bytes(&bytes);
        assert_eq!(p, p2);
    }

    #[test]
    fn point_allow_floored_at_zero() {
        // denied + challenged + rate_limited + tarpit + rtbh > requests
        let p = Point {
            t_unix: 1,
            requests: 10,
            denied: 5,
            challenged: 4,
            rate_limited: 3,
            tarpit: 0,
            rtbh: 0,
            ..Default::default()
        };
        // 5 + 4 + 3 = 12 > 10 → allow = 0
        assert_eq!(p.allow(), 0);
    }

    #[test]
    fn point_allow_normal() {
        let p = Point {
            t_unix: 1,
            requests: 100,
            denied: 10,
            challenged: 5,
            rate_limited: 3,
            tarpit: 2,
            rtbh: 1,
            ..Default::default()
        };
        // 100 - (10+5+3+2+1) = 79
        assert_eq!(p.allow(), 79);
    }

    // ── RingFile wrap-around ───────────────────────────────────────────────

    #[test]
    fn ring_file_wraparound() {
        let dir = tmp_dir_path("wraparound");
        let path = dir.join("test_ring.bin");
        let capacity = 4u32;
        let mut ring = RingFile::open_or_create(&path, capacity).unwrap();

        // Write capacity+2 records (forces wraparound).
        for i in 0..(capacity + 2) {
            let p = Point {
                t_unix: 1000 + u64::from(i),
                requests: u64::from(i),
                ..Default::default()
            };
            ring.append(p).unwrap();
        }

        // Read back — should see at most 4 records (most recent).
        let records = ring.read_recent(capacity as usize).unwrap();
        // All returned records must have t_unix > 0.
        assert!(!records.is_empty());
        for r in &records {
            assert!(r.t_unix >= 1000);
        }
        // The most-recent t_unix should be 1000 + capacity + 1.
        let max_t = records.iter().map(|r| r.t_unix).max().unwrap();
        assert_eq!(max_t, 1000 + u64::from(capacity) + 1);
        cleanup(&dir);
    }

    #[test]
    fn ring_file_header_persisted() {
        let dir = tmp_dir_path("header_persist");
        let path = dir.join("persist_test.bin");

        {
            let mut ring = RingFile::open_or_create(&path, 8).unwrap();
            for i in 0u64..3 {
                ring.append(Point {
                    t_unix: 100 + i,
                    requests: i,
                    ..Default::default()
                })
                .unwrap();
            }
            // head should be 3 after 3 appends.
            assert_eq!(ring.head, 3);
        }

        // Re-open and verify head was persisted.
        let ring2 = RingFile::open_or_create(&path, 8).unwrap();
        assert_eq!(ring2.head, 3);
        cleanup(&dir);
    }

    // ── Downsample bucketing ───────────────────────────────────────────────

    #[test]
    fn downsample_no_op_when_under_limit() {
        let records: Vec<Point> = (0..10u64)
            .map(|i| Point {
                t_unix: i,
                requests: i,
                ..Default::default()
            })
            .collect();
        let out = downsample(records, 300);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn downsample_reduces_to_max() {
        let records: Vec<Point> = (0..600u64)
            .map(|i| Point {
                t_unix: i,
                requests: 1,
                ..Default::default()
            })
            .collect();
        let out = downsample(records, 300);
        assert!(out.len() <= 300);
        // Each bin sums 2 requests → 2 per QueryPoint.
        for qp in &out {
            assert_eq!(qp.requests, 2, "expected each bin to sum 2 requests");
        }
    }

    #[test]
    fn downsample_empty_input() {
        let out = downsample(vec![], 300);
        assert!(out.is_empty());
    }

    // ── Derived allow field ────────────────────────────────────────────────

    #[test]
    fn derived_allow_in_query_point() {
        let p = Point {
            t_unix: 1,
            requests: 50,
            denied: 10,
            challenged: 5,
            rate_limited: 2,
            tarpit: 1,
            rtbh: 0,
            ..Default::default()
        };
        let qp: QueryPoint = p.into();
        assert_eq!(qp.allow, 32); // 50 - (10+5+2+1) = 32
    }

    // ── 1m → 1h rollover accumulation ─────────────────────────────────────

    #[test]
    fn hour_accumulator_add_to_accum() {
        let mut accum = Point::default();
        for _ in 0..60 {
            add_to_accum(
                &mut accum,
                &Point {
                    t_unix: 1,
                    requests: 1,
                    denied: 1,
                    ..Default::default()
                },
            );
        }
        assert_eq!(accum.requests, 60);
        assert_eq!(accum.denied, 60);
    }

    // ── TimeSeriesStore integration ────────────────────────────────────────

    #[test]
    fn store_new_creates_dir() {
        let dir = tmp_dir_path("store_new");
        let store_dir = dir.join("metrics_test");
        let store = TimeSeriesStore::new(store_dir.clone()).unwrap();
        assert!(store_dir.exists());
        // Whether this process is writer depends on flock availability; either
        // is acceptable in a unit test.
        let _ = store.is_writer();
        cleanup(&dir);
    }

    #[test]
    fn store_query_empty_returns_ok() {
        let dir = tmp_dir_path("store_query_empty");
        let store = TimeSeriesStore::new(dir.join("mq")).unwrap();
        let resp = store.query(3600).unwrap();
        // Empty ring → no points (nothing written yet).
        assert!(resp.points.is_empty());
        // Resolution for ≤48h range should be "1m".
        assert_eq!(resp.resolution, "1m");
        cleanup(&dir);
    }

    #[test]
    fn store_query_1h_resolution_for_large_range() {
        let dir = tmp_dir_path("store_query_1h");
        let store = TimeSeriesStore::new(dir.join("lq")).unwrap();
        // 7-day range → should use "1h" ring.
        let resp = store.query(7 * 24 * 3600).unwrap();
        assert_eq!(resp.resolution, "1h");
        cleanup(&dir);
    }

    /// The two tests below both depend on the process-wide value of
    /// `AEGIS_METRICS_DIR`. `cargo test` runs them on different threads of the
    /// same process, so without this lock the override test can be holding the
    /// env var while the fallback test reads it — which is exactly the
    /// intermittent CI failure this replaces. Serialise them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_store_dir_uses_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Override AEGIS_METRICS_DIR and confirm it's respected.
        // set_var / remove_var are unsafe in Rust 2024; guard with unsafe block.
        let orig = std::env::var("AEGIS_METRICS_DIR").ok();
        // SAFETY: ENV_LOCK serialises every test in this module that touches
        // this variable, and nothing else in the test binary reads it.
        unsafe { std::env::set_var("AEGIS_METRICS_DIR", "/tmp/aegis_metrics_test_override") };
        let d = default_store_dir();
        // Restore before asserting so env isn't left dirty on failure.
        unsafe {
            if let Some(v) = orig {
                std::env::set_var("AEGIS_METRICS_DIR", v);
            } else {
                std::env::remove_var("AEGIS_METRICS_DIR");
            }
        }
        assert_eq!(d, PathBuf::from("/tmp/aegis_metrics_test_override"));
    }

    #[test]
    fn default_store_dir_falls_back_to_default() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let orig = std::env::var("AEGIS_METRICS_DIR").ok();
        // SAFETY: serialised by ENV_LOCK, see above.
        unsafe { std::env::remove_var("AEGIS_METRICS_DIR") };
        let d = default_store_dir();
        unsafe {
            if let Some(v) = orig {
                std::env::set_var("AEGIS_METRICS_DIR", v);
            }
        }
        assert!(
            d.ends_with("metrics"),
            "default store dir should end with 'metrics', got {d:?}"
        );
    }
}
