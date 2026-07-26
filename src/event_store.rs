//! V243 — Persistent request/event log store.
//!
//! Every request the proxy serves can be recorded as one [`EventRow`] in a
//! local SQLite database. The admin UI reads these rows back to power
//! per-host traffic analytics, the bots/DDoS "over any period" view, WAF
//! hit history, and free-text request search.
//!
//! # Sharding model (mirrors [`crate::site_map`])
//!
//! Each SO_REUSEPORT worker process owns its **own** SQLite file
//! `<dir>/shard-<slot>.db`, where `<slot>` is acquired via a non-blocking
//! advisory `flock` on `<dir>/.slot-<n>.lock` (exactly the same scheme as
//! `site_map`, reusing [`crate::site_map::SiteMap::acquire_slot`]). Because
//! a slot is held for the process lifetime there is exactly **one writer per
//! database file** — so the write path never contends with another process
//! and never blocks on SQLite's busy handler. Dir default
//! `/var/lib/aegis/events`, overridable via `AEGIS_EVENTS_DIR`.
//!
//! The admin read side ([`EventStore::query`] / [`EventStore::stats`]) opens
//! a fresh read-only connection that `ATTACH`es every existing
//! `shard-*.db` and runs `UNION ALL` across them, so a query returns a stable
//! aggregate regardless of which worker handles the admin request.
//!
//! # Hot-path contract (CRITICAL — do not regress)
//!
//! [`EventStore::record`] is called **on the proxy hot path**, once per
//! request, from the `logging()` phase. It MUST be non-blocking and cheap:
//!
//! * It does a `try_send` into a **bounded** channel (capacity
//!   [`CHANNEL_CAP`]). If the channel is full it **drops the row** and bumps
//!   a dropped counter. It NEVER blocks and NEVER touches SQLite on the
//!   caller's thread.
//! * A dedicated background writer thread drains the channel and commits in
//!   **batches** inside a single transaction (flush when the batch reaches
//!   [`BATCH_MAX`] rows OR every [`FLUSH_INTERVAL`]).
//! * The writer thread also runs **retention** (delete rows older than
//!   `AEGIS_EVENTS_RETENTION_DAYS`, default 14) hourly, enforces a hard row
//!   cap as a safety net, and periodically checkpoints the WAL to bound file
//!   size.
//!
//! The team had a production latency outage from doing synchronous logging
//! I/O on the hot path before; the channel + batching design exists
//! specifically to make that impossible again.
//!
//! # Enable gate + sampling
//!
//! * `AEGIS_EVENT_LOG` — default ENABLED. Set to `0` / `false` to disable;
//!   then [`EventStore::record`] is a cheap no-op.
//! * `AEGIS_EVENTS_SAMPLE_PASS` — float in `0.0..=1.0`, default `1.0`. The
//!   fraction of `action == "pass"` rows to keep. All **non-pass** actions
//!   (deny/challenge/tarpit/rate/rtbh/...) are ALWAYS kept. Sampling uses a
//!   cheap counter-based "keep every Nth" sampler — no RNG on the hot path.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Bounded write-channel capacity. At ~200 bytes/row this is a few MiB of
/// worst-case backlog before we start dropping — large enough to absorb a
/// flush stall, small enough to bound memory under sustained overload.
pub const CHANNEL_CAP: usize = 16_384;

/// Flush the batch when it reaches this many rows.
const BATCH_MAX: usize = 1_000;

/// Flush the batch at least this often even if it hasn't filled.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// How often the writer runs retention (delete-old + checkpoint).
const RETENTION_INTERVAL: Duration = Duration::from_secs(3_600);

/// Hard safety-net row cap per shard. If a shard somehow exceeds this we
/// trim the oldest rows down to it regardless of the time-based retention.
const HARD_ROW_CAP: i64 = 5_000_000;

/// Max number of slot files probed when acquiring a worker slot. Matches
/// `site_map::MAX_SLOTS`.
const MAX_SLOTS: u32 = 16;

/// Default shard directory.
const DEFAULT_DIR: &str = "/var/lib/aegis/events";

/// Hard cap on rows returned by a single [`EventStore::query`].
const QUERY_LIMIT_CAP: usize = 1_000;

// ── EventRow ────────────────────────────────────────────────────────────────

/// One recorded request. Plain data, `Serialize`/`Deserialize` so the admin
/// API can return query results straight as JSON.
///
/// `action` is one of `pass` / `deny` / `challenge` / `tarpit` / `rate` /
/// `rtbh`. `path_pattern` is the generalised path (see
/// [`crate::site_map::generalise_path`]) used for per-endpoint aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    /// Unix milliseconds.
    pub ts: i64,
    pub host: String,
    pub method: String,
    pub path: String,
    /// Generalised path, e.g. `/api/users/:id`.
    pub path_pattern: String,
    pub status: i64,
    /// pass / deny / challenge / tarpit / rate / rtbh.
    pub action: String,
    pub reason: String,
    pub waf_rule: String,
    pub client_ip: String,
    pub country: String,
    pub ja4: String,
    pub latency_ms: i64,
    pub bytes: i64,
    pub protocol: String,
    pub user_agent: String,
}

impl EventRow {
    /// Convenience constructor with the current wall-clock timestamp and all
    /// optional string fields empty. Callers fill in what they have.
    pub fn now(
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        path_pattern: impl Into<String>,
        status: u16,
        action: impl Into<String>,
    ) -> Self {
        Self {
            ts: unix_millis(),
            host: host.into(),
            method: method.into(),
            path: path.into(),
            path_pattern: path_pattern.into(),
            status: status as i64,
            action: action.into(),
            reason: String::new(),
            waf_rule: String::new(),
            client_ip: String::new(),
            country: String::new(),
            ja4: String::new(),
            latency_ms: 0,
            bytes: 0,
            protocol: String::new(),
            user_agent: String::new(),
        }
    }
}

// ── Query filter + stats result types ────────────────────────────────────────

/// Optional filters for [`EventStore::query`]. All `None`/empty fields mean
/// "no constraint". `limit` is capped at [`QUERY_LIMIT_CAP`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFilter {
    pub host: Option<String>,
    /// Matches `path_pattern`.
    pub endpoint: Option<String>,
    pub action: Option<String>,
    pub client_ip: Option<String>,
    /// Free-text — `LIKE %q%` over `path` and `user_agent`.
    pub q: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// `(label, count)` aggregate pair, JSON-friendly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Count {
    pub key: String,
    pub count: i64,
}

/// Per-client-IP aggregate used by the bots/DDoS history view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpStat {
    pub client_ip: String,
    pub hits: i64,
    pub deny: i64,
    pub challenge: i64,
    pub country: String,
}

/// Per-(host, endpoint) aggregate with distinct-IP fan-out, used by the
/// DDoS "endpoint under attack" view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointStat {
    pub host: String,
    pub path_pattern: String,
    pub hits: i64,
    pub distinct_ips: i64,
}

/// One time-bucket in a [`LogStats`] series.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeBucket {
    /// Bucket start, unix millis.
    pub ts: i64,
    pub hits: i64,
    pub deny: i64,
    pub challenge: i64,
}

/// Aggregated analytics over a time range (and optional host).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogStats {
    pub total: i64,
    pub by_action: Vec<Count>,
    pub top_endpoints: Vec<Count>,
    pub top_ips: Vec<IpStat>,
    pub top_reasons: Vec<Count>,
    pub status_dist: Vec<Count>,
    /// (host, path_pattern, distinct_ips) — powers the DDoS view.
    pub endpoint_fanout: Vec<EndpointStat>,
    pub series: Vec<TimeBucket>,
    /// Bucket width of `series`, in milliseconds.
    pub bucket_ms: i64,
}

// ── EventStore ──────────────────────────────────────────────────────────────

/// Handle held by the proxy. Cheap to clone-via-`Arc`. The write side is the
/// bounded channel + background thread; the read side opens its own
/// connections per call so it never contends with the writer.
pub struct EventStore {
    /// `None` when logging is disabled (`AEGIS_EVENT_LOG=0`) — then
    /// [`record`](Self::record) is a no-op and persistence is never enabled.
    enabled: bool,
    /// Directory holding all `shard-*.db` files. Read side scans this.
    dir: PathBuf,
    /// Bounded sender to the writer thread. `None` until persistence is
    /// enabled (or when disabled) — `record` is a no-op in that case.
    tx: Option<SyncSender<EventRow>>,
    /// Keep-every-Nth sampler for `action == "pass"`. `1` keeps all.
    pass_sample_n: u64,
    /// Monotonic counter for the pass sampler.
    pass_counter: AtomicU64,
    /// Rows dropped because the channel was full. Diagnostic / admin.
    dropped: Arc<AtomicU64>,
    /// Rows handed to the channel (accepted, not necessarily committed yet).
    accepted: Arc<AtomicU64>,
    /// Signals the writer thread to stop and flush.
    stop: Arc<AtomicBool>,
    /// Writer thread handle, joined on drop.
    writer: Option<JoinHandle<()>>,
    /// Held flock on `.slot-<n>.lock` for the process lifetime. Dropping
    /// releases the slot for the next worker.
    #[allow(dead_code)]
    slot_lock: Option<std::fs::File>,
    /// This worker's own shard path, if persistence is enabled.
    shard_path: Option<PathBuf>,
}

impl EventStore {
    /// Construct an `EventStore` reading the enable gate + sampling knob from
    /// the environment, **without** enabling persistence (no writer thread,
    /// no slot, no DB file). `record` is a no-op until
    /// [`with_persistence`](Self::with_persistence) is called.
    ///
    /// Use this in tests, or call [`from_env`](Self::from_env) for the full
    /// production wiring.
    pub fn new(dir: PathBuf) -> Self {
        let enabled = env_enabled("AEGIS_EVENT_LOG", true);
        let pass_sample_n = sample_n_from_fraction(env_f64("AEGIS_EVENTS_SAMPLE_PASS", 1.0));
        Self {
            enabled,
            dir,
            tx: None,
            pass_sample_n,
            pass_counter: AtomicU64::new(0),
            dropped: Arc::new(AtomicU64::new(0)),
            accepted: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            writer: None,
            slot_lock: None,
            shard_path: None,
        }
    }

    /// Full production constructor: reads `AEGIS_EVENTS_DIR` (default
    /// `/var/lib/aegis/events`), the enable gate and sampling knob, then —
    /// if enabled — acquires a worker slot and spawns the writer thread.
    ///
    /// Always returns a usable handle. If logging is disabled, or the slot /
    /// directory / database cannot be set up, the handle degrades to a
    /// no-op writer (and logs a warning) rather than failing startup.
    pub fn from_env() -> Self {
        let dir = std::env::var("AEGIS_EVENTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_DIR));
        let store = Self::new(dir);
        if store.enabled {
            store.with_persistence()
        } else {
            store
        }
    }

    /// Whether logging is enabled (the gate said yes). Even when `true`,
    /// `record` only persists once [`with_persistence`](Self::with_persistence)
    /// has succeeded.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// This worker's shard path, if persistence is active.
    pub fn shard_path(&self) -> Option<&Path> {
        self.shard_path.as_deref()
    }

    /// Number of rows dropped because the bounded channel was full.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Number of rows accepted into the channel (not necessarily committed).
    pub fn accepted_count(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Enable disk persistence: acquire a worker slot via non-blocking
    /// `flock`, open this worker's `shard-<slot>.db` (WAL, busy_timeout),
    /// create the schema, and spawn the background writer thread.
    ///
    /// Call once at startup before serving traffic. On any failure (no free
    /// slot, cannot create dir, cannot open DB) it logs a warning and returns
    /// `self` unchanged in no-op mode — `record` stays a no-op and
    /// [`shard_path`](Self::shard_path) returns `None`.
    pub fn with_persistence(mut self) -> Self {
        if !self.enabled {
            return self;
        }
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            tracing::warn!(
                dir = %self.dir.display(),
                error = %e,
                "event_store: cannot create shard directory — running without persistence"
            );
            return self;
        }
        let (slot, lock_file) = match crate::site_map::SiteMap::acquire_slot(&self.dir, MAX_SLOTS) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    dir = %self.dir.display(),
                    "event_store: no free slot in {} tries — running without persistence",
                    MAX_SLOTS
                );
                return self;
            }
        };
        let shard = self.dir.join(format!("shard-{slot}.db"));
        let conn = match open_writer_conn(&shard) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %shard.display(),
                    error = %e,
                    "event_store: cannot open shard db — running without persistence"
                );
                return self;
            }
        };

        let retention_days = env_u64("AEGIS_EVENTS_RETENTION_DAYS", 14);
        let (tx, rx) = sync_channel::<EventRow>(CHANNEL_CAP);
        let stop = self.stop.clone();
        let accepted = self.accepted.clone();
        let shard_for_log = shard.clone();
        let handle = std::thread::Builder::new()
            .name("aegis-eventlog".into())
            .spawn(move || {
                writer_loop(conn, rx, stop, retention_days, &shard_for_log);
                let _ = accepted; // accepted is bumped on the producer side
            })
            .ok();

        if handle.is_none() {
            tracing::warn!(
                "event_store: failed to spawn writer thread — running without persistence"
            );
            return self;
        }

        tracing::info!(slot, path = %shard.display(), "event_store: persistence enabled");
        self.tx = Some(tx);
        self.writer = handle;
        self.slot_lock = Some(lock_file);
        self.shard_path = Some(shard);
        self
    }

    /// HOT PATH. Record one request. Non-blocking and cheap:
    ///
    /// 1. No-op if logging disabled or persistence not enabled.
    /// 2. Counter-based sampling drops a fraction of `action == "pass"` rows
    ///    (non-pass actions are always kept).
    /// 3. `try_send` into the bounded channel. On full, drops the row and
    ///    bumps the dropped counter — NEVER blocks, NEVER does SQLite I/O.
    pub fn record(&self, row: EventRow) {
        let Some(tx) = self.tx.as_ref() else { return };

        // Sampling: keep all non-pass; keep every Nth pass.
        if self.pass_sample_n > 1 && row.action == "pass" {
            let n = self.pass_counter.fetch_add(1, Ordering::Relaxed);
            if n % self.pass_sample_n != 0 {
                return;
            }
        }

        match tx.try_send(row) {
            Ok(()) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // Writer thread gone — count as dropped, never panic.
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// READ SIDE. Query rows across **all** shards in the directory, newest
    /// first, applying [`LogFilter`]. Opens a fresh read-only connection that
    /// `ATTACH`es every `shard-*.db` and `UNION ALL`s them. Missing or locked
    /// shards are skipped gracefully. `limit` capped at [`QUERY_LIMIT_CAP`].
    pub fn query(&self, filter: &LogFilter) -> Vec<EventRow> {
        query_dir(&self.dir, filter)
    }

    /// READ SIDE. Aggregated analytics across all shards for the given range
    /// (and optional host). See [`LogStats`].
    pub fn stats(&self, host: Option<&str>, from_ms: i64, to_ms: i64) -> LogStats {
        stats_dir(&self.dir, host, from_ms, to_ms)
    }
}

impl Drop for EventStore {
    fn drop(&mut self) {
        // Tell the writer to flush + exit, drop the sender so the channel
        // disconnects, then join so a final batch lands before the process
        // (or test) moves on.
        self.stop.store(true, Ordering::Relaxed);
        self.tx = None;
        if let Some(h) = self.writer.take() {
            let _ = h.join();
        }
    }
}

// ── Writer thread ────────────────────────────────────────────────────────────

/// Drains `rx`, committing in batches inside a single transaction, and runs
/// retention periodically. Exits when `stop` is set and the channel drains,
/// or when the channel disconnects.
fn writer_loop(
    mut conn: Connection,
    rx: Receiver<EventRow>,
    stop: Arc<AtomicBool>,
    retention_days: u64,
    shard: &Path,
) {
    let mut batch: Vec<EventRow> = Vec::with_capacity(BATCH_MAX);
    let mut last_flush = Instant::now();
    let mut last_retention = Instant::now();

    loop {
        // Block up to the remaining flush interval waiting for a row, so an
        // idle writer doesn't spin.
        let wait = FLUSH_INTERVAL
            .checked_sub(last_flush.elapsed())
            .unwrap_or(Duration::ZERO);
        match rx.recv_timeout(wait.max(Duration::from_millis(10))) {
            Ok(row) => {
                batch.push(row);
                // Greedily drain whatever else is queued without blocking.
                while batch.len() < BATCH_MAX {
                    match rx.try_recv() {
                        Ok(r) => batch.push(r),
                        Err(_) => break,
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                flush_batch(&mut conn, &mut batch, shard);
                break;
            }
        }

        let due = last_flush.elapsed() >= FLUSH_INTERVAL;
        if batch.len() >= BATCH_MAX || (due && !batch.is_empty()) {
            flush_batch(&mut conn, &mut batch, shard);
            last_flush = Instant::now();
        } else if due {
            last_flush = Instant::now();
        }

        if last_retention.elapsed() >= RETENTION_INTERVAL {
            run_retention(&conn, retention_days, shard);
            last_retention = Instant::now();
        }

        if stop.load(Ordering::Relaxed) {
            // Drain anything still queued, then exit.
            while let Ok(r) = rx.try_recv() {
                batch.push(r);
                if batch.len() >= BATCH_MAX {
                    flush_batch(&mut conn, &mut batch, shard);
                }
            }
            flush_batch(&mut conn, &mut batch, shard);
            break;
        }
    }

    // Best-effort final checkpoint so the WAL is folded back into the db.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

/// Insert `batch` in a single transaction, then clear it. Errors are logged
/// (never panic on the writer thread).
fn flush_batch(conn: &mut Connection, batch: &mut Vec<EventRow>, shard: &Path) {
    if batch.is_empty() {
        return;
    }
    let res: rusqlite::Result<()> = (|| {
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(INSERT_SQL)?;
            for r in batch.iter() {
                stmt.execute(rusqlite::params![
                    r.ts,
                    r.host,
                    r.method,
                    r.path,
                    r.path_pattern,
                    r.status,
                    r.action,
                    r.reason,
                    r.waf_rule,
                    r.client_ip,
                    r.country,
                    r.ja4,
                    r.latency_ms,
                    r.bytes,
                    r.protocol,
                    r.user_agent,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!(
            path = %shard.display(),
            error = %e,
            rows = batch.len(),
            "event_store: batch insert failed — dropping batch"
        );
    }
    batch.clear();
}

/// Delete rows older than the retention window, enforce the hard row cap, and
/// checkpoint the WAL to bound file size. Best-effort; errors are logged.
fn run_retention(conn: &Connection, retention_days: u64, shard: &Path) {
    let cutoff = unix_millis() - (retention_days as i64) * 86_400_000;
    let res: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM requests WHERE ts < ?1", [cutoff])?;
        // Hard cap safety net: if still over cap, delete the oldest overflow.
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))?;
        if count > HARD_ROW_CAP {
            let overflow = count - HARD_ROW_CAP;
            conn.execute(
                "DELETE FROM requests WHERE rowid IN \
                 (SELECT rowid FROM requests ORDER BY ts ASC LIMIT ?1)",
                [overflow],
            )?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!(path = %shard.display(), error = %e, "event_store: retention failed");
    }
    // Bound WAL + reclaim freed pages. Best-effort.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA incremental_vacuum;");
}

// ── Schema / connection setup ────────────────────────────────────────────────

const INSERT_SQL: &str = "INSERT INTO requests \
    (ts, host, method, path, path_pattern, status, action, reason, waf_rule, \
     client_ip, country, ja4, latency_ms, bytes, protocol, user_agent) \
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)";

const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS requests (
    ts           INTEGER NOT NULL,
    host         TEXT NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    status       INTEGER NOT NULL,
    action       TEXT NOT NULL,
    reason       TEXT NOT NULL,
    waf_rule     TEXT NOT NULL,
    client_ip    TEXT NOT NULL,
    country      TEXT NOT NULL,
    ja4          TEXT NOT NULL,
    latency_ms   INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    protocol     TEXT NOT NULL,
    user_agent   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_ts          ON requests (host, ts);
CREATE INDEX IF NOT EXISTS idx_host_pattern_ts  ON requests (host, path_pattern, ts);
CREATE INDEX IF NOT EXISTS idx_action_ts        ON requests (action, ts);
CREATE INDEX IF NOT EXISTS idx_client_ip_ts     ON requests (client_ip, ts);
CREATE INDEX IF NOT EXISTS idx_ts               ON requests (ts);
";

/// Open the single-writer connection for this worker's shard: WAL mode,
/// generous busy_timeout, NORMAL sync (WAL-safe), incremental auto-vacuum so
/// `PRAGMA incremental_vacuum` can reclaim space. Creates the schema.
fn open_writer_conn(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA auto_vacuum=INCREMENTAL;
         PRAGMA wal_autocheckpoint=1000;",
    )?;
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(conn)
}

// ── Read side: multi-shard ATTACH + UNION ALL ────────────────────────────────

/// All `shard-*.db` files in `dir`, sorted for deterministic ordering.
fn shard_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("shard-") && name.ends_with(".db") {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

/// Open a read-only in-memory connection with every shard ATTACHed as
/// `s0`, `s1`, …. Returns the connection plus the list of attached aliases.
/// Shards that fail to attach (locked/corrupt) are skipped.
fn open_read_conn(dir: &Path) -> Option<(Connection, Vec<String>)> {
    let conn = Connection::open_in_memory().ok()?;
    let mut aliases = Vec::new();
    for (i, path) in shard_files(dir).into_iter().enumerate() {
        let alias = format!("s{i}");
        // ATTACH in read-only mode via URI so a missing table later is the
        // only failure mode, never a write lock.
        let uri = format!("file:{}?mode=ro", path.to_string_lossy());
        let sql = format!("ATTACH DATABASE '{}' AS {}", uri.replace('\'', "''"), alias);
        match conn.execute_batch(&sql) {
            Ok(()) => aliases.push(alias),
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "event_store: skip shard on attach");
            }
        }
    }
    if aliases.is_empty() {
        return None;
    }
    Some((conn, aliases))
}

/// Build a `(SELECT ... FROM <alias>.requests) UNION ALL (...)` subquery over
/// all attached shards, selecting every column in EventRow order.
fn union_all_subquery(aliases: &[String]) -> String {
    let cols = "ts,host,method,path,path_pattern,status,action,reason,waf_rule,\
                client_ip,country,ja4,latency_ms,bytes,protocol,user_agent";
    aliases
        .iter()
        .map(|a| format!("SELECT {cols} FROM {a}.requests"))
        .collect::<Vec<_>>()
        .join(" UNION ALL ")
}

fn row_from(r: &rusqlite::Row) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        ts: r.get(0)?,
        host: r.get(1)?,
        method: r.get(2)?,
        path: r.get(3)?,
        path_pattern: r.get(4)?,
        status: r.get(5)?,
        action: r.get(6)?,
        reason: r.get(7)?,
        waf_rule: r.get(8)?,
        client_ip: r.get(9)?,
        country: r.get(10)?,
        ja4: r.get(11)?,
        latency_ms: r.get(12)?,
        bytes: r.get(13)?,
        protocol: r.get(14)?,
        user_agent: r.get(15)?,
    })
}

fn query_dir(dir: &Path, filter: &LogFilter) -> Vec<EventRow> {
    let Some((conn, aliases)) = open_read_conn(dir) else {
        return Vec::new();
    };
    let inner = union_all_subquery(&aliases);

    // Build the WHERE clause with positional params.
    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    let push = |sql: String,
                val: Box<dyn rusqlite::ToSql>,
                wc: &mut Vec<String>,
                p: &mut Vec<Box<dyn rusqlite::ToSql>>| {
        p.push(val);
        wc.push(format!("{sql} ?{}", p.len()));
    };

    if let Some(h) = nonempty(&filter.host) {
        push(
            "host =".into(),
            Box::new(h),
            &mut where_clauses,
            &mut params,
        );
    }
    if let Some(e) = nonempty(&filter.endpoint) {
        push(
            "path_pattern =".into(),
            Box::new(e),
            &mut where_clauses,
            &mut params,
        );
    }
    if let Some(a) = nonempty(&filter.action) {
        push(
            "action =".into(),
            Box::new(a),
            &mut where_clauses,
            &mut params,
        );
    }
    if let Some(ip) = nonempty(&filter.client_ip) {
        push(
            "client_ip =".into(),
            Box::new(ip),
            &mut where_clauses,
            &mut params,
        );
    }
    if let Some(from) = filter.from_ms {
        push(
            "ts >=".into(),
            Box::new(from),
            &mut where_clauses,
            &mut params,
        );
    }
    if let Some(to) = filter.to_ms {
        push(
            "ts <=".into(),
            Box::new(to),
            &mut where_clauses,
            &mut params,
        );
    }
    if let Some(q) = nonempty(&filter.q) {
        let like = format!("%{q}%");
        params.push(Box::new(like.clone()));
        let i1 = params.len();
        params.push(Box::new(like));
        let i2 = params.len();
        where_clauses.push(format!("(path LIKE ?{i1} OR user_agent LIKE ?{i2})"));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let limit = filter.limit.unwrap_or(QUERY_LIMIT_CAP).min(QUERY_LIMIT_CAP);
    let offset = filter.offset.unwrap_or(0);
    let sql = format!(
        "SELECT * FROM ({inner}) {where_sql} ORDER BY ts DESC LIMIT {limit} OFFSET {offset}"
    );

    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "event_store: query prepare failed");
            return Vec::new();
        }
    };
    let rows = match stmt.query_map(param_refs.as_slice(), row_from) {
        Ok(it) => it,
        Err(e) => {
            tracing::debug!(error = %e, "event_store: query_map failed");
            return Vec::new();
        }
    };
    rows.filter_map(|r| r.ok()).collect()
}

fn stats_dir(dir: &Path, host: Option<&str>, from_ms: i64, to_ms: i64) -> LogStats {
    let mut stats = LogStats::default();
    let Some((conn, aliases)) = open_read_conn(dir) else {
        return stats;
    };
    let inner = union_all_subquery(&aliases);

    // Common range/host predicate. host param is ?1 (optional), range ?2/?3.
    let host_filter = host.filter(|h| !h.is_empty());
    let (host_clause, host_param): (String, Option<String>) = match host_filter {
        Some(h) => ("AND host = ?3".into(), Some(h.to_string())),
        None => (String::new(), None),
    };
    let base = format!("SELECT * FROM ({inner}) WHERE ts >= ?1 AND ts <= ?2 {host_clause}");

    // Helper: aggregate COUNT(*) grouped by `key_expr` (which becomes column
    // `k`), with an optional extra row predicate, ordered by count desc.
    let run_counts = |key_expr: &str, extra_where: &str| -> Vec<Count> {
        let extra = if extra_where.is_empty() {
            String::new()
        } else {
            format!("AND {extra_where}")
        };
        let sql = format!(
            "SELECT {key_expr} AS k, COUNT(*) AS c FROM ({inner}) \
             WHERE ts >= ?1 AND ts <= ?2 {host_clause} {extra} \
             GROUP BY k ORDER BY c DESC LIMIT 20"
        );
        run_count_query(&conn, &sql, from_ms, to_ms, host_param.as_deref())
    };

    // total
    {
        let sql = format!("SELECT COUNT(*) FROM ({base})");
        stats.total = scalar_i64(&conn, &sql, from_ms, to_ms, host_param.as_deref());
    }

    // by_action
    stats.by_action = run_counts("action", "");
    // top_endpoints (path_pattern)
    stats.top_endpoints = run_counts("path_pattern", "");
    // top_reasons (skip empty)
    stats.top_reasons = run_counts("reason", "reason != ''");
    // status distribution
    stats.status_dist = run_counts("CAST(status AS TEXT)", "");

    // top_ips with deny/challenge breakdown
    {
        let sql = format!(
            "SELECT client_ip, COUNT(*) AS hits, \
             SUM(CASE WHEN action='deny' THEN 1 ELSE 0 END) AS deny, \
             SUM(CASE WHEN action='challenge' THEN 1 ELSE 0 END) AS challenge, \
             MAX(country) AS country \
             FROM ({base}) WHERE client_ip != '' \
             GROUP BY client_ip ORDER BY hits DESC LIMIT 50"
        );
        if let Ok(mut stmt) = conn.prepare(&sql) {
            let it = stmt.query_map(
                params_for(from_ms, to_ms, host_param.as_deref())
                    .refs()
                    .as_slice(),
                |r| {
                    Ok(IpStat {
                        client_ip: r.get(0)?,
                        hits: r.get(1)?,
                        deny: r.get(2)?,
                        challenge: r.get(3)?,
                        country: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    })
                },
            );
            if let Ok(it) = it {
                stats.top_ips = it.filter_map(|r| r.ok()).collect();
            }
        }
    }

    // endpoint_fanout: (host, path_pattern, hits, distinct_ips)
    {
        let sql = format!(
            "SELECT host, path_pattern, COUNT(*) AS hits, \
             COUNT(DISTINCT client_ip) AS distinct_ips \
             FROM ({base}) \
             GROUP BY host, path_pattern ORDER BY distinct_ips DESC, hits DESC LIMIT 50"
        );
        if let Ok(mut stmt) = conn.prepare(&sql) {
            let it = stmt.query_map(
                params_for(from_ms, to_ms, host_param.as_deref())
                    .refs()
                    .as_slice(),
                |r| {
                    Ok(EndpointStat {
                        host: r.get(0)?,
                        path_pattern: r.get(1)?,
                        hits: r.get(2)?,
                        distinct_ips: r.get(3)?,
                    })
                },
            );
            if let Ok(it) = it {
                stats.endpoint_fanout = it.filter_map(|r| r.ok()).collect();
            }
        }
    }

    // time-bucketed series — auto bucket so we get roughly <=120 buckets.
    let span = (to_ms - from_ms).max(1);
    let bucket = auto_bucket_ms(span);
    stats.bucket_ms = bucket;
    {
        let sql = format!(
            "SELECT (ts / {bucket}) * {bucket} AS b, COUNT(*) AS hits, \
             SUM(CASE WHEN action='deny' THEN 1 ELSE 0 END) AS deny, \
             SUM(CASE WHEN action='challenge' THEN 1 ELSE 0 END) AS challenge \
             FROM ({base}) GROUP BY b ORDER BY b ASC"
        );
        if let Ok(mut stmt) = conn.prepare(&sql) {
            let it = stmt.query_map(
                params_for(from_ms, to_ms, host_param.as_deref())
                    .refs()
                    .as_slice(),
                |r| {
                    Ok(TimeBucket {
                        ts: r.get(0)?,
                        hits: r.get(1)?,
                        deny: r.get(2)?,
                        challenge: r.get(3)?,
                    })
                },
            );
            if let Ok(it) = it {
                stats.series = it.filter_map(|r| r.ok()).collect();
            }
        }
    }

    stats
}

/// Build the positional params for a stats query: ?1=from, ?2=to, ?3=host?.
fn params_for<'a>(
    from_ms: i64,
    to_ms: i64,
    host: Option<&'a str>,
) -> Vec<Box<dyn rusqlite::ToSql + 'a>> {
    let mut v: Vec<Box<dyn rusqlite::ToSql + 'a>> = vec![Box::new(from_ms), Box::new(to_ms)];
    if let Some(h) = host {
        v.push(Box::new(h));
    }
    v
}

trait ParamSlice {
    fn refs(&self) -> Vec<&dyn rusqlite::ToSql>;
}
impl ParamSlice for Vec<Box<dyn rusqlite::ToSql + '_>> {
    fn refs(&self) -> Vec<&dyn rusqlite::ToSql> {
        self.iter().map(|b| b.as_ref()).collect()
    }
}

fn run_count_query(
    conn: &Connection,
    sql: &str,
    from_ms: i64,
    to_ms: i64,
    host: Option<&str>,
) -> Vec<Count> {
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "event_store: count prepare failed");
            return Vec::new();
        }
    };
    let it = stmt.query_map(params_for(from_ms, to_ms, host).refs().as_slice(), |r| {
        Ok(Count {
            key: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            count: r.get(1)?,
        })
    });
    match it {
        Ok(it) => it.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

fn scalar_i64(conn: &Connection, sql: &str, from_ms: i64, to_ms: i64, host: Option<&str>) -> i64 {
    conn.query_row(
        sql,
        params_for(from_ms, to_ms, host).refs().as_slice(),
        |r| r.get(0),
    )
    .unwrap_or(0)
}

/// Choose a bucket width so a range yields a reasonable number of buckets
/// (target ~120). Snaps to human-friendly widths.
fn auto_bucket_ms(span_ms: i64) -> i64 {
    const TARGET: i64 = 120;
    let raw = (span_ms / TARGET).max(1);
    // Snap up to the next friendly bucket.
    const STEPS: [i64; 13] = [
        1_000,          // 1s
        5_000,          // 5s
        15_000,         // 15s
        60_000,         // 1m
        300_000,        // 5m
        900_000,        // 15m
        3_600_000,      // 1h
        21_600_000,     // 6h
        86_400_000,     // 1d
        604_800_000,    // 1w
        2_592_000_000,  // 30d
        7_776_000_000,  // 90d
        31_536_000_000, // 1y
    ];
    for &s in &STEPS {
        if raw <= s {
            return s;
        }
    }
    *STEPS.last().unwrap()
}

// ── Small helpers ────────────────────────────────────────────────────────────

fn nonempty(o: &Option<String>) -> Option<String> {
    o.as_ref().filter(|s| !s.is_empty()).cloned()
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Read a boolean-ish env gate. Disabled by `0` / `false` / `off` / `no`
/// (case-insensitive). Anything else (including unset) yields `default`.
fn env_enabled(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => default,
    }
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Convert a "keep fraction" in `[0,1]` into a "keep every Nth" divisor.
/// `1.0` (or anything >=1) → 1 (keep all). `0.5` → 2. `0.1` → 10. `0.0` or
/// negative → a very large N (keep ~none, but never divide by zero).
fn sample_n_from_fraction(frac: f64) -> u64 {
    if frac >= 1.0 {
        return 1;
    }
    if frac <= 0.0 {
        return u64::MAX;
    }
    (1.0 / frac).round().max(1.0) as u64
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an EventStore writing into `dir`, with persistence enabled,
    /// bypassing env gates (always enabled, given sample N).
    fn store_in(dir: &Path, pass_sample_n: u64) -> EventStore {
        let mut s = EventStore::new(dir.to_path_buf());
        s.enabled = true;
        s.pass_sample_n = pass_sample_n;
        s.with_persistence()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aegis_eventstore_{tag}_{}_{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mkrow(ts: i64, host: &str, action: &str, ip: &str) -> EventRow {
        let mut r = EventRow::now(host, "GET", "/x", "/x", 200, action);
        r.ts = ts;
        r.client_ip = ip.into();
        r
    }

    /// (a) record → flush → query roundtrip.
    #[test]
    fn record_flush_query_roundtrip() {
        let dir = tmpdir("roundtrip");
        let store = store_in(&dir, 1);
        assert!(
            store.shard_path().is_some(),
            "persistence should be enabled"
        );

        for i in 0..50 {
            store.record(mkrow(1_000 + i, "a.test", "pass", "1.1.1.1"));
        }
        // Drop forces a flush + join.
        drop(store);

        let reader = EventStore::new(dir.clone());
        let rows = reader.query(&LogFilter::default());
        assert_eq!(rows.len(), 50, "all 50 rows should be persisted");
        // Newest first.
        assert!(rows[0].ts >= rows[1].ts);
    }

    /// (d) query filters by host / action / time.
    #[test]
    fn query_filters() {
        let dir = tmpdir("filters");
        let store = store_in(&dir, 1);
        store.record(mkrow(1_000, "a.test", "pass", "1.1.1.1"));
        store.record(mkrow(2_000, "a.test", "deny", "2.2.2.2"));
        store.record(mkrow(3_000, "b.test", "deny", "3.3.3.3"));
        store.record(mkrow(4_000, "b.test", "pass", "4.4.4.4"));
        drop(store);

        let reader = EventStore::new(dir.clone());

        let by_host = reader.query(&LogFilter {
            host: Some("a.test".into()),
            ..Default::default()
        });
        assert_eq!(by_host.len(), 2);
        assert!(by_host.iter().all(|r| r.host == "a.test"));

        let by_action = reader.query(&LogFilter {
            action: Some("deny".into()),
            ..Default::default()
        });
        assert_eq!(by_action.len(), 2);
        assert!(by_action.iter().all(|r| r.action == "deny"));

        let by_time = reader.query(&LogFilter {
            from_ms: Some(2_500),
            to_ms: Some(3_500),
            ..Default::default()
        });
        assert_eq!(by_time.len(), 1);
        assert_eq!(by_time[0].ts, 3_000);

        let by_ip = reader.query(&LogFilter {
            client_ip: Some("4.4.4.4".into()),
            ..Default::default()
        });
        assert_eq!(by_ip.len(), 1);
        assert_eq!(by_ip[0].host, "b.test");
    }

    /// (b) retention deletes old rows but keeps recent ones.
    #[test]
    fn retention_deletes_old_rows() {
        let dir = tmpdir("retention");
        let store = store_in(&dir, 1);
        let now = unix_millis();
        let old = now - 30 * 86_400_000; // 30 days ago
        store.record(mkrow(old, "a.test", "pass", "1.1.1.1"));
        store.record(mkrow(now, "a.test", "pass", "2.2.2.2"));
        drop(store);

        // Re-open the writer connection directly and run retention with a
        // 14-day window — the 30-day-old row must go, the fresh one stays.
        let shard = shard_files(&dir).into_iter().next().expect("a shard file");
        let conn = open_writer_conn(&shard).unwrap();
        run_retention(&conn, 14, &shard);
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "only the fresh row should survive retention");
        let surviving_ts: i64 = conn
            .query_row("SELECT ts FROM requests", [], |r| r.get(0))
            .unwrap();
        assert_eq!(surviving_ts, now);
    }

    /// (c) sampling keeps ALL non-pass actions, drops a fraction of pass.
    #[test]
    fn sampling_keeps_all_non_pass() {
        let dir = tmpdir("sampling");
        // Keep every 10th pass (frac 0.1), keep all deny/challenge/etc.
        let store = store_in(&dir, 10);

        for i in 0..100 {
            store.record(mkrow(10_000 + i, "a.test", "pass", "1.1.1.1"));
        }
        for i in 0..30 {
            store.record(mkrow(20_000 + i, "a.test", "deny", "2.2.2.2"));
        }
        for i in 0..20 {
            store.record(mkrow(30_000 + i, "a.test", "challenge", "3.3.3.3"));
        }
        drop(store);

        let reader = EventStore::new(dir.clone());
        let deny = reader.query(&LogFilter {
            action: Some("deny".into()),
            ..Default::default()
        });
        let chal = reader.query(&LogFilter {
            action: Some("challenge".into()),
            ..Default::default()
        });
        let pass = reader.query(&LogFilter {
            action: Some("pass".into()),
            ..Default::default()
        });

        assert_eq!(deny.len(), 30, "ALL deny rows must be kept");
        assert_eq!(chal.len(), 20, "ALL challenge rows must be kept");
        // ~10% of 100 passes. Counter-based so it's deterministic-ish; allow slack.
        assert!(
            pass.len() >= 8 && pass.len() <= 12,
            "expected ~10 sampled pass rows, got {}",
            pass.len()
        );
    }

    #[test]
    fn stats_aggregations() {
        let dir = tmpdir("stats");
        let store = store_in(&dir, 1);
        store.record(mkrow(1_000, "a.test", "pass", "1.1.1.1"));
        store.record(mkrow(1_500, "a.test", "deny", "1.1.1.1"));
        store.record(mkrow(2_000, "a.test", "deny", "2.2.2.2"));
        store.record(mkrow(2_500, "a.test", "challenge", "2.2.2.2"));
        drop(store);

        let reader = EventStore::new(dir.clone());
        let s = reader.stats(Some("a.test"), 0, 10_000);
        assert_eq!(s.total, 4);

        // by_action has deny=2, pass=1, challenge=1
        let deny = s.by_action.iter().find(|c| c.key == "deny").unwrap();
        assert_eq!(deny.count, 2);

        // top_ips: 1.1.1.1 has 2 hits (1 deny), 2.2.2.2 has 2 hits (1 deny, 1 challenge)
        assert_eq!(s.top_ips.len(), 2);
        let ip2 = s.top_ips.iter().find(|i| i.client_ip == "2.2.2.2").unwrap();
        assert_eq!(ip2.hits, 2);
        assert_eq!(ip2.deny, 1);
        assert_eq!(ip2.challenge, 1);

        // endpoint_fanout: /x with 2 distinct ips
        assert!(!s.endpoint_fanout.is_empty());
        assert_eq!(s.endpoint_fanout[0].distinct_ips, 2);

        // series populated
        assert!(!s.series.is_empty());
        assert!(s.bucket_ms > 0);
    }

    #[test]
    fn disabled_store_is_noop() {
        let dir = tmpdir("disabled");
        let mut s = EventStore::new(dir.clone());
        s.enabled = false;
        let s = s.with_persistence();
        assert!(s.shard_path().is_none());
        s.record(mkrow(1, "a", "deny", "1.1.1.1")); // must not panic / persist
        drop(s);
        let reader = EventStore::new(dir);
        assert!(reader.query(&LogFilter::default()).is_empty());
    }

    #[test]
    fn sample_fraction_to_n() {
        assert_eq!(sample_n_from_fraction(1.0), 1);
        assert_eq!(sample_n_from_fraction(1.5), 1);
        assert_eq!(sample_n_from_fraction(0.5), 2);
        assert_eq!(sample_n_from_fraction(0.1), 10);
        assert_eq!(sample_n_from_fraction(0.0), u64::MAX);
    }

    #[test]
    fn dropped_counter_on_full_channel() {
        // Tiny manual store with a 1-slot channel and NO writer draining it,
        // to deterministically exercise the full-channel drop path.
        let dir = tmpdir("dropped");
        let mut s = EventStore::new(dir);
        s.enabled = true;
        let (tx, _rx) = sync_channel::<EventRow>(1);
        s.tx = Some(tx);
        // First send fills the single slot; subsequent sends are dropped.
        s.record(mkrow(1, "a", "deny", "1.1.1.1"));
        s.record(mkrow(2, "a", "deny", "1.1.1.1"));
        s.record(mkrow(3, "a", "deny", "1.1.1.1"));
        assert!(s.dropped_count() >= 2, "full channel should drop rows");
        // Avoid the Drop join hanging on the never-spawned writer.
        s.tx = None;
    }
}
