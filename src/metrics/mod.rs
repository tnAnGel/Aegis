// V230 — `AtomicU64` no longer needed here; every counter in this
// module now lives behind `ShardedCounter` (which still wraps
// `AtomicU64` internally, per cache-line-padded shard).
use std::sync::{Arc, atomic::Ordering};

use dashmap::DashMap;

pub mod sharded;
use sharded::ShardedCounter;

/// V242 — cross-worker GeoIP country aggregation (shard + merge-on-read).
pub mod geo_shard;
use geo_shard::{CountryRow, GeoShard, GeoSnapshot};

use std::path::PathBuf;

/// Persistent fleet-wide time-series store. Samples the cluster mmap
/// counters every 60 seconds and writes delta records to two fixed-size
/// binary ring files: `series_1m.bin` (1-minute resolution, 48 h) and
/// `series_1h.bin` (1-hour resolution, 90 d). Single-writer advisory flock
/// ensures exactly one REUSEPORT worker persists while the others no-op.
/// The query layer downsamples to ≤300 points and computes the derived
/// `allow` field at read time.
pub mod timeseries;
pub use timeseries::{
    MAX_RESPONSE_POINTS, Point, QueryPoint, RING_1H_CAPACITY, RING_1M_CAPACITY, SeriesResponse,
    TimeSeriesStore, default_store_dir,
};

/// Histogram buckets (milliseconds) chosen to cover edge proxy latency range.
pub const LATENCY_BUCKETS_MS: &[u64] = &[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

// V230 — sharded per-domain counters. Each domain entry in the
// `RuntimeMetrics::domain` DashMap holds one of these; the value's
// counters are bumped on every request matching the host. Before
// V230, a single `AtomicU64` per field meant the hottest domains
// (often just one or two in production) bottlenecked on cache-line
// bouncing across cores. `ShardedCounter` is a drop-in: identical
// `fetch_add` / `load` signatures, per-CPU write slots, summed only
// on `/metrics` scrape.
#[derive(Default)]
pub struct DomainCounter {
    pub total: ShardedCounter,
    pub denied: ShardedCounter,
    pub challenged: ShardedCounter,
}

pub struct LatencyHistogram {
    /// Per-bucket sharded counters. Every request makes 11-13 atomic
    /// fetch_add ops; without per-CPU sharding these all contend on
    /// the same cache lines and become a hard ceiling at 100k+ RPS
    /// (~22-44 % of one CPU burned on cache-line bouncing alone).
    /// Sharded variant has each CPU bump its own slot, summed only
    /// when /metrics is scraped.
    pub buckets: Vec<ShardedCounter>,
    pub count: ShardedCounter,
    pub sum_ms: ShardedCounter,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: LATENCY_BUCKETS_MS
                .iter()
                .map(|_| ShardedCounter::new())
                .collect(),
            count: ShardedCounter::new(),
            sum_ms: ShardedCounter::new(),
        }
    }
}

impl LatencyHistogram {
    pub fn observe(&self, ms: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);
        // Single-bucket write: find the first bucket whose edge >= ms and
        // increment only that one.  render_prometheus reconstructs the
        // cumulative `le=` series via a running prefix sum, so Prometheus
        // output is byte-identical to the old all-buckets approach while
        // this hot path now performs exactly 3 atomic RMW ops (count,
        // sum_ms, one bucket) instead of ~13.
        let idx = LATENCY_BUCKETS_MS.partition_point(|&edge| edge < ms);
        if idx < self.buckets.len() {
            self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        }
        // If ms exceeds every bucket edge the observation is captured by
        // count/sum only; the +Inf bucket in render_prometheus uses `count`.
    }
}

/// Wire-protocol the request was served on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    H1,
    H2,
    H3,
    Other,
}

impl Protocol {
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Protocol::H1 => "h1",
            Protocol::H2 => "h2",
            Protocol::H3 => "h3",
            Protocol::Other => "other",
        }
    }
}

#[derive(Default)]
pub struct ProtocolCounters {
    // Sharded — every request increments one of these. Without
    // per-CPU sharding, h1/h2 traffic would contend on the same
    // cache line just like LatencyHistogram's buckets did.
    pub h1: ShardedCounter,
    pub h2: ShardedCounter,
    pub h3: ShardedCounter,
    pub other: ShardedCounter,
}

impl ProtocolCounters {
    pub fn record(&self, p: Protocol) {
        match p {
            Protocol::H1 => &self.h1,
            Protocol::H2 => &self.h2,
            Protocol::H3 => &self.h3,
            Protocol::Other => &self.other,
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct RuntimeMetrics {
    // Hot per-request counters use `ShardedCounter` — per-CPU array
    // of cache-line-padded slots that eliminate atomic-write
    // contention when many cores increment the same logical counter.
    // API surface is intentionally `fetch_add` + `load` so callers
    // (`http.rs` hot path) don't need to change a single line.
    pub requests_total: ShardedCounter,
    pub requests_denied: ShardedCounter,
    pub requests_challenged: ShardedCounter,
    pub upstream_2xx: ShardedCounter,
    pub upstream_4xx: ShardedCounter,
    pub upstream_5xx: ShardedCounter,
    pub upstream_errors: ShardedCounter,
    /// Threat-aware response cache hits. Sharded so the cache hot
    /// path (which can run at line rate when cache is warm) doesn't
    /// pay any cross-CPU cache-line bouncing on this counter.
    pub cache_hits: ShardedCounter,
    /// Cache misses — incremented when a cache-eligible request did
    /// not find a fresh entry (low-threat client) and went through
    /// to the upstream call.
    pub cache_misses: ShardedCounter,
    pub domain: DashMap<String, Arc<DomainCounter>>,
    /// V239 — per-country request tally for the dashboard "Live Traffic
    /// Overview" world map + Top Countries widget. Populated at request
    /// ingress only when a GeoIP database is configured (the lookup is a
    /// near-free None on the NoopGeoIp default), so there is no hot-path
    /// cost on deployments without GeoIP. Reuses DomainCounter (total +
    /// denied + challenged) keyed by ISO country code. Per-worker under
    /// SO_REUSEPORT — the admin endpoint reads one worker's slice, a
    /// representative sample for a top-N overview (not billing-accurate).
    pub by_country: DashMap<String, Arc<DomainCounter>>,
    pub latency: LatencyHistogram,
    pub by_protocol: ProtocolCounters,
    /// Per-filter decisions. Operators need this to answer "who is
    /// blocking the most traffic" without grepping logs — informs
    /// pipeline ordering, threshold tuning, and rule cleanups.
    pub by_filter: DashMap<String, Arc<FilterCounter>>,
    /// V242 — optional per-worker geo shard for cross-worker country
    /// aggregation. When `Some`, `flush_geo_shard()` writes this worker's
    /// `by_country` slice to its shard file, and `top_countries()` merges
    /// all workers' shards so the dashboard world map is stable poll-to-poll.
    /// `None` (the `#[derive(Default)]` value) → per-worker counters only.
    pub geo_shard: Option<GeoShard>,
}

// V230 — sharded per-filter counters. Same rationale as
// `DomainCounter`: the by_filter DashMap typically has a handful of
// hot keys (the noisy filters) that every request contends on.
// Switching the inner counter to `ShardedCounter` removes the
// cross-CPU cache-line bouncing on those hot keys. The DashMap key
// allocation itself is unchanged (still cardinality-bounded by the
// caller-supplied filter list, not attacker input).
#[derive(Default)]
pub struct FilterCounter {
    pub blocks: ShardedCounter,
    pub challenges: ShardedCounter,
}

impl RuntimeMetrics {
    pub fn observe_domain_outcome(&self, host: &str, denied: bool, challenged: bool) {
        let key = if host.is_empty() { "_unknown" } else { host };
        // Fast path: host already in the map — read lock only, zero allocation.
        // DashMap::get accepts &str because String: Borrow<str>.
        if let Some(e) = self.domain.get(key) {
            e.total.fetch_add(1, Ordering::Relaxed);
            if denied {
                e.denied.fetch_add(1, Ordering::Relaxed);
            }
            if challenged {
                e.challenged.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        // Cold path (first sight of this host): take write lock and insert.
        let entry = self
            .domain
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(DomainCounter::default()))
            .clone();
        entry.total.fetch_add(1, Ordering::Relaxed);
        if denied {
            entry.denied.fetch_add(1, Ordering::Relaxed);
        }
        if challenged {
            entry.challenged.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// V239 — record a request for the resolved ISO country code (for the
    /// dashboard world map). `denied`/`challenged` flag the request's
    /// outcome. Called at most once per request, at ingress, and only
    /// when GeoIP resolved a country. Same fast/cold-path shape as
    /// observe_domain_outcome.
    pub fn observe_country(&self, cc: &str, denied: bool, challenged: bool) {
        if cc.is_empty() {
            return;
        }
        if let Some(e) = self.by_country.get(cc) {
            e.total.fetch_add(1, Ordering::Relaxed);
            if denied {
                e.denied.fetch_add(1, Ordering::Relaxed);
            }
            if challenged {
                e.challenged.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        let entry = self
            .by_country
            .entry(cc.to_string())
            .or_insert_with(|| Arc::new(DomainCounter::default()))
            .clone();
        entry.total.fetch_add(1, Ordering::Relaxed);
        if denied {
            entry.denied.fetch_add(1, Ordering::Relaxed);
        }
        if challenged {
            entry.challenged.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// V242 — enable cross-worker geo persistence. Acquires a worker slot
    /// under `dir` (default `/var/lib/aegis/geo`), reloads this worker's
    /// own prior shard so counters survive a restart, and arms
    /// `flush_geo_shard()` / shard-merging in `top_countries()`. Call once
    /// at startup on the owned `RuntimeMetrics`, before it is wrapped in an
    /// `Arc` and traffic flows. Falls back to per-worker-only counters
    /// (logging a warning) if the slot can't be acquired.
    pub fn with_geo_persistence(mut self, dir: PathBuf) -> Self {
        if let Some(shard) = GeoShard::acquire(dir) {
            // Bootstrap from our own prior shard so restart-survival works,
            // mirroring SiteMap::with_persistence.
            if let Some(snap) = shard.load_own() {
                for row in &snap.countries {
                    if row.country.is_empty() {
                        continue;
                    }
                    let e = self
                        .by_country
                        .entry(row.country.clone())
                        .or_insert_with(|| Arc::new(DomainCounter::default()))
                        .clone();
                    e.total.fetch_add(row.total, Ordering::Relaxed);
                    e.denied.fetch_add(row.denied, Ordering::Relaxed);
                    e.challenged.fetch_add(row.challenged, Ordering::Relaxed);
                }
                tracing::info!(
                    path = %shard.shard_path().display(),
                    countries = snap.countries.len(),
                    "metrics: restored geo shard from disk"
                );
            }
            self.geo_shard = Some(shard);
        }
        self
    }

    /// V242 — snapshot this worker's `by_country` counters into a
    /// `GeoSnapshot` for shard serialisation.
    fn geo_snapshot(&self) -> GeoSnapshot {
        let countries = self
            .by_country
            .iter()
            .map(|e| CountryRow {
                country: e.key().clone(),
                total: e.value().total.load(Ordering::Relaxed),
                denied: e.value().denied.load(Ordering::Relaxed),
                challenged: e.value().challenged.load(Ordering::Relaxed),
            })
            .collect();
        GeoSnapshot {
            written_at_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            countries,
        }
    }

    /// V242 — flush this worker's `by_country` slice to its geo shard.
    /// No-op when geo persistence was not configured. Wired into the
    /// PingoraBackground tick alongside the site-map flush.
    pub fn flush_geo_shard(&self) {
        if let Some(shard) = &self.geo_shard {
            shard.flush(&self.geo_snapshot());
        }
    }

    /// V239 — top-N countries by total request count, descending.
    /// Returns (country_code, total, denied) for the geo/top admin API.
    ///
    /// V242 — when geo persistence is configured, this merges **all**
    /// workers' shards (summing per-country totals/denied) so the result
    /// is stable regardless of which SO_REUSEPORT worker answers the admin
    /// request. The merge folds in this worker's own current shard via the
    /// directory read, and also unions the live in-memory counters for
    /// counts accumulated since the last flush. Without persistence it
    /// falls back to the per-worker in-memory slice (prior behaviour).
    pub fn top_countries(&self, n: usize) -> Vec<(String, u64, u64)> {
        // Start from the in-memory per-worker counters.
        let mut merged: std::collections::HashMap<String, (u64, u64)> = self
            .by_country
            .iter()
            .map(|e| {
                (
                    e.key().clone(),
                    (
                        e.value().total.load(Ordering::Relaxed),
                        e.value().denied.load(Ordering::Relaxed),
                    ),
                )
            })
            .collect();

        // Fold in the OTHER workers' shards. We deliberately skip our own
        // shard file (already represented by the fresher in-memory counts
        // above) to avoid double-counting our slice.
        if let Some(shard) = &self.geo_shard {
            let dir = shard.shard_path().parent();
            let own = shard.shard_path();
            if let Some(dir) = dir {
                let per_shard =
                    geo_shard::merge_all_shards_excluding(dir, own, geo_shard::SHARD_MAX_AGE_SECS);
                for (cc, row) in per_shard {
                    let e = merged.entry(cc).or_insert((0, 0));
                    e.0 += row.total;
                    e.1 += row.denied;
                }
            }
        }

        let mut v: Vec<(String, u64, u64)> = merged
            .into_iter()
            .map(|(cc, (total, denied))| (cc, total, denied))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    pub fn observe_filter_block(&self, filter: &str) {
        let entry = self
            .by_filter
            .entry(filter.to_string())
            .or_insert_with(|| Arc::new(FilterCounter::default()))
            .clone();
        entry.blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_filter_challenge(&self, filter: &str) {
        let entry = self
            .by_filter
            .entry(filter.to_string())
            .or_insert_with(|| Arc::new(FilterCounter::default()))
            .clone();
        entry.challenges.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_upstream_status(&self, status: u16) {
        match status / 100 {
            2 => self.upstream_2xx.fetch_add(1, Ordering::Relaxed),
            4 => self.upstream_4xx.fetch_add(1, Ordering::Relaxed),
            5 => self.upstream_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Render the full snapshot in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        let push_counter = |out: &mut String, name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };

        push_counter(
            &mut out,
            "aegis_requests_total",
            "Total inbound HTTP requests.",
            self.requests_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_requests_denied",
            "Requests rejected by filter pipeline.",
            self.requests_denied.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_requests_challenged",
            "Requests answered with a challenge.",
            self.requests_challenged.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_upstream_2xx",
            "Upstream responses with 2xx status.",
            self.upstream_2xx.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_upstream_4xx",
            "Upstream responses with 4xx status.",
            self.upstream_4xx.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_upstream_5xx",
            "Upstream responses with 5xx status.",
            self.upstream_5xx.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_upstream_errors",
            "Upstream connection failures.",
            self.upstream_errors.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_cache_hits",
            "Threat-aware response cache hits served from RAM.",
            self.cache_hits.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "aegis_cache_misses",
            "Cache-eligible requests that fell through to upstream.",
            self.cache_misses.load(Ordering::Relaxed),
        );

        out.push_str("# HELP aegis_domain_total Per-domain request counter.\n");
        out.push_str("# TYPE aegis_domain_total counter\n");
        for kv in self.domain.iter() {
            let host = kv.key().replace('"', "");
            let v = kv.value();
            out.push_str(&format!(
                "aegis_domain_total{{host=\"{host}\"}} {}\n",
                v.total.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "aegis_domain_denied{{host=\"{host}\"}} {}\n",
                v.denied.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "aegis_domain_challenged{{host=\"{host}\"}} {}\n",
                v.challenged.load(Ordering::Relaxed)
            ));
        }

        out.push_str("# HELP aegis_requests_by_protocol Requests served per wire protocol.\n");
        out.push_str("# TYPE aegis_requests_by_protocol counter\n");
        for (label, atom) in [
            ("h1", &self.by_protocol.h1),
            ("h2", &self.by_protocol.h2),
            ("h3", &self.by_protocol.h3),
            ("other", &self.by_protocol.other),
        ] {
            out.push_str(&format!(
                "aegis_requests_by_protocol{{protocol=\"{label}\"}} {}\n",
                atom.load(Ordering::Relaxed)
            ));
        }

        out.push_str("# HELP aegis_filter_blocks Per-filter block counter.\n");
        out.push_str("# TYPE aegis_filter_blocks counter\n");
        for kv in self.by_filter.iter() {
            let f = kv.key().replace('"', "");
            let v = kv.value();
            out.push_str(&format!(
                "aegis_filter_blocks{{filter=\"{f}\"}} {}\n",
                v.blocks.load(Ordering::Relaxed)
            ));
            out.push_str(&format!(
                "aegis_filter_challenges{{filter=\"{f}\"}} {}\n",
                v.challenges.load(Ordering::Relaxed)
            ));
        }

        out.push_str("# HELP aegis_request_latency_ms Request latency in ms.\n");
        out.push_str("# TYPE aegis_request_latency_ms histogram\n");
        // observe() writes to exactly ONE bucket (the first whose edge >= ms).
        // Prometheus requires cumulative `le=` counts, so we reconstruct them
        // here with a running prefix sum — byte-identical output to the old
        // all-buckets scheme but only 3 atomic RMW ops per request instead of ~13.
        let mut cumulative = 0u64;
        for (i, edge) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative += self.latency.buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "aegis_request_latency_ms_bucket{{le=\"{edge}\"}} {cumulative}\n"
            ));
        }
        let count = self.latency.count.load(Ordering::Relaxed);
        let sum = self.latency.sum_ms.load(Ordering::Relaxed);
        out.push_str(&format!(
            "aegis_request_latency_ms_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        out.push_str(&format!("aegis_request_latency_ms_sum {sum}\n"));
        out.push_str(&format!("aegis_request_latency_ms_count {count}\n"));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_all_counters() {
        let m = RuntimeMetrics::default();
        m.requests_total.fetch_add(3, Ordering::Relaxed);
        m.observe_domain_outcome("example.com", true, false);
        m.observe_upstream_status(404);
        m.latency.observe(7);
        m.by_protocol.record(Protocol::H3);
        let out = m.render_prometheus();
        assert!(out.contains("aegis_requests_total 3"));
        assert!(out.contains("aegis_domain_total{host=\"example.com\"} 1"));
        assert!(out.contains("aegis_upstream_4xx 1"));
        assert!(out.contains("aegis_request_latency_ms_count 1"));
        assert!(out.contains("aegis_requests_by_protocol{protocol=\"h3\"} 1"));
        assert_eq!(Protocol::H3.label(), "h3");
    }

    #[test]
    fn histogram_buckets_monotonic() {
        // Under the single-bucket layout observe() increments exactly one raw
        // bucket per call.  render_prometheus reconstructs the Prometheus
        // cumulative `le=` series via a prefix sum.  This test verifies:
        //   1. The prefix sum is non-decreasing (monotonic).
        //   2. The final cumulative value equals the total observation count.
        //   3. The cumulative series is correct for the two test inputs.
        //      Edges = [1,5,10,25,50,...]:
        //        observe(3)  → first edge >= 3  = 5  → bucket index 1
        //        observe(40) → first edge >= 40 = 50 → bucket index 4
        let h = LatencyHistogram::default();
        h.observe(3);
        h.observe(40);
        let prefix_sums: Vec<u64> = h
            .buckets
            .iter()
            .scan(0u64, |acc, b| {
                *acc += b.load(Ordering::Relaxed);
                Some(*acc)
            })
            .collect();
        // Must be non-decreasing.
        for w in prefix_sums.windows(2) {
            assert!(w[1] >= w[0], "prefix sum not monotonic: {:?}", prefix_sums);
        }
        // Final cumulative must equal total count (2 observations).
        assert_eq!(*prefix_sums.last().unwrap(), 2);
        // observe(3) lands at index 1, observe(40) at index 4 (edge=50): the
        // cumulative is 1 from index 1..=3 and reaches 2 at index 4.
        assert_eq!(prefix_sums[1], 1);
        assert_eq!(prefix_sums[3], 1);
        assert_eq!(prefix_sums[4], 2);
    }
}
