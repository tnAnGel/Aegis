# Metrics and telemetry

**Languages:** **English** · [Русский](../ru/25-metrics-telemetry.md) · [中文](../zh/25-metrics-telemetry.md)

AEGIS's observability subsystem consists of three independent layers: persistent timeseries rings for dashboard charts (`series_1m`/`series_1h`), the `GET /metrics` endpoint in Prometheus format with all `aegis_*` counters, and streaming export of every security decision (`SecurityEvent`) — into the structured log, into Prometheus counters with bounded cardinality, and into EventBridge (NDJSON over a Unix socket for SIEM, optionally in the T-Pot/Sicherheitstacho schema). This document describes each layer exactly as it is implemented in the code, with file paths.

> Related documents: request log — [24-request-log.md](24-request-log.md); multi-process operation and cross-worker state — [06-workers.md](06-workers.md); XDP counters in the fast-path context — [13-xdp-ebpf.md](13-xdp-ebpf.md); GeoIP aggregation — [20-geoip.md](20-geoip.md); arsenal and scenarios (the sicherheitstacho_emits counter) — [21-arsenal-scenarios.md](21-arsenal-scenarios.md); the admin API in full — [30-admin-api.md](30-admin-api.md); the admin panel — [29-admin-panel.md](29-admin-panel.md).

---

## 1. Overview of the layers

| Layer | Source | Purpose | File |
|------|----------|------------|------|
| Timeseries rings | cluster-mmap counters, sampled once every 60 s | Dashboard charts (traffic/blocks over 1h…90d) | `src/metrics/timeseries.rs` |
| Prometheus `/metrics` | `RuntimeMetrics` + cache + XDP + cluster | Prometheus/Grafana scrape, per-process + cluster | `src/metrics/mod.rs`, `src/proxy/pingora_admin.rs` |
| SecurityEvent | every filter decision | One canonical shape per decision | `src/security_event.rs` |
| EventBridge | stream of `SecurityEvent` | NDJSON over a Unix socket for SIEM | `src/event_bridge.rs` |
| Sicherheitstacho | rendering of `SecurityEvent` | T-Pot-compatible NDJSON format | `src/sicherheitstacho.rs` |
| Sharded counters | hot path | per-CPU slots without cache-line bouncing | `src/metrics/sharded.rs` |

The three layers are independent: you can scrape `/metrics` without EventBridge, you can run EventBridge without timeseries, and so on. All three tolerate absence (graceful degradation): an uninitialised store returns an empty response, a disabled bridge is a no-op, XDP counters render as zeroes.

---

## 2. Sharded counters (the hot-path foundation)

File: `src/metrics/sharded.rs`.

All hot per-request counters are wrapped in `ShardedCounter` — an array of `AtomicU64`, one slot per CPU, each slot aligned to 64 bytes (the `#[repr(align(64))]` struct `Padded`), so that adjacent slots do not share a cache line.

```rust
#[repr(align(64))]
struct Padded(AtomicU64);

pub struct ShardedCounter {
    shards: Box<[Padded]>,
}
```

- **The number of shards** is `num_shards()`: `std::thread::available_parallelism()` (one per CPU), falling back to `8`, always clamped to the range `[1, 64]`. The ceiling of 64 keeps the read-sum cost acceptable even on large machines.
- **`fetch_add(delta, order)`** writes into the shard bound to the current thread (`shard_idx`: round-robin assignment via thread-local on first access, after which it is a single TLS read with no atomics). It returns the previous value of **one shard**, not the total (the signature mirrors `AtomicU64::fetch_add` for drop-in compatibility).
- **`load(order)`** sums all shards. Linear in the number of shards, called rarely (only on a `/metrics` scrape).

This means: to obtain a correct total counter value always use `load()`, not the return value of `fetch_add()`. The API is deliberately identical to `AtomicU64`, so the hot path in `http.rs` does not change.

---

## 3. Prometheus `/metrics`

The `GET /metrics` endpoint is served by both data planes:

- **aegis-pingora** (primary): `src/proxy/pingora_admin.rs`, the `("GET", "/metrics")` branch (around line 5374). Content-Type is `text/plain; version=0.0.4`.
- **aegis (hyper)**: `src/server.rs` (around line 1322).

The endpoint is **public** — no authorisation required: `src/admin_auth.rs` explicitly returns `("GET", "/metrics") => None` (metrics are public), whereas `GET /admin/api/metrics/series` requires the `Read` role.

### 3.1 Response composition (aegis-pingora)

In `pingora_admin.rs` the body is assembled from four blocks:

```rust
let mut m = self.metrics.render_prometheus();   // RuntimeMetrics
self.append_cache_stats(&mut m);                // aegis_cache_*
self.append_xdp_stats(&mut m);                  // aegis_xdp_*
self.append_cluster_stats(&mut m);              // aegis_cluster_*
```

> **Honest caveat.** `SecurityEventEmitter::render_prometheus()` (the `aegis_security_decisions_total` / `aegis_security_events_total` counters, see §5.2) exists in the code but is **not** appended to the `/metrics` body in either the pingora or the hyper handler as of the time of writing. The `/metrics` assembly includes only `RuntimeMetrics` + cache + XDP + cluster. These security counters are available via `snapshot()`/`total()` for the admin API's JSON endpoints. Likewise, in the hyper `/metrics` branch only the XDP block is appended.

### 3.2 Base counters `RuntimeMetrics::render_prometheus()`

File: `src/metrics/mod.rs`. All are of type `counter`, per-process (the value of a single worker).

| Metric | Type | What it counts |
|---------|-----|-------------|
| `aegis_requests_total` | counter | All incoming HTTP requests |
| `aegis_requests_denied` | counter | Rejected by the filter pipeline |
| `aegis_requests_challenged` | counter | Answered with a challenge |
| `aegis_upstream_2xx` | counter | Upstream 2xx responses |
| `aegis_upstream_4xx` | counter | Upstream 4xx responses |
| `aegis_upstream_5xx` | counter | Upstream 5xx responses |
| `aegis_upstream_errors` | counter | Upstream connection errors |
| `aegis_cache_hits` | counter | Hits of the threat-aware cache from RAM |
| `aegis_cache_misses` | counter | Cache-eligible requests that went to the upstream |

Labelled metrics (also counters):

| Metric | Labels | Source |
|---------|--------|----------|
| `aegis_domain_total` / `aegis_domain_denied` / `aegis_domain_challenged` | `host="…"` | DashMap `domain`, `observe_domain_outcome()` |
| `aegis_requests_by_protocol` | `protocol="h1\|h2\|h3\|other"` | `ProtocolCounters::record()` |
| `aegis_filter_blocks` / `aegis_filter_challenges` | `filter="…"` | DashMap `by_filter`, `observe_filter_block()`/`observe_filter_challenge()` |

> The cardinality of the `host`/`filter` labels is bounded by the set of real domains and filter names (not by attacker input). `"` is escaped in labels (via `.replace('"', "")` for host/filter).

### 3.3 Latency histogram

`aegis_request_latency_ms` is of type `histogram`. The buckets (in milliseconds) are defined in `LATENCY_BUCKETS_MS`:

```rust
pub const LATENCY_BUCKETS_MS: &[u64] =
    &[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
```

Series: `aegis_request_latency_ms_bucket{le="…"}` (including `le="+Inf"`), `aegis_request_latency_ms_sum`, `aegis_request_latency_ms_count`.

Hot-path optimisation: `observe(ms)` performs exactly **3** atomic RMWs (count, sum_ms and **one** bucket — the first whose edge ≥ ms, via `partition_point`), instead of ~13 when incrementing all buckets. Prometheus requires cumulative `le=` counters, so `render_prometheus()` reconstructs the cumulative series with a prefix sum at scrape time — the output is byte-for-byte identical to the "all buckets" scheme. Observations with `ms` greater than the largest edge are counted only in `count`/`sum` (the `+Inf` bucket uses `count`).

### 3.4 Cache counters (`append_cache_stats`)

The source is `self.cache.stats()` (see `src/proxy/response_cache.rs`). All counters:

| Metric | What it counts |
|---------|-------------|
| `aegis_cache_stores` | Entries inserted into the cache |
| `aegis_cache_evictions` | Evicted (stale, LRU pressure, broadcast purge) |
| `aegis_cache_skipped_high_threat` | Lookups forced to MISS by the threat-aware policy |
| `aegis_cache_skipped_uncacheable` | Stores skipped because the response is uncacheable per RFC 9111 |
| `aegis_cache_not_modified` | 304 Not Modified from cached validators |
| `aegis_cache_served_low` | Hits served to low-threat clients (V98 tiered) |
| `aegis_cache_served_medium` | Medium-threat hits within the TTL/2 freshness window |
| `aegis_cache_forced_miss_high` | Lookups turned into MISS by the high-threat policy |

### 3.5 XDP counters (`append_xdp_stats`)

The source is `self.xdp.counters().unwrap_or_default()`. With XDP disabled, `NoopXdp.counters()` returns `Ok(default)` → all zeroes are always rendered, so dashboards can scrape unconditionally without branch logic. All counters:

| Metric | What it counts |
|---------|-------------|
| `aegis_xdp_pass` | Packets passed by the XDP fast path into userspace |
| `aegis_xdp_drop_deny` | Dropped by the XDP deny list |
| `aegis_xdp_drop_rate` | Dropped by XDP's per-IP token bucket |
| `aegis_xdp_drop_allowonly` | Dropped in allow-only (whitelist) mode |
| `aegis_xdp_drop_syn` | SYNs dropped by the SYN-flood guard |
| `aegis_xdp_drop_waf` | Dropped by the inline eBPF WAF (Phase 3X, scanner paths) |
| `aegis_xdp_fast_pass` | Packets on the allow-list fast path (bypassing deny/rate/WAF) |

XDP counters are per-CPU under the hood and are summed on read inside `xdp::counters()`. Fast-path details are in [13-xdp-ebpf.md](13-xdp-ebpf.md).

### 3.6 Cluster counters (`append_cluster_stats`)

Phase D: sums across **all** REUSEPORT workers via a shared-mmap arena. Unlike the per-process `aegis_*`, any worker renders the cluster aggregate — dashboards do not need to scrape every worker and add up.

The block is a no-op if the arena did not attach (`crate::shared_state::global::enabled()` == false): Linux without `/dev/shm`, macOS dev builds, restricted containers. The absence of `aegis_cluster_*` lines is an indicator of an arena-unavailable worker.

| Metric | Type | Cluster index (`cluster_idx`) |
|---------|-----|--------------------------------|
| `aegis_cluster_requests_total` | counter | `REQUESTS_TOTAL` (0) |
| `aegis_cluster_requests_denied` | counter | `REQUESTS_DENIED` (1) |
| `aegis_cluster_requests_challenged` | counter | `REQUESTS_CHALLENGED` (2) |
| `aegis_cluster_cache_hits` | counter | `CACHE_HITS` (3) |
| `aegis_cluster_cache_misses` | counter | `CACHE_MISSES` (4) |
| `aegis_cluster_upstream_2xx` | counter | `UPSTREAM_2XX` (5) |
| `aegis_cluster_upstream_4xx` | counter | `UPSTREAM_4XX` (6) |
| `aegis_cluster_upstream_5xx` | counter | `UPSTREAM_5XX` (7) |
| `aegis_cluster_compactions_total` | counter | `COMPACTIONS_TOTAL` (8) |
| `aegis_cluster_compactions_removed` | counter | `COMPACTIONS_REMOVED` (9) |
| `aegis_cluster_arena_bytes` | **gauge** | arena size (`arena_size()`) |
| `aegis_cluster_arena_used_bytes` | **gauge** | used within the arena (`arena_used()`) |

The counter ordinals are defined in `src/shared_state/global.rs`, module `cluster_idx`. They are **stable across releases** — operators build dashboards on these indexes; new counters are only appended at the end, never reordered and never reused. The full slot set: 0–12 are occupied (the above plus `RATE_LIMITED=10`, `TARPIT=11`, `RTBH=12`), `SLOTS=16` is reserved. The arena name is set by `AEGIS_SHARED_STATE_NAME` (default `/aegis-state`) and its size by `AEGIS_SHARED_STATE_SIZE_MB` (default 4 MB).

> Note: `RATE_LIMITED`, `TARPIT`, `RTBH` exist as cluster slots and are used by the timeseries sampler (§4), but `append_cluster_stats` does **not** emit separate `aegis_cluster_rate_limited` / `…_tarpit` / `…_rtbh` lines.

### 3.7 PromQL examples

```promql
# block ratio over 5 minutes (cluster aggregate)
sum(rate(aegis_cluster_requests_denied[5m]))
  / sum(rate(aegis_cluster_requests_total[5m]))

# p99 latency (from a single worker's histogram)
histogram_quantile(0.99, rate(aegis_request_latency_ms_bucket[5m]))

# top filters by blocks
topk(10, sum by (filter)(rate(aegis_filter_blocks[5m])))

# volume of XDP drops by reason
sum by (__name__)({__name__=~"aegis_xdp_drop_.*"})
```

---

## 4. Timeseries rings

File: `src/metrics/timeseries.rs`. These are persistent fleet-wide charts for the dashboard, not Prometheus.

### 4.1 The "single writer" architecture

One `TimeSeriesStore` lives in each REUSEPORT worker. All workers **read** from the cluster mmap (via `snapshot_cluster()`), but only the worker holding the advisory lock `flock(LOCK_EX | LOCK_NB)` on `.sampler.lock` **writes**. Since increments from all workers are already visible in the cluster mmap, the single writer captures the whole fleet — with no double counting. The remaining workers are in read-only mode (`state == None`): `sample_once()` is a no-op, `query()` reads the files written by the writer.

The lock is acquired in `TimeSeriesStore::new()` (`try_acquire_writer_lock`): whoever first succeeds at `LOCK_EX | LOCK_NB` is the writer. `is_writer()` reports the status.

### 4.2 Sampling

The sampler is called from a background tick: `src/proxy/pingora_background.rs` (around line 463); `ts.sample_once()` fires once every 60 s (every 2nd 30-second tick, via the xor parity `ts_tick_parity`). The call is safe on all workers — on non-writers it is a no-op.

`sample_once()` takes a `snapshot_cluster()`, computes deltas against the previous snapshot (`wrapping_sub`), builds a `Point` and:
1. writes into the 1-minute ring `series_1m.bin`;
2. accumulates into the current 1-hour bucket; on a UTC hour change (`current_hour_start`) it flushes the accumulated `Point` into `series_1h.bin` and resets the accumulator.

If the arena is not yet initialised (`snap.len() < cluster_idx::SLOTS`) the tick is skipped. A poisoned mutex results in a warning and a skip, without panicking.

### 4.3 Binary ring format

Directory: `$AEGIS_METRICS_DIR` → `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics` (priority order in `default_store_dir()`).

```text
series_1m.bin  — 1-minute resolution, 2880 records (48 h)
series_1h.bin  — 1-hour    resolution, 2160 records (90 d)
.sampler.lock  — the writer's advisory flock
```

| Constant | Value |
|-----------|----------|
| `RING_1M_CAPACITY` | 2880 (48 h) |
| `RING_1H_CAPACITY` | 2160 (90 d) |
| `MAX_RESPONSE_POINTS` | 300 |

Each file is a 16-byte versioned header plus fixed 96-byte records forming a ring buffer.

**Header `FileHeader` (16 bytes):**

| Offset | Size | Field | Value |
|--------|------|------|----------|
| 0 | 8 | magic | `b"AEGISTS1"` |
| 8 | 4 | version | `1u32` LE |
| 12 | 4 | head | `u32` LE — index of the next slot to write (mod capacity) |

On a magic/version mismatch or `head >= capacity` the file is reinitialised with a fresh header (migration-safe tombstone — changing `FILE_MAGIC` forces recreation of all files).

**Record `Point` (96 bytes = 12 × u64 LE):** `t_unix`, `requests`, `denied`, `challenged`, `rate_limited`, `tarpit`, `rtbh`, `cache_hits`, `cache_misses`, `upstream_2xx`, `upstream_4xx`, `upstream_5xx`.

All counter fields are **bucket deltas** (increments over the interval), not running totals. The deltas come from the cluster indexes `REQUESTS_TOTAL`, `REQUESTS_DENIED`, `REQUESTS_CHALLENGED`, `RATE_LIMITED`, `TARPIT`, `RTBH`, `CACHE_HITS`, `CACHE_MISSES`, `UPSTREAM_2XX/4XX/5XX`.

**The derived field `allow`** is computed on read (not stored):

```rust
allow = max(0, requests − (denied + challenged + rate_limited + tarpit + rtbh))
```

Flooring at zero (`saturating_sub`) guards against transient counter skew.

### 4.4 Downsampling and querying

`query(range_secs)`:
- `range_secs <= 172_800` (≤ 48 h) → the 1-minute ring, `resolution = "1m"`;
- `range_secs > 172_800` → the 1-hour ring, `resolution = "1h"`.

The required number of most recent records is read (`read_recent`, chronological order), filtered by `t_unix >= now − range_secs`, then **downsampled** to ≤ `MAX_RESPONSE_POINTS` (300): records are grouped into ≤300 bins, each bin's fields are summed (`add_to_accum`), and the bin's `t_unix` is the timestamp of the first record. If there are ≤ 300 records they are returned as is.

### 4.5 `GET /admin/api/metrics/series`

Handler: `api_metrics_series` in `src/proxy/pingora_admin.rs` (around line 995). Requires the `Read` role.

The `?range=` parameter (case-insensitive, default `24h`):

| Label | Seconds | Ring |
|-------|--------|------|
| `1h` | 3 600 | 1m |
| `6h` | 21 600 | 1m |
| `24h` | 86 400 | 1m |
| `7d` | 604 800 | 1h |
| `30d` | 2 592 000 | 1h |
| `90d` | 7 776 000 | 1h |

An unknown label → `400` with `{"error": "unknown range …; use one of: 1h 6h 24h 7d 30d 90d"}`.

The response is the JSON `SeriesResponse`:

```json
{
  "resolution": "1m",
  "points": [
    {
      "t_unix": 1733659200,
      "requests": 1240, "denied": 30, "challenged": 5,
      "rate_limited": 8, "tarpit": 2, "rtbh": 0,
      "allow": 1195,
      "cache_hits": 800, "cache_misses": 120,
      "upstream_2xx": 1100, "upstream_4xx": 25, "upstream_5xx": 3
    }
  ]
}
```

When the store is **not attached** (the operator did not call `with_timeseries`), a `200` is returned with `{"resolution":"1m","points":[]}` — the UI draws "no data" rather than breaking. A serialisation/query error → `500` with `{"error": …}`.

```bash
curl -s -H "x-admin-token: $TOKEN" \
  "http://127.0.0.1:8080/admin/api/metrics/series?range=24h" | jq .
```

---

## 5. SecurityEvent — the canonical decision shape (V116)

File: `src/security_event.rs`.

Before V116 each filter logged its decision in its own ad-hoc form. `SecurityEvent` is a single small JSON-serialisable shape with no high-cardinality fields (there are no raw IPs in metric labels — only in the event body).

### 5.1 Structure

```rust
pub enum DecisionKind { Allow, Challenge, Deny, Throttle, Observed }

pub struct SecurityEvent {
    pub action: DecisionKind,
    pub reason: &'static str,        // static string → cardinality is bounded
    pub request_id: String,
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub risk_score: Option<u8>,      // 0..=255 from RiskEngine, None if it was not consulted
    pub extra_reasons: Vec<&'static str>,
    pub waf_rule_id: Option<String>,
    pub ja4_prefix: Option<String>,  // truncated to 12 characters (the JA4_a family)
}
```

| `DecisionKind` | Semantics |
|----------------|-----------|
| `Allow` | Passed through |
| `Challenge` | Answered with a challenge |
| `Deny` | Blocked |
| `Throttle` | Slowed down (rate limit) |
| `Observed` | Match-but-don't-act — WAF shadow mode (V109), Risk Engine observe mode (V108): "would have blocked", but did not |

Builder methods: `.with_risk(score, extras)`, `.with_waf_rule(id)`, `.with_ja4(ja4)` (truncates to 12 characters). The `reason`s are `&'static str`, reused throughout the code (V108 RiskEngine + V109 WAF severity + V110 UA/JA4 mismatch), which gives bounded cardinality (~30 distinct values).

### 5.2 `SecurityEventEmitter` — the sink

`emit(&ev)` does the following (metrics first — they must not fail on log serialisation problems):
1. increments `total` (AtomicU64);
2. increments the counter keyed by `(action, reason)` — a DashMap whose key is `&'static str` ⇒ the map cannot grow beyond the static set;
3. a structured log line: `tracing::info!(target: "aegis::security_event", action, reason, request_id, host, client_ip, method, path, risk_score, waf_rule_id, ja4_prefix, "security_decision")`.

The operator collects this target with their own log aggregator.

`render_prometheus()` produces (see the caveat in §3.1 — it is currently not inserted into `/metrics`):

| Metric | Type | Labels |
|---------|-----|--------|
| `aegis_security_decisions_total` | counter | `action="allow\|challenge\|deny\|throttle\|observed"`, `reason="…"` |
| `aegis_security_events_total` | counter | — (total emissions since startup) |

`reason` is escaped (`\\` and `"`) for strictness of the Prometheus text format. For the admin API's JSON endpoints there are `snapshot()` → `Vec<((DecisionKind, &'static str), u64)>` and `total()`.

Ready-made dashboard queries (from the module docstring):

```promql
sum(rate(aegis_security_decisions_total{action="deny"}[5m]))
topk(10, sum by (reason)(rate(aegis_security_decisions_total[5m])))
```

---

## 6. EventBridge — NDJSON over a Unix socket for SIEM (V127)

File: `src/event_bridge.rs`.

The operator connects a SIEM / log aggregator (Wazuh, Elasticsearch, Loki, Splunk, Vector, FluentBit) to a single endpoint that emits one JSON object per security decision. `SecurityEvent` (V116) is the data; EventBridge (V127) is the transport.

### 6.1 Properties

- **Unix socket**: by default the path from `AEGIS_EVENT_SOCKET` (there is no hard-coded fallback in the code — `new(socket_path)` takes an `Option<PathBuf>`; the docstring mentions the typical `/var/run/aegis-events.sock`). No network exposure, ACL by file permissions. Subscribe via `nc -U` / `socat` / the SIEM's unix-socket reader. On `spawn()` the socket is created with permissions `0600` (the operator chmods/chowns it for their own SIEM).
- **NDJSON broadcast**: every connected subscriber receives every event. New connections start "from a clean slate" (no history replay).
- **Lossy bounded queue per subscriber**: `SUBSCRIBER_CHANNEL_CAP = 1024` events of headroom. If a slow subscriber cannot keep up, `try_send` drops the event for it (drop > block), and the proxy never blocks. AEGIS is a proxy that emits, not a logging system.
- **Best-effort**: if the socket is unavailable / `socket_path = None`, `emit()` is cheap and a no-op (`enabled()` == false).

Hot-path cost: one mpsc `try_send` per event, sub-µs when there are no subscribers. The JSON is serialised **once** per call and shared between subscribers via `Arc` (cloning is an atomic bump). Dead subscribers (`Closed`) are pruned on the next `emit`. Diagnostics: `subscriber_count()`.

### 6.2 Lifecycle

- `EventBridge::new(socket_path)` — constructs it disconnected; the format is chosen from the env var `AEGIS_EVENT_FORMAT` (see §7).
- `spawn().await` — binds the Unix socket (first best-effort removing a stale one from a previous process), starts the accept loop in the background, sets permissions to 0600. A no-op when `socket_path = None`. Idempotent.
- `emit(&ev)` — serialises and broadcasts (see above).

### 6.3 Native NDJSON (the default format)

With `WireFormat::Native` the event is serialised via `serde_json` directly from `SecurityEvent` (see §5.1) — fields as they are, one line per event:

```bash
# subscribe to the stream
socat - UNIX-CONNECT:/var/run/aegis-events.sock
# or
nc -U /var/run/aegis-events.sock
```

```json
{"action":"deny","reason":"waf_critical","request_id":"…","host":"example.com","client_ip":"1.2.3.4","method":"GET","path":"/admin","risk_score":85,"extra_reasons":["…"],"waf_rule_id":"custom-001","ja4_prefix":"t13d1516h2_8"}
```

---

## 7. Sicherheitstacho / T-Pot format (V185)

File: `src/sicherheitstacho.rs`.

T-Pot (telekom-security/tpotce) reduces dozens of honeypots to Telekom CERT's normalised "Sicherheitstacho" format. By adopting it, AEGIS gains interop with the whole consumer side of the deception ecosystem (ELK ingest mappings, threat-feed aggregators, the public Sicherheitstacho dashboard).

### 7.1 Enabling it

```bash
# switch the NDJSON schema without changing code
AEGIS_EVENT_FORMAT=sicherheitstacho   # synonym: tpot
```

The choice is made in `EventBridge::new`: `Some("sicherheitstacho") | Some("tpot")` → `WireFormat::Sicherheitstacho`, otherwise `WireFormat::Native`. Programmatically: `.with_format(...)`.

### 7.2 Mapping and schema

`render_sicherheitstacho(ev)` (in `event_bridge.rs`) translates `DecisionKind` into `Category`:

| `DecisionKind` | `Category` |
|----------------|-----------|
| `Deny` | `Block` (`"block"`) |
| `Challenge` | `Challenge` (`"challenge"`) |
| `Throttle` | `Waf` (`"waf"`) |
| `Allow` / `Observed` | `Waf` (`"waf"`) |

(`Category::Honeypot` / `Tarpit` are defined in the enum, but the current mapping from `SecurityEvent` never selects them.) `tags` = `extra_reasons` + `reason`. `transport="TCP"`, `service="aegis-waf"`, `dst_port=443`, `src_port=0`; `country`/`asn`/`user_agent` are `None`.

The module renders JSON **by hand** (with no serde dependency — it is small, so as to remain drop-in for EventBridge), with correct escaping (`"`, `\`, `\n`, `\r`, `\t`, control characters < 0x20 → `\uXXXX`) and its own minimalist ISO-8601 UTC timestamp renderer (Hinnant's algorithm, without chrono/jiff).

```json
{"@timestamp":"2026-05-22T12:34:56.000Z","type":"Aegis","src_ip":"203.0.113.7","src_port":0,"dst_port":443,"transport":"TCP","service":"aegis-waf","category":"block","tags":["sqlmap","waf_critical"],"request":{"method":"POST","host":"evil.test","path":"/phpmyadmin/index.php"}}
```

### 7.3 Export volume counter (arsenal)

In the Sicherheitstacho format every `emit` bumps (if bound) `sicherheitstacho_counter` — an `Arc<ShardedCounter>` pointing at the arsenal shard `sicherheitstacho_emits`. This way the Defence Arsenal panel (`/admin/api/arsenal` → `sicherheitstacho.emits`) reflects the real export volume in the T-Pot schema. The binding is `.with_sicherheitstacho_counter(...)`, called from the binary when both EventBridge and `ArsenalState` are present. With `None` (no arsenal) the counter is not bumped. See [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

---

## 8. Dashboard panels and related endpoints

The charts are built by the frontend (see [29-admin-panel.md](29-admin-panel.md)) on top of data from:

| Endpoint | Data source | Purpose |
|----------|-----------------|------------|
| `GET /admin/api/metrics/series?range=` | timeseries rings (§4) | Traffic/block charts over 1h…90d |
| `GET /metrics` | Prometheus (§3) | External scrape |
| `GET /admin/api/geo/top` | `RuntimeMetrics::top_countries(20)` | World map / Top Countries |
| `GET /admin/api/geoip/status` | `geoip::resolve_country_db_path` | GeoIP database status |
| (telemetry) `api_telemetry_status` | env | Status of EventBridge/format/ClamAV |

### 8.1 Geo aggregation (V239/V242)

`observe_country(cc, denied, challenged)` tallies the request by ISO country code at ingress — **only** if a GeoIP database is configured (on the default `NoopGeoIp` the lookup is a near-free `None`, so there is no hot-path cost on deployments without GeoIP). The counters are the reusable `DomainCounter` (total/denied/challenged), per worker under SO_REUSEPORT.

`GET /admin/api/geo/top` → `api_geo_top` returns `[{country, total, denied}]` (up to 20). With no GeoIP database, resolve returns `None`, nothing is tallied — the array is empty and the map renders gracefully empty.

`top_countries(n)` (V242): when geo persistence is enabled (`with_geo_persistence(dir)`, default `/var/lib/aegis/geo`), the result merges the shards of **all** workers (its own from live in-memory, the others via `merge_all_shards_excluding` so as not to double count), so it is stable regardless of which worker answered. Without persistence it is a per-worker in-memory slice (a representative sample for top-N, not billing-accurate). Shard flush happens on every ~30-second tick (`flush_geo_shard()`). The shard implementation is `src/metrics/geo_shard.rs`. More detail in [20-geoip.md](20-geoip.md).

### 8.2 Telemetry status

`api_telemetry_status` (`/admin/api/...`) returns the state of EventBridge for the panel:

```json
{
  "event_bridge": {
    "format": "native",
    "format_options": ["native", "sicherheitstacho", "tpot"],
    "socket_path": "/var/run/aegis-events.sock"
  },
  "clamav": { "enabled": false, "addr": null, "env_var": "AEGIS_CLAMAV_ADDR (host:port)" },
  "audit_log_path": "…"
}
```

---

## 9. Cross-worker operation and multi-process

Under SO_REUSEPORT, `aegis-pingora@0..N` runs (see [06-workers.md](06-workers.md)). Summary of metric behaviour:

| Class | Visibility |
|-------|-----------|
| `RuntimeMetrics` (`aegis_*` without `cluster_`) | per-process — the value of a single worker |
| `aegis_cluster_*` | the whole fleet (cluster mmap, any worker renders the aggregate) |
| timeseries rings | the whole fleet (a single writer samples the cluster mmap) |
| `by_country` / geo-top | per worker, or merged-all-shards with `with_geo_persistence` |
| SecurityEvent / EventBridge | per-process (each worker has its own sink/socket — but `AEGIS_EVENT_SOCKET` is one path; the first one binds, `spawn` is idempotent) |

For cross-worker aggregation rely on `aegis_cluster_*` (Prometheus) and the timeseries rings; sum the per-process `aegis_*` yourself if you scrape workers individually.

---

## 10. Environment variables (summary)

| Env | Default | Layer | Effect |
|-----|--------------|------|--------|
| `AEGIS_METRICS_DIR` | `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics` | timeseries | Ring directory |
| `AEGIS_HOME` | `/var/lib/aegis` | timeseries/geo | Path base |
| `AEGIS_EVENT_SOCKET` | (none) | EventBridge | Unix socket path; unset → bridge is a no-op |
| `AEGIS_EVENT_FORMAT` | `native` | EventBridge | `sicherheitstacho`/`tpot` → T-Pot schema |
| `AEGIS_SHARED_STATE_NAME` | `/aegis-state` | cluster | Name of the shared mmap arena |
| `AEGIS_SHARED_STATE_SIZE_MB` | `4` | cluster | Arena size |
| `AEGIS_CLAMAV_ADDR` | (none) | telemetry status | ClamAV host:port (for the panel) |

---

## 11. Operational notes

- **`/metrics` is public** — do not put it behind admin auth; if necessary restrict it with a network ACL/firewall rather than a token.
- **Security counters are not in `/metrics`** — `aegis_security_decisions_total` is collected by the emitter but is not wired into `/metrics`; for decision dashboards use either the structured log `target=aegis::security_event` via a log aggregator, or the EventBridge stream, or the admin API's JSON snapshots.
- **Timeseries data survives a restart** — the rings are on disk; the header is versioned, and on a format change the files are recreated automatically.
- **Without the writer lock** a worker still answers `/admin/api/metrics/series` (it reads the writer's files) — graceful.
- **GeoIP metrics are free without GeoIP** — `observe_country` does nothing on `NoopGeoIp`.
- **EventBridge does not lose the proxy** — a slow SIEM subscriber loses events (lossy), but does not slow traffic down.
- **Cluster counters are absent on non-Linux/without `/dev/shm`** — the absence of `aegis_cluster_*` lines is normal for dev builds.
