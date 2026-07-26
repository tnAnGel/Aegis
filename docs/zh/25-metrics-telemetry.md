# 指标与遥测

**语言：** [English](../en/25-metrics-telemetry.md) · [Русский](../ru/25-metrics-telemetry.md) · **中文**

AEGIS 的可观测性子系统由三个彼此独立的层构成：为仪表盘图表提供数据的持久化时间序列环形缓冲（`series_1m`/`series_1h`）、包含全部 `aegis_*` 计数器的 Prometheus 格式 `GET /metrics` 端点，以及每个安全决策（`SecurityEvent`）的流式导出——导出到结构化日志、导出到基数受限的 Prometheus 计数器，以及导出到 EventBridge（通过 Unix 套接字的 NDJSON，供 SIEM 使用，可选采用 T-Pot/Sicherheitstacho 模式）。本文档严格按照代码中的实现来描述每一层，并给出文件路径。

> 相关文档：请求日志——[24-request-log.md](24-request-log.md)；多进程与跨 worker 状态——[06-workers.md](06-workers.md)；fast-path 语境下的 XDP 计数器——[13-xdp-ebpf.md](13-xdp-ebpf.md)；GeoIP 聚合——[20-geoip.md](20-geoip.md)；arsenal 与场景（sicherheitstacho_emits 计数器）——[21-arsenal-scenarios.md](21-arsenal-scenarios.md)；完整的 admin API——[30-admin-api.md](30-admin-api.md)；管理面板——[29-admin-panel.md](29-admin-panel.md)。

---

## 1. 各层概览

| 层 | 数据源 | 用途 | 文件 |
|------|----------|------------|------|
| 时间序列环形缓冲 | cluster-mmap 计数器，每 60 秒采样一次 | 仪表盘图表（1 小时…90 天的流量/拦截） | `src/metrics/timeseries.rs` |
| Prometheus `/metrics` | `RuntimeMetrics` + cache + XDP + cluster | Prometheus/Grafana 抓取，per-process + cluster | `src/metrics/mod.rs`、`src/proxy/pingora_admin.rs` |
| SecurityEvent | 每个过滤器决策 | 每个决策一个规范结构 | `src/security_event.rs` |
| EventBridge | `SecurityEvent` 流 | 通过 Unix 套接字给 SIEM 的 NDJSON | `src/event_bridge.rs` |
| Sicherheitstacho | `SecurityEvent` 的渲染 | 兼容 T-Pot 的 NDJSON 格式 | `src/sicherheitstacho.rs` |
| 分片计数器 | hot-path | 每 CPU 槽位，避免 cache-line bouncing | `src/metrics/sharded.rs` |

这三层彼此独立：可以在没有 EventBridge 的情况下抓取 `/metrics`，也可以在没有时间序列的情况下运行 EventBridge，等等。三者都能容忍缺失（优雅降级）：未初始化的 store 返回空响应，被关闭的 bridge 是 no-op，XDP 计数器渲染为零。

---

## 2. 分片计数器（hot-path 的基础）

文件：`src/metrics/sharded.rs`。

所有热点的 per-request 计数器都被包装在 `ShardedCounter` 中——一个 `AtomicU64` 数组，每个 CPU 一个槽位，每个槽位按 64 字节对齐（`#[repr(align(64))]` 的 `Padded` 结构体），使相邻槽位不共享 cache line。

```rust
#[repr(align(64))]
struct Padded(AtomicU64);

pub struct ShardedCounter {
    shards: Box<[Padded]>,
}
```

- **分片数量**——`num_shards()`：`std::thread::available_parallelism()`（每 CPU 一个），失败时取 `8`，并始终夹在 `[1, 64]` 区间内。上限 64 使得即使在大型机器上，读取求和的开销也仍可接受。
- **`fetch_add(delta, order)`**——写入与当前线程绑定的分片（`shard_idx`：首次访问时通过 thread-local 做 round-robin 分配，之后就是一次 TLS 读取、无原子操作）。它返回的是**单个分片**的旧值，而不是总和（签名镜像 `AtomicU64::fetch_add` 以保持 drop-in 兼容）。
- **`load(order)`**——对所有分片求和。开销与分片数成线性关系，调用很少（仅在 `/metrics` 抓取时）。

这意味着：要获得正确的计数器总值，请始终使用 `load()`，而不是 `fetch_add()` 的返回值。该 API 刻意与 `AtomicU64` 保持一致，因此 `http.rs` 中的 hot-path 无需改动。

---

## 3. Prometheus `/metrics`

`GET /metrics` 端点由两个数据平面同时提供：

- **aegis-pingora**（主要）：`src/proxy/pingora_admin.rs`，`("GET", "/metrics")` 分支（约在第 5374 行）。Content-Type 为 `text/plain; version=0.0.4`。
- **aegis (hyper)**：`src/server.rs`（约在第 1322 行）。

该端点是**公开的**——不需要授权：`src/admin_auth.rs` 明确返回 `("GET", "/metrics") => None`（指标是公开的），而 `GET /admin/api/metrics/series` 则需要 `Read` 角色。

### 3.1 响应的组成（aegis-pingora）

在 `pingora_admin.rs` 中，响应体由四个块拼装而成：

```rust
let mut m = self.metrics.render_prometheus();   // RuntimeMetrics
self.append_cache_stats(&mut m);                // aegis_cache_*
self.append_xdp_stats(&mut m);                  // aegis_xdp_*
self.append_cluster_stats(&mut m);              // aegis_cluster_*
```

> **诚实声明。** `SecurityEventEmitter::render_prometheus()`（`aegis_security_decisions_total` / `aegis_security_events_total` 计数器，见 §5.2）在代码中是存在的，但截至撰写本文档时，无论是 pingora 还是 hyper 的处理器都**没有**把它追加进 `/metrics` 的响应体。`/metrics` 的组装只包含 `RuntimeMetrics` + cache + XDP + cluster。这些安全计数器可通过 `snapshot()`/`total()` 供 admin API 的 JSON 端点使用。同样地，在 hyper 的 `/metrics` 分支中只追加了 XDP 块。

### 3.2 基础计数器 `RuntimeMetrics::render_prometheus()`

文件：`src/metrics/mod.rs`。全部为 `counter` 类型，per-process（单个 worker 的值）。

| 指标 | 类型 | 统计什么 |
|---------|-----|-------------|
| `aegis_requests_total` | counter | 所有入站 HTTP 请求 |
| `aegis_requests_denied` | counter | 被 filter 流水线拒绝 |
| `aegis_requests_challenged` | counter | 以挑战应答 |
| `aegis_upstream_2xx` | counter | 上游的 2xx 响应 |
| `aegis_upstream_4xx` | counter | 上游的 4xx 响应 |
| `aegis_upstream_5xx` | counter | 上游的 5xx 响应 |
| `aegis_upstream_errors` | counter | 与上游的连接错误 |
| `aegis_cache_hits` | counter | 来自内存的 threat-aware 缓存命中 |
| `aegis_cache_misses` | counter | 可缓存但被转发到上游的请求 |

带标签的指标（同样是 counter）：

| 指标 | 标签 | 数据源 |
|---------|--------|----------|
| `aegis_domain_total` / `aegis_domain_denied` / `aegis_domain_challenged` | `host="…"` | DashMap `domain`，`observe_domain_outcome()` |
| `aegis_requests_by_protocol` | `protocol="h1\|h2\|h3\|other"` | `ProtocolCounters::record()` |
| `aegis_filter_blocks` / `aegis_filter_challenges` | `filter="…"` | DashMap `by_filter`，`observe_filter_block()`/`observe_filter_challenge()` |

> `host`/`filter` 标签的基数受限于真实域名集合和过滤器名称（而非攻击者输入）。标签中会对 `"` 做转义（host/filter 通过 `.replace('"', "")`）。

### 3.3 延迟直方图

`aegis_request_latency_ms`——类型为 `histogram`。桶（以毫秒计）定义在 `LATENCY_BUCKETS_MS` 中：

```rust
pub const LATENCY_BUCKETS_MS: &[u64] =
    &[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
```

序列：`aegis_request_latency_ms_bucket{le="…"}`（包括 `le="+Inf"`）、`aegis_request_latency_ms_sum`、`aegis_request_latency_ms_count`。

hot-path 优化：`observe(ms)` 恰好执行 **3** 次原子 RMW（count、sum_ms 和**一个**桶——通过 `partition_point` 找到的第一个边界 ≥ ms 的桶），而不是递增所有桶时的约 13 次。Prometheus 要求累积的 `le=` 计数器，因此 `render_prometheus()` 在抓取时用前缀和还原累积序列——输出与"所有桶"方案逐字节一致。`ms` 大于最大边界的观测值只计入 `count`/`sum`（`+Inf` 桶使用 `count`）。

### 3.4 缓存计数器（`append_cache_stats`）

数据源是 `self.cache.stats()`（见 `src/proxy/response_cache.rs`）。全部为 counter：

| 指标 | 统计什么 |
|---------|-------------|
| `aegis_cache_stores` | 插入缓存的条目数 |
| `aegis_cache_evictions` | 被逐出的条目（stale、LRU 压力、broadcast-purge） |
| `aegis_cache_skipped_high_threat` | 因 threat-aware 策略被强制置为 MISS 的查找 |
| `aegis_cache_skipped_uncacheable` | 因响应按 RFC 9111 不可缓存而跳过的写入 |
| `aegis_cache_not_modified` | 由缓存的验证器产生的 304 Not Modified |
| `aegis_cache_served_low` | 提供给 low-threat 客户端的命中（V98 tiered） |
| `aegis_cache_served_medium` | 在 TTL/2 新鲜度窗口内的 medium-threat 命中 |
| `aegis_cache_forced_miss_high` | 因 high-threat 策略被置为 MISS 的查找 |

### 3.5 XDP 计数器（`append_xdp_stats`）

数据源是 `self.xdp.counters().unwrap_or_default()`。当 XDP 关闭时，`NoopXdp.counters()` 返回 `Ok(default)` → 始终渲染全零，因而仪表盘可以无条件抓取，不需要分支逻辑。全部为 counter：

| 指标 | 统计什么 |
|---------|-------------|
| `aegis_xdp_pass` | 被 XDP fast-path 放行到用户态的数据包 |
| `aegis_xdp_drop_deny` | 按 XDP deny-list 丢弃 |
| `aegis_xdp_drop_rate` | 被 XDP 的 per-IP token bucket 丢弃 |
| `aegis_xdp_drop_allowonly` | 在 allow-only（白名单）模式下丢弃 |
| `aegis_xdp_drop_syn` | 被 SYN-flood guard 丢弃的 SYN |
| `aegis_xdp_drop_waf` | 被内联 eBPF-WAF 丢弃（Phase 3X，扫描器路径） |
| `aegis_xdp_fast_pass` | 走 allow-list fast-path 的数据包（绕过 deny/rate/WAF） |

XDP 计数器底层是 per-CPU 的，在 `xdp::counters()` 内部读取时求和。fast-path 的细节见 [13-xdp-ebpf.md](13-xdp-ebpf.md)。

### 3.6 Cluster 计数器（`append_cluster_stats`）

Phase D：通过 shared-mmap 竞技场（arena）对**所有** REUSEPORT worker 求和。与 per-process 的 `aegis_*` 不同——任何一个 worker 都能渲染 cluster 聚合值，仪表盘无需抓取每个 worker 再相加。

如果 arena 未接入（`crate::shared_state::global::enabled()` == false），该块为 no-op：没有 `/dev/shm` 的 Linux、macOS 开发构建、受限容器。缺少 `aegis_cluster_*` 行就是该 worker arena 不可用的标志。

| 指标 | 类型 | Cluster 索引（`cluster_idx`） |
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
| `aegis_cluster_arena_bytes` | **gauge** | arena 大小（`arena_size()`） |
| `aegis_cluster_arena_used_bytes` | **gauge** | arena 已占用（`arena_used()`） |

计数器的序号定义在 `src/shared_state/global.rs` 的 `cluster_idx` 模块中。它们**在各个发行版之间保持稳定**——运维会基于这些索引搭建仪表盘；新计数器只能追加到末尾，绝不重新排序、也绝不复用。完整槽位集合：0–12 已占用（上表加上 `RATE_LIMITED=10`、`TARPIT=11`、`RTBH=12`），`SLOTS=16` 为预留。arena 名称由 `AEGIS_SHARED_STATE_NAME` 指定（默认 `/aegis-state`），大小由 `AEGIS_SHARED_STATE_SIZE_MB` 指定（默认 4 MB）。

> 请注意：`RATE_LIMITED`、`TARPIT`、`RTBH` 作为 cluster 槽位是存在的，并且被时间序列采样器使用（§4），但 `append_cluster_stats` **不会**输出单独的 `aegis_cluster_rate_limited` / `…_tarpit` / `…_rtbh` 行。

### 3.7 PromQL 示例

```promql
# 5 分钟内被拦截的比例（cluster 聚合）
sum(rate(aegis_cluster_requests_denied[5m]))
  / sum(rate(aegis_cluster_requests_total[5m]))

# p99 延迟（基于单个 worker 的直方图）
histogram_quantile(0.99, rate(aegis_request_latency_ms_bucket[5m]))

# 按拦截量排名的 top 过滤器
topk(10, sum by (filter)(rate(aegis_filter_blocks[5m])))

# 按原因统计的 XDP 丢包量
sum by (__name__)({__name__=~"aegis_xdp_drop_.*"})
```

---

## 4. 时间序列环形缓冲

文件：`src/metrics/timeseries.rs`。这是为仪表盘提供的持久化的全集群（fleet-wide）图表，不是 Prometheus。

### 4.1 "单写入者"架构

每个 REUSEPORT worker 中都存在一个 `TimeSeriesStore`。所有 worker 都从 cluster-mmap **读取**（通过 `snapshot_cluster()`），但只有持有 `.sampler.lock` 上 advisory 锁 `flock(LOCK_EX | LOCK_NB)` 的那个 worker 才**写入**。由于所有 worker 的递增在 cluster-mmap 中已经可见，唯一的写入者就覆盖了整个集群——而且不会重复计数。其余 worker 处于只读模式（`state == None`）：`sample_once()` 是 no-op，`query()` 读取写入者写下的文件。

锁的获取发生在 `TimeSeriesStore::new()`（`try_acquire_writer_lock`）：谁先成功执行 `LOCK_EX | LOCK_NB`，谁就是写入者。`is_writer()` 报告该状态。

### 4.2 采样

采样器由后台 tick 调用：`src/proxy/pingora_background.rs`（约在第 463 行），`ts.sample_once()` 每 60 秒触发一次（每隔一个 30 秒 tick，通过 xor 奇偶位 `ts_tick_parity`）。该调用在所有 worker 上都是安全的——在非写入者上是 no-op。

`sample_once()` 执行 `snapshot_cluster()`，计算与上一次快照的差值（`wrapping_sub`），构造 `Point`，然后：
1. 写入 1 分钟环形缓冲 `series_1m.bin`；
2. 累加进当前的 1 小时桶；当 UTC 小时切换时（`current_hour_start`），把累积的 `Point` 刷入 `series_1h.bin` 并清零累加器。

如果 arena 尚未初始化（`snap.len() < cluster_idx::SLOTS`），则跳过该 tick。互斥锁中毒（poisoned）时打印 warning 并跳过，不会 panic。

### 4.3 环形缓冲的二进制格式

目录：`$AEGIS_METRICS_DIR` → `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics`（优先级见 `default_store_dir()`）。

```text
series_1m.bin  — 1 分钟分辨率，2880 条记录（48 小时）
series_1h.bin  — 1 小时分辨率，2160 条记录（90 天）
.sampler.lock  — 写入者的 advisory flock
```

| 常量 | 值 |
|-----------|----------|
| `RING_1M_CAPACITY` | 2880（48 小时） |
| `RING_1H_CAPACITY` | 2160（90 天） |
| `MAX_RESPONSE_POINTS` | 300 |

每个文件由 16 字节的带版本头部 + 固定 96 字节的记录组成，作为环形缓冲区使用。

**头部 `FileHeader`（16 字节）：**

| Offset | Size | 字段 | 值 |
|--------|------|------|----------|
| 0 | 8 | magic | `b"AEGISTS1"` |
| 8 | 4 | version | `1u32` LE |
| 12 | 4 | head | `u32` LE —— 下一个待写入槽位的索引（mod capacity） |

当 magic/version 不匹配或 `head >= capacity` 时，文件会被用全新头部重新初始化（migration-safe tombstone——更改 `FILE_MAGIC` 会强制重建所有文件）。

**记录 `Point`（96 字节 = 12 × u64 LE）：** `t_unix`、`requests`、`denied`、`challenged`、`rate_limited`、`tarpit`、`rtbh`、`cache_hits`、`cache_misses`、`upstream_2xx`、`upstream_4xx`、`upstream_5xx`。

所有计数器字段都是**桶内增量**（该区间内的增长量），而不是累计总数。增量来源于 cluster 索引 `REQUESTS_TOTAL`、`REQUESTS_DENIED`、`REQUESTS_CHALLENGED`、`RATE_LIMITED`、`TARPIT`、`RTBH`、`CACHE_HITS`、`CACHE_MISSES`、`UPSTREAM_2XX/4XX/5XX`。

**派生字段 `allow`** 在读取时计算（不存储）：

```rust
allow = max(0, requests − (denied + challenged + rate_limited + tarpit + rtbh))
```

下限截断到零（`saturating_sub`）可防止计数器出现瞬时偏斜。

### 4.4 降采样与查询

`query(range_secs)`：
- `range_secs <= 172_800`（≤ 48 小时）→ 1 分钟环形缓冲，`resolution = "1m"`；
- `range_secs > 172_800` → 1 小时环形缓冲，`resolution = "1h"`。

读取所需数量的最新记录（`read_recent`，按时间顺序），按 `t_unix >= now − range_secs` 过滤，然后**降采样**到 ≤ `MAX_RESPONSE_POINTS`（300）：记录被分组到 ≤300 个 bin 中，每个 bin 的字段求和（`add_to_accum`），bin 的 `t_unix` 取第一条记录的时间戳。如果记录数 ≤ 300，则原样返回。

### 4.5 `GET /admin/api/metrics/series`

处理器：`src/proxy/pingora_admin.rs` 中的 `api_metrics_series`（约在第 995 行）。需要 `Read` 角色。

`?range=` 参数（不区分大小写，默认 `24h`）：

| Label | 秒数 | 环形缓冲 |
|-------|--------|------|
| `1h` | 3 600 | 1m |
| `6h` | 21 600 | 1m |
| `24h` | 86 400 | 1m |
| `7d` | 604 800 | 1h |
| `30d` | 2 592 000 | 1h |
| `90d` | 7 776 000 | 1h |

未知 label → `400`，返回 `{"error": "unknown range …; use one of: 1h 6h 24h 7d 30d 90d"}`。

响应是 JSON `SeriesResponse`：

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

当 store **未接入**（运维没有调用 `with_timeseries`）时，返回 `200` 和 `{"resolution":"1m","points":[]}`——UI 会绘制"无数据"，而不是崩溃。序列化/查询错误 → `500`，返回 `{"error": …}`。

```bash
curl -s -H "x-admin-token: $TOKEN" \
  "http://127.0.0.1:8080/admin/api/metrics/series?range=24h" | jq .
```

---

## 5. SecurityEvent —— 决策的规范结构（V116）

文件：`src/security_event.rs`。

在 V116 之前，每个过滤器都以自己的临时形式记录决策。`SecurityEvent` 是一个统一的、小巧的、可 JSON 序列化的结构，不含高基数字段（指标标签中没有原始 IP——只在事件体中）。

### 5.1 结构

```rust
pub enum DecisionKind { Allow, Challenge, Deny, Throttle, Observed }

pub struct SecurityEvent {
    pub action: DecisionKind,
    pub reason: &'static str,        // 静态字符串 → 基数受限
    pub request_id: String,
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub risk_score: Option<u8>,      // 0..=255，来自 RiskEngine，未咨询时为 None
    pub extra_reasons: Vec<&'static str>,
    pub waf_rule_id: Option<String>,
    pub ja4_prefix: Option<String>,  // 截断到 12 个字符（JA4_a 族）
}
```

| `DecisionKind` | 语义 |
|----------------|-----------|
| `Allow` | 放行 |
| `Challenge` | 以挑战应答 |
| `Deny` | 已拦截 |
| `Throttle` | 已限速（rate-limit） |
| `Observed` | Match-but-don't-act —— WAF 的 shadow 模式（V109）、Risk Engine 的 observe 模式（V108）："本来会拦截"，但没有拦截 |

Builder 方法：`.with_risk(score, extras)`、`.with_waf_rule(id)`、`.with_ja4(ja4)`（截断到 12 个字符）。各 `reason` 都是 `&'static str`，在整个代码库中复用（V108 RiskEngine + V109 WAF severity + V110 UA/JA4 mismatch），因而基数受限（约 30 个不同取值）。

### 5.2 `SecurityEventEmitter` —— sink

`emit(&ev)` 会做（指标优先——不应因日志序列化问题而失败）：
1. 递增 `total`（AtomicU64）；
2. 递增以 `(action, reason)` 为键的计数器——DashMap，键为 `&'static str` ⇒ 该 map 不可能超出静态集合的规模；
3. 一行结构化日志：`tracing::info!(target: "aegis::security_event", action, reason, request_id, host, client_ip, method, path, risk_score, waf_rule_id, ja4_prefix, "security_decision")`。

运维用自己的日志聚合器采集这个 target。

`render_prometheus()` 产出（见 §3.1 的声明——目前并未插入 `/metrics`）：

| 指标 | 类型 | 标签 |
|---------|-----|--------|
| `aegis_security_decisions_total` | counter | `action="allow\|challenge\|deny\|throttle\|observed"`、`reason="…"` |
| `aegis_security_events_total` | counter | ——（自启动以来的总发出次数） |

为符合 Prometheus 文本格式的严格性，`reason` 会被转义（`\\` 和 `"`）。面向 admin API 的 JSON 端点，提供了 `snapshot()` → `Vec<((DecisionKind, &'static str), u64)>` 和 `total()`。

现成的仪表盘查询（来自模块 docstring）：

```promql
sum(rate(aegis_security_decisions_total{action="deny"}[5m]))
topk(10, sum by (reason)(rate(aegis_security_decisions_total[5m])))
```

---

## 6. EventBridge —— 通过 Unix 套接字给 SIEM 的 NDJSON（V127）

文件：`src/event_bridge.rs`。

运维把 SIEM / 日志聚合器（Wazuh、Elasticsearch、Loki、Splunk、Vector、FluentBit）接到单一端点上，该端点为每个安全决策发出一个 JSON 对象。`SecurityEvent`（V116）是数据；EventBridge（V127）是传输层。

### 6.1 特性

- **Unix 套接字**：默认使用来自 `AEGIS_EVENT_SOCKET` 的路径（代码中没有硬编码的回退值——`new(socket_path)` 接受 `Option<PathBuf>`；docstring 中提到典型路径 `/var/run/aegis-events.sock`）。没有网络暴露，ACL 由文件权限决定。通过 `nc -U` / `socat` / SIEM 的 unix-socket reader 订阅。在 `spawn()` 时套接字以权限 `0600` 创建（由运维 chmod/chown 给自己的 SIEM）。
- **NDJSON 广播**：每个已连接的订阅者都会收到每个事件。新连接从"干净状态"开始（不回放历史）。
- **每订阅者的有损有界队列**：`SUBSCRIBER_CHANNEL_CAP = 1024` 个事件的余量。如果慢速订阅者跟不上——`try_send` 会为它丢弃事件（drop > block），代理绝不会阻塞。AEGIS 是一个会发出事件的代理，而不是 logging 系统。
- **Best-effort**：如果套接字不可用／`socket_path = None`——`emit()` 很廉价且是 no-op（`enabled()` == false）。

hot-path 开销：每个事件一次 mpsc `try_send`，没有订阅者时为亚微秒级。JSON 每次调用只序列化**一次**，并通过 `Arc` 在订阅者之间共享（克隆即一次原子递增）。已死亡的订阅者（`Closed`）会在下一次 `emit` 时被清理。诊断手段是 `subscriber_count()`。

### 6.2 生命周期

- `EventBridge::new(socket_path)`——构造为未连接状态；格式从环境变量 `AEGIS_EVENT_FORMAT` 选取（见 §7）。
- `spawn().await`——绑定 Unix 套接字（先以 best-effort 方式删除上一个进程遗留的陈旧套接字），在后台启动 accept 循环，设置权限 0600。当 `socket_path = None` 时为 no-op。幂等。
- `emit(&ev)`——序列化并分发（见上文）。

### 6.3 Native NDJSON（默认格式）

在 `WireFormat::Native` 下，事件通过 `serde_json` 直接从 `SecurityEvent` 序列化（见 §5.1）——字段原样保留，每个事件一行：

```bash
# 订阅事件流
socat - UNIX-CONNECT:/var/run/aegis-events.sock
# 或者
nc -U /var/run/aegis-events.sock
```

```json
{"action":"deny","reason":"waf_critical","request_id":"…","host":"example.com","client_ip":"1.2.3.4","method":"GET","path":"/admin","risk_score":85,"extra_reasons":["…"],"waf_rule_id":"custom-001","ja4_prefix":"t13d1516h2_8"}
```

---

## 7. Sicherheitstacho / T-Pot 格式（V185）

文件：`src/sicherheitstacho.rs`。

T-Pot（telekom-security/tpotce）把数十个蜜罐归一到 Telekom CERT 的 "Sicherheitstacho" 标准化格式。采用它之后，AEGIS 便获得了与整个 deception 生态消费端的互操作能力（ELK ingest 映射、威胁情报聚合器、公开的 Sicherheitstacho 仪表盘）。

### 7.1 启用

```bash
# 无需改代码即可切换 NDJSON 模式
AEGIS_EVENT_FORMAT=sicherheitstacho   # 同义词：tpot
```

选择在 `EventBridge::new` 中完成：`Some("sicherheitstacho") | Some("tpot")` → `WireFormat::Sicherheitstacho`，否则为 `WireFormat::Native`。以编程方式则用 `.with_format(...)`。

### 7.2 映射与模式

`render_sicherheitstacho(ev)`（位于 `event_bridge.rs`）把 `DecisionKind` 转换为 `Category`：

| `DecisionKind` | `Category` |
|----------------|-----------|
| `Deny` | `Block`（`"block"`） |
| `Challenge` | `Challenge`（`"challenge"`） |
| `Throttle` | `Waf`（`"waf"`） |
| `Allow` / `Observed` | `Waf`（`"waf"`） |

（`Category::Honeypot` / `Tarpit` 在枚举中有定义，但当前从 `SecurityEvent` 出发的映射不会选中它们。）`tags` = `extra_reasons` + `reason`。`transport="TCP"`、`service="aegis-waf"`、`dst_port=443`、`src_port=0`，`country`/`asn`/`user_agent` 为 `None`。

该模块**手工**渲染 JSON（不依赖 serde——保持小巧，以便对 EventBridge 保持 drop-in），带有正确的转义（`"`、`\`、`\n`、`\r`、`\t`，以及 < 0x20 的控制字符 → `\uXXXX`），并自带一个极简的 ISO-8601 UTC 时间戳渲染器（Hinnant 算法，不使用 chrono/jiff）。

```json
{"@timestamp":"2026-05-22T12:34:56.000Z","type":"Aegis","src_ip":"203.0.113.7","src_port":0,"dst_port":443,"transport":"TCP","service":"aegis-waf","category":"block","tags":["sqlmap","waf_critical"],"request":{"method":"POST","host":"evil.test","path":"/phpmyadmin/index.php"}}
```

### 7.3 导出量计数器（arsenal）

在 Sicherheitstacho 格式下，每次 `emit` 都会（如果已绑定）递增 `sicherheitstacho_counter`——一个指向 arsenal 分片 `sicherheitstacho_emits` 的 `Arc<ShardedCounter>`。这样，Defence Arsenal 面板（`/admin/api/arsenal` → `sicherheitstacho.emits`）就能反映 T-Pot 模式下的真实导出量。绑定方式是 `.with_sicherheitstacho_counter(...)`，在同时存在 EventBridge 和 `ArsenalState` 时由二进制文件调用。若为 `None`（没有 arsenal）——计数器不会递增。见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

---

## 8. 仪表盘面板与相关端点

图表由前端（见 [29-admin-panel.md](29-admin-panel.md)）基于以下数据构建：

| 端点 | 数据源 | 用途 |
|----------|-----------------|------------|
| `GET /admin/api/metrics/series?range=` | 时间序列环形缓冲（§4） | 1 小时…90 天的流量/拦截图表 |
| `GET /metrics` | Prometheus（§3） | 外部抓取 |
| `GET /admin/api/geo/top` | `RuntimeMetrics::top_countries(20)` | World map / Top Countries |
| `GET /admin/api/geoip/status` | `geoip::resolve_country_db_path` | GeoIP 数据库状态 |
| （遥测）`api_telemetry_status` | env | EventBridge/格式/ClamAV 的状态 |

### 8.1 Geo 聚合（V239/V242）

`observe_country(cc, denied, challenged)` 在 ingress 处按 ISO 国家代码统计请求——**仅当**配置了 GeoIP 数据库时（在默认的 `NoopGeoIp` 上，查询几乎是免费的 `None`，在没有 GeoIP 的部署中不产生 hot-path 开销）。计数器复用 `DomainCounter`（total/denied/challenged），在 SO_REUSEPORT 下是 per-worker 的。

`GET /admin/api/geo/top` → `api_geo_top` 返回 `[{country, total, denied}]`（最多 20 条）。当没有 GeoIP 数据库时，resolve 返回 `None`，不做任何统计——数组为空，地图会优雅地渲染为空。

`top_countries(n)`（V242）：当启用 geo 持久化时（`with_geo_persistence(dir)`，默认 `/var/lib/aegis/geo`），结果会合并**所有** worker 的分片（自己的取自内存中的实时数据，其他的通过 `merge_all_shards_excluding` 以免重复计数），因此无论由哪个 worker 应答，结果都是稳定的。没有持久化时——就是 per-worker 的内存切片（对 top-N 而言是有代表性的采样，但不是 billing-accurate 的）。分片刷写在每个约 30 秒的 tick 上进行（`flush_geo_shard()`）。分片的实现见 `src/metrics/geo_shard.rs`。更多细节见 [20-geoip.md](20-geoip.md)。

### 8.2 遥测状态

`api_telemetry_status`（`/admin/api/...`）为面板返回 EventBridge 的状态：

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

## 9. 跨 worker 与多进程

在 SO_REUSEPORT 下运行的是 `aegis-pingora@0..N`（见 [06-workers.md](06-workers.md)）。指标行为小结：

| 类别 | 可见范围 |
|-------|-----------|
| `RuntimeMetrics`（不带 `cluster_` 的 `aegis_*`） | per-process —— 单个 worker 的值 |
| `aegis_cluster_*` | 整个集群（cluster-mmap，任何 worker 都能渲染聚合值） |
| 时间序列环形缓冲 | 整个集群（单写入者对 cluster-mmap 采样） |
| `by_country` / geo-top | per-worker，或在 `with_geo_persistence` 下为 merged-all-shards |
| SecurityEvent / EventBridge | per-process（每个 worker 有自己的 sink/套接字——但 `AEGIS_EVENT_SOCKET` 只有一个路径；第一个进程绑定，`spawn` 是幂等的） |

跨 worker 聚合请依赖 `aegis_cluster_*`（Prometheus）和时间序列环形缓冲；如果你分别抓取各个 worker，则需要自己对 per-process 的 `aegis_*` 求和。

---

## 10. 环境变量（汇总）

| Env | 默认值 | 层 | 效果 |
|-----|--------------|------|--------|
| `AEGIS_METRICS_DIR` | `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics` | timeseries | 环形缓冲文件目录 |
| `AEGIS_HOME` | `/var/lib/aegis` | timeseries/geo | 路径基准 |
| `AEGIS_EVENT_SOCKET` | （无） | EventBridge | Unix 套接字路径；未设置 → bridge 为 no-op |
| `AEGIS_EVENT_FORMAT` | `native` | EventBridge | `sicherheitstacho`/`tpot` → T-Pot 模式 |
| `AEGIS_SHARED_STATE_NAME` | `/aegis-state` | cluster | shared-mmap arena 的名称 |
| `AEGIS_SHARED_STATE_SIZE_MB` | `4` | cluster | arena 的大小 |
| `AEGIS_CLAMAV_ADDR` | （无） | 遥测状态 | ClamAV 的 host:port（供面板使用） |

---

## 11. 运维要点

- **`/metrics` 是公开的**——不要把它放到 admin-auth 之后；必要时用网络 ACL/防火墙来限制，而不是用 token。
- **安全计数器不在 `/metrics` 中**——`aegis_security_decisions_total` 由 emitter 收集，但没有接入 `/metrics`；要做决策相关的仪表盘，请使用通过日志聚合器采集的结构化日志 `target=aegis::security_event`、EventBridge 事件流，或 admin API 的 JSON 快照。
- **时间序列数据可跨重启保留**——环形缓冲在磁盘上；头部带版本，格式变更时文件会自动重建。
- **在没有 writer-lock 的情况下**，worker 仍会响应 `/admin/api/metrics/series`（读取写入者的文件）——优雅降级。
- **没有 GeoIP 时 GeoIP 指标是免费的**——在 `NoopGeoIp` 上 `observe_country` 什么都不做。
- **EventBridge 不会拖垮代理**——慢速的 SIEM 订阅者会丢失事件（有损），但不会拖慢流量。
- **在非 Linux／没有 `/dev/shm` 的环境中没有 cluster 计数器**——对开发构建而言，缺少 `aegis_cluster_*` 行是正常的。
