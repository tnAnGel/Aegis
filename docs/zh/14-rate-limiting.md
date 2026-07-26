# 限流（rate limiting）

**语言：** [English](../en/14-rate-limiting.md) · [Русский](../ru/14-rate-limiting.md) · **中文**

AEGIS 在多个层级上限制请求强度：per-IP（IPv6 会折叠到 `/64`）、按 `/24`/`/16`
子网（IPv4）以及 `/48`/`/32`（IPv6）、per-URI；在实战负载下还额外通过 Redis
做分布式限流（用 Lua 实现的原子令牌桶），以及在 HTTP/2 帧层面限流
（Tempesta 风格的预算，用于对抗 Rapid Reset 及同类攻击）。所有本地限流都是
带惰性补充（lazy refill）的令牌桶；L3/L4 上的全局洪泛无法由此覆盖
（见下文的说明以及 BGP RTBH、[XDP/eBPF](./13-xdp-ebpf.md)）。

来源：[`src/filters/rate_limit.rs`](../../src/filters/rate_limit.rs)、
[`src/h2_budget.rs`](../../src/h2_budget.rs)、
[`src/state/reputation.rs`](../../src/state/reputation.rs)、
[`src/config.rs`](../../src/config.rs)、
[`src/domain_policy.rs`](../../src/domain_policy.rs)。

---

## 1. 各层级概览

AEGIS 在代码中的三个相互独立的位置实现了限流 —— 理解这一点很重要，因为它们的
配置方式和工作方式各不相同：

| 层级 | 模块 | 在哪里计数 | 用途 |
|---|---|---|---|
| 本地 per-IP / per-subnet / per-URI | [`src/filters/rate_limit.rs`](../../src/filters/rate_limit.rs) | 在 worker 内存中（`DashMap`） | 过滤器链热路径上的主要 L7 限流 |
| 分布式 per-(host,IP) | [`src/state/reputation.rs`](../../src/state/reputation.rs)（由 [`src/proxy/http.rs`](../../src/proxy/http.rs) 调用） | 在 Redis 中以 Lua `EVAL` 执行 | 多个 worker/实例之间一致的限流 |
| HTTP/2 per-connection 帧预算 | [`src/h2_budget.rs`](../../src/h2_budget.rs) | 在内存中（RwLock + FxHashMap） | 防护 Rapid Reset / Settings / Ping / CONTINUATION flood |

> 🟡 这是**三套不同的**机制，而不是一套机制的三种后端。本地
> `RateLimitFilter`（DashMap）与分布式 Redis 令牌桶是并行存在的。Redis 路径目前
> 主要用于 legacy hyper 处理器（[`src/proxy/http.rs`](../../src/proxy/http.rs)），
> 见 §5。

---

## 2. 本地令牌桶（`RateLimitFilter`）

### 2.1 算法

每个 key 持有一个 `Bucket { tokens: f64, last_refill: Instant }` 结构
（[`rate_limit.rs:93`](../../src/filters/rate_limit.rs#L93)）。补充量在检查时
惰性计算，不使用定时器
（[`rate_limit.rs:432`](../../src/filters/rate_limit.rs#L432)）：

```rust
let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
entry.tokens = (entry.tokens + elapsed * rate).min(burst);
entry.last_refill = now;
if entry.tokens >= 1.0 { entry.tokens -= 1.0; true } else { false }
```

- `rate` —— 每秒令牌数（稳态 RPS）。
- `burst` —— 桶容量（最大瞬时突发）。
- 每个请求恰好扣除 1 个令牌。当令牌数 < 1 时，请求被拒绝。

### 2.2 桶的 key（`RateKey`）

key 是一个固定大小的结构（而不是字符串），以避免每个请求上的 `format!()`
分配（[`rate_limit.rs:19`](../../src/filters/rate_limit.rs#L19)）：

```rust
struct RateKey { scope: u8, ip: IpAddr, host_hash: u64 }
```

- `scope`：`0` = per-IP，`1` = `/24`(`/48`)，`2` = `/16`(`/32`)。
- `host_hash`：Host 头的 64 位哈希（`DefaultHasher`），使限额按域名分别计算。
  host 碰撞概率约为 1/2⁶⁴ —— 视为可忽略不计
  （[`rate_limit.rs:24`](../../src/filters/rate_limit.rs#L24)）。

### 2.3 IPv6：per-IP 折叠到 `/64`

🔴 此前 IPv6 的 per-IP 桶按完整 `/128` 作为 key，攻击者可以在自己的 `/64` 内轮换
地址（SLAAC 会给每台主机分配整个 `/64`），从而完全绕过 per-IP 限流 —— 这就是
SECURITY-AUDIT 中的 **H3** 发现。已修复：IPv6 的 per-IP key 被截断到 `/64`
（[`IPV6_PER_IP_PREFIX = 64`, rate_limit.rs:38](../../src/filters/rate_limit.rs#L38)、
[`RateKey::ip`, rate_limit.rs:41](../../src/filters/rate_limit.rs#L41)）。IPv4
仍按完整 `/32` 作为 key（一台主机 = 一个地址）。

该行为由测试 `ipv6_per_ip_key_collapses_same_64` 和
`ipv6_rotation_within_64_shares_quota` 固定
（[rate_limit.rs:855](../../src/filters/rate_limit.rs#L855)）。

### 2.4 子网桶（Subnet buckets）

可选（`subnet_buckets`，默认**关闭** ⚠️），AEGIS 会额外从子网桶中扣除令牌。逻辑
位于 `check()`（[rate_limit.rs:576](../../src/filters/rate_limit.rs#L576)）：先
per-IP，然后 `/24`，然后 `/16`。任何一个空桶都会导致 `Deny 429`。

| scope | IPv4 前缀 | IPv6 前缀 | rate/burst |
|---|---|---|---|
| per-IP | `/32` | `/64` | `rate`, `burst` |
| `subnet24` | `/24` | `/48` | `rate × subnet_24_multiplier`, `burst × …` |
| `subnet16` | `/16` | `/32` | `rate × subnet_16_multiplier`, `burst × …` |

IPv6 的截断由 `v6_prefix()` 完成
（[rate_limit.rs:486](../../src/filters/rate_limit.rs#L486)）：`subnet24` 用 `/48`，
`subnet16` 用 `/32`（[rate_limit.rs:61](../../src/filters/rate_limit.rs#L61)、
[L75](../../src/filters/rate_limit.rs#L75)）。

乘数（`max(1)`，默认为 `8` 和 `64`）会放大子网预算，使合法的 NAT/ISP 地址池
不会看起来像单个「吵闹」的客户端，但一个由同一 `/24` 内数千个 `/32` 组成的
僵尸网络仍然会撞上子网的共享预算。该行为由测试
`subnet_bucket_blocks_botnet_within_24` 和 `..._16` 固定
（[rate_limit.rs:709](../../src/filters/rate_limit.rs#L709)）。

> 🟠 **Honesty caveat：** `subnet_buckets` 默认为 `false`。若不显式开启，同一
> `/48` 内通过相邻 `/64` 进行的 IPv6 规避不会被子网逻辑覆盖（per-IP 已经折叠
> `/64`，但跨子网预算未启用）。这是 SECURITY-AUDIT 中 **H3** 发现的一部分。
> 审计对 IPv6 环境的建议：`subnet_buckets = true`。

### 2.5 Per-URI 预算（URI budgets）

针对具体路径的一组独立限额（`uri_budgets`）。匹配器
（[`UriMatcher`, rate_limit.rs:177](../../src/filters/rate_limit.rs#L177)）只支持
两类模式：

- **Exact** —— 精确路径，例如 `/login`。
- **Prefix** —— 以 `*` 结尾的模式，例如 `/api/*`。

匹配采用 **first-match-wins**，因此具体路径必须列在 catch-all 之前。比较只针对
路径进行；query string 会被截去
（`ctx.path.split('?')`，[rate_limit.rs:542](../../src/filters/rate_limit.rs#L542)）。

URI 桶**最先**扣除，甚至在 per-IP 桶之前
（[rate_limit.rs:543](../../src/filters/rate_limit.rs#L543)），但 per-IP/子网桶
同样会被扣除 —— 这样客户端就不能在被匹配的 URI 之间「跳跃」并烧光整个连接预算。
URI 桶的 key 是字符串 `uri|{matcher.key}|{host}|{client_ip}`
（[rate_limit.rs:549](../../src/filters/rate_limit.rs#L549)）；这里保留了字符串
（而非 `RateKey`），因为模式的标识本身就是天然的 key，而路径出现频率较低。

超出 URI 预算 → `Deny { status: 429, reason: "uri rate limit exceeded (<pattern>)" }`。

### 2.6 Hot-URI 跟踪

可选的「热点」路径检测器（`hot_uri_rps_threshold`，默认 `0` = 关闭，
[config.rs:735](../../src/config.rs#L735)）。它**只是一个观察者 —— 它自身永远
不会阻断**（[config.rs:717](../../src/config.rs#L717)）。

`HotUriTracker`（[rate_limit.rs:209](../../src/filters/rate_limit.rs#L209)）为每条
路径保存一个 `VecDeque<Instant>`，其中是 `1s` 滑动窗口内的请求时间戳。当每秒命中
数达到阈值时，会写入 `tracing::warn!("hot URI detected")`
（[rate_limit.rs:558](../../src/filters/rate_limit.rs#L558)）。选择 `VecDeque`
是为了让旧时间戳的过期成为 O(1) 的 `pop_front()`，而不是 O(n) 的
`Vec::remove(0)` —— 这是 SECURITY-AUDIT 中 **H2** 发现的一部分。

热点路径的 Top 列表可通过 `hot_uris(limit)` 获取
（[rate_limit.rs:372](../../src/filters/rate_limit.rs#L372)），并提供给管理面板
（`/admin/hot_uris`，见 Admin API）。

### 2.7 动态信任 —— 绕过限流

在 `check()` 的最开始，受信任的客户端会跳过限流
（[rate_limit.rs:514](../../src/filters/rate_limit.rs#L514)）：

```rust
if ctx.is_trusted { return FilterAction::Allow; }
```

信任通过干净的流量赢得（见
[`src/filters/dynamic_trust.rs`](../../src/filters/dynamic_trust.rs) 和
Arsenal/场景）。限流的存在是为了防护来自未知客户端的突发；受信任的客户端已经
「付过」审计的代价了。

### 2.8 内存限制与清理

状态映射受到硬性上限约束，否则地址/URI 的轮换就会把限流变成内存耗尽向量
（**H2** 发现，SECURITY-AUDIT）：

| 映射 | 上限 | 常量 |
|---|---|---|
| per-IP/subnet `state` | `1 048 576` | [`MAX_STATE_ENTRIES`, rate_limit.rs:132](../../src/filters/rate_limit.rs#L132) |
| URI `uri_state` | `262 144` | [`MAX_URI_STATE_ENTRIES`, rate_limit.rs:135](../../src/filters/rate_limit.rs#L135) |

达到上限时，插入新 key 会先**淘汰最旧的条目**（按 `last_refill` 的类 LRU 策略，
[`evict_oldest_state`, rate_limit.rs:405](../../src/filters/rate_limit.rs#L405)），
镜像了 `dynamic_trust.rs` 中的 `evict_lru` 模式。两个 `DashMap` 都被分为 128 个
分片以提升并行度（V230，
[rate_limit.rs:335](../../src/filters/rate_limit.rs#L335)）。

此外还有 `cleanup_stale(now)`
（[rate_limit.rs:474](../../src/filters/rate_limit.rs#L474)），它会删除早于
`stale_after`（固定为 `300s`，
[rate_limit.rs:338](../../src/filters/rate_limit.rs#L338)）的条目，并清理
hot-URI 映射。

> 🟠 **Honesty caveat（H2）：** 代码中的注释明确指出
> “deployed pingora path **never wires `cleanup_stale` into a background loop**”
> （[rate_limit.rs:124](../../src/filters/rate_limit.rs#L124)）。因此在 Pingora
> 路径中，对映射膨胀的防护依赖硬性 cap + 淘汰，而不是周期性清理。在
> SECURITY-AUDIT 中，H2 被标记为「修复中（+ 集成）」—— 修复状态请查阅审计本身。

---

## 3. 本地限流的配置

结构体 `RateLimitConfig`（[config.rs:692](../../src/config.rs#L692)）。在 DSL/TOML
中这是 `[filters.rate_limit]` 段（准确语法见[配置](./04-configuration.md)）。

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `enabled` | bool | — | config-time 标志。⚠️ `check()` 本身**不**依赖它（见 §6） |
| `requests_per_second` | u64 | — | 全局 per-IP rate |
| `burst` | u64 | — | 全局 per-IP burst |
| `subnet_buckets` | bool | `false` | 启用 `/24`(`/48`) 和 `/16`(`/32`) 限额 |
| `subnet_24_multiplier` | u64 | `8`（[config.rs:739](../../src/config.rs#L739)） | `/24`(`/48`) 预算的乘数 |
| `subnet_16_multiplier` | u64 | `64`（[config.rs:742](../../src/config.rs#L742)） | `/16`(`/32`) 预算的乘数 |
| `uri_budgets` | `Vec<UriBudget>` | `[]` | Per-URI 限额（first-match-wins） |
| `hot_uri_rps_threshold` | u64 | `0`（关闭） | 「hot URI」日志的 hits/sec 阈值 |

`UriBudget`（[config.rs:726](../../src/config.rs#L726)）：

| 字段 | 说明 |
|---|---|
| `pattern` | Exact（`/login`）或 prefix-glob（`/api/*`）。只按路径匹配，忽略 query |
| `requests_per_second` | 该桶的 rate |
| `burst` | 该桶的 burst |

### 示例（概念性）

```toml
[filters.rate_limit]
enabled = true
requests_per_second = 20
burst = 40
subnet_buckets = true        # 推荐开启，尤其是 IPv6 环境
subnet_24_multiplier = 8
subnet_16_multiplier = 64
hot_uri_rps_threshold = 200  # 仅记录日志，不阻断

[[filters.rate_limit.uri_budgets]]
pattern = "/login"           # exact：昂贵的 auth 端点
requests_per_second = 1
burst = 5

[[filters.rate_limit.uri_budgets]]
pattern = "/api/*"           # prefix-glob
requests_per_second = 10
burst = 20
```

> 各段的准确语法请参见[配置（DSL 与 TOML）](./04-configuration.md)；构建与环境
> 变量见 [`install.sh`](../../install.sh)（参见[安装与运维](./03-installation.md)）。

---

## 4. Per-domain 覆盖

限额按 host 以如下优先级顺序选取（`check()`，
[rate_limit.rs:529](../../src/filters/rate_limit.rs#L529)）：

1. **运行时 per-host overlay（V234）** —— `domain_policy.rate_limit_for(host)`。
   这是通过管理 API 设置的 override
   （`PUT /admin/api/sites/<host>/policy`，见 Admin API），落盘且跨 worker 生效。
   即使对于 `.conf` 为只读的 ops-managed 站点也同样有效
   （[domain_policy.rs:117](../../src/domain_policy.rs#L117)、
   [domain_policy.rs:550](../../src/domain_policy.rs#L550)）。当不存在任何 override
   时，这只是一次 relaxed 原子加载（empty-gate 快速路径）。
2. **静态 `domain_limits`** —— `limits_for_host(host)`
   （[rate_limit.rs:379](../../src/filters/rate_limit.rs#L379)）：
   - host 的精确匹配优先；
   - key 中的前导点（`.example.com`）作为 suffix-glob 工作，可匹配
     `api.example.com`、`www.example.com` —— 从而为 apex + 子域名提供一个共享桶。
3. **全局** `requests_per_second` / `burst`。

`RateLimitOverride`（[domain_policy.rs:86](../../src/domain_policy.rs#L86)）保存
`rps` 和 `burst`（均为 `u64`，语义为 per-IP，与全局过滤器一致）。overlay 的行为
由测试 `domain_policy_overlay_overrides_global_per_host` 固定
（[rate_limit.rs:663](../../src/filters/rate_limit.rs#L663)）。更多内容 ——
制图与 per-domain 策略。

---

## 5. 通过 Redis 的分布式限流

这是与 §2 **相互独立**的机制：一个完全在 Redis 内部作为 Lua 脚本以 `EVAL` 执行的
原子令牌桶
（[`TOKEN_BUCKET_LUA`, reputation.rs:11](../../src/state/reputation.rs#L11)）。
全部 refill/decrement 运算都是原子的，因此来自多个 worker/实例的并发调用不会
「超支」预算（[reputation.rs:83](../../src/state/reputation.rs#L83)）。

- key：`aegis:tb:{key}`，其中 `key = redis_tb_key(host, ip)` —— host+IP 的定长
  哈希摘要。🔴 此前 key 是 `{host}|{ip}`；由于 Host 完全由攻击者控制且可能包含
  `|`，每个请求替换 Host 就会铸出一个新桶从而绕过限流器。已在 **V233** 中通过
  对两个组成部分做哈希修复（[http.rs:932](../../src/proxy/http.rs#L932)、
  [http.rs:2159](../../src/proxy/http.rs#L2159)）。
- 脚本的返回：`(allowed, value)`。当 `allowed=1` 时 value 是剩余令牌数
  （`BucketOutcome::Allowed { tokens_left }`）；当 `allowed=0` 时 value 是距下次
  尝试的毫秒数（`Throttled { retry_after_ms }`），用于 `Retry-After` 头
  （[reputation.rs:48](../../src/state/reputation.rs#L48)）。
- key 的 TTL 自动设置为：
  `max(1000, ceil(burst / max(rate,1) * 2000))` 毫秒
  （[reputation.rs:26](../../src/state/reputation.rs#L26)）。

### Fail-open

如果 Redis 不可用或 EVAL 失败，该路径会**放行（fail-open）** —— 后端不应因存储
故障而挂掉（[http.rs:950](../../src/proxy/http.rs#L950)、
[`distributed_rate_exceeded`, http.rs:927](../../src/proxy/http.rs#L927)）。当未
配置存储时，该桶完全不会被使用
（`storage.redis_url`，[config.rs:350](../../src/config.rs#L350)；按
`redis://…` 校验，[config.rs:1090](../../src/config.rs#L1090)）。

> 🟠 **Honesty caveat：** 在当前代码中，分布式 Redis 令牌桶是从 **legacy hyper
> 处理器**（[`src/proxy/http.rs`](../../src/proxy/http.rs)）调用的。基于 Pingora
> 的生产 data plane 使用的是本地 `RateLimitFilter`（§2）；在 Pingora 路径中，429
> 的 reason 被称为 `distributed_rate` 只是给访问者的消息标签
> （[pingora_http.rs:3141](../../src/proxy/pingora_http.rs#L3141)），并不表示访问
> 了 Redis。在没有显式核对自己的构建/配置之前，不要认为 Redis 令牌桶在 Pingora
> 路径上是启用的。

---

## 6. 与 FilterEngine 的交互以及 `enabled` 标志

⚠️ **一个重要的细节（V231）：** `RateLimitFilter::check()` **不**对
`self.enabled` 做自我 gating
（[rate_limit.rs:505](../../src/filters/rate_limit.rs#L505)）。「是否运行该过滤器」
的决定由 `FilterEngine` 通过 `RuntimeToggles` 和 per-domain `domain_policy` 做出
—— 这是唯一的事实来源，否则 per-domain 覆盖会被双重 gating 而失效
（[rate_limit.rs:358](../../src/filters/rate_limit.rs#L358)）。

- `config_enabled()`（[rate_limit.rs:363](../../src/filters/rate_limit.rs#L363)）
  —— 在注册 `RuntimeToggle` 时由引擎读取。
- 按 host 的 per-filter 开关通过
  `DomainPolicy.filter_enabled["rate_limit"]` 设置
  （[domain_policy.rs:106](../../src/domain_policy.rs#L106)）。

请求生命周期以及限流在过滤器链中的位置见[架构](./02-architecture.md)。相邻的
自适应升级机制（RPS penalty、exempt-paths）是 `AdaptiveConfig`
（[config.rs:746](../../src/config.rs#L746)），参见 ML 与风险引擎以及
Arsenal/场景。

---

## 7. HTTP/2 帧预算（`h2_budget`）

V182，[`src/h2_budget.rs`](../../src/h2_budget.rs)。针对 HTTP/2 控制帧的
Tempesta 风格预算，面向 CVE-2023-44487（Rapid Reset）、CVE-2024-27316
（CONTINUATION flood）以及「Made You Reset」/ Settings / Ping flood 家族。所有
这些攻击都利用了某类控制帧在服务端一侧的低成本；修复办法是 per-connection 预算，
并在帧到达 HTTP/2 状态机**之前**进行检查。

这是一个**独立的**令牌桶（`tokens: f32`，
[h2_budget.rs:92](../../src/h2_budget.rs#L92)），带惰性补充，key 为
`(conn_id, FrameKind)` 二元组（[h2_budget.rs:118](../../src/h2_budget.rs#L118)）。
桶为空时返回 `Verdict::Reject`，调用方必须关闭 stream/连接
（[h2_budget.rs:143](../../src/h2_budget.rs#L143)）。

### 默认预算

`Budget::default_for(kind)`（[h2_budget.rs:73](../../src/h2_budget.rs#L73)）：

| 帧（`FrameKind`） | Burst | Refill/s | 针对什么 |
|---|---:|---:|---|
| `RstStream` | 50 | 20 | Rapid Reset |
| `Settings` | 10 | 2 | Settings flood |
| `Ping` | 30 | 10 | Ping flood |
| `Priority` | 100 | 50 | Priority churn |
| `Goaway` | 3 | 1 | 本应很少出现 |
| `Continuation` | 50 | 20 | CONTINUATION flood |

覆盖值以编程方式设置：`with_override(kind, Budget { burst, refill_per_s })`
（[h2_budget.rs:131](../../src/h2_budget.rs#L131)）。简报中提到它们可由运维通过
DSL 调整；而模块本身的 API 只有 `with_override`。

### 状态管理

- `consume(conn_id, kind)` —— 主要热路径
  （[h2_budget.rs:143](../../src/h2_budget.rs#L143)）。
- `drop_conn(conn_id)` —— 清除已关闭连接的全部状态
  （[h2_budget.rs:151](../../src/h2_budget.rs#L151)）。
- `gc(idle)` —— 对空闲桶的后台清理
  （[h2_budget.rs:157](../../src/h2_budget.rs#L157)）。
- 使用 `FxHashMap` 而非 SipHash，因为 key（连接内的顺序 ID + 一个小 enum）不受
  攻击者控制（[h2_budget.rs:36](../../src/h2_budget.rs#L36)）。

per-connection 预算由测试确认
（`rapid_reset_burst_blocked_after_budget`、`budgets_are_per_connection`，
[h2_budget.rs:185](../../src/h2_budget.rs#L185)）。该模块通过 `H2Guard`
（[`src/proxy/h2_guard.rs`](../../src/proxy/h2_guard.rs)）和 Arsenal
（[`src/arsenal.rs`](../../src/arsenal.rs)）集成；模块中的注释说明同一套预算逻辑
设计上可镜像到 XDP fast-path 以实现内核侧的强制执行
（[h2_budget.rs:10](../../src/h2_budget.rs#L10)，见 [XDP/eBPF](./13-xdp-ebpf.md)）。

> 🟠 **Honesty caveat（C3）：** SECURITY-AUDIT 中相关的 **C3** 发现指出，部分
> 硬性 HTTP/2 限制（`max_header_list_size`、concurrent-streams）**在不升级框架的
> 情况下无法在 Pingora 0.8.0 上设置** —— 状态为「已推迟（需要升级 pingora）」。
> `h2_budget` 覆盖了帧洪泛预算，但并不能完全替代框架中缺失的这些设置。

---

## 8. 响应码

| 情况 | 动作 | Status | Reason / 消息 |
|---|---|---|---|
| 超出 per-IP 限额 | `FilterAction::Deny` | `429` | `"rate limit exceeded"`（[rate_limit.rs:566](../../src/filters/rate_limit.rs#L566)） |
| 超出 `/24`(`/48`) | `FilterAction::Deny` | `429` | `"subnet /24 rate limit exceeded"`（[rate_limit.rs:584](../../src/filters/rate_limit.rs#L584)） |
| 超出 `/16`(`/32`) | `FilterAction::Deny` | `429` | `"subnet /16 rate limit exceeded"`（[rate_limit.rs:596](../../src/filters/rate_limit.rs#L596)） |
| 超出 URI 预算 | `FilterAction::Deny` | `429` | `"uri rate limit exceeded (<pattern>)"`（[rate_limit.rs:551](../../src/filters/rate_limit.rs#L551)） |
| 超出 Redis 令牌桶 | 返回 `Some(retry_after_ms)` | `429` + `Retry-After` | legacy hyper（[http.rs:949](../../src/proxy/http.rs#L949)） |
| H2 帧预算耗尽 | `Verdict::Reject` | ——（关闭 stream/conn） | 调用方（[h2_budget.rs:143](../../src/h2_budget.rs#L143)） |

在 Pingora 路径中，deny 通过 `respond_visitor_error()` 渲染，标签为
`distributed_rate` →「Too many requests. Please wait before retrying.」
（[pingora_http.rs:3141](../../src/proxy/pingora_http.rs#L3141)）。

所有这些响应都会进入请求日志以及指标/遥测。

---

## 9. 限流**不能**覆盖什么（honesty caveats）

1. **L3/L4 容量型洪泛。** 令牌桶工作在 L7 —— 作用于已经建立的连接上。容量型洪泛
   需要上游防护：见 BGP RTBH 和 [XDP/eBPF](./13-xdp-ebpf.md)。即使是已缓存的响应
   也需要一条入站连接，因此没有上游丢包，后端仍可能被压垮（见性能一文中的缓存
   说明）。
2. **IPv6 规避。** per-IP 会折叠 `/64`，但跨子网防护（`/48`/`/32`）依赖
   `subnet_buckets`，而它**默认是关闭的**（**H3** 发现，SECURITY-AUDIT）。
3. **框架层面的 HTTP/2 Rapid Reset。** `h2_budget` 提供了预算，但一系列硬性 H2
   限制在 Pingora 0.8.0 上不可用（**C3** 发现，「已推迟」）。
4. **映射的内存耗尽。** 防护依赖硬性 cap + LRU 淘汰；Pingora 路径中的后台
   `cleanup_stale` 未接入循环（**H2** 发现）—— 请在 SECURITY-AUDIT 中查看当前
   状态。
5. **限流基准测试是 in-process 的。** [`src/bin/aegis-distbench.rs`](../../src/bin/aegis-distbench.rs)
   与 `bench/` 中的令牌桶测试测量的是**没有网络 I/O** 的过滤器引擎
   （token-bucket simulation）。完整的 `aegis-pingora` 在实战负载下相比合成数据
   会下降 15–30%（Pingora 的 I/O、系统调用、TCP/TLS）。绝不要在不标注
   「in-process filter relay，非真实部署」的情况下引用基准中的绝对 RPS。更多内容
   —— 基准测试。

关于已发现问题及修复状态的权威来源是
SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md；安全模型的概览见安全模型。

---

## 另见

- [架构与请求生命周期](./02-architecture.md)
- [配置（DSL 与 TOML）](./04-configuration.md)
- [XDP/eBPF 内核 fast-path](./13-xdp-ebpf.md)
- [Challenge ladder、PoW 与 captcha](./15-challenge-ladder.md)
- BGP RTBH
- Defence Arsenal、场景与执行器
- 制图与 per-domain 策略
- Admin API —— 参考手册
- 安全模型与加固
- 基准测试与代理对比
