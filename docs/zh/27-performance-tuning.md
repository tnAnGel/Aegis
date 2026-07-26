# 性能与调优

**语言：** [English](../en/27-performance-tuning.md) · [Русский](../ru/27-performance-tuning.md) · **中文**

AEGIS 如何针对具体硬件构建、在负载下如何铺开，以及运维与开发者手上有哪些调节杆。这里的每条论断都绑定到真实代码 —— `Cargo.toml`（`[profile.release]`）、`install.sh`（`aegis_rustflags`/`build_and_install`）、`src/h2_budget.rs`、`src/proxy/response_cache.rs`、`src/bin/aegis-pingora.rs` —— 而方法论与实测数据的报告则位于 [`PERFORMANCE.md`](../en/reference/performance.md)。

> 诚实的框定（见 [`PERFORMANCE.md`](../en/reference/performance.md) 与 [`28-benchmarking.md`](./28-benchmarking.md)）：在纯转发场景下 AEGIS **并不**比裸 nginx 更快 —— 差距约 10–13%（CPU 隔离，8 核），这一点已被证明。AEGIS 的真正价值在于缓存（HIT 约为 nginx 转发的 1.7×）以及 L7 防护，后者比 nginx+ModSecurity 便宜一个数量级（VM 内约 18×）。本文档讲的是如何把已声明的能力榨出来，而不是如何在裸速度上跑赢代理。

---

## 1. 构建：在哪里编译，以及为什么这很重要

`install.sh` 在**部署服务器本机**上编译 AEGIS，每次 `--update` 都会重编。这是一个关乎性能的关键架构决策：既然二进制在同一台机器上构建并运行，就可以安全地针对实际 CPU 做特化，而不必担心在别人的硬件上出现 `SIGILL`。

由此引出两个默认值：

1. **`target-cpu=native`** —— 针对这颗 CPU 的全部特性进行编译。
2. **快速并行构建剖面**（thin LTO + 16 个 codegen unit + incremental）—— 这样例行的 `--update` 就不会让单个 rustc 在单核上烤上好几分钟。

以及一个用于切release 的可选模式：**`AEGIS_BUILD_OPT=max`** —— 最大限度优化（但构建缓慢、几乎单线程）的二进制。

---

## 2. 构建剖面 `[profile.release]`

默认的 release 剖面在 `Cargo.toml` 的 `[profile.release]` 中定义：

```toml
[profile.release]
lto = "thin"
codegen-units = 16
incremental = true
panic = "abort"
strip = "symbols"
opt-level = 3
debug = false
```

| 字段 | 取值 | 为什么（依据 `Cargo.toml` 中的注释块） |
|---|---|---|
| `lto` | `"thin"` | 并行的跨 crate 优化。Thin LTO 可以并行化（相比之下 `fat` = 对整个程序做一次串行处理）。热路径跨越 5–7 个 crate 边界（pingora、hyper、http、tokio + 我们的 80 多个模块）—— LTO 带来吞吐收益。 |
| `codegen-units` | `16` | 让 LLVM codegen 跑满服务器的所有核心。这就是所谓的「并行构建」。 |
| `incremental` | `true` | 小改动的 `--update` 只重编 crate 的一部分，而不是全部。大幅削减例行更新耗时。 |
| `panic` | `"abort"` | 从每个函数的序言中去掉 unwind 表（在热的 Allow 路径上节省 icache），并缩小二进制。这是安全的：代理本就把任何 panic 当作工作进程崩溃处理 —— pingora 会重启工作进程，SO_REUSEPORT 让监听器保持存活。 |
| `strip` | `"symbols"` | 削减约 30% 的二进制体积。需要时可从 split-debug 的 `.dwp` 中取回符号。 |
| `opt-level` | `3` | 完全优化。 |
| `debug` | `false` | 生产环境不带调试信息。 |

> **历史说明（诚实地）。** 在 V246 之前，默认值是 `lto="fat"` + `codegen-units=1` —— 最快的*二进制*，但**完全单线程的构建**：每次 `install.sh --update` 都有一个 rustc 占住一个核心好几分钟，其余核心闲置。由于 install.sh 在每次更新时都直接在服务器上重编，默认值被切换成了快速并行剖面。相对 `fat`+`cgu=1` 的运行时代价是几个百分点（实测：在受保护的负载下 AEGIS+WAF 依然领先裸 nginx）。

### 配套剖面

```toml
[profile.profiling]   # 供 perf/flamegraph 使用 —— release + 符号
inherits = "release"
lto = "thin"
strip = false
debug = 1

[profile.bench]       # 以生产设置运行的微基准
lto = "fat"
codegen-units = 1
panic = "abort"
opt-level = 3
debug = true
```

- `[profile.profiling]` 镜像 release，但保留符号表与行号，好让 `perf`/flamegraph 能解析函数名。永不发布 —— 仅用于性能研究。
- `[profile.bench]` 使用 `fat` LTO + `cgu=1`，好让微基准反映真实的生产性能，而不是未优化调试构建的噪声。

---

## 3. `AEGIS_BUILD_OPT=max` —— 最大限度优化的二进制

`install.sh` 中的 `build_and_install()`（约 497–509 行）实现了一个 opt-in 开关。默认使用 `Cargo.toml` 中的快速并行剖面；当 `AEGIS_BUILD_OPT=max` 时，会导出覆盖该剖面的环境变量：

```bash
if [ "${AEGIS_BUILD_OPT:-}" = "max" ]; then
    export CARGO_PROFILE_RELEASE_LTO=fat
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    export CARGO_PROFILE_RELEASE_INCREMENTAL=false
    log "AEGIS_BUILD_OPT=max → fat LTO + codegen-units=1 (slow build, max-perf binary)"
else
    log "build profile: fast parallel (thin LTO, codegen-units=16, incremental) — set AEGIS_BUILD_OPT=max for max-perf"
fi
```

| 模式 | LTO | codegen-units | incremental | 何时使用 |
|---|---|---|---|---|
| 默认 | `thin` | `16` | `true` | 服务器上例行的 `install.sh --update`。构建吃满所有核心，只重编改动过的部分。 |
| `AEGIS_BUILD_OPT=max` | `fat` | `1` | `false` | 切正式发版。构建缓慢、几乎单线程，但能得到绝对最快的二进制。**不适用于例行的 `--update`。** |

```bash
# 最大限度优化的二进制：
sudo AEGIS_BUILD_OPT=max bash install.sh --update
```

其机制是 Cargo 标准的 `CARGO_PROFILE_RELEASE_*` 环境变量覆盖，因此可以叠加在 `[profile.release]` 之上，无需修改 `Cargo.toml`。

---

## 4. `target-cpu=native` 与 `aegis_rustflags`

codegen 目标由变量 `AEGIS_TARGET_CPU`（默认 `native`）设定，并由函数 `aegis_rustflags()` 组装进 RUSTFLAGS（`install.sh`，约 419–435 行）：

```bash
: "${AEGIS_TARGET_CPU:=native}"
aegis_rustflags() {
    local flags=""
    if [ "$AEGIS_TARGET_CPU" != "generic" ] && [ -n "$AEGIS_TARGET_CPU" ]; then
        flags="-C target-cpu=$AEGIS_TARGET_CPU"
    fi
    if command -v mold >/dev/null 2>&1; then
        flags="${flags:+$flags }-C link-arg=-fuse-ld=mold"
    fi
    if [ -n "${RUSTFLAGS:-}" ]; then
        flags="${flags:+$flags }$RUSTFLAGS"
    fi
    printf '%s' "$flags"
}
```

| `AEGIS_TARGET_CPU` | 行为 |
|---|---|
| `native`（默认） | 对**这台**机器最优。启用所有 CPU 特性。 |
| `generic` | 可移植；适用于 build-once-deploy-many。完全不添加 `-C target-cpu`。 |
| `neoverse-n1` / `x86-64-v3` / … | 固定到某个具体微架构。 |

**为什么 `native` 是安全的。** 二进制直接在部署主机上构建、也只在这里运行，因此针对构建 CPU 做特化既安全又最优。在现代 ARM 上（Graviton2+、Ampere、Apple、Neoverse），`native` 会启用 **ARMv8.1 的 LSE 原子指令**：单指令的 `ldadd`/`swpal` 取代 LL/SC 循环（`__aarch64_ldadd8`）。这会加速热路径上的**所有**原子操作 —— Arc、DashMap、tokio、mimalloc。在现代 x86 上则是 AVX2/BMI。对 V237 二进制的 objdump：5775 条 `ldadd` / 414 条 `ldaddal`，对比 10 条 `ldaxr`（见 [`PERFORMANCE.md`](../en/reference/performance.md)，V237）。

> **重要 —— 特性并未硬编码。** 已提交的 `.cargo/config.toml` 刻意不硬编码任何东西；来自 `aegis_rustflags()` 的 RUSTFLAGS 会覆盖它。环境中任何预先设置的 `RUSTFLAGS` 都会**被保留，并追加在我们的**标志之后。这带来了对老旧 ARM/x86 的可移植性，且没有 `SIGILL` 风险（你是针对自己的硬件构建的）。

在两个构建函数中都会应用（`build_aegis_hyper`、`build_aegis_pingora`）：

```bash
RUSTFLAGS="$(aegis_rustflags)" "$cargo" build --release --bin aegis-pingora --features "$features"
```

手工复现（与 [`PERFORMANCE.md`](../en/reference/performance.md) 中一致）：

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --features pingora
```

> **PGO（profile-guided optimization）—— opt-in，未集成进 install.sh。** 实测 PGO 在转发上带来 +10%、在 TLS-steady 上带来 +3–5%，但对带宽受限的路径（大响应体）**没有帮助**。它作为独立的 RUSTFLAGS 流水线提供（`perf-tier1`），集成到 `install.sh` 属于后续事项（PGO 会给构建增加约 10 分钟）。所声称的 +10% 是在单进程拓扑下剖析出来的，**并未**迁移验证到生产的 REUSEPORT 铺开方式 —— 见 [`PERFORMANCE.md`](../en/reference/performance.md) 中的说明。

---

## 5. mold 链接器

`mold` 是多线程链接器；否则大型二进制 `aegis-pingora` 的最终链接是单线程的（GNU ld），并占用每次构建中相当可观的一部分时间。它以 **best-effort** 方式使用：如果没有 mold，就静默回退到默认链接器，构建不会失败。

mold 的安装出现在 `install.sh` 的两处（全新安装时，以及 `--update` 走的 `build_and_install` 中）：

```bash
case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mold ... ;;
    dnf) dnf install -y -q mold ... ;;
    apk) apk add --no-cache mold ... ;;
esac
```

如果 `command -v mold` 找到了该二进制，`aegis_rustflags()` 就会加上 `-C link-arg=-fuse-ld=mold`（见 §4）。否则不添加该标志。Mold **只影响构建速度**，不影响运行时性能。

---

## 6. SO_REUSEPORT 与工作进程数量

AEGIS 的生产铺开方式是 **N 个独立的 SO_REUSEPORT 进程** `aegis-pingora@0..N-1`，采用 **thread-per-core** 方案：N 个工作进程 × 1 个线程，每个通过 systemd 的 `CPUAffinity` 1:1 绑核。跨工作进程状态的细节见 [`06-workers.md`](./06-workers.md)。

### 工作进程数量的选择 —— `resolve_workers()`

`install.sh`（约 156–191 行）：

```bash
: "${AEGIS_WORKERS:=auto}"   # auto = nproc | explicit N
```

解析顺序：

1. 若命令行显式给出 `--workers N` —— 它**总是**获胜。
2. 否则，若 `AEGIS_WORKERS=auto` 且存在 `/var/lib/aegis/topology.json` —— 取由管理面板 Workers 页面（经 `PUT /admin/api/topology`）写入的 `{"workers":...}` 值。
3. 否则 `auto` → `nproc` 个工作进程，`AEGIS_THREADS_PER_WORKER=1`。

任何情况下都有 `AEGIS_THREADS_PER_WORKER=1`（thread-per-core）。

```bash
sudo bash install.sh --workers 8     # 覆盖 REUSEPORT 实例数量
```

| 来源 | 优先级 |
|---|---|
| `--workers N`（CLI） | 最高 |
| `topology.json`（面板，`PUT /admin/api/topology`） | 中（仅在 `auto` 时） |
| `nproc` | 默认 |

### 为什么是 thread-per-core，而不是 work-stealing

`resolve_workers()` 固定 N×1 的铺开方式，是因为 pingora 运行时是 NoSteal 的：N 个工作进程 × 1 个线程、1:1 绑核。此前的 4×4 方案让内核调度器把线程在所有 CPU 之间漂移，破坏了 L1/L2 局部性。这与 nginx/envoy/HAProxy 的模式一致。实测已经确认：**work-stealing 没有帮助** —— A/B 测试显示 NoSteal 稳定胜出；当前默认值是正确的（[`PERFORMANCE.md`](../en/reference/performance.md)，第 3/4 条）。

### REUSEPORT 运行时标志

通过 `AEGIS_PINGORA_REUSEPORT=1` 启动（systemd 模板 `aegis-pingora@.service`）。在 `src/bin/aegis-pingora.rs` 中：

- SO_REUSEPORT 通过 `AEGIS_PINGORA_REUSEPORT=1` opt-in（注释，约第 38 行）。
- 当 reuseport 启用时，`build_downstream_sock_opt(reuseport)` 设置 `sock_opt.so_reuseport = Some(true)`（约第 583 行）。
- 每个实例绑定**相同的**端口；内核把进入的连接哈希分配到各工作进程。

> **LEVER 3 —— 共享的 REUSEPORT ticket 密钥。** 生产铺开方式是 N 个独立进程，如果没有共享的 TLS session-ticket 密钥，每个工作进程都会签发自己的 ticket → 跨工作进程的 resumption 就会失效（落到另一个工作进程上的连接会做完整握手）。修复方式：所有 REUSEPORT 工作进程**共用一个 ticket 密钥**（`src/bin/aegis-pingora.rs`，约第 611 行起）。在正确的铺开方式下，这才是 TLS 路径上的主要调节杆，而不是密码学本身（见 [`08-tls-certificates.md`](./08-tls-certificates.md) 与 [`PERFORMANCE.md`](../en/reference/performance.md)，第 4 条）。

---

## 7. 响应缓存（threat-aware response cache）

`src/proxy/response_cache.rs` 是给 AEGIS 带来真正领先幅度的响应缓存（HIT 约为 nginx 转发的 1.7×，相比开启 `proxy_cache` 的 nginx 高 20–47%；[`PERFORMANCE.md`](../en/reference/performance.md)，TL;DR）。完整的行为描述不在 [`14-rate-limiting.md`](./14-rate-limiting.md) 中；缓存在此处以及 [`04-configuration.md`](./04-configuration.md) 中描述。

### Threat-aware：不是普通的 proxy_cache

- **低威胁/可信客户端**（`ctx.is_trusted` 为真者，或在没有威胁信号时的所有客户端）会得到 cache HIT。
- **高威胁客户端**（近期被 denied/challenged 的 IP）被强制 cache MISS —— 响应会被重新拉取，并走完整条过滤器流水线。这阻断了通过 header/query 走私实现的缓存投毒。

防护属性（出自模块的文档注释）：
- 对高威胁 IP，WAF 在每个请求上仍然会运行 —— 缓存是性能捷径，**不是**防护的旁路。
- 条目只保存上游响应；可缓存的响应按定义对给定缓存键是确定性的。
- 带 `Set-Cookie` 的响应永不缓存（否则会造成会话交叉污染）。
- 尊重 `Cache-Control: private | no-store`。

### 存储 —— 热路径无分配

- 单进程 LRU，键为 `(Method, Host, Path)`。进程之间**没有**共享状态 —— 每个工作进程持有自己的缓存（零协调：没有 Redis 跳转，也没有锁竞争）。每进程重复的代价被 `max_entries × max_body_bytes` 所限制。
- **响应体以 `Bytes` 存储 → HIT 时 zero-copy**：只是克隆一个 Arc，没有 memcpy。
- **`CACHE_SHARDS = 32`** 个独立的 LRU 分片，各有自己的 `RwLock` —— 不同键上的并行查找互不竞争（`response_cache.rs`，第 61 行）。每分片容量 = `(max_entries / 32).max(4)`。

### 配置 —— `ResponseCacheConfig`

`src/config.rs`，`pub struct ResponseCacheConfig`：

| 字段 | 默认值 | 用途 |
|---|---|---|
| `enabled` | `false` | 启用缓存。 |
| `max_entries` | 10 000 | LRU 中的最大记录数。最坏情况下内存 ≈ `max_entries × max_body_bytes`。 |
| `default_ttl_secs` | 60 | 当上游没有给出 `Cache-Control: max-age`/`s-maxage` 时的回退 TTL。 |
| `max_body_bytes` | 1 MiB | 可缓存响应体大小的硬上限。更大的会绕过缓存直接流式转发。 |
| `status_ttl_secs` | `{}` | 按状态码的 TTL 覆盖，例如 `{200 = 300, 404 = 10, 301 = 3600}`。常见套路：把 404 缓存很短的时间（10s），以在不冲击上游的前提下压住扫描器的突发。 |
| `stale_if_error_secs` | 0（关闭） | Stale-if-error 窗口：当上游返回 5xx/失败，且该窗口内存在近期刚过期的条目时，会带着 `Warning: 110` 返回过期副本。在后端故障期间维持站点可用。 |

> **缓存深度是主要调节杆。** 命中率比转发上的任何百分比都更重要（[`PERFORMANCE.md`](../en/reference/performance.md)，第 5 条）。请按流量画像调 `max_entries`、`default_ttl_secs`、`status_ttl_secs`；为抵御后端故障请启用 `stale_if_error_secs`。

---

## 8. H2 预算（控制帧预算）

`src/h2_budget.rs`（V182）是 Tempesta 风格的 per-connection HTTP/2 控制帧预算，在帧到达 h2 状态机**之前**施加。这既是性能措施也是防护措施：它压制那些利用某类控制帧成本低廉的攻击（Rapid Reset CVE-2023-44487、CONTINUATION flood CVE-2024-27316、Settings/Ping flood）。防护面的细节见 [`14-rate-limiting.md`](./14-rate-limiting.md) 与 [`21-arsenal-scenarios.md`](./21-arsenal-scenarios.md)。

### 默认预算 —— `Budget::default_for`

按 `(conn_id, FrameKind)` 的令牌桶。桶空时 —— `Verdict::Reject`（调用方关闭流/连接）。没有定时器 —— 补充量在 `consume` 时惰性计算。

| 帧（`FrameKind`） | `burst` | `refill_per_s` | 攻击类别 |
|---|---|---|---|
| `RstStream` | 50 | 20 | Rapid Reset |
| `Settings` | 10 | 2 | Settings flood |
| `Ping` | 30 | 10 | Ping flood |
| `Priority` | 100 | 50 | Priority churn |
| `Goaway` | 3 | 1 | 应当很罕见 |
| `Continuation` | 50 | 20 | CONTINUATION flood |

### 实现 —— 热路径上很廉价

- 映射的键是 `(u64 conn_id, FrameKind)`，两者都是 **connection-local** 的（连续 ID + 小 enum），不受攻击者控制 → 因此使用 **`FxHashMap`** 而非 SipHash：SipHash 的抗 DoS 特性在这里是多余的开销，而 FxHash 在小整数键上明显更快（`h2_budget.rs`，第 36–41、116–118 行）。
- `Bucket::consume` 惰性补充：`tokens = (tokens + elapsed × refill_per_s).min(burst)`，然后在 ≥1.0 时执行 `-= 1.0`（第 102–112 行）。
- `drop_conn(conn_id)` 清除已关闭连接的全部状态；`gc(idle)` 是对空闲桶的后台清理（第 151–163 行）。

### 运维调优

预算可通过 `H2BudgetTracker::with_override(kind, Budget { burst, refill_per_s })`（第 131–134 行）覆盖 —— 这是 DSL/配置的门面。同一套预算逻辑被抽成了一个极小的状态机，**XDP 快路径可以镜像它**以实现内核侧的执行：阈值只有一个事实来源，计数在两处进行（见 [`13-xdp-ebpf.md`](./13-xdp-ebpf.md)）。arsenal runner 通过 `src/proxy/pingora_admin.rs` 暴露 `h2_budget` 指标（`allows`/`rejects`/`tracked_conns`）（见 [`25-metrics-telemetry.md`](./25-metrics-telemetry.md) 与 [`30-admin-api.md`](./30-admin-api.md)）。

> **说明（诚实地）。** 在 `src/bin/aegis-pingora.rs`（约第 1724 行）有一条注释指出：in-tree 的 `h2_guard`/`h2_budget` 模块无法通过 pingora 栈本身完全控制公开监听器上的 h2 帧 —— 计数是在 hyper/h2 层（`src/proxy/h2_guard.rs`，V111）以及这台预算状态机中进行的，而 XDP 镜像是另一条路径。不要默认把它当作端到端的内核级强制执行。

---

## 9. 负载下的调优 —— 热路径与去分配

V236→V237 的审计（56 个 agent、14 个区域、对「在 plain 模式下每个请求是否真的会执行」做对抗性验证）关掉了「我们自己的」大部分开销。已实现的安全优化（见 [`PERFORMANCE.md`](../en/reference/performance.md) 的「优化了什么」）：

| 优化 | 要点 |
|---|---|
| LSE 原子指令 | `target-cpu=native` → 单指令的 `ldadd`/`swpal`（见 §4）。 |
| 减少 `clock_gettime` | 每请求 8× → 1×（过滤器引擎此前在每个过滤器上都读时钟）。 |
| 惰性 JA4H | SHA-256 指纹在首次读取时计算，而不是每个请求都算。 |
| 集群计数器批量化 | per-worker 缓冲，每 128 次 flush 一次；原地 RefCell 批处理（不复制整个数组）。 |
| read-lock + 零分配快路径 | 在 per-domain 指标中；单桶延迟直方图（3 个原子操作而非 13 个）。 |
| borrow-or-own 的 host 键 | 当 host 已经是小写时，不做 `to_ascii_lowercase` 分配。 |
| empty-feed 快路径 | threat-intel（`AtomicUsize` 哨兵）与 honeypot（没有启用的包时跳过 `canonical_path`）。 |
| 无分配的 Cookie 解析 | 在无 cookie 的路径上。 |

来自 `Cargo.toml` 的相关、依赖编译器的调节杆：

- **`mimalloc`**（`Cargo.toml`，第 143 行）—— 默认分配器，在热的 alloc/free 上比系统分配器更便宜。
- **`coarsetime`** —— 粗粒度的 `Instant`（约 10ms 一跳，约 3ns 一次读取），用于后台聚合器（dynamic_trust 的老化窗口、scorer、anomaly EMA），那里 1–10ms 的偏差不可见。精确的 `Instant::now()` 保留给延迟直方图与安全敏感的 token 过期。
- **`rustc-hash`（FxHash）** —— 用于键**不受**攻击者控制的内部映射（字面量、规则 ID、状态码、帧类型）。受攻击者控制的映射（IP、host、JA4）保留 AHash/SipHash 以获得抗 DoS 能力。
- **`memchr`** —— 在 WAF 规范化与 per-field 子串扫描中使用 SIMD 字节搜索（aarch64 上的 NEON，x86_64 上的 AVX2），取代标量的 `str::contains`。
- **带 `release_max_level_info` 的 `tracing`** —— `debug!`/`trace!` 在 release 中于编译期被剔除：热路径上的 19 个调用点不再各付出约 20–40 ns（在 100k+ RPS 下恢复了约 50–95 MB/s 的 dispatch）。

### V237 剖面 —— 剩余 CPU 花在哪

在 V236/V237 之后，**我们的代码 self-time <2%**（主要是 HeaderMap 的克隆）。剩下的约 25% 是框架 + 内核，在我们的代码之外：

| 是什么 | % self-time | 属于谁 |
|---|---|---|
| 内核 TCP 栈 | ~12% | 内核 —— 不可避免 |
| 读时钟（`cntvct`+`clock_gettime`） | ~6.8% | Pingora + tokio I/O/timer |
| Pingora HTTP 机制 | ~7% | 框架 |
| connection-pool LRU + 哈希 | ~3% | 框架（复用上游连接） |
| 我们的代码 | <2% | HeaderMap 的克隆 |

> **死胡同（不要再挖 —— 已验证，见 [`PERFORMANCE.md`](../en/reference/performance.md)）：**
> - **io_uring 数据面** —— 实测在 loopback 上比 nginx 慢约 24%（没有 DMA/zero-copy 收益；差距在 filter/routing 层，不在 I/O）。NO-GO。
> - **给 HeaderMap 克隆加门控（1.3%）** —— 被否决：即使是最安全的设计也产生了 2 个关键的 WAF-bypass 竞态。对于安全代理来说，1.3% 的吞吐不值得冒 WAF 被绕过的风险。保留无条件克隆。
> - **转发微基准本身** —— 这里的天花板是异步框架 + 内核 TCP，靠微优化最多再拿 2–3%。

---

## 10. 运维实用清单

```bash
# 1. 针对这套硬件的 release 构建（默认 —— native + 并行剖面）：
sudo bash install.sh --update

# 2. 最大限度优化的二进制（用于切发版，不用于日常）：
sudo AEGIS_BUILD_OPT=max bash install.sh --update

# 3. 可移植的二进制（build-once-deploy-many）：
sudo AEGIS_TARGET_CPU=generic bash install.sh --update

# 4. 按核心数设定工作进程数（或 auto = nproc）：
sudo bash install.sh --workers 8
```

| 调节杆 | 在哪里调 | 效果 |
|---|---|---|
| 构建剖面 | `AEGIS_BUILD_OPT=max` | 以漫长构建为代价换取运行时 +几个百分点 |
| Codegen 目标 | `AEGIS_TARGET_CPU`（`native`/`generic`/微架构） | LSE 原子指令 / AVX2 与可移植性之间的取舍 |
| 链接器 | mold（best-effort） | 只影响构建速度 |
| 工作进程 | `--workers` / 面板 / `nproc` | thread-per-core，1:1 绑核 |
| 缓存 | `ResponseCacheConfig`（`max_entries`、`*_ttl_secs`、`stale_if_error_secs`） | 命中率 —— 吞吐的主要调节杆 |
| H2 预算 | `H2BudgetTracker::with_override` / DSL | 对控制帧洪泛的抗性 |
| TLS resumption | 共享的 REUSEPORT ticket 密钥（自动） | 跨工作进程的 resumption |

---

## 另见

- [`PERFORMANCE.md`](../en/reference/performance.md) —— 方法论、真实数字、死胡同（本文档的第一手来源）。
- [`28-benchmarking.md`](./28-benchmarking.md) —— 如何复现测量，以及基准 lane 的说明。
- [`06-workers.md`](./06-workers.md) —— SO_REUSEPORT，跨工作进程状态。
- [`05-requirements.md`](./05-requirements.md) —— 硬件要求。
- [`03-installation.md`](./03-installation.md) —— install.sh 的完整说明。
- [`08-tls-certificates.md`](./08-tls-certificates.md) —— TLS 路径，ticket 密钥。
- [`13-xdp-ebpf.md`](./13-xdp-ebpf.md) —— 把 h2 预算镜像到内核。
- [`14-rate-limiting.md`](./14-rate-limiting.md)、[`21-arsenal-scenarios.md`](./21-arsenal-scenarios.md) —— h2 预算的防护面。
- [`25-metrics-telemetry.md`](./25-metrics-telemetry.md) —— `h2_budget` 指标，性能剖析。
