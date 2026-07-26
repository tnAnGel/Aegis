# 项目发展规划

**语言：** [English](../en/41-development-plan.md) · [Русский](../ru/41-development-plan.md) · **中文**

> 战略性文档：AEGIS 作为边缘防护平台的发展方向、哪些方向优先以及原因。
> 与战术性的[路线图](40-roadmap.md)（在哪个版本交付什么）不同，本文关注的是
> **方向与论证**：统一 risk engine、类 CRS 的 WAF 模型、
> 协议级 L7 防护、会话/设备信誉、API guard 以及来自生产流量的闭环
> feedback-loop。

本文以仓库中的真实代码以及三份战略来源为依据：
`ROADMAP-NEXT.md`（直至 technology ceiling 的规划，V100 已于 2026-05-20 达成）、
`AEGIS-X-ROADMAP.md`（四层 commodity 架构）以及
docs/RESEARCH-2026-05.md（针对 14 个 OSS 项目的 feature 级差距分析）。
每一处「已经具备」的声明都附有文件引用；所有部分实现/opt-in/未来的内容都如实标注。

---

## 1. 我们目前所处的位置（规划的起点）

`ROADMAP-NEXT.md` 记录：**V100 已达成，Phase A–E feature-complete**
（第 1–6 行）。后续全部规划所依赖的防护栈已经在 `main` 中：

| 层 | 代码中真实存在的内容 | 文件（示例） |
|---|---|---|
| eBPF/XDP fast-path | deny/allow-set + per-CPU 计数器 + first-byte WAF triage | `xdp/`, `src/xdp.rs` |
| WAF | Aho-Corasick 签名 + Sigma 语料 + compound 规则 + webshell | `src/filters/waf.rs`, `src/sigma.rs`, `src/filters/sigma_overlay.rs` |
| TLS 指纹 | JA3/JA4/JA4H/JA4T（在 ClientHello 回调中采集） | 见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| Risk engine | `RiskEngineMode { Off, Observe, Enforce }` | `src/config.rs:419`, `src/ddos/risk_engine.rs` |
| ML scoring | LR v1/v2 + GBM + adversarial，online SGD | `src/ddos/ml_score.rs`, `src/ddos/ml_score_v2.rs`, `src/ddos/ml_gbm.rs` |
| 信誉 | self-learning JA4 + ASN/CIDR + CrowdSec LAPI + threat-intel | `src/ja4_reputation.rs`, `src/proxy/pingora_admin.rs:109` |
| Self-improving sigs | n-gram miner + online-miner | `src/signature_mine.rs`, `src/online_signature_miner.rs` |
| Cluster state | shared-mmap arena + AtomicHashMap（Linux） | 见 [06-workers.md](06-workers.md) |

> **如实说明（出自 `ROADMAP-NEXT.md`，V100 closing notes，第 315–329 行）：**
> 「technology-ceiling checklist」的 5 项中有三项（#1 throughput-headline、
> #2 bench vs nginx、#4 bare-metal x86 32c、#5 真实 edge）**取决于压测运行
> 和硬件，而非代码**。也就是说功能基础已经就绪；尚未解决的是运维层面的
> 验证。这决定了下文的优先级 №0。

---

## 2. 战略方向

来自简报的六个方向。对每一个都说明：**代码中已有什么**、**哪些是
部分实现/opt-in**、**规划中有什么**以及**优先级的论证**。

### 2.1. 统一 risk engine

**愿景。** 所有信号（WAF 判定、JA4 信誉、anomaly-score、
ML 推理、rate-limit、GeoIP/ASN、honeypot 命中）汇聚到一个
相关性关联点，由它以透明的 explainability 做出决策，
而不是作为一组彼此独立的过滤器。

**已经具备的内容。** risk engine 以三种模式实例化
（`src/config.rs:419`）：

```rust
pub enum RiskEngineMode {
    Off,      // 不实例化，zero cost —— safe default
    Observe,  // 计算并记录 score，但不改变决策（shadow）
    Enforce,  // score >= threshold 时，将本应 Allow 的请求升级处理
}
```

默认阈值较为保守 —— `default_risk_threshold() = 90`
（`src/config.rs`）。引入了 Observe-first rollout（`src/config.rs:394`，
注释「correlational RiskEngine wiring」）并明确注明：过早 enforce
是危险的，需要 ≥ 一周的 Observe 数据。0..100 的 ML 输出已经
作为特征接入 risk engine（`src/ddos/risk_engine.rs:67` ——「ML inference
output 0..100 from V97 MlScorer」）。

> **关于术语的如实说明。** 简报中提到的模式
> `Observe/HighConfidenceEnforce/FullEnforce` 是*设计阶段*的
> 命名。在实际代码中该 enum 名为 `Off/Observe/Enforce`
> （`src/config.rs:419`）。编写场景/配置时请使用真实的
> 名称。`FullEnforce` 仅作为历史引用出现在
> BGP 模块的注释中（`src/bgp_rtbh.rs:10`）。

**规划中（方向）。** 出自 `ROADMAP-NEXT.md`「Out of scope for V100」
（第 331–344 行），原文明确指出：V97 `MlScorer` + V98 `ThreatTier` 经由
`pingora_http` 的 **hot-path wiring** 尚未完成 —— 数据结构已经就位，
但 call-site refactor 被刻意分离出去。这正是统一 engine 方面最近的
工作：把 ML/tier 信号送达 pingora 热路径上的决策点，而不只是计算它们。

出自 RESEARCH-2026-05.md —— 有两个想法可以强化统一 engine：
- **复合 identity**（Cilium 模式，§2）：带 TTL 的稳定哈希
  `(JA4 || ASN || cookie || behaviour-fp)`，使决策能够在
  IP 变化（NAT/代理）后依然有效。「Plugs into ThreatScorer naturally」。
- **Flowbits/flowints**（Suricata，Top-10 #7）：per-connection 状态，
  让规则可以表达「POST /login → 401 ≥3 次，然后 GET /admin →
  block」而无需 bespoke 代码。

**优先级：高。** engine 已经存在，但主要运行在 Observe 模式；
把 ML/tier 接到决策点是把「计算」变成「防护」最廉价的路径。

### 2.2. 类 CRS 的 WAF 模型（paranoia-levels / anomaly-score / shadow-mode）

**愿景。** 从扁平的规则集合转向 OWASP CRS 风格的模型：
带严格度等级（paranoia）的规则、带阻断阈值的累积 anomaly-score，
以及用于安全上线新规则的强制 shadow 模式。

**已经具备的内容。**
- **Shadow-mode —— 确实可用。** `action: "shadow"` /
  `"log"` 的 WAF 规则只统计触发次数，不改变判定（`src/config.rs:807`，
  注释：「shadow first, watches metrics for a week, then flips」）。
  Sigma 导入器会自动把 `low`/`informational` 等级映射为
  `("log", "low", Some("shadow"))`（`src/sigma.rs:568`；测试
  `level_low_maps_to_log_shadow` 位于 `src/sigma.rs:1076`）。
  「match-but-don't-act」这一决策有独立的 `DecisionKind::Observed`
  （`src/security_event.rs:43`）。
- **Anomaly-score —— 部分实现，位于 TLS 层。** `anomaly_score()` 存在
  于 GREASE 异常（`src/grease_anomaly.rs:42`），并接入
  client-consistency 打分（`src/client_consistency.rs:189`）。这**不是**
  覆盖全部 WAF 规则的 CRS 式累积 score —— 目前只是一个狭窄的
  TLS 信号。
- **Sigma 语料与 compound 规则**已经交付（`src/sigma.rs`、
  `src/filters/sigma_overlay.rs`，以及独立二进制 `src/bin/aegis-sigma-import.rs`），
  外加 webshell 签名（来自最近一次提交）。Compiled rule plan
  （per-field Aho-Corasick）在 `ROADMAP-NEXT.md` 中为 V95-V96（第 309 行）。

**部分实现/规划中的内容。**
- **Paranoia-levels** 本身在代码中并不存在 —— 这是一个方向。最近的
  可挂接机制是：规则上的 severity/tags 与 shadow 标志已经具备，因此
  paranoia 等级可以自然落成「激活 severity ≤ N 的规则」这样一个筛选条件。
- **覆盖 WAF 的累积 anomaly-score**（CRS 的核心）—— 是对现有打分的
  扩展：把触发规则的权重求和后与阈值比较。
- 出自 RESEARCH-2026-05.md，方向 A.1（§Cross-cutting）：
  **Wirefilter 之上的 macro/list 层**（Falco 风格）被称为「the single cheapest
  UX upgrade we can make for ops」。这是让 CRS 模型对运维人员变得
  好用的基础设施。

**优先级：高。** 就广度而言，检测能力已经达到 ModSecurity/CrowdSec 的水平
（见 RESEARCH executive summary）。所欠缺的是*运维侧的管理模型*：
paranoia + 累积 score + macro/list DSL。这属于 ergonomics，
以 10% 的工作量带来 80% 的价值。

### 2.3. 协议级 L7 防护（h2/h3）

**愿景。** 针对 HTTP/2 与 HTTP/3 的专门防护：帧 flood 限制、
rapid-reset、把 h2/h3 abuse-guard 作为独立的一层。

**已经具备的内容。**
- **H2 flood 限制 / abuse-guard。** 该分支最近的提交正是关于这一点：
  「sigma compound rules + C3 h2 flood limits」（commit 78294ec）以及带 jitter 的
  Sigma-overlay（`src/latency_jitter.rs`）。RESEARCH（§14，「We already have」）
  确认存在「H2 abuse guard」。
- **HTTP/3 / QUIC** 通过共享 pipeline 状态的 hyper-handler shim 提供服务
  （`AEGIS-X-ROADMAP.md`，V46，第 236 行），并配有 h3 WAF
  hot-reload poller（V61）与 e2e smoke（V62）。

**部分实现/规划中的内容（如实说明）。**
- **H2 frame-fingerprint（Akamai 风格，`h2_fp`）** —— **在
  pingora-core 层面被阻塞**：「needs fork to expose h2 frames」（`AEGIS-X-ROADMAP.md`，
  第 256 行，标注为「by design / blocked」）。这是已知限制，
  不是 bug。策略（Risks 表，第 366 行）：把采集保留在 XDP/eBPF 中，
  pingora 只负责读取。
- **HTTP/3 server push** 有意不在规划内 —— 已在 RFC 中被废弃
  （`ROADMAP-NEXT.md`，「不在规划内的内容」，第 174 行）。
- **gRPC**：我们不做单独的 gRPC 专门处理 ——「pingora handles 这一点已经
  generic」（`ROADMAP-NEXT.md`，第 176 行）。另见 §2.5 关于 API-guard 的部分。

**优先级：中。** 基本的 h2-flood 限制已经具备；协议层面的深度
（frame-fp）受制于 upstream 依赖，因此通过 XDP 而不是通过 fork pingora
来推进。

### 2.4. 会话与设备信誉（session/device reputation）

**愿景。** 信誉不仅基于 IP/JA4，还基于「设备」/「会话」——
一种能在 IP 变化后依然稳定的复合身份。

**已经具备的内容。**
- **Self-learning JA4 信誉** —— 默认启用
  （`src/proxy/pingora_admin.rs:109`：「reputation feeds now ON by default
  (self-learning JA4 + ...)」；`src/ja4_reputation.rs` 维护 `learned` 计数器）。
  自学习的来源：honeypot/WAF/tarpit。默认开启的还有 ASN/CIDR
  （Tor/Spamhaus）、CrowdSec LAPI、threat-intel（见 [12-reputation.md](12-reputation.md)）。
- **Device/passive-fp 信号**：p0f 风格的 TTL 观测（`src/p0f.rs:291`）、
  UA-vs-JA4 mismatch（`src/filters/ua_fp_mismatch.rs`）、client-consistency
  （`src/client_consistency.rs`）。这些是「device reputation」的原料。

**部分实现/规划中的内容。**
- **复合 identity**（Cilium 的思路，RESEARCH-2026-05.md §2）：
  「today we operate on `(IP, ASN, JA4, cookie)` individually. A composite
  identity type —— 带 TTL 的稳定哈希 —— would let per-endpoint policies match
  on identity, surviving NAT/proxy IP changes」。这正是从
  「指纹信誉」通往「会话/设备信誉」的桥梁。
- **带 provenance 的类型化 IntelStore**（Zeek/Suricata `datarep`，
  Top-10 #5/#6）：目前 threat-intel 是「a flat IP/CIDR set」（RESEARCH，
  「Directions still empty」第 5 条）。规划是做类型化集合
  （`IP/CIDR/JA4/SHA256/...`），带 `(source, confidence, first/last_seen)` 以及
  `in_set(name, rep>=N)` 运算符，使信誉不再是二值的。

**优先级：中-高。** Self-learning JA4 已经带来了大部分
价值。复合 identity 是对抗 IP 轮换的下一个杠杆，但
需要谨慎处理 TTL 与基数（LRU-cap）。

### 2.5. API-guard（REST / JWT / GraphQL / gRPC）

**愿景。** 面向现代 API 的专用 guard：JWT 校验、
GraphQL 深度/复杂度限制、gRPC 防护。

**已经具备的内容（如实说 —— 只有 GraphQL）。**
- **GraphQL guard** 确实存在并已接入：`src/filters/graphql.rs`
  （`GraphqlFilter`、`GraphqlConfig`），在 `src/server.rs:283` 注册。
  出于成本/依赖方面的考虑并非完整解析器
  （`src/filters/graphql.rs:3`）；最强的防护是 **persisted query hashes**
  （`persisted_hashes`，`src/filters/graphql.rs:31`，「Strongest GraphQL DDoS
  defence」）。

**目前尚不存在的内容（是方向，而非实现）。**
- **JWT-guard** —— `src/filters/` 中没有单独的 JWT 校验/inspection 过滤器
  （该目录里属于 API-guard 的只有 `graphql.rs`）。这是规划。
- **gRPC-guard** —— 有意不做单独的 gRPC 专门处理（见 §2.3：
  「pingora handles generic」）。
- **REST-guard** —— 由通用 WAF + per-endpoint policy 覆盖
  （[26-sites-and-domains.md](26-sites-and-domains.md)），没有作为模块的
  单独 REST-aware guard。

**规划的挂接点。** Per-domain/per-endpoint policy 与 actuator 方向
（见 §2.6）是天然的基础：把 JWT-claims 作为规则选择器（RESEARCH §4，
Tracee：「if event.jwt_role ... and event.path starts_with /admin: block」）。

**优先级：中。** GraphQL 已经覆盖（API 最常见的 DDoS 向量）。
JWT-guard 是下一个显而易见的步骤，REST/gRPC 由通用流水线覆盖。

### 2.6. 来自生产流量的闭环 feedback-loop

**愿景。** 被 honeypot/tarpit/WAF 捕获的攻击自动改进
防护：继续训练 ML、产生签名、提升信誉分。

**已经具备的内容。**
- **Honeypot → ML feedback。** `src/robots_honeypot.rs:10`：「V149 wires that
  signal into the V135 MlTrainer feedback loop」。ML 的在线再训练是 V123
  （`src/ddos/ml_score_v2.rs:14`，「operator-driven feedback」）、online SGD
  （`src/ddos/ml_score.rs`）。
- **Self-improving signatures。** N-gram miner（`src/signature_mine.rs`）+
  online-miner（`src/online_signature_miner.rs`），后台运行位于
  `src/proxy/pingora_background.rs`（第 68/233/412 行）。管理路由
  `POST /admin/signature_mine`（`src/admin_auth.rs:187`，角色 `Write`）。
- **Self-learning 信誉**（§2.4）—— 同一条回路：honeypot/WAF/tarpit
  喂养 JA4 信誉。

**部分实现/规划中的内容（如实说明）。**
- **No-write-back by design。** V99（`ROADMAP-NEXT.md`，第 312 行）：miner
  执行「intentional no-write-back (operator promotes manually)」。也就是说
  这条回路目前是**半闭合**的：候选项自动挖掘，但推到生产
  由操作员完成。完全自动化（对 low-confidence 配以 approval-pipeline）
  是方向 E.4（`ROADMAP-NEXT.md`，第 158–162 行）。
- **Online tarpit-log → miner automation** —— 处于「Out of scope for V100」
  （`ROADMAP-NEXT.md`，第 343 行）：「currently corpus is supplied per admin
  request」。
- **Hunt jobs**（Arkime，RESEARCH §8）：用新规则对最近 N 小时的事件
  做后台重扫 ——「catches signatures we just learned against
  attacks that already happened」。这是 feedback-loop 合乎逻辑的扩展。

**优先级：高（差异化点）。** RESEARCH 明确把
self-improving signature mining 称为 OSS 代理中无人具备的独特功能
（`ROADMAP-NEXT.md`，第 346–354 行）。打通最后一公里
（受控的 auto-promote）是巨大的战略收益。

---

## 3. 优先级汇总矩阵

按 ROI 排序（以 RESEARCH Top-10 差距分析 + 代码现状为依据）。

| # | 方向 | 代码中的状态 | 优先级 | 论证 |
|---|---|---|---|---|
| 0 | **Operational validation**（bench-sweep + bare-metal 32c + 真实 edge） | 取决于硬件/压测运行 | **关键** | 5 个 ceiling 项中有 3 个等待的不是代码而是验证（`ROADMAP-NEXT.md` 315–329） |
| 1 | 统一 risk engine：ML/tier 的 hot-path wiring | 结构已有，call-site 没有 | 高 | 成本最低：从「计算」到「防护」（out-of-scope V100，331–344） |
| 2 | Sigma importer（扩展）+ Wirefilter 之上的 macro/list DSL | Sigma 导入已有；DSL 没有 | 高 | 「whole detection ecosystem」+「cheapest UX upgrade」（RESEARCH Top-10 #1，§A.1） |
| 3 | Leaky-bucket scenario DSL（CrowdSec 风格） | rate-limit 是扁平的 | 高 | 「10 distinct 4xx URIs from one IP in 10s」= 7 行 YAML 而不是代码（Top-10 #2） |
| 4 | Actuator registry + revert-timers | 动作是硬编码的 | 高 | 解锁各类集成；回路 §2.6（Top-10 #4） |
| 5 | Feedback-loop：受控的签名 auto-promote | 半闭合 | 高 | 独特的差异化点（`ROADMAP-NEXT.md` 346–354） |
| 6 | 复合 identity（session/device reputation） | 信号已有，identity 没有 | 中-高 | 能在 IP 轮换后依然有效（RESEARCH §2） |
| 7 | 类型化 IntelStore + `datarep` reputation | flat IP/CIDR set | 中 | 信誉不再是二值的（Top-10 #5/#6） |
| 8 | CRS 模型：paranoia + 累积 anomaly-score | shadow 已有，paranoia 没有 | 中 | WAF 的运维管理模型（§2.2） |
| 9 | API-guard：JWT-guard | 只有 GraphQL | 中 | GraphQL 已覆盖；JWT 是下一个向量（§2.5） |
| 10 | Flowbits/flowints（multi-stage） | 规则是 per-request 的 | 中 | 无需 bespoke state 的关联（Top-10 #7） |
| 11 | File-carving + YARA pipeline | 只有 ClamAV TCP | 中 | 「10x detection upgrade」但 effort 为 L（Top-10 #3） |
| 12 | 协议层 h2_fp 深度 | 在 pingora-core 处被阻塞 | 低 | upstream 依赖；通过 XDP 绕开（§2.3） |

---

## 4. 整体战略的论证

**差异化原则（`AEGIS-X-ROADMAP.md`，第 6–11 行）。** 取胜靠的
不是功能数量，而是 OSS 世界中无人具备的**独特组合**：
XDP fast-path + 带 compiled plan 的用户态 WAF + per-IP ML + threat-aware
tiered cache + cluster shared-mmap integrity + self-improving sigs。没有任何一个
开源代理能一次性覆盖这整个范围
（`ROADMAP-NEXT.md`，第 346–354 行）。发展战略 = **深化这一组合
及其 ergonomics**，而不是在纯粹速度上追赶竞争者。

**关于性能的如实说明。** AEGIS 并不声称自己在纯速度上快过
真实的代理。AEGIS 的压测通道是 in-process 引擎，
而不是完整的 pingora 二进制；在没有硬件 SHA 加速的 VM 内，per-core 的
硬件 SHA 压测数值偏低（此时容量预测偏悲观）。项目真正有力的
论据是**安全矩阵**，而不是 RPS。性能天花板
（`ROADMAP-NEXT.md`，condition #1，第 355–356 行）受限于硬件而非
功能 —— 因此优先级 №0 属于运维层面，而不是代码层面。详情见
[27-performance-tuning.md](27-performance-tuning.md)、
[28-benchmarking.md](28-benchmarking.md)。

**为什么 ergonomics（DSL/macro/scenario）是最高优先级。** RESEARCH
executive summary：就广度而言 AEGIS 的检测已经达到或超过 ModSecurity/CrowdSec/
Suricata 的水平；我们在 JA4 矩阵、ML 流水线和 honeypot 广度上领先
（§B「Where we already lead」）。相对*全部* 14 个项目而言唯一
系统性的缺口，是引擎之上缺少声明式的 DSL 层
（§A.1、§C.1）。因此 RESEARCH 中的「下一个 sprint」主要是 DSL/
适配器（Sigma、scenarios、actuators），而不是新的检测器。

**我们有意不做的事**（`ROADMAP-NEXT.md`，第 166–177 行）：

| 不做 | 原因 |
|---|---|
| Full monoio swap | 需要 fork pingora-core，维护负担大 |
| XDP_REDIRECT to upstream | 对 TLS-terminating 代理不可行（没有 DSR） |
| AF_XDP zero-copy receive | 需要重写 TCP 层，场景小众 |
| WASM filters | 与已有的 Lua 插件重叠（[31-plugins.md](31-plugins.md)） |
| HTTP/3 server push | 已在 RFC 中废弃 |
| gRPC proxy specifics | pingora handles generic |
| Community-consensus blocklist | 需要 users at scale（RESEARCH §13） |

---

## 5. 阶段顺序（来自 ROADMAP 各来源）

`ROADMAP-NEXT.md` 的历史阶梯（V77 → V100）展示了已完成的
模块；未来则是在 `AEGIS-X-ROADMAP.md` 同样这些层内部的扩展。

```
Phase A — XDP        ✅ partial (counters + WAF; XDP_REDIRECT 不适用于 TLS proxy)
Phase B — Pingora    ✅ done (V72; ~770k stable —— target 的上沿)
Phase C.2 — WAF AC   ✅ done (V76; overhead 10%→2%)
Phase C.3 — headers  ✅ done (V78-V79; cache fast-path 位于 build_ctx 之前)
Phase C.1 — io_uring ⏳ V83-85 未开始 (tokio-uring, gated, +15-25% expected)
Phase D — mmap state ✅ V86-V89; ⏳ V90 scorer-migration 未开始
Phase E — JIT+ML     ✅ feature-complete (V91-V100)，但 hot-path wiring 被推迟
```

**最近的正确步骤**（`ROADMAP-NEXT.md`，第 326–329 行）：在
Aegis-Proxy-dev 平台上做 bench-sweep（Bench A vs nginx，Bench C distributed-attacker），
随后用 i9-9900K native-Linux 双系统跑出 32c 的数字。这可以关闭
ceiling-checklist 的第 1/2/4 项，之后是第 5 项（真实 edge）。

**「technology ceiling」的定义**（`ROADMAP-NEXT.md`，第 196–211 行）：
在满足 **5 项中的 4 项**条件时停止功能开发，转入
「maintenance + operator UX polish + docs」阶段。按 checklist 的当前状态 ——
见 42-текущее-состояние-STATUS.md。

---

## 6. 需要操作员做什么

出自 `ROADMAP-NEXT.md`（第 215–231 行），已按当前状态调整：

1. **压测验证**：热路径改动之后在平台上进行（Bench A vs nginx，
   Bench C distributed-attacker）—— 见 [28-benchmarking.md](28-benchmarking.md)。
2. **在 bare-metal x86 32c 上的最终压测**（i9-9900K native Linux 双系统
   或云上 Hetzner/OVH）—— 只需一次，给出诚实的 production-class 数字
   （关闭 ceiling #4）。
3. **在真实 edge 上的生产验证**（真实流量，而非压测）——
   关闭 ceiling #5；这是唯一无法在实验室中获得的一项。
4. **risk engine 与 WAF 的 Observe-first。** 在 `Enforce` 之前 —— 至少一周的
   `Observe`/shadow 数据（`src/config.rs:404`）；观察指标
   （[25-metrics-telemetry.md](25-metrics-telemetry.md)），然后再切换。

---

## 7. 相关文档

- [40-roadmap.md](40-roadmap.md) —— 按版本的战术规划
- 42-текущее-состояние-STATUS.md —— 状态快照
- [10-waf.md](10-waf.md) · [18-ml-risk-engine.md](18-ml-risk-engine.md) ·
  [12-reputation.md](12-reputation.md) · [11-tls-fingerprinting.md](11-tls-fingerprinting.md)
- [13-xdp-ebpf.md](13-xdp-ebpf.md) · [17-honeypot-tarpit.md](17-honeypot-tarpit.md) ·
  [21-arsenal-scenarios.md](21-arsenal-scenarios.md) · [22-enrichment.md](22-enrichment.md)
- [23-security-model.md](23-security-model.md) —— 项目最有力的论据
- [30-admin-api.md](30-admin-api.md) —— 诸如 `POST /admin/signature_mine` 的路由
- 战略来源：`ROADMAP-NEXT.md`、`AEGIS-X-ROADMAP.md`、
  RESEARCH-2026-05.md
