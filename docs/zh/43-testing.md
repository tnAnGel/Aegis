# 测试

**语言：** [English](../en/43-testing.md) · [Русский](../ru/43-testing.md) · **中文**

本文描述 AEGIS 的测试策略：测试的组织方式与规模（约 1485 个函数）、如何运行它们（`cargo test`、`pingora`/`xdp` 特性开关、按库过滤），以及各 e2e 二进制的用途与运行方式 —— 压测用的 `aegis-e2e`、pingora 冒烟测试 `aegis-pingora-e2e`、sqlmap-replay `aegis-sqlmap-replay` 和分布式的 `aegis-distbench`。每一处论断都对应真实代码；部分实现/opt-in 的覆盖如实标注。

另见：[28-benchmarking.md](28-benchmarking.md)（性能，独立工具 `aegis-bench`）、42-текущее-состояние-STATUS.md、[10-waf.md](10-waf.md)、[21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

---

## 1. 测试的层次

AEGIS 使用三个相互补充的测试层次：

| 层次 | 位置 | 检查什么 | 如何运行 |
|------|-----------|---------------|-----------------|
| 单元测试 | `src/**.rs` 内的 inline 模块 `#[cfg(test)] mod tests` | 各个模块的逻辑（解析器、打分器、归一化、状态机） | `cargo test --lib` |
| 集成测试 | `tests/integration.rs`、`tests/arsenal_integration.rs` | 端到端的代理流水线，以及 Defence Arsenal 经由库的公开入口点的接线 | `cargo test --test integration --test arsenal_integration` |
| E2E 二进制 | `src/bin/aegis-e2e.rs`、`src/bin/aegis-pingora-e2e.rs`、`src/bin/aegis-sqlmap-replay.rs`、`src/bin/aegis-distbench.rs` | 真实 AEGIS 进程（们）在真实 socket 上的行为 | `cargo build --release --bin <名称>`，然后运行该二进制 |

整个仓库合计约 **1485** 个测试函数（`#[test]` + `#[tokio::test]`）：`src/` 中约 **1453** 个（单元测试），`tests/` 中 **32** 个（集成测试）。Inline 的 `mod tests` 大约出现在 **140** 个 `src/` 文件中。

> 规模按源码中的 `#[test]`/`#[tokio::test]` 标记统计：`grep -rn '#\[test\]\|#\[tokio::test\]' src/ tests/ | wc -l`。该数字是当前分支状态的快照，会随代码变化。

---

## 2. 如何运行测试

### 2.1. 基础运行

```bash
# 完整集合：单元测试 + 集成测试 + doctests + 所有二进制/示例的编译
cargo test --all-targets

# 仅单元测试（快；不含集成用二进制）
cargo test --lib

# 指定的集成测试文件
cargo test --test integration
cargo test --test arsenal_integration
```

与 CI 的做法一致（`.github/workflows/ci.yml`，job `test`）：`cargo check --all-targets` → `cargo clippy --all-targets -- -D warnings` → `cargo test --all-targets`。CI 在 `ubuntu-latest` 和 `macos-latest` 上运行，另有单独的 `fmt` job（`cargo fmt --all -- --check`）。全局启用了 `RUSTFLAGS: "-D warnings"`，因此任何编译器警告都会导致构建失败。

### 2.2. 过滤测试（`--lib` + 模式）

`cargo test` 接受测试名的子串作为过滤条件。与 `--lib` 搭配尤其有用，可以只跑需要的子系统：

```bash
# 全部 WAF 测试（模块 src/filters/waf.rs —— 最大的一组，约 78 个测试）
cargo test --lib waf

# 仅 SQL 语义
cargo test --lib sql_semantic

# Privacy Pass
cargo test --lib privacy_pass

# 按完整的 模块::函数 名运行某一个具体测试
cargo test --lib filters::waf::tests::sqli_signature_matches

# 列出将会运行的内容，但不执行
cargo test --lib waf -- --list
```

有用的测试 harness 标志（放在 `--` 之后）：

| 标志 | 用途 |
|------|------------|
| `-- --nocapture` | 不吞掉测试的 `println!`/stdout |
| `-- --test-threads=1` | 串行运行（用于对环境敏感的测试） |
| `-- --ignored` | 运行标记为 `#[ignore]` 的测试 |
| `-- --list` | 输出测试列表而不执行 |

### 2.3. 特性开关

测试默认以 `default = []` 编译（见 `Cargo.toml` 中的 `[features]`）。有两个可选特性需要显式开启：

```bash
# Pingora data plane（会拉入 openssl/pingora-* —— 依赖树很大）
cargo test --features pingora --all-targets

# XDP/eBPF fast-path（仅 Linux；运行时需要 CAP_BPF + CAP_NET_ADMIN，
# 但编译/单元测试没有特权也能工作）
cargo test --features xdp --all-targets
```

CI 用独立的 job 体现了这一点：`xdp-feature`（在 Linux 上执行 `cargo test --features xdp --all-targets`）与 `bpf-program`（在 nightly 上通过 `bpf-linker` 构建 eBPF 对象 `aegis-xdp`）。pingora 路径专有的测试（例如 `src/proxy/pingora_http.rs` 约 26 个、`src/proxy/pingora_challenge.rs` 约 28 个）只在 `--features pingora` 下编译。

> 如实说明：e2e 二进制 `aegis-pingora-e2e` 整体被锁在 `#![cfg(feature = "pingora")]` 之后（`src/bin/aegis-pingora-e2e.rs:18`）—— 没有该特性时它会编译成一个空壳，什么也不检查。

---

## 3. 流水线的集成测试（`tests/integration.rs`）

这些是代理处理器的端到端测试。每个测试都会在一个空闲 TCP 端口上启动**真实的 upstream**（`spawn_mock_upstream`，每个测试一个 tokio 任务），并直接调用 `ProxyHttpHandler::handle_collected`，在真实 socket 上跑完整条流水线（distributed 检查 → WAF → bot → adaptive → rate-limit → challenge → 转发到 upstream），而不启动公开的监听器。

辅助函数 `build_handler(...)` 以可预测的配置组装处理器：过滤器链 `IpAcl → Waf → Bot → Adaptive → Challenge → RateLimit`（`FilterEngine::new(..., DefaultAction::Allow)`）、`NoopXdp`、`NoopGeoIp`、位于 `temp_dir` 的临时 `HoneypotStore`、默认的 `AnomalyDetector`、`DynamicTrustConfig`、`ResponseCacheConfig`。

覆盖的场景（`#[tokio::test]`）：

| 测试 | 论断 |
|------|-------------|
| `upstream_passthrough_returns_body` | 干净的 GET 抵达 upstream，返回响应体，upstream 收到 1 次命中 |
| `waf_sqli_signature_blocks_before_upstream` | query 中经 URL 编码的 `UNION SELECT` → `403 FORBIDDEN`，响应体包含 `sqli`，upstream **未**被触及 |
| `ip_acl_deny_short_circuits` | 位于 deny 列表中的 IP → `403`，upstream 无命中 |
| `rate_limit_returns_429_after_burst` | 当 `burst=2` 时前两个请求通过，第三个 → `429 TOO_MANY_REQUESTS` |
| `challenge_ladder_emits_set_cookie_and_step_header` | 阶梯的第一步 → `307`，包含 `location`、`x-aegis-step: headers`、`Set-Cookie: aegis_token=...; HttpOnly` 等头 |
| `challenge_cookie_round_trip_passes_to_upstream` | 带有效 `aegis_token` 的重试 → `200` + 转发到 upstream |
| `waf_body_inspection_catches_signature_in_payload` | POST 体中的 SQLi → `403`，upstream 未被触及 |
| `waf_body_size_limit_returns_413` | 在 `max_body_bytes=1024` 时 4096 B 的请求体 → `413 PAYLOAD_TOO_LARGE` |
| `upstream_unavailable_returns_502` | 死掉的 upstream → `502 BAD_GATEWAY` |
| `fingerprint_cookie_short_circuits_challenge` | 向 `/__aegis/verify?...&fp=...` 的 POST 会设置 `aegis_token` + `aegis_fp`；长生命周期的 `aegis_fp` 单独即可绕过阶梯 |
| `verify_endpoint_with_invalid_token_rejects` | 带伪造 token 的 `/__aegis/verify` → `403` |

运行：

```bash
cargo test --test integration
cargo test --test integration challenge      # 仅 challenge 场景
```

---

## 4. Defence Arsenal 的集成（`tests/arsenal_integration.rs`）

用途（V194，见文件头部）：证明 Defence Arsenal 的各模块在从与代理热路径相同的库入口点被调用时，确实会「推动」计数器。如果这些测试失败，说明 `src/bin/aegis-pingora.rs` 中的接线产生的是死状态，任何关于「计数器是活的」的说法都是谎言。这些测试并不启动 HTTP 服务器；它们直接调用 `ArsenalState` 及相关模块。

覆盖的模块与不变式：

| 测试 | 模块 / API | 检查什么 |
|------|--------------|----------------|
| `ja4_corpus_lookup_bumps_counter` | `ja4_corpus` | 按 JA4 字符串查询返回判定，计数器 `ja4_corpus_lookups`/`ja4_corpus_allow_hits` 增长 |
| `ja4_churn_observe_tracks_ip` | `ja4_churn` | 同一 IP 上的 JA4 轮换产生高 churn（>0.9） |
| `h2_observe_bucket_consumes_and_rejects` | `observe_h2_frame` / `h2_budget` | HTTP/2 帧（RST_STREAM）预算在 120 个中放行约 40–60 个，其余拒绝；计数器 `h2_budget_allows`/`rejects` 准确 |
| `rule_plan_install_and_dispatch_round_trip` | `rule_planner::RulePlan` | 安装计划并按阶段分派（`RequestUriOrQuery`、`RequestHeaders`） |
| `waf_rule_descriptors_translate_to_planner_phases` | `WafFilter::rule_descriptors` | 自定义规则 + 内置规则被分配到 URI/headers/body 各阶段 |
| `honeypot_responder_returns_synth_with_counter` | `honeypot_respond` | 合成响应 + `llm_honeypot_responses` 或 `yaml_honeypot_engagements` 增长 |
| `bgp_rtbh_announce_then_withdraw` | `bgp_rtbh` | announce/withdraw 改变规模以及计数器 `bgp_rtbh_announces`/`withdraws` |
| `grease_extract_parses_chrome_shaped_handshake` | `ja4::extract_grease_positions` | 解析 GREASE 位于位置 0 的合成 ClientHello |
| `route_difficulty_ai_scraper_ua_bumps` | `route_difficulty` | UA `GPTBot` 相对浏览器 UA 提高 challenge 难度 |
| `decoy_headers_produce_cloudflare_shape` | `decoy_headers` | Cloudflare 系列给出 `server`、`cf-ray`、`alt-svc` |
| `sicherheitstacho_renders_valid_ndjson` | `sicherheitstacho` | 供 SIEM 使用的正确 NDJSON，包含字段 `category`、`src_ip`、`request` |
| `latency_jitter_distribution_sensible` | `latency_jitter` | 默认的 tarpit jitter 中心落在约 200–900 毫秒 |
| `timing_entropy_flags_synthetic` | `timing_entropy` | 均匀的鼠标/滚动间隔 → 高 `anomaly_score` |
| `normalisation_chains_url_html` | `normalisation` | URL→HTML 解码链还原出 `<script>` |
| `param_profile_anomaly_after_training` | `param_profile` | 在 6 位数字上训练之后，`<script>` 被判为异常 |
| `actuator_registry_applies_and_reverts_via_arsenal` | `actuator` | `XdpDeny` 被应用并通过 `tick()` 按 TTL 自动回滚 |
| `enrichment_facade_aggregates_two_sources` | `enrichment` | 两个来源的聚合：`Deny` 占主导，`sources.len()==2` |
| `scenario_engine_fires_block_after_capacity_via_arsenal` | `scenarios` | YAML 场景 `brute_login` 在 `capacity` 耗尽后触发（`Fired`） |
| `arsenal_counters_include_new_module_fields` | `counters::snapshot` | 计数器结构体的形状契约（字段可编译） |
| `sigma_imported_toml_loads_through_waf_rule_file_parser` | `config::WafRule` | 导入的 `rules/sigma/sigma-webserver.toml` 作为 `rule_files` 加载（>100 条规则，≥2 个 severity 等级）；若该文件未在本地生成，则**测试跳过** |
| `sql_semantic_with_normalisation_catches_doubled_encoded` | `sql_semantic` | 双重 URL 编码的 SQLi（`%2527...`）累计出高分 |

运行：

```bash
cargo test --test arsenal_integration
```

> 关于 `sigma_imported_toml_*` 的说明：`rules/sigma/sigma-webserver.toml` 是生成产物（见二进制 `aegis-sigma-import`）。如果它不存在，测试会干净地 `return` 并被算作通过，实际上什么都没检查。要让该测试真正验证些什么，需要事先生成语料。

---

## 5. E2E 二进制

E2E harness 被做成 `src/bin/` 下独立的二进制，而不是 `#[test]` 函数，因为它们会 spawn 真实的 AEGIS 进程，和/或需要对主机做网络配置。需要先构建它们（通常用 `--release`），然后运行。

### 5.1. `aegis-e2e` —— 压测 harness（hyper 二进制）

`src/bin/aegis-e2e.rs` 会针对 mock upstream spawn 一个**真实的 `aegis` 进程**，并跑遍每一个主要关卡，同时检查 (a) 可观察到的 HTTP 状态码与 (b) 从 `/metrics` 抓取的 `aegis_*` 计数器增量。指标发射悄然停止，会像 WAF 规则放过攻击一样，同样响亮地让构建失败。它面向 CI 设计：耗时有限（约 30 秒）、全部在 `127.0.0.1` 上、无外部依赖（没有 Redis/GeoIP）、不会因时序而 flaky。

参数（`clap`）：

| 标志 | 默认值 | 用途 |
|------|--------------|------------|
| `--aegis-binary` | `target/release/aegis` | 被测二进制的路径 |
| `--config-template` | `bench/e2e-config.toml` | 带占位符的配置模板 |
| `--startup-timeout-secs` | `10` | 等待 AEGIS 就绪的时间 |
| `--dump-metrics` | （标志） | 即使成功也打印完整的 `/metrics` |

配置模板 `bench/e2e-config.toml` 会被即时打补丁：`__AEGIS_LISTEN__`、`__ADMIN_LISTEN__`、`__UPSTREAM_URL__`。其中 WAF 与 rate-limit 已启用（`requests_per_second = 5`、`burst = 5`、`max_body_bytes = 4096`），而 challenge/bot/adaptive 被关闭，以免 WAF 与 rate-limit 场景被无关的升级动作截获；`header_read_timeout_ms = 1000` 是 Slowloris 场景所需。管理 token 通过 `AEGIS_ADMIN_TOKEN=e2e-admin-token` 传入。

被验证的场景（摘自 `run_scenarios`）：

1. `baseline_passthrough` —— ≥3 个 `200` 响应，upstream 收到 ≥3 次命中；
2. `waf_sqli_query_blocked` —— query 中的 SQLi 得到 5×`403`；
3. `waf_xss_query_blocked` —— query 中的 XSS 得到 5×`403`；
4. `waf_body_sqli_blocked` —— POST 体中的 SQLi → `403`；
5. `waf_body_size_413` —— 限制 4 KB 时的 16 KB 请求体 → `413`；
6. `ip_acl_loaded_without_self_lock` —— 已加载 deny `198.51.100.99`，但 `127.0.0.1` 未被阻断；
7. `rate_limit_burst` —— 50 个并行请求中 ≥10 个收到 `429`；
8. `slowloris_connection_killed` —— 未写完的请求在 `header_read_timeout` 之内被切断；
9. `admin_unauth_rejected` —— 错误的 `x-admin-token` → `401`；
10. `admin_authorized_passes` —— 正确的 token → `200`；
11. `admin_read_endpoints_alive` —— `/admin/threats`、`/admin/xdp`、`/admin/hot_uris`、`/admin/anomaly` 返回 `200`；
12. 指标回归 —— 增量 `aegis_requests_total > 0`、`aegis_requests_denied > 0`，存在 `aegis_request_latency_ms_count` 以及 `aegis_requests_by_protocol` 系列。

运行（如同 CI job `e2e-load`）：

```bash
cargo build --release --bin aegis --bin aegis-e2e
./target/release/aegis-e2e \
    --aegis-binary ./target/release/aegis \
    --config-template bench/e2e-config.toml \
    --dump-metrics
```

非零退出码意味着至少有一个场景失败（列表打印在 `=== scenario results ===` 中并标注 `FAIL`）。

### 5.2. `aegis-pingora-e2e` —— pingora data plane 的冒烟测试

`src/bin/aegis-pingora-e2e.rs`（V64）在形式上是 `aegis-e2e` 的镜像，但瞄准 `aegis-pingora` 二进制的 openssl 后端。整个文件位于 `#![cfg(feature = "pingora")]` 之下。它针对 in-process 的 mock upstream spawn 真实的 `aegis-pingora`，并写出一份类 nginx DSL 格式的临时配置（块 `admin { ... }`、`defaults { ... }`、`server { ... }`），honeypot 状态路径通过 `AEGIS_HONEYPOT_STATE` 传入，响应缓存通过 `AEGIS_RESPONSE_CACHE_ENABLE=1` 开启。

参数：`--binary`（默认 `target/release/aegis-pingora`）、`--aegis-port`/`--admin-port`/`--upstream-port`、`--admin-token`、`--startup-secs`。

测试（`run_tests`）：

| № | 检查 |
|---|----------|
| 1 | 普通 GET → `200`，响应体包含 `ok` |
| 2 | WAF path-traversal `/../../etc/passwd` → `403`，响应体包含 `blocked` |
| 3 | `/metrics` 是公开的（`200`）且包含 `aegis_requests_total` |
| 4 | 无 token 的 `/admin/cache` → `401` |
| 5 | token 错误的 `/admin/cache` → `401` |
| 6 | token 正确的 `/admin/cache` → `200`，响应体包含 `cache_hits` |
| 7 | `/health` → `200`，响应体以 `ok` 开头 |
| 8 | 两个相同的 GET → 计数器 `aegis_cache_hits`/`aegis_cache_misses` 非零 |
| 9 | 带 token 的 `POST /admin/cache/purge?all=1` → `200` |
| 10 | 配置有效时的 `POST /admin/api/config/test` → `ok:true` |
| 11 | 配置损坏时的 `POST /admin/api/config/test` → `ok:false` |
| 12 | JSON 损坏时的 `POST /admin/api/sites` → `400` |
| 13 | `POST /admin/api/honeypots/packs/wordpress {"enabled":false}` → `200`，`ok:true` |

运行（见文件头部）：

```bash
cargo build --release --features pingora --bin aegis-pingora
cargo build --release --features pingora --bin aegis-pingora-e2e
./target/release/aegis-pingora-e2e
```

成功时打印 `PASS: aegis-pingora end-to-end smoke green`；失败时打印 `FAIL: ...` 并 `exit(1)`。

### 5.3. `aegis-sqlmap-replay` —— WAF 绕过矩阵

`src/bin/aegis-sqlmap-replay.rs`（V118）：操作员把该工具指向运行中的 AEGIS（或任意 URL），它会以原始形式跑一遍 SQLi 载荷，并在每一个等价于 sqlmap 的 tamper 之后再跑一遍，打印出覆盖矩阵。标注 `! BYPASSED` 的行就是 WAF 的缺口：该 tamper 变体返回了非 `403` 的状态。这**不是**对 sqlmap 的完整移植；实现的是 sqlmap `tamper/` 目录中约 12–15 个最常用的 tamper。

参数：`--target`（默认 `http://127.0.0.1/`；载荷以 `?q=<payload>` 追加）、`--payload`（默认 `union select 1,2,3 from users`）、`--chain`（以逗号分隔的 tamper 列表，叠加在每次迭代之上 —— 类似 sqlmap 的 `--tamper`）、`--timeout-secs`。

已实现的 tamper（数组 `tampers`）：`space2comment`、`space2morecomments`、`space2dash`、`space2hash`、`space2plus`、`randomcase`、`backticks`、`htmlencode_dec`、`htmlencode_hex`、`charencode`、`chardoubleencode`、`versionedkeywords`、`appendnullbyte`、`equaltolike`、`apostrophenullencode`。

判定逻辑：`403` → `OK`；任何其他状态 → `! BYPASSED`；请求出错 → `! ERROR`。只要存在至少一个 bypass，进程就以 `exit(2)` 结束。

```bash
cargo build --release --bin aegis-sqlmap-replay
./target/release/aegis-sqlmap-replay --target http://127.0.0.1:8080/

# 带 tamper 链（类似 sqlmap --tamper）
./target/release/aegis-sqlmap-replay \
    --target http://127.0.0.1:8080/ \
    --chain space2comment,htmlencode_hex,backticks
```

> 这是检查**已部署**实例的工具，而不是单元测试。它展示的是它所指向的那份 WAF 配置的真实覆盖情况。见 [10-waf.md](10-waf.md)。

### 5.4. `aegis-distbench` —— 分布式攻击模拟器

`src/bin/aegis-distbench.rs`（V105）：pingora 监听器从 `accept()` 看到 peer 地址，即连接的 source IP。通过把 loopback 别名成 `127.0.0.2 .. 127.0.0.{N+1}` 并把每个连接绑定到各自的别名，就能在监听器不支持 PROXY 协议的情况下，模拟 N 个攻击者对单个 AEGIS 的攻击。每个「来源」都有自己的 hyper 客户端，其 `HttpConnector` 会把出向 TCP 绑定到自己的 IP（`set_local_address`）—— 正是这一点让 AEGIS 的 per-IP 打分器看到不同的攻击者。

参数：`--target`（必填）、`--sources`（默认 50）、`--requests-per-source`（200）、`--concurrency-per-source`（4）、`--path`（默认 `/?q=union+select+1` —— 若 WAF 启用则会命中它）、`--timeout-secs`（60）。输出：总 RPS、状态分布（`200`/`403`/errors）、接收的字节数。

在 Linux 上的前置条件 —— 预先创建别名：

```bash
for i in $(seq 2 51); do sudo ip addr add 127.0.0.$i/8 dev lo; done

cargo build --release --bin aegis-distbench
./target/release/aegis-distbench \
    --target http://127.0.0.1:8080/ \
    --sources 50 --requests-per-source 200 --concurrency-per-source 4
```

> 这是用于检验跨 worker 聚合与 per-IP 打分的压测/行为平台（文件头部建议在跑完之后看一下 `/admin/threats`），而不是 pass/fail 测试。关于压测方法论与容量方面如实说明的更多内容 —— 见 [28-benchmarking.md](28-benchmarking.md)。

---

## 6. 各子系统的覆盖率

单元测试在 `src/` 各模块上的分布（快照；按 `#[test]`/`#[tokio::test]` 统计）。覆盖最密集的是热路径关卡和解析器：

| 子系统 / 文件 | ≈ 测试数 | 文档 |
|-------------------|----------|----------|
| `src/filters/waf.rs` | ~78 | [10-waf.md](10-waf.md) |
| `src/proxy/response_cache.rs` | ~47 | [27-performance-tuning.md](27-performance-tuning.md) |
| `src/ml_adversarial.rs` | ~40 | [18-ml-risk-engine.md](18-ml-risk-engine.md) |
| `src/challenge_signals.rs` | ~40 | [15-challenge-ladder.md](15-challenge-ladder.md) |
| `src/domain_policy.rs` | ~29 | [26-sites-and-domains.md](26-sites-and-domains.md) |
| `src/real_ip.rs` | ~28 | [07-protocols.md](07-protocols.md) |
| `src/proxy/pingora_challenge.rs` | ~28（在 `pingora` 下） | [15-challenge-ladder.md](15-challenge-ladder.md) |
| `src/proxy/pingora_http.rs` | ~26（在 `pingora` 下） | [02-architecture.md](02-architecture.md) |
| `src/proxy/http.rs` | ~25 | [02-architecture.md](02-architecture.md) |
| `src/sql_semantic.rs` | ~23 | [10-waf.md](10-waf.md) |
| `src/filters/login_abuse.rs` | ~23 | [14-rate-limiting.md](14-rate-limiting.md) |
| `src/filters/graphql.rs` | ~23 | [10-waf.md](10-waf.md) |
| `src/sigma.rs` | ~20 | [10-waf.md](10-waf.md) |
| `src/client_consistency.rs` | ~20 | [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| `src/site_map.rs` | ~18 | [26-sites-and-domains.md](26-sites-and-domains.md) |
| `src/privacy_pass.rs` | ~18 | [16-privacy-pass.md](16-privacy-pass.md) |
| `src/poisoned_tarpit.rs` | ~18 | [17-honeypot-tarpit.md](17-honeypot-tarpit.md) |
| `src/p0f.rs` | ~17 | [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| `src/normalisation.rs` | ~17 | [10-waf.md](10-waf.md) |
| `src/honeypot/matcher.rs` | ~17 | [17-honeypot-tarpit.md](17-honeypot-tarpit.md) |

按大的模块族做的汇总（按测试名子串搜索，便于 `cargo test --lib <子串>`）：

| 族（模式） | ≈ 测试数 |
|---------------------|----------|
| `filters`（整个 `src/filters/` 目录） | ~240 |
| `ml`（ML risk engine + adversarial） | ~105 |
| `waf`（按名称子串） | ~86 |
| `challenge`（阶梯 + 信号） | ~79 |
| `ja4`（指纹） | ~48 |
| `reputation` | ~25 |
| `rate_limit` | ~15 |
| `ja3` | ~6 |

> 这些数字是近似快照，会随改动而波动。获取某个子系统当前数字的权威方式是 `cargo test --lib <模式> -- --list`。

单元测试层次之外的覆盖：

- **未被自动化测试以严格 pass/fail 方式覆盖：** 负载下的 XDP/eBPF 内核 fast-path（`--features xdp` 的测试检查的是编译与 loader 的逻辑，而不是真实的 BPF 挂载 —— 那需要特权和网卡）、经由真实 ExaBGP 的 BGP RTBH（`arsenal_integration` 中只检查内存中的 announce/withdraw）、外部集成（Redis rate-limit、CrowdSec LAPI、threat-intel、GeoIP 数据库）—— e2e harness 有意在不依赖它们的情况下工作。
- **仅通过已部署实例覆盖（opt-in 工具）：** WAF 对绕过的真实抵抗力（`aegis-sqlmap-replay`）、分布式负载下的跨 worker 聚合（`aegis-distbench`）。

---

## 7. 如何添加测试

### 7.1. 单元测试（首选路径）

把测试放在代码旁边，即同一个 `src/...` 文件末尾的 inline 模块中：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_name_states_the_invariant() {
        let out = my_function("input");
        assert_eq!(out, expected);
    }

    // 对于 async 代码：
    #[tokio::test]
    async fn async_path_holds() {
        let r = my_async_fn().await;
        assert!(r.is_ok());
    }
}
```

代码中可见的约定：
- 测试名描述所检查的不变式（例如 `sqli_signature_blocks_before_upstream`、`ja4_churn_observe_tracks_ip`）；
- 测试不应要求外部服务；文件状态请使用带唯一后缀的 `std::env::temp_dir()`（见 `tests/integration.rs` 中的 `TEST_HONEYPOT_SEQ` + `std::process::id()`）；
- 用 `#[cfg(feature = "pingora")]` / `#[cfg(feature = "xdp")]` 标注特性专有代码，以免默认构建被破坏；
- 记住 CI 中的 `RUSTFLAGS=-D warnings`：未使用的导入/变量会让运行失败（代码中可见诸如 `let _ = challenged_delta;` 这样的规避写法）。

### 7.2. 流水线的集成测试

在 `tests/integration.rs` 中添加 `#[tokio::test]`，复用 `spawn_mock_upstream` 与 `build_handler`。必要时给 `build_handler` 的签名增加新参数，以启用被测的关卡。既要对 HTTP 状态码断言，也要对副作用断言（upstream 命中次数、`Set-Cookie`/`x-aegis-step` 头）。

### 7.3. Arsenal 接线测试

对于新的 Defence Arsenal 模块，请在 `tests/arsenal_integration.rs` 中添加一个 `#[test]`，通过 `ArsenalState::new_default()` 调用其 API，并检查 `counters.snapshot()` 中相应字段发生了变化。这是对「死状态」的保险（见文件头部）。

### 7.4. 新的 e2e 场景

在 `aegis-e2e` 中，通过辅助函数 `record(&mut scenario_results, "名称", &report, &mut failures, |r| {...})` 添加场景，返回 `Ok(info)`/`Err(msg)`。检查指标请使用 `delta(&baseline, &after, "aegis_<名称>")`。在 `aegis-pingora-e2e` 中，请在 `run_tests` 里添加检查，使用辅助函数 `http_get`/`http_get_with_token`/`http_with_body_and_token`，并在不匹配时 `bail!`。

### 7.5. 提交之前

在本地复现 CI：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
# 改动 pingora/xdp 路径时：
cargo test --features pingora --all-targets
cargo check --features xdp --all-targets
```

---

## 8. 命令速查表

```bash
# 快速开发循环
cargo test --lib <子串>            # 单个子系统
cargo test --lib <子串> -- --list  # 会运行什么
cargo test --lib -- --nocapture    # 查看测试输出

# 完整的本地检查（与 CI 一致）
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --features pingora --all-targets

# E2E
cargo build --release --bin aegis --bin aegis-e2e && \
    ./target/release/aegis-e2e --dump-metrics
cargo build --release --features pingora --bin aegis-pingora --bin aegis-pingora-e2e && \
    ./target/release/aegis-pingora-e2e
cargo build --release --bin aegis-sqlmap-replay && \
    ./target/release/aegis-sqlmap-replay --target http://127.0.0.1:8080/
cargo build --release --bin aegis-distbench && \
    ./target/release/aegis-distbench --target http://127.0.0.1:8080/ --sources 50
```
