# FAQ 与故障排查

**语言：** [English](../en/47-faq-troubleshooting.md) · [Русский](../ru/47-faq-troubleshooting.md) · **中文**

关于 AEGIS 典型故障及其排除方法的实用参考。每一节都对应到实际代码（`install.sh`、`src/xdp.rs`、`src/proxy/pingora_tls.rs`、`src/bin/aegis-pingora.rs`、`src/web_admin.rs`、`src/main.rs`）—— 不作猜测；部分生效和 opt-in 的行为都会显式标注。

> 有用的相邻文档：[03-installation.md](03-installation.md)、[06-workers.md](06-workers.md)、[07-protocols.md](07-protocols.md)、[08-tls-certificates.md](08-tls-certificates.md)、[11-tls-fingerprinting.md](11-tls-fingerprinting.md)、[13-xdp-ebpf.md](13-xdp-ebpf.md)、[24-request-log.md](24-request-log.md)、[25-metrics-telemetry.md](25-metrics-telemetry.md)、[29-admin-panel.md](29-admin-panel.md)、[30-admin-api.md](30-admin-api.md)。

---

## 0. 快速诊断：从哪里开始

在深入具体症状之前，先收集基础状态。以下三条命令覆盖 90% 的事故：

```bash
# 1. data plane 的 worker 是否存活（pingora 模式）？
systemctl status aegis-pingora.target
systemctl list-units 'aegis-pingora@*.service' --no-legend

# 2. 所有 worker 的最新日志（journald 是该服务唯一的日志汇）
journalctl -u aegis-pingora.target -n 80 --no-pager

# 3. 谁占用着特权端口？
ss -tlnp | grep -E ':80|:443|:6280'
ss -ulnp | grep ':443'      # HTTP/3 走的是 UDP
```

在 hyper 模式（`--mode hyper`）下服务名为 `aegis`（而不是 `aegis-pingora.target`），并且没有 XDP/HTTP-3 —— 参见 [06-workers.md](06-workers.md)。

工作路径一览（默认值取自 `install.sh`）：

| 用途 | 路径 | 安装器变量 |
|---|---|---|
| 配置 | `/etc/aegis/aegis.conf` | `AEGIS_ETC` |
| 服务的 Env | `/etc/aegis/aegis.env` | — |
| 功能开关的 Env（面板） | `/var/lib/aegis/aegis-ui.env` | `AEGIS_HOME` |
| Admin 令牌 | `/etc/aegis/admin-token` | — |
| Web 管理员状态 | `/var/lib/aegis/web.json` | `web_state_path` |
| eBPF 对象文件 | `/var/lib/aegis/aegis-xdp.o` | `AEGIS_XDP_OBJ` |
| GeoIP / 信誉 | `/var/lib/aegis/geoip`、`/var/lib/aegis/reputation` | — |
| 审计日志 | `/var/log/aegis/audit.log` | `AEGIS_LOG_DIR` |

---

## 1. XDP 无法加载 (capabilities / 内核)

XDP 是内核 fast-path，**仅**在 pingora 模式下可用，且**仅**在 Linux 上、构建时启用了 `xdp` feature 才可用（`src/xdp.rs:131-143`）。在其他任何平台上、或未启用该 feature 时，`load()` 会返回 `NoopXdp` 并打印：

```
XDP fast-path not available on this build (need target_os=linux + `xdp` feature)
```

### 1.1. 安装器在什么情况下根本不启用 XDP

`resolve_xdp_enable()`（`install.sh:131-154`）在两种情况下自动关闭 XDP：

- `--mode hyper` → `AEGIS_ENABLE_XDP=0`（「data plane is hyper-only」）；
- 内核低于 **4.18** → 关闭并给出警告 `linux <ver> < 4.18 — XDP disabled (need ≥ 4.18 for aya)`。

检查内核：

```bash
uname -r          # 需要 >= 4.18
```

强制开启/关闭：使用 `--xdp` / `--no-xdp` 标志或变量 `AEGIS_ENABLE_XDP=1|0|auto`。

### 1.2. 缺少 eBPF 构建依赖

当 `AEGIS_ENABLE_XDP=1` 时，安装器（`install.sh:296-318`）会安装 **rust nightly + rust-src** 和 `bpf-linker`。症状与原因：

| 构建日志中的症状 | 原因 | 解决办法 |
|---|---|---|
| `bpf-linker install failed — eBPF build will fail; retry with --no-xdp` | `bpf-linker` 未能构建 | 手动安装 `cargo install bpf-linker --locked`，或改用 `--no-xdp` 安装 |
| `eBPF build did not produce …/aegis-xdp` | `xdp/aegis-xdp-ebpf` 的构建失败 | 检查 nightly + `rust-src`、clang/llvm |
| release 构建失败并提示 `is `cmake` not installed?` | 缺少 cmake（传递依赖） | `install_packages()` 会安装 cmake；在「unknown」包管理器上请手动安装 |

eBPF 对象由独立的工作区 `xdp/aegis-xdp-ebpf` 在 `bpfel-unknown-none` 目标下构建（`install.sh:469-484`）。

### 1.3. 权限不足 (capabilities)

这是「XDP 在运行时加载不了」的主要原因。权限在两个地方授予：

1. **二进制上的 file-capability**（`install.sh:463-465`）：
   ```
   setcap 'cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep' /usr/local/bin/aegis-pingora
   ```
   如果 `setcap` 失败，日志中会出现：`setcap failed; pingora workers will need to run as root for :80/:443`。

2. **systemd unit 中的 capabilities**（`write_systemd_unit_pingora`，`install.sh:1223-1232`）。启用 XDP 时该集合会扩展：
   ```
   AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON
   CapabilityBoundingSet=<同上>
   RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
   ```

> **6.x 内核的重要细节。** 没有 `CAP_PERFMON` 时（即便已有 `CAP_BPF`），验证器会以 **EACCES (os error 13)** 拒绝 `BPF_PROG_LOAD`，因为涉及指针/`packet-data` 的操作被藏在 `perfmon_capable()` 之后（`install.sh:1224-1228` 中的注释）。如果日志中在加载程序时出现 `EACCES`/`os error 13` —— 请检查 unit 中是否包含 `CAP_PERFMON`，以及 `RestrictAddressFamilies` 中是否有 `AF_NETLINK`（attach 是通过 rtnetlink 完成的）。

unit 中的 `LimitMEMLOCK=infinity`（`install.sh:1266`）是为了让 BPF map 和 locked-ring 缓冲区能够超出默认的 64 KiB rlimit。没有它，map 可能无法分配。

修改 unit 之后：

```bash
systemctl daemon-reload && systemctl restart aegis-pingora.target
```

### 1.4. «xdp-already-owned-by-sibling-worker» —— 这不是错误

一块 NIC 只能承载**恰好一个** XDP 程序。在 `N` 个 SO_REUSEPORT worker 的情况下，只有一个能赢得 attach，其余会得到 `EEXIST`（`os error 17`，「File exists」）。代码识别了这一点（`src/xdp.rs:163-178, 231-245`）并返回哨兵值 `XDP_ALREADY_OWNED_MARKER`（`src/xdp.rs:17`），调用方会把它记为**信息性**状况：拥有者 worker 在 NIC 上对全部流量强制执行 deny/allow map，其余 worker 在用户态过滤。兄弟 worker 日志中出现 `xdp-already-owned-by-sibling-worker` 属于正常现象，不是故障。

### 1.5. Native (DRV) 与 SKB (generic) 模式

Loader 先尝试 native attach，失败时回退到 SKB 模式（`src/xdp.rs:218-252`）：

```
XDP native attach failed, retrying in SKB (generic) mode
XDP attached in SKB mode
```

SKB 模式更慢（数据包在分配 `sk_buff` 之后被重新注入），但可以在任何 NIC 上工作，包括 hypervisor 下的 `virtio-net`。在没有原生 XDP 支持的云 VM 上这是预期行为。如果在**两种**模式下都无法 attach：

```
failed to attach XDP program to <iface> (tried both DRV and SKB modes): <err>
```

—— 请检查接口名称（`AEGIS_XDP_IFACE`，自动探测规则为「第一个非 lo 且 UP 的接口」，`install.sh:193-209`）。

### 1.6. 验证 XDP 确实在工作

XDP 计数器由 PerCpu map 汇总而来（`src/xdp.rs:373-392`）：`pass`、`drop_deny`、`drop_rate`、`drop_allowonly`、`drop_syn`、`drop_waf`、`fast_pass`。它们可通过 `/metrics` 和面板查看（参见 [13-xdp-ebpf.md](13-xdp-ebpf.md)、[25-metrics-telemetry.md](25-metrics-telemetry.md)）。拥有者 worker 上不断增长的 `pass`/`drop_*` 就证明它在工作。

---

## 2. HTTP/3 (QUIC) 无法绑定

AEGIS 中的 HTTP/3 是一个基于 hyper 的 `ProxyHttpHandler`，运行在独立线程中的独立 tokio runtime 上（`maybe_spawn_h3`，`src/bin/aegis-pingora.rs:1585-1612, 2304+`），因为 pingora 目前只支持 h1/h2。监听地址取自 `tls.h3_listen`（默认与 `tls.listen` 相同）。

### 2.1. «HTTP/3 not started by this worker» —— 通常是正常现象

该消息处于 **info** 级别，而非 warn：

```
aegis-pingora: HTTP/3 not started by this worker
  (served by a sibling worker under REUSEPORT, or h3 disabled/misconfigured)
```

原因（`src/bin/aegis-pingora.rs:1600-1611`）：quinn 的 QUIC socket **没有 SO_REUSEPORT**，因此在多 worker 布局下只有**第一个**成功绑定 `:443/udp` 的 worker 提供 HTTP/3 服务；兄弟 worker 会得到 `AddrInUse` 并走到这里。这是预期且无害的 —— TCP 之上的 h1/h2 不受影响。只有当 `tls.enabled && tls.h3_enabled` 时才会启用 h3（`src/bin/aegis-pingora.rs:2316`）。

### 2.2. 什么时候才是真正的问题

如果 HTTP/3 在**任何一个** worker 上都不工作，请在 info 日志中查找 `error = ...` 之后被包装的原因：

- `invalid h3_listen <str>` —— 无法解析的地址（`src/bin/aegis-pingora.rs:2319-2322`）；
- 证书错误 —— h3 需要有效的 TLS 配置；
- `:443/udp` 端口被防火墙封锁。

安装器会单独开放 UDP（`install.sh:1364`，`ufw allow 443/udp comment 'aegis h3 quic'`；firewalld 则是 `--add-port=443/udp`）。检查：

```bash
ss -ulnp | grep ':443'                 # 应当恰好只有一个 worker 在监听
journalctl -u aegis-pingora.target | grep -i h3
```

在站点的 `listen` 指令中，h3 通过 `http3` 令牌启用（参见默认的 `server { listen 443 ssl http2 http3 default_server; }`，`install.sh:1097`）。细节见 [07-protocols.md](07-protocols.md)。

---

## 3. WAF 误报

WAF 默认开启（`defaults { filters { waf on; } }`，`install.sh:1075`）。引擎由基于签名的 Aho-Corasick + Sigma 语料 + compound 规则 + webshell 检测器构成（参见 [10-waf.md](10-waf.md)）。误报的典型排查流程：

1. **确定是哪条规则。** 在请求日志（[24-request-log.md](24-request-log.md)）以及 `audit_log_path`（`/var/log/aegis/audit.log`）中，被拦截请求会显示触发的签名/Sigma 标识符。
2. **缩小范围。** Per-domain policy 与 site_map 允许针对特定 host/路径放宽 WAF（[26-sites-and-domains.md](26-sites-and-domains.md)），而不影响其他站点。
3. **临时性的全局措施。** 通过面板的功能开关关闭该 filter（`PUT /admin/api/env`，写入 `/var/lib/aegis/aegis-ui.env`），或者修改 `defaults { filters { waf off; } }`。这是最后手段 —— 会把防护整体关掉。

> **功能开关的覆盖值存放在哪里。** 面板会把开关写入**独立的**可写文件 `$AEGIS_HOME/aegis-ui.env`，它通过 systemd drop-in（`install.sh:544-575`）在只读的 `/etc/aegis/aegis.env` **之后**被加载，因此面板中的值会覆盖运维人员的默认值。这是有意为之：`ProtectSystem=strict` + `ReadOnlyPaths=$AEGIS_ETC` 意味着被攻陷的守护进程**无法**改写自己的配置/证书/令牌。改动通过重启生效：`systemctl restart aegis-pingora.target`。

同样可能拦截合法流量、并可用同样方式排查的相邻 filter：`bot_fingerprint`、`adaptive_spike_detection`（`install.sh:1076-1077`）、rate-limit（[14-rate-limiting.md](14-rate-limiting.md)）、ML risk engine（[18-ml-risk-engine.md](18-ml-risk-engine.md)，它有一个 `Observe` 模式可在不拦截的情况下做标定）、信誉（[12-reputation.md](12-reputation.md)）。

---

## 4. 登录面板后白屏 (`email.split`)

**症状：** 登录成功后管理面板立即显示白屏 / 顶栏崩溃。

**原因（RC4，`src/proxy/pingora_admin.rs:4386-4393`）：** 登录响应此前**不包含 `email` 字段**，因此 SPA 的 auth 状态拿到的是 `email=undefined`，顶栏在 `email.split(...)` 处崩溃。已修复：`POST /admin/api/login` 现在会在响应体中把刚刚通过认证的 email 回传：

```json
{
  "ok": true, "token": "...", "email": "<输入的 email>",
  "must_change_credentials": <bool>, "must_change": <bool>,
  "set_cookie": "aegis_admin_session=...; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400"
}
```

**如果症状依然存在：**

- 你运行的是过时的二进制/前端。请更新：`sudo bash install.sh --update`（会重新构建内嵌进二进制的前端 `web/dist`，`install.sh:382-396`），然后在浏览器中强制刷新（Ctrl-Shift-R）以清掉 SPA 缓存。
- 确认 `GET /admin/api/me` 返回了 `email`（`src/proxy/pingora_admin.rs:4434-4494`）。对于令牌认证，`me` 会返回一个合成的 `email: "token-<Role>"` —— 这是正常的。

相关细节：`must_change_credentials` **和** `must_change` 两个字段是有意重复的（`src/proxy/pingora_admin.rs:4389-4395`），因为客户端读取 `must_change` 来触发强制修改凭据的流程。

---

## 5. 首次登录时强制修改凭据

**这是设计如此，不是 bug。** 首次运行时安装器会调用 `aegis web reset-admin`（`seed_web_admin`，`install.sh:1133-1162`），创建一个使用随机密码且带 **`must_change = true`** 的账号（`src/web_admin.rs:82, 127, 277-282`）。首次登录时，面板会在做任何其他事情之前**强制同时修改 email 和密码**（`src/main.rs:119-120`）：

```
Log in once with these credentials — the panel will force you to
change both email and password before anything else.
```

修改凭据（`change_credentials`，`src/web_admin.rs:234-262`）会把 `must_change` 重置为 `false`，并**使其余所有会话失效**。此后再次运行安装器**不会**重新生成密码：如果 `web.json` 中存在 `"must_change":false`，`seed_web_admin` 会跳过该步骤（`install.sh:1139-1143`），并打印 `web admin already initialised — preserving operator's credentials`。

如果强制修改流程无法完成（例如遇到第 4 节的白屏问题）—— 请先更新并重置凭据（第 9 节），然后重新登录。

---

## 6. 构建缓慢

构建是**在部署主机上**进行的（`install.sh:406-419`），因此它会针对该 CPU 做优化。可调的杠杆：

| 项目 | 位置 | 效果 |
|---|---|---|
| 默认 profile | `Cargo.toml` | thin-LTO、`codegen-units=16`、incremental —— **快速**的并行构建（`install.sh:507-509`） |
| `AEGIS_BUILD_OPT=max` | env | fat-LTO + `codegen-units=1` + 非 incremental —— 二进制最快，但构建**很慢**且几乎是单线程的（`install.sh:502-506`）；仅用于发布，不用于日常 `--update` |
| `mold` 链接器 | 自动、best-effort | 对最终的大二进制做多线程链接（`install.sh:270-277, 420-435`）；日志中为 `mold linker available — parallel linking enabled` |
| `AEGIS_TARGET_CPU` | env | `native`（默认，对本机最优）/ `generic`（可移植）/ 具体的微架构（`install.sh:419-435`） |

注释中给出的参考值：`aegis`（hyper+CLI）首次构建约 3-5 分钟（`install.sh:438`），`aegis-pingora` 约 5-8 分钟（`install.sh:448`）。XDP 会额外引入 nightly toolchain + `bpf-linker`（链接器首次约 1-2 分钟）。如果构建时间意外地长 —— 请确认没有误设 `AEGIS_BUILD_OPT=max`，并确认 `mold` 已安装成功。

建议：日常 `--update` 保持默认 profile；`AEGIS_BUILD_OPT=max` 只在真正切发行版时使用。

---

## 7. nginx (或其他代理) 占用了 :80

**症状：** 服务无法启动 / 在 `:80`、`:443` 或 `:6280` 上出现 `AddrInUse`。

安装器会在启动前对此发出警告（`detect_port_conflict`，`install.sh:1376-1389`）：

```
port 80 is already bound by <owner> — aegis will fail to start. Stop it first:
  systemctl stop nginx 2>/dev/null; systemctl stop apache2 2>/dev/null
```

查找并释放端口：

```bash
ss -tlnp | grep -E ':80|:443|:6280'
systemctl stop nginx;  systemctl disable nginx
systemctl stop apache2; systemctl disable apache2
systemctl restart aegis-pingora.target
```

> **关于基准测试用代理的细节。** 安装器会有意安装 nginx/HAProxy/Caddy/Envoy/ModSecurity 以便做「vs nginx」的对比基准测试，但随即将它们 **disable+stop（Caddy 甚至 mask）**，以免它们占住 `:80/:443` —— 这些端口归 AEGIS 所有（`ensure_nginx_for_benchmark` 及其相邻函数，`install.sh:582-761`）。基准测试会以临时配置在 loopback 端口上按需启动它们的二进制。如果安装后又有东西占用了 `:80` —— 请检查是否有人把这些 unit 重新启用了（`systemctl is-enabled nginx caddy haproxy`）。

可以通过安装器变量 `AEGIS_PORT_HTTP` / `AEGIS_PORT_HTTPS` / `AEGIS_PORT_ADMIN`（`install.sh:47-49`）或修改配置中的 `listen` 来更改 AEGIS 的端口。参见 [03-installation.md](03-installation.md)。

---

## 8. JA4/JA3 为空 (指纹识别门控 / 在 ClientHello 中捕获)

### 8.1. 捕获必须发生在 ClientHello 回调中

JA3/JA4 在 `capture_client_hello`（`src/proxy/pingora_tls.rs:736-855`）中计算，该函数**必须**从 OpenSSL 的 **ClientHello 回调**中调用（在 `aegis-pingora.rs` 中通过 `set_client_hello_callback` 注册）。这是握手中**唯一**一个 `SSL_client_hello_*` 访问器能返回客户端所提议的密码套件与扩展的阶段。

> **历史症状（V246）：** 如果指纹是在 `certificate_callback`（OpenSSL 较晚的 cert_cb）中计算的，访问器会返回空值，于是**每个**客户端都得到一个退化的、完全相同的 JA4 `t12i000000_e3b0c44298fc`（`src/proxy/pingora_tls.rs:740-742`）。如果你看到所有客户端都是这个退化指纹 —— 说明你的构建早于该修复；请更新（`--update`）。

计算好的指纹会被放入 SSL `ex_data`；`handshake_complete_callback` 将其发布到 session digest，而 `read_fingerprints` 再把它读回 `ctx.ja3` / `ctx.ja4`（`src/proxy/pingora_tls.rs:742-744`）。

### 8.2. 指纹识别门控 (LEVER 1) —— JA4 为空的主要原因

为了避免在**没有任何消费者**使用指纹时，仍在每次握手上花费 MD5 + 2×SHA-256 + 约 18-22 次堆分配，存在一个门控 `fingerprinting_enabled`（`src/proxy/pingora_tls.rs:138-155, 753-770`）。当它为 `false` 时，`capture_client_hello` 会放入一个**所有字段均为 `None`** 的 `TlsFingerprints`（JA3/JA4 将为空）并直接返回。该门控默认为 **ON**（`src/proxy/pingora_tls.rs:414-417`）。

只要存在至少一个消费者，门控就会自动保持开启（`src/proxy/pingora_tls.rs:142-152`）：

- 配置了 `ja3_deny_hashes` / `ja4_deny_prefixes`；
- 启用了 Defence Arsenal（`ja4_corpus`、`ja4_churn`、GREASE 评分）；
- `ja4_reputation` 数据源处于活动状态；
- 存在带 `field:"ja3"`/`field:"ja4"` 的 WAF 规则（内联规则在启动时会被扫描；外部 `rule_files` 则**强制**门控为 ON，参见 `src/proxy/pingora_tls.rs:147-152`）。

**如果 JA4 为空：**

1. 检查运维人员是否通过 `AEGIS_TLS_FINGERPRINT=0` 显式关闭了指纹识别（`src/proxy/pingora_tls.rs:152`）。但请注意：如果检测到消费者，二进制会**覆盖**显式的 `AEGIS_TLS_FINGERPRINT=0` 并给出警告（`src/bin/aegis-pingora.rs:1864-1889`）：
   ```
   aegis-pingora: AEGIS_TLS_FINGERPRINT=0 OVERRIDDEN — a consumer was detected …
   ```
   如果没有消费者、而你又确实需要强制门控 —— 请移除 `AEGIS_TLS_FINGERPRINT=0` 并重启。
2. 通过面板/`/admin/api/env` 检查该标志的当前状态（`tls_fingerprinting`，`src/proxy/pingora_admin.rs:122, 2849`）。
3. 对于不使用 TLS 的客户端（普通 HTTP）不会出现 JA4 —— 对 no-cert/no-TLS 客户端指纹仍为 `None`。

> **JA4T (TCP/SYN) 是另一回事。** JA4T 的 SYN 捕获存放在 XDP map 中（`read_ja4t_v4`，`src/xdp.rs:52-64, 394-411`），仅在启用 XDP 时对 **IPv4** 有效；缺少记录（XDP 关闭、IPv6、被淘汰）会被解读为「未捕获 → 回退到 TCP_INFO」，**不是**错误。细节见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

---

## 9. 如何重置 Web 管理员凭据 (`aegis web reset-admin`)

CLI 位于 `aegis`（hyper 二进制）中，即便在 pingora 模式下也会安装它，正是为了这些工具（`install.sh:516-521`）。命令（`src/main.rs:112-121`、`src/web_admin.rs:277-282`）：

```bash
aegis -c /etc/aegis/aegis.conf web reset-admin
```

输出：

```
✓ web admin reset
  email:    <DEFAULT_EMAIL>
  password: <随机>
  state:    /var/lib/aegis/web.json
```

`reset_admin()` 会把新密码写入 state 文件并设置 `must_change = true`，因此下次登录会再次要求修改 email+密码。**无需重启：** 守护进程会按 mtime 轮询获知 `web.json` 的变化（`install.sh:1135-1136` 的注释）。state 文件路径取自 `admin { web_state_path … }`（`install.sh:1066`），否则使用 `web_admin::DEFAULT_STATE_PATH`（`src/main.rs:101-108`）。

Web 面板相关的其他 CLI 命令（`src/main.rs:122-139`）：

| 命令 | 动作 | 效果 |
|---|---|---|
| `aegis web reset-admin` | 重置凭据 | 新密码，`must_change=true` |
| `aegis web stop` | 停止面板 | `/admin/ui` 和 `/admin/api/*` 开始返回 **503** |
| `aegis web start` | 启用面板 | 解除封锁 |
| `aegis web status` | 显示状态 | `enabled`、`email`、`must_change`、会话数量、state 路径 |

> 如果凭据被遗忘，而面板返回「invalid credentials」（`src/proxy/pingora_admin.rs:4400`）—— 这就是标准的恢复路径：`reset-admin` + 用新密码登录。

登录之外的替代方案是：使用 `/etc/aegis/admin-token` 中的令牌，通过 `x-admin-token: <token>` 请求头直接访问 admin API（`install.sh:1474-1476`、[30-admin-api.md](30-admin-api.md)）。

---

## 10. 日志在哪里 (journald / event-store)

AEGIS 不会为服务写自己的文本日志文件 —— 一切都进入 **journald**。

```bash
# pingora 模式（整个 worker 布局）
journalctl -u aegis-pingora.target -f
# 具体某个 worker
journalctl -u aegis-pingora@0 -n 50
# hyper 模式
journalctl -u aegis -f
# 面板重启器与数据源刷新器
journalctl -u aegis-restart.service -n 30
journalctl -u aegis-refresh-feeds.service -n 30
```

日志级别在 `/etc/aegis/aegis.env` 中通过 `RUST_LOG` 设置（默认 `info,aegis=info,aegis_pingora=info`，`install.sh:1334`），和/或通过 ExecStart 中的 `--log-level info` 标志（`install.sh:1254`）。修改之后：

```bash
systemctl daemon-reload && systemctl restart aegis-pingora.target
```

除 journald 外还有若干独立的数据流（参见 [24-request-log.md](24-request-log.md)、[25-metrics-telemetry.md](25-metrics-telemetry.md)）：

- **event-store** —— 持久化的 per-worker SQLite（按 worker 分片），请求/事件历史，按 domain/endpoint 维度；可通过面板和 admin API 查看；
- **audit_log** —— `/var/log/aegis/audit.log`（`install.sh:1055`），记录 admin API 的操作；
- **指标** —— timeseries 环形缓冲 + Prometheus `/metrics`；
- **EventBridge** —— 供 SIEM 使用的 NDJSON 流。

> 在 pingora 模式下 event-store 是**按 worker** 分片的 —— 要看聚合后的全貌，请使用面板或汇总类的 admin API 路由，而不是单个 shard 文件。

---

## 11. 状态重置

AEGIS 把状态保存在磁盘上，并通过文件 + mtime 轮询在 worker 之间同步（跨 worker）。各子系统的重置方式：

| 重置对象 | 操作 | 生效方式 |
|---|---|---|
| Web 管理员凭据/会话 | `aegis web reset-admin`（第 9 节） | mtime 轮询，无需重启 |
| Honeypot 包 | 删除/改写 `/var/lib/aegis/honeypots.json`（默认 `{"enabled":true,"packs":{},"per_host":{}}`，`install.sh:1125-1130`） | mtime 轮询 |
| Worker/布局 | `topology.json` 由面板写入（`PUT /admin/api/topology`）；安装器在 `--workers auto` 时读取（`install.sh:169-179`） | 下次安装/重启时 |
| 面板功能开关 | 清除 `/var/lib/aegis/aegis-ui.env` 中的覆盖值 | 重启 target |
| 信誉数据源 | 重新运行 `aegis-refresh-feeds`（Tor/Spamhaus/ASN-DB/CrowdSec） | mtime 热加载 |
| GeoIP | 替换 `/var/lib/aegis/geoip/*.mmdb`（或使用面板中的 Update 按钮） | mtime 热加载 |

```bash
# 强制刷新信誉数据源
/usr/local/bin/aegis-refresh-feeds
# 完整重启 data plane（应用任何更改）
systemctl restart aegis-pingora.target
```

### 11.1. 完全重置（uninstall / purge）

`install.sh`（`uninstall()`，`install.sh:1511-1538`）：

```bash
# 删除二进制/unit/源码，但保留 /etc/aegis 和 /var/lib/aegis
sudo bash install.sh --uninstall

# 彻底清理：连同 /etc/aegis、/var/lib/aegis、/var/log/aegis 一起删除 + 删除 aegis 用户
sudo bash install.sh --purge
```

- `--uninstall`：停止并禁用 `aegis` / `aegis-pingora.target` / `aegis-pingora@0..16`，删除 unit 和 `$AEGIS_SRC`，但**保留配置**（`uninstalled — config preserved at /etc/aegis (use --purge to remove)`）。
- `--purge`：额外执行 `rm -rf /etc/aegis /var/lib/aegis /var/log/aegis` 和 `userdel aegis` → `fully purged`。这就是「恢复出厂设置」。

> 执行 `--purge` 之后，下一次安装会重新生成 admin 令牌、hmac-secret、自签名证书以及 Web 管理员凭据。

---

## 12. 「症状 → 章节」对照表

| 症状 | 章节 |
|---|---|
| `XDP fast-path not available on this build` | [1](#1-xdp-无法加载-capabilities--内核) |
| BPF 加载时出现 `EACCES` / `os error 13` | [1.3](#13-权限不足-capabilities) |
| `xdp-already-owned-by-sibling-worker` | [1.4](#14-xdp-already-owned-by-sibling-worker--这不是错误) |
| `XDP attached in SKB mode` | [1.5](#15-native-drv-与-skb-generic-模式) |
| `HTTP/3 not started by this worker` | [2.1](#21-http3-not-started-by-this-worker--通常是正常现象) |
| `invalid h3_listen` | [2.2](#22-什么时候才是真正的问题) |
| 合法请求被拦截 | [3](#3-waf-误报) |
| 登录后白屏 / 顶栏崩溃 | [4](#4-登录面板后白屏-emailsplit) |
| 面板要求修改 email+密码 | [5](#5-首次登录时强制修改凭据) |
| 构建耗时过长 | [6](#6-构建缓慢) |
| `port 80 is already bound by …` / `AddrInUse` | [7](#7-nginx-或其他代理-占用了-80) |
| JA4/JA3 为空或为 `t12i000000_e3b0c44298fc` | [8](#8-ja4ja3-为空-指纹识别门控--在-clienthello-中捕获) |
| 忘记管理员密码 | [9](#9-如何重置-web-管理员凭据-aegis-web-reset-admin) |
| 去哪里看日志 | [10](#10-日志在哪里-journald--event-store) |
| 回滚状态 / 重新安装 | [11](#11-状态重置) |

---

另见：42-текущее-состояние-STATUS.md、[44-updates-migration.md](44-updates-migration.md)、[46-glossary.md](46-glossary.md)。
