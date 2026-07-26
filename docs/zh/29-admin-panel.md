# 管理面板 —— 使用指南

**语言：** [English](../en/29-admin-panel.md) · [Русский](../ru/29-admin-panel.md) · **中文**

AEGIS 的 Web 面板是一个 React 应用（37 个页面），由代理自身在 `/admin/ui/` 前缀下提供服务，并通过 `/admin/api/*` 下的管理 API 通信。本文详细描述面板登录、认证模型（`x-admin-token`、会话、角色）、首次凭据更换、文本仪表盘 `aegis-tui`，以及每个页面的用途 —— 它展示什么、配置什么、依赖哪些 API 路由。

> 代码导览：前端 —— `web/src/pages/v2/*.tsx`，导航 —— `web/src/components/layout/nav-config.ts`，HTTP 客户端与路由列表 —— `web/src/api/client.ts`。面板认证的后端 —— `src/web_admin.rs`，角色门控 —— `src/admin_auth.rs`，SPA 分发 —— `src/admin_ui.rs` / `src/server.rs`。文本仪表盘 —— `src/tui.rs`。

另见：[30-admin-api.md](30-admin-api.md) —— 完整 API 路由图；[23-security-model.md](23-security-model.md) —— 威胁模型；[03-installation.md](03-installation.md) —— 安装；[04-configuration.md](04-configuration.md) —— DSL 配置。

---

## 1. 访问与认证

### 1.1 面板在哪里

SPA 内嵌在二进制中，在 `/admin/ui/` 下分发：

- `/` 与 `/admin/ui`（不带斜杠）→ 301 重定向到 `/admin/ui/`（`src/server.rs:1616`）。
- Vite 打包使用 `base: "/admin/ui/"` 构建，因此所有资源都在该前缀下使用绝对路径；未知的客户端路由（`/admin/ui/sites`、`/admin/ui/config`、…）会回退到 `index.html`（`src/admin_ui.rs:29`）。
- 管理调用发往 `/admin/api/*`。当面板被关闭（`enabled = false`）时，`/admin/ui*` 和 `/admin/api/*` 都返回 `503`，但「裸」端点 `/admin/*`（reload、health、threats、…）继续工作，以免 `systemctl reload aegis` 失效（`src/web_admin.rs:49-53`）。

### 1.2 两套独立的访问模型

务必区分**两种不同的**认证机制（`src/web_admin.rs:12-16`）：

| 机制 | 覆盖范围 | 存储 |
|---|---|---|
| **面板会话**（email + 密码 → 会话令牌） | 仅 React 面板：`/admin/ui` + `/admin/api/*` | `/var/lib/aegis/web.json`（`DEFAULT_STATE_PATH`） |
| **DSL 静态令牌**（`token <role> <value>;` / `[[admin.tokens]]`） | CLI / `curl` 访问 `/admin/reload`、`/admin/health`、`/admin/threats` 等 | DSL 配置 |

面板的 HTTP 客户端会在每个发往 `/admin/` 的请求上把令牌放进 **`x-admin-token`** 请求头（`web/src/api/client.ts:73-76`）。令牌存放在 `localStorage` 的 `aegis_admin_token` 键下（`TOKEN_KEY`）。保存时令牌会被激进地清除空格/换行 —— 这是从终端复制时出现假 `401` 的「头号原因」（`web/src/api/client.ts:46-50`）。

端点 `GET /admin/api/me` 返回字段 `auth: "session" | "config_token"` —— 面板据此判断用户是通过表单登录的还是通过静态令牌（`web/src/api/client.ts:645-655`）。

### 1.3 角色

DSL 静态令牌带有角色（`src/config.rs:250-257`、`src/admin_auth.rs`）：

| 角色 | 权限 |
|---|---|
| `Read` | 只读：指标、health、threats、XDP 计数器 |
| `Write` | 读取 + 运行时变更（xdp deny/undeny、编辑站点、config apply、restart、…） |
| `Admin` | 完全控制（reload、stop + 以上全部）。环境变量 `AEGIS_ADMIN_TOKEN` 隐式赋予 `Admin` 角色 |

每个路由所需的最低角色由 `required_role_for()` 计算（`src/admin_auth.rs:168`）。粗略规则：`GET /admin/api/*` → `Read`；变更类（`POST`/`PUT`/`DELETE`）→ `Write`。面板会话在更换凭据后实际拥有足以完成所有面板操作的权限。

### 1.4 首次登录与强制更换凭据

预置行为（`src/web_admin.rs:101-141`）：

- **全新安装**（不存在 `web.json` 文件）：创建管理员 `admin@local.lcl`（`DEFAULT_EMAIL`），并使用**随机**强密码（约 108 比特熵）。密码通过 `tracing::warn!` **仅输出一次**到服务日志，不会以明文形式存放在任何地方（M8）。全新安装上，静态的「众所周知」默认密码是**无效的**。
- **已有安装**：文件按原样加载，不做迁移。

获取输出的密码：

```bash
journalctl -u aegis-pingora --no-pager | grep "Generated initial admin password"
```

在用户把 email **和**密码都从默认值改掉之前，字段 `must_change` 保持为 `true`。只要该标志存在，React 就会显示强制更换的红色横幅（`src/web_admin.rs:56-60`）。端点：

- `POST /admin/api/login` → `{ token, email, must_change }`
- `POST /admin/api/change-credentials`（当前密码 + 新 email + 新密码）—— 原子地更换凭据、清除 `must_change` 并使所有其他会话失效，同时重新签发当前会话（`src/web_admin.rs:234-272`）。
- `POST /admin/api/logout` —— 删除会话。

安全参数：密码以带每条记录独立 salt 的 **argon2id** 存储；会话令牌为 256 个随机比特，base64 url-safe；会话 TTL 为 **24 小时**（`SESSION_TTL_SECS`，`src/web_admin.rs:45`）。令牌比较是**常数时间**的（`constant_time_eq`），以封堵时序预言机（V233，`src/web_admin.rs:33-37`）。更换时的校验：email 长度 1..=254 且含 `@`；密码长度 8..=256（`src/web_admin.rs:333-352`）。

守护进程在每个已认证请求上都会 **stat** `web.json` 文件，并在 mtime 变化时重新读取 —— 因此通过 CLI 做的修改会立即生效，无需 SIGHUP（`src/web_admin.rs:143-153`）。

### 1.5 通过 CLI 重置与关闭

登录表单会提示恢复命令（`web/src/pages/v2/Login.tsx:214`）：

```bash
aegis web reset-admin   # 把密码重置为新的随机值，email → admin@local.lcl，must_change=true
aegis web stop          # 关闭面板：/admin/ui 与 /admin/api/* 返回 503
```

`reset_admin()` 会清空所有会话并把新的明文密码返回到 stdout（`src/web_admin.rs:277-289`）。`set_enabled(false)` 会抹掉会话，使得再次开启时必须重新登录（`src/web_admin.rs:291-300`）。

### 1.6 终端仪表盘 `aegis-tui`

当没有浏览器时（跳板机、恢复用 SSH、嵌入式部署）或面板尚未配置好时，运维人员可运行 `aegis-tui` —— 一个基于 Ratatui 的实时仪表盘（`src/tui.rs:1-35`）。它按间隔轮询 `/admin/api/runtime/status` 与 `/metrics`，并绘制单屏界面：

- **顶部**：版本、hostname、uptime；`MODE`（按严重程度着色：Normal=绿、Elevated=黄、Attack=紫、Critical=红）、`TLS on/off`、`XDP backend`。
- **流量**：req/s、bps、p50/p95/p99。
- **决策**：allow / challenge / deny / throttle / observed（百分比 + 三个 gauge 条）。
- **底部**：top-filters 表格（filter → hits）与 recent events 流（time / ip / decision / reason）。
- **快捷键**：`q` quit · `r` refresh · `f` follow events。

渲染是对 `DashboardSnapshot` 的纯函数，因此相同的帧可以来自网络、Unix socket 或回放文件。

### 1.7 导航结构

侧边栏分为 6 个可展开的分组 + 固定在底部的 Settings 项（`web/src/components/layout/nav-config.ts:85-177`）。分组展开状态保存在 `localStorage` 的 `aegis:nav:open` 键下。

| 分组 | 条目 |
|---|---|
| **Overview** | Dashboard (`/`)、Metrics (`/metrics`) |
| **Traffic & Routing** | Sites (`/sites`)、Site map (`/site-map`)、Upstreams (`/upstreams`)、Certificates (`/certificates`) |
| **Security** | Security (`/security`)、Bots (`/bots`)、DDoS (`/ddos`)、Log (`/logs`)、Rate limits (`/rate-limits`)、Reputation (`/reputation`)、GeoIP (`/geoip`)、Sigma rules (`/sigma`) |
| **Defence Arsenal** | Defence Arsenal (`/arsenal`)、Challenge Ladder (`/challenge`)、Scenarios (`/scenarios`)、Active actions (`/actuators`)、Honeypots (`/honeypots`)、Tarpit (`/tarpit`)、BGP RTBH (`/bgp`)、Privacy Pass (`/privacy-pass`) |
| **Intelligence & ML** | Enrichment (`/enrichment`)、ML (`/ml`)、Signature miner (`/signatures`)、CrowdSec (`/crowdsec`) |
| **Operations** | Workers (`/workers`)、Cluster (`/cluster`)、Benchmark (`/benchmark`)、Telemetry (`/telemetry`)、Updates (`/updates`)、Config editor (`/config`) |
| **固定项** | Settings (`/settings`) |

此外还有侧边栏之外的路由：`SiteDetail`（`/sites/:host`）、`SiteMapHost`（`/site-map/:host`）、`Login`、`NotFound`、`ServiceUnavailable`。

> 每个页面都遵循统一原则：数据通过 `@tanstack/react-query` 拉取（常带 `refetchInterval`），变更通过 `web/src/api/client.ts` 中同样的 `*Api` 发起。视觉层是来自 `web/src/v2/components` 的 `MetricCard` / `KPITile` / `SectionHeader` / `StatusBadge` 原语。写在代码里的设计准则：**绝不编造数字** —— 所有数值都来自真实的 API 响应，否则显示 `—`（`web/src/pages/v2/Dashboard.tsx:28-33`）。

---

## 2. Overview

### 2.1 Dashboard (`/`)

来源：`web/src/pages/v2/Dashboard.tsx`。主概览页。自上而下：

1. 时间范围选择器（控制所有时间序列）。
2. 5 个 KPI 磁贴：Total Requests、Threat Score、Active Attacks、Mitigation Efficiency、Cluster Health。
3. 三列：Live Traffic Overview（WorldMap + 国家 Top）、Traffic Flow（历史面积图）、Security Events 流。
4. Live Decision Engine —— 全宽堆叠面积图。
5. Proxy Status（环形图）| Upstream Status | System Health（4× ArcGauge）。
6. Defence Arsenal | Threat Intelligence | Top Attack Types（环形图）。
7. Sites Overview（宽表格）+ System Status。

拉取：`/metrics`（Prometheus 文本）、`/admin/api/metrics/series?range=`、`/admin/api/topology`（CPU+worker）、`/admin/api/benchmark/result`（RAM）、`/admin/api/geo/top`（按国家的流量，未部署时可能返回 404）、`/admin/health`、`/admin/threats`、`/admin/anomaly`、`/admin/api/runtime/info`、`/admin/api/arsenal`、`/admin/api/cluster/status`。若某项功能缺失，该区块会以最接近的可用数据绘制，并标注「live host stats unavailable」。

### 2.2 Metrics (`/metrics`)

来源：`web/src/pages/v2/Metrics.tsx`。详细的指标图表。见 [25-metrics-telemetry.md](25-metrics-telemetry.md)。

- 4 个 KPI 磁贴：Requests / Denied / Challenged / Filter toggles。
- 按范围的历史面板：Traffic / Upstream / Cache。
- 实时 XDP fast-path（无持久化历史）。
- 3 个环形图：Decision mix / Upstream status mix / Top hosts。
- 原始 Prometheus 转储。

数据：`metricsApi.series(range)`（`/admin/api/metrics/series` —— 持久化的、分桶的机群历史；后台每 30 秒从集群 mmap 计数器采样一次，由一个 worker 在 file-lock 下写入，所有 worker 都可读）；`metricsApi.raw`（`/metrics`，3 秒轮询 → 累计数值、环形图、top-hosts）；`runtimeInfoApi.get`（15 秒 → 过滤器开关计数）。

---

## 3. Traffic & Routing

### 3.1 Sites (`/sites`)

来源：`web/src/pages/v2/Sites.tsx`。已配置站点列表。`sitesApi.list`（`GET /admin/api/sites`）与 `sitesApi.remove`（`DELETE /admin/api/sites/<host>`）。来源徽章（`StatusBadge`）以及 TLS/rate-limit 徽章。向导 `AddSiteWizard` 通过 `POST /admin/api/sites` 创建站点（幂等：相同 host 会覆盖 `.conf`；响应中包含生成的 `dsl_snippet`）。见 [26-sites-and-domains.md](26-sites-and-domains.md)。

### 3.2 SiteDetail (`/sites/:host`)

来源：`web/src/pages/v2/SiteDetail.tsx`。单个域名的详情卡，带标签页（`SiteDetail.tsx:200-243`）：

- **Overview** —— KPI 行 + 该主机指标的 LiveAreaChart；per-domain 过滤器策略开关（`sitePolicyApi.get/put/remove` —— `/admin/api/sites/<host>/policy`）。策略保存 `filter_enabled`（对每个过滤器的 on/off 覆盖）、`endpoint_policies`（path 模式 → 动作 `allow|block|challenge|tarpit`，V166）以及 `rate_limit`（主机级 RPS/burst 的运行时覆盖层，V234 —— 无需修改只读的 `.conf` 即可生效）。
- **Endpoints** —— 来自站点测绘的已发现端点表（`siteMapApi.forHost`），可绑定 per-endpoint 动作。
- **Challenge** —— per-domain 的验证挑战阶梯配置（`challengeApi.getHost/putHost/deleteHost` —— `/admin/api/sites/<host>/challenge`）：Argon2-PoW、Privacy Pass、adaptive、varied errors、诱饵 CAPTCHA、蜜罐字段、JA4/UA 一致性、header/H2 指纹、headless 检测、WebGL/audio FP 等。

同时还会拉取 `metricsApi.raw`、`honeypotApi.builtin/get/toggleHost`、`sitesApi.update`。

### 3.3 SiteMap (`/site-map`, `/site-map/:host`)

来源：`web/src/pages/v2/SiteMap.tsx`。站点测绘：已观测到的主机及其端点列表。后端合并分片 `shard-*.json` 并返回 per-host 聚合。每个主机被标记为 **Configured**（存在于 `/admin/api/sites` 中）或 **Referring · unconfigured**（能解析到代理，但未配置为站点 —— 琥珀色徽章）。路由：`GET /admin/api/site_map`（主机、`total_endpoints`）、`GET /admin/api/site_map/<host>`（端点：method、path_pattern、hits、last_seen、2xx/3xx/4xx/5xx 状态分布）。见 [26-sites-and-domains.md](26-sites-and-domains.md)。

### 3.4 Upstreams (`/upstreams`)

来源：`web/src/pages/v2/Upstreams.tsx`。上游健康状况。`sitesApi.list` + `opsApi.health`（10 秒轮询；解析 `/admin/health` 文本：形如 `unhealthy <host> since_ms=<n>` 的行，或 `all_upstreams_healthy`）。见 [07-protocols.md](07-protocols.md)。

### 3.5 Certificates (`/certificates`)

来源：`web/src/pages/v2/Certificates.tsx`。TLS 证书与 ACME/Let's Encrypt 管理。`sitesApi` + `acmeApi`：

- `GET/PUT /admin/api/acme/config`（PUT —— 需要 Write 角色），
- `GET /admin/api/acme/orders`、`GET /admin/api/acme/orders/<host>`，
- `POST /admin/api/acme/orders`（创建订单：host+email），
- `POST /admin/api/acme/orders/<host>/renew`（续期）。

变更操作：saveConfig / createOrder / renewOrder。见 [08-tls-certificates.md](08-tls-certificates.md)。

---

## 4. Security

### 4.1 Security (`/security`)

来源：`web/src/pages/v2/Security.tsx`。全局过滤器链及其 on/off 开关。`defaultsApi`（`GET/PUT /admin/api/defaults/filters` —— 运行时开关；**仅在内存中**，重启会恢复为配置值）+ `filterActivityApi`（`GET /admin/api/filters` —— 每个过滤器的拦截/挑战计数）。页面底部是一张带 DSL 片段的卡片，用于永久固化。见 [10-waf.md](10-waf.md)。

### 4.2 Bots (`/bots`)

来源：`web/src/pages/v2/Bots.tsx`。按 IP 的 bot 检测。模式切换：

- **Live** —— `threatAnalyticsApi.bots()`（`/admin/api/bots`），内存中约 5 分钟的实时窗口（client_ip、primary_reason、hits、last_seen）。
- **Historical** —— 来自持久化存储、覆盖任意所选范围的 `logsApi.stats({from,to}).top_client_ips`。

### 4.3 DDoS (`/ddos`)

来源：`web/src/pages/v2/Ddos.tsx`。分布式攻击的目标。SeverityChip（C/H/M/L）、KPI 磁贴。

- **Live** —— `threatAnalyticsApi.ddos()`（`/admin/api/ddos`）：host + path + distinct IP + total hits。
- **Historical** —— `logsApi.stats({from,to}).top_endpoints`（不保存按端点的 distinct-IP 归因，因此历史行按热门 path 模式上的流量排序）。

### 4.4 Logs / 日志 (`/logs`)

来源：`web/src/pages/v2/Logs.tsx`。逐请求的决策日志：action、reason/WAF 规则、状态、latency、客户端指纹（JA4）、国家、协议、UA。路由：`GET /admin/api/logs`（分页：host/endpoint/action/ip/q 过滤 + limit/offset）与 `GET /admin/api/logs/stats`（聚合：by_action、top_endpoints、带 deny/challenge 拆分的 top_client_ips、top_reasons、status_distribution、分桶 series）。host/from/to 这三个过滤条件对两个端点通用；在 stats 中其余字段会被忽略。见 [24-request-log.md](24-request-log.md)。

### 4.5 Rate limits (`/rate-limits`)

来源：`web/src/pages/v2/RateLimits.tsx`。限流编辑器。`opsApi` + `sitesApi`。展示默认值 vs 覆盖值；对非托管（ops）站点显示 `ops` 徽章。见 [14-rate-limiting.md](14-rate-limiting.md)。

### 4.6 Reputation (`/reputation`)

来源：`web/src/pages/v2/Reputation.tsx`。JA4 指纹与 ASN/CIDR 的信誉，以及内置 JA4 语料库。`reputationApi.ja4()` / `reputationApi.asn()`（feed 状态：`active`、`entry_count`、`corpus_count`）、`reputationApi.ja4Lookup()` / `asnLookup()`（按哈希/IP 查询）、`envApi.get/set`（feed 路径）。见 [12-reputation.md](12-reputation.md)。

### 4.7 GeoIP (`/geoip`)

来源：`web/src/pages/v2/GeoIP.tsx`。按国家的 deny 规则与 ASN 富化。`geoipApi.status()`（`/admin/api/geoip/status`：数据库路径、`loaded`、`database_type`、`bundled`、署名信息）、`geoipApi.lookup()`（按 IP）、`geoipApi.update()`（`POST /admin/api/geoip/update` —— 更新内置的 db-ip Country Lite）。见 [20-geoip.md](20-geoip.md)。

### 4.8 Sigma rules (`/sigma`)

来源：`web/src/pages/v2/Sigma.tsx`。把 SigmaHQ 的 Sigma 规则转换为 AEGIS 的 WAF 规则 + 管理捆绑语料库。`sigmaApi.status()`（`/admin/api/sigma/rules`：路径、exists、rule_count、size_bytes）、`sigmaApi.importRule(yaml)`（`POST /admin/api/sigma/import`）、`sigmaApi.list()`（`/admin/api/sigma/rules/list` —— 每条规则及其 enabled 状态）、`sigmaApi.toggle(id, enabled)`（V237 —— 通过磁盘 overlay 逐条开关）。导入通过 Monaco 编辑器。见 [10-waf.md](10-waf.md)。

---

## 5. Defence Arsenal

### 5.1 Defence Arsenal (`/arsenal`)

来源：`web/src/pages/v2/Arsenal.tsx`。按家族（fingerprint / waf / ddos / honeypot / telemetry / challenge / deception）汇总所有防御模块，带 `shipped|planned|experimental` 状态与实时计数。`arsenalApi.get()`（`/admin/api/arsenal`），特性开关通过 `envApi` / `restartApi` / `runtimeInfoApi` 管理。见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### 5.2 Challenge Ladder (`/challenge`)

来源：`web/src/pages/v2/ChallengeLadder.tsx`。验证挑战阶梯的全局状态 + per-host 配置 + per-route 难度。`challengeApi.listHosts()`（`/admin/api/challenge/hosts` —— 包含 `global`：attack_mode、fast_track_hits、randomized_picks、decoy_forms_rendered、honeypot_fills_detected、privacy_pass_issuers、…）、`challengeApi.setAttackMode(on)`（`/admin/api/challenge/attack-mode`）、`routeDifficultyApi.list()`（`/admin/api/route-difficulty` —— 按 host+path 的 difficulty_bits 覆盖，预设 ai_scraper/auth）。见 [15-challenge-ladder.md](15-challenge-ladder.md)。

### 5.3 Scenarios (`/scenarios`)

来源：`web/src/pages/v2/Scenarios.tsx`。leaky-bucket 的 YAML 场景（类 CrowdSec）。`scenariosApi.list()`（`/admin/api/scenarios` —— `wired`、scenarios[]、stats）、`scenariosApi.test(yaml)`（`/admin/api/scenarios/test` —— 解析校验）、`scenariosApi.load(yaml)`（`/admin/api/scenarios/load`）。场景字段：filter、groupby、distinct、capacity、leak_speed、blackhole、action。编辑器为 Monaco。见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### 5.4 Active actions / Actuators (`/actuators`)

来源：`web/src/pages/v2/Actuators.tsx`。已生效的主动动作（执行器），可回滚。`actuatorsApi.list()`（`/admin/api/actuators` —— 5 秒轮询：`active[]`，含 kind/target/reason/source_module/applied_at/remaining_secs，生命周期 `stats`，`kinds`）、`actuatorsApi.revert(kind, target_kind, target_value)`（`/admin/api/actuators/revert`）。`StatusBadge` 显示 arsenal 的 `wired` 状态。见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### 5.5 Honeypots (`/honeypots`)

来源：`web/src/pages/v2/Honeypots.tsx`。蜜罐包与参数管理。`honeypotApi.builtin()`（`/admin/api/honeypots/builtin` —— 内置包）、`honeypotApi.get/save`（`/admin/api/honeypots` —— 完整状态：`enabled`、`packs`、`per_host`、`host_disabled`（绕过全部蜜罐匹配的主机）、`custom_paths`、`tarpit_seconds`、`tarpit_chunk_bytes`、`score_bump`、`auto_xdp_deny_threshold`、`server_header`）、`toggleGlobal` / `toggleHost` / `clearHost` / `setHostEnabled`。另有 `envApi`/`runtimeInfoApi` 用于特性开关（例如 LLM 蜜罐）。见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

### 5.6 Tarpit (`/tarpit`)

来源：`web/src/pages/v2/Tarpit.tsx`。tarpit 参数 + 多轮蜜罐对话的 YAML 描述符。`tarpitApi.status()`（`/admin/api/tarpit/status`：tarpit_seconds、tarpit_chunk_bytes、auto_xdp_deny_threshold、poisoned_tarpit_default_delay_ms）、`honeypotYamlApi.list/parse`（`/admin/api/honeypot-yaml`、`/admin/api/honeypot-yaml/load`）。每个描述符把 path 模式绑定到 N 轮对话；per-IP 状态跟踪进度。编辑器为 Monaco。见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

### 5.7 BGP RTBH (`/bgp`)

来源：`web/src/pages/v2/BgpRtbh.tsx`。活跃的 RTBH BGP 通告（ExaBGP）。`bgpApi.list()`（`/admin/api/bgp/announces` —— 10 秒轮询：`wired`、`active_count`、`active[]`，含 ip/community/age_secs）、`bgpApi.withdraw(ip)`（`/admin/api/bgp/withdraw` —— 撤回通告）。见 [19-bgp-rtbh.md](19-bgp-rtbh.md)。

### 5.8 Privacy Pass (`/privacy-pass`)

来源：`web/src/pages/v2/PrivacyPass.tsx`。Privacy Pass 签发方（Ed25519）。`privacyPassApi.status()`（`/admin/api/privacy-pass` —— 30 秒轮询：`wired`、`issuer_count`、`nonce_cache_size`）、`privacyPassApi.addIssuer()`（`/admin/api/privacy-pass/issuers` —— name、key_id_hex、public_key_hex、algorithm `ed25519|hmac_sha256`、trust_duration_secs）。见 [16-privacy-pass.md](16-privacy-pass.md)。

---

## 6. Intelligence & ML

### 6.1 Enrichment (`/enrichment`)

来源：`web/src/pages/v2/Enrichment.tsx`。来自外部来源（threat-intel）的威胁富化。`enrichmentApi.status()`（`/admin/api/enrichment` —— 10 秒轮询：`wired`、每来源的 queries/hits/misses 统计、缓存）、`enrichmentApi.lookup(key_kind, value)`（`/admin/api/enrichment/lookup` —— 按 ip/ja4/asn/user_agent 手动测试；返回聚合裁决 + 各来源结果）。见 [22-enrichment.md](22-enrichment.md)。

### 6.2 ML (`/ml`)

来源：`web/src/pages/v2/ML.tsx`。ML 特性标志与风险引擎状态管理。`mlApi.status()`（`/admin/api/ml/status`：`v2_wired`、`v2_kind` logistic/gbm、`adversarial_loop_env`）、`mlApi.retrain()`（`/admin/api/ml/retrain`）、`mlApi.adversarial()`（`/admin/api/ml/adversarial`）、`envApi` + `runtimeInfoApi` 用于标志（`AEGIS_ML_V2`、`AEGIS_ML_SCORER`、`AEGIS_ML_ADVERSARIAL`、`AEGIS_RISK_ENGINE_MODE`）。部分标志只在重启时生效 —— 会显示 restart-required 横幅。见 [18-ml-risk-engine.md](18-ml-risk-engine.md)。

### 6.3 Signature miner (`/signatures`)

来源：`web/src/pages/v2/SignatureMine.tsx`。从 payload 语料库中挖掘攻击特征（n-gram），并以 benign 作为对照集。`signatureMineApi.mine(attacks, benign)`（`POST /admin/signature_mine` —— 请求体：attack 行、字面量 `---`、benign 行；响应：带 confidence/attack_support/benign_support/category/ngram 的候选）、`signatureMineApi.minedCandidates()`（`GET /admin/api/mined_signatures` —— 来自在线流水线 tarpit→miner 的自动挖掘候选）。**不会直接写入 WAF 配置** —— 运维人员把候选复制为 WAF 规则 TOML，并通过 Config Editor 粘贴。见 [10-waf.md](10-waf.md)。

### 6.4 CrowdSec (`/crowdsec`)

来源：`web/src/pages/v2/CrowdSec.tsx`。CrowdSec LAPI 适配器配置。`crowdsecApi.status()`（`/admin/api/crowdsec/status`：`lapi_url`、`bouncer_key_configured`、`format_adapter_available`），配置通过 `envApi`。变更后显示 restart-required 横幅。见 [22-enrichment.md](22-enrichment.md)。

---

## 7. Operations

### 7.1 Workers (`/workers`)

来源：`web/src/pages/v2/Workers.tsx`。worker 拓扑（SO_REUSEPORT 多进程）。`topologyApi.get()`（`GET /admin/api/topology` —— host、layout、per-worker procs、推荐值）、`topologyApi.put(workers)`（`PUT /admin/api/topology` —— 期望数量：`"auto"` 或数字字符串）、`envApi`、`runtimeInfoApi`、`restartApi`。见 [06-workers.md](06-workers.md)。

### 7.2 Cluster (`/cluster`)

来源：`web/src/pages/v2/Cluster.tsx`。威胁集群 shared-mmap 的状态。`clusterApi.status()`（`/admin/api/cluster/status` —— 5 秒轮询：`shared_scorer_attached`、`counts.ipv4_slots_active`、`counts.top[]`，含 ip/score）。见 [06-workers.md](06-workers.md)。

### 7.3 Benchmark (`/benchmark`)

来源：`web/src/pages/v2/Benchmark.tsx`。硬件基准测试、压力测试以及与其他代理的对比。三组路由（fire-and-forget + 轮询结果）：

- `benchmarkApi` —— `POST /admin/api/benchmark/run`、`GET /admin/api/benchmark/result`（硬件基准 + 容量预测）。
- `floodApi` —— `POST /admin/api/benchmark/flood/run`、`GET .../flood/result`（SYN / HTTP / TLS / slowloris / cache 洪水测试）。
- `compareApi` —— `POST .../compare/run`、`GET .../compare/result`（head-to-head：AEGIS raw、AEGIS+WAF、nginx、nginx+ModSec+CRS、HAProxy、Caddy、Envoy；按攻击类型的安全矩阵）。

> 诚实声明（直接写在代码的 `caveat` 字段中）：AEGIS 的基准通道是**进程内引擎，而不是完整的 pingora 二进制**；硬件 SHA 基准是 per-core 的，在没有硬件 SHA 加速的 VM 中会偏低，因此容量预测偏悲观。它并不被定位为「在裸速度上快过真实代理」—— 真正有力的论据正是安全矩阵。见 [28-benchmarking.md](28-benchmarking.md)、[27-performance-tuning.md](27-performance-tuning.md)。

### 7.4 Telemetry (`/telemetry`)

来源：`web/src/pages/v2/Telemetry.tsx`。遥测与 SIEM 集成配置。`telemetryApi.status()`（`/admin/api/telemetry/status`：EventBridge format/format_options/socket_path，ClamAV enabled/addr/env_var，audit_log_path）、`captchaApi.status()`（`/admin/api/captcha/status`：PoW enabled/difficulty_bits/algorithm，外部提供方 hcaptcha/turnstile/recaptcha），env 控制通过 `envApi` + `restartApi`。见 [25-metrics-telemetry.md](25-metrics-telemetry.md)。

### 7.5 Updates (`/updates`)

来源：`web/src/pages/v2/Updates.tsx`。**只读**的更新检查（V208）。`updatesApi.status()`（`/admin/api/updates/status`：current_version、channel、latest、update_available、last_checked_at、last_error）、`updatesApi.check()`（`POST .../check`）、`updatesApi.releases()`、`updatesApi.setConfig()`（`PUT .../config`：repo_api_url、channel `stable|beta|nightly`、poll_interval_secs）。

> 安全性（V233）：**自更新-应用**机制被整体移除（`apply`/`snapshots` 的类型与路由已删除）—— 它会以服务用户身份下载并执行未签名、可被攻击者控制的二进制（这是未认证 RCE 的设计）。现在只保留只读检查。更新的应用需手动进行，见 [44-updates-migration.md](44-updates-migration.md)。

### 7.6 Config editor (`/config`)

来源：`web/src/pages/v2/ConfigEditor.tsx`。在 Monaco 中编辑原始 DSL 配置，带语法高亮（关键字：`admin`、`defaults`、`server`、`include`、`location`、`listen`、`server_name`、`ssl_certificate`、…）。`configApi.raw()`（`GET /admin/api/config/raw`）、`configApi.test(text)`（`POST /admin/api/config/test` —— 只校验不应用）、`configApi.save(text)`（`PUT /admin/api/config/raw`）、`configApi.apply()`（`POST /admin/api/config/apply` —— 需要 Write 角色；应用/重启）。见 [04-configuration.md](04-configuration.md)。

---

## 8. Settings (`/settings`)

来源：`web/src/pages/v2/Settings.tsx`。四个标签页：

| 标签页 | 内容 |
|---|---|
| **General** | Runtime info、当前会话、更换凭据（`ChangeCredentialsCard` → `authApi.changeCredentials`）、danger zone |
| **ML & Detection** | ML scorer、adversarial loop、honeypot |
| **Reputation** | JA4 + ASN feed |
| **Infrastructure** | Response cache、dynamic trust、fw backend、XDP、ACME、CrowdSec、ClamAV（通过环境变量；带 restart-required 横幅） |

数据：`runtimeApi.status`（`/admin/api/runtime/status`）、`runtimeInfoApi.get`（`/admin/api/runtime/info`，15 秒 —— 版本、uptime、config_path、ML v2 状态、JA4/ASN 信誉、honeypot、开关/策略数量、clamav_addr，以及扩展的 env 门控）、`envApi.set`（`PUT /admin/api/env` —— 密钥为 write-only：GET 返回 `configured: true/false`、`value: null`；对于启动时才生效的变量，响应含 `restart_required: true`）、`restartApi.run`（`POST /admin/api/restart` —— 需要 Write 角色；触发 `aegis-pingora.target` 的滚动重启，连接会在几秒后断开）。

---

## 9. 辅助页面

| 页面 | 文件 | 用途 |
|---|---|---|
| **Login** | `Login.tsx` | 全屏登录表单（email + 密码，可切换可见性）。在 `logged_out` 状态下由 `main.tsx` 直接渲染，不经路由/布局。恢复提示：`aegis web reset-admin` |
| **ServiceUnavailable** | `ServiceUnavailable.tsx` | `503` 时的页面（面板关闭 / 代理不可用） |
| **NotFound** | `NotFound.tsx` | 未知客户端路由的 404 |

---

## 10. 运维实用笔记

- **刚复制完令牌就出现「401 unauthorized」** —— 几乎总是多了一个换行；客户端已经会归一化该值（`setToken`），但通过 curl 手动填 `x-admin-token` 时请确认没有 `\n`。
- **通过 Security 页面做的过滤器修改无法在重启后保留** —— `defaultsApi` 改的是内存中的运行时状态；要持久化，请把页面展示的片段固化到 DSL 中，并通过 Config Editor 应用。
- **部分功能需要重启** —— `PUT /admin/api/env` 响应中标记 `restart_required` 的标志，以及 ML / CrowdSec / Telemetry / Workers 页面会显示横幅；重启可由按钮触发（`POST /admin/api/restart`），也可用 `systemctl`。
- **Mock 模式** —— 用 `VITE_USE_MOCKS=true` 构建前端时，面板会返回 `mocks.ts` 中的合成数据，无需后端即可浏览（用于 UI 开发）。
- **完全被锁死时的恢复** —— `aegis web reset-admin` 会把 email 重置为 `admin@local.lcl` 并把新密码输出到 stdout；对 `web.json` 的修改会被守护进程按 mtime 感知，无需重启。

另见：[30-admin-api.md](30-admin-api.md)、42-текущее-состояние-STATUS.md、[47-faq-troubleshooting.md](47-faq-troubleshooting.md)。
