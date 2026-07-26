# 术语表

**语言：** [English](../en/46-glossary.md) · [Русский](../ru/46-glossary.md) · **中文**

AEGIS 术语、协议与子系统的按字母排序参考。每一条定义都对应到真实的代码模块（`src/lib.rs`），并诚实标注哪些默认开启、哪些是 opt-in。子系统缩写均以其在代码中出现的形式给出（模块名、指令、环境变量、路由）。

---

## 使用说明

- 术语按字母顺序排列（拉丁字母在前）。
- 「代码中的位置」一栏给出 `src/lib.rs` 中的模块（`pub mod …`）或仓库中的其他文件。
- 标记 **opt-in** 表示该功能默认关闭，需要显式启用（环境变量、配置、`.with_arsenal()` 等）。
- 标记 **default-on** 表示该子系统无需额外配置即处于启用状态。
- 各主题的详细内容见相邻文档；链接以相对路径给出。

---

## A

### ALPN (Application-Layer Protocol Negotiation)
TLS 扩展，客户端在 `ClientHello` 中借此声明应用层协议列表（`h2`、`http/1.1`、`h3`）。AEGIS 在捕获 ClientHello 时读取 ALPN，并将其作为指纹识别与协议协商的输入之一。详情：[11-tls-fingerprinting.md](11-tls-fingerprinting.md)、[07-protocols.md](07-protocols.md)。

### Argon2id PoW
SHA-256 工作量证明的内存困难（memory-hard）替代方案。按设计在 GPU 农场上的成本高 100–1000 倍，因为每次尝试的 RAM 下限（默认 64 MB）限制了并行度。模块 `argon2_pow`（V200）。参见 [15-challenge-ladder.md](15-challenge-ladder.md)。

### ASN (Autonomous System Number)
自治系统号 —— BGP 中网络运营商的标识符。AEGIS 以两种方式使用 ASN：(1) 基于 db-ip 数据库的 GeoIP 富化（国家 + ASN），模块 `geoip`；(2) 按 ASN 的信誉，模块 `asn_reputation`（V142）—— 一份「坏」ASN/CIDR 的数据源，配合查询 trait `AsnLookup`，为 ML 特征 `asn_reputation` 供数。参见 [20-geoip.md](20-geoip.md)、[12-reputation.md](12-reputation.md)。

### Adversarial（对抗训练）
生成语义等价的 SQLi 载荷变体并将其送入 WAF/评分器的循环；绕过样本作为 hard-negative 样本回流到 `MlTrainer`，用于下一轮重训练。模块 `ml_adversarial`（V146，WAF-A-MoLE 风格）。参见 [18-ml-risk-engine.md](18-ml-risk-engine.md)。

### Aho-Corasick
同时进行多模式子串匹配的算法。AEGIS WAF 签名引擎的基础：对归一化后的请求做一次遍历即可匹配整个签名集。参见 [10-waf.md](10-waf.md)。

---

## B

### BGP RTBH (Remotely-Triggered Black Hole)
远程触发黑洞 —— 通过向上游通告路由，在网络层抑制攻击，使发往受害者的流量在到达代理之前就被丢弃。AEGIS 将 L7 阻断决策以 /32 BGP 通告的形式向上推送（默认通过 ExaBGP 管道；trait 抽象也允许 goBGP/FRR），带 TTL 与自动撤销。模块 `bgp_rtbh`（V187，FlowSpec/RTBH 调度器），**opt-in**。参见 [19-bgp-rtbh.md](19-bgp-rtbh.md)。

---

## C

### CIDR (Classless Inter-Domain Routing)
形如 `203.0.113.0/24` 的地址段记法。AEGIS 在按子网的限速和信誉中使用 CIDR（`asn_reputation` 可在没有 ASN 数据库的情况下按 CIDR 工作）。默认的 Tor/Spamhaus 列表以 **default-on** 的信誉形式随附。参见 [14-rate-limiting.md](14-rate-limiting.md)、[12-reputation.md](12-reputation.md)。

### Challenge ladder（挑战阶梯）
逐级升级的客户端校验序列：cookie → reload → PoW → CAPTCHA → WebAuthn。与链式信任（`chained_trust`，V202：cookie 5 分钟 → captcha 24 小时 → WebAuthn 7 天）、自适应性（`adaptive_ladder`，V204：异常模式下提升 PoW 位数、按 IP 随机化起始层级）以及欺骗层（`challenge_deception`，V203：诱饵 CAPTCHA、表单 honeypot 字段）相关联。参见 [15-challenge-ladder.md](15-challenge-ladder.md)。

### CrowdSec LAPI (Local API)
CrowdSec 的本地 API —— CrowdSec「bouncer」（nginx、HAProxy、Cloudflare worker、iptables、Caddy、k8s ingress）所理解的阻断决策线路格式。AEGIS 以该格式发出决策（`crowdsec_api`，V157），使已有的 bouncer 无需改造执行层即可落实 AEGIS 的裁决。CrowdSec 同时也被用作信誉来源（**opt-in**）。参见 [12-reputation.md](12-reputation.md)、[21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### Compound rules（复合规则）
按条件组合而非单一签名触发的 WAF 规则。与 Aho-Corasick 签名、Sigma 规则集和 webshell 检测一并构成 WAF 规则库的一部分。参见 [10-waf.md](10-waf.md)。

### CAPTCHA 提供方
可插拔的外部 CAPTCHA 提供方：hCaptcha、Cloudflare Turnstile、Google reCAPTCHA。trait `CaptchaProvider` 抽象 siteverify 调用，`HttpPoster` 抽象传输。模块 `captcha_providers`（V132），**opt-in**。参见 [15-challenge-ladder.md](15-challenge-ladder.md)。

---

## D

### Defence Arsenal
一个伞状子系统，将 V176–V190 各模块（`arsenal`，V192）统一到 `ArsenalState` 之下，并带有按组件的活动计数器。通过 `.with_arsenal()` 接入 `AegisPingoraProxy`，且**默认不存在** —— 生产二进制需显式启用该武器库。参见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### Decoy headers（诱饵响应头）
在可疑请求上模仿 Cloudflare / Akamai / Fastly / CloudFront 的响应形态，让攻击者的绕过工具选错 playbook。模块 `decoy_headers`（V188，Scrapling 的反向应用），**opt-in**（武器库的一部分）。参见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

---

## E

### eBPF (extended Berkeley Packet Filter)
在 Linux 内核中执行程序的技术。AEGIS 用它来实现丢包快速路径的 XDP 程序。参见 [13-xdp-ebpf.md](13-xdp-ebpf.md)。

### Ed25519
基于椭圆曲线的数字签名算法。AEGIS 用它验证 Privacy Pass 令牌。参见 [16-privacy-pass.md](16-privacy-pass.md)。

### EventBridge
面向 SIEM 的安全事件（V116 `SecurityEvent`）NDJSON 流式输出器，基于 Unix 套接字。Best-effort 且容忍丢失：慢订阅者会丢事件，但代理的热路径永不阻塞。模块 `event_bridge`（V127）。参见 [25-metrics-telemetry.md](25-metrics-telemetry.md)。

### Event-store（事件存储）
请求/事件的持久化日志。每个工作进程一个 SQLite 分片（`shard-<slot>.db`，WAL，每进程一个写入者），由后台线程通过有界通道写入，使热路径上的 `record()` 不阻塞；管理面板的读取侧对所有分片执行 `ATTACH` 并 `UNION ALL`。它支撑请求日志检索、按域名的分析以及「任意时间段内的 bots/DDoS」。模块 `event_store`（V243）。参见 [24-request-log.md](24-request-log.md)。

---

## G

### GeoIP
基于 db-ip 数据库的地理富化：国家 + ASN。模块 `geoip`。参见 [20-geoip.md](20-geoip.md)。

### GREASE (Generate Random Extensions And Sustain Extensibility)
RFC 8701 机制：浏览器在 TLS 的 cipher/extension 列表中混入随机的「垃圾」值，以免服务端僵化于固定集合。AEGIS 检测 GREASE 位置异常：真正的 Chrome 会把 GREASE 放在 `cipher[0]`、`ext[0]` 和 `supported_versions[0]`，而伪造者往往硬编码单一排列。模块 `grease_anomaly`（V178，utls 风格），输出 [0,1] 区间的异常分。参见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

---

## H

### Honeypot（蜜罐）
陷阱：诱饵资源与路径，访问它们会自动将客户端标记为恶意。在 AEGIS 中包括：基础 `honeypot`（`HoneypotStore`）、带确定性多步交互场景的 YAML 服务描述符（`honeypot_yaml`，V184，Beelzebub 风格）、LLM 蜜罐（见下）、robots.txt 蜜罐（`robots_honeypot`，V149 —— 对 Disallow 路径的访问会把 Malicious 样本推入 `MlTrainer`）。参见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

### LLM-honeypot（LLM 蜜罐）
以 LLM 生成的可信回答进行响应的蜜罐，并按请求形态的语义哈希（方法、路径模板、请求头名称、请求体形态）做缓存，使同一个扫描器获得连贯的响应，而无需为每个请求付出 LLM 成本。trait `LlmClient`。模块 `llm_honeypot`（V183，Galah 风格），**opt-in**。参见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

### Honeypot self-learn (JA4 self-learn)
JA4 信誉的自学习：从 honeypot/WAF/tarpit 的决策中挖掘「坏」JA4 哈希，并送入信誉数据源。参见 `ja4_reputation`、`online_signature_miner`。参见 [12-reputation.md](12-reputation.md)。

---

## J

### JA3
`ClientHello` TLS 指纹的哈希（版本、cipher suites、extensions、椭圆曲线、点格式）。模块 `ja3`。捕获发生在 `set_client_hello_callback` 回调中，受 fingerprinting 开关控制。参见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

### JA4
JA4+ 家族（FoxIO）的现代 TLS 指纹：由 `ClientHello` 导出的人类可读结构。基础模块 `ja4`。衍生项：

| 术语 | 指纹化对象 | 模块／备注 |
|---|---|---|
| **JA4** | TLS ClientHello（客户端） | `ja4` |
| **JA4H** | HTTP 请求（方法、版本、请求头、cookie） | 属于指纹识别的一部分，与 JA4 交叉校验 |
| **JA4T** | 客户端的 TCP SYN（window、选项） | `tcp_info` / 与 `p0f` 相邻 |
| **JA4L** | TLS 握手延迟（客户端侧） | 延迟测量 |
| **JA4S** | TLS ServerHello（服务端） | `ja4_server`（V126） |
| **JA4X** | X.509 证书 | `ja4_server`（V126） |
| **JA4TS** | 服务端的 TCP SYN-ACK | `ja4_server`（V126） |
| **JA4LS** | 服务端侧延迟 | `ja4_server`（V126） |

运维人员使用服务端家族（`ja4_server`）来检测被攻陷的上游，并监控证书链的稳定性。参见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

### JA4 corpus（JA4 语料库）
经过整理的 JA4 语料库（种子来自 FoxIO）：已知浏览器为 `Verdict::Allow`，已知工具为 `Verdict::Deny`。在信誉数据源之前查询；运维人员的文件可扩展该语料库。模块 `ja4_corpus`（V176）。参见 [12-reputation.md](12-reputation.md)。

### JA4 churn（JA4 变动率）
按滑动窗口计算的每 IP JA4「变动率」评分。高 churn = TLS 指纹轮换（utls / curl-impersonate）。为 ML 特征 `ja4_churn` 供数。模块 `ja4_churn`（V177）。参见 [18-ml-risk-engine.md](18-ml-risk-engine.md)。

### JA4 reputation feed（JA4 信誉源）
JA4 信誉数据源：运维人员把坏 JA4 哈希列表写入文件（社区 CTI、内部 IR、来自 honeypot 的挖掘），模块提供 O(1) 查询 + 热重载。两种匹配方式：完整 JA4（最强）与仅按 cipher 前缀（较弱、更宽）。模块 `ja4_reputation`（V138）。参见 [12-reputation.md](12-reputation.md)。

---

## L

### LAPI
参见 **CrowdSec LAPI**。

### Latency jitter（延迟抖动）
对 tarpit/honeypot/诱饵响应，按对数正态或双峰（类 CDN）分布对响应延迟进行整形，以挫败基于响应时间的指纹识别。模块 `latency_jitter`（V190，LLMHoney 风格），**opt-in**。参见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

---

## M

### ML risk engine（风险引擎）
基于 ML 的风险评分子系统。执行模式：**Observe**（仅观察）、**HighConfidenceEnforce**（仅在高置信度时执行）、**FullEnforce**（完全执行）。模型版本 v1/v2（logistic/gbm）。相关模块：`anomaly`、`fp_correlation`（V137，跨指纹关联：「Chrome JA4 + curl UA」）、`client_consistency`（V145，CreepJS 风格）、`ml_adversarial`（V146）、`timing_entropy`（V189）、`signature_mine`/`online_signature_miner`（签名挖掘）。参见 [18-ml-risk-engine.md](18-ml-risk-engine.md)。

### ModSecurity
经典的 WAF 规则引擎（背景：OWASP CRS 最初就是为它编写的）。AEGIS 不直接使用 ModSecurity，但在精神上与「阶段 + 规则」的思路兼容：按阶段索引的规则计划实现在 `rule_planner`（V181，Coraza 风格）—— 按 `Phase`（uri/headers/body/response）对规则 ID 分桶，并按 severity 排序派发。参见 [10-waf.md](10-waf.md)。

### mTLS (mutual TLS)
双向 TLS 认证 —— 客户端也要出示证书。AEGIS 在 mTLS 下对客户端证书做指纹识别。模块 `mtls_fp`。参见 [08-tls-certificates.md](08-tls-certificates.md)、[11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

---

## N

### Normalisation（归一化）
WAF 匹配之前的多轮请求归一化链（SafeLine 风格）：URL 解码 → HTML 实体 → NFKC 全角 → unicode 易混字符 → 去除 null → 转小写。以有限的遍数运行至不动点。模块 `normalisation`（V179）。参见 [10-waf.md](10-waf.md)。

---

## O

### OWASP CRS (Core Rule Set)
OWASP 核心规则集 —— 开放的 WAF 规则集合。AEGIS 没有直接导入 CRS；取而代之的是自有签名库 + Sigma 规则导入（`sigma`，V196）与按阶段索引的规划器（`rule_planner`）。兼容性体现在「处理阶段」这一概念层面。参见 [10-waf.md](10-waf.md)。

---

## P

### p0f
基于 AEGIS 已捕获的 SYN 观测量（window、MSS、wscale、选项、TTL）对操作系统 / TCP 栈进行被动指纹识别，并归类到操作系统家族，用于「UA 对比协议栈」的交叉校验。模块 `p0f`（V155）。参见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

### PoW (Proof-of-Work)
工作量证明 —— 一个非对称任务：客户端花费数秒 CPU，服务端在微秒内完成校验。SHA-256 hashcash 实现于 `pow_captcha`（V131）；内存困难的替代方案是 `argon2_pow`（V200）。目标是压制那些代理大量会话的单个攻击者。参见 [15-challenge-ladder.md](15-challenge-ladder.md)。

### Privacy Pass
匿名的信任证明令牌（RFC 9576 的一种形式），由 Cloudflare/Apple/Fastly 等签发；通过验证的浏览器会静默通过挑战阶梯。验证器基于 Ed25519。模块 `privacy_pass`（V201）。参见 [16-privacy-pass.md](16-privacy-pass.md)。

### Param profile（参数画像）
可学习的、按端点的参数画像（open-appsec 风格）：对 `(host, endpoint, param)` 维护滑动统计（长度 / 字符集 / 熵）；在观测数达到 `learn_threshold` 后给出异常分。模块 `param_profile`（V180）。参见 [10-waf.md](10-waf.md)。

### Poisoned tarpit（投毒式焦油坑）
带马尔可夫链文本生成器 + 无限内部 HTML 链接的 tarpit，使无视 robots.txt 的 AI 爬虫陷入迷宫，在递归抓取伪造页面时消耗 CPU。按部署确定的随机种子使该语料难以被指纹识别。模块 `poisoned_tarpit`（V147，Iocaine/Nepenthes/HellPot 一脉）。参见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

---

## R

### Rate limiting（限速）
按 IP / 按子网 / 按 URI 限制请求频率，使用 Redis 后端保存跨工作进程的状态。参见 [14-rate-limiting.md](14-rate-limiting.md)。

### Risk engine
参见 **ML risk engine**。

### Reputation（信誉）
对来源的综合信任数据源。构成部分：JA4 self-learn（honeypot/WAF/tarpit）、ASN/CIDR 信誉（Tor/Spamhaus **default-on**）、CrowdSec LAPI（**opt-in**）、威胁情报。实现：`ja4_reputation`、`ja4_corpus`、`asn_reputation`、`crowdsec_api`、`enrichment`。参见 [12-reputation.md](12-reputation.md)。

### Route difficulty（按路由的难度）
按 (host,path) 覆盖挑战难度 + 针对 AI 爬虫的预设（对 GPTBot 之类 +4 位）+ 针对认证端点的预设（+6 位，对 `*/login` 强制 JS-PoW）。模块 `route_difficulty`（V186，Anubis 风格）。参见 [15-challenge-ladder.md](15-challenge-ladder.md)。

---

## S

### Scenarios（场景）
CrowdSec 漏桶（leaky-bucket）风格的行为限速 YAML DSL：语法 `filter / groupby / distinct / capacity / leak_speed / blackhole` 无需写代码即可覆盖行为异常检测。模块 `scenarios`（V199），属于 Arsenal + 执行器的一部分。参见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### Sigma
开放的检测规则格式。AEGIS 通过 CLI `aegis-sigma-import` 将 SigmaHQ 的 YAML 规则（`logsource.category: webserver`）导入为 `crate::config::WafRule` 值。支持通用修饰符集合（contains/startswith/endswith/re）、列表值、单块条件 + 「1 of selection_*」+「selection and not filter」。模块 `sigma`（V196）。参见 [10-waf.md](10-waf.md)。

### SNI (Server Name Indication)
TLS 扩展，客户端在 `ClientHello` 中借此声明所请求的主机名 —— 使单个 IP 能服务多个 TLS 站点并按域名路由。模块 `tls_sni`。参见 [08-tls-certificates.md](08-tls-certificates.md)、[26-sites-and-domains.md](26-sites-and-domains.md)。

### SO_REUSEPORT
一个套接字选项，允许多个进程监听同一端口，由内核分发连接。这是 AEGIS 多进程的基础：工作进程 `aegis-pingora@0..N` 监听同一端口，跨工作进程的状态通过磁盘 + mtime 轮询共享。参见 [06-workers.md](06-workers.md)。

### Site map（站点测绘）
从实时流量中自动发现端点，并对路径做泛化（`/users/12345` → `/users/:id`），按 host 使用有界 LRU。它是管理面板中按域名编辑页面的数据来源。模块 `site_map`（V119）；按域名的策略为 `domain_policy`（V162）。参见 [26-sites-and-domains.md](26-sites-and-domains.md)。

### SQL semantic detector（SQL 语义检测器）
SQL 注入的语义检测器（SafeLine 风格）：对载荷做词法切分（URL 解码 + 处理注释/引号/hex/运算符），并识别「注入的形态」（恒真式、值之后的 UNION、堆叠 DDL、time-blind、引号后的注释）。按设计对 V146/V148 的变异器具有抵抗力。模块 `sql_semantic`（V156）。参见 [10-waf.md](10-waf.md)。

---

## T

### Tarpit（焦油坑）
减速陷阱：可疑连接被保持/拖延，以消耗攻击者的资源。在 AEGIS 中即 `poisoned_tarpit`（见上），同时也是签名挖掘的来源（`online_signature_miner`，V107：tarpit 的决策会记录 payload，后台挖掘器定期提取排序后的候选并通过 `/admin/api/mined_signatures` 提供）。参见 [17-honeypot-tarpit.md](17-honeypot-tarpit.md)。

> 关于 slowloris 的说明：AEGIS 的反应就是 AEGIS 的反应 —— 收割（reaping）慢连接被视为防御，而不是过载（参见 `benchmark_flood` 中的裁决逻辑）。参见 [28-benchmarking.md](28-benchmarking.md)。

### Threat intel / enrichment（威胁情报 / 富化）
覆盖所有情报来源（`ja4_reputation`、`asn_reputation`、`threat_intel`、`geoip`、`ja4_corpus`）的可缓存门面，带按来源的 TTL 与来源溯源。模块 `enrichment`（V198，WISE 风格）。威胁分析（`threat_analytics`，V121）区分按 IP 的机器人检测与分布式 DDoS（僵尸网络）。参见 [22-enrichment.md](22-enrichment.md)、[12-reputation.md](12-reputation.md)。

### Timing entropy（时序熵）
基于时序熵的 ML 特征：服务端分析由客户端 `client_consistency`（V145）采集的鼠标抖动 / 滚动节奏。均匀定时器检测器输出 ∈ [0,1] 的异常分。模块 `timing_entropy`（V189）。参见 [18-ml-risk-engine.md](18-ml-risk-engine.md)。

---

## W

### WAF (Web Application Firewall)
Web 应用防火墙 —— 在应用层过滤 HTTP 请求。AEGIS 的 WAF：Aho-Corasick 签名 + Sigma 规则集 + 复合规则 + webshell 检测，构建在多轮归一化（`normalisation`）之上，并配有语义 SQLi 检测器（`sql_semantic`）、阶段规划器（`rule_planner`）与参数画像（`param_profile`）。基础模块：`filters`、`dsl`、`config::WafRule`。参见 [10-waf.md](10-waf.md)。

### Webshell signatures（Webshell 签名）
WAF 规则库中用于检测 web shell（含 PHP webshell）的签名。参见 [10-waf.md](10-waf.md)。

### WebAuthn
挑战阶梯中最强的一层（硬件/平台认证器）。在链式信任（`chained_trust`）中给出最长的信任窗口（7 天）。参见 [15-challenge-ladder.md](15-challenge-ladder.md)。

---

## X

### XDP (eXpress Data Path)
Linux 内核中的快速路径（基于 eBPF），在网络协议栈之前丢弃/重定向数据包。AEGIS 将 XDP 用作内核快速路径；执行层的回退链为 **XDP → nftables → iptables → userspace**（`xdp`、`nftables_backend` V128、`iptables_backend` V130；`open_with_fallback()` 返回第一个成功初始化的后端，它们都实现共同的 `XdpHandle`）。参见 [13-xdp-ebpf.md](13-xdp-ebpf.md)。

---

## 其他术语

### Actuator（执行器）
主动响应框架：注册表 `(kind, target) → Actuator`，带回滚 TTL 与时间轮。它取代了零散的「永不过期的 XDP 丢包」模式。模块 `actuator`（V197）。参见 [21-arsenal-scenarios.md](21-arsenal-scenarios.md)。

### Admin API
约 86 条 `/admin/api/*` 路由；通过 `x-admin-token` / 会话 / 角色进行授权。模块 `admin_auth`、`web_admin`、`server`。参见 [30-admin-api.md](30-admin-api.md)。

### Admin 面板
构建在 Admin API 之上的 37 个页面的 React 面板。模块 `admin_ui`。参见 [29-admin-panel.md](29-admin-panel.md)。

### ACME
证书自动签发（Let's Encrypt）：HTTP-01 挑战应答器 + 证书落盘布局 + 续期编排器。协议驱动通过 trait `AcmeClient` 注入；具体实现基于 `instant-acme`（`acme` V134、`acme_instant` V234），账户密钥以 `O_CREAT|O_EXCL` + chmod 0600 写入。参见 [08-tls-certificates.md](08-tls-certificates.md)。

### Benchmark / capacity projection（基准测试 / 容量预测）
CPU 整数 / SHA-256 / 内存带宽微基准 + 使用标定线性模型的 RPS 预测（forwarding/TLS/WAF）（`benchmark`，V240）；loopback 上的洪泛测试（`benchmark_flood`，V241）；与 nginx 的对比 + 安全能力矩阵（`benchmark_compare`，V245）。

> 诚实的说明：AEGIS 的基准通道是**进程内引擎**，而非完整的 pingora 二进制。硬件 SHA 基准是按核心的，在没有硬件 SHA 加速的 VM 内数值偏低，此时容量预测偏悲观。安全能力矩阵是诚实而有力的论据；AEGIS **并不**声称在纯速度上快于真实的代理。参见 [28-benchmarking.md](28-benchmarking.md)、[27-performance-tuning.md](27-performance-tuning.md)。

### ClamAV scanner（ClamAV 扫描器）
通过 INSTREAM 协议对请求体（multipart/octet-stream 上传）进行扫描的 ClamAV TCP 扫描器。**默认关闭**；通过 `AEGIS_CLAMAV_ADDR=host:3310` 启用。模块 `clamav_scanner`（V129）。

### ClientHello callback
TLS 指纹的捕获点 —— `set_client_hello_callback`，受 fingerprinting 开关控制。cipher/extensions/ALPN/SNI/GREASE 都在这里读取。参见 [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

### H2 budget (HTTP/2 control-frame budgets)
对每个 `FrameKind` 按连接维护的令牌桶（Tempesta 风格）。它封堵了 Rapid Reset / Settings flood / Ping flood / CONTINUATION flood 这一类攻击。模块 `h2_budget`（V182）。相邻的还有 H2 指纹（`h2_fp`）与 HTTP/3 指纹（`h3_fp`）。参见 [07-protocols.md](07-protocols.md)。

### Real-IP resolver（真实 IP 解析器）
从 `CF-Connecting-IP` / `X-Forwarded-For` 解析真实客户端 IP，**仅当** TCP 对端属于运维人员配置的可信代理集合时才生效。若未设置 `AEGIS_BEHIND_CLOUDFLARE` 与 `AEGIS_TRUSTED_PROXIES`，行为零变化。模块 `real_ip`。参见 [04-configuration.md](04-configuration.md)。

### SecurityEvent
结构化的安全事件（V116）+ 按决策的 Prometheus 计数器。每个 Allow/Challenge/Deny/Throttle/Observed 决策的统一发出点；标签的基数受限（原因为 `&'static str`）。模块 `security_event`。参见 [25-metrics-telemetry.md](25-metrics-telemetry.md)。

### Sicherheitstacho
T-Pot Sicherheitstacho 的事件导出方案：将 AEGIS 的安全事件渲染为 Sicherheitstacho 兼容的 NDJSON，以便与欺骗防御生态互操作。模块 `sicherheitstacho`（V185）。参见 [25-metrics-telemetry.md](25-metrics-telemetry.md)。

### TUI
终端仪表盘（Ratatui）：作用于 `DashboardSnapshot` 值的纯渲染函数。二进制 `aegis-tui` 从 Admin API 获取快照并喂给它。模块 `tui`（V133）。

### Topology（拓扑）
面向管理面板 Workers 页面的工作进程拓扑运行时自省（主机 CPU 的事实信息 + 对 `aegis-pingora` 进程的实时扫描）。模块 `topology`（V232）。参见 [06-workers.md](06-workers.md)。

### Updates（更新）
Phase 1：更新检查 —— 轮询 Gitea/GitHub 兼容的 Releases API，将标签分类到 stable/beta/nightly 通道，在管理面板中展示「update available + changelog」。**不应用**更新（由运维人员驱动）。Phase 2/3：配置快照/恢复（`update_snapshot`）、`releases/<version>/` 布局 + 符号链接的原子切换（`update_layout`）、apply-status 代理（`update_apply`）。模块 `updates`（V208）、`update_snapshot`（V209）、`update_layout`（V210）、`update_apply`（V211）。参见 [44-updates-migration.md](44-updates-migration.md)。

---

## 二进制与构建（参考）

| 名称 | 角色 |
|---|---|
| `aegis` | hyper + CLI |
| `aegis-pingora` | 主数据平面（特性 `pingora`+`xdp`），多进程形式 `aegis-pingora@0..N` |
| `aegis-tui` | 终端仪表盘 |
| `aegis-sigma-import` | 将 Sigma 规则导入为 `WafRule` |
| `aegis-updater` | 应用更新（Phase 3） |

安装：`install.sh`（`curl | bash`）+ systemd target + 模板 unit。构建配置：thin-LTO / cgu16 / incremental + `AEGIS_BUILD_OPT=max` + `mold`。参见 [03-installation.md](03-installation.md)、[27-performance-tuning.md](27-performance-tuning.md)。

---

## 参见

- [01-overview.md](01-overview.md) —— AEGIS 总体概览
- [02-architecture.md](02-architecture.md) —— 子系统架构
- [23-security-model.md](23-security-model.md) —— 安全模型与矩阵
- 42-текущее-состояние-STATUS.md —— 目前已实现的内容
- [47-faq-troubleshooting.md](47-faq-troubleshooting.md) —— FAQ 与故障排查
