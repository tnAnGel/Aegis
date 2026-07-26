# 信誉源 (JA4、ASN/CIDR、CrowdSec)

**语言：** [English](../en/12-reputation.md) · [Русский](../ru/12-reputation.md) · **中文**

AEGIS 汇聚了多个相互独立的信誉来源——自学习的 JA4 源、ASN/CIDR 列表（Tor + Spamhaus DROP，默认启用）、人工整理的 JA4 语料库、基于 threat-intel 文件的 IP 拒绝列表，以及 CrowdSec LAPI。它们全部从本地文件加载，并按 mtime 热重载；没有任何一个会从数据平面直接发起 HTTPS 请求。本文档描述代码实际做了什么，以及哪些功能只是部分实现。

代码来源：[src/ja4_reputation.rs](../../src/ja4_reputation.rs)、[src/asn_reputation.rs](../../src/asn_reputation.rs)、[src/ja4_corpus.rs](../../src/ja4_corpus.rs)、[src/crowdsec_api.rs](../../src/crowdsec_api.rs)、[src/filters/threat_intel.rs](../../src/filters/threat_intel.rs)、[install.sh](../../install.sh)（`ensure_reputation_feeds`），装配代码见 [src/bin/aegis-pingora.rs](../../src/bin/aegis-pingora.rs)。

相关文档：[TLS 指纹](./11-tls-fingerprinting.md)、GeoIP（国家与 ASN）、富化与 threat-intel、ML 与风险引擎、Honeypot 与 tarpit、Defence Arsenal。

---

## 1. 概览：五个信誉来源

| 来源 | 模块 | 键 | 信号类型 | 默认 | 应用位置 |
|---|---|---|---|---|---|
| JA4 信誉源 | [`ja4_reputation.rs`](../../src/ja4_reputation.rs)（V138/V244） | JA4 字符串 / cipher 哈希 | ML 特征 `ja4_reputation` [0..1] | **ON**（自学习） | `extract_ml_features_v2` |
| JA4 语料库（seed） | [`ja4_corpus.rs`](../../src/ja4_corpus.rs)（V176） | JA4 字符串 / cipher 哈希 | Allow / Deny / Unknown | 内置于二进制 | Arsenal，抬高 `ja4_reputation` |
| ASN/CIDR 信誉 | [`asn_reputation.rs`](../../src/asn_reputation.rs)（V142/V144） | AS 号 / CIDR | ML 特征 `asn_reputation` [0..1] | **ON** | `extract_ml_features_v2` |
| Threat-intel 拒绝 | [`filters/threat_intel.rs`](../../src/filters/threat_intel.rs)（V113/V237） | IP / CIDR | 硬性 Deny（HTTP 403） | OFF（默认无路径） | 过滤器链 |
| CrowdSec LAPI | [`crowdsec_api.rs`](../../src/crowdsec_api.rs)（V157） | IP / Range / Country | 决策（decisions）导出 | 半成品（wire types） | 外部 bouncer |

裁决严格程度上的关键区别：

- **JA4 / ASN 信誉**是*软*信号：返回一个 `[0..1]` 的数值，作为其中一个特征进入 ML 打分器。其本身不做拦截。参见 ML 与风险引擎。
- **Threat-intel** 是*硬*过滤器：命中即立刻 `FilterAction::Deny { status: 403 }`。
- **JA4 语料库**是双向的：`Deny` 会把 `ja4_reputation` 抬到 1.0；`Allow` 只能*抑制*怀疑度，但不能把它压到不可伪造的 baseline 之下（见 §4）。

---

## 2. JA4 信誉源 (`ja4_reputation.rs`)

### 2.1. 用途与文件格式

一个自学习的索引，收录已知属于恶意工具（sqlmap、hydra、nuclei、recon-ng……）或僵尸网络的 JA4 哈希。运维把文件放进信誉目录，AEGIS 就会抬高每个 JA4 命中的请求的分值。

格式为纯文本，每个非空、非注释行一条记录（`#` 为注释）。支持两种形式（解析器为 `parse_into`，[src/ja4_reputation.rs:258](../../src/ja4_reputation.rs)）：

```text
# 完整 JA4 字符串 <token> [tag]
t13d1516h2_8daaf6152771_b186095e22b6  sqlmap

# 仅 cipher 哈希（中间 12 个字符的块）——社区源
# 往往正是发布这一部分，因为它在浏览器升级时更稳定
8daaf6152771    nuclei
```

token 的分类规则：

- 含 `_` → 作为 **完整 JA4** 建立索引（精确匹配）；
- 恰好 12 个十六进制字符 → 作为 **cipher-prefix** 建立索引（按中间块匹配）；
- 否则该 token 被静默忽略（源的正确性由运维负责）。

tag 对 AEGIS 而言是不透明的：它会进入指标和审计日志。默认情况下，如果没有 tag，则为 `"unknown"`。

### 2.2. lookup 与打分逻辑

`lookup()`（[src/ja4_reputation.rs:193](../../src/ja4_reputation.rs)）先查完整表（最强信号），再查 cipher-prefix（中间块，12 个十六进制字符）。结果由 `reputation_feature()` 转换为特征值：

| 匹配类型 | 特征值 | 说明 |
|---|---|---|
| `MatchKind::Full` | **1.0** | 在 CTI 源中精确命中 JA4 |
| `MatchKind::CipherPrefix` | **0.6** | 较弱——浏览器可能与某工具共用同一份 cipher 列表 |
| 未命中 | **0.0** | |

索引结构是 `RwLock` 下的两个 `HashMap`（full + cipher）。哈希使用 AHash（抗 DoS）：按 V230 审计结论，键直接由客户端 TLS 握手派生，因此这里禁止使用 FxHash（攻击者可以构造握手来探测哈希碰撞）。

### 2.3. 自学习 (`observe_bad`，V244)

最主要的特点是：**并不存在公开的恶意 JA4 批量列表**，而且工具的 JA4 会与通用的 Go/Python 客户端相撞——静态默认列表会倾向于产生误报。因此开箱即用的来源是从确认为恶意的流量中自学习。

`observe_bad(ja4, tag)`（[src/ja4_reputation.rs:110](../../src/ja4_reputation.rs)）只在已判定为恶意的结局上被调用：

- **honeypot trap** 与 **WAF 签名命中**——[src/proxy/pingora_http.rs:3106](../../src/proxy/pingora_http.rs)（tag = 触发的过滤器名）；
- **tarpit**——[src/proxy/pingora_http.rs:3279](../../src/proxy/pingora_http.rs)（tag = `"tarpit"`）。

记录下来的 JA4 会以原子方式（`O_APPEND`）追加写入落地文件 `ja4-observed.txt`，该文件同样在 `paths` 中，因此兄弟 worker 与重启后的进程都能通过 mtime 重载拿到它们。

保护性限制：

- **上限。** `OBSERVED_CAP = 50_000` 条完整 JA4 记录——限制内存占用，并防止轮换 JA4 的攻击者灌爆学习集。
- **去重。** 再次观察到已知 JA4 → 直接返回，不产生 I/O（在读锁下开销很低，写锁下做二次检查）。
- **退化 JA4 的防护 (V246)。** `is_degenerate_ja4()`（[src/ja4_reputation.rs:233](../../src/ja4_reputation.rs)）拒绝从“空 ClientHello”上学习。如果 ClientHello 字段的抓取返回为空，则 cipher/extension 哈希 = 截断的 `SHA256("")` = `"e3b0c44298fc"`——**对每个客户端都相同**。基于一次恶意请求学习这样的 JA4，会把全部流量都打上标记。凡是 cipher 块或 extension 块等于空输入哈希的 JA4 都会被跳过。

  🟡 这是**安全网**，而不是真正的修复。正确的解法是抓取真实的 ClientHello 字段；该防护只是避免灾难发生。代码注释中就是这么直说的（[src/ja4_reputation.rs:114-119](../../src/ja4_reputation.rs)）。

- **空操作条件。** 若自动学习被关闭（没有 `observed_path`）、JA4 为空或不含 `_`、JA4 已退化，或已达到上限，`observe_bad` 什么也不做。

`learned_count()` 是该 worker 生命周期内自动学习条目的计数器，会显示在面板上，方便运维看到这个源是“活的”。

### 2.4. 启用与环境变量开关

在 `aegis-pingora` 中 JA4 信誉**默认启用**（[src/bin/aegis-pingora.rs:1229](../../src/bin/aegis-pingora.rs)）。路径集合包括：

1. 来自 `AEGIS_JA4_REPUTATION` 的运维自有源（以冒号分隔的路径）；
2. `ja4-observed.txt`——自动学习的落地文件（通过 `.with_observed_path()`）；
3. `ja4-crowdsec.txt`——若配置了 CrowdSec LAPI，则由 refresh 任务填充的源（见 §6.3）；即使文件不存在，该路径也会被监视。

| Env | 取值 | 效果 |
|---|---|---|
| `AEGIS_JA4_REPUTATION` | `0` / `false` / `off` | 完全关闭 JA4 信誉 |
| `AEGIS_JA4_REPUTATION` | `path1:path2:…` | 增加运维自有源（冒号为分隔符） |
| `AEGIS_REPUTATION_DIR` | 路径 | 信誉目录（默认 `/var/lib/aegis/reputation`） |

> ⚠️ 适用范围：这里描述的全部 JA4/ASN 信誉功能都实现在 **`aegis-pingora`** 二进制中。遗留的 hyper 路径（`aegis`）不会执行这套装配。参见[架构](./02-architecture.md)。

---

## 3. JA4 语料库——人工整理的 seed (`ja4_corpus.rs`)

与 V138（运维的 CTI 列表）不同，V176 语料库**编译进二进制**，并且在运维源之前就作为“全局真值” baseline 被查询。

### 3.1. 内置 seed

`SEED`（[src/ja4_corpus.rs:60](../../src/ja4_corpus.rs)）约有 30 条形如 `(ja4_or_cipher, verdict, label)` 的记录。共三种裁决：

- **Allow**——已知的稳定浏览器（Chrome/Firefox/Safari/Edge——Windows/macOS/Linux/iOS/Android）。语义是：“这个指纹确实由数以百万计的用户发出”。
- **Deny**——已知工具：`curl`、`python-requests`、`python-urllib3`、`go-default-http-client`、`java-okhttp`、`java-apache-httpclient`、`sqlmap`、`nikto`、`nuclei`、`hydra`、`wpscan`。
- **Unknown**——不在语料库中 → 把决定权交给 V137 fp_correlation / V138 reputation / ML。

也有 cipher-prefix 记录（覆盖更广/更弱）：`8daaf6152771` → chrome-family-cipher（Allow）、`56d4dd6ee7df` → sqlmap-family-cipher（Deny）等等。

> 🟡 来自代码本身的诚实说明：这些哈希取自 FoxIO JA4+ 的公开快照以及自有 honeypot 挖掘；“保守——只收录在多个部署中大量观察到的条目”。seed 很小且是固定的。

### 3.2. 运维扩展

`extend_from_path()`（[src/ja4_corpus.rs:141](../../src/ja4_corpus.rs)）从文件追加记录。格式为 `<ja4_or_cipher> <verdict> <label>`，其中 verdict ∈ `allow` / `deny`（若省略或无法识别，**默认为 `deny`**）。文件缺失时静默跳过（对 compose 友好）。

### 3.3. 对打分的影响

逻辑位于 [src/proxy/pingora_http.rs:1568-1599](../../src/proxy/pingora_http.rs)：

- **Deny** → `ja4_reputation = ja4_reputation.max(1.0)`（把特征抬到最大值）。
- **Allow** → `(ja4_reputation - 0.25).max(baseline).max(0.0)`。这就是 **H9b-clamp**：JA4 由客户端选择（攻击者完全控制自己的 ClientHello），因此 Allow 裁决**不能把怀疑度压到运维 V138 源所设定的、不可伪造的 baseline 之下**。伪造成“我是 Chrome”的 JA4 最好也只是中性，绝不会变成负向。
- **Unknown** → 不做改变。

此外，**JA4 churn**（V177，[ja4_churn.rs](../../src/ja4_churn.rs)）也在此处折叠进来：当 churn > 0.6 时 `ja4_reputation = max(churn)`。详见 [TLS 指纹](./11-tls-fingerprinting.md)。

与此并行（V199，[src/proxy/pingora_http.rs:2687](../../src/proxy/pingora_http.rs)），语料库的 `Deny` 可以作为独立的 actuator 出现在 Arsenal 中，并带有 `SecurityEvent` 日志（`ja4_corpus_deny`）。计数器 `ja4_corpus_lookups`/`_deny_hits`/`_allow_hits` 会被导出。参见 Arsenal。

---

## 4. ASN / CIDR 信誉 (`asn_reputation.rs`)

### 4.1. 用途与两种记录形式

由运维/refresh 任务提供的恶意 ASN 列表（主机托管、代理农场、滥用型 VPN、Tor 集群）加上恶意 CIDR。`lookup()` 返回 `[0..1]` 的分值，写入 ML 槽位 `asn_reputation`（V139/V140）。

为什么两种形式都要（注释见 [src/asn_reputation.rs:8](../../src/asn_reputation.rs)）：

- **ASN DB**（MaxMind GeoIP2-ASN 或等价物）最适合主机托管/中转：一个坏 AS 可以覆盖该 AS *所有*现有和未来的地址块。
- **CIDR 列表**更便于手工维护，不需要数据库；对 Spamhaus DROP、FireHOL 聚合列表以及自有 threat-intel 导出而言，这才是正确的形式。

> AEGIS 内核**不附带默认列表**——正确的列表与具体部署强相关（SaaS 讨厌 DigitalOcean 的流量，而游戏商店必须放行它）。默认的 `asn-cidr.txt` 由安装/refresh 任务填充（Tor + Spamhaus），见 §6。

### 4.2. 文件格式

```text
# ASN 记录 — AS<number>  <score>  [tag]
AS14061  0.8  digitalocean
AS16509  0.7  aws-ec2

# CIDR 记录 — <cidr>  <score>  [tag]
185.220.100.0/22  1.0  tor-exit
1.2.3.4/32        0.9  burned-host
```

解析器（[src/asn_reputation.rs:222](../../src/asn_reputation.rs)）：第一个字段是 token，第二个是**必填**的 `f32` 分值（没有分值的行会被跳过），第三个是 tag（默认 `"unknown"`）。分值执行 `clamp(0.0, 1.0)`。前缀为 `AS`/`as`（不区分大小写）→ ASN 记录；否则走 `parse_cidr()`（v4 前缀 ≤ 32，v6 前缀 ≤ 128）。无法解析的 token 被静默跳过。

### 4.3. lookup 逻辑

`lookup(ip)`（[src/asn_reputation.rs:166](../../src/asn_reputation.rs)）：

1. **ASN 路径**——若 `AsnLookup::asn(ip)` 返回了编号且它存在于 `asn_index` 中。
2. **CIDR 路径**——对每个地址族的 Vec（v4/v6）做线性扫描，按掩码挑出匹配项。
3. **若命中多条，则返回分值最高的那条**（堆叠记录的运维会得到最强的信号）。

性能：ASN 为 O(1)，CIDR 最坏情况为 O(n)，但 AEGIS 风格的运维通常维持在 O(10²) 条 CIDR，这在 line-rate 下是没问题的。

### 4.4. ASN GeoIP 数据库

以 ASN 为键的记录（`AS<num>`）**只有在加载了 ASN 数据库时才会匹配**。`AsnLookup` trait（[src/asn_reputation.rs:61](../../src/asn_reputation.rs)）抽象了 IP→ASN 的映射；默认的 `NoopAsnLookup` 永远返回 `None` → 没有 ASN 数据库的部署仍可工作，但只会匹配 CIDR 记录。

在 `aegis-pingora` 中（[src/bin/aegis-pingora.rs:1277](../../src/bin/aegis-pingora.rs)），已加载的 GeoIP 句柄被包装为 `GeoIpAsnLookup`，因此以 AS 为键的记录能够解析。ASN 数据库（`dbip-asn-lite.mmdb`）通过 `[geoip].asn_db_path` 挂载，并由 refresh 任务填充（db-ip ASN-lite，每月一次）。详见 GeoIP（国家与 ASN）。

### 4.5. 启用与环境变量开关

ASN/CIDR 信誉**默认启用**（[src/bin/aegis-pingora.rs:1260](../../src/bin/aegis-pingora.rs)）。路径集合为：来自 `AEGIS_ASN_REPUTATION` 的运维源 + 默认的 `asn-cidr.txt`（即使文件不存在也会被监视）。

| Env | 取值 | 效果 |
|---|---|---|
| `AEGIS_ASN_REPUTATION` | `0` / `false` / `off` | 关闭 ASN/CIDR 信誉 |
| `AEGIS_ASN_REPUTATION` | `path1:path2:…` | 增加运维自有源 |

---

## 5. Threat-intel 拒绝 (`filters/threat_intel.rs`)

### 5.1. 与 IP ACL 的区别及用途

这是一个**硬性 deny 过滤器**，独立于运维的 `IpAclFilter`（后者存在于配置中，只在配置重载时才刷新）。Threat-intel 持有 `Arc<RwLock<HashSet>>` 以及若干 CIDR Vec，由后台任务从本地文件更新——运维用 cron+curl 把源拉到某个路径，AEGIS 按 mtime 重新读取。

为什么用本地文件而不是直接发 HTTPS 请求（注释见 [src/filters/threat_intel.rs:12](../../src/filters/threat_intel.rs)）：不想把第二个 HTTPS 客户端及证书固定（cert-pinning）的攻击面拉进代理；运维本来就有自己向付费源认证的方式（curl+token、GitHub Actions、Vault）；mtime 免费提供了幂等性。

### 5.2. 文件格式

每行一条记录。`#` 之后的一切都是注释（包括行尾注释）。含 `/` 的行 → CIDR（v4/v6），否则是裸 IP → 进入精确匹配的 HashSet。解析器是 `parse_feed_v113`（[src/filters/threat_intel.rs:202](../../src/filters/threat_intel.rs)）。

```text
# AbuseIPDB / Spamhaus DROP / FireHOL 导出
203.0.113.5
192.168.0.0/24
2001:db8::/32        # 支持 IPv6
```

> ⚠️ 代码中的文档不一致：`ThreatIntelConfig` 的 docstring（[src/config.rs:648](../../src/config.rs)）仍写着 “CIDRs not supported yet”，但这已经过时——从 V113 起 CIDR 已被完整支持（见测试 `cidr_v4_range_blocks_any_member` / `cidr_v6_range_blocks_any_member`）。

### 5.3. CIDR 合并 (V125)

每次重载时，相邻和重叠的 CIDR 都会被合并（`coalesce_v4` / `coalesce_v6`，[src/filters/threat_intel.rs:261](../../src/filters/threat_intel.rs)）：三趟处理——(net,mask)→区间、区间排序+归并、再分解为最小的 CIDR 集合。覆盖范围无损保留；在真实的公开源上（Spamhaus DROP、FireHOL L1+2）通常能减少 30…50% 的条目 → 线性扫描更快。`coalesce_preserves_coverage_end_to_end` 验证合并前能匹配的每个 IP，在合并后依然能匹配。

### 5.4. 热路径与 fast-path 哨兵 (V237)

`check()`（[src/filters/threat_intel.rs:405](../../src/filters/threat_intel.rs)）：

1. **空集合快速路径。** `has_entries: AtomicUsize` 在重载时以 `Release` 写入，在每个请求上以 `Acquire` 读取。为零时——立即 `Allow`，一次 RwLock 都不用获取（适用于纯转发 / 没有配置源的场景）。
2. 否则：精确匹配的 HashSet（O(1)）→ 未命中则进行 CIDR 扫描。
3. 命中 → `FilterAction::Deny { status: 403 }`（冷路径构造函数 `ip_deny_cold`，V230，以便热的 Allow 路径对 icache 保持紧凑）。

### 5.5. 配置 (TOML/DSL)

`ThreatIntelConfig`（[src/config.rs:648](../../src/config.rs)）：

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `paths` | `Vec<String>` | `[]`（过滤器不生效） | deny 源的路径 |
| `refresh_secs` | `u64` | `300` | 多久重新读取一次文件 |

`config_enabled()` 永远为 `true`——ThreatIntel 没有 on/off 开关：空的源是无害的（`Allow`）。运维可以通过 Web UI 按域名强制关闭它（V231）。关于规模的细节：对于 10⁵ 条以上的源，代码建议使用 XDP CIDR maps（内核态查找）——参见 [XDP/eBPF](./13-xdp-ebpf.md)。

---

## 6. 源的安装与每日刷新 (`install.sh`)

`ensure_reputation_feeds`（[install.sh:788](../../install.sh)）创建 `/var/lib/aegis/reputation`，安装 `aegis-refresh-feeds` 脚本和 systemd timer。

### 6.1. refresh 任务填充哪些内容

脚本 `/usr/local/bin/aegis-refresh-feeds`（尽力而为；守护进程按 mtime 热重载变更内容，无需重启）：

| 目标 | 来源 | 写入记录 |
|---|---|---|
| **Tor 出口节点** | `https://check.torproject.org/torbulkexitlist` | `<ip>/32 0.5 tor-exit` → `asn-cidr.txt` |
| **Spamhaus DROP** | `https://www.spamhaus.org/drop/drop.txt` | `<cidr> 0.8 spamhaus-drop` → `asn-cidr.txt` |
| **db-ip ASN-lite** | `download.db-ip.com/.../dbip-asn-lite-<YYYY-MM>.mmdb.gz` | → `geoip/dbip-asn-lite.mmdb` |
| **CrowdSec JA4**（opt-in） | `${CROWDSEC_LAPI_URL}/v1/decisions?scope=ja4` | `<value>\tcrowdsec` → `ja4-crowdsec.txt` |

只有当 `asn-cidr.txt` 至少包含一行非注释内容时才会被安装（通过 `install -m 0644` 原子完成）。Tor 得到 **0.5** 分（signal），Spamhaus DROP 得到 **0.8** 分（abuse）。

### 6.2. 每日定时器

`aegis-refresh-feeds.timer`（[install.sh:880+](../../install.sh)）：

```ini
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
```

`enable --now` → 安装时立即执行一次种子填充（尽力而为；若网络不通，模块保持惰性）。Service 为 `Type=oneshot`、`After=network-online.target`。

### 6.3. 通过 refresh 消费 CrowdSec（opt-in）

从 CrowdSec LAPI 拉取 JA4 决策是 opt-in 的，通过 `/etc/aegis/feeds.env` 配置：

```bash
# /etc/aegis/feeds.env
CROWDSEC_LAPI_URL=http://127.0.0.1:8080
CROWDSEC_LAPI_KEY=<bouncer-api-key>
```

当这些变量被设置后，refresh 任务会带上 `X-Api-Key` 发起 `GET .../v1/decisions?scope=ja4`，然后由一行 Python 挑出包含 `_` 的 `value` 字段（即 JA4 字符串），以 tag `crowdsec` 写入 `ja4-crowdsec.txt`。该文件已经在 JA4 信誉的 `paths` 中（§2.4），会被 mtime 重载捡起。

> 🟡 这正是 [crowdsec_api.rs](../../src/crowdsec_api.rs) 中被称为 “small follow-up” 的“消费方向”——它实现在 Rust 之外的 refresh 脚本里，而且只针对 JA4 scope。

---

## 7. CrowdSec LAPI (`crowdsec_api.rs`)

### 7.1. 已实现的部分 (V157)

该模块实现的是**暴露方向**：AEGIS 以 CrowdSec Local API 的格式对外提供自己的决策，使任何现成的 bouncer（nginx、HAProxy、Cloudflare worker、firewall-iptables、Caddy、kubernetes-ingress……）都能成为 AEGIS 决策的执行者。

Wire 类型（[src/crowdsec_api.rs:45](../../src/crowdsec_api.rs)）：

- `Decision { id, kind ("type"), scope, value, duration, scenario, origin }`——bouncer 实际会消费的那个子集。
- `DecisionStream { new, deleted }`——`GET /v1/decisions/stream` 的形状。
- `AegisDecision`——适配器进行转换的内部形式。

裁决映射（`AegisDecisionKind::as_crowdsec_str`）：`Ban → "ban"`、`Captcha → "captcha"`、`Throttle → "throttle"`。`scope` 恒为 `"Ip"`，`origin` 恒为 `"aegis"`，`scenario` = `"aegis/<reason>"`。`format_duration()` 输出 CrowdSec 风格的字符串（`1d4h`、`4h30m`、`5m30s`）。

bouncer 认证——`validate_bouncer_key()`（[src/crowdsec_api.rs:169](../../src/crowdsec_api.rs)）：将 `X-Api-Key` 的密钥与运维提供的 `(key, label)` 允许集合做常数时间比较（`ct_eq`）。

### 7.2. 未实现的部分——诚实说明

> 🟠 **`crowdsec_api.rs` 是 wire 类型 + 适配器，而不是已挂载的 HTTP 路由。** docstring 中直说了：“Operator wires the actual HTTP route handler”。该模块把内部的拒绝状态转换成 decision 形状并校验密钥，但是：
> - `build_stream()` 把 `deleted` 留空——“caller fills from its tracked-removed set”；已删除决策的跟踪与单调递增的 id 都在调用方一侧。
> - 不存在现成的、从运行时状态构造 `AegisDecision` 的构造器——注释说明由运维的适配器代码从 DynamicTrust/ResponseCache/RiskEngine/ML 构造它们。
> - 消费方向（AEGIS 读取别人的 CrowdSec）只实现了一部分，而且在 Rust 之外——在 refresh 脚本中，仅针对 JA4 scope（§6.3）。

换句话说：代码中的 CrowdSec 集成是**扎实的半成品 + 对 serde/duration/auth 的完整测试覆盖**，但不是开箱即用、端到端挂载好的服务。

---

## 8. 源的热重载

三个基于文件的源（JA4、ASN/CIDR、threat-intel）都由后台任务 `PingoraBackground`（[src/proxy/pingora_background.rs](../../src/proxy/pingora_background.rs)）重载——粗粒度 tick **默认 30 秒**。每个 tick 都会检查已配置路径的 mtime（`any_file_changed`，[src/ja4_reputation.rs:286](../../src/ja4_reputation.rs)），有变化时调用 `reload()`。

一个关键的安全保证（在 JA4/ASN/threat-intel 中完全一致）：**文件消失或不可读时不会把索引清空**。`reload()` 构建新索引，并且只有在 `had_any == true`（至少读到了一个文件）时才做替换。否则，源短暂消失一秒引发的重载竞态就会为机器人打开闸门。测试 `missing_file_preserves_prior_index` / `reload_from_*_file_works` 固化了这一行为。

---

## 9. 环境变量汇总

| Env | 默认值 | 模块 | 用途 |
|---|---|---|---|
| `AEGIS_REPUTATION_DIR` | `/var/lib/aegis/reputation` | 全部 | 信誉文件目录 |
| `AEGIS_JA4_REPUTATION` | （未设置 → **ON**） | ja4_reputation | `0/false/off` 关闭；路径以 `:` 分隔 |
| `AEGIS_ASN_REPUTATION` | （未设置 → **ON**） | asn_reputation | `0/false/off` 关闭；路径以 `:` 分隔 |
| `CROWDSEC_LAPI_URL` | （未设置） | refresh 任务 | `/etc/aegis/feeds.env`，opt-in 的 JA4 消费 |
| `CROWDSEC_LAPI_KEY` | （未设置） | refresh 任务 | LAPI 的 API 密钥 |

配置段：

| 字段 | 默认值 | 模块 |
|---|---|---|
| `threat_intel.paths` | `[]` | threat_intel |
| `threat_intel.refresh_secs` | `300` | threat_intel |
| `[geoip].asn_db_path` | （见 GeoIP） | asn_reputation（以 ASN 为键） |

---

## 10. 诚实声明 (Honesty caveats)

1. **信誉 ≠ 完整防护。** JA4/ASN 信誉是 `[0..1]` 的软 ML 特征，不是拦截动作；裁决由风险引擎做出（ML 与风险引擎）。Threat-intel 是硬性 403，但要求运维自己去填充源。在 volumetric L3/L4 洪水下，即使是瞬时 deny 也仍然需要一条入站连接——需要上游防护（BGP/CDN），参见 BGP RTBH 与 SECURITY-AUDIT。

2. **JA4 由客户端控制。** 攻击者完全掌控自己的 ClientHello。因此语料库的 `Allow` 不能把怀疑度压到不可伪造的 baseline 之下（H9b-clamp，§3.3），而自学习会对退化的 JA4 做防护（§2.3）。这是指纹类信号的已知局限。

3. **退化 JA4 的防护是安全网，不是修复。** `is_degenerate_ja4` 能抓住“空 ClientHello”，但真正的解法（抓取真实字段）尚未完成——代码里就是这么写的。

4. **CrowdSec 是半成品，不是已挂载的服务。** wire 类型、适配器、认证和测试都已实现；HTTP 路由、`deleted` 的跟踪，以及从运行时状态组装决策则由运维负责（§7.2）。

5. **内核不附带默认信誉列表**（内置的约 30 条 JA4 语料库除外）。`asn-cidr.txt` 由安装/refresh 任务填充（Tor 0.5 + Spamhaus 0.8）；没有网络或没有该任务时，ASN/CIDR 模块虽处于启用状态，但内容为空且惰性。在运维设置 `paths` 之前，threat-intel 是空的。

6. **全部信誉功能都工作在 `aegis-pingora` 二进制中**，而不是遗留的 hyper 中。性能数字（亚微秒级 CIDR 扫描、O(1) 的 JA4 查找）是进程内的特性；真实部署还会叠加 Pingora 的 I/O 开销（参见基准测试）。
