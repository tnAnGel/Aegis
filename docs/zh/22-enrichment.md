# 情报聚合与 threat-intel

**语言：** [English](../en/22-enrichment.md) · [Русский](../ru/22-enrichment.md) · **中文**

情报聚合（enrichment）子系统在"裸" HTTP 请求之上收集关于客户端的额外上下文：被动的操作系统/TCP 栈指纹（p0f）、通过 `clamd`（ClamAV）对请求体做的可选杀毒扫描，以及来自外部 threat-intel 源（AbuseIPDB / Spamhaus DROP / FireHOL 等）的定期更新 deny 列表。本文描述 `src/enrichment.rs`、`src/filters/threat_intel.rs`、`src/p0f.rs`、`src/clamav_scanner.rs` 中的代码究竟做了什么，以及哪些部分是可选启用的。

> 关于范围的坦诚说明：在"实时"路径上（`ArsenalState`），目前向情报聚合门面注册的真正生产级源实现只有一个 —— JA4 语料库（`src/arsenal.rs:464`）。其余的源（JA4/ASN 信誉、GeoIP）拥有各自独立的缓存和路径，默认并未接入 `EnrichmentFacade`。下文对此有明确标注。

---

## 1. 子系统全图

| 组件 | 文件 | 用途 | 默认状态 |
|---|---|---|---|
| 统一情报聚合门面（WISE 风格） | `src/enrichment.rs` | 在异构源之上的一个可缓存门面，统一的 lookup 形状，聚合裁决 | 启用；注册了 1 个源（JA4 语料库） |
| Threat-intel deny 列表 | `src/filters/threat_intel.rs` | 依据本地源文件中的精确 IP 与 CIDR 做 deny，后台 reload | 仅当设置了 `paths` 时才生效 |
| p0f —— 被动 OS 指纹 | `src/p0f.rs` | 把 TCP SYN（window/MSS/wscale/TTL/选项）分类为 OS 家族 | 内置迷你数据库；可用文件扩展 |
| ClamAV 请求体扫描 | `src/clamav_scanner.rs` | 通过 INSTREAM TCP 把上传的请求体流式送入 `clamd`，按签名给出裁决 | 关闭（通过 `AEGIS_CLAMAV_ADDR` opt-in） |

相关文档：WAF —— [10-waf.md](10-waf.md)，TLS 指纹与 JA4T —— [11-tls-fingerprinting.md](11-tls-fingerprinting.md)，信誉 —— [12-reputation.md](12-reputation.md)，XDP/eBPF（内核侧 CIDR 路径）—— [13-xdp-ebpf.md](13-xdp-ebpf.md)，GeoIP —— [20-geoip.md](20-geoip.md)，Arsenal/场景 —— [21-arsenal-scenarios.md](21-arsenal-scenarios.md)，安全模型 —— [23-security-model.md](23-security-model.md)，Admin API —— [30-admin-api.md](30-admin-api.md)。

---

## 2. 情报聚合门面（`src/enrichment.rs`）

思路借鉴自 Arkime WISE（Wireless Intelligence Sources Engine）：在每个源之前放一个可缓存的门面，统一的 lookup 形状，按源的 TTL 以及贯穿响应传递的来源信息（provenance，即哪个源给出了裁决）。这取代了"每个源有自己的缓存，需要某个 IP 完整画像的代码要调用四次并自行合并裁决"的方案。

### 2.1. 键与裁决

被聚合的实体是 `EntityKey`（`src/enrichment.rs:55`）：

| `EntityKey` 变体 | `kind_str()` | 来源 |
|---|---|---|
| `Ip(IpAddr)` | `"ip"` | 客户端 IP |
| `Ja4(String)` | `"ja4"` | TLS JA4 指纹 |
| `Asn(u32)` | `"asn"` | 自治系统号 |
| `UserAgent(String)` | `"ua"` | User-Agent |

源以及聚合体的裁决是 `Verdict`（`src/enrichment.rs:74`）：`Allow`、`Deny`、`Unknown`。

### 2.2. 源即 read-through 提供者

源实现 `EnrichmentSource` trait（`src/enrichment.rs:121`）：

```rust
pub trait EnrichmentSource: Send + Sync {
    fn name(&self) -> &'static str;
    fn lookup(&self, key: &EntityKey) -> Option<(Verdict, String)>;
    fn default_ttl(&self) -> Duration { Duration::from_secs(30) }
}
```

- `name()` 返回 `&'static str` —— 这使按源计数器的基数保持有界。
- 当源成功执行但该键不在其跟踪范围内时，`lookup()` 返回 `None`。明确的不确定性（例如 GeoIP 数据库已加载，但国家未被分类）用 `Some((Verdict::Unknown, ...))` 表示。
- 元组的第二个元素是 `label` —— 人类可读的标签/标记（`"sqlmap"`、`"aws"` 等），会进入 `SourceHit.label`。

### 2.3. 裁决聚合

`Enrichment::aggregate()`（`src/enrichment.rs:98`）按如下规则把所有 `SourceHit` 归结为一个裁决：

```
任一 Deny  →  Deny   (short-circuit)
否则任一 Allow  →  Allow
否则  →  Unknown
```

`Enrichment::deny_reasons()`（`src/enrichment.rs:109`）返回所有投了 `Deny` 的源的 `label` —— 用于日志/面板。

### 2.4. 门面的缓存

`EnrichmentFacade`（`src/enrichment.rs:156`）持有：

- `sources: Vec<Arc<dyn EnrichmentSource>>` —— 按注册顺序排列的已注册源；
- `cache: RwLock<HashMap<EntityKey, CacheEntry>>` —— 聚合缓存；
- `per_source_stats` —— 每个源独立的 `queries/hits/misses` 计数器；
- 全局的 `cache_hits`/`cache_misses` 与 `capacity`。

`lookup()` 的行为（`src/enrichment.rs:187`）：

1. **Cache hit：** 如果记录存在且 `Instant::now() < entry.expires_at` —— 返回克隆，递增 `cache_hits`。
2. **Cache miss：** 递增 `cache_misses`，遍历所有源。对每个源递增 `queries`；当返回 `Some` —— 递增 `hits` 并加入 `SourceHit { source, verdict, label, fetched_at }`；当返回 `None` —— 递增 `misses`。
3. **聚合体的 TTL：** `expires_at = now + shortest_ttl`，其中 `shortest_ttl` 是命中源的 `default_ttl()` 的最小值，但不超过初始上限 `Duration::from_secs(300)`（`src/enrichment.rs:199`）。也就是说聚合记录的 TTL = 各贡献者 TTL 的最小值（信誉更新的新鲜度依然可见）。
4. 结果被放入缓存并返回。

淘汰（`insert`，`src/enrichment.rs:243`）：达到 `capacity` 时删除按 `inserted` 最旧的一条记录（线性扫描 `min_by_key`）。在"实时"路径上门面以 **16 384** 的容量创建（`src/arsenal.rs:463`）。

> 关于缓存语义的说明：这不是按访问的经典 LRU —— 被丢弃的是插入时间最小的记录（insert-order），而不是最后访问时间最早的。在实际规模下（数万条记录、短 TTL）这是可以接受的。

其他方法：`invalidate(key)` / `invalidate_all()`（`src/enrichment.rs:265`）、`registered_sources()`、`source_stats(name) -> (queries, hits, misses)`、`cache_stats() -> (hits, misses, len)`。

### 2.5. 在实时路径上的接入与 admin API

在 `ArsenalState::new_default()` 中构建门面，并向其注册**一个**源 —— 基于共享 `Ja4Corpus` 的 `Ja4CorpusEnrichmentSource`（`src/arsenal.rs:460-468`）。辅助函数 `ArsenalState::enrich_ja4(ja4)`（`src/arsenal.rs:589`）访问门面，递增 `counters.enrichment_lookups` 并返回聚合结果。

状态与临时检查可通过 Admin API 获取（`src/proxy/pingora_admin.rs`）：

| 方法 | 路径 | 返回什么 |
|---|---|---|
| `GET` | `/admin/api/enrichment` | `wired`、按源的 `{name, queries, hits, misses}`、`cache {hits, misses, size}`（`pingora_admin.rs:2131`、`:4077`） |
| `POST` | `/admin/api/enrichment/lookup` | 对 JSON `{key_kind, value}`（`ip`/`ja4`/`asn`/`user_agent`）—— 返回 `aggregate` + `sources [{source, verdict, label}]` 列表（`pingora_admin.rs:2160`、`:4080`） |

完整的管理端路由列表 —— [30-admin-api.md](30-admin-api.md)。

---

## 3. Threat-intel deny 列表（`src/filters/threat_intel.rs`）

`ThreatIntelFilter` 是一个 `TrafficFilter`（过滤器名为 `"threat_intel"`，`src/filters/threat_intel.rs:402`），它依据周期性从本地文件重新读取的 deny 列表来封禁客户端 IP。

### 3.1. 为什么要与 IP ACL 分成两个过滤器

- `IpAclFilter` 由运维人员维护并存在于主配置中；reload 会一次性更换整个集合，无法在不重载配置的情况下由外部每天更新数次。
- `ThreatIntelFilter` 持有 `Arc<RwLock<HashSet>>`（+ CIDR 向量），由后台任务从一个或多个文件刷新。运维人员用 cron 填充它们：把源 `curl` 到文件 —— Aegis 重新读取。

**为什么用本地文件而不是直接 HTTPS 拉取**（模块头部注释）：不想再往代理里拉一个 HTTPS 客户端和证书 pinning；运维人员已有惯用的付费源认证方式（curl+token、GitHub Actions、Vault）；文件的 mtime 免费带来幂等性 —— 重新读取未变更的文件是 no-op。

### 3.2. 配置

配置节 `filters.threat_intel` —— 结构体 `ThreatIntelConfig`（`src/config.rs:647`）：

| 字段 | 类型 | 默认值 | 用途 |
|---|---|---|---|
| `paths` | `Vec<String>` | `[]` | 源文件的本地路径（每行一条记录） |
| `refresh_secs` | `u64` | `300` | 多久重新读取一次源文件 |

```yaml
filters:
  threat_intel:
    paths:
      - /var/lib/aegis/feeds/spamhaus-drop.txt
      - /var/lib/aegis/feeds/firehol-level1.netset
      - /var/lib/aegis/feeds/abuseipdb-blacklist.txt
    refresh_secs: 300
```

用 cron 填充源的示例（在 Aegis 之外）：

```bash
# Spamhaus DROP（仅 CIDR）
curl -s https://www.spamhaus.org/drop/drop.txt \
  -o /var/lib/aegis/feeds/spamhaus-drop.txt

# FireHOL Level 1
curl -s https://iplists.firehol.org/files/firehol_level1.netset \
  -o /var/lib/aegis/feeds/firehol-level1.netset
```

### 3.3. 源文件格式

解析器 `parse_feed_v113`（`src/filters/threat_intel.rs:202`）按每行一条记录解析：

- `#` 之后的内容全部丢弃（注释，包括行尾注释），空行被忽略。
- 含 `/` 的行 → CIDR，进入按地址族的向量。IPv4：`prefix <= 32`，IPv6：`prefix <= 128`；掩码被计算出来并对网络做归一化（`net & mask`）。`0.0.0.0/0` 会正确匹配一切。
- 裸 IP → 精确匹配的 HashSet（`O(1)` lookup）。
- 无效行（非数字前缀、无法解析的地址）被静默跳过。

IPv4 与 IPv6 都受支持（两个地址族的精确地址与 CIDR）。

### 3.4. Reload 与 CIDR 合并

`reload()`（`src/filters/threat_intel.rs:100`）重新读取所有文件并**原子地**替换集合：

- 读取失败的文件以 `warn` 级别记录并跳过 —— 一个缺失的源不会抹掉其余的。
- 组装完成后对 CIDR 做合并：`coalesce_v4` / `coalesce_v6`（`:261`、`:299`）把重叠与相邻的区间合并（interval-merge → 再分解回最小的 CIDR 集合）。在真实的公开源上这通常能减少 30…50% 的条目而不损失覆盖（此前匹配的每个 IP 之后仍然匹配）。
- 集合的写入在 `RwLock::write` 下进行，随后更新 fast-path 哨兵。

> 关于"mtime-reload"的重要说明：reload 按定时器**无条件**重新读取文件。`ThreatIntelFilter` 自身并不比较 mtime —— 幂等性依赖于重新读取未变更的文件会得到相同集合这一事实（注释 "file mtime gives free idempotency" 指的是运维人员的工作流程）。mtime-aware 的 reload 实现在相邻子系统中（JA4/ASN 信誉 —— `src/proxy/pingora_background.rs:427-438`），而不在这里。

reload 调度器：在 `aegis`（Hyper）中 —— 以 `refresh_secs.max(30)` 为间隔的 `tokio::spawn`；第一次立即 tick 被跳过，因为构造时已经加载过了（`src/server.rs:576-591`）。只有当 `is_active()`（至少有一个路径）时才创建该任务。

### 3.5. 热路径检查

`check()`（`src/filters/threat_intel.rs:405`）：

1. **Empty-set fast path（V237）：** 原子哨兵 `has_entries`（合并后精确 IP 数 + CIDR 数的总和）以 `Acquire` 读取。若为 `0` —— 立即 `Allow`，不获取任何一次 `RwLock`。这在纯转发以及未加载源的部署中，从热路径上去掉了三次加锁。哨兵在 `reload()` 中提交集合**之后**以 `Release` 写入。
2. 按 `HashSet` 的精确匹配（`O(1)`）。
3. 若未命中 —— `matches_cidr()`（`:176`）：对按地址族的 `(net, mask)` 向量做线性扫描，判断 `(host & mask) == net`。

任何命中 → `FilterAction::Deny { status: 403, reason }`（`ip on threat-intel deny list` 或 `ip in threat-intel CIDR range`）。Deny 的构造被抽到 `#[cold] #[inline(never)] ip_deny_cold`（V230），以便热的 Allow 路径（约 99% 流量）在 icache 上保持紧凑。

**规模：** 线性扫描是为 10²–10⁴ 条记录设计的（Spamhaus DROP 约 1000 条）；在这种规模下它是亚微秒级的。对于非常大的源（10⁵+），建议运维人员把 CIDR 移到 **XDP CIDR 映射**（[13-xdp-ebpf.md](13-xdp-ebpf.md)）中，由内核完成 lookup。

### 3.6. 启用控制

ThreatIntel 没有 on/off 标志：只要存在它就一直是活动的（`config_enabled()` 恒为 `true`，`src/filters/threat_intel.rs:78`）—— 空集合是无害的（`Allow`）。要按域名强制关闭可以通过 Web UI 完成（过滤器开关的单一事实来源是 `RuntimeToggles`）。诊断：`entry_count()`、`cidr_count()`、`is_active()`。

---

## 4. p0f —— 被动的 OS/TCP 栈指纹（`src/p0f.rs`）

JA4T（在 `src/ja4.rs` 中）记录 TCP SYN 的选项，但止步于 wire-shape 的哈希。p0f 走得更远：依据 TCP 栈默认值的数据库把这一形状分类为可能的 OS 家族。这一组合的价值：JA4T 说"这两个客户端是同一个 TCP 栈"；p0f 给出的是**"客户端在 UA 中自称是 Windows 上的 Chrome，但它的 TCP 栈是 Linux"** —— 这对指纹关联器（`crate::fp_correlation`）而言是很强的代理/沙箱/爬虫信号。

> 范围被坦率地限制了：V155 是聚焦的 p0f 最小子集，而不是完整移植。完整的 p0f 语料库没有被打包（会给二进制增加约 50KB；99% 的运维人员只需要现代的桌面/移动集群）。

### 4.1. 分类器的输入 —— `Ja4tSyn`

`Ja4tSyn`（`src/p0f.rs:36`）—— Aegis 已经捕获的 SYN 观测值（`src/tcp_info.rs::capture_with_xdp`，优先 eBPF，带用户态 `TCP_INFO` 回退）：

| 字段 | 类型 | 含义 |
|---|---|---|
| `window` | `u16` | SYN 中的 TCP 窗口大小 |
| `mss` | `u16` | Maximum Segment Size |
| `wscale` | `u8` | Window scale |
| `ttl` | `u8` | 首跳的 TTL（p0f 区分 OS 的主要依据） |
| `options` | `[u8; 8]` | 按 wire 顺序的选项种类（MSS=2、NOP=1、WSCALE=3、SACKOK=4、TS=8）；尾部的零 = "没有更多选项" |

### 4.2. 签名与 TTL 分桶

`olayout_string()`（`:57`）用 `-` 连接非零选项（例如 `2-4-8-1-3`）。`signature()`（`:70`）构造类 p0f 的字符串：

```
<ttl_bucket>:<window>:<mss>:<wscale>:<olayout>
例如  64:64240:1460:7:2-4-8-1-3
```

`ttl_bucket(observed)`（`:86`）从观测到的（已被跳数递减的）TTL 还原出原始 TTL：`0..=32→32`、`33..=64→64`、`65..=128→128`、`129..→255`。

> 完整格式的子集：Aegis 省略了 p0f 的 IP 版本、DF 标志、quirks 与 payload-class —— 匹配器只依赖那些能被可靠捕获的字段。

### 4.3. 签名库与分类

`OsFamily`（`src/p0f.rs:99`）：`Linux`、`Windows`、`Macos`、`Bsd`、`Ios`、`Android`、`Unknown`（粗粒度分类 —— 达到关联器所需的粒度即可；对安全代理来说"Linux 2.6 vs 5.4"很少是可行动的）。

内置数据库 `OsDatabase::default()`（`:135`）—— 一个 `HashMap<signature → OsFamily>`，包含截至 2024 年的现代桌面/移动集群（来源：`p0f-3.09b/p0f.fp`、FoxIO JA4 cookbook、Wireshark 抓包对比）：

| 家族 | 签名示例 |
|---|---|
| Linux 5.x+ | `64:64240:1460:7:2-4-8-1-3`、`64:65535:...`、`64:29200:...` |
| Windows 10/11 | `128:65535:1460:8:2-1-3-1-1-8-4`、`128:64240:...` |
| macOS 13+ | `64:65535:1460:6:2-1-3-1-1-8-4` |
| iOS 16+ | `64:65535:1460:7:2-1-3-1-1-8-4` |
| Android 12+ | `64:65535:1460:9:2-4-8-1-3`、`64:65535:1460:8:...` |
| FreeBSD/pfSense | `64:65535:1460:6:2-1-3-4-8` |

`classify(sig)`（`:214`）—— **仅精确匹配**；未命中 → `OsFamily::Unknown`。模糊匹配（对 window 等使用通配符）不在范围内 —— 需求更丰富的运维人员建议 vendor `huginn-net`，或在旁边跑一个完整的 p0f 并把它的裁决喂进来。

扩展数据库：`OsDatabase::load_str()`（`:184`，同时提到 `load_file`）—— 每行 `<signature> <os_family>`，`#` 注释与空行被忽略，家族名不区分大小写（`mac`→macos，`freebsd`→bsd），未知家族被静默跳过（以免用垃圾污染数据库）。

便捷函数：`classify_syn(syn, db)`（`:223`）—— `db.classify(syn.signature())` 的包装。`ua_os_family(ua)`（`:231`）—— 通往关联器的桥梁：推导出 User-Agent 中声称的 OS（重要：`iphone`/`ipad` 的检查**先于** `mac os`，因为 iOS 的 UA 历史上包含 "Mac OS X"）。`ua_os_family` ↔ `classify_syn` 的不一致正是所要寻找的失配信号。

---

## 5. ClamAV 请求体扫描（`src/clamav_scanner.rs`）

WAF 的请求体检查（参见 [10-waf.md](10-waf.md)）能在 `application/x-www-form-urlencoded`/JSON 请求体中抓到 SQLi/XSS/命令注入，但**抓不到** `multipart/form-data` 文件上传中的恶意软件 —— 那是 ClamAV 的任务。本模块通过 **INSTREAM TCP API** 把 Aegis 接到一个正在运行的 `clamd` 守护进程上。

> 默认关闭且为 opt-in：若未设置 `AEGIS_CLAMAV_ADDR` —— 这就是 no-op。`clamd` 跑在运维人员的网络里；Aegis 不打包该守护进程。此外，该模块在 V129 就已完整构建，但很长时间没有活的调用方（处于休眠）；V234 使它可以在不改变行为的前提下被干净地唤醒。

### 5.1. 配置（env）

`ClamavScanner::from_env()`（`src/clamav_scanner.rs:170`）读取：

| 环境变量 | 默认值 | `ClamavConfig` 字段 |
|---|---|---|
| `AEGIS_CLAMAV_ADDR` | 未设置 → no-op | `addr: Option<String>` |
| `AEGIS_CLAMAV_MAX_BODY_BYTES` | `26214400`（25 MiB） | `max_body_bytes` |
| `AEGIS_CLAMAV_TIMEOUT_MS` | `5000` | `timeout` |

```bash
AEGIS_CLAMAV_ADDR=127.0.0.1:3310
AEGIS_CLAMAV_MAX_BODY_BYTES=26214400   # 25MB
AEGIS_CLAMAV_TIMEOUT_MS=5000
```

`scan_content_types`（`ClamavConfig::default()`，`:86`）—— 扫描哪些 `application/*`。默认为：`multipart/form-data`、`application/octet-stream`、`application/zip`、`application/x-rar-compressed`、`application/x-7z-compressed`、`application/x-tar`、`application/x-bzip2`、`application/pdf`、`application/msword`、`application/vnd.openxmlformats-officedocument`。`application/json` 被有意排除 —— clamd 在那里没什么可找的；`text/*`、`image/*` 被跳过。

### 5.2. 生命周期与调用

每个进程一个共享实例（`ClamavScanner` 的 `Clone` 很廉价，只持有配置 —— 既无 socket 也无连接池）。推荐方案是在启动时使用 `Arc<ClamavScanner>`，与 handler 的其他服务（`Arc<WafFilter>`、`Arc<AnomalyDetector>`）保持一致。调用点（在 WAF 缓冲完请求体之后）：

```rust
if scanner.is_enabled()
    && scanner.should_scan(content_type, body.len())
{
    if let ScanVerdict::Infected { signature } = scanner.scan(&body).await {
        // 只有 Infected 会阻断 —— 此处 deny/403
    }
}
```

- `is_enabled()`（`:198`）—— 廉价的 opt-in 开关：只有设置了 `addr` 时才为 `true`。热路径必须首先检查它 —— 当为 `false` 时扫描器什么都不做，可以跳过全部与请求体相关的工作。`enabled()`（`:205`）是向后兼容的别名。
- `should_scan(content_type, len)`（`:214`）—— 无需加锁的前置过滤：当扫描器关闭、请求体为空、请求体 > `max_body_bytes`、或 content-type 不在列表中时返回 `false`。

### 5.3. 扫描协议与边界

`scan(body)`（`:256`）→ `scan_inner`（`:280`）：

- 未配置 → `Skipped`；空的或超限的请求体 → `Skipped`（请求体被跳过；代理依赖 WAF 自身的 body-cap，**不扫描前缀** —— V129 的契约）。
- INSTREAM：`zINSTREAM\0`，随后是重复的 `<u32 BE 长度><字节>`，分块为 64 KiB，终止符为 `0u32`。响应读到 `NUL` 为止。
- 整个交互被包在 `timeout(self.cfg.timeout, ...)` 中。
- **响应上限（V233）：** 响应缓冲区被限制为 `RESP_CAP = 4096`；如果在上限内没有收到 `NUL` —— 直接硬错误（socket 上被入侵/冒充的进程无法灌入数 GB 数据把 worker 打到 OOM）。

解析器 `parse_response()`（`:344`）：

| clamd 的响应 | 裁决 |
|---|---|
| `stream: OK`（恰好是这一行） | `Clean` |
| `stream: <sig> FOUND` | `Infected { signature }` |
| 其他 / 空 / 大小错误 | `Error` |

> V233 加固：`FOUND` 被**首先且独立地**检查 —— 真正的 `FOUND` 无法用精心构造的后缀"降级"为 Clean；`Clean` 是对字符串 `stream: OK` 的锚定全量匹配，而不是 `ends_with(" OK")`（否则签名以 " OK" 结尾的请求体就会 fail-open 通过）。

### 5.4. 失败方向（fail-open by design）

`ScanVerdict`（`:117`）与 `is_block()`（`:141`）是单一事实来源：**只有 `Infected` 会阻断**。`Clean`、`Skipped` 与 `Error` 全都是 ALLOW。

| 裁决 | 含义 | 是否阻断？ |
|---|---|---|
| `Clean` | 请求体干净 | 否 |
| `Infected { signature }` | clamd 找到了签名 | **是** |
| `Skipped` | Content-type 不在列表 / 请求体为空 / > cap / 未配置 | 否 |
| `Error` | clamd 不可达、超时，或响应为垃圾/超限 | 否（fail-open） |

连接失败、超时与格式错误的响应都给出 `Error` → ALLOW。这是有意为之：clamd 的一次短暂故障不应卡死全部上传（运维人员应部署冗余的 clamd）。`Error` 计入指标 `aegis_clamav_scan_errors`（[25-metrics-telemetry.md](25-metrics-telemetry.md)）。需要 **fail-closed** 的人 —— 必须自己在调用点把 `Error` 解释为 deny；模块永远不会这么做。

---

## 6. 总结：默认启用了什么

| 能力 | 是否"开箱"启用 | 如何启用 |
|---|---|---|
| 情报聚合门面 + JA4 语料库源 | 是 | 在 `ArsenalState` 中自动注册 |
| JA4/ASN 信誉、GeoIP 作为门面的源 | 否（各有独立的缓存/路径） | 默认未接入 `EnrichmentFacade` —— 参见 [12-reputation.md](12-reputation.md)、[20-geoip.md](20-geoip.md) |
| Threat-intel deny 列表 | 仅当设置了 `filters.threat_intel.paths` | 指定源文件路径 + cron 更新 |
| p0f 的 OS 分类 | 内置迷你数据库处于活动状态 | 通过 `OsDatabase::load_str`/`load_file` 用文件扩展 |
| ClamAV 请求体扫描 | 否（opt-in） | 设置 `AEGIS_CLAMAV_ADDR`（+ 可选的 cap/timeout） |

另见：[04-configuration.md](04-configuration.md)（完整的配置 schema）、42-текущее-состояние-STATUS.md（opt-in 特性的当前状态）、[47-faq-troubleshooting.md](47-faq-troubleshooting.md)。
