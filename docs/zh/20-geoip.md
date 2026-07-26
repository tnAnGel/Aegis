# GeoIP（国家与 ASN）

**语言：** [English](../en/20-geoip.md) · [Русский](../ru/20-geoip.md) · **中文**

AEGIS 中的 GeoIP 子系统负责两项相互独立的任务：识别客户端所属国家（ISO 3166-1 alpha-2），用于国家级规则和管理面板中的世界地图；以及识别客户端 IP 的自治系统号（ASN），用于按 AS 绑定的信誉。两个数据库都是 MaxMind `.mmdb` 格式，通过 `maxminddb` crate 读取，随发行版一同附带（db-ip Lite，CC BY 4.0），无需强制配置即可开箱加载。

本章所依据的源码：[`src/geoip.rs`](../../src/geoip.rs)、[`src/real_ip.rs`](../../src/real_ip.rs)、[`install.sh`](../../install.sh)（`ensure_geoip_db` 函数），以及在 [`src/proxy/pingora_http.rs`](../../src/proxy/pingora_http.rs)、[`src/proxy/pingora_admin.rs`](../../src/proxy/pingora_admin.rs)、[`src/config.rs`](../../src/config.rs)、[`src/metrics/geo_shard.rs`](../../src/metrics/geo_shard.rs) 和 [`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs) 中的使用点。

---

## 1. GeoIP 具体做什么

| 功能 | 数据库 | 使用位置 | 文件 |
|---|---|---|---|
| 客户端国家（alpha-2） | Country DB（db-ip "IP to Country Lite"） | 国家 deny 列表、世界地图、请求日志富化 | `geoip.rs`、`pingora_http.rs` |
| AS 号（ASN） | ASN DB（db-ip "IP to ASN Lite"） | 按 AS 绑定的信誉（Tor/Spamhaus + 运维自定义）、ML 特征 `asn_reputation` | `geoip.rs`、`asn_reputation.rs` |

关键不变量（见 `src/geoip.rs` 的模块 docstring）：数据库在**启动时以 mmap 方式加载一次**，查询过程不分配内存；加载失败**永远不会中断启动** —— 它会记录一条警告并替换为 no-op（`NoopGeoIp`），因此在数据库缺失或过期时代理仍会继续服务流量。

---

## 2. `GeoIpLookup` trait 及其实现

一个与平台无关的门面（`src/geoip.rs`）：

```rust
pub trait GeoIpLookup: Send + Sync {
    fn country(&self, ip: IpAddr) -> Option<String>;   // alpha-2, UPPERCASE
    fn asn(&self, _ip: IpAddr) -> Option<u32> { None }  // 默认: None
}
```

| 实现 | `country()` | `asn()` | 何时从 `load_with_asn` 返回 |
|---|---|---|---|
| `NoopGeoIp` | `None` | `None`（trait 默认） | 既没有 country 也没有 ASN 数据库（或两者都打不开） |
| `MaxMindGeoIp` | 来自 Country DB | 来自 ASN DB（若通过 `with_asn` 附加） | country 数据库已加载（ASN 可选） |
| `AsnOnlyGeoIp` | `None` | 来自 ASN DB | 只设置了 ASN 路径，没有 country 数据库 |

- `country()` 提取 `rec.country.iso_code` 并转换为**大写**（`to_ascii_uppercase`）。`None` 表示：私有地址段、未分配地址块，或没有数据库。
- `asn()` 返回 `rec.autonomous_system_number`。默认为 `None`，因此不支持 ASN 的实现无需覆写任何内容。
- Country 和 ASN 是**两个独立的 `.mmdb` 文件**（MaxMind/db-ip 就是这样发布的），所以 ASN 读取器通过单独的方法 `MaxMindGeoIp::with_asn(path)` 附加。

> 诚实的说明：记录的 schema 直接使用 `maxminddb` crate 自带的 `geoip2::Country` / `geoip2::Asn`（零拷贝且生命周期正确）；自己写的结构体过不了 borrow checker。

---

## 3. 附带的数据库（预置）

AEGIS 在仓库的 `data/geoip/` 下附带了可用的数据库：

| 常量（位于 `geoip.rs`） | 文件名 | 来源 | 许可证 |
|---|---|---|---|
| `BUNDLED_COUNTRY_DB_NAME` | `dbip-country-lite.mmdb` | db-ip "IP to Country Lite" | CC BY 4.0 |
| `BUNDLED_ASN_DB_NAME` | `dbip-asn-lite.mmdb` | db-ip "IP to ASN Lite" | CC BY 4.0 |

管理 API 返回的署名信息：`IP geolocation by DB-IP (https://db-ip.com) — CC BY 4.0`（见 `api_geoip_status`）。

### 安装时的预置（`install.sh`，`ensure_geoip_db`）

`ensure_geoip_db` 函数把附带的 country 数据库复制到一个可写的绝对路径，守护进程会自动解析该路径：

```sh
# src = $AEGIS_SRC/data/geoip/dbip-country-lite.mmdb
# dst = $AEGIS_HOME/geoip  (= /var/lib/aegis/geoip)
cp -n "$src" "$dst/dbip-country-lite.mmdb"   # -n: 不覆盖运维人员已更新的数据库
chown -R "$AEGIS_USER:$AEGIS_USER" "$dst"
chmod 0755 "$dst"; chmod 0644 "$dst/dbip-country-lite.mmdb"
```

- `cp -n`（no-clobber）确保预置不会覆盖已经通过面板 Update 按钮更新过的数据库。
- 若附带文件不存在，install.sh 会记录 `WARN: bundled GeoIP db missing … — map will be empty until Update is run` 而不会失败。

### ASN 数据库的预置（`install.sh`，`aegis-refresh-feeds` 脚本）

ASN 数据库不是通过 `ensure_geoip_db` 预置的，而是通过 install.sh 生成的 `aegis-refresh-feeds` 脚本（`ensure_reputation_feeds` 的一部分），因为按 AS 绑定的信誉默认是开启的。该脚本每月拉取 db-ip ASN-lite：

```sh
GEO_DIR=/var/lib/aegis/geoip
M=$(date -u +%Y-%m)
curl -fsS -m 120 "https://download.db-ip.com/free/dbip-asn-lite-$M.mmdb.gz" -o "$TMP/asn.mmdb.gz"
gunzip -f "$TMP/asn.mmdb.gz"
install -m 0644 -o "$OWNER" -g "$OWNER" "$TMP/asn.mmdb" "$GEO_DIR/dbip-asn-lite.mmdb"
```

该脚本通过定时器 `aegis-refresh-feeds.timer` 安装（`OnCalendar=daily`、`RandomizedDelaySec=1h`、`Persistent=true`）。所有下载都是 best-effort：网络故障时该模块保持惰性（零误报），而不会让安装失败。守护进程会按 mtime **热重新读取**发生变化的文件 —— 无需重启。关于信誉情报源的更多内容见 [12-reputation.md](12-reputation.md)。

---

## 4. 路径解析器（优先级：config → env → bundled）

`src/geoip.rs` 中的两个解析器遵循同一套方案，只有在什么都没配置**且**找不到任何附带文件时才返回 `None`（此时使用 `NoopGeoIp`）。

### Country：`resolve_country_db_path(configured)`

1. 配置中显式的 `[geoip] db_path`（若非空）—— 优先级最高。
2. 环境变量 `AEGIS_GEOIP_PATH`（若非空）。
3. `default_country_db_path()` —— 目录列表中第一个存在的文件。

### ASN：`resolve_asn_db_path(configured)`

1. 显式的 `[geoip] asn_db_path`。
2. 环境变量 `AEGIS_ASN_PATH`。
3. `default_asn_db_path()`。

> 这种对称性很重要：通过 DSL 配置路径会让 `cfg.geoip = None`，因此回退到 env/bundled 是按 AS 绑定的信誉和世界地图能够开箱工作的唯一途径。

### 搜索目录列表（按优先级）

对**两个**数据库，`default_*_db_path()` 都会尝试相同的目录，并追加对应的文件名：

| 优先级 | 目录 | 用途 |
|---|---|---|
| 1 | `/var/lib/aegis/geoip` | 守护进程标准的可写路径（install.sh 和 Update 都写到这里） |
| 2 | `/etc/aegis/geoip` | 备用的系统级位置 |
| 3 | `/usr/local/src/aegis/data/geoip` | 从源码安装时的源码树 |
| 4 | `data/geoip` | 相对路径（开发时从仓库目录运行） |

由 Update 端点写入 `/var/lib/aegis/geoip` 的文件总是优先于附带文件（因为它在列表中排第一）。

### 加载点

| 二进制 / 路径 | 调用 |
|---|---|
| `aegis-pingora`（data plane） | `pingora_http.rs`：`resolve_country_db_path` + `resolve_asn_db_path` → `load_with_asn(...)` |
| `aegis`（hyper） | `server.rs`：`load_with_asn(cfg.geoip.db_path, cfg.geoip.asn_db_path)` |

> 诚实的说明：hyper 路径（`server.rs`）**严格只从 `cfg.geoip`** 加载数据库（没有 env/bundled 回退）—— 若未设置 `[geoip]`，则传入 `None`。完整的 config→env→bundled 解析器只应用于 pingora data plane（`pingora_http.rs`），而后者才是主路径。

---

## 5. `load_with_asn` 的逻辑

`load_with_asn(country_path, asn_path)`（`src/geoip.rs`）是构造 `Arc<dyn GeoIpLookup>` 的唯一入口。空路径/`None`/不存在的路径都是允许的；降级情况会被记录。决策树：

| country | asn | 结果 | 日志 |
|---|---|---|---|
| 有 | 有，且成功打开 | `MaxMindGeoIp`（country + ASN） | `info`: country + ASN databases loaded |
| 有 | 有，但**未**打开成功 | `MaxMindGeoIp`（仅 country） | `warn`: ASN reputation will only match CIDR entries |
| 有 | 无 | `MaxMindGeoIp`（仅 country） | `info`: country database loaded |
| 无 | 有，且成功打开 | `AsnOnlyGeoIp` | `info`: ASN-only database loaded |
| 无 | 无（或 country 未打开成功） | `NoopGeoIp` | `warn`: geo deny list ignored |

`load(path)` 是 `load_with_asn(path, None)` 的薄封装，供不带 ASN 的调用方使用。

---

## 6. 国家规则（`[geoip]` deny 列表）

配置（`src/config.rs`，`GeoIpConfig` 结构体）：

| 字段 | 类型 | 默认值 | 用途 |
|---|---|---|---|
| `db_path` | `String` | —（该块必填） | Country `.mmdb` 的路径；没有它整个块就是 no-op |
| `asn_db_path` | `Option<String>` | `None` | ASN `.mmdb` 的路径；没有它则信誉只匹配 CIDR 条目 |
| `deny_countries` | `Vec<String>` | `[]` | 要拦截的 alpha-2 代码（大小写不敏感）。空列表 = 监控模式 |
| `attack_mode_only` | `bool` | `false` | 仅在异常检测器认为该主机"处于攻击中"时才应用 deny 列表 |

示例：

```toml
[geoip]
db_path = "/var/lib/aegis/geoip/dbip-country-lite.mmdb"
asn_db_path = "/var/lib/aegis/geoip/dbip-asn-lite.mmdb"
deny_countries = ["RU", "KP"]
attack_mode_only = true   # 休眠的地理封锁，仅在 DDoS 时激活
```

### deny 检查（`geoip_deny`，`src/proxy/pingora_http.rs`）

```rust
fn geoip_deny(&self, ip: IpAddr, host: &str) -> Option<String> {
    let cfg = self.geoip_cfg.as_ref()?;                       // 没有 [geoip] → 跳过
    if cfg.attack_mode_only && !self.anomaly.under_attack(host) {
        return None;                                          // 和平时期休眠
    }
    if cfg.deny_countries.is_empty() { return None; }         // 监控模式
    let country = self.geoip.country(ip)?;                     // None（私有地址/无数据库）→ 跳过
    if cfg.deny_countries.iter().any(|c| c.eq_ignore_ascii_case(&country)) {
        Some(format!("geo deny: {country}"))
    } else { None }
}
```

运维人员所依赖的语义：

- **空的 `deny_countries`** = "监控模式"：国家会进入指标/地图，但流量永远不会被拦截。
- **`attack_mode_only = true`**：deny 列表处于休眠状态，直到该主机被标记为 `anomaly.under_attack(host)`。当你希望有一个休眠的地理封锁、且在和平时期不惩罚少数国家的合法流量时非常有用。
- 触发时，代理会在请求上设置 `ctx.denied_by = Some("geoip")`，并递增 `observe_filter_block("geoip")`。地理 deny 是最廉价的过滤器之一（一次 mmap 查询），它在 `request_filter` 中很早就短路返回。

> 与域名的绑定：`geoip_deny` 接收 `host`，且 `attack_mode_only` 是**按主机**通过异常检测器评估的。但国家列表本身是全局的（只有一个 `[geoip]` 块）。per-domain 策略见 [26-sites-and-domains.md](26-sites-and-domains.md)。

---

## 7. 用于信誉的 ASN 查询

客户端 IP 的 ASN 号被按 AS 绑定的信誉所使用。这个衔接由 `src/geoip.rs` 中的适配器实现：

```rust
pub struct GeoIpAsnLookup { geoip: Arc<dyn GeoIpLookup> }
impl crate::asn_reputation::AsnLookup for GeoIpAsnLookup {
    fn asn(&self, ip: IpAddr) -> Option<u32> { self.geoip.asn(ip) }
}
```

该适配器把已加载的 GeoIP 句柄的 `asn()` 方法暴露为 `AsnLookup` trait，使信誉情报源使用**同一个**代理已经打开的数据库（无需第二个读取器）。实际的组装在 `src/bin/aegis-pingora.rs` 中：

```rust
let asn_lookup: Arc<dyn AsnLookup> =
    Arc::new(GeoIpAsnLookup::new(pipeline.geoip.clone()));
// ... AsnReputation::new(paths, asn_lookup)
```

行为：

- 当 ASN 数据库已加载时，情报源中按 AS 绑定的条目（`AS<n>  <score>  <tag>`）会按客户端真实的 AS 号匹配。
- 当 ASN 数据库**未**加载时，`asn()` 返回 `None`，情报源中**只有 CIDR 条目**会生效（`<cidr>  <score>  <tag>`）。`load_with_asn` 的日志以及 `aegis-pingora.rs` 中的注释对此都作了诚实的提示。
- 在 data plane 中，ASN 还作为 ML 特征 `asn_reputation` 参与（见 `pingora_http.rs` 中的 `self.geoip.asn(client_ip)` 调用点）；没有 ASN 数据库时该特征保持为 0。

关于情报源、评分和 JA4 自学习的详细内容见 [12-reputation.md](12-reputation.md)；关于 ML 引擎见 [18-ml-risk-engine.md](18-ml-risk-engine.md)。

---

## 8. real_ip —— 识别代理/CDN 背后真实的客户端 IP

在 CDN 或反向代理之后，TCP peer 是一个轮换的边缘节点，而不是客户端。真实 IP 从 forwarded 请求头中解析，**但仅当 TCP peer 属于受信任集合时**。这是整个子系统的输入：国家和 ASN 都是基于解析器返回的那个 IP 计算的，而不是基于 TCP peer。

### 安全不变量

`peer ∈ trusted_proxy_cidrs` 这项检查是**无条件的**。如果 TCP peer 不受信任，forwarded 请求头会被静默忽略。不在受信任代理之后的攻击者无法通过注入 `X-Forwarded-For` 或 `CF-Connecting-IP` 来伪造自己的 IP。

### 配置（两个选项默认都**关闭**）

| 环境变量 | 效果 |
|---|---|
| `AEGIS_BEHIND_CLOUDFLARE=1` | 当 TCP peer 落在内置的 Cloudflare 地址段列表内时，信任 `CF-Connecting-IP`。接受 `1`/`true`/`yes`/`on` |
| `AEGIS_TRUSTED_PROXIES=cidr,cidr,...` | 额外信任这些 CIDR；并查阅 `X-Forwarded-For`（"最右侧不受信任"算法） |

### 解析算法

生产路径是 `src/proxy/pingora_http.rs` 中的 `resolve_client_ip` 方法：

1. 未设置 `trusted_proxy_cidrs` → 原样返回 TCP peer（默认行为，不读取请求头）。
2. TCP peer **不在**受信任集合中 → 返回 TCP peer（安全闸门）。
3. `AEGIS_BEHIND_CLOUDFLARE=1` → 读取 `CF-Connecting-IP`（当终结边缘是 Cloudflare 时，这是唯一权威的取值）。
4. 否则 → 读取 `X-Forwarded-For`，从右向左遍历，取第一个**不在**受信任集合中的 IP（即紧邻信任边界之前的真实客户端）。任何解析错误，或所有跳点都受信任时，回退到 TCP peer。

内置的 Cloudflare 地址段列表（`pingora_http.rs` 中的 `CF_IP_RANGES`）**仅**在 `AEGIS_BEHIND_CLOUDFLARE=1` 时启用，默认永不查阅。CIDR 匹配使用 stdlib 位运算，不依赖外部 crate；IPv4-in-IPv6（`::ffff:x.x.x.x`）不会自动归一化 —— 对于 IPv4 连接，Pingora 的 `SocketAddr::as_inet().ip()` 已经给出干净的 `IpAddr::V4`。

> 关于两套实现的诚实说明。[`src/real_ip.rs`](../../src/real_ip.rs) 模块包含一套独立的、测试完全覆盖的实现（`TrustedProxies`、`IpCidr`、`resolve_client_ip`，`from_config`/`from_env` 构造函数，读取 `AEGIS_BEHIND_CLOUDFLARE`/`AEGIS_TRUSTED_PROXIES`）。然而，生产环境的 pingora data plane 用的**不是**它，而是 `pingora_http.rs` 中自带的 `resolve_client_ip` + `CF_IP_RANGES` + `ip_in_cidr`（`real_ip` 模块在 `src/bin/*` 和 proxy 中都没有被引入 —— 在 proxy 中 `grep` `real_ip::`/`use crate::real_ip` 结果为空，而 `real_ip` 在 `lib.rs` 中是声明了的）。两套实现的语义一致（同样的安全闸门、同样的从右向左取首个不受信任 IP 的 XFF 遍历、同样的 CF-Connecting-IP 优先级），区别仅在于热路径上实际执行的是哪份代码。两处的 Cloudflare 地址段列表完全相同，并已于 2026 年核对。

---

## 9. 面板中的世界地图与 Top Countries

### 按国家计数（`observe_country`）

在每个请求的入口处，代理做一次查询并对计数器计数（`src/proxy/pingora_http.rs`）：

```rust
if let Some(cc) = self.geoip.country(client_ip) {
    self.metrics.observe_country(&cc, false, false);
}
```

由于默认是 `NoopGeoIp`（其 `country()` 不做任何工作直接返回 `None`），在未配置数据库时这**几乎是零成本**的；数据库已加载时则是一次 mmap 查询。当 event-store 启用时，国家也会写入请求日志行（`EventRow.country`）（见 [24-request-log.md](24-request-log.md)）。

### 跨 worker 聚合（`src/metrics/geo_shard.rs`）

在 `SO_REUSEPORT` 下，每个 worker 维护自己的 `by_country` 映射，只能看到自己那一份流量。为了让世界地图无论由哪个 worker 响应管理请求都保持稳定，采用了分片 + 读时合并的方案（与 site_map 相同的模式 —— 见 [26-sites-and-domains.md](26-sites-and-domains.md) 和 [06-workers.md](06-workers.md)）：

- 每个 worker 通过非阻塞的 advisory `flock` 在 `.slot-<n>.lock` 上占据一个槽位（最多 `MAX_SLOTS = 16`），并周期性地把快照写入 `shard-<slot>.json`。
- `CountryRow` 行：`country`、`total`、`denied`、`challenged`。
- 读取（`top_countries`）会合并**所有**分片，按国家代码累加计数；超过 `SHARD_MAX_AGE_SECS = 900` 的分片被视为孤儿并跳过（依据 `written_at_unix_secs` 和文件 mtime）。
- 重启时 worker 会重新读取自己的分片 —— 计数器可以跨重启保留。
- 默认目录：`/var/lib/aegis/geo`（可用 `AEGIS_GEO_DIR` 覆盖）。
- 写入是原子的（同目录 tmp 文件 + rename），权限为 `0o640`。

### Admin API

| 方法 + 路由 | 处理函数 | 用途 |
|---|---|---|
| `GET /admin/api/geo/top` | `api_geo_top` | 前 20 个国家 `[{country, total, denied}]`，用于世界地图和 Top Countries 组件；若未配置数据库则为空（地图会正确地渲染为空） |
| `GET /admin/api/geoip/status` | `api_geoip_status` | 解析出的 country 数据库路径、`AEGIS_ASN_PATH`、`loaded`、`database_type` + `build_epoch`（取自 `.mmdb` 元数据）、`bundled`、db-ip 署名 |
| `POST /admin/api/geoip/update` | `api_geoip_update` | 把 country 数据库更新为当月的 db-ip Lite |
| `POST /admin/api/geoip/lookup` | `api_geoip_lookup` | **计划中**：返回 `501`（GeoIP 句柄尚未接入 `AdminProxy`） |

管理路由的完整列表和认证方式见 [30-admin-api.md](30-admin-api.md)。

### 从面板更新 country 数据库（`api_geoip_update`）

AEGIS 不想为此在 Rust 里引入 HTTP/gzip 依赖，因此 Update 会 shell 调用 `curl | gunzip`，原子地替换 `/var/lib/aegis/geoip` 下的 mmdb，并**仅在成功时**写入重启标记，以便 path-watcher 重新读取新的数据库：

```sh
url="https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz"
tmp=/var/lib/aegis/geoip/.dbip.new
curl -sfL --max-time 180 "$url" | gunzip > "$tmp"
[ -s "$tmp" ]
mv -f "$tmp" /var/lib/aegis/geoip/dbip-country-lite.mmdb
date +%s > /var/lib/aegis/geoip/.last-update
date +%s > <…/.restart-request>   # 重启标记
```

它以 detached 方式启动（下载可能需要几秒）；面板会重新轮询 `status`（重启后构建日期会变化）。服务会自行重启 —— 无需手动 `systemctl`。关于重启机制见 [03-installation.md](03-installation.md)。

---

## 10. 运维速查表

```bash
# 查看守护进程解析到了哪个数据库 + 其构建日期
curl -s -H "x-admin-token: $TOKEN" http://127.0.0.1:PORT/admin/api/geoip/status | jq

# 国家排行（用于世界地图）
curl -s -H "x-admin-token: $TOKEN" http://127.0.0.1:PORT/admin/api/geo/top | jq

# 把 country 数据库更新到当月（自动重启）
curl -s -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:PORT/admin/api/geoip/update

# 手动刷新 ASN 数据库 + 信誉情报源（与定时器使用同一脚本）
sudo /usr/local/bin/aegis-refresh-feeds

# 通过 env 显式指定路径（会盖过 bundled，但会被配置中的 [geoip] 盖过）
export AEGIS_GEOIP_PATH=/var/lib/aegis/geoip/dbip-country-lite.mmdb
export AEGIS_ASN_PATH=/var/lib/aegis/geoip/dbip-asn-lite.mmdb

# 启用对 Cloudflare / 自有代理的信任（否则 forwarded 请求头会被忽略）
export AEGIS_BEHIND_CLOUDFLARE=1
export AEGIS_TRUSTED_PROXIES=10.0.0.0/8,192.0.2.0/24
```

### 典型场景

| 症状 | 原因 | 检查什么 |
|---|---|---|
| 世界地图为空 | country 数据库未加载 | `geoip/status` → `loaded`；`/var/lib/aegis/geoip/dbip-country-lite.mmdb` 是否存在；点击 Update |
| 地理 deny 不生效 | `deny_countries` 为空，或启用了 `attack_mode_only` 而主机并非"处于攻击中"，或国家解析不出来 | `[geoip]` 块；该主机的异常状态；私有/未分配的 IP |
| 信誉只命中 CIDR，不命中 AS | ASN 数据库未加载 | `geoip/status` → `asn_db_path`；运行 `aegis-refresh-feeds`；查看 `…only match CIDR entries` 日志 |
| 国家/ASN 是按边缘节点 IP 而非客户端计算的 | real_ip 未启用 | 是否设置了 `AEGIS_BEHIND_CLOUDFLARE` / `AEGIS_TRUSTED_PROXIES`；TCP peer 是否真的在受信任集合中 |
| 国家计数在两次轮询之间"跳变" | （历史原因）per-worker 的映射 | 现在已通过 geo-shard 合并聚合；检查 `/var/lib/aegis/geo`（或 `AEGIS_GEO_DIR`）是否可写 |

---

## 另见

- [12-reputation.md](12-reputation.md) —— AS/CIDR 情报源、评分、Tor/Spamhaus、CrowdSec。
- [18-ml-risk-engine.md](18-ml-risk-engine.md) —— ML 特征 `asn_reputation`。
- [24-request-log.md](24-request-log.md) —— `EventRow` 中的 `country` 字段。
- [25-metrics-telemetry.md](25-metrics-telemetry.md) —— `observe_country`、`observe_filter_block`。
- [26-sites-and-domains.md](26-sites-and-domains.md) —— 分片 + 合并模式、per-domain 策略。
- [06-workers.md](06-workers.md) —— SO_REUSEPORT、跨 worker 状态。
- [30-admin-api.md](30-admin-api.md) —— `/admin/api/geo*` 路由与认证。
- [04-configuration.md](04-configuration.md) —— 总体语境中的 `[geoip]` 块。
