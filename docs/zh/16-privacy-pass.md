# Privacy Pass

**语言：** [English](../en/16-privacy-pass.md) · [Русский](../ru/16-privacy-pass.md) · **中文**

Privacy Pass 是一种接受由第三方 issuer（Cloudflare Research、Apple Private Access Tokens、Fastly）签发的匿名一次性信任令牌的机制，它允许已经受信任的客户端在不暴露自身身份的情况下通过 challenge ladder。AEGIS 对令牌进行密码学校验（Ed25519，RFC 9578 Type-1），若有效，则通过 [chained trust](#chained-trust--信任链) 授予临时 bypass。本文档描述的是 [src/privacy_pass.rs](../../src/privacy_pass.rs) 和 [src/chained_trust.rs](../../src/chained_trust.rs) 中代码**实际**所做的事情。

> 🟡 **诚实状态（在落地之前请阅读）。** Verifier 已完整实现并有测试覆盖，issuer 注册表可通过 Admin API 在运行时管理，但**令牌校验尚未接入 Pingora 处理器中的 request-path**（[src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs) 并未调用 `parse_token`/`verify`）。目前它是：可用的 verifier + 运行时注册表 + Admin API + 计数器/面板，但还不是 data plane 中的端到端过滤器。详见[哪些真正可用，哪些不可用](#哪些真正可用哪些不可用)一节。

---

## 1. 为什么需要它

Privacy Pass（语义遵循 RFC 9576，令牌格式遵循 RFC 9578）解决了 UX 与防护之间的取舍：一个已经在大型 issuer 处完成认证（例如 Apple device attestation 或 Cloudflare）的受信任浏览器，可以出示一个**匿名**令牌，而不必再次求解 CAPTCHA/PoW。AEGIS：

1. 用本地注册表中该 issuer 的公钥校验令牌签名。
2. 将令牌的 `nonce` 标记为已使用（防重放）。
3. 在 issuer 指定的 `trust_duration` 内授予对 challenge ladder 的临时 bypass。

这既降低了受信任客户端的摩擦，同时又不要求 AEGIS 了解关于客户端的任何信息 —— 令牌在构造上就是匿名的（Type-1 是可公开验证的，不含用户标识符）。

另见：[Challenge ladder、PoW 与 captcha](./15-challenge-ladder.md)、Defence Arsenal。

---

## 2. 线上的令牌格式（RFC 9578 Type-1）

客户端发送如下头部（在 docstring [src/privacy_pass.rs:14](../../src/privacy_pass.rs) 中有说明）：

```text
Authorization: PrivateToken token=<base64url(token_bytes)>,
                            issuer-name=cloudflare-research.com
```

令牌的原始字节（`token_bytes`）具有固定布局。AEGIS 接受一种简化的 raw 形式（并非完整的 RFC 9578 HTTP 语义编码 —— 见说明部分）：

| 偏移 | 字段 | 大小 | 说明 |
|---|---|---|---|
| `0..2` | `token_type` | 2 字节（u16 BE） | 可公开验证令牌为 `0x0002` |
| `2..34` | `nonce` | 32 字节 | 唯一的一次性标识符（anti-replay） |
| `34..66` | `challenge_digest` | 32 字节 | 令牌所绑定的 challenge 的摘要 |
| `66..98` | `token_key_id` | 32 字节 | issuer 选择子（RFC 9578 `token_key_id`） |
| `98..end` | `signature` | 取决于密钥族 | 对 Ed25519 —— 恰好 64 字节 |

解析由 `PrivacyPassVerifier::parse_token`（[src/privacy_pass.rs:178](../../src/privacy_pass.rs)）完成。任何短于 98 字节的输入 → `None`（malformed）。签名被取为「第 98 字节之后的全部内容」，其长度在 verify 阶段才校验。

### 被签名的消息

签名覆盖**四个**字段的拼接（但不包含签名本身），在 `verify` 中重建（[src/privacy_pass.rs:204](../../src/privacy_pass.rs)）：

```text
msg = token_type (BE) || nonce || challenge_digest || token_key_id   // 恰好 98 字节
```

也就是说，对 `nonce`、`challenge_digest` 或 `key_id` 的任何修改都会使签名失效 —— 这由测试 `tampered_message_fails_verification`（[src/privacy_pass.rs:565](../../src/privacy_pass.rs)）验证。

---

## 3. 签名算法

类型 `SignatureAlgorithm`（[src/privacy_pass.rs:61](../../src/privacy_pass.rs)）认识两个变体：

| 变体 | Wire/admin 名称 | 用途 | 状态 |
|---|---|---|---|
| `Ed25519` | `ed25519` | RFC 8032 Ed25519 —— **生产**算法（V242） | ✅ Production |
| `HmacSha256` | `hmac_sha256` | SHA-256 HMAC（RFC 2104） | 🟡 **仅用于测试** |

> 🔴 **HmacSha256 不用于生产。** 算法的 docstring 中直接写着：「NOT FOR PRODUCTION」。HMAC 使用**共享密钥**，这破坏了 Privacy Pass 的核心思想 —— 基于**公**钥的匿名验证。保留这个变体只是为了在不生成 Ed25519 密钥的情况下跑通 verifier 的外围逻辑。生产中请使用 `ed25519`（[src/privacy_pass.rs:66](../../src/privacy_pass.rs)）。

### 3.1. Ed25519 与 `verify_strict`（防护可延展签名）

生产校验位于 `verify_ed25519`（[src/privacy_pass.rs:300](../../src/privacy_pass.rs)），使用 `ed25519_dalek` crate。关键点是 —— **使用的是 `VerifyingKey::verify_strict`，而不是普通的 `verify`**：

```rust
key.verify_strict(msg, &signature)
    .map_err(|_| Ed25519Error::BadSignature)
```

`verify_strict` 会拒绝利用点可延展性的签名 —— 即 Curve25519 曲线的 small-order / torsion 分量。对于一个**授予 challenge ladder bypass** 的原语来说，这是正确的默认选择：严格校验保证签名恰好绑定到一个公钥，攻击者无法通过小阶点替换密钥（[src/privacy_pass.rs:293-299](../../src/privacy_pass.rs)）。

同一路径上的其他严格检查：

- 公钥必须**恰好 32 字节**，且是曲线上有效的规范压缩点（`VerifyingKey::from_bytes`）。否则 → `Ed25519Error::InvalidKey`。
- 签名必须**恰好 64 字节**。长度不正确属于令牌中攻击者可控的字段，因此被当作 `BadSignature` 而非配置错误处理（[src/privacy_pass.rs:307-311](../../src/privacy_pass.rs)）。

### 3.2. 区分「坏密钥」与「坏签名」

类型 `Ed25519Error`（[src/privacy_pass.rs:283](../../src/privacy_pass.rs)）有意区分两种情况，而这是 **security-relevant** 的：

| 错误 | 原因 | 对外结果（`VerifyOutcome`） | 为何如此 |
|---|---|---|---|
| `InvalidKey` | 已注册的 issuer 公钥无效（长度不对／不在曲线上） | `UnsupportedAlgorithm` | 这是**运维错误** —— 可诊断，而不是看起来像伪造 |
| `BadSignature` | 签名与消息 + 密钥不符，或不是 64 字节／不规范 | `BadSignature` | 这是**真正的校验失败／伪造尝试** —— 与任何其他坏令牌一样解读 |

两种情况都**fail closed**（不授予信任），但 `UnsupportedAlgorithm` 让注册了坏密钥的 Ed25519 issuer 的运维人员能看到配置错误，而不是「所有令牌都被静默地当作伪造品拒绝」。

### 3.3. HMAC-SHA256：length-extension 修复的来龙去脉

> 🟡 安全背景（尽管 HMAC 是测试算法）。在 V233 中，函数 `verify_hmac_sha256`（[src/privacy_pass.rs:338](../../src/privacy_pass.rs)）被重写。此前它计算 `SHA256(key || msg)` —— 一种朴素的 prefix-MAC，易受 **length-extension** 攻击：观察到一组有效 `(msg, tag)` 的攻击者（而令牌是走请求头传输的，也就是说并不保密）可以在没有密钥的情况下为 `msg || pad || suffix` 伪造 tag，从而获得 24 小时的 bypass。现在使用的是真正的 `Hmac::<Sha256>`（RFC 2104），并通过 `mac.verify_slice(sig)` 进行**常量时间**的 tag 比较（绝不用 `==`）。回归测试为 `length_extended_token_is_rejected`（[src/privacy_pass.rs:526](../../src/privacy_pass.rs)）。

保留下来的函数 `constant_time_eq`（[src/privacy_pass.rs:368](../../src/privacy_pass.rs)）已不在 HMAC 路径上（被 `verify_slice` 取代），但作为一个正确的、无依赖的常量时间原语被保留下来供未来调用方使用，并标记为 `#[allow(dead_code)]`。

---

## 4. 校验结果（`VerifyOutcome`）

`PrivacyPassVerifier::verify`（[src/privacy_pass.rs:199](../../src/privacy_pass.rs)）返回其中一种结果（[src/privacy_pass.rs:109](../../src/privacy_pass.rs)）：

| 结果 | 何时出现 | 是否授予信任？ |
|---|---|---|
| `Valid` | 签名有效且 nonce 此前未出现过 | ✅ 是 |
| `UnknownIssuer` | 注册表中找不到 `token_key_id` | ❌ |
| `BadSignature` | 签名不符／长度不正确 | ❌ |
| `Replayed` | nonce 已在 replay 缓存中 | ❌ |
| `Malformed` | （在 `parse_token` 层 → `None`） | ❌ |
| `UnsupportedAlgorithm` | 算法可识别，但密钥无效／算法未实现 | ❌（fail closed，但可观测） |

`verify` 中的检查顺序：**issuer 查找 → 重建消息 → 校验签名 → replay 检查**。只有在签名校验**成功之后**才标记 replay，因此无效签名不会用他人的 nonce「污染」replay 缓存。

---

## 5. Trusted issuers 注册表

### 5.1. 结构

`TrustedIssuer`（[src/privacy_pass.rs:50](../../src/privacy_pass.rs)）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `key_id` | `[u8; 32]` | RFC 9578 `token_key_id`，注册表中的查找键 |
| `name` | `String` | 人类可读的名称（例如 `cloudflare-research.com`） |
| `public_key` | `Vec<u8>` | issuer 的公钥（Ed25519 为 32 字节） |
| `algorithm` | `SignatureAlgorithm` | `Ed25519` 或 `HmacSha256` |
| `trust_duration` | `Duration` | 已校验的令牌在重新 challenge 之前能给予多久的信任 |

注册表以 `RwLock<HashMap<[u8;32], TrustedIssuer>>` 形式保存在 `PrivacyPassVerifier` 中（[src/privacy_pass.rs:125](../../src/privacy_pass.rs)）。注册是**按 `key_id` 幂等的** —— 用相同 `key_id` 重复调用 `register_issuer` 会覆盖该条目（测试 `issuer_registration_idempotent_per_key_id`，[src/privacy_pass.rs:505](../../src/privacy_pass.rs)）。

### 5.2. 面板安全的视图（`IssuerInfo`）

`list_issuers`（[src/privacy_pass.rs:159](../../src/privacy_pass.rs)）返回 `Vec<IssuerInfo>`（[src/privacy_pass.rs:87](../../src/privacy_pass.rs)）—— 一种可安全序列化到管理面板的形式：

| 字段 | 说明 |
|---|---|
| `name` | issuer 名称 |
| `key_id_hex` | 完整 hex 形式的 `token_key_id`（这是 on-wire 选择子，不是秘密） |
| `algorithm` | `ed25519` \| `hmac_sha256` |
| `public_key_fingerprint` | 密钥字节的 `sha256:<前 16 位 hex>` —— **是指纹，不是密钥本身** |
| `trust_duration_secs` | 信任窗口，单位为秒 |

> 🟡 尽管 Type-1 的 issuer 密钥是**公开的**验证密钥（并非秘密），面板拿到的仍然只是指纹，而不是原始字节。这样一来，若未来某种算法会携带私有材料，契约依然是正确的。测试 `list_issuers_never_leaks_key_bytes`（[src/privacy_pass.rs:728](../../src/privacy_pass.rs)）检查原始密钥不会进入序列化后的 JSON。列表按 `key_id_hex` 排序，以保证面板中行顺序稳定。

### 5.3. 密钥轮换

轮换实现为一个**静态注册表**，Admin API 可在运行时修改它（docstring [src/privacy_pass.rs:41](../../src/privacy_pass.rs)）。**没有**单独的自动轮换／拉取 issuer 密钥的机制 —— 运维人员通过 API 手动注册／覆盖 issuers。

---

## 6. 防重放（nonce cache）

`try_mark_seen`（[src/privacy_pass.rs:236](../../src/privacy_pass.rs)）把见过的 nonce 保存在 `RwLock<HashMap<[u8;32], Instant>>` 中，其中的 `Instant` 是**过期时刻**（`now + trust_duration`）：

- 若 nonce 已在缓存中 → `false` → `VerifyOutcome::Replayed`。
- 溢出时（`cache_capacity`，通过 `PrivacyPassVerifier::default()` 默认为 **100 000**，[src/privacy_pass.rs:270](../../src/privacy_pass.rs)）会淘汰**最旧的那一个**元素（按时间 `min_by_key`）。
- `gc()`（[src/privacy_pass.rs:257](../../src/privacy_pass.rs)）丢弃所有过期的 nonce；应从服务 actuator wheel 的同一个 tick 中调用。
- `nonce_cache_size()` 返回当前大小，供指标／面板使用。

测试 `gc_drops_expired_nonces`（[src/privacy_pass.rs:486](../../src/privacy_pass.rs)）确认了过期与垃圾回收。

---

## 7. Chained trust —— 信任链

实现：[src/chained_trust.rs](../../src/chained_trust.rs)（V202）。思路是：**通过的 challenge 越强，信任窗口越长**，并且通过了一个强 challenge 的客户端在该窗口内免于重新求解较弱的 challenge（docstring [src/chained_trust.rs:1](../../src/chained_trust.rs)）。

### 7.1. 层级（`TrustTier`）与窗口

`TrustTier`（[src/chained_trust.rs:50](../../src/chained_trust.rs)）是一个有序枚举；窗口由 `default_duration` 给定（[src/chained_trust.rs:63](../../src/chained_trust.rs)）：

| Tier | `as_str` | 信任窗口 | 覆盖 |
|---|---|---|---|
| `None` | `none` | 0 | — |
| `Cookie` | `cookie` | 5 分钟 | L1+L2 |
| `Reload` | `reload` | 15 分钟 | L1..L3 |
| `Interaction` | `interaction` | 30 分钟 | — |
| `Pow` | `pow` | 1 小时 | L1..L4 |
| `Captcha` | `captcha` | 24 小时 | L1..L5 |
| `WebAuthn` | `webauthn` | **7 天** | L1..L6 |
| `PrivacyPass` | `privacy_pass` | 24 小时（issuer-specified） | — |

Privacy Pass 作为一个独立的 `PrivacyPass` tier 进入这条阶梯。注意：它的 `default_duration` 是 24 小时，但真实的 `trust_duration` 由 issuer 在 `TrustedIssuer` 中给定，而 nonce 的 replay 窗口至少等于一个 `trust_duration`。

### 7.2. 将授权绑定到已签名的 nonce（V233 auth_bypass 修复）

> 🔴 这曾是一个关键修复。此前信任授权是绑定到**裸 IP** 的。任何位于共享 CGNAT／企业 NAT 出口后面的人，只要有**一个**同 IP 的对端通过了 challenge，就能「蹭」到 24 小时的授权。

现在每一份授权都绑定到一个服务端生成的随机 nonce，并作为 cookie 投递给特定客户端。实现（[src/chained_trust.rs:21-32](../../src/chained_trust.rs)）：

- 授权按 key `(IpAddr, RouteClass, nonce)` 保存（[src/chained_trust.rs:119](../../src/chained_trust.rs)）。
- `mint_nonce`（[src/chained_trust.rs:162](../../src/chained_trust.rs)）生成 16 个随机字节并对其签名。
- `sign_nonce`（[src/chained_trust.rs:171](../../src/chained_trust.rs)）签发形如 `base64(nonce).base64(hmac)` 的 cookie，其中 HMAC 是对 `ip:nonce` 计算的 —— 为某个 IP 签发的 cookie **在另一个 IP 下无法通过校验**。
- `verify_nonce`（[src/chained_trust.rs:186](../../src/chained_trust.rs)）—— 常量时间（`Mac::verify_slice`）；任何 malformed／坏 base64／IP 不符／伪造的情况 → `None`。
- `current()`/`covers()`（[src/chained_trust.rs:253](../../src/chained_trust.rs)、[src/chained_trust.rs:287](../../src/chained_trust.rs)）要求客户端出示相匹配的已签名 cookie。**缺失或不匹配的 cookie → `TrustTier::None`。** 仅有裸 IP 永远不够。

回归测试 `grant_not_honoured_for_same_ip_with_different_or_absent_nonce`（[src/chained_trust.rs:447](../../src/chained_trust.rs)）正是针对这个 shared-CGNAT bypass。

### 7.3. HMAC 密钥与重启后的存活

`ChainedTrustStore::new()`（[src/chained_trust.rs:130](../../src/chained_trust.rs)）会生成一个**每进程**随机的 32 字节 HMAC 密钥。后果是：不读取进程内存就无法伪造已签名的 nonce，但**重启也会使**所有已签发的 cookie 失效。若要在重启后仍然有效／在机群中工作，请使用 `with_secret(...)`（[src/chained_trust.rs:146](../../src/chained_trust.rs)）并显式给出运维密钥（测试 `cookie_from_other_secret_rejected`，[src/chained_trust.rs:518](../../src/chained_trust.rs)）。

### 7.4. 路由类别（`RouteClass`）

`RouteClass`（[src/chained_trust.rs:102](../../src/chained_trust.rs)）：

| 类别 | 路由 | 行为 |
|---|---|---|
| `Generic` | 除 auth 之外的一切 | 自动授予信任 |
| `Auth` | `/login`、`/signup`、password-reset | **永不**自动授予信任；需要显式 opt-in `with_allow_for_auth(true)` |
| `Api` | `/api/*` | 单独配置（例如 API 使用方可通过 mTLS 认证并完全绕过 ladder） |

各类别的授权是**相互独立的**（测试 `route_classes_are_independent`，[src/chained_trust.rs:426](../../src/chained_trust.rs)）。在没有 opt-in 的 auth 路由上调用 `record` 会返回 `None`，运维方由此知道不需要设置 cookie（[src/chained_trust.rs:203-244](../../src/chained_trust.rs)）。

### 7.5. 防降级

如果 `(ip, route_class)` 已经有一份存活的**更强**授权，那么较弱 tier 的 `record` 不会降低信任 —— 它会返回既有的强授权 cookie，客户端保留更长的窗口（[src/chained_trust.rs:221-232](../../src/chained_trust.rs)；测试 `stronger_grant_not_downgraded_by_weaker`）。

### 7.6. 撤销与 GC

- `revoke(ip)`（[src/chained_trust.rs:300](../../src/chained_trust.rs)）—— 丢弃该 IP 在所有类别下的**全部** per-nonce 授权（例如在 `aegis_fp` cookie 被篡改时，或在 deny 决策之后）。
- `gc()`（[src/chained_trust.rs:305](../../src/chained_trust.rs)）—— 丢弃过期的授权。

---

## 8. 集成与开关

### 8.1. Arsenal

Verifier 与 trust-store 以 `Arc` 包装的单例形式存在于 `Arsenal` 中（[src/arsenal.rs:422-507](../../src/arsenal.rs)）：

```rust
pub chained_trust: Arc<ChainedTrustStore>,   // ::new()  (process-random secret)
pub privacy_pass:  Arc<PrivacyPassVerifier>, // ::default() (cache_capacity = 100_000)
```

`DomainChallengeConfig` 中的开关（[src/arsenal.rs:52-58](../../src/arsenal.rs)）—— **per-host，二者默认均关闭**（`bool` 上的 `#[serde(default)]` → `false`）：

| 字段 | 默认值 | 用途 |
|---|---|---|
| `privacy_pass` | `false` | 在该 host 上启用 Privacy Pass bypass |
| `chained_trust` | `false` | 启用信任递进链 |
| `trust_for_auth` | `false` | 允许在 auth 路由上进行信任递进 |

计数器（`ShardedCounter`，[src/arsenal.rs:166-169](../../src/arsenal.rs)）：`privacy_pass_accepts`、`privacy_pass_rejects`、`chained_trust_grants`、`chained_trust_bypasses`。

### 8.2. Admin API

处理器位于 [src/proxy/pingora_admin.rs](../../src/proxy/pingora_admin.rs)：

| 方法 | 路径 | 动作 |
|---|---|---|
| `GET` | `/admin/api/privacy-pass` | 汇总：`issuer_count`、`nonce_cache_size`、`wired`（[:2392](../../src/proxy/pingora_admin.rs)） |
| `GET` | `/admin/api/privacy-pass/issuers` | 供面板使用的完整 issuers 列表（`IssuerInfo`）（[:2412](../../src/proxy/pingora_admin.rs)） |
| `POST` | `/admin/api/privacy-pass/issuers` | 在运行时注册 issuer（[:2427](../../src/proxy/pingora_admin.rs)） |

POST 请求体（`Payload`，[src/proxy/pingora_admin.rs:2428](../../src/proxy/pingora_admin.rs)）：

```json
{
  "name": "cloudflare-research.com",
  "key_id_hex": "<64 个 hex 字符 = 32 字节>",
  "public_key_hex": "<公钥的 hex>",
  "algorithm": "ed25519",
  "trust_duration_secs": 86400
}
```

服务端校验：
- `key_id_hex` 必须是 **64 个 hex 字符**（32 字节），否则 `400`。
- `algorithm` 必须是 `ed25519` 或 `hmac_sha256`，否则 `400`。
- `trust_duration_secs` 会被强制提升到**至少 60 秒**（`.max(60)`，[src/proxy/pingora_admin.rs:2466](../../src/proxy/pingora_admin.rs)）。

注册 Ed25519 issuer 的示例：

```bash
curl -sS -X POST http://127.0.0.1:6280/admin/api/privacy-pass/issuers \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "cloudflare-research.com",
    "key_id_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "public_key_hex": "<32 字节 Ed25519 pubkey 的 hex>",
    "algorithm": "ed25519",
    "trust_duration_secs": 86400
  }'
# → {"ok":true,"name":"cloudflare-research.com"}
```

该汇总也可在通用的 admin 快照中获取：`trust_grants_active` 与 `privacy_pass_issuers`（[src/proxy/pingora_admin.rs:1334-1335](../../src/proxy/pingora_admin.rs)）。关于 API 的更多内容 —— Admin API —— 参考手册。

---

## 9. 哪些真正可用，哪些不可用

> 必须遵守安全模型以及简报中的诚实说明。

**✅ 已实现并经过测试：**
- RFC 9578 Type-1 令牌（raw 形式）的解析，以及被签名消息的重建。
- 通过 `verify_strict` 的生产级 Ed25519 校验（防护 malleable/torsion 签名）。
- 区分 `InvalidKey`（配置错误 → `UnsupportedAlgorithm`）与 `BadSignature`（伪造），fail-closed。
- 带容量淘汰与 GC 的 nonce replay 缓存。
- 运行时 issuers 注册表 + 面板安全的 `IssuerInfo`（指纹，而非原始密钥）。
- 带校验的 Admin API（GET 汇总/列表，POST 注册）。
- 带 per-nonce HMAC cookie 的 chained trust（封堵了 shared-CGNAT auth_bypass，V233）。

**🟡 部分实现／未实现（依据 docstring [src/privacy_pass.rs:35-44](../../src/privacy_pass.rs)）：**
- **Verifier 未从 request-path 调用。** 在 [src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs) 中没有对 `parse_token`/`privacy_pass.verify` 的调用。`PrivateToken` 头目前不会在生产处理器中被解析 —— data plane 中经由 Privacy Pass 的 bypass 尚未接入。这是一套基础设施（verifier + 注册表 + API + 计数器），而不是端到端的过滤器。
- **Type-2（Blind Signature Scheme）私有令牌未实现。** 只支持 Type-1 的公开验证，因为每个大型 issuer 都会公布其密钥。对于 Type-2，运维方需要一个独立的 issuer-client。
- **RFC 9578 的 HTTP 语义编码未实现** —— 接受的是简化的令牌原始字节形式。
- **`HmacSha256` 仅用于测试**，不用于生产（共享密钥破坏了公开验证的匿名性）。
- **没有 issuer 密钥的自动轮换** —— 静态注册表，密钥通过 Admin API 手动更换。

**运维注意事项：**
- 使用 `ChainedTrustStore::new()`（默认）时，HMAC 密钥是每进程随机的 → 所有已签发的 trust-cookie 在重启时失效。若需要稳定性，请通过 `with_secret` 设置共享密钥。
- 两个开关（`privacy_pass`、`chained_trust`）默认关闭 —— 通过 `DomainChallengeConfig` 按 host 启用（见制图与 per-domain 策略）。

---

## 10. 相关文档

- [Challenge ladder、PoW 与 captcha](./15-challenge-ladder.md) —— Privacy Pass tier 所嵌入的那条阶梯。
- Defence Arsenal、场景与执行器 —— verifier 与 trust-store 所在之处。
- Admin API —— 参考手册 —— `/admin/api/privacy-pass/*` 的完整参考。
- 安全模型与加固 —— 总体威胁模型。
- 制图与 per-domain 策略 —— per-host 开关。
- 术语表 —— Privacy Pass、replay、TrustTier 等术语。
