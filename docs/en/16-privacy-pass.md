# Privacy Pass

**Languages:** **English** · [Русский](../ru/16-privacy-pass.md) · [中文](../zh/16-privacy-pass.md)

Privacy Pass is a mechanism for accepting anonymous single-use trust tokens issued by a third-party issuer (Cloudflare Research, Apple Private Access Tokens, Fastly), which allow an already-trusted client to pass the challenge ladder without revealing its identity. AEGIS cryptographically verifies the token (Ed25519, RFC 9578 Type-1) and, if it is valid, grants a temporary bypass through [chained trust](#chained-trust--the-trust-chain). This document describes what the code in [src/privacy_pass.rs](../../src/privacy_pass.rs) and [src/chained_trust.rs](../../src/chained_trust.rs) **actually** does.

> 🟡 **Honesty status (read before deploying).** The verifier is fully implemented and covered by tests, the issuer registry is managed through the Admin API at runtime, but **token verification is not yet wired into the request path in the Pingora handler** ([src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs) does not call `parse_token`/`verify`). At this point this is: a working verifier + a runtime registry + Admin API + counters/panel, but not an end-to-end filter in the data plane. More details — the section [What actually works and what does not](#what-actually-works-and-what-does-not).

---

## 1. Why this is needed

Privacy Pass (RFC 9576 for the semantics, RFC 9578 for the token format) resolves the trade-off between UX and protection: a trusted browser that has already been attested by a major issuer (for example Apple device attestation or Cloudflare) can present an **anonymous** token instead of solving a CAPTCHA/PoW again. AEGIS:

1. Verifies the token signature with the issuer's public key from the local registry.
2. Marks the token's `nonce` as used (replay protection).
3. Grants a temporary bypass of the challenge ladder for the `trust_duration` specified by the issuer.

This reduces friction for trusted clients while requiring AEGIS to know nothing about the client — the token is anonymous by construction (Type-1 is publicly verifiable, with no user identifier).

See also: [Challenge ladder, PoW and captcha](./15-challenge-ladder.md), Defence Arsenal.

---

## 2. On-the-wire token format (RFC 9578 Type-1)

The client sends a header (documented in the docstring [src/privacy_pass.rs:14](../../src/privacy_pass.rs)):

```text
Authorization: PrivateToken token=<base64url(token_bytes)>,
                            issuer-name=cloudflare-research.com
```

The raw token bytes (`token_bytes`) have a fixed layout. AEGIS accepts a simplified raw form (NOT the full HTTP-semantic RFC 9578 encoding — see the caveats):

| Offset | Field | Size | Description |
|---|---|---|---|
| `0..2` | `token_type` | 2 bytes (u16 BE) | `0x0002` for publicly verifiable tokens |
| `2..34` | `nonce` | 32 bytes | Unique single-use identifier (anti-replay) |
| `34..66` | `challenge_digest` | 32 bytes | Digest of the challenge the token is bound to |
| `66..98` | `token_key_id` | 32 bytes | Issuer selector (RFC 9578 `token_key_id`) |
| `98..end` | `signature` | depends on the key family | For Ed25519 — exactly 64 bytes |

Parsing is done by `PrivacyPassVerifier::parse_token` ([src/privacy_pass.rs:178](../../src/privacy_pass.rs)). Any input shorter than 98 bytes → `None` (malformed). The signature is taken as "everything after byte 98", and its length is checked at the verify stage.

### The signed message

The signature covers the concatenation of **four** fields (but NOT the signature itself), reconstructed in `verify` ([src/privacy_pass.rs:204](../../src/privacy_pass.rs)):

```text
msg = token_type (BE) || nonce || challenge_digest || token_key_id   // exactly 98 bytes
```

That is, any change to `nonce`, `challenge_digest` or `key_id` invalidates the signature — this is checked by the test `tampered_message_fails_verification` ([src/privacy_pass.rs:565](../../src/privacy_pass.rs)).

---

## 3. Signature algorithms

The `SignatureAlgorithm` type ([src/privacy_pass.rs:61](../../src/privacy_pass.rs)) knows two variants:

| Variant | Wire/admin name | Purpose | Status |
|---|---|---|---|
| `Ed25519` | `ed25519` | RFC 8032 Ed25519 — the **production** algorithm (V242) | ✅ Production |
| `HmacSha256` | `hmac_sha256` | SHA-256 HMAC (RFC 2104) | 🟡 **Tests only** |

> 🔴 **HmacSha256 is not for production.** The algorithm's docstring says so outright: "NOT FOR PRODUCTION". HMAC uses a **shared secret**, which destroys the very idea of Privacy Pass — anonymous verification with a **public** key. This variant has been kept only to exercise the verifier harness without generating an Ed25519 key. In production use `ed25519` ([src/privacy_pass.rs:66](../../src/privacy_pass.rs)).

### 3.1. Ed25519 and `verify_strict` (protection against malleable signatures)

The production check lives in `verify_ed25519` ([src/privacy_pass.rs:300](../../src/privacy_pass.rs)) and uses the `ed25519_dalek` crate. The key point is that **`VerifyingKey::verify_strict` is used, not the ordinary `verify`**:

```rust
key.verify_strict(msg, &signature)
    .map_err(|_| Ed25519Error::BadSignature)
```

`verify_strict` rejects signatures that exploit point malleability — small-order / torsion components of the Curve25519 curve. For a primitive that **grants a bypass of the challenge ladder**, this is the right default: strict verification guarantees that the signature is bound to exactly one public key, and that an attacker cannot substitute the key via a small-order point ([src/privacy_pass.rs:293-299](../../src/privacy_pass.rs)).

Additional strict checks on the same path:

- The public key must be **exactly 32 bytes** and a valid canonical compressed point on the curve (`VerifyingKey::from_bytes`). Otherwise → `Ed25519Error::InvalidKey`.
- The signature must be **exactly 64 bytes**. An incorrect length is an attacker-controlled field of the token, so it is treated as `BadSignature` rather than as a configuration error ([src/privacy_pass.rs:307-311](../../src/privacy_pass.rs)).

### 3.2. Distinguishing "bad key" from "bad signature"

The `Ed25519Error` type ([src/privacy_pass.rs:283](../../src/privacy_pass.rs)) deliberately separates two cases, and this is **security-relevant**:

| Error | Cause | External outcome (`VerifyOutcome`) | Why it is done this way |
|---|---|---|---|
| `InvalidKey` | The registered issuer public key is invalid (wrong length / not on the curve) | `UnsupportedAlgorithm` | This is an **operator error** — it is diagnosable rather than looking like forgery |
| `BadSignature` | The signature does not match the message + key, or is not 64 bytes / not canonical | `BadSignature` | This is a **genuine verification failure / forgery attempt** — read like any other bad token |

Both cases **fail closed** (no trust is granted), but `UnsupportedAlgorithm` lets an operator who registered an Ed25519 issuer with a broken key see a config error rather than "all tokens are silently rejected as forgeries".

### 3.3. HMAC-SHA256: the history of the length-extension fix

> 🟡 Security context (even though HMAC is a test algorithm). In V233 the function `verify_hmac_sha256` ([src/privacy_pass.rs:338](../../src/privacy_pass.rs)) was rewritten. Previously it computed `SHA256(key || msg)` — a naive prefix-MAC vulnerable to **length extension**: an attacker who observed one valid `(msg, tag)` (and tokens travel in a request header, i.e. they are not secret) could forge a tag for `msg || pad || suffix` without the key and obtain a 24-hour bypass. Now a real `Hmac::<Sha256>` (RFC 2104) is used, with a **constant-time** tag comparison via `mac.verify_slice(sig)` (never `==`). The regression test is `length_extended_token_is_rejected` ([src/privacy_pass.rs:526](../../src/privacy_pass.rs)).

The remaining function `constant_time_eq` ([src/privacy_pass.rs:368](../../src/privacy_pass.rs)) is no longer on the HMAC path (`verify_slice` has replaced it), but has been kept as a correct dependency-free constant-time primitive for future callers, marked `#[allow(dead_code)]`.

---

## 4. Verification outcomes (`VerifyOutcome`)

`PrivacyPassVerifier::verify` ([src/privacy_pass.rs:199](../../src/privacy_pass.rs)) returns one of the outcomes ([src/privacy_pass.rs:109](../../src/privacy_pass.rs)):

| Outcome | When | Trust granted? |
|---|---|---|
| `Valid` | The signature is valid AND the nonce has not been seen before | ✅ Yes |
| `UnknownIssuer` | `token_key_id` not found in the registry | ❌ |
| `BadSignature` | The signature does not match / has the wrong length | ❌ |
| `Replayed` | The nonce is already in the replay cache | ❌ |
| `Malformed` | (at the `parse_token` level → `None`) | ❌ |
| `UnsupportedAlgorithm` | The algorithm is recognised, but the key is invalid / the algorithm is not implemented | ❌ (fail closed, but observable) |

The order of checks in `verify`: **issuer lookup → message reconstruction → signature verification → replay check**. Replay is marked only **after** a successful signature check, so an invalid signature does not "poison" the replay cache with someone else's nonces.

---

## 5. The trusted issuers registry

### 5.1. Structures

`TrustedIssuer` ([src/privacy_pass.rs:50](../../src/privacy_pass.rs)):

| Field | Type | Description |
|---|---|---|
| `key_id` | `[u8; 32]` | RFC 9578 `token_key_id`, the lookup key in the registry |
| `name` | `String` | Human-readable name (e.g. `cloudflare-research.com`) |
| `public_key` | `Vec<u8>` | The issuer's public key (32 bytes for Ed25519) |
| `algorithm` | `SignatureAlgorithm` | `Ed25519` or `HmacSha256` |
| `trust_duration` | `Duration` | How long a verified token grants trust before a re-challenge |

The registry is stored in `PrivacyPassVerifier` ([src/privacy_pass.rs:125](../../src/privacy_pass.rs)) as an `RwLock<HashMap<[u8;32], TrustedIssuer>>`. Registration is **idempotent by `key_id`** — a repeated `register_issuer` with the same `key_id` overwrites the entry (test `issuer_registration_idempotent_per_key_id`, [src/privacy_pass.rs:505](../../src/privacy_pass.rs)).

### 5.2. Panel-safe view (`IssuerInfo`)

`list_issuers` ([src/privacy_pass.rs:159](../../src/privacy_pass.rs)) returns a `Vec<IssuerInfo>` ([src/privacy_pass.rs:87](../../src/privacy_pass.rs)) — a form that is safe to serialise to the admin panel:

| Field | Description |
|---|---|
| `name` | Issuer name |
| `key_id_hex` | `token_key_id` in full hex (this is the on-wire selector, not a secret) |
| `algorithm` | `ed25519` \| `hmac_sha256` |
| `public_key_fingerprint` | `sha256:<first 16 hex>` of the key bytes — **a fingerprint, not the key itself** |
| `trust_duration_secs` | The trust window in seconds |

> 🟡 Although Type-1 issuer keys are **public** verification keys (not secrets), the panel still receives only a fingerprint rather than the raw bytes. This keeps the contract correct should a future algorithm carry private material. The test `list_issuers_never_leaks_key_bytes` ([src/privacy_pass.rs:728](../../src/privacy_pass.rs)) checks that the raw key does not end up in the serialised JSON. The list is sorted by `key_id_hex` for a stable row order in the panel.

### 5.3. Key rotation

Rotation is implemented as a **static registry** that the Admin API can change at runtime (docstring [src/privacy_pass.rs:41](../../src/privacy_pass.rs)). There is **no** separate mechanism for automatic rotation/fetching of issuer keys — the operator registers/overwrites issuers manually through the API.

---

## 6. Replay protection (nonce cache)

`try_mark_seen` ([src/privacy_pass.rs:236](../../src/privacy_pass.rs)) stores seen nonces in an `RwLock<HashMap<[u8;32], Instant>>`, where the `Instant` is the **expiry moment** (`now + trust_duration`):

- If the nonce is already in the cache → `false` → `VerifyOutcome::Replayed`.
- On overflow (`cache_capacity`, default **100 000** via `PrivacyPassVerifier::default()`, [src/privacy_pass.rs:270](../../src/privacy_pass.rs)) **a single oldest** element is evicted (`min_by_key` by time).
- `gc()` ([src/privacy_pass.rs:257](../../src/privacy_pass.rs)) drops all expired nonces; call it from the same tick that services the actuator wheel.
- `nonce_cache_size()` reports the current size for metrics/the panel.

The test `gc_drops_expired_nonces` ([src/privacy_pass.rs:486](../../src/privacy_pass.rs)) confirms expiry and garbage collection.

---

## 7. Chained trust — the trust chain

Implementation: [src/chained_trust.rs](../../src/chained_trust.rs) (V202). The idea: **a stronger passed challenge grants a longer trust window**, and a passed strong challenge exempts the client from re-solving weaker ones for that window (docstring [src/chained_trust.rs:1](../../src/chained_trust.rs)).

### 7.1. Tiers (`TrustTier`) and windows

`TrustTier` ([src/chained_trust.rs:50](../../src/chained_trust.rs)) is an ordered enumeration; the windows are set by `default_duration` ([src/chained_trust.rs:63](../../src/chained_trust.rs)):

| Tier | `as_str` | Trust window | Covers |
|---|---|---|---|
| `None` | `none` | 0 | — |
| `Cookie` | `cookie` | 5 minutes | L1+L2 |
| `Reload` | `reload` | 15 minutes | L1..L3 |
| `Interaction` | `interaction` | 30 minutes | — |
| `Pow` | `pow` | 1 hour | L1..L4 |
| `Captcha` | `captcha` | 24 hours | L1..L5 |
| `WebAuthn` | `webauthn` | **7 days** | L1..L6 |
| `PrivacyPass` | `privacy_pass` | 24 hours (issuer-specified) | — |

Privacy Pass enters this ladder as a separate `PrivacyPass` tier. Note: its `default_duration` is 24 hours, but the real `trust_duration` is set by the issuer in `TrustedIssuer`, and the nonce replay window equals at least one `trust_duration`.

### 7.2. Binding the grant to a signed nonce (V233 auth_bypass fix)

> 🔴 This was a critical fix. Previously the trust grant was bound to the **bare IP**. Anyone behind a shared CGNAT / corporate NAT egress could "ride" a 24-hour grant the moment **one** peer behind the same IP passed a challenge.

Now every grant is bound to a server-side random nonce delivered to a specific client as a cookie. Implementation ([src/chained_trust.rs:21-32](../../src/chained_trust.rs)):

- The grant is stored under the key `(IpAddr, RouteClass, nonce)` ([src/chained_trust.rs:119](../../src/chained_trust.rs)).
- `mint_nonce` ([src/chained_trust.rs:162](../../src/chained_trust.rs)) generates 16 random bytes and signs them.
- `sign_nonce` ([src/chained_trust.rs:171](../../src/chained_trust.rs)) issues a cookie of the form `base64(nonce).base64(hmac)`, where the HMAC is taken over `ip:nonce` — a cookie issued for one IP **does not verify under another**.
- `verify_nonce` ([src/chained_trust.rs:186](../../src/chained_trust.rs)) is constant-time (`Mac::verify_slice`); anything malformed/bad-base64/wrong-IP/forged → `None`.
- `current()`/`covers()` ([src/chained_trust.rs:253](../../src/chained_trust.rs), [src/chained_trust.rs:287](../../src/chained_trust.rs)) require the client to present a matching signed cookie. **A missing or mismatched cookie → `TrustTier::None`.** A bare IP is never enough.

The regression test `grant_not_honoured_for_same_ip_with_different_or_absent_nonce` ([src/chained_trust.rs:447](../../src/chained_trust.rs)) covers exactly the shared-CGNAT bypass.

### 7.3. The HMAC key and surviving restarts

`ChainedTrustStore::new()` ([src/chained_trust.rs:130](../../src/chained_trust.rs)) generates a random 32-byte **per-process** HMAC key. Consequence: signed nonces cannot be forged without reading process memory, but a **restart also invalidates** all issued cookies. To survive restarts / to operate across a fleet, use `with_secret(...)` ([src/chained_trust.rs:146](../../src/chained_trust.rs)) with an explicit operator secret (test `cookie_from_other_secret_rejected`, [src/chained_trust.rs:518](../../src/chained_trust.rs)).

### 7.4. Route classes (`RouteClass`)

`RouteClass` ([src/chained_trust.rs:102](../../src/chained_trust.rs)):

| Class | Routes | Behaviour |
|---|---|---|
| `Generic` | everything except auth | Trust is granted automatically |
| `Auth` | `/login`, `/signup`, password reset | Trust is **never** granted automatically; an explicit opt-in `with_allow_for_auth(true)` is required |
| `Api` | `/api/*` | Configured separately (e.g. API consumers may authenticate through mTLS and bypass the ladder entirely) |

Grants are **independent** per class (test `route_classes_are_independent`, [src/chained_trust.rs:426](../../src/chained_trust.rs)). `record` on an auth route without opt-in returns `None`, and the operator knows that no cookie needs to be set ([src/chained_trust.rs:203-244](../../src/chained_trust.rs)).

### 7.5. Anti-downgrade

If `(ip, route_class)` already has a live **stronger** grant, `record` of a weaker tier does not downgrade trust — it returns the existing cookie of the stronger grant, and the client keeps the longer window ([src/chained_trust.rs:221-232](../../src/chained_trust.rs); test `stronger_grant_not_downgraded_by_weaker`).

### 7.6. Revocation and GC

- `revoke(ip)` ([src/chained_trust.rs:300](../../src/chained_trust.rs)) — drops **all** per-nonce grants for an IP across all classes (e.g. on tampering with the `aegis_fp` cookie or after a deny decision).
- `gc()` ([src/chained_trust.rs:305](../../src/chained_trust.rs)) — drops expired grants.

---

## 8. Integration and toggles

### 8.1. Arsenal

The verifier and the trust store live in `Arsenal` as `Arc`-wrapped singletons ([src/arsenal.rs:422-507](../../src/arsenal.rs)):

```rust
pub chained_trust: Arc<ChainedTrustStore>,   // ::new()  (process-random secret)
pub privacy_pass:  Arc<PrivacyPassVerifier>, // ::default() (cache_capacity = 100_000)
```

The toggles in `DomainChallengeConfig` ([src/arsenal.rs:52-58](../../src/arsenal.rs)) are **per-host, both disabled by default** (`#[serde(default)]` on `bool` → `false`):

| Field | Default | Purpose |
|---|---|---|
| `privacy_pass` | `false` | Enable the Privacy Pass bypass on this host |
| `chained_trust` | `false` | Enable the trust progression chain |
| `trust_for_auth` | `false` | Allow trust progression on auth routes |

Counters (`ShardedCounter`, [src/arsenal.rs:166-169](../../src/arsenal.rs)): `privacy_pass_accepts`, `privacy_pass_rejects`, `chained_trust_grants`, `chained_trust_bypasses`.

### 8.2. Admin API

The handlers are in [src/proxy/pingora_admin.rs](../../src/proxy/pingora_admin.rs):

| Method | Path | Action |
|---|---|---|
| `GET` | `/admin/api/privacy-pass` | Summary: `issuer_count`, `nonce_cache_size`, `wired` ([:2392](../../src/proxy/pingora_admin.rs)) |
| `GET` | `/admin/api/privacy-pass/issuers` | The full list of issuers (`IssuerInfo`) for the panel ([:2412](../../src/proxy/pingora_admin.rs)) |
| `POST` | `/admin/api/privacy-pass/issuers` | Register an issuer at runtime ([:2427](../../src/proxy/pingora_admin.rs)) |

The POST request body (`Payload`, [src/proxy/pingora_admin.rs:2428](../../src/proxy/pingora_admin.rs)):

```json
{
  "name": "cloudflare-research.com",
  "key_id_hex": "<64 hex characters = 32 bytes>",
  "public_key_hex": "<public key in hex>",
  "algorithm": "ed25519",
  "trust_duration_secs": 86400
}
```

Server-side validation:
- `key_id_hex` must be **64 hex characters** (32 bytes), otherwise `400`.
- `algorithm` must be `ed25519` or `hmac_sha256`, otherwise `400`.
- `trust_duration_secs` is forcibly raised to **at least 60 seconds** (`.max(60)`, [src/proxy/pingora_admin.rs:2466](../../src/proxy/pingora_admin.rs)).

An example of registering an Ed25519 issuer:

```bash
curl -sS -X POST http://127.0.0.1:6280/admin/api/privacy-pass/issuers \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "cloudflare-research.com",
    "key_id_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "public_key_hex": "<32-byte Ed25519 pubkey in hex>",
    "algorithm": "ed25519",
    "trust_duration_secs": 86400
  }'
# → {"ok":true,"name":"cloudflare-research.com"}
```

The summary is also available in the general admin snapshot: `trust_grants_active` and `privacy_pass_issuers` ([src/proxy/pingora_admin.rs:1334-1335](../../src/proxy/pingora_admin.rs)). More about the API — Admin API — reference.

---

## 9. What actually works and what does not

> Adherence to the security model and to the briefing's honesty caveats is mandatory.

**✅ Implemented and tested:**
- Parsing of the RFC 9578 Type-1 token (raw form) and reconstruction of the signed message.
- Production Ed25519 verification through `verify_strict` (protection against malleable/torsion signatures).
- Distinguishing `InvalidKey` (config error → `UnsupportedAlgorithm`) from `BadSignature` (forgery), fail-closed.
- Nonce replay cache with capacity eviction and GC.
- Runtime issuer registry + panel-safe `IssuerInfo` (fingerprint, not the raw key).
- Admin API (GET summary/list, POST registration) with validation.
- Chained trust with a per-nonce HMAC cookie (closes the shared-CGNAT auth_bypass, V233).

**🟡 Partially / not implemented (per the docstring [src/privacy_pass.rs:35-44](../../src/privacy_pass.rs)):**
- **The verifier is NOT called from the request path.** In [src/proxy/pingora_http.rs](../../src/proxy/pingora_http.rs) there are no calls to `parse_token`/`privacy_pass.verify`. The `PrivateToken` header is currently not parsed in the production handler — the Privacy Pass bypass in the data plane is not yet wired up. This is a foundation (verifier + registry + API + counters), not an end-to-end filter.
- **Type-2 (Blind Signature Scheme) private tokens are NOT implemented.** Only Type-1 public verification is supported, because every major issuer publishes its key. For Type-2, operators need a separate issuer client.
- **The HTTP-semantic RFC 9578 encoding is NOT implemented** — a simplified raw byte form of the token is accepted.
- **`HmacSha256` is for tests only**, not for production (a shared secret breaks the anonymity of public verification).
- **There is no automatic issuer key rotation** — the registry is static, keys are changed manually through the Admin API.

**Operational notes:**
- With `ChainedTrustStore::new()` (the default) the HMAC key is per-process random → all issued trust cookies are invalidated on restart. For durability, set a shared secret through `with_secret`.
- Both toggles (`privacy_pass`, `chained_trust`) are disabled by default — enable them per host through `DomainChallengeConfig` (see Cartography and per-domain policies).

---

## 10. Related documents

- [Challenge ladder, PoW and captcha](./15-challenge-ladder.md) — the ladder into which the Privacy Pass tier is embedded.
- Defence Arsenal, scenarios and actuators — where the verifier and the trust store live.
- Admin API — reference — the full reference for `/admin/api/privacy-pass/*`.
- Security model and hardening — the general threat model.
- Cartography and per-domain policies — the per-host toggles.
- Glossary — the terms Privacy Pass, replay, TrustTier.
