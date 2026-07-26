# Rate limiting

**Languages:** **English** · [Русский](../ru/14-rate-limiting.md) · [中文](../zh/14-rate-limiting.md)

AEGIS limits request intensity at several levels: per-IP (with IPv6 collapsed
into `/64`), per `/24`/`/16` subnet (for IPv4) and `/48`/`/32` (for IPv6),
per-URI, and under production load additionally — in a distributed way through
Redis (an atomic token bucket in Lua) and at the HTTP/2 frame level
(Tempesta-style budgets against Rapid Reset and related attacks). All local
limits are token buckets with lazy refill; a global L3/L4 flood is not covered by
this (see the caveats below and BGP RTBH, [XDP/eBPF](./13-xdp-ebpf.md)).

Sources: [`src/filters/rate_limit.rs`](../../src/filters/rate_limit.rs),
[`src/h2_budget.rs`](../../src/h2_budget.rs),
[`src/state/reputation.rs`](../../src/state/reputation.rs),
[`src/config.rs`](../../src/config.rs),
[`src/domain_policy.rs`](../../src/domain_policy.rs).

---

## 1. Overview of the levels

AEGIS implements rate limiting in three independent places in the code — it is
important to understand this, because they are configured and behave differently:

| Level | Module | Where it is counted | Purpose |
|---|---|---|---|
| Local per-IP / per-subnet / per-URI | [`src/filters/rate_limit.rs`](../../src/filters/rate_limit.rs) | In worker memory (`DashMap`) | The main L7 rate limit on the hot path of the filter chain |
| Distributed per-(host,IP) | [`src/state/reputation.rs`](../../src/state/reputation.rs) (called from [`src/proxy/http.rs`](../../src/proxy/http.rs)) | In Redis under Lua `EVAL` | A consistent limit shared across several workers/instances |
| HTTP/2 frame budgets per-connection | [`src/h2_budget.rs`](../../src/h2_budget.rs) | In memory (RwLock + FxHashMap) | Protection against Rapid Reset / Settings / Ping / CONTINUATION flood |

> 🟡 These are **different** mechanisms, not one mechanism with three backends.
> The local `RateLimitFilter` (DashMap) and the distributed Redis bucket exist in
> parallel. The Redis path is currently used predominantly in the legacy hyper
> handler ([`src/proxy/http.rs`](../../src/proxy/http.rs)), see §5.

---

## 2. Local token bucket (`RateLimitFilter`)

### 2.1 Algorithm

Every key holds a `Bucket { tokens: f64, last_refill: Instant }` structure
([`rate_limit.rs:93`](../../src/filters/rate_limit.rs#L93)). The refill is
computed lazily at check time, with no timers
([`rate_limit.rs:432`](../../src/filters/rate_limit.rs#L432)):

```rust
let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
entry.tokens = (entry.tokens + elapsed * rate).min(burst);
entry.last_refill = now;
if entry.tokens >= 1.0 { entry.tokens -= 1.0; true } else { false }
```

- `rate` — tokens per second (steady-state RPS).
- `burst` — bucket capacity (the maximum instantaneous spike).
- Exactly 1 token is deducted per request. When there is less than 1 token left,
  the request is rejected.

### 2.2 Bucket key (`RateKey`)

The key is a fixed-size structure (not a string), so as to avoid `format!()`
allocations on every request
([`rate_limit.rs:19`](../../src/filters/rate_limit.rs#L19)):

```rust
struct RateKey { scope: u8, ip: IpAddr, host_hash: u64 }
```

- `scope`: `0` = per-IP, `1` = `/24`(`/48`), `2` = `/16`(`/32`).
- `host_hash`: a 64-bit hash of the Host header (`DefaultHasher`), so that limits
  are counted separately per domain. The probability of a host collision is
  ~1/2⁶⁴ — ignored as insignificant ([`rate_limit.rs:24`](../../src/filters/rate_limit.rs#L24)).

### 2.3 IPv6: collapsing into `/64` for per-IP

🔴 Previously the per-IP bucket for IPv6 was keyed by the full `/128`, and an
attacker could rotate addresses within their own `/64` (SLAAC hands out an entire
`/64` per host), bypassing the per-IP limit completely — this is finding **H3** in
SECURITY-AUDIT. Fixed: the per-IP key for IPv6 is truncated to `/64`
([`IPV6_PER_IP_PREFIX = 64`, rate_limit.rs:38](../../src/filters/rate_limit.rs#L38),
[`RateKey::ip`, rate_limit.rs:41](../../src/filters/rate_limit.rs#L41)). IPv4 is
still keyed by the full `/32` (one host = one address).

The behaviour is pinned by the tests `ipv6_per_ip_key_collapses_same_64` and
`ipv6_rotation_within_64_shares_quota`
([rate_limit.rs:855](../../src/filters/rate_limit.rs#L855)).

### 2.4 Subnet buckets

Optionally (`subnet_buckets`, **disabled** by default ⚠️) AEGIS additionally
deducts tokens from subnet buckets. The logic is in `check()`
([rate_limit.rs:576](../../src/filters/rate_limit.rs#L576)): first per-IP, then
`/24`, then `/16`. Any empty bucket yields `Deny 429`.

| scope | IPv4 prefix | IPv6 prefix | rate/burst |
|---|---|---|---|
| per-IP | `/32` | `/64` | `rate`, `burst` |
| `subnet24` | `/24` | `/48` | `rate × subnet_24_multiplier`, `burst × …` |
| `subnet16` | `/16` | `/32` | `rate × subnet_16_multiplier`, `burst × …` |

IPv6 truncation is done by `v6_prefix()`
([rate_limit.rs:486](../../src/filters/rate_limit.rs#L486)): `/48` for `subnet24`
and `/32` for `subnet16` ([rate_limit.rs:61](../../src/filters/rate_limit.rs#L61),
[L75](../../src/filters/rate_limit.rs#L75)).

The multipliers (`max(1)`, `8` and `64` by default) widen the subnet budget so
that legitimate NAT/ISP pools do not look like a single "noisy" client, while a
botnet of thousands of `/32`s inside one `/24` still hits the shared subnet
budget. The behaviour is pinned by the tests
`subnet_bucket_blocks_botnet_within_24` and `..._16`
([rate_limit.rs:709](../../src/filters/rate_limit.rs#L709)).

> 🟠 **Honesty caveat:** `subnet_buckets` defaults to `false`. Without explicitly
> enabling it, IPv6 evasion via adjacent `/64`s within a single `/48` is not
> covered by the subnet logic (per-IP already collapses `/64`, but the
> cross-subnet budget is inactive). This is part of finding **H3** in
> SECURITY-AUDIT. The audit's recommendation for IPv6 environments:
> `subnet_buckets = true`.

### 2.5 Per-URI budgets (URI budgets)

A separate set of limits on specific paths (`uri_budgets`). The matcher
([`UriMatcher`, rate_limit.rs:177](../../src/filters/rate_limit.rs#L177)) supports
only two kinds of patterns:

- **Exact** — an exact path, e.g. `/login`.
- **Prefix** — a pattern with a trailing `*`, e.g. `/api/*`.

Matching is **first-match-wins**, so specific paths must be listed before the
catch-all. The comparison is done on the path only; the query string is stripped
(`ctx.path.split('?')`, [rate_limit.rs:542](../../src/filters/rate_limit.rs#L542)).

The URI bucket is charged **first**, even before the per-IP bucket
([rate_limit.rs:543](../../src/filters/rate_limit.rs#L543)), but the
per-IP/subnet buckets are charged too — so that a client cannot "hop" between
matched URIs and burn the whole connection budget. The URI bucket key is the
string `uri|{matcher.key}|{host}|{client_ip}`
([rate_limit.rs:549](../../src/filters/rate_limit.rs#L549)); a string is kept
here (not a `RateKey`), since the pattern identity is the natural key and the
path is rare.

Exceeding a URI budget → `Deny { status: 429, reason: "uri rate limit exceeded (<pattern>)" }`.

### 2.6 Hot-URI tracking

An optional detector of "hot" paths (`hot_uri_rps_threshold`, `0` by default =
disabled, [config.rs:735](../../src/config.rs#L735)). This is **only an observer
— it never blocks anything itself**
([config.rs:717](../../src/config.rs#L717)).

`HotUriTracker` ([rate_limit.rs:209](../../src/filters/rate_limit.rs#L209)) holds
per path a `VecDeque<Instant>` of request timestamps over a sliding `1s` window.
When the number of hits per second reaches the threshold, a
`tracing::warn!("hot URI detected")` is written
([rate_limit.rs:558](../../src/filters/rate_limit.rs#L558)). `VecDeque` was
chosen so that expiring old timestamps is an O(1) `pop_front()` instead of an
O(n) `Vec::remove(0)` — this is part of finding **H2** in SECURITY-AUDIT.

The top hot paths are available through `hot_uris(limit)`
([rate_limit.rs:372](../../src/filters/rate_limit.rs#L372)) and are served to the
admin panel (`/admin/hot_uris`, see Admin API).

### 2.7 Dynamic trust — bypassing the limit

Right at the start of `check()`, trusted clients skip past the rate limit
([rate_limit.rs:514](../../src/filters/rate_limit.rs#L514)):

```rust
if ctx.is_trusted { return FilterAction::Allow; }
```

Trust is earned through clean traffic (see
[`src/filters/dynamic_trust.rs`](../../src/filters/dynamic_trust.rs) and
Arsenal/scenarios). Throttling exists to protect against spikes from unknown
clients; trusted clients have already "paid" the audit.

### 2.8 Memory bounding and cleanup

The state maps are bounded by hard limits, otherwise rotating addresses/URIs
turns the rate limiter into a memory-exhaustion vector (finding **H2**,
SECURITY-AUDIT):

| Map | Limit | Constant |
|---|---|---|
| per-IP/subnet `state` | `1 048 576` | [`MAX_STATE_ENTRIES`, rate_limit.rs:132](../../src/filters/rate_limit.rs#L132) |
| URI `uri_state` | `262 144` | [`MAX_URI_STATE_ENTRIES`, rate_limit.rs:135](../../src/filters/rate_limit.rs#L135) |

Once the limit is reached, inserting a new key first **evicts the oldest entry**
(LRU-ish by `last_refill`, [`evict_oldest_state`,
rate_limit.rs:405](../../src/filters/rate_limit.rs#L405)), mirroring the
`evict_lru` pattern from `dynamic_trust.rs`. Both `DashMap`s are sharded into 128
shards for parallelism (V230,
[rate_limit.rs:335](../../src/filters/rate_limit.rs#L335)).

There is additionally `cleanup_stale(now)`
([rate_limit.rs:474](../../src/filters/rate_limit.rs#L474)), which removes entries
older than `stale_after` (fixed at `300s`,
[rate_limit.rs:338](../../src/filters/rate_limit.rs#L338)) and cleans the hot-URI
map.

> 🟠 **Honesty caveat (H2):** the comment in the code states outright that the
> "deployed pingora path **never wires `cleanup_stale` into a background loop**"
> ([rate_limit.rs:124](../../src/filters/rate_limit.rs#L124)). Therefore
> protection against map growth in the Pingora path rests on the hard cap +
> eviction, not on periodic cleanup. In SECURITY-AUDIT, H2 is marked as "fixing
> (+ integration)" — check the audit itself for the status of the fixes.

---

## 3. Configuration of the local limit

The `RateLimitConfig` structure
([config.rs:692](../../src/config.rs#L692)). In the DSL/TOML this is the
`[filters.rate_limit]` section (for the exact grammar see
[Configuration](./04-configuration.md)).

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | — | A config-time flag. ⚠️ `check()` itself does **not** rely on it (see §6) |
| `requests_per_second` | u64 | — | Global per-IP rate |
| `burst` | u64 | — | Global per-IP burst |
| `subnet_buckets` | bool | `false` | Enable `/24`(`/48`) and `/16`(`/32`) limits |
| `subnet_24_multiplier` | u64 | `8` ([config.rs:739](../../src/config.rs#L739)) | Budget multiplier for `/24`(`/48`) |
| `subnet_16_multiplier` | u64 | `64` ([config.rs:742](../../src/config.rs#L742)) | Budget multiplier for `/16`(`/32`) |
| `uri_budgets` | `Vec<UriBudget>` | `[]` | Per-URI limits (first-match-wins) |
| `hot_uri_rps_threshold` | u64 | `0` (off) | hits/sec threshold for the "hot URI" log |

`UriBudget` ([config.rs:726](../../src/config.rs#L726)):

| Field | Description |
|---|---|
| `pattern` | Exact (`/login`) or prefix glob (`/api/*`). Path only, query ignored |
| `requests_per_second` | The rate of this bucket |
| `burst` | The burst of this bucket |

### Example (conceptual)

```toml
[filters.rate_limit]
enabled = true
requests_per_second = 20
burst = 40
subnet_buckets = true        # recommended, especially for IPv6
subnet_24_multiplier = 8
subnet_16_multiplier = 64
hot_uri_rps_threshold = 200  # log only, no blocking

[[filters.rate_limit.uri_budgets]]
pattern = "/login"           # exact: expensive auth endpoint
requests_per_second = 1
burst = 5

[[filters.rate_limit.uri_budgets]]
pattern = "/api/*"           # prefix glob
requests_per_second = 10
burst = 20
```

> Take the exact section syntax from [Configuration (DSL and TOML)](./04-configuration.md);
> the build and environment variables are in [`install.sh`](../../install.sh) (see
> [Installation and operations](./03-installation.md)).

---

## 4. Per-domain overrides

Limits are selected by host in the following priority order (`check()`,
[rate_limit.rs:529](../../src/filters/rate_limit.rs#L529)):

1. **Runtime per-host overlay (V234)** — `domain_policy.rate_limit_for(host)`.
   This is an override set through the admin API
   (`PUT /admin/api/sites/<host>/policy`, see Admin API), disk-backed and
   cross-worker. It works even for ops-managed sites whose `.conf` is read-only
   ([domain_policy.rs:117](../../src/domain_policy.rs#L117),
   [domain_policy.rs:550](../../src/domain_policy.rs#L550)). When there are no
   overrides, this is a single relaxed atomic load (empty-gate fast path).
2. **Static `domain_limits`** — `limits_for_host(host)`
   ([rate_limit.rs:379](../../src/filters/rate_limit.rs#L379)):
   - an exact host match wins;
   - a leading dot in the key (`.example.com`) works as a suffix glob and matches
     `api.example.com`, `www.example.com` — it lets you give a shared bucket to
     the apex + subdomains.
3. **Global** `requests_per_second` / `burst`.

`RateLimitOverride` ([domain_policy.rs:86](../../src/domain_policy.rs#L86)) stores
`rps` and `burst` (both `u64`, per-IP semantics, as in the global filter). The
overlay behaviour is pinned by the test
`domain_policy_overlay_overrides_global_per_host`
([rate_limit.rs:663](../../src/filters/rate_limit.rs#L663)). More details —
Cartography and per-domain policies.

---

## 5. Distributed limit through Redis

This is a **separate** mechanism from §2: an atomic token bucket executed
entirely inside Redis as a Lua script under `EVAL`
([`TOKEN_BUCKET_LUA`, reputation.rs:11](../../src/state/reputation.rs#L11)). All
refill/decrement arithmetic happens atomically, so concurrent calls from many
workers/instances do not "overspend" the budget
([reputation.rs:83](../../src/state/reputation.rs#L83)).

- Key: `aegis:tb:{key}`, where `key = redis_tb_key(host, ip)` — a fixed hash
  digest of host+IP. 🔴 The key used to be `{host}|{ip}`; since the Host is fully
  attacker-controlled and may contain `|`, changing the Host on every request
  minted a new bucket and bypassed the limiter. Fixed in **V233** by hashing both
  components ([http.rs:932](../../src/proxy/http.rs#L932),
  [http.rs:2159](../../src/proxy/http.rs#L2159)).
- Script response: `(allowed, value)`. When `allowed=1`, value is the remaining
  tokens (`BucketOutcome::Allowed { tokens_left }`); when `allowed=0`, value is
  the milliseconds until the next attempt (`Throttled { retry_after_ms }`), which
  is used for the `Retry-After` header
  ([reputation.rs:48](../../src/state/reputation.rs#L48)).
- The key TTL is set automatically:
  `max(1000, ceil(burst / max(rate,1) * 2000))` ms
  ([reputation.rs:26](../../src/state/reputation.rs#L26)).

### Fail-open

If Redis is unavailable or the EVAL failed, the path **opens (fail-open)** — the
backend must not go down because of a storage outage
([http.rs:950](../../src/proxy/http.rs#L950),
[`distributed_rate_exceeded`, http.rs:927](../../src/proxy/http.rs#L927)). The
bucket is not used at all when storage is not configured
(`storage.redis_url`, [config.rs:350](../../src/config.rs#L350); validated as
`redis://…`, [config.rs:1090](../../src/config.rs#L1090)).

> 🟠 **Honesty caveat:** in the current code the distributed Redis bucket is
> called from the **legacy hyper handler**
> ([`src/proxy/http.rs`](../../src/proxy/http.rs)). The production data plane on
> Pingora uses the local `RateLimitFilter` (§2); in the Pingora path the reason
> for a 429 is called `distributed_rate` only as a label of the message shown to
> the visitor ([pingora_http.rs:3141](../../src/proxy/pingora_http.rs#L3141)),
> not as a call to Redis. Do not consider the Redis bucket active on the Pingora
> path without explicitly verifying your own build/configuration.

---

## 6. Interaction with the FilterEngine and the `enabled` flag

⚠️ **An important subtlety (V231):** `RateLimitFilter::check()` does **not**
self-gate on `self.enabled`
([rate_limit.rs:505](../../src/filters/rate_limit.rs#L505)). The decision of
"whether to run the filter" is made by the `FilterEngine` through
`RuntimeToggles` and the per-domain `domain_policy` — this is a single source of
truth, otherwise per-domain overrides would be double-gated and would break
([rate_limit.rs:358](../../src/filters/rate_limit.rs#L358)).

- `config_enabled()` ([rate_limit.rs:363](../../src/filters/rate_limit.rs#L363)) —
  read by the engine when registering the `RuntimeToggle`.
- Per-filter on/off for a host is set through
  `DomainPolicy.filter_enabled["rate_limit"]`
  ([domain_policy.rs:106](../../src/domain_policy.rs#L106)).

The request lifecycle and the place of the rate limit in the filter chain are in
[Architecture](./02-architecture.md). The adjacent mechanism of adaptive
escalation (RPS penalty, exempt paths) is `AdaptiveConfig`
([config.rs:746](../../src/config.rs#L746)), see ML and risk engine and
Arsenal/scenarios.

---

## 7. HTTP/2 frame budgets (`h2_budget`)

V182, [`src/h2_budget.rs`](../../src/h2_budget.rs). Tempesta-style budgets on
HTTP/2 control frames, targeting CVE-2023-44487 (Rapid Reset), CVE-2024-27316
(CONTINUATION flood) and the "Made You Reset" / Settings / Ping flood family. All
of these attacks exploit how cheap a particular control frame is on the server
side; the fix is a per-connection budget checked **before** the frame reaches the
HTTP/2 state machine.

This is a **separate** token bucket (`tokens: f32`,
[h2_budget.rs:92](../../src/h2_budget.rs#L92)) with lazy refill, keyed by the pair
`(conn_id, FrameKind)` ([h2_budget.rs:118](../../src/h2_budget.rs#L118)). When
the bucket is empty, `Verdict::Reject` is returned and the caller is obliged to
close the stream/connection
([h2_budget.rs:143](../../src/h2_budget.rs#L143)).

### Default budgets

`Budget::default_for(kind)` ([h2_budget.rs:73](../../src/h2_budget.rs#L73)):

| Frame (`FrameKind`) | Burst | Refill/s | Against what |
|---|---:|---:|---|
| `RstStream` | 50 | 20 | Rapid Reset |
| `Settings` | 10 | 2 | Settings flood |
| `Ping` | 30 | 10 | Ping flood |
| `Priority` | 100 | 50 | Priority churn |
| `Goaway` | 3 | 1 | should be rare |
| `Continuation` | 50 | 20 | CONTINUATION flood |

Overrides are set programmatically:
`with_override(kind, Budget { burst, refill_per_s })`
([h2_budget.rs:131](../../src/h2_budget.rs#L131)). The briefing notes that they
are operator-tunable through the DSL; in the module itself the API is only
`with_override`.

### State management

- `consume(conn_id, kind)` — the main hot path
  ([h2_budget.rs:143](../../src/h2_budget.rs#L143)).
- `drop_conn(conn_id)` — drops all state of a closed connection
  ([h2_budget.rs:151](../../src/h2_budget.rs#L151)).
- `gc(idle)` — background cleanup of idle buckets
  ([h2_budget.rs:157](../../src/h2_budget.rs#L157)).
- `FxHashMap` instead of SipHash, since the keys (conn-local sequential IDs + a
  small enum) are not attacker-controlled
  ([h2_budget.rs:36](../../src/h2_budget.rs#L36)).

The per-connection budgets are confirmed by tests
(`rapid_reset_burst_blocked_after_budget`, `budgets_are_per_connection`,
[h2_budget.rs:185](../../src/h2_budget.rs#L185)). The module is integrated through
`H2Guard` ([`src/proxy/h2_guard.rs`](../../src/proxy/h2_guard.rs)) and Arsenal
([`src/arsenal.rs`](../../src/arsenal.rs)); the comment in the module describes
how the same budget logic is designed to be mirrored into the XDP fast path for
kernel-side enforcement ([h2_budget.rs:10](../../src/h2_budget.rs#L10), see
[XDP/eBPF](./13-xdp-ebpf.md)).

> 🟠 **Honesty caveat (C3):** the related finding **C3** in SECURITY-AUDIT notes
> that some hard HTTP/2 limits (`max_header_list_size`, concurrent streams)
> **cannot be set on Pingora 0.8.0 without upgrading the framework** — status
> "deferred (needs pingora upgrade)". `h2_budget` covers the frame-flood budgets,
> but it does not fully replace the missing framework settings.

---

## 8. Response codes

| Situation | Action | Status | Reason / message |
|---|---|---|---|
| per-IP limit exceeded | `FilterAction::Deny` | `429` | `"rate limit exceeded"` ([rate_limit.rs:566](../../src/filters/rate_limit.rs#L566)) |
| `/24`(`/48`) exceeded | `FilterAction::Deny` | `429` | `"subnet /24 rate limit exceeded"` ([rate_limit.rs:584](../../src/filters/rate_limit.rs#L584)) |
| `/16`(`/32`) exceeded | `FilterAction::Deny` | `429` | `"subnet /16 rate limit exceeded"` ([rate_limit.rs:596](../../src/filters/rate_limit.rs#L596)) |
| URI budget exceeded | `FilterAction::Deny` | `429` | `"uri rate limit exceeded (<pattern>)"` ([rate_limit.rs:551](../../src/filters/rate_limit.rs#L551)) |
| Redis bucket exceeded | returns `Some(retry_after_ms)` | `429` + `Retry-After` | legacy hyper ([http.rs:949](../../src/proxy/http.rs#L949)) |
| H2 frame budget exhausted | `Verdict::Reject` | — (stream/conn closed) | the caller ([h2_budget.rs:143](../../src/h2_budget.rs#L143)) |

In the Pingora path the deny is rendered through `respond_visitor_error()` with
the label `distributed_rate` → "Too many requests. Please wait before retrying."
([pingora_http.rs:3141](../../src/proxy/pingora_http.rs#L3141)).

All of these responses end up in the request log and in metrics/telemetry.

---

## 9. What rate limiting does NOT cover (honesty caveats)

1. **L3/L4 volumetric flood.** The token bucket works at L7 — on an
   already-accepted connection. A volumetric flood requires upstream protection:
   see BGP RTBH and [XDP/eBPF](./13-xdp-ebpf.md). Even a cached response requires
   an inbound connection, so without an upstream drop the backend can be
   overloaded (see the cache caveat in Performance).
2. **IPv6 evasion.** per-IP collapses `/64`, but the cross-subnet protection
   (`/48`/`/32`) depends on `subnet_buckets`, which is **disabled by default**
   (finding **H3**, SECURITY-AUDIT).
3. **HTTP/2 Rapid Reset at the framework level.** `h2_budget` provides budgets,
   but a number of hard H2 limits are unavailable on Pingora 0.8.0 (finding
   **C3**, "deferred").
4. **Map memory exhaustion.** The protection rests on the hard cap + LRU
   eviction; the background `cleanup_stale` is not wired into a loop in the
   Pingora path (finding **H2**) — check the current status in SECURITY-AUDIT.
5. **Rate-limit benchmarks are in-process.** The token bucket tests in
   [`src/bin/aegis-distbench.rs`](../../src/bin/aegis-distbench.rs) and `bench/`
   measure the filter engine **without network I/O** (token-bucket simulation).
   The full `aegis-pingora` under production load gives ↓15–30% relative to the
   synthetic figure (Pingora I/O, syscalls, TCP/TLS). Never quote an absolute RPS
   from the bench without the note "in-process filter relay, not a real
   deployment". More details — Benchmarking.

The authoritative source on the issues found and the status of the fixes is
SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md; a summary of the security model is in
Security model.

---

## See also

- [Architecture and the request lifecycle](./02-architecture.md)
- [Configuration (DSL and TOML)](./04-configuration.md)
- [XDP/eBPF kernel fast path](./13-xdp-ebpf.md)
- [Challenge ladder, PoW and captcha](./15-challenge-ladder.md)
- BGP RTBH
- Defence Arsenal, scenarios and actuators
- Cartography and per-domain policies
- Admin API — reference
- Security model and hardening
- Benchmarking and comparison with proxies
