# Enrichment and threat intel

**Languages:** **English** · [Русский](../ru/22-enrichment.md) · [中文](../zh/22-enrichment.md)

The enrichment subsystem gathers additional context about a client on top of the "bare" HTTP request: a passive OS/TCP-stack fingerprint (p0f), an optional antivirus scan of the body via `clamd` (ClamAV), and periodically refreshed deny lists from external threat-intel feeds (AbuseIPDB / Spamhaus DROP / FireHOL and the like). This document describes exactly what the code in `src/enrichment.rs`, `src/filters/threat_intel.rs`, `src/p0f.rs`, `src/clamav_scanner.rs` does, and where parts are enabled optionally.

> An honest note about scope: on the "live" path (`ArsenalState`), exactly one real production source implementation is currently registered in the enrichment facade — the JA4 corpus (`src/arsenal.rs:464`). The other sources (JA4/ASN reputation, GeoIP) have their own separate caches and paths and are not wired into `EnrichmentFacade` by default. This is flagged explicitly below.

---

## 1. Subsystem map

| Component | File | Purpose | Default state |
|---|---|---|---|
| Unifying enrichment facade (WISE style) | `src/enrichment.rs` | One cacheable facade over heterogeneous sources, a single lookup shape, an aggregated verdict | Enabled; 1 source registered (JA4 corpus) |
| Threat-intel deny list | `src/filters/threat_intel.rs` | Deny by exact IPs and CIDRs from local feed files, background reload | Active only if `paths` are set |
| p0f — passive OS fingerprint | `src/p0f.rs` | Classification of a TCP SYN (window/MSS/wscale/TTL/options) into an OS family | Built-in mini-DB; extensible with a file |
| ClamAV body scan | `src/clamav_scanner.rs` | Streams the upload body to `clamd` over INSTREAM TCP, verdict by signature | Disabled (opt-in via `AEGIS_CLAMAV_ADDR`) |

Related documents: WAF — [10-waf.md](10-waf.md), TLS fingerprinting and JA4T — [11-tls-fingerprinting.md](11-tls-fingerprinting.md), reputation — [12-reputation.md](12-reputation.md), XDP/eBPF (kernel-side CIDR path) — [13-xdp-ebpf.md](13-xdp-ebpf.md), GeoIP — [20-geoip.md](20-geoip.md), Arsenal/scenarios — [21-arsenal-scenarios.md](21-arsenal-scenarios.md), security model — [23-security-model.md](23-security-model.md), Admin API — [30-admin-api.md](30-admin-api.md).

---

## 2. The enrichment facade (`src/enrichment.rs`)

The idea is borrowed from Arkime WISE (Wireless Intelligence Sources Engine): one cacheable facade in front of every source, an identical lookup shape, per-source TTL and provenance (which source produced the verdict) carried through the response. This replaces the scheme where "every source has its own cache, and code that needs the full picture for an IP calls four times and merges the verdicts itself".

### 2.1. Keys and verdicts

The entity being enriched is an `EntityKey` (`src/enrichment.rs:55`):

| `EntityKey` variant | `kind_str()` | Source |
|---|---|---|
| `Ip(IpAddr)` | `"ip"` | Client IP |
| `Ja4(String)` | `"ja4"` | TLS JA4 fingerprint |
| `Asn(u32)` | `"asn"` | Autonomous system number |
| `UserAgent(String)` | `"ua"` | User-Agent |

The verdict of a source and of the aggregate is `Verdict` (`src/enrichment.rs:74`): `Allow`, `Deny`, `Unknown`.

### 2.2. A source as a read-through provider

A source implements the `EnrichmentSource` trait (`src/enrichment.rs:121`):

```rust
pub trait EnrichmentSource: Send + Sync {
    fn name(&self) -> &'static str;
    fn lookup(&self, key: &EntityKey) -> Option<(Verdict, String)>;
    fn default_ttl(&self) -> Duration { Duration::from_secs(30) }
}
```

- `name()` returns a `&'static str` — this keeps the cardinality of the per-source counters bounded.
- `lookup()` returns `None` when the source completed successfully but the key is not tracked by it. Explicit indeterminacy (for example, the GeoIP database is loaded but the country is not classified) is signalled as `Some((Verdict::Unknown, ...))`.
- The second element of the tuple is a `label` — a human-readable label/tag (`"sqlmap"`, `"aws"` and so on) that ends up in `SourceHit.label`.

### 2.3. Verdict aggregation

`Enrichment::aggregate()` (`src/enrichment.rs:98`) reduces all `SourceHit`s to a single verdict by the rule:

```
any Deny  →  Deny   (short-circuit)
else any Allow  →  Allow
else  →  Unknown
```

`Enrichment::deny_reasons()` (`src/enrichment.rs:109`) returns the `label` of every source that voted `Deny` — for logging/the panel.

### 2.4. The facade cache

`EnrichmentFacade` (`src/enrichment.rs:156`) holds:

- `sources: Vec<Arc<dyn EnrichmentSource>>` — the registered sources in registration order;
- `cache: RwLock<HashMap<EntityKey, CacheEntry>>` — the aggregated cache;
- `per_source_stats` — independent `queries/hits/misses` counters for each source;
- global `cache_hits`/`cache_misses` and `capacity`.

The behaviour of `lookup()` (`src/enrichment.rs:187`):

1. **Cache hit:** if the entry exists and `Instant::now() < entry.expires_at` — return a clone, increment `cache_hits`.
2. **Cache miss:** increment `cache_misses`, walk all the sources. `queries` is incremented for each; on `Some` — `hits` + a `SourceHit { source, verdict, label, fetched_at }` is added; on `None` — `misses`.
3. **Aggregate TTL:** `expires_at = now + shortest_ttl`, where `shortest_ttl` is the minimum of the `default_ttl()` of the sources that fired, but no more than the initial ceiling `Duration::from_secs(300)` (`src/enrichment.rs:199`). That is, the TTL of the aggregated entry = the minimum TTL of the contributors (the freshness of a reputation update stays visible).
4. The result is put into the cache and returned.

Eviction (`insert`, `src/enrichment.rs:243`): when `capacity` is reached, the single oldest entry by `inserted` is removed (a linear `min_by_key` scan). On the "live" path the facade is created with a capacity of **16,384** (`src/arsenal.rs:463`).

> A note on the cache semantics: this is not a classic access-based LRU — the entry with the smallest insertion time (insert order) is discarded, not the least recently accessed one. At working sizes (tens of thousands of entries, a short TTL) this is acceptable.

Other methods: `invalidate(key)` / `invalidate_all()` (`src/enrichment.rs:265`), `registered_sources()`, `source_stats(name) -> (queries, hits, misses)`, `cache_stats() -> (hits, misses, len)`.

### 2.5. Wiring on the live path and the admin API

In `ArsenalState::new_default()` the facade is built and **one** source is registered in it — `Ja4CorpusEnrichmentSource` over the shared `Ja4Corpus` (`src/arsenal.rs:460-468`). The `ArsenalState::enrich_ja4(ja4)` helper (`src/arsenal.rs:589`) hits the facade, increments `counters.enrichment_lookups` and returns the aggregate.

State and ad-hoc checks are available through the Admin API (`src/proxy/pingora_admin.rs`):

| Method | Path | What it returns |
|---|---|---|
| `GET` | `/admin/api/enrichment` | `wired`, per-source `{name, queries, hits, misses}`, `cache {hits, misses, size}` (`pingora_admin.rs:2131`, `:4077`) |
| `POST` | `/admin/api/enrichment/lookup` | For JSON `{key_kind, value}` (`ip`/`ja4`/`asn`/`user_agent`) — `aggregate` + a list of `sources [{source, verdict, label}]` (`pingora_admin.rs:2160`, `:4080`) |

The full list of admin routes — [30-admin-api.md](30-admin-api.md).

---

## 3. Threat-intel deny lists (`src/filters/threat_intel.rs`)

`ThreatIntelFilter` is a `TrafficFilter` (filter name `"threat_intel"`, `src/filters/threat_intel.rs:402`) that blocks the client IP against deny lists periodically re-read from local files.

### 3.1. Why it is a separate filter from the IP ACL

- `IpAclFilter` is curated by the operator and lives in the main config; a reload changes the whole set at once, and it cannot be updated several times a day from outside without reloading the config.
- `ThreatIntelFilter` holds an `Arc<RwLock<HashSet>>` (+ CIDR vectors) which a background task refreshes from one or more files. The operator fills them by cron: `curl` the feed into a file — Aegis re-reads it.

**Why local files rather than a direct HTTPS fetch** (from the comment in the module header): to avoid pulling yet another HTTPS client and cert pinning into the proxy; operators already have a familiar way of authenticating to paid feeds (curl+token, GitHub Actions, Vault); the file mtime gives free idempotency — re-reading an unchanged file is a no-op.

### 3.2. Configuration

The `filters.threat_intel` config section — the `ThreatIntelConfig` struct (`src/config.rs:647`):

| Field | Type | Default | Purpose |
|---|---|---|---|
| `paths` | `Vec<String>` | `[]` | Local paths to feed files (one entry per line) |
| `refresh_secs` | `u64` | `300` | How often to re-read the feed files |

```yaml
filters:
  threat_intel:
    paths:
      - /var/lib/aegis/feeds/spamhaus-drop.txt
      - /var/lib/aegis/feeds/firehol-level1.netset
      - /var/lib/aegis/feeds/abuseipdb-blacklist.txt
    refresh_secs: 300
```

An example of filling the feeds by cron (outside Aegis):

```bash
# Spamhaus DROP (CIDR only)
curl -s https://www.spamhaus.org/drop/drop.txt \
  -o /var/lib/aegis/feeds/spamhaus-drop.txt

# FireHOL Level 1
curl -s https://iplists.firehol.org/files/firehol_level1.netset \
  -o /var/lib/aegis/feeds/firehol-level1.netset
```

### 3.3. Feed file format

The `parse_feed_v113` parser (`src/filters/threat_intel.rs:202`) parses one entry per line:

- Everything after `#` is discarded (comments, including trailing ones), empty lines are ignored.
- A line with `/` → a CIDR, which goes into the per-family vectors. IPv4: `prefix <= 32`, IPv6: `prefix <= 128`; the mask is computed and the network is normalised (`net & mask`). `0.0.0.0/0` correctly matches everything.
- A bare IP → the exact-match HashSet (`O(1)` lookup).
- Invalid lines (a non-numeric prefix, an unparseable address) are silently skipped.

Both IPv4 and IPv6 are supported (exact addresses and CIDRs of both families).

### 3.4. Reload and CIDR coalescing

`reload()` (`src/filters/threat_intel.rs:100`) re-reads all the files and swaps the sets **atomically**:

- A file that could not be read is logged at `warn` level and skipped — one missing feed does not wipe out the rest.
- After assembly the CIDRs are coalesced: `coalesce_v4` / `coalesce_v6` (`:261`, `:299`) merge overlapping and adjacent ranges (interval merge → decomposition back into a minimal set of CIDRs). On real public feeds this is typically −30…50% of entries with no loss of coverage (every IP that matched before still matches after).
- The sets are written under `RwLock::write`, after which the fast-path sentinel is updated.

> Important about "mtime reload": reload re-reads the files **unconditionally** on the timer. `ThreatIntelFilter` itself does not compare mtimes — idempotency rests on the fact that re-reading an unchanged file produces the same set (the comment "file mtime gives free idempotency" refers to the operator's workflow). mtime-aware reload is implemented in neighbouring subsystems (JA4/ASN reputation — `src/proxy/pingora_background.rs:427-438`), not here.

The reload scheduler: in `aegis` (Hyper) — `tokio::spawn` with an interval of `refresh_secs.max(30)`; the first immediate tick is skipped since loading already happened at construction time (`src/server.rs:576-591`). The task is only created if `is_active()` (there is at least one path).

### 3.5. Hot-path checks

`check()` (`src/filters/threat_intel.rs:405`):

1. **Empty-set fast path (V237):** the atomic sentinel `has_entries` (the total number of exact IPs + CIDRs after coalescing) is read with `Acquire`. If it is `0` — an immediate `Allow` without a single `RwLock` acquisition. This removes three lock acquisitions from the hot path in plain forwarding and in deployments with no feed loaded. The sentinel is written with `Release` **after** the sets are committed in `reload()`.
2. Exact match against the `HashSet` (`O(1)`).
3. If not — `matches_cidr()` (`:176`): a linear scan of the per-family `(net, mask)` vector with `(host & mask) == net`.

Any hit → `FilterAction::Deny { status: 403, reason }` (`ip on threat-intel deny list` or `ip in threat-intel CIDR range`). The Deny constructor is factored out into `#[cold] #[inline(never)] ip_deny_cold` (V230) so that the hot Allow path (≈99% of traffic) stays compact in the icache.

**Scale:** the linear scan is designed for 10²–10⁴ entries (Spamhaus DROP is ~1000); at those sizes it is sub-microsecond. For very large feeds (10⁵+) the operator is advised to move the CIDRs into the **XDP CIDR maps** ([13-xdp-ebpf.md](13-xdp-ebpf.md)), where the lookup is done by the kernel.

### 3.6. Controlling activation

ThreatIntel has no on/off flag: it is always active when present (`config_enabled()` is always `true`, `src/filters/threat_intel.rs:78`) — empty sets are harmless (`Allow`). It can be forcibly disabled per domain through the web UI (the single source of truth for filter toggles is `RuntimeToggles`). Diagnostics: `entry_count()`, `cidr_count()`, `is_active()`.

---

## 4. p0f — passive OS/TCP-stack fingerprint (`src/p0f.rs`)

JA4T (in `src/ja4.rs`) captures the TCP SYN options but stops at a hash of the wire shape. p0f goes further: it classifies that shape into a likely OS family using a database of TCP-stack defaults. The value of the pairing: JA4T says "these two clients share one TCP stack"; p0f gives **"the client's UA calls itself Chrome on Windows, but its TCP stack is Linux"** — a strong proxy/sandbox/scraper signal for the fingerprint correlator (`crate::fp_correlation`).

> The scope is honestly limited: V155 is a focused minimal subset of p0f, not a full port. The full p0f corpus is not bundled (≈50KB added to the binary; 99% of operators only need the modern desktop/mobile clusters).

### 4.1. The classifier input — `Ja4tSyn`

`Ja4tSyn` (`src/p0f.rs:36`) — the SYN observations Aegis already captures (`src/tcp_info.rs::capture_with_xdp`, preferably eBPF, with a userspace `TCP_INFO` fallback):

| Field | Type | Meaning |
|---|---|---|
| `window` | `u16` | TCP window size in the SYN |
| `mss` | `u16` | Maximum Segment Size |
| `wscale` | `u8` | Window scale |
| `ttl` | `u8` | TTL of the first hop (p0f's main OS discriminator) |
| `options` | `[u8; 8]` | Option kinds in wire order (MSS=2, NOP=1, WSCALE=3, SACKOK=4, TS=8); trailing zeros = "no more options" |

### 4.2. Signature and TTL buckets

`olayout_string()` (`:57`) joins the non-zero options with `-` (for example `2-4-8-1-3`). `signature()` (`:70`) builds a p0f-like string:

```
<ttl_bucket>:<window>:<mss>:<wscale>:<olayout>
e.g.  64:64240:1460:7:2-4-8-1-3
```

`ttl_bucket(observed)` (`:86`) reconstructs the original TTL from the observed one (already decremented by hops): `0..=32→32`, `33..=64→64`, `65..=128→128`, `129..→255`.

> A subset of the full format: Aegis omits p0f's IP version, DF flag, quirks and payload class — the matcher relies only on the fields that are captured reliably.

### 4.3. Signature database and classification

`OsFamily` (`src/p0f.rs:99`): `Linux`, `Windows`, `Macos`, `Bsd`, `Ios`, `Android`, `Unknown` (a coarse classification — at the level the correlator needs; "Linux 2.6 vs 5.4" is rarely actionable for a security proxy).

The built-in database `OsDatabase::default()` (`:135`) is a `HashMap<signature → OsFamily>` with the modern desktop/mobile clusters as of 2024 (sources: `p0f-3.09b/p0f.fp`, the FoxIO JA4 cookbook, comparisons of Wireshark captures):

| Family | Example signatures |
|---|---|
| Linux 5.x+ | `64:64240:1460:7:2-4-8-1-3`, `64:65535:...`, `64:29200:...` |
| Windows 10/11 | `128:65535:1460:8:2-1-3-1-1-8-4`, `128:64240:...` |
| macOS 13+ | `64:65535:1460:6:2-1-3-1-1-8-4` |
| iOS 16+ | `64:65535:1460:7:2-1-3-1-1-8-4` |
| Android 12+ | `64:65535:1460:9:2-4-8-1-3`, `64:65535:1460:8:...` |
| FreeBSD/pfSense | `64:65535:1460:6:2-1-3-4-8` |

`classify(sig)` (`:214`) — **exact match only**; a miss → `OsFamily::Unknown`. Fuzzy matching (wildcards on window and so on) is out of scope — operators with richer needs are advised to vendor `huginn-net` or run a full p0f alongside and feed in its verdict.

Extending the database: `OsDatabase::load_str()` (`:184`, `load_file` is also mentioned) — lines of `<signature> <os_family>`, `#` comments and empty lines are ignored, family names are case-insensitive (`mac`→macos, `freebsd`→bsd), unknown families are silently skipped (so as not to pollute the DB with junk).

Convenience functions: `classify_syn(syn, db)` (`:223`) — a wrapper for `db.classify(syn.signature())`. `ua_os_family(ua)` (`:231`) — the bridge into the correlator: it derives the OS declared in the User-Agent (important: `iphone`/`ipad` is checked **before** `mac os`, since iOS UAs historically contain "Mac OS X"). A mismatch between `ua_os_family` and `classify_syn` is exactly the divergence signal being sought.

---

## 5. ClamAV body scan (`src/clamav_scanner.rs`)

WAF body inspection (see [10-waf.md](10-waf.md)) catches SQLi/XSS/cmd injection in `application/x-www-form-urlencoded`/JSON bodies, but does **not** catch malware in `multipart/form-data` file uploads — that is ClamAV's job. The module connects Aegis to a running `clamd` daemon through its **INSTREAM TCP API**.

> Disabled by default and opt-in: if `AEGIS_CLAMAV_ADDR` is not set, it is a no-op. `clamd` runs in the operator's network; Aegis does not bundle the daemon. In addition, the module was fully built in V129 but for a long time had no live caller (it lay dormant); V234 made it cleanly revivable without changing behaviour.

### 5.1. Configuration (env)

`ClamavScanner::from_env()` (`src/clamav_scanner.rs:170`) reads:

| Environment variable | Default | `ClamavConfig` field |
|---|---|---|
| `AEGIS_CLAMAV_ADDR` | unset → no-op | `addr: Option<String>` |
| `AEGIS_CLAMAV_MAX_BODY_BYTES` | `26214400` (25 MiB) | `max_body_bytes` |
| `AEGIS_CLAMAV_TIMEOUT_MS` | `5000` | `timeout` |

```bash
AEGIS_CLAMAV_ADDR=127.0.0.1:3310
AEGIS_CLAMAV_MAX_BODY_BYTES=26214400   # 25MB
AEGIS_CLAMAV_TIMEOUT_MS=5000
```

`scan_content_types` (`ClamavConfig::default()`, `:86`) — which `application/*` types to scan. By default: `multipart/form-data`, `application/octet-stream`, `application/zip`, `application/x-rar-compressed`, `application/x-7z-compressed`, `application/x-tar`, `application/x-bzip2`, `application/pdf`, `application/msword`, `application/vnd.openxmlformats-officedocument`. `application/json` is deliberately excluded — there is nothing there for clamd to find; `text/*`, `image/*` are skipped.

### 5.2. Lifecycle and invocation

One shared instance per process (`ClamavScanner` is cheap to `Clone` and holds only the config — no sockets, no pools). The recommended pattern is an `Arc<ClamavScanner>` at startup, matching the handler's other services (`Arc<WafFilter>`, `Arc<AnomalyDetector>`). Call site (after the WAF has buffered the body):

```rust
if scanner.is_enabled()
    && scanner.should_scan(content_type, body.len())
{
    if let ScanVerdict::Infected { signature } = scanner.scan(&body).await {
        // only Infected blocks — deny/403 here
    }
}
```

- `is_enabled()` (`:198`) — a cheap opt-in gate: `true` only when `addr` is set. The hot path must check it first — when `false` the scanner does nothing and all the body work can be skipped. `enabled()` (`:205`) is a back-compat alias.
- `should_scan(content_type, len)` (`:214`) — a lock-free pre-filter: `false` if the scanner is disabled, the body is empty, the body is > `max_body_bytes`, or the content type is not in the list.

### 5.3. Scan protocol and limits

`scan(body)` (`:256`) → `scan_inner` (`:280`):

- Not configured → `Skipped`; an empty or over-limit body → `Skipped` (the body is skipped; the proxy relies on the WAF's own body cap, **the prefix is not scanned** — the V129 contract).
- INSTREAM: `zINSTREAM\0`, then repeated `<u32 BE length><bytes>` in 64 KiB chunks, terminator `0u32`. The response is read up to the `NUL`.
- The whole exchange is wrapped in `timeout(self.cfg.timeout, ...)`.
- **Response cap (V233):** the response buffer is capped at `RESP_CAP = 4096`; if the `NUL` has not arrived within the cap — a hard error (a compromised/foreign process on the socket cannot flood gigabytes and OOM the worker).

The `parse_response()` parser (`:344`):

| clamd response | Verdict |
|---|---|
| `stream: OK` (exactly this line) | `Clean` |
| `stream: <sig> FOUND` | `Infected { signature }` |
| anything else / empty / size error | `Error` |

> V233 hardening: `FOUND` is checked **first and independently** — a genuine `FOUND` cannot be "downgraded" to Clean with a crafted suffix; `Clean` is an anchored full match of the string `stream: OK`, not `ends_with(" OK")` (otherwise a body whose signature ends in " OK" would pass fail-open).

### 5.4. Failure direction (fail-open by design)

`ScanVerdict` (`:117`) and `is_block()` (`:141`) are the single source of truth: **only `Infected` blocks**. `Clean`, `Skipped` and `Error` are all ALLOW.

| Verdict | Meaning | Blocks? |
|---|---|---|
| `Clean` | The body is clean | No |
| `Infected { signature }` | clamd found a signature | **Yes** |
| `Skipped` | Content type not in the list / empty body / > cap / not configured | No |
| `Error` | clamd unreachable, timeout, or a garbage/over-limit response | No (fail-open) |

A connect failure, a timeout and a malformed response all yield `Error` → ALLOW. This is deliberate: a single clamd dip must not jam all uploads (the operator deploys a redundant clamd). `Error` is counted into the `aegis_clamav_scan_errors` metric ([25-metrics-telemetry.md](25-metrics-telemetry.md)). Anyone who needs **fail-closed** must treat `Error` as a deny themselves at their own call site; the module never does so.

---

## 6. Summary: what is enabled by default

| Capability | Enabled out of the box | How to enable |
|---|---|---|
| Enrichment facade + JA4 corpus source | Yes | Registered automatically in `ArsenalState` |
| JA4/ASN reputation, GeoIP as facade sources | No (their own separate caches/paths) | Not wired into `EnrichmentFacade` by default — see [12-reputation.md](12-reputation.md), [20-geoip.md](20-geoip.md) |
| Threat-intel deny lists | Only if `filters.threat_intel.paths` is set | Point at the feed paths + a cron refresh |
| p0f OS classification | The built-in mini-DB is active | Extend with a file via `OsDatabase::load_str`/`load_file` |
| ClamAV body scan | No (opt-in) | Set `AEGIS_CLAMAV_ADDR` (+ optional cap/timeout) |

See also: [04-configuration.md](04-configuration.md) (the full config schema), 42-текущее-состояние-STATUS.md (the current status of opt-in features), [47-faq-troubleshooting.md](47-faq-troubleshooting.md).
