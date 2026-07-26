# Reputation feeds (JA4, ASN/CIDR, CrowdSec)

**Languages:** **English** · [Русский](../ru/12-reputation.md) · [中文](../zh/12-reputation.md)

AEGIS combines several independent reputation sources — a self-learning JA4 feed, an ASN/CIDR list (Tor + Spamhaus DROP, enabled by default), a curated JA4 corpus, IP deny lists from threat-intel files, and the CrowdSec LAPI. All of them are loaded from local files with hot reload based on mtime; none of them makes direct HTTPS requests from the data plane. This document describes what the code actually does, and where the functionality is only partial.

Code sources: [src/ja4_reputation.rs](../../src/ja4_reputation.rs), [src/asn_reputation.rs](../../src/asn_reputation.rs), [src/ja4_corpus.rs](../../src/ja4_corpus.rs), [src/crowdsec_api.rs](../../src/crowdsec_api.rs), [src/filters/threat_intel.rs](../../src/filters/threat_intel.rs), [install.sh](../../install.sh) (`ensure_reputation_feeds`), wiring — [src/bin/aegis-pingora.rs](../../src/bin/aegis-pingora.rs).

Related documents: [TLS fingerprinting](./11-tls-fingerprinting.md), GeoIP (country and ASN), Enrichment and threat intel, ML and risk engine, Honeypot and tarpit, Defence Arsenal.

---

## 1. Overview: five reputation sources

| Source | Module | Key | Signal type | Default | Where it is applied |
|---|---|---|---|---|---|
| JA4 reputation feed | [`ja4_reputation.rs`](../../src/ja4_reputation.rs) (V138/V244) | JA4 string / cipher hash | ML feature `ja4_reputation` [0..1] | **ON** (self-learning) | `extract_ml_features_v2` |
| JA4 corpus (seed) | [`ja4_corpus.rs`](../../src/ja4_corpus.rs) (V176) | JA4 string / cipher hash | Allow / Deny / Unknown | built into the binary | Arsenal, raises `ja4_reputation` |
| ASN/CIDR reputation | [`asn_reputation.rs`](../../src/asn_reputation.rs) (V142/V144) | AS number / CIDR | ML feature `asn_reputation` [0..1] | **ON** | `extract_ml_features_v2` |
| Threat-intel deny | [`filters/threat_intel.rs`](../../src/filters/threat_intel.rs) (V113/V237) | IP / CIDR | hard Deny (HTTP 403) | OFF (no paths by default) | filter chain |
| CrowdSec LAPI | [`crowdsec_api.rs`](../../src/crowdsec_api.rs) (V157) | IP / Range / Country | decision export | scaffolding (wire types) | external bouncers |

The key difference lies in the strictness of the verdict:

- **JA4 / ASN reputation** is a *soft* signal: it returns a number in `[0..1]` that goes into the ML scorer as one feature among many. On its own it does not block. See ML and risk engine.
- **Threat intel** is a *hard* filter: a match results in an immediate `FilterAction::Deny { status: 403 }`.
- **JA4 corpus** is bidirectional: `Deny` raises `ja4_reputation` to 1.0, `Allow` can only *hold back* suspicion, but cannot lower it below the unforgeable baseline (see §4).

---

## 2. JA4 reputation feed (`ja4_reputation.rs`)

### 2.1. Purpose and file format

A self-learning index of JA4 hashes known to belong to malicious tooling (sqlmap, hydra, nuclei, recon-ng…) or to botnets. The operator drops a file into the reputation directory, and AEGIS raises the score for every request whose JA4 matches.

The format is plain text, one entry per non-empty, non-comment line (`#` is a comment). Two forms are supported (parser — `parse_into`, [src/ja4_reputation.rs:258](../../src/ja4_reputation.rs)):

```text
# full JA4 string <token> [tag]
t13d1516h2_8daaf6152771_b186095e22b6  sqlmap

# cipher hash only (the middle 12-character block) — community feeds
# often ship exactly this, since it is more stable across browser updates
8daaf6152771    nuclei
```

Token classification rules:

- contains `_` → indexed as a **full JA4** (exact match);
- exactly 12 hex characters → indexed as a **cipher prefix** (match on the middle block);
- otherwise the token is silently ignored (the feed is the operator's responsibility).

The tag is opaque to AEGIS: it ends up in metrics and in the audit log. By default, if the tag is missing, it is `"unknown"`.

### 2.2. Lookup and scoring logic

`lookup()` ([src/ja4_reputation.rs:193](../../src/ja4_reputation.rs)) first tries the full table (the strongest signal), then the cipher prefix (middle block, 12 hex characters). The result is converted into a feature by `reputation_feature()`:

| Match type | Feature value | Comment |
|---|---|---|
| `MatchKind::Full` | **1.0** | exact JA4 match in the CTI feed |
| `MatchKind::CipherPrefix` | **0.6** | weaker — a browser may share its cipher list with a tool |
| no match | **0.0** | |

The index structure is two `HashMap`s behind an `RwLock` (full + cipher). Hashing uses AHash (DoS-resistant): per audit V230 the keys are derived directly from the client TLS handshake, therefore FxHash is forbidden here (an attacker can craft handshakes to probe for collisions).

### 2.3. Self-learning (`observe_bad`, V244)

The main peculiarity: **no public bulk list of malicious JA4 exists**, and the JA4s of tools collide with generic Go/Python clients — a static default would be FP-prone. Hence the out-of-the-box source is self-learning from confirmed-bad traffic.

`observe_bad(ja4, tag)` ([src/ja4_reputation.rs:110](../../src/ja4_reputation.rs)) is called only on already-bad outcomes:

- **honeypot trap** and **WAF signature hit** — [src/proxy/pingora_http.rs:3106](../../src/proxy/pingora_http.rs) (tag = the name of the filter that fired);
- **tarpit** — [src/proxy/pingora_http.rs:3279](../../src/proxy/pingora_http.rs) (tag = `"tarpit"`).

Recorded JA4s are atomically (`O_APPEND`) appended to the sink file `ja4-observed.txt`, which is itself part of `paths`, so sibling workers and restarts pick them up through mtime reload.

Protective limits:

- **Cap.** `OBSERVED_CAP = 50_000` full JA4 entries — bounds memory and protects against a JA4-rotating attacker flooding the learned set.
- **Dedup.** Observing a known JA4 again → return without I/O (cheap under the read lock, double-checked under the write lock).
- **Degenerate JA4 guard (V246).** `is_degenerate_ja4()` ([src/ja4_reputation.rs:233](../../src/ja4_reputation.rs)) refuses to learn from an "empty ClientHello". If the capture of ClientHello fields returned nothing, the cipher/extension hash = truncated `SHA256("")` = `"e3b0c44298fc"` — **identical for every client**. Learning such a JA4 from a single bad request would flag all traffic. Any JA4 whose cipher or extension block equals the empty-input hash is skipped.

  🟡 This is a **safety net**, not a real fix. The correct solution is to capture the real ClientHello fields; the guard merely prevents a catastrophe. This is stated directly in a code comment ([src/ja4_reputation.rs:114-119](../../src/ja4_reputation.rs)).

- **No-op conditions.** `observe_bad` does nothing if auto-learn is disabled (no `observed_path`), if the JA4 is empty or has no `_`, if the JA4 is degenerate, or if the cap has been reached.

`learned_count()` is a counter of entries auto-learned during the worker's lifetime; it is shown in the panel so the operator can see that the feed is "alive".

### 2.4. Enabling and env knobs

JA4 reputation is **enabled by default** in `aegis-pingora` ([src/bin/aegis-pingora.rs:1229](../../src/bin/aegis-pingora.rs)). The set of paths is:

1. operator feeds from `AEGIS_JA4_REPUTATION` (colon-separated paths);
2. `ja4-observed.txt` — the auto-learning sink (via `.with_observed_path()`);
3. `ja4-crowdsec.txt` — a feed populated by the refresh job if the CrowdSec LAPI is configured (see §6.3); the path is watched even when the file is absent.

| Env | Value | Effect |
|---|---|---|
| `AEGIS_JA4_REPUTATION` | `0` / `false` / `off` | disable JA4 reputation completely |
| `AEGIS_JA4_REPUTATION` | `path1:path2:…` | add operator feeds (colon is the separator) |
| `AEGIS_REPUTATION_DIR` | path | reputation directory (default `/var/lib/aegis/reputation`) |

> ⚠️ Applicability: all the JA4/ASN reputation described here is implemented in the **`aegis-pingora`** binary. The legacy hyper path (`aegis`) does not perform this wiring. See [architecture](./02-architecture.md).

---

## 3. JA4 corpus — a curated seed (`ja4_corpus.rs`)

Unlike V138 (the operator's CTI list), the V176 corpus is **compiled into the binary** and is consulted as a "globally true" baseline even before the operator feed.

### 3.1. Built-in seed

`SEED` ([src/ja4_corpus.rs:60](../../src/ja4_corpus.rs)) contains ~30 entries of the form `(ja4_or_cipher, verdict, label)`. There are three verdicts:

- **Allow** — known stable browsers (Chrome/Firefox/Safari/Edge — Windows/macOS/Linux/iOS/Android). Semantics: "this fingerprint really is emitted by millions of users".
- **Deny** — known tooling: `curl`, `python-requests`, `python-urllib3`, `go-default-http-client`, `java-okhttp`, `java-apache-httpclient`, `sqlmap`, `nikto`, `nuclei`, `hydra`, `wpscan`.
- **Unknown** — not in the corpus → hand the decision over to V137 fp_correlation / V138 reputation / ML.

Cipher-prefix entries (broader/weaker) are present too: `8daaf6152771` → chrome-family-cipher (Allow), `56d4dd6ee7df` → sqlmap-family-cipher (Deny), and so on.

> 🟡 An honest caveat taken from the code itself: the hashes come from public FoxIO JA4+ snapshots and from in-house honeypot mining; "conservative — only entries observed at volume across several deployments". The seed is small and fixed.

### 3.2. Extension by the operator

`extend_from_path()` ([src/ja4_corpus.rs:141](../../src/ja4_corpus.rs)) appends entries from a file. The format is `<ja4_or_cipher> <verdict> <label>`, where verdict ∈ `allow` / `deny` (**default `deny`** if omitted or not recognised). A missing file is silently skipped (compose-friendly).

### 3.3. Effect on scoring

The logic lives in [src/proxy/pingora_http.rs:1568-1599](../../src/proxy/pingora_http.rs):

- **Deny** → `ja4_reputation = ja4_reputation.max(1.0)` (raises the feature to its maximum).
- **Allow** → `(ja4_reputation - 0.25).max(baseline).max(0.0)`. This is the **H9b clamp**: JA4 is chosen by the client (an attacker fully controls their own ClientHello), therefore an Allow verdict **cannot lower suspicion below the unforgeable baseline** set by the operator's V138 feed. A spoofed "I am Chrome" JA4 is at worst neutral, never negative.
- **Unknown** → no change.

**JA4 churn** (V177, [ja4_churn.rs](../../src/ja4_churn.rs)) is folded in at the same place: when churn > 0.6, `ja4_reputation = max(churn)`. For details see [TLS fingerprinting](./11-tls-fingerprinting.md).

In parallel (V199, [src/proxy/pingora_http.rs:2687](../../src/proxy/pingora_http.rs)) a corpus `Deny` may appear in the Arsenal as a separate actuator with a `SecurityEvent` log entry (`ja4_corpus_deny`). The counters `ja4_corpus_lookups`/`_deny_hits`/`_allow_hits` are exposed. See Arsenal.

---

## 4. ASN / CIDR reputation (`asn_reputation.rs`)

### 4.1. Purpose and the two forms of entries

An operator/refresh-supplied list of bad ASNs (hosting, proxy farms, abusive VPNs, Tor clusters) plus bad CIDRs. `lookup()` returns a score in `[0..1]`, which is written into the ML slot `asn_reputation` (V139/V140).

Why both forms (comment at [src/asn_reputation.rs:8](../../src/asn_reputation.rs)):

- **ASN DB** (MaxMind GeoIP2-ASN or equivalent) is best for hosting/transit: a bad AS catches *all* current and future blocks of that AS.
- **CIDR list** is simpler to maintain by hand and needs no database; it is the right form for Spamhaus DROP, FireHOL aggregates, and your own threat-intel exports.

> The AEGIS core **does not ship a default list** — the right list is deployment-specific (a SaaS hates DigitalOcean traffic, a gaming shop is obliged to allow it). The default `asn-cidr.txt` is populated by the install/refresh job (Tor + Spamhaus), see §6.

### 4.2. File format

```text
# ASN entries — AS<number>  <score>  [tag]
AS14061  0.8  digitalocean
AS16509  0.7  aws-ec2

# CIDR entries — <cidr>  <score>  [tag]
185.220.100.0/22  1.0  tor-exit
1.2.3.4/32        0.9  burned-host
```

The parser ([src/asn_reputation.rs:222](../../src/asn_reputation.rs)): the first field is the token, the second is the **mandatory** `f32` score (a line without a score is skipped), the third is the tag (`"unknown"` by default). The score is `clamp(0.0, 1.0)`. A prefix of `AS`/`as` (case-insensitive) → an ASN entry; otherwise `parse_cidr()` (v4 prefix ≤ 32, v6 prefix ≤ 128). Unparsable tokens are silently skipped.

### 4.3. Lookup logic

`lookup(ip)` ([src/asn_reputation.rs:166](../../src/asn_reputation.rs)):

1. **ASN path** — if `AsnLookup::asn(ip)` returned a number and it is present in `asn_index`.
2. **CIDR path** — a linear scan of the per-family Vec (v4/v6), selecting matches by mask.
3. **If several match, the highest score is returned** (an operator stacking entries gets the strongest signal).

Performance: ASN is O(1), CIDR is O(n) in the worst case, but AEGIS-style operators keep O(10²) CIDRs, which is fine at line rate.

### 4.4. ASN GeoIP database

ASN-keyed entries (`AS<num>`) **only match when an ASN database is loaded**. The `AsnLookup` trait ([src/asn_reputation.rs:61](../../src/asn_reputation.rs)) abstracts IP→ASN; the default `NoopAsnLookup` always returns `None` → deployments without an ASN DB work, but only match CIDR entries.

In `aegis-pingora` ([src/bin/aegis-pingora.rs:1277](../../src/bin/aegis-pingora.rs)) the already-loaded GeoIP handle is wrapped into `GeoIpAsnLookup`, so AS-keyed entries do resolve. The ASN DB (`dbip-asn-lite.mmdb`) is mounted via `[geoip].asn_db_path` and is populated by the refresh job (db-ip ASN-lite, monthly). For details see GeoIP (country and ASN).

### 4.5. Enabling and env knobs

ASN/CIDR reputation is **enabled by default** ([src/bin/aegis-pingora.rs:1260](../../src/bin/aegis-pingora.rs)). The set of paths is: operator paths from `AEGIS_ASN_REPUTATION` plus the default `asn-cidr.txt` (watched even when absent).

| Env | Value | Effect |
|---|---|---|
| `AEGIS_ASN_REPUTATION` | `0` / `false` / `off` | disable ASN/CIDR reputation |
| `AEGIS_ASN_REPUTATION` | `path1:path2:…` | add operator feeds |

---

## 5. Threat-intel deny (`filters/threat_intel.rs`)

### 5.1. Difference from the IP ACL, and purpose

This is a **hard deny filter**, separate from the operator's `IpAclFilter` (which lives in the config and is only reloaded on a config reload). Threat intel keeps an `Arc<RwLock<HashSet>>` plus CIDR Vecs, updated from local files by a background task — the operator cron-curls the feed into a path, and AEGIS re-reads it by mtime.

Why local files rather than direct HTTPS fetches (comment at [src/filters/threat_intel.rs:12](../../src/filters/threat_intel.rs)): to avoid pulling a second HTTPS client plus cert-pinning surface into the proxy; operators already have their own way of authenticating to paid feeds (curl+token, GitHub Actions, Vault); mtime gives idempotency for free.

### 5.2. File format

One entry per line. Everything after `#` is a comment (including trailing comments). A line containing `/` → CIDR (v4/v6), otherwise a bare IP → exact-match HashSet. The parser is `parse_feed_v113` ([src/filters/threat_intel.rs:202](../../src/filters/threat_intel.rs)).

```text
# AbuseIPDB / Spamhaus DROP / FireHOL export
203.0.113.5
192.168.0.0/24
2001:db8::/32        # IPv6 is supported
```

> ⚠️ A documentation mismatch in the code: the `ThreatIntelConfig` docstring ([src/config.rs:648](../../src/config.rs)) still says "CIDRs not supported yet", but this is outdated — since V113 CIDRs are fully supported (see the tests `cidr_v4_range_blocks_any_member` / `cidr_v6_range_blocks_any_member`).

### 5.3. CIDR coalescing (V125)

On every reload, adjacent and overlapping CIDRs are coalesced (`coalesce_v4` / `coalesce_v6`, [src/filters/threat_intel.rs:261](../../src/filters/threat_intel.rs)): three passes — (net,mask)→ranges, sort+merge of intervals, decomposition into a minimal set of CIDRs. Coverage is preserved losslessly; on real public feeds (Spamhaus DROP, FireHOL L1+2) this typically removes 30–50% of entries → a faster linear scan. `coalesce_preserves_coverage_end_to_end` verifies that every IP that matched before coalescing still matches afterwards.

### 5.4. Hot path and fast-path sentinel (V237)

`check()` ([src/filters/threat_intel.rs:405](../../src/filters/threat_intel.rs)):

1. **Empty-set fast path.** `has_entries: AtomicUsize`, written on reload with `Release`, read on every request with `Acquire`. When it is zero — an instant `Allow` without taking the RwLock even once (for plain forwarding / no feed).
2. Otherwise: exact-match HashSet (O(1)) → on a miss, a CIDR scan.
3. A match → `FilterAction::Deny { status: 403 }` (cold-path constructor `ip_deny_cold`, V230, so the hot Allow path stays compact for the icache).

### 5.5. Configuration (TOML/DSL)

`ThreatIntelConfig` ([src/config.rs:648](../../src/config.rs)):

| Field | Type | Default | Description |
|---|---|---|---|
| `paths` | `Vec<String>` | `[]` (filter inactive) | paths to deny feeds |
| `refresh_secs` | `u64` | `300` | how often to re-read the files |

`config_enabled()` is always `true` — ThreatIntel has no on/off flag: an empty feed is harmless (`Allow`). The operator can force it off per domain via the web UI (V231). On scale: for feeds of 10⁵+ entries the code recommends XDP CIDR maps (kernel lookup) — see [XDP/eBPF](./13-xdp-ebpf.md).

---

## 6. Feed installation and daily refresh (`install.sh`)

`ensure_reputation_feeds` ([install.sh:788](../../install.sh)) creates `/var/lib/aegis/reputation`, installs the `aegis-refresh-feeds` script and a systemd timer.

### 6.1. What the refresh job populates

The script `/usr/local/bin/aegis-refresh-feeds` (best effort; the daemon hot-reloads whatever changed by mtime, without a restart):

| Target | Source | Entry |
|---|---|---|
| **Tor exit nodes** | `https://check.torproject.org/torbulkexitlist` | `<ip>/32 0.5 tor-exit` → `asn-cidr.txt` |
| **Spamhaus DROP** | `https://www.spamhaus.org/drop/drop.txt` | `<cidr> 0.8 spamhaus-drop` → `asn-cidr.txt` |
| **db-ip ASN-lite** | `download.db-ip.com/.../dbip-asn-lite-<YYYY-MM>.mmdb.gz` | → `geoip/dbip-asn-lite.mmdb` |
| **CrowdSec JA4** (opt-in) | `${CROWDSEC_LAPI_URL}/v1/decisions?scope=ja4` | `<value>\tcrowdsec` → `ja4-crowdsec.txt` |

`asn-cidr.txt` is installed only if it contains at least one non-comment line (atomically, via `install -m 0644`). Tor gets a score of **0.5** (signal), Spamhaus DROP **0.8** (abuse).

### 6.2. Daily timer

`aegis-refresh-feeds.timer` ([install.sh:880+](../../install.sh)):

```ini
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
```

`enable --now` → the seed runs immediately at install time (best effort; the module stays inert if the network is down). The service is `Type=oneshot`, `After=network-online.target`.

### 6.3. CrowdSec consume via refresh (opt-in)

Pulling JA4 decisions from the CrowdSec LAPI is opt-in via `/etc/aegis/feeds.env`:

```bash
# /etc/aegis/feeds.env
CROWDSEC_LAPI_URL=http://127.0.0.1:8080
CROWDSEC_LAPI_KEY=<bouncer-api-key>
```

When these variables are set, the refresh job performs `GET .../v1/decisions?scope=ja4` with `X-Api-Key`, and a Python one-liner selects the `value` fields that contain `_` (i.e. JA4 strings) and writes them to `ja4-crowdsec.txt` with the tag `crowdsec`. That file is already in the JA4 reputation `paths` (§2.4) and is picked up by the mtime reload.

> 🟡 This is exactly the "consume direction" that [crowdsec_api.rs](../../src/crowdsec_api.rs) calls a "small follow-up" — implemented outside Rust, in the refresh script, and only for the JA4 scope.

---

## 7. CrowdSec LAPI (`crowdsec_api.rs`)

### 7.1. What is implemented (V157)

The module implements the **expose direction**: AEGIS publishes its own decisions in the CrowdSec Local API format, so that any existing bouncer (nginx, HAProxy, a Cloudflare worker, firewall-iptables, Caddy, kubernetes-ingress…) becomes an enforcer of AEGIS decisions.

Wire types ([src/crowdsec_api.rs:45](../../src/crowdsec_api.rs)):

- `Decision { id, kind ("type"), scope, value, duration, scenario, origin }` — the subset that bouncers actually consume.
- `DecisionStream { new, deleted }` — the shape of `GET /v1/decisions/stream`.
- `AegisDecision` — the internal form that the adapter converts from.

Verdict mapping (`AegisDecisionKind::as_crowdsec_str`): `Ban → "ban"`, `Captcha → "captcha"`, `Throttle → "throttle"`. `scope` is always `"Ip"`, `origin` is always `"aegis"`, `scenario` = `"aegis/<reason>"`. `format_duration()` emits a CrowdSec string (`1d4h`, `4h30m`, `5m30s`).

Bouncer authentication — `validate_bouncer_key()` ([src/crowdsec_api.rs:169](../../src/crowdsec_api.rs)): a constant-time comparison (`ct_eq`) of the `X-Api-Key` key against the operator-supplied allow-set of `(key, label)`.

### 7.2. What is NOT implemented — an honest caveat

> 🟠 **`crowdsec_api.rs` is wire types + an adapter, NOT a mounted HTTP route.** The docstring says so directly: "Operator wires the actual HTTP route handler". The module converts internal denial state into the decision shape and validates keys, but:
> - `build_stream()` leaves `deleted` empty — "caller fills from its tracked-removed set"; tracking removed decisions and monotonic ids is on the caller's side.
> - There is no ready-made builder of `AegisDecision` from runtime state — the comment says the operator's adapter code constructs them from DynamicTrust/ResponseCache/RiskEngine/ML.
> - The consume direction (AEGIS reading someone else's CrowdSec) is only partially implemented and outside Rust — in the refresh script, for the JA4 scope (§6.3).

In other words: the CrowdSec integration in the code is a **solid piece of scaffolding plus full test coverage of serde/duration/auth**, but not an end-to-end mounted service out of the box.

---

## 8. Hot reloading of feeds

All three file-based feeds (JA4, ASN/CIDR, threat intel) are reloaded by the `PingoraBackground` background task ([src/proxy/pingora_background.rs](../../src/proxy/pingora_background.rs)) — a coarse tick of **30 s by default**. On every tick the mtime of the configured paths is checked (`any_file_changed`, [src/ja4_reputation.rs:286](../../src/ja4_reputation.rs)) and, if changed, `reload()` is called.

A critical safety guarantee (identical in JA4/ASN/threat intel): **a file that has disappeared or become unreadable does NOT zero out the index**. `reload()` builds a new index and swaps it in only if `had_any == true` (at least one file was read). Otherwise a reload race, in which the feed vanished for a second, would open the gate to bots. The tests `missing_file_preserves_prior_index` / `reload_from_*_file_works` pin this down.

---

## 9. Environment variable summary

| Env | Default | Module | Purpose |
|---|---|---|---|
| `AEGIS_REPUTATION_DIR` | `/var/lib/aegis/reputation` | all | directory of reputation files |
| `AEGIS_JA4_REPUTATION` | (unset → **ON**) | ja4_reputation | `0/false/off` disables; paths separated by `:` |
| `AEGIS_ASN_REPUTATION` | (unset → **ON**) | asn_reputation | `0/false/off` disables; paths separated by `:` |
| `CROWDSEC_LAPI_URL` | (unset) | refresh job | `/etc/aegis/feeds.env`, opt-in JA4 consume |
| `CROWDSEC_LAPI_KEY` | (unset) | refresh job | API key for the LAPI |

Config section:

| Field | Default | Module |
|---|---|---|
| `threat_intel.paths` | `[]` | threat_intel |
| `threat_intel.refresh_secs` | `300` | threat_intel |
| `[geoip].asn_db_path` | (see GeoIP) | asn_reputation (ASN-keyed) |

---

## 10. Honesty caveats

1. **Reputation ≠ complete protection.** JA4/ASN reputation are soft ML features in `[0..1]`, not blocks; the verdict is taken by the risk engine (ML and risk engine). Threat intel is a hard 403, but it requires the operator to populate the feed themselves. Under a volumetric L3/L4 flood even an instant deny still requires an inbound connection — upstream protection is needed (BGP/CDN), see BGP RTBH and SECURITY-AUDIT.

2. **JA4 is controlled by the client.** An attacker fully owns their own ClientHello. Therefore a corpus `Allow` cannot lower suspicion below the unforgeable baseline (H9b clamp, §3.3), and self-learning guards against degenerate JA4 (§2.3). This is a known limitation of fingerprint signals.

3. **The degenerate-JA4 guard is a safety net, not a fix.** `is_degenerate_ja4` catches the "empty ClientHello", but the real solution (capturing the real fields) has not been done yet — as stated in the code.

4. **CrowdSec is scaffolding, not a mounted service.** Wire types, an adapter, auth and tests are implemented; the HTTP route, `deleted` tracking, and assembling decisions from runtime state are on the operator (§7.2).

5. **The core ships no default reputation lists** (apart from the built-in ~30-entry JA4 corpus). `asn-cidr.txt` is populated by the install/refresh job (Tor 0.5 + Spamhaus 0.8); without network or the job the ASN/CIDR module is active but empty and inert. Threat intel is empty until the operator sets `paths`.

6. **All reputation works in the `aegis-pingora` binary**, not in the legacy hyper one. The performance numbers (sub-µs CIDR scan, O(1) JA4 lookup) are in-process characteristics; a real deployment adds Pingora's I/O overhead (see Benchmarking).
