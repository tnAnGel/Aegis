# Glossary

**Languages:** **English** · [Русский](../ru/46-glossary.md) · [中文](../zh/46-glossary.md)

An alphabetical reference of AEGIS terms, protocols and subsystems. Every definition is tied to real code modules (`src/lib.rs`) and honestly marks what is on by default and what is opt-in. Subsystem abbreviations are given in the form in which they appear in the code (module names, directives, environment variables, routes).

---

## How to use

- Terms are sorted alphabetically (Latin script first).
- The "Where in the code" column gives the module from `src/lib.rs` (`pub mod …`) or another file in the repository.
- The **opt-in** label means the feature is off by default and requires explicit enabling (an environment variable, config, `.with_arsenal()` and so on).
- The **default-on** label means the subsystem is active without additional configuration.
- Details on each topic are in the neighbouring docs; links are given as relative paths.

---

## A

### ALPN (Application-Layer Protocol Negotiation)
A TLS extension by which the client announces a list of application protocols (`h2`, `http/1.1`, `h3`) in the `ClientHello`. AEGIS reads ALPN when capturing the ClientHello and uses it as one of the inputs to fingerprinting and protocol negotiation. Details: [11-tls-fingerprinting.md](11-tls-fingerprinting.md), [07-protocols.md](07-protocols.md).

### Argon2id PoW
A memory-hard alternative to SHA-256 Proof-of-Work. By design 100–1000× more expensive on GPU farms, because the lower bound on RAM per attempt (64 MB by default) limits parallelism. Module `argon2_pow` (V200). See [15-challenge-ladder.md](15-challenge-ladder.md).

### ASN (Autonomous System Number)
The autonomous system number — the identifier of a network operator in BGP. AEGIS uses ASN in two ways: (1) GeoIP enrichment from the db-ip database (country + ASN), module `geoip`; (2) reputation by ASN, module `asn_reputation` (V142) — a feed of "bad" ASNs/CIDRs with the `AsnLookup` lookup trait, feeding the ML feature `asn_reputation`. See [20-geoip.md](20-geoip.md), [12-reputation.md](12-reputation.md).

### Adversarial (adversarial training)
A loop that generates semantically equivalent mutations of SQLi payloads and runs them through the WAF/scorer; bypasses are returned to `MlTrainer` as hard-negative samples for the next retraining. Module `ml_adversarial` (V146, WAF-A-MoLE style). See [18-ml-risk-engine.md](18-ml-risk-engine.md).

### Aho-Corasick
An algorithm for simultaneous multi-pattern substring search. The basis of the AEGIS WAF signature engine: a single pass over the normalised request matches the whole signature corpus. See [10-waf.md](10-waf.md).

---

## B

### BGP RTBH (Remotely-Triggered Black Hole)
Remotely-Triggered Black Hole — suppressing an attack at the network layer by announcing a route upstream so that traffic to the victim is dropped before it ever reaches the proxy. AEGIS pushes L7 blocking decisions upwards as /32 BGP announcements (by default through an ExaBGP pipe; the trait abstraction allows goBGP/FRR) with a TTL and auto-withdrawal. Module `bgp_rtbh` (V187, FlowSpec/RTBH dispatcher), **opt-in**. See [19-bgp-rtbh.md](19-bgp-rtbh.md).

---

## C

### CIDR (Classless Inter-Domain Routing)
Address-range notation of the form `203.0.113.0/24`. AEGIS applies CIDR in subnet rate limiting and in reputation (`asn_reputation` can work by CIDR without an ASN database). The default Tor/Spamhaus lists ship as **default-on** reputation. See [14-rate-limiting.md](14-rate-limiting.md), [12-reputation.md](12-reputation.md).

### Challenge ladder
An escalating sequence of client checks: cookie → reload → PoW → CAPTCHA → WebAuthn. Tied to chained trust (`chained_trust`, V202: cookie 5 min → captcha 24 h → WebAuthn 7 days), adaptivity (`adaptive_ladder`, V204: bumping PoW bits in anomaly mode, randomising the starting level per IP) and a deception layer (`challenge_deception`, V203: decoy CAPTCHA, honeypot form fields). See [15-challenge-ladder.md](15-challenge-ladder.md).

### CrowdSec LAPI (Local API)
The CrowdSec local API — the wire format for blocking decisions understood by CrowdSec "bouncers" (nginx, HAProxy, Cloudflare worker, iptables, Caddy, k8s ingress). AEGIS emits decisions in this format (`crowdsec_api`, V157) so that existing bouncers enforce AEGIS verdicts without reworking enforcement. CrowdSec is also used as a reputation source (**opt-in**). See [12-reputation.md](12-reputation.md), [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Compound rules
WAF rules that fire on a combination of conditions rather than on a single signature. Part of the WAF corpus alongside Aho-Corasick signatures, the Sigma corpus and webshell detections. See [10-waf.md](10-waf.md).

### CAPTCHA providers
Pluggable external CAPTCHA providers: hCaptcha, Cloudflare Turnstile, Google reCAPTCHA. The `CaptchaProvider` trait abstracts the siteverify call, `HttpPoster` the transport. Module `captcha_providers` (V132), **opt-in**. See [15-challenge-ladder.md](15-challenge-ladder.md).

---

## D

### Defence Arsenal
An umbrella subsystem uniting the V176–V190 modules (`arsenal`, V192) under `ArsenalState` with per-component activity counters. It is attached to `AegisPingoraProxy` through `.with_arsenal()` and is **absent by default** — the production binary enables the arsenal explicitly. See [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Decoy headers
Imitating the response shape of Cloudflare / Akamai / Fastly / CloudFront on suspicious requests, so that the attacker's evasion tooling picks the wrong playbook. Module `decoy_headers` (V188, an inversion of Scrapling), **opt-in** (part of the arsenal). See [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

---

## E

### eBPF (extended Berkeley Packet Filter)
A technology for executing programs inside the Linux kernel. AEGIS uses it for the XDP program on the fast path of packet dropping. See [13-xdp-ebpf.md](13-xdp-ebpf.md).

### Ed25519
An elliptic-curve digital signature algorithm. Used by AEGIS to verify Privacy Pass tokens. See [16-privacy-pass.md](16-privacy-pass.md).

### EventBridge
An NDJSON streamer of security events (V116 `SecurityEvent`) over a Unix socket for SIEM. Best-effort and loss-tolerant: slow subscribers lose events, but the proxy's hot path is never blocked. Module `event_bridge` (V127). See [25-metrics-telemetry.md](25-metrics-telemetry.md).

### Event store
A persistent log of requests/events. A per-worker SQLite shard (`shard-<slot>.db`, WAL, one writer per process) is written from a background thread through a bounded channel so that `record()` on the hot path does not block; the admin read side does an `ATTACH` of all shards plus `UNION ALL`. It powers request-log search, per-domain analytics and "bots/DDoS over any period". Module `event_store` (V243). See [24-request-log.md](24-request-log.md).

---

## G

### GeoIP
Geo enrichment from the db-ip database: country + ASN. Module `geoip`. See [20-geoip.md](20-geoip.md).

### GREASE (Generate Random Extensions And Sustain Extensibility)
The RFC 8701 mechanism: browsers mix random "junk" values into TLS cipher/extension lists so that servers do not ossify on a fixed set. AEGIS detects GREASE position anomalies: a real Chrome puts GREASE in `cipher[0]`, `ext[0]` and `supported_versions[0]`, while spoofers hardcode a single permutation. Module `grease_anomaly` (V178, utls style), producing an anomaly score in [0,1]. See [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

---

## H

### Honeypot
A trap: decoy resources and paths, access to which automatically marks the client as malicious. In AEGIS: the base `honeypot` (`HoneypotStore`), YAML service descriptors with deterministic multi-step engagement scenarios (`honeypot_yaml`, V184, Beelzebub style), the LLM honeypot (see below), the robots.txt honeypot (`robots_honeypot`, V149 — visits to Disallow paths push Malicious samples into `MlTrainer`). See [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

### LLM honeypot
A honeypot that replies with plausible answers from an LLM, with a cache keyed by a semantic hash of the request shape (method, path template, header names, body shape), so that a single scanner receives coherent responses without an LLM cost per request. Trait `LlmClient`. Module `llm_honeypot` (V183, Galah style), **opt-in**. See [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

### Honeypot self-learn (JA4 self-learn)
Self-learning of JA4 reputation: "bad" JA4 hashes are mined from honeypot/WAF/tarpit decisions and fed into the reputation feed. See `ja4_reputation`, `online_signature_miner`. See [12-reputation.md](12-reputation.md).

---

## J

### JA3
A hash of the `ClientHello` TLS fingerprint (version, cipher suites, extensions, elliptic curves, point formats). Module `ja3`. Capture happens in the `set_client_hello_callback` callback, behind the fingerprinting gate. See [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### JA4
The modern TLS fingerprint of the JA4+ family (FoxIO): a human-readable structure derived from the `ClientHello`. Base module `ja4`. Derivatives:

| Term | What it fingerprints | Module / note |
|---|---|---|
| **JA4** | TLS ClientHello (client) | `ja4` |
| **JA4H** | HTTP request (method, version, headers, cookie) | part of fingerprinting, cross-checked against JA4 |
| **JA4T** | The client's TCP SYN (window, options) | `tcp_info` / adjacent to `p0f` |
| **JA4L** | TLS handshake latency (client leg) | latency measurement |
| **JA4S** | TLS ServerHello (server) | `ja4_server` (V126) |
| **JA4X** | X.509 certificate | `ja4_server` (V126) |
| **JA4TS** | The server's TCP SYN-ACK | `ja4_server` (V126) |
| **JA4LS** | server-leg latency | `ja4_server` (V126) |

Operators use the server-side family (`ja4_server`) to detect compromised upstreams and to monitor certificate-chain stability. See [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### JA4 corpus
A curated JA4 corpus (seeded by FoxIO): `Verdict::Allow` for known browsers, `Verdict::Deny` for known tooling. Consulted before the reputation feed; an operator file extends the corpus. Module `ja4_corpus` (V176). See [12-reputation.md](12-reputation.md).

### JA4 churn
A per-IP JA4 "churn" score over a sliding window. High churn = TLS fingerprint rotation (utls / curl-impersonate). Feeds the ML feature `ja4_churn`. Module `ja4_churn` (V177). See [18-ml-risk-engine.md](18-ml-risk-engine.md).

### JA4 reputation feed
A JA4 reputation feed: the operator puts a list of bad JA4 hashes into a file (community CTI, internal IR, honeypot mining), and the module provides O(1) lookup plus hot reloading. Two kinds of match: full JA4 (strongest) and cipher-prefix only (weaker, broader). Module `ja4_reputation` (V138). See [12-reputation.md](12-reputation.md).

---

## L

### LAPI
See **CrowdSec LAPI**.

### Latency jitter
Shaping of response delays according to a log-normal or bimodal (CDN-like) distribution for tarpit/honeypot/decoy responses, in order to defeat fingerprinting by response time. Module `latency_jitter` (V190, LLMHoney style), **opt-in**. See [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

---

## M

### ML risk engine
The ML-based risk-scoring subsystem. Enforcement modes: **Observe** (observation only), **HighConfidenceEnforce** (enforce only at high confidence), **FullEnforce** (full enforcement). Model versions v1/v2 (logistic/gbm). Related modules: `anomaly`, `fp_correlation` (V137, cross-fingerprint correlation: "Chrome JA4 + curl UA"), `client_consistency` (V145, CreepJS style), `ml_adversarial` (V146), `timing_entropy` (V189), `signature_mine`/`online_signature_miner` (signature mining). See [18-ml-risk-engine.md](18-ml-risk-engine.md).

### ModSecurity
The classic WAF rule engine (context: OWASP CRS was originally written for it). AEGIS does not use ModSecurity directly, but is compatible in spirit with the "phases + rules" approach: a phase-indexed rule plan is implemented in `rule_planner` (V181, Coraza style) — bucketing rule IDs by `Phase` (uri/headers/body/response) with severity-sorted dispatch. See [10-waf.md](10-waf.md).

### mTLS (mutual TLS)
Mutual TLS authentication — the client also presents a certificate. AEGIS fingerprints the client certificate under mTLS. Module `mtls_fp`. See [08-tls-certificates.md](08-tls-certificates.md), [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

---

## N

### Normalisation
A multi-pass request normalisation chain before WAF matching (SafeLine style): URL decode → HTML entities → NFKC full-width → unicode confusables → strip null → lowercase. Run to a fixed point with a bounded number of passes. Module `normalisation` (V179). See [10-waf.md](10-waf.md).

---

## O

### OWASP CRS (Core Rule Set)
The OWASP Core Rule Set — an open set of WAF rules. AEGIS does not import CRS directly; instead it has its own signature corpus plus an import of Sigma rules (`sigma`, V196) and a phase-indexed planner (`rule_planner`). Compatibility is at the level of the "processing phases" concept. See [10-waf.md](10-waf.md).

---

## P

### p0f
Passive OS / TCP-stack fingerprinting from SYN observations (window, MSS, wscale, options, TTL) that AEGIS already captures, with classification into an OS family for a "UA versus stack" cross-check. Module `p0f` (V155). See [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### PoW (Proof-of-Work)
Proof of work — an asymmetric task: the client spends seconds of CPU, the server verifies in microseconds. SHA-256 hashcash is implemented in `pow_captcha` (V131); the memory-hard alternative is `argon2_pow` (V200). The goal is to crush a single attacker proxying many sessions. See [15-challenge-ladder.md](15-challenge-ladder.md).

### Privacy Pass
Anonymous proof-of-trust tokens (a form of RFC 9576) issued by Cloudflare/Apple/Fastly and others; verified browsers pass the challenge ladder silently. The verifier is based on Ed25519. Module `privacy_pass` (V201). See [16-privacy-pass.md](16-privacy-pass.md).

### Param profile
A learnable per-endpoint parameter profile (open-appsec style): rolling statistics (length / charset / entropy) over `(host, endpoint, param)`; an anomaly score after `learn_threshold` observations. Module `param_profile` (V180). See [10-waf.md](10-waf.md).

### Poisoned tarpit
A tarpit with a Markov-chain text generator plus infinite internal HTML links, so that AI scrapers ignoring robots.txt get stuck in a maze and burn CPU recursively crawling fake pages. A deterministic per-deployment seed keeps the corpus hard to fingerprint. Module `poisoned_tarpit` (V147, the Iocaine/Nepenthes/HellPot line). See [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

---

## R

### Rate limiting
Limiting the request rate per IP / per subnet / per URI, with a Redis backend for cross-worker state. See [14-rate-limiting.md](14-rate-limiting.md).

### Risk engine
See **ML risk engine**.

### Reputation
An aggregate trust feed for a source. Its components: JA4 self-learn (honeypot/WAF/tarpit), ASN/CIDR reputation (Tor/Spamhaus **default-on**), CrowdSec LAPI (**opt-in**), threat intel. Implementation: `ja4_reputation`, `ja4_corpus`, `asn_reputation`, `crowdsec_api`, `enrichment`. See [12-reputation.md](12-reputation.md).

### Route difficulty
A per-(host,path) override of challenge difficulty + a preset for AI scrapers (+4 bits for GPTBot and the like) + a preset for auth endpoints (+6 bits, forcing JS PoW on `*/login`). Module `route_difficulty` (V186, Anubis style). See [15-challenge-ladder.md](15-challenge-ladder.md).

---

## S

### Scenarios
A YAML DSL for behavioural rate limiting in the leaky-bucket style of CrowdSec: the grammar `filter / groupby / distinct / capacity / leak_speed / blackhole` covers detection of behavioural anomalies without code. Module `scenarios` (V199), part of the Arsenal + actuators. See [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Sigma
An open detection-rule format. AEGIS imports SigmaHQ YAML rules (`logsource.category: webserver`) into `crate::config::WafRule` values via the `aegis-sigma-import` CLI. The common set of modifiers is supported (contains/startswith/endswith/re), as are list values, single-block conditions + "1 of selection_*" + "selection and not filter". Module `sigma` (V196). See [10-waf.md](10-waf.md).

### SNI (Server Name Indication)
A TLS extension by which the client announces the requested host name in the `ClientHello` — it lets a single IP serve many TLS sites and route by domain. Module `tls_sni`. See [08-tls-certificates.md](08-tls-certificates.md), [26-sites-and-domains.md](26-sites-and-domains.md).

### SO_REUSEPORT
A socket option allowing several processes to listen on one port, with connections distributed by the kernel. The basis of AEGIS multi-process operation: the workers `aegis-pingora@0..N` listen on one port, and cross-worker state goes through disk + mtime polling. See [06-workers.md](06-workers.md).

### Site map
Auto-discovery of endpoints from live traffic with path generalisation (`/users/12345` → `/users/:id`) and a bounded per-host LRU. The surface for the per-domain editing page in the admin panel. Module `site_map` (V119); the per-domain policy is `domain_policy` (V162). See [26-sites-and-domains.md](26-sites-and-domains.md).

### SQL semantic detector
A semantic SQL injection detector (SafeLine style): it tokenises the payload (URL decode + handling of comments/quotes/hex/operators) and recognises the "shape of an injection" (tautology, UNION after a value, stacked DDL, time-blind, comment after a quote). By design it is resistant to the V146/V148 mutators. Module `sql_semantic` (V156). See [10-waf.md](10-waf.md).

---

## T

### Tarpit
A slowing trap: suspicious connections are held/dragged out in order to exhaust the attacker's resources. In AEGIS this is `poisoned_tarpit` (see above), and also a source for signature mining (`online_signature_miner`, V107: tarpit decisions log the payload, and a background miner periodically extracts ranked candidates and serves them via `/admin/api/mined_signatures`). See [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

> A note on slowloris: the AEGIS response is the AEGIS response — reaping slow connections is counted as defence, not as overload (see the verdict logic in `benchmark_flood`). See [28-benchmarking.md](28-benchmarking.md).

### Threat intel / enrichment
A cacheable facade over all intelligence sources (`ja4_reputation`, `asn_reputation`, `threat_intel`, `geoip`, `ja4_corpus`) with per-source TTL and provenance. Module `enrichment` (V198, WISE style). Threat analytics (`threat_analytics`, V121) separates per-IP bot detections from distributed DDoS (botnet). See [22-enrichment.md](22-enrichment.md), [12-reputation.md](12-reputation.md).

### Timing entropy
ML features based on timing entropy: a server-side analyser of mouse jitter / scroll cadence collected by the client-side `client_consistency` (V145). Uniform-timer detectors produce an anomaly score ∈ [0,1]. Module `timing_entropy` (V189). See [18-ml-risk-engine.md](18-ml-risk-engine.md).

---

## W

### WAF (Web Application Firewall)
A web application firewall — filtering HTTP requests at the application layer. The AEGIS WAF: Aho-Corasick signatures + the Sigma corpus + compound rules + webshell detections, on top of multi-pass normalisation (`normalisation`), with a semantic SQLi detector (`sql_semantic`), a phase planner (`rule_planner`) and a parameter profile (`param_profile`). Base modules: `filters`, `dsl`, `config::WafRule`. See [10-waf.md](10-waf.md).

### Webshell signatures
Signatures for detecting web shells (including PHP web shells) as part of the WAF corpus. See [10-waf.md](10-waf.md).

### WebAuthn
The strongest tier of the challenge ladder (a hardware/platform authenticator). In chained trust (`chained_trust`) it grants the longest trust window (7 days). See [15-challenge-ladder.md](15-challenge-ladder.md).

---

## X

### XDP (eXpress Data Path)
A fast path in the Linux kernel (on eBPF) for dropping/redirecting packets before the network stack. AEGIS uses XDP as a kernel fast path; the enforcement fallback chain is **XDP → nftables → iptables → userspace** (`xdp`, `nftables_backend` V128, `iptables_backend` V130; `open_with_fallback()` returns the first successfully initialised backend, and all of them implement the common `XdpHandle`). See [13-xdp-ebpf.md](13-xdp-ebpf.md).

---

## Other terms

### Actuator
An active-response framework: a registry `(kind, target) → Actuator` with rollback TTL and a timer wheel. It replaces scattered "an XDP drop that never expires" patterns. Module `actuator` (V197). See [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### Admin API
About 86 `/admin/api/*` routes; authorisation by `x-admin-token` / session / roles. Modules `admin_auth`, `web_admin`, `server`. See [30-admin-api.md](30-admin-api.md).

### Admin panel
A 37-page React panel on top of the Admin API. Module `admin_ui`. See [29-admin-panel.md](29-admin-panel.md).

### ACME
Automatic certificate issuance (Let's Encrypt): an HTTP-01 challenge responder + cert-on-disk layout + a renewal orchestrator. The protocol driver is injected via the `AcmeClient` trait; the concrete implementation is based on `instant-acme` (`acme` V134, `acme_instant` V234), writing the account key with `O_CREAT|O_EXCL` + chmod 0600. See [08-tls-certificates.md](08-tls-certificates.md).

### Benchmark / capacity projection
CPU integer / SHA-256 / memory-bandwidth micro-benchmarks + an RPS projection (forwarding/TLS/WAF) using a calibrated linear model (`benchmark`, V240); flood tests on loopback (`benchmark_flood`, V241); a comparison vs nginx + a security matrix (`benchmark_compare`, V245).

> Honest caveats: the AEGIS bench lanes are an **in-process engine**, not the full pingora binary. The hardware SHA bench is per-core, and inside a VM without hardware SHA acceleration it is low, in which case the capacity forecast is pessimistic. The security matrix is an honest, strong argument; AEGIS does **not** claim to be faster than real proxies on raw speed. See [28-benchmarking.md](28-benchmarking.md), [27-performance-tuning.md](27-performance-tuning.md).

### ClamAV scanner
A TCP ClamAV scanner for the body (multipart/octet-stream uploads) via the INSTREAM protocol. **Off by default**; enabled with `AEGIS_CLAMAV_ADDR=host:3310`. Module `clamav_scanner` (V129).

### ClientHello callback
The TLS fingerprint capture point — `set_client_hello_callback`, behind the fingerprinting gate. Cipher/extensions/ALPN/SNI/GREASE are read here. See [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

### H2 budget (HTTP/2 control-frame budgets)
A per-connection token bucket for each `FrameKind` (Tempesta style). It closes off the Rapid Reset / Settings flood / Ping flood / CONTINUATION flood class of attacks. Module `h2_budget` (V182). Adjacent to it — H2 fingerprinting (`h2_fp`) and HTTP/3 (`h3_fp`). See [07-protocols.md](07-protocols.md).

### Real-IP resolver
A resolver of the real client IP from `CF-Connecting-IP` / `X-Forwarded-For`, **only** if the TCP peer belongs to the operator's trusted proxy set. Zero behaviour change if `AEGIS_BEHIND_CLOUDFLARE` and `AEGIS_TRUSTED_PROXIES` are not set. Module `real_ip`. See [04-configuration.md](04-configuration.md).

### SecurityEvent
A structured security event (V116) + per-decision Prometheus counters. A single emission point for every Allow/Challenge/Deny/Throttle/Observed decision; labels are cardinality-bounded (`&'static str` reasons). Module `security_event`. See [25-metrics-telemetry.md](25-metrics-telemetry.md).

### Sicherheitstacho
The T-Pot Sicherheitstacho event export scheme: rendering AEGIS security events into Sicherheitstacho-compatible NDJSON for interop with the deception ecosystem. Module `sicherheitstacho` (V185). See [25-metrics-telemetry.md](25-metrics-telemetry.md).

### TUI
A terminal dashboard (Ratatui): pure render functions over a `DashboardSnapshot` value. The `aegis-tui` binary feeds it snapshots from the Admin API. Module `tui` (V133).

### Topology
Runtime introspection of worker topology for the Workers page in the admin panel (facts about the host CPU + a live scan of `aegis-pingora` processes). Module `topology` (V232). See [06-workers.md](06-workers.md).

### Updates
Phase 1: update checking — polling a Gitea/GitHub-compatible Releases API, classifying tags into the stable/beta/nightly channels, showing "update available + changelog" in the admin panel. It does **not apply** updates (operator-driven). Phase 2/3: config snapshot/restore (`update_snapshot`), the `releases/<version>/` layout + an atomic symlink swap (`update_layout`), an apply-status broker (`update_apply`). Modules `updates` (V208), `update_snapshot` (V209), `update_layout` (V210), `update_apply` (V211). See [44-updates-migration.md](44-updates-migration.md).

---

## Binaries and build (for reference)

| Name | Role |
|---|---|
| `aegis` | hyper + CLI |
| `aegis-pingora` | the main data plane (features `pingora`+`xdp`), multi-process as `aegis-pingora@0..N` |
| `aegis-tui` | terminal dashboard |
| `aegis-sigma-import` | import of Sigma rules into `WafRule` |
| `aegis-updater` | applying updates (Phase 3) |

Installation: `install.sh` (`curl | bash`) + a systemd target + a template unit. Build profile: thin LTO / cgu16 / incremental + `AEGIS_BUILD_OPT=max` + `mold`. See [03-installation.md](03-installation.md), [27-performance-tuning.md](27-performance-tuning.md).

---

## See also

- [01-overview.md](01-overview.md) — a general overview of AEGIS
- [02-architecture.md](02-architecture.md) — subsystem architecture
- [23-security-model.md](23-security-model.md) — the security model and matrix
- 42-текущее-состояние-STATUS.md — what is implemented today
- [47-faq-troubleshooting.md](47-faq-troubleshooting.md) — FAQ and troubleshooting
