# Changelog

All notable changes to Aegis are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

Aegis was developed privately through an internal `V<n>` revision series before
its public release. The detailed engineering history of those revisions
(V97 → V245, in Russian) is preserved in
[docs/ru/45-changelog-history.md](docs/ru/45-changelog-history.md).

## [1.0.0] — first public release

The first version published as open source. Feature-complete relative to the
internal V245 series.

### Data plane
- Production data plane on Cloudflare Pingora (`aegis-pingora`), deployed as an
  `SO_REUSEPORT` worker set with one CPU-pinned single-threaded worker per core.
- HTTP/1.1, HTTP/2 with listener-level frame-abuse limits, HTTP/3 (QUIC) with
  `SO_REUSEPORT` on the UDP socket.
- Threat-aware response cache with a pre-filter-chain hit path.
- eBPF/XDP fast path: kernel deny/allow maps, per-IP packet and SYN budgets.

### Protection
- WAF: Aho-Corasick signatures, SIMD prefix/suffix matchers, semantic SQLi
  analysis, multi-pass normalisation with Unicode confusable folding, gzip and
  deflate request-body decompression before inspection (ratio-capped, fail-closed
  on unknown or stacked encodings), duplicate `Transfer-Encoding` rejection.
- 569 SigmaHQ community rules converted through `aegis-sigma-import`, from the
  two logsource categories that describe HTTP traffic: `webserver` and `proxy`.
  Endpoint telemetry (process_creation, file_event, registry_set, …) is recorded
  in `rules/sigma/skipped.txt` with a reason instead of being emitted as rules
  that could never match an HTTP request.
- Full JA4 family (JA4/S/T/L/X/H) plus JA3, GREASE-anomaly detection, JA4 churn
  scoring, corpus-backed allow/deny baseline, operator-configurable JA3/JA4 deny
  lists enforced on the production path.
- Challenge ladder: cookie → JS → SHA-256 PoW → Argon2id memory-hard PoW →
  CAPTCHA, with per-route difficulty, trust tiers, adaptive attack-mode floor and
  decoy-CAPTCHA deception. Off by default, opt-in per site.
- Privacy Pass verification over Ed25519 (RFC 8032).
- Rate limiting with per-IP and per-URI buckets, IPv6 aggregated to /64,
  bounded state with background cleanup.
- Deception arsenal: honeypot packs, YAML state-machine honeypots, LLM honeypot,
  Markov tarpit, decoy CDN headers, log-normal latency jitter.
- Intelligence: IP/ASN reputation, threat-intel feeds, CrowdSec API, GeoIP
  (bundled DB-IP Country Lite), enrichment fan-out, ML risk engine (LR + GBM).
- Actuator registry with revert TTLs: XDP deny, nftables drop, BGP RTBH/FlowSpec
  announce, challenge-floor raise.

### Operations
- React admin panel (35+ pages, English and Russian, light and dark) embedded
  into the binary.
- REST admin API with role-based tokens (`read` / `operator` / `admin`), audit
  logging, and fail-closed handling of unknown `/admin/api/*` routes.
- Built-in benchmark suite: hardware capacity projection, flood harness, and a
  multi-proxy comparison against nginx, nginx+ModSecurity+CRS, HAProxy, Caddy and
  Envoy, including a security-coverage matrix.
- Worker topology dashboard with live per-worker PID/RSS/CPU/uptime.
- Prometheus metrics, request log, per-domain policy, live config reload.

### Security hardening
- Remote self-update was **removed**. The previous implementation accepted an
  attacker-controlled download URL without signature verification, which was a
  persistent remote code execution path. Updates are now an explicit operator
  action through `install.sh`.
- Constant-time HMAC verification for trust tokens, session tokens and Privacy
  Pass MACs, eliminating timing-oracle and length-extension forgery.
- Admin SSRF protection: upstream validation blocks loopback, link-local, RFC1918
  and cloud metadata addresses. Open-redirect fix in return-URL handling.
- Response cache never stores credentialed responses.
- CAPTCHA verification calls the real provider and fails closed without a secret.
- Fresh installs generate a random admin password; no default credentials.
- QUIC 0-RTT early data disabled.
- `cookie_secure` defaults to true.

### Fixed in this release
- Worker startup failure (`status=203/EXEC`) on installations without XDP: the
  systemd unit's `CapabilityBoundingSet` did not cover the file capabilities set
  on the binary, so the kernel refused `execve()` and every worker crash-looped.
- Generated `aegis.conf` contained a mangled comment because backticks inside an
  unquoted heredoc were evaluated as a command substitution during install.

- Client-supplied `X-Forwarded-For` / `X-Real-IP` / `Forwarded` are replaced with
  the proxy's resolved client address before the request reaches the origin, on
  both data planes. Previously only the legacy hyper plane did this, so an origin
  trusting those headers could be fed an attacker-chosen IP.

### Known limitations
Documented honestly in the [security model](docs/en/23-security-model.md) —
bearer-style trust tokens, IP-keyed earned trust, observe-only risk engine,
partial HTTP/2 frame budgets, GraphQL guards not wired into the production plane,
a `challenge` Sigma rule masking a `block` rule, and the request-body inspection
size limit.
