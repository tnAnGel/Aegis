# Deploying `aegis-pingora` (Phase B preview)

`aegis-pingora` is the Pingora-based proxy binary shipped alongside
the production hyper-based `aegis` since V22. It reads the same DSL
config, runs the same FilterEngine, and produces the same Prometheus
metrics — but the request hot path runs on Cloudflare's
[Pingora](https://github.com/cloudflare/pingora) framework instead of
hyper.

**Status (as of V71 — Release Candidate 2, cutover-validated):**
- ✅ Full data-plane parity with the hyper binary (filter chain,
  threat-aware cache, single-flight, challenge ladder cookie+verify,
  honeypot slow-drip TarpitBody, dynamic-trust, anomaly detector,
  geoip, XDP fast-path with admin CRUD).
- ✅ Full TLS parity (h1/h2/h3 with per-SNI cert routing on all three,
  JA3-MD5 + JA4 + JA4H + JA4T + mTLS leaf-cert fingerprints all
  byte-identical with the hyper handler — locked in by V56 cross-
  binary parity tests).
- ✅ Full admin surface (`/metrics`, `/health`, all `/admin/*`
  endpoints with token auth + audit log).
- ✅ Production-grade ops (SO_REUSEPORT multi-process, graceful
  drain, WAF/cert/trust/cache mtime hot-reload, pingora `--upgrade`
  for zero-downtime binary swap).
- ✅ V64 e2e integration harness verifies 9 invariants in CI.
- ✅ Web admin UI + `/admin/api/*` read-side surface (V66-V69) —
  React SPA served from `/admin/ui` (same `include_dir!` bundle the
  hyper handler uses), session login via
  `POST /admin/api/login` + cookie validation, dashboard fuel via
  `/admin/api/runtime/status`, plus filters / honeypots / sites
  listings. Write-side endpoints (`POST /sites`, `PUT /config`,
  honeypot mutations) are RC3 — operators using aegis-pingora's
  panel today see read-only views and use `/admin/cache/purge`,
  `/admin/waf/reload`, `/admin/xdp/*` via curl for mutations.
- 🔒 `h2_fp` (Akamai HTTP/2 frame fingerprint) — genuinely blocked
  at pingora-core (requires forking to expose h2 frames).

Bench harnesses (V57/V58/V62/V63) need stand execution to publish
the cutover bench numbers; see [Benchmark + validation suite](#benchmark--validation-suite)
below.

---

## Why a second binary?

Pingora ships its own multi-threaded runtime and takes ownership of
the process via `Server::run_forever`. Embedding that inside the
hyper-based `aegis` binary would mean two runtimes fighting for the
same listening socket. A sibling binary is cleaner: operators
explicitly choose which proxy to run at deploy time, and rollback is
"swap the bin path in the systemd unit."

The hyper binary remains the default and the place new features land
first; aegis-pingora catches up version-by-version (see roadmap
weeks 4-10 of Phase B).

---

## Build

```bash
# Requires Rust 1.84+; pingora 0.8 enforces this.
cargo build --release --features pingora --bin aegis-pingora
sudo install -m 0755 target/release/aegis-pingora /usr/local/bin/
```

The `pingora` feature is off by default. Without it, the binary is
not produced; `aegis` (hyper) still builds normally.

---

## Minimal config

`aegis-pingora` reuses the existing DSL parser. Same `aegis.conf`
works — only fields not yet supported are ignored, not rejected.

```nginx
admin {
    listen 127.0.0.1:9090;     # admin /metrics + /health
}

defaults {
    request_timeout 10s;
    graceful_shutdown 10s;
    filters {
        waf on;
        bot_fingerprint on;
        adaptive_spike_detection on;
        challenge_ladder on;   # (folds into 403 stub today, see Parity)
    }
    rate_limit {
        requests_per_second 100;
        burst 200;
    }
}

server {
    listen 0.0.0.0:80 default_server;
    listen 0.0.0.0:443 ssl;
    ssl_certificate     /etc/aegis/certs/site.crt;
    ssl_certificate_key /etc/aegis/certs/site.key;
    proxy_pass http://127.0.0.1:8000;
}
```

Run:

```bash
/usr/local/bin/aegis-pingora --config /etc/aegis/aegis.conf
```

---

## systemd template unit

Install as `/etc/systemd/system/aegis-pingora@.service`:

```ini
[Unit]
Description=Aegis Pingora-based edge proxy (worker %i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=/var/lib/aegis
EnvironmentFile=-/etc/aegis/aegis-pingora.env

# Each worker gets its own state dirs + admin port to avoid
# fighting for the same files. Edit per-instance via drop-ins:
#   /etc/systemd/system/aegis-pingora@2.service.d/ports.conf
Environment=AEGIS_PINGORA_REUSEPORT=1
Environment=AEGIS_ADMIN_LISTEN=127.0.0.1:909%i
Environment=AEGIS_HONEYPOT_STATE=/var/lib/aegis/w%i/honeypots.json
Environment=AEGIS_WEB_STATE=/var/lib/aegis/w%i/web.json

ExecStartPre=/bin/mkdir -p /var/lib/aegis/w%i
ExecStart=/usr/local/bin/aegis-pingora --config /etc/aegis/aegis.conf

Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

# Pin each worker to its own CPU set (see hyper deployment doc for
# the same rationale; pingora ships an internal multi-thread runtime
# per process and benefits from the same isolation).
CPUAffinity=0-1

# Sandboxing — mirror hyper unit; both binaries are equally trustless.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/aegis /var/log/aegis
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
# Allow binding to ports <1024 without root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable + start 4 workers:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-pingora@{1,2,3,4}.service
sudo systemctl status 'aegis-pingora@*'
```

Verify all 4 share the same listening port:

```bash
sudo ss -ltnp | grep :80
# Should show 4 aegis-pingora processes on 0.0.0.0:80
```

---

## Environment variables

| Variable | Effect |
|---|---|
| `AEGIS_LISTEN` | Override `server.listen` from config (plain HTTP). |
| `AEGIS_LISTEN_TLS` | Override `tls.listen` from config (HTTPS). |
| `AEGIS_ADMIN_LISTEN` | Override admin port (default `127.0.0.1:9090`). |
| `AEGIS_PINGORA_REUSEPORT` | `1` to enable `SO_REUSEPORT` (required for N>1 workers on the same port). |
| `AEGIS_HONEYPOT_STATE` | Path to honeypot JSON state file. |
| `AEGIS_WEB_STATE` | Path to web-admin JSON state file. |

Anything unset falls back to the config-file value.

---

## Feature parity vs `aegis` (hyper)

Last refreshed: V65 (after V22–V64 — Phase B complete + production-readiness batch).

| Feature | hyper aegis | aegis-pingora (today) | Roadmap |
|---|:-:|:-:|---|
| Full FilterEngine (WAF, IP ACL, bot, adaptive, plugins, rate, etc.) | ✅ | ✅ V23 | — |
| Per-host upstream routing | ✅ | ✅ V23 | — |
| SO_REUSEPORT multi-process | ✅ V18 | ✅ V24 | — |
| TLS termination (h2 + h1) | ✅ | ✅ V25 | — |
| Per-SNI cert routing (h1/h2) | ✅ | ✅ **V50** (via TlsAccept on openssl feature) | — |
| Per-SNI cert routing (h3) | ✅ | ✅ **V46** (via quinn) | — |
| `/metrics` Prometheus scrape | ✅ | ✅ V27 | — |
| `/health` liveness | ✅ | ✅ V27 | — |
| Upstream status counters (2xx/4xx/5xx) | ✅ | ✅ V26 | — |
| Per-request latency histogram | ✅ | ✅ V26 | — |
| Per-domain success/deny/challenge counters | ✅ | ✅ V26 | — |
| Per-filter block/challenge counters | ✅ | ✅ V23 | — |
| Graceful SIGTERM/SIGINT drain | ✅ V20 | ✅ V23 (pingora built-in) | — |
| WAF rule file hot-reload (mtime poll) | ✅ V19 | ✅ V29 | — |
| Dynamic-trust enrolment/revocation | ✅ V6 | ✅ V30 | — |
| Dynamic-trust stale eviction (background) | ✅ | ✅ V29/V30 | — |
| Honeypot state mtime auto-refresh | ✅ | ✅ V23 (inline in `HoneypotStore::check`) | — |
| Honeypot slow-drip TarpitBody | ✅ | ✅ **V40** | — |
| Threat-aware response cache | ✅ V7 | ✅ V32 | — |
| Single-flight stampede protection | ✅ V17 | ✅ V34 | — |
| Cross-worker cache purge broadcast | ✅ V21 | ✅ V33 | — |
| Cache stats in `/metrics` (stores/evictions/etc.) | ✅ | ✅ V33 | — |
| Threat-score → cache `is_high_threat` flag | ✅ | ✅ **V37** | — |
| ThreatScorer + cleanup (background) | ✅ | ✅ **V37** | — |
| AnomalyDetector + per-request EMA tick | ✅ | ✅ **V38** | — |
| GeoIP country-deny (anomaly-mode gated) | ✅ | ✅ **V39** | — |
| Bypass matcher (IP / path / UA) | ✅ | ✅ **V37** | — |
| `/admin/cache` (stats text) | ✅ | ✅ **V36** | — |
| `/admin/cache/dump` (entry list) | ✅ | ✅ **V36** | — |
| `/admin/cache/purge` (with broadcast) | ✅ | ✅ **V36** | — |
| `/admin/waf/reload` (manual trigger) | ✅ | ✅ **V36** | — |
| `/admin/threats` (top scored IPs) | ✅ | ✅ **V38** | — |
| `/admin/anomaly` (under-attack hosts) | ✅ | ✅ **V38** | — |
| Admin token auth (`x-admin-token`) + audit log | ✅ | ✅ **V36** | — |
| `/admin/health` (load-balancer probe) | ✅ | ✅ **V44** | — |
| `/admin/hot_uris` (per-URI RPS top-N) | ✅ | ✅ **V43** | — |
| Challenge ladder (cookie + verify endpoint) | ✅ | ✅ **V42** | — |
| `POST /admin/reload` (config hot-swap) | ✅ | ❌ (501 → use `--upgrade`) | by design |
| Zero-downtime binary upgrade | systemd reload | ✅ pingora `--upgrade` | — |
| Web admin UI static React bundle on `/admin/ui` | ✅ | ✅ **V66** | — |
| `/admin/api/login` + session cookie + `/admin/api/logout` | ✅ | ✅ **V67** | — |
| `/admin/api/me` | ✅ | ✅ **V67** | — |
| `/admin/api/runtime/status` (dashboard fuel) | ✅ | ✅ **V68** | — |
| `/admin/api/filters` (per-filter counters) | ✅ | ✅ **V68** | — |
| `/admin/api/audit` (entries) | ✅ | ⚡ V68 (path-not-plumbed stub) | RC3 |
| `/admin/api/honeypots/builtin` + `/admin/api/honeypots` | ✅ | ✅ **V69** (read-only) | — |
| `/admin/api/sites` (list) | ✅ | ✅ **V69** (read-only) | — |
| `/admin/api/sites` write (POST/DELETE) | ✅ | ❌ | RC3 |
| `/admin/api/config/raw` PUT | ✅ | ❌ | RC3 |
| `/admin/api/honeypots` mutations (PUT/DELETE) | ✅ | ❌ | RC3 |
| `/admin/api/change-credentials` | ✅ | ❌ | RC3 |
| `GET /admin/xdp` (counters) | ✅ | ✅ **V45** | — |
| `POST /admin/xdp/{deny,undeny}/<ip>` | ✅ | ✅ **V45** | — |
| `aegis_xdp_*` counters in `/metrics` | ✅ | ✅ **V45** | — |
| XDP fast-path loaded at startup | ✅ | ✅ **V45** | — |
| Dynamic-trust → XDP allow auto-promote | ✅ | ✅ **V45** (via `.with_xdp()`) | — |
| HTTP/3 (QUIC) | ✅ V12+ | ✅ **V46** (via hyper-handler shim) | — |
| JA4T (TCP SYN fingerprint) | ✅ | ✅ **V45** (XDP captures pre-TLS) | — |
| JA3 (TLS ClientHello MD5) | ✅ | ✅ **V51** (openssl FFI) | — |
| JA4 (TLS 1.3 fingerprint) | ✅ | ✅ **V51** (openssl FFI) | — |
| JA4H (HTTP-side fingerprint) | ✅ | ✅ **V52** | — |
| h2_fp (Akamai h2 frame fingerprint) | ✅ | ❌ | Genuinely blocked — pingora-core consumes h2 frames via the `h2` crate before exposing parsed requests. Would require forking pingora-core to surface SETTINGS / WINDOW_UPDATE / PRIORITY values. Decision deferred. |
| mTLS leaf-cert fingerprint | ✅ | ✅ **V53** + V55 byte-identical | — |
| DSL knob for mTLS (`tls.mtls.enabled`, `ca_paths`, `require_cert`) | ✅ | ✅ **V59** | — |
| Background cert/key mtime auto-reload | ✅ | ✅ **V60** (ArcSwap<CertStore>) | — |
| h3 WAF rule hot-reload poller | ✅ | ✅ **V61** | — |
| Cross-binary JA3/JA4 byte-identical parity | n/a | ✅ **V56** (locked in by tests) | — |
| `aegis-pingora-e2e` integration harness | aegis-e2e | ✅ **V64** (9/9 PASS) | — |
| Stand bench harness (pingora vs hyper) | bench.sh | ✅ **V57** (runnable on stand) | run on stand |
| TLS-backend perf bench (openssl vs rustls) | n/a | ✅ **V58** (runnable on stand) | run on stand |
| HTTP/3 e2e smoke script | n/a | ✅ **V62** (curl --http3-only / quiche) | run on stand |
| systemd unit deployment validation | n/a | ✅ **V63** (root script) | run on stand |

The "yes" features are validated end-to-end on the dev box (see
`bench/comparison/results-2026-05-19-V24-pingora-foundation.md`).

---

## When to use which binary

**Use `aegis` (hyper) when:**
- You need any of the "❌" features above (most production
  deployments today).
- You need the full `/admin/*` API for hot config changes, cache
  purges, WAF rule reloads, or token rotation.
- You serve multiple TLS domains from one port (per-SNI cert).
- You rely on JA3/JA4-based filtering or HTTP/3.

**Use `aegis-pingora` when:**
- You want to A/B compare throughput against the hyper path before
  the V28 cutover bench.
- You operate a single-domain HTTPS site with no exotic TLS needs.
- You can tolerate "deploy = restart" instead of `/admin/reload`
  while the admin port catches up.

**Run both side-by-side** (different ports) for shadow benchmarking.
Both consume the same DSL config, so configuration drift is
impossible.

---

## Zero-downtime upgrade / config reload

Aegis-pingora deliberately does **not** implement `POST /admin/reload`
(returns 501 with a pointer to this section). Pingora ships its own
zero-downtime upgrade mechanism that does the same job better: the
new process inherits the listening file descriptors from the old one
and the old one drains its in-flight connections before exiting. No
dropped connections, no momentary 502s.

The mechanism lives on a Unix socket configured via pingora's
`upgrade_sock` (default `/tmp/pingora_upgrade.sock`).

```bash
# Drop the new aegis-pingora binary in place
sudo install target/release/aegis-pingora /usr/local/bin/

# Start the new process with --upgrade. It connects to the old
# process's upgrade_sock, receives the listening fds, and starts
# accepting new connections. The old process keeps serving its
# in-flight requests for `graceful_shutdown` seconds, then exits.
sudo /usr/local/bin/aegis-pingora --upgrade --config /etc/aegis/aegis.conf
```

For systemd-managed multi-worker deploys, wire this into a
sibling unit (`aegis-pingora-upgrade@.service`) that calls
`aegis-pingora --upgrade` per worker. The systemd template
deliberately doesn't pin the upgrade_sock path per-worker today —
multi-worker upgrade with SO_REUSEPORT is an open ops detail and
will be revisited in a later doc once we've benchmarked it on the
stand.

If you just want to push a config change without a binary swap, the
simplest path today is `systemctl restart aegis-pingora@*` —
SIGTERM triggers pingora's drain, restart picks up the new config.
With a small `graceful_shutdown_secs` this is sub-second and
in-flight requests still complete.

## Cutover bench (V71, 2026-05-20, 16-core arm64 stand)

Full results in
[bench/comparison/results-2026-05-20-V71-pingora-cutover.md](../../../bench/comparison/results-2026-05-20-V71-pingora-cutover.md).

| Scenario | Hyper | Pingora |
|---|---|---|
| HTTP single proc c=400 | 240k RPS / 1.67ms | **279k RPS / 1.49ms** |
| HTTP N=4 c=400 | 327k RPS / 5.58ms | **328k RPS / 1.25ms** (4.5× lower latency) |
| WAF-on N=4 c=400 | **344k RPS** / 1.22ms | 312k RPS / 1.31ms |
| TLS h2 N=4 c=400 | **301k RPS** / 1.93ms | 259k RPS / **1.61ms** |

**Recommendation:** GO for aegis-pingora on latency-sensitive
deployments. Throughput parity (within ~15% in worst case), but
tail latency consistently better. V71 found + fixed a single-
threaded default in pingora's ServerConf — multi-process REUSEPORT
deploys should set `AEGIS_PINGORA_THREADS=4` per worker on a
16-core box (cleanly partitioned, no thread oversubscription).

## Benchmark + validation suite

Four runnable scripts in `bench/comparison/` + one integration
harness binary. Run these on the production stand to publish
release-quality numbers + validate end-to-end behaviour.

| Script / binary | What it tests | Run-as | Run time |
|---|---|---|---|
| `bench/comparison/bench_pingora_vs_hyper.sh` | aegis (hyper) vs aegis-pingora at single + N=4 workers, light + heavy load. Writes a results markdown the operator attaches to the cutover decision. | operator | ~5 min |
| `bench/comparison/bench_openssl_vs_rustls.sh` | aegis-pingora openssl backend vs rustls backend (RPS + p99 + new-handshakes/sec). Validates V50 "+5-15% openssl" claim on your hardware. | operator | ~5 min |
| `bench/comparison/smoke_h3.sh` | curl --http3-only against aegis-pingora's h3 listener. Asserts HTTP/3 protocol negotiation + 200 status. | operator | <1 min |
| `bench/comparison/validate_systemd.sh` | Installs aegis-pingora@.service, starts a test instance, hits it via curl, stops cleanly, validates port released. | root | ~30s |
| `target/release/aegis-pingora-e2e` | In-process 9-invariant harness: plain GET, WAF deny, /metrics, admin token auth (no/wrong/valid), /health, cache flow, purge. CI-ready. | anyone | ~5s |

To produce a release-quality cutover bench:
```bash
cd /path/to/aegis
cargo build --release --features pingora --bin aegis-pingora
cargo build --release --bin aegis
sudo bench/comparison/validate_systemd.sh        # validate ops
bench/comparison/bench_pingora_vs_hyper.sh        # publish RPS
bench/comparison/bench_openssl_vs_rustls.sh       # validate perf claim
bench/comparison/smoke_h3.sh                       # h3 actually works
./target/release/aegis-pingora-e2e                 # integration green
```

## Known limitations + workarounds

### Per-SNI cert routing (h1/h2)

**Resolved in V50** by switching pingora's `pingora-core` /
`pingora-proxy` feature from `rustls` to `openssl`. The openssl
backend implements the `TlsAccept` trait's `certificate_callback`
hook (the rustls backend errors out — see
`pingora-core/src/listeners/tls/rustls/mod.rs:110`). Our
`AegisTlsAccept` preloads cert/key pairs from `tls.cert_path` +
`tls.sni[]` at startup and installs the right one mid-handshake
via `ssl.set_certificate()` / `ssl.set_private_key()`.

Verified on dev box:
```
openssl s_client -connect :18443 -servername localhost
  → subject=CN=localhost                       (default cert)
openssl s_client -connect :18443 -servername api.example.com
  → subject=CN=api.example.com                 (per-SNI entry)
openssl s_client -connect :18443 -servername unknown.example.com
  → subject=CN=localhost                       (fallback)
```

Performance impact of openssl vs rustls: handshake throughput is
typically +5–15% faster on openssl (mature C, native AES-NI/AVX-512
crypto), per-request crypto is parity (both use AES-NI). Memory
per-connection: openssl ~60KB vs rustls ~30KB — irrelevant unless
you maintain >1M concurrent connections.

Build cost of the switch: `libssl-dev` (Debian/Ubuntu) or
`openssl@3` (Homebrew) — both already present on every Linux
distro + standard CI image + macOS dev box.

### JA3 / JA4 / JA4H / h2_fp TLS fingerprints

**JA3 + JA4 resolved end-to-end in V51.** Switching to the openssl
feature (V50) exposed the `set_client_hello_cb` API plus
`SslRef::client_hello_*` accessors that give us raw ClientHello
data inside the `certificate_callback` phase of the handshake.
V51 wires the FFI calls (`SSL_client_hello_get1_extensions_present`,
`SSL_client_hello_get0_ext` from openssl-sys 0.9) and feeds the
parsed pieces to `ja3::compute_ja3_from_parts` /
`ja4::compute_ja4_from_parts` — same canonical strings the
hyper handler computes from raw record bytes. RFC-compliant
JA3-MD5 hex digest is exposed on TlsFingerprints.ja3_hash.

What works today on aegis-pingora (V45 + V50 + V51):

  • **JA4T** (TCP SYN fingerprint) — captured by the XDP/eBPF
    program before TLS even happens. V45 wires the XDP loader on
    aegis-pingora; `read_ja4t_v4(src_ip, src_port)` returns the
    same data the hyper handler reads. Filters that branch on
    JA4T (rate-limit per fingerprint class) work today.
  • **JA3 string + MD5 hex** — wire-compatible with abuse.ch /
    SSL Blacklist publication format. Operators can paste threat-
    intel hashes straight into `ja3_deny_hashes`.
  • **JA4 fingerprint** — FoxIO-compliant `{a}_{b}_{c}` format,
    GREASE-filtered. Picks the highest version from supported_versions
    (TLS 1.3 detection via ext 43).
  • **Per-SNI fingerprint capture** — handshake_complete_callback
    fires for every connection and stashes a TlsFingerprints struct
    on the SslDigest.extension. RequestContext.ja4 is populated.

  • **JA4H** (HTTP-side fingerprint, V52) — computed in
    `AegisPingoraProxy::build_ctx` from the request method +
    version + headers via `compute_ja4h_from_headermap`. Skipped
    for already-trusted IPs (hot-path optimisation parity with
    the hyper handler — trust grants are authoritative).

  • **mTLS client cert hash** (V53) — backfilled in
    `handshake_complete_callback` once the post-handshake peer
    chain is available. Same `mtls_fp::compute` the hyper handler
    uses, so fingerprints are byte-identical across both binaries.
    Activates when the operator wires
    `TlsSettings::set_client_cert_verifier` on the listener (DSL
    knob pending — until then peer_certificate returns None and
    `RequestContext.mtls_fp` stays None, no behavioural impact).

What still needs work:
  • **h2_fp** (Akamai HTTP/2 frame fingerprint) — needs raw h2
    frame bytes (SETTINGS / WINDOW_UPDATE / PRIORITY values).
    Pingora consumes h2 frames internally before exposing parsed
    requests, so this needs deeper pingora-proxy surface hooks.
    Genuinely blocked.

## Roll back

```bash
sudo systemctl stop 'aegis-pingora@*'
sudo systemctl start 'aegis@{1,2,3,4}'
```

The hyper unit keeps running independently — no state corruption,
no ports stolen (assuming you didn't try to run both pointing at the
same listener port).
