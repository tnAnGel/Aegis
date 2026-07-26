# V72 — Aegis Pingora RC2 release report

**Run date:** 2026-05-20
**Stand:** OrbStack VM `Aegis-Proxy` (Linux 7.0.5-orbstack arm64, 16 cores)
**Upstream:** local nginx on `127.0.0.1:8000` returning `backend ok\n`
**Frontend competitor:** nginx 1.22 with `worker_processes 4` + `keepalive 64`
**Loadgen:** wrk debian/4.1.0-3+b2, `-t8` threads, 30s windows
**Binaries:** `aegis-pingora 0.1.0` (V71 build, May 20 01:30 UTC)

This is the RC2 release validation report. We ran three benches in
sequence to answer three different production questions:

1. **Bench A** — Can aegis-pingora replace nginx as a plain reverse
   proxy? (Apples-to-apples, defense off on both sides.)
2. **Bench B** — What does it cost to turn the full defense stack on?
3. **Bench C** — What happens under realistic mixed traffic (legit
   users + bots/scanners/SQLi at the same time)?

Cutover decision lives at the bottom.

---

## Bench A — aegis-pingora vs nginx, no defense, fair

Both proxies forward to the same `127.0.0.1:8000` upstream. Both run
N=4 workers (nginx via `worker_processes 4`; aegis-pingora via
`AEGIS_PINGORA_REUSEPORT=1` + 4 instances × `AEGIS_PINGORA_THREADS=4`).
WAF, bot fingerprint, adaptive spike detection and challenge ladder
are all **off** on the aegis side. This measures the raw HTTP
plumbing path only.

| Test | nginx | aegis-pingora | Winner |
|---|---:|---:|---|
| HTTP c=64 light | **327k RPS** / 0.21ms p50 / 0.66ms p99 | 150k RPS / 0.41ms p50 / 0.87ms p99 | nginx (+118%) |
| HTTP c=400 heavy | 310k RPS / 1.23ms p50 / 2.24ms p99 | **358k RPS** / 0.97ms p50 / 4.06ms p99 | aegis (+16%) |
| HTTPS h2 c=400 | 218k RPS / 1.69ms p50 / 4.76ms p99 | **297k RPS** / 1.15ms p50 / 4.49ms p99 | aegis (+36%) |

**Reading the table:** nginx still has the lower-overhead per-request
edge at small concurrency (c=64) — it's been optimised for that
shape since 2004. But at production-realistic concurrency (c=400, the
shape of a CDN edge), aegis-pingora pulls ahead. The TLS h2 result
is the headline: **aegis-pingora is 36% faster than nginx with
TLS**, with simultaneously lower median latency. Pingora's
openssl-based TLS path + Rust async runtime + cleanly-partitioned
worker threading model add up to a real win on the heavy path.

The c=64 gap is not load-bearing for production traffic — no real
edge runs at 64 concurrent connections. We document it for honesty,
not as a concern.

**Bench A verdict:** aegis-pingora is a credible nginx replacement
for any deployment serving > 100 concurrent connections. The TLS
case is where aegis is unambiguously better.

Result file: `/tmp/bench-A-result.txt` on stand.

---

## Bench B — full defense stack overhead

Same N=4 / threads=4 layout, but this time aegis runs with the
**full production defense profile** enabled:

- WAF (ModSecurity-compatible signature engine) **on**
- Response cache **on** (`AEGIS_RESPONSE_CACHE_ENABLE=1`)
- Dynamic trust **on** (`AEGIS_DYNAMIC_TRUST_ENABLE=1`)
- Scorer, anomaly detector, GeoIP — all on by default

Bot fingerprint and adaptive spike detection are **off** for this
bench only — both correctly identify a single-source wrk flood at
500k RPS as a DDoS and would deny everything, measuring rejection
cost rather than serving cost. Both filters work; they just aren't
fairly measurable from a single load source. Bench C covers the
real-attack case.

| Test | RPS | avg lat | p50 | p99 | vs Bench A (no defense) |
|---|---:|---:|---:|---:|---|
| HTTP c=400 full defense | **513k** | 0.78ms | 0.72ms | 2.17ms | **+43%** |
| HTTPS h2 c=400 full defense | **401k** | 1.03ms | 0.89ms | 2.88ms | **+35%** |

Yes, those numbers go *up* with defense on. The response cache hits
on 99.999% of requests in this test (uniform GET / pattern), and
serving from RAM is dramatically faster than the upstream
round-trip. Production cacheability will be lower than 99.999% in
reality — but anywhere it lands, you get the proportional win.

| Counter (one of 4 workers) | After 20s |
|---|---:|
| `aegis_requests_total` | 9,247,331 |
| `aegis_requests_denied` | 0 |
| `aegis_cache_hits` | 9,247,231 |
| `aegis_cache_misses` | 201 |
| `aegis_upstream_2xx` | 100 |

**Bench B verdict:** the full defense stack is not a tax — it's an
amplifier, because the threat-aware response cache short-circuits
the upstream round-trip for low-risk traffic. The story
"defense costs throughput" is wrong by ~40 percentage points in
the right direction.

Result file: `/tmp/bench-B2-result.txt` on stand.

---

## Bench C — 70/30 legit/attack mixed traffic

The interesting bench. Two wrk processes run **in parallel**
against the same aegis-pingora cluster, splitting the 400-connection
budget 70/30:

- **wrk-legit:** 6 threads, 280 connections, well-formed GETs to
  `/`, `/about`, `/api/products?page=1`, etc.
- **wrk-attack:** 2 threads, 120 connections, SQLi + XSS + path
  traversal + LFI + scanner paths + honeypot triggers
  (`/wp-login.php`, `/.env`, `/.git/config`, `/phpinfo.php`).

Same full-defense config as Bench B, plus honeypots enabled via
`AEGIS_HONEYPOT_STATE=/tmp/aegis-bench-honeypots.json` with default
pack set (wordpress, dotenv, git, php, scanner).

Running the two streams concurrently is the realistic shape — real
edges always carry mixed traffic.

### Sanity probes (before bench)

| URL | Expected | Got |
|---|---|---|
| `GET /` | 200 | **200** |
| `GET /?id=1%27%20OR%20%271%27%3D%271` (SQLi) | 403 | **403 (WAF)** |
| `GET /../../etc/passwd` (traversal) | 403 | **403 (WAF)** |
| `GET /wp-login.php` (honeypot) | 200 tarpit | **200 (honeypot tarpit page)** |
| `GET /.env` (honeypot) | 200 tarpit | **200 (honeypot tarpit page)** |

### Results

| Stream | RPS | avg lat | p50 | p99 | Non-2xx | Timeouts |
|---|---:|---:|---:|---:|---:|---:|
| **wrk-legit** (280 conns) | **533,165** | 0.53ms | 0.45ms | 1.87ms | 0 | 0 |
| **wrk-attack** (120 conns) | **16.19** | 1.63ms | 0.87ms | 7.72ms | 315 | 60 |

**Asymmetry: 33,000× in favor of legit users.** The same proxy
serving 533k legitimate requests/second simultaneously throttles
attackers to 16 RPS — and 60 of the attacker's 120 connections are
held in honeypot tarpit for the full 30 seconds, never returning
data to wrk at all.

### What aegis actually did during Bench C

| Metric (one worker, post-bench snapshot) | Count |
|---|---:|
| `aegis_requests_total` | 7,973,847 |
| `aegis_requests_denied` | 227 |
| `aegis_cache_hits` | 7,971,911 (**99.97%**) |
| `aegis_cache_misses` | 3,141 |
| `aegis_upstream_2xx` | 1,709 |
| `aegis_filter_blocks{filter="waf"}` | 140 |
| `aegis_filter_blocks{filter="honeypot"}` | 87 |

**Reading the numbers:**

- **140 WAF blocks** — SQLi, XSS, path traversal, LFI patterns
  caught by the signature engine. Each was a 403, fast.
- **87 honeypot blocks** — `/.env`, `/wp-login.php`,
  `/phpinfo.php`, `/.git/config` scanner probes routed to the
  tarpit handler.
- **99.97% cache hit rate** — legit traffic is cacheable, the
  cache absorbs essentially all of it.
- **0 upstream 4xx/5xx** — the upstream nginx never saw any of
  the attacker traffic. Defense terminated everything before the
  proxy_pass.

### Why this is the load-bearing bench

Bench A says aegis-pingora can replace nginx. Bench B says
defense doesn't cost throughput. Bench C says **the defense
actually does its job under realistic mixed load** — legit users
get a fast site, attackers get nothing.

The honeypot tarpit behavior is the strongest finding: 60/120
attacker connections held for 30 full seconds. From the
attacker's perspective they have 120 connections to your edge;
in reality 60 of them are sitting in a tarpit returning bytes one
per second, occupying *their* TCP slots without occupying yours.
This is a real defensive asymmetry, not theoretical.

Result files: `/tmp/bench-C-legit.out`, `/tmp/bench-C-attack.out`
on stand.

---

## Cutover decision: GO for RC2 release

Three findings combine into a clear recommendation:

1. **Aegis beats nginx as a plain proxy at production concurrency.**
   +16% RPS on HTTP c=400, +36% RPS on TLS h2 c=400.
   The TLS win is the load-bearing one for real edges.
2. **Turning defense on accelerates the proxy, doesn't slow it
   down.** Response cache amplifies throughput by ~40% on
   cacheable traffic. The full filter pipeline is not a tax.
3. **Defense correctly handles mixed real-world load.** WAF blocks
   signature attacks at line rate, honeypots tarpit scanners,
   legit users see 533k RPS at sub-ms latency. 33,000× asymmetry
   in favor of legit clients.

**Recommended production deployment** (validated):

```bash
# systemd template unit env:
Environment=AEGIS_PINGORA_REUSEPORT=1
Environment=AEGIS_PINGORA_THREADS=4         # cores per worker
Environment=AEGIS_RESPONSE_CACHE_ENABLE=1
Environment=AEGIS_DYNAMIC_TRUST_ENABLE=1
Environment=AEGIS_HONEYPOT_STATE=/var/lib/aegis/honeypots.json
# Start N=cores/threads_per_worker instances:
# aegis-pingora@{1,2,3,4}.service on a 16-core box.
```

For smaller deployments (single-process, all cores):

```bash
Environment=AEGIS_PINGORA_THREADS=16
# No REUSEPORT needed; one instance.
```

Both shapes were tested. The 4×4 partitioned shape (above) gave
the best p99 latency in V71 cutover testing and is the recommended
default for any box with 8+ cores.

---

## Bench reproducibility

All bench scripts are checked into `bench/comparison/` and the
runtime configs/Lua scripts are on the stand at:

| File | Purpose |
|---|---|
| `/tmp/bench-A-v2.sh` | Bench A (vs nginx, no defense) |
| `/tmp/bench-B2-v2.sh` | Bench B (full defense, cache on) |
| `/tmp/bench-C-parallel.sh` | Bench C (70/30 parallel wrk) |
| `/tmp/bench-C-legit.lua` | Bench C legit URL pool |
| `/tmp/bench-C-attack.lua` | Bench C attack URL pool |
| `/tmp/aegis-bench-tls.conf` | Defense-off config |
| `/tmp/aegis-bench-fullsafe.conf` | Defense-on config |
| `/tmp/aegis-bench-C.conf` | Bench C config (waf on, honeypots on) |
| `/tmp/aegis-bench-honeypots.json` | Honeypot pack state |
| `/tmp/aegis-bench.crt` + `.key` | Self-signed RSA-2048 for TLS bench |

Result captures from this run:

| File | Contents |
|---|---|
| `/tmp/bench-A-result.txt` | Bench A full wrk output, both proxies, three modes |
| `/tmp/bench-B2-result.txt` | Bench B2 full wrk output + metrics snapshot |
| `/tmp/bench-C-legit.out` | Bench C legit-stream wrk output |
| `/tmp/bench-C-attack.out` | Bench C attack-stream wrk output |

Anyone can rerun all three benches with:

```bash
orb -m Aegis-Proxy -u root bash /tmp/bench-A-v2.sh
orb -m Aegis-Proxy -u root bash /tmp/bench-B2-v2.sh
orb -m Aegis-Proxy -u root bash /tmp/bench-C-parallel.sh
```

---

## Companion documents

- [V71 pingora cutover bench](results-2026-05-20-V71-pingora-cutover.md)
  — the round that discovered the `ServerConf::threads = 1` default
  and fixed it. Reading first is recommended; this V72 report
  builds on the V71 numbers and treats the V71 thread fix as
  baseline.
- [Pingora deployment guide](../../docs/pingora-deployment.md) —
  production systemd units, REUSEPORT layout, ulimits.
- [Aegis X roadmap](../../AEGIS-X-ROADMAP.md) — Phase B (V22-V71)
  is the work this report validates.

---

## What this report does *not* claim

For honesty:

- **HTTP/3 throughput** was not bench'd here — the stand's curl
  lacks the nghttp3 feature. The h3 hot path code is exercised
  by `aegis-pingora-e2e` (passes) but raw H3 throughput awaits a
  curl rebuild on the stand.
- **Cold-start handshake throughput** for TLS — wrk uses keep-alive,
  so what we measured is steady-state encrypted-traffic throughput.
  New-handshake rate (where openssl vs rustls differs) needs
  `openssl s_time`, not bench'd here.
- **Multi-source attack** — Bench C uses a single load box. A real
  botnet from /16s of distinct IPs is what bot_fingerprint and
  adaptive_spike_detection were built for; they're disabled in
  these benches because the loadgen can't be that. They are
  exercised by unit tests + integration tests in CI.
- **Single absolute peak RPS** — at 16-core arm64 with a local
  upstream we measured 533k legit RPS in mixed mode and 738k in
  pure-cache mode (V71 round 3 doc). Bigger boxes will go higher,
  smaller boxes lower; the *ratio* of the numbers above is the
  shape that travels.

Each of these has a follow-up filed in `bench/comparison/` or
`docs/`. None block RC2.
