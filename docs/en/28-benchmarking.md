# Benchmarking

**Languages:** **English** · [Русский](../ru/28-benchmarking.md)

Aegis ships its own benchmark harness so you can measure *your* hardware instead
of trusting someone else's numbers.

## The built-in benchmark page

The admin panel's **Benchmark** page runs three things, all on the host the
panel is running on:

| Benchmark | What it does |
|---|---|
| **Hardware + capacity** | Micro-benchmarks CPU integer throughput, SHA-256 rate and memory bandwidth, then projects forwarding / TLS / WAF request rates and names the bottleneck |
| **Flood harness** | SYN flood, HTTP request flood, TLS handshake flood, Slowloris and cache-served throughput — each with a pass/fail verdict and p99 under attack |
| **Proxy comparison** | Spins up nginx, nginx+ModSecurity+CRS, HAProxy, Caddy and Envoy as ephemeral reverse proxies in front of the same in-process upstream, drives the same load at each, and sends the same attack payloads through each |

Or from the API:

```bash
TOKEN=$(cat /etc/aegis/admin-token)

curl -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/run
curl -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/flood/run
curl -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/compare/run

curl -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/compare/result
```

Runs are fire-and-forget; poll the `/result` endpoint until `status` is `done`.

### Getting the competitors installed

The installer sets them up for you (services installed but disabled, so they
never contend for :80/:443). Manually, on Debian 12:

```bash
apt install haproxy caddy libnginx-mod-http-modsecurity modsecurity-crs libmodsecurity3
# Envoy has no apt package — drop the static binary into /usr/local/bin/envoy
systemctl disable --now nginx haproxy caddy
systemctl mask caddy caddy-api
```

Missing binaries are reported as `available: false` and the matrix still renders.

## Reference results

Measured on a Debian 12 VM, 16 vCPU / 16 GB (aarch64), 8 CPU-pinned workers:

| Proxy | WAF | Throughput | p50 | p99 |
|---|:---:|---:|---:|---:|
| Aegis (raw proxy) | — | 217 681 rps | 0.25 ms | 0.80 ms |
| **Aegis + WAF** | ✅ | **134 997 rps** | 0.40 ms | 1.55 ms |
| HAProxy 2.6.12 | — | 116 594 rps | 0.55 ms | 1.30 ms |
| Caddy 2.6.2 | — | 83 705 rps | 0.05 ms | 15.70 ms |
| nginx 1.22.1 | — | 42 667 rps | 0.55 ms | 1.20 ms |
| Envoy | — | 39 550 rps | 1.45 ms | 4.05 ms |
| nginx + ModSec + CRS | ✅ | 2 203 rps | 8.60 ms | 25.05 ms |

Security coverage on the same run: Aegis + WAF blocked 10/10 payload classes,
nginx+ModSec+CRS 9/10, every plain forwarder 0/10.

## Reading these numbers honestly

- **Loopback, single host, short windows.** The generator, the proxies and the
  upstream all share the same cores. Absolute figures are conservative and
  compressed; the *ratios between lanes* are what carry meaning.
- **Competitors run as ephemeral single instances** with a minimal reverse-proxy
  config. A production-tuned multi-worker nginx on dedicated cores is much
  faster than the number above — see the next point.
- **As a plain forwarder, tuned nginx beats Aegis.** On a CPU-isolated stand
  with each proxy in its own high-performance configuration, plain forwarding
  measures roughly nginx 590k rps vs Aegis 513k at c=500 — about a 13% gap, with
  Aegis holding the lower p99 (1.9 ms vs 2.0 ms). In cache mode the order
  reverses: Aegis ~970k rps vs nginx+proxy_cache ~660k.
- **The fair fight is with inspection on.** nginx with ModSecurity + OWASP CRS
  loses ~95% of its throughput (42.7k → 2.2k); Aegis loses ~38% (217.7k → 135.0k)
  and still ends up faster than every unprotected proxy in the table. That is the
  comparison that reflects what each stack actually does per request.
- **Short windows are noisy.** Repeated runs on the same idle box move each lane
  by 10-20%. Take several runs; the ordering and the ratios are stable, the
  absolute numbers wander.
- **Under attack the comparison stops being meaningful.** No plain forwarder
  filters anything — 100% of the attack traffic reaches the origin.

## Rolling your own

Scripts under `bench/comparison/` drive external load generators
(`wrk`, `oha`, `slowhttptest`) against a running Aegis and a reference nginx:

```bash
bench/comparison/bench.sh          # attack + load matrix, aegis vs nginx
bench/comparison/bench_fair.sh     # equal-protection comparison
bench/comparison/setup_stand.sh    # provision a comparison stand
```

For reproducible numbers:

1. Put the load generator on a **different machine** from the proxy.
2. Pin the proxy to a fixed core set and the generator to another.
3. Use `--latency-correction` (`oha`) so coordinated omission does not flatter
   your p99.
4. Take a best-of-N, not a single run, and report the methodology alongside the
   number.

See also the [performance deep dive](reference/performance.md) — profiling
method, where the remaining time goes, and two optimisation paths (io_uring and
header-map gating) that were measured and rejected with evidence.
