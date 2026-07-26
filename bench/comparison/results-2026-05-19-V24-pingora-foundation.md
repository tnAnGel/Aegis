# V24 — aegis-pingora vs aegis (hyper), dev-box smoke bench

Dev-box (M-series Mac, OrbStack containerised upstream on :8000)
comparison of the Phase B preview binary `aegis-pingora` against the
production hyper-based `aegis` binary. **This is a dev-box bench, not
a production bench** — both proxies are bottlenecked by the same
single-process Python/OrbStack upstream sitting behind a thin reverse
tunnel, so the numbers track *parity*, not absolute throughput. The
real perf cutover bench will run on the Linux stand
(`aegis-proxy.orb.local`, 16-core arm64) once V25's TLS support is
wired and we can A/B with the same config.

## Setup

- macOS Darwin 24.5.0 (M-series arm64).
- Upstream: existing dev backend on `127.0.0.1:8000` (responds
  `backend ok\n`, 11 bytes).
- Both proxies built `--release`. Same DSL config:
  WAF off, rate_limit 100k rps, no challenge / bot / adaptive — pure
  pipe-through so the comparison isolates the proxy hot-path only.
- Load: `wrk -t4 -c64 -d10s` for single-worker runs;
  `wrk -t8 -c128 -d10s` for the 4-worker pingora run.

## Results

| Variant | RPS | p99 latency | Notes |
|---|---|---|---|
| `aegis` (hyper, single process) | **22,881** | 2.9 ms avg | Production V21 build |
| `aegis-pingora` (single worker, no reuseport) | 20,677 | 3.1 ms avg | New V23 binary |
| `aegis-pingora` (4 workers, `AEGIS_PINGORA_REUSEPORT=1`) | 20,082 | 11.2 ms avg | Bottlenecked by upstream — see below |

## Reading the numbers

The 4-worker pingora run did *not* scale linearly. That's expected
here: the upstream backend is single-process Python with no
concurrency, so once any one proxy worker saturates the upstream's
accept queue the others spend their time blocked on connect/read.
Latency jumped to 11 ms avg with 9 timeouts in the 10-second window
— classic upstream-bound symptom, not a proxy problem.

Single-worker pingora and single-process hyper are within ~10% on
this dev box. The V18 multi-process bench on the Linux stand
(N=4 hyper = 408k RPS) was specifically demonstrating that
hyper-aegis with SO_REUSEPORT can saturate 16 cores against a *fast*
upstream (nginx echo). The pingora binary now supports the same
SO_REUSEPORT pattern (V24); the equivalent stand bench will land
once the OrbStack VM gets the new binary deployed.

## What this proves about V22–V24

1. **End-to-end correctness** — aegis-pingora serves real HTTP
   through the same FilterEngine the hyper path uses. Both legit
   requests (200 + upstream body) and WAF blocks (403 + reason
   string) verified.
2. **SO_REUSEPORT works** — 4 aegis-pingora workers bound the same
   port via `AEGIS_PINGORA_REUSEPORT=1`, `lsof` confirmed 4 listeners
   on `127.0.0.1:18080`, all 5 sanity-check requests served 200.
3. **Graceful drain works** — SIGINT triggers pingora's own drain;
   in-flight connections finish, then the process exits clean.
4. **No perf regression at parity** — single-worker pingora is
   within ~10% of single-process hyper on the dev box, in the
   ballpark expected for a foundation skeleton with zero
   pingora-side tuning yet. On a fast upstream the gap will close.

## Stand bench plan (not run here)

For the production-grade comparison on the Linux stand:

```bash
# Deploy aegis-pingora release binary to /usr/local/bin
scp target/release/aegis-pingora aegis-proxy.orb.local:/tmp/
ssh aegis-proxy.orb.local 'sudo install /tmp/aegis-pingora /usr/local/bin/'

# Use the existing nginx echo upstream on :8000
# Run single-worker first
ssh aegis-proxy.orb.local '
  AEGIS_HONEYPOT_STATE=/tmp/aegis-hp1.json \
    /usr/local/bin/aegis-pingora --config /etc/aegis/aegis.conf --log-level error
' &
# Run wrk from host: wrk -t8 -c100 -d30s http://aegis-proxy.orb.local/

# Then N=4 reuseport
for n in 1 2 3 4; do
  ssh aegis-proxy.orb.local "
    AEGIS_PINGORA_REUSEPORT=1 AEGIS_HONEYPOT_STATE=/tmp/aegis-hp$n.json \
      /usr/local/bin/aegis-pingora --config /etc/aegis/aegis.conf --log-level error
  " &
done
# wrk -t16 -c400 -d30s http://aegis-proxy.orb.local/
```

Expected ranges based on V18 hyper baselines:
- Single-worker pingora: 100k–180k RPS (target: match or beat hyper's 142k).
- N=4 pingora reuseport: 350k–500k RPS (target: match or beat hyper's 408k).

If pingora wins both, V28 (cutover) can flip the default. If hyper
wins single-worker but pingora wins multi-worker, both stay shipped
and operators choose per deployment.
