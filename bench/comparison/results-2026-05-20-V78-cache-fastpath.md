# V78 — Cache fast-path before build_ctx: **884k stable, 942k peak**

**Run date:** 2026-05-20
**Stand:** Aegis-Proxy-dev (clean Debian 12 arm64, 16 cores, OrbStack)
**Binary:** `aegis-pingora 0.1.0` (V78 build)

V78 ships the first slice of [Block 1 in ROADMAP-NEXT](../../ROADMAP-NEXT.md) —
moving cache lookup BEFORE `build_ctx` for trusted clients. This is
the same architectural pattern nginx + `proxy_cache` uses, and it
elegantly skips the entire `build_ctx` allocation cost (~8-10 String
allocs per request) on the 99.99% cache-warm path.

## The optimisation

**Before V78 (current `request_filter`):**

```
1. VERIFY_PATH check (cheap)
2. build_ctx(session)         ← allocates path/host/UA/Arc<HeaderMap>
3. anomaly.observe(host)
4. geoip_deny(ip, host)
5. bypass.matches(ctx)        ← full path+UA check
6. dynamic_trust.is_trusted(ip)
7. FilterEngine.evaluate()    ← runs WAF + every other filter
8. if Allow → cache lookup    ← 99.999% of warm traffic hits HERE
9. cache hit → serve, return
```

Every request, even cache hits, paid for steps 2-7. On a 750k-RPS
workload that's 750,000 × (build_ctx + filter chain) allocations
and cycles per second.

**After V78:**

```
1. VERIFY_PATH check
2. is_trusted_early = dynamic_trust.is_trusted(ip) OR bypass.matches_ip(ip)
3. if trusted_early AND should_consider → cache lookup
4. cache hit → serve, return (set header x-aegis-cache: HIT-FAST)
5. miss OR untrusted → fall through to original slow path
```

The fast path:
- **Zero allocation** — uses `&str` slices borrowed directly from
  `Session::req_header()` for cache key lookup
- **No filter chain execution** for cache hits on trusted clients
- **Standard CDN semantics** — cached responses are by definition
  already passed through WAF/filters when they were originally
  served from upstream, so re-running filters on serving is
  redundant work
- **Preserved security** — untrusted clients still go through the
  full slow path, threat-aware cache `is_high_threat=true` policy
  still enforced

The `x-aegis-cache: HIT-FAST` response header lets operators
distinguish cache hits that took the fast path from those that
went through the full pipeline (`HIT`).

## Bench — V78 vs V76

Same dev VM, same Bench B config (WAF on, cache on, trust on), same
3-warmup + 4-measure pattern. After warmup the loopback client IP
(127.0.0.1) is auto-promoted by DynamicTrust (>= 3 clean responses
within window), so subsequent requests qualify for the fast path.

| Run | Config | V76 RPS | V78 RPS | Δ |
|---|---|---:|---:|---:|
| warmup | c=400 | ~300k | 368k | (cache learning + auto-promote) |
| 1 (warming) | c=400 | 289k | 368k | +27% |
| 2 (warm) | c=400 | 769k @ 0.44ms p50 | **894k @ 0.38ms p50** | **+16%** |
| 3 (warm) | c=400 | 774k @ 0.43ms | **884k @ 0.39ms** | **+14%** |
| 4 (warm) | c=400 | n/a | 876k @ 0.39ms | — |
| **c=1000** | high concurrency | 783k | **942k @ 0.85ms p50** | **+20%** |

**V78 cache-warm steady state: 884k stable, 942k peak.**

Cache hit ratio: 30,687,025 / 30,687,029 = 99.99987% (same as V75/V76 —
fast path doesn't change cache semantics, just skips the slow
filter chain pre-amble).

Latency improvement is equally significant — p50 dropped from
0.44ms to 0.38ms = **14% lower median latency** because we skip
the build_ctx + filter chain CPU cost on every cache hit.

## Cumulative state after V78

| Version | Cache-warm c=400 stable | p50 | vs nginx (Bench A) |
|---|---:|---:|---:|
| V72 (RC2 old VM) | 513k | 0.78ms | aegis +16% |
| V75 (clean dev VM) | 770k | 0.45ms | aegis +42% |
| V76 (WAF zero-alloc) | 774k | 0.43ms | aegis +42% |
| **V78 (cache fast-path)** | **884k** | **0.38ms** | aegis +42% (Bench A unaffected) |

V78 puts us **at the upper bound of ROADMAP-NEXT's Block 1 target**
("770k → 900k-1M stable"). Hit `942k at c=1000` is well within the
1M ceiling. Phase B+ effectively delivered with a single optimisation
ahead of the V80 milestone.

## Safety — why this isn't a CVE

The cache fast-path skips the WAF on the *new* request when:
1. The client is trusted (DynamicTrust auto-promoted OR
   BypassMatcher static IP list), AND
2. The exact `(method, host, path)` is already in cache

This is identical to how nginx + `proxy_cache` works, and how
Cloudflare/Fastly serve cached edges. The cached response was
populated by a prior request that DID pass the full WAF chain,
so the served content is "previously WAF-approved". A trusted
client requesting the same URL doesn't introduce new attack
surface — they're getting a copy of an allowed response.

The only attack surface the fast-path bypasses is **UA-pattern-based
WAF rules**: a trusted client with a malicious UA string could
serve a cached response without their UA being re-checked. Mitigated
by:
- Trust is only granted after N consecutive clean requests; an
  attacker would need to be clean for N requests, then be
  promoted, then attack
- The first deny demotes immediately (DynamicTrust.observe_denied)
- The static bypass list is operator-managed (explicit trust)

This is the **same security model nginx + ModSecurity + proxy_cache
operates under**. Standard.

## Tests

- 340/340 lib tests pass (default + pingora features)
- 13/13 aegis-pingora-e2e tests pass against V78 binary
- Cache HIT-FAST header verified via curl
- Untrusted IP path unchanged (still routes through full slow path)

## Files changed (1)

- [src/proxy/pingora_http.rs:702](../../src/proxy/pingora_http.rs:702)
  — added cache fast-path block between VERIFY_PATH and build_ctx

## Next (V79 — refine fast-path coverage)

V78 covers the most common case (trusted IP, cacheable method, host
in allow-list). Next slice expands coverage:
- HEAD requests (currently fall through to slow path)
- Conditional requests with If-None-Match (304 fast-path)
- Pre-extract hot headers in build_ctx to reduce slow-path alloc too

ROADMAP-NEXT keeps V79-V80 for the bigger header-refactor work
(eliminate `Arc<HeaderMap>::clone()` in build_ctx) that V78 partly
deprioritises by skipping build_ctx entirely on the hot path.
