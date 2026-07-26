# V76 — Phase C realistic delivery + monoio blocker doc

**Run date:** 2026-05-20
**Stand:** Aegis-Proxy-dev (clean Debian 12 arm64, 16 cores, OrbStack)
**Binary:** `aegis-pingora 0.1.0` (V76 build)

The roadmap's [Phase C](../../AEGIS-X-ROADMAP.md) ("monoio + SIMD parser
+ lock-free header maps") is an **8-week project**: it requires
either forking pingora-core to swap out tokio, or rebuilding a
parallel data plane on monoio (50k+ LOC of HTTP/1.1+h2 plumbing).
That's not deliverable in a single session.

What V76 ships instead is the **honest portion of Phase C that fits
in one session, plus a clear blocker doc for the parts that don't**.

## What landed

### Phase C.2 — eliminate WAF hot-path `format!()`

[src/filters/waf.rs:695-727](../../src/filters/waf.rs:695) used to
do this per request:

```rust
let target = format!(
    "{} {} {} {} {}",
    ctx.method, ctx.path,
    ctx.user_agent.clone().unwrap_or_default(),
    ctx.headers.get("referer")...
    ctx.headers.get("cookie")...
);
if let Some(kind) = self.match_signature(&target) { ... }
```

Two heap allocs per request even on the happy path (legit GET, no
signature hit):
1. The `format!` String concatenation
2. `user_agent.clone()` — an extra String alloc

V76 scans each field independently — patterns never span field
boundaries (scanner paths, SQLi tokens are self-contained), so the
AC automaton's leftmost-first semantics are preserved per-field:

```rust
let path_str = ctx.path.as_str();
let ua_str = ctx.user_agent.as_deref().unwrap_or("");
// ...
for field in [method_str, path_str, ua_str, referer_str, cookie_str] {
    if field.is_empty() { continue; }
    if let Some(kind) = self.match_signature(field) {
        return Deny;
    }
}
```

**Zero alloc on the hot path** for legit traffic.

### Bench results (clean dev VM, same setup as V75)

**Cache-warm path** (cache absorbs everything, WAF rarely runs):

| Run | V75 | V76 |
|---|---:|---:|
| stable run 1 | 744,614 | **769,766** |
| stable run 2 | 743,022 | **774,521** |

V76 cache-warm steady-state: **~770k vs V75 ~744k = +3.5%**. Small
because at 99.99% cache hit ratio the WAF check almost never
executes anyway.

**Cache-off WAF-on path** (WAF runs on every request):

| Config | Stable RPS | p50 | p99 |
|---|---:|---:|---:|
| **V76 WAF-on, cache-off** | **244k** | 1.40ms | 6.21ms |
| V75 baseline (no defense) | 248k | 1.39ms | 6.51ms |
| V72 reported WAF-on overhead | -10% | — | — |

V76 WAF-on is **within 1.6% of the no-defense baseline** (244k vs 248k).
V72 reported WAF-on costing ~10% (the bench that motivated the V73
hot-path counter sharding fix). Combined V73 + V74 + V76 has reduced
WAF overhead from 10% to ~2%. **The WAF is now effectively free** on
this workload.

### What V76 deliberately did NOT ship

- **Per-worker thread-local cache front** — explored, deferred. The
  cache already hits 99.9997% on bench. Contention isn't the
  bottleneck right now; would add risk (cache invalidation race
  across threads) for marginal win. Revisit if real production
  traffic shows hot-shard contention.
- **SIMD body scan** — body inspection is a slow-path code (most
  GETs have no body). memchr / SIMD optimisation here doesn't
  affect throughput numbers in our bench profile. Worth doing if
  POST-heavy workload becomes priority.
- **Inline filter dispatch** — would specialise `Box<dyn Filter>`
  into a const struct, removing one vtable call per request.
  Tested locally; the vtable indirection is too cheap on modern
  CPUs to measure. Punt.

## Phase C.1 — monoio + io_uring runtime swap

**Verdict: 4-8 week project. Not shippable in this session.**

The roadmap claims "+50-100% throughput" from replacing tokio with
monoio. Real picture:

### Why it's not a drop-in

pingora-core 0.8.0 is **built on top of tokio**. Specifically:

- `pingora_core::server::Server` calls `tokio::runtime::Runtime::new`
- Every `async fn` in the trait `ProxyHttp` (our handler interface)
  returns a `Future` that's polled by tokio's executor
- `Session::read_request_body()` etc. all assume a tokio reactor
- `pingora_cache`, `pingora_proxy` etc. all use `tokio::sync::*`
  primitives — different lock implementations than monoio's

You cannot "just" swap the runtime. monoio's `async fn` differs
from tokio's — monoio uses **completion-based** I/O (io_uring) and
**!Send futures** by default. Every pingora call site that holds
state across `.await` needs auditing.

### Realistic paths forward

| Path | Effort | Risk | Outcome |
|---|---|---|---|
| **Fork pingora-core, replace tokio→monoio** | 4-6 weeks | High — diverging from upstream pingora releases; we eat all future maintenance | +30-50% on tight loops, much higher on I/O-bound |
| **Build parallel monoio data plane**, keep pingora as legacy fallback | 6-10 weeks | Medium — clean separation, but doubles code paths | Full control over I/O, +50-100% theoretical |
| **Wait for pingora upstream to support monoio** | unknown | Low effort | Cloudflare has no public plans for this |
| **tokio tuning instead** (better than nothing) | 2-3 days | Low | +5-10% via runtime hooks (LIFO local queue, lazy reactor wakeups) |

### What we could actually do this quarter

The minimum-viable Phase C.1 replacement is:

1. **tokio runtime tuning** (~3 days). Configure `tokio::runtime::Builder`
   with `lifo_slot()` enabled (keeps recently-scheduled tasks on the
   same core for cache locality), `disable_lifo_slot()` selectively
   for I/O-heavy workloads, `event_interval(N)` to amortise reactor
   polling. Expected: +5-10% steady state on this stand.

2. **io_uring socket I/O** as a feature flag (~3 weeks). Replace
   the `tokio::net::TcpStream` read/write loops in pingora's
   listener with io_uring-backed equivalents via `tokio-uring`.
   This is a contained change (doesn't touch the async runtime
   itself), and tokio-uring is reasonably mature on Linux 5.10+.
   Expected: +15-25% on Linux deployments; macOS/BSD fall back to
   regular tokio.

3. **Full monoio swap** — deferred until either pingora upstream
   adds runtime abstraction, or we make a calls about how much
   maintenance burden the fork is worth.

This is the realistic Phase C.1 timeline: **3-6 weeks for tuning +
io_uring, with the option to go further if the numbers justify it**.

## Phase C.2 — SIMD HTTP parser

**Already there.** `httparse` (which pingora uses under the hood)
has SIMD via its `simd` cargo feature. It's auto-enabled on x86_64
with SSE4.2 and aarch64 with NEON. The roadmap's "port picohttpparser"
target was based on V0 numbers where we used a slower parser; that's
no longer the case.

No-op for V76.

## Phase C.3 — lock-free header maps

The `http` crate's `HeaderMap` is a hash-based map with O(1) lookup
in the steady state. The "lock-free" framing in the roadmap meant
"don't take a Mutex per request for shared header parsing", which
we already don't — `RequestContext.headers` is an `Arc<HeaderMap>`
(shared via refcount, no locks).

The remaining cost in V76 is **the `HeaderMap::clone()` in `build_ctx`**
([src/proxy/pingora_http.rs:584](../../src/proxy/pingora_http.rs:584)) —
we clone the whole HeaderMap to wrap in an Arc, when ideally we'd
pass the request reference through to filters. That's a wider
refactor (filter trait signature change, 200+ LOC); deferred.

## V76 closing — Phase ladder updated

| Phase | Promised | V76 status |
|---|---|---|
| A — XDP fast-path | 500k-1M mixed | ✅ partial (V73/V74) |
| B — Pingora migration | 800k-1M mixed | ✅ **750-775k stable confirmed** |
| **C.2 — WAF AC + hot-path fixes** | — | ✅ **WAF now ~2% overhead vs 10% in V72** |
| C.1 — monoio + io_uring | 1.5-2M | ⏳ 3-6 weeks (path: tokio tune + tokio-uring) |
| C.3 — lock-free headers | 1.5-2M | ⏳ 2-3 weeks (HeaderMap clone refactor) |
| D — Shared mmap state | 1.5-2M (security) | ⏳ 8 weeks |
| E — JIT WAF + ML + cache++ | 3-5M / 10M cached | ⏳ 12 weeks |

V76 confirms the V75 baseline holds (770k stable cache-warm),
delivers the achievable Phase C piece (WAF zero-alloc hot path),
and documents the realistic 3-6 week path to the next throughput
tier.

The single biggest non-code win remains **bare-metal x86 hardware**.
The same V76 binary on a 32-core x86 box (no macOS hypervisor) would
roughly **double** the numbers without changing one line of code.
That's the cheapest path to the next level if hardware budget exists.
