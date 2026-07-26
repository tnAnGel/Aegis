# Performance and tuning

**Languages:** **English** · [Русский](../ru/27-performance-tuning.md) · [中文](../zh/27-performance-tuning.md)

How AEGIS is built for specific hardware, how it lays itself out under load, and which levers the operator and the developer have. Every statement here is tied to real code — `Cargo.toml` (`[profile.release]`), `install.sh` (`aegis_rustflags`/`build_and_install`), `src/h2_budget.rs`, `src/proxy/response_cache.rs`, `src/bin/aegis-pingora.rs` — while the report on methodology and measurements lives in [`PERFORMANCE.md`](../en/reference/performance.md).

> Honest framing (see [`PERFORMANCE.md`](../en/reference/performance.md) and [`28-benchmarking.md`](./28-benchmarking.md)): AEGIS is **not** faster than bare nginx in plain forwarding — the gap is ~10–13% (CPU-isolated, 8 cores), and that is proven. The real value of AEGIS is the cache (HIT ≈1.7× versus nginx forwarding) and L7 protection, which is an order of magnitude cheaper than nginx+ModSecurity (≈18× within-VM). This document describes how to extract what is claimed, not how to out-run a proxy on raw speed.

---

## 1. The build: where it is compiled and why that matters

`install.sh` compiles AEGIS **on the deployment server itself**, on every `--update`. This is a key architectural decision for performance: since the binary is built and run on the same machine, it can safely be tuned for the actual CPU with no risk of `SIGILL` on somebody else's hardware.

Two defaults follow from this:

1. **`target-cpu=native`** — compile for all the features of this exact CPU.
2. **A fast parallel build profile** (thin LTO + 16 codegen units + incremental) — so that a routine `--update` does not bake a single rustc on a single core for minutes.

Plus an optional mode for cutting a release: **`AEGIS_BUILD_OPT=max`** — a maximally optimised (but slow, almost single-threaded) binary.

---

## 2. The build profile `[profile.release]`

The default release profile is set in `Cargo.toml`, `[profile.release]`:

```toml
[profile.release]
lto = "thin"
codegen-units = 16
incremental = true
panic = "abort"
strip = "symbols"
opt-level = 3
debug = false
```

| Field | Value | Why (per the comment block in `Cargo.toml`) |
|---|---|---|
| `lto` | `"thin"` | Parallel cross-crate optimisation. Thin LTO parallelises (vs `fat` = one sequential pass over the whole program). The hot path crosses 5–7 crate boundaries (pingora, hyper, http, tokio + 80+ of our modules) — LTO gives a throughput win. |
| `codegen-units` | `16` | Lets LLVM codegen run across all the server's cores. This is what "parallel build" means. |
| `incremental` | `true` | A small `--update` recompiles part of a crate rather than all of it. Sharply cuts routine update time. |
| `panic` | `"abort"` | Removes unwind tables from every function prologue (icache savings on the hot Allow path), shrinks the binary. Safe: the proxy already treats any panic as a worker crash — pingora restarts the worker, SO_REUSEPORT keeps the listener alive. |
| `strip` | `"symbols"` | Cuts ~30% off the binary size. Symbols can be recovered when needed from the split-debug `.dwp`. |
| `opt-level` | `3` | Full optimisation. |
| `debug` | `false` | No debug information in production. |

> **Historical caveat (honestly).** Before V246 the default was `lto="fat"` + `codegen-units=1` — the fastest *binary*, but a **completely single-threaded build**: one rustc pinned one core for minutes on every `install.sh --update` while the other cores idled. Since install.sh rebuilds directly on the server on every update, the default was switched to the fast parallel profile. The runtime cost versus `fat`+`cgu=1` is a few per cent (measured: AEGIS+WAF still beats bare nginx on a protected workload).

### Companion profiles

```toml
[profile.profiling]   # for perf/flamegraph — release + symbols
inherits = "release"
lto = "thin"
strip = false
debug = 1

[profile.bench]       # microbenchmarks under production settings
lto = "fat"
codegen-units = 1
panic = "abort"
opt-level = 3
debug = true
```

- `[profile.profiling]` mirrors release but keeps the symbol table and line numbers so that `perf`/flamegraph can resolve function names. Never shipped — only for performance investigations.
- `[profile.bench]` uses `fat` LTO + `cgu=1` so that microbenchmarks reflect real production performance rather than the noise of an unoptimised debug build.

---

## 3. `AEGIS_BUILD_OPT=max` — the maximally optimised binary

`build_and_install()` in `install.sh` (lines ~497–509) implements an opt-in switch. By default the fast parallel profile from `Cargo.toml` is used; with `AEGIS_BUILD_OPT=max`, environment variables that override the profile are exported:

```bash
if [ "${AEGIS_BUILD_OPT:-}" = "max" ]; then
    export CARGO_PROFILE_RELEASE_LTO=fat
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    export CARGO_PROFILE_RELEASE_INCREMENTAL=false
    log "AEGIS_BUILD_OPT=max → fat LTO + codegen-units=1 (slow build, max-perf binary)"
else
    log "build profile: fast parallel (thin LTO, codegen-units=16, incremental) — set AEGIS_BUILD_OPT=max for max-perf"
fi
```

| Mode | LTO | codegen-units | incremental | When |
|---|---|---|---|---|
| default | `thin` | `16` | `true` | Routine `install.sh --update` on the server. The build saturates all cores and recompiles only what changed. |
| `AEGIS_BUILD_OPT=max` | `fat` | `1` | `false` | Cutting an actual release. A slow, almost single-threaded build, but the absolutely fastest binary. **Not for routine `--update`.** |

```bash
# Maximally optimised binary:
sudo AEGIS_BUILD_OPT=max bash install.sh --update
```

The mechanism is Cargo's standard `CARGO_PROFILE_RELEASE_*` env overrides, so it layers on top of `[profile.release]` without editing `Cargo.toml`.

---

## 4. `target-cpu=native` and `aegis_rustflags`

The codegen target is set by the variable `AEGIS_TARGET_CPU` (default `native`) and assembled into RUSTFLAGS by the function `aegis_rustflags()` (`install.sh`, lines ~419–435):

```bash
: "${AEGIS_TARGET_CPU:=native}"
aegis_rustflags() {
    local flags=""
    if [ "$AEGIS_TARGET_CPU" != "generic" ] && [ -n "$AEGIS_TARGET_CPU" ]; then
        flags="-C target-cpu=$AEGIS_TARGET_CPU"
    fi
    if command -v mold >/dev/null 2>&1; then
        flags="${flags:+$flags }-C link-arg=-fuse-ld=mold"
    fi
    if [ -n "${RUSTFLAGS:-}" ]; then
        flags="${flags:+$flags }$RUSTFLAGS"
    fi
    printf '%s' "$flags"
}
```

| `AEGIS_TARGET_CPU` | Behaviour |
|---|---|
| `native` (default) | Optimal for **this** machine. Enables all CPU features. |
| `generic` | Portable; for build-once-deploy-many. `-C target-cpu` is not added at all. |
| `neoverse-n1` / `x86-64-v3` / … | Pin a specific microarchitecture. |

**Why `native` is safe.** The binary is built directly on the deployment host and only ever runs there, so targeting the build CPU is both safe and optimal. On modern ARM (Graviton2+, Ampere, Apple, Neoverse) `native` enables **ARMv8.1 LSE atomics**: single-instruction `ldadd`/`swpal` instead of LL/SC loops (`__aarch64_ldadd8`). This speeds up **all** atomics — Arc, DashMap, tokio, mimalloc — on the hot path. On modern x86 it is AVX2/BMI. objdump of the V237 binary: 5775 `ldadd` / 414 `ldaddal` versus 10 `ldaxr` (see [`PERFORMANCE.md`](../en/reference/performance.md), V237).

> **Important — features are NOT hard-coded.** The committed `.cargo/config.toml` deliberately hard-codes nothing; RUSTFLAGS from `aegis_rustflags()` overrides it. Any pre-set `RUSTFLAGS` from the environment is **preserved and appended after our** flags. This gives portability to old ARM/x86 with no risk of `SIGILL` (you build for your own hardware).

Applied in both build functions (`build_aegis_hyper`, `build_aegis_pingora`):

```bash
RUSTFLAGS="$(aegis_rustflags)" "$cargo" build --release --bin aegis-pingora --features "$features"
```

Reproduce by hand (as in [`PERFORMANCE.md`](../en/reference/performance.md)):

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --features pingora
```

> **PGO (profile-guided optimization) — opt-in, not integrated into install.sh.** PGO measurably gives +10% on forwarding and +3–5% on TLS-steady, but does **not** help on bandwidth-bound paths (large bodies). Available as a separate RUSTFLAGS pipeline (`perf-tier1`); integration into `install.sh` is a follow-up (PGO adds ~10 min to the build). The claimed +10% was profiled in a single-process topology and was **not carried over** to a production REUSEPORT layout — see the caveat in [`PERFORMANCE.md`](../en/reference/performance.md).

---

## 5. The mold linker

`mold` is a multi-threaded linker; final linking of the large `aegis-pingora` binary is otherwise single-threaded (GNU ld) and takes a noticeable part of every build. It is used **best-effort**: if mold is absent, there is a silent fallback to the default linker and the build does not fail.

Installing mold happens in two places in `install.sh` (on a fresh install and in `build_and_install` for `--update`):

```bash
case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mold ... ;;
    dnf) dnf install -y -q mold ... ;;
    apk) apk add --no-cache mold ... ;;
esac
```

If `command -v mold` finds the binary, `aegis_rustflags()` adds `-C link-arg=-fuse-ld=mold` (see §4). Otherwise the flag is not added. Mold affects **build speed only**, not runtime performance.

---

## 6. SO_REUSEPORT and the number of workers

The AEGIS production layout is **N separate SO_REUSEPORT processes** `aegis-pingora@0..N-1`, following a **thread-per-core** scheme: N workers × 1 thread, each pinned 1:1 to a CPU via systemd `CPUAffinity`. Details of cross-worker state are in [`06-workers.md`](./06-workers.md).

### Choosing the number of workers — `resolve_workers()`

`install.sh` (lines ~156–191):

```bash
: "${AEGIS_WORKERS:=auto}"   # auto = nproc | explicit N
```

Resolution order:

1. If `--workers N` is given explicitly on the CLI — it **always** wins.
2. Otherwise, if `AEGIS_WORKERS=auto` and `/var/lib/aegis/topology.json` exists — the `{"workers":...}` value written by the admin panel's Workers page (via `PUT /admin/api/topology`) is used.
3. Otherwise `auto` → `nproc` workers, `AEGIS_THREADS_PER_WORKER=1`.

In every case `AEGIS_THREADS_PER_WORKER=1` (thread-per-core).

```bash
sudo bash install.sh --workers 8     # override the number of REUSEPORT instances
```

| Source | Priority |
|---|---|
| `--workers N` (CLI) | highest |
| `topology.json` (panel, `PUT /admin/api/topology`) | medium (only when `auto`) |
| `nproc` | default |

### Why thread-per-core rather than work-stealing

`resolve_workers()` fixes the N×1 layout because the pingora runtime is NoSteal: a layout of N workers × 1 thread, pinned 1:1 to CPUs. The former 4×4 scheme let the kernel scheduler float threads across all CPUs and tore up L1/L2 locality. This matches the nginx/envoy/HAProxy pattern. Measurements confirmed it: **work-stealing does NOT help** — an A/B showed that NoSteal consistently wins; the default is right ([`PERFORMANCE.md`](../en/reference/performance.md), items 3/4).

### REUSEPORT runtime flags

Launched via `AEGIS_PINGORA_REUSEPORT=1` (the systemd template `aegis-pingora@.service`). In `src/bin/aegis-pingora.rs`:

- SO_REUSEPORT is opt-in via `AEGIS_PINGORA_REUSEPORT=1` (comment, line ~38).
- `build_downstream_sock_opt(reuseport)` sets `sock_opt.so_reuseport = Some(true)` when reuseport is enabled (line ~583).
- Each instance binds **the same** ports; the kernel hashes incoming connections across workers.

> **LEVER 3 — a shared REUSEPORT ticket key.** The production layout is N separate processes, and without a shared TLS session-ticket key each worker would issue its own tickets → cross-worker resumption would break (a connection landing on another worker does a full handshake). The fix: all REUSEPORT workers **share one ticket key** (`src/bin/aegis-pingora.rs`, lines ~611+). This, not the crypto, is the main lever on the TLS path in a correct layout (see [`08-tls-certificates.md`](./08-tls-certificates.md) and [`PERFORMANCE.md`](../en/reference/performance.md), item 4).

---

## 7. Response cache (threat-aware response cache)

`src/proxy/response_cache.rs` is the response cache that gives AEGIS its real lead (HIT ≈1.7× versus nginx forwarding, +20–47% versus nginx with `proxy_cache`; [`PERFORMANCE.md`](../en/reference/performance.md), TL;DR). A full description of the behaviour is not in [`14-rate-limiting.md`](./14-rate-limiting.md); the cache is described here and in [`04-configuration.md`](./04-configuration.md).

### Threat-aware: not an ordinary proxy_cache

- **Low-threat/trusted clients** (those for whom `ctx.is_trusted` holds, or everyone in the absence of a threat signal) get a cache HIT.
- **High-threat clients** (recently denied/challenged IPs) are forced into a cache MISS — the response is fetched fresh and passes the entire filter pipeline. This blocks cache poisoning through header/query smuggling.

Protective properties (from the module's doc comment):
- The WAF still runs for high-threat IPs on every request — the cache is a performance shortcut, **not** a bypass of protection.
- Entries store only the upstream response; cacheable responses are by definition deterministic for the cache key.
- Responses with `Set-Cookie` are never cached (otherwise sessions would cross-contaminate).
- `Cache-Control: private | no-store` is respected.

### Storage — an allocation-free hot path

- Single-process LRU, keyed by `(Method, Host, Path)`. There is **no** shared state between processes — each worker keeps its own cache (zero coordination: no Redis hop, no lock contention). The cost of duplication per process is bounded by `max_entries × max_body_bytes`.
- **The body is stored as `Bytes` → zero-copy on HIT**: an Arc is simply cloned, no memcpy.
- **`CACHE_SHARDS = 32`** independent LRU shards, each with its own `RwLock` — parallel lookups on different keys do not contend (`response_cache.rs`, line 61). Per-shard capacity = `(max_entries / 32).max(4)`.

### Configuration — `ResponseCacheConfig`

`src/config.rs`, `pub struct ResponseCacheConfig`:

| Field | Default | Purpose |
|---|---|---|
| `enabled` | `false` | Enable the cache. |
| `max_entries` | 10,000 | Max records in the LRU. Memory ≈ `max_entries × max_body_bytes` in the worst case. |
| `default_ttl_secs` | 60 | Fallback TTL when the upstream gave no `Cache-Control: max-age`/`s-maxage`. |
| `max_body_bytes` | 1 MiB | Hard ceiling on the size of a cacheable body. Anything larger is streamed past the cache. |
| `status_ttl_secs` | `{}` | Per-status TTL overrides, for example `{200 = 300, 404 = 10, 301 = 3600}`. A common pattern: cache 404s briefly (10s) to damp scanner bursts without hammering the upstream. |
| `stale_if_error_secs` | 0 (off) | Stale-if-error window: on a 5xx/upstream failure, if a recently expired record exists within this window, the stale copy is served with `Warning: 110`. Keeps the site afloat during backend outages. |

> **Cache depth is the main lever.** Hit ratio matters more than any percentage of forwarding ([`PERFORMANCE.md`](../en/reference/performance.md), item 5). Tune `max_entries`, `default_ttl_secs`, `status_ttl_secs` for your traffic profile; enable `stale_if_error_secs` for resilience against backend failures.

---

## 8. H2 budget (control-frame budgets)

`src/h2_budget.rs` (V182) implements Tempesta-style per-connection HTTP/2 control-frame budgets, applied **before** a frame reaches the h2 state machine. This is both a performance and a protective measure: it damps classes of attacks that exploit the cheapness of a specific control frame (Rapid Reset CVE-2023-44487, CONTINUATION flood CVE-2024-27316, Settings/Ping flood). The protective side in detail — [`14-rate-limiting.md`](./14-rate-limiting.md) and [`21-arsenal-scenarios.md`](./21-arsenal-scenarios.md).

### Default budgets — `Budget::default_for`

Token bucket per `(conn_id, FrameKind)`. On an empty bucket — `Verdict::Reject` (the caller closes the stream/connection). No timers — refill is computed lazily on `consume`.

| Frame (`FrameKind`) | `burst` | `refill_per_s` | Attack class |
|---|---|---|---|
| `RstStream` | 50 | 20 | Rapid Reset |
| `Settings` | 10 | 2 | Settings flood |
| `Ping` | 30 | 10 | Ping flood |
| `Priority` | 100 | 50 | Priority churn |
| `Goaway` | 3 | 1 | should be rare |
| `Continuation` | 50 | 20 | CONTINUATION flood |

### Implementation — cheap on the hot path

- The map key is `(u64 conn_id, FrameKind)`, both **connection-local** (sequential IDs + a small enum) and not attacker-controlled → **`FxHashMap`** is used instead of SipHash: SipHash's DoS resistance is wasted effort here, and FxHash is materially faster on small integer keys (`h2_budget.rs`, lines 36–41, 116–118).
- `Bucket::consume` refills lazily: `tokens = (tokens + elapsed × refill_per_s).min(burst)`, then `-= 1.0` when ≥1.0 (lines 102–112).
- `drop_conn(conn_id)` discards all state for a closed connection; `gc(idle)` is background cleanup of idle buckets (lines 151–163).

### Operator tuning

Budgets are overridden via `H2BudgetTracker::with_override(kind, Budget { burst, refill_per_s })` (lines 131–134) — a DSL/config facade. The same budget logic is factored into a tiny state machine that **the XDP fast path can mirror** for kernel-side enforcement: one source of truth for the thresholds, accounting in two places (see [`13-xdp-ebpf.md`](./13-xdp-ebpf.md)). The arsenal runner exposes `h2_budget` metrics (`allows`/`rejects`/`tracked_conns`) via `src/proxy/pingora_admin.rs` (see [`25-metrics-telemetry.md`](./25-metrics-telemetry.md) and [`30-admin-api.md`](./30-admin-api.md)).

> **Caveat (honestly).** In `src/bin/aegis-pingora.rs` (line ~1724) there is a comment that the in-tree `h2_guard`/`h2_budget` modules cannot fully control h2 frames on the public listener through the pingora stack itself — accounting is done at the hyper/h2 level (`src/proxy/h2_guard.rs`, V111) and in this budget machine, while XDP mirroring is a separate path. Do not treat this as end-to-end kernel enforcement by default.

---

## 9. Tuning under load — the hot path and de-allocations

The V236→V237 audit (56 agents, 14 zones, adversarial verification of "is this really executed per request in plain mode") closed most of "our" overhead. Implemented safe optimisations (see [`PERFORMANCE.md`](../en/reference/performance.md), "What was optimised"):

| Optimisation | Gist |
|---|---|
| LSE atomics | `target-cpu=native` → single-instruction `ldadd`/`swpal` (see §4). |
| Less `clock_gettime` | 8×/request → 1× (the filter engine was reading the clock on every filter). |
| Lazy JA4H | The SHA-256 fingerprint is computed on first read, not on every request. |
| Cluster-counter batching | per-worker buffer, flush once per 128; in-place RefCell batch (no copy of the whole array). |
| read-lock + zero-alloc fast path | in per-domain metrics; single-bucket latency histogram (3 atomics instead of 13). |
| borrow-or-own host keys | no `to_ascii_lowercase` allocation when the host is already lower-case. |
| empty-feed fast path | threat intel (`AtomicUsize` sentinel) and honeypot (skip `canonical_path` when no packs are active). |
| alloc-free Cookie parsing | on the no-cookie path. |

Related compiler-dependent levers from `Cargo.toml`:

- **`mimalloc`** (`Cargo.toml`, line 143) — the default allocator, cheaper than the system one on hot alloc/free.
- **`coarsetime`** — a coarse-resolution `Instant` (~10ms tick, ~3ns load) for background aggregators (dynamic_trust aging windows, scorer, anomaly EMA), where a 1–10ms skew is invisible. Precise `Instant::now()` is kept for latency histograms and security-sensitive token expiry.
- **`rustc-hash` (FxHash)** — for internal maps whose keys are **not** attacker-controlled (literals, rule IDs, status codes, frame kinds). Adversary-controlled maps (IP, host, JA4) keep AHash/SipHash for DoS resistance.
- **`memchr`** — SIMD byte search (NEON on aarch64, AVX2 on x86_64) in WAF canonicalisation and per-field substring scans instead of scalar `str::contains`.
- **`tracing` with `release_max_level_info`** — `debug!`/`trace!` are compiled out in release: 19 call sites on the hot path stop paying ~20–40 ns each (~50–95 MB/s of dispatch recovered at 100k+ RPS).

### The V237 profile — where the remaining CPU goes

After V236/V237, **our code is <2% self-time** (mostly the HeaderMap clone). The remaining ~25% is framework + kernel, outside our code:

| What | % self-time | Whose |
|---|---|---|
| kernel TCP stack | ~12% | the kernel — unavoidable |
| clock reads (`cntvct`+`clock_gettime`) | ~6.8% | Pingora + tokio I/O/timer |
| Pingora HTTP machinery | ~7% | the framework |
| connection-pool LRU + hash | ~3% | the framework (upstream reuse) |
| our code | <2% | the HeaderMap clone |

> **Dead ends (do NOT dig — verified, see [`PERFORMANCE.md`](../en/reference/performance.md)):**
> - **io_uring data plane** — measured ~24% slower than nginx on loopback (no DMA/zero-copy win; the gap is in the filter/routing layer, not in I/O). NO-GO.
> - **Gating the HeaderMap clone (1.3%)** — rejected: even the safest design produced 2 critical WAF-bypass races. For a security proxy, 1.3% of throughput is not worth the risk of a WAF bypass. The unconditional clone stays.
> - **The forwarding microbenchmark in principle** — the ceiling here is the async framework + kernel TCP, at most 2–3% from micro-optimisations.

---

## 10. Practical operator checklist

```bash
# 1. Release build for this hardware (default — native + parallel profile):
sudo bash install.sh --update

# 2. Maximally optimised binary (for cutting a release, not for routine work):
sudo AEGIS_BUILD_OPT=max bash install.sh --update

# 3. Portable binary (build-once-deploy-many):
sudo AEGIS_TARGET_CPU=generic bash install.sh --update

# 4. Number of workers matched to the core count (or auto = nproc):
sudo bash install.sh --workers 8
```

| Lever | Where to turn it | Effect |
|---|---|---|
| Build profile | `AEGIS_BUILD_OPT=max` | +a few % of runtime at the price of a long build |
| Codegen target | `AEGIS_TARGET_CPU` (`native`/`generic`/microarch) | LSE atomics / AVX2 vs portability |
| Linker | mold (best-effort) | build speed only |
| Workers | `--workers` / the panel / `nproc` | thread-per-core, 1:1 pinning to CPUs |
| Cache | `ResponseCacheConfig` (`max_entries`, `*_ttl_secs`, `stale_if_error_secs`) | hit ratio — the main throughput lever |
| H2 budget | `H2BudgetTracker::with_override` / DSL | resilience to control-frame floods |
| TLS resumption | shared REUSEPORT ticket key (automatic) | cross-worker resumption |

---

## See also

- [`PERFORMANCE.md`](../en/reference/performance.md) — methodology, real numbers, dead ends (the primary source for this document).
- [`28-benchmarking.md`](./28-benchmarking.md) — how to reproduce the measurements, benchmark-lane caveats.
- [`06-workers.md`](./06-workers.md) — SO_REUSEPORT, cross-worker state.
- [`05-requirements.md`](./05-requirements.md) — hardware requirements.
- [`03-installation.md`](./03-installation.md) — install.sh in full.
- [`08-tls-certificates.md`](./08-tls-certificates.md) — the TLS path, ticket keys.
- [`13-xdp-ebpf.md`](./13-xdp-ebpf.md) — mirroring the h2 budget into the kernel.
- [`14-rate-limiting.md`](./14-rate-limiting.md), [`21-arsenal-scenarios.md`](./21-arsenal-scenarios.md) — the protective side of the h2 budget.
- [`25-metrics-telemetry.md`](./25-metrics-telemetry.md) — `h2_budget` metrics, profiling.
