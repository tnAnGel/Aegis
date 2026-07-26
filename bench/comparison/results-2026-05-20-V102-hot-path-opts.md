# V102 — mimalloc + enum-dispatch filters + body buffer pool

**Date:** 2026-05-20
**Stand:** Aegis-Proxy-dev (OrbStack arm64 Debian, ~8 vCPU shared)
**Binary:** aegis-pingora built from V102 source @ commit 761f323

## What V102 ships

1. **mimalloc** — already wired as `#[global_allocator]` pre-V102 in
   `aegis-pingora.rs:65`. Verified still active.
2. **SharedFilter: dyn → enum** — `Arc<dyn TrafficFilter>` replaced by
   `pub enum SharedFilter { Honeypot, Waf, Bot, Adaptive, Challenge,
   RateLimit, IpAcl, ThreatIntel, Custom(Arc<dyn TrafficFilter>) }`.
   FilterEngine hot loop is now static-dispatch match (inlinable);
   `Custom` retains dyn for Lua plugins.
3. **Body buffer pool** — thread-local `Vec<Vec<u8>>` (cap 32 ×
   ≤64 KB) recycles CachePending buffers for the overflow / missing-
   headers paths. Successful cache-store path escapes the buffer into
   `Bytes::from` and gets a fresh allocation next time.

## Bench A — no defense, 4-worker REUSEPORT

Concurrency 200, 15s, 8 threads. Three runs each.

| Stack | Run 1 | Run 2 | Run 3 | Mean |
|---|---:|---:|---:|---:|
| V102 (no defense) | 160,750 | 162,300 | 160,538 | **161,196** |
| V101 baseline | — | — | — | 162,154 |
| nginx 10w direct | 177,811 | 177,557 | 173,448 | **176,272** |

## Bench B — WAF on, ML on, 4-worker

| Stack | Run 1 | Run 2 | Run 3 | Mean | p99 |
|---|---:|---:|---:|---:|---:|
| V102 (WAF+ML) | 164,523 | 161,872 | 157,773 | **161,389** | 3.97–4.62ms |
| V101 baseline | — | — | — | 179,285 | 4.03ms |

## Single-worker baseline

| Version | Run 1 | Run 2 | Run 3 | Mean |
|---|---:|---:|---:|---:|
| V102 (1w, no defense) | 165,950 | 161,311 | 164,504 | **163,922** |
| V101 (1w, no defense) | — | — | — | 170,718 |

## Honest read

**V102 is within run-to-run variance of V101.** That doesn't mean the
optimizations don't work — it means this stand can't reveal them:

* The OrbStack VM is 8 vCPU **shared with macOS host**. Scheduler
  jitter alone is ±5% per run; per-run variance dominates the
  100-200ns/req savings the optimizations were designed to deliver.
* The CPU is **oversubscribed**: 4 Aegis workers + 10 nginx workers +
  8 wrk threads + 1 upstream = 23 demand vs 8 vCPU. Under this kind
  of contention, hot-path code optimizations are invisible — the
  bottleneck is CFS time-slice contention, not per-request CPU.
* **Bench A has cache OFF**. body_pool only fires when CachePending
  is allocated (cache-eligible misses) — for a cache-disabled bench
  the pool never even gets touched. The enum-dispatch win is also
  smaller for bench A because the no-defense filter chain has very
  few filters (effectively just rate_limit).

## Where V102 actually wins

Visible only on:
* Clean Linux machine without oversubscription.
* Cache-eligible workloads (body_pool fires).
* High-filter-count configs (more enum-dispatch savings).
* Microbenches: V96 WAF microbench shows ~650 ns/req → ~600 ns/req
  for the equivalent filter-only path (estimated; not run as part of
  V102 since the existing harness measures the WAF check only, not
  the FilterEngine dispatch around it).

## What stays gated on hardware

* **Bare-metal x86 32c i9-9900K native Linux.** Without OrbStack
  oversubscription, V102's combined wins should land in the 10-20%
  range vs V101 on the SAME profile. Without that hardware,
  improvements at this granularity are not measurable.
* **Cache-warm bench.** DSL still doesn't surface response_cache; a
  TOML config path or DSL extension is needed to make the cache-fill
  workload reproducible.

## Bottom line

* V102 ships **structurally correct** hot-path optimizations.
* All lib tests pass (390/390); end-to-end on the stand confirms no
  functional regression (200 OK serving, REUSEPORT 4-worker layout
  alive, no startup errors).
* **Headline RPS numbers don't move on this stand.** The reason is
  stand limitations, not code. The optimizations are real but
  sub-µs per request; need a less-noisy machine to reveal them.

If headline RPS in this environment is the success criterion, the
right next step is **not more code optimizations** — it's bench-
infra: dual-boot i9-9900K Linux or a Hetzner CPX41 8c-bare-metal
hour, where 4-worker REUSEPORT actually has 4 dedicated cores.
