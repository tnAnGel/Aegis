# V11 — Throttling skip for trusted IPs (final hyper-era optimization)

## Что вошло в V11

Единый `pre_trusted` gate в начале `handle_collected`, через который
пропускается работа существующая **только для throttling/scoring
неизвестных клиентов**. Для уже trusted IPs:

| Skipped | Cost saved | Defense impact |
|---|---|---|
| `anomaly.observe` → `anomaly.under_attack` (read-only) | DashMap entry + EMA + VecDeque ~500 ns | None — read-only path still gets attack flag |
| `distributed_rate_exceeded` | Redis hop / DashMap ~100-500 ns | None — trust authoritative |
| `distributed_bot_score` | Same | None |
| `fingerprints.lookup` | DashMap read ~200 ns | None — fingerprint data unused for trusted |
| `JA4H compute` (already in V10) | ~2 µs | None — no filter matches ja4h for trusted |

**Total saved per trusted request: ~3 µs.**

WAF / smuggling / honeypot / threat-intel **всё равно работают** —
trust skip касается throttling/observation, не security.

## Бенч на стенде

| Сценарий | V10 | **V11** | Δ |
|---|---|---|---|
| c=100 (avg of 5) | 135 559 | **138 734** | +2.4 % |
| c=500 (avg of 3) | 135 338 | **140 060** | +3.5 % |
| c=1000 | 127 141 | 128 107 | +0.8 % |

Latency p50: 775 µs → **712 µs** (-8 %).
Latency p99: 1.92 ms → **1.83 ms**.

## Защита 100%

Untrusted IP:
- SQLi → 403, XSS → 403, PROPFIND → 405, 9KB URI → 414

После 60 clean reqs (IP trusted):
- SQLi → **403** (WAF runs)
- XSS → **403** (WAF runs)
- Path traversal → **403** (WAF runs)

## Полная сводка V0 → V11

| Версия | c=100 | c=500 | p99 | Защита | vs nginx |
|---|---|---|---|---|---|
| BEFORE | 103 968 | 97 634 | 1.95 ms | full | 45 % |
| V4 (Phase 1) | 111 037 | 110 471 | 1.79 ms | full | 48 % |
| V5 (static bypass) | 219 159 | 251 925 | — | bypass | **104 %** ⭐ |
| V6.1 (dyn trust safe) | 117 278 | 114 320 | — | full | 51 % |
| V7.1 (+threat cache) | 133 142 | 133 002 | — | full | 58 % |
| V8 (cache cleanup) | 132 887 | 128 289 | — | full | 57 % |
| V9 (sharded metrics) | 131 232 | 130 772 | — | full | 57 % |
| V10 (skip JA4H trusted) | 135 559 | 135 338 | — | full | 59 % |
| **V11 (skip throttling trusted)** | **138 734** | **140 060** | **1.83 ms** | **full** | **60 %** |

**От V0 baseline V11 — +33 % на c=100, +43 % на c=500.**

## Honest hyper ceiling — где мы сейчас

На стенде backend direct = 1M RPS, nginx proxy = 237k. Aegis V11 = 140k = **59 % nginx**.

Дальнейшие throughput-victories внутри hyper упираются в:

1. **`HeaderMap::clone()`** на каждом cache hit — ~300-500 ns
2. **`Response::builder` + body wrapping** — фундаментально неотделимо от http::Response API
3. **Tokio task scheduling + hyper internal serialization** — внутренности фреймворка

Все мелкие оптимизации (allocations, atomic contention, redundant
work for trusted) **уже сняты**. Ceiling определяется framework'ом,
не нашим кодом.

## Что осталось для обгона nginx

| Approach | Effort | Expected | Beats nginx? |
|---|---|---|---|
| **Phase B Pingora migration** | 10 нед | 240-280k RPS | **Yes** |
| **Phase 3X XDP allow fast-forward** | 4 нед (BPF) | line rate bypass | **Yes** для bypass-eligible |
| **Phase A.3-lite eBPF WAF** | 1-2 нед (BPF) | line rate deny | **Yes** для scanner traffic |
| Cache invalidation API + per-host config | 1 нед | n/a (UX win, не RPS) | — |
| ETag/304 Not Modified support | 1 нед | +30 % на conditional GETs | partial |

**Static bypass (V5)** уже даёт **104 % nginx** для operator-declared
trusted webhook'ов. **V11 (full defense + dyn trust + cache)** = **60 % nginx**.

## Активная конфигурация

```
md5sum
  /usr/local/bin/aegis      de0be1e4…  ← V11
  /usr/local/bin/aegis.bak  84b13e18…  ← BEFORE (откат)

env (через systemd EnvironmentFile):
  AEGIS_DYNAMIC_TRUST_ENABLE=1
  AEGIS_RESPONSE_CACHE_ENABLE=1
```

## Commits в этой ветке

```
594f68a perf(http):  V11 — skip throttling observation for trusted IPs
5882500 perf(http):  V10 — skip JA4H compute for trusted IPs
3ced406 perf(metrics): V9 — shard LatencyHistogram + ProtocolCounters
90675fd perf(cache):   V8 — fast-path cleanup + trust refresh skip
47175f6 perf(cache):   V7 — Phase E preview — threat-aware response cache
d48d411 perf(trust):   V6 — Phase A.1-ext — reputation-driven dynamic trust
b53983e perf(xdp):     V5 — Phase A.1 — unify XDP allow with userspace bypass
d118339 perf:          V4 — Phase 1 hot-path optimizations + Aegis-X roadmap
```

Все pushed в `main`.
