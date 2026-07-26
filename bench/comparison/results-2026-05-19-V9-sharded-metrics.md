# V9 — Sharded LatencyHistogram + ProtocolCounters

## Что вошло в V9

**Per-CPU sharding для горячих метрик:**

- `LatencyHistogram` — был `Vec<AtomicU64>` 11 buckets + `count` + `sum_ms`.
  На каждый запрос 13 `fetch_add` ops на одних cache-lines = ~1.7 M
  contended atomics/s при 130k RPS.
- `ProtocolCounters` — был AtomicU64 per protocol (h1/h2/h3/other).
  100% h1 трафика контендят одну cache line.
- Оба перешли на `ShardedCounter` (cache-line-padded per-CPU slots).

## Бенч

| Сценарий | V8 | **V9** | Δ |
|---|---|---|---|
| c=100 | 132 887 | 131 232 | within noise |
| c=500 | 128 289 | 130 772 | within noise |
| c=1000 | 127 141 | 129 028 | within noise |

**V9 ≈ V8.** Sharding eliminates contention, но bench не показывает
выигрыш — значит current bottleneck **не** в этой работе.

## Чего стоит ожидать дальше — pre-built response template

Профиль cache-hit показывает доминирующий cost не в atomics, а в:

```rust
let mut resp = Response::builder()
    .status(cached.status)
    .body(Full::new(cached.body.clone()).map_err(...).boxed())
    .expect("cached response");
*resp.headers_mut() = cached.headers.clone();  // ← deep clone каждого header value
```

`HeaderMap::clone()` deep-clones ~30 header values per request. На 130k
RPS = ~4M alloc/s. Это **реальный** bottleneck.

**Pre-built template approach** (не реализовано — следующий шаг):
- Store `Bytes::from(serialized_headers) + Bytes::from(serialized_body)` в cache
- На hit: write directly to socket через custom AsyncWrite implementation
- Bypass `Response::builder` и `HeaderMap::clone` целиком
- Expected: 2-3× от current cache-hit speed → 250-400k RPS

Но это требует выхода из `http::Response<B>` API hyper'а, и по сути
является мини-pingora на уровне cache hits.

## Полная картина — wall reached

```
   V0 BEFORE       103 968 RPS   45%  nginx
   V1              109 044 RPS   47%
   V3              107 483 RPS   47%
   V4 (Phase 1)    111 037 RPS   48%
─────────────────────────── trust whitelist split ──────────
   V5 (static)     219 159 RPS   94%  ← полный bypass (operator-declared)
   V6.1 (dyn)      117 278 RPS   51%  ← full defense + dynamic trust
   V7.1 (+cache)   133 142 RPS   58%  ← +threat-aware cache
   V8 (+cleanup)   132 887 RPS   57%
   V9 (+sharding)  131 232 RPS   57%  ← hyper ceiling
─────────────────────────── nginx ─────────────────────────
                   ~230 000 RPS   100%
```

V5 (static bypass) обогнал nginx на c=500 уже давно — для оператор-
declared trusted webhooks.

V9 при full defense + cache + threat policy = **57 % nginx**.
Это honest hyper ceiling на этом железе.

## Что нужно чтобы обогнать nginx на full defense

| Approach | Effort | Expected RPS | Beats nginx? |
|---|---|---|---|
| Pre-built response template | 1 нед | 250-400k mixed | **Yes** ⭐ |
| Phase B Pingora migration | 10 нед | 240-280k mixed | Match-beat |
| Phase 3X XDP allow-fast-forward | 4 нед | line rate bypass | Yes for bypass-eligible |
| Phase A.3-lite eBPF WAF | 1 нед | line rate deny | Yes for cheap-deny |

**Самый быстрый путь к обгону для cached content:** pre-built template
(1 week, +90-200% throughput на cache hits).

## Активная конфигурация

```
md5sum
  /usr/local/bin/aegis      9c3c28aa…  ← V9
  /usr/local/bin/aegis.bak  84b13e18…  ← BEFORE
```

## История от BEFORE → V9

| Версия | c=100 | c=500 | Защита | vs nginx |
|---|---|---|---|---|
| BEFORE | 103 968 | 97 634 | full | 45 % |
| V4 (Phase 1) | 111 037 | 110 471 | full | 48 % |
| V5 (static bypass) | 219 159 | 251 925 | bypass-mode | **104 %** |
| V6.1 (dyn trust) | 117 278 | 114 320 | full | 51 % |
| V7.1 (+cache) | 133 142 | 133 002 | full | 58 % |
| V8 (+fastpath cleanup) | 132 887 | 128 289 | full | 57 % |
| **V9 (+sharded metrics)** | **131 232** | **130 772** | **full** | **57 %** |

**Прирост от V0→V9 (full defense):** c=100 +26%, c=500 +34%.
