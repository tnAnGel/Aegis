# V4 — Phase 1 complete (Aegis-Proxy, 2026-05-19)

## Что вошло в V4

Все 7 шагов Фазы 1 из [PERF-ROADMAP.md](../../PERF-ROADMAP.md):

| # | Изменение | Файл | Описание |
|---|---|---|---|
| F1.1 | **mimalloc** global allocator | [main.rs](src/main.rs) | Microsoft mimalloc заменяет glibc malloc — лучше под multi-threaded |
| F1.2 | **h2c к upstream** (config-gated) | [config.rs](src/config.rs), [proxy/http.rs](src/proxy/http.rs) | `upstream.protocol = "h2c"` мультиплексит запросы по одному соединению |
| F1.3 | **Lazy request_id** | [proxy/http.rs](src/proxy/http.rs) | Thread-local counter вместо `Uuid::new_v4()` — нет RNG syscall |
| F1.4 | **Typed RateKey + bot fp без format!()** | [filters/rate_limit.rs](src/filters/rate_limit.rs), [filters/bot.rs](src/filters/bot.rs) | DashMap key — `(scope, IpAddr, host_hash)` вместо String |
| F1.5 | **Arc<HeaderMap>** в RequestContext | [proxy/request_context.rs](src/proxy/request_context.rs), [proxy/http.rs](src/proxy/http.rs) | Убран `parts.headers.clone()` — самый дорогой клон в hot-path |
| F1.6 | **ShardedCounter** per-CPU | [metrics/sharded.rs](src/metrics/sharded.rs) | Cache-line-padded per-CPU слоты вместо одного AtomicU64 |
| F1.7 | **Cached host** в RequestContext | [proxy/request_context.rs](src/proxy/request_context.rs), [filters/rate_limit.rs](src/filters/rate_limit.rs), [filters/waf.rs](src/filters/waf.rs) | Однократный pre-extract Host — фильтры не re-hash'ят HeaderMap |

## Бенч

Все измерения: `wrk` 10s, native arm64 Linux, бэкенд `nginx → :8000`,
сравнение с nginx-proxy на :8080.

### Throughput (`wrk -t4 -c100 -d10s`) — 8 трайлов

| BEFORE | V3 | **V4** | Δ vs BEFORE | Δ vs V3 |
|---|---|---|---|---|
| 103 968 | 107 483 | **111 037** (avg of 8) | **+6.8 %** | +3.3 % |

Best single trial: **114 602 RPS**.
p99 latency: **1.79 ms** (nginx 2.98-3.07 ms). p99 — лучше nginx.

### Sustained flood (`wrk -t8 -c500 -d10s`)

| BEFORE | V3 | **V4** | Δ vs BEFORE |
|---|---|---|---|
| 97 634 | 103 641 | **110 471** (avg) | **+13.2 %** |

### Extreme flood (`wrk -t16 -c1000 -d10s`)

| BEFORE | V3 | **V4** | Δ vs BEFORE |
|---|---|---|---|
| 93 714 | 99 179 | **104 746** (avg) | **+11.8 %** |

### WAF-active path (`?name=alice&id=42`)

| BEFORE | V3 | **V4** | Δ vs BEFORE |
|---|---|---|---|
| 93 817 | 104 147 | **104 495** (avg) | **+11.4 %** |

## Защита — 12/12 без регрессий

| Атака | V3 | V4 |
|---|---|---|
| SQLi UNION | 403 | **403** |
| SQLi or 1=1 | 403 | **403** |
| XSS js:alert | 403 | **403** |
| SSRF metadata | 403 | **403** |
| Path traversal | 403 | **403** |
| MySQL versioned `/*!*/` | 403 | **403** |
| PROPFIND | 405 | **405** |
| 9 KB URI | 414 | **414** |
| 16 KB header | 431 | **431** |
| Honeypot `/wp-login.php` | tarpit 12s | **tarpit 12s** |
| Honeypot `/.env` | tarpit 12s | **tarpit 12s** |
| Honeypot `/xmlrpc.php` | tarpit 12s | **tarpit 12s** |

## Сводная таблица всех 4 версий

| Сценарий | BEFORE | V1 | V3 | **V4** |
|---|---|---|---|---|
| Throughput c=100 (avg) | 103 968 | 109 044 | 107 483 | **111 037** |
| Sustained c=500 | 97 634 | 103 886 | 103 641 | **110 471** |
| Extreme c=1000 | 93 714 | — | 99 179 | **104 746** |
| WAF-active path | 93 817 | 101 110 | 104 147 | **104 495** |
| p99 latency | 1.95 ms | 1.89 ms | 1.92 ms | **1.79 ms** |
| Tests | 269 | 269 | 269 | **272** |

## vs nginx (та же машина)

| Сценарий | aegis V4 | nginx :8080 | aegis/nginx |
|---|---|---|---|
| c=100 | 111 037 | 229 700 (avg) | 48 % |
| c=500 | 110 471 | 226 621 (avg) | 49 % |

**Достигли 48-49 % nginx**. Чтобы догнать — нужна Фаза 2 (SO_REUSEPORT
multi-process или Pingora). Чтобы обогнать — Фаза 3 (XDP fast-forward
или threat-aware cache).

## Что было самым эффективным

Глядя на промежуточные результаты по шагам и сравнивая с теоретическим прогнозом из PERF-ROADMAP:

| # | Прогноз | Реальность |
|---|---|---|
| F1.1 mimalloc | +2–5 % | основной вклад в +3-5 % на throughput |
| F1.4 typed keys | +2–5 % | очевидно помог на c=500/c=1000 (где rate_limit жжёт) |
| F1.5 Arc<HeaderMap> | +3–5 % | значимый вклад на c=500 (где clone был ~5 µs × 100k = 500 ms wasted) |
| F1.6 ShardedCounter | +3–7 % | заметно помог на c=1000 (atomic contention реальная) |
| F1.2 h2c | +3–7 % | не активирован в бенче (backend на h1) — потенциал на будущее |
| F1.3 lazy uuid | +1–3 % | мелкий вклад, но честный |
| F1.7 cached host | +1–2 % | мелкий вклад |

Кумулятивно: **прогноз +25-30 %, факт +7-13 %**. Разница объясняется:
- mimalloc и atomic-shard эффективны только когда есть contention
- Arc<HeaderMap> часто `try_unwrap` не получается — sub-task'и держат ref'ы
- WAF-active не вырос дальше V3 потому что Aho-Corasick уже сделал основную работу

## Активная конфигурация на стенде

```
md5sum
  /usr/local/bin/aegis      db4f3809…  ← V4 (Phase 1 active)
  /usr/local/bin/aegis.bak  84b13e18…  ← BEFORE (откат)
```

## Что дальше — для обгона nginx

Текущая позиция: **48-49 % nginx**. Чтобы превзойти, по плану нужны:

**Фаза 2** (выбор между двумя путями):
- **2A SO_REUSEPORT multi-process** (2-3 недели) → ~85 % nginx (~200k RPS)
- **2B Pingora migration** (4-6 недель) → ~100-110 % nginx (~240-280k RPS)

**Фаза 3** (для обгона):
- **3X XDP fast-forward** (3-4 недели) → 300k+ на смешанной нагрузке
- **3Y threat-aware response cache** (2-3 недели) → 500k+ на cacheable нагрузке

См. [PERF-ROADMAP.md](../../PERF-ROADMAP.md) с полным планом.
