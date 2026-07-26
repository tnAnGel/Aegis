# Метрики и телеметрия

Подсистема наблюдаемости AEGIS состоит из трёх независимых слоёв: персистентные timeseries-ринги для дашборд-графиков (`series_1m`/`series_1h`), эндпоинт `GET /metrics` в формате Prometheus со всеми счётчиками `aegis_*`, и потоковый экспорт каждого решения безопасности (`SecurityEvent`) — в structured-лог, в Prometheus-счётчики с ограниченной кардинальностью и в EventBridge (NDJSON по Unix-сокету для SIEM, опционально в схеме T-Pot/Sicherheitstacho). Документ описывает каждый слой ровно так, как он реализован в коде, с указанием путей к файлам.

> Смежные документы: журнал запросов — [24-request-log.md](24-request-log.md); многопроцессность и cross-worker-состояние — [06-workers.md](06-workers.md); XDP-счётчики в контексте fast-path — [13-xdp-ebpf.md](13-xdp-ebpf.md); GeoIP-агрегация — [20-geoip.md](20-geoip.md); арсенал и сценарии (счётчик sicherheitstacho_emits) — [21-arsenal-scenarios.md](21-arsenal-scenarios.md); админ-API целиком — [30-admin-api.md](30-admin-api.md); админ-панель — [29-admin-panel.md](29-admin-panel.md).

---

## 1. Обзор слоёв

| Слой | Источник | Назначение | Файл |
|------|----------|------------|------|
| Timeseries ринги | cluster-mmap счётчики, сэмпл раз в 60 с | Графики на дашборде (трафик/блоки за 1ч…90д) | `src/metrics/timeseries.rs` |
| Prometheus `/metrics` | `RuntimeMetrics` + cache + XDP + cluster | Скрейп Prometheus/Grafana, per-process + cluster | `src/metrics/mod.rs`, `src/proxy/pingora_admin.rs` |
| SecurityEvent | каждое решение фильтра | Один канонический shape на решение | `src/security_event.rs` |
| EventBridge | поток `SecurityEvent` | NDJSON по Unix-сокету для SIEM | `src/event_bridge.rs` |
| Sicherheitstacho | рендер `SecurityEvent` | T-Pot-совместимый NDJSON-формат | `src/sicherheitstacho.rs` |
| Шардированные счётчики | hot-path | per-CPU слоты без cache-line bouncing | `src/metrics/sharded.rs` |

Три слоя независимы: можно скрейпить `/metrics` без EventBridge, можно держать EventBridge без timeseries и т. д. Все три устойчивы к отсутствию (graceful degradation): неинициализированный store возвращает пустой ответ, выключенный bridge — no-op, XDP-счётчики рендерятся нулями.

---

## 2. Шардированные счётчики (фундамент hot-path)

Файл: `src/metrics/sharded.rs`.

Все горячие per-request счётчики обёрнуты в `ShardedCounter` — массив `AtomicU64`, по одному слоту на CPU, каждый слот выровнен на 64 байта (`#[repr(align(64))]` структура `Padded`), чтобы соседние слоты не делили cache line.

```rust
#[repr(align(64))]
struct Padded(AtomicU64);

pub struct ShardedCounter {
    shards: Box<[Padded]>,
}
```

- **Число шардов** — `num_shards()`: `std::thread::available_parallelism()` (один на CPU), при неудаче — `8`, всегда зажато в диапазон `[1, 64]`. Потолок 64 удерживает стоимость read-sum приемлемой даже на больших машинах.
- **`fetch_add(delta, order)`** — пишет в шард, привязанный к текущему потоку (`shard_idx`: round-robin-распределение по thread-local при первом доступе, дальше — один TLS-read без атомиков). Возвращает прежнее значение **одного шарда**, а не суммарное (сигнатура зеркалит `AtomicU64::fetch_add` для drop-in-совместимости).
- **`load(order)`** — суммирует все шарды. Линейно по числу шардов, вызывается редко (только на скрейпе `/metrics`).

Это означает: для получения корректного суммарного значения счётчика всегда используйте `load()`, не возвращаемое значение `fetch_add()`. API намеренно идентичен `AtomicU64`, поэтому hot-path в `http.rs` не меняется.

---

## 3. Prometheus `/metrics`

Эндпоинт `GET /metrics` отдаётся обоими data plane:

- **aegis-pingora** (основной): `src/proxy/pingora_admin.rs`, ветка `("GET", "/metrics")` (около строки 5374). Content-Type — `text/plain; version=0.0.4`.
- **aegis (hyper)**: `src/server.rs` (около строки 1322).

Эндпоинт **публичный** — авторизация не требуется: `src/admin_auth.rs` явно возвращает `("GET", "/metrics") => None` (метрики публичны), тогда как `GET /admin/api/metrics/series` требует роль `Read`.

### 3.1 Состав ответа (aegis-pingora)

В `pingora_admin.rs` тело собирается из четырёх блоков:

```rust
let mut m = self.metrics.render_prometheus();   // RuntimeMetrics
self.append_cache_stats(&mut m);                // aegis_cache_*
self.append_xdp_stats(&mut m);                  // aegis_xdp_*
self.append_cluster_stats(&mut m);              // aegis_cluster_*
```

> **Честная оговорка.** `SecurityEventEmitter::render_prometheus()` (счётчики `aegis_security_decisions_total` / `aegis_security_events_total`, см. §5.2) существует в коде, но **не** дописывается в тело `/metrics` ни в pingora-, ни в hyper-обработчике на момент написания документа. В сборку `/metrics` входят только `RuntimeMetrics` + cache + XDP + cluster. Эти security-счётчики доступны через `snapshot()`/`total()` для JSON-эндпоинтов админ-API. Аналогично в hyper-ветке `/metrics` дописывается только блок XDP.

### 3.2 Базовые счётчики `RuntimeMetrics::render_prometheus()`

Файл: `src/metrics/mod.rs`. Все — тип `counter`, per-process (значение одного воркера).

| Метрика | Тип | Что считает |
|---------|-----|-------------|
| `aegis_requests_total` | counter | Все входящие HTTP-запросы |
| `aegis_requests_denied` | counter | Отклонены filter-пайплайном |
| `aegis_requests_challenged` | counter | Отвечены челленджем |
| `aegis_upstream_2xx` | counter | Ответы апстрима 2xx |
| `aegis_upstream_4xx` | counter | Ответы апстрима 4xx |
| `aegis_upstream_5xx` | counter | Ответы апстрима 5xx |
| `aegis_upstream_errors` | counter | Ошибки соединения с апстримом |
| `aegis_cache_hits` | counter | Хиты threat-aware кэша из RAM |
| `aegis_cache_misses` | counter | Cache-eligible запросы, ушедшие в апстрим |

Метрики с лейблами (тоже counter):

| Метрика | Лейблы | Источник |
|---------|--------|----------|
| `aegis_domain_total` / `aegis_domain_denied` / `aegis_domain_challenged` | `host="…"` | DashMap `domain`, `observe_domain_outcome()` |
| `aegis_requests_by_protocol` | `protocol="h1\|h2\|h3\|other"` | `ProtocolCounters::record()` |
| `aegis_filter_blocks` / `aegis_filter_challenges` | `filter="…"` | DashMap `by_filter`, `observe_filter_block()`/`observe_filter_challenge()` |

> Кардинальность `host`/`filter`-лейблов ограничена набором реальных доменов и именами фильтров (не вводом атакующего). В лейблах экранируется `"` (через `.replace('"', "")` для host/filter).

### 3.3 Гистограмма латентности

`aegis_request_latency_ms` — тип `histogram`. Бакеты (в миллисекундах) заданы в `LATENCY_BUCKETS_MS`:

```rust
pub const LATENCY_BUCKETS_MS: &[u64] =
    &[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
```

Серии: `aegis_request_latency_ms_bucket{le="…"}` (включая `le="+Inf"`), `aegis_request_latency_ms_sum`, `aegis_request_latency_ms_count`.

Оптимизация hot-path: `observe(ms)` делает ровно **3** атомарных RMW (count, sum_ms и **один** бакет — первый, чей edge ≥ ms, через `partition_point`), вместо ~13 при инкременте всех бакетов. Prometheus требует кумулятивные `le=`-счётчики, поэтому `render_prometheus()` восстанавливает кумулятивную серию префиксной суммой на скрейпе — вывод байт-в-байт совпадает со схемой «все бакеты». Наблюдения с `ms` больше максимального edge учитываются только в `count`/`sum` (бакет `+Inf` использует `count`).

### 3.4 Cache-счётчики (`append_cache_stats`)

Источник — `self.cache.stats()` (см. `src/proxy/response_cache.rs`). Все counter:

| Метрика | Что считает |
|---------|-------------|
| `aegis_cache_stores` | Вставлено записей в кэш |
| `aegis_cache_evictions` | Выброшено (stale, LRU-давление, broadcast-purge) |
| `aegis_cache_skipped_high_threat` | Lookup-и принудительно в MISS по threat-aware политике |
| `aegis_cache_skipped_uncacheable` | Store-ы пропущены, т.к. ответ некэшируем по RFC 9111 |
| `aegis_cache_not_modified` | 304 Not Modified из закэшированных валидаторов |
| `aegis_cache_served_low` | Хиты, отданные low-threat клиентам (V98 tiered) |
| `aegis_cache_served_medium` | Хиты medium-threat в окне свежести TTL/2 |
| `aegis_cache_forced_miss_high` | Lookup-и в MISS по high-threat политике |

### 3.5 XDP-счётчики (`append_xdp_stats`)

Источник — `self.xdp.counters().unwrap_or_default()`. При выключенном XDP `NoopXdp.counters()` возвращает `Ok(default)` → все нули рендерятся всегда, дашборды можно скрейпить безусловно без branch-логики. Все counter:

| Метрика | Что считает |
|---------|-------------|
| `aegis_xdp_pass` | Пакеты, пропущенные XDP fast-path в userspace |
| `aegis_xdp_drop_deny` | Дропнуты по XDP deny-list |
| `aegis_xdp_drop_rate` | Дропнуты per-IP token bucket-ом XDP |
| `aegis_xdp_drop_allowonly` | Дропнуты в allow-only (whitelist) режиме |
| `aegis_xdp_drop_syn` | SYN-ы, дропнутые SYN-flood guard-ом |
| `aegis_xdp_drop_waf` | Дропнуты inline eBPF-WAF (Phase 3X, scanner-пути) |
| `aegis_xdp_fast_pass` | Пакеты по allow-list fast-path (минуя deny/rate/WAF) |

XDP-счётчики per-CPU под капотом и суммируются на чтении внутри `xdp::counters()`. Подробности fast-path — в [13-xdp-ebpf.md](13-xdp-ebpf.md).

### 3.6 Cluster-счётчики (`append_cluster_stats`)

Phase D: суммы по **всем** REUSEPORT-воркерам через shared-mmap-арену. В отличие от per-process `aegis_*` — любой воркер рендерит cluster-агрегат, дашбордам не нужно скрейпить каждый воркер и складывать.

Блок — no-op, если арена не подключилась (`crate::shared_state::global::enabled()` == false): Linux без `/dev/shm`, macOS dev-сборки, ограниченные контейнеры. Отсутствие строк `aegis_cluster_*` — индикатор arena-unavailable воркера.

| Метрика | Тип | Cluster-индекс (`cluster_idx`) |
|---------|-----|--------------------------------|
| `aegis_cluster_requests_total` | counter | `REQUESTS_TOTAL` (0) |
| `aegis_cluster_requests_denied` | counter | `REQUESTS_DENIED` (1) |
| `aegis_cluster_requests_challenged` | counter | `REQUESTS_CHALLENGED` (2) |
| `aegis_cluster_cache_hits` | counter | `CACHE_HITS` (3) |
| `aegis_cluster_cache_misses` | counter | `CACHE_MISSES` (4) |
| `aegis_cluster_upstream_2xx` | counter | `UPSTREAM_2XX` (5) |
| `aegis_cluster_upstream_4xx` | counter | `UPSTREAM_4XX` (6) |
| `aegis_cluster_upstream_5xx` | counter | `UPSTREAM_5XX` (7) |
| `aegis_cluster_compactions_total` | counter | `COMPACTIONS_TOTAL` (8) |
| `aegis_cluster_compactions_removed` | counter | `COMPACTIONS_REMOVED` (9) |
| `aegis_cluster_arena_bytes` | **gauge** | размер арены (`arena_size()`) |
| `aegis_cluster_arena_used_bytes` | **gauge** | занято в арене (`arena_used()`) |

Ординалы счётчиков определены в `src/shared_state/global.rs`, модуль `cluster_idx`. Они **стабильны между релизами** — операторы строят дашборды на этих индексах; новые счётчики только дописываются в конец, никогда не переупорядочиваются и не переиспользуются. Полный набор слотов: 0–12 заняты (выше + `RATE_LIMITED=10`, `TARPIT=11`, `RTBH=12`), `SLOTS=16` зарезервировано. Имя арены задаётся `AEGIS_SHARED_STATE_NAME` (по умолчанию `/aegis-state`), размер — `AEGIS_SHARED_STATE_SIZE_MB` (по умолчанию 4 МБ).

> Заметьте: `RATE_LIMITED`, `TARPIT`, `RTBH` существуют как cluster-слоты и используются timeseries-сэмплером (§4), но **отдельных** `aegis_cluster_rate_limited` / `…_tarpit` / `…_rtbh` строк `append_cluster_stats` не выводит.

### 3.7 Примеры PromQL

```promql
# доля заблокированных за 5 минут (cluster-агрегат)
sum(rate(aegis_cluster_requests_denied[5m]))
  / sum(rate(aegis_cluster_requests_total[5m]))

# p99-латентность (по гистограмме одного воркера)
histogram_quantile(0.99, rate(aegis_request_latency_ms_bucket[5m]))

# топ-фильтры по блокам
topk(10, sum by (filter)(rate(aegis_filter_blocks[5m])))

# объём XDP-дропов по причинам
sum by (__name__)({__name__=~"aegis_xdp_drop_.*"})
```

---

## 4. Timeseries ринги

Файл: `src/metrics/timeseries.rs`. Это персистентные fleet-wide графики для дашборда, не Prometheus.

### 4.1 Архитектура «один писатель»

Один `TimeSeriesStore` живёт в каждом REUSEPORT-воркере. Все воркеры **читают** из cluster-mmap (через `snapshot_cluster()`), но **пишет** только тот воркер, что держит advisory-lock `flock(LOCK_EX | LOCK_NB)` на `.sampler.lock`. Поскольку инкременты всех воркеров уже видны в cluster-mmap, единственный писатель захватывает весь флот — без двойного счёта. Остальные воркеры — read-only режим (`state == None`): `sample_once()` — no-op, `query()` читает файлы, написанные писателем.

Захват lock-а — при `TimeSeriesStore::new()` (`try_acquire_writer_lock`): кто первый успел `LOCK_EX | LOCK_NB`, тот писатель. `is_writer()` сообщает статус.

### 4.2 Сэмплинг

Сэмплер вызывается из background-тика: `src/proxy/pingora_background.rs` (около строки 463), `ts.sample_once()` срабатывает раз в 60 с (каждый 2-й 30-секундный тик, через xor-parity `ts_tick_parity`). Вызов безопасен на всех воркерах — на не-писателях это no-op.

`sample_once()` делает `snapshot_cluster()`, вычисляет дельты против предыдущего снимка (`wrapping_sub`), формирует `Point` и:
1. пишет в 1-минутный ринг `series_1m.bin`;
2. аккумулирует в текущий 1-часовой бакет; при смене UTC-часа (`current_hour_start`) флашит накопленный `Point` в `series_1h.bin` и обнуляет аккумулятор.

Если арена ещё не инициализирована (`snap.len() < cluster_idx::SLOTS`) — тик пропускается. Mutex poisoned — warning и пропуск, без паники.

### 4.3 Бинарный формат рингов

Каталог: `$AEGIS_METRICS_DIR` → `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics` (приоритет в `default_store_dir()`).

```text
series_1m.bin  — 1-минутное разрешение, 2880 записей (48 ч)
series_1h.bin  — 1-часовое   разрешение, 2160 записей (90 д)
.sampler.lock  — advisory flock писателя
```

| Константа | Значение |
|-----------|----------|
| `RING_1M_CAPACITY` | 2880 (48 ч) |
| `RING_1H_CAPACITY` | 2160 (90 д) |
| `MAX_RESPONSE_POINTS` | 300 |

Каждый файл — 16-байтовый версионированный заголовок + фиксированные 96-байтовые записи как кольцевой буфер.

**Заголовок `FileHeader` (16 байт):**

| Offset | Size | Поле | Значение |
|--------|------|------|----------|
| 0 | 8 | magic | `b"AEGISTS1"` |
| 8 | 4 | version | `1u32` LE |
| 12 | 4 | head | `u32` LE — индекс следующего слота для записи (mod capacity) |

При несовпадении magic/version или `head >= capacity` файл переинициализируется свежим заголовком (migration-safe tombstone — смена `FILE_MAGIC` форсирует пересоздание всех файлов).

**Запись `Point` (96 байт = 12 × u64 LE):** `t_unix`, `requests`, `denied`, `challenged`, `rate_limited`, `tarpit`, `rtbh`, `cache_hits`, `cache_misses`, `upstream_2xx`, `upstream_4xx`, `upstream_5xx`.

Все поля-счётчики — **дельты бакета** (приращения за интервал), а не нарастающие итоги. Источник дельт — cluster-индексы `REQUESTS_TOTAL`, `REQUESTS_DENIED`, `REQUESTS_CHALLENGED`, `RATE_LIMITED`, `TARPIT`, `RTBH`, `CACHE_HITS`, `CACHE_MISSES`, `UPSTREAM_2XX/4XX/5XX`.

**Производное поле `allow`** вычисляется на чтении (не хранится):

```rust
allow = max(0, requests − (denied + challenged + rate_limited + tarpit + rtbh))
```

Floor в ноль (`saturating_sub`) защищает от транзиентного перекоса счётчиков.

### 4.4 Downsampling и запрос

`query(range_secs)`:
- `range_secs <= 172_800` (≤ 48 ч) → 1-минутный ринг, `resolution = "1m"`;
- `range_secs > 172_800` → 1-часовой ринг, `resolution = "1h"`.

Читается нужное число последних записей (`read_recent`, хронологический порядок), фильтруется по `t_unix >= now − range_secs`, затем **downsampling** до ≤ `MAX_RESPONSE_POINTS` (300): записи группируются в ≤300 бинов, поля каждого бина суммируются (`add_to_accum`), `t_unix` бина — таймстемп первой записи. Если записей ≤ 300 — возвращаются как есть.

### 4.5 `GET /admin/api/metrics/series`

Обработчик: `api_metrics_series` в `src/proxy/pingora_admin.rs` (около строки 995). Требует роль `Read`.

Параметр `?range=` (case-insensitive, по умолчанию `24h`):

| Label | Секунд | Ринг |
|-------|--------|------|
| `1h` | 3 600 | 1m |
| `6h` | 21 600 | 1m |
| `24h` | 86 400 | 1m |
| `7d` | 604 800 | 1h |
| `30d` | 2 592 000 | 1h |
| `90d` | 7 776 000 | 1h |

Неизвестный label → `400` с `{"error": "unknown range …; use one of: 1h 6h 24h 7d 30d 90d"}`.

Ответ — JSON `SeriesResponse`:

```json
{
  "resolution": "1m",
  "points": [
    {
      "t_unix": 1733659200,
      "requests": 1240, "denied": 30, "challenged": 5,
      "rate_limited": 8, "tarpit": 2, "rtbh": 0,
      "allow": 1195,
      "cache_hits": 800, "cache_misses": 120,
      "upstream_2xx": 1100, "upstream_4xx": 25, "upstream_5xx": 3
    }
  ]
}
```

Когда store **не подключён** (оператор не вызвал `with_timeseries`), возвращается `200` с `{"resolution":"1m","points":[]}` — UI рисует «нет данных», а не падает. Ошибка сериализации/запроса → `500` с `{"error": …}`.

```bash
curl -s -H "x-admin-token: $TOKEN" \
  "http://127.0.0.1:8080/admin/api/metrics/series?range=24h" | jq .
```

---

## 5. SecurityEvent — канонический shape решения (V116)

Файл: `src/security_event.rs`.

До V116 каждый фильтр логировал решение в своём ad-hoc-виде. `SecurityEvent` — единый небольшой JSON-сериализуемый shape без high-cardinality полей (сырых IP в лейблах метрик нет — только в теле события).

### 5.1 Структура

```rust
pub enum DecisionKind { Allow, Challenge, Deny, Throttle, Observed }

pub struct SecurityEvent {
    pub action: DecisionKind,
    pub reason: &'static str,        // статическая строка → кардинальность ограничена
    pub request_id: String,
    pub host: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub risk_score: Option<u8>,      // 0..=255 от RiskEngine, None если не консультировался
    pub extra_reasons: Vec<&'static str>,
    pub waf_rule_id: Option<String>,
    pub ja4_prefix: Option<String>,  // обрезан до 12 символов (семейство JA4_a)
}
```

| `DecisionKind` | Семантика |
|----------------|-----------|
| `Allow` | Пропущено |
| `Challenge` | Отвечено челленджем |
| `Deny` | Заблокировано |
| `Throttle` | Притормозлено (rate-limit) |
| `Observed` | Match-but-don't-act — shadow-режим WAF (V109), observe-режим Risk Engine (V108): «заблокировал бы», но не блокировал |

Builder-методы: `.with_risk(score, extras)`, `.with_waf_rule(id)`, `.with_ja4(ja4)` (обрезает до 12 символов). `reason`-ы — `&'static str`, переиспользуемые по всему коду (V108 RiskEngine + V109 WAF severity + V110 UA/JA4 mismatch), что даёт ограниченную кардинальность (~30 различных значений).

### 5.2 `SecurityEventEmitter` — sink

`emit(&ev)` делает (метрики первыми — не должны падать на проблемах сериализации лога):
1. инкремент `total` (AtomicU64);
2. инкремент counter-а с ключом `(action, reason)` — DashMap, ключ `&'static str` ⇒ карта не может вырасти за пределы статического набора;
3. structured-лог одной строкой: `tracing::info!(target: "aegis::security_event", action, reason, request_id, host, client_ip, method, path, risk_score, waf_rule_id, ja4_prefix, "security_decision")`.

Оператор собирает этот target своим лог-аггрегатором.

`render_prometheus()` выдаёт (см. оговорку в §3.1 — в `/metrics` сейчас не вставляется):

| Метрика | Тип | Лейблы |
|---------|-----|--------|
| `aegis_security_decisions_total` | counter | `action="allow\|challenge\|deny\|throttle\|observed"`, `reason="…"` |
| `aegis_security_events_total` | counter | — (суммарно эмиссий с запуска) |

`reason` экранируется (`\\` и `"`) для строгости text-формата Prometheus. Для JSON-эндпоинтов админ-API есть `snapshot()` → `Vec<((DecisionKind, &'static str), u64)>` и `total()`.

Готовые дашборд-запросы (из docstring модуля):

```promql
sum(rate(aegis_security_decisions_total{action="deny"}[5m]))
topk(10, sum by (reason)(rate(aegis_security_decisions_total[5m])))
```

---

## 6. EventBridge — NDJSON по Unix-сокету для SIEM (V127)

Файл: `src/event_bridge.rs`.

Оператор подключает SIEM / лог-аггрегаторы (Wazuh, Elasticsearch, Loki, Splunk, Vector, FluentBit) к одному эндпоинту, который эмитит один JSON-объект на каждое решение безопасности. `SecurityEvent` (V116) — данные; EventBridge (V127) — транспорт.

### 6.1 Свойства

- **Unix-сокет**: по умолчанию путь из `AEGIS_EVENT_SOCKET` (в коде нет жёстко зашитого fallback — `new(socket_path)` принимает `Option<PathBuf>`; в докстринге упомянут типовой `/var/run/aegis-events.sock`). Нет сетевой экспозиции, ACL по правам файла. Подписка через `nc -U` / `socat` / unix-socket-reader SIEM-а. На `spawn()` сокет создаётся с правами `0600` (оператор chmod/chown-ит под свой SIEM).
- **NDJSON broadcast**: каждый подключённый подписчик получает каждое событие. Новые подключения начинают «с чистого листа» (без реплея истории).
- **Lossy bounded queue на подписчика**: `SUBSCRIBER_CHANNEL_CAP = 1024` событий headroom. Если медленный подписчик не успевает — `try_send` дропает событие для него (drop > block), прокси никогда не блокируется. AEGIS — прокси, который эмитит, а не logging-система.
- **Best-effort**: если сокет недоступен / `socket_path = None` — `emit()` дёшев и no-op (`enabled()` == false).

Hot-path-стоимость: один mpsc `try_send` на событие, sub-µs когда подписчиков нет. JSON сериализуется **один раз** на вызов и шарится между подписчиками через `Arc` (клон — атомарный bump). Мёртвые подписчики (`Closed`) пруннятся на следующем `emit`. Диагностика — `subscriber_count()`.

### 6.2 Жизненный цикл

- `EventBridge::new(socket_path)` — конструирует disconnected; формат выбирается из env `AEGIS_EVENT_FORMAT` (см. §7).
- `spawn().await` — биндит Unix-сокет (предварительно best-effort удаляя устаревший от прошлого процесса), запускает accept-loop в фоне, ставит права 0600. No-op при `socket_path = None`. Идемпотентен.
- `emit(&ev)` — сериализует и рассылает (см. выше).

### 6.3 Native NDJSON (формат по умолчанию)

При `WireFormat::Native` событие сериализуется через `serde_json` прямо из `SecurityEvent` (см. §5.1) — поля как есть, по строке на событие:

```bash
# подписаться на поток
socat - UNIX-CONNECT:/var/run/aegis-events.sock
# или
nc -U /var/run/aegis-events.sock
```

```json
{"action":"deny","reason":"waf_critical","request_id":"…","host":"example.com","client_ip":"1.2.3.4","method":"GET","path":"/admin","risk_score":85,"extra_reasons":["…"],"waf_rule_id":"custom-001","ja4_prefix":"t13d1516h2_8"}
```

---

## 7. Sicherheitstacho / T-Pot формат (V185)

Файл: `src/sicherheitstacho.rs`.

T-Pot (telekom-security/tpotce) сводит десятки honeypot-ов к нормализованному формату «Sicherheitstacho» Telekom CERT. Приняв его, AEGIS получает interop со всем consumer-ом deception-экосистемы (ELK ingest-маппинги, threat-feed-аггрегаторы, публичный дашборд Sicherheitstacho).

### 7.1 Включение

```bash
# переключить схему NDJSON без изменения кода
AEGIS_EVENT_FORMAT=sicherheitstacho   # синоним: tpot
```

Выбор в `EventBridge::new`: `Some("sicherheitstacho") | Some("tpot")` → `WireFormat::Sicherheitstacho`, иначе `WireFormat::Native`. Программно — `.with_format(...)`.

### 7.2 Маппинг и схема

`render_sicherheitstacho(ev)` (в `event_bridge.rs`) транслирует `DecisionKind` в `Category`:

| `DecisionKind` | `Category` |
|----------------|-----------|
| `Deny` | `Block` (`"block"`) |
| `Challenge` | `Challenge` (`"challenge"`) |
| `Throttle` | `Waf` (`"waf"`) |
| `Allow` / `Observed` | `Waf` (`"waf"`) |

(`Category::Honeypot` / `Tarpit` определены в enum, но текущий маппинг из `SecurityEvent` их не выбирает.) `tags` = `extra_reasons` + `reason`. `transport="TCP"`, `service="aegis-waf"`, `dst_port=443`, `src_port=0`, `country`/`asn`/`user_agent` — `None`.

Модуль рендерит JSON **вручную** (без serde-зависимости — мал, чтобы оставаться drop-in для EventBridge), с корректным экранированием (`"`, `\`, `\n`, `\r`, `\t`, управляющие < 0x20 → `\uXXXX`) и собственным минималистичным ISO-8601 UTC-рендерером таймстемпа (алгоритм Hinnant, без chrono/jiff).

```json
{"@timestamp":"2026-05-22T12:34:56.000Z","type":"Aegis","src_ip":"203.0.113.7","src_port":0,"dst_port":443,"transport":"TCP","service":"aegis-waf","category":"block","tags":["sqlmap","waf_critical"],"request":{"method":"POST","host":"evil.test","path":"/phpmyadmin/index.php"}}
```

### 7.3 Счётчик объёма экспорта (арсенал)

При формате Sicherheitstacho каждый `emit` бампает (если привязан) `sicherheitstacho_counter` — `Arc<ShardedCounter>`, указывающий на шард арсенала `sicherheitstacho_emits`. Так панель Defence Arsenal (`/admin/api/arsenal` → `sicherheitstacho.emits`) отражает реальный объём экспорта в T-Pot-схеме. Привязка — `.with_sicherheitstacho_counter(...)`, вызывается из бинаря, когда есть и EventBridge, и `ArsenalState`. При `None` (нет арсенала) — счётчик не бампается. См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

---

## 8. Дашборд-панели и связанные эндпоинты

Графики строятся фронтендом (см. [29-admin-panel.md](29-admin-panel.md)) поверх данных из:

| Эндпоинт | Источник данных | Назначение |
|----------|-----------------|------------|
| `GET /admin/api/metrics/series?range=` | timeseries ринги (§4) | Графики трафика/блоков 1ч…90д |
| `GET /metrics` | Prometheus (§3) | Внешний скрейп |
| `GET /admin/api/geo/top` | `RuntimeMetrics::top_countries(20)` | World map / Top Countries |
| `GET /admin/api/geoip/status` | `geoip::resolve_country_db_path` | Статус GeoIP-БД |
| (телеметрия) `api_telemetry_status` | env | Статус EventBridge/формата/ClamAV |

### 8.1 Geo-агрегация (V239/V242)

`observe_country(cc, denied, challenged)` тallies запрос по ISO-коду страны на ingress — **только** если GeoIP-БД сконфигурирована (на дефолтном `NoopGeoIp` lookup — почти бесплатный `None`, hot-path-стоимости на деплоях без GeoIP нет). Счётчики — переиспользуемый `DomainCounter` (total/denied/challenged), per-worker под SO_REUSEPORT.

`GET /admin/api/geo/top` → `api_geo_top` отдаёт `[{country, total, denied}]` (до 20). При отсутствии GeoIP-БД resolve возвращает `None`, ничего не tallies — массив пуст, карта рендерится gracefully пустой.

`top_countries(n)` (V242): когда geo-персистентность включена (`with_geo_persistence(dir)`, по умолчанию `/var/lib/aegis/geo`), результат мержит шарды **всех** воркеров (свой — из live in-memory, чужие — `merge_all_shards_excluding`, чтобы не дублировать), поэтому он стабилен независимо от того, какой воркер ответил. Без персистентности — per-worker in-memory slice (репрезентативная выборка для top-N, не billing-accurate). Шард-флаш — каждый ~30-секундный тик (`flush_geo_shard()`). Реализация шардов — `src/metrics/geo_shard.rs`. Подробнее — [20-geoip.md](20-geoip.md).

### 8.2 Телеметрия-статус

`api_telemetry_status` (`/admin/api/...`) отдаёт состояние EventBridge для панели:

```json
{
  "event_bridge": {
    "format": "native",
    "format_options": ["native", "sicherheitstacho", "tpot"],
    "socket_path": "/var/run/aegis-events.sock"
  },
  "clamav": { "enabled": false, "addr": null, "env_var": "AEGIS_CLAMAV_ADDR (host:port)" },
  "audit_log_path": "…"
}
```

---

## 9. Cross-worker и многопроцессность

Под SO_REUSEPORT работает `aegis-pingora@0..N` (см. [06-workers.md](06-workers.md)). Резюме поведения метрик:

| Класс | Видимость |
|-------|-----------|
| `RuntimeMetrics` (`aegis_*` без `cluster_`) | per-process — значение одного воркера |
| `aegis_cluster_*` | весь флот (cluster-mmap, любой воркер рендерит агрегат) |
| timeseries ринги | весь флот (single-writer сэмплит cluster-mmap) |
| `by_country` / geo-top | per-worker, либо merged-all-shards при `with_geo_persistence` |
| SecurityEvent / EventBridge | per-process (каждый воркер свой sink/сокет — но `AEGIS_EVENT_SOCKET` один путь; биндит первый, `spawn` идемпотентен) |

Для cross-worker-агрегации полагайтесь на `aegis_cluster_*` (Prometheus) и timeseries-ринги; per-process `aegis_*` суммируйте сами, если скрейпите воркеры по отдельности.

---

## 10. Переменные окружения (сводка)

| Env | По умолчанию | Слой | Эффект |
|-----|--------------|------|--------|
| `AEGIS_METRICS_DIR` | `$AEGIS_HOME/metrics` → `/var/lib/aegis/metrics` | timeseries | Каталог рингов |
| `AEGIS_HOME` | `/var/lib/aegis` | timeseries/geo | База путей |
| `AEGIS_EVENT_SOCKET` | (нет) | EventBridge | Путь Unix-сокета; не задан → bridge no-op |
| `AEGIS_EVENT_FORMAT` | `native` | EventBridge | `sicherheitstacho`/`tpot` → T-Pot-схема |
| `AEGIS_SHARED_STATE_NAME` | `/aegis-state` | cluster | Имя shared-mmap-арены |
| `AEGIS_SHARED_STATE_SIZE_MB` | `4` | cluster | Размер арены |
| `AEGIS_CLAMAV_ADDR` | (нет) | телеметрия-статус | host:port ClamAV (для панели) |

---

## 11. Эксплуатационные заметки

- **`/metrics` публичен** — не кладите за admin-auth; при необходимости ограничьте сетевым ACL/firewall, а не токеном.
- **Security-счётчики не в `/metrics`** — `aegis_security_decisions_total` собирается эмиттером, но не вшит в `/metrics`; для дашбордов по решениям используйте либо structured-лог `target=aegis::security_event` через лог-аггрегатор, либо EventBridge-поток, либо JSON-снапшоты админ-API.
- **Timeseries-данные переживают рестарт** — ринги на диске; заголовок версионирован, при смене формата файлы пересоздаются автоматически.
- **При отсутствии writer-lock** воркер всё равно отвечает на `/admin/api/metrics/series` (читает файлы писателя) — graceful.
- **GeoIP-метрики бесплатны без GeoIP** — `observe_country` ничего не делает на `NoopGeoIp`.
- **EventBridge не теряет прокси** — медленный SIEM-подписчик теряет события (lossy), но не тормозит трафик.
- **Cluster-счётчики отсутствуют на не-Linux/без `/dev/shm`** — отсутствие `aegis_cluster_*` строк нормально для dev-сборок.
