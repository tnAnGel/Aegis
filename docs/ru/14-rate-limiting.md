# Ограничение запросов (rate limiting)

AEGIS ограничивает интенсивность запросов на нескольких уровнях: per-IP (с
коллапсом IPv6 в `/64`), по подсети `/24`/`/16` (для IPv4) и `/48`/`/32` (для
IPv6), per-URI, а под боевой нагрузкой дополнительно — распределённо через
Redis (атомарный токен-бакет на Lua) и на уровне HTTP/2-фреймов (Tempesta-style
бюджеты против Rapid Reset и родственных атак). Все локальные лимиты — это
token-bucket с ленивым refill; глобальный flood на L3/L4 этим не закрывается
(см. оговорки ниже и BGP RTBH, [XDP/eBPF](./13-xdp-ebpf.md)).

Источники: [`src/filters/rate_limit.rs`](../../src/filters/rate_limit.rs),
[`src/h2_budget.rs`](../../src/h2_budget.rs),
[`src/state/reputation.rs`](../../src/state/reputation.rs),
[`src/config.rs`](../../src/config.rs),
[`src/domain_policy.rs`](../../src/domain_policy.rs).

---

## 1. Обзор уровней

AEGIS реализует ограничение запросов в трёх независимых местах кода — это важно
понимать, потому что они конфигурируются и работают по-разному:

| Уровень | Модуль | Где считается | Назначение |
|---|---|---|---|
| Локальный per-IP / per-subnet / per-URI | [`src/filters/rate_limit.rs`](../../src/filters/rate_limit.rs) | В памяти воркера (`DashMap`) | Основной L7 rate-limit на горячем пути фильтр-чейна |
| Распределённый per-(host,IP) | [`src/state/reputation.rs`](../../src/state/reputation.rs) (вызывается из [`src/proxy/http.rs`](../../src/proxy/http.rs)) | В Redis под Lua-EVAL | Согласованный лимит между несколькими воркерами/инстансами |
| HTTP/2 frame-budgets per-connection | [`src/h2_budget.rs`](../../src/h2_budget.rs) | В памяти (RwLock + FxHashMap) | Защита от Rapid Reset / Settings / Ping / CONTINUATION flood |

> 🟡 Это **разные** механизмы, а не один с тремя бэкендами. Локальный
> `RateLimitFilter` (DashMap) и распределённый Redis-бакет существуют
> параллельно. Redis-путь сейчас задействован преимущественно в legacy
> hyper-обработчике ([`src/proxy/http.rs`](../../src/proxy/http.rs)), см. §5.

---

## 2. Локальный token-bucket (`RateLimitFilter`)

### 2.1 Алгоритм

Каждый ключ держит структуру `Bucket { tokens: f64, last_refill: Instant }`
([`rate_limit.rs:93`](../../src/filters/rate_limit.rs#L93)). Refill вычисляется
лениво в момент проверки, без таймеров
([`rate_limit.rs:432`](../../src/filters/rate_limit.rs#L432)):

```rust
let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
entry.tokens = (entry.tokens + elapsed * rate).min(burst);
entry.last_refill = now;
if entry.tokens >= 1.0 { entry.tokens -= 1.0; true } else { false }
```

- `rate` — токены в секунду (steady-state RPS).
- `burst` — ёмкость бакета (максимальный мгновенный всплеск).
- За один запрос списывается ровно 1 токен. Когда токенов < 1 — запрос
  отклоняется.

### 2.2 Ключ бакета (`RateKey`)

Ключ — это фиксированная по размеру структура (не строка), чтобы избегать
аллокаций `format!()` на каждом запросе
([`rate_limit.rs:19`](../../src/filters/rate_limit.rs#L19)):

```rust
struct RateKey { scope: u8, ip: IpAddr, host_hash: u64 }
```

- `scope`: `0` = per-IP, `1` = `/24`(`/48`), `2` = `/16`(`/32`).
- `host_hash`: 64-битный хеш Host-заголовка (`DefaultHasher`), чтобы лимиты
  считались раздельно по доменам. Вероятность коллизии хостов ~1/2⁶⁴ —
  игнорируется как незначимая ([`rate_limit.rs:24`](../../src/filters/rate_limit.rs#L24)).

### 2.3 IPv6: коллапс в `/64` для per-IP

🔴 Раньше per-IP бакет для IPv6 ключевался по полному `/128`, и атакующий мог
ротировать адреса внутри своего же `/64` (SLAAC раздаёт целый `/64` на хост),
полностью обходя per-IP лимит — это находка **H3** в
SECURITY-AUDIT. Исправлено:
per-IP ключ для IPv6 усекается до `/64`
([`IPV6_PER_IP_PREFIX = 64`, rate_limit.rs:38](../../src/filters/rate_limit.rs#L38),
[`RateKey::ip`, rate_limit.rs:41](../../src/filters/rate_limit.rs#L41)). IPv4
по-прежнему ключуется по полному `/32` (один хост = один адрес).

Поведение зафиксировано тестами `ipv6_per_ip_key_collapses_same_64` и
`ipv6_rotation_within_64_shares_quota`
([rate_limit.rs:855](../../src/filters/rate_limit.rs#L855)).

### 2.4 Subnet buckets (по подсети)

Опционально (`subnet_buckets`, по умолчанию **выключено** ⚠️) AEGIS дополнительно
списывает токены с бакетов подсети. Логика в `check()`
([rate_limit.rs:576](../../src/filters/rate_limit.rs#L576)): сначала per-IP, затем
`/24`, затем `/16`. Любой пустой бакет даёт `Deny 429`.

| scope | IPv4 префикс | IPv6 префикс | rate/burst |
|---|---|---|---|
| per-IP | `/32` | `/64` | `rate`, `burst` |
| `subnet24` | `/24` | `/48` | `rate × subnet_24_multiplier`, `burst × …` |
| `subnet16` | `/16` | `/32` | `rate × subnet_16_multiplier`, `burst × …` |

Усечение IPv6 делает `v6_prefix()`
([rate_limit.rs:486](../../src/filters/rate_limit.rs#L486)): `/48` для `subnet24` и
`/32` для `subnet16` ([rate_limit.rs:61](../../src/filters/rate_limit.rs#L61),
[L75](../../src/filters/rate_limit.rs#L75)).

Мультипликаторы (`max(1)`, по умолчанию `8` и `64`) расширяют бюджет подсети так,
чтобы легитимные NAT/ISP-пулы не выглядели как один «крикливый» клиент, но
ботнет из тысяч `/32` внутри одного `/24` всё равно упирался в общий бюджет
подсети. Поведение зафиксировано тестами `subnet_bucket_blocks_botnet_within_24`
и `..._16` ([rate_limit.rs:709](../../src/filters/rate_limit.rs#L709)).

> 🟠 **Honesty caveat:** `subnet_buckets` по умолчанию `false`. Без явного
> включения IPv6-evasion через смежные `/64` в рамках одного `/48` не
> покрывается subnet-логикой (per-IP уже коллапсит `/64`, но межсетевой бюджет
> неактивен). Это часть находки **H3** в
> SECURITY-AUDIT. Для IPv6-сред
> рекомендация аудита: `subnet_buckets = true`.

### 2.5 Per-URI бюджеты (URI budgets)

Отдельный набор лимитов на конкретные пути (`uri_budgets`). Матчер
([`UriMatcher`, rate_limit.rs:177](../../src/filters/rate_limit.rs#L177)) поддерживает
только два вида паттернов:

- **Exact** — точный путь, например `/login`.
- **Prefix** — паттерн с завершающим `*`, например `/api/*`.

Матчинг — **first-match-wins**, поэтому специфичные пути нужно перечислять до
catch-all. Сравнение идёт только по пути; query-string отрезается
(`ctx.path.split('?')`, [rate_limit.rs:542](../../src/filters/rate_limit.rs#L542)).

URI-бакет списывается **первым**, ещё до per-IP бакета
([rate_limit.rs:543](../../src/filters/rate_limit.rs#L543)), но per-IP/subnet бакеты
тоже списываются — чтобы клиент не мог «прыгать» между matched-URI и сжечь весь
бюджет соединения. Ключ URI-бакета — строка
`uri|{matcher.key}|{host}|{client_ip}`
([rate_limit.rs:549](../../src/filters/rate_limit.rs#L549)); здесь оставлена строка
(не `RateKey`), т.к. идентичность паттерна — естественный ключ, а путь редкий.

Превышение URI-бюджета → `Deny { status: 429, reason: "uri rate limit exceeded (<pattern>)" }`.

### 2.6 Hot-URI трекинг

Опциональный детектор «горячих» путей (`hot_uri_rps_threshold`, по умолчанию
`0` = выключен, [config.rs:735](../../src/config.rs#L735)). Это **только
наблюдатель — он сам никогда не блокирует**
([config.rs:717](../../src/config.rs#L717)).

`HotUriTracker` ([rate_limit.rs:209](../../src/filters/rate_limit.rs#L209)) держит
на каждый путь `VecDeque<Instant>` из таймстемпов запросов за скользящее окно
`1s`. Когда число хитов за секунду достигает порога — пишется
`tracing::warn!("hot URI detected")`
([rate_limit.rs:558](../../src/filters/rate_limit.rs#L558)). `VecDeque` выбран,
чтобы истечение старых таймстемпов было O(1) `pop_front()` вместо O(n)
`Vec::remove(0)` — это часть находки **H2** в
SECURITY-AUDIT.

Топ горячих путей доступен через `hot_uris(limit)`
([rate_limit.rs:372](../../src/filters/rate_limit.rs#L372)) и отдаётся в админ-панель
(`/admin/hot_uris`, см. Admin API).

### 2.7 Динамическое доверие — обход лимита

В самом начале `check()` доверенные клиенты пропускаются мимо rate-limit
([rate_limit.rs:514](../../src/filters/rate_limit.rs#L514)):

```rust
if ctx.is_trusted { return FilterAction::Allow; }
```

Доверие зарабатывается чистым трафиком (см.
[`src/filters/dynamic_trust.rs`](../../src/filters/dynamic_trust.rs) и
Arsenal/сценарии). Throttling существует для защиты
от всплесков от неизвестных клиентов; доверенные клиенты уже «оплатили» аудит.

### 2.8 Ограничение памяти и очистка

Карты состояния ограничены жёсткими лимитами, иначе ротация адресов/URI
превращает rate-limit в вектор memory-exhaustion (находка **H2**,
SECURITY-AUDIT):

| Карта | Лимит | Константа |
|---|---|---|
| per-IP/subnet `state` | `1 048 576` | [`MAX_STATE_ENTRIES`, rate_limit.rs:132](../../src/filters/rate_limit.rs#L132) |
| URI `uri_state` | `262 144` | [`MAX_URI_STATE_ENTRIES`, rate_limit.rs:135](../../src/filters/rate_limit.rs#L135) |

При достижении лимита вставка нового ключа сначала **вытесняет самую старую
запись** (LRU-ish по `last_refill`, [`evict_oldest_state`,
rate_limit.rs:405](../../src/filters/rate_limit.rs#L405)), зеркаля паттерн
`evict_lru` из `dynamic_trust.rs`. Оба `DashMap` шардированы на 128 шардов для
параллелизма (V230, [rate_limit.rs:335](../../src/filters/rate_limit.rs#L335)).

Дополнительно есть `cleanup_stale(now)`
([rate_limit.rs:474](../../src/filters/rate_limit.rs#L474)), удаляющий записи старше
`stale_after` (фиксировано `300s`, [rate_limit.rs:338](../../src/filters/rate_limit.rs#L338))
и чистящий hot-URI-карту.

> 🟠 **Honesty caveat (H2):** комментарий в коде прямо отмечает, что
> «deployed pingora path **never wires `cleanup_stale` into a background loop**»
> ([rate_limit.rs:124](../../src/filters/rate_limit.rs#L124)). Поэтому защита от
> разрастания карты в Pingora-пути держится на жёстком cap + eviction, а не на
> периодической очистке. В SECURITY-AUDIT
> H2 помечен как «чиню (+ интеграция)» — статус фиксов смотрите в самом аудите.

---

## 3. Конфигурация локального лимита

Структура `RateLimitConfig`
([config.rs:692](../../src/config.rs#L692)). В DSL/TOML это секция
`[filters.rate_limit]` (точную грамматику см. в
[Конфигурация](./04-configuration.md)).

| Поле | Тип | Default | Описание |
|---|---|---|---|
| `enabled` | bool | — | Config-time флаг. ⚠️ Сам `check()` на него **не** опирается (см. §6) |
| `requests_per_second` | u64 | — | Глобальный per-IP rate |
| `burst` | u64 | — | Глобальный per-IP burst |
| `subnet_buckets` | bool | `false` | Включить лимиты по `/24`(`/48`) и `/16`(`/32`) |
| `subnet_24_multiplier` | u64 | `8` ([config.rs:739](../../src/config.rs#L739)) | Множитель бюджета `/24`(`/48`) |
| `subnet_16_multiplier` | u64 | `64` ([config.rs:742](../../src/config.rs#L742)) | Множитель бюджета `/16`(`/32`) |
| `uri_budgets` | `Vec<UriBudget>` | `[]` | Per-URI лимиты (first-match-wins) |
| `hot_uri_rps_threshold` | u64 | `0` (выкл.) | Порог hits/sec для «hot URI» лога |

`UriBudget` ([config.rs:726](../../src/config.rs#L726)):

| Поле | Описание |
|---|---|
| `pattern` | Exact (`/login`) или prefix-glob (`/api/*`). Только по пути, query игнорируется |
| `requests_per_second` | rate этого бакета |
| `burst` | burst этого бакета |

### Пример (концептуально)

```toml
[filters.rate_limit]
enabled = true
requests_per_second = 20
burst = 40
subnet_buckets = true        # рекомендуется, особенно для IPv6
subnet_24_multiplier = 8
subnet_16_multiplier = 64
hot_uri_rps_threshold = 200  # только лог, не блок

[[filters.rate_limit.uri_budgets]]
pattern = "/login"           # exact: дорогой auth-эндпоинт
requests_per_second = 1
burst = 5

[[filters.rate_limit.uri_budgets]]
pattern = "/api/*"           # prefix-glob
requests_per_second = 10
burst = 20
```

> Точный синтаксис секций берите из [Конфигурация (DSL и TOML)](./04-configuration.md);
> сборка и переменные окружения — в [`install.sh`](../../install.sh) (см.
> [Установка и эксплуатация](./03-installation.md)).

---

## 4. Per-domain оверрайды

Лимиты выбираются по хосту в порядке приоритета (`check()`,
[rate_limit.rs:529](../../src/filters/rate_limit.rs#L529)):

1. **Runtime per-host overlay (V234)** — `domain_policy.rate_limit_for(host)`.
   Это override, выставляемый через админ-API
   (`PUT /admin/api/sites/<host>/policy`, см. Admin API),
   disk-backed и cross-worker. Работает даже для ops-managed сайтов, чьи `.conf`
   read-only ([domain_policy.rs:117](../../src/domain_policy.rs#L117),
   [domain_policy.rs:550](../../src/domain_policy.rs#L550)). При отсутствии
   оверрайдов это один relaxed atomic-load (empty-gate fast path).
2. **Статический `domain_limits`** — `limits_for_host(host)`
   ([rate_limit.rs:379](../../src/filters/rate_limit.rs#L379)):
   - точный матч хоста выигрывает;
   - ведущая точка в ключе (`.example.com`) работает как suffix-glob и матчит
     `api.example.com`, `www.example.com` — позволяет дать общий бакет на
     apex+поддомены.
3. **Глобальные** `requests_per_second` / `burst`.

`RateLimitOverride` ([domain_policy.rs:86](../../src/domain_policy.rs#L86)) хранит
`rps` и `burst` (оба `u64`, семантика per-IP, как у глобального фильтра).
Поведение overlay зафиксировано тестом
`domain_policy_overlay_overrides_global_per_host`
([rate_limit.rs:663](../../src/filters/rate_limit.rs#L663)). Подробнее —
Картография и per-domain политики.

---

## 5. Распределённый лимит через Redis

Это **отдельный** механизм от §2: атомарный токен-бакет, целиком исполняемый
внутри Redis как Lua-скрипт под `EVAL`
([`TOKEN_BUCKET_LUA`, reputation.rs:11](../../src/state/reputation.rs#L11)). Вся
арифметика refill/decrement происходит атомарно, поэтому конкурентные вызовы из
многих воркеров/инстансов не «перерасходуют» бюджет
([reputation.rs:83](../../src/state/reputation.rs#L83)).

- Ключ: `aegis:tb:{key}`, где `key = redis_tb_key(host, ip)` — фиксированный
  хеш-дайджест host+IP. 🔴 Раньше ключ был `{host}|{ip}`; поскольку Host
  полностью контролируется атакующим и может содержать `|`, подмена Host на
  каждый запрос минтила новый бакет и обходила лимитер. Исправлено в **V233**
  хешированием обеих компонент ([http.rs:932](../../src/proxy/http.rs#L932),
  [http.rs:2159](../../src/proxy/http.rs#L2159)).
- Ответ скрипта: `(allowed, value)`. При `allowed=1` value — остаток токенов
  (`BucketOutcome::Allowed { tokens_left }`); при `allowed=0` value — мс до
  следующей попытки (`Throttled { retry_after_ms }`), что используется для
  заголовка `Retry-After` ([reputation.rs:48](../../src/state/reputation.rs#L48)).
- TTL ключа выставляется автоматически:
  `max(1000, ceil(burst / max(rate,1) * 2000))` мс
  ([reputation.rs:26](../../src/state/reputation.rs#L26)).

### Fail-open

Если Redis недоступен или EVAL упал, путь **открывается (fail-open)** — backend
не должен падать из-за outage стораджа
([http.rs:950](../../src/proxy/http.rs#L950),
[`distributed_rate_exceeded`, http.rs:927](../../src/proxy/http.rs#L927)). Бакет
вообще не задействуется, когда стораж не сконфигурирован
(`storage.redis_url`, [config.rs:350](../../src/config.rs#L350); валидируется как
`redis://…`, [config.rs:1090](../../src/config.rs#L1090)).

> 🟠 **Honesty caveat:** распределённый Redis-бакет в текущем коде вызывается из
> **legacy hyper-обработчика** ([`src/proxy/http.rs`](../../src/proxy/http.rs)).
> Production data plane на Pingora использует локальный `RateLimitFilter` (§2);
> в Pingora-пути reason для 429 называется `distributed_rate` лишь как ярлык
> сообщения посетителю ([pingora_http.rs:3141](../../src/proxy/pingora_http.rs#L3141)),
> а не как обращение к Redis. Не считайте Redis-бакет активным на Pingora-пути
> без явной проверки своей сборки/конфигурации.

---

## 6. Взаимодействие с FilterEngine и флаг `enabled`

⚠️ **Важная тонкость (V231):** `RateLimitFilter::check()` **не** само-гейтится на
`self.enabled` ([rate_limit.rs:505](../../src/filters/rate_limit.rs#L505)). Решение
«запускать ли фильтр» принимает `FilterEngine` через `RuntimeToggles` и
per-domain `domain_policy` — это единый источник истины, иначе per-domain
оверрайды были бы дважды-гейтнуты и сломались бы
([rate_limit.rs:358](../../src/filters/rate_limit.rs#L358)).

- `config_enabled()` ([rate_limit.rs:363](../../src/filters/rate_limit.rs#L363)) —
  читается движком при регистрации `RuntimeToggle`.
- Per-filter on/off на хост задаётся через
  `DomainPolicy.filter_enabled["rate_limit"]`
  ([domain_policy.rs:106](../../src/domain_policy.rs#L106)).

Жизненный цикл запроса и место rate-limit в фильтр-чейне — в
[Архитектура](./02-architecture.md). Смежный механизм адаптивной эскалации (RPS-
penalty, exempt-paths) — `AdaptiveConfig`
([config.rs:746](../../src/config.rs#L746)), см.
ML и risk engine и
Arsenal/сценарии.

---

## 7. HTTP/2 frame-budgets (`h2_budget`)

V182, [`src/h2_budget.rs`](../../src/h2_budget.rs). Tempesta-style бюджеты на
управляющие HTTP/2-фреймы, нацеленные на CVE-2023-44487 (Rapid Reset),
CVE-2024-27316 (CONTINUATION flood) и семейство «Made You Reset» / Settings /
Ping flood. Все эти атаки эксплуатируют дешевизну конкретного control-фрейма со
стороны сервера; фикс — per-connection бюджет, проверяемый **до** того, как фрейм
дойдёт до HTTP/2-стейт-машины.

Это **отдельный** token-bucket (`tokens: f32`,
[h2_budget.rs:92](../../src/h2_budget.rs#L92)) с ленивым refill, ключуемый по паре
`(conn_id, FrameKind)` ([h2_budget.rs:118](../../src/h2_budget.rs#L118)). При пустом
бакете возвращается `Verdict::Reject`, и вызывающая сторона обязана закрыть
stream/соединение ([h2_budget.rs:143](../../src/h2_budget.rs#L143)).

### Дефолтные бюджеты

`Budget::default_for(kind)` ([h2_budget.rs:73](../../src/h2_budget.rs#L73)):

| Frame (`FrameKind`) | Burst | Refill/s | Против чего |
|---|---:|---:|---|
| `RstStream` | 50 | 20 | Rapid Reset |
| `Settings` | 10 | 2 | Settings flood |
| `Ping` | 30 | 10 | Ping flood |
| `Priority` | 100 | 50 | Priority churn |
| `Goaway` | 3 | 1 | должен быть редким |
| `Continuation` | 50 | 20 | CONTINUATION flood |

Оверрайды задаются программно: `with_override(kind, Budget { burst, refill_per_s })`
([h2_budget.rs:131](../../src/h2_budget.rs#L131)). Брифинг отмечает, что они
operator-tunable через DSL; в самом модуле API — только `with_override`.

### Управление состоянием

- `consume(conn_id, kind)` — основной хот-путь
  ([h2_budget.rs:143](../../src/h2_budget.rs#L143)).
- `drop_conn(conn_id)` — сброс всего состояния закрытого соединения
  ([h2_budget.rs:151](../../src/h2_budget.rs#L151)).
- `gc(idle)` — фоновая чистка простаивающих бакетов
  ([h2_budget.rs:157](../../src/h2_budget.rs#L157)).
- `FxHashMap` вместо SipHash, т.к. ключи (conn-local sequential IDs + маленький
  enum) не контролируются атакующим
  ([h2_budget.rs:36](../../src/h2_budget.rs#L36)).

Бюджеты per-connection подтверждены тестами
(`rapid_reset_burst_blocked_after_budget`, `budgets_are_per_connection`,
[h2_budget.rs:185](../../src/h2_budget.rs#L185)). Модуль интегрируется через
`H2Guard` ([`src/proxy/h2_guard.rs`](../../src/proxy/h2_guard.rs)) и Arsenal
([`src/arsenal.rs`](../../src/arsenal.rs)); комментарий в модуле описывает, что та же
бюджет-логика рассчитана на зеркалирование в XDP fast-path для kernel-side
энфорса ([h2_budget.rs:10](../../src/h2_budget.rs#L10), см.
[XDP/eBPF](./13-xdp-ebpf.md)).

> 🟠 **Honesty caveat (C3):** связанная находка **C3** в
> SECURITY-AUDIT отмечает, что
> часть жёстких HTTP/2-лимитов (`max_header_list_size`, concurrent-streams)
> **нельзя выставить на Pingora 0.8.0 без апгрейда фреймворка** — статус
> «отложено (нужен апгрейд pingora)». `h2_budget` закрывает frame-flood-бюджеты,
> но не заменяет полностью отсутствующие настройки фреймворка.

---

## 8. Коды ответов

| Ситуация | Действие | Status | Reason / сообщение |
|---|---|---|---|
| Превышен per-IP лимит | `FilterAction::Deny` | `429` | `"rate limit exceeded"` ([rate_limit.rs:566](../../src/filters/rate_limit.rs#L566)) |
| Превышен `/24`(`/48`) | `FilterAction::Deny` | `429` | `"subnet /24 rate limit exceeded"` ([rate_limit.rs:584](../../src/filters/rate_limit.rs#L584)) |
| Превышен `/16`(`/32`) | `FilterAction::Deny` | `429` | `"subnet /16 rate limit exceeded"` ([rate_limit.rs:596](../../src/filters/rate_limit.rs#L596)) |
| Превышен URI-бюджет | `FilterAction::Deny` | `429` | `"uri rate limit exceeded (<pattern>)"` ([rate_limit.rs:551](../../src/filters/rate_limit.rs#L551)) |
| Превышен Redis-бакет | возвращается `Some(retry_after_ms)` | `429` + `Retry-After` | legacy hyper ([http.rs:949](../../src/proxy/http.rs#L949)) |
| H2 frame-budget исчерпан | `Verdict::Reject` | — (закрытие stream/conn) | вызывающая сторона ([h2_budget.rs:143](../../src/h2_budget.rs#L143)) |

В Pingora-пути deny рендерится через `respond_visitor_error()` с ярлыком
`distributed_rate` → «Too many requests. Please wait before retrying.»
([pingora_http.rs:3141](../../src/proxy/pingora_http.rs#L3141)).

Все эти ответы попадают в журнал запросов и
метрики/телеметрию.

---

## 9. Что rate limiting НЕ закрывает (honesty caveats)

1. **L3/L4 volumetric flood.** Token-bucket работает на L7 — на уже принятом
   соединении. Объёмный флуд требует upstream-защиты: см.
   BGP RTBH и [XDP/eBPF](./13-xdp-ebpf.md). Даже
   закэшированный ответ требует входящего соединения, поэтому без upstream-drop
   бэкенд можно перегрузить (см. кэш-оговорку в
   Производительность).
2. **IPv6-evasion.** per-IP коллапсит `/64`, но межсетевая защита (`/48`/`/32`)
   зависит от `subnet_buckets`, который **по умолчанию выключен** (находка
   **H3**, SECURITY-AUDIT).
3. **HTTP/2 Rapid Reset на уровне фреймворка.** `h2_budget` даёт бюджеты, но ряд
   жёстких H2-лимитов недоступен на Pingora 0.8.0 (находка **C3**, «отложено»).
4. **Memory-exhaustion карты.** Защита держится на жёстком cap + LRU-eviction;
   фоновый `cleanup_stale` в Pingora-пути не подключён к loop (находка **H2**) —
   проверяйте актуальный статус в
   SECURITY-AUDIT.
5. **Бенчмарки rate-limit — in-process.** Тесты токен-бакета в
   [`src/bin/aegis-distbench.rs`](../../src/bin/aegis-distbench.rs) и `bench/`
   измеряют filter engine **без сетевого I/O** (token-bucket simulation). Полный
   `aegis-pingora` под боевой нагрузкой даёт ↓15–30% к синтетике (I/O Pingora,
   syscalls, TCP/TLS). Никогда не цитируйте абсолютный RPS из bench без пометки
   «in-process filter relay, не real deployment». Подробнее —
   Бенчмаркинг.

Авторитетный источник по найденным проблемам и статусу фиксов —
SECURITY-AUDIT-CONSOLIDATED-2026-06-07.md;
сводка модели безопасности — Модель безопасности.

---

## См. также

- [Архитектура и жизненный цикл запроса](./02-architecture.md)
- [Конфигурация (DSL и TOML)](./04-configuration.md)
- [XDP/eBPF kernel fast-path](./13-xdp-ebpf.md)
- [Challenge ladder, PoW и captcha](./15-challenge-ladder.md)
- BGP RTBH
- Defence Arsenal, сценарии и актуаторы
- Картография и per-domain политики
- Admin API — справочник
- Модель безопасности и харднинг
- Бенчмаркинг и сравнение с прокси
