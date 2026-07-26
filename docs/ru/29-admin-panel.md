# Админ-панель — руководство

Веб-панель AEGIS — это React-приложение (37 экранов), которое обслуживается самим прокси под префиксом `/admin/ui/` и общается с управляющим API под `/admin/api/*`. Этот документ подробно описывает вход в панель, модель аутентификации (`x-admin-token`, сессии, роли), первую смену учётных данных, текстовый дашборд `aegis-tui`, а также назначение каждой страницы — что она показывает, что настраивает и на какие маршруты API опирается.

> Грунтовка по коду: фронтенд — `web/src/pages/v2/*.tsx`, навигация — `web/src/components/layout/nav-config.ts`, HTTP-клиент и список маршрутов — `web/src/api/client.ts`. Бэкенд аутентификации панели — `src/web_admin.rs`, гейт ролей — `src/admin_auth.rs`, раздача SPA — `src/admin_ui.rs` / `src/server.rs`. Текстовый дашборд — `src/tui.rs`.

См. также: [30-admin-api.md](30-admin-api.md) — полная карта маршрутов API; [23-security-model.md](23-security-model.md) — модель угроз; [03-installation.md](03-installation.md) — установка; [04-configuration.md](04-configuration.md) — DSL-конфиг.

---

## 1. Доступ и аутентификация

### 1.1 Где живёт панель

SPA встроена в бинарь и раздаётся под `/admin/ui/`:

- `/` и `/admin/ui` (без слэша) → редирект 301 на `/admin/ui/` (`src/server.rs:1616`).
- Vite-бандл собран с `base: "/admin/ui/"`, поэтому все ассеты абсолютны под этим префиксом; неизвестные клиентские маршруты (`/admin/ui/sites`, `/admin/ui/config`, …) откатываются на `index.html` (`src/admin_ui.rs:29`).
- Управляющие вызовы идут на `/admin/api/*`. Когда панель выключена (`enabled = false`), и `/admin/ui*`, и `/admin/api/*` отвечают `503`, но «голые» эндпоинты `/admin/*` (reload, health, threats, …) продолжают работать, чтобы `systemctl reload aegis` не ломался (`src/web_admin.rs:49-53`).

### 1.2 Две независимые модели доступа

Важно различать **два разных механизма** аутентификации (`src/web_admin.rs:12-16`):

| Механизм | Что покрывает | Хранилище |
|---|---|---|
| **Сессия панели** (email + пароль → токен сессии) | Только React-панель: `/admin/ui` + `/admin/api/*` | `/var/lib/aegis/web.json` (`DEFAULT_STATE_PATH`) |
| **Статические токены DSL** (`token <role> <value>;` / `[[admin.tokens]]`) | CLI / `curl` доступ к `/admin/reload`, `/admin/health`, `/admin/threats` и т.п. | DSL-конфиг |

Панельный HTTP-клиент кладёт токен в заголовок **`x-admin-token`** на каждый запрос к `/admin/` (`web/src/api/client.ts:73-76`). Токен хранится в `localStorage` под ключом `aegis_admin_token` (`TOKEN_KEY`). При сохранении токен агрессивно очищается от пробелов/переводов строки — это «причина №1» ложных `401` при копировании из терминала (`web/src/api/client.ts:46-50`).

Эндпоинт `GET /admin/api/me` возвращает поле `auth: "session" | "config_token"` — панель понимает, вошёл ли пользователь через форму или через статический токен (`web/src/api/client.ts:645-655`).

### 1.3 Роли

Статические токены DSL имеют роль (`src/config.rs:250-257`, `src/admin_auth.rs`):

| Роль | Права |
|---|---|
| `Read` | Только чтение: метрики, health, threats, XDP-счётчики |
| `Write` | Чтение + мутации рантайма (xdp deny/undeny, правка сайтов, config apply, restart, …) |
| `Admin` | Полный контроль (reload, stop + всё выше). Переменная `AEGIS_ADMIN_TOKEN` даёт неявную роль `Admin` |

Минимально требуемая роль для каждого маршрута вычисляется в `required_role_for()` (`src/admin_auth.rs:168`). Грубое правило: `GET /admin/api/*` → `Read`; мутации (`POST`/`PUT`/`DELETE`) → `Write`. Сессия панели после смены кредов фактически работает с правами, достаточными для всех панельных операций.

### 1.4 Первый вход и обязательная смена кредов

Поведение провижининга (`src/web_admin.rs:101-141`):

- **Свежая установка** (файла `web.json` нет): создаётся админ `admin@local.lcl` (`DEFAULT_EMAIL`) со **случайным** сильным паролем (~108 бит энтропии). Пароль выводится **ровно один раз** через `tracing::warn!` в журнал службы и нигде не хранится в открытом виде (M8). Статический «общеизвестный» дефолтный пароль на свежих установках **не работает**.
- **Существующая установка**: файл загружается «как есть», без миграций.

Получить выведенный пароль:

```bash
journalctl -u aegis-pingora --no-pager | grep "Generated initial admin password"
```

Поле `must_change` остаётся `true`, пока пользователь не сменит **и** email, **и** пароль с дефолтных. Пока флаг стоит, React показывает красный баннер, форсирующий смену (`src/web_admin.rs:56-60`). Эндпоинты:

- `POST /admin/api/login` → `{ token, email, must_change }`
- `POST /admin/api/change-credentials` (текущий пароль + новый email + новый пароль) — атомарно меняет креды, снимает `must_change` и инвалидирует все прочие сессии, переиздавая текущую (`src/web_admin.rs:234-272`).
- `POST /admin/api/logout` — удаляет сессию.

Параметры безопасности: пароли хранятся как **argon2id** с пер-записным salt; токены сессий — 256 случайных бит, base64 url-safe; TTL сессии — **24 часа** (`SESSION_TTL_SECS`, `src/web_admin.rs:45`). Сравнение токенов — **константное по времени** (`constant_time_eq`), чтобы закрыть тайминг-оракул (V233, `src/web_admin.rs:33-37`). Валидация при смене: email 1..=254 символов с `@`; пароль 8..=256 символов (`src/web_admin.rs:333-352`).

Демон **стат-ит** файл `web.json` на каждом аутентифицированном запросе и перечитывает его при изменении mtime — поэтому правки CLI вступают в силу немедленно, без SIGHUP (`src/web_admin.rs:143-153`).

### 1.5 Сброс и отключение через CLI

Форма входа подсказывает команду восстановления (`web/src/pages/v2/Login.tsx:214`):

```bash
aegis web reset-admin   # сбросить пароль на новый случайный, email → admin@local.lcl, must_change=true
aegis web stop          # выключить панель: /admin/ui и /admin/api/* отдают 503
```

`reset_admin()` чистит все сессии и возвращает новый plaintext-пароль в stdout (`src/web_admin.rs:277-289`). `set_enabled(false)` стирает сессии, чтобы повторное включение требовало свежего входа (`src/web_admin.rs:291-300`).

### 1.6 Терминальный дашборд `aegis-tui`

Когда браузера нет (jump-host, recovery-SSH, встроенные развёртывания) или панель ещё не настроена, оператор запускает `aegis-tui` — Ratatui-дашборд реального времени (`src/tui.rs:1-35`). Он опрашивает `/admin/api/runtime/status` и `/metrics` на интервале и рисует один экран:

- **Шапка**: версия, hostname, uptime; `MODE` (цвет по тяжести: Normal=зелёный, Elevated=жёлтый, Attack=пурпурный, Critical=красный), `TLS on/off`, `XDP backend`.
- **Трафик**: req/s, bps, p50/p95/p99.
- **Решения**: allow / challenge / deny / throttle / observed (% + три gauge-бара).
- **Низ**: таблица top-filters (filter → hits) и лента recent events (time / ip / decision / reason).
- **Хоткеи**: `q` quit · `r` refresh · `f` follow events.

Рендер — чистая функция над `DashboardSnapshot`, поэтому одни и те же кадры можно скармливать из сети, Unix-сокета или replay-файла.

### 1.7 Структура навигации

Сайдбар сгруппирован в 6 раскрываемых групп + закреплённый внизу пункт Settings (`web/src/components/layout/nav-config.ts:85-177`). Состояние раскрытия групп хранится в `localStorage` под ключом `aegis:nav:open`.

| Группа | Пункты |
|---|---|
| **Overview** | Dashboard (`/`), Metrics (`/metrics`) |
| **Traffic & Routing** | Sites (`/sites`), Site map (`/site-map`), Upstreams (`/upstreams`), Certificates (`/certificates`) |
| **Security** | Security (`/security`), Bots (`/bots`), DDoS (`/ddos`), Log (`/logs`), Rate limits (`/rate-limits`), Reputation (`/reputation`), GeoIP (`/geoip`), Sigma rules (`/sigma`) |
| **Defence Arsenal** | Defence Arsenal (`/arsenal`), Challenge Ladder (`/challenge`), Scenarios (`/scenarios`), Active actions (`/actuators`), Honeypots (`/honeypots`), Tarpit (`/tarpit`), BGP RTBH (`/bgp`), Privacy Pass (`/privacy-pass`) |
| **Intelligence & ML** | Enrichment (`/enrichment`), ML (`/ml`), Signature miner (`/signatures`), CrowdSec (`/crowdsec`) |
| **Operations** | Workers (`/workers`), Cluster (`/cluster`), Benchmark (`/benchmark`), Telemetry (`/telemetry`), Updates (`/updates`), Config editor (`/config`) |
| **Закреплён** | Settings (`/settings`) |

Плюс маршруты вне сайдбара: `SiteDetail` (`/sites/:host`), `SiteMapHost` (`/site-map/:host`), `Login`, `NotFound`, `ServiceUnavailable`.

> Каждая страница построена на едином принципе: данные тянутся через `@tanstack/react-query` (часто с `refetchInterval`), мутации идут через те же `*Api` из `web/src/api/client.ts`. Визуальный слой — примитивы `MetricCard` / `KPITile` / `SectionHeader` / `StatusBadge` из `web/src/v2/components`. Дизайн-правило, прописанное в коде: **никогда не выдумывать числа** — все значения из реальных ответов API, иначе показывается `—` (`web/src/pages/v2/Dashboard.tsx:28-33`).

---

## 2. Overview

### 2.1 Dashboard (`/`)

Источник: `web/src/pages/v2/Dashboard.tsx`. Главный обзорный экран. Сверху вниз:

1. Селектор временного диапазона (управляет всеми временными рядами).
2. 5 KPI-плиток: Total Requests, Threat Score, Active Attacks, Mitigation Efficiency, Cluster Health.
3. Три колонки: Live Traffic Overview (WorldMap + топ стран), Traffic Flow (исторический area-chart), лента Security Events.
4. Live Decision Engine — полноширинный stacked area-chart.
5. Proxy Status (donut) | Upstream Status | System Health (4× ArcGauge).
6. Defence Arsenal | Threat Intelligence | Top Attack Types (donut).
7. Sites Overview (широкая таблица) + System Status.

Тянет: `/metrics` (Prometheus-текст), `/admin/api/metrics/series?range=`, `/admin/api/topology` (CPU+воркеры), `/admin/api/benchmark/result` (RAM), `/admin/api/geo/top` (трафик по странам, может вернуть 404 если не развёрнуто), `/admin/health`, `/admin/threats`, `/admin/anomaly`, `/admin/api/runtime/info`, `/admin/api/arsenal`, `/admin/api/cluster/status`. Если фича отсутствует, блок рисуется по ближайшим доступным данным с пометкой «live host stats unavailable».

### 2.2 Metrics (`/metrics`)

Источник: `web/src/pages/v2/Metrics.tsx`. Подробные графики метрик. См. [25-metrics-telemetry.md](25-metrics-telemetry.md).

- 4 KPI-плитки: Requests / Denied / Challenged / Filter toggles.
- Исторические панели по диапазону: Traffic / Upstream / Cache.
- Live XDP fast-path (без персистентной истории).
- 3 donut: Decision mix / Upstream status mix / Top hosts.
- Сырой Prometheus-дамп.

Данные: `metricsApi.series(range)` (`/admin/api/metrics/series` — персистентная, бакетированная история флота; сэмплируется из mmap-счётчиков кластера в фоне раз в 30 с, пишет один воркер под file-lock, читают все); `metricsApi.raw` (`/metrics`, опрос 3 с → кумулятивные числа, donut-ы, top-hosts); `runtimeInfoApi.get` (15 с → счётчики тоглов фильтров).

---

## 3. Traffic & Routing

### 3.1 Sites (`/sites`)

Источник: `web/src/pages/v2/Sites.tsx`. Список сконфигурированных сайтов. `sitesApi.list` (`GET /admin/api/sites`) и `sitesApi.remove` (`DELETE /admin/api/sites/<host>`). Бейджи источника (`StatusBadge`) и TLS/rate-limit. Мастер `AddSiteWizard` создаёт сайт через `POST /admin/api/sites` (идемпотентно: тот же host перезаписывает `.conf`; ответ содержит сгенерированный `dsl_snippet`). См. [26-sites-and-domains.md](26-sites-and-domains.md).

### 3.2 SiteDetail (`/sites/:host`)

Источник: `web/src/pages/v2/SiteDetail.tsx`. Карточка одного домена с вкладками (`SiteDetail.tsx:200-243`):

- **Overview** — KPI-строка + LiveAreaChart по метрикам хоста; переключатели per-domain политики фильтров (`sitePolicyApi.get/put/remove` — `/admin/api/sites/<host>/policy`). Политика хранит `filter_enabled` (оверрайды on/off на фильтр), `endpoint_policies` (path-паттерн → действие `allow|block|challenge|tarpit`, V166) и `rate_limit` (рантайм-оверлей RPS/burst на хост, V234 — работает без правки read-only `.conf`).
- **Endpoints** — таблица обнаруженных эндпоинтов из картографии (`siteMapApi.forHost`), привязка per-endpoint действий.
- **Challenge** — per-domain конфиг challenge-ладдера (`challengeApi.getHost/putHost/deleteHost` — `/admin/api/sites/<host>/challenge`): Argon2-PoW, Privacy Pass, adaptive, varied errors, decoy CAPTCHA, honeypot-поля, JA4/UA-консистентность, header/H2-фингерпринт, headless-детект, WebGL/audio FP и т.д.

Также тянет `metricsApi.raw`, `honeypotApi.builtin/get/toggleHost`, `sitesApi.update`.

### 3.3 SiteMap (`/site-map`, `/site-map/:host`)

Источник: `web/src/pages/v2/SiteMap.tsx`. Картография: список наблюдённых хостов и их эндпоинтов. Бэкенд мёрджит шарды `shard-*.json` и отдаёт per-host агрегаты. Каждый хост тегируется как **Configured** (есть в `/admin/api/sites`) или **Referring · unconfigured** (резолвится на прокси, но не настроен как сайт — янтарный бейдж). Маршруты: `GET /admin/api/site_map` (хосты, `total_endpoints`), `GET /admin/api/site_map/<host>` (эндпоинты: method, path_pattern, hits, last_seen, разбивка статусов 2xx/3xx/4xx/5xx). См. [26-sites-and-domains.md](26-sites-and-domains.md).

### 3.4 Upstreams (`/upstreams`)

Источник: `web/src/pages/v2/Upstreams.tsx`. Здоровье апстримов. `sitesApi.list` + `opsApi.health` (опрос 10 с; парсит текст `/admin/health`: строки `unhealthy <host> since_ms=<n>`, либо `all_upstreams_healthy`). См. [07-protocols.md](07-protocols.md).

### 3.5 Certificates (`/certificates`)

Источник: `web/src/pages/v2/Certificates.tsx`. Управление TLS-сертификатами и ACME/Let's Encrypt. `sitesApi` + `acmeApi`:

- `GET/PUT /admin/api/acme/config` (PUT — роль Write),
- `GET /admin/api/acme/orders`, `GET /admin/api/acme/orders/<host>`,
- `POST /admin/api/acme/orders` (создать ордер: host+email),
- `POST /admin/api/acme/orders/<host>/renew` (продление).

Мутации: saveConfig / createOrder / renewOrder. См. [08-tls-certificates.md](08-tls-certificates.md).

---

## 4. Security

### 4.1 Security (`/security`)

Источник: `web/src/pages/v2/Security.tsx`. Глобальная цепочка фильтров с переключателями on/off. `defaultsApi` (`GET/PUT /admin/api/defaults/filters` — рантайм-тоглы; **только в памяти**, рестарт сбрасывает к конфигу) + `filterActivityApi` (`GET /admin/api/filters` — счётчики блокировок/челленджей на фильтр). Внизу — карточка с DSL-сниппетом для постоянного закрепления. См. [10-waf.md](10-waf.md).

### 4.2 Bots (`/bots`)

Источник: `web/src/pages/v2/Bots.tsx`. Детекции ботов по IP. Переключатель режима:

- **Live** — `threatAnalyticsApi.bots()` (`/admin/api/bots`), окно реального времени ~5 мин в памяти (client_ip, primary_reason, hits, last_seen).
- **Historical** — `logsApi.stats({from,to}).top_client_ips` из персистентного хранилища за любой выбранный диапазон.

### 4.3 DDoS (`/ddos`)

Источник: `web/src/pages/v2/Ddos.tsx`. Цели распределённых атак. SeverityChip (C/H/M/L), KPI-плитки.

- **Live** — `threatAnalyticsApi.ddos()` (`/admin/api/ddos`): host + path + distinct IPs + total hits.
- **Historical** — `logsApi.stats({from,to}).top_endpoints` (атрибуция distinct-IP на эндпоинт не хранится, поэтому исторические строки ранжируются по объёму на горячих path-паттернах).

### 4.4 Logs / Журнал (`/logs`)

Источник: `web/src/pages/v2/Logs.tsx`. Журнал решений по каждому запросу: action, reason/WAF-правило, статус, latency, фингерпринт клиента (JA4), страна, протокол, UA. Маршруты: `GET /admin/api/logs` (пагинация: фильтры host/endpoint/action/ip/q + limit/offset) и `GET /admin/api/logs/stats` (агрегации: by_action, top_endpoints, top_client_ips с разбивкой deny/challenge, top_reasons, status_distribution, бакетированный series). Фильтр-трио host/from/to общее для обоих эндпоинтов; в stats остальные поля игнорируются. См. [24-request-log.md](24-request-log.md).

### 4.5 Rate limits (`/rate-limits`)

Источник: `web/src/pages/v2/RateLimits.tsx`. Редактор лимитов. `opsApi` + `sitesApi`. Показывает дефолты vs оверрайды; для неуправляемых (ops) сайтов — бейдж `ops`. См. [14-rate-limiting.md](14-rate-limiting.md).

### 4.6 Reputation (`/reputation`)

Источник: `web/src/pages/v2/Reputation.tsx`. Репутация JA4-фингерпринтов и ASN/CIDR + встроенный JA4-корпус. `reputationApi.ja4()` / `reputationApi.asn()` (статус фидов: `active`, `entry_count`, `corpus_count`), `reputationApi.ja4Lookup()` / `asnLookup()` (поиск по хешу/IP), `envApi.get/set` (пути фидов). См. [12-reputation.md](12-reputation.md).

### 4.7 GeoIP (`/geoip`)

Источник: `web/src/pages/v2/GeoIP.tsx`. Правила deny по странам и ASN-обогащение. `geoipApi.status()` (`/admin/api/geoip/status`: пути БД, `loaded`, `database_type`, `bundled`, атрибуция), `geoipApi.lookup()` (по IP), `geoipApi.update()` (`POST /admin/api/geoip/update` — обновить встроенную db-ip Country Lite). См. [20-geoip.md](20-geoip.md).

### 4.8 Sigma rules (`/sigma`)

Источник: `web/src/pages/v2/Sigma.tsx`. Конвертация Sigma-правил SigmaHQ в WAF-правила AEGIS + управление бандл-корпусом. `sigmaApi.status()` (`/admin/api/sigma/rules`: путь, exists, rule_count, size_bytes), `sigmaApi.importRule(yaml)` (`POST /admin/api/sigma/import`), `sigmaApi.list()` (`/admin/api/sigma/rules/list` — каждое правило + состояние enabled), `sigmaApi.toggle(id, enabled)` (V237 — per-rule вкл/выкл через дисковый оверлей). Импорт через Monaco-редактор. См. [10-waf.md](10-waf.md).

---

## 5. Defence Arsenal

### 5.1 Defence Arsenal (`/arsenal`)

Источник: `web/src/pages/v2/Arsenal.tsx`. Сводка всех модулей обороны по семействам (fingerprint / waf / ddos / honeypot / telemetry / challenge / deception) со статусом `shipped|planned|experimental` и live-счётчиками. `arsenalApi.get()` (`/admin/api/arsenal`), управление фича-гейтами через `envApi` / `restartApi` / `runtimeInfoApi`. См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### 5.2 Challenge Ladder (`/challenge`)

Источник: `web/src/pages/v2/ChallengeLadder.tsx`. Глобальное состояние challenge-ладдера + per-host конфиги + per-route difficulty. `challengeApi.listHosts()` (`/admin/api/challenge/hosts` — содержит `global`: attack_mode, fast_track_hits, randomized_picks, decoy_forms_rendered, honeypot_fills_detected, privacy_pass_issuers, …), `challengeApi.setAttackMode(on)` (`/admin/api/challenge/attack-mode`), `routeDifficultyApi.list()` (`/admin/api/route-difficulty` — оверрайды difficulty_bits на host+path, пресеты ai_scraper/auth). См. [15-challenge-ladder.md](15-challenge-ladder.md).

### 5.3 Scenarios (`/scenarios`)

Источник: `web/src/pages/v2/Scenarios.tsx`. YAML-сценарии leaky-bucket (CrowdSec-подобные). `scenariosApi.list()` (`/admin/api/scenarios` — `wired`, scenarios[], stats), `scenariosApi.test(yaml)` (`/admin/api/scenarios/test` — парс-проверка), `scenariosApi.load(yaml)` (`/admin/api/scenarios/load`). Поля сценария: filter, groupby, distinct, capacity, leak_speed, blackhole, action. Редактор — Monaco. См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### 5.4 Active actions / Actuators (`/actuators`)

Источник: `web/src/pages/v2/Actuators.tsx`. Активные применённые действия (актуаторы) с возможностью отката. `actuatorsApi.list()` (`/admin/api/actuators` — опрос 5 с: `active[]` с kind/target/reason/source_module/applied_at/remaining_secs, lifetime-`stats`, `kinds`), `actuatorsApi.revert(kind, target_kind, target_value)` (`/admin/api/actuators/revert`). `StatusBadge` показывает `wired`-состояние арсенала. См. [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

### 5.5 Honeypots (`/honeypots`)

Источник: `web/src/pages/v2/Honeypots.tsx`. Управление honeypot-паками и параметрами. `honeypotApi.builtin()` (`/admin/api/honeypots/builtin` — встроенные паки), `honeypotApi.get/save` (`/admin/api/honeypots` — полное состояние: `enabled`, `packs`, `per_host`, `host_disabled` (хосты, обходящие весь honeypot-матчинг), `custom_paths`, `tarpit_seconds`, `tarpit_chunk_bytes`, `score_bump`, `auto_xdp_deny_threshold`, `server_header`), `toggleGlobal` / `toggleHost` / `clearHost` / `setHostEnabled`. Также `envApi`/`runtimeInfoApi` для фича-гейтов (например LLM-honeypot). См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

### 5.6 Tarpit (`/tarpit`)

Источник: `web/src/pages/v2/Tarpit.tsx`. Параметры tarpit + YAML-дескрипторы многоходовых honeypot-разговоров. `tarpitApi.status()` (`/admin/api/tarpit/status`: tarpit_seconds, tarpit_chunk_bytes, auto_xdp_deny_threshold, poisoned_tarpit_default_delay_ms), `honeypotYamlApi.list/parse` (`/admin/api/honeypot-yaml`, `/admin/api/honeypot-yaml/load`). Каждый дескриптор биндит path-паттерн к N ходам разговора; per-IP state отслеживает прогресс. Редактор — Monaco. См. [17-honeypot-tarpit.md](17-honeypot-tarpit.md).

### 5.7 BGP RTBH (`/bgp`)

Источник: `web/src/pages/v2/BgpRtbh.tsx`. Активные BGP-анонсы RTBH (ExaBGP). `bgpApi.list()` (`/admin/api/bgp/announces` — опрос 10 с: `wired`, `active_count`, `active[]` с ip/community/age_secs), `bgpApi.withdraw(ip)` (`/admin/api/bgp/withdraw` — отозвать анонс). См. [19-bgp-rtbh.md](19-bgp-rtbh.md).

### 5.8 Privacy Pass (`/privacy-pass`)

Источник: `web/src/pages/v2/PrivacyPass.tsx`. Эмитенты Privacy Pass (Ed25519). `privacyPassApi.status()` (`/admin/api/privacy-pass` — опрос 30 с: `wired`, `issuer_count`, `nonce_cache_size`), `privacyPassApi.addIssuer()` (`/admin/api/privacy-pass/issuers` — name, key_id_hex, public_key_hex, algorithm `ed25519|hmac_sha256`, trust_duration_secs). См. [16-privacy-pass.md](16-privacy-pass.md).

---

## 6. Intelligence & ML

### 6.1 Enrichment (`/enrichment`)

Источник: `web/src/pages/v2/Enrichment.tsx`. Обогащение угроз из внешних источников (threat-intel). `enrichmentApi.status()` (`/admin/api/enrichment` — опрос 10 с: `wired`, per-source stats queries/hits/misses, кэш), `enrichmentApi.lookup(key_kind, value)` (`/admin/api/enrichment/lookup` — ручной тест по ip/ja4/asn/user_agent; возвращает агрегатный вердикт + по источникам). См. [22-enrichment.md](22-enrichment.md).

### 6.2 ML (`/ml`)

Источник: `web/src/pages/v2/ML.tsx`. Управление фича-флагами ML и статусом risk-движка. `mlApi.status()` (`/admin/api/ml/status`: `v2_wired`, `v2_kind` logistic/gbm, `adversarial_loop_env`), `mlApi.retrain()` (`/admin/api/ml/retrain`), `mlApi.adversarial()` (`/admin/api/ml/adversarial`), `envApi` + `runtimeInfoApi` для флагов (`AEGIS_ML_V2`, `AEGIS_ML_SCORER`, `AEGIS_ML_ADVERSARIAL`, `AEGIS_RISK_ENGINE_MODE`). Часть флагов запускается только при рестарте — показывается баннер restart-required. См. [18-ml-risk-engine.md](18-ml-risk-engine.md).

### 6.3 Signature miner (`/signatures`)

Источник: `web/src/pages/v2/SignatureMine.tsx`. Майнинг attack-сигнатур (n-грамм) из корпуса payload'ов с контраст-сетом benign. `signatureMineApi.mine(attacks, benign)` (`POST /admin/signature_mine` — тело: attack-строки, литерал `---`, benign-строки; ответ: candidates с confidence/attack_support/benign_support/category/ngram), `signatureMineApi.minedCandidates()` (`GET /admin/api/mined_signatures` — авто-намайненные кандидаты из online-пайплайна tarpit→miner). **Без прямой записи в WAF-конфиг** — оператор копирует кандидаты как WAF-правила TOML и вставляет через Config Editor. См. [10-waf.md](10-waf.md).

### 6.4 CrowdSec (`/crowdsec`)

Источник: `web/src/pages/v2/CrowdSec.tsx`. Настройка адаптера CrowdSec LAPI. `crowdsecApi.status()` (`/admin/api/crowdsec/status`: `lapi_url`, `bouncer_key_configured`, `format_adapter_available`), конфиг через `envApi`. Баннер restart-required при изменениях. См. [22-enrichment.md](22-enrichment.md).

---

## 7. Operations

### 7.1 Workers (`/workers`)

Источник: `web/src/pages/v2/Workers.tsx`. Топология воркеров (многопроцессность SO_REUSEPORT). `topologyApi.get()` (`GET /admin/api/topology` — host, layout, per-worker procs, рекомендация), `topologyApi.put(workers)` (`PUT /admin/api/topology` — желаемое число: `"auto"` или числовая строка), `envApi`, `runtimeInfoApi`, `restartApi`. См. [06-workers.md](06-workers.md).

### 7.2 Cluster (`/cluster`)

Источник: `web/src/pages/v2/Cluster.tsx`. Состояние shared-mmap кластера угроз. `clusterApi.status()` (`/admin/api/cluster/status` — опрос 5 с: `shared_scorer_attached`, `counts.ipv4_slots_active`, `counts.top[]` с ip/score). См. [06-workers.md](06-workers.md).

### 7.3 Benchmark (`/benchmark`)

Источник: `web/src/pages/v2/Benchmark.tsx`. Аппаратный бенчмарк, нагрузочные тесты и сравнение с другими прокси. Три набора маршрутов (fire-and-forget + поллинг результата):

- `benchmarkApi` — `POST /admin/api/benchmark/run`, `GET /admin/api/benchmark/result` (аппаратный бенч + прогноз ёмкости).
- `floodApi` — `POST /admin/api/benchmark/flood/run`, `GET .../flood/result` (SYN / HTTP / TLS / slowloris / cache flood-тесты).
- `compareApi` — `POST .../compare/run`, `GET .../compare/result` (head-to-head: AEGIS raw, AEGIS+WAF, nginx, nginx+ModSec+CRS, HAProxy, Caddy, Envoy; матрица безопасности по атакам).

> Честные оговорки (прямо в коде, поле `caveat`): бенч-лейны AEGIS — это **in-process движок, а не полный pingora-бинарь**; аппаратный SHA-бенч — per-core и в VM без аппаратного SHA-ускорения занижен, отчего прогноз ёмкости пессимистичен. Не позиционируется как «быстрее реальных проксей по голой скорости» — сильный аргумент именно матрица безопасности. См. [28-benchmarking.md](28-benchmarking.md), [27-performance-tuning.md](27-performance-tuning.md).

### 7.4 Telemetry (`/telemetry`)

Источник: `web/src/pages/v2/Telemetry.tsx`. Настройка телеметрии и интеграций SIEM. `telemetryApi.status()` (`/admin/api/telemetry/status`: EventBridge format/format_options/socket_path, ClamAV enabled/addr/env_var, audit_log_path), `captchaApi.status()` (`/admin/api/captcha/status`: PoW enabled/difficulty_bits/algorithm, внешние провайдеры hcaptcha/turnstile/recaptcha), env-контролы через `envApi` + `restartApi`. См. [25-metrics-telemetry.md](25-metrics-telemetry.md).

### 7.5 Updates (`/updates`)

Источник: `web/src/pages/v2/Updates.tsx`. **Read-only** проверка обновлений (V208). `updatesApi.status()` (`/admin/api/updates/status`: current_version, channel, latest, update_available, last_checked_at, last_error), `updatesApi.check()` (`POST .../check`), `updatesApi.releases()`, `updatesApi.setConfig()` (`PUT .../config`: repo_api_url, channel `stable|beta|nightly`, poll_interval_secs).

> Безопасность (V233): механизм **самообновления-применения убран** целиком (типы и маршруты `apply`/`snapshots` удалены) — он скачивал и исполнял неподписанный, контролируемый атакующим бинарь от имени сервис-юзера (дизайн unauthenticated-RCE). Осталась только read-only проверка. Применение обновлений — вручную, см. [44-updates-migration.md](44-updates-migration.md).

### 7.6 Config editor (`/config`)

Источник: `web/src/pages/v2/ConfigEditor.tsx`. Редактор сырого DSL-конфига в Monaco с подсветкой синтаксиса (ключевые слова: `admin`, `defaults`, `server`, `include`, `location`, `listen`, `server_name`, `ssl_certificate`, …). `configApi.raw()` (`GET /admin/api/config/raw`), `configApi.test(text)` (`POST /admin/api/config/test` — проверка без применения), `configApi.save(text)` (`PUT /admin/api/config/raw`), `configApi.apply()` (`POST /admin/api/config/apply` — роль Write; применить/перезапустить). См. [04-configuration.md](04-configuration.md).

---

## 8. Settings (`/settings`)

Источник: `web/src/pages/v2/Settings.tsx`. Четыре вкладки:

| Вкладка | Содержание |
|---|---|
| **General** | Runtime info, текущая сессия, смена учётных данных (`ChangeCredentialsCard` → `authApi.changeCredentials`), danger zone |
| **ML & Detection** | ML scorer, adversarial loop, honeypot |
| **Reputation** | Фиды JA4 + ASN |
| **Infrastructure** | Response cache, dynamic trust, fw backend, XDP, ACME, CrowdSec, ClamAV (через env-vars; баннер restart-required) |

Данные: `runtimeApi.status` (`/admin/api/runtime/status`), `runtimeInfoApi.get` (`/admin/api/runtime/info`, 15 с — версия, uptime, config_path, статус ML v2, JA4/ASN-репутации, honeypot, число тоглов/политик, clamav_addr, плюс расширенные env-гейты), `envApi.set` (`PUT /admin/api/env` — секреты write-only: GET отдаёт `configured: true/false`, `value: null`; для startup-gated переменных ответ содержит `restart_required: true`), `restartApi.run` (`POST /admin/api/restart` — роль Write; запускает rolling-restart `aegis-pingora.target`, соединение упадёт через пару секунд).

---

## 9. Служебные экраны

| Экран | Файл | Назначение |
|---|---|---|
| **Login** | `Login.tsx` | Полноэкранная форма входа (email + пароль, toggle видимости). Рендерится напрямую из `main.tsx` при состоянии `logged_out`, без роутера/лейаута. Подсказка восстановления: `aegis web reset-admin` |
| **ServiceUnavailable** | `ServiceUnavailable.tsx` | Экран при `503` (панель выключена / прокси недоступен) |
| **NotFound** | `NotFound.tsx` | 404 для неизвестных клиентских маршрутов |

---

## 10. Практические заметки оператора

- **«401 unauthorized» сразу после копирования токена** — почти всегда лишний перевод строки; клиент уже нормализует значение (`setToken`), но при ручной вставке в `x-admin-token` через curl убедитесь в отсутствии `\n`.
- **Изменения фильтров через Security не переживают рестарт** — `defaultsApi` правит рантайм-состояние в памяти; для постоянства зафиксируйте сниппет в DSL (страница показывает его) и примените через Config Editor.
- **Часть фич требует рестарта** — флаги, помеченные `restart_required` в ответе `PUT /admin/api/env`, и страницы ML / CrowdSec / Telemetry / Workers показывают баннер; рестарт инициируется кнопкой (`POST /admin/api/restart`) либо `systemctl`.
- **Mock-режим** — при сборке фронта с `VITE_USE_MOCKS=true` панель отдаёт синтетику из `mocks.ts` и просматривается без работающего бэкенда (для разработки UI).
- **Восстановление при полной блокировке** — `aegis web reset-admin` сбрасывает email на `admin@local.lcl` и выдаёт новый пароль в stdout; правка `web.json` подхватывается демоном по mtime без перезапуска.

См. также: [30-admin-api.md](30-admin-api.md), 42-текущее-состояние-STATUS.md, [47-faq-troubleshooting.md](47-faq-troubleshooting.md).
