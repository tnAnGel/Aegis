# Aegis

**Aegis** — высоконагруженный reverse proxy / edge gateway для DDoS mitigation и L7-фильтрации трафика. Написан на Rust, поддерживает HTTP/1.1, HTTP/2, HTTP/3 (QUIC), eBPF/XDP fast-path и многоуровневую challenge-систему в стиле vDDoS.

**Текущая версия: `V237`** (2026-06-02) · production data plane на Cloudflare Pingora.

> 1176 unit + 21 integration + 11 e2e scenarios (+ 13 в pingora-e2e harness), `clippy -D warnings` чистый, `cargo fmt` чистый, GitHub Actions CI на ubuntu + macos.

## Что нового (V175 → V236) — Arsenal, безопасность, производительность

### V176–V191 — 15 новых модулей защиты + Arsenal UI
Спринт кросс-поллинации по идеям FoxIO JA4, utls, SafeLine, open-appsec, Coraza, Tempesta, Galah, Beelzebub, T-Pot, Anubis, FastNetMon, Scrapling, LLMHoney.

**Fingerprint & сигналы:** V176 ja4_corpus (FoxIO-seeded allow/deny baseline) · V177 ja4_churn (скользящее окно ротации JA4 per-IP) · V178 grease_anomaly (детектор spoofed-Chrome по позициям GREASE) · V189 timing_entropy (серверный анализ мышиного jitter / scroll-каденции).

**WAF / нормализация:** V179 normalisation (SafeLine-style multi-pass URL→HTML→NFKC→confusables→null→lowercase до fixed-point) · V180 param_profile (open-appsec-style rolling stats length/charset/entropy per param) · V181 rule_planner (Coraza-style phase-indexed compiled rule dispatch).

**DDoS / сеть:** V182 h2_budget (Tempesta-style per-conn token-bucket по виду H2-фрейма — Rapid Reset / Settings / Ping / CONTINUATION flood) · V187 bgp_rtbh (FlowSpec/RTBH dispatcher: Deny при scorer ≥ 80 → /32 announce через exabgp).

**Honeypot / deception:** V183 llm_honeypot (Galah-style LLM-клиент + semantic-hash кэш) · V184 honeypot_yaml (Beelzebub-style YAML-дескрипторы + multi-turn state machine) · V188 decoy_headers (Scrapling-inverted Cloudflare/Akamai/Fastly/CloudFront impersonation) · V190 latency_jitter (LLMHoney-style log-normal / bimodal задержки).

**Challenge / telemetry:** V185 sicherheitstacho (T-Pot-compatible NDJSON event export) · V186 route_difficulty (Anubis-style per-route PoW difficulty — GPTBot/CCBot +4 бита, */login +6 бит) · V191 Arsenal UI (nav-страница со всеми модулями, live counters).

### V192–V199 — Wire-in модулей + Sigma importer + Actuator/Enrichment/Scenario
- **V192–V195** — ArsenalState интегрирован в `AegisPingoraProxy`; все V176–V190 активны на горячем пути с атомарными счётчиками в `/admin/api/arsenal`.
- **V196 SigmaHQ importer** — 562 community-правила (webserver + emerging-threats) сконвертированы в WAF-формат; drop-in через `rule_files`. CLI `aegis-sigma-import`.
- **V197 actuator** — единый реестр активных мер (XdpDeny / NftDrop / BgpAnnounce / ChallengeFloorRaise) с revert-TTL.
- **V198 enrichment** — WISE-style кэшированный fan-out по intel-источникам (ja4_reputation, asn_reputation, threat_intel, geoip, ja4_corpus) → aggregated verdict.
- **V199 scenarios** — CrowdSec-style leaky-bucket YAML DSL для behavioural detection без Rust-кода.

### V200–V207 — Расширения challenge ladder
- **V200 argon2_pow** — Argon2id memory-hard PoW (64 MB / 2 iter / 18 бит): 100–1000× дороже для GPU-ферм чем SHA-256.
- **V201 privacy_pass** — RFC 9576-shaped token verifier; анонимные браузеры от доверенных issuer'ов проходят ladder молча.
- **V202 chained_trust** — TrustTier-прогрессия (Cookie 5 мин → WebAuthn 7 дней) per-(IP, RouteClass).
- **V203 challenge_deception** — decoy CAPTCHA-форма (сжигает 2captcha-бюджет атакующего) + honeypot-поля.
- **V204 adaptive_ladder** — глобальный attack_mode поднимает сложность; fast-track к PoW/Captcha по suspicion.
- **V205–V207** — per-domain challenge-панель в admin UI.

### V213–V227 — Admin panel: закрытие всех пробелов аудита
30+ новых admin-endpoint'ов и ~20 React-страниц: Scenarios, Actuators, Sigma, Enrichment, Reputation, ML, PrivacyPass, BGP RTBH, Telemetry, GeoIP, Cluster, Tarpit, CrowdSec. Итого ~35 пунктов в sidebar.

### V228–V230 — Производительность: устранение регрессий + два больших sweep'а
- **V228** — `[profile.release]` с `lto="fat"` + `codegen-units=1` + `panic="abort"` + `strip="symbols"` (отсутствовал) → +5–15% throughput; RuntimeToggles statx-throttle; 5 горячих `RwLock<HashMap>` → `DashMap`; `arsenal::Counters` → `ShardedCounter` (per-CPU shard).
- **V229** — `FilterAction::reason` `String` → `Cow<'static,str>` (20+ deny-путей без heap-аллокации); `release_max_level_info` (debug!/trace! на hot path стали dead code); upstream keepalive pool 1 → 4096; `anomaly` hot path 1.5 мкс → 5 нс lock-free.
- **V230** — 40-agent sweep: 11 горячих DashMap на `with_shard_amount(128)`; FxHash на internal-картах; WAF `PrefixMatcher`/`SuffixMatcher` + `memchr::memmem` SIMD; `request_id` `String` → `u64`; CPU pinning `CPUAffinity=%i`; **mimalloc** глобальным аллокатором; H3 sidecar runtime `multi-thread` → `current_thread`.

### V231 — RuntimeToggles как единственный источник истины + фикс краша admin listener
- RuntimeToggles — авторитетный gate enable/disable; внутренний `if !enabled` удалён из всех фильтров (per-domain force-on теперь реально работает).
- **SO_REUSEPORT** применён к admin listener — фикс bind-race-краша при нескольких worker'ах.
- TCP keepalive-регрессия V230 исправлена (downstream keepalive за флаг `AEGIS_PINGORA_DOWNSTREAM_KEEPALIVE`); `net.core.somaxconn = 65535` задокументирован.
- **ChallengeConfig** по умолчанию `enabled = false` — challenge-ladder теперь opt-in per-domain.

### V232 — Worker-topology dashboard + контроль числа worker'ов
Новый модуль `src/topology.rs`: `host_info()`, `enumerate_workers()` (скан /proc), `DesiredTopology` (в `/var/lib/aegis/topology.json`). Admin API `GET/PUT /admin/api/topology`; React-страница **Workers** (per-worker PID/RSS/uptime/CPU, Auto/Custom-контрол). Security-fix: `admin_auth.rs` fail-closed catch-all для всех мутаций `/admin/api/*`.

### V233 — 37-agent security audit: 21 находка устранена
- **CRITICAL — самообновление УДАЛЕНО**: `POST /admin/api/updates/apply` принимал attacker-controlled `download_url` без проверки подписи → persistent RCE. Бинарь `aegis-updater` теперь tombstone; операторы деплоят через `install.sh` вручную.
- **CRITICAL — constant-time HMAC**: `verify_token` (`aegis_fp`), session-token и Privacy Pass MAC переведены на `Hmac<Sha256>` + `Mac::verify_slice` / `constant_time_eq` (устранены timing-oracle и length-extension forgery).
- **HIGH**: WAF `canon_once` переписан на `&[u8]` (была паника `/` + multibyte → worker SIGABRT); `/* */`-комментарии коллапсируются; whole-body scan вместо первых 256 KiB; response-cache не кэширует credentialed-запросы; admin SSRF — `validate_upstream` блокирует loopback/link-local/RFC1918/metadata; open-redirect фикс в `safe_return_url`.

### V234 — Оживление мёртвых модулей защиты
- **PoW** (CRITICAL fix) — `PowIssuer` полностью подключён в `pingora_challenge.rs`: сервер минтит IP-bound HMAC-signed задачу и проверяет решение (раньше `?pow=<anything>` принималось без верификации).
- **CAPTCHA** (CRITICAL fix) — `verify_recaptcha` вызывает реальный Google siteverify; fails closed без секрета; старый static-word bypass удалён.
- **ACME HTTP-01** — `/.well-known/acme-challenge/<token>` отвечает из памяти до filter chain.
- **login-abuse + ClamAV** — новый `request_body_filter`: тело буферируется только когда включён ClamAV или путь — login endpoint; infected / brute-force → abort.

### V235 — Фикс регрессии honeypot на root-path
V233 добавил `canonical_path()` в `HoneypotMatcher::from_patterns`; legacy Drupal-пробы `/?q=admin` сворачивались в `/` → каждый запрос к корню сайта попадал в 30-секундный tarpit. Фикс: degenerate-pattern guard — любой паттерн, чей канонический вид равен `/`, отбрасывается при сборке matcher'а. Подтверждено на 16-worker стенде: `GET /` снова 200 за ~1 мс.

### V236 — Perf-оптимизации hot-path форвардинга
Профиль `perf` форвардинг-пути вскрыл устранимый оверхед — 5 правок, без смены фреймворка и kernel-пути: filter-движок больше не читает часы 8×/запрос (→ 1×) и проверяет toggle прямым `AtomicBool`-load вместо DashMap-lookup; JA4H-фингерпринт (SHA-256) считается лениво по первому чтению, а не на каждом запросе; убран двойной клон `host`/`path`/`method` (`RequestContext` → `AegisCtx`); `cluster_bump` батчит счётчики в per-worker-буфере (нет кросс-процессного cache-line ping-pong). Замер на стенде: форвардинг c=500 452k → **486k RPS** (+7.5%), c=1000 425k → **442k** (+4%), p99 ниже; 1206 unit-тестов зелёные, 0 паник под нагрузкой.

## Результаты нагрузочного тестирования

> Замерено на **V235**, 2026-05-22. Стенд: 16-vCPU Linux VM (16 worker'ов
> × 1 поток, CPU-pinned, SO_REUSEPORT), генератор нагрузки `oha`
> (`--latency-correction`); proxy + upstream nginx + генератор — на одной
> машине, поэтому абсолютные числа консервативны (всё конкурирует за 16 ядер).

### Пропускная способность — кэш-режим (response-cache HIT)

Ответ отдаётся из памяти worker'а, апстрим не трогается:

| Concurrency | RPS | p99 |
|---|---|---|
| c=500  | 1 216 927 | 4.5 мс |
| c=1000 | 1 184 080 | 8.3 мс |
| c=2000 | 1 091 267 | 12.8 мс |

### Пропускная способность — форвардинг (cache off) vs nginx

> ⚠️ **DEPRECATED — ceiling-capped, не прокси-сравнение.** Оба прокси
> упирались в апстрим (~308k RPS), поэтому таблица измеряет потолок бэкенда,
> а не возможности прокси. Изолированный V237-замер (см. ниже) показывает
> обратную картину: nginx ~13% быстрее AEGIS при отсутствии ограничения
> апстримом. Данные ниже сохранены как исторический артефакт V235.

Apples-to-apples: каждый запрос форвардится на один и тот же nginx-апстрим.
Прокси физически не может быть быстрее своего бэкенда — потолок апстрима ~308k RPS.

| Прокси | RPS | p50 | p99 |
|---|---|---|---|
| nginx — отдаёт статику напрямую (потолок апстрима) | 307 800 | 0.24 мс | 1.81 мс |
| **AEGIS** — reverse-proxy форвардинг | **272 840** | 0.32 мс | **1.13 мс** |
| nginx — reverse-proxy форвардинг | 179 058 | 0.37 мс | 2.97 мс |

AEGIS-форвардинг = **89% потолка апстрима** (накладные расходы прокси ~11%) —
**+52% RPS против nginx** в режиме reverse-proxy, p99 в 2.6× ниже.
_(Это ceiling-capped: оба прокси ограничены ~308k-бэкендом — см. примечание выше.)_

### 16×1 thread-per-core vs 4×4 — выбор раскладки потоков

Отдельный 3-trial apples-to-apples прогон (кэш-режим):

| Concurrency | 16×1 thread-per-core | 4×4 | Победитель |
|---|---|---|---|
| c=500  | ~1074k RPS, p99 3.0 мс | ~976k RPS, p99 3.6 мс | 16×1 +10% |
| c=1000 | ~962k RPS, p99 3.85 мс | ~902k RPS, p99 4.95 мс | 16×1 +6.6% |
| c=2000 | ~766k RPS, p99 5.5 мс | ~782k RPS, p99 9.1 мс | RPS ничья, p99 −40% у 16×1 |
| RAM    | 639 MB | 148 MB | 4×4 (×4.3 меньше) |

16×1 thread-per-core быстрее (+6-10% RPS, p99 на 40% ниже под нагрузкой) — ценой
RAM (16 копий процесса). Это дефолт V230-инсталлера; число воркеров настраивается
на странице **Workers** в панели.

### Устойчивость к DDoS (хардтесты)

Прод-конфиг (16×1, cache on, все фильтры on):

| Хардтест | Результат |
|---|---|
| Волюметрический флуд, c=1000 → 8000 | success **100%** на всех уровнях, **0 паник**, 16/16 воркеров; RPS 1.21M→685k (graceful degradation); `/` после флуда — 0.18 мс |
| Slowloris — 4000 slow-header соединений, 45 с | **10/10 «service available: YES»** — медленные соединения сброшены по header-timeout, сервис не просел |
| Смешанная атака — ~4 млн запросов/15 с (path-traversal + SQLi + scanner-UA) | **100% → HTTP 403**, до origin дошло 16 из ~4M (~0.0004%), honeypot тарпитит, 0 паник |
| Эндьюранс — 90 с непрерывно @ 1.1M RPS | RPS плоский (1.109M→1.095M), p99 плоский (~10.8 мс), RSS 711→721 MB (**утечки нет**), 0 паник, 0 OOM |
| Одиночный флуд 200 conn, фильтры on | 23.5 M запросов/20 с поглощено, **16 дошло до origin** (~0%); nginx-proxy в том же тесте пропускает **100%** флуда |
| WAF block-path (path-traversal + SQLi → 403) | **259 691 RPS** блокировки, **0** атак до origin |

**Вердикт:** за весь DDoS-прогон — сотни миллионов запросов по 4 векторам —
**0 паник, 0 крашей, 0 OOM, 0 зависаний**. Origin прикрыт полностью,
восстановление мгновенное, память не течёт.

### Сравнение с другими reverse-proxy

Отдельный стенд `Any-Proxy-Dev` — чистый 16-vCPU / 16 GB VM, идентичный
стенду AEGIS. Все прокси установлены на одну машину, форвардят на один
бэкенд (nginx `return 200`, потолок ~1.6M RPS), нагрузка — `oha`
(`-z 20s --latency-correction`), методика одна и та же. Каждый прокси — в
своей штатной high-perf конфигурации, **чистый форвардинг без кэша**.

| Прокси | Версия | c=500, RPS | c=1000, RPS | p99 @ c=1000 |
|---|---|---|---|---|
| _бэкенд (nginx `return 200`) — потолок_ | 1.22.1 | _1 579 084_ | _1 606 819_ | _4.0 мс_ |
| OpenResty | 1.29.2 | 731 974 | 701 574 | 9.0 мс |
| nginx | 1.22.1 | 716 768 | 674 212 | 9.4 мс |
| HAProxy | 2.6.12 | 523 440 | 503 811 | 12.6 мс |
| **AEGIS** — plain proxy | **V236** | **485 239** | **456 404** | **12.1 мс** |
| **🛡 AEGIS** — protected | **V236** | **464 973** | **441 915** | **12.0 мс** |
| NGINX Unit | 1.34.2 | 348 121 | 428 046 | 8.2 мс |
| Envoy | 1.31.0 | 254 212 | 243 390 | 16.2 мс |
| Apache httpd | 2.4.67 | 176 518 | 172 163 | 97 мс |
| Traefik | 3.7.1 | 150 534 | 139 636 | 28.6 мс |
| Caddy | 2.11.3 | 104 642 | 98 441 | 44 мс |
| Varnish (pass-through) | 7.1.1 | 44 958 | 39 026 | 115 мс |

> Две строки AEGIS: **plain proxy** — все фильтры выключены, чистый форвардинг;
> **protected** — WAF + bot-фингерпринт + JA4H + движок фильтров отрабатывают на
> КАЖДОМ запросе. Разница (~4%) — это цена полного per-request L7-security-
> конвейера на легитимном трафике. Объёмные детекторы (rate-limit, spike) — не
> per-request-стоимость, а логика обнаружения; их эффект — в DDoS-тесте выше.
> Числа — после perf-оптимизаций V236; остальные прокси из исходного прогона.
>
> ⚠️ **Кросс-сессионная оговорка:** строки AEGIS (оба режима) — из отдельного
> V236 re-run сеанса; остальные 9 прокси — из оригинального `Any-Proxy-Dev`
> прогона. Прямое сравнение AEGIS/nginx (~0.68× в этой таблице) занижает AEGIS:
> в изолированном V237-замере на одном хосте честное соотношение **≈0.87×**
> (см. раздел ниже).

**Как это читать честно:**

- Это **чистый форвардинг**. nginx / OpenResty / HAProxy — минималистичные
  C-форвардеры, годами вылизанные, без слоя безопасности вообще. AEGIS даже
  в plain-proxy режиме (все фильтры выключены) на каждом запросе строит
  AegisCtx, гоняет anomaly-детектор, threat-scoring, метрики,
  site-map-картографию — голые форвардеры не делают ничего из этого.
- AEGIS — **4-е место даже с полной защитой**: и в plain, и в protected
  режиме обгоняет все современные feature-rich прокси (Envoy — CNCF service
  mesh, Traefik, Caddy) и классический Apache. Полный per-request
  security-конвейер (WAF + bot + JA4H) стоит лишь ~4% throughput.
- AEGIS здесь даёт ~485k, а в разделе «форвардинг vs nginx» выше — 272k:
  там бэкенд медленный (~308k) и AEGIS упирался в апстрим; здесь бэкенд
  ~1.6M, поэтому ~485k — это истинный потолок форвардинга AEGIS, не
  ограниченный бэкендом.
- **Varnish** — кэширующий прокси, pass-through не его сценарий. В режиме
  кэша Varnish даёт **588 712 RPS** (c=500). AEGIS в режиме кэша —
  **~1.1M RPS** (см. кэш-таблицу выше): быстрее только сам бэкенд.
- Под **DDoS / атаками** сравнение бессмысленно: ни у одного competitor'а
  нет L7-защиты — они форвардят 100% вредоносного трафика на origin. AEGIS
  единственный фильтрует (см. DDoS-хардтесты выше): WAF режет атаки на
  ~260k RPS, флуд отражается с ~0% origin exposure.

**Вывод:** как «голый» форвардер AEGIS — середина списка (медленнее
вылизанных C-форвардеров, быстрее современных Go/C++-прокси). Но AEGIS —
не форвардер, а security-edge: с кэшем он первый после бэкенда, а под
атакой — единственный, кто реально защищает origin.

**Главное — fair-fight с равной защитой.** Голый nginx быстрее AEGIS как dumb-прокси,
но это спорткар против броневика: у nginx нет L7-защиты. Честный конкурент —
**nginx + ModSecurity + OWASP CRS**. Замерено (оба WAF ON, forwarding c=500):
AEGIS-protected **494k RPS** vs nginx+ModSec **15.8k RPS** — **AEGIS ≈18× быстрее**
(нормализовано по скорости хоста; сырое кросс-VM число — 31×, но стенд с nginx+ModSec
имел голый nginx 334k RPS, тогда как стенд AEGIS — 590k RPS, разница хостов 1.76×).
Бесспорный факт в рамках одного хоста: ModSec+CRS съедает **−95.3%** пропускной
nginx (334k → 15.8k RPS), тогда как компилированный Rust-конвейер AEGIS — доли
этого. Вот где AEGIS реально выигрывает: **эффективная встроенная L7-защита**.
Детали + оговорки — [docs/PERFORMANCE.md](../en/reference/performance.md).

> Таблица выше — снимок на V236, single-box (генератор + прокси + бэкенд
> делят 16 ядер). Это занижает абсолют и преувеличивает разрыв с nginx —
> 16 процессов AEGIS конкурируют с генератором сильнее, чем потоки nginx.
> Строгий CPU-изолированный замер — ниже.

### Изолированный замер V237 (CPU-pinned, apples-to-apples vs nginx)

Стенд `Aegis-Proxy-Test` (16-vCPU). Жёсткий пиннинг убирает конкуренцию за
ядра: прокси на ядрах 0-7, генератор `oha` на 10-13, бэкенд на 14-15. nginx
и AEGIS — через идентичную раскладку, best-of-5, чистый форвардинг без кэша.

| Режим (8 ядер) | c=500, RPS | c=1000, RPS |
|---|---|---|
| nginx — форвардинг | 589 748 | 502 601 |
| **AEGIS V237** — plain форвардинг | 513 506 | 442 535 |
| _AEGIS V236 (для дельты)_ | _506 917_ | _440 669_ |
| **🏆 AEGIS V237** — режим кэша (HIT) | **971 937** | 767 176 |
| nginx + proxy_cache | 660 957 | 641 112 |

**Что показал изолированный замер.** Разрыв в форвардинге — **~13%** (а не
1.48× из single-box: то был артефакт методики). p99 у AEGIS при этом **ниже
nginx** (1.9 vs 2.0 мс). В режиме кэша AEGIS **обгоняет nginx-с-кэшем на
20-47%** и nginx-форвардинг — в **1.7×**.

### История оптимизаций V236 → V237

- **V236** — `perf`-профиль форвардинг-пути: убраны лишние `clock_gettime`
  (8×→1× на запрос), JA4H считается лениво, батчинг кластер-счётчиков.
- **V237** — аудит горячего пути **56 агентами** (14 зон, каждая находка
  состязательно верифицирована «реально ли исполняется на запросе в plain»):
  30 подтверждённых находок, реализована безопасная часть —
  - **LSE-атомики** (ARMv8.1): сборка под фактический CPU (`target-cpu=native`
    в `install.sh`) заменяет LL/SC-циклы (`__aarch64_ldadd8`) одноинструкционными
    `ldadd`/`swpal` — ускоряет все атомики (Arc, DashMap, tokio, mimalloc).
    Конфиг НЕ хардкодит фичи — портируемо на старый ARM/x86 (сборка под своё
    железо, ноль SIGILL-риска);
  - read-lock + zero-alloc fast-path в per-domain метриках; single-bucket
    гистограмма (3 атомика вместо 13); borrow-or-own host-ключи без аллокаций;
    empty-feed fast-path в threat-intel/honeypot; gating мёртвого scorer-write;
    alloc-free разбор Cookie на no-cookie пути; in-place батч кластер-счётчиков.
  - Измерено interleaved A/B (гасит шум хоста): **+2-3%** на c=500. Прирост
    скромный честно: оптимизированный слой (атомики/аллокации/локи) — лишь ~2%
    профиля; доминанта — framework I/O (Pingora/tokio) + kernel TCP, вне нашего
    кода. 1215 unit-тестов зелёные, 0 паник.

**Потолок нашего кода достигнут.** Дальше форвардинг упирается во фреймворк
(async-Pingora + tokio timer + kernel syscalls ≈ 25% профиля). Два пути «обойти»
проверены и отклонены с доказательствами: **io_uring** — измеренно на 24%
медленнее nginx на этом профиле (NO-GO); **gating клона HeaderMap** — даёт 1.3%,
но вносит WAF-bypass-гонку (REJECTED для security-прокси). А там, где это
считается — кэш (1.7×) и защита под атакой (origin exposure ~0%) — AEGIS уже
впереди nginx.

> Полный отчёт перф-исследования (методика, профиль, тупики io_uring/HeaderMap,
> «куда копать») — [docs/PERFORMANCE.md](../en/reference/performance.md).

## Что нового (V158 → V174) — Admin panel v2

Полный rebuild админ-панели. Раньше большая часть страниц была
observational (читала state, но не давала менять). Теперь оператор
управляет **всем что попадает в категорию A** из аудита: per-domain
overrides, per-endpoint policies, runtime filter toggles, ML kind,
reputation feeds — без редактирования config-файла и рестарта.

**Backend — per-domain control:**
- **V160 RuntimeToggles** ([src/filters/engine.rs](../../src/filters/engine.rs)) — runtime on/off per filter без рестарта, persisted в `/var/lib/aegis/runtime-toggles.json`, mtime-sync между worker'ами.
- **V162 DomainPolicy** ([src/domain_policy.rs](../../src/domain_policy.rs)) — `filter_enabled` overrides per host (force on/off конкретного фильтра только для одного сайта). Wins over global RuntimeToggles. Persisted + cross-worker.
- **V166 EndpointAction** — path-pattern → `allow/block/challenge/tarpit` короткое замыкание ДО filter chain. Operator: «атакуют /login → ставлю captcha там одним кликом».
- **V168 cross-worker persistence** — atomic JSON file + mtime-poll. Подтверждено: 10 запросов через 4 REUSEPORT воркера → 10/10 видят policy через ~50ms.

**Admin API additions:**

| Method | Path | Что |
|---|---|---|
| GET | `/admin/api/defaults/filters` | runtime toggle state каждого фильтра |
| PUT | `/admin/api/defaults/filters` | flip filter on/off (atomic, persistent) |
| GET | `/admin/api/sites/<host>/policy` | per-domain overrides + global filter list |
| PUT | `/admin/api/sites/<host>/policy` | atomic replace всей policy |
| DELETE | `/admin/api/sites/<host>/policy` | clear per-host overrides |
| GET | `/admin/api/runtime/info` | combined module state (ML/feeds/honeypot/infra) для Settings page |
| GET | `/admin/api/honeypots/builtin` | **V158 fix** — теперь возвращает ВСЕ 18 packs (раньше только operator-toggled) |

**Frontend — V169/V170/V171/V173 charts overhaul:**
- **Sites click-through** — каждая строка ведёт на `/sites/<host>` с 5 табами (Overview / Security / Endpoints / Rate limits / Honeypots).
- **Settings tabbed rebuild** (4 вкладки: General / ML & Detection / Reputation Feeds / Infrastructure).
- **Dashboard + Metrics enterprise charts** — sparklines под каждым KPI, live stacked area для traffic decisions / upstream / cache / XDP, donut с центральной метрикой, horizontal stacked bars per-domain, threat heatmap с HSL gradient.
- **Library `web/src/components/charts/`** — `useTimeSeries`/`useTimeSeriesMulti` hooks превращают polled cumulative counter в bounded rolling per-second series. Sparkline, LiveAreaChart, DonutChart, HBarStack, ThreatHeatmap.

**Per-module guides:**
- [docs/per-domain-policy.md](../en/reference/per-domain-policy.md) — V162/V166 backend + UI workflow + worked examples.
- [docs/client-consistency.md](../en/reference/client-consistency.md) — V145 JS snippet embed instructions, anti-detect detection signals.
- [docs/ml-pipeline.md](../en/reference/ml-pipeline.md) — V135-V151 retrain + adversarial loop operator guide.
- [docs/admin-api.md](../en/reference/admin-api.md) — exhaustive endpoint reference с curl examples.

## Что нового (V97 → V157)

**Защитные слои** (Phase E.2+ — ML + behavioural + adversarial loop):

- **ML scoring V97 → V139** — 23-feature логистическая регрессия + V136 GBM (gradient-boosted trees для feature interactions). Online retrain с L2-регуляризацией, stratified train/test split, AUC/F1/precision/recall/ECE метрики, active learning (uncertain-prediction picker), NDJSON persistence ([src/ddos/ml_score_v2.rs](../../src/ddos/ml_score_v2.rs), [ml_gbm.rs](../../src/ddos/ml_gbm.rs), [ml_training.rs](../../src/ddos/ml_training.rs), [ml_eval.rs](../../src/ddos/ml_eval.rs), [ml_model.rs](../../src/ddos/ml_model.rs)).
- **Fingerprint stack** — JA4 + JA4H + JA4T + JA4L + JA4S + JA4X + JA4TS + JA4LS + H2FP + H3FP + mTLS_FP + **V137 cross-fingerprint correlator** (Chrome JA4 + curl UA = bot) + **V145 CreepJS-style client consistency** (UA-vs-navigator.platform, webdriver flag, zero plugins, timezone mismatch) + **V155 p0f-style passive OS classification** ([src/fp_correlation.rs](../../src/fp_correlation.rs), [client_consistency.rs](../../src/client_consistency.rs), [p0f.rs](../../src/p0f.rs)).
- **Reputation feeds** — V138 JA4 reputation (community CTI + V107 honeypot mining) + V142 ASN/CIDR reputation + V144 MaxMind GeoLite2-ASN adapter ([src/ja4_reputation.rs](../../src/ja4_reputation.rs), [asn_reputation.rs](../../src/asn_reputation.rs), [geoip.rs](../../src/geoip.rs)).
- **WAF V109 → V156** — V124 wirefilter expression DSL, V125 CIDR coalescing, V146/V148 mutation engine (SQLi + XSS + cmd-injection — 8/7/7 mutators), V151 background adversarial loop (генерит 1500 вариантов / 5 мин, bypass'ы → trainer как Malicious labels), V156 SafeLine-style semantic SQL-injection detector (tokenize + intent detection — устойчив к V146 mutator set) ([src/sql_semantic.rs](../../src/sql_semantic.rs), [ml_adversarial.rs](../../src/ml_adversarial.rs)).
- **Anti-AI-crawler** — V147 Markov-chain poisoned tarpit с endless internal links (V152 HTTP endpoint на `/__aegis/tarpit/`, slow-streaming 5s/page) + V149/V154 robots.txt honeypot auto-labeling (Disallow visits → Malicious training samples) ([src/poisoned_tarpit.rs](../../src/poisoned_tarpit.rs), [robots_honeypot.rs](../../src/robots_honeypot.rs)).
- **CAPTCHA stack** — V131 Proof-of-Work (hashcash SHA-256, asymmetric — client тратит секунды CPU, server verifies за микросекунды) + V132 hCaptcha/Turnstile/reCAPTCHA pluggable providers ([src/pow_captcha.rs](../../src/pow_captcha.rs), [captcha_providers.rs](../../src/captcha_providers.rs)).

**Инфраструктура**:

- **V128/V130 firewall fallback** — XDP → nftables → iptables → userspace, автоматический выбор по доступности ([src/nftables_backend.rs](../../src/nftables_backend.rs), [iptables_backend.rs](../../src/iptables_backend.rs)).
- **V129 ClamAV** — TCP scanner для multipart/octet-stream upload bodies via INSTREAM ([src/clamav_scanner.rs](../../src/clamav_scanner.rs)).
- **V133 Terminal TUI** — Ratatui live dashboard для ssh-only deployments ([src/tui.rs](../../src/tui.rs)).
- **V134 ACME** — Let's Encrypt HTTP-01 challenge responder + cert-on-disk layout + renewal orchestrator ([src/acme.rs](../../src/acme.rs)).
- **V157 CrowdSec LAPI** — Aegis отдаёт решения в CrowdSec-compatible формате; любой существующий bouncer (nginx, HAProxy, Cloudflare worker, kubernetes ingress) enforces Aegis verdicts ([src/crowdsec_api.rs](../../src/crowdsec_api.rs)).

**Observability**:

- **V116 SecurityEvent** — структурированный событийный поток + per-decision Prometheus counters (cardinality-bounded `&'static str` reasons).
- **V127 EventBridge** — NDJSON Unix socket sink для SIEM (best-effort lossy broadcast, slow subscribers роняются).

Полная сводка изменений vs Synapse — SYNAPSE-COMPARISON.md.

## Установка в одну строку

```bash
curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash
```

Скрипт идемпотентный — повторный запуск обновляет до tip'а ветки. Что произойдёт:
- определит OS (Debian/Ubuntu/Fedora/Alpine) + архитектуру (amd64/arm64)
- поставит build-зависимости + rustup, склонирует репо, соберёт релизный бинарь
- создаст системного user'а `aegis`, директории `/etc/aegis/{,sites-enabled,sites-available,certs}` и `/var/lib/aegis/sites.d`
- сгенерирует self-signed cert + admin token + HMAC secret (все 0600, root:aegis)
- напишет hardened systemd unit (NoNewPrivileges, ProtectSystem=strict, ambient CAP_NET_BIND_SERVICE для портов 80/443)
- откроет порты в ufw/firewalld если активны
- стартанёт сервис, проверит что живой
- напечатает URL панели + admin token

После установки:

```
Web UI:        http://<server-ip>:6280/admin/ui
Admin token:   <напечатан в выводе; также в /etc/aegis/admin-token>
```

- По умолчанию запускается N = nproc worker'ов (один systemd-инстанс `aegis-pingora@N.service` на ядро, CPU-pinned через `CPUAffinity=%i`, SO_REUSEPORT). Число меняется на странице **Workers** в панели → `PUT /admin/api/topology` → повторный `sudo bash install.sh`. Состояние — `/var/lib/aegis/topology.json`.

Опции: `--uninstall` (сохранит `/etc/aegis`), `--purge` (удалит всё), `--version <ref>` (конкретная ветка/тег). Переменные окружения для тонкой настройки: `AEGIS_PORT_ADMIN`, `AEGIS_USER`, `AEGIS_SKIP_FIREWALL=1`, etc. См. шапку [install.sh](../../install.sh).

## Веб-панель (порт 6280)

Single-page React + TypeScript панель (Vite + Tailwind + shadcn/ui + TanStack Router/Query/Table + Monaco editor + Recharts). Production-сборка `web/dist` встраивается в бинарь Aegis через `include_dir!`, так что на хосте при рантайме Node.js не нужен — он требуется только в момент `cargo build`. Token вводится один раз и сохраняется в `localStorage`; параметр `#token=…` в URL принимается при первом заходе.

Страницы (35+, основные ниже; полный список — web/src/router.tsx):

- **Dashboard** (V170/V171) — 4 KPI карточки со sparkline'ами под каждым числом, ряд module-status (ML/JA4-rep/Honeypot/Domain-overrides), большой live stacked-area chart с decision rates over 5-минутным rolling window, donut со статусами, horizontal stacked bars per-host pressure, threat heatmap с HSL gradient (зелёный→жёлтый→красный по score).
- **Sites** — таблица + поиск, бейджи `TLS`, `UI` (managed) / `ops` (read-only), `+ Add site` мастер с превью сгенерированного DSL. Каждая строка кликабельна → `/sites/<host>`.
- **Site detail** (V165/V167/V172) — 5 табов:
  - **Overview** — per-host sparklines (Total/Denied/Challenged), live traffic stacked area отфильтрованный на этот host, site config, top endpoints с share-bar.
  - **Security** — per-domain filter overrides: на каждый фильтр radio inherit/force-on/force-off. Effective state vs global отображается inline.
  - **Endpoints** — auto-discovered paths (V119 site_map) с 2xx/4xx/5xx breakdown + 5 кнопок `inherit/allow/challenge/tarpit/block` на каждый endpoint.
  - **Rate limits** — RPS+burst editor с Clear override.
  - **Honeypots** — per-host pack toggle (18 packs).
- **Upstreams** — агрегаты по уникальным backend URL + статус healthcheck.
- **Certificates** — TLS-сайты, пути cert/key (read-only, изменения в конфиге).
- **Security** (V160) — Switch'и (не декорация) на каждый фильтр через `/admin/api/defaults/filters`. Optimistic updates, in-memory toggle, hint про persist через Config editor.
- **Bots** / **DDoS** / **Site map** (V120/V121) — аналитика V107 honeypot mining, V121 split bot vs DDoS.
- **Signature miner** (V106) — UI для auto-mined WAF candidates.
- **Honeypots** (V158) — 18 packs catalogue с toggle (раньше показывало 0/0).
- **Rate Limits** (V159) — inline RPS+burst editor per site + hot-URIs panel.
- **Config Editor** — Monaco editor с custom `aegis` language (подсветка + базовый autocomplete по ключевым словам DSL). Кнопки **Test** (dry-run parse через `/admin/api/config/test`) → **Save** (PUT в `/admin/api/config/raw`) → **Apply** (`/admin/reload`).
- **Audit log** (V161) — tail JSON-аудита, фильтр по подстроке, pause/resume polling.
- **Metrics** (V173) — Grafana-style: 4 KPI panels со sparkline'ами, 2×2 grid live area charts (traffic/upstream/cache/XDP), donut row + top-hosts, raw Prometheus dump с filter + export snapshot.
- **Settings** (V169) — 4 таба:
  - **General** — runtime info, session, change credentials, danger zone.
  - **ML & Detection** — V139 scorer kind, V151 adversarial loop state, V147 honeypot summary.
  - **Reputation Feeds** — V138 JA4 + V142 ASN status + entry counts.
  - **Infrastructure** — XDP / ACME / CrowdSec / ClamAV (NotWired graceful fallback).
- **Workers** (V232) — воркер-топология, CPU-affinity, рекомендации по масштабированию.
- **Arsenal** — live counters всех V176–V191 модулей.
- **Challenge ladder** — per-domain challenge конфигурация.
- **Updates** — read-only update-checker (write-endpoint самообновления удалён в V233).
- **Scenarios** — CrowdSec-style YAML behavioural detection.
- **Actuators** — реестр активных мер (XdpDeny / NftDrop / BgpAnnounce / ChallengeFloorRaise).
- **Sigma** — импорт Sigma-правил (SigmaHQ community, V196).
- **Enrichment** — WISE-style fan-out по intel-источникам.
- **Reputation** — JA4 + ASN reputation управление.
- **ML** — управление ML-моделями и adversarial loop.
- **PrivacyPass** — RFC 9576 token issuer конфигурация.
- **BGP RTBH** — FlowSpec/RTBH dispatcher управление.
- **Telemetry** — T-Pot-compatible NDJSON event export.
- **GeoIP** — страна-блок управление.
- **Cluster** — distributed state overview.
- **Tarpit** — slow-drip + poisoned tarpit конфигурация.
- **CrowdSec** — LAPI интеграция.
- **Logs** — streaming audit log.

Сборка фронтенда (выполняется автоматически в `install.sh`):
```bash
cd web
pnpm install
pnpm build            # → web/dist/index.html + assets/* (embedded в бинарь)
pnpm dev              # локально на :5173, проксирует /admin → :6280
```

Mock-режим без бэкенда: `VITE_USE_MOCKS=true pnpm dev` — все API возвращают синтетику из `web/src/api/mocks.ts` (удобно для UI-итераций).

JSON API за UI (RBAC через `x-admin-token`). Полный справочник —
[docs/admin-api.md](../en/reference/admin-api.md). Кратко:

| Method | Path | Role | Что |
|---|---|---|---|
| GET | `/admin/ui[/...]` | — | SPA bundle (любой неизвестный путь возвращает `index.html` для client-side router) |
| **Runtime / observability** | | | |
| GET | `/admin/api/runtime/status` | Read | uptime, requests counters, top threats, cache, XDP |
| GET | `/admin/api/runtime/info` | Read | V169 — combined module state (ML/feeds/honeypot/infra) для Settings page |
| GET | `/admin/api/filters` | Read | per-filter blocks/challenges counters |
| GET | `/admin/api/audit` | Read | tail audit log |
| GET | `/admin/api/bots` / `/ddos` | Read | V121 split analytics |
| GET | `/admin/api/site_map` / `/site_map/<host>` | Read | V119 auto-discovered endpoints |
| GET | `/admin/api/mined_signatures` | Read | V107 online miner candidates |
| **Sites CRUD** | | | |
| GET | `/admin/api/sites` | Read | список сайтов из managed + ops dirs |
| POST | `/admin/api/sites` | Write | добавить (upsert) → render DSL → write `<host>.conf` → reload |
| DELETE | `/admin/api/sites/<host>` | Write | удалить managed-файл → reload |
| **Per-domain policy** (V162/V164) | | | |
| GET | `/admin/api/sites/<host>/policy` | Read | per-host filter overrides + endpoint policies + global view |
| PUT | `/admin/api/sites/<host>/policy` | Write | atomic replace (persistent across workers via JSON file) |
| DELETE | `/admin/api/sites/<host>/policy` | Write | clear per-host overrides |
| **Runtime filter toggles** (V160) | | | |
| GET | `/admin/api/defaults/filters` | Read | runtime on/off per filter |
| PUT | `/admin/api/defaults/filters` | Write | flip filter(s) — `{updates: [{name, enabled}]}` |
| **Honeypots** | | | |
| GET | `/admin/api/honeypots/builtin` | Read | V158 — all 18 packs catalogue + enabled state |
| GET | `/admin/api/honeypots` | Read | full HoneypotState snapshot |
| PUT | `/admin/api/honeypots` | Write | atomic replace state |
| PUT | `/admin/api/honeypots/global` | Write | toggle one pack globally |
| PUT | `/admin/api/honeypots/host` | Write | per-host pack override |
| DELETE | `/admin/api/honeypots/hosts/<host>` | Write | clear per-host overrides |
| **Config editor** | | | |
| GET | `/admin/api/config/raw` | Read | сырой DSL основного конфига |
| PUT | `/admin/api/config/raw` | Write | dry-run parse → atomic rename → success (apply через POST /admin/reload; на pingora-порту 6280 — aegis-pingora --upgrade --config /etc/aegis/aegis.conf) |
| POST | `/admin/api/config/test` | Read | dry-run parse без записи |
| **XDP / threat scorer** | | | |
| GET | `/admin/xdp` | Read | per-IP deny/rate-limit counters |
| POST | `/admin/xdp/deny/<ip>` | Write | программно добавить IP в kernel deny map |
| POST | `/admin/xdp/undeny/<ip>` | Write | убрать |
| GET | `/admin/threats` | Read | top 50 IP по threat score (cluster-aware) |
| **V145 client consistency endpoint** | | | |
| **Worker topology** (V232) | | | |
| GET | `/admin/api/topology` | Read | live worker layout + рекомендация по масштабированию |
| PUT | `/admin/api/topology` | Write | желаемое число worker'ов → /var/lib/aegis/topology.json |
| **Update checker** (V233) | | | |
| GET | `/admin/api/updates/status` | Read | состояние update-checker |
| POST | `/admin/api/updates/check` | Write | форсировать проверку |
| POST | `/.well-known/aegis/consistency` | none | CreepJS JS snippet POST'ит сюда payload, ≤8 KiB body |
| **Auth** | | | |
| POST | `/admin/api/login` | none | `{email, password}` → `{ok, token, must_change_credentials}` |
| POST | `/admin/api/logout` | none | invalidate session token |
| GET | `/admin/api/me` | none | `{authenticated, email, role, must_change_credentials, auth}` |
| POST | `/admin/api/change-credentials` | none | force-change на first login |



---

## Содержание

1. [Архитектура и flow запроса](#архитектура-и-flow-запроса)
2. [Что реализовано](#что-реализовано)
   - [L4 — сеть и транспорт](#l4--сеть-и-транспорт)
   - [TLS / handshake](#tls--handshake)
   - [HTTP стек](#http-стек)
   - [L7 фильтры](#l7-фильтры)
   - [Арсенал обмана](#арсенал-обмана-deception-arsenal)
   - [Challenge ladder (vDDoS-style)](#challenge-ladder-vddos-style)
   - [Аномалии и автоматическая эскалация](#аномалии-и-автоматическая-эскалация)
   - [Распределённое состояние (Redis)](#распределённое-состояние-redis)
   - [Admin API + RBAC + аудит](#admin-api--rbac--аудит)
   - [Observability](#observability)
   - [Операционные качества](#операционные-качества)
3. [Результаты нагрузочного тестирования](#результаты-нагрузочного-тестирования)
4. [Конфигурация](#конфигурация)
5. [Запуск и сборка](#запуск-и-сборка)
6. [Production checklist](#production-checklist)
7. [Что осталось сделать](#что-осталось-сделать)
8. [Дальнейшее развитие по компонентам](#дальнейшее-развитие-по-компонентам)

---

## Архитектура и flow запроса

Production data plane = **pingora** (`aegis-pingora` binary, V72+).
Hyper-based handler (`aegis`) остаётся для HTTP/3 и dev-сред — те же
фильтры и тот же threat-state, отдельный transport.

```
                       ┌──────────────────────────────────────────────┐
TCP/UDP пакет     →    │ XDP fast-path (Linux, V45+)                  │
                       │  · ALLOW map (early PASS, fast_pass counter) │
                       │  · DENY map (early DROP)                     │
                       │  · per-IP rate + SYN-flood guard             │
                       │  · inline WAF (48 patterns, per-CPU array)   │
                       │  · allow_only (whitelist mode)               │
                       └──────────────┬───────────────────────────────┘
                                      │ (если PASS)
                       ┌──────────────▼───────────────────────────────┐
                       │ TCP accept (pingora REUSEPORT, N workers)    │
                       │  · PROXY protocol v1/v2 strip → real IP      │
                       │  · TLS: JA3+JA4 sniff + JA3-hash reject      │
                       │  · TLS: SNI resolver → per-host cert + mTLS  │
                       │  · h1/h2 slowloris + h2 reset cap            │
                       │  · h3: quinn+h3, отдельный tokio-runtime     │
                       └──────────────┬───────────────────────────────┘
                                      │
                       ┌──────────────▼───────────────────────────────┐
                       │ AegisPingoraProxy::request_filter            │
                       │                                              │
                       │ Early fast-paths (до полного build_ctx):     │
                       │  · cache HIT-FAST для trusted клиентов (V78) │
                       │  · /__aegis/verify intercept                 │
                       │                                              │
                       │ Полный pipeline:                             │
                       │  1. BypassMatcher → is_trusted               │
                       │  2. DynamicTrust + fp_cookie → is_trusted    │
                       │  3. AnomalyDetector::observe (per-host EMA)  │
                       │  4. GeoIP deny (static / attack-mode-only)   │
                       │  5. FilterEngine pipeline (config-ordered):  │
                       │     Honeypot → ThreatIntel → IpAcl → WAF →   │
                       │     Bot → Adaptive → [Plugins] → Challenge → │
                       │     RateLimit (per-IP + /24 + /16 + URI +    │
                       │     hot-URI tracker)                         │
                       │  6. ThreatTier derivation (V101):            │
                       │     tier = max(ThreatScorer, MlScorer) → Low/│
                       │            Medium/High                       │
                       │  7. ResponseCache::lookup_tiered             │
                       │     · Low: full TTL hit                      │
                       │     · Medium: hit if entry < TTL/2 old       │
                       │     · High: forced miss                      │
                       │  8. upstream_peer → forward (или 304/HIT)    │
                       │  9. response_body_filter: buffer для cache   │
                       │ 10. logging hook:                            │
                       │     · per-worker ThreatScorer record_*       │
                       │     · SharedScorer record_* (cluster-wide)   │
                       │     · cluster_bump_* (Phase D counters)      │
                       │     · DynamicTrust observe (enroll/revoke)   │
                       │     · ResponseCache::store (leader path)     │
                       │     · single-flight notify_waiters           │
                       │     · SiteMap::observe (cartography)         │
                       │     · LoginAbuseGuard::record (outcome)      │
                       └──────────────────────────────────────────────┘
```

Каждый слой может отдать `Allow`, `Deny` (custom status) или
`Challenge` (уровень для следующей рунги ladder).

### Cross-cutting state planes

| План | Storage | Лайфтайм | Кто читает / пишет |
|---|---|---|---|
| Per-worker ThreatScorer | `DashMap<IpAddr, WindowStats>` | tokio runtime | `record_*` после filter outcome; `/admin/threats` per-worker |
| **SharedScorer (V90-V94)** | `shm_open` + mmap arena → `AtomicHashMap` (IPv4 u32) + `AtomicHashMap128` (IPv6 u128) | survives worker restart, attached by всеми REUSEPORT процессами | Все воркеры record/score в одни байты; `/admin/threats source=cluster` |
| Cluster counters | SharedCounters slab (фиксированный AtomicU64 массив) | tied to arena | `cluster_bump(idx)` на hot-path; `aegis_cluster_*` метрики |
| ResponseCache | per-process sharded `LruCache` + cross-worker broadcast-purge файл mtime poll | tokio runtime, mtime watch | `lookup_tiered`/`store`; `POST /admin/cache/purge` |
| WAF compiled rules (V95) | `ArcSwap<CompiledRules>` (per-field AhoCorasick + HashMap) | hot-reload via файлы mtime | hot-path eval; `POST /admin/waf/reload` |
| MlScorer weights (V97) | `ArcSwap<Weights>` (8×f32 + bias) | optional disk path + hot-reload | hot-path inference; `train_step` для online SGD |
| Compaction (V94) | background tick (30s/worker) | tokio | `SharedScorer::cleanup_stale` ⇒ tombstones; `POST /admin/shared_scorer/compact` |

### Defensive scope (cumulative по версиям)

| Layer | Версия | Что даёт |
|---|---|---|
| eBPF XDP | V45+ | DDoS отбивка до user-space; inline 48-pattern WAF |
| Compiled WAF rules | V95 | Per-field AhoCorasick + LeftmostFirst; ~560 ns/req @ 250 rules |
| ML threat scoring | V97 | 8-feature logistic regression, <100 ns inference, online retrain |
| Tiered cache policy | V98 | Low/Medium/High → full TTL / TTL/2 / forced miss |
| Cluster scorer integrity | V90-V94 | Distributed attacker не может «обойти» per-worker scorer |
| Self-improving signatures | V99 | n-gram майнер из honeypot/tarpit логов → ranked WAF candidates |

---

## Что реализовано

### L4 — сеть и транспорт

#### eBPF/XDP fast-path (Linux)
Отдельный no_std crate `xdp/aegis-xdp-ebpf` компилируется под target `bpfel-unknown-none` (aya-ebpf). Userspace loader `src/xdp.rs` (фича `xdp`) грузит .o через aya, pin'ит к интерфейсу и mmap'ит BPF maps. Все методы — no-op на non-Linux.

- **DENY_V4 / DENY_V6** — HashMap<IP, u8>; матч → `XDP_DROP` до того, как пакет попадёт в userspace.
- **ALLOW_V4 / ALLOW_V6** — whitelist; матч → unconditional `XDP_PASS` (минует deny + rate).
- **`allow_only` mode** — всё, что не в ALLOW, дропается. Maintenance window / closed beta.
- **AEGIS_RATE_V4** — per-IPv4 rolling-window rate-limit с конфигурируемым `rate_burst` и `rate_window_ms` через `RATE_CFG` array.
- **AEGIS_SYN_V4** — *отдельный* счётчик только для TCP SYN-without-ACK, чтобы SYN-storm не съедал бюджет легитимного established трафика.
- **Counters** (через `/admin/xdp`): `pass`, `drop_deny`, `drop_rate`, `drop_allowonly`, `drop_syn`, `drop_waf` (инлайновый eBPF-WAF drop), `fast_pass` (allow-list fast-pass).
- **JA4T_V4** — BPF HashMap (src_ip, src_port) → SYN-fingerprint; захватывает TCP-опции SYN-пакета (window, MSS, WSCALE, option kinds) для JA4T; устаревшие записи вычищаются userspace'ом.
- **Hot reload**: `Reloader::sync_xdp_from` диффит desired vs applied set, делает только инкрементальные `insert/remove` в BPF map.

#### PROXY protocol v1 + v2
Свой парсер ([src/proxy_proto.rs](../../src/proxy_proto.rs)), без сторонних crates. Поддерживает:
- v1 текстовый: `PROXY TCP4|TCP6|UNKNOWN ...\r\n`
- v2 binary: 12-byte magic + version+command + family+proto + addr block
- `LOCAL` команда (LB health-checks без override)
- `Auto` режим (принимает любой формат)

Header consume'ится через `peek` + `read_exact` ДО того, как stream уходит в rustls / hyper — JA3 sniff и SNI видят правильный client IP. Strict v1/v2 режимы намеренно fail-closed на non-PROXY traffic.

### TLS / handshake

#### rustls 0.23 + ring backend
- TLS 1.2 / 1.3, ALPN (h2, http/1.1)
- Без `aws-lc-sys` (избегаем нативной зависимости)

#### SNI per-domain resolver ([src/tls_sni.rs](../../src/tls_sni.rs))
Свой `ResolvesServerCert`:
- mapping `host → CertifiedKey` (case-insensitive)
- fallback к default cert для unknown SNI / IP-only requests
- catch-all host'ы продолжают handshake'иться (не падают)

На pingora-пути resolver подключается через `TlsSettings` (BoringSSL accept callback). На legacy hyper-пути — через `TlsAcceptor`. Для h3 resolver передаётся через `QuicServerConfig::try_from(RustlsServerConfig)` — сертификат тот же по всем протоколам.

#### JA3 TLS fingerprinting ([src/ja3.rs](../../src/ja3.rs))
Свой парсер ClientHello (без `tls-parser` зависимости). Canonical Salesforce JA3 строка:

```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```

MD5 хеш совместим с публичными feed'ами (abuse.ch SSL Blacklist и т.д.). GREASE values (RFC 8701) отфильтрованы — браузеры с random GREASE дают стабильный хеш. Match при accept'е TLS → `peek` первого record'а с 250ms timeout → compare с `ja3_deny_hashes` → close socket до key-exchange.

### HTTP стек

#### HTTP/1.1 + HTTP/2 через Pingora (production) / hyper (legacy-бинарь)
Первичный production data plane — `aegis-pingora` (Pingora + BoringSSL); hyper-based handler (`aegis`) остаётся вторичным путём для HTTP/3 и dev-сред.

- ALPN negotiation, auto-detection
- **Slowloris guard** (`http1_header_read_timeout`): соединение режется если headers не закончились за `header_read_timeout_ms` (default 5s)
- **HTTP/2 Rapid Reset (CVE-2023-44487)**:
  - `h2_max_concurrent_streams` (default 200)
  - `h2_max_reset_streams` (default 100)
  - GOAWAY при превышении
  - На pingora-пути дополнительная защита от Rapid-Reset / CONTINUATION-flood через `src/proxy/h2_guard.rs` (CVE-2023-44487 + CVE-2024-27316)

#### HTTP/3 через quinn + h3 ([src/proxy/http3.rs](../../src/proxy/http3.rs))
- ALPN `h3` через тот же SNI resolver
- 0-RTT включён (`max_early_data_size = u32::MAX`)
- request body cap из `waf.max_body_bytes` (overflow → 413 через WafFilter, не silent truncate)
- `Alt-Svc: h3=":<port>"; ma=86400` стампается на h1/h2 ответах → клиенты автоматически апгрейдятся на следующий запрос

#### Per-protocol метрики
`aegis_requests_by_protocol{protocol="h1|h2|h3|other"}` — увидеть переход трафика на h3 после включения Alt-Svc.

#### Upstream routing
- `Upstream::from_url` парсит `http://host:port`
- `UpstreamRouter` маппит `Host` header → конкретный upstream, fallback к default
- per-domain `requests_per_second` и `burst` override

#### Per-upstream circuit breaker ([src/proxy/health.rs](../../src/proxy/health.rs))
- `UpstreamHealth` хранит per-host флаг unhealthy (был глобальный — теперь per-host)
- 3-секундный TCP probe в фоне
- `/admin/health` показывает unhealthy хосты + downtime

### L7 фильтры

#### Filter pipeline ([src/filters/engine.rs](../../src/filters/engine.rs))
`FilterEngine` first-wins: первый не-Allow результат (Deny / Challenge / Tarpit) немедленно возвращается, остальные фильтры не вызываются. Default action для пустого pipeline — настраивается.

#### `IpAclFilter` ([src/filters/ip_acl.rs](../../src/filters/ip_acl.rs))
- `deny` list → 403
- `allow` list → если непустой, всё остальное → Challenge (мягкий whitelist)

#### `WafFilter` ([src/filters/waf.rs](../../src/filters/waf.rs))
- **Built-in signatures** (5 категорий): SQLi (`union select`, `' or 1=1`, `sleep(`, `benchmark(`, `drop table`, `information_schema`), XSS (`<script`, `javascript:`, `onerror=`, `onload=`), command injection (`;cat`, `;wget`, `;curl`, `|bash`, `&& rm -rf`, `/bin/sh`), **path_traversal** (`../../`, `/etc/passwd`, `/proc/self/`, `..%2f`, `..%5c`), **ssrf** (`http://169.254.169.254`, `http://metadata.google`, `http://127.0.0.1`, `file://`, `gopher://`, `dict://`)
- **Canonicalization**: многопроходная (до 4 итераций) — повторный URL-decode (двойное/тройное кодирование), декод HTML-entities, стриппинг SQL-комментариев (`-- `, `#`, `/* */`), lowercase, `%2f`/`%5c` → `/`/`\`, удаление null-байт; работает на байтах (`&[u8]`), `memchr` SIMD
- **disable_signatures**: операторы могут отключить целые категории (`["sqli"]`) для false-positive heavy окружений
- **Custom rules** через TOML DSL: `{ id, field, op, value, action }`. Fields: `path`, `method`, `user_agent`, `header:<name>`, `query`, `body`, `header`, `referer`, `cookie`. Ops: `contains`, `equals`, `starts_with`, `regex`, `not_contains`. Actions: `deny`, `challenge`. Shadow/log mode: совпадение в shadow-режиме инкрементит счётчик, запрос не блокируется. Rule files горячо перезагружаются через mtime-watcher.
- **External rule files**: `rule_files = ["config/waf-rules.toml"]` — отдельные .toml с `[[rules]]` блоками; merge с inline на init/reload
- **Body inspection** (`inspect_body`): после collect body — проверка фактической длины (chunked uploads без `content-length` тоже ловятся) + signature scan всего принятого тела (bounded by max_body_bytes, по умолчанию 64 KiB) — V233 закрыл обход через вставку сигнатуры за offset 256 KiB; тело сканируется через from_utf8_lossy
- **Query string в `path`**: ctx.path = `path_and_query()` — signature ловит `?q=...UNION SELECT...`

`src/sql_semantic.rs` (V156) предоставляет независимый семантический детектор SQL-инъекций (токенизатор + распознавание intent, confidence score) как defence-in-depth сигнал параллельно с regex WAF.

#### `RateLimitFilter` ([src/filters/rate_limit.rs](../../src/filters/rate_limit.rs))
- Token bucket per-IP (DashMap<key, Bucket{tokens, last_refill}>)
- Per-domain rate overrides
- **Subnet aggregation**: параллельные buckets для `/24` (IPv4) или `/48` (IPv6) и `/16` (IPv4) или `/32` (IPv6) — defeats botnet pivoting. Multipliers (default 8x, 64x) для NAT pool tolerance
- **Per-URI budgets**: `pattern = "/login"` или `"/api/*"`, first-match-wins, отдельный bucket per URI+IP. Параллельно с per-IP — клиент не может pivot'нуть между URI и сжечь общий бюджет
- **Hot-URI detector**: sliding 1-сек окно per URI, log warning при превышении threshold, surface через `/admin/hot_uris` top-20 (observe-only)
- Cleanup stale buckets раз в 30 секунд

#### `BotFilter` ([src/filters/bot.rs](../../src/filters/bot.rs))
- Per-(IP,UA,lang,enc,path)-fingerprint reputation (DashMap, in-memory)
- Score base сигналы: пустой UA, scanner names (`curl`, `python-requests`, `sqlmap`, `nikto`, `nmap`, `wget`), длина path, SQLi/path traversal markers
- `challenge_score` → Challenge, `deny_score` → Deny + penalty window

#### `AdaptiveFilter` ([src/filters/adaptive.rs](../../src/filters/adaptive.rs))
- Per-IP сounter за 1-секундное окно
- При spike > `suspicious_rps_threshold` → Challenge + penalty

#### `ChallengeFilter` ([src/filters/challenge.rs](../../src/filters/challenge.rs))
- Per-IP escalation counter с TTL
- `reset(ip)` снимает escalation после успешной верификации
- **Удалён trivial bypass** (`x-aegis-verify: ok`) — только подписанный токен + bound IP считается решением

### Challenge ladder (vDDoS-style)

5 уровней escalation, выдаются через [src/proxy/http.rs](../../src/proxy/http.rs) (legacy) и [src/proxy/pingora_challenge.rs](../../src/proxy/pingora_challenge.rs) (production pingora) с реальной семантикой. Challenge ladder по умолчанию выключен — opt-in per domain (`ChallengeConfig` defaults to `enabled = false`).

| # | Level | HTTP | Что делает | Кого режет |
|---|---|---|---|---|
| 1 | `307` Headers | 307 Temporary Redirect + Set-Cookie + Location | Cookie возвращается на retry | bots без cookie support (~75%) |
| 2 | `200` Html | 200 + `<meta refresh>` | требует HTML-парсер | bots без HTML parse (~75%) |
| 3 | `click` Iframe | 200 с скрытым `<iframe src="/__aegis/verify">` | iframe load → cookie refresh | bots без iframe render (~80%) |
| 4 | `high` Javascript | 200 с PoW + canvas fingerprint | proof-of-work (IP-bound HMAC-signed nonce, verified server-side via `PowIssuer::verify_bound`, V234) + canvas + navigator + screen + tz | bots без JS engine (~90%) |
| 5 | `capt` Captcha | 200 с reCAPTCHA v2 form | пользователь решает; `verify_recaptcha` вызывает реальный Google siteverify, fails closed без секрета (V234; static-word bypass удалён) | автоматизированные tools (~99%) |

#### Token transport
- `Set-Cookie: aegis_token=<HMAC-SHA256(ip:nonce:exp)>; HttpOnly; SameSite=Lax; Path=/`
- Браузер re-send'ит автоматически; header `x-aegis-token` как fallback для API-клиентов
- `safe_return_url` фильтрует `//evil.com`, `http://`, CR/LF-injection — никаких open-redirect через Location

#### `/__aegis/verify` endpoint
- `GET` (iframe rung) → 204 + refresh cookie
- `POST` (captcha submit) → 303 + cookie + redirect к origin
- reCAPTCHA: site_key для рендеринга, secret — для server-side verify через Google siteverify (V234: реальная верификация, fails closed без секрета; статический word-match bypass удалён)
- `js_string_literal` escapes `<`, `>`, `&` в инлайн JS — защита от XSS через token / return URL

#### Behavioural fingerprint cookie
- JS challenge собирает: `navigator.userAgent / language / languages / platform / hardwareConcurrency / deviceMemory`, `screen.{width,height,colorDepth}`, `Intl.DateTimeFormat tz`, canvas 2D render → `toDataURL()` (GPU + fontset signature)
- FNV-1a 32-bit hash → 8 hex chars
- POST на `/__aegis/verify?fp=<hash>`
- Server подписывает `fp.<hash>:ip:exp` → `Set-Cookie: aegis_fp=<token>; Max-Age=86400`
- На каждом запросе: `fp_cookie_valid()` коротит challenge ladder (24h по умолчанию)
- Headless без canvas → degenerate fp видно сразу

### Арсенал обмана (Deception Arsenal)

Помимо классического тарпита Aegis содержит несколько модулей активного противодействия.

**Honeypot-паки** (`src/honeypot/`) — 18 встроенных паков с кураторскими списками URL, которые никогда не посещает реальный пользователь (WordPress/phpMyAdmin/Drupal/Joomla/XenForo-пути, секретные файлы `.env`/`.git`/`.aws`, веб-шеллы, SQL-дампы, CI/CD-конфиги, IoT-дефолты, Java-актуаторы, мониторинг-страницы). Любое совпадение — сигнал с нулевым false-positive. Оператор включает/выключает паки по хосту через admin UI без рестарта; состояние в `/var/lib/aegis/honeypots.json` с mtime-поллингом. `HoneypotMatcher` отбрасывает вырожденные паттерны (canonical form = `/`), чтобы ловушка не могла тарпитить корень сайта (V235).

**Slow-drip tarpit** (`src/honeypot/tarpit.rs`) — `TarpitBody` удерживает соединение сканера, эмитируя байты раз в 5 секунд через chunked-encoding. Ответ маскируется под `Apache/2.4.41` — нормальный HTTP 200, который «вот-вот закончится»; слот в пуле воркеров сканера заблокирован.

**Отравляющий тарпит** (`src/poisoned_tarpit.rs`) — вдохновлён Iocaine/Nepenthes/HellPot. Генерирует бесконечный контент через Markov-цепочку (обученную на corpus оператора) с внутренними ссылками обратно в тарпит; ИИ-скраперы, игнорирующие `robots.txt`, рекурсивно жгут вычислительный ресурс.

**LLM-ловушка** (`src/llm_honeypot.rs`) — по мотивам Galah: синтезирует контекстуально-правдоподобный HTTP-ответ через LLM-провайдер (OpenAI/Anthropic/Ollama за трейтом `LlmClient`). Semantic-hash кэш обеспечивает согласованность ответов на повторные запросы.

**robots.txt-ловушка** (`src/robots_honeypot.rs`) — автоматически маркирует визиты на `Disallow`-пути как `Malicious` в ML-тренере; бесплатная разметка датасета.

**Ложные заголовки CDN** (`src/decoy_headers.rs`) — Scrapling и адаптивные скраперы по заголовкам ответа определяют защитный CDN и грузят соответствующий playbook обхода. Aegis эмитирует поддельные заголовки Cloudflare / Akamai / Fastly / CloudFront (`Server: cloudflare`, `CF-RAY`, `CF-Cache-Status`, `__cf_bm`-cookie) — исключительно клиентам, уже помеченным как угроза. Атакующий выбирает неверный playbook и тратит время впустую.

### Аномалии и автоматическая эскалация

#### `AnomalyDetector` ([src/anomaly.rs](../../src/anomaly.rs))
Per-domain трекинг:
- **Sliding window** 10s → current RPS
- **EMA** с half-life 5min → baseline RPS

Trip при `current > baseline * multiplier` И `baseline > min_baseline_rps` (иначе тихий домен с 0→5 выглядел бы как 5x spike). Flag sticky на `attack_duration_secs` после каждого trip.

#### Реакция на attack flag
- **GeoIP `attack_mode_only`** активируется (dormant deny list начинает работать)
- **Challenge ladder** поднимается до `min_challenge_level` (`escalate_level` берёт HIGHER из organic-rung и attack-floor — repeat offender не демотируется)
- `/admin/anomaly` показывает активные атаки + remaining ms

### Распределённое состояние (Redis)

#### `ReputationStore` ([src/state/reputation.rs](../../src/state/reputation.rs))
- `incr_score(key, by, ttl)` — distributed bot reputation counter
- `mark_nonce(nonce, ttl)` — `SET NX` + `EXPIRE`, replay protection для challenge token

#### Atomic distributed token-bucket (Lua)
`consume_token(key, rate, burst, cost)` — Lua-скрипт в Redis:
- Атомарно: `HMGET tokens, ts → refill (now - ts) * rate → если < cost: throttle → иначе spend`
- Возврат: `Allowed{tokens_left}` или `Throttled{retry_after_ms}`
- Multi-instance проксей не double-spend бюджет на границе секунды
- Handler ставит `Retry-After` (sec) + `x-aegis-retry-after-ms`

#### Distributed bot scoring
- `distributed_bot_score(host, ip, ua, path)` — Redis-backed reputation
- **Skip при score == 0** (важный fix) — benign браузеры не аккумулируют counter и не trip'ают threshold спустя время

#### GeoIP ([src/geoip.rs](../../src/geoip.rs))
- MaxMind GeoLite2-Country .mmdb (mmap, zero-alloc lookup)
- Lazy load, fail-soft: битый mmdb → no-op + warning, сервер живёт
- `deny_countries` список ISO 3166-1 alpha-2 (case-insensitive)
- `attack_mode_only`: гейт активируется только когда `AnomalyDetector` flag'ает домен

### Admin API + RBAC + аудит

#### RBAC ([src/admin_auth.rs](../../src/admin_auth.rs))
- **Роли**: `Read < Write < Admin`
- **TokenRegistry**: env var `AEGIS_ADMIN_TOKEN` (implicit Admin) + `[[admin.tokens]]` с явной ролью
- **Constant-time compare** на каждом entry — нет timing leak
- Дубликаты токена → highest role wins
- **Без токенов** → все `/admin/*` отвечают 401

#### Endpoints
| Method | Path | Role | Что |
|---|---|---|---|
| GET | `/metrics` | none | Prometheus текст |
| GET | `/admin/health` | Read | unhealthy upstreams + downtime |
| GET | `/admin/threats` | Read | top-50 IP по threat score |
| GET | `/admin/xdp` | Read | XDP counters |
| GET | `/admin/hot_uris` | Read | top-20 hot URIs |
| GET | `/admin/anomaly` | Read | активные attack flags |
| POST | `/admin/xdp/deny/{ip}` | Write | hot blacklist |
| POST | `/admin/xdp/undeny/{ip}` | Write | hot remove |
| POST | `/admin/reload` | Admin | reload config + rebuild handler |
| POST | `/admin/stop` | Admin | graceful shutdown |

#### Audit log
- Каждый `/admin/*` запрос: `tracing::info!(target: "aegis::audit", ...)` со всеми полями (peer, method, path, role, status, ts)
- Опциональный JSON-line file (`admin.audit_log_path`)
- Auth failures и successes — оба audited

#### Hot reload через `Reloader`
- Раньше `/admin/reload` только переписывал `active_cfg` — handler не пересобирался, WAF rule file changes не применялись
- Теперь `Reloader::reload(cfg)` → `build_handler` → swap `handler` и `health_state` атомарно
- XDP deny/allow sets diff-reconciled (только инкрементальные `insert/remove`)

### Observability

#### `RuntimeMetrics` ([src/metrics/mod.rs](../../src/metrics/mod.rs))
Atomic counters + DashMap для per-domain. Полный Prometheus exposition format:

```
aegis_requests_total
aegis_requests_denied
aegis_requests_challenged
aegis_upstream_2xx / 4xx / 5xx / errors
aegis_domain_total{host="..."}
aegis_domain_denied{host="..."}
aegis_domain_challenged{host="..."}
aegis_requests_by_protocol{protocol="h1|h2|h3|other"}
aegis_request_latency_ms_bucket{le="1|5|10|25|50|100|250|500|1000|2500|5000|+Inf"}
aegis_request_latency_ms_sum
aegis_request_latency_ms_count
```

#### `ThreatScorer` ([src/ddos/score.rs](../../src/ddos/score.rs))
- Per-IP sliding window
- Weighted score: `denied + 0.5*challenged` / total → 0..100
- `top(n)` для `/admin/threats`
- Periodic cleanup

#### Per-domain stats persister ([src/domains.rs](../../src/domains.rs))
- Раз в 30s flush'ит `RuntimeMetrics.domain` в `config/domains.toml`
- Reboot восстанавливает agregated counters

#### Audit log
- `target: "aegis::audit"` → отдельный tracing layer (env filter friendly)
- JSON file для long-term retention

### Операционные качества

#### Graceful drain ([src/server.rs](../../src/server.rs))
- `TaskTracker` + `CancellationToken` (tokio-util)
- SIGTERM → drop listeners (no new connects) → `tracker.wait()` с timeout `graceful_shutdown_secs` → если истёк, `cancel` + `hyper::graceful_shutdown` + final 500ms grace

#### Hot config reload
- `/admin/reload` или конфиг-валидация через `cargo run -- reload`
- `Reloader` rebuilds handler atomically
- XDP deny/allow sets, GeoIP, anomaly state переинициализируются

#### Lib + bin split
- `src/lib.rs` re-exports modules → integration tests могут drive `ProxyHttpHandler::handle_collected` напрямую без процесса
- `src/main.rs` — тонкий CLI dispatcher

#### CI ([.github/workflows/ci.yml](../../.github/workflows/ci.yml))
- `fmt` job — `cargo fmt --check`
- `test` matrix (ubuntu + macos) — `cargo check + clippy -D warnings + cargo test`
- `xdp-feature` — Linux build с `--features xdp`
- `bpf-program` — nightly + bpf-linker, build BPF object, upload artifact
- `bench-smoke` — `aegis-bench --help` чтобы load tool не сгнил
- `e2e-load` — поднимает реальный aegis binary с mock upstream и прогоняет 15 сценариев (WAF SQLi/XSS, body 413, IP ACL, rate-limit burst, Slowloris, admin auth, admin endpoints, /metrics регрессия). Запускается на ubuntu + macos каждый push в main. Лог сохраняется как artifact.

#### E2E load harness (`bench/e2e-config.toml` + [src/bin/aegis-e2e.rs](../../src/bin/aegis-e2e.rs))
- Свой Rust harness без внешних зависимостей (hping3 и т.д. не нужны)
- Spawn'ит mock TCP upstream на free port → подставляет в шаблон конфига → запускает aegis как child process → ждёт `/metrics` readiness → прогоняет сценарии → scrape `/metrics`, diff counters → kill aegis
- Каждый сценарий ассертит на конкретный детерминированный invariant (статус-код + Δ счётчиков), без timing-sensitive порогов
- Запуск локально: `cargo run --release --bin aegis-e2e -- --aegis-binary target/release/aegis --config-template bench/e2e-config.toml`
- Нашёл реальный баг при первом прогоне: hyper `header_read_timeout` требовал `TokioTimer` — без него worker панику'eт; зафиксировано до релиза

---

## Конфигурация

Полный пример — [config/aegis.example.toml](../../config/aegis.example.toml). Кратко по секциям:

### `[server]`
```toml
listen = "0.0.0.0:8080"
request_timeout_ms = 10000
graceful_shutdown_secs = 10
header_read_timeout_ms = 5000        # Slowloris guard
h2_max_reset_streams = 100           # CVE-2023-44487
h2_max_concurrent_streams = 200
proxy_protocol = "off"               # off | v1 | v2 | auto
```

### `[admin]`
```toml
listen = "127.0.0.1:9090"
audit_log_path = "aegis-audit.log"   # JSON lines

[[admin.tokens]]
token = "READ_ONLY_SECRET"
role = "read"
[[admin.tokens]]
token = "ADMIN_SECRET"
role = "admin"
```
Альтернативно: `AEGIS_ADMIN_TOKEN` env var → implicit Admin role.

### `[tls]`
```toml
enabled = true
listen = "0.0.0.0:8443"
cert_path = "certs/server.crt"
key_path  = "certs/server.key"
h3_enabled = true
h3_listen = "0.0.0.0:8443"           # тот же порт по UDP

ja3_deny_hashes = [
  "e7d705a3286e19ea42f587b344ee6865",  # tor
  "6734f37431670b3ab4292b8f60f29984",  # sqlmap
]

[[tls.sni]]
host = "api.example.com"
cert_path = "certs/api.crt"
key_path  = "certs/api.key"
```

### `[storage]` (Redis)
```toml
redis_url = "redis://127.0.0.1:6379"
```

### `[geoip]`
```toml
db_path = "/etc/aegis/GeoLite2-Country.mmdb"
deny_countries = ["RU", "KP", "IR"]
attack_mode_only = false
```

### `[anomaly]`
```toml
enabled = true
window_secs = 10
multiplier = 3.0
min_baseline_rps = 10.0
attack_duration_secs = 60
min_challenge_level = "javascript"
```

### `[xdp]` (Linux + feature `xdp`)
```toml
enabled = true
interface = "eth0"
bpf_object_path = "xdp/aegis-xdp-ebpf/target/bpfel-unknown-none/release/aegis-xdp"
allow = ["192.0.2.10"]
allow_only = false
rate_window_ms = 1000
rate_burst = 10000
syn_burst = 200
```

### `[filters.*]`
```toml
[filters.ip_acl]
deny = ["192.0.2.1"]
allow = []

[filters.rate_limit]
enabled = true
requests_per_second = 50
burst = 100
subnet_buckets = true
subnet_24_multiplier = 8
subnet_16_multiplier = 64
hot_uri_rps_threshold = 100

[[filters.rate_limit.uri_budgets]]
pattern = "/login"
requests_per_second = 5
burst = 10

[filters.waf]
enabled = true
max_body_bytes = 65536
rule_files = ["config/waf-rules.example.toml"]
disable_signatures = []

[filters.challenge]
enabled = true
token_ttl_secs = 300
hmac_secret = "replace_with_long_random_secret"
fp_ttl_secs = 86400
captcha_site_key = "..."             # optional, reCAPTCHA v2
captcha_secret  = "..."

[filters.bot]
enabled = true
challenge_score = 60
deny_score = 90
penalty_seconds = 60

[filters.adaptive]
enabled = true
suspicious_rps_threshold = 200
penalty_seconds = 10
```

---

## Формат конфига

**Основной формат — nginx-подобный DSL** (`/etc/aegis/aegis.conf`). Старый TOML продолжает работать как legacy, auto-detection по расширению. Полный пример: [config/aegis.example.conf](../../config/aegis.example.conf).

### Quick start — добавить сайт

```nginx
server {
    listen 80;
    listen 443 ssl http2 http3;

    server_name blog.example.com;

    ssl_certificate     /etc/aegis/certs/blog.crt;
    ssl_certificate_key /etc/aegis/certs/blog.key;

    proxy_pass http://127.0.0.1:3003;

    rate_limit {
        requests_per_second 20;
        burst 50;
    }
}
```

```bash
aegis -t                                              # validate без рестарта
curl -X POST -H "x-admin-token: $TOKEN" \
     http://127.0.0.1:9090/admin/reload               # hot apply
```

### Поддерживаемые блоки

- **`admin { listen ...; token <role> <secret>; audit_log_path ...; }`** — admin endpoint + RBAC tokens
- **`defaults { request_timeout 10s; graceful_shutdown 10s; filters {...}; rate_limit {...}; }`** — глобальные дефолты
- **`server { listen ...; server_name ...; ssl_certificate ...; proxy_pass ...; filters {...}; rate_limit {...}; location ... {...}; }`** — per-host route
- **`include /etc/aegis/sites-enabled/*.conf;`** — glob expand, sort detrministic, cycle guard
- **`location /path/ { proxy_pass ...; rate_limit {...}; }`** — prefix
- **`location = /exact { ... }`** — exact match

### CLI

```bash
aegis -t                                    # validate, print summary, exit 1 on error
aegis -c /etc/aegis/aegis.conf config test  # то же
aegis config migrate --from old.toml --to /etc/aegis/aegis.conf  # TOML → DSL
aegis reload                                # validate locally, instruct curl POST
```

`aegis -t` показывает:

```
config ok
servers: 3
listeners:
  - 0.0.0.0:443 ssl http2 http3
  - 0.0.0.0:80
routes:
  - default -> http://127.0.0.1:8000
  - api.example.com -> http://127.0.0.1:3001
  - app.example.com -> http://127.0.0.1:3002
```

Ошибки человекочитаемые с file:line:col + suggestions:

```
config error: /etc/aegis/sites-enabled/blog.conf:6:5
  unknown server directive: `proxypass`
  did you mean: proxy_pass?
```

### Reload safety

`POST /admin/reload` сначала парсит + валидирует + строит новый handler. Если что-то падает — старый runtime продолжает работать, ответ описывает причину:

```
reload failed: /etc/aegis/sites-enabled/blog.conf:7:1
  server_name blog.example.com is already defined

related:
config error: /etc/aegis/sites-enabled/blog-old.conf:3:17
  previous definition of `blog.example.com`

Current runtime config was not changed.
```

### Миграция с TOML

```bash
aegis config migrate --from /etc/aegis/legacy.toml --to /etc/aegis/aegis.conf
aegis -c /etc/aegis/aegis.conf -t
```

Не полная nginx-совместимость. Это собственный DSL Aegis с похожим синтаксисом — `rewrite`, `fastcgi`, `upstream {}` блоки и прочие nginx-специфичные директивы не поддерживаются.

## Запуск и сборка

```bash
# Базовая сборка
cargo build --release

# С XDP fast-path (Linux)
cargo build --release --features xdp

# BPF program отдельно (nightly + bpf-linker)
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo +nightly build --release --manifest-path xdp/aegis-xdp-ebpf/Cargo.toml

# Запуск
./target/release/aegis --config config/aegis.example.toml start
# или
cargo run -- --config config/aegis.example.toml start
```

CLI commands: `start | stop | restart | reload | metrics | rules validate | domain {add|list|remove|stats} | config {test|migrate} | web {reset-admin|start|stop|status}`.

Тесты: `cargo test` (1176 unit + 21 integration; плюс harness'ы aegis-e2e и aegis-pingora-e2e). Clippy: `cargo clippy --all-targets -- -D warnings`.

---

## Production checklist

- [ ] `AEGIS_ADMIN_TOKEN` либо `[[admin.tokens]]` сконфигурированы
- [ ] `[filters.challenge].hmac_secret` — 32+ байт random
- [ ] TLS сертификат + key — не от Let's Encrypt staging
- [ ] Redis URL указывает на отдельную (не shared) instance
- [ ] `[storage.redis]` доступен с задержкой < 5ms
- [ ] `[geoip].db_path` указывает на свежий .mmdb (обновлять cron'ом)
- [ ] `proxy_protocol` соответствует тому, что присылает LB
- [ ] XDP программа собрана и pinned (для Linux fast-path)
- [ ] CAP_BPF + CAP_NET_ADMIN на бинаре (`setcap cap_bpf,cap_net_admin=eip`)
- [ ] graceful_shutdown_secs ≥ longest reasonable request
- [ ] Prometheus scrape `/metrics` каждые 15s
- [ ] Audit log file rotates через logrotate / systemd
- [ ] Health probe LB указывает на `/admin/health` с Read токеном
- [ ] WAF rule files — symlink на git-managed файл (для reload без rebuild)

---

## Что осталось сделать

Из roadmap'а на 25+ пунктов реализовано большинство. Открытые задачи:

### Средний приоритет
- [ ] **Threat-intel feed sync** — Spamhaus DROP/EDROP, GreyNoise sensors, FireHOL — hourly cron в `ip_acl.deny` + XDP map
- [ ] **Distributed challenge state в Redis** — challenge escalation сейчас per-instance; multi-proxy deployment теряет escalation history при failover

### Низкий приоритет / nice to have
- [ ] **OpenTelemetry traces** — `tracing-opentelemetry` для distributed tracing через upstream
- [ ] **HTTP/3 0-RTT replay protection через Redis nonce store** (есть для challenge, но не для general h3 0-RTT)

---

## Дальнейшее развитие по компонентам

Список того, что можно прокачать в каждой подсистеме — не roadmap, а pool идей для long-term direction.

### XDP / eBPF
- **eBPF DDoS scoring map** — агрегировать SYN-rate + packet-rate + conn-rate per IP в единый score в kernel, drop при превышении (а не только при явном rate-limit); сейчас scoring только в userspace
- **TCP SYN cookies в XDP** — отвечать SYN/ACK с cookie прямо из BPF, не открывая socket в kernel SYN queue (полностью отучает Linux от хранения half-open connections)
- **UDP amplification protection** — drop spoofed UDP с известных reflector ports (DNS 53, NTP 123, SSDP 1900, memcached 11211, chargen 19) если upstream их не использует
- **TCP fingerprinting (p0f-style) в XDP** — detect spoofed source IPs по TTL + window size + TCP options anomalies до того, как пакет попадёт в userspace
- **Conntrack pressure check** — drop new connections когда `/proc/sys/net/netfilter/nf_conntrack_count` > 80% от max
- **AF_XDP zero-copy** для сценариев с десятками миллионов pps — bypass kernel network stack полностью
- **GeoIP в XDP** через bpf-cidr-tree map — country lookup без userspace round-trip
- **eBPF в CNI mode (Cilium-style)** — Aegis как L4 LB в Kubernetes overlay
- **Per-IP entropy scoring** — random/encoded paths look bot-like; в BPF трекать частоту переходов по domains
- **XDP rate-limit IPv6** — сейчас только v4, нужен parallel SYN/RATE map keyed on [u8;16]

### TLS / handshake
- **JA4 / JA4S / JA4H fingerprinting** — newer, более robust чем JA3 (учитывает GREASE и enumeration order)
- **HTTP/2 fingerprinting** — Akamai-style hash из SETTINGS frame + WINDOW_UPDATE + PRIORITY ordering
- **mTLS / client cert** — для admin endpoints или upstream auth
- **OCSP stapling** — снижает latency cert validation у клиента
- **Post-quantum hybrid kex** (X25519MLKEM768) — rustls 0.23 поддерживает через feature
- **Session ticket key rotation** — automatic, чтобы старые ticket'ы expire'ались по schedule
- **Encrypted Client Hello (ECH)** — Cloudflare-style hiding SNI
- **Selective TLS termination** — для passthrough scenarios (upstream сам TLS, мы только L4 inspect)

### HTTP стек
- **HTTP/2 PRIORITY abuse protection** — `priority_dependency_chain` cap
- **HTTP/2 settings flood (CVE-2019-9515)** — cap SETTINGS frame rate per connection
- **HTTP/2 ping flood** — cap PING frame rate
- **WebSocket support** — h1 Upgrade handling + WS-specific filters (frame size, payload inspection)
- **gRPC awareness** — h2 trailers, gRPC status code passthrough, per-method rate limits
- **HTTP/3 datagram (RFC 9221)** для MASQUE / WebTransport
- **QUIC connection migration** — поддержка client IP change без re-handshake
- **HTTP semantic compression awareness** — decompress + re-inspect Brotli/gzip request bodies (сейчас WAF видит compressed bytes)
- **CONNECT method handling** — для HTTP/2 / HTTP/3 tunnels
- **Server push deprecation** — explicitly disable, чтобы не возникал amplification

### WAF
- **Regex engine** — `regex` crate с lazy_static; сейчас только substring match. Compiled regex per rule
- **OWASP ModSecurity CRS import** — парсер `.conf` файлов CRS rule set (paranoia levels, anomaly scoring)
- **Behaviour-based detection** — track request shape per session (e.g., 10 paths in 5 seconds → bot)
- **ML signatures** — отдельный модуль с lightweight model (tract-rust + ONNX); classifier на захардкоженных features
- **Content-type aware parsing** — JSON / XML body parse + scan structure, не bytes
- **Multipart form parser** — для file uploads (рейтинги, размер, magic bytes check)
- **Response inspection** — sensitive data leak detection (CC numbers, SSN patterns) в outgoing body
- **Per-domain WAF policy** — `[domains.<host>.waf]` overrides
- **WAF rule learning mode** — observe-only логирует, что бы matched, без блокировки
- **Custom rule actions** — `tag`, `score`, `delay`, `redirect`
- **CRS-compatible severity / category / phase** — переход на full ModSec semantics
- **Bot-specific signatures** — отдельный set правил под scrapers, не security tools
- **GraphQL query depth limit** — для GraphQL endpoints
- **JSON schema validation** — `[[filters.waf.json_schemas]]` для конкретных endpoints

### Rate limiting
- **GCRA (Generic Cell Rate Algorithm)** вместо token bucket — single state variable, точнее
- **Hierarchical token bucket** — per-tenant → per-user → per-IP, с borrowing между уровнями
- **Sliding log** для precise rate (вместо approximation) — для critical endpoints
- **Leaky bucket** для request shaping (smooth output, не cap input)
- **ASN-based aggregation** через MaxMind GeoLite2-ASN — defeats cross-ISP botnets
- **JA3-based aggregation** — все запросы с одним fingerprint делят бюджет
- **Adaptive rate** — автоматически снижать `requests_per_second` когда upstream 5xx растёт
- **Per-method rate** — GET свободно, POST/PUT строже
- **Request weight** — `/api/expensive` потребляет 10 tokens, `/static/` 1 token
- **Distributed sync** — gossip protocol между instances вместо Redis round-trip
- **Negative caching** — IPs that hit limit get cached как "denied" на N секунд без re-spend
- **Predictive throttling** — Holt-Winters прогноз RPS, throttle ДО переполнения

### Bot detection
- **JA3 + JA4 combo scoring** — single fingerprint в deny list + score-based escalation
- **TCP-level fingerprint** — IP TTL, window size, TCP options (p0f style)
- **HTTP header order fingerprint** — браузеры всегда шлют headers в стабильном порядке; HTTP client'ы — нет
- **Behaviour graph** — переходы по pages, mouse movement через JS challenge, scroll patterns
- **WebGL fingerprint** — beyond canvas, более точно различает реальный GPU vs headless software rendering
- **Audio fingerprint** — `AudioContext.createOscillator()` → headless даёт constant output
- **WebRTC IP leak detection** — verify публичный IP клиента vs claimed
- **Touch event detection** — mobile bots часто без touch events
- **Network timing fingerprint** — TLS handshake duration, TCP RTT pattern
- **Header consistency** — `User-Agent` claims Chrome, но JS challenge daн с другим `navigator.userAgent`
- **Reputation feeds** — Project Honey Pot, StopForumSpam, MaxMind GeoIP2 Anonymous IP

### Challenge ladder
- **WebAuthn passkey verification** — для admin / sensitive endpoints (FIDO2 hardware tokens)
- **JS challenge difficulty** — параметризованный PoW (100/1k/10k/1m iterations)
- **Challenge bypass list** — known good bots (Googlebot, Bingbot) по verified reverse DNS
- **Token rotation** — каждый N запросов re-issue новый fp cookie с обновлённым signature
- **Progressive enhancement** — start с softest rung, escalate по failure
- **Custom challenge pages** — per-domain branded HTML

### Anomaly / autoresponse
- **EWMA + N-sigma** для baseline (current = mean + 3*stddev → anomaly)
- **Per-URI baselines** — anomaly не только domain-wide, но и per endpoint
- **Auto-tightening response** — при attack flag дополнительно: rate down 10x, bot deny_score down 30%, challenge minimum up 1 rung
- **Alert webhook integration** — POST в Slack/Discord/PagerDuty при flag
- **Incident replay** — записывать первые 1000 requests attack'а в файл для post-mortem
- **Cross-domain correlation** — если 5 доменов одновременно flag'нуто → likely common attacker → escalate globally
- **Auto-revert** — после `attack_duration_secs` graceful степ-down (не сразу resume normal traffic level)
- **Manual override** — `POST /admin/attack/{host}` force enter attack mode

### Distributed state
- **Redis Cluster support** — sharding rate-limit buckets по `cluster slot`
- **Multi-region replication** — CRDT counters (replicated, eventually consistent) для cross-region rate
- **Per-tenant Redis isolation** — отдельный DB index или key prefix per upstream
- **In-memory L2 cache** — recent token-bucket decisions кэшируются 100ms (избегаем Redis round-trip)
- **Failover/circuit-break Redis** — при недоступности fall back to local bucket с warning, не серверу падать
- **KeyDB / Dragonfly compatibility** — multi-threaded Redis alternatives
- **etcd backend option** — для GitOps deployments где Redis нежелателен
- **Local SQLite для small-scale deployments** — без Redis вообще

### Admin / operations
- **Slack/Discord webhooks** для notifications
- **Prometheus AlertManager integration** — generic alerting rules
- **Hot-add rate limit override** через `POST /admin/rate/<host>`
- **Live config validation diff** — показать что изменится при reload перед apply
- **Backup/restore admin commands** — XDP deny list, hot URI history, anomaly state
- **Multi-tenant admin** — token scoped per upstream / per host
- **Audit log signing** — chain-of-hash для tamper-evidence

### Observability
- **OpenTelemetry traces** — `tracing-opentelemetry` → Jaeger/Tempo; trace через upstream
- **RED metrics** (Rate, Errors, Duration) — derived per-endpoint
- **USE metrics** (Utilization, Saturation, Errors) для resource health
- **Per-rule WAF hit counters** — какое правило сколько раз тригернуло (false-positive triage)
- **Grafana dashboard JSON** — ship as part of repo (`dashboards/aegis.json`)
- **Loki integration** — structured log shipping
- **Profiling endpoint** — `pprof`-compatible endpoint для CPU/heap profiles
- **`tokio-console` support** — live task introspection
- **eBPF program profiling** — `bpftool prog profile` integration; latency per BPF call
- **Sampling control** — high-volume счётчики семплировать (1:100) при overflow

### Deployment
- **Helm chart** для Kubernetes
- **Terraform module** для AWS / GCP / Hetzner
- **systemd unit file** + journald integration
- **Container image** (distroless + статический бинарь)
- **Reproducible builds** через `cargo --frozen --locked`
- **Signed releases** через sigstore/cosign
- **SBOM generation** через `cargo-sbom`
- **Health endpoint conventions** — `/healthz`, `/readyz`, `/livez` (Kubernetes-friendly)
- **Multi-arch builds** — arm64, riscv64

### Security
- **Supply chain scanning** — `cargo-deny`, `cargo-audit` в CI
- **Fuzzing** — `cargo-fuzz` для парсеров (PROXY proto, JA3, WAF DSL)
- **Memory-safety review** — `miri` для unsafe blocks
- **CodeQL / Semgrep** rules для Aegis
- **Penetration testing harness** — bench/ + slowhttptest + sqlmap automated suite
- **Threat model document** — STRIDE per компонент
- **Bug bounty rules** — scope, safe harbor
- **HSM / KMS support** для HMAC secrets (AWS KMS, GCP KMS, Vault)

### Performance
- **io_uring** на Linux через `tokio-uring` для accept loop
- **Zero-copy upstream forwarding** — `splice()` system call вместо userspace buffer
- **Profile-guided optimization** (PGO) build profile

---

Этот файл — описание текущего состояния и vision. Если что-то из roadmap'а нужно ускорить — открывай issue / коммить PR.
