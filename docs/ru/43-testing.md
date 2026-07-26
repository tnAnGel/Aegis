# Тестирование

Документ описывает стратегию тестирования AEGIS: организацию и объём тестов (≈1485 функций), как их запускать (`cargo test`, фичефлаги `pingora`/`xdp`, фильтры по библиотеке), а также назначение и запуск e2e-бинарников — нагрузочного `aegis-e2e`, pingora-смоука `aegis-pingora-e2e`, sqlmap-replay `aegis-sqlmap-replay` и распределённого `aegis-distbench`. Каждое утверждение привязано к реальному коду; частичное/opt-in покрытие отмечено честно.

См. также: [28-benchmarking.md](28-benchmarking.md) (производительность, отдельный инструмент `aegis-bench`), 42-текущее-состояние-STATUS.md, [10-waf.md](10-waf.md), [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

---

## 1. Слои тестирования

AEGIS использует три слоя тестов, дополняющих друг друга:

| Слой | Где живёт | Что проверяет | Как запускается |
|------|-----------|---------------|-----------------|
| Unit-тесты | inline-модули `#[cfg(test)] mod tests` внутри `src/**.rs` | логика отдельных модулей (парсеры, скореры, нормализация, конечные автоматы) | `cargo test --lib` |
| Интеграционные | `tests/integration.rs`, `tests/arsenal_integration.rs` | сквозной конвейер прокси и проводка Defence Arsenal через публичные точки входа библиотеки | `cargo test --test integration --test arsenal_integration` |
| E2E-бинарники | `src/bin/aegis-e2e.rs`, `src/bin/aegis-pingora-e2e.rs`, `src/bin/aegis-sqlmap-replay.rs`, `src/bin/aegis-distbench.rs` | поведение реального процесса/процессов AEGIS на настоящих сокетах | `cargo build --release --bin <имя>`, затем запуск бинарника |

Суммарно по репозиторию около **1485** тестовых функций (`#[test]` + `#[tokio::test]`): ≈**1453** в `src/` (unit) и **32** в `tests/` (интеграционные). Inline-`mod tests` присутствуют примерно в **140** файлах `src/`.

> Объём считается по разметке `#[test]`/`#[tokio::test]` в исходниках: `grep -rn '#\[test\]\|#\[tokio::test\]' src/ tests/ | wc -l`. Число — снимок текущего состояния ветки и меняется вместе с кодом.

---

## 2. Как запускать тесты

### 2.1. Базовый прогон

```bash
# Полный набор: unit + интеграционные + doctests + компиляция всех бинарников/примеров
cargo test --all-targets

# Только unit-тесты (быстро; без интеграционных бинарей)
cargo test --lib

# Конкретный интеграционный файл
cargo test --test integration
cargo test --test arsenal_integration
```

Так же, как это делает CI (`.github/workflows/ci.yml`, джоб `test`): `cargo check --all-targets` → `cargo clippy --all-targets -- -D warnings` → `cargo test --all-targets`. CI прогоняется на `ubuntu-latest` и `macos-latest`, плюс отдельный джоб `fmt` (`cargo fmt --all -- --check`). Глобально включён `RUSTFLAGS: "-D warnings"`, поэтому любое предупреждение компилятора валит сборку.

### 2.2. Фильтрация тестов (`--lib` + паттерны)

`cargo test` принимает подстроку имени теста как фильтр. Это особенно полезно с `--lib`, чтобы гонять только нужную подсистему:

```bash
# Все WAF-тесты (модуль src/filters/waf.rs — крупнейший набор, ~78 тестов)
cargo test --lib waf

# Только SQL-семантика
cargo test --lib sql_semantic

# Privacy Pass
cargo test --lib privacy_pass

# Один конкретный тест по полному имени модуля::функции
cargo test --lib filters::waf::tests::sqli_signature_matches

# Перечислить, что бы запустилось, без выполнения
cargo test --lib waf -- --list
```

Полезные флаги тест-харнесса (после `--`):

| Флаг | Назначение |
|------|------------|
| `-- --nocapture` | не глушить `println!`/stdout тестов |
| `-- --test-threads=1` | последовательный прогон (для тестов, чувствительных к окружению) |
| `-- --ignored` | запустить тесты, помеченные `#[ignore]` |
| `-- --list` | вывести список тестов без выполнения |

### 2.3. Фичефлаги

Тесты по умолчанию компилируются с `default = []` (см. `[features]` в `Cargo.toml`). Две опциональные фичи требуют явного включения:

```bash
# Pingora data plane (подтягивает openssl/pingora-* — большое дерево зависимостей)
cargo test --features pingora --all-targets

# XDP/eBPF fast-path (Linux-only; для рантайма нужны CAP_BPF + CAP_NET_ADMIN,
# но компиляция/юнит-тесты работают и без привилегий)
cargo test --features xdp --all-targets
```

CI отражает это отдельными джобами: `xdp-feature` (`cargo test --features xdp --all-targets` на Linux) и `bpf-program` (сборка eBPF-объекта `aegis-xdp` на nightly через `bpf-linker`). Тесты, специфичные для pingora-пути (например, `src/proxy/pingora_http.rs` ~26, `src/proxy/pingora_challenge.rs` ~28), компилируются только под `--features pingora`.

> Честная оговорка: e2e-бинарь `aegis-pingora-e2e` целиком заперт за `#![cfg(feature = "pingora")]` (`src/bin/aegis-pingora-e2e.rs:18`) — без фичи он компилируется в пустышку и ничего не проверяет.

---

## 3. Интеграционные тесты конвейера (`tests/integration.rs`)

Это сквозные тесты обработчика прокси. Каждый тест поднимает **настоящий upstream** на свободном TCP-порту (`spawn_mock_upstream`, по одной tokio-задаче на тест) и напрямую дёргает `ProxyHttpHandler::handle_collected`, прогоняя полный конвейер (distributed-проверки → WAF → bot → adaptive → rate-limit → challenge → форвард на upstream) на реальных сокетах, не поднимая публичные слушатели.

Хелпер `build_handler(...)` собирает обработчик с предсказуемой конфигурацией: цепочка фильтров `IpAcl → Waf → Bot → Adaptive → Challenge → RateLimit` (`FilterEngine::new(..., DefaultAction::Allow)`), `NoopXdp`, `NoopGeoIp`, временный `HoneypotStore` в `temp_dir`, дефолтные `AnomalyDetector`, `DynamicTrustConfig`, `ResponseCacheConfig`.

Покрываемые сценарии (`#[tokio::test]`):

| Тест | Утверждение |
|------|-------------|
| `upstream_passthrough_returns_body` | чистый GET доходит до upstream, тело возвращается, upstream получил 1 хит |
| `waf_sqli_signature_blocks_before_upstream` | URL-энкоженный `UNION SELECT` в query → `403 FORBIDDEN`, тело содержит `sqli`, upstream **не** тронут |
| `ip_acl_deny_short_circuits` | IP из deny-списка → `403`, без хита на upstream |
| `rate_limit_returns_429_after_burst` | при `burst=2` первые два запроса проходят, третий → `429 TOO_MANY_REQUESTS` |
| `challenge_ladder_emits_set_cookie_and_step_header` | первый шаг лестницы → `307`, заголовки `location`, `x-aegis-step: headers`, `Set-Cookie: aegis_token=...; HttpOnly` |
| `challenge_cookie_round_trip_passes_to_upstream` | повтор с валидным `aegis_token` → `200` + проброс на upstream |
| `waf_body_inspection_catches_signature_in_payload` | SQLi в теле POST → `403`, upstream не тронут |
| `waf_body_size_limit_returns_413` | тело 4096 Б при `max_body_bytes=1024` → `413 PAYLOAD_TOO_LARGE` |
| `upstream_unavailable_returns_502` | мёртвый upstream → `502 BAD_GATEWAY` |
| `fingerprint_cookie_short_circuits_challenge` | POST на `/__aegis/verify?...&fp=...` ставит `aegis_token` + `aegis_fp`; долгоживущий `aegis_fp` в одиночку обходит лестницу |
| `verify_endpoint_with_invalid_token_rejects` | `/__aegis/verify` с фальшивым токеном → `403` |

Запуск:

```bash
cargo test --test integration
cargo test --test integration challenge      # только challenge-сценарии
```

---

## 4. Интеграция Defence Arsenal (`tests/arsenal_integration.rs`)

Назначение (V194, см. шапку файла): доказать, что модули Defence Arsenal действительно «двигают» счётчики при вызове из тех же точек входа библиотеки, что и горячий путь прокси. Если эти тесты падают — проводка в `src/bin/aegis-pingora.rs` производит мёртвое состояние, и любые заявления про «живые счётчики» оказываются ложью. Тесты НЕ поднимают HTTP-сервер; они дёргают `ArsenalState` и связанные модули напрямую.

Покрываемые модули и инварианты:

| Тест | Модуль / API | Что проверяет |
|------|--------------|----------------|
| `ja4_corpus_lookup_bumps_counter` | `ja4_corpus` | lookup по JA4-строке возвращает вердикт, счётчики `ja4_corpus_lookups`/`ja4_corpus_allow_hits` растут |
| `ja4_churn_observe_tracks_ip` | `ja4_churn` | ротация JA4 у одного IP даёт высокий churn (>0.9) |
| `h2_observe_bucket_consumes_and_rejects` | `observe_h2_frame` / `h2_budget` | бюджет HTTP/2-фреймов (RST_STREAM) допускает ~40–60 из 120, остальные отвергает; счётчики `h2_budget_allows`/`rejects` точны |
| `rule_plan_install_and_dispatch_round_trip` | `rule_planner::RulePlan` | установка плана и диспетчеризация по фазам (`RequestUriOrQuery`, `RequestHeaders`) |
| `waf_rule_descriptors_translate_to_planner_phases` | `WafFilter::rule_descriptors` | кастомные + встроенные правила раскладываются по фазам URI/headers/body |
| `honeypot_responder_returns_synth_with_counter` | `honeypot_respond` | синтетический ответ + рост `llm_honeypot_responses` либо `yaml_honeypot_engagements` |
| `bgp_rtbh_announce_then_withdraw` | `bgp_rtbh` | announce/withdraw меняют размер и счётчики `bgp_rtbh_announces`/`withdraws` |
| `grease_extract_parses_chrome_shaped_handshake` | `ja4::extract_grease_positions` | разбор синтетического ClientHello с GREASE на позиции 0 |
| `route_difficulty_ai_scraper_ua_bumps` | `route_difficulty` | UA `GPTBot` повышает сложность challenge относительно браузерного UA |
| `decoy_headers_produce_cloudflare_shape` | `decoy_headers` | семейство Cloudflare даёт `server`, `cf-ray`, `alt-svc` |
| `sicherheitstacho_renders_valid_ndjson` | `sicherheitstacho` | корректный NDJSON для SIEM с полями `category`, `src_ip`, `request` |
| `latency_jitter_distribution_sensible` | `latency_jitter` | дефолтный tarpit-jitter центрируется ~200–900 мс |
| `timing_entropy_flags_synthetic` | `timing_entropy` | равномерные интервалы мыши/скролла → высокий `anomaly_score` |
| `normalisation_chains_url_html` | `normalisation` | цепочка URL→HTML декодирования восстанавливает `<script>` |
| `param_profile_anomaly_after_training` | `param_profile` | после обучения на 6-значных числах `<script>` оценивается аномально |
| `actuator_registry_applies_and_reverts_via_arsenal` | `actuator` | `XdpDeny` применяется и авто-откатывается по TTL через `tick()` |
| `enrichment_facade_aggregates_two_sources` | `enrichment` | агрегация двух источников: `Deny` доминирует, `sources.len()==2` |
| `scenario_engine_fires_block_after_capacity_via_arsenal` | `scenarios` | YAML-сценарий `brute_login` срабатывает (`Fired`) после исчерпания `capacity` |
| `arsenal_counters_include_new_module_fields` | `counters::snapshot` | контракт формы структуры счётчиков (поля компилируются) |
| `sigma_imported_toml_loads_through_waf_rule_file_parser` | `config::WafRule` | импортированный `rules/sigma/sigma-webserver.toml` грузится как `rule_files` (>100 правил, ≥2 уровней severity); **тест-скип**, если файл не сгенерирован локально |
| `sql_semantic_with_normalisation_catches_doubled_encoded` | `sql_semantic` | двойное URL-кодирование SQLi (`%2527...`) набирает высокий score |

Запуск:

```bash
cargo test --test arsenal_integration
```

> Оговорка по `sigma_imported_toml_*`: `rules/sigma/sigma-webserver.toml` — генерируемый артефакт (см. бинарь `aegis-sigma-import`). Если его нет, тест аккуратно делает `return` и считается пройденным, ничего не проверяя. Чтобы тест реально что-то валидировал, корпус нужно предварительно сгенерировать.

---

## 5. E2E-бинарники

E2E-харнессы оформлены как отдельные бинарники в `src/bin/`, а не как `#[test]`-функции, потому что они спавнят реальные процессы AEGIS и/или требуют сетевой настройки хоста. Их нужно сначала собрать (как правило в `--release`), затем запустить.

### 5.1. `aegis-e2e` — нагрузочный харнесс (hyper-бинарь)

`src/bin/aegis-e2e.rs` спавнит **настоящий процесс `aegis`** против mock-upstream и прогоняет каждый крупный гейт, проверяя одновременно (а) наблюдаемые HTTP-статусы и (б) дельты счётчиков `aegis_*`, соскрейпленных из `/metrics`. Тихая остановка эмиссии метрик валит сборку так же громко, как и WAF-правило, пропускающее атаку. Рассчитан на CI: ограниченное время (~30 с), всё на `127.0.0.1`, без внешних зависимостей (нет Redis/GeoIP), без флейки на таймингах.

Аргументы (`clap`):

| Флаг | По умолчанию | Назначение |
|------|--------------|------------|
| `--aegis-binary` | `target/release/aegis` | путь к тестируемому бинарю |
| `--config-template` | `bench/e2e-config.toml` | шаблон конфига с плейсхолдерами |
| `--startup-timeout-secs` | `10` | ожидание готовности AEGIS |
| `--dump-metrics` | (флаг) | печатать полный `/metrics` даже при успехе |

Шаблон конфига `bench/e2e-config.toml` патчится на лету: `__AEGIS_LISTEN__`, `__ADMIN_LISTEN__`, `__UPSTREAM_URL__`. В нём WAF и rate-limit включены (`requests_per_second = 5`, `burst = 5`, `max_body_bytes = 4096`), а challenge/bot/adaptive выключены, чтобы WAF- и rate-limit-сценарии не перехватывались несвязанной эскалацией; `header_read_timeout_ms = 1000` нужен сценарию Slowloris. Admin-токен передаётся через `AEGIS_ADMIN_TOKEN=e2e-admin-token`.

Проверяемые сценарии (выдержка из `run_scenarios`):

1. `baseline_passthrough` — ≥3 ответа `200`, upstream получил ≥3 хита;
2. `waf_sqli_query_blocked` — 5×`403` на SQLi в query;
3. `waf_xss_query_blocked` — 5×`403` на XSS в query;
4. `waf_body_sqli_blocked` — SQLi в теле POST → `403`;
5. `waf_body_size_413` — тело 16 КБ при лимите 4 КБ → `413`;
6. `ip_acl_loaded_without_self_lock` — deny `198.51.100.99` загружен, но `127.0.0.1` не заблокирован;
7. `rate_limit_burst` — из 50 параллельных запросов ≥10 получают `429`;
8. `slowloris_connection_killed` — недописанный запрос рвётся в пределах `header_read_timeout`;
9. `admin_unauth_rejected` — неверный `x-admin-token` → `401`;
10. `admin_authorized_passes` — верный токен → `200`;
11. `admin_read_endpoints_alive` — `/admin/threats`, `/admin/xdp`, `/admin/hot_uris`, `/admin/anomaly` отвечают `200`;
12. Регрессия метрик — дельты `aegis_requests_total > 0`, `aegis_requests_denied > 0`, наличие `aegis_request_latency_ms_count` и серий `aegis_requests_by_protocol`.

Запуск (как в CI-джобе `e2e-load`):

```bash
cargo build --release --bin aegis --bin aegis-e2e
./target/release/aegis-e2e \
    --aegis-binary ./target/release/aegis \
    --config-template bench/e2e-config.toml \
    --dump-metrics
```

Ненулевой код выхода означает, что хотя бы один сценарий упал (список печатается в `=== scenario results ===` с пометкой `FAIL`).

### 5.2. `aegis-pingora-e2e` — смоук pingora data plane

`src/bin/aegis-pingora-e2e.rs` (V64) зеркалит `aegis-e2e` по форме, но целится в openssl-бэкенд бинаря `aegis-pingora`. Файл целиком под `#![cfg(feature = "pingora")]`. Спавнит реальный `aegis-pingora` против in-process mock-upstream и пишет временный конфиг в формате nginx-подобного DSL (блоки `admin { ... }`, `defaults { ... }`, `server { ... }`), путь honeypot-стейта передаётся через `AEGIS_HONEYPOT_STATE`, кэш ответов включается `AEGIS_RESPONSE_CACHE_ENABLE=1`.

Аргументы: `--binary` (по умолчанию `target/release/aegis-pingora`), `--aegis-port`/`--admin-port`/`--upstream-port`, `--admin-token`, `--startup-secs`.

Тесты (`run_tests`):

| № | Проверка |
|---|----------|
| 1 | plain GET → `200`, тело содержит `ok` |
| 2 | WAF path-traversal `/../../etc/passwd` → `403`, тело содержит `blocked` |
| 3 | `/metrics` публичен (`200`) и содержит `aegis_requests_total` |
| 4 | `/admin/cache` без токена → `401` |
| 5 | `/admin/cache` с неверным токеном → `401` |
| 6 | `/admin/cache` с верным токеном → `200`, тело содержит `cache_hits` |
| 7 | `/health` → `200`, тело начинается с `ok` |
| 8 | два одинаковых GET → счётчики `aegis_cache_hits`/`aegis_cache_misses` не нулевые |
| 9 | `POST /admin/cache/purge?all=1` с токеном → `200` |
| 10 | `POST /admin/api/config/test` с валидным конфигом → `ok:true` |
| 11 | `POST /admin/api/config/test` с битым конфигом → `ok:false` |
| 12 | `POST /admin/api/sites` с битым JSON → `400` |
| 13 | `POST /admin/api/honeypots/packs/wordpress {"enabled":false}` → `200`, `ok:true` |

Запуск (см. шапку файла):

```bash
cargo build --release --features pingora --bin aegis-pingora
cargo build --release --features pingora --bin aegis-pingora-e2e
./target/release/aegis-pingora-e2e
```

При успехе печатает `PASS: aegis-pingora end-to-end smoke green`; при падении — `FAIL: ...` и `exit(1)`.

### 5.3. `aegis-sqlmap-replay` — матрица обхода WAF

`src/bin/aegis-sqlmap-replay.rs` (V118): оператор наводит инструмент на запущенный AEGIS (или любой URL), и тот прогоняет SQLi-пейлоад в сыром виде И после каждого sqlmap-эквивалентного tamper'а, печатая матрицу покрытия. Строка с пометкой `! BYPASSED` — это брешь в WAF: tamper-вариант вернул не-`403`. Это НЕ полный порт sqlmap; реализованы ~12–15 наиболее ходовых tamper'ов из каталога `tamper/` sqlmap.

Аргументы: `--target` (по умолчанию `http://127.0.0.1/`; пейлоад добавляется как `?q=<payload>`), `--payload` (по умолчанию `union select 1,2,3 from users`), `--chain` (список tamper'ов через запятую, накладываются поверх каждой итерации — как `--tamper` в sqlmap), `--timeout-secs`.

Реализованные tamper'ы (массив `tampers`): `space2comment`, `space2morecomments`, `space2dash`, `space2hash`, `space2plus`, `randomcase`, `backticks`, `htmlencode_dec`, `htmlencode_hex`, `charencode`, `chardoubleencode`, `versionedkeywords`, `appendnullbyte`, `equaltolike`, `apostrophenullencode`.

Логика вердикта: `403` → `OK`; любой другой статус → `! BYPASSED`; ошибка запроса → `! ERROR`. При наличии хотя бы одного bypass процесс завершается `exit(2)`.

```bash
cargo build --release --bin aegis-sqlmap-replay
./target/release/aegis-sqlmap-replay --target http://127.0.0.1:8080/

# С цепочкой tamper'ов (как sqlmap --tamper)
./target/release/aegis-sqlmap-replay \
    --target http://127.0.0.1:8080/ \
    --chain space2comment,htmlencode_hex,backticks
```

> Это инструмент проверки **развёрнутого** инстанса, а не unit-тест. Он показывает реальное покрытие именно той конфигурации WAF, на которую наведён. См. [10-waf.md](10-waf.md).

### 5.4. `aegis-distbench` — симулятор распределённой атаки

`src/bin/aegis-distbench.rs` (V105): pingora-listener видит peer-адрес из `accept()`, т.е. source-IP подключения. Алиасируя loopback на `127.0.0.2 .. 127.0.0.{N+1}` и привязывая каждое соединение к своему алиасу, можно сымитировать N атакующих против одного AEGIS без поддержки PROXY-протокола на слушателе. Каждый «источник» получает свой hyper-клиент, чей `HttpConnector` биндит исходящий TCP на свой IP (`set_local_address`) — именно это заставляет per-IP-скорер AEGIS видеть разных атакующих.

Аргументы: `--target` (обязателен), `--sources` (по умолчанию 50), `--requests-per-source` (200), `--concurrency-per-source` (4), `--path` (по умолчанию `/?q=union+select+1` — попадёт в WAF, если включён), `--timeout-secs` (60). Вывод: суммарный RPS, распределение статусов (`200`/`403`/errors), принятые байты.

Предусловие на Linux — заранее создать алиасы:

```bash
for i in $(seq 2 51); do sudo ip addr add 127.0.0.$i/8 dev lo; done

cargo build --release --bin aegis-distbench
./target/release/aegis-distbench \
    --target http://127.0.0.1:8080/ \
    --sources 50 --requests-per-source 200 --concurrency-per-source 4
```

> Это нагрузочный/поведенческий стенд для проверки кросс-воркерной агрегации и per-IP-скоринга (шапка предлагает заглянуть в `/admin/threats` после прогона), а не pass/fail-тест. Подробнее о методологии нагрузки и честных оговорках по ёмкости — [28-benchmarking.md](28-benchmarking.md).

---

## 6. Покрытие по подсистемам

Распределение unit-тестов по модулям `src/` (снимок; считается по `#[test]`/`#[tokio::test]`). Наиболее плотно покрыты гейты горячего пути и парсеры:

| Подсистема / файл | ≈ тестов | Документ |
|-------------------|----------|----------|
| `src/filters/waf.rs` | ~78 | [10-waf.md](10-waf.md) |
| `src/proxy/response_cache.rs` | ~47 | [27-performance-tuning.md](27-performance-tuning.md) |
| `src/ml_adversarial.rs` | ~40 | [18-ml-risk-engine.md](18-ml-risk-engine.md) |
| `src/challenge_signals.rs` | ~40 | [15-challenge-ladder.md](15-challenge-ladder.md) |
| `src/domain_policy.rs` | ~29 | [26-sites-and-domains.md](26-sites-and-domains.md) |
| `src/real_ip.rs` | ~28 | [07-protocols.md](07-protocols.md) |
| `src/proxy/pingora_challenge.rs` | ~28 (под `pingora`) | [15-challenge-ladder.md](15-challenge-ladder.md) |
| `src/proxy/pingora_http.rs` | ~26 (под `pingora`) | [02-architecture.md](02-architecture.md) |
| `src/proxy/http.rs` | ~25 | [02-architecture.md](02-architecture.md) |
| `src/sql_semantic.rs` | ~23 | [10-waf.md](10-waf.md) |
| `src/filters/login_abuse.rs` | ~23 | [14-rate-limiting.md](14-rate-limiting.md) |
| `src/filters/graphql.rs` | ~23 | [10-waf.md](10-waf.md) |
| `src/sigma.rs` | ~20 | [10-waf.md](10-waf.md) |
| `src/client_consistency.rs` | ~20 | [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| `src/site_map.rs` | ~18 | [26-sites-and-domains.md](26-sites-and-domains.md) |
| `src/privacy_pass.rs` | ~18 | [16-privacy-pass.md](16-privacy-pass.md) |
| `src/poisoned_tarpit.rs` | ~18 | [17-honeypot-tarpit.md](17-honeypot-tarpit.md) |
| `src/p0f.rs` | ~17 | [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| `src/normalisation.rs` | ~17 | [10-waf.md](10-waf.md) |
| `src/honeypot/matcher.rs` | ~17 | [17-honeypot-tarpit.md](17-honeypot-tarpit.md) |

Агрегаты по крупным семействам модулей (поиск по подстроке имени теста, удобно для `cargo test --lib <подстрока>`):

| Семейство (паттерн) | ≈ тестов |
|---------------------|----------|
| `filters` (вся директория `src/filters/`) | ~240 |
| `ml` (ML risk engine + adversarial) | ~105 |
| `waf` (по подстроке имени) | ~86 |
| `challenge` (лестница + сигналы) | ~79 |
| `ja4` (фингерпринтинг) | ~48 |
| `reputation` | ~25 |
| `rate_limit` | ~15 |
| `ja3` | ~6 |

> Числа — приблизительные снимки и колеблются при правках. Авторитетный способ получить актуальную цифру для подсистемы — `cargo test --lib <паттерн> -- --list`.

Покрытие за пределами unit-уровня:

- **Не покрыто автотестами в строгом pass/fail-режиме:** XDP/eBPF kernel fast-path под нагрузкой (тесты `--features xdp` проверяют компиляцию и логику loader'а, но не реальное прикрепление BPF — для него нужны привилегии и NIC), BGP RTBH через настоящий ExaBGP (в `arsenal_integration` проверяется только in-memory announce/withdraw), внешние интеграции (Redis-rate-limit, CrowdSec LAPI, threat-intel, GeoIP-БД) — e2e-харнессы намеренно работают без них.
- **Покрыто только через развёрнутый инстанс (opt-in инструменты):** реальная стойкость WAF к обходам (`aegis-sqlmap-replay`), кросс-воркерная агрегация под распределённой нагрузкой (`aegis-distbench`).

---

## 7. Как добавлять тесты

### 7.1. Unit-тест (предпочтительный путь)

Размещайте тесты рядом с кодом, в inline-модуле в конце того же файла `src/...`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_name_states_the_invariant() {
        let out = my_function("input");
        assert_eq!(out, expected);
    }

    // Для async-кода:
    #[tokio::test]
    async fn async_path_holds() {
        let r = my_async_fn().await;
        assert!(r.is_ok());
    }
}
```

Соглашения, видимые в коде:
- имя теста описывает проверяемый инвариант (например `sqli_signature_blocks_before_upstream`, `ja4_churn_observe_tracks_ip`);
- тесты не должны требовать внешних сервисов; для файлового стейта используйте `std::env::temp_dir()` с уникальным суффиксом (см. `TEST_HONEYPOT_SEQ` + `std::process::id()` в `tests/integration.rs`);
- помечайте фичеспецифичный код `#[cfg(feature = "pingora")]` / `#[cfg(feature = "xdp")]`, чтобы дефолтная сборка не ломалась;
- помните про `RUSTFLAGS=-D warnings` в CI: неиспользуемые импорты/переменные валят прогон (в коде встречаются обходы вроде `let _ = challenged_delta;`).

### 7.2. Интеграционный тест конвейера

Добавляйте `#[tokio::test]` в `tests/integration.rs`, переиспользуя `spawn_mock_upstream` и `build_handler`. При необходимости расширьте сигнатуру `build_handler` новым параметром, чтобы включить тестируемый гейт. Утверждайте и на HTTP-статусе, и на побочном эффекте (число хитов upstream, заголовки `Set-Cookie`/`x-aegis-step`).

### 7.3. Тест проводки Arsenal

Для нового модуля Defence Arsenal добавьте `#[test]` в `tests/arsenal_integration.rs`, который вызывает API через `ArsenalState::new_default()` и проверяет, что соответствующее поле в `counters.snapshot()` сдвинулось. Это страховка от «мёртвого состояния» (см. шапку файла).

### 7.4. Новый e2e-сценарий

В `aegis-e2e` добавьте сценарий через хелпер `record(&mut scenario_results, "имя", &report, &mut failures, |r| {...})`, возвращая `Ok(info)`/`Err(msg)`. Для проверки метрик используйте `delta(&baseline, &after, "aegis_<имя>")`. В `aegis-pingora-e2e` добавьте проверку в `run_tests`, используя хелперы `http_get`/`http_get_with_token`/`http_with_body_and_token` и `bail!` при несоответствии.

### 7.5. Перед коммитом

Воспроизведите CI локально:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
# при правках pingora/xdp-путей:
cargo test --features pingora --all-targets
cargo check --features xdp --all-targets
```

---

## 8. Краткая шпаргалка команд

```bash
# Быстрый цикл разработки
cargo test --lib <подстрока>            # одна подсистема
cargo test --lib <подстрока> -- --list  # что запустится
cargo test --lib -- --nocapture         # видеть вывод тестов

# Полная локальная проверка (как CI)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --features pingora --all-targets

# E2E
cargo build --release --bin aegis --bin aegis-e2e && \
    ./target/release/aegis-e2e --dump-metrics
cargo build --release --features pingora --bin aegis-pingora --bin aegis-pingora-e2e && \
    ./target/release/aegis-pingora-e2e
cargo build --release --bin aegis-sqlmap-replay && \
    ./target/release/aegis-sqlmap-replay --target http://127.0.0.1:8080/
cargo build --release --bin aegis-distbench && \
    ./target/release/aegis-distbench --target http://127.0.0.1:8080/ --sources 50
```
