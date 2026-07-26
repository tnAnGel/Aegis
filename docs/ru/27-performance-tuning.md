# Производительность и тюнинг

Как AEGIS собирается под конкретное железо, как раскладывается под нагрузкой и какие рычаги есть у оператора и разработчика. Каждое утверждение здесь привязано к реальному коду — `Cargo.toml` (`[profile.release]`), `install.sh` (`aegis_rustflags`/`build_and_install`), `src/h2_budget.rs`, `src/proxy/response_cache.rs`, `src/bin/aegis-pingora.rs` — а отчёт о методике и измерениях живёт в [`PERFORMANCE.md`](../en/reference/performance.md).

> Честная рамка (см. [`PERFORMANCE.md`](../en/reference/performance.md) и [`28-benchmarking.md`](./28-benchmarking.md)): AEGIS **не** быстрее голого nginx в plain-форвардинге — разрыв ~10–13% (CPU-изолированно, 8 ядер), и это доказано. Реальная ценность AEGIS — кэш (HIT ≈1.7× против nginx-форвардинга) и L7-защита, которая на порядок дешевле nginx+ModSecurity (≈18× within-VM). Этот документ описывает, как выжать заявленное, а не как обогнать proxy по голой скорости.

---

## 1. Сборка: где собирается и почему это важно

`install.sh` компилирует AEGIS **на самом сервере развёртывания**, при каждом `--update`. Это ключевое архитектурное решение для производительности: раз бинарь собирается и запускается на одной и той же машине, его можно безопасно затачивать под фактический CPU без риска `SIGILL` на чужом железе.

Из этого вытекают два дефолта по умолчанию:

1. **`target-cpu=native`** — компилировать под все фичи именно этого CPU.
2. **Быстрый параллельный профиль сборки** (thin LTO + 16 codegen-unit + incremental) — чтобы рутинный `--update` не пёк один rustc на одном ядре минутами.

И опциональный режим для выпуска релиза: **`AEGIS_BUILD_OPT=max`** — максимально оптимизированный (но медленный, почти однопоточный) бинарь.

---

## 2. Build-профиль `[profile.release]`

Дефолтный релиз-профиль задан в `Cargo.toml`, `[profile.release]`:

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

| Поле | Значение | Зачем (по коммент-блоку в `Cargo.toml`) |
|---|---|---|
| `lto` | `"thin"` | Параллельная межкрейтовая оптимизация. Thin LTO распараллеливается (vs `fat` = один последовательный проход по всей программе). Горячий путь пересекает 5–7 границ крейтов (pingora, hyper, http, tokio + 80+ наших модулей) — LTO даёт выигрыш по throughput. |
| `codegen-units` | `16` | Позволяет LLVM-codegen бежать по всем ядрам сервера. Это и есть «параллельная сборка». |
| `incremental` | `true` | Маленький `--update` перекомпилирует часть крейта, а не весь. Резко режет время рутинного обновления. |
| `panic` | `"abort"` | Убирает unwind-таблицы из пролога каждой функции (экономия icache на горячем Allow-пути), уменьшает бинарь. Безопасно: прокси уже трактует любую панику как падение воркера — pingora перезапускает воркер, SO_REUSEPORT держит слушатель живым. |
| `strip` | `"symbols"` | Срезает ~30% размера бинаря. Символы при нужде достаются из split-debug `.dwp`. |
| `opt-level` | `3` | Полная оптимизация. |
| `debug` | `false` | Без отладочной информации в проде. |

> **Историческая оговорка (честно).** До V246 дефолт был `lto="fat"` + `codegen-units=1` — самый быстрый *бинарь*, но **полностью однопоточная сборка**: один rustc пеленговал одно ядро минутами на каждом `install.sh --update`, остальные ядра простаивали. Поскольку install.sh пересобирает прямо на сервере при каждом обновлении, дефолт переключён на быстрый параллельный профиль. Цена по рантайму против `fat`+`cgu=1` — несколько процентов (измерено: AEGIS+WAF по-прежнему обгоняет голый nginx на защищённой нагрузке).

### Сопутствующие профили

```toml
[profile.profiling]   # для perf/flamegraph — release + символы
inherits = "release"
lto = "thin"
strip = false
debug = 1

[profile.bench]       # микробенчи под прод-настройками
lto = "fat"
codegen-units = 1
panic = "abort"
opt-level = 3
debug = true
```

- `[profile.profiling]` зеркалит release, но сохраняет таблицу символов и номера строк, чтобы `perf`/flamegraph разрешали имена функций. Никогда не отгружается — только для перф-исследований.
- `[profile.bench]` использует `fat` LTO + `cgu=1`, чтобы микробенчи отражали реальную прод-производительность, а не шум неоптимизированной отладки.

---

## 3. `AEGIS_BUILD_OPT=max` — максимально оптимизированный бинарь

`build_and_install()` в `install.sh` (строки ~497–509) реализует opt-in переключатель. По умолчанию используется быстрый параллельный профиль из `Cargo.toml`; при `AEGIS_BUILD_OPT=max` экспортируются переменные окружения, переопределяющие профиль:

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

| Режим | LTO | codegen-units | incremental | Когда |
|---|---|---|---|---|
| дефолт | `thin` | `16` | `true` | Рутинный `install.sh --update` на сервере. Сборка пилит все ядра, перекомпилит только изменённое. |
| `AEGIS_BUILD_OPT=max` | `fat` | `1` | `false` | Нарезка настоящего релиза. Медленная, почти однопоточная сборка, но абсолютно самый быстрый бинарь. **Не для рутинного `--update`.** |

```bash
# Максимально оптимизированный бинарь:
sudo AEGIS_BUILD_OPT=max bash install.sh --update
```

Механизм — стандартные `CARGO_PROFILE_RELEASE_*` env-override Cargo, поэтому он накладывается поверх `[profile.release]` без правки `Cargo.toml`.

---

## 4. `target-cpu=native` и `aegis_rustflags`

Codegen-таргет задаётся переменной `AEGIS_TARGET_CPU` (дефолт `native`) и собирается в RUSTFLAGS функцией `aegis_rustflags()` (`install.sh`, строки ~419–435):

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

| `AEGIS_TARGET_CPU` | Поведение |
|---|---|
| `native` (дефолт) | Оптимально для **этой** машины. Включает все фичи CPU. |
| `generic` | Портируемо; для build-once-deploy-many. `-C target-cpu` не добавляется вовсе. |
| `neoverse-n1` / `x86-64-v3` / … | Зафиксировать конкретную микроархитектуру. |

**Почему `native` безопасен.** Бинарь собирается прямо на хосте развёртывания и только тут и запускается, поэтому таргетинг под build-CPU безопасен и оптимален. На современных ARM (Graviton2+, Ampere, Apple, Neoverse) `native` включает **LSE-атомики ARMv8.1**: одноинструкционные `ldadd`/`swpal` вместо LL/SC-циклов (`__aarch64_ldadd8`). Это ускоряет **все** атомики — Arc, DashMap, tokio, mimalloc — на горячем пути. На современном x86 — AVX2/BMI. objdump V237-бинаря: 5775 `ldadd` / 414 `ldaddal` против 10 `ldaxr` (см. [`PERFORMANCE.md`](../en/reference/performance.md), V237).

> **Важно — фичи НЕ хардкодятся.** Закоммиченный `.cargo/config.toml` намеренно ничего не хардкодит; RUSTFLAGS из `aegis_rustflags()` переопределяет его. Любой заранее заданный `RUSTFLAGS` из окружения **сохраняется и дописывается после наших** флагов. Это даёт портируемость на старый ARM/x86 без риска `SIGILL` (собираешь под своё железо).

Применяется в обоих build-функциях (`build_aegis_hyper`, `build_aegis_pingora`):

```bash
RUSTFLAGS="$(aegis_rustflags)" "$cargo" build --release --bin aegis-pingora --features "$features"
```

Воспроизвести вручную (как в [`PERFORMANCE.md`](../en/reference/performance.md)):

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --features pingora
```

> **PGO (profile-guided optimization) — opt-in, не интегрировано в install.sh.** PGO измеренно даёт +10% на форвардинге и +3–5% на TLS-steady, но **не помогает** на bandwidth-bound путях (большие тела). Доступно как отдельный RUSTFLAGS-конвейер (`perf-tier1`), интеграция в `install.sh` — follow-up (PGO добавляет ~10 мин к сборке). Заявленные +10% профилировались в single-process топологии и **не перегонялись** в прод-раскладке REUSEPORT — см. оговорку в [`PERFORMANCE.md`](../en/reference/performance.md).

---

## 5. Линковщик mold

`mold` — многопоточный линковщик; финальная линковка большого бинаря `aegis-pingora` иначе однопоточна (GNU ld) и занимает заметную часть каждой сборки. Используется **best-effort**: если mold нет, тихий фолбэк на дефолтный линковщик, сборка не падает.

Установка mold идёт в двух местах `install.sh` (на свежей установке и в `build_and_install` для `--update`):

```bash
case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mold ... ;;
    dnf) dnf install -y -q mold ... ;;
    apk) apk add --no-cache mold ... ;;
esac
```

Если `command -v mold` находит бинарь, `aegis_rustflags()` добавляет `-C link-arg=-fuse-ld=mold` (см. §4). Иначе флаг не добавляется. Mold влияет **только на скорость сборки**, не на рантайм-производительность.

---

## 6. SO_REUSEPORT и число воркеров

Прод-раскладка AEGIS — **N отдельных SO_REUSEPORT-процессов** `aegis-pingora@0..N-1`, по схеме **thread-per-core**: N воркеров × 1 поток, каждый пинится 1:1 к CPU через systemd `CPUAffinity`. Подробности кросс-воркерного состояния — в [`06-workers.md`](./06-workers.md).

### Выбор числа воркеров — `resolve_workers()`

`install.sh` (строки ~156–191):

```bash
: "${AEGIS_WORKERS:=auto}"   # auto = nproc | explicit N
```

Порядок разрешения:

1. Если `--workers N` задан явно в CLI — он **всегда** побеждает.
2. Иначе, если `AEGIS_WORKERS=auto` и существует `/var/lib/aegis/topology.json` — берётся значение `{"workers":...}`, записанное страницей Workers админ-панели (через `PUT /admin/api/topology`).
3. Иначе `auto` → `nproc` воркеров, `AEGIS_THREADS_PER_WORKER=1`.

В любом случае `AEGIS_THREADS_PER_WORKER=1` (thread-per-core).

```bash
sudo bash install.sh --workers 8     # переопределить число REUSEPORT-инстансов
```

| Источник | Приоритет |
|---|---|
| `--workers N` (CLI) | высший |
| `topology.json` (панель, `PUT /admin/api/topology`) | средний (только при `auto`) |
| `nproc` | дефолт |

### Почему thread-per-core, а не work-stealing

`resolve_workers()` фиксирует раскладку N×1 потому, что pingora-рантайм NoSteal: раскладка N воркеров × 1 поток, пинённых 1:1 к CPU. Прежняя 4×4-схема оставляла планировщику ядра плавать потоки по всем CPU и рвала L1/L2-локальность. Это совпадает с паттерном nginx/envoy/HAProxy. Измерения подтвердили: **work-stealing НЕ помогает** — A/B показал, что NoSteal стабильно выигрывает; дефолт верен ([`PERFORMANCE.md`](../en/reference/performance.md), п.3/4).

### Рантайм-флаги REUSEPORT

Запускается через `AEGIS_PINGORA_REUSEPORT=1` (systemd-шаблон `aegis-pingora@.service`). В `src/bin/aegis-pingora.rs`:

- SO_REUSEPORT — opt-in через `AEGIS_PINGORA_REUSEPORT=1` (комментарий, строка ~38).
- `build_downstream_sock_opt(reuseport)` ставит `sock_opt.so_reuseport = Some(true)`, когда reuseport включён (строка ~583).
- Каждый инстанс биндит **одни и те же** порты; ядро хеширует входящие соединения по воркерам.

> **LEVER 3 — общий ticket-ключ REUSEPORT.** Прод-раскладка = N отдельных процессов, и без общего ключа TLS session-ticket каждый воркер выдавал бы свои тикеты → cross-worker resumption ломался бы (соединение, попавшее на другой воркер, делает полный хендшейк). Фикс: все REUSEPORT-воркеры **делят один ticket-ключ** (`src/bin/aegis-pingora.rs`, строки ~611+). Это и есть главный рычаг TLS-пути в правильной раскладке, а не крипта (см. [`08-tls-certificates.md`](./08-tls-certificates.md) и [`PERFORMANCE.md`](../en/reference/performance.md), п.4).

---

## 7. Кэш ответов (threat-aware response cache)

`src/proxy/response_cache.rs` — кэш ответов, который и даёт реальный отрыв AEGIS (HIT ≈1.7× против nginx-форвардинга, +20–47% против nginx-с-`proxy_cache`; [`PERFORMANCE.md`](../en/reference/performance.md), TL;DR). Полное описание поведения — в [`14-rate-limiting.md`](./14-rate-limiting.md) нет; кэш описан здесь и в [`04-configuration.md`](./04-configuration.md).

### Threat-aware: не обычный proxy_cache

- **Низкоугрозные/доверенные клиенты** (для кого `ctx.is_trusted` истинно, либо все при отсутствии угрозного сигнала) получают cache-HIT.
- **Высокоугрозные клиенты** (недавно denied/challenged IP) принудительно получают cache-MISS — ответ тянется свежим и проходит весь конвейер фильтров. Это блокирует cache-poisoning через header/query-смаглинг.

Защитные свойства (из doc-комментария модуля):
- WAF всё равно бежит для высокоугрозных IP на каждом запросе — кэш это перф-ярлык, **не** обход защиты.
- Записи хранят только upstream-ответ; кэшируемые ответы по определению детерминированы для ключа кэша.
- Ответы с `Set-Cookie` никогда не кэшируются (иначе кросс-загрязнение сессий).
- `Cache-Control: private | no-store` уважается.

### Хранилище — горячий путь без аллокаций

- Single-process LRU, ключ `(Method, Host, Path)`. **Нет** общего состояния между процессами — каждый воркер держит свой кэш (нулевая координация: ни Redis-хопа, ни локовой конкуренции). Цена дубля на процесс ограничена `max_entries × max_body_bytes`.
- **Тело хранится как `Bytes` → zero-copy на HIT**: просто клонируется Arc, без memcpy.
- **`CACHE_SHARDS = 32`** независимых LRU-шардов, у каждого свой `RwLock` — параллельные lookup'ы по разным ключам не конкурируют (`response_cache.rs`, строка 61). Per-shard ёмкость = `(max_entries / 32).max(4)`.

### Конфигурация — `ResponseCacheConfig`

`src/config.rs`, `pub struct ResponseCacheConfig`:

| Поле | Дефолт | Назначение |
|---|---|---|
| `enabled` | `false` | Включить кэш. |
| `max_entries` | 10 000 | Макс. записей в LRU. Память ≈ `max_entries × max_body_bytes` в худшем случае. |
| `default_ttl_secs` | 60 | Fallback-TTL, когда upstream не дал `Cache-Control: max-age`/`s-maxage`. |
| `max_body_bytes` | 1 MiB | Жёсткий потолок размера кэшируемого тела. Больше — стримится мимо кэша. |
| `status_ttl_secs` | `{}` | Per-status TTL-оверрайды, например `{200 = 300, 404 = 10, 301 = 3600}`. Частый паттерн: кэшировать 404 коротко (10s), чтобы гасить всплески сканеров, не долбя upstream. |
| `stale_if_error_secs` | 0 (выкл) | Stale-if-error окно: при 5xx/отказе upstream и наличии недавно протухшей записи в этом окне — отдаётся stale с `Warning: 110`. Держит сайт на плаву во время сбоев бэкенда. |

> **Глубина кэша — главный рычаг.** Hit-ratio важнее любого процента форвардинга ([`PERFORMANCE.md`](../en/reference/performance.md), п.5). Тюньте `max_entries`, `default_ttl_secs`, `status_ttl_secs` под профиль трафика; включайте `stale_if_error_secs` для устойчивости к сбоям бэкенда.

---

## 8. H2-бюджет (контроль-фрейм-бюджеты)

`src/h2_budget.rs` (V182) — Tempesta-стиль per-connection бюджеты HTTP/2 контроль-фреймов, применяемые **до** того, как фрейм дойдёт до h2-стейт-машины. Это и перф-, и защитная мера: гасит классы атак, эксплуатирующих дешевизну конкретного контроль-фрейма (Rapid Reset CVE-2023-44487, CONTINUATION flood CVE-2024-27316, Settings/Ping flood). Защитная сторона детально — в [`14-rate-limiting.md`](./14-rate-limiting.md) и [`21-arsenal-scenarios.md`](./21-arsenal-scenarios.md).

### Дефолтные бюджеты — `Budget::default_for`

Token-bucket per `(conn_id, FrameKind)`. На пустом бакете — `Verdict::Reject` (вызывающий закрывает stream/соединение). Без таймеров — refill считается лениво на `consume`.

| Фрейм (`FrameKind`) | `burst` | `refill_per_s` | Класс атаки |
|---|---|---|---|
| `RstStream` | 50 | 20 | Rapid Reset |
| `Settings` | 10 | 2 | Settings flood |
| `Ping` | 30 | 10 | Ping flood |
| `Priority` | 100 | 50 | Priority churn |
| `Goaway` | 3 | 1 | должен быть редок |
| `Continuation` | 50 | 20 | CONTINUATION flood |

### Реализация — дёшево на горячем пути

- Ключ карты — `(u64 conn_id, FrameKind)`, оба **connection-local** (последовательные ID + малый enum), не контролируются атакующим → используется **`FxHashMap`** вместо SipHash: DoS-устойчивость SipHash тут лишняя трата, FxHash материально быстрее на малых целочисленных ключах (`h2_budget.rs`, строки 36–41, 116–118).
- `Bucket::consume` refill'ит лениво: `tokens = (tokens + elapsed × refill_per_s).min(burst)`, потом `-= 1.0` при ≥1.0 (строки 102–112).
- `drop_conn(conn_id)` сбрасывает всё состояние закрытого соединения; `gc(idle)` — фоновая чистка простаивающих бакетов (строки 151–163).

### Оператор-тюнинг

Бюджеты переопределяются через `H2BudgetTracker::with_override(kind, Budget { burst, refill_per_s })` (строки 131–134) — DSL/конфиг-фасад. Та же логика бюджета вынесена в крошечную стейт-машину, которую **XDP fast-path может зеркалить** для kernel-side применения: один источник правды для порогов, учёт в двух местах (см. [`13-xdp-ebpf.md`](./13-xdp-ebpf.md)). Раннер арсенала экспонирует метрики `h2_budget` (`allows`/`rejects`/`tracked_conns`) через `src/proxy/pingora_admin.rs` (см. [`25-metrics-telemetry.md`](./25-metrics-telemetry.md) и [`30-admin-api.md`](./30-admin-api.md)).

> **Оговорка (честно).** В `src/bin/aegis-pingora.rs` (строка ~1724) есть комментарий, что in-tree `h2_guard`/`h2_budget` модули не могут полностью контролировать h2-фреймы на публичном слушателе через сам pingora-стек — учёт ведётся на хайпер/h2-уровне (`src/proxy/h2_guard.rs`, V111) и в этой бюджет-машине, а XDP-зеркалирование — отдельный путь. Не считайте это сквозным kernel-enforcement по умолчанию.

---

## 9. Тюнинг под нагрузку — горячий путь и де-аллокации

Аудит V236→V237 (56 агентов, 14 зон, состязательная верификация «реально ли исполняется на запросе в plain-режиме») закрыл бо́льшую часть «нашего» оверхеда. Реализованные безопасные оптимизации (см. [`PERFORMANCE.md`](../en/reference/performance.md), «Что оптимизировали»):

| Оптимизация | Суть |
|---|---|
| LSE-атомики | `target-cpu=native` → одноинструкционные `ldadd`/`swpal` (см. §4). |
| Меньше `clock_gettime` | 8×/запрос → 1× (filter-движок не читал часы на каждом фильтре). |
| Ленивый JA4H | SHA-256-фингерпринт считается по первому чтению, не на каждом запросе. |
| Батчинг кластер-счётчиков | per-worker буфер, flush раз в 128; in-place RefCell-батч (без копии всего массива). |
| read-lock + zero-alloc fast-path | в per-domain метриках; single-bucket гистограмма латентности (3 атомика вместо 13). |
| borrow-or-own host-ключи | нет `to_ascii_lowercase`-аллокации, когда хост уже в нижнем регистре. |
| empty-feed fast-path | threat-intel (`AtomicUsize`-сентинел) и honeypot (skip `canonical_path` без активных паков). |
| alloc-free разбор Cookie | на no-cookie пути. |

Сопутствующие компиляторно-зависимые рычаги из `Cargo.toml`:

- **`mimalloc`** (`Cargo.toml`, строка 143) — аллокатор по умолчанию, дешевле системного на горячем alloc/free.
- **`coarsetime`** — coarse-resolution `Instant` (~10ms тик, ~3ns load) для фоновых агрегаторов (aging окна dynamic_trust, scorer, anomaly EMA), где 1–10ms скос невидим. Точный `Instant::now()` оставлен для гистограмм латентности и security-чувствительной экспирации токенов.
- **`rustc-hash` (FxHash)** — для внутренних карт, где ключи **не** контролируются атакующим (литералы, rule ID, статус-коды, типы фреймов). Adversary-controlled карты (IP, host, JA4) сохраняют AHash/SipHash ради DoS-устойчивости.
- **`memchr`** — SIMD-поиск байт (NEON на aarch64, AVX2 на x86_64) в WAF-канонизации и per-field substring-сканах вместо скалярных `str::contains`.
- **`tracing` c `release_max_level_info`** — `debug!`/`trace!` вырезаются на этапе компиляции в release: 19 callsite на горячем пути перестают платить ~20–40 ns каждый (восстановлено ~50–95 MB/s dispatch при 100k+ RPS).

### Профиль V237 — где остаток CPU

После V236/V237 **наш код <2% self-time** (в основном клон HeaderMap). Остаток ~25% — framework + kernel, вне нашего кода:

| Что | % self-time | Чьё |
|---|---|---|
| kernel TCP-стек | ~12% | ядро — неизбежно |
| чтение часов (`cntvct`+`clock_gettime`) | ~6.8% | Pingora + tokio I/O/timer |
| Pingora HTTP-машинерия | ~7% | фреймворк |
| connection-pool LRU + хеш | ~3% | фреймворк (reuse upstream) |
| наш код | <2% | клон HeaderMap |

> **Тупики (НЕ копать — проверено, см. [`PERFORMANCE.md`](../en/reference/performance.md)):**
> - **io_uring data plane** — измеренно на ~24% медленнее nginx на loopback (нет DMA/zero-copy выигрыша; разрыв в filter/routing-слое, не в I/O). NO-GO.
> - **Gating клона HeaderMap (1.3%)** — отклонено: даже самый безопасный дизайн дал 2 критические WAF-bypass-гонки. Для security-прокси 1.3% throughput не стоят риска обхода WAF. Оставлен безусловный клон.
> - **Форвардинг-микробенч в принципе** — потолок здесь async-фреймворк + kernel TCP, максимум 2–3% микро-оптимизациями.

---

## 10. Практический чек-лист оператора

```bash
# 1. Релизная сборка под это железо (дефолт — native + параллельный профиль):
sudo bash install.sh --update

# 2. Максимально оптимизированный бинарь (для нарезки релиза, не для рутины):
sudo AEGIS_BUILD_OPT=max bash install.sh --update

# 3. Портируемый бинарь (build-once-deploy-many):
sudo AEGIS_TARGET_CPU=generic bash install.sh --update

# 4. Число воркеров под число ядер (или auto = nproc):
sudo bash install.sh --workers 8
```

| Рычаг | Где крутить | Эффект |
|---|---|---|
| Профиль сборки | `AEGIS_BUILD_OPT=max` | +несколько % рантайма ценой долгой сборки |
| Codegen-таргет | `AEGIS_TARGET_CPU` (`native`/`generic`/микроарх) | LSE-атомики / AVX2 vs портируемость |
| Линковщик | mold (best-effort) | только скорость сборки |
| Воркеры | `--workers` / панель / `nproc` | thread-per-core, 1:1 пиннинг к CPU |
| Кэш | `ResponseCacheConfig` (`max_entries`, `*_ttl_secs`, `stale_if_error_secs`) | hit-ratio — главный рычаг throughput |
| H2-бюджет | `H2BudgetTracker::with_override` / DSL | устойчивость к флуду контроль-фреймов |
| TLS resumption | общий ticket-ключ REUSEPORT (авто) | cross-worker resumption |

---

## См. также

- [`PERFORMANCE.md`](../en/reference/performance.md) — методика, реальные числа, тупики (первоисточник этого документа).
- [`28-benchmarking.md`](./28-benchmarking.md) — как воспроизвести замеры, оговорки бенч-лейнов.
- [`06-workers.md`](./06-workers.md) — SO_REUSEPORT, кросс-воркерное состояние.
- [`05-requirements.md`](./05-requirements.md) — требования к железу.
- [`03-installation.md`](./03-installation.md) — install.sh целиком.
- [`08-тls-и-сертификаты.md`](./08-tls-certificates.md) — TLS-путь, ticket-ключи.
- [`13-xdp-ebpf.md`](./13-xdp-ebpf.md) — зеркалирование h2-бюджета в ядро.
- [`14-rate-limiting.md`](./14-rate-limiting.md), [`21-arsenal-scenarios.md`](./21-arsenal-scenarios.md) — защитная сторона h2-бюджета.
- [`25-metrics-telemetry.md`](./25-metrics-telemetry.md) — метрики `h2_budget`, профилирование.
