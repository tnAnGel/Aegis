# План развития проекта

> Стратегический документ: куда движется AEGIS как платформа edge-защиты,
> какие направления приоритетны и почему. В отличие от тактической
> [дорожной карты](40-roadmap.md) (что и в каком релизе), здесь —
> **направления и обоснование**: единый risk engine, CRS-подобная модель WAF,
> протокольная L7-защита, репутация сессий/устройств, API-guards и замкнутый
> feedback-loop из прод-трафика.

Документ грунтуется в реальном коде репозитория и в трёх источниках стратегии:
`ROADMAP-NEXT.md` (план до technology ceiling, V100 достигнут 2026-05-20),
`AEGIS-X-ROADMAP.md` (4-слойная commodity-архитектура) и
docs/RESEARCH-2026-05.md (feature-level gap-анализ против
14 OSS-проектов). Каждое заявленное «уже есть» — со ссылкой на файл; всё
частичное/opt-in/будущее отмечено честно.

---

## 1. Где мы сейчас (исходная точка для планирования)

`ROADMAP-NEXT.md` фиксирует: **V100 достигнут, Phase A–E feature-complete**
(строки 1–6). Защитный стек, на который опирается весь дальнейший план, уже
в `main`:

| Слой | Что реально в коде | Файлы (примеры) |
|---|---|---|
| eBPF/XDP fast-path | deny/allow-set + per-CPU счётчики + first-byte WAF triage | `xdp/`, `src/xdp.rs` |
| WAF | Aho-Corasick сигнатуры + Sigma-корпус + compound-правила + webshell | `src/filters/waf.rs`, `src/sigma.rs`, `src/filters/sigma_overlay.rs` |
| TLS-фингерпринтинг | JA3/JA4/JA4H/JA4T (захват в ClientHello-callback) | см. [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| Risk engine | `RiskEngineMode { Off, Observe, Enforce }` | `src/config.rs:419`, `src/ddos/risk_engine.rs` |
| ML scoring | LR v1/v2 + GBM + adversarial, online SGD | `src/ddos/ml_score.rs`, `src/ddos/ml_score_v2.rs`, `src/ddos/ml_gbm.rs` |
| Репутация | self-learning JA4 + ASN/CIDR + CrowdSec LAPI + threat-intel | `src/ja4_reputation.rs`, `src/proxy/pingora_admin.rs:109` |
| Self-improving sigs | n-gram miner + online-miner | `src/signature_mine.rs`, `src/online_signature_miner.rs` |
| Cluster state | shared-mmap arena + AtomicHashMap (Linux) | см. [06-workers.md](06-workers.md) |

> **Честная оговорка (из `ROADMAP-NEXT.md`, V100 closing notes, строки 315–329):**
> из 5 пунктов «technology-ceiling checklist» три (#1 throughput-headline,
> #2 bench vs nginx, #4 bare-metal x86 32c, #5 живой edge) **gated на bench-прогоны
> и железо, а не на код**. То есть фичевая база готова; нерешённое — операционная
> валидация. Это определяет приоритет №0 ниже.

---

## 2. Стратегические направления

Шесть направлений из брифа. Для каждого: **что уже есть в коде**, **что
частично/opt-in**, **что в плане** и **обоснование приоритета**.

### 2.1. Единый risk engine

**Видение.** Все сигналы (WAF-вердикт, JA4-репутация, anomaly-score,
ML-инференс, rate-limit, GeoIP/ASN, honeypot-хиты) сходятся в одну
коррелирующую точку, которая принимает решение с прозрачной explainability,
а не как набор независимых фильтров.

**Что уже есть.** Risk engine инстанцируется в трёх режимах
(`src/config.rs:419`):

```rust
pub enum RiskEngineMode {
    Off,      // не инстанцируется, zero cost — safe default
    Observe,  // score считается + логируется, решение НЕ меняется (shadow)
    Enforce,  // score >= threshold эскалирует иначе-Allow запрос
}
```

Порог по умолчанию консервативный — `default_risk_threshold() = 90`
(`src/config.rs`). Введён Observe-first rollout (`src/config.rs:394`,
комментарий «correlational RiskEngine wiring») с явной нотой: enforce
преждевременно опасен, нужна ≥ неделя Observe-данных. ML-выход 0..100 уже
заведён в risk engine как фича (`src/ddos/risk_engine.rs:67` — «ML inference
output 0..100 from V97 MlScorer»).

> **Честная оговорка по терминологии.** Бриф упоминает режимы
> `Observe/HighConfidenceEnforce/FullEnforce` — это была *проектная*
> номенклатура. В фактическом коде enum называется `Off/Observe/Enforce`
> (`src/config.rs:419`). При написании сценариев/конфигов используйте реальные
> имена. `FullEnforce` встречается лишь как историческая ссылка в
> комментариях BGP-модуля (`src/bgp_rtbh.rs:10`).

**В плане (направление).** Из `ROADMAP-NEXT.md` «Out of scope for V100»
(строки 331–344) прямым текстом: **hot-path wiring** V97 `MlScorer` + V98
`ThreatTier` через `pingora_http` ещё не выполнен — структуры данных
поставлены, но call-site refactor намеренно отделён. Это и есть ближайшая
работа по единому engine: довести ML/tier-сигналы до точки решения в
горячем пути pingora, а не только считать их.

Из RESEARCH-2026-05.md — две идеи усиливают единый engine:
- **Композитная identity** (Cilium-паттерн, §2): стабильный хеш
  `(JA4 || ASN || cookie || behaviour-fp)` с TTL, чтобы решения переживали
  смену IP (NAT/прокси). «Plugs into ThreatScorer naturally».
- **Flowbits/flowints** (Suricata, Top-10 #7): per-connection состояние,
  чтобы правило выражало «POST /login → 401 ≥3 раза, затем GET /admin →
  block» без bespoke-кода.

**Приоритет: ВЫСОКИЙ.** Engine уже есть, но работает в основном в Observe;
дотягивание ML/tier до решения — самый дешёвый путь превратить «считаем»
в «защищаем».

### 2.2. CRS-подобная модель WAF (paranoia-levels / anomaly-score / shadow-mode)

**Видение.** Перейти от плоского набора правил к модели в духе OWASP CRS:
правила с уровнями строгости (paranoia), накопительный anomaly-score с
порогом блокировки, и обязательный shadow-режим для безопасного выката новых
правил.

**Что уже есть.**
- **Shadow-mode — реально работает.** WAF-правило с `action: "shadow"` /
  `"log"` только считает срабатывания, не меняя вердикт (`src/config.rs:807`,
  комментарий: «shadow first, watches metrics for a week, then flips»).
  Sigma-импортёр автоматически маппит `low`/`informational` уровни в
  `("log", "low", Some("shadow"))` (`src/sigma.rs:568`; тест
  `level_low_maps_to_log_shadow` на `src/sigma.rs:1076`). Решение
  «match-but-don't-act» имеет отдельный `DecisionKind::Observed`
  (`src/security_event.rs:43`).
- **Anomaly-score — частично, на TLS-уровне.** `anomaly_score()` существует
  для GREASE-аномалий (`src/grease_anomaly.rs:42`) и заводится в
  client-consistency скоринг (`src/client_consistency.rs:189`). Это **не**
  CRS-style накопительный score по всем WAF-правилам — пока узкий
  TLS-сигнал.
- **Sigma-корпус и compound-правила** уже поставлены (`src/sigma.rs`,
  `src/filters/sigma_overlay.rs`, отдельный бинарь `src/bin/aegis-sigma-import.rs`),
  плюс webshell-сигнатуры (из последнего коммита). Compiled rule plan
  (per-field Aho-Corasick) — V95-V96 в `ROADMAP-NEXT.md` (строка 309).

**Что частично/в плане.**
- **Paranoia-levels** как таковых в коде нет — это направление. Ближайший
  механизм-зацепка: severity/tags на правилах + shadow-флаг уже есть, поэтому
  paranoia-уровень ложится как фильтр «активировать правила с severity ≤ N».
- **Накопительный anomaly-score по WAF** (CRS-сердцевина) — расширение
  существующего скоринга: сумма весов сработавших правил против порога.
- Из RESEARCH-2026-05.md, направление A.1 (§Cross-cutting):
  **macro/list-слой над Wirefilter** (Falco-style) назван «the single cheapest
  UX upgrade we can make for ops». Это инфраструктура, на которой CRS-модель
  становится удобной операторам.

**Приоритет: ВЫСОКИЙ.** Детекция уже на уровне ModSecurity/CrowdSec по широте
(см. RESEARCH executive summary). Чего не хватает — *операторской модели*
управления: paranoia + накопительный score + macro/list DSL. Это ergonomics,
дающие 80% ценности за 10% работы.

### 2.3. Протокольная L7-защита (h2/h3)

**Видение.** Защита, специфичная для HTTP/2 и HTTP/3: лимиты на flood
кадров, rapid-reset, h2/h3 abuse-guard как самостоятельный слой.

**Что уже есть.**
- **H2 flood-лимиты / abuse-guard.** Последние коммиты ветки прямо про это:
  «sigma compound rules + C3 h2 flood limits» (commit 78294ec) и Sigma-overlay
  с jitter (`src/latency_jitter.rs`). RESEARCH (§14, «We already have»)
  подтверждает наличие «H2 abuse guard».
- **HTTP/3 / QUIC** обслуживается через hyper-handler shim, разделяющий
  pipeline-состояние (`AEGIS-X-ROADMAP.md`, V46, строка 236), с h3 WAF
  hot-reload poller (V61) и e2e smoke (V62).

**Что частично/в плане (честно).**
- **H2 frame-fingerprint (Akamai-style, `h2_fp`)** — **заблокирован на уровне
  pingora-core**: «needs fork to expose h2 frames» (`AEGIS-X-ROADMAP.md`,
  строка 256, помечено «by design / blocked»). Это известное ограничение,
  не баг. Стратегия (Risks-таблица, строка 366): держать захват в XDP/eBPF,
  pingora лишь читает.
- **HTTP/3 server push** сознательно НЕ в плане — deprecated в RFC
  (`ROADMAP-NEXT.md`, «Что НЕ в плане», строка 174).
- **gRPC**: отдельной gRPC-специфики не делаем — «pingora handles это уже
  generic» (`ROADMAP-NEXT.md`, строка 176). См. также §2.5 про API-guards.

**Приоритет: СРЕДНИЙ.** Базовые h2-flood-лимиты есть; протокольная глубина
(frame-fp) упирается в upstream-зависимость, поэтому развивается через XDP,
а не через форк pingora.

### 2.4. Репутация сессий и устройств (session/device reputation)

**Видение.** Репутация не только по IP/JA4, но по «устройству»/«сессии» —
композитной стабильной идентичности, переживающей смену IP.

**Что уже есть.**
- **Self-learning JA4-репутация** — включена по умолчанию
  (`src/proxy/pingora_admin.rs:109`: «reputation feeds now ON by default
  (self-learning JA4 + ...)»; `src/ja4_reputation.rs` ведёт `learned`-счётчик).
  Источники самообучения: honeypot/WAF/tarpit. Дефолт-он также ASN/CIDR
  (Tor/Spamhaus), CrowdSec LAPI, threat-intel (см. [12-reputation.md](12-reputation.md)).
- **Device/passive-fp сигналы**: p0f-стиль TTL-наблюдения (`src/p0f.rs:291`),
  UA-vs-JA4 mismatch (`src/filters/ua_fp_mismatch.rs`), client-consistency
  (`src/client_consistency.rs`). Это сырьё для «device reputation».

**Что частично/в плане.**
- **Композитная identity** (Cilium-идея, RESEARCH-2026-05.md §2):
  «today we operate on `(IP, ASN, JA4, cookie)` individually. A composite
  identity type — стабильный хеш с TTL — would let per-endpoint policies match
  on identity, surviving NAT/proxy IP changes». Это и есть мост от
  «репутации фингерпринта» к «репутации сессии/устройства».
- **Типизированный IntelStore с provenance** (Zeek/Suricata `datarep`,
  Top-10 #5/#6): сейчас threat-intel — «a flat IP/CIDR set» (RESEARCH,
  «Directions still empty», п.5). План — типизированные множества
  (`IP/CIDR/JA4/SHA256/...`) с `(source, confidence, first/last_seen)` и
  оператором `in_set(name, rep>=N)`, чтобы репутация была не бинарной.

**Приоритет: СРЕДНИЙ-ВЫСОКИЙ.** Self-learning JA4 уже даёт большую часть
ценности. Композитная identity — следующий рычаг против ротации IP, но
требует аккуратной работы с TTL и кардинальностью (LRU-cap).

### 2.5. API-guards (REST / JWT / GraphQL / gRPC)

**Видение.** Специализированные guard'ы для современных API: валидация JWT,
ограничение глубины/сложности GraphQL, защита gRPC.

**Что уже есть (честно — только GraphQL).**
- **GraphQL guard** реально существует и подключён: `src/filters/graphql.rs`
  (`GraphqlFilter`, `GraphqlConfig`), регистрируется в `src/server.rs:283`.
  Не полный парсер по соображениям стоимости/зависимостей
  (`src/filters/graphql.rs:3`); сильнейшая защита — **persisted query hashes**
  (`persisted_hashes`, `src/filters/graphql.rs:31`, «Strongest GraphQL DDoS
  defence»).

**Что НЕ существует пока (направление, не реализация).**
- **JWT-guard** — отдельного фильтра валидации/inspection JWT в `src/filters/`
  нет (в каталоге из API-guard'ов есть только `graphql.rs`). Это план.
- **gRPC-guard** — отдельной gRPC-специфики нет намеренно (см. §2.3:
  «pingora handles generic»).
- **REST-guard** — покрывается общим WAF + per-endpoint policy
  ([26-sites-and-domains.md](26-sites-and-domains.md)), отдельного
  REST-aware guard как модуля нет.

**Зацепки для плана.** Per-domain/per-endpoint policy и actuator-направление
(см. §2.6) — естественная база: JWT-claims как селекторы правил (RESEARCH §4,
Tracee: «if event.jwt_role ... and event.path starts_with /admin: block»).

**Приоритет: СРЕДНИЙ.** GraphQL закрыт (самый частый DDoS-вектор для API).
JWT-guard — следующий очевидный шаг, REST/gRPC покрываются общим конвейером.

### 2.6. Замкнутый feedback-loop из прод-трафика

**Видение.** Атаки, пойманные honeypot/tarpit/WAF, автоматически улучшают
защиту: дообучают ML, порождают сигнатуры, поднимают репутацию-скор.

**Что уже есть.**
- **Honeypot → ML feedback.** `src/robots_honeypot.rs:10`: «V149 wires that
  signal into the V135 MlTrainer feedback loop». Online-ретрейнинг ML — V123
  (`src/ddos/ml_score_v2.rs:14`, «operator-driven feedback»), online SGD
  (`src/ddos/ml_score.rs`).
- **Self-improving signatures.** N-gram miner (`src/signature_mine.rs`) +
  online-miner (`src/online_signature_miner.rs`), фоновый прогон в
  `src/proxy/pingora_background.rs` (строки 68/233/412). Админ-маршрут
  `POST /admin/signature_mine` (`src/admin_auth.rs:187`, роль `Write`).
- **Self-learning репутация** (§2.4) — тот же контур: honeypot/WAF/tarpit
  кормят JA4-репутацию.

**Что частично/в плане (честно).**
- **No-write-back by design.** V99 (`ROADMAP-NEXT.md`, строка 312): miner
  делает «intentional no-write-back (operator promotes manually)». То есть
  loop пока **полу-замкнут**: кандидаты майнятся автоматически, но в прод
  их продвигает оператор. Полная автоматизация (с approval-pipeline для
  low-confidence) — направление E.4 (`ROADMAP-NEXT.md`, строки 158–162).
- **Online tarpit-log → miner automation** — в «Out of scope for V100»
  (`ROADMAP-NEXT.md`, строка 343): «currently corpus is supplied per admin
  request».
- **Hunt jobs** (Arkime, RESEARCH §8): фоновый ре-скан последних N часов
  событий новыми правилами — «catches signatures we just learned against
  attacks that already happened». Логичное расширение feedback-loop.

**Приоритет: ВЫСОКИЙ (дифференциатор).** RESEARCH прямо называет
self-improving signature mining уникальной фичей, которой нет ни у кого из
OSS-проксей (`ROADMAP-NEXT.md`, строки 346–354). Закрыть последнюю милю
(контролируемый auto-promote) — большой стратегический выигрыш.

---

## 3. Сводная матрица приоритетов

Ранжирование по ROI (грунтуется в gap-анализе RESEARCH Top-10 + статусе кода).

| # | Направление | Состояние в коде | Приоритет | Обоснование |
|---|---|---|---|---|
| 0 | **Operational validation** (bench-sweep + bare-metal 32c + живой edge) | gated на железо/прогоны | **КРИТИЧЕСКИЙ** | 3 из 5 ceiling-пунктов ждут не код, а валидацию (`ROADMAP-NEXT.md` 315–329) |
| 1 | Единый risk engine: hot-path wiring ML/tier | структуры есть, call-site нет | ВЫСОКИЙ | дешевле всего: из «считаем» в «защищаем» (out-of-scope V100, 331–344) |
| 2 | Sigma importer (расширение) + macro/list DSL над Wirefilter | Sigma-импорт есть; DSL нет | ВЫСОКИЙ | «whole detection ecosystem» + «cheapest UX upgrade» (RESEARCH Top-10 #1, §A.1) |
| 3 | Leaky-bucket scenario DSL (CrowdSec-style) | rate-limit плоский | ВЫСОКИЙ | «10 distinct 4xx URIs from one IP in 10s» = 7 строк YAML вместо кода (Top-10 #2) |
| 4 | Actuator registry + revert-timers | действия захардкожены | ВЫСОКИЙ | разблокирует интеграции; loop §2.6 (Top-10 #4) |
| 5 | Feedback-loop: контролируемый auto-promote сигнатур | полу-замкнут | ВЫСОКИЙ | уникальный дифференциатор (`ROADMAP-NEXT.md` 346–354) |
| 6 | Композитная identity (session/device reputation) | сигналы есть, identity нет | СРЕДНИЙ-ВЫС. | переживает ротацию IP (RESEARCH §2) |
| 7 | Типизированный IntelStore + `datarep` reputation | flat IP/CIDR set | СРЕДНИЙ | репутация перестаёт быть бинарной (Top-10 #5/#6) |
| 8 | CRS-модель: paranoia + накопительный anomaly-score | shadow есть, paranoia нет | СРЕДНИЙ | операторская модель управления WAF (§2.2) |
| 9 | API-guards: JWT-guard | только GraphQL | СРЕДНИЙ | GraphQL закрыт; JWT — следующий вектор (§2.5) |
| 10 | Flowbits/flowints (multi-stage) | правила per-request | СРЕДНИЙ | корреляция без bespoke state (Top-10 #7) |
| 11 | File-carving + YARA pipeline | только ClamAV TCP | СРЕДНИЙ | «10x detection upgrade» но effort L (Top-10 #3) |
| 12 | Протокольная h2_fp глубина | blocked на pingora-core | НИЗКИЙ | upstream-зависимость; обходим через XDP (§2.3) |

---

## 4. Обоснование стратегии в целом

**Принцип дифференциации (`AEGIS-X-ROADMAP.md`, строки 6–11).** Превосходить
не числом фич, а **уникальной комбинацией**, которой нет ни у кого из
OSS-мира: XDP fast-path + user-space WAF с compiled plan + per-IP ML + threat-aware
tiered cache + cluster shared-mmap integrity + self-improving sigs. Ни одна
open-source прокся не покрывает весь этот scope разом
(`ROADMAP-NEXT.md`, строки 346–354). Стратегия развития = **углублять
комбинацию и её ergonomics**, а не догонять конкурентов по голой скорости.

**Честная оговорка о производительности.** AEGIS НЕ заявляет, что он быстрее
реальных проксей по голой скорости. Бенч-лейны AEGIS — in-process движок,
не полный pingora-бинарь; аппаратный SHA-бенч per-core и низок внутри VM без
аппаратного SHA-ускорения (тогда прогноз ёмкости пессимистичен). Сильный
аргумент проекта — **матрица безопасности**, а не RPS. Потолок производительности
(`ROADMAP-NEXT.md`, condition #1, строки 355–356) ограничен железом, а не
фичами — поэтому приоритет №0 операционный, а не кодовый. Подробности —
[27-performance-tuning.md](27-performance-tuning.md),
[28-benchmarking.md](28-benchmarking.md).

**Почему ergonomics (DSL/macro/scenario) — топ-приоритет.** RESEARCH
executive summary: детекция AEGIS уже на уровне или выше ModSecurity/CrowdSec/
Suricata по широте; ведём по JA4-матрице, ML-пайплайну и honeypot-широте
(§B «Where we already lead»). Единственная систематическая дыра против
*всех* 14 проектов — отсутствие декларативного DSL-слоя над движком
(§A.1, §C.1). Поэтому «следующий sprint» в RESEARCH — это в основном DSL/
адаптеры (Sigma, scenarios, actuators), а не новые детекторы.

**Что сознательно НЕ делаем** (`ROADMAP-NEXT.md`, строки 166–177):

| Не делаем | Почему |
|---|---|
| Full monoio swap | требует форк pingora-core, maintenance burden |
| XDP_REDIRECT to upstream | не viable для TLS-terminating proxy (нет DSR) |
| AF_XDP zero-copy receive | переписать TCP layer, нишево |
| WASM filters | overlap с уже имеющимися Lua-плагинами ([31-plugins.md](31-plugins.md)) |
| HTTP/3 server push | deprecated в RFC |
| gRPC proxy specifics | pingora handles generic |
| Community-consensus blocklist | нужны users at scale (RESEARCH §13) |

---

## 5. Фазовая последовательность (из ROADMAP-источников)

Историческая лестница `ROADMAP-NEXT.md` (V77 → V100) показывает выполненные
блоки; будущее — расширения внутри тех же слоёв `AEGIS-X-ROADMAP.md`.

```
Phase A — XDP        ✅ partial (counters + WAF; XDP_REDIRECT не для TLS proxy)
Phase B — Pingora    ✅ done (V72; ~770k stable — верхний край target)
Phase C.2 — WAF AC   ✅ done (V76; overhead 10%→2%)
Phase C.3 — headers  ✅ done (V78-V79; cache fast-path до build_ctx)
Phase C.1 — io_uring ⏳ V83-85 не начато (tokio-uring, gated, +15-25% expected)
Phase D — mmap state ✅ V86-V89; ⏳ V90 scorer-migration не начат
Phase E — JIT+ML     ✅ feature-complete (V91-V100), но hot-path wiring отложен
```

**Ближайший правильный шаг** (`ROADMAP-NEXT.md`, строки 326–329): bench-sweep
на стенде Aegis-Proxy-dev (Bench A vs nginx, Bench C distributed-attacker),
затем i9-9900K native-Linux dual-boot для 32c-числа. Это закрывает пункты
ceiling-checklist 1/2/4, после чего — пункт 5 (живой edge).

**Definition of "technology ceiling"** (`ROADMAP-NEXT.md`, строки 196–211):
останов фичевого dev при выполнении **4 из 5** условий, переход в фазу
«maintenance + operator UX polish + docs». Текущий статус по checklist'у —
см. 42-текущее-состояние-STATUS.md.

---

## 6. Что нужно от оператора

Из `ROADMAP-NEXT.md` (строки 215–231), адаптировано к текущему статусу:

1. **Bench-валидация** на стенде после изменений в hot-path (Bench A vs nginx,
   Bench C distributed-attacker) — см. [28-benchmarking.md](28-benchmarking.md).
2. **Финальный bench на bare-metal x86 32c** (i9-9900K native Linux dual-boot
   или cloud Hetzner/OVH) — 1 раз, даёт честные production-class цифры
   (закрывает ceiling #4).
3. **Production-валидация на реальном edge** (живой трафик, не bench) —
   закрывает ceiling #5; единственный пункт, который нельзя получить в лабе.
4. **Observe-first для risk engine и WAF.** Перед `Enforce` — минимум неделя
   `Observe`/shadow данных (`src/config.rs:404`); смотреть метрики
   ([25-metrics-telemetry.md](25-metrics-telemetry.md)), затем флипать.

---

## 7. Связанные документы

- [40-roadmap.md](40-roadmap.md) — тактический план по релизам
- 42-текущее-состояние-STATUS.md — снимок статуса
- [10-waf.md](10-waf.md) · [18-ml-risk-engine.md](18-ml-risk-engine.md) ·
  [12-reputation.md](12-reputation.md) · [11-tls-fingerprinting.md](11-tls-fingerprinting.md)
- [13-xdp-ebpf.md](13-xdp-ebpf.md) · [17-honeypot-tarpit.md](17-honeypot-tarpit.md) ·
  [21-arsenal-scenarios.md](21-arsenal-scenarios.md) · [22-enrichment.md](22-enrichment.md)
- [23-security-model.md](23-security-model.md) — сильнейший аргумент проекта
- [30-admin-api.md](30-admin-api.md) — маршруты вроде `POST /admin/signature_mine`
- Источники стратегии: `ROADMAP-NEXT.md`, `AEGIS-X-ROADMAP.md`,
  RESEARCH-2026-05.md
