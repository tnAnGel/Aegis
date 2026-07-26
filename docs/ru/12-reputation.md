# Репутационные фиды (JA4, ASN/CIDR, CrowdSec)

AEGIS объединяет несколько независимых источников репутации — самообучающийся JA4-фид, ASN/CIDR-список (Tor + Spamhaus DROP, включён по умолчанию), курируемый JA4-корпус, IP-deny по threat-intel файлам и CrowdSec LAPI. Все они подгружаются из локальных файлов с горячей перезагрузкой по mtime; ни один не делает прямых HTTPS-запросов из data plane. Этот документ описывает, что код реально делает, а где функциональность частична.

Источники кода: [src/ja4_reputation.rs](../../src/ja4_reputation.rs), [src/asn_reputation.rs](../../src/asn_reputation.rs), [src/ja4_corpus.rs](../../src/ja4_corpus.rs), [src/crowdsec_api.rs](../../src/crowdsec_api.rs), [src/filters/threat_intel.rs](../../src/filters/threat_intel.rs), [install.sh](../../install.sh) (`ensure_reputation_feeds`), wiring — [src/bin/aegis-pingora.rs](../../src/bin/aegis-pingora.rs).

Смежные документы: [TLS-фингерпринтинг](./11-tls-fingerprinting.md), GeoIP (страна и ASN), Обогащение и threat-intel, ML и risk engine, Honeypot и tarpit, Defence Arsenal.

---

## 1. Обзор: пять источников репутации

| Источник | Модуль | Ключ | Тип сигнала | Дефолт | Где применяется |
|---|---|---|---|---|---|
| JA4 reputation feed | [`ja4_reputation.rs`](../../src/ja4_reputation.rs) (V138/V244) | JA4-строка / cipher-hash | ML-фича `ja4_reputation` [0..1] | **ON** (self-learning) | `extract_ml_features_v2` |
| JA4 corpus (seed) | [`ja4_corpus.rs`](../../src/ja4_corpus.rs) (V176) | JA4-строка / cipher-hash | Allow / Deny / Unknown | встроен в бинарь | Arsenal, поднимает `ja4_reputation` |
| ASN/CIDR reputation | [`asn_reputation.rs`](../../src/asn_reputation.rs) (V142/V144) | AS-номер / CIDR | ML-фича `asn_reputation` [0..1] | **ON** | `extract_ml_features_v2` |
| Threat-intel deny | [`filters/threat_intel.rs`](../../src/filters/threat_intel.rs) (V113/V237) | IP / CIDR | hard Deny (HTTP 403) | OFF (нет путей по умолчанию) | filter chain |
| CrowdSec LAPI | [`crowdsec_api.rs`](../../src/crowdsec_api.rs) (V157) | IP / Range / Country | экспорт решений (decisions) | заготовка (wire types) | внешние bouncer'ы |

Ключевое различие в строгости вердикта:

- **JA4 / ASN reputation** — это *мягкий* сигнал: возвращает число `[0..1]`, которое попадает в ML-скорер как одна из фич. Сам по себе не блокирует. См. ML и risk engine.
- **Threat-intel** — это *жёсткий* фильтр: совпадение → немедленный `FilterAction::Deny { status: 403 }`.
- **JA4 corpus** — двунаправленный: `Deny` поднимает `ja4_reputation` до 1.0, `Allow` может только *удержать* подозрение, но не опустить его ниже неподделываемого baseline (см. §4).

---

## 2. JA4 reputation feed (`ja4_reputation.rs`)

### 2.1. Назначение и формат файла

Самообучающийся индекс JA4-хешей, известных как принадлежащие вредоносному инструментарию (sqlmap, hydra, nuclei, recon-ng…) или ботнетам. Оператор кладёт файл в каталог репутации, AEGIS поднимает каждый запрос, чей JA4 совпал.

Формат — plain text, одна запись на непустую/некомментированную строку (`#` — комментарий). Поддерживаются две формы (парсер — `parse_into`, [src/ja4_reputation.rs:258](../../src/ja4_reputation.rs)):

```text
# полная JA4-строка <token> [tag]
t13d1516h2_8daaf6152771_b186095e22b6  sqlmap

# только cipher-hash (средний 12-символьный блок) — comunity-фиды
# часто шипят именно его, т.к. он стабильнее при апдейтах браузера
8daaf6152771    nuclei
```

Правила классификации токена:

- содержит `_` → индексируется как **full JA4** (точное совпадение);
- ровно 12 hex-символов → индексируется как **cipher-prefix** (совпадение по среднему блоку);
- иначе — токен тихо игнорируется (фид — ответственность оператора).

Tag непрозрачен для AEGIS: попадает в метрики и audit-лог. По умолчанию, если tag отсутствует — `"unknown"`.

### 2.2. Логика lookup и scoring

`lookup()` ([src/ja4_reputation.rs:193](../../src/ja4_reputation.rs)) сначала пробует full-таблицу (сильнейший сигнал), затем cipher-prefix (средний блок, 12 hex-символов). Результат конвертируется в фичу `reputation_feature()`:

| Тип совпадения | Значение фичи | Комментарий |
|---|---|---|
| `MatchKind::Full` | **1.0** | точное совпадение JA4 в CTI-фиде |
| `MatchKind::CipherPrefix` | **0.6** | слабее — браузер может делить cipher-список с инструментом |
| нет совпадения | **0.0** | |

Структура индекса — два `HashMap` под `RwLock` (full + cipher). Хеширование — AHash (DoS-устойчивое): по аудиту V230 ключи производятся напрямую из клиентского TLS-хендшейка, поэтому FxHash здесь запрещён (атакующий может крафтить хендшейки для зондирования коллизий).

### 2.3. Самообучение (`observe_bad`, V244)

Главная особенность: **публичного bulk-списка вредоносных JA4 не существует**, а JA4 инструментов коллидируют с дженериковыми Go/Python-клиентами — статический дефолт был бы FP-склонным. Поэтому источник «из коробки» — самообучение из подтверждённо-плохого трафика.

`observe_bad(ja4, tag)` ([src/ja4_reputation.rs:110](../../src/ja4_reputation.rs)) вызывается только на уже-плохих исходах:

- **honeypot trap** и **WAF signature hit** — [src/proxy/pingora_http.rs:3106](../../src/proxy/pingora_http.rs) (tag = имя сработавшего фильтра);
- **tarpit** — [src/proxy/pingora_http.rs:3279](../../src/proxy/pingora_http.rs) (tag = `"tarpit"`).

Записанные JA4 атомарно (`O_APPEND`) дописываются в файл-сток `ja4-observed.txt`, который тоже входит в `paths`, поэтому sibling-воркеры и рестарты подхватывают их через mtime-reload.

Защитные ограничения:

- **Cap.** `OBSERVED_CAP = 50_000` full-JA4 записей — ограничивает память и защищает от JA4-ротирующего атакующего, флудящего learned-set.
- **Dedup.** Повторное наблюдение известного JA4 → return без I/O (дёшево под read-lock, double-check под write-lock).
- **Guard вырожденных JA4 (V246).** `is_degenerate_ja4()` ([src/ja4_reputation.rs:233](../../src/ja4_reputation.rs)) отказывается обучаться на «пустом ClientHello». Если захват полей ClientHello вернул пусто, cipher/extension-хеш = `SHA256("")` усечённый = `"e3b0c44298fc"` — **одинаков для каждого клиента**. Обучение такого JA4 с одного плохого запроса флагнуло бы весь трафик. Любой JA4, чей cipher- или extension-блок равен empty-input-хешу, пропускается.

  🟡 Это **safety net**, а не настоящий фикс. Правильное решение — захватывать реальные поля ClientHello; guard лишь не даёт катастрофе случиться. Так прямо сказано в комментарии кода ([src/ja4_reputation.rs:114-119](../../src/ja4_reputation.rs)).

- **No-op условия.** `observe_bad` ничего не делает, если auto-learn выключен (нет `observed_path`), JA4 пуст/без `_`, JA4 вырожден, либо достигнут cap.

`learned_count()` — счётчик авто-обученных за время жизни воркера, выводится в панели, чтобы оператор видел, что фид «живой».

### 2.4. Включение и env-кнобы

JA4 reputation **включён по умолчанию** в `aegis-pingora` ([src/bin/aegis-pingora.rs:1229](../../src/bin/aegis-pingora.rs)). Состав путей:

1. операторские фиды из `AEGIS_JA4_REPUTATION` (colon-separated пути);
2. `ja4-observed.txt` — sink авто-обучения (через `.with_observed_path()`);
3. `ja4-crowdsec.txt` — фид, наполняемый refresh-джобом, если настроен CrowdSec LAPI (см. §6.3); путь watched даже когда файл отсутствует.

| Env | Значение | Эффект |
|---|---|---|
| `AEGIS_JA4_REPUTATION` | `0` / `false` / `off` | полностью выключить JA4 reputation |
| `AEGIS_JA4_REPUTATION` | `path1:path2:…` | добавить операторские фиды (двоеточие — разделитель) |
| `AEGIS_REPUTATION_DIR` | путь | каталог репутации (default `/var/lib/aegis/reputation`) |

> ⚠️ Применимость: вся репутация JA4/ASN, описанная здесь, реализована в **`aegis-pingora`**-бинаре. Legacy-гипер-путь (`aegis`) не выполняет это wiring. См. [архитектуру](./02-architecture.md).

---

## 3. JA4 corpus — курируемый seed (`ja4_corpus.rs`)

В отличие от V138 (операторский CTI-список), V176-корпус **вшит в бинарь** и консультируется как «глобально-истинный» baseline ещё до операторского фида.

### 3.1. Встроенный seed

`SEED` ([src/ja4_corpus.rs:60](../../src/ja4_corpus.rs)) — ~30 записей вида `(ja4_or_cipher, verdict, label)`. Три вердикта:

- **Allow** — известные стабильные браузеры (Chrome/Firefox/Safari/Edge — Windows/macOS/Linux/iOS/Android). Семантика: «этот fingerprint реально эмитят миллионы пользователей».
- **Deny** — известный инструментарий: `curl`, `python-requests`, `python-urllib3`, `go-default-http-client`, `java-okhttp`, `java-apache-httpclient`, `sqlmap`, `nikto`, `nuclei`, `hydra`, `wpscan`.
- **Unknown** — нет в корпусе → отдать решение V137 fp_correlation / V138 reputation / ML.

Cipher-prefix-записи (broader/weaker) тоже есть: `8daaf6152771` → chrome-family-cipher (Allow), `56d4dd6ee7df` → sqlmap-family-cipher (Deny) и т.д.

> 🟡 Честная оговорка из самого кода: хеши взяты из публичных снапшотов FoxIO JA4+ и собственного honeypot-mining; «conservative — только записи, наблюдавшиеся в большом объёме на нескольких деплоях». Seed маленький и фиксированный.

### 3.2. Расширение оператором

`extend_from_path()` ([src/ja4_corpus.rs:141](../../src/ja4_corpus.rs)) дописывает записи из файла. Формат — `<ja4_or_cipher> <verdict> <label>`, где verdict ∈ `allow` / `deny` (**default `deny`**, если опущено или не распознано). Отсутствующий файл тихо пропускается (compose-friendly).

### 3.3. Влияние на scoring

Логика в [src/proxy/pingora_http.rs:1568-1599](../../src/proxy/pingora_http.rs):

- **Deny** → `ja4_reputation = ja4_reputation.max(1.0)` (поднимает фичу до максимума).
- **Allow** → `(ja4_reputation - 0.25).max(baseline).max(0.0)`. Это **H9b-clamp**: JA4 выбирается клиентом (атакующий полностью контролирует свой ClientHello), поэтому Allow-вердикт **не может опустить подозрение ниже неподделываемого baseline**, установленного операторским V138-фидом. Спуфнутый «я Chrome» JA4 в худшем случае нейтрален, никогда не отрицателен.
- **Unknown** → без изменений.

Дополнительно сюда же сворачивается **JA4 churn** (V177, [ja4_churn.rs](../../src/ja4_churn.rs)): при churn > 0.6 `ja4_reputation = max(churn)`. Подробнее — [TLS-фингерпринтинг](./11-tls-fingerprinting.md).

Параллельно (V199, [src/proxy/pingora_http.rs:2687](../../src/proxy/pingora_http.rs)) corpus `Deny` может фигурировать в Arsenal как отдельный actuator с `SecurityEvent`-логом (`ja4_corpus_deny`). Счётчики `ja4_corpus_lookups`/`_deny_hits`/`_allow_hits` экспонируются. См. Arsenal.

---

## 4. ASN / CIDR reputation (`asn_reputation.rs`)

### 4.1. Назначение и две формы записей

Operator/refresh-snabжаемый список плохих ASN (хостинг, proxy-фермы, абузивные VPN, Tor-кластеры) + плохих CIDR. `lookup()` возвращает score `[0..1]`, который пишется в ML-слот `asn_reputation` (V139/V140).

Зачем обе формы (комментарий [src/asn_reputation.rs:8](../../src/asn_reputation.rs)):

- **ASN DB** (MaxMind GeoIP2-ASN или эквивалент) — лучшая для хостинга/транзита: плохой AS ловит *все* текущие и будущие блоки этого AS.
- **CIDR-список** — проще вести руками, не нужна БД; правильная форма для Spamhaus DROP, FireHOL-агрегатов, своих threat-intel экспортов.

> AEGIS-ядро **не шипит дефолтный список** — правильный список deployment-specific (SaaS ненавидит трафик DigitalOcean, gaming-шоп обязан его допускать). Дефолтный `asn-cidr.txt` наполняется install/refresh-джобом (Tor + Spamhaus), см. §6.

### 4.2. Формат файла

```text
# ASN entries — AS<number>  <score>  [tag]
AS14061  0.8  digitalocean
AS16509  0.7  aws-ec2

# CIDR entries — <cidr>  <score>  [tag]
185.220.100.0/22  1.0  tor-exit
1.2.3.4/32        0.9  burned-host
```

Парсер ([src/asn_reputation.rs:222](../../src/asn_reputation.rs)): первое поле — токен, второе — **обязательный** score `f32` (строка без score пропускается), третье — tag (`"unknown"` по умолчанию). Score `clamp(0.0, 1.0)`. Префикс `AS`/`as` (без регистра) → ASN-запись; иначе `parse_cidr()` (v4 prefix ≤ 32, v6 prefix ≤ 128). Непарсимые токены тихо пропускаются.

### 4.3. Логика lookup

`lookup(ip)` ([src/asn_reputation.rs:166](../../src/asn_reputation.rs)):

1. **ASN-путь** — если `AsnLookup::asn(ip)` вернул номер и он есть в `asn_index`.
2. **CIDR-путь** — линейный скан per-family Vec (v4/v6), отбирает совпадения по маске.
3. **Если совпало несколько — возвращается с наивысшим score** (оператор, стекающий записи, получает сильнейший сигнал).

Производительность: ASN — O(1), CIDR — O(n) худший случай, но AEGIS-style операторы держат O(10²) CIDR, что нормально на line-rate.

### 4.4. ASN GeoIP-база

ASN-keyed записи (`AS<num>`) **матчат только когда загружена ASN-БД**. Trait `AsnLookup` ([src/asn_reputation.rs:61](../../src/asn_reputation.rs)) абстрагирует IP→ASN; дефолтная `NoopAsnLookup` всегда возвращает `None` → деплои без ASN-БД работают, но матчат только CIDR-записи.

В `aegis-pingora` ([src/bin/aegis-pingora.rs:1277](../../src/bin/aegis-pingora.rs)) уже-загруженный GeoIP-хендл оборачивается в `GeoIpAsnLookup`, так что AS-keyed записи резолвятся. ASN-БД (`dbip-asn-lite.mmdb`) монтируется через `[geoip].asn_db_path` и наполняется refresh-джобом (db-ip ASN-lite, ежемесячно). Подробнее — GeoIP (страна и ASN).

### 4.5. Включение и env-кнобы

ASN/CIDR reputation **включён по умолчанию** ([src/bin/aegis-pingora.rs:1260](../../src/bin/aegis-pingora.rs)). Состав путей: операторские из `AEGIS_ASN_REPUTATION` + дефолтный `asn-cidr.txt` (watched даже при отсутствии).

| Env | Значение | Эффект |
|---|---|---|
| `AEGIS_ASN_REPUTATION` | `0` / `false` / `off` | выключить ASN/CIDR reputation |
| `AEGIS_ASN_REPUTATION` | `path1:path2:…` | добавить операторские фиды |

---

## 5. Threat-intel deny (`filters/threat_intel.rs`)

### 5.1. Отличие от IP ACL и назначение

Это **жёсткий deny-фильтр**, отдельный от операторского `IpAclFilter` (тот живёт в конфиге, перезагружается только при reload конфига). Threat-intel держит `Arc<RwLock<HashSet>>` + CIDR-Vec'ы, обновляемые из локальных файлов фоновой задачей — оператор cron-curl'ит фид в путь, AEGIS перечитывает по mtime.

Почему локальные файлы, а не прямые HTTPS-фетчи (комментарий [src/filters/threat_intel.rs:12](../../src/filters/threat_intel.rs)): не тянуть второй HTTPS-клиент + cert-pinning surface в прокси; у операторов уже есть свой способ аутентификации к платным фидам (curl+token, GitHub Actions, Vault); mtime даёт бесплатную идемпотентность.

### 5.2. Формат файла

Одна запись на строку. Всё после `#` — комментарий (включая trailing). Строка с `/` → CIDR (v4/v6), иначе bare IP → exact-match HashSet. Парсер — `parse_feed_v113` ([src/filters/threat_intel.rs:202](../../src/filters/threat_intel.rs)).

```text
# AbuseIPDB / Spamhaus DROP / FireHOL export
203.0.113.5
192.168.0.0/24
2001:db8::/32        # IPv6 поддерживается
```

> ⚠️ Несоответствие документации в коде: docstring `ThreatIntelConfig` ([src/config.rs:648](../../src/config.rs)) всё ещё пишет «CIDRs not supported yet», но это устарело — с V113 CIDR полноценно поддерживаются (см. тесты `cidr_v4_range_blocks_any_member` / `cidr_v6_range_blocks_any_member`).

### 5.3. CIDR coalescing (V125)

На каждом reload смежные и перекрывающиеся CIDR коалесцируются (`coalesce_v4` / `coalesce_v6`, [src/filters/threat_intel.rs:261](../../src/filters/threat_intel.rs)): три прохода — (net,mask)→диапазоны, sort+merge интервалов, декомпозиция в минимальный набор CIDR. Покрытие сохраняется без потерь; на реальных публичных фидах (Spamhaus DROP, FireHOL L1+2) типично −30…50% записей → быстрее линейный скан. `coalesce_preserves_coverage_end_to_end` проверяет, что каждый IP, матчившийся до коалесцинга, матчится после.

### 5.4. Hot-path и fast-path sentinel (V237)

`check()` ([src/filters/threat_intel.rs:405](../../src/filters/threat_intel.rs)):

1. **Empty-set fast path.** `has_entries: AtomicUsize`, записываемый при reload с `Release`, читается на каждом запросе с `Acquire`. При нуле — мгновенный `Allow` без единого захвата RwLock (для plain-forwarding / без фида).
2. Иначе: exact-match HashSet (O(1)) → при промахе CIDR-скан.
3. Совпадение → `FilterAction::Deny { status: 403 }` (cold-path конструктор `ip_deny_cold`, V230, чтобы hot Allow-путь оставался компактным для icache).

### 5.5. Конфигурация (TOML/DSL)

`ThreatIntelConfig` ([src/config.rs:648](../../src/config.rs)):

| Поле | Тип | Default | Описание |
|---|---|---|---|
| `paths` | `Vec<String>` | `[]` (фильтр неактивен) | пути к deny-фидам |
| `refresh_secs` | `u64` | `300` | как часто перечитывать файлы |

`config_enabled()` всегда `true` — у ThreatIntel нет on/off-флага: пустой фид безвреден (`Allow`). Оператор может принудительно выключить его per-domain через web-UI (V231). Деталей по масштабу: для фидов 10⁵+ записей код советует XDP CIDR-maps (kernel-lookup) — см. [XDP/eBPF](./13-xdp-ebpf.md).

---

## 6. Установка фидов и дневной refresh (`install.sh`)

`ensure_reputation_feeds` ([install.sh:788](../../install.sh)) создаёт `/var/lib/aegis/reputation`, ставит скрипт `aegis-refresh-feeds` и systemd timer.

### 6.1. Что наполняет refresh-джоб

Скрипт `/usr/local/bin/aegis-refresh-feeds` (best-effort, daemon hot-reload'ит изменённое по mtime без рестарта):

| Цель | Источник | Запись |
|---|---|---|
| **Tor exit nodes** | `https://check.torproject.org/torbulkexitlist` | `<ip>/32 0.5 tor-exit` → `asn-cidr.txt` |
| **Spamhaus DROP** | `https://www.spamhaus.org/drop/drop.txt` | `<cidr> 0.8 spamhaus-drop` → `asn-cidr.txt` |
| **db-ip ASN-lite** | `download.db-ip.com/.../dbip-asn-lite-<YYYY-MM>.mmdb.gz` | → `geoip/dbip-asn-lite.mmdb` |
| **CrowdSec JA4** (opt-in) | `${CROWDSEC_LAPI_URL}/v1/decisions?scope=ja4` | `<value>\tcrowdsec` → `ja4-crowdsec.txt` |

`asn-cidr.txt` устанавливается только если содержит ≥1 не-комментарий-строку (атомарно через `install -m 0644`). Tor получает score **0.5** (signal), Spamhaus DROP — **0.8** (abuse).

### 6.2. Дневной таймер

`aegis-refresh-feeds.timer` ([install.sh:880+](../../install.sh)):

```ini
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
```

`enable --now` → seed выполняется сразу при установке (best-effort; модуль остаётся инертным, если сеть упала). Service — `Type=oneshot`, `After=network-online.target`.

### 6.3. CrowdSec consume через refresh (opt-in)

Подтягивание JA4-решений из CrowdSec LAPI — opt-in через `/etc/aegis/feeds.env`:

```bash
# /etc/aegis/feeds.env
CROWDSEC_LAPI_URL=http://127.0.0.1:8080
CROWDSEC_LAPI_KEY=<bouncer-api-key>
```

При заданных переменных refresh-джоб делает `GET .../v1/decisions?scope=ja4` с `X-Api-Key`, и Python-однострочник выбирает `value`-поля, содержащие `_` (т.е. JA4-строки), пишет их в `ja4-crowdsec.txt` с tag `crowdsec`. Этот файл уже в `paths` JA4-reputation (§2.4) и подхватывается mtime-reload'ом.

> 🟡 Это и есть «consume direction», который в [crowdsec_api.rs](../../src/crowdsec_api.rs) назван «small follow-up» — реализован вне Rust, в refresh-скрипте, и только для JA4-scope.

---

## 7. CrowdSec LAPI (`crowdsec_api.rs`)

### 7.1. Что реализовано (V157)

Модуль реализует **expose-direction**: AEGIS отдаёт свои решения в формате CrowdSec Local API, чтобы любой существующий bouncer (nginx, HAProxy, Cloudflare worker, firewall-iptables, Caddy, kubernetes-ingress…) стал enforcer'ом решений AEGIS.

Wire-типы ([src/crowdsec_api.rs:45](../../src/crowdsec_api.rs)):

- `Decision { id, kind ("type"), scope, value, duration, scenario, origin }` — подмножество, которое bouncer'ы реально потребляют.
- `DecisionStream { new, deleted }` — форма `GET /v1/decisions/stream`.
- `AegisDecision` — внутренняя форма, из которой адаптер конвертирует.

Маппинг вердиктов (`AegisDecisionKind::as_crowdsec_str`): `Ban → "ban"`, `Captcha → "captcha"`, `Throttle → "throttle"`. `scope` всегда `"Ip"`, `origin` всегда `"aegis"`, `scenario` = `"aegis/<reason>"`. `format_duration()` отдаёт CrowdSec-строку (`1d4h`, `4h30m`, `5m30s`).

Аутентификация bouncer'а — `validate_bouncer_key()` ([src/crowdsec_api.rs:169](../../src/crowdsec_api.rs)): constant-time сравнение (`ct_eq`) ключа `X-Api-Key` против operator-supplied allow-set `(key, label)`.

### 7.2. Что НЕ реализовано — честная оговорка

> 🟠 **`crowdsec_api.rs` — это wire-типы + адаптер, НЕ смонтированный HTTP-роут.** В докстринге прямо сказано: «Operator wires the actual HTTP route handler». Модуль конвертирует внутреннее denial-state в decision-shape и валидирует ключи, но:
> - `build_stream()` оставляет `deleted` пустым — «caller fills from its tracked-removed set»; трекинг удалённых решений и монотонные id — на стороне caller'а.
> - Не существует готового сборщика `AegisDecision` из runtime-state — комментарий говорит, что operator's adapter code строит их из DynamicTrust/ResponseCache/RiskEngine/ML.
> - Consume-direction (AEGIS читает чужой CrowdSec) реализован только частично и вне Rust — в refresh-скрипте для JA4-scope (§6.3).

Иными словами: CrowdSec-интеграция в коде — это **прочная заготовка + полное тестовое покрытие serde/duration/auth**, но не end-to-end смонтированный сервис из коробки.

---

## 8. Горячая перезагрузка фидов

Все три файловых фида (JA4, ASN/CIDR, threat-intel) перезагружаются фоновой задачей `PingoraBackground` ([src/proxy/pingora_background.rs](../../src/proxy/pingora_background.rs)) — coarse tick **30 с по умолчанию**. На каждом тике проверяется mtime сконфигурированных путей (`any_file_changed`, [src/ja4_reputation.rs:286](../../src/ja4_reputation.rs)) и при изменении вызывается `reload()`.

Критическая safety-гарантия (одинаковая в JA4/ASN/threat-intel): **исчезнувший или нечитаемый файл НЕ обнуляет индекс**. `reload()` собирает новый индекс и свопает его только при `had_any == true` (хоть один файл прочитался). Иначе reload-race, когда фид на секунду пропал, открыл бы шлюз ботам. Тесты `missing_file_preserves_prior_index` / `reload_from_*_file_works` это фиксируют.

---

## 9. Сводка env-переменных

| Env | Default | Модуль | Назначение |
|---|---|---|---|
| `AEGIS_REPUTATION_DIR` | `/var/lib/aegis/reputation` | все | каталог файлов репутации |
| `AEGIS_JA4_REPUTATION` | (unset → **ON**) | ja4_reputation | `0/false/off` выключает; пути через `:` |
| `AEGIS_ASN_REPUTATION` | (unset → **ON**) | asn_reputation | `0/false/off` выключает; пути через `:` |
| `CROWDSEC_LAPI_URL` | (unset) | refresh-джоб | `/etc/aegis/feeds.env`, opt-in JA4 consume |
| `CROWDSEC_LAPI_KEY` | (unset) | refresh-джоб | API-ключ для LAPI |

Конфиг-секция:

| Поле | Default | Модуль |
|---|---|---|
| `threat_intel.paths` | `[]` | threat_intel |
| `threat_intel.refresh_secs` | `300` | threat_intel |
| `[geoip].asn_db_path` | (см. GeoIP) | asn_reputation (ASN-keyed) |

---

## 10. Honesty caveats

1. **Репутация ≠ полная защита.** JA4/ASN reputation — мягкие ML-фичи `[0..1]`, не блокировки; вердикт принимает risk engine (ML и risk engine). Threat-intel — жёсткий 403, но требует, чтобы оператор сам наполнял фид. Под volumetric L3/L4-флудом даже мгновенный deny требует входящего соединения — нужна upstream-защита (BGP/CDN), см. BGP RTBH и SECURITY-AUDIT.

2. **JA4 контролируется клиентом.** Атакующий полностью владеет своим ClientHello. Поэтому corpus-`Allow` не может опустить подозрение ниже неподделываемого baseline (H9b-clamp, §3.3), а самообучение guard'ит вырожденный JA4 (§2.3). Это известное ограничение fingerprint-сигналов.

3. **Guard вырожденных JA4 — safety net, не фикс.** `is_degenerate_ja4` ловит «пустой ClientHello», но настоящее решение (захват реальных полей) ещё не сделано — так сказано в коде.

4. **CrowdSec — заготовка, не смонтированный сервис.** Реализованы wire-типы, адаптер, auth и тесты; HTTP-роут, трекинг `deleted` и сборка решений из runtime-state — на операторе (§7.2).

5. **Дефолтных репутационных списков ядро не шипит** (кроме встроенного ~30-записного JA4-корпуса). `asn-cidr.txt` наполняется install/refresh-джобом (Tor 0.5 + Spamhaus 0.8); без сети/джоба ASN/CIDR-модуль активен, но пуст и инертен. Threat-intel пуст пока оператор не задаст `paths`.

6. **Вся репутация работает в `aegis-pingora`-бинаре**, не в legacy-гипере. Числа производительности (sub-µs CIDR-скан, O(1) JA4-lookup) — это in-process характеристики; реальный деплой добавляет I/O-overhead Pingora (см. Бенчмаркинг).
