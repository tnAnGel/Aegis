# Обогащение и threat-intel

Подсистема обогащения (enrichment) собирает дополнительный контекст о клиенте поверх «голого» HTTP-запроса: пассивный отпечаток ОС/TCP-стека (p0f), опциональный антивирусный скан тела через `clamd` (ClamAV) и периодически-обновляемые deny-листы из внешних threat-intel фидов (AbuseIPDB / Spamhaus DROP / FireHOL и т.п.). Этот документ описывает, что именно делает код в `src/enrichment.rs`, `src/filters/threat_intel.rs`, `src/p0f.rs`, `src/clamav_scanner.rs`, и где части включаются опционально.

> Честная оговорка по объёму: на «живом» пути (`ArsenalState`) в фасад обогащения сейчас регистрируется одна реальная боевая источник-реализация — JA4-корпус (`src/arsenal.rs:464`). Остальные источники (JA4/ASN-репутация, GeoIP) имеют свои отдельные кэши и пути и в `EnrichmentFacade` по умолчанию не подключены. Это явно отмечено ниже.

---

## 1. Карта подсистемы

| Компонент | Файл | Назначение | Состояние по умолчанию |
|---|---|---|---|
| Унифицирующий фасад обогащения (WISE-стиль) | `src/enrichment.rs` | Один кэшируемый фасад поверх разнородных источников, единая форма lookup, агрегированный вердикт | Включён; зарегистрирован 1 источник (JA4-корпус) |
| Threat-intel deny-лист | `src/filters/threat_intel.rs` | Deny по точным IP и CIDR из локальных файлов-фидов, фоновый reload | Активен, только если заданы `paths` |
| p0f — пассивный отпечаток ОС | `src/p0f.rs` | Классификация TCP SYN (window/MSS/wscale/TTL/опции) в семейство ОС | Встроенная мини-БД; расширяется файлом |
| ClamAV-скан тела | `src/clamav_scanner.rs` | Стрим тела загрузок в `clamd` по INSTREAM TCP, вердикт по сигнатуре | Выключен (opt-in через `AEGIS_CLAMAV_ADDR`) |

Смежные документы: WAF — [10-waf.md](10-waf.md), TLS-фингерпринтинг и JA4T — [11-tls-fingerprinting.md](11-tls-fingerprinting.md), репутация — [12-reputation.md](12-reputation.md), XDP/eBPF (kernel-путь CIDR) — [13-xdp-ebpf.md](13-xdp-ebpf.md), GeoIP — [20-geoip.md](20-geoip.md), Arsenal/сценарии — [21-arsenal-scenarios.md](21-arsenal-scenarios.md), модель безопасности — [23-security-model.md](23-security-model.md), Admin API — [30-admin-api.md](30-admin-api.md).

---

## 2. Фасад обогащения (`src/enrichment.rs`)

Идея заимствована из Arkime WISE (Wireless Intelligence Sources Engine): один кэшируемый фасад перед каждым источником, одинаковая форма lookup, per-source TTL и провенанс (какой источник дал вердикт), который проносится через ответ. Это заменяет схему «у каждого источника свой кэш, и код, которому нужна полная картина по IP, зовёт четыре раза и сам сливает вердикты».

### 2.1. Ключи и вердикты

Сущность, по которой обогащаемся, — `EntityKey` (`src/enrichment.rs:55`):

| Вариант `EntityKey` | `kind_str()` | Откуда |
|---|---|---|
| `Ip(IpAddr)` | `"ip"` | IP клиента |
| `Ja4(String)` | `"ja4"` | TLS JA4-отпечаток |
| `Asn(u32)` | `"asn"` | Номер автономной системы |
| `UserAgent(String)` | `"ua"` | User-Agent |

Вердикт источника и агрегата — `Verdict` (`src/enrichment.rs:74`): `Allow`, `Deny`, `Unknown`.

### 2.2. Источник как read-through-провайдер

Источник реализует трейт `EnrichmentSource` (`src/enrichment.rs:121`):

```rust
pub trait EnrichmentSource: Send + Sync {
    fn name(&self) -> &'static str;
    fn lookup(&self, key: &EntityKey) -> Option<(Verdict, String)>;
    fn default_ttl(&self) -> Duration { Duration::from_secs(30) }
}
```

- `name()` возвращает `&'static str` — это удерживает кардинальность per-source счётчиков ограниченной.
- `lookup()` возвращает `None`, когда источник успешно отработал, но ключ им не отслеживается. Явную неопределённость (например, GeoIP-БД загружена, но страна не классифицирована) сигнализируют как `Some((Verdict::Unknown, ...))`.
- Вторым элементом кортежа идёт `label` — человекочитаемая метка/тег (`"sqlmap"`, `"aws"` и т.п.), попадающая в `SourceHit.label`.

### 2.3. Агрегация вердиктов

`Enrichment::aggregate()` (`src/enrichment.rs:98`) сводит все `SourceHit` в один вердикт по правилу:

```
любой Deny  →  Deny   (short-circuit)
иначе любой Allow  →  Allow
иначе  →  Unknown
```

`Enrichment::deny_reasons()` (`src/enrichment.rs:109`) возвращает `label` всех источников, проголосовавших `Deny`, — для журналирования/панели.

### 2.4. Кэш фасада

`EnrichmentFacade` (`src/enrichment.rs:156`) держит:

- `sources: Vec<Arc<dyn EnrichmentSource>>` — зарегистрированные источники в порядке регистрации;
- `cache: RwLock<HashMap<EntityKey, CacheEntry>>` — агрегированный кэш;
- `per_source_stats` — независимые счётчики `queries/hits/misses` на каждый источник;
- глобальные `cache_hits`/`cache_misses` и `capacity`.

Поведение `lookup()` (`src/enrichment.rs:187`):

1. **Cache hit:** если запись есть и `Instant::now() < entry.expires_at` — вернуть клон, инкремент `cache_hits`.
2. **Cache miss:** инкремент `cache_misses`, обход всех источников. Для каждого инкрементится `queries`; при `Some` — `hits` + добавляется `SourceHit { source, verdict, label, fetched_at }`; при `None` — `misses`.
3. **TTL агрегата:** `expires_at = now + shortest_ttl`, где `shortest_ttl` — минимум из `default_ttl()` сработавших источников, но не более стартового потолка `Duration::from_secs(300)` (`src/enrichment.rs:199`). То есть TTL агрегированной записи = минимуму TTL вкладчиков (свежесть обновления репутации остаётся видимой).
4. Результат кладётся в кэш и возвращается.

Вытеснение (`insert`, `src/enrichment.rs:243`): при достижении `capacity` удаляется одна самая старая по `inserted` запись (линейный скан `min_by_key`). На «живом» пути фасад создаётся с ёмкостью **16 384** (`src/arsenal.rs:463`).

> Замечание по семантике кэша: это не классический LRU по обращению — отбрасывается запись с наименьшим временем вставки (insert-order), а не последнего доступа. На рабочих размерах (десятки тысяч записей, короткий TTL) это допустимо.

Прочие методы: `invalidate(key)` / `invalidate_all()` (`src/enrichment.rs:265`), `registered_sources()`, `source_stats(name) -> (queries, hits, misses)`, `cache_stats() -> (hits, misses, len)`.

### 2.5. Подключение на живом пути и admin API

В `ArsenalState::new_default()` фасад строится и в него регистрируется **один** источник — `Ja4CorpusEnrichmentSource` поверх общего `Ja4Corpus` (`src/arsenal.rs:460-468`). Хелпер `ArsenalState::enrich_ja4(ja4)` (`src/arsenal.rs:589`) бьёт по фасаду, инкрементит `counters.enrichment_lookups` и возвращает агрегат.

Состояние и ad-hoc-проверки доступны через Admin API (`src/proxy/pingora_admin.rs`):

| Метод | Путь | Что отдаёт |
|---|---|---|
| `GET` | `/admin/api/enrichment` | `wired`, per-source `{name, queries, hits, misses}`, `cache {hits, misses, size}` (`pingora_admin.rs:2131`, `:4077`) |
| `POST` | `/admin/api/enrichment/lookup` | По JSON `{key_kind, value}` (`ip`/`ja4`/`asn`/`user_agent`) — `aggregate` + список `sources [{source, verdict, label}]` (`pingora_admin.rs:2160`, `:4080`) |

Полный список маршрутов админки — [30-admin-api.md](30-admin-api.md).

---

## 3. Threat-intel deny-листы (`src/filters/threat_intel.rs`)

`ThreatIntelFilter` — это `TrafficFilter` (имя фильтра `"threat_intel"`, `src/filters/threat_intel.rs:402`), который блокирует IP клиента по deny-листам, периодически перечитываемым из локальных файлов.

### 3.1. Почему отдельный фильтр от IP ACL

- `IpAclFilter` курируется оператором и живёт в основном конфиге; reload меняет весь набор сразу, его нельзя обновлять несколько раз в день извне без перезагрузки конфига.
- `ThreatIntelFilter` держит `Arc<RwLock<HashSet>>` (+ CIDR-вектора), которые фоновая задача обновляет из одного или нескольких файлов. Оператор наполняет их по cron'у: `curl` фид в файл — Aegis перечитывает.

**Почему локальные файлы, а не прямой HTTPS-фетч** (комментарий в шапке модуля): не тянуть ещё один HTTPS-клиент и cert-pinning в прокси; у операторов уже есть привычный способ аутентификации к платным фидам (curl+токен, GitHub Actions, Vault); mtime файла даёт бесплатную идемпотентность — перечитать неизменённый файл это no-op.

### 3.2. Конфигурация

Секция конфига `filters.threat_intel` — структура `ThreatIntelConfig` (`src/config.rs:647`):

| Поле | Тип | Дефолт | Назначение |
|---|---|---|---|
| `paths` | `Vec<String>` | `[]` | Локальные пути к файлам-фидам (одна запись на строку) |
| `refresh_secs` | `u64` | `300` | Как часто перечитывать файлы фидов |

```yaml
filters:
  threat_intel:
    paths:
      - /var/lib/aegis/feeds/spamhaus-drop.txt
      - /var/lib/aegis/feeds/firehol-level1.netset
      - /var/lib/aegis/feeds/abuseipdb-blacklist.txt
    refresh_secs: 300
```

Пример наполнения фидов по cron (вне Aegis):

```bash
# Spamhaus DROP (только CIDR)
curl -s https://www.spamhaus.org/drop/drop.txt \
  -o /var/lib/aegis/feeds/spamhaus-drop.txt

# FireHOL Level 1
curl -s https://iplists.firehol.org/files/firehol_level1.netset \
  -o /var/lib/aegis/feeds/firehol-level1.netset
```

### 3.3. Формат файла фида

Парсер `parse_feed_v113` (`src/filters/threat_intel.rs:202`) разбирает по одной записи на строку:

- Всё после `#` отбрасывается (комментарии, в т.ч. хвостовые), пустые строки игнорируются.
- Строка с `/` → CIDR, попадает в per-family вектора. IPv4: `prefix <= 32`, IPv6: `prefix <= 128`; маска вычисляется и сеть нормализуется (`net & mask`). `0.0.0.0/0` корректно матчит всё.
- Голый IP → точный HashSet (`O(1)` lookup).
- Невалидные строки (нечисловой префикс, неразбираемый адрес) тихо пропускаются.

Поддерживаются и IPv4, и IPv6 (точные адреса и CIDR обоих семейств).

### 3.4. Reload и коалесцирование CIDR

`reload()` (`src/filters/threat_intel.rs:100`) перечитывает все файлы и **атомарно** подменяет наборы:

- Файл, который не удалось прочитать, логируется на уровне `warn` и пропускается — один отсутствующий фид не стирает остальные.
- После сборки CIDR коалесцируются: `coalesce_v4` / `coalesce_v6` (`:261`, `:299`) объединяют перекрывающиеся и смежные диапазоны (interval-merge → разложение обратно в минимальный набор CIDR). На реальных публичных фидах это обычно −30…50% записей без потери покрытия (каждый IP, матчившийся до, матчится и после).
- Запись наборов идёт под `RwLock::write`, после чего обновляется fast-path-сентинел.

> Важно про «mtime-reload»: reload **безусловно** перечитывает файлы по таймеру. Сам `ThreatIntelFilter` не сравнивает mtime — идемпотентность держится на том, что перечитывание неизменённого файла даёт тот же набор (комментарий «file mtime gives free idempotency» относится к рабочему процессу оператора). mtime-aware reload реализован у соседних подсистем (JA4-/ASN-репутация — `src/proxy/pingora_background.rs:427-438`), а не здесь.

Планировщик reload: в `aegis` (Hyper) — `tokio::spawn` с интервалом `refresh_secs.max(30)`; первый немедленный tick пропускается, т.к. загрузка уже была при конструировании (`src/server.rs:576-591`). Задача создаётся только если `is_active()` (есть хотя бы один путь).

### 3.5. Hot-path проверки

`check()` (`src/filters/threat_intel.rs:405`):

1. **Empty-set fast path (V237):** атомарный сентинел `has_entries` (суммарное число точных IP + CIDR после коалесцирования) читается с `Acquire`. Если `0` — немедленный `Allow` без единого захвата `RwLock`. Это убирает три захвата лока на горячем пути в plain-forwarding и деплоях без загруженного фида. Сентинел пишется с `Release` **после** коммита наборов в `reload()`.
2. Точный матч по `HashSet` (`O(1)`).
3. Если нет — `matches_cidr()` (`:176`): линейный скан per-family вектора `(net, mask)` с `(host & mask) == net`.

Любое срабатывание → `FilterAction::Deny { status: 403, reason }` (`ip on threat-intel deny list` или `ip in threat-intel CIDR range`). Конструктор Deny вынесен в `#[cold] #[inline(never)] ip_deny_cold` (V230), чтобы горячий Allow-путь (≈99% трафика) оставался компактным по icache.

**Масштаб:** линейный скан рассчитан на 10²–10⁴ записей (Spamhaus DROP ~1000); при таких размерах он суб-микросекундный. Для очень больших фидов (10⁵+) оператору рекомендуется выносить CIDR в **XDP CIDR-карты** ([13-xdp-ebpf.md](13-xdp-ebpf.md)), где lookup делает ядро.

### 3.6. Управление включением

ThreatIntel не имеет on/off-флага: он активен всегда, когда присутствует (`config_enabled()` всегда `true`, `src/filters/threat_intel.rs:78`) — пустые наборы безвредны (`Allow`). Принудительно выключить per-domain можно через веб-UI (единый источник правды по тумблерам фильтров — `RuntimeToggles`). Диагностика: `entry_count()`, `cidr_count()`, `is_active()`.

---

## 4. p0f — пассивный отпечаток ОС/TCP-стека (`src/p0f.rs`)

JA4T (в `src/ja4.rs`) фиксирует опции TCP SYN, но останавливается на хэше wire-shape. p0f идёт дальше: классифицирует эту форму в вероятное семейство ОС по БД дефолтов TCP-стеков. Ценность связки: JA4T говорит «два клиента — один TCP-стек»; p0f даёт **«клиент в UA называется Chrome на Windows, но его TCP-стек — Linux»** — сильный сигнал прокси/песочницы/скрапера для коррелятора отпечатков (`crate::fp_correlation`).

> Объём честно ограничен: V155 — это сфокусированный минимальный сабсет p0f, а не полный порт. Полный корпус p0f не бандлится (≈50KB к бинарю; 99% операторов нужны только современные desktop/mobile кластеры).

### 4.1. Вход классификатора — `Ja4tSyn`

`Ja4tSyn` (`src/p0f.rs:36`) — SYN-наблюдения, которые Aegis уже захватывает (`src/tcp_info.rs::capture_with_xdp`, предпочтительно eBPF, с userspace `TCP_INFO`-фолбэком):

| Поле | Тип | Смысл |
|---|---|---|
| `window` | `u16` | Размер TCP-окна в SYN |
| `mss` | `u16` | Maximum Segment Size |
| `wscale` | `u8` | Window scale |
| `ttl` | `u8` | TTL первого хопа (главный делитель ОС у p0f) |
| `options` | `[u8; 8]` | Виды опций в wire-порядке (MSS=2, NOP=1, WSCALE=3, SACKOK=4, TS=8); хвостовые нули = «опций больше нет» |

### 4.2. Сигнатура и TTL-бакеты

`olayout_string()` (`:57`) джойнит ненулевые опции через `-` (например `2-4-8-1-3`). `signature()` (`:70`) строит p0f-подобную строку:

```
<ttl_bucket>:<window>:<mss>:<wscale>:<olayout>
напр.  64:64240:1460:7:2-4-8-1-3
```

`ttl_bucket(observed)` (`:86`) восстанавливает исходный TTL из наблюдаемого (уже декрементированного хопами): `0..=32→32`, `33..=64→64`, `65..=128→128`, `129..→255`.

> Сабсет полного формата: IP-версию, DF-флаг, quirks и payload-class p0f Aegis опускает — матчер держится только на тех полях, что захватываются надёжно.

### 4.3. База сигнатур и классификация

`OsFamily` (`src/p0f.rs:99`): `Linux`, `Windows`, `Macos`, `Bsd`, `Ios`, `Android`, `Unknown` (грубая классификация — нужного коррелятору уровня; «Linux 2.6 vs 5.4» для security-прокси редко actionable).

Встроенная БД `OsDatabase::default()` (`:135`) — `HashMap<signature → OsFamily>` с современными desktop/mobile-кластерами на 2024 (источники: `p0f-3.09b/p0f.fp`, FoxIO JA4 cookbook, сравнения захватов Wireshark):

| Семейство | Примеры сигнатур |
|---|---|
| Linux 5.x+ | `64:64240:1460:7:2-4-8-1-3`, `64:65535:...`, `64:29200:...` |
| Windows 10/11 | `128:65535:1460:8:2-1-3-1-1-8-4`, `128:64240:...` |
| macOS 13+ | `64:65535:1460:6:2-1-3-1-1-8-4` |
| iOS 16+ | `64:65535:1460:7:2-1-3-1-1-8-4` |
| Android 12+ | `64:65535:1460:9:2-4-8-1-3`, `64:65535:1460:8:...` |
| FreeBSD/pfSense | `64:65535:1460:6:2-1-3-4-8` |

`classify(sig)` (`:214`) — **только точное совпадение**; промах → `OsFamily::Unknown`. Fuzzy-матч (wildcards по window и т.п.) вне объёма — операторам с богатыми нуждами рекомендуется вендорить `huginn-net` или гонять полноценный p0f рядом и скармливать его вердикт.

Расширение БД: `OsDatabase::load_str()` (`:184`, упоминается и `load_file`) — строки `<signature> <os_family>`, комментарии `#` и пустые строки игнорируются, имена семейств case-insensitive (`mac`→macos, `freebsd`→bsd), неизвестные семейства тихо пропускаются (чтобы не засорять БД мусором).

Удобные функции: `classify_syn(syn, db)` (`:223`) — обёртка `db.classify(syn.signature())`. `ua_os_family(ua)` (`:231`) — мост в коррелятор: выводит ОС, заявленную в User-Agent (важно: `iphone`/`ipad` проверяется **раньше** `mac os`, т.к. iOS-UA исторически содержат «Mac OS X»). Несовпадение `ua_os_family` ↔ `classify_syn` и есть искомый сигнал рассогласования.

---

## 5. ClamAV-скан тела (`src/clamav_scanner.rs`)

WAF-инспекция тела (см. [10-waf.md](10-waf.md)) ловит SQLi/XSS/cmd-injection в `application/x-www-form-urlencoded`/JSON-телах, но **не** ловит малварь в файловых загрузках `multipart/form-data` — это задача ClamAV. Модуль подключает Aegis к работающему демону `clamd` через его **INSTREAM TCP API**.

> Выключен по умолчанию и opt-in: если `AEGIS_CLAMAV_ADDR` не задан — это no-op. `clamd` крутится в сети оператора; Aegis демон не бандлит. Кроме того, модуль был полностью построен в V129, но долго не имел живого вызывающего кода (дремал); V234 сделал его чисто оживляемым без смены поведения.

### 5.1. Конфигурация (env)

`ClamavScanner::from_env()` (`src/clamav_scanner.rs:170`) читает:

| Переменная окружения | Дефолт | Поле `ClamavConfig` |
|---|---|---|
| `AEGIS_CLAMAV_ADDR` | не задано → no-op | `addr: Option<String>` |
| `AEGIS_CLAMAV_MAX_BODY_BYTES` | `26214400` (25 MiB) | `max_body_bytes` |
| `AEGIS_CLAMAV_TIMEOUT_MS` | `5000` | `timeout` |

```bash
AEGIS_CLAMAV_ADDR=127.0.0.1:3310
AEGIS_CLAMAV_MAX_BODY_BYTES=26214400   # 25MB
AEGIS_CLAMAV_TIMEOUT_MS=5000
```

`scan_content_types` (`ClamavConfig::default()`, `:86`) — какие `application/*` сканировать. По умолчанию: `multipart/form-data`, `application/octet-stream`, `application/zip`, `application/x-rar-compressed`, `application/x-7z-compressed`, `application/x-tar`, `application/x-bzip2`, `application/pdf`, `application/msword`, `application/vnd.openxmlformats-officedocument`. `application/json` намеренно исключён — clamd там нечего искать; `text/*`, `image/*` пропускаются.

### 5.2. Жизненный цикл и вызов

Один общий экземпляр на процесс (`ClamavScanner` дёшево `Clone`, держит только конфиг — ни сокетов, ни пулов). Рекомендованная схема — `Arc<ClamavScanner>` при старте под стать другим сервисам хендлера (`Arc<WafFilter>`, `Arc<AnomalyDetector>`). Call-site (после буферизации тела WAF'ом):

```rust
if scanner.is_enabled()
    && scanner.should_scan(content_type, body.len())
{
    if let ScanVerdict::Infected { signature } = scanner.scan(&body).await {
        // только Infected блокирует — здесь deny/403
    }
}
```

- `is_enabled()` (`:198`) — дешёвый opt-in-гейт: `true` только когда задан `addr`. Hot-path обязан проверять его первым — при `false` сканер ничего не делает, и можно пропустить всю работу с телом. `enabled()` (`:205`) — back-compat-алиас.
- `should_scan(content_type, len)` (`:214`) — пре-фильтр без блокировки: `false`, если сканер выключен, тело пустое, тело > `max_body_bytes`, или content-type не в списке.

### 5.3. Протокол скана и границы

`scan(body)` (`:256`) → `scan_inner` (`:280`):

- Не сконфигурирован → `Skipped`; пустое или сверх-лимитное тело → `Skipped` (тело пропускается; прокси полагается на собственный body-cap WAF, **префикс не сканируется** — контракт V129).
- INSTREAM: `zINSTREAM\0`, затем повторяющиеся `<u32 BE длина><байты>` чанками по 64 KiB, терминатор `0u32`. Ответ читается до `NUL`.
- Весь обмен обёрнут в `timeout(self.cfg.timeout, ...)`.
- **Cap ответа (V233):** буфер ответа ограничен `RESP_CAP = 4096`; если `NUL` не пришёл в пределах cap — жёсткая ошибка (скомпрометированный/чужой процесс на сокете не сможет залить гигабайты и устроить OOM воркеру).

Парсер `parse_response()` (`:344`):

| Ответ clamd | Вердикт |
|---|---|
| `stream: OK` (ровно эта строка) | `Clean` |
| `stream: <sig> FOUND` | `Infected { signature }` |
| прочее / пусто / ошибка размера | `Error` |

> Закалка V233: `FOUND` проверяется **первым и независимо** — реальный `FOUND` нельзя «понизить» до Clean подобранным суффиксом; `Clean` — это якорный полный матч строки `stream: OK`, а не `ends_with(" OK")` (иначе тело, чья сигнатура оканчивается на « OK», прошло бы fail-open).

### 5.4. Направление отказа (fail-open by design)

`ScanVerdict` (`:117`) и `is_block()` (`:141`) — единственный источник правды: **блокирует только `Infected`**. `Clean`, `Skipped` и `Error` — все ALLOW.

| Вердикт | Значение | Блокирует? |
|---|---|---|
| `Clean` | Тело чисто | Нет |
| `Infected { signature }` | clamd нашёл сигнатуру | **Да** |
| `Skipped` | Content-type не в списке / тело пустое / > cap / не сконфигурирован | Нет |
| `Error` | clamd недоступен, таймаут, или мусорный/сверх-лимитный ответ | Нет (fail-open) |

Connect-failure, timeout и malformed-ответ дают `Error` → ALLOW. Это намеренно: единичная просадка clamd не должна заклинить все загрузки (оператор разворачивает редундантный clamd). `Error` считается в метрику `aegis_clamav_scan_errors` ([25-metrics-telemetry.md](25-metrics-telemetry.md)). Кому нужен **fail-closed** — обязан сам трактовать `Error` как deny на своём call-site; модуль этого никогда не делает.

---

## 6. Сводка: что включено по умолчанию

| Возможность | Включена «из коробки» | Как включить |
|---|---|---|
| Фасад обогащения + JA4-корпус-источник | Да | Регистрируется автоматически в `ArsenalState` |
| JA4/ASN-репутация, GeoIP как источники фасада | Нет (свои отдельные кэши/пути) | Не подключены к `EnrichmentFacade` по умолчанию — см. [12-reputation.md](12-reputation.md), [20-geoip.md](20-geoip.md) |
| Threat-intel deny-листы | Только если задан `filters.threat_intel.paths` | Указать пути к фидам + cron-обновление |
| p0f-классификация ОС | Встроенная мини-БД активна | Расширить файлом через `OsDatabase::load_str`/`load_file` |
| ClamAV-скан тела | Нет (opt-in) | Задать `AEGIS_CLAMAV_ADDR` (+ опц. cap/timeout) |

См. также: [04-configuration.md](04-configuration.md) (полная схема конфига), 42-текущее-состояние-STATUS.md (актуальный статус opt-in-фич), [47-faq-troubleshooting.md](47-faq-troubleshooting.md).
