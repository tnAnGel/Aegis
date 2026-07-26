# GeoIP (страна и ASN)

Подсистема GeoIP в AEGIS отвечает за две независимые задачи: определение страны клиента (ISO 3166-1 alpha-2) для страновых правил и карты мира в панели, а также определение номера автономной системы (ASN) клиентского IP для AS-привязанной репутации. Обе базы — формат MaxMind `.mmdb`, читаются через crate `maxminddb`, поставляются в комплекте (db-ip Lite, CC BY 4.0) и загружаются «из коробки» без обязательной конфигурации.

Исходники, на которых основана эта глава: [`src/geoip.rs`](../../src/geoip.rs), [`src/real_ip.rs`](../../src/real_ip.rs), [`install.sh`](../../install.sh) (функция `ensure_geoip_db`), а также точки использования в [`src/proxy/pingora_http.rs`](../../src/proxy/pingora_http.rs), [`src/proxy/pingora_admin.rs`](../../src/proxy/pingora_admin.rs), [`src/config.rs`](../../src/config.rs), [`src/metrics/geo_shard.rs`](../../src/metrics/geo_shard.rs) и [`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs).

---

## 1. Что именно делает GeoIP

| Функция | База | Где используется | Файл |
|---|---|---|---|
| Страна клиента (alpha-2) | Country DB (db-ip «IP to Country Lite») | страновой deny-лист, карта мира, обогащение журнала запросов | `geoip.rs`, `pingora_http.rs` |
| Номер AS (ASN) | ASN DB (db-ip «IP to ASN Lite») | AS-привязанная репутация (Tor/Spamhaus + оператор), ML-фича `asn_reputation` | `geoip.rs`, `asn_reputation.rs` |

Ключевой инвариант (см. модульный docstring `src/geoip.rs`): база — **mmap-загрузка один раз на старте**, поиск без аллокаций; неудачная загрузка **никогда не прерывает старт** — она логирует предупреждение и подставляет no-op (`NoopGeoIp`), так что прокси продолжает обслуживать трафик при отсутствующей или устаревшей базе.

---

## 2. Трейт `GeoIpLookup` и реализации

Платформенно-нейтральный фасад (`src/geoip.rs`):

```rust
pub trait GeoIpLookup: Send + Sync {
    fn country(&self, ip: IpAddr) -> Option<String>;   // alpha-2, UPPERCASE
    fn asn(&self, _ip: IpAddr) -> Option<u32> { None }  // дефолт: None
}
```

| Реализация | `country()` | `asn()` | Когда возвращается из `load_with_asn` |
|---|---|---|---|
| `NoopGeoIp` | `None` | `None` (дефолт трейта) | нет ни country, ни ASN базы (или обе не открылись) |
| `MaxMindGeoIp` | из Country DB | из ASN DB, если прикреплена через `with_asn` | загружена country-база (ASN опционально) |
| `AsnOnlyGeoIp` | `None` | из ASN DB | задан только ASN-путь, country-базы нет |

- `country()` извлекает `rec.country.iso_code` и приводит к **верхнему регистру** (`to_ascii_uppercase`). `None` означает: приватный диапазон, неаллоцированный блок или отсутствие базы.
- `asn()` возвращает `rec.autonomous_system_number`. По умолчанию `None`, поэтому реализациям без ASN ничего переопределять не нужно.
- Country и ASN — **два отдельных `.mmdb`-файла** (MaxMind/db-ip так и поставляют), поэтому ASN-ридер прикрепляется отдельным методом `MaxMindGeoIp::with_asn(path)`.

> Честная оговорка: схема записей — это `geoip2::Country` / `geoip2::Asn` из самого crate `maxminddb` (нулевое копирование с корректными лайфтаймами); самописная структура borrow-checker не проходила.

---

## 3. Поставляемые базы (засев)

AEGIS поставляет рабочие базы в репозитории под `data/geoip/`:

| Константа (в `geoip.rs`) | Имя файла | Источник | Лицензия |
|---|---|---|---|
| `BUNDLED_COUNTRY_DB_NAME` | `dbip-country-lite.mmdb` | db-ip «IP to Country Lite» | CC BY 4.0 |
| `BUNDLED_ASN_DB_NAME` | `dbip-asn-lite.mmdb` | db-ip «IP to ASN Lite» | CC BY 4.0 |

Атрибуция, которую возвращает админ-API: `IP geolocation by DB-IP (https://db-ip.com) — CC BY 4.0` (см. `api_geoip_status`).

### Засев на установке (`install.sh`, `ensure_geoip_db`)

Функция `ensure_geoip_db` копирует поставляемую country-базу в записываемый абсолютный путь, который демон резолвит автоматически:

```sh
# src = $AEGIS_SRC/data/geoip/dbip-country-lite.mmdb
# dst = $AEGIS_HOME/geoip  (= /var/lib/aegis/geoip)
cp -n "$src" "$dst/dbip-country-lite.mmdb"   # -n: не затирать обновлённую оператором базу
chown -R "$AEGIS_USER:$AEGIS_USER" "$dst"
chmod 0755 "$dst"; chmod 0644 "$dst/dbip-country-lite.mmdb"
```

- `cp -n` (no-clobber) гарантирует, что засев не перезапишет базу, уже обновлённую через кнопку Update в панели.
- Если поставляемый файл отсутствует, install.sh логирует `WARN: bundled GeoIP db missing … — map will be empty until Update is run` и не падает.

### Засев ASN-базы (`install.sh`, скрипт `aegis-refresh-feeds`)

ASN-база засевается не через `ensure_geoip_db`, а через генерируемый install.sh скрипт `aegis-refresh-feeds` (часть `ensure_reputation_feeds`), потому что AS-привязанная репутация включена по умолчанию. Скрипт ежемесячно тянет db-ip ASN-lite:

```sh
GEO_DIR=/var/lib/aegis/geoip
M=$(date -u +%Y-%m)
curl -fsS -m 120 "https://download.db-ip.com/free/dbip-asn-lite-$M.mmdb.gz" -o "$TMP/asn.mmdb.gz"
gunzip -f "$TMP/asn.mmdb.gz"
install -m 0644 -o "$OWNER" -g "$OWNER" "$TMP/asn.mmdb" "$GEO_DIR/dbip-asn-lite.mmdb"
```

Скрипт ставится таймером `aegis-refresh-feeds.timer` (`OnCalendar=daily`, `RandomizedDelaySec=1h`, `Persistent=true`). Все скачивания best-effort: при сетевом сбое модуль остаётся инертным (нулевые ложные срабатывания), а не валит установку. Демон **горячо перечитывает** изменившиеся файлы по mtime — рестарт не нужен. Подробнее о репутационных фидах см. [12-reputation.md](12-reputation.md).

---

## 4. Резолвер путей (приоритет: config → env → bundled)

Оба резолвера в `src/geoip.rs` следуют одной схеме и возвращают `None`, только когда ничего не задано **и** не найден ни один поставляемый файл (тогда — `NoopGeoIp`).

### Country: `resolve_country_db_path(configured)`

1. Явный `[geoip] db_path` из конфигурации (если непустой) — побеждает.
2. Переменная окружения `AEGIS_GEOIP_PATH` (если непустая).
3. `default_country_db_path()` — первый существующий файл из списка каталогов.

### ASN: `resolve_asn_db_path(configured)`

1. Явный `[geoip] asn_db_path`.
2. Переменная окружения `AEGIS_ASN_PATH`.
3. `default_asn_db_path()`.

> Зеркальность важна: путь конфигурации через DSL оставляет `cfg.geoip = None`, поэтому fallback на env/bundled — единственный способ, которым AS-привязанная репутация и карта мира работают «из коробки».

### Список каталогов поиска (в порядке приоритета)

Для **обеих** баз `default_*_db_path()` пробует одни и те же каталоги, добавляя соответствующее имя файла:

| Приоритет | Каталог | Назначение |
|---|---|---|
| 1 | `/var/lib/aegis/geoip` | стандартный writable-путь демона (сюда пишет install.sh и Update) |
| 2 | `/etc/aegis/geoip` | альтернативное системное размещение |
| 3 | `/usr/local/src/aegis/data/geoip` | дерево исходников при установке из исходников |
| 4 | `data/geoip` | относительный путь (запуск из репозитория для разработки) |

Файл, записанный Update-эндпоинтом в `/var/lib/aegis/geoip`, всегда побеждает поставляемый (он первый в списке).

### Точки загрузки

| Бинарь / путь | Вызов |
|---|---|
| `aegis-pingora` (data plane) | `pingora_http.rs`: `resolve_country_db_path` + `resolve_asn_db_path` → `load_with_asn(...)` |
| `aegis` (hyper) | `server.rs`: `load_with_asn(cfg.geoip.db_path, cfg.geoip.asn_db_path)` |

> Честная оговорка: hyper-путь (`server.rs`) загружает базы **строго из `cfg.geoip`** (без env/bundled-fallback) — если `[geoip]` не задан, передаётся `None`. Полный резолвер config→env→bundled применяется в pingora-data-plane (`pingora_http.rs`), который является основным.

---

## 5. Логика `load_with_asn`

`load_with_asn(country_path, asn_path)` (`src/geoip.rs`) — единственная точка сборки `Arc<dyn GeoIpLookup>`. Пустые/`None`/отсутствующие пути допустимы; деградация логируется. Дерево решений:

| country | asn | Результат | Лог |
|---|---|---|---|
| есть | есть, открылась | `MaxMindGeoIp` (country + ASN) | `info`: country + ASN databases loaded |
| есть | есть, **не** открылась | `MaxMindGeoIp` (только country) | `warn`: ASN reputation will only match CIDR entries |
| есть | нет | `MaxMindGeoIp` (только country) | `info`: country database loaded |
| нет | есть, открылась | `AsnOnlyGeoIp` | `info`: ASN-only database loaded |
| нет | нет (или country не открылась) | `NoopGeoIp` | `warn`: geo deny list ignored |

`load(path)` — тонкая обёртка `load_with_asn(path, None)` для вызовов без ASN.

---

## 6. Страновые правила (`[geoip]` deny-лист)

Конфигурация (`src/config.rs`, структура `GeoIpConfig`):

| Поле | Тип | По умолчанию | Назначение |
|---|---|---|---|
| `db_path` | `String` | — (обязательно для блока) | путь к Country `.mmdb`; без него весь блок — no-op |
| `asn_db_path` | `Option<String>` | `None` | путь к ASN `.mmdb`; без него совпадают только CIDR-записи репутации |
| `deny_countries` | `Vec<String>` | `[]` | alpha-2 коды для блокировки (регистронезависимо). Пустой список = режим мониторинга |
| `attack_mode_only` | `bool` | `false` | применять deny-лист только пока аномалия-детектор видит хост «под атакой» |

Пример:

```toml
[geoip]
db_path = "/var/lib/aegis/geoip/dbip-country-lite.mmdb"
asn_db_path = "/var/lib/aegis/geoip/dbip-asn-lite.mmdb"
deny_countries = ["RU", "KP"]
attack_mode_only = true   # дремлющий гео-блок, активируется только при DDoS
```

### Проверка deny (`geoip_deny`, `src/proxy/pingora_http.rs`)

```rust
fn geoip_deny(&self, ip: IpAddr, host: &str) -> Option<String> {
    let cfg = self.geoip_cfg.as_ref()?;                       // нет [geoip] → пропуск
    if cfg.attack_mode_only && !self.anomaly.under_attack(host) {
        return None;                                          // дремлет в мирное время
    }
    if cfg.deny_countries.is_empty() { return None; }         // режим мониторинга
    let country = self.geoip.country(ip)?;                     // None (приватный/нет базы) → пропуск
    if cfg.deny_countries.iter().any(|c| c.eq_ignore_ascii_case(&country)) {
        Some(format!("geo deny: {country}"))
    } else { None }
}
```

Семантика, на которую опираются операторы:

- **Пустой `deny_countries`** = «режим мониторинга»: страна попадает в метрики/карту, но трафик никогда не блокируется.
- **`attack_mode_only = true`**: deny-лист спит, пока хост не помечен `anomaly.under_attack(host)`. Полезно, когда нужен дремлющий гео-блок, не наказывающий легитимный трафик стран-меньшинств в мирное время.
- При срабатывании запроса в proxy выставляется `ctx.denied_by = Some("geoip")`, инкрементируется `observe_filter_block("geoip")`. Гео-deny — один из самых дешёвых фильтров (mmap-lookup), он короткозамыкается рано в `request_filter`.

> Привязка к домену: `geoip_deny` принимает `host`, и `attack_mode_only` оценивается **per-host** через аномалия-детектор. Сам список стран при этом глобальный (один `[geoip]` блок). Per-domain политики см. [26-sites-and-domains.md](26-sites-and-domains.md).

---

## 7. ASN-lookup для репутации

ASN-номер клиентского IP используется AS-привязанной репутацией. Связка реализована адаптером в `src/geoip.rs`:

```rust
pub struct GeoIpAsnLookup { geoip: Arc<dyn GeoIpLookup> }
impl crate::asn_reputation::AsnLookup for GeoIpAsnLookup {
    fn asn(&self, ip: IpAddr) -> Option<u32> { self.geoip.asn(ip) }
}
```

Адаптер экспонирует метод `asn()` уже загруженного GeoIP-хэндла как трейт `AsnLookup`, чтобы репутационный фид использовал **ту же** базу, что прокси уже открыл (без второго ридера). Реальная сборка — в `src/bin/aegis-pingora.rs`:

```rust
let asn_lookup: Arc<dyn AsnLookup> =
    Arc::new(GeoIpAsnLookup::new(pipeline.geoip.clone()));
// ... AsnReputation::new(paths, asn_lookup)
```

Поведение:

- Когда ASN-база загружена, AS-привязанные записи фида (`AS<n>  <score>  <tag>`) совпадают по реальному номеру AS клиента.
- Когда ASN-база **не** загружена, `asn()` возвращает `None`, и из фида срабатывают **только CIDR-записи** (`<cidr>  <score>  <tag>`). Об этом честно предупреждает лог `load_with_asn` и комментарий в `aegis-pingora.rs`.
- В data plane ASN также участвует как ML-фича `asn_reputation` (см. точки `self.geoip.asn(client_ip)` в `pingora_http.rs`); без ASN-базы фича остаётся 0.

Подробно о фидах, скоринге и self-learn JA4 — в [12-reputation.md](12-reputation.md); о ML-движке — в [18-ml-risk-engine.md](18-ml-risk-engine.md).

---

## 8. real_ip — определение реального IP клиента за прокси/CDN

За CDN или реверс-прокси TCP-peer — это ротируемая edge-нода, а не клиент. Реальный IP резолвится из forwarded-заголовков, **но только когда TCP-peer входит в доверенный набор**. Это вход для всей подсистемы: страна и ASN считаются от того IP, что вернул резолвер, а не от TCP-peer.

### Security-инвариант

Проверка `peer ∈ trusted_proxy_cidrs` **безусловна**. Если TCP-peer не доверен — forwarded-заголовки молча игнорируются. Атакующий, не сидящий за доверенным прокси, не может подменить свой IP инъекцией `X-Forwarded-For` или `CF-Connecting-IP`.

### Конфигурация (обе опции **выключены** по умолчанию)

| Переменная окружения | Эффект |
|---|---|
| `AEGIS_BEHIND_CLOUDFLARE=1` | доверять `CF-Connecting-IP`, когда TCP-peer входит во встроенный список диапазонов Cloudflare. Принимает `1`/`true`/`yes`/`on` |
| `AEGIS_TRUSTED_PROXIES=cidr,cidr,...` | дополнительно доверять этим CIDR; консультировать `X-Forwarded-For` (алгоритм «самый правый недоверенный») |

### Алгоритм резолва

Боевой путь — метод `resolve_client_ip` в `src/proxy/pingora_http.rs`:

1. `trusted_proxy_cidrs` не задан → вернуть TCP-peer без изменений (поведение по умолчанию, заголовки не читаются).
2. TCP-peer **не** в доверенном наборе → вернуть TCP-peer (security-гейт).
3. `AEGIS_BEHIND_CLOUDFLARE=1` → прочитать `CF-Connecting-IP` (единственное авторитетное значение, когда терминирующий edge — Cloudflare).
4. Иначе → `X-Forwarded-For`, обход справа налево, первый IP, **не** входящий в доверенный набор (реальный клиент прямо перед границей доверия). При любой ошибке парсинга или если все хопы доверены — fallback на TCP-peer.

Встроенный список диапазонов Cloudflare (`CF_IP_RANGES` в `pingora_http.rs`) активен **только** при `AEGIS_BEHIND_CLOUDFLARE=1` и никогда не консультируется по умолчанию. CIDR-сопоставление — stdlib-битовая арифметика без внешних crate; IPv4-в-IPv6 (`::ffff:x.x.x.x`) не авто-приводится — Pingora `SocketAddr::as_inet().ip()` уже отдаёт чистый `IpAddr::V4` для IPv4-соединений.

> Честная оговорка о двух реализациях. Модуль [`src/real_ip.rs`](../../src/real_ip.rs) содержит самостоятельную, полностью покрытую тестами реализацию (`TrustedProxies`, `IpCidr`, `resolve_client_ip`, конструкторы `from_config`/`from_env`, чтение `AEGIS_BEHIND_CLOUDFLARE`/`AEGIS_TRUSTED_PROXIES`). Однако боевой pingora-data-plane использует **не** её, а собственный встроенный `resolve_client_ip` + `CF_IP_RANGES` + `ip_in_cidr` в `pingora_http.rs` (модуль `real_ip` нигде в `src/bin/*` и в proxy не подключается — `grep` по `real_ip::`/`use crate::real_ip` в proxy пуст, при этом `real_ip` объявлен в `lib.rs`). Семантика обеих реализаций совпадает (тот же security-гейт, тот же rightmost-non-trusted обход XFF, тот же приоритет CF-Connecting-IP), различие — только в том, какой код исполняется на горячем пути. Список диапазонов Cloudflare в обоих местах идентичен и сверен в 2026.

---

## 9. Карта мира и Top Countries в панели

### Запись по странам (`observe_country`)

На входе каждого запроса proxy делает один lookup и тикает счётчик (`src/proxy/pingora_http.rs`):

```rust
if let Some(cc) = self.geoip.country(client_ip) {
    self.metrics.observe_country(&cc, false, false);
}
```

Поскольку дефолт — `NoopGeoIp` (его `country()` возвращает `None` без работы), это **почти бесплатно**, когда база не настроена; при загруженной базе — один mmap-lookup. Страна также пишется в строку журнала запросов (`EventRow.country`), когда event-store включён (см. [24-request-log.md](24-request-log.md)).

### Cross-worker агрегация (`src/metrics/geo_shard.rs`)

Под `SO_REUSEPORT` каждый воркер ведёт собственную `by_country`-карту и видит лишь свою долю трафика. Чтобы карта мира была стабильной независимо от того, какой воркер ответил админ-запросу, применяется шард+merge-on-read (тот же паттерн, что у site_map — см. [26-sites-and-domains.md](26-sites-and-domains.md) и [06-workers.md](06-workers.md)):

- Каждый воркер берёт слот неблокирующим advisory `flock` на `.slot-<n>.lock` (до `MAX_SLOTS = 16`) и периодически пишет снапшот в `shard-<slot>.json`.
- Строка `CountryRow`: `country`, `total`, `denied`, `challenged`.
- Чтение (`top_countries`) сливает **все** шарды, суммируя счётчики по коду страны; шарды старше `SHARD_MAX_AGE_SECS = 900` считаются осиротевшими и пропускаются (по `written_at_unix_secs` и по mtime файла).
- При рестарте воркер перечитывает свой шард — счётчики переживают перезапуск.
- Каталог по умолчанию: `/var/lib/aegis/geo` (переопределяется `AEGIS_GEO_DIR`).
- Запись — атомарно (tmp-сосед + rename), права `0o640`.

### Admin API

| Метод + маршрут | Хэндлер | Назначение |
|---|---|---|
| `GET /admin/api/geo/top` | `api_geo_top` | топ-20 стран `[{country, total, denied}]` для карты мира и виджета Top Countries; пусто, если база не настроена (карта рендерится корректно пустой) |
| `GET /admin/api/geoip/status` | `api_geoip_status` | резолвнутый путь country-базы, `AEGIS_ASN_PATH`, `loaded`, `database_type` + `build_epoch` (из метаданных `.mmdb`), `bundled`, атрибуция db-ip |
| `POST /admin/api/geoip/update` | `api_geoip_update` | обновить country-базу до db-ip Lite текущего месяца |
| `POST /admin/api/geoip/lookup` | `api_geoip_lookup` | **планируется**: возвращает `501` (хэндл GeoIP пока не проброшен в `AdminProxy`) |

Полный список admin-маршрутов и аутентификация — в [30-admin-api.md](30-admin-api.md).

### Обновление country-базы из панели (`api_geoip_update`)

AEGIS не тянет HTTP/gzip-зависимость в Rust, поэтому Update шеллит в `curl | gunzip`, атомарно подменяет mmdb под `/var/lib/aegis/geoip` и **только при успехе** пишет restart-маркер, чтобы path-watcher перечитал свежую базу:

```sh
url="https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz"
tmp=/var/lib/aegis/geoip/.dbip.new
curl -sfL --max-time 180 "$url" | gunzip > "$tmp"
[ -s "$tmp" ]
mv -f "$tmp" /var/lib/aegis/geoip/dbip-country-lite.mmdb
date +%s > /var/lib/aegis/geoip/.last-update
date +%s > <…/.restart-request>   # restart-маркер
```

Запускается detached (скачивание может занять секунды); панель перепрашивает `status` (дата сборки меняется после рестарта). Сервис перезапускается сам — ручной `systemctl` не нужен. О механике рестарта см. [03-installation.md](03-installation.md).

---

## 10. Эксплуатационная шпаргалка

```bash
# Проверить, какую базу резолвит демон + её дату сборки
curl -s -H "x-admin-token: $TOKEN" http://127.0.0.1:PORT/admin/api/geoip/status | jq

# Топ стран (для карты мира)
curl -s -H "x-admin-token: $TOKEN" http://127.0.0.1:PORT/admin/api/geo/top | jq

# Обновить country-базу до текущего месяца (рестарт автоматический)
curl -s -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:PORT/admin/api/geoip/update

# Ручной refresh ASN-базы + репутационных фидов (тот же скрипт, что и таймер)
sudo /usr/local/bin/aegis-refresh-feeds

# Явно указать пути через env (перебивают bundled, перебиваются [geoip] в конфиге)
export AEGIS_GEOIP_PATH=/var/lib/aegis/geoip/dbip-country-lite.mmdb
export AEGIS_ASN_PATH=/var/lib/aegis/geoip/dbip-asn-lite.mmdb

# Включить доверие к Cloudflare / своим прокси (иначе forwarded-заголовки игнорируются)
export AEGIS_BEHIND_CLOUDFLARE=1
export AEGIS_TRUSTED_PROXIES=10.0.0.0/8,192.0.2.0/24
```

### Типичные ситуации

| Симптом | Причина | Что проверить |
|---|---|---|
| Карта мира пустая | country-база не загружена | `geoip/status` → `loaded`; наличие `/var/lib/aegis/geoip/dbip-country-lite.mmdb`; нажать Update |
| Гео-deny не срабатывает | пустой `deny_countries`, либо `attack_mode_only` и хост не «под атакой», либо страна не резолвится | `[geoip]` блок; статус аномалии хоста; приватный/неаллоцированный IP |
| Репутация ловит только CIDR, не AS | ASN-база не загружена | `geoip/status` → `asn_db_path`; запустить `aegis-refresh-feeds`; лог `…only match CIDR entries` |
| Страна/ASN считаются от edge-IP, а не клиента | real_ip выключен | `AEGIS_BEHIND_CLOUDFLARE` / `AEGIS_TRUSTED_PROXIES` заданы; TCP-peer реально в доверенном наборе |
| Счётчики стран «прыгают» между опросами | (исторически) per-worker карты | сейчас агрегируется через geo-shard merge; проверить writable `/var/lib/aegis/geo` (или `AEGIS_GEO_DIR`) |

---

## См. также

- [12-reputation.md](12-reputation.md) — AS/CIDR-фиды, скоринг, Tor/Spamhaus, CrowdSec.
- [18-ml-risk-engine.md](18-ml-risk-engine.md) — ML-фича `asn_reputation`.
- [24-request-log.md](24-request-log.md) — поле `country` в `EventRow`.
- [25-metrics-telemetry.md](25-metrics-telemetry.md) — `observe_country`, `observe_filter_block`.
- [26-sites-and-domains.md](26-sites-and-domains.md) — паттерн шард+merge, per-domain политики.
- [06-workers.md](06-workers.md) — SO_REUSEPORT, cross-worker состояние.
- [30-admin-api.md](30-admin-api.md) — маршруты `/admin/api/geo*` и аутентификация.
- [04-configuration.md](04-configuration.md) — блок `[geoip]` в общем контексте.
