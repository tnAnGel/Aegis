# FAQ и устранение неполадок

Практический справочник по типовым отказам AEGIS и их устранению. Каждый раздел привязан к реальному коду (`install.sh`, `src/xdp.rs`, `src/proxy/pingora_tls.rs`, `src/bin/aegis-pingora.rs`, `src/web_admin.rs`, `src/main.rs`) — без догадок; частичные и opt-in поведения помечены явно.

> Полезные соседние документы: [03-installation.md](03-installation.md), [06-workers.md](06-workers.md), [07-protocols.md](07-protocols.md), [08-tls-certificates.md](08-tls-certificates.md), [11-tls-fingerprinting.md](11-tls-fingerprinting.md), [13-xdp-ebpf.md](13-xdp-ebpf.md), [24-request-log.md](24-request-log.md), [25-metrics-telemetry.md](25-metrics-telemetry.md), [29-admin-panel.md](29-admin-panel.md), [30-admin-api.md](30-admin-api.md).

---

## 0. Быстрая диагностика: с чего начать

Прежде чем углубляться в конкретный симптом, соберите базовое состояние. Эти три команды покрывают 90% инцидентов:

```bash
# 1. Живы ли воркеры data plane (pingora-режим)?
systemctl status aegis-pingora.target
systemctl list-units 'aegis-pingora@*.service' --no-legend

# 2. Последние логи всех воркеров (journald — единственный лог-сток сервиса)
journalctl -u aegis-pingora.target -n 80 --no-pager

# 3. Кто держит привилегированные порты?
ss -tlnp | grep -E ':80|:443|:6280'
ss -ulnp | grep ':443'      # HTTP/3 — это UDP
```

В hyper-режиме (`--mode hyper`) сервис называется `aegis` (не `aegis-pingora.target`), а XDP/HTTP-3 отсутствуют — см. [06-workers.md](06-workers.md).

Карта рабочих путей (значения по умолчанию из `install.sh`):

| Назначение | Путь | Переменная установщика |
|---|---|---|
| Конфиг | `/etc/aegis/aegis.conf` | `AEGIS_ETC` |
| Env сервиса | `/etc/aegis/aegis.env` | — |
| Env фич-флагов (панель) | `/var/lib/aegis/aegis-ui.env` | `AEGIS_HOME` |
| Admin-токен | `/etc/aegis/admin-token` | — |
| Состояние веб-админа | `/var/lib/aegis/web.json` | `web_state_path` |
| eBPF-объект | `/var/lib/aegis/aegis-xdp.o` | `AEGIS_XDP_OBJ` |
| GeoIP / репутация | `/var/lib/aegis/geoip`, `/var/lib/aegis/reputation` | — |
| Журнал аудита | `/var/log/aegis/audit.log` | `AEGIS_LOG_DIR` |

---

## 1. XDP не загружается (capabilities / ядро)

XDP — это kernel fast-path, доступный **только** в pingora-режиме и **только** в Linux при сборке с фичей `xdp` (`src/xdp.rs:131-143`). На любой другой платформе или при отсутствии фичи `load()` возвращает `NoopXdp` и пишет:

```
XDP fast-path not available on this build (need target_os=linux + `xdp` feature)
```

### 1.1. Когда установщик вообще не включает XDP

`resolve_xdp_enable()` (`install.sh:131-154`) отключает XDP автоматически в двух случаях:

- `--mode hyper` → `AEGIS_ENABLE_XDP=0` («data plane is hyper-only»);
- ядро младше **4.18** → отключается с предупреждением `linux <ver> < 4.18 — XDP disabled (need ≥ 4.18 for aya)`.

Проверка ядра:

```bash
uname -r          # нужно >= 4.18
```

Принудительное включение/выключение: флаги `--xdp` / `--no-xdp` или переменная `AEGIS_ENABLE_XDP=1|0|auto`.

### 1.2. Сборочные зависимости eBPF отсутствуют

При `AEGIS_ENABLE_XDP=1` установщик (`install.sh:296-318`) ставит **rust nightly + rust-src** и `bpf-linker`. Симптомы и причины:

| Симптом в логе сборки | Причина | Решение |
|---|---|---|
| `bpf-linker install failed — eBPF build will fail; retry with --no-xdp` | не собрался `bpf-linker` | поставить вручную `cargo install bpf-linker --locked` или ставить с `--no-xdp` |
| `eBPF build did not produce …/aegis-xdp` | сборка `xdp/aegis-xdp-ebpf` упала | проверить nightly + `rust-src`, clang/llvm |
| падение release-сборки с `is `cmake` not installed?` | нет cmake (транзитивная зависимость) | `install_packages()` ставит cmake; на «unknown» pkg-mgr поставьте вручную |

eBPF-объект собирается отдельным воркспейсом `xdp/aegis-xdp-ebpf` под таргетом `bpfel-unknown-none` (`install.sh:469-484`).

### 1.3. Прав не хватает (capabilities)

Главная причина «XDP не грузится в рантайме». Привилегии раздаются в двух местах:

1. **File-capability на бинаре** (`install.sh:463-465`):
   ```
   setcap 'cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep' /usr/local/bin/aegis-pingora
   ```
   Если `setcap` упал, в логе: `setcap failed; pingora workers will need to run as root for :80/:443`.

2. **Capabilities в systemd-юните** (`write_systemd_unit_pingora`, `install.sh:1223-1232`). При включённом XDP набор расширяется:
   ```
   AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON
   CapabilityBoundingSet=<то же>
   RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
   ```

> **Важный нюанс ядра 6.x.** Без `CAP_PERFMON` (даже при наличии `CAP_BPF`) верификатор отклоняет `BPF_PROG_LOAD` с **EACCES (os error 13)**, потому что операции с указателями/`packet-data` спрятаны за `perfmon_capable()` (комментарий в `install.sh:1224-1228`). Если в логе `EACCES`/`os error 13` при загрузке программы — проверьте, что юнит содержит `CAP_PERFMON`, а `AF_NETLINK` присутствует в `RestrictAddressFamilies` (attach идёт через rtnetlink).

`LimitMEMLOCK=infinity` в юните (`install.sh:1266`) нужен, чтобы BPF-карты и locked-ring-буферы выросли за дефолтные 64 KiB rlimit. Без него карты могут не аллоцироваться.

После правки юнита:

```bash
systemctl daemon-reload && systemctl restart aegis-pingora.target
```

### 1.4. «xdp-already-owned-by-sibling-worker» — это НЕ ошибка

NIC может нести **ровно одну** XDP-программу. При `N` воркерах SO_REUSEPORT только один выигрывает attach, остальные получают `EEXIST` (`os error 17`, «File exists»). Код распознаёт это (`src/xdp.rs:163-178, 231-245`) и возвращает сентинел `XDP_ALREADY_OWNED_MARKER` (`src/xdp.rs:17`), который вызывающая сторона логирует как **информационное** условие: воркер-владелец энфорсит deny/allow-карты на NIC для всего трафика, остальные фильтруют в userspace. Сообщение вида `xdp-already-owned-by-sibling-worker` в логе сиблингов — норма, не сбой.

### 1.5. Native (DRV) против SKB (generic) режима

Loader сначала пытается native-attach, при неудаче падает в SKB-режим (`src/xdp.rs:218-252`):

```
XDP native attach failed, retrying in SKB (generic) mode
XDP attached in SKB mode
```

SKB-режим медленнее (пакеты переинъектируются после аллокации `sk_buff`), но работает на любом NIC, включая `virtio-net` под гипервизором. Это ожидаемо на облачных VM без нативной XDP-поддержки. Если же привязка не удалась **в обоих** режимах:

```
failed to attach XDP program to <iface> (tried both DRV and SKB modes): <err>
```

— проверьте имя интерфейса (`AEGIS_XDP_IFACE`, авто-детект «первый non-lo UP», `install.sh:193-209`).

### 1.6. Проверка, что XDP реально работает

Счётчики XDP суммируются по PerCpu-картам (`src/xdp.rs:373-392`): `pass`, `drop_deny`, `drop_rate`, `drop_allowonly`, `drop_syn`, `drop_waf`, `fast_pass`. Они доступны через `/metrics` и панель (см. [13-xdp-ebpf.md](13-xdp-ebpf.md), [25-metrics-telemetry.md](25-metrics-telemetry.md)). Растущий `pass`/`drop_*` на воркере-владельце подтверждает работу.

---

## 2. HTTP/3 (QUIC) не биндится

HTTP/3 в AEGIS — это hyper-based `ProxyHttpHandler` на отдельном tokio-runtime в отдельном потоке (`maybe_spawn_h3`, `src/bin/aegis-pingora.rs:1585-1612, 2304+`), потому что pingora сегодня несёт только h1/h2. Слушатель берётся из `tls.h3_listen` (по умолчанию совпадает с `tls.listen`).

### 2.1. «HTTP/3 not started by this worker» — обычно норма

Сообщение (на уровне **info**, не warn):

```
aegis-pingora: HTTP/3 not started by this worker
  (served by a sibling worker under REUSEPORT, or h3 disabled/misconfigured)
```

Причина (`src/bin/aegis-pingora.rs:1600-1611`): QUIC-сокет quinn **не имеет SO_REUSEPORT**, поэтому при многоворкерной раскладке только **первый** воркер, успевший привязать `:443/udp`, обслуживает HTTP/3; сиблинги получают `AddrInUse` и приземляются сюда. Это ожидаемо и безвредно — h1/h2 поверх TCP не затронуты. Включается h3 только когда `tls.enabled && tls.h3_enabled` (`src/bin/aegis-pingora.rs:2316`).

### 2.2. Когда это реальная проблема

Если HTTP/3 **не работает ни на одном** воркере, ищите в info-логе обёрнутую причину после `error = ...`:

- `invalid h3_listen <str>` — неразбираемый адрес (`src/bin/aegis-pingora.rs:2319-2322`);
- ошибка сертификата — h3 требует валидную TLS-конфигурацию;
- порт `:443/udp` закрыт фаерволом.

Установщик открывает UDP отдельно (`install.sh:1364`, `ufw allow 443/udp comment 'aegis h3 quic'`; firewalld — `--add-port=443/udp`). Проверка:

```bash
ss -ulnp | grep ':443'                 # должен слушать ровно один воркер
journalctl -u aegis-pingora.target | grep -i h3
```

В директиве `listen` сайта h3 включается токеном `http3` (см. дефолтный `server { listen 443 ssl http2 http3 default_server; }`, `install.sh:1097`). Подробности — [07-protocols.md](07-protocols.md).

---

## 3. Ложные срабатывания WAF

WAF включён по умолчанию (`defaults { filters { waf on; } }`, `install.sh:1075`). Движок — Aho-Corasick по сигнатурам + Sigma-корпус + compound-правила + webshell-детектор (см. [10-waf.md](10-waf.md)). Типовая отладка ложного позитива:

1. **Определите правило.** В журнале запросов ([24-request-log.md](24-request-log.md)) и в `audit_log_path` (`/var/log/aegis/audit.log`) для заблокированного запроса виден сработавший сигнатурный/Sigma-идентификатор.
2. **Сузьте область.** Per-domain policy и site_map позволяют ослабить WAF для конкретного хоста/пути ([26-sites-and-domains.md](26-sites-and-domains.md)), не трогая остальные сайты.
3. **Временная глобальная мера.** Отключение фильтра через фич-флаги панели (`PUT /admin/api/env`, пишет в `/var/lib/aegis/aegis-ui.env`) или правкой `defaults { filters { waf off; } }`. Это последнее средство — выключает защиту целиком.

> **Где живут переопределения фич-флагов.** Панель пишет тогглы в **отдельный** writable-файл `$AEGIS_HOME/aegis-ui.env`, который через systemd drop-in (`install.sh:544-575`) подключается **после** read-only `/etc/aegis/aegis.env`, поэтому значения панели перекрывают дефолты оператора. Это сделано осознанно: `ProtectSystem=strict` + `ReadOnlyPaths=$AEGIS_ETC` означает, что скомпрометированный демон **не может** переписать собственный конфиг/сертификаты/токен. Изменения применяются рестартом: `systemctl restart aegis-pingora.target`.

Соседние фильтры, тоже способные блокировать легитимный трафик и проверяемые тем же образом: `bot_fingerprint`, `adaptive_spike_detection` (`install.sh:1076-1077`), rate-limit ([14-rate-limiting.md](14-rate-limiting.md)), ML risk engine ([18-ml-risk-engine.md](18-ml-risk-engine.md), у него есть режим `Observe` для калибровки без блокировок), репутация ([12-reputation.md](12-reputation.md)).

---

## 4. Белый экран после входа в панель (`email.split`)

**Симптом:** сразу после успешного логина админ-панель показывает белый экран / падает верхний бар.

**Причина (RC4, `src/proxy/pingora_admin.rs:4386-4393`):** ответ на логин раньше **не содержал поле `email`**, поэтому auth-состояние SPA получало `email=undefined`, и верхний бар крашился на `email.split(...)`. Исправлено: `POST /admin/api/login` теперь возвращает только что аутентифицированный email обратно в теле:

```json
{
  "ok": true, "token": "...", "email": "<введённый email>",
  "must_change_credentials": <bool>, "must_change": <bool>,
  "set_cookie": "aegis_admin_session=...; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400"
}
```

**Если симптом всё ещё наблюдается:**

- Вы на устаревшем бинаре/фронте. Обновитесь: `sudo bash install.sh --update` (пересобирает фронт `web/dist`, встраиваемый в бинарь, `install.sh:382-396`), затем жёсткий рефреш браузера (Ctrl-Shift-R), чтобы сбросить кэш SPA.
- Проверьте, что `GET /admin/api/me` отдаёт `email` (`src/proxy/pingora_admin.rs:4434-4494`). Для токен-аутентификации `me` возвращает синтетический `email: "token-<Role>"` — это норма.

Связанный нюанс: поля `must_change_credentials` **и** `must_change` дублируются намеренно (`src/proxy/pingora_admin.rs:4389-4395`), потому что клиент читает `must_change` для запуска принудительной смены кредов.

---

## 5. Принудительная смена кредов при первом входе

**Это by-design, а не баг.** При первом запуске установщик вызывает `aegis web reset-admin` (`seed_web_admin`, `install.sh:1133-1162`), создавая аккаунт со случайным паролем и **`must_change = true`** (`src/web_admin.rs:82, 127, 277-282`). На первом логине панель **заставляет сменить и email, и пароль**, прежде чем что-либо ещё (`src/main.rs:119-120`):

```
Log in once with these credentials — the panel will force you to
change both email and password before anything else.
```

Смена кредов (`change_credentials`, `src/web_admin.rs:234-262`) сбрасывает `must_change = false` и **инвалидирует все остальные сессии**. После этого повторный запуск установщика **не** перегенерирует пароль: `seed_web_admin` пропускает шаг, если в `web.json` есть `"must_change":false` (`install.sh:1139-1143`), печатая `web admin already initialised — preserving operator's credentials`.

Если форс-смена не может завершиться (например, белый экран из раздела 4) — сначала обновитесь и сбросьте креды (раздел 9), затем войдите заново.

---

## 6. Медленная сборка

Сборка идёт **на хосте развёртывания** (`install.sh:406-419`), поэтому она оптимизируется под этот CPU. Рычаги:

| Что | Где | Эффект |
|---|---|---|
| Профиль по умолчанию | `Cargo.toml` | thin-LTO, `codegen-units=16`, incremental — **быстрая** параллельная сборка (`install.sh:507-509`) |
| `AEGIS_BUILD_OPT=max` | env | fat-LTO + `codegen-units=1` + non-incremental — самый быстрый бинарь, но **медленная**, почти однопоточная сборка (`install.sh:502-506`); только для релиза, не для рутинного `--update` |
| `mold` линкер | авто, best-effort | многопоточная линковка финального большого бинаря (`install.sh:270-277, 420-435`); в логе `mold linker available — parallel linking enabled` |
| `AEGIS_TARGET_CPU` | env | `native` (по умолчанию, оптимально для этой машины) / `generic` (портируемо) / конкретный микроарх (`install.sh:419-435`) |

Ориентиры из комментариев: `aegis` (hyper+CLI) ~3-5 мин первой сборки (`install.sh:438`), `aegis-pingora` ~5-8 мин (`install.sh:448`). XDP добавляет nightly-toolchain + `bpf-linker` (первый раз ~1-2 мин на линкер). Если сборка неожиданно долгая — убедитесь, что не выставлен случайно `AEGIS_BUILD_OPT=max` и что `mold` установился.

Рекомендация: для рутинного `--update` оставляйте профиль по умолчанию; `AEGIS_BUILD_OPT=max` — только когда режете настоящий релиз.

---

## 7. nginx (или другой прокси) занял :80

**Симптом:** сервис не стартует / `AddrInUse` на `:80`, `:443` или `:6280`.

Установщик предупреждает об этом до старта (`detect_port_conflict`, `install.sh:1376-1389`):

```
port 80 is already bound by <owner> — aegis will fail to start. Stop it first:
  systemctl stop nginx 2>/dev/null; systemctl stop apache2 2>/dev/null
```

Найти и освободить порт:

```bash
ss -tlnp | grep -E ':80|:443|:6280'
systemctl stop nginx;  systemctl disable nginx
systemctl stop apache2; systemctl disable apache2
systemctl restart aegis-pingora.target
```

> **Тонкость с бенчмарк-прокси.** Установщик намеренно ставит nginx/HAProxy/Caddy/Envoy/ModSecurity для сравнительного бенча «vs nginx», но сразу их **disable+stop (Caddy — даже mask)**, чтобы они не держали `:80/:443` — AEGIS владеет этими портами (`ensure_nginx_for_benchmark` и соседи, `install.sh:582-761`). Бенч запускает их бинарь ad-hoc на loopback-порту с временным конфигом. Если после установки что-то снова заняло `:80` — проверьте, не включил ли кто-то эти юниты обратно (`systemctl is-enabled nginx caddy haproxy`).

Сменить порты AEGIS можно через переменные установщика `AEGIS_PORT_HTTP` / `AEGIS_PORT_HTTPS` / `AEGIS_PORT_ADMIN` (`install.sh:47-49`) либо правкой `listen` в конфиге. См. [03-installation.md](03-installation.md).

---

## 8. JA4/JA3 пустой (gate фингерпринтинга / захват в ClientHello)

### 8.1. Захват обязан идти из ClientHello-callback

JA3/JA4 вычисляются в `capture_client_hello` (`src/proxy/pingora_tls.rs:736-855`), который **обязан** вызываться из OpenSSL **ClientHello-callback** (регистрируется в `aegis-pingora.rs` через `set_client_hello_callback`). Это **единственная** стадия handshake, где аксессоры `SSL_client_hello_*` возвращают предложенные клиентом шифры и расширения.

> **Исторический симптом (V246):** если фингерпринт считался в `certificate_callback` (поздний cert_cb OpenSSL), аксессоры возвращали пусто, и для **каждого** клиента получался вырожденный одинаковый JA4 `t12i000000_e3b0c44298fc` (`src/proxy/pingora_tls.rs:740-742`). Если вы видите этот вырожденный отпечаток у всех клиентов — у вас сборка до фикса; обновитесь (`--update`).

Готовый отпечаток складывается в SSL `ex_data`; `handshake_complete_callback` публикует его в session digest, а `read_fingerprints` читает обратно в `ctx.ja3` / `ctx.ja4` (`src/proxy/pingora_tls.rs:742-744`).

### 8.2. Gate фингерпринтинга (LEVER 1) — главная причина пустого JA4

Чтобы не тратить MD5 + 2×SHA-256 + ~18-22 heap-аллокации на handshake, когда отпечатки **никто не потребляет**, есть гейт `fingerprinting_enabled` (`src/proxy/pingora_tls.rs:138-155, 753-770`). Когда он `false`, `capture_client_hello` кладёт `TlsFingerprints` со **всеми полями `None`** (JA3/JA4 будут пустыми) и выходит. По умолчанию гейт **ON** (`src/proxy/pingora_tls.rs:414-417`).

Гейт автоматически остаётся включённым, если есть хоть один потребитель (`src/proxy/pingora_tls.rs:142-152`):

- настроены `ja3_deny_hashes` / `ja4_deny_prefixes`;
- включён Defence Arsenal (`ja4_corpus`, `ja4_churn`, GREASE-scoring);
- активен фид `ja4_reputation`;
- есть WAF-правила с `field:"ja3"`/`field:"ja4"` (inline-правила сканируются на старте; внешние `rule_files` **форсируют** гейт ON, см. `src/proxy/pingora_tls.rs:147-152`).

**Если JA4 пустой:**

1. Проверьте, не выключил ли оператор фингерпринтинг явно через `AEGIS_TLS_FINGERPRINT=0` (`src/proxy/pingora_tls.rs:152`). Но учтите: бинарь **переопределяет** явный `AEGIS_TLS_FINGERPRINT=0` с предупреждением, если детектирует потребителя (`src/bin/aegis-pingora.rs:1864-1889`):
   ```
   aegis-pingora: AEGIS_TLS_FINGERPRINT=0 OVERRIDDEN — a consumer was detected …
   ```
   Если потребителя нет, а гейт нужен принудительно — уберите `AEGIS_TLS_FINGERPRINT=0` и перезапустите.
2. Проверьте текущее состояние флага через панель/`/admin/api/env` (`tls_fingerprinting`, `src/proxy/pingora_admin.rs:122, 2849`).
3. JA4 не появится для клиентов без TLS (обычный HTTP) — фингерпринт остаётся `None` для no-cert/no-TLS клиентов.

> **JA4T (TCP/SYN) отдельно.** JA4T-захват SYN живёт в XDP-карте (`read_ja4t_v4`, `src/xdp.rs:52-64, 394-411`) и работает только для **IPv4** при включённом XDP; отсутствие записи (XDP off, IPv6, eviction) трактуется как «нет захвата → fallback на TCP_INFO» и **не** является ошибкой. Подробности — [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

---

## 9. Как сбросить креды веб-админа (`aegis web reset-admin`)

CLI живёт в `aegis` (hyper-бинарь), который ставится даже в pingora-режиме именно ради этих утилит (`install.sh:516-521`). Команда (`src/main.rs:112-121`, `src/web_admin.rs:277-282`):

```bash
aegis -c /etc/aegis/aegis.conf web reset-admin
```

Вывод:

```
✓ web admin reset
  email:    <DEFAULT_EMAIL>
  password: <случайный>
  state:    /var/lib/aegis/web.json
```

`reset_admin()` записывает в state-файл свежий пароль и ставит `must_change = true`, так что следующий вход снова потребует смены email+пароля. **Рестарт не нужен:** демон подхватывает изменение `web.json` по mtime-poll (комментарий `install.sh:1135-1136`). Путь state-файла берётся из `admin { web_state_path … }` (`install.sh:1066`), иначе `web_admin::DEFAULT_STATE_PATH` (`src/main.rs:101-108`).

Смежные CLI-команды веб-панели (`src/main.rs:122-139`):

| Команда | Действие | Эффект |
|---|---|---|
| `aegis web reset-admin` | сброс кредов | новый пароль, `must_change=true` |
| `aegis web stop` | остановить панель | `/admin/ui` и `/admin/api/*` начинают отдавать **503** |
| `aegis web start` | включить панель | снимает блокировку |
| `aegis web status` | показать состояние | `enabled`, `email`, `must_change`, число сессий, путь state |

> Если креды забыты, а панель отдаёт «invalid credentials» (`src/proxy/pingora_admin.rs:4400`) — это штатный путь восстановления: `reset-admin` + вход с новым паролем.

Альтернатива логину — прямой доступ к admin API по токену из `/etc/aegis/admin-token` с заголовком `x-admin-token: <token>` (`install.sh:1474-1476`, [30-admin-api.md](30-admin-api.md)).

---

## 10. Где логи (journald / event-store)

AEGIS не пишет собственный текстовый лог-файл сервиса — всё идёт в **journald**.

```bash
# pingora-режим (вся раскладка воркеров)
journalctl -u aegis-pingora.target -f
# конкретный воркер
journalctl -u aegis-pingora@0 -n 50
# hyper-режим
journalctl -u aegis -f
# панель-рестартер и фид-рефрешер
journalctl -u aegis-restart.service -n 30
journalctl -u aegis-refresh-feeds.service -n 30
```

Уровень логирования задаётся в `/etc/aegis/aegis.env` через `RUST_LOG` (по умолчанию `info,aegis=info,aegis_pingora=info`, `install.sh:1334`) и/или флагом `--log-level info` в ExecStart (`install.sh:1254`). После правки:

```bash
systemctl daemon-reload && systemctl restart aegis-pingora.target
```

Помимо journald есть отдельные потоки данных (см. [24-request-log.md](24-request-log.md), [25-metrics-telemetry.md](25-metrics-telemetry.md)):

- **event-store** — персистентный SQLite per-worker (шарды по воркерам), история запросов/событий, per-domain/endpoint; виден через панель и admin API;
- **audit_log** — `/var/log/aegis/audit.log` (`install.sh:1055`), действия admin API;
- **метрики** — timeseries-ринги + Prometheus `/metrics`;
- **EventBridge** — NDJSON-поток для SIEM.

> В pingora-режиме event-store шардирован **по воркерам** — для агрегированной картины смотрите панель или сводные admin-API маршруты, а не один shard-файл.

---

## 11. Сброс состояния

AEGIS хранит состояние на диске и синхронизирует воркеры через файлы + mtime-poll (cross-worker). Сброс отдельных подсистем:

| Что сбросить | Действие | Подхват |
|---|---|---|
| Креды/сессии веб-админа | `aegis web reset-admin` (раздел 9) | mtime-poll, без рестарта |
| Honeypot-паки | удалить/переписать `/var/lib/aegis/honeypots.json` (дефолт `{"enabled":true,"packs":{},"per_host":{}}`, `install.sh:1125-1130`) | mtime-poll |
| Воркеры/раскладка | `topology.json` пишет панель (`PUT /admin/api/topology`); установщик читает при `--workers auto` (`install.sh:169-179`) | при следующем install/рестарте |
| Фич-флаги панели | очистить переопределения в `/var/lib/aegis/aegis-ui.env` | рестарт target |
| Репутационные фиды | перезапустить `aegis-refresh-feeds` (Tor/Spamhaus/ASN-DB/CrowdSec) | mtime hot-reload |
| GeoIP | заменить `/var/lib/aegis/geoip/*.mmdb` (или кнопка Update в панели) | mtime hot-reload |

```bash
# принудительный рефреш репутационных фидов
/usr/local/bin/aegis-refresh-feeds
# полный рестарт data plane (применить любые изменения)
systemctl restart aegis-pingora.target
```

### 11.1. Полный сброс (uninstall / purge)

`install.sh` (`uninstall()`, `install.sh:1511-1538`):

```bash
# Снести бинари/юниты/исходники, СОХРАНИВ /etc/aegis и /var/lib/aegis
sudo bash install.sh --uninstall

# Полная зачистка: ещё и /etc/aegis, /var/lib/aegis, /var/log/aegis + удалить пользователя aegis
sudo bash install.sh --purge
```

- `--uninstall`: останавливает+отключает `aegis` / `aegis-pingora.target` / `aegis-pingora@0..16`, удаляет юниты и `$AEGIS_SRC`, но **оставляет конфиг** (`uninstalled — config preserved at /etc/aegis (use --purge to remove)`).
- `--purge`: дополнительно `rm -rf /etc/aegis /var/lib/aegis /var/log/aegis` и `userdel aegis` → `fully purged`. Это и есть «сброс к заводским».

> После `--purge` следующая установка перегенерирует admin-токен, hmac-secret, самоподписанный сертификат и креды веб-админа заново.

---

## 12. Сводная таблица «симптом → раздел»

| Симптом | Раздел |
|---|---|
| `XDP fast-path not available on this build` | [1](#1-xdp-не-загружается-capabilities--ядро) |
| `EACCES` / `os error 13` при загрузке BPF | [1.3](#13-прав-не-хватает-capabilities) |
| `xdp-already-owned-by-sibling-worker` | [1.4](#14-xdp-already-owned-by-sibling-worker--это-не-ошибка) |
| `XDP attached in SKB mode` | [1.5](#15-native-drv-против-skb-generic-режима) |
| `HTTP/3 not started by this worker` | [2.1](#21-http3-not-started-by-this-worker--обычно-норма) |
| `invalid h3_listen` | [2.2](#22-когда-это-реальная-проблема) |
| Легитимный запрос блокируется | [3](#3-ложные-срабатывания-waf) |
| Белый экран / краш топ-бара после логина | [4](#4-белый-экран-после-входа-в-панель-emailsplit) |
| Панель требует сменить email+пароль | [5](#5-принудительная-смена-кредов-при-первом-входе) |
| Сборка идёт слишком долго | [6](#6-медленная-сборка) |
| `port 80 is already bound by …` / `AddrInUse` | [7](#7-nginx-или-другой-прокси-занял-80) |
| JA4/JA3 пустой или `t12i000000_e3b0c44298fc` | [8](#8-ja4ja3-пустой-gate-фингерпринтинга--захват-в-clienthello) |
| Забыт пароль админа | [9](#9-как-сбросить-креды-веб-админа-aegis-web-reset-admin) |
| Где смотреть логи | [10](#10-где-логи-journald--event-store) |
| Откатить состояние / переустановить | [11](#11-сброс-состояния) |

---

См. также: 42-текущее-состояние-STATUS.md, [44-updates-migration.md](44-updates-migration.md), [46-glossary.md](46-glossary.md).
