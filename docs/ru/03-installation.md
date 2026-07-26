# Установка и эксплуатация

Руководство по развёртыванию AEGIS на боевом сервере: одностроковый
установщик [`install.sh`](../../install.sh), режимы сборки, раскладка systemd
(template-юнит + target + воркеры `aegis-pingora@N`), rolling restart,
обновление, удаление и каталоги состояния. Каждое утверждение здесь сверено
с реальным кодом установщика и бинаря [`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs);
там, где функция частична или опциональна, это оговорено явно.

> Авторитетный источник по сборке и деплою — сам [`install.sh`](../../install.sh).
> Этот документ не дублирует скрипт пошагово, а объясняет, что он делает и как
> этим управлять. Если документ и код разойдутся — прав код.

---

## 1. Быстрый старт — одностроковый установщик

```bash
curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash
```

или, после скачивания репозитория:

```bash
sudo bash install.sh
```

Скрипт **идемпотентен**: повторный запуск обновляет код до тек��щего tip ветки,
не трогает существующий `/etc/aegis`, и сохраняет пароль веб-панели между
прогонами (новый генерируется только при первой установке или после `--purge`,
см. [`install.sh`](../../install.sh):27-30).

Что делает установщик по шагам (функция `main`, [`install.sh`](../../install.sh):1543-1572):

1. `require_root` — требует root (`sudo bash install.sh`).
2. `detect_os` — определяет дистрибутив и архитектуру.
3. `resolve_xdp_enable` / `resolve_workers` / `resolve_xdp_iface` — вычисляет
   план развёртывания.
4. `install_packages` → `install_node` → `install_rust` — ставит build-зависимости,
   Node.js + pnpm (для сборки веб-панели) и Rust-toolchain.
5. `create_user` — создаёт системного пользователя `aegis`.
6. `build_and_install` — синхронизирует исходники, собирает фронтенд и бинари.
7. `generate_self_signed_cert` → `create_default_config` → `write_systemd_unit`
   → `ensure_ui_env_dropin` — генерирует bootstrap-сертификат, конфиг, юниты.
8. `setup_firewall` → `enable_and_start` — открывает порты и стартует сервис.
9. `seed_web_admin` → `print_summary` — генерирует учётку панели и печатает сводку.

После установки админ-панель доступна на `http://<ip>:6280/admin/ui`
(React SPA встроена в бинарь, Node.js в runtime **не нужен**). Первичные
логин/пароль печатаются в конце вывода установщика; панель форсирует их смену
при первом входе.

Подробнее о панели — Админ-панель, о API —
Admin API.

---

## 2. Поддерживаемые ОС и пакетные менеджеры

`detect_os` ([`install.sh`](../../install.sh):105-129) сопоставляет `ID` из
`/etc/os-release` с пакетным менеджером:

| Дистрибутив | `PKG` | Менеджер |
|---|---|---|
| debian, ubuntu | `apt` | apt-get |
| fedora, rhel, centos, rocky, almalinux | `dnf` | dnf |
| alpine | `apk` | apk |
| прочие | `unknown` | пропуск установки пакетов (предупреждение) |

Архитектура (`uname -m`): поддерживаются `x86_64/amd64` → `amd64` и
`aarch64/arm64` → `arm64`; остальные — фатальная ошибка. Версия ядра
вычисляется как `MAJOR.MINOR` и используется для решения про XDP.

Build-зависимости (`install_packages`, [`install.sh`](../../install.sh):243-278):
`curl git pkg-config build-essential ca-certificates openssl cmake` плюс
`libssl-dev/openssl-devel clang llvm`. `cmake` ставится заранее намеренно — он
транзитивная зависимость `libz-ng-sys` (через `pingora-cache`/`zstd`), без него
сборка `aegis-pingora` падает поздно с «is cmake not installed?».

> **Honesty caveat.** На `PKG=unknown` (нестандартный дистрибутив) установщик
> только предупреждает и продолжает «оптимистично». Зависимости придётся
> ставить вручную: gcc, cmake, git, pkg-config, openssl-dev, ca-certificates,
> clang, llvm.

### Node.js и pnpm

`install_node` ([`install.sh`](../../install.sh):211-241) нужен **только для сборки**
React-панели (`web/dist` вшивается в бинарь через `include_dir!`). В runtime
Node не требуется. Логика:

- если `pnpm` уже на PATH — пропуск;
- иначе ставит Node.js 20.x (apt: NodeSource setup_20.x; dnf: `nodejs:20`;
  apk: `nodejs npm`), затем `npm install -g pnpm@10`.

`AEGIS_SKIP_NODE_INSTALL=1` пропускает установку (Node + pnpm должны быть на PATH).

### Rust-toolchain

`install_rust` ([`install.sh`](../../install.sh):280-319):

- если `cargo` отсутствует — ставит `rustup` + **stable** toolchain (profile minimal);
- при включённом XDP дополнительно ставит **nightly** + компонент `rust-src`
  (для `-Z build-std` eBPF-кода) и бинарь `bpf-linker` (через `cargo install`).

`AEGIS_SKIP_RUST_INSTALL=1` пропускает (cargo должен быть на PATH).

> **Honesty caveat.** nightly и `bpf-linker` нужны **только** для XDP-фичи. Если
> `bpf-linker` не установится, eBPF-сборка упадёт; установщик советует
> повторить с `--no-xdp`. Без XDP достаточно stable.

---

## 3. Режимы (`--mode`) и бинари

AEGIS поставляет два data-plane бинаря. `--mode` (env `AEGIS_MODE`,
default `pingora`) выбирает, что собрать и какой сервис включить
([`install.sh`](../../install.sh):511-528, 1340-1351):

| `--mode` | Что собирается | Какой сервис включён | Назначение |
|---|---|---|---|
| `pingora` (default) | `aegis` (CLI/hyper) + `aegis-pingora` + XDP-объект | `aegis-pingora.target` | Production (V72+) |
| `hyper` | только `aegis` | `aegis.service` | Legacy / HTTP/3 dev / compat |
| `both` | оба бинаря + XDP | `aegis-pingora.target` (primary), `aegis.service` записан, но **отключён** | A/B, shadow-бенч |

Важная деталь: даже в `--mode pingora` собирается **и** hyper-бинарь `aegis` —
он несёт CLI-инструменты (`aegis web reset-admin`, `aegis -t` для валидации
конфига и т.д.), которые работают с тем же файлом состояния, что читает демон
pingora ([`install.sh`](../../install.sh):516-522).

Бинари ставятся в `/usr/local/bin/aegis` и `/usr/local/bin/aegis-pingora`.
Подробнее о различиях путей данных — [Архитектура](./02-architecture.md) и
[Протоколы и слушатели](./07-protocols.md).

### CLI самого `aegis-pingora`

Бинарь `aegis-pingora` принимает **только два флага** (clap-структура `Cli`,
[`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs):530-535):

| Флаг | Default | Назначение |
|---|---|---|
| `-c`, `--config <PATH>` | `/etc/aegis/aegis.conf` | путь к конфигу (DSL или legacy TOML, автодетект) |
| `--log-level <LEVEL>` | `info` | уровень логирования |

Всё остальное поведение управляется переменными окружения (раздел 9).

> **Honesty caveat про `--upgrade`.** Документ [`pingora-deployment.md`](../en/reference/pingora-deployment.md)
> описывает zero-downtime-апгрейд через `aegis-pingora --upgrade`. В текущей
> clap-структуре бинаря такого флага **нет** — он принимает лишь `--config` и
> `--log-level`. Для применения новой конфигурации/бинаря используйте
> rolling restart воркеров (раздел 6) или `--update` (раздел 7), а не `--upgrade`.

---

## 4. Профиль сборки, `AEGIS_BUILD_OPT=max`, target-cpu и mold

### Профиль по умолчанию

Релизный профиль в `Cargo.toml` оптимизирован под **быстрый параллельный**
билд (важно для `--update`): `lto = "thin"`, `codegen-units = 16`,
`incremental = true`, `opt-level = 3`, `panic = "abort"`, `strip = "symbols"`.

### `AEGIS_BUILD_OPT=max`

Для выпуска релиза можно затянуть профиль до максимума
([`install.sh`](../../install.sh):502-509). При `AEGIS_BUILD_OPT=max` экспортируются:

```
CARGO_PROFILE_RELEASE_LTO=fat
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
CARGO_PROFILE_RELEASE_INCREMENTAL=false
```

Это даёт самый быстрый бинарь ценой долгой, почти однопоточной сборки — для
routine `--update` не рекомендуется.

### target-cpu

`install.sh` компилирует **на целевом хосте**, поэтому сборка под локальный CPU
безопасна и оптимальна (`AEGIS_TARGET_CPU`, default `native`,
[`install.sh`](../../install.sh):419-435):

| `AEGIS_TARGET_CPU` | Эффект |
|---|---|
| `native` (default) | все фичи именно этого CPU (AVX2/BMI на x86, LSE-атомики на ARM) |
| `generic` | портируемый бинарь (build-once-deploy-many) |
| `neoverse-n1`, `x86-64-v3`, … | пин конкретной микроархитектуры |

Передаётся через `RUSTFLAGS -C target-cpu=...`; предустановленный `RUSTFLAGS`
из окружения сохраняется и добавляется после.

### mold (V246)

`install_packages` ставит линкер **mold** best-effort (apt/dnf/apk;
[`install.sh`](../../install.sh):270-277). Если mold доступен, `aegis_rustflags`
добавляет `-C link-arg=-fuse-ld=mold` для многопоточного финального линка
большого бинаря `aegis-pingora`. Отсутствие mold — не ошибка: используется
дефолтный линкер. На пути `--update` наличие mold переустанавливается
best-effort ([`install.sh`](../../install.sh):490-496).

См. также Производительность и тюнинг.

---

## 5. Раскладка systemd: template, target, воркеры

### Pingora-режим (рекомендуемый)

`write_systemd_unit_pingora` ([`install.sh`](../../install.sh):1209-1309) пишет два юнита:

- **Template-юнит** `/etc/systemd/system/aegis-pingora@.service` — один экземпляр
  на воркер. Ключевые поля:
  - `User=aegis`, `Group=aegis`, `WorkingDirectory=/var/lib/aegis`;
  - `EnvironmentFile=-/etc/aegis/aegis.env`;
  - `Environment=AEGIS_PINGORA_REUSEPORT=1` — все экземпляры биндят одни и те же
    порты, ядро хеширует 4-tuple на один из них;
  - `Environment=AEGIS_PINGORA_THREADS=1` — thread-per-core (V230);
  - `ExecStart=/usr/local/bin/aegis-pingora -c /etc/aegis/aegis.conf --log-level info`;
  - `CPUAffinity=%i` — воркер `i` прибит к CPU `i` (экземпляры нумеруются `0..N-1`);
  - `LimitNOFILE=1048576`, `LimitMEMLOCK=infinity` (для BPF-карт), `Nice=-10`;
  - `Restart=on-failure`, `RestartSec=2`;
  - `PartOf=aegis-pingora.target`.

- **Target** `/etc/systemd/system/aegis-pingora.target`
  ([`install.sh`](../../install.sh):1290-1308) группирует воркеры. Принципиальный
  момент V237: target использует **`Wants=`**, а **не** `Requires=` для
  перечисления экземпляров `aegis-pingora@0..N-1.service`. Это и делает возможным
  rolling restart: остановка одного воркера не делает зависимость target
  «неудовлетворённой» и **не каскадит** остановку соседей. `PartOf` на template
  по-прежнему обеспечивает, что рестарт target веером доходит до всех экземпляров.

Включение/старт ([`install.sh`](../../install.sh):1411-1435): экземпляры `0..N-1`
включаются, затем включается и рестартится `aegis-pingora.target`. Каждый воркер
проверяется через `systemctl is-active`.

> **Расхождение с примером в [`pingora-deployment.md`](../en/reference/pingora-deployment.md).**
> Тот документ показывает ручную нумерацию `aegis-pingora@{1,2,3,4}` и
> `CPUAffinity=0-1`. Реальный установщик (V230) нумерует экземпляры **с нуля**
> (`0..N-1`) и прибивает каждый к **одному** CPU (`CPUAffinity=%i`). Ориентируйтесь
> на установщик.

### Hyper-режим

`write_systemd_unit_hyper` ([`install.sh`](../../install.sh):1164-1207) пишет один
`aegis.service`:
- `ExecStartPre=$AEGIS_BIN -c .../aegis.conf -t` (валидация конфига перед стартом);
- `ExecStart=$AEGIS_BIN -c .../aegis.conf start`;
- `ExecReload=` дёргает `POST /admin/reload` через curl с админ-токеном
  (hot-reload без рестарта — особенность hyper-пути).

### Количество воркеров (`--workers`)

`resolve_workers` ([`install.sh`](../../install.sh):156-191):

1. Если `--workers` не задан и существует `/var/lib/aegis/topology.json`, берётся
   значение, записанное панелью (страница Workers, `PUT /admin/api/topology`).
2. Если всё ещё `auto` — `AEGIS_WORKERS = nproc`, по одному потоку на воркер.
3. Явный `--workers N` всегда побеждает. Всегда 1 поток на воркер
   (thread-per-core).

CLI-флаг `--workers N` или env `AEGIS_WORKERS`. Подробно про REUSEPORT и сайзинг —
[Многопроцессность и воркеры](./06-workers.md).

---

## 6. Rolling restart (path-watcher)

Кнопка «Restart» в панели (`POST /admin/api/restart`) не может напрямую
вызвать `systemctl restart`: демон работает непривилегированно и внутри
собственного cgroup воркера (`NoNewPrivileges` блокирует sudo-эскалацию, а
прямой `systemctl` получил бы SIGKILL вместе со своим cgroup в момент рестарта).

Решение — **path-watcher** (`ensure_restart_watcher`,
[`install.sh`](../../install.sh):888-945):

1. Демон пишет marker-файл `/var/lib/aegis/.restart-request`.
2. Root-овый `aegis-restart.path` следит за `PathExists=` этого маркера и
   запускает `aegis-restart.service` из отдельного cgroup, где он переживает
   падение target.
3. Сервис сначала удаляет маркер (`ExecStartPre`, чтобы не зациклиться), затем
   вызывает `/usr/local/bin/aegis-rolling-restart`.

Скрипт `aegis-rolling-restart` ([`install.sh`](../../install.sh):898-910):

```sh
units=$(systemctl list-units ... 'aegis-pingora@*.service' | awk '{print $1}')
count=...
if [ "$count" -le 1 ]; then
    exec systemctl restart aegis-pingora.target   # 0/1 воркер — обычный рестарт
fi
for u in $units; do
    systemctl restart "$u" || true                # по одному
    sleep 3
done
```

То есть воркеры REUSEPORT перезапускаются **по одному** с паузой 3 c —
оставшиеся держат слушающие сокеты, downtime близок к нулю. Для 0/1 воркера
(hyper или один воркер) делается обычный рестарт target.

> Старые попытки выдать права на рестарт через sudoers/polkit удаляются
> ([`install.sh`](../../install.sh):943) — теперь это делает path-watcher.

Ручной эквивалент: `systemctl restart aegis-pingora.target` (атомарно через все
экземпляры) или `/usr/local/bin/aegis-rolling-restart` (по одному).

---

## 7. Обновление (`--update`)

```bash
sudo bash install.sh --update
```

`update_only` ([`install.sh`](../../install.sh):947-973):

1. Проверяет, что `/usr/local/src/aegis/.git` существует (иначе — «сначала
   полная установка»).
2. `build_and_install` — `git fetch`/`checkout`/`reset --hard` до tip ветки
   (`AEGIS_VERSION`, default `main`), пересборка фронтенда и бинарей.
3. `ensure_ui_env_dropin` — гарантирует наличие UI-env и systemd drop-in (путь
   `--update` **никогда** не переписывает unit-файлы).
4. Валидация конфига: `aegis -c /etc/aegis/aegis.conf -t`.
5. Рестарт: `systemctl restart aegis` (hyper) или `aegis-pingora.target`.
6. Проверка `is-active`; при провале — указатель на `journalctl`.

Конкретную ветку/тег ставит `--version`:

```bash
sudo bash install.sh --version v1.0
```

> **Honesty caveat.** `--update` делает **полный рестарт target**, а не rolling.
> Для near-zero-downtime применения изменений вне обновления кода используйте
> rolling restart (раздел 6). Air-gapped/локальная сборка — через
> `AEGIS_SRC_OVERRIDE=/path/to/tree` (пропускает все git-операции,
> [`install.sh`](../../install.sh):337-343).

Про миграцию между версиями — Обновление и миграция.

---

## 8. Удаление (`--uninstall`) и полная очистка (`--purge`)

```bash
sudo bash install.sh --uninstall   # стоп + удалить бинари, /etc/aegis сохранить
sudo bash install.sh --purge       # uninstall + удалить state-каталоги
```

`uninstall` ([`install.sh`](../../install.sh):1511-1538):

- Останавливает и отключает `aegis.service`, `aegis-pingora.target` и экземпляры
  `aegis-pingora@0..16` (диапазон `0..16` подметает и старую нумерацию `1..16`,
  и новую `0..15`).
- Удаляет unit-файлы (`aegis.service`, `aegis-pingora@.service`,
  `aegis-pingora.target`), `daemon-reload`.
- Удаляет бинари `/usr/local/bin/aegis*` и исходники `/usr/local/src/aegis`.
- При `--purge` дополнительно удаляет `/etc/aegis`, `/var/lib/aegis`,
  `/var/log/aegis` и системного пользователя `aegis` (`userdel`).

> **Honesty caveat.** `--uninstall` **сохраняет** конфиг и состояние в
> `/etc/aegis`; чтобы их тоже снести — `--purge`. Установщик не удаляет
> сопутствующие таймеры/скрипты, поставленные best-effort (например
> `aegis-refresh-feeds.timer`, `aegis-restart.path`) и nginx/HAProxy/Caddy/Envoy,
> подтянутые для сравнительного бенчмарка, — их нужно вычищать вручную при
> необходимости.

---

## 9. Каталоги, файлы состояния и env-файлы

### Каталоги (`create_default_config`, [`install.sh`](../../install.sh):1000-1011)

| Путь | Владелец / права | Содержимое |
|---|---|---|
| `/etc/aegis/` | `root:aegis` | конфиг, токены, сертификаты (read-only для демона) |
| `/etc/aegis/aegis.conf` | `root:aegis` 0640 | главный конфиг (DSL) |
| `/etc/aegis/sites-enabled/`, `sites-available/` | `root:aegis` | ops-управляемые сайты |
| `/etc/aegis/admin-token` | `root:aegis` 0600 | админ-токен API |
| `/etc/aegis/hmac-secret` | `root:aegis` 0600 | секрет challenge/HMAC |
| `/etc/aegis/certs/` | — | bootstrap self-signed cert (`default.crt/key`) |
| `/var/lib/aegis/` (`AEGIS_HOME`) | `aegis:aegis` | writable-состояние демона |
| `/var/lib/aegis/sites.d/` | `aegis:aegis` 0750 | сайты, управляемые UI |
| `/var/lib/aegis/acme/{orders,accounts,challenges}` | `aegis:aegis` | состояние ACME |
| `/var/lib/aegis/certs/` | `aegis:aegis` | выпущенные ACME-сертификаты |
| `/var/log/aegis/` (`AEGIS_LOG_DIR`) | `aegis:aegis` | audit.log и пр. |

Дополнительные подкаталоги `/var/lib/aegis/`, создаваемые демоном на старте
(каждый SO_REUSEPORT-воркер берёт flock-шард), сверено по
[`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs):

| Путь (env-override) | Назначение | Default |
|---|---|---|
| `runtime-toggles.json` (`AEGIS_TOGGLES_PATH`) | runtime-тогглы фильтров (V168) | `/var/lib/aegis/runtime-toggles.json` |
| `domain-policy.json` (`AEGIS_DOMAIN_POLICY_PATH`) | per-domain политики (V168) | `/var/lib/aegis/domain-policy.json` |
| `geo/` (`AEGIS_GEO_DIR`) | агрегация GeoIP по странам (V242) | `/var/lib/aegis/geo` |
| `site-map/` (`AEGIS_SITEMAP_DIR`) | картография сайтов (V240) | `/var/lib/aegis/site-map` |
| `events/` (`AEGIS_EVENTS_DIR`) | журнал запросов (V243) | `/var/lib/aegis/events` |
| `reputation/` (`AEGIS_REPUTATION_DIR`) | фиды репутации (ASN/CIDR, JA4) | `/var/lib/aegis/reputation` |
| `geoip/` | GeoIP mmdb (страна/ASN) | `/var/lib/aegis/geoip` |
| `topology.json` | желаемое число воркеров (панель) | `/var/lib/aegis/topology.json` |
| `web.json` (`AEGIS_WEB_STATE`) | учётка/сессии веб-панели | `/var/lib/aegis/web.json` |
| `honeypots.json` (`AEGIS_HONEYPOT_STATE`) | состояние honeypot | `/var/lib/aegis/honeypots.json` |

Демон **читает** эти файлы по mtime-поллингу — правки подхватываются без
рестарта. См. Журнал запросов,
GeoIP, [Репутация](./12-reputation.md),
Honeypot и tarpit.

### Два env-файла: `/etc/aegis/aegis.env` и `aegis-ui.env`

Намеренно разделены ради модели безопасности (`ensure_ui_env_dropin`,
[`install.sh`](../../install.sh):531-575):

1. **`/etc/aegis/aegis.env`** ([`install.sh`](../../install.sh):1311-1338) —
   операторские дефолты, **read-only** для демона (юнит держит
   `ReadOnlyPaths=/etc/aegis`). Содержит, в частности:
   - `AEGIS_ADMIN_TOKEN_FILE`, `AEGIS_CHALLENGE_SECRET_FILE`;
   - `AEGIS_RESPONSE_CACHE_ENABLE=1`, `AEGIS_DYNAMIC_TRUST_ENABLE=1`;
   - `AEGIS_HONEYPOT_STATE=/var/lib/aegis/honeypots.json`;
   - `RUST_LOG=info,aegis=info,aegis_pingora=info`.

2. **`/var/lib/aegis/aegis-ui.env`** — тогглы фич, которые пишет панель
   (`PUT /admin/api/env`). Лежит в **writable**-зоне (`ReadWritePaths`,
   владелец — сервисный пользователь), 0640. Подключается systemd **drop-in**
   `/etc/systemd/system/aegis-pingora@.service.d/10-aegis-ui-env.conf`
   (и аналогичный для `aegis.service.d`):

   ```ini
   [Service]
   EnvironmentFile=-/var/lib/aegis/aegis-ui.env
   Environment=AEGIS_ENV_FILE=/var/lib/aegis/aegis-ui.env
   ```

   Файл подключается **после** `/etc/aegis/aegis.env`, поэтому тогглы панели
   **перекрывают** операторские дефолты. `AEGIS_ENV_FILE` указывает
   in-process-писателю на writable-файл.

> **Зачем разделение (honesty / модель безопасности).** Под `ProtectSystem=strict`
> + `ReadOnlyPaths=/etc/aegis` скомпрометированный демон **не может** переписать
> собственный конфиг, сертификаты или токен. Drop-in (а не правка template)
> используется, чтобы env-связка применялась и при `--update` (который не
> переписывает unit-файлы), и переживала будущие переписывания шаблона.
> Применить изменения env: `systemctl restart aegis-pingora.target`.
> См. Модель безопасности.

### Избранные runtime env-переменные демона

Сверено по [`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs). Полный
список фич-флагов — в соответствующих доках; здесь — эксплуатационно значимые:

| Переменная | Default | Эффект |
|---|---|---|
| `AEGIS_PINGORA_REUSEPORT` | (юнит ставит `1`) | `SO_REUSEPORT` — обязателен для N>1 воркеров на одном порту |
| `AEGIS_PINGORA_THREADS` | (юнит ставит `1`) | потоков на воркер |
| `AEGIS_PINGORA_WORK_STEALING` | off (NoSteal) | `1` возвращает work-stealing tokio |
| `AEGIS_PINGORA_UPSTREAM_POOL` | — | размер пула upstream-соединений |
| `AEGIS_PINGORA_GRACE_SECS` | — | окно graceful-дрейна при SIGTERM |
| `AEGIS_PINGORA_DOWNSTREAM_KEEPALIVE` | off | TCP keepalive на принятых клиентских стримах (по умолчанию OFF — V231 fix против переполнения accept-очереди) |
| `AEGIS_LISTEN` / `AEGIS_LISTEN_TLS` | из конфига | переопределение plain/TLS listen |
| `AEGIS_ADMIN_LISTEN` | из конфига / `127.0.0.1:9090` | адрес admin-порта |
| `AEGIS_ADMIN_TOKEN` | — | админ-токен (роль Admin), мерджится с `[[admin.tokens]]` |
| `AEGIS_TLS_TICKET_KEY_FILE` | `/etc/aegis/tls_ticket.key` | общий TLS session-ticket ключ для REUSEPORT-воркеров |

> **Honesty про TLS-тикеты.** Общий ticket-ключ генерируется CSPRNG (OsRng),
> файл 0600, длина запрашивается у OpenSSL в runtime
> ([`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs):661-867).
> **Ротация ключа НЕ реализована** (см. `TODO(security)` в коде) — ключ статичен
> до рестарта процесса. Это явно отмеченное ограничение; форвард-секретность
> TLS 1.3 (ECDHE per-handshake) при этом не ослабляется. См.
> [TLS и сертификаты](./08-tls-certificates.md).

---

## 10. Capabilities и sandbox systemd

### File-capabilities на бинаре

После сборки `aegis-pingora` устанавливается file-capability
([`install.sh`](../../install.sh):463-465):

```
setcap 'cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep' /usr/local/bin/aegis-pingora
```

Это даёт биндинг привилегированных портов (`:80`/`:443`) без root; capability
переживает exec, так что template-юнит роняет привилегии до пользователя
`aegis`. Если `setcap` не сработал — предупреждение, и воркеры на `:80/:443`
потребуют root.

### Ambient/Bounding capabilities в юните

`write_systemd_unit_pingora` ([`install.sh`](../../install.sh):1221-1232, 1282-1283)
задаёт набор capability в зависимости от XDP:

| Сценарий | `AmbientCapabilities` / `CapabilityBoundingSet` | `RestrictAddressFamilies` |
|---|---|---|
| без XDP | `CAP_NET_BIND_SERVICE` | `AF_INET AF_INET6 AF_UNIX` |
| с XDP | `CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON` | `+ AF_NETLINK` |

Почему именно так (комментарии в коде): `CAP_BPF`+`CAP_PERFMON` нужны для
загрузки/верификации eBPF-программы (на ядрах 6.x верификатор гейтит
pointer/packet-data операции за `perfmon_capable()`, и без `CAP_PERFMON`
`BPF_PROG_LOAD` падает с `EACCES`); `CAP_NET_ADMIN` — для attach программы к NIC;
`AF_NETLINK` — XDP-attach идёт через rtnetlink.

### Sandbox-харднинг

Оба юнита включают (с небольшими отличиями):
`NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp=true`, `ProtectKernelTunables=true`, `ProtectKernelModules=true`,
`ProtectControlGroups=true`, `RestrictNamespaces=true`, `LockPersonality=true`,
`ReadOnlyPaths=/etc/aegis`, `ReadWritePaths=/var/log/aegis /var/lib/aegis`.

Полный разбор модели — Модель безопасности и харднинг;
про XDP-требования к ядру/CAP — [XDP/eBPF](./13-xdp-ebpf.md).

---

## 11. XDP fast-path при установке

`resolve_xdp_enable` ([`install.sh`](../../install.sh):131-154):

- `--mode hyper` → XDP всегда выключен (data plane hyper-only; XDP подключён через
  pingora-путь);
- `auto` (default): включается при ядре **≥ 4.18** (минимум для aya XDP), иначе
  выключается с предупреждением;
- `--xdp` / `--no-xdp` / `AEGIS_ENABLE_XDP=1|0` форсируют.

`resolve_xdp_iface` ([`install.sh`](../../install.sh):193-209): `auto` берёт первый
non-`lo` интерфейс в состоянии `UP`; иначе `--xdp-iface <name>` / `AEGIS_XDP_IFACE`.

При включённом XDP установщик собирает eBPF-объект (`build_xdp_object`,
[`install.sh`](../../install.sh):469-484) в `/var/lib/aegis/aegis-xdp.o` и добавляет
в конфиг блок `xdp { ... }` с kernel rate-limit
([`install.sh`](../../install.sh):1024-1042):

```
xdp {
    enabled true;
    interface <iface>;
    bpf_object_path /var/lib/aegis/aegis-xdp.o;
    rate_window_ms 1000;
    rate_burst 200;
    syn_burst 100;
}
```

> **Honesty caveat.** XDP — Linux-only и зависит от ядра/CAP. На ARM без PMU
> (`CAP_PERFMON`/perf) загрузка XDP не пройдёт — будет graceful fallback на
> nftables/iptables. Подробности и ограничения — [XDP/eBPF](./13-xdp-ebpf.md),
> [Системные требования](./05-requirements.md).

---

## 12. Сертификат, firewall, фиды и бенч-прокси

- **Bootstrap-сертификат**: `generate_self_signed_cert`
  ([`install.sh`](../../install.sh):983-998) пишет self-signed `default.crt/key`
  (CN=aegis-default, 365 дней) — заменяется реальным/ACME позже. См.
  [TLS и сертификаты](./08-tls-certificates.md).
- **Firewall**: `setup_firewall` ([`install.sh`](../../install.sh):1355-1374)
  открывает `:80/tcp`, `:443/tcp`, `:443/udp` (h3/QUIC), `:6280/tcp` в ufw или
  firewalld, если те активны. Отключается `AEGIS_SKIP_FIREWALL=1`.
- **Конфликт портов**: `detect_port_conflict` ([`install.sh`](../../install.sh):1376-1389)
  предупреждает (не падает), если `:80/:443/:6280` уже заняты (типично — старый
  nginx/apache).
- **Фиды репутации**: `ensure_reputation_feeds` ([`install.sh`](../../install.sh):788-879)
  ставит `/usr/local/bin/aegis-refresh-feeds` + ежедневный таймер
  `aegis-refresh-feeds.timer` (Tor exit list, Spamhaus DROP, db-ip ASN-lite;
  опциональный CrowdSec через `/etc/aegis/feeds.env`). Демон hot-reload-ит файлы
  по mtime. Всё best-effort. См. [Репутация](./12-reputation.md).
- **GeoIP**: `ensure_geoip_db` ([`install.sh`](../../install.sh):768-777) сидит
  встроенную db-ip Country Lite mmdb (`cp -n`, не затирает обновлённую панелью).
  См. GeoIP.

> **Honesty caveat про бенч-прокси.** `ensure_nginx_for_benchmark` и
> `ensure_benchmark_proxies` ([`install.sh`](../../install.sh):582-761) ставят
> nginx, HAProxy, Caddy, nginx+ModSecurity+CRS и Envoy **исключительно** для
> сравнительного бенчмарка панели и сразу **disable/stop/mask** их сервисы
> (чтобы они не отбирали `:80/:443`). Бенч запускает их ad-hoc на loopback. Всё
> best-effort: неустановившийся прокси просто показывается как `unavailable` и
> **никогда** не валит установку. Это **не** часть data plane AEGIS. См.
> Бенчмаркинг.

---

## 13. Команды эксплуатации (шпаргалка)

Из `print_summary` ([`install.sh`](../../install.sh):1483-1502) и реального
поведения юнитов:

```bash
# Статус и логи
systemctl status aegis-pingora.target
systemctl status 'aegis-pingora@*'
journalctl -u aegis-pingora.target -f          # или -u aegis -f в hyper-режиме
journalctl -u aegis-pingora@0 -n 50            # конкретный воркер

# Применить изменения конфига
aegis -c /etc/aegis/aegis.conf -t              # валидация без рестарта
systemctl restart aegis-pingora.target         # полный рестарт (атомарно)
/usr/local/bin/aegis-rolling-restart           # near-zero-downtime, по одному

# Проверить, что воркеры делят порт
ss -ltnp | grep ':80'                           # несколько процессов aegis-pingora

# Учётка веб-панели
aegis web reset-admin                           # перегенерировать креды

# Метрики/здоровье через admin-токен
curl -s -H "x-admin-token: $(cat /etc/aegis/admin-token)" \
     http://127.0.0.1:6280/metrics

# Обновление / удаление
sudo bash install.sh --update
sudo bash install.sh --uninstall                # сохранить /etc/aegis
sudo bash install.sh --purge                    # снести всё

# Фиды репутации вручную
/usr/local/bin/aegis-refresh-feeds
systemctl list-timers aegis-refresh-feeds.timer
```

Добавление сайта (`print_summary`): создать `.conf` в
`/etc/aegis/sites-enabled/` (ops) или дать панели писать в
`/var/lib/aegis/sites.d/` (UI), затем `aegis -t` и
`systemctl restart aegis-pingora.target`. Синтаксис — см.
[Конфигурация (DSL и TOML)](./04-configuration.md) и
Картография и домены.

---

## 14. Сводка переменных окружения установщика

Все читаются перед запуском (шапка [`install.sh`](../../install.sh):38-57), могут
быть заданы перед `bash install.sh`:

| Переменная | Default | Назначение |
|---|---|---|
| `AEGIS_VERSION` | `main` | ветка/тег для clone/checkout (= `--version`) |
| `AEGIS_MODE` | `pingora` | `pingora` \| `hyper` \| `both` (= `--mode`) |
| `AEGIS_WORKERS` | `auto` (= nproc) | число REUSEPORT-воркеров (= `--workers`) |
| `AEGIS_ENABLE_XDP` | `auto` | `1` \| `0` (= `--xdp` / `--no-xdp`) |
| `AEGIS_XDP_IFACE` | `auto` | интерфейс для XDP (= `--xdp-iface`) |
| `AEGIS_BUILD_OPT` | (unset) | `max` → fat LTO + codegen-units=1 |
| `AEGIS_TARGET_CPU` | `native` | `generic` \| микроарх |
| `AEGIS_PORT_HTTP` / `_HTTPS` / `_ADMIN` | `80` / `443` / `6280` | порты |
| `AEGIS_SKIP_RUST_INSTALL` | `0` | пропустить установку Rust |
| `AEGIS_SKIP_NODE_INSTALL` | `0` | пропустить установку Node/pnpm |
| `AEGIS_SKIP_FIREWALL` | `0` | не трогать ufw/firewalld |
| `AEGIS_REPO` | github.com/tnAnGel/Aegis | URL репозитория (для приватного — с auth) |
| `AEGIS_SRC_OVERRIDE` | (unset) | использовать готовое дерево исходников (air-gapped) |

---

## Связанные документы

- [Обзор](./01-overview.md) — что такое AEGIS
- [Архитектура и жизненный цикл запроса](./02-architecture.md)
- [Конфигурация (DSL и TOML)](./04-configuration.md)
- [Системные требования и совместимость](./05-requirements.md)
- [Многопроцессность, REUSEPORT и воркеры](./06-workers.md)
- [Сетевые слушатели и протоколы](./07-protocols.md)
- [TLS и сертификаты (ACME)](./08-tls-certificates.md)
- [XDP/eBPF kernel fast-path](./13-xdp-ebpf.md)
- Модель безопасности и харднинг
- Обновление и миграция
- FAQ и устранение неполадок
- Первоисточники: [`install.sh`](../../install.sh),
  [`src/bin/aegis-pingora.rs`](../../src/bin/aegis-pingora.rs),
  [pingora-deployment.md](../en/reference/pingora-deployment.md),
  [multi-process-deployment.md](../en/reference/multi-process-deployment.md)
</content>
</invoke>
