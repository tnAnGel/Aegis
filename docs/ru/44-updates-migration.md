# Обновление и миграция

Как AEGIS обновляется на хосте, что именно делает поток `install.sh --update` (git fetch → reset → build → restart), что переживает обновление, а что нет, и как откатиться. Документ важно прочитать честно: **встроенный в панель механизм самообновления (download/verify/install/activate/restart) был полностью удалён в V233** как класс уязвимости (unauthenticated-RCE). Сегодня единственный путь обновления — ручной запуск установщика на хосте; панель остаётся только read-only «проверкой обновлений».

> Источники, на которых грунтуется документ: `install.sh` (флаг `--update`, функции `sync_source_tree`, `build_and_install`, `update_only`, `ensure_restart_watcher`), `src/updates.rs` (update-checker), `src/bin/aegis-updater.rs` (отключённый апплаер), а также — для исторического контекста — `src/update_snapshot.rs`, `src/update_layout.rs`, `src/update_apply.rs` (модули прежней apply-машины, более не вызываемые из data plane).

---

## 1. Картина целиком

Есть два разных понятия «обновления», которые легко перепутать:

| Понятие | Где живёт | Что делает | Активно сейчас? |
|---------|-----------|-----------|-----------------|
| **Update-checker** | `src/updates.rs`, маршруты `/admin/api/updates/*` | Read-only: опрашивает Releases API, говорит «доступна новая версия», даёт ссылку на релиз | **Да** (opt-in) |
| **In-panel apply** (download/verify/install/activate/restart) | `src/bin/aegis-updater.rs` + `update_snapshot.rs`/`update_layout.rs`/`update_apply.rs` | Скачивал и исполнял бинарь, переключал симлинк, перезапускал демон — **из панели** | **Нет, удалён в V233** |
| **`install.sh --update`** | `install.sh` | git fetch → reset → rebuild → rolling restart, **запускается оператором на хосте** | **Да** — единственный путь применения обновлений |

Иначе говоря: панель **показывает**, что обновление есть, а **ставит** его оператор руками через установщик.

---

## 2. Update-checker (`src/updates.rs`)

Read-only поллер Releases API, совместимый с Gitea v1.x и GitHub Releases API. Обе платформы отдают `GET /repos/<owner>/<repo>/releases` — JSON-массив релизов (`tag_name`, `name`, `body`, `published_at`, `prerelease`, `draft`, `assets[]`). Ни одна точка входа в этом модуле не достигает apply/execute-пути — каждый вызов это HTTP GET к фиду релизов.

### 2.1. Каналы

Оператор выбирает канал `stable | beta | nightly` (`enum Channel`). Релиз классифицируется по тегу (`Release::channel`):

| Условие в `tag_name` (lowercase) | Канал |
|----------------------------------|-------|
| содержит `-nightly` | `nightly` |
| содержит `-beta` или `-rc` | `beta` |
| иначе | `stable` |

Видимость каналов (`Channel::permits`) — как в Rust/Chrome: stable видят все; beta видят beta+nightly; nightly видит только nightly.

```text
stable   → stable
beta     → stable, beta
nightly  → stable, beta, nightly
```

### 2.2. Конфигурация (`UpdateConfig`)

| Поле | Назначение | Default |
|------|-----------|---------|
| `repo_api_url` | Базовый URL API до репозитория (без слэша в конце) | `https://api.github.com/repos/tnAnGel/Aegis` |
| `channel` | Канал оператора | `Stable` |
| `current_version` | Текущая версия (берётся из `CARGO_PKG_VERSION`) | версия сборки |
| `poll_interval_secs` | Период фоновых проверок; `0` = не опрашивать автоматически | `3600` |

### 2.3. Поведение

- `check()` тянет `{repo_api_url}/releases?limit=50`, отсеивает `draft`-релизы (`releases.retain(|r| !r.draft)`), кладёт результат в кэш с таймстампом. Ошибки **best-effort**: записываются в `last_error`, но предыдущий успешный список остаётся валиден.
- `status()` фильтрует кэш по разрешённым каналам, берёт самый свежий по `published_at`, сравнивает с `current_version` через семвер-аккуратное `is_newer`. Возвращает `UpdateStatus { current_version, channel, latest, update_available, last_checked_at, last_error }`.
- `releases()` — полная история всех каналов для вкладки «История».
- `poll_due()` — должен ли сработать фоновый поллинг (учитывает `poll_interval_secs` и время последней проверки).

Сравнение версий (`compare_versions`/`parse_version`): срезает ведущий `v`/`V`, бьёт на `.`/`-`, числовые сегменты сравнивает численно, pre-release-метки лексически, с правилом **«нет pre-release» > «любой pre-release»** (`v0.2.0` новее `v0.2.0-beta.1`). Покрывает теги вида `v0.1.5`, `v0.2.0-beta.1`, `v0.2.0-nightly.20260522`.

### 2.4. HTTP-бэкенд

Трейт `HttpClient` (opt-in, как у captcha-провайдеров). Прод-реализация `CurlHttpClient` шеллит в `curl -sS -L --max-time <15s>` — ноль новых зависимостей, есть на любом Linux-хосте, ценой ~50 ms на спавн процесса (нормально для часовых поллов и кнопки «Проверить сейчас»). `StubHttpClient` — для тестов и как фолбэк, когда HTTPS-клиент не подключён. Поддерживается условный GET по ETag, если реализация `HttpClient` заполняет заголовок ответа.

### 2.5. Admin API (read-only)

Маршруты опциональны — включаются только когда update-checker подключён (`src/proxy/pingora_admin.rs`):

| Метод и путь | Действие |
|--------------|----------|
| `GET /admin/api/updates/status` | Дешёвое чтение кэша (`UpdateChecker::status`) |
| `POST /admin/api/updates/check` | Принудительный опрос upstream («Проверить сейчас») |
| `GET /admin/api/updates/releases` | Полная история релизов |
| `PUT /admin/api/updates/config` | Сменить канал / `repo_api_url` / интервал |

> Подробнее об аутентификации этих маршрутов — см. [30-admin-api.md](30-admin-api.md) и [29-admin-panel.md](29-admin-panel.md).

### 2.6. Что было удалено (V233) — честно

В `pingora_admin.rs` явно закомментированы снятые арки диспетчера — их **больше нет**:

```
POST   /admin/api/updates/apply
GET    /admin/api/updates/snapshots
POST   /admin/api/updates/snapshots/create
POST   /admin/api/updates/snapshots/<id>/restore
DELETE /admin/api/updates/snapshots/<id>
GET    /admin/api/updates/releases-installed
GET    /admin/api/updates/apply-status
```

Причина прямым текстом из кода: они скачивали и исполняли управляемый атакующим бинарь от имени сервисного пользователя **без какой-либо криптографической проверки подписи** — дизайн класса unauthenticated-RCE. Любой, кто мог достучаться до `POST /admin/api/updates/apply` (или иначе подбросить launch-манифест), мог заставить хост скачать и выполнить произвольный код.

`src/bin/aegis-updater.rs` оставлен как заглушка только чтобы `[[bin]]`-таргет в `Cargo.toml` собирался: он печатает инструкцию по ручной установке и **завершается с ненулевым кодом** (`ExitCode::FAILURE`), чтобы любой залежавшийся вызыватель (например, старый systemd-unit) падал громко, а не молча ничего не делал.

---

## 3. Снапшоты состояния — что переживает обновление

> ВАЖНАЯ ОГОВОРКА. Модули `src/update_snapshot.rs` / `src/update_layout.rs` / `src/update_apply.rs` — это машинерия снапшотов/релизов прежнего in-panel апплаера (V209–V212). После V233 **она не вызывается из data plane** (нет маршрута, нет апплаера). Код остаётся в дереве и покрыт юнит-тестами, но как функция обновления он не активен. Раздел приведён для понимания формата данных и как ориентир для ручного бэкапа — не описывает «живую кнопку».

При обновлении через `install.sh --update` снапшоты **не создаются автоматически**: установщик делает `git reset --hard` по дереву исходников (`$AEGIS_SRC`, по умолчанию `/usr/local/src/aegis`) и пересобирает бинари — он **не трогает** конфиги в `/etc/aegis` и состояние в `/var/lib/aegis`. Поэтому состояние «переживает» обновление просто потому, что лежит вне дерева исходников. Перечень ниже отражает то, что прежний `SnapshotManager` считал «достойным сохранения» — удобный чек-лист для ручного бэкапа перед обновлением.

### 3.1. Что сохраняется (по `SnapshotManager::create`)

| Путь | Зачем |
|------|-------|
| `/etc/aegis/aegis.conf` | Основной конфиг (DSL или TOML) |
| `/etc/aegis/aegis.env` | systemd env-файл |
| `/etc/aegis/admin-token` | Токен оператора — **терять нельзя** |
| `/etc/aegis/hmac-secret` | Секрет challenge-токенов |
| `/etc/aegis/sites-enabled/*.conf` | Per-site конфиги (фильтр `*.conf`) |
| `/etc/aegis/certs/*` | TLS-сертификаты (фильтр `crt`/`key`/`pem`) |
| `/var/lib/aegis/web.json` | Состояние веб-админки |
| `/var/lib/aegis/honeypots.json` | Тумблеры honeypot-паков |
| `/var/lib/aegis/runtime-toggles.json` | Состояние вкл/выкл фильтров (V160) |
| `/var/lib/aegis/domain-policy.json` | Per-domain оверрайды (V162) |
| `/var/lib/aegis/sites.d/*.conf` | UI-managed файлы сайтов (фильтр `*.conf`) |

### 3.2. Что пропускается (намеренно)

Логи, обучающие сэмплы, кэш намайненных сигнатур — воспроизводимое / огромное / постоянно меняющееся. Эти данные **не** входили в снапшот и при обновлении не сохраняются специально (но и не удаляются `--update`).

### 3.3. Формат снапшота (для справки/ручного бэкапа)

`DEFAULT_SNAPSHOT_ROOT = /var/lib/aegis/snapshots`. Каталог снапшота: `<ISO-компакт>_<slug-причины>`, например `2026-05-22T12-00-00_pre-v0.2.0/`. Внутри `manifest.json` (когда, зачем, версия, список файлов с размерами) + дерево `etc/…` и `var/…`. GC хранит последние `keep_count` снапшотов (default 5), дропая старейшие сверх лимита.

> Практический эквивалент сегодня: перед обновлением просто скопируйте `/etc/aegis` и нужные `*.json` из `/var/lib/aegis` (см. список выше) — это и есть ручной снапшот. Подробнее про эти файлы — [04-configuration.md](04-configuration.md), [26-sites-and-domains.md](26-sites-and-domains.md).

---

## 4. Поток `install.sh --update`

Это **единственный поддерживаемый способ применить обновление**. Запускается оператором на хосте от root.

```bash
# на хосте, в дереве исходников или с прокинутым AEGIS_SRC
sudo bash install.sh --update
```

Диспетчер в конце `install.sh`:

```sh
if [ "$MODE_FLAG" = "update" ]; then
    update_only
    exit 0
fi
```

### 4.1. Что делает `update_only()`

1. `require_root` — обязателен root.
2. Проверка `[ -d "$AEGIS_SRC/.git" ]` — иначе fatal «run full install first» (обновление работает только поверх существующего git-дерева).
3. `build_and_install` → внутри `sync_source_tree` (см. 4.2) + сборка.
4. `ensure_ui_env_dropin` — путь `--update` **никогда не переписывает unit-файлы** (`write_systemd_unit`), поэтому env-файл с UI-фича-флагами и drop-in гарантируются отдельно, чтобы тумблеры панели вступили в силу после рестарта.
5. Валидация конфига: `"$AEGIS_BIN" -c "$AEGIS_ETC/aegis.conf" -t`.
6. Рестарт (см. 4.3).
7. `sleep 1` + проверка `systemctl is-active`; при провале — fatal с подсказкой `journalctl -u <svc> -n 30`.

### 4.2. git fetch → checkout → reset (`sync_source_tree`)

Дефолты: `AEGIS_REPO=https://github.com/tnAnGel/Aegis.git`, `AEGIS_VERSION=main`, `AEGIS_SRC=/usr/local/src/aegis`.

```sh
# реклейм владения (Git 2.35+ ругается "dubious ownership" на чужой репо)
chown -R root:root "$AEGIS_SRC"
git config --global --add safe.directory "$AEGIS_SRC"

# GIT_TERMINAL_PROMPT=0 → нет зависания на запросе логина под curl|sudo bash
if GIT_TERMINAL_PROMPT=0 git -C "$AEGIS_SRC" fetch --tags --quiet; then
    git -C "$AEGIS_SRC" checkout --quiet "$AEGIS_VERSION"          || warn "checkout failed — staying on HEAD"
    git -C "$AEGIS_SRC" reset --hard --quiet "origin/$AEGIS_VERSION" \
        || git -C "$AEGIS_SRC" reset --hard --quiet "$AEGIS_VERSION" || warn "reset failed — building local HEAD"
else
    warn "git fetch failed — building from local HEAD: <последний коммит>"
fi
```

Ключевые свойства:

- **`reset --hard`** означает, что любые локальные правки в `$AEGIS_SRC` будут затёрты. Кастомизация должна жить в `/etc/aegis`, не в дереве исходников.
- **Деградация без сети**: если `fetch` упал (сеть/авторизация), установщик не падает, а собирает из локального HEAD с предупреждением.
- **Приватный репо**: если `clone` нужен (нет `.git`), а репо приватный — fatal с подсказкой задать `AEGIS_REPO` с токеном (`https://user:token@host/repo.git`) или распаковать дерево вручную и задать `AEGIS_SRC_OVERRIDE=/path`.
- `AEGIS_SRC_OVERRIDE` — указать готовое дерево; тогда git-операции **не выполняются** вовсе.

Управляющие переменные:

| Переменная | Назначение | Default |
|------------|-----------|---------|
| `AEGIS_REPO` | URL git-репозитория | `https://github.com/tnAnGel/Aegis.git` |
| `AEGIS_VERSION` | ветка или тег для checkout/reset (`--version` тоже) | `main` |
| `AEGIS_SRC` | Путь дерева исходников | `/usr/local/src/aegis` |
| `AEGIS_SRC_OVERRIDE` | Готовое дерево, без git-операций | (не задан) |
| `AEGIS_MODE` | `pingora` (default) \| `hyper` \| `both` | `pingora` |
| `AEGIS_BUILD_OPT` | `max` → fat LTO + codegen-units=1 (медленно, max-perf) | (не задан → thin LTO, cgu16, incremental) |
| `AEGIS_TARGET_CPU` | `native` (default) \| `generic` \| микроарх | `native` |
| `AEGIS_ENABLE_XDP` | `auto` \| `1` \| `0` | `auto` |

### 4.3. build → rebuild

`build_and_install`:
- `sync_source_tree` (см. выше);
- best-effort доустановка `mold` (на `--update` `install_packages` не вызывается, так что линкер подтягивается здесь);
- профиль сборки: по умолчанию thin LTO / codegen-units=16 / incremental; `AEGIS_BUILD_OPT=max` → fat LTO + codegen-units=1;
- сборка нужных бинарей по `AEGIS_MODE`:
  - `build_aegis_hyper` → `cargo build --release --bin aegis`, ставит в `$AEGIS_BIN` (`/usr/local/bin/aegis`);
  - `build_aegis_pingora` → `cargo build --release --bin aegis-pingora --features "pingora[ xdp]"`, ставит в `$AEGIS_PINGORA_BIN`, навешивает `setcap cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep`;
  - `build_xdp_object` (если `AEGIS_ENABLE_XDP=1`) → nightly + `bpfel-unknown-none`, ставит `aegis-xdp.o`.

> Подробности профиля сборки и CPU-тюнинга — [27-performance-tuning.md](27-performance-tuning.md). Про XDP — [13-xdp-ebpf.md](13-xdp-ebpf.md).

### 4.4. rolling restart

После сборки `update_only` перезапускает сервис:

```sh
if [ "$AEGIS_MODE" = "hyper" ]; then
    systemctl restart aegis
else
    systemctl restart aegis-pingora.target    # фанит на все template-инстансы
fi
```

Это **полный** рестарт таргета. Для near-zero-downtime есть отдельный rolling-механизм, который ставит установщик (`ensure_restart_watcher`) и который дёргает кнопка «Restart» в панели:

- скрипт `/usr/local/bin/aegis-rolling-restart` перечисляет `aegis-pingora@*.service` и при `count > 1` перезапускает воркеры по одному с `sleep 3` между ними — соседи держат слушающие сокеты (SO_REUSEPORT), даунтайма почти нет; при `count <= 1` (hyper или один воркер) фолбэк на `systemctl restart aegis-pingora.target`;
- панель пишет marker-файл `$AEGIS_HOME/.restart-request`, а root-owned path-watcher `aegis-restart.path` → `aegis-restart.service` (`Type=oneshot`) выполняет rolling-restart из отдельного cgroup, переживающего падение таргета. `PathExists` (не `Modified`) → marker срабатывает ровно один раз и удаляется (`ExecStartPre=-rm -f <marker>`), без boot-time loop;
- unit-зависимость намеренно `Wants=` (не `Requires=`): рестарт одного воркера **не** роняет таргет и соседей (см. коммит «restart: target Wants=…»).

> Подробнее про многопроцессность и SO_REUSEPORT — [06-workers.md](06-workers.md). Про эксплуатацию и кнопку Restart — [03-installation.md](03-installation.md), [29-admin-panel.md](29-admin-panel.md).

---

## 5. Self-update lag: `install.sh` обновляет сам себя

Тонкий, но важный момент. `install.sh` лежит **внутри** дерева исходников, которое `--update` затирает через `reset --hard`. Значит, при `--update`:

1. вы запускаете **текущую** (старую) версию `install.sh` на хосте;
2. она делает `git fetch` + `reset --hard` — на диск ложится **новая** версия `install.sh`;
3. но текущий процесс уже исполняется из старого кода — он **не перечитывает** обновлённый скрипт в этом запуске.

Следствия и рекомендации:

- Если в новой версии изменилась логика установки/рестарта/unit-файлов, она применится **только со следующего** запуска `install.sh`.
- Канонический способ получить заведомо свежий установщик — снова взять его через `curl`:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash -s -- --update
  ```
  здесь скрипт скачивается из ветки на лету, поэтому lag-а нет — выполняется уже новая версия (она же затем синхронизирует дерево). Для критичных мажорных переходов это предпочтительный путь.
- Локальный `sudo bash install.sh --update` удобнее (без сети для самого скрипта), но помните о лаге на одну итерацию.

---

## 6. Миграции

В кодовой базе **нет отдельного фреймворка схемных миграций** с версионированными шагами. «Миграция» в AEGIS складывается из нескольких механизмов, каждый из которых надо понимать честно:

| Механизм | Как мигрирует | Источник |
|----------|---------------|----------|
| Конфиг (`aegis.conf`) | Парсер толерантен к незнакомым/отсутствующим директивам; новые поля имеют дефолты. После `--update` обязательна валидация `aegis -c … -t` | `update_only` (шаг 5) |
| State-файлы (`*.json`) | serde с `#[serde(default)]` на новых полях → старый JSON читается, недостающее заполняется дефолтом | напр. `Release`/`UpdateConfig` в `updates.rs` |
| systemd unit-файлы | `--update` **их не переписывает**; меняются только при полной установке (`write_systemd_unit`). Изменения в шаблоне/таргете требуют ручного `systemctl daemon-reload && systemctl restart aegis-pingora.target` | `update_only`, комментарии в `install.sh` |
| UI feature-flag env | `ensure_ui_env_dropin` создаёт/дополняет writable env-файл + drop-in на каждом install/update (идемпотентно), чтобы тумблеры панели пережили обновление | `update_only` (шаг 4) |
| Mtime-poll состояния | Демон хот-релоадит изменившиеся файлы по mtime без рестарта — новые/изменённые `*.json`/`*.conf` подхватываются за ~1s | см. [06-workers.md](06-workers.md) |

Практические следствия при крупном апгрейде:
- всегда прогоняйте `aegis -c /etc/aegis/aegis.conf -t` **до** рестарта (это делает и `update_only`);
- если меняли unit-файлы (новый шаблон, новый таргет, изменился `AEGIS_MODE`) — выполните полную установку, а не `--update`, либо вручную `daemon-reload`;
- секреты `admin-token` и `hmac-secret` менять при обновлении **не нужно и нельзя** — их потеря разлогинит операторов и инвалидирует challenge-токены.

---

## 7. Откат

Откат тоже **ручной** — автоматического rollback (как в прежнем `update_apply.rs` с health-probe и обратным переключением симлинка) после V233 **нет**, потому что нет и апплаера, который его запускал.

Поскольку `--update` собирает из git-дерева, откат = вернуть дерево на прошлую версию и пересобрать.

### 7.1. Откат бинаря (исходники)

```bash
# выбрать заведомо рабочий тег/коммит и собрать из него
sudo AEGIS_VERSION=v0.1.5 bash install.sh --update
# либо вручную в дереве:
sudo git -C /usr/local/src/aegis checkout v0.1.5
sudo bash install.sh --update      # reset --hard origin/<ветка> может вернуть HEAD —
                                   # для пинов используйте AEGIS_VERSION=<тег>
```

> Внимание: при `AEGIS_VERSION=<ветка>` шаг `reset --hard origin/<ветка>` снова подтянет вершину ветки. Чтобы зафиксироваться на конкретной точке, задавайте `AEGIS_VERSION=<тег>` или закоммиченный SHA — тогда checkout/reset нацелятся именно туда.

### 7.2. Откат конфига/состояния

Если перед обновлением вы сделали ручной бэкап `/etc/aegis` и `*.json` из `/var/lib/aegis` (см. раздел 3) — просто верните файлы на место и сделайте rolling restart. Это смысловой эквивалент `SnapshotManager::restore` (перезапись файлов на месте по манифесту), но выполняемый руками.

### 7.3. После любого отката

```bash
aegis -c /etc/aegis/aegis.conf -t          # валидация конфига
sudo /usr/local/bin/aegis-rolling-restart  # near-zero-downtime, либо:
sudo systemctl restart aegis-pingora.target
systemctl is-active aegis-pingora.target
journalctl -u aegis-pingora@0 -n 30        # если что-то не так
```

---

## 8. Чек-лист безопасного обновления

1. **Бэкап** `/etc/aegis` + нужные `*.json` из `/var/lib/aegis` (раздел 3) — это ваш «снапшот».
2. Зафиксируйте текущую рабочую версию/тег (для возможного отката).
3. Обновление: `curl …/install.sh | sudo bash -s -- --update` (без self-update lag) **или** локальный `sudo bash install.sh --update`.
4. Дождитесь валидации `aegis -c … -t` (делает установщик) — при ошибке конфига он остановится до рестарта.
5. Проверьте `systemctl is-active` и панель.
6. При проблеме — откат по разделу 7.

---

## См. также

- [03-installation.md](03-installation.md) — установка, кнопка Restart, эксплуатация.
- [04-configuration.md](04-configuration.md) — `aegis.conf`, env, валидация.
- [06-workers.md](06-workers.md) — SO_REUSEPORT, rolling restart, mtime-poll.
- [23-security-model.md](23-security-model.md) — почему in-panel apply был удалён (RCE-класс).
- [29-admin-panel.md](29-admin-panel.md), [30-admin-api.md](30-admin-api.md) — UI и маршруты `/admin/api/updates/*`.
- 42-текущее-состояние-STATUS.md — статус фич, что opt-in/частично.
