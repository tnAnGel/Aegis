# Плагины: Lua/WASM, реестр и модель доверия

AEGIS позволяет операторам встраивать в фильтр‑цепочку собственную логику принятия решений в виде плагинов: скриптов на **Lua 5.4** (через `mlua`, vendored) и модулей **WebAssembly** (через `wasmi`, чистый Rust‑интерпретатор). Плагины подключаются как обычные фильтры (`TrafficFilter`), горячо перезагружаются по mtime файла и не могут уронить прокси — упавший плагин просто пропускает запрос (`Allow`). Этот документ описывает, как именно это работает в коде, какие точки расширения есть, какова модель доверия/песочницы и где функционал намеренно ограничен.

> Грунтовка: всё описанное ниже соответствует коду в `src/filters/plugins/` (`mod.rs`, `manager.rs`, `lua.rs`, `wasm.rs`), `src/config.rs` (`PluginsConfig`), `src/filters/mod.rs`/`src/filters/engine.rs` (цепочка фильтров), `src/dsl/` (DSL‑блок `plugins`) и зависимостям в `Cargo.toml` (`mlua`, `wasmi`).

См. также: модель безопасности — [23-security-model.md](23-security-model.md); WAF — [10-waf.md](10-waf.md); конфигурация — [04-configuration.md](04-configuration.md); rate‑limit — [14-rate-limiting.md](14-rate-limiting.md); challenge‑ladder — [15-challenge-ladder.md](15-challenge-ladder.md); многопроцессность/воркеры — [06-workers.md](06-workers.md).

---

## 1. Обзор и статус

| Возможность | Статус | Где в коде |
|---|---|---|
| Lua 5.4 плагины (mlua, vendored) | реализовано | `src/filters/plugins/lua.rs` |
| WASM плагины (wasmi) | реализовано | `src/filters/plugins/wasm.rs` |
| Горячая перезагрузка по mtime (без рестарта) | реализовано | `maybe_reload()` в `lua.rs` / `wasm.rs` |
| Загрузка из конфига (TOML `PluginsConfig` + DSL‑блок `plugins`) | реализовано | `src/config.rs`, `src/dsl/parser.rs`, `src/dsl/lower.rs` |
| Бюджет инструкций Lua (abort на runaway) | реализовано | `instruction_budget`, `set_hook` в `lua.rs` |
| Fuel‑metering WASM (10M на вызов) | реализовано | `config.consume_fuel(true)`, `store.set_fuel(...)` в `wasm.rs` |
| Песочница Lua (срезаны `io`/`os`/`package`/`require`/…) | реализовано | `new_state()` в `lua.rs` |
| Защита хоста от вредоносной длины буфера в WASM | реализовано | `MAX_GUEST_BUF_BYTES`, клампы в `wasm.rs` |
| Реестр/загрузка плагинов через admin‑панель или admin API | **НЕ реализовано** | плагинов нет ни в `/admin/api/*`, ни в React‑панели |
| Per‑plugin метрики/тоглы по имени | **частично/ограничено** | все Lua‑плагины делят имя `"lua_plugin"`, все WASM — `"wasm_plugin"` (см. §7) |
| WIT/Component Model, доступ к телу запроса, async/IO из плагина | **НЕ реализовано** (намеренно) | ABI минимален; тело не передаётся (см. §3, §8) |

Ключевой принцип честности: **«реестра» в смысле динамического каталога/маркетплейса/загрузки по HTTP нет.** «Реестр» здесь — это статический набор путей в конфиге, который `PluginManager`/`PluginSet` материализует при старте воркера и обновляет содержимое файлов по mtime. Управление через веб‑панель отсутствует.

---

## 2. Когда что выбирать: Lua vs WASM

Из docstring‑а `src/filters/plugins/mod.rs`:

- **Lua (`mlua`, `lua54`, `vendored`)** — для коротких логических скриптов: низкие накладные на вызов (~µs), тривиальная горячая перезагрузка, без шага компиляции.
- **WASM (`wasmi`)** — когда нужна настоящая изоляция памяти, фильтр CPU‑тяжёлый, или написан не на Lua (Rust, Go, AssemblyScript и т.д.).

Почему `wasmi`, а не `wasmtime` (комментарий в `wasm.rs`): чистый Rust, без LLVM/cranelift в дереве зависимостей, ~500 КБ в скомпилированном виде. Жертвуем частью пропускной в обмен на тонкий футпринт; проверка фильтра всё равно µs‑масштаба.

Обе разновидности реализуют один и тот же трейт `TrafficFilter` (`src/filters/mod.rs`) и встают в цепочку как `SharedFilter::Custom(Arc<dyn TrafficFilter>)` — то есть это «длинный хвост» с динамической диспетчеризацией (`dyn`), в отличие от встроенных фильтров, которые имеют свои enum‑варианты для статической диспетчеризации.

Зависимости (`Cargo.toml`):

```toml
mlua = { version = "0.10", features = ["lua54", "vendored", "send", "serialize"] }
wasmi = "0.40"
```

`vendored` означает, что Lua 5.4 компилируется из исходников в составе сборки (внешний `liblua` не требуется). `send` нужен, чтобы `Lua` можно было держать за `Mutex` в `Send + Sync` фильтре; `serialize` — для `LuaSerdeExt` (`lua.from_value::<PluginResponse>`).

---

## 3. Точка расширения: где плагин в фильтр‑цепочке

Плагины вставляются **после** встроенных WAF/bot/adaptive‑гейтов, но **до** challenge‑ladder и rate‑limit. Это даёт операторскому правилу «последнее слово» перед challenge. Порядок идентичен в обоих data plane (Hyper и Pingora):

- `src/server.rs` (Hyper, бинарь `aegis`) — строки ~225–255.
- `src/proxy/pingora_http.rs` (основной data plane, бинарь `aegis-pingora`) — строки ~162–178.

Фрагмент `src/server.rs`:

```rust
// User plugins run after the built-in WAF / bot / adaptive
// gates but before the challenge ladder — so an operator's
// custom rule can return Deny/Challenge with confidence that
// it's the last word before the request reaches challenge.
let plugin_set = crate::filters::plugins::manager::PluginSet::from_config(
    &cfg.filters.plugins,
);
for p in plugin_set.filters {
    filters.push(p);
}
filters.push(SharedFilter::Challenge(challenge.clone()));
```

Итоговый порядок цепочки (из комментария в `src/filters/engine.rs`): сначала дешёвые точные проверки (honeypot, threat‑intel, IP ACL), затем CPU‑тяжёлая работа (WAF, bot, adaptive), **затем плагины**, затем challenge‑ladder, и per‑host rate‑limit последним.

### Семантика короткого замыкания

`FilterEngine::evaluate_with_attribution` (`src/filters/engine.rs`) идёт по фильтрам по порядку; первый, кто вернул не‑`Allow`, завершает обход и его решение становится итоговым:

```rust
match filter.check(ctx) {
    FilterAction::Allow => continue,
    decision => return (decision, name),
}
```

Следствия для плагина:
- Если ваш плагин вернёт `deny`/`challenge`, нижестоящие фильтры (challenge‑ladder, rate‑limit) **не выполняются**.
- Если плагин вернул `allow`, обход продолжается дальше по цепочке.
- Несколько плагинов выполняются в порядке их объявления в конфиге (сперва все `lua` в порядке списка, затем все `wasm` — см. `PluginSet::from_config`).

### Что плагин видит: `PluginRequest`

Набор полей намеренно мал (`src/filters/plugins/mod.rs`, `PluginRequest`). Из комментария: «plugin trapdoor is for logic, not for parsing» — для разбора тел/глубокого матчинга предполагается WAF‑правило, а плагин получает уже подготовленный контекст.

| Поле | Тип | Источник (`request_context::RequestContext`) |
|---|---|---|
| `method` | string | `ctx.method.as_str()` |
| `path` | string | `ctx.path` |
| `host` | string | заголовок `host` (пустая строка, если нет) |
| `user_agent` | string | `ctx.user_agent` |
| `client_ip` | string | `ctx.client_ip` |
| `ja4` | string | `ctx.ja4` (TLS JA4) |
| `ja4h` | string | `ctx.ja4h()` (HTTP JA4H; ленивое вычисление) |
| `ja4t` | string | `ctx.ja4t` (TCP JA4T) |
| `ja4l` | string | `ctx.ja4l` |
| `h2fp` | string | HTTP/2 fingerprint |
| `h3fp` | string | HTTP/3 fingerprint |
| `mtls_fp` | string | fingerprint клиентского mTLS‑сертификата |
| `headers` | список `(name, value)` | все заголовки запроса, попавшие в `to_str()` |

Про фингерпринты подробнее — [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

**Тело запроса плагину не передаётся.** В структуре нет полей body/query‑params в распарсенном виде (только `path` целиком и заголовки). Это сознательное ограничение ABI.

> Оптимизация (комментарии V230 в коде): на горячем пути Lua строит таблицу прямо из `RequestContext` (`build_request_table`), а WASM сериализует `BorrowedRequest` в переиспользуемый scratch‑буфер — без материализации промежуточного `PluginRequest`. Публичная структура `PluginRequest` сохранена как описание wire‑формата и используется как опорная форма полей.

### Что плагин возвращает: `PluginResponse` → `FilterAction`

`PluginResponse` (`mod.rs`) и его маппинг в `FilterAction` (`into_action`):

| `action` | Поведение | Доп. поля |
|---|---|---|
| `"allow"` (по умолчанию) | пропустить, идти дальше по цепочке | — |
| `"deny"` | `FilterAction::Deny` | `status` (по умолчанию **403**), `reason` |
| `"challenge"` | `FilterAction::Challenge` | `level`, `reason` |
| любое другое | **лог‑варнинг + проваливается в `Allow`** | — |

Уровни challenge (`level`), маппинг в `ChallengeLevel`:

| `level` | `ChallengeLevel` |
|---|---|
| `"headers"` | Headers |
| `"html"` | Html |
| `"iframe"` | Iframe |
| `"captcha"` | Captcha |
| иное / отсутствует | **Javascript** (дефолт) |

Важно: неизвестный `action` **не блокирует** — «a misbehaving plugin never blocks the whole pipeline» (`into_action`). Если `reason` пуст, подставляется `"plugin <name> deny"` / `"plugin <name> challenge"`.

Плагин **не может** вернуть `Tarpit` — этот вариант `FilterAction` зарезервирован за honeypot‑фильтром (`src/filters/mod.rs`).

---

## 4. Lua‑плагины (mlua, lua54, vendored)

### Контракт скрипта

Файл должен определять глобальную функцию `aegis_check(req)`. Возврат:
- `nil` или `{action="allow"}` → пропустить;
- таблица с `action`/`reason`/`status`/`level` → соответствующее действие.

Пример из docstring `lua.rs`:

```lua
function aegis_check(req)
    if req.user_agent:find("evil-scraper") then
        return { action="deny", reason="blocked by ua-rule", status=403 }
    end
    if req.method == "POST" and req.path:find("/admin") then
        return { action="challenge", level="captcha" }
    end
    return { action="allow" }
end
```

`req` — таблица с полями из §3 (`method, path, host, user_agent, client_ip, ja4, ja4h, ja4t, ja4l, h2fp, h3fp, mtls_fp`) и `headers` — списком таблиц `{name, value}` (1‑индексированный).

Доступен один host‑хелпер: `aegis.log("…")` — пишет в tracing‑конвейер под target `aegis::plugin` (уровень `info`). Используйте для отладки; вывод попадёт в журналы воркера.

### Песочница Lua

Перед загрузкой пользовательского кода `new_state()` (`lua.rs`) выполняет пролог, срезающий опасные таблицы:

```lua
io = nil
os = { time = os.time, date = os.date }
package = nil
require = nil
loadfile = nil
dofile = nil
```

То есть из стандартной библиотеки убраны: файловый/процессный I/O (`io`), управление пакетами (`package`, `require`), загрузка кода с диска (`loadfile`, `dofile`). Из `os` оставлены только `time` и `date` — остальное (`os.execute`, `os.getenv`, `os.remove`, …) недоступно. Глобальные `string`, `table`, `math` и т.п. остаются.

> Оговорка по доверию: это **whitelist‑песочница на уровне Lua‑globals**, а не аппаратная изоляция памяти. Lua‑плагин исполняется в адресном пространстве воркера. Для жёсткой изоляции используйте WASM (§5). Считайте Lua‑скрипты доверенным операторским кодом, а не загрузкой от третьих лиц.

### Бюджет инструкций (защита от runaway)

У Lua нет нативного лимита инструкций, но `mlua` даёт hook каждые N инструкций. AEGIS вешает hook, который прерывает вызов ошибкой `"instruction budget exceeded"`:

```rust
if instruction_budget > 0 {
    let triggers = mlua::HookTriggers::new().every_nth_instruction(instruction_budget);
    lua.set_hook(triggers, |_lua, _debug| {
        Err(mlua::Error::RuntimeError("instruction budget exceeded".to_string()))
    });
}
```

Бюджет настраивается (`PluginsConfig.lua_instruction_budget`), **по умолчанию 100 000** (`default_lua_instruction_budget`). Значение `0` отключает hook. Ошибка времени выполнения (в т.ч. превышение бюджета или `error("...")` в скрипте) логируется и трактуется как `Allow` — fail‑open.

### Конкурентность и состояние

Каждый `LuaPlugin` держит свой `Lua` за `Mutex<LuaState>` (`lua.rs`). Значит, вызовы `aegis_check` **сериализуются** в рамках одного процесса‑воркера: одновременно исполняется не более одного вызова на плагин. Для CPU‑тяжёлой логики это узкое место — рассмотрите WASM (он тоже под `Mutex` на этапе подготовки запроса, но исполнение идёт в отдельном `Store`, создаваемом на вызов). Многопроцессность (SO_REUSEPORT, `aegis-pingora@0..N`) даёт параллелизм между воркерами; см. [06-workers.md](06-workers.md). Состояние Lua‑плагина **не разделяется** между воркерами.

### Горячая перезагрузка

`maybe_reload()` вызывается на каждом `check()`, но фактический `stat` файла дросселируется до раза в секунду (`LUA_RELOAD_INTERVAL_MICROS = 1_000_000`) — это сделано после профиля, где `statx` съедал заметную долю syscall‑времени на высоком RPS (комментарий V229). При изменившемся mtime скрипт перечитывается и пересобирается `Lua`‑состояние; при ошибке компиляции/загрузки нового файла **сохраняется предыдущая рабочая версия**, плагин помечается `failed` только если перезагрузка упала, а сам файл больше не перечитывается до следующего изменения mtime.

---

## 5. WASM‑плагины (wasmi)

### ABI модуля

ABI намеренно минимален (без WIT‑тулинга). Из docstring `wasm.rs`:

Модуль **импортирует**:
```
env.aegis_log(ptr: i32, len: i32) -> ()
```
Модуль **экспортирует**:
```
aegis_alloc(size: i32) -> i32
aegis_check(req_ptr: i32, req_len: i32) -> i64
memory            ; линейная память с именем "memory"
```

Протокол вызова:
1. Хост сериализует запрос в JSON (поля как в §3), вызывает `aegis_alloc(len)`, получает указатель и копирует JSON в линейную память гостя.
2. Хост вызывает `aegis_check(req_ptr, req_len)`.
3. Гость читает `req_len` UTF‑8 байт JSON по `req_ptr`, пишет ответ‑JSON в свою память и **возвращает `i64`**: указатель в старших 32 битах, длина — в младших 32 битах.
4. **Возврат `0` трактуется как `allow`** (хост не читает память).
5. Иначе хост читает JSON‑ответ и парсит его в `PluginResponse` (`serde_json::from_slice`).

`aegis_log(ptr, len)` доступен гостю для отладочного вывода — байты читаются из линейной памяти и пишутся в tracing под `aegis::plugin`.

### Изоляция и лимиты ресурсов

- **Память:** настоящая изоляция — гость работает только в своей линейной памяти; `Store` пересоздаётся **на каждый вызов** и уничтожается после, унося память гостя.
- **CPU (fuel):** `config.consume_fuel(true)` + `store.set_fuel(10_000_000)` — **10M единиц топлива на вызов** (комментарий: примерно ~10 мс потолок). При исчерпании топлива `aegis_check` «trap»‑ится; хост логирует и проваливается в `Allow`.
- **Защита хоста от враждебной длины буфера (V233):** длина, которую гость передаёт в `aegis_log` или возвращает из `aegis_check`, — это **неконтролируемый `i32`**; вредоносный/багнутый модуль может передать `i32::MAX` (~2 ГиБ) и спровоцировать host‑side `vec!` до того, как сработает bounds‑check `wasmi`. Под `panic = "abort"` это убило бы весь воркер. Поэтому длина клампится **до** аллокации:

```rust
const MAX_GUEST_BUF_BYTES: usize = 64 * 1024;
let n = (len.max(0) as usize)
    .min(MAX_GUEST_BUF_BYTES)
    .min(mem.data_size(&caller)); // не больше адресуемого гостём
```

То есть и `aegis_log`‑полезная нагрузка, и тело ответа `aegis_check` ограничены **64 КиБ** (и фактическим размером памяти гостя). Само чтение (`memory.read`) остаётся bounds‑checked. Есть регрессионный тест `hostile_log_length_does_not_crash_host` (`wasm.rs`), проверяющий, что length `0x7FFFFFFF` не роняет хост.

> Практический вывод: держите JSON‑ответ плагина в пределах 64 КиБ — иначе он будет усечён и парсинг JSON провалится (→ `Allow`).

### Что писать на чём

Любой язык, компилирующийся в чистый WASM с экспортом `memory` + двух функций и без неподдерживаемых импортов: Rust (`--target wasm32-unknown-unknown`), AssemblyScript, TinyGo, C/Zig и т.п. WIT/Component Model **не используется** — это «сырой» core WebAssembly ABI. Тесты в репозитории собирают модули из WAT прямо в рантайме (`wat::parse_str`), что показывает минимальную форму валидного модуля (`deny_all_wasm`, `allow_all_wasm` в `wasm.rs`).

### Конкурентность

`WasmState` (модуль + scratch‑буфер) живёт за `Mutex`. Сериализация запроса и клонирование `Module` происходят под мьютексом; затем мьютекс отпускается, и сам вызов идёт в собственном `Store` (комментарии V230). RAII‑guard `ScratchReturn` гарантированно возвращает scratch‑буфер обратно в state на любом пути выхода, чтобы переиспользовать аллокацию между вызовами.

---

## 6. «Реестр» и загрузка: конфигурация

«Реестр» плагинов — это списки путей в конфиге. Их материализует `PluginSet::from_config` (`src/filters/plugins/manager.rs`): для каждого Lua‑пути вызывается `LuaPlugin::load(path, lua_instruction_budget)`, для каждого WASM — `WasmPlugin::load(path)`. **Упавший при загрузке плагин логирует варнинг и пропускается** — один сломанный скрипт не валит прокси.

### Поля `PluginsConfig` (TOML)

`src/config.rs`, секция `[filters.plugins]`:

| Поле | Тип | По умолчанию | Назначение |
|---|---|---|---|
| `lua` | список строк (путей) | `[]` | пути к `.lua`‑файлам; каждый определяет `aegis_check(req)`; перезагрузка по mtime |
| `wasm` | список строк (путей) | `[]` | пути к `.wasm`‑модулям; экспорт `aegis_alloc`+`aegis_check`+`memory` |
| `lua_instruction_budget` | u32 | `100000` | бюджет инструкций на вызов Lua; hook прерывает превышение; `0` = выкл |

Пример TOML:

```toml
[filters.plugins]
lua = [
    "/etc/aegis/plugins/block-scrapers.lua",
    "/etc/aegis/plugins/admin-captcha.lua",
]
wasm = [
    "/etc/aegis/plugins/geo-fence.wasm",
]
lua_instruction_budget = 100000
```

> В поставляемых примерах (`config/aegis.example.conf`, `config/aegis.example.toml`) секция `plugins` отсутствует — это opt‑in возможность, по умолчанию ни одного плагина не загружается (`PluginsConfig::default()` даёт пустые списки).

### DSL‑форма (`aegis.conf`)

Конфиг‑DSL поддерживает вложенный блок `plugins` внутри `filters { ... }` (`src/dsl/parser.rs::parse_plugins_block`, `src/dsl/ast.rs::PluginsBlock`, маппинг в `src/dsl/lower.rs`):

```
filters {
    waf on;
    plugins {
        lua  "/etc/aegis/plugins/block-scrapers.lua";
        wasm "/etc/aegis/plugins/geo-fence.wasm";
    }
}
```

Допустимы только ключи `lua` и `wasm`; любой другой даёт ошибку парсинга `unknown plugin kind` (`parser.rs`). При понижении DSL в конфиг (`lower.rs`) пути копируются в `cfg.plugins.lua` / `cfg.plugins.wasm`. Обратите внимание: DSL‑блок **не** содержит `lua_instruction_budget` — там используется TOML‑дефолт (100k); чтобы задать иной бюджет, используйте TOML‑конфиг. Подробнее о форматах конфигурации — [04-configuration.md](04-configuration.md).

### Чего нет (честно)

- **Нет admin‑API маршрутов и страниц панели для плагинов.** В `/admin/api/*` и в React‑панели плагины не представлены (grep по `src/` и `web/` не находит управляющих маршрутов). Установить/удалить/перезалить плагин через UI нельзя.
- **Нет загрузки по URL/из сети, нет подписей/верификации артефактов, нет версионирования каталога.** Источник плагина — только локальный путь файловой системы.
- **Нет разделяемого состояния плагинов между воркерами.** Каждый воркер грузит свой экземпляр; синхронизация — только через идентичный файл на диске (mtime‑poll), как и у остальной cross‑worker модели AEGIS.

---

## 7. Имена, метрики и runtime‑тоглы

Из‑за того, что `TrafficFilter::name()` требует `&'static str`, а имя плагина — владеемая строка, **все Lua‑плагины возвращают имя `"lua_plugin"`, все WASM — `"wasm_plugin"`** (`lua.rs`/`wasm.rs`). Следствия:

- **Атрибуция по конкретному плагину** идёт через tracing‑поля (`plugin = %self.name`, где `name` = file stem), а не через метки метрик. В журналах вы увидите имя файла; в Prometheus‑метках — обобщённое `lua_plugin`/`wasm_plugin`.
- **Runtime‑тоглы и per‑domain overrides** (`RuntimeToggles` в `src/filters/engine.rs`) работают по имени фильтра. Поскольку все Lua‑плагины делят одно имя, тогл `lua_plugin` включает/выключает **сразу все** Lua‑плагины (аналогично `wasm_plugin`). Для `SharedFilter::Custom` `config_enabled()` всегда `true` (плагины ставятся оператором явно), но движок‑тогл и per‑domain override через `domain_policy` к ним применимы. См. [26-sites-and-domains.md](26-sites-and-domains.md) про per‑domain политику.

Целевой target логов плагинов: `aegis::plugin` (и для `aegis.log(...)`/`aegis_log`, и для служебных warn/info). Подробнее о телеметрии — [25-metrics-telemetry.md](25-metrics-telemetry.md).

---

## 8. Модель доверия — сводно

| Аспект | Lua | WASM |
|---|---|---|
| Изоляция памяти | нет (адресное пространство воркера) | да (линейная память гостя, `Store` на вызов) |
| Доступ к ФС/процессам/сети | срезан на уровне Lua‑globals (`io/os/package/...`) | нет (нет соответствующих импортов; только `aegis_log`) |
| Лимит CPU | hook по инструкциям (дефолт 100k), abort | fuel 10M/вызов, trap |
| Лимит памяти ответа/лога | n/a (Lua‑значения) | клампится до 64 КиБ (`MAX_GUEST_BUF_BYTES`) |
| Поведение при сбое | fail‑open → `Allow` (+warn) | fail‑open → `Allow` (+warn) |
| Доступ к телу запроса | нет | нет |
| Конкурентность вызовов | сериализованы (`Mutex`) | подготовка под `Mutex`, исполнение в своём `Store` |

**Рекомендация по доверию.** Рассматривайте оба типа плагинов как **доверенный операторский код**, поставляемый через контролируемый контрольный план (доступ на запись в каталог плагинов = эквивалент доступа к конфигу прокси). Lua даёт скорость и hot‑reload, но не изолирует память; WASM добавляет изоляцию памяти и жёсткий CPU‑бюджет ценой более тяжёлого тулинга сборки и минимального ABI. Ни тот, ни другой не предназначены для исполнения недоверенного кода от третьих лиц — нет sandbox‑эскейп‑аудита, подписей или per‑plugin привилегий. Общую модель угроз см. в [23-security-model.md](23-security-model.md).

---

## 9. Эксплуатация: типовые сценарии

### 9.1 Lua: блок по User‑Agent + challenge для админки

```lua
-- /etc/aegis/plugins/admin-guard.lua
function aegis_check(req)
    -- грубый бан по UA
    if req.user_agent:find("evil%-scraper") then
        return { action = "deny", reason = "ua block: evil-scraper", status = 403 }
    end
    -- captcha на чувствительные пути
    if req.path:sub(1, 7) == "/admin/" then
        return { action = "challenge", level = "captcha", reason = "admin area" }
    end
    return { action = "allow" }
end
```

### 9.2 Lua: решение по TLS‑фингерпринту JA4

```lua
function aegis_check(req)
    -- бан известного бот‑клиента по началу JA4
    if req.ja4 ~= "" and req.ja4:sub(1, 6) == "t13d59" then
        return { action = "challenge", level = "javascript", reason = "suspicious ja4" }
    end
    return { action = "allow" }
end
```

### 9.3 Lua: матчинг по заголовкам

```lua
function aegis_check(req)
    for _, h in ipairs(req.headers) do
        local name, value = h[1], h[2]
        if name:lower() == "x-internal-tool" and value == "1" then
            return { action = "deny", reason = "internal header from outside", status = 403 }
        end
    end
    return { action = "allow" }
end
```

### 9.4 WASM (Rust): минимальный allow‑модуль

Скелет на Rust под `wasm32-unknown-unknown`, реализующий ABI из §5:

```rust
// аллокатор: вернуть указатель на буфер размера size
static mut BUF: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn aegis_alloc(_size: i32) -> i32 {
    unsafe { BUF.as_mut_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn aegis_check(_req_ptr: i32, _req_len: i32) -> i64 {
    // 0 == allow; читать JSON из req_ptr/req_len при необходимости,
    // ответ писать в собственную память и вернуть (ptr << 32) | len.
    0
}
```

Для `deny`/`challenge` модуль должен записать JSON вида `{"action":"deny","status":418,"reason":"..."}` в линейную память и вернуть `((ptr as u64) << 32) | (len as u64)`. Канонический минимум см. в WAT‑фикстурах `deny_all_wasm`/`allow_all_wasm` в `src/filters/plugins/wasm.rs`.

### 9.5 Горячая перезагрузка

Просто перезапишите файл плагина (атомарно: запись во временный файл + `mv` поверх, чтобы mtime гарантированно сменился). В течение ~1 секунды каждый воркер заметит новый mtime, перечитает и применит новую версию без рестарта. Если новая версия не компилируется/не валидируется — воркер сохранит предыдущую рабочую и залогирует `... reload failed — keeping previous version`. Это согласуется с подходом AEGIS «панель/файл первичны, ручной `systemctl` не нужен» — см. [03-installation.md](03-installation.md).

---

## 10. Ограничения и тонкие места (резюме)

- Плагин не видит тело запроса и распарсенные query‑параметры — только метод, путь, host, UA, IP, набор фингерпринтов и заголовки (§3). Для тел используйте WAF/GraphQL‑лимиты ([10-waf.md](10-waf.md)).
- Плагин не может вернуть `Tarpit`; только `allow`/`deny`/`challenge` (§3).
- Все плагины одного типа делят имя для метрик/тоглов — атрибуция по файлу только в логах (§7).
- WASM‑ответ ограничен 64 КиБ; больше — усечётся и не распарсится → `Allow` (§5).
- Lua‑вызовы сериализованы на плагин; CPU‑тяжёлое лучше в WASM или вынести из плагина (§4).
- Реестра/загрузки через панель/сеть нет; источник — только локальный путь, управляемый через конфиг (§6).
- Состояние плагинов не разделяется между воркерами (§4, §6).
- Fail‑open во всех ошибочных ветках: упавший плагин **пропускает** трафик, а не блокирует. Если вам нужен fail‑closed для конкретного домена, ставьте `default_action = deny` на уровне движка и комбинируйте с явными `allow`‑правилами — но помните, что fall‑through плагина даёт `Allow` локально (короткого замыкания не происходит), и до `default_action` дойдёт обход только если ни один фильтр не вынес вердикт.

---

## 11. Где смотреть в коде

| Файл | Что содержит |
|---|---|
| `src/filters/plugins/mod.rs` | `PluginRequest`, `PluginResponse`, `into_action`, `request_from_ctx` (wire‑формат) |
| `src/filters/plugins/manager.rs` | `PluginSet::from_config` — материализация плагинов из конфига |
| `src/filters/plugins/lua.rs` | `LuaPlugin`: песочница, hook бюджета, hot‑reload, `build_request_table`, тесты |
| `src/filters/plugins/wasm.rs` | `WasmPlugin`: ABI, fuel, клампы буферов (V233), scratch‑буфер, тесты |
| `src/config.rs` | `PluginsConfig` (`lua`/`wasm`/`lua_instruction_budget`) |
| `src/filters/mod.rs` | `TrafficFilter`, `FilterAction`, `SharedFilter::Custom` |
| `src/filters/engine.rs` | порядок цепочки, короткое замыкание, `RuntimeToggles` |
| `src/server.rs`, `src/proxy/pingora_http.rs` | вставка плагинов в цепочку (после WAF/bot/adaptive, до challenge) |
| `src/dsl/parser.rs`, `src/dsl/ast.rs`, `src/dsl/lower.rs` | DSL‑блок `plugins { lua ...; wasm ...; }` |
| `Cargo.toml` | зависимости `mlua` (lua54/vendored/send/serialize), `wasmi` |
