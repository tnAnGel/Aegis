# Plugins: Lua/WASM, registry and trust model

**Languages:** **English** · [Русский](../ru/31-plugins.md) · [中文](../zh/31-plugins.md)

AEGIS lets operators embed their own decision logic into the filter chain as plugins: scripts in **Lua 5.4** (via `mlua`, vendored) and **WebAssembly** modules (via `wasmi`, a pure-Rust interpreter). Plugins are wired in as ordinary filters (`TrafficFilter`), hot-reload on file mtime, and cannot take the proxy down — a plugin that fails simply lets the request through (`Allow`). This document describes exactly how this works in the code, which extension points exist, what the trust/sandbox model is, and where functionality is deliberately limited.

> Grounding: everything described below corresponds to the code in `src/filters/plugins/` (`mod.rs`, `manager.rs`, `lua.rs`, `wasm.rs`), `src/config.rs` (`PluginsConfig`), `src/filters/mod.rs`/`src/filters/engine.rs` (the filter chain), `src/dsl/` (the `plugins` DSL block) and the dependencies in `Cargo.toml` (`mlua`, `wasmi`).

See also: security model — [23-security-model.md](23-security-model.md); WAF — [10-waf.md](10-waf.md); configuration — [04-configuration.md](04-configuration.md); rate limiting — [14-rate-limiting.md](14-rate-limiting.md); challenge ladder — [15-challenge-ladder.md](15-challenge-ladder.md); multi-process/workers — [06-workers.md](06-workers.md).

---

## 1. Overview and status

| Capability | Status | Where in the code |
|---|---|---|
| Lua 5.4 plugins (mlua, vendored) | implemented | `src/filters/plugins/lua.rs` |
| WASM plugins (wasmi) | implemented | `src/filters/plugins/wasm.rs` |
| Hot reload on mtime (no restart) | implemented | `maybe_reload()` in `lua.rs` / `wasm.rs` |
| Loading from config (TOML `PluginsConfig` + `plugins` DSL block) | implemented | `src/config.rs`, `src/dsl/parser.rs`, `src/dsl/lower.rs` |
| Lua instruction budget (abort on runaway) | implemented | `instruction_budget`, `set_hook` in `lua.rs` |
| WASM fuel metering (10M per call) | implemented | `config.consume_fuel(true)`, `store.set_fuel(...)` in `wasm.rs` |
| Lua sandbox (`io`/`os`/`package`/`require`/… stripped) | implemented | `new_state()` in `lua.rs` |
| Host protection against hostile buffer lengths in WASM | implemented | `MAX_GUEST_BUF_BYTES`, clamps in `wasm.rs` |
| Registry/plugin upload via the admin panel or admin API | **NOT implemented** | plugins appear neither in `/admin/api/*` nor in the React panel |
| Per-plugin metrics/toggles by name | **partial/limited** | all Lua plugins share the name `"lua_plugin"`, all WASM ones `"wasm_plugin"` (see §7) |
| WIT/Component Model, access to the request body, async/IO from a plugin | **NOT implemented** (deliberately) | the ABI is minimal; the body is not passed (see §3, §8) |

The key honesty principle: **there is no "registry" in the sense of a dynamic catalogue/marketplace/HTTP download.** "Registry" here means a static set of paths in the config, which `PluginManager`/`PluginSet` materialises at worker start-up and whose file contents it refreshes by mtime. There is no management via the web panel.

---

## 2. When to choose what: Lua vs WASM

From the docstring of `src/filters/plugins/mod.rs`:

- **Lua (`mlua`, `lua54`, `vendored`)** — for short logic scripts: low per-call overhead (~µs), trivial hot reload, no compilation step.
- **WASM (`wasmi`)** — when you need real memory isolation, when the filter is CPU-heavy, or when it is written in something other than Lua (Rust, Go, AssemblyScript, etc.).

Why `wasmi` and not `wasmtime` (comment in `wasm.rs`): pure Rust, no LLVM/cranelift in the dependency tree, ~500 KB compiled. We sacrifice some throughput in exchange for a thin footprint; a filter check is µs-scale anyway.

Both varieties implement the same `TrafficFilter` trait (`src/filters/mod.rs`) and enter the chain as `SharedFilter::Custom(Arc<dyn TrafficFilter>)` — that is, they are the "long tail" with dynamic dispatch (`dyn`), unlike the built-in filters, which have their own enum variants for static dispatch.

Dependencies (`Cargo.toml`):

```toml
mlua = { version = "0.10", features = ["lua54", "vendored", "send", "serialize"] }
wasmi = "0.40"
```

`vendored` means Lua 5.4 is compiled from source as part of the build (no external `liblua` required). `send` is needed so that `Lua` can be held behind a `Mutex` in a `Send + Sync` filter; `serialize` — for `LuaSerdeExt` (`lua.from_value::<PluginResponse>`).

---

## 3. Extension point: where the plugin sits in the filter chain

Plugins are inserted **after** the built-in WAF/bot/adaptive gates but **before** the challenge ladder and rate limit. This gives the operator's rule the "last word" before challenge. The order is identical in both data planes (Hyper and Pingora):

- `src/server.rs` (Hyper, the `aegis` binary) — lines ~225–255.
- `src/proxy/pingora_http.rs` (the main data plane, the `aegis-pingora` binary) — lines ~162–178.

Fragment from `src/server.rs`:

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

The resulting chain order (from the comment in `src/filters/engine.rs`): first the cheap exact checks (honeypot, threat intel, IP ACL), then the CPU-heavy work (WAF, bot, adaptive), **then plugins**, then the challenge ladder, and per-host rate limit last.

### Short-circuit semantics

`FilterEngine::evaluate_with_attribution` (`src/filters/engine.rs`) walks the filters in order; the first one to return something other than `Allow` ends the walk and its decision becomes final:

```rust
match filter.check(ctx) {
    FilterAction::Allow => continue,
    decision => return (decision, name),
}
```

Consequences for a plugin:
- If your plugin returns `deny`/`challenge`, the downstream filters (challenge ladder, rate limit) **are not executed**.
- If the plugin returns `allow`, the walk continues further down the chain.
- Multiple plugins run in their declaration order in the config (first all `lua` in list order, then all `wasm` — see `PluginSet::from_config`).

### What the plugin sees: `PluginRequest`

The field set is deliberately small (`src/filters/plugins/mod.rs`, `PluginRequest`). From the comment: "plugin trapdoor is for logic, not for parsing" — body parsing/deep matching is expected to be a WAF rule, whereas the plugin receives an already-prepared context.

| Field | Type | Source (`request_context::RequestContext`) |
|---|---|---|
| `method` | string | `ctx.method.as_str()` |
| `path` | string | `ctx.path` |
| `host` | string | the `host` header (empty string if absent) |
| `user_agent` | string | `ctx.user_agent` |
| `client_ip` | string | `ctx.client_ip` |
| `ja4` | string | `ctx.ja4` (TLS JA4) |
| `ja4h` | string | `ctx.ja4h()` (HTTP JA4H; computed lazily) |
| `ja4t` | string | `ctx.ja4t` (TCP JA4T) |
| `ja4l` | string | `ctx.ja4l` |
| `h2fp` | string | HTTP/2 fingerprint |
| `h3fp` | string | HTTP/3 fingerprint |
| `mtls_fp` | string | fingerprint of the client mTLS certificate |
| `headers` | list of `(name, value)` | all request headers that survived `to_str()` |

More about fingerprints — [11-tls-fingerprinting.md](11-tls-fingerprinting.md).

**The request body is not passed to the plugin.** The struct has no body/parsed query-param fields (only the whole `path` and the headers). This is a deliberate ABI limitation.

> Optimisation (V230 comments in the code): on the hot path Lua builds the table straight from `RequestContext` (`build_request_table`), while WASM serialises a `BorrowedRequest` into a reusable scratch buffer — without materialising an intermediate `PluginRequest`. The public `PluginRequest` struct is kept as a description of the wire format and is used as the reference shape of the fields.

### What the plugin returns: `PluginResponse` → `FilterAction`

`PluginResponse` (`mod.rs`) and its mapping to `FilterAction` (`into_action`):

| `action` | Behaviour | Extra fields |
|---|---|---|
| `"allow"` (default) | let through, continue down the chain | — |
| `"deny"` | `FilterAction::Deny` | `status` (default **403**), `reason` |
| `"challenge"` | `FilterAction::Challenge` | `level`, `reason` |
| anything else | **log warning + falls through to `Allow`** | — |

Challenge levels (`level`), mapped to `ChallengeLevel`:

| `level` | `ChallengeLevel` |
|---|---|
| `"headers"` | Headers |
| `"html"` | Html |
| `"iframe"` | Iframe |
| `"captcha"` | Captcha |
| anything else / absent | **Javascript** (default) |

Important: an unknown `action` **does not block** — "a misbehaving plugin never blocks the whole pipeline" (`into_action`). If `reason` is empty, `"plugin <name> deny"` / `"plugin <name> challenge"` is substituted.

A plugin **cannot** return `Tarpit` — that `FilterAction` variant is reserved for the honeypot filter (`src/filters/mod.rs`).

---

## 4. Lua plugins (mlua, lua54, vendored)

### Script contract

The file must define a global function `aegis_check(req)`. Return value:
- `nil` or `{action="allow"}` → let through;
- a table with `action`/`reason`/`status`/`level` → the corresponding action.

Example from the `lua.rs` docstring:

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

`req` is a table with the fields from §3 (`method, path, host, user_agent, client_ip, ja4, ja4h, ja4t, ja4l, h2fp, h3fp, mtls_fp`) plus `headers` — a list of `{name, value}` tables (1-indexed).

One host helper is available: `aegis.log("…")` — writes into the tracing pipeline under the target `aegis::plugin` (level `info`). Use it for debugging; the output lands in the worker logs.

### The Lua sandbox

Before loading user code, `new_state()` (`lua.rs`) runs a prologue that strips the dangerous tables:

```lua
io = nil
os = { time = os.time, date = os.date }
package = nil
require = nil
loadfile = nil
dofile = nil
```

That is, the following are removed from the standard library: file/process I/O (`io`), package management (`package`, `require`), loading code from disk (`loadfile`, `dofile`). Only `time` and `date` are left from `os` — everything else (`os.execute`, `os.getenv`, `os.remove`, …) is unavailable. The globals `string`, `table`, `math` and so on remain.

> Trust caveat: this is a **whitelist sandbox at the level of Lua globals**, not hardware memory isolation. A Lua plugin executes in the worker's address space. For hard isolation use WASM (§5). Treat Lua scripts as trusted operator code, not as third-party uploads.

### Instruction budget (runaway protection)

Lua has no native instruction limit, but `mlua` provides a hook every N instructions. AEGIS installs a hook that aborts the call with the error `"instruction budget exceeded"`:

```rust
if instruction_budget > 0 {
    let triggers = mlua::HookTriggers::new().every_nth_instruction(instruction_budget);
    lua.set_hook(triggers, |_lua, _debug| {
        Err(mlua::Error::RuntimeError("instruction budget exceeded".to_string()))
    });
}
```

The budget is configurable (`PluginsConfig.lua_instruction_budget`), **default 100,000** (`default_lua_instruction_budget`). A value of `0` disables the hook. A runtime error (including budget overrun or `error("...")` in the script) is logged and treated as `Allow` — fail-open.

### Concurrency and state

Each `LuaPlugin` holds its own `Lua` behind a `Mutex<LuaState>` (`lua.rs`). This means calls to `aegis_check` are **serialised** within a single worker process: at most one call per plugin executes at a time. For CPU-heavy logic this is a bottleneck — consider WASM (it too is behind a `Mutex` during request preparation, but execution happens in a separate `Store` created per call). Multi-process operation (SO_REUSEPORT, `aegis-pingora@0..N`) gives parallelism across workers; see [06-workers.md](06-workers.md). Lua plugin state is **not shared** between workers.

### Hot reload

`maybe_reload()` is called on every `check()`, but the actual `stat` of the file is throttled to once per second (`LUA_RELOAD_INTERVAL_MICROS = 1_000_000`) — this was done after profiling showed `statx` eating a noticeable share of syscall time at high RPS (comment V229). When the mtime changes, the script is re-read and the `Lua` state is rebuilt; if the new file fails to compile/load, **the previous working version is kept**, the plugin is marked `failed` only if the reload itself failed, and the file is not re-read again until the next mtime change.

---

## 5. WASM plugins (wasmi)

### Module ABI

The ABI is deliberately minimal (no WIT tooling). From the `wasm.rs` docstring:

The module **imports**:
```
env.aegis_log(ptr: i32, len: i32) -> ()
```
The module **exports**:
```
aegis_alloc(size: i32) -> i32
aegis_check(req_ptr: i32, req_len: i32) -> i64
memory            ; linear memory named "memory"
```

Call protocol:
1. The host serialises the request into JSON (fields as in §3), calls `aegis_alloc(len)`, gets a pointer and copies the JSON into the guest's linear memory.
2. The host calls `aegis_check(req_ptr, req_len)`.
3. The guest reads `req_len` UTF-8 bytes of JSON at `req_ptr`, writes a response JSON into its own memory and **returns an `i64`**: the pointer in the upper 32 bits, the length in the lower 32 bits.
4. **A return of `0` is treated as `allow`** (the host does not read memory).
5. Otherwise the host reads the JSON response and parses it into `PluginResponse` (`serde_json::from_slice`).

`aegis_log(ptr, len)` is available to the guest for debug output — the bytes are read from linear memory and written into tracing under `aegis::plugin`.

### Isolation and resource limits

- **Memory:** real isolation — the guest works only within its own linear memory; the `Store` is recreated **on every call** and destroyed afterwards, taking the guest memory with it.
- **CPU (fuel):** `config.consume_fuel(true)` + `store.set_fuel(10_000_000)` — **10M fuel units per call** (comment: roughly a ~10 ms ceiling). When fuel is exhausted, `aegis_check` traps; the host logs it and falls through to `Allow`.
- **Host protection against hostile buffer lengths (V233):** the length that the guest passes to `aegis_log` or returns from `aegis_check` is an **uncontrolled `i32`**; a malicious/buggy module could pass `i32::MAX` (~2 GiB) and provoke a host-side `vec!` before `wasmi`'s bounds check fires. Under `panic = "abort"` this would kill the whole worker. Therefore the length is clamped **before** allocation:

```rust
const MAX_GUEST_BUF_BYTES: usize = 64 * 1024;
let n = (len.max(0) as usize)
    .min(MAX_GUEST_BUF_BYTES)
    .min(mem.data_size(&caller)); // no more than the guest can address
```

That is, both the `aegis_log` payload and the `aegis_check` response body are limited to **64 KiB** (and to the guest's actual memory size). The read itself (`memory.read`) remains bounds-checked. There is a regression test `hostile_log_length_does_not_crash_host` (`wasm.rs`) verifying that a length of `0x7FFFFFFF` does not bring the host down.

> Practical takeaway: keep the plugin's JSON response within 64 KiB — otherwise it will be truncated and the JSON parse will fail (→ `Allow`).

### What to write it in

Any language that compiles to plain WASM exporting `memory` plus the two functions and without unsupported imports: Rust (`--target wasm32-unknown-unknown`), AssemblyScript, TinyGo, C/Zig and so on. WIT/Component Model is **not used** — this is "raw" core WebAssembly ABI. The tests in the repository build modules from WAT at runtime (`wat::parse_str`), which shows the minimal shape of a valid module (`deny_all_wasm`, `allow_all_wasm` in `wasm.rs`).

### Concurrency

`WasmState` (module + scratch buffer) lives behind a `Mutex`. Request serialisation and cloning of the `Module` happen under the mutex; then the mutex is released and the call itself runs in its own `Store` (V230 comments). The RAII guard `ScratchReturn` guarantees the scratch buffer is returned to the state on every exit path, so the allocation is reused between calls.

---

## 6. The "registry" and loading: configuration

The plugin "registry" is a set of path lists in the config. `PluginSet::from_config` (`src/filters/plugins/manager.rs`) materialises them: for each Lua path it calls `LuaPlugin::load(path, lua_instruction_budget)`, for each WASM one `WasmPlugin::load(path)`. **A plugin that fails to load logs a warning and is skipped** — one broken script does not take the proxy down.

### `PluginsConfig` fields (TOML)

`src/config.rs`, section `[filters.plugins]`:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `lua` | list of strings (paths) | `[]` | paths to `.lua` files; each defines `aegis_check(req)`; reloads on mtime |
| `wasm` | list of strings (paths) | `[]` | paths to `.wasm` modules; exporting `aegis_alloc`+`aegis_check`+`memory` |
| `lua_instruction_budget` | u32 | `100000` | instruction budget per Lua call; the hook aborts on overrun; `0` = off |

TOML example:

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

> In the shipped examples (`config/aegis.example.conf`, `config/aegis.example.toml`) the `plugins` section is absent — this is an opt-in capability, and by default no plugin is loaded (`PluginsConfig::default()` yields empty lists).

### DSL form (`aegis.conf`)

The config DSL supports a nested `plugins` block inside `filters { ... }` (`src/dsl/parser.rs::parse_plugins_block`, `src/dsl/ast.rs::PluginsBlock`, mapping in `src/dsl/lower.rs`):

```
filters {
    waf on;
    plugins {
        lua  "/etc/aegis/plugins/block-scrapers.lua";
        wasm "/etc/aegis/plugins/geo-fence.wasm";
    }
}
```

Only the keys `lua` and `wasm` are allowed; any other one produces the parse error `unknown plugin kind` (`parser.rs`). When lowering the DSL into the config (`lower.rs`) the paths are copied into `cfg.plugins.lua` / `cfg.plugins.wasm`. Note that the DSL block does **not** carry `lua_instruction_budget` — the TOML default (100k) is used there; to set a different budget, use the TOML config. More on configuration formats — [04-configuration.md](04-configuration.md).

### What is missing (honestly)

- **There are no admin API routes or panel pages for plugins.** Plugins are not represented in `/admin/api/*` or in the React panel (a grep over `src/` and `web/` finds no management routes). You cannot install/remove/re-upload a plugin through the UI.
- **There is no loading over URL/network, no signatures or artefact verification, no catalogue versioning.** The only plugin source is a local filesystem path.
- **There is no shared plugin state between workers.** Each worker loads its own instance; synchronisation happens only via an identical file on disk (mtime poll), as with the rest of the AEGIS cross-worker model.

---

## 7. Names, metrics and runtime toggles

Because `TrafficFilter::name()` requires a `&'static str` while a plugin's name is an owned string, **all Lua plugins return the name `"lua_plugin"` and all WASM ones `"wasm_plugin"`** (`lua.rs`/`wasm.rs`). Consequences:

- **Attribution to a specific plugin** goes through tracing fields (`plugin = %self.name`, where `name` = the file stem), not through metric labels. In the logs you will see the file name; in Prometheus labels — the generic `lua_plugin`/`wasm_plugin`.
- **Runtime toggles and per-domain overrides** (`RuntimeToggles` in `src/filters/engine.rs`) work by filter name. Since all Lua plugins share one name, the `lua_plugin` toggle enables/disables **all** Lua plugins at once (likewise for `wasm_plugin`). For `SharedFilter::Custom`, `config_enabled()` is always `true` (plugins are added explicitly by the operator), but the engine toggle and the per-domain override via `domain_policy` do apply to them. See [26-sites-and-domains.md](26-sites-and-domains.md) on per-domain policy.

The target for plugin logs: `aegis::plugin` (both for `aegis.log(...)`/`aegis_log` and for internal warn/info). More on telemetry — [25-metrics-telemetry.md](25-metrics-telemetry.md).

---

## 8. Trust model — summary

| Aspect | Lua | WASM |
|---|---|---|
| Memory isolation | no (worker address space) | yes (guest linear memory, `Store` per call) |
| Access to FS/processes/network | stripped at the level of Lua globals (`io/os/package/...`) | no (no corresponding imports; only `aegis_log`) |
| CPU limit | instruction hook (default 100k), abort | fuel 10M/call, trap |
| Response/log memory limit | n/a (Lua values) | clamped to 64 KiB (`MAX_GUEST_BUF_BYTES`) |
| Behaviour on failure | fail-open → `Allow` (+warn) | fail-open → `Allow` (+warn) |
| Access to the request body | no | no |
| Call concurrency | serialised (`Mutex`) | preparation under `Mutex`, execution in its own `Store` |

**Trust recommendation.** Treat both plugin types as **trusted operator code**, delivered through a controlled control plane (write access to the plugins directory = the equivalent of access to the proxy config). Lua gives speed and hot reload but does not isolate memory; WASM adds memory isolation and a hard CPU budget at the cost of heavier build tooling and a minimal ABI. Neither is intended for executing untrusted third-party code — there is no sandbox-escape audit, no signatures and no per-plugin privileges. For the overall threat model see [23-security-model.md](23-security-model.md).

---

## 9. Operations: typical scenarios

### 9.1 Lua: block by User-Agent + challenge for the admin area

```lua
-- /etc/aegis/plugins/admin-guard.lua
function aegis_check(req)
    -- crude ban by UA
    if req.user_agent:find("evil%-scraper") then
        return { action = "deny", reason = "ua block: evil-scraper", status = 403 }
    end
    -- captcha on sensitive paths
    if req.path:sub(1, 7) == "/admin/" then
        return { action = "challenge", level = "captcha", reason = "admin area" }
    end
    return { action = "allow" }
end
```

### 9.2 Lua: decision based on the JA4 TLS fingerprint

```lua
function aegis_check(req)
    -- ban a known bot client by its JA4 prefix
    if req.ja4 ~= "" and req.ja4:sub(1, 6) == "t13d59" then
        return { action = "challenge", level = "javascript", reason = "suspicious ja4" }
    end
    return { action = "allow" }
end
```

### 9.3 Lua: matching on headers

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

### 9.4 WASM (Rust): a minimal allow module

A Rust skeleton for `wasm32-unknown-unknown` implementing the ABI from §5:

```rust
// allocator: return a pointer to a buffer of size `size`
static mut BUF: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn aegis_alloc(_size: i32) -> i32 {
    unsafe { BUF.as_mut_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn aegis_check(_req_ptr: i32, _req_len: i32) -> i64 {
    // 0 == allow; read the JSON from req_ptr/req_len if needed,
    // write the response into your own memory and return (ptr << 32) | len.
    0
}
```

For `deny`/`challenge` the module must write JSON of the form `{"action":"deny","status":418,"reason":"..."}` into linear memory and return `((ptr as u64) << 32) | (len as u64)`. For the canonical minimum see the WAT fixtures `deny_all_wasm`/`allow_all_wasm` in `src/filters/plugins/wasm.rs`.

### 9.5 Hot reload

Simply overwrite the plugin file (atomically: write to a temporary file + `mv` over the top, so the mtime is guaranteed to change). Within ~1 second each worker will notice the new mtime, re-read it and apply the new version without a restart. If the new version does not compile/validate, the worker keeps the previous working one and logs `... reload failed — keeping previous version`. This is consistent with the AEGIS approach of "the panel/file is authoritative, manual `systemctl` is not needed" — see [03-installation.md](03-installation.md).

---

## 10. Limitations and sharp edges (summary)

- A plugin does not see the request body or the parsed query parameters — only the method, path, host, UA, IP, the set of fingerprints and the headers (§3). For bodies use WAF/GraphQL limits ([10-waf.md](10-waf.md)).
- A plugin cannot return `Tarpit`; only `allow`/`deny`/`challenge` (§3).
- All plugins of one type share a name for metrics/toggles — per-file attribution exists only in the logs (§7).
- A WASM response is limited to 64 KiB; anything larger is truncated and will not parse → `Allow` (§5).
- Lua calls are serialised per plugin; CPU-heavy work is better in WASM or outside the plugin altogether (§4).
- There is no registry/upload via the panel or the network; the only source is a local path managed through the config (§6).
- Plugin state is not shared between workers (§4, §6).
- Fail-open on every error branch: a plugin that fails **lets** traffic through rather than blocking it. If you need fail-closed for a specific domain, set `default_action = deny` at the engine level and combine it with explicit `allow` rules — but remember that a plugin fall-through gives `Allow` locally (no short circuit happens), and the walk only reaches `default_action` if no filter has issued a verdict.

---

## 11. Where to look in the code

| File | What it contains |
|---|---|
| `src/filters/plugins/mod.rs` | `PluginRequest`, `PluginResponse`, `into_action`, `request_from_ctx` (wire format) |
| `src/filters/plugins/manager.rs` | `PluginSet::from_config` — materialising plugins from the config |
| `src/filters/plugins/lua.rs` | `LuaPlugin`: sandbox, budget hook, hot reload, `build_request_table`, tests |
| `src/filters/plugins/wasm.rs` | `WasmPlugin`: ABI, fuel, buffer clamps (V233), scratch buffer, tests |
| `src/config.rs` | `PluginsConfig` (`lua`/`wasm`/`lua_instruction_budget`) |
| `src/filters/mod.rs` | `TrafficFilter`, `FilterAction`, `SharedFilter::Custom` |
| `src/filters/engine.rs` | chain order, short circuit, `RuntimeToggles` |
| `src/server.rs`, `src/proxy/pingora_http.rs` | inserting plugins into the chain (after WAF/bot/adaptive, before challenge) |
| `src/dsl/parser.rs`, `src/dsl/ast.rs`, `src/dsl/lower.rs` | the DSL block `plugins { lua ...; wasm ...; }` |
| `Cargo.toml` | dependencies `mlua` (lua54/vendored/send/serialize), `wasmi` |
