# 插件：Lua/WASM、注册表与信任模型

**语言：** [English](../en/31-plugins.md) · [Русский](../ru/31-plugins.md) · **中文**

AEGIS 允许运维人员以插件的形式，把自己的决策逻辑嵌入过滤器链：**Lua 5.4** 脚本（通过 `mlua`，vendored 方式）和 **WebAssembly** 模块（通过 `wasmi`，纯 Rust 解释器）。插件作为普通过滤器（`TrafficFilter`）接入，按文件 mtime 热重载，并且不会拖垮代理——出错的插件只会放行请求（`Allow`）。本文档说明这一切在代码中究竟如何工作、有哪些扩展点、信任/沙箱模型是什么样的，以及哪些功能是被刻意限制的。

> 依据：以下所有内容都对应于 `src/filters/plugins/` 中的代码（`mod.rs`、`manager.rs`、`lua.rs`、`wasm.rs`）、`src/config.rs`（`PluginsConfig`）、`src/filters/mod.rs`/`src/filters/engine.rs`（过滤器链）、`src/dsl/`（DSL 的 `plugins` 块）以及 `Cargo.toml` 中的依赖（`mlua`、`wasmi`）。

另请参阅：安全模型 — [23-security-model.md](23-security-model.md)；WAF — [10-waf.md](10-waf.md)；配置 — [04-configuration.md](04-configuration.md)；限流 — [14-rate-limiting.md](14-rate-limiting.md)；challenge 阶梯 — [15-challenge-ladder.md](15-challenge-ladder.md)；多进程/工作进程 — [06-workers.md](06-workers.md)。

---

## 1. 概览与状态

| 能力 | 状态 | 代码位置 |
|---|---|---|
| Lua 5.4 插件（mlua，vendored） | 已实现 | `src/filters/plugins/lua.rs` |
| WASM 插件（wasmi） | 已实现 | `src/filters/plugins/wasm.rs` |
| 按 mtime 热重载（无需重启） | 已实现 | `lua.rs` / `wasm.rs` 中的 `maybe_reload()` |
| 从配置加载（TOML `PluginsConfig` + DSL 的 `plugins` 块） | 已实现 | `src/config.rs`、`src/dsl/parser.rs`、`src/dsl/lower.rs` |
| Lua 指令预算（失控时中止） | 已实现 | `lua.rs` 中的 `instruction_budget`、`set_hook` |
| WASM 燃料计量（每次调用 10M） | 已实现 | `wasm.rs` 中的 `config.consume_fuel(true)`、`store.set_fuel(...)` |
| Lua 沙箱（剥离 `io`/`os`/`package`/`require`/…） | 已实现 | `lua.rs` 中的 `new_state()` |
| 保护宿主免受 WASM 中恶意缓冲区长度攻击 | 已实现 | `wasm.rs` 中的 `MAX_GUEST_BUF_BYTES` 与钳制 |
| 通过管理面板或 admin API 管理注册表/上传插件 | **未实现** | 插件既不在 `/admin/api/*` 中，也不在 React 面板中 |
| 按名称区分的单插件指标/开关 | **部分实现/受限** | 所有 Lua 插件共用名称 `"lua_plugin"`，所有 WASM 插件共用 `"wasm_plugin"`（见 §7） |
| WIT/组件模型、访问请求体、插件内 async/IO | **未实现**（刻意如此） | ABI 极简；不传递请求体（见 §3、§8） |

关键的诚实原则：**不存在动态目录/市场/通过 HTTP 下载意义上的「注册表」。** 这里的「注册表」指的是配置中的一组静态路径，`PluginManager`/`PluginSet` 在工作进程启动时将其物化，并按 mtime 更新文件内容。没有通过 Web 面板的管理功能。

---

## 2. 何时选用哪种：Lua vs WASM

摘自 `src/filters/plugins/mod.rs` 的 docstring：

- **Lua（`mlua`、`lua54`、`vendored`）** — 适合简短的逻辑脚本：调用开销低（~µs）、热重载极其简单、无需编译步骤。
- **WASM（`wasmi`）** — 当你需要真正的内存隔离、过滤器是 CPU 密集型，或者它不是用 Lua 编写的（Rust、Go、AssemblyScript 等）时。

为什么用 `wasmi` 而不是 `wasmtime`（`wasm.rs` 中的注释）：纯 Rust，依赖树中没有 LLVM/cranelift，编译后约 500 KB。我们牺牲了一部分吞吐量，换来纤薄的体积；反正过滤器检查本身也是 µs 量级。

两种形态都实现同一个 `TrafficFilter` trait（`src/filters/mod.rs`），并以 `SharedFilter::Custom(Arc<dyn TrafficFilter>)` 的形式进入过滤器链——也就是说，它们属于采用动态分发（`dyn`）的「长尾」，不同于内置过滤器：后者拥有各自的 enum 变体以便静态分发。

依赖（`Cargo.toml`）：

```toml
mlua = { version = "0.10", features = ["lua54", "vendored", "send", "serialize"] }
wasmi = "0.40"
```

`vendored` 意味着 Lua 5.4 作为构建的一部分从源码编译（不需要外部 `liblua`）。`send` 是为了让 `Lua` 能在 `Send + Sync` 的过滤器中被 `Mutex` 持有；`serialize` 用于 `LuaSerdeExt`（`lua.from_value::<PluginResponse>`）。

---

## 3. 扩展点：插件在过滤器链中的位置

插件插入在内置 WAF/bot/adaptive 闸门**之后**，但在 challenge 阶梯与限流**之前**。这让运维人员的规则在 challenge 之前拥有「最终发言权」。两个数据平面（Hyper 与 Pingora）中的顺序完全一致：

- `src/server.rs`（Hyper，`aegis` 二进制）— 约第 225–255 行。
- `src/proxy/pingora_http.rs`（主数据平面，`aegis-pingora` 二进制）— 约第 162–178 行。

`src/server.rs` 片段：

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

最终的链顺序（来自 `src/filters/engine.rs` 中的注释）：先是廉价的精确检查（honeypot、威胁情报、IP ACL），然后是 CPU 密集的工作（WAF、bot、adaptive），**接着是插件**，然后是 challenge 阶梯，最后是 per-host 限流。

### 短路语义

`FilterEngine::evaluate_with_attribution`（`src/filters/engine.rs`）按顺序遍历过滤器；第一个返回非 `Allow` 的过滤器会终止遍历，其决策即为最终结果：

```rust
match filter.check(ctx) {
    FilterAction::Allow => continue,
    decision => return (decision, name),
}
```

对插件的影响：
- 如果你的插件返回 `deny`/`challenge`，下游过滤器（challenge 阶梯、限流）**不会执行**。
- 如果插件返回 `allow`，遍历会沿链继续。
- 多个插件按其在配置中声明的顺序执行（先按列表顺序执行所有 `lua`，然后是所有 `wasm` — 见 `PluginSet::from_config`）。

### 插件能看到什么：`PluginRequest`

字段集刻意保持很小（`src/filters/plugins/mod.rs`，`PluginRequest`）。注释中说：「plugin trapdoor is for logic, not for parsing」——请求体解析/深度匹配应交给 WAF 规则，而插件拿到的是已经准备好的上下文。

| 字段 | 类型 | 来源（`request_context::RequestContext`） |
|---|---|---|
| `method` | string | `ctx.method.as_str()` |
| `path` | string | `ctx.path` |
| `host` | string | `host` 头（不存在时为空字符串） |
| `user_agent` | string | `ctx.user_agent` |
| `client_ip` | string | `ctx.client_ip` |
| `ja4` | string | `ctx.ja4`（TLS JA4） |
| `ja4h` | string | `ctx.ja4h()`（HTTP JA4H；惰性计算） |
| `ja4t` | string | `ctx.ja4t`（TCP JA4T） |
| `ja4l` | string | `ctx.ja4l` |
| `h2fp` | string | HTTP/2 指纹 |
| `h3fp` | string | HTTP/3 指纹 |
| `mtls_fp` | string | 客户端 mTLS 证书的指纹 |
| `headers` | `(name, value)` 列表 | 所有能通过 `to_str()` 的请求头 |

关于指纹的更多内容 — [11-tls-fingerprinting.md](11-tls-fingerprinting.md)。

**请求体不会传给插件。** 结构体中没有 body/解析后 query 参数的字段（只有完整的 `path` 和请求头）。这是刻意的 ABI 限制。

> 优化（代码中的 V230 注释）：在热路径上，Lua 直接从 `RequestContext` 构建表（`build_request_table`），而 WASM 把 `BorrowedRequest` 序列化到可复用的 scratch 缓冲区——不会物化中间的 `PluginRequest`。公开的 `PluginRequest` 结构体被保留下来作为 wire 格式的描述，并用作字段形态的参考。

### 插件返回什么：`PluginResponse` → `FilterAction`

`PluginResponse`（`mod.rs`）及其到 `FilterAction` 的映射（`into_action`）：

| `action` | 行为 | 附加字段 |
|---|---|---|
| `"allow"`（默认） | 放行，沿链继续 | — |
| `"deny"` | `FilterAction::Deny` | `status`（默认 **403**）、`reason` |
| `"challenge"` | `FilterAction::Challenge` | `level`、`reason` |
| 其他任意值 | **记录告警日志 + 回退为 `Allow`** | — |

challenge 等级（`level`）到 `ChallengeLevel` 的映射：

| `level` | `ChallengeLevel` |
|---|---|
| `"headers"` | Headers |
| `"html"` | Html |
| `"iframe"` | Iframe |
| `"captcha"` | Captcha |
| 其他 / 缺失 | **Javascript**（默认） |

重要：未知的 `action` **不会拦截**——「a misbehaving plugin never blocks the whole pipeline」（`into_action`）。如果 `reason` 为空，则填入 `"plugin <name> deny"` / `"plugin <name> challenge"`。

插件**不能**返回 `Tarpit`——该 `FilterAction` 变体保留给 honeypot 过滤器（`src/filters/mod.rs`）。

---

## 4. Lua 插件（mlua、lua54、vendored）

### 脚本契约

文件必须定义全局函数 `aegis_check(req)`。返回值：
- `nil` 或 `{action="allow"}` → 放行；
- 带 `action`/`reason`/`status`/`level` 的表 → 对应的动作。

摘自 `lua.rs` docstring 的示例：

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

`req` 是一个表，包含 §3 中的字段（`method, path, host, user_agent, client_ip, ja4, ja4h, ja4t, ja4l, h2fp, h3fp, mtls_fp`），以及 `headers`——由 `{name, value}` 表组成的列表（从 1 开始索引）。

提供一个宿主辅助函数：`aegis.log("…")` — 以 target `aegis::plugin`（级别 `info`）写入 tracing 管道。可用于调试；输出会进入工作进程的日志。

### Lua 沙箱

在加载用户代码之前，`new_state()`（`lua.rs`）会执行一段前导代码，剥离危险的表：

```lua
io = nil
os = { time = os.time, date = os.date }
package = nil
require = nil
loadfile = nil
dofile = nil
```

也就是说，标准库中被移除的有：文件/进程 I/O（`io`）、包管理（`package`、`require`）、从磁盘加载代码（`loadfile`、`dofile`）。`os` 中只保留了 `time` 和 `date`——其余（`os.execute`、`os.getenv`、`os.remove`、…）不可用。全局的 `string`、`table`、`math` 等仍然保留。

> 关于信任的说明：这是**在 Lua 全局变量层面的白名单沙箱**，而不是硬件级的内存隔离。Lua 插件在工作进程的地址空间内执行。若需要严格隔离，请使用 WASM（§5）。请把 Lua 脚本视为可信的运维代码，而不是第三方上传的内容。

### 指令预算（防止失控）

Lua 没有原生的指令上限，但 `mlua` 提供了每 N 条指令触发一次的 hook。AEGIS 挂载了一个 hook，会以错误 `"instruction budget exceeded"` 中断调用：

```rust
if instruction_budget > 0 {
    let triggers = mlua::HookTriggers::new().every_nth_instruction(instruction_budget);
    lua.set_hook(triggers, |_lua, _debug| {
        Err(mlua::Error::RuntimeError("instruction budget exceeded".to_string()))
    });
}
```

预算可配置（`PluginsConfig.lua_instruction_budget`），**默认 100 000**（`default_lua_instruction_budget`）。值为 `0` 时禁用 hook。运行时错误（包括超出预算或脚本中的 `error("...")`）会被记录并按 `Allow` 处理——fail-open。

### 并发与状态

每个 `LuaPlugin` 都把自己的 `Lua` 放在 `Mutex<LuaState>` 之后（`lua.rs`）。这意味着在单个工作进程内，对 `aegis_check` 的调用是**串行化**的：同一插件同时最多执行一次调用。对 CPU 密集型逻辑而言这是瓶颈——可考虑 WASM（它在请求准备阶段同样处于 `Mutex` 之下，但执行发生在每次调用新建的独立 `Store` 中）。多进程（SO_REUSEPORT，`aegis-pingora@0..N`）提供了工作进程之间的并行；见 [06-workers.md](06-workers.md)。Lua 插件的状态**不会**在工作进程之间共享。

### 热重载

`maybe_reload()` 在每次 `check()` 时都会被调用，但对文件的实际 `stat` 被限流到每秒一次（`LUA_RELOAD_INTERVAL_MICROS = 1_000_000`）——这是在性能剖析发现高 RPS 下 `statx` 吃掉了可观的系统调用时间之后所做的调整（注释 V229）。当 mtime 发生变化时，脚本会被重新读取并重建 `Lua` 状态；如果新文件编译/加载失败，则**保留先前可用的版本**，只有当重载失败时插件才会被标记为 `failed`，而该文件在下一次 mtime 变化之前不会再被重新读取。

---

## 5. WASM 插件（wasmi）

### 模块 ABI

ABI 刻意保持极简（不使用 WIT 工具链）。摘自 `wasm.rs` 的 docstring：

模块**导入**：
```
env.aegis_log(ptr: i32, len: i32) -> ()
```
模块**导出**：
```
aegis_alloc(size: i32) -> i32
aegis_check(req_ptr: i32, req_len: i32) -> i64
memory            ; 名为 "memory" 的线性内存
```

调用协议：
1. 宿主把请求序列化为 JSON（字段同 §3），调用 `aegis_alloc(len)` 取得指针，并把 JSON 复制到 guest 的线性内存中。
2. 宿主调用 `aegis_check(req_ptr, req_len)`。
3. Guest 从 `req_ptr` 读取 `req_len` 字节的 UTF-8 JSON，把响应 JSON 写入自己的内存，并**返回一个 `i64`**：高 32 位为指针，低 32 位为长度。
4. **返回 `0` 被视为 `allow`**（宿主不会读取内存）。
5. 否则宿主读取 JSON 响应并将其解析为 `PluginResponse`（`serde_json::from_slice`）。

`aegis_log(ptr, len)` 供 guest 输出调试信息——字节从线性内存读取，并以 `aegis::plugin` 写入 tracing。

### 隔离与资源限制

- **内存：** 真正的隔离——guest 只在自己的线性内存中工作；`Store` **在每次调用时**重建，调用结束后销毁，同时带走 guest 的内存。
- **CPU（燃料）：** `config.consume_fuel(true)` + `store.set_fuel(10_000_000)` — **每次调用 10M 燃料单位**（注释：大致相当于 ~10 ms 的上限）。燃料耗尽时 `aegis_check` 会「trap」；宿主记录日志并回退为 `Allow`。
- **保护宿主免受恶意缓冲区长度攻击（V233）：** guest 传给 `aegis_log` 或从 `aegis_check` 返回的长度是**不受控的 `i32`**；恶意/有 bug 的模块可以传入 `i32::MAX`（~2 GiB），在 `wasmi` 的边界检查生效之前就触发宿主侧的 `vec!`。在 `panic = "abort"` 下这会杀死整个工作进程。因此长度会在分配**之前**被钳制：

```rust
const MAX_GUEST_BUF_BYTES: usize = 64 * 1024;
let n = (len.max(0) as usize)
    .min(MAX_GUEST_BUF_BYTES)
    .min(mem.data_size(&caller)); // 不超过 guest 可寻址的范围
```

也就是说，`aegis_log` 的负载和 `aegis_check` 的响应体都被限制在 **64 KiB**（以及 guest 内存的实际大小）以内。读取本身（`memory.read`）仍然是有边界检查的。仓库中有回归测试 `hostile_log_length_does_not_crash_host`（`wasm.rs`），用于验证长度 `0x7FFFFFFF` 不会拖垮宿主。

> 实践结论：把插件的 JSON 响应控制在 64 KiB 以内——否则它会被截断，JSON 解析随之失败（→ `Allow`）。

### 用什么写

任何能编译成纯 WASM、导出 `memory` 和两个函数、且不含不受支持导入的语言：Rust（`--target wasm32-unknown-unknown`）、AssemblyScript、TinyGo、C/Zig 等等。**不使用** WIT/组件模型——这是「裸」的 core WebAssembly ABI。仓库中的测试直接在运行时从 WAT 构建模块（`wat::parse_str`），展示了一个有效模块的最小形态（`wasm.rs` 中的 `deny_all_wasm`、`allow_all_wasm`）。

### 并发

`WasmState`（模块 + scratch 缓冲区）位于 `Mutex` 之后。请求的序列化和 `Module` 的克隆在互斥锁下进行；随后释放互斥锁，调用本身在自己的 `Store` 中执行（V230 注释）。RAII guard `ScratchReturn` 保证在任何退出路径上都把 scratch 缓冲区归还给 state，以便在多次调用之间复用该内存分配。

---

## 6. 「注册表」与加载：配置

插件「注册表」就是配置中的路径列表。`PluginSet::from_config`（`src/filters/plugins/manager.rs`）负责物化它们：对每个 Lua 路径调用 `LuaPlugin::load(path, lua_instruction_budget)`，对每个 WASM 路径调用 `WasmPlugin::load(path)`。**加载失败的插件会记录告警并被跳过**——一个损坏的脚本不会拖垮代理。

### `PluginsConfig` 字段（TOML）

`src/config.rs`，`[filters.plugins]` 小节：

| 字段 | 类型 | 默认值 | 用途 |
|---|---|---|---|
| `lua` | 字符串（路径）列表 | `[]` | `.lua` 文件的路径；每个都定义 `aegis_check(req)`；按 mtime 重载 |
| `wasm` | 字符串（路径）列表 | `[]` | `.wasm` 模块的路径；导出 `aegis_alloc`+`aegis_check`+`memory` |
| `lua_instruction_budget` | u32 | `100000` | 每次 Lua 调用的指令预算；超出时 hook 会中断；`0` = 关闭 |

TOML 示例：

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

> 在随附的示例中（`config/aegis.example.conf`、`config/aegis.example.toml`）没有 `plugins` 小节——这是一项可选启用（opt-in）的能力，默认不加载任何插件（`PluginsConfig::default()` 返回空列表）。

### DSL 形式（`aegis.conf`）

配置 DSL 支持在 `filters { ... }` 内嵌套 `plugins` 块（`src/dsl/parser.rs::parse_plugins_block`、`src/dsl/ast.rs::PluginsBlock`，映射见 `src/dsl/lower.rs`）：

```
filters {
    waf on;
    plugins {
        lua  "/etc/aegis/plugins/block-scrapers.lua";
        wasm "/etc/aegis/plugins/geo-fence.wasm";
    }
}
```

只允许 `lua` 和 `wasm` 两个键；其他任何键都会产生解析错误 `unknown plugin kind`（`parser.rs`）。在把 DSL 下降为配置时（`lower.rs`），路径会被复制到 `cfg.plugins.lua` / `cfg.plugins.wasm`。请注意：DSL 块中**不**包含 `lua_instruction_budget`——那里使用 TOML 的默认值（100k）；若要设置不同的预算，请使用 TOML 配置。关于配置格式的更多内容 — [04-configuration.md](04-configuration.md)。

### 缺少什么（如实说明）

- **没有面向插件的 admin API 路由和面板页面。** 插件在 `/admin/api/*` 和 React 面板中都没有体现（对 `src/` 和 `web/` 的 grep 找不到任何管理路由）。无法通过 UI 安装/删除/重新上传插件。
- **没有通过 URL/网络加载，没有签名或制品校验，没有目录版本管理。** 插件的来源只有本地文件系统路径。
- **插件状态不在工作进程之间共享。** 每个工作进程加载自己的实例；同步仅通过磁盘上完全相同的文件（mtime 轮询）实现，这与 AEGIS 其余的跨工作进程模型一致。

---

## 7. 名称、指标与运行时开关

由于 `TrafficFilter::name()` 要求 `&'static str`，而插件名称是拥有所有权的字符串，因此**所有 Lua 插件都返回名称 `"lua_plugin"`，所有 WASM 插件都返回 `"wasm_plugin"`**（`lua.rs`/`wasm.rs`）。由此带来：

- **对具体插件的归因**通过 tracing 字段实现（`plugin = %self.name`，其中 `name` = 文件主名），而不是通过指标标签。在日志中你会看到文件名；在 Prometheus 标签中则是笼统的 `lua_plugin`/`wasm_plugin`。
- **运行时开关与 per-domain 覆盖**（`src/filters/engine.rs` 中的 `RuntimeToggles`）按过滤器名称工作。由于所有 Lua 插件共用一个名称，`lua_plugin` 开关会**一次性**启用/禁用所有 Lua 插件（`wasm_plugin` 同理）。对于 `SharedFilter::Custom`，`config_enabled()` 始终为 `true`（插件由运维人员显式添加），但引擎开关和通过 `domain_policy` 的 per-domain 覆盖对它们仍然适用。关于 per-domain 策略见 [26-sites-and-domains.md](26-sites-and-domains.md)。

插件日志的目标 target：`aegis::plugin`（既用于 `aegis.log(...)`/`aegis_log`，也用于内部的 warn/info）。关于遥测的更多内容 — [25-metrics-telemetry.md](25-metrics-telemetry.md)。

---

## 8. 信任模型 — 汇总

| 方面 | Lua | WASM |
|---|---|---|
| 内存隔离 | 无（工作进程的地址空间） | 有（guest 线性内存，每次调用一个 `Store`） |
| 访问文件系统/进程/网络 | 在 Lua 全局变量层面被剥离（`io/os/package/...`） | 无（没有相应的导入；只有 `aegis_log`） |
| CPU 上限 | 按指令的 hook（默认 100k），中止 | 每次调用 10M 燃料，trap |
| 响应/日志的内存上限 | n/a（Lua 值） | 钳制到 64 KiB（`MAX_GUEST_BUF_BYTES`） |
| 出错时的行为 | fail-open → `Allow`（+warn） | fail-open → `Allow`（+warn） |
| 访问请求体 | 无 | 无 |
| 调用并发 | 串行化（`Mutex`） | 准备阶段在 `Mutex` 下，执行在各自的 `Store` 中 |

**关于信任的建议。** 请把两类插件都视为**可信的运维代码**，通过受控的控制平面交付（对插件目录的写权限 = 等同于对代理配置的访问权限）。Lua 提供速度和热重载，但不隔离内存；WASM 增加了内存隔离和严格的 CPU 预算，代价是更重的构建工具链和极简的 ABI。两者都不适合执行来自第三方的不可信代码——没有沙箱逃逸审计、没有签名、没有 per-plugin 权限。整体威胁模型见 [23-security-model.md](23-security-model.md)。

---

## 9. 运维：典型场景

### 9.1 Lua：按 User-Agent 拦截 + 对后台做 challenge

```lua
-- /etc/aegis/plugins/admin-guard.lua
function aegis_check(req)
    -- 按 UA 粗暴封禁
    if req.user_agent:find("evil%-scraper") then
        return { action = "deny", reason = "ua block: evil-scraper", status = 403 }
    end
    -- 对敏感路径出 captcha
    if req.path:sub(1, 7) == "/admin/" then
        return { action = "challenge", level = "captcha", reason = "admin area" }
    end
    return { action = "allow" }
end
```

### 9.2 Lua：基于 JA4 TLS 指纹的决策

```lua
function aegis_check(req)
    -- 按 JA4 前缀封禁已知的 bot 客户端
    if req.ja4 ~= "" and req.ja4:sub(1, 6) == "t13d59" then
        return { action = "challenge", level = "javascript", reason = "suspicious ja4" }
    end
    return { action = "allow" }
end
```

### 9.3 Lua：按请求头匹配

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

### 9.4 WASM（Rust）：最小的 allow 模块

面向 `wasm32-unknown-unknown` 的 Rust 骨架，实现 §5 中的 ABI：

```rust
// 分配器：返回指向大小为 size 的缓冲区的指针
static mut BUF: [u8; 65536] = [0; 65536];

#[no_mangle]
pub extern "C" fn aegis_alloc(_size: i32) -> i32 {
    unsafe { BUF.as_mut_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn aegis_check(_req_ptr: i32, _req_len: i32) -> i64 {
    // 0 == allow；如有需要，从 req_ptr/req_len 读取 JSON，
    // 把响应写入自己的内存并返回 (ptr << 32) | len。
    0
}
```

对于 `deny`/`challenge`，模块必须把形如 `{"action":"deny","status":418,"reason":"..."}` 的 JSON 写入线性内存，并返回 `((ptr as u64) << 32) | (len as u64)`。规范的最小示例见 `src/filters/plugins/wasm.rs` 中的 WAT 夹具 `deny_all_wasm`/`allow_all_wasm`。

### 9.5 热重载

只需覆盖写入插件文件即可（原子地：写入临时文件 + `mv` 覆盖，以确保 mtime 一定发生变化）。约 1 秒内，每个工作进程都会注意到新的 mtime，重新读取并应用新版本，无需重启。如果新版本无法编译/校验不通过，工作进程会保留先前可用的版本并记录 `... reload failed — keeping previous version`。这与 AEGIS「以面板/文件为准，无需手动 `systemctl`」的思路一致 — 见 [03-installation.md](03-installation.md)。

---

## 10. 限制与注意事项（小结）

- 插件看不到请求体和解析后的 query 参数——只有方法、路径、host、UA、IP、一组指纹和请求头（§3）。对于请求体，请使用 WAF/GraphQL 限制（[10-waf.md](10-waf.md)）。
- 插件不能返回 `Tarpit`；只能是 `allow`/`deny`/`challenge`（§3）。
- 同一类型的所有插件在指标/开关上共用一个名称——按文件的归因只存在于日志中（§7）。
- WASM 响应被限制在 64 KiB；超出部分会被截断且无法解析 → `Allow`（§5）。
- Lua 调用在每个插件内是串行化的；CPU 密集的工作最好放到 WASM 中，或者干脆移出插件（§4）。
- 没有通过面板/网络的注册表或上传功能；来源只有通过配置管理的本地路径（§6）。
- 插件状态不在工作进程之间共享（§4、§6）。
- 所有出错分支均为 fail-open：出错的插件会**放行**流量，而不是拦截。如果你需要对某个具体域名做 fail-closed，请在引擎层面设置 `default_action = deny` 并配合显式的 `allow` 规则——但请记住，插件的 fall-through 在本地产生的是 `Allow`（不会发生短路），只有当没有任何过滤器给出裁决时，遍历才会走到 `default_action`。

---

## 11. 到代码中的哪里去看

| 文件 | 包含什么 |
|---|---|
| `src/filters/plugins/mod.rs` | `PluginRequest`、`PluginResponse`、`into_action`、`request_from_ctx`（wire 格式） |
| `src/filters/plugins/manager.rs` | `PluginSet::from_config` — 从配置物化插件 |
| `src/filters/plugins/lua.rs` | `LuaPlugin`：沙箱、预算 hook、热重载、`build_request_table`、测试 |
| `src/filters/plugins/wasm.rs` | `WasmPlugin`：ABI、燃料、缓冲区钳制（V233）、scratch 缓冲区、测试 |
| `src/config.rs` | `PluginsConfig`（`lua`/`wasm`/`lua_instruction_budget`） |
| `src/filters/mod.rs` | `TrafficFilter`、`FilterAction`、`SharedFilter::Custom` |
| `src/filters/engine.rs` | 链的顺序、短路、`RuntimeToggles` |
| `src/server.rs`、`src/proxy/pingora_http.rs` | 把插件插入链中（在 WAF/bot/adaptive 之后，challenge 之前） |
| `src/dsl/parser.rs`、`src/dsl/ast.rs`、`src/dsl/lower.rs` | DSL 块 `plugins { lua ...; wasm ...; }` |
| `Cargo.toml` | 依赖 `mlua`（lua54/vendored/send/serialize）、`wasmi` |
