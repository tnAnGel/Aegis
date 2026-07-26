//! Lua 5.4 plugin filter (mlua, vendored).
//!
//! Each plugin file must define a top-level function `aegis_check(req)`
//! that returns either nil/`{action="allow"}` to pass the request, or a
//! table describing the action. Example:
//!
//! ```lua
//! function aegis_check(req)
//!     if req.user_agent:find("evil-scraper") then
//!         return { action="deny", reason="blocked by ua-rule", status=403 }
//!     end
//!     if req.method == "POST" and req.path:find("/admin") then
//!         return { action="challenge", level="captcha" }
//!     end
//!     return { action="allow" }
//! end
//! ```
//!
//! `req` is a table with: method, path, host, user_agent, client_ip,
//! ja4, ja4h, headers (a list of {name, value} pairs). The script also
//! has access to `aegis.log("...")` for debug output that goes to the
//! proxy's tracing pipeline under the `aegis::plugin` target.

use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::UNIX_EPOCH,
};

use mlua::{Lua, LuaSerdeExt, Table as LuaTable, Value as LuaValue};

use crate::{
    filters::{FilterAction, TrafficFilter, plugins::PluginResponse},
    proxy::request_context::RequestContext,
};

pub struct LuaPlugin {
    name: String,
    path: PathBuf,
    state: Mutex<LuaState>,
    mtime_secs: AtomicU64,
    /// V229 — throttle for the per-request `maybe_reload` stat. The
    /// CPU profile on the stand showed `statx` consuming 24% of all
    /// syscall time; this stat was one of the per-request offenders
    /// for any deployment running Lua filters. Microsecond-resolution
    /// timestamp of the last attempted reload; reads inside the
    /// window skip the stat syscall entirely.
    last_reload_micros: AtomicU64,
    reload_start: std::time::Instant,
    /// Hard cap on script CPU per call. Lua doesn't have native
    /// instruction limits but mlua exposes a hook fired every N
    /// instructions — we use it to abort runaway scripts.
    instruction_budget: u32,
}

const LUA_RELOAD_INTERVAL_MICROS: u64 = 1_000_000;

struct LuaState {
    lua: Lua,
    failed: bool,
}

impl LuaPlugin {
    pub fn load(path: &Path, instruction_budget: u32) -> anyhow::Result<Self> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("lua-plugin")
            .to_string();
        let lua = Self::new_state(path, instruction_budget)?;
        let mtime_secs = file_mtime(path);
        Ok(Self {
            name,
            path: path.to_path_buf(),
            state: Mutex::new(LuaState { lua, failed: false }),
            mtime_secs: AtomicU64::new(mtime_secs),
            last_reload_micros: AtomicU64::new(0),
            reload_start: std::time::Instant::now(),
            instruction_budget,
        })
    }

    fn new_state(path: &Path, instruction_budget: u32) -> anyhow::Result<Lua> {
        let lua = Lua::new();
        // Sandbox: drop file/process/io tables and the OS clock helpers
        // before user code runs. The plugin slot is for filter logic,
        // not for poking the host.
        lua.load(
            r#"
            io = nil
            os = { time = os.time, date = os.date }
            package = nil
            require = nil
            loadfile = nil
            dofile = nil
        "#,
        )
        .exec()?;
        // aegis.log("…") -> tracing::info!
        let log_fn = lua.create_function(|_, msg: String| {
            tracing::info!(target: "aegis::plugin", "{msg}");
            Ok(())
        })?;
        let aegis_tbl = lua.create_table()?;
        aegis_tbl.set("log", log_fn)?;
        lua.globals().set("aegis", aegis_tbl)?;
        // Load the user script.
        let source = std::fs::read_to_string(path)?;
        lua.load(&source)
            .set_name(format!("{}", path.display()))
            .exec()?;
        // Set instruction-count hook.
        if instruction_budget > 0 {
            let triggers = mlua::HookTriggers::new().every_nth_instruction(instruction_budget);
            lua.set_hook(triggers, |_lua, _debug| {
                Err(mlua::Error::RuntimeError(
                    "instruction budget exceeded".to_string(),
                ))
            });
        }
        Ok(lua)
    }

    fn maybe_reload(&self) {
        // V229 — throttle to once per second. The previous impl ran
        // `file_mtime` (= `statx`) on every filter check; at high RPS
        // this dominated syscall time per worker.
        let now_micros = self.reload_start.elapsed().as_micros() as u64;
        let last = self.last_reload_micros.load(Ordering::Relaxed);
        if now_micros.saturating_sub(last) < LUA_RELOAD_INTERVAL_MICROS {
            return;
        }
        self.last_reload_micros.store(now_micros, Ordering::Relaxed);

        let on_disk = file_mtime(&self.path);
        let cached = self.mtime_secs.load(Ordering::Relaxed);
        if on_disk == cached {
            return;
        }
        match Self::new_state(&self.path, self.instruction_budget) {
            Ok(lua) => {
                if let Ok(mut guard) = self.state.lock() {
                    guard.lua = lua;
                    guard.failed = false;
                }
                self.mtime_secs.store(on_disk, Ordering::Relaxed);
                tracing::info!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    path = %self.path.display(),
                    "lua plugin reloaded"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    path = %self.path.display(),
                    error = %e,
                    "lua plugin reload failed — keeping previous version"
                );
                if let Ok(mut guard) = self.state.lock() {
                    guard.failed = true;
                }
                self.mtime_secs.store(on_disk, Ordering::Relaxed);
            }
        }
    }

    fn call(&self, ctx: &RequestContext) -> Option<PluginResponse> {
        let guard = self.state.lock().ok()?;
        if guard.failed {
            return None;
        }
        let lua = &guard.lua;
        let aegis_check: mlua::Function = match lua.globals().get("aegis_check") {
            Ok(f) => f,
            Err(_) => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    "lua plugin missing top-level `aegis_check` function"
                );
                return None;
            }
        };
        // V230 — build the request table directly from the RequestContext
        // instead of materialising a `PluginRequest` and round-tripping
        // through serde. The old path cloned every header value, every
        // JA fingerprint, the path, and the user-agent into an
        // intermediate struct that was immediately serialised into Lua
        // values and dropped. Building the table by hand lets mlua copy
        // each `&str` straight into Lua's string heap with no
        // owned-`String` middle step.
        let arg = match build_request_table(lua, ctx) {
            Ok(t) => LuaValue::Table(t),
            Err(e) => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    error = %e,
                    "failed to serialise request for lua plugin"
                );
                return None;
            }
        };
        let result: LuaValue = match aegis_check.call::<LuaValue>(arg) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    error = %e,
                    "lua plugin raised an error — falling through as allow"
                );
                return None;
            }
        };
        if matches!(result, LuaValue::Nil) {
            return Some(PluginResponse {
                action: "allow".into(),
                ..Default::default()
            });
        }
        match lua.from_value::<PluginResponse>(result) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin = %self.name,
                    error = %e,
                    "lua plugin returned a value that doesn't deserialise as action"
                );
                None
            }
        }
    }
}

impl TrafficFilter for LuaPlugin {
    fn name(&self) -> &'static str {
        // We need a `'static str` here but the plugin's name is owned;
        // return a generic label and let per-plugin attribution happen
        // through tracing fields instead of metrics labels.
        "lua_plugin"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        self.maybe_reload();
        // V230 — skip the `request_from_ctx` clone-fest; the lua call
        // path now reads straight from the context.
        match self.call(ctx) {
            Some(resp) => resp.into_action(&self.name),
            None => FilterAction::Allow,
        }
    }
}

/// V230 — direct `RequestContext` -> Lua table conversion. Mirrors the
/// public [`crate::filters::plugins::PluginRequest`] field layout so
/// scripts see the same shape as before, but skips the intermediate
/// owned-`String` struct: each `set` borrows the slice and Lua copies
/// the bytes once.
fn build_request_table(lua: &Lua, ctx: &RequestContext) -> mlua::Result<LuaTable> {
    // 13 named fields + headers; size hints help mlua skip the rehash.
    let t = lua.create_table_with_capacity(0, 13)?;
    t.set("method", ctx.method.as_str())?;
    t.set("path", ctx.path.as_str())?;
    let host = ctx
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    t.set("host", host)?;
    t.set("user_agent", ctx.user_agent.as_deref().unwrap_or(""))?;
    let client_ip = ctx.client_ip.to_string();
    t.set("client_ip", client_ip.as_str())?;
    t.set("ja4", ctx.ja4.as_deref().unwrap_or(""))?;
    t.set("ja4h", ctx.ja4h().unwrap_or(""))?;
    t.set("ja4t", ctx.ja4t.as_deref().unwrap_or(""))?;
    t.set("ja4l", ctx.ja4l.as_deref().unwrap_or(""))?;
    t.set("h2fp", ctx.h2fp.as_deref().unwrap_or(""))?;
    t.set("h3fp", ctx.h3fp.as_deref().unwrap_or(""))?;
    t.set("mtls_fp", ctx.mtls_fp.as_deref().unwrap_or(""))?;
    // Headers as a sequence of {name, value} pairs — matches the
    // pre-V230 wire format. Each row table is sized {2, 0}.
    let headers = lua.create_table_with_capacity(ctx.headers.len(), 0)?;
    let mut idx = 1i64;
    for (n, v) in ctx.headers.iter() {
        if let Ok(vs) = v.to_str() {
            let row = lua.create_table_with_capacity(2, 0)?;
            row.set(1, n.as_str())?;
            row.set(2, vs)?;
            headers.set(idx, row)?;
            idx += 1;
        }
    }
    t.set("headers", headers)?;
    Ok(t)
}

fn file_mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as TestSeq;

    static SEQ: TestSeq = TestSeq::new(0);

    fn tmp(contents: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "aegis-lua-{}-{}.lua",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn deny_rule_matches() {
        let p = tmp(r#"
            function aegis_check(req)
                if req.user_agent == "evil" then
                    return { action="deny", reason="ua block", status=418 }
                end
                return { action="allow" }
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("evil");
        match plugin.check(&ctx) {
            FilterAction::Deny { status, reason } => {
                assert_eq!(status, 418);
                assert_eq!(reason, "ua block");
            }
            other => panic!("expected deny, got {other:?}"),
        }
        let ctx2 = RequestContext::test_with("1.1.1.1", "/").with_ua("benign");
        assert_eq!(plugin.check(&ctx2), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn challenge_rule_matches() {
        let p = tmp(r#"
            function aegis_check(req)
                return { action="challenge", level="captcha" }
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert!(matches!(plugin.check(&ctx), FilterAction::Challenge { .. }));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn nil_return_is_allow() {
        let p = tmp(r#"
            function aegis_check(req)
                return nil
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert_eq!(plugin.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn script_error_is_allow() {
        let p = tmp(r#"
            function aegis_check(req)
                error("boom")
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        // Plugin failure must not block legitimate traffic.
        assert_eq!(plugin.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn hot_reload_picks_up_changes() {
        let p = tmp(r#"
            function aegis_check(req)
                return { action="allow" }
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert_eq!(plugin.check(&ctx), FilterAction::Allow);
        // Replace the script and bump the mtime.
        std::thread::sleep(std::time::Duration::from_secs(1));
        std::fs::write(
            &p,
            r#"
            function aegis_check(req)
                return { action="deny", reason="new rule" }
            end
        "#,
        )
        .unwrap();
        assert!(matches!(plugin.check(&ctx), FilterAction::Deny { .. }));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unknown_action_falls_through_to_allow() {
        let p = tmp(r#"
            function aegis_check(req)
                return { action="explode" }
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert_eq!(plugin.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn ja4h_field_visible_to_script() {
        let p = tmp(r#"
            function aegis_check(req)
                if req.ja4h:sub(1,2) == "ge" then
                    return { action="deny", reason="get-banned" }
                end
                return { action="allow" }
            end
        "#);
        let plugin = LuaPlugin::load(&p, 100_000).unwrap();
        // V231 — ja4h is now lazy; use set_ja4h_for_test to inject a
        // known fingerprint value.
        let ctx = RequestContext::test_with("1.1.1.1", "/")
            .set_ja4h_for_test("ge11nn010000_aaaa_bbbb_cccc");
        assert!(matches!(plugin.check(&ctx), FilterAction::Deny { .. }));
        let _ = std::fs::remove_file(&p);
    }
}
