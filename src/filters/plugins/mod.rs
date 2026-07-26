//! User-supplied filter plugins.
//!
//! Two flavours:
//!   - [`lua`] — embedded Lua 5.4 via mlua. Best for short logic
//!     scripts: low per-call overhead (~µs), trivially hot-reloadable,
//!     no compilation step.
//!   - [`wasm`] — WebAssembly via wasmi (pure-Rust interpreter). Best
//!     for filters that need true memory isolation, are CPU-heavy, or
//!     are written in something other than Lua (Rust, Go, AssemblyScript).
//!
//! Both expose the same [`TrafficFilter`] surface so they slot into the
//! filter pipeline anywhere operators want them ordered. The
//! [`PluginManager`] keeps a watch on each plugin's file mtime and
//! reloads on change without a proxy restart.

pub mod lua;
pub mod manager;
pub mod wasm;

use serde::{Deserialize, Serialize};

/// Wire-format request payload handed to plugins. Field set is
/// deliberately small — most of what a filter wants to inspect.
/// Plugins that need more should be configured against a custom WAF
/// rule first; the plugin trapdoor is for logic, not for parsing.
#[derive(Debug, Clone, Serialize)]
pub struct PluginRequest {
    pub method: String,
    pub path: String,
    pub host: String,
    pub user_agent: String,
    pub client_ip: String,
    pub ja4: String,
    pub ja4h: String,
    pub ja4t: String,
    pub ja4l: String,
    pub h2fp: String,
    pub h3fp: String,
    pub mtls_fp: String,
    pub headers: Vec<(String, String)>,
}

/// Wire-format response from a plugin. `action` must be one of
/// `"allow"`, `"deny"`, `"challenge"`. Status code only used for
/// "deny" (defaults to 403). "challenge" level is one of headers /
/// html / iframe / javascript / captcha (defaults to javascript).
///
/// V230 — we deliberately keep `action`/`reason`/`level` as owned
/// `String` rather than `#[serde(borrow)] Cow<'a, str>`. Both call
/// sites deserialise from short-lived buffers: the wasm path reads
/// bytes out of a sandboxed linear memory that is dropped with the
/// `Store` after the call returns, and the lua path goes through
/// `mlua::Lua::from_value` which consumes a `LuaValue` rather than
/// a `&[u8]` slice — neither produces a borrow that outlives the
/// frame `into_action` is invoked from, so borrowed strings would
/// either dangle or force a lifetime parameter on the public type.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PluginResponse {
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub level: Option<String>,
}

// V230 — `from()` instead of `to_string()` skips the `Display`
// machinery and is the canonical zero-format path for a static
// `&str` -> `String`. Same allocation either way.
fn default_action() -> String {
    String::from("allow")
}

impl PluginResponse {
    /// Resolve into a built-in FilterAction. Unknown action strings
    /// log a warning and fall through to Allow so a misbehaving
    /// plugin never blocks the whole pipeline.
    pub fn into_action(self, plugin: &str) -> crate::filters::FilterAction {
        use crate::filters::{ChallengeLevel, FilterAction};
        match self.action.as_str() {
            "allow" => FilterAction::Allow,
            "deny" => FilterAction::Deny {
                status: self.status.unwrap_or(403),
                reason: if self.reason.is_empty() {
                    format!("plugin {plugin} deny").into()
                } else {
                    self.reason.into()
                },
            },
            "challenge" => FilterAction::Challenge {
                level: match self.level.as_deref() {
                    Some("headers") => ChallengeLevel::Headers,
                    Some("html") => ChallengeLevel::Html,
                    Some("iframe") => ChallengeLevel::Iframe,
                    Some("captcha") => ChallengeLevel::Captcha,
                    _ => ChallengeLevel::Javascript,
                },
                reason: if self.reason.is_empty() {
                    format!("plugin {plugin} challenge").into()
                } else {
                    self.reason.into()
                },
            },
            other => {
                tracing::warn!(
                    target: "aegis::plugin",
                    plugin,
                    action = other,
                    "plugin returned unknown action; falling through as allow"
                );
                FilterAction::Allow
            }
        }
    }
}

/// Build a [`PluginRequest`] from a [`crate::proxy::request_context::RequestContext`].
///
/// V230 — the public struct holds owned `String`s because the request
/// is serialised across a process / language boundary (wasmi linear
/// memory, mlua value table) where borrowed `&str` would either dangle
/// or pin the context for the lifetime of the plugin call. So the
/// String allocations here are unavoidable; the audit focused on
/// shaving the *avoidable* extras: pre-sizing the header `Vec` (one
/// allocation instead of log₂(N) re-grows), skipping a `String::new`
/// for an empty host header, and rewriting the per-fingerprint
/// `clone().unwrap_or_default()` chain to use `as_deref()` so we
/// allocate exactly once on the `Some` branch and zero times on
/// `None` (the previous form cloned the `Option` discriminant before
/// unwrapping, generating a small but real branch on every absent
/// fingerprint).
pub fn request_from_ctx(ctx: &crate::proxy::request_context::RequestContext) -> PluginRequest {
    // V230 — empty host avoids an allocation by leaving `String::new()`
    // as the default rather than going through `to_string()`.
    let host = match ctx.headers.get("host").and_then(|v| v.to_str().ok()) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => String::new(),
    };
    // V230 — pre-size to header count. `HeaderMap::len()` reports the
    // number of values (which may exceed entries for multi-value
    // headers), which is exactly what we iterate over here, so this
    // is an upper bound that avoids reallocation in the common case.
    let mut headers: Vec<(String, String)> = Vec::with_capacity(ctx.headers.len());
    for (n, v) in ctx.headers.iter() {
        if let Ok(s) = v.to_str() {
            headers.push((n.as_str().to_owned(), s.to_owned()));
        }
    }
    PluginRequest {
        // V230 — `Method::as_str()` returns `&'static str` for the
        // standard verbs; the `to_owned()` allocation is unavoidable
        // because PluginRequest holds an owned `String`.
        method: ctx.method.as_str().to_owned(),
        path: ctx.path.clone(),
        host,
        // V230 — `as_deref().unwrap_or("").to_owned()` skips the
        // intermediate `Option<String>` clone the previous code did.
        // For absent fields this is one branch + `String::new()` (no
        // alloc); for present fields it's a single heap copy.
        user_agent: ctx.user_agent.as_deref().unwrap_or("").to_owned(),
        client_ip: ctx.client_ip.to_string(),
        ja4: ctx.ja4.as_deref().unwrap_or("").to_owned(),
        ja4h: ctx.ja4h().unwrap_or("").to_owned(),
        ja4t: ctx.ja4t.as_deref().unwrap_or("").to_owned(),
        ja4l: ctx.ja4l.as_deref().unwrap_or("").to_owned(),
        h2fp: ctx.h2fp.as_deref().unwrap_or("").to_owned(),
        h3fp: ctx.h3fp.as_deref().unwrap_or("").to_owned(),
        mtls_fp: ctx.mtls_fp.as_deref().unwrap_or("").to_owned(),
        headers,
    }
}
