//! Owns the live set of Lua + WASM plugins, exposes them as
//! [`SharedFilter`]s the pipeline can consume directly.
//!
//! Plugin paths come from the DSL config (`filters.plugins.lua` /
//! `filters.plugins.wasm`). At build time we instantiate every plugin;
//! plugins that fail to load log a warning and are skipped — one
//! broken script never takes the proxy down.

use std::{path::PathBuf, sync::Arc};

use crate::{
    config::PluginsConfig,
    filters::{
        SharedFilter,
        plugins::{lua::LuaPlugin, wasm::WasmPlugin},
    },
};

pub struct PluginSet {
    pub filters: Vec<SharedFilter>,
}

impl PluginSet {
    pub fn from_config(cfg: &PluginsConfig) -> Self {
        let mut filters: Vec<SharedFilter> = Vec::new();
        for path in &cfg.lua {
            let p = PathBuf::from(path);
            match LuaPlugin::load(&p, cfg.lua_instruction_budget) {
                Ok(plugin) => {
                    tracing::info!(
                        target: "aegis::plugin",
                        path = %p.display(),
                        "loaded lua plugin"
                    );
                    filters.push(SharedFilter::Custom(Arc::new(plugin)));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "aegis::plugin",
                        path = %p.display(),
                        error = %e,
                        "lua plugin failed to load — skipping"
                    );
                }
            }
        }
        for path in &cfg.wasm {
            let p = PathBuf::from(path);
            match WasmPlugin::load(&p) {
                Ok(plugin) => {
                    tracing::info!(
                        target: "aegis::plugin",
                        path = %p.display(),
                        "loaded wasm plugin"
                    );
                    filters.push(SharedFilter::Custom(Arc::new(plugin)));
                }
                Err(e) => {
                    tracing::warn!(
                        target: "aegis::plugin",
                        path = %p.display(),
                        error = %e,
                        "wasm plugin failed to load — skipping"
                    );
                }
            }
        }
        Self { filters }
    }
}
