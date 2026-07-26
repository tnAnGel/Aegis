//! Nginx-style configuration DSL for Aegis.
//!
//! The DSL is the primary config format going forward:
//!
//! ```text
//! admin { listen 127.0.0.1:9090; }
//! defaults { request_timeout 10s; }
//! server {
//!     listen 80;
//!     server_name api.example.com;
//!     proxy_pass http://127.0.0.1:3001;
//! }
//! ```
//!
//! Three layers (lexer → parser → lower) keep concerns separate so
//! the AST stays useful for future tooling (`aegis config migrate`,
//! IDE plugins, lint passes). Failures carry file:line:col + edit-
//! distance suggestions so operator typos point at the right line.
//!
//! Legacy TOML configs (`.toml`) continue to load through
//! `config::AppConfig::from_path`; dispatch happens by file
//! extension in `load_any` below.

use std::path::Path;

use crate::config::AppConfig;

pub mod ast;
pub mod error;
pub mod lexer;
pub mod lower;
pub mod parser;

pub use error::DslError;
pub use lower::{LoadSummary, migrate_from_toml, render_summary};

/// Load a config from an arbitrary path. Dispatches by extension:
///   `.conf` → nginx-style DSL
///   `.toml` → legacy TOML (preserved for back-compat)
/// Anything else attempts DSL first, falls back to TOML.
pub fn load_any(path: &Path) -> anyhow::Result<(AppConfig, Option<LoadSummary>)> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "toml" {
        let cfg = AppConfig::from_path(path)?;
        return Ok((cfg, None));
    }
    if ext == "conf" {
        return load_dsl(path);
    }
    // Unknown extension — try DSL first (more common going forward),
    // fall back to TOML so existing automation keeps working.
    if let Ok(loaded) = load_dsl(path) {
        return Ok(loaded);
    }
    let cfg = AppConfig::from_path(path)?;
    Ok((cfg, None))
}

pub fn load_dsl(path: &Path) -> anyhow::Result<(AppConfig, Option<LoadSummary>)> {
    let ast = parser::parse_file(path).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let (cfg, summary) = lower::lower(&ast).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    cfg.validate()?;
    Ok((cfg, Some(summary)))
}

/// Parse + validate only. Used by `aegis -t` / `aegis config test` to
/// surface errors without booting the proxy.
pub fn validate_file(path: &Path) -> anyhow::Result<LoadSummary> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "toml" {
        let cfg = AppConfig::from_path(path)?;
        cfg.validate()?;
        return Ok(LoadSummary {
            server_count: cfg.domains.len() + 1,
            listeners: vec![cfg.server.listen.clone()],
            routes: cfg
                .domains
                .iter()
                .map(|(h, d)| (h.clone(), d.upstream_url.clone()))
                .chain(std::iter::once((
                    "default".to_string(),
                    cfg.upstream.url.clone(),
                )))
                .collect(),
        });
    }
    let ast = parser::parse_file(path).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let (cfg, summary) = lower::lower(&ast).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    cfg.validate()?;
    Ok(summary)
}
