//! AST for the nginx-like DSL.
//!
//! Every node carries the file + line + col of its first token so the
//! lowering pass can build pinpoint diagnostics ("server_name `foo`
//! already defined at sites-enabled/foo.conf:3:17").

use std::{path::PathBuf, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
}

impl Span {
    pub fn new(file: PathBuf, line: u32, col: u32) -> Self {
        Self { file, line, col }
    }
}

#[derive(Debug, Default)]
pub struct ConfigAst {
    pub admin: Option<AdminBlock>,
    pub defaults: Option<DefaultsBlock>,
    pub xdp: Option<XdpBlock>,
    pub servers: Vec<ServerBlock>,
}

#[derive(Debug)]
pub struct AdminBlock {
    pub listen: Option<String>,
    pub audit_log_path: Option<String>,
    pub managed_sites_dir: Option<String>,
    pub ops_sites_dir: Option<String>,
    pub web_state_path: Option<String>,
    pub tokens: Vec<AdminTokenEntry>,
    pub span: Span,
}

#[derive(Debug)]
pub struct AdminTokenEntry {
    pub token: String,
    pub role: String,
    pub span: Span,
}

#[derive(Debug, Default)]
pub struct DefaultsBlock {
    pub request_timeout: Option<Duration>,
    pub graceful_shutdown: Option<Duration>,
    pub header_read_timeout: Option<Duration>,
    pub body_read_timeout: Option<Duration>,
    pub filters: Option<FiltersBlock>,
    pub rate_limit: Option<RateLimitBlock>,
    /// V103 — response_cache config from DSL. None = cache disabled
    /// (pre-V103 default). Operator opts in via `cache { ... }` block
    /// inside `defaults`.
    pub cache: Option<CacheBlock>,
    pub span: Option<Span>,
}

/// V103 — DSL surface for [crate::config::ResponseCacheConfig].
/// Only exposes the high-cardinality knobs operators actually tune.
/// Per-host overrides + status TTL overrides + stale-if-error remain
/// settable only via the legacy TOML path until V104+ adds nested
/// `cache { per_host { ... } }`.
#[derive(Debug, Default)]
pub struct CacheBlock {
    pub default_ttl_secs: Option<u64>,
    pub max_entries: Option<usize>,
    pub max_body_bytes: Option<usize>,
    /// Limit to specific hosts. Empty / absent = enable for all hosts.
    pub hosts: Vec<String>,
}

#[derive(Debug)]
pub struct ServerBlock {
    pub listens: Vec<Listen>,
    pub server_names: Vec<String>,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
    pub proxy_pass: Option<String>,
    pub filters: Option<FiltersBlock>,
    pub rate_limit: Option<RateLimitBlock>,
    pub locations: Vec<LocationBlock>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Listen {
    /// Raw text the operator wrote: `80`, `0.0.0.0:443`, `[::]:443`.
    pub addr: String,
    pub ssl: bool,
    pub http2: bool,
    pub http3: bool,
    pub default_server: bool,
    pub span: Span,
}

#[derive(Debug, Default, Clone)]
pub struct FiltersBlock {
    pub waf: Option<bool>,
    pub bot_fingerprint: Option<bool>,
    pub adaptive_spike_detection: Option<bool>,
    pub challenge_ladder: Option<bool>,
    pub geoip: Option<bool>,
    pub xdp: Option<bool>,
    pub plugins: Option<PluginsBlock>,
    pub span: Option<Span>,
}

#[derive(Debug, Default, Clone)]
pub struct PluginsBlock {
    pub lua: Vec<String>,
    pub wasm: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct XdpBlock {
    pub enabled: bool,
    pub interface: Option<String>,
    pub bpf_object_path: Option<String>,
    pub allow_only: bool,
    pub allow: Vec<String>,
    pub rate_window_ms: u64,
    pub rate_burst: u64,
    pub syn_burst: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RateLimitBlock {
    pub requests_per_second: Option<u64>,
    pub burst: Option<u64>,
}

#[derive(Debug)]
pub struct LocationBlock {
    pub matcher: LocationMatcher,
    pub proxy_pass: Option<String>,
    pub rate_limit: Option<RateLimitBlock>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum LocationMatcher {
    Prefix(String),
    Exact(String),
}
