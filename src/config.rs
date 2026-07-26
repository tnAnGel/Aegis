use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, net::IpAddr, path::Path, str::FromStr};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub filters: FiltersConfig,
    pub admin: Option<AdminConfig>,
    pub tls: Option<TlsConfig>,
    pub storage: Option<StorageConfig>,
    pub xdp: Option<XdpConfig>,
    pub geoip: Option<GeoIpConfig>,
    pub anomaly: Option<AnomalyDetectorConfig>,
    #[serde(default)]
    pub domains: HashMap<String, DomainConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnomalyDetectorConfig {
    pub enabled: bool,
    /// Sliding window over which current RPS is computed (seconds).
    #[serde(default = "default_anomaly_window_secs")]
    pub window_secs: u64,
    /// Multiplier over baseline RPS that constitutes an attack.
    #[serde(default = "default_anomaly_multiplier")]
    pub multiplier: f64,
    /// Don't flag until baseline crosses this RPS (avoids false
    /// positives on quiet domains where 0 → 5 looks like a 5x spike).
    #[serde(default = "default_anomaly_min_baseline_rps")]
    pub min_baseline_rps: f64,
    /// How long the under-attack flag stays set after the last trip.
    #[serde(default = "default_anomaly_attack_secs")]
    pub attack_duration_secs: u64,
    /// Minimum challenge level forced on unverified requests while
    /// under attack. One of: headers, html, iframe, javascript, captcha.
    #[serde(default = "default_anomaly_min_level")]
    pub min_challenge_level: String,
}

fn default_anomaly_window_secs() -> u64 {
    10
}
fn default_anomaly_multiplier() -> f64 {
    3.0
}
fn default_anomaly_min_baseline_rps() -> f64 {
    10.0
}
fn default_anomaly_attack_secs() -> u64 {
    60
}
fn default_anomaly_min_level() -> String {
    "javascript".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    /// Path to a MaxMind GeoLite2-Country .mmdb file. Required —
    /// without it the rest of the geoip block is a no-op.
    pub db_path: String,
    /// V144 — optional path to a MaxMind GeoLite2-ASN .mmdb file.
    /// When set, the GeoIpLookup handle answers asn() lookups; the
    /// V142 ASN reputation feed uses these for AS-keyed matching.
    /// Without this, only CIDR-keyed entries match.
    #[serde(default)]
    pub asn_db_path: Option<String>,
    /// ISO 3166-1 alpha-2 country codes to reject (e.g. ["RU","KP"]).
    /// Case-insensitive. Empty list = monitor mode (records country in
    /// metrics but never blocks).
    #[serde(default)]
    pub deny_countries: Vec<String>,
    /// When true the deny list only applies while the anomaly detector
    /// has the upstream flagged under attack. Useful when you want a
    /// dormant geo-block that activates only during DDoS events.
    #[serde(default)]
    pub attack_mode_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct XdpConfig {
    pub enabled: bool,
    pub interface: String,
    pub bpf_object_path: String,
    /// IPv4/IPv6 source addresses that bypass the deny + rate-limit
    /// checks. When `allow_only = true`, these are the *only* IPs
    /// allowed through — everything else gets XDP_DROP'd.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub allow_only: bool,
    /// Per-IPv4 in-kernel rate limiter. Both fields must be > 0 to
    /// activate; the BPF program drops packets whose source has more
    /// than `burst` packets within the rolling `window_ms` window.
    #[serde(default)]
    pub rate_window_ms: u64,
    #[serde(default)]
    pub rate_burst: u64,
    /// Per-IPv4 TCP-SYN burst limit within `rate_window_ms`. Counts
    /// only SYN-without-ACK packets, so legit established traffic
    /// doesn't deplete the SYN budget. 0 disables the dedicated SYN
    /// guard.
    #[serde(default)]
    pub syn_burst: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    pub upstream_url: String,
    pub requests_per_second: Option<u64>,
    pub burst: Option<u64>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub request_timeout_ms: u64,
    pub graceful_shutdown_secs: u64,
    /// Parse a PROXY protocol header at the start of every accepted
    /// connection so the real client IP is used downstream — required
    /// when Aegis runs behind a L4 load balancer (AWS NLB, HAProxy,
    /// nftables/IPVS DR). Supported levels:
    ///   "off"   — ignore the header (default; assume direct TCP)
    ///   "v1"    — text format only (HAProxy 1.5+)
    ///   "v2"    — binary format only (HAProxy 1.6+, AWS NLB)
    ///   "auto"  — accept either
    #[serde(default = "default_proxy_protocol")]
    pub proxy_protocol: ProxyProtocolMode,
    /// Slowloris guard: kill any HTTP/1.x connection that hasn't finished
    /// sending request headers within this many milliseconds. Default 5s.
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    /// Slow-POST guard: kill the request if the body hasn't fully
    /// arrived within this many milliseconds. Default 30s. Set to 0
    /// to disable (not recommended).
    #[serde(default = "default_body_read_timeout_ms")]
    pub body_read_timeout_ms: u64,
    /// HTTP/2 Rapid Reset (CVE-2023-44487): maximum number of
    /// concurrently-resetting streams kept around per connection
    /// before we close the connection. Default 100.
    #[serde(default = "default_h2_max_reset_streams")]
    pub h2_max_reset_streams: usize,
    /// V230 — anti-RapidReset limit (CVE-2023-44487). Applied to both
    /// hyper and pingora H2 listeners. Maximum number of concurrent
    /// HTTP/2 streams per connection. Default 200 (pre-V230 behaviour
    /// preserved); lower to ~50 if you want a tighter cap against
    /// stream-flood attacks, raise to 100+ if you trust your clients
    /// and need higher concurrency per connection.
    #[serde(default = "default_h2_max_concurrent_streams")]
    pub h2_max_concurrent_streams: u32,
    /// V230 — initial H2 stream window. Larger = fewer WINDOW_UPDATE
    /// round-trips for large responses. Default 1 MB.
    #[serde(default = "default_h2_initial_window_size")]
    pub h2_initial_window_size: u32,
    /// V230 — initial H2 connection window. Larger = better parallel
    /// stream throughput. Default 8 MB (8x stream window).
    #[serde(default = "default_h2_initial_connection_window_size")]
    pub h2_initial_connection_window_size: u32,
    /// V230 — disable Nagle's algorithm on accepted connections. Default
    /// true; only set false if running over a saturated low-bandwidth
    /// link where coalescing helps.
    #[serde(default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,
    /// V230 — TCP keepalive idle seconds. 0 disables; default 60 (matches
    /// haproxy/nginx tier-1 defaults). Reaps half-open slowloris sockets.
    #[serde(default = "default_tcp_keepalive_secs")]
    pub tcp_keepalive_secs: u64,
}

fn default_proxy_protocol() -> ProxyProtocolMode {
    ProxyProtocolMode::Off
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    Off,
    V1,
    V2,
    Auto,
}

fn default_header_read_timeout_ms() -> u64 {
    5_000
}
fn default_body_read_timeout_ms() -> u64 {
    30_000
}
fn default_h2_max_reset_streams() -> usize {
    100
}
fn default_h2_max_concurrent_streams() -> u32 {
    200
}
/// V230 — initial H2 stream window (1 MiB).
fn default_h2_initial_window_size() -> u32 {
    1_048_576
}
/// V230 — initial H2 connection window (8 MiB).
fn default_h2_initial_connection_window_size() -> u32 {
    8 * 1_048_576
}
/// V230 — disable Nagle's algorithm on accepted connections.
fn default_tcp_nodelay() -> bool {
    true
}
/// V230 — TCP keepalive idle seconds (matches haproxy/nginx tier-1).
fn default_tcp_keepalive_secs() -> u64 {
    60
}
#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub listen: String,
    #[serde(default)]
    pub tokens: Vec<AdminTokenEntry>,
    #[serde(default)]
    pub audit_log_path: Option<String>,
    /// Directory where the admin web UI writes site `.conf` files
    /// it manages. Aegis includes it via `include <dir>/*.conf;`.
    /// Default: /var/lib/aegis/sites.d when the directory exists.
    #[serde(default)]
    pub managed_sites_dir: Option<String>,
    /// Operator-managed sites directory — surfaced read-only in the
    /// UI. Default: /etc/aegis/sites-enabled.
    #[serde(default)]
    pub ops_sites_dir: Option<String>,
    /// Path to the web panel state file (admin credentials, sessions,
    /// enabled flag). The CLI (`aegis web reset-admin`, `aegis web
    /// stop/start`) writes here; the daemon stats it on every request
    /// to pick up out-of-band changes. Default:
    /// `/var/lib/aegis/web.json`.
    #[serde(default)]
    pub web_state_path: Option<String>,
    /// Path to the honeypot state file (global pack toggles, per-host
    /// overrides, tarpit settings). Admin panel writes here; daemon
    /// stats it on every honeypot check. Default:
    /// `/var/lib/aegis/honeypots.json`.
    #[serde(default)]
    pub honeypot_state_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminTokenEntry {
    pub token: String,
    pub role: AdminRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminRole {
    /// Read-only: metrics, health, threats, xdp counters.
    Read,
    /// Read + mutate runtime state (xdp deny/undeny).
    Write,
    /// Full control (reload, stop, plus everything above).
    Admin,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub listen: String,
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub h3_enabled: bool,
    #[serde(default)]
    pub h3_listen: Option<String>,
    /// Per-SNI hostname cert/key overrides. The cert_path/key_path pair
    /// above is the default returned when no SNI entry matches.
    #[serde(default)]
    pub sni: Vec<SniEntry>,
    /// JA3 MD5 fingerprint hex strings to reject at TLS handshake.
    /// Each new TLS connection has its ClientHello sniffed; a matching
    /// hash gets the socket closed without a handshake reply, saving
    /// CPU spent on key exchange against known attack tools. Compare
    /// hashes from abuse.ch SSL Blacklist or similar feeds.
    #[serde(default)]
    pub ja3_deny_hashes: Vec<String>,
    /// JA4 prefix matches to reject at TLS handshake. Each entry is
    /// matched with `starts_with` against the full JA4 string
    /// (`q13d2613h2_8daaf6152771_b186095e22b6`). Lets operators
    /// block a whole JA4_a class (e.g. `t13d` for any TLS 1.3 with
    /// SNI) or a specific full fingerprint. JA4 is more stable than
    /// JA3 across browser sessions because both segments are
    /// pre-sorted before hashing.
    #[serde(default)]
    pub ja4_deny_prefixes: Vec<String>,
    /// V59 — mTLS (client cert authentication) settings. When
    /// `mtls.enabled = true`, the TLS listener requires every
    /// incoming connection to present a client certificate signed
    /// by one of the CAs in `ca_paths`. Aegis computes the mTLS
    /// fingerprint per connection (see V53) and stamps it on
    /// `RequestContext.mtls_fp` for filter rules to inspect.
    /// Without this block, mTLS stays off and `mtls_fp` is None.
    #[serde(default)]
    pub mtls: MtlsConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MtlsConfig {
    /// Master switch. False (default) → no client-cert verification,
    /// `RequestContext.mtls_fp` is always None. True → require a
    /// client cert that chains to one of `ca_paths`.
    #[serde(default)]
    pub enabled: bool,
    /// PEM file(s) containing the CA certificates aegis will trust
    /// for verifying client certs. Multiple files are concatenated
    /// into a single trust store. Empty list with `enabled = true`
    /// is a configuration error caught at startup.
    #[serde(default)]
    pub ca_paths: Vec<String>,
    /// When true, the handshake fails (connection dropped) if the
    /// client doesn't present a cert. When false (default),
    /// no-cert connections proceed with `mtls_fp = None` —
    /// operator filter rules can decide whether to reject those
    /// downstream. "Optional but verified if presented" semantics.
    #[serde(default)]
    pub require_cert: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SniEntry {
    pub host: String,
    pub cert_path: String,
    pub key_path: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub url: String,
    /// Wire protocol used for upstream requests.
    /// - `"h1"` (default): HTTP/1.1 keep-alive pool
    /// - `"h2c"`: HTTP/2 cleartext (prior-knowledge). Requires upstream
    ///   to accept h2 without TLS (`nginx`: `listen ... http2;` or
    ///   any modern h2-capable backend). Multiplexes thousands of
    ///   requests over a single connection — measurably reduces
    ///   syscall + accept overhead at high RPS.
    #[serde(default)]
    pub protocol: UpstreamProtocol,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    #[default]
    H1,
    H2c,
}
#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub redis_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FiltersConfig {
    pub default_action: DefaultAction,
    pub ip_acl: IpAclConfig,
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub adaptive: AdaptiveConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub bot: BotConfig,
    #[serde(default)]
    pub challenge: ChallengeConfig,
    #[serde(default)]
    pub graphql: GraphqlConfig,
    /// Bypass list — requests matching any rule skip the entire
    /// filter pipeline. Useful for trusted webhook endpoints
    /// (Stripe, GitHub) that legitimately send high-volume,
    /// payload-heavy POSTs that look like attacks.
    #[serde(default)]
    pub bypass: BypassConfig,
    /// Reputation-driven dynamic trust promotion. An IP that
    /// accumulates `min_clean_requests` Allow responses within
    /// `trust_window_secs` (with zero Denies in that window) gets
    /// promoted into the bypass fast-path for `trust_ttl_secs`. A
    /// single Deny/Challenge during the TTL revokes trust instantly.
    /// Off by default — operators opt in when they want production
    /// traffic to auto-bypass without explicit allow-listing.
    #[serde(default)]
    pub dynamic_trust: DynamicTrustConfig,
    /// Threat-aware response cache. Memoises cacheable upstream
    /// responses; high-threat IPs get forced cache MISS to block
    /// cache-poisoning. Off by default — operators opt in per the
    /// usual semantics (caching changes upstream behaviour and ops
    /// should be explicit about it).
    #[serde(default)]
    pub response_cache: ResponseCacheConfig,
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,
    #[serde(default)]
    pub plugins: PluginsConfig,
    /// V108 — correlational RiskEngine wiring (Observe-first rollout).
    #[serde(default)]
    pub risk_engine: RiskEngineConfig,
}

/// V108 — config for the correlational RiskEngine. Default `off` keeps the
/// engine UNINSTANTIATED (zero hot-path cost) so existing deployments
/// upgrade with no behaviour change. `observe` computes + logs a risk score
/// per request but NEVER changes the allow/deny decision (the legacy
/// FilterEngine still decides). Flip to `enforce` only after reviewing
/// >= 1 week of Observe data (premature enforce with placeholder bot/ml
/// > scores produces false negatives).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RiskEngineConfig {
    #[serde(default)]
    pub mode: RiskEngineMode,
    /// Score (0..=255) at/above which `enforce` mode escalates an
    /// otherwise-Allow request. Default 90 = the Deny band. Ignored in
    /// `off`/`observe`.
    #[serde(default = "default_risk_threshold")]
    pub threshold: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskEngineMode {
    /// Engine not instantiated. Zero cost. Safe default.
    #[default]
    Off,
    /// Score computed + logged; decision UNCHANGED (shadow mode).
    Observe,
    /// Score >= threshold escalates an otherwise-Allow request.
    Enforce,
}

fn default_risk_threshold() -> u8 {
    90
}

#[derive(Debug, Clone, Deserialize)]
pub struct DynamicTrustConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Number of consecutive Allow responses required before an IP
    /// is promoted to trusted. Higher = more conservative (less
    /// chance of false-trusting a sleeper bot). Default 100.
    #[serde(default = "default_dt_min_clean")]
    pub min_clean_requests: u32,
    /// Window inside which the clean run must accumulate. If the
    /// elapsed time since the run started exceeds this, the counter
    /// resets. Defeats slow drip-feed trust accumulation. Default 60s.
    #[serde(default = "default_dt_window")]
    pub trust_window_secs: u64,
    /// How long a trust grant lasts before it must be re-earned.
    /// Default 300s (5 min) — short enough that attacker behaviour
    /// change is captured quickly, long enough to amortise the
    /// observation cost for high-volume legitimate clients.
    #[serde(default = "default_dt_ttl")]
    pub trust_ttl_secs: u64,
    /// Hard cap on currently-trusted IPs (memory bound). LRU eviction
    /// when crossed. Default 10 000 — fits in ~500 KB.
    #[serde(default = "default_dt_max")]
    pub max_trusted: usize,
}

impl Default for DynamicTrustConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_clean_requests: default_dt_min_clean(),
            trust_window_secs: default_dt_window(),
            trust_ttl_secs: default_dt_ttl(),
            max_trusted: default_dt_max(),
        }
    }
}

fn default_dt_min_clean() -> u32 {
    100
}
fn default_dt_window() -> u64 {
    60
}
fn default_dt_ttl() -> u64 {
    300
}
fn default_dt_max() -> usize {
    10_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Maximum entries kept in the LRU. Memory bound is
    /// `max_entries × max_body_bytes` worst case. Default 10 000.
    #[serde(default = "default_rc_entries")]
    pub max_entries: usize,
    /// Fallback TTL when the upstream response carries no
    /// `Cache-Control: max-age` / `s-maxage`. Conservative default 60s.
    #[serde(default = "default_rc_ttl")]
    pub default_ttl_secs: u64,
    /// Hard cap on cacheable body size. Larger responses bypass the
    /// cache and stream through normally. Default 1 MiB.
    #[serde(default = "default_rc_body")]
    pub max_body_bytes: usize,
    /// Status-specific TTL overrides (Phase 3Y.6). Common pattern:
    /// cache 404s briefly (10s) to absorb scanner bursts without
    /// hammering upstream, while keeping 200s at the longer
    /// default_ttl_secs.
    /// Examples: `{200 = 300, 404 = 10, 301 = 3600}`.
    /// Status not listed → falls back to default_ttl_secs.
    #[serde(default)]
    pub status_ttl_secs: std::collections::HashMap<u16, u64>,
    /// Phase 3Y.7 — Stale-if-error window (seconds). When upstream
    /// returns 5xx or fails entirely AND we have a cached entry
    /// whose TTL recently expired within this window, serve the
    /// stale entry with a `Warning: 110 - "Response is Stale"`
    /// header instead of 502. Keeps the site up during backend
    /// hiccups. Default 0 = disabled.
    #[serde(default)]
    pub stale_if_error_secs: u64,
    /// Per-host enable list. Empty = cache eligible for every host.
    /// Operators typically restrict to known static/CDN hosts.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Per-host TTL / body-size overrides — Phase 3Y.3.
    /// Each entry: `{host = "x", ttl_secs = 120, max_body_bytes = 65536}`.
    /// When set, takes precedence over global `default_ttl_secs` and
    /// `max_body_bytes` for matching host. Lets ops tune long-TTL for
    /// /static/* hosts and short-TTL for /api/* hosts in one cache.
    #[serde(default)]
    pub per_host: Vec<PerHostCache>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PerHostCache {
    pub host: String,
    /// Override default TTL for this host. `None` keeps global.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Override body-size cap for this host. `None` keeps global.
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
    /// If `Some(false)`, this host is *excluded* from caching even
    /// when present in `hosts` allow-list. Lets ops disable a single
    /// host without rewriting the full allow-list.
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_entries: default_rc_entries(),
            default_ttl_secs: default_rc_ttl(),
            max_body_bytes: default_rc_body(),
            status_ttl_secs: std::collections::HashMap::new(),
            stale_if_error_secs: 0,
            hosts: Vec::new(),
            per_host: Vec::new(),
        }
    }
}

fn default_rc_entries() -> usize {
    10_000
}
fn default_rc_ttl() -> u64 {
    60
}
fn default_rc_body() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PluginsConfig {
    /// Paths to Lua 5.4 plugin files. Each must define a top-level
    /// `aegis_check(req)` function. Reloaded on file mtime change.
    #[serde(default)]
    pub lua: Vec<String>,
    /// Paths to WebAssembly plugin modules (.wasm). Each must export
    /// `aegis_alloc(size: i32) -> i32` and
    /// `aegis_check(ptr: i32, len: i32) -> i64`.
    #[serde(default)]
    pub wasm: Vec<String>,
    /// Per-call Lua instruction budget. Hooks fire every N
    /// instructions and abort the call. Default 100k — generous
    /// for any realistic filter, hard cap on runaway loops.
    #[serde(default = "default_lua_instruction_budget")]
    pub lua_instruction_budget: u32,
}

fn default_lua_instruction_budget() -> u32 {
    100_000
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GraphqlConfig {
    /// When true the proxy parses POST bodies on `paths` and rejects
    /// queries that exceed the depth/alias/directive limits.
    #[serde(default)]
    pub enabled: bool,
    /// URL paths that should be treated as GraphQL endpoints
    /// (default `["/graphql"]`).
    #[serde(default = "default_graphql_paths")]
    pub paths: Vec<String>,
    /// Maximum nested `{ ... }` selection depth (default 10).
    /// Cloudflare-class commercial WAFs cap at ~15 by default.
    #[serde(default = "default_graphql_max_depth")]
    pub max_depth: u32,
    /// Maximum number of field aliases in a single query (default 50).
    /// Each `a:field b:field …` adds 1 — used to amplify single-cost
    /// fields into N expensive resolutions.
    #[serde(default = "default_graphql_max_aliases")]
    pub max_aliases: u32,
    /// Maximum length of the raw `query` string (default 16 KiB).
    /// Cheap pre-filter against oversized payloads.
    #[serde(default = "default_graphql_max_body")]
    pub max_query_bytes: usize,
    /// Block GraphQL introspection queries (`__schema`, `__type`).
    /// Recommended for production endpoints.
    #[serde(default = "default_true")]
    pub block_introspection: bool,
    /// V112 — when true, reject ANY query whose SHA-256 hash isn't in
    /// `persisted_hashes`. This is the strongest GraphQL DDoS defence
    /// (info.md P1): production traffic uses a fixed set of operations
    /// known at build time; arbitrary queries are denied. Defaults
    /// false so the V99-era behaviour is preserved.
    #[serde(default)]
    pub persisted_only: bool,
    /// V112 — operator-curated set of SHA-256 hex digests (one per
    /// allowed operation). Compared lowercase. Empty + `persisted_only=true`
    /// effectively disables the endpoint, which is sometimes useful
    /// for emergencies.
    #[serde(default)]
    pub persisted_hashes: Vec<String>,
}

fn default_graphql_paths() -> Vec<String> {
    vec!["/graphql".to_string()]
}
fn default_graphql_max_depth() -> u32 {
    10
}
fn default_graphql_max_aliases() -> u32 {
    50
}
fn default_graphql_max_body() -> usize {
    16 * 1024
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ThreatIntelConfig {
    /// Local file paths to load threat-intel deny lists from. Each
    /// file is "one IP per line" (CIDRs not supported yet; lines
    /// starting with `#` are ignored). Files are re-read on every
    /// `refresh_secs` tick so operators can cron-curl from
    /// AbuseIPDB / Spamhaus DROP / FireHOL into here without
    /// restarting Aegis.
    #[serde(default)]
    pub paths: Vec<String>,
    /// How often to re-scan the feed files. Default 300 s.
    #[serde(default = "default_threat_refresh_secs")]
    pub refresh_secs: u64,
}

fn default_threat_refresh_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BypassConfig {
    /// IPv4 / IPv6 source addresses that bypass all L7 filters. Use
    /// for trusted infrastructure (internal scrapers, monitoring).
    #[serde(default)]
    pub ips: Vec<String>,
    /// Path prefixes that bypass all L7 filters. Trailing `*` is the
    /// only wildcard — use `/webhooks/*` for whole subtrees.
    #[serde(default)]
    pub paths: Vec<String>,
    /// User-Agent substring matches that bypass all L7 filters. Use
    /// for trusted automation (`GitHub-Hookshot`, `Stripe/`).
    #[serde(default)]
    pub user_agents: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Allow,
    Deny,
}
#[derive(Debug, Clone, Deserialize)]
pub struct IpAclConfig {
    pub deny: Vec<String>,
    pub allow: Vec<String>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u64,
    pub burst: u64,
    /// Botnet defence: also apply rate limits to the client's /24
    /// (IPv4) or /48 (IPv6) prefix and /16 (IPv4) or /32 (IPv6)
    /// prefix. A single IP can be evaded by a botnet with thousands
    /// of addresses, but a /24 budget can't. Multipliers scale the
    /// per-IP rate to make legitimate ISP NAT pools not collide.
    #[serde(default)]
    pub subnet_buckets: bool,
    /// Multiplier applied to per-IP rate/burst for the /24 bucket
    /// (or /48 for v6). Default 8 = up to 8 active IPs per subnet
    /// before throttling kicks in.
    #[serde(default = "default_subnet_24_mul")]
    pub subnet_24_multiplier: u64,
    /// Multiplier for the /16 (or /32 v6) bucket. Default 64.
    #[serde(default = "default_subnet_16_mul")]
    pub subnet_16_multiplier: u64,
    /// Per-URI rate-limit overrides. First-match-wins; if no pattern
    /// matches the request path the default rate / burst above
    /// applies. Useful for caps on `/api/expensive`, `/login`, etc.
    #[serde(default)]
    pub uri_budgets: Vec<UriBudget>,
    /// Per-URI hits/sec threshold above which we log a "hot URI"
    /// event. 0 disables auto-detection. The detector only observes —
    /// it never blocks on its own (operators get the signal in
    /// tracing + /admin/hot_uris and decide how to react).
    #[serde(default = "default_hot_uri_threshold")]
    pub hot_uri_rps_threshold: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UriBudget {
    /// Path pattern. Either an exact match (`"/login"`) or a prefix
    /// with a trailing `*` (`"/api/*"`). Matching is path-only — query
    /// strings are ignored.
    pub pattern: String,
    pub requests_per_second: u64,
    pub burst: u64,
}

fn default_hot_uri_threshold() -> u64 {
    0
}

fn default_subnet_24_mul() -> u64 {
    8
}
fn default_subnet_16_mul() -> u64 {
    64
}
#[derive(Debug, Clone, Deserialize)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub suspicious_rps_threshold: u64,
    pub penalty_seconds: u64,
    /// Path patterns exempt from adaptive throttling. Same wildcard
    /// rules as rate-limit URI budgets — `/health`, `/metrics/*`.
    /// Lets monitoring / load-balancer probes hit at any rate without
    /// tripping the per-IP RPS guard.
    #[serde(default)]
    pub exempt_paths: Vec<String>,
}
impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            suspicious_rps_threshold: 200,
            penalty_seconds: 10,
            exempt_paths: Vec::new(),
        }
    }
}

/// One AND group in a compound WAF rule. The group matches when the
/// request's value for `field` op-matches ANY string in `any_of` (an OR
/// over the listed values, using the same `op` set custom rules already
/// support: "contains" | "equals" | "starts_with" | "ends_with").
///
/// A [`WafRule`] with a non-empty `all_of` fires only when its PRIMARY
/// `{field, op, value}` matches AND every group in `all_of` matches —
/// this is the AND-of-OR shape Sigma compound conditions need. Without
/// it (the historical default — empty `all_of`), the rule stays a plain
/// single-condition rule with byte-identical behaviour.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct WafAndGroup {
    pub field: String,
    pub op: String,
    pub any_of: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
pub struct WafRule {
    pub id: String,
    pub field: String,
    pub op: String,
    pub value: String,
    pub action: String,
    /// V109 — severity classification fed into [crate::ddos::risk_engine::WafSeverity].
    /// Values: "critical" | "high" | "medium" | "low". Defaults to
    /// "medium" when absent (pre-V109 rules read this way).
    #[serde(default)]
    pub severity: Option<String>,
    /// V109 — operator-supplied tags ("sqli", "xss", "wordpress-cve-2025-...").
    /// Surface in metrics + SecurityEvent logs, no enforcement effect.
    #[serde(default)]
    pub tags: Vec<String>,
    /// V109 — explicit numeric score contribution into the risk engine.
    /// When absent we derive from `severity`. Lets operators tune
    /// individual rules without changing severity.
    #[serde(default)]
    pub score: Option<u32>,
    /// V109 — rule operating mode. "enforce" (default) hits the
    /// rule's `action` field on match; "shadow" / "log" only counts
    /// the match in metrics without affecting the request;
    /// "disabled" skips the rule entirely (cheaper than removing it
    /// from the config when iterating). Operator drops new rules in
    /// shadow first, watches metrics for a week, then flips to
    /// enforce.
    #[serde(default)]
    pub mode: Option<String>,
    /// Compound (AND-of-OR) conditions. The rule fires only when its
    /// PRIMARY `{field, op, value}` matches AND every group here matches
    /// (each group is an OR over `any_of`). Empty (the default) keeps the
    /// rule a plain single-condition rule with unchanged behaviour. Lets
    /// the Sigma importer express real compound conditions
    /// (e.g. `method == POST` AND `path contains /admin`) instead of
    /// flattening them into independent — falsely broad — single rules.
    #[serde(default)]
    pub all_of: Vec<WafAndGroup>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    pub enabled: bool,
    #[serde(default)]
    pub custom_rules: Vec<WafRule>,
    pub max_body_bytes: Option<usize>,
    /// Extra TOML files containing `[[rules]]` entries; merged with
    /// `custom_rules` at startup and on reload.
    #[serde(default)]
    pub rule_files: Vec<String>,
    /// Built-in signature categories to skip. Valid values: "sqli",
    /// "xss", "cmdi". Useful when a category causes too many false
    /// positives in a particular environment.
    #[serde(default)]
    pub disable_signatures: Vec<String>,
    /// Reject any single header value longer than this many bytes
    /// (default 8 KiB). Defends against Range/Cookie/Referer flood
    /// attacks that try to exhaust memory or DoS the parser.
    #[serde(default = "default_max_header_value_bytes")]
    pub max_header_value_bytes: usize,
    /// Reject requests with more than this many headers (default 64).
    /// Hyper has its own cap but it's not exposed; this one is.
    #[serde(default = "default_max_header_count")]
    pub max_header_count: usize,
    /// Reject requests whose total URI (path + query) is longer than
    /// this many bytes. Default 8 KiB. Stops "very long URL" attacks
    /// against the upstream router and downstream apps that don't
    /// handle them well.
    #[serde(default = "default_max_uri_bytes")]
    pub max_uri_bytes: usize,
    /// Allowed HTTP methods. Default = the seven RFC-7231 methods. An
    /// empty list disables the filter (i.e. allow anything). Operators
    /// who don't use WebDAV / TRACE / CONNECT should leave this on —
    /// it stops a whole class of upstream-tunneling attacks.
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    /// Reject requests where Content-Length and Transfer-Encoding
    /// disagree (HTTP request-smuggling CL/TE / TE/TE / TE.CL). This
    /// is the defence for CVE classes like CVE-2019-18277 / Burp's
    /// HTTP Desync research. Default on; turn off only if you know
    /// you front a smuggling-tolerant upstream and have a reason.
    #[serde(default = "default_true")]
    pub block_smuggling: bool,
    /// Hard ceiling on compressed→decompressed body ratio for upstream
    /// responses (default 100×). Above this we treat the response as
    /// a decompression bomb and return 502 to the client. 0 disables
    /// the check.
    #[serde(default = "default_max_decompress_ratio")]
    pub max_decompress_ratio: u32,
}

fn default_max_header_value_bytes() -> usize {
    8 * 1024
}
fn default_max_header_count() -> usize {
    64
}
fn default_max_uri_bytes() -> usize {
    8 * 1024
}
fn default_allowed_methods() -> Vec<String> {
    vec!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_true() -> bool {
    true
}
fn default_max_decompress_ratio() -> u32 {
    100
}

#[cfg(test)]
pub fn default_allowed_methods_pub() -> Vec<String> {
    default_allowed_methods()
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            custom_rules: Vec::new(),
            max_body_bytes: None,
            rule_files: Vec::new(),
            disable_signatures: Vec::new(),
            max_header_value_bytes: default_max_header_value_bytes(),
            max_header_count: default_max_header_count(),
            max_uri_bytes: default_max_uri_bytes(),
            allowed_methods: default_allowed_methods(),
            block_smuggling: default_true(),
            max_decompress_ratio: default_max_decompress_ratio(),
        }
    }
}

/// Wire format for external WAF rule files. Each file is a TOML
/// document with a `rules = [...]` array of WafRule entries.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WafRuleFile {
    #[serde(default)]
    pub rules: Vec<WafRule>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct BotConfig {
    pub enabled: bool,
    pub challenge_score: u32,
    pub deny_score: u32,
    pub penalty_seconds: u64,
}
impl Default for BotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            challenge_score: 60,
            deny_score: 90,
            penalty_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeConfig {
    pub enabled: bool,
    pub token_ttl_secs: u64,
    pub hmac_secret: String,
    /// Optional Google reCAPTCHA v2 site key. When set, the captcha
    /// level renders a real <div class="g-recaptcha"> + script.
    #[serde(default)]
    pub captcha_site_key: Option<String>,
    /// Optional Google reCAPTCHA v2 secret. When set, /aegis-verify
    /// validates submitted g-recaptcha-response with Google before
    /// setting the verification cookie.
    #[serde(default)]
    pub captcha_secret: Option<String>,
    /// TTL (seconds) for the behavioural-fingerprint cookie. When the
    /// JS challenge captures a stable browser fingerprint (canvas +
    /// navigator + screen) we sign it into aegis_fp; subsequent
    /// requests with a valid cookie skip the challenge ladder for
    /// this long. Default 86400 = 24h. 0 disables the cookie entirely.
    #[serde(default = "default_fp_ttl_secs")]
    pub fp_ttl_secs: u64,
    /// Add `Secure` to challenge cookies so browsers refuse to send
    /// them over plain HTTP. Default on — the AEGIS data plane
    /// terminates TLS for protected sites, so the signed challenge /
    /// trust cookies (aegis_token, aegis_fp) should never travel over
    /// plain HTTP. Sites that mix HTTP and HTTPS upstreams must set this
    /// to false explicitly or the challenge breaks on HTTP pages.
    #[serde(default = "default_cookie_secure")]
    pub cookie_secure: bool,
}

fn default_fp_ttl_secs() -> u64 {
    86_400
}
/// M11 — Secure-by-default for challenge cookies. The AEGIS data plane
/// terminates TLS for protected sites, so signed challenge / trust
/// cookies must carry the `Secure` attribute unless an operator
/// explicitly opts out for mixed HTTP/HTTPS upstreams.
fn default_cookie_secure() -> bool {
    true
}
impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            // V230 — challenge ladder is opt-in per domain. Operators
            // turn it on via the web UI (per-`server{}` policy) for
            // sites that need browser verification. Defaulting it on
            // would challenge every client of every site — including
            // API and non-browser traffic — the moment a config omits
            // the `challenge_ladder` toggle.
            enabled: false,
            token_ttl_secs: 300,
            hmac_secret: "change_me".to_string(),
            captcha_site_key: None,
            captcha_secret: None,
            fp_ttl_secs: 86_400,
            // M11 — Secure-by-default; data plane terminates TLS.
            cookie_secure: true,
        }
    }
}

/// V233 — minimum acceptable length for an HMAC / signing secret.
/// Shorter secrets are brute-forceable offline once an attacker has a
/// single signed token to check guesses against.
const MIN_SIGNING_SECRET_LEN: usize = 16;

/// V233 — known-weak placeholder secrets. Compared case-insensitively.
/// A deployment that ships any of these is effectively using a
/// publicly-known signing key.
const WEAK_SIGNING_SECRETS: &[&str] =
    &["change_me", "changeme", "test-secret", "secret", "password"];

/// V233 — reject empty, placeholder, or too-short HMAC/signing secrets.
/// `field` is the dotted config path used in the error message so the
/// operator knows exactly which value to fix.
fn validate_signing_secret(field: &str, secret: &str) -> Result<()> {
    anyhow::ensure!(
        !secret.is_empty(),
        "{field} must not be empty; set a strong unique secret \
         (>= {MIN_SIGNING_SECRET_LEN} random chars)"
    );
    let lowered = secret.to_ascii_lowercase();
    anyhow::ensure!(
        !WEAK_SIGNING_SECRETS.contains(&lowered.as_str()),
        "{field} is set to a well-known placeholder value; \
         set a strong unique secret (>= {MIN_SIGNING_SECRET_LEN} random chars) \
         — anyone who reads the source can forge tokens otherwise"
    );
    anyhow::ensure!(
        secret.chars().count() >= MIN_SIGNING_SECRET_LEN,
        "{field} is too short ({} chars); use at least \
         {MIN_SIGNING_SECRET_LEN} random chars to resist brute force",
        secret.chars().count()
    );
    Ok(())
}

impl AppConfig {
    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw).context("failed to parse TOML config")?;
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<()> {
        for ip in self
            .filters
            .ip_acl
            .deny
            .iter()
            .chain(self.filters.ip_acl.allow.iter())
        {
            let _ = IpAddr::from_str(ip).with_context(|| format!("invalid ip in ACL: {ip}"))?;
        }
        anyhow::ensure!(
            self.server.request_timeout_ms > 0,
            "request_timeout_ms must be > 0"
        );
        anyhow::ensure!(
            self.server.graceful_shutdown_secs > 0,
            "graceful_shutdown_secs must be > 0"
        );
        anyhow::ensure!(
            self.upstream.url.starts_with("http://"),
            "only http:// upstream is supported in MVP"
        );
        // V233 — challenge.hmac_secret signs every challenge / trust
        // token. A blank, placeholder, or short secret means anyone who
        // reads the source (or guesses) can forge valid tokens. Reject
        // empty, known-weak placeholders (case-insensitive), and any
        // secret shorter than 16 chars.
        validate_signing_secret("challenge.hmac_secret", &self.filters.challenge.hmac_secret)?;
        if let Some(s) = &self.storage {
            anyhow::ensure!(
                s.redis_url.starts_with("redis://"),
                "storage.redis_url must start with redis://"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const MINIMAL: &str = r#"
[server]
listen = "0.0.0.0:8080"
request_timeout_ms = 1000
graceful_shutdown_secs = 5

[upstream]
url = "http://127.0.0.1:3000"

[filters]
default_action = "allow"

[filters.ip_acl]
deny = []
allow = []

[filters.rate_limit]
enabled = false
requests_per_second = 10
burst = 10

[filters.challenge]
enabled = true
token_ttl_secs = 60
hmac_secret = "s3cure-r4ndom-hmac-key-001"
"#;

    fn write_tmp(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("aegis-cfg-{}.toml", uuid_like()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    fn uuid_like() -> String {
        use std::time::SystemTime;
        format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[test]
    fn parses_minimal_config() {
        let p = write_tmp(MINIMAL);
        let cfg = AppConfig::from_path(&p).expect("parses");
        assert_eq!(cfg.server.listen, "0.0.0.0:8080");
        assert_eq!(cfg.filters.default_action, DefaultAction::Allow);
        std::fs::remove_file(&p).ok();
    }

    // M11 — challenge cookies must be Secure unless the operator
    // explicitly opts out. An omitted `cookie_secure` (as in MINIMAL)
    // and the struct Default must both resolve to true, since the data
    // plane terminates TLS for protected sites.
    #[test]
    fn cookie_secure_defaults_true() {
        assert!(ChallengeConfig::default().cookie_secure);
        let p = write_tmp(MINIMAL);
        let cfg = AppConfig::from_path(&p).expect("parses");
        assert!(cfg.filters.challenge.cookie_secure);
        std::fs::remove_file(&p).ok();
    }

    // M11 — an operator with mixed HTTP/HTTPS upstreams can still opt
    // out explicitly.
    #[test]
    fn cookie_secure_explicit_false_honoured() {
        let cfg = MINIMAL.replace(
            "hmac_secret = \"s3cure-r4ndom-hmac-key-001\"",
            "hmac_secret = \"s3cure-r4ndom-hmac-key-001\"\ncookie_secure = false",
        );
        let p = write_tmp(&cfg);
        let parsed = AppConfig::from_path(&p).expect("parses");
        assert!(!parsed.filters.challenge.cookie_secure);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_invalid_ip_in_acl() {
        let bad = MINIMAL.replace(
            "[filters.ip_acl]\ndeny = []\nallow = []",
            "[filters.ip_acl]\ndeny = [\"not-an-ip\"]\nallow = []",
        );
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_empty_hmac_secret() {
        let bad = MINIMAL.replace(
            "hmac_secret = \"s3cure-r4ndom-hmac-key-001\"",
            "hmac_secret = \"\"",
        );
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    // V233 — a config that ships the literal `change_me` placeholder
    // must be rejected so deployments can't run with a globally-known
    // signing key.
    #[test]
    fn rejects_placeholder_hmac_secret() {
        let bad = MINIMAL.replace(
            "hmac_secret = \"s3cure-r4ndom-hmac-key-001\"",
            "hmac_secret = \"change_me\"",
        );
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    // V233 — placeholder match is case-insensitive.
    #[test]
    fn rejects_placeholder_hmac_secret_mixed_case() {
        let bad = MINIMAL.replace(
            "hmac_secret = \"s3cure-r4ndom-hmac-key-001\"",
            "hmac_secret = \"ChangeMe\"",
        );
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    // V233 — a short (5-char) secret is brute-forceable and must fail.
    #[test]
    fn rejects_short_hmac_secret() {
        let bad = MINIMAL.replace(
            "hmac_secret = \"s3cure-r4ndom-hmac-key-001\"",
            "hmac_secret = \"abcde\"",
        );
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    // V233 — a strong, sufficiently-long, non-placeholder secret passes.
    #[test]
    fn accepts_strong_hmac_secret() {
        // MINIMAL already carries a 26-char non-placeholder secret.
        let p = write_tmp(MINIMAL);
        assert!(AppConfig::from_path(&p).is_ok());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_zero_timeout() {
        let bad = MINIMAL.replace("request_timeout_ms = 1000", "request_timeout_ms = 0");
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_non_redis_url() {
        let bad = format!("{MINIMAL}\n[storage]\nredis_url = \"http://nope\"\n");
        let p = write_tmp(&bad);
        assert!(AppConfig::from_path(&p).is_err());
        std::fs::remove_file(&p).ok();
    }
}
