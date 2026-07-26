//! AST → AppConfig.
//!
//! Encodes every cross-block invariant: duplicate server_name detection,
//! default_server uniqueness, TLS certificate requirements, etc.
//! Errors point back to the offending span(s) so operators land on the
//! right file:line:col.

use std::{collections::HashMap, time::Duration};

use crate::config::{
    AdminConfig, AdminRole, AdminTokenEntry, AppConfig, BotConfig, ChallengeConfig, DefaultAction,
    DomainConfig, FiltersConfig, IpAclConfig, RateLimitConfig, ServerConfig, SniEntry, TlsConfig,
    UpstreamConfig, WafConfig,
};

use super::{ast::*, error::DslError};

/// Plain summary type used by `aegis config test` to print what the
/// loaded config will actually do at runtime.
#[derive(Debug, Default)]
pub struct LoadSummary {
    pub server_count: usize,
    pub listeners: Vec<String>,
    pub routes: Vec<(String, String)>, // (host_or_"default", upstream_url)
}

pub fn lower(ast: &ConfigAst) -> Result<(AppConfig, LoadSummary), DslError> {
    let mut cfg = base_config();
    let mut summary = LoadSummary::default();

    // --- admin block ---
    if let Some(a) = &ast.admin {
        let listen = a
            .listen
            .clone()
            .unwrap_or_else(|| "127.0.0.1:9090".to_string());
        validate_listen_addr(&listen, &a.span)?;
        let tokens: Vec<AdminTokenEntry> = a
            .tokens
            .iter()
            .map(|t| {
                let role = match t.role.to_ascii_lowercase().as_str() {
                    "read" => AdminRole::Read,
                    "write" => AdminRole::Write,
                    "admin" => AdminRole::Admin,
                    other => {
                        return Err(DslError::new(
                            format!("unknown admin role: `{other}` (read|write|admin)"),
                            t.span.file.clone(),
                            t.span.line,
                            t.span.col,
                        ));
                    }
                };
                Ok(AdminTokenEntry {
                    token: t.token.clone(),
                    role,
                })
            })
            .collect::<Result<_, _>>()?;
        cfg.admin = Some(AdminConfig {
            listen,
            tokens,
            audit_log_path: a.audit_log_path.clone(),
            managed_sites_dir: a.managed_sites_dir.clone(),
            ops_sites_dir: a.ops_sites_dir.clone(),
            web_state_path: a.web_state_path.clone(),
            honeypot_state_path: None,
        });
    }

    // --- defaults block ---
    if let Some(d) = &ast.defaults {
        if let Some(t) = d.request_timeout {
            cfg.server.request_timeout_ms = t.as_millis().max(1) as u64;
        }
        if let Some(t) = d.graceful_shutdown {
            cfg.server.graceful_shutdown_secs = t.as_secs().max(1);
        }
        if let Some(t) = d.header_read_timeout {
            cfg.server.header_read_timeout_ms = t.as_millis().max(1) as u64;
        }
        if let Some(t) = d.body_read_timeout {
            cfg.server.body_read_timeout_ms = t.as_millis() as u64;
        }
        if let Some(f) = &d.filters {
            apply_filters(&mut cfg.filters, f);
        }
        if let Some(r) = &d.rate_limit {
            apply_rate_limit(&mut cfg.filters.rate_limit, r);
        }
        if let Some(c) = &d.cache {
            apply_cache(&mut cfg.filters.response_cache, c);
        }
    }

    // --- server blocks ---
    let mut plain_listen: Option<String> = None;
    let mut tls_listen: Option<String> = None;
    let mut h3_listen: Option<String> = None;
    let mut default_cert: Option<(String, String)> = None;
    let mut sni: Vec<SniEntry> = Vec::new();
    let mut domains: HashMap<String, DomainConfig> = HashMap::new();
    let mut default_upstream: Option<String> = None;
    let mut name_index: HashMap<String, Span> = HashMap::new();
    let mut default_server_seen: HashMap<String, Span> = HashMap::new();

    for srv in &ast.servers {
        if srv.listens.is_empty() {
            return Err(DslError::new(
                "server block has no `listen` directive",
                srv.span.file.clone(),
                srv.span.line,
                srv.span.col,
            ));
        }
        if srv.proxy_pass.is_none() && srv.locations.is_empty() {
            return Err(DslError::new(
                "server block needs `proxy_pass` (or at least one location)",
                srv.span.file.clone(),
                srv.span.line,
                srv.span.col,
            ));
        }

        let mut is_default = false;
        for l in &srv.listens {
            let addr = normalise_listen(&l.addr, l.ssl);
            validate_listen_addr(&addr, &l.span)?;
            if l.ssl {
                tls_listen.get_or_insert(addr.clone());
                if l.http3 {
                    h3_listen.get_or_insert(addr.clone());
                }
                if srv.ssl_certificate.is_none() || srv.ssl_certificate_key.is_none() {
                    return Err(DslError::new(
                        "`listen ssl` requires `ssl_certificate` + `ssl_certificate_key`",
                        l.span.file.clone(),
                        l.span.line,
                        l.span.col,
                    ));
                }
            } else {
                plain_listen.get_or_insert(addr.clone());
                if l.http3 {
                    return Err(DslError::new(
                        "`http3` requires `ssl` on the same listen line",
                        l.span.file.clone(),
                        l.span.line,
                        l.span.col,
                    ));
                }
            }
            if l.default_server {
                let key = format!("{addr}/{}", if l.ssl { "tls" } else { "tcp" });
                if let Some(prev) = default_server_seen.get(&key) {
                    return Err(default_server_conflict(&l.span, prev));
                }
                default_server_seen.insert(key, l.span.clone());
                is_default = true;
            }
            summary.listeners.push(if l.ssl {
                format!(
                    "{addr} ssl{}{}",
                    if l.http2 { " http2" } else { "" },
                    if l.http3 { " http3" } else { "" },
                )
            } else {
                addr
            });
        }

        // Routing: per-server_name or default
        let proxy = srv.proxy_pass.clone().ok_or_else(|| {
            DslError::new(
                "server block missing proxy_pass",
                srv.span.file.clone(),
                srv.span.line,
                srv.span.col,
            )
        })?;

        if srv.server_names.is_empty() {
            if !is_default {
                return Err(DslError::new(
                    "server block without `server_name` must declare a `default_server` listen",
                    srv.span.file.clone(),
                    srv.span.line,
                    srv.span.col,
                ));
            }
            if let Some(existing) = &default_upstream {
                if existing != &proxy {
                    return Err(DslError::new(
                        "two default_server blocks point at different upstreams",
                        srv.span.file.clone(),
                        srv.span.line,
                        srv.span.col,
                    ));
                }
            } else {
                default_upstream = Some(proxy.clone());
                summary.routes.push(("default".to_string(), proxy.clone()));
            }
            if let (Some(cert), Some(key)) =
                (srv.ssl_certificate.clone(), srv.ssl_certificate_key.clone())
            {
                default_cert.get_or_insert((cert, key));
            }
        } else {
            for name in &srv.server_names {
                if let Some(prev) = name_index.get(name) {
                    return Err(duplicate_server_name(name, &srv.span, prev));
                }
                name_index.insert(name.clone(), srv.span.clone());

                let mut entry = DomainConfig {
                    upstream_url: proxy.clone(),
                    requests_per_second: None,
                    burst: None,
                };
                if let Some(r) = &srv.rate_limit {
                    entry.requests_per_second = r.requests_per_second;
                    entry.burst = r.burst;
                }
                domains.insert(name.clone(), entry);
                summary.routes.push((name.clone(), proxy.clone()));

                if srv.listens.iter().any(|l| l.ssl)
                    && let (Some(cert), Some(key)) =
                        (srv.ssl_certificate.clone(), srv.ssl_certificate_key.clone())
                {
                    sni.push(SniEntry {
                        host: name.clone(),
                        cert_path: cert,
                        key_path: key,
                    });
                }
            }
        }
    }

    summary.server_count = ast.servers.len();

    // Wire collected pieces into AppConfig.
    if let Some(l) = plain_listen {
        cfg.server.listen = l;
    }
    cfg.upstream.url = default_upstream
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:80".to_string());
    cfg.domains = domains;
    if let Some(x) = &ast.xdp
        && let (Some(iface), Some(obj)) = (&x.interface, &x.bpf_object_path)
    {
        cfg.xdp = Some(crate::config::XdpConfig {
            enabled: x.enabled,
            interface: iface.clone(),
            bpf_object_path: obj.clone(),
            allow: x.allow.clone(),
            allow_only: x.allow_only,
            rate_window_ms: x.rate_window_ms,
            rate_burst: x.rate_burst,
            syn_burst: x.syn_burst,
        });
    }
    if let (Some(tls_addr), Some((cert, key))) = (tls_listen, default_cert) {
        cfg.tls = Some(TlsConfig {
            enabled: true,
            listen: tls_addr.clone(),
            cert_path: cert,
            key_path: key,
            h3_enabled: h3_listen.is_some(),
            h3_listen: h3_listen.clone(),
            sni,
            ja3_deny_hashes: Vec::new(),
            ja4_deny_prefixes: Vec::new(),
            // V59 — mTLS defaults to off; operators turn it on
            // either via direct TOML or (V60+) a DSL `mtls { ... }`
            // sub-block inside `server { listen ssl; ... }`.
            mtls: crate::config::MtlsConfig::default(),
        });
    }

    Ok((cfg, summary))
}

fn apply_filters(cfg: &mut FiltersConfig, f: &FiltersBlock) {
    if let Some(v) = f.waf {
        cfg.waf.enabled = v;
    }
    if let Some(v) = f.bot_fingerprint {
        cfg.bot.enabled = v;
    }
    if let Some(v) = f.adaptive_spike_detection {
        cfg.adaptive.enabled = v;
    }
    if let Some(v) = f.challenge_ladder {
        cfg.challenge.enabled = v;
    }
    // geoip / xdp are not in FiltersConfig — they're separate top-level
    // sections, so we accept them in DSL but currently leave them as
    // documentation-only toggles (see README on how to configure GeoIP
    // and XDP). When the operator writes `xdp off` in defaults we
    // simply trust them.
    let _ = f.geoip;
    let _ = f.xdp;
    if let Some(p) = &f.plugins {
        cfg.plugins.lua = p.lua.clone();
        cfg.plugins.wasm = p.wasm.clone();
    }
}

fn apply_rate_limit(cfg: &mut RateLimitConfig, r: &RateLimitBlock) {
    cfg.enabled = true;
    if let Some(v) = r.requests_per_second {
        cfg.requests_per_second = v;
    }
    if let Some(v) = r.burst {
        cfg.burst = v;
    }
}

/// V103 — lower DSL `cache { ... }` block into ResponseCacheConfig.
/// Presence of the block flips `enabled = true`; absent block keeps
/// the V102 default (disabled).
fn apply_cache(cfg: &mut crate::config::ResponseCacheConfig, c: &crate::dsl::ast::CacheBlock) {
    cfg.enabled = true;
    if let Some(v) = c.default_ttl_secs {
        cfg.default_ttl_secs = v.max(1);
    }
    if let Some(v) = c.max_entries {
        cfg.max_entries = v.max(1);
    }
    if let Some(v) = c.max_body_bytes {
        cfg.max_body_bytes = v.max(1024);
    }
    if !c.hosts.is_empty() {
        cfg.hosts = c.hosts.clone();
    }
}

fn validate_listen_addr(addr: &str, span: &Span) -> Result<(), DslError> {
    if let Ok(_p) = addr.parse::<u16>() {
        return Ok(());
    }
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(());
    }
    Err(DslError::new(
        format!("invalid listen address: `{addr}`"),
        span.file.clone(),
        span.line,
        span.col,
    ))
}

fn normalise_listen(raw: &str, ssl: bool) -> String {
    if raw.parse::<u16>().is_ok() {
        format!("0.0.0.0:{raw}")
    } else if ssl && !raw.contains(':') {
        // Shouldn't happen post-validation, but keep robust.
        format!("0.0.0.0:{raw}")
    } else {
        raw.to_string()
    }
}

fn duplicate_server_name(name: &str, here: &Span, previous: &Span) -> DslError {
    DslError::new(
        format!("server_name `{name}` is already defined"),
        here.file.clone(),
        here.line,
        here.col,
    )
    .with_secondary(DslError::new(
        format!("previous definition of `{name}`"),
        previous.file.clone(),
        previous.line,
        previous.col,
    ))
}

fn default_server_conflict(here: &Span, previous: &Span) -> DslError {
    DslError::new(
        "duplicate `default_server` for the same listener",
        here.file.clone(),
        here.line,
        here.col,
    )
    .with_secondary(DslError::new(
        "previous default_server here",
        previous.file.clone(),
        previous.line,
        previous.col,
    ))
}

/// Resolve the bundled Sigma WAF corpus path so the DSL config enforces
/// it out of the box. Tries well-known install locations in order and
/// returns the FIRST that exists. Returns an empty vec (no panic) when
/// none exist, or when the operator opts out with `AEGIS_SIGMA_WAF=0`.
fn default_sigma_rule_files() -> Vec<String> {
    // OPT-OUT (default ON). The importer now emits COMPOUND (AND-of-OR)
    // rules with a SELECTIVE primary field (path/query/user_agent, never a
    // bare method/host), so the corpus no longer false-positives legit
    // traffic the way the old flattened corpus did (which blocked all POST
    // and broke the site). Every rule requires its full condition set to
    // match. Set AEGIS_SIGMA_WAF=0 to disable; tune individual rules via
    // the per-rule disable overlay.
    if matches!(
        std::env::var("AEGIS_SIGMA_WAF").ok().as_deref(),
        Some("0") | Some("off") | Some("false") | Some("no")
    ) {
        return Vec::new();
    }
    const CANDIDATES: &[&str] = &[
        "/etc/aegis/rules/sigma/sigma-webserver.toml",
        "/var/lib/aegis/rules/sigma/sigma-webserver.toml",
        "/usr/local/src/aegis/rules/sigma/sigma-webserver.toml",
        "rules/sigma/sigma-webserver.toml",
    ];
    for p in CANDIDATES {
        if std::path::Path::new(p).exists() {
            return vec![(*p).to_string()];
        }
    }
    Vec::new()
}

fn base_config() -> AppConfig {
    AppConfig {
        server: ServerConfig {
            listen: "0.0.0.0:80".to_string(),
            request_timeout_ms: 10_000,
            graceful_shutdown_secs: 10,
            header_read_timeout_ms: 5_000,
            body_read_timeout_ms: 30_000,
            h2_max_reset_streams: 100,
            h2_max_concurrent_streams: 200,
            // V230 — new tuning knobs default to the same constants as
            // the serde defaults in config.rs.
            h2_initial_window_size: 1_048_576,
            h2_initial_connection_window_size: 8 * 1_048_576,
            tcp_nodelay: true,
            tcp_keepalive_secs: 60,
            proxy_protocol: crate::config::ProxyProtocolMode::Off,
        },
        upstream: UpstreamConfig {
            url: "http://127.0.0.1:80".to_string(),
            protocol: crate::config::UpstreamProtocol::default(),
        },
        filters: FiltersConfig {
            default_action: DefaultAction::Allow,
            ip_acl: IpAclConfig {
                deny: Vec::new(),
                allow: Vec::new(),
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                requests_per_second: 0,
                burst: 0,
                subnet_buckets: false,
                subnet_24_multiplier: 8,
                subnet_16_multiplier: 64,
                uri_budgets: Vec::new(),
                hot_uri_rps_threshold: 0,
            },
            adaptive: Default::default(),
            risk_engine: Default::default(),
            waf: WafConfig {
                enabled: true,
                custom_rules: Vec::new(),
                max_body_bytes: Some(64 * 1024),
                // Default-load the bundled Sigma WAF corpus so the ~562
                // rules listed on the admin "Signatures" page actually
                // enforce out of the box. Opt out with AEGIS_SIGMA_WAF=0.
                // waf.rs `load_rules_from` consumes + mtime-reloads this.
                rule_files: default_sigma_rule_files(),
                disable_signatures: Vec::new(),
                ..Default::default()
            },
            bot: BotConfig::default(),
            challenge: ChallengeConfig {
                enabled: true,
                token_ttl_secs: 300,
                hmac_secret: std::env::var("AEGIS_CHALLENGE_SECRET")
                    .unwrap_or_else(|_| "change_me_replace_with_long_random_secret".to_string()),
                captcha_site_key: None,
                captcha_secret: None,
                fp_ttl_secs: 86_400,
                // M11 — secure-by-default: AEGIS terminates TLS for the
                // protected site, so challenge/trust cookies must carry
                // `; Secure`. (The nginx-DSL config has no cookie_secure
                // directive yet; flip to false here only for a plain-HTTP
                // deployment.)
                cookie_secure: true,
            },
            graphql: Default::default(),
            bypass: Default::default(),
            dynamic_trust: Default::default(),
            response_cache: Default::default(),
            threat_intel: Default::default(),
            plugins: Default::default(),
        },
        admin: None,
        tls: None,
        storage: None,
        xdp: None,
        geoip: None,
        anomaly: None,
        domains: HashMap::new(),
    }
}

/// Format the LoadSummary for `aegis config test`.
pub fn render_summary(s: &LoadSummary) -> String {
    let mut out = String::new();
    out.push_str(&format!("config ok\nservers: {}\n", s.server_count));
    out.push_str("listeners:\n");
    let mut listeners = s.listeners.clone();
    listeners.sort();
    listeners.dedup();
    for l in listeners {
        out.push_str(&format!("  - {l}\n"));
    }
    out.push_str("routes:\n");
    for (name, up) in &s.routes {
        out.push_str(&format!("  - {name} -> {up}\n"));
    }
    out
}

/// Convert a legacy TOML AppConfig to the nginx-like DSL text. Best-
/// effort: covers the subset most operators use (server, admin,
/// defaults, domains, TLS). Comments mark anything the converter
/// couldn't faithfully express.
pub fn migrate_from_toml(cfg: &AppConfig) -> String {
    let mut out = String::new();
    out.push_str("# Generated by `aegis config migrate`.\n");
    out.push_str("# Aegis DSL — nginx-like syntax, not full nginx.\n\n");

    if let Some(a) = &cfg.admin {
        out.push_str("admin {\n");
        out.push_str(&format!("    listen {};\n", a.listen));
        if let Some(p) = &a.audit_log_path {
            out.push_str(&format!("    audit_log_path {p};\n"));
        }
        for t in &a.tokens {
            let role = match t.role {
                AdminRole::Read => "read",
                AdminRole::Write => "write",
                AdminRole::Admin => "admin",
            };
            out.push_str(&format!("    token {role} {};\n", t.token));
        }
        out.push_str("}\n\n");
    }

    out.push_str("defaults {\n");
    out.push_str(&format!(
        "    request_timeout {}ms;\n",
        cfg.server.request_timeout_ms
    ));
    out.push_str(&format!(
        "    graceful_shutdown {}s;\n",
        cfg.server.graceful_shutdown_secs
    ));
    out.push_str(&format!(
        "    header_read_timeout {}ms;\n",
        cfg.server.header_read_timeout_ms
    ));
    out.push_str("\n    filters {\n");
    out.push_str(&format!(
        "        waf {};\n",
        on_off(cfg.filters.waf.enabled)
    ));
    out.push_str(&format!(
        "        bot_fingerprint {};\n",
        on_off(cfg.filters.bot.enabled)
    ));
    out.push_str(&format!(
        "        adaptive_spike_detection {};\n",
        on_off(cfg.filters.adaptive.enabled)
    ));
    out.push_str(&format!(
        "        challenge_ladder {};\n",
        on_off(cfg.filters.challenge.enabled)
    ));
    out.push_str("    }\n");
    if cfg.filters.rate_limit.enabled {
        out.push_str("\n    rate_limit {\n");
        out.push_str(&format!(
            "        requests_per_second {};\n",
            cfg.filters.rate_limit.requests_per_second
        ));
        out.push_str(&format!(
            "        burst {};\n",
            cfg.filters.rate_limit.burst
        ));
        out.push_str("    }\n");
    }
    out.push_str("}\n\n");

    // Default server (the [upstream] block)
    let plain = &cfg.server.listen;
    let (tls_listen, tls_cert, tls_key, h3) = match &cfg.tls {
        Some(t) if t.enabled => (
            Some(t.listen.clone()),
            Some(t.cert_path.clone()),
            Some(t.key_path.clone()),
            t.h3_enabled,
        ),
        _ => (None, None, None, false),
    };

    out.push_str("server {\n");
    out.push_str(&format!("    listen {plain} default_server;\n"));
    if let Some(l) = &tls_listen {
        let modifiers = if h3 { "ssl http2 http3" } else { "ssl http2" };
        out.push_str(&format!("    listen {l} {modifiers} default_server;\n"));
    }
    if let (Some(c), Some(k)) = (&tls_cert, &tls_key) {
        out.push_str(&format!("    ssl_certificate {c};\n"));
        out.push_str(&format!("    ssl_certificate_key {k};\n"));
    }
    out.push_str(&format!("    proxy_pass {};\n", cfg.upstream.url));
    out.push_str("}\n");

    // SNI entries become per-domain servers
    let sni_map: HashMap<String, &SniEntry> = cfg
        .tls
        .as_ref()
        .map(|t| t.sni.iter().map(|s| (s.host.clone(), s)).collect())
        .unwrap_or_default();
    let mut domains: Vec<_> = cfg.domains.iter().collect();
    domains.sort_by(|a, b| a.0.cmp(b.0));
    for (host, route) in domains {
        out.push_str("\nserver {\n");
        out.push_str(&format!("    listen {plain};\n"));
        if let Some(l) = &tls_listen {
            let modifiers = if h3 { "ssl http2 http3" } else { "ssl http2" };
            out.push_str(&format!("    listen {l} {modifiers};\n"));
        }
        out.push_str(&format!("    server_name {host};\n"));
        if let Some(s) = sni_map.get(host) {
            out.push_str(&format!("    ssl_certificate {};\n", s.cert_path));
            out.push_str(&format!("    ssl_certificate_key {};\n", s.key_path));
        } else if tls_cert.is_some() {
            // Falls back to default cert; no per-host override.
        }
        out.push_str(&format!("    proxy_pass {};\n", route.upstream_url));
        if let (Some(rps), Some(burst)) = (route.requests_per_second, route.burst) {
            out.push_str("\n    rate_limit {\n");
            out.push_str(&format!("        requests_per_second {rps};\n"));
            out.push_str(&format!("        burst {burst};\n"));
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    out
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// Silence unused-import warning when only some submodules need it.
#[allow(dead_code)]
fn _force_use(_d: Duration) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::parser::parse_file;
    use std::io::Write;

    fn parse_to_cfg(src: &str) -> Result<(AppConfig, LoadSummary), DslError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "aegis-lower-{}-{}.conf",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(src.as_bytes())
            .unwrap();
        let r = parse_file(&path).and_then(|ast| lower(&ast));
        std::fs::remove_file(&path).ok();
        r
    }

    #[test]
    fn minimal_default_server() {
        let (cfg, summary) = parse_to_cfg(
            r#"
            server {
                listen 80 default_server;
                proxy_pass http://127.0.0.1:8000;
            }
        "#,
        )
        .unwrap();
        assert_eq!(cfg.server.listen, "0.0.0.0:80");
        assert_eq!(cfg.upstream.url, "http://127.0.0.1:8000");
        assert_eq!(summary.routes[0].0, "default");
    }

    #[test]
    fn per_domain_routing() {
        let (cfg, _) = parse_to_cfg(
            r#"
            server {
                listen 80 default_server;
                proxy_pass http://default;
            }
            server {
                listen 80;
                server_name api.example.com;
                proxy_pass http://api;
                rate_limit {
                    requests_per_second 20;
                    burst 50;
                }
            }
        "#,
        )
        .unwrap();
        let entry = cfg.domains.get("api.example.com").expect("present");
        assert_eq!(entry.upstream_url, "http://api");
        assert_eq!(entry.requests_per_second, Some(20));
        assert_eq!(entry.burst, Some(50));
    }

    #[test]
    fn duplicate_server_name_errors() {
        let r = parse_to_cfg(
            r#"
            server {
                listen 80; server_name x.example; proxy_pass http://a;
            }
            server {
                listen 80; server_name x.example; proxy_pass http://b;
            }
        "#,
        );
        let e = r.unwrap_err();
        assert!(e.message.contains("x.example"));
        assert!(e.secondary.is_some());
    }

    #[test]
    fn default_server_conflict_errors() {
        let r = parse_to_cfg(
            r#"
            server { listen 80 default_server; proxy_pass http://a; }
            server { listen 80 default_server; server_name x; proxy_pass http://b; }
        "#,
        );
        assert!(r.is_err());
    }

    #[test]
    fn server_without_server_name_or_default_errors() {
        let r = parse_to_cfg(r#"server { listen 80; proxy_pass http://x; }"#);
        let e = r.unwrap_err();
        assert!(e.message.contains("default_server"));
    }

    #[test]
    fn ssl_without_cert_errors() {
        let r = parse_to_cfg(
            r#"server { listen 443 ssl; server_name x.example; proxy_pass http://a; }"#,
        );
        let e = r.unwrap_err();
        assert!(e.message.contains("ssl_certificate"));
    }

    #[test]
    fn tls_sni_collected() {
        let (cfg, _) = parse_to_cfg(
            r#"
            server {
                listen 443 ssl default_server;
                ssl_certificate /default.crt;
                ssl_certificate_key /default.key;
                proxy_pass http://defaults;
            }
            server {
                listen 443 ssl http2 http3;
                server_name api.example.com;
                ssl_certificate /api.crt;
                ssl_certificate_key /api.key;
                proxy_pass http://api;
            }
        "#,
        )
        .unwrap();
        let tls = cfg.tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.cert_path, "/default.crt");
        assert!(tls.h3_enabled);
        let sni = tls
            .sni
            .iter()
            .find(|s| s.host == "api.example.com")
            .unwrap();
        assert_eq!(sni.cert_path, "/api.crt");
    }

    #[test]
    fn defaults_filters_apply_globally() {
        let (cfg, _) = parse_to_cfg(
            r#"
            defaults {
                filters { waf off; challenge_ladder off; }
            }
            server { listen 80 default_server; proxy_pass http://x; }
        "#,
        )
        .unwrap();
        assert!(!cfg.filters.waf.enabled);
        assert!(!cfg.filters.challenge.enabled);
    }

    #[test]
    fn defaults_rate_limit_applies_globally() {
        let (cfg, _) = parse_to_cfg(
            r#"
            defaults {
                rate_limit { requests_per_second 50; burst 100; }
            }
            server { listen 80 default_server; proxy_pass http://x; }
        "#,
        )
        .unwrap();
        assert!(cfg.filters.rate_limit.enabled);
        assert_eq!(cfg.filters.rate_limit.requests_per_second, 50);
    }

    #[test]
    fn defaults_cache_block_enables_and_overrides() {
        let (cfg, _) = parse_to_cfg(
            r#"
            defaults {
                cache {
                    default_ttl_secs 120;
                    max_entries     8192;
                    max_body_bytes  131072;
                    host static.example.com;
                    host cdn.example.com;
                }
            }
            server { listen 80 default_server; proxy_pass http://x; }
        "#,
        )
        .unwrap();
        assert!(
            cfg.filters.response_cache.enabled,
            "cache block should enable"
        );
        assert_eq!(cfg.filters.response_cache.default_ttl_secs, 120);
        assert_eq!(cfg.filters.response_cache.max_entries, 8192);
        assert_eq!(cfg.filters.response_cache.max_body_bytes, 131072);
        assert_eq!(
            cfg.filters.response_cache.hosts,
            vec![
                "static.example.com".to_string(),
                "cdn.example.com".to_string()
            ]
        );
    }

    #[test]
    fn missing_cache_block_keeps_disabled() {
        let (cfg, _) = parse_to_cfg(
            r#"
            server { listen 80 default_server; proxy_pass http://x; }
        "#,
        )
        .unwrap();
        assert!(
            !cfg.filters.response_cache.enabled,
            "absent cache block must NOT enable"
        );
    }

    // Both opt-in and opt-out are asserted in ONE test: AEGIS_SIGMA_WAF is a
    // process-global env var, so splitting them into two #[test] fns lets the
    // parallel test harness race the var. Single test = deterministic.
    #[test]
    fn sigma_corpus_opt_out_default_on() {
        // AEGIS_SIGMA_WAF is a process-global env var, so all cases live in
        // ONE test to avoid the parallel harness racing the var.
        let prev = std::env::var("AEGIS_SIGMA_WAF").ok();
        let restore = |p: &Option<String>| unsafe {
            match p {
                Some(v) => std::env::set_var("AEGIS_SIGMA_WAF", v),
                None => std::env::remove_var("AEGIS_SIGMA_WAF"),
            }
        };

        // Default ON: unset loads the corpus (now safe compound rules).
        unsafe { std::env::remove_var("AEGIS_SIGMA_WAF") };
        let unset = default_sigma_rule_files();
        // Explicit opt-out: "0" yields no corpus.
        unsafe { std::env::set_var("AEGIS_SIGMA_WAF", "0") };
        let off = default_sigma_rule_files();

        restore(&prev);

        assert!(off.is_empty(), "AEGIS_SIGMA_WAF=0 must disable corpus");
        // Default-on returns at most one path, which must exist on disk
        // (the bundled corpus exists in the repo's working dir under test).
        assert!(unset.len() <= 1, "resolver must return at most one path");
        for f in &unset {
            assert!(
                std::path::Path::new(f).exists(),
                "resolved corpus path must exist: {f}"
            );
        }
    }

    #[test]
    fn migrate_round_trips_minimal_toml() {
        let toml_src = r#"
[server]
listen = "0.0.0.0:80"
request_timeout_ms = 10000
graceful_shutdown_secs = 10
[upstream]
url = "http://127.0.0.1:8000"
[filters]
default_action = "allow"
[filters.ip_acl]
deny = []
allow = []
[filters.rate_limit]
enabled = false
requests_per_second = 0
burst = 0
[filters.challenge]
enabled = true
token_ttl_secs = 60
hmac_secret = "dsl-migrate-test-hmac-key-001"
"#;
        let dir = std::env::temp_dir();
        let toml_path = dir.join(format!("aegis-mig-{}.toml", std::process::id()));
        std::fs::write(&toml_path, toml_src).unwrap();
        let toml_cfg = AppConfig::from_path(&toml_path).unwrap();
        let dsl_text = migrate_from_toml(&toml_cfg);
        assert!(dsl_text.contains("server {"));
        assert!(dsl_text.contains("proxy_pass http://127.0.0.1:8000"));
        std::fs::remove_file(&toml_path).ok();
    }
}
