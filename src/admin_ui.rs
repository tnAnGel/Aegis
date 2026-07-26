//! Embedded web admin UI + JSON API.
//!
//! Static HTML/CSS/JS are baked into the binary so the installer
//! doesn't need a separate frontend deploy. JSON endpoints under
//! `/admin/api/*` back the UI and live next to the existing plain-
//! text `/admin/*` endpoints used by `curl` and `systemctl reload`.
//!
//! Site CRUD writes to `/var/lib/aegis/sites.d/<host>.conf` — a
//! directory the `aegis` user owns. Operator-managed files in
//! `/etc/aegis/sites-enabled/` are surfaced read-only.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use include_dir::{Dir, include_dir};

/// React + Vite production bundle. Built by `pnpm build` in `web/` and
/// baked into the binary so the installer doesn't need a separate
/// frontend deploy. Hashed asset names (`assets/index-XXXX.js`) are
/// served verbatim from the embedded directory.
pub static WEB_DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/web/dist");

/// Look up a path inside the embedded React bundle. Strips the
/// `/admin/ui/` prefix and falls back to `index.html` for client-side
/// router routes (`/admin/ui/sites`, `/admin/ui/config`, …).
pub fn web_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    let rel = path.trim_start_matches("/admin/ui").trim_start_matches('/');
    let file = if rel.is_empty() {
        WEB_DIST.get_file("index.html")?
    } else {
        WEB_DIST
            .get_file(rel)
            .or_else(|| WEB_DIST.get_file("index.html"))?
    };
    let ct = match file.path().extension().and_then(|s| s.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    };
    Some((file.contents(), ct))
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteSummary {
    pub host: String,
    pub upstream: Option<String>,
    pub tls: bool,
    pub rate_limit: Option<RateLimitSummary>,
    /// `true` when the site lives in the UI-managed directory (writable).
    /// `false` when it's in the operator-managed sites-enabled/.
    pub managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSummary {
    pub rps: u64,
    pub burst: u64,
}

#[derive(Debug, Deserialize)]
pub struct NewSite {
    pub host: String,
    pub upstream: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub h3: bool,
    pub ssl_cert: Option<String>,
    pub ssl_key: Option<String>,
    pub rate_limit: Option<RateLimitSummary>,
}

/// Validate `host` to refuse anything that could escape the managed
/// directory or break the filename. Letters, digits, dot, dash,
/// underscore. No leading dot, no slashes.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 {
        return Err("host must be 1..=253 characters".into());
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err("host cannot start or end with a dot".into());
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err("host may only contain letters, digits, '.', '-', '_'".into());
    }
    Ok(())
}

fn validate_path_field(value: &str, what: &str) -> Result<(), String> {
    // Cert/key paths are stored verbatim in the generated DSL file.
    // Refuse newlines (would break the .conf), backticks and `;` to
    // make accidental shell-style injection harder. Operators that
    // really need exotic paths can edit the .conf directly.
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{what} cannot contain newlines"));
    }
    if value.contains(';') || value.contains('{') || value.contains('}') {
        return Err(format!("{what} cannot contain ';', '{{' or '}}'"));
    }
    Ok(())
}

/// V233: classify a literal IP as unsafe for an upstream target.
/// Loopback, link-local (incl. the cloud metadata range 169.254/16),
/// and RFC1918 / RFC4193 private ranges are all refused — connecting
/// there is SSRF (metadata credential theft, hitting the admin port,
/// reaching internal services). `unspecified` (0.0.0.0, ::) is also
/// refused since it routes to localhost on many stacks.
fn ip_is_internal(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()  // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254.0.0/16 (metadata endpoint)
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast() // 255.255.255.255
                // 100.64.0.0/10 carrier-grade NAT — `is_shared` is
                // unstable, so test the prefix by hand.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback()        // ::1
                || v6.is_unspecified() // ::
                // RFC4193 unique-local fc00::/7 and RFC4291
                // link-local fe80::/10. `is_unique_local` /
                // `is_unicast_link_local` are unstable on stable
                // Rust, so match the prefixes directly.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
            {
                return true;
            }
            // IPv4-mapped (::ffff:a.b.c.d): unwrap and re-check.
            if let Some(m) = v6.to_ipv4_mapped() {
                return ip_is_internal(IpAddr::V4(m));
            }
            // IPv4-compatible (deprecated) ::a.b.c.d — the high 96
            // bits are zero. `to_ipv4()` is deprecated, so detect the
            // form by hand from the segments.
            let seg = v6.segments();
            if seg[0..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && seg[7] <= 1) {
                let v4 = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                return ip_is_internal(IpAddr::V4(v4));
            }
            false
        }
    }
}

/// V233: validate the admin-API-supplied upstream URL before it is
/// written verbatim into `proxy_pass {upstream};`. Beyond the scheme
/// check this rejects SSRF targets: the value is parsed enough to
/// isolate the authority, embedded userinfo is refused, and a literal
/// host IP is range-checked. Hostnames are screened against obvious
/// internal names and the literal metadata addresses.
///
/// Residual: a public hostname that resolves (now or later, via
/// DNS rebinding) to an internal address is not caught here — that
/// needs a resolve-at-connect-time check in the proxy path.
fn validate_upstream(u: &str) -> Result<(), String> {
    if !u.starts_with("http://") && !u.starts_with("https://") {
        return Err("upstream must start with http:// or https://".into());
    }
    validate_path_field(u, "upstream URL")?;

    // V233: any whitespace produces a broken `proxy_pass http://a b;`
    // that fails the *entire* next config reload — refuse it outright.
    if u.chars().any(|c| c.is_whitespace()) {
        return Err("upstream URL cannot contain whitespace".into());
    }

    // V233: isolate the authority. Strip the scheme, then everything
    // from the first '/', '?' or '#' is path/query/fragment.
    let after_scheme = u
        .strip_prefix("http://")
        .or_else(|| u.strip_prefix("https://"))
        .unwrap_or(u);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        return Err("upstream URL is missing a host".into());
    }

    // V233: reject embedded userinfo (`http://user:pass@host`). An
    // attacker can hide the real target after the '@'.
    if let Some((_, host_part)) = authority.rsplit_once('@') {
        let _ = host_part;
        return Err("upstream URL cannot contain userinfo ('@')".into());
    }

    // V233: split off the port to leave a bare host. IPv6 literals
    // are bracketed (`[::1]:8080`); handle that form explicitly.
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // `[v6]` or `[v6]:port`
        let close = rest
            .find(']')
            .ok_or("upstream URL has an unterminated IPv6 literal")?;
        &rest[..close]
    } else {
        // host or host:port — a bare IPv6 with multiple ':' has no
        // brackets and is rejected below as an unparseable host.
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        return Err("upstream URL is missing a host".into());
    }

    // V233: if the host is a literal IP, range-check it.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip_is_internal(ip) {
            return Err(format!(
                "upstream host {host} is an internal/loopback address (SSRF blocked)"
            ));
        }
        return Ok(());
    }

    // V233: not a literal IP — treat as a hostname. A full
    // DNS-resolve-and-check would need an async resolver; at minimum
    // refuse obvious internal names. DNS rebinding remains a residual.
    let lower = host.to_ascii_lowercase();
    let internal_name = lower == "localhost"
        || lower.ends_with(".localhost")
        || lower == "localhost.localdomain"
        || lower == "ip6-localhost"
        || lower == "metadata"               // GCP metadata.google.internal short form
        || lower == "metadata.google.internal"
        || lower.ends_with(".internal")
        || lower.ends_with(".local");
    if internal_name {
        return Err(format!(
            "upstream host {host} is an internal hostname (SSRF blocked)"
        ));
    }
    Ok(())
}

/// Render a single site to a complete DSL `.conf` snippet. The output
/// is a standalone file that can be parsed back by `include` from the
/// main config.
pub fn render_site(site: &NewSite) -> Result<String, String> {
    validate_host(&site.host)?;
    validate_upstream(&site.upstream)?;
    if site.tls {
        let cert = site
            .ssl_cert
            .as_deref()
            .ok_or("ssl_cert is required when tls is enabled")?;
        let key = site
            .ssl_key
            .as_deref()
            .ok_or("ssl_key is required when tls is enabled")?;
        validate_path_field(cert, "ssl_cert")?;
        validate_path_field(key, "ssl_key")?;
    }
    if site.h3 && !site.tls {
        return Err("HTTP/3 requires TLS".into());
    }
    let mut out = String::new();
    out.push_str(&format!(
        "# Managed by Aegis admin UI — host: {}\n",
        site.host
    ));
    out.push_str(&format!("# Generated at: {}\n", chrono_now_rfc3339()));
    out.push_str("server {\n");
    out.push_str("    listen 0.0.0.0:80;\n");
    if site.tls {
        let modifiers = if site.h3 {
            "ssl http2 http3"
        } else {
            "ssl http2"
        };
        out.push_str(&format!("    listen 0.0.0.0:443 {modifiers};\n"));
    }
    out.push_str(&format!("    server_name {};\n", site.host));
    if site.tls {
        out.push_str(&format!(
            "    ssl_certificate     {};\n",
            site.ssl_cert.as_deref().unwrap_or("")
        ));
        out.push_str(&format!(
            "    ssl_certificate_key {};\n",
            site.ssl_key.as_deref().unwrap_or("")
        ));
    }
    out.push_str(&format!("    proxy_pass {};\n", site.upstream));
    if let Some(rl) = &site.rate_limit
        && rl.rps > 0
        && rl.burst > 0
    {
        out.push_str("\n    rate_limit {\n");
        out.push_str(&format!("        requests_per_second {};\n", rl.rps));
        out.push_str(&format!("        burst {};\n", rl.burst));
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    Ok(out)
}

fn chrono_now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix={secs}")
}

/// Write the site to `<managed_dir>/<host>.conf`, atomically (write
/// to a temp file then rename) so a partial write can't desync the
/// next reload.
pub fn write_site(managed_dir: &Path, site: &NewSite) -> Result<PathBuf, String> {
    let content = render_site(site)?;
    fs::create_dir_all(managed_dir).map_err(|e| format!("mkdir {}: {e}", managed_dir.display()))?;
    let final_path = managed_dir.join(format!("{}.conf", site.host));
    let tmp = managed_dir.join(format!(".{}.conf.tmp", site.host));
    fs::write(&tmp, content).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &final_path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), final_path.display()))?;
    Ok(final_path)
}

pub fn delete_site(managed_dir: &Path, host: &str) -> Result<(), String> {
    validate_host(host)?;
    let path = managed_dir.join(format!("{host}.conf"));
    if !path.exists() {
        return Err(format!("no managed site for {host}"));
    }
    fs::remove_file(&path).map_err(|e| format!("remove {}: {e}", path.display()))
}

/// List sites by scanning both the UI-managed dir and the ops dir.
/// We parse each `.conf` with the regular DSL parser so the same
/// validation pass that aegis uses at startup vets summary data.
pub fn list_sites(managed_dir: Option<&Path>, ops_dir: Option<&Path>) -> Vec<SiteSummary> {
    let mut all: BTreeMap<String, SiteSummary> = BTreeMap::new();
    if let Some(dir) = ops_dir {
        scan_dir_into(dir, false, &mut all);
    }
    if let Some(dir) = managed_dir {
        scan_dir_into(dir, true, &mut all);
    }
    all.into_values().collect()
}

fn scan_dir_into(dir: &Path, managed: bool, into: &mut BTreeMap<String, SiteSummary>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("conf") {
            continue;
        }
        if let Ok(ast) = crate::dsl::parser::parse_file(&path) {
            for srv in &ast.servers {
                for host in &srv.server_names {
                    let tls = srv.listens.iter().any(|l| l.ssl);
                    let rate_limit =
                        srv.rate_limit
                            .and_then(|r| match (r.requests_per_second, r.burst) {
                                (Some(rps), Some(burst)) => Some(RateLimitSummary { rps, burst }),
                                _ => None,
                            });
                    into.insert(
                        host.clone(),
                        SiteSummary {
                            host: host.clone(),
                            upstream: srv.proxy_pass.clone(),
                            tls,
                            rate_limit,
                            managed,
                        },
                    );
                }
            }
        }
    }
}

/// Tail the last N lines of the audit log file (best-effort, returns
/// empty string when the file isn't configured / readable).
pub fn tail_audit(path: &Path, last_n: usize) -> String {
    let Ok(content) = fs::read_to_string(path) else {
        return String::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(last_n);
    let mut out = String::new();
    for line in &lines[start..] {
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmpdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "aegis-ui-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn host_validation_rejects_path_escape() {
        assert!(validate_host("..").is_err());
        assert!(validate_host("/etc/passwd").is_err());
        assert!(validate_host("a/b").is_err());
        assert!(validate_host("foo bar").is_err());
        assert!(validate_host(".leading").is_err());
        assert!(validate_host("trailing.").is_err());
        assert!(validate_host("").is_err());
        assert!(validate_host("good.example.com").is_ok());
    }

    #[test]
    fn render_minimal_plain_site() {
        // V233: upstream must be a public address — loopback is
        // refused by validate_upstream as an SSRF target.
        let site = NewSite {
            host: "blog.example.com".into(),
            upstream: "http://origin.example.com:3003".into(),
            tls: false,
            h3: false,
            ssl_cert: None,
            ssl_key: None,
            rate_limit: None,
        };
        let s = render_site(&site).unwrap();
        assert!(s.contains("server_name blog.example.com"));
        assert!(s.contains("proxy_pass http://origin.example.com:3003"));
        assert!(!s.contains("ssl_certificate"));
    }

    #[test]
    fn render_tls_site() {
        // V233: public upstream — loopback would be rejected.
        let site = NewSite {
            host: "api.example.com".into(),
            upstream: "http://backend.example.com:3001".into(),
            tls: true,
            h3: true,
            ssl_cert: Some("/etc/aegis/certs/api.crt".into()),
            ssl_key: Some("/etc/aegis/certs/api.key".into()),
            rate_limit: Some(RateLimitSummary { rps: 20, burst: 50 }),
        };
        let s = render_site(&site).unwrap();
        assert!(s.contains("listen 0.0.0.0:443 ssl http2 http3"));
        assert!(s.contains("ssl_certificate     /etc/aegis/certs/api.crt"));
        assert!(s.contains("requests_per_second 20"));
    }

    #[test]
    fn render_h3_without_tls_errors() {
        let site = NewSite {
            host: "x".into(),
            upstream: "http://x".into(),
            tls: false,
            h3: true,
            ssl_cert: None,
            ssl_key: None,
            rate_limit: None,
        };
        assert!(render_site(&site).is_err());
    }

    #[test]
    fn render_tls_without_cert_errors() {
        let site = NewSite {
            host: "x".into(),
            upstream: "http://x".into(),
            tls: true,
            h3: false,
            ssl_cert: None,
            ssl_key: None,
            rate_limit: None,
        };
        assert!(render_site(&site).is_err());
    }

    #[test]
    fn upstream_must_be_http_url() {
        let site = NewSite {
            host: "x".into(),
            upstream: "ssh://x".into(),
            tls: false,
            h3: false,
            ssl_cert: None,
            ssl_key: None,
            rate_limit: None,
        };
        assert!(render_site(&site).is_err());
    }

    // V233: SSRF guard — internal/loopback upstreams are refused.
    #[test]
    fn upstream_rejects_cloud_metadata_endpoint() {
        assert!(validate_upstream("http://169.254.169.254").is_err());
        // Common metadata path form.
        assert!(validate_upstream("http://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn upstream_rejects_admin_port_on_loopback() {
        assert!(validate_upstream("http://127.0.0.1:9090").is_err());
        assert!(validate_upstream("https://127.0.0.1:9090").is_err());
        assert!(validate_upstream("http://[::1]:9090").is_err());
    }

    #[test]
    fn upstream_rejects_rfc1918_private() {
        assert!(validate_upstream("http://10.0.0.5").is_err());
        assert!(validate_upstream("http://192.168.1.1").is_err());
        assert!(validate_upstream("http://172.16.0.1").is_err());
        // IPv4-mapped IPv6 of a private address must also be caught.
        assert!(validate_upstream("http://[::ffff:10.0.0.5]").is_err());
        // RFC4193 unique-local IPv6.
        assert!(validate_upstream("http://[fc00::1]").is_err());
    }

    #[test]
    fn upstream_rejects_whitespace_reload_dos() {
        // A space yields a broken `proxy_pass http://a b;` that would
        // fail the whole next config reload.
        assert!(validate_upstream("http://a b").is_err());
        assert!(validate_upstream("http://host /path").is_err());
        assert!(validate_upstream("http://host\t8080").is_err());
    }

    #[test]
    fn upstream_rejects_userinfo() {
        // Userinfo can hide the real target after the '@'.
        assert!(validate_upstream("http://user@evil.example.com").is_err());
        assert!(validate_upstream("http://user:pass@169.254.169.254").is_err());
    }

    #[test]
    fn upstream_rejects_internal_hostnames() {
        assert!(validate_upstream("http://localhost").is_err());
        assert!(validate_upstream("http://localhost:8080").is_err());
        assert!(validate_upstream("http://db.internal").is_err());
        assert!(validate_upstream("http://printer.local").is_err());
        assert!(validate_upstream("http://metadata.google.internal").is_err());
    }

    #[test]
    fn upstream_accepts_normal_public_targets() {
        assert!(validate_upstream("http://origin.example.com").is_ok());
        assert!(validate_upstream("https://api.example.com:8443/v1").is_ok());
        assert!(validate_upstream("http://backend.example.com:3001").is_ok());
        // A public literal IP is fine.
        assert!(validate_upstream("http://93.184.216.34").is_ok());
        assert!(validate_upstream("http://[2606:2800:220:1::1]:80").is_ok());
    }

    #[test]
    fn injection_attempts_in_paths_rejected() {
        let site = NewSite {
            host: "x".into(),
            upstream: "http://x".into(),
            tls: true,
            h3: false,
            ssl_cert: Some("/etc/x;\nrm -rf /".into()),
            ssl_key: Some("/etc/y".into()),
            rate_limit: None,
        };
        assert!(render_site(&site).is_err());
    }

    #[test]
    fn write_then_list_roundtrips() {
        let dir = tmpdir();
        // V233: public upstream — loopback would be rejected.
        let site = NewSite {
            host: "x.example.com".into(),
            upstream: "http://upstream.example.com:9999".into(),
            tls: false,
            h3: false,
            ssl_cert: None,
            ssl_key: None,
            rate_limit: None,
        };
        write_site(&dir, &site).unwrap();
        let sites = list_sites(Some(&dir), None);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].host, "x.example.com");
        assert!(sites[0].managed);
        delete_site(&dir, "x.example.com").unwrap();
        assert!(list_sites(Some(&dir), None).is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_missing_site_errors() {
        let dir = tmpdir();
        assert!(delete_site(&dir, "nope.example.com").is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
