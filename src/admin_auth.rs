//! Role-based admin token authentication and an append-only audit log.
//!
//! Tokens come from two places that are merged at startup:
//! - `AEGIS_ADMIN_TOKEN` env var → implicit `Admin` role (backwards compat)
//! - `[[admin.tokens]]` config entries with explicit `role`
//!
//! Each `/admin/*` request is matched in constant time against the
//! configured tokens and the resulting role gates the endpoint.

use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::config::{AdminRole, AdminTokenEntry};

#[derive(Clone)]
pub struct TokenRegistry {
    entries: Arc<Vec<TokenEntry>>,
}

struct TokenEntry {
    token: String,
    role: AdminRole,
}

impl TokenRegistry {
    pub fn from_sources(env_token: Option<String>, config_tokens: &[AdminTokenEntry]) -> Self {
        let mut entries = Vec::with_capacity(config_tokens.len() + 1);
        if let Some(t) = env_token
            && !t.is_empty()
        {
            entries.push(TokenEntry {
                token: t,
                role: AdminRole::Admin,
            });
        }
        for cfg in config_tokens {
            if cfg.token.is_empty() {
                continue;
            }
            entries.push(TokenEntry {
                token: cfg.token.clone(),
                role: cfg.role,
            });
        }
        Self {
            entries: Arc::new(entries),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve a supplied token to its role. Constant-time compares each
    /// configured token; returns the strongest matching role or None if
    /// no token matches.
    pub fn authenticate(&self, supplied: &str) -> Option<AdminRole> {
        let mut best: Option<AdminRole> = None;
        for entry in self.entries.iter() {
            if constant_time_eq(supplied.as_bytes(), entry.token.as_bytes()) {
                best = Some(match best {
                    Some(prev) if prev >= entry.role => prev,
                    _ => entry.role,
                });
            }
        }
        best
    }
}

// V233 — `pub(crate)` so `web_admin.rs` can reuse this for session-token
// comparison (was private; session tokens compared with `String ==`,
// a byte-by-byte short-circuiting compare = remote timing oracle).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Audit logger. Always emits a tracing event (target `aegis::audit`)
/// and, if a path was configured, appends a JSON line to the file.
#[derive(Clone)]
pub struct AuditLog {
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Self {
        let file = path.and_then(|p| match OpenOptions::new().create(true).append(true).open(&p) {
            Ok(f) => Some(Arc::new(Mutex::new(f))),
            Err(e) => {
                tracing::warn!(error = %e, path = %p.display(), "failed to open audit log file");
                None
            }
        });
        Self { file }
    }

    /// Skip read-only polling traffic and SPA asset loads — the
    /// React panel hits /metrics, /admin/api/runtime/status,
    /// /admin/api/audit, /admin/api/me etc every few seconds and
    /// writing each one would flood the audit log with no security
    /// value. Mutating verbs and auth events still get recorded.
    fn is_audit_worthy(method: &str, path: &str) -> bool {
        if path.starts_with("/admin/ui") || path == "/" {
            return false;
        }
        // GET requests are read-only telemetry. The two interesting
        // exceptions (login, logout, change-credentials) are POSTs
        // and fall through to `true` below.
        if method == "GET" {
            return false;
        }
        true
    }

    pub fn record(
        &self,
        peer: &str,
        method: &str,
        path: &str,
        role: Option<AdminRole>,
        status: u16,
    ) {
        if !Self::is_audit_worthy(method, path) {
            return;
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let role_str = role
            .map(|r| format!("{r:?}").to_lowercase())
            .unwrap_or_else(|| "anonymous".to_string());
        tracing::info!(
            target: "aegis::audit",
            ts,
            peer,
            method,
            path,
            role = %role_str,
            status,
            "admin action"
        );
        if let Some(file) = &self.file {
            let line = format!(
                "{{\"ts\":{ts},\"peer\":\"{peer}\",\"method\":\"{method}\",\"path\":\"{path}\",\"role\":\"{role_str}\",\"status\":{status}}}\n"
            );
            if let Ok(mut f) = file.lock() {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

/// Required role for an admin endpoint, expressed as the minimum
/// privilege level that may invoke it.
pub fn required_role_for(method: &str, path: &str) -> Option<AdminRole> {
    match (method, path) {
        ("GET", "/metrics") => None, // metrics are public
        ("GET", "/admin/health")
        | ("GET", "/admin/threats")
        | ("GET", "/admin/xdp")
        | ("GET", "/admin/hot_uris")
        | ("GET", "/admin/anomaly")
        // Cache observability endpoints — Read role. Previously
        // unmatched → public; the admin port is bound to localhost
        // in production so external attackers can't reach them, but
        // belt-and-braces beats relying on the operator getting that
        // bind right. Mirrors the hyper handler's actual surface.
        | ("GET", "/admin/cache")
        | ("GET", "/admin/cache/dump") => Some(AdminRole::Read),
        // Cache + WAF mutations — Write role. Same reasoning.
        ("POST", "/admin/cache/purge")
        | ("POST", "/admin/waf/reload")
        | ("POST", "/admin/shared_scorer/compact")
        | ("POST", "/admin/signature_mine") => Some(AdminRole::Write),
        // Web UI assets — public, the JSON API underneath enforces auth.
        ("GET", p) if p == "/" || p == "/admin/ui" || p.starts_with("/admin/ui/") => None,
        // Auth endpoints — explicitly None so a logged-out client can
        // hit them. The handler does its own validation.
        ("POST", "/admin/api/login")
        | ("POST", "/admin/api/logout")
        | ("POST", "/admin/api/change-credentials")
        | ("GET", "/admin/api/me") => None,
        // TS — time-series metrics query. Read role (observability only,
        // no state mutation). Listed explicitly before the catch-all so
        // the role is unambiguous and testable without relying on pattern
        // ordering.
        ("GET", "/admin/api/metrics/series") => Some(AdminRole::Read),
        ("GET", "/admin/api/geo/top") => Some(AdminRole::Read),
        // JSON API: per-endpoint role enforced inside handle_api_route.
        // Surface as Read here so the auth gate doesn't reject reads;
        // writes get re-checked at the route level.
        ("GET", p) if p.starts_with("/admin/api/") => Some(AdminRole::Read),
        ("POST", p) if p.starts_with("/admin/api/sites") => Some(AdminRole::Write),
        ("PUT", p) if p.starts_with("/admin/api/sites/") => Some(AdminRole::Write),
        ("DELETE", p) if p.starts_with("/admin/api/sites/") => Some(AdminRole::Write),
        // V160 — runtime filter toggles + V162 per-domain policy CRUD.
        ("PUT", "/admin/api/defaults/filters") => Some(AdminRole::Write),
        ("PUT", p) if p.starts_with("/admin/api/config/") => Some(AdminRole::Write),
        // V-env — POST /admin/api/config/apply restarts the service → Write.
        // This arm MUST precede the prefix catch-all below which maps POST
        // /admin/api/config/* to Read (that catch-all covers test/raw ops).
        ("POST", "/admin/api/config/apply")   => Some(AdminRole::Write),
        ("POST", p) if p.starts_with("/admin/api/config/") => Some(AdminRole::Read),
        // V-env — env-file feature-flag toggle + service restart.
        // GET /env is Read; PUT /env and restart are Write.
        ("GET",  "/admin/api/env")            => Some(AdminRole::Read),
        ("PUT",  "/admin/api/env")            => Some(AdminRole::Write),
        ("POST", "/admin/api/restart")        => Some(AdminRole::Write),
        ("PUT", p) if p.starts_with("/admin/api/honeypots") => Some(AdminRole::Write),
        ("DELETE", p) if p.starts_with("/admin/api/honeypots/") => Some(AdminRole::Write),
        ("POST", p) if p.starts_with("/admin/xdp/deny/") || p.starts_with("/admin/xdp/undeny/") => {
            Some(AdminRole::Write)
        }
        ("POST", "/admin/reload") | ("POST", "/admin/stop") => Some(AdminRole::Admin),
        // V240 — benchmark/run is a fire-and-forget trigger that only reads
        // hardware facts + runs CPU/memory work. Read role is sufficient —
        // it does not mutate any config or stored state.
        ("POST", "/admin/api/benchmark/run") => Some(AdminRole::Read),
        // V241 — flood-capacity suite. Like benchmark/run it mutates no config;
        // it only spins up bounded loopback victim servers + load generators.
        // Read role is sufficient (GET result is covered by the Read catch-all).
        ("POST", "/admin/api/benchmark/flood/run") => Some(AdminRole::Read),
        // ACME / Let's Encrypt endpoints.
        // GET arms are already covered by the `GET /admin/api/` Read catch-all
        // above. Explicit arms here make the role unambiguous and testable.
        // PUT /admin/api/acme/config MUST be listed before any /admin/api/acme/*
        // prefix arm so the specific path wins.
        ("GET",  "/admin/api/acme/config")  => Some(AdminRole::Read),
        ("PUT",  "/admin/api/acme/config")  => Some(AdminRole::Write),
        ("GET",  "/admin/api/acme/orders")  => Some(AdminRole::Read),
        ("POST", "/admin/api/acme/orders")  => Some(AdminRole::Write),
        // POST /admin/api/acme/orders/<host>/renew — Write role.
        ("POST", p) if p.starts_with("/admin/api/acme/orders/") && p.ends_with("/renew") => {
            Some(AdminRole::Write)
        }
        // GET /admin/api/acme/orders/<host> — Read role.
        ("GET",  p) if p.starts_with("/admin/api/acme/orders/") => Some(AdminRole::Read),
        // V232 — fail-closed default for admin-API mutations. Any
        // POST/PUT/DELETE under `/admin/api/` that isn't an explicit
        // public endpoint above (login / logout / change-credentials)
        // now requires the Write role. Previously such routes fell
        // through to `_ => None` and were served UNAUTHENTICATED — the
        // new `PUT /admin/api/topology` and the pre-existing
        // `POST /admin/api/challenge/attack-mode` were both exposed.
        // The explicit public `None` arms (login/logout/...) sit above
        // this and match first, so they keep working.
        ("POST" | "PUT" | "DELETE", p) if p.starts_with("/admin/api/") => {
            Some(AdminRole::Write)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(token: &str, role: AdminRole) -> AdminTokenEntry {
        AdminTokenEntry {
            token: token.to_string(),
            role,
        }
    }

    #[test]
    fn env_only_admin_token_authenticates() {
        let r = TokenRegistry::from_sources(Some("secret".to_string()), &[]);
        assert_eq!(r.authenticate("secret"), Some(AdminRole::Admin));
        assert_eq!(r.authenticate("wrong"), None);
    }

    #[test]
    fn config_tokens_get_their_role() {
        let r = TokenRegistry::from_sources(
            None,
            &[
                cfg("r", AdminRole::Read),
                cfg("w", AdminRole::Write),
                cfg("a", AdminRole::Admin),
            ],
        );
        assert_eq!(r.authenticate("r"), Some(AdminRole::Read));
        assert_eq!(r.authenticate("w"), Some(AdminRole::Write));
        assert_eq!(r.authenticate("a"), Some(AdminRole::Admin));
    }

    #[test]
    fn duplicate_token_picks_highest_role() {
        let r = TokenRegistry::from_sources(
            None,
            &[cfg("same", AdminRole::Read), cfg("same", AdminRole::Admin)],
        );
        assert_eq!(r.authenticate("same"), Some(AdminRole::Admin));
    }

    #[test]
    fn role_ordering() {
        assert!(AdminRole::Admin > AdminRole::Write);
        assert!(AdminRole::Write > AdminRole::Read);
    }

    #[test]
    fn endpoint_roles() {
        assert_eq!(required_role_for("GET", "/metrics"), None);
        assert_eq!(
            required_role_for("GET", "/admin/threats"),
            Some(AdminRole::Read)
        );
        assert_eq!(
            required_role_for("POST", "/admin/xdp/deny/1.2.3.4"),
            Some(AdminRole::Write)
        );
        assert_eq!(
            required_role_for("POST", "/admin/reload"),
            Some(AdminRole::Admin)
        );
    }

    #[test]
    fn v232_admin_api_mutations_fail_closed() {
        // The worker-topology endpoints: GET is a Read, PUT a Write —
        // PUT must NOT be public (it persists a state file).
        assert_eq!(
            required_role_for("GET", "/admin/api/topology"),
            Some(AdminRole::Read),
        );
        assert_eq!(
            required_role_for("PUT", "/admin/api/topology"),
            Some(AdminRole::Write),
            "PUT /admin/api/topology must require Write — never public",
        );
        // Regression lock for the pre-existing hole the V232 catch-all
        // closed: this POST used to fall through to `None` (public).
        assert_eq!(
            required_role_for("POST", "/admin/api/challenge/attack-mode"),
            Some(AdminRole::Write),
        );
        // Explicit public auth endpoints still bypass the catch-all.
        assert_eq!(required_role_for("POST", "/admin/api/login"), None);
        assert_eq!(required_role_for("POST", "/admin/api/logout"), None);
        // A hypothetical future mutation under /admin/api/ fails closed.
        assert_eq!(
            required_role_for("DELETE", "/admin/api/something-new"),
            Some(AdminRole::Write),
        );
    }

    #[test]
    fn acme_endpoint_roles() {
        // Config: GET = Read, PUT = Write.
        assert_eq!(
            required_role_for("GET", "/admin/api/acme/config"),
            Some(AdminRole::Read),
            "GET /admin/api/acme/config must be Read",
        );
        assert_eq!(
            required_role_for("PUT", "/admin/api/acme/config"),
            Some(AdminRole::Write),
            "PUT /admin/api/acme/config must be Write",
        );
        // Orders list: GET = Read.
        assert_eq!(
            required_role_for("GET", "/admin/api/acme/orders"),
            Some(AdminRole::Read),
        );
        // New order: POST = Write.
        assert_eq!(
            required_role_for("POST", "/admin/api/acme/orders"),
            Some(AdminRole::Write),
        );
        // Single order: GET = Read.
        assert_eq!(
            required_role_for("GET", "/admin/api/acme/orders/www.example.com"),
            Some(AdminRole::Read),
        );
        // Renew: POST = Write.
        assert_eq!(
            required_role_for("POST", "/admin/api/acme/orders/www.example.com/renew"),
            Some(AdminRole::Write),
        );
    }

    #[test]
    fn ts_metrics_series_role() {
        // GET /admin/api/metrics/series must require exactly Read — not public,
        // not Write, so a Read-role token is sufficient for dashboard charts.
        assert_eq!(
            required_role_for("GET", "/admin/api/metrics/series"),
            Some(AdminRole::Read),
            "GET /admin/api/metrics/series must be Read role",
        );
    }

    #[test]
    fn v_env_endpoint_roles() {
        // GET /env is Read-only.
        assert_eq!(
            required_role_for("GET", "/admin/api/env"),
            Some(AdminRole::Read),
            "GET /admin/api/env must be Read role",
        );
        // PUT /env and the two restart endpoints require Write.
        assert_eq!(
            required_role_for("PUT", "/admin/api/env"),
            Some(AdminRole::Write),
            "PUT /admin/api/env must require Write — it writes aegis.env",
        );
        assert_eq!(
            required_role_for("POST", "/admin/api/restart"),
            Some(AdminRole::Write),
            "POST /admin/api/restart must require Write — it restarts the service",
        );
        assert_eq!(
            required_role_for("POST", "/admin/api/config/apply"),
            Some(AdminRole::Write),
            "POST /admin/api/config/apply must require Write — it restarts the service",
        );
    }
}
