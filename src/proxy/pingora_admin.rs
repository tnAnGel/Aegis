//! V27 + V36 — Admin endpoints for aegis-pingora.
//!
//! Pingora's `Server` is a multi-service host: each service is its own
//! listener + connection loop. We register this `AdminProxy` as a
//! second `http_proxy_service` on the admin port (default 127.0.0.1:9090,
//! `AEGIS_ADMIN_LISTEN` env-override or `admin.listen` in config).
//!
//! Public (no auth):
//!   • `GET /metrics`  — Prometheus text exposition of all
//!                       RuntimeMetrics + ResponseCache counters.
//!                       Format matches the hyper handler's /metrics.
//!   • `GET /health`   — Cheap liveness probe. Always returns 200
//!                       with body "ok". No upstream dependency.
//!
//! Authenticated (x-admin-token header, token from AEGIS_ADMIN_TOKEN
//! env-var or `admin.tokens` config block — same registry the hyper
//! path uses, with role gating from `required_role_for`):
//!   • `GET  /admin/cache`        — full cache stats text.
//!   • `GET  /admin/cache/dump`   — list cached entries (capped 200,
//!                                  no body content surfaced).
//!   • `POST /admin/cache/purge`  — invalidate cache (?all=1 / ?host=
//!                                  / ?prefix=) + broadcast purge to
//!                                  sibling workers.
//!   • `POST /admin/waf/reload`   — force WAF rule file reload (the
//!                                  30s background poller does this
//!                                  automatically; this is for ops
//!                                  who don't want to wait).
//!
//! Anything else returns 404. Every authenticated request goes through
//! `AuditLog::record` so the operator can grep who-did-what.
//!
//! Deliberately deferred (V37+):
//!   • POST /admin/reload (config hot-swap rebuilds the whole pipeline)
//!   • Web admin UI / /admin/api/* JSON surface
//!   • POST /admin/xdp/deny|undeny (XDP isn't loaded by aegis-pingora)
//!   • GET /admin/threats, /admin/anomaly (ThreatScorer + AnomalyDetector
//!     aren't threaded through yet — see V37 plan)

use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use crate::acme::AcmeClient;
use crate::admin_auth::{AuditLog, TokenRegistry, required_role_for};
use crate::anomaly::AnomalyDetector;
use crate::ddos::score::ThreatScorer;
use crate::filters::rate_limit::RateLimitFilter;
use crate::filters::waf::WafFilter;
use crate::honeypot::HoneypotStore;
use crate::metrics::RuntimeMetrics;
use crate::metrics::timeseries::TimeSeriesStore;
use crate::proxy::response_cache::ResponseCache;
use crate::web_admin::WebAdminStore;
use crate::xdp::XdpHandle;

// ── ENV_ALLOWLIST ────────────────────────────────────────────────────────────
//
// Static list of AEGIS_* environment variables that the admin UI may read/write
// via GET|PUT /admin/api/env. Any key NOT in this list is rejected with 400.
//
// `kind` drives value validation:
//   Bool   — only "0" or "1" accepted
//   Enum   — only the listed variants (lowercase) accepted
//   Path   — printable ASCII, no newlines/control chars, no shell metacharacters;
//             regex: [[:print:]]+ with an extra reject-list for ;|&`$(){}
//   Uint   — decimal non-negative integer
//   Secret — same printable-ASCII rules as Path; value is NEVER returned by GET
//            (configured:true/false only)
//
// To add a new feature flag: append an entry here — no other change required.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Uint is reserved for future numeric feature-flag keys
enum EnvKind {
    Bool,
    Enum(&'static [&'static str]),
    Path,
    /// host:port or URL (e.g. AEGIS_CLAMAV_ADDR, AEGIS_CROWDSEC_LAPI_URL).
    /// Same metachar/space/control-char rejection as Path, but NOT required
    /// to be an absolute filesystem path. Surfaced to the UI as "Path"
    /// (a plain text input).
    Addr,
    Uint,
    /// Floating-point value stored as a string (e.g.
    /// AEGIS_EVENTS_SAMPLE_PASS = "0.1"). Validated as a parseable f64 in
    /// `[0.0, 1.0]`. Surfaced to the UI as a plain text/number input.
    Float,
    Secret,
}

struct EnvEntry {
    key: &'static str,
    kind: EnvKind,
}

static ENV_ALLOWLIST: &[EnvEntry] = &[
    EnvEntry {
        key: "AEGIS_ML_V2",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_ML_V2_KIND",
        kind: EnvKind::Enum(&["logistic", "gbm"]),
    },
    EnvEntry {
        key: "AEGIS_ML_V2_GBM_FILE",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_ML_SCORER",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_ML_ADVERSARIAL",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_JA4_REPUTATION",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_ASN_REPUTATION",
        kind: EnvKind::Path,
    },
    // V244 — reputation feeds now ON by default (self-learning JA4 +
    // Tor/Spamhaus ASN/CIDR). These knobs let the panel relocate the feed
    // dir / ASN DB. Set AEGIS_JA4_REPUTATION / AEGIS_ASN_REPUTATION to "0"
    // to disable a module.
    EnvEntry {
        key: "AEGIS_REPUTATION_DIR",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_ASN_PATH",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_ARSENAL",
        kind: EnvKind::Bool,
    },
    // Risk Engine fusion mode. The admin UI (arsenal page) renders this
    // selector from the GET status `risk_engine_mode`, and the backend reads
    // AEGIS_RISK_ENGINE_MODE at startup (off|observe|enforce). It was missing
    // from this write-allowlist, so saving the selector returned 400 — fixed.
    // Takes effect on restart (restart_required:true on save).
    EnvEntry {
        key: "AEGIS_RISK_ENGINE_MODE",
        kind: EnvKind::Enum(&["off", "observe", "enforce"]),
    },
    EnvEntry {
        key: "AEGIS_TLS_FINGERPRINT",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_LLM_HONEYPOT",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_UPSTREAM_HEALTHCHECK",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_RESPONSE_CACHE_ENABLE",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_DYNAMIC_TRUST_ENABLE",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_LOG_JSON",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_FW_BACKEND",
        kind: EnvKind::Enum(&["auto", "xdp", "nftables", "iptables", "noop"]),
    },
    EnvEntry {
        key: "AEGIS_CLAMAV_ADDR",
        kind: EnvKind::Addr,
    },
    EnvEntry {
        key: "AEGIS_EVENT_FORMAT",
        kind: EnvKind::Enum(&["native", "sicherheitstacho", "tpot"]),
    },
    EnvEntry {
        key: "AEGIS_PINGORA_REUSEPORT",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_HCAPTCHA_SECRET",
        kind: EnvKind::Secret,
    },
    EnvEntry {
        key: "AEGIS_TURNSTILE_SECRET",
        kind: EnvKind::Secret,
    },
    // Cloudflare Turnstile sitekey — PUBLIC (embedded in the challenge page's
    // HTML), so it is a plain text value (Path kind), unlike the secret above
    // which is write-only. Both must be set for the `turnstile` rung to render;
    // absent either one, the host falls back to the normal PoW rung.
    EnvEntry {
        key: "AEGIS_TURNSTILE_SITEKEY",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_CROWDSEC_LAPI_URL",
        kind: EnvKind::Addr,
    },
    EnvEntry {
        key: "AEGIS_CROWDSEC_BOUNCER_KEY",
        kind: EnvKind::Secret,
    },
    // V-new — trusted-proxy / real-IP resolution (see src/proxy/pingora_http.rs).
    // AEGIS_BEHIND_CLOUDFLARE=1 enables CF-Connecting-IP resolution using
    // Cloudflare's built-in published CIDRs. AEGIS_TRUSTED_PROXIES accepts a
    // comma-separated list of CIDR/IP strings for custom upstream proxies and
    // uses the rightmost non-trusted hop from X-Forwarded-For.
    // Both are off by default; no behaviour change without explicit opt-in.
    EnvEntry {
        key: "AEGIS_BEHIND_CLOUDFLARE",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_TRUSTED_PROXIES",
        kind: EnvKind::Addr,
    },
    // V247 — knobs for the subsystems made real this pass.
    // AEGIS_SIGMA_WAF=0 disables loading the bundled 562-rule Sigma corpus
    // into the WAF (default ON). AEGIS_BGP_PIPE/_NEXTHOP wire the exabgp
    // file-announcer so RTBH blackholes propagate. AEGIS_ML_V2_SAMPLES is
    // the NDJSON path the ML trainer persists labelled samples to.
    EnvEntry {
        key: "AEGIS_SIGMA_WAF",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_BGP_PIPE",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_BGP_NEXTHOP",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_ML_V2_SAMPLES",
        kind: EnvKind::Path,
    },
    // V243 — persistent per-request event log (src/event_store.rs).
    // AEGIS_EVENT_LOG toggles the whole subsystem (default ON);
    // AEGIS_EVENTS_DIR is the shard directory (default /var/lib/aegis/events);
    // AEGIS_EVENTS_RETENTION_DAYS bounds how long rows are kept (default 14);
    // AEGIS_EVENTS_SAMPLE_PASS is the fraction of action=pass rows to keep
    // (default 1.0 = keep all; non-pass actions are always kept). All take
    // effect on restart (restart_required:true on save).
    EnvEntry {
        key: "AEGIS_EVENT_LOG",
        kind: EnvKind::Bool,
    },
    EnvEntry {
        key: "AEGIS_EVENTS_DIR",
        kind: EnvKind::Path,
    },
    EnvEntry {
        key: "AEGIS_EVENTS_RETENTION_DAYS",
        kind: EnvKind::Uint,
    },
    EnvEntry {
        key: "AEGIS_EVENTS_SAMPLE_PASS",
        kind: EnvKind::Float,
    },
];

/// Look up the allowlist entry for `key`. Returns None for unknown keys.
fn env_allowlist_entry(key: &str) -> Option<&'static EnvEntry> {
    ENV_ALLOWLIST.iter().find(|e| e.key == key)
}

/// V243 — parse a URL query string (`a=1&b=hello%20world`) into decoded
/// `(name, value)` pairs. Percent-decodes both sides (treating `+` as
/// space) and silently skips malformed pairs. Used by the event-log admin
/// endpoints to extract filter params.
fn parse_query_params(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let decode = |s: &str| -> String {
                urlencoding::decode(&s.replace('+', " "))
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| s.to_string())
            };
            Some((decode(k), decode(v)))
        })
        .collect()
}

/// Validate `value` against `kind`. Returns Ok(()) or an error description.
fn validate_env_value(value: &str, kind: EnvKind) -> Result<(), String> {
    // All values: reject newlines and control characters outright.
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("value must not contain control characters or newlines".to_string());
    }
    match kind {
        EnvKind::Bool => {
            if value == "0" || value == "1" {
                Ok(())
            } else {
                Err(format!(
                    "Bool key: only \"0\" or \"1\" allowed, got {:?}",
                    value
                ))
            }
        }
        EnvKind::Enum(variants) => {
            if variants.contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "Enum key: allowed variants are {:?}, got {:?}",
                    variants, value
                ))
            }
        }
        EnvKind::Path | EnvKind::Secret | EnvKind::Addr => {
            // Reject shell metacharacters that could turn an env value into an
            // injection vector if anything ever passed values through a shell.
            // (We never do, but belt-and-braces for defence-in-depth.) A space
            // is rejected too: systemd sources aegis.env unquoted, so an
            // embedded space would silently split the value and break the
            // feature.
            let bad_chars = [
                ';', '|', '&', '`', '$', '(', ')', '{', '}', '\'', '"', '\\', '\n', '\r', ' ',
            ];
            if let Some(c) = value.chars().find(|c| bad_chars.contains(c)) {
                return Err(format!("value: character {:?} not allowed", c));
            }
            if value.is_empty() {
                return Err("value must not be empty".to_string());
            }
            // File paths must be absolute and free of traversal sequences.
            // (Addr/Secret are host:port / URL / opaque tokens — not paths.)
            if kind == EnvKind::Path {
                if !value.starts_with('/') {
                    return Err(
                        "Path key: value must be an absolute path (start with '/')".to_string()
                    );
                }
                if value.split('/').any(|seg| seg == "..") {
                    return Err(
                        "Path key: value must not contain '..' traversal segments".to_string()
                    );
                }
            }
            Ok(())
        }
        EnvKind::Uint => {
            if value.parse::<u64>().is_ok() {
                Ok(())
            } else {
                Err(format!(
                    "Uint key: expected a non-negative integer, got {:?}",
                    value
                ))
            }
        }
        EnvKind::Float => match value.parse::<f64>() {
            Ok(f) if (0.0..=1.0).contains(&f) => Ok(()),
            Ok(_) => Err(format!(
                "Float key: value must be in [0.0, 1.0], got {:?}",
                value
            )),
            Err(_) => Err(format!("Float key: expected a number, got {:?}", value)),
        },
    }
}

/// Default path for the aegis.env file (overridable via AEGIS_ENV_FILE for tests).
fn aegis_env_file_path() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("AEGIS_ENV_FILE").unwrap_or_else(|_| "/etc/aegis/aegis.env".to_string()),
    )
}

/// Read /etc/aegis/aegis.env (or AEGIS_ENV_FILE) and parse KEY=VALUE lines.
/// Returns a Vec of (key, raw_value) for lines that match KEY=... syntax.
/// Lines that don't match (comments, blanks, malformed) are preserved but
/// not returned here — they pass through unchanged in the atomic writer.
fn read_aegis_env_file() -> std::io::Result<Vec<(String, String)>> {
    let path = aegis_env_file_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_string(), v.to_string()));
        }
    }
    Ok(out)
}

/// Pure core of the env-file rewrite: given the current file `content`,
/// upsert (or delete, when `value == None`) the line for `key`, returning the
/// new file text. Preserves comments, blank lines, and unrelated KEY=VALUE
/// pairs. The KEY is matched on the EXACT left-hand side of the first '=' — a
/// `starts_with("KEY=")` prefix test would wrongly drop e.g.
/// `AEGIS_ML_V2_KIND=...` when rewriting `AEGIS_ML_V2`. Pulled out as a pure
/// function so the prefix-collision regression is unit-testable without I/O.
fn rewrite_env_content(content: &str, key: &str, value: Option<&str>) -> String {
    let mut new_lines: Vec<String> = content
        .lines()
        .filter(|line| {
            let stripped = line.trim_start();
            if stripped.starts_with('#') || stripped.is_empty() {
                return true;
            }
            // Keep the line unless its KEY (lhs of the first '=') is exactly `key`.
            match stripped.split_once('=') {
                Some((k, _)) => k.trim() != key,
                None => true,
            }
        })
        .map(|l| l.to_string())
        .collect();

    if let Some(v) = value {
        new_lines.push(format!("{}={}", key, v));
    }

    // Ensure a trailing newline.
    let mut out = new_lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Atomically upsert or delete a KEY=VALUE line in aegis.env.
/// `value == None` → delete the line (unset the var).
/// Preserves comments, blank lines, and unrelated KEY=VALUE pairs.
/// Writes via .tmp + rename (atomic) at mode 0640.
fn write_aegis_env_file(key: &str, value: Option<&str>) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let path = aegis_env_file_path();
    // Read the existing file (or start empty).
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };

    let out = rewrite_env_content(&content, key, value);

    // Write to .tmp then rename (atomic on POSIX).
    let tmp_path = path.with_extension("env.tmp");
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Create the tmp file with 0600 from the very first syscall (.mode at
        // open), so a secret value never momentarily exists with world- or
        // group-readable bits between create() and a later fchmod() — closing
        // the TOCTOU window. We then widen to 0640 (owner rw, group r) to
        // match the daemon's expected aegis.env perms.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        f.write_all(out.as_bytes())?;
        f.flush()?;
    }
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

// ── ACME config + order state (in-process, backed by /var/lib/aegis/acme/) ──

/// Persisted ACME configuration — stored at /var/lib/aegis/acme/config.json.
/// Read on startup and updated via PUT /admin/api/acme/config.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AcmeConfig {
    pub account_email: Option<String>,
    /// When `true` the production LE directory is used. Default = false (staging).
    #[serde(default)]
    pub use_production: bool,
    /// Unix timestamp when the operator accepted LE TOS. Required before
    /// `use_production` can be set to `true`.
    pub accepted_tos_at: Option<u64>,
}

impl AcmeConfig {
    /// Load from `path` or return a staging-default config.
    pub fn load_or_default(path: &std::path::Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist atomically (tmp + rename) to `path` with mode 0640.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;

        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize AcmeConfig: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        {
            #[cfg(unix)]
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o640)
                .open(&tmp)?;
            #[cfg(not(unix))]
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.flush()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Minimum seconds between completed ACME orders for the same host
/// (only the `pending` state is exempt — that is guarded by `in_flight`).
/// One hour is well below the natural renewal cadence (every ~30 days
/// for 90-day certs) yet long enough that a runaway Write-role token can
/// only attempt ~24 issuances per host per day rather than ~5/week worth
/// in seconds. Adversarial-review must-fix from the ACME PR.
const MIN_ACME_ORDER_INTERVAL_SECS: u64 = 3_600;

/// Return Ok if a fresh order for this host is permitted, or `Err(json_err 429)`
/// when the previous completed order is within the cooldown window. Concurrent
/// in-flight orders are handled separately by `is_in_flight` — this gate
/// strictly catches the "burn rate limit by hammering after completion" path.
fn check_acme_order_cooldown(prev: Option<&AcmeOrderRecord>) -> Result<(), (u16, String, Bytes)> {
    let Some(rec) = prev else { return Ok(()) };
    // Only "issued" / "failed" / "expiring" / "idle" are completed; "pending"
    // is already protected by the in_flight guard, but we still gate by time.
    let now = crate::acme::now_unix();
    let age = now.saturating_sub(rec.updated_at);
    if age < MIN_ACME_ORDER_INTERVAL_SECS {
        let retry_in = MIN_ACME_ORDER_INTERVAL_SECS - age;
        let body = serde_json::json!({
            "error": format!(
                "rate-limited: last order attempt was {age}s ago; minimum {MIN_ACME_ORDER_INTERVAL_SECS}s between orders for the same host"
            ),
            "retry_after_secs": retry_in,
            "status": 429,
        });
        return Err((
            429,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        ));
    }
    Ok(())
}

/// Persisted order state for a single host.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AcmeOrderRecord {
    pub host: String,
    /// "idle" | "pending" | "issued" | "expiring" | "failed"
    pub status: String,
    pub not_after_unix: Option<u64>,
    pub error: Option<String>,
    pub updated_at: u64,
}

impl AcmeOrderRecord {
    fn status_str(not_after_unix: Option<u64>) -> &'static str {
        match not_after_unix {
            None => "idle",
            Some(t) => {
                let now = crate::acme::now_unix();
                let days_left = (t as i64 - now as i64) / 86_400;
                if days_left <= crate::acme::RENEW_AT_DAYS_REMAINING {
                    "expiring"
                } else {
                    "issued"
                }
            }
        }
    }

    fn to_api_json(&self) -> serde_json::Value {
        let safe_host: String = self
            .host
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let (cert_path, key_path) = if self.not_after_unix.is_some() {
            (
                Some(format!("/var/lib/aegis/certs/{safe_host}.cert.pem")),
                Some(format!("/var/lib/aegis/certs/{safe_host}.key.pem")),
            )
        } else {
            (None, None)
        };
        let expires_in_days = self.not_after_unix.map(|t| {
            let now = crate::acme::now_unix();
            (t as i64 - now as i64) / 86_400
        });
        serde_json::json!({
            "host": self.host,
            "status": self.status,
            "not_after_unix": self.not_after_unix,
            "expires_in_days": expires_in_days,
            "cert_path": cert_path,
            "key_path": key_path,
            "error": self.error,
        })
    }
}

/// In-memory + on-disk order state store.
/// Thread-safe via a RwLock. Paths: /var/lib/aegis/acme/orders/<host>.json.
struct AcmeOrderStore {
    dir: std::path::PathBuf,
    /// In-flight hosts (a host being actively provisioned).
    in_flight: dashmap::DashMap<String, ()>,
    /// Cached on-disk records (host -> record).
    records: std::sync::RwLock<std::collections::HashMap<String, AcmeOrderRecord>>,
}

impl AcmeOrderStore {
    fn new(dir: std::path::PathBuf) -> Self {
        let mut records = std::collections::HashMap::new();
        // Load existing records from disk on construction.
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(rec) = serde_json::from_slice::<AcmeOrderRecord>(&bytes) {
                        records.insert(rec.host.clone(), rec);
                    }
                }
            }
        }
        Self {
            dir,
            in_flight: dashmap::DashMap::new(),
            records: std::sync::RwLock::new(records),
        }
    }

    fn is_in_flight(&self, host: &str) -> bool {
        self.in_flight.contains_key(host)
    }

    fn mark_in_flight(&self, host: &str) {
        self.in_flight.insert(host.to_string(), ());
        // Mark status as "pending" in records immediately.
        let now = crate::acme::now_unix();
        let rec = AcmeOrderRecord {
            host: host.to_string(),
            status: "pending".to_string(),
            not_after_unix: None,
            error: None,
            updated_at: now,
        };
        if let Ok(mut map) = self.records.write() {
            map.insert(host.to_string(), rec);
        }
    }

    fn clear_in_flight(&self, host: &str) {
        self.in_flight.remove(host);
    }

    fn update_issued(&self, host: &str, not_after_unix: u64) {
        self.clear_in_flight(host);
        let status = AcmeOrderRecord::status_str(Some(not_after_unix)).to_string();
        let rec = AcmeOrderRecord {
            host: host.to_string(),
            status,
            not_after_unix: Some(not_after_unix),
            error: None,
            updated_at: crate::acme::now_unix(),
        };
        self.persist_record(&rec);
        if let Ok(mut map) = self.records.write() {
            map.insert(host.to_string(), rec);
        }
    }

    fn update_failed(&self, host: &str, error: &str) {
        self.clear_in_flight(host);
        let rec = AcmeOrderRecord {
            host: host.to_string(),
            status: "failed".to_string(),
            not_after_unix: None,
            error: Some(error.to_string()),
            updated_at: crate::acme::now_unix(),
        };
        self.persist_record(&rec);
        if let Ok(mut map) = self.records.write() {
            map.insert(host.to_string(), rec);
        }
    }

    fn get(&self, host: &str) -> Option<AcmeOrderRecord> {
        self.records.read().ok()?.get(host).cloned()
    }

    fn all(&self) -> Vec<AcmeOrderRecord> {
        self.records
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    fn persist_record(&self, rec: &AcmeOrderRecord) {
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;

        let Ok(json) = serde_json::to_vec_pretty(rec) else {
            return;
        };
        let _ = std::fs::create_dir_all(&self.dir);
        let safe_host: String = rec
            .host
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = self.dir.join(format!("{safe_host}.json"));
        let tmp = path.with_extension("json.tmp");
        let write_result = (|| {
            #[cfg(unix)]
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o640)
                .open(&tmp)?;
            #[cfg(not(unix))]
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.flush()?;
            std::fs::rename(&tmp, &path)?;
            std::io::Result::Ok(())
        })();
        if let Err(e) = write_result {
            tracing::warn!(host = %rec.host, error = %e, "acme: failed to persist order record");
        }
    }
}

#[derive(Clone)]
pub struct AdminProxy {
    metrics: Arc<RuntimeMetrics>,
    /// V33 — render cache stats inline with the rest of the
    /// counters. ResponseCache owns its own atomics (hits, misses,
    /// stores, evictions, ...) outside RuntimeMetrics, so we have to
    /// pull them and format them here.
    cache: Arc<ResponseCache>,
    /// V36 — admin token registry. Empty registry → every /admin/*
    /// request is rejected with 401, matching the hyper handler's
    /// fail-closed behaviour. /metrics + /health remain public.
    tokens: TokenRegistry,
    /// V36 — audit log. Records every authenticated mutation to the
    /// configured path + emits a tracing::info!(target="aegis::audit")
    /// event. Read-only and SPA-asset traffic is filtered inside
    /// AuditLog::record.
    audit: AuditLog,
    /// V36 — WAF filter ref for `/admin/waf/reload`. Same Arc the
    /// background poller uses, so a manual reload + the periodic
    /// reload are atomic with respect to the live ruleset (ArcSwap
    /// inside WafFilter).
    waf: Arc<WafFilter>,
    /// V38 — sliding-window threat scorer. Rendered by
    /// `GET /admin/threats` so operators can see the top N
    /// attacking IPs without parsing /metrics.
    scorer: Arc<ThreatScorer>,
    /// V119 — site cartography. Read-only access for /admin/api/site_map.
    site_map: Arc<crate::site_map::SiteMap>,
    /// V121 — split bot vs DDoS analytics.
    threat_analytics: Arc<crate::threat_analytics::ThreatAnalytics>,
    /// V107 — online signature miner. Read-only access via the
    /// /admin/api/mined_signatures endpoint so the React UI can show
    /// auto-mined candidates alongside the manual-corpus path.
    online_miner: Option<Arc<crate::online_signature_miner::OnlineMiner>>,
    /// V92 — cluster-wide scorer (shared mmap across REUSEPORT workers).
    /// When Some, `/admin/threats` and the JSON `top_threats` widget
    /// prefer it so operators see the *cluster* top-N rather than a
    /// single worker's slice (which under a distributed attack misses
    /// the other 3 workers' counters). Falls back to per-worker
    /// `scorer` when None (non-Linux / arena unavailable).
    shared_scorer: Option<Arc<crate::ddos::shared_score::SharedScorer>>,
    /// V38 — per-host attack-mode detector. Rendered by
    /// `GET /admin/anomaly` (which hosts are currently flagged
    /// + how long until the attack window closes).
    anomaly: Arc<AnomalyDetector>,
    /// V43 — rate-limit filter ref for `/admin/hot_uris`. Same
    /// Arc the engine holds.
    rate: Arc<RateLimitFilter>,
    /// V45 — XDP handle. NoopXdp on non-Linux / unconfigured; on
    /// Linux with eBPF loaded, drives /admin/xdp counters +
    /// /admin/xdp/{deny,undeny}/<ip> mutations.
    xdp: Arc<dyn XdpHandle>,
    /// V66 — web admin store (sessions, password hash, kill switch).
    /// Drives the `/admin/api/login` + session validation flow for
    /// the React panel. None when the operator hasn't wired
    /// `cfg.admin.web_state_path` — panel routes 503 in that case.
    web_admin: Option<Arc<WebAdminStore>>,
    /// V66 — honeypot store. Read-only access for the React UI's
    /// honeypot management page (`GET /admin/api/honeypots`).
    /// Write paths land in RC3.
    honeypots: Arc<HoneypotStore>,
    /// V66 — process start time, drives the "uptime" panel widget
    /// via `GET /admin/api/runtime/status`.
    started_at: std::time::Instant,
    /// V66 — config file path so the panel can show "loaded from"
    /// + (RC3) the raw-config editor.
    config_path: std::path::PathBuf,
    /// RC3 — audit log file path. When configured, the read-side
    /// `GET /admin/api/audit` endpoint tails the last 200 entries
    /// instead of returning the placeholder.
    audit_log_path: Option<std::path::PathBuf>,
    /// V160 — runtime filter on/off toggles. Shared handle to the
    /// FilterEngine's RuntimeToggles so the admin API can read/write
    /// without needing the full engine.
    filter_toggles: crate::filters::engine::RuntimeToggles,
    /// V162 — per-domain policy overrides. Shared handle to the
    /// FilterEngine's DomainPolicyStore. The admin API exposes CRUD
    /// at `/admin/api/sites/<host>/policy`.
    domain_policy: crate::domain_policy::DomainPolicyStore,
    /// V169 — optional ML V2 model (logistic / GBM). When Some, the
    /// `/admin/api/runtime/info` endpoint surfaces the kind +
    /// inference availability so Settings page shows the wired
    /// configuration without operator having to grep env vars.
    ml_v2: Option<Arc<crate::ddos::ml_model::MlModel>>,
    /// V169 — optional JA4 reputation feed. Surfaces entry count +
    /// active state in /admin/api/runtime/info.
    ja4_reputation: Option<Arc<crate::ja4_reputation::Ja4Reputation>>,
    /// V169 — optional ASN reputation feed. Same surface treatment.
    asn_reputation: Option<Arc<crate::asn_reputation::AsnReputation>>,
    /// V192 — optional Defence Arsenal handle. When set, the
    /// `/admin/api/arsenal` endpoint folds live activity counters
    /// into the catalogue payload.
    arsenal: Option<Arc<crate::arsenal::ArsenalState>>,
    /// V208 — update checker. When set, /admin/api/updates/* serves
    /// status + manual "Check now" + channel config.
    updates: Option<Arc<crate::updates::UpdateChecker>>,
    /// V240 — server hardware benchmark + capacity projection. Shared
    /// across all handler invocations so poll requests see live state.
    bench_state: Arc<crate::benchmark::BenchState>,
    /// V241 — flood-capacity test state (SYN/HTTP/TLS/slowloris/cache).
    /// Shared like `bench_state` so poll requests see live progress.
    flood_state: Arc<crate::benchmark_flood::FloodState>,
    /// V245 — nginx head-to-head comparison state.
    compare_state: Arc<crate::benchmark_compare::CompareState>,
    /// ACME/LE integration — optional instantiated client (None until
    /// `with_acme_client` is called). When `None`, ACME endpoints
    /// return 503 with a helpful message.
    acme_client: Option<Arc<dyn AcmeClient>>,
    /// ACME order state: in-flight flags + persisted order records.
    /// Always present even when `acme_client` is None so the GET
    /// endpoints can serve whatever was persisted on a previous run.
    acme_orders: Arc<AcmeOrderStore>,
    /// Path to /var/lib/aegis/acme/config.json. Stored so handlers can
    /// read/write the config without needing a second constructor arg.
    acme_config_path: std::path::PathBuf,
    /// SHARED ChallengeStore the data-plane HTTP-01 handler reads from.
    /// Plumbed via `with_acme_challenges` at boot. None when ACME is not
    /// wired, in which case order endpoints fall back to a fresh per-order
    /// store (which fails HTTP-01 validation in production — see
    /// `with_acme_challenges` doc for the live-test rationale).
    acme_challenges: Option<crate::acme::ChallengeStore>,
    /// TS — TimeSeriesStore for GET /admin/api/metrics/series.
    /// Wired via `with_timeseries`. When None the endpoint returns an
    /// empty {resolution:"1m",points:[]} rather than an error.
    timeseries: Option<Arc<TimeSeriesStore>>,
    /// V240 — shard directory for cross-worker SiteMap aggregation.
    /// When Some, the /admin/api/site_map endpoints read all shard-*.json
    /// files from this directory, merge them, and serve the aggregate so
    /// the response is stable regardless of which SO_REUSEPORT worker
    /// answers the request. Set via `with_sitemap_dir`; defaults to None
    /// (falls back to this worker's in-memory SiteMap).
    sitemap_dir: Option<std::path::PathBuf>,
    /// ML retrain — optional V123 trainer handle. When Some, the
    /// `POST /admin/api/ml/retrain` endpoint ingests operator-labelled
    /// samples from the request body and runs an SGD retrain pass over
    /// the live MlScorerV2 weights. When None the endpoint returns a
    /// clear 501 telling the operator the trainer isn't wired. Set via
    /// `with_ml_trainer` after `new()`.
    ml_trainer: Option<Arc<crate::ddos::ml_training::MlTrainer>>,
    /// V243 — persistent event-log store. Read side for
    /// `GET /admin/api/logs` (query) and `/admin/api/logs/stats`
    /// (aggregations). query()/stats() open their own read connections by
    /// scanning the shard dir, so any handle works regardless of whether
    /// persistence is enabled on it. Set via `with_event_store`; when
    /// None the endpoints return an empty result set.
    event_store: Option<Arc<crate::event_store::EventStore>>,
    /// V245 — the live `FilterEngine` the data plane runs. Wired via
    /// `with_engine` so the nginx head-to-head comparison can drive the
    /// REAL per-request inspection pipeline for its "AEGIS + WAF" bar
    /// (the honest cost of protection). When `None`, the comparison falls
    /// back to a standalone `WafFilter` scan inside `benchmark_compare`.
    engine: Option<Arc<crate::filters::engine::FilterEngine>>,
}

impl AdminProxy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metrics: Arc<RuntimeMetrics>,
        cache: Arc<ResponseCache>,
        tokens: TokenRegistry,
        audit: AuditLog,
        waf: Arc<WafFilter>,
        scorer: Arc<ThreatScorer>,
        shared_scorer: Option<Arc<crate::ddos::shared_score::SharedScorer>>,
        anomaly: Arc<AnomalyDetector>,
        rate: Arc<RateLimitFilter>,
        xdp: Arc<dyn XdpHandle>,
        honeypots: Arc<HoneypotStore>,
        web_admin: Option<Arc<WebAdminStore>>,
        config_path: std::path::PathBuf,
        audit_log_path: Option<std::path::PathBuf>,
        online_miner: Option<Arc<crate::online_signature_miner::OnlineMiner>>,
        site_map: Arc<crate::site_map::SiteMap>,
        threat_analytics: Arc<crate::threat_analytics::ThreatAnalytics>,
        filter_toggles: crate::filters::engine::RuntimeToggles,
        domain_policy: crate::domain_policy::DomainPolicyStore,
    ) -> Self {
        Self {
            metrics,
            cache,
            tokens,
            audit,
            waf,
            scorer,
            shared_scorer,
            anomaly,
            rate,
            xdp,
            honeypots,
            web_admin,
            started_at: std::time::Instant::now(),
            config_path,
            audit_log_path,
            online_miner,
            site_map,
            threat_analytics,
            filter_toggles,
            domain_policy,
            ml_v2: None,
            ja4_reputation: None,
            asn_reputation: None,
            arsenal: None,
            updates: None,
            bench_state: Arc::new(crate::benchmark::BenchState::new()),
            flood_state: Arc::new(crate::benchmark_flood::FloodState::new()),
            compare_state: Arc::new(crate::benchmark_compare::CompareState::new()),
            acme_client: None,
            acme_orders: Arc::new(AcmeOrderStore::new(std::path::PathBuf::from(
                "/var/lib/aegis/acme/orders",
            ))),
            acme_config_path: std::path::PathBuf::from("/var/lib/aegis/acme/config.json"),
            acme_challenges: None,
            timeseries: None,
            sitemap_dir: None,
            ml_trainer: None,
            event_store: None,
            engine: None,
        }
    }

    /// V245 — wire the live `FilterEngine` so the nginx head-to-head
    /// comparison's "AEGIS + WAF" bar can drive the real per-request
    /// inspection pipeline. Reuses the same `Arc` the data plane runs.
    pub fn with_engine(mut self, engine: Arc<crate::filters::engine::FilterEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    /// V243 — wire the shared event-log store so `GET /admin/api/logs`
    /// and `/admin/api/logs/stats` can serve persisted request history.
    /// Reuses the same `Arc` the data-plane proxy records into; the read
    /// side opens its own connections per call. When not wired, those
    /// endpoints return an empty result.
    pub fn with_event_store(mut self, store: Arc<crate::event_store::EventStore>) -> Self {
        self.event_store = Some(store);
        self
    }

    /// V240 — register the shard directory so site-map endpoints aggregate
    /// across all SO_REUSEPORT workers instead of serving one worker's slice.
    /// Reads `AEGIS_SITEMAP_DIR` (same source as the data-plane workers use)
    /// or falls back to `/var/lib/aegis/site-map` when the env var is absent.
    /// Call once at startup before the admin listener is wired into pingora.
    pub fn with_sitemap_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.sitemap_dir = Some(dir);
        self
    }

    /// V192 — opt in to Defence Arsenal counters on /admin/api/arsenal.
    pub fn with_arsenal(mut self, arsenal: Arc<crate::arsenal::ArsenalState>) -> Self {
        self.arsenal = Some(arsenal);
        self
    }

    /// V208 — opt in to the update checker on /admin/api/updates/*.
    pub fn with_updates(mut self, updates: Arc<crate::updates::UpdateChecker>) -> Self {
        self.updates = Some(updates);
        self
    }

    /// Wire an instantiated [AcmeClient] so the /admin/api/acme/* endpoints
    /// can drive live issuance. Without this call the endpoints return 503.
    /// Also accepts an optional custom orders-dir and config-path override
    /// (used by `aegis-pingora.rs`); pass `None` to use the defaults.
    pub fn with_acme_client(
        mut self,
        client: Arc<dyn AcmeClient>,
        orders_dir: Option<std::path::PathBuf>,
        config_path: Option<std::path::PathBuf>,
    ) -> Self {
        if let Some(dir) = orders_dir {
            self.acme_orders = Arc::new(AcmeOrderStore::new(dir));
        }
        if let Some(path) = config_path {
            self.acme_config_path = path;
        }
        self.acme_client = Some(client);
        self
    }

    /// Plumb the SAME ChallengeStore the data-plane HTTP-01 handler reads
    /// from. Required so the Provisioner the admin handler spawns
    /// publishes tokens into the store the proxy actually serves at
    /// `/.well-known/acme-challenge/<token>`. Without this, Provisioner
    /// uses its own Default::default() store, the proxy never sees the
    /// token, LE GETs a 302 (the HTTP→HTTPS redirect), validation fails
    /// with state=Invalid. Live-tested.
    pub fn with_acme_challenges(mut self, challenges: crate::acme::ChallengeStore) -> Self {
        self.acme_challenges = Some(challenges);
        self
    }

    /// TS — Wire a TimeSeriesStore so `GET /admin/api/metrics/series`
    /// can serve historical request-rate data. The store is shared
    /// across workers via the `Arc`; only the designated writer worker
    /// (the one holding `.sampler.lock`) actually appends samples.
    /// All workers can serve read queries from the same mmap'd ring files.
    pub fn with_timeseries(mut self, store: Arc<TimeSeriesStore>) -> Self {
        self.timeseries = Some(store);
        self
    }

    /// V169 — opt-in references for Settings page surface. Operator's
    /// binary calls these AFTER `new()` with whichever modules it
    /// wired in `aegis-pingora.rs`. None values render as
    /// "not configured" in the UI.
    pub fn with_ml_v2(mut self, m: Arc<crate::ddos::ml_model::MlModel>) -> Self {
        self.ml_v2 = Some(m);
        self
    }
    /// ML retrain — wire the V123 [MlTrainer] so `POST /admin/api/ml/retrain`
    /// can ingest operator-labelled samples and retrain the live MlScorerV2
    /// weights at runtime. Without this call the endpoint returns 501.
    pub fn with_ml_trainer(mut self, trainer: Arc<crate::ddos::ml_training::MlTrainer>) -> Self {
        self.ml_trainer = Some(trainer);
        self
    }
    pub fn with_ja4_reputation(mut self, r: Arc<crate::ja4_reputation::Ja4Reputation>) -> Self {
        self.ja4_reputation = Some(r);
        self
    }
    pub fn with_asn_reputation(mut self, r: Arc<crate::asn_reputation::AsnReputation>) -> Self {
        self.asn_reputation = Some(r);
        self
    }

    /// TS — GET /admin/api/metrics/series?range=<label>.
    ///
    /// Accepted `range` labels (case-insensitive; default "24h"):
    ///   1h  →  3_600 s   (1-minute ring)
    ///   6h  →  21_600 s  (1-minute ring)
    ///   24h →  86_400 s  (1-minute ring)
    ///   7d  →  604_800 s (1-hour ring, ≤172_800 threshold is crossed)
    ///   30d →  2_592_000 s
    ///   90d →  7_776_000 s
    ///
    /// Response (JSON):
    ///   { "resolution": "1m"|"1h", "points": [ <QueryPoint>… ] }
    ///
    /// When the store is not wired (operator omitted `with_timeseries`),
    /// returns 200 with an empty point list rather than an error, so the
    /// UI degrades gracefully on deployments that haven't enabled the TS
    /// writer.
    fn api_metrics_series(&self, query: &str) -> (u16, String, Bytes) {
        // Parse ?range= query parameter.
        let range_label = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, _)| k.eq_ignore_ascii_case("range"))
            .map(|(_, v)| v)
            .unwrap_or("24h");

        let range_secs: u64 = match range_label.to_ascii_lowercase().as_str() {
            "1h" => 3_600,
            "6h" => 21_600,
            "24h" => 86_400,
            "7d" => 604_800,
            "30d" => 2_592_000,
            "90d" => 7_776_000,
            _ => {
                let body = serde_json::json!({
                    "error": format!(
                        "unknown range {:?}; use one of: 1h 6h 24h 7d 30d 90d",
                        range_label
                    )
                });
                return (
                    400,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        };

        let Some(store) = self.timeseries.as_ref() else {
            // Store not wired — return a well-typed empty response so the
            // frontend chart renders "no data" rather than throwing.
            let body = serde_json::json!({ "resolution": "1m", "points": [] });
            return (
                200,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        };

        match store.query(range_secs) {
            Ok(resp) => match serde_json::to_string(&resp) {
                Ok(json) => (200, "application/json".to_string(), Bytes::from(json)),
                Err(e) => {
                    let body = serde_json::json!({ "error": format!("serialize: {e}") });
                    (
                        500,
                        "application/json".to_string(),
                        Bytes::from(body.to_string()),
                    )
                }
            },
            Err(e) => {
                let body = serde_json::json!({ "error": format!("query: {e}") });
                (
                    500,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                )
            }
        }
    }

    /// V243 — GET /admin/api/logs. Parse the filter query string
    /// (`host`, `endpoint`, `action`, `ip`, `q`, `from`, `to`, `limit`,
    /// `offset`) into a [`LogFilter`] and return the matching rows newest
    /// first as `{ entries: [...], total }`. `total` is the number of
    /// entries returned (the query limit is hard-capped at 1000 by the
    /// store). Returns an empty result when the store isn't wired.
    fn api_logs(&self, query: &str) -> (u16, String, Bytes) {
        let Some(store) = self.event_store.as_ref() else {
            let body = serde_json::json!({ "entries": [], "total": 0 });
            return (
                200,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        };
        let params = parse_query_params(query);
        let getstr = |k: &str| -> Option<String> {
            params
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .filter(|s| !s.is_empty())
        };
        let geti64 = |k: &str| -> Option<i64> { getstr(k).and_then(|v| v.parse().ok()) };
        let getusize = |k: &str| -> Option<usize> { getstr(k).and_then(|v| v.parse().ok()) };
        let filter = crate::event_store::LogFilter {
            host: getstr("host"),
            endpoint: getstr("endpoint"),
            action: getstr("action"),
            client_ip: getstr("ip"),
            q: getstr("q"),
            from_ms: geti64("from"),
            to_ms: geti64("to"),
            limit: getusize("limit"),
            offset: getusize("offset"),
        };
        let entries = store.query(&filter);
        let total = entries.len();
        let body = serde_json::json!({ "entries": entries, "total": total });
        match serde_json::to_string(&body) {
            Ok(json) => (200, "application/json".to_string(), Bytes::from(json)),
            Err(e) => {
                let body = serde_json::json!({ "error": format!("serialize: {e}") });
                (
                    500,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                )
            }
        }
    }

    /// V243 — GET /admin/api/logs/stats. Aggregated analytics over a time
    /// range (params `host`, `from`, `to`; ms epoch). When `from`/`to` are
    /// omitted, defaults to the last 24h. Returns a [`LogStats`] JSON
    /// object (by_action / top_endpoints / top_ips / endpoint_fanout /
    /// series / …). Empty stats when the store isn't wired.
    fn api_logs_stats(&self, query: &str) -> (u16, String, Bytes) {
        let Some(store) = self.event_store.as_ref() else {
            let body = serde_json::to_string(&crate::event_store::LogStats::default())
                .unwrap_or_else(|_| "{}".to_string());
            return (200, "application/json".to_string(), Bytes::from(body));
        };
        let params = parse_query_params(query);
        let getstr = |k: &str| -> Option<String> {
            params
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .filter(|s| !s.is_empty())
        };
        let geti64 = |k: &str| -> Option<i64> { getstr(k).and_then(|v| v.parse().ok()) };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let from_ms = geti64("from").unwrap_or(now_ms - 86_400_000);
        let to_ms = geti64("to").unwrap_or(now_ms);
        let host = getstr("host");
        let stats = store.stats(host.as_deref(), from_ms, to_ms);
        match serde_json::to_string(&stats) {
            Ok(json) => (200, "application/json".to_string(), Bytes::from(json)),
            Err(e) => {
                let body = serde_json::json!({ "error": format!("serialize: {e}") });
                (
                    500,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                )
            }
        }
    }

    /// V239 — GET /admin/api/geo/top. Top countries by request volume for
    /// the dashboard "Live Traffic Overview" world map + Top Countries
    /// list. Returns [{country, total, denied}] (up to 20). Empty when no
    /// GeoIP database is configured (country resolution returns None, so
    /// nothing is tallied) — the dashboard renders the map gracefully
    /// empty in that case.
    fn api_geo_top(&self) -> (u16, String, Bytes) {
        let rows: Vec<serde_json::Value> = self
            .metrics
            .top_countries(20)
            .into_iter()
            .map(|(country, total, denied)| {
                serde_json::json!({ "country": country, "total": total, "denied": denied })
            })
            .collect();
        let body = serde_json::Value::Array(rows);
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V169 — GET /admin/api/runtime/info. Single endpoint that
    /// surfaces the configuration of every optional module the
    /// operator may have wired. The Settings page renders four tabs
    /// (General / ML / Feeds / Infrastructure) over this response.
    /// V191 — Defence Arsenal: catalogue of every V176-V190 module
    /// with id, label, family, status, description. The UI renders
    /// this as a grouped board so operators can see the entire
    /// defensive surface at a glance.
    fn api_arsenal(&self) -> (u16, String, Bytes) {
        // V240 — honest per-module status. Each module's status is
        // derived from whether its activity counter can actually fire
        // on the live path, NOT a hardcoded "shipped". The values map
        // onto the panel's existing status vocabulary
        // (ArsenalStatusChip in web/src/pages/v2/Arsenal.tsx):
        //   "shipped"      (green) — wired into the request/TLS/tarpit
        //                  path with the arsenal attached; its counter
        //                  increments on real traffic.
        //   "experimental" (amber) — code path is wired but only fires
        //                  when the operator opts in (needs a
        //                  non-default env / feed / collector), so it
        //                  can legitimately read 0.
        //   "planned"      (grey)  — implemented + unit-tested but not
        //                  yet invoked on any daemon data path (no
        //                  counter can fire), OR the arsenal is detached
        //                  via AEGIS_ARSENAL=0 (nothing can fire at all).
        let wired = self.arsenal.is_some();
        // "live" modules read "shipped" only when the arsenal is
        // actually attached; otherwise no counter can fire so they are
        // honestly "planned".
        let live = if wired { "shipped" } else { "planned" };
        // Opt-in modules: wired but gated on operator config → amber.
        let ready = if wired { "experimental" } else { "planned" };
        // sicherheitstacho: the emit() counter-bump mechanism is wired,
        // but the EventBridge that calls it is not constructed on the
        // pingora daemon data path — so it stays "planned" until an
        // operator wires an event sink. Honest, not "shipped".
        let library = "planned";
        let modules = serde_json::json!([
            { "id": "ja4_corpus", "v": "V176", "family": "fingerprint", "label": "JA4 corpus (FoxIO-seeded)",
              "desc": "Curated allow/deny baseline for known browsers + tooling. Operator file extends.",
              "status": live },
            { "id": "ja4_churn", "v": "V177", "family": "fingerprint", "label": "JA4 churn score",
              "desc": "Per-IP sliding-window JA4 rotation detector. utls/curl-impersonate tell.",
              "status": live },
            { "id": "grease_anomaly", "v": "V178", "family": "fingerprint", "label": "GREASE anomaly detector",
              "desc": "Catches spoofed Chrome ClientHello via missing GREASE positions.",
              "status": live },
            { "id": "normalisation", "v": "V179", "family": "waf", "label": "Multi-pass normalisation chain",
              "desc": "URL → HTML → NFKC → confusable → null-strip → lowercase, fixed-point.",
              "status": live },
            { "id": "param_profile", "v": "V180", "family": "waf", "label": "Per-endpoint parameter profile",
              "desc": "Rolling length/charset/entropy stats per (host, endpoint, param).",
              "status": live },
            { "id": "rule_planner", "v": "V181", "family": "waf", "label": "Phase-indexed rule plan",
              "desc": "Bucketise rules by request phase + field presence; skip irrelevant.",
              "status": live },
            { "id": "h2_budget", "v": "V182", "family": "ddos", "label": "H2 control-frame budgets",
              "desc": "Token-bucket per (conn, frame_kind) — Rapid Reset / Settings flood / CONT.",
              "status": live },
            { "id": "llm_honeypot", "v": "V183", "family": "honeypot", "label": "LLM honeypot + semantic cache",
              "desc": "Pluggable LlmClient with response cache keyed by request shape.",
              "status": ready },
            { "id": "honeypot_yaml", "v": "V184", "family": "honeypot", "label": "YAML honeypot descriptors",
              "desc": "Multi-turn engagement scripts, per-(IP,descriptor) state machine.",
              "status": ready },
            { "id": "sicherheitstacho", "v": "V185", "family": "telemetry", "label": "T-Pot event export schema",
              "desc": "Render security events in Sicherheitstacho NDJSON for ecosystem interop.",
              "status": library },
            { "id": "route_difficulty", "v": "V186", "family": "challenge", "label": "Per-route PoW difficulty",
              "desc": "Anubis-style: scale work factor by route + UA (AI scraper preset).",
              "status": live },
            { "id": "bgp_rtbh", "v": "V187", "family": "ddos", "label": "BGP RTBH dispatcher",
              "desc": "Push /32 announcements upstream via exabgp pipe; TTL'd auto-withdraw.",
              "status": live },
            { "id": "decoy_headers", "v": "V188", "family": "deception", "label": "Cloudflare-impersonating decoys",
              "desc": "Suspect responses get CF-Ray / __cf_bm; mislead Scrapling/Botasaurus.",
              "status": live },
            { "id": "timing_entropy", "v": "V189", "family": "fingerprint", "label": "Timing-entropy ML features",
              "desc": "Mouse jitter / scroll cadence entropy; flag uniform-timer synthetics.",
              "status": ready },
            { "id": "latency_jitter", "v": "V190", "family": "deception", "label": "Tarpit latency jitter shaping",
              "desc": "Log-normal / bimodal-CDN delays defeat response-time fingerprinting.",
              "status": live },
            { "id": "actuators", "v": "V197", "family": "orchestration", "label": "Active-response actuator registry",
              "desc": "Pluggable (kind, target) → enforcement primitive + timer wheel + revert TTL.",
              "status": ready },
            { "id": "enrichment", "v": "V198", "family": "intel", "label": "WISE-style enrichment facade",
              "desc": "Cached fan-out over JA4/ASN/CIDR/GeoIP/corpus with per-source provenance.",
              "status": live },
            { "id": "scenarios", "v": "V199", "family": "behavioural", "label": "CrowdSec-style scenario DSL",
              "desc": "YAML leaky-bucket: filter / groupby / distinct / capacity / leak_speed / blackhole.",
              "status": ready }
        ]);
        let summary = serde_json::json!({
            "total_modules": 18,
            "families": {
                "fingerprint": 4,
                "waf": 3,
                "ddos": 2,
                "honeypot": 2,
                "telemetry": 1,
                "challenge": 1,
                "deception": 2,
                "orchestration": 1,
                "intel": 1,
                "behavioural": 1
            },
            "version_range": "V176-V199"
        });
        // V192 — fold in live counters when the arsenal is wired.
        // Each per-module `calls` number lets the UI render a heat
        // chip showing whether the module is actually firing in
        // production traffic.
        let counters_json = match self.arsenal.as_ref() {
            Some(arsenal) => {
                let s = arsenal.counters.snapshot();
                serde_json::json!({
                    "wired": true,
                    "ja4_corpus":      { "lookups": s.ja4_corpus_lookups, "allow_hits": s.ja4_corpus_allow_hits, "deny_hits": s.ja4_corpus_deny_hits, "entries": arsenal.ja4_corpus.len() },
                    "ja4_churn":       { "observations": s.ja4_churn_observations, "tracked_ips": arsenal.ja4_churn.tracked_ips() },
                    "grease_anomaly":  { "checks": s.grease_checks, "anomalies": s.grease_anomalies },
                    "normalisation":   { "calls": s.normalisation_calls, "passes": s.normalisation_chained_passes },
                    "param_profile":   { "observations": s.param_profile_observations, "anomalies": s.param_profile_anomalies, "keys": arsenal.param_profile.len() },
                    "rule_planner":    {
                        "dispatches": s.rule_plan_dispatches,
                        "rules_total": arsenal.rule_plan_summary().map(|(r, _)| r).unwrap_or(0),
                        "phases":      arsenal.rule_plan_summary().map(|(_, p)| p).unwrap_or(0),
                    },
                    "h2_budget":       { "allows": s.h2_budget_allows, "rejects": s.h2_budget_rejects, "tracked_conns": arsenal.h2_budget.tracked_conns() },
                    "llm_honeypot":    { "responses": s.llm_honeypot_responses, "cached": arsenal.llm_honeypot.len() },
                    "honeypot_yaml":   { "engagements": s.yaml_honeypot_engagements, "sessions": arsenal.yaml_honeypot.sessions(), "descriptors": arsenal.yaml_honeypot.descriptors().len() },
                    "sicherheitstacho":{ "emits": s.sicherheitstacho_emits },
                    "route_difficulty":{ "bumps": s.route_difficulty_bumps, "overrides": arsenal.route_difficulty.overrides().len() },
                    "bgp_rtbh":        { "announces": s.bgp_rtbh_announces, "withdraws": s.bgp_rtbh_withdraws, "active": arsenal.bgp_rtbh.len() },
                    "decoy_headers":   { "emits": s.decoy_header_emits },
                    "timing_entropy":  { "calls": s.timing_entropy_calls, "synthetic_flags": s.timing_entropy_synthetic_flags },
                    "latency_jitter":  { "emits": s.latency_jitter_emits },
                    "actuators":       {
                        "applies":          s.actuator_applies,
                        "reverts_expired":  s.actuator_reverts_expired,
                        "active":           arsenal.actuators.active_count(),
                        "kinds":            arsenal.actuators.registered_kinds().len(),
                    },
                    "enrichment":      {
                        "lookups":          s.enrichment_lookups,
                        "cache_hits":       s.enrichment_cache_hits,
                        "sources":          arsenal.enrichment.read().map(|e| e.registered_sources().len()).unwrap_or(0),
                    },
                    "scenarios":       {
                        "events":           s.scenario_events,
                        "fires":            s.scenario_fires,
                        "loaded":           arsenal.scenarios.scenarios().len(),
                        "buckets":          arsenal.scenarios.bucket_count(),
                    },
                })
            }
            None => serde_json::json!({ "wired": false }),
        };
        let body = serde_json::json!({ "summary": summary, "modules": modules, "counters": counters_json });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V205 — GET /admin/api/challenge/hosts. Lists every host that
    /// has a per-domain challenge override + a snapshot of global
    /// adaptive ladder state (attack mode, last decision counters).
    fn api_challenge_hosts(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(arsenal) => {
                let hosts = arsenal.domain_challenge_hosts();
                let cfgs: Vec<_> = hosts
                    .iter()
                    .map(|h| {
                        serde_json::json!({
                            "host": h,
                            "config": arsenal.domain_challenge_config(h),
                        })
                    })
                    .collect();
                let (fast, attack_bumps, rand) = arsenal.adaptive_ladder.stats().snapshot();
                let (decoy, honeypot, varied) = (
                    arsenal
                        .deception
                        .decoy_forms_rendered
                        .load(std::sync::atomic::Ordering::Relaxed),
                    arsenal
                        .deception
                        .honeypot_fills_detected
                        .load(std::sync::atomic::Ordering::Relaxed),
                    arsenal
                        .deception
                        .varied_errors_rendered
                        .load(std::sync::atomic::Ordering::Relaxed),
                );
                // V233+ challenge arsenal activity counters (phase 1).
                let s = arsenal.counters.snapshot();
                serde_json::json!({
                    "wired": true,
                    "hosts": cfgs,
                    "global": {
                        "attack_mode": arsenal.adaptive_ladder.is_attack_mode(),
                        "config": arsenal.adaptive_ladder.config(),
                        "fast_track_hits": fast,
                        "attack_mode_bumps": attack_bumps,
                        "randomized_picks": rand,
                        "decoy_forms_rendered": decoy,
                        "honeypot_fills_detected": honeypot,
                        "varied_errors_rendered": varied,
                        "trust_grants_active": arsenal.chained_trust.len(),
                        "privacy_pass_issuers": arsenal.privacy_pass.issuer_count(),
                    },
                    "signals": {
                        "ja4_ua_consistency":       s.challenge_ja4_ua_consistency_hits,
                        "header_fingerprint":       s.challenge_header_fingerprint_hits,
                        "h2_fingerprint":           s.challenge_h2_fingerprint_hits,
                        "datacenter_asn_challenge": s.challenge_datacenter_asn_challenge_hits,
                        "headless_detection":       s.challenge_headless_detection_hits,
                        "webgl_audio_fp":           s.challenge_webgl_audio_fp_hits,
                        "dom_timing_entropy":       s.challenge_dom_timing_entropy_hits,
                        "reputation_difficulty":    s.challenge_reputation_difficulty_hits,
                        "fail_to_xdp_deny":         s.challenge_fail_to_xdp_deny_hits,
                        "turnstile":                s.challenge_turnstile_hits,
                        "proof_of_click":           s.challenge_proof_of_click_hits,
                    }
                })
            }
            None => serde_json::json!({ "wired": false, "hosts": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// V232 — GET /admin/api/topology. Worker-topology dashboard data
    /// for the panel's Workers page: host CPU facts, the live process
    /// layout, every running `aegis-pingora` worker, and a layout
    /// recommendation. Reads `/proc` — off the data path, called only
    /// on a dashboard refresh.
    fn api_topology_get(&self) -> (u16, String, Bytes) {
        use crate::topology;
        let host = topology::host_info();
        let workers = topology::enumerate_workers();
        let topo_path = std::env::var("AEGIS_TOPOLOGY_PATH")
            .unwrap_or_else(|_| topology::DEFAULT_TOPOLOGY_PATH.to_string());
        let desired = topology::read_desired(std::path::Path::new(&topo_path));

        // threads/worker is uniform — every systemd instance launches
        // with the same `AEGIS_PINGORA_THREADS` env.
        let threads_per_worker = std::env::var("AEGIS_PINGORA_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            });
        let reuseport = std::env::var("AEGIS_PINGORA_REUSEPORT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let workers_running = workers.len();
        let total_runtime_threads = workers_running * threads_per_worker;
        let mode = if threads_per_worker == 1 {
            "thread-per-core"
        } else {
            "multi-thread"
        };
        let total_rss: u64 = workers.iter().map(|w| w.rss_mb).sum();
        let total_cpu: f32 = workers.iter().map(|w| w.cpu_pct_avg).sum();
        let (status, message) = Self::topology_recommendation(
            workers_running,
            threads_per_worker,
            total_runtime_threads,
            host.cpu_count,
        );

        let body = serde_json::json!({
            "host": host,
            "layout": {
                "workers_running": workers_running,
                "threads_per_worker": threads_per_worker,
                "total_runtime_threads": total_runtime_threads,
                "reuseport": reuseport,
                "mode": mode,
            },
            "workers": workers,
            "totals": { "rss_mb": total_rss, "cpu_pct_avg": total_cpu },
            "desired": {
                "workers": desired.workers,
                "effective": desired.effective(&host),
            },
            "recommendation": { "status": status, "message": message },
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// Classify the current layout vs. the host core count. "optimal"
    /// is exactly one runtime thread per core in a thread-per-core
    /// shape; everything else is "suboptimal" with an actionable hint.
    fn topology_recommendation(
        workers: usize,
        threads_per: usize,
        total_threads: usize,
        cores: usize,
    ) -> (&'static str, String) {
        if workers == 0 {
            return (
                "suboptimal",
                "No worker processes detected — the /proc scan returned nothing.".to_string(),
            );
        }
        if total_threads == cores && threads_per == 1 {
            return (
                "optimal",
                format!(
                    "{workers} workers × 1 thread on {cores} cores — optimal \
                     thread-per-core layout."
                ),
            );
        }
        if total_threads == cores {
            return (
                "suboptimal",
                format!(
                    "{workers} workers × {threads_per} threads = {total_threads} \
                     runtime threads on {cores} cores. All cores are covered, but \
                     thread-per-core ({cores} workers × 1 thread) gives better L1/L2 \
                     locality — roughly 5-10% more RPS."
                ),
            );
        }
        if total_threads < cores {
            return (
                "suboptimal",
                format!(
                    "{total_threads} runtime threads on {cores} cores — \
                     {} core(s) sitting idle. Raise the worker count to {cores}.",
                    cores - total_threads
                ),
            );
        }
        (
            "suboptimal",
            format!(
                "{total_threads} runtime threads on {cores} cores — oversubscribed \
                 by {}. Lower the worker count to {cores} so threads don't fight \
                 for cores.",
                total_threads - cores
            ),
        )
    }

    /// V232 — PUT /admin/api/topology. Records the operator's desired
    /// worker count to the topology state file. The running daemon
    /// cannot rescale its own systemd instances (that needs root +
    /// `systemctl`), so this persists the *intent*; `install.sh`
    /// applies it on the next deploy. Same model as nginx
    /// `worker_processes` — a reload is always required.
    fn api_topology_put(&self, body: &[u8]) -> (u16, String, Bytes) {
        use crate::topology;
        let err = |code: u16, msg: String| -> (u16, String, Bytes) {
            (
                code,
                "application/json".into(),
                Bytes::from(serde_json::json!({ "ok": false, "error": msg }).to_string()),
            )
        };
        // Accept {"workers":"auto"}, {"workers":"8"} or {"workers":8}.
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return err(400, format!("invalid JSON body: {e}")),
        };
        let raw = match parsed.get("workers") {
            Some(serde_json::Value::String(s)) => s.trim().to_string(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => {
                return err(
                    400,
                    "missing field 'workers' (string \"auto\" or a number)".to_string(),
                );
            }
        };
        let is_auto = raw.eq_ignore_ascii_case("auto");
        let is_pos_int = raw.parse::<usize>().map(|n| n >= 1).unwrap_or(false);
        if !is_auto && !is_pos_int {
            return err(
                400,
                "'workers' must be \"auto\" or a positive integer".to_string(),
            );
        }
        let normalised = if is_auto { "auto".to_string() } else { raw };
        let desired = topology::DesiredTopology {
            workers: normalised.clone(),
        };
        let topo_path = std::env::var("AEGIS_TOPOLOGY_PATH")
            .unwrap_or_else(|_| topology::DEFAULT_TOPOLOGY_PATH.to_string());
        if let Err(e) = topology::write_desired(std::path::Path::new(&topo_path), &desired) {
            return err(500, format!("could not persist topology: {e}"));
        }
        let host = topology::host_info();
        let apply_hint = format!(
            "sudo bash install.sh --workers {normalised}   \
             # then: systemctl restart aegis-pingora.target"
        );
        let body = serde_json::json!({
            "ok": true,
            "desired": {
                "workers": normalised,
                "effective": desired.effective(&host),
            },
            "restart_required": true,
            "apply_hint": apply_hint,
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// V240 — GET /admin/api/benchmark/result.
    /// Returns the current benchmark state as the CONTRACT JSON shape.
    /// `status` is the poll discriminator: "idle" / "running" / "done" / "error".
    fn api_benchmark_result(&self) -> (u16, String, Bytes) {
        // V244 — read the shared file, not per-worker state, so a result is
        // visible no matter which SO_REUSEPORT worker the poll lands on.
        let idle = serde_json::to_string(&crate::benchmark::BenchmarkResult::idle())
            .unwrap_or_else(|_| r#"{"ok":true,"status":"idle","estimate":true}"#.to_string());
        read_result_file(&benchmark_result_path(), idle, 180)
    }

    /// V240 — POST /admin/api/benchmark/run.
    /// Fire-and-forget: returns 202 {"ok":true,"queued":true} immediately;
    /// 409 {"ok":false,"error":"benchmark_already_running"} if one is in progress.
    async fn api_benchmark_run(&self) -> (u16, String, Bytes) {
        let path = benchmark_result_path();
        // V244 — cross-worker gate: another worker may be mid-run.
        if result_running_fresh(&path, 180) {
            let body = serde_json::json!({ "ok": false, "error": "benchmark_already_running" });
            return (
                409,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        }
        let started_at_unix = match crate::benchmark::try_start(&self.bench_state) {
            Ok(ts) => ts,
            Err(()) => {
                let body = serde_json::json!({
                    "ok": false,
                    "error": "benchmark_already_running"
                });
                return (
                    409,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        };

        // V244 — publish a "running" sentinel to the shared file so any worker
        // polling /result reflects progress immediately.
        let running = crate::benchmark::BenchmarkResult::running(started_at_unix);
        write_result_file(
            &path,
            serde_json::to_vec(&running).unwrap_or_default().as_slice(),
        );

        // Clone the Arc so the spawned task owns its own handle.
        let state = Arc::clone(&self.bench_state);
        let result_path = path.clone();
        tokio::task::spawn_blocking(move || {
            let result = crate::benchmark::run_benchmark();
            // Persist the finished result to the shared file FIRST so a poll on
            // any worker sees "done" the instant the run completes.
            write_result_file(
                &result_path,
                serde_json::to_vec(&result).unwrap_or_default().as_slice(),
            );
            state.result.store(Arc::new(Some(result)));
            state
                .running
                .store(false, std::sync::atomic::Ordering::Release);
        });

        let body = serde_json::json!({
            "ok": true,
            "queued": true,
            "started_at_unix": started_at_unix,
        });
        (
            202,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V241 — GET /admin/api/benchmark/flood/result.
    /// Returns the current flood-suite state ("idle"/"running"/"done"/"error").
    fn api_flood_result(&self) -> (u16, String, Bytes) {
        // V244 — shared file so the result survives a poll landing on a
        // different SO_REUSEPORT worker than the one that ran the suite.
        let idle = serde_json::to_string(&crate::benchmark_flood::FloodResult::idle())
            .unwrap_or_else(|_| {
                r#"{"ok":true,"status":"idle","scenarios":[],"loopback":true,"caveat":""}"#
                    .to_string()
            });
        read_result_file(&flood_result_path(), idle, 60)
    }

    /// V241 — POST /admin/api/benchmark/flood/run.
    /// Fire-and-forget: 202 {"ok":true,"queued":true}; 409 if already running.
    async fn api_flood_run(&self) -> (u16, String, Bytes) {
        let path = flood_result_path();
        // V244 — cross-worker gate.
        if result_running_fresh(&path, 60) {
            let body = serde_json::json!({ "ok": false, "error": "flood_already_running" });
            return (
                409,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        }
        let started_at_unix = match crate::benchmark_flood::try_start(&self.flood_state) {
            Ok(ts) => ts,
            Err(()) => {
                let body = serde_json::json!({
                    "ok": false,
                    "error": "flood_already_running"
                });
                return (
                    409,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        };

        // V244 — publish a "running" sentinel to the shared file.
        let running = crate::benchmark_flood::FloodResult::running(started_at_unix);
        write_result_file(
            &path,
            serde_json::to_vec(&running).unwrap_or_default().as_slice(),
        );

        let state = Arc::clone(&self.flood_state);
        let result_path = path.clone();
        // The flood suite is async (drives loopback tokio servers/clients), so
        // run it on the runtime rather than spawn_blocking.
        tokio::spawn(async move {
            let result = crate::benchmark_flood::run_flood_suite().await;
            write_result_file(
                &result_path,
                serde_json::to_vec(&result).unwrap_or_default().as_slice(),
            );
            state.result.store(Arc::new(Some(result)));
            state
                .running
                .store(false, std::sync::atomic::Ordering::Release);
        });

        let body = serde_json::json!({
            "ok": true,
            "queued": true,
            "started_at_unix": started_at_unix,
        });
        (
            202,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V245 — GET /admin/api/benchmark/compare/result.
    fn api_compare_result(&self) -> (u16, String, Bytes) {
        let idle = serde_json::to_string(&crate::benchmark_compare::ComparisonResult::idle())
            .unwrap_or_else(|_| {
                r#"{"ok":true,"status":"idle","targets":[],"security":[]}"#.to_string()
            });
        read_result_file(&compare_result_path(), idle, 120)
    }

    /// V245 — POST /admin/api/benchmark/compare/run. Fire-and-forget.
    async fn api_compare_run(&self) -> (u16, String, Bytes) {
        let path = compare_result_path();
        if result_running_fresh(&path, 120) {
            let body = serde_json::json!({ "ok": false, "error": "compare_already_running" });
            return (
                409,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        }
        let started_at_unix = match crate::benchmark_compare::try_start(&self.compare_state) {
            Ok(ts) => ts,
            Err(()) => {
                let body = serde_json::json!({ "ok": false, "error": "compare_already_running" });
                return (
                    409,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        };
        let running = crate::benchmark_compare::ComparisonResult::running(started_at_unix);
        write_result_file(
            &path,
            serde_json::to_vec(&running).unwrap_or_default().as_slice(),
        );

        let state = Arc::clone(&self.compare_state);
        let result_path = path.clone();
        // V245 — hand the live FilterEngine to the comparison so the
        // "AEGIS + WAF" bar runs the real per-request inspection pipeline.
        let engine = self.engine.clone();
        tokio::spawn(async move {
            let result = crate::benchmark_compare::run_comparison(engine).await;
            write_result_file(
                &result_path,
                serde_json::to_vec(&result).unwrap_or_default().as_slice(),
            );
            state.result.store(Arc::new(Some(result)));
            state
                .running
                .store(false, std::sync::atomic::Ordering::Release);
        });

        let body = serde_json::json!({
            "ok": true,
            "queued": true,
            "started_at_unix": started_at_unix,
        });
        (
            202,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_challenge_get(&self, host: &str) -> (u16, String, Bytes) {
        let cfg = self
            .arsenal
            .as_ref()
            .map(|a| a.domain_challenge_config(host))
            .unwrap_or_default();
        let body = serde_json::json!({ "host": host, "config": cfg });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_challenge_put(&self, host: &str, body: &[u8]) -> (u16, String, Bytes) {
        let cfg: crate::arsenal::DomainChallengeConfig = match serde_json::from_slice(body) {
            Ok(c) => c,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid json: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        if let Some(arsenal) = self.arsenal.as_ref() {
            arsenal.set_domain_challenge_config(host.to_string(), cfg.clone());
        }
        let body = serde_json::json!({ "host": host, "config": cfg, "status": "saved" });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_challenge_delete(&self, host: &str) -> (u16, String, Bytes) {
        let removed = self
            .arsenal
            .as_ref()
            .map(|a| a.clear_domain_challenge_config(host))
            .unwrap_or(false);
        let body = serde_json::json!({ "host": host, "removed": removed });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_challenge_attack_mode(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            on: bool,
        }
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid json: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        if let Some(arsenal) = self.arsenal.as_ref() {
            arsenal.adaptive_ladder.set_attack_mode(p.on);
        }
        let body = serde_json::json!({ "attack_mode": p.on });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// V208 — GET /admin/api/updates/status. Cheap read of the cached
    /// status (does NOT poll upstream). Use POST /check for that.
    fn api_updates_status(&self) -> (u16, String, Bytes) {
        let body = match self.updates.as_ref() {
            Some(u) => serde_json::to_value(u.status()).unwrap_or(serde_json::json!({})),
            None => serde_json::json!({
                "wired": false,
                "note": "AdminProxy::with_updates() not called — \
                         operator opt-in via aegis-pingora binary"
            }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// V208 — POST /admin/api/updates/check. Forces an upstream
    /// refresh; returns the resulting status.
    fn api_updates_check(&self) -> (u16, String, Bytes) {
        let Some(u) = self.updates.as_ref() else {
            let body = serde_json::json!({ "error": "updates not wired" });
            return (
                503,
                "application/json".into(),
                Bytes::from(body.to_string()),
            );
        };
        match u.check() {
            Ok(n) => {
                let body = serde_json::json!({
                    "ok": true,
                    "releases_fetched": n,
                    "status": u.status(),
                });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(body.to_string()),
                )
            }
            Err(e) => {
                let body = serde_json::json!({
                    "ok": false,
                    "error": e,
                    "status": u.status(),
                });
                (
                    502,
                    "application/json".into(),
                    Bytes::from(body.to_string()),
                )
            }
        }
    }

    /// V208 — GET /admin/api/updates/releases. Full release history
    /// the checker has cached (after at least one /check call).
    fn api_updates_releases(&self) -> (u16, String, Bytes) {
        let Some(u) = self.updates.as_ref() else {
            return (200, "application/json".into(), Bytes::from("[]"));
        };
        let releases = u.releases();
        let body = serde_json::to_string(&releases).unwrap_or("[]".into());
        (200, "application/json".into(), Bytes::from(body))
    }

    /// V208 — PUT /admin/api/updates/config. Operator changes
    /// channel / poll interval / repo URL.
    fn api_updates_config_put(&self, body: &[u8]) -> (u16, String, Bytes) {
        let Some(u) = self.updates.as_ref() else {
            let body = serde_json::json!({ "error": "updates not wired" });
            return (
                503,
                "application/json".into(),
                Bytes::from(body.to_string()),
            );
        };
        let cfg: crate::updates::UpdateConfig = match serde_json::from_slice(body) {
            Ok(c) => c,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid json: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        u.update_config(cfg.clone());
        let body = serde_json::json!({ "ok": true, "config": cfg });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    // ── V213-V220 — panel gap-fill endpoints (PANEL-AUDIT-2026-05) ──

    fn api_scenarios_list(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let scenarios = a.scenarios.scenarios();
                let s = a.scenarios.stats();
                serde_json::json!({
                    "wired": true,
                    "scenarios": scenarios,
                    "stats": {
                        "events_observed": s.events_observed,
                        "events_matched": s.events_matched,
                        "events_bucketed": s.events_bucketed,
                        "buckets_fired": s.buckets_fired,
                        "buckets_active": a.scenarios.bucket_count(),
                    }
                })
            }
            None => serde_json::json!({ "wired": false, "scenarios": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_scenarios_load(&self, body: &[u8]) -> (u16, String, Bytes) {
        let Some(arsenal) = self.arsenal.as_ref() else {
            return (
                503,
                "application/json".into(),
                Bytes::from(r#"{"error":"arsenal not wired"}"#),
            );
        };
        let yaml = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"non-utf8 body"}"#),
                );
            }
        };
        match crate::scenarios::ScenarioEngine::parse_yaml(yaml) {
            Ok(cfgs) => {
                let n = cfgs.len();
                arsenal.scenarios.load_many(cfgs);
                // V246 — persist the raw YAML so this load propagates to
                // every SO_REUSEPORT worker (mtime-reload on the background
                // tick) and survives restart, instead of living only in the
                // one worker process that handled this request.
                arsenal.scenarios.save_yaml(yaml);
                let resp = serde_json::json!({ "ok": true, "loaded": n });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => {
                let resp = serde_json::json!({ "ok": false, "error": e });
                (
                    400,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
        }
    }

    fn api_scenarios_test(&self, body: &[u8]) -> (u16, String, Bytes) {
        let yaml = std::str::from_utf8(body).unwrap_or("");
        match crate::scenarios::ScenarioEngine::parse_yaml(yaml) {
            Ok(cfgs) => {
                let resp = serde_json::json!({ "ok": true, "parsed": cfgs });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => {
                let resp = serde_json::json!({ "ok": false, "error": e });
                (
                    400,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
        }
    }

    fn api_actuators_list(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let active: Vec<_> = a
                    .actuators
                    .active_actions()
                    .iter()
                    .map(|act| {
                        serde_json::json!({
                            "kind": act.kind.as_str(),
                            "target": act.target.as_display(),
                            "reason": act.params.reason,
                            "source_module": act.params.source_module,
                            "applied_at": act.applied_at.elapsed().as_secs(),
                            "remaining_secs": act.remaining().map(|d| d.as_secs()),
                        })
                    })
                    .collect();
                let s = a.actuators.stats();
                serde_json::json!({
                    "wired": true,
                    "active": active,
                    "kinds": a.actuators.registered_kinds().iter().map(|k| k.as_str()).collect::<Vec<_>>(),
                    "stats": {
                        "applied": s.applied.load(std::sync::atomic::Ordering::Relaxed),
                        "already_applied": s.already_applied.load(std::sync::atomic::Ordering::Relaxed),
                        "failed": s.failed.load(std::sync::atomic::Ordering::Relaxed),
                        "reverted_on_expiry": s.reverted_on_expiry.load(std::sync::atomic::Ordering::Relaxed),
                        "reverted_manually": s.reverted_manually.load(std::sync::atomic::Ordering::Relaxed),
                    }
                })
            }
            None => serde_json::json!({ "wired": false, "active": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_actuators_revert(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            kind: String,
            target_kind: String,
            target_value: String,
        }
        let Some(arsenal) = self.arsenal.as_ref() else {
            return (
                503,
                "application/json".into(),
                Bytes::from(r#"{"error":"arsenal not wired"}"#),
            );
        };
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let kind = match p.kind.as_str() {
            "xdp_deny" => crate::actuator::ActionKind::XdpDeny,
            "nft_drop" => crate::actuator::ActionKind::NftDrop,
            "bgp_announce" => crate::actuator::ActionKind::BgpAnnounce,
            "challenge_floor_raise" => crate::actuator::ActionKind::ChallengeFloorRaise,
            "response_cache_poison" => crate::actuator::ActionKind::ResponseCachePoison,
            _ => crate::actuator::ActionKind::Custom("manual"),
        };
        let target = match p.target_kind.as_str() {
            "ip" => match p.target_value.parse::<std::net::IpAddr>() {
                Ok(ip) => crate::actuator::Target::Ip(ip),
                Err(_) => crate::actuator::Target::Custom(p.target_value.clone()),
            },
            "path" => crate::actuator::Target::Path(p.target_value.clone()),
            "user_agent" => crate::actuator::Target::UserAgent(p.target_value.clone()),
            _ => crate::actuator::Target::Custom(p.target_value.clone()),
        };
        let outcome = arsenal.actuators.revert(kind, &target);
        let resp = serde_json::json!({ "outcome": format!("{outcome:?}") });
        (
            200,
            "application/json".into(),
            Bytes::from(resp.to_string()),
        )
    }

    // V230 — async-context handler; reads sigma rules off-thread via tokio::fs.
    async fn api_sigma_rules(&self) -> (u16, String, Bytes) {
        let path = resolve_sigma_rules_path();
        let exists = std::path::Path::new(&path).exists();
        let (rule_count, size_bytes) = if exists {
            // V230 — was std::fs::read_to_string (blocked the pingora runtime).
            let body = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            (body.matches("[[rules]]").count(), body.len() as u64)
        } else {
            (0, 0)
        };
        let body = serde_json::json!({
            "path": path,
            "exists": exists,
            "rule_count": rule_count,
            "size_bytes": size_bytes,
            "note": "regenerate via: aegis-sigma-import --input <sigma_dir> --output <this path>",
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_sigma_import(&self, body: &[u8]) -> (u16, String, Bytes) {
        let yaml = std::str::from_utf8(body).unwrap_or("");
        match crate::sigma::parse_yaml(yaml) {
            Ok(rule) => match crate::sigma::convert(&rule, "<paste>") {
                Ok(rules) => {
                    let resp = serde_json::json!({
                        "ok": true,
                        "title": rule.title,
                        "emitted": rules.len(),
                        "rules": rules,
                    });
                    (
                        200,
                        "application/json".into(),
                        Bytes::from(resp.to_string()),
                    )
                }
                Err(e) => {
                    let resp = serde_json::json!({ "ok": false, "error": e });
                    (
                        400,
                        "application/json".into(),
                        Bytes::from(resp.to_string()),
                    )
                }
            },
            Err(e) => {
                let resp = serde_json::json!({ "ok": false, "error": e });
                (
                    400,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
        }
    }

    /// V237 — GET /admin/api/sigma/rules/list. Returns every rule in
    /// the bundled corpus with its current enabled state (from the
    /// disk overlay the WAF compile path reads). Shape per rule:
    /// `{id, field, op, value, severity, action, tags, enabled}`.
    /// The React panel renders these as a searchable list with a
    /// per-rule Switch, same UX as the honeypot packs page.
    async fn api_sigma_rules_list(&self) -> (u16, String, Bytes) {
        let path = resolve_sigma_rules_path();
        // V230 — async read off the pingora runtime (the corpus is
        // ~5600 lines / a few hundred KiB).
        let raw = match tokio::fs::read_to_string(&path).await {
            Ok(r) => r,
            Err(e) => {
                return json_err(404, &format!("sigma rules file not readable: {e}"));
            }
        };
        let parsed: crate::config::WafRuleFile = match toml::from_str(&raw) {
            Ok(f) => f,
            Err(e) => return json_err(500, &format!("sigma rules parse error: {e}")),
        };
        // Disabled set is a HashSet probe per rule — fine for 562 rules.
        // Refresh from disk first so a toggle made on another SO_REUSEPORT
        // worker is reflected immediately (the overlay is cross-worker via
        // mtime poll; without this the admin read could show a stale set).
        self.waf.sigma_overlay().refresh();
        let disabled = self.waf.sigma_overlay().disabled_ids();
        let rules: Vec<serde_json::Value> = parsed
            .rules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "field": r.field,
                    "op": r.op,
                    "value": r.value,
                    "severity": r.severity.as_deref().unwrap_or("medium"),
                    "action": r.action,
                    "tags": r.tags,
                    "enabled": !disabled.contains(&r.id),
                })
            })
            .collect();
        let total = rules.len();
        let disabled_count = disabled.len();
        let body = serde_json::json!({
            "path": path,
            "total": total,
            "disabled_count": disabled_count,
            "rules": rules,
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// V237 — PUT /admin/api/sigma/rules/toggle. Body `{id, enabled}`.
    /// Flips one rule's enabled state in the disk overlay (cross-worker
    /// via mtime poll) and forces an immediate recompile on this worker
    /// so the change is live for the next request — mirrors the
    /// honeypot pack toggle.
    fn api_sigma_rule_toggle(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            id: String,
            enabled: bool,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"id\":...,\"enabled\":bool}");
        };
        if input.id.trim().is_empty() {
            return json_err(400, "id must not be empty");
        }
        match self
            .waf
            .sigma_overlay()
            .set_enabled(&input.id, input.enabled)
        {
            Ok(()) => {
                // Recompile this worker's rule plan now; other workers
                // pick up the overlay file change on their next poll.
                self.waf.recompile_now();
                let resp = serde_json::json!({
                    "ok": true,
                    "id": input.id,
                    "enabled": input.enabled,
                });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    fn api_enrichment_status(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let e = a.enrichment.read().unwrap();
                let sources: Vec<_> = e
                    .registered_sources()
                    .iter()
                    .map(|name| {
                        let (q, h, m) = e.source_stats(name).unwrap_or((0, 0, 0));
                        serde_json::json!({
                            "name": name,
                            "queries": q,
                            "hits": h,
                            "misses": m,
                        })
                    })
                    .collect();
                let (hits, misses, size) = e.cache_stats();
                serde_json::json!({
                    "wired": true,
                    "sources": sources,
                    "cache": {
                        "hits": hits,
                        "misses": misses,
                        "size": size,
                    }
                })
            }
            None => serde_json::json!({ "wired": false, "sources": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_enrichment_lookup(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            key_kind: String,
            value: String,
        }
        let Some(arsenal) = self.arsenal.as_ref() else {
            return (
                503,
                "application/json".into(),
                Bytes::from(r#"{"error":"arsenal not wired"}"#),
            );
        };
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let key = match p.key_kind.as_str() {
            "ip" => match p.value.parse::<std::net::IpAddr>() {
                Ok(ip) => crate::enrichment::EntityKey::Ip(ip),
                Err(_) => {
                    return (
                        400,
                        "application/json".into(),
                        Bytes::from(r#"{"error":"bad ip"}"#),
                    );
                }
            },
            "ja4" => crate::enrichment::EntityKey::Ja4(p.value),
            "asn" => match p.value.parse::<u32>() {
                Ok(n) => crate::enrichment::EntityKey::Asn(n),
                Err(_) => {
                    return (
                        400,
                        "application/json".into(),
                        Bytes::from(r#"{"error":"bad asn"}"#),
                    );
                }
            },
            "user_agent" => crate::enrichment::EntityKey::UserAgent(p.value),
            _ => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"unknown key_kind"}"#),
                );
            }
        };
        let result = arsenal.enrichment.read().unwrap().lookup(&key);
        let body = serde_json::json!({
            "aggregate": format!("{:?}", result.aggregate()),
            "sources": result.sources.iter().map(|h| serde_json::json!({
                "source": h.source,
                "verdict": format!("{:?}", h.verdict),
                "label": h.label,
            })).collect::<Vec<_>>(),
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_reputation_ja4(&self) -> (u16, String, Bytes) {
        let body = serde_json::json!({
            "wired": self.ja4_reputation.is_some(),
            "entry_count": self.ja4_reputation.as_ref().map(|r| r.entry_count()).unwrap_or(0),
            "active": self.ja4_reputation.as_ref().map(|r| r.is_active()).unwrap_or(false),
            "corpus_count": self.arsenal.as_ref().map(|a| a.ja4_corpus.len()).unwrap_or(0),
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_reputation_ja4_lookup(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            ja4: String,
        }
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let feed_hit = self.ja4_reputation.as_ref().and_then(|r| r.lookup(&p.ja4));
        let corpus_hit = self.arsenal.as_ref().map(|a| a.ja4_corpus.lookup(&p.ja4));
        let body = serde_json::json!({
            "ja4": p.ja4,
            "feed": feed_hit.map(|h| serde_json::json!({
                "tag": h.tag,
                "kind": format!("{:?}", h.match_kind),
            })),
            "corpus": corpus_hit.map(|h| serde_json::json!({
                "verdict": format!("{:?}", h.verdict),
                "label": h.label,
            })),
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_reputation_asn(&self) -> (u16, String, Bytes) {
        let body = serde_json::json!({
            "wired": self.asn_reputation.is_some(),
            "entry_count": self.asn_reputation.as_ref().map(|r| r.entry_count()).unwrap_or(0),
            "active": self.asn_reputation.as_ref().map(|r| r.is_active()).unwrap_or(false),
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_reputation_asn_lookup(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            ip: String,
        }
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let ip = match p.ip.parse::<std::net::IpAddr>() {
            Ok(i) => i,
            Err(_) => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"bad ip"}"#),
                );
            }
        };
        let hit = self.asn_reputation.as_ref().and_then(|r| r.lookup(ip));
        let body = serde_json::json!({
            "ip": p.ip,
            "score": hit.as_ref().map(|h| h.score),
            "tag": hit.as_ref().map(|h| h.tag.clone()),
            "match_kind": hit.as_ref().map(|h| format!("{:?}", h.match_kind)),
            "matched": hit.is_some(),
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_ml_status(&self) -> (u16, String, Bytes) {
        let body = serde_json::json!({
            "v2_wired": self.ml_v2.is_some(),
            "v2_kind": self.ml_v2.as_ref().map(|m| match m.kind() {
                crate::ddos::ml_model::MlModelKind::Logistic => "logistic",
                crate::ddos::ml_model::MlModelKind::Gbm => "gbm",
            }),
            "adversarial_loop_env": std::env::var("AEGIS_ML_ADVERSARIAL").ok().map(|v| v == "1").unwrap_or(false),
            "samples_endpoint": "/admin/api/ml/samples (POST training samples via DSL retrain)",
            "note": "Detailed retrain/sample browser planned; current endpoint surfaces status only",
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// POST /admin/api/ml/retrain.
    ///
    /// Request body (all fields optional):
    ///   {
    ///     "epochs": 1,            // SGD passes (default 1, capped at 1000)
    ///     "lr": 0.1,              // learning rate (default 0.1)
    ///     "samples": [            // optional operator-labelled samples to
    ///                             // ingest BEFORE retraining
    ///       { "features": [<23 floats>], "label": "malicious" },
    ///       { "features": [<23 floats>], "label": "benign" }
    ///     ]
    ///   }
    ///
    /// Behaviour:
    ///   * When the trainer isn't wired (`with_ml_trainer` not called) →
    ///     501 with a clear, actionable error.
    ///   * Any supplied samples are added to the trainer's ring (and
    ///     persisted if the trainer has a persistence path).
    ///   * A retrain pass runs over ALL stored samples; the TrainResult
    ///     (loss before/after) is returned so the UI can show convergence.
    fn api_ml_retrain(&self, body: &[u8]) -> (u16, String, Bytes) {
        let Some(trainer) = self.ml_trainer.as_ref() else {
            let body = serde_json::json!({
                "ok": false,
                "error": "ml trainer not wired into AdminProxy",
                "hint": "construct an MlTrainer in aegis-pingora.rs and call admin.with_ml_trainer(...); requires AEGIS_ML_V2=1 for the V2 scorer",
            });
            return (
                501,
                "application/json".into(),
                Bytes::from(body.to_string()),
            );
        };

        // Empty body is allowed → retrain over existing samples with defaults.
        let req: MlRetrainRequest = if body.is_empty() {
            MlRetrainRequest::default()
        } else {
            match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => {
                    let err =
                        serde_json::json!({ "ok": false, "error": format!("invalid body: {e}") });
                    return (400, "application/json".into(), Bytes::from(err.to_string()));
                }
            }
        };

        // Validate + clamp hyperparameters.
        let epochs = req.epochs.unwrap_or(1).clamp(1, 1000);
        let lr = req.lr.unwrap_or(0.1);
        if !(lr.is_finite() && lr > 0.0 && lr <= 10.0) {
            let err = serde_json::json!({ "ok": false, "error": "lr must be a finite number in (0, 10]" });
            return (400, "application/json".into(), Bytes::from(err.to_string()));
        }

        // Ingest any supplied samples.
        let mut ingested = 0usize;
        for (i, s) in req.samples.iter().enumerate() {
            let sample = match s.to_labelled_sample() {
                Ok(ls) => ls,
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("sample[{i}]: {e}"),
                    });
                    return (400, "application/json".into(), Bytes::from(err.to_string()));
                }
            };
            trainer.add_sample(sample);
            ingested += 1;
        }

        let total = trainer.sample_count();
        if total == 0 {
            let err = serde_json::json!({
                "ok": false,
                "error": "no training samples available; supply `samples` in the body or POST labelled samples first",
                "samples_total": 0,
            });
            return (400, "application/json".into(), Bytes::from(err.to_string()));
        }

        let result = trainer.retrain(epochs, lr);
        let body = serde_json::json!({
            "ok": true,
            "samples_ingested": ingested,
            "samples_total": total,
            "samples_used": result.samples_used,
            "epochs": result.epochs,
            "learning_rate": lr,
            "starting_loss": result.starting_loss,
            "ending_loss": result.ending_loss,
            "residual_drop": result.residual_drop,
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_ml_adversarial(&self) -> (u16, String, Bytes) {
        let on = std::env::var("AEGIS_ML_ADVERSARIAL").ok().as_deref() == Some("1");
        let body = serde_json::json!({
            "ok": on,
            "enabled": on,
            "hint": if on {
                "adversarial loop runs every N background ticks; check /admin/api/ml/status for last run"
            } else {
                "set AEGIS_ML_ADVERSARIAL=1 and restart to enable"
            },
        });
        (
            if on { 200 } else { 501 },
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_privacy_pass_list(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => serde_json::json!({
                "wired": true,
                "issuer_count": a.privacy_pass.issuer_count(),
                "nonce_cache_size": a.privacy_pass.nonce_cache_size(),
                "note": "GET /admin/api/privacy-pass/issuers lists issuers; POST there registers one at runtime",
            }),
            None => serde_json::json!({ "wired": false, "issuer_count": 0 }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// GET /admin/api/privacy-pass/issuers — full issuer list for the panel.
    ///
    /// Delegates to `PrivacyPassVerifier::list_issuers()`, which returns a
    /// panel-safe `IssuerInfo` per issuer (name, full key-id hex, algorithm,
    /// a fingerprint of the public key — never raw key bytes — and the trust
    /// window in seconds). Returns `{wired:false, issuers:[]}` when the
    /// arsenal (which owns the verifier) isn't attached.
    fn api_privacy_pass_issuers(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let issuers = a.privacy_pass.list_issuers();
                serde_json::json!({
                    "wired": true,
                    "issuer_count": issuers.len(),
                    "issuers": issuers,
                })
            }
            None => serde_json::json!({ "wired": false, "issuer_count": 0, "issuers": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_privacy_pass_add(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            name: String,
            key_id_hex: String,
            public_key_hex: String,
            algorithm: String,
            trust_duration_secs: u64,
        }
        let Some(arsenal) = self.arsenal.as_ref() else {
            return (
                503,
                "application/json".into(),
                Bytes::from(r#"{"error":"arsenal not wired"}"#),
            );
        };
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let key_id_bytes = match hex_to_bytes(&p.key_id_hex, 32) {
            Some(b) => b,
            None => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"key_id_hex must be 64 hex chars"}"#),
                );
            }
        };
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&key_id_bytes);
        let public_key = match hex_to_bytes_any(&p.public_key_hex) {
            Some(b) => b,
            None => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"bad public_key_hex"}"#),
                );
            }
        };
        let algorithm = match p.algorithm.as_str() {
            "ed25519" => crate::privacy_pass::SignatureAlgorithm::Ed25519,
            "hmac_sha256" => crate::privacy_pass::SignatureAlgorithm::HmacSha256,
            _ => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"algorithm must be ed25519|hmac_sha256"}"#),
                );
            }
        };
        arsenal
            .privacy_pass
            .register_issuer(crate::privacy_pass::TrustedIssuer {
                key_id,
                name: p.name.clone(),
                public_key,
                algorithm,
                trust_duration: std::time::Duration::from_secs(p.trust_duration_secs.max(60)),
            });
        let body = serde_json::json!({ "ok": true, "name": p.name });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_bgp_list(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let active: Vec<_> = a
                    .bgp_rtbh
                    .active()
                    .into_iter()
                    .map(|(ip, community, age)| {
                        serde_json::json!({
                            "ip": ip.to_string(),
                            "community": community,
                            "age_secs": age.as_secs(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "wired": true,
                    "active_count": active.len(),
                    "active": active,
                })
            }
            None => serde_json::json!({ "wired": false, "active": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_bgp_withdraw(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            ip: String,
        }
        let Some(arsenal) = self.arsenal.as_ref() else {
            return (
                503,
                "application/json".into(),
                Bytes::from(r#"{"error":"arsenal not wired"}"#),
            );
        };
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let ip: std::net::IpAddr = match p.ip.parse() {
            Ok(i) => i,
            Err(_) => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"bad ip"}"#),
                );
            }
        };
        match arsenal.bgp_rtbh.withdraw(ip) {
            Ok(()) => {
                let body = serde_json::json!({ "ok": true, "ip": p.ip });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(body.to_string()),
                )
            }
            Err(e) => {
                let body = serde_json::json!({ "ok": false, "error": e.to_string() });
                (
                    500,
                    "application/json".into(),
                    Bytes::from(body.to_string()),
                )
            }
        }
    }

    // ── V221-V227 — final panel gap-fill (status read-only views) ──

    fn api_telemetry_status(&self) -> (u16, String, Bytes) {
        let format = std::env::var("AEGIS_EVENT_FORMAT")
            .ok()
            .unwrap_or_else(|| "native".into());
        let clamav = std::env::var("AEGIS_CLAMAV_ADDR").ok();
        let body = serde_json::json!({
            "event_bridge": {
                "format": format,
                "format_options": ["native", "sicherheitstacho", "tpot"],
                "socket_path": std::env::var("AEGIS_EVENT_SOCKET").ok(),
            },
            "clamav": {
                "enabled": clamav.is_some(),
                "addr": clamav,
                "env_var": "AEGIS_CLAMAV_ADDR (host:port)",
            },
            "audit_log_path": self.audit_log_path.as_ref().map(|p| p.display().to_string()),
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_geoip_status(&self) -> (u16, String, Bytes) {
        // V235 — report the DB Aegis actually resolves out of the box
        // (env override → bundled db-ip lite under /var/lib/aegis/geoip),
        // plus the on-disk DB metadata (type + build date) so the panel
        // can show "db-ip Country Lite, built <date>" and whether an
        // update is warranted.
        let resolved = crate::geoip::resolve_country_db_path(None);
        let asn_path = std::env::var("AEGIS_ASN_PATH").ok();
        let mut db_type = serde_json::Value::Null;
        let mut build_epoch = serde_json::Value::Null;
        let mut loaded = false;
        if let Some(p) = resolved.as_deref()
            && let Ok(reader) = maxminddb::Reader::open_readfile(p)
        {
            loaded = true;
            db_type = serde_json::Value::String(reader.metadata.database_type.clone());
            build_epoch = serde_json::json!(reader.metadata.build_epoch);
        }
        let body = serde_json::json!({
            "geoip_db_path": resolved,
            "asn_db_path": asn_path,
            "loaded": loaded,
            "database_type": db_type,
            "build_epoch": build_epoch,
            "bundled": true,
            "attribution": "IP geolocation by DB-IP (https://db-ip.com) — CC BY 4.0",
            "note": "Bundled db-ip Country Lite loads out of the box; click Update to refresh \
                     to the current month. deny_countries / attack_mode_only via [geoip] block.",
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    /// V235 — POST /admin/api/geoip/update. Refresh the bundled country
    /// DB to the current month's db-ip "IP to Country Lite" (CC BY 4.0).
    /// We ship no Rust HTTP/gzip dependency, so this shells out to
    /// `curl | gunzip`, atomically swaps the mmdb under
    /// /var/lib/aegis/geoip, and (only on success) writes the restart
    /// marker so the path-watcher reloads the refreshed DB. Runs detached
    /// — the download can take many seconds — and the panel re-polls
    /// status (the build date changes once the restart completes).
    fn api_geoip_update(&self) -> (u16, String, Bytes) {
        let dir = "/var/lib/aegis/geoip";
        let marker = aegis_env_file_path()
            .with_file_name(".restart-request")
            .to_string_lossy()
            .into_owned();
        let script = format!(
            "set -e; mkdir -p {dir}; \
             url=\"https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz\"; \
             tmp={dir}/.dbip.new; \
             curl -sfL --max-time 180 \"$url\" | gunzip > \"$tmp\"; \
             [ -s \"$tmp\" ]; \
             mv -f \"$tmp\" {dir}/dbip-country-lite.mmdb; \
             date +%s > {dir}/.last-update; \
             date +%s > {marker}"
        );
        match std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => {
                let body = serde_json::json!({
                    "ok": true,
                    "note": "GeoIP update started (db-ip Country Lite, CC BY 4.0). \
                             The service restarts automatically once the refreshed \
                             database is downloaded; re-check status in ~30s.",
                });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(body.to_string()),
                )
            }
            Err(e) => json_err(500, &format!("failed to start geoip update: {e}")),
        }
    }

    fn api_geoip_lookup(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct Payload {
            ip: String,
        }
        let p: Payload = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => {
                let err = serde_json::json!({ "error": format!("invalid: {e}") });
                return (400, "application/json".into(), Bytes::from(err.to_string()));
            }
        };
        let _ip = match p.ip.parse::<std::net::IpAddr>() {
            Ok(i) => i,
            Err(_) => {
                return (
                    400,
                    "application/json".into(),
                    Bytes::from(r#"{"error":"bad ip"}"#),
                );
            }
        };
        // GeoIP handle isn't currently plumbed into AdminProxy
        // (it lives on AegisPingoraProxy). Surface guidance instead.
        let body = serde_json::json!({
            "ip": p.ip,
            "note": "GeoIP lookup at /admin/api/geoip/lookup planned; \
                     consult MaxMind directly until plumbed",
        });
        (
            501,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_cluster_status(&self) -> (u16, String, Bytes) {
        let shared = self.shared_scorer.is_some();
        let counts = self
            .shared_scorer
            .as_ref()
            .map(|s| {
                serde_json::json!({
                    "ipv4_slots_active": s.live_v4_count(),
                    "top": s.top(10).iter().map(|(ip, score)| serde_json::json!({
                        "ip": ip.to_string(),
                        "score": score.0,
                    })).collect::<Vec<_>>(),
                })
            })
            .unwrap_or(serde_json::json!({}));
        let body = serde_json::json!({
            "shared_scorer_attached": shared,
            "counts": counts,
            "note": if shared { "Phase D cluster scorer active" }
                    else { "Per-worker only — macOS / restricted container" },
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_tarpit_status(&self) -> (u16, String, Bytes) {
        let snap = self.honeypots.snapshot();
        let body = serde_json::json!({
            "tarpit_seconds": snap.tarpit_seconds,
            "tarpit_chunk_bytes": snap.tarpit_chunk_bytes,
            "auto_xdp_deny_threshold": snap.auto_xdp_deny_threshold,
            "poisoned_tarpit_default_delay_ms": 350,
            "note": "configure via [filters.honeypot] and AEGIS_TARPIT_LOG env",
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_honeypot_yaml_list(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let descs: Vec<_> = a
                    .yaml_honeypot
                    .descriptors()
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "name": d.name,
                            "path_pattern": d.path_pattern,
                            "turns": d.turns.len(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "wired": true,
                    "descriptors": descs,
                    "active_sessions": a.yaml_honeypot.sessions(),
                })
            }
            None => serde_json::json!({ "wired": false, "descriptors": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_honeypot_yaml_load(&self, body: &[u8]) -> (u16, String, Bytes) {
        // YamlHoneypotEngine is constructed at startup with a fixed
        // Vec; runtime hot-reload requires an Arc<RwLock<…>> swap
        // that isn't in scope here. Surface the YAML preview instead
        // so operators can validate before redeploying.
        let yaml = std::str::from_utf8(body).unwrap_or("");
        match crate::honeypot_yaml::parse_descriptors(yaml) {
            Ok(ds) => {
                let resp = serde_json::json!({
                    "ok": true,
                    "parsed": ds.iter().map(|d| serde_json::json!({
                        "name": d.name,
                        "path_pattern": d.path_pattern,
                        "turns": d.turns.len(),
                    })).collect::<Vec<_>>(),
                    "note": "runtime hot-load not yet wired; redeploy with these descriptors",
                });
                (
                    200,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => {
                let resp = serde_json::json!({ "ok": false, "error": e });
                (
                    400,
                    "application/json".into(),
                    Bytes::from(resp.to_string()),
                )
            }
        }
    }

    fn api_crowdsec_status(&self) -> (u16, String, Bytes) {
        // V157 ships only the format adapter. Real CrowdSec LAPI
        // wiring is operator-supplied. Surface guidance.
        let lapi_url = std::env::var("AEGIS_CROWDSEC_LAPI_URL").ok();
        let bouncer_key = std::env::var("AEGIS_CROWDSEC_BOUNCER_KEY").is_ok();
        let body = serde_json::json!({
            "lapi_url": lapi_url,
            "bouncer_key_configured": bouncer_key,
            "format_adapter_available": true,
            "note": "Aegis emits decisions in CrowdSec LAPI wire format. \
                     Wire AEGIS_CROWDSEC_LAPI_URL + AEGIS_CROWDSEC_BOUNCER_KEY to push/pull.",
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_captcha_status(&self) -> (u16, String, Bytes) {
        let pow = std::env::var("AEGIS_POW_DIFFICULTY").ok();
        let hcaptcha = std::env::var("AEGIS_HCAPTCHA_SECRET").is_ok();
        let turnstile = std::env::var("AEGIS_TURNSTILE_SECRET").is_ok();
        let recaptcha = std::env::var("AEGIS_RECAPTCHA_SECRET").is_ok();
        let body = serde_json::json!({
            "pow": {
                "enabled": true,
                "difficulty_bits": pow.unwrap_or_else(|| "16".into()),
                "algorithm": "SHA-256 hashcash (V131) + Argon2id alt (V200)",
            },
            "external_providers": {
                "hcaptcha": hcaptcha,
                "turnstile": turnstile,
                "recaptcha": recaptcha,
            },
            "note": "secrets via AEGIS_HCAPTCHA_SECRET / AEGIS_TURNSTILE_SECRET / AEGIS_RECAPTCHA_SECRET env",
        });
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_route_difficulty_list(&self) -> (u16, String, Bytes) {
        let body = match self.arsenal.as_ref() {
            Some(a) => {
                let overrides: Vec<_> = a
                    .route_difficulty
                    .overrides()
                    .iter()
                    .map(|o| {
                        serde_json::json!({
                            "host": o.host,
                            "path_pattern": o.path_pattern,
                            "difficulty_bits": o.difficulty_bits,
                            "force_kind": o.force_kind.map(|k| format!("{k:?}")),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "wired": true,
                    "overrides": overrides,
                    "ai_scraper_preset": true,
                    "auth_preset": true,
                })
            }
            None => serde_json::json!({ "wired": false, "overrides": [] }),
        };
        (
            200,
            "application/json".into(),
            Bytes::from(body.to_string()),
        )
    }

    // V233 — REMOVED: the in-panel self-update *apply* and *snapshot*
    // machinery. `api_updates_apply` accepted an attacker-controllable
    // `download_url` with an optional, self-supplied SHA256 and no
    // signature verification, then fork+exec'd `aegis-updater` to
    // download and EXECUTE that binary as the service user — an
    // unauthenticated-RCE-class design. Removed alongside it:
    //   • api_updates_snapshots_list / _create / _restore / _delete
    //   • api_updates_releases_installed   (apply-layout staging view)
    //   • api_updates_apply_status         (apply-run progress stream)
    //   • the snapshot_manager / release_layout / apply_status_path
    //     helpers that only fed the removed handlers.
    // The read-only checker (status / check / releases / config) is
    // KEPT — see api_updates_status etc. above. Operators now install
    // releases manually from the CLI via `sudo bash install.sh`.

    fn api_runtime_info(&self) -> (u16, String, Bytes) {
        use crate::filters::engine::RuntimeToggles;
        let _ = RuntimeToggles::new; // anchor crate path
        let cargo_pkg_version = env!("CARGO_PKG_VERSION");
        let uptime_secs = self.started_at.elapsed().as_secs();
        let ml_v2 = self.ml_v2.as_ref().map(|m| {
            serde_json::json!({
                "kind": match m.kind() {
                    crate::ddos::ml_model::MlModelKind::Logistic => "logistic",
                    crate::ddos::ml_model::MlModelKind::Gbm => "gbm",
                },
                "available": true,
            })
        });
        let ja4 = self.ja4_reputation.as_ref().map(|r| {
            serde_json::json!({
                "active": r.is_active(),
                "entry_count": r.entry_count(),
            })
        });
        let asn = self.asn_reputation.as_ref().map(|r| {
            serde_json::json!({
                "active": r.is_active(),
                "entry_count": r.entry_count(),
            })
        });
        let honeypot_snap = self.honeypots.snapshot();
        let honeypot = serde_json::json!({
            "enabled": honeypot_snap.enabled,
            "packs_total": crate::honeypot::BUILTIN_PACKS.len(),
            "packs_enabled": crate::honeypot::BUILTIN_PACKS
                .iter()
                .filter(|p| honeypot_snap.packs.get(p.id).copied().unwrap_or(true))
                .count(),
            "custom_paths_count": honeypot_snap.custom_paths.len(),
            "tarpit_seconds": honeypot_snap.tarpit_seconds,
            "auto_xdp_deny_threshold": honeypot_snap.auto_xdp_deny_threshold,
        });

        // V-env — live env-flag snapshot for the Settings / Status page so
        // the UI can display current state without reading the env file directly.
        let bool_env = |k: &str| std::env::var(k).ok().map(|v| v == "1").unwrap_or(false);
        let opt_env = |k: &str| std::env::var(k).ok();

        let body = serde_json::json!({
            "version": cargo_pkg_version,
            "uptime_secs": uptime_secs,
            "config_path": self.config_path.display().to_string(),
            "ml_v2": ml_v2,
            "ja4_reputation": ja4,
            "asn_reputation": asn,
            "honeypot": honeypot,
            "filter_toggles_count": self.filter_toggles.len(),
            "domain_policy_count": self.domain_policy.len(),
            // Feature-flag env status (live process environment).
            "ml_v2_enabled":           bool_env("AEGIS_ML_V2"),
            "ml_v1_enabled":           bool_env("AEGIS_ML_SCORER"),
            "ml_adversarial":          bool_env("AEGIS_ML_ADVERSARIAL"),
            "arsenal_enabled":         std::env::var("AEGIS_ARSENAL").ok().as_deref() != Some("0"),
            "tls_fingerprinting":      bool_env("AEGIS_TLS_FINGERPRINT"),
            "llm_honeypot":            bool_env("AEGIS_LLM_HONEYPOT"),
            "upstream_healthcheck":    bool_env("AEGIS_UPSTREAM_HEALTHCHECK"),
            "risk_engine_mode":        opt_env("AEGIS_RISK_ENGINE_MODE"),
            "dynamic_trust_enabled":   bool_env("AEGIS_DYNAMIC_TRUST_ENABLE"),
            "response_cache_enabled":  bool_env("AEGIS_RESPONSE_CACHE_ENABLE"),
            "log_json":                bool_env("AEGIS_LOG_JSON"),
            "fw_backend":              opt_env("AEGIS_FW_BACKEND").unwrap_or_else(|| "auto".to_string()),
            "reuseport":               bool_env("AEGIS_PINGORA_REUSEPORT"),
            "clamav_addr":             opt_env("AEGIS_CLAMAV_ADDR"),
            "adversarial_loop":        bool_env("AEGIS_ML_ADVERSARIAL"),
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    // ── ACME / Let's Encrypt admin endpoints ─────────────────────────────────

    /// GET /admin/api/acme/config — Read role.
    fn api_acme_config_get(&self) -> (u16, String, Bytes) {
        let cfg = AcmeConfig::load_or_default(&self.acme_config_path);
        let body = serde_json::json!({
            "account_email": cfg.account_email,
            "use_production": cfg.use_production,
            "accepted_tos_at": cfg.accepted_tos_at,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// PUT /admin/api/acme/config — Write role. Partial update; all fields optional.
    fn api_acme_config_put(&self, body_bytes: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            account_email: Option<String>,
            use_production: Option<bool>,
            accepted_tos_at: Option<u64>,
        }
        let input: In = match serde_json::from_slice(body_bytes) {
            Ok(v) => v,
            Err(e) => return json_err(400, &format!("invalid JSON body: {e}")),
        };

        let mut cfg = AcmeConfig::load_or_default(&self.acme_config_path);

        // Apply partial updates.
        if let Some(email) = input.account_email {
            cfg.account_email = if email.is_empty() { None } else { Some(email) };
        }
        if let Some(ts) = input.accepted_tos_at {
            cfg.accepted_tos_at = Some(ts);
        }
        if let Some(prod) = input.use_production {
            // Switching to production requires TOS acceptance (in this request or already stored).
            if prod && cfg.accepted_tos_at.is_none() {
                return json_err(
                    400,
                    "use_production=true requires accepted_tos_at to be set \
                     (set it in the same request or a prior PUT)",
                );
            }
            cfg.use_production = prod;
        }

        if let Err(e) = cfg.save(&self.acme_config_path) {
            tracing::error!(error = %e, "acme: failed to persist config");
            return json_err(500, &format!("failed to persist ACME config: {e}"));
        }
        tracing::info!(
            use_production = cfg.use_production,
            has_email = cfg.account_email.is_some(),
            "acme: config updated via admin API"
        );

        let body = serde_json::json!({
            "account_email": cfg.account_email,
            "use_production": cfg.use_production,
            "accepted_tos_at": cfg.accepted_tos_at,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// GET /admin/api/acme/orders — Read role.
    fn api_acme_orders_list(&self) -> (u16, String, Bytes) {
        let mut records = self.acme_orders.all();
        // Overlay in-flight status for any hosts currently being provisioned.
        for rec in &mut records {
            if self.acme_orders.is_in_flight(&rec.host) {
                rec.status = "pending".to_string();
            }
        }
        let orders: Vec<serde_json::Value> = records.iter().map(|r| r.to_api_json()).collect();
        let body = serde_json::json!({ "orders": orders });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// GET /admin/api/acme/orders/<host> — Read role.
    fn api_acme_orders_get(&self, host: &str) -> (u16, String, Bytes) {
        match self.acme_orders.get(host) {
            Some(mut rec) => {
                if self.acme_orders.is_in_flight(host) {
                    rec.status = "pending".to_string();
                }
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(rec.to_api_json().to_string()),
                )
            }
            None => json_err(404, &format!("no order record for host {host:?}")),
        }
    }

    /// POST /admin/api/acme/orders — Write role. Enqueue a new issuance.
    async fn api_acme_orders_create(&self, body_bytes: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            host: String,
            #[allow(dead_code)]
            email: Option<String>,
        }
        let input: In = match serde_json::from_slice(body_bytes) {
            Ok(v) => v,
            Err(e) => return json_err(400, &format!("invalid JSON body: {e}")),
        };

        // Validate hostname.
        if let Err(e) = crate::admin_ui::validate_host(&input.host) {
            return json_err(400, &format!("invalid host: {e}"));
        }

        let Some(client) = self.acme_client.clone() else {
            return json_err(
                503,
                "ACME client not configured — set account_email via PUT /admin/api/acme/config and restart",
            );
        };

        if self.acme_orders.is_in_flight(&input.host) {
            return json_err(
                409,
                &format!("order already in flight for host {}", input.host),
            );
        }

        // V237 — adversarial review must-fix: after a completed order (issued
        // or failed), reject re-orders within MIN_ORDER_INTERVAL_SECS for the
        // same host. The in_flight guard only blocks concurrent double-orders;
        // without this cooldown a Write-role attacker could burn the LE prod
        // rate limit (5 issuances per registered domain per week) in seconds
        // by hammering the endpoint in a loop. One hour is a generous safe
        // floor (renewal naturally happens every ~30 days for 90-day certs).
        if let Err(e) = check_acme_order_cooldown(self.acme_orders.get(&input.host).as_ref()) {
            return e;
        }

        self.acme_orders.mark_in_flight(&input.host);

        // Spawn background issuance task.
        let host = input.host.clone();
        let orders = Arc::clone(&self.acme_orders);
        let cert_dir = crate::acme::CertDir::new("/var/lib/aegis/certs");
        // CRITICAL: use the SAME ChallengeStore the data-plane HTTP-01
        // handler reads from. Default::default() creates a fresh store,
        // tokens go in but the proxy never sees them, LE GETs a 302 →
        // validation fails with state=Invalid. Live-tested on the production stand.
        let challenges = self
            .acme_challenges
            .clone()
            .unwrap_or_else(crate::acme::ChallengeStore::new);
        let provisioner = crate::acme::Provisioner::new(client, challenges, cert_dir);
        tokio::spawn(async move {
            tracing::info!(host, "acme: starting issuance");
            match provisioner.issue(&[host.clone()]).await {
                Ok(cert) => {
                    let not_after = cert.not_after_unix;
                    // Write cert to disk.
                    let cert_dir2 = crate::acme::CertDir::new("/var/lib/aegis/certs");
                    match cert_dir2.write_async(&cert).await {
                        Ok((crt, key)) => {
                            tracing::info!(host, crt = ?crt, key = ?key, "acme: cert written");
                            orders.update_issued(&host, not_after);
                        }
                        Err(e) => {
                            tracing::error!(host, error = %e, "acme: cert write failed");
                            orders.update_failed(&host, &e.to_string());
                        }
                    }
                }
                Err(e) => {
                    // `{:#}` walks the anyhow::Error::source() chain so we
                    // see WHAT instant-acme actually rejected (network,
                    // TLS, HTTP status, parse failure, …). Plain `%e`
                    // only shows the topmost .context() wrapper which
                    // turned a hard-to-diagnose bug into a 30-min debug
                    // session live on the production stand — never again.
                    let full = format!("{e:#}");
                    tracing::error!(host, error = %full, "acme: issuance failed");
                    orders.update_failed(&host, &full);
                }
            }
        });

        let body = serde_json::json!({ "host": input.host, "status": "pending" });
        (
            202,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// POST /admin/api/acme/orders/<host>/renew — Write role.
    /// Forces re-issuance ignoring remaining validity.
    async fn api_acme_orders_renew(&self, host: &str) -> (u16, String, Bytes) {
        // Host must have an existing order record.
        if self.acme_orders.get(host).is_none() {
            return json_err(
                404,
                &format!(
                    "no order record for host {host:?} — use POST /admin/api/acme/orders to create"
                ),
            );
        }

        let Some(client) = self.acme_client.clone() else {
            return json_err(503, "ACME client not configured");
        };

        if self.acme_orders.is_in_flight(host) {
            return json_err(409, &format!("order already in flight for host {host}"));
        }

        // V237 — same cooldown gate as the create handler. See its comment.
        if let Err(e) = check_acme_order_cooldown(self.acme_orders.get(host).as_ref()) {
            return e;
        }

        self.acme_orders.mark_in_flight(host);

        let host_owned = host.to_string();
        let orders = Arc::clone(&self.acme_orders);
        let cert_dir = crate::acme::CertDir::new("/var/lib/aegis/certs");
        // CRITICAL: use the SAME ChallengeStore the data-plane HTTP-01
        // handler reads from. Default::default() creates a fresh store,
        // tokens go in but the proxy never sees them, LE GETs a 302 →
        // validation fails with state=Invalid. Live-tested on the production stand.
        let challenges = self
            .acme_challenges
            .clone()
            .unwrap_or_else(crate::acme::ChallengeStore::new);
        let provisioner = crate::acme::Provisioner::new(client, challenges, cert_dir);
        tokio::spawn(async move {
            tracing::info!(host = %host_owned, "acme: forced renewal");
            match provisioner.issue(&[host_owned.clone()]).await {
                Ok(cert) => {
                    let not_after = cert.not_after_unix;
                    let cert_dir2 = crate::acme::CertDir::new("/var/lib/aegis/certs");
                    match cert_dir2.write_async(&cert).await {
                        Ok(_) => orders.update_issued(&host_owned, not_after),
                        Err(e) => orders.update_failed(&host_owned, &e.to_string()),
                    }
                }
                Err(e) => orders.update_failed(&host_owned, &e.to_string()),
            }
        });

        let body = serde_json::json!({ "host": host, "status": "pending" });
        (
            202,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    // ── end ACME endpoints ────────────────────────────────────────────────────

    /// V-env — GET /admin/api/env.
    /// Returns all allowlisted AEGIS_* vars with their current value from
    /// aegis.env (the systemd-sourced override file). Secrets are never
    /// echoed; they appear as `{ configured: true, value: null }`.
    fn api_env_get(&self) -> (u16, String, Bytes) {
        // Read the on-disk file. Runtime env may differ (set before last
        // restart) — the file is what the next restart will pick up.
        let file_pairs: std::collections::HashMap<String, String> = read_aegis_env_file()
            .unwrap_or_default()
            .into_iter()
            .collect();

        let vars: Vec<serde_json::Value> = ENV_ALLOWLIST
            .iter()
            .map(|entry| {
                let is_secret = entry.kind == EnvKind::Secret;
                let file_val = file_pairs.get(entry.key);
                let configured = file_val.is_some();
                let value: serde_json::Value = if is_secret {
                    serde_json::Value::Null // never echo secrets
                } else {
                    file_val
                        .map(|v| serde_json::Value::String(v.clone()))
                        .unwrap_or(serde_json::Value::Null)
                };
                let kind_str = match entry.kind {
                    EnvKind::Bool => "Bool",
                    EnvKind::Enum(_) => "Enum",
                    EnvKind::Path | EnvKind::Addr => "Path",
                    EnvKind::Uint => "Uint",
                    EnvKind::Float => "Float",
                    EnvKind::Secret => "Secret",
                };
                let allowed_values: Option<Vec<&str>> = match entry.kind {
                    EnvKind::Enum(variants) => Some(variants.to_vec()),
                    _ => None,
                };
                serde_json::json!({
                    "key":        entry.key,
                    "kind":       kind_str,
                    "is_secret":  is_secret,
                    "configured": configured,
                    "value":      value,
                    "allowed_values": allowed_values,
                })
            })
            .collect();

        let body = serde_json::json!({ "vars": vars });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V-env — PUT /admin/api/env.
    /// Body: `{"key": "AEGIS_ML_V2", "value": "1"}` (or `"value": null` to unset).
    /// Validates key against allowlist, value against kind, then atomically
    /// rewrites /etc/aegis/aegis.env. Returns `restart_required: true`.
    fn api_env_put(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            key: String,
            value: Option<String>,
        }
        let input: In = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return json_err(400, &format!("invalid JSON body: {e}")),
        };

        // 1. Key must be in allowlist.
        let entry = match env_allowlist_entry(&input.key) {
            Some(e) => e,
            None => {
                return json_err(
                    400,
                    &format!(
                        "unknown or disallowed key {:?}; only AEGIS_* feature-flag keys are accepted",
                        input.key
                    ),
                );
            }
        };

        // 2. Validate value (skip when unsetting).
        if let Some(ref v) = input.value {
            if let Err(msg) = validate_env_value(v, entry.kind) {
                return json_err(400, &msg);
            }
        }

        // 3. Atomic write.
        if let Err(e) = write_aegis_env_file(&input.key, input.value.as_deref()) {
            tracing::error!(key = %input.key, error = %e, "failed to write aegis.env");
            return json_err(500, &format!("failed to write aegis.env: {e}"));
        }

        tracing::info!(key = %input.key, set = input.value.is_some(), "aegis.env updated via admin API");
        let body = serde_json::json!({
            "ok": true,
            "key": input.key,
            "restart_required": true,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V-env — POST /admin/api/restart.
    /// Spawns `systemctl restart aegis-pingora.target` without blocking on
    /// the full restart sequence (the process will receive SIGTERM shortly
    /// after). Returns immediately so the client can handle reconnection.
    fn api_restart(&self) -> (u16, String, Bytes) {
        // Cooldown: refuse a restart within RESTART_COOLDOWN_SECS of the last
        // one. Even though this endpoint is Write-role-only, a compromised
        // token must not be able to wedge the service in a perpetual restart
        // loop. A process-local AtomicU64 would be bypassable because the 4
        // SO_REUSEPORT workers are separate processes (each with its own
        // static), so we persist the timestamp to a file in the writable
        // state dir (alongside aegis-ui.env) that ALL workers share. Best
        // effort: if the marker can't be read/written we still proceed — the
        // cooldown is a guard rail, not a correctness invariant.
        const RESTART_COOLDOWN_SECS: u64 = 30;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let marker = aegis_env_file_path().with_file_name(".aegis-last-restart");
        let last = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if last != 0 && now > last && now - last < RESTART_COOLDOWN_SECS {
            let retry_after = RESTART_COOLDOWN_SECS - (now - last);
            tracing::warn!(retry_after, "admin API: restart rejected — cooldown active");
            let body = serde_json::json!({
                "ok": false,
                "error": "restart cooldown active",
                "retry_after_secs": retry_after,
            });
            return (
                429,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        }
        // Record this restart time before spawning (best effort).
        let _ = std::fs::write(&marker, now.to_string());

        tracing::warn!("admin API: restart requested — writing restart marker");
        // The daemon runs unprivileged (user `aegis`, NoNewPrivileges=yes) AND
        // inside the `aegis-pingora@N.service` cgroup. Spawning `systemctl
        // restart` directly does not work: sudo can't escalate (NoNewPrivileges)
        // and a direct systemctl gets SIGKILLed mid-operation because the
        // restart stops its own cgroup — the very cgroup the systemctl child
        // lives in. So we DECOUPLE: write a marker file (a plain, unprivileged
        // file write that nothing can interrupt) and let a root-owned systemd
        // `.path` watcher (aegis-restart.path → aegis-restart.service, both
        // installed by install.sh) perform the actual restart from its own
        // cgroup, where it survives the target going down.
        let marker = aegis_env_file_path().with_file_name(".restart-request");
        match std::fs::write(&marker, now.to_string()) {
            Ok(()) => {
                let body = serde_json::json!({
                    "ok": true,
                    "estimated_downtime_ms": 2000,
                    "note": "restart requested via systemd path watcher; \
                             connection will drop within a couple of seconds",
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                )
            }
            Err(e) => {
                tracing::error!(error = %e, path = %marker.display(),
                    "failed to write restart marker");
                json_err(
                    500,
                    &format!(
                        "failed to request restart: {e}. Ensure {} is writable by the \
                         service user and the aegis-restart.path unit is enabled.",
                        marker.display()
                    ),
                )
            }
        }
    }

    /// V162/V164 — GET /admin/api/sites/<host>/policy. Returns the
    /// per-domain override bundle (or an empty one if no override
    /// registered for this host). Surfaces both the per-host state
    /// AND the global filter list so the UI can render "this filter
    /// is on per host X, on globally, off here for host Y" cleanly.
    ///
    /// Also surfaces `"honeypot_host_enabled"` (bool): true when the
    /// honeypot filter is NOT bypassed for this host (i.e. the host
    /// is absent from `HoneypotState::host_disabled`). Computed via
    /// `HoneypotStore::is_host_enabled` — no extra lock or allocation
    /// beyond the read-side lookup already done by that method.
    fn api_site_policy_get(&self, host: &str) -> (u16, String, Bytes) {
        let host = host.to_ascii_lowercase();
        let policy = self.domain_policy.get(&host).unwrap_or_default();
        let global = self.filter_toggles.snapshot();
        let honeypot_host_enabled = self.honeypots.is_host_enabled(&host);
        let body = serde_json::json!({
            "host": host,
            "policy": policy,
            "global_filters": global.iter().map(|(n, e)| serde_json::json!({
                "name": n,
                "enabled": e,
            })).collect::<Vec<_>>(),
            "honeypot_host_enabled": honeypot_host_enabled,
            "note": "Per-domain overrides win over global runtime toggles. \
                     Both are in-memory; restart resets to config defaults.",
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V162/V164 — PUT /admin/api/sites/<host>/policy. Body is the
    /// DomainPolicy JSON shape; replaces the host's policy atomically.
    /// Empty policy ({}) → policy removed (host falls back to globals).
    fn api_site_policy_put(&self, host: &str, body: &[u8]) -> (u16, String, Bytes) {
        let policy: crate::domain_policy::DomainPolicy = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(e) => return json_err(400, &format!("invalid policy JSON: {e}")),
        };
        let host = host.to_ascii_lowercase();
        self.domain_policy.put(&host, policy);
        let body = serde_json::json!({
            "ok": true,
            "host": host,
            "policy": self.domain_policy.get(&host).unwrap_or_default(),
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V162/V164 — DELETE /admin/api/sites/<host>/policy. Removes the
    /// per-host override entry so the host falls back to global.
    fn api_site_policy_delete(&self, host: &str) -> (u16, String, Bytes) {
        let host = host.to_ascii_lowercase();
        self.domain_policy.remove(&host);
        let body = serde_json::json!({"ok": true, "host": host, "removed": true});
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V160 — GET /admin/api/defaults/filters. Returns the runtime
    /// on/off state for every registered filter. Operator-controlled
    /// from the Security page in the React panel.
    fn api_defaults_filters_get(&self) -> (u16, String, Bytes) {
        let snap = self.filter_toggles.snapshot();
        let body = serde_json::json!({
            "filters": snap.iter().map(|(name, enabled)| serde_json::json!({
                "name": name,
                "enabled": enabled,
            })).collect::<Vec<_>>(),
            "note": "In-memory toggles. Restart resets to config defaults — \
                     persist via the Config editor's `defaults { filters { … } }` block.",
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V160 — PUT /admin/api/defaults/filters. Body shape:
    /// `[{"name":"waf","enabled":false}, ...]` or
    /// `{"updates":[{"name":"waf","enabled":false}]}`.
    fn api_defaults_filters_put(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct One {
            name: String,
            enabled: bool,
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Input {
            List(Vec<One>),
            Wrapped { updates: Vec<One> },
        }
        let parsed: Input = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return json_err(400, &format!("invalid JSON: {e}")),
        };
        let updates = match parsed {
            Input::List(v) => v,
            Input::Wrapped { updates } => updates,
        };
        let mut applied = 0u32;
        let mut unknown: Vec<String> = vec![];
        for u in updates {
            if self.filter_toggles.set(&u.name, u.enabled) {
                applied += 1;
            } else {
                unknown.push(u.name);
            }
        }
        let body = serde_json::json!({
            "ok": true,
            "applied": applied,
            "unknown_filters": unknown,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V121 — GET /admin/api/bots → top single-IP bot detections.
    fn api_bots(&self) -> (u16, String, Bytes) {
        let bots: Vec<serde_json::Value> = self
            .threat_analytics
            .top_bots(100)
            .iter()
            .map(|b| {
                serde_json::json!({
                    "client_ip": b.client_ip,
                    "primary_reason": b.primary_reason.as_str(),
                    "hits": b.hits,
                    "last_seen_unix_secs": b.last_seen_unix_secs,
                })
            })
            .collect();
        let body = serde_json::json!({
            "bots": bots,
            "summary": {
                "tracked_bots": self.threat_analytics.summary().tracked_bots,
            },
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V121 — GET /admin/api/ddos → top distributed-attack targets.
    fn api_ddos(&self) -> (u16, String, Bytes) {
        let targets: Vec<serde_json::Value> = self
            .threat_analytics
            .top_ddos_targets(100)
            .iter()
            .map(|t| {
                serde_json::json!({
                    "host": t.host,
                    "path_pattern": t.path_pattern,
                    "total_hits": t.total_hits,
                    "distinct_ips": t.distinct_ips,
                    "last_seen_unix_secs": t.last_seen_unix_secs,
                })
            })
            .collect();
        let body = serde_json::json!({
            "targets": targets,
            "summary": {
                "tracked_endpoints": self.threat_analytics.summary().tracked_endpoints,
            },
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V119/V240 — GET /admin/api/site_map → aggregated hosts list.
    ///
    /// When a shard directory is configured (`sitemap_dir`), reads all
    /// active shard-*.json files (max-age 15 min), merges them into a
    /// single snapshot (union keys; sum counters; max last_seen), and
    /// serves the result. The response is identical regardless of which
    /// SO_REUSEPORT worker answers — no more flicker. Includes per-host
    /// `total_hits` and `last_seen` so the UI can sort by recency/volume.
    ///
    /// Falls back to this worker's in-memory SiteMap when no shards exist
    /// yet (first boot before the first 30 s flush).
    fn api_site_map_hosts(&self) -> (u16, String, Bytes) {
        // Try the persisted, cross-worker view first.
        if let Some(dir) = &self.sitemap_dir {
            let snaps = crate::site_map::SiteMap::read_all_shards(dir, 900);
            if !snaps.is_empty() {
                let merged = crate::site_map::SiteMap::merge_snapshots(&snaps);
                // `hosts` = flat string list (frontend SiteMapHostsResponse.hosts);
                // `host_entries` = the per-host detail the UI sorts/tags by. The
                // field is `last_seen_unix_secs` to match the TS type exactly.
                let hosts: Vec<&str> = merged.hosts.iter().map(|hs| hs.host.as_str()).collect();
                let host_entries: Vec<serde_json::Value> = merged
                    .hosts
                    .iter()
                    .map(|hs| {
                        serde_json::json!({
                            "host": hs.host,
                            "total_hits": hs.total_hits,
                            "last_seen_unix_secs": hs.last_seen,
                        })
                    })
                    .collect();
                let total_endpoints: usize = merged.hosts.iter().map(|hs| hs.endpoints.len()).sum();
                let body = serde_json::json!({
                    "hosts": hosts,
                    "host_entries": host_entries,
                    "total_endpoints": total_endpoints,
                });
                return (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        }
        // Fallback: serve this worker's in-memory slice (same shape).
        let snap = self.site_map.export_snapshot();
        let hosts: Vec<&str> = snap.hosts.iter().map(|hs| hs.host.as_str()).collect();
        let host_entries: Vec<serde_json::Value> = snap
            .hosts
            .iter()
            .map(|hs| {
                serde_json::json!({
                    "host": hs.host,
                    "total_hits": hs.total_hits,
                    "last_seen_unix_secs": hs.last_seen,
                })
            })
            .collect();
        let total_endpoints = self.site_map.total_endpoints();
        let body = serde_json::json!({
            "hosts": hosts,
            "host_entries": host_entries,
            "total_endpoints": total_endpoints,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V119/V240 — GET /admin/api/site_map/<host> → endpoints for one host.
    ///
    /// Same aggregation strategy as `api_site_map_hosts`: reads all active
    /// shards, merges them, then filters to the requested host. Each endpoint
    /// row includes the full stats breakdown. Falls back to the in-memory
    /// SiteMap when no shards are available.
    fn api_site_map_host(&self, host: &str) -> (u16, String, Bytes) {
        // Helper: build the endpoint JSON array from a PersistedEndpoint slice.
        let make_endpoints =
            |eps: &[crate::site_map::PersistedEndpoint]| -> Vec<serde_json::Value> {
                eps.iter()
                    .map(|e| {
                        serde_json::json!({
                            "method": e.method,
                            "path_pattern": e.path_pattern,
                            "hits": e.hits,
                            "last_seen_unix_secs": e.last_seen_unix_secs,
                            "status_2xx": e.status_2xx,
                            "status_3xx": e.status_3xx,
                            "status_4xx": e.status_4xx,
                            "status_5xx": e.status_5xx,
                        })
                    })
                    .collect()
            };

        // Try the persisted, cross-worker view first.
        if let Some(dir) = &self.sitemap_dir {
            let snaps = crate::site_map::SiteMap::read_all_shards(dir, 900);
            if !snaps.is_empty() {
                let merged = crate::site_map::SiteMap::merge_snapshots(&snaps);
                let host_snap = merged.hosts.iter().find(|hs| hs.host == host);
                let (endpoints, total_hits, last_seen) = match host_snap {
                    Some(hs) => (make_endpoints(&hs.endpoints), hs.total_hits, hs.last_seen),
                    None => (vec![], 0u64, 0u64),
                };
                let body = serde_json::json!({
                    "host": host,
                    "total_hits": total_hits,
                    "last_seen": last_seen,
                    "endpoints": endpoints,
                });
                return (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        }
        // Fallback: serve this worker's in-memory slice.
        let in_mem = self.site_map.snapshot(host);
        let endpoints: Vec<serde_json::Value> = in_mem
            .iter()
            .map(|e| {
                serde_json::json!({
                    "method": e.method,
                    "path_pattern": e.path_pattern,
                    "hits": e.hits,
                    "last_seen_unix_secs": e.last_seen_unix_secs,
                    "status_2xx": e.status_2xx,
                    "status_3xx": e.status_3xx,
                    "status_4xx": e.status_4xx,
                    "status_5xx": e.status_5xx,
                })
            })
            .collect();
        let total_hits: u64 = in_mem.iter().map(|e| e.hits).sum();
        let last_seen: u64 = in_mem
            .iter()
            .map(|e| e.last_seen_unix_secs)
            .max()
            .unwrap_or(0);
        let body = serde_json::json!({
            "host": host,
            "total_hits": total_hits,
            "last_seen": last_seen,
            "endpoints": endpoints,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// Append `aegis_cache_*` counters to a Prometheus body. Kept
    /// separate from `render_prometheus()` because ResponseCache lives
    /// outside RuntimeMetrics; this is the bridge.
    fn append_cache_stats(&self, out: &mut String) {
        let stats = self.cache.stats();
        let push = |out: &mut String, name: &str, help: &str, value: u64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        };
        push(
            out,
            "aegis_cache_stores",
            "Cache entries inserted.",
            stats.stores,
        );
        push(
            out,
            "aegis_cache_evictions",
            "Cache entries dropped (stale, LRU pressure, broadcast purge).",
            stats.evictions,
        );
        push(
            out,
            "aegis_cache_skipped_high_threat",
            "Cache lookups forced to MISS by threat-aware policy.",
            stats.skipped_high_threat,
        );
        push(
            out,
            "aegis_cache_skipped_uncacheable",
            "Cache stores skipped because response was uncacheable per RFC 9111.",
            stats.skipped_uncacheable,
        );
        push(
            out,
            "aegis_cache_not_modified",
            "304 Not Modified responses served from cached validators.",
            stats.not_modified,
        );
        // V98 — tiered policy counters.
        push(
            out,
            "aegis_cache_served_low",
            "Cache hits served to low-threat clients (ThreatTier::Low).",
            stats.served_low,
        );
        push(
            out,
            "aegis_cache_served_medium",
            "Cache hits served to medium-threat clients within TTL/2 freshness window.",
            stats.served_medium,
        );
        push(
            out,
            "aegis_cache_forced_miss_high",
            "Cache lookups forced to MISS by high-threat tier policy (subset of skipped_high_threat for tiered-path callers).",
            stats.forced_miss_high,
        );
    }

    /// V45 — append `aegis_xdp_*` counters to a Prometheus body.
    /// Zeros render when XDP is off (NoopXdp.counters() returns
    /// Ok(default)) — operators can scrape unconditionally without
    /// branch logic in dashboards.
    fn append_xdp_stats(&self, out: &mut String) {
        let c = self.xdp.counters().unwrap_or_default();
        let push = |out: &mut String, name: &str, help: &str, value: u64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        };
        push(
            out,
            "aegis_xdp_pass",
            "Packets passed by XDP fast-path.",
            c.pass,
        );
        push(
            out,
            "aegis_xdp_drop_deny",
            "Packets dropped by XDP deny list.",
            c.drop_deny,
        );
        push(
            out,
            "aegis_xdp_drop_rate",
            "Packets dropped by XDP rate limiter.",
            c.drop_rate,
        );
        push(
            out,
            "aegis_xdp_drop_allowonly",
            "Packets dropped by XDP allow-only mode.",
            c.drop_allowonly,
        );
        push(
            out,
            "aegis_xdp_drop_syn",
            "SYNs dropped by XDP flood guard.",
            c.drop_syn,
        );
        push(
            out,
            "aegis_xdp_drop_waf",
            "Packets dropped by inline XDP WAF.",
            c.drop_waf,
        );
        // Phase A.1 — fast-pass distinct from generic PASS so trust
        // bypass volume is observable. Per-CPU underneath; summed at
        // read time in xdp::counters().
        push(
            out,
            "aegis_xdp_fast_pass",
            "Packets that took the allow-list fast-path (bypassed deny/rate/WAF).",
            c.fast_pass,
        );
    }

    /// V89 — Phase D cluster-wide counters (sum across all REUSEPORT
    /// workers via shared mmap arena). Distinct from per-process
    /// `aegis_*_total` counters: ANY worker can render these via
    /// /metrics and the value is the cluster aggregate, so dashboards
    /// don't need per-worker scraping + summation.
    ///
    /// Render is a no-op when the arena failed to attach at startup
    /// (Linux without /dev/shm, macOS dev builds, restricted
    /// containers). Operators can grep for the absence of
    /// `aegis_cluster_*` lines to detect arena-unavailable workers.
    fn append_cluster_stats(&self, out: &mut String) {
        if !crate::shared_state::global::enabled() {
            return;
        }
        let snap = crate::shared_state::global::snapshot_cluster();
        let push = |out: &mut String, name: &str, help: &str, value: u64| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        };
        use crate::shared_state::global::cluster_idx;
        let get = |idx: usize| snap.get(idx).copied().unwrap_or(0);
        push(
            out,
            "aegis_cluster_requests_total",
            "Total inbound requests across the whole REUSEPORT cluster (Phase D).",
            get(cluster_idx::REQUESTS_TOTAL),
        );
        push(
            out,
            "aegis_cluster_requests_denied",
            "Cluster-wide requests rejected by the filter pipeline.",
            get(cluster_idx::REQUESTS_DENIED),
        );
        push(
            out,
            "aegis_cluster_requests_challenged",
            "Cluster-wide requests answered with a challenge.",
            get(cluster_idx::REQUESTS_CHALLENGED),
        );
        push(
            out,
            "aegis_cluster_cache_hits",
            "Cluster-wide response-cache hits.",
            get(cluster_idx::CACHE_HITS),
        );
        push(
            out,
            "aegis_cluster_cache_misses",
            "Cluster-wide response-cache misses.",
            get(cluster_idx::CACHE_MISSES),
        );
        push(
            out,
            "aegis_cluster_upstream_2xx",
            "Cluster-wide upstream 2xx responses.",
            get(cluster_idx::UPSTREAM_2XX),
        );
        push(
            out,
            "aegis_cluster_upstream_4xx",
            "Cluster-wide upstream 4xx responses.",
            get(cluster_idx::UPSTREAM_4XX),
        );
        push(
            out,
            "aegis_cluster_upstream_5xx",
            "Cluster-wide upstream 5xx responses.",
            get(cluster_idx::UPSTREAM_5XX),
        );
        push(
            out,
            "aegis_cluster_compactions_total",
            "Cluster-wide SharedScorer compaction passes run.",
            get(cluster_idx::COMPACTIONS_TOTAL),
        );
        push(
            out,
            "aegis_cluster_compactions_removed",
            "Cluster-wide SharedScorer entries reclaimed by compaction.",
            get(cluster_idx::COMPACTIONS_REMOVED),
        );
        // Diagnostic gauges (not Counter type — TYPE gauge — but
        // we re-use the push helper to keep the renderer small).
        let _ = writeln!(
            out,
            "# HELP aegis_cluster_arena_bytes Cluster shared-state arena total size in bytes.\n\
             # TYPE aegis_cluster_arena_bytes gauge\n\
             aegis_cluster_arena_bytes {}",
            crate::shared_state::global::arena_size()
        );
        let _ = writeln!(
            out,
            "# HELP aegis_cluster_arena_used_bytes Cluster shared-state arena allocated bytes.\n\
             # TYPE aegis_cluster_arena_used_bytes gauge\n\
             aegis_cluster_arena_used_bytes {}",
            crate::shared_state::global::arena_used()
        );
    }

    async fn respond(
        session: &mut Session,
        status: u16,
        content_type: &'static str,
        body: Bytes,
    ) -> pingora_core::Result<()> {
        let mut header = ResponseHeader::build(status, Some(2))?;
        header.insert_header("content-type", content_type)?;
        header.insert_header("content-length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(body), true).await?;
        Ok(())
    }

    /// V66 — like `respond` but takes the content-type as an owned
    /// String (or `&'static str` via `leak_ct` helper). Lets the
    /// /admin/api dispatcher pick content-types dynamically per
    /// endpoint without needing const lifetime gymnastics.
    async fn respond_bytes(
        session: &mut Session,
        status: u16,
        content_type: &'static str,
        body: Bytes,
    ) -> pingora_core::Result<()> {
        Self::respond(session, status, content_type, body).await
    }

    /// Render the full text-format cache snapshot for `GET /admin/cache`.
    /// Same column layout the hyper handler emits — operators can use
    /// existing scrapers / dashboards without changes.
    fn render_cache_text(&self) -> String {
        let s = self.cache.stats();
        let total = s.hits + s.misses;
        let hit_ratio = if total > 0 {
            (s.hits as f64) * 100.0 / (total as f64)
        } else {
            0.0
        };
        format!(
            "cache_hits {}\ncache_misses {}\ncache_not_modified {}\ncache_stores {}\ncache_evictions {}\ncache_skipped_high_threat {}\ncache_skipped_uncacheable {}\ncache_hit_ratio_pct {:.2}\n",
            s.hits,
            s.misses,
            s.not_modified,
            s.stores,
            s.evictions,
            s.skipped_high_threat,
            s.skipped_uncacheable,
            hit_ratio,
        )
    }

    /// `GET /admin/cache/dump` — list the first 200 cached entries
    /// (host, path, status, body bytes, expiry). Body content is
    /// never surfaced — could contain PII / secrets.
    fn render_cache_dump(&self) -> String {
        let mut entries = self.cache.dump(200, std::time::Instant::now());
        entries.sort_by(|a, b| a.host.cmp(&b.host).then(a.path.cmp(&b.path)));
        if entries.is_empty() {
            return "no cached entries\n".to_string();
        }
        let mut out = String::with_capacity(entries.len() * 80);
        out.push_str("method host path status body_bytes expires_in_secs\n");
        for e in entries {
            let _ = writeln!(
                out,
                "{} {} {} {} {} {}",
                e.method, e.host, e.path, e.status, e.body_bytes, e.expires_in_secs
            );
        }
        out
    }

    /// Parse `?all=1`, `?host=...`, `?prefix=...` query into the
    /// `(purge_all, host, prefix)` triple that drives ResponseCache
    /// purge methods. Returns Err with a plain-text reason when no
    /// filter is specified — `request_filter` turns that into a 400.
    fn parse_purge_query(query: &str) -> Result<(bool, Option<String>, Option<String>), String> {
        let mut host: Option<String> = None;
        let mut prefix: Option<String> = None;
        let mut all = false;
        for pair in query.split('&').filter(|s| !s.is_empty()) {
            if let Some((k, v)) = pair.split_once('=') {
                let decoded = urlencoding::decode(v)
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| v.to_string());
                match k {
                    "all" if decoded == "1" || decoded == "true" => all = true,
                    "host" => host = Some(decoded),
                    "prefix" | "path_prefix" => prefix = Some(decoded),
                    _ => {}
                }
            }
        }
        if !all && host.is_none() && prefix.is_none() {
            return Err("missing filter — use ?all=1 or ?host=... or ?prefix=...\n".to_string());
        }
        Ok((all, host, prefix))
    }

    /// `GET /admin/threats` — top-N attacking IPs ranked by score.
    /// Mirrors the hyper handler's text format so existing scrapers
    /// keep working.
    fn render_threats(&self) -> String {
        // V92 — prefer cluster-wide scorer when available so the top-N
        // reflects every REUSEPORT worker's view, not just whichever
        // worker happened to serve /admin/threats.
        let (top, source) = match &self.shared_scorer {
            Some(s) => (s.top(50), "cluster"),
            None => (self.scorer.top(50), "worker"),
        };
        if top.is_empty() {
            return format!("no scored ips (source={source})\n");
        }
        let mut out = String::with_capacity(top.len() * 40 + 24);
        let _ = writeln!(out, "# source={source}");
        out.push_str("ip score\n");
        for (ip, score) in top {
            let _ = writeln!(out, "{} {:.2}", ip, score.as_f64());
        }
        out
    }

    /// `GET /admin/xdp` — XDP fast-path counters (pass, drop_*).
    /// Renders zeros on NoopXdp (non-Linux or unconfigured) — that's
    /// the legible "XDP is off" signal for ops.
    fn render_xdp(&self) -> String {
        let c = self.xdp.counters().unwrap_or_default();
        format!(
            "xdp_pass {}\nxdp_drop_deny {}\nxdp_drop_rate {}\nxdp_drop_allowonly {}\nxdp_drop_syn {}\nxdp_drop_waf {}\n",
            c.pass, c.drop_deny, c.drop_rate, c.drop_allowonly, c.drop_syn, c.drop_waf
        )
    }

    /// Parse an IP out of a `/admin/xdp/(deny|undeny)/<ip>` path.
    /// Returns Err with a reason when the suffix isn't a valid
    /// v4/v6 address.
    fn parse_xdp_ip(path: &str, prefix: &str) -> Result<std::net::IpAddr, String> {
        let suffix = path
            .strip_prefix(prefix)
            .ok_or_else(|| "bad path".to_string())?;
        suffix
            .parse::<std::net::IpAddr>()
            .map_err(|e| format!("invalid ip {suffix:?}: {e}"))
    }

    fn xdp_deny(&self, ip: std::net::IpAddr) -> Result<(), String> {
        match ip {
            std::net::IpAddr::V4(v4) => self
                .xdp
                .deny_v4(v4)
                .map_err(|e| format!("xdp deny_v4: {e}")),
            std::net::IpAddr::V6(v6) => self
                .xdp
                .deny_v6(v6)
                .map_err(|e| format!("xdp deny_v6: {e}")),
        }
    }

    fn xdp_undeny(&self, ip: std::net::IpAddr) -> Result<(), String> {
        self.xdp.undeny(ip).map_err(|e| format!("xdp undeny: {e}"))
    }

    /// `GET /admin/hot_uris` — list the top-25 URIs by current RPS
    /// as tracked by RateLimitFilter's HotUriTracker. Returns
    /// "no hot uris" when the tracker is disabled
    /// (`hot_uri_rps_threshold = 0`) or no URI has crossed the
    /// threshold. Mirrors the hyper handler's text format.
    fn render_hot_uris(&self) -> String {
        let top = self.rate.hot_uris(25);
        if top.is_empty() {
            return "no hot uris\n".to_string();
        }
        let mut out = String::with_capacity(top.len() * 80);
        out.push_str("path rps\n");
        for (path, rps) in top {
            let _ = writeln!(out, "{path} {rps}");
        }
        out
    }

    /// V66 — dispatch /admin/api/* JSON endpoints used by the React
    /// panel. Returns Some((status, content_type, body)) when the
    /// route matched; None falls through to a 404 in
    /// `request_filter`. body is JSON-encoded for everything except
    /// raw config text (which uses text/plain).
    ///
    /// The hyper handler's `handle_api_route` is the reference
    /// implementation. RC3 widened the pingora-side dispatcher to
    /// cover the write surface (POST /sites, DELETE /sites/<host>,
    /// POST /change-credentials, PUT /honeypots, raw config edit).
    /// Reload-from-disk is intentionally NOT implemented here — the
    /// pingora binary uses `--upgrade` for hot-swap, so write
    /// endpoints persist to disk and rely on the operator triggering
    /// upgrade separately. This keeps the admin handler small and
    /// matches how pingora-style deployments expect to reconfigure.
    async fn handle_api(
        &self,
        method: &str,
        path: &str,
        query: &str,
        role: Option<crate::config::AdminRole>,
        body: &[u8],
        session: &Session,
    ) -> Option<(u16, String, Bytes)> {
        let _ = query; // reserved for V69+ paginated lists

        // === V67 — session auth ============================================
        if method == "POST" && path == "/admin/api/login" {
            return Some(self.api_login(body));
        }
        if method == "POST" && path == "/admin/api/logout" {
            return Some(self.api_logout(session));
        }
        if method == "GET" && path == "/admin/api/me" {
            return Some(self.api_me(session));
        }
        // RC3 — change current operator's email + password.
        if method == "POST" && path == "/admin/api/change-credentials" {
            return Some(self.api_change_credentials(body, session));
        }

        // === V68 — read-side dashboard =====================================
        if method == "GET" && path == "/admin/api/runtime/status" {
            return Some(self.api_runtime_status());
        }
        // V169 — Settings page payload (ML / feeds / infrastructure).
        if method == "GET" && path == "/admin/api/runtime/info" {
            return Some(self.api_runtime_info());
        }
        // TS — historical time-series query for the panel's traffic charts.
        if method == "GET" && path == "/admin/api/metrics/series" {
            return Some(self.api_metrics_series(query));
        }
        // V239 — per-country traffic for the dashboard world map.
        if method == "GET" && path == "/admin/api/geo/top" {
            return Some(self.api_geo_top());
        }
        // V191 — Defence Arsenal umbrella endpoint. Returns the catalogue
        // of V176-V190 modules with per-module status + description, so
        // the Arsenal page can render the full defensive surface in one
        // call.
        if method == "GET" && path == "/admin/api/arsenal" {
            return Some(self.api_arsenal());
        }
        // V205 — per-domain challenge config CRUD.
        if method == "GET" && path == "/admin/api/challenge/hosts" {
            return Some(self.api_challenge_hosts());
        }
        if method == "GET"
            && let Some(host) = path.strip_prefix("/admin/api/sites/")
            && let Some(host) = host.strip_suffix("/challenge")
        {
            return Some(self.api_challenge_get(host));
        }
        if method == "PUT"
            && let Some(host) = path.strip_prefix("/admin/api/sites/")
            && let Some(host) = host.strip_suffix("/challenge")
        {
            return Some(self.api_challenge_put(host, body));
        }
        if method == "DELETE"
            && let Some(host) = path.strip_prefix("/admin/api/sites/")
            && let Some(host) = host.strip_suffix("/challenge")
        {
            return Some(self.api_challenge_delete(host));
        }
        if method == "POST" && path == "/admin/api/challenge/attack-mode" {
            return Some(self.api_challenge_attack_mode(body));
        }
        // V232 — worker-topology dashboard for the panel's Workers page.
        if method == "GET" && path == "/admin/api/topology" {
            return Some(self.api_topology_get());
        }
        if method == "PUT" && path == "/admin/api/topology" {
            return Some(self.api_topology_put(body));
        }
        // V240 — server hardware benchmark + capacity projection.
        if method == "GET" && path == "/admin/api/benchmark/result" {
            return Some(self.api_benchmark_result());
        }
        if method == "POST" && path == "/admin/api/benchmark/run" {
            return Some(self.api_benchmark_run().await);
        }
        // V241 — flood-capacity tests (SYN / HTTP / TLS / slowloris / cache).
        if method == "GET" && path == "/admin/api/benchmark/flood/result" {
            return Some(self.api_flood_result());
        }
        if method == "POST" && path == "/admin/api/benchmark/flood/run" {
            return Some(self.api_flood_run().await);
        }
        // V245 — head-to-head comparison vs nginx.
        if method == "GET" && path == "/admin/api/benchmark/compare/result" {
            return Some(self.api_compare_result());
        }
        if method == "POST" && path == "/admin/api/benchmark/compare/run" {
            return Some(self.api_compare_run().await);
        }
        // V208 — update checker.
        if method == "GET" && path == "/admin/api/updates/status" {
            return Some(self.api_updates_status());
        }
        if method == "POST" && path == "/admin/api/updates/check" {
            return Some(self.api_updates_check());
        }
        if method == "GET" && path == "/admin/api/updates/releases" {
            return Some(self.api_updates_releases());
        }
        if method == "PUT" && path == "/admin/api/updates/config" {
            return Some(self.api_updates_config_put(body));
        }
        // V233 — REMOVED route-dispatch arms for the self-update apply +
        // snapshot machinery (was V209-V212 Phase 2/3):
        //   POST   /admin/api/updates/apply
        //   GET    /admin/api/updates/snapshots
        //   POST   /admin/api/updates/snapshots/create
        //   POST   /admin/api/updates/snapshots/<id>/restore
        //   DELETE /admin/api/updates/snapshots/<id>
        //   GET    /admin/api/updates/releases-installed
        //   GET    /admin/api/updates/apply-status
        // These downloaded + executed an attacker-supplied binary as the
        // service user (unauthenticated-RCE design). The read-only
        // checker routes above (status / check / releases / config) are
        // KEPT. Updates are now installed manually via `sudo bash
        // install.sh` on the host.
        // V213 — Scenarios DSL (V199).
        if method == "GET" && path == "/admin/api/scenarios" {
            return Some(self.api_scenarios_list());
        }
        if method == "POST" && path == "/admin/api/scenarios/load" {
            return Some(self.api_scenarios_load(body));
        }
        if method == "POST" && path == "/admin/api/scenarios/test" {
            return Some(self.api_scenarios_test(body));
        }
        // V214 — Actuators (V197).
        if method == "GET" && path == "/admin/api/actuators" {
            return Some(self.api_actuators_list());
        }
        if method == "POST" && path == "/admin/api/actuators/revert" {
            return Some(self.api_actuators_revert(body));
        }
        // V215 — Sigma rules (V196).
        if method == "GET" && path == "/admin/api/sigma/rules" {
            // V230 — api_sigma_rules is now async (tokio::fs).
            return Some(self.api_sigma_rules().await);
        }
        if method == "POST" && path == "/admin/api/sigma/import" {
            return Some(self.api_sigma_import(body));
        }
        // V237 — per-rule enable/disable for the bundled Sigma corpus.
        // GET lists every rule (id/field/op/value/severity/action/tags/
        // enabled); PUT toggles one rule's enabled state via the disk
        // overlay (cross-worker, like the honeypot pack toggles).
        if method == "GET" && path == "/admin/api/sigma/rules/list" {
            return Some(self.api_sigma_rules_list().await);
        }
        if method == "PUT" && path == "/admin/api/sigma/rules/toggle" {
            return Some(self.api_sigma_rule_toggle(body));
        }
        // V216 — Enrichment (V198).
        if method == "GET" && path == "/admin/api/enrichment" {
            return Some(self.api_enrichment_status());
        }
        if method == "POST" && path == "/admin/api/enrichment/lookup" {
            return Some(self.api_enrichment_lookup(body));
        }
        // V217 — Reputation feeds (V138/V142/V176).
        if method == "GET" && path == "/admin/api/reputation/ja4" {
            return Some(self.api_reputation_ja4());
        }
        if method == "POST" && path == "/admin/api/reputation/ja4/lookup" {
            return Some(self.api_reputation_ja4_lookup(body));
        }
        if method == "GET" && path == "/admin/api/reputation/asn" {
            return Some(self.api_reputation_asn());
        }
        if method == "POST" && path == "/admin/api/reputation/asn/lookup" {
            return Some(self.api_reputation_asn_lookup(body));
        }
        // V218 — ML training (V123/V150) + adversarial (V151).
        if method == "GET" && path == "/admin/api/ml/status" {
            return Some(self.api_ml_status());
        }
        if method == "POST" && path == "/admin/api/ml/retrain" {
            return Some(self.api_ml_retrain(body));
        }
        if method == "POST" && path == "/admin/api/ml/adversarial" {
            return Some(self.api_ml_adversarial());
        }
        // V219 — Privacy Pass issuers (V201).
        if method == "GET" && path == "/admin/api/privacy-pass" {
            return Some(self.api_privacy_pass_list());
        }
        // The React panel polls the issuer LIST at /privacy-pass/issuers
        // (the bare /privacy-pass path only carries summary counters).
        if method == "GET" && path == "/admin/api/privacy-pass/issuers" {
            return Some(self.api_privacy_pass_issuers());
        }
        if method == "POST" && path == "/admin/api/privacy-pass/issuers" {
            return Some(self.api_privacy_pass_add(body));
        }
        // V220 — BGP RTBH (V187).
        if method == "GET" && path == "/admin/api/bgp/announces" {
            return Some(self.api_bgp_list());
        }
        if method == "POST" && path == "/admin/api/bgp/withdraw" {
            return Some(self.api_bgp_withdraw(body));
        }
        // V221 — Telemetry status (EventBridge / ClamAV / Sicherheitstacho).
        if method == "GET" && path == "/admin/api/telemetry/status" {
            return Some(self.api_telemetry_status());
        }
        // V222 — GeoIP status + lookup.
        if method == "GET" && path == "/admin/api/geoip/status" {
            return Some(self.api_geoip_status());
        }
        if method == "POST" && path == "/admin/api/geoip/lookup" {
            return Some(self.api_geoip_lookup(body));
        }
        if method == "POST" && path == "/admin/api/geoip/update" {
            return Some(self.api_geoip_update());
        }
        // V223 — Cluster (Phase D shared scorer + XDP counters).
        if method == "GET" && path == "/admin/api/cluster/status" {
            return Some(self.api_cluster_status());
        }
        // V224 — Tarpit (V147) + honeypot YAML (V184).
        if method == "GET" && path == "/admin/api/tarpit/status" {
            return Some(self.api_tarpit_status());
        }
        if method == "GET" && path == "/admin/api/honeypot-yaml" {
            return Some(self.api_honeypot_yaml_list());
        }
        if method == "POST" && path == "/admin/api/honeypot-yaml/load" {
            return Some(self.api_honeypot_yaml_load(body));
        }
        // V225 — CrowdSec LAPI adapter status (V157).
        if method == "GET" && path == "/admin/api/crowdsec/status" {
            return Some(self.api_crowdsec_status());
        }
        // V226 — CAPTCHA provider status (V131/V132).
        if method == "GET" && path == "/admin/api/captcha/status" {
            return Some(self.api_captcha_status());
        }
        // V227 — Route-difficulty per-route overrides (V186).
        if method == "GET" && path == "/admin/api/route-difficulty" {
            return Some(self.api_route_difficulty_list());
        }
        if method == "GET" && path == "/admin/api/filters" {
            return Some(self.api_filters());
        }
        // V160 — runtime filter on/off toggles (read + write).
        if method == "GET" && path == "/admin/api/defaults/filters" {
            return Some(self.api_defaults_filters_get());
        }
        if method == "PUT" && path == "/admin/api/defaults/filters" {
            return Some(self.api_defaults_filters_put(body));
        }
        if method == "GET" && path == "/admin/api/audit" {
            return Some(self.api_audit());
        }
        // V107 — auto-mined signature candidates (from tarpit log).
        if method == "GET" && path == "/admin/api/mined_signatures" {
            return Some(self.api_mined_signatures());
        }
        // V119 — site cartography.
        if method == "GET" && path == "/admin/api/site_map" {
            return Some(self.api_site_map_hosts());
        }
        // V121 — bot vs DDoS analytics.
        if method == "GET" && path == "/admin/api/bots" {
            return Some(self.api_bots());
        }
        if method == "GET" && path == "/admin/api/ddos" {
            return Some(self.api_ddos());
        }
        // V243 — persistent event log. /logs/stats is checked first so the
        // longer path doesn't get shadowed by the /logs prefix match.
        if method == "GET" && path == "/admin/api/logs/stats" {
            return Some(self.api_logs_stats(query));
        }
        if method == "GET" && path == "/admin/api/logs" {
            return Some(self.api_logs(query));
        }
        if method == "GET"
            && let Some(host) = path.strip_prefix("/admin/api/site_map/")
            && !host.is_empty()
        {
            return Some(self.api_site_map_host(host));
        }

        // === V69 — honeypots + sites (read) ================================
        if method == "GET" && path == "/admin/api/honeypots/builtin" {
            return Some(self.api_honeypots_builtin());
        }
        if method == "GET" && path == "/admin/api/honeypots" {
            return Some(self.api_honeypots());
        }
        if method == "GET" && path == "/admin/api/sites" {
            return Some(self.api_sites());
        }

        // === RC3 — sites write ============================================
        if method == "POST" && path == "/admin/api/sites" {
            return Some(self.api_sites_create(body));
        }
        // === V162/V164 — per-domain policy CRUD ===========================
        // Note: this match runs BEFORE the catch-all DELETE
        // /admin/api/sites/<host> so the /policy suffix wins.
        if let Some(rest) = path.strip_prefix("/admin/api/sites/")
            && let Some(host) = rest.strip_suffix("/policy")
            && !host.is_empty()
            && !host.contains('/')
        {
            return Some(match method {
                "GET" => self.api_site_policy_get(host),
                "PUT" => self.api_site_policy_put(host, body),
                "DELETE" => self.api_site_policy_delete(host),
                _ => json_err(405, "method not allowed"),
            });
        }
        if method == "DELETE"
            && let Some(host) = path.strip_prefix("/admin/api/sites/")
        {
            return Some(self.api_sites_delete(host));
        }

        // === RC3 — honeypots write ========================================
        if method == "PUT" && path == "/admin/api/honeypots" {
            return Some(self.api_honeypots_replace(body));
        }
        // React panel paths (PUT global / PUT host / DELETE host) — kept
        // alongside the canonical REST paths below so the existing UI
        // works without a frontend rebuild.
        if method == "PUT" && path == "/admin/api/honeypots/global" {
            return Some(self.api_honeypots_global_via_body(body));
        }
        // Per-host honeypot bypass toggle. MUST appear BEFORE the
        // `PUT /admin/api/honeypots/host` arm below so this more-specific
        // path wins over the pack-level host override endpoint.
        if method == "PUT" && path == "/admin/api/honeypots/host/enabled" {
            return Some(self.api_honeypots_host_enabled(body));
        }
        if method == "PUT" && path == "/admin/api/honeypots/host" {
            return Some(self.api_honeypots_host_via_body(body));
        }
        if method == "DELETE"
            && let Some(host) = path.strip_prefix("/admin/api/honeypots/host/")
            && !host.contains('/')
        {
            return Some(self.api_honeypots_host_clear(host));
        }
        // Canonical REST paths (segment-encoded pack/host names).
        if method == "POST"
            && let Some(pack_id) = path.strip_prefix("/admin/api/honeypots/packs/")
        {
            return Some(self.api_honeypots_pack_toggle(pack_id, body));
        }
        if method == "POST"
            && let Some(rest) = path.strip_prefix("/admin/api/honeypots/hosts/")
            && let Some((host, pack_id)) = rest.split_once("/packs/")
        {
            return Some(self.api_honeypots_host_pack_toggle(host, pack_id, body));
        }
        if method == "DELETE"
            && let Some(host) = path.strip_prefix("/admin/api/honeypots/hosts/")
            && !host.contains('/')
        {
            return Some(self.api_honeypots_host_clear(host));
        }

        // === RC3 — raw config editor ======================================
        if method == "GET" && path == "/admin/api/config/raw" {
            // V230 — api_config_raw_get is now async (tokio::fs).
            return Some(self.api_config_raw_get().await);
        }
        if method == "PUT" && path == "/admin/api/config/raw" {
            // V230 — api_config_raw_put is now async (tokio::fs + spawn_blocking).
            return Some(self.api_config_raw_put(body).await);
        }
        if method == "POST" && path == "/admin/api/config/test" {
            // V230 — api_config_test is now async (tokio::fs + spawn_blocking).
            return Some(self.api_config_test(body).await);
        }

        // V-env — env-file feature-flag toggle endpoints (Write role enforced
        // by required_role_for in admin_auth.rs; double-checked implicitly
        // because handle_api is only reached when the gate passes).
        if method == "GET" && path == "/admin/api/env" {
            return Some(self.api_env_get());
        }
        if method == "PUT" && path == "/admin/api/env" {
            return Some(self.api_env_put(body));
        }
        // V-env — POST /admin/api/restart: spawn systemctl restart.
        if method == "POST" && path == "/admin/api/restart" {
            return Some(self.api_restart());
        }
        // V-env — POST /admin/api/config/apply: same as restart; named
        // separately so the Config page "Apply" button has a distinct endpoint.
        if method == "POST" && path == "/admin/api/config/apply" {
            return Some(self.api_restart());
        }

        // === ACME / Let's Encrypt endpoints ================================
        // NOTE: PUT /admin/api/acme/config is dispatched BEFORE any
        // /admin/api/acme/* prefix catch-all so the more-specific arm wins.

        // GET /admin/api/acme/config — Read role.
        if method == "GET" && path == "/admin/api/acme/config" {
            return Some(self.api_acme_config_get());
        }
        // PUT /admin/api/acme/config — Write role (enforced by required_role_for).
        if method == "PUT" && path == "/admin/api/acme/config" {
            return Some(self.api_acme_config_put(body));
        }
        // GET /admin/api/acme/orders — Read role.
        if method == "GET" && path == "/admin/api/acme/orders" {
            return Some(self.api_acme_orders_list());
        }
        // POST /admin/api/acme/orders — Write role.
        if method == "POST" && path == "/admin/api/acme/orders" {
            return Some(self.api_acme_orders_create(body).await);
        }
        // POST /admin/api/acme/orders/<host>/renew — Write role.
        if method == "POST"
            && let Some(rest) = path.strip_prefix("/admin/api/acme/orders/")
            && let Some(host) = rest.strip_suffix("/renew")
            && !host.is_empty()
            && !host.contains('/')
        {
            return Some(self.api_acme_orders_renew(host).await);
        }
        // GET /admin/api/acme/orders/<host> — Read role. Must be AFTER /renew.
        if method == "GET"
            && let Some(host) = path.strip_prefix("/admin/api/acme/orders/")
            && !host.is_empty()
            && !host.contains('/')
        {
            return Some(self.api_acme_orders_get(host));
        }

        let _ = role;
        None
    }

    /// V67 — POST /admin/api/login. Body is JSON
    /// `{"email": "...", "password": "..."}`. On success returns a
    /// session token (also Set-Cookie'd via the wrapping route).
    fn api_login(&self, body: &[u8]) -> (u16, String, Bytes) {
        let Some(store) = &self.web_admin else {
            return json_err(503, "web admin not configured");
        };
        #[derive(serde::Deserialize)]
        struct In<'a> {
            email: &'a str,
            password: &'a str,
        }
        let Ok(input) = serde_json::from_slice::<In<'_>>(body) else {
            return json_err(400, "invalid login body");
        };
        match store.login(input.email, input.password) {
            Some((token, must_change)) => {
                let cookie = format!(
                    "aegis_admin_session={token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400"
                );
                let body = serde_json::json!({
                    "ok": true,
                    "token": token,
                    // RC4 — the login response previously omitted `email`, so the
                    // SPA's auth state had email=undefined right after login,
                    // crashing the top bar (`email.split`). Echo the
                    // just-authenticated email back. `must_change` is emitted
                    // alongside `must_change_credentials` so the client (which
                    // reads `must_change`) actually triggers the forced
                    // credential-change flow at login AND on reload.
                    "email": input.email,
                    "must_change_credentials": must_change,
                    "must_change": must_change,
                    "set_cookie": cookie,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                )
            }
            None => json_err(401, "invalid credentials"),
        }
    }

    /// V67 — POST /admin/api/logout. Reads the session cookie,
    /// invalidates it in the store, returns 200 + Set-Cookie that
    /// clears the browser cookie.
    fn api_logout(&self, session: &Session) -> (u16, String, Bytes) {
        if let Some(store) = &self.web_admin {
            let headers = &session.req_header().headers;
            // V74-RC3 bug-fix: also accept the session token via the
            // x-admin-token header (React panel path). Otherwise
            // logout was a silent no-op for header-based clients and
            // the session stayed valid until its TTL elapsed.
            if let Some(t) = crate::security::cookie::read_cookie(headers, "aegis_admin_session") {
                store.logout(&t);
            }
            if let Some(t) = headers
                .get("x-admin-token")
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty())
            {
                store.logout(t);
            }
        }
        let body = serde_json::json!({
            "ok": true,
            "set_cookie": "aegis_admin_session=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0",
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V67 — GET /admin/api/me. Returns the current session's
    /// email + must_change flag, or 401 if no valid session.
    fn api_me(&self, session: &Session) -> (u16, String, Bytes) {
        let Some(store) = &self.web_admin else {
            return json_err(503, "web admin not configured");
        };
        let headers = &session.req_header().headers;
        let header_tok = headers
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty());

        // V74-RC3 bug-fix: try the header against BOTH registries
        // (config tokens AND web sessions). The React panel keeps
        // its post-login session token in localStorage and sends it
        // through this header — previously /me only checked config
        // tokens for the header path, returning 401 even though
        // /sites etc. would accept the same value via the cookie
        // (which the browser never gets, because the response body's
        // `set_cookie` field isn't an actual Set-Cookie header). Now
        // the header path mirrors authorise()'s dual lookup.
        if let Some(tok) = header_tok {
            if let Some(role) = self.tokens.authenticate(tok) {
                let body = serde_json::json!({
                    "authenticated": true,
                    "email": format!("token-{role:?}"),
                    "role": format!("{role:?}").to_lowercase(),
                    "must_change_credentials": false,
                    "must_change": false,
                    "auth": "config_token",
                });
                return (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
            if let Some((email, must_change)) = store.validate(tok) {
                let body = serde_json::json!({
                    "authenticated": true,
                    "email": email,
                    "role": "admin",
                    "must_change_credentials": must_change,
                    "must_change": must_change,
                    "auth": "session",
                });
                return (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                );
            }
        }
        let Some(t) = crate::security::cookie::read_cookie(headers, "aegis_admin_session") else {
            return json_err(401, "no session");
        };
        match store.validate(&t) {
            Some((email, must_change)) => {
                let body = serde_json::json!({
                    "authenticated": true,
                    "email": email,
                    "role": "admin",
                    "must_change_credentials": must_change,
                    "must_change": must_change,
                    "auth": "session",
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(body.to_string()),
                )
            }
            None => json_err(401, "invalid session"),
        }
    }

    /// V68 — GET /admin/api/runtime/status. Dashboard fuel:
    /// uptime, request counters, cache stats, scorer snapshot.
    fn api_runtime_status(&self) -> (u16, String, Bytes) {
        use std::sync::atomic::Ordering;
        let cache = self.cache.stats();
        let anomaly = self.anomaly.snapshot();
        let xdp = self.xdp.counters().unwrap_or_default();
        let body = serde_json::json!({
            "uptime_secs": self.started_at.elapsed().as_secs(),
            "config_path": self.config_path.display().to_string(),
            "requests": {
                "total": self.metrics.requests_total.load(Ordering::Relaxed),
                "denied": self.metrics.requests_denied.load(Ordering::Relaxed),
                "challenged": self.metrics.requests_challenged.load(Ordering::Relaxed),
            },
            "upstream": {
                "2xx": self.metrics.upstream_2xx.load(Ordering::Relaxed),
                "4xx": self.metrics.upstream_4xx.load(Ordering::Relaxed),
                "5xx": self.metrics.upstream_5xx.load(Ordering::Relaxed),
                "errors": self.metrics.upstream_errors.load(Ordering::Relaxed),
            },
            "cache": {
                "hits": cache.hits,
                "misses": cache.misses,
                "stores": cache.stores,
                "evictions": cache.evictions,
                "skipped_high_threat": cache.skipped_high_threat,
                "skipped_uncacheable": cache.skipped_uncacheable,
                "not_modified": cache.not_modified,
            },
            "xdp": {
                "pass": xdp.pass,
                "fast_pass": xdp.fast_pass,
                "drop_deny": xdp.drop_deny,
                "drop_rate": xdp.drop_rate,
                "drop_allowonly": xdp.drop_allowonly,
                "drop_syn": xdp.drop_syn,
                "drop_waf": xdp.drop_waf,
            },
            "anomaly_active_hosts": anomaly.into_iter().map(|(h, ms)| {
                serde_json::json!({"host": h, "remaining_ms": ms.to_string()})
            }).collect::<Vec<_>>(),
            "top_threats": match &self.shared_scorer {
                Some(s) => s.top(10),
                None => self.scorer.top(10),
            }.into_iter().map(|(ip, score)| {
                serde_json::json!({"ip": ip.to_string(), "score": score.as_f64()})
            }).collect::<Vec<_>>(),
            "top_threats_source": if self.shared_scorer.is_some() { "cluster" } else { "worker" },
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V68 — GET /admin/api/filters. Per-filter block/challenge
    /// counters scraped from RuntimeMetrics.
    fn api_filters(&self) -> (u16, String, Bytes) {
        use std::sync::atomic::Ordering;
        let mut filters = Vec::with_capacity(self.metrics.by_filter.len());
        for entry in self.metrics.by_filter.iter() {
            let name = entry.key().clone();
            let c = entry.value();
            filters.push(serde_json::json!({
                "name": name,
                "blocks": c.blocks.load(Ordering::Relaxed),
                "challenges": c.challenges.load(Ordering::Relaxed),
            }));
        }
        filters.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let body = serde_json::json!({"filters": filters});
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V68/RC3 — GET /admin/api/audit. Tails the last 200 audit
    /// log lines from `cfg.admin.audit_log_path` (plumbed in at
    /// construction time). Returns the text wrapped in JSON so the
    /// React panel can render it in a <pre> without paying for a
    /// separate Content-Type negotiation.
    /// V107 — auto-mined signature candidates surfaced from the
    /// online tarpit→miner background pipeline. Read-only;
    /// operator approval still happens via the Config editor +
    /// manual paste from the signature miner UI (V106).
    fn api_mined_signatures(&self) -> (u16, String, Bytes) {
        let Some(m) = &self.online_miner else {
            let body = serde_json::json!({
                "enabled": false,
                "note": "online miner not wired (Some pipeline init error). \
                         Configure AEGIS_TARPIT_LOG to populate the corpus.",
                "candidates": Vec::<serde_json::Value>::new(),
            });
            return (
                200,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        };
        let cands = (**m.current.load()).clone();
        let last_run = **m.last_run.load();
        let last_run_secs = last_run
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let body = serde_json::json!({
            "enabled": true,
            "last_run_unix_secs": last_run_secs,
            "candidates": cands.iter().map(|c| serde_json::json!({
                "ngram": c.ngram,
                "confidence": c.confidence,
                "attack_support": c.attack_support,
                "benign_support": c.benign_support,
                "category": c.suggested_category,
            })).collect::<Vec<_>>(),
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    fn api_audit(&self) -> (u16, String, Bytes) {
        let Some(path) = self.audit_log_path.as_deref() else {
            let body = serde_json::json!({
                "note": "admin.audit_log_path not configured — set it to enable in-panel audit tail",
                "entries": Vec::<serde_json::Value>::new(),
            });
            return (
                200,
                "application/json".to_string(),
                Bytes::from(body.to_string()),
            );
        };
        let text = crate::admin_ui::tail_audit(path, 200);
        let entries: Vec<&str> = text.lines().collect();
        let body = serde_json::json!({
            "path": path.display().to_string(),
            "entries": entries,
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V69 — GET /admin/api/honeypots/builtin. List the bait-path
    /// packs the HoneypotStore knows about. Operator's panel uses
    /// this to render checkboxes for the host overrides editor.
    ///
    /// V158 — return the FULL catalogue of BUILTIN_PACKS (with
    /// name/description/path_count), merged with the per-deployment
    /// enable state from the live snapshot. Previously only packs
    /// explicitly toggled by the operator were returned, so a fresh
    /// state file rendered as "0/0 packs" in the UI even though
    /// 18 packs are available.
    fn api_honeypots_builtin(&self) -> (u16, String, Bytes) {
        let snap = self.honeypots.snapshot();
        // Default to enabled per packs.rs comment: "Default is all on —
        // the patterns are globally safe." Per-deployment state can
        // turn individual packs off.
        let packs: Vec<serde_json::Value> = crate::honeypot::BUILTIN_PACKS
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "path_count": p.path_count(),
                    "enabled": snap.packs.get(p.id).copied().unwrap_or(true),
                })
            })
            .collect();
        let enabled_count = packs
            .iter()
            .filter(|p| p["enabled"].as_bool().unwrap_or(false))
            .count();
        let body = serde_json::json!({
            "global_enabled": snap.enabled,
            "tarpit_seconds": snap.tarpit_seconds,
            "tarpit_chunk_bytes": snap.tarpit_chunk_bytes,
            "server_header": snap.server_header,
            "score_bump": snap.score_bump,
            "auto_xdp_deny_threshold": snap.auto_xdp_deny_threshold,
            "packs": packs,
            "packs_total": crate::honeypot::BUILTIN_PACKS.len(),
            "packs_enabled": enabled_count,
            "custom_paths_count": snap.custom_paths.len(),
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V69/V74-RC3 — GET /admin/api/honeypots. Returns the FULL
    /// HoneypotState snapshot. The React panel deserialises it as
    /// the same TypeScript interface the `save` endpoint accepts, so
    /// shape mismatch between read and write was breaking the
    /// /admin/ui/honeypots page (TypeError: undefined is not an
    /// object reading l.packs[h.id]). Now everything is symmetrical:
    ///   GET  /admin/api/honeypots → HoneypotState
    ///   PUT  /admin/api/honeypots ← HoneypotState
    ///
    /// The response also includes a top-level `"host_disabled"` array
    /// (sorted) listing every host for which the honeypot filter has
    /// been bypassed via `PUT /admin/api/honeypots/host/enabled`.
    /// This field is already present in the serialised `HoneypotState`
    /// but is surfaced here explicitly so the React panel can render
    /// a "trusted hosts" list without parsing the full state blob.
    fn api_honeypots(&self) -> (u16, String, Bytes) {
        let snap = self.honeypots.snapshot();
        let mut body = match serde_json::to_value(&snap) {
            Ok(v) => v,
            Err(e) => return json_err(500, &format!("serialise honeypot state: {e}")),
        };
        // Inject a sorted `host_disabled` array at the top level so the UI
        // can render a "trusted hosts" panel without deep-parsing the state.
        // The value is already present inside `snap` (via serde), but an
        // explicit sorted list is more convenient for the React panel.
        let host_disabled = self.honeypots.host_disabled_list();
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "host_disabled".to_string(),
                serde_json::Value::Array(
                    host_disabled
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    /// V69 — GET /admin/api/sites. Combined view of operator-
    /// managed sites (/var/lib/aegis/sites.d/) plus ops-controlled
    /// sites (/etc/aegis/sites-enabled/). RC3 added the matching
    /// POST/DELETE writers.
    fn api_sites(&self) -> (u16, String, Bytes) {
        let managed = std::path::Path::new("/var/lib/aegis/sites.d");
        let ops = std::path::Path::new("/etc/aegis/sites-enabled");
        let sites = crate::admin_ui::list_sites(
            managed.exists().then_some(managed),
            ops.exists().then_some(ops),
        );
        let body = serde_json::json!({
            "sites": sites,
            "writable": true,
            "note": "RC3 supports POST/DELETE; reload via `aegis-pingora --upgrade`",
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(body.to_string()),
        )
    }

    // ============================================================
    //  RC3 — write-side endpoints
    // ============================================================

    /// RC3 — POST /admin/api/change-credentials. Body
    /// `{current_password, new_email, new_password}`. Verifies the
    /// old password, swaps email + hash, invalidates all other
    /// sessions, returns a freshly issued session token. The
    /// session cookie still needs to be re-set by the browser (the
    /// React panel reads `token` from the JSON and re-issues the
    /// cookie before its next request).
    fn api_change_credentials(&self, body: &[u8], session: &Session) -> (u16, String, Bytes) {
        let Some(store) = &self.web_admin else {
            return json_err(503, "web admin not configured");
        };
        #[derive(serde::Deserialize)]
        struct In<'a> {
            current_password: &'a str,
            new_email: &'a str,
            new_password: &'a str,
        }
        let Ok(input) = serde_json::from_slice::<In<'_>>(body) else {
            return json_err(400, "invalid change-credentials body");
        };
        // Need the current session token to identify which session
        // gets re-issued. Pull from the cookie header (same path the
        // login + logout flow uses).
        let headers = &session.req_header().headers;
        // V74-RC3 bug-fix: accept the session token from either the
        // aegis_admin_session cookie OR the x-admin-token header (the
        // React panel uses the latter). Without this fallback the
        // forced first-login password change couldn't complete from
        // the panel because the response only set the cookie via the
        // JSON body's `set_cookie` field, not an actual Set-Cookie
        // header — so the browser never had the cookie to send.
        let current_token = crate::security::cookie::read_cookie(headers, "aegis_admin_session")
            .or_else(|| {
                headers
                    .get("x-admin-token")
                    .and_then(|v| v.to_str().ok())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            });
        let Some(current_token) = current_token else {
            return json_err(401, "no active session");
        };
        match store.change_credentials(
            &current_token,
            input.current_password,
            input.new_email,
            input.new_password,
        ) {
            Ok(new_token) => {
                let cookie = format!(
                    "aegis_admin_session={new_token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400"
                );
                let resp = serde_json::json!({
                    "ok": true,
                    "token": new_token,
                    "email": input.new_email,
                    "set_cookie": cookie,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(400, &e),
        }
    }

    /// RC3 — POST /admin/api/sites. Body is `crate::admin_ui::NewSite`
    /// JSON. Writes the rendered `.conf` snippet to
    /// `/var/lib/aegis/sites.d/<host>.conf` atomically. Operator runs
    /// `aegis-pingora --upgrade` to pick the change up live.
    fn api_sites_create(&self, body: &[u8]) -> (u16, String, Bytes) {
        let site: crate::admin_ui::NewSite = match serde_json::from_slice(body) {
            Ok(s) => s,
            Err(e) => return json_err(400, &format!("invalid site JSON: {e}")),
        };
        // Render first so we surface validation errors as 400 (not
        // as a half-written .conf on disk).
        let dsl = match crate::admin_ui::render_site(&site) {
            Ok(s) => s,
            Err(e) => return json_err(400, &e),
        };
        let managed_dir = std::path::Path::new("/var/lib/aegis/sites.d");
        let written = match crate::admin_ui::write_site(managed_dir, &site) {
            Ok(p) => p,
            Err(e) => return json_err(500, &e),
        };
        let resp = serde_json::json!({
            "ok": true,
            "host": site.host,
            "path": written.to_string_lossy(),
            "dsl_snippet": dsl,
            "note": "run `aegis-pingora --upgrade` to load the new site without dropping connections",
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(resp.to_string()),
        )
    }

    /// RC3 — DELETE /admin/api/sites/<host>. Removes the matching
    /// `.conf` from the managed dir. URL-decodes the host segment so
    /// IDN / punycode hosts work.
    fn api_sites_delete(&self, host_segment: &str) -> (u16, String, Bytes) {
        let host = urlencoding::decode(host_segment)
            .unwrap_or_default()
            .into_owned();
        let managed_dir = std::path::Path::new("/var/lib/aegis/sites.d");
        match crate::admin_ui::delete_site(managed_dir, &host) {
            Ok(()) => {
                let resp = serde_json::json!({
                    "ok": true,
                    "host": host,
                    "note": "run `aegis-pingora --upgrade` to apply",
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(400, &e),
        }
    }

    /// RC3 — PUT /admin/api/honeypots. Body is the full
    /// `HoneypotState` JSON. Atomic-replace the whole state file —
    /// the background reloader picks the new state up within one
    /// tick (~30s) on sibling workers via mtime poll.
    fn api_honeypots_replace(&self, body: &[u8]) -> (u16, String, Bytes) {
        let state: crate::honeypot::HoneypotState = match serde_json::from_slice(body) {
            Ok(s) => s,
            Err(e) => return json_err(400, &format!("invalid honeypot state: {e}")),
        };
        match self.honeypots.replace(state) {
            Ok(()) => {
                let resp = serde_json::json!({"ok": true});
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// V74-RC3 — PUT /admin/api/honeypots/global. React panel path,
    /// body `{pack_id, enabled}`. Delegates to set_global_pack.
    fn api_honeypots_global_via_body(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            pack_id: String,
            enabled: bool,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"pack_id\":...,\"enabled\":bool}");
        };
        match self
            .honeypots
            .set_global_pack(&input.pack_id, input.enabled)
        {
            Ok(()) => {
                let resp = serde_json::json!({
                    "ok": true,
                    "pack": input.pack_id,
                    "enabled": input.enabled,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// V74-RC3 — PUT /admin/api/honeypots/host. React panel path,
    /// body `{host, pack_id, enabled}`. Delegates to set_host_pack.
    fn api_honeypots_host_via_body(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            host: String,
            pack_id: String,
            enabled: bool,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(
                400,
                "expected {\"host\":...,\"pack_id\":...,\"enabled\":bool}",
            );
        };
        match self
            .honeypots
            .set_host_pack(&input.host, &input.pack_id, input.enabled)
        {
            Ok(()) => {
                let resp = serde_json::json!({
                    "ok": true,
                    "host": input.host,
                    "pack": input.pack_id,
                    "enabled": input.enabled,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// PUT /admin/api/honeypots/host/enabled — per-host honeypot bypass.
    ///
    /// Body: `{"host": "<hostname>", "enabled": bool}`
    ///
    /// `enabled=false` adds the host (ASCII-lowercased) to
    /// `HoneypotState::host_disabled`, causing `HoneypotStore::check()` to
    /// return `None` for every request from that host, bypassing all pack
    /// and matcher logic.  `enabled=true` removes the host from that set so
    /// normal pack-based evaluation resumes.  The change is persisted
    /// atomically to `/var/lib/aegis/honeypots.json` by `set_host_enabled`.
    ///
    /// Response 200: `{"ok": true, "host": "<lowercased>", "enabled": bool,
    ///                 "host_disabled": [...]}`
    /// Response 400: `{"error": "..."}`
    ///
    /// Auth: Write role (covered by the catch-all
    /// `PUT /admin/api/honeypots*` arm in `required_role_for`).
    ///
    /// NOTE: This route is dispatched BEFORE `PUT /admin/api/honeypots/host`
    /// in the router so the more-specific `/host/enabled` path wins.
    fn api_honeypots_host_enabled(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            host: String,
            enabled: bool,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"host\":\"<hostname>\",\"enabled\":bool}");
        };
        if input.host.is_empty() {
            return json_err(400, "\"host\" must not be empty");
        }
        // V237 — adversarial-review belt-and-braces: hostnames per RFC 1035 max
        // out at 253 bytes, and we never want non-printable / control bytes,
        // dots aside, in the persisted JSON. Cap and validate before any state
        // mutation so a Write-role operator can't bloat or corrupt the on-disk
        // honeypots.json by accident or curiosity.
        if input.host.len() > 253 {
            return json_err(400, "\"host\" must be ≤ 253 bytes");
        }
        if !input
            .host
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b':'))
        {
            return json_err(
                400,
                "\"host\" must contain only ASCII letters, digits, '-', '.' or ':'",
            );
        }
        match self.honeypots.set_host_enabled(&input.host, input.enabled) {
            Ok(()) => {
                let host_lower = input.host.to_ascii_lowercase();
                let host_disabled = self.honeypots.host_disabled_list();
                let resp = serde_json::json!({
                    "ok": true,
                    "host": host_lower,
                    "enabled": input.enabled,
                    "host_disabled": host_disabled,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// RC3 — POST /admin/api/honeypots/packs/<pack_id>. Body
    /// `{enabled: bool}`. Flips one pack at the global level. The
    /// per-host overrides are unchanged.
    fn api_honeypots_pack_toggle(&self, pack_id: &str, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            enabled: bool,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"enabled\": true|false}");
        };
        match self.honeypots.set_global_pack(pack_id, input.enabled) {
            Ok(()) => {
                let resp = serde_json::json!({
                    "ok": true,
                    "pack": pack_id,
                    "enabled": input.enabled,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// RC3 — POST /admin/api/honeypots/hosts/<host>/packs/<pack_id>.
    /// Same as pack_toggle but scoped to a single host. Host is
    /// URL-decoded so dots in the segment don't trip the router.
    fn api_honeypots_host_pack_toggle(
        &self,
        host: &str,
        pack_id: &str,
        body: &[u8],
    ) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            enabled: bool,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"enabled\": true|false}");
        };
        let host = urlencoding::decode(host).unwrap_or_default().into_owned();
        match self.honeypots.set_host_pack(&host, pack_id, input.enabled) {
            Ok(()) => {
                let resp = serde_json::json!({
                    "ok": true,
                    "host": host,
                    "pack": pack_id,
                    "enabled": input.enabled,
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// RC3 — DELETE /admin/api/honeypots/hosts/<host>. Drops the
    /// per-host override entirely so the host falls back to global
    /// pack toggles.
    fn api_honeypots_host_clear(&self, host: &str) -> (u16, String, Bytes) {
        let host = urlencoding::decode(host).unwrap_or_default().into_owned();
        match self.honeypots.clear_host_override(&host) {
            Ok(()) => {
                let resp = serde_json::json!({"ok": true, "host": host});
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => json_err(500, &e.to_string()),
        }
    }

    /// RC3 — GET /admin/api/config/raw. Returns the raw text of the
    /// currently loaded config file. Operators use this to wire the
    /// "edit raw config" textarea in the panel; it bypasses the
    /// site-snippet renderer for advanced edits the structured
    /// form can't express.
    // V230 — async-context handler; reads config off-thread via tokio::fs.
    async fn api_config_raw_get(&self) -> (u16, String, Bytes) {
        // V230 — was std::fs::read_to_string (blocking).
        let text = match tokio::fs::read_to_string(&self.config_path).await {
            Ok(t) => t,
            Err(e) => return json_err(500, &format!("read {}: {e}", self.config_path.display())),
        };
        (
            200,
            "text/plain; charset=utf-8".to_string(),
            Bytes::from(text),
        )
    }

    /// RC3 — PUT /admin/api/config/raw. Body `{content: "..."}`.
    /// Probe-parses against a sibling temp file so a syntax error
    /// short-circuits with 400 before the live config gets touched;
    /// on success, atomic-renames the new content into place.
    /// `--upgrade` to apply.
    // V230 — async-context handler; probe/write/rename run off-thread.
    async fn api_config_raw_put(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            content: String,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"content\": \"...\"}");
        };
        // Step 1 — probe parse.
        let probe = self.config_path.with_extension("conf.probe");
        // V230 — was std::fs::write (blocking).
        if let Err(e) = tokio::fs::write(&probe, &input.content).await {
            return json_err(500, &format!("probe write: {e}"));
        }
        // V230 — parse_file does sync I/O + parsing; push it onto a blocking
        // thread so it doesn't stall the pingora runtime.
        let probe_for_parse = probe.clone();
        let parse_result = match tokio::task::spawn_blocking(move || {
            crate::dsl::parser::parse_file(&probe_for_parse)
        })
        .await
        {
            Ok(r) => r,
            Err(e) => return json_err(500, &format!("parse join: {e}")),
        };
        // V230 — was std::fs::remove_file (blocking).
        let _ = tokio::fs::remove_file(&probe).await;
        if let Err(e) = parse_result {
            return json_err(400, &format!("parse error: {e}"));
        }
        // Step 2 — atomic write.
        let tmp = self.config_path.with_extension("conf.tmp");
        // V230 — was std::fs::write (blocking).
        if let Err(e) = tokio::fs::write(&tmp, &input.content).await {
            return json_err(500, &format!("write tmp: {e}"));
        }
        // V230 — was std::fs::rename (blocking).
        if let Err(e) = tokio::fs::rename(&tmp, &self.config_path).await {
            return json_err(500, &format!("rename: {e}"));
        }
        let resp = serde_json::json!({
            "ok": true,
            "path": self.config_path.to_string_lossy(),
            "note": "run `aegis-pingora --upgrade` to load",
        });
        (
            200,
            "application/json".to_string(),
            Bytes::from(resp.to_string()),
        )
    }

    /// RC3 — POST /admin/api/config/test. Body `{content: "..."}`.
    /// Probe-parses WITHOUT writing the live config. Lets the panel
    /// validate config edits before committing.
    // V230 — async-context handler; probe write/parse/remove run off-thread.
    async fn api_config_test(&self, body: &[u8]) -> (u16, String, Bytes) {
        #[derive(serde::Deserialize)]
        struct In {
            content: String,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return json_err(400, "expected {\"content\": \"...\"}");
        };
        let probe = self.config_path.with_extension("conf.probe");
        // V230 — was std::fs::write (blocking).
        if let Err(e) = tokio::fs::write(&probe, &input.content).await {
            return json_err(500, &format!("probe write: {e}"));
        }
        // V230 — parse_file does sync I/O; offload via spawn_blocking.
        let probe_for_parse = probe.clone();
        let result = match tokio::task::spawn_blocking(move || {
            crate::dsl::parser::parse_file(&probe_for_parse)
        })
        .await
        {
            Ok(r) => r,
            Err(e) => return json_err(500, &format!("parse join: {e}")),
        };
        // V230 — was std::fs::remove_file (blocking).
        let _ = tokio::fs::remove_file(&probe).await;
        match result {
            Ok(_) => {
                let resp = serde_json::json!({"ok": true});
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
            Err(e) => {
                let resp = serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                });
                (
                    200,
                    "application/json".to_string(),
                    Bytes::from(resp.to_string()),
                )
            }
        }
    }

    /// `GET /admin/anomaly` — list hosts currently in attack-mode
    /// and the milliseconds remaining on each window.
    fn render_anomaly(&self) -> String {
        let snap = self.anomaly.snapshot();
        if snap.is_empty() {
            return "no_active_attacks\n".to_string();
        }
        let mut out = String::with_capacity(snap.len() * 60);
        for (host, remaining_ms) in snap {
            let _ = writeln!(out, "{host} attack_remaining_ms={remaining_ms}");
        }
        out
    }

    fn execute_purge(&self, all: bool, host: Option<&str>, prefix: Option<&str>) -> usize {
        let removed = if all {
            self.cache.purge_all()
        } else {
            match (host, prefix) {
                (Some(h), None) => self.cache.purge_host(h),
                (None, Some(p)) => self.cache.purge_path_prefix(p),
                (Some(h), Some(p)) => self
                    .cache
                    .purge_where(|k| !(k.host_lower_eq(h) && k.path.starts_with(p))),
                (None, None) => 0,
            }
        };
        // Always broadcast — multi-process deploys converge within
        // one background tick (30s) on sibling workers via mtime poll.
        // No-op when AEGIS_CACHE_BROADCAST is unset.
        ResponseCache::broadcast_purge();
        removed
    }

    /// Decide if the request's token (header `x-admin-token` OR
    /// session cookie `aegis_admin_session` from the web UI login
    /// flow) clears the role bar set by
    /// `required_role_for(method, path)`. Returns `Ok(role)` when
    /// authorised, `Err((status, reason))` when not.
    ///
    /// Resolution order mirrors hyper handler:
    ///   1. x-admin-token header — first tried as a config-file token
    ///      (CLI / curl path), then as a WebAdminStore session token
    ///      (the React panel stores its session token in localStorage
    ///      and sends it through this same header). The dual lookup
    ///      lets one client-side code path serve both auth styles
    ///      without the browser needing to deal with cookies.
    ///   2. aegis_admin_session cookie — set by the login endpoint
    ///      via Set-Cookie. Browsers that have the cookie use this
    ///      path automatically; CLI clients ignore it.
    fn authorise(
        &self,
        session: &Session,
        method: &str,
        path: &str,
    ) -> Result<Option<crate::config::AdminRole>, (u16, &'static str)> {
        let required = required_role_for(method, path);
        let Some(required) = required else {
            return Ok(None); // endpoint is public
        };
        let headers = &session.req_header().headers;
        let supplied = headers
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let session_token = crate::security::cookie::read_cookie(headers, "aegis_admin_session");

        // Bug-fix (V74-RC3 follow-up): the previous logic refused
        // `x-admin-token: <session-token>` because it only checked
        // `tokens.authenticate()` (config-file tokens). The React panel
        // stores its post-login session token in localStorage and
        // sends it via this header, so the panel was getting 401 on
        // every API call after login. Now we try both registries:
        // first the config-token registry, then — if that returns
        // None and we have a web_admin store — the session table.
        let granted = if !supplied.is_empty() {
            self.tokens.authenticate(supplied).or_else(|| {
                self.web_admin
                    .as_ref()
                    .and_then(|s| s.validate(supplied))
                    .map(|_| crate::config::AdminRole::Admin)
            })
        } else if let (Some(store), Some(t)) = (&self.web_admin, session_token.as_deref()) {
            store.validate(t).map(|_| crate::config::AdminRole::Admin)
        } else {
            None
        };

        if self.tokens.is_empty() && self.web_admin.is_none() {
            return Err((503, "admin auth not configured"));
        }
        match granted {
            Some(role) if role >= required => Ok(Some(role)),
            Some(_) => Err((403, "insufficient role")),
            None => Err((401, "invalid or missing token")),
        }
    }
}

#[async_trait]
impl ProxyHttp for AdminProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        let method = session.req_header().method.clone();
        let uri = session.req_header().uri.clone();
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();
        let peer = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_string());

        // Auth gate first — public endpoints (None required role)
        // pass through without bumping the audit log. V66+ also
        // honours web session cookies inside `authorise` so the
        // React panel can call /admin/api/* without an admin token.
        let role = match self.authorise(session, method.as_str(), &path) {
            Ok(r) => r,
            Err((status, reason)) => {
                self.audit
                    .record(&peer, method.as_str(), &path, None, status);
                Self::respond(
                    session,
                    status,
                    "text/plain",
                    Bytes::from(format!("{reason}\n")),
                )
                .await?;
                return Ok(true);
            }
        };

        // V66 — early-branch for static React assets. `web_asset`
        // returns Some((bytes, content_type)) for both exact files
        // and SPA fallback (unknown subpaths → index.html for
        // client-side router). 404 only when web_asset can't even
        // find index.html (binary built without the React bundle).
        if path == "/" || path == "/admin/ui" || path.starts_with("/admin/ui/") {
            if let Some((bytes, ct)) = crate::admin_ui::web_asset(&path) {
                self.audit.record(&peer, method.as_str(), &path, role, 200);
                Self::respond_bytes(session, 200, ct, Bytes::from_static(bytes)).await?;
            } else {
                self.audit.record(&peer, method.as_str(), &path, role, 404);
                Self::respond(
                    session,
                    404,
                    "text/plain",
                    Bytes::from_static(b"web UI assets not bundled\n"),
                )
                .await?;
            }
            return Ok(true);
        }

        // V66 — /admin/api/* JSON surface (login flow, dashboard
        // fuel, honeypot/site listings). Bodies are JSON bytes;
        // routed through a separate dispatcher that returns
        // (status, content_type, body bytes).
        if path.starts_with("/admin/api/") {
            // Some endpoints (POST login, PUT config) need the
            // request body. Pull it up to 1 MiB; beyond that we
            // refuse with 413.
            let body_bytes = read_request_body(session, 1024 * 1024).await?;
            let resp = self
                .handle_api(method.as_str(), &path, &query, role, &body_bytes, session)
                .await;
            let (status_u16, ct, body) = match resp {
                Some(r) => r,
                None => (
                    404,
                    "application/json".to_string(),
                    Bytes::from_static(br#"{"error":"unknown admin api endpoint"}"#),
                ),
            };
            self.audit
                .record(&peer, method.as_str(), &path, role, status_u16);
            // Build header inline (content-type is dynamic — not
            // a 'static str — so we can't go through respond_bytes).
            let mut header = ResponseHeader::build(status_u16, Some(2))?;
            let _ = header.insert_header("content-type", ct.as_str());
            let _ = header.insert_header("content-length", body.len().to_string());
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(body), true).await?;
            return Ok(true);
        }

        // Route. Status defaults to 200 unless overridden below.
        let mut status: u16 = 200;
        let body: String;
        let content_type: &'static str;
        match (method.as_str(), path.as_str()) {
            ("GET", "/metrics") => {
                let mut m = self.metrics.render_prometheus();
                self.append_cache_stats(&mut m);
                self.append_xdp_stats(&mut m);
                self.append_cluster_stats(&mut m);
                body = m;
                content_type = "text/plain; version=0.0.4";
            }
            // `/health` is the original aegis-pingora path; `/admin/health`
            // matches the hyper handler's public health endpoint so
            // existing load-balancer health checks pointing at either
            // path keep working when traffic moves over.
            ("GET", "/health") | ("GET", "/admin/health") => {
                body = "ok\n".to_string();
                content_type = "text/plain";
            }
            ("GET", "/admin/cache") => {
                body = self.render_cache_text();
                content_type = "text/plain";
            }
            ("GET", "/admin/cache/dump") => {
                body = self.render_cache_dump();
                content_type = "text/plain";
            }
            ("POST", "/admin/cache/purge") => match Self::parse_purge_query(&query) {
                Ok((all, host, prefix)) => {
                    let n = self.execute_purge(all, host.as_deref(), prefix.as_deref());
                    body = format!("purged {n}\n");
                    content_type = "text/plain";
                }
                Err(reason) => {
                    status = 400;
                    body = reason;
                    content_type = "text/plain";
                }
            },
            // V94 — operator-triggered SharedScorer compaction. Walks
            // both shared v4+v6 maps and tombstones entries idle past
            // `5 × window` seconds. Returns the count reclaimed.
            // 503s when the cluster scorer isn't wired (non-Linux dev,
            // arena init failed).
            ("POST", "/admin/shared_scorer/compact") => match &self.shared_scorer {
                Some(ss) => {
                    let removed = ss.cleanup_stale(std::time::Instant::now());
                    body = format!("compacted removed={removed}\n");
                    content_type = "text/plain";
                }
                None => {
                    status = 503;
                    body =
                        "shared scorer unavailable (cluster arena not initialised)\n".to_string();
                    content_type = "text/plain";
                }
            },
            ("POST", "/admin/waf/reload") => {
                let n = self.waf.maybe_reload_rules();
                body = format!("reloaded {n} file(s)\n");
                content_type = "text/plain";
            }
            // V99 — signature miner. Body format: two newline-delimited
            // sections separated by a line containing only `---`.
            // First section = attack payloads (one per line); second =
            // benign samples. Returns ranked candidates.
            //
            // Example body:
            //   /api?id=1' union select 1,2--
            //   /login?u=' or 1=1--
            //   ---
            //   /api?id=5
            //   /login?u=alice
            //
            // Output is text/plain so an operator can pipe directly to
            // a WAF rule file edit. No write-back — operator promotes
            // by hand (intentional: signature mining produces approx
            // patterns and unattended writes to WAF config is a bad
            // edge for any prod deployment).
            ("POST", "/admin/signature_mine") => {
                // Pull up to 1 MiB of payload — operator typically
                // pipes a few hundred lines, hard cap is just a
                // safety net.
                let body_bytes = read_request_body(session, 1024 * 1024).await?;
                let raw = std::str::from_utf8(&body_bytes).unwrap_or("");
                let mut attacks: Vec<String> = Vec::new();
                let mut benign: Vec<String> = Vec::new();
                let mut bucket = &mut attacks;
                for line in raw.lines() {
                    let t = line.trim();
                    if t == "---" {
                        bucket = &mut benign;
                        continue;
                    }
                    if !t.is_empty() {
                        bucket.push(t.to_string());
                    }
                }
                let cands = crate::signature_mine::mine(&attacks, &benign);
                if cands.is_empty() {
                    body = format!(
                        "no candidates (attacks={} benign={})\n",
                        attacks.len(),
                        benign.len()
                    );
                } else {
                    let mut out = String::with_capacity(cands.len() * 80);
                    let _ = writeln!(
                        out,
                        "# attacks={} benign={} candidates={}",
                        attacks.len(),
                        benign.len(),
                        cands.len()
                    );
                    let _ = writeln!(
                        out,
                        "# confidence  attack_support  benign_support  category  ngram"
                    );
                    for c in &cands {
                        let _ = writeln!(
                            out,
                            "{:.3}  {:.3}  {:.3}  {}  {}",
                            c.confidence,
                            c.attack_support,
                            c.benign_support,
                            c.suggested_category,
                            c.ngram
                        );
                    }
                    body = out;
                }
                content_type = "text/plain";
            }
            ("GET", "/admin/threats") => {
                body = self.render_threats();
                content_type = "text/plain";
            }
            ("GET", "/admin/anomaly") => {
                body = self.render_anomaly();
                content_type = "text/plain";
            }
            ("GET", "/admin/hot_uris") => {
                body = self.render_hot_uris();
                content_type = "text/plain";
            }
            // V45 — XDP counters + deny/undeny mutations. The path-
            // prefix routes for deny/undeny are matched in the
            // catch-all below because Rust match-on-(String, String)
            // can't do `starts_with` patterns. The arm here handles
            // the bare /admin/xdp counters endpoint.
            ("GET", "/admin/xdp") => {
                body = self.render_xdp();
                content_type = "text/plain";
            }
            // V44 — explicit "use pingora's built-in upgrade"
            // response instead of silently 404'ing /admin/reload.
            // Operators coming from the hyper handler expect this
            // endpoint to exist; pointing them at the right mechanism
            // is more useful than a generic 404.
            ("POST", "/admin/reload") => {
                status = 501;
                body = "/admin/reload is not implemented on aegis-pingora.\n\
                       \nUse the JSON API restart endpoint: POST /admin/api/restart\n\
                       \n  curl -X POST http://127.0.0.1:9090/admin/api/restart \\\n\
                       \n       -H 'x-admin-token: <token>' -H 'Content-Type: application/json' -d '{}'\n\
                       \nOr use pingora's built-in zero-downtime upgrade:\n\
                       \n  /usr/local/bin/aegis-pingora --upgrade --config /etc/aegis/aegis.conf\n".to_string();
                content_type = "text/plain";
            }
            // V45 — XDP deny/undeny take an IP suffix; match by
            // prefix rather than exact path. Constrained to POST per
            // required_role_for's Write-role gate.
            ("POST", p) if p.starts_with("/admin/xdp/deny/") => {
                match Self::parse_xdp_ip(p, "/admin/xdp/deny/") {
                    Ok(ip) => match self.xdp_deny(ip) {
                        Ok(()) => {
                            body = format!("xdp_deny {ip}\n");
                            content_type = "text/plain";
                        }
                        Err(reason) => {
                            status = 500;
                            body = format!("{reason}\n");
                            content_type = "text/plain";
                        }
                    },
                    Err(reason) => {
                        status = 400;
                        body = format!("{reason}\n");
                        content_type = "text/plain";
                    }
                }
            }
            ("POST", p) if p.starts_with("/admin/xdp/undeny/") => {
                match Self::parse_xdp_ip(p, "/admin/xdp/undeny/") {
                    Ok(ip) => match self.xdp_undeny(ip) {
                        Ok(()) => {
                            body = format!("xdp_undeny {ip}\n");
                            content_type = "text/plain";
                        }
                        Err(reason) => {
                            status = 500;
                            body = format!("{reason}\n");
                            content_type = "text/plain";
                        }
                    },
                    Err(reason) => {
                        status = 400;
                        body = format!("{reason}\n");
                        content_type = "text/plain";
                    }
                }
            }
            _ => {
                status = 404;
                body = "aegis-pingora admin endpoints:\n\
                       \n  public:\n\
                       \n    GET  /health\n\
                       \n    GET  /metrics\n\
                       \n  authenticated (x-admin-token, Read role):\n\
                       \n    GET  /admin/health\n\
                       \n    GET  /admin/cache\n\
                       \n    GET  /admin/cache/dump\n\
                       \n    GET  /admin/threats\n\
                       \n    GET  /admin/anomaly\n\
                       \n    GET  /admin/hot_uris\n\
                       \n    GET  /admin/xdp\n\
                       \n  authenticated (x-admin-token, Write role):\n\
                       \n    POST /admin/cache/purge?all=1|?host=|?prefix=\n\
                       \n    POST /admin/waf/reload\n\
                       \n    POST /admin/shared_scorer/compact\n\
                       \n    POST /admin/signature_mine\n\
                       \n    POST /admin/xdp/deny/<ip>\n\
                       \n    POST /admin/xdp/undeny/<ip>\n\
                       \n  authenticated (x-admin-token, Admin role):\n\
                       \n    POST /admin/reload  (returns 501 — use --upgrade)\n"
                    .to_string();
                content_type = "text/plain";
            }
        }

        self.audit
            .record(&peer, method.as_str(), &path, role, status);
        Self::respond(session, status, content_type, Bytes::from(body)).await?;
        Ok(true)
    }

    /// Unreachable: `request_filter` always returns Ok(true) above.
    /// pingora still demands the trait method exists; we point it at
    /// an obviously-invalid loopback peer so any future regression
    /// that breaks the short-circuit fails loudly instead of silently
    /// proxying admin requests to a real backend.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            ("127.0.0.1", 1),
            false,
            String::new(),
        )))
    }
}

/// V67 — small helper to build a JSON error response.
fn json_err(status: u16, msg: &str) -> (u16, String, Bytes) {
    let body = serde_json::json!({"error": msg, "status": status});
    (
        status,
        "application/json".to_string(),
        Bytes::from(body.to_string()),
    )
}

// ── V244 — file-backed benchmark/flood result state ────────────────────────
// Each SO_REUSEPORT worker has its OWN in-memory bench/flood state, so a run
// started on one worker is invisible to a result-poll that lands on another
// worker → the panel's progress bar spun forever ("results never appear").
// The result is therefore persisted to a shared file under AEGIS_HOME that
// every worker reads, mirroring how the other cross-worker state is handled.

fn benchmark_result_path() -> std::path::PathBuf {
    aegis_env_file_path().with_file_name(".benchmark-result.json")
}
fn flood_result_path() -> std::path::PathBuf {
    aegis_env_file_path().with_file_name(".benchmark-flood-result.json")
}
fn compare_result_path() -> std::path::PathBuf {
    aegis_env_file_path().with_file_name(".benchmark-compare-result.json")
}

fn write_result_file(path: &std::path::Path, json: &[u8]) {
    let _ = std::fs::write(path, json);
}

/// True when the file holds a `"status":"running"` sentinel written less than
/// `stale_secs` ago — i.e. a run is genuinely in progress on some worker.
fn result_running_fresh(path: &std::path::Path, stale_secs: u64) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    if !String::from_utf8_lossy(&bytes).contains("\"status\":\"running\"") {
        return false;
    }
    let age = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    age <= stale_secs
}

/// Serve a persisted result file as the JSON response. A stale "running"
/// sentinel (writer crashed) older than `stale_secs` falls back to `idle_json`.
fn read_result_file(
    path: &std::path::Path,
    idle_json: String,
    stale_secs: u64,
) -> (u16, String, Bytes) {
    let Ok(bytes) = std::fs::read(path) else {
        return (200, "application/json".to_string(), Bytes::from(idle_json));
    };
    if String::from_utf8_lossy(&bytes).contains("\"status\":\"running\"") {
        let age = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if age > stale_secs {
            return (200, "application/json".to_string(), Bytes::from(idle_json));
        }
    }
    (200, "application/json".to_string(), Bytes::from(bytes))
}

/// Resolve the Sigma corpus path robustly. The daemon's CWD is `/` under
/// systemd, so a bare relative path never resolves — that was why both the
/// summary and the per-rule list reported nothing even though the bundled
/// corpus has 562 rules. Honour `AEGIS_SIGMA_RULES` first, then probe the
/// known install locations (synced source tree + packaged dirs), falling back
/// to the relative path only as a last resort.
fn resolve_sigma_rules_path() -> String {
    if let Ok(p) = std::env::var("AEGIS_SIGMA_RULES")
        && !p.is_empty()
    {
        return p;
    }
    const CANDIDATES: [&str; 4] = [
        "/etc/aegis/rules/sigma/sigma-webserver.toml",
        "/var/lib/aegis/rules/sigma/sigma-webserver.toml",
        "/usr/local/src/aegis/rules/sigma/sigma-webserver.toml",
        "rules/sigma/sigma-webserver.toml",
    ];
    CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or(&CANDIDATES[3])
        .to_string()
}

/// V66 — drain the request body up to `max` bytes. Returns 413 via
/// Err(...) when exceeded so the caller can short-circuit. Pingora's
/// session model: read_request_body() returns chunks; we accumulate.
async fn read_request_body(session: &mut Session, max: usize) -> pingora_core::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(0);
    while let Some(chunk) = session.read_request_body().await? {
        if out.len() + chunk.len() > max {
            // Hit the cap — truncate + return what we have. Callers
            // can detect via len() == max and reject as 413.
            let remaining = max - out.len();
            out.extend_from_slice(&chunk[..remaining]);
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

// V219 — hex helpers for Privacy Pass issuer registration.
fn hex_to_bytes(s: &str, want_len: usize) -> Option<Vec<u8>> {
    let bytes = hex_to_bytes_any(s)?;
    if bytes.len() == want_len {
        Some(bytes)
    } else {
        None
    }
}

fn hex_to_bytes_any(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── ML retrain request model ─────────────────────────────────────────────────
//
// POST /admin/api/ml/retrain body schema. All fields optional so an empty
// `{}` (or empty body) retrains over whatever samples the trainer already
// holds with conservative defaults.

#[derive(Debug, Default, serde::Deserialize)]
struct MlRetrainRequest {
    epochs: Option<u32>,
    lr: Option<f32>,
    #[serde(default)]
    samples: Vec<MlRetrainSample>,
}

#[derive(Debug, serde::Deserialize)]
struct MlRetrainSample {
    /// Exactly N_FEATURES_V2 (23) floats in `FeaturesV2::as_array()` order.
    features: Vec<f32>,
    /// "benign" | "malicious" (case-insensitive; also accepts "0"/"1").
    label: String,
}

impl MlRetrainSample {
    fn to_labelled_sample(&self) -> Result<crate::ddos::ml_training::LabelledSample, String> {
        use crate::ddos::ml_score_v2::N_FEATURES_V2;
        use crate::ddos::ml_training::{Label, LabelledSample};

        if self.features.len() != N_FEATURES_V2 {
            return Err(format!(
                "features must have exactly {} elements, got {}",
                N_FEATURES_V2,
                self.features.len()
            ));
        }
        if let Some(bad) = self.features.iter().find(|v| !v.is_finite()) {
            return Err(format!("feature value {bad} is not finite"));
        }
        let label = match self.label.trim().to_ascii_lowercase().as_str() {
            "malicious" | "bad" | "1" => Label::Malicious,
            "benign" | "good" | "0" => Label::Benign,
            other => {
                return Err(format!(
                    "label must be \"benign\" or \"malicious\", got {other:?}"
                ));
            }
        };
        Ok(LabelledSample {
            features: features_v2_from_slice(&self.features),
            label,
        })
    }
}

/// Build a [FeaturesV2] from a slice of exactly N_FEATURES_V2 floats, in the
/// same order as `FeaturesV2::as_array()`. Caller must validate the length;
/// this indexes positionally and panics on a short slice (the public callers
/// above always length-check first).
fn features_v2_from_slice(a: &[f32]) -> crate::ddos::ml_score_v2::FeaturesV2 {
    crate::ddos::ml_score_v2::FeaturesV2 {
        uri_length: a[0],
        query_param_count: a[1],
        uri_entropy: a[2],
        query_entropy: a[3],
        header_count: a[4],
        has_user_agent: a[5],
        has_accept_language: a[6],
        has_accept_encoding: a[7],
        has_referer: a[8],
        method_is_post: a[9],
        body_length: a[10],
        ja4_present: a[11],
        ja4_browser_family: a[12],
        h2fp_present: a[13],
        recent_denied_rate: a[14],
        recent_challenged_rate: a[15],
        bot_score_rate: a[16],
        requests_per_min: a[17],
        fast_repeat: a[18],
        night_window: a[19],
        fp_consistency_score: a[20],
        ja4_reputation: a[21],
        asn_reputation: a[22],
    }
}

#[cfg(test)]
mod env_flag_tests {
    use super::{EnvKind, env_allowlist_entry, rewrite_env_content, validate_env_value};

    #[test]
    fn rewrite_does_not_drop_prefix_sibling_keys() {
        // Regression: rewriting AEGIS_ML_V2 must NOT drop AEGIS_ML_V2_KIND,
        // which shares the "AEGIS_ML_V2" prefix.
        let before = "AEGIS_ML_V2=1\nAEGIS_ML_V2_KIND=gbm\n# comment\nAEGIS_ARSENAL=0\n";
        let after = rewrite_env_content(before, "AEGIS_ML_V2", Some("0"));
        assert!(
            after.contains("AEGIS_ML_V2_KIND=gbm"),
            "sibling key dropped: {after:?}"
        );
        assert!(
            after.contains("AEGIS_ML_V2=0"),
            "target key not updated: {after:?}"
        );
        assert!(after.contains("# comment"), "comment not preserved");
        assert!(after.contains("AEGIS_ARSENAL=0"), "unrelated key dropped");
        // Exactly one AEGIS_ML_V2= line (the new one), not a duplicate.
        assert_eq!(after.matches("AEGIS_ML_V2=").count(), 1);
    }

    #[test]
    fn rewrite_unset_removes_only_target() {
        let before = "AEGIS_ML_V2=1\nAEGIS_ML_V2_KIND=gbm\n";
        let after = rewrite_env_content(before, "AEGIS_ML_V2", None);
        assert!(!after.contains("AEGIS_ML_V2=1"));
        assert!(after.contains("AEGIS_ML_V2_KIND=gbm"));
    }

    #[test]
    fn validate_rejects_injection_and_traversal() {
        // newline / control chars
        assert!(validate_env_value("a\nb", EnvKind::Path).is_err());
        // shell metachars
        assert!(validate_env_value("/etc/x;rm", EnvKind::Path).is_err());
        // space (systemd word-split)
        assert!(validate_env_value("/path with space", EnvKind::Path).is_err());
        // relative path
        assert!(validate_env_value("relative/file", EnvKind::Path).is_err());
        // traversal
        assert!(validate_env_value("/a/../../etc/shadow", EnvKind::Path).is_err());
        // bool domain
        assert!(validate_env_value("2", EnvKind::Bool).is_err());
        assert!(validate_env_value("1", EnvKind::Bool).is_ok());
        // enum domain
        assert!(validate_env_value("logistic", EnvKind::Enum(&["logistic", "gbm"])).is_ok());
        assert!(validate_env_value("evil", EnvKind::Enum(&["logistic", "gbm"])).is_err());
    }

    #[test]
    fn validate_accepts_legit_values() {
        // absolute file path, colon-separated list
        assert!(
            validate_env_value(
                "/var/lib/aegis/ja4.csv:/var/lib/aegis/more.csv",
                EnvKind::Path
            )
            .is_ok()
        );
        // Addr: host:port and URL must pass (no absolute-path requirement)
        assert!(validate_env_value("127.0.0.1:3310", EnvKind::Addr).is_ok());
        assert!(validate_env_value("http://127.0.0.1:8080", EnvKind::Addr).is_ok());
        // Secret: opaque token
        assert!(validate_env_value("0xABCDEF1234567890", EnvKind::Secret).is_ok());
    }

    #[test]
    fn allowlist_rejects_dangerous_keys() {
        for k in [
            "LD_PRELOAD",
            "PATH",
            "AEGIS_PINGORA_BIN",
            "RUST_LOG",
            "HOME",
        ] {
            assert!(
                env_allowlist_entry(k).is_none(),
                "{k} must not be in allowlist"
            );
        }
        // Sanity: a known feature flag IS present.
        assert!(env_allowlist_entry("AEGIS_ML_V2").is_some());
    }
}

#[cfg(test)]
mod ml_retrain_tests {
    use super::{MlRetrainRequest, MlRetrainSample, features_v2_from_slice};
    use crate::ddos::ml_score_v2::N_FEATURES_V2;
    use crate::ddos::ml_training::Label;

    fn full_feature_vec() -> Vec<f32> {
        (0..N_FEATURES_V2).map(|i| i as f32).collect()
    }

    #[test]
    fn sample_parses_label_variants() {
        for (s, want) in [
            ("malicious", Label::Malicious),
            ("MALICIOUS", Label::Malicious),
            ("bad", Label::Malicious),
            ("1", Label::Malicious),
            ("benign", Label::Benign),
            ("Benign", Label::Benign),
            ("good", Label::Benign),
            ("0", Label::Benign),
        ] {
            let sample = MlRetrainSample {
                features: full_feature_vec(),
                label: s.to_string(),
            };
            let ls = sample.to_labelled_sample().expect("should parse");
            assert_eq!(ls.label, want, "label {s:?}");
        }
    }

    #[test]
    fn sample_rejects_bad_label() {
        let sample = MlRetrainSample {
            features: full_feature_vec(),
            label: "spicy".to_string(),
        };
        assert!(sample.to_labelled_sample().is_err());
    }

    #[test]
    fn sample_rejects_wrong_feature_count() {
        let sample = MlRetrainSample {
            features: vec![1.0, 2.0, 3.0],
            label: "benign".to_string(),
        };
        let err = sample.to_labelled_sample().unwrap_err();
        assert!(err.contains("exactly"), "err: {err}");
    }

    #[test]
    fn sample_rejects_non_finite_feature() {
        let mut f = full_feature_vec();
        f[5] = f32::NAN;
        let sample = MlRetrainSample {
            features: f,
            label: "benign".to_string(),
        };
        assert!(sample.to_labelled_sample().is_err());
    }

    #[test]
    fn features_from_slice_preserves_order() {
        let v = full_feature_vec();
        let feats = features_v2_from_slice(&v);
        // Round-trip through as_array() must equal the input slice exactly.
        assert_eq!(feats.as_array().to_vec(), v);
    }

    #[test]
    fn request_defaults_when_empty() {
        let req: MlRetrainRequest = serde_json::from_str("{}").unwrap();
        assert!(req.epochs.is_none());
        assert!(req.lr.is_none());
        assert!(req.samples.is_empty());
    }

    #[test]
    fn request_parses_full_body() {
        let v = full_feature_vec();
        let body = serde_json::json!({
            "epochs": 5,
            "lr": 0.25,
            "samples": [ { "features": v, "label": "malicious" } ],
        })
        .to_string();
        let req: MlRetrainRequest = serde_json::from_str(&body).unwrap();
        assert_eq!(req.epochs, Some(5));
        assert_eq!(req.lr, Some(0.25));
        assert_eq!(req.samples.len(), 1);
        assert!(req.samples[0].to_labelled_sample().is_ok());
    }
}
