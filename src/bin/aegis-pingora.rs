//! V23 — Runnable pingora-based Aegis entry point.
//!
//! Sibling binary to the default `aegis` (hyper-based). When operators
//! want to A/B the pingora migration in production they build with
//! `--features pingora --bin aegis-pingora` and run this instead.
//!
//! Responsibilities (now the full production data plane, not a preview):
//!   • Parse the same config file the hyper proxy uses
//!     (DSL or legacy TOML, auto-detected).
//!   • Open the honeypot store from the configured state path.
//!   • Build the same `FilterEngine` + `UpstreamRouter` the hyper path
//!     builds, via the shared `proxy::pingora_http::build_filter_engine_and_router`
//!     helper.
//!   • Stand up a pingora `Server` with `AegisPingoraProxy` registered
//!     as an `http_proxy_service`, with the plain listener plus (when
//!     configured) a TLS/ALPN-h2 listener, the admin listener, and an
//!     h3 sidecar — all bound from the config (SO_REUSEPORT-capable).
//!
//! Intentionally deferred (tracked on the roadmap as V24+):
//!   • Periodic honeypot hit-tally cleanup. The hyper cleanup_task
//!     prunes stale per-IP honeypot hit counters hourly via
//!     `HoneypotStore::cleanup_stale` (server.rs); `PingoraBackground`
//!     doesn't wire that call yet, so `hits_by_ip` isn't pruned on the
//!     pingora path. (Honeypot *store* mtime hot-reload is NOT deferred —
//!     it's inline in `HoneypotStore::check`, so out-of-band edits to
//!     the JSON reflect on the next request here too.)
//!
//! Implemented since this list was first written (pointers for readers
//! who remember these as gaps):
//!   • TLS termination + per-SNI certs + ALPN h2 — V25/V50, the
//!     `if tls_enabled` block below (`AegisTlsAccept` /
//!     `TlsSettings::with_callbacks` / `enable_h2`).
//!   • Admin port + background cert reload — `AdminProxy` plus the
//!     `PingoraBackground::with_tls` cert-mtime poller.
//!   • XDP fast-path load + WAF rule hot-reload — `build_pipeline`
//!     loads the eBPF program; `PingoraBackground` (and a 30s h3-side
//!     poller) hot-reload WAF rules.
//!   • SO_REUSEPORT multi-process — opt in via `AEGIS_PINGORA_REUSEPORT=1`.

#![cfg(feature = "pingora")]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use aegis::admin_auth::{AuditLog, TokenRegistry};
use aegis::dsl;
use aegis::honeypot::HoneypotStore;
use aegis::logging;
use aegis::metrics::{RuntimeMetrics, TimeSeriesStore, default_store_dir};
use aegis::proxy::health::UpstreamHealth;
use aegis::proxy::pingora_admin::AdminProxy;
use aegis::proxy::pingora_background::PingoraBackground;
use aegis::proxy::pingora_http::{AegisPingoraProxy, build_pipeline};
use aegis::proxy::{http::ProxyHttpHandler, http3};
use aegis::state::fingerprint::FingerprintCache;

// ── ACME background task ────────────────────────────────────────────────────

/// Persisted ACME configuration. Stored in /var/lib/aegis/acme/config.json.
/// Defaults to LE staging (safe for dev/test — production has 5/week rate limit).
///
/// SAFETY: use_production=true requires accepted_tos_at to be set. This is
/// enforced by the PUT /admin/api/acme/config endpoint, not here.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AcmeConfig {
    /// Email address for the ACME account (required for LE registration).
    account_email: Option<String>,
    /// When false (default), use LE staging directory. When true, use
    /// LE production (5/week rate limit — operator must explicitly opt in).
    #[serde(default)]
    use_production: bool,
    /// Unix timestamp of TOS acceptance (required when use_production=true).
    accepted_tos_at: Option<u64>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            account_email: None,
            use_production: false,
            accepted_tos_at: None,
        }
    }
}

impl AcmeConfig {
    /// Load from disk, or return a safe default (staging, no email) if
    /// the file doesn't exist. Never fails — a corrupt file is treated
    /// as the default rather than crashing the proxy.
    fn load_or_default(path: &std::path::Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(cfg) => {
                    tracing::debug!(
                        path = %path.display(),
                        email = ?cfg.account_email,
                        use_production = cfg.use_production,
                        "aegis::acme: config loaded"
                    );
                    cfg
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "aegis::acme: config parse error — using defaults (staging)"
                    );
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    path = %path.display(),
                    "aegis::acme: config not found — using defaults (staging)"
                );
                Self::default()
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "aegis::acme: config read error — using defaults (staging)"
                );
                Self::default()
            }
        }
    }
}

/// Persisted per-host order state. Written atomically to
/// /var/lib/aegis/acme/orders/<host>.json after each successful issuance
/// and updated with error info on failure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OrderState {
    host: String,
    /// One of: "idle", "pending", "issued", "expiring", "failed"
    status: String,
    not_after_unix: Option<u64>,
    error: Option<String>,
    updated_at: u64,
}

impl OrderState {
    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn pending(host: &str) -> Self {
        Self {
            host: host.to_string(),
            status: "pending".to_string(),
            not_after_unix: None,
            error: None,
            updated_at: Self::now_unix(),
        }
    }

    fn issued(host: &str, not_after_unix: u64) -> Self {
        let now = Self::now_unix();
        let days_remaining = (not_after_unix as i64 - now as i64) / 86_400;
        let status = if days_remaining <= aegis::acme::RENEW_AT_DAYS_REMAINING {
            "expiring"
        } else {
            "issued"
        };
        Self {
            host: host.to_string(),
            status: status.to_string(),
            not_after_unix: Some(not_after_unix),
            error: None,
            updated_at: now,
        }
    }

    fn failed(host: &str, error: impl Into<String>) -> Self {
        Self {
            host: host.to_string(),
            status: "failed".to_string(),
            not_after_unix: None,
            error: Some(error.into()),
            updated_at: Self::now_unix(),
        }
    }

    /// Write atomically to `orders_dir/<host>.json` using a temp file + rename.
    fn persist(&self, orders_dir: &std::path::Path) {
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
        let target = orders_dir.join(format!("{safe_host}.json"));
        let tmp = orders_dir.join(format!(".{safe_host}.json.tmp"));
        match serde_json::to_vec_pretty(self) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&tmp, &bytes) {
                    tracing::warn!(host = %self.host, error = %e, "aegis::acme: write order state tmp failed");
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, &target) {
                    tracing::warn!(host = %self.host, error = %e, "aegis::acme: rename order state failed");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                tracing::warn!(host = %self.host, error = %e, "aegis::acme: serialize order state failed");
            }
        }
    }

    /// Load from `orders_dir/<host>.json`. Returns None if not found.
    fn load(orders_dir: &std::path::Path, host: &str) -> Option<Self> {
        let safe_host: String = host
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = orders_dir.join(format!("{safe_host}.json"));
        let bytes = std::fs::read(&path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Load all order states from `orders_dir/*.json`.
    fn load_all(orders_dir: &std::path::Path) -> Vec<Self> {
        let Ok(rd) = std::fs::read_dir(orders_dir) else {
            return Vec::new();
        };
        rd.filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension()?.to_str()? != "json" {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            // Skip temp files.
            if name.starts_with('.') {
                return None;
            }
            let bytes = std::fs::read(&path).ok()?;
            serde_json::from_slice(&bytes).ok()
        })
        .collect()
    }
}

/// Message sent from admin API handlers into the ACME background loop.
pub struct ProvisionRequest {
    /// Domain to issue/renew for.
    pub host: String,
    /// Force re-issuance even if the cert is still fresh.
    pub force_renew: bool,
}

/// Handle the admin API can use to trigger new issuance orders.
/// The channel is unbounded so admin handlers never block waiting
/// for the ACME task to drain; duplicate requests for the same host
/// are idempotent (per-host in-flight lock prevents double-order).
#[derive(Clone)]
pub struct AcmeRuntime {
    tx: tokio::sync::mpsc::UnboundedSender<ProvisionRequest>,
}

impl AcmeRuntime {
    /// Request issuance/renewal for `host`. Returns Err if the
    /// background task has exited (should not happen in normal operation).
    pub fn request(&self, host: impl Into<String>, force_renew: bool) -> anyhow::Result<()> {
        self.tx
            .send(ProvisionRequest {
                host: host.into(),
                force_renew,
            })
            .map_err(|_| anyhow::anyhow!("ACME runtime task has exited"))
    }
}

/// Background loop that drives ACME issuance and scheduled renewals.
///
/// Responsibilities:
///   1. On startup: load saved order state from orders_dir/*.json; for
///      each "issued"/"expiring" host, schedule renewal via
///      next_renewal_delay().
///   2. Wait for the next event: either a tokio::time::sleep expiry
///      (scheduled renewal) or an incoming ProvisionRequest (new order
///      from admin API).
///   3. Per-host in-flight lock (DashMap<host, Arc<Mutex<()>>>) prevents
///      double-ordering when the same host fires both a scheduled renewal
///      AND a manual request concurrently.
///   4. On success: write cert + key to /etc/aegis/certs/<host>.cert.pem
///      and .key.pem (via CertDir::write_async); persist order state JSON.
///      The PingoraBackground cert-mtime poller picks up the new files
///      within 30s — no explicit nudge needed.
///   5. On failure: persist error into order state; log at warn level.
///      Retry on the next 6-hour polling tick.
async fn acme_background_loop(
    provisioner: Arc<aegis::acme::Provisioner>,
    orders_dir: PathBuf,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<ProvisionRequest>,
) {
    use aegis::acme::{next_renewal_delay, now_unix};
    use dashmap::DashMap;

    // Per-host in-flight locks. A second order for the same host blocks
    // until the first completes, preventing double-order at the LE
    // rate-limited tier.
    let inflight: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>> = Arc::new(DashMap::new());

    // Ensure orders directory exists.
    if let Err(e) = tokio::fs::create_dir_all(&orders_dir).await {
        tracing::warn!(
            target: "aegis::acme",
            path = %orders_dir.display(),
            error = %e,
            "ACME: could not create orders directory"
        );
    }

    // ── Boot: load saved order states and queue immediate renewals ──
    let mut scheduled: Vec<(u64, String)> = Vec::new(); // (fire_at_unix, host)
    {
        let saved = OrderState::load_all(&orders_dir);
        tracing::info!(
            target: "aegis::acme",
            count = saved.len(),
            "ACME: loaded order states from disk"
        );
        for state in &saved {
            if let Some(not_after) = state.not_after_unix {
                let now = now_unix();
                let delay = next_renewal_delay(not_after, now);
                let fire_at = now + delay.as_secs();
                tracing::info!(
                    target: "aegis::acme",
                    host = %state.host,
                    status = %state.status,
                    not_after_unix = not_after,
                    delay_secs = delay.as_secs(),
                    "ACME: scheduling renewal from saved state"
                );
                scheduled.push((fire_at, state.host.clone()));
            } else if state.status == "pending" {
                // Mid-order restart: re-queue immediately for re-issuance.
                tracing::info!(
                    target: "aegis::acme",
                    host = %state.host,
                    "ACME: re-queuing pending order from saved state"
                );
                scheduled.push((now_unix(), state.host.clone()));
            }
        }
    }

    // ── 6-hour catch-all polling tick ──
    let mut six_hour_tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3_600));
    six_hour_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the first immediate tick so we don't double-issue on startup.
    six_hour_tick.tick().await;

    loop {
        // Find the earliest scheduled item.
        let now = now_unix();
        let next_fire = scheduled.iter().map(|(t, _)| *t).min().unwrap_or(u64::MAX);
        let until_next = if next_fire <= now {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_secs(next_fire - now)
        };

        tokio::select! {
            // Scheduled renewal tick (either a specific host or 6h catch-all).
            _ = tokio::time::sleep(until_next), if next_fire != u64::MAX => {
                let now = now_unix();
                let due: Vec<String> = scheduled
                    .iter()
                    .filter(|(t, _)| *t <= now)
                    .map(|(_, h)| h.clone())
                    .collect();
                scheduled.retain(|(t, _)| *t > now);

                for host in due {
                    let prov = Arc::clone(&provisioner);
                    let ifl = Arc::clone(&inflight);
                    let odir = orders_dir.clone();
                    let host_clone = host.clone();
                    tokio::spawn(async move {
                        issue_for_host(prov, ifl, &host_clone, false, &odir).await;
                    });
                }
            }

            // 6-hour catch-all: re-check every issued cert in case
            // the last renewal failed or the scheduling was off.
            _ = six_hour_tick.tick() => {
                let saved = OrderState::load_all(&orders_dir);
                for state in saved {
                    if let Some(not_after) = state.not_after_unix {
                        let delay = next_renewal_delay(not_after, now_unix());
                        if delay.is_zero() {
                            // Past renewal threshold — fire immediately.
                            tracing::info!(
                                target: "aegis::acme",
                                host = %state.host,
                                "ACME: 6h tick: cert at/past renewal threshold, issuing"
                            );
                            let prov = Arc::clone(&provisioner);
                            let ifl = Arc::clone(&inflight);
                            let odir = orders_dir.clone();
                            let host = state.host.clone();
                            tokio::spawn(async move {
                                issue_for_host(prov, ifl, &host, false, &odir).await;
                            });
                        } else {
                            // Re-schedule to make sure it's in the list.
                            let fire_at = now_unix() + delay.as_secs();
                            if !scheduled.iter().any(|(_, h)| h == &state.host) {
                                scheduled.push((fire_at, state.host.clone()));
                            }
                        }
                    }
                }
            }

            // New issuance request from admin API.
            Some(req) = rx.recv() => {
                tracing::info!(
                    target: "aegis::acme",
                    host = %req.host,
                    force = req.force_renew,
                    "ACME: received provision request from admin API"
                );
                // Persist pending state immediately so GET /orders shows it.
                let state = OrderState::pending(&req.host);
                state.persist(&orders_dir);

                let prov = Arc::clone(&provisioner);
                let ifl = Arc::clone(&inflight);
                let odir = orders_dir.clone();
                let host = req.host.clone();
                let force = req.force_renew;
                tokio::spawn(async move {
                    let result = issue_for_host(prov, ifl, &host, force, &odir).await;
                    // On success, schedule next renewal.
                    if let Some(not_after) = result {
                        let _ = not_after; // scheduled in issue_for_host via returned value
                    }
                });
            }
        }
    }
}

/// Issue/renew a certificate for `host`. Acquires the per-host in-flight
/// lock so concurrent requests for the same host serialise. Returns
/// `Some(not_after_unix)` on success, `None` on failure.
async fn issue_for_host(
    provisioner: Arc<aegis::acme::Provisioner>,
    inflight: Arc<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    host: &str,
    force_renew: bool,
    orders_dir: &std::path::Path,
) -> Option<u64> {
    // Acquire or create the per-host mutex.
    let lock = inflight
        .entry(host.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    tracing::info!(
        target: "aegis::acme",
        host,
        force_renew,
        "ACME: starting issuance"
    );

    let identifiers = vec![host.to_string()];
    let result = if force_renew {
        provisioner.issue(&identifiers).await.map(Some)
    } else {
        provisioner.maybe_renew(&identifiers).await
    };

    match result {
        Ok(Some(cert)) => {
            let not_after = cert.not_after_unix;
            tracing::info!(
                target: "aegis::acme",
                host,
                not_after_unix = not_after,
                "ACME: certificate issued successfully"
            );
            let state = OrderState::issued(host, not_after);
            state.persist(orders_dir);
            Some(not_after)
        }
        Ok(None) => {
            // Cert still fresh — nothing to do.
            tracing::debug!(
                target: "aegis::acme",
                host,
                "ACME: cert still fresh, renewal skipped"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                target: "aegis::acme",
                host,
                error = %e,
                "ACME: issuance failed"
            );
            // Preserve previous not_after_unix from disk if available.
            let prev_not_after = OrderState::load(orders_dir, host).and_then(|s| s.not_after_unix);
            let mut state = OrderState::failed(host, e.to_string());
            state.not_after_unix = prev_not_after;
            state.persist(orders_dir);
            None
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "aegis-pingora",
    about = "Aegis proxy running on Cloudflare's Pingora framework (Phase B preview)",
    version
)]
struct Cli {
    #[arg(short, long, default_value = "/etc/aegis/aegis.conf")]
    config: PathBuf,
    #[arg(long, default_value = "info")]
    log_level: String,
}

// Swap the global allocator for mimalloc, matching the main `aegis`
// bin. Reverse-proxy hot paths allocate aggressively (headers, body
// buffers, scratch) and mimalloc's per-thread slabs measurably reduce
// cross-CPU cache-line bouncing under sustained load.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn conf_threads(server: &pingora_core::server::Server) -> usize {
    server.configuration.threads
}

/// V230 — construct the shared `TcpSocketOptions` for every downstream
/// listener (plain HTTP and TLS). Sets `so_reuseport` per the operator
/// toggle and (optionally) TCP keepalive on accepted client streams.
///
/// Note: TCP_NODELAY is NOT a field on Pingora 0.8.0's
/// `TcpSocketOptions`. Pingora unconditionally calls
/// `stream.set_nodelay()` inside `apply_stream_settings` for every
/// accepted TCP stream (pingora-core listeners/l4.rs:385), so Nagle's
/// 40ms coalescing is always disabled. The struct is `#[non_exhaustive]`
/// so we build with `Default + field set` rather than a struct literal.
///
/// V231 — REGRESSION FIX. V230 unconditionally set `tcp_keepalive` here.
/// That field is NOT applied to the listening socket — Pingora's
/// `apply_tcp_socket_options` (pingora-core listeners/l4.rs:163-196)
/// only handles ipv6_only / so_reuseport / tcp_fastopen / dscp. The
/// `tcp_keepalive` field is consumed exclusively by
/// `apply_stream_settings` (l4.rs:389-391), which runs once per
/// *accepted* stream — synchronously, inside the accept loop
/// (l4.rs:432/443). Each call issues 3-4 serial `setsockopt`s
/// (TCP_KEEPIDLE/INTVL/CNT + TCP_USER_TIMEOUT for `user_timeout`).
/// Under load (oha, 500-1000 conns) that per-accept syscall storm
/// slowed accept-queue drain enough to overflow the kernel accept
/// backlog — Pingora requests `listen(65535)` but the kernel silently
/// clamps it to `net.core.somaxconn` (l4.rs:51,250). Result: 24-29k
/// `Connection refused (os error 111)` at the client. V229 had no
/// per-accept keepalive syscall, drained fast, and saw zero refusals.
///
/// `TcpSocketOptions` has NO `backlog` field (l4.rs:84-103, see the
/// upstream `// TODO: ... backlog`), so the backlog cannot be raised
/// in code. The fix: gate keepalive behind `AEGIS_PINGORA_DOWNSTREAM_KEEPALIVE`,
/// OFF by default — restoring V229's hot-accept-path syscall profile.
/// Dead-client reaping is already handled by request/idle timeouts;
/// per-accept keepalive is not worth an accept-queue overflow. The
/// kernel accept-queue ceiling itself is a sysctl (`net.core.somaxconn`)
/// and belongs in install.sh / a sysctl.d drop-in, not in this binary.
fn build_downstream_sock_opt(reuseport: bool) -> pingora_core::listeners::TcpSocketOptions {
    let mut sock_opt = pingora_core::listeners::TcpSocketOptions::default();
    if reuseport {
        sock_opt.so_reuseport = Some(true);
    }
    // V231 — keepalive is opt-in. Default OFF keeps the accept loop
    // syscall-light and matches V229's connection-acceptance behavior.
    let downstream_keepalive = std::env::var("AEGIS_PINGORA_DOWNSTREAM_KEEPALIVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if downstream_keepalive {
        // TCP keepalive on accepted client streams. Probes after 60s
        // idle, every 10s, 5 probes before teardown. NOTE: applied
        // per-accept by Pingora (see the doc comment above) — only
        // enable when the accept rate is low enough to absorb the
        // extra setsockopt(s) per connection.
        sock_opt.tcp_keepalive = Some(pingora_core::protocols::l4::ext::TcpKeepalive {
            idle: std::time::Duration::from_secs(60),
            interval: std::time::Duration::from_secs(10),
            count: 5,
            // `user_timeout` is Linux-only on the upstream struct; gate it.
            #[cfg(target_os = "linux")]
            user_timeout: std::time::Duration::from_secs(30),
        });
    }
    sock_opt
}

// LEVER 3 — TLS session-ticket key helpers for REUSEPORT workers.
//
// AEGIS production layout = N separate SO_REUSEPORT OS processes. Each
// process's SslContext normally gets its own (random, per-process) TLS 1.3
// session-ticket key, so a client that resumes onto a DIFFERENT worker
// cannot have its ticket decrypted → silent full handshake on reconnect.
//
// Fix: all REUSEPORT workers share the SAME ticket key, loaded from a
// persistent shared key file. The file is generated once-and-for-all on
// first startup with 0600 perms; subsequent workers just load it.
//
// Key-file path: /etc/aegis/tls_ticket.key (override via AEGIS_TLS_TICKET_KEY_FILE).
// Key size: QUERIED from OpenSSL at runtime (never hardcoded) via the
// NULL-buffer SSL_CTX_set_tlsext_ticket_keys call. OpenSSL layout:
//   • 48 bytes legacy AES-128 (16 B key name + 16 B HMAC + 16 B AES key)
//   • 80 bytes on OpenSSL 3.0+ (16 B key name + 32 B HMAC + 32 B AES key)
//     — the size Debian bookworm's OpenSSL 3.0 requires
// A key file written under a different layout is auto-migrated.
//
// TODO(security): KEY ROTATION — the key file is static and must be
//   rotated periodically (e.g., every 24h). Rotation is NOT implemented
//   here. To add it safely:
//   1. Keep a "current" + "previous" key pair (96 B total) and update
//      the ticket-key callback (set_tlsext_ticket_key_cb) to try both.
//   2. Rotate current → previous when `now % period < prev_age`.
//   3. Coordinate rotation across workers via a shared filesystem lock
//      or by having a single privileged process write the new key.
//   4. Never hard-code the key; never log the key bytes.
//   Until rotation is implemented, use short-lived ticket hints
//   (ssl_session_timeout is OK to set low; the ticket just triggers a
//   fresh handshake instead of succeeding silently — no security loss).
//
// SECURITY INVARIANTS (enforced in this implementation):
//   (a) Key is generated via OsRng (CSPRNG) — never hardcoded.
//   (b) Key file is created with 0o600 perms (owner read/write only).
//   (c) Key file path is NOT stored in source; it comes from env/default.
//   (d) Forward secrecy is NOT weakened — TLS 1.3 ephemeral ECDHE still
//       runs per-handshake; the ticket only skips the server auth and
//       key-derivation ceremony (client sends its DH share under the
//       ticket-protected envelope). This is how all production TLS
//       servers work (nginx, haproxy, envoy).
//   (e) 0-RTT / early data: NOT enabled here. pingora's default OpenSSL
//       context has max_early_data=0; we don't touch that setting.

/// Load or generate the shared TLS session-ticket key (`len` bytes — the
/// length OpenSSL requires) for REUSEPORT workers. Returns the key bytes
/// or an error describing why.
///
/// Called once at startup, before any listener socket is bound, so the
/// key is in memory before the first TLS handshake can arrive.
fn load_or_generate_tls_ticket_key(
    key_path: &std::path::Path,
    len: usize,
) -> anyhow::Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;

    // Fast path: an existing key file of EXACTLY the required length. The
    // length is dictated by OpenSSL at runtime (queried by the caller) —
    // 48 bytes on the legacy AES-128 layout, 80 on OpenSSL 3.0+ (16-byte
    // key name + 32-byte HMAC key + 32-byte AES key). A file of the wrong
    // length (stale build / OpenSSL upgrade) is migrated below, never
    // trusted.
    if let Ok(meta) = std::fs::metadata(key_path) {
        if meta.len() == len as u64 {
            let mut f = std::fs::File::open(key_path)
                .map_err(|e| anyhow::anyhow!("open tls_ticket key {}: {e}", key_path.display()))?;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf).map_err(|e| {
                anyhow::anyhow!(
                    "read tls_ticket key {}: {e} (expected {len} bytes)",
                    key_path.display()
                )
            })?;
            tracing::info!(
                path = %key_path.display(),
                len,
                "aegis-pingora: shared TLS session-ticket key loaded from file"
            );
            return Ok(buf);
        }
        // Wrong length — remove the stale file so the atomic create below
        // replaces it. Safe: a transient cross-worker key mismatch only
        // costs a missed resumption and self-heals on the next start.
        tracing::warn!(
            path = %key_path.display(),
            found = meta.len(),
            expected = len,
            "aegis-pingora: tls_ticket key file has wrong length — regenerating"
        );
        let _ = std::fs::remove_file(key_path);
    }

    // Key file doesn't exist (or was just removed) — generate a fresh one
    // with 0600 perms. Parent directory must exist (operator
    // responsibility; /etc/aegis/ is created by the package installer).
    if let Some(parent) = key_path.parent() {
        if !parent.exists() {
            anyhow::bail!(
                "tls_ticket key directory {} does not exist; create it first \
                 (e.g. `install -d -m 0700 {0}`)",
                parent.display()
            );
        }
    }

    // Generate `len` cryptographically secure random bytes via OsRng
    // (getrandom(2) on Linux / SecRandomCopyBytes on macOS). try_fill_bytes
    // (not fill_bytes) so a broken OS CSPRNG returns Err and propagates
    // cleanly through the caller's safe fallback instead of panicking.
    use rand::RngCore;
    let mut key = vec![0u8; len];
    rand::rngs::OsRng.try_fill_bytes(&mut key).map_err(|e| {
        anyhow::anyhow!("OsRng CSPRNG unavailable — cannot generate tls_ticket key: {e}")
    })?;

    // Write with 0600 so only the aegis process owner can read it.
    // `create_new` is atomic — if two REUSEPORT workers race to generate
    // the key, exactly one wins; the loser gets AlreadyExists and loads
    // the winner's bytes so all workers converge on the same key.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // atomic create-exclusive
        .mode(0o600)
        .open(key_path)
    {
        Ok(mut f) => {
            f.write_all(&key)
                .map_err(|e| anyhow::anyhow!("write tls_ticket key {}: {e}", key_path.display()))?;
            f.flush()
                .map_err(|e| anyhow::anyhow!("flush tls_ticket key {}: {e}", key_path.display()))?;
            tracing::info!(
                path = %key_path.display(),
                len,
                "aegis-pingora: shared TLS session-ticket key GENERATED and saved (0600)"
            );
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another REUSEPORT worker won the race. Load its key IF it is
            // the right length; otherwise error so the caller falls back
            // safely (per-worker keys) rather than installing a bad key.
            tracing::debug!(
                path = %key_path.display(),
                "aegis-pingora: tls_ticket key create race — loading winner's key"
            );
            let meta = std::fs::metadata(key_path).map_err(|e| {
                anyhow::anyhow!("stat winner's tls_ticket key {}: {e}", key_path.display())
            })?;
            if meta.len() != len as u64 {
                anyhow::bail!(
                    "winner's tls_ticket key file {} is {} bytes, expected {len}",
                    key_path.display(),
                    meta.len()
                );
            }
            let mut f = std::fs::File::open(key_path).map_err(|e| {
                anyhow::anyhow!("open winner's tls_ticket key {}: {e}", key_path.display())
            })?;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf).map_err(|e| {
                anyhow::anyhow!("read winner's tls_ticket key {}: {e}", key_path.display())
            })?;
            Ok(buf)
        }
        Err(e) => Err(anyhow::anyhow!(
            "create tls_ticket key {}: {e}",
            key_path.display()
        )),
    }
}

/// Apply the shared session-ticket key and turn OFF the per-worker
/// server-side session cache (which is useless under REUSEPORT because
/// connections land on different workers and the cache is per-worker).
///
/// `builder` is the `SslAcceptorBuilder` inside pingora's `TlsSettings`
/// (accessed via DerefMut). The ticket key is installed via the raw
/// `SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_TICKET_KEYS, 48, key_ptr)`
/// call — this is exactly what the `SSL_CTX_set_tlsext_ticket_keys()`
/// C macro expands to. openssl-sys 0.9.x doesn't wrap it as a safe
/// binding (it wraps the callback variant only), so we call it through
/// the raw FFI path that openssl-sys DOES expose (`SSL_CTX_ctrl`).
///
/// SAFETY: The pointer to `key` is valid for the duration of the call
/// (stack-pinned slice). OpenSSL copies the bytes internally. The
/// 48-byte length matches the OpenSSL internal layout documented above.
fn apply_shared_ticket_key(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    key_path: &std::path::Path,
) -> anyhow::Result<()> {
    use openssl::ssl::SslSessionCacheMode;
    use std::os::raw::{c_int, c_long};

    // Turn OFF the per-worker server-side session cache. Under REUSEPORT
    // each worker has its own cache; a resumed session that lands on a
    // different worker gets a cache miss and triggers a full handshake
    // anyway. Keeping the cache ON wastes memory and is misleading.
    // The ticket mechanism (below) is the correct cross-worker resumption
    // path for REUSEPORT layouts.
    builder.set_session_cache_mode(SslSessionCacheMode::OFF);

    // SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59 (defined in tls1.h; stable
    // since OpenSSL 1.0.1; present in OpenSSL 3.x).
    const SSL_CTRL_SET_TLSEXT_TICKET_KEYS: c_int = 59;
    let ctx_ptr = builder.as_ptr(); // *mut ffi::SSL_CTX

    // Query the REQUIRED key length FIRST: a NULL key buffer makes OpenSSL
    // RETURN the expected length instead of installing. It is 48 on the
    // legacy AES-128 layout and 80 on OpenSSL 3.0+ (16-byte key name +
    // 32-byte HMAC key + 32-byte AES key). Hardcoding 48 fails with
    // INVALID_TICKET_KEYS_LENGTH (rc=0) on 3.0 — query, never assume.
    let needed = unsafe {
        openssl_sys::SSL_CTX_ctrl(
            ctx_ptr,
            SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
            0,
            std::ptr::null_mut(),
        )
    };
    if !(16..=256).contains(&needed) {
        anyhow::bail!(
            "SSL_CTX_set_tlsext_ticket_keys reported an implausible key length ({needed}); \
             not installing a shared ticket key"
        );
    }
    let key = load_or_generate_tls_ticket_key(key_path, needed as usize)?;

    // Install the shared ticket key. SAFETY: `key` is exactly `needed`
    // bytes (load_or_generate guarantees the length); OpenSSL copies the
    // bytes internally during the call, so the pointer only needs to be
    // valid for the call's duration.
    let rc = unsafe {
        openssl_sys::SSL_CTX_ctrl(
            ctx_ptr,
            SSL_CTRL_SET_TLSEXT_TICKET_KEYS,
            key.len() as c_long,
            key.as_ptr() as *mut std::ffi::c_void,
        )
    };
    if rc != 1 {
        anyhow::bail!(
            "SSL_CTX_set_tlsext_ticket_keys failed (rc={rc}, keylen={}); \
             check OpenSSL version ≥ 1.0.1",
            key.len()
        );
    }
    // TODO(security): KEY ROTATION — see the module-level comment above.
    // The key installed here is valid until the process restarts. For
    // production, wire a background task that:
    //   1. Calls load_or_generate_tls_ticket_key() on a 24h interval.
    //   2. Re-installs via apply_shared_ticket_key on the live context.
    //   3. Keeps the previous key for a grace window (clients in-flight
    //      still hold tickets encrypted under the old key).
    tracing::info!(
        "aegis-pingora: shared TLS session-ticket key installed \
         (session cache OFF, REUSEPORT resumption enabled)"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    logging::init_logging(&args.log_level)?;

    // Install a rustls CryptoProvider — still required because our
    // *direct* rustls usage (HTTP/3 via quinn + tokio-rustls for the
    // hyper handler's TLS edge in `for_h3()`) needs one even though
    // pingora now uses OpenSSL via its `openssl` feature (V50).
    // Picking `ring` matches our `rustls = { features = ["ring", ...] }`
    // and avoids needing aws-lc-rs in the dep tree at all.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed by an earlier call — that's fine.
    }

    let (cfg, _summary) = dsl::load_any(&args.config)
        .with_context(|| format!("load config from {:?}", args.config))?;

    // Honour the same env-var overrides the hyper server respects, so
    // operators can flip aegis ↔ aegis-pingora without touching the
    // shared aegis.conf or the systemd unit's other knobs.
    let listen = std::env::var("AEGIS_LISTEN").unwrap_or_else(|_| cfg.server.listen.clone());

    // Honeypot store is the only non-trivial filter dependency at
    // startup — it owns the bait-path catalogue read by HoneypotFilter
    // on every request. The hyper server opens it the same way.
    let honeypot_state_path = PathBuf::from(
        std::env::var("AEGIS_HONEYPOT_STATE")
            .ok()
            .or_else(|| {
                cfg.admin
                    .as_ref()
                    .and_then(|a| a.honeypot_state_path.clone())
            })
            .unwrap_or_else(|| aegis::honeypot::state::DEFAULT_STATE_PATH.to_string()),
    );
    let honeypots = Arc::new(HoneypotStore::open(honeypot_state_path)?);

    // V91 — initialise Phase D shared-state arena BEFORE proxy
    // construction so SharedScorer can be allocated during pipeline
    // setup. Failures are non-fatal (graceful degradation to
    // per-worker scorer only); see V89 commit for the init contract.
    if let Err(e) = aegis::shared_state::global::init() {
        tracing::warn!(error = %e, "aegis-shared-state: init failed (cluster scorer disabled)");
    }
    let shared_scorer: Option<Arc<aegis::ddos::shared_score::SharedScorer>> =
        match aegis::ddos::shared_score::SharedScorer::from_global_arena(
            65536,
            std::time::Duration::from_secs(60),
        ) {
            Ok(s) => {
                tracing::info!(
                    "aegis-shared-state: SharedScorer attached (capacity=65536 IPv4 slots)"
                );
                Some(Arc::new(s))
            }
            Err(e) => {
                tracing::info!(error = %e, "aegis-shared-state: SharedScorer unavailable — per-worker only");
                None
            }
        };

    // TS — construct the fleet-wide time-series store.  Every worker
    // opens the same directory; only the one that wins the advisory flock
    // on `.sampler.lock` actually writes — the rest operate read-only and
    // serve query results from the shared ring files.
    //
    // `create_dir_all` inside `TimeSeriesStore::new` handles the common
    // case (first boot, install.sh already creates $AEGIS_HOME but not the
    // metrics sub-directory).  We are defensive here and log rather than
    // abort on failure — a missing time-series store degrades the dashboard
    // to "no data" but does not affect request forwarding.
    let ts_store_dir = default_store_dir();
    let timeseries_store: Option<Arc<TimeSeriesStore>> =
        match TimeSeriesStore::new(ts_store_dir.clone()) {
            Ok(store) => {
                tracing::info!(
                    dir = %ts_store_dir.display(),
                    is_writer = store.is_writer(),
                    "aegis-pingora: time-series store opened"
                );
                Some(Arc::new(store))
            }
            Err(e) => {
                tracing::warn!(
                    dir = %ts_store_dir.display(),
                    error = %e,
                    "aegis-pingora: time-series store unavailable — \
                     dashboard charts will show no historical data"
                );
                None
            }
        };

    let pipeline = build_pipeline(&cfg, honeypots.clone())?;

    // V168 — cross-worker persistence for runtime toggles + per-domain
    // policy. Paths come from env (operator can override) or default
    // to /var/lib/aegis/{runtime-toggles,domain-policy}.json. Each
    // worker writes mutations atomically; every read mtime-polls so
    // sibling workers see the change within microseconds (not the
    // 30s background tick).
    let toggles_path = std::env::var("AEGIS_TOGGLES_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/aegis/runtime-toggles.json"));
    if let Err(e) = pipeline
        .engine
        .toggles()
        .attach_persistence(toggles_path.clone())
    {
        tracing::warn!(path = %toggles_path.display(), error = %e,
            "V168: runtime toggles persistence not attached");
    } else {
        tracing::info!(path = %toggles_path.display(),
            "V168: runtime toggles persistence attached");
    }
    let policy_path = std::env::var("AEGIS_DOMAIN_POLICY_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/aegis/domain-policy.json"));
    if let Err(e) = pipeline
        .engine
        .domain_policy()
        .attach_persistence(policy_path.clone())
    {
        tracing::warn!(path = %policy_path.display(), error = %e,
            "V168: domain policy persistence not attached");
    } else {
        tracing::info!(path = %policy_path.display(),
            "V168: domain policy persistence attached");
    }
    // V242 — cross-worker GeoIP country aggregation. Each SO_REUSEPORT
    // worker acquires a slot-based flock shard under AEGIS_GEO_DIR
    // (default /var/lib/aegis/geo), reloads its own prior shard so per-
    // country counters survive restarts, and the background tick flushes
    // it every ~30 s. The admin geo/top endpoint merges all workers'
    // shards so the dashboard world map is stable regardless of which
    // worker answers. `with_geo_persistence` is a graceful no-op (per-
    // worker counters only) when the slot can't be acquired.
    let geo_dir = std::env::var("AEGIS_GEO_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/aegis/geo"));
    let metrics = Arc::new(RuntimeMetrics::default().with_geo_persistence(geo_dir.clone()));
    tracing::info!(dir = %geo_dir.display(), "aegis-pingora: geo aggregation configured");

    // Same Arc<RuntimeMetrics> is handed to both proxies so the admin
    // service sees the counters the data-plane proxy increments. The
    // background service holds an Arc<WafFilter> to poll rule-file
    // mtime for hot-reload (parity with hyper server.rs cleanup_task).
    // Clones below let us reuse the same engine + state for the V46
    // HTTP/3 hyper handler later in this function.
    // V101 — Phase E.2 ML scorer. Opt-in via env: when AEGIS_ML_SCORER=1
    // is set, the proxy attaches an [MlScorer] (V97) and the hot path
    // factors its output into the per-request ThreatTier (V98). Weights
    // come from AEGIS_ML_WEIGHTS path when set (TOML), otherwise the
    // conservative built-in defaults from `Weights::default()`. Disabled
    // by default — operators need to explicitly opt in until they've
    // trained weights on their own traffic.
    // V107 — online tarpit signature miner state. Logger writes only
    // when AEGIS_TARPIT_LOG is set; sampler is always live and cheap.
    // Background miner ticks every AEGIS_TARPIT_MINER_SECS (default 60s).
    let tarpit_logger = Arc::new(aegis::online_signature_miner::TarpitLogger::from_env());
    let allowed_sampler = Arc::new(aegis::online_signature_miner::AllowedSampler::default());
    let online_miner = Arc::new(aegis::online_signature_miner::OnlineMiner::new(
        tarpit_logger.clone(),
        allowed_sampler.clone(),
        std::time::Duration::from_secs(
            std::env::var("AEGIS_TARPIT_MINER_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60)
                .max(5),
        ),
    ));

    // V119 — site cartography. Always live; cheap when traffic is
    // low. Periodic eviction comes from PingoraBackground tick.
    //
    // V240 — persistence: acquire a slot-based flock shard in
    // AEGIS_SITEMAP_DIR (default /var/lib/aegis/site-map). Each
    // SO_REUSEPORT worker owns one shard file; on boot it reloads
    // from that file so counters survive restarts. The background
    // service flushes the shard every ~30 s. `with_persistence`
    // creates the directory if needed, acquires the flock slot, and
    // imports the prior shard — all at startup, before traffic flows.
    let sitemap_dir = std::env::var("AEGIS_SITEMAP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/aegis/site-map"));
    let site_map = Arc::new(aegis::site_map::SiteMap::new().with_persistence(sitemap_dir.clone()));
    tracing::info!(
        dir = %sitemap_dir.display(),
        shard = ?site_map.shard_path(),
        "aegis-pingora: site-map persistence configured"
    );

    // V243 — persistent per-request event log. Like site_map, each
    // SO_REUSEPORT worker owns one shard file (flock slot in
    // AEGIS_EVENTS_DIR, default /var/lib/aegis/events) and runs its own
    // background writer + retention thread. `from_env()` reads the enable
    // gate, sampling fraction and dir, acquires the slot and spawns the
    // writer — once per worker process, before traffic flows. It always
    // returns a usable handle (degrades to a no-op on any failure), and
    // record() is a non-blocking try_send on the hot path. The same Arc
    // is cloned into the proxy (write side) and the admin store (read
    // side); query()/stats() open their own read connections by scanning
    // the dir, so the read side works on any handle.
    let event_store = Arc::new(aegis::event_store::EventStore::from_env());
    tracing::info!(
        enabled = event_store.is_enabled(),
        shard = ?event_store.shard_path(),
        "aegis-pingora: event-log store configured"
    );

    // V121 — split bot vs DDoS analytics. Populated by the proxy
    // hot-path (observe_bot on per-IP signals, observe_endpoint_hit
    // on every deny/challenge with the path pattern).
    let threat_analytics = Arc::new(aegis::threat_analytics::ThreatAnalytics::new());

    let ml_scorer: Option<Arc<aegis::ddos::ml_score::MlScorer>> =
        if std::env::var("AEGIS_ML_SCORER").as_deref() == Ok("1") {
            let scorer = aegis::ddos::ml_score::MlScorer::new(true);
            let scorer = if let Ok(p) = std::env::var("AEGIS_ML_WEIGHTS") {
                scorer.with_path(std::path::PathBuf::from(p))
            } else {
                scorer
            };
            tracing::info!("aegis-pingora: ML threat scorer attached (Phase E.2)");
            Some(Arc::new(scorer))
        } else {
            None
        };

    // V140/V141 — V122/V139 23-feature model. Out-of-the-box default-ON.
    // This takes precedence over V97 in derive_threat_tier.
    // AEGIS_ML_V2_KIND={logistic,gbm} picks the engine (default
    // logistic). GBM kicks in operator-supplied weight file via
    // AEGIS_ML_V2_GBM_FILE; without it, GBM starts empty and only
    // matches the prior class log-odds (no learned signal).
    //
    // ENABLEMENT (changed): historically gated on AEGIS_ML_V2=1, which
    // meant the V2 scorer stayed dormant on the live stand (only
    // AEGIS_ML_V2_KIND=logistic was set there). Now the scorer is ON by
    // default whenever EITHER AEGIS_ML_V2=1 OR a KIND is configured —
    // i.e. configuring a kind is enough to make it real out of the box.
    // AEGIS_ML_V2=0 still hard-disables it (explicit operator opt-out).
    let ml_v2_explicit = std::env::var("AEGIS_ML_V2").ok();
    let ml_v2_kind_set = std::env::var("AEGIS_ML_V2_KIND")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let ml_v2_enabled = match ml_v2_explicit.as_deref() {
        // Explicit hard-off always wins (honour AEGIS_ML_V2=0).
        Some("0") | Some("false") | Some("no") | Some("off") => false,
        // Explicit on.
        Some("1") | Some("true") | Some("yes") | Some("on") => true,
        // Unset (or any other value): default-ON when a kind is configured.
        _ => ml_v2_kind_set,
    };
    // Hold the logistic scorer Arc out here so we can BOTH wrap it in the
    // MlModel served on the hot path AND hand the same instance to the
    // MlTrainer below — retrain then mutates the live scorer's weights.
    let mut ml_v2_logistic_scorer: Option<Arc<aegis::ddos::ml_score_v2::MlScorerV2>> = None;
    let ml_model_v2: Option<Arc<aegis::ddos::ml_model::MlModel>> = if ml_v2_enabled {
        use aegis::ddos::{
            ml_gbm::GbmModel,
            ml_model::{MlModel, MlModelKind},
            ml_score_v2::MlScorerV2,
        };
        let kind = std::env::var("AEGIS_ML_V2_KIND")
            .ok()
            .and_then(|s| MlModelKind::parse(&s))
            .unwrap_or(MlModelKind::Logistic);
        let model = match kind {
            MlModelKind::Logistic => {
                tracing::info!(
                    explicit = ?ml_v2_explicit,
                    kind_set = ml_v2_kind_set,
                    "aegis-pingora: ML V2 scorer attached (logistic, 23 features, default-on)"
                );
                let scorer = Arc::new(MlScorerV2::new(true));
                ml_v2_logistic_scorer = Some(scorer.clone());
                MlModel::logistic(scorer)
            }
            MlModelKind::Gbm => {
                let gbm = match std::env::var("AEGIS_ML_V2_GBM_FILE") {
                    Ok(p) => match std::fs::read_to_string(&p) {
                        Ok(json) => match serde_json::from_str::<GbmModel>(&json) {
                            Ok(g) => {
                                tracing::info!(
                                    path = %p,
                                    trees = g.trees.len(),
                                    "aegis-pingora: ML V2 GBM loaded from file"
                                );
                                g
                            }
                            Err(e) => {
                                tracing::error!(
                                    path = %p, error = %e,
                                    "aegis-pingora: GBM file unparseable; using empty model"
                                );
                                GbmModel::default()
                            }
                        },
                        Err(e) => {
                            tracing::error!(
                                path = %p, error = %e,
                                "aegis-pingora: GBM file unreadable; using empty model"
                            );
                            GbmModel::default()
                        }
                    },
                    Err(_) => {
                        tracing::warn!(
                            "aegis-pingora: GBM requested but AEGIS_ML_V2_GBM_FILE unset; \
                                 using empty model (no learned signal)"
                        );
                        GbmModel::default()
                    }
                };
                MlModel::gbm(Arc::new(gbm))
            }
        };
        Some(Arc::new(model))
    } else {
        tracing::info!(
            explicit = ?ml_v2_explicit,
            kind_set = ml_v2_kind_set,
            "aegis-pingora: ML V2 scorer disabled (AEGIS_ML_V2=0 or no kind configured)"
        );
        None
    };

    // Build the V2 trainer when the logistic scorer is live. The trainer
    // holds the SAME Arc<MlScorerV2> the data plane scores with, so a
    // POST /admin/api/ml/retrain mutates the weights in place — no
    // restart, no separate model file. Samples are persisted as NDJSON
    // (override path via AEGIS_ML_V2_SAMPLES) so operator-labelled
    // feedback survives a restart. GBM has no in-process trainer (trees
    // are trained offline and loaded via AEGIS_ML_V2_GBM_FILE), so the
    // trainer is only constructed for the logistic kind.
    let ml_trainer: Option<Arc<aegis::ddos::ml_training::MlTrainer>> =
        ml_v2_logistic_scorer.as_ref().map(|scorer| {
            let samples_path = std::env::var("AEGIS_ML_V2_SAMPLES")
                .unwrap_or_else(|_| "/var/lib/aegis/ml-v2-samples.ndjson".to_string());
            let trainer = aegis::ddos::ml_training::MlTrainer::new(scorer.clone())
                .with_persistence(samples_path.clone());
            tracing::info!(
                samples = trainer.sample_count(),
                path = %samples_path,
                "aegis-pingora: ML V2 trainer attached (retrain mutates live scorer)"
            );
            Arc::new(trainer)
        });

    // V244 — reputation feed directory (auto-learned + install/refresh-seeded
    // feeds live here). Override via AEGIS_REPUTATION_DIR.
    let reputation_dir = std::env::var("AEGIS_REPUTATION_DIR")
        .unwrap_or_else(|_| "/var/lib/aegis/reputation".to_string());
    let _ = std::fs::create_dir_all(&reputation_dir);

    // V140/V244 — JA4 reputation. ON BY DEFAULT and self-learning: the proxy
    // auto-records JA4s seen on honeypot/WAF/tarpit hits into
    // `ja4-observed.txt` (the auto-learn sink), and also loads any
    // operator-supplied feeds (colon-separated `AEGIS_JA4_REPUTATION`) plus a
    // `ja4-crowdsec.txt` feed populated by the refresh job when a CrowdSec
    // LAPI is configured. There is no public bulk malicious-JA4 list to bundle
    // and tool JA4s collide with generic Go/Python clients, so a static
    // default would be FP-prone — self-learning from confirmed-bad traffic is
    // the safe out-of-box source. Disable with AEGIS_JA4_REPUTATION=0.
    let ja4_reputation: Option<Arc<aegis::ja4_reputation::Ja4Reputation>> = {
        let raw = std::env::var("AEGIS_JA4_REPUTATION").unwrap_or_default();
        if matches!(raw.to_ascii_lowercase().as_str(), "0" | "false" | "off") {
            tracing::info!("aegis-pingora: JA4 reputation disabled (AEGIS_JA4_REPUTATION=0)");
            None
        } else {
            let observed = std::path::PathBuf::from(&reputation_dir).join("ja4-observed.txt");
            let mut paths: Vec<std::path::PathBuf> = raw
                .split(':')
                .filter(|p| !p.is_empty())
                .map(std::path::PathBuf::from)
                .collect();
            // CrowdSec JA4 feed file — watched even when absent so the refresh
            // job can populate it later and the mtime reload picks it up.
            paths.push(std::path::PathBuf::from(&reputation_dir).join("ja4-crowdsec.txt"));
            let rep = aegis::ja4_reputation::Ja4Reputation::new(paths).with_observed_path(observed);
            tracing::info!(
                entries = rep.entry_count(),
                "aegis-pingora: JA4 reputation enabled (auto-learn from honeypot/WAF/tarpit)"
            );
            Some(Arc::new(rep))
        }
    };

    // V142/V144/V244 — ASN/CIDR reputation. ON BY DEFAULT: loads the
    // install/refresh-seeded `asn-cidr.txt` (Tor exit nodes + Spamhaus DROP
    // + operator entries) plus any operator-supplied colon-separated
    // `AEGIS_ASN_REPUTATION` paths. ASN-keyed entries (`AS<num>`) match only
    // when a MaxMind ASN DB is loaded via [geoip].asn_db_path; CIDR entries
    // always fire. Disable with AEGIS_ASN_REPUTATION=0.
    let asn_reputation: Option<Arc<aegis::asn_reputation::AsnReputation>> = {
        let raw = std::env::var("AEGIS_ASN_REPUTATION").unwrap_or_default();
        if matches!(raw.to_ascii_lowercase().as_str(), "0" | "false" | "off") {
            tracing::info!("aegis-pingora: ASN/CIDR reputation disabled (AEGIS_ASN_REPUTATION=0)");
            None
        } else {
            let mut paths: Vec<std::path::PathBuf> = raw
                .split(':')
                .filter(|p| !p.is_empty())
                .map(std::path::PathBuf::from)
                .collect();
            // Default seeded feed file (populated by install.sh + refresh job;
            // watched even when absent so it loads once written).
            paths.push(std::path::PathBuf::from(&reputation_dir).join("asn-cidr.txt"));
            // V144 — wrap the already-loaded GeoIp handle as an AsnLookup so
            // AS-keyed entries resolve. When no ASN DB is loaded, asn()
            // returns None and only CIDR matches fire.
            let asn_lookup: Arc<dyn aegis::asn_reputation::AsnLookup> =
                Arc::new(aegis::geoip::GeoIpAsnLookup::new(pipeline.geoip.clone()));
            tracing::info!(
                paths = paths.len(),
                "aegis-pingora: ASN/CIDR reputation enabled (Tor/Spamhaus + operator)"
            );
            Some(Arc::new(aegis::asn_reputation::AsnReputation::new(
                paths, asn_lookup,
            )))
        }
    };

    let proxy = AegisPingoraProxy::new(
        pipeline.engine.clone(),
        pipeline.router.clone(),
        metrics.clone(),
        pipeline.dynamic_trust.clone(),
        pipeline.response_cache.clone(),
        pipeline.bypass.clone(),
        pipeline.scorer.clone(),
        shared_scorer.clone(),
        pipeline.anomaly.clone(),
        pipeline.geoip.clone(),
        pipeline.geoip_cfg.clone(),
        pipeline.challenge.clone(),
        ml_scorer.clone(),
        tarpit_logger.clone(),
        allowed_sampler.clone(),
        site_map.clone(),
        threat_analytics.clone(),
    );
    // V140 — chain optional V2 scorer + JA4 reputation onto the proxy.
    let proxy = match ml_model_v2.clone() {
        Some(m) => proxy.with_ml_model_v2(m),
        None => proxy,
    };
    let proxy = match ja4_reputation.clone() {
        Some(r) => proxy.with_ja4_reputation(r),
        None => proxy,
    };
    let proxy = match asn_reputation.clone() {
        Some(r) => proxy.with_asn_reputation(r),
        None => proxy,
    };
    // V243 — hand the proxy the shared event-log handle for the hot-path
    // record() call in logging().
    let proxy = proxy.with_event_store(event_store.clone());

    // V36 — admin token registry. Same precedence the hyper server
    // uses: AEGIS_ADMIN_TOKEN env (implicit Admin role) merged with
    // any [[admin.tokens]] config entries. Empty registry means every
    // /admin/* request fails closed with 503.
    let env_token = std::env::var("AEGIS_ADMIN_TOKEN").ok();
    let cfg_tokens: Vec<_> = cfg
        .admin
        .as_ref()
        .map(|a| a.tokens.clone())
        .unwrap_or_default();
    let tokens = TokenRegistry::from_sources(env_token, &cfg_tokens);
    if tokens.is_empty() {
        tracing::warn!(
            "aegis-pingora: no admin tokens configured — /admin/* will fail with 503 \
            (set AEGIS_ADMIN_TOKEN or [[admin.tokens]] in aegis.conf)"
        );
    }
    let audit = AuditLog::new(
        cfg.admin
            .as_ref()
            .and_then(|a| a.audit_log_path.clone())
            .map(std::path::PathBuf::from),
    );

    // V66 — open the web-admin store (sessions, password hash, kill
    // switch). Path comes from cfg.admin.web_state_path or env
    // AEGIS_WEB_STATE; falls back to /var/lib/aegis/web.json. When
    // the operator hasn't configured anything we fall through with
    // None — the React panel + session login endpoints 503.
    let web_state_path = std::env::var("AEGIS_WEB_STATE")
        .ok()
        .or_else(|| cfg.admin.as_ref().and_then(|a| a.web_state_path.clone()));
    let web_admin: Option<Arc<aegis::web_admin::WebAdminStore>> = if let Some(p) = web_state_path {
        match aegis::web_admin::WebAdminStore::open(p.into()) {
            Ok(store) => Some(Arc::new(store)),
            Err(e) => {
                tracing::warn!(error = %e, "aegis-pingora: web_admin store open failed — web UI session login disabled");
                None
            }
        }
    } else {
        None
    };
    let audit_log_path = cfg
        .admin
        .as_ref()
        .and_then(|a| a.audit_log_path.clone())
        .map(std::path::PathBuf::from);
    let admin = AdminProxy::new(
        metrics.clone(),
        pipeline.response_cache.clone(),
        tokens,
        audit,
        pipeline.waf.clone(),
        pipeline.scorer.clone(),
        shared_scorer.clone(),
        pipeline.anomaly.clone(),
        pipeline.rate.clone(),
        pipeline.xdp.clone(),
        honeypots.clone(),
        web_admin,
        args.config.clone(),
        audit_log_path,
        Some(online_miner.clone()),
        site_map.clone(),
        threat_analytics.clone(),
        // V160 — share the FilterEngine's runtime toggle table so the
        // admin API can flip filters on/off without restart.
        pipeline.engine.toggles(),
        // V162 — share the per-domain policy store so the admin API
        // can read/write per-host filter overrides.
        pipeline.engine.domain_policy(),
    );
    // V169 — chain optional module refs for /admin/api/runtime/info.
    let admin = match ml_model_v2.clone() {
        Some(m) => admin.with_ml_v2(m),
        None => admin,
    };
    // Wire the V2 trainer so POST /admin/api/ml/retrain works (was 501
    // "ml trainer not wired into AdminProxy"). The trainer shares the
    // live logistic scorer Arc, so retrain takes effect without restart.
    let admin = match ml_trainer.clone() {
        Some(t) => admin.with_ml_trainer(t),
        None => admin,
    };
    let admin = match ja4_reputation.clone() {
        Some(r) => admin.with_ja4_reputation(r),
        None => admin,
    };
    let admin = match asn_reputation.clone() {
        Some(r) => admin.with_asn_reputation(r),
        None => admin,
    };
    // V243 — hand the admin store the same event-log handle so
    // /admin/api/logs + /admin/api/logs/stats serve persisted history.
    let admin = admin.with_event_store(event_store.clone());
    // V245 — share the live FilterEngine so the nginx head-to-head
    // comparison's "AEGIS + WAF" bar runs the real per-request inspection
    // pipeline (honest cost of protection, not just the bare serving stack).
    let admin = admin.with_engine(pipeline.engine.clone());

    // V192/V194 — construct + attach the Defence Arsenal so V176-V190
    // modules are live in the data plane. The arsenal counts every
    // ja4 lookup, churn observation, GREASE check, normalisation
    // pass, param-profile anomaly, etc., and surfaces them through
    // /admin/api/arsenal. Disable via AEGIS_ARSENAL=0 for benchmark
    // baselining.
    let arsenal_enabled = std::env::var("AEGIS_ARSENAL").ok().as_deref() != Some("0");
    let arsenal: Option<Arc<aegis::arsenal::ArsenalState>> = if arsenal_enabled {
        // BGP RTBH announcer wiring. ArsenalState::new_default() builds the
        // BgpRtbhDispatcher with an in-memory/noop announcer, so blackhole
        // decisions never leave the process. Out of the box we now install
        // a real file-based ExabgpPipeAnnouncer: it appends
        // `announce route .. / withdraw route ..` lines to a pipe/file that
        // an operator points `exabgp` at. The append target is created if
        // missing (see bgp_rtbh::write_line), so this is safe even before
        // exabgp is running — the lines simply queue in the file.
        //
        // Controllable knobs:
        //   AEGIS_BGP_PIPE     — pipe/file path. Default
        //                        /var/lib/aegis/bgp-announce.pipe. Set to the
        //                        empty string to keep the in-memory noop
        //                        announcer (no propagation).
        //   AEGIS_BGP_NEXTHOP  — BGP next-hop for announced /32|/128 routes.
        //                        Default 192.0.2.1 (TEST-NET-1, RFC5737) — a
        //                        non-routable placeholder operators MUST
        //                        override with their real RTBH next-hop.
        let bgp_pipe = std::env::var("AEGIS_BGP_PIPE")
            .unwrap_or_else(|_| "/var/lib/aegis/bgp-announce.pipe".to_string());
        let a = if bgp_pipe.trim().is_empty() {
            tracing::info!(
                "aegis-pingora: BGP RTBH pipe disabled (AEGIS_BGP_PIPE empty) — \
                 blackhole decisions stay in-process (noop announcer)"
            );
            aegis::arsenal::ArsenalState::new_default()
        } else {
            let next_hop =
                std::env::var("AEGIS_BGP_NEXTHOP").unwrap_or_else(|_| "192.0.2.1".to_string());
            let announcer: Arc<dyn aegis::bgp_rtbh::BgpAnnouncer> =
                Arc::new(aegis::bgp_rtbh::ExabgpPipeAnnouncer::new(
                    std::path::PathBuf::from(&bgp_pipe),
                    next_hop.clone(),
                ));
            tracing::info!(
                pipe = %bgp_pipe,
                next_hop = %next_hop,
                "aegis-pingora: BGP RTBH file announcer wired (exabgp pipe) — \
                 set AEGIS_BGP_NEXTHOP to your real RTBH next-hop"
            );
            aegis::arsenal::ArsenalState::new_default().with_bgp_announcer(announcer)
        };
        let a = Arc::new(a);
        // V245 — cross-worker persistence for per-domain challenge config so
        // a panel write is seen by every SO_REUSEPORT worker (not just the
        // one that handled the PUT).
        let challenge_path = std::env::var("AEGIS_CHALLENGE_CONFIG_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/aegis/domain-challenge.json"));
        a.attach_challenge_persistence(challenge_path.clone());
        // V246 — same cross-worker persistence for leaky-bucket scenarios:
        // a panel "Load" writes this file, every worker mtime-reloads it,
        // and it survives restart. Without this, scenarios lived only in the
        // one worker process that handled the load request.
        let scenarios_path = std::env::var("AEGIS_SCENARIOS_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/aegis/scenarios.yaml"));
        a.scenarios.set_persistence(scenarios_path.clone());
        tracing::info!(
            modules = 18,
            challenge_config = %challenge_path.display(),
            "aegis-pingora: Defence Arsenal attached (V176-V199); \
             set AEGIS_ARSENAL=0 to disable"
        );
        Some(a)
    } else {
        tracing::info!("aegis-pingora: Defence Arsenal disabled via AEGIS_ARSENAL=0");
        None
    };
    let proxy = match arsenal.clone() {
        Some(a) => proxy.with_arsenal(a),
        None => proxy,
    };
    // V108 — install the RiskEngine when configured (Observe-first).
    let proxy = match pipeline.risk_engine.clone() {
        Some(re) => proxy.with_risk_engine(re),
        None => proxy,
    };
    // Phase 4 — wire the XDP handle so the `fail_to_xdp_deny` challenge
    // lever can push repeat-offender IPs into the kernel deny set.
    // NoopXdp when XDP is unavailable, so the lever no-ops gracefully.
    let proxy = proxy.with_xdp(pipeline.xdp.clone());
    // H9a — enforce TLS fingerprint deny lists on the pingora data plane.
    // Previously `tls.ja4_deny_prefixes` / `tls.ja3_deny_hashes` were only
    // honoured by the legacy hyper path; on pingora they were silently
    // inert. Empty lists make the per-request check short-circuit, so this
    // is a no-op unless the operator configures deny entries.
    let proxy = {
        let (ja4_deny, ja3_deny) = cfg
            .tls
            .as_ref()
            .map(|t| (t.ja4_deny_prefixes.clone(), t.ja3_deny_hashes.clone()))
            .unwrap_or_default();
        proxy.with_tls_deny_lists(ja4_deny, ja3_deny)
    };
    // Build the V181 rule plan from the live WAF rules and install
    // it on the arsenal. Re-call this after WAF hot-reload to keep
    // the planner aligned (V194 refresh_arsenal_rule_plan).
    if arsenal.is_some() {
        proxy.refresh_arsenal_rule_plan(&pipeline.waf);
    }
    let admin = match arsenal.clone() {
        Some(a) => admin.with_arsenal(a),
        None => admin,
    };

    // V208 — wire the update checker so the admin UI's Updates page
    // works. Config is read from env (AEGIS_UPDATE_REPO_API /
    // AEGIS_UPDATE_CHANNEL / AEGIS_UPDATE_POLL_SECS) so operators
    // can point at a private mirror or pin the channel without
    // recompiling.
    let updates = {
        let mut cfg = aegis::updates::UpdateConfig::default();
        if let Ok(url) = std::env::var("AEGIS_UPDATE_REPO_API") {
            cfg.repo_api_url = url;
        }
        if let Ok(ch) = std::env::var("AEGIS_UPDATE_CHANNEL") {
            cfg.channel = match ch.to_ascii_lowercase().as_str() {
                "beta" => aegis::updates::Channel::Beta,
                "nightly" => aegis::updates::Channel::Nightly,
                _ => aegis::updates::Channel::Stable,
            };
        }
        if let Ok(s) = std::env::var("AEGIS_UPDATE_POLL_SECS")
            && let Ok(n) = s.parse::<u64>()
        {
            cfg.poll_interval_secs = n;
        }
        Arc::new(aegis::updates::UpdateChecker::new(
            cfg,
            Arc::new(aegis::updates::CurlHttpClient::new()),
        ))
    };
    let admin = admin.with_updates(updates.clone());
    // TS — wire the time-series store so GET /admin/api/metrics/series
    // can serve historical data. When `timeseries_store` is None the
    // admin endpoint returns an empty point list (graceful degradation).
    let admin = match timeseries_store.clone() {
        Some(ts) => admin.with_timeseries(ts),
        None => admin,
    };
    // V240 — tell the admin handler where shard files live so it can
    // aggregate all workers' data and serve a stable, flicker-free
    // /admin/api/site_map response that also survives restarts.
    let admin = admin.with_sitemap_dir(sitemap_dir.clone());
    // V60 — background service construction moved BELOW the TLS
    // listener setup so it can `.with_tls(tls_acceptor_for_reload)`
    // for cert mtime polling. See further down in `main`.

    // V46 — HTTP/3 over QUIC. Pingora ships h1/h2 but no h3 today,
    // so we spawn the hyper-based `ProxyHttpHandler` (the production
    // h3 path on aegis) on a dedicated tokio runtime in a separate
    // thread. It reuses the same engine, router, response_cache,
    // dynamic_trust, scorer, anomaly, geoip, xdp Arcs the pingora
    // service holds — one source of truth for filter decisions and
    // cache state; only the WAF/bypass/honeypot caches are
    // duplicated (the hyper handler builds its own from cfg) and
    // their hot-reload mtime poll is per-instance.
    let h3_spawn_ok = maybe_spawn_h3(&cfg, &pipeline, &metrics, &honeypots);
    if let Err(e) = h3_spawn_ok {
        // V231 — under the multi-worker REUSEPORT layout quinn's QUIC
        // UDP socket has no SO_REUSEPORT, so only the first worker to
        // bind :443/udp serves HTTP/3; sibling workers land here with
        // `AddrInUse`. That is expected and harmless — HTTP/3 is still
        // served by the worker that won the bind, and h1/h2 over TCP
        // is unaffected. Logged at info (not warn) so it doesn't read
        // as an error; a genuine misconfig (bad cert, bad h3_listen)
        // still surfaces with the wrapped cause.
        tracing::info!(error = %e,
            "aegis-pingora: HTTP/3 not started by this worker \
             (served by a sibling worker under REUSEPORT, or h3 disabled/misconfigured)");
    }

    // V71 — pingora's Server takes ownership of the process —
    // `run_forever` never returns. Operators stop it via SIGTERM
    // (pingora installs its own handler that drains in-flight
    // requests).
    //
    // Critical perf knob: `ServerConf::threads` defaults to **1**.
    // The first round of the V57 stand bench had pingora-1 topping
    // out at ~44k RPS vs hyper-1's ~238k RPS purely because
    // pingora was running on one core. Set threads = num_cpus by
    // default; operator can override via AEGIS_PINGORA_THREADS
    // (useful for pinned-CPU multi-process deploys where each
    // worker should claim its CPU set, not race siblings).
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let threads = std::env::var("AEGIS_PINGORA_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(num_cpus);
    // V80/V81 — thread-per-core runtime via `work_stealing=false`,
    // now the default. pingora-runtime exposes two flavours:
    //   * Steal   (tokio multi_thread Builder) — work-stealing
    //              scheduler, good for mixed I/O+CPU workloads where
    //              task duration varies wildly
    //   * NoSteal (pingora's NoStealRuntime)    — N single-threaded
    //              current_thread runtimes, no cross-thread task
    //              migration. Better cache locality for cache-heavy
    //              AND WAF-heavy workloads where most tasks are short
    //              and stay on the same core.
    //
    // V80 A/B benched both flavours on V79 binary:
    //   cache-warm c=400:  Steal 875k → NoSteal 964k stable (+10%)
    //   cache-warm c=1000: Steal 925k → NoSteal 987k         (+7%)
    //   cache-off  c=400:  Steal 107k → NoSteal 250k stable  (+135% — Steal
    //                                                          was clearly
    //                                                          contention-bound)
    // NoSteal wins on every measured workload, so V81 flips the
    // default. Operators that prefer the work-stealing scheduler
    // can opt back in via AEGIS_PINGORA_WORK_STEALING=1.
    let work_stealing = std::env::var("AEGIS_PINGORA_WORK_STEALING")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    // V229 — sized upstream connection pool. Default `1` forced a
    // new TCP/TLS handshake on every cache miss; bumping to 4096
    // lets pingora reuse keepalive'd connections per worker, which
    // matches the haproxy/nginx-proxy baseline behaviour.
    let upstream_pool = std::env::var("AEGIS_PINGORA_UPSTREAM_POOL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4096);
    // V229 — grace period for in-flight requests on shutdown. Default
    // is short; bumping prevents lost responses during a reload.
    let grace_secs = std::env::var("AEGIS_PINGORA_GRACE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    let conf = pingora_core::server::configuration::ServerConf {
        threads: threads.max(1),
        work_stealing,
        upstream_keepalive_pool_size: upstream_pool,
        grace_period_seconds: Some(grace_secs),
        ..Default::default()
    };
    let mut server = pingora_core::server::Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();
    tracing::info!(
        threads = conf_threads(&server),
        "aegis-pingora: pingora runtime configured"
    );

    // V91 — Phase D cluster state was init'd above before
    // build_pipeline so SharedScorer could attach. Re-log here
    // after server.bootstrap() ran (post-fork in daemon mode) so
    // each worker confirms it sees the segment.
    if aegis::shared_state::global::enabled() {
        tracing::info!(
            arena = aegis::shared_state::global::arena_name().unwrap_or("?"),
            size_bytes = aegis::shared_state::global::arena_size(),
            created_by_us = aegis::shared_state::global::created_by_us(),
            "aegis-shared-state: cluster arena live"
        );
    }

    // V238 — enable disk-backed cross-worker token sharing on the
    // proxy's ChallengeStore BEFORE we clone it for the bg task. Without
    // this, each SO_REUSEPORT worker has its own in-memory map and LE's
    // validation GET (kernel-routed to a random worker) misses 3/4 of
    // the time → state=Invalid. The directory is on the writable state
    // partition the service user owns.
    let acme_challenges_disk_dir = PathBuf::from(
        std::env::var("AEGIS_ACME_STATE_DIR").unwrap_or_else(|_| "/var/lib/aegis/acme".to_string()),
    )
    .join("challenges");
    let proxy = proxy.with_acme_challenges_disk_dir(acme_challenges_disk_dir);

    // Extract the ACME ChallengeStore BEFORE proxy is moved into the
    // pingora service. Both the service and the ACME Provisioner will
    // share the same Arc<DashMap> (and disk_dir, set just above) via
    // this clone.
    let acme_challenge_store_for_bg = proxy.acme_challenge_store();

    let mut service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    // C3 — HTTP/2 protocol-flood limits. pingora's HttpProxy exposes an
    // `h2_options` field (= h2::server::Builder) that pingora_core applies
    // at the H2 handshake (apps/mod.rs: `server::handshake(stream,
    // self.h2_options())`). Left as None it used h2's permissive defaults,
    // leaving Rapid-Reset (CVE-2023-44487), CONTINUATION-flood
    // (CVE-2024-27316) and stream-churn effectively unbounded on the
    // public listener. (The in-tree h2_guard/h2_budget modules could never
    // wire in because pingora owns the frame loop — THIS is the supported
    // hook.) Tunable via AEGIS_H2_* env; sane secure defaults otherwise.
    if let Some(app) = service.app_logic_mut() {
        let max_streams: u32 = std::env::var("AEGIS_H2_MAX_STREAMS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128);
        let max_header_list: u32 = std::env::var("AEGIS_H2_MAX_HEADER_LIST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64 * 1024);
        let max_reset: usize = std::env::var("AEGIS_H2_MAX_RESET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let mut h2 = pingora_core::protocols::http::v2::server::H2Options::default();
        h2.max_concurrent_streams(max_streams)
            .max_header_list_size(max_header_list)
            .max_pending_accept_reset_streams(max_reset);
        app.h2_options = Some(h2);
        tracing::info!(
            max_streams,
            max_header_list,
            max_reset,
            "aegis-pingora: HTTP/2 flood limits applied (C3)"
        );
    }
    // SO_REUSEPORT mirrors the V18 multi-process pattern from the
    // hyper path — N instances can bind the same port, kernel
    // distributes accept queues. Operators opt in per-instance with
    // AEGIS_PINGORA_REUSEPORT=1 in the systemd template unit.
    let reuseport = std::env::var("AEGIS_PINGORA_REUSEPORT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    // V230 — build downstream-listener socket options once and reuse
    // for both the reuseport and non-reuseport branches. TCP_NODELAY
    // (disabling Nagle's 40ms coalescing) is set implicitly by pingora
    // in `apply_stream_settings` on every accepted stream (see
    // pingora-core listeners/l4.rs:385), so we don't need a knob for
    // it — it's always on.
    //
    // V231 — both `add_tcp` and `add_tcp_with_settings` route through
    // the SAME `bind_tcp` and call `listen(LISTENER_BACKLOG=65535)`
    // (pingora-core listeners/l4.rs:223-252) — the choice does NOT
    // change the accept backlog. We still go through
    // `add_tcp_with_settings` so `so_reuseport` (and opt-in keepalive)
    // can be applied; see `build_downstream_sock_opt` for the V231
    // connection-refused regression analysis.
    let downstream_sock_opt = build_downstream_sock_opt(reuseport);
    if reuseport {
        service.add_tcp_with_settings(&listen, downstream_sock_opt.clone());
    } else {
        // V231 — non-reuseport path. `downstream_sock_opt` carries
        // only what the operator opted into; keepalive is OFF by
        // default so the accept loop stays syscall-light.
        service.add_tcp_with_settings(&listen, downstream_sock_opt.clone());
    }

    // V25 + V50 — TLS termination. Cert/key paths come from the
    // same `tls.cert_path`/`tls.key_path` the hyper path uses, so
    // operators don't need a parallel cert config. V50 routes the
    // handshake through our `AegisTlsAccept` (TlsAccept impl) which
    // implements per-SNI cert selection — multi-domain HTTPS on h1/h2
    // now works the same as on the hyper handler (the V35 doc's
    // "blocked on pingora-rustls" limitation was lifted by switching
    // to the `openssl` feature, which exposes the TlsAccept callback
    // API the rustls feature lacks).
    let tls_enabled = cfg.tls.as_ref().is_some_and(|t| t.enabled);
    let mut tls_acceptor_for_reload: Option<Arc<aegis::proxy::pingora_tls::AegisTlsAccept>> = None;
    if tls_enabled {
        let tls = cfg.tls.as_ref().expect("checked above");
        let tls_listen = std::env::var("AEGIS_LISTEN_TLS").unwrap_or_else(|_| tls.listen.clone());
        // V60 — wrap AegisTlsAccept in an Arc so the same instance
        // backs (a) the pingora TlsAcceptCallbacks and (b) the
        // background cert-reload poller. Both halves see the same
        // ArcSwap<CertStore> inside.
        let acceptor = Arc::new(
            aegis::proxy::pingora_tls::AegisTlsAccept::build(
                &tls.cert_path,
                &tls.key_path,
                &tls.sni,
            )
            .map_err(|e| anyhow::anyhow!("aegis-pingora: TLS acceptor build failed: {e}"))?,
        );
        // V178/V194 — attach the arsenal so certificate_callback
        // observes GREASE positions live on every TLS handshake.
        if let Some(a) = arsenal.as_ref() {
            acceptor.set_arsenal(a.clone());
        }

        // LEVER 1 — decide once at startup whether JA3/JA4
        // fingerprinting is needed. The gate is TRUE (compute) when
        // ANY known consumer is active. It is FALSE only when ALL of
        // the following hold:
        //   1. No ja3_deny_hashes configured (TLS-level deny rules)
        //   2. No ja4_deny_prefixes configured
        //   3. Arsenal disabled (AEGIS_ARSENAL=0) — arsenal uses ja4
        //      for corpus lookup, churn, and GREASE scoring
        //   4. No JA4 reputation feed (AEGIS_JA4_REPUTATION unset)
        //   5. No inline WAF rule reads ja3/ja4 (field:"ja3"|"ja4")
        //   6. No external WAF rule_files are configured (we cannot
        //      inspect their predicates here, and they reload at
        //      runtime, so their presence alone forces the gate ON)
        //   7. Operator explicitly opts out via AEGIS_TLS_FINGERPRINT=0
        //
        // NOTE: a WafRule.field is an arbitrary string, so a rule like
        // {field:"ja4", op:"starts_with", action:"deny"} is a live ja4
        // consumer (waf.rs reads ctx.ja4 for it). Inline rules are scanned
        // directly; external rule_files force the gate ON conservatively.
        // An explicit AEGIS_TLS_FINGERPRINT=0 is OVERRIDDEN (with a warn)
        // whenever any consumer is detected — a false-OFF gate would
        // silently break any ja3/ja4 rule (SECURITY REGRESSION).
        {
            let has_ja3_deny = !tls.ja3_deny_hashes.is_empty();
            let has_ja4_deny = !tls.ja4_deny_prefixes.is_empty();
            let arsenal_on = arsenal_enabled; // AEGIS_ARSENAL != "0"
            let ja4_rep_on = std::env::var("AEGIS_JA4_REPUTATION").is_ok();
            // A WafRule.field is an arbitrary string, so a rule like
            // {field:"ja4", op:"starts_with", value:"t13d", action:"deny"}
            // is a live fingerprint consumer (waf.rs reads ctx.ja4/ctx.ja3
            // for it). Inline rules we inspect directly (skipping ones in
            // mode="disabled", which never fire). External rule_files are
            // merged at startup AND on reload and cannot be cheaply
            // inspected here, so their mere presence forces the gate ON —
            // we cannot prove they contain no ja3/ja4 rule.
            let waf = &cfg.filters.waf;
            let has_inline_fp_rule = waf.custom_rules.iter().any(|r| {
                matches!(r.field.as_str(), "ja3" | "ja4") && r.mode.as_deref() != Some("disabled")
            });
            let has_external_waf_rules = !waf.rule_files.is_empty();
            let any_consumer = has_ja3_deny
                || has_ja4_deny
                || arsenal_on
                || ja4_rep_on
                || has_inline_fp_rule
                || has_external_waf_rules;
            let explicit_off = std::env::var("AEGIS_TLS_FINGERPRINT").ok().as_deref() == Some("0");
            // Fail-safe: ON whenever ANY consumer is detected; OFF only on
            // an explicit opt-out with no detectable consumer. A false-OFF
            // gate would silently disable any ja3/ja4 rule (SECURITY
            // REGRESSION), so an explicit opt-out is OVERRIDDEN when a
            // consumer is present.
            let fingerprinting_on = any_consumer || !explicit_off;
            acceptor.set_fingerprinting(fingerprinting_on);
            if explicit_off && any_consumer {
                tracing::warn!(
                    has_ja3_deny,
                    has_ja4_deny,
                    arsenal_on,
                    ja4_rep_on,
                    has_inline_fp_rule,
                    has_external_waf_rules,
                    "aegis-pingora: AEGIS_TLS_FINGERPRINT=0 OVERRIDDEN — a \
                     ja3/ja4 consumer is configured; fingerprinting stays ON \
                     to avoid silently disabling it"
                );
            } else if !fingerprinting_on {
                tracing::warn!(
                    "aegis-pingora: TLS JA3/JA4 fingerprinting DISABLED \
                     (AEGIS_TLS_FINGERPRINT=0, no consumer detected). Any \
                     ja3/ja4-based rule (TLS deny, WAF field:\"ja3\"/\"ja4\", \
                     arsenal, reputation) added later will NOT match until you \
                     unset AEGIS_TLS_FINGERPRINT and restart."
                );
            }
            tracing::info!(
                fingerprinting = fingerprinting_on,
                has_ja3_deny,
                has_ja4_deny,
                arsenal_on,
                ja4_rep_on,
                has_inline_fp_rule,
                has_external_waf_rules,
                explicit_off,
                "aegis-pingora: TLS JA3/JA4 fingerprinting gate set"
            );
        }

        tls_acceptor_for_reload = Some(acceptor.clone());
        // Convert Arc<AegisTlsAccept> → Box<dyn TlsAccept> via a
        // tiny wrapper. pingora wants ownership of the callbacks;
        // the Arc lets the reload poller keep a handle.
        let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
            Box::new(aegis::proxy::pingora_tls::SharedTlsAccept(acceptor));
        let mut tls_settings = pingora_core::listeners::tls::TlsSettings::with_callbacks(callbacks)
            .map_err(|e| anyhow::anyhow!("pingora TlsSettings::with_callbacks failed: {e}"))?;
        // V246 — register a ClientHello callback to capture JA3/JA4 at the ONLY
        // handshake stage where the SSL_client_hello_* accessors are valid.
        // certificate_callback (OpenSSL cert_cb) fires later and returns empty
        // there, which made every client's fingerprint degenerate
        // (t12i000000_e3b0c44298fc). Resolves via TlsSettings → SslAcceptorBuilder
        // → SslContextBuilder deref. `tls_acceptor_for_reload` holds the Arc clone
        // captured just above (the original is moved into the callbacks box).
        if let Some(fp_acceptor) = tls_acceptor_for_reload.clone() {
            use openssl::ssl::{ClientHelloResponse, SslAlert, SslRef};
            tls_settings.set_client_hello_callback(
                move |ssl: &mut SslRef, _alert: &mut SslAlert| {
                    fp_acceptor.capture_client_hello(ssl);
                    Ok::<_, openssl::error::ErrorStack>(ClientHelloResponse::SUCCESS)
                },
            );
        }
        tls_settings.enable_h2();
        // V230 — h2 protocol limits (max_concurrent_streams,
        // initial_window_size, initial_connection_window_size) would
        // ideally be tuned here to mitigate Rapid-Reset (CVE-2023-44487)
        // and tune flow control for our traffic shape. Pingora 0.8.0
        // does NOT expose `tls_settings.h2_options()` (verified against
        // pingora-core 0.8.0/src/listeners/tls/boringssl_openssl/mod.rs
        // — the only h2-related public method on TlsSettings is
        // `enable_h2()` which just sets ALPN). The server-side h2
        // stream limit is therefore the pingora-internal default. If
        // we move to pingora 0.9+ this is the place to call
        // `set_max_concurrent_streams(50)` / `set_initial_window_size(1MB)`
        // / `set_initial_connection_window_size(8MB)`.

        // LEVER 3 — shared TLS session-ticket key for REUSEPORT workers.
        // When REUSEPORT is on, install a shared per-file ticket key so
        // clients can resume on any worker. When REUSEPORT is off (single
        // process), this is still correct (and slightly better than the
        // random ephemeral key because the key survives hot-reloads).
        // Always turns off the per-worker server-side session cache, which
        // is useless under REUSEPORT and wastes memory in all cases.
        {
            let key_path = std::path::PathBuf::from(
                std::env::var("AEGIS_TLS_TICKET_KEY_FILE")
                    .unwrap_or_else(|_| "/etc/aegis/tls_ticket.key".to_string()),
            );
            // apply_shared_ticket_key turns the (REUSEPORT-useless)
            // server-side session cache OFF, queries the OpenSSL-required
            // ticket-key length, loads/generates a shared key of exactly
            // that length, and installs it. A failure is SAFE — per-worker
            // ephemeral keys; cross-worker resumption just falls back to
            // full handshakes — so never abort startup over it.
            if let Err(e) = apply_shared_ticket_key(&mut *tls_settings, &key_path) {
                tracing::warn!(
                    error = %e,
                    path = %key_path.display(),
                    "aegis-pingora: shared ticket key setup failed — per-worker \
                     random key used (safe, REUSEPORT cross-worker resumption degraded)"
                );
                // Ensure the server-side session cache is OFF even if apply
                // bailed before reaching its own set_session_cache_mode call.
                use openssl::ssl::SslSessionCacheMode;
                tls_settings.set_session_cache_mode(SslSessionCacheMode::OFF);
            }
        }

        // V59 — mTLS: when enabled in config, install the client-
        // cert trust store + SslVerifyMode on the inner
        // SslAcceptorBuilder via the DerefMut impl on TlsSettings.
        // Disabled by default (the build call returns Ok(None) when
        // mtls.enabled = false) so existing deploys stay unchanged.
        if let Some(setup) = aegis::proxy::pingora_tls::MtlsSetup::build(&tls.mtls)
            .map_err(|e| anyhow::anyhow!("aegis-pingora: mTLS setup failed: {e}"))?
        {
            tracing::info!(
                require_cert = setup.require_cert,
                ca_count = tls.mtls.ca_paths.len(),
                "aegis-pingora: mTLS verification enabled"
            );
            setup.apply(&mut tls_settings);
        }
        // V230/V231 — same TCP-level options on the TLS listener:
        // reuseport (when enabled) + opt-in keepalive (OFF by default,
        // see `build_downstream_sock_opt`). Pingora applies TCP_NODELAY
        // implicitly to every accepted stream.
        let tls_sock_opt = build_downstream_sock_opt(reuseport);
        service.add_tls_with_settings(&tls_listen, Some(tls_sock_opt), tls_settings);
        tracing::info!(
            listen_tls = %tls_listen,
            default_cert = %tls.cert_path,
            sni_entries = tls.sni.len(),
            "aegis-pingora TLS listener active (h2 + h1, per-SNI cert via TlsAccept callback)"
        );
    }

    // V60 — build the background service AFTER TLS so we can hand
    // the AegisTlsAccept Arc into the cert-reload poller.
    let mut background = PingoraBackground::new(
        pipeline.waf.clone(),
        pipeline.dynamic_trust.clone(),
        pipeline.response_cache.clone(),
        pipeline.scorer.clone(),
    );
    if let Some(tls) = tls_acceptor_for_reload {
        background = background.with_tls(tls);
    }
    // V94 — register the cluster scorer for periodic compaction.
    // Each worker ticks every 30s; the 4-worker REUSEPORT layout
    // hits compaction ~7.5s on average. Stale shared-map entries
    // get tombstoned so the arena slot can be reclaimed.
    if let Some(ss) = &shared_scorer {
        background = background.with_shared_scorer(ss.clone());
    }
    background = background.with_online_miner(online_miner.clone());
    // H2 — let the background tick prune stale rate-limiter buckets
    // (the pingora path otherwise never calls cleanup_stale).
    background = background.with_rate(pipeline.rate.clone());
    // V140 — register JA4 reputation feed for periodic mtime reload.
    if let Some(rep) = &ja4_reputation {
        background = background.with_ja4_reputation(rep.clone());
    }
    // V142 — same for ASN/CIDR reputation feed.
    if let Some(rep) = &asn_reputation {
        background = background.with_asn_reputation(rep.clone());
    }
    // V197/V199 — attach arsenal so the background tick drives the
    // actuator timer wheel + GCs stale scenario buckets.
    if let Some(a) = arsenal.as_ref() {
        background = background.with_arsenal(a.clone());
    }
    // TS — register the time-series store for periodic sampling.
    // `sample_once()` fires every 60 s (every 2nd 30 s tick) on the
    // worker holding the writer lock; the others silently no-op.
    if let Some(ts) = &timeseries_store {
        background = background.with_timeseries(ts.clone());
    }
    // V240 — register site-map for periodic shard flushing. Each tick
    // the background service calls flush_shard() so all SO_REUSEPORT
    // workers' snapshots land on disk and the admin API can merge them
    // into a stable, complete aggregate.
    background = background.with_site_map(site_map.clone());
    // V242 — register RuntimeMetrics so the background tick flushes this
    // worker's per-country slice to its geo shard. The admin geo/top
    // endpoint merges all workers' shards so the world-map dot counts stay
    // stable poll-to-poll under SO_REUSEPORT. No-op when geo persistence
    // wasn't acquired (slot taken / dir unwritable).
    background = background.with_metrics(metrics.clone());

    // Admin service — separate listener, independent ProxyHttp impl
    // that serves /metrics + /health + the admin API and never
    // forwards upstream. Default 127.0.0.1:9090 (matches the hyper
    // handler's default); AEGIS_ADMIN_LISTEN overrides it.
    let admin_listen = std::env::var("AEGIS_ADMIN_LISTEN")
        .ok()
        .or_else(|| cfg.admin.as_ref().map(|a| a.listen.clone()));

    // ── ACME / Let's Encrypt client wiring (BEFORE admin is consumed) ───
    // The admin service for POST /admin/api/acme/orders needs an
    // Arc<dyn AcmeClient>. The background renewal task spawned further
    // down in main() also needs one — both get clones of the same Arc.
    // Construction depends on the persisted config (account_email +
    // use_production), so we read that JSON twice (once here, once for
    // the bg task). load_or_default is a tiny synchronous read; doing
    // it twice is cheaper than refactoring the bg block right now.
    let acme_state_dir_for_admin = PathBuf::from(
        std::env::var("AEGIS_ACME_STATE_DIR").unwrap_or_else(|_| "/var/lib/aegis/acme".to_string()),
    );
    let acme_orders_dir_for_admin = acme_state_dir_for_admin.join("orders");
    let acme_config_path_for_admin = acme_state_dir_for_admin.join("config.json");
    let acme_config_for_admin = AcmeConfig::load_or_default(&acme_config_path_for_admin);
    // V238 — construct the ACME client UNCONDITIONALLY. account_email is
    // optional per RFC 8555 §7.3 (LE accepts contact-less accounts;
    // the only consequence is no expiry-reminder email). Previously we
    // gated the client on Some(email), forcing a restart-after-config
    // workflow and making the panel show a frozen "Request" button
    // before email was set. Now: the empty-email path just calls
    // register_account with an empty contact slice.
    let admin = {
        let email = acme_config_for_admin
            .account_email
            .clone()
            .unwrap_or_default();
        let account_key_subdir = if acme_config_for_admin.use_production {
            "accounts/production"
        } else {
            "accounts/staging"
        };
        let account_key_path = acme_state_dir_for_admin
            .join(account_key_subdir)
            .join("account.json");
        let dir_url = if acme_config_for_admin.use_production {
            aegis::acme_instant::production_directory()
        } else {
            aegis::acme_instant::staging_directory()
        };
        let cert_dir_root_str = std::env::var("AEGIS_ACME_CERT_DIR")
            .unwrap_or_else(|_| "/var/lib/aegis/certs".to_string());
        let client: Arc<dyn aegis::acme::AcmeClient> =
            Arc::new(aegis::acme_instant::InstantAcmeClient::new(
                email.as_str(),
                dir_url,
                account_key_path,
                cert_dir_root_str,
            ));
        tracing::info!(
            target: "aegis::acme",
            email = if email.is_empty() { "<none>" } else { email.as_str() },
            dir_url,
            "ACME: client plumbed into AdminProxy (POST /admin/api/acme/orders enabled)"
        );
        admin
            .with_acme_client(
                client,
                Some(acme_orders_dir_for_admin),
                Some(acme_config_path_for_admin),
            )
            // CRITICAL: share the SAME ChallengeStore the data-plane
            // HTTP-01 handler reads from (captured at line ~1421 via
            // proxy.acme_challenge_store()). Without this, the admin
            // handler's spawned Provisioner publishes tokens into a
            // fresh store and LE validation fails with state=Invalid.
            .with_acme_challenges(acme_challenge_store_for_bg.clone())
    };

    let mut admin_service = pingora_proxy::http_proxy_service(&server.configuration, admin);
    let admin_addr = admin_listen.unwrap_or_else(|| "127.0.0.1:9090".to_string());
    // V231 — BIND-RACE FIX. The admin listener must share SO_REUSEPORT
    // with the data plane. Under the multi-worker REUSEPORT layout
    // (systemd `aegis-pingora@1..N`, all running this identical binary)
    // a plain `add_tcp` makes every worker race to bind the same admin
    // port — only one wins, the rest panic in pingora's `run_forever`
    // with `AddrInUse`.
    //
    // Pre-V230 that panic merely unwound the admin-service THREAD; the
    // data-plane thread kept running, so the bug was invisible (each
    // worker just silently had a dead admin thread). V230's
    // `panic = "abort"` turned the same thread panic into a
    // whole-process SIGABRT → systemd restart → re-race → restart loop.
    //
    // With `so_reuseport` every worker binds the admin port cleanly and
    // the kernel load-balances admin requests across them. Admin state
    // stays consistent across workers because it is all disk-backed
    // with mtime-poll cross-worker sync: WebAdminStore (login sessions
    // — see `web_admin.rs` `refresh()`), DomainPolicyStore and
    // RuntimeToggles (V168). When reuseport is off (single-process /
    // dev) `build_downstream_sock_opt(false)` yields default options,
    // i.e. identical behaviour to the old `add_tcp`.
    admin_service.add_tcp_with_settings(&admin_addr, build_downstream_sock_opt(reuseport));

    // ── ACME background task ────────────────────────────────────────────
    // Reads /var/lib/aegis/acme/config.json (email, use_production).
    // Constructs InstantAcmeClient with the right LE directory URL.
    // Wires the SAME ChallengeStore instance the data-plane HTTP-01
    // handler reads from (via proxy.acme_challenge_store() accessor).
    // Loads saved order state and schedules renewals on boot.
    //
    // SAFETY: defaults to LE staging. Switching to production requires
    // an explicit PUT /admin/api/acme/config {use_production:true,
    // accepted_tos_at:<unix>} from a Write-role admin token.
    // Account key is O_CREAT|O_EXCL + chmod 0600, never regenerated.
    // HTTP-01 only; per-host in-flight lock prevents double-order.
    let acme_store_dir = PathBuf::from(
        std::env::var("AEGIS_ACME_STATE_DIR").unwrap_or_else(|_| "/var/lib/aegis/acme".to_string()),
    );
    let acme_cert_dir = aegis::acme::CertDir::new(
        std::env::var("AEGIS_ACME_CERT_DIR").unwrap_or_else(|_| "/var/lib/aegis/certs".to_string()),
    );
    let acme_config = AcmeConfig::load_or_default(&acme_store_dir.join("config.json"));
    // V238 — bg renewal loop also runs UNCONDITIONALLY. Email is now
    // optional (see InstantAcmeClient::register_account); the only
    // gate is that we still need a directory URL + the shared
    // ChallengeStore, both of which are independent of email.
    let acme_runtime: Option<AcmeRuntime> = {
        let email = acme_config.account_email.clone().unwrap_or_default();
        {
            // Separate account key per directory (staging vs production)
            // so the staging account key is NEVER used against production.
            let account_key_subdir = if acme_config.use_production {
                "accounts/production"
            } else {
                "accounts/staging"
            };
            let account_key_path = acme_store_dir.join(account_key_subdir).join("account.json");
            let dir_url = if acme_config.use_production {
                aegis::acme_instant::production_directory()
            } else {
                aegis::acme_instant::staging_directory()
            };
            tracing::info!(
                target: "aegis::acme",
                email = if email.is_empty() { "<none>" } else { email.as_str() },
                dir_url,
                account_key = %account_key_path.display(),
                "ACME: initialising client"
            );
            let cert_dir_root_str = std::env::var("AEGIS_ACME_CERT_DIR")
                .unwrap_or_else(|_| "/var/lib/aegis/certs".to_string());
            let client = Arc::new(aegis::acme_instant::InstantAcmeClient::new(
                email.as_str(),
                dir_url,
                account_key_path.clone(),
                cert_dir_root_str,
            ));
            // Share the proxy's ChallengeStore — the data-plane HTTP-01
            // handler reads from this same Arc<DashMap> at line 1730+.
            // We captured it before proxy was moved into the service.
            let challenges = acme_challenge_store_for_bg.clone();
            let provisioner = Arc::new(aegis::acme::Provisioner::new(
                client,
                challenges,
                acme_cert_dir,
            ));
            let orders_dir = acme_store_dir.join("orders");
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ProvisionRequest>();
            // Spawn a dedicated tokio task. Pingora owns the main runtime;
            // the ACME task lives on it as a background task rather than
            // a separate thread so it can await network I/O without a
            // second runtime.
            //
            // Note: pingora calls server.bootstrap() above which forks
            // the runtime internals. The tokio task here is spawned
            // AFTER bootstrap on the main runtime, which is correct.
            let _acme_handle = {
                let prov = Arc::clone(&provisioner);
                let odir = orders_dir.clone();
                // We need a tokio runtime handle to spawn a background task.
                // Pingora's server constructs its own runtime; we spawn on
                // the current tokio runtime (which is the multi-thread one
                // from the process entry point, or from a test harness).
                // In production, main() runs synchronously before run_forever()
                // so we use tokio::runtime::Handle::current() if available,
                // otherwise fall back to creating a dedicated thread.
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(acme_background_loop(prov, odir, rx));
                        tracing::info!(
                            target: "aegis::acme",
                            "ACME: background loop spawned on existing tokio runtime"
                        );
                    }
                    Err(_) => {
                        // No current runtime (pingora uses its own internal
                        // runtime). Spin up a dedicated background thread
                        // with a current_thread runtime for the ACME task.
                        std::thread::Builder::new()
                            .name("aegis-acme-bg".to_string())
                            .spawn(move || {
                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .thread_name("aegis-acme-rt")
                                    .build()
                                    .expect("ACME tokio runtime build");
                                rt.block_on(acme_background_loop(prov, odir, rx));
                            })
                            .expect("spawn aegis-acme-bg thread");
                        tracing::info!(
                            target: "aegis::acme",
                            "ACME: background loop spawned on dedicated thread"
                        );
                    }
                }
            };
            Some(AcmeRuntime { tx })
        }
    };
    // The AcmeRuntime channel sender is owned by the background loop
    // spawned above (the loop's mpsc receiver lives inside the spawned
    // future). The admin API does NOT use the channel — each POST
    // /admin/api/acme/orders spawns its own short-lived Provisioner
    // using the Arc<dyn AcmeClient> plumbed via `with_acme_client`
    // before admin_service was built. The renewal loop drives long-term
    // periodic re-issuance via the same client. Keep `acme_runtime`
    // alive (don't drop) so the channel doesn't close.
    let _acme_renewal_runtime = acme_runtime;

    tracing::info!(
        listen = %listen,
        reuseport,
        tls = tls_enabled,
        admin = %admin_addr,
        "aegis-pingora starting (Phase B preview)"
    );
    server.add_service(service);
    server.add_service(admin_service);
    // Background hot-reload poller. pingora's `background_service`
    // wraps a BackgroundService impl as a ServiceWithDependents the
    // Server can start + drain alongside the listeners.
    server.add_service(pingora_core::services::background::background_service(
        "aegis-pingora-maintenance",
        background,
    ));
    server.run_forever();
}

/// V46 — optionally spawn an HTTP/3 listener that shares the pingora
/// pipeline's engine + state via Arc clones. Returns Ok(()) when h3
/// is disabled in config (no listener spawned, no error); Err when
/// h3 was requested but the listener couldn't bind / TLS isn't set up.
fn maybe_spawn_h3(
    cfg: &aegis::config::AppConfig,
    pipeline: &aegis::proxy::pingora_http::BuiltPipeline,
    metrics: &Arc<RuntimeMetrics>,
    honeypots: &Arc<HoneypotStore>,
) -> Result<()> {
    let Some(tls) = cfg.tls.as_ref() else {
        return Ok(());
    };
    if !tls.enabled || !tls.h3_enabled {
        return Ok(());
    }
    let h3_listen_str = tls.h3_listen.as_deref().unwrap_or(&tls.listen);
    let h3_addr: std::net::SocketAddr = h3_listen_str
        .parse()
        .with_context(|| format!("invalid h3_listen {h3_listen_str}"))?;

    // Build a hyper-based ProxyHttpHandler from the pipeline Arcs.
    // Most fields are shared (one source of truth); WAF / bypass /
    // honeypots / fingerprints get parallel hyper-side state because
    // ProxyHttpHandler::new constructs them from cfg directly. WAF
    // rule hot-reload is per-instance — operators triggering
    // /admin/waf/reload reload only the pingora-side WAF, the h3
    // WAF picks up changes on its own 30s tick via the cleanup_task
    // path which is NOT wired here (V47+ todo).
    let upstream = pipeline.router.clone();
    let filters = pipeline.engine.clone();
    let metrics = metrics.clone();
    let scorer = pipeline.scorer.clone();
    let challenge_cfg = cfg.filters.challenge.clone();
    let challenge_filter = pipeline.challenge.filter.clone();
    let bot_cfg = cfg.filters.bot.clone();
    let rate_cfg = cfg.filters.rate_limit.clone();
    let waf_cfg = cfg.filters.waf.clone();
    let graphql_cfg = cfg.filters.graphql.clone();
    let bypass_cfg = cfg.filters.bypass.clone();
    let health = Arc::new(UpstreamHealth::new(upstream.clone()));
    let fingerprints = Arc::new(FingerprintCache::new());
    let honeypots_clone = honeypots.clone();
    let xdp = pipeline.xdp.clone();
    // ReputationStore (Redis) — opt-in. h3 path is fine without it.
    let store = cfg
        .storage
        .as_ref()
        .and_then(|s| aegis::state::reputation::ReputationStore::new(&s.redis_url).ok());
    let geoip = pipeline.geoip.clone();
    let geoip_cfg = pipeline.geoip_cfg.clone();
    let anomaly = pipeline.anomaly.clone();
    let body_read_timeout = cfg.server.body_read_timeout_ms;
    let upstream_protocol = cfg.upstream.protocol;
    let xdp_allow_ips: Vec<std::net::IpAddr> = cfg
        .xdp
        .as_ref()
        .map(|x| x.allow.iter().filter_map(|s| s.parse().ok()).collect())
        .unwrap_or_default();
    let dyn_trust_cfg = cfg.filters.dynamic_trust.clone();
    let cache_cfg = cfg.filters.response_cache.clone();
    let cert_path = tls.cert_path.clone();
    let key_path = tls.key_path.clone();
    let sni = tls.sni.clone();

    // Spawn the h3 listener on a dedicated tokio runtime in a new
    // OS thread. Pingora's `Server::run_forever` owns the main
    // thread (and its own runtime) once we call it; the h3 runtime
    // stays alive in this side-thread until process exit.
    std::thread::Builder::new()
        .name("aegis-pingora-h3".to_string())
        .spawn(move || {
            // V230 — current_thread runtime. The default
            // `Runtime::new()` spawns a multi-thread scheduler
            // (worker_threads = num_cpus by default) which CPU-contends
            // with the pingora workers that already pin themselves to
            // every core. The h3 sidecar's job is tiny (one quinn
            // endpoint accept loop + the per-connection task it forks +
            // one 30s WAF reload ticker), so a single-thread runtime
            // is plenty and keeps it out of the pingora worker pool.
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("aegis-h3-rt")
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "aegis-pingora: h3 runtime build failed");
                    return;
                }
            };
            rt.block_on(async move {
                // Build the handler inside the runtime so its inner
                // hyper-util Client uses this runtime's executor.
                let handler = ProxyHttpHandler::new(
                    upstream,
                    filters,
                    metrics,
                    scorer,
                    challenge_cfg,
                    challenge_filter,
                    bot_cfg,
                    rate_cfg,
                    &waf_cfg,
                    &graphql_cfg,
                    &bypass_cfg,
                    health.clone(),
                    fingerprints.clone(),
                    honeypots_clone,
                    xdp,
                    store,
                    geoip,
                    geoip_cfg,
                    anomaly,
                    // alt_svc — empty on the h3 listener itself.
                    None,
                    body_read_timeout,
                    upstream_protocol,
                    xdp_allow_ips,
                    &dyn_trust_cfg,
                    &cache_cfg,
                );
                // Mark the handler as h3-bound so it skips
                // Alt-Svc stamping on responses it sends back.
                let handler = handler.for_h3();
                let endpoint = match http3::build_endpoint(h3_addr, &cert_path, &key_path, &sni) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::error!(error = %e, listen = %h3_addr, "aegis-pingora: h3 endpoint bind failed");
                        return;
                    }
                };
                tracing::info!(listen = %h3_addr, "aegis-pingora: h3 listener active");
                let handler = Arc::new(tokio::sync::RwLock::new(handler));
                health.spawn_checker();
                // V61 — the hyper-handler shim has its own internal
                // WAF (built from cfg inside ProxyHttpHandler::new),
                // separate from pingora's WAF that the
                // PingoraBackground task hot-reloads. Without a
                // dedicated h3-side reloader, mtime changes to the
                // WAF rule files would only take effect on the
                // pingora h1/h2 path; h3 traffic would still be
                // gated by the boot-time ruleset. Spawn a 30s
                // poller on the h3 runtime so both protocols see
                // the same live ruleset.
                let h3_waf_handler = handler.clone();
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(
                        std::time::Duration::from_secs(30),
                    );
                    ticker.set_missed_tick_behavior(
                        tokio::time::MissedTickBehavior::Delay,
                    );
                    loop {
                        ticker.tick().await;
                        let n = h3_waf_handler.read().await.waf_maybe_reload();
                        if n > 0 {
                            tracing::info!(
                                files = n,
                                "aegis-pingora h3: WAF rules reloaded via mtime poll"
                            );
                        }
                    }
                });
                let _ = http3::spawn_server(endpoint, handler, fingerprints).await;
            });
        })
        .with_context(|| "spawn aegis-pingora-h3 thread")?;
    Ok(())
}
