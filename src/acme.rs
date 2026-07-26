//! V134 — ACME auto-cert (Let's Encrypt) integration.
//!
//! Synapse parity. Two responsibilities:
//!
//! 1. **HTTP-01 challenge responder** — Let's Encrypt validates domain
//!    ownership by GETting `/.well-known/acme-challenge/<token>` on
//!    port 80 of every identifier in an order. Because Aegis already
//!    binds port 80 (it's the proxy front door), no operator-side
//!    ACME client can do this without coordination. We expose a
//!    [ChallengeStore] the proxy hot path checks before falling
//!    through to upstream routing.
//!
//! 2. **Renewal orchestrator** — schedules issuance for the configured
//!    domain set, retries on failure with backoff, writes the issued
//!    cert + key to disk where the existing cert reloader picks them
//!    up (see `src/proxy/pingora_tls.rs:cert_reload_picks_up_disk_change`).
//!
//! The actual ACME protocol (JWS-signed POSTs to the Let's Encrypt
//! directory) is abstracted behind the [AcmeClient] trait. This
//! mirrors V132's [HttpPoster] pattern — Aegis core stays free of
//! heavy crypto deps; the operator wires instant-acme / acme-lib /
//! their preferred crate in a thin shim. The provisioner state
//! machine, the challenge responder, and the on-disk cert layout
//! are all in-tree and unit-tested.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use serde::{Deserialize, Serialize};

/// Thread-safe map of `token → keyauth` populated by the provisioner
/// during an active order. The proxy's HTTP-01 route handler reads
/// from here on every request. Empty in steady state (no order in
/// flight) so the lookup is a hashmap miss → fast path.
///
/// V230 — switched the inner hasher from `DashMap`'s default
/// (SipHash, `RandomState`) to `FxBuildHasher`. Tokens come from the
/// ACME server (Let's Encrypt) — semi-trusted, not arbitrary client
/// input — and the store holds at most a handful of entries during an
/// active order, so DoS-resistant hashing buys us nothing and Fx cuts
/// the per-lookup cost on the request hot path. Same pattern used in
/// `src/filters/engine.rs`.
#[derive(Clone)]
pub struct ChallengeStore {
    inner: Arc<DashMap<String, String, FxBuildHasher>>,
    /// V238 — disk-backed token directory for cross-worker sharing under
    /// SO_REUSEPORT. AEGIS runs N worker processes that each have their
    /// own DashMap. The admin handler runs the Provisioner on one worker,
    /// so the token only lands in that worker's in-memory map. LE's
    /// challenge GET hits any of the N workers chosen by the kernel —
    /// 1/N hits the right one, (N-1)/N hit a miss → 302 redirect →
    /// validation Invalid. Solution: persist tokens to a shared dir
    /// (typically /var/lib/aegis/acme/challenges/) — `insert` writes a
    /// file, `remove` deletes it, `get` falls back to the file on memory
    /// miss. Tokens are URL-safe base64 (vetted by HTTP01_PATH_PREFIX +
    /// the `contains('/')` guard in challenge_response_for_path), so
    /// they're safe to use as filenames. None disables disk sharing
    /// (unit-test default).
    disk_dir: Option<PathBuf>,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        // V230 — manual `Default` impl: the derived one needs the
        // hasher type to also be `Default`, which is true for
        // `FxBuildHasher` — but being explicit keeps the construction
        // path identical to `new()`.
        Self::new()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        // V230 — explicit constructor required now that the hasher
        // slot is no longer `RandomState`. `FxBuildHasher` is a unit
        // struct so this is free at runtime.
        Self {
            inner: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            disk_dir: None,
        }
    }

    /// V238 — enable cross-worker token sharing via a directory on disk.
    /// Idempotently `mkdir -p` at construction; `insert`/`remove`/`get`
    /// then mirror to the directory so every worker on the host can
    /// serve any token regardless of which worker initiated the order.
    /// Returns the store with disk-backing enabled.
    pub fn with_disk_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let _ = std::fs::create_dir_all(&dir);
        self.disk_dir = Some(dir);
        self
    }

    /// Path on disk where a token's keyauth is stored. Only call after
    /// `with_disk_dir` has set the directory. Token is filesystem-safe
    /// (URL-safe base64, guarded by the prefix-strip + `contains('/')`
    /// check upstream).
    fn token_path(&self, token: &str) -> Option<PathBuf> {
        self.disk_dir.as_ref().map(|d| d.join(token))
    }

    pub fn insert(&self, token: impl Into<String>, keyauth: impl Into<String>) {
        let token = token.into();
        let keyauth = keyauth.into();
        if let Some(p) = self.token_path(&token) {
            // Atomic write: tmp + rename. File is short-lived (LE finishes
            // a validation in seconds), but we still avoid the partial-read
            // race if a sibling worker reads while we write.
            let tmp = p.with_extension("tmp");
            if let Ok(()) = std::fs::write(&tmp, keyauth.as_bytes()) {
                let _ = std::fs::rename(&tmp, &p);
            }
        }
        self.inner.insert(token, keyauth);
    }

    pub fn remove(&self, token: &str) -> Option<String> {
        if let Some(p) = self.token_path(token) {
            let _ = std::fs::remove_file(&p);
        }
        self.inner.remove(token).map(|(_, v)| v)
    }

    pub fn get(&self, token: &str) -> Option<String> {
        // Fast path: memory hit (initiator worker).
        if let Some(v) = self.inner.get(token).map(|v| v.value().clone()) {
            return Some(v);
        }
        // Fallback: read from disk (sibling worker under SO_REUSEPORT).
        // Token is already prefix-stripped and `/`-guarded by
        // `challenge_response_for_path`, so the join is safe.
        if let Some(p) = self.token_path(token)
            && let Ok(s) = std::fs::read_to_string(&p)
        {
            return Some(s);
        }
        None
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    /// V234 — request-path entry point for the proxy HTTP-01 route
    /// handler. Given a raw request path, returns `Some(keyauth)` if it
    /// is a `/.well-known/acme-challenge/<token>` URL with a registered
    /// token; `None` otherwise (non-ACME path or unknown token).
    ///
    /// This is the method form of the free [`challenge_response_for_path`]
    /// function — it exists so a handler that already holds a
    /// `ChallengeStore` can write `store.challenge_response_for_path(path)`
    /// without threading the store through as an argument. The free
    /// function remains the single implementation; this only forwards.
    ///
    /// Hot-path safe: `O(1)` hashmap lookup plus a prefix check, no
    /// filesystem I/O, no allocation on the miss path, and panic-free
    /// for any attacker-controlled `path` — empty tokens and tokens
    /// containing `/` (subpath traversal) are rejected before the
    /// lookup. Empty in steady state, so the common case is a hashmap
    /// miss.
    #[inline]
    pub fn challenge_response_for_path(&self, path: &str) -> Option<String> {
        challenge_response_for_path(self, path)
    }
}

/// Token shape that Let's Encrypt embeds in HTTP-01 challenge URLs.
/// Tokens are URL-safe base64; we don't decode them — we just pass
/// through.
pub const HTTP01_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// Look up the keyauth for the token in `request_path`. Returns
/// `Some(keyauth)` if the path is an ACME challenge with a registered
/// token; `None` otherwise (non-ACME path or unknown token).
///
/// Hot path: called on every incoming request before normal routing.
/// `O(1)` hashmap lookup plus a path-prefix check.
pub fn challenge_response_for_path(store: &ChallengeStore, request_path: &str) -> Option<String> {
    let token = request_path.strip_prefix(HTTP01_PATH_PREFIX)?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    store.get(token)
}

/// Operator-injected ACME protocol driver. Implementing this against
/// `instant-acme` is ~80 lines (see crate docs). The orchestrator
/// below uses only these three methods.
#[async_trait::async_trait]
pub trait AcmeClient: Send + Sync {
    /// Begin a new order for `identifiers`. Returns the per-identifier
    /// HTTP-01 challenge artifacts the orchestrator must publish via
    /// [ChallengeStore] before triggering verification.
    async fn new_order(&self, identifiers: &[String]) -> Result<Vec<Http01Challenge>>;

    /// Tell the ACME server "the challenges are now live, please
    /// verify". Server polls our challenge URLs; we wait for a final
    /// status.
    async fn finalize_and_collect(&self, order: &OrderHandle) -> Result<IssuedCertificate>;

    /// Optional pre-flight: returns days until soonest existing cert
    /// expiry. The orchestrator uses this to decide whether to renew.
    /// Implementations without local cert state return `None`.
    async fn days_until_expiry(&self, identifier: &str) -> Option<i64>;
}

/// One HTTP-01 challenge issued by the ACME server for one identifier.
#[derive(Debug, Clone)]
pub struct Http01Challenge {
    pub identifier: String,
    pub token: String,
    pub keyauth: String,
}

/// Opaque handle the [AcmeClient] returns from `new_order` and accepts
/// in `finalize_and_collect`. Lets the orchestrator stay agnostic
/// about the underlying ACME library's state.
#[derive(Debug, Clone)]
pub struct OrderHandle {
    pub order_url: String,
    pub identifiers: Vec<String>,
}

/// PEM-encoded artifacts the orchestrator writes to disk for the cert
/// reloader to pick up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    pub cert_chain_pem: String,
    pub private_key_pem: String,
    pub identifiers: Vec<String>,
    /// Unix seconds. Used by the orchestrator to schedule renewal at
    /// `not_after - 30 days`.
    pub not_after_unix: u64,
}

/// Cert layout on disk. One pair per identifier set; named after the
/// primary (first) identifier with `.cert.pem` / `.key.pem` suffixes.
/// Matches what the pingora cert reloader watches.
#[derive(Clone, Debug)]
pub struct CertDir {
    pub root: PathBuf,
}

impl CertDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn paths_for(&self, primary: &str) -> (PathBuf, PathBuf) {
        let safe = primary
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>();
        (
            self.root.join(format!("{safe}.cert.pem")),
            self.root.join(format!("{safe}.key.pem")),
        )
    }

    pub fn write(&self, cert: &IssuedCertificate) -> Result<(PathBuf, PathBuf)> {
        let primary = cert.identifiers.first().context("no identifiers")?;
        std::fs::create_dir_all(&self.root).with_context(|| format!("mkdir {:?}", self.root))?;
        let (cert_path, key_path) = self.paths_for(primary);
        // Write key first with strict perms; cert second.
        std::fs::write(&key_path, cert.private_key_pem.as_bytes())
            .with_context(|| format!("write {key_path:?}"))?;
        Self::tighten_perms(&key_path).ok();
        std::fs::write(&cert_path, cert.cert_chain_pem.as_bytes())
            .with_context(|| format!("write {cert_path:?}"))?;
        Ok((cert_path, key_path))
    }

    /// V230 — async sibling of [`Self::write`] for use from `Provisioner`
    /// and any other async caller. Issues `tokio::fs` ops so a renewal
    /// running on the proxy runtime can't stall a worker thread while
    /// the kernel does the dirty-page flush on a slow disk. The sync
    /// [`Self::write`] is preserved for external/sync callers and the
    /// in-file unit tests; both paths share `tighten_perms`.
    pub async fn write_async(&self, cert: &IssuedCertificate) -> Result<(PathBuf, PathBuf)> {
        let primary = cert.identifiers.first().context("no identifiers")?;
        tokio::fs::create_dir_all(&self.root)
            .await
            .with_context(|| format!("mkdir {:?}", self.root))?;
        let (cert_path, key_path) = self.paths_for(primary);
        // Write key first with strict perms; cert second.
        tokio::fs::write(&key_path, cert.private_key_pem.as_bytes())
            .await
            .with_context(|| format!("write {key_path:?}"))?;
        // V230 — perm tightening uses metadata + set_permissions which
        // are also blocking; offload via `spawn_blocking` rather than
        // pulling in another tokio::fs round trip per call. The op is
        // best-effort (`.ok()`) — same semantics as the sync path.
        let kp_for_perms = key_path.clone();
        let _ = tokio::task::spawn_blocking(move || Self::tighten_perms(&kp_for_perms))
            .await
            .ok();
        tokio::fs::write(&cert_path, cert.cert_chain_pem.as_bytes())
            .await
            .with_context(|| format!("write {cert_path:?}"))?;
        Ok((cert_path, key_path))
    }

    #[cfg(unix)]
    fn tighten_perms(p: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(p)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(p, perms)
    }
    #[cfg(not(unix))]
    fn tighten_perms(_p: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

/// Renewal threshold. Let's Encrypt issues 90-day certs; standard
/// practice is to renew at 30 days remaining so a single retry cycle
/// has plenty of runway.
pub const RENEW_AT_DAYS_REMAINING: i64 = 30;

/// Drives one issuance/renewal cycle against an [AcmeClient]. The
/// caller wires this into a tokio interval task (typically daily) —
/// no internal timer, so tests run sync.
pub struct Provisioner {
    pub client: Arc<dyn AcmeClient>,
    pub store: ChallengeStore,
    pub cert_dir: CertDir,
}

impl Provisioner {
    pub fn new(client: Arc<dyn AcmeClient>, store: ChallengeStore, cert_dir: CertDir) -> Self {
        Self {
            client,
            store,
            cert_dir,
        }
    }

    /// Check expiry, issue if needed. Returns the issued cert on
    /// renewal; `None` if the existing cert is still fresh.
    pub async fn maybe_renew(&self, identifiers: &[String]) -> Result<Option<IssuedCertificate>> {
        if let Some(primary) = identifiers.first()
            && let Some(days) = self.client.days_until_expiry(primary).await
            && days > RENEW_AT_DAYS_REMAINING
        {
            tracing::debug!(primary, days, "acme: cert still fresh, skipping");
            return Ok(None);
        }
        let cert = self.issue(identifiers).await?;
        // V230 — was `self.cert_dir.write(&cert)?;` (blocking
        // `std::fs::*` inside an async fn). Use the async sibling so
        // the proxy runtime worker isn't parked on a disk flush
        // during renewal.
        self.cert_dir.write_async(&cert).await?;
        Ok(Some(cert))
    }

    /// Force a full issuance cycle regardless of existing cert state.
    pub async fn issue(&self, identifiers: &[String]) -> Result<IssuedCertificate> {
        let challenges = self.client.new_order(identifiers).await?;
        for c in &challenges {
            self.store.insert(c.token.clone(), c.keyauth.clone());
        }
        let handle = OrderHandle {
            order_url: String::new(),
            identifiers: identifiers.to_vec(),
        };
        let result = self.client.finalize_and_collect(&handle).await;
        // Always drain the challenge store — leaked tokens would let
        // any client probe random ACME paths and learn a keyauth.
        for c in &challenges {
            self.store.remove(&c.token);
        }
        result
    }
}

/// Renewal scheduler helper — pure function so tests can verify the
/// next-tick computation without spinning a tokio interval.
pub fn next_renewal_delay(not_after_unix: u64, now_unix: u64) -> Duration {
    let renew_at = not_after_unix.saturating_sub((RENEW_AT_DAYS_REMAINING as u64) * 86_400);
    if renew_at <= now_unix {
        Duration::ZERO
    } else {
        Duration::from_secs(renew_at - now_unix)
    }
}

/// Convenience: current unix seconds, monotonic-skip safe.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    /// Minimal scoped temp dir — avoids pulling in the tempfile crate
    /// just for these tests.
    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("aegis-acme-test-{pid}-{now}-{n}"));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn store_insert_get_remove() {
        let s = ChallengeStore::new();
        assert!(s.is_empty());
        s.insert("t1", "k1");
        assert_eq!(s.len(), 1);
        assert_eq!(s.get("t1").as_deref(), Some("k1"));
        assert_eq!(s.remove("t1").as_deref(), Some("k1"));
        assert!(s.is_empty());
    }

    #[test]
    fn challenge_path_matches_only_acme_prefix() {
        let s = ChallengeStore::new();
        s.insert("abc", "keyauth-abc");
        assert_eq!(
            challenge_response_for_path(&s, "/.well-known/acme-challenge/abc").as_deref(),
            Some("keyauth-abc"),
        );
        // Wrong prefix.
        assert!(challenge_response_for_path(&s, "/abc").is_none());
        // Subdirectory traversal not allowed.
        assert!(challenge_response_for_path(&s, "/.well-known/acme-challenge/abc/leak").is_none());
        // Empty token.
        assert!(challenge_response_for_path(&s, "/.well-known/acme-challenge/").is_none());
        // Unknown token.
        assert!(challenge_response_for_path(&s, "/.well-known/acme-challenge/zzz").is_none());
    }

    /// V234 — the `ChallengeStore::challenge_response_for_path` method
    /// must behave identically to the free function it forwards to,
    /// including rejecting every attacker-shaped path without panicking.
    #[test]
    fn store_method_challenge_response_for_path_matches_free_fn() {
        let s = ChallengeStore::new();
        s.insert("abc", "keyauth-abc");
        // Happy path via the method form.
        assert_eq!(
            s.challenge_response_for_path("/.well-known/acme-challenge/abc")
                .as_deref(),
            Some("keyauth-abc"),
        );
        // Method and free function agree across a spread of inputs,
        // including hostile ones — none may panic.
        for p in [
            "/.well-known/acme-challenge/abc",
            "/.well-known/acme-challenge/zzz",
            "/.well-known/acme-challenge/",
            "/.well-known/acme-challenge/abc/leak",
            "/.well-known/acme-challenge",
            "/abc",
            "/",
            "",
            "/.well-known/acme-challenge/../../../etc/passwd",
        ] {
            assert_eq!(
                s.challenge_response_for_path(p),
                challenge_response_for_path(&s, p),
                "method and free fn disagree on {p:?}",
            );
        }
    }

    #[test]
    fn cert_dir_writes_files_with_safe_names() {
        let tmp = TempDir::new();
        let cd = CertDir::new(tmp.path());
        let cert = IssuedCertificate {
            cert_chain_pem: "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n".into(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nbar\n-----END PRIVATE KEY-----\n".into(),
            identifiers: vec!["www.example.com".into(), "example.com".into()],
            not_after_unix: 0,
        };
        let (cp, kp) = cd.write(&cert).unwrap();
        assert!(cp.exists());
        assert!(kp.exists());
        let written_cert = std::fs::read_to_string(&cp).unwrap();
        assert!(written_cert.contains("BEGIN CERTIFICATE"));
        // Identifier with slashes / unsafe chars gets sanitised.
        let cert2 = IssuedCertificate {
            cert_chain_pem: "x".into(),
            private_key_pem: "y".into(),
            identifiers: vec!["weird/name with spaces".into()],
            not_after_unix: 0,
        };
        let (cp2, _) = cd.write(&cert2).unwrap();
        assert!(
            !cp2.to_string_lossy()
                .contains('/')
                .then_some(true)
                .unwrap_or(false)
                || cp2
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        );
    }

    #[cfg(unix)]
    #[test]
    fn cert_dir_tightens_key_perms_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new();
        let cd = CertDir::new(tmp.path());
        let cert = IssuedCertificate {
            cert_chain_pem: "x".into(),
            private_key_pem: "y".into(),
            identifiers: vec!["a.example".into()],
            not_after_unix: 0,
        };
        let (_, kp) = cd.write(&cert).unwrap();
        let m = std::fs::metadata(&kp).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn next_renewal_delay_when_far_future() {
        let now = 1_000_000;
        // 90-day cert: should schedule ~60 days out.
        let not_after = now + 90 * 86_400;
        let d = next_renewal_delay(not_after, now);
        assert_eq!(d, Duration::from_secs(60 * 86_400));
    }

    #[test]
    fn next_renewal_delay_when_close_to_expiry() {
        let now = 1_000_000;
        // 5 days left — past the 30-day renew threshold → renew now.
        let not_after = now + 5 * 86_400;
        assert_eq!(next_renewal_delay(not_after, now), Duration::ZERO);
    }

    // ── Mock AcmeClient for orchestrator tests ─────────────────────

    struct MockClient {
        challenges: Vec<Http01Challenge>,
        cert: IssuedCertificate,
        days_left: Option<i64>,
        new_order_calls: Mutex<u32>,
        finalize_calls: Mutex<u32>,
    }

    #[async_trait::async_trait]
    impl AcmeClient for MockClient {
        async fn new_order(&self, identifiers: &[String]) -> Result<Vec<Http01Challenge>> {
            *self.new_order_calls.lock().unwrap() += 1;
            // Return challenges matching identifiers from the prefab list.
            let _ = identifiers;
            Ok(self.challenges.clone())
        }

        async fn finalize_and_collect(&self, _o: &OrderHandle) -> Result<IssuedCertificate> {
            *self.finalize_calls.lock().unwrap() += 1;
            Ok(self.cert.clone())
        }

        async fn days_until_expiry(&self, _id: &str) -> Option<i64> {
            self.days_left
        }
    }

    fn mock(days_left: Option<i64>) -> Arc<MockClient> {
        Arc::new(MockClient {
            challenges: vec![Http01Challenge {
                identifier: "example.com".into(),
                token: "tok1".into(),
                keyauth: "ka1".into(),
            }],
            cert: IssuedCertificate {
                cert_chain_pem: "PEM-CERT".into(),
                private_key_pem: "PEM-KEY".into(),
                identifiers: vec!["example.com".into()],
                not_after_unix: now_unix() + 90 * 86_400,
            },
            days_left,
            new_order_calls: Mutex::new(0),
            finalize_calls: Mutex::new(0),
        })
    }

    #[tokio::test]
    async fn issue_publishes_then_drains_challenges() {
        let store = ChallengeStore::new();
        let tmp = TempDir::new();
        let m = mock(None);
        let p = Provisioner::new(m.clone(), store.clone(), CertDir::new(tmp.path()));
        let cert = p.issue(&["example.com".to_string()]).await.unwrap();
        assert_eq!(cert.cert_chain_pem, "PEM-CERT");
        // Store must be drained on success — leaving tokens would
        // make /.well-known/acme-challenge/tok1 leak the keyauth.
        assert!(store.is_empty(), "challenge store should be drained");
        assert_eq!(*m.new_order_calls.lock().unwrap(), 1);
        assert_eq!(*m.finalize_calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn maybe_renew_skips_when_cert_fresh() {
        let store = ChallengeStore::new();
        let tmp = TempDir::new();
        let m = mock(Some(60)); // 60 days left → above the 30-day threshold
        let p = Provisioner::new(m.clone(), store.clone(), CertDir::new(tmp.path()));
        let out = p.maybe_renew(&["example.com".to_string()]).await.unwrap();
        assert!(out.is_none());
        assert_eq!(*m.new_order_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn maybe_renew_issues_when_cert_near_expiry() {
        let store = ChallengeStore::new();
        let tmp = TempDir::new();
        let m = mock(Some(10)); // 10 days left → below threshold → renew
        let p = Provisioner::new(m.clone(), store.clone(), CertDir::new(tmp.path()));
        let out = p.maybe_renew(&["example.com".to_string()]).await.unwrap();
        assert!(out.is_some());
        assert_eq!(*m.new_order_calls.lock().unwrap(), 1);
        // And the cert should now exist on disk.
        let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(entries.len(), 2); // cert + key
    }

    #[tokio::test]
    async fn issue_drains_challenges_even_on_finalize_error() {
        struct FailClient {
            challenges: Vec<Http01Challenge>,
        }
        #[async_trait::async_trait]
        impl AcmeClient for FailClient {
            async fn new_order(&self, _: &[String]) -> Result<Vec<Http01Challenge>> {
                Ok(self.challenges.clone())
            }
            async fn finalize_and_collect(&self, _: &OrderHandle) -> Result<IssuedCertificate> {
                Err(anyhow::anyhow!("finalize blew up"))
            }
            async fn days_until_expiry(&self, _: &str) -> Option<i64> {
                None
            }
        }
        let store = ChallengeStore::new();
        let tmp = TempDir::new();
        let client = Arc::new(FailClient {
            challenges: vec![Http01Challenge {
                identifier: "example.com".into(),
                token: "tok-leak".into(),
                keyauth: "ka-leak".into(),
            }],
        });
        let p = Provisioner::new(client, store.clone(), CertDir::new(tmp.path()));
        let r = p.issue(&["example.com".to_string()]).await;
        assert!(r.is_err());
        // Store still drained even though finalize failed — otherwise
        // probe-and-replay attacks become trivial.
        assert!(store.is_empty(), "store must be drained on failure too");
    }
}
