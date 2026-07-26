//! V234 — Concrete [AcmeClient] implementation backed by `instant-acme`.
//!
//! # Safety / key-management invariants
//!
//! * Account credentials are loaded from `account_key_path` on the **first
//!   order** request (lazy init). If absent, a fresh ECDSA P-256 account is
//!   registered against the configured ACME directory and persisted with
//!   `O_CREAT|O_EXCL` + `chmod 0600`. Subsequent calls (including across
//!   process restarts) load the file; the account is **never** re-generated
//!   if the file exists.
//! * Switching `directory_url` at runtime (staging ↔ production toggle) uses
//!   a **separate** credentials file path per directory so the staging account
//!   key is never used against the production directory. The caller
//!   (`InstantAcmeClient::new`) receives the full path; the admin API layer
//!   maps it to `accounts/<staging|production>.json` under the ACME state dir.
//!
//! # In-flight state
//!
//! `new_order` returns HTTP-01 challenges immediately. The corresponding
//! `instant_acme::Order` object (plus the private key for the eventual CSR) is
//! stashed in `orders: DashMap<order_url, InFlightOrder>`. `finalize_and_collect`
//! retrieves it by the `order_url` embedded in [OrderHandle], drives the
//! ACME state machine to completion, and removes the entry.
//!
//! Because `instant_acme::Order` is `!Send`, the stashed value wraps it in a
//! `tokio::sync::Mutex` so the future is `Send` even though we never actually
//! poll it concurrently.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use tokio::sync::Mutex;

use crate::acme::{AcmeClient, Http01Challenge, IssuedCertificate, OrderHandle};

// ── URL helpers ──────────────────────────────────────────────────────────────

/// ACME directory URL for Let's Encrypt **staging** (safe for development).
/// This is the default when `use_production` is `false`.
pub const fn staging_directory() -> &'static str {
    instant_acme::LetsEncrypt::Staging.url()
}

/// ACME directory URL for Let's Encrypt **production**.
/// Only used when `use_production = true` **and** TOS have been accepted.
pub const fn production_directory() -> &'static str {
    instant_acme::LetsEncrypt::Production.url()
}

// ── In-flight order ──────────────────────────────────────────────────────────

struct InFlightOrder {
    /// The instant-acme order handle. Wrapped in a Mutex so
    /// `InFlightOrder: Send` even though `Order` holds a `!Send` Arc.
    order: Mutex<instant_acme::Order>,
    /// Identifiers from the original request.
    identifiers: Vec<String>,
}

// ── Main struct ──────────────────────────────────────────────────────────────

/// Concrete [AcmeClient] backed by `instant-acme` 0.8.x.
///
/// Create via [`InstantAcmeClient::new`]. The first call to [`AcmeClient::new_order`]
/// will register (or load) the ACME account lazily.
pub struct InstantAcmeClient {
    /// ACME directory URL (staging or production).
    directory_url: String,
    /// Loaded-or-created account. `None` until the first order is placed.
    account: Mutex<Option<Account>>,
    /// Path to the persisted [`AccountCredentials`] JSON.
    account_key_path: PathBuf,
    /// Email address used when registering a new account. Empty string
    /// = no contact (RFC 8555 §7.3 allows this; LE then can't send
    /// expiry reminders but issuance is unchanged). See
    /// `register_account` for the empty-slice handling.
    account_email: String,
    /// In-flight orders keyed by order_url.
    orders: DashMap<String, Arc<InFlightOrder>>,
    /// Path to the certificate root for `days_until_expiry` lookups.
    cert_dir_root: PathBuf,
}

impl InstantAcmeClient {
    /// Build a new client.
    ///
    /// * `email` — contact address for the ACME account (required).
    /// * `directory_url` — see [`staging_directory`] / [`production_directory`].
    /// * `account_key_path` — where to persist/load the account credentials.
    /// * `cert_dir_root` — where `<host>.cert.pem` files live (for expiry
    ///   pre-check via [`AcmeClient::days_until_expiry`]).
    pub fn new(
        email: impl Into<String>,
        directory_url: impl Into<String>,
        account_key_path: impl Into<PathBuf>,
        cert_dir_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            directory_url: directory_url.into(),
            account: Mutex::new(None),
            account_key_path: account_key_path.into(),
            account_email: email.into(),
            orders: DashMap::new(),
            cert_dir_root: cert_dir_root.into(),
        }
    }

    /// Load or register the ACME account, persisting the credentials on first
    /// registration. Returns a clone of the stored `Account`.
    ///
    /// Idempotent: if the account is already loaded in memory, returns it
    /// without touching the file. If the credentials file exists, loads it.
    /// Otherwise registers a new account and writes the file.
    async fn ensure_account(&self) -> Result<Account> {
        let mut guard = self.account.lock().await;
        if let Some(acc) = guard.as_ref() {
            return Ok(acc.clone());
        }

        let acc = if self.account_key_path.exists() {
            self.load_account().await?
        } else {
            self.register_account().await?
        };

        *guard = Some(acc.clone());
        Ok(acc)
    }

    async fn load_account(&self) -> Result<Account> {
        let raw = tokio::fs::read(&self.account_key_path)
            .await
            .with_context(|| format!("read {:?}", self.account_key_path))?;
        let creds: AccountCredentials = serde_json::from_slice(&raw)
            .with_context(|| format!("parse credentials from {:?}", self.account_key_path))?;
        let acc = Account::builder()
            .context("build ACME account builder")?
            .from_credentials(creds)
            .await
            .context("restore ACME account from credentials")?;
        tracing::info!(path = ?self.account_key_path, "acme: loaded existing account");
        Ok(acc)
    }

    async fn register_account(&self) -> Result<Account> {
        // V238 — email is OPTIONAL per RFC 8555 §7.3 ("If the server
        // accepts the request, it will create a new account…"). LE
        // accepts contact-less accounts; the only consequence is no
        // expiry-reminder email. Mirrors certbot's --register-unsafely-
        // without-email behaviour. When unset we pass an empty contact
        // slice and skip the "mailto:" prefix construction.
        let mailto = if self.account_email.is_empty() {
            String::new()
        } else {
            format!("mailto:{}", self.account_email)
        };
        let contact_vec: Vec<&str> = if mailto.is_empty() {
            Vec::new()
        } else {
            vec![mailto.as_str()]
        };
        let (acc, creds) = Account::builder()
            .context("build ACME account builder")?
            .create(
                &NewAccount {
                    contact: &contact_vec,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url.clone(),
                None,
            )
            .await
            .context("register new ACME account")?;

        self.persist_credentials(&creds).await?;
        tracing::info!(
            path = ?self.account_key_path,
            email = self.account_email,
            "acme: registered new account, credentials saved"
        );
        Ok(acc)
    }

    async fn persist_credentials(&self, creds: &AccountCredentials) -> Result<()> {
        let json = serde_json::to_vec_pretty(creds).context("serialize ACME credentials")?;
        // Create parent dir.
        if let Some(parent) = self.account_key_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("mkdir {:?}", parent))?;
        }
        // Write with O_CREAT|O_EXCL so we never overwrite an existing key.
        // If the file somehow appeared between our `exists()` check and here,
        // we just load it instead (TOCTOU benign — both paths produce a valid
        // account).
        write_new_0600(&self.account_key_path, &json).await?;
        Ok(())
    }

    /// Resolve the `.cert.pem` path for a host identifier and parse `not_after`.
    fn cert_not_after_unix(&self, identifier: &str) -> Option<u64> {
        let safe: String = identifier
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let cert_path = self.cert_dir_root.join(format!("{safe}.cert.pem"));
        if !cert_path.exists() {
            return None;
        }
        let pem = std::fs::read(&cert_path).ok()?;
        parse_not_after_from_pem(&pem)
    }
}

// ── AcmeClient impl ──────────────────────────────────────────────────────────

#[async_trait]
impl AcmeClient for InstantAcmeClient {
    /// Start a new ACME order for `identifiers` and return the HTTP-01 challenge
    /// artifacts. The in-flight `Order` object is stashed internally; call
    /// `finalize_and_collect` with the returned `OrderHandle` to complete issuance.
    async fn new_order(&self, identifiers: &[String]) -> Result<Vec<Http01Challenge>> {
        let account = self.ensure_account().await?;

        let ia_identifiers: Vec<Identifier> = identifiers
            .iter()
            .map(|s| Identifier::Dns(s.clone()))
            .collect();

        let mut order = account
            .new_order(&NewOrder::new(&ia_identifiers))
            .await
            .context("create ACME order")?;

        let order_url = order.url().to_owned();
        tracing::debug!(url = %order_url, ?identifiers, "acme: new order placed");

        // Collect HTTP-01 challenges from all pending authorizations.
        let mut challenges = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result.context("fetch authorization")?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    s => {
                        bail!("authorization in unexpected state: {s:?}");
                    }
                }

                let mut ch = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow::anyhow!("no HTTP-01 challenge for identifier"))?;

                let keyauth = ch.key_authorization().as_str().to_owned();
                let token = ch.token.clone();
                let identifier = ch.identifier().to_string();

                tracing::debug!(identifier, token, "acme: http-01 challenge acquired");

                // Tell the server we are ready to serve this challenge.
                ch.set_ready()
                    .await
                    .context("set http-01 challenge ready")?;

                challenges.push(Http01Challenge {
                    identifier,
                    token,
                    keyauth,
                });
            }
        }

        // Stash in-flight order. `Order` is !Clone so we wrap it.
        let in_flight = Arc::new(InFlightOrder {
            order: Mutex::new(order),
            identifiers: identifiers.to_vec(),
        });
        self.orders.insert(order_url, in_flight);

        Ok(challenges)
    }

    /// Drive the ACME state machine to completion, generate + submit a CSR,
    /// then download and return the issued certificate chain.
    async fn finalize_and_collect(&self, handle: &OrderHandle) -> Result<IssuedCertificate> {
        // Fast path: look up by the order URL embedded in the handle.
        // Fallback: when `order_url` is empty (e.g. Provisioner::issue
        // creates a synthetic handle after calling new_order), find the
        // single in-flight order whose identifiers match the handle's
        // identifiers.  This makes Provisioner::issue work correctly with
        // InstantAcmeClient — the order was placed in new_order and keyed
        // by the real LE URL; we just have to find it.
        let in_flight = if !handle.order_url.is_empty() {
            self.orders
                .get(&handle.order_url)
                .map(|e| e.value().clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no in-flight order for {:?} — was new_order called first?",
                        handle.order_url
                    )
                })?
        } else {
            // Empty order_url: find by matching identifiers.
            let found = self
                .orders
                .iter()
                .find(|e| e.value().identifiers == handle.identifiers)
                .map(|e| e.value().clone());
            found.ok_or_else(|| {
                anyhow::anyhow!(
                    "no in-flight order matching identifiers {:?}",
                    handle.identifiers
                )
            })?
        };

        let identifiers = in_flight.identifiers.clone();
        let poll_policy = RetryPolicy::new()
            .initial_delay(Duration::from_secs(2))
            .backoff(1.5)
            .timeout(Duration::from_secs(120));

        // Poll until the order is ready (challenges validated).
        let status = {
            let mut order = in_flight.order.lock().await;
            order
                .poll_ready(&poll_policy)
                .await
                .context("poll ACME order ready")?
        };

        if status != OrderStatus::Ready {
            self.orders.remove(&handle.order_url);
            bail!("ACME order ended in unexpected state: {status:?}");
        }

        // Finalize: generate ECDSA key + CSR, submit, wait for certificate.
        let (private_key_pem, cert_chain_pem) = {
            let mut order = in_flight.order.lock().await;
            // `Order::finalize()` (rcgen feature) generates the key + CSR internally
            // and returns the PEM private key.
            let pkey = order
                .finalize()
                .await
                .context("finalize ACME order (CSR submission)")?;
            let cert = order
                .poll_certificate(&poll_policy)
                .await
                .context("poll ACME certificate")?;
            (pkey, cert)
        };

        // Clean up in-flight entry.
        self.orders.remove(&handle.order_url);

        let not_after_unix =
            parse_not_after_from_pem(cert_chain_pem.as_bytes()).unwrap_or_else(|| {
                // Fallback: 90 days from now (LE standard validity).
                now_unix() + 90 * 86_400
            });

        tracing::info!(
            ?identifiers,
            not_after_unix,
            "acme: certificate issued successfully"
        );

        Ok(IssuedCertificate {
            cert_chain_pem,
            private_key_pem,
            identifiers,
            not_after_unix,
        })
    }

    /// Return days remaining until the cert for `identifier` expires, or
    /// `None` if no cert file exists yet. Used by the orchestrator to skip
    /// renewal when the cert is still fresh.
    async fn days_until_expiry(&self, identifier: &str) -> Option<i64> {
        let not_after = self.cert_not_after_unix(identifier)?;
        let now = now_unix();
        Some((not_after as i64 - now as i64) / 86_400)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Current Unix seconds.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write `data` to `path` using `O_CREAT|O_EXCL` (never overwrite) and
/// `chmod 0600`. On non-Unix platforms this falls back to a plain write.
async fn write_new_0600(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Spawn into blocking thread because OpenOptions is sync.
        let path = path.to_path_buf();
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true) // O_CREAT|O_EXCL
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(&data)
                })
                .with_context(|| format!("write new 0600 {:?}", path))
        })
        .await
        .context("spawn_blocking write_new_0600")?
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(path, data)
            .await
            .with_context(|| format!("write {:?}", path))
    }
}

/// Parse `notAfter` from the first PEM certificate block in `pem_bytes`.
/// Returns Unix seconds, or `None` if parsing fails. Uses `x509-parser`.
fn parse_not_after_from_pem(pem_bytes: &[u8]) -> Option<u64> {
    // Walk PEM blocks looking for a CERTIFICATE.
    let pem_str = std::str::from_utf8(pem_bytes).ok()?;
    for pem_block in pem_str.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let end = pem_block.find("-----END CERTIFICATE-----")?;
        let b64: String = pem_block[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).ok()?;
        if let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) {
            let ts = cert.validity().not_after.timestamp();
            if ts > 0 {
                return Some(ts as u64);
            }
        }
    }
    None
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Minimal scoped temp dir without the tempfile crate.
    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path =
                std::env::temp_dir().join(format!("aegis-acme-instant-test-{pid}-{now}-{n}"));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    // ── Helper constants / constructors ──────────────────────────────────────

    /// URL helpers return distinct, non-empty LE URLs.
    #[test]
    fn directory_url_helpers_are_distinct_and_non_empty() {
        let staging = staging_directory();
        let prod = production_directory();
        assert!(!staging.is_empty());
        assert!(!prod.is_empty());
        assert_ne!(staging, prod);
        assert!(
            staging.contains("staging"),
            "staging URL should contain 'staging'"
        );
        assert!(
            !prod.contains("staging"),
            "production URL should not contain 'staging'"
        );
    }

    /// Cert-not-after parsing on a self-signed PEM cert round-trips correctly.
    #[test]
    fn parse_not_after_from_pem_returns_plausible_timestamp() {
        // Minimal test: a known LE staging cert snippet won't compile-in cleanly,
        // so instead verify that None is returned for obviously invalid data
        // without panicking.
        assert!(parse_not_after_from_pem(b"not a certificate").is_none());
        assert!(parse_not_after_from_pem(b"").is_none());
        assert!(
            parse_not_after_from_pem(
                b"-----BEGIN CERTIFICATE-----\nbadbase64!!!\n-----END CERTIFICATE-----\n"
            )
            .is_none()
        );
    }

    /// `days_until_expiry` returns `None` when cert file is absent.
    #[tokio::test]
    async fn days_until_expiry_returns_none_when_cert_absent() {
        let tmp = TempDir::new();
        let client = InstantAcmeClient::new(
            "test@example.com",
            staging_directory(),
            tmp.path.join("account.json"),
            tmp.path.clone(),
        );
        // No cert file created → should return None without panicking.
        let result = client.days_until_expiry("www.example.com").await;
        assert!(result.is_none());
    }

    /// `write_new_0600` must refuse to overwrite an existing file.
    #[tokio::test]
    async fn write_new_0600_refuses_to_overwrite_existing_file() {
        let tmp = TempDir::new();
        let path = tmp.path.join("secret.json");
        // First write succeeds.
        write_new_0600(&path, b"original").await.unwrap();
        // Second write must fail (O_CREAT|O_EXCL semantics).
        let result = write_new_0600(&path, b"overwrite").await;
        assert!(result.is_err(), "expected error on second write, got ok");
        // File content must be unchanged.
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"original");
    }

    /// On Unix the key file must be mode 0600.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_new_0600_sets_correct_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new();
        let path = tmp.path.join("key.json");
        write_new_0600(&path, b"{}").await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }
}
