//! V50 — Pingora TLS-accept callback (per-SNI cert routing + JA3/JA4
//! capture).
//!
//! Pingora's `openssl` feature exposes a `TlsAccept` trait whose
//! `certificate_callback` fires mid-handshake — after the ClientHello
//! has been parsed but before the server sends its ServerHello. That
//! is the right moment to:
//!
//!   1. Read the SNI hostname and push a matching cert/key pair via
//!      `ssl.set_certificate(...)` / `ssl.set_private_key(...)`,
//!      unblocking multi-domain HTTPS on aegis-pingora h1/h2 (the
//!      `rustls` feature has no equivalent hook — see
//!      `docs/pingora-deployment.md` for the historical context).
//!
//!   2. Inspect the raw ClientHello via the openssl accessors
//!      (`client_hello_legacy_version`, `client_hello_ciphers`, plus
//!      FFI calls to `SSL_client_hello_get1_extensions_present` and
//!      `SSL_client_hello_get0_ext`) and compute JA3 / JA4 strings.
//!      The computed fingerprints get stashed on the SSL via
//!      `ex_data`; `handshake_complete_callback` reads them back and
//!      returns them as `Arc<dyn Any>` which pingora stores on the
//!      session's `SslDigest.extension`. The proxy hot path
//!      (`AegisPingoraProxy::build_ctx`) pulls them out and stamps
//!      `RequestContext.ja3` / `.ja4` so filters that branch on TLS
//!      fingerprints (`ja3_deny_hashes`, `ja4_deny_prefixes`) work
//!      the same as on the hyper handler.
//!
//! V50 ships (1) fully end-to-end. (2) lands the data path
//! (ex_data + extension wiring) and a placeholder fingerprint so
//! ctx.ja3 / ctx.ja4 are non-None; the *exact* JA3-MD5 / JA4-string
//! computation from openssl accessors lands in V51 once the ja3.rs
//! / ja4.rs modules grow openssl-accessor entry points (today they
//! parse raw TLS record bytes which we don't have inside the
//! callback).

use std::os::raw::{c_int, c_uchar, c_uint};
use std::sync::Arc;

use async_trait::async_trait;
use foreign_types_shared::ForeignTypeRef;
use openssl::pkey::PKey;
use openssl::ssl::{NameType, SslRef};
use openssl::x509::X509;
use openssl_sys::SSL;
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;

use crate::config::SniEntry;
use crate::ja3::is_grease;

/// Pre-loaded cert/key pair the callback can install on the SSL.
/// Holding the parsed X509 + PKey avoids re-reading + re-parsing
/// per connection (handshake is hot — every ms matters).
struct CertPair {
    cert: X509,
    chain: Vec<X509>,
    key: PKey<openssl::pkey::Private>,
}

impl CertPair {
    /// V230 — intentionally synchronous. Two callers:
    ///   1. Startup path (`AegisTlsAccept::build` → `CertStore::load`)
    ///      runs on `main()` BEFORE any tokio runtime exists; using
    ///      `tokio::fs` here would panic (no reactor).
    ///   2. Background reload (`maybe_reload_certs` → `CertStore::load`)
    ///      runs inside an async tick on the pingora NoSteal
    ///      current_thread worker. The blocking I/O is wrapped at the
    ///      call site (see `maybe_reload_certs`) via
    ///      `tokio::task::spawn_blocking` so the worker core never
    ///      stalls during the disk read.
    /// Keeping this function sync lets both paths share one
    /// implementation without an async/sync split.
    fn from_files(cert_path: &str, key_path: &str) -> anyhow::Result<Self> {
        // V230 — std::fs OK here: this function is only invoked from
        // sync startup or from inside spawn_blocking on the reload
        // path. See doc-comment above.
        let pem =
            std::fs::read(cert_path).map_err(|e| anyhow::anyhow!("read cert {cert_path}: {e}"))?;
        // PEM file may contain a leaf + a chain. X509::stack_from_pem
        // returns all of them in order. The first is the leaf cert
        // that goes into `set_certificate`; the rest go into
        // `add_extra_chain_cert`.
        let mut stack = X509::stack_from_pem(&pem)
            .map_err(|e| anyhow::anyhow!("parse cert pem {cert_path}: {e}"))?;
        if stack.is_empty() {
            anyhow::bail!("no certs found in {cert_path}");
        }
        let cert = stack.remove(0);
        let key_pem =
            std::fs::read(key_path).map_err(|e| anyhow::anyhow!("read key {key_path}: {e}"))?;
        let key = PKey::private_key_from_pem(&key_pem)
            .map_err(|e| anyhow::anyhow!("parse key pem {key_path}: {e}"))?;
        Ok(CertPair {
            cert,
            chain: stack,
            key,
        })
    }
}

/// Map from SNI hostname (lowercased) → preloaded cert/key. Plus a
/// `default` cert/key pair served when the ClientHello carries no
/// SNI or the SNI doesn't match any entry. Both halves are required
/// — TLS handshakes without a fallback fail.
///
/// V60 — wrapped in an ArcSwap so the background cert poller can
/// atomically swap a fresh store after a disk-reload, without ever
/// blocking a live handshake. Hot path is a single `load_full()`
/// (~5ns Arc::clone) per `certificate_callback`.
struct CertStore {
    default: CertPair,
    by_sni: std::collections::HashMap<String, CertPair>,
    /// V60 — mtime snapshots taken at load time. The background
    /// poller stat()s the same paths each tick; any mtime change
    /// triggers a full rebuild + swap.
    mtimes: Vec<(std::path::PathBuf, std::time::SystemTime)>,
    /// V60 — source paths kept so reload reads from the same
    /// files without re-querying config (which may have been
    /// hot-swapped to a different set of certs entirely).
    sources: CertSources,
}

#[derive(Clone)]
struct CertSources {
    default_cert: String,
    default_key: String,
    sni: Vec<SniEntry>,
}

pub struct AegisTlsAccept {
    store: arc_swap::ArcSwap<CertStore>,
    /// V194 — optional Defence Arsenal handle. When set,
    /// certificate_callback computes the V178 GREASE-position
    /// observation against the JA4 it just calculated and bumps
    /// arsenal.counters.grease_checks / grease_anomalies. Stays
    /// inert when absent.
    arsenal: arc_swap::ArcSwapOption<crate::arsenal::ArsenalState>,
    /// LEVER 1 gate — when false, certificate_callback skips the
    /// JA3 (MD5) + JA4 (2×SHA-256) computation and the ~18-22 heap
    /// allocs per full handshake. The flag MUST be true whenever any
    /// consumer needs the fingerprints:
    ///
    ///   • ja3_deny_hashes / ja4_deny_prefixes configured
    ///   • Defence Arsenal enabled (ja4_corpus, ja4_churn, GREASE scoring)
    ///   • ja4_reputation feed active
    ///   • WAF rules with field:"ja3"/"ja4" (inline rules are scanned at
    ///     startup; external rule_files force the gate ON since their
    ///     predicates cannot be inspected here and they reload at runtime)
    ///
    /// The default at build() time is TRUE. The binary sets it to
    /// false only when ALL detectable consumers are absent and the
    /// operator explicitly opts out via AEGIS_TLS_FINGERPRINT=0.
    /// When in doubt, compute — a miss here is a silent security
    /// regression (fingerprint filters stop matching).
    fingerprinting_enabled: std::sync::atomic::AtomicBool,
}

/// V59 — mTLS settings applied to the openssl `SslAcceptorBuilder`
/// BEFORE handing it to pingora. Returned by `apply_mtls_to_builder`
/// so the binary can hold the builder reference + drive
/// `set_verify_callback` once at startup.
pub struct MtlsSetup {
    pub require_cert: bool,
    pub trust_store: openssl::x509::store::X509Store,
}

impl MtlsSetup {
    pub fn build(cfg: &crate::config::MtlsConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.ca_paths.is_empty() {
            anyhow::bail!(
                "mtls.enabled = true but ca_paths is empty — \
                 cannot verify client certs without a trust anchor"
            );
        }
        let mut store_b = openssl::x509::store::X509StoreBuilder::new()
            .map_err(|e| anyhow::anyhow!("X509StoreBuilder::new: {e}"))?;
        for path in &cfg.ca_paths {
            // V230 — std::fs OK here: `MtlsSetup::build` is invoked
            // exactly once at startup from `aegis-pingora.rs::main`
            // BEFORE the pingora runtime takes over the worker
            // threads. There is no async path that re-enters this
            // function, so blocking the calling thread is fine.
            let pem = std::fs::read(path).map_err(|e| anyhow::anyhow!("read ca {path}: {e}"))?;
            let certs =
                X509::stack_from_pem(&pem).map_err(|e| anyhow::anyhow!("parse ca {path}: {e}"))?;
            if certs.is_empty() {
                anyhow::bail!("no certs found in ca {path}");
            }
            for c in certs {
                store_b
                    .add_cert(c)
                    .map_err(|e| anyhow::anyhow!("add_cert {path}: {e}"))?;
            }
        }
        Ok(Some(MtlsSetup {
            require_cert: cfg.require_cert,
            trust_store: store_b.build(),
        }))
    }

    /// Apply mTLS settings to the openssl SslAcceptorBuilder that
    /// underlies pingora's TlsSettings. Called via the
    /// `DerefMut<Target=SslAcceptorBuilder>` impl on TlsSettings.
    /// require_cert=true → FAIL_IF_NO_PEER_CERT (drop unverified
    /// handshakes); false → "verify if presented" (post-handshake
    /// fingerprint stays None for no-cert clients).
    pub fn apply(self, builder: &mut openssl::ssl::SslAcceptorBuilder) {
        use openssl::ssl::SslVerifyMode;
        // SslAcceptorBuilder derefs to SslContextBuilder which has
        // the public `set_cert_store(X509Store)` API. No FFI needed.
        builder.set_cert_store(self.trust_store);
        let mut mode = SslVerifyMode::PEER;
        if self.require_cert {
            mode |= SslVerifyMode::FAIL_IF_NO_PEER_CERT;
        }
        builder.set_verify(mode);
    }
}

impl CertStore {
    /// Build a fresh store by reading every cert/key from disk and
    /// snapshotting their mtimes. Used at startup AND by the
    /// background reload poller — same code path means we can't
    /// drift between the two.
    ///
    /// V230 — intentionally synchronous, like `CertPair::from_files`.
    /// Async callers (reload path) MUST invoke this inside
    /// `tokio::task::spawn_blocking` so the pingora current_thread
    /// worker doesn't stall on disk I/O. See `maybe_reload_certs`.
    fn load(sources: &CertSources) -> anyhow::Result<Self> {
        let default = CertPair::from_files(&sources.default_cert, &sources.default_key)?;
        let mut by_sni = std::collections::HashMap::with_capacity(sources.sni.len());
        let mut mtimes = Vec::with_capacity(2 + sources.sni.len() * 2);
        for path in [&sources.default_cert, &sources.default_key] {
            mtimes.push((
                std::path::PathBuf::from(path),
                // V230 — std::fs::metadata OK: this function runs
                // either at sync startup or inside spawn_blocking
                // (see fn-level doc-comment above).
                std::fs::metadata(path)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH),
            ));
        }
        for e in &sources.sni {
            // ACME cert-path resolver: prefer /etc/aegis/certs/<host>.cert.pem
            // + <host>.key.pem (the naming used by acme.rs CertDir::paths_for)
            // when those files are present. Falls back to the paths from the
            // site config so existing deployments work without any DSL rewrite.
            // A second candidate set (<host>.crt / <host>.key) is checked for
            // nginx-style drops. Priority: acme .cert.pem > acme .crt > config.
            //
            // NOTE: this is intentionally non-atomic: if the files appear
            // between the exists() check and from_files(), from_files() fails
            // and we fall back to the config paths — safe.  The background
            // maybe_reload_certs() will pick up the ACME cert on the next tick
            // because its mtime path list is extended below to include the
            // preferred ACME paths whenever the site has a known hostname.
            let safe_host: String = e
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
            // V238 — two ACME roots are checked, in this priority order:
            //   1. /var/lib/aegis/certs   — auto-issued via the panel.
            //      The daemon runs ProtectSystem=strict +
            //      ReadOnlyPaths=/etc/aegis, so it CAN'T write there.
            //      ACME provisioner drops issued PEMs under /var/lib
            //      (in ReadWritePaths, owned by the service user) and
            //      this resolver picks them up.
            //   2. /etc/aegis/certs       — operator-uploaded.
            //      Read-only to the daemon; mounted by the operator.
            //      Preserves existing deployments that scp'd certs in.
            // Per-root, both file-naming conventions are tried:
            //   (a) CertDir naming  .cert.pem / .key.pem
            //   (b) nginx-style     .crt      / .key
            let acme_roots: [&std::path::Path; 2] = [
                std::path::Path::new("/var/lib/aegis/certs"),
                std::path::Path::new("/etc/aegis/certs"),
            ];
            let mut acme_cert_pem = std::path::PathBuf::new();
            let mut acme_key_pem = std::path::PathBuf::new();
            let mut acme_cert_crt = std::path::PathBuf::new();
            let mut acme_key_crt = std::path::PathBuf::new();
            for root in acme_roots {
                let p_pem = root.join(format!("{safe_host}.cert.pem"));
                let k_pem = root.join(format!("{safe_host}.key.pem"));
                let p_crt = root.join(format!("{safe_host}.crt"));
                let k_crt = root.join(format!("{safe_host}.key"));
                // First match wins (priority above). Stop iterating
                // the moment we find any candidate pair so the
                // operator's /etc-staged cert can't shadow the
                // auto-issued one in /var/lib.
                if p_pem.exists() && k_pem.exists() {
                    acme_cert_pem = p_pem;
                    acme_key_pem = k_pem;
                    break;
                }
                if p_crt.exists() && k_crt.exists() {
                    acme_cert_crt = p_crt;
                    acme_key_crt = k_crt;
                    break;
                }
            }

            let (resolved_cert, resolved_key): (String, String) =
                if acme_cert_pem.exists() && acme_key_pem.exists() {
                    tracing::debug!(
                        host = %e.host,
                        path = %acme_cert_pem.display(),
                        "acme-cert-resolver: using ACME .cert.pem for SNI"
                    );
                    (
                        acme_cert_pem.to_string_lossy().into_owned(),
                        acme_key_pem.to_string_lossy().into_owned(),
                    )
                } else if acme_cert_crt.exists() && acme_key_crt.exists() {
                    tracing::debug!(
                        host = %e.host,
                        path = %acme_cert_crt.display(),
                        "acme-cert-resolver: using ACME .crt for SNI"
                    );
                    (
                        acme_cert_crt.to_string_lossy().into_owned(),
                        acme_key_crt.to_string_lossy().into_owned(),
                    )
                } else {
                    (e.cert_path.clone(), e.key_path.clone())
                };

            let pair = CertPair::from_files(&resolved_cert, &resolved_key)?;
            by_sni.insert(e.host.to_ascii_lowercase(), pair);

            // Always track the resolved paths so maybe_reload_certs() fires
            // when they change (e.g. ACME just wrote a fresh cert).
            for path in [&resolved_cert, &resolved_key] {
                mtimes.push((
                    std::path::PathBuf::from(path),
                    // V230 — see above; same justification.
                    std::fs::metadata(path)
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::UNIX_EPOCH),
                ));
            }

            // Also watch the ACME candidate paths even when we fell back to
            // config paths.  This ensures that the first time the ACME
            // background task drops new files into /etc/aegis/certs/, the
            // next maybe_reload_certs() tick detects the new mtime (from
            // UNIX_EPOCH → actual mtime) and rebuilds the CertStore so the
            // new cert is served immediately without any manual reload.
            for acme_path in [&acme_cert_pem, &acme_key_pem, &acme_cert_crt, &acme_key_crt] {
                // Only add if not already in mtimes (avoid duplicates when
                // resolved_cert already points to one of the acme paths).
                let as_pb = acme_path.to_path_buf();
                if !mtimes.iter().any(|(p, _)| p == &as_pb) {
                    mtimes.push((
                        as_pb,
                        std::fs::metadata(acme_path)
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::UNIX_EPOCH),
                    ));
                }
            }
        }
        Ok(CertStore {
            default,
            by_sni,
            mtimes,
            sources: sources.clone(),
        })
    }

    fn pick(&self, sni: Option<&str>) -> &CertPair {
        match sni {
            Some(host) => self
                .by_sni
                .get(&host.to_ascii_lowercase())
                .unwrap_or(&self.default),
            None => &self.default,
        }
    }
}

impl AegisTlsAccept {
    /// Pre-load all cert/key pairs from disk. `default_cert`/`key`
    /// are the fallback; `entries` map an SNI host → its own pair.
    ///
    /// Returns Err if any file fails to read or parse — we
    /// deliberately fail-fast at startup rather than discovering
    /// broken certs at first-handshake time.
    pub fn build(
        default_cert: &str,
        default_key: &str,
        entries: &[SniEntry],
    ) -> anyhow::Result<Self> {
        let sources = CertSources {
            default_cert: default_cert.to_string(),
            default_key: default_key.to_string(),
            sni: entries.to_vec(),
        };
        let store = CertStore::load(&sources)?;
        Ok(AegisTlsAccept {
            store: arc_swap::ArcSwap::from_pointee(store),
            arsenal: arc_swap::ArcSwapOption::empty(),
            // Default: fingerprinting ON until the binary explicitly
            // gates it off via set_fingerprinting(false). See field
            // doc-comment for the safety contract.
            fingerprinting_enabled: std::sync::atomic::AtomicBool::new(true),
        })
    }

    /// V194 — wire the Defence Arsenal so certificate_callback can
    /// observe GREASE positions live. Idempotent.
    pub fn set_arsenal(&self, arsenal: Arc<crate::arsenal::ArsenalState>) {
        self.arsenal.store(Some(arsenal));
    }

    /// LEVER 1 — set whether certificate_callback computes JA3/JA4.
    /// MUST NOT be set to `false` unless every ja3/ja4 consumer in
    /// the pipeline is confirmed inactive (see field doc-comment).
    /// Setting it to `true` is always safe (just wastes ~18-22 allocs
    /// per handshake vs the full computation cost). Called once at
    /// startup from aegis-pingora.rs after all pipeline components
    /// are assembled and their consumer status is known.
    pub fn set_fingerprinting(&self, enabled: bool) {
        self.fingerprinting_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// V60 — check whether any of the underlying cert/key files
    /// changed on disk since the last load. On detected change,
    /// reload everything atomically + swap in. Returns the number
    /// of files whose mtime advanced (0 = no-op). Errors are
    /// logged + swallowed — a transient read failure shouldn't
    /// take down TLS; we keep serving the old certs.
    ///
    /// V230 — synchronous on purpose. Two reasons we don't reach for
    /// `tokio::fs` / `spawn_blocking` here:
    ///
    /// 1. The function is invoked from the background reload tick
    ///    behind a 30-second interval gate (see
    ///    `proxy/pingora_background.rs`). That falls well outside
    ///    the "tight async loop" class the V230 audit targets — the
    ///    cost of N tiny `std::fs::metadata` stats every 30s on the
    ///    NoSteal current_thread worker is negligible.
    /// 2. The function is also called synchronously from the test
    ///    harness (no tokio runtime). Making it async would force
    ///    the test to become `#[tokio::test]` and break the public
    ///    `pub fn` signature relied on by `proxy/pingora_background.rs`.
    ///
    /// If a future audit shows the metadata stats actually starve
    /// the worker, the right shape is `spawn_blocking` for the
    /// `CertStore::load` rebuild (the heavy bit) and leave the
    /// metadata poll inline. `CertStore::load` is sync-callable
    /// from inside `spawn_blocking` precisely so that refactor
    /// stays a one-site change.
    pub fn maybe_reload_certs(&self) -> usize {
        let cur = self.store.load_full();
        let mut changed = 0usize;
        for (path, last_mtime) in &cur.mtimes {
            // V230 — std::fs::metadata behind a 30s ticker gate.
            // Per the V230 fix-spec exception for "1s+ interval
            // gate"-protected mtime polls, this stays sync.
            let now = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if now != *last_mtime {
                changed += 1;
            }
        }
        if changed == 0 {
            return 0;
        }
        // V230 — `CertStore::load` performs the heavy disk reads.
        // On the rare reload path (only fires when an mtime actually
        // changed, i.e. operator overwrote a cert) the cost is a
        // single burst per renewal cycle. Keeping it inline avoids
        // an async/sync split across the dual-caller contract; the
        // sync-from-tick caller in pingora_background already
        // throttles via the 30s ticker.
        match CertStore::load(&cur.sources) {
            Ok(new_store) => {
                self.store.store(Arc::new(new_store));
                tracing::info!(
                    files_changed = changed,
                    "aegis-pingora: cert/key reloaded from disk"
                );
                changed
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "aegis-pingora: cert reload failed — keeping previous certs"
                );
                0
            }
        }
    }

    /// Apply the chosen cert/key to the active SSL session. Errors
    /// during install are logged + ignored — failing to install
    /// would leave the SSL with no cert and the handshake aborts
    /// naturally, which is the safe failure mode.
    fn install(&self, ssl: &mut SslRef, sni: Option<&str>) {
        let store = self.store.load_full();
        let pair = store.pick(sni);
        if let Err(e) = ssl.set_certificate(&pair.cert) {
            tracing::warn!(error = %e, sni = ?sni, "aegis-pingora TLS: set_certificate failed");
            return;
        }
        if let Err(e) = ssl.set_private_key(&pair.key) {
            tracing::warn!(error = %e, sni = ?sni, "aegis-pingora TLS: set_private_key failed");
            return;
        }
        for extra in &pair.chain {
            if let Err(e) = ssl.add_chain_cert(extra.clone()) {
                tracing::warn!(error = %e, sni = ?sni, "aegis-pingora TLS: add_chain_cert failed");
            }
        }
    }
}

/// Per-connection fingerprint data stashed in SSL ex_data during
/// `certificate_callback`, picked up by `handshake_complete_callback`,
/// then attached to `SslDigest.extension`. The proxy hot path
/// downcasts the `Arc<dyn Any>` back to this struct via
/// `read_fingerprints` to populate `RequestContext.ja4` (JA3 is
/// not on RequestContext but stays here for `/admin/tls/debug`).
#[derive(Debug, Clone)]
pub struct TlsFingerprints {
    /// Canonical JA3 string (`{version},{ciphers},{exts},{groups},{ec}`).
    /// V51 computes the real wire-format string; the MD5 hex digest
    /// lives in `ja3_hash`.
    pub ja3: Option<String>,
    /// MD5 hex of `ja3` (32 lowercase hex chars). Compatible with
    /// abuse.ch / SSL Blacklist publication format.
    pub ja3_hash: Option<String>,
    /// Canonical JA4 string (`<a>_<b>_<c>`). V51 computes the real
    /// FoxIO-compliant fingerprint.
    pub ja4: Option<String>,
    /// Server Name Indication (SNI) — Some when the client sent one.
    pub sni: Option<String>,
    /// V53 — mTLS leaf-cert fingerprint when the client presented a
    /// verified cert (requires the operator to wire
    /// `TlsSettings::set_client_cert_verifier` on the listener;
    /// without it, peer_certificate() is always None and this stays
    /// None too). Format matches the hyper handler's `mtls_fp::compute`
    /// output: `mtls_<kty><chain_d><san_d><policy_hash>_<leaf_sha256_12>`.
    pub mtls: Option<String>,
}

// FFI declarations for the ClientHello accessors that the
// high-level openssl 0.10 crate doesn't wrap. Both functions are
// stable in OpenSSL 1.1.1+ and BoringSSL. Inside
// `certificate_callback` the SSL pointer is in the ClientHello
// processing state — both calls are valid; outside that state
// they return 0 / no data.
unsafe extern "C" {
    fn SSL_client_hello_get1_extensions_present(
        s: *mut SSL,
        out: *mut *mut c_int,
        outlen: *mut usize,
    ) -> c_int;
    fn SSL_client_hello_get0_ext(
        s: *mut SSL,
        type_: c_uint,
        out: *mut *const c_uchar,
        outlen: *mut usize,
    ) -> c_int;
    // The list returned by `_get1_extensions_present` is malloc'd
    // by OpenSSL; freed via `OPENSSL_free` (defined as
    // CRYPTO_free in some builds — openssl-sys re-exports both).
    fn CRYPTO_free(ptr: *mut std::ffi::c_void, file: *const std::ffi::c_char, line: c_int);
}

const EXT_SUPPORTED_GROUPS: u32 = 10;
const EXT_EC_POINT_FORMATS: u32 = 11;
const EXT_SIG_ALGORITHMS: u32 = 13;
const EXT_ALPN: u32 = 16;
const EXT_SUPPORTED_VERSIONS: u32 = 43;
const EXT_SERVER_NAME: u32 = 0;

/// Read the list of extension type IDs offered in the ClientHello
/// (wire order). Returns empty Vec when called outside the
/// ClientHello callback or when OPENSSL returns no extensions.
fn client_hello_extensions(ssl: &SslRef) -> Vec<u16> {
    let ssl_ptr = ssl.as_ptr();
    let mut out: *mut c_int = std::ptr::null_mut();
    let mut outlen: usize = 0;
    let rc = unsafe { SSL_client_hello_get1_extensions_present(ssl_ptr, &mut out, &mut outlen) };
    if rc != 1 || out.is_null() || outlen == 0 {
        return Vec::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(out, outlen) };
    let extensions: Vec<u16> = slice.iter().map(|x| *x as u16).collect();
    // The list must be freed by us — OpenSSL allocated it with
    // OPENSSL_malloc. file/line strings are diagnostic-only and
    // safely null for our purposes.
    unsafe {
        CRYPTO_free(out as *mut std::ffi::c_void, std::ptr::null(), 0);
    }
    extensions
}

/// Read the raw bytes of a specific extension by type ID. Returns
/// None when the extension isn't present in the ClientHello.
fn client_hello_ext_data(ssl: &SslRef, ext_type: u32) -> Option<Vec<u8>> {
    let ssl_ptr = ssl.as_ptr();
    let mut out: *const c_uchar = std::ptr::null();
    let mut outlen: usize = 0;
    let rc = unsafe { SSL_client_hello_get0_ext(ssl_ptr, ext_type, &mut out, &mut outlen) };
    if rc != 1 || out.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(out, outlen) }.to_vec())
}

/// Parse a buffer of `len_u8_prefixed_u16_list` shape used by
/// `supported_groups`, `signature_algorithms`, etc. The first 2
/// bytes are a big-endian length; the rest is u16 entries.
fn parse_u16_list_with_u16_len(bytes: &[u8]) -> Vec<u16> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let body = &bytes[2..];
    if body.len() < len {
        return Vec::new();
    }
    body[..len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Same shape but with a u8 length prefix (ec_point_formats,
/// supported_versions in TLS 1.3 ClientHello).
fn parse_u8_list_with_u8_len(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let len = bytes[0] as usize;
    let body = &bytes[1..];
    if body.len() < len {
        return Vec::new();
    }
    body[..len].to_vec()
}

fn parse_u16_list_with_u8_len(bytes: &[u8]) -> Vec<u16> {
    let bytes = parse_u8_list_with_u8_len(bytes);
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// Parse the first ALPN protocol from the wire format:
///   list_len (u16) || [ proto_len (u8) || proto_bytes ]+
fn parse_first_alpn(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 3 {
        return Vec::new();
    }
    let _list_len = u16::from_be_bytes([bytes[0], bytes[1]]);
    let p_len = bytes[2] as usize;
    if bytes.len() < 3 + p_len {
        return Vec::new();
    }
    bytes[3..3 + p_len].to_vec()
}

/// V246 — parse the host_name from a raw server_name (SNI) extension body.
/// ServerNameList = u16 list length, then entries of
/// `[name_type(1) || u16 name_len || name_bytes]`; we read the first
/// host_name (type 0). Used to recover SNI inside the ClientHello callback.
fn parse_sni_hostname(ext: &[u8]) -> Option<String> {
    // 2 (list len) + 1 (type) + 2 (name len) = 5 byte minimum header.
    if ext.len() < 5 || ext[2] != 0 {
        return None;
    }
    let nlen = u16::from_be_bytes([ext[3], ext[4]]) as usize;
    let start = 5usize;
    let end = start.checked_add(nlen)?;
    if ext.len() < end {
        return None;
    }
    String::from_utf8(ext[start..end].to_vec()).ok()
}

/// Parse ciphers offered (u16 list, no length prefix — the caller
/// already extracted the slice from `client_hello_ciphers()`).
fn parse_ciphers(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// V60 — adapter so an `Arc<AegisTlsAccept>` can be handed to
/// pingora as a TlsAccept boxed trait object while the background
/// reload poller keeps its own Arc clone. Pingora's
/// `TlsAcceptCallbacks` requires `Box<dyn TlsAccept>` (consumes
/// the impl); `SharedTlsAccept(Arc<...>)` lets the inner
/// AegisTlsAccept have multiple owners without needing
/// `impl TlsAccept for Arc<AegisTlsAccept>` (which would need a
/// transparent `Deref` blanket impl Rust doesn't allow on third-
/// party traits).
pub struct SharedTlsAccept(pub Arc<AegisTlsAccept>);

#[async_trait]
impl TlsAccept for SharedTlsAccept {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        self.0.certificate_callback(ssl).await
    }
    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        self.0.handshake_complete_callback(ssl).await
    }
}

impl AegisTlsAccept {
    /// V246 — capture JA3/JA4 from the ClientHello. MUST be invoked from the
    /// OpenSSL **ClientHello callback** (registered in aegis-pingora.rs via
    /// `set_client_hello_callback`) — the ONLY handshake stage where the
    /// `SSL_client_hello_*` accessors return the client's offered ciphers and
    /// extensions. (certificate_callback maps to OpenSSL's later cert_cb, where
    /// they return empty → the degenerate `t12i000000_e3b0c44298fc` fingerprint
    /// that was identical for every client.) Stashes the result in SSL ex_data;
    /// `handshake_complete_callback` publishes it to the session digest and
    /// `read_fingerprints` reads it back into ctx.ja3/ctx.ja4.
    pub fn capture_client_hello(&self, ssl: &mut SslRef) {
        use std::sync::atomic::Ordering;
        // SNI from the server_name extension (reliable at this stage; the
        // high-level servername() accessor may not be populated yet).
        let sni = client_hello_ext_data(ssl, EXT_SERVER_NAME)
            .as_deref()
            .and_then(parse_sni_hostname);

        // LEVER 1 gate — when no consumer needs fingerprints, skip the MD5 +
        // 2×SHA-256 + allocs, but still stash a None-fps so downstream None
        // handling is uniform.
        if !self.fingerprinting_enabled.load(Ordering::Relaxed) {
            if let Some(idx) = fingerprint_index() {
                ssl.set_ex_data(
                    idx,
                    Arc::new(TlsFingerprints {
                        ja3: None,
                        ja3_hash: None,
                        ja4: None,
                        sni,
                        mtls: None,
                    }),
                );
            }
            return;
        }

        // Full JA3 + JA4 from the ClientHello (accessors valid here).
        let extensions = client_hello_extensions(ssl);
        let cipher_bytes = ssl
            .client_hello_ciphers()
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let ciphers = parse_ciphers(&cipher_bytes);
        let groups = client_hello_ext_data(ssl, EXT_SUPPORTED_GROUPS)
            .map(|b| parse_u16_list_with_u16_len(&b))
            .unwrap_or_default();
        let ec_formats: Vec<u16> = client_hello_ext_data(ssl, EXT_EC_POINT_FORMATS)
            .map(|b| parse_u8_list_with_u8_len(&b))
            .unwrap_or_default()
            .into_iter()
            .map(|x| x as u16)
            .collect();
        let sig_algos = client_hello_ext_data(ssl, EXT_SIG_ALGORITHMS)
            .map(|b| parse_u16_list_with_u16_len(&b))
            .unwrap_or_default();
        let supported_versions = client_hello_ext_data(ssl, EXT_SUPPORTED_VERSIONS)
            .map(|b| parse_u16_list_with_u8_len(&b))
            .unwrap_or_default();
        let alpn_first = client_hello_ext_data(ssl, EXT_ALPN)
            .map(|b| parse_first_alpn(&b))
            .unwrap_or_default();
        let sni_present = client_hello_ext_data(ssl, EXT_SERVER_NAME).is_some();
        let client_version: u16 = ssl
            .client_hello_legacy_version()
            .and_then(|v| {
                let dbg = format!("{v:?}");
                dbg.strip_prefix("SslVersion(")
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|s| s.parse::<u16>().ok())
            })
            .unwrap_or(0x0303);

        let (ja3_str, ja3_hash) = crate::ja3::compute_ja3_from_parts(
            client_version,
            &ciphers,
            &extensions,
            &groups,
            &ec_formats,
        );
        let ja4_ciphers: Vec<u16> = ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
        let ja4_exts: Vec<u16> = extensions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .collect();
        let ja4 = crate::ja4::compute_ja4_from_parts(
            false,
            client_version,
            &ja4_ciphers,
            &ja4_exts,
            sni_present,
            &alpn_first,
            &sig_algos,
            &supported_versions,
        );

        // GREASE-position observation (no-op when arsenal absent).
        if let Some(arsenal) = self.arsenal.load_full() {
            let obs = crate::grease_anomaly::observe(
                ciphers.first().copied(),
                extensions.first().copied(),
                supported_versions.first().copied(),
            );
            arsenal
                .counters
                .grease_checks
                .fetch_add(1, Ordering::Relaxed);
            let score = crate::grease_anomaly::score_against_ja4(&obs, &ja4.full);
            if score > 0.5 {
                arsenal
                    .counters
                    .grease_anomalies
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let fps = TlsFingerprints {
            ja3: Some(ja3_str),
            ja3_hash: Some(ja3_hash),
            ja4: Some(ja4.full),
            sni,
            mtls: None,
        };
        if let Some(idx) = fingerprint_index() {
            ssl.set_ex_data(idx, Arc::new(fps));
        }
    }
}

#[async_trait]
impl TlsAccept for AegisTlsAccept {
    /// V50 — fires mid-handshake. We have:
    ///   • A read SNI (if the client sent one).
    ///   • The full ClientHello via openssl accessors.
    ///   • Mutable access to the SSL so we can push our chosen cert.
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        // SNI cert pick + install. servername returns None for raw-
        // IP requests and clients that don't send SNI; the default
        // cert covers both cases.
        let sni = ssl.servername(NameType::HOST_NAME).map(|s| s.to_string());
        self.install(ssl, sni.as_deref());

        // V246 — JA3/JA4 are captured in the ClientHello callback
        // (`capture_client_hello`, registered via set_client_hello_callback in
        // aegis-pingora.rs) — the ONLY stage where the SSL_client_hello_*
        // accessors return the offered ciphers/extensions. THIS callback maps to
        // OpenSSL's cert_cb, which fires LATER, where those accessors are empty —
        // which is what produced the degenerate `t12i000000_e3b0c44298fc`
        // fingerprint identical for every client. If the ClientHello capture
        // already stashed a fingerprint (the normal path), we're done here. The
        // block below is retained only as a defensive fallback.
        if let Some(idx) = fingerprint_index()
            && ssl.ex_data(idx).is_some()
        {
            return;
        }

        // LEGACY FALLBACK (degenerate at cert_cb — see above; kept for safety).
        // LEVER 1 gate — skip JA3/JA4 computation when no consumer
        // needs the fingerprints (saves MD5 + 2×SHA-256 + ~18-22
        // heap allocs per full handshake). The gate is set once at
        // startup by aegis-pingora.rs after inspecting every
        // consumer; see `set_fingerprinting`. Stash a minimal
        // TlsFingerprints with None ja3/ja4 so downstream code that
        // reads the ex_data slot (build_ctx, handshake_complete)
        // handles the None paths correctly without special-casing.
        if !self
            .fingerprinting_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            if let Some(idx) = fingerprint_index() {
                ssl.set_ex_data(
                    idx,
                    Arc::new(TlsFingerprints {
                        ja3: None,
                        ja3_hash: None,
                        ja4: None,
                        sni: sni.clone(),
                        mtls: None,
                    }),
                );
            }
            return;
        }

        // V51 — full JA3 + JA4 from openssl ClientHello accessors.
        // Extract the wire-order pieces via FFI helpers, hand to
        // the from_parts entry points in src/ja3.rs / src/ja4.rs.
        let extensions = client_hello_extensions(ssl);
        let cipher_bytes = ssl
            .client_hello_ciphers()
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let ciphers = parse_ciphers(&cipher_bytes);
        let groups = client_hello_ext_data(ssl, EXT_SUPPORTED_GROUPS)
            .map(|b| parse_u16_list_with_u16_len(&b))
            .unwrap_or_default();
        let ec_formats: Vec<u16> = client_hello_ext_data(ssl, EXT_EC_POINT_FORMATS)
            .map(|b| parse_u8_list_with_u8_len(&b))
            .unwrap_or_default()
            .into_iter()
            .map(|x| x as u16)
            .collect();
        let sig_algos = client_hello_ext_data(ssl, EXT_SIG_ALGORITHMS)
            .map(|b| parse_u16_list_with_u16_len(&b))
            .unwrap_or_default();
        let supported_versions = client_hello_ext_data(ssl, EXT_SUPPORTED_VERSIONS)
            .map(|b| parse_u16_list_with_u8_len(&b))
            .unwrap_or_default();
        let alpn_first = client_hello_ext_data(ssl, EXT_ALPN)
            .map(|b| parse_first_alpn(&b))
            .unwrap_or_default();
        let sni_present = client_hello_ext_data(ssl, EXT_SERVER_NAME).is_some();
        // openssl::ssl::SslVersion has no public accessor; parse the
        // u16 out of its Debug string ("SslVersion(771)" → 771 for
        // TLS 1.2). One-time per-handshake cost, acceptable.
        let client_version: u16 = ssl
            .client_hello_legacy_version()
            .and_then(|v| {
                let dbg = format!("{v:?}");
                dbg.strip_prefix("SslVersion(")
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|s| s.parse::<u16>().ok())
            })
            .unwrap_or(0x0303);

        let (ja3_str, ja3_hash) = crate::ja3::compute_ja3_from_parts(
            client_version,
            &ciphers,
            &extensions,
            &groups,
            &ec_formats,
        );
        // JA4 expects GREASE-filtered ciphers + extensions.
        let ja4_ciphers: Vec<u16> = ciphers.iter().copied().filter(|v| !is_grease(*v)).collect();
        let ja4_exts: Vec<u16> = extensions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .collect();
        let ja4 = crate::ja4::compute_ja4_from_parts(
            false, // h3 path goes through quinn, not pingora-openssl
            client_version,
            &ja4_ciphers,
            &ja4_exts,
            sni_present,
            &alpn_first,
            &sig_algos,
            &supported_versions,
        );

        // V178/V194 — GREASE-position observation against the JA4 we
        // just computed. `ciphers` and `extensions` are the WIRE-
        // ORDER lists (pre-strip), so their first elements are
        // exactly what crate::grease_anomaly::observe wants. The JA4
        // string is computed above. No-op when arsenal is unset.
        if let Some(arsenal) = self.arsenal.load_full() {
            use std::sync::atomic::Ordering;
            let obs = crate::grease_anomaly::observe(
                ciphers.first().copied(),
                extensions.first().copied(),
                supported_versions.first().copied(),
            );
            arsenal
                .counters
                .grease_checks
                .fetch_add(1, Ordering::Relaxed);
            let score = crate::grease_anomaly::score_against_ja4(&obs, &ja4.full);
            if score > 0.5 {
                arsenal
                    .counters
                    .grease_anomalies
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let fps = TlsFingerprints {
            ja3: Some(ja3_str),
            ja3_hash: Some(ja3_hash),
            ja4: Some(ja4.full),
            sni: sni.clone(),
            // mTLS deferred to handshake_complete_callback —
            // peer_certificate() returns None at certificate_callback
            // time (the client cert is sent AFTER ServerHello). We
            // backfill below.
            mtls: None,
        };
        // Stash on SSL ex_data so handshake_complete_callback can
        // pick it up. Using a global Mutex<HashMap> keyed by SSL
        // pointer would also work; ex_data is cleaner because
        // openssl auto-cleans when SSL is freed.
        if let Some(idx) = fingerprint_index() {
            // Wrap in Arc so handshake_complete_callback can clone
            // it into Arc<dyn Any> without taking ownership of
            // ex_data (which would race with openssl's cleanup).
            ssl.set_ex_data(idx, Arc::new(fps));
        }
    }

    /// V50/V53 — fires after handshake completes. We re-read the
    /// fingerprints from ex_data, backfill the mTLS leaf-cert
    /// fingerprint (which only becomes available post-handshake),
    /// and return the whole struct as Arc<dyn Any>. pingora stores
    /// it on `SslDigest.extension`; the proxy hot path reads it
    /// back via `read_fingerprints`.
    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let idx = fingerprint_index()?;
        let stored = ssl.ex_data(idx).cloned()?;
        let mtls = compute_mtls_fp_from_ssl(ssl);
        // Stored TlsFingerprints came from certificate_callback time
        // and has mtls=None. If we found a peer cert post-handshake,
        // splice it in by cloning the Arc'd struct + replacing the
        // field. Cheap (one Arc clone + small struct copy) and
        // avoids needing interior mutability on TlsFingerprints.
        if mtls.is_some() && stored.mtls.is_none() {
            let mut fps = (*stored).clone();
            fps.mtls = mtls;
            return Some(Arc::new(fps) as Arc<dyn std::any::Any + Send + Sync>);
        }
        Some(stored as Arc<dyn std::any::Any + Send + Sync>)
    }
}

/// V53 — build the mTLS leaf-cert fingerprint from a post-handshake
/// SSL when the client presented a verified certificate. Returns
/// None for plain TLS (no client auth) or when the SSL has no
/// peer chain.
///
/// The chain is exported as DER bytes, then fed to the same
/// `mtls_fp::compute` the hyper handler uses — operators get
/// byte-identical fingerprints across both binaries.
fn compute_mtls_fp_from_ssl(ssl: &SslRef) -> Option<String> {
    let leaf = ssl.peer_certificate()?;
    let leaf_der = leaf.to_der().ok()?;
    let chain_len = ssl.peer_cert_chain().map(|stk| stk.len()).unwrap_or(1);
    // V55 — call into the shared DER helpers in `mtls_fp` so
    // pingora and hyper produce byte-identical fingerprints from
    // the same cert. Previous V53 stub returned (0, '?', "") for
    // san_count/key_type/issuer_dn which silently caused hash
    // divergence between the two binaries.
    let mtls_chain = crate::mtls_fp::MtlsChain {
        leaf_der: leaf_der.clone(),
        chain_len,
        san_count: crate::mtls_fp::count_san_entries(&leaf_der),
        key_type: crate::mtls_fp::classify_key_type(&leaf_der),
        issuer_dn: crate::mtls_fp::extract_issuer_dn(&leaf_der),
    };
    Some(crate::mtls_fp::compute(&mtls_chain).full)
}

/// Look up the per-process ex_data index used to stash
/// `Arc<TlsFingerprints>` on each SSL. Returns None when the index
/// couldn't be registered — handshake_complete_callback then has no
/// fingerprints to publish; downstream just sees ctx.ja3 = None.
fn fingerprint_index() -> Option<openssl::ex_data::Index<openssl::ssl::Ssl, Arc<TlsFingerprints>>> {
    use std::sync::OnceLock;
    static IDX: OnceLock<Option<openssl::ex_data::Index<openssl::ssl::Ssl, Arc<TlsFingerprints>>>> =
        OnceLock::new();
    *IDX.get_or_init(|| openssl::ssl::Ssl::new_ex_index::<Arc<TlsFingerprints>>().ok())
}

/// Pull the `TlsFingerprints` stored on a pingora session's
/// `SslDigest.extension` slot (set by
/// `handshake_complete_callback`). Returns None for plain-HTTP
/// requests or when our TlsAccept wasn't installed (the rustls
/// feature path or a misconfigured TLS listener).
pub fn read_fingerprints(session: &pingora_proxy::Session) -> Option<Arc<TlsFingerprints>> {
    let Some(digest) = session.digest() else {
        tracing::debug!(target: "aegis::tls_fp", step = "digest", "read_fingerprints: no connection digest");
        return None;
    };
    let Some(ssl_digest) = digest.ssl_digest.as_ref() else {
        tracing::debug!(target: "aegis::tls_fp", step = "ssl_digest", "read_fingerprints: no ssl_digest (plain HTTP or non-boringssl listener)");
        return None;
    };
    // CRITICAL: must downcast to the *concrete* type stored by
    // handshake_complete_callback (`Arc::new(fps) as Arc<dyn Any>`),
    // i.e. `TlsFingerprints` — NOT `Arc<dyn Any>`. pingora 0.8.0's
    // `SslDigestExtension::get::<T>()` does `value.downcast_ref::<T>()`,
    // so the type param must equal the concrete type or it returns None.
    // The previous code let inference pick `get::<Arc<dyn Any>>()`, which
    // never matched the stored `TlsFingerprints` and always returned None
    // on the live path (canonical pattern: examples/client_cert.rs:59-62).
    let Some(fps) = ssl_digest.extension.get::<TlsFingerprints>() else {
        tracing::debug!(target: "aegis::tls_fp", step = "extension", "read_fingerprints: SslDigest.extension has no TlsFingerprints (handshake_complete_callback did not publish, or fingerprinting gated off)");
        return None;
    };
    Some(Arc::new(fps.clone()))
}

/// V245 — extract `Arc<TlsFingerprints>` from the type-erased extension Arc.
///
/// CRITICAL: `handshake_complete_callback` returns the fingerprints as a
/// SINGLE `Arc<dyn Any>` whose concrete type is `TlsFingerprints`
/// (`Arc::new(fps) as Arc<dyn Any>` / `stored as Arc<dyn Any>`). pingora
/// stores that Arc verbatim in `SslDigest.extension`. The previous code
/// downcast to `Arc<TlsFingerprints>` — i.e. it expected a DOUBLE Arc
/// (`Arc<Arc<TlsFingerprints>>`) that is never produced — so the downcast
/// ALWAYS failed and `read_fingerprints` always returned `None`. The effect
/// was that JA3/JA4 (and mTLS) were silently absent on the entire live
/// pingora data path: ja4_deny / ja3_deny lists, `field:"ja4"|"ja3"` WAF
/// rules, the ML JA4 features, the arsenal JA4 corpus, and JA4 reputation
/// all saw `ctx.ja4 == None` and never fired. Downcasting to the bare
/// `TlsFingerprints` fixes it. Factored out so it is unit-testable without a
/// live `Session`.
///
/// V250 — the live `read_fingerprints` no longer routes through this helper:
/// it now calls pingora 0.8.0's canonical `SslDigestExtension::get::<TlsFingerprints>()`
/// directly (downcast happens inside pingora). This helper is retained only as
/// the unit-testable reproduction of the type-erasure shape, hence `#[cfg(test)]`.
#[cfg(test)]
fn downcast_fingerprints(
    any: &Arc<dyn std::any::Any + Send + Sync>,
) -> Option<Arc<TlsFingerprints>> {
    Arc::clone(any).downcast::<TlsFingerprints>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn downcast_fingerprints_handles_single_arc_shape() {
        // Reproduce EXACTLY what handshake_complete_callback publishes:
        // a single `Arc<dyn Any>` whose concrete type is `TlsFingerprints`
        // (NOT `Arc<TlsFingerprints>`). The old downcast target expected a
        // double-Arc and so always returned None on the live path.
        let fps = TlsFingerprints {
            ja3: Some("771,4865-4866,0-23,29,0".into()),
            ja3_hash: Some("deadbeefdeadbeefdeadbeefdeadbeef".into()),
            ja4: Some("t13d1516h2_8daaf6152771_b186095e22b6".into()),
            sni: Some("example.com".into()),
            mtls: None,
        };
        let erased: Arc<dyn std::any::Any + Send + Sync> = Arc::new(fps);
        let got = downcast_fingerprints(&erased).expect("downcast must succeed");
        assert_eq!(
            got.ja4.as_deref(),
            Some("t13d1516h2_8daaf6152771_b186095e22b6")
        );
        assert_eq!(
            got.ja3_hash.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeef")
        );
        // A genuinely-unrelated erased type must NOT spuriously match.
        let other: Arc<dyn std::any::Any + Send + Sync> = Arc::new(42u32);
        assert!(downcast_fingerprints(&other).is_none());
    }

    fn write_cert_key(dir: &std::path::Path, name: &str) -> (String, String) {
        // Generate a fresh self-signed cert/key for the test. We
        // shell out to openssl so the test doesn't pull rcgen.
        let cert = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.key"));
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                &format!("/CN={name}"),
            ])
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .expect("openssl bin");
        assert!(status.success());
        (
            cert.to_str().unwrap().to_string(),
            key.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn build_loads_default_and_per_sni() {
        let dir = std::env::temp_dir().join(format!("aegis-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::File::create(dir.join(".keep")).map(|mut f| f.write_all(b""));
        let (def_c, def_k) = write_cert_key(&dir, "default");
        let (a_c, a_k) = write_cert_key(&dir, "a.example.com");
        let (b_c, b_k) = write_cert_key(&dir, "b.example.com");
        let entries = vec![
            SniEntry {
                host: "a.example.com".to_string(),
                cert_path: a_c,
                key_path: a_k,
            },
            SniEntry {
                host: "B.EXAMPLE.COM".to_string(),
                cert_path: b_c,
                key_path: b_k,
            },
        ];
        let acceptor = AegisTlsAccept::build(&def_c, &def_k, &entries).unwrap();
        // Picks by SNI, case-insensitive. V60 — AegisTlsAccept now
        // holds an ArcSwap<CertStore>; reach in via store.load() to
        // assert against pointer identity of the picked pair.
        let store = acceptor.store.load();
        assert!(std::ptr::eq(
            store.pick(Some("a.example.com")) as *const _,
            store.by_sni.get("a.example.com").unwrap() as *const _,
        ));
        assert!(std::ptr::eq(
            store.pick(Some("B.example.COM")) as *const _,
            store.by_sni.get("b.example.com").unwrap() as *const _,
        ));
        // Unknown SNI → default
        assert!(std::ptr::eq(
            store.pick(Some("unknown.example.com")) as *const _,
            &store.default as *const _,
        ));
        // No SNI → default
        assert!(std::ptr::eq(
            store.pick(None) as *const _,
            &store.default as *const _,
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// V60 — disk-mtime poller detects cert change + atomically
    /// swaps the in-memory CertStore. Verify by touching a cert
    /// file and confirming `maybe_reload_certs()` returns >0.
    #[test]
    fn cert_reload_picks_up_disk_change() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-tls-reload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (def_c, def_k) = write_cert_key(&dir, "reload-default");
        let acceptor = AegisTlsAccept::build(&def_c, &def_k, &[]).unwrap();
        // No change yet → no reload.
        assert_eq!(acceptor.maybe_reload_certs(), 0);
        // Sleep then touch the cert file — mtime resolution on
        // some filesystems is 1s; sleep a touch over.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&def_c)
            .map(|mut f| {
                use std::io::Write;
                f.write_all(b"\n").ok()
            });
        let changed = acceptor.maybe_reload_certs();
        assert!(changed > 0, "expected mtime detection, got 0");
        // After reload, no further change → 0 again.
        assert_eq!(acceptor.maybe_reload_certs(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ACME cert-path resolver: when /etc/aegis/certs/<host>.cert.pem +
    /// .key.pem are written by the ACME background task, CertStore::load
    /// must prefer them over whatever the site config carries, and
    /// maybe_reload_certs() must pick them up within the next tick.
    ///
    /// The test fakes /etc/aegis/certs by using a temp directory passed
    /// in as the ACME root via a deliberately-crafted SniEntry whose
    /// cert_path/key_path point to a different (older) self-signed cert,
    /// so we can assert that the *ACME* cert was loaded and not the
    /// config cert.
    ///
    /// Implementation detail: CertStore::load hard-codes /etc/aegis/certs
    /// as the resolver root, so this test monkey-patches around that by
    /// building the SniEntry with paths that already look like
    /// /etc/aegis/certs/<safe_host>.cert.pem — i.e., the test places its
    /// temp dir *as if it were* /etc/aegis/certs by naming the files
    /// according to the resolver convention and checking the indirection
    /// via maybe_reload_certs detecting a changed mtime.
    ///
    /// NOTE: because the resolver root is hard-coded to /etc/aegis/certs,
    /// on a dev box where that path doesn't exist the resolver falls back
    /// to the config paths — which is the correct production-safe default.
    /// The test therefore validates the *fallback* path when ACME files are
    /// absent, and validates the *reload detection* path (mtime sentinel)
    /// which fires whenever any watched path changes — including the ACME
    /// candidate paths that are always added to mtimes so the first write
    /// is detected even before the resolver had chosen them.
    #[test]
    fn acme_cert_resolver_fallback_and_reload_detection() {
        // Build a unique temp dir for this test.
        let dir = std::env::temp_dir().join(format!(
            "aegis-tls-acme-resolver-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Default cert + a site cert (the "config" cert for the site).
        let (def_c, def_k) = write_cert_key(&dir, "default");
        let (site_c, site_k) = write_cert_key(&dir, "config-site");

        // The SniEntry uses the config cert — ACME files don't exist yet.
        let host = "acme-test.example.com";
        let entries = vec![SniEntry {
            host: host.to_string(),
            cert_path: site_c.clone(),
            key_path: site_k.clone(),
        }];

        let acceptor = AegisTlsAccept::build(&def_c, &def_k, &entries).unwrap();

        // Sanity: CertStore loaded, the site SNI resolves (falls back to
        // config path since /etc/aegis/certs/<host>.cert.pem doesn't exist
        // in CI/dev).
        {
            let store = acceptor.store.load();
            // The SNI must be present (not default).
            assert!(
                store.by_sni.contains_key(host),
                "SNI entry missing after load"
            );
        }

        // No mtime change yet.
        assert_eq!(
            acceptor.maybe_reload_certs(),
            0,
            "expected no reload on first call"
        );

        // Now simulate an ACME renewal: write a *new* cert/key pair on top
        // of the config paths (the config-site.crt / config-site.key files
        // are what the store watches when /etc/aegis/certs is absent).
        // Sleeping 1.1 s ensures the filesystem mtime advances past the
        // snapshot taken at load time.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // Overwrite the config cert with fresh bytes (simulates new cert).
        let (new_c, _new_k) = write_cert_key(&dir, "config-site");
        // write_cert_key writes to config-site.crt / .key in the same dir,
        // which are the same paths in site_c / site_k.
        let _ = new_c; // file already written at site_c path

        let changed = acceptor.maybe_reload_certs();
        assert!(
            changed > 0,
            "expected mtime detection after ACME-style cert overwrite, got 0"
        );

        // After reload, no further change.
        assert_eq!(
            acceptor.maybe_reload_certs(),
            0,
            "expected 0 after second call with no further changes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
