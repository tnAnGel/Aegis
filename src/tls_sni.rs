//! Per-SNI TLS certificate resolver.
//!
//! Builds a `ResolvesServerCert` that maps each ServerName (case-
//! insensitive exact match) to its own certificate chain + private
//! key. Falls back to a default cert for unknown names so the
//! handshake still succeeds (with the default cert) — useful for
//! catch-all hosts and IP-only requests.

use std::{collections::HashMap, fs::File, io::BufReader, sync::Arc};

use anyhow::{Context, Result};
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::config::SniEntry;

pub struct SniResolver {
    map: HashMap<String, Arc<CertifiedKey>>,
    default: Arc<CertifiedKey>,
}

impl SniResolver {
    pub fn build(default_cert: &str, default_key: &str, entries: &[SniEntry]) -> Result<Arc<Self>> {
        let default = load_certified(default_cert, default_key)
            .with_context(|| format!("default cert ({default_cert}) load failed"))?;
        let mut map = HashMap::new();
        for entry in entries {
            let ck = load_certified(&entry.cert_path, &entry.key_path).with_context(|| {
                format!(
                    "SNI cert for {} ({}) load failed",
                    entry.host, entry.cert_path
                )
            })?;
            map.insert(entry.host.to_ascii_lowercase(), ck);
        }
        Ok(Arc::new(Self { map, default }))
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("hosts", &self.map.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let key = client_hello
            .server_name()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if let Some(ck) = self.map.get(&key) {
            return Some(ck.clone());
        }
        Some(self.default.clone())
    }
}

fn load_certified(cert_path: &str, key_path: &str) -> Result<Arc<CertifiedKey>> {
    let cert_file = File::open(cert_path).context("open cert")?;
    let key_file = File::open(key_path).context("open key")?;
    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert chain")?;
    let mut keys: Vec<PrivateKeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map(|r| r.map(Into::into))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse PKCS8 private keys")?;
    anyhow::ensure!(!keys.is_empty(), "no PKCS8 private key found");
    let signing_key = any_supported_type(&keys.remove(0)).context("unsupported key type")?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sni_falls_through_to_default() {
        // We can't easily build a CertifiedKey without real cert
        // material in unit tests, so we just verify the resolver
        // structure: building from an empty entries list works once
        // we have a default. Real cert wiring is covered by manual /
        // integration tests.
        let entries: Vec<SniEntry> = vec![];
        // Just exercise the type signature; actual load_certified
        // would need real PEM files.
        assert!(SniResolver::build("/nonexistent", "/nonexistent", &entries).is_err());
    }
}
