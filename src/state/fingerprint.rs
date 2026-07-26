//! Per-connection fingerprint cache.
//!
//! JA4 and JA4T are computed once per connection (TLS accept / TCP
//! accept) but the handler that needs them runs once per request and
//! doesn't carry connection-scoped state through hyper's service
//! abstraction. We bridge that by stashing the latest fingerprint for
//! a client IP+port pair in this cache; the handler reads it back on
//! every request.
//!
//! Entries are short-lived — the cache exists per-process and gets
//! pruned on a timer. A small TTL is fine: a connection lives for
//! seconds-to-minutes, and as long as the fingerprint outlives the
//! TCP/TLS handshake long enough for the first request to read it,
//! we're good. Stale entries that miss are harmless (the handler
//! treats None as "no fingerprint available").

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

#[derive(Debug, Clone, Default)]
pub struct ConnectionFingerprint {
    pub ja4: Option<String>,
    pub ja4t: Option<String>,
    /// TLS-latency string `client_ms_server_ms` — see
    /// `crate::ja4::compute_ja4l`.
    pub ja4l: Option<String>,
    /// HTTP/2 Akamai-style fingerprint (full form: `settings|wu|prio|pseudo`).
    pub h2fp: Option<String>,
    /// HTTP/3 / QUIC fingerprint (`q{version}{alpn}_{params_hash}`).
    pub h3fp: Option<String>,
    /// mTLS client-certificate fingerprint (`mtls_{kty}{len}{san}{policy}_{leaf}`).
    pub mtls_fp: Option<String>,
    pub recorded_at: Option<Instant>,
}

#[derive(Default)]
pub struct FingerprintCache {
    inner: Arc<DashMap<(IpAddr, u16), ConnectionFingerprint>>,
}

impl FingerprintCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_ja4(&self, peer: IpAddr, port: u16, ja4: String) {
        let mut entry = self.inner.entry((peer, port)).or_default();
        entry.ja4 = Some(ja4);
        entry.recorded_at = Some(Instant::now());
    }

    pub fn record_ja4t(&self, peer: IpAddr, port: u16, ja4t: String) {
        let mut entry = self.inner.entry((peer, port)).or_default();
        entry.ja4t = Some(ja4t);
        entry.recorded_at = Some(Instant::now());
    }

    pub fn record_ja4l(&self, peer: IpAddr, port: u16, ja4l: String) {
        let mut entry = self.inner.entry((peer, port)).or_default();
        entry.ja4l = Some(ja4l);
        entry.recorded_at = Some(Instant::now());
    }

    pub fn record_h2fp(&self, peer: IpAddr, port: u16, h2fp: String) {
        let mut entry = self.inner.entry((peer, port)).or_default();
        entry.h2fp = Some(h2fp);
        entry.recorded_at = Some(Instant::now());
    }

    pub fn record_h3fp(&self, peer: IpAddr, port: u16, h3fp: String) {
        let mut entry = self.inner.entry((peer, port)).or_default();
        entry.h3fp = Some(h3fp);
        entry.recorded_at = Some(Instant::now());
    }

    pub fn record_mtls_fp(&self, peer: IpAddr, port: u16, mtls_fp: String) {
        let mut entry = self.inner.entry((peer, port)).or_default();
        entry.mtls_fp = Some(mtls_fp);
        entry.recorded_at = Some(Instant::now());
    }

    pub fn lookup(&self, peer: IpAddr, port: u16) -> Option<ConnectionFingerprint> {
        self.inner.get(&(peer, port)).map(|kv| kv.clone())
    }

    /// Drop entries whose recorded_at is older than `stale`. Called
    /// from the background cleanup task.
    pub fn cleanup_stale(&self, now: Instant, stale: Duration) {
        self.inner.retain(|_, v| {
            v.recorded_at
                .map(|t| now.duration_since(t) <= stale)
                .unwrap_or(false)
        });
    }

    pub fn entry_count(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_reads_ja4() {
        let c = FingerprintCache::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        c.record_ja4(ip, 4444, "t13d1516h2_aaa_bbb".to_string());
        let fp = c.lookup(ip, 4444).unwrap();
        assert_eq!(fp.ja4.as_deref(), Some("t13d1516h2_aaa_bbb"));
        assert!(fp.ja4t.is_none());
    }

    #[test]
    fn cleanup_drops_stale() {
        let c = FingerprintCache::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        c.record_ja4(ip, 1, "x".into());
        assert_eq!(c.entry_count(), 1);
        c.cleanup_stale(
            Instant::now() + Duration::from_secs(60),
            Duration::from_secs(5),
        );
        assert_eq!(c.entry_count(), 0);
    }
}
