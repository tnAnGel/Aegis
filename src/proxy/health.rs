use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio::net::TcpStream;

use crate::proxy::upstream::SharedUpstreamRouter;

/// Health flag for a single upstream. We mark `since` so callers can
/// implement half-open behaviour later (try one probe after N seconds).
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
struct UnhealthyMark {
    since: Instant,
}

/// Per-upstream circuit breaker. A single failing backend only opens its
/// own circuit; the rest of the routing table keeps serving traffic.
#[derive(Clone)]
pub struct UpstreamHealth {
    router: SharedUpstreamRouter,
    unhealthy: Arc<DashMap<String, UnhealthyMark>>,
}

const HEALTH_KEY_DEFAULT: &str = "_default";

impl UpstreamHealth {
    pub fn new(router: SharedUpstreamRouter) -> Self {
        Self {
            router,
            unhealthy: Arc::new(DashMap::new()),
        }
    }

    fn key_for_host(&self, host: &str) -> String {
        if self.router.domain_upstreams.contains_key(host) {
            host.to_string()
        } else {
            HEALTH_KEY_DEFAULT.to_string()
        }
    }

    /// Returns true when the upstream serving `host` is currently
    /// circuit-broken. Empty/unknown host falls back to the default
    /// upstream's flag.
    pub fn circuit_open(&self, host: &str) -> bool {
        self.unhealthy.contains_key(&self.key_for_host(host))
    }

    pub fn mark_failure(&self, key: &str) {
        self.unhealthy.insert(
            key.to_string(),
            UnhealthyMark {
                since: Instant::now(),
            },
        );
    }

    pub fn mark_success(&self, key: &str) {
        self.unhealthy.remove(key);
    }

    pub fn snapshot(&self) -> Vec<(String, Duration)> {
        let now = Instant::now();
        self.unhealthy
            .iter()
            .map(|kv| (kv.key().clone(), now.duration_since(kv.value().since)))
            .collect()
    }

    pub fn spawn_checker(&self) {
        // V230 — active probing is opt-in. The in-band circuit breaker
        // (mark_failure on any upstream error) already handles eviction.
        // Enable AEGIS_UPSTREAM_HEALTHCHECK=1 for active probing on
        // deployments with intermittent backends that recover silently.
        if std::env::var("AEGIS_UPSTREAM_HEALTHCHECK").ok().as_deref() != Some("1") {
            tracing::debug!(
                "upstream health-check disabled (set AEGIS_UPSTREAM_HEALTHCHECK=1 to enable)"
            );
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            // V229 — tick 15s instead of 3s. The circuit breaker
            // already opens on any in-band failure (mark_failure), so
            // the proactive prober only needs to recover backends
            // that came back online while their circuit was open.
            // 3s × N upstreams × M workers added up to noticeable
            // background syscall load with no observable benefit.
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let mut all: HashMap<String, String> = HashMap::new();
                all.insert(
                    HEALTH_KEY_DEFAULT.to_string(),
                    this.router.default_upstream.authority.clone(),
                );
                for e in &this.router.domain_upstreams {
                    all.insert(e.0.clone(), e.1.authority.clone());
                }

                for (k, addr) in all {
                    if TcpStream::connect(&addr).await.is_ok() {
                        this.mark_success(&k);
                    } else {
                        this.mark_failure(&k);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::upstream::{Upstream, UpstreamRouter};

    fn router() -> SharedUpstreamRouter {
        let mut domains = HashMap::new();
        domains.insert(
            "api.example.com".to_string(),
            Upstream::from_url("http://127.0.0.1:9001").unwrap(),
        );
        Arc::new(UpstreamRouter {
            default_upstream: Upstream::from_url("http://127.0.0.1:9000").unwrap(),
            domain_upstreams: domains,
        })
    }

    #[test]
    fn unknown_host_uses_default_circuit() {
        let h = UpstreamHealth::new(router());
        h.mark_failure(HEALTH_KEY_DEFAULT);
        assert!(h.circuit_open("nope.example.com"));
        assert!(!h.circuit_open("api.example.com"));
    }

    #[test]
    fn per_domain_isolation() {
        let h = UpstreamHealth::new(router());
        h.mark_failure("api.example.com");
        assert!(h.circuit_open("api.example.com"));
        assert!(!h.circuit_open("other.example.com"));
    }

    #[test]
    fn success_clears_failure() {
        let h = UpstreamHealth::new(router());
        h.mark_failure("api.example.com");
        h.mark_success("api.example.com");
        assert!(!h.circuit_open("api.example.com"));
    }
}
