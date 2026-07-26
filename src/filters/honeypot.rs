//! TrafficFilter wrapper around `crate::honeypot::HoneypotStore`.
//!
//! Sits at the front of the pipeline (after threat_intel + ip_acl)
//! so a single map lookup terminates the request before any heavier
//! filter runs. Returns `FilterAction::Tarpit` on match — the proxy
//! handler turns that into a slow-drip `TarpitBody` response.

use std::sync::Arc;

use crate::{
    filters::{FilterAction, TrafficFilter},
    honeypot::{HoneypotDecision, HoneypotStore},
    proxy::request_context::RequestContext,
};

pub struct HoneypotFilter {
    store: Arc<HoneypotStore>,
}

impl HoneypotFilter {
    pub fn new(store: Arc<HoneypotStore>) -> Self {
        Self { store }
    }

    // V231 — `FilterEngine::new` seeds each engine toggle from
    // `config_enabled()`. HoneypotFilter has no filter-level on/off
    // flag: it is gated entirely by the `HoneypotStore`'s own `enabled`
    // state plus per-host pack config. So it registers its engine
    // toggle as `true` — the store decides matches, and operators can
    // still force it off per-domain from the web UI.
    pub fn config_enabled(&self) -> bool {
        true
    }
}

// V230 — hot-path audit: extract Tarpit construction into a `#[cold]`
// out-of-line helper, mirroring the ip_acl / threat_intel pattern. The
// overwhelming majority of requests miss the honeypot map and return
// `FilterAction::Allow`, so we keep the fast path's instruction-cache
// footprint minimal and let LLVM treat this branch as unlikely.
//
// V230 — the `reason` field is now a static `"honeypot match"` instead
// of `format!("honeypot match on {path}")`. The path is already logged
// separately by the engine/handler at deny time, and the previous
// `format!` allocated a `String` on every tarpit engagement. `reason`
// is `Cow<'static, str>` (V229 Tier 2), so the static literal is
// zero-alloc via `Cow::Borrowed`. `decision.server_header` stays a
// `String` upstream; `.into()` lifts it into `Cow::Owned` unchanged.
#[cold]
#[inline(never)]
fn tarpit_cold(decision: HoneypotDecision) -> FilterAction {
    FilterAction::Tarpit {
        duration_seconds: decision.tarpit_seconds,
        chunk_bytes: decision.tarpit_chunk_bytes,
        server_header: decision.server_header.into(),
        reason: "honeypot match".into(),
    }
}

impl TrafficFilter for HoneypotFilter {
    fn name(&self) -> &'static str {
        "honeypot"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // V236 — use the pre-extracted `ctx.host` field (populated once
        // at ingress by `build_ctx`) instead of re-hashing the HeaderMap
        // key and decoding the `HeaderValue` bytes on every request.
        // `ctx.host` carries exactly the same raw Host header value as
        // the old `headers.get("host")` lookup. The honeypot matcher
        // already lowercases internally, so the un-lowercased form here
        // is fine (identical to the previous `.unwrap_or("")` result).
        let Some(decision) = self.store.check(&ctx.host, &ctx.path) else {
            return FilterAction::Allow;
        };
        // Record the IP hit so the auto-XDP-deny path can fire after
        // the configured number of attempts. Scorer bump happens in
        // the handler so it can also issue the XDP deny call.
        // V230 — cold path: see `tarpit_cold` above.
        tarpit_cold(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-honeypot-filter-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn well_known_probe_path_returns_tarpit() {
        let p = tmp();
        let store = Arc::new(HoneypotStore::open(p.clone()).unwrap());
        let f = HoneypotFilter::new(store);
        let ctx = RequestContext::test_with("1.2.3.4", "/wp-login.php")
            .with_header("host", "example.com");
        match f.check(&ctx) {
            FilterAction::Tarpit {
                duration_seconds, ..
            } => {
                assert!(duration_seconds > 0);
            }
            other => panic!("expected tarpit, got {other:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn legitimate_path_passes() {
        let p = tmp();
        let store = Arc::new(HoneypotStore::open(p.clone()).unwrap());
        let f = HoneypotFilter::new(store);
        let ctx = RequestContext::test_with("1.2.3.4", "/api/users/me")
            .with_header("host", "example.com");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn per_host_override_short_circuits_match() {
        let p = tmp();
        let store = Arc::new(HoneypotStore::open(p.clone()).unwrap());
        store
            .set_host_pack("blog.example", "wordpress", false)
            .unwrap();
        let f = HoneypotFilter::new(store);
        let ctx = RequestContext::test_with("1.2.3.4", "/wp-login.php")
            .with_header("host", "blog.example");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }
}
