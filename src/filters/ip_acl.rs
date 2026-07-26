use std::collections::HashSet;

use crate::proxy::request_context::RequestContext;

use super::{FilterAction, TrafficFilter, parse_ip};

pub struct IpAclFilter {
    deny: HashSet<std::net::IpAddr>,
    allow: HashSet<std::net::IpAddr>,
}

impl IpAclFilter {
    pub fn new(deny: &[String], allow: &[String]) -> Self {
        let deny = deny.iter().filter_map(|i| parse_ip(i)).collect();
        let allow = allow.iter().filter_map(|i| parse_ip(i)).collect();
        Self { deny, allow }
    }

    // V231 — IpAcl has no on/off flag: it is always active when present, and
    // empty deny/allow lists are a no-op in `check()` anyway. So it seeds its
    // engine toggle as `true`. Operators can still force it off per-domain via
    // the web UI; `RuntimeToggles` remains the single source of truth at runtime.
    pub fn config_enabled(&self) -> bool {
        true
    }
}

// V230 — hot-path audit: extract Deny construction into a `#[cold]`
// out-of-line helper. The vast majority of requests hit `FilterAction::Allow`,
// so we want the Deny branches to act as branch-prediction hints and keep the
// fast path's instruction cache footprint minimal. `HashSet<IpAddr>` with the
// default SipHash hasher is intentional: IP keys come from untrusted clients,
// so the DoS-resistant hasher is the correct choice here. CIDR matching lives
// in `threat_intel.rs` and is deliberately not duplicated.
#[cold]
#[inline(never)]
fn deny_cold(reason: &'static str) -> FilterAction {
    FilterAction::Deny {
        status: 403,
        reason: reason.into(),
    }
}

impl TrafficFilter for IpAclFilter {
    fn name(&self) -> &'static str {
        "ip_acl"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        if self.deny.contains(&ctx.client_ip) {
            // V230 — cold path: see `deny_cold` above.
            return deny_cold("ip denied");
        }
        if !self.allow.is_empty() && !self.allow.contains(&ctx.client_ip) {
            // ACL is a hard gate. Returning a Challenge would mean an
            // attacker who can solve the JS challenge bypasses the
            // allowlist — that defeats the purpose of an allowlist.
            // V230 — cold path: see `deny_cold` above.
            return deny_cold("ip not in allowlist");
        }
        FilterAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_blocks() {
        let f = IpAclFilter::new(&["10.0.0.1".to_string()], &[]);
        let ctx = RequestContext::test_with("10.0.0.1", "/");
        matches!(f.check(&ctx), FilterAction::Deny { .. });
    }

    #[test]
    fn allow_list_denies_unknown() {
        let f = IpAclFilter::new(&[], &["10.0.0.2".to_string()]);
        let ctx = RequestContext::test_with("10.0.0.3", "/");
        assert!(matches!(
            f.check(&ctx),
            FilterAction::Deny { status: 403, .. }
        ));
    }

    #[test]
    fn allow_list_permits_known() {
        let f = IpAclFilter::new(&[], &["10.0.0.2".to_string()]);
        let ctx = RequestContext::test_with("10.0.0.2", "/");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }

    #[test]
    fn empty_lists_allow() {
        let f = IpAclFilter::new(&[], &[]);
        let ctx = RequestContext::test_with("1.2.3.4", "/");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }
}
