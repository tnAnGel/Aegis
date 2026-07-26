//! Trusted-source bypass for the entire L7 pipeline.
//!
//! Some endpoints legitimately look like attacks — payment-provider
//! webhooks (Stripe, PayPal), git host webhooks (GitHub, GitLab),
//! monitoring scrapers, internal batch jobs. Forcing those through
//! WAF + rate-limit + challenge produces churn without security
//! upside. Operators register them once here and the proxy short-
//! circuits the pipeline (after geo / smuggling gates, which still
//! run — those are too cheap and important to bypass).

use std::{collections::HashSet, net::IpAddr};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Anchored, Input, StartKind};

use crate::{config::BypassConfig, proxy::request_context::RequestContext};

pub struct BypassMatcher {
    ips: HashSet<IpAddr>,
    /// V230 — Aho-Corasick over path prefixes. Replaces the previous
    /// `Vec<String>` + linear `starts_with` scan with one Teddy-SIMD
    /// pass (NEON/AVX2) over the request path. `None` when no
    /// prefixes were configured — `AhoCorasick::build` rejects empty
    /// pattern sets, so we skip construction entirely and use
    /// `is_some()` for the activity check.
    path_prefix_ac: Option<AhoCorasick>,
    path_exacts: HashSet<String>,
    /// V230 — Aho-Corasick over UA substrings (lowercased at build
    /// time so we only lowercase the input string per request). `None`
    /// when no substrings were configured.
    ua_substring_ac: Option<AhoCorasick>,
}

impl BypassMatcher {
    pub fn new(cfg: &BypassConfig) -> Self {
        Self::with_extra_trusted_ips(cfg, std::iter::empty())
    }

    /// Build the matcher with both the operator-declared `bypass.ips`
    /// and an additional set of trusted IPs (typically those already
    /// permitted at the XDP layer via `xdp.allow`). Unifies the two
    /// trust surfaces: any IP an operator marks as kernel-level
    /// "always pass" also gets the userspace L7 fast-path, so a single
    /// "trusted" declaration short-circuits both layers. Eliminates
    /// the previous footgun where an IP could be XDP-allowed but
    /// still pay full WAF/rate/bot cost in userspace.
    pub fn with_extra_trusted_ips<I>(cfg: &BypassConfig, extra: I) -> Self
    where
        I: IntoIterator<Item = IpAddr>,
    {
        let mut path_prefixes: Vec<String> = Vec::new();
        let mut path_exacts = HashSet::new();
        for p in &cfg.paths {
            if let Some(prefix) = p.strip_suffix('*') {
                path_prefixes.push(prefix.to_string());
            } else {
                path_exacts.insert(p.clone());
            }
        }
        let mut ips: HashSet<IpAddr> = cfg.ips.iter().filter_map(|s| s.parse().ok()).collect();
        ips.extend(extra);

        // V230 — single Aho-Corasick pass over all prefixes, anchored
        // at offset 0 so a match equates to `starts_with`. Auto-selects
        // the Teddy backend on x86_64/aarch64 for short ASCII patterns.
        let path_prefix_ac = if path_prefixes.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .start_kind(StartKind::Anchored)
                    .build(&path_prefixes)
                    .expect("build bypass path-prefix automaton"),
            )
        };

        // V230 — single Aho-Corasick pass over the UA substring set.
        // Patterns are pre-lowercased so we only pay one lowercase per
        // request and the automaton itself stays case-sensitive (faster
        // than ascii_case_insensitive() in the auto-selected backend).
        let ua_patterns: Vec<String> = cfg
            .user_agents
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let ua_substring_ac = if ua_patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .build(&ua_patterns)
                    .expect("build bypass UA-substring automaton"),
            )
        };

        Self {
            ips,
            path_prefix_ac,
            path_exacts,
            ua_substring_ac,
        }
    }

    /// True when `ip` is in the static bypass set. Cheap IP-only
    /// check used by the proxy hot path before full context is
    /// materialised — lets us short-circuit expensive work (JA4H
    /// computation, etc.) for IPs we already know are trusted.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip)
    }

    /// True when this request should skip the L7 pipeline.
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        if self.ips.contains(&ctx.client_ip) {
            return true;
        }
        let bare = ctx.path.split('?').next().unwrap_or(&ctx.path);
        if self.path_exacts.contains(bare) {
            return true;
        }
        // V230 — anchored Aho-Corasick replaces the N-call linear scan.
        // `Anchored` forces matches to begin at offset 0, making the
        // semantics identical to `iter().any(|p| bare.starts_with(p))`.
        if let Some(ac) = &self.path_prefix_ac {
            if ac.is_match(Input::new(bare).anchored(Anchored::Yes)) {
                return true;
            }
        }
        if let Some(ac) = &self.ua_substring_ac {
            let ua = ctx.user_agent.as_deref().unwrap_or("").to_ascii_lowercase();
            // V230 — one Teddy/NFA pass over the UA in lieu of an
            // O(N*M) `contains` loop.
            if ac.is_match(ua.as_str()) {
                return true;
            }
        }
        false
    }

    pub fn is_active(&self) -> bool {
        !self.ips.is_empty()
            || !self.path_exacts.is_empty()
            || self.path_prefix_ac.is_some()
            || self.ua_substring_ac.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ips: &[&str], paths: &[&str], uas: &[&str]) -> BypassConfig {
        BypassConfig {
            ips: ips.iter().map(|s| s.to_string()).collect(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            user_agents: uas.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn ip_match_bypasses() {
        let m = BypassMatcher::new(&cfg(&["10.0.0.1"], &[], &[]));
        let ctx = RequestContext::test_with("10.0.0.1", "/anything");
        assert!(m.matches(&ctx));
        let ctx2 = RequestContext::test_with("10.0.0.2", "/anything");
        assert!(!m.matches(&ctx2));
    }

    #[test]
    fn path_prefix_matches() {
        let m = BypassMatcher::new(&cfg(&[], &["/webhooks/*"], &[]));
        let ctx = RequestContext::test_with("1.1.1.1", "/webhooks/stripe");
        assert!(m.matches(&ctx));
        let ctx2 = RequestContext::test_with("1.1.1.1", "/api/users");
        assert!(!m.matches(&ctx2));
    }

    #[test]
    fn path_exact_matches() {
        let m = BypassMatcher::new(&cfg(&[], &["/health"], &[]));
        let ctx = RequestContext::test_with("1.1.1.1", "/health");
        assert!(m.matches(&ctx));
        let ctx2 = RequestContext::test_with("1.1.1.1", "/healthy");
        assert!(!m.matches(&ctx2));
    }

    #[test]
    fn ua_substring_matches() {
        let m = BypassMatcher::new(&cfg(&[], &[], &["GitHub-Hookshot"]));
        let ctx = RequestContext::test_with("1.1.1.1", "/").with_ua("GitHub-Hookshot/abc");
        assert!(m.matches(&ctx));
    }

    #[test]
    fn empty_config_is_inactive() {
        let m = BypassMatcher::new(&cfg(&[], &[], &[]));
        assert!(!m.is_active());
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert!(!m.matches(&ctx));
    }
}
