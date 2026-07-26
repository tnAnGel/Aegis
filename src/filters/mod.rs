pub mod adaptive;
pub mod bot;
pub mod bypass;
pub mod challenge;
pub mod dynamic_trust;
pub mod engine;
pub mod graphql;
pub mod honeypot;
pub mod ip_acl;
/// V115 — Login abuse protection. Per (IP × username), per username,
/// per IP fan-out counters with exponential backoff. Operator wires
/// before upstream POST on the login endpoint(s).
pub mod login_abuse;
pub mod plugins;
pub mod rate_limit;
pub mod threat_intel;
/// V114 — webhook HMAC verification. Safer alternative to
/// `BypassMatcher`'s UA/path bypass for inbound webhooks: only
/// requests carrying a valid HMAC signature get treated as Trusted.
pub mod webhook_hmac;

/// V237 — per-rule enable/disable overlay for the bundled WAF/Sigma
/// corpus. Disk-backed, cross-worker, mtime-polled — see module docs.
pub mod sigma_overlay;
/// V110 — UA vs JA4 fingerprint mismatch detector (P1 from info.md).
/// Stateless classifier; output feeds the V108 RiskEngine as a graded
/// signal rather than a standalone Allow/Deny gate.
pub mod ua_fp_mismatch;
pub mod waf;
/// V124 — Wirefilter expression WAF. Adapter around Cloudflare's
/// wirefilter-engine crate for compositional rule expressions.
/// Coexists with V95 flat WafRule shape; operators pick per rule.
pub mod wirefilter_waf;

use crate::proxy::request_context::RequestContext;
use std::{borrow::Cow, net::IpAddr, sync::Arc};

/// V229 — `reason` fields hold `Cow<'static, str>` so the 20+ filter
/// call sites that pass `&'static str` literals (e.g. `"ip denied"`,
/// `"waf rule N"`) become zero-alloc. Dynamic cases (`format!(...)`)
/// still work via `.into()`. Was: `String` → one heap alloc per
/// deny path even for compile-time-known reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    Allow,
    Deny {
        status: u16,
        reason: Cow<'static, str>,
    },
    Challenge {
        level: ChallengeLevel,
        reason: Cow<'static, str>,
    },
    /// Hold the connection open with a slow-drip response. Returned
    /// by the honeypot filter — the handler turns this into a
    /// `TarpitBody` that emits `chunk_bytes` every 5 s for
    /// `duration_seconds`, then closes. Pins the scanner's worker
    /// without consuming the upstream.
    Tarpit {
        duration_seconds: u64,
        chunk_bytes: usize,
        server_header: Cow<'static, str>,
        reason: Cow<'static, str>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeLevel {
    Headers,
    Html,
    Iframe,
    Javascript,
    Captcha,
}

pub trait TrafficFilter: Send + Sync {
    fn check(&self, ctx: &RequestContext) -> FilterAction;
    /// Short stable identifier ("waf", "ip_acl", "bot", …) used for
    /// per-filter metrics labels. Defaults to "unknown" so old custom
    /// filters compile without churn — built-ins override this.
    fn name(&self) -> &'static str {
        "unknown"
    }
}

/// V102 — enum-dispatch wrapper around the built-in filters so the
/// hot path in [engine::FilterEngine] avoids `dyn TrafficFilter`
/// virtual calls. Each variant holds an `Arc<concrete type>`; `check`
/// is a static dispatch the compiler can inline.
///
/// `Custom(Arc<dyn TrafficFilter>)` keeps the dyn dispatch for the
/// long tail (Lua plugins, operator-supplied filters). Built-ins are
/// always declared as their concrete variant.
pub enum SharedFilter {
    Honeypot(Arc<honeypot::HoneypotFilter>),
    ThreatIntel(Arc<threat_intel::ThreatIntelFilter>),
    IpAcl(Arc<ip_acl::IpAclFilter>),
    Waf(Arc<waf::WafFilter>),
    Bot(Arc<bot::BotFilter>),
    Adaptive(Arc<adaptive::AdaptiveFilter>),
    Challenge(Arc<challenge::ChallengeFilter>),
    RateLimit(Arc<rate_limit::RateLimitFilter>),
    /// Lua plugin or operator-supplied custom filter. Long tail —
    /// retained as `dyn` because plugin types aren't known at compile
    /// time.
    Custom(Arc<dyn TrafficFilter>),
}

impl SharedFilter {
    #[inline]
    pub fn check(&self, ctx: &RequestContext) -> FilterAction {
        match self {
            Self::Honeypot(f) => f.check(ctx),
            Self::ThreatIntel(f) => f.check(ctx),
            Self::IpAcl(f) => f.check(ctx),
            Self::Waf(f) => f.check(ctx),
            Self::Bot(f) => f.check(ctx),
            Self::Adaptive(f) => f.check(ctx),
            Self::Challenge(f) => f.check(ctx),
            Self::RateLimit(f) => f.check(ctx),
            Self::Custom(f) => f.check(ctx),
        }
    }

    #[inline]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Honeypot(f) => f.name(),
            Self::ThreatIntel(f) => f.name(),
            Self::IpAcl(f) => f.name(),
            Self::Waf(f) => f.name(),
            Self::Bot(f) => f.name(),
            Self::Adaptive(f) => f.name(),
            Self::Challenge(f) => f.name(),
            Self::RateLimit(f) => f.name(),
            Self::Custom(f) => f.name(),
        }
    }

    /// V231 — the filter's configured enable state. `FilterEngine::new`
    /// seeds the `RuntimeToggles` registry from this so the engine
    /// toggle reflects `aegis.conf` instead of a hardcoded `true`.
    ///
    /// This makes `RuntimeToggles` (+ per-domain `domain_policy`
    /// overrides) the *single source of truth* for enable/disable:
    /// each filter's `check()` no longer self-gates on its own
    /// `enabled` field, so an operator who force-enables a
    /// default-off filter (e.g. `challenge`) for one domain via the
    /// web UI actually gets it — previously the filter's internal
    /// gate short-circuited the per-domain override.
    ///
    /// `Custom` plugins are operator-installed explicitly; they have
    /// no uniform config flag, so they register as `true` (per-domain
    /// override still works through the engine toggle).
    #[inline]
    pub fn config_enabled(&self) -> bool {
        match self {
            Self::Honeypot(f) => f.config_enabled(),
            Self::ThreatIntel(f) => f.config_enabled(),
            Self::IpAcl(f) => f.config_enabled(),
            Self::Waf(f) => f.config_enabled(),
            Self::Bot(f) => f.config_enabled(),
            Self::Adaptive(f) => f.config_enabled(),
            Self::Challenge(f) => f.config_enabled(),
            Self::RateLimit(f) => f.config_enabled(),
            Self::Custom(_) => true,
        }
    }
}

impl Clone for SharedFilter {
    fn clone(&self) -> Self {
        match self {
            Self::Honeypot(f) => Self::Honeypot(Arc::clone(f)),
            Self::ThreatIntel(f) => Self::ThreatIntel(Arc::clone(f)),
            Self::IpAcl(f) => Self::IpAcl(Arc::clone(f)),
            Self::Waf(f) => Self::Waf(Arc::clone(f)),
            Self::Bot(f) => Self::Bot(Arc::clone(f)),
            Self::Adaptive(f) => Self::Adaptive(Arc::clone(f)),
            Self::Challenge(f) => Self::Challenge(Arc::clone(f)),
            Self::RateLimit(f) => Self::RateLimit(Arc::clone(f)),
            Self::Custom(f) => Self::Custom(Arc::clone(f)),
        }
    }
}
pub fn parse_ip(ip: &str) -> Option<IpAddr> {
    ip.parse::<IpAddr>().ok()
}
