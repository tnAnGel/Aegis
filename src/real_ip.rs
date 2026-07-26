//! V-new — Trusted-proxy real-client-IP resolver.
//!
//! Behind a CDN or reverse-proxy tier the TCP peer address is a rotating
//! edge node, not the actual client. This module resolves the **real**
//! client IP from forwarded headers, but **only when** the TCP peer is
//! inside the operator-configured trusted-proxy set. When no trusted
//! proxies are configured the module is a no-op and every call returns
//! the peer address unchanged — preserving 100 % of the existing
//! behaviour.
//!
//! ## Security invariant
//!
//! The gate check (`peer ∈ trusted_proxy_cidrs`) is unconditional. If the
//! TCP peer is **not** trusted the forwarded headers are silently ignored.
//! An attacker who is not behind a trusted proxy cannot spoof their IP by
//! injecting `X-Forwarded-For` or `CF-Connecting-IP`.
//!
//! ## Configuration surface
//!
//! | Env var | Effect |
//! |---|---|
//! | `AEGIS_BEHIND_CLOUDFLARE=1` | Trust `CF-Connecting-IP` when the TCP peer is in the built-in Cloudflare CIDR list. |
//! | `AEGIS_TRUSTED_PROXIES=cidr,cidr,...` | Additionally trust these CIDRs; consult `X-Forwarded-For` (rightmost-non-trusted algorithm). |
//!
//! Both are **off by default** — zero behaviour change unless explicitly enabled.

use std::net::IpAddr;

/// Cloudflare published edge IP ranges.
///
/// Source: <https://www.cloudflare.com/ips-v4> + <https://www.cloudflare.com/ips-v6>
/// Last verified: 2026.
/// Toggle with `AEGIS_BEHIND_CLOUDFLARE=1`.
pub const CLOUDFLARE_RANGES: &[&str] = &[
    // IPv4
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    // IPv6
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

// ---------------------------------------------------------------------------
// Tiny zero-dep CIDR matcher
// ---------------------------------------------------------------------------

/// An owned, pre-parsed CIDR (network address + prefix length).
///
/// Both v4-in-v4 and v6-in-v6 matching are supported. IPv4-mapped IPv6
/// addresses (::ffff:x.x.x.x) are **not** auto-converted; Pingora's
/// `as_inet().ip()` already returns a proper `IpAddr::V4` for IPv4
/// connections even on dual-stack sockets, so this is not an issue in
/// practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u32,
}

impl IpCidr {
    /// Parse `"a.b.c.d/n"` or `"2001:db8::/32"`.
    ///
    /// Returns `None` on any parse error so callers can skip bad entries
    /// rather than panic.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_s, prefix_s) = s.split_once('/')?;
        let addr: IpAddr = addr_s.trim().parse().ok()?;
        let prefix: u32 = prefix_s.trim().parse().ok()?;
        match addr {
            IpAddr::V4(_) if prefix > 32 => return None,
            IpAddr::V6(_) if prefix > 128 => return None,
            _ => {}
        }
        Some(Self { addr, prefix })
    }

    /// Returns `true` when `ip` is contained in this CIDR.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (ip, self.addr) {
            (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                let mask: u32 = prefix_mask_v4(self.prefix);
                (u32::from(ip4) & mask) == (u32::from(net4) & mask)
            }
            (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
                let mask: u128 = prefix_mask_v6(self.prefix);
                (u128::from(ip6) & mask) == (u128::from(net6) & mask)
            }
            // v4 vs v6 or vice versa — never matches.
            _ => false,
        }
    }
}

#[inline]
fn prefix_mask_v4(prefix: u32) -> u32 {
    if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    }
}

#[inline]
fn prefix_mask_v6(prefix: u32) -> u128 {
    if prefix == 0 {
        0u128
    } else {
        !0u128 << (128 - prefix)
    }
}

// ---------------------------------------------------------------------------
// TrustedProxies
// ---------------------------------------------------------------------------

/// The set of trusted proxy CIDRs plus the resolved header-preference
/// strategy. Constructed once at startup and shared read-only.
///
/// When `cidrs` is **empty** the struct is a no-op: `resolve_client_ip`
/// always returns the peer address, identical to the pre-feature behaviour.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    /// Combined list of trusted CIDRs (Cloudflare built-ins + operator extras).
    cidrs: Vec<IpCidr>,
    /// When `true`, prefer `CF-Connecting-IP` over `X-Forwarded-For`.
    cf: bool,
}

impl TrustedProxies {
    /// Construct from configuration.
    ///
    /// - `behind_cloudflare`: if `true`, the built-in [`CLOUDFLARE_RANGES`]
    ///   are added and `CF-Connecting-IP` is consulted first.
    /// - `extra_cidrs`: comma-separated CIDR string from
    ///   `AEGIS_TRUSTED_PROXIES` (may be empty / `None`).
    ///
    /// Invalid CIDR strings are skipped with a warning-level log; they
    /// never cause a panic.
    pub fn from_config(behind_cloudflare: bool, extra_cidrs: Option<&str>) -> Self {
        let mut cidrs: Vec<IpCidr> = Vec::new();

        if behind_cloudflare {
            for &s in CLOUDFLARE_RANGES {
                match IpCidr::parse(s) {
                    Some(c) => cidrs.push(c),
                    None => {
                        // Should never happen with the hard-coded list;
                        // log at warn so a future list update surfaces quickly.
                        eprintln!("real_ip: failed to parse built-in CF CIDR {s:?}");
                    }
                }
            }
        }

        if let Some(extra) = extra_cidrs {
            for part in extra.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                match IpCidr::parse(part) {
                    Some(c) => cidrs.push(c),
                    None => {
                        eprintln!(
                            "real_ip: skipping invalid CIDR from AEGIS_TRUSTED_PROXIES: {part:?}"
                        );
                    }
                }
            }
        }

        Self {
            cidrs,
            cf: behind_cloudflare,
        }
    }

    /// Build from the standard environment variables at process startup.
    ///
    /// Reads `AEGIS_BEHIND_CLOUDFLARE` and `AEGIS_TRUSTED_PROXIES`.
    /// This is a convenience wrapper; callers that already parsed these
    /// vars can use [`Self::from_config`] directly.
    pub fn from_env() -> Self {
        let behind_cloudflare = std::env::var("AEGIS_BEHIND_CLOUDFLARE")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        let extra = std::env::var("AEGIS_TRUSTED_PROXIES").ok();
        Self::from_config(behind_cloudflare, extra.as_deref())
    }

    /// Returns `true` when this instance has **no** trusted CIDRs
    /// (feature disabled). `resolve_client_ip` is a no-op in this case.
    #[inline]
    pub fn is_disabled(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Returns `true` when `ip` falls inside any of the trusted CIDRs.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }

    /// Resolve the real client IP.
    ///
    /// **Algorithm:**
    ///
    /// 1. If the feature is disabled (`is_disabled()`) → return `peer` unchanged.
    /// 2. If `peer` is **not** in the trusted set → return `peer` unchanged
    ///    (security gate: headers from untrusted sources are never consulted).
    /// 3. If `behind_cloudflare` is set → read `CF-Connecting-IP` (single IP,
    ///    authoritative when Cloudflare is the terminating edge). Fall back to
    ///    `peer` on any parse failure.
    /// 4. Otherwise → read `X-Forwarded-For`, walk right-to-left, and return
    ///    the first IP that is **not** itself in the trusted set (the real client
    ///    just before the trust boundary). Fall back to `peer` on any parse
    ///    failure or if every hop is trusted.
    pub fn resolve_client_ip(&self, peer: IpAddr, headers: &http::HeaderMap) -> IpAddr {
        // Step 1 — feature disabled.
        if self.is_disabled() {
            return peer;
        }

        // Step 2 — security gate.
        if !self.is_trusted(peer) {
            return peer;
        }

        // Step 3 — Cloudflare authoritative header.
        if self.cf {
            if let Some(ip) = read_single_ip(headers, "cf-connecting-ip") {
                return ip;
            }
            // CF-Connecting-IP missing or malformed — fall through to peer.
            return peer;
        }

        // Step 4 — X-Forwarded-For rightmost-non-trusted walk.
        if let Some(ip) = self.resolve_xff(headers) {
            return ip;
        }

        peer
    }

    /// Walk `X-Forwarded-For` right-to-left and return the first IP that
    /// is not itself a trusted proxy.
    ///
    /// Returns `None` if the header is absent, malformed, or every hop is
    /// trusted.
    fn resolve_xff(&self, headers: &http::HeaderMap) -> Option<IpAddr> {
        // XFF may be split across multiple header lines; collect them all.
        let raw: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();

        if raw.is_empty() {
            return None;
        }

        // Flatten all comma-separated entries from all header lines.
        let hops: Vec<&str> = raw.iter().flat_map(|line| line.split(',')).collect();

        // Walk right-to-left; first non-trusted IP is the real client.
        for hop in hops.iter().rev() {
            let hop = hop.trim();
            match hop.parse::<IpAddr>() {
                Ok(ip) if !self.is_trusted(ip) => return Some(ip),
                Ok(_) => {} // trusted hop — keep walking left
                Err(_) => {
                    // Malformed entry in XFF — abort and fall back to peer.
                    return None;
                }
            }
        }

        // Every hop was trusted (unusual but not impossible). Caller falls
        // back to peer.
        None
    }
}

/// Read a single IP address from a named header.
fn read_single_ip(headers: &http::HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for &(k, v) in pairs {
            map.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    // -----------------------------------------------------------------------
    // IpCidr::parse
    // -----------------------------------------------------------------------

    #[test]
    fn cidr_parse_valid_v4() {
        let c = IpCidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.1".parse().unwrap()));
        assert!(!c.contains("192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_valid_v6() {
        let c = IpCidr::parse("2606:4700::/32").unwrap();
        assert!(c.contains("2606:4700::1".parse().unwrap()));
        assert!(!c.contains("2606:4800::1".parse().unwrap()));
    }

    #[test]
    fn cidr_host_route() {
        // /32 should match exactly the host.
        let c = IpCidr::parse("10.0.0.1/32").unwrap();
        assert!(c.contains("10.0.0.1".parse().unwrap()));
        assert!(!c.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn cidr_slash_zero_v4_matches_all() {
        let c = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn cidr_slash_zero_v6_matches_all() {
        let c = IpCidr::parse("::/0").unwrap();
        assert!(c.contains(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn cidr_parse_invalid_returns_none() {
        assert!(IpCidr::parse("not-an-ip/24").is_none());
        assert!(IpCidr::parse("192.168.1.0/33").is_none());
        assert!(IpCidr::parse("::1/129").is_none());
        assert!(IpCidr::parse("no-slash").is_none());
    }

    #[test]
    fn cidr_v4_vs_v6_no_match() {
        let c = IpCidr::parse("192.168.0.0/16").unwrap();
        // IPv6 address against IPv4 CIDR must not match.
        assert!(!c.contains("::ffff:192.168.0.1".parse().unwrap()));
    }

    // -----------------------------------------------------------------------
    // Cloudflare range membership
    // -----------------------------------------------------------------------

    #[test]
    fn cf_range_ipv4_104_16() {
        // 104.16.0.0/13 — well-known CF worker range
        let c = IpCidr::parse("104.16.0.0/13").unwrap();
        assert!(c.contains("104.16.0.1".parse().unwrap()));
        assert!(c.contains("104.23.255.255".parse().unwrap()));
        assert!(!c.contains("104.24.0.0".parse().unwrap()));
    }

    #[test]
    fn cf_range_ipv6_2606() {
        let c = IpCidr::parse("2606:4700::/32").unwrap();
        assert!(c.contains("2606:4700:dead:beef::1".parse().unwrap()));
        assert!(!c.contains("2607:4700::1".parse().unwrap()));
    }

    // -----------------------------------------------------------------------
    // TrustedProxies::from_config
    // -----------------------------------------------------------------------

    #[test]
    fn disabled_by_default() {
        let tp = TrustedProxies::from_config(false, None);
        assert!(tp.is_disabled());
    }

    #[test]
    fn cf_enabled_not_empty() {
        let tp = TrustedProxies::from_config(true, None);
        assert!(!tp.is_disabled());
        assert!(tp.cf);
    }

    #[test]
    fn extra_cidrs_parsed() {
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8,172.16.0.0/12"));
        assert!(!tp.is_disabled());
        assert!(tp.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(tp.is_trusted("172.16.5.1".parse().unwrap()));
        assert!(!tp.is_trusted("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn invalid_extra_cidrs_skipped() {
        // Should not panic; the valid entry is kept.
        let tp = TrustedProxies::from_config(false, Some("bad-cidr,10.0.0.0/8"));
        assert!(tp.is_trusted("10.5.6.7".parse().unwrap()));
    }

    // -----------------------------------------------------------------------
    // resolve_client_ip — security: untrusted peer ignores headers
    // -----------------------------------------------------------------------

    #[test]
    fn untrusted_peer_ignores_xff() {
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "9.9.9.9")]);
        // Peer is not in 10/8, so the header must be ignored.
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    #[test]
    fn untrusted_peer_ignores_cf_connecting_ip() {
        let tp = TrustedProxies::from_config(true, None);
        // Use a non-CF peer.
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let headers = make_headers(&[("cf-connecting-ip", "8.8.8.8")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    // -----------------------------------------------------------------------
    // resolve_client_ip — feature disabled
    // -----------------------------------------------------------------------

    #[test]
    fn feature_disabled_returns_peer() {
        let tp = TrustedProxies::default();
        assert!(tp.is_disabled());
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let headers = make_headers(&[
            ("cf-connecting-ip", "9.9.9.9"),
            ("x-forwarded-for", "7.7.7.7"),
        ]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    // -----------------------------------------------------------------------
    // resolve_client_ip — CF-Connecting-IP path
    // -----------------------------------------------------------------------

    #[test]
    fn trusted_cf_peer_reads_cf_connecting_ip() {
        let tp = TrustedProxies::from_config(true, None);
        // Use a known CF IP (103.21.244.1 is inside 103.21.244.0/22).
        let peer: IpAddr = "103.21.244.1".parse().unwrap();
        let real: IpAddr = "203.0.113.42".parse().unwrap();
        let headers = make_headers(&[("cf-connecting-ip", "203.0.113.42")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), real);
    }

    #[test]
    fn trusted_cf_peer_missing_header_falls_back_to_peer() {
        let tp = TrustedProxies::from_config(true, None);
        let peer: IpAddr = "103.21.244.1".parse().unwrap();
        let headers = make_headers(&[]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    #[test]
    fn trusted_cf_peer_malformed_header_falls_back_to_peer() {
        let tp = TrustedProxies::from_config(true, None);
        let peer: IpAddr = "103.21.244.1".parse().unwrap();
        let headers = make_headers(&[("cf-connecting-ip", "not-an-ip")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    // CF mode does NOT consult XFF even if CF-Connecting-IP is absent —
    // it falls back to peer to avoid ambiguity.
    #[test]
    fn trusted_cf_peer_missing_cf_ip_ignores_xff() {
        let tp = TrustedProxies::from_config(true, None);
        let peer: IpAddr = "103.21.244.1".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "8.8.8.8")]);
        // CF mode: no CF-Connecting-IP → peer, not the XFF value.
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    // -----------------------------------------------------------------------
    // resolve_client_ip — X-Forwarded-For path
    // -----------------------------------------------------------------------

    #[test]
    fn xff_simple_chain() {
        // Single trusted proxy; XFF has one hop = the real client.
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let real: IpAddr = "203.0.113.1".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "203.0.113.1")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), real);
    }

    #[test]
    fn xff_rightmost_non_trusted() {
        // Chain: real-client → proxy-A (trusted) → proxy-B (trusted) = peer.
        // XFF: "real-client, proxy-A"
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let real: IpAddr = "203.0.113.5".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "203.0.113.5, 10.0.0.1")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), real);
    }

    #[test]
    fn xff_injection_before_real_client() {
        // Attacker prepends a fake IP to the XFF list. The rightmost
        // non-trusted IP is still the real client (10.0.0.1 is the last
        // hop before the trust boundary, i.e. peer is 10.0.0.2 a proxy).
        // Chain: [attacker-fake, real-client, proxy] — rightmost non-trusted is real-client.
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let real: IpAddr = "203.0.113.5".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.5, 10.0.0.1")]);
        // Rightmost non-trusted: 203.0.113.5
        assert_eq!(tp.resolve_client_ip(peer, &headers), real);
    }

    #[test]
    fn xff_missing_falls_back_to_peer() {
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let headers = make_headers(&[]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    #[test]
    fn xff_malformed_entry_falls_back_to_peer() {
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    #[test]
    fn xff_all_trusted_hops_falls_back_to_peer() {
        // Every entry in XFF is itself trusted — unusual but handled.
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "10.0.0.5, 10.0.0.1")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), peer);
    }

    #[test]
    fn xff_ipv6_real_client() {
        let tp = TrustedProxies::from_config(false, Some("10.0.0.0/8"));
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let real: IpAddr = "2001:db8::1".parse().unwrap();
        let headers = make_headers(&[("x-forwarded-for", "2001:db8::1")]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), real);
    }

    // -----------------------------------------------------------------------
    // Combined: both CF flag + extra CIDRs — CF-Connecting-IP wins
    // -----------------------------------------------------------------------

    #[test]
    fn combined_cf_and_extra_cidrs_cf_ip_wins() {
        let tp = TrustedProxies::from_config(true, Some("10.0.0.0/8"));
        // Peer is in the extra CIDR (not in CF ranges), but cf=true so we
        // still prefer CF-Connecting-IP when it is present.
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let real: IpAddr = "203.0.113.99".parse().unwrap();
        let headers = make_headers(&[
            ("cf-connecting-ip", "203.0.113.99"),
            ("x-forwarded-for", "9.9.9.9"),
        ]);
        assert_eq!(tp.resolve_client_ip(peer, &headers), real);
    }
}
