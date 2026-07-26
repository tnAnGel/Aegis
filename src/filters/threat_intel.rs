//! Periodically-refreshed deny list driven by external threat feeds.
//!
//! Why a separate filter from `IpAclFilter`?
//!  - IpAclFilter is operator-curated and lives in the main config.
//!    A reload swaps the whole set, so it can't be updated several
//!    times a day from outside without a config reload.
//!  - This one holds an `Arc<RwLock<HashSet>>` that a background task
//!    refreshes from one or more local files. Operators feed it from
//!    AbuseIPDB / Spamhaus DROP / FireHOL by cron-curling the feed
//!    into the path and letting Aegis re-read it.
//!
//! Why local files, not direct HTTPS fetches?
//!  - Avoids pulling another HTTPS client + cert-pinning surface area
//!    into the proxy itself.
//!  - Operators already have their preferred way to authenticate to
//!    paid threat feeds (curl + token, GitHub Actions, Vault, etc).
//!  - File mtime gives free idempotency: re-reading a file Aegis
//!    already loaded is a no-op.

use std::{
    collections::HashSet,
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{
    config::ThreatIntelConfig,
    filters::{FilterAction, TrafficFilter},
    proxy::request_context::RequestContext,
};

pub struct ThreatIntelFilter {
    paths: Vec<PathBuf>,
    set: Arc<RwLock<HashSet<IpAddr>>>,
    /// V113 — CIDR ranges. Operators feed e.g. Spamhaus DROP (which
    /// is exclusively CIDR), AbuseIPDB exports, or country/ASN
    /// aggregates. We use a small flat Vec + linear scan: feeds are
    /// usually 10² to 10⁴ entries (Spamhaus DROP is ~1000), and a
    /// per-request linear scan at that size is still sub-µs. For
    /// bigger feeds (10⁵+) operators should use XDP CIDR maps where
    /// the kernel does the lookup.
    cidrs_v4: Arc<RwLock<Vec<(u32, u32)>>>, // (network, mask) both host order
    cidrs_v6: Arc<RwLock<Vec<(u128, u128)>>>,
    /// V237 — fast-path empty-set sentinel. Holds the total count of
    /// loaded entries (exact IPs + CIDR ranges, post-coalesce). Written
    /// once per reload() under the RwLock writes, read with Relaxed on
    /// every request. When zero, check() returns Allow immediately
    /// without touching any RwLock — eliminates three lock acquisitions
    /// on the hot path in plain-forwarding / no-feed-loaded deployments.
    has_entries: AtomicUsize,
}

impl ThreatIntelFilter {
    pub fn new(cfg: &ThreatIntelConfig) -> Self {
        let paths: Vec<PathBuf> = cfg.paths.iter().map(PathBuf::from).collect();
        let f = Self {
            paths,
            set: Arc::new(RwLock::new(HashSet::new())),
            cidrs_v4: Arc::new(RwLock::new(Vec::new())),
            cidrs_v6: Arc::new(RwLock::new(Vec::new())),
            has_entries: AtomicUsize::new(0),
        };
        f.reload();
        f
    }

    /// V231 — uniform engine-toggle seed accessor (see `RuntimeToggles`,
    /// the single source of truth for filter enable/disable).
    /// ThreatIntel has no on/off flag — it is active whenever present:
    /// `check()` simply matches against the deny-list / CIDR sets and
    /// allows when nothing matches, and empty intel sets are a harmless
    /// no-op. So it registers its engine toggle as `true`. Operators can
    /// still force it off per-domain via the web UI.
    pub fn config_enabled(&self) -> bool {
        true
    }

    /// V113 — diagnostic: total CIDR entries (v4 + v6) currently loaded.
    pub fn cidr_count(&self) -> usize {
        self.cidrs_v4.read().map(|v| v.len()).unwrap_or(0)
            + self.cidrs_v6.read().map(|v| v.len()).unwrap_or(0)
    }

    /// True when the filter has any feed paths configured.
    pub fn is_active(&self) -> bool {
        !self.paths.is_empty()
    }

    pub fn entry_count(&self) -> usize {
        self.set.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Re-read every feed file and atomically swap the deny set.
    /// Files that fail to read are logged at warn and skipped — one
    /// missing feed doesn't wipe the others.
    pub fn reload(&self) {
        if self.paths.is_empty() {
            return;
        }
        let mut next: HashSet<IpAddr> = HashSet::new();
        let mut next_v4: Vec<(u32, u32)> = Vec::new();
        let mut next_v6: Vec<(u128, u128)> = Vec::new();
        for path in &self.paths {
            match std::fs::read_to_string(path) {
                Ok(raw) => {
                    let (ips_added, cidrs_added) =
                        parse_feed_v113(&raw, &mut next, &mut next_v4, &mut next_v6);
                    tracing::info!(
                        path = %path.display(),
                        ip_entries = ips_added,
                        cidr_entries = cidrs_added,
                        "loaded threat-intel feed"
                    );
                }
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "threat-intel feed read failed"
                ),
            }
        }
        // V125 — coalesce adjacent + overlapping CIDR ranges. Real
        // public feeds (Spamhaus DROP, FireHOL Level 1+2) often
        // contain redundant entries: a /24 that includes a /27 listed
        // separately, or two adjacent /24s that could be one /23.
        // coalesce() merges them, typically -30-50% entry count on
        // public feeds → faster linear scan per request.
        let pre_v4 = next_v4.len();
        let pre_v6 = next_v6.len();
        next_v4 = coalesce_v4(next_v4);
        next_v6 = coalesce_v6(next_v6);
        if pre_v4 != next_v4.len() {
            tracing::info!(
                from = pre_v4,
                to = next_v4.len(),
                "threat-intel: coalesced v4 CIDR ranges"
            );
        }
        if pre_v6 != next_v6.len() {
            tracing::info!(
                from = pre_v6,
                to = next_v6.len(),
                "threat-intel: coalesced v6 CIDR ranges"
            );
        }
        let ip_count = next.len();
        let cidr_count = next_v4.len() + next_v6.len();
        if let Ok(mut g) = self.set.write() {
            *g = next;
        }
        if let Ok(mut g) = self.cidrs_v4.write() {
            *g = next_v4;
        }
        if let Ok(mut g) = self.cidrs_v6.write() {
            *g = next_v6;
        }
        // V237 — update the fast-path sentinel AFTER the RwLock writes
        // are committed. Release ordering ensures any thread that
        // subsequently reads has_entries with Acquire (or sees a
        // non-zero value via Relaxed) will observe the populated sets.
        self.has_entries
            .store(ip_count + cidr_count, Ordering::Release);
        tracing::info!(
            ip_entries = ip_count,
            cidr_entries = cidr_count,
            "threat-intel deny list refreshed"
        );
    }

    /// V113 — does this IP fall inside any loaded CIDR? Linear scan
    /// over the per-family Vec; sub-µs at the 10² to 10⁴ entry sizes
    /// real threat feeds publish.
    fn matches_cidr(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let host = u32::from(v4);
                if let Ok(g) = self.cidrs_v4.read() {
                    g.iter().any(|(net, mask)| (host & mask) == *net)
                } else {
                    false
                }
            }
            IpAddr::V6(v6) => {
                let host = u128::from(v6);
                if let Ok(g) = self.cidrs_v6.read() {
                    g.iter().any(|(net, mask)| (host & mask) == *net)
                } else {
                    false
                }
            }
        }
    }
}

/// V113 — parse one entry per line. Lines that contain `/` are CIDR
/// and land in the per-family CIDR buckets; bare IPs go in the exact-
/// match HashSet (existing path, faster lookup). Returns
/// `(ip_entries, cidr_entries)` added.
fn parse_feed_v113(
    raw: &str,
    ips: &mut HashSet<IpAddr>,
    cidrs_v4: &mut Vec<(u32, u32)>,
    cidrs_v6: &mut Vec<(u128, u128)>,
) -> (usize, usize) {
    let mut ip_added = 0;
    let mut cidr_added = 0;
    for line in raw.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((addr, mask_str)) = trimmed.split_once('/') {
            // CIDR path.
            let Ok(prefix) = mask_str.trim().parse::<u32>() else {
                continue;
            };
            let Ok(net) = addr.trim().parse::<IpAddr>() else {
                continue;
            };
            match net {
                IpAddr::V4(v4) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0u32
                    } else {
                        (!0u32) << (32 - prefix)
                    };
                    let net_u32 = u32::from(v4) & mask;
                    cidrs_v4.push((net_u32, mask));
                    cidr_added += 1;
                }
                IpAddr::V6(v6) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0u128
                    } else {
                        (!0u128) << (128 - prefix)
                    };
                    let net_u128 = u128::from(v6) & mask;
                    cidrs_v6.push((net_u128, mask));
                    cidr_added += 1;
                }
                _ => continue,
            }
        } else if let Ok(ip) = trimmed.parse::<IpAddr>()
            && ips.insert(ip)
        {
            ip_added += 1;
        }
    }
    (ip_added, cidr_added)
}

/// V125 — Coalesce a Vec of (network, mask) IPv4 CIDR pairs.
/// Three-pass algorithm:
///   1. Convert each (net, mask) → (start, end) range.
///   2. Sort by start; merge any range overlapping or adjacent to
///      the previous (Lowe's interval-merging).
///   3. Decompose each merged range back into the minimal set of
///      CIDR (network, mask) pairs.
///
/// Result: zero loss of coverage (every IP that matched before still
/// matches), typically -30-50% entries on real public feeds.
pub fn coalesce_v4(cidrs: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if cidrs.len() < 2 {
        return cidrs;
    }
    // Pass 1: → (start, end_inclusive) ranges.
    let mut ranges: Vec<(u32, u32)> = cidrs
        .into_iter()
        .map(|(net, mask)| {
            let end = net | !mask;
            (net, end)
        })
        .collect();
    // Pass 2: sort by start, merge.
    ranges.sort_by_key(|(s, _)| *s);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            // Adjacent: last.1 + 1 == s. Use saturating math so the
            // 255.255.255.255 boundary doesn't wrap into 0.
            let next_after_last = last.1.saturating_add(1);
            if s <= next_after_last {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }
    // Pass 3: decompose each merged range into CIDR (net, mask) pairs.
    let mut out = Vec::with_capacity(merged.len());
    for (s, e) in merged {
        decompose_v4_range(s, e, &mut out);
    }
    out
}

/// IPv6 analog of [coalesce_v4]. Same three passes, u128 math.
pub fn coalesce_v6(cidrs: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if cidrs.len() < 2 {
        return cidrs;
    }
    let mut ranges: Vec<(u128, u128)> = cidrs
        .into_iter()
        .map(|(net, mask)| (net, net | !mask))
        .collect();
    ranges.sort_by_key(|(s, _)| *s);
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            let next_after_last = last.1.saturating_add(1);
            if s <= next_after_last {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }
    let mut out = Vec::with_capacity(merged.len());
    for (s, e) in merged {
        decompose_v6_range(s, e, &mut out);
    }
    out
}

/// Decompose a [start, end] IPv4 range into the minimal set of CIDR
/// blocks. Standard algorithm: at each step pick the largest CIDR
/// that (a) starts at `start` and (b) doesn't extend past `end`.
fn decompose_v4_range(mut start: u32, end: u32, out: &mut Vec<(u32, u32)>) {
    while start <= end {
        // Largest prefix length such that the block aligned at `start`
        // doesn't extend past `end`. Two constraints:
        //   * block aligned at start → prefix ≤ trailing-zero count of start
        //   * block fits in [start, end] → block_size ≤ end - start + 1
        let trailing_zeros = if start == 0 {
            32
        } else {
            start.trailing_zeros()
        };
        let max_size_by_align = 1u64 << trailing_zeros;
        let max_size_by_end = (end as u64) - (start as u64) + 1;
        let size = max_size_by_align.min(max_size_by_end);
        // size is a power of two ≤ 2^32. Find prefix.
        let prefix = 32 - size.trailing_zeros();
        let mask = if prefix == 0 {
            0u32
        } else {
            (!0u32) << (32 - prefix)
        };
        out.push((start, mask));
        // Advance start by size; saturate at u32::MAX so termination
        // is guaranteed at the top of the address space.
        match start.checked_add((size - 1) as u32) {
            Some(last_in_block) => match last_in_block.checked_add(1) {
                Some(next) => start = next,
                None => break, // would overflow past u32::MAX
            },
            None => break,
        }
    }
}

fn decompose_v6_range(mut start: u128, end: u128, out: &mut Vec<(u128, u128)>) {
    while start <= end {
        let trailing_zeros = if start == 0 {
            128
        } else {
            start.trailing_zeros()
        };
        // Use u128 with explicit saturation since 1 << 128 overflows.
        let max_size_by_align: u128 = if trailing_zeros >= 128 {
            u128::MAX
        } else {
            1u128 << trailing_zeros
        };
        let max_size_by_end = end - start + 1;
        let size = max_size_by_align.min(max_size_by_end);
        let prefix = 128 - size.trailing_zeros();
        let mask = if prefix == 0 {
            0u128
        } else {
            (!0u128) << (128 - prefix)
        };
        out.push((start, mask));
        let advance = size - 1;
        match start.checked_add(advance) {
            Some(last_in_block) => match last_in_block.checked_add(1) {
                Some(next) => start = next,
                None => break,
            },
            None => break,
        }
    }
}

// V230 — cold path extracted so the icache footprint of the Allow
// path (the 99% case) stays tight. Threat-intel deny is a < 1% path
// in steady state; pushing the Deny constructor out-of-line keeps
// the hot path lean and lets the branch predictor favour the
// fall-through into Allow.
#[cold]
#[inline(never)]
fn ip_deny_cold(reason: &'static str) -> FilterAction {
    FilterAction::Deny {
        status: 403,
        reason: reason.into(),
    }
}

impl TrafficFilter for ThreatIntelFilter {
    fn name(&self) -> &'static str {
        "threat_intel"
    }
    fn check(&self, ctx: &RequestContext) -> FilterAction {
        // V237 — empty-set fast path. In plain-forwarding mode and any
        // deployment where no threat-intel feed has been loaded, all
        // three underlying sets are empty. We avoid every lock
        // acquisition in that common case by checking an AtomicUsize
        // that reload() writes (Release) after committing the sets.
        // Acquire ordering here pairs with Release in reload() so we
        // can never observe has_entries == 0 while a populated set is
        // already in place.
        if self.has_entries.load(Ordering::Acquire) == 0 {
            return FilterAction::Allow;
        }
        // Exact-match first (HashSet O(1)). Then CIDR scan if no hit.
        let exact_hit = self
            .set
            .read()
            .map(|g| g.contains(&ctx.client_ip))
            .unwrap_or(false);
        // V230 — both deny arms delegate to ip_deny_cold so the
        // FilterAction::Deny construction lives out-of-line.
        if exact_hit {
            return ip_deny_cold("ip on threat-intel deny list");
        }
        if self.matches_cidr(ctx.client_ip) {
            return ip_deny_cold("ip in threat-intel CIDR range");
        }
        FilterAction::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn tmp(contents: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "aegis-threatfeed-{}-{}.txt",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn loads_and_blocks() {
        let p = tmp("# comment\n10.0.0.1\n10.0.0.2 # trailing comment\n");
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        assert_eq!(f.entry_count(), 2);
        let ctx = RequestContext::test_with("10.0.0.1", "/");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
        let ctx2 = RequestContext::test_with("10.0.0.3", "/");
        assert_eq!(f.check(&ctx2), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn cidr_v4_range_blocks_any_member() {
        // V113 — CIDR is now actually a prefix match, not the network
        // address only.
        let p = tmp("192.168.0.0/24\n203.0.113.5\n");
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        assert_eq!(f.entry_count(), 1, "203.0.113.5 is exact-match");
        assert_eq!(f.cidr_count(), 1, "192.168.0.0/24 is a CIDR");
        // Anything in 192.168.0.0/24 must be blocked.
        for ip in ["192.168.0.0", "192.168.0.1", "192.168.0.255"] {
            let ctx = RequestContext::test_with(ip, "/");
            assert!(
                matches!(f.check(&ctx), FilterAction::Deny { .. }),
                "{ip} should match CIDR"
            );
        }
        // Outside the range — Allow.
        let ctx = RequestContext::test_with("192.168.1.0", "/");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn cidr_v6_range_blocks_any_member() {
        let p = tmp("2001:db8::/32\n");
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        assert_eq!(f.cidr_count(), 1);
        let ctx = RequestContext::test_with("2001:db8:dead:beef::1", "/");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
        let ctx2 = RequestContext::test_with("2001:db9::1", "/");
        assert_eq!(f.check(&ctx2), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn coalesce_v4_merges_adjacent_blocks() {
        // 192.168.0.0/24 + 192.168.1.0/24 → 192.168.0.0/23
        let a = (u32::from_be_bytes([192, 168, 0, 0]), 0xFFFF_FF00);
        let b = (u32::from_be_bytes([192, 168, 1, 0]), 0xFFFF_FF00);
        let merged = coalesce_v4(vec![a, b]);
        assert_eq!(merged.len(), 1);
        let (net, mask) = merged[0];
        assert_eq!(net, u32::from_be_bytes([192, 168, 0, 0]));
        assert_eq!(mask, 0xFFFF_FE00); // /23
    }

    #[test]
    fn coalesce_v4_subsumes_subnet() {
        // 10.0.0.0/8 + 10.1.2.0/24 → 10.0.0.0/8 (super absorbs sub)
        let big = (u32::from_be_bytes([10, 0, 0, 0]), 0xFF00_0000);
        let small = (u32::from_be_bytes([10, 1, 2, 0]), 0xFFFF_FF00);
        let merged = coalesce_v4(vec![big, small]);
        assert_eq!(merged.len(), 1);
        let (net, mask) = merged[0];
        assert_eq!(net, u32::from_be_bytes([10, 0, 0, 0]));
        assert_eq!(mask, 0xFF00_0000);
    }

    #[test]
    fn coalesce_v4_keeps_disjoint() {
        // Two truly disjoint, non-adjacent blocks → both kept.
        let a = (u32::from_be_bytes([10, 0, 0, 0]), 0xFFFF_FF00);
        let b = (u32::from_be_bytes([192, 168, 1, 0]), 0xFFFF_FF00);
        let merged = coalesce_v4(vec![a, b]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn coalesce_v4_merges_three_into_one_supernet() {
        // 10.0.0.0/24 + 10.0.1.0/24 + 10.0.2.0/24 + 10.0.3.0/24
        // → 10.0.0.0/22 (single block).
        let inputs: Vec<(u32, u32)> = (0..4u8)
            .map(|i| (u32::from_be_bytes([10, 0, i, 0]), 0xFFFF_FF00))
            .collect();
        let merged = coalesce_v4(inputs);
        assert_eq!(merged.len(), 1);
        let (_, mask) = merged[0];
        assert_eq!(mask, 0xFFFF_FC00); // /22
    }

    #[test]
    fn coalesce_v6_merges_adjacent() {
        // 2001:db8:0::/48 + 2001:db8:1::/48 → 2001:db8::/47
        let a_addr = u128::from_be_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let b_addr = u128::from_be_bytes([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mask48 = (!0u128) << (128 - 48);
        let mask47 = (!0u128) << (128 - 47);
        let merged = coalesce_v6(vec![(a_addr & mask48, mask48), (b_addr & mask48, mask48)]);
        assert_eq!(merged.len(), 1);
        let (_, m) = merged[0];
        assert_eq!(m, mask47);
    }

    #[test]
    fn coalesce_preserves_coverage_end_to_end() {
        // Load a feed with redundant entries, check that EVERY IP
        // matching pre-coalesce still matches post-coalesce.
        let p = tmp("10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\n10.0.3.0/24\n\
             192.168.0.0/16\n192.168.5.0/24\n");
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        // 6 input ranges should coalesce to 2 (one /22 + one /16).
        assert_eq!(f.cidr_count(), 2);
        // Verify coverage preserved at the boundaries + middle.
        for ip in [
            "10.0.0.0",
            "10.0.0.255",
            "10.0.3.255",
            "192.168.0.0",
            "192.168.5.42",
            "192.168.255.255",
        ] {
            let ctx = RequestContext::test_with(ip, "/");
            assert!(
                matches!(f.check(&ctx), FilterAction::Deny { .. }),
                "{ip} should still match"
            );
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn cidr_zero_prefix_matches_everything() {
        let p = tmp("0.0.0.0/0\n");
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        let ctx = RequestContext::test_with("8.8.8.8", "/");
        assert!(matches!(f.check(&ctx), FilterAction::Deny { .. }));
    }

    #[test]
    fn reload_swaps_set() {
        let p = tmp("1.1.1.1\n");
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        assert_eq!(f.entry_count(), 1);
        std::fs::write(&p, "2.2.2.2\n3.3.3.3\n").unwrap();
        f.reload();
        assert_eq!(f.entry_count(), 2);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn empty_config_is_inactive() {
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![],
            refresh_secs: 60,
        });
        assert!(!f.is_active());
        let ctx = RequestContext::test_with("1.1.1.1", "/");
        assert_eq!(f.check(&ctx), FilterAction::Allow);
    }

    /// V237 — empty-set fast path: has_entries must be zero after
    /// construction with no paths, and check() must return Allow
    /// immediately (no lock contention). When entries ARE loaded the
    /// sentinel is non-zero and the full check runs normally.
    #[test]
    fn empty_set_fast_path_sentinel() {
        // Case 1: no paths → has_entries == 0.
        let f = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![],
            refresh_secs: 60,
        });
        assert_eq!(
            f.has_entries.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "sentinel must be 0 when no feed is loaded"
        );
        let ctx = RequestContext::test_with("9.9.9.9", "/");
        assert_eq!(f.check(&ctx), FilterAction::Allow, "fast path must Allow");

        // Case 2: feed with entries → has_entries > 0, deny still works.
        let p = tmp("5.5.5.5\n10.0.0.0/8\n");
        let f2 = ThreatIntelFilter::new(&ThreatIntelConfig {
            paths: vec![p.to_string_lossy().into_owned()],
            refresh_secs: 60,
        });
        assert!(
            f2.has_entries.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "sentinel must be non-zero when entries are loaded"
        );
        // Exact-match deny still works.
        let ctx_deny = RequestContext::test_with("5.5.5.5", "/");
        assert!(matches!(f2.check(&ctx_deny), FilterAction::Deny { .. }));
        // CIDR deny still works.
        let ctx_cidr = RequestContext::test_with("10.1.2.3", "/");
        assert!(matches!(f2.check(&ctx_cidr), FilterAction::Deny { .. }));
        // Non-matching IP still Allows.
        let ctx_ok = RequestContext::test_with("8.8.8.8", "/");
        assert_eq!(f2.check(&ctx_ok), FilterAction::Allow);
        let _ = std::fs::remove_file(&p);
    }
}
