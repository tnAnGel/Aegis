//! V142 — ASN / CIDR reputation feed.
//!
//! Operator-supplied list of bad ASNs (hosting, proxy farms,
//! commonly-abused VPN providers, Tor-exit clusters) + bad CIDRs.
//! Lookup returns a `[0, 1]` reputation score that V140's
//! `extract_ml_features_v2` writes into the `asn_reputation` slot.
//!
//! ## Why both ASN-keyed and CIDR-keyed?
//!
//! Most operators have at least one of:
//! * **ASN DB** (MaxMind GeoIP2-ASN or equivalent) — best for hosting/
//!   transit identification because a bad ASN catches *every* current
//!   and future IP block on that AS.
//! * **CIDR list** — easier to maintain by hand, no DB needed; covers
//!   specific subnets the operator has burned in IR before. Also the
//!   right shape for Spamhaus DROP, FireHOL aggregates, and bring-
//!   your-own threat-intel exports.
//!
//! Aegis core doesn't ship a default list — the right list is
//! deployment-specific (a SaaS shop hates DigitalOcean traffic, a
//! gaming shop has to allow it).
//!
//! ## File format
//!
//!     # ASN entries — `AS<number>  <score>  [tag]`
//!     AS14061  0.8  digitalocean
//!     AS16509  0.7  aws-ec2
//!
//!     # CIDR entries — `<cidr>  <score>  [tag]`
//!     185.220.100.0/22  1.0  tor-exit
//!     1.2.3.4/32        0.9  burned-host
//!
//! Score is in `[0, 1]`. Tag is opaque; surfaced in metrics and
//! audit logs. Lookup is O(1) for ASN entries, O(n) over CIDRs in
//! the worst case but Aegis-style operators run with O(10²) CIDR
//! entries, which is fine at line rate.
//!
//! ## Wiring
//!
//! V142 ships:
//! * Standalone module with ASN-keyed and CIDR-keyed lookup.
//! * `AsnLookup` trait so operators can plug in a MaxMind ASN DB or
//!   a static CSV; default impl is `NoopAsnLookup` that always
//!   returns `None`.
//! * Hot-reload via mtime poll, plugs into PingoraBackground tick.
//!
//! Wired into `extract_ml_features_v2` so the V139 `asn_reputation`
//! feature is populated.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

/// Operator-supplied IP → ASN lookup. Real impls front a MaxMind
/// GeoIP2-ASN database or a static CSV. The noop returns None so
/// deployments without an ASN DB still work (only CIDR entries
/// matter).
pub trait AsnLookup: Send + Sync {
    fn asn(&self, ip: IpAddr) -> Option<u32>;
}

/// No-op ASN lookup — used when no ASN DB is wired. Causes the
/// reputation module to fall back to CIDR-only matching.
#[derive(Default)]
pub struct NoopAsnLookup;

impl AsnLookup for NoopAsnLookup {
    fn asn(&self, _: IpAddr) -> Option<u32> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct AsnHit {
    pub score: f32,
    pub tag: String,
    pub match_kind: AsnMatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsnMatchKind {
    Asn,
    Cidr,
}

/// In-memory index of ASN and CIDR entries. Reloadable from disk.
pub struct AsnReputation {
    paths: Vec<PathBuf>,
    asn_index: RwLock<HashMap<u32, (f32, String)>>,
    cidr_v4: RwLock<Vec<(u32, u32, f32, String)>>, // (network, mask, score, tag)
    cidr_v6: RwLock<Vec<(u128, u128, f32, String)>>,
    lookup: Arc<dyn AsnLookup>,
}

impl AsnReputation {
    pub fn new(paths: Vec<PathBuf>, lookup: Arc<dyn AsnLookup>) -> Self {
        let s = Self {
            paths,
            asn_index: RwLock::new(HashMap::new()),
            cidr_v4: RwLock::new(vec![]),
            cidr_v6: RwLock::new(vec![]),
            lookup,
        };
        s.reload();
        s
    }

    /// Construct with no ASN DB (CIDR-only mode).
    pub fn cidr_only(paths: Vec<PathBuf>) -> Self {
        Self::new(paths, Arc::new(NoopAsnLookup))
    }

    pub fn is_active(&self) -> bool {
        !self.paths.is_empty()
    }

    pub fn entry_count(&self) -> usize {
        let asn = self.asn_index.read().map(|g| g.len()).unwrap_or(0);
        let v4 = self.cidr_v4.read().map(|g| g.len()).unwrap_or(0);
        let v6 = self.cidr_v6.read().map(|g| g.len()).unwrap_or(0);
        asn + v4 + v6
    }

    /// Reload all configured files. Same safety as V138: a vanished
    /// file does NOT blank the index — preserves the prior table.
    pub fn reload(&self) {
        let mut new_asn: HashMap<u32, (f32, String)> = HashMap::new();
        let mut new_v4: Vec<(u32, u32, f32, String)> = vec![];
        let mut new_v6: Vec<(u128, u128, f32, String)> = vec![];
        let mut had_any = false;
        for path in &self.paths {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    had_any = true;
                    parse_into(&contents, &mut new_asn, &mut new_v4, &mut new_v6);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e,
                        "asn_reputation: file unreadable; skipping");
                }
            }
        }
        if had_any {
            if let Ok(mut g) = self.asn_index.write() {
                *g = new_asn;
            }
            if let Ok(mut g) = self.cidr_v4.write() {
                *g = new_v4;
            }
            if let Ok(mut g) = self.cidr_v6.write() {
                *g = new_v6;
            }
        }
    }

    /// Test-only: load from a string. Bypasses disk I/O.
    pub fn load_str(&self, contents: &str) {
        let mut new_asn = HashMap::new();
        let mut new_v4 = vec![];
        let mut new_v6 = vec![];
        parse_into(contents, &mut new_asn, &mut new_v4, &mut new_v6);
        if let Ok(mut g) = self.asn_index.write() {
            *g = new_asn;
        }
        if let Ok(mut g) = self.cidr_v4.write() {
            *g = new_v4;
        }
        if let Ok(mut g) = self.cidr_v6.write() {
            *g = new_v6;
        }
    }

    /// Lookup. Tries ASN table first (if AsnLookup returns one for
    /// this IP); falls back to a linear CIDR scan. Returns the
    /// highest-scored match if multiple fire — operators stacking
    /// entries get the strongest signal, never the weakest.
    pub fn lookup(&self, ip: IpAddr) -> Option<AsnHit> {
        let mut best: Option<AsnHit> = None;

        // ASN path.
        if let Some(asn) = self.lookup.asn(ip)
            && let Ok(g) = self.asn_index.read()
            && let Some((score, tag)) = g.get(&asn)
        {
            best = Some(AsnHit {
                score: *score,
                tag: tag.clone(),
                match_kind: AsnMatchKind::Asn,
            });
        }

        // CIDR path.
        let cidr_hit = match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                self.cidr_v4.read().ok().and_then(|g| {
                    g.iter()
                        .filter(|(net, mask, _, _)| (bits & mask) == *net)
                        .map(|(_, _, score, tag)| (*score, tag.clone()))
                        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
                })
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                self.cidr_v6.read().ok().and_then(|g| {
                    g.iter()
                        .filter(|(net, mask, _, _)| (bits & mask) == *net)
                        .map(|(_, _, score, tag)| (*score, tag.clone()))
                        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
                })
            }
        };
        if let Some((score, tag)) = cidr_hit {
            let new = AsnHit {
                score,
                tag,
                match_kind: AsnMatchKind::Cidr,
            };
            best = match best {
                None => Some(new),
                Some(old) if new.score > old.score => Some(new),
                Some(old) => Some(old),
            };
        }

        best
    }

    /// Convenience: numeric feature value in [0, 1] for the V139
    /// `asn_reputation` slot. Returns the hit score (already in [0, 1])
    /// or 0.0 when no entry matches.
    pub fn feature(&self, ip: IpAddr) -> f32 {
        self.lookup(ip).map(|h| h.score).unwrap_or(0.0)
    }
}

fn parse_into(
    contents: &str,
    asn: &mut HashMap<u32, (f32, String)>,
    v4: &mut Vec<(u32, u32, f32, String)>,
    v6: &mut Vec<(u128, u128, f32, String)>,
) {
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(token) = parts.next() else { continue };
        let Some(score_s) = parts.next() else {
            continue;
        };
        let Ok(score) = score_s.parse::<f32>() else {
            continue;
        };
        let score = score.clamp(0.0, 1.0);
        let tag = parts.next().unwrap_or("unknown").to_string();

        // ASN entry: starts with AS or as (case-insensitive).
        let lower = token.to_ascii_lowercase();
        if let Some(num_s) = lower.strip_prefix("as")
            && let Ok(num) = num_s.parse::<u32>()
        {
            asn.insert(num, (score, tag));
            continue;
        }

        // CIDR entry.
        if let Some((cidr_net, cidr_mask, is_v6)) = parse_cidr(token) {
            if is_v6 {
                v6.push((cidr_net, cidr_mask, score, tag));
            } else {
                v4.push((cidr_net as u32, cidr_mask as u32, score, tag));
            }
            continue;
        }
        // Unparseable token: skip silently. Operator-vetted feed.
    }
}

/// Parse `1.2.3.0/24` or `::1/128`. Returns (network, mask, is_v6)
/// as u128 — caller narrows to u32 for v4. Returns None on parse
/// failure (port-embedded entries, hostnames, malformed bits).
fn parse_cidr(s: &str) -> Option<(u128, u128, bool)> {
    let (addr_part, prefix_part) = s.split_once('/')?;
    let addr: IpAddr = addr_part.parse().ok()?;
    let prefix: u8 = prefix_part.parse().ok()?;
    match addr {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0u32
            } else {
                (!0u32) << (32 - prefix)
            };
            Some(((bits & mask) as u128, mask as u128, false))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0u128
            } else {
                (!0u128) << (128 - prefix)
            };
            Some((bits & mask, mask, true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> AsnReputation {
        AsnReputation::cidr_only(vec![])
    }

    #[test]
    fn empty_reputation_has_zero_entries() {
        let r = empty();
        assert_eq!(r.entry_count(), 0);
        assert_eq!(r.feature("1.2.3.4".parse().unwrap()), 0.0);
        assert!(!r.is_active());
    }

    #[test]
    fn parses_asn_entries() {
        let r = empty();
        r.load_str(
            "\
# header comment
AS14061  0.8  digitalocean
AS16509  0.7  aws-ec2
as13335  0.4  cloudflare
",
        );
        assert_eq!(r.entry_count(), 3);
    }

    #[test]
    fn parses_cidr_v4_entries() {
        let r = empty();
        r.load_str(
            "\
185.220.100.0/22  1.0  tor-exit
1.2.3.0/24        0.5  burned-block
",
        );
        let hit = r.lookup("185.220.100.42".parse().unwrap()).unwrap();
        assert_eq!(hit.tag, "tor-exit");
        assert_eq!(hit.match_kind, AsnMatchKind::Cidr);
        assert!((hit.score - 1.0).abs() < 1e-5);

        let hit2 = r.lookup("1.2.3.7".parse().unwrap()).unwrap();
        assert_eq!(hit2.tag, "burned-block");

        // Out-of-range IP → no hit.
        assert!(r.lookup("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn parses_cidr_v6_entries() {
        let r = empty();
        r.load_str("2001:db8::/32  0.7  bad-v6\n");
        let hit = r.lookup("2001:db8:1::1".parse().unwrap()).unwrap();
        assert_eq!(hit.tag, "bad-v6");
        assert!(r.lookup("2002:db8::1".parse().unwrap()).is_none());
    }

    #[test]
    fn slash_32_matches_exactly_one_address() {
        let r = empty();
        r.load_str("1.2.3.4/32  0.9  single\n");
        assert!(r.lookup("1.2.3.4".parse().unwrap()).is_some());
        assert!(r.lookup("1.2.3.5".parse().unwrap()).is_none());
    }

    #[test]
    fn lookup_picks_highest_score_when_multiple_match() {
        let r = empty();
        r.load_str(
            "\
1.2.3.0/24  0.5  weak
1.2.3.0/25  0.9  strong
",
        );
        let hit = r.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert!((hit.score - 0.9).abs() < 1e-5);
        assert_eq!(hit.tag, "strong");
    }

    /// Test stub: returns a fixed ASN regardless of IP.
    struct FixedAsn(u32);
    impl AsnLookup for FixedAsn {
        fn asn(&self, _: IpAddr) -> Option<u32> {
            Some(self.0)
        }
    }

    #[test]
    fn asn_path_matches_when_lookup_wired() {
        let r = AsnReputation::new(vec![], Arc::new(FixedAsn(14061)));
        r.load_str("AS14061  0.8  digitalocean\n");
        let hit = r.lookup("8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(hit.match_kind, AsnMatchKind::Asn);
        assert_eq!(hit.tag, "digitalocean");
    }

    #[test]
    fn feature_returns_zero_when_no_match() {
        let r = empty();
        r.load_str("AS1234 0.7 x\n");
        // No ASN lookup wired → can't match the ASN entry.
        assert_eq!(r.feature("8.8.8.8".parse().unwrap()), 0.0);
    }

    #[test]
    fn score_clamps_to_one() {
        let r = empty();
        r.load_str("1.2.3.0/24  9.99  ignored\n");
        let hit = r.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert!((hit.score - 1.0).abs() < 1e-5);
    }

    #[test]
    fn missing_score_skips_entry() {
        let r = empty();
        r.load_str("1.2.3.0/24\n"); // no score field
        assert_eq!(r.entry_count(), 0);
    }

    #[test]
    fn malformed_lines_skipped() {
        let r = empty();
        r.load_str(
            "\
not-a-cidr-or-asn  0.5  x
1.2.3.0/99  0.5  bad-prefix
AS  0.5  no-number
1.2.3.0/24  not-a-number  bad-score
1.2.3.0/24  0.7  good
",
        );
        assert_eq!(r.entry_count(), 1);
        assert!(r.lookup("1.2.3.5".parse().unwrap()).is_some());
    }

    #[test]
    fn reload_from_file_works() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-asn-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("asn.txt");
        std::fs::write(&path, "1.2.3.0/24  0.7  initial\n").unwrap();
        let r = AsnReputation::cidr_only(vec![path.clone()]);
        assert!(r.lookup("1.2.3.4".parse().unwrap()).is_some());
        std::fs::write(&path, "5.6.7.0/24  0.9  replaced\n").unwrap();
        r.reload();
        assert!(r.lookup("1.2.3.4".parse().unwrap()).is_none());
        assert!(r.lookup("5.6.7.8".parse().unwrap()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
