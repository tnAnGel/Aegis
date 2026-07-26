//! V187 — FlowSpec / BGP RTBH dispatcher.
//!
//! Aegis's nftables/iptables/XDP backends drop hostile traffic at the
//! host edge. For volumetric attacks where the host edge is the
//! bottleneck, the right answer is *upstream blackhole* — announce
//! the /32 (or /128) to your transit provider's BGP RTBH community,
//! and the drop happens at the carrier edge.
//!
//! FastNetMon does this at L3/L4; we want it driven by L7 verdicts
//! so a Risk-Engine `FullEnforce` on a scraper farm can propagate
//! the same /32 list a volumetric event would.
//!
//! This module is the *dispatcher*: takes block decisions and writes
//! them to a [BgpAnnouncer] trait. Default ships an exabgp-pipe
//! adapter (writes lines like `announce route 1.2.3.4/32 next-hop
//! 192.0.2.1 community 65000:666` to a configured file/pipe; exabgp
//! does the BGP heavy lifting). Operators with goBGP / FRR can swap
//! in their own announcer.
//!
//! Decision lifecycle:
//!
//! * `announce(ip)` — added to active set; the announcer emits a
//!   route. Idempotent.
//! * `withdraw(ip)` — removed; announcer emits a withdraw.
//! * `expire_ttl()` — periodic GC; entries older than `ttl` are
//!   automatically withdrawn (so a blocked attacker isn't blackholed
//!   forever on the carrier).

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub trait BgpAnnouncer: Send + Sync {
    fn announce(&self, ip: IpAddr, community: &str) -> std::io::Result<()>;
    fn withdraw(&self, ip: IpAddr) -> std::io::Result<()>;
}

/// No-op announcer for tests and dry-run mode.
#[derive(Default, Clone)]
pub struct InMemoryAnnouncer {
    pub announced: Arc<Mutex<Vec<(IpAddr, String)>>>,
    pub withdrawn: Arc<Mutex<Vec<IpAddr>>>,
}

impl BgpAnnouncer for InMemoryAnnouncer {
    fn announce(&self, ip: IpAddr, community: &str) -> std::io::Result<()> {
        self.announced.lock().unwrap().push((ip, community.into()));
        Ok(())
    }
    fn withdraw(&self, ip: IpAddr) -> std::io::Result<()> {
        self.withdrawn.lock().unwrap().push(ip);
        Ok(())
    }
}

/// Append-only file announcer compatible with exabgp's stdin-from-file
/// mode. Operators run exabgp pointed at this file; we write
/// announce/withdraw lines and exabgp pumps BGP updates upstream.
#[derive(Clone)]
pub struct ExabgpPipeAnnouncer {
    path: PathBuf,
    next_hop: String,
}

impl ExabgpPipeAnnouncer {
    pub fn new(path: PathBuf, next_hop: String) -> Self {
        Self { path, next_hop }
    }
}

impl BgpAnnouncer for ExabgpPipeAnnouncer {
    fn announce(&self, ip: IpAddr, community: &str) -> std::io::Result<()> {
        let line = format!(
            "announce route {}/{} next-hop {} community {}\n",
            ip,
            host_mask(ip),
            self.next_hop,
            community
        );
        write_line(&self.path, &line)
    }
    fn withdraw(&self, ip: IpAddr) -> std::io::Result<()> {
        let line = format!(
            "withdraw route {}/{} next-hop {}\n",
            ip,
            host_mask(ip),
            self.next_hop
        );
        write_line(&self.path, &line)
    }
}

fn host_mask(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// V233 — `true` only if `ip` is a target it is safe and meaningful to
/// blackhole at a transit provider, i.e. a plausibly public unicast
/// host. Returns `false` for addresses that must never be announced to
/// a carrier RTBH community:
///
/// * unspecified — `0.0.0.0`, `::`
/// * loopback — `127.0.0.0/8`, `::1`
/// * multicast — `224.0.0.0/4`, `ff00::/8`
/// * link-local — `169.254.0.0/16`, `fe80::/10`
/// * RFC1918 private — `10/8`, `172.16/12`, `192.168/16`
/// * IPv6 unique-local — `fc00::/7`
///
/// This is defence-in-depth: the primary control is that `announce`
/// only ever receives the real TCP peer address (see [`announce`]).
/// But blackholing e.g. a private or loopback range at the carrier is
/// never correct, so we reject it unconditionally. Announcing such a
/// route would either be a no-op upstream or, worse, propagate a
/// null-route for a range an operator legitimately uses.
fn is_blackholeable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_documentation()
            {
                return false;
            }
            // 100.64.0.0/10 — RFC6598 carrier-grade NAT shared space.
            // `Ipv4Addr::is_shared` is unstable, so test the octets.
            let o = v4.octets();
            if o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                return false;
            }
            let seg0 = v6.segments()[0];
            // fe80::/10 — link-local unicast.
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            // fc00::/7 — unique-local addresses (`is_unique_local` unstable).
            if (seg0 & 0xfe00) == 0xfc00 {
                return false;
            }
            // An IPv4-mapped IPv6 address (::ffff:0:0/96) carries an IPv4
            // host; defer to the IPv4 rules so a mapped private/loopback
            // address can't sneak through the v6 branch.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blackholeable(IpAddr::V4(mapped));
            }
            true
        }
    }
}

fn write_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())
}

#[derive(Debug, Clone)]
struct Entry {
    inserted: Instant,
    community: String,
}

pub struct BgpRtbhDispatcher {
    announcer: Arc<dyn BgpAnnouncer>,
    active: RwLock<HashMap<IpAddr, Entry>>,
    ttl: Duration,
    default_community: String,
}

impl BgpRtbhDispatcher {
    pub fn new(announcer: Arc<dyn BgpAnnouncer>, default_community: String, ttl: Duration) -> Self {
        Self {
            announcer,
            active: RwLock::new(HashMap::new()),
            ttl,
            default_community,
        }
    }

    /// Announce a /32 (or /128) blackhole route for `ip` to the carrier.
    ///
    /// # Safety invariant — caller MUST uphold
    ///
    /// `ip` **MUST** be the kernel-level TCP peer address of the
    /// connection (i.e. the remote end of the accepted socket, as
    /// reported by the OS). It **MUST NEVER** be an address derived from
    /// a request header (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`,
    /// `CF-Connecting-IP`, etc.).
    ///
    /// Rationale: this routine asks the *transit provider* to blackhole
    /// the address. Request headers are fully attacker-controlled, so a
    /// header-derived IP would let any remote client name a VICTIM IP and
    /// have the carrier null-route it — a remote-triggered DoS / auth-
    /// bypass abuse primitive. The address must come from the socket,
    /// which an attacker cannot forge (modulo on-path spoofing, which BGP
    /// RTBH cannot defend against anyway).
    ///
    /// As defence-in-depth, [`announce_with_community`] additionally
    /// rejects targets that must never be blackholed at a carrier
    /// regardless of provenance — see [`is_blackholeable`]. A rejected
    /// target returns `ErrorKind::InvalidInput` and announces nothing.
    pub fn announce(&self, ip: IpAddr) -> std::io::Result<()> {
        self.announce_with_community(ip, &self.default_community.clone())
    }

    /// See [`announce`](Self::announce) for the caller-upheld invariant
    /// that `ip` is the real TCP peer, never a header-derived address.
    pub fn announce_with_community(&self, ip: IpAddr, community: &str) -> std::io::Result<()> {
        // V233 — harden the announce boundary. Even if a future caller
        // wires in a bad IP source, never ask the carrier to blackhole an
        // address that is structurally not a routable public host: that
        // would be useless at best and a self-inflicted / victim-targeted
        // outage at worst. Reject loopback, link-local, multicast,
        // unspecified, and RFC1918 / unique-local private ranges.
        if !is_blackholeable(ip) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to announce non-public / non-routable RTBH target {ip}: \
                     announce() must only ever receive the kernel TCP peer address"
                ),
            ));
        }

        let mut g = self.active.write().unwrap();
        if g.contains_key(&ip) {
            return Ok(());
        }
        self.announcer.announce(ip, community)?;
        g.insert(
            ip,
            Entry {
                inserted: Instant::now(),
                community: community.into(),
            },
        );
        Ok(())
    }

    pub fn withdraw(&self, ip: IpAddr) -> std::io::Result<()> {
        let mut g = self.active.write().unwrap();
        if g.remove(&ip).is_some() {
            self.announcer.withdraw(ip)?;
        }
        Ok(())
    }

    pub fn expire_ttl(&self) -> usize {
        let now = Instant::now();
        let to_remove: Vec<IpAddr> = {
            let g = self.active.read().unwrap();
            g.iter()
                .filter(|(_, e)| now.saturating_duration_since(e.inserted) > self.ttl)
                .map(|(ip, _)| *ip)
                .collect()
        };
        let mut n = 0;
        for ip in to_remove {
            let _ = self.withdraw(ip);
            n += 1;
        }
        n
    }

    pub fn active(&self) -> Vec<(IpAddr, String, Duration)> {
        let now = Instant::now();
        self.active
            .read()
            .unwrap()
            .iter()
            .map(|(ip, e)| {
                (
                    *ip,
                    e.community.clone(),
                    now.saturating_duration_since(e.inserted),
                )
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.active.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dispatcher() -> (BgpRtbhDispatcher, InMemoryAnnouncer) {
        let mem = InMemoryAnnouncer::default();
        let d = BgpRtbhDispatcher::new(
            Arc::new(mem.clone()),
            "65000:666".into(),
            Duration::from_secs(60),
        );
        (d, mem)
    }

    // V233 — dispatcher tests use a genuinely public IP (9.9.9.x, Quad9
    // space). The old 203.0.113.x is TEST-NET-3 documentation space, which
    // `is_blackholeable` now correctly rejects.
    #[test]
    fn announce_writes_route() {
        let (d, mem) = dispatcher();
        let ip: IpAddr = Ipv4Addr::new(9, 9, 9, 1).into();
        d.announce(ip).unwrap();
        let g = mem.announced.lock().unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].0, ip);
        assert_eq!(g[0].1, "65000:666");
    }

    #[test]
    fn double_announce_is_idempotent() {
        let (d, mem) = dispatcher();
        let ip: IpAddr = Ipv4Addr::new(9, 9, 9, 2).into();
        d.announce(ip).unwrap();
        d.announce(ip).unwrap();
        assert_eq!(mem.announced.lock().unwrap().len(), 1);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn withdraw_emits_event() {
        let (d, mem) = dispatcher();
        let ip: IpAddr = Ipv4Addr::new(9, 9, 9, 3).into();
        d.announce(ip).unwrap();
        d.withdraw(ip).unwrap();
        assert_eq!(mem.withdrawn.lock().unwrap()[0], ip);
        assert_eq!(d.len(), 0);
    }

    // V233 — announce() must refuse non-public / non-routable targets so a
    // header-derived IP can never null-route a victim (or an operator's own
    // private range) at the carrier. Each rejected announce must emit
    // nothing and leave the active set empty.
    #[test]
    fn announce_rejects_loopback_private_and_unspecified() {
        use std::net::Ipv6Addr;

        let reject: &[IpAddr] = &[
            // unspecified
            Ipv4Addr::new(0, 0, 0, 0).into(),
            Ipv6Addr::UNSPECIFIED.into(),
            // loopback
            Ipv4Addr::new(127, 0, 0, 1).into(),
            Ipv4Addr::new(127, 13, 37, 9).into(),
            Ipv6Addr::LOCALHOST.into(),
            // RFC1918 private
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(172, 16, 5, 5).into(),
            Ipv4Addr::new(192, 168, 1, 1).into(),
            // link-local
            Ipv4Addr::new(169, 254, 1, 1).into(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
            // multicast / broadcast
            Ipv4Addr::new(224, 0, 0, 1).into(),
            Ipv4Addr::new(255, 255, 255, 255).into(),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).into(),
            // IPv6 unique-local
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into(),
            // CGNAT shared space (RFC6598)
            Ipv4Addr::new(100, 64, 0, 1).into(),
            // IPv4-mapped IPv6 carrying a private host must not slip through
            Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped().into(),
        ];

        for &ip in reject {
            let (d, mem) = dispatcher();
            let err = d.announce(ip).expect_err(&format!("{ip} must be rejected"));
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "for {ip}");
            assert!(
                mem.announced.lock().unwrap().is_empty(),
                "{ip} must announce nothing"
            );
            assert!(d.is_empty(), "{ip} must not enter the active set");
        }

        // Control: a genuinely public address is still accepted.
        let (d, mem) = dispatcher();
        d.announce(Ipv4Addr::new(9, 9, 9, 9).into()).unwrap();
        assert_eq!(mem.announced.lock().unwrap().len(), 1);
    }

    #[test]
    fn expire_ttl_withdraws_old_entries() {
        let mem = InMemoryAnnouncer::default();
        let d = BgpRtbhDispatcher::new(
            Arc::new(mem.clone()),
            "65000:666".into(),
            Duration::from_millis(50),
        );
        // V233 — public IP; 203.0.113.x (TEST-NET-3) is now rejected by
        // the dispatcher's announce() gate.
        let ip: IpAddr = Ipv4Addr::new(9, 9, 9, 4).into();
        d.announce(ip).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let n = d.expire_ttl();
        assert_eq!(n, 1);
        assert_eq!(mem.withdrawn.lock().unwrap().len(), 1);
    }

    #[test]
    fn exabgp_format_round_trip() {
        let tmp = std::env::temp_dir().join(format!("aegis-exabgp-{}.pipe", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let a = ExabgpPipeAnnouncer::new(tmp.clone(), "192.0.2.1".into());
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 9).into();
        a.announce(ip, "65000:666").unwrap();
        a.withdraw(ip).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert!(
            content
                .contains("announce route 203.0.113.9/32 next-hop 192.0.2.1 community 65000:666")
        );
        assert!(content.contains("withdraw route 203.0.113.9/32"));
    }
}
