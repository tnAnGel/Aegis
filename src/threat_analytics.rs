//! V121 — Threat analytics: split per-IP bot detections from
//! distributed DDoS (botnet) detections.
//!
//! info.md: operators want different lenses on attack data.
//!
//! * **Single bots**: one IP exhibiting bot-like behaviour — fingerprint
//!   mismatch (V110), UA fakery, sustained per-IP rate. The kind of
//!   thing a single scraper or automation tool produces. Operator
//!   action: deny, challenge, or rate-limit that IP.
//! * **DDoS / botnet**: many distinct IPs hitting the same endpoint at
//!   the same time — characteristic of a coordinated attack from
//!   distributed sources where no single IP exceeds the per-IP limit
//!   but the aggregate is enormous. Operator action: aggressive
//!   per-endpoint rate-limit, geographic filtering, attack-mode
//!   challenge floor.
//!
//! V121 ships [ThreatAnalytics] — two cheap rolling-window aggregators
//! that the proxy populates as decisions land, and the V122 admin UI
//! splits into two separate pages.
//!
//! Output shapes:
//!
//! * BotEvidence — top suspected single-IP bots: IP, why (mismatch /
//!   high score / fakery), score, hit count.
//! * DdosEvidence — top suspected attack-targeted endpoints: host +
//!   path, distinct attacking IPs, total hits, time window. The
//!   "distinct IPs hitting this endpoint" signal is what separates
//!   DDoS from a single bot.

use std::{
    collections::HashSet,
    net::IpAddr,
    time::{Duration, Instant},
};

use dashmap::DashMap;

const WINDOW: Duration = Duration::from_secs(300); // 5 min
const MAX_TRACKED_BOTS: usize = 256;
const MAX_TRACKED_ENDPOINTS: usize = 256;
/// An endpoint qualifies as DDoS-targeted when ≥ this many distinct
/// IPs have hit it in the window. Tunable per deployment.
const DDOS_DISTINCT_IP_THRESHOLD: usize = 10;

/// Why a single IP was flagged as a bot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotReason {
    UaFpMismatch,
    NoUserAgent,
    HighThreatScore,
    HighMlScore,
    HoneypotHit,
    WafSignature,
    /// Multiple signals fired for this IP across observations.
    Compound,
}

impl BotReason {
    pub fn as_str(self) -> &'static str {
        match self {
            BotReason::UaFpMismatch => "ua_fp_mismatch",
            BotReason::NoUserAgent => "no_user_agent",
            BotReason::HighThreatScore => "high_threat_score",
            BotReason::HighMlScore => "high_ml_score",
            BotReason::HoneypotHit => "honeypot_hit",
            BotReason::WafSignature => "waf_signature",
            BotReason::Compound => "compound",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BotEvidence {
    pub client_ip: String,
    pub primary_reason: BotReason,
    pub hits: u64,
    pub last_seen_unix_secs: u64,
}

#[derive(Debug, Clone)]
pub struct DdosEvidence {
    pub host: String,
    pub path_pattern: String,
    pub total_hits: u64,
    pub distinct_ips: usize,
    pub last_seen_unix_secs: u64,
}

struct BotEntry {
    primary_reason: BotReason,
    reasons_seen: u8, // bitmask
    hits: u64,
    last_seen: Instant,
}

struct EndpointEntry {
    hits: u64,
    ips: HashSet<IpAddr>,
    last_seen: Instant,
}

pub struct ThreatAnalytics {
    bots: DashMap<IpAddr, BotEntry>,
    endpoints: DashMap<(String, String), EndpointEntry>,
}

impl Default for ThreatAnalytics {
    fn default() -> Self {
        Self {
            // V230 — boost shard count to 128 to reduce lock contention under high concurrency.
            bots: DashMap::with_shard_amount(128),
            // V230 — boost shard count to 128 to reduce lock contention under high concurrency.
            endpoints: DashMap::with_shard_amount(128),
        }
    }
}

impl ThreatAnalytics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single-IP bot signal. Called whenever a per-IP
    /// detection fires (e.g. UA/JA4 mismatch, WAF signature with
    /// known-bad UA, etc.).
    pub fn observe_bot(&self, ip: IpAddr, reason: BotReason) {
        let now = Instant::now();
        {
            let mut entry = self.bots.entry(ip).or_insert_with(|| BotEntry {
                primary_reason: reason,
                reasons_seen: 0,
                hits: 0,
                last_seen: now,
            });
            entry.hits += 1;
            entry.last_seen = now;
            let bit = 1u8 << (reason as u8).min(7);
            entry.reasons_seen |= bit;
            if entry.reasons_seen.count_ones() > 1 {
                entry.primary_reason = BotReason::Compound;
            }
        }
        // Bound memory. Done after dropping the entry's RefMut to avoid
        // holding a shard lock while iterating across other shards.
        if self.bots.len() > MAX_TRACKED_BOTS {
            let oldest = self
                .bots
                .iter()
                .min_by_key(|r| r.value().last_seen)
                .map(|r| *r.key());
            if let Some(k) = oldest {
                self.bots.remove(&k);
            }
        }
    }

    /// Record an attack-shaped hit on a specific endpoint. Called
    /// when a request matches deny/challenge/throttle. Used to detect
    /// "many IPs hitting the same endpoint" = DDoS signal.
    pub fn observe_endpoint_hit(&self, host: &str, path_pattern: &str, ip: IpAddr) {
        if host.is_empty() {
            return;
        }
        let now = Instant::now();
        let key = (host.to_string(), path_pattern.to_string());
        {
            let mut entry = self.endpoints.entry(key).or_insert_with(|| EndpointEntry {
                hits: 0,
                ips: HashSet::new(),
                last_seen: now,
            });
            entry.hits += 1;
            entry.ips.insert(ip);
            entry.last_seen = now;
        }
        // Bound memory. Done after dropping the entry's RefMut to avoid
        // holding a shard lock while iterating across other shards.
        if self.endpoints.len() > MAX_TRACKED_ENDPOINTS {
            let oldest = self
                .endpoints
                .iter()
                .min_by_key(|r| r.value().last_seen)
                .map(|r| r.key().clone());
            if let Some(k) = oldest {
                self.endpoints.remove(&k);
            }
        }
    }

    /// Top suspected bots, sorted by hits desc, max `limit` entries.
    pub fn top_bots(&self, limit: usize) -> Vec<BotEvidence> {
        let mut out: Vec<BotEvidence> = self
            .bots
            .iter()
            .map(|r| BotEvidence {
                client_ip: r.key().to_string(),
                primary_reason: r.value().primary_reason,
                hits: r.value().hits,
                last_seen_unix_secs: unix_secs(r.value().last_seen),
            })
            .collect();
        out.sort_by(|a, b| b.hits.cmp(&a.hits));
        out.truncate(limit);
        out
    }

    /// Top DDoS-targeted endpoints (≥ DDOS_DISTINCT_IP_THRESHOLD
    /// distinct IPs), sorted by distinct_ips desc.
    pub fn top_ddos_targets(&self, limit: usize) -> Vec<DdosEvidence> {
        let mut out: Vec<DdosEvidence> = self
            .endpoints
            .iter()
            .filter(|r| r.value().ips.len() >= DDOS_DISTINCT_IP_THRESHOLD)
            .map(|r| {
                let (h, p) = r.key();
                let e = r.value();
                DdosEvidence {
                    host: h.clone(),
                    path_pattern: p.clone(),
                    total_hits: e.hits,
                    distinct_ips: e.ips.len(),
                    last_seen_unix_secs: unix_secs(e.last_seen),
                }
            })
            .collect();
        out.sort_by(|a, b| b.distinct_ips.cmp(&a.distinct_ips));
        out.truncate(limit);
        out
    }

    /// Diagnostic: total tracked entries.
    pub fn summary(&self) -> ThreatAnalyticsSummary {
        ThreatAnalyticsSummary {
            tracked_bots: self.bots.len(),
            tracked_endpoints: self.endpoints.len(),
        }
    }

    /// Periodic eviction of entries outside the 5-min window. Called
    /// from PingoraBackground tick.
    pub fn evict_stale(&self) {
        let now = Instant::now();
        self.bots
            .retain(|_, e| now.duration_since(e.last_seen) <= WINDOW);
        self.endpoints
            .retain(|_, e| now.duration_since(e.last_seen) <= WINDOW);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ThreatAnalyticsSummary {
    pub tracked_bots: usize,
    pub tracked_endpoints: usize,
}

fn unix_secs(t: Instant) -> u64 {
    // Best-effort conversion from monotonic to wall-clock UNIX seconds.
    // The admin UI uses this only for "last seen" relative-time
    // formatting, so a small monotonic-vs-wallclock drift is fine.
    let now_wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_mono = Instant::now();
    let age = now_mono.saturating_duration_since(t).as_secs();
    now_wall.saturating_sub(age)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn observe_bot_tracks_hits_and_reason() {
        let a = ThreatAnalytics::new();
        a.observe_bot(ip("1.1.1.1"), BotReason::UaFpMismatch);
        a.observe_bot(ip("1.1.1.1"), BotReason::UaFpMismatch);
        let top = a.top_bots(10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].client_ip, "1.1.1.1");
        assert_eq!(top[0].primary_reason, BotReason::UaFpMismatch);
        assert_eq!(top[0].hits, 2);
    }

    #[test]
    fn two_reasons_promotes_to_compound() {
        let a = ThreatAnalytics::new();
        a.observe_bot(ip("2.2.2.2"), BotReason::UaFpMismatch);
        a.observe_bot(ip("2.2.2.2"), BotReason::HighMlScore);
        let top = a.top_bots(10);
        assert_eq!(top[0].primary_reason, BotReason::Compound);
    }

    #[test]
    fn ddos_threshold_requires_many_ips() {
        let a = ThreatAnalytics::new();
        // 5 IPs hitting same endpoint → below threshold (10), not DDoS.
        for i in 1..=5u8 {
            a.observe_endpoint_hit("example.com", "/api/login", ip(&format!("10.0.0.{i}")));
        }
        assert!(a.top_ddos_targets(10).is_empty());
        // 12 distinct IPs → over threshold.
        for i in 1..=12u8 {
            a.observe_endpoint_hit("example.com", "/api/billing", ip(&format!("10.0.1.{i}")));
        }
        let top = a.top_ddos_targets(10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].path_pattern, "/api/billing");
        assert!(top[0].distinct_ips >= 10);
    }

    #[test]
    fn endpoints_with_single_ip_never_show_as_ddos() {
        let a = ThreatAnalytics::new();
        for _ in 0..1000 {
            a.observe_endpoint_hit("h", "/p", ip("3.3.3.3"));
        }
        assert!(a.top_ddos_targets(10).is_empty());
    }

    #[test]
    fn bots_sorted_by_hits_desc() {
        let a = ThreatAnalytics::new();
        for _ in 0..3 {
            a.observe_bot(ip("4.4.4.4"), BotReason::NoUserAgent);
        }
        for _ in 0..10 {
            a.observe_bot(ip("5.5.5.5"), BotReason::HoneypotHit);
        }
        let top = a.top_bots(10);
        assert_eq!(top[0].client_ip, "5.5.5.5");
        assert_eq!(top[1].client_ip, "4.4.4.4");
    }

    #[test]
    fn summary_counts() {
        let a = ThreatAnalytics::new();
        a.observe_bot(ip("1.1.1.1"), BotReason::HoneypotHit);
        a.observe_endpoint_hit("h", "/p", ip("2.2.2.2"));
        a.observe_endpoint_hit("h2", "/q", ip("3.3.3.3"));
        let s = a.summary();
        assert_eq!(s.tracked_bots, 1);
        assert_eq!(s.tracked_endpoints, 2);
    }

    #[test]
    fn empty_host_ignored() {
        let a = ThreatAnalytics::new();
        a.observe_endpoint_hit("", "/p", ip("1.1.1.1"));
        assert_eq!(a.summary().tracked_endpoints, 0);
    }
}
