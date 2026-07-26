//! V177 — JA4 churn score per-IP.
//!
//! Inspired by CDNetworks / hunt.io behavioural-correlation post:
//! attackers using TLS-fingerprint rotation libraries (utls,
//! curl-impersonate, golang fhttp) will emit a *different* JA4 every
//! few requests from the same IP. A real browser keeps the same JA4
//! across hundreds of requests until you upgrade Chrome.
//!
//! The score is the ratio of unique JA4s to total observations in a
//! sliding window per (IP, time-window). Feeds the V139 ML scorer
//! as the `ja4_churn` feature.
//!
//! ## Score semantics
//!
//! * `0.0` — every request shared the same JA4 (normal browser).
//! * `1.0` — every request used a unique JA4 (rotation in progress).
//! * Mid-range values typical of users behind shared NAT (multiple
//!   real browsers from one egress IP).
//!
//! The V108 RiskEngine treats score > 0.6 as suspicious; > 0.9 as
//! enforcement-grade.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Window {
    /// Recent JA4 observations as (ja4_hash, observed_at).
    samples: VecDeque<(u64, Instant)>,
}

impl Window {
    fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(32),
        }
    }

    fn record(&mut self, ja4_hash: u64, now: Instant, ttl: Duration, cap: usize) {
        self.samples.push_back((ja4_hash, now));
        // Evict by age first, then by count cap.
        while let Some((_, t)) = self.samples.front() {
            if now.duration_since(*t) > ttl {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        while self.samples.len() > cap {
            self.samples.pop_front();
        }
    }

    fn churn(&self) -> f32 {
        let total = self.samples.len();
        if total < 2 {
            return 0.0;
        }
        let mut seen = std::collections::HashSet::with_capacity(total);
        for (h, _) in &self.samples {
            seen.insert(*h);
        }
        seen.len() as f32 / total as f32
    }
}

pub struct Ja4ChurnTracker {
    by_ip: DashMap<IpAddr, Window>,
    tracked_count: AtomicUsize,
    window_ttl: Duration,
    sample_cap: usize,
}

impl Ja4ChurnTracker {
    pub fn new(window_secs: u64, sample_cap: usize) -> Self {
        Self {
            // V230 — boost shard count to 128. Per-IP writes happen on
            // every TLS request via observe()'s get_mut/insert; the
            // default shard amount (typically 4× CPU count) becomes a
            // contention point under heavy fan-in. 128 shards keeps
            // write-side lock collisions rare across busy edge cores.
            by_ip: DashMap::with_shard_amount(128),
            tracked_count: AtomicUsize::new(0),
            window_ttl: Duration::from_secs(window_secs),
            sample_cap,
        }
    }

    /// Default: 60 s window, last 16 samples. Captures rotation in
    /// real-time without thrashing memory on long-lived sessions.
    pub fn default_config() -> Self {
        Self::new(60, 16)
    }

    /// Atomic fast-path for hot callers — avoids any shard lock when
    /// the tracker is empty (common at cold start and during low-JA4
    /// traffic windows).
    pub fn is_empty(&self) -> bool {
        self.tracked_count.load(Ordering::Relaxed) == 0
    }

    pub fn observe(&self, ip: IpAddr, ja4: &str) {
        use dashmap::mapref::entry::Entry;
        let h = hash_ja4(ja4);
        let now = Instant::now();
        match self.by_ip.entry(ip) {
            Entry::Occupied(mut occ) => {
                occ.get_mut()
                    .record(h, now, self.window_ttl, self.sample_cap);
            }
            Entry::Vacant(vac) => {
                let mut w = Window::new();
                w.record(h, now, self.window_ttl, self.sample_cap);
                vac.insert(w);
                self.tracked_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // V230 — read path. `get()` takes only the shard read lock; the
    // Window::churn() body iterates the VecDeque into a HashSet without
    // mutating it. Do NOT switch to `get_mut` here — that would block
    // concurrent observe()/churn() callers on the same shard and undo
    // the V228 RwLock→DashMap win.
    pub fn churn(&self, ip: IpAddr) -> f32 {
        self.by_ip.get(&ip).map(|w| w.churn()).unwrap_or(0.0)
    }

    /// Background sweep — drop windows that haven't observed traffic
    /// for 4 × window_ttl. Bound memory across long uptimes.
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        let cutoff = self.window_ttl * 4;
        let before = self.by_ip.len();
        self.by_ip.retain(|_, w| {
            w.samples
                .back()
                .map(|(_, t)| now.duration_since(*t) < cutoff)
                .unwrap_or(false)
        });
        let after = self.by_ip.len();
        let removed = before - after;
        if removed > 0 {
            self.tracked_count.fetch_sub(removed, Ordering::Relaxed);
        }
        removed
    }

    pub fn tracked_ips(&self) -> usize {
        self.tracked_count.load(Ordering::Relaxed)
    }
}

fn hash_ja4(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn same_ja4_repeat_zero_churn() {
        let t = Ja4ChurnTracker::default_config();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        for _ in 0..10 {
            t.observe(ip, "t13d1516h2_8daaf6152771_b1ff8ab2d16f");
        }
        assert!(t.churn(ip) < 0.2);
    }

    #[test]
    fn rotation_yields_full_churn() {
        let t = Ja4ChurnTracker::default_config();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        for i in 0..8 {
            t.observe(ip, &format!("t13d000000_aaaaaaaaaaaa_{i:012x}"));
        }
        assert!((t.churn(ip) - 1.0).abs() < 0.01);
    }

    #[test]
    fn shared_nat_midrange_churn() {
        let t = Ja4ChurnTracker::default_config();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();
        // 2 distinct browsers, 4 requests each = 2/8 = 0.25
        for _ in 0..4 {
            t.observe(ip, "ja4_browser_a");
        }
        for _ in 0..4 {
            t.observe(ip, "ja4_browser_b");
        }
        let c = t.churn(ip);
        assert!((0.2..=0.3).contains(&c), "got {c}");
    }

    #[test]
    fn no_samples_means_zero() {
        let t = Ja4ChurnTracker::default_config();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 4).into();
        assert_eq!(t.churn(ip), 0.0);
    }

    #[test]
    fn gc_drops_idle_ips() {
        let t = Ja4ChurnTracker::new(1, 4);
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 5).into();
        t.observe(ip, "x");
        assert_eq!(t.tracked_ips(), 1);
        std::thread::sleep(Duration::from_millis(4500));
        t.gc();
        assert_eq!(t.tracked_ips(), 0);
    }
}
