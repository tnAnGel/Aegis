use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ThreatScore(pub f64);

impl ThreatScore {
    pub fn as_f64(self) -> f64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct WindowStats {
    allowed: u32,
    denied: u32,
    challenged: u32,
    last: Option<Instant>,
    /// V143 — previous request's timestamp (one step behind `last`).
    /// Used to compute the inter-request gap, which feeds the
    /// `fast_repeat` feature: gap < 1s for the same IP is the
    /// scripted-bot signature.
    prev_last: Option<Instant>,
}

/// Sliding-window per-IP threat scorer.
///
/// Counts how many requests from each client IP were allowed, denied or
/// challenged within `window`. The score is the share of "bad" outcomes
/// scaled to 0..=100 — useful for downstream throttling, alerts and
/// metrics export.
pub struct ThreatScorer {
    state: Arc<DashMap<IpAddr, WindowStats>>,
    window: Duration,
}

impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl ThreatScorer {
    pub fn new(window: Duration) -> Self {
        Self {
            // V230 — boost shard count to 128 for maximum per-IP parallelism on hot scoring path.
            state: Arc::new(DashMap::with_shard_amount(128)),
            window,
        }
    }

    /// Take the shard write lock exactly once, roll the window if it
    /// expired, then apply `bump` to the stat field in place. Avoids
    /// the entry-then-insert double-write that V73 measured costing
    /// ~10% of WAF-on throughput in the AegisPingoraProxy hot path.
    fn record(&self, ip: IpAddr, now: Instant, bump: impl FnOnce(&mut WindowStats)) {
        let mut entry = self.state.entry(ip).or_default();
        if let Some(last) = entry.last
            && now.duration_since(last) > self.window
        {
            entry.allowed = 0;
            entry.denied = 0;
            entry.challenged = 0;
            // Window rolled — clear gap history too, otherwise
            // fast_repeat would fire on the first request after a
            // long quiet period.
            entry.prev_last = None;
        }
        // Shift last → prev_last BEFORE writing the new timestamp.
        entry.prev_last = entry.last;
        entry.last = Some(now);
        bump(&mut entry);
    }

    pub fn record_allowed(&self, ip: IpAddr, now: Instant) {
        self.record(ip, now, |s| s.allowed = s.allowed.saturating_add(1));
    }

    pub fn record_denied(&self, ip: IpAddr, now: Instant) {
        self.record(ip, now, |s| s.denied = s.denied.saturating_add(1));
    }

    pub fn record_challenged(&self, ip: IpAddr, now: Instant) {
        self.record(ip, now, |s| s.challenged = s.challenged.saturating_add(1));
    }

    pub fn score(&self, ip: IpAddr) -> ThreatScore {
        let Some(stats) = self.state.get(&ip) else {
            return ThreatScore(0.0);
        };
        let total = (stats.allowed + stats.denied + stats.challenged) as f64;
        if total < 1.0 {
            return ThreatScore(0.0);
        }
        let weighted = stats.denied as f64 + stats.challenged as f64 * 0.5;
        ThreatScore(((weighted / total) * 100.0).clamp(0.0, 100.0))
    }

    pub fn top(&self, limit: usize) -> Vec<(IpAddr, ThreatScore)> {
        let mut all: Vec<_> = self
            .state
            .iter()
            .map(|e| (*e.key(), self.score(*e.key())))
            .collect();
        all.sort_by(|a, b| {
            b.1.0
                .partial_cmp(&a.1.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all.truncate(limit);
        all
    }

    /// V143 — denied requests / total in the sliding window. Returns
    /// 0.0 when no traffic. Cheaper than [score] for callers that
    /// only want the denied component (ML feature extraction).
    pub fn denied_rate(&self, ip: IpAddr) -> f32 {
        let Some(s) = self.state.get(&ip) else {
            return 0.0;
        };
        let total = (s.allowed + s.denied + s.challenged) as f32;
        if total < 1.0 {
            return 0.0;
        }
        (s.denied as f32 / total).clamp(0.0, 1.0)
    }

    /// V143 — challenged requests / total in the sliding window.
    pub fn challenged_rate(&self, ip: IpAddr) -> f32 {
        let Some(s) = self.state.get(&ip) else {
            return 0.0;
        };
        let total = (s.allowed + s.denied + s.challenged) as f32;
        if total < 1.0 {
            return 0.0;
        }
        (s.challenged as f32 / total).clamp(0.0, 1.0)
    }

    /// V143 — total requests in the current window divided by
    /// `window` seconds. Sustained scanning shows up here as
    /// 10+ req/s from one source; normal browsing is well under 1.
    pub fn recent_rps(&self, ip: IpAddr) -> f32 {
        let Some(s) = self.state.get(&ip) else {
            return 0.0;
        };
        let total = (s.allowed + s.denied + s.challenged) as f32;
        let secs = self.window.as_secs_f32().max(1.0);
        total / secs
    }

    /// V143 — "this IP repeated within 1 second" feature. Returns
    /// 1.0 when the gap between the previous request and `now` is
    /// under 1s, 0.0 otherwise (including first-ever request from
    /// the IP, where no prior timestamp exists).
    ///
    /// Designed to fire *after* the current request has been recorded,
    /// so the gap is between the now-just-stored timestamp and the
    /// one before it.
    pub fn fast_repeat(&self, ip: IpAddr) -> f32 {
        let Some(s) = self.state.get(&ip) else {
            return 0.0;
        };
        match (s.last, s.prev_last) {
            (Some(last), Some(prev)) if last.duration_since(prev) < Duration::from_secs(1) => 1.0,
            _ => 0.0,
        }
    }

    pub fn cleanup_stale(&self, now: Instant) {
        let retain_for = self.window * 5;
        self.state.retain(|_, v| match v.last {
            Some(t) => now.duration_since(t) <= retain_for,
            None => false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_history_zero_score() {
        let s = ThreatScorer::default();
        assert_eq!(s.score(ip("10.0.0.1")), ThreatScore(0.0));
    }

    #[test]
    fn all_denied_full_score() {
        let s = ThreatScorer::default();
        let now = Instant::now();
        for _ in 0..5 {
            s.record_denied(ip("10.0.0.2"), now);
        }
        assert_eq!(s.score(ip("10.0.0.2")), ThreatScore(100.0));
    }

    #[test]
    fn challenged_weighted_half() {
        let s = ThreatScorer::default();
        let now = Instant::now();
        for _ in 0..10 {
            s.record_challenged(ip("10.0.0.3"), now);
        }
        assert_eq!(s.score(ip("10.0.0.3")), ThreatScore(50.0));
    }

    #[test]
    fn mixed_outcomes() {
        let s = ThreatScorer::default();
        let now = Instant::now();
        for _ in 0..7 {
            s.record_allowed(ip("10.0.0.4"), now);
        }
        for _ in 0..3 {
            s.record_denied(ip("10.0.0.4"), now);
        }
        // 3 denied of 10 → 30
        assert!((s.score(ip("10.0.0.4")).as_f64() - 30.0).abs() < 0.001);
    }

    #[test]
    fn window_rolls_over() {
        let s = ThreatScorer::new(Duration::from_millis(10));
        let t0 = Instant::now();
        s.record_denied(ip("10.0.0.5"), t0);
        assert_eq!(s.score(ip("10.0.0.5")), ThreatScore(100.0));
        let t1 = t0 + Duration::from_millis(50);
        s.record_allowed(ip("10.0.0.5"), t1);
        // window rolled — only the new allowed counts
        assert_eq!(s.score(ip("10.0.0.5")), ThreatScore(0.0));
    }

    #[test]
    fn top_sorted_by_score() {
        let s = ThreatScorer::default();
        let now = Instant::now();
        s.record_allowed(ip("1.1.1.1"), now);
        s.record_denied(ip("2.2.2.2"), now);
        s.record_challenged(ip("3.3.3.3"), now);
        let top = s.top(3);
        assert_eq!(top[0].0, ip("2.2.2.2"));
    }

    // ── V143 — split outputs ──────────────────────────────────────

    #[test]
    fn denied_rate_zero_when_no_traffic() {
        let s = ThreatScorer::default();
        assert_eq!(s.denied_rate(ip("1.2.3.4")), 0.0);
        assert_eq!(s.challenged_rate(ip("1.2.3.4")), 0.0);
        assert_eq!(s.recent_rps(ip("1.2.3.4")), 0.0);
    }

    #[test]
    fn denied_and_challenged_rates_split_cleanly() {
        let s = ThreatScorer::default();
        let now = Instant::now();
        for _ in 0..4 {
            s.record_allowed(ip("1.2.3.5"), now);
        }
        for _ in 0..3 {
            s.record_denied(ip("1.2.3.5"), now);
        }
        for _ in 0..3 {
            s.record_challenged(ip("1.2.3.5"), now);
        }
        // 3/10 denied, 3/10 challenged.
        assert!((s.denied_rate(ip("1.2.3.5")) - 0.3).abs() < 1e-5);
        assert!((s.challenged_rate(ip("1.2.3.5")) - 0.3).abs() < 1e-5);
    }

    #[test]
    fn rps_reflects_total_over_window() {
        let s = ThreatScorer::new(Duration::from_secs(10));
        let now = Instant::now();
        for _ in 0..50 {
            s.record_allowed(ip("1.2.3.6"), now);
        }
        // 50 requests / 10s window = 5 rps.
        assert!((s.recent_rps(ip("1.2.3.6")) - 5.0).abs() < 1e-5);
    }

    #[test]
    fn fast_repeat_fires_for_sub_second_gap() {
        let s = ThreatScorer::default();
        let t0 = Instant::now();
        s.record_allowed(ip("1.2.3.7"), t0);
        // First request — no prior timestamp.
        assert_eq!(s.fast_repeat(ip("1.2.3.7")), 0.0);
        s.record_allowed(ip("1.2.3.7"), t0 + Duration::from_millis(200));
        // Gap 200ms → fires.
        assert_eq!(s.fast_repeat(ip("1.2.3.7")), 1.0);
    }

    #[test]
    fn fast_repeat_silent_for_normal_browsing_pace() {
        let s = ThreatScorer::default();
        let t0 = Instant::now();
        s.record_allowed(ip("1.2.3.8"), t0);
        s.record_allowed(ip("1.2.3.8"), t0 + Duration::from_secs(5));
        // Gap 5s → does NOT fire.
        assert_eq!(s.fast_repeat(ip("1.2.3.8")), 0.0);
    }

    #[test]
    fn fast_repeat_resets_when_window_rolls() {
        let s = ThreatScorer::new(Duration::from_millis(50));
        let t0 = Instant::now();
        s.record_allowed(ip("1.2.3.9"), t0);
        s.record_allowed(ip("1.2.3.9"), t0 + Duration::from_millis(10));
        assert_eq!(s.fast_repeat(ip("1.2.3.9")), 1.0);
        // Long gap → window rolls + prev_last cleared.
        s.record_allowed(ip("1.2.3.9"), t0 + Duration::from_secs(60));
        // Window rolled, so this is "first request after reset" → no
        // fast_repeat signal even though raw clock gap of 50s isn't <1s.
        assert_eq!(s.fast_repeat(ip("1.2.3.9")), 0.0);
    }

    #[test]
    fn cleanup_stale_drops_old() {
        let s = ThreatScorer::new(Duration::from_millis(5));
        let t0 = Instant::now();
        s.record_denied(ip("9.9.9.9"), t0);
        let later = t0 + Duration::from_secs(60);
        s.cleanup_stale(later);
        assert_eq!(s.score(ip("9.9.9.9")), ThreatScore(0.0));
    }
}
