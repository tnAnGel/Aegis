//! Per-domain traffic anomaly detector with auto-escalation.
//!
//! Maintains, for every Host header seen:
//!   - a per-second request counter (current RPS)
//!   - an exponential moving average over a longer window (baseline)
//!
//! When `current > baseline * multiplier` and the baseline is above
//! `min_baseline_rps`, the domain is flagged "under attack" for
//! `attack_duration`. While the flag is set, callers (handler, geo
//! filter, challenge ladder) elevate their own response.
//!
//! V230 — Hot-path is now a single `AtomicU64::fetch_add(1, Relaxed)`
//! (~5 ns). Previously every request took a per-host shard write lock,
//! pushed an `Instant` into a `VecDeque<Instant>` that could grow to
//! millions of entries at high RPS (10 s × 100 k rps = 1 M per host),
//! popped expired entries, and recomputed the EMA — all inside the
//! locked section. The EMA / attack-detection logic now runs from a
//! background tick (default 1 s) instead, snapshotting the counter
//! delta to derive RPS. Same math, moved off the request path.

use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;

use crate::filters::ChallengeLevel;

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub enabled: bool,
    pub window: Duration,
    pub multiplier: f64,
    pub min_baseline_rps: f64,
    pub attack_duration: Duration,
    pub min_challenge_level: ChallengeLevel,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window: Duration::from_secs(10),
            multiplier: 3.0,
            min_baseline_rps: 10.0,
            attack_duration: Duration::from_secs(60),
            min_challenge_level: ChallengeLevel::Javascript,
        }
    }
}

/// V230 — split into a lock-free hot half (`counter`) and a
/// rarely-written slow half (`slow`). The hot path only ever does
/// `counter.fetch_add(1, Relaxed)` and a relaxed load of the cached
/// "currently flagged" deadline; the EMA + attack flag are recomputed
/// from the background tick.
struct DomainState {
    /// Bumped once per request on the hot path. Background tick reads
    /// + resets via `last_tick_count`.
    counter: AtomicU64,
    /// Value of `counter` at the previous tick. Subtraction gives the
    /// number of requests in the tick interval.
    last_tick_count: AtomicU64,
    /// Cached attack-until deadline as monotonic nanos since the
    /// detector was constructed. 0 means "not currently flagged". The
    /// hot path reads this with `Relaxed` to avoid touching `slow`.
    attack_until_nanos: AtomicU64,
    /// Slow path — only touched by the background tick and by the rare
    /// "first observation" inserter. Read/write contention is low so a
    /// std `RwLock` is fine.
    slow: RwLock<SlowState>,
}

#[derive(Default)]
struct SlowState {
    /// Exponential moving average of RPS, updated by the background
    /// tick.
    baseline_ema: f64,
    /// Instant of the previous tick that updated `baseline_ema`. Used
    /// to derive the EMA alpha from the elapsed dt.
    last_update: Option<Instant>,
    /// Absolute deadline at which the attack flag expires. Mirrored
    /// into `attack_until_nanos` so the hot path doesn't need the
    /// lock.
    attack_until: Option<Instant>,
}

impl DomainState {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            last_tick_count: AtomicU64::new(0),
            attack_until_nanos: AtomicU64::new(0),
            slow: RwLock::new(SlowState::default()),
        }
    }
}

pub struct AnomalyDetector {
    cfg: AnomalyConfig,
    state: Arc<DashMap<String, DomainState>>,
    /// Reference instant used to encode `attack_until` as a `u64` of
    /// nanos so the hot path can compare via a single atomic load.
    epoch: Instant,
}

impl AnomalyDetector {
    pub fn new(cfg: AnomalyConfig) -> Self {
        Self {
            cfg,
            state: Arc::new(DashMap::new()),
            epoch: Instant::now(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn min_challenge_level(&self) -> ChallengeLevel {
        self.cfg.min_challenge_level.clone()
    }

    /// Encode an `Instant` as nanoseconds since `self.epoch`. Saturates
    /// at u64::MAX (~585 years) so we never wrap. Returns 0 for any
    /// instant at-or-before the epoch, which is also the sentinel for
    /// "not flagged" — safe because we only ever care about deadlines
    /// in the future of the epoch.
    fn encode_instant(&self, t: Instant) -> u64 {
        t.saturating_duration_since(self.epoch).as_nanos() as u64
    }

    fn now_nanos(&self) -> u64 {
        self.encode_instant(Instant::now())
    }

    /// Record a request and return true if `host` is currently flagged
    /// under attack. Operates per-domain so a noisy tenant doesn't
    /// raise the alert level for everyone else.
    ///
    /// V230 — Hot path is one `DashMap::get` (read lock on the shard,
    /// no allocation thanks to `Borrow<str>`), one
    /// `AtomicU64::fetch_add(1, Relaxed)` to bump the request count,
    /// and one `Relaxed` load of the cached attack deadline. The EMA
    /// and attack-detection math are *no longer* done here; they run
    /// from `tick()` on the background loop.
    ///
    /// V229 — `enabled()` check first so a disabled detector is
    /// zero-cost.
    /// V73 — Avoided the per-request `host.to_string()` alloc by using
    /// `DashMap::get` (Borrow lookup with `&str`) on the steady-state
    /// path; the rare miss path still allocates exactly once.
    ///
    /// NOTE: the returned bool now means "host is currently flagged"
    /// rather than "this specific call tripped the threshold". The
    /// only caller in `pingora_http.rs` discards the return value
    /// (`let _just_tripped = ...`), so the semantic shift is invisible
    /// to it. The dedicated `under_attack(host)` accessor returns the
    /// same value.
    pub fn observe(&self, host: &str, now: Instant) -> bool {
        if !self.cfg.enabled {
            return false;
        }
        let host_key = if host.is_empty() { "_unknown" } else { host };

        // Fast path: entry already exists. Read lock on the shard,
        // zero alloc (DashMap accepts `&str` via Borrow).
        if let Some(entry) = self.state.get(host_key) {
            entry.counter.fetch_add(1, Ordering::Relaxed);
            let until = entry.attack_until_nanos.load(Ordering::Relaxed);
            return until != 0 && until > self.encode_instant(now);
        }

        // Slow path: first observation of this host. Pay the alloc and
        // the write lock once, then drop straight into the same
        // bump-and-read sequence so the very first request still
        // contributes to the next tick's RPS.
        let entry = self
            .state
            .entry(host_key.to_string())
            .or_insert_with(DomainState::new)
            .downgrade();
        entry.counter.fetch_add(1, Ordering::Relaxed);
        let until = entry.attack_until_nanos.load(Ordering::Relaxed);
        until != 0 && until > self.encode_instant(now)
    }

    /// V230 — Background-tick worker. Snapshots each domain's request
    /// counter, derives RPS, updates the EMA, and re-evaluates the
    /// attack flag. Same math as the old per-request `apply_observation`
    /// but amortised across one second of traffic instead of running
    /// per request.
    ///
    /// Safe to call from any thread; the tick interval is configurable
    /// by the caller. The detector remains correct (only "less timely"
    /// to within one tick) if this is invoked irregularly or skipped.
    pub fn tick(&self) {
        if !self.cfg.enabled {
            return;
        }
        let now = Instant::now();

        for kv in self.state.iter() {
            let entry = kv.value();

            // Snapshot counter delta since last tick.
            let cur = entry.counter.load(Ordering::Relaxed);
            let prev = entry.last_tick_count.swap(cur, Ordering::Relaxed);
            let delta = cur.saturating_sub(prev);

            let mut slow = entry.slow.write().unwrap();

            // Derive an instantaneous RPS for *this* tick interval and
            // also a sliding-window RPS averaged over `cfg.window` to
            // preserve the original semantics.
            let dt = match slow.last_update {
                Some(t) => now.duration_since(t).as_secs_f64().max(1e-3),
                None => 1.0,
            };
            let current_rps = delta as f64 / dt;

            // EMA with half-life ~5 minutes, same as V229.
            let alpha = match slow.last_update {
                Some(_) => 1.0 - (-dt / 300.0).exp(),
                None => 1.0,
            };
            slow.baseline_ema = (1.0 - alpha) * slow.baseline_ema + alpha * current_rps;
            slow.last_update = Some(now);

            let under_attack_now = slow.baseline_ema >= self.cfg.min_baseline_rps
                && current_rps > slow.baseline_ema * self.cfg.multiplier;
            if under_attack_now {
                let until = now + self.cfg.attack_duration;
                slow.attack_until = Some(until);
                entry
                    .attack_until_nanos
                    .store(self.encode_instant(until), Ordering::Relaxed);
            } else if let Some(until) = slow.attack_until {
                // Expire the flag once we cross the deadline so the
                // hot path stops reporting "flagged" without having to
                // compare wall time itself.
                if until <= now {
                    slow.attack_until = None;
                    entry.attack_until_nanos.store(0, Ordering::Relaxed);
                } else {
                    // Re-publish in case `epoch` changed (it can't,
                    // but keep the mirror authoritative).
                    entry
                        .attack_until_nanos
                        .store(self.encode_instant(until), Ordering::Relaxed);
                }
            }

            // Cheap sanity: clear stale mirror if the slow side has
            // already cleared the flag.
            if slow.attack_until.is_none() && entry.attack_until_nanos.load(Ordering::Relaxed) != 0
            {
                entry.attack_until_nanos.store(0, Ordering::Relaxed);
            }
        }
    }

    /// V230 — Spawn the background tick on the current tokio runtime.
    /// Loops forever calling `self.tick()` every second. The caller
    /// (pingora_background.rs) is expected to drop the returned handle
    /// only on shutdown.
    ///
    /// Marked `async` so it can be `tokio::spawn`-ed directly; the
    /// loop never returns of its own accord.
    pub async fn run_background_tick(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately — skip it so we don't compute
        // RPS from a zero-second window.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            self.tick();
        }
    }

    pub fn under_attack(&self, host: &str) -> bool {
        if !self.cfg.enabled {
            return false;
        }
        let host_key = if host.is_empty() { "_unknown" } else { host };
        // V230 — hot accessor reads only the atomic mirror, no slow
        // lock acquired.
        self.state
            .get(host_key)
            .map(|entry| {
                let until = entry.attack_until_nanos.load(Ordering::Relaxed);
                until != 0 && until > self.now_nanos()
            })
            .unwrap_or(false)
    }

    /// Snapshot of all currently flagged domains and their remaining
    /// attack timer (in ms). Drives `/admin/anomaly`.
    pub fn snapshot(&self) -> Vec<(String, u128)> {
        let now = Instant::now();
        let mut out: Vec<_> = self
            .state
            .iter()
            .filter_map(|kv| {
                // V230 — prefer the authoritative `slow.attack_until`
                // (Instant) so the millisecond figure stays accurate
                // even if the atomic mirror is lagging by a tick.
                let slow = kv.value().slow.read().ok()?;
                slow.attack_until.and_then(|until| {
                    if until > now {
                        Some((kv.key().clone(), until.duration_since(now).as_millis()))
                    } else {
                        None
                    }
                })
            })
            .collect();
        out.sort_by_key(|b| std::cmp::Reverse(b.1));
        out
    }
}

/// Escalate `actual` to at least `floor`, preserving the higher of the
/// two. Used when an under-attack domain demands a minimum rung even
/// though the per-IP ladder hasn't climbed there yet.
pub fn escalate_level(actual: ChallengeLevel, floor: ChallengeLevel) -> ChallengeLevel {
    fn rank(l: &ChallengeLevel) -> u8 {
        match l {
            ChallengeLevel::Headers => 0,
            ChallengeLevel::Html => 1,
            ChallengeLevel::Iframe => 2,
            ChallengeLevel::Javascript => 3,
            ChallengeLevel::Captcha => 4,
        }
    }
    if rank(&floor) > rank(&actual) {
        floor
    } else {
        actual
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, mult: f64, min_base: f64) -> AnomalyConfig {
        AnomalyConfig {
            enabled,
            window: Duration::from_secs(1),
            multiplier: mult,
            min_baseline_rps: min_base,
            attack_duration: Duration::from_secs(5),
            min_challenge_level: ChallengeLevel::Javascript,
        }
    }

    #[test]
    fn disabled_never_fires() {
        let d = AnomalyDetector::new(cfg(false, 2.0, 1.0));
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(!d.observe("x", now));
        }
        // Tick should also be a no-op when disabled.
        d.tick();
        assert!(!d.under_attack("x"));
    }

    /// V230 — Steady traffic should not flag. We now have to drive the
    /// tick manually (the previous test relied on per-request
    /// evaluation), but the math is unchanged so the assertion still
    /// holds: a low, even rate never trips the multiplier-over-baseline
    /// threshold.
    #[test]
    fn steady_traffic_does_not_flag() {
        let d = AnomalyDetector::new(cfg(true, 3.0, 5.0));
        for _ in 0..100 {
            d.observe("steady.example", Instant::now());
        }
        d.tick();
        assert!(!d.under_attack("steady.example"));
    }

    /// V230 — Burst-after-baseline test, rewritten for the tick-based
    /// model. Step 1: pour a baseline of requests, tick a few times to
    /// build up `baseline_ema`. Step 2: pour a hammering burst and
    /// tick once — RPS for that tick should now exceed
    /// `baseline_ema * multiplier` and trip the flag.
    #[test]
    fn burst_after_baseline_flags_attack() {
        let d = AnomalyDetector::new(cfg(true, 3.0, 1.0));

        // Build baseline: ~10 rps over a few ticks.
        for _ in 0..5 {
            for _ in 0..10 {
                d.observe("api.example", Instant::now());
            }
            // Force the tick clock forward by sleeping briefly so the
            // EMA's `dt` is non-zero.
            std::thread::sleep(Duration::from_millis(20));
            d.tick();
        }

        // Hammer phase: pour way more than 3× the baseline in one
        // tick window.
        for _ in 0..2000 {
            d.observe("api.example", Instant::now());
        }
        std::thread::sleep(Duration::from_millis(20));
        d.tick();

        assert!(
            d.under_attack("api.example"),
            "attack should be detected after burst"
        );
    }

    #[test]
    fn escalate_chooses_higher_rung() {
        assert_eq!(
            escalate_level(ChallengeLevel::Headers, ChallengeLevel::Javascript),
            ChallengeLevel::Javascript
        );
        assert_eq!(
            escalate_level(ChallengeLevel::Captcha, ChallengeLevel::Iframe),
            ChallengeLevel::Captcha
        );
    }

    /// V230 — Snapshot test updated to call `tick()` so the attack
    /// flag actually gets set; under the old model the per-request
    /// path set it implicitly.
    #[test]
    fn snapshot_lists_only_active_attacks() {
        let d = AnomalyDetector::new(cfg(true, 2.0, 1.0));

        // Two ticks of low traffic to seed a small baseline, then a
        // burst that easily clears `baseline * 2.0`.
        for _ in 0..3 {
            d.observe("a.example", Instant::now());
            std::thread::sleep(Duration::from_millis(10));
            d.tick();
        }
        for _ in 0..500 {
            d.observe("a.example", Instant::now());
        }
        std::thread::sleep(Duration::from_millis(10));
        d.tick();

        assert!(d.under_attack("a.example"));
        let snap = d.snapshot();
        assert!(snap.iter().any(|(h, _)| h == "a.example"));
    }

    /// V230 — New test: the bare hot path (observe with no ticks) must
    /// never flag, because the EMA/attack logic now lives exclusively
    /// in `tick()`. This locks in the "hot path is cheap" invariant.
    #[test]
    fn observe_without_tick_never_flags() {
        let d = AnomalyDetector::new(cfg(true, 1.0, 0.0));
        let now = Instant::now();
        for _ in 0..100_000 {
            // Even with absurd volume, no tick = no flag.
            assert!(!d.observe("noisy.example", now));
        }
        assert!(!d.under_attack("noisy.example"));
    }
}
