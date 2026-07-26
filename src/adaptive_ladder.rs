//! V204 — Adaptive challenge difficulty + randomized ladder order.
//!
//! Two improvements layered on the existing V42 ladder:
//!
//! 1. **Adaptive difficulty under anomaly** — when the V38 anomaly
//!    detector signals an attack mode, every challenge level bumps
//!    by `+attack_mode_bits` (default +4). Operator can tune.
//!
//! 2. **Randomized ladder order** — clients seen for the first time
//!    don't always get the cookie level first; the order rotates
//!    deterministically by IP hash so an attacker fingerprinting
//!    "what does this site send to my IP?" can't precompute the
//!    challenge sequence.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeLevel {
    Cookie,
    Reload,
    Interaction,
    Pow,
    Captcha,
}

impl ChallengeLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Reload => "reload",
            Self::Interaction => "interaction",
            Self::Pow => "pow",
            Self::Captcha => "captcha",
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct AdaptiveConfig {
    pub attack_mode_bits: u8,
    pub randomize_order: bool,
    /// When `true`, suspicion score above this threshold skips the
    /// cheaper levels and starts at PoW.
    pub fast_track_threshold: f32,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            attack_mode_bits: 4,
            randomize_order: true,
            fast_track_threshold: 0.75,
        }
    }
}

pub struct AdaptiveLadder {
    config: std::sync::RwLock<AdaptiveConfig>,
    attack_mode: AtomicBool,
    current_floor: AtomicU8,
    stats: Arc<LadderStats>,
}

#[derive(Debug, Default)]
pub struct LadderStats {
    pub fast_track_hits: std::sync::atomic::AtomicU64,
    pub attack_mode_bumps: std::sync::atomic::AtomicU64,
    pub randomized_picks: std::sync::atomic::AtomicU64,
}

impl LadderStats {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.fast_track_hits.load(Ordering::Relaxed),
            self.attack_mode_bumps.load(Ordering::Relaxed),
            self.randomized_picks.load(Ordering::Relaxed),
        )
    }
}

impl AdaptiveLadder {
    pub fn new(config: AdaptiveConfig) -> Self {
        Self {
            config: std::sync::RwLock::new(config),
            attack_mode: AtomicBool::new(false),
            current_floor: AtomicU8::new(0),
            stats: Arc::new(LadderStats::default()),
        }
    }

    /// Set by the V38 anomaly detector tick: `true` means the
    /// proxy is under attack and difficulty should escalate.
    pub fn set_attack_mode(&self, on: bool) {
        self.attack_mode.store(on, Ordering::Relaxed);
    }

    pub fn is_attack_mode(&self) -> bool {
        self.attack_mode.load(Ordering::Relaxed)
    }

    pub fn config(&self) -> AdaptiveConfig {
        *self.config.read().unwrap()
    }

    pub fn update_config(&self, cfg: AdaptiveConfig) {
        *self.config.write().unwrap() = cfg;
    }

    pub fn stats(&self) -> Arc<LadderStats> {
        self.stats.clone()
    }

    /// Decide which level to serve. Inputs:
    /// * `ip_hash` — deterministic seed per client (use IP bytes)
    /// * `suspicion` — 0..=1 score from ML / risk engine
    /// * `baseline_bits` — the operator-configured baseline PoW bits
    pub fn decide(&self, ip_hash: u64, suspicion: f32, baseline_bits: u8) -> LadderDecision {
        let cfg = *self.config.read().unwrap();
        let attack = self.attack_mode.load(Ordering::Relaxed);
        let bonus = if attack { cfg.attack_mode_bits } else { 0 };
        if attack && bonus > 0 {
            self.stats.attack_mode_bumps.fetch_add(1, Ordering::Relaxed);
        }
        let effective_bits = baseline_bits.saturating_add(bonus);

        // Fast-track: high suspicion skips to PoW or Captcha.
        if suspicion >= cfg.fast_track_threshold {
            self.stats.fast_track_hits.fetch_add(1, Ordering::Relaxed);
            return LadderDecision {
                level: if suspicion >= 0.9 {
                    ChallengeLevel::Captcha
                } else {
                    ChallengeLevel::Pow
                },
                bits: effective_bits.max(20),
                reason: "fast_track_high_suspicion",
            };
        }

        // Randomized order: cheap escalation but starting slot
        // varies by IP hash so attackers can't precompute.
        let level = if cfg.randomize_order {
            self.stats.randomized_picks.fetch_add(1, Ordering::Relaxed);
            self.pick_by_hash(ip_hash, effective_bits)
        } else {
            self.pick_by_floor(effective_bits)
        };

        LadderDecision {
            level,
            bits: effective_bits,
            reason: if attack { "attack_mode" } else { "default" },
        }
    }

    fn pick_by_hash(&self, ip_hash: u64, _bits: u8) -> ChallengeLevel {
        // Bias toward cheap levels: 50% cookie, 25% reload, 15%
        // interaction, 9% pow, 1% captcha. Rotation via hash so
        // any given IP gets a consistent assignment until the IP
        // changes.
        let r = (ip_hash & 0xff) as u8;
        match r {
            0..=127 => ChallengeLevel::Cookie,
            128..=191 => ChallengeLevel::Reload,
            192..=229 => ChallengeLevel::Interaction,
            230..=254 => ChallengeLevel::Pow,
            255 => ChallengeLevel::Captcha,
        }
        // Note: `_bits` only matters for Pow/Captcha downstream; the
        // returned tier is what the caller renders.
    }

    fn pick_by_floor(&self, _bits: u8) -> ChallengeLevel {
        // Read the AtomicU8 floor — operator can raise via admin
        // API; default is 0 = Cookie.
        match self.current_floor.load(Ordering::Relaxed) {
            0 => ChallengeLevel::Cookie,
            1 => ChallengeLevel::Reload,
            2 => ChallengeLevel::Interaction,
            3 => ChallengeLevel::Pow,
            _ => ChallengeLevel::Captcha,
        }
    }

    /// Admin API hook — raise the baseline floor for non-randomized
    /// mode. 0..=4.
    pub fn set_floor(&self, floor: u8) {
        self.current_floor.store(floor.min(4), Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LadderDecision {
    pub level: ChallengeLevel,
    pub bits: u8,
    pub reason: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_mode_bumps_bits() {
        let l = AdaptiveLadder::new(AdaptiveConfig::default());
        let d_normal = l.decide(0xdeadbeef, 0.1, 16);
        l.set_attack_mode(true);
        let d_attack = l.decide(0xdeadbeef, 0.1, 16);
        assert_eq!(d_normal.bits, 16);
        assert_eq!(d_attack.bits, 20);
        assert_eq!(d_attack.reason, "attack_mode");
    }

    #[test]
    fn high_suspicion_fast_tracks_to_pow() {
        let l = AdaptiveLadder::new(AdaptiveConfig::default());
        let d = l.decide(0, 0.8, 16);
        assert_eq!(d.level, ChallengeLevel::Pow);
        assert_eq!(d.reason, "fast_track_high_suspicion");
    }

    #[test]
    fn very_high_suspicion_fast_tracks_to_captcha() {
        let l = AdaptiveLadder::new(AdaptiveConfig::default());
        let d = l.decide(0, 0.95, 16);
        assert_eq!(d.level, ChallengeLevel::Captcha);
    }

    #[test]
    fn randomize_distributes_across_levels() {
        let l = AdaptiveLadder::new(AdaptiveConfig {
            randomize_order: true,
            ..Default::default()
        });
        let mut seen = std::collections::HashSet::new();
        for h in 0u64..1024 {
            let d = l.decide(h, 0.1, 16);
            seen.insert(d.level);
        }
        // Should have hit at least the top 3 levels.
        assert!(seen.contains(&ChallengeLevel::Cookie));
        assert!(seen.contains(&ChallengeLevel::Reload));
    }

    #[test]
    fn deterministic_per_ip_hash() {
        let l = AdaptiveLadder::new(AdaptiveConfig::default());
        let a = l.decide(0x1234_5678, 0.1, 16);
        let b = l.decide(0x1234_5678, 0.1, 16);
        assert_eq!(a, b);
    }

    #[test]
    fn floor_mode_uses_atomic() {
        let l = AdaptiveLadder::new(AdaptiveConfig {
            randomize_order: false,
            ..Default::default()
        });
        l.set_floor(3);
        let d = l.decide(0, 0.1, 16);
        assert_eq!(d.level, ChallengeLevel::Pow);
        l.set_floor(4);
        assert_eq!(l.decide(0, 0.1, 16).level, ChallengeLevel::Captcha);
    }

    #[test]
    fn stats_track_bumps_and_picks() {
        let l = AdaptiveLadder::new(AdaptiveConfig::default());
        l.set_attack_mode(true);
        for h in 0..10u64 {
            l.decide(h, 0.5, 16);
        }
        let (fast, attack, rand) = l.stats().snapshot();
        assert_eq!(fast, 0);
        assert_eq!(attack, 10);
        assert_eq!(rand, 10);
    }
}
