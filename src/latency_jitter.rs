//! V190 — LLMHoney-style response-latency jitter shaping.
//!
//! Attacker fingerprinting of LLM-backed honeypots and tarpits often
//! starts with response-time uniformity: real network responses
//! exhibit log-normal-ish jitter, while a naive tarpit `sleep(N)`
//! produces sub-ms uniformity that's trivially detectable. arXiv
//! 2509.01463 (LLMHoney) demonstrates that adding shape-correct
//! jitter to tarpit/honeypot responses defeats this class of
//! detection.
//!
//! This module produces a per-response delay drawn from one of three
//! distributions:
//!
//! * `LogNormal { median_ms, sigma }` — best general fit for network
//!   round trips. Default for tarpit/honeypot.
//! * `BimodalCdn { fast_ms, slow_ms, slow_prob }` — mimics CDN
//!   cache-hit vs miss bimodality (Fastly/Cloudflare). Default for
//!   decoy responses paired with V188 headers.
//! * `Fixed(ms)` — explicit operator override (rarely useful, kept
//!   for compatibility with old V147 paths).
//!
//! Output is a [Duration]; caller is responsible for actually
//! sleeping (we don't bind to a runtime here).

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub enum Distribution {
    LogNormal {
        median_ms: u32,
        sigma: f32,
    },
    BimodalCdn {
        fast_ms: u32,
        slow_ms: u32,
        slow_prob: f32,
    },
    Fixed(u32),
}

impl Distribution {
    pub fn default_tarpit() -> Self {
        Self::LogNormal {
            median_ms: 350,
            sigma: 0.55,
        }
    }
    pub fn default_decoy() -> Self {
        Self::BimodalCdn {
            fast_ms: 18,
            slow_ms: 220,
            slow_prob: 0.15,
        }
    }
}

/// PRNG entropy source. Caller passes a seed (e.g., conn_id ⊕
/// request counter) so latencies stay coherent within a session but
/// vary across requests.
pub fn sample(dist: Distribution, seed: u64) -> Duration {
    match dist {
        Distribution::Fixed(ms) => Duration::from_millis(ms as u64),
        Distribution::LogNormal { median_ms, sigma } => {
            let z = standard_normal(seed);
            let mu = (median_ms as f32).ln();
            let v = (mu + sigma * z).exp();
            Duration::from_millis(v.round().max(0.0) as u64)
        }
        Distribution::BimodalCdn {
            fast_ms,
            slow_ms,
            slow_prob,
        } => {
            let u = uniform01(seed);
            let ms = if u < slow_prob { slow_ms } else { fast_ms };
            // Add small uniform jitter so the two modes aren't pixel-
            // sharp (real CDN-served responses still wobble ±5%).
            let jitter_seed = mix(seed.wrapping_add(0xA5A5_5A5A));
            let jitter = (uniform01(jitter_seed) - 0.5) * 0.10 * (ms as f32);
            Duration::from_millis((ms as f32 + jitter).round().max(0.0) as u64)
        }
    }
}

/// Splitmix64 step. Cheap and reproducible.
fn mix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn uniform01(seed: u64) -> f32 {
    (mix(seed) >> 32) as f32 / u32::MAX as f32
}

/// Box-Muller standard-normal sample with two uniforms drawn from the
/// same seed via splitmix chains.
fn standard_normal(seed: u64) -> f32 {
    let s1 = mix(seed);
    let s2 = mix(s1);
    let u1 = (s1 as f32 / u64::MAX as f32).max(1e-9);
    let u2 = s2 as f32 / u64::MAX as f32;
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_returns_exact() {
        let d = sample(Distribution::Fixed(123), 0);
        assert_eq!(d, Duration::from_millis(123));
    }

    #[test]
    fn lognormal_centred_near_median() {
        let dist = Distribution::LogNormal {
            median_ms: 350,
            sigma: 0.55,
        };
        let mut tot: u64 = 0;
        let n = 2000u64;
        for i in 0..n {
            tot += sample(dist, i).as_millis() as u64;
        }
        let mean = tot as f64 / n as f64;
        // LogNormal mean = exp(mu + sigma^2/2). For median=350, sigma=0.55:
        //   mean = 350 * exp(0.55^2/2) ≈ 407 ms.
        assert!((360.0..=460.0).contains(&mean), "got mean={mean}");
    }

    #[test]
    fn bimodal_respects_probability() {
        let dist = Distribution::BimodalCdn {
            fast_ms: 20,
            slow_ms: 200,
            slow_prob: 0.2,
        };
        let mut slow = 0;
        let n = 5000u64;
        for i in 0..n {
            let d = sample(dist, i).as_millis() as u32;
            if d > 100 {
                slow += 1;
            }
        }
        let p = slow as f32 / n as f32;
        assert!((0.16..=0.24).contains(&p), "got p={p}");
    }

    #[test]
    fn sample_deterministic_per_seed() {
        let dist = Distribution::LogNormal {
            median_ms: 200,
            sigma: 0.4,
        };
        let a = sample(dist, 42);
        let b = sample(dist, 42);
        let c = sample(dist, 43);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn defaults_yield_sensible_ranges() {
        let tar = sample(Distribution::default_tarpit(), 1);
        assert!(tar.as_millis() >= 30 && tar.as_millis() <= 5_000);
        let dec = sample(Distribution::default_decoy(), 1);
        assert!(dec.as_millis() <= 400);
    }
}
