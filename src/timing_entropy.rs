//! V189 — Timing-entropy ML features (mouse jitter, scroll cadence).
//!
//! Headed-Chrome scrapers (Botasaurus, undetected_chromedriver) defeat
//! many fingerprint-based detectors by running an actual browser.
//! What they typically can't fake well: human input timing.
//!
//! A real user generates noisy mouse-move and scroll events with
//! highly variable inter-arrival times (entropy ~3.5-5.5 bits) and
//! non-Gaussian distributions. Synthetic input ladder usually emits
//! either: (a) perfectly uniform timing, or (b) sampled from a
//! Gaussian RNG that's still much less varied than real humans.
//!
//! The V145 client_consistency JS collector ships data; this module
//! computes the entropy + dispersion stats server-side and exposes
//! them as ML features.
//!
//! Three features:
//!
//! * `move_interval_entropy` — Shannon entropy of inter-arrival
//!   times bucketed to 8 ms bins. Real users > 3.0; synthetics
//!   often < 1.5.
//! * `move_interval_cv` — coefficient of variation (stddev/mean).
//!   Real users > 0.5; uniform timer < 0.1.
//! * `scroll_cadence_mad` — median absolute deviation of scroll
//!   event spacing. Sensitive to wheel-tick simulators that scroll
//!   at fixed Hz.

pub fn shannon_entropy_bucketed(intervals_ms: &[u32], bucket_ms: u32) -> f32 {
    if intervals_ms.is_empty() || bucket_ms == 0 {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<u32, u32>::new();
    for v in intervals_ms {
        *counts.entry(v / bucket_ms).or_insert(0) += 1;
    }
    let total = intervals_ms.len() as f32;
    counts
        .values()
        .map(|&c| {
            let p = c as f32 / total;
            -p * p.log2()
        })
        .sum()
}

pub fn coefficient_of_variation(values: &[u32]) -> f32 {
    if values.len() < 2 {
        return 0.0;
    }
    let n = values.len() as f32;
    let mean: f32 = values.iter().map(|v| *v as f32).sum::<f32>() / n;
    if mean == 0.0 {
        return 0.0;
    }
    let var: f32 = values
        .iter()
        .map(|v| {
            let d = *v as f32 - mean;
            d * d
        })
        .sum::<f32>()
        / (n - 1.0);
    var.sqrt() / mean
}

pub fn median_absolute_deviation(values: &[u32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted: Vec<u32> = values.to_vec();
    sorted.sort_unstable();
    let med = sorted[sorted.len() / 2] as f32;
    let mut abs_dev: Vec<f32> = sorted.iter().map(|v| (*v as f32 - med).abs()).collect();
    abs_dev.sort_by(|a, b| a.partial_cmp(b).unwrap());
    abs_dev[abs_dev.len() / 2]
}

#[derive(Debug, Clone)]
pub struct TimingSample {
    pub mouse_intervals_ms: Vec<u32>,
    pub scroll_intervals_ms: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct TimingFeatures {
    pub move_interval_entropy: f32,
    pub move_interval_cv: f32,
    pub scroll_cadence_mad: f32,
    /// 0.0 = looks human; 1.0 = synthetic shape.
    pub anomaly_score: f32,
}

pub fn extract(sample: &TimingSample) -> TimingFeatures {
    let entropy = shannon_entropy_bucketed(&sample.mouse_intervals_ms, 8);
    let cv = coefficient_of_variation(&sample.mouse_intervals_ms);
    let mad = median_absolute_deviation(&sample.scroll_intervals_ms);

    // Lower entropy → more synthetic.
    let entropy_anom = (1.0 - (entropy / 3.5).clamp(0.0, 1.0)).clamp(0.0, 1.0);
    // Lower CV → more synthetic.
    let cv_anom = (1.0 - (cv / 0.5).clamp(0.0, 1.0)).clamp(0.0, 1.0);
    // Lower MAD → uniform scroll cadence.
    let mad_anom = (1.0 - (mad / 20.0).clamp(0.0, 1.0)).clamp(0.0, 1.0);

    // If we have no scroll data at all (likely; not every session
    // scrolls), don't penalise — drop that axis.
    let denom = 2.0
        + if sample.scroll_intervals_ms.is_empty() {
            0.0
        } else {
            1.0
        };
    let mad_contrib = if sample.scroll_intervals_ms.is_empty() {
        0.0
    } else {
        mad_anom
    };
    let anomaly = (entropy_anom + cv_anom + mad_contrib) / denom;

    TimingFeatures {
        move_interval_entropy: entropy,
        move_interval_cv: cv,
        scroll_cadence_mad: mad,
        anomaly_score: anomaly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_timer_is_low_entropy() {
        let ivals: Vec<u32> = (0..50).map(|_| 16).collect();
        let e = shannon_entropy_bucketed(&ivals, 8);
        assert!(e < 0.5, "expected near-zero, got {e}");
    }

    #[test]
    fn varied_intervals_high_entropy() {
        let ivals: Vec<u32> = (0..50).map(|i| 8 + (i * 7919) as u32 % 200).collect();
        let e = shannon_entropy_bucketed(&ivals, 8);
        assert!(e > 2.5, "expected high entropy, got {e}");
    }

    #[test]
    fn cv_of_constant_is_zero() {
        let ivals: Vec<u32> = vec![16; 20];
        assert_eq!(coefficient_of_variation(&ivals), 0.0);
    }

    #[test]
    fn cv_of_human_intervals_above_threshold() {
        let ivals: Vec<u32> = vec![12, 18, 9, 31, 22, 14, 47, 25, 17, 11, 38];
        let cv = coefficient_of_variation(&ivals);
        assert!(cv > 0.4, "got cv={cv}");
    }

    #[test]
    fn synthetic_sample_flags_high_anomaly() {
        let s = TimingSample {
            mouse_intervals_ms: vec![16; 40],
            scroll_intervals_ms: vec![100; 20],
        };
        let f = extract(&s);
        assert!(f.anomaly_score > 0.85, "got {}", f.anomaly_score);
    }

    #[test]
    fn human_sample_flags_low_anomaly() {
        let s = TimingSample {
            mouse_intervals_ms: (0..80).map(|i| 8 + (i * 7919) as u32 % 200).collect(),
            scroll_intervals_ms: (0..15).map(|i| 80 + (i * 137) as u32 % 220).collect(),
        };
        let f = extract(&s);
        assert!(f.anomaly_score < 0.5, "got {}", f.anomaly_score);
    }
}
