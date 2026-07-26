//! V135 — ML evaluation metrics.
//!
//! V123 retrain returned only mean-squared loss before/after. That's
//! a noisy signal: loss can fall while accuracy on the malicious
//! class stays at zero (the model just learns to predict the majority
//! class). This module computes the metrics that actually answer
//! "is the model getting better?":
//!
//! * **Confusion matrix** — TP/FP/TN/FN at a chosen threshold.
//! * **Accuracy** — overall correct fraction.
//! * **Precision / Recall / F1** — per-class, for imbalanced traffic
//!   where 99% of samples are benign.
//! * **ROC AUC** — threshold-independent quality measure (1.0 perfect,
//!   0.5 random). Computed by Mann-Whitney U formula in O(n log n).
//! * **Calibration ECE** — Expected Calibration Error, bucketed:
//!   "when the model says 0.8, is it actually right 80% of the time?".
//!
//! All metrics work on `(predicted_score: f32, target: f32)` pairs so
//! they're decoupled from the specific model — same code evaluates
//! the logistic-regression V97/V122 and the GBM V136 below it.

/// One sample's (score, target) for evaluation. `target` is 0.0
/// (benign) or 1.0 (malicious); `score` is the model's raw sigmoid
/// output in [0, 1].
#[derive(Debug, Clone, Copy)]
pub struct EvalPair {
    pub score: f32,
    pub target: f32,
}

/// Confusion matrix entries at a fixed decision threshold (default 0.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfusionMatrix {
    pub tp: u32,
    pub fp: u32,
    pub tn: u32,
    pub fn_: u32,
}

impl ConfusionMatrix {
    pub fn total(&self) -> u32 {
        self.tp + self.fp + self.tn + self.fn_
    }
    pub fn accuracy(&self) -> f32 {
        let t = self.total();
        if t == 0 {
            return 0.0;
        }
        (self.tp + self.tn) as f32 / t as f32
    }
    pub fn precision(&self) -> f32 {
        let den = self.tp + self.fp;
        if den == 0 {
            return 0.0;
        }
        self.tp as f32 / den as f32
    }
    pub fn recall(&self) -> f32 {
        let den = self.tp + self.fn_;
        if den == 0 {
            return 0.0;
        }
        self.tp as f32 / den as f32
    }
    pub fn f1(&self) -> f32 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
    /// False-positive rate — how often we wrongly flag a benign
    /// request as malicious. Operators with low-FP budgets watch this
    /// closely; the model is useless if it cries wolf every other
    /// request.
    pub fn fpr(&self) -> f32 {
        let den = self.fp + self.tn;
        if den == 0 {
            return 0.0;
        }
        self.fp as f32 / den as f32
    }
}

/// Build the confusion matrix at `threshold` (commonly 0.5).
pub fn confusion(pairs: &[EvalPair], threshold: f32) -> ConfusionMatrix {
    let mut cm = ConfusionMatrix::default();
    for p in pairs {
        let pred_pos = p.score >= threshold;
        let true_pos = p.target >= 0.5;
        match (pred_pos, true_pos) {
            (true, true) => cm.tp += 1,
            (true, false) => cm.fp += 1,
            (false, true) => cm.fn_ += 1,
            (false, false) => cm.tn += 1,
        }
    }
    cm
}

/// Compute ROC AUC via the Mann-Whitney U / rank-sum identity. O(n log n)
/// for the sort, then O(n) to walk and accumulate ranks. Robust to
/// tied scores via mid-rank.
pub fn roc_auc(pairs: &[EvalPair]) -> f32 {
    let n_pos = pairs.iter().filter(|p| p.target >= 0.5).count();
    let n_neg = pairs.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        // Undefined — only one class present. Convention: 0.5 (random).
        return 0.5;
    }
    // Sort by score asc.
    let mut sorted: Vec<EvalPair> = pairs.to_vec();
    sorted.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Assign mid-ranks for ties.
    let mut sum_pos_ranks = 0.0_f64;
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i;
        while j < sorted.len() && (sorted[j].score - sorted[i].score).abs() < f32::EPSILON {
            j += 1;
        }
        // Ranks for this tied block are (i+1)..=j, mid-rank = (i+1+j)/2.
        let mid_rank = (i as f64 + 1.0 + j as f64) / 2.0;
        for k in i..j {
            if sorted[k].target >= 0.5 {
                sum_pos_ranks += mid_rank;
            }
        }
        i = j;
    }
    let u = sum_pos_ranks - (n_pos as f64 * (n_pos as f64 + 1.0)) / 2.0;
    (u / (n_pos as f64 * n_neg as f64)) as f32
}

/// Expected Calibration Error with `bins` equal-width buckets in
/// [0, 1]. Lower is better — a well-calibrated model has ECE close
/// to zero, meaning when it says "0.7" it's right 70% of the time.
pub fn ece(pairs: &[EvalPair], bins: usize) -> f32 {
    if pairs.is_empty() || bins == 0 {
        return 0.0;
    }
    let mut bucket_sum = vec![0.0_f32; bins];
    let mut bucket_count = vec![0u32; bins];
    let mut bucket_pos = vec![0u32; bins];
    for p in pairs {
        let idx = ((p.score * bins as f32) as usize).min(bins - 1);
        bucket_sum[idx] += p.score;
        bucket_count[idx] += 1;
        if p.target >= 0.5 {
            bucket_pos[idx] += 1;
        }
    }
    let n = pairs.len() as f32;
    let mut ece = 0.0_f32;
    for i in 0..bins {
        let c = bucket_count[i];
        if c == 0 {
            continue;
        }
        let avg_score = bucket_sum[i] / c as f32;
        let actual_pos = bucket_pos[i] as f32 / c as f32;
        ece += (c as f32 / n) * (avg_score - actual_pos).abs();
    }
    ece
}

/// Full summary — what the retrain endpoint returns.
#[derive(Debug, Clone)]
pub struct EvalSummary {
    pub samples: u32,
    pub positives: u32,
    pub negatives: u32,
    pub confusion: ConfusionMatrix,
    pub accuracy: f32,
    pub precision: f32,
    pub recall: f32,
    pub f1: f32,
    pub fpr: f32,
    pub auc: f32,
    pub ece: f32,
    pub mean_squared_error: f32,
}

pub fn summarize(pairs: &[EvalPair], threshold: f32) -> EvalSummary {
    let positives = pairs.iter().filter(|p| p.target >= 0.5).count() as u32;
    let negatives = pairs.len() as u32 - positives;
    let cm = confusion(pairs, threshold);
    let mse = if pairs.is_empty() {
        0.0
    } else {
        pairs
            .iter()
            .map(|p| (p.target - p.score).powi(2))
            .sum::<f32>()
            / pairs.len() as f32
    };
    EvalSummary {
        samples: pairs.len() as u32,
        positives,
        negatives,
        accuracy: cm.accuracy(),
        precision: cm.precision(),
        recall: cm.recall(),
        f1: cm.f1(),
        fpr: cm.fpr(),
        confusion: cm,
        auc: roc_auc(pairs),
        ece: ece(pairs, 10),
        mean_squared_error: mse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(score: f32, target: f32) -> EvalPair {
        EvalPair { score, target }
    }

    #[test]
    fn confusion_counts_quadrants() {
        let pairs = vec![
            ep(0.9, 1.0), // TP
            ep(0.8, 1.0), // TP
            ep(0.1, 0.0), // TN
            ep(0.7, 0.0), // FP
            ep(0.2, 1.0), // FN
        ];
        let cm = confusion(&pairs, 0.5);
        assert_eq!(cm.tp, 2);
        assert_eq!(cm.fp, 1);
        assert_eq!(cm.tn, 1);
        assert_eq!(cm.fn_, 1);
        assert!((cm.accuracy() - 0.6).abs() < 1e-6);
        assert!((cm.precision() - 2.0 / 3.0).abs() < 1e-6);
        assert!((cm.recall() - 2.0 / 3.0).abs() < 1e-6);
        assert!((cm.f1() - 2.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn confusion_handles_zero_denominators() {
        let cm = ConfusionMatrix::default();
        assert_eq!(cm.accuracy(), 0.0);
        assert_eq!(cm.precision(), 0.0);
        assert_eq!(cm.recall(), 0.0);
        assert_eq!(cm.f1(), 0.0);
        assert_eq!(cm.fpr(), 0.0);
    }

    #[test]
    fn auc_perfect_ranking() {
        let pairs = vec![ep(0.1, 0.0), ep(0.2, 0.0), ep(0.8, 1.0), ep(0.9, 1.0)];
        let a = roc_auc(&pairs);
        assert!((a - 1.0).abs() < 1e-6, "perfect ranking → 1.0, got {a}");
    }

    #[test]
    fn auc_inverted_ranking_is_zero() {
        let pairs = vec![ep(0.9, 0.0), ep(0.8, 0.0), ep(0.2, 1.0), ep(0.1, 1.0)];
        let a = roc_auc(&pairs);
        assert!(a < 0.01, "inverted ranking → 0.0, got {a}");
    }

    #[test]
    fn auc_random_ranking_is_half() {
        let pairs = vec![ep(0.5, 0.0), ep(0.5, 1.0), ep(0.5, 0.0), ep(0.5, 1.0)];
        let a = roc_auc(&pairs);
        assert!((a - 0.5).abs() < 0.01, "tied scores → 0.5, got {a}");
    }

    #[test]
    fn auc_returns_0_5_when_single_class() {
        let pairs = vec![ep(0.7, 1.0), ep(0.3, 1.0)];
        assert!((roc_auc(&pairs) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn ece_well_calibrated_low() {
        // Build pairs where score == empirical pos rate within each bucket.
        let mut pairs = vec![];
        // 10 samples at score=0.1, 1 positive (10%).
        for i in 0..10 {
            pairs.push(ep(0.1, if i == 0 { 1.0 } else { 0.0 }));
        }
        // 10 samples at score=0.9, 9 positives (90%).
        for i in 0..10 {
            pairs.push(ep(0.9, if i == 0 { 0.0 } else { 1.0 }));
        }
        let e = ece(&pairs, 10);
        assert!(e < 0.05, "well-calibrated → ECE near 0, got {e}");
    }

    #[test]
    fn ece_overconfident_high() {
        // All scored 0.95 but only 50% positive → bad calibration.
        let mut pairs = vec![];
        for i in 0..20 {
            pairs.push(ep(0.95, if i % 2 == 0 { 1.0 } else { 0.0 }));
        }
        let e = ece(&pairs, 10);
        assert!(e > 0.4, "overconfident → ECE high, got {e}");
    }

    #[test]
    fn summarize_includes_all_metrics() {
        let pairs = vec![ep(0.9, 1.0), ep(0.1, 0.0), ep(0.8, 1.0), ep(0.2, 0.0)];
        let s = summarize(&pairs, 0.5);
        assert_eq!(s.samples, 4);
        assert_eq!(s.positives, 2);
        assert_eq!(s.negatives, 2);
        assert!((s.accuracy - 1.0).abs() < 1e-6);
        assert!((s.auc - 1.0).abs() < 1e-6);
    }
}
