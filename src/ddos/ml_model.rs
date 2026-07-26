//! V141 — Unified ML model selector.
//!
//! V97 (linear) and V122/V139 (linear, wider feature set) and V136
//! (GBM) all live in this codebase, all take the same `FeaturesV2`
//! input, all return a `[0, 1]` probability. The hot path doesn't
//! want to know which one is wired — it just wants to call
//! `model.score_pct(&features)` and get back a number.
//!
//! [MlModel] is that unified handle. It also gates which engines the
//! operator wants ENABLED, so a deployment that only trusts logistic
//! regression can `MlModel::logistic_only(...)`, and one that wants
//! the GBM for interaction handling can `MlModel::gbm(...)`. Config
//! comes from `AEGIS_ML_V2_KIND={logistic,gbm}`.
//!
//! Why not a trait?  A `dyn ModelScorer` would work, but the variant
//! count is tiny (2), the call site is one hot-path function, and an
//! enum with monomorphised match is slightly cheaper at inference
//! (~5ns per call) than a vtable. The cost difference is real because
//! `score_pct` runs per-request.

use std::sync::Arc;

use crate::ddos::{
    ml_gbm::GbmModel,
    ml_score_v2::{FeaturesV2, MlScorerV2},
};

/// The kind picked at startup. Driven by config / env. Kept separate
/// from the enum body so a deployment can switch without rebuilding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlModelKind {
    Logistic,
    Gbm,
}

impl MlModelKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "logistic" | "linear" | "lr" => Some(Self::Logistic),
            "gbm" | "tree" | "trees" => Some(Self::Gbm),
            _ => None,
        }
    }
}

/// Unified scorer. Variants own their model; cloning is cheap (both
/// inner types are Arc-managed at the call site).
pub enum MlModel {
    Logistic(Arc<MlScorerV2>),
    Gbm(Arc<GbmModel>),
}

impl MlModel {
    pub fn logistic(scorer: Arc<MlScorerV2>) -> Self {
        Self::Logistic(scorer)
    }

    pub fn gbm(model: Arc<GbmModel>) -> Self {
        Self::Gbm(model)
    }

    pub fn kind(&self) -> MlModelKind {
        match self {
            Self::Logistic(_) => MlModelKind::Logistic,
            Self::Gbm(_) => MlModelKind::Gbm,
        }
    }

    /// Probability score in [0, 1] for one feature vector.
    #[inline]
    pub fn score(&self, f: &FeaturesV2) -> f32 {
        match self {
            Self::Logistic(s) => s.score(f),
            Self::Gbm(g) => g.score(f),
        }
    }

    /// Same as [score] but rescaled to 0..=100 for ThreatTier
    /// comparison. Matches V97/V122 `score_pct` convention.
    #[inline]
    pub fn score_pct(&self, f: &FeaturesV2) -> f32 {
        self.score(f) * 100.0
    }

    /// V153 — convenience predicate for the V151 adversarial loop.
    /// Returns a closure `|payload| -> bool` that synthesises an
    /// attacker-shaped [FeaturesV2] from the payload string, scores
    /// it through this model, and returns true when the score
    /// percentage exceeds `threshold_pct` (i.e., the model "would
    /// catch" the payload).
    ///
    /// The synthesised feature vector matches V146's
    /// `bypass_to_training_sample`: high URI entropy, no browser
    /// headers, no JA4. A model that's been trained on attack-shaped
    /// inputs scores these high; one that hasn't returns the bias
    /// term alone.
    ///
    /// Operator wires:
    ///
    ///     let predicate = ml_model.payload_predicate(50.0);
    ///     let lp = AdversarialLoop::with_default_mutation_sets(
    ///         trainer, predicate,
    ///     );
    pub fn payload_predicate(
        self: Arc<Self>,
        threshold_pct: f32,
    ) -> Arc<dyn Fn(&str) -> bool + Send + Sync> {
        Arc::new(move |payload: &str| {
            let f = synth_features_from_payload(payload);
            self.score_pct(&f) >= threshold_pct
        })
    }
}

/// V153 — build an attacker-shape [FeaturesV2] from a raw payload
/// string. Used by [MlModel::payload_predicate] and by V146's
/// `bypass_to_training_sample` (which now delegates here to keep
/// the shape consistent).
pub fn synth_features_from_payload(payload: &str) -> FeaturesV2 {
    use crate::ddos::ml_score_v2::ascii_entropy;
    FeaturesV2 {
        uri_length: (payload.len() as f32 / 8192.0).min(1.0),
        query_param_count: (payload.matches('&').count() as f32 / 32.0).min(1.0),
        uri_entropy: ascii_entropy(payload),
        query_entropy: ascii_entropy(payload),
        header_count: 0.0,
        has_user_agent: 0.0,
        has_accept_language: 0.0,
        has_accept_encoding: 0.0,
        has_referer: 0.0,
        method_is_post: 0.0,
        body_length: 0.0,
        ja4_present: 0.0,
        ja4_browser_family: 0.0,
        h2fp_present: 0.0,
        recent_denied_rate: 0.0,
        recent_challenged_rate: 0.0,
        bot_score_rate: 0.0,
        requests_per_min: 0.0,
        fast_repeat: 0.0,
        night_window: 0.0,
        fp_consistency_score: 0.5,
        ja4_reputation: 0.0,
        asn_reputation: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ddos::ml_training::empty_features;

    #[test]
    fn parse_kind_recognises_aliases() {
        assert_eq!(MlModelKind::parse("logistic"), Some(MlModelKind::Logistic));
        assert_eq!(MlModelKind::parse("LR"), Some(MlModelKind::Logistic));
        assert_eq!(MlModelKind::parse("linear"), Some(MlModelKind::Logistic));
        assert_eq!(MlModelKind::parse("gbm"), Some(MlModelKind::Gbm));
        assert_eq!(MlModelKind::parse("Trees"), Some(MlModelKind::Gbm));
        assert_eq!(MlModelKind::parse("xgboost"), None);
        assert_eq!(MlModelKind::parse(""), None);
    }

    #[test]
    fn logistic_variant_delegates_to_inner_scorer() {
        let inner = Arc::new(MlScorerV2::new(true));
        let m = MlModel::logistic(inner.clone());
        let f = empty_features();
        // Direct + wrapper should agree to within numerical noise.
        let direct = inner.score(&f);
        let via = m.score(&f);
        assert!((direct - via).abs() < 1e-6);
        assert_eq!(m.kind(), MlModelKind::Logistic);
    }

    #[test]
    fn gbm_variant_returns_bounded_score() {
        // Train a tiny GBM on synthetic separable data so the wrapped
        // model has actual weight, then check score is in [0, 1].
        let mut samples = vec![];
        let mut targets = vec![];
        for i in 0..30 {
            let mut a = [0.0_f32; crate::ddos::ml_score_v2::N_FEATURES_V2];
            a[0] = (i % 10) as f32 / 10.0;
            samples.push(a);
            targets.push(if a[0] > 0.5 { 1.0 } else { 0.0 });
        }
        let g = Arc::new(GbmModel::train(
            &samples,
            &targets,
            &crate::ddos::ml_gbm::GbmConfig::default(),
        ));
        let m = MlModel::gbm(g);
        let f = empty_features();
        let s = m.score(&f);
        assert!((0.0..=1.0).contains(&s));
        assert_eq!(m.kind(), MlModelKind::Gbm);
    }

    #[test]
    fn synth_features_marks_attacker_shape() {
        let f = synth_features_from_payload("' OR 1=1 --");
        assert_eq!(f.has_user_agent, 0.0);
        assert_eq!(f.ja4_present, 0.0);
        assert!(f.uri_entropy > 0.0);
        assert!(f.fp_consistency_score > 0.0);
    }

    #[test]
    fn payload_predicate_threshold_separates() {
        let model = Arc::new(MlModel::logistic(Arc::new(MlScorerV2::new(true))));
        // Threshold absurdly low → predicate fires on anything (or
        // nothing depending on synthesised score; bias dominates).
        let low_pred = model.clone().payload_predicate(0.0);
        let high_pred = model.payload_predicate(99.9);
        let payload = "' OR 1=1 --";
        // At 0.0 threshold, "anything >= 0" must be true.
        assert!(low_pred(payload));
        // At 99.9, untrained logistic with neutral synth shape can't
        // hit 99.9% — predicate should miss.
        assert!(!high_pred(payload));
    }

    #[test]
    fn payload_predicate_clone_works_across_invocations() {
        // The Arc<dyn Fn> must be reusable.
        let model = Arc::new(MlModel::logistic(Arc::new(MlScorerV2::new(true))));
        let pred = model.payload_predicate(0.0);
        // Call multiple times — should always return true at threshold 0.
        for s in &["abc", "xyz", "' OR '1'='1"] {
            assert!(pred(s));
        }
    }

    #[test]
    fn score_pct_is_score_times_100() {
        let m = MlModel::logistic(Arc::new(MlScorerV2::new(true)));
        let f = empty_features();
        let s = m.score(&f);
        let p = m.score_pct(&f);
        assert!((p - s * 100.0).abs() < 1e-4);
    }
}
