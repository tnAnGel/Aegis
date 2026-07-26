//! V122 — ML v2: expanded feature set + improved baseline.
//!
//! V97 shipped logistic regression over 8 features and proved the
//! pipeline. V122 widens the feature set to 20 covering signals the
//! enterprise bot-management products (Cloudflare Bot Management,
//! Akamai Bot Manager, PerimeterX) read.
//!
//! Honest framing — info.md's "top 0, beat all enterprise" target is
//! aspirational; the enterprise vendors train on billions of samples
//! we don't have. What V122 CAN match:
//!
//! * **Feature coverage** — fingerprint signal richness, header-shape
//!   anomalies, URI entropy, request-rate patterns.
//! * **Online retraining** — V123 ships the operator-driven feedback
//!   loop so the model adapts to the deployment's specific traffic
//!   (which the giant generic models can't do without operator
//!   labelling).
//! * **Explainability** — every score breaks down into per-feature
//!   contributions so the operator sees WHY a request scored 80
//!   instead of "trust me, the LSTM says so".
//!
//! Coexists with V97 MlScorer — V97 is the simpler 8-feature model.
//! Operators can pick: V97 for low-cardinality / small-deployment
//! configurations where the simpler model is enough; V122 for
//! rich-signal deployments where the extra features pay back.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Number of features V122 emits. Bump (with a matching weight-vector
/// width) when adding new features — the persistence format embeds
/// the count so a stale weights file with N≠CURRENT loads as
/// "incompatible, fall back to defaults".
///
/// V139 bumped from 20 → 23: added fp_consistency_score (V137),
/// ja4_reputation (V138), and asn_reputation (operator-supplied).
pub const N_FEATURES_V2: usize = 23;

/// Compact per-request feature vector. All values pre-normalised
/// into [0, 1] (or [-1, 1] for signed signals) so weight magnitudes
/// stay sane during retraining.
///
/// Stable indices — the V123 retraining endpoint and saved-model
/// files refer to these by position. Append-only, never reorder.
#[derive(Debug, Clone, Copy)]
pub struct FeaturesV2 {
    // ── request shape (4) ────────────────────────────────────────
    pub uri_length: f32,        // 0
    pub query_param_count: f32, // 1
    pub uri_entropy: f32,       // 2
    pub query_entropy: f32,     // 3
    // ── header shape (5) ─────────────────────────────────────────
    pub header_count: f32,        // 4
    pub has_user_agent: f32,      // 5
    pub has_accept_language: f32, // 6
    pub has_accept_encoding: f32, // 7
    pub has_referer: f32,         // 8
    // ── method + body (2) ────────────────────────────────────────
    pub method_is_post: f32, // 9
    pub body_length: f32,    // 10
    // ── fingerprint (3) ──────────────────────────────────────────
    pub ja4_present: f32,        // 11 (1=present, 0=missing)
    pub ja4_browser_family: f32, // 12 (1=browser-like, 0=other)
    pub h2fp_present: f32,       // 13
    // ── reputation (3) ───────────────────────────────────────────
    pub recent_denied_rate: f32,     // 14
    pub recent_challenged_rate: f32, // 15
    pub bot_score_rate: f32,         // 16
    // ── temporal (3) ─────────────────────────────────────────────
    pub requests_per_min: f32, // 17 (normalised to /100)
    pub fast_repeat: f32,      // 18 (same IP repeats within 1s, 1=yes)
    pub night_window: f32,     // 19 (UTC hour ∈ [0, 6), 1=yes)
    // ── V139: cross-signal & reputation (3) ──────────────────────
    /// V137 — cross-fingerprint correlation score in [0, 1].
    /// 0 = JA4 / JA4H / H2FP / UA all agree (real browser),
    /// 1 = stacked mismatches (e.g. Chrome JA4 + curl UA + no Accept-
    /// Language). Sourced from `fp_correlation::correlate()`.
    pub fp_consistency_score: f32, // 20
    /// V138 — JA4 reputation feature in [0, 1]. 1.0 = full JA4 match
    /// against the operator's CTI feed; 0.6 = cipher-prefix match only;
    /// 0.0 = no entry. Sourced from `ja4_reputation::reputation_feature()`.
    pub ja4_reputation: f32, // 21
    /// V139 — operator-supplied ASN reputation in [0, 1]. Hosting /
    /// proxy / Tor-exit / commonly-abused ASNs get a non-zero score.
    /// Aegis core doesn't ship a default ASN list (operators have
    /// strong opinions); slot is here so the model can consume one
    /// when the operator wires it.
    pub asn_reputation: f32, // 22
}

impl FeaturesV2 {
    pub fn as_array(&self) -> [f32; N_FEATURES_V2] {
        [
            self.uri_length,
            self.query_param_count,
            self.uri_entropy,
            self.query_entropy,
            self.header_count,
            self.has_user_agent,
            self.has_accept_language,
            self.has_accept_encoding,
            self.has_referer,
            self.method_is_post,
            self.body_length,
            self.ja4_present,
            self.ja4_browser_family,
            self.h2fp_present,
            self.recent_denied_rate,
            self.recent_challenged_rate,
            self.bot_score_rate,
            self.requests_per_min,
            self.fast_repeat,
            self.night_window,
            self.fp_consistency_score,
            self.ja4_reputation,
            self.asn_reputation,
        ]
    }
}

/// V2 weights — 20-dim vector + bias.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightsV2 {
    pub w: [f32; N_FEATURES_V2],
    pub bias: f32,
    /// Schema version. Used to gate loading: incompatible files fall
    /// back to defaults instead of corrupting the model.
    #[serde(default = "default_schema")]
    pub schema_version: u32,
}

fn default_schema() -> u32 {
    3
}

impl Default for WeightsV2 {
    /// Conservative defaults tuned to flag obvious anomaly stacks
    /// while not penalising real browsers. Operator retrains via V123
    /// once they have ≥1000 labelled samples.
    fn default() -> Self {
        let mut w = [0.0_f32; N_FEATURES_V2];
        // Request shape — long URIs + high entropy = mildly suspicious.
        w[0] = 0.6; // uri_length
        w[1] = 0.3; // query_param_count
        w[2] = 1.2; // uri_entropy   (good signal — random paths)
        w[3] = 0.8; // query_entropy
        // Header shape — missing common browser headers is bot-shaped.
        w[4] = 0.2; // header_count (mild)
        w[5] = -1.5; // has_user_agent (negative: present is GOOD)
        w[6] = -1.0; // has_accept_language
        w[7] = -0.8; // has_accept_encoding
        w[8] = -0.6; // has_referer
        // Method + body.
        w[9] = 0.1; // method_is_post
        w[10] = 0.3; // body_length
        // Fingerprint — JA4 present + browser-family = trusted client.
        w[11] = -1.0; // ja4_present (negative)
        w[12] = -1.2; // ja4_browser_family (negative)
        w[13] = -0.7; // h2fp_present
        // Reputation — explicit prior bad behaviour.
        w[14] = 3.0; // recent_denied_rate (strong)
        w[15] = 1.5; // recent_challenged_rate
        w[16] = 2.0; // bot_score_rate
        // Temporal — high rate + fast-repeat + night-window combine
        // for "scripted, not human".
        w[17] = 1.0; // requests_per_min
        w[18] = 1.5; // fast_repeat
        w[19] = 0.4; // night_window
        // V139 — cross-signal features. fp_consistency and ja4_rep
        // are strong direct signals; asn_reputation starts at 0
        // because the slot is opt-in (operator wires the feed).
        w[20] = 1.5; // fp_consistency_score
        w[21] = 2.0; // ja4_reputation
        w[22] = 0.0; // asn_reputation (operator-opt-in; default neutral)
        Self {
            w,
            bias: -2.5,
            schema_version: 3,
        }
    }
}

/// Per-feature score breakdown for explainability. The admin UI
/// renders this as a stacked bar showing which features pushed the
/// score up/down — operators no longer have to trust "the model says
/// 80".
#[derive(Debug, Clone)]
pub struct ScoreBreakdown {
    pub feature_contributions: [(String, f32); N_FEATURES_V2],
    pub bias: f32,
    pub raw_z: f32,
    pub sigmoid: f32,
    pub score_pct: f32,
}

pub struct MlScorerV2 {
    enabled: bool,
    weights: ArcSwap<WeightsV2>,
}

impl MlScorerV2 {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            weights: ArcSwap::from_pointee(WeightsV2::default()),
        }
    }

    /// Replace weights atomically. Caller is V123 retraining
    /// endpoint or the disk-reload background task.
    pub fn store_weights(&self, w: WeightsV2) {
        self.weights.store(Arc::new(w));
    }

    pub fn snapshot_weights(&self) -> WeightsV2 {
        (**self.weights.load()).clone()
    }

    /// Fast-path inference. <200 ns: 20 f32 muls + 19 adds + sigmoid.
    #[inline]
    pub fn score(&self, f: &FeaturesV2) -> f32 {
        if !self.enabled {
            return 0.0;
        }
        let w = self.weights.load();
        let xs = f.as_array();
        let mut z = w.bias;
        for i in 0..N_FEATURES_V2 {
            z += w.w[i] * xs[i];
        }
        sigmoid(z)
    }

    /// Score scaled to 0..=100 for ThreatTier comparison.
    #[inline]
    pub fn score_pct(&self, f: &FeaturesV2) -> f32 {
        self.score(f) * 100.0
    }

    /// Score + per-feature breakdown for /admin/api/ml_explain.
    /// Operator sees "this request scored 73 because: ja4_present=
    /// -1.0×0=0, recent_denied_rate=3.0×0.8=2.4, ...".
    pub fn explain(&self, f: &FeaturesV2) -> ScoreBreakdown {
        let w = self.weights.load();
        let xs = f.as_array();
        let names: [&'static str; N_FEATURES_V2] = [
            "uri_length",
            "query_param_count",
            "uri_entropy",
            "query_entropy",
            "header_count",
            "has_user_agent",
            "has_accept_language",
            "has_accept_encoding",
            "has_referer",
            "method_is_post",
            "body_length",
            "ja4_present",
            "ja4_browser_family",
            "h2fp_present",
            "recent_denied_rate",
            "recent_challenged_rate",
            "bot_score_rate",
            "requests_per_min",
            "fast_repeat",
            "night_window",
            "fp_consistency_score",
            "ja4_reputation",
            "asn_reputation",
        ];
        let mut z = w.bias;
        // Use uninit-style array via map().
        let contribs: [(String, f32); N_FEATURES_V2] = std::array::from_fn(|i| {
            let c = w.w[i] * xs[i];
            z += c;
            (names[i].to_string(), c)
        });
        let sig = sigmoid(z);
        ScoreBreakdown {
            feature_contributions: contribs,
            bias: w.bias,
            raw_z: z,
            sigmoid: sig,
            score_pct: sig * 100.0,
        }
    }

    /// Online SGD update. `target` is 0 (benign) or 1 (malicious);
    /// `lr` is learning rate. Returns residual (target - prediction).
    pub fn train_step(&self, f: &FeaturesV2, target: f32, lr: f32) -> f32 {
        self.train_step_ex(f, target, lr, 0.0, 1.0)
    }

    /// V135 — SGD update with L2 weight decay and per-sample weight.
    ///
    /// * `l2_lambda` — coefficient for the L2 penalty (typical 1e-4
    ///   to 1e-2). Shrinks each weight toward zero proportionally on
    ///   every step so a single noisy batch can't blow weights up.
    ///   Bias is NOT decayed (regularising the intercept biases the
    ///   model toward the equiprobable prior, which we don't want).
    /// * `sample_weight` — multiplies the gradient. Use for class
    ///   weighting: in imbalanced traffic (99% benign), set
    ///   `sample_weight = neg_count/pos_count` on malicious samples
    ///   so the rare class contributes equally to the loss.
    pub fn train_step_ex(
        &self,
        f: &FeaturesV2,
        target: f32,
        lr: f32,
        l2_lambda: f32,
        sample_weight: f32,
    ) -> f32 {
        let cur = self.weights.load_full();
        let pred = self.score(f);
        let err = target - pred;
        let effective_grad = lr * err * sample_weight;
        let xs = f.as_array();
        let mut new_w = cur.w;
        for i in 0..N_FEATURES_V2 {
            // gradient + L2 decay: w_i ← (1 - lr·λ)·w_i + lr·err·x_i
            new_w[i] = (1.0 - lr * l2_lambda) * new_w[i] + effective_grad * xs[i];
        }
        let new_bias = cur.bias + effective_grad;
        self.weights.store(Arc::new(WeightsV2 {
            w: new_w,
            bias: new_bias,
            schema_version: 3,
        }));
        err
    }
}

/// Shannon entropy of an ASCII string, normalised into [0, 1].
/// Useful as a feature: legitimate paths have low entropy
/// (`/users/profile`), randomly-generated scanning paths have high
/// entropy (`/aXz4qPj8`).
pub fn ascii_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 128];
    let mut total = 0u32;
    for b in s.bytes() {
        if b < 128 {
            counts[b as usize] += 1;
            total += 1;
        }
    }
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f32;
    let mut h = 0.0_f32;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = (*c as f32) / total_f;
        h -= p * p.log2();
    }
    // Max entropy for 128-symbol alphabet is log2(128) = 7. Normalise.
    (h / 7.0).clamp(0.0, 1.0)
}

#[inline]
fn sigmoid(z: f32) -> f32 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_browser_features() -> FeaturesV2 {
        FeaturesV2 {
            uri_length: 0.05,
            query_param_count: 0.0,
            uri_entropy: 0.4, // typical path
            query_entropy: 0.0,
            header_count: 0.3,
            has_user_agent: 1.0,
            has_accept_language: 1.0,
            has_accept_encoding: 1.0,
            has_referer: 1.0,
            method_is_post: 0.0,
            body_length: 0.0,
            ja4_present: 1.0,
            ja4_browser_family: 1.0,
            h2fp_present: 1.0,
            recent_denied_rate: 0.0,
            recent_challenged_rate: 0.0,
            bot_score_rate: 0.0,
            requests_per_min: 0.02,
            fast_repeat: 0.0,
            night_window: 0.0,
            fp_consistency_score: 0.0,
            ja4_reputation: 0.0,
            asn_reputation: 0.0,
        }
    }

    fn hostile_scanner_features() -> FeaturesV2 {
        FeaturesV2 {
            uri_length: 0.9,
            query_param_count: 0.8,
            uri_entropy: 0.95,
            query_entropy: 0.9,
            header_count: 0.1,
            has_user_agent: 0.0,
            has_accept_language: 0.0,
            has_accept_encoding: 0.0,
            has_referer: 0.0,
            method_is_post: 1.0,
            body_length: 0.5,
            ja4_present: 0.0,
            ja4_browser_family: 0.0,
            h2fp_present: 0.0,
            recent_denied_rate: 0.9,
            recent_challenged_rate: 0.6,
            bot_score_rate: 0.8,
            requests_per_min: 0.8,
            fast_repeat: 1.0,
            night_window: 1.0,
            fp_consistency_score: 0.9,
            ja4_reputation: 1.0,
            asn_reputation: 0.5,
        }
    }

    #[test]
    fn defaults_score_clean_browser_low() {
        let s = MlScorerV2::new(true);
        let p = s.score_pct(&clean_browser_features());
        assert!(p < 25.0, "clean browser should score <25, got {p}");
    }

    #[test]
    fn defaults_score_hostile_scanner_high() {
        let s = MlScorerV2::new(true);
        let p = s.score_pct(&hostile_scanner_features());
        assert!(p > 80.0, "hostile scanner should score >80, got {p}");
    }

    #[test]
    fn explain_breakdown_sums_to_raw_z() {
        let s = MlScorerV2::new(true);
        let b = s.explain(&hostile_scanner_features());
        let sum: f32 = b.feature_contributions.iter().map(|(_, c)| c).sum::<f32>() + b.bias;
        assert!((sum - b.raw_z).abs() < 0.001, "explanation must sum to z");
        assert!((b.sigmoid * 100.0 - b.score_pct).abs() < 0.001);
    }

    #[test]
    fn train_step_pushes_prediction_toward_target() {
        let s = MlScorerV2::new(true);
        let f = clean_browser_features();
        let p0 = s.score(&f);
        // Force-train as malicious 50 times.
        for _ in 0..50 {
            s.train_step(&f, 1.0, 0.3);
        }
        let p1 = s.score(&f);
        assert!(p1 > p0, "training toward 1 should raise prediction");
    }

    #[test]
    fn disabled_scorer_returns_zero() {
        let s = MlScorerV2::new(false);
        assert_eq!(s.score_pct(&hostile_scanner_features()), 0.0);
    }

    #[test]
    fn weights_roundtrip_via_store_snapshot() {
        let s = MlScorerV2::new(true);
        let mut w = s.snapshot_weights();
        w.bias = 99.0;
        s.store_weights(w);
        let w2 = s.snapshot_weights();
        assert_eq!(w2.bias, 99.0);
    }

    #[test]
    fn ascii_entropy_low_for_repeating() {
        let h = ascii_entropy("aaaaaa");
        assert!(h < 0.1, "all-same → near-zero entropy, got {h}");
    }

    #[test]
    fn ascii_entropy_high_for_random_ish() {
        let h = ascii_entropy("aXz4qPj8K7nMz2");
        assert!(h > 0.3, "random-ish → entropy > 0.3, got {h}");
    }

    #[test]
    fn ascii_entropy_typical_path_mid() {
        let h = ascii_entropy("/api/users/profile");
        assert!(h > 0.3 && h < 0.8, "typical path mid-range, got {h}");
    }

    // ── V139 — schema v3 cross-signal features ────────────────────

    #[test]
    fn defaults_use_schema_version_3() {
        let w = WeightsV2::default();
        assert_eq!(w.schema_version, 3);
    }

    #[test]
    fn n_features_v2_is_23() {
        assert_eq!(N_FEATURES_V2, 23);
        let f = clean_browser_features();
        assert_eq!(f.as_array().len(), 23);
    }

    #[test]
    fn ja4_reputation_hit_pushes_score_up() {
        let s = MlScorerV2::new(true);
        let base = clean_browser_features();
        let p_clean = s.score_pct(&base);
        let mut with_rep = base;
        with_rep.ja4_reputation = 1.0; // full CTI match
        let p_rep = s.score_pct(&with_rep);
        // Clean browser scores deep in the sigmoid tail, so the
        // absolute pp delta stays small; what matters is that the
        // feature meaningfully shifts the score upward (multiple x).
        assert!(
            p_rep > p_clean,
            "JA4 reputation must push score up: {p_clean} → {p_rep}"
        );
        assert!(
            p_rep > p_clean * 3.0,
            "JA4 rep weight=2.0 should at least triple the score, got {p_clean} → {p_rep}",
        );
    }

    #[test]
    fn fp_consistency_pushes_score_up_on_mismatch() {
        let s = MlScorerV2::new(true);
        let base = clean_browser_features();
        let p_clean = s.score_pct(&base);
        let mut mismatched = base;
        mismatched.fp_consistency_score = 1.0; // stacked mismatch
        let p_mis = s.score_pct(&mismatched);
        assert!(
            p_mis > p_clean,
            "fp_consistency must push score up: {p_clean} → {p_mis}"
        );
        assert!(
            p_mis > p_clean * 2.0,
            "fp_consistency weight=1.5 should at least double the score, got {p_clean} → {p_mis}",
        );
    }

    #[test]
    fn asn_reputation_is_neutral_by_default() {
        // V139 ships asn_reputation with weight 0 (operator opt-in)
        // so setting it must NOT change the score until the operator
        // retrains with a non-zero weight.
        let s = MlScorerV2::new(true);
        let base = clean_browser_features();
        let p0 = s.score_pct(&base);
        let mut bad_asn = base;
        bad_asn.asn_reputation = 1.0;
        let p1 = s.score_pct(&bad_asn);
        assert!(
            (p1 - p0).abs() < 1e-4,
            "default asn weight must be 0, got delta {}",
            p1 - p0
        );
    }
}
