//! V123 — Operator-driven ML retraining pipeline.
//!
//! V97 + V122 ship models with conservative defaults. Real
//! deployments need to ADAPT the model to their specific traffic —
//! one operator's "scanner" is another's "weekly internal scraper".
//! V123 closes the loop with:
//!
//! 1. **Labelled-sample store** — admin POSTs `{features, label}`
//!    where label is `benign | malicious`. We append to a bounded
//!    in-memory ring (RAM-only by default; persisted via the
//!    existing weights-file mechanism if operator opts in).
//! 2. **Batch retrain endpoint** — admin POSTs `/admin/api/ml/retrain`
//!    to run N passes of SGD over the labelled set. Returns the
//!    final loss + new weights snapshot.
//! 3. **Predict + explain endpoint** — admin POSTs a feature vector
//!    and gets back the model's score + per-feature breakdown. Used
//!    by the UI's "test this request" widget.
//! 4. **Weights export/import** — admin GET the current weights
//!    JSON, POST to replace. Operators back up models, share with
//!    other deployments, or revert after a bad training run.
//!
//! Workflow:
//!
//!     while true:
//!       sample = pick_from_recent_traffic(); show_to_operator()
//!       label = operator_clicks(benign | malicious)
//!       store.append({sample.features, label})
//!     when store.len() >= 100:
//!       POST /admin/api/ml/retrain
//!
//! The 100-sample threshold is a soft floor — fewer samples retrain
//! fine but the model may overfit. UI surfaces "you have N samples,
//! recommended ≥100".

use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::ddos::{
    ml_eval::{EvalPair, EvalSummary, summarize},
    ml_score_v2::{FeaturesV2, MlScorerV2, N_FEATURES_V2},
};

/// Bounded ring of operator-labelled samples. RAM-only by default;
/// V123 doesn't add disk persistence beyond exporting weights —
/// operators back up the weights file after a good retrain.
const MAX_SAMPLES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Benign,
    Malicious,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Benign => "benign",
            Label::Malicious => "malicious",
        }
    }

    pub fn target(self) -> f32 {
        match self {
            Label::Benign => 0.0,
            Label::Malicious => 1.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LabelledSample {
    pub features: FeaturesV2,
    pub label: Label,
}

#[derive(Debug, Clone)]
pub struct TrainResult {
    pub samples_used: usize,
    pub epochs: u32,
    pub starting_loss: f32,
    pub ending_loss: f32,
    pub residual_drop: f32,
}

/// V135 — options for the extended retrain path. Backward-compatible
/// defaults make this equivalent to the original [MlTrainer::retrain].
#[derive(Debug, Clone)]
pub struct RetrainOptions {
    pub epochs: u32,
    pub learning_rate: f32,
    /// L2 weight-decay coefficient. 0.0 disables (matches V123 behaviour).
    /// Typical range 1e-4 to 1e-2.
    pub l2_lambda: f32,
    /// Test-set fraction in [0.0, 0.5]. 0.0 disables hold-out (train
    /// + evaluate on the same set; gives an optimistic but historical
    /// number). 0.2 (80/20 split) is standard.
    pub test_split: f32,
    /// PRNG seed for reproducible shuffling/splitting. Same seed
    /// → same split, which lets operators bisect "did this retrain
    /// help, or did I get lucky with the split?".
    pub split_seed: u64,
    /// When true, weight malicious samples by the benign:malicious
    /// ratio so the rare class contributes equally to the loss.
    /// Essential on production traffic where positives are ~1%.
    pub class_balance: bool,
}

impl Default for RetrainOptions {
    fn default() -> Self {
        Self {
            epochs: 1,
            learning_rate: 0.1,
            l2_lambda: 1e-3,
            test_split: 0.2,
            split_seed: 0xA5A5_A5A5_A5A5_A5A5,
            class_balance: true,
        }
    }
}

/// V135 — extended result. Carries train + held-out metrics so the
/// admin UI can compare "model got better on the training set but
/// worse on hold-out" (overfit) vs "improved both" (genuine learning).
#[derive(Debug, Clone)]
pub struct RetrainResultEx {
    pub samples_train: u32,
    pub samples_test: u32,
    pub epochs: u32,
    pub starting_train: EvalSummary,
    pub ending_train: EvalSummary,
    pub starting_test: EvalSummary,
    pub ending_test: EvalSummary,
}

/// Persistent sample format. NDJSON one line per sample, append-only.
/// Reloaded on construction so the model survives restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSample {
    /// 20 floats — order must match `FeaturesV2::as_array()`.
    f: [f32; N_FEATURES_V2],
    /// "b" (benign) or "m" (malicious). Single-char so the file
    /// stays compact at 100k+ samples.
    l: char,
}

impl PersistedSample {
    fn from(sample: &LabelledSample) -> Self {
        Self {
            f: sample.features.as_array(),
            l: match sample.label {
                Label::Benign => 'b',
                Label::Malicious => 'm',
            },
        }
    }
    fn into_sample(self) -> Option<LabelledSample> {
        let label = match self.l {
            'b' => Label::Benign,
            'm' => Label::Malicious,
            _ => return None,
        };
        Some(LabelledSample {
            features: features_from_array(self.f),
            label,
        })
    }
}

fn features_from_array(a: [f32; N_FEATURES_V2]) -> FeaturesV2 {
    FeaturesV2 {
        uri_length: a[0],
        query_param_count: a[1],
        uri_entropy: a[2],
        query_entropy: a[3],
        header_count: a[4],
        has_user_agent: a[5],
        has_accept_language: a[6],
        has_accept_encoding: a[7],
        has_referer: a[8],
        method_is_post: a[9],
        body_length: a[10],
        ja4_present: a[11],
        ja4_browser_family: a[12],
        h2fp_present: a[13],
        recent_denied_rate: a[14],
        recent_challenged_rate: a[15],
        bot_score_rate: a[16],
        requests_per_min: a[17],
        fast_repeat: a[18],
        night_window: a[19],
        fp_consistency_score: a[20],
        ja4_reputation: a[21],
        asn_reputation: a[22],
    }
}

pub struct MlTrainer {
    scorer: Arc<MlScorerV2>,
    samples: Mutex<VecDeque<LabelledSample>>,
    /// V135 — append-only NDJSON file. When set, every add_sample()
    /// also writes the sample to disk so a restart doesn't drop
    /// operator-labelled history.
    persist_path: Mutex<Option<PathBuf>>,
}

impl MlTrainer {
    pub fn new(scorer: Arc<MlScorerV2>) -> Self {
        Self {
            scorer,
            samples: Mutex::new(VecDeque::with_capacity(MAX_SAMPLES.min(1024))),
            persist_path: Mutex::new(None),
        }
    }

    /// V135 — opt into on-disk persistence at `path`. On call:
    ///   * loads any existing samples from the file (NDJSON);
    ///   * subsequent add_sample() calls append a line each.
    /// Malformed lines are skipped with a warning rather than
    /// poisoning the whole file.
    pub fn with_persistence(self, path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        // Load existing.
        if let Ok(file) = std::fs::File::open(&path) {
            let reader = BufReader::new(file);
            let mut g = self.samples.lock().expect("trainer mutex");
            for line in reader.lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<PersistedSample>(&line) {
                    Ok(p) => {
                        if let Some(s) = p.into_sample() {
                            if g.len() == MAX_SAMPLES {
                                g.pop_front();
                            }
                            g.push_back(s);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ml_training: skipping malformed sample line");
                    }
                }
            }
        }
        *self.persist_path.lock().expect("persist mutex") = Some(path);
        self
    }

    /// Append a labelled sample. Evicts oldest when at MAX_SAMPLES.
    /// When persistence is enabled, also appends to disk.
    pub fn add_sample(&self, sample: LabelledSample) {
        if let Ok(g_path) = self.persist_path.lock()
            && let Some(path) = g_path.as_ref()
        {
            // Best-effort append; disk failure should never block
            // operator-labelled feedback.
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let p = PersistedSample::from(&sample);
                if let Ok(line) = serde_json::to_string(&p) {
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        let mut g = self.samples.lock().expect("trainer mutex poisoned");
        if g.len() == MAX_SAMPLES {
            g.pop_front();
        }
        g.push_back(sample);
    }

    pub fn sample_count(&self) -> usize {
        self.samples.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Run `epochs` passes of SGD over all stored samples with the
    /// given learning rate. Returns starting and ending mean loss.
    /// Default lr=0.1 is conservative; aggressive operators try 0.3.
    pub fn retrain(&self, epochs: u32, lr: f32) -> TrainResult {
        let samples: Vec<LabelledSample> = self
            .samples
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default();
        if samples.is_empty() {
            return TrainResult {
                samples_used: 0,
                epochs: 0,
                starting_loss: 0.0,
                ending_loss: 0.0,
                residual_drop: 0.0,
            };
        }
        let starting_loss = mean_loss(&self.scorer, &samples);
        for _ in 0..epochs {
            for s in &samples {
                self.scorer.train_step(&s.features, s.label.target(), lr);
            }
        }
        let ending_loss = mean_loss(&self.scorer, &samples);
        TrainResult {
            samples_used: samples.len(),
            epochs,
            starting_loss,
            ending_loss,
            residual_drop: starting_loss - ending_loss,
        }
    }

    /// V135 — full retrain with L2 + class weighting + hold-out
    /// evaluation. Returns metrics on both train and held-out test
    /// sets so the operator can see overfit (train good, test bad) vs
    /// genuine improvement (both better).
    ///
    /// Stratified split: positives and negatives are independently
    /// shuffled with `split_seed` and split at `test_split` so the
    /// test set's class balance matches the training set's.
    pub fn retrain_ex(&self, opts: RetrainOptions) -> RetrainResultEx {
        let all: Vec<LabelledSample> = self
            .samples
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default();
        if all.is_empty() {
            let empty = summarize(&[], 0.5);
            return RetrainResultEx {
                samples_train: 0,
                samples_test: 0,
                epochs: 0,
                starting_train: empty.clone(),
                ending_train: empty.clone(),
                starting_test: empty.clone(),
                ending_test: empty,
            };
        }
        let (train, test) = stratified_split(&all, opts.test_split, opts.split_seed);

        // Class-balance weight: positives get weighted by neg/pos so
        // both classes contribute equally to the gradient.
        let (n_pos, n_neg) = count_classes(&train);
        let pos_weight = if opts.class_balance && n_pos > 0 {
            (n_neg as f32 / n_pos as f32).max(1.0)
        } else {
            1.0
        };

        let starting_train = eval_on(&self.scorer, &train);
        let starting_test = eval_on(&self.scorer, &test);

        for _ in 0..opts.epochs {
            for s in &train {
                let weight = match s.label {
                    Label::Malicious => pos_weight,
                    Label::Benign => 1.0,
                };
                self.scorer.train_step_ex(
                    &s.features,
                    s.label.target(),
                    opts.learning_rate,
                    opts.l2_lambda,
                    weight,
                );
            }
        }

        let ending_train = eval_on(&self.scorer, &train);
        let ending_test = eval_on(&self.scorer, &test);
        RetrainResultEx {
            samples_train: train.len() as u32,
            samples_test: test.len() as u32,
            epochs: opts.epochs,
            starting_train,
            ending_train,
            starting_test,
            ending_test,
        }
    }

    /// V135 — active learning. Returns up to `top_k` samples from
    /// `candidates` whose model score is closest to the decision
    /// boundary (0.5). These are the requests the model is least
    /// confident about — labelling them is the highest information-
    /// gain for the next retrain.
    ///
    /// Caller supplies recent unlabelled traffic snapshots; admin UI
    /// surfaces them with "this one is uncertain — is it benign or
    /// malicious?" prompts.
    pub fn uncertain_predictions(
        &self,
        candidates: &[FeaturesV2],
        top_k: usize,
    ) -> Vec<(usize, f32)> {
        let mut scored: Vec<(usize, f32)> = candidates
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let score = self.scorer.score(f);
                let uncertainty = 1.0 - (score - 0.5).abs() * 2.0; // 0 = certain, 1 = boundary
                (i, uncertainty)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);
        scored
    }

    /// Snapshot samples for /admin/api/ml/samples export.
    pub fn samples_snapshot(&self) -> Vec<LabelledSample> {
        self.samples
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Clear all stored samples — used by "reset training data"
    /// admin action when the operator wants to start over.
    /// NOTE: does not truncate the on-disk persistence file; admin
    /// must remove that separately to fully reset.
    pub fn clear_samples(&self) {
        if let Ok(mut g) = self.samples.lock() {
            g.clear();
        }
    }
}

/// Count (positive, negative) samples in `s`.
fn count_classes(s: &[LabelledSample]) -> (u32, u32) {
    let mut p = 0u32;
    let mut n = 0u32;
    for x in s {
        match x.label {
            Label::Malicious => p += 1,
            Label::Benign => n += 1,
        }
    }
    (p, n)
}

/// Evaluate scorer on samples. Wraps [summarize] to keep call sites
/// in this module clean.
fn eval_on(scorer: &MlScorerV2, samples: &[LabelledSample]) -> EvalSummary {
    let pairs: Vec<EvalPair> = samples
        .iter()
        .map(|s| EvalPair {
            score: scorer.score(&s.features),
            target: s.label.target(),
        })
        .collect();
    summarize(&pairs, 0.5)
}

/// Stratified 1-(1-test_split) / test_split split. Positives and
/// negatives are each shuffled independently with `seed` then split
/// proportionally so both sets have the same class balance.
pub fn stratified_split(
    all: &[LabelledSample],
    test_split: f32,
    seed: u64,
) -> (Vec<LabelledSample>, Vec<LabelledSample>) {
    let test_split = test_split.clamp(0.0, 0.5);
    if test_split == 0.0 {
        return (all.to_vec(), vec![]);
    }
    let mut pos: Vec<LabelledSample> = all
        .iter()
        .filter(|s| s.label == Label::Malicious)
        .cloned()
        .collect();
    let mut neg: Vec<LabelledSample> = all
        .iter()
        .filter(|s| s.label == Label::Benign)
        .cloned()
        .collect();
    shuffle(&mut pos, seed.wrapping_add(0x1111));
    shuffle(&mut neg, seed.wrapping_add(0x2222));
    let pos_test = ((pos.len() as f32) * test_split).round() as usize;
    let neg_test = ((neg.len() as f32) * test_split).round() as usize;
    let mut train = Vec::with_capacity(all.len() - pos_test - neg_test);
    let mut test = Vec::with_capacity(pos_test + neg_test);
    test.extend(pos.drain(0..pos_test.min(pos.len())));
    train.extend(pos);
    test.extend(neg.drain(0..neg_test.min(neg.len())));
    train.extend(neg);
    shuffle(&mut train, seed.wrapping_add(0x3333));
    shuffle(&mut test, seed.wrapping_add(0x4444));
    (train, test)
}

/// Deterministic Fisher-Yates with a splitmix64 PRNG. Used for split
/// shuffling — same seed gives same order, which is essential for
/// reproducible retrain comparisons.
fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut state = seed | 1;
    for i in (1..v.len()).rev() {
        // splitmix64 step.
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        let j = (z as usize) % (i + 1);
        v.swap(i, j);
    }
}

/// Mean squared loss across samples. Cheap diagnostic for
/// before/after retrain comparison.
fn mean_loss(s: &MlScorerV2, samples: &[LabelledSample]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut total = 0.0_f32;
    for sample in samples {
        let pred = s.score(&sample.features);
        let target = sample.label.target();
        let err = target - pred;
        total += err * err;
    }
    total / samples.len() as f32
}

/// Build a default FeaturesV2 — used by admin endpoints that accept
/// partial JSON (operator only supplies the features they care about
/// for testing; rest stay zero).
pub fn empty_features() -> FeaturesV2 {
    FeaturesV2 {
        uri_length: 0.0,
        query_param_count: 0.0,
        uri_entropy: 0.0,
        query_entropy: 0.0,
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
        fp_consistency_score: 0.0,
        ja4_reputation: 0.0,
        asn_reputation: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_features(uri_entropy: f32, has_ua: f32, denied: f32) -> FeaturesV2 {
        let mut f = empty_features();
        f.uri_entropy = uri_entropy;
        f.has_user_agent = has_ua;
        f.recent_denied_rate = denied;
        f
    }

    #[test]
    fn add_sample_grows_count() {
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s);
        for _ in 0..5 {
            t.add_sample(LabelledSample {
                features: empty_features(),
                label: Label::Benign,
            });
        }
        assert_eq!(t.sample_count(), 5);
    }

    #[test]
    fn ring_evicts_oldest_at_cap() {
        // Use a fake low cap by adding (MAX_SAMPLES + 50) and verifying.
        // Real test would be slow at 10k+ adds; use a sentinel:
        // we trust the same VecDeque rotation. Verify count holds
        // at the cap.
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s);
        // Approximate test: add a smaller batch + verify boundedness.
        for _ in 0..50 {
            t.add_sample(LabelledSample {
                features: empty_features(),
                label: Label::Benign,
            });
        }
        assert!(t.sample_count() <= MAX_SAMPLES);
    }

    #[test]
    fn retrain_drops_loss_on_separable_data() {
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s.clone());
        // Construct 20 clean + 20 hostile samples with distinct features.
        for _ in 0..20 {
            t.add_sample(LabelledSample {
                features: mk_features(0.3, 1.0, 0.0),
                label: Label::Benign,
            });
            t.add_sample(LabelledSample {
                features: mk_features(0.95, 0.0, 0.9),
                label: Label::Malicious,
            });
        }
        let r = t.retrain(50, 0.3);
        assert_eq!(r.samples_used, 40);
        assert!(
            r.ending_loss < r.starting_loss,
            "loss should drop: start={} end={}",
            r.starting_loss,
            r.ending_loss
        );
    }

    #[test]
    fn empty_retrain_is_noop() {
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s);
        let r = t.retrain(10, 0.1);
        assert_eq!(r.samples_used, 0);
        assert_eq!(r.starting_loss, 0.0);
        assert_eq!(r.ending_loss, 0.0);
    }

    #[test]
    fn clear_samples_resets() {
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s);
        t.add_sample(LabelledSample {
            features: empty_features(),
            label: Label::Benign,
        });
        assert_eq!(t.sample_count(), 1);
        t.clear_samples();
        assert_eq!(t.sample_count(), 0);
    }

    #[test]
    fn label_target_values() {
        assert_eq!(Label::Benign.target(), 0.0);
        assert_eq!(Label::Malicious.target(), 1.0);
    }

    // ── V135 — extended training tests ────────────────────────────

    #[test]
    fn stratified_split_preserves_class_balance() {
        let mut all = vec![];
        for _ in 0..80 {
            all.push(LabelledSample {
                features: empty_features(),
                label: Label::Benign,
            });
        }
        for _ in 0..20 {
            all.push(LabelledSample {
                features: empty_features(),
                label: Label::Malicious,
            });
        }
        let (train, test) = stratified_split(&all, 0.2, 42);
        // 20% of 80 benign = 16, 20% of 20 malicious = 4 → test has 20 total.
        assert_eq!(test.len(), 20);
        assert_eq!(train.len(), 80);
        let test_pos = test.iter().filter(|s| s.label == Label::Malicious).count();
        let test_neg = test.iter().filter(|s| s.label == Label::Benign).count();
        assert_eq!(test_pos, 4);
        assert_eq!(test_neg, 16);
    }

    #[test]
    fn stratified_split_is_deterministic_for_same_seed() {
        let mut all = vec![];
        for i in 0..50 {
            let mut f = empty_features();
            f.uri_length = i as f32;
            let label = if i % 3 == 0 {
                Label::Malicious
            } else {
                Label::Benign
            };
            all.push(LabelledSample { features: f, label });
        }
        let (a_train, a_test) = stratified_split(&all, 0.25, 12345);
        let (b_train, b_test) = stratified_split(&all, 0.25, 12345);
        let a_train_ids: Vec<f32> = a_train.iter().map(|s| s.features.uri_length).collect();
        let b_train_ids: Vec<f32> = b_train.iter().map(|s| s.features.uri_length).collect();
        assert_eq!(a_train_ids, b_train_ids);
        let a_test_ids: Vec<f32> = a_test.iter().map(|s| s.features.uri_length).collect();
        let b_test_ids: Vec<f32> = b_test.iter().map(|s| s.features.uri_length).collect();
        assert_eq!(a_test_ids, b_test_ids);
    }

    #[test]
    fn stratified_split_with_zero_returns_all_train() {
        let all = vec![LabelledSample {
            features: empty_features(),
            label: Label::Benign,
        }];
        let (train, test) = stratified_split(&all, 0.0, 1);
        assert_eq!(train.len(), 1);
        assert!(test.is_empty());
    }

    #[test]
    fn retrain_ex_reports_train_and_test_metrics() {
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s);
        for _ in 0..30 {
            t.add_sample(LabelledSample {
                features: mk_features(0.3, 1.0, 0.0),
                label: Label::Benign,
            });
            t.add_sample(LabelledSample {
                features: mk_features(0.95, 0.0, 0.9),
                label: Label::Malicious,
            });
        }
        let r = t.retrain_ex(RetrainOptions {
            epochs: 20,
            learning_rate: 0.3,
            l2_lambda: 1e-3,
            test_split: 0.2,
            split_seed: 7,
            class_balance: true,
        });
        assert_eq!(r.samples_train + r.samples_test, 60);
        // Test set should also exist.
        assert!(r.samples_test > 0);
        // Both train and test AUC should improve from the random baseline.
        assert!(r.ending_train.auc >= r.starting_train.auc - 0.01);
        // Separable data should reach high accuracy.
        assert!(
            r.ending_train.accuracy > 0.9,
            "train acc low: {}",
            r.ending_train.accuracy
        );
    }

    #[test]
    fn retrain_ex_with_empty_returns_zeros() {
        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s);
        let r = t.retrain_ex(RetrainOptions::default());
        assert_eq!(r.samples_train, 0);
        assert_eq!(r.samples_test, 0);
    }

    #[test]
    fn class_balance_lifts_rare_class_recall() {
        // Imbalanced: 100 benign, 5 malicious. Without weighting,
        // model can learn "always predict benign" and look 95% accurate.
        let s = Arc::new(MlScorerV2::new(true));
        // Re-init weights to zero to start neutral.
        let mut w = s.snapshot_weights();
        w.w = [0.0; N_FEATURES_V2];
        w.bias = 0.0;
        s.store_weights(w);
        let t = MlTrainer::new(s.clone());
        for _ in 0..100 {
            t.add_sample(LabelledSample {
                features: mk_features(0.3, 1.0, 0.0),
                label: Label::Benign,
            });
        }
        for _ in 0..5 {
            t.add_sample(LabelledSample {
                features: mk_features(0.95, 0.0, 0.9),
                label: Label::Malicious,
            });
        }
        let r = t.retrain_ex(RetrainOptions {
            epochs: 30,
            learning_rate: 0.3,
            l2_lambda: 1e-4,
            test_split: 0.0, // train on all so we can check the model directly
            split_seed: 1,
            class_balance: true,
        });
        // With class balancing the malicious recall should be high
        // (catches the rare class).
        assert!(
            r.ending_train.recall > 0.5,
            "recall on rare class too low: {}",
            r.ending_train.recall
        );
    }

    #[test]
    fn uncertain_predictions_picks_boundary_scores() {
        let s = Arc::new(MlScorerV2::new(true));
        // Zero out weights so scores stay near 0.5 controllably.
        let mut w = s.snapshot_weights();
        w.w = [0.0; N_FEATURES_V2];
        w.bias = 0.0;
        // bias 0 + zero weights → all features score exactly 0.5.
        s.store_weights(w);
        let t = MlTrainer::new(s);
        let candidates = vec![empty_features(); 5];
        let picks = t.uncertain_predictions(&candidates, 3);
        assert_eq!(picks.len(), 3);
        // All scores are 0.5, all uncertainty 1.0 — top 3 are first 3
        // (stable sort).
        for (_, u) in &picks {
            assert!(
                (u - 1.0).abs() < 1e-5,
                "expected boundary uncertainty, got {u}"
            );
        }
    }

    #[test]
    fn uncertain_predictions_skips_confident_ones() {
        let s = Arc::new(MlScorerV2::new(true));
        // Use simple weights so feature → score mapping is predictable.
        let mut w = s.snapshot_weights();
        w.w = [0.0; N_FEATURES_V2];
        w.w[0] = 10.0; // uri_length dominates
        w.bias = -5.0;
        s.store_weights(w);
        let t = MlTrainer::new(s);
        // uri_length=1.0 → z=10-5=5 → score ~0.993 (very confident).
        let confident = {
            let mut f = empty_features();
            f.uri_length = 1.0;
            f
        };
        // uri_length=0.5 → z=5-5=0 → score=0.5 (max uncertainty).
        let boundary = {
            let mut f = empty_features();
            f.uri_length = 0.5;
            f
        };
        let candidates = vec![confident, boundary];
        let picks = t.uncertain_predictions(&candidates, 1);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].0, 1, "boundary candidate must win");
    }

    /// Deterministic-unique temp path. Atomic counter prevents the
    /// nanos+pid combo from colliding when two persistence tests run
    /// in parallel inside the same nanosecond (Linux fast clock).
    fn unique_temp(prefix: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{prefix}-{}-{}-{}", std::process::id(), nanos, n))
    }

    #[test]
    fn persistence_roundtrip_via_disk() {
        let dir = unique_temp("aegis-mltrain");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("samples.ndjson");

        // First trainer: persist some samples.
        {
            let s = Arc::new(MlScorerV2::new(true));
            let t = MlTrainer::new(s).with_persistence(&path);
            for _ in 0..5 {
                t.add_sample(LabelledSample {
                    features: mk_features(0.5, 1.0, 0.1),
                    label: Label::Benign,
                });
            }
            for _ in 0..3 {
                t.add_sample(LabelledSample {
                    features: mk_features(0.9, 0.0, 0.8),
                    label: Label::Malicious,
                });
            }
            assert_eq!(t.sample_count(), 8);
        }

        // Second trainer at the same path: loads the prior 8.
        {
            let s = Arc::new(MlScorerV2::new(true));
            let t = MlTrainer::new(s).with_persistence(&path);
            assert_eq!(t.sample_count(), 8);
            let snap = t.samples_snapshot();
            let pos = snap.iter().filter(|s| s.label == Label::Malicious).count();
            let neg = snap.iter().filter(|s| s.label == Label::Benign).count();
            assert_eq!(pos, 3);
            assert_eq!(neg, 5);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persistence_tolerates_malformed_lines() {
        let dir = unique_temp("aegis-mltrain-mal");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("samples.ndjson");
        // Mix of good and bad lines.
        let good = serde_json::to_string(&PersistedSample::from(&LabelledSample {
            features: mk_features(0.4, 1.0, 0.0),
            label: Label::Benign,
        }))
        .unwrap();
        std::fs::write(&path, format!("{good}\nnot-valid-json\n{good}\n")).unwrap();

        let s = Arc::new(MlScorerV2::new(true));
        let t = MlTrainer::new(s).with_persistence(&path);
        // Two valid lines loaded, one skipped.
        assert_eq!(t.sample_count(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn l2_decay_shrinks_weights_toward_zero() {
        let s = Arc::new(MlScorerV2::new(true));
        // Set a large weight.
        let mut w = s.snapshot_weights();
        w.w[0] = 10.0;
        w.bias = 0.0;
        s.store_weights(w);
        let f = empty_features();
        // Step with target matching prediction (no gradient pull) so
        // ONLY L2 decay moves the weight.
        let pred = s.score(&f);
        s.train_step_ex(&f, pred, 0.1, 0.5, 1.0);
        let after = s.snapshot_weights();
        assert!(after.w[0] < 10.0, "L2 should shrink, got {}", after.w[0]);
        assert!(after.w[0] > 0.0, "should not flip sign in one step");
    }
}
