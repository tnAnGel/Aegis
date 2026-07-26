//! V136 — Gradient Boosted Decision Trees (GBM) for feature interactions.
//!
//! V97/V122 logistic regression assumes features combine linearly,
//! so "high URI entropy" + "missing UA" scores as the sum of the two
//! penalties — but in real traffic the combination is worse than
//! either alone. GBM picks up those interactions automatically:
//! every leaf is a conjunction of feature thresholds along its
//! root-to-leaf path, so a leaf that says "uri_entropy > 0.8 AND
//! has_ua = 0 → +1.4" is exactly the kind of pattern linear models
//! can't represent.
//!
//! Architecture:
//!
//! 1. **Shallow trees** (default max_depth=4 → ≤16 leaves). Shallow
//!    trees keep variance low; we lean on ensembling for capacity.
//! 2. **Stage-wise residual fitting** — tree T fits the gradient of
//!    the logistic loss with respect to the running prediction
//!    `F(x) = Σ_t lr · tree_t(x)`. Concretely each tree is trained
//!    on residuals `(y - σ(F(x)))`.
//! 3. **Bounded ensemble size** — default 50 trees. More trees only
//!    matters with more data and we cap to keep inference predictable
//!    (~50 × max_depth comparisons = fast).
//!
//! Coexists with the logistic V122 — operators pick which scorer
//! drives their RiskEngine via config. Same FeaturesV2 input so the
//! whole rest of the pipeline (training samples, eval metrics,
//! active learning) reuses without change.
//!
//! ## Inference cost
//!
//! 50 trees × 4 depth = 200 comparisons max per request. On modern
//! x86 that's ~500 ns; comparable to V122's 20 fused multiply-adds
//! once cache effects are accounted for. No SIMD speedup, but the
//! quality lift from interactions usually justifies it.

use serde::{Deserialize, Serialize};

use crate::ddos::ml_score_v2::{FeaturesV2, N_FEATURES_V2};

/// Tree node — either an internal split or a terminal leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Node {
    Split {
        feature_idx: u8,
        threshold: f32,
        left: u32,
        right: u32,
    },
    Leaf {
        value: f32,
    },
}

/// One decision tree. Stored as a flat Vec so Serde can
/// roundtrip it and so traversal stays cache-friendly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

impl Tree {
    pub fn predict(&self, x: &[f32; N_FEATURES_V2]) -> f32 {
        let mut idx = 0usize;
        loop {
            match &self.nodes[idx] {
                Node::Leaf { value } => return *value,
                Node::Split {
                    feature_idx,
                    threshold,
                    left,
                    right,
                } => {
                    idx = if x[*feature_idx as usize] <= *threshold {
                        *left as usize
                    } else {
                        *right as usize
                    };
                }
            }
        }
    }
}

/// Operator-tunable training knobs. Defaults aim at correctness over
/// raw throughput — operators with deeper data can crank up.
#[derive(Debug, Clone)]
pub struct GbmConfig {
    pub n_trees: u32,
    pub max_depth: u8,
    /// Minimum samples per leaf. Hard floor so a single noisy sample
    /// can't carve out a high-leverage leaf.
    pub min_samples_leaf: usize,
    /// Shrinkage applied per tree. Smaller = needs more trees but
    /// generalises better; classic GBM literature recommends 0.05–0.1.
    pub learning_rate: f32,
}

impl Default for GbmConfig {
    fn default() -> Self {
        Self {
            n_trees: 50,
            max_depth: 4,
            min_samples_leaf: 10,
            learning_rate: 0.1,
        }
    }
}

/// Trained ensemble. Predict via stage-wise sum + sigmoid.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GbmModel {
    pub trees: Vec<Tree>,
    pub learning_rate: f32,
    /// Initial prediction — log-odds of the training class prior.
    /// Bookkeeping; cheap to recompute but stored for clarity.
    pub init_score: f32,
}

impl GbmModel {
    /// Train on samples. `targets[i]` must be 0.0 or 1.0.
    pub fn train(samples: &[[f32; N_FEATURES_V2]], targets: &[f32], cfg: &GbmConfig) -> Self {
        assert_eq!(
            samples.len(),
            targets.len(),
            "samples/targets length mismatch"
        );
        if samples.is_empty() {
            return Self {
                trees: vec![],
                learning_rate: cfg.learning_rate,
                init_score: 0.0,
            };
        }
        // Initialise F(x) at the prior log-odds. Avoids the first tree
        // having to learn the base rate from scratch.
        let mean = targets.iter().sum::<f32>() / targets.len() as f32;
        let init_score = logit(mean.clamp(1e-6, 1.0 - 1e-6));
        let mut running = vec![init_score; samples.len()];
        let mut trees = Vec::with_capacity(cfg.n_trees as usize);

        for _ in 0..cfg.n_trees {
            // Residuals = y - sigmoid(F(x)) — the gradient of logistic
            // loss w.r.t. F.
            let residuals: Vec<f32> = running
                .iter()
                .zip(targets.iter())
                .map(|(f, y)| y - sigmoid(*f))
                .collect();
            let indices: Vec<u32> = (0..samples.len() as u32).collect();
            let tree = build_tree(samples, &residuals, &indices, cfg, 0);
            // Update running predictions.
            for (i, x) in samples.iter().enumerate() {
                running[i] += cfg.learning_rate * tree.predict(x);
            }
            trees.push(tree);
        }
        Self {
            trees,
            learning_rate: cfg.learning_rate,
            init_score,
        }
    }

    /// Score one sample. Returns probability in [0, 1].
    pub fn score(&self, f: &FeaturesV2) -> f32 {
        let x = f.as_array();
        let mut acc = self.init_score;
        for t in &self.trees {
            acc += self.learning_rate * t.predict(&x);
        }
        sigmoid(acc)
    }
}

fn build_tree(
    samples: &[[f32; N_FEATURES_V2]],
    residuals: &[f32],
    indices: &[u32],
    cfg: &GbmConfig,
    depth: u8,
) -> Tree {
    let mut nodes = Vec::with_capacity(16);
    grow(samples, residuals, indices, cfg, depth, &mut nodes);
    Tree { nodes }
}

/// Recursive build appending into `nodes`. Returns the index of the
/// node it just appended (the subtree root from this call's POV).
fn grow(
    samples: &[[f32; N_FEATURES_V2]],
    residuals: &[f32],
    indices: &[u32],
    cfg: &GbmConfig,
    depth: u8,
    nodes: &mut Vec<Node>,
) -> u32 {
    // Stop conditions: max depth, too few samples, or no positive
    // variance to split on.
    let leaf_value = mean_residual(residuals, indices);
    if depth >= cfg.max_depth || indices.len() <= cfg.min_samples_leaf * 2 {
        nodes.push(Node::Leaf { value: leaf_value });
        return (nodes.len() - 1) as u32;
    }

    let Some((best_feat, best_thr, left_idx, right_idx)) =
        best_split(samples, residuals, indices, cfg)
    else {
        nodes.push(Node::Leaf { value: leaf_value });
        return (nodes.len() - 1) as u32;
    };

    // Reserve our position; fix up child indices after recursion.
    let my_idx = nodes.len() as u32;
    nodes.push(Node::Leaf { value: 0.0 }); // placeholder
    let left = grow(samples, residuals, &left_idx, cfg, depth + 1, nodes);
    let right = grow(samples, residuals, &right_idx, cfg, depth + 1, nodes);
    nodes[my_idx as usize] = Node::Split {
        feature_idx: best_feat,
        threshold: best_thr,
        left,
        right,
    };
    my_idx
}

fn mean_residual(residuals: &[f32], indices: &[u32]) -> f32 {
    if indices.is_empty() {
        return 0.0;
    }
    let sum: f32 = indices.iter().map(|i| residuals[*i as usize]).sum();
    sum / indices.len() as f32
}

/// Find the (feature, threshold) split that minimises the sum of
/// squared residuals after the split. Returns None if no split beats
/// the no-split baseline by enough or violates min_samples_leaf.
fn best_split(
    samples: &[[f32; N_FEATURES_V2]],
    residuals: &[f32],
    indices: &[u32],
    cfg: &GbmConfig,
) -> Option<(u8, f32, Vec<u32>, Vec<u32>)> {
    let n = indices.len();
    if n < cfg.min_samples_leaf * 2 {
        return None;
    }
    let total_sum: f32 = indices.iter().map(|i| residuals[*i as usize]).sum();
    let total_sq: f32 = indices.iter().map(|i| residuals[*i as usize].powi(2)).sum();
    let baseline_sse = total_sq - (total_sum * total_sum) / n as f32;

    let mut best: Option<(u8, f32, f32)> = None; // (feat, threshold, sse_reduction)

    for f in 0..N_FEATURES_V2 {
        // Sort indices by feature value.
        let mut sorted: Vec<u32> = indices.to_vec();
        sorted.sort_by(|&a, &b| {
            samples[a as usize][f]
                .partial_cmp(&samples[b as usize][f])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        // Walk and find the split index minimising SSE.
        let mut left_sum = 0.0_f32;
        let mut left_sq = 0.0_f32;
        for k in 0..(n - 1) {
            let idx = sorted[k] as usize;
            left_sum += residuals[idx];
            left_sq += residuals[idx].powi(2);
            let left_n = k + 1;
            let right_n = n - left_n;
            if left_n < cfg.min_samples_leaf || right_n < cfg.min_samples_leaf {
                continue;
            }
            // Skip when values are equal — threshold must separate them.
            if samples[sorted[k] as usize][f] == samples[sorted[k + 1] as usize][f] {
                continue;
            }
            let right_sum = total_sum - left_sum;
            let right_sq = total_sq - left_sq;
            let left_sse = left_sq - (left_sum * left_sum) / left_n as f32;
            let right_sse = right_sq - (right_sum * right_sum) / right_n as f32;
            let reduction = baseline_sse - left_sse - right_sse;
            if reduction > best.map(|b| b.2).unwrap_or(0.0) {
                let threshold =
                    0.5 * (samples[sorted[k] as usize][f] + samples[sorted[k + 1] as usize][f]);
                best = Some((f as u8, threshold, reduction));
            }
        }
    }

    let (feat, thr, _) = best?;
    let mut left_idx = Vec::with_capacity(n / 2);
    let mut right_idx = Vec::with_capacity(n / 2);
    for &i in indices {
        if samples[i as usize][feat as usize] <= thr {
            left_idx.push(i);
        } else {
            right_idx.push(i);
        }
    }
    Some((feat, thr, left_idx, right_idx))
}

fn logit(p: f32) -> f32 {
    (p / (1.0 - p)).ln()
}

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
    use crate::ddos::ml_training::empty_features;

    fn feat_with_idx(idx: usize, val: f32) -> FeaturesV2 {
        let mut f = empty_features();
        let mut arr = f.as_array();
        arr[idx] = val;
        f = features_from_array(arr);
        f
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

    #[test]
    fn empty_training_returns_empty_model() {
        let m = GbmModel::train(&[], &[], &GbmConfig::default());
        assert!(m.trees.is_empty());
    }

    #[test]
    fn single_split_separates_linearly_separable_data() {
        // Feature 0 > 0.5 → label 1, else label 0.
        let mut samples = vec![];
        let mut targets = vec![];
        for i in 0..40 {
            let v = if i < 20 { 0.1 } else { 0.9 };
            let target = if v > 0.5 { 1.0 } else { 0.0 };
            samples.push(feat_with_idx(0, v).as_array());
            targets.push(target);
        }
        let m = GbmModel::train(
            &samples,
            &targets,
            &GbmConfig {
                n_trees: 10,
                max_depth: 2,
                min_samples_leaf: 5,
                learning_rate: 0.3,
            },
        );
        let low = m.score(&feat_with_idx(0, 0.1));
        let high = m.score(&feat_with_idx(0, 0.9));
        assert!(low < 0.3, "low feature → low score, got {low}");
        assert!(high > 0.7, "high feature → high score, got {high}");
    }

    #[test]
    fn captures_conditional_interaction_logistic_struggles_with() {
        // Real-traffic style conditional pattern:
        //   "high uri_entropy → malicious, UNLESS has_user_agent is
        //    also high (legitimate scanner with proper UA)."
        // Logistic regression with sum-of-weights cannot represent
        // the cancellation; trees pick up the conditional via
        // depth-2 split (root on uri_entropy, right child on
        // has_user_agent).
        //
        //   (low entropy, no UA)   → benign
        //   (low entropy, with UA) → benign
        //   (high entropy, no UA)  → MALICIOUS
        //   (high entropy, with UA)→ benign (legit scanner)
        let mut samples = vec![];
        let mut targets = vec![];
        for _ in 0..25 {
            let mut a = [0.0_f32; N_FEATURES_V2];
            a[2] = 0.1;
            a[5] = 0.0; // low entropy, no UA
            samples.push(a);
            targets.push(0.0);
            let mut a = [0.0_f32; N_FEATURES_V2];
            a[2] = 0.1;
            a[5] = 1.0; // low entropy, with UA
            samples.push(a);
            targets.push(0.0);
            let mut a = [0.0_f32; N_FEATURES_V2];
            a[2] = 0.9;
            a[5] = 0.0; // high entropy, no UA → MALICIOUS
            samples.push(a);
            targets.push(1.0);
            let mut a = [0.0_f32; N_FEATURES_V2];
            a[2] = 0.9;
            a[5] = 1.0; // high entropy, with UA → benign
            samples.push(a);
            targets.push(0.0);
        }
        let m = GbmModel::train(
            &samples,
            &targets,
            &GbmConfig {
                n_trees: 30,
                max_depth: 3,
                min_samples_leaf: 3,
                learning_rate: 0.3,
            },
        );
        let mk = |entropy: f32, ua: f32| {
            let mut a = [0.0_f32; N_FEATURES_V2];
            a[2] = entropy;
            a[5] = ua;
            features_from_array(a)
        };
        let s_low_no = m.score(&mk(0.1, 0.0));
        let s_low_yes = m.score(&mk(0.1, 1.0));
        let s_high_no = m.score(&mk(0.9, 0.0));
        let s_high_yes = m.score(&mk(0.9, 1.0));
        assert!(
            s_high_no > 0.6,
            "high entropy + no UA → malicious, got {s_high_no}"
        );
        assert!(
            s_high_yes < 0.4,
            "high entropy + UA → benign (legit), got {s_high_yes}"
        );
        assert!(s_low_no < 0.4, "low entropy → benign, got {s_low_no}");
        assert!(
            s_low_yes < 0.4,
            "low entropy + UA → benign, got {s_low_yes}"
        );
    }

    #[test]
    fn predictions_bounded_in_0_1() {
        let samples = vec![[0.5_f32; N_FEATURES_V2]; 30];
        let targets = vec![0.0_f32; 30];
        let m = GbmModel::train(&samples, &targets, &GbmConfig::default());
        let s = m.score(&empty_features());
        assert!((0.0..=1.0).contains(&s));
    }

    #[test]
    fn tree_traversal_handles_leaf_only_tree() {
        let t = Tree {
            nodes: vec![Node::Leaf { value: 0.42 }],
        };
        let x = [0.0_f32; N_FEATURES_V2];
        assert!((t.predict(&x) - 0.42).abs() < 1e-6);
    }

    #[test]
    fn shallow_tree_caps_depth() {
        let mut samples = vec![];
        let mut targets = vec![];
        // Generate 100 diverse samples.
        for i in 0..100 {
            let mut a = [0.0_f32; N_FEATURES_V2];
            a[0] = (i % 10) as f32 / 10.0;
            a[1] = ((i / 10) % 10) as f32 / 10.0;
            samples.push(a);
            targets.push(if i % 2 == 0 { 1.0 } else { 0.0 });
        }
        let m = GbmModel::train(
            &samples,
            &targets,
            &GbmConfig {
                n_trees: 5,
                max_depth: 2,
                min_samples_leaf: 5,
                learning_rate: 0.1,
            },
        );
        // max_depth=2 → at most 4 leaves, so ≤7 total nodes (3 internal + 4 leaves).
        for t in &m.trees {
            assert!(
                t.nodes.len() <= 7,
                "tree exceeds expected node cap: {}",
                t.nodes.len()
            );
        }
    }

    #[test]
    fn roundtrip_via_serde_preserves_predictions() {
        let mut samples = vec![];
        let mut targets = vec![];
        for i in 0..30 {
            let v = i as f32 / 30.0;
            samples.push(feat_with_idx(2, v).as_array());
            targets.push(if v > 0.5 { 1.0 } else { 0.0 });
        }
        let m = GbmModel::train(&samples, &targets, &GbmConfig::default());
        let json = serde_json::to_string(&m).unwrap();
        let back: GbmModel = serde_json::from_str(&json).unwrap();
        let f = feat_with_idx(2, 0.8);
        assert!((m.score(&f) - back.score(&f)).abs() < 1e-6);
    }
}
