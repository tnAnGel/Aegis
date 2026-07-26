pub mod score;

/// V90 — Cluster-wide per-IP scorer backed by the Phase D shared
/// mmap arena. Coexists with the per-worker `score::ThreatScorer`;
/// V91+ will wire it into the proxy as opt-in.
pub mod shared_score;

/// V97 — tiny in-Rust ML threat scorer (logistic regression).
/// Hand-engineered 8-feature vector + sigmoid; <100ns inference;
/// weights persistable + hot-reloadable.
pub mod ml_score;

/// V122 — ML v2: 20-feature logistic regression replacing V97's 8.
/// Expanded coverage (URI/query entropy, fingerprint richness,
/// header shape, temporal patterns) + explainability surface
/// (per-feature contribution breakdown for /admin/api/ml_explain).
pub mod ml_score_v2;

/// V123 — operator-driven ML training pipeline. Labelled-sample
/// store + batch retrain endpoint + predict-and-explain so deployments
/// adapt the V97/V122 models to their specific traffic.
pub mod ml_training;

/// V135 — ML evaluation metrics: confusion matrix, AUC, F1, ECE.
/// Decoupled from the specific model so the same code grades V97 /
/// V122 logistic regression and V136 GBM.
pub mod ml_eval;

/// V136 — Gradient Boosted Decision Trees. Captures non-linear feature
/// interactions (XOR-style) that logistic regression cannot. Uses the
/// same FeaturesV2 input as V122, so all training infrastructure
/// (samples, eval, active learning) carries over.
pub mod ml_gbm;

/// V141 — unified ML model selector. Wraps logistic V122/V139 or
/// V136 GBM behind a single enum so the hot path can call score()
/// without branching on which engine is wired. Config-driven.
pub mod ml_model;

/// V108 — Unified Risk Engine. Folds independent filter signals
/// (WAF/ML/honeypot/threat-intel/fingerprints/...) into a single
/// explainable score → action. Default mode is observe-only.
pub mod risk_engine;
