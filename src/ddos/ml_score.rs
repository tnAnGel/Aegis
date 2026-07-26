//! V97 — Tiny in-Rust ML threat scorer (logistic regression).
//!
//! Why hand-rolled vs `tract` / TFLite
//! ------------------------------------
//! The roadmap framing said "TF Lite / tract binding" but the actual
//! deliverable is "~1µs inference, ~50KB model, online retraining".
//! Logistic regression over 8 hand-engineered features delivers all
//! three without dragging in a ~10 MB runtime + ONNX model file
//! shipping infra. Future swap-in of a richer model (tract, ort, etc)
//! is straightforward: keep the [Features] vector shape, change the
//! [MlScorer::score] body.
//!
//! Features (V97)
//! --------------
//!   0. uri_length         — normalised path+query length.
//!   1. header_count       — normalised header count.
//!   2. body_length        — normalised content-length (header-stated).
//!   3. has_user_agent     — binary 0/1.
//!   4. method_is_post     — binary 0/1; POST/PUT/PATCH bucketed together.
//!   5. ja4_unusual        — JA4 fingerprint hash maps to non-browser
//!                            bucket via FNV-bucket lookup against a tiny
//!                            in-memory popular-fingerprints set.
//!   6. recent_denied_rate — from per-worker ThreatScorer: denied count
//!                            normalised by total observed for this IP.
//!   7. recent_challenged  — challenged count normalised.
//!
//! Model
//! -----
//! Trained offline (or via [MlScorer::train_step] online) as logistic
//! regression: `score = sigmoid(Σ w_i · x_i + bias)` ∈ [0, 1]. Operator
//! converts to a 0..=100 ThreatScore via `* 100.0`.
//!
//! Persistence
//! -----------
//! Weights serialise to/from a single TOML line; ~200 bytes on disk.
//! Hot-reloadable via mtime poll (operator drops in a new weights file,
//! background task picks it up within one tick). Default ships with
//! conservative weights that mark obvious anomalies (no UA, huge URI,
//! known-attacker JA4) without flagging clean traffic.

use std::{sync::Arc, time::SystemTime};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// 8-feature vector. Each entry is pre-normalised to roughly [0, 1].
#[derive(Debug, Clone, Copy, Default)]
pub struct Features {
    pub uri_length: f32,
    pub header_count: f32,
    pub body_length: f32,
    pub has_user_agent: f32,
    pub method_is_post: f32,
    pub ja4_unusual: f32,
    pub recent_denied_rate: f32,
    pub recent_challenged_rate: f32,
}

impl Features {
    pub const N: usize = 8;

    #[inline]
    pub fn as_array(&self) -> [f32; Self::N] {
        [
            self.uri_length,
            self.header_count,
            self.body_length,
            self.has_user_agent,
            self.method_is_post,
            self.ja4_unusual,
            self.recent_denied_rate,
            self.recent_challenged_rate,
        ]
    }
}

/// Serialisable weights file. Hand-edited by operators or written
/// by [MlScorer::train_step] during online retraining.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Weights {
    pub w: [f32; Features::N],
    pub bias: f32,
}

impl Default for Weights {
    /// Conservative defaults. Mark obvious anomalies (no UA, very long
    /// URI, recent-denied IPs) but won't flag clean GETs from real
    /// browsers. Operators are expected to retrain on their own logs.
    fn default() -> Self {
        Self {
            w: [
                0.8,  // uri_length: long URIs → mildly suspicious
                0.4,  // header_count: many headers → mildly suspicious
                0.3,  // body_length: large bodies → mildly suspicious
                -1.5, // has_user_agent: absence is a strong negative signal
                0.1,  // method_is_post: small bias upward
                2.0,  // ja4_unusual: unfamiliar JA4 → strong upward
                3.0,  // recent_denied_rate: history of deny → strong upward
                1.5,  // recent_challenged_rate: history of challenge → upward
            ],
            bias: -2.0, // Default decision sits well below 0.5 → clean by default.
        }
    }
}

/// In-memory scorer. Holds weights inside [ArcSwap] so a background
/// reloader (or admin endpoint) can hot-swap without locking the
/// hot path.
pub struct MlScorer {
    enabled: bool,
    weights: ArcSwap<Weights>,
    /// Optional disk path for hot reload. None for in-memory-only use.
    path: Option<std::path::PathBuf>,
    /// Last-observed mtime so the reload task can detect changes.
    mtime: ArcSwap<Option<SystemTime>>,
}

impl MlScorer {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            weights: ArcSwap::from_pointee(Weights::default()),
            path: None,
            mtime: ArcSwap::from_pointee(None),
        }
    }

    pub fn with_path(mut self, path: std::path::PathBuf) -> Self {
        // Best-effort initial load. Missing file → defaults; bad file → defaults + warn.
        if let Ok(raw) = std::fs::read_to_string(&path) {
            match toml::from_str::<Weights>(&raw) {
                Ok(w) => {
                    self.weights.store(Arc::new(w));
                    tracing::info!(path = %path.display(), "ml_score: loaded weights");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "ml_score: weights file parse error — using defaults");
                }
            }
            if let Ok(m) = std::fs::metadata(&path)
                && let Ok(t) = m.modified()
            {
                self.mtime.store(Arc::new(Some(t)));
            }
        }
        self.path = Some(path);
        self
    }

    /// Score `features` in [0, 1]. Hot path: 8 f32 muls + 7 adds +
    /// one sigmoid call. Well under 100ns on any modern CPU.
    #[inline]
    pub fn score(&self, features: &Features) -> f32 {
        if !self.enabled {
            return 0.0;
        }
        let w = self.weights.load();
        let xs = features.as_array();
        let mut z = w.bias;
        for i in 0..Features::N {
            z += w.w[i] * xs[i];
        }
        sigmoid(z)
    }

    /// Convenience: returns score scaled to 0..=100 to match the
    /// ThreatScorer surface.
    #[inline]
    pub fn score_pct(&self, features: &Features) -> f32 {
        self.score(features) * 100.0
    }

    /// Online single-sample SGD update. `target` is 0 (benign) or 1
    /// (malicious); `lr` is the learning rate (0.01 is reasonable).
    /// Mutates the weights atomically via ArcSwap. Concurrent
    /// score() readers see either the pre- or post-update weights,
    /// never a torn mix.
    ///
    /// Returns the residual loss `target - prediction`. Operators can
    /// log this to track convergence.
    pub fn train_step(&self, features: &Features, target: f32, lr: f32) -> f32 {
        let cur = self.weights.load_full();
        let pred = self.score(features);
        let err = target - pred;
        let xs = features.as_array();
        let mut new_w = cur.w;
        for i in 0..Features::N {
            new_w[i] += lr * err * xs[i];
        }
        let new_bias = cur.bias + lr * err;
        self.weights.store(Arc::new(Weights {
            w: new_w,
            bias: new_bias,
        }));
        err
    }

    /// Snapshot current weights for /admin/api/ml_weights or
    /// persistence. Cheap — ArcSwap::load_full clones the Arc.
    pub fn snapshot_weights(&self) -> Weights {
        (**self.weights.load()).clone()
    }

    /// Persist current weights to the configured `path`. No-op when
    /// no path is set. Atomic via temp-file + rename so a partial
    /// write can't poison the file.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let w = self.snapshot_weights();
        let body = toml::to_string(&w).map_err(|e| std::io::Error::other(e.to_string()))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Background hot-reload tick. Reads the configured path's mtime;
    /// if newer than the last observed mtime, reloads weights. Returns
    /// true when a reload happened.
    pub fn maybe_reload(&self) -> bool {
        let Some(path) = &self.path else {
            return false;
        };
        let m = match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(t) => Some(t),
            Err(_) => return false,
        };
        let prev = **self.mtime.load();
        if prev == m {
            return false;
        }
        let Ok(raw) = std::fs::read_to_string(path) else {
            return false;
        };
        match toml::from_str::<Weights>(&raw) {
            Ok(w) => {
                self.weights.store(Arc::new(w));
                self.mtime.store(Arc::new(m));
                tracing::info!(path = %path.display(), "ml_score: weights reloaded");
                true
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ml_score: reload parse error");
                false
            }
        }
    }
}

/// Numerically stable sigmoid for the [0, 1] output.
#[inline]
fn sigmoid(z: f32) -> f32 {
    if z >= 0.0 {
        let e = (-z).exp();
        1.0 / (1.0 + e)
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_weights_score_clean_request_below_threshold() {
        let s = MlScorer::new(true);
        // Clean GET: short URI, few headers, has UA, GET method, JA4 ok.
        let f = Features {
            uri_length: 0.1,
            header_count: 0.2,
            body_length: 0.0,
            has_user_agent: 1.0,
            method_is_post: 0.0,
            ja4_unusual: 0.0,
            recent_denied_rate: 0.0,
            recent_challenged_rate: 0.0,
        };
        let p = s.score(&f);
        assert!(p < 0.3, "clean request should score low, got {p}");
    }

    #[test]
    fn default_weights_score_dirty_request_above_threshold() {
        let s = MlScorer::new(true);
        // Dirty: huge URI, no UA, unusual JA4, recently denied.
        let f = Features {
            uri_length: 1.0,
            header_count: 0.8,
            body_length: 0.5,
            has_user_agent: 0.0,
            method_is_post: 1.0,
            ja4_unusual: 1.0,
            recent_denied_rate: 1.0,
            recent_challenged_rate: 0.5,
        };
        let p = s.score(&f);
        assert!(p > 0.7, "dirty request should score high, got {p}");
    }

    #[test]
    fn disabled_scorer_always_zero() {
        let s = MlScorer::new(false);
        let f = Features {
            uri_length: 1.0,
            header_count: 1.0,
            body_length: 1.0,
            has_user_agent: 0.0,
            method_is_post: 1.0,
            ja4_unusual: 1.0,
            recent_denied_rate: 1.0,
            recent_challenged_rate: 1.0,
        };
        assert_eq!(s.score(&f), 0.0);
    }

    #[test]
    fn train_step_moves_prediction_toward_target() {
        let s = MlScorer::new(true);
        let f = Features {
            uri_length: 0.5,
            header_count: 0.5,
            body_length: 0.5,
            has_user_agent: 1.0,
            method_is_post: 0.0,
            ja4_unusual: 0.0,
            recent_denied_rate: 0.0,
            recent_challenged_rate: 0.0,
        };
        let p0 = s.score(&f);
        // Drive it toward 1.0 a few times.
        for _ in 0..50 {
            s.train_step(&f, 1.0, 0.5);
        }
        let p1 = s.score(&f);
        assert!(
            p1 > p0,
            "online training should raise prediction toward target=1, p0={p0} p1={p1}"
        );
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-mlscore-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("weights.toml");
        let s = MlScorer::new(true).with_path(p.clone());
        // Mutate weights via training, persist, then reload via fresh scorer.
        let f = Features {
            uri_length: 0.5,
            header_count: 0.5,
            body_length: 0.0,
            has_user_agent: 1.0,
            method_is_post: 0.0,
            ja4_unusual: 1.0,
            recent_denied_rate: 1.0,
            recent_challenged_rate: 0.0,
        };
        for _ in 0..20 {
            s.train_step(&f, 1.0, 0.3);
        }
        let pred_before = s.score(&f);
        s.save().expect("save");
        let s2 = MlScorer::new(true).with_path(p.clone());
        let pred_after = s2.score(&f);
        assert!(
            (pred_after - pred_before).abs() < 1e-3,
            "round-trip mismatch: before={pred_before} after={pred_after}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sigmoid_extrema_finite() {
        assert!(sigmoid(100.0).is_finite() && sigmoid(100.0) > 0.99);
        assert!(sigmoid(-100.0).is_finite() && sigmoid(-100.0) < 0.01);
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
    }
}
