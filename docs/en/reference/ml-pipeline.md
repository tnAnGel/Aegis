# ML pipeline (V97 → V151) — operator guide

The Aegis ML pipeline is an in-process, online-trainable threat
scorer that drives per-request `ThreatTier` for cache routing AND
contributes signal to the V108 RiskEngine. No external service
required (no Python, no model server) — everything compiled into
the `aegis-pingora` binary.

This guide walks the full operator workflow: enable → label samples →
retrain → evaluate → deploy.

## Architecture overview

```
                 raw HTTP request
                       │
                       ▼
              extract_ml_features_v2()
                       │
            [23-feature FeaturesV2 vector]
                       │
                       ▼
         ┌─────────────┴─────────────┐
         ▼                           ▼
    MlScorerV2                    GbmModel
   (V122 logistic)             (V136 trees)
         │                           │
         └─────────────┬─────────────┘
                       ▼
               score_pct() → 0..100
                       │
                       ▼
            ThreatTier::from_score()
                       │
                       ▼
            (Low | Medium | High)
                       │
                       ▼
               ResponseCache routing
```

V139 schema = 23 features:

- URI shape (4): length, query param count, URI entropy, query entropy
- Header shape (5): header count, has UA / Accept-Language / Accept-Encoding / Referer
- Method + body (2): is POST/PUT/PATCH/DELETE, content-length
- Fingerprint (3): ja4_present, ja4_browser_family, h2fp_present
- Reputation (3): recent_denied_rate, recent_challenged_rate, bot_score_rate
- Temporal (3): requests_per_min, fast_repeat, night_window
- **Cross-signal (3, V139 new)**: `fp_consistency_score` (V137+V145),
  `ja4_reputation` (V138 hit feature), `asn_reputation` (V142 hit feature)

Full schema: [src/ddos/ml_score_v2.rs](../../../src/ddos/ml_score_v2.rs).

## Step 1 — enable the V2 scorer

V97 (8-feature) is the default. V139 (23-feature) is opt-in:

```sh
# /etc/aegis/aegis.env
AEGIS_ML_V2=1
AEGIS_ML_V2_KIND=logistic      # or "gbm"
AEGIS_ML_V2_GBM_FILE=/var/lib/aegis/gbm.json   # only when kind=gbm

# Restart to apply
systemctl restart aegis-pingora.target
```

The Settings page (Settings → ML & Detection tab) reflects the
chosen kind and reports "wired" status. Without these env vars set,
the V139 scorer slot stays empty and the panel renders "not
configured" with the env var hint.

### Logistic vs GBM — when to pick which

| | Logistic (V122) | GBM (V136) |
|---|---|---|
| Inference cost | ~50ns (single multiply-add per feature) | ~500ns (50 trees × depth 4) |
| Captures feature interactions | NO (additive only) | YES (each leaf is a conjunction) |
| Online retrain | YES (single-sample SGD with L2) | NO (batch only; train offline + ship JSON) |
| Cold-start with default weights | sensible (V122 defaults work out of box) | empty model = bias term only |
| Memory | ~200 bytes (weight vector) | ~10-50 KB (trees) |

Start with logistic. Switch to GBM if you observe operator-labeled
interaction patterns (e.g., "high entropy URI AND missing UA is
worse than either alone") that logistic can't capture even after
retraining.

## Step 2 — collect labeled samples

The trainer lives at [src/ddos/ml_training.rs](../../../src/ddos/ml_training.rs).
Operator labels samples through the admin UI (planned — currently
via the JSON API directly):

```sh
# Submit a labeled sample
curl -sS -H "x-admin-token: $T" -X POST \
  http://localhost:6280/admin/api/ml/sample \
  -H 'Content-Type: application/json' \
  -d '{
    "features": {
      "uri_length": 0.95,
      "query_param_count": 0.8,
      "uri_entropy": 0.92,
      "has_user_agent": 0.0,
      ...
    },
    "label": "malicious"
  }'
```

(Endpoint slot reserved; full API ships in a follow-up.)

Until the admin endpoint is exposed, samples are collected
**automatically** through three on-by-default streams:

- **V149 robots.txt honeypot** — every Disallow visit auto-labeled
  Malicious. Hit `/wp-admin` on a non-WordPress site → label.
- **V151 adversarial loop** — V146 mutation engine generates SQLi
  / XSS / cmd variants every 5 min, runs them against the current
  WAF, labels bypasses as Malicious.
- **V107 online signature miner** — promotes mined ngrams.

Free streams will give the model 100+ samples per day in production
traffic. Operator-labeled samples are higher-quality but optional.

Optional disk persistence:

```sh
# /etc/aegis/aegis.env
AEGIS_ML_SAMPLES_PATH=/var/lib/aegis/ml-samples.ndjson
```

Samples append-only on add (NDJSON, one record per line); reloaded
on construction so a restart doesn't lose history.

## Step 3 — train

Retrain via the admin API:

```sh
curl -sS -H "x-admin-token: $T" -X POST \
  http://localhost:6280/admin/api/ml/retrain \
  -H 'Content-Type: application/json' \
  -d '{
    "epochs": 50,
    "learning_rate": 0.1,
    "l2_lambda": 1e-3,
    "test_split": 0.2,
    "split_seed": 42,
    "class_balance": true
  }'
```

Returns `RetrainResultEx`:

```json
{
  "samples_train": 800,
  "samples_test": 200,
  "epochs": 50,
  "starting_train": { "samples": 800, "accuracy": 0.52, "f1": 0.0, "auc": 0.5, "ece": 0.43, "mean_squared_error": 0.25, ...},
  "ending_train":   { "samples": 800, "accuracy": 0.94, "f1": 0.92, "auc": 0.98, "ece": 0.04, "mean_squared_error": 0.045, ...},
  "starting_test":  { "samples": 200, "accuracy": 0.50, "f1": 0.0, "auc": 0.5, ...},
  "ending_test":    { "samples": 200, "accuracy": 0.91, "f1": 0.89, "auc": 0.95, "ece": 0.06, ...}
}
```

### Reading the metrics

| Metric | Good | Bad | What it tells you |
|---|---|---|---|
| `accuracy` | >0.9 | <0.7 | overall correct fraction. Misleading on imbalanced data. |
| `precision` | >0.8 | <0.5 | when model says malicious, how often it's right (low → too many FPs) |
| `recall` | >0.7 | <0.3 | of actual malicious, how many model catches (low → missing attacks) |
| `f1` | >0.8 | <0.5 | harmonic mean of precision + recall. THE primary class-imbalance metric. |
| `fpr` (False positive rate) | <0.05 | >0.15 | how often we wrongly flag a benign as malicious |
| `auc` | >0.9 | <0.7 | threshold-independent ranking quality. 0.5 = random, 1.0 = perfect. |
| `ece` (Expected Calibration Error) | <0.1 | >0.3 | are model probabilities well-calibrated? When it says 0.7, is it right 70% of the time? |
| `mean_squared_error` | low | high | baseline loss. Use the delta start→end. |

### Watching for overfit

Overfit = `ending_train.f1` high BUT `ending_test.f1` low (test
metrics worse than train). Caused by:

- Too many epochs
- L2 too low (`l2_lambda=1e-5` instead of `1e-3`)
- Too few samples (< 100 typically)

Fix: lower epochs (10 instead of 50), raise L2 (`1e-2`), collect
more samples, or both.

### Class imbalance

In production traffic, ~99% of samples are benign. Without
`class_balance: true`, the model learns "always predict benign"
and looks 99% accurate but catches nothing (recall ~0).

`class_balance: true` weights malicious samples by
`neg_count / pos_count` during SGD so rare-class samples contribute
equally to the gradient. Result: recall lifts dramatically without
flooding the model with synthetic positives.

Test V135 `class_balance_lifts_rare_class_recall` in
[src/ddos/ml_training.rs](../../../src/ddos/ml_training.rs) demonstrates
this on a 100:5 imbalanced synthetic dataset.

## Step 4 — adversarial self-improvement (V151)

V146/V148 ship 22 semantics-preserving mutators (8 SQLi + 7 XSS +
7 cmd-injection). V151 puts them in a background loop:

```
every N ticks (default 10 × 30s = 5 min):
    for each (mutator_set, seed_corpus):
        for each seed:
            for each variant in fan_out(seed, 50 variants, chain_len 2):
                if !predicate(variant):  # WAF / ML missed it
                    bypass_count += 1
                    add to trainer as Malicious sample
```

Enable:

```sh
# /etc/aegis/aegis.env
AEGIS_ML_ADVERSARIAL=1
```

The loop emits a tracing INFO log on cycles with bypasses found:

```
2026-05-22T03:12:18.842Z INFO adversarial loop: bypasses fed back to trainer
  seeds=30 variants=1500 bypasses=12 samples=12
```

After a few cycles + a retrain, the model catches the variants
the WAF was missing. Run with operator-supplied richer corpora
(your own internal CTI feeds) for better coverage.

The predicate is operator-supplied. Easiest wire (against the V139
model itself):

```rust
use std::sync::Arc;
let pred = ml_model.clone().payload_predicate(50.0);  // > 50% score = catch
let lp = Arc::new(AdversarialLoop::with_default_mutation_sets(
    trainer.clone(), pred,
));
background = background.with_adversarial(lp, 10);
```

Default in `aegis-pingora` binary: predicate gated to wired WAF +
ML check chain.

## Step 5 — explain a prediction

For debugging "why did this request score 73 instead of 20":

```sh
curl -sS -H "x-admin-token: $T" -X POST \
  http://localhost:6280/admin/api/ml/explain \
  -H 'Content-Type: application/json' \
  -d '{"features": { ... }}'
```

Returns:

```json
{
  "feature_contributions": [
    ["uri_length", 0.4],
    ["uri_entropy", 0.95],
    ["has_user_agent", -1.5],
    ["recent_denied_rate", 2.4],
    ...
  ],
  "bias": -2.5,
  "raw_z": 3.85,
  "sigmoid": 0.979,
  "score_pct": 97.9
}
```

Each line = feature value × weight = contribution to the raw z.
Sort by absolute value to see what's driving the score. The
admin UI's "test this request" widget (planned) renders this as a
stacked bar.

## Step 6 — persistence

Model weights persist to disk via:

```sh
# /etc/aegis/aegis.env
AEGIS_ML_WEIGHTS_FILE=/var/lib/aegis/ml-weights.toml
```

Format is TOML for human inspection. Atomic write on every retrain.
Loaded on construction; restart preserves trained weights.

For GBM, weights are a JSON blob:

```sh
AEGIS_ML_V2_GBM_FILE=/var/lib/aegis/gbm.json
```

Operator trains GBM offline (typically in a notebook with
Python+xgboost on labeled samples exported via
`GET /admin/api/ml/samples` — planned), exports to the JSON shape
expected by [src/ddos/ml_gbm.rs](../../../src/ddos/ml_gbm.rs)'s
`GbmModel`, drops the file in place, restarts.

## Reference modules

| Module | Purpose |
|---|---|
| [ml_score.rs](../../../src/ddos/ml_score.rs) | V97 — 8-feature logistic (legacy fallback) |
| [ml_score_v2.rs](../../../src/ddos/ml_score_v2.rs) | V122 + V139 — 23-feature logistic + FeaturesV2 schema |
| [ml_gbm.rs](../../../src/ddos/ml_gbm.rs) | V136 — GBM trees (alternative model) |
| [ml_model.rs](../../../src/ddos/ml_model.rs) | V141 — `MlModel` enum wrapper (logistic vs GBM dispatch) |
| [ml_training.rs](../../../src/ddos/ml_training.rs) | V123 + V135 — sample store + retrain pipeline |
| [ml_eval.rs](../../../src/ddos/ml_eval.rs) | V135 — confusion matrix / AUC / F1 / ECE |
| [ml_adversarial.rs](../../../src/ml_adversarial.rs) | V146 / V148 / V151 — mutation engine + loop |
| [fp_correlation.rs](../../../src/fp_correlation.rs) | V137 — server-side fingerprint correlator |
| [client_consistency.rs](../../../src/client_consistency.rs) | V145 — CreepJS-style client signals |

## Best practices

**Train weekly, not hourly.** SGD has natural noise; retraining
every few minutes makes weights bounce. Once a day or weekly is
sufficient for most production deployments.

**Keep an "off" path.** When testing model changes, set
`AEGIS_ML_V2=0` to roll back to V97 instantly. Both models read
the same `extract_ml_features_v2`/`extract_ml_features` shape so
no state migration.

**Watch FPR on benign traffic.** If your model scores legit user
traffic >50%, your real users get the challenge ladder and
complain. Test in shadow mode first (RiskEngine `observe-only`
default) and check the false-positive rate on a known-good IP
sample before promoting to enforce.

**Adversarial loop is for blind spots, not novel attacks.** The
mutators are public knowledge from sqlmap / XSS hunters. It catches
operators who haven't seen those mutation classes but does NOT
discover novel CVE-class attacks. For that, pair with V107 mined
signatures and traditional WAF feeds.

**Class balance changes the threshold meaning.** With
`class_balance: true`, the model's 0.5 cutoff effectively moves —
you're optimizing for F1, not raw accuracy. If you want a specific
FPR target, set the threshold higher (`threshold_pct: 70` in the
predicate) and accept slightly lower recall.
