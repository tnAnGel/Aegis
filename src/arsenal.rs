//! V192 — ArsenalState: umbrella holder for every V176-V190 module
//! with per-module activity counters.
//!
//! Each module is wrapped in an `Arc<…>` so request-path code can
//! `arsenal.normalisation()` and grab a shared handle without lock
//! contention. Counters are `AtomicU64` so the request path bumps
//! them lock-free; the `/admin/api/arsenal` endpoint reads them out
//! for the UI.
//!
//! Wired into `AegisPingoraProxy` via `.with_arsenal(arsenal)`. If
//! left unset, every getter returns `None` and the request path
//! short-circuits cleanly (defensive defaults — arsenal is optional
//! infrastructure, not load-bearing for correctness).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::{ArcSwap, ArcSwapOption};

use crate::actuator::ActuatorRegistry;
use crate::adaptive_ladder::AdaptiveLadder;
use crate::bgp_rtbh::{BgpRtbhDispatcher, InMemoryAnnouncer};
use crate::chained_trust::ChainedTrustStore;
use crate::challenge_deception::DeceptionStats;
use crate::enrichment::{EnrichmentFacade, EnrichmentSource, EntityKey, Verdict as EnrichVerdict};
use crate::h2_budget::H2BudgetTracker;
use crate::honeypot_yaml::YamlHoneypotEngine;
use crate::ja4_churn::Ja4ChurnTracker;
use crate::ja4_corpus::Ja4Corpus;
use crate::llm_honeypot::{LlmHoneypot, StubLlm};
use crate::param_profile::ParamProfileStore;
use crate::privacy_pass::PrivacyPassVerifier;
use crate::route_difficulty::DifficultyTable;
use crate::rule_planner::RulePlan;
use crate::scenarios::ScenarioEngine;
use std::sync::RwLock;

/// V205 — per-domain challenge override. Stored in DomainPolicy
/// (V162) as JSON; the ChallengeContext consults this before
/// falling through to the global AdaptiveLadder defaults.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct DomainChallengeConfig {
    /// Enable Argon2id PoW instead of SHA-256 for this host.
    #[serde(default)]
    pub argon2_pow: bool,
    /// Argon2 difficulty bits (overrides global default).
    #[serde(default)]
    pub argon2_bits: Option<u8>,
    /// Argon2 memory KB (overrides global default).
    #[serde(default)]
    pub argon2_memory_kb: Option<u32>,
    /// Enable Privacy Pass token bypass on this host.
    #[serde(default)]
    pub privacy_pass: bool,
    /// Enable chained trust progression (cleared captcha = 24h
    /// bypass).
    #[serde(default)]
    pub chained_trust: bool,
    /// Enable adaptive ladder mode (anomaly bumps + randomized
    /// order + fast-track on high suspicion).
    #[serde(default)]
    pub adaptive: bool,
    /// Use varied error pages instead of plain "blocked".
    #[serde(default)]
    pub varied_errors: bool,
    /// Render decoy CAPTCHA for very-high-suspicion clients
    /// (suspicion ≥ 0.9). Wastes attacker solver quota.
    #[serde(default)]
    pub decoy_captcha: bool,
    /// Inject honeypot form fields into challenge forms.
    #[serde(default)]
    pub honeypot_fields: bool,
    /// Allow trust progression on auth routes (/login, /signup,
    /// /reset). OFF by default — recovery actions should always
    /// re-challenge.
    #[serde(default)]
    pub trust_for_auth: bool,
    /// Suspicion threshold for fast-track (0.0..=1.0).
    #[serde(default)]
    pub fast_track_threshold: Option<f32>,
    /// Bits to bump under attack mode (default +4).
    #[serde(default)]
    pub attack_mode_bits: Option<u8>,

    // ── V233+ challenge arsenal (phase 1 foundation) ──────────────
    // All new fields default to None/false so existing hosts are
    // unchanged. Passive signals + JS probes + enforcement levers +
    // Turnstile top rung. Real logic lands in later phases; phase 1
    // only lays the config + counter shape.
    /// Passive: TLS JA4 vs claimed User-Agent mismatch.
    #[serde(default)]
    pub ja4_ua_consistency: Option<bool>,
    /// Passive: HTTP header order/casing fingerprint.
    #[serde(default)]
    pub header_fingerprint: Option<bool>,
    /// Passive: HTTP/2 SETTINGS/window/pseudo-header fingerprint.
    #[serde(default)]
    pub h2_fingerprint: Option<bool>,
    /// Passive: escalate challenge when client ASN is hosting/VPN.
    #[serde(default)]
    pub datacenter_asn_challenge: Option<bool>,
    /// JS: navigator.webdriver / automation artifacts.
    #[serde(default)]
    pub headless_detection: Option<bool>,
    /// JS: WebGL renderer + AudioContext fingerprint.
    #[serde(default)]
    pub webgl_audio_fp: Option<bool>,
    /// JS: rAF cadence / timer-fake detection.
    #[serde(default)]
    pub dom_timing_entropy: Option<bool>,
    /// Scale PoW difficulty up with suspicion score.
    #[serde(default)]
    pub reputation_difficulty: Option<bool>,
    /// N challenge failures from an IP -> push to XDP deny.
    #[serde(default)]
    pub fail_to_xdp_deny: Option<bool>,
    /// Cloudflare Turnstile top rung when keys configured.
    #[serde(default)]
    pub turnstile: Option<bool>,
    /// Interactive hold/click-to-verify gesture.
    #[serde(default)]
    pub proof_of_click: Option<bool>,
}

/// V229 — every counter is now a `ShardedCounter` (per-CPU
/// cache-padded shard array). 35 plain `AtomicU64` fields previously
/// shared ~5 cache lines, so a hot-path bump (`ja4_corpus_lookups`,
/// `param_profile_observations`, `adaptive_ladder_decisions` etc.)
/// caused cross-CPU cache-line ping-pong even though the writers
/// only ever wanted to bump their own counter. `ShardedCounter` is
/// a drop-in: `.fetch_add(1, Ordering::Relaxed)` and `.load(...)`
/// keep the same signatures, so call sites need no edit.
#[derive(Default)]
pub struct Counters {
    pub ja4_corpus_lookups: crate::metrics::sharded::ShardedCounter,
    pub ja4_corpus_allow_hits: crate::metrics::sharded::ShardedCounter,
    pub ja4_corpus_deny_hits: crate::metrics::sharded::ShardedCounter,
    pub ja4_churn_observations: crate::metrics::sharded::ShardedCounter,
    pub grease_checks: crate::metrics::sharded::ShardedCounter,
    pub grease_anomalies: crate::metrics::sharded::ShardedCounter,
    pub normalisation_calls: crate::metrics::sharded::ShardedCounter,
    pub normalisation_chained_passes: crate::metrics::sharded::ShardedCounter,
    pub param_profile_observations: crate::metrics::sharded::ShardedCounter,
    pub param_profile_anomalies: crate::metrics::sharded::ShardedCounter,
    pub rule_plan_dispatches: crate::metrics::sharded::ShardedCounter,
    pub h2_budget_allows: crate::metrics::sharded::ShardedCounter,
    pub h2_budget_rejects: crate::metrics::sharded::ShardedCounter,
    pub llm_honeypot_responses: crate::metrics::sharded::ShardedCounter,
    pub yaml_honeypot_engagements: crate::metrics::sharded::ShardedCounter,
    pub sicherheitstacho_emits: crate::metrics::sharded::ShardedCounter,
    pub route_difficulty_bumps: crate::metrics::sharded::ShardedCounter,
    pub bgp_rtbh_announces: crate::metrics::sharded::ShardedCounter,
    pub bgp_rtbh_withdraws: crate::metrics::sharded::ShardedCounter,
    pub decoy_header_emits: crate::metrics::sharded::ShardedCounter,
    pub timing_entropy_calls: crate::metrics::sharded::ShardedCounter,
    pub timing_entropy_synthetic_flags: crate::metrics::sharded::ShardedCounter,
    pub latency_jitter_emits: crate::metrics::sharded::ShardedCounter,
    pub actuator_applies: crate::metrics::sharded::ShardedCounter,
    pub actuator_reverts_expired: crate::metrics::sharded::ShardedCounter,
    pub enrichment_lookups: crate::metrics::sharded::ShardedCounter,
    pub enrichment_cache_hits: crate::metrics::sharded::ShardedCounter,
    pub scenario_events: crate::metrics::sharded::ShardedCounter,
    pub scenario_fires: crate::metrics::sharded::ShardedCounter,
    pub argon2_pow_verifies: crate::metrics::sharded::ShardedCounter,
    pub argon2_pow_failures: crate::metrics::sharded::ShardedCounter,
    pub privacy_pass_accepts: crate::metrics::sharded::ShardedCounter,
    pub privacy_pass_rejects: crate::metrics::sharded::ShardedCounter,
    pub chained_trust_grants: crate::metrics::sharded::ShardedCounter,
    pub chained_trust_bypasses: crate::metrics::sharded::ShardedCounter,
    pub adaptive_ladder_decisions: crate::metrics::sharded::ShardedCounter,

    // ── V233+ challenge arsenal activity counters (phase 1) ───────
    // One counter per new DomainChallengeConfig signal. Bumped when
    // the corresponding signal fires; surfaced via the
    // /admin/api/challenge endpoints.
    pub challenge_ja4_ua_consistency_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_header_fingerprint_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_h2_fingerprint_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_datacenter_asn_challenge_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_headless_detection_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_webgl_audio_fp_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_dom_timing_entropy_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_reputation_difficulty_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_fail_to_xdp_deny_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_turnstile_hits: crate::metrics::sharded::ShardedCounter,
    pub challenge_proof_of_click_hits: crate::metrics::sharded::ShardedCounter,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        let g = |c: &crate::metrics::sharded::ShardedCounter| c.load(Ordering::Relaxed);
        CounterSnapshot {
            ja4_corpus_lookups: g(&self.ja4_corpus_lookups),
            ja4_corpus_allow_hits: g(&self.ja4_corpus_allow_hits),
            ja4_corpus_deny_hits: g(&self.ja4_corpus_deny_hits),
            ja4_churn_observations: g(&self.ja4_churn_observations),
            grease_checks: g(&self.grease_checks),
            grease_anomalies: g(&self.grease_anomalies),
            normalisation_calls: g(&self.normalisation_calls),
            normalisation_chained_passes: g(&self.normalisation_chained_passes),
            param_profile_observations: g(&self.param_profile_observations),
            param_profile_anomalies: g(&self.param_profile_anomalies),
            rule_plan_dispatches: g(&self.rule_plan_dispatches),
            h2_budget_allows: g(&self.h2_budget_allows),
            h2_budget_rejects: g(&self.h2_budget_rejects),
            llm_honeypot_responses: g(&self.llm_honeypot_responses),
            yaml_honeypot_engagements: g(&self.yaml_honeypot_engagements),
            sicherheitstacho_emits: g(&self.sicherheitstacho_emits),
            route_difficulty_bumps: g(&self.route_difficulty_bumps),
            bgp_rtbh_announces: g(&self.bgp_rtbh_announces),
            bgp_rtbh_withdraws: g(&self.bgp_rtbh_withdraws),
            decoy_header_emits: g(&self.decoy_header_emits),
            timing_entropy_calls: g(&self.timing_entropy_calls),
            timing_entropy_synthetic_flags: g(&self.timing_entropy_synthetic_flags),
            latency_jitter_emits: g(&self.latency_jitter_emits),
            actuator_applies: g(&self.actuator_applies),
            actuator_reverts_expired: g(&self.actuator_reverts_expired),
            enrichment_lookups: g(&self.enrichment_lookups),
            enrichment_cache_hits: g(&self.enrichment_cache_hits),
            scenario_events: g(&self.scenario_events),
            scenario_fires: g(&self.scenario_fires),
            argon2_pow_verifies: g(&self.argon2_pow_verifies),
            argon2_pow_failures: g(&self.argon2_pow_failures),
            privacy_pass_accepts: g(&self.privacy_pass_accepts),
            privacy_pass_rejects: g(&self.privacy_pass_rejects),
            chained_trust_grants: g(&self.chained_trust_grants),
            chained_trust_bypasses: g(&self.chained_trust_bypasses),
            adaptive_ladder_decisions: g(&self.adaptive_ladder_decisions),
            challenge_ja4_ua_consistency_hits: g(&self.challenge_ja4_ua_consistency_hits),
            challenge_header_fingerprint_hits: g(&self.challenge_header_fingerprint_hits),
            challenge_h2_fingerprint_hits: g(&self.challenge_h2_fingerprint_hits),
            challenge_datacenter_asn_challenge_hits: g(
                &self.challenge_datacenter_asn_challenge_hits
            ),
            challenge_headless_detection_hits: g(&self.challenge_headless_detection_hits),
            challenge_webgl_audio_fp_hits: g(&self.challenge_webgl_audio_fp_hits),
            challenge_dom_timing_entropy_hits: g(&self.challenge_dom_timing_entropy_hits),
            challenge_reputation_difficulty_hits: g(&self.challenge_reputation_difficulty_hits),
            challenge_fail_to_xdp_deny_hits: g(&self.challenge_fail_to_xdp_deny_hits),
            challenge_turnstile_hits: g(&self.challenge_turnstile_hits),
            challenge_proof_of_click_hits: g(&self.challenge_proof_of_click_hits),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CounterSnapshot {
    pub ja4_corpus_lookups: u64,
    pub ja4_corpus_allow_hits: u64,
    pub ja4_corpus_deny_hits: u64,
    pub ja4_churn_observations: u64,
    pub grease_checks: u64,
    pub grease_anomalies: u64,
    pub normalisation_calls: u64,
    pub normalisation_chained_passes: u64,
    pub param_profile_observations: u64,
    pub param_profile_anomalies: u64,
    pub rule_plan_dispatches: u64,
    pub h2_budget_allows: u64,
    pub h2_budget_rejects: u64,
    pub llm_honeypot_responses: u64,
    pub yaml_honeypot_engagements: u64,
    pub sicherheitstacho_emits: u64,
    pub route_difficulty_bumps: u64,
    pub bgp_rtbh_announces: u64,
    pub bgp_rtbh_withdraws: u64,
    pub decoy_header_emits: u64,
    pub timing_entropy_calls: u64,
    pub timing_entropy_synthetic_flags: u64,
    pub latency_jitter_emits: u64,
    pub actuator_applies: u64,
    pub actuator_reverts_expired: u64,
    pub enrichment_lookups: u64,
    pub enrichment_cache_hits: u64,
    pub scenario_events: u64,
    pub scenario_fires: u64,
    pub argon2_pow_verifies: u64,
    pub argon2_pow_failures: u64,
    pub privacy_pass_accepts: u64,
    pub privacy_pass_rejects: u64,
    pub chained_trust_grants: u64,
    pub chained_trust_bypasses: u64,
    pub adaptive_ladder_decisions: u64,
    pub challenge_ja4_ua_consistency_hits: u64,
    pub challenge_header_fingerprint_hits: u64,
    pub challenge_h2_fingerprint_hits: u64,
    pub challenge_datacenter_asn_challenge_hits: u64,
    pub challenge_headless_detection_hits: u64,
    pub challenge_webgl_audio_fp_hits: u64,
    pub challenge_dom_timing_entropy_hits: u64,
    pub challenge_reputation_difficulty_hits: u64,
    pub challenge_fail_to_xdp_deny_hits: u64,
    pub challenge_turnstile_hits: u64,
    pub challenge_proof_of_click_hits: u64,
}

/// V184 — built-in YAML honeypot descriptors.
///
/// Previously `new_default()` constructed the engine with an empty
/// `Vec`, so `match_descriptor()` always returned `None` and the
/// `yaml_honeypot_engagements` counter could never fire. This default
/// set models the handful of paths automated scanners hammer hardest
/// (phpMyAdmin, WordPress login, .env, .git/config) with single-turn
/// believable responses. Operators override the whole set via the
/// `AEGIS_HONEYPOT_YAML` file path (loaded in `new_default`).
const DEFAULT_HONEYPOT_YAML: &str = r#"
- name: fake-phpmyadmin
  path: /phpmyadmin/*
  turns:
    - on: login_view
      response:
        status: 200
        headers:
          server: "Apache/2.4.41 (Ubuntu)"
        body: "<!DOCTYPE html><title>phpMyAdmin</title><h1>Welcome to phpMyAdmin</h1>"
- name: fake-wp-login
  path: /wp-login.php
  turns:
    - on: login_view
      response:
        status: 200
        headers:
          server: "nginx"
        body: "<!DOCTYPE html><title>Log In</title><h1>WordPress</h1>"
- name: fake-dotenv
  path: /.env
  turns:
    - on: read
      response:
        status: 200
        body: "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=changeme\n"
- name: fake-git-config
  path: /.git/config
  turns:
    - on: read
      response:
        status: 200
        body: "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.invalid/app.git\n"
"#;

/// V184 — parse the built-in descriptor set, falling back to an empty
/// vec on parse error (never panics at startup). When the
/// `AEGIS_HONEYPOT_YAML` env var points at a readable file, that file
/// wins over the built-in default.
fn default_honeypot_descriptors() -> Vec<crate::honeypot_yaml::Descriptor> {
    let yaml = match std::env::var("AEGIS_HONEYPOT_YAML")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
    {
        Some(text) => text,
        None => DEFAULT_HONEYPOT_YAML.to_string(),
    };
    match crate::honeypot_yaml::parse_descriptors(&yaml) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "arsenal: honeypot descriptor parse failed; running with none");
            Vec::new()
        }
    }
}

/// V198 — built-in enrichment source backed by the JA4 corpus.
///
/// `new_default()` previously constructed the enrichment facade with
/// zero sources, so `lookup()` walked an empty source list and the
/// `enrichment_lookups` counter could only fire from an admin-only
/// endpoint. Registering this source means a per-request JA4 lookup
/// produces a real `SourceHit`, so the facade does meaningful work on
/// the live path. The corpus is the same `Arc<Ja4Corpus>` the rest of
/// the arsenal uses (shared, no duplicate state).
struct Ja4CorpusEnrichmentSource {
    corpus: Arc<Ja4Corpus>,
}

impl EnrichmentSource for Ja4CorpusEnrichmentSource {
    fn name(&self) -> &'static str {
        "ja4-corpus"
    }
    fn lookup(&self, key: &EntityKey) -> Option<(EnrichVerdict, String)> {
        let EntityKey::Ja4(ja4) = key else {
            return None;
        };
        let hit = self.corpus.lookup(ja4);
        match hit.verdict {
            crate::ja4_corpus::Verdict::Deny => Some((EnrichVerdict::Deny, hit.label.to_string())),
            crate::ja4_corpus::Verdict::Allow => {
                Some((EnrichVerdict::Allow, hit.label.to_string()))
            }
            crate::ja4_corpus::Verdict::Unknown => None,
        }
    }
}

pub struct ArsenalState {
    pub ja4_corpus: Arc<Ja4Corpus>,
    pub ja4_churn: Arc<Ja4ChurnTracker>,
    pub param_profile: Arc<ParamProfileStore>,
    pub h2_budget: Arc<H2BudgetTracker>,
    pub llm_honeypot: Arc<LlmHoneypot>,
    pub yaml_honeypot: Arc<YamlHoneypotEngine>,
    pub route_difficulty: Arc<DifficultyTable>,
    pub bgp_rtbh: Arc<BgpRtbhDispatcher>,
    /// V181 — operator-installed rule plan. Optional because most
    /// deployments populate it at startup from the parsed WAF DSL;
    /// stays None until install_rule_plan() runs. Stored in an
    /// `ArcSwapOption` so hot-path readers fetch a lock-free snapshot
    /// while writers swap atomically; `rule_plan_loaded` is the
    /// single-load fast-path gate (Relaxed because correctness still
    /// hinges on the ArcSwap snapshot — the flag is purely a hint).
    pub rule_plan: ArcSwapOption<RulePlan>,
    /// Single-atomic gate that mirrors "rule_plan has been installed
    /// at least once". Hot-path callers check this first to skip the
    /// ArcSwap snapshot when no plan is loaded.
    pub rule_plan_loaded: AtomicBool,
    /// V197 — Active-response actuator registry (timer wheel +
    /// pluggable enforcement primitives).
    pub actuators: Arc<ActuatorRegistry>,
    /// V198 — WISE-style enrichment facade over all intel sources.
    /// Constructed empty; operator/binary calls .register() per
    /// source they want unified.
    pub enrichment: Arc<RwLock<EnrichmentFacade>>,
    /// V199 — CrowdSec-style scenario engine for behavioural rate
    /// limit detection.
    pub scenarios: Arc<ScenarioEngine>,
    /// V202 — chained challenge trust progression store.
    pub chained_trust: Arc<ChainedTrustStore>,
    /// V201 — Privacy Pass token verifier.
    pub privacy_pass: Arc<PrivacyPassVerifier>,
    /// V204 — adaptive ladder controller (anomaly mode, randomized
    /// order, fast-track).
    pub adaptive_ladder: Arc<AdaptiveLadder>,
    /// V203 — deception stats (decoy CAPTCHAs rendered, honeypot
    /// fills detected, varied error pages rendered).
    pub deception: Arc<DeceptionStats>,
    /// V205 — per-domain challenge config overrides. Operator
    /// writes via /admin/api/sites/<host>/challenge; daemon reads
    /// per-request. Stored as an ArcSwap snapshot so the request
    /// path takes one atomic load instead of an RwLock acquisition;
    /// writers clone-and-swap the whole HashMap (count is tiny —
    /// O(configured hosts), updates are admin-driven and rare).
    pub domain_challenge: ArcSwap<std::collections::HashMap<String, DomainChallengeConfig>>,
    /// Single-atomic gate mirroring "domain_challenge has at least
    /// one configured host". Hot-path callers check this first to
    /// skip the ArcSwap snapshot when no overrides exist.
    pub domain_challenge_configured: AtomicBool,
    /// V245 — cross-worker persistence for the per-domain challenge config.
    /// Without this the ArcSwap above is per-worker (SO_REUSEPORT), so a
    /// panel write landed on one worker and request handling / read-back on
    /// another never saw it. When a path is attached, every set/clear writes
    /// the whole map atomically and reads mtime-poll the file — mirrors the
    /// DomainPolicyStore model.
    pub challenge_path: std::sync::Mutex<Option<std::path::PathBuf>>,
    pub challenge_mtime: std::sync::Mutex<Option<std::time::SystemTime>>,
    pub counters: Arc<Counters>,
}

impl ArsenalState {
    pub fn new_default() -> Self {
        let bgp_announcer = Arc::new(InMemoryAnnouncer::default());
        // V176 — single shared corpus instance: used both for the
        // direct request-path lookup AND as the backing store for the
        // built-in enrichment source registered below.
        let ja4_corpus = Arc::new(Ja4Corpus::new());
        // V198 — register at least one real enrichment source so the
        // facade does work on the live path (was constructed empty).
        let enrichment = {
            let mut facade = EnrichmentFacade::new(16_384);
            facade.register(Arc::new(Ja4CorpusEnrichmentSource {
                corpus: Arc::clone(&ja4_corpus),
            }));
            Arc::new(RwLock::new(facade))
        };
        Self {
            ja4_corpus: Arc::clone(&ja4_corpus),
            ja4_churn: Arc::new(Ja4ChurnTracker::default_config()),
            param_profile: Arc::new(ParamProfileStore::new(50)),
            h2_budget: Arc::new(H2BudgetTracker::new()),
            llm_honeypot: Arc::new(LlmHoneypot::new(
                Arc::new(StubLlm),
                std::time::Duration::from_secs(3600),
                4096,
            )),
            yaml_honeypot: Arc::new(YamlHoneypotEngine::new(default_honeypot_descriptors())),
            route_difficulty: Arc::new(
                DifficultyTable::new()
                    .enable_ai_scraper_preset(true)
                    .enable_auth_preset(true),
            ),
            bgp_rtbh: Arc::new(BgpRtbhDispatcher::new(
                bgp_announcer,
                "65000:666".into(),
                std::time::Duration::from_secs(3600),
            )),
            rule_plan: ArcSwapOption::const_empty(),
            rule_plan_loaded: AtomicBool::new(false),
            actuators: {
                let r = ActuatorRegistry::new();
                // Pre-register Noop actuators so the registry shows
                // the standard action kinds in /admin/api/arsenal
                // even before the operator wires a real backend.
                use crate::actuator::{ActionKind, NoopActuator};
                r.register(Arc::new(NoopActuator::new(ActionKind::XdpDeny)));
                r.register(Arc::new(NoopActuator::new(ActionKind::NftDrop)));
                r.register(Arc::new(NoopActuator::new(ActionKind::BgpAnnounce)));
                r.register(Arc::new(NoopActuator::new(ActionKind::ChallengeFloorRaise)));
                Arc::new(r)
            },
            enrichment,
            scenarios: Arc::new(ScenarioEngine::new()),
            chained_trust: Arc::new(ChainedTrustStore::new()),
            privacy_pass: Arc::new(PrivacyPassVerifier::default()),
            adaptive_ladder: Arc::new(AdaptiveLadder::new(Default::default())),
            deception: Arc::new(DeceptionStats::default()),
            domain_challenge: ArcSwap::from_pointee(Default::default()),
            domain_challenge_configured: AtomicBool::new(false),
            challenge_path: std::sync::Mutex::new(None),
            challenge_mtime: std::sync::Mutex::new(None),
            counters: Arc::new(Counters::default()),
        }
    }
}

impl Default for ArsenalState {
    fn default() -> Self {
        Self::new_default()
    }
}

impl ArsenalState {
    /// V178 — score a parsed ClientHello against the GREASE-position
    /// detector and bump counters. Caller passes the TLS record bytes
    /// (same input as [`crate::ja4::compute_ja4`]) and the JA4 that
    /// was computed from them. Returns the anomaly score in [0,1];
    /// 0 when JA4 didn't look Chrome-shaped.
    pub fn observe_grease(&self, client_hello: &[u8], ja4: &str) -> f32 {
        use std::sync::atomic::Ordering;
        self.counters.grease_checks.fetch_add(1, Ordering::Relaxed);
        let Some(obs) = crate::ja4::extract_grease_positions(client_hello) else {
            return 0.0;
        };
        let score = crate::grease_anomaly::score_against_ja4(&obs, ja4);
        if score > 0.5 {
            self.counters
                .grease_anomalies
                .fetch_add(1, Ordering::Relaxed);
        }
        score
    }

    /// V182 — token-bucket consume for an H2 control frame. Bumps
    /// counters and returns whether the frame should be allowed.
    /// Caller already has `conn_id` (e.g., session ptr or u64 from
    /// remote addr+port).
    pub fn observe_h2_frame(&self, conn_id: u64, kind: crate::h2_budget::FrameKind) -> bool {
        use crate::h2_budget::Verdict;
        use std::sync::atomic::Ordering;
        let v = self.h2_budget.consume(conn_id, kind);
        match v {
            Verdict::Allow => {
                self.counters
                    .h2_budget_allows
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            Verdict::Reject => {
                self.counters
                    .h2_budget_rejects
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// V179 — run the multi-pass normalisation chain + the SQL
    /// semantic recogniser over an untrusted payload (typically the
    /// raw query string). Bumps `normalisation_calls` once and
    /// `normalisation_chained_passes` by the number of decode passes
    /// the chain executed, so the admin panel reflects real activity.
    /// Returns the injection verdict so the caller can fold the score
    /// into its decision. Cheap on benign input — the chain stabilises
    /// in one pass when nothing needs decoding.
    pub fn normalisation_analyse(&self, payload: &str) -> crate::sql_semantic::InjectionVerdict {
        use std::sync::atomic::Ordering;
        self.counters
            .normalisation_calls
            .fetch_add(1, Ordering::Relaxed);
        let norm = crate::normalisation::normalise(payload);
        self.counters
            .normalisation_chained_passes
            .fetch_add(norm.passes as u64, Ordering::Relaxed);
        // Run the recogniser on the normalised form so multi-encoded
        // payloads are caught (the whole point of the chain).
        crate::sql_semantic::analyse_with_normalisation(payload, true)
    }

    /// V198 — enrich a JA4 fingerprint through the unified facade and
    /// bump the arsenal-level enrichment counters. Returns the
    /// aggregated verdict. The per-source + cache stats live on the
    /// facade itself; these counters give the admin panel a single
    /// "is enrichment firing on live traffic" signal.
    pub fn enrich_ja4(&self, ja4: &str) -> crate::enrichment::Verdict {
        use std::sync::atomic::Ordering;
        self.counters
            .enrichment_lookups
            .fetch_add(1, Ordering::Relaxed);
        let Ok(facade) = self.enrichment.read() else {
            return crate::enrichment::Verdict::Unknown;
        };
        let before = facade.cache_stats().0;
        let enr = facade.lookup(&EntityKey::Ja4(ja4.to_string()));
        // cache_hits increments inside lookup() on a hit; mirror that
        // into the arsenal counter so the panel separates warm lookups.
        if facade.cache_stats().0 > before {
            self.counters
                .enrichment_cache_hits
                .fetch_add(1, Ordering::Relaxed);
        }
        enr.aggregate()
    }

    /// V182 — per-request H2 budget observation. Pingora does not
    /// expose raw frame hooks, but every HTTP/2 request opens a stream,
    /// so the request path can enforce the per-connection stream budget
    /// (the Rapid-Reset / stream-churn surface) and bump the arsenal
    /// counter. Returns `true` when the request is within budget,
    /// `false` when the connection's stream budget is exhausted (caller
    /// may reject). No-op-safe: callers gate on `http_version == HTTP_2`.
    pub fn observe_h2_request(&self, conn_id: u64) -> bool {
        self.observe_h2_frame(conn_id, crate::h2_budget::FrameKind::RstStream)
    }

    /// V183/V184 — try the operator's honeypot responders for a path.
    /// Order: YAML descriptor first (multi-turn engagement), then LLM
    /// honeypot fallback. Returns the synthesised response when a
    /// responder matched, None when neither did.
    ///
    /// The honeypot path handler invokes this BEFORE the V147
    /// poisoned tarpit so a YAML descriptor or LLM-synth response
    /// takes precedence for paths the operator explicitly modelled.
    pub fn honeypot_respond(
        &self,
        client_ip: std::net::IpAddr,
        method: &str,
        host: &str,
        path: &str,
        body: &str,
    ) -> Option<crate::llm_honeypot::SynthResponse> {
        use std::sync::atomic::Ordering;
        if let Some(desc) = self.yaml_honeypot.match_descriptor(path) {
            let desc_name = desc.name.clone();
            if let Some(turn) = self.yaml_honeypot.step(client_ip, &desc_name, body) {
                self.counters
                    .yaml_honeypot_engagements
                    .fetch_add(1, Ordering::Relaxed);
                return Some(crate::llm_honeypot::SynthResponse {
                    status: turn.response.status,
                    headers: turn.response.headers.clone(),
                    body: turn.response.body.clone().into_bytes(),
                });
            }
        }
        // LLM fallback only fires on operator-declared honeypot paths
        // (caller's responsibility). When the cache has been primed
        // for the request shape this is essentially free.
        let key = crate::llm_honeypot::SemanticKey::compute(
            method,
            path,
            &["host", "user-agent"],
            &crate::llm_honeypot::body_shape(body, "application/x-www-form-urlencoded"),
        );
        let ctx = crate::llm_honeypot::RequestContext {
            method,
            path,
            headers: vec![("host", host)],
            body_preview: body,
        };
        let resp = self.llm_honeypot.respond(&ctx, key);
        self.counters
            .llm_honeypot_responses
            .fetch_add(1, Ordering::Relaxed);
        Some(resp)
    }

    /// V181 — register a rule plan for an operator's WAF ruleset.
    /// Once registered, callers can `arsenal.rule_plan()` to get a
    /// shared handle and pre-filter which rule IDs to evaluate for
    /// the current request phase.
    ///
    /// V230 — TODO(perf): the only in-tree callers
    /// (`proxy::pingora_http` request scorer) discard the returned
    /// `Vec<u32>` immediately with `let _ = ...`. The allocation +
    /// `to_vec()` copy of the per-phase ID slice is pure waste on
    /// the request hot path. Prefer [`Self::rule_plan_dispatch_count`]
    /// (or [`Self::rule_plan_dispatch_observe`] when callers want a
    /// non-allocating bool gate) — kept here for compatibility with
    /// any external API consumer that genuinely needs the IDs.
    pub fn rule_plan_dispatch(&self, phase: crate::rule_planner::Phase) -> Vec<u32> {
        use std::sync::atomic::Ordering;
        // Fast path: single atomic load gates the ArcSwap deref.
        // Skips the snapshot allocation entirely when no plan has
        // ever been installed (the overwhelmingly common case on
        // deployments that don't ship a custom WAF DSL).
        if !self.rule_plan_loaded.load(Ordering::Relaxed) {
            self.counters
                .rule_plan_dispatches
                .fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }
        let ids = self
            .rule_plan
            .load()
            .as_ref()
            .map(|p| p.rules_for_phase(phase).to_vec())
            .unwrap_or_default();
        self.counters
            .rule_plan_dispatches
            .fetch_add(1, Ordering::Relaxed);
        ids
    }

    /// V230 — allocation-free variant of [`Self::rule_plan_dispatch`].
    /// Bumps the same dispatch counter and returns the number of rule
    /// IDs that would fire for the phase (or 0 when no plan is
    /// installed). The hot path on deployments without a custom WAF
    /// DSL takes one relaxed atomic load + one counter increment, no
    /// `Vec` allocation, no slice copy. Use this when the caller only
    /// needs to know whether/how-many rules would match — the current
    /// in-tree callers in `proxy::pingora_http` discard the IDs.
    pub fn rule_plan_dispatch_count(&self, phase: crate::rule_planner::Phase) -> usize {
        use std::sync::atomic::Ordering;
        if !self.rule_plan_loaded.load(Ordering::Relaxed) {
            self.counters
                .rule_plan_dispatches
                .fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        let count = self
            .rule_plan
            .load()
            .as_ref()
            .map(|p| p.rules_for_phase(phase).len())
            .unwrap_or(0);
        self.counters
            .rule_plan_dispatches
            .fetch_add(1, Ordering::Relaxed);
        count
    }

    /// V230 — pure side-effect form: bumps the dispatch counter and
    /// returns `true` iff a plan is installed AND has at least one
    /// rule for the phase. Cheapest of the three variants when the
    /// caller doesn't care how many rules would fire, only whether
    /// the planner would have done work. Single relaxed atomic load
    /// on the no-plan path.
    pub fn rule_plan_dispatch_observe(&self, phase: crate::rule_planner::Phase) -> bool {
        self.rule_plan_dispatch_count(phase) > 0
    }

    /// V230 — convenience delegator for the hot-path emptiness check
    /// at `proxy::pingora_http`'s request-filter pipeline. Avoids
    /// `arsenal.scenarios.scenarios().is_empty()` (which used to
    /// clone every loaded `ScenarioConfig` just to call `.is_empty()`)
    /// in favour of `ScenarioEngine::is_empty`, which reads a single
    /// relaxed atomic gate. Pure delegation — kept here so callers
    /// that already hold `&ArsenalState` don't have to deref through
    /// the `scenarios` field manually.
    #[inline]
    pub fn scenarios_is_empty(&self) -> bool {
        self.scenarios.is_empty()
    }

    /// Swap the BGP RTBH announcer (consuming builder, call right after
    /// `new_default`). Lets the binary wire a real `ExabgpPipeAnnouncer`
    /// (writes `announce route … community 65000:666` to a file/pipe an
    /// operator points exabgp at) instead of the default in-memory/noop
    /// announcer, so blackhole decisions actually propagate. Keeps the
    /// same community + TTL `new_default` uses.
    pub fn with_bgp_announcer(
        mut self,
        announcer: std::sync::Arc<dyn crate::bgp_rtbh::BgpAnnouncer>,
    ) -> Self {
        self.bgp_rtbh = std::sync::Arc::new(BgpRtbhDispatcher::new(
            announcer,
            "65000:666".into(),
            std::time::Duration::from_secs(3600),
        ));
        self
    }

    pub fn install_rule_plan(&self, plan: crate::rule_planner::RulePlan) {
        self.rule_plan.store(Some(Arc::new(plan)));
        // Set after the swap so any reader that sees the flag is
        // guaranteed to observe the new plan via the ArcSwap.
        self.rule_plan_loaded.store(true, Ordering::Relaxed);
    }

    /// V245 — attach a disk path for cross-worker persistence of the
    /// per-domain challenge config. Loads any existing file, then every
    /// set/clear writes it atomically and reads mtime-poll it. Call once
    /// at startup (bin/aegis-pingora.rs), like DomainPolicyStore.
    pub fn attach_challenge_persistence(&self, path: std::path::PathBuf) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(raw) = std::fs::read_to_string(&path)
            && let Ok(map) = serde_json::from_str::<
                std::collections::HashMap<String, DomainChallengeConfig>,
            >(&raw)
        {
            let configured = !map.is_empty();
            self.domain_challenge.store(Arc::new(map));
            self.domain_challenge_configured
                .store(configured, Ordering::Relaxed);
        }
        let mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        *self.challenge_mtime.lock().expect("challenge mtime") = mtime;
        *self.challenge_path.lock().expect("challenge path") = Some(path);
    }

    /// Write the current map to disk atomically (no-op when no path).
    fn persist_domain_challenge(&self) {
        let guard = self.challenge_path.lock().expect("challenge path");
        let Some(path) = guard.clone() else { return };
        drop(guard);
        let snap = (**self.domain_challenge.load()).clone();
        let Ok(json) = serde_json::to_vec_pretty(&snap) else {
            return;
        };
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &json).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            if let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) {
                *self.challenge_mtime.lock().expect("challenge mtime") = Some(m);
            }
        }
    }

    /// Reload from disk if another worker changed the file (mtime-poll).
    fn refresh_domain_challenge(&self) {
        let guard = self.challenge_path.lock().expect("challenge path");
        let Some(path) = guard.clone() else { return };
        drop(guard);
        let current = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        {
            let cached = self.challenge_mtime.lock().expect("challenge mtime");
            if *cached == current {
                return;
            }
        }
        if let Ok(raw) = std::fs::read_to_string(&path)
            && let Ok(map) = serde_json::from_str::<
                std::collections::HashMap<String, DomainChallengeConfig>,
            >(&raw)
        {
            let configured = !map.is_empty();
            self.domain_challenge.store(Arc::new(map));
            self.domain_challenge_configured
                .store(configured, Ordering::Relaxed);
            *self.challenge_mtime.lock().expect("challenge mtime") = current;
        }
    }

    /// V205 — fetch the per-host challenge config (or default).
    pub fn domain_challenge_config(&self, host: &str) -> DomainChallengeConfig {
        // V245 — cross-worker refresh before the empty-gate so a config
        // written by another worker is seen here.
        self.refresh_domain_challenge();
        // Fast path: skip the snapshot deref when no host overrides
        // are configured (the default).
        if !self.domain_challenge_configured.load(Ordering::Relaxed) {
            return DomainChallengeConfig::default();
        }
        self.domain_challenge
            .load()
            .get(host)
            .cloned()
            .unwrap_or_default()
    }

    /// V205 — write the per-host challenge config (admin API hook).
    pub fn set_domain_challenge_config(&self, host: String, cfg: DomainChallengeConfig) {
        // V245 — refresh first so we merge onto another worker's latest map.
        self.refresh_domain_challenge();
        // Clone-modify-swap: copy the current snapshot, mutate, swap
        // atomically. Hot-path readers either see the old map or the
        // new one — never an intermediate state.
        let mut next = (**self.domain_challenge.load()).clone();
        next.insert(host, cfg);
        self.domain_challenge.store(Arc::new(next));
        self.domain_challenge_configured
            .store(true, Ordering::Relaxed);
        self.persist_domain_challenge();
    }

    /// V205 — list all configured hosts (for admin UI).
    pub fn domain_challenge_hosts(&self) -> Vec<String> {
        self.refresh_domain_challenge();
        if !self.domain_challenge_configured.load(Ordering::Relaxed) {
            return Vec::new();
        }
        self.domain_challenge.load().keys().cloned().collect()
    }

    /// V205 — clear a host's override (returns to defaults).
    pub fn clear_domain_challenge_config(&self, host: &str) -> bool {
        self.refresh_domain_challenge();
        // Fast path: nothing is configured, nothing to clear.
        if !self.domain_challenge_configured.load(Ordering::Relaxed) {
            return false;
        }
        let mut next = (**self.domain_challenge.load()).clone();
        let removed = next.remove(host).is_some();
        if removed {
            let now_empty = next.is_empty();
            self.domain_challenge.store(Arc::new(next));
            // If we cleared the last entry, flip the gate so future
            // hot-path lookups skip the snapshot entirely.
            if now_empty {
                self.domain_challenge_configured
                    .store(false, Ordering::Relaxed);
            }
            self.persist_domain_challenge();
        }
        removed
    }

    pub fn rule_plan_summary(&self) -> Option<(usize, usize)> {
        if !self.rule_plan_loaded.load(Ordering::Relaxed) {
            return None;
        }
        self.rule_plan
            .load()
            .as_ref()
            .map(|p| (p.total_rules(), p.phase_count()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_config_serde_round_trip_defaults() {
        // A default config must serialise and deserialise back to an
        // all-OFF config (every new field None / unset).
        let cfg = DomainChallengeConfig::default();
        let json = serde_json::to_string(&cfg).expect("serialise");
        let back: DomainChallengeConfig = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.ja4_ua_consistency, None);
        assert_eq!(back.header_fingerprint, None);
        assert_eq!(back.h2_fingerprint, None);
        assert_eq!(back.datacenter_asn_challenge, None);
        assert_eq!(back.headless_detection, None);
        assert_eq!(back.webgl_audio_fp, None);
        assert_eq!(back.dom_timing_entropy, None);
        assert_eq!(back.reputation_difficulty, None);
        assert_eq!(back.fail_to_xdp_deny, None);
        assert_eq!(back.turnstile, None);
        assert_eq!(back.proof_of_click, None);
    }

    #[test]
    fn challenge_config_serde_round_trip_enabled() {
        // Enabling the new fields must survive a JSON round-trip and
        // not disturb the pre-existing fields.
        let cfg = DomainChallengeConfig {
            argon2_pow: true,
            ja4_ua_consistency: Some(true),
            header_fingerprint: Some(true),
            h2_fingerprint: Some(false),
            datacenter_asn_challenge: Some(true),
            headless_detection: Some(true),
            webgl_audio_fp: Some(true),
            dom_timing_entropy: Some(true),
            reputation_difficulty: Some(true),
            fail_to_xdp_deny: Some(true),
            turnstile: Some(true),
            proof_of_click: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).expect("serialise");
        let back: DomainChallengeConfig = serde_json::from_str(&json).expect("deserialise");
        assert!(back.argon2_pow);
        assert_eq!(back.ja4_ua_consistency, Some(true));
        assert_eq!(back.h2_fingerprint, Some(false));
        assert_eq!(back.datacenter_asn_challenge, Some(true));
        assert_eq!(back.turnstile, Some(true));
        assert_eq!(back.proof_of_click, Some(true));
    }

    #[test]
    fn snapshot_round_trips() {
        let s = ArsenalState::new_default();
        s.counters
            .ja4_corpus_lookups
            .fetch_add(7, Ordering::Relaxed);
        s.counters
            .normalisation_calls
            .fetch_add(3, Ordering::Relaxed);
        let snap = s.counters.snapshot();
        assert_eq!(snap.ja4_corpus_lookups, 7);
        assert_eq!(snap.normalisation_calls, 3);
        assert_eq!(snap.bgp_rtbh_announces, 0);
    }

    #[test]
    fn h2_observe_consumes_bucket() {
        let s = ArsenalState::new_default();
        let mut allow = 0;
        let mut reject = 0;
        for _ in 0..100 {
            if s.observe_h2_frame(1, crate::h2_budget::FrameKind::RstStream) {
                allow += 1;
            } else {
                reject += 1;
            }
        }
        assert!((45..=55).contains(&allow));
        assert!(reject >= 45);
        let snap = s.counters.snapshot();
        assert_eq!(snap.h2_budget_allows, allow as u64);
        assert_eq!(snap.h2_budget_rejects, reject as u64);
    }

    #[test]
    fn rule_plan_install_and_dispatch() {
        let s = ArsenalState::new_default();
        let plan =
            crate::rule_planner::RulePlan::from_rules(vec![crate::rule_planner::RuleDescriptor {
                id: 1,
                name: "r1".into(),
                fields: ["http.request.uri.path"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                severity: 3,
            }]);
        s.install_rule_plan(plan);
        let ids = s.rule_plan_dispatch(crate::rule_planner::Phase::RequestUriOrQuery);
        assert_eq!(ids, vec![1]);
        assert_eq!(s.rule_plan_summary(), Some((1, 1)));
    }

    #[test]
    fn rule_plan_dispatch_count_matches_vec_len() {
        // V230 — the allocation-free count + observe variants must
        // agree with the legacy Vec API on both the no-plan and
        // plan-installed paths.
        let s = ArsenalState::new_default();
        // No plan: count == 0, observe == false, counter still bumps.
        assert_eq!(
            s.rule_plan_dispatch_count(crate::rule_planner::Phase::RequestUriOrQuery),
            0
        );
        assert!(!s.rule_plan_dispatch_observe(crate::rule_planner::Phase::RequestUriOrQuery));
        let plan = crate::rule_planner::RulePlan::from_rules(vec![
            crate::rule_planner::RuleDescriptor {
                id: 7,
                name: "r7".into(),
                fields: ["http.request.uri.path"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                severity: 3,
            },
            crate::rule_planner::RuleDescriptor {
                id: 8,
                name: "r8".into(),
                fields: ["http.request.uri.path"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                severity: 3,
            },
        ]);
        s.install_rule_plan(plan);
        let ids = s.rule_plan_dispatch(crate::rule_planner::Phase::RequestUriOrQuery);
        let count = s.rule_plan_dispatch_count(crate::rule_planner::Phase::RequestUriOrQuery);
        assert_eq!(count, ids.len());
        assert!(s.rule_plan_dispatch_observe(crate::rule_planner::Phase::RequestUriOrQuery));
    }

    #[test]
    fn scenarios_is_empty_delegates() {
        // V230 — wrapper must mirror ScenarioEngine::is_empty().
        let s = ArsenalState::new_default();
        assert!(s.scenarios_is_empty());
        assert_eq!(s.scenarios_is_empty(), s.scenarios.is_empty());
    }

    #[test]
    fn yaml_honeypot_respond_matches_default_descriptor() {
        let s = ArsenalState::new_default();
        // V184 — new_default() now ships built-in descriptors, so
        // `/.git/config` matches the `fake-git-config` descriptor and
        // engages the YAML responder (not the LLM fallback).
        let r = s.honeypot_respond(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            "GET",
            "evil.test",
            "/.git/config",
            "",
        );
        assert!(r.is_some());
        let snap = s.counters.snapshot();
        assert_eq!(snap.yaml_honeypot_engagements, 1);
        assert_eq!(snap.llm_honeypot_responses, 0);
    }

    #[test]
    fn yaml_honeypot_respond_falls_back_to_llm_for_unmodelled_path() {
        let s = ArsenalState::new_default();
        // A path no built-in descriptor models → LLM stub fallback.
        let r = s.honeypot_respond(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            "GET",
            "evil.test",
            "/totally/unmodelled/path",
            "",
        );
        assert!(r.is_some());
        let snap = s.counters.snapshot();
        assert_eq!(snap.llm_honeypot_responses, 1);
        assert_eq!(snap.yaml_honeypot_engagements, 0);
    }

    #[test]
    fn default_honeypot_descriptors_loaded() {
        // V184 — the built-in descriptor set must parse cleanly so the
        // engagement counter can actually fire on the live path.
        let descs = default_honeypot_descriptors();
        assert!(
            descs.iter().any(|d| d.name == "fake-git-config"),
            "expected built-in fake-git-config descriptor; got {:?}",
            descs.iter().map(|d| &d.name).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn default_enrichment_source_registered() {
        // V198 — new_default() must register at least one real source
        // so enrich_ja4() does work + the counter fires.
        let s = ArsenalState::new_default();
        let sources = s
            .enrichment
            .read()
            .map(|e| e.registered_sources())
            .unwrap_or_default();
        assert!(
            sources.contains(&"ja4-corpus"),
            "expected ja4-corpus enrichment source; got {sources:?}",
        );
        // A lookup bumps the arsenal lookup counter.
        let _ = s.enrich_ja4("t13d1516h2_8daaf6152771_b186095e22b6");
        assert_eq!(s.counters.snapshot().enrichment_lookups, 1);
    }

    #[test]
    fn normalisation_analyse_bumps_counters() {
        // V179 — the chain must bump the call counter (and pass counter)
        // so the panel reflects activity.
        let s = ArsenalState::new_default();
        let _ = s.normalisation_analyse("id=%2527%20UNION%20SELECT%201");
        let snap = s.counters.snapshot();
        assert_eq!(snap.normalisation_calls, 1);
        assert!(snap.normalisation_chained_passes >= 1);
    }

    #[test]
    fn default_modules_instantiated() {
        let s = ArsenalState::new_default();
        // Just exercise the getters so a missing field becomes a
        // compile error rather than silent skip.
        let _ = s.ja4_corpus.len();
        let _ = s.ja4_churn.tracked_ips();
        let _ = s.param_profile.len();
        let _ = s.h2_budget.tracked_conns();
        let _ = s.llm_honeypot.len();
        let _ = s.yaml_honeypot.descriptors().len();
        let _ = s.route_difficulty.overrides().len();
        let _ = s.bgp_rtbh.len();
    }
}
