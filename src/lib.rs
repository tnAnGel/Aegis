//! Aegis library surface.
//!
//! The crate ships both a `bin` (the standalone proxy) and this `lib`
//! so integration tests can drive the handler against a real upstream
//! mock without going through process exec / network. Modules are
//! re-exported as `pub mod` so tests in `tests/` can reach into them
//! the same way `main.rs` does.

use std::{path::PathBuf, sync::Arc, time::Instant};

use tokio::sync::{RwLock, broadcast};

pub mod admin_auth;
pub mod admin_ui;
pub mod anomaly;
pub mod cli;
pub mod config;
pub mod control;
pub mod ddos;
/// V162 — per-domain policy overrides. DomainPolicyStore holds
/// per-host filter on/off overrides; the FilterEngine checks it
/// before falling through to the global RuntimeToggles (V160).
/// Future fields: per-host custom rules, per-host captcha
/// provider choice, per-endpoint policy (V166).
pub mod domain_policy;
pub mod domains;
pub mod dsl;
pub mod error;
pub mod filters;
pub mod geoip;
pub mod h2_fp;
pub mod h3_fp;
pub mod honeypot;
pub mod ja3;
pub mod ja4;

/// V134 — ACME auto-cert (Let's Encrypt). Ships the HTTP-01 challenge
/// responder + cert-on-disk layout + renewal orchestrator. The actual
/// ACME protocol driver is injected via the AcmeClient trait so the
/// operator wires instant-acme / acme-lib / their preferred crate.
pub mod acme;
/// V234 — concrete AcmeClient implementation backed by `instant-acme`.
/// Drives the full ACME RFC-8555 state machine (new-order → HTTP-01
/// challenge → finalize → certificate) and persists account credentials
/// to disk with O_CREAT|O_EXCL + chmod 0600 so the key is written
/// exactly once and never overwritten.
pub mod acme_instant;
/// V197 — Active-response actuator framework. Registry of
/// (kind, target) → pluggable Actuator with revert TTL + timer
/// wheel. Replaces scattered "XDP deny that never expires" patterns.
pub mod actuator;
/// V204 — Adaptive ladder: anomaly-mode bumps PoW bits; high
/// suspicion fast-tracks past cookie/reload; randomized starting
/// level per-IP defeats attacker fingerprinting of the sequence.
pub mod adaptive_ladder;
/// V200 — Argon2id memory-hard PoW alternative to V131 SHA-256.
/// 100-1000× more expensive per-solve on GPU farms because the
/// per-attempt RAM floor (default 64 MB) caps parallelism.
pub mod argon2_pow;
/// V192 — ArsenalState: umbrella holder for every V176-V190 module
/// + per-module activity counters. Plumbed into `AegisPingoraProxy`
/// via `.with_arsenal()`; absent by default so production binaries
/// opt in.
pub mod arsenal;
/// V142 — ASN/CIDR reputation feed. Same shape as ja4_reputation but
/// keyed by ASN (via operator-supplied AsnLookup trait) or by CIDR
/// (works without an ASN DB). Feeds the V139 asn_reputation feature.
pub mod asn_reputation;
/// V240 — server hardware benchmark + capacity projection for the admin panel.
/// Runs CPU integer / SHA-256 / memory-bandwidth micro-benchmarks and projects
/// forwarding / TLS / WAF RPS via a calibrated linear model.
pub mod benchmark;
/// V245 — head-to-head comparison vs nginx: raw HTTP throughput (tokio vs an
/// ephemeral nginx, same load generator) plus a WAF security matrix (real
/// attack payloads AEGIS blocks that a vanilla nginx forwards to the origin).
pub mod benchmark_compare;
/// V241 — flood-capacity tests for the admin Benchmark page. Spins up bounded,
/// loopback-only victim servers and load generators to measure how much of each
/// flood (SYN/connection, HTTP, TLS handshake, slowloris, cache-served) the
/// host actually withstands — achieved rps, p99 latency, drop counts, verdict.
pub mod benchmark_flood;
/// V187 — FlowSpec/BGP RTBH dispatcher. Push L7 block decisions
/// upstream as BGP /32 announcements (via exabgp pipe by default;
/// trait-based for goBGP/FRR). TTL'd auto-withdraw.
pub mod bgp_rtbh;
/// V132 — Pluggable external CAPTCHA providers (hCaptcha, Cloudflare
/// Turnstile, Google reCAPTCHA). CaptchaProvider trait abstracts the
/// siteverify call; HttpPoster trait abstracts the HTTPS transport.
pub mod captcha_providers;
/// V202 — Chained challenge trust progression. A stronger cleared
/// tier grants longer trust window covering all weaker tiers. Cookie
/// 5 min → Captcha 24h → WebAuthn 7 days.
pub mod chained_trust;
/// V203 — Challenge ladder deception layer: decoy CAPTCHA, honeypot
/// form fields, varied error pages.
pub mod challenge_deception;
/// V233+ — Challenge arsenal phase 1: passive bot-signal evaluator.
///
/// Pure, testable scoring core (`passive_bot_score`) for the new
/// challenge family (JA4↔UA consistency, header/h2 fingerprint,
/// datacenter-ASN escalation). All sub-checks are gated on the
/// per-host `DomainChallengeConfig` flags and OFF by default; phase-1
/// detectors are conservative stubs, real logic lands in phase 2.
pub mod challenge_signals;
/// V129 — ClamAV TCP scanner for body content (multipart/octet-stream
/// uploads). Wires Aegis to operator's clamd via INSTREAM protocol.
/// Disabled by default — AEGIS_CLAMAV_ADDR=host:3310 enables.
pub mod clamav_scanner;
/// V145 — CreepJS-style client consistency scoring. Tier under V137
/// fp_correlation: server-side fp_correlation catches matched-stack
/// bots, this catches anti-detect browsers via JS-environment
/// cross-signal inconsistencies (UA vs navigator.platform vs WebGL,
/// webdriver flag, zero plugins / hw_concurrency, etc.).
pub mod client_consistency;
/// V157 — CrowdSec-compatible Local API decisions adapter. Aegis
/// emits decisions in the CrowdSec LAPI wire format so every
/// existing CrowdSec bouncer (nginx, HAProxy, Cloudflare worker,
/// firewall-iptables, Caddy plugin, k8s ingress) can enforce
/// Aegis's verdicts without re-engineering enforcement.
pub mod crowdsec_api;
/// V188 — Scrapling-inverted decoy headers. Impersonates Cloudflare /
/// Akamai / Fastly / CloudFront response shape on suspect requests
/// so attacker bypass tooling selects the wrong playbook.
pub mod decoy_headers;
/// V198 — WISE-style enrichment proxy. One cached facade over all
/// intel sources (ja4_reputation, asn_reputation, threat_intel,
/// geoip, ja4_corpus). Per-source TTL + provenance.
pub mod enrichment;
/// V127 — EventBridge NDJSON streamer over Unix socket. SIEM-friendly
/// transport for V116 SecurityEvent payloads. Best-effort lossy
/// broadcast: slow subscribers get dropped events, never blocks the
/// proxy hot path.
pub mod event_bridge;
/// V243 — persistent request/event log store. Per-worker SQLite shard
/// (`shard-<slot>.db`, WAL, single writer per process) written from a
/// bounded-channel background thread so the hot-path `record()` never
/// blocks; admin read side ATTACHes all shards and UNION ALLs across them.
/// Powers request-log search, per-host analytics, and the bots/DDoS
/// "over any period" view.
pub mod event_store;
/// V137 — Cross-fingerprint correlation score. Detects "Chrome JA4 +
/// curl UA" style mismatches by checking the consistency of the JA4 /
/// JA4H / H2FP / UA tuple. Output feeds ML scorer + WAF risk engine.
pub mod fp_correlation;
/// V178 — utls GREASE-position anomaly detector. Real Chrome puts
/// GREASE in cipher[0] + ext[0] + supported_versions[0]; spoofers
/// hardcode one permutation. Anomaly score in [0,1].
pub mod grease_anomaly;
/// V182 — Tempesta-style HTTP/2 control-frame budgets. Per-connection
/// token-bucket per FrameKind. Closes Rapid Reset / Settings flood /
/// Ping flood / CONTINUATION flood class.
pub mod h2_budget;
/// V184 — Beelzebub-style YAML honeypot service descriptors. Each
/// declared path runs a deterministic multi-turn engagement script
/// with per-(IP,name) state. Includes a zero-dep YAML subset parser.
pub mod honeypot_yaml;
/// V130 — iptables backend (4th-tier fallback completing the chain
/// XDP → nftables → iptables → userspace). For legacy/embedded hosts
/// without nftables. Implements XdpHandle the same way V128 does.
pub mod iptables_backend;
/// V177 — Per-IP JA4 churn score over sliding window. High churn =
/// TLS-fingerprint rotation (utls / curl-impersonate). Feeds ML
/// scorer `ja4_churn` feature.
pub mod ja4_churn;
/// V176 — Curated JA4 corpus (FoxIO-seeded). Verdict::Allow for
/// known browsers, Verdict::Deny for known tooling. Consulted
/// before V138 reputation feed; the operator file extends it.
pub mod ja4_corpus;
/// V138 — JA4 reputation feed. Operator drops a list of bad JA4
/// hashes (community CTI, internal IR, V107 honeypot mining) into a
/// file; module exposes O(1) lookup + hot-reload. Two match kinds:
/// full JA4 (strongest) and cipher-prefix-only (weaker, broader).
pub mod ja4_reputation;
/// V126 — server-side JA4+ family: JA4S (TLS ServerHello), JA4X
/// (X.509 cert), JA4TS (TCP SYN-ACK), JA4LS (server-leg latency).
/// Synapse parity. Operator uses these to detect compromised
/// upstreams, monitor cert-chain stability, and cluster cert
/// fingerprints from CT feeds.
pub mod ja4_server;
/// V190 — LLMHoney-style response-latency jitter shaping. Log-normal
/// or bimodal-CDN distribution-shaped delays for tarpit/honeypot/
/// decoy responses. Defeats response-time fingerprinting.
pub mod latency_jitter;
/// V183 — Galah-style LLM honeypot with semantic-hash response cache.
/// LlmClient trait + cache keyed by request shape (method, path
/// template, header names, body shape) so same scanner sees coherent
/// replies without per-request LLM cost.
pub mod llm_honeypot;
pub mod logging;
pub mod metrics;
/// V146 — WAF-A-MoLE-style adversarial mutation loop. Generates
/// semantics-preserving SQLi payload variants and runs them through
/// the operator's WAF/scorer; bypasses feed back into the V135
/// MlTrainer as hard-negative samples for the next retrain.
pub mod ml_adversarial;
pub mod mtls_fp;
/// V128 — nftables firewall backend as fallback to XDP. Implements
/// XdpHandle so it drops into the existing pipeline without touching
/// the rest of the codebase. open_with_fallback() returns whatever
/// backend successfully initialised (XDP → nftables → userspace).
pub mod nftables_backend;
/// V179 — SafeLine-style multi-pass normalisation chain.
/// URL → HTML entity → NFKC full-width → unicode confusable → null
/// strip → lowercase. Runs to fixed-point with bounded passes.
pub mod normalisation;
/// V107 — online tarpit→signature miner pipeline. Tarpit decisions
/// log their payload to a file; a background task periodically mines
/// the latest entries against an in-memory sample of allowed traffic
/// and surfaces ranked candidates via /admin/api/mined_signatures.
pub mod online_signature_miner;
/// V155 — p0f-style passive OS / TCP-stack fingerprinting. Takes
/// SYN observations (window, MSS, wscale, options, TTL) Aegis
/// already captures and classifies them into an OS family for
/// UA-vs-stack cross-checking.
pub mod p0f;
/// V180 — open-appsec-style per-endpoint parameter profile learner.
/// Rolling stats (len/charset/entropy) per (host, endpoint, param);
/// anomaly score after `learn_threshold` observations.
pub mod param_profile;
/// V147 — Poisoned tarpit (Iocaine / Nepenthes / HellPot lineage).
/// Markov-chain text generator + endless-internal-links HTML so AI
/// scrapers that ignore robots.txt fall into a maze and burn CPU
/// recursively crawling fake pages. Deterministic-per-deployment
/// seed so the corpus stays hard to fingerprint.
pub mod poisoned_tarpit;
/// V131 — Proof-of-Work CAPTCHA. Asymmetric SHA-256 hashcash: client
/// pays seconds of CPU, server verifies in microseconds. Designed to
/// crush single-host attackers proxying many sessions.
pub mod pow_captcha;
/// V201 — Privacy Pass token verifier (RFC 9576-shaped). Anonymous
/// proof-of-trust tokens issued by Cloudflare/Apple/Fastly/etc;
/// verified browsers silently bypass the challenge ladder.
pub mod privacy_pass;
pub mod proxy;
pub mod proxy_proto;
/// V-new — Trusted-proxy real-client-IP resolver.
///
/// Resolves the real client IP from `CF-Connecting-IP` or
/// `X-Forwarded-For` **only when** the TCP peer is inside the
/// operator-configured trusted-proxy set. Zero behaviour change when
/// no trusted proxies are configured (`AEGIS_BEHIND_CLOUDFLARE` and
/// `AEGIS_TRUSTED_PROXIES` are both unset).
pub mod real_ip;
/// V149 — robots.txt honeypot auto-labeling. Visits to Disallow'd
/// paths automatically push Malicious training samples into the
/// V135 MlTrainer. Free high-signal label source — operators already
/// maintain robots.txt; we just consume it.
pub mod robots_honeypot;
/// V186 — Anubis-style per-route challenge difficulty. Per-(host,path)
/// difficulty overrides + AI-scraper UA preset (+4 bits for GPTBot
/// etc.) + auth-endpoint preset (+6 bits forced JS PoW on */login).
pub mod route_difficulty;
/// V181 — Coraza-style phase-indexed compiled rule plan. Buckets
/// rule IDs by Phase (uri/headers/body/response) with severity-sorted
/// dispatch and field-presence skip.
pub mod rule_planner;
/// V199 — CrowdSec-style leaky-bucket scenario DSL. YAML
/// `filter / groupby / distinct / capacity / leak_speed / blackhole`
/// grammar covers behavioural rate-limit detection without code.
pub mod scenarios;
pub mod security;
/// V116 — Structured SecurityEvent + per-decision Prometheus counters.
/// One canonical emit point for every Allow/Challenge/Deny/Throttle/
/// Observed decision the proxy makes. Cardinality-bounded labels
/// (`&'static str` reasons).
pub mod security_event;
pub mod server;
pub mod shared_state;
pub mod shutdown;
/// V185 — T-Pot Sicherheitstacho event export schema. Renders Aegis
/// security events as Sicherheitstacho-compatible NDJSON for free
/// interop with the deception-tooling ecosystem.
pub mod sicherheitstacho;
/// V196 — Sigma rule importer. Parses SigmaHQ YAML rules
/// (`logsource.category: webserver`) and emits crate::config::WafRule
/// values via the CLI `aegis-sigma-import`. Supports the common
/// modifier set (contains/startswith/endswith/re), list values,
/// single-block + "1 of selection_*" + "selection and not filter"
/// conditions.
pub mod sigma;
/// V99 — self-improving signature mining (Phase E.4). Takes a corpus
/// of attack payloads + clean traffic samples, produces ranked WAF
/// signature candidates via document-frequency n-gram extraction.
pub mod signature_mine;
/// V119 — site cartography. Auto-discovers endpoints from live
/// traffic with path generalisation (`/users/12345` → `/users/:id`)
/// and per-host bounded LRU. Surface for the admin UI per-domain
/// edit page.
pub mod site_map;
/// V156 — SafeLine-style semantic SQL-injection detector. Tokenizes
/// payloads (URL-decode + comment / quote / hex / operator-aware)
/// and recognizes shape-of-injection patterns (tautology, UNION
/// after value, stacked DDL, time-blind, comment after quote).
/// Robust against the V146/V148 mutator set by design.
pub mod sql_semantic;
pub mod state;
pub mod tcp_info;
/// V121 — threat analytics: split per-IP bot detections from
/// distributed DDoS (botnet) detections so operators can apply
/// different remediation per pattern.
pub mod threat_analytics;
/// V189 — Timing-entropy ML features. Server-side analyser for mouse
/// jitter / scroll cadence collected by V145 client_consistency.
/// Uniform-timer detectors output anomaly score ∈ [0,1].
pub mod timing_entropy;
pub mod tls_sni;
/// V232 — runtime worker-topology introspection for the admin panel's
/// Workers page (host CPU facts + live `aegis-pingora` process scan).
pub mod topology;
/// V133 — Terminal TUI dashboard (Ratatui). Pure render functions
/// over a [DashboardSnapshot] value so tests stay network-free.
/// The `aegis-tui` binary feeds it snapshots polled from the admin API.
pub mod tui;
/// V211 — Phase 3: apply-status JSON broker between aegis-updater
/// and the panel.
pub mod update_apply;
/// V210 — Phase 2: releases/<version>/ layout + atomic symlink swap.
pub mod update_layout;
/// V209 — Phase 2: pre-update config snapshot + restore.
pub mod update_snapshot;
/// V208 — Phase 1 update checker. Polls a Gitea/GitHub-compatible
/// Releases API, classifies tags into stable/beta/nightly channels,
/// surfaces "update available + changelog" to the admin UI. Does
/// NOT apply updates (operator-driven, future Phase 3).
pub mod updates;
pub mod web_admin;
pub mod xdp;

#[derive(Clone)]
pub struct RuntimeState {
    pub config_path: PathBuf,
    pub active_cfg: Arc<RwLock<config::AppConfig>>,
    pub shutdown_tx: broadcast::Sender<()>,
    pub reloader: Arc<server::Reloader>,
    pub started_at: Instant,
    pub web_admin: Arc<web_admin::WebAdminStore>,
    pub fingerprints: Arc<state::fingerprint::FingerprintCache>,
    pub honeypots: Arc<honeypot::HoneypotStore>,
}
