# Project development plan

**Languages:** **English** · [Русский](../ru/41-development-plan.md) · [中文](../zh/41-development-plan.md)

> Strategic document: where AEGIS is heading as an edge-protection platform,
> which directions are a priority and why. Unlike the tactical
> [roadmap](40-roadmap.md) (what ships in which release), this document is about
> **directions and rationale**: a unified risk engine, a CRS-like WAF model,
> protocol-level L7 protection, session/device reputation, API guards and a closed
> feedback loop from production traffic.

The document is grounded in the repository's real code and in three strategy
sources: `ROADMAP-NEXT.md` (the plan up to the technology ceiling, V100 reached
2026-05-20), `AEGIS-X-ROADMAP.md` (the 4-layer commodity architecture) and
docs/RESEARCH-2026-05.md (feature-level gap analysis against
14 OSS projects). Every "already there" claim comes with a file reference; everything
partial/opt-in/future is flagged honestly.

---

## 1. Where we are now (the starting point for planning)

`ROADMAP-NEXT.md` records: **V100 reached, Phase A–E feature-complete**
(lines 1–6). The defence stack that the whole plan below builds on is already
in `main`:

| Layer | What is really in the code | Files (examples) |
|---|---|---|
| eBPF/XDP fast-path | deny/allow-set + per-CPU counters + first-byte WAF triage | `xdp/`, `src/xdp.rs` |
| WAF | Aho-Corasick signatures + Sigma corpus + compound rules + webshell | `src/filters/waf.rs`, `src/sigma.rs`, `src/filters/sigma_overlay.rs` |
| TLS fingerprinting | JA3/JA4/JA4H/JA4T (captured in the ClientHello callback) | see [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| Risk engine | `RiskEngineMode { Off, Observe, Enforce }` | `src/config.rs:419`, `src/ddos/risk_engine.rs` |
| ML scoring | LR v1/v2 + GBM + adversarial, online SGD | `src/ddos/ml_score.rs`, `src/ddos/ml_score_v2.rs`, `src/ddos/ml_gbm.rs` |
| Reputation | self-learning JA4 + ASN/CIDR + CrowdSec LAPI + threat intel | `src/ja4_reputation.rs`, `src/proxy/pingora_admin.rs:109` |
| Self-improving sigs | n-gram miner + online miner | `src/signature_mine.rs`, `src/online_signature_miner.rs` |
| Cluster state | shared-mmap arena + AtomicHashMap (Linux) | see [06-workers.md](06-workers.md) |

> **Honest caveat (from `ROADMAP-NEXT.md`, V100 closing notes, lines 315–329):**
> of the 5 items in the "technology-ceiling checklist", three (#1 throughput headline,
> #2 bench vs nginx, #4 bare-metal x86 32c, #5 live edge) are **gated on bench runs
> and hardware, not on code**. In other words the feature base is ready; what is
> unresolved is operational validation. That determines priority #0 below.

---

## 2. Strategic directions

Six directions from the brief. For each: **what is already in the code**, **what is
partial/opt-in**, **what is planned** and **the rationale for the priority**.

### 2.1. Unified risk engine

**Vision.** All signals (WAF verdict, JA4 reputation, anomaly score,
ML inference, rate limit, GeoIP/ASN, honeypot hits) converge into a single
correlating point that takes a decision with transparent explainability,
rather than acting as a set of independent filters.

**What is already there.** The risk engine is instantiated in three modes
(`src/config.rs:419`):

```rust
pub enum RiskEngineMode {
    Off,      // not instantiated, zero cost — safe default
    Observe,  // score is computed + logged, the decision is NOT changed (shadow)
    Enforce,  // score >= threshold escalates an otherwise-Allow request
}
```

The default threshold is conservative — `default_risk_threshold() = 90`
(`src/config.rs`). An Observe-first rollout was introduced (`src/config.rs:394`,
the comment "correlational RiskEngine wiring") with an explicit note: enforcing
prematurely is dangerous, at least a week of Observe data is needed. The ML output
0..100 is already fed into the risk engine as a feature (`src/ddos/risk_engine.rs:67`
— "ML inference output 0..100 from V97 MlScorer").

> **Honest caveat about terminology.** The brief mentions the modes
> `Observe/HighConfidenceEnforce/FullEnforce` — that was the *design-time*
> nomenclature. In the actual code the enum is called `Off/Observe/Enforce`
> (`src/config.rs:419`). When writing scenarios/configs, use the real
> names. `FullEnforce` appears only as a historical reference in the
> comments of the BGP module (`src/bgp_rtbh.rs:10`).

**Planned (direction).** From `ROADMAP-NEXT.md` "Out of scope for V100"
(lines 331–344), in so many words: **hot-path wiring** of the V97 `MlScorer` + V98
`ThreatTier` through `pingora_http` has not been done yet — the data structures are
in place, but the call-site refactor was deliberately kept separate. That is exactly
the nearest piece of work on the unified engine: carry the ML/tier signals through to
the decision point in the pingora hot path, not merely compute them.

From RESEARCH-2026-05.md — two ideas reinforce the unified engine:
- **Composite identity** (Cilium pattern, §2): a stable hash of
  `(JA4 || ASN || cookie || behaviour-fp)` with a TTL, so that decisions survive
  an IP change (NAT/proxy). "Plugs into ThreatScorer naturally".
- **Flowbits/flowints** (Suricata, Top-10 #7): per-connection state,
  so that a rule can express "POST /login → 401 ≥3 times, then GET /admin →
  block" without bespoke code.

**Priority: HIGH.** The engine already exists but mostly runs in Observe;
carrying ML/tier through to the decision is the cheapest way to turn "we compute"
into "we protect".

### 2.2. CRS-like WAF model (paranoia levels / anomaly score / shadow mode)

**Vision.** Move from a flat rule set to a model in the spirit of OWASP CRS:
rules with strictness levels (paranoia), a cumulative anomaly score with a
blocking threshold, and a mandatory shadow mode for safely rolling out new
rules.

**What is already there.**
- **Shadow mode — really works.** A WAF rule with `action: "shadow"` /
  `"log"` only counts hits without changing the verdict (`src/config.rs:807`,
  comment: "shadow first, watches metrics for a week, then flips").
  The Sigma importer automatically maps `low`/`informational` levels to
  `("log", "low", Some("shadow"))` (`src/sigma.rs:568`; test
  `level_low_maps_to_log_shadow` at `src/sigma.rs:1076`). The
  "match-but-don't-act" decision has its own `DecisionKind::Observed`
  (`src/security_event.rs:43`).
- **Anomaly score — partial, at the TLS level.** `anomaly_score()` exists
  for GREASE anomalies (`src/grease_anomaly.rs:42`) and is fed into
  client-consistency scoring (`src/client_consistency.rs:189`). This is **not**
  a CRS-style cumulative score across all WAF rules — for now it is a narrow
  TLS signal.
- **The Sigma corpus and compound rules** are already shipped (`src/sigma.rs`,
  `src/filters/sigma_overlay.rs`, a separate binary `src/bin/aegis-sigma-import.rs`),
  plus webshell signatures (from the latest commit). The compiled rule plan
  (per-field Aho-Corasick) is V95-V96 in `ROADMAP-NEXT.md` (line 309).

**What is partial/planned.**
- **Paranoia levels** as such do not exist in the code — this is a direction. The
  nearest mechanism to hook into: severity/tags on rules + the shadow flag already
  exist, so a paranoia level fits naturally as a filter "activate rules with severity ≤ N".
- **A cumulative anomaly score across the WAF** (the heart of CRS) — an extension of
  the existing scoring: the sum of the weights of triggered rules against a threshold.
- From RESEARCH-2026-05.md, direction A.1 (§Cross-cutting):
  **a macro/list layer over Wirefilter** (Falco-style) is called "the single cheapest
  UX upgrade we can make for ops". That is the infrastructure that makes the CRS model
  convenient for operators.

**Priority: HIGH.** Detection is already at the level of ModSecurity/CrowdSec in breadth
(see the RESEARCH executive summary). What is missing is the *operator model* of
control: paranoia + cumulative score + macro/list DSL. These are ergonomics
that deliver 80% of the value for 10% of the work.

### 2.3. Protocol-level L7 protection (h2/h3)

**Vision.** Protection specific to HTTP/2 and HTTP/3: limits on frame
floods, rapid reset, an h2/h3 abuse guard as a layer in its own right.

**What is already there.**
- **H2 flood limits / abuse guard.** The branch's latest commits are directly about
  this: "sigma compound rules + C3 h2 flood limits" (commit 78294ec) and the Sigma overlay
  with jitter (`src/latency_jitter.rs`). RESEARCH (§14, "We already have")
  confirms the presence of an "H2 abuse guard".
- **HTTP/3 / QUIC** is served through a hyper-handler shim that shares the
  pipeline state (`AEGIS-X-ROADMAP.md`, V46, line 236), with an h3 WAF
  hot-reload poller (V61) and an e2e smoke (V62).

**What is partial/planned (honestly).**
- **H2 frame fingerprint (Akamai-style, `h2_fp`)** — **blocked at the
  pingora-core level**: "needs fork to expose h2 frames" (`AEGIS-X-ROADMAP.md`,
  line 256, marked "by design / blocked"). This is a known limitation,
  not a bug. The strategy (Risks table, line 366): keep the capture in XDP/eBPF,
  pingora only reads it.
- **HTTP/3 server push** is deliberately NOT in the plan — deprecated in the RFC
  (`ROADMAP-NEXT.md`, "What is NOT in the plan", line 174).
- **gRPC**: we do not build gRPC-specific handling — "pingora handles this already
  generically" (`ROADMAP-NEXT.md`, line 176). See also §2.5 on API guards.

**Priority: MEDIUM.** Basic h2 flood limits are there; protocol depth
(frame fp) runs into an upstream dependency, so it is developed through XDP
rather than through a pingora fork.

### 2.4. Session and device reputation

**Vision.** Reputation not only by IP/JA4, but by "device"/"session" — a
composite stable identity that survives an IP change.

**What is already there.**
- **Self-learning JA4 reputation** — enabled by default
  (`src/proxy/pingora_admin.rs:109`: "reputation feeds now ON by default
  (self-learning JA4 + ...)"; `src/ja4_reputation.rs` maintains a `learned` counter).
  Self-learning sources: honeypot/WAF/tarpit. Also on by default are ASN/CIDR
  (Tor/Spamhaus), CrowdSec LAPI, threat intel (see [12-reputation.md](12-reputation.md)).
- **Device/passive-fp signals**: p0f-style TTL observations (`src/p0f.rs:291`),
  UA-vs-JA4 mismatch (`src/filters/ua_fp_mismatch.rs`), client consistency
  (`src/client_consistency.rs`). This is the raw material for "device reputation".

**What is partial/planned.**
- **Composite identity** (the Cilium idea, RESEARCH-2026-05.md §2):
  "today we operate on `(IP, ASN, JA4, cookie)` individually. A composite
  identity type — a stable hash with a TTL — would let per-endpoint policies match
  on identity, surviving NAT/proxy IP changes". This is precisely the bridge from
  "fingerprint reputation" to "session/device reputation".
- **A typed IntelStore with provenance** (Zeek/Suricata `datarep`,
  Top-10 #5/#6): today threat intel is "a flat IP/CIDR set" (RESEARCH,
  "Directions still empty", item 5). The plan is typed sets
  (`IP/CIDR/JA4/SHA256/...`) with `(source, confidence, first/last_seen)` and an
  `in_set(name, rep>=N)` operator, so that reputation is not binary.

**Priority: MEDIUM-HIGH.** Self-learning JA4 already delivers most of the
value. Composite identity is the next lever against IP rotation, but it
requires careful handling of TTL and cardinality (LRU cap).

### 2.5. API guards (REST / JWT / GraphQL / gRPC)

**Vision.** Specialised guards for modern APIs: JWT validation,
limiting GraphQL depth/complexity, gRPC protection.

**What is already there (honestly — GraphQL only).**
- **A GraphQL guard** really exists and is wired in: `src/filters/graphql.rs`
  (`GraphqlFilter`, `GraphqlConfig`), registered in `src/server.rs:283`.
  Not a full parser, for cost/dependency reasons
  (`src/filters/graphql.rs:3`); the strongest protection is **persisted query hashes**
  (`persisted_hashes`, `src/filters/graphql.rs:31`, "Strongest GraphQL DDoS
  defence").

**What does NOT exist yet (a direction, not an implementation).**
- **JWT guard** — there is no separate JWT validation/inspection filter in `src/filters/`
  (of the API guards, the directory contains only `graphql.rs`). This is a plan.
- **gRPC guard** — there is deliberately no gRPC-specific handling (see §2.3:
  "pingora handles generic").
- **REST guard** — covered by the general WAF + per-endpoint policy
  ([26-sites-and-domains.md](26-sites-and-domains.md)); there is no separate
  REST-aware guard as a module.

**Hooks for the plan.** Per-domain/per-endpoint policy and the actuator direction
(see §2.6) are the natural base: JWT claims as rule selectors (RESEARCH §4,
Tracee: "if event.jwt_role ... and event.path starts_with /admin: block").

**Priority: MEDIUM.** GraphQL is covered (the most common DDoS vector for APIs).
A JWT guard is the next obvious step; REST/gRPC are covered by the general pipeline.

### 2.6. A closed feedback loop from production traffic

**Vision.** Attacks caught by the honeypot/tarpit/WAF automatically improve the
defence: they retrain the ML, generate signatures, raise the reputation score.

**What is already there.**
- **Honeypot → ML feedback.** `src/robots_honeypot.rs:10`: "V149 wires that
  signal into the V135 MlTrainer feedback loop". Online ML retraining is V123
  (`src/ddos/ml_score_v2.rs:14`, "operator-driven feedback"), online SGD
  (`src/ddos/ml_score.rs`).
- **Self-improving signatures.** The n-gram miner (`src/signature_mine.rs`) +
  the online miner (`src/online_signature_miner.rs`), with a background run in
  `src/proxy/pingora_background.rs` (lines 68/233/412). The admin route
  `POST /admin/signature_mine` (`src/admin_auth.rs:187`, role `Write`).
- **Self-learning reputation** (§2.4) — the same loop: honeypot/WAF/tarpit
  feed JA4 reputation.

**What is partial/planned (honestly).**
- **No write-back by design.** V99 (`ROADMAP-NEXT.md`, line 312): the miner
  does "intentional no-write-back (operator promotes manually)". That is, the
  loop is for now **half-closed**: candidates are mined automatically, but it is
  the operator who promotes them to production. Full automation (with an approval
  pipeline for low-confidence candidates) is direction E.4 (`ROADMAP-NEXT.md`, lines 158–162).
- **Online tarpit-log → miner automation** — in "Out of scope for V100"
  (`ROADMAP-NEXT.md`, line 343): "currently corpus is supplied per admin
  request".
- **Hunt jobs** (Arkime, RESEARCH §8): a background re-scan of the last N hours
  of events with new rules — "catches signatures we just learned against
  attacks that already happened". A logical extension of the feedback loop.

**Priority: HIGH (differentiator).** RESEARCH explicitly calls
self-improving signature mining a unique feature that none of the
OSS proxies have (`ROADMAP-NEXT.md`, lines 346–354). Closing the last mile
(controlled auto-promote) is a big strategic win.

---

## 3. Summary priority matrix

Ranked by ROI (grounded in the RESEARCH Top-10 gap analysis + the state of the code).

| # | Direction | State in the code | Priority | Rationale |
|---|---|---|---|---|
| 0 | **Operational validation** (bench sweep + bare-metal 32c + live edge) | gated on hardware/runs | **CRITICAL** | 3 of 5 ceiling items are waiting not on code but on validation (`ROADMAP-NEXT.md` 315–329) |
| 1 | Unified risk engine: hot-path wiring of ML/tier | structures exist, call site does not | HIGH | cheapest of all: from "we compute" to "we protect" (out-of-scope V100, 331–344) |
| 2 | Sigma importer (extension) + macro/list DSL over Wirefilter | Sigma import exists; DSL does not | HIGH | "whole detection ecosystem" + "cheapest UX upgrade" (RESEARCH Top-10 #1, §A.1) |
| 3 | Leaky-bucket scenario DSL (CrowdSec-style) | rate limiting is flat | HIGH | "10 distinct 4xx URIs from one IP in 10s" = 7 lines of YAML instead of code (Top-10 #2) |
| 4 | Actuator registry + revert timers | actions are hardcoded | HIGH | unblocks integrations; loop §2.6 (Top-10 #4) |
| 5 | Feedback loop: controlled auto-promote of signatures | half-closed | HIGH | a unique differentiator (`ROADMAP-NEXT.md` 346–354) |
| 6 | Composite identity (session/device reputation) | signals exist, identity does not | MEDIUM-HIGH | survives IP rotation (RESEARCH §2) |
| 7 | Typed IntelStore + `datarep` reputation | flat IP/CIDR set | MEDIUM | reputation stops being binary (Top-10 #5/#6) |
| 8 | CRS model: paranoia + cumulative anomaly score | shadow exists, paranoia does not | MEDIUM | the operator model for controlling the WAF (§2.2) |
| 9 | API guards: JWT guard | GraphQL only | MEDIUM | GraphQL is covered; JWT is the next vector (§2.5) |
| 10 | Flowbits/flowints (multi-stage) | rules are per-request | MEDIUM | correlation without bespoke state (Top-10 #7) |
| 11 | File carving + YARA pipeline | ClamAV TCP only | MEDIUM | a "10x detection upgrade" but effort L (Top-10 #3) |
| 12 | Protocol-level h2_fp depth | blocked on pingora-core | LOW | upstream dependency; we work around it via XDP (§2.3) |

---

## 4. Rationale for the strategy as a whole

**The differentiation principle (`AEGIS-X-ROADMAP.md`, lines 6–11).** Excel
not by the number of features, but by a **unique combination** that nobody in the
OSS world has: XDP fast-path + user-space WAF with a compiled plan + per-IP ML + threat-aware
tiered cache + cluster shared-mmap integrity + self-improving sigs. No single
open-source proxy covers this entire scope at once
(`ROADMAP-NEXT.md`, lines 346–354). The development strategy = **deepen the
combination and its ergonomics**, rather than catching up with competitors on raw speed.

**Honest caveat about performance.** AEGIS does NOT claim to be faster than
real proxies on raw speed. The AEGIS bench lanes are an in-process engine,
not the full pingora binary; the hardware SHA bench per core is low inside a VM without
hardware SHA acceleration (in which case the capacity forecast is pessimistic). The project's
strong argument is the **security matrix**, not RPS. The performance ceiling
(`ROADMAP-NEXT.md`, condition #1, lines 355–356) is limited by hardware, not by
features — which is why priority #0 is operational rather than code-related. Details in
[27-performance-tuning.md](27-performance-tuning.md),
[28-benchmarking.md](28-benchmarking.md).

**Why ergonomics (DSL/macro/scenario) is the top priority.** The RESEARCH
executive summary: AEGIS detection is already at or above the level of ModSecurity/CrowdSec/
Suricata in breadth; we lead on the JA4 matrix, the ML pipeline and honeypot breadth
(§B "Where we already lead"). The single systematic hole against
*all* 14 projects is the absence of a declarative DSL layer over the engine
(§A.1, §C.1). That is why the "next sprint" in RESEARCH is mostly DSL/
adapters (Sigma, scenarios, actuators) rather than new detectors.

**What we deliberately do NOT do** (`ROADMAP-NEXT.md`, lines 166–177):

| Not doing | Why |
|---|---|
| Full monoio swap | requires forking pingora-core, maintenance burden |
| XDP_REDIRECT to upstream | not viable for a TLS-terminating proxy (no DSR) |
| AF_XDP zero-copy receive | means rewriting the TCP layer, niche |
| WASM filters | overlaps with the existing Lua plugins ([31-plugins.md](31-plugins.md)) |
| HTTP/3 server push | deprecated in the RFC |
| gRPC proxy specifics | pingora handles generic |
| Community-consensus blocklist | needs users at scale (RESEARCH §13) |

---

## 5. Phase sequence (from the ROADMAP sources)

The historical ladder of `ROADMAP-NEXT.md` (V77 → V100) shows the completed
blocks; the future consists of extensions within the same layers of `AEGIS-X-ROADMAP.md`.

```
Phase A — XDP        ✅ partial (counters + WAF; XDP_REDIRECT not for a TLS proxy)
Phase B — Pingora    ✅ done (V72; ~770k stable — top end of target)
Phase C.2 — WAF AC   ✅ done (V76; overhead 10%→2%)
Phase C.3 — headers  ✅ done (V78-V79; cache fast-path before build_ctx)
Phase C.1 — io_uring ⏳ V83-85 not started (tokio-uring, gated, +15-25% expected)
Phase D — mmap state ✅ V86-V89; ⏳ V90 scorer-migration not started
Phase E — JIT+ML     ✅ feature-complete (V91-V100), but hot-path wiring deferred
```

**The nearest correct step** (`ROADMAP-NEXT.md`, lines 326–329): a bench sweep
on the Aegis-Proxy-dev rig (Bench A vs nginx, Bench C distributed-attacker),
then an i9-9900K native-Linux dual boot for the 32c figure. That closes
ceiling-checklist items 1/2/4, after which comes item 5 (a live edge).

**Definition of "technology ceiling"** (`ROADMAP-NEXT.md`, lines 196–211):
stop feature development once **4 of 5** conditions are met, and move to a phase of
"maintenance + operator UX polish + docs". For the current status against the checklist —
see 42-текущее-состояние-STATUS.md.

---

## 6. What is needed from the operator

From `ROADMAP-NEXT.md` (lines 215–231), adapted to the current status:

1. **Bench validation** on the rig after changes in the hot path (Bench A vs nginx,
   Bench C distributed-attacker) — see [28-benchmarking.md](28-benchmarking.md).
2. **A final bench on bare-metal x86 32c** (i9-9900K native Linux dual boot
   or cloud Hetzner/OVH) — once, giving honest production-class figures
   (closes ceiling #4).
3. **Production validation on a real edge** (live traffic, not a bench) —
   closes ceiling #5; the only item that cannot be obtained in the lab.
4. **Observe-first for the risk engine and the WAF.** Before `Enforce` — at least a week
   of `Observe`/shadow data (`src/config.rs:404`); watch the metrics
   ([25-metrics-telemetry.md](25-metrics-telemetry.md)), then flip.

---

## 7. Related documents

- [40-roadmap.md](40-roadmap.md) — the tactical plan by release
- 42-текущее-состояние-STATUS.md — a status snapshot
- [10-waf.md](10-waf.md) · [18-ml-risk-engine.md](18-ml-risk-engine.md) ·
  [12-reputation.md](12-reputation.md) · [11-tls-fingerprinting.md](11-tls-fingerprinting.md)
- [13-xdp-ebpf.md](13-xdp-ebpf.md) · [17-honeypot-tarpit.md](17-honeypot-tarpit.md) ·
  [21-arsenal-scenarios.md](21-arsenal-scenarios.md) · [22-enrichment.md](22-enrichment.md)
- [23-security-model.md](23-security-model.md) — the project's strongest argument
- [30-admin-api.md](30-admin-api.md) — routes such as `POST /admin/signature_mine`
- Strategy sources: `ROADMAP-NEXT.md`, `AEGIS-X-ROADMAP.md`,
  RESEARCH-2026-05.md
