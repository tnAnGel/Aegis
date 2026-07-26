# Testing

**Languages:** **English** · [Русский](../ru/43-testing.md) · [中文](../zh/43-testing.md)

This document describes the AEGIS testing strategy: how the tests are organised and how many there are (≈1485 functions), how to run them (`cargo test`, the `pingora`/`xdp` feature flags, filtering by library), and the purpose and invocation of the e2e binaries — the load harness `aegis-e2e`, the pingora smoke `aegis-pingora-e2e`, the sqlmap replay `aegis-sqlmap-replay` and the distributed `aegis-distbench`. Every statement is tied to real code; partial/opt-in coverage is flagged honestly.

See also: [28-benchmarking.md](28-benchmarking.md) (performance, the separate `aegis-bench` tool), 42-текущее-состояние-STATUS.md, [10-waf.md](10-waf.md), [21-arsenal-scenarios.md](21-arsenal-scenarios.md).

---

## 1. Testing layers

AEGIS uses three layers of tests that complement each other:

| Layer | Where it lives | What it checks | How it is run |
|------|-----------|---------------|-----------------|
| Unit tests | inline modules `#[cfg(test)] mod tests` inside `src/**.rs` | the logic of individual modules (parsers, scorers, normalisation, state machines) | `cargo test --lib` |
| Integration | `tests/integration.rs`, `tests/arsenal_integration.rs` | the end-to-end proxy pipeline and the wiring of the Defence Arsenal through the library's public entry points | `cargo test --test integration --test arsenal_integration` |
| E2E binaries | `src/bin/aegis-e2e.rs`, `src/bin/aegis-pingora-e2e.rs`, `src/bin/aegis-sqlmap-replay.rs`, `src/bin/aegis-distbench.rs` | the behaviour of a real AEGIS process (or processes) on real sockets | `cargo build --release --bin <name>`, then run the binary |

In total the repository has about **1485** test functions (`#[test]` + `#[tokio::test]`): ≈**1453** in `src/` (unit) and **32** in `tests/` (integration). Inline `mod tests` blocks are present in roughly **140** files under `src/`.

> The count is taken from the `#[test]`/`#[tokio::test]` markers in the sources: `grep -rn '#\[test\]\|#\[tokio::test\]' src/ tests/ | wc -l`. The number is a snapshot of the current state of the branch and changes along with the code.

---

## 2. How to run the tests

### 2.1. Basic run

```bash
# Full set: unit + integration + doctests + compilation of all binaries/examples
cargo test --all-targets

# Unit tests only (fast; without the integration binaries)
cargo test --lib

# A specific integration file
cargo test --test integration
cargo test --test arsenal_integration
```

Just as CI does it (`.github/workflows/ci.yml`, job `test`): `cargo check --all-targets` → `cargo clippy --all-targets -- -D warnings` → `cargo test --all-targets`. CI runs on `ubuntu-latest` and `macos-latest`, plus a separate `fmt` job (`cargo fmt --all -- --check`). `RUSTFLAGS: "-D warnings"` is enabled globally, so any compiler warning fails the build.

### 2.2. Filtering tests (`--lib` + patterns)

`cargo test` accepts a substring of the test name as a filter. This is especially useful with `--lib`, to run only the subsystem you need:

```bash
# All WAF tests (module src/filters/waf.rs — the largest set, ~78 tests)
cargo test --lib waf

# SQL semantics only
cargo test --lib sql_semantic

# Privacy Pass
cargo test --lib privacy_pass

# One specific test by the full module::function name
cargo test --lib filters::waf::tests::sqli_signature_matches

# List what would run, without executing
cargo test --lib waf -- --list
```

Useful test-harness flags (after `--`):

| Flag | Purpose |
|------|------------|
| `-- --nocapture` | do not swallow the tests' `println!`/stdout |
| `-- --test-threads=1` | sequential run (for tests sensitive to the environment) |
| `-- --ignored` | run tests marked `#[ignore]` |
| `-- --list` | print the list of tests without executing them |

### 2.3. Feature flags

By default tests compile with `default = []` (see `[features]` in `Cargo.toml`). Two optional features require explicit enabling:

```bash
# Pingora data plane (pulls in openssl/pingora-* — a large dependency tree)
cargo test --features pingora --all-targets

# XDP/eBPF fast-path (Linux-only; the runtime needs CAP_BPF + CAP_NET_ADMIN,
# but compilation/unit tests work without privileges too)
cargo test --features xdp --all-targets
```

CI reflects this with separate jobs: `xdp-feature` (`cargo test --features xdp --all-targets` on Linux) and `bpf-program` (building the eBPF object `aegis-xdp` on nightly via `bpf-linker`). Tests specific to the pingora path (for example `src/proxy/pingora_http.rs` ~26, `src/proxy/pingora_challenge.rs` ~28) compile only under `--features pingora`.

> Honest caveat: the e2e binary `aegis-pingora-e2e` is entirely locked behind `#![cfg(feature = "pingora")]` (`src/bin/aegis-pingora-e2e.rs:18`) — without the feature it compiles into a stub and checks nothing.

---

## 3. Pipeline integration tests (`tests/integration.rs`)

These are end-to-end tests of the proxy handler. Each test brings up a **real upstream** on a free TCP port (`spawn_mock_upstream`, one tokio task per test) and calls `ProxyHttpHandler::handle_collected` directly, driving the full pipeline (distributed checks → WAF → bot → adaptive → rate limit → challenge → forward to upstream) over real sockets, without bringing up the public listeners.

The helper `build_handler(...)` assembles a handler with a predictable configuration: the filter chain `IpAcl → Waf → Bot → Adaptive → Challenge → RateLimit` (`FilterEngine::new(..., DefaultAction::Allow)`), `NoopXdp`, `NoopGeoIp`, a temporary `HoneypotStore` in `temp_dir`, default `AnomalyDetector`, `DynamicTrustConfig`, `ResponseCacheConfig`.

Scenarios covered (`#[tokio::test]`):

| Test | Assertion |
|------|-------------|
| `upstream_passthrough_returns_body` | a clean GET reaches the upstream, the body is returned, the upstream got 1 hit |
| `waf_sqli_signature_blocks_before_upstream` | a URL-encoded `UNION SELECT` in the query → `403 FORBIDDEN`, the body contains `sqli`, the upstream is **not** touched |
| `ip_acl_deny_short_circuits` | an IP from the deny list → `403`, with no hit on the upstream |
| `rate_limit_returns_429_after_burst` | with `burst=2` the first two requests pass, the third → `429 TOO_MANY_REQUESTS` |
| `challenge_ladder_emits_set_cookie_and_step_header` | the first rung of the ladder → `307`, headers `location`, `x-aegis-step: headers`, `Set-Cookie: aegis_token=...; HttpOnly` |
| `challenge_cookie_round_trip_passes_to_upstream` | a repeat with a valid `aegis_token` → `200` + forwarding to the upstream |
| `waf_body_inspection_catches_signature_in_payload` | SQLi in a POST body → `403`, the upstream is not touched |
| `waf_body_size_limit_returns_413` | a 4096 B body with `max_body_bytes=1024` → `413 PAYLOAD_TOO_LARGE` |
| `upstream_unavailable_returns_502` | a dead upstream → `502 BAD_GATEWAY` |
| `fingerprint_cookie_short_circuits_challenge` | a POST to `/__aegis/verify?...&fp=...` sets `aegis_token` + `aegis_fp`; a long-lived `aegis_fp` on its own bypasses the ladder |
| `verify_endpoint_with_invalid_token_rejects` | `/__aegis/verify` with a forged token → `403` |

Running:

```bash
cargo test --test integration
cargo test --test integration challenge      # challenge scenarios only
```

---

## 4. Defence Arsenal integration (`tests/arsenal_integration.rs`)

Purpose (V194, see the file header): to prove that the Defence Arsenal modules really do "move" the counters when called from the same library entry points as the proxy hot path. If these tests fail, the wiring in `src/bin/aegis-pingora.rs` produces dead state, and any claims about "live counters" turn out to be a lie. The tests do NOT bring up an HTTP server; they call `ArsenalState` and the related modules directly.

Modules and invariants covered:

| Test | Module / API | What it checks |
|------|--------------|----------------|
| `ja4_corpus_lookup_bumps_counter` | `ja4_corpus` | a lookup by JA4 string returns a verdict, the counters `ja4_corpus_lookups`/`ja4_corpus_allow_hits` grow |
| `ja4_churn_observe_tracks_ip` | `ja4_churn` | JA4 rotation on a single IP produces high churn (>0.9) |
| `h2_observe_bucket_consumes_and_rejects` | `observe_h2_frame` / `h2_budget` | the HTTP/2 frame budget (RST_STREAM) admits ~40–60 out of 120 and rejects the rest; the counters `h2_budget_allows`/`rejects` are exact |
| `rule_plan_install_and_dispatch_round_trip` | `rule_planner::RulePlan` | installing a plan and dispatching by phase (`RequestUriOrQuery`, `RequestHeaders`) |
| `waf_rule_descriptors_translate_to_planner_phases` | `WafFilter::rule_descriptors` | custom + built-in rules are laid out across the URI/headers/body phases |
| `honeypot_responder_returns_synth_with_counter` | `honeypot_respond` | a synthetic response + growth of `llm_honeypot_responses` or `yaml_honeypot_engagements` |
| `bgp_rtbh_announce_then_withdraw` | `bgp_rtbh` | announce/withdraw change the size and the counters `bgp_rtbh_announces`/`withdraws` |
| `grease_extract_parses_chrome_shaped_handshake` | `ja4::extract_grease_positions` | parsing a synthetic ClientHello with GREASE at position 0 |
| `route_difficulty_ai_scraper_ua_bumps` | `route_difficulty` | the UA `GPTBot` raises the challenge difficulty relative to a browser UA |
| `decoy_headers_produce_cloudflare_shape` | `decoy_headers` | the Cloudflare family yields `server`, `cf-ray`, `alt-svc` |
| `sicherheitstacho_renders_valid_ndjson` | `sicherheitstacho` | correct NDJSON for SIEM with the fields `category`, `src_ip`, `request` |
| `latency_jitter_distribution_sensible` | `latency_jitter` | the default tarpit jitter is centred around ~200–900 ms |
| `timing_entropy_flags_synthetic` | `timing_entropy` | uniform mouse/scroll intervals → a high `anomaly_score` |
| `normalisation_chains_url_html` | `normalisation` | the URL→HTML decoding chain restores `<script>` |
| `param_profile_anomaly_after_training` | `param_profile` | after training on 6-digit numbers, `<script>` is scored as anomalous |
| `actuator_registry_applies_and_reverts_via_arsenal` | `actuator` | `XdpDeny` is applied and auto-reverted by TTL via `tick()` |
| `enrichment_facade_aggregates_two_sources` | `enrichment` | aggregation of two sources: `Deny` dominates, `sources.len()==2` |
| `scenario_engine_fires_block_after_capacity_via_arsenal` | `scenarios` | the YAML scenario `brute_login` fires (`Fired`) once `capacity` is exhausted |
| `arsenal_counters_include_new_module_fields` | `counters::snapshot` | the shape contract of the counters struct (the fields compile) |
| `sigma_imported_toml_loads_through_waf_rule_file_parser` | `config::WafRule` | the imported `rules/sigma/sigma-webserver.toml` loads as `rule_files` (>100 rules, ≥2 severity levels); **the test skips** if the file has not been generated locally |
| `sql_semantic_with_normalisation_catches_doubled_encoded` | `sql_semantic` | double URL-encoded SQLi (`%2527...`) accumulates a high score |

Running:

```bash
cargo test --test arsenal_integration
```

> Caveat about `sigma_imported_toml_*`: `rules/sigma/sigma-webserver.toml` is a generated artefact (see the `aegis-sigma-import` binary). If it is absent, the test quietly does a `return` and counts as passed while checking nothing. For the test to actually validate something, the corpus must be generated beforehand.

---

## 5. E2E binaries

The e2e harnesses are shipped as separate binaries in `src/bin/` rather than as `#[test]` functions, because they spawn real AEGIS processes and/or require host network configuration. They must first be built (usually in `--release`), then run.

### 5.1. `aegis-e2e` — the load harness (hyper binary)

`src/bin/aegis-e2e.rs` spawns a **real `aegis` process** against a mock upstream and drives every major gate, checking simultaneously (a) the observable HTTP statuses and (b) the deltas of the `aegis_*` counters scraped from `/metrics`. A silent halt in metrics emission fails the build just as loudly as a WAF rule that lets an attack through. It is designed for CI: bounded time (~30 s), everything on `127.0.0.1`, no external dependencies (no Redis/GeoIP), no timing flakiness.

Arguments (`clap`):

| Flag | Default | Purpose |
|------|--------------|------------|
| `--aegis-binary` | `target/release/aegis` | path to the binary under test |
| `--config-template` | `bench/e2e-config.toml` | config template with placeholders |
| `--startup-timeout-secs` | `10` | how long to wait for AEGIS to be ready |
| `--dump-metrics` | (flag) | print the full `/metrics` even on success |

The config template `bench/e2e-config.toml` is patched on the fly: `__AEGIS_LISTEN__`, `__ADMIN_LISTEN__`, `__UPSTREAM_URL__`. In it, the WAF and rate limiting are enabled (`requests_per_second = 5`, `burst = 5`, `max_body_bytes = 4096`), while challenge/bot/adaptive are disabled so that the WAF and rate-limit scenarios are not intercepted by unrelated escalation; `header_read_timeout_ms = 1000` is needed by the Slowloris scenario. The admin token is passed via `AEGIS_ADMIN_TOKEN=e2e-admin-token`.

Scenarios verified (an extract from `run_scenarios`):

1. `baseline_passthrough` — ≥3 `200` responses, the upstream got ≥3 hits;
2. `waf_sqli_query_blocked` — 5×`403` on SQLi in the query;
3. `waf_xss_query_blocked` — 5×`403` on XSS in the query;
4. `waf_body_sqli_blocked` — SQLi in a POST body → `403`;
5. `waf_body_size_413` — a 16 KB body with a 4 KB limit → `413`;
6. `ip_acl_loaded_without_self_lock` — deny `198.51.100.99` is loaded, but `127.0.0.1` is not blocked;
7. `rate_limit_burst` — out of 50 parallel requests ≥10 get `429`;
8. `slowloris_connection_killed` — an unfinished request is torn down within `header_read_timeout`;
9. `admin_unauth_rejected` — a wrong `x-admin-token` → `401`;
10. `admin_authorized_passes` — the correct token → `200`;
11. `admin_read_endpoints_alive` — `/admin/threats`, `/admin/xdp`, `/admin/hot_uris`, `/admin/anomaly` answer `200`;
12. Metrics regression — deltas `aegis_requests_total > 0`, `aegis_requests_denied > 0`, the presence of `aegis_request_latency_ms_count` and of the `aegis_requests_by_protocol` series.

Running (as in the CI job `e2e-load`):

```bash
cargo build --release --bin aegis --bin aegis-e2e
./target/release/aegis-e2e \
    --aegis-binary ./target/release/aegis \
    --config-template bench/e2e-config.toml \
    --dump-metrics
```

A non-zero exit code means at least one scenario failed (the list is printed under `=== scenario results ===` marked `FAIL`).

### 5.2. `aegis-pingora-e2e` — the pingora data plane smoke

`src/bin/aegis-pingora-e2e.rs` (V64) mirrors `aegis-e2e` in shape but targets the openssl backend of the `aegis-pingora` binary. The whole file is under `#![cfg(feature = "pingora")]`. It spawns a real `aegis-pingora` against an in-process mock upstream and writes a temporary config in an nginx-like DSL format (blocks `admin { ... }`, `defaults { ... }`, `server { ... }`); the honeypot state path is passed via `AEGIS_HONEYPOT_STATE`, and the response cache is turned on with `AEGIS_RESPONSE_CACHE_ENABLE=1`.

Arguments: `--binary` (default `target/release/aegis-pingora`), `--aegis-port`/`--admin-port`/`--upstream-port`, `--admin-token`, `--startup-secs`.

Tests (`run_tests`):

| № | Check |
|---|----------|
| 1 | plain GET → `200`, the body contains `ok` |
| 2 | WAF path traversal `/../../etc/passwd` → `403`, the body contains `blocked` |
| 3 | `/metrics` is public (`200`) and contains `aegis_requests_total` |
| 4 | `/admin/cache` without a token → `401` |
| 5 | `/admin/cache` with a wrong token → `401` |
| 6 | `/admin/cache` with the correct token → `200`, the body contains `cache_hits` |
| 7 | `/health` → `200`, the body starts with `ok` |
| 8 | two identical GETs → the counters `aegis_cache_hits`/`aegis_cache_misses` are non-zero |
| 9 | `POST /admin/cache/purge?all=1` with a token → `200` |
| 10 | `POST /admin/api/config/test` with a valid config → `ok:true` |
| 11 | `POST /admin/api/config/test` with a broken config → `ok:false` |
| 12 | `POST /admin/api/sites` with broken JSON → `400` |
| 13 | `POST /admin/api/honeypots/packs/wordpress {"enabled":false}` → `200`, `ok:true` |

Running (see the file header):

```bash
cargo build --release --features pingora --bin aegis-pingora
cargo build --release --features pingora --bin aegis-pingora-e2e
./target/release/aegis-pingora-e2e
```

On success it prints `PASS: aegis-pingora end-to-end smoke green`; on failure — `FAIL: ...` and `exit(1)`.

### 5.3. `aegis-sqlmap-replay` — the WAF bypass matrix

`src/bin/aegis-sqlmap-replay.rs` (V118): the operator points the tool at a running AEGIS (or any URL), and it replays an SQLi payload raw AND after each sqlmap-equivalent tamper, printing a coverage matrix. A line marked `! BYPASSED` is a hole in the WAF: the tamper variant returned something other than `403`. This is NOT a full port of sqlmap; roughly 12–15 of the most commonly used tampers from sqlmap's `tamper/` catalogue are implemented.

Arguments: `--target` (default `http://127.0.0.1/`; the payload is appended as `?q=<payload>`), `--payload` (default `union select 1,2,3 from users`), `--chain` (a comma-separated list of tampers, applied on top of each iteration — like `--tamper` in sqlmap), `--timeout-secs`.

Tampers implemented (the `tampers` array): `space2comment`, `space2morecomments`, `space2dash`, `space2hash`, `space2plus`, `randomcase`, `backticks`, `htmlencode_dec`, `htmlencode_hex`, `charencode`, `chardoubleencode`, `versionedkeywords`, `appendnullbyte`, `equaltolike`, `apostrophenullencode`.

Verdict logic: `403` → `OK`; any other status → `! BYPASSED`; a request error → `! ERROR`. If there is at least one bypass, the process exits with `exit(2)`.

```bash
cargo build --release --bin aegis-sqlmap-replay
./target/release/aegis-sqlmap-replay --target http://127.0.0.1:8080/

# With a tamper chain (like sqlmap --tamper)
./target/release/aegis-sqlmap-replay \
    --target http://127.0.0.1:8080/ \
    --chain space2comment,htmlencode_hex,backticks
```

> This is a tool for checking a **deployed** instance, not a unit test. It shows the real coverage of exactly the WAF configuration it is pointed at. See [10-waf.md](10-waf.md).

### 5.4. `aegis-distbench` — a distributed attack simulator

`src/bin/aegis-distbench.rs` (V105): the pingora listener sees the peer address from `accept()`, i.e. the source IP of the connection. By aliasing loopback to `127.0.0.2 .. 127.0.0.{N+1}` and binding each connection to its own alias, one can simulate N attackers against a single AEGIS without PROXY-protocol support on the listener. Each "source" gets its own hyper client whose `HttpConnector` binds the outgoing TCP to its own IP (`set_local_address`) — that is exactly what makes the AEGIS per-IP scorer see distinct attackers.

Arguments: `--target` (required), `--sources` (default 50), `--requests-per-source` (200), `--concurrency-per-source` (4), `--path` (default `/?q=union+select+1` — will hit the WAF if it is enabled), `--timeout-secs` (60). Output: total RPS, the status distribution (`200`/`403`/errors), bytes received.

Precondition on Linux — create the aliases in advance:

```bash
for i in $(seq 2 51); do sudo ip addr add 127.0.0.$i/8 dev lo; done

cargo build --release --bin aegis-distbench
./target/release/aegis-distbench \
    --target http://127.0.0.1:8080/ \
    --sources 50 --requests-per-source 200 --concurrency-per-source 4
```

> This is a load/behavioural rig for checking cross-worker aggregation and per-IP scoring (the file header suggests looking at `/admin/threats` after a run), not a pass/fail test. For more on load methodology and honest caveats about capacity — [28-benchmarking.md](28-benchmarking.md).

---

## 6. Coverage by subsystem

The distribution of unit tests across `src/` modules (a snapshot; counted by `#[test]`/`#[tokio::test]`). The most densely covered areas are the hot-path gates and the parsers:

| Subsystem / file | ≈ tests | Document |
|-------------------|----------|----------|
| `src/filters/waf.rs` | ~78 | [10-waf.md](10-waf.md) |
| `src/proxy/response_cache.rs` | ~47 | [27-performance-tuning.md](27-performance-tuning.md) |
| `src/ml_adversarial.rs` | ~40 | [18-ml-risk-engine.md](18-ml-risk-engine.md) |
| `src/challenge_signals.rs` | ~40 | [15-challenge-ladder.md](15-challenge-ladder.md) |
| `src/domain_policy.rs` | ~29 | [26-sites-and-domains.md](26-sites-and-domains.md) |
| `src/real_ip.rs` | ~28 | [07-protocols.md](07-protocols.md) |
| `src/proxy/pingora_challenge.rs` | ~28 (under `pingora`) | [15-challenge-ladder.md](15-challenge-ladder.md) |
| `src/proxy/pingora_http.rs` | ~26 (under `pingora`) | [02-architecture.md](02-architecture.md) |
| `src/proxy/http.rs` | ~25 | [02-architecture.md](02-architecture.md) |
| `src/sql_semantic.rs` | ~23 | [10-waf.md](10-waf.md) |
| `src/filters/login_abuse.rs` | ~23 | [14-rate-limiting.md](14-rate-limiting.md) |
| `src/filters/graphql.rs` | ~23 | [10-waf.md](10-waf.md) |
| `src/sigma.rs` | ~20 | [10-waf.md](10-waf.md) |
| `src/client_consistency.rs` | ~20 | [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| `src/site_map.rs` | ~18 | [26-sites-and-domains.md](26-sites-and-domains.md) |
| `src/privacy_pass.rs` | ~18 | [16-privacy-pass.md](16-privacy-pass.md) |
| `src/poisoned_tarpit.rs` | ~18 | [17-honeypot-tarpit.md](17-honeypot-tarpit.md) |
| `src/p0f.rs` | ~17 | [11-tls-fingerprinting.md](11-tls-fingerprinting.md) |
| `src/normalisation.rs` | ~17 | [10-waf.md](10-waf.md) |
| `src/honeypot/matcher.rs` | ~17 | [17-honeypot-tarpit.md](17-honeypot-tarpit.md) |

Aggregates for the larger module families (search by test-name substring, convenient for `cargo test --lib <substring>`):

| Family (pattern) | ≈ tests |
|---------------------|----------|
| `filters` (the whole `src/filters/` directory) | ~240 |
| `ml` (ML risk engine + adversarial) | ~105 |
| `waf` (by name substring) | ~86 |
| `challenge` (ladder + signals) | ~79 |
| `ja4` (fingerprinting) | ~48 |
| `reputation` | ~25 |
| `rate_limit` | ~15 |
| `ja3` | ~6 |

> The numbers are approximate snapshots and fluctuate with edits. The authoritative way to get the current figure for a subsystem is `cargo test --lib <pattern> -- --list`.

Coverage beyond the unit level:

- **Not covered by automated tests in a strict pass/fail mode:** the XDP/eBPF kernel fast-path under load (the `--features xdp` tests check compilation and the loader's logic, but not real BPF attachment — that requires privileges and a NIC), BGP RTBH through a real ExaBGP (in `arsenal_integration` only in-memory announce/withdraw is checked), external integrations (Redis rate limit, CrowdSec LAPI, threat intel, GeoIP databases) — the e2e harnesses deliberately work without them.
- **Covered only through a deployed instance (opt-in tools):** the WAF's real resistance to bypasses (`aegis-sqlmap-replay`), cross-worker aggregation under distributed load (`aegis-distbench`).

---

## 7. How to add tests

### 7.1. Unit test (the preferred route)

Put tests next to the code, in an inline module at the end of the same `src/...` file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_name_states_the_invariant() {
        let out = my_function("input");
        assert_eq!(out, expected);
    }

    // For async code:
    #[tokio::test]
    async fn async_path_holds() {
        let r = my_async_fn().await;
        assert!(r.is_ok());
    }
}
```

Conventions visible in the code:
- the test name describes the invariant being checked (for example `sqli_signature_blocks_before_upstream`, `ja4_churn_observe_tracks_ip`);
- tests must not require external services; for file state use `std::env::temp_dir()` with a unique suffix (see `TEST_HONEYPOT_SEQ` + `std::process::id()` in `tests/integration.rs`);
- mark feature-specific code `#[cfg(feature = "pingora")]` / `#[cfg(feature = "xdp")]` so that the default build does not break;
- remember `RUSTFLAGS=-D warnings` in CI: unused imports/variables fail the run (the code contains workarounds such as `let _ = challenged_delta;`).

### 7.2. Pipeline integration test

Add a `#[tokio::test]` to `tests/integration.rs`, reusing `spawn_mock_upstream` and `build_handler`. If necessary, extend the signature of `build_handler` with a new parameter to enable the gate under test. Assert both on the HTTP status and on the side effect (the number of upstream hits, the `Set-Cookie`/`x-aegis-step` headers).

### 7.3. Arsenal wiring test

For a new Defence Arsenal module, add a `#[test]` to `tests/arsenal_integration.rs` that calls the API through `ArsenalState::new_default()` and checks that the corresponding field in `counters.snapshot()` has moved. This is the insurance against "dead state" (see the file header).

### 7.4. A new e2e scenario

In `aegis-e2e`, add a scenario via the helper `record(&mut scenario_results, "name", &report, &mut failures, |r| {...})`, returning `Ok(info)`/`Err(msg)`. To check metrics use `delta(&baseline, &after, "aegis_<name>")`. In `aegis-pingora-e2e`, add a check to `run_tests`, using the helpers `http_get`/`http_get_with_token`/`http_with_body_and_token` and `bail!` on a mismatch.

### 7.5. Before committing

Reproduce CI locally:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
# when editing the pingora/xdp paths:
cargo test --features pingora --all-targets
cargo check --features xdp --all-targets
```

---

## 8. Quick command cheat sheet

```bash
# Fast development loop
cargo test --lib <substring>            # a single subsystem
cargo test --lib <substring> -- --list  # what would run
cargo test --lib -- --nocapture         # see the tests' output

# Full local check (as in CI)
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo test --features pingora --all-targets

# E2E
cargo build --release --bin aegis --bin aegis-e2e && \
    ./target/release/aegis-e2e --dump-metrics
cargo build --release --features pingora --bin aegis-pingora --bin aegis-pingora-e2e && \
    ./target/release/aegis-pingora-e2e
cargo build --release --bin aegis-sqlmap-replay && \
    ./target/release/aegis-sqlmap-replay --target http://127.0.0.1:8080/
cargo build --release --bin aegis-distbench && \
    ./target/release/aegis-distbench --target http://127.0.0.1:8080/ --sources 50
```
