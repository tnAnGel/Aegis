<!--
Security fixes: do not describe an unfixed vulnerability in a public PR.
Report it privately first — see SECURITY.md.
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The problem this solves. If it is a bug, what was the failure? -->

## Data planes covered

Aegis has two request paths and a fix in one does not apply to the other.

- [ ] `aegis-pingora` (`src/proxy/pingora_*.rs`) — production, all H1/H2 traffic
- [ ] `aegis` legacy hyper (`src/proxy/http.rs`) — CLI and the HTTP/3 sidecar
- [ ] Not applicable (docs, tooling, build, admin UI)

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --all-targets`
- [ ] New behaviour has tests; a bypass fix includes the payload that used to get through
- [ ] Nothing on the request path can panic on malformed input
- [ ] Documentation updated in the same PR (all languages you can manage)

## Performance impact

<!-- Anything on the per-request hot path: what did you measure, and how? -->
