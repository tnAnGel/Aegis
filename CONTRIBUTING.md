# Contributing to Aegis

Thanks for wanting to help. This document is short on purpose.

## Before you start

- **Security bugs do not go here.** Report them privately — see
  [SECURITY.md](SECURITY.md).
- For anything larger than a bug fix, open an issue first and describe what you
  want to do. It is cheaper for both of us than a rejected 2000-line PR.

## The two data planes

This trips up every newcomer, so it is worth stating up front:

| Path | File | Status |
|---|---|---|
| `aegis-pingora` | `src/proxy/pingora_*.rs` | **Production.** All HTTP/1.1 and HTTP/2 traffic. |
| `aegis` (Hyper) | `src/proxy/http.rs` | Legacy + CLI, and the HTTP/3 sidecar. |

A filter wired into `http.rs` alone does **not** run for production traffic. If
you fix something in one plane, check whether the other needs the same fix, and
say in the PR which planes you covered.

## Development setup

```bash
git clone https://github.com/tnAnGel/Aegis.git && cd Aegis

# admin UI (embedded into the binary at build time)
cd web && pnpm install && pnpm build && cd ..

# build + test
cargo build --release --bin aegis-pingora --features pingora
cargo test --all-targets
```

Requirements: Rust 1.85+, Node 20+, pnpm 10+. See
[system requirements](docs/en/05-requirements.md).

## Before you open a PR

CI runs these and fails on any of them, so run them locally first:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
cargo test --all-targets
```

The clippy gate is scoped to the lint groups that describe real defects. CI also
runs the full lint surface as a non-blocking, informational step — new stylistic
lints from a newer toolchain should not fail a build for code that did not
change, but the output is there to read and the backlog is worth chipping at.

One warning from experience: **do not trust `cargo clippy --fix` blindly.** It
has already rewritten a `match` guard whose condition carried a load-bearing
side effect into a pure predicate, silently disabling a feature. Read every
autofix hunk and run the tests.

The e2e harness is also worth running for anything touching the request path:

```bash
cargo build --release --bin aegis --bin aegis-e2e
./target/release/aegis-e2e --aegis-binary ./target/release/aegis \
    --config-template bench/e2e-config.toml --dump-metrics
```

## Code conventions

- Match the surrounding code — comment density, naming, error handling. The
  codebase has a consistent voice; keep it.
- Comments explain *why*, not *what*. If a line exists because of a specific
  attack, protocol quirk or measured regression, say so.
- New filters go through the `FilterEngine`, return `FilterAction`, and use
  `Cow<'static, str>` for deny reasons — the hot path avoids allocations.
- Anything on the per-request path needs a test proving it does not panic on
  malformed input. This is a security proxy; a panic is an outage.
- No `unwrap()` on anything derived from a request.

## Tests

- Unit tests next to the code they cover.
- Integration tests in `tests/`.
- For a WAF rule or a bypass fix, include the payload that used to get through
  as a test case.

## Documentation

Documentation lives in `docs/`, split by language:

| Directory | Contents |
|---|---|
| `docs/ru/` | Russian — 37 documents. The source of truth. |
| `docs/en/` | English — 36 documents. |
| `docs/zh/` | Chinese — 36 documents. |
| `docs/en/reference/` | Engineering deep dives. |

All three language sets are complete and mirror each other file-for-file (the
sole exception is `ru/45-changelog-history.md`, the pre-release engineering
archive). Russian is the source of truth: write there first, then port the
change across. Keep filenames identical between languages — the switcher links
at the top of each document depend on it.

If you change behaviour, update the docs in the same PR. If you add a config
directive, document it in every language you can.

## Commit messages

Conventional-commit style, with a scope:

```
fix(waf): decompress gzip bodies before signature matching
feat(challenge): per-route PoW difficulty
docs(en): translate the rate limiting guide
```

Explain *why* in the body when it is not obvious from the subject.

## Licence of contributions

Aegis is licensed under the AGPL-3.0-or-later. By contributing you agree that
your contribution is licensed under the same terms.

Note that the project is also offered commercially by the copyright holder. If
you are not comfortable with your contribution being included in commercially
licensed builds, say so in the PR and we will discuss it before merging.
