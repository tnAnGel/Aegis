# V74 — RC3 admin write-side + Phase A.3 WAF triage + audit tail

**Run date:** 2026-05-20 (same-day follow-up to V73)
**Stand:** OrbStack VM `Aegis-Proxy` (Linux 7.0.5-orbstack arm64, 16 cores)
**Binary:** `aegis-pingora 0.1.0` (V74 build)

V74 closes two outstanding items from the V72 roadmap and tightens
the XDP WAF hot path. Everything below ships without breaking
changes; the V73 numbers from `bench/comparison/results-2026-05-20-V73-hotpath-and-xdp.md`
still describe the steady-state runtime.

## Slice 1 — RC3 admin write-side API

The single biggest user-visible gap in V72 was the asymmetry between
the React panel (read-only) and the underlying capability (the hyper
handler already had the full write surface). V74 wires the matching
write endpoints into the pingora admin so the panel works the same
way regardless of which binary is serving it.

| Method | Path | Action |
|---|---|---|
| POST | `/admin/api/change-credentials` | Verifies old password, swaps email + hash, invalidates other sessions, returns new token + Set-Cookie |
| POST | `/admin/api/sites` | Writes a new managed `.conf` under `/var/lib/aegis/sites.d/<host>.conf`; validates with `admin_ui::render_site` first |
| DELETE | `/admin/api/sites/<host>` | Removes the matching managed `.conf` (URL-decoded host); no-op if file isn't present |
| PUT | `/admin/api/honeypots` | Atomically replaces the whole honeypot state JSON |
| POST | `/admin/api/honeypots/packs/<pack_id>` | `{"enabled":bool}` — flips one global pack |
| POST | `/admin/api/honeypots/hosts/<host>/packs/<pack_id>` | `{"enabled":bool}` — per-host override |
| DELETE | `/admin/api/honeypots/hosts/<host>` | Clears a per-host override |
| GET | `/admin/api/config/raw` | Returns the raw text of the loaded config |
| PUT | `/admin/api/config/raw` | `{"content":...}` — probe-parses against a `.probe` sibling, then atomic-renames into place |
| POST | `/admin/api/config/test` | `{"content":...}` — probe-parse only, returns `{ok, error?}` |

All write endpoints are gated by `required_role_for` to `Write`
role (already present in `src/admin_auth.rs`; no new role added).

**Reload semantics:** the pingora binary uses `--upgrade` for
hot-swap (process-level handoff), so V74 write endpoints persist
to disk and the response includes
`"note": "run \`aegis-pingora --upgrade\` to load"`. Operators run
upgrade separately. This is a deliberate decision — the hyper
binary has live in-process reload (`reload_from_disk`), but pingora
doesn't expose an equivalent API today and `--upgrade` is the
idiomatic way to push config changes without dropping connections.

**Audit-tail endpoint** (previously a placeholder) now actually
tails the file. Threaded `audit_log_path: Option<PathBuf>` through
`AdminProxy::new`; `GET /admin/api/audit` returns the last 200
lines as a JSON array.

## Slice 2 — Phase A.3 eBPF WAF first-byte triage

The V72/V73 inline WAF matched 48 prefix patterns by walking each
one byte-by-byte. Worst case: 48 patterns × 16 bytes = 768
byte-compares per non-SYN data packet. V74 adds a single-byte
triage gate: read `buf[path_start + 1]` (the second character of
the URL path, after `/`) once, then skip any pattern whose
pre-extracted `WAF_PATTERN_FIRST_BYTE[i]` doesn't match.

```rust
let target_first = buf[triage_idx];
let mut i = 0;
while i < WAF_PATTERN_COUNT {
    if WAF_PATTERN_FIRST_BYTE[i] != target_first {
        i += 1;
        continue;        // 1-byte mismatch → skip full 16-byte walk
    }
    // ... full prefix compare only on bucket-hit
}
```

| Pattern bucket (2nd byte) | Patterns | Avg compares per packet (was) | Now |
|---|---:|---:|---:|
| `.` (11 dotfiles) | 11 | 176 (11 × 16) | 1 + 16 (triage + 1 winner inner walk) |
| `w` (4 WordPress/web) | 4 | 64 | 1 + 16 |
| `e` (5 /etc/...) | 5 | 80 | 1 + 16 |
| `p` (5 /proc/..., /phpmyadmin, ...) | 5 | 80 | 1 + 16 |
| `s` (4 /server-*, /shell.php, /solr) | 4 | 64 | 1 + 16 |
| ... unique second-byte buckets ... | 1 each | 16 | 1 + 16 |

Expected steady-state per-packet work drops ~5-8× on the WAF
data path. **Verifier shape unchanged** — still a constant-bounded
outer loop (`WAF_PATTERN_COUNT` iterations) with a single early
`continue` gate. Smoke-loaded on the stand against `eth0`:

```
{"message":"XDP fast-path attached","iface":"eth0"}
{"message":"aegis-pingora: XDP fast-path loaded"}
{"message":"aegis-pingora: XDP deny/allow lists primed","deny":0,"allow":0}
```

Verifier accepts the triage gate + 48 patterns in V74's bytecode
shape, same as V73.

## Slice 3 — Loose ends from V73

- `aegis_xdp_fast_pass` counter now exposed in
  `GET /metrics` (was added to `XdpCounters` in V73 but not
  surfaced in `append_xdp_stats`).
- Runtime status JSON (`GET /admin/api/runtime/status`) gets the
  `fast_pass` field too, so the React panel can render trusted-
  bypass volume distinctly from generic PASS.

## Phase A.5 deferred (PerCpuHashMap for rate buckets)

Considered and rejected for V74. Converting `RATE_V4` and `SYN_V4`
to `BPF_MAP_TYPE_PERCPU_HASH` would eliminate cross-CPU contention
on per-IP bucket writes, but **changes rate-limit semantics**:
each CPU has its own bucket for the same IP, so a single attacker
spreading connections across CPUs (different source ports → RSS
hash → different RX queues) gets `burst × num_cpus` effective
budget. For DDoS-style traffic that's a real defensive regression.

For long-lived single connections this is fine (RSS pins one
flow to one CPU), but for a flood of new connections it isn't.
Documented and deferred — the right fix is either keep shared
maps with `BPF_F_NO_PREALLOC + bpf_atomic_xadd` for the count
(atomic increment on a kernel-mode atomic, no full map.insert
syscall), or use a per-CPU sketch (count-min) which gets you most
of the perf with shared semantics. Both are bigger changes than
this V74 scope warrants.

## E2E coverage

Extended `src/bin/aegis-pingora-e2e.rs` from 9 tests to 13:

| # | What |
|--:|---|
| 10 | `POST /admin/api/config/test` with VALID content → `ok:true` |
| 11 | `POST /admin/api/config/test` with INVALID DSL → `ok:false` |
| 12 | `POST /admin/api/sites` with malformed JSON → `400` |
| 13 | `POST /admin/api/honeypots/packs/wordpress` `{enabled:false}` → `ok:true` |

These reuse the existing harness boot path (`/usr/bin/aegis-pingora-e2e`
or running through `cargo run --bin aegis-pingora-e2e`). Added one
new helper, `http_with_body_and_token`, for body-bearing requests.

## Files changed (7)

- [src/proxy/pingora_admin.rs](src/proxy/pingora_admin.rs)
  — 11 new endpoints + audit-tail wiring + `fast_pass` runtime
  status field + `audit_log_path` constructor arg
- [src/bin/aegis-pingora.rs](src/bin/aegis-pingora.rs)
  — pass `audit_log_path` through from config into `AdminProxy::new`
- [src/bin/aegis-pingora-e2e.rs](src/bin/aegis-pingora-e2e.rs)
  — 4 new tests + body helper
- [src/proxy/pingora_admin.rs (metrics)](src/proxy/pingora_admin.rs)
  — `aegis_xdp_fast_pass` Prometheus counter
- [xdp/aegis-xdp-ebpf/src/main.rs](xdp/aegis-xdp-ebpf/src/main.rs)
  — `WAF_PATTERN_FIRST_BYTE` table + triage gate in `waf_check_v4`

## Tests

- **333/333** library unit tests pass (default features)
- **340/340** library unit tests pass (with `pingora` feature)
- **`cargo clippy --bin aegis-pingora --features pingora -- -D warnings`** clean
- **eBPF object loads on `eth0`** (verifier accepts triage table)

## Cumulative state after V72 → V73 → V74

| Slice | V72 RC2 | V73 | V74 |
|---|---|---|---|
| Bench A — vs nginx HTTP c=400 | aegis +16% | parity | parity |
| Bench A — vs nginx TLS h2 c=400 | aegis +36% | parity | parity |
| Bench B — full defense (cache-warm) | 513k RPS | parity | parity |
| Bench C — 70/30 mixed | 533k legit / 16 attack | unchanged | unchanged |
| Userspace hot-path | — | scorer single-lock + anomaly zero-alloc | — |
| XDP counters | shared `Array<u64>` | `PerCpuArray<u64>` | exposed in /metrics |
| XDP WAF | 32 patterns linear walk | 48 patterns linear walk | 48 patterns first-byte triage |
| XDP attach | DRV-only | DRV + SKB fallback | unchanged |
| Admin write API | hyper only | hyper only | **pingora reaches parity** |
| Audit log endpoint | placeholder | placeholder | **tails the file** |

V74 closes the RC2 → RC3 gap and finishes the XDP fast-path
hardening that V73 started. Next meaningful slice is either:

1. **Real eBPF AC WAF** (V75) — replace first-byte triage with
   precomputed Aho-Corasick automaton; lets us scale to 200+
   patterns at the same per-packet budget
2. **Phase A.4 — XDP SYN cookies** — needs kernel 5.18+ helpers
   (`bpf_tcp_raw_gen_syncookie_ipv4`), multi-day verifier debug
3. **Phase C — monoio + SIMD parser** — multi-week userspace
   runtime rework

None of these block V74 shipping. Pick by operational priority.
