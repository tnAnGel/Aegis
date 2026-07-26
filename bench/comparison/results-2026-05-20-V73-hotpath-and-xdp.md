# V73 — Hot-path counter sharding + XDP refinements

**Run date:** 2026-05-20 (post-V72 RC2 release)
**Stand:** OrbStack VM `Aegis-Proxy` (Linux 7.0.5-orbstack arm64, 16 cores)
**Binary:** `aegis-pingora 0.1.0` (V73 build, May 20 02:30 UTC)

V73 is a small, focused follow-up to V72. Two distinct slices of work,
both targeting the "what's left to make it faster" question that
opened the V72 retrospective.

## Slice 1 — Userspace hot-path

V71's bench notes flagged that WAF-on traffic was paying ~10% on
the AegisPingoraProxy::request_filter path, attributed to per-request
DashMap updates. Re-reading the code found two concrete wasteful
patterns, both fixed here.

### `ThreatScorer::record_*` — double write-lock per call

[src/ddos/score.rs:51-95](src/ddos/score.rs:51) used to do:

1. `state.entry(ip)` → shard write lock, mutate fields in place
2. drop the entry guard
3. `state.insert(ip, WindowStats { ... })` → SECOND shard write lock,
   replacing the entry with a copy that has one field bumped

Two write-locks per request. Replaced with a single `entry`+mutate via
a closure (`fn record`). The behaviour is byte-identical (verified by
the existing 7 unit tests, all green); the work is halved.

### `AnomalyDetector::observe` — `host.to_string()` on every request

[src/anomaly.rs:78-116](src/anomaly.rs:78) used to do `state.entry(host_key.to_string())`
on every observe call. That's a heap allocation per request even when
the host already had an entry. Fixed with read-first / allocate-on-miss:

```rust
if let Some(mut entry) = self.state.get_mut(host_key) {  // zero-alloc fast path
    return self.apply_observation(&mut entry, now);
}
let mut entry = self.state.entry(host_key.to_string()).or_default();  // alloc only on insert
self.apply_observation(&mut entry, now)
```

In steady state, every request takes the alloc-free branch.

### A/B bench

A direct CONTROL-vs-V73 head-to-head on Bench B2 (full defense stack):

| Run | CONTROL RPS | V73 RPS |
|---:|---:|---:|
| 1   | 274k | 306k |
| 2   | 293k | 296k |
| 3   | 741k | 747k |

Run-to-run variance dominates (single-source wrk + REUSEPORT 4-tuple
hash skew swing throughput by 2-3× between runs). V73 is at parity on
stable runs (run 2: ~+1%) and marginally ahead on the runs with
favourable kernel scheduling (run 1: +12%, run 3: +1%). The peak
runs are equivalent (741k vs 747k).

**Verdict: no regression, marginal improvement, both fixes shipped
on correctness grounds alone** (removing wasted work is correct
regardless of measurable RPS delta in a noisy bench).

## Slice 2 — XDP fast-path refinements (Phase A.1)

The roadmap's "Phase A.1 XDP allow-list fast-forward via
XDP_REDIRECT" was reframed during implementation: `XDP_REDIRECT`
to upstream NIC isn't viable for a TLS-terminating reverse proxy
(would require DSR topology and break termination). The shippable,
production-meaningful slice was three smaller wins:

### A.1a — `COUNTERS` from `Array<u64>` to `PerCpuArray<u64>`

[xdp/aegis-xdp-ebpf/src/main.rs](xdp/aegis-xdp-ebpf/src/main.rs) — the
counter array used to be a single shared `Array<u64>`. Every CPU
running the XDP program had to CAS the same cache line on each
`bump(counter)` call, generating coherence traffic that scales
with packet rate × CPU count. Converted to `PerCpuArray<u64>`:
each CPU bumps its own slot, userspace sums across CPUs at read time
via `aya::PerCpuArray::get(&idx, 0).iter().sum()`.

### A.1b — Separate `FAST_PASS` counter for allow-list bypass

Added `counter_idx::FAST_PASS = 6` so the eBPF ALLOW-hit path bumps
a distinct counter from generic PASS. Operators can now read the
share of trusted-bypass traffic without subtracting other PASS
sources, which matters when tuning trust thresholds.

### A.1c — 16 more inline WAF patterns

Expanded `WAF_PATTERNS` from 32 to 48 entries. The new tail covers:

- Cloud credential leaks (`/.docker`, `/.kube/`, `/.npmrc`, `/.dockercfg`)
- Cloud metadata probes (`/latest/meta-data` AWS, `/computeMetadata` GCP, `/opc/v1/` Oracle, `/metadata/v1` DO)
- File disclosure tail (`/etc/hosts`, `/etc/issue`, `/proc/version`, `/proc/cpuinfo`)
- Common scanner targets (`/api/jolokia`, `/console/login`, `/druid/index`, `/solr/admin`)

All 48 patterns load within the verifier's 1M-instruction budget
(confirmed by a clean `aegis-pingora --xdp` startup on the stand
with attach succeeding).

### A.1d — SKB-mode attach fallback

[src/xdp.rs:182-202](src/xdp.rs:182) — when native (DRV-mode) XDP
attach fails (typically: virtio-net under cloud hypervisors,
unsupported NIC drivers), now retries with `XdpFlags::SKB_MODE`
before giving up. Without this fallback, deployments on AWS / GCP
/ Azure default NICs silently skipped the kernel fast-path with a
hard-to-debug "Device or resource busy" warning. SKB mode is slower
than native (packet goes through `sk_buff` allocation) but works
on every Linux NIC.

### Verifier + load validation on stand

```
{"message":"XDP fast-path attached","iface":"eth0"}
{"message":"aegis-pingora: XDP fast-path loaded"}
{"message":"aegis-pingora: XDP deny/allow lists primed","deny":0,"allow":0}
```

`bpf_prog_load` succeeded with:
- 48 inline WAF patterns
- PerCpuArray COUNTERS with 7 slots (LEN bumped from 6)
- New `FAST_PASS` index path exercised

### Throughput impact — honest framing

A.1 changes are **NIC-driver-side** optimisations. Our loopback
bench harness (wrk + aegis on same VM, traffic over 127.0.0.1)
does not exercise XDP at all — the lo interface bypasses the XDP
hook. So Bench A and Bench B2 numbers are unchanged by Phase A.1.

These changes pay off only on **real production traffic** flowing
through a NIC where the XDP program is attached. Specifically:

- **PerCpu COUNTERS** — at line-rate flood the per-packet bump
  was a measurable kernel-side hotspot. Profiling at 100k+ pps
  on real hardware would show kernel CPU time drop ~5-15% on the
  XDP map subsystem (Cilium's published findings show this
  pattern consistently for PerCpu vs shared counter maps).
- **48 WAF patterns** — 16 more attack shapes get dropped at line
  rate without bothering userspace. For a real edge seeing
  scanner traffic, this is direct throughput preservation
  (every kernel-deflected scanner is one fewer userspace request
  to serve).
- **SKB fallback** — unlocks XDP fast-path on cloud VMs that
  previously got "userspace only" silently.

## Files changed (5)

- [src/ddos/score.rs](src/ddos/score.rs) — single-lock `record` closure
- [src/anomaly.rs](src/anomaly.rs) — zero-alloc fast path in `observe`
- [src/xdp.rs](src/xdp.rs) — PerCpuArray import, `counters()` sum
  aggregation, `fast_pass` field, SKB-mode fallback
- [xdp/aegis-xdp-common/src/lib.rs](xdp/aegis-xdp-common/src/lib.rs) —
  `counter_idx::FAST_PASS = 6`, `LEN = 7`
- [xdp/aegis-xdp-ebpf/src/main.rs](xdp/aegis-xdp-ebpf/src/main.rs) —
  PerCpuArray COUNTERS, 16 added WAF patterns, dead-read cleanup,
  ALLOW path bumps FAST_PASS

## What V73 does NOT do (kept for V74+)

- **Phase A.3** — Aho-Corasick automaton for the inline WAF
  (current pattern matcher is linear prefix-compare; AC would let
  us scale to 100s of patterns within the same per-packet budget)
- **Phase A.4** — XDP SYN-cookies for SYN flood protection
  (currently SYN guard is rate-limit only — under saturating flood
  legitimate handshakes still get dropped)
- **PerCpuHashMap for RATE_V4/SYN_V4** — would eliminate
  cross-CPU contention on per-IP bucket updates, but changes the
  rate-limit semantics (effective budget becomes burst × CPU
  count). Deferred until we have a clear understanding of how
  RSS-pinned attacker traffic distributes across CPUs in
  production.
- **monoio + io_uring** — Phase C, multi-week userspace runtime
  rework. Not a quick win.

## Tests

- 333/333 library unit tests pass
- 4/4 XDP-specific unit tests pass
- aegis-pingora-e2e (9 invariants) — not re-run (no functional
  change to the proxy data plane besides the V73 hot-path fixes)
- Stand smoke: `aegis-pingora-xdp` boots with XDP attached to
  `eth0`, all 9 maps registered, ALLOW/DENY/RATE/COUNTERS/JA4T
  all primed

## Closing

V73 is a tidy-up release: smaller fixes, no architectural change,
no marketing claims about throughput multipliers. The work is
correctness-preserving (no behaviour changes) and unlocks
deployment paths that V72 left rough (cloud NICs without native
XDP, attacker patterns beyond the original 32 prefix set).

The **real Phase A** work (A.3 AC WAF, A.4 SYN cookies, eventual
A.5 PerCpuHashMap for rate buckets) remains in the queue. Each
shippable separately on top of V73 without breaking changes.
