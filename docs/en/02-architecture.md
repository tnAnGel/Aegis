# Architecture

**Languages:** **English** · [Русский](../ru/02-architecture.md)

## Process model

Aegis runs as **N single-threaded worker processes**, one per CPU core, each
pinned 1:1 to its core (`CPUAffinity=%i`) and all binding the same listen ports
via `SO_REUSEPORT`. The kernel hashes each incoming 4-tuple to one worker, so
there is no shared accept lock and no cross-core wakeup storm.

```
                 :80 / :443 (SO_REUSEPORT)
   ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
   │ w0   │ w1   │ w2   │ w3   │ w4   │ w5   │ w6   │ w7   │   systemd template
   │ cpu0 │ cpu1 │ cpu2 │ cpu3 │ cpu4 │ cpu5 │ cpu6 │ cpu7 │   aegis-pingora@N
   └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
           shared memory: counters, reputation, rate state
```

`systemctl restart aegis-pingora.target` fans out to every instance; a rolling
restart takes workers down one at a time so the listening socket set is never
empty.

Trade-off: thread-per-core is measurably faster (higher RPS, lower p99 under
load) but costs RAM, since each worker is a full process image. The worker count
is configurable at install time and from the **Workers** page in the panel.

## Request pipeline

```
   packet
     │
     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ XDP / eBPF (kernel)  deny map · allow map · SYN budget  │  ← never reaches userspace
 └─────────────────────────────────────────────────────────┘
     │
     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ TLS handshake        JA3 · JA4 · JA4S/T/L/X · GREASE    │
 │                      SNI routing · mTLS · ticket keys   │
 └─────────────────────────────────────────────────────────┘
     │
     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ HTTP layer           H1 / H2 (frame budgets) / H3       │
 │                      JA4H · header normalisation        │
 └─────────────────────────────────────────────────────────┘
     │
     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Response cache       HIT → answer from worker memory    │──► client
 └─────────────────────────────────────────────────────────┘
     │ MISS
     ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Filter chain (ordered, short-circuits on Deny)          │
 │   IP/ASN/Geo ACL → reputation → rate limit → bot score  │
 │   → WAF (signatures, semantic SQLi, Sigma) → honeypot   │
 │   → challenge ladder → login-abuse → body scan (ClamAV) │
 └─────────────────────────────────────────────────────────┘
     │ Allow                          │ Deny
     ▼                                ▼
 ┌──────────────┐              ┌──────────────────────────┐
 │ upstream     │              │ 403 · challenge page     │
 │ proxy_pass   │              │ tarpit · decoy content   │
 └──────────────┘              └──────────────────────────┘
```

Each stage can short-circuit. The response cache sits *before* the filter chain
for hits, which is why cached throughput is roughly double the forwarding
throughput.

## Cross-cutting state planes

| Plane | Scope | Contents |
|---|---|---|
| **Per-worker** | one process | Response cache, hot counters, per-connection state |
| **Shared memory** | all workers on the host | Sharded atomic counters, reputation, rate-limit buckets, scorer state |
| **Redis (optional)** | the whole cluster | Cross-node reputation, distributed rate limits, cluster view |
| **Disk** | persistent | Config, site files, honeypot state, topology, ML models, feeds |

Counters are sharded per CPU to avoid cache-line ping-pong, and batched
per-worker before being folded into the shared plane.

## The two data planes

`aegis-pingora` (Cloudflare Pingora) is the production plane and is what the
installer deploys. `aegis` (Hyper) is the legacy plane plus the CLI, and it also
backs the HTTP/3 sidecar listener.

This split matters when reading the code: a filter wired into `src/proxy/http.rs`
alone does **not** run for H1/H2 production traffic — that path lives in
`src/proxy/pingora_http.rs`.

## Signals, scores and actions

Aegis separates three concerns deliberately:

1. **Signals** — fingerprints, reputation lookups, anomaly detectors, ML scores.
   Cheap, always computed, never blocking on their own.
2. **Scores** — signals aggregated per IP / per JA4 / per ASN with decay.
3. **Actions** — the only things that block: filter `Deny`, challenge issuance,
   actuator invocation (XDP deny, nftables drop, BGP RTBH announce, challenge
   floor raise), each with a revert TTL.

This is why a "suspicious" user agent does not by itself produce a 403: it raises
a score. Blocking decisions come from explicit rules and thresholds, which keeps
false positives controllable.

## Admin plane

The admin listener is a separate bind (default `:6280`) serving:

- the embedded React panel at `/admin/ui`,
- a REST API under `/admin/api/*` with token RBAC (`admin` / `operator` / `read`),
- `/metrics` in Prometheus format,
- `/admin/reload` for config reloads.

Every mutating call is written to the audit log. All `/admin/api/*` mutations are
fail-closed: unknown routes require authentication rather than falling through.

## See also

- [Workers and multi-process deployment](../ru/06-workers.md) (RU)
- [Pingora deployment notes](reference/pingora-deployment.md)
- [Performance study](reference/performance.md)
