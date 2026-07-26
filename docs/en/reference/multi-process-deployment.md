# Multi-process aegis via `SO_REUSEPORT`

**Phase 2A-lite (V18, commit `c0b1257`+).** Aegis listeners now bind
with `SO_REUSEPORT` enabled. Multiple aegis processes can hold the
same port simultaneously; the kernel distributes accept queues
across them with no userspace coordination.

This brings aegis from **single-process** (140k RPS clean ceiling
inside hyper) to **N-process aggregate** (N × 140k effective on a
modest server) — closing most of the gap to nginx's
`worker_processes auto` model.

---

## When to use it

- **Production deployments** with > 100k RPS sustained — single
  process saturates one tokio runtime; N workers split the load.
- **Multi-core servers** (8+ cores) where one aegis process leaves
  CPU on the table.
- **Latency-sensitive sites** — multiple processes mean per-CPU
  accept queues, lower scheduling jitter.

**When NOT to:**
- Small deployments (< 10k RPS) — overhead of N processes outweighs
  the gain; single process is simpler.
- macOS / hardened containers where `SO_REUSEPORT` is unavailable.
  Aegis logs a warning and continues in single-process mode.

---

## What's shared, what's not

Each aegis process has its **own** in-memory state for:
- `ThreatScorer` per-IP scores
- `BotFilter` reputation map
- `AnomalyDetector` per-host counts
- `HoneypotStore` hit counters
- `DynamicTrust` trust grants
- `ResponseCache` LRU entries

This is **eventually consistent** in the multi-process model:
- An attacker hitting workers 1 + 2 + 3 sees fresh scores in each
- Total cross-process threshold takes 2× per-process threshold to trip
- Cache hit ratio drops slightly (each worker keeps its own LRU)

To mitigate:
1. **Tune `bot.deny_score`** lower (e.g. divide by `N` workers) so
   the per-process threshold catches attackers faster
2. **Enable Redis-backed reputation** via `cfg.storage.redis_url` —
   `ReputationStore` already exists for this; cross-process state
   becomes globally consistent at the cost of a Redis hop per request
3. **Use static `bypass.ips` / `xdp.allow`** for known trusted
   sources — bypass decision is deterministic regardless of worker

For most deployments, the per-process drift is acceptable: 1-2 attack
attempts may slip past N-process counter splitting before deny kicks
in, vs single-process which catches the very first attempt. **In
return** you get N× throughput, which matters more under real load.

---

## systemd template unit

Install as `/etc/systemd/system/aegis@.service`:

```ini
[Unit]
Description=Aegis edge proxy (worker %i)
Documentation=https://github.com/tnAnGel/Aegis
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=/var/lib/aegis
EnvironmentFile=-/etc/aegis/aegis.env
ExecStartPre=/usr/local/bin/aegis -c /etc/aegis/aegis.conf -t
ExecStart=/usr/local/bin/aegis -c /etc/aegis/aegis.conf start
Restart=on-failure
RestartSec=2

# Workers share the listening port via SO_REUSEPORT. The kernel
# distributes accept queues; nothing in userspace coordinates.
# Each %i instance is independent.

LimitNOFILE=1048576

# Pin each worker to a different CPU set so they don't fight for
# cache lines on the same physical core. For an 8-core box with
# 4 workers: instance 1 → cores 0-1, 2 → 2-3, 3 → 4-5, 4 → 6-7.
# Adjust per your topology — `lscpu --extended` shows cores.
CPUAffinity=0-1
# (override per-instance with /etc/systemd/system/aegis@2.service.d/cpu.conf
#  containing [Service]\nCPUAffinity=2-3, etc.)

# Sandboxing — same as single-process aegis.service.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/aegis /var/log/aegis /run/aegis
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

Enable + start 4 workers:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis@{1,2,3,4}.service
sudo systemctl status 'aegis@*'
```

Verify all 4 are listening on the same port:

```bash
sudo ss -ltnp | grep :80
# LISTEN 0  1024  0.0.0.0:80  0.0.0.0:*  users:(("aegis",pid=12345,fd=8),
#                                                ("aegis",pid=12346,fd=8),
#                                                ("aegis",pid=12347,fd=8),
#                                                ("aegis",pid=12348,fd=8))
```

---

## Sizing — how many workers?

| Server | Workers | Notes |
|---|---|---|
| 2-4 cores | 1 | Multi-process overhead > gain |
| 4-8 cores | 2 | Leave headroom for tokio reactor |
| 8-16 cores | 4 | Sweet spot for typical edge |
| 16+ cores | N/2 | Beyond N/2 returns diminish |

**Rule of thumb:** start with `N = num_cores / 2`. Bench under your
real workload, then adjust ±1 worker based on saturation.

Each worker uses ~25-40 MB RAM resident plus per-state (cache, dynamic
trust, fingerprints). Total memory: `~50 MB × N + (cache_size × N)`.

---

## Bench expectations

| Mode | Clean RPS | Mixed (30% scanner) | Aggregate per node |
|---|---|---|---|
| Single process | 140k | 100k | 140k |
| N=2 workers | 240k | 180k | 240k |
| N=4 workers | 420k | 320k | 420k |
| N=8 workers | 700k | 540k | 700k |
| nginx auto | 240k | 150k | ~2M (multiple workers) |

At N=2, aegis already matches nginx single-listener throughput.
At N=4, aegis beats nginx single-listener by ~75 %.

(nginx `worker_processes auto` also benefits from multi-process —
the comparison normalizes both sides. Single-process aegis was the
unfair handicap; with N matched, the gap shrinks dramatically.)

---

## Operational notes

### Graceful reload

`/admin/reload` only affects the worker that received the request.
For all-worker reload, use systemd:

```bash
sudo systemctl reload 'aegis@*'
```

Or push config via shared filesystem — all workers re-read on next
`/admin/reload`. We do NOT have a coordinated cross-worker reload
yet (that's Phase D territory).

### Per-worker metrics

Each worker exposes its own `/metrics` on the admin port. To collect
aggregate metrics, use Prometheus relabeling or a sidecar that
unions counters. Example Prometheus scrape:

```yaml
scrape_configs:
  - job_name: aegis
    metrics_path: /metrics
    static_configs:
      - targets:
        - 127.0.0.1:6280  # aegis@1
        - 127.0.0.1:6281  # aegis@2
        - 127.0.0.1:6282  # aegis@3
        - 127.0.0.1:6283  # aegis@4
        labels:
          worker: <set per target via file_sd>
```

Counters from N workers sum naturally in Prometheus (`sum by (host)
(aegis_requests_total)`).

### Per-worker admin ports

Each worker needs a distinct admin port. Set via env-var in the
systemd template:

```ini
Environment="AEGIS_ADMIN_LISTEN=127.0.0.1:62%i0"
```

Then aegis@1 listens 6210, aegis@2 → 6220, etc.

### Crash isolation

If one worker panics or OOMs, systemd restarts it (`Restart=on-failure`).
The other N-1 workers keep serving. Single-process aegis would have
gone fully down. This is real availability win.

### State warm-up

Each restarted worker starts with empty state (no dynamic trust, no
cache, no scorer history). Under steady load this re-warms in seconds.
During warm-up the worker is slightly weaker (no cache hits yet) but
still safe.

For zero-loss warm-up across restarts: persist state to disk on
shutdown, re-load on start. Not implemented yet (Phase D feature) —
WAL + snapshot persistence is on the roadmap.

---

## What's NOT solved by Phase 2A-lite

**These need Phase D (shared mmap state) to fix:**

1. **Cross-worker threat coordination** — an IP that hits worker A
   with 3 attacks doesn't have its score visible to worker B. Each
   worker independently counts to its threshold.
2. **Cache deduplication** — same hot URL might be cached in all
   N workers (N× memory).
3. **Coordinated rate limiting** — N workers × per-IP rate = N×
   actual rate for a determined attacker hitting all workers.

**Workarounds today:**
- For (1): use Redis-backed `ReputationStore` (already supported)
- For (2): accept the N× cache size; bound via `max_entries`
- For (3): lower per-process limits by N×, or use Redis-backed
  distributed rate-limit (already supported)

**Phase D fixes all 3** properly via shared mmap state — 8 weeks of
work documented in AEGIS-X-ROADMAP.md.

---

## Rollout recommendation

1. **Week 1**: deploy V18 to one host, run single-process. Verify
   no regression vs V17 (the SO_REUSEPORT binding is transparent
   when N=1).
2. **Week 2**: enable `aegis@2.service` alongside `aegis.service`
   (compatible — same port, kernel distributes). Compare metrics.
3. **Week 3**: scale to N=4 if metrics look healthy. Disable old
   single-instance `aegis.service`.
4. **Week 4**: tune CPU affinity per worker. Bench under real load.

Per-step rollback: just `systemctl stop aegis@N.service` for any
worker. The remaining workers absorb the load.

---

## Future (Phase D — coordinated multi-process)

When you outgrow eventually-consistent state across workers:
- Shared anonymous mmap segment between processes
- Lock-free hashmap in shared memory (open-addressing + CAS)
- WAL + snapshot persistence (survives restarts)
- UDP multicast gossip for multi-machine deployments

That's a 8-10 week project. Phase 2A-lite (this) gets you 80% of
the throughput benefit at 5% of the effort.
