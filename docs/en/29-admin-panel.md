# Admin panel

**Languages:** **English** · [Русский](../ru/29-admin-panel.md)

The panel is a React application embedded into the binary at build time and
served from the admin listener at `/admin/ui`. There is nothing extra to deploy.

## First login

```
http://<host>:6280/admin/ui
```

The installer prints the generated email and password once. Lost them?

```bash
sudo aegis web reset-admin
```

The panel forces an email and password change on first login and shows a red
banner until you do it.

> **Do not expose `:6280` to the internet.** Bind it to a management interface
> or reach it through a VPN or SSH tunnel. See the
> [security model](23-security-model.md).

## Layout

The sidebar groups ~35 pages:

| Group | Pages |
|---|---|
| **Overview** | Dashboard, Metrics |
| **Traffic & routing** | Sites, Site map, Upstreams, Certificates |
| **Security** | Security, Bots, DDoS, Log, Rate limits, Reputation, GeoIP, Sigma rules |
| **Defence arsenal** | Defence arsenal, Challenge ladder, Scenarios, Active actions, Honeypots, Tarpit, BGP RTBH, Privacy Pass, Enrichment |
| **Intelligence** | ML risk engine, Signature miner, CrowdSec, Telemetry |
| **Operations** | Cluster, Workers, Benchmark, Config editor, Updates, Settings |

Language (English / Russian) and theme (light / dark) are switched from the top bar.

## The pages that matter most

**Dashboard** — total requests, threat score, active attacks, mitigation
efficiency and cluster health, plus a live world map of request origins and the
allowed / blocked / challenged traffic mix. The map needs the GeoIP database
loaded (it ships bundled and seeds itself on install).

**Security** — the live verdict stream: what was blocked, by which rule, from
where. This is where you tune false positives.

**Log** — per-request records with client IP, country, host, path, verdict,
reason, WAF rule, fingerprint and latency. Filterable.

**DDoS** — attack state, scoring, and what mitigation is currently active.

**Defence arsenal** — every protection module with its live counter, so you can
see at a glance which parts of the stack are actually firing on your traffic.
A module with a flat zero counter is either not applicable to your traffic or
not wired the way you assumed.

**Challenge ladder** — per-domain rung configuration, difficulty and TTLs.

**Workers** — per-worker PID, RSS, CPU and uptime, plus Auto/Custom control over
how many workers run. Changing the count restarts the worker set.

**Benchmark** — the built-in throughput, flood and proxy-comparison harness.
See [benchmarking](28-benchmarking.md).

**Config editor** — edit `aegis.conf` and the site files in the browser, with
validation before apply. Operator-managed files under `/etc/aegis/sites-enabled`
are shown read-only; the panel writes its own files to `/var/lib/aegis/sites.d`.

## Roles

Panel sessions are separate from API tokens. API tokens carry a role:

| Role | Can |
|---|---|
| `read` | Read every endpoint, mutate nothing |
| `operator` | Read plus operational actions (toggles, reloads, actuator reverts) |
| `admin` | Everything, including credential and config changes |

Every mutating call is written to the audit log.

## Restart-required banner

Some settings take effect only after a worker restart. The panel tracks this and
shows a banner with a restart button rather than silently applying half a change.

## See also

- [Admin API](30-admin-api.md)
- [Configuration](04-configuration.md)
