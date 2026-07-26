# Admin API

**Languages:** **English** · [Русский](../ru/30-admin-api.md) · [detailed notes](reference/admin-api.md)

Everything the panel does, it does through this API. It is served from the admin
listener (default `:6280`) under `/admin/api/*`.

## Authentication

Two mechanisms:

| Mechanism | Use |
|---|---|
| `x-admin-token: <token>` header | Automation, scripts, monitoring |
| `aegis_admin_session` cookie | The web panel (issued by `POST /admin/api/login`) |

Tokens are declared in the config with a role:

```nginx
admin {
    listen 127.0.0.1:6280;
    token admin    <long-random>;
    token operator <long-random>;
    token read     <long-random>;
    audit_log_path /var/log/aegis/audit.log;
}
```

The installer writes the admin token to `/etc/aegis/admin-token`.

| Role | Permissions |
|---|---|
| `read` | GET everything |
| `operator` | Read + operational mutations (toggles, reload, actuator revert) |
| `admin` | Everything, including credentials and config |

All `/admin/api/*` mutations are **fail-closed**: an unrecognised route requires
authentication rather than falling through unauthenticated.

## Quick start

```bash
TOKEN=$(sudo cat /etc/aegis/admin-token)
API=http://127.0.0.1:6280/admin/api

curl -H "x-admin-token: $TOKEN" $API/runtime/status
curl -H "x-admin-token: $TOKEN" "$API/logs?limit=20"
curl -H "x-admin-token: $TOKEN" $API/arsenal
curl -H "x-admin-token: $TOKEN" $API/geo/top
```

## Frequently used endpoints

### Status and telemetry

| Method | Path | Returns |
|---|---|---|
| GET | `/admin/api/runtime/status` | Health, uptime, worker state |
| GET | `/admin/api/runtime/info` | Module configuration (general / ML / feeds / infra) |
| GET | `/admin/api/metrics/series` | Time series behind the panel charts |
| GET | `/admin/api/geo/top` | Top countries by request and deny count |
| GET | `/admin/api/arsenal` | Every protection module with its live counter |
| GET | `/metrics` | Prometheus exposition (not under `/admin/api`) |

### Traffic

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/api/logs?limit=N` | Request log |
| GET | `/admin/api/sites` | Configured sites |
| GET | `/admin/api/sites/<host>` | Per-site policy and stats |
| GET | `/admin/api/challenge/hosts` | Challenge ladder configuration per host |

### Operations

| Method | Path | Purpose |
|---|---|---|
| POST | `/admin/reload` | Reload configuration |
| GET/PUT | `/admin/api/topology` | Worker count and layout |
| GET/PUT | `/admin/api/env` | Feature-flag environment overrides |
| GET | `/admin/api/geoip/status` | GeoIP database state |
| POST | `/admin/api/geoip/update` | Fetch the current month's database |

### Benchmarks

| Method | Path | Purpose |
|---|---|---|
| POST | `/admin/api/benchmark/run` | Hardware + capacity projection |
| POST | `/admin/api/benchmark/flood/run` | Flood scenario harness |
| POST | `/admin/api/benchmark/compare/run` | Multi-proxy comparison |
| GET | `/admin/api/benchmark[/flood\|/compare]/result` | Result of the corresponding run |

Runs are fire-and-forget and return `{"ok":true,"queued":true}`; poll the
matching `/result` until `status` is `done`. Starting a run while one is in
flight returns `409`.

### Session

| Method | Path | Purpose |
|---|---|---|
| POST | `/admin/api/login` | `{email, password}` → session token |
| POST | `/admin/api/logout` | Invalidate the session |
| GET | `/admin/api/me` | Current identity and role |
| POST | `/admin/api/change-credentials` | `{current_password, new_email, new_password}` |

## Conventions

- Requests and responses are JSON.
- Errors: `{"error": "...", "status": <code>}` with the matching HTTP status.
- `200` success · `400` bad input · `401` unauthenticated · `403` role denied ·
  `404` unknown route · `409` conflicting operation in progress · `503` module
  not configured.

## Audit log

Every mutating call appends a record to `audit_log_path`: timestamp, identity,
role, method, path, and outcome. Ship it off-box — it is your record of who
changed what during an incident.

## Example: watch the deny stream

```bash
watch -n2 'curl -s -H "x-admin-token: $TOKEN" \
  "http://127.0.0.1:6280/admin/api/logs?limit=50" |
  jq -r ".entries[] | select(.action != \"pass\") |
         \"\(.action)\t\(.client_ip)\t\(.country)\t\(.reason)\t\(.path)\""'
```
