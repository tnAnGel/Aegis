# Aegis admin API reference

Every endpoint authenticated unless noted. Auth header: `x-admin-token: <value>`.
Token sources (resolved in order): config-file `admin.tokens[]`, env
`AEGIS_ADMIN_TOKEN`, web session cookie `aegis_admin_session`.

Roles (least → most): `Read` → `Write` → `Admin`. Endpoint table below
notes the minimum role required.

For per-endpoint details, see [src/proxy/pingora_admin.rs](../../../src/proxy/pingora_admin.rs)
and [src/admin_auth.rs](../../../src/admin_auth.rs).

---

## Runtime & observability (Read)

### `GET /admin/api/runtime/status`

Live counter snapshot. Used by Dashboard KPI strip.

```sh
curl -sS -H "x-admin-token: $T" http://localhost:6280/admin/api/runtime/status
```

```json
{
  "uptime_secs": 3621,
  "config_path": "/etc/aegis/aegis.conf",
  "requests": { "total": 12453, "denied": 421, "challenged": 1872 },
  "upstream": { "2xx": 9120, "4xx": 1040, "5xx": 0, "errors": 0 },
  "cache":  { "hits": 0, "misses": 0, "stores": 0, "evictions": 0,
              "not_modified": 0, "skipped_high_threat": 0, "skipped_uncacheable": 0 },
  "xdp":    { "pass": 0, "drop_deny": 0, "drop_rate": 0, "drop_allowonly": 0,
              "drop_syn": 0, "drop_waf": 0, "fast_pass": 0 },
  "anomaly_active_hosts": ["api.example"],
  "top_threats": [{"ip": "1.2.3.4", "score": 84.2}],
  "top_threats_source": "cluster"
}
```

### `GET /admin/api/runtime/info` (V169)

Combined module-state snapshot for the Settings page. Returns `null`
for any module the operator hasn't wired (so the UI renders
"not configured" hints with the env var to enable).

```json
{
  "version": "0.1.0",
  "uptime_secs": 3621,
  "config_path": "/etc/aegis/aegis.conf",
  "ml_v2": { "kind": "logistic", "available": true },
  "ja4_reputation": { "active": true, "entry_count": 1840 },
  "asn_reputation": { "active": true, "entry_count": 215 },
  "honeypot": {
    "enabled": true,
    "packs_total": 18,
    "packs_enabled": 17,
    "custom_paths_count": 4,
    "tarpit_seconds": 30,
    "auto_xdp_deny_threshold": 3
  },
  "filter_toggles_count": 8,
  "domain_policy_count": 3,
  "clamav_addr": "127.0.0.1:3310",
  "adversarial_loop": true
}
```

### `GET /admin/api/filters`

Per-filter cumulative counters (blocks + challenges).

### `GET /admin/api/audit`

Tails the last 200 lines from `audit_log_path` if configured.

### `GET /admin/api/bots` / `/admin/api/ddos`

V121 split analytics — `bots` = per-IP single-source signals,
`ddos` = distributed-attack endpoints (≥10 distinct IPs).

### `GET /admin/api/site_map` / `/admin/api/site_map/<host>`

V119 auto-discovered endpoints. Hosts list at the top level;
host-scoped returns method+path_pattern+hits+status breakdown.

### `GET /admin/api/mined_signatures`

V107 online tarpit-miner output (ranked WAF rule candidates with
attack-support / benign-support confidence scores).

---

## Sites CRUD (Write)

### `GET /admin/api/sites`

Combined view of `/var/lib/aegis/sites.d/` (UI-managed) and
`/etc/aegis/sites-enabled/` (ops-managed, read-only in UI).

### `POST /admin/api/sites`

Body:
```json
{
  "host": "example.com",
  "upstream": "http://127.0.0.1:8080",
  "tls": true,
  "h3": true,
  "ssl_cert": "/etc/aegis/certs/example.crt",
  "ssl_key":  "/etc/aegis/certs/example.key",
  "rate_limit": { "rps": 100, "burst": 200 }
}
```

POST is an **upsert** — same host overwrites the .conf. Returns
`{ok, host, path, dsl_snippet, note}`. The site is picked up by
the next mtime poll (~30s) or operator `aegis-pingora --upgrade`.

### `DELETE /admin/api/sites/<host>`

Removes the managed `.conf`. Ops-managed sites can't be deleted via API.

---

## Per-domain policy (V162/V164) — Write

Per-host filter overrides + endpoint-level actions. **In-memory + JSON
on disk at `/var/lib/aegis/domain-policy.json`**, mtime-synced across
REUSEPORT workers.

### `GET /admin/api/sites/<host>/policy`

```json
{
  "host": "api.example.com",
  "policy": {
    "filter_enabled": { "waf": true, "challenge": false },
    "endpoint_policies": {
      "/login": "challenge",
      "/.env": "tarpit",
      "/wp-admin/install.php": "block"
    }
  },
  "global_filters": [
    { "name": "waf", "enabled": true },
    { "name": "bot", "enabled": true },
    { "name": "challenge", "enabled": true }
  ],
  "note": "Per-domain overrides win over global runtime toggles. \
           Both are in-memory; restart resets to config defaults."
}
```

### `PUT /admin/api/sites/<host>/policy`

Body is the `DomainPolicy` object:
```json
{
  "filter_enabled": { "waf": false },
  "endpoint_policies": { "/health": "allow" }
}
```

Atomic replace — what you PUT is exactly what's stored. Empty
`{}` removes the entry entirely (host falls back to globals).

### `DELETE /admin/api/sites/<host>/policy`

Same as PUT with empty body.

### Endpoint action enum

| Value | Behaviour |
|---|---|
| `"allow"` | Bypass the filter chain entirely. Use for `/health`. |
| `"block"` | 403 with reason `"endpoint_policy"`. |
| `"challenge"` | Force V42 challenge ladder even if challenge filter is disabled. |
| `"tarpit"` | Mark for V147 poisoned tarpit routing. |

Path pattern syntax (same as honeypot packs):
- `/foo` — exact match
- `/foo/*` — prefix match (anything under `/foo/`)
- `*/foo` — suffix match (e.g., `*/.env` matches any path ending in `/.env`)

First alphabetic match wins (deterministic — independent of insertion order).

---

## Runtime filter toggles (V160) — Write

Runtime on/off per filter. **In-memory + JSON at
`/var/lib/aegis/runtime-toggles.json`**, cross-worker sync.

### `GET /admin/api/defaults/filters`

```json
{
  "filters": [
    { "name": "adaptive",     "enabled": true },
    { "name": "bot",          "enabled": true },
    { "name": "challenge",    "enabled": true },
    { "name": "honeypot",     "enabled": true },
    { "name": "ip_acl",       "enabled": true },
    { "name": "rate_limit",   "enabled": true },
    { "name": "threat_intel", "enabled": true },
    { "name": "waf",          "enabled": false }
  ],
  "note": "In-memory toggles. Restart resets to config defaults …"
}
```

### `PUT /admin/api/defaults/filters`

Body accepts either shape:
```json
{"updates": [{"name": "waf", "enabled": false}]}
```
or just the array:
```json
[{"name": "waf", "enabled": false}]
```

Returns `{ok, applied, unknown_filters}`. Unknown filter names are
silently ignored (so the file is safe to hand-edit).

---

## Honeypots (Write)

### `GET /admin/api/honeypots/builtin` (V158)

Returns ALL 18 built-in packs with name + description + path_count
+ current enabled state (merged with operator overrides):

```json
{
  "global_enabled": true,
  "tarpit_seconds": 30,
  "packs": [
    {
      "id": "wordpress",
      "name": "WordPress",
      "description": "wp-admin, xmlrpc, wp-config…",
      "path_count": 47,
      "enabled": true
    }
  ],
  "packs_total": 18,
  "packs_enabled": 17,
  "custom_paths_count": 4
}
```

### `GET /admin/api/honeypots`

Full `HoneypotState` snapshot (the same shape `PUT` accepts).

### `PUT /admin/api/honeypots`

Replace whole state atomically. Mtime-synced via the existing
honeypot state file (`/var/lib/aegis/honeypots.json`).

### `PUT /admin/api/honeypots/global` / `/host`

Body `{pack_id, enabled}` (or `{host, pack_id, enabled}` for host
variant) — toggles one pack without touching the rest of state.

### `DELETE /admin/api/honeypots/hosts/<host>`

Clear all per-host overrides; falls back to global setting.

---

## Config editor

### `GET /admin/api/config/raw`

Returns the raw DSL config text.

### `PUT /admin/api/config/raw`

Body: `{content: "..."}`. Probe-parses via temp file first; on
parse error returns 400 without touching disk. On success, atomic
rename. **Does not reload the running process** — operator must
run `aegis-pingora --upgrade` or restart.

### `POST /admin/api/config/test`

Body: `{content: "..."}`. Dry-run parse only, no disk write. Returns
`{ok: bool, error?: string}`.

---

## XDP fast-path

### `GET /admin/xdp`

Plain text counters: `pass / fast_pass / drop_deny / drop_rate /
drop_allowonly / drop_syn / drop_waf`.

### `POST /admin/xdp/deny/<ip>` / `undeny/<ip>`

Programmatically add/remove from the kernel deny map.

### `GET /admin/threats`

Top 50 IPs by threat score (uses cluster scorer when shared arena
is available, falls back to per-worker).

---

## V145 client consistency collector

### `POST /.well-known/aegis/consistency`

**No auth** — public endpoint. Browser POSTs JSON payload from the
[CREEPJS_CLIENT_JS](../../../src/client_consistency.rs) snippet. Body cap
8 KiB; returns 204 on success, 400 on malformed JSON, 413 on oversize.

Operator embeds the JS via:
```html
<script>
  // …paste CREEPJS_CLIENT_JS source from src/client_consistency.rs…
  aegisCollectAndPost("/.well-known/aegis/consistency");
</script>
```

See [docs/client-consistency.md](./client-consistency.md) for the full
guide.

---

## Auth (none required)

| Endpoint | Body | Returns |
|---|---|---|
| `POST /admin/api/login` | `{email, password}` | `{ok, token, must_change_credentials, set_cookie}` |
| `POST /admin/api/logout` | — | `{ok, set_cookie: "…Max-Age=0"}` |
| `GET /admin/api/me` | — | `{authenticated, email, role, must_change_credentials, auth: "config_token"|"session"}` |
| `POST /admin/api/change-credentials` | `{old_password, new_email, new_password}` | `{ok, token, email, set_cookie}` |

Web admin state lives in `/var/lib/aegis/web.json` (or
`web_state_path` from config). Initial install generates one
default user with `must_change_credentials: true` — operator forced
to set their own creds on first login. To reset:

```sh
aegis web reset-admin
```

Prints a freshly-generated password.

---

## Public endpoints (no auth)

| Endpoint | Returns |
|---|---|
| `GET /health` / `/admin/health` | `ok\n` |
| `GET /metrics` | Prometheus exposition format |

---

## Auth failures

| Status | Meaning |
|---|---|
| 401 `invalid or missing token` | No / wrong token. Re-login or refresh `x-admin-token` header. |
| 403 `insufficient role` | Token valid but role too low (Read can't POST). |
| 503 `admin auth not configured` | No tokens registered AND no web admin store — fail closed. |

---

## Curl cookbook

Set token once:
```sh
export AEGIS_TOKEN=$(cat /etc/aegis/admin-token)
alias acurl='curl -sS -H "x-admin-token: $AEGIS_TOKEN"'
```

Snapshot dashboard:
```sh
acurl http://localhost:6280/admin/api/runtime/status | jq
acurl http://localhost:6280/admin/api/runtime/info | jq
```

Per-domain policy round-trip:
```sh
HOST=api.example.com
acurl http://localhost:6280/admin/api/sites/$HOST/policy | jq
acurl -X PUT http://localhost:6280/admin/api/sites/$HOST/policy \
  -H 'Content-Type: application/json' \
  -d '{"filter_enabled":{},"endpoint_policies":{"/login":"challenge"}}'
```

Flip all filters off (kill-switch):
```sh
acurl -X PUT http://localhost:6280/admin/api/defaults/filters \
  -H 'Content-Type: application/json' \
  -d '{"updates":[
    {"name":"waf","enabled":false},
    {"name":"bot","enabled":false},
    {"name":"adaptive","enabled":false},
    {"name":"challenge","enabled":false},
    {"name":"rate_limit","enabled":false}
  ]}'
```

Disable WordPress pack on a non-WP host:
```sh
acurl -X PUT http://localhost:6280/admin/api/honeypots/host \
  -H 'Content-Type: application/json' \
  -d '{"host":"api.example.com","pack_id":"wordpress","enabled":false}'
```

Persist a 10-minute kernel ban:
```sh
acurl -X POST http://localhost:6280/admin/xdp/deny/1.2.3.4
# (no automatic expiry — undeny manually or via background task)
acurl -X POST http://localhost:6280/admin/xdp/undeny/1.2.3.4
```
