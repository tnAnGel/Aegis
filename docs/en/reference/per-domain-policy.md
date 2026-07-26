# Per-domain policy (V162 / V166)

Aegis filters run globally by default (one chain for every host).
Per-domain policy lets you override that for individual hosts AND
short-circuit individual endpoints to a fixed action.

Two layers:

1. **Filter overrides** (V162) — for each filter (waf / bot /
   challenge / rate_limit / honeypot / threat_intel / adaptive /
   ip_acl), force `on` or `off` on this host only.
2. **Endpoint actions** (V166) — for path patterns on this host,
   short-circuit to `allow` / `block` / `challenge` / `tarpit`
   BEFORE the filter chain runs.

Stored in `/var/lib/aegis/domain-policy.json`, mtime-synced across
REUSEPORT workers within ~50ms.

---

## When to use what

| Use case | Use this |
|---|---|
| "WAF generates FPs on this site, but I want it everywhere else" | Filter override: `waf → off` for the noisy host |
| "API host needs higher rate limit ceiling" | Site rate limit (POST `/admin/api/sites`), not a policy override |
| "Force captcha on `/login` on auth-heavy hosts" | Endpoint action: `/login → challenge` |
| "Block scanner-magnet paths on a non-WP site" | Endpoint action: `/wp-admin/* → block` |
| "Send hostile `/.env` probes to the tarpit" | Endpoint action: `/.env → tarpit` |
| "Whitelist `/health` from chain entirely" | Endpoint action: `/health → allow` |

---

## UI workflow

### Site detail → Security tab

For each global filter, pick one of three states:

- **inherit** (default) — uses the global toggle from
  `/admin/api/defaults/filters` (Security page).
- **force on** — runs this filter on this host even when globally off.
- **force off** — skips this filter on this host even when globally on.

The row shows: current global state · current override · computed
effective state for this host (badge). "Clear all" button removes
every override on the host.

### Site detail → Endpoints tab

Auto-discovered endpoints from V119 site_map. Each row has 5
clickable buttons: `inherit` · `allow` · `challenge` · `tarpit` · `block`.

Active choice highlighted. Save is immediate (TanStack mutation
with optimistic update + persistence to disk).

---

## API workflow

```sh
export TOKEN=$(cat /etc/aegis/admin-token)
HOST=api.example.com

# 1. Read current state (gives you per-host + global view).
curl -sS -H "x-admin-token: $TOKEN" \
  http://localhost:6280/admin/api/sites/$HOST/policy | jq

# 2. Write a policy: force WAF off, captcha on /login, tarpit on /.env.
curl -sS -H "x-admin-token: $TOKEN" \
  -X PUT http://localhost:6280/admin/api/sites/$HOST/policy \
  -H 'Content-Type: application/json' \
  -d '{
    "filter_enabled": { "waf": false },
    "endpoint_policies": {
      "/login": "challenge",
      "/.env": "tarpit",
      "/admin/secret": "block"
    }
  }'

# 3. Verify (file on disk):
cat /var/lib/aegis/domain-policy.json

# 4. Clear all overrides for the host:
curl -sS -H "x-admin-token: $TOKEN" \
  -X DELETE http://localhost:6280/admin/api/sites/$HOST/policy
```

---

## Path pattern syntax

| Syntax | Matches |
|---|---|
| `/foo` | exact path `/foo` only |
| `/foo/*` | `/foo` plus anything starting with `/foo/` |
| `*/foo` | any path ending in `/foo` (e.g., `*/login` matches `/auth/login`, `/api/v1/login`) |

First **alphabetic** match wins (sorted before iteration —
deterministic regardless of insertion order). If you set both
`/admin/*` → block and `/admin/health` → allow, `/admin/health`
wins because it comes alphabetically first.

---

## Endpoint actions in detail

### `allow`

Bypasses the entire filter chain (including WAF, rate limit,
challenge). Use sparingly — typically only for `/health`, monitor
endpoints, and other things you trust completely.

### `block`

Returns 403 with reason `"endpoint_policy"`. Faster than letting
the chain decide because it short-circuits before any filter runs.

### `challenge`

Forces the V42 challenge ladder — Browser cookie → HTML reload →
iframe → JS PoW → reCAPTCHA. Even if the global challenge filter
is disabled, this fires.

Use case: gating `/login`, `/admin/*`, password reset endpoints
against credential stuffing.

### `tarpit`

Marks the request for V147 poisoned tarpit routing. Currently
emits 403 with reason `"endpoint_tarpit"`; future versions will
route directly into the slow-streaming Markov maze response.

Use case: paths that should NEVER be hit by legitimate clients
(`/.env`, `/.git/config`, `/wp-config.php.bak`).

---

## Filter override semantics

```
effective_state(filter, host) =
    if host has explicit override → override
    else if global runtime toggle exists → global toggle
    else → enabled (default)
```

So:

- Global `waf: off`, host override `waf: on` → WAF runs for THIS host
- Global `waf: on`, host override `waf: off` → WAF skipped for THIS host
- Global `waf: on`, no override → WAF runs (default)

In-memory + persisted. Reload picks up changes within ~50ms across
workers.

---

## Persistence layout

```
/var/lib/aegis/domain-policy.json
{
  "entries": {
    "api.example.com": {
      "filter_enabled": { "waf": false, "challenge": true },
      "endpoint_policies": {
        "/login": "challenge",
        "/.env": "tarpit"
      }
    },
    "admin.example.com": {
      "filter_enabled": { "ip_acl": true },
      "endpoint_policies": {}
    }
  }
}
```

The file is **safe to hand-edit** (atomic temp+rename, comments
not supported because it's JSON, but reformat-friendly).
Mutations from `PUT /admin/api/sites/<host>/policy` rewrite the
whole file atomically.

Override the path via `AEGIS_DOMAIN_POLICY_PATH` env (e.g.,
`/etc/aegis/policy.json` for ops-managed paths).

---

## Common pitfalls

**1. "I PUT a policy but the next request doesn't apply it"**

mtime-sync polls on every read path. If you're using HTTP/2
keep-alive and pinning to one worker, that worker sees the change
on its next request (microseconds). Cross-worker propagation is
near-instant on Linux's nanosecond mtime resolution.

If you see drift, check:
```sh
ls -la /var/lib/aegis/domain-policy.json
stat /var/lib/aegis/domain-policy.json
```

mtime should match the time of your last PUT.

**2. "Endpoint policy `/login → challenge` shows in API but not enforced"**

Check the request path matches your pattern exactly:
- `/login?foo=bar` — path is just `/login` (query stripped), matches `/login`
- `/login/` — different path, does NOT match `/login`
- `/users/login` — matches `*/login` but not `/login`

**3. "I set everything but the request still hits upstream"**

The policy applies BEFORE the filter chain but AFTER bypass +
trusted-IP fast-paths. If the client IP is in the bypass list
or is dynamic-trust promoted, the cache fast-path serves and
neither the policy nor the chain runs.

Workaround: clear the trust grant via `/admin/api/runtime/trust-clear`
(not yet exposed; use `systemctl restart aegis-pingora.target` for now).

**4. "I want to delete one endpoint policy without affecting the rest"**

API doesn't expose per-key delete. Do a GET + PUT roundtrip:
```sh
POLICY=$(curl -sS -H "x-admin-token: $T" http://localhost:6280/admin/api/sites/$HOST/policy | jq .policy)
NEW=$(echo "$POLICY" | jq 'del(.endpoint_policies."/login")')
curl -sS -H "x-admin-token: $T" -X PUT \
  http://localhost:6280/admin/api/sites/$HOST/policy \
  -H 'Content-Type: application/json' -d "$NEW"
```

UI's "inherit" button on the endpoint row does exactly this.

---

## Persistence vs config DSL

These overrides are **runtime state**, not part of your DSL config.
A `systemctl restart aegis-pingora.target` will:

- **Keep** what's in `/var/lib/aegis/domain-policy.json` (loaded on
  startup).
- **Reset** RuntimeToggles to whatever `defaults { filters { } }`
  says in the DSL.

To make overrides survive AND be the canonical source of truth,
either:

1. **Just leave them in the JSON file** — operator-friendly, easy
   to edit, auto-loaded.
2. **Encode them in DSL** — V162+ doesn't yet support `server {
   policy { … } }` blocks; planned but not shipped. Until then
   the JSON file is the only persistence layer.

For most operators (1) is fine: the JSON file lives in
`/var/lib/aegis/` next to other runtime state (honeypot toggles,
training samples), is backed up by the same volumes, and shows up
in `aegis backup` (planned) along with the rest.
