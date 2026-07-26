# Client consistency (V145) — operator guide

CreepJS-style cross-signal anti-detect-browser detection. Browser
runs a tiny JS collector that gathers 10 signals (UA, platform,
timezone, language, WebGL vendor, webdriver flag,
hardware_concurrency, plugin count, canvas hash) and POSTs them to
Aegis. Server-side a rule set scores the consistency of those
signals against the request's `User-Agent` header.

The output feeds the V139 ML scorer's `fp_consistency_score`
feature alongside the server-side V137 fp_correlation — whichever
tier lights up wins (we take the max).

## Why this complements server-side fingerprinting

V137 catches mismatched-stack bots from server-side fingerprints
(JA4 / JA4H / H2FP / UA). A moderately skilled attacker defeats
this by routing through a real Chrome instance over a SOCKS proxy —
TLS and HTTP fingerprints match because the real browser produced
them.

Client-side consistency catches that case. Anti-detect browsers
(Multilogin, Octo, GoLogin) spoof the UA but can't simultaneously
keep `navigator.platform`, WebGL `UNMASKED_VENDOR_WEBGL`, plugins
list, hardware_concurrency, and timezone consistent with a real
target stack — the underlying OS/GPU/etc. leak through.

## The 7 detection rules

| Rule | Weight | Catches |
|---|---|---|
| `ua_header_vs_navigator` | 0.4 | request `User-Agent` header ≠ `navigator.userAgent` (proxy/replay rewrite) |
| `webdriver_true` | 0.5 | `navigator.webdriver === true` (Selenium/Playwright tell) |
| `zero_hw_concurrency` | 0.3 | `navigator.hardwareConcurrency === 0` (impossible on real hardware) |
| `ua_platform_vs_navigator_platform` | 0.35 | UA claims Windows but `navigator.platform === "Linux x86_64"` |
| `chrome_ua_mesa_webgl` | 0.4 | Chrome UA + WebGL vendor contains "mesa" / "swiftshader" / "llvmpipe" (Chromium headless) |
| `desktop_ua_zero_plugins` | 0.2 | Desktop browser UA + `navigator.plugins.length === 0` (headless tell) |
| `timezone_language_mismatch` | 0.15 | Strong-language vs strong-timezone mismatch (`ja-JP` + `Europe/Moscow`) |

Score clamps at `1.0`. Cards lighting up add their weights;
stacked anti-detect tells reliably push score to 1.0.

Per-rule sources: [src/client_consistency.rs](../../../src/client_consistency.rs).

---

## Step 1 — embed the collector

The JS snippet lives in `CREEPJS_CLIENT_JS` const inside
[src/client_consistency.rs](../../../src/client_consistency.rs). To use
it, paste the body into a `<script>` tag on any page you want
fingerprinted.

### Option A — inline `<script>` (simplest)

```html
<script>
// Paste contents of CREEPJS_CLIENT_JS verbatim
async function aegisCollectAndPost(endpoint) { /* … */ }

// Fire on page load.
aegisCollectAndPost("/.well-known/aegis/consistency");
</script>
```

The snippet is ~3 KB unminified. It uses only browser-native APIs
(`navigator`, `Intl`, `crypto.subtle`, `WebGLRenderingContext`)
and works in any modern browser including mobile.

### Option B — external file served by Aegis (preferred)

Aegis can ship a built-in `/aegis-consistency.js` endpoint as a
follow-up — for now extract `CREEPJS_CLIENT_JS` into your own
`/static/aegis-consistency.js` and reference it:

```html
<script src="/static/aegis-consistency.js" defer></script>
<script>
  window.addEventListener('load', () =>
    aegisCollectAndPost("/.well-known/aegis/consistency"),
  );
</script>
```

### Option C — gate the collector to suspicious clients only

If you don't want to pay the JS bandwidth on every page, render the
collector only on:
- Login / signup forms (highest credential-stuffing target)
- Pages behind the V42 challenge ladder (operator already deemed
  the client suspicious)
- Pages reached after an Allow decision with high ML score

Just don't include the script on cached pages — the V145 store is
per-IP so coverage on first request is what matters.

---

## Step 2 — wire the store in your binary

The endpoint `/.well-known/aegis/consistency` is registered automatically
when `ClientSignalsStore` is wired on `AegisPingoraProxy`. Default
`aegis-pingora` binary chains this in startup:

```rust
let signals = Arc::new(ClientSignalsStore::new(10_000));
let proxy = AegisPingoraProxy::new(...)
    .with_client_signals(signals.clone());
```

The store is a per-IP LRU (default 10k entries). Latest payload
per IP wins.

Once wired, `extract_ml_features_v2` automatically folds the
client-side consistency score into `fp_consistency_score` (taking
max with the server-side V137 score). The ML model sees the
elevated feature value on the very next request from the same IP.

---

## Step 3 — verify the round-trip

From the browser DevTools network tab:

1. Load the instrumented page
2. Find the `POST /.well-known/aegis/consistency` request — status
   should be `204 No Content`
3. Payload should be a JSON object with the 10 signals

From the server side:

```sh
# Tail the audit log to see the POST land:
tail -f /var/log/aegis/audit.log | grep consistency

# Check the runtime status: requests_total should have incremented
curl -sS -H "x-admin-token: $T" \
  http://localhost:6280/admin/api/runtime/status | jq .requests
```

The store itself isn't exposed via admin API yet (planned). To
sanity-check it's populating, look at `fp_consistency_score` for
the same IP via `/admin/api/ml_explain` (after a request lands).

---

## Step 4 — operational tuning

### "I'm getting false positives on real users"

Most likely the `ua_header_vs_navigator` rule firing — corporate
MITM proxies (Zscaler, Cloudflare WARP for some configs, Citrix)
rewrite the `User-Agent` header. Either:

- Operator-supplied bypass on those IP ranges (`bypass { ip
  192.168.0.0/24; }` in DSL)
- Future: per-rule weight tuning via the Settings page (not
  implemented; for now edit the `consistency_score` weights in
  [src/client_consistency.rs](../../../src/client_consistency.rs) and
  rebuild)

### "I want to track which rule fired most"

Reasons are emitted as `&'static str` tags — see the `reasons`
field on the returned `ConsistencyScore`. Future versions will
surface per-reason Prometheus counters; for now, look at
`SecurityEvent` records (`AEGIS_EVENT_SINK=…`) for the structured
event.

### "I want to test the rules locally without a browser"

Use `curl` to POST a synthesized payload:

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "ua": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
    "platform": "Linux x86_64",
    "timezone": "Europe/Moscow",
    "language": "ja-JP",
    "webgl_vendor": "Mesa",
    "webgl_renderer": "Mesa SwiftShader",
    "webdriver": true,
    "hardware_concurrency": 0,
    "plugin_count": 0,
    "canvas_hash": "abc"
  }' \
  -H 'User-Agent: Mozilla/5.0 Chrome/120' \
  http://localhost:80/.well-known/aegis/consistency

# That payload trips: ua_header_vs_navigator, webdriver_true,
# zero_hw_concurrency, ua_platform_vs_navigator_platform,
# chrome_ua_mesa_webgl, desktop_ua_zero_plugins,
# timezone_language_mismatch — score clipped to 1.0.
```

---

## What client consistency is NOT

- **Not** a replacement for V42 challenge ladder. Challenge is
  proof-of-work + cookie; consistency is a feature signal.
- **Not** a fingerprint store (we don't try to identify the user
  across visits — that's V42's `aegis_fp` cookie's job).
- **Not** a privacy-violating tracker. We collect what the browser
  exposes to ANY website (no canvas fingerprint reconstruction,
  no AudioContext profiling). Operator should still surface this
  in their privacy policy.

---

## Privacy / GDPR notes

The 10 signals collected are all already exposed to every website
via standard JS APIs — Aegis isn't reading anything new. But:

- The signals are stored in-memory for ~10k IPs (LRU). No
  persistence to disk in default config.
- The IP itself is the key — so this is incidentally an IP-tracking
  store. Operators with strict GDPR posture should:
  - Configure shorter LRU window
  - Salt+hash IPs before key insert (not yet supported — TODO)
  - Add this collector to their cookie/consent banner

For most operators the rules are fine because the collector only
runs on pages the operator chose to instrument — embedding the
script is opt-in.

---

## What's coming

| Feature | Status |
|---|---|
| Built-in `/aegis-consistency.js` endpoint | planned |
| Per-rule weight tuning via Settings UI | planned |
| Per-reason Prometheus counters | planned |
| Long-term storage in Redis for cross-deployment correlation | planned |
| Cookie/consent integration helpers | planned |
| Salted-IP key option | planned |
