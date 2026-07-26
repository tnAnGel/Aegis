# Challenge ladder

**Languages:** **English** · [Русский](../ru/15-challenge-ladder.md)

The challenge ladder is a graduated browser-verification system. Instead of a
binary allow/block, a client climbs rungs as suspicion rises — each rung costs
the client more and a legitimate browser more or less silently passes.

## The rungs

| # | Rung | What the client must do | Cost to a real user |
|---|---|---|---|
| 0 | **Transparent** | Nothing | None |
| 1 | **Cookie** | Accept and echo a signed cookie | Invisible |
| 2 | **Headers / HTML** | Render a page and follow a redirect | ~100 ms |
| 3 | **Iframe** | Load a nested document and auto-submit | ~200 ms, works without JS |
| 4 | **JavaScript PoW** | Solve a SHA-256 proof of work (difficulty in bits) | 0.2-2 s |
| 5 | **Argon2id PoW** | Memory-hard PoW (64 MB, 2 iterations, 18 bits) | 1-3 s |
| 6 | **CAPTCHA** | Solve reCAPTCHA / Turnstile | 5-15 s |

Argon2id is the interesting rung: because it is memory-hard, a GPU farm gets
100-1000× less advantage than it does against plain SHA-256, which is what makes
mass solving uneconomic rather than merely slow.

## Enabling it

The ladder is **off by default** and opt-in per site — enabling it globally
would challenge API clients and every non-browser integration you have.

```nginx
server {
    listen 0.0.0.0:443 ssl http2 http3;
    server_name shop.example.com;
    proxy_pass http://127.0.0.1:3000;

    filters {
        challenge_ladder on;
    }
}
```

Per-site difficulty, TTLs and the starting rung are configurable from the
**Challenge ladder** page in the admin panel.

## How a client climbs

Suspicion comes from the scoring layer: bot score, fingerprint mismatches,
reputation, rate anomalies, WAF near-misses. A clean browser stays at rung 0-1
indefinitely. A client that trips detectors gets escalated; sustained abuse
fast-tracks it straight to PoW or CAPTCHA.

Two global modifiers:

- **Adaptive ladder** — when the anomaly detector declares an attack, the
  *floor* rung rises for everyone, so during an active flood even unknown
  clients start at PoW.
- **Per-route difficulty** — sensitive or expensive routes carry extra bits.
  For example `*/login` adds difficulty, and known AI crawlers get more still.

## Trust after passing

Passing a rung mints a signed trust token (`aegis_fp`), and while it is valid
the client skips the ladder. Trust is tiered: a cookie-level pass buys minutes,
a strong pass buys longer, per route class.

> **Operational note.** The trust token is currently a bearer token: it is not
> bound to the client IP (deliberately, so clients behind CDNs and mobile
> carriers that flip IPs are not re-challenged constantly). The trade-off is
> that a captured token can be replayed from elsewhere. Keep the TTL short for
> high-value sites, and keep the WAF and rate limiter enabled — trust does not
> disable them.

## Privacy Pass

Clients holding a valid Privacy Pass token from a trusted issuer pass the ladder
silently, without solving anything and without revealing an identity. Tokens are
verified with Ed25519 (RFC 8032). See [Privacy Pass](../ru/16-privacy-pass.md).

## Deception rungs

Two options exist on top of the normal ladder:

- **Decoy CAPTCHA** — a fake form that burns an attacker's paid solving budget
  while never granting trust.
- **Honeypot fields** — hidden inputs that only automation fills in.

## See also

- [WAF](10-waf.md)
- [Security model](23-security-model.md)
- Full Russian reference: [15-challenge-ladder.md](../ru/15-challenge-ladder.md)
