# Security model

**Languages:** **English** · [Русский](../ru/23-security-model.md)

This document states what Aegis defends against, what it explicitly does not,
where the trust boundaries are, and what the known limitations are. It is
deliberately unflattering in places — you cannot deploy a security proxy safely
against a marketing description of it.

## What Aegis defends

| Threat | Mechanism |
|---|---|
| L7 application attacks (SQLi, XSS, traversal, RCE, LFI, SSRF, XXE, webshells) | WAF: signatures, semantic SQL analysis, multi-pass normalisation, Sigma corpus |
| Automated scanning and scraping | Bot scoring, fingerprint consistency, honeypots, tarpits |
| HTTP request floods | Rate limiting, adaptive spike detection, response cache, challenge ladder |
| Slow-attack classes (Slowloris, slow POST) | Header and body read timeouts, connection budgets |
| HTTP/2 frame abuse (Rapid Reset, oversized headers) | Frame limits on the listener |
| Credential stuffing / login abuse | Login-abuse detection, per-route challenge difficulty |
| Volumetric packet floods (partially) | eBPF/XDP kernel drops, per-IP packet and SYN budgets, BGP RTBH announcements |
| Malware upload | ClamAV body scanning (optional) |

## What Aegis does not defend

- **Link saturation.** If the flood is larger than your uplink, no reverse proxy
  helps — the packets are already on your wire. That is why Aegis speaks BGP
  RTBH: the mitigation has to happen upstream of you.
- **Vulnerabilities in your application.** A WAF raises the cost of exploitation;
  it does not patch your code.
- **Compromised origin.** Aegis protects the path to your origin, not the origin
  itself.
- **Attackers with valid credentials.** Authorisation is your application's job.

## Trust boundaries

```
   untrusted ───────────────────────────────────────► trusted
   ┌──────────┐   ┌────────────┐   ┌────────────┐   ┌──────────┐
   │ client   │   │ Aegis      │   │ admin      │   │ origin   │
   │ request  │──►│ data plane │──►│ plane      │   │ backend  │
   └──────────┘   └────────────┘   └────────────┘   └──────────┘
    fully          parses          authenticated     assumed
    hostile        hostile input   operators only    trusted
```

1. **Everything from the client is hostile** — headers, body, TLS parameters,
   cookies, fingerprints. Fingerprints in particular are *client-controlled*:
   JA4 can be forged. Aegis uses fingerprints as signals and for denial by
   explicit operator rules; it does not grant privilege on a fingerprint alone.
2. **The admin plane is a separate bind and a separate trust level.** It is not
   protected by the data-plane filters. Its security is authentication, RBAC and
   *network placement*.
3. **The origin is trusted** by the data plane. Which is exactly why the point
   below about forwarded headers matters.

## Hardening checklist

- [ ] **Admin port is not on the public internet.** Bind `:6280` to a management
      interface, or reach it over VPN / SSH tunnel. This is the single most
      important item on this list.
- [ ] Panel password changed from the generated one; admin API tokens rotated.
- [ ] Separate tokens per role — do not hand out the `admin` token for reading
      metrics; use the `read` role.
- [ ] Audit log shipped off-box (`audit_log_path`).
- [ ] Real TLS certificates, not the bootstrap self-signed pair.
- [ ] `cookie_secure` on and all sites served over HTTPS.
- [ ] Origin reachable **only** from Aegis (firewall or private network) — an
      origin that is directly reachable makes the whole proxy optional for an
      attacker.
- [ ] Your origin does **not** blindly trust `X-Forwarded-For` (see below).
- [ ] SSH hardened on the host: keys only, no password auth, fail2ban, firewall.
- [ ] Rate limits tuned to your real traffic, not left at defaults.
- [ ] Challenge ladder enabled on browser-facing sites, off on API hosts.
- [ ] Log review or alerting on the deny stream — protection you never look at
      is protection you cannot tune.

## Known limitations

These are current, deliberate or not-yet-closed. They are listed so you can
compensate in your deployment.

### Forwarded client-IP headers (behaviour, not a limitation)

Aegis replaces `X-Forwarded-For`, `X-Real-IP` and `Forwarded` on every
upstream-bound request with its own resolved view of the client, and drops
`Forwarded` entirely. A client cannot smuggle a spoofed address to your origin,
including by sending the header twice.

The value your origin receives is a single address, not a chain. If Aegis sits
behind a CDN or load balancer, list that hop in `AEGIS_TRUSTED_PROXIES` — only
then is an inbound `X-Forwarded-For` honoured when resolving the real client,
and the resolved address is what gets forwarded.

### The trust token is a bearer token

Passing the challenge ladder mints a signed trust cookie (`aegis_fp`). It is
deliberately **not** bound to the client IP, so that users behind CDNs and mobile
carriers that rotate addresses are not re-challenged constantly. The trade-off is
that a captured token can be replayed from another host.

**Compensate:** keep the trust TTL short on high-value sites. Note that trust
does not disable the WAF or the rate limiter — it short-circuits the challenge
ladder, not inspection.

### Earned trust is keyed on the IP address

A client that behaves cleanly for a while is promoted to a trusted tier, which
skips throttling and challenges for the TTL. A patient attacker can warm an IP up
before using it. A single deny revokes the trust, and the WAF still runs.

### Risk engine is observe-only

The ML risk engine computes and reports scores, but its decisions are not
enforced as blocks — the enforcing decisions come from the filter chain. If you
configure the engine into an enforcing mode, treat the score as telemetry rather
than assuming it is blocking.

### HTTP/2 frame budgets are partial

Concurrent-stream, header-list-size and pending-reset limits are enforced on the
listener (this covers Rapid Reset and oversized-header classes). There is no
dedicated per-connection budget for SETTINGS/PING floods yet.

### GraphQL guards

Query depth, introspection and batch limits are implemented but not wired into
the production data plane. If you front a GraphQL API, enforce depth and
complexity limits at the application layer.

### A `challenge` WAF rule can mask a `block` rule

WAF matching is first-match-wins. The imported Sigma corpus mixes `block` and
`challenge` actions, so a medium-severity `challenge` rule that matches a
payload first will win over a high-severity `block` rule further down — and if
the challenge ladder is disabled for that site, `challenge` degrades to a pass.

**Compensate:** enable the challenge ladder on browser-facing sites, and treat
the corpus as detection-in-depth rather than a guarantee that a given payload is
blocked. The hand-written signature layer (SQLi, XSS, traversal, RCE) is
unaffected — those deny outright.

### Request body inspection has a size limit

Bodies are scanned up to a configured limit (1 MiB by default). Content beyond
that limit is forwarded without WAF inspection. Raise the limit or restrict
upload paths at the origin if large bodies matter to your threat model.

### XDP requires capabilities and a compatible kernel

Without `CAP_PERFMON` on kernel 6.x the eBPF program fails to load and Aegis
silently falls back to userspace filtering — protection still works, but the
kernel fast path is absent. Check the startup log; do not assume XDP is active.

## Reporting

Found something not listed here? Report it privately — see
[SECURITY.md](../../SECURITY.md). Testing against your own installation only.
