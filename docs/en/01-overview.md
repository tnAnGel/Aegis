# Overview

**Languages:** **English** · [Русский](../ru/01-overview.md)

Aegis is an armoured layer in front of your origin: it terminates all inbound
HTTP/HTTPS traffic, runs it through a multi-stage protection pipeline, and only
forwards what survives. It is written in Rust (`edition = 2024`), speaks
HTTP/1.1, HTTP/2 and HTTP/3 (QUIC), can push IP verdicts into the Linux kernel
through eBPF/XDP, and ships a multi-step browser challenge ladder.

## Where it fits

```
        Internet                Aegis edge                  your infrastructure
   ┌───────────────┐      ┌─────────────────────┐        ┌──────────────────────┐
   │ browsers      │      │  XDP / eBPF         │        │  nginx / app server  │
   │ bots          │ ───► │  TLS + fingerprints │  ───►  │  API backends        │
   │ scanners      │      │  WAF + rate limit   │        │  static origin       │
   │ botnets       │      │  challenge ladder   │        │                      │
   └───────────────┘      └─────────────────────┘        └──────────────────────┘
```

Aegis replaces the "reverse proxy + WAF + bot management" trio that usually
requires nginx + ModSecurity + a commercial bot vendor, and keeps all of it
self-hosted: no traffic leaves your perimeter, no per-request pricing, no
third-party TLS termination.

## What it does

| Layer | Capability |
|---|---|
| L3/L4 | XDP/eBPF deny and allow maps in the kernel, SYN-flood mitigation, PROXY protocol, connection budgets |
| TLS | JA3, JA4 / JA4S / JA4T / JA4L / JA4X, GREASE anomaly detection, mTLS fingerprints, TLS ticket rotation, ACME |
| HTTP | HTTP/1.1, HTTP/2 (with frame-level abuse budgets), HTTP/3 / QUIC, JA4H, response cache |
| L7 filters | WAF signatures + semantic SQLi, bot detection, rate limiting, IP/ASN/Geo ACLs, GraphQL guards, login-abuse detection, ClamAV body scanning |
| Challenge | Cookie → JS → proof-of-work (SHA-256 and Argon2id) → CAPTCHA, Privacy Pass, per-route difficulty, trust tiers |
| Deception | Honeypot packs, YAML state-machine honeypots, LLM honeypot, Markov tarpit, decoy CDN headers, latency jitter |
| Intelligence | IP/ASN reputation, threat-intel feeds, CrowdSec API, Sigma rule import, enrichment fan-out, ML risk engine |
| Response | Auto-escalation, actuators with revert TTL (XDP deny, nftables drop, BGP RTBH announce, challenge floor raise) |
| Operations | Web admin panel, REST API with RBAC, Prometheus metrics, request log, per-domain policy, live reload |

## What it is not

- **Not a general-purpose web server.** There is no FastCGI, no rewrite engine,
  no arbitrary nginx directive support. Aegis proxies and protects; your origin
  serves.
- **Not a CDN.** It caches responses, but it is a single-edge cache, not a
  globally distributed network.
- **Not a substitute for upstream L3/L4 scrubbing.** A reverse proxy cannot
  absorb a link-saturating volumetric flood — that has to be dropped upstream
  of your uplink (this is exactly why Aegis speaks BGP RTBH).

## Two binaries

| Binary | Role |
|---|---|
| `aegis-pingora` | The production data plane, built on Cloudflare Pingora. This is what the installer deploys and runs. |
| `aegis` | The legacy Hyper-based data plane plus the CLI (`aegis -t`, `aegis config test`, tooling). Secondary. |

The installer deploys `aegis-pingora` as an `SO_REUSEPORT` worker set — by
default one single-threaded worker per CPU core, each pinned 1:1 to a core
(thread-per-core, no scheduler float).

## Next steps

- [System requirements](05-requirements.md)
- [Installation](03-installation.md)
- [Configuration](04-configuration.md)
- [Architecture](02-architecture.md)
