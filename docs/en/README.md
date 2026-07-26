# Aegis documentation (English)

**Languages:** **English** · [Русский](../ru/README.md) · [中文](../zh/README.md)

Aegis is a high-performance defensive reverse proxy — anti-DDoS and WAF in one
binary. It combines kernel-level XDP/eBPF filtering, TLS/HTTP fingerprinting
(JA3, the full JA4 family), IP/ASN reputation, rate limiting, a multi-step
challenge ladder, active deception (honeypots, tarpits) and an ML risk engine,
behind a single admin panel with a REST API.

## Getting started

- [Overview](01-overview.md) — what Aegis is, where it fits, what it is not.
- [System requirements](05-requirements.md) — OS, CPU, memory, kernel features.
- [Installation](03-installation.md) — one-line installer, manual build, systemd.
- [Configuration](04-configuration.md) — the nginx-style DSL and the TOML form.

## Architecture and deployment

- [Architecture](02-architecture.md) — request pipeline, processes, state planes.
- [Workers and multi-process layout](06-workers.md)
- [Protocols and listeners](07-protocols.md)
- [TLS and certificates](08-tls-certificates.md)
- [Updates and migration](44-updates-migration.md)

## Protection subsystems

- [WAF](10-waf.md) — signatures, normalisation, semantic SQLi, 569 Sigma rules.
- [TLS fingerprinting](11-tls-fingerprinting.md) — JA3, JA4 family, GREASE anomalies.
- [Reputation](12-reputation.md)
- [XDP / eBPF](13-xdp-ebpf.md)
- [Rate limiting](14-rate-limiting.md)
- [Challenge ladder](15-challenge-ladder.md) — cookie → JS → PoW → CAPTCHA.
- [Privacy Pass](16-privacy-pass.md)
- [Honeypots and tarpits](17-honeypot-tarpit.md)
- [ML risk engine](18-ml-risk-engine.md)
- [BGP RTBH](19-bgp-rtbh.md)
- [GeoIP](20-geoip.md)
- [Arsenal scenarios](21-arsenal-scenarios.md)
- [Enrichment](22-enrichment.md)
- [Security model](23-security-model.md) — threat model, trust boundaries,
  hardening checklist, known limitations.

## Observability and operations

- [Request log](24-request-log.md)
- [Metrics and telemetry](25-metrics-telemetry.md)
- [Sites and domains](26-sites-and-domains.md)
- [Performance tuning](27-performance-tuning.md)
- [Benchmarking](28-benchmarking.md)

## Panel and API

- [Admin panel](29-admin-panel.md)
- [Admin API](30-admin-api.md)
- [Plugins](31-plugins.md)

## Project

- [Roadmap](40-roadmap.md)
- [Development plan](41-development-plan.md)
- [Testing](43-testing.md)
- [Glossary](46-glossary.md)
- [FAQ and troubleshooting](47-faq-troubleshooting.md)

## Engineering deep dives (`reference/`)

- [Performance study](reference/performance.md) — profiling, the io_uring dead
  end, where the remaining headroom is.
- [ML pipeline](reference/ml-pipeline.md) — features, training, evaluation.
- [Pingora deployment](reference/pingora-deployment.md)
- [Multi-process deployment](reference/multi-process-deployment.md)
- [Per-domain policy](reference/per-domain-policy.md)
- [Client consistency](reference/client-consistency.md)
- [Admin API (detailed notes)](reference/admin-api.md)

> The only document that remains Russian-only is the pre-release engineering
> history, [45-changelog-history.md](../ru/45-changelog-history.md) — a ~100 KB
> archive of the internal V97 → V245 revision series. The public changelog is
> [CHANGELOG.md](../../CHANGELOG.md).
