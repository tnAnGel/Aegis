# Aegis documentation

**Languages:** [English](en/README.md) · [Русский](ru/README.md) · [中文](zh/README.md)

Aegis is a high-performance defensive reverse proxy (anti-DDoS / WAF) that combines
kernel-level XDP/eBPF filtering, TLS fingerprinting, IP/ASN reputation, rate limiting,
a multi-step challenge ladder and an ML risk engine. It is built for multi-process
deployments with per-core workers, deep observability and a single admin panel backed
by a REST API.

| Section | What is inside |
|---|---|
| [English](en/README.md) | The full set — 36 documents covering every subsystem. |
| [Русский](ru/README.md) | Полный справочник — 37 документов по всем подсистемам. |
| [中文](zh/README.md) | 完整文档集——覆盖所有子系统的 36 篇文档。 |
| [en/reference](en/reference/) | Deep-dive engineering notes (performance study, ML pipeline, Pingora deployment, per-domain policy). |

> All three sets cover the same ground. The Russian set is the source of truth
> — it is written first and the other two are translated from it, so if you find
> a discrepancy, Russian wins. The only Russian-only document is the pre-release
> engineering history, `ru/45-changelog-history.md`.
>
> Corrections and improvements to any language are welcome — see
> [CONTRIBUTING.md](../CONTRIBUTING.md).
