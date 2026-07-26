# Aegis 文档（中文）

**语言：** [English](../en/README.md) · [Русский](../ru/README.md) · **中文**

Aegis 是一款高性能的防护型反向代理——集抗 DDoS 与 WAF 于一体。它把内核态
eBPF/XDP 过滤、TLS/HTTP 指纹识别（JA3 与完整的 JA4 家族）、IP/ASN 信誉、限流、
分级验证挑战、主动欺骗（蜜罐、焦油坑）和机器学习风险引擎整合在一起，并提供统一的
管理面板与 REST API。

## 快速开始

- [概述](01-overview.md) — Aegis 是什么、适用场景、不适用场景。
- [系统要求](05-requirements.md) — 操作系统、CPU、内存、内核特性。
- [安装](03-installation.md) — 一键安装脚本、手动编译、systemd。
- [配置](04-configuration.md) — 类 nginx 的 DSL 与 TOML 形式。

## 架构与部署

- [架构](02-architecture.md) — 请求流水线、进程模型、状态层。
- [工作进程与多进程布局](06-workers.md)
- [协议与监听器](07-protocols.md)
- [TLS 与证书](08-tls-certificates.md)
- [升级与迁移](44-updates-migration.md)

## 防护子系统

- [WAF](10-waf.md) — 特征、归一化、语义化 SQL 注入检测、569 条 Sigma 规则。
- [TLS 指纹识别](11-tls-fingerprinting.md) — JA3、JA4 家族、GREASE 异常。
- [信誉](12-reputation.md)
- [XDP / eBPF](13-xdp-ebpf.md)
- [限流](14-rate-limiting.md)
- [分级验证挑战](15-challenge-ladder.md) — Cookie → JS → PoW → 验证码。
- [Privacy Pass](16-privacy-pass.md)
- [蜜罐与焦油坑](17-honeypot-tarpit.md)
- [ML 风险引擎](18-ml-risk-engine.md)
- [BGP RTBH](19-bgp-rtbh.md)
- [GeoIP](20-geoip.md)
- [武器库场景](21-arsenal-scenarios.md)
- [情报聚合](22-enrichment.md)
- [安全模型](23-security-model.md) — 威胁模型、信任边界、加固清单、已知限制。

## 可观测性与运维

- [请求日志](24-request-log.md)
- [指标与遥测](25-metrics-telemetry.md)
- [站点与域名](26-sites-and-domains.md)
- [性能调优](27-performance-tuning.md)
- [基准测试](28-benchmarking.md)

## 面板与 API

- [管理面板](29-admin-panel.md)
- [管理 API](30-admin-api.md)
- [插件](31-plugins.md)

## 项目

- [路线图](40-roadmap.md)
- [开发计划](41-development-plan.md)
- [测试](43-testing.md)
- [术语表](46-glossary.md)
- [FAQ 与故障排查](47-faq-troubleshooting.md)

## 工程深度分析（英文，`../en/reference/`）

- [性能研究](../en/reference/performance.md)
- [ML 流水线](../en/reference/ml-pipeline.md)
- [Pingora 部署](../en/reference/pingora-deployment.md)
- [多进程部署](../en/reference/multi-process-deployment.md)
- [按域策略](../en/reference/per-domain-policy.md)
- [客户端一致性](../en/reference/client-consistency.md)

> 唯一仍然只有俄文版本的文档是发布前的工程历史
> [45-changelog-history.md](../ru/45-changelog-history.md)——约 100 KB 的内部
> V97 → V245 版本序列存档。面向公众的变更日志见
> [CHANGELOG.md](../../CHANGELOG.md)。
