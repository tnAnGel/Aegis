# 概述

**语言：** **中文** · [English](../en/01-overview.md) · [Русский](../ru/01-overview.md)

Aegis 是挡在你源站前面的一层装甲：它终结所有入站 HTTP/HTTPS 流量，让流量通过多级
防护流水线，只把通过检查的请求转发给后端。它使用 Rust 编写（`edition = 2024`），
支持 HTTP/1.1、HTTP/2 与 HTTP/3 (QUIC)，可通过 eBPF/XDP 把 IP 判定下推到 Linux
内核，并内置多级浏览器验证挑战。

## 定位

```
        互联网                    Aegis 边缘                        你的基础设施
   ┌───────────────┐      ┌─────────────────────┐        ┌──────────────────────┐
   │ 浏览器        │      │  XDP / eBPF         │        │  nginx / 应用服务器  │
   │ 爬虫          │ ───► │  TLS + 指纹识别     │  ───►  │  API 后端            │
   │ 扫描器        │      │  WAF + 限流         │        │  静态资源源站        │
   │ 僵尸网络      │      │  分级验证挑战       │        │                      │
   └───────────────┘      └─────────────────────┘        └──────────────────────┘
```

Aegis 取代了通常需要「nginx + ModSecurity + 商业反爬厂商」才能凑齐的
「反向代理 + WAF + 机器人管理」三件套，并且全部自托管：流量不出你的边界、
不按请求计费、也不需要第三方替你终结 TLS。

## 能力一览

| 层次 | 能力 |
|---|---|
| L3/L4 | 内核态 eBPF/XDP 拒绝与放行表、SYN 洪水缓解、PROXY protocol、连接预算 |
| TLS | JA3、JA4 / JA4S / JA4T / JA4L / JA4X、GREASE 异常检测、mTLS 指纹、TLS 票据轮换、ACME |
| HTTP | HTTP/1.1、带帧滥用预算的 HTTP/2、HTTP/3 / QUIC、JA4H、响应缓存 |
| L7 过滤 | WAF 特征库 + 语义化 SQL 注入检测、机器人识别、限流、IP/ASN/地理 ACL、GraphQL 防护、登录滥用检测、ClamAV 请求体扫描 |
| 验证挑战 | Cookie → JS → 工作量证明（SHA-256 与 Argon2id）→ 验证码、Privacy Pass、按路由难度、信任分级 |
| 欺骗防御 | 蜜罐包、YAML 状态机蜜罐、LLM 蜜罐、马尔可夫焦油坑、伪装 CDN 响应头、延迟抖动 |
| 情报 | IP/ASN 信誉、威胁情报源、CrowdSec API、Sigma 规则导入、情报聚合、ML 风险引擎 |
| 响应处置 | 自动升级处置、带回滚 TTL 的处置器（XDP 拒绝、nftables 丢弃、BGP RTBH 通告、抬升验证下限） |
| 运维 | Web 管理面板、带 RBAC 的 REST API、Prometheus 指标、请求日志、按域策略、热重载 |

## 它不是什么

- **不是通用 Web 服务器。** 没有 FastCGI、没有 rewrite 引擎、不支持任意 nginx 指令。
  Aegis 负责代理与防护，内容由你的源站提供。
- **不是 CDN。** 它会缓存响应，但那是单边缘节点的缓存，不是全球分发网络。
- **不能取代上游 L3/L4 清洗。** 反向代理无法吸收把链路打满的容量型洪水——那必须在
  你的上联之前丢弃（这正是 Aegis 支持 BGP RTBH 的原因）。

## 两个二进制程序

| 二进制 | 角色 |
|---|---|
| `aegis-pingora` | 生产环境数据面，基于 Cloudflare Pingora。安装脚本部署并运行的就是它。 |
| `aegis` | 旧版基于 Hyper 的数据面，以及命令行工具（`aegis -t`、`aegis config test` 等）。次要。 |

安装脚本会以 `SO_REUSEPORT` 工作进程组的方式部署 `aegis-pingora`：默认每个 CPU 核心
一个单线程工作进程，并与核心 1:1 绑定（thread-per-core，避免调度漂移）。

## 下一步

- [系统要求](05-requirements.md)
- [安装](03-installation.md)
- [配置](04-configuration.md)
- [架构](02-architecture.md)
