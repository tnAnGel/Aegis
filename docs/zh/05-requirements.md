# 系统要求

**语言：** **中文** · [English](../en/05-requirements.md) · [Русский](../ru/05-requirements.md)

## 操作系统

| 系统 | 支持情况 |
|---|---|
| Debian 12 / Ubuntu 22.04+ | 主要目标——安装脚本在此开发与测试 |
| RHEL / Rocky / Alma 9 | 支持（安装脚本的 `dnf` 分支） |
| Alpine | 尽力支持（`apk` 分支；musl 构建） |
| macOS | 仅用于开发与测试——无 XDP，不可用于生产 |
| Windows | 不支持 |

eBPF/XDP 快速路径需要 Linux **5.10+**（推荐 6.x），内核启用 BPF，且网卡驱动支持
XDP。generic/SKB 模式在任何环境（包括 virtio 网卡）都可用；native 模式需要驱动支持。

## 硬件

| 场景 | CPU | 内存 | 说明 |
|---|---|---|---|
| 最低 | 2 核 | 1 GB | 小站点，关闭缓存 |
| 推荐 | 8 核 | 8 GB | 适合真实业务负载 |
| 高负载 | 16 核以上 | 16 GB 以上 | 每核一个工作进程，开启响应缓存 |

内存随工作进程数量增长：thread-per-core 意味着每个工作进程都是完整的进程镜像。
在 16 核、16 个工作进程的机器上，持续负载下整组常驻内存约 600–750 MB；
4 个工作进程的布局大约只占其四分之一，代价是约 6–10% 的吞吐量和更高的 p99。

磁盘：二进制、状态、GeoIP 与情报源约需 2 GB，另需为日志预留空间。源码构建目录
约需 5 GB。

## 构建工具链

`install.sh` 会自动处理；此处列出以便手动构建：

| 组件 | 版本 |
|---|---|
| Rust | 1.85+（edition 2024），stable |
| Node.js | 20+ |
| pnpm | 10+ |
| C 工具链 | gcc/clang、`pkg-config`、`libssl-dev`、`cmake`、`perl` |
| 构建 BPF 对象 | Rust nightly + `rust-src` + `bpf-linker` |

两个二进制的冷启动 release 构建大约需要 5–15 分钟（取决于机器）；
`AEGIS_BUILD_OPT=max`（fat LTO、`codegen-units=1`）构建明显更慢，但产物更快。

## 内核与网络调优

高负载部署建议应用：

```
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

工作进程单元中已设置 `LimitNOFILE=1048576`。

## 能力（capabilities）

工作进程以非特权用户 `aegis` 运行，能力附加在二进制文件上：

| 能力 | 用途 |
|---|---|
| `CAP_NET_BIND_SERVICE` | 无需 root 即可绑定 80/443 |
| `CAP_NET_ADMIN` | 把 XDP 程序挂载到网卡 |
| `CAP_SYS_RESOURCE` | 为 BPF map 提高 memlock 限制 |
| `CAP_BPF`、`CAP_PERFMON` | 加载并校验 eBPF 程序（仅 XDP 构建） |

在 6.x 内核上，仅有 `CAP_BPF` + `CAP_NET_ADMIN` 是不够的：校验器把涉及指针与报文
数据的操作放在 `perfmon_capable()` 之后，缺少 `CAP_PERFMON` 会导致程序加载失败并
返回 `EACCES`。

## 可选依赖

| 组件 | 启用的能力 |
|---|---|
| Redis | 跨节点信誉、分布式限流、集群视图 |
| ClamAV daemon | 请求体恶意软件扫描 |
| exabgp | BGP RTBH / FlowSpec 通告 |
| nftables / iptables | 主机级处置器丢包 |
