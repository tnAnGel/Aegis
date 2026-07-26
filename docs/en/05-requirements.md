# System requirements

**Languages:** **English** · [Русский](../ru/05-requirements.md)

## Operating system

| OS | Support |
|---|---|
| Debian 12 / Ubuntu 22.04+ | Primary target — the installer is developed and tested here |
| RHEL / Rocky / Alma 9 | Supported (`dnf` path in the installer) |
| Alpine | Best-effort (`apk` path; musl build) |
| macOS | Development and tests only — no XDP, not for production |
| Windows | Not supported |

The eBPF/XDP fast path requires Linux **5.10+** (6.x recommended) with BPF
enabled and a NIC driver that supports XDP. Generic/SKB mode works everywhere,
including virtio NICs; native mode needs driver support.

## Hardware

| Profile | CPU | RAM | Notes |
|---|---|---|---|
| Minimum | 2 cores | 1 GB | Small site, cache off |
| Recommended | 8 cores | 8 GB | Comfortable for a real workload |
| High load | 16+ cores | 16+ GB | One worker per core, response cache on |

Memory scales with the worker count: thread-per-core means each worker is a full
process. On a 16-core box with 16 workers, expect roughly 600-750 MB resident
across the whole set under sustained load; a 4-worker layout uses about a
quarter of that at the cost of ~6-10% throughput and a higher p99.

Disk: 2 GB for binaries, state, GeoIP and feeds, plus whatever you budget for
logs. The source build tree needs about 5 GB.

## Build toolchain

Handled automatically by `install.sh`, listed here for manual builds:

| Component | Version |
|---|---|
| Rust | 1.85+ (edition 2024), stable |
| Node.js | 20+ |
| pnpm | 10+ |
| C toolchain | gcc/clang, `pkg-config`, `libssl-dev`, `cmake`, `perl` |
| For the BPF object | Rust nightly + `rust-src` + `bpf-linker` |

A cold release build of both binaries takes roughly 5-15 minutes depending on
the machine; `AEGIS_BUILD_OPT=max` (fat LTO, `codegen-units=1`) is noticeably
slower to build and produces a faster binary.

## Kernel and network tuning

The installer documents these; apply them for high-load deployments:

```
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

`LimitNOFILE=1048576` is set on the worker unit already.

## Capabilities

Workers run as the unprivileged `aegis` user with file capabilities on the
binary:

| Capability | Why |
|---|---|
| `CAP_NET_BIND_SERVICE` | Bind ports 80/443 without root |
| `CAP_NET_ADMIN` | Attach the XDP program to the NIC |
| `CAP_SYS_RESOURCE` | Raise memlock for BPF maps |
| `CAP_BPF`, `CAP_PERFMON` | Load and verify the eBPF program (XDP builds only) |

On kernel 6.x, `CAP_BPF` + `CAP_NET_ADMIN` alone are not enough: the verifier
gates pointer/packet-data operations behind `perfmon_capable()`, so without
`CAP_PERFMON` the program load fails with `EACCES`.

## Optional dependencies

| Component | Enables |
|---|---|
| Redis | Cross-node reputation, distributed rate limits, cluster view |
| ClamAV daemon | Request-body malware scanning |
| exabgp | BGP RTBH / FlowSpec announcements |
| nftables / iptables | Host-level actuator drops |
