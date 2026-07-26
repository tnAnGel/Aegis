# 基准测试

**语言：** **中文** · [English](../en/28-benchmarking.md) · [Русский](../ru/28-benchmarking.md)

Aegis 自带基准测试套件，你可以用它测量**自己的**硬件，而不必相信别人的数字。

## 面板内置的基准测试页面

管理面板的 **Benchmark** 页面会在运行面板的这台主机上执行三类测试：

| 测试 | 内容 |
|---|---|
| **硬件与容量** | 微基准测试 CPU 整数吞吐、SHA-256 速率与内存带宽，然后推算转发 / TLS / WAF 请求速率并指出瓶颈所在 |
| **洪水套件** | SYN 洪水、HTTP 请求洪水、TLS 握手洪水、Slowloris、缓存命中吞吐——每项都给出通过/失败结论与攻击下的 p99 |
| **代理对比** | 把 nginx、nginx+ModSecurity+CRS、HAProxy、Caddy 与 Envoy 作为临时反向代理启动，指向同一个进程内上游，用同一压测器施加同样负载，并向每个代理发送同样的攻击载荷 |

也可以通过 API 触发：

```bash
TOKEN=$(cat /etc/aegis/admin-token)

curl -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/run
curl -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/flood/run
curl -X POST -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/compare/run

curl -H "x-admin-token: $TOKEN" http://127.0.0.1:6280/admin/api/benchmark/compare/result
```

任务为「触发即返回」，请轮询 `/result` 直到 `status` 变为 `done`。

## 参考结果

测试环境：Debian 12 虚拟机，16 vCPU / 16 GB（aarch64），8 个绑核工作进程。

| 代理 | WAF | 吞吐量 | p50 | p99 |
|---|:---:|---:|---:|---:|
| Aegis（纯转发） | — | 217 681 rps | 0.25 ms | 0.80 ms |
| **Aegis + WAF** | ✅ | **134 997 rps** | 0.40 ms | 1.55 ms |
| HAProxy 2.6.12 | — | 116 594 rps | 0.55 ms | 1.30 ms |
| Caddy 2.6.2 | — | 83 705 rps | 0.05 ms | 15.70 ms |
| nginx 1.22.1 | — | 42 667 rps | 0.55 ms | 1.20 ms |
| Envoy | — | 39 550 rps | 1.45 ms | 4.05 ms |
| nginx + ModSec + CRS | ✅ | 2 203 rps | 8.60 ms | 25.05 ms |

同一次运行的安全覆盖结果：Aegis + WAF 拦截 10/10 类载荷，nginx+ModSec+CRS 为 9/10，
所有纯转发代理均为 0/10。

## 如何客观解读这些数字

- **环回地址、单主机、短时窗口。** 压测器、各代理与上游共享同一批核心。绝对数值
  偏保守且被压缩；真正有意义的是**各行之间的比例**。
- **竞品以临时单实例运行**，使用最小化的反向代理配置。经过生产调优的多进程 nginx
  远快于上表中的数字——见下一条。
- **作为纯转发器，调优后的 nginx 快于 Aegis。** 在 CPU 隔离的专用测试机上，各代理
  以各自的高性能配置进行纯转发，实测约为 nginx 590k rps 对 Aegis 513k（c=500），
  差距约 13%，而 Aegis 的 p99 更低（1.9 ms 对 2.0 ms）。在缓存模式下顺序反转：
  Aegis 约 970k rps，nginx+proxy_cache 约 660k。
- **公平的对比是在开启检测的前提下。** nginx 加上 ModSecurity + OWASP CRS 会损失约
  95% 的吞吐（42.7k → 2.2k），Aegis 损失约 38%（217.7k → 135.0k），且仍然快于表中
  所有不做防护的代理。这才反映了两套方案每个请求实际做了什么。
- **短时窗口存在噪声。** 在同一台空闲机器上重复运行，各行会有 10–20% 的波动。
  请多跑几次；排序与比例是稳定的，绝对值会漂移。
- **在真实攻击下这种对比失去意义。** 纯转发代理不做任何过滤——100% 的攻击流量直达
  源站。

## 自行测试

`bench/comparison/` 下的脚本使用外部压测工具（`wrk`、`oha`、`slowhttptest`）对运行中的
Aegis 与作为参照的 nginx 施压：

```bash
bench/comparison/bench.sh          # 攻击 + 负载矩阵，aegis 对比 nginx
bench/comparison/bench_fair.sh     # 同等防护条件下的对比
bench/comparison/setup_stand.sh    # 搭建对比测试环境
```

要得到可复现的数字：

1. 把压测器放在与代理**不同的机器**上。
2. 把代理绑定到固定核心集合，压测器绑定到另一组。
3. 使用 `--latency-correction`（`oha`），避免协调遗漏美化你的 p99。
4. 取 N 次中的最好成绩，而不是单次运行，并在给出数字时一并说明方法论。

另见[性能深度分析（英文）](../en/reference/performance.md)——包含剖析方法、剩余耗时
去向，以及两条经过实测后被否决的优化路径（io_uring 与 header-map 门控）。
