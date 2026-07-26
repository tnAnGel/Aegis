# 安装

**语言：** **中文** · [English](../en/03-installation.md) · [Русский](../ru/03-installation.md)

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash
```

安装脚本是幂等的——重复执行即升级现有安装，且不会改动 `/etc/aegis`。它会：

1. 在缺失时安装 Rust 工具链、Node 20 与 pnpm 10；
2. 把源码克隆（或更新）到 `/usr/local/src/aegis`；
3. 构建 React 管理界面，并嵌入到二进制中；
4. 编译 `aegis-pingora`（数据面）与 `aegis`（命令行 + 旧版数据面）；
5. 生成 `/etc/aegis/aegis.conf`、引导用自签名证书、管理 API 令牌与随机面板密码；
6. 安装 systemd 模板单元，并按核心数启动绑核工作进程；
7. 预置 GeoIP 数据库与信誉源。

结束时会打印管理地址与生成的面板凭据。**请记录下来**——密码只显示一次。如果丢失：

```bash
sudo aegis web reset-admin
```

## 安装选项

```bash
sudo bash install.sh                 # 安装 / 升级（可用时启用 pingora + XDP）
sudo bash install.sh --mode hyper    # 仅旧版 hyper 模式
sudo bash install.sh --no-xdp        # 跳过 eBPF（无需 nightly 工具链）
sudo bash install.sh --workers 8     # 覆盖 REUSEPORT 工作进程数量
sudo bash install.sh --update        # 拉取 + 重新编译 + 重启
sudo bash install.sh --uninstall     # 停止并移除，保留 /etc/aegis
sudo bash install.sh --purge         # 卸载并删除状态目录
```

环境变量（在管道执行前设置）：

| 变量 | 默认值 | 含义 |
|---|---|---|
| `AEGIS_REPO` | `https://github.com/tnAnGel/Aegis.git` | 源码仓库 |
| `AEGIS_VERSION` | `main` | 要构建的分支或标签 |
| `AEGIS_PORT_HTTP` | `80` | 对外 HTTP 端口 |
| `AEGIS_PORT_HTTPS` | `443` | 对外 HTTPS 端口 |
| `AEGIS_PORT_ADMIN` | `6280` | 管理面板 / API 端口 |
| `AEGIS_WORKERS` | `auto` | 工作进程数（`auto` = 每核一个） |
| `AEGIS_ENABLE_XDP` | `auto` | `1` / `0` 强制开关 eBPF 快速路径 |
| `AEGIS_BUILD_OPT` | `fast` | `max` = fat LTO、`codegen-units=1`（编译更慢、运行更快） |

## 安装后的目录结构

| 路径 | 内容 |
|---|---|
| `/usr/local/bin/aegis-pingora` | 生产数据面 |
| `/usr/local/bin/aegis` | 命令行 + 旧版数据面 |
| `/etc/aegis/aegis.conf` | 主配置文件 |
| `/etc/aegis/sites-enabled/*.conf` | 运维手工管理的站点文件 |
| `/var/lib/aegis/sites.d/*.conf` | 由 Web 面板生成的站点文件 |
| `/etc/aegis/admin-token` | 管理 API 令牌 |
| `/var/lib/aegis/` | 状态：面板、蜜罐、拓扑、GeoIP、情报源 |
| `/var/log/aegis/` | 访问日志、审计日志与错误日志 |

## 服务管理

```bash
systemctl status  aegis-pingora.target      # 所有工作进程
systemctl restart aegis-pingora.target      # 重启整组
systemctl reload  aegis-pingora.target      # 不中断流量地应用配置
journalctl -u 'aegis-pingora@*' -f          # 跟踪所有工作进程日志
aegis -t                                    # 校验配置，不重启
```

工作进程以非特权用户 `aegis` 运行；二进制带有文件能力
（`cap_net_bind_service`、`cap_net_admin`、`cap_sys_resource`），因此无需 root
即可绑定 80/443 端口。

> **若工作进程报 `status=203/EXEC ... Operation not permitted`：** 单元中的
> `CapabilityBoundingSet` 必须是二进制文件能力的超集，否则内核会拒绝
> `execve()`。随附的安装脚本会保持两者一致；如果你手工改过单元文件，请先检查这里。

## 手动编译

```bash
git clone https://github.com/tnAnGel/Aegis.git && cd Aegis

# 管理界面（构建期嵌入二进制）
cd web && pnpm install && pnpm build && cd ..

# 数据面
cargo build --release --bin aegis-pingora --features pingora

# 含 eBPF/XDP 快速路径（仅 Linux）
cargo build --release --bin aegis-pingora --features "pingora xdp"

# BPF 对象本身需要 nightly + bpf-linker
cargo install bpf-linker
cargo +nightly build --release --manifest-path xdp/aegis-xdp-ebpf/Cargo.toml
```

## 安装后的第一步

1. 打开 `http://<host>:6280/admin/ui` 并使用生成的凭据登录，面板会强制你在首次登录时
   修改邮箱与密码。
2. 限制管理端口——**不要**把 `:6280` 暴露到公网。把它绑定到管理网口或置于 VPN 之后，
   参见[安全模型](23-security-model.md)。
3. 用正式证书替换引导用的自签名证书（支持 ACME）。
4. 把站点指向你的源站——参见[配置](04-configuration.md)。
