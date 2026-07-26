# 配置

**语言：** **中文** · [English](../en/04-configuration.md) · [Русский](../ru/04-configuration.md)

Aegis 读取单一主配置文件 `/etc/aegis/aegis.conf`，使用类 nginx 的 DSL 编写。
它只是「像 nginx」，并不是 nginx：没有 `rewrite`、没有 `fastcgi`、没有 upstream 组。
所有 Aegis 专有配置都放在自己的块里（`filters { }`、`rate_limit { }`、`xdp { }` 等）。

也支持 TOML 形式（见 `config/aegis.example.toml`），但推荐并且支持更完善的是 DSL。

## 校验与重载

```bash
aegis -t                                  # 语法检查，不重启
aegis -c /etc/aegis/aegis.conf config test
systemctl reload aegis-pingora.target     # 热更新生效
```

`reload` 是安全的：配置会先被解析和校验，损坏的文件不会影响正在运行的工作进程。

## 最小配置

```nginx
admin {
    listen 127.0.0.1:6280;
    token admin REPLACE_WITH_LONG_RANDOM;
    audit_log_path /var/log/aegis/audit.log;
}

defaults {
    request_timeout     10s;
    header_read_timeout 5s;
    graceful_shutdown   10s;

    filters {
        waf                      on;
        bot_fingerprint          on;
        adaptive_spike_detection on;
        challenge_ladder         off;   # 按站点单独开启
    }

    rate_limit {
        requests_per_second 100;
        burst 200;
    }
}

server {
    listen 0.0.0.0:80 default_server;
    proxy_pass http://127.0.0.1:8000;
}
```

## 按站点配置

```nginx
server {
    listen 0.0.0.0:80;
    listen 0.0.0.0:443 ssl http2 http3;

    server_name api.example.com;

    ssl_certificate     /etc/aegis/certs/api.crt;
    ssl_certificate_key /etc/aegis/certs/api.key;

    proxy_pass http://127.0.0.1:3001;

    # 比全局默认更严格的限流
    rate_limit {
        requests_per_second 20;
        burst 50;
    }

    # 仅对该站点启用浏览器验证
    filters {
        challenge_ladder on;
    }
}
```

站点也可以拆分成独立文件：

```nginx
include /etc/aegis/sites-enabled/*.conf;   # 运维手工管理
include /var/lib/aegis/sites.d/*.conf;     # Web 面板写入
```

两个目录都按字母序确定性扫描；通配符为空只是警告而非错误，因此放置顺序无关紧要。

## 主要配置块

### `admin`

| 指令 | 含义 |
|---|---|
| `listen` | 管理面板与 API 的监听地址。请勿暴露到公网。 |
| `token <角色> <密钥>` | API 令牌。角色：`admin` / `operator` / `read`。 |
| `audit_log_path` | 所有变更类管理调用都会追加到这里。 |
| `managed_sites_dir` | Web 面板写入生成站点文件的目录。 |
| `ops_sites_dir` | 运维管理的站点文件（在面板中只读）。 |
| `web_state_path` | Web 面板的凭据与会话。 |

### `filters`

| 过滤器 | 默认 | 作用 |
|---|---|---|
| `waf` | on | 基于特征与语义的请求检测 |
| `bot_fingerprint` | on | UA / 请求头 / JA4 一致性评分 |
| `adaptive_spike_detection` | on | 按 IP 与全局的速率异常检测 |
| `challenge_ladder` | **off** | 浏览器验证（Cookie → JS → PoW → 验证码） |

`challenge_ladder` 默认关闭是刻意为之：全局开启会让每个站点的每个客户端都被验证，
包括 API 与非浏览器流量。请在具体的 `server` 块中开启。

### `rate_limit`

```nginx
rate_limit {
    requests_per_second 100;
    burst 200;
}
```

令牌桶按来源 IP 划分。IPv6 来源会聚合到 `/64`，避免单台主机通过在自己前缀内轮换地址
来重置计数。

### `xdp`（Linux，需 `xdp` 特性）

```nginx
xdp {
    enabled true;
    interface eth0;
    bpf_object_path /var/lib/aegis/aegis-xdp.o;

    rate_window_ms 1000;   # 每 IPv4 的内核限流窗口
    rate_burst 200;        # 窗口内超过该报文数即丢弃
    syn_burst 100;         # 独立的 TCP SYN 预算
}
```

XDP 程序在内核态丢包，流量根本不会到达用户态。它需要
`CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`，以及支持 XDP 的网卡驱动
（generic/SKB 模式在 virtio 上同样可用）。

## 运行时开关与配置文件

大多数过滤器也可以在管理面板或 API 中按域名实时开关。**运行时开关是权威的**：
即使配置文件写着 `on`，在运行时被关闭的过滤器也不会执行。这样你可以在事故中
临时关掉某个误报严重的过滤器，而无需改文件或重载。

## 下一步

- [安全模型](23-security-model.md)
- [架构](02-architecture.md)
- 完整的分子系统参考：[docs/ru](../ru/README.md)
