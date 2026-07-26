# 升级与迁移

**语言：** [English](../en/44-updates-migration.md) · [Русский](../ru/44-updates-migration.md) · **中文**

AEGIS 在主机上如何升级，`install.sh --update` 流程究竟做了什么（git fetch → reset → build → restart），哪些内容能在升级后保留、哪些不能，以及如何回滚。本文必须诚实地阅读：**面板内置的自升级机制（download/verify/install/activate/restart）已在 V233 中被完全移除**，因为它属于一类漏洞（未认证 RCE）。今天唯一的升级路径是在主机上手动运行安装脚本；面板仅保留只读的「检查更新」功能。

> 本文依据的来源：`install.sh`（`--update` 标志，`sync_source_tree`、`build_and_install`、`update_only`、`ensure_restart_watcher` 函数）、`src/updates.rs`（更新检查器）、`src/bin/aegis-updater.rs`（已禁用的应用器），以及——作为历史背景——`src/update_snapshot.rs`、`src/update_layout.rs`、`src/update_apply.rs`（旧 apply 机制的模块，已不再从数据平面调用）。

---

## 1. 全景图

有两个很容易混淆的、不同的「升级」概念：

| 概念 | 位于何处 | 做什么 | 目前是否启用？ |
|---------|-----------|-----------|-----------------|
| **更新检查器（Update-checker）** | `src/updates.rs`，路由 `/admin/api/updates/*` | 只读：轮询 Releases API，提示「有新版本可用」，给出发布页链接 | **是**（opt-in） |
| **面板内应用（In-panel apply）**（download/verify/install/activate/restart） | `src/bin/aegis-updater.rs` + `update_snapshot.rs`/`update_layout.rs`/`update_apply.rs` | 下载并执行二进制、切换符号链接、重启守护进程——**从面板发起** | **否，已在 V233 移除** |
| **`install.sh --update`** | `install.sh` | git fetch → reset → 重新构建 → 滚动重启，**由运维人员在主机上运行** | **是** —— 应用升级的唯一路径 |

换句话说：面板只**显示**存在升级，而**安装**由运维人员通过安装脚本手动完成。

---

## 2. 更新检查器（`src/updates.rs`）

一个只读的 Releases API 轮询器，兼容 Gitea v1.x 与 GitHub Releases API。两个平台都提供 `GET /repos/<owner>/<repo>/releases` —— 一个 JSON 发布数组（`tag_name`、`name`、`body`、`published_at`、`prerelease`、`draft`、`assets[]`）。该模块中没有任何入口点会触达 apply/execute 路径 —— 每次调用都只是对发布源的一次 HTTP GET。

### 2.1. 通道

运维人员选择通道 `stable | beta | nightly`（`enum Channel`）。发布按标签分类（`Release::channel`）：

| `tag_name`（小写）中的条件 | 通道 |
|----------------------------------|-------|
| 包含 `-nightly` | `nightly` |
| 包含 `-beta` 或 `-rc` | `beta` |
| 否则 | `stable` |

通道可见性（`Channel::permits`）与 Rust/Chrome 一致：stable 所有人可见；beta 对 beta+nightly 可见；nightly 仅 nightly 可见。

```text
stable   → stable
beta     → stable, beta
nightly  → stable, beta, nightly
```

### 2.2. 配置（`UpdateConfig`）

| 字段 | 用途 | 默认值 |
|------|-----------|---------|
| `repo_api_url` | 到仓库为止的 API 基础 URL（结尾不带斜杠） | `https://api.github.com/repos/tnAnGel/Aegis` |
| `channel` | 运维人员选择的通道 | `Stable` |
| `current_version` | 当前版本（取自 `CARGO_PKG_VERSION`） | 构建版本 |
| `poll_interval_secs` | 后台检查周期；`0` = 不自动轮询 | `3600` |

### 2.3. 行为

- `check()` 拉取 `{repo_api_url}/releases?limit=50`，过滤掉 `draft` 发布（`releases.retain(|r| !r.draft)`），并将结果带时间戳写入缓存。错误处理是 **best-effort**：记录到 `last_error`，但先前成功获取的列表仍然有效。
- `status()` 按允许的通道过滤缓存，取 `published_at` 最新的一条，通过语义化版本感知的 `is_newer` 与 `current_version` 比较。返回 `UpdateStatus { current_version, channel, latest, update_available, last_checked_at, last_error }`。
- `releases()` —— 供「历史」标签页使用的全部通道完整历史。
- `poll_due()` —— 后台轮询是否应当触发（考虑 `poll_interval_secs` 与上次检查时间）。

版本比较（`compare_versions`/`parse_version`）：去掉前导的 `v`/`V`，按 `.`/`-` 切分，数字段按数值比较，预发布标签按字典序比较，并遵循规则 **「无预发布」> 「任何预发布」**（`v0.2.0` 比 `v0.2.0-beta.1` 更新）。覆盖形如 `v0.1.5`、`v0.2.0-beta.1`、`v0.2.0-nightly.20260522` 的标签。

### 2.4. HTTP 后端

`HttpClient` trait（opt-in，与 captcha 提供方一致）。生产实现 `CurlHttpClient` 调用 shell 执行 `curl -sS -L --max-time <15s>` —— 零新增依赖，任何 Linux 主机上都有，代价是进程创建约 50 ms（对于按小时轮询和「立即检查」按钮完全可接受）。`StubHttpClient` 用于测试，也作为未接入 HTTPS 客户端时的回退。若 `HttpClient` 实现填充了响应头，则支持基于 ETag 的条件 GET。

### 2.5. Admin API（只读）

这些路由是可选的 —— 只有在接入更新检查器时才启用（`src/proxy/pingora_admin.rs`）：

| 方法与路径 | 动作 |
|--------------|----------|
| `GET /admin/api/updates/status` | 廉价的缓存读取（`UpdateChecker::status`） |
| `POST /admin/api/updates/check` | 强制轮询上游（「立即检查」） |
| `GET /admin/api/updates/releases` | 完整发布历史 |
| `PUT /admin/api/updates/config` | 更改通道 / `repo_api_url` / 间隔 |

> 关于这些路由的认证细节，参见 [30-admin-api.md](30-admin-api.md) 与 [29-admin-panel.md](29-admin-panel.md)。

### 2.6. 被移除的内容（V233）—— 诚实说明

在 `pingora_admin.rs` 中，被撤下的调度分支被明确注释掉 —— 它们**已经不存在**：

```
POST   /admin/api/updates/apply
GET    /admin/api/updates/snapshots
POST   /admin/api/updates/snapshots/create
POST   /admin/api/updates/snapshots/<id>/restore
DELETE /admin/api/updates/snapshots/<id>
GET    /admin/api/updates/releases-installed
GET    /admin/api/updates/apply-status
```

代码中直白写出的原因：它们以服务用户身份下载并执行由攻击者控制的二进制，**没有任何加密签名校验** —— 这是未认证 RCE 一类的设计。任何能够触达 `POST /admin/api/updates/apply`（或以其他方式投放 launch 清单）的人，都能让主机下载并执行任意代码。

`src/bin/aegis-updater.rs` 仅作为占位保留，好让 `Cargo.toml` 中的 `[[bin]]` 目标仍能构建：它打印手动安装说明并**以非零退出码结束**（`ExitCode::FAILURE`），使任何遗留的调用方（例如旧的 systemd unit）会大声失败，而不是静默地什么都不做。

---

## 3. 状态快照 —— 升级后哪些内容会保留

> 重要说明。模块 `src/update_snapshot.rs` / `src/update_layout.rs` / `src/update_apply.rs` 是旧的面板内应用器（V209–V212）的快照/发布机制。V233 之后**它不再从数据平面被调用**（没有路由，也没有应用器）。这些代码仍留在代码树中并有单元测试覆盖，但作为升级功能它并未启用。本节旨在说明数据格式，并作为手动备份的参考 —— 它并不描述一个「可用的按钮」。

通过 `install.sh --update` 升级时，快照**不会自动创建**：安装脚本对源码树（`$AEGIS_SRC`，默认 `/usr/local/src/aegis`）执行 `git reset --hard` 并重新构建二进制 —— 它**不会触碰** `/etc/aegis` 中的配置或 `/var/lib/aegis` 中的状态。因此状态之所以能「挺过」升级，仅仅是因为它位于源码树之外。下面的清单反映了旧 `SnapshotManager` 认为「值得保存」的内容 —— 这是升级前手动备份的实用检查表。

### 3.1. 会保存哪些内容（依据 `SnapshotManager::create`）

| 路径 | 用途 |
|------|-----|
| `/etc/aegis/aegis.conf` | 主配置（DSL 或 TOML） |
| `/etc/aegis/aegis.env` | systemd env 文件 |
| `/etc/aegis/admin-token` | 运维令牌 —— **不可丢失** |
| `/etc/aegis/hmac-secret` | 挑战令牌密钥 |
| `/etc/aegis/sites-enabled/*.conf` | 各站点配置（过滤 `*.conf`） |
| `/etc/aegis/certs/*` | TLS 证书（过滤 `crt`/`key`/`pem`） |
| `/var/lib/aegis/web.json` | Web 管理面板状态 |
| `/var/lib/aegis/honeypots.json` | honeypot 包开关 |
| `/var/lib/aegis/runtime-toggles.json` | 过滤器开/关状态（V160） |
| `/var/lib/aegis/domain-policy.json` | 按域名的覆盖配置（V162） |
| `/var/lib/aegis/sites.d/*.conf` | 由 UI 管理的站点文件（过滤 `*.conf`） |

### 3.2. 有意跳过哪些内容

日志、训练样本、已挖掘签名的缓存 —— 可重现的 / 体积巨大的 / 持续变化的。这些数据**不**包含在快照中，升级时也不会被特意保存（但 `--update` 也不会删除它们）。

### 3.3. 快照格式（供参考／手动备份）

`DEFAULT_SNAPSHOT_ROOT = /var/lib/aegis/snapshots`。快照目录：`<紧凑 ISO 时间>_<原因 slug>`，例如 `2026-05-22T12-00-00_pre-v0.2.0/`。内部包含 `manifest.json`（时间、原因、版本、带大小的文件列表）以及 `etc/…` 与 `var/…` 目录树。GC 保留最近 `keep_count` 个快照（默认 5 个），丢弃超出上限的最旧者。

> 今天的实际等价做法：升级前，直接复制 `/etc/aegis` 以及 `/var/lib/aegis` 中需要的 `*.json`（见上表）—— 这就是手动快照。关于这些文件的更多说明 —— [04-configuration.md](04-configuration.md)、[26-sites-and-domains.md](26-sites-and-domains.md)。

---

## 4. `install.sh --update` 流程

这是**唯一受支持的升级应用方式**。由运维人员以 root 身份在主机上运行。

```bash
# 在主机上，位于源码树中或已透传 AEGIS_SRC
sudo bash install.sh --update
```

`install.sh` 末尾的调度器：

```sh
if [ "$MODE_FLAG" = "update" ]; then
    update_only
    exit 0
fi
```

### 4.1. `update_only()` 做什么

1. `require_root` —— 必须是 root。
2. 检查 `[ -d "$AEGIS_SRC/.git" ]` —— 否则 fatal「run full install first」（升级只能在已有的 git 树之上工作）。
3. `build_and_install` → 内部调用 `sync_source_tree`（见 4.2）+ 构建。
4. `ensure_ui_env_dropin` —— `--update` 路径**从不重写 unit 文件**（`write_systemd_unit`），因此带 UI 功能开关的 env 文件与 drop-in 需要单独保证，好让面板中的开关在重启后生效。
5. 配置校验：`"$AEGIS_BIN" -c "$AEGIS_ETC/aegis.conf" -t`。
6. 重启（见 4.3）。
7. `sleep 1` + 检查 `systemctl is-active`；失败时 —— fatal 并提示 `journalctl -u <svc> -n 30`。

### 4.2. git fetch → checkout → reset（`sync_source_tree`）

默认值：`AEGIS_REPO=https://github.com/tnAnGel/Aegis.git`、`AEGIS_VERSION=main`、`AEGIS_SRC=/usr/local/src/aegis`。

```sh
# 收回所有权（Git 2.35+ 对他人的仓库会报 "dubious ownership"）
chown -R root:root "$AEGIS_SRC"
git config --global --add safe.directory "$AEGIS_SRC"

# GIT_TERMINAL_PROMPT=0 → 在 curl|sudo bash 下不会卡在登录提示上
if GIT_TERMINAL_PROMPT=0 git -C "$AEGIS_SRC" fetch --tags --quiet; then
    git -C "$AEGIS_SRC" checkout --quiet "$AEGIS_VERSION"          || warn "checkout failed — staying on HEAD"
    git -C "$AEGIS_SRC" reset --hard --quiet "origin/$AEGIS_VERSION" \
        || git -C "$AEGIS_SRC" reset --hard --quiet "$AEGIS_VERSION" || warn "reset failed — building local HEAD"
else
    warn "git fetch failed — building from local HEAD: <最后一次提交>"
fi
```

关键特性：

- **`reset --hard`** 意味着 `$AEGIS_SRC` 中的任何本地修改都会被覆盖。定制内容应放在 `/etc/aegis`，而不是源码树中。
- **无网络时的降级**：若 `fetch` 失败（网络/鉴权），安装脚本不会中止，而是带警告从本地 HEAD 构建。
- **私有仓库**：若需要 `clone`（没有 `.git`）而仓库是私有的 —— fatal，并提示设置带令牌的 `AEGIS_REPO`（`https://user:token@host/repo.git`），或手动解包源码树并设置 `AEGIS_SRC_OVERRIDE=/path`。
- `AEGIS_SRC_OVERRIDE` —— 指定一份现成的源码树；此时**完全不执行** git 操作。

控制变量：

| 变量 | 用途 | 默认值 |
|------------|-----------|---------|
| `AEGIS_REPO` | git 仓库 URL | `https://github.com/tnAnGel/Aegis.git` |
| `AEGIS_VERSION` | 用于 checkout/reset 的分支或标签（也可用 `--version`） | `main` |
| `AEGIS_SRC` | 源码树路径 | `/usr/local/src/aegis` |
| `AEGIS_SRC_OVERRIDE` | 现成的源码树，不执行 git 操作 | （未设置） |
| `AEGIS_MODE` | `pingora`（默认） \| `hyper` \| `both` | `pingora` |
| `AEGIS_BUILD_OPT` | `max` → fat LTO + codegen-units=1（慢，性能最大化） | （未设置 → thin LTO、cgu16、incremental） |
| `AEGIS_TARGET_CPU` | `native`（默认） \| `generic` \| 微架构 | `native` |
| `AEGIS_ENABLE_XDP` | `auto` \| `1` \| `0` | `auto` |

### 4.3. build → rebuild

`build_and_install`：
- `sync_source_tree`（见上）；
- best-effort 地补装 `mold`（`--update` 时不会调用 `install_packages`，因此链接器在此处拉取）；
- 构建配置：默认 thin LTO / codegen-units=16 / incremental；`AEGIS_BUILD_OPT=max` → fat LTO + codegen-units=1；
- 按 `AEGIS_MODE` 构建所需二进制：
  - `build_aegis_hyper` → `cargo build --release --bin aegis`，安装到 `$AEGIS_BIN`（`/usr/local/bin/aegis`）；
  - `build_aegis_pingora` → `cargo build --release --bin aegis-pingora --features "pingora[ xdp]"`，安装到 `$AEGIS_PINGORA_BIN`，并设置 `setcap cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep`；
  - `build_xdp_object`（若 `AEGIS_ENABLE_XDP=1`）→ nightly + `bpfel-unknown-none`，安装 `aegis-xdp.o`。

> 构建配置与 CPU 调优细节 —— [27-performance-tuning.md](27-performance-tuning.md)。关于 XDP —— [13-xdp-ebpf.md](13-xdp-ebpf.md)。

### 4.4. 滚动重启

构建完成后，`update_only` 重启服务：

```sh
if [ "$AEGIS_MODE" = "hyper" ]; then
    systemctl restart aegis
else
    systemctl restart aegis-pingora.target    # 扇出到所有模板实例
fi
```

这是对 target 的**完整**重启。为实现近乎零停机，另有一套滚动机制，由安装脚本部署（`ensure_restart_watcher`），并由面板中的「Restart」按钮触发：

- 脚本 `/usr/local/bin/aegis-rolling-restart` 枚举 `aegis-pingora@*.service`，当 `count > 1` 时逐个重启工作进程，之间 `sleep 3` —— 相邻进程持有监听套接字（SO_REUSEPORT），几乎没有停机；当 `count <= 1`（hyper 或只有一个工作进程）时回退到 `systemctl restart aegis-pingora.target`；
- 面板写入标记文件 `$AEGIS_HOME/.restart-request`，而 root 拥有的路径监视器 `aegis-restart.path` → `aegis-restart.service`（`Type=oneshot`）在一个独立的 cgroup 中执行滚动重启，该 cgroup 能在 target 崩溃时存活。使用 `PathExists`（而非 `Modified`）→ 标记恰好触发一次并被删除（`ExecStartPre=-rm -f <marker>`），不会出现开机时的循环；
- unit 依赖有意使用 `Wants=`（而非 `Requires=`）：重启单个工作进程**不会**拖垮 target 及其相邻进程（参见提交「restart: target Wants=…」）。

> 关于多进程与 SO_REUSEPORT 的更多说明 —— [06-workers.md](06-workers.md)。关于运维与 Restart 按钮 —— [03-installation.md](03-installation.md)、[29-admin-panel.md](29-admin-panel.md)。

---

## 5. 自升级滞后：`install.sh` 会更新它自己

一个微妙但重要的细节。`install.sh` 位于源码树**内部**，而 `--update` 会用 `reset --hard` 覆盖该树。因此在 `--update` 时：

1. 你在主机上运行的是**当前**（旧）版本的 `install.sh`；
2. 它执行 `git fetch` + `reset --hard` —— 磁盘上落下的是**新**版本的 `install.sh`；
3. 但当前进程已经在按旧代码执行 —— 它在本次运行中**不会重新读取**更新后的脚本。

后果与建议：

- 如果新版本中安装/重启/unit 文件的逻辑有变化，它**只会从下一次**运行 `install.sh` 时才生效。
- 获取确定最新安装脚本的规范做法，是再次通过 `curl` 拉取：
  ```bash
  curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash -s -- --update
  ```
  这里脚本是实时从分支下载的，因此没有滞后 —— 执行的已经是新版本（它随后再同步源码树）。对于关键的大版本迁移，这是首选路径。
- 本地的 `sudo bash install.sh --update` 更方便（脚本本身不需要网络），但请记住存在一次迭代的滞后。

---

## 6. 迁移

代码库中**没有独立的、带版本化步骤的 schema 迁移框架**。AEGIS 中的「迁移」由若干机制组成，每一个都需要诚实理解：

| 机制 | 如何迁移 | 来源 |
|----------|---------------|--------|
| 配置（`aegis.conf`） | 解析器对未知/缺失指令是宽容的；新字段有默认值。`--update` 之后必须执行 `aegis -c … -t` 校验 | `update_only`（第 5 步） |
| 状态文件（`*.json`） | serde 在新字段上使用 `#[serde(default)]` → 旧 JSON 可读，缺失项以默认值填充 | 例如 `updates.rs` 中的 `Release`/`UpdateConfig` |
| systemd unit 文件 | `--update` **不会重写它们**；仅在完整安装时更改（`write_systemd_unit`）。模板/target 的变更需要手动执行 `systemctl daemon-reload && systemctl restart aegis-pingora.target` | `update_only`、`install.sh` 中的注释 |
| UI 功能开关 env | `ensure_ui_env_dropin` 在每次 install/update 时创建/补充可写 env 文件 + drop-in（幂等），使面板中的开关能挺过升级 | `update_only`（第 4 步） |
| 基于 mtime 轮询的状态 | 守护进程按 mtime 热重载变更过的文件，无需重启 —— 新增/修改的 `*.json`/`*.conf` 约 1 秒内被拾取 | 参见 [06-workers.md](06-workers.md) |

大版本升级时的实际影响：
- 始终在重启**之前**运行 `aegis -c /etc/aegis/aegis.conf -t`（`update_only` 也会这样做）；
- 如果你改动了 unit 文件（新模板、新 target、`AEGIS_MODE` 变化）—— 请执行完整安装而不是 `--update`，或手动 `daemon-reload`；
- 升级时 `admin-token` 与 `hmac-secret` 这两个密钥**既不需要也不可以**更改 —— 丢失它们会让运维人员掉线并使挑战令牌失效。

---

## 7. 回滚

回滚同样是**手动的** —— V233 之后**没有**自动回滚（如旧 `update_apply.rs` 中带健康探测与反向切换符号链接的那套），因为触发它的应用器也已不存在。

由于 `--update` 是从 git 树构建的，回滚 = 把源码树退回上一个版本并重新构建。

### 7.1. 回滚二进制（源码）

```bash
# 选择一个确定可用的标签/提交并从中构建
sudo AEGIS_VERSION=v0.1.5 bash install.sh --update
# 或者在源码树中手动操作：
sudo git -C /usr/local/src/aegis checkout v0.1.5
sudo bash install.sh --update      # reset --hard origin/<分支> 可能会把 HEAD 拉回来 ——
                                   # 需要固定版本时请使用 AEGIS_VERSION=<标签>
```

> 注意：当 `AEGIS_VERSION=<分支>` 时，`reset --hard origin/<分支>` 这一步会再次拉取分支顶端。要固定到某个具体点，请设置 `AEGIS_VERSION=<标签>` 或某个已提交的 SHA —— 这样 checkout/reset 才会精确指向那里。

### 7.2. 回滚配置/状态

如果你在升级前手动备份了 `/etc/aegis` 以及 `/var/lib/aegis` 中的 `*.json`（见第 3 节）—— 只需把文件放回原处并执行滚动重启。这在语义上等价于 `SnapshotManager::restore`（按清单就地覆盖文件），只不过是手工完成的。

### 7.3. 任何回滚之后

```bash
aegis -c /etc/aegis/aegis.conf -t          # 配置校验
sudo /usr/local/bin/aegis-rolling-restart  # 近乎零停机，或者：
sudo systemctl restart aegis-pingora.target
systemctl is-active aegis-pingora.target
journalctl -u aegis-pingora@0 -n 30        # 如果有异常
```

---

## 8. 安全升级检查表

1. **备份** `/etc/aegis` + `/var/lib/aegis` 中需要的 `*.json`（第 3 节）—— 这就是你的「快照」。
2. 记录当前可用的版本/标签（以备回滚）。
3. 升级：`curl …/install.sh | sudo bash -s -- --update`（无自升级滞后）**或**本地的 `sudo bash install.sh --update`。
4. 等待 `aegis -c … -t` 校验完成（由安装脚本执行）—— 配置有误时它会在重启前停下。
5. 检查 `systemctl is-active` 与面板。
6. 出现问题时 —— 按第 7 节回滚。

---

## 参见

- [03-installation.md](03-installation.md) —— 安装、Restart 按钮、运维。
- [04-configuration.md](04-configuration.md) —— `aegis.conf`、env、校验。
- [06-workers.md](06-workers.md) —— SO_REUSEPORT、滚动重启、mtime 轮询。
- [23-security-model.md](23-security-model.md) —— 为什么移除了面板内 apply（RCE 类问题）。
- [29-admin-panel.md](29-admin-panel.md)、[30-admin-api.md](30-admin-api.md) —— UI 与 `/admin/api/updates/*` 路由。
- 42-текущее-состояние-STATUS.md —— 功能状态，哪些是 opt-in/部分实现。
