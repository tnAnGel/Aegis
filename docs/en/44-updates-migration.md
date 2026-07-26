# Updates and migration

**Languages:** **English** · [Русский](../ru/44-updates-migration.md) · [中文](../zh/44-updates-migration.md)

How AEGIS is updated on the host, what exactly the `install.sh --update` flow does (git fetch → reset → build → restart), what survives an update and what does not, and how to roll back. This document must be read honestly: **the panel's built-in self-update mechanism (download/verify/install/activate/restart) was removed entirely in V233** as a vulnerability class (unauthenticated RCE). Today the only update path is running the installer manually on the host; the panel remains a read-only "update check" only.

> Sources this document is grounded in: `install.sh` (the `--update` flag, the `sync_source_tree`, `build_and_install`, `update_only`, `ensure_restart_watcher` functions), `src/updates.rs` (update checker), `src/bin/aegis-updater.rs` (the disabled applier), and — for historical context — `src/update_snapshot.rs`, `src/update_layout.rs`, `src/update_apply.rs` (modules of the former apply machinery, no longer called from the data plane).

---

## 1. The whole picture

There are two different notions of "update" that are easy to confuse:

| Notion | Where it lives | What it does | Active today? |
|---------|-----------|-----------|-----------------|
| **Update checker** | `src/updates.rs`, routes `/admin/api/updates/*` | Read-only: polls the Releases API, says "a new version is available", gives a link to the release | **Yes** (opt-in) |
| **In-panel apply** (download/verify/install/activate/restart) | `src/bin/aegis-updater.rs` + `update_snapshot.rs`/`update_layout.rs`/`update_apply.rs` | Downloaded and executed a binary, switched the symlink, restarted the daemon — **from the panel** | **No, removed in V233** |
| **`install.sh --update`** | `install.sh` | git fetch → reset → rebuild → rolling restart, **run by the operator on the host** | **Yes** — the only path for applying updates |

In other words: the panel **shows** that an update exists, and the operator **installs** it by hand through the installer.

---

## 2. Update checker (`src/updates.rs`)

A read-only poller of the Releases API, compatible with Gitea v1.x and the GitHub Releases API. Both platforms serve `GET /repos/<owner>/<repo>/releases` — a JSON array of releases (`tag_name`, `name`, `body`, `published_at`, `prerelease`, `draft`, `assets[]`). No entry point in this module reaches an apply/execute path — every call is an HTTP GET against the releases feed.

### 2.1. Channels

The operator picks a channel `stable | beta | nightly` (`enum Channel`). A release is classified by its tag (`Release::channel`):

| Condition in `tag_name` (lowercase) | Channel |
|----------------------------------|-------|
| contains `-nightly` | `nightly` |
| contains `-beta` or `-rc` | `beta` |
| otherwise | `stable` |

Channel visibility (`Channel::permits`) works as in Rust/Chrome: everyone sees stable; beta is seen by beta+nightly; nightly is seen by nightly only.

```text
stable   → stable
beta     → stable, beta
nightly  → stable, beta, nightly
```

### 2.2. Configuration (`UpdateConfig`)

| Field | Purpose | Default |
|------|-----------|---------|
| `repo_api_url` | Base API URL up to the repository (no trailing slash) | `https://api.github.com/repos/tnAnGel/Aegis` |
| `channel` | Operator's channel | `Stable` |
| `current_version` | Current version (taken from `CARGO_PKG_VERSION`) | build version |
| `poll_interval_secs` | Background check period; `0` = do not poll automatically | `3600` |

### 2.3. Behaviour

- `check()` fetches `{repo_api_url}/releases?limit=50`, filters out `draft` releases (`releases.retain(|r| !r.draft)`) and stores the result in a cache with a timestamp. Errors are **best-effort**: they are recorded in `last_error`, but the previously successful list stays valid.
- `status()` filters the cache by the permitted channels, takes the newest by `published_at` and compares it with `current_version` via the semver-aware `is_newer`. Returns `UpdateStatus { current_version, channel, latest, update_available, last_checked_at, last_error }`.
- `releases()` — the full history across all channels for the "History" tab.
- `poll_due()` — whether the background poll should fire (takes `poll_interval_secs` and the time of the last check into account).

Version comparison (`compare_versions`/`parse_version`): strips a leading `v`/`V`, splits on `.`/`-`, compares numeric segments numerically and pre-release labels lexically, with the rule **"no pre-release" > "any pre-release"** (`v0.2.0` is newer than `v0.2.0-beta.1`). Covers tags such as `v0.1.5`, `v0.2.0-beta.1`, `v0.2.0-nightly.20260522`.

### 2.4. HTTP backend

The `HttpClient` trait (opt-in, as with the captcha providers). The production implementation `CurlHttpClient` shells out to `curl -sS -L --max-time <15s>` — zero new dependencies, present on any Linux host, at the cost of ~50 ms for the process spawn (fine for hourly polls and the "Check now" button). `StubHttpClient` is for tests and as a fallback when no HTTPS client is wired up. Conditional GET by ETag is supported if the `HttpClient` implementation fills in the response header.

### 2.5. Admin API (read-only)

The routes are optional — they are enabled only when the update checker is wired up (`src/proxy/pingora_admin.rs`):

| Method and path | Action |
|--------------|----------|
| `GET /admin/api/updates/status` | Cheap cache read (`UpdateChecker::status`) |
| `POST /admin/api/updates/check` | Forced upstream poll ("Check now") |
| `GET /admin/api/updates/releases` | Full release history |
| `PUT /admin/api/updates/config` | Change channel / `repo_api_url` / interval |

> For more on authenticating these routes see [30-admin-api.md](30-admin-api.md) and [29-admin-panel.md](29-admin-panel.md).

### 2.6. What was removed (V233) — honestly

In `pingora_admin.rs` the withdrawn dispatcher arms are explicitly commented out — they are **gone**:

```
POST   /admin/api/updates/apply
GET    /admin/api/updates/snapshots
POST   /admin/api/updates/snapshots/create
POST   /admin/api/updates/snapshots/<id>/restore
DELETE /admin/api/updates/snapshots/<id>
GET    /admin/api/updates/releases-installed
GET    /admin/api/updates/apply-status
```

The reason, stated plainly in the code: they downloaded and executed an attacker-controlled binary as the service user **without any cryptographic signature verification** — an unauthenticated-RCE class design. Anyone who could reach `POST /admin/api/updates/apply` (or otherwise plant a launch manifest) could make the host download and execute arbitrary code.

`src/bin/aegis-updater.rs` is kept as a stub purely so that the `[[bin]]` target in `Cargo.toml` still builds: it prints manual installation instructions and **exits with a non-zero code** (`ExitCode::FAILURE`), so that any stale caller (an old systemd unit, for example) fails loudly rather than silently doing nothing.

---

## 3. State snapshots — what survives an update

> IMPORTANT CAVEAT. The modules `src/update_snapshot.rs` / `src/update_layout.rs` / `src/update_apply.rs` are the snapshot/release machinery of the former in-panel applier (V209–V212). After V233 **it is not called from the data plane** (no route, no applier). The code remains in the tree and is covered by unit tests, but as an update feature it is not active. This section is given to explain the data format and as a guide for a manual backup — it does not describe a "live button".

When updating via `install.sh --update`, snapshots are **not created automatically**: the installer runs `git reset --hard` over the source tree (`$AEGIS_SRC`, `/usr/local/src/aegis` by default) and rebuilds the binaries — it **does not touch** the configs in `/etc/aegis` or the state in `/var/lib/aegis`. State therefore "survives" the update simply because it lives outside the source tree. The list below reflects what the former `SnapshotManager` considered "worth preserving" — a handy checklist for a manual backup before updating.

### 3.1. What is preserved (per `SnapshotManager::create`)

| Path | Why |
|------|-----|
| `/etc/aegis/aegis.conf` | Main config (DSL or TOML) |
| `/etc/aegis/aegis.env` | systemd env file |
| `/etc/aegis/admin-token` | Operator token — **must not be lost** |
| `/etc/aegis/hmac-secret` | Challenge-token secret |
| `/etc/aegis/sites-enabled/*.conf` | Per-site configs (filter `*.conf`) |
| `/etc/aegis/certs/*` | TLS certificates (filter `crt`/`key`/`pem`) |
| `/var/lib/aegis/web.json` | Web admin state |
| `/var/lib/aegis/honeypots.json` | Honeypot pack toggles |
| `/var/lib/aegis/runtime-toggles.json` | Filter on/off state (V160) |
| `/var/lib/aegis/domain-policy.json` | Per-domain overrides (V162) |
| `/var/lib/aegis/sites.d/*.conf` | UI-managed site files (filter `*.conf`) |

### 3.2. What is skipped (deliberately)

Logs, training samples, the mined-signature cache — reproducible / huge / constantly changing. This data was **not** part of a snapshot and is not specifically preserved on update (nor is it deleted by `--update`).

### 3.3. Snapshot format (for reference / manual backup)

`DEFAULT_SNAPSHOT_ROOT = /var/lib/aegis/snapshots`. Snapshot directory: `<compact-ISO>_<reason-slug>`, e.g. `2026-05-22T12-00-00_pre-v0.2.0/`. Inside, `manifest.json` (when, why, version, list of files with sizes) plus the `etc/…` and `var/…` trees. GC keeps the last `keep_count` snapshots (default 5), dropping the oldest beyond the limit.

> The practical equivalent today: before updating, simply copy `/etc/aegis` and the required `*.json` files from `/var/lib/aegis` (see the list above) — that is your manual snapshot. More on these files: [04-configuration.md](04-configuration.md), [26-sites-and-domains.md](26-sites-and-domains.md).

---

## 4. The `install.sh --update` flow

This is **the only supported way to apply an update**. It is run by the operator on the host as root.

```bash
# on the host, inside the source tree or with AEGIS_SRC passed through
sudo bash install.sh --update
```

The dispatcher at the end of `install.sh`:

```sh
if [ "$MODE_FLAG" = "update" ]; then
    update_only
    exit 0
fi
```

### 4.1. What `update_only()` does

1. `require_root` — root is mandatory.
2. Check `[ -d "$AEGIS_SRC/.git" ]` — otherwise fatal "run full install first" (an update only works on top of an existing git tree).
3. `build_and_install` → internally `sync_source_tree` (see 4.2) + the build.
4. `ensure_ui_env_dropin` — the `--update` path **never rewrites unit files** (`write_systemd_unit`), so the env file with the UI feature flags and the drop-in are guaranteed separately, so that the panel's toggles take effect after the restart.
5. Config validation: `"$AEGIS_BIN" -c "$AEGIS_ETC/aegis.conf" -t`.
6. Restart (see 4.3).
7. `sleep 1` + a `systemctl is-active` check; on failure — fatal with a `journalctl -u <svc> -n 30` hint.

### 4.2. git fetch → checkout → reset (`sync_source_tree`)

Defaults: `AEGIS_REPO=https://github.com/tnAnGel/Aegis.git`, `AEGIS_VERSION=main`, `AEGIS_SRC=/usr/local/src/aegis`.

```sh
# reclaim ownership (Git 2.35+ complains about "dubious ownership" on someone else's repo)
chown -R root:root "$AEGIS_SRC"
git config --global --add safe.directory "$AEGIS_SRC"

# GIT_TERMINAL_PROMPT=0 → no hang on a login prompt under curl|sudo bash
if GIT_TERMINAL_PROMPT=0 git -C "$AEGIS_SRC" fetch --tags --quiet; then
    git -C "$AEGIS_SRC" checkout --quiet "$AEGIS_VERSION"          || warn "checkout failed — staying on HEAD"
    git -C "$AEGIS_SRC" reset --hard --quiet "origin/$AEGIS_VERSION" \
        || git -C "$AEGIS_SRC" reset --hard --quiet "$AEGIS_VERSION" || warn "reset failed — building local HEAD"
else
    warn "git fetch failed — building from local HEAD: <last commit>"
fi
```

Key properties:

- **`reset --hard`** means any local edits in `$AEGIS_SRC` will be wiped. Customisation must live in `/etc/aegis`, not in the source tree.
- **Degradation without network**: if `fetch` failed (network/authentication), the installer does not abort but builds from the local HEAD with a warning.
- **Private repo**: if a `clone` is needed (no `.git`) and the repo is private — fatal, with a hint to set `AEGIS_REPO` with a token (`https://user:token@host/repo.git`) or to unpack the tree manually and set `AEGIS_SRC_OVERRIDE=/path`.
- `AEGIS_SRC_OVERRIDE` — point at a ready tree; git operations are then **not performed** at all.

Controlling variables:

| Variable | Purpose | Default |
|------------|-----------|---------|
| `AEGIS_REPO` | git repository URL | `https://github.com/tnAnGel/Aegis.git` |
| `AEGIS_VERSION` | branch or tag to checkout/reset (`--version` also works) | `main` |
| `AEGIS_SRC` | Source tree path | `/usr/local/src/aegis` |
| `AEGIS_SRC_OVERRIDE` | Ready tree, no git operations | (not set) |
| `AEGIS_MODE` | `pingora` (default) \| `hyper` \| `both` | `pingora` |
| `AEGIS_BUILD_OPT` | `max` → fat LTO + codegen-units=1 (slow, max perf) | (not set → thin LTO, cgu16, incremental) |
| `AEGIS_TARGET_CPU` | `native` (default) \| `generic` \| microarch | `native` |
| `AEGIS_ENABLE_XDP` | `auto` \| `1` \| `0` | `auto` |

### 4.3. build → rebuild

`build_and_install`:
- `sync_source_tree` (see above);
- best-effort installation of `mold` (on `--update`, `install_packages` is not called, so the linker is pulled in here);
- build profile: by default thin LTO / codegen-units=16 / incremental; `AEGIS_BUILD_OPT=max` → fat LTO + codegen-units=1;
- building the binaries required by `AEGIS_MODE`:
  - `build_aegis_hyper` → `cargo build --release --bin aegis`, installs into `$AEGIS_BIN` (`/usr/local/bin/aegis`);
  - `build_aegis_pingora` → `cargo build --release --bin aegis-pingora --features "pingora[ xdp]"`, installs into `$AEGIS_PINGORA_BIN`, applies `setcap cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep`;
  - `build_xdp_object` (if `AEGIS_ENABLE_XDP=1`) → nightly + `bpfel-unknown-none`, installs `aegis-xdp.o`.

> Details of the build profile and CPU tuning — [27-performance-tuning.md](27-performance-tuning.md). On XDP — [13-xdp-ebpf.md](13-xdp-ebpf.md).

### 4.4. rolling restart

After the build, `update_only` restarts the service:

```sh
if [ "$AEGIS_MODE" = "hyper" ]; then
    systemctl restart aegis
else
    systemctl restart aegis-pingora.target    # fans out to all template instances
fi
```

This is a **full** restart of the target. For near-zero downtime there is a separate rolling mechanism installed by the installer (`ensure_restart_watcher`) and triggered by the "Restart" button in the panel:

- the script `/usr/local/bin/aegis-rolling-restart` enumerates `aegis-pingora@*.service` and, when `count > 1`, restarts workers one at a time with `sleep 3` between them — the neighbours keep the listening sockets (SO_REUSEPORT), so downtime is nearly zero; when `count <= 1` (hyper or a single worker) it falls back to `systemctl restart aegis-pingora.target`;
- the panel writes a marker file `$AEGIS_HOME/.restart-request`, and the root-owned path watcher `aegis-restart.path` → `aegis-restart.service` (`Type=oneshot`) performs the rolling restart from a separate cgroup that survives the target going down. `PathExists` (not `Modified`) → the marker fires exactly once and is removed (`ExecStartPre=-rm -f <marker>`), with no boot-time loop;
- the unit dependency is deliberately `Wants=` (not `Requires=`): restarting one worker does **not** take down the target and its neighbours (see the commit "restart: target Wants=…").

> More on multi-process operation and SO_REUSEPORT — [06-workers.md](06-workers.md). On operations and the Restart button — [03-installation.md](03-installation.md), [29-admin-panel.md](29-admin-panel.md).

---

## 5. Self-update lag: `install.sh` updates itself

A subtle but important point. `install.sh` lives **inside** the source tree that `--update` wipes via `reset --hard`. So, during `--update`:

1. you run the **current** (old) version of `install.sh` on the host;
2. it does `git fetch` + `reset --hard` — the **new** version of `install.sh` lands on disk;
3. but the current process is already executing from the old code — it **does not re-read** the updated script during this run.

Consequences and recommendations:

- If the installation/restart/unit-file logic changed in the new version, it will be applied **only from the next** run of `install.sh`.
- The canonical way to get a guaranteed-fresh installer is to fetch it again via `curl`:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash -s -- --update
  ```
  here the script is downloaded from the branch on the fly, so there is no lag — the new version is what runs (and it then syncs the tree). For critical major transitions this is the preferred path.
- The local `sudo bash install.sh --update` is more convenient (no network needed for the script itself), but remember the one-iteration lag.

---

## 6. Migrations

The codebase has **no separate schema migration framework** with versioned steps. A "migration" in AEGIS is made up of several mechanisms, each of which must be understood honestly:

| Mechanism | How it migrates | Source |
|----------|---------------|--------|
| Config (`aegis.conf`) | The parser is tolerant of unknown/missing directives; new fields have defaults. After `--update`, validation via `aegis -c … -t` is mandatory | `update_only` (step 5) |
| State files (`*.json`) | serde with `#[serde(default)]` on new fields → old JSON is read, missing values are filled with defaults | e.g. `Release`/`UpdateConfig` in `updates.rs` |
| systemd unit files | `--update` **does not rewrite them**; they change only on a full install (`write_systemd_unit`). Changes to the template/target require a manual `systemctl daemon-reload && systemctl restart aegis-pingora.target` | `update_only`, comments in `install.sh` |
| UI feature-flag env | `ensure_ui_env_dropin` creates/extends a writable env file + drop-in on every install/update (idempotently), so the panel's toggles survive the update | `update_only` (step 4) |
| Mtime-polled state | The daemon hot-reloads changed files by mtime without a restart — new/changed `*.json`/`*.conf` are picked up within ~1s | see [06-workers.md](06-workers.md) |

Practical consequences for a large upgrade:
- always run `aegis -c /etc/aegis/aegis.conf -t` **before** the restart (`update_only` does this too);
- if you changed unit files (a new template, a new target, a changed `AEGIS_MODE`) — perform a full install rather than `--update`, or run `daemon-reload` by hand;
- the `admin-token` and `hmac-secret` secrets **need not and must not** be changed during an update — losing them logs operators out and invalidates challenge tokens.

---

## 7. Rollback

Rollback is **manual** too — there is **no** automatic rollback (as in the former `update_apply.rs` with a health probe and reverse symlink switch) after V233, because the applier that ran it is gone as well.

Since `--update` builds from the git tree, rollback = return the tree to the previous version and rebuild.

### 7.1. Rolling back the binary (sources)

```bash
# pick a known-good tag/commit and build from it
sudo AEGIS_VERSION=v0.1.5 bash install.sh --update
# or by hand in the tree:
sudo git -C /usr/local/src/aegis checkout v0.1.5
sudo bash install.sh --update      # reset --hard origin/<branch> may bring HEAD back —
                                   # for pins use AEGIS_VERSION=<tag>
```

> Caution: with `AEGIS_VERSION=<branch>` the `reset --hard origin/<branch>` step will pull the branch tip again. To pin to a specific point, set `AEGIS_VERSION=<tag>` or a committed SHA — then checkout/reset will target exactly that.

### 7.2. Rolling back config/state

If you made a manual backup of `/etc/aegis` and the `*.json` files from `/var/lib/aegis` before the update (see section 3) — simply put the files back and do a rolling restart. This is the semantic equivalent of `SnapshotManager::restore` (in-place file overwrite per the manifest), but performed by hand.

### 7.3. After any rollback

```bash
aegis -c /etc/aegis/aegis.conf -t          # config validation
sudo /usr/local/bin/aegis-rolling-restart  # near-zero downtime, or:
sudo systemctl restart aegis-pingora.target
systemctl is-active aegis-pingora.target
journalctl -u aegis-pingora@0 -n 30        # if something is wrong
```

---

## 8. Safe-update checklist

1. **Back up** `/etc/aegis` + the required `*.json` files from `/var/lib/aegis` (section 3) — that is your "snapshot".
2. Record the current working version/tag (for a possible rollback).
3. Update: `curl …/install.sh | sudo bash -s -- --update` (no self-update lag) **or** the local `sudo bash install.sh --update`.
4. Wait for the `aegis -c … -t` validation (the installer does it) — on a config error it will stop before the restart.
5. Check `systemctl is-active` and the panel.
6. If there is a problem — roll back per section 7.

---

## See also

- [03-installation.md](03-installation.md) — installation, the Restart button, operations.
- [04-configuration.md](04-configuration.md) — `aegis.conf`, env, validation.
- [06-workers.md](06-workers.md) — SO_REUSEPORT, rolling restart, mtime polling.
- [23-security-model.md](23-security-model.md) — why in-panel apply was removed (RCE class).
- [29-admin-panel.md](29-admin-panel.md), [30-admin-api.md](30-admin-api.md) — UI and the `/admin/api/updates/*` routes.
- 42-текущее-состояние-STATUS.md — feature status, what is opt-in/partial.
