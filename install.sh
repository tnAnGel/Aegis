#!/usr/bin/env bash
# Aegis installer / updater. Single-command bootstrap for any Linux box.
#
# Default mode (pingora + XDP) ships the V72+ production stack:
#   * aegis-pingora binary as the data plane (V71 cutover — beats nginx
#     +16% on HTTP c=400, +36% on TLS h2 c=400)
#   * eBPF XDP fast-path with PerCpu counters + first-byte WAF triage
#   * SO_REUSEPORT N=workers layout (V230: nproc workers × 1 thread,
#     each pinned 1:1 to a CPU — thread-per-core, no scheduler float)
#   * Threat-aware response cache + dynamic trust + honeypot tarpit
#   * Web admin UI on port 6280 (initial creds auto-generated + printed)
#
# Usage:
#     curl -fsSL https://raw.githubusercontent.com/tnAnGel/Aegis/main/install.sh | sudo bash
#
# or (after downloading):
#     sudo bash install.sh                 # install / update (pingora + XDP)
#     sudo bash install.sh --mode hyper    # legacy hyper-only mode
#     sudo bash install.sh --mode both     # both binaries (pingora primary)
#     sudo bash install.sh --no-xdp        # skip eBPF (no nightly toolchain)
#     sudo bash install.sh --workers 8     # override REUSEPORT instance count
#     sudo bash install.sh --uninstall     # stop + remove, keep /etc/aegis
#     sudo bash install.sh --purge         # uninstall + delete state dirs
#     sudo bash install.sh --update        # pull + rebuild + restart
#     sudo bash install.sh --version v1.0  # install a specific branch / tag
#
# The script is idempotent — re-running it upgrades to the current
# branch tip and leaves /etc/aegis untouched if it already exists.
# Web admin password is preserved across re-runs (regenerated only on
# first install or after --purge).

set -euo pipefail

# ----------------------------------------------------------------------
# Defaults — operators can override via env vars before piping into sh:
#     AEGIS_VERSION=v0.2 AEGIS_PORT_HTTP=8080 bash install.sh
# ----------------------------------------------------------------------
: "${AEGIS_REPO:=https://github.com/tnAnGel/Aegis.git}"
: "${AEGIS_VERSION:=main}"
: "${AEGIS_USER:=aegis}"
: "${AEGIS_HOME:=/var/lib/aegis}"
: "${AEGIS_ETC:=/etc/aegis}"
: "${AEGIS_BIN:=/usr/local/bin/aegis}"
: "${AEGIS_PINGORA_BIN:=/usr/local/bin/aegis-pingora}"
: "${AEGIS_XDP_OBJ:=/var/lib/aegis/aegis-xdp.o}"
: "${AEGIS_SRC:=/usr/local/src/aegis}"
: "${AEGIS_PORT_HTTP:=80}"
: "${AEGIS_PORT_HTTPS:=443}"
: "${AEGIS_PORT_ADMIN:=6280}"
: "${AEGIS_LOG_DIR:=/var/log/aegis}"
: "${AEGIS_SKIP_FIREWALL:=0}"
: "${AEGIS_SKIP_RUST_INSTALL:=0}"
: "${AEGIS_SKIP_NODE_INSTALL:=0}"
: "${AEGIS_MODE:=pingora}"          # pingora (default) | hyper | both
: "${AEGIS_ENABLE_XDP:=auto}"       # auto (default) | 1 | 0
: "${AEGIS_WORKERS:=auto}"          # auto = max(1, nproc/4) | explicit N
: "${AEGIS_XDP_IFACE:=auto}"        # auto = first non-lo UP iface | explicit

SCRIPT_NAME="aegis-install"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()   { printf "${BLUE}[%s]${NC} %s\n"  "$SCRIPT_NAME" "$*"; }
ok()    { printf "${GREEN}[%s] ok:${NC} %s\n" "$SCRIPT_NAME" "$*"; }
warn()  { printf "${YELLOW}[%s] warn:${NC} %s\n" "$SCRIPT_NAME" "$*" >&2; }
fatal() { printf "${RED}[%s] error:${NC} %s\n" "$SCRIPT_NAME" "$*" >&2; exit 1; }

# ----------------------------------------------------------------------
# Sub-command parsing
# ----------------------------------------------------------------------
MODE_FLAG=install
while [ "$#" -gt 0 ]; do
    case "$1" in
        --uninstall) MODE_FLAG=uninstall ;;
        --purge)     MODE_FLAG=purge ;;
        --update)    MODE_FLAG=update ;;
        --version)   AEGIS_VERSION="$2"; shift ;;
        --mode)      AEGIS_MODE="$2"; shift ;;
        --no-xdp)    AEGIS_ENABLE_XDP=0 ;;
        --xdp)       AEGIS_ENABLE_XDP=1 ;;
        --workers)   AEGIS_WORKERS="$2"; shift ;;
        --xdp-iface) AEGIS_XDP_IFACE="$2"; shift ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) fatal "unknown arg: $1 (use --help)" ;;
    esac
    shift
done

case "$AEGIS_MODE" in
    pingora|hyper|both) ;;
    *) fatal "invalid --mode: $AEGIS_MODE (expected: pingora|hyper|both)" ;;
esac

# ----------------------------------------------------------------------
# Pre-flight checks
# ----------------------------------------------------------------------
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        fatal "must run as root (try: sudo bash install.sh)"
    fi
}

detect_os() {
    if [ ! -f /etc/os-release ]; then
        fatal "cannot detect OS — /etc/os-release missing"
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    case "$OS_ID" in
        debian|ubuntu) PKG=apt ;;
        fedora|rhel|centos|rocky|almalinux) PKG=dnf ;;
        alpine) PKG=apk ;;
        *)
            warn "untested OS: $OS_ID — proceeding optimistically"
            PKG=unknown
            ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) fatal "unsupported architecture: $(uname -m)" ;;
    esac
    KERNEL_VERSION=$(uname -r | awk -F. '{printf "%d.%d", $1, $2}')
    log "detected: $OS_ID $OS_VERSION / $ARCH / linux $KERNEL_VERSION (pkg=$PKG, mode=$AEGIS_MODE)"
}

resolve_xdp_enable() {
    # If user didn't force, decide based on what's possible:
    #   * hyper-only mode → skip XDP regardless (XDP is wired via the
    #     pingora data plane)
    #   * kernel < 4.18 → skip (aya-ebpf XDP support starts there)
    #   * otherwise → enable
    if [ "$AEGIS_MODE" = "hyper" ]; then
        AEGIS_ENABLE_XDP=0
        log "AEGIS_MODE=hyper → XDP disabled (data plane is hyper-only)"
        return
    fi
    if [ "$AEGIS_ENABLE_XDP" = "auto" ]; then
        local maj min
        maj=$(uname -r | cut -d. -f1)
        min=$(uname -r | cut -d. -f2)
        if [ "$maj" -gt 4 ] || { [ "$maj" -eq 4 ] && [ "$min" -ge 18 ]; }; then
            AEGIS_ENABLE_XDP=1
        else
            AEGIS_ENABLE_XDP=0
            warn "linux $KERNEL_VERSION < 4.18 — XDP disabled (need ≥ 4.18 for aya)"
        fi
    fi
    log "XDP fast-path: $([ "$AEGIS_ENABLE_XDP" = "1" ] && echo enabled || echo disabled)"
}

resolve_workers() {
    # V230 — thread-per-core layout. With the NoSteal pingora runtime
    # the right shape is N workers × 1 thread, each pinned 1:1 to a
    # CPU via systemd CPUAffinity. The previous 4×4 layout left the
    # kernel scheduler floating threads across all cores and shredded
    # L1/L2 locality. Matches the nginx/envoy/HAProxy thread-per-core
    # pattern. CPU pinning is wired up in write_systemd_unit_pingora
    # and enable_and_start (instances are numbered 0..N-1 so the
    # template's CPUAffinity=%i maps directly to CPU index).
    # V232 — when --workers isn't given explicitly, honour the desired
    # count the admin panel recorded in the topology state file (the
    # panel's Workers page writes {"workers":"auto"|"N"} there via
    # PUT /admin/api/topology). CLI --workers always wins over it.
    local topo_file=/var/lib/aegis/topology.json
    if [ "$AEGIS_WORKERS" = "auto" ] && [ -f "$topo_file" ]; then
        # Minimal JSON scrape — the file is a flat {"workers":"..."}.
        local panel_workers
        panel_workers=$(grep -oE '"workers"[[:space:]]*:[[:space:]]*"[^"]*"' "$topo_file" \
            | head -1 | grep -oE '"[^"]*"$' | tr -d '"')
        if [ -n "$panel_workers" ]; then
            AEGIS_WORKERS=$panel_workers
            log "pingora topology: applying panel-set worker count '${panel_workers}' from ${topo_file}"
        fi
    fi
    if [ "$AEGIS_WORKERS" = "auto" ]; then
        local cpus
        cpus=$(nproc 2>/dev/null || echo 1)
        AEGIS_WORKERS=$cpus
        AEGIS_THREADS_PER_WORKER=1
    else
        # V230 — operator-provided / panel-set --workers still gets the
        # thread-per-core default (1 thread/worker) for sane pinning.
        AEGIS_THREADS_PER_WORKER=1
    fi
    log "pingora topology: ${AEGIS_WORKERS} workers × ${AEGIS_THREADS_PER_WORKER} thread (CPU-pinned)"
}

resolve_xdp_iface() {
    if [ "$AEGIS_ENABLE_XDP" != "1" ]; then
        return
    fi
    if [ "$AEGIS_XDP_IFACE" = "auto" ]; then
        # First non-loopback interface in UP state. ip -br link cleanly
        # lists exactly what we want.
        AEGIS_XDP_IFACE=$(ip -br link show 2>/dev/null \
            | awk '$1 != "lo" && $2 == "UP" {print $1; exit}' \
            | sed 's/@.*//' || true)
        if [ -z "$AEGIS_XDP_IFACE" ]; then
            warn "no UP interface found — XDP will fall back to skb-mode on whatever"
            AEGIS_XDP_IFACE="eth0"
        fi
    fi
    log "XDP attach interface: $AEGIS_XDP_IFACE"
}

install_node() {
    if [ "$AEGIS_SKIP_NODE_INSTALL" = "1" ]; then
        log "AEGIS_SKIP_NODE_INSTALL=1 — assuming node + pnpm are on PATH"
        return
    fi
    if command -v pnpm >/dev/null 2>&1; then
        log "pnpm already installed: $(pnpm --version)"
        return
    fi
    if ! command -v node >/dev/null 2>&1; then
        log "installing Node.js 20.x"
        case "$PKG" in
            apt)
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
                apt-get install -y nodejs >/dev/null
                ;;
            dnf)
                dnf module install -y nodejs:20 >/dev/null 2>&1 || dnf install -y nodejs >/dev/null
                ;;
            apk)
                apk add --no-cache nodejs npm >/dev/null
                ;;
            *)
                warn "skipping Node.js install (unknown pkg mgr); install nodejs ≥18 + pnpm before --update"
                return
                ;;
        esac
    fi
    log "installing pnpm 10 (npm -g)"
    npm install -g pnpm@10 >/dev/null 2>&1 || fatal "npm install -g pnpm@10 failed"
}

install_packages() {
    # cmake is pulled in by libz-ng-sys (transitive dep of pingora-cache/
    # zstd). Without it the aegis-pingora release build fails late with
    # "is `cmake` not installed?". Adding it up-front avoids the cryptic
    # mid-build failure on clean Debian/Ubuntu boxes.
    local pkgs=(curl git pkg-config build-essential ca-certificates openssl cmake)
    case "$PKG" in
        apt)
            log "installing build deps via apt"
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                "${pkgs[@]}" libssl-dev clang llvm >/dev/null
            ;;
        dnf)
            log "installing build deps via dnf"
            dnf install -y -q gcc make pkgconfig openssl-devel git curl \
                ca-certificates clang llvm cmake >/dev/null
            ;;
        apk)
            log "installing build deps via apk"
            apk add --no-cache build-base pkgconfig openssl-dev git curl \
                ca-certificates clang llvm cmake >/dev/null
            ;;
        unknown)
            warn "skipping package install (unknown pkg mgr); ensure: gcc, cmake, git, pkg-config, openssl-dev, ca-certificates, clang, llvm"
            ;;
    esac
    # V246 — mold (multi-threaded linker) for faster builds. Best-effort: a
    # missing mold just falls back to the default linker, so never fail here.
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mold >/dev/null 2>&1 || true ;;
        dnf) dnf install -y -q mold >/dev/null 2>&1 || true ;;
        apk) apk add --no-cache mold >/dev/null 2>&1 || true ;;
    esac
    command -v mold >/dev/null 2>&1 && log "mold linker available — parallel linking enabled"
}

install_rust() {
    if [ "$AEGIS_SKIP_RUST_INSTALL" = "1" ]; then
        log "AEGIS_SKIP_RUST_INSTALL=1 — assuming cargo is on PATH"
        return
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        log "installing rustup + stable toolchain (this takes ~2 min)"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain stable --profile minimal
        # shellcheck disable=SC1090
        . "$HOME/.cargo/env"
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        log "cargo already installed: $(cargo --version)"
    fi

    if [ "$AEGIS_ENABLE_XDP" = "1" ]; then
        local nightly_marker="/root/.rustup/toolchains/nightly-$(uname -m)-unknown-linux-gnu"
        if [ ! -d "$nightly_marker" ]; then
            log "installing rust nightly + rust-src (for eBPF build-std)"
            rustup install nightly --profile minimal --no-self-update >/dev/null
            rustup component add rust-src --toolchain nightly >/dev/null
        else
            log "rust nightly already present"
        fi
        # aya 0.13's bpfel-unknown-none target build requires the
        # `bpf-linker` binary (it knows how to emit the BPF ELF format
        # that the kernel verifier accepts). It's a separate cargo
        # crate; install if missing. Slow first time (~1-2 min); cached
        # in /root/.cargo/bin afterwards.
        if ! command -v bpf-linker >/dev/null 2>&1; then
            log "installing bpf-linker (cargo install, ~1-2 min)"
            cargo install bpf-linker --locked >/dev/null 2>&1 \
                || cargo install bpf-linker >/dev/null \
                || warn "bpf-linker install failed — eBPF build will fail; retry with --no-xdp"
        else
            log "bpf-linker already present"
        fi
    fi
}

create_user() {
    if id -u "$AEGIS_USER" >/dev/null 2>&1; then
        log "system user '$AEGIS_USER' already exists"
        return
    fi
    log "creating system user '$AEGIS_USER'"
    useradd --system --home-dir "$AEGIS_HOME" --create-home \
        --shell /usr/sbin/nologin "$AEGIS_USER"
}

sync_source_tree() {
    # AEGIS_SRC_OVERRIDE lets the operator point the installer at an
    # already-checked-out tree (useful for air-gapped installs and
    # local development where the source is e.g. on a bind-mount or
    # rsync target). When set, we skip every git operation entirely
    # and just verify the tree contains a Cargo.toml.
    if [ -n "${AEGIS_SRC_OVERRIDE:-}" ]; then
        [ -f "${AEGIS_SRC_OVERRIDE}/Cargo.toml" ] \
            || fatal "AEGIS_SRC_OVERRIDE=$AEGIS_SRC_OVERRIDE has no Cargo.toml"
        AEGIS_SRC="$AEGIS_SRC_OVERRIDE"
        log "using AEGIS_SRC_OVERRIDE=$AEGIS_SRC (no git operations)"
        return
    fi
    log "syncing source tree to $AEGIS_SRC (ref: $AEGIS_VERSION)"
    # Git 2.35+ refuses to operate on a repo owned by a different user
    # ("detected dubious ownership"). When the installer was previously
    # run by a non-root user (or the operator unpacked a tarball as a
    # different user), this kills `--update`. We always reclaim
    # ownership to root since the installer runs as root and the
    # daemon doesn't need to write to the source tree.
    if [ -d "$AEGIS_SRC" ]; then
        chown -R root:root "$AEGIS_SRC" 2>/dev/null || true
    fi
    git config --global --add safe.directory "$AEGIS_SRC" 2>/dev/null || true
    # GIT_TERMINAL_PROMPT=0 turns "could not read Username for ..." prompts
    # into clean failures we can branch on (instead of hanging forever
    # under `curl | sudo bash`).
    if [ -d "$AEGIS_SRC/.git" ]; then
        if GIT_TERMINAL_PROMPT=0 git -C "$AEGIS_SRC" fetch --tags --quiet 2>/dev/null; then
            git -C "$AEGIS_SRC" checkout --quiet "$AEGIS_VERSION" 2>/dev/null \
                || warn "checkout $AEGIS_VERSION failed — staying on current HEAD"
            git -C "$AEGIS_SRC" reset --hard --quiet "origin/$AEGIS_VERSION" 2>/dev/null \
                || git -C "$AEGIS_SRC" reset --hard --quiet "$AEGIS_VERSION" 2>/dev/null \
                || warn "reset failed — building from current local HEAD"
        else
            warn "git fetch failed (network or auth) — building from local HEAD: $(git -C "$AEGIS_SRC" log -1 --oneline)"
        fi
    else
        rm -rf "$AEGIS_SRC"
        mkdir -p "$(dirname "$AEGIS_SRC")"
        if ! GIT_TERMINAL_PROMPT=0 git clone --quiet --branch "$AEGIS_VERSION" \
                "$AEGIS_REPO" "$AEGIS_SRC" 2>/dev/null; then
            fatal "git clone of $AEGIS_REPO failed. Either:
    1. the repo is private — set AEGIS_REPO to a URL that auths
       (e.g. https://user:token@host/repo.git), or
    2. unpack the source manually and set AEGIS_SRC_OVERRIDE=/path/to/tree
       before re-running the installer."
        fi
    fi
}

build_frontend() {
    log "building React admin UI (web/dist gets embedded into the binary)"
    local pnpm_bin
    pnpm_bin="$(command -v pnpm || true)"
    if [ -z "$pnpm_bin" ]; then
        fatal "pnpm not on PATH; install Node 20 + pnpm 10 before retrying"
    fi
    # CI=true tells pnpm to proceed non-interactively (otherwise it
    # refuses to nuke an existing node_modules from a different arch
    # under `curl | sudo bash` since there's no TTY). Also covers the
    # "would you like to add this peer dep?" prompts.
    ( cd "$AEGIS_SRC/web" \
        && CI=true "$pnpm_bin" install --no-frozen-lockfile --reporter=silent \
        && CI=true "$pnpm_bin" build 2>&1 | tail -3 )
}

cargo_bin_path() {
    # sudo strips PATH; find cargo regardless of how we were invoked.
    local cargo_bin="/root/.cargo/bin/cargo"
    [ -x "$cargo_bin" ] || cargo_bin="$(command -v cargo || true)"
    [ -n "$cargo_bin" ] || fatal "cargo not on PATH — install rust first"
    echo "$cargo_bin"
}

# CPU codegen tuning. install.sh compiles ON the deploy host, so building for
# the build CPU is both safe and optimal: the binary only ever runs here.
# `native` enables every feature THIS CPU has — LSE single-instruction atomics
# on modern ARM (Graviton2+, Ampere, Apple, Neoverse), AVX2/BMI on modern x86
# — yielding a measurable hot-path uplift with zero SIGILL risk on older CPUs.
#
#   AEGIS_TARGET_CPU=native    (default) — optimal for THIS machine.
#   AEGIS_TARGET_CPU=generic            — portable; for build-once-deploy-many.
#   AEGIS_TARGET_CPU=neoverse-n1|x86-64-v3|...  — pin a specific microarch.
#
# We pass it through RUSTFLAGS (which overrides .cargo/config.toml's rustflags;
# the committed config intentionally hardcodes nothing). Any pre-set RUSTFLAGS
# from the environment is preserved and appended after ours.
: "${AEGIS_TARGET_CPU:=native}"
aegis_rustflags() {
    local flags=""
    if [ "$AEGIS_TARGET_CPU" != "generic" ] && [ -n "$AEGIS_TARGET_CPU" ]; then
        flags="-C target-cpu=$AEGIS_TARGET_CPU"
    fi
    # V246 — mold is a multi-threaded linker; the final link of the big
    # aegis-pingora binary is otherwise single-threaded (GNU ld) and a notable
    # chunk of each build. Use it when present (installed best-effort below).
    if command -v mold >/dev/null 2>&1; then
        flags="${flags:+$flags }-C link-arg=-fuse-ld=mold"
    fi
    if [ -n "${RUSTFLAGS:-}" ]; then
        flags="${flags:+$flags }$RUSTFLAGS"
    fi
    printf '%s' "$flags"
}

build_aegis_hyper() {
    log "building aegis (hyper data plane + CLI, release; ~3-5 min on first build)"
    local cargo
    cargo="$(cargo_bin_path)"
    log "  codegen target-cpu=$AEGIS_TARGET_CPU"
    ( cd "$AEGIS_SRC" && RUSTFLAGS="$(aegis_rustflags)" "$cargo" build --release --bin aegis 2>&1 | tail -3 )
    install -m 0755 -o root -g root "$AEGIS_SRC/target/release/aegis" "$AEGIS_BIN"
    ok "aegis installed at $AEGIS_BIN ($($AEGIS_BIN --version 2>/dev/null || echo unknown))"
}

build_aegis_pingora() {
    log "building aegis-pingora (V72+ data plane, release; ~5-8 min on first build)"
    local cargo
    cargo="$(cargo_bin_path)"
    local features="pingora"
    if [ "$AEGIS_ENABLE_XDP" = "1" ]; then
        features="pingora xdp"
    fi
    log "  codegen target-cpu=$AEGIS_TARGET_CPU"
    ( cd "$AEGIS_SRC" && RUSTFLAGS="$(aegis_rustflags)" "$cargo" build --release --bin aegis-pingora \
        --features "$features" 2>&1 | tail -3 )
    install -m 0755 -o root -g root \
        "$AEGIS_SRC/target/release/aegis-pingora" "$AEGIS_PINGORA_BIN"
    # Bind to privileged ports without granting root — file capability
    # survives across exec so the systemd template unit can drop to the
    # aegis user.
    setcap 'cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep' \
        "$AEGIS_PINGORA_BIN" 2>/dev/null || \
        warn "setcap failed; pingora workers will need to run as root for :80/:443"
    ok "aegis-pingora installed at $AEGIS_PINGORA_BIN ($($AEGIS_PINGORA_BIN --version 2>/dev/null || echo unknown))"
}

build_xdp_object() {
    if [ "$AEGIS_ENABLE_XDP" != "1" ]; then
        return
    fi
    log "building eBPF XDP fast-path object (nightly + bpfel-unknown-none)"
    local cargo="/root/.cargo/bin/cargo"
    [ -x "$cargo" ] || cargo="$(command -v cargo)"
    # The eBPF crate is a separate workspace with its own .cargo/config.toml
    # pinning the bpfel-unknown-none target and -Z build-std=core.
    ( cd "$AEGIS_SRC/xdp/aegis-xdp-ebpf" && \
        "$cargo" +nightly build --release 2>&1 | tail -3 )
    local obj="$AEGIS_SRC/xdp/aegis-xdp-ebpf/target/bpfel-unknown-none/release/aegis-xdp"
    [ -f "$obj" ] || fatal "eBPF build did not produce $obj"
    install -m 0644 -o root -g root "$obj" "$AEGIS_XDP_OBJ"
    ok "eBPF object installed at $AEGIS_XDP_OBJ ($(stat -c %s "$AEGIS_XDP_OBJ" 2>/dev/null || echo ?) bytes)"
}

build_and_install() {
    sync_source_tree
    # V246 — ensure the mold linker is present (install_packages runs only on a
    # fresh install, not on --update; this path covers both). Idempotent + best-effort.
    if ! command -v mold >/dev/null 2>&1; then
        case "$PKG" in
            apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mold >/dev/null 2>&1 || true ;;
            dnf) dnf install -y -q mold >/dev/null 2>&1 || true ;;
            apk) apk add --no-cache mold >/dev/null 2>&1 || true ;;
        esac
    fi
    # V246 — opt-in max-optimization build. Default is the fast parallel profile
    # (thin LTO, codegen-units=16, incremental) from Cargo.toml; set
    # AEGIS_BUILD_OPT=max to re-tighten to fat LTO + single codegen unit for the
    # absolute fastest binary (slow, mostly single-threaded — for cutting a real
    # release, not for routine --update).
    if [ "${AEGIS_BUILD_OPT:-}" = "max" ]; then
        export CARGO_PROFILE_RELEASE_LTO=fat
        export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
        export CARGO_PROFILE_RELEASE_INCREMENTAL=false
        log "AEGIS_BUILD_OPT=max → fat LTO + codegen-units=1 (slow build, max-perf binary)"
    else
        log "build profile: fast parallel (thin LTO, codegen-units=16, incremental) — set AEGIS_BUILD_OPT=max for max-perf"
    fi
    build_frontend
    case "$AEGIS_MODE" in
        hyper)
            build_aegis_hyper
            ;;
        pingora)
            # Need the hyper binary too — `aegis web reset-admin` and
            # other CLI tools live there and operate on the shared
            # state file the pingora daemon reads.
            build_aegis_hyper
            build_aegis_pingora
            build_xdp_object
            ;;
        both)
            build_aegis_hyper
            build_aegis_pingora
            build_xdp_object
            ;;
    esac
}

# V241 — UI-managed feature-flag plumbing. The web panel (PUT /admin/api/env)
# writes feature-flag toggles to a SEPARATE writable env file under $AEGIS_HOME
# (in ReadWritePaths, owned by the service user), kept apart from the read-only
# /etc/aegis/aegis.env so ProtectSystem=strict + ReadOnlyPaths=$AEGIS_ETC still
# hold — a compromised daemon cannot rewrite its own config, certs, or token.
#
# Wired via a systemd DROP-IN (not the unit template) so it applies on BOTH
# fresh installs and `--update` (which never rewrites unit files) and survives
# future template rewrites. The drop-in:
#   * sources $AEGIS_HOME/aegis-ui.env AFTER /etc/aegis/aegis.env, so panel
#     toggles override operator defaults;
#   * sets AEGIS_ENV_FILE so the in-process writer targets the writable file.
# Idempotent: safe to call on every install/update.
ensure_ui_env_dropin() {
    local uienv="$AEGIS_HOME/aegis-ui.env"
    if [ ! -f "$uienv" ]; then
        cat > "$uienv" <<EOF
# Feature-flag overrides written by the Aegis web panel (PUT /admin/api/env).
# Sourced AFTER /etc/aegis/aegis.env, so values here override operator defaults.
# Manage via the panel; manual edits are fine too (one KEY=VALUE per line).
# Apply changes with: systemctl restart aegis-pingora.target
EOF
        chmod 0640 "$uienv"
        chown "$AEGIS_USER":"$AEGIS_USER" "$uienv"
    fi
    # Drop-in for the pingora template instances (and the hyper unit in
    # hyper/both mode). Same content for both — they share the env model.
    local body="[Service]
EnvironmentFile=-$uienv
Environment=AEGIS_ENV_FILE=$uienv
"
    local d
    for d in /etc/systemd/system/aegis-pingora@.service.d /etc/systemd/system/aegis.service.d; do
        mkdir -p "$d"
        printf '%s' "$body" > "$d/10-aegis-ui-env.conf"
        chmod 0644 "$d/10-aegis-ui-env.conf"
    done
    systemctl daemon-reload 2>/dev/null || true
    log "UI-managed env file + systemd drop-in in place ($uienv)"
    ensure_restart_watcher
    ensure_geoip_db
    ensure_reputation_feeds
    ensure_nginx_for_benchmark
    ensure_benchmark_proxies
}

# V245 — install nginx purely so the panel's "vs nginx" benchmark can launch an
# ephemeral nginx for a head-to-head throughput comparison. We do NOT want nginx
# running as a service (it would grab :80 from AEGIS), so we disable+stop the
# system unit immediately — the benchmark invokes the binary ad-hoc on a
# loopback port with its own temp config. Best-effort: never fail the install.
ensure_nginx_for_benchmark() {
    if command -v nginx >/dev/null 2>&1; then
        systemctl disable --now nginx >/dev/null 2>&1 || true
        return 0
    fi
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx-light >/dev/null 2>&1 || true ;;
        dnf) dnf install -y -q nginx >/dev/null 2>&1 || true ;;
        apk) apk add --no-cache nginx >/dev/null 2>&1 || true ;;
        *)   : ;;
    esac
    # Free :80 — AEGIS owns it. The benchmark uses the binary, not the service.
    systemctl disable --now nginx >/dev/null 2>&1 || true
    if command -v nginx >/dev/null 2>&1; then
        log "nginx installed for the comparison benchmark (service disabled)"
    else
        log "WARN: nginx not installed — the vs-nginx benchmark will show 'nginx unavailable'"
    fi
}

# Install the comparison proxies the multi-proxy benchmark launches ad-hoc:
# HAProxy, Caddy, nginx+ModSecurity+CRS, and Envoy. Same contract as
# ensure_nginx_for_benchmark: install the binary, then DISABLE+STOP any system
# unit so it never holds :80/:443 (the benchmark spawns its own ephemeral
# loopback instances with private temp configs). Everything is BEST-EFFORT — a
# proxy that fails to install simply makes that benchmark target report
# available:false; it must NEVER fail the install. Runs on fresh install AND
# --update because it is reached via ensure_nginx_for_benchmark's caller.
ensure_benchmark_proxies() {
    ensure_haproxy_for_benchmark
    ensure_caddy_for_benchmark
    ensure_modsec_for_benchmark
    ensure_envoy_for_benchmark
}

# HAProxy — plain L4/L7 reverse proxy (no WAF). Debian 12 ships 2.6.x in the
# default repo. The .deb postinst enables+starts the service against the stock
# root-only /etc/haproxy/haproxy.cfg, so we disable+stop it; the benchmark runs
# `haproxy -db -f <tmp>.cfg` unprivileged on a loopback port instead.
ensure_haproxy_for_benchmark() {
    if command -v haproxy >/dev/null 2>&1; then
        systemctl disable --now haproxy.service >/dev/null 2>&1 || true
        return 0
    fi
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq haproxy >/dev/null 2>&1 || true ;;
        dnf) dnf install -y -q haproxy >/dev/null 2>&1 || true ;;
        apk) apk add --no-cache haproxy >/dev/null 2>&1 || true ;;
        *)   : ;;
    esac
    systemctl disable --now haproxy.service >/dev/null 2>&1 || true
    if command -v haproxy >/dev/null 2>&1 \
       || [ -x /usr/sbin/haproxy ] || [ -x /usr/bin/haproxy ]; then
        log "HAProxy installed for the comparison benchmark (service disabled)"
    else
        log "WARN: HAProxy not installed — that benchmark target will show 'unavailable'"
    fi
}

# Caddy — plain reverse proxy (no WAF in the apt build). Debian 12 ships 2.6.x.
# The .deb installs BOTH caddy.service AND caddy-api.service; neither is enabled
# by default, but caddy-api (`caddy run --resume`) could independently bind
# ports, so we stop+disable+MASK both. The benchmark runs `caddy run` ad-hoc.
ensure_caddy_for_benchmark() {
    if command -v caddy >/dev/null 2>&1; then
        systemctl stop    caddy caddy-api >/dev/null 2>&1 || true
        systemctl disable caddy caddy-api >/dev/null 2>&1 || true
        systemctl mask    caddy caddy-api >/dev/null 2>&1 || true
        return 0
    fi
    case "$PKG" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null 2>&1 || true ;;
        dnf) dnf install -y -q caddy >/dev/null 2>&1 || true ;;
        apk) apk add --no-cache caddy >/dev/null 2>&1 || true ;;
        *)   : ;;
    esac
    # Mask BOTH units so neither can grab :80/:443/:2019 — AEGIS owns those.
    systemctl stop    caddy caddy-api >/dev/null 2>&1 || true
    systemctl disable caddy caddy-api >/dev/null 2>&1 || true
    systemctl mask    caddy caddy-api >/dev/null 2>&1 || true
    if command -v caddy >/dev/null 2>&1; then
        log "Caddy installed for the comparison benchmark (service masked)"
    else
        log "WARN: Caddy not installed — that benchmark target will show 'unavailable'"
    fi
}

# nginx + ModSecurity v3 (libmodsecurity3) + OWASP CRS — the ONE comparison
# target that actually blocks L7 attacks (the benchmark arms it with
# SecRuleEngine On + the CRS loader in its ephemeral config). On Debian 12 all
# pieces come from apt: the dynamic connector module, the engine, and the rule
# set. The connector links libmodsecurity3 at runtime (already a dep). We keep
# nginx's own service disabled (ensure_nginx_for_benchmark already does that).
# After install we run a 1-line dlopen smoke-test so a PCRE/ABI version skew
# (Debian #1037226: "undefined symbol: pcre_malloc") is surfaced in the log
# rather than silently breaking the WAF target at benchmark time.
ensure_modsec_for_benchmark() {
    case "$PKG" in
        apt)
            # The connector needs the matching dynamic-module-capable nginx; pull
            # the full nginx + the connector + engine + rules from the same suite.
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                nginx libnginx-mod-http-modsecurity libmodsecurity3 modsecurity-crs \
                >/dev/null 2>&1 || true
            ;;
        dnf)
            # RHEL family: connector is not always packaged; try the engine + CRS.
            dnf install -y -q nginx-mod-modsecurity mod_security_crs >/dev/null 2>&1 || true
            ;;
        apk)
            apk add --no-cache nginx-mod-http-modsecurity modsecurity-crs >/dev/null 2>&1 || true
            ;;
        *)  : ;;
    esac
    # nginx itself must stay a non-service; reassert (idempotent with the nginx hook).
    systemctl disable --now nginx >/dev/null 2>&1 || true
    # ABI smoke-test: dlopen the connector via `nginx -t` with only load_module.
    local modso abicheck
    for modso in \
        /usr/lib/nginx/modules/ngx_http_modsecurity_module.so \
        /usr/lib64/nginx/modules/ngx_http_modsecurity_module.so \
        /usr/share/nginx/modules/ngx_http_modsecurity_module.so; do
        [ -f "$modso" ] && break
    done
    if [ -f "$modso" ] && command -v nginx >/dev/null 2>&1; then
        abicheck="$(mktemp /tmp/aegis-modsec-abicheck.XXXXXX.conf 2>/dev/null || echo /tmp/aegis-modsec-abicheck.conf)"
        printf 'load_module %s;\nevents{}\nhttp{}\n' "$modso" > "$abicheck"
        if nginx -t -c "$abicheck" >/dev/null 2>&1; then
            log "nginx+ModSecurity+CRS installed for the comparison benchmark (ABI ok)"
        else
            log "WARN: ModSecurity connector failed ABI smoke-test (PCRE/version skew?) — WAF benchmark target will show 'unavailable'"
        fi
        rm -f "$abicheck" 2>/dev/null || true
    else
        log "WARN: ModSecurity connector module not found — the WAF benchmark target will show 'unavailable'"
    fi
}

# Envoy — plain proxy (no WAF). No apt package exists for Debian 12, so we
# fetch a pinned static binary from the tetratelabs archive (func-e's source)
# and install it to /usr/local/bin/envoy. The static binary creates no systemd
# unit and binds nothing on install, so there is no service to disable. amd64
# only from the archive; arm64 falls through to a best-effort func-e attempt.
ensure_envoy_for_benchmark() {
    if command -v envoy >/dev/null 2>&1 || [ -x /usr/local/bin/envoy ]; then
        log "Envoy already present for the comparison benchmark"
        return 0
    fi
    local ver="1.38.1" plat tmp
    case "$ARCH" in
        amd64) plat="linux-amd64" ;;
        arm64) plat="linux-arm64" ;;
        *)     plat="" ;;
    esac
    if [ -n "$plat" ] && command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        # tar -xJ needs xz; on stripped images pull it in (best-effort, no-op if present).
        command -v xz >/dev/null 2>&1 || case "$PKG" in
            apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xz-utils >/dev/null 2>&1 || true ;;
            dnf) dnf install -y -q xz >/dev/null 2>&1 || true ;;
            apk) apk add --no-cache xz >/dev/null 2>&1 || true ;;
        esac
        tmp="$(mktemp -d /tmp/aegis-envoy.XXXXXX 2>/dev/null || echo /tmp/aegis-envoy)"
        mkdir -p "$tmp"
        if curl -fsSL -o "$tmp/envoy.tar.xz" \
            "https://archive.tetratelabs.io/envoy/download/v${ver}/envoy-v${ver}-${plat}.tar.xz" 2>/dev/null \
           && tar -xJf "$tmp/envoy.tar.xz" -C "$tmp" 2>/dev/null \
           && [ -f "$tmp/envoy-v${ver}-${plat}/bin/envoy" ]; then
            install -m 0755 "$tmp/envoy-v${ver}-${plat}/bin/envoy" /usr/local/bin/envoy 2>/dev/null || true
        fi
        rm -rf "$tmp" 2>/dev/null || true
    fi
    # Defensive: nothing to disable for the static binary, but the legacy getenvoy
    # apt package shipped a unit — disable it if it ever existed.
    systemctl disable --now envoy >/dev/null 2>&1 || true
    if command -v envoy >/dev/null 2>&1 || [ -x /usr/local/bin/envoy ]; then
        log "Envoy ${ver} installed for the comparison benchmark"
    else
        log "WARN: Envoy not installed — that benchmark target will show 'unavailable'"
    fi
}

# Seed the bundled GeoIP country database so the world map + country rules work
# out of the box. We ship a db-ip "IP to Country Lite" mmdb (CC BY 4.0) in the
# repo under data/geoip and copy it to a writable absolute path the daemon
# resolves automatically. cp -n: never clobber a database the operator already
# refreshed via the panel's Update button.
ensure_geoip_db() {
    local dst="$AEGIS_HOME/geoip"
    local src="$AEGIS_SRC/data/geoip/dbip-country-lite.mmdb"
    [ -f "$src" ] || { log "WARN: bundled GeoIP db missing at $src — map will be empty until Update is run"; return 0; }
    mkdir -p "$dst"
    cp -n "$src" "$dst/dbip-country-lite.mmdb" 2>/dev/null || true
    chown -R "$AEGIS_USER:$AEGIS_USER" "$dst"
    chmod 0755 "$dst"; chmod 0644 "$dst/dbip-country-lite.mmdb" 2>/dev/null || true
    log "GeoIP country database seeded ($dst/dbip-country-lite.mmdb)"
}

# V244 — reputation feeds are ON by default in the daemon. Seed the ASN/CIDR
# feed (Tor exit nodes + Spamhaus DROP) and the db-ip ASN-lite DB (so AS<n>
# entries resolve), and install a daily refresh timer — Tor/Spamhaus/ASN-DB
# all drift over time and the daemon hot-reloads changed files by mtime, so no
# restart is needed. The in-proxy JA4 reputation is self-learning from
# honeypot/WAF/tarpit hits and needs no seed; an optional CrowdSec JA4 pull is
# wired but stays inert until the operator sets CROWDSEC_LAPI_* in
# /etc/aegis/feeds.env. All fetches are best-effort: a failed fetch leaves the
# module inert (zero false positives) rather than failing the install.
ensure_reputation_feeds() {
    local rep="$AEGIS_HOME/reputation"
    mkdir -p "$rep"
    chown -R "$AEGIS_USER:$AEGIS_USER" "$rep"
    chmod 0755 "$rep"

    cat > /usr/local/bin/aegis-refresh-feeds <<'RFEOF'
#!/usr/bin/env bash
# aegis-refresh-feeds — refresh AEGIS reputation feeds. Best-effort; the
# daemon hot-reloads changed files by mtime (no restart needed).
set -uo pipefail
REP_DIR=/var/lib/aegis/reputation
GEO_DIR=/var/lib/aegis/geoip
OWNER=$(stat -c %U "$REP_DIR" 2>/dev/null || echo aegis)
mkdir -p "$REP_DIR" "$GEO_DIR"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# --- ASN/CIDR: Tor exit nodes (signal, 0.5) + Spamhaus DROP (abuse, 0.8) ---
out="$TMP/asn-cidr.txt"
{
  echo "# AEGIS ASN/CIDR reputation — auto-refreshed $(date -u +%FT%TZ)"
  echo "# format: <cidr|AS<n>>  <score 0..1>  <tag>"
  if curl -fsS -m 45 https://check.torproject.org/torbulkexitlist -o "$TMP/tor.txt"; then
    awk 'NF && $1 !~ /^#/ {print $1"/32 0.5 tor-exit"}' "$TMP/tor.txt"
  fi
  if curl -fsS -m 45 https://www.spamhaus.org/drop/drop.txt -o "$TMP/drop.txt"; then
    awk -F';' '$1 ~ /\// {gsub(/[ \t]/,"",$1); if ($1!="") print $1" 0.8 spamhaus-drop"}' "$TMP/drop.txt"
  fi
} > "$out"
if [ "$(grep -cvE '^#' "$out" 2>/dev/null || echo 0)" -ge 1 ]; then
  install -m 0644 -o "$OWNER" -g "$OWNER" "$out" "$REP_DIR/asn-cidr.txt"
fi

# --- db-ip ASN-lite DB (monthly) for AS<n>-keyed entries ---
M=$(date -u +%Y-%m)
if curl -fsS -m 120 "https://download.db-ip.com/free/dbip-asn-lite-$M.mmdb.gz" -o "$TMP/asn.mmdb.gz"; then
  if gunzip -f "$TMP/asn.mmdb.gz"; then
    install -m 0644 -o "$OWNER" -g "$OWNER" "$TMP/asn.mmdb" "$GEO_DIR/dbip-asn-lite.mmdb"
  fi
fi

# --- Optional CrowdSec JA4 reputation (opt-in via /etc/aegis/feeds.env) ---
[ -f /etc/aegis/feeds.env ] && . /etc/aegis/feeds.env
if [ -n "${CROWDSEC_LAPI_URL:-}" ] && [ -n "${CROWDSEC_LAPI_KEY:-}" ]; then
  if curl -fsS -m 45 -H "X-Api-Key: $CROWDSEC_LAPI_KEY" \
       "${CROWDSEC_LAPI_URL%/}/v1/decisions?scope=ja4" -o "$TMP/cs.json"; then
    python3 - "$TMP/cs.json" "$REP_DIR/ja4-crowdsec.txt" <<'PYEOF'
import json,sys
try: data=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
out=["# AEGIS CrowdSec JA4 reputation — auto-refreshed"]
for d in (data or []):
    v=str((d or {}).get("value","")).strip()
    if v and "_" in v: out.append(v+"\tcrowdsec")
open(sys.argv[2],"w").write("\n".join(out)+"\n")
PYEOF
    chown "$OWNER:$OWNER" "$REP_DIR/ja4-crowdsec.txt" 2>/dev/null || true
  fi
fi
echo "aegis-refresh-feeds: done ($(grep -cvE '^#' "$REP_DIR/asn-cidr.txt" 2>/dev/null || echo 0) ASN/CIDR entries)"
RFEOF
    chmod 0755 /usr/local/bin/aegis-refresh-feeds

    cat > /etc/systemd/system/aegis-refresh-feeds.service <<EOF
[Unit]
Description=Aegis reputation feed refresh (Tor/Spamhaus/ASN-DB/CrowdSec)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegis-refresh-feeds
EOF
    cat > /etc/systemd/system/aegis-refresh-feeds.timer <<EOF
[Unit]
Description=Daily Aegis reputation feed refresh

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    chmod 0644 /etc/systemd/system/aegis-refresh-feeds.service /etc/systemd/system/aegis-refresh-feeds.timer
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now aegis-refresh-feeds.timer 2>/dev/null || true
    # Seed immediately (best-effort; the module stays inert if the network fails).
    /usr/local/bin/aegis-refresh-feeds 2>&1 | tail -1 || log "WARN: initial feed refresh failed (will retry via timer)"
    log "reputation feeds configured (ASN/CIDR seeded + daily refresh timer)"
}

# Let the panel's "Restart" button (POST /admin/api/restart) actually restart
# the service. The daemon runs unprivileged AND inside aegis-pingora@N's own
# cgroup, so it cannot spawn a working `systemctl restart` (sudo can't escalate
# under NoNewPrivileges, and a direct systemctl is SIGKILLed when its own
# cgroup is stopped mid-restart). Instead the daemon writes a marker file and a
# decoupled, root-owned systemd path-watcher performs the restart from a
# separate cgroup where it survives the target going down.
ensure_restart_watcher() {
    local marker="$AEGIS_HOME/.restart-request"
    local sc; sc="$(command -v systemctl || echo /usr/bin/systemctl)"
    local rm_bin; rm_bin="$(command -v rm || echo /bin/rm)"

    # Rolling restart helper: restart the SO_REUSEPORT worker instances one at
    # a time so siblings keep the listening sockets bound — applying a
    # panel-saved setting becomes near-zero-downtime instead of a full target
    # bounce. Falls back to a plain target restart for 0/1 instance (hyper
    # mode, or a single worker, where rolling buys nothing).
    cat > /usr/local/bin/aegis-rolling-restart <<'RREOF'
#!/bin/sh
units=$(systemctl list-units --no-legend --plain 'aegis-pingora@*.service' 2>/dev/null | awk '{print $1}')
count=$(printf '%s\n' "$units" | grep -c . 2>/dev/null || echo 0)
if [ "$count" -le 1 ]; then
    exec systemctl restart aegis-pingora.target
fi
for u in $units; do
    systemctl restart "$u" || true
    sleep 3
done
RREOF
    chmod 0755 /usr/local/bin/aegis-rolling-restart

    cat > /etc/systemd/system/aegis-restart.service <<EOF
[Unit]
Description=Aegis panel-requested rolling restart of aegis-pingora workers
# Don't let this be torn down together with the target it restarts.
After=network.target

[Service]
Type=oneshot
# Clear the marker FIRST so the .path unit re-arms and we never loop.
ExecStartPre=-$rm_bin -f $marker
ExecStart=/usr/local/bin/aegis-rolling-restart
EOF

    cat > /etc/systemd/system/aegis-restart.path <<EOF
[Unit]
Description=Watch for Aegis panel restart requests

[Path]
# PathExists (not Modified) so a leftover marker triggers exactly once and is
# then removed by the service, avoiding boot-time restart loops.
PathExists=$marker
Unit=aegis-restart.service

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 /etc/systemd/system/aegis-restart.service /etc/systemd/system/aegis-restart.path
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now aegis-restart.path 2>/dev/null || true
    # Clean up earlier (ineffective) restart-permission attempts if present.
    rm -f /etc/sudoers.d/aegis-restart /etc/polkit-1/rules.d/49-aegis-restart.rules 2>/dev/null || true
    log "restart path-watcher installed (aegis-restart.path → aegis-restart.service)"
}

update_only() {
    require_root
    [ -d "$AEGIS_SRC/.git" ] || fatal "$AEGIS_SRC does not exist — run full install first"
    log "updating to latest $AEGIS_VERSION"
    build_and_install
    # Ensure the UI feature-flag env file + drop-in exist before restart so
    # panel toggles take effect (update path never calls write_systemd_unit).
    ensure_ui_env_dropin
    log "validating new config syntax"
    "$AEGIS_BIN" -c "$AEGIS_ETC/aegis.conf" -t
    log "restarting service(s)"
    if [ "$AEGIS_MODE" = "hyper" ]; then
        systemctl restart aegis
    else
        # Template + target — restart the target which fans out to all
        # template instances atomically.
        systemctl restart aegis-pingora.target
    fi
    sleep 1
    local svc=aegis
    [ "$AEGIS_MODE" = "hyper" ] || svc=aegis-pingora.target
    if systemctl is-active --quiet "$svc"; then
        ok "$svc restarted"
    else
        fatal "$svc failed to restart; see: journalctl -u $svc -n 30"
    fi
}

generate_secret() {
    if command -v openssl >/dev/null; then
        openssl rand -base64 32 | tr -d '\n='
    else
        head -c 32 /dev/urandom | base64 | tr -d '\n='
    fi
}

generate_self_signed_cert() {
    local cert_dir="$AEGIS_ETC/certs"
    local crt="$cert_dir/default.crt"
    local key="$cert_dir/default.key"
    if [ -f "$crt" ] && [ -f "$key" ]; then
        log "self-signed cert already at $crt"
        return
    fi
    log "generating bootstrap self-signed cert (replace with real cert later)"
    mkdir -p "$cert_dir"
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout "$key" -out "$crt" \
        -subj "/CN=aegis-default" >/dev/null 2>&1
    chmod 0640 "$key" "$crt"
    chown root:"$AEGIS_USER" "$key" "$crt"
}

create_default_config() {
    mkdir -p "$AEGIS_ETC" "$AEGIS_ETC/sites-enabled" "$AEGIS_ETC/sites-available" \
        "$AEGIS_LOG_DIR" "$AEGIS_HOME/sites.d" \
        "$AEGIS_HOME/certs" "$AEGIS_HOME/acme/orders" \
        "$AEGIS_HOME/acme/accounts/staging" "$AEGIS_HOME/acme/accounts/production" \
        "$AEGIS_HOME/acme/challenges"
    chown root:"$AEGIS_USER" "$AEGIS_ETC" "$AEGIS_ETC/sites-enabled" "$AEGIS_ETC/sites-available"
    chown -R "$AEGIS_USER:$AEGIS_USER" "$AEGIS_LOG_DIR" "$AEGIS_HOME" "$AEGIS_HOME/sites.d"
    chmod 0750 "$AEGIS_HOME/sites.d" "$AEGIS_HOME/acme/accounts/staging" \
        "$AEGIS_HOME/acme/accounts/production"
    chmod 0755 "$AEGIS_HOME/certs" "$AEGIS_HOME/acme/orders" "$AEGIS_HOME/acme/challenges"

    local conf="$AEGIS_ETC/aegis.conf"
    if [ -f "$conf" ]; then
        log "config already exists at $conf — preserving"
        return
    fi

    local admin_token; admin_token=$(generate_secret)
    local hmac_secret; hmac_secret=$(generate_secret)

    log "writing default config → $conf"
    local xdp_block=""
    if [ "$AEGIS_ENABLE_XDP" = "1" ]; then
        xdp_block=$(cat <<EOF

# Phase A XDP fast-path. Loaded into the kernel on startup; deny/allow
# maps are programmed from userspace. Detached automatically on shutdown.
xdp {
    enabled true;
    interface $AEGIS_XDP_IFACE;
    bpf_object_path $AEGIS_XDP_OBJ;

    # Per-IPv4 kernel rate-limit. Both fields must be > 0 to activate.
    # Drops packets whose source has > burst within rate_window_ms.
    rate_window_ms 1000;
    rate_burst 200;
    # Per-IPv4 TCP-SYN burst within rate_window_ms (separate budget from
    # the general limiter so a SYN flood can't deplete legit traffic).
    syn_burst 100;
}
EOF
)
    fi

    cat > "$conf" <<EOF
# Aegis main config — generated by installer on $(date -Iseconds).
# Edit this file (or drop site files into sites-enabled/) then run:
#     aegis -t                                # validate without restart
#     systemctl reload aegis-pingora.target   # apply changes
# (or 'systemctl reload aegis' in --mode hyper)

admin {
    listen 0.0.0.0:$AEGIS_PORT_ADMIN;
    token admin GENERATED_ABOVE_BY_INSTALLER;     # see /etc/aegis/admin-token
    audit_log_path $AEGIS_LOG_DIR/audit.log;

    # Web UI writes generated site .conf files here (aegis-owned).
    # Operator-managed files live in /etc/aegis/sites-enabled and are
    # surfaced read-only in the web UI.
    managed_sites_dir $AEGIS_HOME/sites.d;
    ops_sites_dir     $AEGIS_ETC/sites-enabled;

    # Web admin session state — credentials, login sessions, kill switch.
    # The 'aegis web reset-admin' CLI writes here; daemon reads on each
    # request (mtime-polled). Default: $AEGIS_HOME/web.json.
    web_state_path $AEGIS_HOME/web.json;
}

defaults {
    request_timeout    10s;
    graceful_shutdown  10s;
    header_read_timeout 5s;

    filters {
        waf                       on;
        bot_fingerprint           on;
        adaptive_spike_detection  on;
        # challenge_ladder is opt-in per domain — operators enable it
        # on a \`server { ... }\` block for sites that actually need
        # browser-verification gating. Defaulting it on would issue a
        # JS/PoW challenge to every client of every site, including
        # API endpoints and non-browser traffic.
        challenge_ladder          off;
    }

    rate_limit {
        requests_per_second 100;
        burst 200;
    }
}
$xdp_block

# Stub default upstream — replace with your real backend, or add a
# server { ... server_name foo.example.com; ... } block per site.
server {
    listen 0.0.0.0:$AEGIS_PORT_HTTP default_server;
    listen 0.0.0.0:$AEGIS_PORT_HTTPS ssl http2 http3 default_server;

    ssl_certificate     $AEGIS_ETC/certs/default.crt;
    ssl_certificate_key $AEGIS_ETC/certs/default.key;

    proxy_pass http://127.0.0.1:8000;
}

# Per-site config files. Both directories are scanned in deterministic
# alphabetical order; UI-managed sites take precedence on conflict.
include $AEGIS_ETC/sites-enabled/*.conf;
include $AEGIS_HOME/sites.d/*.conf;
EOF
    chmod 0640 "$conf"
    chown root:"$AEGIS_USER" "$conf"

    printf "%s\n" "$admin_token" > "$AEGIS_ETC/admin-token"
    chmod 0600 "$AEGIS_ETC/admin-token"
    chown root:"$AEGIS_USER" "$AEGIS_ETC/admin-token"
    sed -i "s/GENERATED_ABOVE_BY_INSTALLER/${admin_token//\//\\/}/" "$conf"

    printf "%s\n" "$hmac_secret" > "$AEGIS_ETC/hmac-secret"
    chmod 0600 "$AEGIS_ETC/hmac-secret"
    chown root:"$AEGIS_USER" "$AEGIS_ETC/hmac-secret"

    # Honeypot state file (V72+) — empty default means all packs ON.
    # The 'aegis honeypot' CLI and /admin/api/honeypots/* endpoints
    # mutate this file; daemon picks up changes via mtime poll.
    if [ ! -f "$AEGIS_HOME/honeypots.json" ]; then
        printf '%s\n' '{"enabled":true,"packs":{},"per_host":{}}' \
            > "$AEGIS_HOME/honeypots.json"
        chown "$AEGIS_USER:$AEGIS_USER" "$AEGIS_HOME/honeypots.json"
        chmod 0640 "$AEGIS_HOME/honeypots.json"
    fi
}

seed_web_admin() {
    # Generate the first-time admin credentials. The state file lives
    # at $AEGIS_HOME/web.json; the daemon picks it up on mtime poll
    # (no restart needed). Idempotent: skip if the operator already
    # changed the credentials (must_change=false marker).
    local state="$AEGIS_HOME/web.json"
    if [ -f "$state" ] && grep -q '"must_change":false' "$state" 2>/dev/null; then
        log "web admin already initialised — preserving operator's credentials"
        WEB_ADMIN_PASSWORD="(unchanged — already initialised)"
        return
    fi
    log "generating first-time web admin credentials"
    # `aegis web reset-admin` writes the state file with a fresh
    # password + must_change=true. Output looks like:
    #   ✓ web admin reset
    #     email:    admin@example.com
    #     password: <random>
    # We capture both lines to surface to the operator.
    local out
    out=$("$AEGIS_BIN" -c "$AEGIS_ETC/aegis.conf" web reset-admin 2>&1) || {
        warn "aegis web reset-admin failed:"
        printf '%s\n' "$out" | sed 's/^/    /'
        WEB_ADMIN_PASSWORD="(failed to generate — run 'aegis web reset-admin' manually)"
        return
    }
    WEB_ADMIN_EMAIL=$(printf '%s\n' "$out" | awk '/email:/ {print $2}')
    WEB_ADMIN_PASSWORD=$(printf '%s\n' "$out" | awk '/password:/ {print $2}')
    chown "$AEGIS_USER:$AEGIS_USER" "$state"
    chmod 0640 "$state"
}

write_systemd_unit_hyper() {
    local unit=/etc/systemd/system/aegis.service
    log "writing systemd unit → $unit"
    cat > "$unit" <<EOF
[Unit]
Description=Aegis edge proxy (hyper data plane)
Documentation=https://github.com/tnAnGel/Aegis
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$AEGIS_USER
Group=$AEGIS_USER
WorkingDirectory=$AEGIS_HOME
EnvironmentFile=-$AEGIS_ETC/aegis.env
ExecStartPre=$AEGIS_BIN -c $AEGIS_ETC/aegis.conf -t
ExecStart=$AEGIS_BIN -c $AEGIS_ETC/aegis.conf start
ExecReload=/bin/sh -c 'curl --fail -X POST -H "x-admin-token: \$(cat $AEGIS_ETC/admin-token)" http://127.0.0.1:$AEGIS_PORT_ADMIN/admin/reload'
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
ReadOnlyPaths=$AEGIS_ETC
ReadWritePaths=$AEGIS_LOG_DIR $AEGIS_HOME

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$unit"
}

write_systemd_unit_pingora() {
    # V71 layout: template unit `aegis-pingora@.service` + grouping
    # target `aegis-pingora.target`. The operator manages instances via
    # the target (`systemctl restart aegis-pingora.target`) which fans
    # out to all enabled instances atomically. Each instance binds
    # SO_REUSEPORT on $AEGIS_PORT_HTTP / $AEGIS_PORT_HTTPS / admin.
    #
    # Sandboxing is relaxed in two places vs the hyper unit:
    #   * MemoryDenyWriteExecute=false — pingora's openssl path uses
    #     JIT-able code regions on some architectures
    #   * AmbientCapabilities adds CAP_NET_ADMIN when XDP is enabled
    #     (so the worker can attach the eBPF program to the NIC)
    #
    # IMPORTANT: CapabilityBoundingSet must be a SUPERSET of the file
    # capabilities we setcap onto the binary in build_pingora()
    # (cap_net_bind_service,cap_net_admin,cap_sys_resource=+ep). The kernel
    # refuses execve() with EPERM when a file's permitted capability set is
    # not contained in the bounding set — systemd surfaces that as an opaque
    # `status=203/EXEC ... Operation not permitted`, and every worker
    # crash-loops. Keep the two lists in sync.
    local svc_cap="CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE"
    local svc_raf="AF_INET AF_INET6 AF_UNIX"
    if [ "$AEGIS_ENABLE_XDP" = "1" ]; then
        # CAP_BPF + CAP_PERFMON: load/verify the eBPF program. On 6.x the
        #   verifier gates pointer/packet-data ops behind perfmon_capable(),
        #   so without CAP_PERFMON BPF_PROG_LOAD fails with EACCES (os err 13)
        #   even though CAP_BPF is present.
        # CAP_NET_ADMIN: attach the program to the NIC.
        # AF_NETLINK: the XDP attach goes through rtnetlink.
        svc_cap="CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON"
        svc_raf="AF_INET AF_INET6 AF_UNIX AF_NETLINK"
    fi
    local unit=/etc/systemd/system/aegis-pingora@.service
    log "writing systemd template → $unit"
    cat > "$unit" <<EOF
[Unit]
Description=Aegis pingora data plane worker %i
Documentation=https://github.com/tnAnGel/Aegis
After=network-online.target
Wants=network-online.target
PartOf=aegis-pingora.target

[Service]
Type=simple
User=$AEGIS_USER
Group=$AEGIS_USER
WorkingDirectory=$AEGIS_HOME
EnvironmentFile=-$AEGIS_ETC/aegis.env
# REUSEPORT — every instance binds the same listen ports; kernel hashes
# the 4-tuple to one of them. Threads-per-worker matches the V71
# recommendation (cleanly partitioned: workers × threads = cores).
Environment=AEGIS_PINGORA_REUSEPORT=1
Environment=AEGIS_PINGORA_THREADS=$AEGIS_THREADS_PER_WORKER
ExecStart=$AEGIS_PINGORA_BIN -c $AEGIS_ETC/aegis.conf --log-level info
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

# V230 — pin worker %i to CPU %i (thread-per-core, 1:1 affinity).
# Instances are numbered 0..N-1 so %i lines up with CPU index directly.
# LimitMEMLOCK=infinity lets the BPF maps + locked ring buffers grow
# past the default 64 KiB rlimit. Nice=-10 nudges the proxy ahead of
# misc userland under contention without flipping to RT FIFO (which
# would risk starving systemd / journald / sshd if a worker spins).
CPUAffinity=%i
LimitMEMLOCK=infinity
Nice=-10

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=$svc_raf
RestrictNamespaces=true
LockPersonality=true
ReadOnlyPaths=$AEGIS_ETC
ReadWritePaths=$AEGIS_LOG_DIR $AEGIS_HOME

AmbientCapabilities=$svc_cap
CapabilityBoundingSet=$svc_cap

[Install]
WantedBy=aegis-pingora.target
EOF
    chmod 0644 "$unit"

    local target=/etc/systemd/system/aegis-pingora.target
    log "writing systemd target → $target"
    # V230 — instances numbered 0..N-1 so the template's CPUAffinity=%i
    # maps 1:1 to CPU index (worker 0 → CPU 0, ..., worker N-1 → CPU N-1).
    local last=$(( AEGIS_WORKERS - 1 ))
    cat > "$target" <<EOF
[Unit]
Description=Aegis pingora workers ($AEGIS_WORKERS × REUSEPORT, CPU-pinned)
# Wants (not Requires): a single worker restarting must NOT make the target's
# dependency unsatisfied and cascade-stop the siblings — that is what enables
# the near-zero-downtime ROLLING restart (aegis-rolling-restart). PartOf on the
# template still fans a target restart out to every instance.
Wants=$(seq 0 "$last" | sed 's/.*/aegis-pingora@&.service/' | tr '\n' ' ')
After=$(seq 0 "$last" | sed 's/.*/aegis-pingora@&.service/' | tr '\n' ' ')

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$target"
}

write_systemd_unit() {
    # Always pull the env file from the same place; mode-specific
    # services share it. New install gets a fresh file; updates leave
    # the existing one alone.
    if [ ! -f "$AEGIS_ETC/aegis.env" ]; then
        cat > "$AEGIS_ETC/aegis.env" <<EOF
# Environment for aegis services. Reload systemd after edits:
#     systemctl daemon-reload && systemctl restart aegis-pingora.target

AEGIS_ADMIN_TOKEN_FILE=$AEGIS_ETC/admin-token
AEGIS_CHALLENGE_SECRET_FILE=$AEGIS_ETC/hmac-secret

# V72+ pingora data plane — these env vars are read by aegis-pingora
# at startup. Safe to leave on for the hyper binary (it ignores them).
AEGIS_RESPONSE_CACHE_ENABLE=1
AEGIS_DYNAMIC_TRUST_ENABLE=1
AEGIS_HONEYPOT_STATE=$AEGIS_HOME/honeypots.json
# V80 — runtime scheduler. NoSteal (work_stealing=false) is the
# V81+ default; ~10-135% faster than work-stealing tokio across
# every workload we measured. To opt back in to work-stealing:
#   AEGIS_PINGORA_WORK_STEALING=1
# Leaving unset = NoSteal thread-per-core (recommended).

RUST_LOG=info,aegis=info,aegis_pingora=info
EOF
        chmod 0640 "$AEGIS_ETC/aegis.env"
        chown root:"$AEGIS_USER" "$AEGIS_ETC/aegis.env"
    fi

    case "$AEGIS_MODE" in
        hyper)
            write_systemd_unit_hyper
            ;;
        pingora|both)
            # In both mode the pingora unit is primary; the hyper unit
            # is also written but left disabled so the operator can
            # opt-in later (`systemctl enable aegis`).
            write_systemd_unit_pingora
            [ "$AEGIS_MODE" = "both" ] && write_systemd_unit_hyper
            ;;
    esac
    systemctl daemon-reload
}

setup_firewall() {
    if [ "$AEGIS_SKIP_FIREWALL" = "1" ]; then
        log "AEGIS_SKIP_FIREWALL=1 — skipping ufw/firewalld setup"
        return
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        log "ufw is active — opening $AEGIS_PORT_HTTP / $AEGIS_PORT_HTTPS / $AEGIS_PORT_ADMIN"
        ufw allow "$AEGIS_PORT_HTTP"/tcp comment 'aegis http' >/dev/null
        ufw allow "$AEGIS_PORT_HTTPS"/tcp comment 'aegis https' >/dev/null
        ufw allow "$AEGIS_PORT_HTTPS"/udp comment 'aegis h3 quic' >/dev/null
        ufw allow "$AEGIS_PORT_ADMIN"/tcp comment 'aegis admin' >/dev/null
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log "firewalld is active — opening ports"
        firewall-cmd --permanent --add-port="$AEGIS_PORT_HTTP/tcp" >/dev/null
        firewall-cmd --permanent --add-port="$AEGIS_PORT_HTTPS/tcp" >/dev/null
        firewall-cmd --permanent --add-port="$AEGIS_PORT_HTTPS/udp" >/dev/null
        firewall-cmd --permanent --add-port="$AEGIS_PORT_ADMIN/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
    fi
}

detect_port_conflict() {
    # Warn (don't fail) if something else is on :80 / :443 / admin
    # before we start aegis — the most common reason for "service
    # failed to start" is a leftover nginx / apache binding.
    local p
    for p in "$AEGIS_PORT_HTTP" "$AEGIS_PORT_HTTPS" "$AEGIS_PORT_ADMIN"; do
        local owner
        owner=$(ss -tlnp 2>/dev/null | awk -v p=":$p" '$4 ~ p {print $NF}' | head -1 || true)
        if [ -n "$owner" ]; then
            warn "port $p is already bound by $owner — aegis will fail to start. Stop it first:"
            warn "  systemctl stop nginx 2>/dev/null; systemctl stop apache2 2>/dev/null"
        fi
    done
}

enable_and_start() {
    detect_port_conflict
    case "$AEGIS_MODE" in
        hyper)
            log "enabling + starting aegis.service"
            systemctl enable --quiet aegis.service
            if systemctl is-active --quiet aegis.service; then
                systemctl reload aegis.service || systemctl restart aegis.service
            else
                systemctl start aegis.service
            fi
            sleep 1
            if systemctl is-active --quiet aegis.service; then
                ok "aegis.service is active"
            else
                warn "aegis.service failed to start — see: journalctl -u aegis -n 50"
                systemctl status aegis.service --no-pager || true
                exit 1
            fi
            ;;
        pingora|both)
            log "enabling + starting $AEGIS_WORKERS pingora workers (CPU-pinned)"
            # V230 — instances 0..N-1 so template CPUAffinity=%i pins
            # worker i to CPU i.
            local last=$(( AEGIS_WORKERS - 1 ))
            local i
            for i in $(seq 0 "$last"); do
                systemctl enable --quiet "aegis-pingora@${i}.service"
            done
            systemctl enable --quiet aegis-pingora.target
            systemctl restart aegis-pingora.target
            sleep 2
            local failed=0
            for i in $(seq 0 "$last"); do
                if ! systemctl is-active --quiet "aegis-pingora@${i}.service"; then
                    warn "aegis-pingora@${i}.service failed; journalctl -u aegis-pingora@${i} -n 30"
                    failed=$(( failed + 1 ))
                fi
            done
            if [ "$failed" -eq 0 ]; then
                ok "all $AEGIS_WORKERS pingora workers are active (pinned to CPUs 0-$last)"
            else
                exit 1
            fi
            ;;
    esac
}

print_summary() {
    local admin_token
    admin_token=$(cat "$AEGIS_ETC/admin-token" 2>/dev/null || echo "<missing>")
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$ip" ]; then ip="<your-server-ip>"; fi

    local mode_summary
    case "$AEGIS_MODE" in
        hyper)   mode_summary="hyper (single process)" ;;
        pingora) mode_summary="pingora (V72+ recommended) — $AEGIS_WORKERS workers × $AEGIS_THREADS_PER_WORKER thread, REUSEPORT + CPU-pinned (V230)" ;;
        both)    mode_summary="both binaries built; pingora is the primary service" ;;
    esac
    local xdp_summary
    if [ "$AEGIS_ENABLE_XDP" = "1" ]; then
        xdp_summary="enabled on $AEGIS_XDP_IFACE (eBPF object: $AEGIS_XDP_OBJ)"
    else
        xdp_summary="disabled"
    fi

    cat <<EOF

$(printf "${GREEN}")============================================================$(printf "${NC}")
 Aegis is installed and running.
$(printf "${GREEN}")============================================================$(printf "${NC}")

Mode:          $mode_summary
XDP fast-path: $xdp_summary

Web UI:        http://$ip:$AEGIS_PORT_ADMIN/admin/ui
  Web login (first-time use):
    email:    ${WEB_ADMIN_EMAIL:-admin@example.com}
    password: ${WEB_ADMIN_PASSWORD:-(see 'aegis web reset-admin' output)}
    note:     the panel will force a password + email change on first login

  Or use the API directly with the token (CLI / curl):
    Admin token:  $admin_token
    Header:       x-admin-token: <token>

Config file:   $AEGIS_ETC/aegis.conf
Sites folder:  $AEGIS_ETC/sites-enabled/  (ops-managed)
               $AEGIS_HOME/sites.d/        (UI-managed)
Logs:          journalctl -u aegis-pingora.target -f   # or -u aegis -f for hyper mode

Quick commands:
  systemctl status aegis-pingora.target                 # service status
  systemctl restart aegis-pingora.target                # apply config changes
  aegis -c $AEGIS_ETC/aegis.conf -t                     # validate config
  aegis web reset-admin                                 # regenerate web creds
  curl -s -H "x-admin-token: \$(cat $AEGIS_ETC/admin-token)" \\
       http://127.0.0.1:$AEGIS_PORT_ADMIN/metrics

To add a site:
  1. Create $AEGIS_ETC/sites-enabled/example.com.conf:
       server {
           listen 80;
           listen 443 ssl http2 http3;
           server_name example.com;
           ssl_certificate     $AEGIS_ETC/certs/example.crt;
           ssl_certificate_key $AEGIS_ETC/certs/example.key;
           proxy_pass http://127.0.0.1:3000;
       }
  2. aegis -t           # check syntax
  3. systemctl restart aegis-pingora.target

To uninstall:
  curl -fsSL .../install.sh | sudo bash -s -- --uninstall
  (add --purge to also delete $AEGIS_ETC and $AEGIS_HOME)

EOF
}

uninstall() {
    log "stopping + disabling aegis services"
    systemctl disable --quiet --now aegis.service 2>/dev/null || true
    systemctl disable --quiet --now aegis-pingora.target 2>/dev/null || true
    # V230 — instance numbering shifted from 1..N to 0..N-1. Sweep both
    # ranges so upgrades from older installs (1..16) clean up alongside
    # the new layout (0..15).
    local i
    for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
        systemctl disable --quiet --now "aegis-pingora@${i}.service" 2>/dev/null || true
    done
    rm -f /etc/systemd/system/aegis.service \
        /etc/systemd/system/aegis-pingora@.service \
        /etc/systemd/system/aegis-pingora.target
    systemctl daemon-reload
    rm -f "$AEGIS_BIN" "$AEGIS_PINGORA_BIN"
    rm -rf "$AEGIS_SRC"
    if [ "$MODE_FLAG" = "purge" ]; then
        log "purging $AEGIS_ETC, $AEGIS_HOME, $AEGIS_LOG_DIR"
        rm -rf "$AEGIS_ETC" "$AEGIS_HOME" "$AEGIS_LOG_DIR"
        if id -u "$AEGIS_USER" >/dev/null 2>&1; then
            userdel "$AEGIS_USER" 2>/dev/null || true
        fi
        ok "fully purged"
    else
        ok "uninstalled — config preserved at $AEGIS_ETC (use --purge to remove)"
    fi
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
require_root
detect_os
resolve_xdp_enable
resolve_workers
resolve_xdp_iface

if [ "$MODE_FLAG" = "uninstall" ] || [ "$MODE_FLAG" = "purge" ]; then
    uninstall
    exit 0
fi
if [ "$MODE_FLAG" = "update" ]; then
    update_only
    exit 0
fi

install_packages
install_node
install_rust
create_user
build_and_install
generate_self_signed_cert
create_default_config
write_systemd_unit
ensure_ui_env_dropin
setup_firewall
enable_and_start
# seed_web_admin needs the daemon up so the state-file mtime poll
# picks up the new credentials within ~1s.
seed_web_admin
print_summary
