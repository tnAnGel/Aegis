#!/usr/bin/env bash
# V230 — 2-VM (or CPU-isolated single-VM) bench harness.
#
# Why this exists
# ---------------
# `bench_fair.sh` runs wrk + nginx + aegis on the same OrbStack ARM64
# VM. wrk consistently burns 160-180% CPU and steals ~2 cores from
# the proxy under -t4 -c100 -d15s. That caps measured RPS roughly
# 30-50% below the proxy's true capacity. The single-VM bench is
# fine for relative A/B (proxy version X vs Y) but underreports
# absolute throughput.
#
# This script fixes that two ways:
#   1. PREFERRED: hand the load gen to a *second* OrbStack VM
#      (env: CLIENT_VM, e.g. CLIENT_VM=Aegis-Client.orb.local).
#      The proxy VM gets its full 16 cores; the client VM has its
#      own 16 cores. Truly zero contention.
#   2. FALLBACK: same VM, but `taskset` pins the proxy/upstream
#      to CPUs 0-7 and the load gen to CPUs 8-15. The kernel
#      scheduler still owns both, but cache-line ping-pong and
#      core-affinity stealing is mostly eliminated.
#
# Tooling: prefers `oha` (Rust, HDR histogram → true p99.9) over
# `wrk` (per a23c0cfc944903eab agent finding — wrk's stochastic
# sampler is unreliable past p99). Falls back to wrk if oha is not
# installed; falls back further to wrk with --latency if wrk is
# present but oha is not. If neither is installed the script aborts
# with an actionable hint.
#
# Three scenarios run end-to-end:
#   A. nginx static :8000             — upstream ceiling, no proxy
#   B. nginx-proxy :8081 → :8000      — fair reverse-proxy baseline
#   C. aegis-pingora :80 → :8000      — Aegis under the same load
#
# Each scenario gets a 5s warmup (discarded) then a 30s measured
# window. Three back-to-back trials per scenario so variance shows
# up in the table.
#
# Output: a markdown table compatible with `results-*.md` files in
# this directory, written to stdout AND `bench/comparison/results-
# <date>-V230-2vm.md` if --write-results is set. Raw oha/wrk logs
# land in /tmp/bench-2vm-*-<ts>.log so they can be re-parsed later.
#
# Operator notes
# --------------
# Designed to run from cron, CI, or a human shell. Idempotent:
# re-run as many times as you want. Does NOT mutate aegis or nginx
# config — assumes both backends are already configured (use
# `bench_fair.sh` once first to install the nginx :8000 + :8081
# blocks). The first 30 lines of this file explain every knob.
#
# Usage:
#   sudo ./bench_2vm.sh                          # auto-detect mode
#   sudo CLIENT_VM=other.orb.local ./bench_2vm.sh # explicit 2-VM
#   sudo TRIALS=5 DURATION=60s ./bench_2vm.sh   # custom trial count
#   sudo TOOL=wrk ./bench_2vm.sh                 # force wrk over oha
#
# Requires (proxy VM): nginx + aegis-pingora running on their
# configured ports; taskset (util-linux); curl; awk.
# Requires (client side, either VM): oha OR wrk.

set -euo pipefail

# -----------------------------------------------------------------------
# Knobs (env-overridable). Defaults match the V230 OrbStack stand.
# -----------------------------------------------------------------------

# Total CPU budget on the bench host. `nproc` is wrong inside containers
# without `--cpus` so fall back to /proc/cpuinfo for sanity.
TOTAL_CPUS="${TOTAL_CPUS:-$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 16)}"

# Split point. For a 16-core host: 0-7 → proxy/upstream, 8-15 → client.
# If TOTAL_CPUS is not 16 we still split half/half and let the caller
# override via PROXY_CPUS / CLIENT_CPUS if they have asymmetric needs.
HALF=$(( TOTAL_CPUS / 2 ))
PROXY_CPUS="${PROXY_CPUS:-0-$(( HALF - 1 ))}"
CLIENT_CPUS="${CLIENT_CPUS:-$HALF-$(( TOTAL_CPUS - 1 ))}"

# Trial / load shape.
TRIALS="${TRIALS:-3}"             # back-to-back trials per scenario
WARMUP="${WARMUP:-5s}"            # discarded warmup window
DURATION="${DURATION:-30s}"       # measured window
CONNECTIONS="${CONNECTIONS:-200}" # concurrent connections (oha -c / wrk -c)
THREADS="${THREADS:-4}"           # wrk threads (oha auto-sizes)

# Scenario endpoints — all are loopback by default. If running from a
# second VM, override TARGET_HOST to the proxy VM's reachable address
# (e.g. TARGET_HOST=aegis-proxy.orb.local).
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
NGINX_PROXY_PORT="${NGINX_PROXY_PORT:-8081}"
AEGIS_PORT="${AEGIS_PORT:-80}"

# Tool choice. Prefer oha for honest tail latency.
TOOL_OVERRIDE="${TOOL:-}"

# Output
TS=$(date +%Y%m%d-%H%M%S)
DATE_TAG=$(date +%Y-%m-%d)
LOG_DIR="${LOG_DIR:-/tmp}"
SUMMARY="$LOG_DIR/bench-2vm-$TS.summary"
WRITE_RESULTS="${WRITE_RESULTS:-0}"  # 1 → write markdown to bench/comparison/
RESULTS_FILE="${RESULTS_FILE:-bench/comparison/results-$DATE_TAG-V230-2vm.md}"

# Remote client (OrbStack 2-VM mode). If set, the load gen runs over
# ssh on this host. The host MUST already have oha or wrk installed
# and SSH key auth set up; the script doesn't bootstrap it.
CLIENT_VM="${CLIENT_VM:-}"
CLIENT_SSH_USER="${CLIENT_SSH_USER:-$USER}"

# ANSI colours (no-tty safe)
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; BLUE=$'\033[34m'; CYAN=$'\033[36m'; RST=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; RST=""
fi

log() { printf '%s[%s]%s %s\n' "$DIM" "$(date +%H:%M:%S)" "$RST" "$*"; }
hdr() { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RST"; }
die() { printf '%sFATAL:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Mode + tool discovery
# -----------------------------------------------------------------------

# detect_tool — returns "oha" or "wrk" or "" depending on what's
# reachable. Honors $TOOL_OVERRIDE so operators can pin to wrk for
# parity with old result files even when oha is available.
detect_tool() {
    local where="$1"   # "local" or remote ssh target
    local probe
    if [ "$where" = "local" ]; then
        probe() { command -v "$1" >/dev/null 2>&1; }
    else
        # shellcheck disable=SC2317
        probe() { ssh -o BatchMode=yes -o ConnectTimeout=3 "$CLIENT_SSH_USER@$where" "command -v $1 >/dev/null 2>&1"; }
    fi
    if [ -n "$TOOL_OVERRIDE" ]; then
        if probe "$TOOL_OVERRIDE"; then echo "$TOOL_OVERRIDE"; return 0; fi
        die "TOOL=$TOOL_OVERRIDE requested but not installed on $where"
    fi
    if probe oha; then echo "oha"; return 0; fi
    if probe wrk; then echo "wrk"; return 0; fi
    return 1
}

# Decide: remote 2-VM, or local taskset isolation?
MODE="local-taskset"
CLIENT_TARGET="local"
if [ -n "$CLIENT_VM" ]; then
    if ssh -o BatchMode=yes -o ConnectTimeout=3 "$CLIENT_SSH_USER@$CLIENT_VM" true 2>/dev/null; then
        MODE="2vm"
        CLIENT_TARGET="$CLIENT_VM"
    else
        log "${YELLOW}WARN: CLIENT_VM=$CLIENT_VM unreachable over ssh — falling back to taskset${RST}"
    fi
fi

if ! TOOL=$(detect_tool "$CLIENT_TARGET"); then
    die "no load generator found (need oha or wrk). On Debian: 'apt install wrk' or 'cargo install oha'"
fi

# Sanity: taskset needs to exist when we're going to use it on this host.
# In 2vm mode we still pin the proxy here, so taskset is required either way.
command -v taskset >/dev/null 2>&1 || die "taskset (util-linux) not installed — required for CPU pinning"

# -----------------------------------------------------------------------
# Pin already-running services to PROXY_CPUS via taskset -p.
#
# Why -p and not a fresh `taskset … exec`? Pingora + nginx are typically
# already running under systemd. Re-execing them under taskset would
# require a service-file edit + restart and would interrupt operators'
# existing aegis state (admin token, runtime overrides, etc). `-p`
# rewrites the cpumask of an already-running PID + all its threads,
# which is exactly what we want for a transient bench.
#
# We pin by pgrep so the script doesn't hard-code PIDs that change on
# restart. If the binary names ever change update PROXY_PROCS below.
# -----------------------------------------------------------------------
PROXY_PROCS=(aegis-pingora nginx)

pin_proxy_cpus() {
    log "Pinning proxy stack to CPUs $PROXY_CPUS"
    local p pid pinned_any=0
    for p in "${PROXY_PROCS[@]}"; do
        # -a so child threads inherit; quiet on no-match
        for pid in $(pgrep -x "$p" 2>/dev/null || true); do
            taskset -a -p -c "$PROXY_CPUS" "$pid" >/dev/null 2>&1 || true
            pinned_any=1
        done
    done
    if [ "$pinned_any" = "0" ]; then
        log "${YELLOW}WARN: no proxy processes matched ${PROXY_PROCS[*]} — bench will still run but CPUs are not isolated${RST}"
    fi
}

# -----------------------------------------------------------------------
# Health check — make sure all three endpoints answer 200 before we
# spend 3×3×35s benchmarking nothing.
# -----------------------------------------------------------------------
check_endpoint() {
    local name="$1" url="$2" host_hdr="${3:-}"
    local code args=(-sS -o /dev/null -w '%{http_code}' --max-time 5)
    [ -n "$host_hdr" ] && args+=(-H "Host: $host_hdr")
    code=$(curl "${args[@]}" "$url" 2>/dev/null || echo ERR)
    if [ "$code" = "200" ]; then
        printf '  %s%-26s%s → %s%s%s\n' "$DIM" "$name" "$RST" "$GREEN" "$code" "$RST"
    else
        printf '  %s%-26s%s → %s%s%s\n' "$DIM" "$name" "$RST" "$RED" "$code" "$RST"
        die "endpoint $name not healthy — start the service and retry"
    fi
}

# -----------------------------------------------------------------------
# Load-gen invocation. Both oha and wrk produce parseable text; the
# parsers below extract a unified (rps, p50, p90, p99, p999, errs)
# tuple per trial.
#
# oha output (relevant lines):
#   Requests/sec:   123456.78
#   90.00%   in 0.0012 secs
#   99.00%   in 0.0034 secs
#   99.90%   in 0.0089 secs
#   50.00%   in 0.0008 secs   (under "Latency distribution")
#
# wrk output (with --latency):
#   Requests/sec: 123456.78
#   50%    1.23ms
#   90%    2.34ms
#   99%    5.67ms
#   99.999% N/A — wrk caps at p99.999 only with --latency and even
#   then the p99.9 reading is from a tiny tail sample. Recorded as
#   "n/a" rather than an unreliable number.
# -----------------------------------------------------------------------

# build_loadgen_cmd — emits the shell command (as a single string)
# that runs the load generator. Caller is responsible for prepending
# taskset / ssh as appropriate.
build_loadgen_cmd() {
    local url="$1" host_hdr="${2:-}"
    local hdr_arg=""
    [ -n "$host_hdr" ] && hdr_arg="-H 'Host: $host_hdr'"
    case "$TOOL" in
        oha)
            # -j → JSON output (but we still parse text; -j locks the
            # final stats schema). --no-tui keeps it stdout-friendly.
            # -z $DURATION runs for that wall-clock window. -c sets
            # concurrent connections; oha picks its own worker count.
            echo "oha --no-tui -z $DURATION -c $CONNECTIONS $hdr_arg '$url'"
            ;;
        wrk)
            echo "wrk -t$THREADS -c$CONNECTIONS -d$DURATION --latency $hdr_arg '$url'"
            ;;
        *)
            die "unsupported TOOL=$TOOL"
            ;;
    esac
}

# warmup_loadgen — same shape as the measured run but shorter, output
# discarded. Lets the kernel page-cache / aegis-cache stabilise.
warmup_loadgen() {
    local url="$1" host_hdr="${2:-}"
    local cmd
    case "$TOOL" in
        oha) cmd="oha --no-tui -z $WARMUP -c $CONNECTIONS";;
        wrk) cmd="wrk -t$THREADS -c$CONNECTIONS -d$WARMUP";;
    esac
    [ -n "$host_hdr" ] && cmd="$cmd -H 'Host: $host_hdr'"
    cmd="$cmd '$url'"
    run_on_client "$cmd" >/dev/null 2>&1 || true
}

# run_on_client — execute on the load-gen side. In 2vm mode this
# is ssh; in local-taskset mode this is taskset → bash. Both forms
# emit the same stdout so the parsers don't care which path ran.
#
# Also captures the client PID into $CLIENT_PID for the pidstat tail
# at the end. ssh case is best-effort: we capture the *remote* PID
# via $! on the remote shell, but pidstat from the proxy VM can't
# see it. In that case we leave CLIENT_PID empty and skip pidstat.
CLIENT_PID=""
run_on_client() {
    local cmd="$1"
    if [ "$MODE" = "2vm" ]; then
        ssh "$CLIENT_SSH_USER@$CLIENT_VM" "bash -c \"$cmd\""
    else
        # taskset -c restricts the *new* process and all its children.
        # bash -c so the eval of $cmd happens inside the pinned shell.
        taskset -c "$CLIENT_CPUS" bash -c "$cmd"
    fi
}

# -----------------------------------------------------------------------
# Parsers. Tolerate missing fields (return "n/a") so the table still
# renders if a trial fails mid-window.
# -----------------------------------------------------------------------

# parse_oha — extract metrics from oha text output.
parse_oha() {
    local logfile="$1"
    local rps p50 p90 p99 p999 errs
    rps=$(awk '/Requests\/sec/ {print $2; exit}' "$logfile")
    # oha prints "Latency distribution:" then "50.00% in 0.0008 secs"
    # Numbers are seconds; convert to ms for parity with wrk.
    p50=$(awk '/50.00%/ {printf "%.2fms", $3 * 1000; exit}' "$logfile")
    p90=$(awk '/90.00%/ {printf "%.2fms", $3 * 1000; exit}' "$logfile")
    p99=$(awk '/99.00%/ {printf "%.2fms", $3 * 1000; exit}' "$logfile")
    p999=$(awk '/99.90%/ {printf "%.2fms", $3 * 1000; exit}' "$logfile")
    # Error count comes from "Error distribution:" section or "[2xx, 5xx, etc.]"
    errs=$(awk '/Status code distribution/{f=1;next} f && /\[5/{n+=$NF} END{print n+0}' "$logfile")
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${rps:-n/a}" "${p50:-n/a}" "${p90:-n/a}" "${p99:-n/a}" "${p999:-n/a}" "${errs:-0}"
}

# parse_wrk — extract metrics from wrk --latency output.
parse_wrk() {
    local logfile="$1"
    local rps p50 p90 p99 errs
    rps=$(awk '/Requests\/sec/ {print $2; exit}' "$logfile")
    p50=$(awk '/^ *50%/ {print $2; exit}' "$logfile")
    p90=$(awk '/^ *90%/ {print $2; exit}' "$logfile")
    p99=$(awk '/^ *99%/ {print $2; exit}' "$logfile")
    # wrk only reports "Non-2xx or 3xx responses: N" if any occur
    errs=$(awk '/Non-2xx or 3xx responses/ {print $NF; f=1} END{if (!f) print 0}' "$logfile")
    # wrk -t/-c/-d does NOT produce a p99.9 we can trust — its
    # latency sampler is stochastic past p99. Mark explicitly so
    # readers know not to compare against oha's p99.9.
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${rps:-n/a}" "${p50:-n/a}" "${p90:-n/a}" "${p99:-n/a}" "n/a*" "${errs:-0}"
}

parse_tool_output() {
    case "$TOOL" in
        oha) parse_oha "$1";;
        wrk) parse_wrk "$1";;
    esac
}

# run_trial — single warmup + single measured window. Appends one
# tab-separated row to $SUMMARY: scenario \t trial \t rps \t p50 \t
# p90 \t p99 \t p999 \t errs.
run_trial() {
    local scenario="$1" label="$2" url="$3" host_hdr="${4:-}" trial="$5"
    # `logfile` not `log` — `log` is our printf helper at the top.
    local cmd logfile
    cmd=$(build_loadgen_cmd "$url" "$host_hdr")
    logfile="$LOG_DIR/bench-2vm-$scenario-trial$trial-$TS.log"

    log "${BLUE}[$scenario t$trial]${RST} $label  → $logfile"
    log "${DIM}warmup ($WARMUP) …${RST}"
    warmup_loadgen "$url" "$host_hdr"

    log "${DIM}measure ($DURATION) …${RST}"
    # Run in background so we can record CLIENT_PID for pidstat. In
    # 2vm/ssh mode the PID isn't useful locally, but capturing it
    # keeps the code path uniform.
    run_on_client "$cmd" >"$logfile" 2>&1 &
    CLIENT_PID=$!
    wait "$CLIENT_PID" || true

    local row
    row=$(parse_tool_output "$logfile")
    printf '%s\t%s\t%s\n' "$scenario" "$trial" "$row" >> "$SUMMARY"
}

# -----------------------------------------------------------------------
# Main flow
# -----------------------------------------------------------------------
hdr "V230 — 2-VM (or CPU-isolated) bench"
log "Host CPUs    : $TOTAL_CPUS"
log "Proxy CPUs   : $PROXY_CPUS"
log "Client CPUs  : $CLIENT_CPUS  (mode: $MODE)"
log "Load gen     : $TOOL  (override with TOOL=)"
log "Shape        : c=$CONNECTIONS  warmup=$WARMUP  measure=$DURATION  trials=$TRIALS"
log "Target host  : $TARGET_HOST"
log "Summary TSV  : $SUMMARY"

pin_proxy_cpus

hdr "Endpoint health"
check_endpoint "nginx static  :$BACKEND_PORT"      "http://$TARGET_HOST:$BACKEND_PORT/"
check_endpoint "nginx-proxy   :$NGINX_PROXY_PORT"  "http://$TARGET_HOST:$NGINX_PROXY_PORT/"
check_endpoint "aegis-pingora :$AEGIS_PORT"        "http://$TARGET_HOST:$AEGIS_PORT/" "localhost"

: > "$SUMMARY"

hdr "Scenario A — nginx static :$BACKEND_PORT  (upstream ceiling)"
for t in $(seq 1 "$TRIALS"); do
    run_trial "A-nginx-static" "nginx static :$BACKEND_PORT" \
        "http://$TARGET_HOST:$BACKEND_PORT/" "" "$t"
done

hdr "Scenario B — nginx-proxy :$NGINX_PROXY_PORT → :$BACKEND_PORT  (fair baseline)"
for t in $(seq 1 "$TRIALS"); do
    run_trial "B-nginx-proxy" "nginx-proxy :$NGINX_PROXY_PORT" \
        "http://$TARGET_HOST:$NGINX_PROXY_PORT/" "" "$t"
done

hdr "Scenario C — aegis-pingora :$AEGIS_PORT → :$BACKEND_PORT  (under test)"
for t in $(seq 1 "$TRIALS"); do
    run_trial "C-aegis-pingora" "aegis-pingora :$AEGIS_PORT" \
        "http://$TARGET_HOST:$AEGIS_PORT/" "localhost" "$t"
done

# -----------------------------------------------------------------------
# Render markdown table. Format matches the existing results-*.md
# convention: header row, then one row per (scenario, trial) plus
# an average row per scenario. Right-aligned numeric columns.
# -----------------------------------------------------------------------

# avg_col — average a numeric-prefix column from $SUMMARY for a
# given scenario. Strips trailing "ms"/"k" units, ignores n/a.
avg_col() {
    local scenario="$1" col="$2"  # col index 1-based into the row tuple
    # row in summary: scenario \t trial \t rps \t p50 \t p90 \t p99 \t p999 \t errs
    # so we want field (2 + col) when col=1→rps→field 3
    local fld=$(( 2 + col ))
    awk -F'\t' -v s="$scenario" -v f="$fld" '
        $1 == s {
            v = $f
            # strip "ms" suffix, ignore "n/a*" and "n/a"
            sub(/ms$/, "", v)
            if (v == "n/a" || v == "n/a*" || v == "") next
            sum += v; n++
        }
        END {
            if (n == 0) print "n/a"
            else printf "%.2f", sum/n
        }' "$SUMMARY"
}

render_markdown() {
    local out="$1"  # file path or "-" for stdout
    {
        printf '# V230 — 2-VM bench results (%s)\n\n' "$DATE_TAG"
        printf '**Mode:** %s · **Tool:** %s · **Shape:** c=%s warmup=%s measure=%s · **Trials:** %s\n' \
            "$MODE" "$TOOL" "$CONNECTIONS" "$WARMUP" "$DURATION" "$TRIALS"
        printf '**Proxy CPUs:** %s · **Client CPUs:** %s\n\n' "$PROXY_CPUS" "$CLIENT_CPUS"

        if [ "$TOOL" = "wrk" ]; then
            printf '_p99.9 column is "n/a*" — wrk does not produce a trustworthy p99.9. Use oha for tail latency._\n\n'
        fi

        printf '| Scenario | Trial | RPS | p50 | p90 | p99 | p99.9 | errs |\n'
        printf '|---|---:|---:|---:|---:|---:|---:|---:|\n'

        # Per-trial rows
        while IFS=$'\t' read -r scenario trial rps p50 p90 p99 p999 errs; do
            printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
                "$scenario" "$trial" "$rps" "$p50" "$p90" "$p99" "$p999" "$errs"
        done < "$SUMMARY"

        # Averages
        printf '\n## Averages\n\n'
        printf '| Scenario | avg RPS | avg p50 (ms) | avg p99 (ms) |\n'
        printf '|---|---:|---:|---:|\n'
        for s in A-nginx-static B-nginx-proxy C-aegis-pingora; do
            printf '| **%s** | %s | %s | %s |\n' \
                "$s" "$(avg_col "$s" 1)" "$(avg_col "$s" 2)" "$(avg_col "$s" 4)"
        done
    } > "$out"
}

hdr "Results"
render_markdown /dev/stdout

if [ "$WRITE_RESULTS" = "1" ]; then
    mkdir -p "$(dirname "$RESULTS_FILE")"
    render_markdown "$RESULTS_FILE"
    log "Wrote $RESULTS_FILE"
fi

# -----------------------------------------------------------------------
# pidstat tail — verify the client wasn't CPU-saturated during the
# final measured window. If %CPU is consistently > 90% per assigned
# core the load gen was the bottleneck and the numbers above
# underreport proxy capacity (i.e. the same trap bench_fair.sh fell
# into). Operator should re-run with more CLIENT_CPUS or move to 2vm.
#
# Skipped in ssh/2vm mode because the client PID lives on a host
# we can't pidstat from here.
# -----------------------------------------------------------------------
if [ "$MODE" = "local-taskset" ] && [ -n "$CLIENT_PID" ] && command -v pidstat >/dev/null 2>&1; then
    hdr "Client CPU usage (pidstat tail — verify load gen NOT saturated)"
    # The last run's CLIENT_PID is already exited; pidstat -p on a
    # dead pid is a no-op. Instead grab the loadgen's process group
    # CPU stats from the kernel via /proc — but if we want a live
    # sample for the operator to see, advise running a separate
    # 30s window in another terminal. For automated runs, just
    # print whatever pidstat has retained for the most recent
    # client pid.
    pidstat -p "$CLIENT_PID" 1 5 2>/dev/null || \
        log "${DIM}pidstat: client process $CLIENT_PID already exited — run pidstat against a live oha/wrk in a separate shell to confirm headroom${RST}"
elif [ "$MODE" = "2vm" ]; then
    log "${DIM}2vm mode — run 'pidstat -p \$(pgrep $TOOL) 5' on $CLIENT_VM during a re-run to confirm client headroom${RST}"
fi

log "${GREEN}done${RST} — raw logs: $LOG_DIR/bench-2vm-*-$TS.log"
