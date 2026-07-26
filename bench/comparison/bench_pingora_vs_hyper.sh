#!/usr/bin/env bash
#
# V57 — aegis (hyper) vs aegis-pingora full bench harness.
#
# Run this ON the production stand (or any Linux box) with a real
# multi-core CPU + a fast upstream. Writes a results markdown to
# bench/comparison/results-$(date +%F)-V57-pingora-vs-hyper.md.
#
# Run modes (matrix):
#   • aegis (hyper) single process
#   • aegis (hyper) N=4 via SO_REUSEPORT
#   • aegis-pingora single worker
#   • aegis-pingora N=4 via AEGIS_PINGORA_REUSEPORT=1
#
# Each mode runs three wrk scenarios:
#   • c=64  d=30s  — light load, p99 latency focus
#   • c=400 d=30s  — heavy load, throughput ceiling
#   • c=400 d=30s with WAF on, 30% scanner traffic — defense overhead
#
# Requirements on the stand:
#   • cargo build --release --features pingora --bin aegis-pingora
#   • cargo build --release --bin aegis
#   • An upstream binary on UPSTREAM (default 127.0.0.1:8000) that
#     returns a static body fast (nginx 'return 200 "ok"' works well).
#   • wrk in $PATH.
#   • A configured /etc/aegis/aegis.conf with both binaries' state
#     paths writable.

set -euo pipefail

# === knobs (override via env) =========================================
AEGIS_BIN="${AEGIS_BIN:-/usr/local/bin/aegis}"
AEGIS_PINGORA_BIN="${AEGIS_PINGORA_BIN:-/usr/local/bin/aegis-pingora}"
CONFIG="${CONFIG:-/etc/aegis/aegis.conf}"
HOST_HEADER="${HOST_HEADER:-localhost}"
UPSTREAM="${UPSTREAM:-http://127.0.0.1:8000}"
HYPER_PORT="${HYPER_PORT:-8181}"
PINGORA_PORT="${PINGORA_PORT:-8282}"
N_WORKERS="${N_WORKERS:-4}"
WARMUP_SECS="${WARMUP_SECS:-5}"
BENCH_SECS="${BENCH_SECS:-30}"
RESULTS_DIR="${RESULTS_DIR:-bench/comparison}"
DATE="$(date +%F)"
OUT="${RESULTS_DIR}/results-${DATE}-V57-pingora-vs-hyper.md"
WRK_PATH="${WRK_PATH:-/api/v1/users}"
# Scanner paths fired at 30% rate in the mixed scenario — hit known
# WAF signatures so the WAF actually rejects (not just runs).
SCANNER_PATHS=(
    "/../../etc/passwd"
    "/etc/shadow"
    "/wp-admin/setup-config.php"
    "/.git/config"
    "/login?id=1%27%20OR%20%271%27=%271"
)

# === sanity ===========================================================
require() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }
}
require wrk

if [ ! -x "$AEGIS_BIN" ]; then
    echo "warn: $AEGIS_BIN not executable — skipping hyper modes" >&2
    SKIP_HYPER=1
fi
if [ ! -x "$AEGIS_PINGORA_BIN" ]; then
    echo "warn: $AEGIS_PINGORA_BIN not executable — skipping pingora modes" >&2
    SKIP_PINGORA=1
fi
[ "${SKIP_HYPER:-0}" = "1" ] && [ "${SKIP_PINGORA:-0}" = "1" ] && {
    echo "both binaries missing — nothing to bench" >&2
    exit 1
}

mkdir -p "$RESULTS_DIR"

# === helpers ==========================================================
stop_all() {
    pkill -9 -f "$AEGIS_BIN" 2>/dev/null || true
    pkill -9 -f "$AEGIS_PINGORA_BIN" 2>/dev/null || true
    sleep 1
}

wait_for_port() {
    local port="$1"
    local n=0
    while ! ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; do
        sleep 0.1
        n=$((n + 1))
        if [ $n -gt 50 ]; then
            echo "  ERROR: port $port never came up"
            return 1
        fi
    done
}

# Run wrk and append parsed throughput/latency to $OUT.
bench_one() {
    local mode="$1" port="$2" path="$3" connections="$4" desc="$5"
    echo "  bench: $mode @ $connections conn → $path"
    local log
    log=$(wrk -t8 -c"$connections" -d"${BENCH_SECS}s" \
        -H "Host: $HOST_HEADER" \
        "http://127.0.0.1:${port}${path}" 2>&1) || true
    local rps
    local p99
    rps=$(echo "$log" | awk '/Requests\/sec:/ { print $2 }')
    p99=$(echo "$log" | awk '/Latency Distribution/{flag=1; next} /[ \t]*99%/ && flag { print $2; exit }')
    [ -z "$rps" ] && rps="N/A"
    [ -z "$p99" ] && p99="N/A"
    printf '| %s | %s | %s | %s | %s |\n' "$mode" "$desc" "$connections" "$rps" "$p99" >>"$OUT"
}

# === run modes ========================================================
start_hyper_single() {
    "$AEGIS_BIN" \
        --config "$CONFIG" --log-level error \
        & disown
    AEGIS_LISTEN="0.0.0.0:${HYPER_PORT}" wait_for_port "$HYPER_PORT"
}

start_hyper_n4() {
    for n in $(seq 1 "$N_WORKERS"); do
        AEGIS_LISTEN="0.0.0.0:${HYPER_PORT}" \
        AEGIS_HONEYPOT_STATE="/var/lib/aegis/w${n}-honeypots.json" \
        AEGIS_WEB_STATE="/var/lib/aegis/w${n}-web.json" \
            "$AEGIS_BIN" --config "$CONFIG" --log-level error \
            & disown
    done
    wait_for_port "$HYPER_PORT"
}

start_pingora_single() {
    AEGIS_LISTEN="0.0.0.0:${PINGORA_PORT}" \
        "$AEGIS_PINGORA_BIN" --config "$CONFIG" --log-level error \
        & disown
    wait_for_port "$PINGORA_PORT"
}

start_pingora_n4() {
    for n in $(seq 1 "$N_WORKERS"); do
        AEGIS_LISTEN="0.0.0.0:${PINGORA_PORT}" \
        AEGIS_PINGORA_REUSEPORT=1 \
        AEGIS_ADMIN_LISTEN="127.0.0.1:909${n}" \
        AEGIS_HONEYPOT_STATE="/var/lib/aegis/w${n}-honeypots.json" \
            "$AEGIS_PINGORA_BIN" --config "$CONFIG" --log-level error \
            & disown
    done
    wait_for_port "$PINGORA_PORT"
}

# === header to results doc ============================================
cat >"$OUT" <<HEADER
# V57 — aegis (hyper) vs aegis-pingora bench

Run date: $DATE
Hostname: $(hostname)
Kernel: $(uname -r)
CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || echo unknown)
Cores online: $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)
Memory: $(free -h 2>/dev/null | awk '/^Mem:/ { print $2 }' || echo unknown)
wrk: $(wrk --version 2>&1 | head -1)

Upstream: $UPSTREAM
Bench path: $WRK_PATH
Host header: $HOST_HEADER
Warmup: ${WARMUP_SECS}s
Bench duration: ${BENCH_SECS}s
Workers (multi-process): $N_WORKERS

## Results

| Mode | Scenario | Connections | RPS | p99 latency |
|---|---|---|---|---|
HEADER

# === bench matrix =====================================================
if [ "${SKIP_HYPER:-0}" != "1" ]; then
    echo "==> hyper single"
    stop_all
    start_hyper_single
    sleep "$WARMUP_SECS"
    bench_one "hyper" "$HYPER_PORT" "$WRK_PATH"   64 "light"
    bench_one "hyper" "$HYPER_PORT" "$WRK_PATH"  400 "heavy"
    stop_all

    echo "==> hyper N=$N_WORKERS"
    start_hyper_n4
    sleep "$WARMUP_SECS"
    bench_one "hyper N=$N_WORKERS" "$HYPER_PORT" "$WRK_PATH"   64 "light"
    bench_one "hyper N=$N_WORKERS" "$HYPER_PORT" "$WRK_PATH"  400 "heavy"
    stop_all
fi

if [ "${SKIP_PINGORA:-0}" != "1" ]; then
    echo "==> pingora single"
    start_pingora_single
    sleep "$WARMUP_SECS"
    bench_one "pingora" "$PINGORA_PORT" "$WRK_PATH"   64 "light"
    bench_one "pingora" "$PINGORA_PORT" "$WRK_PATH"  400 "heavy"
    stop_all

    echo "==> pingora N=$N_WORKERS"
    start_pingora_n4
    sleep "$WARMUP_SECS"
    bench_one "pingora N=$N_WORKERS" "$PINGORA_PORT" "$WRK_PATH"   64 "light"
    bench_one "pingora N=$N_WORKERS" "$PINGORA_PORT" "$WRK_PATH"  400 "heavy"
    stop_all
fi

cat >>"$OUT" <<FOOTER

## Notes

- This run does NOT include the mixed (30% scanner) WAF-on scenario.
  Add it manually by re-running with WAF turned on in the config and
  a wrk Lua script that interleaves SCANNER_PATHS into the request
  stream — see bench/comparison/bench.sh for the original pattern.

- For the multi-worker pingora rows: kernel SO_REUSEPORT accept
  distribution is per-CPU. To get clean numbers, pin each worker to
  its own CPU set via systemd \`CPUAffinity\` (see
  docs/pingora-deployment.md systemd unit template) before re-running.

- The hyper handler computes JA4H + threat-aware cache + dynamic
  trust + anomaly on every request; aegis-pingora computes the same
  (V50-V53). So differences here reflect TLS-stack and pingora's
  hot-path overhead vs hyper-util's Client, not feature gaps.

- Cutover decision: aegis-pingora is the right default when its
  N=$N_WORKERS row beats hyper's N=$N_WORKERS row on heavy throughput
  AND p99 is within 1ms.
FOOTER

echo ""
echo "Wrote $OUT"
echo ""
cat "$OUT" | tail -40
