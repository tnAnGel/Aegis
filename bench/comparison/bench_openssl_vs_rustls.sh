#!/usr/bin/env bash
#
# V58 — aegis-pingora openssl vs rustls TLS backend bench.
#
# V50 switched the pingora feature from `rustls` to `openssl` because
# rustls's TlsSettings has no callback hook for per-SNI cert routing
# or JA3/JA4 capture. The Cloudflare-recommended pingora path is
# openssl/boringssl; the public claim was "+5-15% handshake
# throughput on modern x86_64". V58 actually measures it on our box.
#
# Run on the stand. Builds aegis-pingora twice — once with `--features
# pingora` (current default = openssl feature) and once with the
# explicit `pingora-rustls` legacy build — then hammers both via wrk
# at HTTPS only (HTTP throughput is identical between TLS backends).
#
# Bench focuses:
#   • Handshake-bound: c=400 short connections (wrk default keep-
#     alives a lot — to stress handshakes use `wrk -c 100 -d 30s` AND
#     a separate openssl s_time pass that does one full handshake per
#     iteration).
#   • Steady-state: c=400 keep-alive — should be at parity (both
#     backends use AES-NI/AVX-512).
#
# Requires:
#   • Two binaries built side by side:
#       cargo build --release --features pingora --bin aegis-pingora
#       (current openssl backend, output: target/release/aegis-pingora)
#     For the rustls comparison, temporarily edit Cargo.toml to
#     `features = ["rustls"]` on the two pingora deps, build into a
#     differently-named output via:
#       cargo build --release --features pingora --bin aegis-pingora --target-dir target/rustls
#   • A self-signed cert at /tmp/aegis-bench.{crt,key}.
#   • A backend at $UPSTREAM (default http://127.0.0.1:8000).
#   • wrk and openssl in $PATH.

set -euo pipefail

PINGORA_OPENSSL_BIN="${PINGORA_OPENSSL_BIN:-/usr/local/bin/aegis-pingora}"
PINGORA_RUSTLS_BIN="${PINGORA_RUSTLS_BIN:-target/rustls/release/aegis-pingora}"
CONFIG="${CONFIG:-/etc/aegis/aegis-bench-tls.conf}"
TLS_PORT="${TLS_PORT:-18443}"
BENCH_SECS="${BENCH_SECS:-30}"
WARMUP_SECS="${WARMUP_SECS:-5}"
HOST_HEADER="${HOST_HEADER:-localhost}"
WRK_PATH="${WRK_PATH:-/api/v1/users}"
DATE="$(date +%F)"
RESULTS_DIR="${RESULTS_DIR:-bench/comparison}"
OUT="${RESULTS_DIR}/results-${DATE}-V58-openssl-vs-rustls.md"

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }
}
require wrk
require openssl

mkdir -p "$RESULTS_DIR"

stop_all() {
    pkill -9 -f /aegis-pingora 2>/dev/null || true
    sleep 1
}

wait_for_port() {
    local port="$1"
    local n=0
    while ! ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; do
        sleep 0.1
        n=$((n + 1))
        [ $n -gt 50 ] && { echo "  ERROR: port $port never came up"; return 1; }
    done
}

bench_one() {
    local backend="$1" bin="$2" desc="$3" connections="$4"
    echo "==> $backend / $desc / c=$connections"
    stop_all
    AEGIS_HONEYPOT_STATE="/tmp/aegis-bench-hp-$backend.json" \
        "$bin" --config "$CONFIG" --log-level error & disown
    wait_for_port "$TLS_PORT"
    sleep "$WARMUP_SECS"
    local log
    log=$(wrk -t8 -c"$connections" -d"${BENCH_SECS}s" \
        -H "Host: $HOST_HEADER" \
        "https://127.0.0.1:${TLS_PORT}${WRK_PATH}" 2>&1) || true
    local rps p99
    rps=$(echo "$log" | awk '/Requests\/sec:/ { print $2 }')
    p99=$(echo "$log" | awk '/Latency Distribution/{flag=1; next} /[ \t]*99%/ && flag { print $2; exit }')
    # Handshake-only: openssl s_time gives connections-per-second for
    # full new handshakes (no session resumption).
    local hps
    hps=$(timeout 10 openssl s_time \
        -connect "127.0.0.1:${TLS_PORT}" -www "$WRK_PATH" \
        -new -time 5 2>&1 | awk '/^[0-9]+ connections in [0-9.]+ real/ { print $1 / $4 }') || hps="N/A"
    printf '| %s | %s | %s | %s | %s |\n' \
        "$backend" "$desc/c=$connections" "$rps" "$p99" "$hps" >>"$OUT"
    stop_all
}

cat >"$OUT" <<HEADER
# V58 — aegis-pingora openssl vs rustls TLS backend bench

Run date: $DATE
Hostname: $(hostname)
Kernel: $(uname -r)
CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || echo unknown)
TLS cert: /tmp/aegis-bench.{crt,key} (RSA 2048 self-signed)
wrk: $(wrk --version 2>&1 | head -1)
openssl: $(openssl version)

V50 switched pingora to the openssl feature to unblock per-SNI +
JA3/JA4. Public Cloudflare claim was "+5-15% handshake throughput
on x86_64". This bench measures the real number on our hardware.

## Results

| Backend | Scenario | RPS (steady) | p99 latency | Handshakes/sec (new) |
|---|---|---|---|---|
HEADER

if [ -x "$PINGORA_OPENSSL_BIN" ]; then
    bench_one "openssl" "$PINGORA_OPENSSL_BIN" "steady" 400
    bench_one "openssl" "$PINGORA_OPENSSL_BIN" "light"  64
fi

if [ -x "$PINGORA_RUSTLS_BIN" ]; then
    bench_one "rustls" "$PINGORA_RUSTLS_BIN" "steady" 400
    bench_one "rustls" "$PINGORA_RUSTLS_BIN" "light"  64
else
    echo ""
    echo "WARN: $PINGORA_RUSTLS_BIN not found — rustls row skipped."
    echo "      Build via:"
    echo "        # temporarily switch Cargo.toml pingora features"
    echo "        # to [\"rustls\"], then:"
    echo "        cargo build --release --features pingora --bin aegis-pingora \\"
    echo "                    --target-dir target/rustls"
    echo "        # restore Cargo.toml afterwards"
    echo ""
fi

cat >>"$OUT" <<FOOTER

## Interpretation

- **RPS (steady)** — same TCP connection, repeated requests. AES-NI
  hardware does the crypto; openssl vs rustls difference should be
  noise. Parity is the expected result.

- **p99 latency** — tail latency under sustained load. Backends with
  better tail behaviour (fewer GC pauses, less head-of-line blocking
  on cert lookups) show lower numbers.

- **Handshakes/sec (new)** — the metric that actually moves between
  TLS backends. openssl's mature C handshake code typically beats
  rustls by 5-15% on x86_64 (Cloudflare's published numbers). Will
  it on our box?

If the openssl row's "Handshakes/sec" is ≥10% above the rustls row,
V50 was a perf win (alongside the feature unblock). If they're at
parity, V50 was a feature-only win. If openssl is slower, file a
follow-up to investigate (build flags, libssl version, etc.).
FOOTER

echo ""
echo "Wrote $OUT"
echo ""
cat "$OUT" | tail -30
