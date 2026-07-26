#!/bin/bash
# bench_fair.sh — head-to-head throughput comparison with an HONEST
# upstream.
#
# What was wrong with the old setup: python3 http.server topped out at
# ~4k RPS and became the bottleneck for every test. Both nginx and
# aegis hit the same ceiling and we couldn't see the proxy-stack diff.
# This version uses nginx-as-static for the upstream so the backend
# can sustain 200k+ RPS on a modern box and the difference between
# proxies actually shows up.
#
# Four tests, identical wrk shape (4t x 100c x 15s):
#   1. Direct  upstream  :8000  - ceiling (no proxy in path)
#   2. Nginx   proxy     :8081  - fair reverse-proxy comparison
#   3. Aegis   bypassed  :80    - all filters off (measures bare proxy)
#   4. Aegis   defenses  :80    - waf/bot/adaptive ON, challenge OFF
#
# The script is idempotent: re-run as many times as you want. It
# only restarts services it knows about and tolerates already-stopped
# state. Raw wrk outputs land in /tmp/bench-fair-<test>-<ts>.log.
#
# Requirements: root (for nginx/aegis writes + systemctl), wrk, nginx,
# aegis already installed and running, AEGIS_ADMIN_TOKEN env exported
# (used to flip filter toggles via /admin/api/defaults/filters).

set -eu
set -o pipefail
# fallback: don't die on housekeeping failures, only on the actual bench
trap 'true' ERR

# -----------------------------------------------------------------------
# Configuration knobs
# -----------------------------------------------------------------------
WRK_THREADS="${WRK_THREADS:-4}"
WRK_CONNS="${WRK_CONNS:-100}"
WRK_DUR="${WRK_DUR:-15s}"

BACKEND_PORT="${BACKEND_PORT:-8000}"
NGINX_PROXY_PORT="${NGINX_PROXY_PORT:-8081}"
AEGIS_PORT="${AEGIS_PORT:-80}"
AEGIS_ADMIN="${AEGIS_ADMIN:-http://127.0.0.1:9090}"
AEGIS_CONF="${AEGIS_CONF:-/etc/aegis/aegis.conf}"

ADMIN_TOKEN="${AEGIS_ADMIN_TOKEN:-}"
if [ -z "$ADMIN_TOKEN" ]; then
    echo "WARN: AEGIS_ADMIN_TOKEN not set — filter-toggle writes will fail." >&2
    echo "      Export it or fall back to editing $AEGIS_CONF + restart." >&2
fi

TS=$(date +%Y%m%d-%H%M%S)
LOG_DIR="${LOG_DIR:-/tmp}"

# ANSI colours (skip when stdout isn't a tty)
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; BLUE=$'\033[34m'; CYAN=$'\033[36m'; RST=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; RST=""
fi

log() { printf '%s[%s]%s %s\n' "$DIM" "$(date +%H:%M:%S)" "$RST" "$*"; }
hdr() { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RST"; }

# -----------------------------------------------------------------------
# Tool / runtime sanity checks
# -----------------------------------------------------------------------
for tool in wrk nginx curl awk sed; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "${RED}FATAL: $tool not installed${RST}" >&2
        exit 1
    fi
done

# -----------------------------------------------------------------------
# Toggle helpers — push runtime filter on/off via admin API
# (DSL does NOT expose a top-level `bypass` block; BypassConfig lives
# at src/config.rs:593 but the DSL lower at src/dsl/lower.rs:452 sets
# it to Default::default() unconditionally. So "bypass 127.0.0.1" at
# runtime is achieved by turning every L7 filter off via the admin
# API: GET/PUT /admin/api/defaults/filters. Registered toggle names
# come from each filter's `fn name()` impl — waf, bot, challenge,
# adaptive, ip_acl, rate_limit, honeypot, threat_intel.)
# -----------------------------------------------------------------------
ALL_FILTERS="waf bot challenge adaptive ip_acl rate_limit honeypot threat_intel"

filter_toggle_set() {
    # $1 = filter name, $2 = "true" | "false"
    local name="$1" enabled="$2"
    if [ -z "$ADMIN_TOKEN" ]; then return 0; fi
    curl -sS -X PUT \
        -H "x-admin-token: $ADMIN_TOKEN" \
        -H 'content-type: application/json' \
        --data "[{\"name\":\"$name\",\"enabled\":$enabled}]" \
        "$AEGIS_ADMIN/admin/api/defaults/filters" >/dev/null || true
}

filters_all_off() {
    log "${CYAN}Aegis: all L7 filters OFF (simulates 127.0.0.1 in bypass)${RST}"
    for f in $ALL_FILTERS; do filter_toggle_set "$f" "false"; done
}

filters_defenses_on_no_challenge() {
    log "${CYAN}Aegis: defenses ON (challenge ladder OFF for nginx-parity)${RST}"
    for f in $ALL_FILTERS; do filter_toggle_set "$f" "true"; done
    # Challenge ladder always off — nginx has no JS gate, so leaving
    # it on punishes Aegis unfairly on raw RPS. Operators who want
    # production-with-challenge numbers should drop the next line.
    filter_toggle_set "challenge" "false"
}

# -----------------------------------------------------------------------
# Step 1 — backend: nginx serving a tiny static body on :8000 with
# keepalive so it's never the bottleneck. Reuses an existing config
# block if one's there, otherwise installs one.
# -----------------------------------------------------------------------
hdr "Step 1: backend nginx on 127.0.0.1:$BACKEND_PORT"

mkdir -p /var/www/test
echo "OK" > /var/www/test/index.html

if [ -d /etc/nginx/sites-available ]; then
    cat > /etc/nginx/sites-available/bench-backend <<EOF
server {
    listen 127.0.0.1:$BACKEND_PORT default_server backlog=8192;
    server_name _;

    access_log off;
    root /var/www/test;
    keepalive_requests 100000;
    keepalive_timeout  75s;

    location / {
        try_files /index.html =404;
        # explicit body — survives if /var/www/test gets wiped
        return 200 "OK\n";
    }
}
EOF
    ln -sf /etc/nginx/sites-available/bench-backend /etc/nginx/sites-enabled/bench-backend
else
    # /etc/nginx is non-standard (Alpine etc.) — drop directly into conf.d
    cat > /etc/nginx/conf.d/bench-backend.conf <<EOF
server {
    listen 127.0.0.1:$BACKEND_PORT default_server backlog=8192;
    server_name _;
    access_log off;
    keepalive_requests 100000;
    keepalive_timeout  75s;
    location / { return 200 "OK\n"; }
}
EOF
fi

# -----------------------------------------------------------------------
# Step 2 — comparison proxy: nginx :8081 -> 127.0.0.1:8000 with the
# upstream-keepalive incantation that 90% of nginx benches forget.
# Without `proxy_http_version 1.1` + `Connection ""` + an explicit
# `keepalive` directive in the upstream block, every proxied request
# opens a new TCP connection to the backend and the comparison turns
# into a connection-setup latency benchmark.
# -----------------------------------------------------------------------
hdr "Step 2: nginx-proxy on 127.0.0.1:$NGINX_PROXY_PORT"

NGX_CONF=/etc/nginx/sites-available/bench-proxy
if [ ! -d /etc/nginx/sites-available ]; then
    NGX_CONF=/etc/nginx/conf.d/bench-proxy.conf
fi

cat > "$NGX_CONF" <<EOF
upstream bench_backend {
    server 127.0.0.1:$BACKEND_PORT;
    keepalive 64;
}

server {
    listen 127.0.0.1:$NGINX_PROXY_PORT default_server backlog=8192;
    server_name _;
    access_log off;

    location / {
        proxy_pass http://bench_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_read_timeout 30s;
    }
}
EOF

if [ -d /etc/nginx/sites-enabled ]; then
    ln -sf "$NGX_CONF" /etc/nginx/sites-enabled/bench-proxy
    # Drop the default that would steal :80 / cause "duplicate" warnings
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
fi

nginx -t >/dev/null 2>&1 || {
    echo "${RED}FATAL: nginx -t failed${RST}" >&2
    nginx -t
    exit 1
}

if command -v systemctl >/dev/null 2>&1; then
    systemctl restart nginx
else
    nginx -s reload 2>/dev/null || nginx
fi
sleep 1

# -----------------------------------------------------------------------
# Step 3 — verify all three layers actually answer 200
# -----------------------------------------------------------------------
hdr "Step 3: handshake checks"

check() {
    local name="$1" url="$2" extra="${3:-}"
    local code
    # shellcheck disable=SC2086
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 $extra "$url" 2>/dev/null || echo "ERR")
    if [ "$code" = "200" ]; then
        printf '  %s%-22s%s -> %s%s%s\n' "$DIM" "$name" "$RST" "$GREEN" "$code" "$RST"
    else
        printf '  %s%-22s%s -> %s%s%s\n' "$DIM" "$name" "$RST" "$RED" "$code" "$RST"
    fi
}

check "backend  :$BACKEND_PORT"      "http://127.0.0.1:$BACKEND_PORT/"
check "nginx-proxy :$NGINX_PROXY_PORT" "http://127.0.0.1:$NGINX_PROXY_PORT/"
check "aegis   :$AEGIS_PORT"          "http://127.0.0.1:$AEGIS_PORT/" "-H Host:localhost"

# -----------------------------------------------------------------------
# Step 4 — run the four wrk tests
# -----------------------------------------------------------------------
WRK_ARGS="-t$WRK_THREADS -c$WRK_CONNS -d$WRK_DUR --latency"

run_wrk() {
    # $1 = test slug (filename-safe), $2 = label, $3 = url, $4... = curl-style header args
    local slug="$1" label="$2" url="$3"
    shift 3
    local log="$LOG_DIR/bench-fair-$slug-$TS.log"
    log "${BLUE}-> $label${RST}  (logging to $log)"
    # shellcheck disable=SC2086
    wrk $WRK_ARGS "$@" "$url" >"$log" 2>&1 || true
    local rps p50 p99
    rps=$(awk '/Requests\/sec/ {print $2}' "$log")
    p50=$(awk '/^ *50%/   {print $2; exit}' "$log")
    p99=$(awk '/^ *99%/   {print $2; exit}' "$log")
    printf '%s\t%s\t%s\t%s\n' "$slug" "${rps:-fail}" "${p50:-?}" "${p99:-?}" >> "$LOG_DIR/bench-fair-$TS.summary"
}

# Ensure the summary file starts clean for this run
: > "$LOG_DIR/bench-fair-$TS.summary"

hdr "Step 4: throughput tests (wrk -t$WRK_THREADS -c$WRK_CONNS -d$WRK_DUR)"

# 4.1 — direct upstream (no proxy)
run_wrk "direct" "Direct upstream  :$BACKEND_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/"

# 4.2 — nginx-proxy
run_wrk "nginx-proxy" "Nginx proxy      :$NGINX_PROXY_PORT" \
    "http://127.0.0.1:$NGINX_PROXY_PORT/"

# 4.3 — aegis with all filters off (logical equivalent of bypass)
filters_all_off
sleep 1
run_wrk "aegis-bypass" "Aegis bypassed   :$AEGIS_PORT  (all L7 filters off)" \
    "http://127.0.0.1:$AEGIS_PORT/" -H "Host: localhost"

# 4.4 — aegis with production defenses on, challenge off for nginx parity
filters_defenses_on_no_challenge
sleep 1
run_wrk "aegis-defenses" "Aegis defenses   :$AEGIS_PORT  (waf/bot/adaptive ON)" \
    "http://127.0.0.1:$AEGIS_PORT/" -H "Host: localhost"

# -----------------------------------------------------------------------
# Step 5 — print the summary table
# -----------------------------------------------------------------------
hdr "Results"

# Pull RPS values into named vars for ratio math
extract() { awk -F'\t' -v slug="$1" '$1==slug {print $2}' "$LOG_DIR/bench-fair-$TS.summary"; }
RPS_DIRECT=$(extract direct)
RPS_NGINX=$(extract nginx-proxy)
RPS_BYPASS=$(extract aegis-bypass)
RPS_DEFENSES=$(extract aegis-defenses)

# helper for ratio printing (handles missing/non-numeric inputs gracefully)
ratio() {
    awk -v num="$1" -v den="$2" 'BEGIN{
        if (num+0==0 || den+0==0) { print "n/a"; exit }
        printf "%.2fx", num/den
    }'
}

R_BYPASS=$(ratio "$RPS_BYPASS"  "$RPS_NGINX")
R_DEF=$(ratio    "$RPS_DEFENSES" "$RPS_NGINX")

# ANSI box drawing — sticks to ASCII so it survives tmux + dumb terminals
SEP="+--------------------------+-------------+-------------+-------------+"
printf '\n%s%s%s\n'      "$BOLD" "$SEP" "$RST"
printf '%s| %-24s | %-11s | %-11s | %-11s |%s\n' \
    "$BOLD" "Test" "RPS" "p50" "p99" "$RST"
printf '%s%s%s\n' "$BOLD" "$SEP" "$RST"

row() {
    local label="$1" slug="$2" colour="$3"
    local rps p50 p99
    rps=$(awk -F'\t' -v s="$slug" '$1==s {print $2}' "$LOG_DIR/bench-fair-$TS.summary")
    p50=$(awk -F'\t' -v s="$slug" '$1==s {print $3}' "$LOG_DIR/bench-fair-$TS.summary")
    p99=$(awk -F'\t' -v s="$slug" '$1==s {print $4}' "$LOG_DIR/bench-fair-$TS.summary")
    printf '| %s%-24s%s | %11s | %11s | %11s |\n' \
        "$colour" "$label" "$RST" "${rps:-?}" "${p50:-?}" "${p99:-?}"
}

row "Direct upstream"        direct          "$DIM"
row "Nginx proxy"            nginx-proxy     ""
row "Aegis bypassed"         aegis-bypass    "$CYAN"
row "Aegis defenses"         aegis-defenses  "$YELLOW"
printf '%s%s%s\n' "$BOLD" "$SEP" "$RST"

printf '\n%sRatios (vs. nginx-proxy):%s\n' "$BOLD" "$RST"
printf '  Aegis bypassed  / nginx-proxy : %s%s%s\n' "$GREEN"  "$R_BYPASS" "$RST"
printf '  Aegis defenses  / nginx-proxy : %s%s%s\n' "$YELLOW" "$R_DEF"    "$RST"

printf '\nRaw outputs   : %s/bench-fair-*-%s.log\n' "$LOG_DIR" "$TS"
printf 'Summary TSV   : %s/bench-fair-%s.summary\n' "$LOG_DIR" "$TS"

# Leave Aegis in a defensible state (defenses on, challenge off) — the
# operator can flip challenge back on with one curl if they want.
log "${DIM}Aegis filters left as: defenses ON, challenge OFF${RST}"
