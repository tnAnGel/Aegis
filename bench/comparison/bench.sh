#!/bin/bash
# Run identical attack/load tests against aegis (:80) and nginx (:8080),
# emit one machine-readable line per test so the harness can table it.
# All tests use the same upstream backend (:8000) so the diff is the
# proxy stack alone.

set +e

apt-get install -y slowhttptest 2>&1 | tail -1

A="http://localhost:80"
N="http://localhost:8080"
A_HOST="-H Host:localhost"

emit() {
    # name | aegis_result | nginx_result | interpretation
    printf '%-40s | %-30s | %-30s | %s\n' "$1" "$2" "$3" "$4"
}

echo "=== T1 baseline throughput (wrk -t4 -c100 -d10s) ==="
A_RPS=$(wrk -t4 -c100 -d10s --latency $A_HOST $A/ 2>/dev/null | awk '/Requests\/sec/ {print $2}')
N_RPS=$(wrk -t4 -c100 -d10s --latency       $N/ 2>/dev/null | awk '/Requests\/sec/ {print $2}')
emit "T1 throughput RPS" "${A_RPS:-fail}" "${N_RPS:-fail}" "higher = better"

echo
echo "=== T1b same load p99 latency ==="
A_P99=$(wrk -t4 -c100 -d10s --latency $A_HOST $A/ 2>/dev/null | awk '/99%/ {print $2}')
N_P99=$(wrk -t4 -c100 -d10s --latency       $N/ 2>/dev/null | awk '/99%/ {print $2}')
emit "T1b p99 latency"       "${A_P99:-fail}" "${N_P99:-fail}" "lower = better"

echo
echo "=== T2 WAF: SQLi in query ==="
A_R=$(curl -sS -o /dev/null -w '%{http_code}' "$A/?q=1%27%20UNION%20SELECT%20*%20FROM%20users" -H 'Host:localhost')
N_R=$(curl -sS -o /dev/null -w '%{http_code}' "$N/?q=1%27%20UNION%20SELECT%20*%20FROM%20users")
emit "T2 SQLi /?q=1' UNION SELECT" "$A_R" "$N_R" "403 = blocked"

echo
echo "=== T3 XSS in query ==="
A_R=$(curl -sS -o /dev/null -w '%{http_code}' "$A/?x=<script>alert(1)</script>" -H 'Host:localhost')
N_R=$(curl -sS -o /dev/null -w '%{http_code}' "$N/?x=<script>alert(1)</script>")
emit "T3 XSS /?x=<script>" "$A_R" "$N_R" "403 = blocked"

echo
echo "=== T4 path traversal ==="
A_R=$(curl -sS -o /dev/null -w '%{http_code}' "$A/?p=../../etc/passwd" -H 'Host:localhost')
N_R=$(curl -sS -o /dev/null -w '%{http_code}' "$N/?p=../../etc/passwd")
emit "T4 path traversal ../../etc/passwd" "$A_R" "$N_R" "403 = blocked"

echo
echo "=== T5 SSRF metadata URL in query ==="
A_R=$(curl -sS -o /dev/null -w '%{http_code}' "$A/?u=http://169.254.169.254/" -H 'Host:localhost')
N_R=$(curl -sS -o /dev/null -w '%{http_code}' "$N/?u=http://169.254.169.254/")
emit "T5 SSRF http://169.254.169.254" "$A_R" "$N_R" "403 = blocked"

echo
echo "=== T6 HTTP method TRACE ==="
A_R=$(curl -sS -o /dev/null -w '%{http_code}' -X TRACE $A/ -H 'Host:localhost')
N_R=$(curl -sS -o /dev/null -w '%{http_code}' -X TRACE $N/)
emit "T6 method TRACE" "$A_R" "$N_R" "405 = blocked"

echo
echo "=== T7 oversize header ==="
BIG=$(python3 -c 'print("a"*16000)')
A_R=$(curl -sS -o /dev/null -w '%{http_code}' $A/ -H 'Host:localhost' -H "X-Big: $BIG" --max-time 5)
N_R=$(curl -sS -o /dev/null -w '%{http_code}' $N/ -H "X-Big: $BIG" --max-time 5)
emit "T7 16KB header X-Big"   "$A_R" "$N_R" "431 = blocked"

echo
echo "=== T8 oversize URI ==="
LONG=$(python3 -c 'print("/" + "a"*9000)')
A_R=$(curl -sS -o /dev/null -w '%{http_code}' "$A$LONG" -H 'Host:localhost' --max-time 5)
N_R=$(curl -sS -o /dev/null -w '%{http_code}' "$N$LONG" --max-time 5)
emit "T8 9KB URI"             "$A_R" "$N_R" "414 = blocked"

echo
echo "=== T9 honeypot /wp-login.php ==="
A_START=$(date +%s%N)
curl -sS -o /dev/null --max-time 35 $A/wp-login.php -H 'Host:localhost'
A_ELAPSED=$(( ($(date +%s%N) - A_START) / 1000000 ))
N_START=$(date +%s%N)
N_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 35 $N/wp-login.php)
N_ELAPSED=$(( ($(date +%s%N) - N_START) / 1000000 ))
emit "T9 honeypot /wp-login.php"  "tarpit ${A_ELAPSED}ms" "${N_R} ${N_ELAPSED}ms" "Aegis pins scanner; nginx instant 200"

echo
echo "=== T10 honeypot /.env ==="
A_START=$(date +%s%N)
curl -sS -o /dev/null --max-time 35 $A/.env -H 'Host:localhost'
A_ELAPSED=$(( ($(date +%s%N) - A_START) / 1000000 ))
N_START=$(date +%s%N)
N_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 35 $N/.env)
N_ELAPSED=$(( ($(date +%s%N) - N_START) / 1000000 ))
emit "T10 honeypot /.env"        "tarpit ${A_ELAPSED}ms" "${N_R} ${N_ELAPSED}ms" "Aegis pins scanner; nginx 404/200"

echo
echo "=== T11 bot UA sqlmap ==="
A_R=$(for i in 1 2 3 4 5; do curl -sS -o /dev/null -w '%{http_code} ' $A/ -H 'Host:localhost' -A 'sqlmap/1.7.2#stable'; done)
N_R=$(for i in 1 2 3 4 5; do curl -sS -o /dev/null -w '%{http_code} ' $N/ -A 'sqlmap/1.7.2#stable'; done)
emit "T11 bot UA sqlmap x5"  "$A_R" "$N_R" "403/challenge after threshold"

echo
echo "=== T12 CL/TE smuggling header pair ==="
A_R=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 nc -q 1 localhost 80 | head -1)
N_R=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 nc -q 1 localhost 8080 | head -1)
emit "T12 CL/TE smuggling"   "${A_R:-no-resp}" "${N_R:-no-resp}" "400 = blocked"

echo
echo "=== T13 graphql introspection ==="
PAYLOAD='{"query":"{__schema{types{name}}}"}'
A_R=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Host:localhost' -H 'Content-Type:application/json' -d "$PAYLOAD" $A/graphql)
N_R=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type:application/json' -d "$PAYLOAD" $N/graphql)
emit "T13 GraphQL __schema POST" "$A_R" "$N_R" "403 = blocked (when graphql filter on)"

echo
echo "=== T14 deep nesting graphql alias DoS ==="
ALIASES=$(python3 -c 'print(" ".join([f"a{i}:user" for i in range(100)]))')
PAYLOAD="{\"query\":\"{ $ALIASES }\"}"
A_R=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Host:localhost' -H 'Content-Type:application/json' -d "$PAYLOAD" $A/graphql)
N_R=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type:application/json' -d "$PAYLOAD" $N/graphql)
emit "T14 GraphQL alias DoS (100 aliases)" "$A_R" "$N_R" "400 = blocked"

echo
echo "=== T15 slowloris (slowhttptest -H 50 conn 60s) ==="
A_R=$(slowhttptest -c 50 -H -i 10 -r 50 -t GET -u $A/ -x 24 -p 3 -l 30 2>&1 | awk '/Service available/ {print $NF}' | head -1)
N_R=$(slowhttptest -c 50 -H -i 10 -r 50 -t GET -u $N/ -x 24 -p 3 -l 30 2>&1 | awk '/Service available/ {print $NF}' | head -1)
emit "T15 slowloris (50 slow conn, 30s)"    "service avail: ${A_R:-?}" "service avail: ${N_R:-?}" "YES = held under attack"

echo
echo "=== T16 flood — wrk -t8 -c500 -d10s on unfiltered path ==="
A_FLOOD=$(wrk -t8 -c500 -d10s $A_HOST $A/ 2>/dev/null | awk '/Requests\/sec/ {print $2}')
N_FLOOD=$(wrk -t8 -c500 -d10s       $N/ 2>/dev/null | awk '/Requests\/sec/ {print $2}')
emit "T16 sustained 500-conn flood RPS" "$A_FLOOD" "$N_FLOOD" "higher = better"

echo
echo "=== T17 rapid SQLi blast from one IP — should escalate ==="
A_BLOCKED=0
for i in $(seq 1 20); do
    code=$(curl -sS -o /dev/null -w '%{http_code}' "$A/?q=1%27+UNION+SELECT+*" -H 'Host:localhost')
    [ "$code" = "403" ] && A_BLOCKED=$((A_BLOCKED+1))
done
N_BLOCKED=0
for i in $(seq 1 20); do
    code=$(curl -sS -o /dev/null -w '%{http_code}' "$N/?q=1%27+UNION+SELECT+*")
    [ "$code" = "403" ] && N_BLOCKED=$((N_BLOCKED+1))
done
emit "T17 20x SQLi from one IP" "${A_BLOCKED}/20 blocked" "${N_BLOCKED}/20 blocked" "20 = full block"
