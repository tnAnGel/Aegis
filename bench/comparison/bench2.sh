#!/bin/bash
set +e
A="http://localhost:80"
N="http://localhost:8080"
A_HOST=(-H Host:localhost)

emit() {
    printf '%-42s | %-32s | %-32s | %s\n' "$1" "$2" "$3" "$4"
}

echo "=== Throughput (wrk -t4 -c100 -d10s) ==="
A_OUT=$(wrk -t4 -c100 -d10s --latency "${A_HOST[@]}" $A/ 2>/dev/null)
N_OUT=$(wrk -t4 -c100 -d10s --latency       $N/ 2>/dev/null)
A_RPS=$(echo "$A_OUT" | awk '/Requests\/sec/ {print $2}')
N_RPS=$(echo "$N_OUT" | awk '/Requests\/sec/ {print $2}')
A_P99=$(echo "$A_OUT" | awk '/99%/ {print $2}')
N_P99=$(echo "$N_OUT" | awk '/99%/ {print $2}')
A_LAT_AVG=$(echo "$A_OUT" | awk '/Latency / && /us|ms|s/ {print $2; exit}')
N_LAT_AVG=$(echo "$N_OUT" | awk '/Latency / && /us|ms|s/ {print $2; exit}')
emit "Raw throughput RPS"      "$A_RPS" "$N_RPS" "higher = better"
emit "Avg latency"             "$A_LAT_AVG" "$N_LAT_AVG" "lower = better"
emit "p99 latency"             "$A_P99" "$N_P99" "lower = better"

echo
echo "=== WAF / signature tests ==="
for path in \
    "?q=1%27%20UNION%20SELECT%20*%20FROM%20users:SQLi UNION SELECT" \
    "?q=1%27+or+1%3D1:SQLi or 1=1" \
    "?x=javascript%3Aalert%281%29:XSS javascript:alert" \
    "?u=http%3A%2F%2F169.254.169.254%2F:SSRF metadata" \
    "?p=..%2F..%2Fetc%2Fpasswd:path traversal" \
    "?c=foo%3Bcat+%2Fetc%2Fpasswd:cmdi cat /etc/passwd" \
    "?q=1%27%3B+WAITFOR+DELAY+%2700%3A00%3A10%27--:time-based SQLi" \
    "?q=%2F%2A%21UNION%2A%2F+SELECT:MySQL versioned comment"; do
    p="${path%%:*}"
    label="${path#*:}"
    A_R=$(curl -sS -o /dev/null -w '%{http_code}' "$A/$p" -H 'Host:localhost')
    N_R=$(curl -sS -o /dev/null -w '%{http_code}' "$N/$p")
    emit "WAF $label" "$A_R" "$N_R" "403 = blocked"
done

echo
echo "=== HTTP smuggling / protocol abuse ==="
A_R=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 nc -q 1 localhost 80 | head -1 | tr -d '\r')
N_R=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 nc -q 1 localhost 8080 | head -1 | tr -d '\r')
emit "CL/TE smuggling (raw nc)" "${A_R:-no-resp}" "${N_R:-no-resp}" "400 = blocked"
A_R=$(printf 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello' | timeout 3 nc -q 1 localhost 80 | head -1 | tr -d '\r')
N_R=$(printf 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello' | timeout 3 nc -q 1 localhost 8080 | head -1 | tr -d '\r')
emit "Duplicate CL headers" "${A_R:-no-resp}" "${N_R:-no-resp}" "400 = blocked"
A_R=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: cow\r\n\r\n' | timeout 3 nc -q 1 localhost 80 | head -1 | tr -d '\r')
N_R=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: cow\r\n\r\n' | timeout 3 nc -q 1 localhost 8080 | head -1 | tr -d '\r')
emit "Bad TE token (cow)" "${A_R:-no-resp}" "${N_R:-no-resp}" "400 = blocked"

echo
echo "=== HTTP method gate ==="
for method in TRACE PROPFIND OPTIONS CONNECT; do
    A_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -X $method $A/ -H 'Host:localhost')
    N_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -X $method $N/)
    emit "method $method" "$A_R" "$N_R" "405 = blocked for TRACE/PROPFIND/CONNECT"
done

echo
echo "=== Oversize hardening ==="
BIG=$(python3 -c 'print("a"*16000)')
A_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 $A/ -H 'Host:localhost' -H "X-Big: $BIG")
N_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 $N/ -H "X-Big: $BIG")
emit "16KB header X-Big" "$A_R" "$N_R" "431 = blocked"
LONG=$(python3 -c 'print("/" + "a"*9000)')
A_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$A$LONG" -H 'Host:localhost')
N_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$N$LONG")
emit "9KB URI" "$A_R" "$N_R" "414 = blocked"

echo
echo "=== Honeypots — tarpit elapsed ==="
for path in /wp-login.php /.env /xmlrpc.php /phpmyadmin/ /.git/config /administrator/ /actuator/env /server-status; do
    A_S=$(date +%s%N); curl -sS -o /dev/null --max-time 12 $A$path -H 'Host:localhost'; A_E=$((($(date +%s%N)-A_S)/1000000))
    N_R=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 12 $N$path)
    emit "honeypot $path" "tarpit ${A_E}ms" "$N_R" "aegis pins ~12s; nginx 404"
done

echo
echo "=== Slowloris (slowhttptest 50 slow conn, 30s) ==="
A_OUT=$(slowhttptest -c 50 -H -i 10 -r 200 -t GET -u $A/ -x 24 -p 3 -l 30 2>&1)
N_OUT=$(slowhttptest -c 50 -H -i 10 -r 200 -t GET -u $N/ -x 24 -p 3 -l 30 2>&1)
A_AVAIL=$(echo "$A_OUT" | grep -oE 'Service available:\s+(YES|NO)' | head -1)
N_AVAIL=$(echo "$N_OUT" | grep -oE 'Service available:\s+(YES|NO)' | head -1)
emit "Slowloris: service stayed up" "${A_AVAIL:-?}" "${N_AVAIL:-?}" "YES = held during attack"

echo
echo "=== Sustained flood (wrk 8t 500c 10s) ==="
A_FLOOD=$(wrk -t8 -c500 -d10s "${A_HOST[@]}" $A/ 2>/dev/null | awk '/Requests\/sec/ {print $2}')
N_FLOOD=$(wrk -t8 -c500 -d10s               $N/ 2>/dev/null | awk '/Requests\/sec/ {print $2}')
emit "500-conn flood RPS" "$A_FLOOD" "$N_FLOOD" "higher = better"

echo
echo "=== Sustained attack: 20× SQLi from same IP ==="
A_BLOCKED=0; for i in $(seq 1 20); do c=$(curl -sS -o /dev/null -w '%{http_code}' "$A/?q=1%27+UNION+SELECT" -H 'Host:localhost'); [ "$c" = "403" ] && A_BLOCKED=$((A_BLOCKED+1)); done
N_BLOCKED=0; for i in $(seq 1 20); do c=$(curl -sS -o /dev/null -w '%{http_code}' "$N/?q=1%27+UNION+SELECT"); [ "$c" = "403" ] && N_BLOCKED=$((N_BLOCKED+1)); done
emit "20× SQLi same IP" "${A_BLOCKED}/20 blocked" "${N_BLOCKED}/20 blocked" "20 = full block"

echo
echo "=== Scanner sweep: 30 honeypot paths in 1s ==="
A_TIME=$(date +%s%N)
for p in /wp-login.php /.env /xmlrpc.php /phpmyadmin/ /administrator/ /actuator/env /server-status /.git/config /shell.php /c99.php /.ssh/id_rsa /web.config /backup.zip /.aws/credentials /HNAP1/ /vendor/phpunit /package.json /Jenkinsfile /downloader/ /Magento_Version /Trace.axd /jmx-console/ /joomla/administrator/ /wp-config.php /info.php /CHANGELOG.txt /db.sql /wp-admin/install.php /core/install.php /test.php; do
    curl -sS -o /dev/null --max-time 1 "$A$p" -H 'Host:localhost' &
done
wait
A_ELAPSED=$((($(date +%s%N)-A_TIME)/1000000))
emit "30-path scanner sweep (parallel)" "${A_ELAPSED}ms held" "n/a (no honeypot)" "aegis: 30 workers stuck"
