#!/bin/bash
set -e

# Configure aegis for fair benchmarking — turn off the challenge
# ladder so we measure WAF / honeypot / bot detection without
# the JS gate (nginx doesn't have one, so it'd be unfair).
sed -i 's|challenge_ladder          on|challenge_ladder          off|' /etc/aegis/aegis.conf
systemctl restart aegis
sleep 2

echo "=== status checks ==="
curl -sS -o /dev/null -w 'backend :8000      → %{http_code}\n' http://localhost:8000/
curl -sS -o /dev/null -w 'aegis   :80 (host=localhost) → %{http_code}\n' -H 'host: localhost' http://localhost:80/

# Install nginx as the comparison reverse proxy on :8080 → :8000
apt-get install -y nginx wrk apache2-utils 2>&1 | tail -3
cat > /etc/nginx/sites-available/aegis-compare <<'NGINX'
server {
    listen 8080 default_server;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 30s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/aegis-compare /etc/nginx/sites-enabled/aegis-compare
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
sleep 1
curl -sS -o /dev/null -w 'nginx   :8080      → %{http_code}\n' http://localhost:8080/

echo
echo "=== installed tools ==="
which wrk ab slowhttptest 2>/dev/null || true
echo
echo "Aegis listens on  :80  (default upstream → 127.0.0.1:8000)"
echo "Nginx listens on  :8080 (proxy_pass     → 127.0.0.1:8000)"
echo "Backend listens on :8000 (python http.server, static index.html)"
