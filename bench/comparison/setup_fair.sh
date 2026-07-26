#!/bin/bash
set -e
# Replace python http.server with nginx serving the same file —
# python is single-threaded and bottlenecks at ~4k RPS, distorting
# the throughput comparison. nginx-as-backend handles 100k+ RPS
# with no problem.
pkill -f 'http.server 8000' 2>/dev/null || true
sleep 1
cat > /etc/nginx/sites-available/backend <<'NGINX'
server {
    listen 8000 default_server;
    server_name _;
    root /var/www/test;
    location / {
        access_log off;
        return 200 "backend ok\n";
    }
}
NGINX
ln -sf /etc/nginx/sites-available/backend /etc/nginx/sites-enabled/backend
nginx -t
systemctl reload nginx
sleep 1
echo "backend :8000  → $(curl -sS -o /dev/null -w '%{http_code}' http://localhost:8000/)"
echo "aegis   :80   → $(curl -sS -o /dev/null -w '%{http_code}' -H 'Host:localhost' http://localhost:80/)"
echo "nginx   :8080 → $(curl -sS -o /dev/null -w '%{http_code}' http://localhost:8080/)"

# Loosen aegis rate-limit + adaptive for raw-throughput baseline
# (we'll re-test with defenses enabled separately).
sed -i 's|requests_per_second 100;|requests_per_second 1000000;|' /etc/aegis/aegis.conf
sed -i 's|adaptive_spike_detection  on|adaptive_spike_detection  off|' /etc/aegis/aegis.conf
sed -i 's|bot_fingerprint           on|bot_fingerprint           off|' /etc/aegis/aegis.conf
systemctl restart aegis
sleep 2
echo "aegis raw-mode :80 → $(curl -sS -o /dev/null -w '%{http_code}' -H 'Host:localhost' http://localhost:80/)"
apt-get install -y netcat-openbsd 2>&1 | tail -2
