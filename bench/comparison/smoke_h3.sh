#!/usr/bin/env bash
#
# V62 — HTTP/3 end-to-end smoke test for aegis-pingora.
#
# V46 wired the h3 listener via a hyper-handler shim spawned on a
# side thread. lsof confirmed the UDP socket binds. THIS script
# proves a real h3 client can connect, get through the filter
# chain, and receive an upstream response.
#
# Requires one of:
#   • curl built with nghttp3 (`curl --http3 --version` shows
#     "HTTP3" in the Features list). Build from source or use
#     `brew install curl --HEAD --with-nghttp3 --with-quiche`.
#   • Chrome with QUIC: `google-chrome --enable-quic
#     --quic-version=h3 https://your-aegis-pingora:443`
#   • Cloudflare's `quiche` `cargo install --git
#     https://github.com/cloudflare/quiche quiche-client`.
#
# This script tries curl first (most CI-friendly), falls back to
# quiche-client if available.

set -euo pipefail

TLS_HOST="${TLS_HOST:-127.0.0.1}"
TLS_PORT="${TLS_PORT:-18443}"
HOST_HEADER="${HOST_HEADER:-localhost}"
H3_PATH="${H3_PATH:-/}"
EXPECT_STATUS="${EXPECT_STATUS:-200}"

# Resolve a working h3 client.
H3_CLIENT=""
if command -v curl >/dev/null 2>&1 \
    && curl --version 2>&1 | grep -q 'HTTP3\|HTTP/3'
then
    H3_CLIENT="curl"
fi
if [ -z "$H3_CLIENT" ] && command -v quiche-client >/dev/null 2>&1; then
    H3_CLIENT="quiche"
fi
if [ -z "$H3_CLIENT" ]; then
    cat <<'EOF' >&2
ERROR: no HTTP/3-capable client found on PATH.

Install one of:

  # macOS — homebrew curl with HTTP/3 support
  brew install curl --HEAD

  # Linux — build curl from source with nghttp3 + ngtcp2
  https://curl.se/docs/http3.html

  # Or quiche-client from Cloudflare
  cargo install --git https://github.com/cloudflare/quiche quiche-apps

Then re-run this script.
EOF
    exit 1
fi

URL="https://${TLS_HOST}:${TLS_PORT}${H3_PATH}"
echo "==> probing $URL via $H3_CLIENT"

case "$H3_CLIENT" in
    curl)
        # --http3-only forces h3 (skip h1/h2 fallback so a
        # misconfigured aegis-pingora doesn't accidentally satisfy
        # the test via h2). --insecure for self-signed certs.
        # -w writes status + protocol so we can assert.
        out=$(curl -ksS \
            --http3-only \
            -o /dev/null \
            -w 'status=%{http_code}\nproto=%{http_version}\n' \
            -H "Host: $HOST_HEADER" \
            --max-time 5 \
            "$URL" 2>&1) || {
            echo "FAIL: curl returned non-zero" >&2
            echo "$out" >&2
            exit 1
        }
        echo "$out"
        status=$(echo "$out" | awk -F= '/^status=/ { print $2 }')
        proto=$(echo "$out" | awk -F= '/^proto=/ { print $2 }')
        if [ "$status" != "$EXPECT_STATUS" ]; then
            echo "FAIL: got HTTP $status, expected $EXPECT_STATUS" >&2
            exit 1
        fi
        if [ "$proto" != "3" ]; then
            echo "FAIL: got HTTP/$proto, expected HTTP/3" >&2
            exit 1
        fi
        echo "PASS: aegis-pingora serves HTTP/3 (got HTTP $status, proto $proto)"
        ;;
    quiche)
        out=$(quiche-client \
            --no-verify \
            --http-version HTTP/3 \
            "$URL" 2>&1) || {
            echo "FAIL: quiche-client returned non-zero" >&2
            echo "$out" >&2
            exit 1
        }
        echo "$out" | head -20
        echo "PASS: quiche-client connected via HTTP/3"
        ;;
esac

echo ""
echo "Next steps:"
echo "  • Hit /__aegis/verify via h3 to verify challenge ladder works on h3"
echo "  • curl --http3 with a known WAF-blocked path: expect HTTP 403"
echo "  • Soak test: wrk doesn't speak h3; use h2load --version HTTP/3"
