#!/bin/sh
# ─────────────────────────────────────────────────────────────
# TokenShield — Nginx Entrypoint (Phase 3.1)
#
# 1. Validates nginx config before starting
# 2. Starts Nginx in foreground
# 3. Watches /etc/nginx/blocked_ips.conf for changes
#    When Flask mitigation adds a new banned IP, this watcher
#    signals Nginx to reload — ban takes effect in <1 second
# ─────────────────────────────────────────────────────────────

set -e

BLOCKED_IPS="/etc/nginx/blocked_ips.conf"
RELOAD_INTERVAL=5   # check for blocklist changes every 5 seconds

echo "======================================================"
echo "  TokenShield Nginx WAF"
echo "  Proxy  : localhost:80 → flask-server:5001"
echo "  WAF    : SQLi, XSS, path traversal, bad agents"
echo "  Limits : 30/min login | 100/min API | 200/min general"
echo "======================================================"

# ── 1. Test config ────────────────────────────────────────────
echo "[nginx] Testing configuration ..."
nginx -t
echo "[nginx] Config OK ✅"

# ── 2. Start Nginx ────────────────────────────────────────────
echo "[nginx] Starting Nginx ..."
nginx -g "daemon off;" &
NGINX_PID=$!
echo "[nginx] Nginx started (PID ${NGINX_PID}) ✅"
echo "[nginx] WAF active on port 80"

# ── 3. Watch blocklist for changes and reload ─────────────────
echo "[nginx] Watching ${BLOCKED_IPS} for new blocked IPs ..."
LAST_HASH=""

# Trap signals for clean shutdown
trap 'echo "[nginx] Shutting down ..."; kill $NGINX_PID 2>/dev/null; exit 0' TERM INT

while true; do
    sleep "$RELOAD_INTERVAL"

    # Hash the blocklist file to detect changes
    CURRENT_HASH=$(md5sum "$BLOCKED_IPS" 2>/dev/null | awk '{print $1}')

    if [ "$CURRENT_HASH" != "$LAST_HASH" ] && [ -n "$LAST_HASH" ]; then
        echo "[nginx] Blocklist changed — reloading Nginx ..."

        # Validate before reloading (never reload a broken config)
        if nginx -t 2>/dev/null; then
            nginx -s reload
            BLOCKED_COUNT=$(grep -c "^deny" "$BLOCKED_IPS" 2>/dev/null || echo 0)
            echo "[nginx] Reloaded ✅ — ${BLOCKED_COUNT} IPs now blocked at network edge"
        else
            echo "[nginx] WARNING: Config test failed — skipping reload"
        fi
    fi

    LAST_HASH="$CURRENT_HASH"

    # Exit if Nginx died unexpectedly
    if ! kill -0 "$NGINX_PID" 2>/dev/null; then
        echo "[nginx] ERROR: Nginx process died unexpectedly"
        exit 1
    fi
done