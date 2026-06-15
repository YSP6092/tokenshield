#!/bin/sh
# ─────────────────────────────────────────────────────────────
# TokenShield — JMeter Container Entrypoint
#
# 1. Waits for Nginx to be healthy (up to 120s)
# 2. Runs the JMeter test plan in non-GUI mode
# 3. Generates an HTML report in /jmeter/report/
# 4. Serves the report on port 8080 via Python HTTP server
#    so you can view http://localhost:8080 in your browser
# ─────────────────────────────────────────────────────────────

set -e

TARGET_HOST="${JMETER_HOST:-nginx-proxy}"
TARGET_PORT="${JMETER_PORT:-80}"
USERS="${JMETER_USERS:-20}"
RAMP="${JMETER_RAMP:-30}"
JMX_FILE="/jmeter/neovault_load_test.jmx"
RESULTS_DIR="/jmeter/results"
REPORT_DIR="/jmeter/report"
REPORT_PORT=8080

echo "======================================================"
echo "  TokenShield JMeter Load Generator"
echo "  Target : http://${TARGET_HOST}:${TARGET_PORT}"
echo "  Users  : ${USERS} virtual users"
echo "  Ramp   : ${RAMP}s"
echo "======================================================"

# ── 1. Wait for the target to be ready ────────────────────────
echo "[entrypoint] Waiting for ${TARGET_HOST}:${TARGET_PORT} ..."
MAX_WAIT=120
WAITED=0
until wget -q --spider "http://${TARGET_HOST}:${TARGET_PORT}/health" 2>/dev/null; do
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "[entrypoint] ERROR: Target not ready after ${MAX_WAIT}s — aborting."
        exit 1
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    echo "[entrypoint] Still waiting ... ${WAITED}s"
done
echo "[entrypoint] Target is up ✅  (waited ${WAITED}s)"

# Extra settle time so Flask users can create accounts first
echo "[entrypoint] Waiting 20s for user traffic to establish baseline ..."
sleep 20

# ── 2. Clean up any previous results ──────────────────────────
mkdir -p "$RESULTS_DIR" "$REPORT_DIR"
rm -f "${RESULTS_DIR}/results.jtl"
# JMeter refuses to overwrite a non-empty report dir
rm -rf "${REPORT_DIR:?}"/*

# ── 3. Run JMeter in non-GUI mode ─────────────────────────────
echo "[entrypoint] Starting JMeter test plan ..."
jmeter \
    -n \
    -t  "$JMX_FILE" \
    -l  "${RESULTS_DIR}/results.jtl" \
    -e  \
    -o  "$REPORT_DIR" \
    -JHOST="$TARGET_HOST" \
    -JPORT="$TARGET_PORT" \
    -JUSERS="$USERS" \
    -JRAMP_SECS="$RAMP" \
    -Djmeter.reportgenerator.overall_granularity=60000 \
    2>&1 | tee /jmeter/jmeter.log &

JMETER_PID=$!
echo "[entrypoint] JMeter started (PID ${JMETER_PID})"

# ── 4. Serve the HTML report ───────────────────────────────────
# Give JMeter a few seconds to create the report directory
sleep 8
echo "[entrypoint] Starting HTTP server on :${REPORT_PORT} → ${REPORT_DIR}"
cd "$REPORT_DIR"
python3 -m http.server "$REPORT_PORT" &
HTTP_PID=$!
echo "[entrypoint] Report dashboard: http://localhost:${REPORT_PORT} ✅"

# ── 5. Keep container alive — forward signals cleanly ─────────
trap 'kill $JMETER_PID $HTTP_PID 2>/dev/null; exit 0' TERM INT

wait $JMETER_PID
echo "[entrypoint] JMeter process finished."

# Keep the HTTP server running so the report stays accessible
wait $HTTP_PID