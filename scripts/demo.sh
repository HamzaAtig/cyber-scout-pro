#!/usr/bin/env bash
set -euo pipefail

# One-command POC demo:
# - starts postgres (for persistence) + demo-target (WireMock)
# - starts Cyber-Scout Pro locally
# - launches a scan against the demo target
# - prints the HTML report URL

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export CS_ALLOWED_HOSTS="${CS_ALLOWED_HOSTS:-localhost,127.0.0.1}"
export CS_ALLOWED_PORTS="${CS_ALLOWED_PORTS:-80,443,8080,8443,18080}"
export CS_DRY_RUN_ONLY="${CS_DRY_RUN_ONLY:-false}"

APP_PROFILES="${CS_DEMO_PROFILES:-local-postgres}"
TARGET_URL="${CS_DEMO_TARGET_URL:-http://localhost:18080}"
CAMPAIGN_ID="${CS_DEMO_CAMPAIGN_ID:-1}"

echo "[demo] starting docker services (postgres + demo-target)..."
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d

echo "[demo] starting app with profiles: ${APP_PROFILES}"
set +e
mvn -q spring-boot:run -Dspring-boot.run.profiles="${APP_PROFILES}" &
APP_PID="$!"
set -e

cleanup() {
  if kill -0 "${APP_PID}" >/dev/null 2>&1; then
    echo "[demo] stopping app (pid=${APP_PID})..."
    kill "${APP_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[demo] waiting for Camunda webapp..."
for _ in {1..120}; do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/camunda/app/welcome/default/ || true)"
  if [[ "${code}" == "200" ]]; then
    break
  fi
  sleep 1
done

code="$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/camunda/app/welcome/default/ || true)"
if [[ "${code}" != "200" ]]; then
  echo "[demo] app did not become ready in time (camunda welcome status=${code})"
  exit 1
fi

echo "[demo] launching scan against ${TARGET_URL} (campaignId=${CAMPAIGN_ID})..."
start_json="$(
  curl -sS -X POST "http://localhost:8080/api/processes/cyber-scout/start" \
    -H "Content-Type: application/json" \
    -d "{\"campaignId\":${CAMPAIGN_ID},\"baseUrl\":\"${TARGET_URL}\"}"
)"

scan_run_id="$(python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
print(data.get("scanRunId") or "")
PY
<<<"${start_json}")"

instance_id="$(python3 - <<'PY'
import json,sys
data=json.loads(sys.stdin.read())
print(data.get("instanceId") or "")
PY
<<<"${start_json}")"

echo "[demo] started instanceId=${instance_id} scanRunId=${scan_run_id}"

if [[ -z "${scan_run_id}" ]]; then
  echo "[demo] scanRunId is empty (persistence disabled?). Use profile local-postgres for reporting."
  exit 1
fi

echo "[demo] waiting for scan to finish..."
for _ in {1..180}; do
  # Report endpoint returns 200 only when run exists; content includes status
  report_json="$(curl -sS "http://localhost:8080/api/reports/scan-runs/${scan_run_id}" || true)"
  status="$(python3 - <<'PY'
import json,sys
try:
  data=json.loads(sys.stdin.read())
  print(data.get("run",{}).get("status",""))
except Exception:
  print("")
PY
<<<"${report_json}")"
  if [[ "${status}" == "FINISHED" ]]; then
    break
  fi
  sleep 1
done

echo "[demo] report:"
echo "  JSON : http://localhost:8080/api/reports/scan-runs/${scan_run_id}"
echo "  HTML : http://localhost:8080/api/reports/scan-runs/${scan_run_id}.html"
echo "  Cockpit: http://localhost:8080/camunda/app/cockpit/default/"
echo "  Demo target: ${TARGET_URL} (OpenAPI: ${TARGET_URL}/v3/api-docs)"

echo "[demo] done (press Ctrl+C to stop)."
wait "${APP_PID}"

