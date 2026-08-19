#!/usr/bin/env bash
# Runs ON THE DEPLOYMENT HOST. Waits for the API to answer /healthz.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."   # deploy/
timeout_s="${1:-120}"
waited=0

probe='import urllib.request,sys
try:
    sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=3).status == 200 else 1)
except Exception:
    sys.exit(1)'

while true; do
    if docker compose exec -T api python -c "$probe" 2>/dev/null; then
        echo "api healthy after ${waited}s"
        exit 0
    fi
    waited=$(( waited + 3 ))
    if (( waited > timeout_s )); then
        echo "api did not become healthy within ${timeout_s}s" >&2
        docker compose logs --tail 40 api >&2 || true
        exit 1
    fi
    sleep 3
done
