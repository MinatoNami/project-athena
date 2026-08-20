#!/usr/bin/env bash
# Runs ON THE DEPLOYMENT HOST via `ssh host bash -s < this-file`. Reports readiness.
set -uo pipefail

command -v docker >/dev/null 2>&1        || { echo "MISSING docker";            exit 0; }
docker compose version >/dev/null 2>&1   || { echo "MISSING compose";           exit 0; }
docker info >/dev/null 2>&1              || { echo "MISSING docker-permission"; exit 0; }

# Tab-delimited: the version string contains spaces, so whitespace splitting
# would silently mangle the fields.
version="$(docker --version | cut -d, -f1)"
free_gb="$(df -Pk / | awk 'NR==2 {print int($4/1048576)}')"
# Ports the stack wants, so a conflict is reported by preflight rather than
# surfacing as a half-finished deploy.
busy=""
if [[ -f "$HOME/${ATHENA_REMOTE_DIR:-athena}/deploy/.env" ]]; then
    # shellcheck disable=SC1090
    . "$HOME/${ATHENA_REMOTE_DIR:-athena}/deploy/.env" 2>/dev/null || true
    for port in "${ATHENA_WEB_PORT:-8080}" "${ATHENA_API_PORT:-8000}"; do
        if ss -lnt 2>/dev/null | grep -q ":${port} "; then
            busy="${busy}${busy:+,}${port}"
        fi
    done
fi

printf 'OK\t%s\t%s\t%s\n' "$version" "$free_gb" "${busy:-none}"
