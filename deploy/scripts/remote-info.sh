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
# surfacing as a half-finished deploy. Ports already published by Athena itself are
# not conflicts — a redeploy is expected to reclaim them.
busy=""
deploy_dir="$HOME/${ATHENA_REMOTE_DIR:-athena}/deploy"
if [[ -f "$deploy_dir/.env" ]]; then
    # shellcheck disable=SC1090
    . "$deploy_dir/.env" 2>/dev/null || true

    ours=""
    if command -v docker >/dev/null 2>&1; then
        ours="$(cd "$deploy_dir" && docker compose ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' | grep -oE ':[0-9]+->' | grep -oE '[0-9]+' | sort -u)"
    fi

    for port in "${ATHENA_WEB_PORT:-8080}" "${ATHENA_API_PORT:-8000}"; do
        ss -lnt 2>/dev/null | grep -q ":${port} " || continue
        grep -qx "$port" <<<"$ours" && continue
        busy="${busy}${busy:+,}${port}"
    done
fi

printf 'OK\t%s\t%s\t%s\n' "$version" "$free_gb" "${busy:-none}"
