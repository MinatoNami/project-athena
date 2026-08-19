#!/usr/bin/env bash
# Runs ON THE DEPLOYMENT HOST via `ssh host bash -s < this-file`. Reports readiness.
set -uo pipefail

command -v docker >/dev/null 2>&1        || { echo "MISSING docker";            exit 0; }
docker compose version >/dev/null 2>&1   || { echo "MISSING compose";           exit 0; }
docker info >/dev/null 2>&1              || { echo "MISSING docker-permission"; exit 0; }

version="$(docker --version | cut -d, -f1)"
free_gb="$(df -Pk / | awk 'NR==2 {print int($4/1048576)}')"
echo "OK ${version} ${free_gb}"
