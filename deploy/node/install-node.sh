#!/usr/bin/env bash
#
# Install the Athena node agent on this host.
#
#   sudo ./install-node.sh --core http://127.0.0.1:8000 --token <enrolment-token>
#
# Installs the binary, creates an unprivileged service account, enrols, and starts
# the agent under systemd. Re-running with a new token re-enrols.
#
#   --docker-proxy URL   read-only Docker API for container inventory
#                        (default tcp://127.0.0.1:2375, as published by the stack)
#   --no-docker          disable container inventory entirely
#
# Container inventory reaches Docker through a read-only proxy rather than through
# docker group membership, which is equivalent to root on this host. The proxy
# permits only GET on containers and images, so nothing on this path can create or
# start anything. If it is unreachable, inspect_docker is recorded as a failed
# collection rather than as "no containers" — the gap stays visible.
set -euo pipefail

CORE=""; TOKEN=""; DOCKER_PROXY="tcp://127.0.0.1:2375"
BIN_SRC="$(dirname "${BASH_SOURCE[0]}")/athena-node"
UNIT_SRC="$(dirname "${BASH_SOURCE[0]}")/athena-node.service"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --core)   CORE="$2"; shift 2 ;;
        --token)  TOKEN="$2"; shift 2 ;;
        --binary) BIN_SRC="$2"; shift 2 ;;
        --docker-proxy) DOCKER_PROXY="$2"; shift 2 ;;
        --no-docker) DOCKER_PROXY=""; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -n "$CORE" && -n "$TOKEN" ]] || { echo "usage: install-node.sh --core URL --token TOKEN" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root: the agent needs a service account and a unit file" >&2; exit 1; }
[[ -f "$BIN_SRC" ]] || { echo "agent binary not found at $BIN_SRC" >&2; exit 1; }

# Unprivileged, no login shell, no home. The agent reads system state; it has no
# reason to be able to log in or own anything.
if ! id athena-node >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin athena-node
    echo "  created service account athena-node"
fi

install -m 0755 "$BIN_SRC" /usr/local/bin/athena-node
install -m 0644 "$UNIT_SRC" /etc/systemd/system/athena-node.service
install -d -m 0700 -o athena-node -g athena-node /var/lib/athena-node

echo "  enrolling with $CORE"
# Enrol as the service account so the key is created with the right ownership and
# never exists as root-owned state the agent then cannot read.
runuser -u athena-node -- env ATHENA_NODE_STATE=/var/lib/athena-node \
    /usr/local/bin/athena-node enrol --core "$CORE" --token "$TOKEN"

# The unit ships a default DOCKER_HOST; override or clear it per this install.
install -d -m 0755 /etc/systemd/system/athena-node.service.d
if [[ -n "$DOCKER_PROXY" ]]; then
    printf '[Service]\nEnvironment=DOCKER_HOST=%s\n' "$DOCKER_PROXY" \
        > /etc/systemd/system/athena-node.service.d/docker.conf
    echo "  container inventory via $DOCKER_PROXY (read-only; no docker group)"
else
    printf '[Service]\nEnvironment=DOCKER_HOST=\n' \
        > /etc/systemd/system/athena-node.service.d/docker.conf
    echo "  container inventory disabled; the gap will be reported, not hidden"
fi

systemctl daemon-reload
systemctl enable --now athena-node
echo "  athena-node is $(systemctl is-active athena-node)"
