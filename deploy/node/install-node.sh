#!/usr/bin/env bash
#
# Install the Athena node agent on this host.
#
#   sudo ./install-node.sh --core http://127.0.0.1:8000 --token <enrolment-token>
#
# Installs the binary, creates an unprivileged service account, enrols, and starts
# the agent under systemd. Re-running with a new token re-enrols.
#
#   --allow-docker   also add the agent to the docker group, so it can inventory
#                    images and containers.
#
# Membership of the docker group is equivalent to root on this host: anyone who can
# reach the socket can start a privileged container. Athena's agent is read-only by
# design, so this widens what a compromise of the agent would be worth. Without it,
# inspect_docker is reported as a failed collection rather than as "no containers" —
# the gap is visible instead of silent. Opt in deliberately.
set -euo pipefail

CORE=""; TOKEN=""; ALLOW_DOCKER=0
BIN_SRC="$(dirname "${BASH_SOURCE[0]}")/athena-node"
UNIT_SRC="$(dirname "${BASH_SOURCE[0]}")/athena-node.service"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --core)   CORE="$2"; shift 2 ;;
        --token)  TOKEN="$2"; shift 2 ;;
        --binary) BIN_SRC="$2"; shift 2 ;;
        --allow-docker) ALLOW_DOCKER=1; shift ;;
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

if (( ALLOW_DOCKER )); then
    if getent group docker >/dev/null; then
        usermod -aG docker athena-node
        echo "  added athena-node to the docker group (root-equivalent on this host)"
    else
        echo "  no docker group on this host; skipping --allow-docker" >&2
    fi
else
    echo "  container inventory disabled (pass --allow-docker to enable; it is"
    echo "  root-equivalent, and the gap is reported rather than hidden)"
fi

systemctl daemon-reload
systemctl enable --now athena-node
echo "  athena-node is $(systemctl is-active athena-node)"
