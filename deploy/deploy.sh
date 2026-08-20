#!/usr/bin/env bash
#
# Athena deployment over SSH.
#
# Syncs this repository to a remote host, builds the images there, and brings the
# stack up. Building remotely avoids cross-architecture image transfer and keeps the
# deployment reproducible from source.
#
#   ./deploy/deploy.sh                     deploy to the default host
#   ./deploy/deploy.sh status              what is running, and at which commit
#   ./deploy/deploy.sh logs api            follow one service
#   ./deploy/deploy.sh doctor              run athena doctor remotely
#   ./deploy/deploy.sh bootstrap           mint an admin bootstrap token
#   ./deploy/deploy.sh down                stop the stack (database volume preserved)
#   ./deploy/deploy.sh --host box deploy   target another host
#
# Options: --dry-run  --allow-dirty  --no-build  --yes  --remote-dir PATH
#
# Secrets are generated on the remote on first deploy, never overwritten, never
# transferred, never committed. Back up deploy/secrets/master_key out of band: without
# it, every stored secret is unrecoverable.

set -euo pipefail

HOST="${ATHENA_DEPLOY_HOST:-alena-tailscale}"
REMOTE_DIR="${ATHENA_REMOTE_DIR:-athena}"     # relative to the remote user's home
DRY_RUN=0; ALLOW_DIRTY=0; NO_BUILD=0; ASSUME_YES=0

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -t 1 ]]; then
  B=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; RST=$'\033[0m'
else
  B=""; DIM=""; RED=""; GRN=""; YLW=""; RST=""
fi
step() { printf "\n%s==>%s %s\n" "$B" "$RST" "$*"; }
info() { printf "    %s\n" "$*"; }
warn() { printf "%s !!  %s%s\n" "$YLW" "$*" "$RST"; }
ok()   { printf "%s ✓   %s%s\n" "$GRN" "$*" "$RST"; }
die()  { printf "%s ✗   %s%s\n" "$RED" "$*" "$RST" >&2; exit 1; }

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10)

# Run a command on the remote, inside the deploy directory.
remote() {
  if (( DRY_RUN )); then
    printf "%s[dry-run] %s%s\n" "$DIM" "$*" "$RST"
    return 0
  fi
  "${SSH[@]}" "$HOST" "cd ~/$REMOTE_DIR/deploy && $*"
}

# Pipe a local script to the remote shell.
remote_script() {
  local script="$1"
  if (( DRY_RUN )); then
    printf "%s[dry-run] ssh %s bash -s < %s%s\n" "$DIM" "$HOST" "$script" "$RST"
    return 0
  fi
  "${SSH[@]}" "$HOST" "bash -s" < "$script"
}

# ── arguments ─────────────────────────────────────────────────────────────────
COMMAND=""
declare -a EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host|-H)     HOST="$2"; shift 2 ;;
    --remote-dir)  REMOTE_DIR="$2"; shift 2 ;;
    --dry-run|-n)  DRY_RUN=1; shift ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    --no-build)    NO_BUILD=1; shift ;;
    --yes|-y)      ASSUME_YES=1; shift ;;
    -h|--help)     sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    deploy|status|logs|doctor|bootstrap|down|secrets)
                   COMMAND="$1"; shift; [[ $# -gt 0 ]] && EXTRA=("$@"); break ;;
    *)             die "Unknown argument: $1 (try --help)" ;;
  esac
done
COMMAND="${COMMAND:-deploy}"

# ── preflight ─────────────────────────────────────────────────────────────────
preflight() {
  step "Preflight"
  command -v rsync >/dev/null || die "rsync not found locally"

  "${SSH[@]}" "$HOST" true 2>/dev/null \
    || die "Cannot reach '$HOST' over SSH. Check ~/.ssh/config and that the host is up."
  ok "SSH to $HOST"

  local report; report="$("${SSH[@]}" "$HOST" "bash -s" < "$REPO_ROOT/deploy/scripts/remote-info.sh")"
  case "$report" in
    "MISSING docker")            die "Docker is not installed on $HOST." ;;
    "MISSING compose")           die "Docker Compose v2 is unavailable on $HOST." ;;
    "MISSING docker-permission") die "The remote user cannot reach the Docker daemon. Add it to the docker group." ;;
    OK*) ;;
    *) die "Unexpected preflight response: $report" ;;
  esac

  local version free_gb busy
  version="$(cut -f2 <<<"$report")"
  free_gb="$(cut -f3 <<<"$report")"
  busy="$(cut -f4 <<<"$report")"
  ok "Remote ready — $version, ${free_gb}GB free on /"
  if [[ "$free_gb" =~ ^[0-9]+$ ]] && (( free_gb < 5 )); then
    warn "Only ${free_gb}GB free on the remote; image builds may fail."
  fi
  if [[ -n "$busy" && "$busy" != "none" ]]; then
    die "Port(s) ${busy} are already in use on ${HOST}. Change ATHENA_WEB_PORT or
    ATHENA_API_PORT in ~/${REMOTE_DIR}/deploy/.env, then deploy again."
  fi

  if [[ -d "$REPO_ROOT/.git" ]]; then
    if (( ! ALLOW_DIRTY )) && [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
      die "Working tree is dirty. Commit first, or pass --allow-dirty."
    fi
    ok "Deploying $(git -C "$REPO_ROOT" rev-parse --short HEAD)$( (( ALLOW_DIRTY )) && echo ' (dirty)')"
  fi
}

confirm_first_deploy() {
  (( ASSUME_YES || DRY_RUN )) && return 0
  local exists
  exists="$("${SSH[@]}" "$HOST" "test -d ~/$REMOTE_DIR/deploy/secrets && echo yes || echo no" 2>/dev/null || echo no)"
  [[ "$exists" == "yes" ]] && return 0

  echo
  warn "First deploy to $HOST (~/$REMOTE_DIR)."
  info "This creates the directory, generates secrets there, builds images, and starts containers."
  read -r -p "    Continue? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || die "Aborted."
}

sync_source() {
  step "Syncing source to $HOST:~/$REMOTE_DIR"
  (( DRY_RUN )) || "${SSH[@]}" "$HOST" "mkdir -p ~/$REMOTE_DIR"

  local args=(-az --delete --human-readable
    --exclude '.git/' --exclude '__pycache__/' --exclude '*.pyc' --exclude '.pytest_cache/'
    --exclude 'node_modules/' --exclude '.venv/' --exclude '.nuxt/' --exclude '.output/'
    --exclude 'deploy/secrets/'    # secrets never traverse the network, in either direction
    --exclude 'deploy/.env')
  (( DRY_RUN )) && args+=(--dry-run)

  rsync "${args[@]}" \
    "$REPO_ROOT/core" "$REPO_ROOT/executor" "$REPO_ROOT/web" \
    "$REPO_ROOT/deploy" "$REPO_ROOT/docs" \
    "$HOST:$REMOTE_DIR/"

  local sha; sha="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  (( DRY_RUN )) || "${SSH[@]}" "$HOST" "printf '%s\n' '$sha' > ~/$REMOTE_DIR/DEPLOYED_SHA"
  ok "Source synced"
}

do_deploy() {
  preflight
  confirm_first_deploy
  sync_source

  step "Secrets"
  remote "bash scripts/gen-secrets.sh"

  if (( ! NO_BUILD )); then
    step "Building images on $HOST"
    remote "docker compose build"
    ok "Images built"
  fi

  step "Starting stack"
  remote "docker compose up -d --remove-orphans"

  step "Waiting for the API"
  remote "bash scripts/wait-healthy.sh 120" || die "Deployment did not converge."
  ok "API healthy"

  step "Post-deploy checks"
  remote "docker compose exec -T api athena doctor" || warn "athena doctor reported failures (above)"

  step "Admin account"
  # No-op once an account exists, so re-deploying never mints a second token.
  remote "docker compose exec -T api athena bootstrap"

  local bind port
  bind="$("${SSH[@]}" "$HOST" "grep -E '^ATHENA_WEB_BIND=' ~/$REMOTE_DIR/deploy/.env | cut -d= -f2" 2>/dev/null || echo 127.0.0.1)"
  port="$("${SSH[@]}" "$HOST" "grep -E '^ATHENA_WEB_PORT=' ~/$REMOTE_DIR/deploy/.env | cut -d= -f2" 2>/dev/null || echo 8080)"

  step "Done"
  ok "Deployed to $HOST"
  info "Dashboard: http://${bind:-127.0.0.1}:${port:-8080}"
  if [[ "${bind:-127.0.0.1}" == "127.0.0.1" ]]; then
    info "Bound to loopback. To reach it over the tailnet, set ATHENA_WEB_BIND in"
    info "~/$REMOTE_DIR/deploy/.env to the host's tailnet IP and re-run deploy."
  fi
}

case "$COMMAND" in
  deploy)    do_deploy ;;
  status)    preflight
             remote "docker compose ps"
             (( DRY_RUN )) || "${SSH[@]}" "$HOST" "sed 's/^/    deployed sha: /' ~/$REMOTE_DIR/DEPLOYED_SHA 2>/dev/null || true" ;;
  logs)      remote "docker compose logs -f --tail 100 ${EXTRA[*]-}" ;;
  doctor)    remote "docker compose exec -T api athena doctor" ;;
  bootstrap) remote "docker compose exec -T api athena bootstrap" ;;
  down)      remote "docker compose down"; ok "Stopped. The database volume is preserved." ;;
  secrets)   remote "bash scripts/gen-secrets.sh" ;;
  *)         die "Unknown command: $COMMAND" ;;
esac
