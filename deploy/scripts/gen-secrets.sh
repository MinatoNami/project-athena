#!/usr/bin/env bash
# Runs ON THE DEPLOYMENT HOST. Generates any missing secret; never overwrites one.
#
# The no-overwrite guarantee is structural (`set -o noclobber`) rather than a check,
# because overwriting master_key silently makes every stored secret unrecoverable.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."   # deploy/
mkdir -p secrets
chmod 700 secrets

# Secrets are mounted into containers by Docker Compose, which — outside swarm —
# bind-mounts the host file with its host ownership and ignores uid/gid/mode. The
# containers run as an unprivileged user that is not the file owner, so the files are
# group-readable and the containers join the owning group (see ATHENA_SECRET_GID).
# Deliberately not world-readable, and deliberately not chowned, which would need root.
SECRET_MODE=640

gen() {
    local name="$1"; shift
    if [[ -s "secrets/$name" ]]; then
        echo "  keep    $name"
        return 0
    fi
    ( set -o noclobber; "$@" > "secrets/$name" )
    echo "  create  $name"
}

gen db_password          openssl rand -base64 32
gen executor_db_password openssl rand -base64 32
gen session_secret       openssl rand -base64 48
gen master_key           openssl rand -base64 32

# Ed25519 approval-grant keypair. The API signs grants with the private half; the
# executor only ever receives the public half, so it can verify a grant but never
# mint one. That asymmetry is the executor privilege boundary.
if [[ -s secrets/grant_private_key ]]; then
    echo "  keep    grant keypair"
else
    ( set -o noclobber; openssl genpkey -algorithm ed25519 -out secrets/grant_private_key )
    openssl pkey -in secrets/grant_private_key -pubout -outform DER | tail -c 32 > secrets/grant_public_key
    echo "  create  grant keypair"
fi

# Signs task envelopes sent to nodes. Separate from the grant key: a node task and
# an executor grant authorise different things, and one compromise must not confer
# the other.
if [[ -s secrets/node_signing_key ]]; then
    echo "  keep    node signing key"
else
    ( set -o noclobber; openssl genpkey -algorithm ed25519 -out secrets/node_signing_key )
    echo "  create  node signing key"
fi

# Applied once, to everything, rather than per branch: the first version set the mode
# at each creation site and missed the "already exists" paths, so a redeployed host
# kept 0600 files that its containers could not read.
chmod "$SECRET_MODE" secrets/* 2>/dev/null || true

if [[ ! -f .env ]]; then
    cp .env.example .env
    # The Docker socket's group differs between Docker Desktop (0) and a Linux host
    # (the `docker` group). Detect it rather than making the operator look it up.
    if [[ -S /var/run/docker.sock ]]; then
        gid="$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)"
        sed -i "s/^DOCKER_SOCKET_GID=.*/DOCKER_SOCKET_GID=${gid}/" .env
    fi
    sed -i "s/^ATHENA_SECRET_GID=.*/ATHENA_SECRET_GID=$(id -g)/" .env
    echo "  create  .env (secret gid $(id -g), docker socket gid ${gid:-0})"
else
    # An existing .env predating this setting would leave containers unable to read
    # the secrets, which fails as an opaque permission error at startup.
    if ! grep -q "^ATHENA_SECRET_GID=" .env; then
        echo "ATHENA_SECRET_GID=$(id -g)" >> .env
        echo "  update  .env (added secret gid $(id -g))"
    else
        echo "  keep    .env"
    fi
fi
