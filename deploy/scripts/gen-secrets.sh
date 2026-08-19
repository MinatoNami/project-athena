#!/usr/bin/env bash
# Runs ON THE DEPLOYMENT HOST. Generates any missing secret; never overwrites one.
#
# The no-overwrite guarantee is structural (`set -o noclobber`) rather than a check,
# because overwriting master_key silently makes every stored secret unrecoverable.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."   # deploy/
mkdir -p secrets
chmod 700 secrets

gen() {
    local name="$1"; shift
    if [[ -s "secrets/$name" ]]; then
        echo "  keep    $name"
        return 0
    fi
    ( set -o noclobber; "$@" > "secrets/$name" )
    chmod 600 "secrets/$name"
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
    chmod 600 secrets/grant_private_key
    openssl pkey -in secrets/grant_private_key -pubout -outform DER | tail -c 32 > secrets/grant_public_key
    chmod 600 secrets/grant_public_key
    echo "  create  grant keypair"
fi

if [[ ! -f .env ]]; then
    cp .env.example .env
    # The Docker socket's group differs between Docker Desktop (0) and a Linux host
    # (the `docker` group). Detect it rather than making the operator look it up.
    if [[ -S /var/run/docker.sock ]]; then
        gid="$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)"
        sed -i "s/^DOCKER_SOCKET_GID=.*/DOCKER_SOCKET_GID=${gid}/" .env
        echo "  create  .env (docker socket gid ${gid})"
    else
        echo "  create  .env (from .env.example)"
    fi
else
    echo "  keep    .env"
fi
