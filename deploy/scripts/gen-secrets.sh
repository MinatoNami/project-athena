#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p secrets
chmod 700 secrets

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

if [[ -s secrets/grant_private_key ]]; then
    echo "  keep    grant keypair"
else
    ( set -o noclobber; openssl genpkey -algorithm ed25519 -out secrets/grant_private_key )
    openssl pkey -in secrets/grant_private_key -pubout -outform DER | tail -c 32 > secrets/grant_public_key
    echo "  create  grant keypair"
fi

if [[ -s secrets/node_signing_key ]]; then
    echo "  keep    node signing key"
else
    ( set -o noclobber; openssl genpkey -algorithm ed25519 -out secrets/node_signing_key )
    echo "  create  node signing key"
fi

chmod "$SECRET_MODE" secrets/* 2>/dev/null || true

if [[ ! -f .env ]]; then
    cp .env.example .env
    secret_gid="$(id -g)"
    gid=""
    if [[ -S /var/run/docker.sock ]]; then
        gid="$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 0)"
    fi
    if [[ -z "$gid" || "$gid" == "$secret_gid" ]]; then
        gid=65534
    fi
    sed -i "s/^DOCKER_SOCKET_GID=.*/DOCKER_SOCKET_GID=${gid}/" .env
    sed -i "s/^ATHENA_SECRET_GID=.*/ATHENA_SECRET_GID=${secret_gid}/" .env
    echo "  create  .env (secret gid ${secret_gid}, docker socket gid ${gid})"
else
    if ! grep -q "^ATHENA_SECRET_GID=" .env; then
        echo "ATHENA_SECRET_GID=$(id -g)" >> .env
        echo "  update  .env (added secret gid $(id -g))"
    else
        echo "  keep    .env"
    fi
fi
