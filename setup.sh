#!/bin/bash
# One-time host preparation: folders, database schema, and a test certificate.
# Replace nginx/certs/*.pem with a certificate your clients trust before go-live.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "Copy .env.example to .env and fill it in first." >&2; exit 1; }

# Read only the two values this script needs. Do not source .env: a group name
# with a space in it is valid to Compose but not to the shell.
env_get() { sed -n "s/^$1=//p" .env | tail -n 1; }
GUAC_VERSION="$(env_get GUAC_VERSION)"
GUAC_HOSTNAME="$(env_get GUAC_HOSTNAME)"
[ -n "$GUAC_VERSION" ] && [ -n "$GUAC_HOSTNAME" ] || {
  echo "Set GUAC_VERSION and GUAC_HOSTNAME in .env first." >&2; exit 1; }

mkdir -p nginx/certs nginx/log data

# The schema comes out of the Guacamole image, so it always matches GUAC_VERSION.
# Delete init/001-initdb.sql after a version change to generate it again.
if [ ! -f init/001-initdb.sql ]; then
  docker run --rm "guacamole/guacamole:${GUAC_VERSION}" \
    /opt/guacamole/bin/initdb.sh --postgresql > init/001-initdb.sql
fi

if [ ! -f nginx/certs/privkey.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem \
    -subj "/CN=${GUAC_HOSTNAME}"
fi

echo "Ready. Now: export POSTGRES_PASSWORD=... && docker compose up -d"
