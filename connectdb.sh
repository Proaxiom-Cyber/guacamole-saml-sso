#!/bin/bash
set -e
cd "$(dirname "$0")"
docker compose exec postgres psql -U guacamole_user -d guacamole_db
