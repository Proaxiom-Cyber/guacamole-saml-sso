#!/bin/sh
# Compatibility entry point for explicit group repair. Setup imports the SQL
# with the schema in one transaction through the deployment binary.
set -eu
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v admin_group="$GUAC_ADMIN_GROUP" -v operator_group="$GUAC_OPERATOR_GROUP" \
  -f "$(dirname "$0")/002-groups.sql"
