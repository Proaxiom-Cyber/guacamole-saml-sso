#!/bin/bash
# Sourced by setup.sh. The generated SQL contains no deployment credentials.

prepare_database_schema() (
  local schema_file=init/001-initdb.sql schema_tmp
  local marker="-- Guacamole schema complete: $GUAC_VERSION"
  mkdir -p init

  # Older setup runs wrote directly to the final file. A failed Docker command
  # could leave an empty or partial file that later runs accepted as complete.
  if [ -s "$schema_file" ] && tail -n 1 "$schema_file" | grep -Fqx -- "$marker"; then
    ok "database schema (complete for Guacamole $GUAC_VERSION)"
    return
  fi

  note "Generating the Guacamole database schema."
  schema_tmp="$(mktemp init/.schema.XXXXXX)" || die "Could not create a temporary schema file."
  trap 'rm -f "$schema_tmp"' EXIT
  docker run --rm "guacamole/guacamole:${GUAC_VERSION}" \
    /opt/guacamole/bin/initdb.sh --postgresql > "$schema_tmp" \
    || die "Database schema generation failed. Resolve the Docker error and run setup again."

  # Reject empty output and output for the wrong database before publishing it.
  if ! grep -Eq '^CREATE TABLE guacamole_entity[[:space:](]' "$schema_tmp" \
      || ! grep -Eq '^CREATE TABLE guacamole_user_group[[:space:](]' "$schema_tmp"; then
    die "The generated SQL does not contain the required Guacamole tables."
  fi
  printf '\n%s\n' "$marker" >> "$schema_tmp"
  # PostgreSQL reads this public schema as its own container user.
  chmod 644 "$schema_tmp"
  mv -f "$schema_tmp" "$schema_file"
  ok "database schema generated from guacamole/guacamole:${GUAC_VERSION}"
)
