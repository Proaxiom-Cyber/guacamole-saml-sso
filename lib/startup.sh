#!/bin/bash
# Sourced by setup.sh. Credentials stay in memory until Compose receives them.

get_database_password() {
  local password_command confirmation
  DB_PASSWORD="${POSTGRES_PASSWORD:-}"
  if [ -z "$DB_PASSWORD" ]; then
    password_command="${POSTGRES_PASSWORD_CMD:-$(env_get POSTGRES_PASSWORD_CMD)}"
    if [ -n "$password_command" ]; then
      # Accept a command and arguments, like CLOUDFLARE_TOKEN_CMD. Do not eval it.
      # shellcheck disable=SC2086
      DB_PASSWORD="$($password_command 2>/dev/null)" \
        || die "The database password command failed. Check your secret store or reconnect with the required secret."
    else
      note "Use the same database password on every run. Keep it in your secret store."
      read -rsp "  Database password (not echoed): " DB_PASSWORD \
        || die "Supply a database password through the prompt, POSTGRES_PASSWORD, or POSTGRES_PASSWORD_CMD."
      printf '\n'
      read -rsp "  Confirm database password (not echoed): " confirmation \
        || die "The database password confirmation is missing."
      printf '\n'
      [ "$DB_PASSWORD" = "$confirmation" ] || die "The database passwords do not match."
    fi
  fi
  [ -n "$DB_PASSWORD" ] || die "The database password is empty."
}

runtime_compose() {
  local profiles
  profiles="$(env_get COMPOSE_PROFILES)"
  [ -n "${DB_PASSWORD:-}" ] || die "The database password is empty."
  if [[ "$profiles" == *cloudflare* ]]; then
    [ -n "${TUNNEL_TOKEN_OUT:-}" ] || die "Cloudflare did not return a tunnel token."
  fi

  # A JSON override goes through a pipe, never a file or command argument.
  # Double dollar signs prevent Compose from interpolating password contents.
  printf '%s\0%s' "$DB_PASSWORD" "${TUNNEL_TOKEN_OUT:-}" \
    | jq -Rs 'split("\u0000") | map(gsub("\\$"; "$$")) |
      {services: {
        postgres: {environment: {POSTGRES_PASSWORD: .[0]}},
        guacamole: {environment: {POSTGRESQL_PASSWORD: .[0]}},
        cloudflared: {environment: {TUNNEL_TOKEN: .[1]}}
      }}' \
    | COMPOSE_PROFILES="$profiles" docker compose --env-file .env \
        -f docker-compose.yaml -f - "$@"
}

wait_for_guacamole() {
  local port status deadline
  port="$(env_get HTTPS_PORT)"; port="${port:-443}"
  deadline=$((SECONDS + 120))
  while [ "$SECONDS" -lt "$deadline" ]; do
    # Probe nginx on this host with the configured hostname. The local
    # certificate can be self-signed when Cloudflare provides public TLS.
    status="$(curl --silent --insecure --noproxy '*' --output /dev/null \
      --write-out '%{http_code}' --connect-timeout 2 --max-time 5 \
      --resolve "$GUAC_HOSTNAME:$port:127.0.0.1" \
      "https://$GUAC_HOSTNAME:$port/guacamole/" || true)"
    case "$status" in
      200|302|303|307|308) return 0 ;;
    esac
    sleep 2
  done
  return 1
}

start_stack() {
  runtime_compose up --detach --wait --wait-timeout 180 \
    || die "The services did not become healthy. Check docker compose ps and docker compose logs."
  wait_for_guacamole \
    || die "Guacamole did not respond through nginx within 120 seconds. Check docker compose logs guacamole nginx."
  runtime_compose ps
  ok "services started; Guacamole responds through nginx"
}
