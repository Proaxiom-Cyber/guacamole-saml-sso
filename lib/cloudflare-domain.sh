# shellcheck shell=bash
# Cloudflare domain selection. Requires cf, env_get, note, ok and die from setup.
choose_cloudflare_hostname() {
  local zones='[]' batch page=1 filter='' count choice keep='' prefix candidate
  local selected saved_zone metadata reset_saml=false
  if [ -n "$ACCT" ]; then
    [[ "$ACCT" =~ ^[a-fA-F0-9]{32}$ ]] || die "The Cloudflare account ID must contain 32 hexadecimal characters."
    filter="&account.id=$ACCT"
  fi
  # Fetch every page, including accounts with more than 50 visible zones.
  while :; do
    batch="$(cf GET "/zones?per_page=50&page=$page&order=name&direction=asc$filter")"
    zones="$(printf '%s\n%s\n' "$zones" "$batch" | jq -sc '.[0] + .[1]')"
    [ "$(jq 'length' <<<"$batch")" -eq 50 ] || break
    page=$((page + 1))
  done
  count="$(jq 'length' <<<"$zones")"
  [ "$count" -gt 0 ] || die "No domains are visible in this account. Check the token's Zone Read permission and domain scope."

  if [ -n "$GUAC_HOSTNAME" ]; then
    if [ -t 0 ]; then
      read -rp "  Keep the saved hostname $GUAC_HOSTNAME? [Y/n] " keep
    fi
    if [[ "${keep:-y}" != [nN] ]]; then
      saved_zone="$(env_get CLOUDFLARE_ZONE_ID)"
      selected="$(jq -c --arg h "$GUAC_HOSTNAME" --arg id "$saved_zone" '
        [.[] | .name as $n | select($h == $n or ($h | endswith("." + $n))) |
          select($id == "" or .id == $id)] | sort_by(.name | length) | last' <<<"$zones")"
      [ "$selected" != null ] || die "The saved hostname has no matching domain visible to this token. Run interactively and choose a domain."
      candidate="$GUAC_HOSTNAME"
    fi
  fi

  if [ -z "${candidate:-}" ]; then
    jq -r 'to_entries[] | "  \(.key + 1)) \(.value.name) — \(.value.account.name) (\(.value.status))"' <<<"$zones"
    choice=1
    if [ "$count" -gt 1 ]; then
      while :; do
        read -rp "  Select a domain [1-$count]: " choice || die "Domain selection needs input."
        # Bound input before shell arithmetic; reject signs and leading zeros.
        if [[ "$choice" =~ ^[1-9][0-9]{0,5}$ ]] && [ "$choice" -le "$count" ]; then break; fi
        note "Enter a number from 1 to $count."
      done
    fi
    selected="$(jq -c --argjson i "$((choice - 1))" '.[$i]' <<<"$zones")"
    NAME="$(jq -r .name <<<"$selected")"
    while :; do
      read -rp "  Hostname before .$NAME [guacamole]: " prefix || die "Hostname selection needs input."
      prefix="${prefix:-guacamole}"
      prefix="$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]')"
      if [[ "$prefix" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then break; fi
      note "Use one name of up to 63 letters, digits or hyphens, starting and ending with a letter or digit."
    done
    candidate="$prefix.$NAME"
    [ "${#candidate}" -le 253 ] || die "The complete hostname is too long."
  fi

  metadata="$(env_get SAML_IDP_METADATA_URL)"
  if [ "$candidate" != "$GUAC_HOSTNAME" ] && [ -n "$metadata" ]; then
    case "$metadata" in
      https://login.microsoftonline.com/*/federationmetadata/2007-06/federationmetadata.xml\?appid=*)
        reset_saml=true
        note "Setup will register Entra SAML for $candidate. The previous registration and DNS records will remain."
        ;;
      *) die "This installation uses a supplied SAML metadata URL. Update the identity provider for the new hostname before changing GUAC_HOSTNAME in .env." ;;
    esac
  fi
  ZINFO="$selected"
  ZONE="$(jq -r .id <<<"$ZINFO")"
  NAME="$(jq -r .name <<<"$ZINFO")"
  ACCT="$(jq -r .account.id <<<"$ZINFO")"
  # Values written here are non-secret configuration only.
  sed -i.bak \
    -e "s|^GUAC_HOSTNAME=.*|GUAC_HOSTNAME=$candidate|" \
    -e "s|^CLOUDFLARE_ACCOUNT_ID=.*|CLOUDFLARE_ACCOUNT_ID=$ACCT|" \
    -e "s|^CLOUDFLARE_ZONE_ID=.*|CLOUDFLARE_ZONE_ID=$ZONE|" .env
  rm .env.bak
  if [ "$reset_saml" = true ]; then
    sed -i.bak 's|^SAML_IDP_METADATA_URL=.*|SAML_IDP_METADATA_URL=|' .env
    rm .env.bak
  fi
  if ! grep -q '^CLOUDFLARE_ZONE_ID=' .env; then
    printf 'CLOUDFLARE_ZONE_ID=%s\n' "$ZONE" >> .env
  fi
  GUAC_HOSTNAME="$candidate"
  ok "domain $NAME ($(jq -r .status <<<"$ZINFO")) in account $(jq -r .account.name <<<"$ZINFO")"
}
