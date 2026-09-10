#!/bin/bash
# Prepare and start Guacamole with Entra ID and optional Cloudflare Access.
# Disable tracing before any credentials enter the script.
set +x
set +a
set -euo pipefail
cd "$(dirname "$0")"

# ---- Look ---------------------------------------------------------------------
# Brand colours from the Proaxiom logo. Only on a terminal, never with NO_COLOR.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  N=$'\e[38;2;13;64;84m' S=$'\e[38;2;76;143;155m' T=$'\e[38;2;36;161;186m'
  M=$'\e[38;2;116;201;185m' R=$'\e[38;2;241;104;102m'
  B=$'\e[1m' D=$'\e[2m' X=$'\e[0m'
else
  N='' S='' T='' M='' R='' B='' D='' X=''
fi
step() { printf '\n%s▸ %s%s\n' "$T$B" "$1" "$X"; }
ok()   { printf '  %s✔%s %s\n' "$M" "$X" "$1"; }
note() { printf '  %s·%s %s\n' "$D" "$X" "$1"; }
warn() { printf '  %s!%s %s\n' "$R" "$X" "$1" >&2; }
die()  { printf '  %s✘ %s%s\n' "$R" "$1" "$X" >&2; exit 1; }
rule() { printf '%s%s%s\n' "$D" "────────────────────────────────────────────────────────────────" "$X"; }

# The mark is the Proaxiom logo: five bars and a dot, in its own colours.
cat <<BANNER

      ${N}██████████████${X}      ${B}______                     _${X}
           ${S}▄▄▄▄▄▄▄▄▄▄▄${X}    ${B}| ___ \\                   (_)${X}
           ${S}▀▀▀▀▀▀▀▀▀▀▀${X}    ${B}| |_/ / __ ___   __ ___  ___  ___  _ __ ___${X}
   ${T}███████████████${X}        ${B}|  __/ '__/ _ \\ / _\` \\ \\/ / |/ _ \\| '_ \` _ \\${X}
  ${M}▄▄▄▄▄▄▄▄${X}                ${B}| |  | | | (_) | (_| |>  <| | (_) | | | | | |${X}
  ${M}▀▀▀▀▀▀▀▀${X}                ${B}\\_|  |_|  \\___/ \\__,_/_/\\_\\_|\\___/|_| |_| |_|${X}
${R}████████${X} ${R}███${X}              ${D}Apache Guacamole · SAML SSO · no local accounts${X}
                          ${D}Cloudflare Tunnel + Access · Entra ID${X}
BANNER
rule

# Read only the values this script needs. Do not source .env: a group name
# with a space in it is valid to Compose but not to the shell.
env_get() { sed -n "s/^$1=//p" .env | tail -n 1; }
# shellcheck source=lib/startup.sh
source lib/startup.sh
# shellcheck source=lib/schema.sh
source lib/schema.sh

# First run: write .env from .env.example. Only two answers have no default.
if [ ! -f .env ]; then
  step "Configuration"
  [ -f .env.example ] || die ".env.example is missing. Run this from the repository folder."
  read -rp "  Public hostname of this Guacamole (e.g. guacamole.example.com): " H
  [ -n "$H" ] || die "A hostname is needed."
  read -rp "  Publish through Cloudflare Tunnel + Access? [Y/n] " CF
  ACCT_IN=""
  [ "${CF:-y}" = n ] || read -rp "  Cloudflare account ID (dashboard > the account > Overview, right-hand column): " ACCT_IN
  sed -e "s/^GUAC_HOSTNAME=.*/GUAC_HOSTNAME=$H/" \
      -e "s/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=$([ "${CF:-y}" = n ] || echo cloudflare)/" \
      -e "s/^CLOUDFLARE_ACCOUNT_ID=.*/CLOUDFLARE_ACCOUNT_ID=$ACCT_IN/" .env.example > .env
  ok ".env written. Group names and the rest keep their defaults; edit .env to change them."
fi
GUAC_VERSION="$(env_get GUAC_VERSION)"
GUAC_HOSTNAME="$(env_get GUAC_HOSTNAME)"
[ -n "$GUAC_VERSION" ] && [ -n "$GUAC_HOSTNAME" ] || die "Set GUAC_VERSION and GUAC_HOSTNAME in .env first."
note "Hostname  $B$GUAC_HOSTNAME$X"
note "Guacamole $B$GUAC_VERSION$X"

# ---- Tools --------------------------------------------------------------------
# Offer to install whatever is missing with the package manager found.
step "Tools"
[ "$(id -u)" = 0 ] && SUDO= || SUDO=sudo
install_docker() {
  local distro=""
  if [ -r /etc/os-release ]; then
    # Read the distribution ID without changing the setup script's variables.
    # shellcheck source=/dev/null
    distro="$(. /etc/os-release; printf '%s' "${ID:-}")"
  fi
  if [ "$distro" = rocky ]; then
    # Rocky's installation guide uses Docker's RHEL repository. The Rocky 10
    # repository selected by get.docker.com is missing the engine packages.
    note "Installing Docker from the RHEL repository recommended by Rocky Linux."
    $SUDO dnf -y install dnf-plugins-core || die "Could not install the DNF repository tools."
    # This replaces docker-ce.repo from a previous failed installation.
    $SUDO dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo \
      || die "Could not configure the Docker repository."
    $SUDO dnf -y --refresh install docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin || die "Could not install Docker."
    $SUDO systemctl enable --now docker || die "Docker is installed, but its service did not start."
  else
    curl -fsSL https://get.docker.com | $SUDO sh || die "Could not install Docker."
  fi
  ok "docker installed"
}
need() {
  command -v "$1" >/dev/null && { ok "$1"; return; }
  read -rp "  $1 is not installed. Install it now? [y/N] " a
  [ "$a" = y ] || die "Install $1 and run again."
  if [ "$1" = docker ]; then
    install_docker
    return
  fi
  for pm in apt-get dnf yum zypper apk pacman; do
    command -v "$pm" >/dev/null || continue
    case $pm in
      apt-get) $SUDO apt-get install -y "$1" ;;
      dnf|yum) $SUDO "$pm" install -y "$1" ;;
      zypper)  $SUDO zypper -n install "$1" ;;
      apk)     $SUDO apk add "$1" ;;
      pacman)  $SUDO pacman -S --noconfirm "$1" ;;
    esac
    ok "$1 installed"; return
  done
  die "No known package manager. Install $1 and run again."
}
for t in curl jq openssl docker; do need "$t"; done
case "$(docker --version 2>/dev/null)" in
  *[Pp]odman*) warn "The docker command runs Podman. This setup has not been verified with Podman." ;;
esac
docker compose version >/dev/null 2>&1 && ok "docker compose" || die "The Docker Compose plugin is missing."
# A version check does not contact the engine. Use Compose here because Podman's
# local CLI can work even when its API socket is unavailable to Compose.
docker compose ls >/dev/null \
  || die "Compose cannot reach the container engine. Check the connection error above before running setup again."
ok "Compose can reach the container engine"

step "Database password"
get_database_password
ok "database password supplied"

# ---- Host ---------------------------------------------------------------------
step "Host"
mkdir -p nginx/certs nginx/log data
ok "folders"

# Save the schema only after generation succeeds. Existing databases are not
# reinitialised or upgraded by generating this file.
prepare_database_schema

if [ -f nginx/certs/privkey.pem ]; then
  ok "certificate (nginx/certs/privkey.pem exists)"
else
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem \
    -subj "/CN=${GUAC_HOSTNAME}" 2>/dev/null
  ok "self-signed certificate for ${GUAC_HOSTNAME}"
fi

# ---- Entra ID -----------------------------------------------------------------
# Registers the SAML application and fills in SAML_IDP_METADATA_URL. Runs only
# while that value is empty, so Okta and Keycloak users skip it by setting the
# URL themselves. Safe to run again: every step finds before it creates.
if [ -z "$(env_get SAML_IDP_METADATA_URL)" ]; then
  step "Entra ID"
  ADMIN_GROUP="$(env_get GUAC_ADMIN_GROUP)"
  OPERATOR_GROUP="$(env_get GUAC_OPERATOR_GROUP)"
  NAMEID_ATTR="$(env_get ENTRA_NAMEID_ATTRIBUTE)"; NAMEID_ATTR="${NAMEID_ATTR:-mailnickname}"
  ENTITY_ID="https://${GUAC_HOSTNAME}/guacamole"

  # Device code sign-in as the "Microsoft Graph Command Line Tools" public
  # client, the same one Connect-MgGraph uses. An administrator must sign in.
  # Unattended use: set GRAPH_TOKEN_CMD to a command that prints an access
  # token for a service principal with the same permissions.
  CLIENT_ID=14d82eec-204b-4c2f-b7e8-296a70dab67e
  SCOPES="Application.ReadWrite.All Policy.ReadWrite.ApplicationConfiguration \
AppRoleAssignment.ReadWrite.All Group.ReadWrite.All Organization.Read.All \
DelegatedPermissionGrant.ReadWrite.All"
  TOKEN="$(${GRAPH_TOKEN_CMD:-true})"
  if [ -n "$TOKEN" ]; then
    ok "access token from GRAPH_TOKEN_CMD"
  else
    DC="$(curl -fsS -d "client_id=$CLIENT_ID" -d "scope=$SCOPES" \
      https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode)"
    printf '\n  Sign in as an administrator of the tenant:\n'
    printf '    open  %s%s%s\n' "$B" "$(jq -r .verification_uri <<<"$DC")" "$X"
    printf '    code  %s%s%s\n\n' "$R$B" "$(jq -r .user_code <<<"$DC")" "$X"
    note "waiting for the sign-in to complete…"
    INTERVAL="$(jq -r .interval <<<"$DC")"
  fi
  while [ -z "$TOKEN" ]; do
    sleep "$INTERVAL"
    R_="$(curl -sS -d "client_id=$CLIENT_ID" -d "device_code=$(jq -r .device_code <<<"$DC")" \
      -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
      https://login.microsoftonline.com/organizations/oauth2/v2.0/token)"
    TOKEN="$(jq -r '.access_token // empty' <<<"$R_")"
    [ -z "$TOKEN" ] || { ok "signed in"; break; }
    case "$(jq -r .error <<<"$R_")" in
      authorization_pending) ;;
      slow_down) INTERVAL=$((INTERVAL + 5)) ;;
      *) die "$(jq -r .error_description <<<"$R_")" ;;
    esac
  done

  # graph METHOD PATH [JSON]. The token goes in through a curl config on stdin
  # and the body through fd 3, so neither appears on a command line (the body
  # can carry a client secret). Entra is eventually consistent: for a minute
  # after a create, calls that touch the new object fail with one of several
  # errors. So every error is retried for a minute, and "already exists" is
  # success, because every POST here is create-if-missing.
  graph() {
    local out
    for _ in 1 2 3 4 5 6; do
      out="$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -sS -K - \
        -X "$1" -H 'Content-Type: application/json' ${3:+-d @/dev/fd/3} \
        "https://graph.microsoft.com/v1.0$2" 3<<<"${3:-}")" \
        || die "Graph $1 $2: curl failed."
      jq -e '.error.message | test("already exist")' <<<"$out" >/dev/null 2>&1 && return 0
      jq -e .error <<<"$out" >/dev/null 2>&1 || break
      sleep 10
    done
    if jq -e .error <<<"$out" >/dev/null 2>&1; then
      die "Graph $1 $2 failed: $(jq -r .error.message <<<"$out")"
    fi
    echo "$out"
  }
  urlenc() { jq -rn --arg s "$1" '$s|@uri'; }

  TENANT="$(graph GET /organization | jq -r '.value[0].id')"
  note "tenant $TENANT"

  # Application and service principal, from the "non-gallery" template. That is
  # what the portal's "Create your own application" does.
  APP="$(graph GET "/applications?\$filter=$(urlenc "displayName eq 'Guacamole'")" | jq -c '.value[0]')"
  if [ "$APP" = null ]; then
    APP="$(graph POST /applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate \
      '{"displayName":"Guacamole"}')"
    APP_OBJ="$(jq -r .application.id <<<"$APP")"
    APP_ID="$(jq -r .application.appId <<<"$APP")"
    SP_ID="$(jq -r .servicePrincipal.id <<<"$APP")"
    ok "enterprise application \"Guacamole\" created ($APP_ID)"
  else
    APP_OBJ="$(jq -r .id <<<"$APP")"
    APP_ID="$(jq -r .appId <<<"$APP")"
    SP_ID="$(graph GET "/servicePrincipals?\$filter=$(urlenc "appId eq '$APP_ID'")" | jq -r '.value[0].id // empty')"
    [ -n "$SP_ID" ] || SP_ID="$(graph POST /servicePrincipals "{\"appId\":\"$APP_ID\"}" | jq -r .id)"
    ok "enterprise application \"Guacamole\" found ($APP_ID)"
  fi

  # Entity ID has no trailing slash (Entra rejects one); the reply URL has one.
  # Group names go out as display names, and only for groups assigned to the
  # app. The groups claim keeps no "source" field: with one, Entra silently
  # drops the change.
  graph PATCH "/applications/$APP_OBJ" "{
    \"identifierUris\": [\"$ENTITY_ID\"],
    \"web\": {\"redirectUris\": [\"$ENTITY_ID/\"]},
    \"groupMembershipClaims\": \"ApplicationGroup\",
    \"optionalClaims\": {\"saml2Token\": [{\"name\": \"groups\", \"additionalProperties\": [\"cloud_displayname\"]}]}
  }" >/dev/null
  graph PATCH "/servicePrincipals/$SP_ID" \
    '{"preferredSingleSignOnMode":"saml","appRoleAssignmentRequired":true}' >/dev/null
  ok "SAML: entity ID $ENTITY_ID, reply URL $ENTITY_ID/, group names in the claim"

  # Signing certificate, once. Entra signs the SAML response with it.
  if [ "$(graph GET "/servicePrincipals/$SP_ID?\$select=preferredTokenSigningKeyThumbprint" \
        | jq -r .preferredTokenSigningKeyThumbprint)" = null ]; then
    THUMB="$(graph POST "/servicePrincipals/$SP_ID/addTokenSigningCertificate" \
      "{\"displayName\":\"CN=$GUAC_HOSTNAME\"}" | jq -r .thumbprint)"
    graph PATCH "/servicePrincipals/$SP_ID" "{\"preferredTokenSigningKeyThumbprint\":\"$THUMB\"}" >/dev/null
    ok "token signing certificate created"
  else
    ok "token signing certificate present"
  fi

  # NameID = the account name on the targets, through a claims mapping policy
  # with a direct attribute source. A transformation is rejected by Graph.
  POLICY="$(jq -cn --arg a "$NAMEID_ATTR" '{displayName: "Guacamole NameID", isOrganizationDefault: false,
    definition: [({ClaimsMappingPolicy: {Version: 1, IncludeBasicClaimSet: "true", ClaimsSchema: [
      {Source: "user", ID: $a, SamlClaimType: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"}
    ]}} | tojson)]}')"
  POLICY_ID="$(graph GET /policies/claimsMappingPolicies | jq -r '.value[] | select(.displayName == "Guacamole NameID").id')"
  if [ -n "$POLICY_ID" ]; then
    graph PATCH "/policies/claimsMappingPolicies/$POLICY_ID" "$POLICY" >/dev/null
  else
    POLICY_ID="$(graph POST /policies/claimsMappingPolicies "$POLICY" | jq -r .id)"
  fi
  graph GET "/servicePrincipals/$SP_ID/claimsMappingPolicies" \
    | jq -e --arg id "$POLICY_ID" '.value[] | select(.id == $id)' >/dev/null \
    || graph POST "/servicePrincipals/$SP_ID/claimsMappingPolicies/\$ref" \
         "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$POLICY_ID\"}" >/dev/null
  ok "NameID claim = $NAMEID_ATTR"

  # The two groups: created if missing, then assigned to the application.
  ROLE_ID="$(graph GET "/servicePrincipals/$SP_ID?\$select=appRoles" \
    | jq -r '.appRoles[0].id // "00000000-0000-0000-0000-000000000000"')"
  assign_group() {
    local gid
    gid="$(graph GET "/groups?\$filter=$(urlenc "displayName eq '$1'")" | jq -r '.value[0].id // empty')"
    if [ -z "$gid" ]; then
      gid="$(graph POST /groups "$(jq -cn --arg n "$1" \
        '{displayName: $n, mailNickname: ($n | gsub("[^A-Za-z0-9]"; "")), mailEnabled: false, securityEnabled: true}')" \
        | jq -r .id)"
      ok "group \"$1\" created (empty: add members in Entra ID)"
    else
      ok "group \"$1\" found"
    fi
    graph GET "/servicePrincipals/$SP_ID/appRoleAssignedTo" \
      | jq -e --arg g "$gid" '.value[] | select(.principalId == $g)' >/dev/null \
      || graph POST "/servicePrincipals/$SP_ID/appRoleAssignedTo" \
           "{\"principalId\":\"$gid\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"$ROLE_ID\"}" >/dev/null
  }
  assign_group "$ADMIN_GROUP"
  assign_group "$OPERATOR_GROUP"
  ok "both groups assigned to the application; nobody else can sign in"

  URL="https://login.microsoftonline.com/$TENANT/federationmetadata/2007-06/federationmetadata.xml?appid=$APP_ID"
  if grep -q '^SAML_IDP_METADATA_URL=' .env; then
    sed -i.bak "s|^SAML_IDP_METADATA_URL=.*|SAML_IDP_METADATA_URL=$URL|" .env && rm .env.bak
  else
    echo "SAML_IDP_METADATA_URL=$URL" >> .env
  fi
  ok "SAML_IDP_METADATA_URL written to .env"
fi

# ---- Cloudflare ---------------------------------------------------------------
# Publishes GUAC_HOSTNAME through a Cloudflare Tunnel, behind Cloudflare Access
# with Entra ID sign-in. Runs while COMPOSE_PROFILES in .env contains
# "cloudflare", which is also what starts the cloudflared container.
PUBLISHED=
TUNNEL_TOKEN_OUT=
if [[ "$(env_get COMPOSE_PROFILES)" == *cloudflare* ]]; then
  step "Cloudflare"
  # Token: the environment, a command that prints it, or a prompt. The prompt
  # first walks through creating the token on the account's token page.
  CF_TOKEN="${CLOUDFLARE_API_TOKEN:-$(${CLOUDFLARE_TOKEN_CMD:-true})}"
  ACCT="$(env_get CLOUDFLARE_ACCOUNT_ID)"
  if [ -n "$CF_TOKEN" ]; then
    ok "API token from the environment"
  else
    [ -n "$ACCT" ] || { read -rp "  Cloudflare account ID (dashboard > the account > Overview, right-hand column): " ACCT; echo; }
    cat <<GUIDE

  Create an account API token, once:
    open   ${B}https://dash.cloudflare.com/${ACCT:-<account-id>}/api-tokens/create${X}
    name   guacamole-setup
    ${B}Policy 1${X}, scope: ${B}the account${X}. Search and tick:
           Cloudflare Tunnel Write
           Access: Apps and Policies Write
           Access: Organizations, Identity Providers, and Groups Write
    ${B}Add policy${X} -> ${B}Policy 2${X}, scope: ${B}Specified Domains${X} -> ${GUAC_HOSTNAME#*.}. Tick:
           DNS Write
           Zone Read
    expiry 7 days, then Review token -> Create token, and copy it.

GUIDE
    read -rsp "  Paste the token (not echoed): " CF_TOKEN; echo
  fi
  [ -n "$CF_TOKEN" ] || die "No token given."

  # cf METHOD PATH [JSON]. Prints .result. Token and body stay off the command line.
  cf() {
    local out
    out="$(printf 'header = "Authorization: Bearer %s"\n' "$CF_TOKEN" | curl -sS -K - \
      -X "$1" -H 'Content-Type: application/json' ${3:+-d @/dev/fd/3} \
      "https://api.cloudflare.com/client/v4$2" 3<<<"${3:-}")" \
      || die "Cloudflare $1 $2: curl failed."
    jq -e .success <<<"$out" >/dev/null 2>&1 \
      || die "Cloudflare $1 $2 failed: $(jq -r '.errors[0].message' <<<"$out")"
    jq -c .result <<<"$out"
  }

  # Account tokens verify under the account, user tokens under /user.
  VERIFY="$(cf GET "/accounts/${ACCT:-_}/tokens/verify" 2>/dev/null || cf GET /user/tokens/verify 2>/dev/null || true)"
  [ "$(jq -r '.status // empty' <<<"$VERIFY")" = active ] \
    || die "Cloudflare rejected the token. Check it was copied whole and that its policies match the list above."
  ok "API token accepted"

  # The zone is the longest suffix of GUAC_HOSTNAME that the token can see.
  NAME="$GUAC_HOSTNAME"; ZONE=""
  while :; do
    ZONE="$(cf GET "/zones?name=$NAME" | jq -r '.[0].id // empty')"
    [ -z "$ZONE" ] && [[ "$NAME" == *.*.* ]] || break
    NAME="${NAME#*.}"
  done
  [ -n "$ZONE" ] || die "No Cloudflare zone for $GUAC_HOSTNAME is visible to this token."
  ZINFO="$(cf GET "/zones/$ZONE")"
  ACCT="$(jq -r .account.id <<<"$ZINFO")"   # authoritative, whatever .env says
  ok "zone $NAME ($(jq -r .status <<<"$ZINFO")) in account $(jq -r .account.name <<<"$ZINFO")"

  # Zero Trust team. An account without one needs CLOUDFLARE_TEAM in .env.
  TEAM_DOMAIN="$(cf GET "/accounts/$ACCT/access/organizations" 2>/dev/null | jq -r '.auth_domain // empty' || true)"
  if [ -z "$TEAM_DOMAIN" ]; then
    TEAM="$(env_get CLOUDFLARE_TEAM)"
    [ -n "$TEAM" ] || die "This Cloudflare account has no Zero Trust team. Set CLOUDFLARE_TEAM in .env."
    TEAM_DOMAIN="$(cf POST "/accounts/$ACCT/access/organizations" \
      "{\"name\":\"$TEAM\",\"auth_domain\":\"$TEAM.cloudflareaccess.com\"}" | jq -r .auth_domain)"
    ok "Zero Trust team $TEAM_DOMAIN created"
  else
    ok "Zero Trust team $TEAM_DOMAIN"
  fi

  # Tunnel, configured in Cloudflare: the hostname goes to nginx on the compose
  # network. Cloudflare holds the public certificate, so nginx's own is not checked.
  TUN_NAME="guacamole-$GUAC_HOSTNAME"
  TUNNEL="$(cf GET "/accounts/$ACCT/cfd_tunnel?name=$TUN_NAME&is_deleted=false" | jq -r '.[0].id // empty')"
  if [ -n "$TUNNEL" ]; then
    ok "tunnel \"$TUN_NAME\" found"
  else
    TUNNEL="$(cf POST "/accounts/$ACCT/cfd_tunnel" \
      "{\"name\":\"$TUN_NAME\",\"config_src\":\"cloudflare\"}" | jq -r .id)"
    ok "tunnel \"$TUN_NAME\" created"
  fi
  cf PUT "/accounts/$ACCT/cfd_tunnel/$TUNNEL/configurations" "{\"config\":{\"ingress\":[
    {\"hostname\":\"$GUAC_HOSTNAME\",\"service\":\"https://nginx:443\",
     \"originRequest\":{\"noTLSVerify\":true,\"originServerName\":\"$GUAC_HOSTNAME\"}},
    {\"service\":\"http_status:404\"}]}}" >/dev/null
  ok "tunnel routes $GUAC_HOSTNAME → nginx"

  REC="$(cf GET "/zones/$ZONE/dns_records?name=$GUAC_HOSTNAME" | jq -r '.[0].id // empty')"
  DNS="{\"type\":\"CNAME\",\"name\":\"$GUAC_HOSTNAME\",\"content\":\"$TUNNEL.cfargotunnel.com\",\"proxied\":true,\"ttl\":1}"
  if [ -n "$REC" ]; then cf PUT "/zones/$ZONE/dns_records/$REC" "$DNS"; else cf POST "/zones/$ZONE/dns_records" "$DNS"; fi >/dev/null
  ok "DNS: $GUAC_HOSTNAME → tunnel (proxied)"

  # Access signs people in with Entra ID through its own OIDC app registration.
  # The client secret goes from Graph to Cloudflare in memory and is never shown.
  IDP_NAME="Entra ID (Guacamole)"
  IDP="$(cf GET "/accounts/$ACCT/access/identity_providers" | jq -r --arg n "$IDP_NAME" '.[] | select(.name == $n).id')"
  if [ -n "$IDP" ]; then
    ok "identity provider \"$IDP_NAME\" found"
  else
    [ -n "${TOKEN:-}" ] || die "Registering the Access identity provider needs the Entra ID sign-in. Blank SAML_IDP_METADATA_URL in .env and run again."
    AA_NAME="Cloudflare Access ($GUAC_HOSTNAME)"
    AA="$(graph GET "/applications?\$filter=$(urlenc "displayName eq '$AA_NAME'")" | jq -c '.value[0]')"
    if [ "$AA" = null ]; then
      AA="$(graph POST /applications "$(jq -cn --arg n "$AA_NAME" --arg cb "https://$TEAM_DOMAIN/cdn-cgi/access/callback" \
        '{displayName: $n, signInAudience: "AzureADMyOrg", web: {redirectUris: [$cb]}}')")"
      AA_SP="$(graph POST /servicePrincipals "{\"appId\":\"$(jq -r .appId <<<"$AA")\"}" | jq -r .id)"
      # Admin consent for the sign-in scopes, so users see no consent prompt.
      GRAPH_SP="$(graph GET "/servicePrincipals?\$filter=$(urlenc "appId eq '00000003-0000-0000-c000-000000000000'")" | jq -r '.value[0].id')"
      (graph POST /oauth2PermissionGrants "{\"clientId\":\"$AA_SP\",\"consentType\":\"AllPrincipals\",\"resourceId\":\"$GRAPH_SP\",\"scope\":\"openid profile email offline_access User.Read\"}" >/dev/null) \
        || warn "could not grant admin consent for the Access app; users will be asked to consent once."
      ok "Entra ID app \"$AA_NAME\" created, admin consent granted"
    fi
    IDP="$(cf POST "/accounts/$ACCT/access/identity_providers" "$(jq -cn --arg n "$IDP_NAME" --arg t "$TENANT" \
      --arg c "$(jq -r .appId <<<"$AA")" \
      --arg s "$(graph POST "/applications/$(jq -r .id <<<"$AA")/addPassword" '{"passwordCredential":{"displayName":"Cloudflare Access"}}' | jq -r .secretText)" \
      '{name: $n, type: "azureAD", config: {client_id: $c, client_secret: $s, directory_id: $t, support_groups: false}}')" | jq -r .id)"
    ok "identity provider \"$IDP_NAME\" created"
  fi

  # The Access application: anyone who signs in through that identity provider.
  # Entra only issues the SAML assertion to members of the assigned groups, and
  # Guacamole maps those groups to permissions, so authorisation stays there.
  # Cloudflare accepts an Access application only on an active zone, so on a
  # zone that still waits for its nameservers this step is left for the next run.
  if [ "$(jq -r .status <<<"$ZINFO")" = active ]; then
    APP="$(cf GET "/accounts/$ACCT/access/apps" | jq -r --arg d "$GUAC_HOSTNAME" '.[] | select(.domain == $d).id')"
    ACCESS="$(jq -cn --arg d "$GUAC_HOSTNAME" --arg i "$IDP" '{name: "Guacamole", domain: $d, type: "self_hosted",
      session_duration: "24h", allowed_idps: [$i], auto_redirect_to_identity: true,
      policies: [{name: "Entra ID users", decision: "allow", include: [{login_method: {id: $i}}]}]}')"
    if [ -n "$APP" ]; then cf PUT "/accounts/$ACCT/access/apps/$APP" "$ACCESS"; else cf POST "/accounts/$ACCT/access/apps" "$ACCESS"; fi >/dev/null
    ok "Access application for $GUAC_HOSTNAME: Entra ID users only"
    PUBLISHED=1
  else
    warn "zone $NAME is not active yet. Point its nameservers at:"
    jq -r '.name_servers[] | "      " + .' <<<"$ZINFO" >&2
    warn "then run ./setup.sh again to add the Access application. The tunnel and DNS record are ready."
  fi
  [ -n "$PUBLISHED" ] || die "Cloudflare Access is not ready. Activate the zone and run setup again."
  TUNNEL_TOKEN_OUT="$(cf GET "/accounts/$ACCT/cfd_tunnel/$TUNNEL/token" | jq -r .)"
fi

# ---- Start --------------------------------------------------------------------
step "Start services"
start_stack
unset DB_PASSWORD TUNNEL_TOKEN_OUT CF_TOKEN TOKEN

# ---- Summary ------------------------------------------------------------------
echo
rule
printf '%s%s Ready.%s\n\n' "$M" "$B" "$X"
if [ -n "$PUBLISHED" ]; then
  printf '  %shttps://%s/guacamole/%s\n  %sthrough Cloudflare, behind Access%s\n\n' "$B" "$GUAC_HOSTNAME" "$X" "$D" "$X"
else
  printf '  %shttps://%s:%s/guacamole/%s\n  %sreplace nginx/certs/*.pem with a trusted certificate%s\n\n' \
    "$B" "$GUAC_HOSTNAME" "$(env_get HTTPS_PORT)" "$X" "$D" "$X"
fi
rule
