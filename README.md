# Guacamole SAML SSO

Apache Guacamole in Docker, with SAML single sign-on and no local accounts. It gives
named staff browser-based SSH and RDP access to internal targets. People sign in with
your identity provider. The database only decides what each group is allowed to reach.

A stock Guacamole deployment keeps its own user list and stores a credential for every
target. This one does neither.

- **No local accounts.** The default `guacadmin` account is deleted while the database
  is built. There is no password in the database to guess or to leak.
- **No stored target credentials.** Connections carry no password and no private key.
  Guacamole asks the person at connect time.
- **The identity carries through.** A connection uses `${GUAC_USERNAME}` as the target
  username, so one connection serves everybody and each person lands on the target as
  their own account. The target's own logs name the real person.
- **Access is a group change.** Onboarding and offboarding happen in the identity
  provider. No SQL, no restart, and the session history stays intact.
- **The schema matches the image.** `setup.sh` generates the database schema from the
  same Guacamole version the stack runs, so the two cannot drift apart.

## Components

Four containers on one Docker network, plus `cloudflared` when enabled. Only nginx
listens on the host.

| Service | Image | Role |
|---|---|---|
| nginx | nginx:1.30-alpine | TLS termination, reverse proxy |
| guacamole | guacamole/guacamole | Web application, SAML authentication |
| guacd | guacamole/guacd | Protocol worker (SSH, RDP, VNC) |
| postgres | postgres:18-alpine | Groups, connections, session history |
| cloudflared | cloudflare/cloudflared:latest | Optional Cloudflare Tunnel connector |

## Requirements

Have these ready before you run `setup.sh`.

**A Linux host**

- A recent distribution: Ubuntu, Debian, RHEL, Rocky, Alma, Fedora, SUSE, Alpine or Arch.
- Docker with the Compose plugin, `curl`, `jq` and `openssl`. `setup.sh` offers to
  install missing tools with the distribution's package manager. On Rocky Linux,
  it installs Docker from the RHEL repository, then enables and starts the Docker
  service. This follows [Rocky's Docker installation guide][rocky-docker].
  Other distributions use `get.docker.com` for Docker. Run setup as root on every
  run, or use `sudo ./setup.sh`. Setup stops before making changes if run without root.
- Outbound internet access. With Cloudflare, no inbound port is needed at all.

[rocky-docker]: https://docs.rockylinux.org/gemstones/containers/docker/

The `podman-docker` package makes the `docker` command run Podman. Installing the
Docker Compose plugin does not change that. Setup warns when it detects Podman;
this project has not been verified with Podman. Before it asks for credentials,
setup checks that Compose can connect to the container engine.

**An Entra ID tenant** (or another SAML identity provider: Okta and Keycloak work, with
manual registration)

- An account with the Global Administrator role. `setup.sh` signs in with a device code
  as the "Microsoft Graph Command Line Tools" client and asks for delegated permissions
  that need a Global Administrator's consent. You consent to that client, not to this
  project. You can revoke it in Enterprise applications afterwards.
- A user attribute that holds the account name on the target hosts: `mailNickname`
  (default) or `onPremisesSamAccountName` for AD-synced accounts.

**A Cloudflare account** (skip if `COMPOSE_PROFILES` is empty)

- The service's domain added to the account as a zone, with the domain's nameservers
  pointed at Cloudflare and the zone showing **Active**. On a pending zone the script
  creates the tunnel and the DNS record, skips Cloudflare Access, and asks you to run it
  again once the zone is active.
- Zero Trust enabled for the account (the free plan is enough). If the account has no
  Zero Trust team yet, set `CLOUDFLARE_TEAM` in `.env` and the script creates one.
- An **account-owned API token**. See the Cloudflare section for the exact permissions.
  Creating one needs the Super Administrator role on the account.

**A DNS name** for the service, such as `guacamole.example.com`. With Cloudflare, that
is all: Cloudflare provides the tunnel and the public certificate. Without Cloudflare,
also a certificate for that name that your clients trust, and a firewall rule for
`HTTPS_PORT`.

## Install the deployment tool

The V1 `guacdeploy` tool installs from a signed GitHub release. No checkout and no Go
toolchain are needed on the server. The launcher verifies the SHA-256 checksum and the
Sigstore signature of the release, and refuses to install anything that fails either
check:

```sh
curl -fsSLO https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/latest/download/get-guacdeploy.sh && sh get-guacdeploy.sh
```

For a normal login, the launcher uses `sudo` to install the verified binary and
start the setup wizard. A terminal run continues into setup without another command.
Use `sh get-guacdeploy.sh --install-only` to install without starting setup.
Without terminal input and output, the launcher only installs the binary.

The guided interface shows one task at a time. Press Tab for timestamped history.
Setup writes a private session log under `/var/lib/guacdeploy/logs` and prints its
path at exit. Use `guacdeploy preview` to try the interface with example data.
See [terminal controls and logs](docs/operator-guide.md#guided-terminal-interface).

Read the script before you run it. [Release and verification](docs/release-and-verification.md)
describes the signing identity, the trust bootstrap, the network destinations the
launcher uses, and the approval an administrator must give on hosts with application
allowlisting.

## Deploy

The launcher starts setup after an interactive installation. To start setup later
or resume an interrupted deployment, run:

```sh
sudo guacdeploy
```

It checks the host first — Rocky Linux 10 on Intel or AMD 64-bit, root, no existing
installation, and the outbound access it needs — and refuses with an explanation rather
than changing anything it should not. It then asks how credentials should be supplied,
shows what it will install before installing it, and records what it creates.

For an unattended run, give it the same answers as flags:

```sh
sudo guacdeploy setup --non-interactive --install-dependencies \
  --credentials file \
  --hostname guac.example.com \
  --admin-group "Guacamole Administrators" \
  --operator-group "Guacamole Operators" \
  --zone example.com
```

Unattended runs never wait for input. Where the specification requires a person —
approving a change to a resource the tool did not create, for instance — the run stops
with exit code 3 and says what needs approving.

What a full run does, in order: prepares the host, selects the Cloudflare account and
zone, creates the tunnel, renders the stack configuration and database schema, obtains a
Let's Encrypt certificate for the origin by DNS-01, starts the containers, installs
reboot recovery and any schedules you asked for, checks the local origin, provisions
Entra sign-in, publishes the DNS record, puts Cloudflare Access in front, and only then
starts the connector. Nothing is reachable from the internet until sign-in exists and
the Access policy has been verified.

If a run is interrupted, run it again: it shows the work that did not finish and offers
to resume or clean up. Completed work is never repeated, and a creation whose response
was lost is reconciled by ownership marker rather than repeated.

`guacdeploy status` shows the deployment record. `docs/operator-guide.md` covers every
command, the exit codes, backups, recordings, certificates and teardown.

### The original shell scripts

`setup.sh` and the `lib/` and `init/` scripts are the pre-V1 workflow and are kept for
reference. They need a checkout on the server, which is exactly what `guacdeploy`
removes. A deployment made by those scripts is **not** adopted by `guacdeploy`: it
refuses to overwrite an existing installation and explains why.

On later interactive runs, setup offers to keep the saved hostname. Answer `n` to
choose another domain and hostname. Runs without a terminal keep the saved hostname.
The chosen domain ID is saved as `CLOUDFLARE_ZONE_ID` in `/opt/guacamole/.env`.

Changing the hostname registers Entra SAML for the new name and replaces a local
certificate that does not match. Previous Entra registrations, tunnels and DNS
records remain in place. For a manually configured SAML provider, update that
provider and the saved hostname yourself before running setup.

1. Keep the database password in your secret store. For an existing database, use its
   current password. For a new database, create a password in the store first.
2. As root, run `./setup.sh` from the Git checkout. It installs or updates the live deployment
   in `/opt/guacamole`, then continues from there. On the first run it asks whether
   to publish through Cloudflare. With Cloudflare, supply the API token, choose a
   domain, then enter a hostname such as `guacamole`. Setup lists the domains that
   the token can access in the selected account. If only one domain is available,
   setup uses it and asks for the hostname. Without Cloudflare, enter the full
   public hostname. It writes non-secret configuration to `/opt/guacamole/.env`.
   To change group names or use Okta or Keycloak, copy `.env.example` to `.env` and edit
   it before the first run. Set the identity provider metadata URL for Okta or Keycloak.
3. Supply the database password at the masked prompt and confirm it. Setup can also
   retrieve it through `POSTGRES_PASSWORD_CMD` or use an existing `POSTGRES_PASSWORD`
   session variable. It never generates a replacement password on a later run.
4. The script creates the folders, generates the database schema, and makes a
   self-signed certificate. If the metadata URL is empty, it also registers the
   application in Entra ID: it shows a device code, you sign in as an administrator,
   and it writes the metadata URL back to `.env`.
   With `COMPOSE_PROFILES=cloudflare` (the default), it uses the supplied token to
   publish the hostname: a tunnel, a proxied DNS record, and Cloudflare
   Access with Entra ID sign-in in front. Setup gets the tunnel token without displaying it.
5. Setup starts the containers and waits for the guacd, database and tunnel health checks.
   It checks the Guacamole page through local nginx, shows container status, then prints
   the service URL. If Cloudflare Access is not ready, setup stops before starting the
   services. Activate the zone and run setup again.
6. Without Cloudflare, replace `nginx/certs/fullchain.pem` and `privkey.pem` with a
   certificate your clients trust, then run setup again. Open `HTTPS_PORT` to your clients.
7. Open the URL from the summary. With Cloudflare, it is
   `https://<GUAC_HOSTNAME>/guacamole/`. Sign-in starts at once.

## Configuration

Non-secret configuration lives in `/opt/guacamole/.env`. Passwords and tokens do not
belong there.

| Setting | What it does |
|---|---|
| `GUAC_VERSION` | Guacamole image tag. The schema is generated from this version. |
| `GUAC_HOSTNAME` | Public hostname. It must match the certificate and the SAML entity ID. |
| `HTTPS_PORT` | Host port for HTTPS. Change it if something else on the host uses 443. |
| `SAML_IDP_METADATA_URL` | SAML metadata URL of the identity provider. Empty means `setup.sh` registers the application in Entra ID and fills it in. |
| `ENTRA_NAMEID_ATTRIBUTE` | Entra ID only. User attribute that becomes the NameID. `mailnickname` (default) or `onpremisessamaccountname`. |
| `SAML_GROUP_ATTRIBUTE` | Name of the SAML attribute that carries group membership. |
| `GUAC_ADMIN_GROUP` | Group whose members use the connections. |
| `GUAC_OPERATOR_GROUP` | Group whose members create and manage the connections. |
| `POSTGRES_PASSWORD_CMD` | Optional command that retrieves the existing database password. Empty means a masked prompt. A session variable with this name overrides the value in `.env`. |
| `COMPOSE_PROFILES` | `cloudflare` publishes through Cloudflare and starts the `cloudflared` container. Empty skips Cloudflare. |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID, used to link straight to the token page. Asked for if empty. |
| `CLOUDFLARE_TEAM` | Zero Trust team name, used only if the Cloudflare account has none yet. |

Use `/opt/guacamole/setup.sh` to start or recreate the services. It passes the database
password and tunnel token to Compose through a pipe. It does not print them or write
them to `.env`, an override file, or a command argument. Docker supplies them to the
containers as environment variables.

On Linux, inject the database secret into the SSH session from the Mac's Keychain.
For example, after connecting with `ssh-secret <host> guacamole-postgres`, run:

```bash
POSTGRES_PASSWORD_CMD='secret-get guacamole-postgres' /opt/guacamole/setup.sh
```

The command must return the same password on later runs. If the command fails, setup
stops. With no command or session password, paste the stored password at the masked
prompt. Setup checks database authentication before it starts Guacamole. It does not
change the password of an existing database.

## Identity provider

Register Guacamole as a SAML application with these values:

- **Entity ID:** `https://<GUAC_HOSTNAME>/guacamole`, no trailing slash.
- **Reply URL (ACS):** `https://<GUAC_HOSTNAME>/guacamole/`, with a trailing slash.
- **NameID:** the account name on the target hosts, not the full email address. This
  is required, not cosmetic. `${GUAC_USERNAME}` expands to the NameID, and a Linux
  account cannot be named `jane.doe@example.com`.
- **Group claim:** enabled, and sending group *names* rather than object IDs. If your
  provider can only send object IDs, put those IDs in `GUAC_ADMIN_GROUP` and
  `GUAC_OPERATOR_GROUP` instead.

Assign only the two groups to the application.

### Entra ID

`setup.sh` does all of this for you. It signs in with a device code as the "Microsoft
Graph Command Line Tools" client, and asks for these delegated permissions:
`Application.ReadWrite.All`, `Policy.ReadWrite.ApplicationConfiguration`,
`AppRoleAssignment.ReadWrite.All`, `Group.ReadWrite.All` and `Organization.Read.All`.
A Global Administrator can consent to them. The script then creates the enterprise
application, its signing certificate, the NameID claims policy, and the two groups if
they do not exist, and assigns the groups to the application. Run it again at any
time; each step finds what exists before it creates anything.

New registrations are named `Guacamole (<hostname>)`. Each application has its own
NameID policy. Setup reuses an older registration named `Guacamole` only if its
entity ID matches this hostname. An existing metadata URL remains unchanged.

If Cloudflare setup fails, run setup again. When the Access identity provider still
needs to be created, setup requests an Entra sign-in even if the SAML metadata URL
is already saved. You do not need to clear that URL.

If the device code flow is not available (Conditional Access blocks it, or the run is
unattended), set `GRAPH_TOKEN_CMD` to a command that prints a Graph access token, and
the script uses that instead. Run these examples in a root session. Commands and
session secrets must be available in that session; `sudo` does not normally retain
them. Two examples:

```bash
# An administrator signed in with the Azure CLI on this machine.
GRAPH_TOKEN_CMD="az account get-access-token --resource-type ms-graph --query accessToken -o tsv" ./setup.sh

# A service principal with the same five permissions as application permissions.
# The client secret comes from a secret store; never put it in a file or the shell history.
GRAPH_TOKEN_CMD=./graph-token.sh ./setup.sh
```

where `graph-token.sh` does a client-credentials request against
`https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` with scope
`https://graph.microsoft.com/.default` and prints the `access_token`. The token is used
in memory only; the script never writes it to a file or a command line.

If you register the application by hand instead, Entra ID needs three things that
its default settings do not give you.

**Entity ID.** Entra rejects an identifier URI that ends in `/`, with
`IdentifierUrisEndsWithSlash`. Use no trailing slash, and keep the reply URL's
trailing slash. They are different on purpose.

**NameID.** Use a claims mapping policy with a direct attribute source, which needs no
transformation: `onPremisesSamAccountName` for AD-synced accounts, or `mailNickname`
for cloud-only ones. A `ClaimsSchema` entry of
`{"Source":"user","ID":"mailnickname","SamlClaimType":"<nameidentifier URI>"}` is
accepted. The equivalent `ExtractMailPrefix` transformation shape is rejected by Graph
with `Property definition has an invalid value`. Creating the policy needs the
`Policy.ReadWrite.ApplicationConfiguration` permission.

**Group names.** Entra sends group object GUIDs by default. To send names instead, set
`optionalClaims.saml2Token` to a `groups` claim with the additional property
`cloud_displayname`. Omit the `source` field, or Entra discards the change without an
error.

Entra names the group claim with a URI, so leave `SAML_GROUP_ATTRIBUTE` set to
`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`. Set it to `groups`
only if you rename the claim in the application.

## Cloudflare

With `COMPOSE_PROFILES=cloudflare`, `setup.sh` publishes the service without opening a
port on the host. It needs a Cloudflare API token, taken from `CLOUDFLARE_API_TOKEN`,
from a command named in `CLOUDFLARE_TOKEN_CMD`, or from a masked prompt. The token is
used in memory during the run and never written anywhere.

### The API token

Use an **account-owned token**. It belongs to the account, not to a person: it keeps
working when staff change, it sees that one account only, and the audit log names it
as its own principal. The script calls account and zone endpoints only, and an account
token can call all of them.

`setup.sh` prints these steps, with the account's own URL, at the moment it needs the
token:

1. Sign in to the [Cloudflare dashboard](https://dash.cloudflare.com) with an account
   that has the **Super Administrator** role on the account that holds the zone.
2. Open `https://dash.cloudflare.com/<account-id>/api-tokens/create` (or the account →
   **Manage account → Account API tokens → Create token**). The account ID is on the
   account's Overview page, right-hand column.
3. Name the token, for example `guacamole-setup`.
4. **Policy 1**, scope the account itself. Search the permission groups and tick:
   - Cloudflare Tunnel **Write**
   - Access: Apps and Policies **Write**
   - Access: Organizations, Identity Providers, and Groups **Write**
5. **Add policy** → **Policy 2**, scope **Specified Domains** → your domain. Tick:
   - DNS **Write**
   - Zone **Read**
6. Token expiration: **7 days**. Setup is a one-off; a later re-run can use a new token.
   Client IP filtering is optional.
7. **Review token → Create token**, copy it, and paste it at the prompt. The dashboard
   shows it once.

| Permission | Scope | Used for |
|---|---|---|
| Cloudflare Tunnel Write | account | the tunnel, its route, and its token |
| Access: Apps and Policies Write | account | the Access application and policy |
| Access: Organizations, Identity Providers, and Groups Write | account | the Entra ID identity provider, and the team if the account has none |
| DNS Write | zone | the CNAME for the hostname |
| Zone Read | zone | finding the zone from the hostname |

Do not use the Global API Key. You cannot scope it, expire it or rotate it on its own. A
user token (My Profile → API Tokens) also works, but Cloudflare deletes it when that
user leaves the account.

The token you paste covers setup only. The tunnel token is a separate credential that
setup retrieves and passes to `cloudflared` without displaying it. The connector uses
that token at runtime. It cannot use it to change DNS or Access configuration.

The script finds the zone from `GUAC_HOSTNAME`, then creates or updates:

1. A Zero Trust team, if the account has none. The name comes from `CLOUDFLARE_TEAM`.
2. A tunnel named `guacamole-<hostname>`, configured in Cloudflare to send the hostname
   to `nginx` on the compose network. Cloudflare holds the public certificate, so the
   self-signed one in `nginx/certs` is enough.
3. A proxied CNAME for the hostname to the tunnel.
4. A second Entra ID app registration, "Cloudflare Access (<hostname>)", and a Cloudflare
   identity provider that uses it. The client secret passes from Graph to Cloudflare in
   memory. Admin consent is granted, so users see no consent prompt.
5. An Access application for the hostname with one policy: anyone who signs in through
   that identity provider. Authorisation stays with Entra ID, which only issues the SAML
   assertion to members of the assigned groups, and with Guacamole's group mapping.

Setup then starts the services and waits for the tunnel to connect to Cloudflare.
Every provisioning step finds what exists before it creates anything. On a later run,
setup retrieves the tunnel token again and requires the same database password.

## Access model

Membership lives in the identity provider. The database holds no individual users.

| Group | Permission | Who |
|---|---|---|
| `GUAC_ADMIN_GROUP` | READ on each connection | The people who use the access. |
| `GUAC_OPERATOR_GROUP` | Create and manage connections | Whoever maintains the target list. |

## Adding a target

Sign in as a member of the operator group and create the connection in the web
interface. Two settings matter:

- **Username:** `${GUAC_USERNAME}`. Guacamole substitutes the signed-in identity at
  connect time. Do not enter a literal username.
- **Password and private key:** leave both empty. Guacamole prompts at connect time,
  so no target credential is ever stored.

Then grant READ on the connection to the administrator group.

## Operate

The live program, configuration, certificate, logs and database are under
`/opt/guacamole`. The Git checkout contains the source used to update that deployment.
Run operational commands from the installed folder:

```bash
cd /opt/guacamole
./setup.sh                         # start or recreate the services
docker compose logs -f guacamole    # application and SAML log
docker compose logs -f guacd        # session log
./connectdb.sh                      # psql shell
./destroy.sh                        # remove containers, networks and images
```

Setup saves the generated schema only after the image command succeeds and the
output contains the required tables. It regenerates files from older setup runs
that have no completion marker. This does not change an existing database.
The database health check requires the Guacamole tables as well as a valid password.

Compose checks guacd's listening port every five seconds. This overrides the
five-minute health-check interval in the guacd 1.6.0 image, which exceeds setup's
three-minute wait limit. Guacamole starts after guacd and the database are healthy.

After the containers start, setup checks the HTTPS page through local nginx for up
to two minutes. It shows progress during this check. HTTP `000` means that the
request received no HTTP response.

An older installer created `/opt/guacamole/nginx/templates` without copying
`guacamole.conf.template`. This left nginx without the HTTPS configuration. From the
Git checkout on an affected host, copy the template and restart nginx:

```bash
sudo install -m 644 nginx/templates/guacamole.conf.template /opt/guacamole/nginx/templates/
docker restart guacamole-saml-sso-nginx-1
```

The restart loads the template into the existing nginx container. If setup already
stopped, run `/opt/guacamole/setup.sh` again with the same database password.

For a failed fresh installation with no connections or session history to preserve,
update the source, install it, then remove the failed database:

Run the following commands in a root session:

```bash
cd /path/to/guacamole-saml-sso &&
git pull --ff-only &&
./setup.sh --install-only &&
cd /opt/guacamole &&
docker compose down &&
rm -rf -- /opt/guacamole/data &&
rm -f -- /opt/guacamole/init/001-initdb.sql &&
./setup.sh
```

Keep `/opt/guacamole/.env` and use the same database password. Setup regenerates the
schema and initialises a new database. Do not use this reset to change access. Access
changes belong in the identity provider.

## Security notes

- Keep `SAML_STRICT` true. Set `SAML_DEBUG` true only during a fault investigation,
  and set it back after.
- Test the REST token endpoint as well as the login page, to confirm that no local
  login path remains.
- Put the service behind a private network path or a zero-trust proxy if the targets
  are sensitive. Nothing here limits who can reach the login page.
- The self-signed certificate from `setup.sh` is for a first test only.

## License

MIT. See [LICENSE](LICENSE).

Apache Guacamole is a trademark of the Apache Software Foundation. This project is not
affiliated with or endorsed by the ASF.
