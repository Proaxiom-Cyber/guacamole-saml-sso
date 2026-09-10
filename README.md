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

Four containers on one Docker network. Only nginx listens on the host.

| Service | Image | Role |
|---|---|---|
| nginx | nginx:1.30-alpine | TLS termination, reverse proxy |
| guacamole | guacamole/guacamole | Web application, SAML authentication |
| guacd | guacamole/guacd | Protocol worker (SSH, RDP, VNC) |
| postgres | postgres:18-alpine | Groups, connections, session history |

## Requirements

- Docker with the Compose plugin, and `openssl`.
- A SAML identity provider. Entra ID, Okta and Keycloak all work.
- A DNS name for the service, and a certificate for it.

## Deploy

1. Copy `.env.example` to `.env`. Set the hostname, the identity provider metadata
   URL, and the two group names.
2. Run `./setup.sh`. It creates the folders, generates the database schema, and makes
   a self-signed certificate.
3. Replace `nginx/certs/fullchain.pem` and `privkey.pem` with a certificate your
   clients trust.
4. Register the application with your identity provider. See below.
5. Start the stack. The database password is never written to a file:

   ```bash
   export POSTGRES_PASSWORD="$(openssl rand -base64 24)"   # keep it: every compose command needs it
   docker compose up -d
   docker compose ps
   ```

6. Open `https://<GUAC_HOSTNAME>/guacamole/`. Sign-in starts at once.

The `init/` scripts run only when `data/` is empty. Get the group names right before
the first start, or delete `data/` and start again.

## Configuration

All of it lives in `.env`, except the database password.

| Setting | What it does |
|---|---|
| `GUAC_VERSION` | Guacamole image tag. The schema is generated from this version. |
| `GUAC_HOSTNAME` | Public hostname. It must match the certificate and the SAML entity ID. |
| `HTTPS_PORT` | Host port for HTTPS. Change it if something else on the host uses 443. |
| `SAML_IDP_METADATA_URL` | SAML metadata URL of the identity provider. |
| `SAML_GROUP_ATTRIBUTE` | Name of the SAML attribute that carries group membership. |
| `GUAC_ADMIN_GROUP` | Group whose members use the connections. |
| `GUAC_OPERATOR_GROUP` | Group whose members create and manage the connections. |

`POSTGRES_PASSWORD` is deliberately not in `.env`. Export it in the shell before each
compose command, and keep it in a password manager or a secret store.

## Identity provider

Register Guacamole as a SAML application with these values:

- **Entity ID:** `https://<GUAC_HOSTNAME>/guacamole` — no trailing slash.
- **Reply URL (ACS):** `https://<GUAC_HOSTNAME>/guacamole/` — with a trailing slash.
- **NameID:** the account name on the target hosts, not the full email address. This
  is required, not cosmetic. `${GUAC_USERNAME}` expands to the NameID, and a Linux
  account cannot be named `jane.doe@example.com`.
- **Group claim:** enabled, and sending group *names* rather than object IDs. If your
  provider can only send object IDs, put those IDs in `GUAC_ADMIN_GROUP` and
  `GUAC_OPERATOR_GROUP` instead.

Assign only the two groups to the application.

### Entra ID

Entra ID needs three things that its default settings do not give you.

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

```bash
docker compose logs -f guacamole    # application and SAML log
docker compose logs -f guacd        # session log
./connectdb.sh                      # psql shell
./destroy.sh                        # remove containers, networks and images
```

To reset the database, stop the stack and delete `data/`. The `init/` scripts run
again on the next start. This also deletes the session history, so do not use it to
change access. Access changes belong in the identity provider.

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
