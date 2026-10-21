# Cloudflare token onboarding research

Research date: 14 September 2026. Scope: public Cloudflare documentation and
Cloudflare-maintained source. No account changes or authenticated API tests.

Follow-up: [live test results](2026-09-14-cloudflare-oauth-tests.md) now verify
the exact scopes, PKCE consent, resource reads, refresh, and revocation. They
also show that published `cf@0.10.0` lacks the device and keyring interfaces
found in main-branch source. Read those results before choosing an implementation.

## Finding

The assumption that Cloudflare requires manual API token setup is outdated.
Cloudflare launched self-managed OAuth clients on 3 June 2026. All account plans
support third-party OAuth. The documented flow for our own CLI is Authorization
Code with PKCE. Cloudflare excludes Device Authorization for third-party clients.
[Launch announcement](https://developers.cloudflare.com/changelog/post/2026-06-03-public-oauth-clients/),
[availability](https://developers.cloudflare.com/fundamentals/oauth/),
[supported flows](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/).

Cloudflare also supports device code through its own tools. Wrangler gained this
flow in version 4.119.0 on 4 August 2026. Its scope list lacks permissions needed
for this deployment. The broader `cf` CLI is another candidate, but Cloudflare
labels it a technical preview. Exact API coverage still needs validation.
[Wrangler release](https://developers.cloudflare.com/changelog/post/2026-08-04-wrangler-login-device-flow/),
[Wrangler scopes](https://github.com/cloudflare/workers-sdk/blob/main/packages/workers-auth/src/core/scopes.ts),
[cf preview](https://developers.cloudflare.com/agent-setup/cursor/).

## Options

| Route | User experience | Evidence and limit |
|---|---|---|
| Our OAuth client with PKCE | Sign in, select an account, approve permissions | Supported for third-party CLIs; exact scope coverage needs validation. |
| Wrangler device login | Open a URL and approve a short code | Supported, but its scope catalog lacks DNS edit and Access write. |
| `cf` device login | Similar device approval | Official source includes the flow and broader scopes; technical preview. |
| Account token template URL | Review prefilled settings and create a token | Documented fallback; scope selection and token transfer remain. |
| Token creation API | Tool creates a token from a policy | Requires an existing authorized credential. |
| `cloudflared tunnel login` | Browser login for tunnel management | Produces an account certificate; no documented full Access provisioning coverage. |

The following sections explain the evidence behind these comparisons.

## Our own OAuth client

Proaxiom can register one client in its account. A third-party CLI uses token
authentication method `none`, PKCE `S256`, and a registered redirect URL. The CLI
does not need an embedded client secret. Registration requires an account role
with OAuth client write access. New clients are private to account members.
Public clients accept other Cloudflare users after publisher domain verification.
Promotion to public is permanent.
[Client configuration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/).

The administrator chooses the accounts and reviews requested permissions on the
Cloudflare consent page. They can revoke the authorization later. Account
administrators can block new public OAuth authorizations through account settings.
That setting does not revoke existing grants.
[Consent and administrator controls](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/).

For `guacdeploy` on a remote Linux server, the browser callback needs a design.
A local helper with an SSH handoff, or a callback relay with a session binding,
are design candidates. These are project proposals, not documented Cloudflare
device flows. Redirect URI acceptance and end-to-end delivery need testing.

Cloudflare publishes authorization, token, revocation, and discovery endpoints.
Its live discovery document advertises a device endpoint and the device-code
grant. The client documentation explicitly excludes that grant for third-party
clients. Provider metadata does not establish permission for our registration.
[Integration endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/),
[live discovery](https://dash.cloudflare.com/.well-known/openid-configuration),
[third-party restriction](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/).

## Permissions: the remaining proof

The project README requires these permissions:

| API permission | Deployment operation |
|---|---|
| Cloudflare Tunnel Write | Create/configure the tunnel and obtain its connector token |
| Access: Apps and Policies Write | Configure the Access application and policy |
| Access: Organizations, Identity Providers, and Groups Write | Configure Entra identity provider and, if absent, the team |
| DNS Write | Publish DNS and complete certificate DNS-01 challenges |
| Zone Read | Select and inspect the zone |

Cloudflare exposes the authoritative OAuth catalog at `GET /oauth/scopes`.
The response contains IDs, names, categories, and underlying resource scopes.
An unauthenticated request during this research failed. No exact third-party
scope IDs for the table above were verified. API token permission IDs and
first-party colon-separated scopes must not be copied into our registration.
The client API accepts validated dot-separated API scopes and simple identity
scopes; it rejects colon-separated scopes.
[OAuth scope API](https://developers.cloudflare.com/api/resources/iam/),
[client creation API](https://developers.cloudflare.com/api/resources/iam/subresources/oauth_clients/methods/create/).

The client API permits `authorization_code` and `refresh_token` grants.
Refresh support alone does not establish an unattended credential policy.
Token lifetime, rotation, revocation, account selection, user role changes, and
zone restrictions need validation before adoption.
[Client creation API](https://developers.cloudflare.com/api/resources/iam/subresources/oauth_clients/methods/create/).

## First-party device login

Wrangler documents `login --device`, `--browser=false`, and `auth token`.
The last command supplies credentials to other tools and refreshes expired OAuth
tokens. This is a supported integration surface. Its source validates requested
scopes against a fixed catalog. That catalog has Zone Read but lacks DNS edit
and Access write. Adding arbitrary scope names is not a supported workaround.
[Wrangler commands](https://developers.cloudflare.com/workers/wrangler/commands/general/),
[scope catalog](https://github.com/cloudflare/workers-sdk/blob/main/packages/workers-auth/src/core/scopes.ts).

The `cf` CLI uses a separate client identity. Its official authentication source
names `cf auth login --device`. Its scope catalog includes `dns_records:edit`,
`access:write`, `teams:write`, and `zone:read`. These are candidates for the
deployment's operations, not a verified permission mapping. Tunnel creation and
configuration, identity providers, and token creation need endpoint tests.
[cf authentication source](https://github.com/cloudflare/workers-sdk/blob/main/packages/workers-auth/src/cf/index.ts),
[cf scope catalog](https://github.com/cloudflare/workers-sdk/blob/main/packages/workers-auth/src/cf/scopes.ts).

Cloudflare labels `cf` a technical preview with a small initial command subset.
The wider API coverage is an objective. A source implementation does not prove
the behavior of a published version. Pin a release and check its commands,
scope selection, token export, and storage before choosing it as a dependency.
[Official preview documentation](https://developers.cloudflare.com/agent-setup/cursor/),
[announcement](https://blog.cloudflare.com/cf-cli-local-explorer/).

Wrangler defaults to plaintext credential storage. Its documentation offers OS
keychain storage. A saved keyring preference can fall back to plaintext when the
backend is unavailable; `CLOUDFLARE_AUTH_USE_KEYRING=true` makes that failure fatal.
The project rules require Mac Keychain storage and in-memory Linux session use.
A stock login on the server does not meet those rules. Do not print exported
tokens or put them in command arguments.
[Credential storage documentation](https://developers.cloudflare.com/workers/wrangler/commands/general/).

## Account-owned tokens and simpler fallback

Cloudflare documents account-owned token template URLs. The link can prefill
permission choices and the token name. The administrator still selects resource
scope and creates the token. The documented permission-key table does not list
a Tunnel key. Do not invent one; verify supported coverage before generating
the complete deployment link.
[Account token template URLs](https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/).

The API can create account-owned tokens at `POST /accounts/{account_id}/tokens`
with `Account API Tokens Write`. The user-token creation guide requires an
existing token with token-creation permission. Neither API supplies an
unauthenticated bootstrap. Whether an OAuth grant can mint the required
account-owned token remains unproven in this research. That route requires both
scope availability and a successful authorized endpoint test.
[Account token creation](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/create/),
[token bootstrap guide](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/).

An OAuth setup session does not remove the need for certificate renewal access.
The project uses DNS-01 challenges. A separate restricted DNS credential, or an
approved refresh mechanism, must serve unattended renewal. Account-owned tokens
also have different ownership and revocation behavior from user OAuth grants.
Keep this decision separate from interactive setup authentication.

## Other mechanisms

`cloudflared tunnel login` opens a browser and creates `cert.pem`. Cloudflare
documents account-wide tunnel administration through that credential. It does
not document the full Access application and identity-provider permissions that
this deployment needs. Its default file storage also conflicts with project
secret rules. A tunnel runner credential only runs its specific tunnel.
[Tunnel permissions](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/tunnel-permissions/).

Cloudflare's API MCP server provides OAuth-authorized API operations. That is
useful for an agent-assisted workflow, but introduces an MCP service dependency.
The documentation does not establish it as a token-export mechanism for
`guacdeploy`. Self-managed OAuth already provides a direct application route
without a partner-only integration program.
[Official API MCP documentation](https://developers.cloudflare.com/agent-setup/cursor/).

## Recommended next validation

1. Read the authenticated OAuth scope catalog without exposing the credential.
2. Map the five permission groups to available scopes and resource restrictions.
3. Test read access, then isolated create/update/delete operations in a test account.
4. Compare a registered PKCE client with a pinned `cf` preview release.
5. Validate account-token creation only if it is needed for durable credentials.
6. Define renewal storage and revocation before replacing the existing method.

The Go preflight currently calls `/user/tokens/verify`. OAuth access tokens and
account-owned tokens need appropriate validation paths. This is a project change
to plan after the authentication choice, not evidence that Cloudflare rejects
OAuth for provisioning.

The documentation supports replacing manual permission setup with OAuth consent.
This research does not yet prove a complete deployment with the required scopes.
The template URL remains a documented way to reduce manual work in the meantime.
