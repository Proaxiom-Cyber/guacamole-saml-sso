# Wiring internal/cloudflare into the session

This package is self-contained: no imports from session, stack, host, or creds. The
parent wires it into the phase registry. Everything below uses existing repo mechanics
(phase journal in `runPhases`, `state.Config`, `state.EnsureResource`, `stack.Up`'s
`tunnelToken` parameter).

## Client construction

```go
cf := &cloudflare.Client{Token: func(ctx context.Context) (string, error) {
        return credsManager.Get(specFor("cloudflare-api-token")) // in-memory only
}}
```

`Client.HTTP` and `Client.Base` stay zero in real runs; tests inject them. Never log
the token; the package never places it in errors.

## Phase placement

Insert three phases between `stack-configure` (hostname is known after it) and
`stack-render` (which writes `COMPOSE_PROFILES` from `Config["compose-profiles"]`
into `.env`). One cloud create per phase, so the existing intent-before-work journal
in `runPhases` is the pre-create intent record the spec requires.

1. `cloudflare-select` — verify token and select account and zone.
2. `cloudflare-tunnel` — create the tunnel and configure ingress.
3. `cloudflare-dns` — create the hostname CNAME.

## Phase 1: cloudflare-select

- Derive the apex from `Config["guac-hostname"]` (parent's job; this package takes
  the apex as given).
- `zones, err := cf.ZonesByName(ctx, apex)` — the caller approves the result:
  zero zones is a hard error; one zone is confirmed interactively or accepted
  unattended when `--zone` matches; more than one needs interactive choice or an
  explicit flag (`ErrApprovalRequired` otherwise).
- `cf.Preflight(ctx, accountID, zoneID)` — proves the token is active and holds the
  read scopes. The doc comment on `Preflight` maps each endpoint to the permission
  it proves. Edit scopes (DNS Edit, Cloudflare Tunnel Edit) have no read-only proof;
  the first Apply proves them and a 403 there names the failed endpoint.
- Store in `state.Config` (non-secret references only): `cloudflare-account-id`,
  `cloudflare-account-name`, `cloudflare-zone-id`, `cloudflare-zone-name`.
- Set `Config["compose-profiles"] = "cloudflare"` here, so `stack-render` writes the
  profile into `.env` and `stack-up` starts cloudflared.

## Phase 2: cloudflare-tunnel

```go
p := &cloudflare.Provisioner{Client: cf, AccountID: ..., ZoneID: ...,
        Hostname: st.Config["guac-hostname"], DeploymentID: st.DeploymentID}
```

- Journal before create: `runPhases` already saves the action with a correlation ID
  before `Run`; additionally put `p.PlanTunnel()` (name + config_src, no secrets) in
  the phase's `u.Say` output so the operator sees what will be created.
- `tun, err := p.ApplyTunnel(ctx)` — reconciles before creating: a tunnel whose name
  carries the deployment-ID marker is adopted (lost-response recovery), a name-only
  match returns `cloudflare.ErrRequiresReview` (interactive review, or nonzero exit
  unattended), otherwise it creates.
- `p.ConfigureIngress(ctx, tun.ID)` — idempotent PUT; TLS verification to the origin
  stays enabled. Until issue #9 issues the origin certificate, the public hostname
  returns a Cloudflare origin-TLS error because nginx still serves the temporary
  self-signed certificate. Say so in the phase output; do not disable verification.
- Record evidence:

```go
st.EnsureResource(state.Resource{Provider: "cloudflare", Type: "tunnel",
        ProviderID: tun.ID, Name: tun.Name, CorrelationID: corrID,
        Ownership: "deployment ID embedded in tunnel name (guacdeploy-<host>-<id>)",
        CreatedAt: now})
```

- Store `Config["cloudflare-tunnel-id"] = tun.ID`. Do NOT call `TunnelToken` here;
  the token is fetched at stack start (below) and is never journalled.

## Phase 3: cloudflare-dns

- `plan := p.PlanDNS(st.Config["cloudflare-tunnel-id"])` — show it, then
  `rec, err := p.ApplyDNS(ctx, plan)`.
- `cloudflare.ErrPreExisting` means a record already occupies the hostname without
  the marker: never overwritten; interactive approval decides (choose another
  hostname or remove the record manually), unattended exits nonzero.
- A record already carrying the marker comment is adopted (lost-response recovery).
- Record evidence:

```go
st.EnsureResource(state.Resource{Provider: "cloudflare", Type: "dns-record",
        ProviderID: rec.ID, Name: rec.Name, CorrelationID: corrID,
        Ownership: "record comment guacdeploy:<deployment-id>", CreatedAt: now})
```

- Store `Config["cloudflare-record-id"] = rec.ID`.

## Tunnel token flow into stack.Up

In `Options.stackSecrets` (internal/session), replace the empty tunnel token:

```go
if id := st.Config["cloudflare-tunnel-id"]; id != "" {
        tunnelToken, err = p.TunnelToken(ctx, id)
}
return password, tunnelToken, err
```

The token goes straight into `stack.Up(ctx, run, cfg, password, tunnelToken)`, which
writes it to an owner-only file on memory-backed storage that the connector reads as
`TUNNEL_TOKEN_FILE`. It must never
reach state, logs, `.env`, or command arguments. Fetching at start time also means a
rotated tunnel token needs no local change.

## Teardown

Order: `p.DeleteRecord(ctx, recordID)` then `p.DeleteTunnel(ctx, tunnelID)` (stop the
cloudflared container first so the tunnel has no active connections; the delete uses
`cascade=true` regardless). Both re-fetch and verify the marker; an unmarked resource
returns `cloudflare.ErrNotOwned` — report it and leave it. This package has no zone
deletion, so a zone that now carries unrelated records is preserved structurally:
only marker-owned records are ever eligible.

## Error conditions the session must map

| Condition | Meaning | Guided | Unattended |
|---|---|---|---|
| `ErrRequiresReview` | name-only tunnel match, an Access application whose marker and hostname disagree, or a second policy found on our own Access application | show and ask | nonzero exit |
| `ErrPreExisting` | foreign DNS record at hostname, or a foreign Access application covering it | show and ask | nonzero exit |
| `ErrNotOwned` | delete target lacks marker | report, keep resource | same |
| `ErrNoAllowList` | nobody was named in the Access allow-list | ask for groups or emails | nonzero exit |
| `ErrAllowsEveryone` | the **stored** Access policy admits everyone | stop; never report as verified | nonzero exit |
| `*APIError` 403 on Apply | missing Edit scope | name the scope, stop | same |

# Phase 4: cloudflare-access (issue #8)

Cloudflare Access in front of the deployment hostname. This phase must run **after
`entra-signin`**, because its allow-list is built from the Entra tenant and group
object IDs that phase produced.

**Turning Access on closes the hostname to anonymous requests.** Any health check the
session makes against the public hostname after this phase will get the Access
challenge, not Guacamole. Check health against the local origin instead.

## Identity model — decided, and why

The Access application is bound to the account's **existing** Entra-backed
(`azureAD`) identity provider, found by matching `config.directory_id` against
`Config["entra-tenant-id"]` from issue #6. The policy allow-list then names the exact
**administrator and operator group object IDs** that issue #6 created. Access and
Guacamole therefore authorise the same people from the same directory objects, and
adding an operator is one Entra group membership.

This package **discovers** the identity provider and never creates one:

- An Access `azureAD` provider needs an OIDC client ID and client secret. The SAML
  application from issue #6 has neither, so creating one means a second Entra
  application registration plus a new long-lived secret for this tool to hold.
- An Access identity provider is **account-wide**, shared by every application in the
  account. Under ADR 0002 the tool could never delete it at teardown, so it would be
  creating a resource it can never clean up.

When the account has no Entra-backed provider, the fallback is an explicit list of
operator **email addresses** (`Allow.Emails`), and setting up the identity provider
stays a one-off account decision for a person. Either way the allow-list is explicit:
`PlanAccess` returns `ErrNoAllowList` rather than produce an application anybody can
reach. Never default to "allow everyone", not even unattended.

Operators sign in **twice**: once to Cloudflare Access, once to Guacamole's Entra
SAML. That is intended — two independent gates. Say so in the phase output so it does
not read as a bug.

## Ownership marker

The Access application API has no writable comment, note or description field, and
its `tags` are a separate account-level resource with its own lifecycle. So the marker
is in the **name**, as it is for the tunnel:

- Application: `Guacamole <hostname> (guacdeploy:<deployment-id>)` —
  `p.AccessAppName()`, set inside the creation request body.
- Policy: `Guacamole operators (guacdeploy:<deployment-id>)` —
  `p.AccessPolicyName()`. The policy is created under the application, so its
  ownership follows the application's.

A name is only half a proof, so **adoption and deletion also require the
application's `domain` to still cover this deployment's hostname**. A marker name on
another hostname is `ErrRequiresReview`, never an adoption.

## Phase flow

```go
p := &cloudflare.Provisioner{Client: cf, AccountID: ..., ZoneID: ...,
        Hostname: st.Config["guac-hostname"], DeploymentID: st.DeploymentID}

if err := cf.PreflightAccess(ctx, accountID); err != nil { ... }

idps, err := cf.IdentityProviders(ctx, accountID)
allow := cloudflare.Allow{}
if idp, found := cloudflare.FindEntraIdP(idps, st.Config["entra-tenant-id"]); found {
        allow.IdPID = idp.ID
        allow.Groups = []string{st.Config["entra-admin-group-id"], st.Config["entra-operator-group-id"]}
} else {
        allow.Emails = operatorEmails // --access-allow-email, required in this case
}

plan, err := p.PlanAccess(allow)         // contacts nothing; journal it first
app, pol, err := p.ApplyAccess(ctx, plan)

// Verification compares what Cloudflare stored with what this deployment applied,
// so it needs the same allow-list and the tenant its groups live in.
v, err := p.VerifyAccess(ctx, app.ID, cloudflare.AccessExpectation{
        Allow:         allow,
        EntraTenantID: st.Config["entra-tenant-id"],
})
```

**Stack gap the parent must close:** issue #6's `entra-signin` phase records the group
object IDs as `state` resources but does not put them in `Config`. Add
`Config["entra-admin-group-id"]` and `Config["entra-operator-group-id"]` there (from
`res.Groups[i].ObjectID`), or read them back out of the resource journal. Without the
object IDs the allow-list falls back to emails for no good reason.

## Preflight

`cf.PreflightAccess(ctx, accountID)` proves the **read** permissions only:

| Endpoint | Proves |
|---|---|
| `GET /accounts/{acct}/access/organizations` | Access: Organizations, Identity Providers, and Groups: Read — **and** that a Zero Trust organization (team domain) exists at all |
| `GET /accounts/{acct}/access/identity_providers` | the same permission, and supplies the provider list |
| `GET /accounts/{acct}/access/apps?per_page=1` | Access: Apps and Policies: Read |

Cloudflare grants apps and policies under one permission, so there is no separate
policy read check. The **mutation** permission (Access: Apps and Policies: Edit) has
no read-only proof — no dry run exists and a probe write would create a real Access
application. The first `ApplyAccess` proves it, and a 403 there arrives as an
`*APIError` naming the endpoint. An account with no Zero Trust organization is
reported as that, not as a missing permission.

## Reconciliation, and the pre-existing case

`ApplyAccess` makes two reads before any write:

1. **Marker lookup** — `?name=<AccessAppName>&exact=true`. A match whose domain also
   covers the hostname is adopted: that is how a create whose response was lost is
   recovered instead of duplicated. A marker name on another domain, or more than one
   match, is `ErrRequiresReview`.
2. **Hostname lookup** — `?domain=<hostname>`, filtered to exact host matches. An
   application following this tool's naming convention with another deployment's ID is
   `ErrRequiresReview`. Any other is `*PreExistingApp`.

```go
var pre *cloudflare.PreExistingApp
if errors.As(err, &pre) {
        // pre.AppID / pre.Name / pre.Domain identify it.
        // pre.Changes is []FieldChange{Field, Original, Applied} — the same shape as
        // internal/entra's — ready for state.SettingChange entries.
}
```

`*PreExistingApp` unwraps to `ErrPreExisting`, so `errors.Is` still works. **This
package has no path that changes an application it does not own.** The original values
are recorded so that an operator's manual change is auditable; the tool itself stops.
Guided: show the application and ask the operator to remove it, rename it, or choose
another hostname. Unattended: nonzero exit.

The policy is reconciled the same way, by its marker name under the adopted
application. Between the two creates the application exists with no policy, which
Access treats as deny-all — a lost response never leaves the hostname open.

## What to record in state

```go
st.EnsureResource(state.Resource{Provider: "cloudflare", Type: "access-app",
        ProviderID: app.ID, Name: app.Name, CorrelationID: corrID,
        Ownership: "deployment ID in the application name, verified together with its domain",
        CreatedAt: now})
```

Store `Config["cloudflare-access-app-id"] = app.ID`. Record the policy as **evidence
on that resource** (`pol.ID`, `pol.Name`, `len(pol.Include)`), not as a resource of its
own: it is scoped to the application and has no independent lifecycle. Also journal the
verification evidence from `VerifyAccess` — `AppID`, `Domain`, `AUD`, `PolicyID`,
`AllowRules`, `IdPID`, `AuthDomain`, `Challenge`, the four `*Verified` booleans, and
`v.String()`. None of it is secret.

## Verification

**Change the parent must wire.** `VerifyAccess` now takes the expectation shown in the
phase flow above:

```go
v, err := p.VerifyAccess(ctx, app.ID, cloudflare.AccessExpectation{
        Allow:         allow,                          // the same Allow given to PlanAccess
        EntraTenantID: st.Config["entra-tenant-id"],    // required when Allow.Groups is set
})
```

The argument is variadic only so that an unwired caller still compiles. Without it the
stored allow-list is never compared with the applied one, `v.PolicyMatchesAllowList`
and `v.IdPBoundToTenant` stay false, and `v.String()` says so. Pass it.

`VerifyAccess` proves four separate things, and `AccessVerification` keeps them
separate so evidence for one is never read as evidence for another:

| Field | What it means |
|---|---|
| `AppVerified` | the application read back carries this deployment's marker, still covers the hostname, and has an audience tag (`AUD`) |
| `PolicyMatchesAllowList` | the application has **exactly one** policy, it is this deployment's, it decides `allow`, and its stored include rules are exactly the rules that were applied |
| `IdPBoundToTenant` | the identity provider those group rules name is the account's `azureAD` provider for `Config["entra-tenant-id"]`, read back from the API. False for the email fallback, which has no binding |
| `ChallengeVerified` | an anonymous request was redirected to **this application's own** Access login |

The challenge check is exact, not a suffix match. The redirect must go to the team
domain from the organization read, to the path `/cdn-cgi/access/login/<hostname>`, with
`kid` equal to the application's own AUD, and its `meta` JWT must describe this
hostname, this audience and `auth_status` `NONE`. The meta token's **signature is not
verified and cannot be** — the probe is anonymous — so it is read as a description of
the redirect and never as identity. A redirect to another Access application, which a
bare `.cloudflareaccess.com` suffix match accepted, now fails.

The probe sends no `Authorization` header — it must look exactly like an anonymous
visitor's request. It keeps honouring a configured proxy and full TLS verification, and
still resolves through the zone's authoritative nameservers when the host's own
resolver cannot see the zone. It works before the origin certificate exists (issue #9),
because Access challenges the request before it is ever routed to the origin.

**None of this is a sign-in.** A reachable login page proves configuration and
enforcement, not that an allowed operator can get in or that a denied one cannot.
`v.String()` ends with `cloudflare.SignInNotProven`, and the phase output must not
claim more than that — say `u.Say("%s", v.String())` rather than composing a sentence
of the parent's own. Demonstrating an allowed and a denied user login is a separate,
manual acceptance step.

A transport failure ("could not reach ...") is a timing problem — DNS or the tunnel is
not up yet — and re-running the phase is the fix. "answered HTTP 200 with no Access
challenge" is a security failure and must stop the run. So is `ErrAllowsEveryone`.

## Teardown

`p.DeleteAccessApp(ctx, appID)` re-fetches the application and verifies **both** halves
of the marker — the name carries this deployment's ID, and the application still
secures this deployment's hostname — before deleting. Anything else is `ErrNotOwned`:
report it and leave it. The policy is scoped to the application and is removed with it,
so there is nothing separate to delete. This package has no deletion for the zone or
for any other Access application, so unrelated applications are preserved structurally.

Order: stop the cloudflared container, delete the DNS record, **then** the Access
application, then the tunnel. Removing Access first would leave the hostname still
resolving to a running Guacamole with nothing in front of it.
