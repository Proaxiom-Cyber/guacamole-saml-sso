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
delivers it through the in-memory Compose override as `TUNNEL_TOKEN`. It must never
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
| `ErrRequiresReview` | name-only tunnel match | show and ask | nonzero exit |
| `ErrPreExisting` | foreign DNS record at hostname | show and ask | nonzero exit |
| `ErrNotOwned` | delete target lacks marker | report, keep resource | same |
| `*APIError` 403 on Apply | missing Edit scope | name the scope, stop | same |
