# Wiring internal/entra into the session

This package is self-contained: it touches no other internal package. The parent wires
it into `internal/session` as one phase. Everything below is what that phase does.

## Phase placement

Add an `entra-signin` phase after `stack-up` (before or after `stack-health`, parent's
choice). After a successful `Apply`, the phase must:

1. Set `st.Config["saml-metadata-url"] = result.MetadataURL` and
   `st.Config["entra-tenant-id"] = result.TenantID`.
2. Re-run `stack.Render` and `stack.Up` (both idempotent) so the compose template's
   SAML block renders and Guacamole restarts with SAML enabled. The template only
   emits the SAML block once `Config["saml-metadata-url"]` is non-empty.

**Stack gap the parent must close:** the rendered `.env` does not set
`SAML_GROUP_ATTRIBUTE`, so the compose default `groups` applies. Entra names the
claim `entra.GroupClaimAttribute`
(`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`). Until
`internal/stack` renders `SAML_GROUP_ATTRIBUTE=<that URI>`, group membership will not
reach Guacamole and nobody gets admin/operator permissions.

## Token (credential keys)

Construct the client with a `TokenSource`; the token never enters state, logs, or
errors.

- Unattended / lab: `entra.StaticTokenFromEnv(entra.DefaultTokenEnv)` reads
  `GUACDEPLOY_GRAPH_TOKEN` (the `GRAPH_TOKEN_CMD` analogue from the old setup.sh; on
  slq-guac-vm the memory notes describe supplying it).
- Guided: the parent supplies a device-code TokenSource (client ID
  `14d82eec-204b-4c2f-b7e8-296a70dab67e`, the Microsoft Graph Command Line Tools
  public client) — not part of this package.
- Required permissions: `entra.RequiredPermissions` (Application.ReadWrite.All,
  Group.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Organization.Read.All).

## Phase flow

```go
c := &entra.Client{Token: tokenSource} // Do: nil = real net/http
cfg := entra.Config{
    Hostname:      st.Config["guac-hostname"],
    DeploymentID:  st.DeploymentID,
    AdminGroup:    st.Config["admin-group"],
    OperatorGroup: st.Config["operator-group"],
    AfterUncertainCreate: resumingUncertain, // see reconciliation below
}

pf, err := c.CheckPermissions(ctx)      // read check is live; mutation check is
                                        // advisory from token claims (see doc)
plan, err := c.Plan(ctx, cfg)           // creates nothing
// 1. Journal intent: the phase Action already carries a CorrelationID; put
//    plan.Creations in its detail (or per-creation Actions) and Save BEFORE Apply.
// 2. Approval: if plan.App != nil && !plan.App.ProvenOurs, show plan.Changes and
//    require interactive approval; unattended -> ErrApprovalRequired.
res, err := c.Apply(ctx, plan)
entityID, err := c.VerifyMetadata(ctx, res.MetadataURL) // sign-in config evidence
```

## Error handling and reconciliation

- `errors.Is(err, entra.ErrUncertain)`: a creation request was sent and the response
  was lost. Journal the phase Action with `state.ResultUncertain`. On resume, run the
  phase again with `Config.AfterUncertainCreate = true`: `Plan` then queries by
  display name AND verifies the `guacdeploy:<deployment-id>` marker before any retry
  of creation, so the half-landed application is adopted instead of duplicated.
- `errors.Is(err, entra.ErrRequiresReview)`: a name match without the marker (or a
  non-unique match, or an application serving another entity ID). Stop and show the
  operator; never adopt, never create a duplicate. Unattended: nonzero exit.
- `errors.Is(err, entra.ErrNotOwned)` (cleanup only): the target lost or never had
  the marker; report it as retained, not removed.

## What to record in state

Created resources (provider `entra`), from `Result`:

- application: `ProviderID: res.App.ObjectID`, `Name: res.App.DisplayName`,
  `Ownership: res.App.Evidence` — record only when `res.App.CreatedApp` (or
  ProvenOurs adoption on resume); a reused pre-existing application is NOT recorded
  as a created resource.
- service principal: `ProviderID: res.App.SPObjectID` when `res.App.CreatedSP`.
- each `res.Groups[i]` with `Created == true`: `ProviderID: g.ObjectID`,
  `Ownership: g.Evidence`. Groups with `Created == false` are pre-existing: never
  record, never offer at teardown.

Changes to a pre-existing application: `res.Changes` is a list of
`{Field, Original, Applied}` ready for `state.SettingChange` entries (it is empty
when the application is ours). Journal each one.

Evidence of verification: record `entityID` from `VerifyMetadata` (the IdP's
`https://sts.windows.net/<tenant>/`) in the phase Action detail.

## Teardown

For each recorded `entra` resource, call `CleanupApp` / `CleanupGroup` with the
recorded ProviderID. Both re-fetch and verify the marker at deletion time and refuse
unmarked resources with `ErrNotOwned`. Deleting the application removes its service
principal and role assignments; do not call anything for the SP separately. Deletion
is Entra's standard soft delete (30-day deleted-items retention).

## Ownership marker (exact fields)

- Application: `notes` = `guacdeploy:<deployment-id>` and the same value in `tags`,
  both set in the creation request body itself (lost responses still leave a marked
  app). Pre-existing applications are never stamped.
- Group: `description` = the marker (groups have no notes/tags).
- Service principal: no marker; its `appId` links it to the marked application.

## Group claim choice

The SAML groups claim emits group display names (`cloud_displayname`), not object
IDs, because the local database authorises by the display names seeded at schema
time (`GUAC_ADMIN_GROUP` / `GUAC_OPERATOR_GROUP`). `groupMembershipClaims` is
`ApplicationGroup`: only the assigned groups are emitted, so the claim never hits
Entra's SAML groups-overage limit. `appRoleAssignmentRequired` is set true: only the
two assigned groups can sign in.

## Deliberately out of this slice (parent decisions pending)

- NameID claims-mapping policy (old setup.sh set NameID = `mailnickname` /
  `onpremisessamaccountname`). Without it users sign in with Entra's default
  persistent NameID: sign-in works, usernames are opaque. Adding it needs
  `Policy.ReadWrite.ApplicationConfiguration` and a policy-assignment dance.
- Device-code sign-in flow (a TokenSource the parent owns).
- The Cloudflare Access application registration (Cloudflare slice).
