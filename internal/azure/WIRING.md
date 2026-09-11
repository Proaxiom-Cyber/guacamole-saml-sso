# Wiring internal/azure into the session

This package connects backups to Azure Blob storage. It signs in, selects an existing
subscription, storage account and container **or creates them when the administrator asks
for that**, checks three permissions separately, grants the unattended uploader its one
data role, and uploads published backups. It deletes nothing except its own marked blobs.

It imports `internal/backup` (the published-completion contract), `internal/schedule` (the
valid-backup listing) and `internal/recording` (where recording copies live), and nothing
else from the deployment. The parent wires it into the phase registry, the status command,
and a timer. Nothing under `internal/session`, `internal/stack`, `internal/host`,
`internal/creds`, `internal/backup`, `internal/schedule`, `internal/recording`,
`internal/certs`, `internal/settings`, `internal/entra`, `internal/cloudflare`,
`internal/teardown`, or `cmd/guacdeploy/main.go` was modified.

Files: `internal/azure/{azure.go,auth.go,blob.go,check.go,upload.go}` (issue #17),
`internal/azure/{create.go,role.go}` (issue #18), `cmd/guacdeploy/azure.go`.

## The two slices

Issue #17 is **using storage that already exists**: `Resolve` selects it and fails, naming
what does exist, when it is not there. Issue #18 is **creating it**: `PlanCreate` /
`ApplyCreate`, plus the role assignment the unattended uploader needs. Both end with the
same `Destination`, and everything after selection — permission checks, upload,
completeness, retrieval — is shared.

The management plane is reached through exactly two helpers: `armGet`, which only reads,
and `armPut`, which only writes with PUT. There is no third.
`TestNoContainerOrAccountDeletionPathExists` fails if a function reaches ARM any other way,
or if a second DELETE appears anywhere in the package. Adding `armPut` widened that test's
allow-list by one name, deliberately and visibly, which is what the test is for.

## The decisions the parent should know about

### 1. Unattended authentication: a service principal with a client secret

The specification says "Scheduled uploads require unattended authentication independent of
the administrator's interactive session. The precise credential mechanism remains an
implementation decision." Three candidates:

| Mechanism | Verdict |
|---|---|
| Managed identity | **Not available.** This host runs on Proxmox, not in Azure. There is no instance metadata endpoint. A deployment built on it would stop backing up the first night. |
| The administrator's refresh token, kept on the host | **Rejected.** It *is* the administrator's session: it dies on a password change, on account disablement, on a Conditional Access policy, or after 90 days unused, and every upload runs as a person rather than as the deployment. That is exactly the dependency the specification forbids. |
| Service principal + client secret, stored through the deployment's credential mode | **Chosen.** |

What it costs, stated plainly:

- The secret is a bearer credential on the host. It is only as protected as the selected
  credential mode, and owner-only plaintext is one of the approved modes.
- It expires on the application registration's schedule (Entra's default is 6 to 24
  months) and **nothing here renews it**. An unrotated secret eventually stops the
  scheduled upload. The status report shows the last result; the operator guide has to say
  to rotate it.
- A certificate credential would be better — no shared secret, and it could be TPM-bound —
  and is the upgrade path. It needs certificate plumbing this slice does not have.

The principal needs **one** role: `Storage Blob Data Contributor`, on the container. It
needs no management-plane role at all, because the account's ARM resource ID and blob
endpoint are recorded in deployment state at selection time. The unattended identity is
therefore narrower than the administrator's.

The guided path is separate: `App.StartSignIn` / `App.CompleteSignIn` run the device-code
flow, and the resulting `Session` covers both planes from one code entry (the sign-in asks
for `offline_access`, and the refresh token is redeemed for the storage scope). It is
in-memory only and is never persisted.

### 2. Upload completeness: verify-then-manifest

Azure Blob storage has **no rename**, so the local "temporary name, then commit" shape is
not available. The remote guarantee is the same completion contract `internal/backup`
already defines, applied remotely, in this order:

1. The local file is verified against its local manifest (`backup.VerifyPublished`). An
   unfinished or foreign local export is never uploaded at all.
2. The blob is written with `Content-MD5`. The service compares the body it received
   against that hash and rejects a mismatch with 400, so a truncated body never becomes a
   blob.
3. The blob is read back with Get Blob Properties and its **length** and `Content-MD5` are
   compared with the local manifest. A blob that arrives short fails here — including when
   the service returns no `Content-MD5`, which is why the length check is separate and has
   its own test.
4. **Only then** is the completion manifest blob written, carrying exactly the local
   manifest bytes.

`RemoteComplete` counts a remote copy as complete only when step 4's manifest exists and
matches the local one. A failure at any earlier step leaves a blob with no manifest: never
counted, never deleted, exactly like the local orphan `internal/backup` can leave, and safe
for the same reason.

### 3. Creating storage: what carries the ownership marker

The specification wants a deployment ownership marker "where supported". Each resource
supports something different, and the difference is not cosmetic — it decides what can be
reconciled after a lost response.

| Resource | Marker | Verified |
|---|---|---|
| Resource group | resource **tag** `guacdeploy_deployment` | Yes. Tags are set in the create request and read back from the group. |
| Storage account | resource **tag** `guacdeploy_deployment` | Yes. Same, and the account list returns tags, so the query is one call. |
| Blob container | **`properties.metadata`** `guacdeploy_deployment` | Yes, and it is **not** a tag: an ARM blob container is a proxy resource with no `tags` property at all. `metadata` is the only key-value store it has. |
| Blob | `x-ms-meta-guacdeploy_deployment` | Yes (issue #17, unchanged). |
| Role assignment | **nothing** | No tag, no metadata, no description. See below. |

One key name everywhere, because blob metadata names must be valid C# identifiers,
container metadata has the same rule, and tag names allow that spelling too.

**A role assignment cannot carry a marker.** Its ownership evidence is instead its
*deterministic name*: a GUID derived from the scope, the principal and the role definition.
The same three inputs always address the same assignment, so a retry after a lost response
writes to the same resource ID and cannot make a second one, and Azure's
409 `RoleAssignmentExists` is reported as "already in place" rather than as a failure.

**There is no "after an uncertain create" mode**, and that is deliberate. Every marker is
written in the *same request* that creates the resource, so anything this deployment
created carries one. A name-only match is therefore never this deployment's half-landed
creation — it is somebody else's resource — and the answer is `ErrRequiresReview` either
way, before or after a lost response. (`internal/entra` needs its `AfterUncertainCreate`
flag because Graph cannot do this; ARM can.)

### 4. Naming

| Resource | Candidate | Why |
|---|---|---|
| Storage account | `gd` + up to 14 characters of the hostname's letters and digits + 8 hex of SHA-256 over the deployment ID, e.g. `gdguacexamplecoma5c6c1a1` | Account names are 3–24 characters, lowercase letters and digits only, and **globally unique across every tenant**. A hostname cannot be used as it stands. The suffix makes a collision with another deployment implausible; it cannot make one with a stranger's account impossible, which is why `ErrNameTaken` exists. |
| Resource group | `guacdeploy-<hostname with dots as hyphens>` | Resource group names allow 90 characters of letters, digits and `-._()`. |
| Container | `guacdeploy` | Matches the blob prefix already written under. |

Every one of them is deterministic from the deployment, which is what makes a retry hit
the same resource. The operator can supply any of them instead; supplied names are
validated against Azure's rules with the rule named in the error, not "invalid name".

**A globally taken account name is not an ownership conflict.** `ErrNameTaken` means the
name is in use somewhere in Azure, possibly in another tenant, and says nothing about who
holds it. `ErrRequiresReview` means a resource *in this subscription* matches by name and
carries no marker. They have different fixes and are never merged.

## API surface for the parent

```go
// Sign in (guided).
app := azure.App{TenantID: tenant}            // ClientID defaults to the Azure CLI public client
dc, err := app.StartSignIn(ctx)               // show dc.UserCode and dc.VerificationURL
sess, err := app.CompleteSignIn(ctx, dc)      // polls; handles authorization_pending / slow_down
c := &azure.Client{Token: sess.TokenSource()}

// Sign in (unattended, for the timer).
p := &azure.ServicePrincipal{
        App:    azure.App{TenantID: tenant, ClientID: appID},
        Secret: func() (string, error) { return m.Get(spec) },   // fetched at point of use
}
c := &azure.Client{Token: p.TokenSource()}

// Select existing storage. Never creates.
subs, err := c.Subscriptions(ctx)                                 // []Subscription
accounts, err := c.StorageAccounts(ctx, subscriptionID)           // []StorageAccount
names, err := c.Containers(ctx, account.ID)                       // []string
d, err := c.Resolve(ctx, subscriptionID, account, container)      // Destination

// Three separate permission checks, against storage that exists.
pre, err := c.CheckPermissions(ctx, d, st.DeploymentID)
pre.Management / pre.BlobData / pre.RoleAssignment   // each {OK, Detail, Fix, Pending}
pre.OK()    // management && blob data; role assignment is advisory
pre.Err()   // first blocking failure, with the role that fixes it
pre.Summary()

// Create storage instead (issue #18).
cfg := azure.CreateConfig{
        SubscriptionID: subID,
        Location:       "australiaeast",        // required; nothing is guessed
        DeploymentID:   st.DeploymentID,        // the marker's value
        Hostname:       st.Hostname,            // only for deriving readable names
        // ResourceGroup / Account / Container are derived when empty.
        // ApproveExistingResourceGroup allows reuse of one that already exists.
}
plan, err := c.PlanCreate(ctx, cfg)     // queries by marker, then by name; creates nothing
plan.Summary()                          // subscription + every proposed resource, to show
plan.Creations                          // []Creation{Type, Name} — JOURNAL THIS FIRST
plan.NeedsApproval()                    // a pre-existing resource group is in the plan

checks, err := c.CheckCreatePermissions(ctx, plan)
checks.Management / checks.RoleAssignment / checks.BlobData
checks.OK()      // only the management check blocks creation
checks.Err()     // the blocking failure, with the role that fixes it
checks.Summary()

d, err := c.ApplyCreate(ctx, plan)      // Destination, same shape as Resolve returns

// Grant the unattended uploader its one role, then prove it works.
ra, err := c.AssignUploaderRole(ctx, d, servicePrincipalObjectID)  // idempotent
k := azure.WaitRoleEffective(ctx, uploaderClient, d, st.DeploymentID, azure.RoleWait{})

// Upload and status.
rep, err := azure.Upload(ctx, c, azure.Options{...})
azure.Summary(stateDir)                                            // destination + last result
c.RemoteComplete(ctx, d, dir, name, deploymentID, azure.AreaDatabase) // retrieval proof
c.DeleteOwnedBlob(ctx, d, blobName, deploymentID)                  // marker-verified, prefix-scoped
```

`azure.Destination` holds only non-secret references and is safe in deployment state and in
the status file.

## Phase placement

One new phase, `azure-destination`, during configuration (specification step 3–5) and
before the backup schedule is installed, because the schedule's destination and the Azure
destination are recorded together. It is skipped entirely when the administrator does not
choose Azure: it is an optional destination alongside local directories and mounted shares.

The phase does, in order:

1. Device-code sign-in (`StartSignIn`, show the code, `CompleteSignIn`).
2. `Subscriptions` → let the administrator choose. Then **reuse or create**:

   **Reuse.** `StorageAccounts` → choose; `Containers` → choose; `Resolve`. Listings of
   what exists; nothing is created. A missing account or container fails with the list of
   what does exist.

   **Create.** `PlanCreate`, show `plan.Summary()` — that is the "show subscription and
   proposed resources before creation" step, and it is the whole of it. Then, in this
   order and no other:
   1. **Journal `plan.Creations` with a correlation identifier** (`state.Action` with
      `Intent` and `CorrelationID`, `ResultUncertain` if the response is lost). Nothing is
      sent to Azure before this is on disk.
   2. If `plan.NeedsApproval()`, ask. `ApplyCreate` refuses with `ErrApprovalRequired`
      until `cfg.ApproveExistingResourceGroup` is set. A pre-existing resource group is
      reused, never written to and never tagged.
   3. `CheckCreatePermissions` and show `Summary()`. `checks.Err()` is the stop condition.
   4. `ApplyCreate`. On any error, journal the action `ResultUncertain` and stop; the next
      run's `PlanCreate` reconciles by marker.
   5. Record each created resource in `state.Resource` with `Provider: "azure"`, the
      correlation identifier, and ownership evidence
      (`"tag guacdeploy_deployment=<id>"`, or `"container metadata ..."`).
3. `CheckPermissions`, and show `Summary()`. `pre.Err()` is the stop condition; a failed
   role-assignment check is shown but does not stop setup.
4. Grant the unattended uploader its role: `AssignUploaderRole` with the service
   principal's **object ID** (the enterprise application's object ID, not the application
   ID), then `WaitRoleEffective` with a client signed in **as that principal**. A role
   assignment is eventually consistent, so this polls a real write rather than assuming.
   If it never lands, show the Check: setup is otherwise complete and the nightly upload
   will fail until the role takes effect.
5. Record the destination in state, and register the client secret credential (below).

## Credential registration

The parent adds one spec to its credential registry (`internal/creds` is not modified by
this slice; the parent owns `creds.Required`):

```go
{Name: azure.ClientSecretCredential, Purpose: "unattended Azure Blob uploads"}
```

`prompt` mode cannot support the scheduled upload — `creds.Explain` already says so — so
selecting Azure with prompt-mode credentials must be refused at configuration time with
that reason, not discovered at 2am by a failing timer.

## State keys

Non-secret references only, as usual. The constants live in `cmd/guacdeploy/azure.go`.

| Key | Value |
|---|---|
| `azure-subscription-id` | selected subscription |
| `azure-resource-group` | from the account's own resource ID, never guessed from a name |
| `azure-account` | storage account name as Azure returned it |
| `azure-container` | container name as Azure returned it |
| `azure-account-id` | full ARM resource ID of the account |
| `azure-blob-endpoint` | the account's blob endpoint, taken from Azure (sovereign clouds differ) |
| `azure-tenant-id` | directory the unattended principal signs in to |
| `azure-client-id` | the unattended application's client ID |
| `azure-upload-schedule` | `OnCalendar` expression actually installed |
| `azure-location` | region the storage was created in (creation path only) |
| `azure-role-assignment` | the uploader's role assignment name, a GUID (creation path only) |

The client secret is **not** here. It goes to the credential store under
`azure.ClientSecretCredential`.

## Created resources

On the reuse path, none: the container and the storage account are pre-existing resources
the deployment *uses*.

On the creation path, record one `state.Resource` per resource **actually created** —
`plan.Creations` says which, and a resource the plan found already present is not one of
them:

| `Type` | `ProviderID` | `Ownership` |
|---|---|---|
| `resource-group` | the group's ARM resource ID | `tag guacdeploy_deployment=<deployment id>` |
| `storage-account` | the account's ARM resource ID | `tag guacdeploy_deployment=<deployment id>` |
| `blob-container` | the container's ARM resource ID | `container metadata guacdeploy_deployment=<deployment id>` |
| `role-assignment` | the assignment's ARM resource ID | `deterministic name from scope, principal and role` |

Recording them is for the action summary and for the record of what this deployment did.
**It does not make them eligible for deletion** — see Teardown.

If the parent later wires the timer, record the unit paths exactly as
`internal/schedule/WIRING.md` describes.

## Flags and dispatch for main.go

```
  --azure-subscription ID   existing subscription for backup uploads
  --azure-account NAME      existing storage account
  --azure-container NAME    existing container
  --azure-tenant ID         directory for unattended sign-in
  --azure-client-id ID      application (client) ID for unattended sign-in
  --no-azure                do not offer an Azure destination

  --azure-create            create the storage instead of reusing existing storage
  --azure-location REGION   region for created storage, e.g. australiaeast (required
                            with --azure-create; there is no default)
  --azure-resource-group N  resource group to create or reuse (derived when absent)
  --azure-approve-existing-group
                            approve reuse of a resource group that already exists
```

`--azure-account` and `--azure-container` name the resource to create when
`--azure-create` is given, and the resource to select when it is not. Unattended runs that
would need approval must stop, not assume it: `plan.NeedsApproval()` without
`--azure-approve-existing-group` is a refusal, which is specification A8.

```go
case "azure-upload":
        err = azureUploadCmd(ctx, *stateDir, *dest, u)
case "azure-status":
        err = azureStatusCmd(*stateDir, u)
```

Both live in `cmd/guacdeploy/azure.go`. The exit-code mapping needs no change: a failed
upload returns a plain error and exits 1.

`azure-upload` takes `--dest` with no default, for the same reason `backup-run` does: it
copies **from** the local published destination, and a silent fallback is what the
specification forbids.

## Scheduling the upload

The upload copies already-published local files, so it must run **after** the backup and
the recording run. Two ways, both fine:

- Add `azure-upload` to the existing backup timer's service as a second `ExecStart=` line
  (systemd runs them in order, and the unit is `Type=oneshot`). This is the recommended
  one: it cannot run before the backup it is meant to upload.
- Install a separate timer at a later hour, the same way `schedule.Install` does.

Either way the installed routine calls the deployment-owned runtime copy of the binary
(`/usr/local/lib/guacdeploy/guacdeploy`), not the provisioning binary — see
`internal/schedule/WIRING.md`. This package needs nothing else from the provisioning run:
the destination comes from state and the credential from the credential store.

## Teardown

**Do nothing.** There is no teardown call here on purpose, and there is no account or
container deletion path to call.

"Preserve remote backups and their supporting storage resources during ordinary teardown"
(specification, "Azure Blob destination"). **This holds for storage this tool created.**
A container this deployment created is exactly the case the specification says to preserve,
because it holds the backups — "Preserve database data, recordings, and backups by default.
Permanent deletion needs explicit intent" (Teardown contract). Ordinary teardown makes no
call to Azure at all. It may drop the state keys and the credential; the resource group,
the storage account, the container and the blobs stay.

That is why the created resources are recorded as history rather than as deletion
candidates, and why `TestNoContainerOrAccountDeletionPathExists` checks the source for
`deleteContainer`, `deleteAccount`, `deleteStorageAccount` and `deleteResourceGroup` as
well as for a second DELETE. If a later slice is asked for permanent deletion with explicit
intent, it belongs behind its own approval, in its own review — not here.

If a future slice needs to remove blobs, the safe primitive is `DeleteOwnedBlob`: it
refuses anything outside this deployment's prefix, reads the ownership marker back from the
service, and refuses anything that does not carry this deployment's ID. Remote retention by
age is issue #20 and is not implemented here.

## Status output

`session.Status` should append the last upload record. It is a separate file,
`<state-dir>/azure-status.json` (0600), beside `backup-status.json` and
`recording-status.json`, for the same reason: the deployment record is the parent's schema
and a nightly timer must not churn it.

```go
u.Say("%s", azure.Summary(stateDir))
```

It prints "No Azure upload has run yet." when the file is absent, so it is safe to call
unconditionally. It shows the destination, the object prefix, which application signed in
and how, the last run and result, and database and recording counts **separately**.

## Behaviour the parent must not undo

- **`Resolve` never creates.** It fails when the account or container is missing, naming
  what does exist. Creation is the separate, explicitly chosen `PlanCreate` /
  `ApplyCreate` path. Do not make the reuse path fall back to creating.
- **Intent is journalled before `ApplyCreate`, never after.** `plan.Creations` on disk with
  a correlation identifier is what makes a lost response recoverable.
- **Nothing deletes a container, a storage account or a resource group.** There is no such
  code path, a test enforces it, and teardown is "do nothing" even for storage this tool
  created — it holds the backups.
- **A name match is never ownership.** `ErrRequiresReview` is for a person, not for a
  retry. Do not "resolve" it by creating a second resource with a different name, and do
  not adopt the match.
- **The uploader gets one role, on the container.** Not on the account, not on the
  subscription, and not Storage Blob Data Owner.
- **The role is proved, not assumed.** `WaitRoleEffective` needs a client signed in as the
  service principal. Passing `nil` returns a check that says it was not verified; do not
  treat that as a pass.
- **The three permission checks stay separate and all three always run.** An operator who
  can see the account but cannot write blobs is told exactly that, with the role name. Do
  not collapse them into one "access denied".
- **The completion manifest is written last.** Never write it before the read-back check;
  a blob with a manifest is counted as a complete backup.
- **Database and recording results stay apart.** Never merge the two `Outcome` values.
- **Blob names stay under `guacdeploy/<deployment-id>/`** and every object carries the
  `guacdeploy_deployment` metadata marker. Retention, scoping and deletion all depend on
  both.
- **No token, refresh token or client secret is logged, returned in an error, stored in a
  serialisable field, or written to the status file.** `Session` and `DeviceCode` have
  `String` methods for exactly this reason: `fmt` prints unexported fields, so a struct
  holding a credential needs its own renderer. Tests fail if any of it leaks.

## Service versions targeted

| Plane | Version |
|---|---|
| Blob REST (`x-ms-version` on every data-plane request) | **2021-08-06** |
| Subscriptions - List, Subscriptions - Get | `2022-12-01` |
| Storage Accounts - List / Get / **Create**, Blob Containers - List / **Create** | `2023-05-01` |
| Permissions - List For Resource and For Resource Group | `2022-04-01` |
| Role Assignments - **Create** | `2022-04-01` |
| Resource Groups - Get / List / **Create Or Update** | `2021-04-01` |

The created storage account is `StorageV2`, `Standard_LRS`, hot tier, HTTPS only, TLS 1.2
floor, `allowBlobPublicAccess: false` and **`allowSharedKeyAccess: false`**. The last one
matters: everything here authenticates with Entra tokens and never uses an account key, so
leaving key access on would leave a second, stronger credential lying about that nothing
needs. Retrieval tooling must therefore use Entra sign-in (`az storage blob download
--auth-mode login`), not an account key. The container is created with
`publicAccess: None`.

## Known limits

- **One Put Blob per file, capped at 256 MiB.** A larger file fails with a message naming
  the ceiling rather than uploading partially. A database export is a few megabytes; a very
  long recording is the case that would hit it. Upgrade path: Put Block + Put Block List,
  whose uncommitted blocks are invisible until the block list is committed, keeping the same
  completeness guarantee.
- **Blob listing does not follow continuation markers.** The two callers (a permission
  probe and a "what is already there" lookup) do not need the whole container. Issue #20
  will need paging.
- **The completion manifest is integrity evidence, not authentication.** Anything that can
  rewrite a blob can rewrite its manifest. It catches truncation, corruption and foreign
  objects, which is what retention needs. Signing is not V1.
- **The default guided client ID is the Azure CLI's public client.** It is pre-consented in
  every tenant for both planes, so a first sign-in needs no application registration. An
  organisation that wants its own audit trail or Conditional Access policy should register
  a public client with the device-code flow enabled and set `ClientID`. The unattended path
  never falls back to it: it refuses to sign in without an explicit tenant and client ID.
- **The right to create a resource group cannot be checked in advance.** Azure reports
  effective permissions for an existing resource or resource group only; there is no
  subscription-scope equivalent of Permissions - List. So when the resource group does not
  exist yet, the management check proves the subscription is readable, says plainly that
  the create right is proved by the creation itself, and names Contributor on the
  subscription as the fix. When the group does exist — including a reused one — the check
  is Azure's own answer for the two actions creation needs. The check is never reported as
  a pass that was not tested.
- **Storage account name availability is not probed before the create.** The
  `checkNameAvailability` API is a POST, and this package's management-plane surface is
  deliberately GET and PUT only. The PUT itself answers the question: 409 becomes
  `ErrNameTaken`, distinct from an ownership conflict, and nothing is overwritten, because
  an account that exists in this subscription is found by the query before any PUT is sent.
- **No pagination on the resource group or storage account lists.** A subscription with
  more than one page of storage accounts could hide this deployment's own account from the
  marker query and lead to a second create attempt, which the deterministic name would
  then turn into `ErrNameTaken` rather than a duplicate. Add `nextLink` following before
  that is likely.
- **Everything here is unit-tested against a fake HTTP seam.** No call has been made to a
  real Azure subscription. Live verification of sign-in, creation, role behaviour, upload
  and retrieval is still required before acceptance (A18, A19, A23).
