# Wiring internal/azure into the session

This package connects backups to Azure Blob storage. It signs in, selects an existing
subscription, storage account and container **or creates them when the administrator asks
for that**, checks three permissions separately, grants the unattended uploader its one
data role, and uploads published backups. It deletes nothing except its own marked blobs.

It imports `internal/backup` (the published-completion contract), `internal/schedule` (the
valid-backup listing, the runner seam and the unit names it extends) and
`internal/recording` (where recording copies live and what the last local cleanup deleted),
and nothing else from the deployment. The parent wires it into the phase registry, the
status command, and a timer. Nothing under `internal/session`, `internal/stack`,
`internal/host`, `internal/creds`, `internal/backup`, `internal/schedule`,
`internal/recording`, `internal/certs`, `internal/settings`, `internal/entra`,
`internal/cloudflare`, `internal/teardown`, or `cmd/guacdeploy/main.go` was modified.

Files: `internal/azure/{azure.go,auth.go,blob.go,check.go,upload.go}` (issue #17),
`internal/azure/{create.go,role.go}` (issue #18), `internal/azure/unit.go` (issue #19),
`internal/azure/expire.go` and `internal/azure/prune.go` (issue #20),
`cmd/guacdeploy/azure.go`.

## The four slices

Issue #17 is **using storage that already exists**: `Resolve` selects it and fails, naming
what does exist, when it is not there. Issue #18 is **creating it**: `PlanCreate` /
`ApplyCreate`, plus the role assignment the unattended uploader needs. Both end with the
same `Destination`, and everything after selection — permission checks, upload,
completeness, retrieval — is shared.

Issue #19 is **running the upload on the backup timer**, unattended: `InstallUpload` adds
one drop-in to the scheduled backup's service, and `Upload` is the run it starts. Issue #20
is **remote retention**, which is two separate rules that never touch each other's objects:
`Expire` removes recordings by **age**, and `PruneBackups` keeps the last seven successful
database backups by **count**.

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

### 4. The scheduled run extends the backup timer instead of adding its own (issue #19)

The upload copies files the scheduled database backup has just published. A timer of its
own would have to be set to a later hour and *hope* the backup had finished. So
`InstallUpload` writes one systemd drop-in,
`/etc/systemd/system/guacdeploy-backup.service.d/10-azure-upload.conf`, adding a second
`ExecStart=` to that service. The service is `Type=oneshot`, which runs its `ExecStart`
lines one after another in order, and a drop-in appends to that list. The upload therefore
runs on the same timer as the backup and always after it.

`internal/schedule` is not modified: a drop-in is systemd's own mechanism for extending a
unit somebody else owns, and `UninstallUpload` removes only the drop-in, never the service.
Both files carry the same `# guacdeploy deployment=<id>` first line the other units use, and
neither is removed unless that line matches.

**What this costs, stated plainly.** systemd stops a `oneshot` service at the first
`ExecStart` that fails, so a night when the *database backup* fails is also a night when
nothing is uploaded. That is the specified behaviour rather than a new hazard — the local
recording budget deletes on its own hourly timer either way, and any resulting loss is
reported (see below) — but an operator whose database backup has been failing for a week
should run `guacdeploy azure-upload --dest <dest>` by hand. If that trade ever stops being
acceptable, the change is a separate timer ordered `After=guacdeploy-backup.service`, not a
change to the completion contract.

The upload needs nothing from the provisioning run: the command line carries only
`--state-dir` and `--dest`, the destination comes from deployment state, the retention
period comes from deployment state, and the client secret is read from the credential store
at the point of use. **No credential is ever on the command line, in the unit, or in an
environment file**, and a test fails if one appears.

### 5. Remote recording retention deletes by blob age, and only after a complete upload (issue #20)

`Expire` lists **only** `guacdeploy/<deployment-id>/recordings/`. A database backup is not
filtered out, it is never seen: database backups keep the separate default of seven
successful backups and the recording age rule is not applied to them (specification,
"Remote recording retention"). Every deletion then goes through `DeleteOwnedBlob`, which
refuses a name outside this deployment's prefix and reads the `guacdeploy_deployment`
marker back from the service first. An object whose ownership cannot be verified is left in
place and reported in `NotOwned`, never deleted.

Three decisions inside it are worth knowing:

- **Age is the service's `Last-Modified`**, so it is how long the copy has been *in Azure*,
  not when the session happened. A copy exactly at the boundary is kept; only a copy
  strictly older goes. A copy whose age the service did not report is left in place and
  reported as a failure — an unknown age is not an expired recording.
- **The completion manifest is deleted first, then the recording.** Between the two the
  copy correctly stops counting as complete. The reverse order would leave a manifest
  describing a blob that is already gone. A failure between them leaves an orphan that no
  longer counts as a backup, and the next run removes it by age.
- **A local copy already older than the retention period is not uploaded** (`Outcome.
  PastRetention`). Published recording copies in the backup destination are never pruned,
  so without this the next run would re-send what expiry had just removed, give it today's
  `Last-Modified`, and the retention period would mean nothing. Database backups are never
  held back this way.

**A failed upload expires nothing.** `Upload` reaches `Expire` only when both the database
and the recording results are clean. The copies in the container are all that is left of a
recording the local budget has already deleted, and a run that could not prove what it holds
must not start removing things.

### 6. Remote database backup retention is a count, and it is a different rule (issue #20)

`PruneBackups` lists **only** `guacdeploy/<deployment-id>/db/` and keeps the last
`Keep` successful backups, default `schedule.DefaultKeep` (seven, the same constant local
retention uses, so the two cannot drift apart). A recording is not filtered out, it is never
seen. The two rules share nothing but the ownership primitive.

**This corrects a misreading.** "Preserve remote backups and their supporting storage
resources during ordinary **teardown**" is about teardown, and says nothing about ordinary
operation. The policy for ordinary operation is the specification's own: "retain the last
seven successful backups by default. Make schedule and retention configurable", and
"Database backups retain the separate default of seven successful backups". Reading the
teardown sentence as "remote database backups are kept for ever" is what let them
accumulate without limit.

| | Recordings (`Expire`) | Database backups (`PruneBackups`) |
|---|---|---|
| Prefix listed | `.../recordings/` | `.../db/` |
| Rule | age, in days, chosen by the administrator | count, default seven, configurable |
| Clock | the blob's `Last-Modified` in Azure | the completion manifest's `PublishedAt` |
| Below the minimum | `Days < 1` refused | `Keep < 1` refused; `Keep == 0` means the default |

**What counts as one of the seven.** Only a copy the run can prove is a complete backup of
this deployment, using the evidence `RemoteComplete` uses when the local file is gone: the
blob carries the `guacdeploy_deployment` marker, its completion manifest blob exists and
decodes, that manifest names this deployment and this file at the right manifest version,
and the blob's own length and `guacdeploy_sha256` metadata match it. The body is **not**
fetched back and re-hashed — `Content-MD5` does its work at the write, where Put Blob
rejects a mismatched body and `UploadPublished` reads the blob back before writing any
manifest, so a manifest exists only for a body the service already confirmed. Downloading
every backup every night would cost the whole container in transfer and prove nothing more.

**Why seven failed uploads cannot evict seven good backups.** An upload that stops between
the bytes and the manifest leaves a blob that is not a backup. It never enters the count, so
it can never push a real backup out of it. It is reported and left in place, and — unlike
the recording case — it does **not** fail the run: it is a fact about the container, and a
retention rule that suspends itself for ever after one half-finished upload is how remote
backups accumulate again.

**And an object the run could not check at all stops it removing anything.** A refused or
failed read means the count is unknown, and pruning on an unknown count is how good backups
disappear. `PruneReport.Withheld` says so, the run returns an error, and every older copy
survives. Same for a failed listing: nothing is removed.

**Ordering is the manifest's `PublishedAt`, not `Last-Modified`.** A catch-up upload of an
old backup must not count as the newest one, and `Last-Modified` is the recording rule's
clock, which this rule deliberately does not share. A manifest with no publication time
cannot be placed in order, so it is not counted and not removed.

**The completion manifest is deleted first, then the backup**, for the reason
`internal/backup` gives for writing it last: a manifest describing a blob that is already
gone would let a later blob landing on that name inherit completion evidence it never
earned. A failure between the two leaves an orphan that no run counts and the next run
reports.

### 7. Naming

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
rep, err := azure.Upload(ctx, c, azure.Options{
        Dest: dest, StateDir: stateDir, DeploymentID: st.DeploymentID, Destination: d,
        ClientID: appID, AuthMode: "service-principal",
        OnCalendar:    st.Config["azure-upload-schedule"],
        RetentionDays: days,   // 0 expires nothing; the administrator chooses it
})
rep.Database / rep.Recordings          // never merged; each {Uploaded, AlreadyThere, Failed, PastRetention}
rep.DeletedWithoutRemoteCopy           // recordings the local budget lost for good
rep.Expire                             // nil when the upload failed or no period is set
azure.Summary(stateDir)                                            // destination + last result
c.RemoteComplete(ctx, d, dir, name, deploymentID, azure.AreaDatabase) // retrieval proof
c.DeleteOwnedBlob(ctx, d, blobName, deploymentID)                  // marker-verified, prefix-scoped

// Remote recording retention on its own, for a manual run or a test.
er, err := azure.Expire(ctx, c, azure.ExpireOptions{
        Destination: d, DeploymentID: st.DeploymentID, Days: days})
er.Removed / er.Kept / er.NotOwned / er.Failed
er.Summary()

// Remote database backup retention: a count, not an age. Separate rule,
// separate prefix, separate report. NOTHING CALLS THIS YET — see below.
pr, err := azure.PruneBackups(ctx, c, azure.PruneOptions{
        Destination: d, DeploymentID: st.DeploymentID,
        Keep: keep})   // 0 means the default of seven; below 1 is refused
pr.Removed / pr.Kept / pr.NotOwned / pr.Failed
pr.Withheld                            // why the run removed nothing at all
pr.Summary()

// Make the backup timer upload as well. Install AFTER schedule.Install: it
// extends that service and refuses when it is not there.
in, err := azure.InstallUpload(ctx, azure.UnitOptions{
        Run: schedule.ExecRunner, DeploymentID: st.DeploymentID,
        StateDir: stateDir, Dest: st.Config["backup-dest"]})
in.DropInPath / in.ExecStart / in.Changed
removed, err := azure.UninstallUpload(ctx, azure.UnitOptions{
        Run: schedule.ExecRunner, DeploymentID: st.DeploymentID})
```

`azure.Destination` holds only non-secret references and is safe in deployment state and in
the status file.

### Wiring `PruneBackups` — the parent's three lines

`PruneBackups` is exposed and tested but **not yet called by anything**, so remote database
backups still accumulate until the parent wires it. It belongs beside `Expire` at the end of
`Upload`, under the same condition — a failed upload prunes nothing — in `upload.go`:

```go
        pr, err := PruneBackups(ctx, c, PruneOptions{Destination: o.Destination,
                DeploymentID: o.DeploymentID, Keep: o.KeepBackups, Now: o.Now})
        rep.Prune = &pr
        if err != nil {
                return o.fail(rep, err)
        }
```

with `KeepBackups int` added to `Options`, `Prune *PruneReport` added to `Report`, and
`rep.Prune.Summary()` appended in `Report.Summary()` beside `rep.Expire`'s. The value comes
from deployment state: add one key, `azure-backup-retention-count`, holding the same number
the local backup schedule keeps (`schedule.Options.Keep`), and pass zero when it is absent
so the specification's default of seven applies. Unlike the recording period, an absent
value must **not** mean "keep for ever" — that is the defect this closes.

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
   Also ask, in this phase, **how many days recordings are kept in Azure**, and record it
   as `azure-recording-retention-days`. There is no default: an absent value means nothing
   ever expires, which is a decision the administrator makes, not one this package guesses.
   Show the policy at the same time as the local recording budget, because the two are
   independent and an operator who confuses them will expect the wrong thing: the local
   budget deletes a recording whether or not its copy reached Azure, and remote retention
   deletes an Azure copy whether or not the local one is still there.
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
| `azure-upload-schedule` | `OnCalendar` expression actually installed (the backup timer's) |
| `azure-recording-retention-days` | days recordings are kept in Azure; absent means never expire |
| `azure-backup-retention-count` | successful database backups kept in Azure; absent means the default of seven, never "for ever" |
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

`InstallUpload` does it, and the parent calls it **after** `schedule.Install` — it extends
that service and refuses, naming the fix, when the backup schedule is not installed.

```go
in, err := azure.InstallUpload(ctx, azure.UnitOptions{
        Run:          schedule.ExecRunner,
        DeploymentID: st.DeploymentID,
        StateDir:     stateDir,
        Dest:         st.Config["backup-dest"],   // the same destination the backup publishes to
})
```

It writes one drop-in on the backup service and reloads systemd only when the file changed,
so a resumed or repeated setup does not churn. `UnitDir` and `RuntimeDir` stay zero in real
runs; tests inject them. The installed command is

```
/usr/local/sbin/guacdeploy-runtime azure-upload --state-dir <dir> --dest <dest>
```

— the deployment-owned runtime copy `internal/schedule` installs, not the provisioning
binary the operator may delete. That is what makes the schedule survive a reboot without the
provisioning binary. This package needs nothing else from the provisioning run: the
destination, the schedule and the retention period come from deployment state, and the
client secret from the credential store at the point of use.

Phase placement: immediately after the backup-schedule phase. Record the drop-in as one more
created resource, the same way that phase records its units:

```go
st.EnsureResource(state.Resource{Provider: "host", Type: "systemd-dropin", Name: in.DropInPath,
        CorrelationID: corrID,
        Ownership: "file written by this deployment, first line marks deployment ID",
        CreatedAt: time.Now().UTC()})
```

The recording timer is left alone. It runs hourly, publishes the local recording copies and
applies the storage budget; this run uploads whatever complete copies it finds. The two are
deliberately not chained — see the next section.

## Local recording retention and remote copies are independent, in both directions

This is the part that is easy to get wrong, and the specification states it twice.

- **The local storage budget deletes whether or not the upload succeeded.** "Upload success
  is not a condition for deletion. The local storage budget takes priority over preserving
  unbacked recordings" (specification, "Local recording retention"). `internal/recording`
  owns that and this package does not touch it: there is no call from here that could stop,
  delay or condition a local deletion, and none may be added.
- **The loss is reported, not prevented.** After uploading, `Upload` reads the last local
  cleanup record and names every recording it deleted that has no confirmed copy in the
  container, in `Report.DeletedWithoutRemoteCopy` and as a `LOST:` line in the summary.
  That is the whole of the coupling: read-only, after the fact, and it never fails the run.
- **An active recording cannot be uploaded**, structurally rather than by a check. This run
  copies only *published* recording copies, and `internal/recording` publishes a copy only
  for a recording no process still holds open. There is no path from a live session's file
  to a blob.
- **An in-progress upload is never reported as complete**, by the verify-then-manifest
  contract above. A recording being uploaded right now has no completion manifest in the
  container yet, so `RemoteComplete` says no, and the loss report treats it as unconfirmed.
- **Remote retention is not driven by the local budget, and the local budget is not driven
  by remote retention.** They use different clocks (the copy's age in Azure; the
  directory's size on disk) and neither consults the other.

Either way the installed routine calls the deployment-owned runtime copy of the binary
(`/usr/local/sbin/guacdeploy-runtime`), not the provisioning binary — see
`internal/schedule/WIRING.md`. This package needs nothing else from the provisioning run:
the destination comes from state and the credential from the credential store.

## Teardown

**Do nothing in Azure**, and remove the drop-in on the host.

```go
removed, err := azure.UninstallUpload(ctx, azure.UnitOptions{
        Run: schedule.ExecRunner, DeploymentID: st.DeploymentID})
```

It removes `.../guacdeploy-backup.service.d/10-azure-upload.conf` only when that file
carries this deployment's marker, leaves the backup service itself to
`schedule.Uninstall`, and is repeatable — a missing file is not an error. Drop the matching
`state.Resource` for the path in `removed` only.

There is no other teardown call here on purpose, and there is no account or
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
service, and refuses anything that does not carry this deployment's ID. Both retention rules
already go through it: `Expire` for recordings by age, `PruneBackups` for database backups
by count.

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
and how, the last run and result, database and recording counts **separately**, every
recording the local budget lost for good, and the remote retention result.

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
- **A failed upload expires nothing remote.** `Upload` reaches `Expire` only after both
  results are clean. Do not move the expiry call above the failure check, and do not add a
  second caller that runs it unconditionally.
- **The recording age rule never reaches a database backup, and the database count rule
  never reaches a recording.** Each lists only its own area. Widening either listing — "so
  we can expire old backups too", "so we can cap the number of recordings" — is how the
  seven successful database backups get silently deleted by an age rule that was never meant
  for them. Do not merge `Expire` and `PruneBackups`, and do not give them a shared listing.
- **A copy that cannot be proved complete is never one of the seven, and is never deleted.**
  That is the whole of why a run of failed uploads cannot evict good backups. Counting
  objects instead of verified backups reintroduces the failure directly.
- **A run that could not read the whole database prefix removes nothing.** `Withheld` says
  so. Do not "carry on with what we could read": the count would be wrong in the one
  direction that deletes things.
- **Local recording cleanup is never made conditional on an upload.** The budget wins, the
  loss is reported. Do not add a "skip deletion when the upload failed" path anywhere.
- **The retention period is asked for, never defaulted.** An absent
  `azure-recording-retention-days` expires nothing; a value below one day is refused.
- **The scheduled upload carries no credential on its command line.** The client secret is
  read from the credential store at the point of use. Do not pass it as a flag, an
  environment variable in the unit, or an `EnvironmentFile=`.
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
- **Retention follows continuation markers; the permission probe does not.** `listAll`
  walks every page, because an old recording hidden behind a marker would otherwise never
  expire and nothing would report it. `ListBlobs` is still one page, and its one caller
  needs a single object. A walk stops after 5000 pages rather than looping for ever on a
  repeated marker, and says so.
- **`PruneBackups` exists but nothing calls it yet.** Until the parent wires it (see
  "Wiring `PruneBackups`" above), remote database backups still accumulate without limit.
  The function, its report and its tests are here; the phase and command wiring is not.
- **Remote backup retention prunes nothing it cannot account for.** An orphan blob left by a
  half-finished upload is reported every run and removed by nothing, because no age rule
  applies to the database area and it is not a backup. It is cleared when the next
  successful upload of the same name rewrites it, or by hand. Growth from that residue is
  bounded by how often an upload fails between the bytes and the manifest.
- **A failed database backup also skips that night's upload**, because systemd stops a
  `oneshot` service at the first failing `ExecStart`. See decision 4 for the trade and the
  manual command.
- **`Last-Modified` is the retention clock.** Anything that rewrites a blob resets its age.
  Nothing in this tool rewrites a complete copy — a copy already in the container is
  skipped, not re-sent — but a person doing so by hand would extend its retention.
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
- **Everything here is unit-tested against a fake HTTP seam and a temporary filesystem.**
  **No live Azure run has ever happened in this project.** No call has been made to a real
  Azure subscription, no blob has been written to a real container, and no systemd unit has
  been loaded by systemd. Mocked tests are not acceptance. Live verification of sign-in,
  creation, role behaviour, upload, retrieval, the timer actually firing, expiry against
  real blob ages, and backup pruning against a real container is still required before
  acceptance (A18, A19, A20, A21, A23).
