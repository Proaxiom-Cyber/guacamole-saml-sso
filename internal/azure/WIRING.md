# Wiring internal/azure into the session

This package connects backups to Azure Blob storage **that already exists**. It signs in,
selects an existing subscription, storage account and container, checks three permissions
separately, and uploads published backups. It creates nothing in Azure and deletes nothing
except its own marked blobs.

It imports `internal/backup` (the published-completion contract), `internal/schedule` (the
valid-backup listing) and `internal/recording` (where recording copies live), and nothing
else from the deployment. The parent wires it into the phase registry, the status command,
and a timer. Nothing under `internal/session`, `internal/stack`, `internal/host`,
`internal/creds`, `internal/backup`, `internal/schedule`, `internal/recording`,
`internal/certs`, `internal/settings`, `internal/entra`, `internal/cloudflare`, or
`cmd/guacdeploy/main.go` was modified.

New files: `internal/azure/{azure.go,auth.go,blob.go,check.go,upload.go}`,
`cmd/guacdeploy/azure.go`.

## Scope: this is issue #17 only

Issue #17 is **connecting to storage that already exists**. Creating storage accounts and
containers through the wizard is **issue #18** and is deliberately absent here.

The seam for #18 is `armGet` in `azure.go`. It is the only management-plane helper, it
takes no method and no body, and every management call in this package goes through it. So
this package structurally cannot create or delete a management-plane resource, and
`TestNoContainerOrAccountDeletionPathExists` fails if a second one appears. Issue #18 adds
its own `armPut` (or similar) next to it, with its own review, its own intent journalling,
and its own ownership marker — and that test will need its allow-list widened by one name,
which is the point: adding creation has to be a deliberate, visible change.

## The two decisions the parent should know about

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

// Three separate permission checks.
pre, err := c.CheckPermissions(ctx, d, st.DeploymentID)
pre.Management / pre.BlobData / pre.RoleAssignment   // each {OK, Detail, Fix}
pre.OK()    // management && blob data; role assignment is advisory
pre.Err()   // first blocking failure, with the role that fixes it
pre.Summary()

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
2. `Subscriptions` → let the administrator choose; `StorageAccounts` → choose; `Containers`
   → choose. All three are listings of what exists. **Nothing is created.** If the account
   or container the administrator names is not there, `Resolve` fails with the list of what
   is, and setup stops rather than creating one — that is issue #18's job.
3. `CheckPermissions`, and show `Summary()`. `pre.Err()` is the stop condition; a failed
   role-assignment check is shown but does not stop setup.
4. Record the destination in state, and register the client secret credential (below).

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

The client secret is **not** here. It goes to the credential store under
`azure.ClientSecretCredential`.

## Created resources

None in Azure. This slice creates no Azure resource, so it records none. The container and
the storage account are pre-existing resources the deployment *uses*, which the teardown
contract requires to be preserved.

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
```

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

**Do nothing.** There is no teardown call here on purpose.

"Preserve remote backups and their supporting storage resources during ordinary teardown"
(specification, "Azure Blob destination"). The container and the storage account were not
created by this deployment, and the blobs are the administrator's backups. Teardown may
drop the state keys and the credential; it must not touch Azure.

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

- **Nothing is created in Azure.** `Resolve` fails when the account or container is
  missing, naming what does exist. Do not "helpfully" create one; that is issue #18.
- **Nothing deletes a container or a storage account.** There is no such code path, and a
  test enforces it.
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
| Subscriptions - List | `2022-12-01` |
| Storage Accounts - List, Blob Containers - List, Storage Accounts - Get | `2023-05-01` |
| Permissions - List For Resource | `2022-04-01` |

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
- **Everything here is unit-tested against a fake HTTP seam.** No call has been made to a
  real Azure subscription. Live verification of sign-in, role behaviour, upload and
  retrieval is still required before acceptance (A18, A19, A23).
