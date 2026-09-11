# Wiring internal/teardown into the command

`cmd/guacdeploy/teardown.go` holds the whole command. `main.go` needs one dispatch
line, one new flag, and the sentinels in the exit-3 branch. Nothing else changes.

## One line in main.go

```go
// with the other flags (--yes already exists, for restore; reuse it)
deleteData := fs.Bool("delete-data", false, "teardown: permanently delete the database, recordings and local backups")

// in the command switch
case "teardown":
        err = teardownCmd(ctx, *stateDir, *yes, *deleteData, u)

// in the exit-code switch, alongside session.ErrApprovalRequired,
// settings.ErrApprovalRequired and ui.ErrInputRequired
case errors.Is(err, teardown.ErrApprovalRequired), errors.Is(err, teardown.ErrReviewRequired):
        return 3
```

`teardown.ErrIncomplete` is deliberately **not** in the exit-3 branch. Residue is a
failure, not a request for approval, so it falls through to exit 1.

Add to `usage`:

```
  teardown Remove what this deployment created, after showing the plan

Flags for teardown:
  --yes                    Unattended consent to remove the resources in the plan
  --delete-data            Also permanently delete the database, recordings and local backups
```

Import `"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"`.

## Why two flags and not one

`--yes` is consent to the teardown. `--delete-data` is the separate, explicit intent
the specification requires before anything is destroyed permanently. Neither implies
the other, and neither overrides ambiguity: a recorded resource that cannot be shown
to be this deployment's own work stops the run with `ErrReviewRequired`, flags or no
flags.

On a terminal both are still confirmed, in two separate questions, because the plan
the operator is approving is the one they just read. Answering no to the second
question keeps the data and removes everything else.

## API surface

```go
func BuildPlan(*state.State, []settings.Entry, deleteData bool) Plan  // reads only
func (Plan) Report(*ui.UI)                                           // prints only
func Run(ctx, *state.State, Plan, Ops, *ui.UI, Options) (Result, error)

func HostUnits(ctx, HostOptions) (removed []string, err error)
func DefaultOps(HostOptions) Ops                  // the host half, ready to run
func RemoveRendered(ctx, dir) (leftover []string, err error)
func RemoveCredentials(ctx, dir string, names []string) (leftover []string, err error)
func RemoveTree(ctx, path) error

var ErrApprovalRequired, ErrReviewRequired, ErrIncomplete error
```

`Ops` is one function per step. A nil function is never a silent skip: the step is
reported as retained, saying no removal is implemented, and the run does not claim to
be complete. `cmd` fills the provider half (Cloudflare and Entra) and takes the host
half from `DefaultOps`.

## Order, and why each pair is in that order

`Plan.Connectors` first, then `Order`:

1. **Stop the cloudflared connector.** The tunnel then has no active connections when
   it is deleted. Best effort: a connector that is already gone is the state we
   wanted, so a failure here is reported as a note and removal continues, because
   `DeleteTunnel` deletes with `cascade=true` anyway.
2. **DNS record** — stops sending traffic at the tunnel.
3. **Access application** — the policy is scoped to it and goes with it. There is no
   separate policy delete, and `internal/cloudflare` has none to call.
4. **Tunnel.**
5. **Entra application** — its service principal and role assignments go with it.
   `CleanupApp` is the only call; the service principal is never deleted separately.
6. **Entra groups.**
7. **Host units** — one call, `HostUnits`, because the units share one binary copy.
   Inside it the order is `certs` → `recording` → `schedule`, and it is load-bearing:
   `schedule.Uninstall` deletes the shared binary unconditionally, and `certs` and
   `recording` deliberately leave it alone for exactly that reason. Backup last means
   no still-installed timer ever loses the binary it calls.
8. **Containers** — one `docker compose down`, before the rendered configuration, so
   the compose file it needs is still there.
9. **Credentials** — after the containers, which were started with them.
10. **Configuration directory** — the rendered files only.
11. **Data** — only with `--delete-data`.
12. **Host changes** — packages and service enablement, always preserved.

## What is never offered

- **Pre-existing resources.** They are not in the deployment record: `internal/session`
  records a group or an application only when it created it. There is nothing to
  filter, and nothing here goes looking at a provider for things to delete.
- **A recorded resource with no ownership evidence.** A matching name never
  establishes ownership, so it goes to review and stops the run.
- **A created resource that now supports unrelated use.** The specification's worked
  example is a created DNS zone holding unrelated records. **It cannot arise in this
  codebase**: nothing here creates a zone, and `internal/cloudflare` has no zone
  deletion at all — `DeleteRecord` removes one marked record from a zone it never
  touches otherwise. The same is true of the Access organisation and the Entra tenant.
  The general rule is implemented where it does apply: the installation directory and
  the credential directory lose the files this deployment wrote, and each directory
  itself is removed only when nothing else is left in it. An installed package and an
  enabled service are the same rule again, and are always kept.
- **Remote backups.** `internal/azure` has no teardown: blobs in the customer's own
  storage account are never removed, with or without `--delete-data`. The plan says so.

## Ownership is re-checked at deletion time

Every provider delete re-fetches its target and refuses with its own `ErrNotOwned`
unless the marker still proves the resource is this deployment's. `teardown.NotOwned`
recognises those sentinels, and such a refusal is reported as **retained** — never as
success, and never as a plain failure. The resource stays in the record.

## Retry

A failed or retained resource stays in `state.Resources`; a removed one is dropped and
the record is saved after every step. Running `teardown` again re-plans from what is
left and retries only that. Nothing is idempotency-sensitive: a missing systemd unit,
a missing directory and a missing credential file are all treated as already removed.

## Cleanup-first restart

`teardownCmd` deletes the state file once nothing is recorded any more, so setup starts
from clean. While anything is still recorded — kept data, an installed package, a
retained resource — the record is kept and `state.Store.Delete` refuses it, which is
what stops setup building a new deployment over a half-removed one.

**What the parent still owes issue #11 here:** `internal/session` has to act on that.
`session.Run` should refuse to start a *new* deployment while a record exists, and
offer teardown, rather than resuming into it. That is session's call and this package
does not make it.

## Two things this package does not do, deliberately

- **`creds.UninstallBoot`.** `internal/creds` has a boot unit and an uninstall for it,
  but `internal/session` installs no boot unit yet and records no resource for one, so
  there is nothing for teardown to find. When that lands, record it as a
  `host/systemd-unit` like the other three and add `creds.UninstallBoot` to
  `HostUnits`, **before** the `schedule` call: it shares the same binary copy and has
  its own `runtimeStillUsed` guard for exactly this reason.
- **Restoring settings unattended.** `settings.Restore` is called only on a terminal,
  because the contract says to prompt before restoring a pre-existing setting. An
  unattended run reports the pending restorations and counts them as outstanding, so
  the teardown is not reported complete. Drift is different: the current value was
  preserved, which is the correct outcome, so it is reported as a note and does not
  make the run incomplete.

The restore runs **before** any delete, because restoring a field needs the object
that carries it to still exist. In practice the two never collide — `res.Changes` is
non-empty only when the application was pre-existing, and a pre-existing application
is never recorded as a created resource — but the order is the safe one either way.
