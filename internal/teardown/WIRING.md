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
func Reconcile(ctx, *state.State, Finders) Reconciliation            // queries providers, records what is proven ours
func Obligations(*state.State) []Obligation                          // reads the journal only
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
  records a group or an application only when it created it. Reconciliation does ask the
  providers what is there (see below), but it only ever adopts what this deployment's
  ownership marker proves is its own.
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

## Reconciliation: what the command still has to pass in (issue #11)

`state.Resources` is only half the truth. `entra.Apply` creates an application, a service
principal, a signing certificate, two groups and two role assignments; an error partway
through returns before one resource ID reaches the record. On the lab that produced
"Teardown is complete. Nothing eligible is outstanding." while an Entra application, its
service principal and a group were still in the tenant.

`Reconcile` closes it. It reads the journal — `state.Pending()`, the latest attempt per
intent — and takes every phase that creates provider resources and did **not** succeed as
a reconciliation obligation. For each one it asks that provider what is there:

```go
type Found struct {
        Owned   []state.Resource // ownership marker verified: eligible
        Unowned []state.Resource // name match only: never touched, always reported
}
type Finder  func(ctx context.Context) (Found, error)
type Finders map[string]Finder // keyed as state keys providers: "entra", "cloudflare"
```

Marker-verified resources go into `st.Resources`, so the plan offers them, the operator
approves them, and a failed delete keeps them for the next run. Name-only matches are
reported and never touched. A provider that **cannot be asked at all** — no Finder, no
credential, no network, an API error — becomes uncertain work: it is reported with what
to check, `Result.Complete()` is false, `Run` returns `ErrIncomplete`, and `teardownCmd`
therefore returns before it can delete the deployment record. There is no name-only
cleanup and no state reset on a failed query anywhere in this package.

The phases that carry an obligation are `entra-signin`, `cloudflare-tunnel`,
`cloudflare-dns` and `cloudflare-access` (`creators` in `reconcile.go`).

### Three lines in `teardownCmd`

```go
finders := teardown.Finders{"entra": findEntra(st), "cloudflare": findCloudflare(cf)}
rec := teardown.Reconcile(ctx, st, finders)   // before BuildPlan: it records what it proves
plan := teardown.BuildPlan(st, settings.List(ctx, st, reg), deleteData)
plan.Reconciled = rec
```

`cf` is the `*cloudflare.Provisioner` `teardownProviders` already builds. Nothing else in
the command changes.

### The Entra Finder needs no change to `internal/entra`

`Client.Plan` is already the marker query — it is what resume uses — and it creates
nothing:

```go
func findEntra(ec *entra.Client, st *state.State) teardown.Finder {
        return func(ctx context.Context) (teardown.Found, error) {
                p, err := ec.Plan(ctx, entra.Config{
                        Hostname: st.Config["guac-hostname"], DeploymentID: st.DeploymentID,
                        AdminGroup: st.Config["admin-group"], OperatorGroup: st.Config["operator-group"],
                })
                if err != nil {
                        return teardown.Found{}, err // including ErrRequiresReview: a person decides
                }
                var f teardown.Found
                if p.App != nil {
                        r := state.Resource{Provider: "entra", Type: "application",
                                ProviderID: p.App.ObjectID, Name: p.App.DisplayName}
                        if !p.App.ProvenOurs {
                                f.Unowned = append(f.Unowned, r)
                        } else {
                                r.Ownership = "marker " + p.App.Marker + " in the application notes and tags"
                                f.Owned = append(f.Owned, r)
                                if p.SP != nil {
                                        f.Owned = append(f.Owned, state.Resource{Provider: "entra",
                                                Type: "service-principal", ProviderID: p.SP.ObjectID,
                                                Name: p.App.DisplayName,
                                                Ownership: "service principal of the marked application"})
                                }
                        }
                }
                for _, g := range p.Groups {
                        r := state.Resource{Provider: "entra", Type: "group",
                                ProviderID: g.ObjectID, Name: g.Name}
                        if !g.ProvenOurs {
                                f.Unowned = append(f.Unowned, r)
                                continue
                        }
                        r.Ownership = "marker " + entra.Marker(st.DeploymentID) + " in the group description"
                        f.Owned = append(f.Owned, r)
                }
                return f, nil
        }
}
```

Leave `AfterUncertainCreate` false here: this is a query, not a resume, and a name-only
match must come back as `Unowned` rather than as an error.

`Plan` still returns `ErrRequiresReview` for two cases a teardown would rather see as
`Unowned`: two applications sharing the display name, and a pre-existing application
serving a different entity ID. Both become uncertain work, which stops the teardown being
called complete until a person looks. That is the safe direction and it needs no change
to `internal/entra`; soften it there only if a real deployment is ever blocked by it.

### The Cloudflare Finder needs one read-only method on `internal/cloudflare`

That package's HTTP seam (`Client.do`) and its marker (`Provisioner.marker`) are both
unexported, so the marker rules cannot be applied from outside without copying them —
which is exactly what must not happen. Its owner adds one method, reusing the three
lookups `ApplyTunnel`, `ApplyDNS` and `applyAccessApp` already perform:

```go
// OwnedResource is one resource at Cloudflare that matches this deployment's
// naming. Ours reports whether the ownership marker proves it is this
// deployment's; a name match alone never does.
type OwnedResource struct {
        Type      string // "tunnel", "dns-record", "access-application"
        ID, Name  string
        Ours      bool
        Ownership string // the evidence, for the deployment record
}

// FindOwned lists them. It only reads: teardown calls it to reconcile a phase
// that failed before it could record what it created.
func (p *Provisioner) FindOwned(ctx context.Context) ([]OwnedResource, error) {
        var out []OwnedResource
        var tunnels []Tunnel
        path := "/accounts/" + p.AccountID + "/cfd_tunnel?is_deleted=false&per_page=50&include_prefix=" +
                url.QueryEscape(p.tunnelPrefix())
        if err := p.Client.do(ctx, "GET", path, nil, &tunnels); err != nil {
                return nil, err
        }
        for _, t := range tunnels {
                out = append(out, OwnedResource{Type: "tunnel", ID: t.ID, Name: t.Name,
                        Ours:      t.Name == p.TunnelName(),
                        Ownership: "deployment ID embedded in the tunnel name"})
        }
        var records []Record
        if err := p.Client.do(ctx, "GET", "/zones/"+p.ZoneID+"/dns_records?per_page=50&name="+
                url.QueryEscape(p.Hostname), nil, &records); err != nil {
                return out, err
        }
        for _, r := range records {
                out = append(out, OwnedResource{Type: "dns-record", ID: r.ID, Name: r.Name,
                        Ours:      r.Comment == p.marker(),
                        Ownership: "record comment carries this deployment's marker"})
        }
        apps, err := p.Client.listAccessApps(ctx, p.AccountID, "")
        if err != nil {
                return out, err
        }
        for _, a := range apps {
                if !strings.HasPrefix(a.Name, p.accessNamePrefix()) && !p.covers(a) {
                        continue // nothing to do with this deployment's hostname
                }
                out = append(out, OwnedResource{Type: "access-application", ID: a.ID, Name: a.Name,
                        Ours:      a.Name == p.AccessAppName() && p.covers(a),
                        Ownership: "deployment ID in the application name, verified against the hostname"})
        }
        return out, nil
}
```

Every marker test above is the one that package's own `Apply*` and `Delete*` already use:
the tunnel name, the DNS record comment, and the Access application name **plus** the
hostname-coverage check. The Access policy is not listed: it is removed with its
application and is never deleted separately.

The command then maps it:

```go
func findCloudflare(cf *cloudflare.Provisioner) teardown.Finder {
        return func(ctx context.Context) (teardown.Found, error) {
                found, err := cf.FindOwned(ctx)
                if err != nil {
                        return teardown.Found{}, err
                }
                var f teardown.Found
                for _, r := range found {
                        res := state.Resource{Provider: "cloudflare", Type: r.Type,
                                ProviderID: r.ID, Name: r.Name}
                        if !r.Ours {
                                f.Unowned = append(f.Unowned, res)
                                continue
                        }
                        res.Ownership = r.Ownership
                        f.Owned = append(f.Owned, res)
                }
                return f, nil
        }
}
```

Until `FindOwned` exists, pass no `"cloudflare"` Finder: a failed Cloudflare phase is
then reported as uncertain work with "no cloudflare query is wired into this run", which
is honest and keeps the teardown from being called complete. The Entra half works today.

### Azure is deliberately absent

Nothing journals a `state.Action` for the Azure destination: it is a separate command,
not a session phase, so there is no creation intent to reconcile against and no
obligation to find. On the day it is journalled, add `"azure-destination": "azure"` to
`creators` in `reconcile.go` and a Finder that matches on the `guacdeploy_deployment`
tag and blob metadata (`internal/azure`'s `ownerMetadata`). Teardown still removes no
remote backup either way.

### Host phases are not reconciled, and do not need to be

`boot-recovery`, `backup-schedule`, `recording-schedule` and `origin-certificate` create
host units, not cloud resources. `HostUnits` removes by marker whatever is on disk,
whether or not it was ever recorded, and every removal is verified against the filesystem
(below), so a half-installed unit is found by the removal step itself.

## Removed means gone

A path is reported under **Removed** only when it is actually gone. `hostUnitOutcomes`
re-stats every unit path after `RemoveHostUnits` returns, and that check — not the step's
own account of itself — decides the outcome. A live teardown listed
`systemd-unit /usr/local/lib/guacdeploy/guacdeploy` as removed while the file was still
on the host: a nil error was read as "all of them went", but each package here removes
only what still carries this deployment's marker, and `creds.UninstallBoot` deliberately
leaves the shared binary alone while another unit still calls it — both without an error.
A path that is still there is now **retained**, with the reason, and stays in the record.

Containers are checked the same way, because the filesystem is not the only thing that
outlives a step's own account of itself. `docker compose down` exits 0 for the project it
can see, so a container this deployment created under a project name the current
configuration no longer produces — an installation directory renamed between runs — stays
up while the step reports no error. `ContainersPresent` asks the runtime for the recorded
names after the down (`docker ps --all --format {{.Names}}`, by name rather than by
project, which is the whole point), and a name still listed is **retained**, not removed.
A runtime that cannot be asked at all makes the outcome **uncertain**: the run says what
to check and does not report completeness.

Anything that cannot be checked that way takes its result from the operation that
performed it: `RemoveRendered` and `RemoveCredentials`
from `removeIfEmpty`'s own `os.Remove`, `RemoveTree` from `os.RemoveAll`, and each
provider delete from its API call. A stat that fails for any reason other than "it is not
there" counts as still there: an unanswerable stat is never evidence of removal.

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
