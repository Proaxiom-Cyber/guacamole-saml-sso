# Wiring recovery onto a replacement VM

`internal/recover` is the reconciliation half of issue #21. It reads a backup, asks each
provider one read-only question per recorded resource, classifies the answers, and returns
the deployment record to persist. **It creates nothing, changes nothing and deletes
nothing.** Recreating what is genuinely gone is your existing provisioning path.

New files: `internal/recover/{recover.go,recover_test.go}` and this document. Nothing
outside `internal/recover/` was modified.

## The shape of a recovery

The operator has a backup file, the passphrase-encrypted recovery key export, its
passphrase, and a fresh Rocky Linux 10 VM. Everything else died with the old host.

```
Load ──▶ Reconcile ──▶ Report.Print ──▶ RequiresReview ──▶ Restore ──▶ save state
 │           │              │                 │                │
 backup   providers     before any        stops here      the record the
 only     read only     change at all     on ambiguity    new host runs on
```

Then, and only then, your existing phases run: re-supply credentials, create what
`state.Pending()` says is missing, render, start the stack, replay the dump, verify.

## 1. The command

`main.go` is outside my boundary, so `guacdeploy recover` does not exist yet. It is a
`case "recover":` and a new `cmd/guacdeploy/recover.go`. Suggested flags:
`--file PATH` (required), `--key-export PATH` (default `<state-dir>/backup-key.age`),
`--yes`.

```go
func recoverCmd(ctx context.Context, o Options, file, keyExport string, yes bool, u *ui.UI) error {
        store, err := state.Open(o.StateDir) // one mutating operation at a time
        if err != nil {
                return err
        }
        defer store.Close()
        if st, err := store.Load(); err != nil {
                return err
        } else if st != nil {
                return fmt.Errorf("this host already runs deployment %s; recovery targets a fresh VM", st.DeploymentID)
        }

        src := recover.Source{BackupFile: file, KeyExport: keyExport, GuacVersion: stack.GuacVersion}
        if raw, err := os.ReadFile(file); err == nil && backup.Encrypted(raw) {
                if src.Passphrase, err = u.HiddenLine("Backup key passphrase"); err != nil {
                        return err
                }
        }
        l, err := recover.Load(src) // decrypt, format, version, record schema
        if err != nil {
                return err
        }

        // The Cloudflare token has to exist before any provider can be asked.
        token, err := m.Get(creds.Spec{Name: "cloudflare-api-token"})
        if err != nil {
                return err
        }

        rep := recover.Reconcile(ctx, l, finders(l, token))
        rep.Print(u)
        if err := rep.RequiresReview(); err != nil {
                return err // exit 3, beside session.ErrApprovalRequired
        }
        if !yes { ...u.Confirm... }

        st, err := recover.Restore(l, rep, time.Now())
        if err != nil {
                return err
        }
        if err := store.Save(st); err != nil {
                return err
        }
        ...existing setup phases, then backup.Apply(ctx, opts, l.SQL)...
}
```

Read the passphrase with `u.HiddenLine`, never a flag: a flag lands in shell history and in
`ps`. `recover.Load` never puts the passphrase, the key or the dump into an error string.

Map `recover.ErrReviewRequired` to the same exit code as `teardown.ErrReviewRequired`.
`ErrKeyRequired`, `ErrIncompatible` and `ErrNoRecord` are ordinary failures: nothing was
changed, so a retry costs nothing.

## 2. The Finders

```go
type Finder func(ctx context.Context, r state.Resource) (recover.Live, error)
type Finders map[string]Finder // keyed by recover.Key(r) == "<provider>/<type>"
```

A `Finder` must **create nothing**. Fill in `Live{Present, ProviderID, Marker}` and let the
package apply the rules. It classifies, you do not:

| What the provider reports | Disposition |
|---|---|
| present, `Marker == recover.Marker(deploymentID)` | `Adopt` — reused, never created again |
| absent | `Recreate` — created again, intent journalled first |
| present, marker absent or different | `Review` — never adopted, never deleted |
| lookup errored, or no `Finder` wired | `Review` |

An unwired key is review, not a skip. That is deliberate: recreating on an unanswered
question is exactly how a duplicate tunnel gets made.

Look each resource up **by the deployment's own name and marker, not by the recorded
provider ID**, and report the ID you found in `Live.ProviderID`. The marker is the durable
evidence; a recorded ID is only a hint, and `Adopt` takes the live ID over the recorded one.

The five keys to wire: `cloudflare/tunnel`, `cloudflare/dns-record`,
`cloudflare/access-application`, `entra/application`, `entra/group`. `cloudflare/access-policy`
and `entra/service-principal` are never queried — they have no lifecycle of their own — and
`host/*` and `docker/*` are rebuilt by setup on the new VM.

### Entra: works today

`entra.Client.Plan` is already the read-only reconciliation query, and it returns the marker
it found. Call it once, serve both keys from the result:

```go
p, err := client.Plan(ctx, entra.Config{
        Hostname:      st.Config["guac-hostname"],
        DeploymentID:  st.DeploymentID,
        AdminGroup:    st.Config["admin-group"],
        OperatorGroup: st.Config["operator-group"],
        // A name match without our marker must be review, not a reusable
        // pre-existing resource. On a replacement host nobody can tell the two
        // apart from here.
        AfterUncertainCreate: true,
})
```

`p.App` nil means gone (`Live{}`); otherwise `Live{Present: true, ProviderID: p.App.ObjectID,
Marker: p.App.Marker}`. Same for `p.Groups[name]` — it carries `ProvenOurs` rather than the
marker text, so pass `recover.Marker(st.DeploymentID)` when it is true and `""` when it is
not. `entra.ErrRequiresReview` from `Plan` is returned as the Finder's error, which is
review anyway.

### Cloudflare: three lookups you have to add

`Client.do` is unexported, so a read-only lookup cannot be written from outside the package,
and `ApplyTunnel` / `ApplyDNS` **create** when nothing matches. Recovery must not call them
before it has reported.

Split the query half out of each `Apply*` and have `Apply*` call it. That keeps recovery's
view and provisioning's view from ever drifting apart, and it is a smaller change than a
second query path:

```go
// LookupTunnel reports the tunnel this deployment owns. Read only: it never
// creates. A zero Tunnel with a nil error means there is none.
func (p *Provisioner) LookupTunnel(ctx context.Context) (Tunnel, error) {
        var found []Tunnel
        path := "/accounts/" + p.AccountID + "/cfd_tunnel?is_deleted=false&per_page=50&include_prefix=" +
                url.QueryEscape(p.tunnelPrefix())
        if err := p.Client.do(ctx, "GET", path, nil, &found); err != nil {
                return Tunnel{}, err
        }
        for _, t := range found {
                if t.Name == p.TunnelName() {
                        return t, nil
                }
        }
        if len(found) > 0 {
                return Tunnel{}, fmt.Errorf("tunnel %q matches hostname %s but not this deployment's marker: %w",
                        found[0].Name, p.Hostname, ErrRequiresReview)
        }
        return Tunnel{}, nil
}
```

`ApplyTunnel` then becomes that call plus the existing POST. Do the same for `ApplyDNS`
(`LookupRecord`, returning the record whose `Comment` carries the marker) and for the Access
application (`LookupAccessApp`, wrapping the existing unexported `listAccessApps` and
`covers`). The marker string for both is what `PlanDNS(...).Comment` returns, which
`TestMarkerMatchesBothProviders` pins to `recover.Marker`.

`is_deleted=false` matters: a deleted tunnel is still returned by a GET on its ID, with
`deleted_at` set. Listing is what tells the truth. For a DNS record, a 404 is a genuine
absence — `errors.As(err, &cloudflare.APIError{})` exposes `Status`.

### Azure

`azure/blob-prefix` has no Finder in the list above, so it is reported as review: one line
asking the operator to confirm the storage account and container are still there. That is
the correct default — recovery never creates or deletes remote backup storage. Wire an
Azure Finder if you want the line to resolve by itself.

## 3. What must change on a replacement host

`Report.Automatic()` names these, and the report prints them:

- **Tunnel connector token** — fetched fresh with `p.TunnelToken(ctx, tunnelID)` for
  whichever tunnel is in use, adopted or new. It is never journalled or backed up, and
  fetching it again creates no tunnel. Pass it to `stack.Up` as today.
- **Origin certificate — re-issued, not restored.** Its private key was only ever on the
  lost host: a backup must not carry a private key, and the certificate files are useless
  without it. `certs.Issue` needs only the Cloudflare API token the operator re-supplies
  anyway, and `certs.Install` puts the renewal timer on the new host regardless. The old
  certificate stays valid until it expires but nobody can use it without the key. Let's
  Encrypt allows five identical certificates per week, which one recovery is well inside.
- **DNS record follows the tunnel actually in use.** When the tunnel is recreated, the
  surviving record still names the dead one, so `Item.Retarget` is set on it. Update that
  record in place — `PATCH /zones/<zone>/dns_records/<id>` with the new
  `<tunnel-id>.cfargotunnel.com` — and do not create a second record. `internal/cloudflare`
  has no update path today (`ApplyDNS` has a `ponytail:` note saying exactly this); delete
  and re-apply works, at the cost of a gap. Either way, one record.
- **Every credential is supplied again.** No credential value is in deployment state or in
  a backup, by construction. `Report.OperatorNeeds()` lists the ones only a person can
  provide; `postgres-password` is regenerated because the dump carries no role password —
  the new PostgreSQL container creates the role from whatever value is chosen here.

A `tpm`- or `host`-sealed credential from the lost host cannot be opened on this machine at
all, even if the file were copied here. The report says so in `creds.Describe(mode)`'s own
words rather than inventing softer ones, and such a credential is never quietly regenerated.

## 4. State keys

`Restore` returns the record with the restored identity, configuration references, resource
identifiers, ownership evidence and setting changes, plus two additions:

| Key | Value |
|---|---|
| `recovered-at` | RFC 3339 UTC, when the record was restored |
| `recovered-from` | base name of the backup it came from |

The **deployment ID is kept, not minted**. Every surviving cloud resource carries the marker
built from it; a new ID would turn the whole deployment into unowned strangers and duplicate
all of it.

Adopted resources take the identifier the provider just confirmed and gain
`; marker re-verified on this replacement host at <time>` in their ownership evidence. A
resource that is gone loses its stale identifier and gains an unfinished journal entry,
`recover:recreate:<provider>/<type>/<name>`, all sharing one correlation ID. **Drive your
provisioning from `st.Pending()`**: an interruption mid-recovery then resumes instead of
duplicating.

The lost host's action journal is deliberately not carried over. Its unfinished intents
describe attempts on a machine that no longer exists and could never resolve. Recorded
setting changes *are* carried over: they were applied to pre-existing objects that outlived
the host, and `internal/settings` drift-checks each one against the live value before it
offers to restore anything.

## 5. Order of operations

1. `state.Open` for the whole recovery. One mutating operation per deployment.
2. `Load`. Refuses an unreadable, wrong-version or undecryptable backup before anything.
3. Credentials, so the providers can be asked at all.
4. `Reconcile`, `Print`, `RequiresReview`, approval.
5. `Restore` and `store.Save`. The record exists before any creation is attempted.
6. Existing phases, driven by `st.Pending()`.
7. Stack up, then `backup.Apply(ctx, opts, l.SQL)` — `psql` runs *inside* the postgres
   container, so the stack has to be running first — then restart the stack.
8. Verify: Entra sign-in and one representative connection, by a person.

`Loaded.SQL` is a decrypted database dump. It can contain saved connection credentials.
Do not log it, journal it, or write it anywhere but the target database.

## 6. What the tests do not prove

`go test ./internal/recover/` covers the record travelling inside the backup and coming
back whole, refusal of an incompatible format, Guacamole version, record schema and
truncated dump before anything is altered, an encrypted backup with no key, no passphrase,
a wrong passphrase and a wrong key, each reconciliation outcome with the marker rules
enforced, an unwired or failing lookup reviewed rather than recreated, no creation while a
resource is still present, the DNS record following the tunnel actually in use, a sealed
credential reported as unrecoverable rather than regenerated, and the exact set of things
the operator must still supply. Thirteen mutations of the load-bearing logic were each
checked to turn a test red.

All of it runs through fakes. **No test has ever read a real Cloudflare or Graph API, built
a VM, or restored a database.** A real replacement-VM recovery on the Rocky Linux test
platform is outstanding: lose a host, bring the backup and the key export to a fresh VM,
watch a surviving tunnel get adopted instead of duplicated, watch a deleted one get
recreated, and sign in through Entra to one connection at the end.
