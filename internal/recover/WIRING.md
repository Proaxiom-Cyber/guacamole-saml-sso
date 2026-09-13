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

        // The same two Finders teardownCmd builds. Nothing new to write.
        st := l.Snapshot.State
        rep := recover.Reconcile(ctx, l, teardown.Finders{
                "entra":      findEntra(ec, st),
                "cloudflare": findCloudflare(cf),
        })
        rep.Print(u)
        if err := rep.RequiresReview(); err != nil {
                return err // exit 3, beside session.ErrApprovalRequired
        }
        if !yes { ...u.Confirm... }

        rec, err := recover.Restore(l, rep, time.Now())
        if err != nil {
                return err
        }
        if err := store.Save(rec); err != nil {
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

## 2. The Finders: teardown's, unchanged

Recovery asks the **same question teardown asks**, through the same seam, so it is the same
type and the same wiring:

```go
type Finder  func(ctx context.Context) (teardown.Found, error)
type Finders map[string]Finder // keyed as state keys providers: "entra", "cloudflare"
```

`teardownCmd` already builds these with `findEntra` and `findCloudflare`
(`internal/teardown/WIRING.md`, section "The Entra Finder" and "The Cloudflare Finder").
**Pass the same two functions here.** There is nothing new to write at either provider, and
`cloudflare.FindOwned` already covers the tunnel, the DNS record and the Access application
in one call.

One marker sweep per provider answers both of recovery's questions at once:

| What the sweep says about a resource | Disposition |
|---|---|
| in `Found.Owned`, and the record holds it | `Adopt` — reused, never created again |
| in `Found.Owned`, and the record does **not** | `Adopt`, `Recovered: true` — see below |
| in `Found.Unowned` (name match, no marker) | `Review` — never adopted, never deleted |
| in neither | `Recreate` — created again, intent journalled first |
| the Finder errored, or none is wired | `Review` |

An error is not an empty answer, and an unwired provider is not a skip. Recreating on an
unanswered question is exactly how a duplicate tunnel gets made. A partial `Found` returned
*with* an error — which is what `cloudflare.FindOwned` does when its second call fails — is
not trusted either: half a sweep proves nothing about the half that failed.

A recorded resource is matched to the sweep by provider ID first and by
provider/type/name second, so a resource renamed at the provider but still carrying the
marker is recognised rather than created beside itself.

`cloudflare/access-policy` and `entra/service-principal` are never classified from the
sweep: they have no lifecycle of their own and follow their parent. `host/*` and `docker/*`
are rebuilt by setup on the new VM.

### Why a sweep and not a lookup per resource

Because the resource list is only half the record. A phase creates several resources and can
fail before any of them is saved, and those resources are still at the provider carrying
this deployment's marker with nothing in `state.Resources` pointing at them. A per-resource
lookup cannot see them, so a recovery would create a second set beside them — the same
orphan failure teardown had to fix, reintroduced on the replacement host. The sweep sees
both, and `Item.Recovered` marks what it found that the record was missing.

### The journal is the other half

`teardown.Obligations(st)` names the unfinished phases that create at a provider, from
teardown's own `creators` map. Recovery asks that provider even when the record mentions it
nowhere, and reports the result as a `recover.Obligation`:

- **Answered** — the provider was asked. Anything it proved ours is adopted above.
- **Not answered** — no Finder, or the Finder errored. `Report.Unanswered()` lists these and
  `RequiresReview()` fails, so `Restore` refuses. The detail says which provider to check and
  which marker to look for.

Nothing here keeps a second copy of which phase creates where. If a new phase starts creating
at a provider, add it to `creators` in `internal/teardown/reconcile.go` and both teardown and
recovery pick it up.

### Azure

`azure/blob-prefix` has no Finder, so it is reported as review: one line asking the operator
to confirm the storage account and container are still there. That is the correct default —
recovery never creates or deletes remote backup storage. Nothing journals an Azure creation
intent today, so there is no obligation to go with it.

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

A resource the sweep found that the record was missing goes in too, with the identifier
`state.EnsureResource` gives it and the ownership evidence the provider reported. **That is
what keeps teardown honest later**: a resource nobody recorded is a resource nobody removes.

The lost host's unfinished creation intents are carried over as answered entries, one per
obligation, spelled `recover:reconciled:<intent>` with the original phase name inside and a
detail saying what asking the provider found. They are neither dropped — that evidence is
the only thing standing between a recovery and a duplicate — nor carried over unfinished,
because the original phase did not succeed and a pending intent naming a dead machine can
never resolve. Pending intents that create nothing at any provider are not carried over at
all; the `recover:restore` entry records how many there were.

Recorded setting changes *are* carried over: they were applied to pre-existing objects that
outlived the host, and `internal/settings` drift-checks each one against the live value
before it offers to restore anything.

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
enforced, an unwired or failing provider reviewed rather than recreated, a renamed resource
adopted rather than created beside itself, no creation while a resource is still present,
the DNS record following the tunnel actually in use, a sealed credential reported as
unrecoverable rather than regenerated, and the exact set of things the operator must still
supply.

The journal half has its own tests, built on the failure that happened in the lab: a phase
that created an Entra application, its service principal and a group and failed before any
of them reached the record. They cover all three being adopted rather than created a second
time, the intent carried forward as evidence instead of dropped, a provider that cannot be
asked stopping the recovery **even though no resource in the record mentions it**, a partial
sweep returned with an error not being trusted as an answer, and a name-only match neither
adopted nor recreated. Twenty-one mutations of the load-bearing logic were each checked to
turn a test red.

All of it runs through fakes. **No test has ever read a real Cloudflare or Graph API, built
a VM, or restored a database.** A real replacement-VM recovery on the Rocky Linux test
platform is outstanding: lose a host, bring the backup and the key export to a fresh VM,
watch a surviving tunnel get adopted instead of duplicated, watch a deleted one get
recreated, and sign in through Entra to one connection at the end.
