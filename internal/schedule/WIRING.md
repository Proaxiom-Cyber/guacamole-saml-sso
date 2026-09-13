# Wiring internal/schedule into the session

This package is self-contained: it imports `internal/backup` (for the published-backup
contract) and nothing else from the deployment. The parent wires it into the phase
registry, the status command, and teardown. Nothing under `internal/session`,
`internal/stack`, `internal/host`, `internal/creds`, `internal/recoverykey`,
`internal/entra`, `internal/cloudflare`, or `cmd/guacdeploy/main.go` was modified.

New files: `internal/schedule/{schedule.go,run.go}`, `cmd/guacdeploy/backup-run.go`.

## The decision the parent should know about

The specification says "Installed backup and renewal routines operate without the
provisioning binary". The provisioning binary is whatever the administrator downloaded
and ran. It may sit in a home directory or a temporary directory, and it may be deleted
as soon as setup finishes. A unit pointing at that path breaks on the next reboot.

So `Install` copies the **running executable** to a deployment-owned runtime path,
`/usr/local/sbin/guacdeploy-runtime`, and the service unit calls that copy. The
installed routine then depends on nothing but itself, the state directory, and Docker.
`/usr/local/bin/guacdeploy` is deliberately **not** used: that is where the launcher
puts the provisioning binary, and the operator is free to remove it.

The copy is a created resource and `Uninstall` removes it.

## Phase placement

One new phase, `backup-schedule`, after the backup key exists and after the stack is
up — the timer's first run needs a running postgres container. Place it after
`backup-key` (or wherever `Config["backup-public-key"]` is set) and after `stack-up`,
in specification step 7 ("Configure services, certificate renewal, and selected backup
scheduling"), before the final health check in step 8.

The phase is skipped entirely when the administrator declines scheduling: scheduled
backups are optional ("Provide manual database backups and optional scheduled
backups").

```go
in, err := schedule.Install(ctx, schedule.Options{
        Run:          schedule.ExecRunner,
        DeploymentID: st.DeploymentID,
        StateDir:     stateDir,
        Dest:         st.Config["backup-dest"],
        OnCalendar:   st.Config["backup-schedule"],     // "" means daily
        Keep:         keep,                             // 0 means 7
        Plaintext:    st.Config["backup-plaintext"] == "true",
        RequireMount: st.Config["backup-require-mount"] == "true",
}, )
```

`UnitDir`, `RuntimeDir` and `Exe` stay zero in real runs; tests inject them.

`Install` is idempotent. A repeated or resumed setup with the same options rewrites
nothing, skips `daemon-reload`, and reports `Changed: false`. It still runs
`systemctl enable --now`, which repairs a timer an administrator stopped by hand.

## Flags for the parent to add to main.go

For `setup` (all optional; the guided wizard can prompt for the same values):

| Flag | Meaning | Default |
|---|---|---|
| `--backup-schedule EXPR` | systemd `OnCalendar` expression | `daily` |
| `--backup-keep N` | successful backups to retain | `7` |
| `--backup-dest DIR` | destination directory | `<state-dir>/backups` |
| `--backup-require-mount` | destination must be on an approved mounted share | off |
| `--no-backup-schedule` | do not install the timer | off |

For the new `backup-run` command, which the timer calls and an administrator can run
by hand. It takes no default destination on purpose: the schedule always records one,
and a silent fallback to local storage is what the specification forbids.

```
backup-run   Take the scheduled backup, then expire old backups
  --state-dir DIR      state directory
  --dest DIR           destination directory (required)
  --keep N             successful backups to retain (default 7)
  --plaintext          explicitly write an unencrypted backup
  --require-mount      fail unless --dest is on the approved mounted share
```

`--keep` and `--dest` already exist as flag names in main.go's shared flag set
(`dest` is there for `backup`); add `keep`, `require-mount`, and the `backup-schedule`
family. Dispatch:

```go
case "backup-run":
        err = backupRunCmd(ctx, backup.ExecRunner, schedule.Options{
                StateDir: *stateDir, Dest: *dest, Keep: *keep,
                Plaintext: *plaintext, RequireMount: *requireMount,
        }, u)
case "backup-status":
        err = backupStatusCmd(*stateDir, u)
```

Both functions live in `cmd/guacdeploy/backup-run.go`. The existing exit-code mapping
needs no change: `backupRunCmd` returns a plain error, so a failed backup exits 1, and
it returns before any retention runs.

## State keys

Non-secret references only, as usual:

| Key | Value |
|---|---|
| `backup-dest` | destination directory |
| `backup-schedule` | `OnCalendar` expression actually installed |
| `backup-keep` | retention count actually installed |
| `backup-plaintext` | `"true"` only when the administrator chose plaintext |
| `backup-require-mount` | `"true"` when the destination is an external mount |

Take the installed values from the returned `Installed`, not from the flags, so the
record matches the host after defaulting.

## Created resources

Three, recorded from `Installed`. The specification requires the tool to record the
installed routines and schedules as created resources.

```go
now := time.Now().UTC()
for _, r := range []struct{ typ, name string }{
        {"systemd-timer", in.TimerPath},
        {"systemd-service", in.ServicePath},
        {"backup-runtime", in.RuntimePath},
} {
        st.EnsureResource(state.Resource{Provider: "host", Type: r.typ, Name: r.name,
                CorrelationID: corrID,
                Ownership: "file written by this deployment, first line marks deployment ID",
                CreatedAt: now})
}
```

The ownership evidence is real: every unit's first line is
`# guacdeploy deployment=<deployment-id>`, and `Uninstall` removes a unit only when
that line matches. A same-named unit written by anything else is left in place and
named in the returned error.

## Teardown

```go
removed, err := schedule.Uninstall(ctx, schedule.Options{
        Run: schedule.ExecRunner, DeploymentID: st.DeploymentID})
```

It disables and stops the timer, removes the two units and the runtime copy, and
reloads systemd. Missing files are not an error, so teardown is repeatable. A non-nil
error with a non-empty `removed` means some units were removed and others were left
because they belong to someone else — report both, exactly as the Cloudflare teardown
reports `ErrNotOwned`.

Drop the matching resources from `state.Resources` for the paths in `removed` only.

Teardown does **not** delete backups. Deleting an administrator's only copy of the
database during teardown is not this tool's call.

## Status output

`session.Status` should append the last-run record. It is a separate file,
`<state-dir>/backup-status.json` (0600), not part of `state.json`: the deployment
record is the parent's schema and a nightly timer must not churn it, and the timer
writes this file while it holds the deployment lock, whereas status reads it without
any lock.

```go
u.Say("%s", schedule.Summary(stateDir))
```

`Summary` prints "No scheduled backup has run yet." when the file is absent, so it is
safe to call unconditionally. It shows destination, schedule, retention, last run time
and result, the published path or the failure reason, how many valid backups are held,
and what retention expired.

The record holds paths, counts and error text only. It never holds a credential: no
credential passes through this package, and the backup commands authenticate over the
postgres container's local socket rather than on a command line, so no failure message
can carry one. `TestStatusFileIsOwnerOnlyAndHoldsNoSecrets` fails if a field is ever
added that could.

## Behaviour the parent must not undo

- **A failed backup deletes nothing.** `RunBackup` records the failure and returns
  before `Prune`. Do not add a retention call anywhere else in the run.
- **Retention only counts files that passed the completion contract.** `Valid` requires
  the published name (`.partial-` can never match) and a matching completion manifest:
  `internal/backup` publishes `<name>.manifest.json` beside every backup, and retention
  re-hashes and length-checks the file against it. That works for an encrypted backup
  too, which a scheduled run cannot decrypt because it deliberately holds only the
  public key.
- **Retention is scoped to one deployment.** `Valid`, `List` and `Prune` take the
  deployment ID and only count backups whose manifest carries it. A shared destination
  holding another deployment's backups is left alone. `backupRunCmd` takes the ID from
  the deployment record, so the unit's command line does not need it.
- **Retention never empties the destination.** `keep < 1` is refused, and only
  `names[keep:]` is ever deleted.
- **Retention only ever deletes files it recognises as this deployment's backups.**
  Anything else in a shared destination directory is untouched: another deployment's
  backups, a backup with no manifest, a file that does not match its manifest, and
  anything unrelated.
- **`RequireMount` records the approved mount** in `<state-dir>/backup-mount.json` on
  the first checked run, and compares on every later one. Do not delete that file as
  part of an unrelated cleanup: the next run would approve whatever is mounted then.

## Known limits

- One deployment per host, so the unit names are fixed. That matches V1.
- A crash between publishing a backup and writing its manifest leaves a backup that
  retention preserves but never counts. It is the safe direction (see
  `publishManifest` for why that ordering was chosen), but the file has to be removed
  by hand, and the operator guide says so.
- The manifest is integrity evidence, not authentication. Anything that can rewrite a
  backup on the share can rewrite its manifest. It catches truncation, corruption and
  foreign files, which is what retention needs. Signing is not V1.
- `RequireMount` cannot tell a deliberately replaced share from a mistake, so it fails
  and tells the operator to delete the record to approve the new share.
