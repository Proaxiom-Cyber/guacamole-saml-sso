# Wiring internal/recording into the session

This package is self-contained. It imports `internal/backup` (for the published-completion
contract it reuses) and `internal/recoverykey` (for the selected encryption mode), and
nothing else from the deployment. The parent wires it into the phase registry, the status
command, teardown, and `main.go` dispatch.

Nothing under `internal/stack/stack.go`, `internal/session`, `internal/host`,
`internal/creds`, `internal/backup`, `internal/schedule`, `internal/entra`,
`internal/cloudflare`, or `cmd/guacdeploy/main.go` was modified.

New files: `internal/recording/{recording.go,backup.go,cleanup.go}`,
`cmd/guacdeploy/recordings.go`, `docs/recordings.md`. One asset was edited:
`internal/stack/assets/compose.yaml.tmpl`.

## The three decisions the parent should know about

### 1. A recording is complete when nothing holds it open

guacd appends to the recording for the whole session, so the file is only complete once
the session ends. `OpenFiles` decides that, and `ProcOpenFiles` is the real
implementation: every open descriptor of every process on this host, collected as
**device and inode pairs**, not paths. guacd sees the file as `/recordings/<uuid>` in its
own mount namespace and the tool sees it as `/opt/guacamole/recordings/<uuid>`; the inode
is the same either way, so no path translation is needed.

The rejected alternative was a quiet period on the modification time. It misjudges
exactly the case that loses evidence: a long idle session writes nothing, is declared
complete, is copied half-finished, and then becomes eligible for deletion while it is
still recording. An open descriptor cannot go quiet.

The ceiling is stated in the code: it needs the writer on this host and `/proc` readable,
which the V1 deployment gives (guacd is a container here and the timer runs as root).
Where it does not hold, `Scan` **fails** instead of guessing, so nothing is backed up and
nothing is deleted. A recording left open by a crashed guacd never becomes complete; it
is preserved, and `docs/recordings.md` says how to clear it.

### 2. The recordings directory must be given to the guacd account

`stack.Render` does not create it, and Docker would create a missing bind-mount source as
root-owned. guacd runs as uid 1000, so it could not write a single recording — while the
session itself still succeeded. That is a silent failure, so the parent must call:

```go
recording.EnsureDirs(cfg.InstallDir)   // <install-dir>/recordings, 0755, owned by 1000:1000
```

Mode 0755 is the same convention `Render` uses for every bind mount a container reads: a
bind mount exposes the directory's own mode, and the container processes are not root.
Confidentiality comes from the installation root, which `Render` creates 0750.

**Call it from the stack phase, before `stack.Up`.** It is idempotent and safe on resume.

### 3. Upload first, then cleanup, from one scan

`recording.Run` scans once and hands the same list to the backup step and the cleanup
step. That is the whole coordination mechanism: both steps see the same active set, in
one process, one after the other, so a recording is never deleted while its own copy is
being written and an in-flight upload is never reported as finished. The service unit is
`Type=oneshot`, so a second run cannot start while one is going.

**A failed upload does not stop cleanup.** The specification is explicit: "Upload success
is not a condition for deletion. The local storage budget takes priority over preserving
unbacked recordings." Every such deletion is named in `Report.Lost`.

## Compose template changes

`guacd` gets `./recordings:/recordings:z` (read-write) and `guacamole` gets
`./recordings:/recordings:ro,z` plus `RECORDING_SEARCH_PATH: /recordings`.

The SELinux option is lowercase **`z`** (shared), not `Z` (private), because the same host
directory is mounted into two containers. A private label is re-applied per container, so
the second mount would take the directory away from the first. Everything else in the
template keeps `Z`, correctly: those mounts have one container each.

## Phase placement

One new phase, `recording-schedule`, in specification step 7 ("Configure services,
certificate renewal, and selected backup scheduling"), after the stack is up and after
the backup key exists (the copies are encrypted with the recorded public key by default).

`EnsureDirs` belongs earlier, in the stack render/up phase.

```go
in, err := recording.Install(ctx, recording.InstallOptions{
        Run:          backup.ExecRunner,
        DeploymentID: st.DeploymentID,
        StateDir:     stateDir,
        Dir:          recording.Dir(installDir),
        Dest:         st.Config["backup-dest"],          // "" backs nothing up
        Budget:       budget,                            // bytes, from ParseBytes
        Plaintext:    st.Config["backup-plaintext"] == "true",
        OnCalendar:   st.Config["recording-schedule"],   // "" means hourly
})
```

`UnitDir`, `RuntimeDir` and `Exe` stay zero in real runs; tests inject them.

`Install` is idempotent and reports `Changed: false` when nothing needed rewriting. It
refuses a schedule with neither a budget nor a destination, because that timer would do
nothing.

## The setup question to ask

"Show this policy during setup" (specification). Ask for the budget and show the caveat
in the same breath:

> How much local disk may session recordings use? (for example 20GB)
>
> When recordings exceed this, the oldest completed recordings are deleted, whether or
> not they were backed up first. Recordings still in progress are never deleted, so usage
> can go over the budget between runs. This is not a hard filesystem quota.

`recording.ParseBytes` accepts `20GB`, `500M`, `10GiB`, or a plain byte count.
`recording.FormatBytes` prints it back.

## Flags for the parent to add to main.go

```
recordings-run       Back up completed recordings, then apply the storage budget
  --state-dir DIR      state directory
  --recordings-dir DIR local recordings directory (default: from the deployment record)
  --dest DIR           backup destination root (optional; no copies without it)
  --budget BYTES       local storage budget in bytes (0 deletes nothing)
  --plaintext          explicitly copy recordings unencrypted

recordings-enable    Turn session recording on for the connections in the database
  --connection NAME    one connection (default: every connection)

recordings-status    Show the last recording backup and cleanup run

recordings-restore   Write one backed-up recording back out as a playable file
  --file PATH          the published copy in the backup destination (required)
  --out PATH           output file (default: <name>.playback)
  --identity-file PATH age identity file instead of the passphrase prompt
```

Dispatch, all four functions living in `cmd/guacdeploy/recordings.go`:

```go
case "recordings-run":
        err = recordingsRunCmd(*stateDir, *recordingsDir, *dest, *budget, *plaintext, u)
case "recordings-enable":
        err = recordingsEnableCmd(ctx, backup.ExecRunner, *stateDir, *connection, u)
case "recordings-status":
        err = recordingsStatusCmd(*stateDir, u)
case "recordings-restore":
        err = recordingsRestoreCmd(*stateDir, *file, *out, *identityFile, u)
```

New flag variables needed: `recordings-dir` (string), `budget` (int64), `connection`
(string), `out` (string). `dest`, `plaintext`, `file`, `identity-file` and `state-dir`
already exist in the shared flag set.

The existing exit-code mapping needs no change. `recordingsRunCmd` returns a plain error,
so a failed upload exits 1 — after cleanup has run, deliberately.

## State keys

Non-secret references only, as usual:

| Key | Value |
|---|---|
| `recording-budget` | the storage budget in bytes, as installed |
| `recording-schedule` | the `OnCalendar` expression actually installed |
| `recording-dir` | the local recordings directory |

Take the installed values from the returned `Installed`, not from the flags.

## Created resources

Two. The runtime binary copy is **not** recorded here: `internal/schedule` already
records it, and both schedules share it.

```go
now := time.Now().UTC()
for _, r := range []struct{ typ, name string }{
        {"systemd-timer", in.TimerPath},
        {"systemd-service", in.ServicePath},
} {
        st.EnsureResource(state.Resource{Provider: "host", Type: r.typ, Name: r.name,
                CorrelationID: corrID,
                Ownership: "file written by this deployment, first line marks deployment ID",
                CreatedAt: now})
}
```

## Teardown

```go
removed, err := recording.Uninstall(ctx, recording.InstallOptions{
        Run: backup.ExecRunner, DeploymentID: st.DeploymentID})
```

It disables and stops the timer and removes the two units. It does **not** remove the
shared runtime binary copy — `schedule.Uninstall` owns that, and removing it from under a
still-installed backup timer would break that timer. It does **not** delete a recording,
locally or in the destination.

## Status output

```go
u.Say("%s", recording.Summary(stateDir))
```

Safe to call unconditionally; it prints "No recording backup or cleanup run has happened
yet." when the file is absent. The record is `<state-dir>/recording-status.json` (0600),
separate from `state.json` for the same reason the backup one is: an hourly timer must
not churn the deployment record.

**Database and recording results stay separate** (specification). `schedule.Status` covers
the database backup; this covers recordings. Print both; never merge them into one
"backup succeeded" line.

## Behaviour the parent must not undo

- **An active recording is never copied and never deleted.** Both steps skip
  `Recording.Active`, and a file whose identity cannot be read is treated as active.
- **`Scan` fails closed.** If it cannot tell which recordings are being written, the run
  fails; it does not assume everything is complete.
- **A copy counts only when its completion record verifies.** `Report.Included` gets a
  name only after `writeManifest` succeeds, and `backup.VerifyPublished` is what proves
  it later. A failed copy leaves nothing under a published name, and a copy whose record
  could not be written is reported in `Report.Failed`, never in `Included`.
- **Nothing is ever overwritten.** A taken name moves to `-1`, `-2`, and so on.
- **Cleanup runs even when the upload failed**, and names every unbacked deletion in
  `Report.Lost`. Do not gate deletion on upload success.
- **The destination must already exist.** A missing directory or absent mount fails
  visibly; copies are never redirected into local storage. Only the `recordings`
  subdirectory inside it is created.

## Known limits

- One deployment per host, so the unit names are fixed. That matches V1.
- Azure Blob is not a destination here. The destination is a local directory or an
  existing mounted share, which is what issue 15 asks for. The Azure slice can reuse
  `Scan` and `Report` unchanged.
- Remote recording retention (expiring copies in the destination by age) is a separate
  specification section and is not implemented here. Cleanup only ever deletes **local**
  recordings.
- `ProcOpenFiles` is Linux. On any other system it returns an error and the run fails
  rather than guessing. Tests inject the seam, so the suite runs anywhere.
- `installRuntime` and `writeIfChanged` in `cleanup.go` are copies of the unexported
  helpers in `internal/schedule`, because this slice may not edit that package. When both
  land on the same branch, export them there and delete the copies.
