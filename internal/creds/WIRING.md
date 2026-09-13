# Encrypted credentials: wired into the session on 11 September 2026

Everything below is **done**. `internal/session` now offers `creds.AllModes`, checks
`Detector.Available` before recording any mode (including one named with `--credentials`),
stores with `Manager.Store` under `creds.Persistent`, and records `credential-sealed`
resources by their on-disk filename so teardown removes the right file. `creds.Modes` is
deleted. The document is kept as the record of what the contract is and why.

This package now offers five credential modes. Two are new and both are encrypted by
`systemd-creds`:

| Mode | Constant | Mechanism |
|---|---|---|
| `tpm` | `creds.ModeTPM` | `systemd-creds encrypt --with-key=host+tpm2` |
| `host` | `creds.ModeHostKey` | `systemd-creds encrypt --with-key=host` |
| `file` | `creds.ModeFile` | owner-only plaintext file (unchanged) |
| `env` | `creds.ModeEnv` | `GUACDEPLOY_CRED_*` (unchanged) |
| `prompt` | `creds.ModePrompt` | hidden prompt (unchanged) |

New files: `internal/creds/{sealed.go,boot.go}` and their tests. `internal/creds/creds.go`
gained a `Run` field on `Manager`, two cases in `Get` and `Missing`, and a rewritten
`Explain`. Nothing under `internal/session`, `internal/stack`, `internal/host`,
`internal/backup`, `internal/schedule`, `internal/recording`, `internal/certs`,
`internal/settings`, `internal/entra`, `internal/cloudflare`, or `cmd/guacdeploy/main.go`
was modified. The repository suite passes as it stands, because the session still offers
only its original three modes until you do the work below.

## 1. Mode selection: detect, show, never downgrade

`creds.Modes` is the old three-mode list. Switch the menu in `credentialMode` to
`creds.AllModes`, which is ordered to offer the preferred mode first and plaintext last:
`tpm`, `host`, `env`, `prompt`, `file`. Delete `creds.Modes` once nothing reads it.

```go
d := creds.Detector{}                       // real seams by default
supported := d.Detect(ctx)                  // one entry per mode, in AllModes order
for _, s := range supported {
        if s.Supported {
                u.Say("  %s — %s", s.Mode, creds.Explain(s.Mode))
        } else {
                u.Say("  %s — not available on this host: %s", s.Mode, s.Reason)
        }
}
```

`Detect` runs at most two commands: `systemd-creds --version` and `systemd-creds has-tpm2`.
It reports a reason for every unsupported mode, and the reasons are the three the ticket
asks for: no `/dev/tpm*` device, systemd older than 250, and a TPM the firmware or driver
cannot use. `prompt`, `env` and `file` are always supported.

Before recording any mode, whether it came from the menu or from `--credentials`:

```go
if err := d.Available(ctx, mode); err != nil {
        return err   // names the mode and the reason; offers no substitute
}
```

**This is the "never silently downgrade" rule and it belongs to you.** Nothing in this
package answers "no TPM on this host" by writing plaintext instead. `Available` returns an
error, the operator reads it, and the operator picks another mode. Do not wrap that error
in a retry that quietly selects `file`.

After selection, show the protection level the specification asks for:

```go
u.Say("Credential storage method: %s.\n%s", mode, creds.Detail(mode))
```

`creds.Detail(mode)` prints four labelled lines: protection, unattended reboot recovery,
replacement host, and backup implication. `creds.Describe(mode)` returns the same content
as a struct if you would rather lay it out yourself. The text is deliberately blunt about
the vTPM: on a virtual machine the hypervisor holds the TPM's secrets, so a compromised
hypervisor can read them, and a sealed credential cannot be decrypted on a replacement VM.
Do not soften that when you render it.

The existing plaintext confirmation prompt stays exactly as it is.

## 2. State keys

Non-secret references only, as usual.

| Key | Value |
|---|---|
| `credential-mode` | `tpm`, `host`, `file`, `env` or `prompt` |
| `credential-boot-unit` | path of the installed boot unit, when one is installed |

Extend the validation switch in `credentialMode` to accept `creds.ModeTPM` and
`creds.ModeHostKey`, and extend the `--credentials` help text in `main.go`.

`internal/creds` writes nothing else to state. The sealed blobs live beside the plaintext
files in `<state-dir>/credentials/`, named `<credential>.cred`, mode 0600 in a 0700
directory.

## 3. Storing a credential: use `Store`, not `StoreFile`

`credentialCheck` currently calls `m.StoreFile` inside an `if m.Mode == creds.ModeFile`
block. Replace that condition with `creds.Persistent(m.Mode)` and the call with `m.Store`,
which dispatches by mode:

```go
m := o.manager(st, u)                         // now also sets Run
if creds.Persistent(m.Mode) {
        for _, s := range o.credSpecs() {
                if _, err := os.Stat(m.Path(s)); err == nil {   // see note below
                        continue
                }
                ...unchanged: generate, or prompt, or skip...
                createdDir, err := m.Store(ctx, s, v)
                ...unchanged resource recording...
        }
}
```

Two details:

- The existence check needs the right filename per mode: plaintext modes store `<name>`
  and encrypted modes store `<name>.cred`. `m.Path(s)` returns the right one, and an empty
  string for the modes that store nothing, so the `os.Stat` line needs only that
  substitution.
- `manager()` must set the command seam: `Run: creds.ExecRunner`. It defaults to
  `ExecRunner` when nil, so an unset field still works; setting it makes the test seam
  visible.

A failed seal writes **nothing**: no blob, no plaintext, not even the directory. The error
names the credential and the key policy, and never contains the value.

The resource records need no change apart from the type name. Record
`credential-file` for `file` mode and `credential-sealed` for `tpm` and `host`, so teardown
and the action summary can tell them apart.

## 4. How the credential reaches the container

**Unchanged. Do not touch `internal/stack`.**

`stackSecrets` already calls `m.Get(spec)`. For the two new modes `Get` reads the blob,
pipes it into `systemd-creds decrypt` through stdin, and returns the plaintext in memory.
The value then travels to `stack.Up`, which writes it to an owner-only file on tmpfs that
the container reads for itself. It never reaches a rendered file, a command argument, the
`.env` file, or Docker's stored container environment. See `internal/stack/WIRING.md`.

`Get` has no `context` parameter, because callers predate this slice. It applies its own
30-second timeout so a TPM that stops answering fails the boot unit with a message instead
of hanging it forever.

A failed decrypt is an error, never an empty string. An empty password would start
PostgreSQL with a password nobody knows and look like a working deployment until the first
connection. The error says the credential is bound to this host and must be re-supplied.

## 5. Reboot recovery without the provisioning binary (A11)

`InstallBoot` follows the convention `internal/schedule` set: it copies the **running
executable** to `/usr/local/sbin/guacdeploy-runtime` and installs a unit that calls the
copy. It is the same path `schedule.Install` uses, and the copy is content-compared, so a
host that installs both ends up with exactly one binary and the second install does
nothing.

```go
in, err := creds.InstallBoot(ctx, creds.BootOptions{
        Run:          creds.ExecRunner,
        DeploymentID: st.DeploymentID,
        Mode:         st.Config["credential-mode"],
        StateDir:     o.StateDir,
})
```

`UnitDir`, `RuntimeDir` and `Exe` stay zero in real runs; tests inject them. `InstallBoot`
is idempotent: a repeated or resumed setup rewrites nothing, skips `daemon-reload`, and
reports `Changed: false`.

It refuses `prompt` and `env`. A boot unit for `prompt` would need a person at every boot.
A boot unit for `env` would need the values written to disk in plaintext, which is the
silent downgrade the specification forbids. The refusal names the three modes that work.
Skip the phase for those two modes and tell the operator, exactly as the operator guide
already does for prompt-mode certificate renewal.

Record two created resources from the returned `BootInstalled`: `systemd-service` at
`in.ServicePath` and `backup-runtime` at `in.RuntimePath` — the same type name
`internal/schedule` records for the shared binary, so the two do not create a duplicate
entry for one file.

### The command you have to add

The unit runs `/usr/local/sbin/guacdeploy-runtime stack-start --state-dir DIR`. That
subcommand does not exist yet, and adding it means editing `main.go`, which is outside my
boundary. It is about fifteen lines in a new `cmd/guacdeploy/stack-start.go`:

```go
func stackStartCmd(ctx context.Context, stateDir string) error {
        st, err := state.Load(stateDir)                   // however main.go loads it
        if err != nil {
                return err
        }
        mode := st.Config["credential-mode"]
        if !creds.Persistent(mode) {
                return fmt.Errorf("credential mode %q cannot start the stack unattended", mode)
        }
        m := &creds.Manager{Mode: mode, Dir: filepath.Join(stateDir, "credentials"),
                Run: creds.ExecRunner}
        password, err := m.Get(creds.Spec{Name: "postgres-password"})
        if err != nil {
                return err
        }
        // The tunnel token is fetched at start time, as stackSecrets does today.
        return stack.Up(ctx, stack.ExecRunner, cfgFromState(st), password, tunnelToken)
}
```

Dispatch it as `case "stack-start":`. The constant `creds.BootCommand` holds the
subcommand name so the two cannot drift apart.

`renew-cert` needs no change. It builds a `creds.Manager` without a `Run` field, which
defaults to `ExecRunner`, so the two encrypted modes work there as soon as the session can
select them. Its prompt-mode refusal is still correct.

## 6. Teardown

```go
removed, err := creds.UninstallBoot(ctx, creds.BootOptions{
        Run: creds.ExecRunner, DeploymentID: st.DeploymentID})
```

It disables and stops the unit, removes it only when its first line carries this
deployment's marker, and reloads systemd. A same-named unit written by anything else is
left in place and named in the returned error, exactly like `schedule.Uninstall`. Missing
files are not an error, so teardown is repeatable.

The runtime binary is shared with the backup timer, so `UninstallBoot` removes it only when
no other `guacdeploy-*.service` or `guacdeploy-*.timer` in the unit directory still
mentions it. Order does not matter: whichever teardown runs last removes the binary. A
non-nil error with a non-empty `removed` means some files went and others were left because
they belong to someone else. Report both.

Sealed blobs are removed with the rest of `<state-dir>/credentials/` by whatever already
removes the plaintext credential directory. There is nothing extra to delete, and nothing
to revoke: the key never left the host.

## 7. What this does not do, and you should know it

- **Docker no longer keeps its own copy of the password.** It used to: the compose
  services carry `restart: always`, and Docker records a container's environment in
  `/var/lib/docker/containers/<id>/config.v2.json`, so delivering the password as an
  environment field left a persistent plaintext copy on disk that this package could not
  encrypt. `internal/stack` now writes each credential to an owner-only file on tmpfs and
  the containers read it for themselves; see `internal/stack/WIRING.md` for the mechanism
  per image and for `stack.CheckDelivery`, which proves no copy reached Docker's metadata.
  The boot unit is what repopulates that tmpfs after a cold boot, so it is now load-bearing
  rather than a convenience: without it the containers Docker restarts by itself come up
  with no credential.
- **`host+tpm2`, not `tpm2` alone.** Both bind to one machine, so neither survives a move
  to a replacement host. `host+tpm2` additionally requires the root-only host secret, so
  reading the TPM is not sufficient by itself. It is systemd's own default.
- **No migration between modes.** Changing `credential-mode` on an existing deployment
  leaves the old blob or file in place and the new mode has nothing to read. The operator
  must re-supply the credentials. If you want a `guacdeploy rotate-credentials`, that is a
  separate slice.
- **`systemd-creds` needs root** for the host key at `/var/lib/systemd/credential.secret`.
  The tool already runs as root.
- **Detection is not a guarantee.** `has-tpm2` reporting `yes` means the TPM is usable, not
  that sealing will succeed. A seal that fails still fails loudly and stores nothing.

## 8. Tests, and what they do not prove

`go test ./internal/creds/` covers mode detection with reasons, an encrypt and decrypt
round trip for both encrypted modes, the absence of the secret from every recorded argument
and from every error string, 0600 blobs in a 0700 directory, the refusal to fall back to
plaintext, a decrypt failure reported as an error rather than an empty credential, and the
honesty of every explanation. Eleven mutations of the load-bearing logic were each checked
to turn a test red.

All of it runs through injected seams. **No test has ever run `systemd-creds`, touched a
TPM, or rebooted anything.** Live verification on the Rocky Linux test platform is still
outstanding: a real seal and unseal on VM133 with its vTPM 2.0, the same on a VM without a
TPM to exercise `host` mode, a reboot with the provisioning binary deleted, and a restore
onto a replacement VM to confirm that the sealed credential does not travel and the
operator is told to re-supply it.
