# Wiring internal/settings into the command and the session

This package decides what may be restored and asks for approval. It knows no provider:
each one registers an `Accessor` under its `state.SettingChange.Provider` name. The
only accessor that exists today is `entra.SettingAccessor` (`internal/entra/restore.go`).

Issue #10 acceptance criteria, and where each one lives:

1. Record original and applied values before changing a pre-existing setting — already
   done by the Entra phase. See "What is already recorded" below for the verification,
   including one defect the parent should fix.
2. Restore only after approval and only while the current state still matches the
   applied value — `settings.List` and `settings.Restore`.
3. Preserve drifted settings and stop unattended runs before approval — the same two
   functions; a drifted entry is never written and never marked restored.

## One line in main.go

`cmd/guacdeploy/settings.go` holds the whole command. `main.go` needs the dispatch, two
flags, and the sentinel in the exit-3 branch:

```go
// with the other flags
list      := fs.Bool("list", false, "settings: show pending restorations, change nothing")
restoreCf := fs.Bool("restore", false, "settings: restore approved pre-existing settings")
_ = list // --list is the default; the flag exists so it parses

// in the command switch
case "settings":
        err = settingsCmd(ctx, *stateDir, *restoreCf, u)

// in the exit-code switch, alongside session.ErrApprovalRequired and ui.ErrInputRequired
case errors.Is(err, settings.ErrApprovalRequired):
        return 3
```

Add to `usage`:

```
  settings Show, and with --restore put back, pre-existing settings this deployment changed

Flags for settings:
  --list                   Show pending restorations without changing anything (default)
  --restore                Offer each restorable setting for approval and put it back
```

`--list` reads state without the deployment lock. `--restore` takes the lock through
`state.Open`, because it writes both at the provider and in the state record.

## The approval sentinel

`settings.ErrApprovalRequired` is this package's own sentinel, wrapped with `%w` into an
error that names every target waiting for approval. An unattended run reports what is
pending, writes nothing, and returns it. Map it to exit 3, the same code the session's
approval sentinel already uses. Drift is **not** an error: it is reported and the run
succeeds, because the current setting was preserved, which is the correct outcome.

## What is already recorded (criterion 1)

`internal/session/session.go` journals `res.Changes` after `entra.Apply`:

```go
st.Changes = append(st.Changes, state.SettingChange{
        ID: state.NewID(), Provider: "entra",
        Target:   "application/" + res.App.ObjectID + "/" + ch.Field,
        Original: ch.Original, Applied: ch.Applied,
})
```

`res.Changes` is non-empty only when the application was pre-existing and not proven
ours, which is the only case where this tool changes a setting it did not create. The
original and applied values are captured by `Plan`, before `Apply` sends anything, and
approval is taken before `Apply` runs. That part is correct and complete for the six
`FieldChange` names.

**One defect for the parent to fix, in session.go (not owned by this work).** Two of the
six fields belong to the service principal, not the application, yet the target names
`res.App.ObjectID` for all six. The field name is right, the object ID is not:

```go
target := "application/" + res.App.ObjectID + "/" + ch.Field
if strings.HasPrefix(ch.Field, "servicePrincipal.") {
        target = "servicePrincipal/" + res.App.SPObjectID + "/" + ch.Field
}
```

Until that lands, `entra.SettingAccessor` still handles the old shape: for a
`servicePrincipal.*` field recorded against an application object ID it reads the
application's `appId` and finds the service principal by it, which is the only link
between the two. Both target shapes work, so the fix is a clarity and one-fewer-request
improvement, not a blocker.

## What the Cloudflare Access phase must journal

**Today: nothing.** `internal/cloudflare` has no path that changes an application it does
not own. A pre-existing Access application returns `*PreExistingApp` and the run stops.
Its `Changes` field carries the original values for the operator to read; nothing was
applied, so there is no change to restore. Journalling a `SettingChange` for it would be
wrong — the restore would compare the live value against an `Applied` value that was
never written, report drift, and the operator would be told about a conflict that does
not exist.

**If that phase ever gains an approved overwrite path**, journal exactly like Entra, in
the same shape, immediately after the write succeeds:

```go
for _, ch := range pre.Changes { // cloudflare.FieldChange{Field, Original, Applied}
        st.Changes = append(st.Changes, state.SettingChange{
                ID: state.NewID(), Provider: "cloudflare",
                Target:   "accessApplication/" + pre.AppID + "/" + ch.Field,
                Original: ch.Original, Applied: ch.Applied,
        })
}
```

Rules the shape has to keep:

- **Provider** is `cloudflare`, matching the registry key the accessor is registered
  under in `settingsRegistry()`.
- **Target** is `<kind>/<objectID>/<field>` — the same three-part shape Entra uses, so
  an accessor can route on it without parsing free text. `kind` names the resource that
  actually owns the field; `field` is the `FieldChange.Field` name unchanged
  (`accessApplication.session_duration`, `accessApplication.allowed_idps`,
  `accessApplication.auto_redirect_to_identity`).
- **Original and Applied** are the raw JSON values as the API returns and accepts them.
  Record what was read, not a rendered string: the comparison is JSON-semantic, so key
  order and whitespace are free, but a value spelt differently from the API's own is a
  false drift verdict later.
- **Journal after the write, once per field.** A journal entry means "this tool changed
  this setting"; anything else makes every later run report a phantom conflict.
- **One entry per field, never per resource.** Restore writes one field at a time, so a
  setting that drifted does not block the ones beside it.

Then register the accessor in `cmd/guacdeploy/settings.go`:

```go
"cloudflare": cloudflare.SettingAccessor{...},
```

Until that exists, a recorded `cloudflare` change is reported as "cannot be restored
automatically" with its recorded values printed, and it is never marked restored. That
is the designed behaviour for an unknown provider, not a gap.

## Host configuration

The teardown contract applies the same rule to host configuration. `internal/host`
changes no pre-existing host setting today, so it journals nothing. Anything it later
changes (a firewall rule it did not create, an SELinux boolean, a sysctl) follows the
same shape with provider `host` and a target such as `firewalld/public/ports`.

## Teardown ordering

Run the restore **before** deleting created resources. Restoring
`servicePrincipal.preferredSingleSignOnMode` needs the service principal to still exist,
and `application.*` fields need the application. A restore after deletion can only
report failures.

## API surface

```go
type Reader interface{ Get(ctx context.Context, target string) (json.RawMessage, error) }
type Writer interface{ Set(ctx context.Context, target string, value json.RawMessage) error }
type Accessor interface{ Reader; Writer }
type Registry map[string]Accessor           // keyed by SettingChange.Provider

func List(ctx, *state.State, Registry) []Entry   // reads providers, writes nothing
func Report(*ui.UI, []Entry)                     // prints; changes nothing
func Restore(ctx, *state.State, Registry, *ui.UI, save func() error) error

var ErrApprovalRequired error                    // wrap-checked with errors.Is
```

`Entry.Status` is `restorable`, `drifted`, `unsupported`, or `unreadable`. Only
`restorable` is ever offered for approval, and only an approved, successful `Set` sets
`RestoredAt`. `save` is called after each successful write so an interruption cannot
lose the record that a setting was already put back; it may be nil in tests.
