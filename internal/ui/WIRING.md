# Wiring the full-screen wizard

The full-screen guided interface lives in `internal/ui/wizard.go`. It is off until a
caller turns it on. Nothing outside `internal/ui` changed, so the repository compiles and
behaves exactly as before until the two edits below are made.

Both edits are small. Neither changes unattended behaviour.

## 1. Start the wizard for guided setup

File: `cmd/guacdeploy/main.go`, in the `case "setup":` branch, before `session.Run`.

```go
case "setup":
	u.StartWizard() // full screen when the terminal supports it; plain lines otherwise
	opts := session.Options{
```

`StartWizard` reports whether it started. Ignore the result: every call in `ui` already
falls back to the line-oriented output when it returns false. It returns false, and
changes nothing, when any of these is true:

- `--non-interactive` was passed, or stdin is not a terminal.
- Stdout is not a terminal (a pipe or a redirect).
- `TERM` is unset or `dumb`.
- The terminal refuses raw mode.

Do not call it for the other commands. They print a report and exit, so a full screen that
closes immediately would help nobody.

`defer u.RestoreTerminal()` and the signal handler in `main` already do the right thing.
`RestoreTerminal` now leaves the alternate screen, restores the terminal settings and
replays the session output, at most once, whichever path reaches it: normal exit,
cancellation, a signal, or a panic unwinding through the deferred call.

## 2. Report phase status from the session

File: `internal/session/session.go`, function `runPhases`. Five edits, all replacing
`u.Say` calls that already exist. The plain-text output of each new method is the exact
line `u.Say` printed before, so the non-interactive path is unchanged byte for byte.

```go
func runPhases(ctx context.Context, store *state.Store, st *state.State, u *ui.UI, opts *Options, phases []Phase) error {
	names := make([]string, 0, len(phases))
	for _, p := range phases {
		names = append(names, p.Name)
	}
	u.PhaseList(names) // (a) declare the registry; prints nothing in plain output

	done := map[string]bool{}
	...
	for _, p := range phases {
		if done[p.Name] && !p.Always {
			u.PhaseSkipped(p.Name) // (b) was: u.Say("Phase %s: already complete, skipping.", p.Name)
			continue
		}
		...
		u.PhaseStart(p.Name) // (c) new call, immediately before the phase runs
		err := p.Run(ctx, st, u)
		...
		if err != nil {
			...
			u.PhaseFailed(p.Name, err) // (d) was the two u.Say lines below
			// u.Say("Phase %s failed: %v", p.Name, err)
			// u.Say("Completed work is retained. Run setup again to resume or clean up.")
			return err
		}
		...
		u.PhaseDone(p.Name) // (e) was: u.Say("Phase %s: complete.", p.Name)
	}
```

Nothing else in `session` needs to change. Phases keep calling `u.Say`, `u.Line`,
`u.Choose`, `u.Confirm` and `u.HiddenLine` exactly as they do now.

Partial wiring degrades sensibly. If only (a) is missed, phases appear in the status list
as they start, without the phases still to come. If only (c) is missed, no phase is ever
shown as running.

## What changes for the operator

While the wizard runs:

- The phase list shows what is done, what is running, what failed, what an earlier session
  already completed, and what is still to come. The bracketed word carries the state;
  colour only repeats it, and `NO_COLOR` turns colour off.
- Prompts accept the arrow keys or `j`/`k`, `Enter` to confirm, and the letter shown in
  brackets as a shortcut. The letter wins over `j`/`k` if a prompt ever offers those keys.
- The footer always shows `Ctrl-C  Cancel. Completed work is retained.`
- A failed phase prints three labelled lines: the action that failed, the work that was
  retained, and the recovery choices.

## Exit codes

`Ctrl-C` inside the wizard does not raise `SIGINT`, because raw mode delivers it as a key.
The wizard restores the terminal, prints the same notice `main` prints for a signal, and
returns `context.Canceled`. `main` already maps that to exit code 130, so no change is
needed. `SIGTERM`, and `SIGINT` outside a prompt, still reach the existing handler.
