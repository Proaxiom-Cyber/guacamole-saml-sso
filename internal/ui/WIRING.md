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
- The footer always shows `Ctrl-C  Cancel. Completed work is retained.`, and on Linux that
  is true at every moment, not only at a prompt.
- Output from a phase, a change of phase status and a resize all keep an unanswered
  question on screen. Answering one takes it off.
- A failed phase prints three labelled lines: the action that failed, the work that was
  retained, and the recovery choices.

## Cancelling and exit codes

On Linux the wizard keeps the terminal's signal characters while it holds raw mode, so
`Ctrl-C` raises `SIGINT` from anywhere, a long running phase included, and reaches the
existing handler in `main`. That handler restores the terminal, prints its notice and
exits 130. Nothing in `main` needs to change for this.

Full raw mode would have made `Ctrl-C` an ordinary key. That is enough at a prompt, where
the wizard is reading the keyboard, but during a phase nothing reads it, so the key was
never seen and the footer's offer to cancel was false. A pseudo-terminal test proves both
cases now exit 130 with the terminal restored.

`Ctrl-Z` and `Ctrl-\` are switched off while the wizard runs. Either would leave the
terminal raw and on the alternate screen with nothing left running to put it back.

`Escape` still cancels as a key. The wizard restores the terminal, prints the same notice,
and returns `context.Canceled`, which `main` already maps to 130. That path is also the
fallback on platforms other than Linux, where the signal characters cannot be kept.

## One change still needed in main.go

**The final error message is lost.** `run` prints `guacdeploy: <err>` to stderr and only
then returns, so the deferred `u.RestoreTerminal()` runs afterwards. The message is drawn
on the alternate screen and destroyed when the wizard leaves it. On a failure before the
first phase the operator sees exit code 1 and an empty terminal.

Reproduce it on a terminal:

```sh
TERM=xterm-256color script -qec "guacdeploy setup --state-dir /proc/nope/x" /dev/null | cat -v
```

The fix is to leave the full-screen view before writing the message. `RestoreTerminal` is
idempotent, so an explicit call costs nothing:

```go
	// Leave the full-screen view before anything is written about the result:
	// the alternate screen is discarded when it closes, and a message drawn on
	// it goes with it.
	u.RestoreTerminal()

	switch {
	case err == nil:
		return 0
	...
```

A failed phase is less badly affected, because the wizard replays its own transcript,
including the three-line error block, when it leaves the alternate screen. The final
`guacdeploy: <err>` line is still lost.

## Resizing

The wizard follows `SIGWINCH` and redraws at the new size. Without that the frame keeps
the width it started with, and a narrower window wraps every rule so the top of the screen
scrolls away. Below 20 rows or 40 columns the frame is deliberately not shrunk further; it
is taller than the window at that point, which is the documented floor.

## Running the terminal tests

The unit tests run everywhere. The acceptance tests need a real terminal and are Linux
only, because macOS does not report the `/dev/ptmx` master as a terminal:

```sh
go test ./internal/ui/ -run PTY -v
```
