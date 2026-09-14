# Terminal interface integration

`cmd/guacdeploy/main.go` starts the full-screen wizard for setup and preview.
Other commands keep their reports on the ordinary terminal screen.

## Components

- `ui.go` provides prompts, phase events, explanations, and summaries.
- `wizard.go` handles keyboard input, resizing, animation, and terminal restoration.
- `presentation.go` lays out the current task, actions, stages, and details view.
- `brand.go` adapts the Proaxiom submark and palette for terminal cells.
- `task_progress.go` reports measured task counts without estimating duration.
- `journal.go` records timestamped events and redacts credentials.
- `preview.go` exercises the interface with labelled example data and no resources.

Phases use `PhaseList`, `PhaseStart`, `PhaseDone`, `PhaseSkipped`, and `PhaseFailed`.
Prompts use `Choose`, `Confirm`, `Line`, and `HiddenLine`. Do not write directly to
stdout while the wizard runs. Each redraw writes one buffered frame under a lock.
Later frames update changed lines; resizing clears and redraws the entire view.

Use `TaskProgress(label, completed, total)` only when the operation knows the total.
The label must explain what is counted. Network checks count attempts, not successes.
The next phase clears the count. Invalid or unknown totals do not draw a bar.

Use `Explain` for a short status with longer guidance in Details. Use `Transient`
for a device sign-in challenge, then `ClearTransient` when authorization ends.
Transient content never enters history or the session log. Use `Protect` for a
credential acquired outside the standard hidden-input or credential-manager paths.

## Layout and input

The current task has priority. Wide terminals add a stage navigator. Tab opens
session details. Page Up and Page Down scroll long guidance and event history.
Choice controls and input fields remain visible while instructions scroll.

The minimum size is 48 columns by 16 rows. Smaller terminals show a resize message
and ignore action keys. They continue to permit cancellation.

Bracketed paste enters text as one value. It cannot select a menu action. Hidden
input shows a bounded mask. The input limit is 16,384 characters. A lone Escape
cancels after 150 ms; arrow sequences can arrive in separate terminal reads.

`NO_COLOR` removes colour. `GUACDEPLOY_ASCII` selects ASCII status graphics.
`GUACDEPLOY_REDUCED_MOTION` stops activity animation. Redirected output, an unset
or dumb terminal, and unattended commands use plain output.

## Exit and logging

Restore the terminal before printing the final error or log path. Restoration is
idempotent. It disables bracketed paste, leaves the alternate screen, restores
terminal settings, and prints a concise result. It does not replay the transcript.

On Linux, Ctrl-C remains a terminal signal while the wizard runs. Ctrl-Z and
Ctrl-backslash are disabled. The command handles SIGINT and SIGTERM, preserves
completed work, restores the terminal, and exits with code 130.

Setup, teardown, and recovery open one private log per invocation. `FinishLog`
reports its path and any write failure. See the operator guide for permissions,
retention, size limits, and excluded content. Session details keep up to 500 events.

## Verification

Run `go test ./internal/ui`. On Linux this includes the real terminal acceptance
checks. For the command-level checks, build `guacdeploy` and run:

```sh
python3 tests/wizard_interactive_test.py /path/to/guacdeploy
```

These checks use preview data. They verify quit, Escape, Ctrl-C, SIGTERM, resizing,
paste handling, and terminal restoration. The release workflow runs both suites.
