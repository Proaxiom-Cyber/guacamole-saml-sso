# Terminal design

The installer uses an expressive console layout. The current decision occupies the
main pane. A compact navigator shows the surrounding deployment steps on wide screens.
Narrow screens keep the current step and its actions visible.

Use the terminal's foreground and background for body text. Proaxiom navy marks the
current action, green marks completion, and red marks failure. State labels carry the
same meaning without colour. Use a strong progress graphic and visible activity animation.
Avoid emoji, decorative dashboards, and guessed completion times.

A single activity indicator and elapsed time show that a request is still running.
The progress bar counts completed steps, including work verified on an earlier run.
It does not estimate the duration of unfinished work. Reduced motion disables animation.

Large terminals show a five-bar adaptation of the Proaxiom submark. A highlight moves
through its bars during work and stops during questions. Small terminals use a compact
Proaxiom heading and activity indicator. The mark retains its stagger and final dot.
Its five colours come from the shared branding repository's logo assets: `#084054`,
`#4e8e99`, `#29a1b9`, `#75c9b9`, and `#f26867`. A light background keeps the navy bar
visible on dark terminals. True-colour terminals use these values; other colour
terminals use the nearest 256-colour palette entries.

Task progress reports measured counts from the operation. Network checks show completed
checks, including failures. This count does not mean that every check passed. Operations
without a known total use the activity indicator; never estimate their percentage.

Instructions say where to act, what to do, and what happens after confirmation. Explain
administrator authorization separately from the certificate used by the installer.
Device-code authorization and a host-generated certificate belong in the same flow.

The primary view shows recent status. A details view contains timestamped history.
Long content scrolls within the viewport. Keyboard hints remain visible. Secret input
and device authorization challenges never enter history or the session log.

Keep the existing provisioning interfaces. Separate terminal layout, input handling,
and diagnostic logging. Verify normal, narrow, monochrome, cancelled, and failed states.

Design reference: the installed pageton/tui-design-skill, especially form workflows,
log viewing, and terminal stability. This terminal-specific guidance supersedes web
presentation conventions from the earlier general design pass.
