# Terminal design

The installer uses an expressive console layout. The current decision occupies the
main pane. A compact navigator shows the surrounding deployment steps on wide screens.
Narrow screens keep the current step and its actions visible.

Use the terminal's foreground and background. Blue marks the current action, green
marks completion, and red marks failure. State labels carry the same meaning without
colour. Use a bold title strip, a strong progress graphic, and visible activity animation.
Avoid emoji, decorative dashboards, and guessed completion times.

A single activity indicator and elapsed time show that a request is still running.
The progress bar counts completed steps, including work verified on an earlier run.
It does not estimate the duration of unfinished work. Reduced motion disables animation.

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
