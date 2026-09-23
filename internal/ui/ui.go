// Package ui provides the terminal primitives for the guided wizard and the
// readable output of unattended mode. Text identifies success, failure, and
// required action; colour is supplementary.
//
// The guided path may run full screen: UI.StartWizard switches prompts,
// output and phase status onto the alternate screen buffer (see wizard.go).
// Everything degrades to the line-oriented output here when the terminal
// cannot support it, and unattended mode never waits for input either way.
package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// ErrInputRequired is returned when a prompt is reached without an
// interactive terminal. Unattended operation never waits for input.
var ErrInputRequired = errors.New("interactive input required")

// Choice is one selectable option in a prompt.
type Choice struct {
	Key         rune
	Label       string
	Description string
}

// UI wraps input/output for one session.
type UI struct {
	In          *bufio.Reader
	Out         io.Writer
	Interactive bool

	// Secret overrides hidden input, for tests.
	Secret func(prompt string) (string, error)

	fd        int
	saved     *term.State
	journal   *journal
	summary   []string
	interrupt chan struct{}
	wiz       *Wizard // non-nil once StartWizard succeeds; never cleared
}

// SecretReader returns the hidden-input function for this UI, or nil when
// no interactive terminal is available.
func (u *UI) SecretReader() func(string) (string, error) {
	if u.Secret != nil {
		return func(prompt string) (string, error) {
			value, err := u.Secret(prompt)
			u.Protect(value)
			return value, err
		}
	}
	if !u.Interactive {
		return nil
	}
	return u.HiddenLine
}

// New builds a UI on stdin/stdout. Interactive requires stdin to be a
// terminal and the flag to allow it. When interactive, the terminal state is
// saved so RestoreTerminal can undo a prompt interrupted mid-read.
func New(allowInteractive bool) *UI {
	u := &UI{In: bufio.NewReader(os.Stdin), Out: os.Stdout, fd: int(os.Stdin.Fd()), interrupt: make(chan struct{}, 1)}
	if allowInteractive && term.IsTerminal(u.fd) {
		u.Interactive = true
		if s, err := term.GetState(u.fd); err == nil {
			u.saved = s
		}
	}
	return u
}

// RestoreTerminal returns the terminal to its saved settings, leaving the
// full-screen view first and printing a short progress summary. Safe to call
// multiple times, from a signal handler, and while a panic unwinds: the
// wizard leaves the alternate screen exactly once.
func (u *UI) RestoreTerminal() {
	if u.wiz != nil {
		u.wiz.stop()
	}
	if u.saved != nil {
		term.Restore(u.fd, u.saved)
	}
}

// Say writes one line to the user.
func (u *UI) Say(format string, args ...any) {
	s := u.safe(fmt.Sprintf(format, args...))
	u.record(eventLevel(s), s)
	if w := u.wizard(); w != nil {
		w.say(s)
		return
	}
	if u.journal != nil {
		for i, line := range strings.Split(s, "\n") {
			stamp := "        "
			if i == 0 {
				stamp = time.Now().Format("15:04:05")
			}
			fmt.Fprintf(u.Out, "%s | %s\n", stamp, line)
		}
		fmt.Fprintln(u.Out)
	} else {
		fmt.Fprintln(u.Out, s)
	}
}

// PhaseList declares the ordered phases of the session, so the full-screen
// view can show what is done, what is running, what failed and what is still
// to come. It writes nothing in line-oriented output.
func (u *UI) PhaseList(names []string) {
	if w := u.wizard(); w != nil {
		w.setPhases(names)
	}
}

// PhaseStart marks a phase as running. It writes nothing in line-oriented
// output, which reports a phase only once it has finished.
func (u *UI) PhaseStart(name string) {
	if j := u.journal; j != nil {
		j.mu.Lock()
		j.phase = name
		j.mu.Unlock()
	}
	u.record("START", name)
	if w := u.wizard(); w != nil {
		w.setPhase(name, phaseRunning)
	}
}

// PhaseDone marks a phase as complete.
func (u *UI) PhaseDone(name string) {
	u.record("DONE", name)
	if w := u.wizard(); w != nil {
		w.setPhase(name, phaseDone)
		return
	}
	u.Say("Phase %s: complete.", name)
}

// PhaseSkipped marks a phase that an earlier session already completed.
func (u *UI) PhaseSkipped(name string) {
	u.record("SKIP", name+" already complete")
	if w := u.wizard(); w != nil {
		w.setPhase(name, phaseSkipped)
		return
	}
	u.Say("Phase %s: already complete, skipping.", name)
}

// PhaseFailed reports a failed phase. Both outputs name the action that
// failed, the work that was retained, and the recovery choices.
func (u *UI) PhaseFailed(name string, err error) {
	err = errors.New(u.safe(err.Error()))
	u.record("ERROR", name+": "+err.Error())
	if w := u.wizard(); w != nil {
		w.failed(name, err)
		return
	}
	u.Say("Phase %s failed: %v", name, err)
	u.Say("Completed work is retained. Run setup again to resume or clean up.")
}

// Choose presents options and reads one. It re-asks on unrecognised input.
func (u *UI) Choose(prompt string, choices []Choice) (rune, error) {
	if !u.Interactive {
		return 0, fmt.Errorf("%w: %s", ErrInputRequired, prompt)
	}
	if w := u.wizard(); w != nil {
		return w.choose(prompt, choices)
	}
	for {
		fmt.Fprintf(u.Out, "%s\n", prompt)
		for _, c := range choices {
			fmt.Fprintf(u.Out, "  [%c] %s\n", c.Key, c.Label)
			if c.Description != "" {
				fmt.Fprintf(u.Out, "      %s\n", c.Description)
			}
		}
		fmt.Fprint(u.Out, "> ")
		line, err := u.In.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		for _, c := range choices {
			if len(line) == 1 && rune(line[0]) == c.Key {
				return c.Key, nil
			}
		}
		u.Say("Enter one of the listed keys.")
	}
}

// Line reads one non-secret line, offering a default. Empty input takes the
// default; with no default it re-asks.
func (u *UI) Line(prompt, def string) (string, error) {
	if !u.Interactive {
		return "", fmt.Errorf("%w: %s", ErrInputRequired, prompt)
	}
	if w := u.wizard(); w != nil {
		return w.readLine(prompt, def, false)
	}
	for {
		if def != "" {
			fmt.Fprintf(u.Out, "%s\n> %s (suggested; Enter accepts this default, or type a replacement): ", prompt, def)
		} else {
			fmt.Fprintf(u.Out, "%s: ", prompt)
		}
		line, err := u.In.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
		if def != "" {
			return def, nil
		}
		u.Say("A value is required.")
	}
}

// Confirm asks a yes/no question.
func (u *UI) Confirm(prompt string) (bool, error) {
	return u.ConfirmWithHelp(prompt, "Approve the action described above. Read the listed changes and consequences before continuing.", "Decline this action. It will not be performed; the workflow may return to an earlier choice or finish with progress retained.")
}

// ConfirmWithHelp explains both outcomes for decisions with specific consequences.
func (u *UI) ConfirmWithHelp(prompt, yesHelp, noHelp string) (bool, error) {
	k, err := u.Choose(prompt, []Choice{{Key: 'y', Label: "Yes", Description: yesHelp}, {Key: 'n', Label: "No", Description: noHelp}})
	return k == 'y', err
}

// HiddenLine reads a line without echo, for credential prompts. The value
// must never be logged or persisted by callers.
func (u *UI) HiddenLine(prompt string) (string, error) {
	if !u.Interactive {
		return "", fmt.Errorf("%w: %s", ErrInputRequired, prompt)
	}
	if w := u.wizard(); w != nil {
		value, err := w.readLine(prompt, "", true)
		u.Protect(value)
		return value, err
	}
	fmt.Fprintf(u.Out, "%s: ", prompt)
	b, err := term.ReadPassword(u.fd)
	fmt.Fprintln(u.Out)
	if err != nil {
		return "", err
	}
	u.Protect(string(b))
	return string(b), nil
}

// Explain keeps an optional explanation in Details and the log, while the
// current task receives its short summary. Plain terminals print both.
func (u *UI) Explain(summary, detail string) {
	if w := u.wizard(); w != nil {
		text := u.safe(detail)
		u.record("NOTE", text)
		w.mu.Lock()
		w.notes = append(w.notes, summary, text, "")
		w.mu.Unlock()
		u.Say("%s", summary)
		return
	}
	u.Say("%s\n%s", summary, detail)
}

// Summary is retained after the alternate screen closes.
func (u *UI) Summary(lines ...string) {
	u.summary = append([]string(nil), lines...)
	if w := u.wizard(); w != nil {
		w.mu.Lock()
		w.summary = append([]string{}, lines...)
		w.mu.Unlock()
		for _, l := range lines {
			u.record("INFO", l)
		}
		return
	}
	for _, l := range lines {
		u.Say("%s", l)
	}
}

func (u *UI) ErrorText(err error) string {
	if err == nil {
		return ""
	}
	return u.safe(err.Error())
}

// FullScreen reports whether the guided terminal view is active.
func (u *UI) FullScreen() bool { return u.wizard() != nil }

// Interrupt releases a pending wizard prompt after an operating-system signal.
// It does not restore the terminal; the caller first saves state and shows the result.
func (u *UI) Interrupt() {
	if u.interrupt != nil {
		select {
		case u.interrupt <- struct{}{}:
		default:
		}
	}
}

// ReviewPhase moves the visible task focus without rewriting execution history.
// The returned function restores the previous focus after a nested review screen.
func (u *UI) ReviewPhase(name string) func() {
	w := u.wizard()
	if w == nil {
		return func() {}
	}
	w.mu.Lock()
	previous := w.viewedPhase
	w.viewedPhase = name
	w.scroll = 0
	w.mu.Unlock()
	w.redraw()
	return func() {
		w.mu.Lock()
		w.viewedPhase = previous
		w.scroll = 0
		w.mu.Unlock()
		w.redraw()
	}
}
