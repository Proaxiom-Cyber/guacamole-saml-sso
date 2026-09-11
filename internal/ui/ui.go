// Package ui provides the terminal primitives for the guided wizard and the
// readable output of unattended mode. Text identifies success, failure, and
// required action; colour would be supplementary and arrives with the full
// terminal experience (issue #23).
package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrInputRequired is returned when a prompt is reached without an
// interactive terminal. Unattended operation never waits for input.
var ErrInputRequired = errors.New("interactive input required")

// Choice is one selectable option in a prompt.
type Choice struct {
	Key   rune
	Label string
}

// UI wraps input/output for one session.
type UI struct {
	In          *bufio.Reader
	Out         io.Writer
	Interactive bool

	// Secret overrides hidden input, for tests.
	Secret func(prompt string) (string, error)

	fd    int
	saved *term.State
}

// SecretReader returns the hidden-input function for this UI, or nil when
// no interactive terminal is available.
func (u *UI) SecretReader() func(string) (string, error) {
	if u.Secret != nil {
		return u.Secret
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
	u := &UI{In: bufio.NewReader(os.Stdin), Out: os.Stdout, fd: int(os.Stdin.Fd())}
	if allowInteractive && term.IsTerminal(u.fd) {
		u.Interactive = true
		if s, err := term.GetState(u.fd); err == nil {
			u.saved = s
		}
	}
	return u
}

// RestoreTerminal returns the terminal to its saved settings. Safe to call
// multiple times and from a signal handler.
func (u *UI) RestoreTerminal() {
	if u.saved != nil {
		term.Restore(u.fd, u.saved)
	}
}

// Say writes one line to the user.
func (u *UI) Say(format string, args ...any) {
	fmt.Fprintf(u.Out, format+"\n", args...)
}

// Choose presents options and reads one. It re-asks on unrecognised input.
func (u *UI) Choose(prompt string, choices []Choice) (rune, error) {
	if !u.Interactive {
		return 0, fmt.Errorf("%w: %s", ErrInputRequired, prompt)
	}
	for {
		fmt.Fprintf(u.Out, "%s\n", prompt)
		for _, c := range choices {
			fmt.Fprintf(u.Out, "  [%c] %s\n", c.Key, c.Label)
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
	for {
		if def != "" {
			fmt.Fprintf(u.Out, "%s [%s]: ", prompt, def)
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
	k, err := u.Choose(prompt, []Choice{{'y', "Yes"}, {'n', "No"}})
	return k == 'y', err
}

// HiddenLine reads a line without echo, for credential prompts. The value
// must never be logged or persisted by callers.
func (u *UI) HiddenLine(prompt string) (string, error) {
	if !u.Interactive {
		return "", fmt.Errorf("%w: %s", ErrInputRequired, prompt)
	}
	fmt.Fprintf(u.Out, "%s: ", prompt)
	b, err := term.ReadPassword(u.fd)
	fmt.Fprintln(u.Out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
