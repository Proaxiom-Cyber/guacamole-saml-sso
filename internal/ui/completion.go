package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// FinalScreen keeps the outcome visible until the operator chooses to leave.
// EOF (a disconnected terminal) cannot be acknowledged; unattended runs never wait.
func (u *UI) FinalScreen(command string, outcome error) error {
	if !u.Interactive {
		return nil
	}
	lines := append([]string(nil), u.summary...)
	if w := u.wizard(); w != nil {
		w.mu.Lock()
		lines = append([]string(nil), w.summary...)
		if len(w.names) > 0 {
			done := 0
			for _, status := range w.state {
				if status == phaseDone || status == phaseSkipped {
					done++
				}
			}
			lines = append(lines, fmt.Sprintf("%d of %d steps complete.", done, len(w.names)))
		}
		w.challenge = ""
		w.finalScreen = true
		w.mu.Unlock()
	}
	if outcome != nil {
		title := "Stopped: this operation needs attention."
		if errors.Is(outcome, context.Canceled) {
			title = "Cancelled. Completed work is saved."
		}
		lines = append([]string{title, ""}, lines...)
		if !errors.Is(outcome, context.Canceled) {
			lines = append(lines, u.ErrorText(outcome))
		}
		if command == "setup" || command == "teardown" || command == "recover" {
			lines = append(lines, "Review saved progress with: sudo /usr/local/bin/guacdeploy")
		}
	}
	if len(lines) == 0 {
		lines = []string{"Session finished."}
	}
	u.Summary(lines...)
	if path := u.LogPath(); path != "" {
		lines = append(lines, "", "Session log: "+path)
	}
	lines = append(lines, "", "Review this summary, then choose Finish and return to the shell.")
	for {
		_, err := u.Choose(strings.Join(lines, "\n"), []Choice{{Key: 'f', Label: "Finish and return to the shell", Description: "Close the summary and return to the command line. Deployment services continue according to the status shown above."}})
		if errors.Is(err, context.Canceled) {
			continue
		}
		if u.wizard() == nil {
			fmt.Fprintln(u.Out)
		}
		return err
	}
}

// CompletionScreen is retained for callers that only have a successful result.
func (u *UI) CompletionScreen() error { return u.FinalScreen("setup", nil) }
