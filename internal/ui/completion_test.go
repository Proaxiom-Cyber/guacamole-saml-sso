package ui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCompletionNeedsAcknowledgementAndKeepsSummary(t *testing.T) {
	u, out, restores := newTestUI("f")
	u.Summary("Setup complete.", "Deployment: fixture", "Open https://example.com/")
	if err := u.CompletionScreen(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Setup complete.", "Deployment: fixture", "https://example.com/", "Finish and return to the shell"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("missing " + want)
		}
	}
	if *restores != 0 {
		t.Fatal("completion restored terminal before caller exited")
	}
	u.RestoreTerminal()
	if *restores != 1 {
		t.Fatal("terminal was not restored")
	}
}
func TestCompletionDoesNotSilentlyExitWithoutInput(t *testing.T) {
	u, _, _ := newTestUI("")
	u.Summary("Setup complete.")
	if err := u.CompletionScreen(); err == nil {
		t.Fatal("completion did not wait for input")
	}
}
func TestCompletionDoesNotPromptInPlainOutput(t *testing.T) {
	var out bytes.Buffer
	u := &UI{Out: &out}
	if err := u.CompletionScreen(); err != nil || out.Len() != 0 {
		t.Fatal("plain output must not prompt")
	}
}

func TestFinalScreenRequiresFinishAfterCancellation(t *testing.T) {
	u, out, restores := newTestUI("\x03f")
	u.PhaseList([]string{"one", "two"})
	u.PhaseDone("one")
	if err := u.FinalScreen("setup", context.Canceled); err != nil {
		t.Fatal(err)
	}
	if *restores != 0 {
		t.Fatal("returned to shell early")
	}
	for _, want := range []string{"Cancelled.", "1 of 2 steps complete", "Session summary", "Review saved progress"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
func TestFinalScreenRedactsFailure(t *testing.T) {
	u, out, _ := newTestUI("f")
	if err := u.StartLog(t.TempDir(), "setup"); err != nil {
		t.Fatal(err)
	}
	defer u.FinishLog(nil)
	u.Protect("test-secret-123")
	if err := u.FinalScreen("setup", errors.New("token test-secret-123 rejected")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "test-secret-123") {
		t.Fatal("secret shown in final screen")
	}
}
func TestFinalScreenPlainInteractiveWaits(t *testing.T) {
	var out bytes.Buffer
	u := &UI{Interactive: true, In: bufio.NewReader(strings.NewReader("f\n")), Out: &out}
	if err := u.FinalScreen("setup", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Finish and return") {
		t.Fatal("plain terminal omitted final acknowledgement")
	}
}
