package ui

import (
	"strings"
	"testing"
)

func TestInstructionsControlsThenLogAcrossWorkflows(t *testing.T) {
	for _, phase := range []string{"credential-mode", "stack-up", "teardown"} {
		for _, cols := range []int{80, 104, 140, 220} {
			u, _, _ := newTestUI("")
			w := u.wiz
			w.cols, w.rows = cols, 48
			w.active = phase
			w.selectionHelp = "Keep the deployment data."
			w.log = []string{"12:00:00 | An earlier event."}
			frame := strings.Join(w.frame([]string{"Read this instruction", "", "> [y] Continue", "  [n] Back", "", "Enter Choose"}), "\n")
			instruction, control, log := strings.Index(frame, "Read this instruction"), strings.Index(frame, "> [y] Continue"), strings.Index(frame, "LIVE LOG")
			if instruction < 0 || control <= instruction || log <= control {
				t.Fatalf("%s %d: wrong pane order:\n%s", phase, cols, frame)
			}
			if !strings.Contains(frame, "Keep the deployment data.") {
				t.Fatalf("missing option help: %s", frame)
			}
		}
	}
}

func TestLongInstructionsScrollWithInputVisible(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.cols, w.rows = 140, 45
	prompt := []string{strings.Repeat("Instruction line\n", 50), "> _", "Enter Continue"}
	w.frame(prompt)
	if !w.instructionsOverflow {
		t.Fatal("long instructions were not scrollable")
	}
	w.viewKey(keyPageDown)
	frame := strings.Join(w.frame(prompt), "\n")
	if w.scroll == 0 || !strings.Contains(frame, "> _") {
		t.Fatalf("scroll hid input: %s", frame)
	}
	if !strings.Contains(frame, "LIVE LOG") {
		t.Fatal("lost bottom log")
	}
}

func TestInputDefaultsAndEnteredValues(t *testing.T) {
	for _, typed := range []string{"\r", "replacement\r"} {
		u, out, _ := newTestUI(typed)
		value, err := u.Line("Deployment name", "suggestion")
		want := "suggestion"
		if typed != "\r" {
			want = "replacement"
		}
		if err != nil || value != want {
			t.Fatalf("%q %v", value, err)
		}
		if !strings.Contains(out.String(), "> suggestion (suggested)") || !strings.Contains(out.String(), "Enter accepts this default") {
			t.Fatalf("missing field suggestion: %s", out.String())
		}
	}
	u, out, _ := newTestUI("custom\x02\r")
	if _, err := u.BackLine("Deployment name", "suggestion"); err != ErrBack {
		t.Fatal(err)
	}
	out.Reset()
	value, err := u.BackLine("Deployment name", "suggestion")
	if err != nil || value != "custom" {
		t.Fatalf("lost edit after Back: %q %v", value, err)
	}
	if !strings.Contains(out.String(), "> custom_") || strings.Contains(out.String(), "(suggested)") {
		t.Fatal("entered value shown as suggestion")
	}
}

func TestHiddenInputNeverShowsOrAcceptsDefault(t *testing.T) {
	u, out, _ := newTestUI("\r")
	got, err := u.wiz.readLine("Secret", "secret-fixture-must-not-appear", true)
	if err != nil || got != "" {
		t.Fatalf("secret default accepted: %q %v", got, err)
	}
	if strings.Contains(out.String(), "secret-fixture") {
		t.Fatal("secret suggestion leaked")
	}
}

func TestSuggestedInputUsesMutedColourOnlyWhenEnabled(t *testing.T) {
	u, _, _ := newTestUI("")
	line := "> example (suggested)"
	u.wiz.colour = true
	if !strings.Contains(u.wiz.paint(line), "\x1b[90m") {
		t.Fatal("suggestion not muted")
	}
	u.wiz.colour = false
	if u.wiz.paint(line) != line {
		t.Fatal("plain output contains colour")
	}
}

func TestBottomLogKeepsHistoryAndSidebar(t *testing.T) {
	u, _, _ := newTestUI("")
	w := u.wiz
	w.cols, w.rows = 140, 45
	u.PhaseList([]string{"host-preflight", "credential-mode", "configure-review", "host-dependencies", "stack-configure", "stack-up", "entra-signin", "cloudflare-dns"})
	for i := 0; i < 100; i++ {
		w.log = append(w.log, "12:00:00 | history event")
	}
	prompt := []string{"Choose protection", "> [t] TPM", "Enter Choose"}
	w.frame(prompt)
	w.viewKey(keyPageUp)
	frame := strings.Join(w.frame(prompt), "\n")
	if w.logScroll == 0 || !strings.Contains(frame, "LOG PAUSED") {
		t.Fatal("log history cannot scroll")
	}
	if !strings.Contains(frame, "Publish") {
		t.Fatalf("sidebar clipped above controls: %s", frame)
	}
}
