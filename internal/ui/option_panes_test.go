package ui

import (
	"github.com/mattn/go-runewidth"
	"strings"
	"testing"
)

func TestSelectionExplanationFollowsHighlight(t *testing.T) {
	u, out, _ := newTestUI("\x1b[B\r")
	u.wiz.cols, u.wiz.rows = 140, 45
	got, err := u.Choose("Protect credentials", []Choice{
		{Key: 't', Label: "TPM", Description: "TPM explanation fixture"},
		{Key: 'h', Label: "Host key", Description: "Host explanation fixture"},
	})
	if err != nil || got != 'h' {
		t.Fatalf("choice %c: %v", got, err)
	}
	for _, want := range []string{"TPM explanation fixture", "Host explanation fixture", "ABOUT THIS OPTION", "├", "┬", "┴"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestPreparationGroupsAreUnique(t *testing.T) {
	u, _, _ := newTestUI("")
	u.wiz.cols, u.wiz.rows = 140, 45
	u.PhaseList([]string{"host-preflight", "credential-mode", "configure-review", "host-dependencies", "stack-configure"})
	u.PhaseStart("credential-mode")
	frame := strings.Join(u.wiz.snapshot(), "\n")
	if strings.Count(frame, "> Prepare") != 1 {
		t.Fatalf("duplicate preparation headings:\n%s", frame)
	}
	if strings.Count(frame, "  Configure") != 1 {
		t.Fatalf("duplicate configuration headings:\n%s", frame)
	}
}

func TestCompactTabVisitsProgressWithoutSubmittingChoice(t *testing.T) {
	u, out, _ := newTestUI("\t\r\t\r\t\r")
	u.PhaseList([]string{"host-preflight", "credential-mode"})
	got, err := u.Choose("Choose protection", []Choice{{Key: 't', Label: "TPM"}})
	if err != nil || got != 't' {
		t.Fatalf("choice %c: %v", got, err)
	}
	if !strings.Contains(out.String(), "Deployment progress") {
		t.Fatal("missing compact progress view")
	}
	if u.wiz.progressView || u.wiz.details {
		t.Fatal("view state survived the prompt")
	}
}

func TestChoicePaneFitsTerminalAndJoinsBorders(t *testing.T) {
	for _, cols := range []int{80, 104, 140, 220} {
		u, _, _ := newTestUI("")
		w := u.wiz
		w.cols, w.rows = cols, 45
		w.selectionHelp = "This option protects credentials. " + strings.Repeat("More explanation. ", 15)
		lines := w.frame([]string{"Protect credentials", "", "> [t] TPM", "  [h] Host key", "", "Enter Choose"})
		if len(lines) > w.rows {
			t.Fatalf("%d columns: %d rows exceed %d", cols, len(lines), w.rows)
		}
		for _, line := range lines {
			if runewidth.StringWidth(line) > cols {
				t.Fatalf("%d columns: overflowing line %q", cols, line)
			}
		}
		if cols >= 104 {
			found := false
			for _, line := range lines {
				if strings.Contains(line, "├") {
					found = true
				}
			}
			if !found {
				t.Fatal("choice divider does not join sidebar")
			}
		}
	}
}

func TestConfirmationExplainsBothConsequences(t *testing.T) {
	u, out, _ := newTestUI("\x1b[B\r")
	u.wiz.cols, u.wiz.rows = 140, 45
	yes, err := u.ConfirmWithHelp("Delete retained data?", "Permanently delete the data.", "Keep data and continue removing services.")
	if err != nil || yes {
		t.Fatalf("confirmation: %t %v", yes, err)
	}
	for _, want := range []string{"Permanently delete the data.", "Keep data and continue removing services."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing explanation %q", want)
		}
	}
}

func TestDetailsIncludesCompleteOptionExplanation(t *testing.T) {
	u, _, _ := newTestUI("")
	u.wiz.selectionHelp = "The selected action preserves data but removes services."
	u.wiz.details = true
	frame := strings.Join(u.wiz.snapshot(), "\n")
	if !strings.Contains(frame, "ABOUT THIS OPTION") || !strings.Contains(frame, u.wiz.selectionHelp) {
		t.Fatalf("missing help in Details:\n%s", frame)
	}
}
