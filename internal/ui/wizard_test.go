package ui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

// The wizard is driven entirely through injected readers and writers: no
// test needs a real terminal.

var ansi = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")

func stripANSI(s string) string { return ansi.ReplaceAllString(s, "") }

// newTestUI builds an interactive UI with the wizard already running on a
// buffer, and returns a counter of terminal restorations.
func newTestUI(keys string) (*UI, *bytes.Buffer, *int) {
	out := &bytes.Buffer{}
	in := bufio.NewReader(strings.NewReader(keys))
	u := &UI{In: in, Out: out, Interactive: true}
	restores := new(int)
	w := newWizard(in, out, 40, 80, false)
	w.restore = func() { *restores++ }
	u.wiz = w
	return u, out, restores
}

// snapshot returns the plain-text frame. Tests are single-goroutine.
func (w *Wizard) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.frame(nil)
}

func hasLineWith(lines []string, parts ...string) bool {
	for _, l := range lines {
		ok := true
		for _, p := range parts {
			if !strings.Contains(l, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

var resumeChoices = []Choice{
	{Key: 'r', Label: "Resume the interrupted work"},
	{Key: 'c', Label: "Clean up and remove the interrupted deployment record"},
	{Key: 'q', Label: "Quit and decide later"},
}

func TestChooseKeyboardNavigation(t *testing.T) {
	for _, tc := range []struct {
		name, keys string
		want       rune
	}{
		{"enter takes the first option", "\r", 'r'},
		{"down arrow moves forward", "\x1b[B\r", 'c'},
		{"two down arrows", "\x1b[B\x1b[B\r", 'q'},
		{"up arrow wraps to the last", "\x1b[A\r", 'q'},
		{"j moves forward", "j\r", 'c'},
		{"k wraps backwards", "k\r", 'q'},
		{"down then up returns", "\x1b[B\x1b[A\r", 'r'},
		{"wraps past the end", "jjj\r", 'r'},
		{"letter in brackets selects directly", "q", 'q'},
		{"uppercase letter selects", "C", 'c'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _, _ := newTestUI(tc.keys)
			got, err := u.Choose("What do you want to do?", resumeChoices)
			if err != nil {
				t.Fatalf("Choose: %v", err)
			}
			if got != tc.want {
				t.Fatalf("selected %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChooseShowsCursorAndCancelAction(t *testing.T) {
	u, out, _ := newTestUI("\x1b[B\r")
	if _, err := u.Choose("What do you want to do?", resumeChoices); err != nil {
		t.Fatalf("Choose: %v", err)
	}
	// Answering draws one more frame without the question, so the frame that
	// was on screen when Enter was pressed is the one before it.
	frames := strings.Split(out.String(), homeAndClear)
	answered, asking := frames[len(frames)-1], frames[len(frames)-2]
	if !strings.Contains(asking, "> [c] Clean up") {
		t.Errorf("selection cursor missing from the frame that asked:\n%s", asking)
	}
	if !strings.Contains(asking, "  [r] Resume") {
		t.Errorf("unselected option missing from the frame that asked:\n%s", asking)
	}
	if !strings.Contains(asking, "Ctrl-C  Cancel") {
		t.Errorf("cancel action not visible:\n%s", asking)
	}
	// An answered question leaves the screen, so a later phase message does
	// not appear under a prompt that no longer applies.
	if strings.Contains(answered, "[c] Clean up") {
		t.Errorf("the answered question is still on screen:\n%s", answered)
	}
}

func TestOutputKeepsAnUnansweredPromptOnScreen(t *testing.T) {
	// A phase that reports progress, or a resize, must not wipe a question
	// the operator is part way through answering.
	u, out, _ := newTestUI("")
	u.wiz.draw([]string{"Public hostname", "", "  guac_"})
	u.Say("Creating the Cloudflare tunnel.")

	frames := strings.Split(out.String(), homeAndClear)
	last := frames[len(frames)-1]
	if !strings.Contains(last, "Public hostname") {
		t.Errorf("output wiped the prompt that is still being answered:\n%s", last)
	}
	if !strings.Contains(last, "Creating the Cloudflare tunnel.") {
		t.Errorf("the new output is missing:\n%s", last)
	}
}

func TestConfirmUsesTheWizard(t *testing.T) {
	u, _, _ := newTestUI("\x1b[B\r") // move from Yes to No
	ok, err := u.Confirm("Start a fresh setup?")
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if ok {
		t.Fatal("selecting No returned true")
	}
}

func TestCancelAtAnyPoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*UI) error
	}{
		{"at a choice", func(u *UI) error {
			_, err := u.Choose("What do you want to do?", resumeChoices)
			return err
		}},
		{"after moving the selection", func(u *UI) error {
			_, err := u.Choose("What do you want to do?", resumeChoices)
			return err
		}},
		{"at a text prompt", func(u *UI) error {
			_, err := u.Line("Public hostname", "")
			return err
		}},
		{"part way through typing", func(u *UI) error {
			_, err := u.Line("Public hostname", "")
			return err
		}},
		{"at a hidden prompt", func(u *UI) error {
			_, err := u.HiddenLine("Passphrase")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys := "\x03"
			if strings.Contains(tc.name, "moving") {
				keys = "\x1b[B\x03"
			}
			if strings.Contains(tc.name, "typing") {
				keys = "guac\x03"
			}
			u, out, restores := newTestUI(keys)
			err := tc.call(u)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel returned %v, want context.Canceled", err)
			}
			if *restores != 0 || strings.Contains(out.String(), leaveAltScreen) {
				t.Fatal("cancel restored the terminal before the final screen")
			}
			if !strings.Contains(strings.Join(u.wiz.log, " "), cancelNotice) {
				t.Fatal("missing cancellation status")
			}
			u.RestoreTerminal()
			if *restores != 1 {
				t.Fatal("terminal was not restored at exit")
			}

		})
	}
}

func TestCancelDuringHiddenInputKeepsTheSecretOffScreen(t *testing.T) {
	u, out, _ := newTestUI("hunter2\x03")
	if _, err := u.HiddenLine("Passphrase"); !errors.Is(err, context.Canceled) {
		t.Fatalf("HiddenLine: %v", err)
	}
	if strings.Contains(out.String(), "hunter2") {
		t.Fatal("hidden input was echoed to the screen")
	}
}

var twentyPhases = []string{
	"initialise-deployment", "host-preflight", "credential-mode", "credential-check",
	"host-dependencies", "stack-configure", "cloudflare-select", "cloudflare-tunnel",
	"stack-render", "stack-schema", "origin-certificate", "stack-up", "boot-recovery",
	"backup-schedule", "recording-schedule", "stack-health", "entra-signin",
	"cloudflare-dns", "cloudflare-access", "cloudflare-connect",
}

func TestPhaseStatusTransitions(t *testing.T) {
	u, _, _ := newTestUI("")
	u.PhaseList(twentyPhases)
	u.PhaseStart("initialise-deployment")
	if !hasLineWith(u.wiz.snapshot(), "Create deployment record") {
		t.Fatal("current task is not visible")
	}
	u.PhaseDone("initialise-deployment")
	u.PhaseSkipped("host-preflight")
	u.PhaseFailed("credential-mode", errors.New("no credential mode selected"))
	if !hasLineWith(u.wiz.snapshot(), "2 / 20 steps complete") {
		t.Fatal("completion counts do not include retained work")
	}
	u.wiz.details = true
	u.wiz.rows = 80
	lines := u.wiz.snapshot()
	for _, want := range [][]string{{phaseDone, "initialise-deployment"}, {phaseSkipped, "host-preflight"}, {phaseFailed, "credential-mode"}, {phaseWaiting, "credential-check"}} {
		if !hasLineWith(lines, want...) {
			t.Fatalf("details lost phase state %v", want)
		}
	}
}

func TestPhaseStatusShowsUndeclaredPhases(t *testing.T) {
	u, _, _ := newTestUI("")
	u.PhaseStart("stack-up")
	if !hasLineWith(u.wiz.snapshot(), "Start the services") || !hasLineWith(u.wiz.snapshot(), "IN PROGRESS") {
		t.Fatal("undeclared current task is not visible")
	}
}

func TestFailedPhaseExplainsActionRetentionAndRecovery(t *testing.T) {
	u, _, _ := newTestUI("")
	u.PhaseList(twentyPhases)
	u.PhaseDone("initialise-deployment")
	u.PhaseDone("host-preflight")
	u.PhaseFailed("credential-check", errors.New("the postgres password is missing"))

	// The block wraps to the screen, so the assertion reads the presented
	// text rather than one line of it.
	flat := strings.ReplaceAll(flatten(u.wiz.snapshot()), " | ", " ")
	for _, want := range []string{
		"Failed action: phase credential-check failed: the postgres password is missing",
		"Retained work: completed work is retained; 2 of 20 phase(s) completed.",
		"Recovery choices: resume, or clean up. Run setup again to choose.",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the error does not say %q\ngot: %s", want, flat)
		}
	}
}

// flatten joins the frame and collapses the wrap, so an assertion can read a
// sentence that the screen split across lines.
func flatten(lines []string) string {
	return strings.Join(strings.Fields(strings.Join(lines, " ")), " ")
}

func TestFrameIsPlainTextAndDistinguishesEveryState(t *testing.T) {
	u, _, _ := newTestUI("")
	u.PhaseList(twentyPhases)
	u.PhaseDone("initialise-deployment")
	u.PhaseSkipped("host-preflight")
	u.PhaseStart("credential-mode")
	u.Say("Deployment 01 initialised on rocky10.")
	u.PhaseFailed("credential-mode", errors.New("no credential mode selected"))

	u.wiz.details = true
	u.wiz.rows = 80
	lines := u.wiz.snapshot()
	for _, l := range lines {
		if strings.ContainsRune(l, 0x1b) {
			t.Fatalf("frame line carries an escape sequence: %q", l)
		}
	}
	// Every state is identifiable from the words alone.
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"[done]", "[skipped]", "[failed]", "[to do]", "Ctrl-C  Cancel", "Failed action:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plain text loses %q:\n%s", want, joined)
		}
	}
	// Success, failure and required action read differently.
	if strings.Contains(joined, phaseRunning) {
		t.Error("a failed phase is still reported as running")
	}
}

func TestColourIsSupplementary(t *testing.T) {
	u, _, _ := newTestUI("")
	u.PhaseList(twentyPhases)
	u.PhaseDone("initialise-deployment")
	u.PhaseSkipped("host-preflight")
	u.PhaseStart("credential-mode")
	u.PhaseFailed("stack-up", errors.New("containers did not become healthy"))

	plain := u.wiz.snapshot()

	coloured := newWizard(bufio.NewReader(strings.NewReader("")), io.Discard, 40, 80, true)
	coloured.names, coloured.state, coloured.log = u.wiz.names, u.wiz.state, u.wiz.log

	var sawColour bool
	for _, l := range plain {
		got := coloured.paint(l)
		if got != l {
			sawColour = true
		}
		if stripANSI(got) != l {
			t.Fatalf("colour changed the text: %q became %q", l, stripANSI(got))
		}
	}
	if !sawColour {
		t.Fatal("no line was coloured at all, so the test proves nothing")
	}
	// With colour off, painting is the identity.
	for _, l := range plain {
		if u.wiz.paint(l) != l {
			t.Fatalf("colour written with colour disabled: %q", l)
		}
	}
}

func TestPhaseListWindowsToTheScreen(t *testing.T) {
	u, _, _ := newTestUI("")
	u.wiz.rows = 24
	u.PhaseList(twentyPhases)
	u.PhaseStart("stack-up")
	lines := u.wiz.snapshot()
	if len(lines) > 24 || !hasLineWith(lines, "Start the services") {
		t.Fatal("current task does not fit")
	}
	u.wiz.details = true
	u.wiz.scroll = 15
	lines = u.wiz.snapshot()
	if len(lines) > 24 || !hasLineWith(lines, "PgUp/PgDn") {
		t.Fatal("history is not bounded and scrollable")
	}
}

func TestWindowLinesCountsEverythingItHides(t *testing.T) {
	lines := make([]string, 10)
	for i := range lines {
		lines[i] = fmt.Sprintf("p%d", i)
	}
	got := windowLines(lines, 5, 5)
	if len(got) != 5 {
		t.Fatalf("window returned %d lines, want 5", len(got))
	}
	hidden := 0
	for _, l := range got {
		var n int
		if _, err := fmt.Sscanf(l, "  ... %d", &n); err == nil {
			hidden += n
		}
	}
	if shown := 5 - 2; hidden+shown != len(lines) {
		t.Fatalf("window hides %d and shows %d of %d lines", hidden, shown, len(lines))
	}
	if len(windowLines(lines[:4], 0, 5)) != 4 {
		t.Error("a list that fits was windowed anyway")
	}
}

func TestFrameFitsTheTerminal(t *testing.T) {
	out := &bytes.Buffer{}
	in := bufio.NewReader(strings.NewReader(""))
	u := &UI{In: in, Out: out, Interactive: true}
	u.wiz = newWizard(in, out, 24, 60, false)
	u.PhaseList(twentyPhases)
	u.PhaseStart("stack-up")
	u.Say("Phase stack-up failed: the Cloudflare API rejected the request " +
		"because the account does not hold the Zone:Edit permission on the " +
		"zone example.com, so no tunnel route was created and nothing was published.")
	u.Say("%s", strings.Repeat("x", 300)) // one unbroken word, longer than the screen

	lines := u.wiz.frame([]string{
		"Replace the database of this deployment from the backup file, " +
			"discarding every connection and recording it holds now?",
		"", "> [y] Yes", "  [n] No",
	})
	if len(lines) > 24 {
		t.Errorf("frame is %d lines on a 24-row terminal", len(lines))
	}
	for _, l := range lines {
		if n := len([]rune(l)); n > 60 {
			t.Fatalf("frame line is %d columns wide on a 60-column terminal: %q", n, l)
		}
	}
	// Wrapping is a display choice: the stored transcript keeps whole lines,
	// so the replay after the wizard stops loses nothing.
	if !strings.Contains(strings.Join(u.wiz.log, "\n"), "Zone:Edit permission on the zone example.com") {
		t.Error("wrapping altered the stored transcript")
	}
}

func TestWrapLine(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		width    int
		want     []string
	}{
		{"short lines are untouched", "hello", 20, []string{"hello"}},
		{"breaks at a space", "alpha beta gamma", 11, []string{"alpha beta", "gamma"}},
		{"breaks a long word", "aaaaaaaaaa", 8, []string{"aaaaaaaa", "aa"}},
		// Counted in runes: a byte-counting wrap would split "ä ö ü ñ"
		// early, because each of those letters is two bytes.
		{"keeps multi-byte runes whole", "ä ö ü ñ é è", 8, []string{"ä ö ü ñ", "é è"}},
		// Absurd widths are clamped rather than looping one rune at a time.
		{"a tiny width is respected", "alpha beta gamma", 2, []string{"al", "ph", "a", "be", "ta", "ga", "mm", "a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := wrapLine(tc.in, tc.width)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("wrapLine = %q, want %q", got, tc.want)
			}
			for _, l := range got {
				if n := len([]rune(l)); n > tc.width && tc.width >= 8 {
					t.Errorf("segment %q is %d runes wide, want at most %d", l, n, tc.width)
				}
			}
		})
	}
}

func TestLineEditing(t *testing.T) {
	for _, tc := range []struct {
		name, keys, def, want string
	}{
		{"plain typing", "guac.example.com\r", "", "guac.example.com"},
		{"backspace removes the last character", "guac\x7f\x7fx\r", "", "gux"},
		{"empty input takes the default", "\r", "Guacamole Operators", "Guacamole Operators"},
		{"typing overrides the default", "Ops\r", "Guacamole Operators", "Ops"},
		{"backspace on an empty buffer is harmless", "\x7f\x7fa\r", "", "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _, _ := newTestUI(tc.keys)
			got, err := u.Line("Public hostname", tc.def)
			if err != nil {
				t.Fatalf("Line: %v", err)
			}
			if got != tc.want {
				t.Fatalf("read %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLineReAsksWhenAValueIsRequired(t *testing.T) {
	u, out, _ := newTestUI("\rhost\r")
	got, err := u.Line("Public hostname", "")
	if err != nil {
		t.Fatalf("Line: %v", err)
	}
	if got != "host" {
		t.Fatalf("read %q", got)
	}
	if !strings.Contains(stripANSI(out.String()), "A value is required.") {
		t.Error("the operator was not told a value is required")
	}
}

func TestHiddenLineIsNeverEchoed(t *testing.T) {
	u, out, _ := newTestUI("s3cret\r")
	got, err := u.HiddenLine("Passphrase")
	if err != nil {
		t.Fatalf("HiddenLine: %v", err)
	}
	if got != "s3cret" {
		t.Fatalf("read %q", got)
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatal("the passphrase was drawn on the screen")
	}
	if !strings.Contains(out.String(), "******") {
		t.Error("no masked feedback was drawn for hidden input")
	}
	// A secret must not survive in the replayed transcript either.
	u.RestoreTerminal()
	if strings.Contains(out.String(), "s3cret") {
		t.Fatal("the passphrase reached the replayed session output")
	}
}

func TestLongAccessTokenStaysHiddenAndDoesNotExpandThePrompt(t *testing.T) {
	token := strings.Repeat("fixture-token-", 500)
	u, out, _ := newTestUI(token + "\r")
	got, err := u.HiddenLine("Graph access token")
	if err != nil || got != token {
		t.Fatal("long token was not read intact")
	}
	u.RestoreTerminal()
	if strings.Contains(out.String(), "fixture-token-") {
		t.Fatal("token reached the screen or transcript")
	}
	if strings.Contains(out.String(), strings.Repeat("*", 33)) {
		t.Fatal("masked token expanded beyond one line")
	}
}

func TestMultilineConsentInstructionsRenderAsSeparateTerminalRows(t *testing.T) {
	u, out, _ := newTestUI("c")
	prompt := "Open your profile menu.\nGrant these permissions:\nApplication.ReadWrite.All\nGroup.ReadWrite.All\nAppRoleAssignment.ReadWrite.All\nOrganization.Read.All"
	_, err := u.Choose(prompt, []Choice{{Key: 'c', Label: "Continue"}})
	if err != nil {
		t.Fatal(err)
	}
	// In raw terminal mode LF moves down without returning to column one.
	// Every output newline must therefore include CR, including prompt text.
	if strings.Contains(strings.ReplaceAll(out.String(), "\r\n", ""), "\n") {
		t.Fatal("multiline prompt emitted a bare LF, causing staircase indentation in a raw terminal")
	}
	w := newWizard(bufio.NewReader(strings.NewReader("")), io.Discard, 40, 80, false)
	for _, row := range w.frame([]string{prompt}) {
		if strings.ContainsAny(row, "\r\n") {
			t.Fatal("frame row contains an uncounted line break")
		}
	}
}

func TestLongConsentPromptKeepsInstructionsAndActionsOnSmallScreen(t *testing.T) {
	u, _, _ := newTestUI("")
	u.wiz.rows = 24
	u.PhaseList(twentyPhases)
	u.PhaseStart("stack-up")
	u.Say("The Microsoft tenant is selected.\nSign-in is required.\nCompleted work is retained.")
	lines := u.wiz.frame([]string{
		"Scroll to the top of Graph Explorer.\nOpen your profile avatar at the top right.\nChoose Consent to permissions.\nFind each permission and choose Consent:\nApplication.ReadWrite.All\nGroup.ReadWrite.All\nAppRoleAssignment.ReadWrite.All\nOrganization.Read.All",
		"", "> [c] Continue", "  [q] Quit and keep deployment progress", "",
		"Up/Down or j/k to move, Enter to choose, or press the letter in brackets.",
	})
	if len(lines) > 24 {
		t.Fatalf("consent instructions overflow the terminal: %d rows", len(lines))
	}
	// Instructions may span pages; action keys remain on every page.
	collected := strings.Join(lines, " ")
	for _, scroll := range []int{5, 10, 20} {
		u.wiz.scroll = scroll
		next := u.wiz.frame([]string{"Scroll to the top of Graph Explorer.\nOpen your profile avatar at the top right.\nChoose Consent to permissions.\nFind each permission and choose Consent:\nApplication.ReadWrite.All\nGroup.ReadWrite.All\nAppRoleAssignment.ReadWrite.All\nOrganization.Read.All", "", "> [c] Continue", "  [q] Quit and keep deployment progress"})
		if !hasLineWith(next, "[c] Continue") || !hasLineWith(next, "[q] Quit") || len(next) > 24 {
			t.Fatal("paging hid an action or overflowed")
		}
		collected += strings.Join(next, " ")
	}
	for _, want := range []string{"Application.ReadWrite.All", "Group.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Organization.Read.All"} {
		if !strings.Contains(collected, want) {
			t.Fatalf("instruction is inaccessible: %s", want)
		}
	}
}

func TestRestoreTerminalRunsOnceWithoutReplayingTheSession(t *testing.T) {
	u, out, restores := newTestUI("")
	u.Say("Deployment 01 initialised on rocky10.")
	u.Say("Phase stack-up: complete.")
	out.Reset()

	u.RestoreTerminal()
	u.RestoreTerminal()
	u.RestoreTerminal()

	if *restores != 1 {
		t.Fatalf("terminal restored %d times, want 1", *restores)
	}
	if n := strings.Count(out.String(), leaveAltScreen); n != 1 {
		t.Fatalf("left the full-screen view %d times, want 1", n)
	}
	if strings.Contains(out.String(), "Deployment 01 initialised on rocky10.") {
		t.Error("closing the wizard replayed the verbose transcript")
	}
	// Output after restoration is line-oriented again.
	out.Reset()
	u.Say("done")
	if out.String() != "done\n" {
		t.Errorf("after restoration Say wrote %q", out.String())
	}
}

func TestRestoreTerminalOnPanic(t *testing.T) {
	u, out, restores := newTestUI("")
	u.Say("work in progress")

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic did not reach the recover")
			}
		}()
		defer u.RestoreTerminal()
		panic("a phase exploded")
	}()

	if *restores != 1 {
		t.Fatalf("terminal restored %d times after a panic, want 1", *restores)
	}
	if !strings.Contains(out.String(), leaveAltScreen) {
		t.Error("a panic left the terminal on the alternate screen")
	}
	if !strings.Contains(out.String(), "work in progress") {
		t.Error("a panic lost the session output")
	}
}

func TestRestoreTerminalWithoutAWizard(t *testing.T) {
	u := &UI{In: bufio.NewReader(strings.NewReader("")), Out: &bytes.Buffer{}}
	u.RestoreTerminal() // must not panic when no wizard and no saved state
}

type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Error("unattended mode read from the terminal")
	return 0, io.EOF
}

func TestUnattendedNeverWaitsForInput(t *testing.T) {
	out := &bytes.Buffer{}
	u := &UI{In: bufio.NewReader(failReader{t}), Out: out}

	if u.StartWizard() {
		t.Fatal("the full-screen wizard started without an interactive terminal")
	}
	if _, err := u.Choose("What do you want to do?", resumeChoices); !errors.Is(err, ErrInputRequired) {
		t.Errorf("Choose returned %v", err)
	}
	if _, err := u.Line("Public hostname", "guac"); !errors.Is(err, ErrInputRequired) {
		t.Errorf("Line returned %v", err)
	}
	if _, err := u.HiddenLine("Passphrase"); !errors.Is(err, ErrInputRequired) {
		t.Errorf("HiddenLine returned %v", err)
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Error("unattended output carries control codes")
	}
}

func TestFullScreenCapableDegradesHonestly(t *testing.T) {
	for _, tc := range []struct {
		name, term string
		out        io.Writer
		want       bool
	}{
		{"a pipe", "xterm-256color", &bytes.Buffer{}, false},
		{"TERM unset", "", &bytes.Buffer{}, false},
		{"TERM=dumb", "dumb", &bytes.Buffer{}, false},
		{"a file that is not a terminal", "xterm", devNull(t), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			if got := fullScreenCapable(tc.out); got != tc.want {
				t.Fatalf("fullScreenCapable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTermSupportsControlCodes(t *testing.T) {
	for _, tc := range []struct {
		term string
		want bool
	}{
		{"dumb", false},
		{"", false},
		{"xterm-256color", true},
		{"screen", true},
		{"vt100", true},
	} {
		t.Run("TERM="+tc.term, func(t *testing.T) {
			t.Setenv("TERM", tc.term)
			if got := termSupportsControlCodes(); got != tc.want {
				t.Fatalf("termSupportsControlCodes = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFullScreenCapableNeedsBothATerminalAndAUsefulTerm(t *testing.T) {
	// A pseudo-terminal is the only real terminal a test can obtain, and it
	// is what proves the TERM rule still applies once the writer check
	// passes. The Linux target reports the /dev/ptmx master as a terminal.
	// macOS does not, and reaching its terminal side needs ptsname, so the
	// test skips on a development Mac and runs on the supported platform.
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { pty.Close() })
	if !term.IsTerminal(int(pty.Fd())) {
		t.Skip("/dev/ptmx is not reported as a terminal here")
	}

	t.Setenv("TERM", "xterm-256color")
	if !fullScreenCapable(pty) {
		t.Fatal("a real terminal with a usable TERM was refused")
	}
	t.Setenv("TERM", "dumb")
	if fullScreenCapable(pty) {
		t.Fatal("TERM=dumb was accepted because the writer is a terminal")
	}
	t.Setenv("TERM", "")
	if fullScreenCapable(pty) {
		t.Fatal("an unset TERM was accepted because the writer is a terminal")
	}
}

// devNull is an *os.File that is not a terminal, which is the case a pipe or
// a redirected stdout hits.
func devNull(t *testing.T) io.Writer {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestStartWizardRefusesWithoutATerminal(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	out := &bytes.Buffer{}
	u := &UI{In: bufio.NewReader(strings.NewReader("y\n")), Out: out, Interactive: true}
	if u.StartWizard() {
		t.Fatal("the wizard started on a buffer")
	}
	// Everything falls back to the line-oriented output.
	u.Say("hello")
	u.PhaseDone("stack-up")
	u.PhaseSkipped("host-preflight")
	u.PhaseFailed("stack-up", errors.New("boom"))
	got := out.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("control codes written to a plain writer: %q", got)
	}
	want := "hello\n" +
		"Phase stack-up: complete.\n" +
		"Phase host-preflight: already complete, skipping.\n" +
		"Phase stack-up failed: boom\n" +
		"Completed work is retained. Run setup again to resume or clean up.\n"
	if got != want {
		t.Fatalf("line-oriented output changed:\ngot  %q\nwant %q", got, want)
	}
}

func TestPhaseStartIsSilentInLineOrientedOutput(t *testing.T) {
	out := &bytes.Buffer{}
	u := &UI{In: bufio.NewReader(strings.NewReader("")), Out: out}
	u.PhaseList(twentyPhases)
	u.PhaseStart("stack-up")
	if out.String() != "" {
		t.Fatalf("phase declaration wrote %q to line-oriented output", out.String())
	}
}

func TestSayKeepsFormattingBehaviour(t *testing.T) {
	out := &bytes.Buffer{}
	u := &UI{In: bufio.NewReader(strings.NewReader("")), Out: out}
	u.Say("Deployment %s on %s.", "01", "rocky10")
	u.Say("%s", "already formatted")
	if got, want := out.String(), "Deployment 01 on rocky10.\nalready formatted\n"; got != want {
		t.Fatalf("Say wrote %q, want %q", got, want)
	}
}

func TestSayRecordsMultipleLines(t *testing.T) {
	u, _, _ := newTestUI("")
	u.Say("first\nsecond")
	if got := len(u.wiz.log); got != 2 {
		t.Fatalf("a two-line message became %d log entries", got)
	}
	if !hasLineWith(u.wiz.snapshot(), "second") {
		t.Error("the second line is missing from the frame")
	}
}

func TestLogIsBounded(t *testing.T) {
	u, _, _ := newTestUI("")
	for i := 0; i < logCap+50; i++ {
		u.Say("line %d", i)
	}
	if got := len(u.wiz.log); got != logCap {
		t.Fatalf("log holds %d lines, want %d", got, logCap)
	}
	if !strings.Contains(u.wiz.log[len(u.wiz.log)-1], fmt.Sprintf("line %d", logCap+49)) {
		t.Error("the newest line was dropped instead of the oldest")
	}
}

func TestReadKeyDecodesSequences(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     rune
	}{
		{"up arrow", "\x1b[A", keyUp},
		{"down arrow", "\x1b[B", keyDown},
		{"application-mode up", "\x1bOA", keyUp},
		{"right arrow is ignored", "\x1b[C", keyOther},
		{"a lone escape cancels", "\x1b", keyCancel},
		{"carriage return", "\r", keyEnter},
		{"newline", "\n", keyEnter},
		{"delete", "\x7f", keyBackspace},
		{"ctrl-c", "\x03", keyCancel},
		{"a letter", "j", 'j'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWizard(bufio.NewReader(strings.NewReader(tc.in)), io.Discard, 40, 80, false)
			got, err := w.readKey()
			if err != nil {
				t.Fatalf("readKey: %v", err)
			}
			if got != tc.want {
				t.Fatalf("readKey = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPromptsReportAClosedInput(t *testing.T) {
	u, _, _ := newTestUI("")
	if _, err := u.Choose("What do you want to do?", resumeChoices); !errors.Is(err, io.EOF) {
		t.Errorf("Choose on closed input returned %v", err)
	}
	u2, _, _ := newTestUI("")
	if _, err := u2.Line("Public hostname", ""); !errors.Is(err, io.EOF) {
		t.Errorf("Line on closed input returned %v", err)
	}
}

func TestBracketedPasteCannotSubmitAChoiceOrLeakHiddenInput(t *testing.T) {
	u, _, _ := newTestUI("\x1b[200~q\n\x1b[201~r")
	choice, err := u.Choose("Choose", resumeChoices)
	if err != nil || choice != 'r' {
		t.Fatalf("pasted text submitted a choice: %c %v", choice, err)
	}
	u, out, _ := newTestUI("\x1b[200~fixture\nsecret\x1b[201~\r")
	got, err := u.HiddenLine("Secret")
	if err != nil || got != "fixturesecret" {
		t.Fatalf("paste was not read as one value: %v", err)
	}
	if strings.Contains(out.String(), "fixture") {
		t.Fatal("pasted secret was drawn")
	}
}
func TestDetailsDoesNotSubmitOrLoseAField(t *testing.T) {
	u, _, _ := newTestUI("value\t\r\t\r\t\r")
	got, err := u.Line("Hostname", "")
	if err != nil || got != "value" {
		t.Fatalf("details lost the input: %s %v", got, err)
	}
}
func TestSmallTerminalCannotAcceptBlindConfirmation(t *testing.T) {
	u, _, _ := newTestUI("y\x03")
	u.wiz.rows = 10
	u.wiz.cols = 40
	_, err := u.Confirm("Delete data?")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("accepted an invisible confirmation: %v", err)
	}
}

func TestMinimumScreenKeepsFieldAndValidationVisible(t *testing.T) {
	u, out, _ := newTestUI("\rnew-value\r")
	u.wiz.rows = 16
	u.wiz.cols = 48
	value, err := u.Line("Identity-provider group for administrators", "")
	if err != nil || value != "new-value" {
		t.Fatal("field could not be completed")
	}
	frames := strings.Split(out.String(), homeAndClear)
	saw := false
	for _, f := range frames {
		if strings.Contains(f, "A value is required.") {
			saw = true
			if !strings.Contains(f, "> ") {
				t.Fatal("validation hid the input")
			}
			if !strings.Contains(f, "Identity-provider group for administrators") {
				t.Fatal("validation hid the question")
			}
		}
	}
	if !saw {
		t.Fatal("validation message was hidden")
	}
	u, out, _ = newTestUI("\r")
	u.wiz.rows = 16
	u.wiz.cols = 48
	u.Line("Identity-provider group for administrators", "Guacamole Administrators")
	if !strings.Contains(out.String(), "> Guacamole Administrators") {
		t.Fatal("default value pushed input off screen")
	}
	if !strings.Contains(out.String(), "(suggested)") {
		t.Fatal("default value was hidden")
	}
}
func TestEscapeTimesOutButFragmentedArrowSurvives(t *testing.T) {
	w := newWizard(bufio.NewReader(strings.NewReader("")), io.Discard, 24, 80, false)
	w.runes = make(chan runeEvent, 3)
	w.inputDone = make(chan struct{})
	w.runes <- runeEvent{r: 27}
	start := time.Now()
	key, err := w.readRawKey()
	if err != nil || key != keyCancel || time.Since(start) > time.Second {
		t.Fatal("Escape blocked")
	}
	w.runes <- runeEvent{r: 27}
	go func() { time.Sleep(20 * time.Millisecond); w.runes <- runeEvent{r: '['}; w.runes <- runeEvent{r: 'A'} }()
	key, err = w.readRawKey()
	if err != nil || key != keyUp {
		t.Fatalf("fragmented arrow was treated as Escape: %d %v", key, err)
	}
}
