package ui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// The full-screen guided interface. It draws the phase status, the session
// output and one prompt at a time on the alternate screen buffer, and it
// reads single keys from a raw-mode terminal.
//
// Colour is supplementary everywhere: the bracketed marker names the state,
// so a reader with no colour, or a reader of the replayed transcript, loses
// nothing. frame builds plain text; paint adds colour to that text and
// nothing else.

// Phase markers. All are the same width so the phase names line up, and the
// text alone identifies the state.
const (
	phaseWaiting = "[to do]  "
	phaseRunning = "[running]"
	phaseDone    = "[done]   "
	phaseSkipped = "[skipped]"
	phaseFailed  = "[failed] "
)

// Control-sequence literals, kept together so the escapes appear once.
const (
	enterAltScreen = "\x1b[?1049h\x1b[?25l"
	leaveAltScreen = "\x1b[?25h\x1b[?1049l"
	homeAndClear   = "\x1b[H\x1b[2J"
)

// cancelNotice is the wording main.go prints when a signal cancels the run.
// Raw mode turns Ctrl-C into a key rather than a signal, so the wizard says
// the same thing itself.
const cancelNotice = "Cancelled. Completed work is saved; run guacdeploy again to resume or clean up."

// logCap bounds the retained transcript. It is replayed when the wizard
// stops, so leaving the full-screen view does not take the session output
// with it.
const logCap = 500

// Keys returned by readKey. They are negative so they cannot collide with a
// real rune.
const (
	keyUp        = rune(-1)
	keyDown      = rune(-2)
	keyEnter     = rune(-3)
	keyBackspace = rune(-4)
	keyCancel    = rune(-5)
	keyOther     = rune(-6)
)

// Wizard draws the guided interface. Use UI.StartWizard to create one; the
// UI routes its own prompts and output through it while it is running.
type Wizard struct {
	out io.Writer
	in  *bufio.Reader

	rows, cols int
	colour     bool

	mu      sync.Mutex
	names   []string
	state   map[string]string
	log     []string
	stopped bool

	stopOnce sync.Once
	restore  func() // undoes raw mode; nil when no real terminal is attached
}

func newWizard(in *bufio.Reader, out io.Writer, rows, cols int, colour bool) *Wizard {
	// ponytail: below about twenty rows the frame is taller than the screen
	// and the top scrolls away. Treat that as the floor rather than build a
	// second compact layout.
	if rows < 20 {
		rows = 20
	}
	if cols < 40 {
		cols = 40
	}
	return &Wizard{out: out, in: in, rows: rows, cols: cols, colour: colour, state: map[string]string{}}
}

// StartWizard switches the guided path to the full-screen interface. It
// reports false and changes nothing when the terminal cannot support it, so
// the caller keeps the line-oriented output: not a terminal, a pipe, or
// TERM unset or "dumb".
func (u *UI) StartWizard() bool {
	if u.wiz != nil {
		return !u.wiz.done()
	}
	if !u.Interactive || !fullScreenCapable(u.Out) {
		return false
	}
	prev, err := term.MakeRaw(u.fd)
	if err != nil {
		return false
	}
	rows, cols := 24, 80
	if c, r, err := term.GetSize(u.fd); err == nil && r > 0 && c > 0 {
		rows, cols = r, c
	}
	w := newWizard(u.In, u.Out, rows, cols, os.Getenv("NO_COLOR") == "")
	w.restore = func() { term.Restore(u.fd, prev) }
	io.WriteString(u.Out, enterAltScreen)
	u.wiz = w
	w.draw(nil)
	return true
}

// fullScreenCapable reports whether control codes may be written to out. A
// pipe, a file, or a terminal that declares itself dumb gets plain lines.
func fullScreenCapable(out io.Writer) bool {
	switch os.Getenv("TERM") {
	case "", "dumb":
		return false
	}
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// wizard returns the running wizard, or nil when output is line-oriented.
func (u *UI) wizard() *Wizard {
	if u.wiz != nil && !u.wiz.done() {
		return u.wiz
	}
	return nil
}

func (w *Wizard) done() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

// stop leaves the full-screen view, restores the terminal, and replays the
// session output onto the ordinary screen. It runs at most once, whichever
// path reaches it: normal exit, cancellation, a signal, or a panic unwinding
// through a deferred UI.RestoreTerminal.
func (w *Wizard) stop() {
	w.stopOnce.Do(func() {
		w.mu.Lock()
		w.stopped = true
		lines := append([]string(nil), w.log...)
		w.mu.Unlock()
		// Cooked mode first: the replayed lines below need a newline to
		// mean carriage return and line feed.
		if w.restore != nil {
			w.restore()
		}
		io.WriteString(w.out, leaveAltScreen)
		for _, l := range lines {
			io.WriteString(w.out, l+"\n")
		}
	})
}

// cancelled ends the session on the explicit cancel key. Raw mode consumed
// the signal, so the wizard prints the notice main.go would have printed and
// returns the error main.go already maps to exit code 130.
func (w *Wizard) cancelled() error {
	w.stop()
	io.WriteString(w.out, cancelNotice+"\n")
	return context.Canceled
}

func (w *Wizard) say(s string) {
	w.mu.Lock()
	for _, l := range strings.Split(s, "\n") {
		w.log = append(w.log, "  "+l)
	}
	if n := len(w.log) - logCap; n > 0 {
		w.log = append([]string(nil), w.log[n:]...)
	}
	w.mu.Unlock()
	w.draw(nil)
}

func (w *Wizard) setPhases(names []string) {
	w.mu.Lock()
	w.names = append([]string(nil), names...)
	w.mu.Unlock()
	w.draw(nil)
}

func (w *Wizard) setPhase(name, state string) {
	w.mu.Lock()
	known := false
	for _, n := range w.names {
		if n == name {
			known = true
			break
		}
	}
	// A phase nobody declared still appears, so a partly wired caller shows
	// real progress instead of an empty list.
	if !known {
		w.names = append(w.names, name)
	}
	w.state[name] = state
	w.mu.Unlock()
	w.draw(nil)
}

// failed records the failure and writes the three things the specification
// requires an error to explain: the action that failed, the work that was
// retained, and the recovery choices. The wording is the session's own.
func (w *Wizard) failed(name string, err error) {
	w.setPhase(name, phaseFailed)
	w.mu.Lock()
	done := 0
	for _, n := range w.names {
		if s := w.state[n]; s == phaseDone || s == phaseSkipped {
			done++
		}
	}
	total := len(w.names)
	w.mu.Unlock()
	w.say(strings.Join([]string{
		fmt.Sprintf("Failed action:    phase %s failed: %v", name, err),
		fmt.Sprintf("Retained work:    completed work is retained; %d of %d phase(s) completed.", done, total),
		"Recovery choices: resume, or clean up. Run setup again to choose.",
	}, "\n"))
}

func (w *Wizard) width() int {
	if w.cols > 78 {
		return 78
	}
	return w.cols
}

// progress summarises the phase list in one line. Every category it names is
// also visible in the list below it.
func (w *Wizard) progress() string {
	count := map[string]int{}
	for _, n := range w.names {
		s := w.state[n]
		if s == "" {
			s = phaseWaiting
		}
		count[s]++
	}
	parts := []string{fmt.Sprintf("%d done", count[phaseDone])}
	if n := count[phaseRunning]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d running", n))
	}
	if n := count[phaseFailed]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", n))
	}
	if n := count[phaseSkipped]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d already complete", n))
	}
	parts = append(parts, fmt.Sprintf("%d to do", count[phaseWaiting]))
	return fmt.Sprintf("Phases (%d): %s", len(w.names), strings.Join(parts, ", "))
}

// frame builds the screen as plain text. It contains no escape sequences:
// everything a reader needs is in the words. The caller holds w.mu.
func (w *Wizard) frame(prompt []string) []string {
	rule := strings.Repeat("-", w.width())

	phases := make([]string, 0, len(w.names))
	active := 0
	for i, n := range w.names {
		s := w.state[n]
		if s == "" {
			s = phaseWaiting
		}
		line := "  " + s + "  " + n
		if s == phaseSkipped {
			line += " (already complete)"
		}
		if s == phaseRunning || s == phaseFailed {
			active = i
		}
		phases = append(phases, line)
	}

	// Furniture: title, progress, three rules, the Output label, the prompt
	// block and the cancel footer. The count only sizes the budget, so an
	// approximation is enough.
	budget := w.rows - (2 + 3 + 1 + len(prompt) + 1) - 1
	if budget < 6 {
		budget = 6
	}
	logRoom := budget - len(phases)
	if logRoom < 3 {
		logRoom = 3
		phases = windowLines(phases, active, budget-logRoom)
	}

	out := []string{"GUACAMOLE DEPLOYMENT (guided setup)"}
	if len(phases) > 0 {
		out = append(out, w.progress(), rule)
		out = append(out, phases...)
	}
	out = append(out, rule, "Output")
	if len(w.log) > logRoom {
		out = append(out, w.log[len(w.log)-logRoom:]...)
	} else {
		out = append(out, w.log...)
	}
	out = append(out, rule)
	if len(prompt) > 0 {
		out = append(out, prompt...)
		out = append(out, rule)
	}
	return append(out, "Ctrl-C  Cancel. Completed work is retained.")
}

// windowLines keeps at most max lines around the active one. The elided
// lines are replaced by a line that counts them, so nothing disappears
// silently.
func windowLines(lines []string, active, max int) []string {
	if max < 3 {
		max = 3
	}
	if len(lines) <= max {
		return lines
	}
	start := active - (max-2)/2
	if start < 0 {
		start = 0
	}
	end := start + max
	if end > len(lines) {
		end, start = len(lines), len(lines)-max
	}
	out := append([]string(nil), lines[start:end]...)
	if start > 0 {
		out[0] = fmt.Sprintf("  ... %d earlier phase(s) not shown", start+1)
	}
	if end < len(lines) {
		out[len(out)-1] = fmt.Sprintf("  ... %d later phase(s) not shown", len(lines)-end+1)
	}
	return out
}

// paint adds colour to one plain frame line and changes nothing else, so
// removing the colour returns exactly the text frame produced.
func (w *Wizard) paint(line string) string {
	if !w.colour {
		return line
	}
	for marker, code := range map[string]string{
		phaseDone:    "\x1b[32m",
		phaseRunning: "\x1b[36m",
		phaseFailed:  "\x1b[31m",
		phaseSkipped: "\x1b[90m",
	} {
		if i := strings.Index(line, marker); i >= 0 {
			return line[:i] + code + marker + "\x1b[0m" + line[i+len(marker):]
		}
	}
	if strings.HasPrefix(line, "> ") {
		return "\x1b[1m" + line + "\x1b[0m"
	}
	return line
}

func (w *Wizard) draw(prompt []string) {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	lines := w.frame(prompt)
	w.mu.Unlock()

	var b strings.Builder
	b.WriteString(homeAndClear)
	for i, l := range lines {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(w.paint(l))
	}
	io.WriteString(w.out, b.String())
}

// readKey reads one keystroke.
func (w *Wizard) readKey() (rune, error) {
	r, _, err := w.in.ReadRune()
	if err != nil {
		return 0, err
	}
	switch r {
	case 3: // Ctrl-C
		return keyCancel, nil
	case '\r', '\n':
		return keyEnter, nil
	case 8, 127:
		return keyBackspace, nil
	case 27:
		// ponytail: a lone Escape is told from an arrow key by whether the
		// rest of the sequence has already arrived. A terminal delivers an
		// arrow key in one read, so this holds; a hand-typed Escape
		// immediately followed by "[A" would be read as an arrow key.
		if w.in.Buffered() == 0 {
			return keyCancel, nil
		}
		if r, _, err = w.in.ReadRune(); err != nil {
			return 0, err
		}
		if r != '[' && r != 'O' {
			return keyOther, nil
		}
		if r, _, err = w.in.ReadRune(); err != nil {
			return 0, err
		}
		switch r {
		case 'A':
			return keyUp, nil
		case 'B':
			return keyDown, nil
		}
		return keyOther, nil
	}
	return r, nil
}

func (w *Wizard) choose(prompt string, choices []Choice) (rune, error) {
	sel := 0
	for {
		lines := []string{prompt, ""}
		for i, c := range choices {
			cursor := "  "
			if i == sel {
				cursor = "> "
			}
			lines = append(lines, fmt.Sprintf("%s[%c] %s", cursor, c.Key, c.Label))
		}
		lines = append(lines, "", "Up/Down or j/k to move, Enter to choose, or press the letter in brackets.")
		w.draw(lines)

		k, err := w.readKey()
		if err != nil {
			return 0, err
		}
		// A choice key wins over the j/k shortcuts, so a prompt that offers
		// "j" keeps working.
		for _, c := range choices {
			if lowerASCII(k) == lowerASCII(c.Key) {
				return c.Key, nil
			}
		}
		switch k {
		case keyCancel:
			return 0, w.cancelled()
		case keyEnter:
			return choices[sel].Key, nil
		case keyUp, 'k':
			sel = (sel - 1 + len(choices)) % len(choices)
		case keyDown, 'j':
			sel = (sel + 1) % len(choices)
		}
	}
}

func lowerASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// readLine edits one line of input. hidden suppresses the echo for
// credential prompts: the value is never drawn, logged or retained.
func (w *Wizard) readLine(prompt, def string, hidden bool) (string, error) {
	var buf []rune
	note := ""
	for {
		shown := string(buf)
		if hidden {
			shown = strings.Repeat("*", len(buf))
		}
		lines := []string{prompt}
		if def != "" {
			lines = append(lines, fmt.Sprintf("Default: %s (press Enter to accept it)", def))
		}
		if hidden {
			lines = append(lines, "Input is hidden.")
		}
		lines = append(lines, "", "  "+shown+"_", "")
		if note != "" {
			lines = append(lines, note)
		}
		lines = append(lines, "Type the value, then press Enter.")
		w.draw(lines)

		k, err := w.readKey()
		if err != nil {
			return "", err
		}
		switch {
		case k == keyCancel:
			return "", w.cancelled()
		case k == keyEnter:
			v := strings.TrimSpace(string(buf))
			if v == "" && def != "" {
				return def, nil
			}
			if v == "" && !hidden {
				note = "A value is required."
				continue
			}
			if hidden {
				return string(buf), nil
			}
			return v, nil
		case k == keyBackspace:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		case k >= ' ':
			buf = append(buf, k)
		}
	}
}
