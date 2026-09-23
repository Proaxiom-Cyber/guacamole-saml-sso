package ui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mattn/go-runewidth"
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
	enterAltScreen = "\x1b[?1049h\x1b[?25l\x1b[?2004h"
	leaveAltScreen = "\x1b[?2004l\x1b[?25h\x1b[?1049l"
	homeAndClear   = "\x1b[H\x1b[2J"
)

// cancelNotice is the wording main.go prints when a signal cancels the run.
// Where the terminal cannot keep its signal characters, Ctrl-C arrives as an
// ordinary key instead, and the wizard says the same thing itself.
const cancelNotice = "Cancelled. Completed work is saved; run guacdeploy again to resume or clean up."

// logCap bounds the retained transcript. Full history is available in the details view and the private log.
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
	keyPageUp    = rune(-7)
	keyPageDown  = rune(-8)
	keyDetails   = rune(-9)
)

const keyPaste = rune(-10)

// Wizard draws the guided interface. Use UI.StartWizard to create one; the
// UI routes its own prompts and output through it while it is running.
type Wizard struct {
	out io.Writer
	in  *bufio.Reader

	rows, cols int
	colour     bool

	mu             sync.Mutex
	names          []string
	state          map[string]string
	log            []string
	prompt         []string // the question on screen now, redrawn with everything else
	stopped        bool
	finalScreen    bool
	started        time.Time
	phaseStarted   time.Time
	active         string
	viewedPhase    string
	challenge      string
	details        bool
	progressView   bool
	selectionHelp  string
	scroll         int
	logScroll      int
	logPaneActive  bool
	copyNotice     string
	plainLink      bool
	plainLinkFrame string
	tick           int
	logPath        string
	task           taskProgress
	dockerStatus   map[string]string
	dockerOrder    []string

	interrupt <-chan struct{}
	keys      chan keyEvent
	waiting   bool
	lastFrame []string

	notes   []string
	summary []string

	rawPaste   string
	inputPaste string

	runes     chan runeEvent
	inputDone chan struct{}

	stopOnce      sync.Once
	restore       func() // undoes raw mode; nil when no real terminal is attached
	stopAnimation func()
	stopResize    func() // stops following the window size; nil when not following
}

// clampSize holds the frame to a usable minimum.
//
// ponytail: below about twenty rows the frame is taller than the screen and
// the top scrolls away. Treat that as the floor rather than build a second
// compact layout.
func clampSize(rows, cols int) (int, int) { return max(1, rows), max(1, cols) }

func newWizard(in *bufio.Reader, out io.Writer, rows, cols int, colour bool) *Wizard {
	rows, cols = clampSize(rows, cols)
	return &Wizard{out: out, in: in, rows: rows, cols: cols, colour: colour, state: map[string]string{}, started: time.Now(), phaseStarted: time.Now()}
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
	// Raw mode would make Ctrl-C an ordinary key, which nothing reads while a
	// phase runs. Put the signal characters back so cancelling works from
	// anywhere, not only at a prompt.
	keepSignalKeys(u.fd)

	rows, cols := 24, 80
	if c, r, err := term.GetSize(u.fd); err == nil && r > 0 && c > 0 {
		rows, cols = r, c
	}
	w := newWizard(u.In, u.Out, rows, cols, os.Getenv("NO_COLOR") == "")
	w.interrupt = u.interrupt
	w.restore = func() { term.Restore(u.fd, prev) }
	io.WriteString(u.Out, enterAltScreen)
	u.wiz = w
	w.logPath = u.LogPath()
	w.startInput()
	w.followResize(u.fd)
	w.animate()
	w.draw(nil)
	return true
}

// followResize redraws at the new size when the window changes. Without it
// the frame keeps the width it started with, so a narrower window wraps every
// line and pushes the top of the screen away.
func (w *Wizard) followResize(fd int) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	w.stopResize = func() { signal.Stop(ch); close(ch) }
	go func() {
		for range ch {
			c, r, err := term.GetSize(fd)
			if err != nil || r <= 0 || c <= 0 {
				continue
			}
			w.mu.Lock()
			w.rows, w.cols = clampSize(r, c)
			w.lastFrame = nil
			w.mu.Unlock()
			w.redraw()
		}
	}()
}

// fullScreenCapable reports whether control codes may be written to out. A
// pipe, a file, or a terminal that declares itself dumb gets plain lines.
func fullScreenCapable(out io.Writer) bool {
	if !termSupportsControlCodes() {
		return false
	}
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// termSupportsControlCodes reports what TERM claims. It is separate from the
// writer check so each half can be tested on its own: a test cannot supply a
// real terminal, and without the split an unset TERM would hide this rule.
func termSupportsControlCodes() bool {
	switch os.Getenv("TERM") {
	case "", "dumb":
		return false
	}
	return true
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

// stop leaves the full-screen view, restores the terminal, and prints a concise
// result on the ordinary screen. It runs at most once, whichever
// path reaches it: normal exit, cancellation, a signal, or a panic unwinding
// through a deferred UI.RestoreTerminal.
func (w *Wizard) stop() {
	w.stopOnce.Do(func() {
		if w.inputDone != nil {
			close(w.inputDone)
		}
		if w.stopAnimation != nil {
			w.stopAnimation()
		}
		if w.stopResize != nil {
			w.stopResize()
		}
		// The lock is held across the writes so a draw already under way
		// cannot interleave with the replay below. Any draw that arrives
		// meanwhile waits, then sees the wizard stopped and writes nothing.
		w.mu.Lock()
		defer w.mu.Unlock()
		w.stopped = true
		// Cooked mode first: the replayed lines below need a newline to
		// mean carriage return and line feed.
		if w.restore != nil {
			w.restore()
		}
		io.WriteString(w.out, leaveAltScreen)
		done := 0
		for _, status := range w.state {
			if status == phaseDone || status == phaseSkipped {
				done++
			}
		}
		for _, line := range w.summary {
			fmt.Fprintln(w.out, line)
		}
		if len(w.names) > 0 && len(w.summary) == 0 {
			command := "setup"
			if len(w.names) > 0 && strings.HasPrefix(w.names[0], "teardown-") {
				command = "teardown"
			}
			fmt.Fprintf(w.out, "Guacamole %s: %d of %d steps complete.\n", command, done, len(w.names))
		}
		if w.active != "" && w.state[w.active] == phaseFailed {
			command := "setup"
			if strings.HasPrefix(w.active, "teardown-") {
				command = "teardown"
			}
			fmt.Fprintf(w.out, "Needs attention: %s. Progress is saved; run sudo /usr/local/bin/guacdeploy %s to continue.\n", phaseInfo(w.active).Title, command)
		}

	})
}

// cancelled stops the operation without closing the terminal view. The caller
// saves progress and shows the final summary before restoring the terminal.
func (w *Wizard) cancelled() error {
	w.say(cancelNotice)
	return context.Canceled
}

func (w *Wizard) say(s string) {
	// Stored without indentation: the frame indents when it draws, and the
	// replayed transcript reads like ordinary output.
	w.mu.Lock()
	for _, line := range strings.Split(cleanText(s), "\n") {
		w.trackDocker(line)
		if len(line) > 8192 {
			line = line[:8192] + " [display shortened; see session log]"
		}
		if w.logScroll > 0 {
			w.logScroll += len(wrapped([]string{line}, max(1, w.width()-33)))
		}
		w.log = append(w.log, time.Now().Format("15:04:05")+" | "+line)
	}
	if n := len(w.log) - logCap; n > 0 {
		w.log = append([]string(nil), w.log[n:]...)
	}
	w.mu.Unlock()
	w.redraw()
}

func (w *Wizard) setPhases(names []string) {
	w.mu.Lock()
	w.names = append([]string(nil), names...)
	w.mu.Unlock()
	w.redraw()
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
	if state == phaseRunning || state == phaseFailed {
		w.task = taskProgress{}
		w.dockerStatus = nil
		w.dockerOrder = nil
		w.active = name
		w.phaseStarted = time.Now()
		w.scroll = 0
		w.challenge = ""
	}
	w.mu.Unlock()
	w.redraw()
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

// wrapLine breaks one line at spaces to fit the width, and breaks mid-word
// only when a single word is longer than the line. It works in runes, so a
// name outside ASCII cannot be cut in half.
func wrapLine(s string, width int) []string {
	width = max(1, width)
	var lines []string
	for runewidth.StringWidth(s) > width {
		head := runewidth.Truncate(s, width, "")
		if head == "" {
			head = string([]rune(s)[0])
		}
		if cut := strings.LastIndex(head, " "); cut > 0 {
			head = head[:cut]
		}
		lines = append(lines, head)
		s = strings.TrimLeft(s[len(head):], " ")
	}
	return append(lines, s)
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

// Redraws and terminal restoration serialize their writes. A timer cannot
// overwrite an input prompt or draw after the alternate screen has closed.
func (w *Wizard) redraw() { w.mu.Lock(); defer w.mu.Unlock(); w.renderLocked() }
func (w *Wizard) draw(prompt []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.prompt = prompt
	w.renderLocked()
}
func (w *Wizard) renderLocked() {
	if w.stopped {
		return
	}
	if w.plainLink && !w.waiting && !w.finalScreen && w.renderPlainLinkLocked() {
		return
	}
	if w.plainLinkFrame != "" {
		w.lastFrame = nil
		w.plainLinkFrame = ""
	}
	w.plainLink = false
	var b strings.Builder
	lines := w.frame(w.prompt)
	if w.keys == nil || len(w.lastFrame) != len(lines) {
		b.WriteString(homeAndClear)
		for i, l := range lines {
			if i > 0 {
				b.WriteString("\r\n")
			}
			b.WriteString(w.linkify(w.paint(l)))
		}
	} else {
		for i, l := range lines {
			if l != w.lastFrame[i] {
				fmt.Fprintf(&b, "\x1b[%d;1H\x1b[2K", i+1)
				b.WriteString(w.linkify(w.paint(l)))
			}
		}
	}
	w.lastFrame = append(w.lastFrame[:0], lines...)
	io.WriteString(w.out, b.String())
}
func (w *Wizard) animate() {
	reduced := os.Getenv("GUACDEPLOY_REDUCED_MOTION") != ""
	done := make(chan struct{})
	w.stopAnimation = func() { close(done) }
	go func() {
		interval := 250 * time.Millisecond
		if reduced {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				w.mu.Lock()
				if w.challenge != "" {
					w.mu.Unlock()
					continue
				}
				if !reduced {
					w.tick++
				}
				w.renderLocked()
				w.mu.Unlock()
			}
		}
	}()
}

// readKey reads one keystroke.
func (w *Wizard) readRawKey() (rune, error) {
	r, err := w.nextRune(0)
	if err != nil {
		return 0, err
	}
	switch r {
	case 9:
		return keyDetails, nil
	case 3: // Ctrl-C
		return keyCancel, nil
	case '\r', '\n':
		return keyEnter, nil
	case 8, 127:
		return keyBackspace, nil
	case 27:
		r, err = w.nextRune(150 * time.Millisecond)
		if err != nil {
			if err == io.EOF || err == errEscapeTimeout {
				return keyCancel, nil
			}
			return 0, err
		}
		if r == 3 {
			return keyCancel, nil
		}
		if r != '[' && r != 'O' {
			return keyOther, nil
		}
		if r, err = w.nextRune(0); err != nil {
			return 0, err
		}
		switch r {
		case 'A':
			return keyUp, nil
		case 'B':
			return keyDown, nil
		case '2':
			sequence := "2"
			for len(sequence) < 16 {
				next, err := w.nextRune(0)
				if err != nil {
					return 0, err
				}
				sequence += string(next)
				if next >= '@' && next <= '~' {
					break
				}
			}
			if sequence != "200~" {
				return keyOther, nil
			}

			var paste strings.Builder
			var suffix string
			for {
				r, err := w.nextRune(0)
				if err != nil {
					return 0, err
				}
				suffix += string(r)
				if strings.HasSuffix(suffix, "\x1b[201~") {
					break
				}
				if len(suffix) > 6 {
					if paste.Len() < 131072 {
						paste.WriteString(suffix[:len(suffix)-6])
					}
					suffix = suffix[len(suffix)-6:]
				}
			}
			if len(suffix) > 6 && paste.Len() < 131072 {
				paste.WriteString(suffix[:len(suffix)-6])
			}
			w.rawPaste = paste.String()
			return keyPaste, nil
		case '5', '6':
			page := r
			end, err := w.nextRune(0)
			if err != nil {
				return 0, err
			}
			if end != '~' {
				return keyOther, nil
			}
			if page == '5' {
				return keyPageUp, nil
			}
			return keyPageDown, nil
		}
		return keyOther, nil
	}
	return r, nil
}

func (w *Wizard) choose(prompt string, choices []Choice) (rune, error) {
	w.beginPrompt()
	defer w.endPrompt()
	if len(choices) == 0 {
		return 0, fmt.Errorf("prompt has no choices")
	}
	sel := 0
	for {
		w.mu.Lock()
		w.selectionHelp = choices[sel].Description
		w.mu.Unlock()
		lines := []string{prompt, ""}
		for i, c := range choices {
			cursor := "  "
			if i == sel {
				cursor = "> "
			}
			lines = append(lines, fmt.Sprintf("%s[%c] %s", cursor, c.Key, c.Label))
		}
		lines = append(lines, "", "Up/Down  Move   Enter  Choose   Letter  Shortcut")
		w.draw(lines)

		k, err := w.readKey()
		if err != nil {
			return 0, err
		}
		if w.viewKey(k) {
			continue
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
			w.resetScroll()
		case keyDown, 'j':
			sel = (sel + 1) % len(choices)
			w.resetScroll()
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
	return w.readLineBack(prompt, def, hidden, false)
}
func (w *Wizard) readLineBack(prompt, def string, hidden, back bool) (string, error) {
	w.beginPrompt()
	defer w.endPrompt()
	var buf []rune
	note := ""
	for {
		shown := string(buf)
		if hidden {
			// Graph access tokens can contain thousands of characters. Keep
			// masked feedback on one line instead of pushing the prompt away.
			shown = strings.Repeat("*", min(len(buf), 32))
		}
		lines := []string{prompt}
		if def != "" {
			lines = append(lines, fmt.Sprintf("Default: %s (press Enter to accept it)", def))
		}
		if hidden {
			lines = append(lines, "Input is hidden.")
		}
		w.mu.Lock()
		fieldWidth := w.width() - 8
		w.mu.Unlock()
		lines = append(lines, "", "> "+inputTail(shown, fieldWidth)+"_", "")
		if note != "" {
			lines = append(lines, note)
		}
		lines = append(lines, "Type the value, then press Enter.")
		w.draw(lines)

		k, err := w.readKey()
		if err != nil {
			return "", err
		}
		if w.viewKey(k) {
			continue
		}
		switch {
		case k == rune(2) && back:
			return "", ErrBack
		case k == keyPaste:
			text := strings.ReplaceAll(cleanText(w.inputPaste), "\n", "")
			chars := []rune(text)
			remaining := max(0, 16384-len(buf))
			if len(chars) > remaining {
				chars = chars[:remaining]
				note = "Pasted text reached the 16,384-character limit. Review before Enter."
			}
			buf = append(buf, chars...)

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
			if len(buf) < 16384 {
				buf = append(buf, k)
			} else {
				note = "Input limit reached (16,384 characters)."
			}
		}
	}
}

func (w *Wizard) endPrompt() {
	w.mu.Lock()
	w.waiting = false
	w.details = false
	w.progressView = false
	w.scroll = 0
	w.prompt = nil
	w.selectionHelp = ""
	w.renderLocked()
	w.mu.Unlock()
}
func (w *Wizard) resetScroll() { w.mu.Lock(); w.scroll = 0; w.mu.Unlock() }
func (w *Wizard) viewKey(k rune) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.waiting && w.plainLink && (k == 'b' || k == 'B' || k == keyEnter) {
		w.plainLink = false
		return true
	}
	if (w.cols < 48 || w.rows < 16) && k != keyCancel && !(w.finalScreen && (k == 'f' || k == 'F' || k == keyEnter)) {
		return true
	}
	switch k {

	case 'l', 'L':
		if w.waiting || challengeURL(w.challenge) == "" {
			return false
		}
		w.plainLink = true
	case 'c', 'C':
		if w.waiting {
			return false
		}
		if target := challengeURL(w.challenge); target != "" {
			w.copyLinkLocked(target)
		} else {
			return false
		}
	case rune(25):
		if target := challengeURL(w.challenge); target != "" {
			w.copyLinkLocked(target)
		}
	case keyDetails:
		if w.cols < 104 || w.rows < 26 {
			if w.progressView {
				w.progressView = false
				w.details = true
			} else if w.details {
				w.details = false
			} else {
				w.progressView = true
			}
		} else {
			w.details = !w.details
			w.progressView = false
		}
		w.scroll = 0
	case keyPageUp:
		if !w.details && w.logPaneActive {
			w.logScroll += max(1, w.rows/3)
			break
		}
		w.scroll = max(0, w.scroll-max(1, w.rows/3))
	case keyPageDown:
		if !w.details && w.logPaneActive {
			w.logScroll = max(0, w.logScroll-max(1, w.rows/3))
			break
		}
		w.scroll += max(1, w.rows/3)
	case keyCancel:
		return false
	default:
		return w.details || w.progressView // do not submit a hidden prompt from history
	}
	return true
}

type keyEvent struct {
	paste string
	key   rune
	err   error
}

func (w *Wizard) beginPrompt() { w.mu.Lock(); w.waiting = true; w.scroll = 0; w.mu.Unlock() }
func (w *Wizard) readKey() (rune, error) {
	if w.keys != nil {
		var e keyEvent
		var ok bool
		select {
		case <-w.interrupt:
			return keyCancel, nil
		case e, ok = <-w.keys:
		}
		if !ok {
			return 0, io.EOF
		}
		w.inputPaste = e.paste
		return e.key, e.err
	}
	k, err := w.readRawKey()
	w.inputPaste = w.rawPaste
	w.rawPaste = ""
	return k, err
}
func (w *Wizard) startInput() {
	w.keys = make(chan keyEvent, 256)
	w.runes = make(chan runeEvent, 256)
	w.inputDone = make(chan struct{})
	go func() {
		defer close(w.runes)
		for {
			r, _, err := w.in.ReadRune()
			select {
			case <-w.inputDone:
				return
			case w.runes <- runeEvent{r, err}:
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer close(w.keys)
		for {
			k, err := w.readRawKey()
			w.mu.Lock()
			stopped, waiting := w.stopped, w.waiting
			w.mu.Unlock()
			if stopped {
				return
			}
			if waiting || err != nil {
				select {
				case <-w.inputDone:
					return
				case w.keys <- keyEvent{key: k, err: err, paste: w.rawPaste}:
				}
				w.rawPaste = ""
			} else if k == 'l' || k == 'L' || k == 'b' || k == 'B' || k == keyEnter || k == 'c' || k == 'C' || k == rune(25) || k == keyDetails || k == keyPageUp || k == keyPageDown {
				w.viewKey(k)
				w.redraw()
			}
			if err != nil {
				return
			}
		}
	}()
}

type runeEvent struct {
	r   rune
	err error
}

var errEscapeTimeout = fmt.Errorf("escape timeout")

func (w *Wizard) nextRune(wait time.Duration) (rune, error) {
	if w.runes == nil {
		r, _, err := w.in.ReadRune()
		return r, err
	}
	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-w.inputDone:
		return 0, io.EOF
	case <-timeout:
		return 0, errEscapeTimeout
	case e, ok := <-w.runes:
		if !ok {
			return 0, io.EOF
		}
		return e.r, e.err
	}
}
func inputTail(s string, width int) string {
	if runewidth.StringWidth(s) <= width {
		return s
	}
	runes := []rune(s)
	for len(runes) > 0 && runewidth.StringWidth(string(runes)) > width-1 {
		runes = runes[1:]
	}
	return "…" + string(runes)
}
