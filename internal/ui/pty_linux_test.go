//go:build linux

// Acceptance tests that need a real terminal. They allocate a pseudo-terminal,
// run a real process on it, and read the terminal settings back from the
// kernel. The unit tests in wizard_test.go drive the wizard through injected
// readers and writers; these prove what a buffer cannot: exact terminal
// restoration, the exit code after an interruption, what a resize does, and
// which conditions produce plain output.
//
// Linux only, and deliberately so. macOS does not report the /dev/ptmx master
// as a terminal, so the same test cannot run on a development Mac. Run it on
// the supported target:
//
//	go test ./internal/ui/ -run PTY -v
package ui_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// Linux ioctl numbers for the pseudo-terminal multiplexer. These come from
// asm-generic, so they are the same on amd64 and arm64, the architectures this
// tool targets.
const (
	tiocsptlck = 0x40045431 // unlock the pair
	tiocgptn   = 0x80045430 // read the pair number
)

// ioctl runs one ioctl on an open file. It reaches the descriptor through
// SyscallConn rather than File.Fd, because Fd puts the descriptor into
// blocking mode and permanently disables SetReadDeadline on it. Without this
// the reader below blocks for ever instead of timing out.
func ioctl(f *os.File, req, arg uintptr) error {
	c, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioErr error
	if err := c.Control(func(fd uintptr) {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); errno != 0 {
			ioErr = errno
		}
	}); err != nil {
		return err
	}
	return ioErr
}

type pty struct{ master, slave *os.File }

// openPTY allocates a pseudo-terminal pair at the given size. The parent keeps
// both ends: the master to drive the child and read what it draws, the
// terminal side to read the terminal settings back after the child has gone.
func openPTY(t *testing.T, rows, cols uint16) *pty {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	var unlock int32
	if err := ioctl(m, tiocsptlck, uintptr(unsafe.Pointer(&unlock))); err != nil {
		t.Fatalf("unlock the pty pair: %v", err)
	}
	var n uint32
	if err := ioctl(m, tiocgptn, uintptr(unsafe.Pointer(&n))); err != nil {
		t.Fatalf("read the pty number: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open the terminal side: %v", err)
	}
	p := &pty{master: m, slave: s}
	p.resize(t, rows, cols)
	t.Cleanup(func() { s.Close(); m.Close() })
	return p
}

// resize changes the terminal size. The kernel sends SIGWINCH to the
// foreground process group on the terminal, exactly as a window manager does.
func (p *pty) resize(t *testing.T, rows, cols uint16) {
	t.Helper()
	ws := struct{ Row, Col, X, Y uint16 }{rows, cols, 0, 0}
	if err := ioctl(p.master, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws))); err != nil {
		t.Fatalf("resize to %dx%d: %v", cols, rows, err)
	}
}

// termios reads the current terminal settings from the kernel.
func (p *pty) termios(t *testing.T) syscall.Termios {
	t.Helper()
	var tio syscall.Termios
	if err := ioctl(p.slave, syscall.TCGETS, uintptr(unsafe.Pointer(&tio))); err != nil {
		t.Fatalf("read the terminal settings: %v", err)
	}
	return tio
}

// muteEcho turns off the terminal's own echo of what is typed. That echo is
// the kernel's doing, not program output, and it would otherwise appear in a
// capture taken from the terminal but not in one taken from a redirected
// file, which would make the two impossible to compare.
func (p *pty) muteEcho(t *testing.T) {
	t.Helper()
	tio := p.termios(t)
	tio.Lflag &^= syscall.ECHO
	if err := ioctl(p.slave, syscall.TCSETS, uintptr(unsafe.Pointer(&tio))); err != nil {
		t.Fatalf("turn off the terminal echo: %v", err)
	}
}

// termiosDiff names every field that changed, so a failure says what was left
// behind rather than only that something was.
func termiosDiff(before, after syscall.Termios) []string {
	var out []string
	add := func(name string, a, b uint32) {
		if a != b {
			out = append(out, fmt.Sprintf("%s %#x -> %#x", name, a, b))
		}
	}
	add("Iflag", before.Iflag, after.Iflag)
	add("Oflag", before.Oflag, after.Oflag)
	add("Cflag", before.Cflag, after.Cflag)
	add("Lflag", before.Lflag, after.Lflag)
	add("Ispeed", before.Ispeed, after.Ispeed)
	add("Ospeed", before.Ospeed, after.Ospeed)
	if before.Line != after.Line {
		out = append(out, fmt.Sprintf("Line %d -> %d", before.Line, after.Line))
	}
	for i := range before.Cc {
		if before.Cc[i] != after.Cc[i] {
			out = append(out, fmt.Sprintf("Cc[%d] %#x -> %#x", i, before.Cc[i], after.Cc[i]))
		}
	}
	return out
}

// runner runs one process on the terminal and collects what it draws while it
// is still running, so a test can wait for the right moment to act.
type runner struct {
	pty         *pty
	controlling bool
	name        string
	args, env   []string
	stdout      *os.File // nil sends output to the terminal
	drive       func(t *testing.T, r *runner)

	mu   sync.Mutex
	buf  bytes.Buffer
	proc *os.Process
}

type result struct {
	code          int
	out           string
	before, after syscall.Termios
}

// seen returns everything drawn so far.
func (r *runner) seen() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func (r *runner) send(s string) { r.pty.master.Write([]byte(s)) }

// await blocks until the plain text of the output contains want.
func (r *runner) await(t *testing.T, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if strings.Contains(stripANSI(r.seen()), want) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("the process never drew %q within %s; saw:\n%s", want, within, stripANSI(r.seen()))
}

func (r *runner) run(t *testing.T) result {
	t.Helper()
	before := r.pty.termios(t)

	cmd := exec.Command(r.name, r.args...)
	cmd.Stdin = r.pty.slave
	if r.stdout != nil {
		cmd.Stdout, cmd.Stderr = r.stdout, r.stdout
	} else {
		cmd.Stdout, cmd.Stderr = r.pty.slave, r.pty.slave
	}
	cmd.Env = r.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: r.controlling, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", r.name, err)
	}
	r.proc = cmd.Process

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 8192)
		for {
			r.pty.master.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := r.pty.master.Read(b)
			if n > 0 {
				r.mu.Lock()
				r.buf.Write(b[:n])
				r.mu.Unlock()
			}
			select {
			case <-stop:
				if n == 0 {
					return
				}
			default:
			}
			if err != nil && !os.IsTimeout(err) {
				return
			}
		}
	}()

	// A child that waits for input it will never get must not stall the
	// suite. The watchdog is a backstop, not a timing assumption: every test
	// here either drives the child to an exit or kills it itself.
	finished := make(chan struct{})
	go func() {
		select {
		case <-finished:
		case <-time.After(90 * time.Second):
			t.Errorf("the process did not exit within 90s; killing it")
			cmd.Process.Kill()
		}
	}()

	if r.drive != nil {
		r.drive(t, r)
	}

	err := cmd.Wait()
	close(finished)
	code := 0
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatalf("wait for %s: %v", r.name, err)
	}

	time.Sleep(250 * time.Millisecond) // let the last output arrive
	close(stop)
	wg.Wait()

	out := r.seen()
	if r.stdout != nil {
		b, err := os.ReadFile(r.stdout.Name())
		if err != nil {
			t.Fatalf("read the redirected output: %v", err)
		}
		out = string(b)
	}
	return result{code: code, out: out, before: before, after: r.pty.termios(t)}
}

var (
	ansiSeq    = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")
	colourSeq  = regexp.MustCompile("\x1b\\[[0-9;]*m")
	idPattern  = regexp.MustCompile(`\b[0-9a-f]{32}\b`)
	rfc3339Pat = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T[\d:]+Z`)
)

func stripANSI(s string) string { return ansiSeq.ReplaceAllString(s, "") }

// normalise removes the parts that legitimately differ between two runs, so
// the rest can be compared byte for byte.
func normalise(s string) string {
	s = idPattern.ReplaceAllString(s, "<deployment-id>")
	s = rfc3339Pat.ReplaceAllString(s, "<time>")
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// ---------------------------------------------------------------------------
// The child helper. The test binary re-runs itself as the child, so the child
// links the real internal/ui and can exit any way a test needs.
// ---------------------------------------------------------------------------

const childModeEnv = "GUACDEPLOY_PTY_CHILD_MODE"

func TestPTYChildHelper(t *testing.T) {
	mode := os.Getenv(childModeEnv)
	if mode == "" {
		t.Skip("helper process, run indirectly by the PTY acceptance tests")
	}
	os.Exit(childMain(mode))
}

func childMain(mode string) int {
	u := ui.New(true)
	defer u.RestoreTerminal()

	if !u.StartWizard() {
		fmt.Fprintln(os.Stderr, "CHILD-NO-WIZARD")
		return 9
	}
	u.PhaseList([]string{"alpha", "bravo", "charlie"})
	u.PhaseStart("alpha")
	u.Say("CHILD-READY")
	u.PhaseDone("alpha")

	switch mode {
	case "normal":
		u.Say("finished cleanly")
		return 0
	case "error":
		u.PhaseFailed("bravo", errors.New("the request was refused"))
		return 1
	case "panic":
		panic("a phase exploded")
	case "resize":
		for i := 0; i < 60; i++ { // keep drawing while the parent resizes
			u.Say("output line %d", i)
			time.Sleep(50 * time.Millisecond)
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "CHILD-UNKNOWN-MODE")
	return 9
}

func childRunner(t *testing.T, p *pty, mode string, controlling bool, drive func(*testing.T, *runner)) *runner {
	t.Helper()
	return &runner{
		pty: p, controlling: controlling,
		name:  os.Args[0],
		args:  []string{"-test.run=TestPTYChildHelper"},
		env:   append(os.Environ(), childModeEnv+"="+mode, "TERM=xterm-256color"),
		drive: drive,
	}
}

// ---------------------------------------------------------------------------
// 1. Terminal settings are restored exactly, on every exit path.
// ---------------------------------------------------------------------------

func TestPTYTermiosRestoredExactly(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		controlling bool
		wantCode    int // -1 means any non-zero code
	}{
		{"normal", true, 0},
		{"error", true, 1},
		{"panic", true, -1},
		{"normal", false, 0},
		{"error", false, 1},
		{"panic", false, -1},
	} {
		name := tc.mode
		if !tc.controlling {
			name += "-no-controlling-terminal"
		}
		t.Run(name, func(t *testing.T) {
			p := openPTY(t, 24, 80)
			r := childRunner(t, p, tc.mode, tc.controlling, nil).run(t)

			if strings.Contains(r.out, "CHILD-NO-WIZARD") {
				t.Fatal("the wizard refused to start on a real terminal")
			}
			if !strings.Contains(stripANSI(r.out), "CHILD-READY") {
				t.Fatalf("the child never reached the wizard:\n%s", stripANSI(r.out))
			}
			switch {
			case tc.wantCode >= 0 && r.code != tc.wantCode:
				t.Errorf("exit code %d, want %d", r.code, tc.wantCode)
			case tc.wantCode < 0 && r.code == 0:
				t.Error("a panic exited 0")
			}
			if diff := termiosDiff(r.before, r.after); len(diff) > 0 {
				t.Errorf("terminal settings were not restored exactly: %s", strings.Join(diff, "; "))
			}
			// Leaving the alternate screen is separate from the settings, and
			// both have to happen, exactly once.
			if n := strings.Count(r.out, "\x1b[?1049l"); n != 1 {
				t.Errorf("left the alternate screen %d times, want 1", n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. A resize is honoured: no frame outgrows the window.
// ---------------------------------------------------------------------------

func TestPTYResize(t *testing.T) {
	p := openPTY(t, 24, 80)
	// Sizes stay at or above the documented floor of 20 rows and 40 columns.
	// Below that the frame is taller than the window by design.
	sizes := []struct{ rows, cols uint16 }{{30, 100}, {24, 60}, {20, 46}}

	r := childRunner(t, p, "resize", true, func(t *testing.T, r *runner) {
		r.await(t, "CHILD-READY", 15*time.Second)
		for _, s := range sizes {
			p.resize(t, s.rows, s.cols)
			time.Sleep(700 * time.Millisecond)
		}
		r.proc.Signal(syscall.SIGKILL)
	}).run(t)

	last := sizes[len(sizes)-1]
	frames := strings.Split(r.out, "\x1b[H\x1b[2J")
	if len(frames) < 4 {
		t.Fatalf("only %d frames were drawn", len(frames))
	}
	// The final frame can be cut short by the kill, so check the one before.
	final := stripANSI(frames[len(frames)-2])
	lines := strings.Split(strings.TrimSuffix(final, "\r\n"), "\r\n")

	var wide []string
	for _, l := range lines {
		if n := len([]rune(l)); n > int(last.cols) {
			wide = append(wide, fmt.Sprintf("%d columns: %q", n, l))
		}
	}
	if len(wide) > 0 {
		t.Errorf("after the window narrowed to %d columns, %d line(s) still overflow it:\n%s",
			last.cols, len(wide), strings.Join(wide, "\n"))
	}
	if len(lines) > int(last.rows) {
		t.Errorf("after the window shrank to %d rows, the frame is %d lines", last.rows, len(lines))
	}
}

// ---------------------------------------------------------------------------
// 3. Cancelling: the real binary, its real signal handler, and exit code 130.
// ---------------------------------------------------------------------------

// guacdeployBinary returns a built guacdeploy. GUACDEPLOY_BIN skips the build
// when the caller has already produced one.
func guacdeployBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GUACDEPLOY_BIN"); p != "" {
		return p
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("no go.mod above the test directory")
		}
		root = parent
	}
	bin := filepath.Join(t.TempDir(), "guacdeploy")
	build := exec.Command("go", "build", "-o", bin, "./cmd/guacdeploy")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build guacdeploy: %v\n%s", err, out)
	}
	return bin
}

func setupRunner(t *testing.T, p *pty, extraEnv []string, drive func(*testing.T, *runner)) *runner {
	t.Helper()
	return &runner{
		pty: p, controlling: true,
		name:  guacdeployBinary(t),
		args:  []string{"setup", "--state-dir", t.TempDir()},
		env:   append(append(os.Environ(), "TERM=xterm-256color"), extraEnv...),
		drive: drive,
	}
}

const cancelNotice = "Cancelled. Completed work is saved"

// TestPTYWizardKeepsSignalCharacters reads the terminal settings while the
// wizard is running. Raw mode is in force, but the signal characters have to
// survive it: Ctrl-C must still raise a signal, because nothing reads the
// keyboard while a phase runs, and the characters that would suspend or quit
// must be switched off, because either would strand the alternate screen.
func TestPTYWizardKeepsSignalCharacters(t *testing.T) {
	p := openPTY(t, 24, 80)
	var running syscall.Termios
	r := childRunner(t, p, "resize", true, func(t *testing.T, r *runner) {
		r.await(t, "CHILD-READY", 15*time.Second)
		time.Sleep(200 * time.Millisecond)
		running = p.termios(t)
		r.proc.Signal(syscall.SIGKILL)
	}).run(t)
	_ = r

	if running.Lflag&syscall.ISIG == 0 {
		t.Error("ISIG is off while the wizard runs, so Ctrl-C cannot reach the signal handler")
	}
	if running.Lflag&syscall.ECHO != 0 {
		t.Error("the terminal still echoes, so the wizard is not in raw mode at all")
	}
	if running.Lflag&syscall.ICANON != 0 {
		t.Error("the terminal is still canonical, so keys arrive only a line at a time")
	}
	if got := running.Cc[syscall.VINTR]; got != 3 {
		t.Errorf("the interrupt character is %#x, want Ctrl-C (0x3)", got)
	}
	if got := running.Cc[syscall.VSUSP]; got != 0 {
		t.Errorf("the suspend character is %#x, want it switched off", got)
	}
	if got := running.Cc[syscall.VQUIT]; got != 0 {
		t.Errorf("the quit character is %#x, want it switched off", got)
	}
}

func TestPTYCancelAtAPrompt(t *testing.T) {
	// Ctrl-C reaches the signal handler, which prints the notice. Escape is
	// read as a key by the wizard, which prints the same notice itself. Both
	// have to restore the terminal and exit 130.
	for _, tc := range []struct{ name, key string }{
		{"ctrl-c", "\x03"},
		{"escape", "\x1b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := openPTY(t, 24, 80)
			r := setupRunner(t, p, nil, func(t *testing.T, r *runner) {
				r.await(t, "Start a fresh setup?", 20*time.Second)
				r.send(tc.key)
			}).run(t)

			if r.code != 130 {
				t.Errorf("cancelling at a prompt exited %d, want 130", r.code)
			}
			if diff := termiosDiff(r.before, r.after); len(diff) > 0 {
				t.Errorf("terminal settings were not restored: %s", strings.Join(diff, "; "))
			}
			if n := strings.Count(stripANSI(r.out), cancelNotice); n != 1 {
				t.Errorf("the cancellation notice appeared %d times, want 1:\n%s", n, stripANSI(r.out))
			}
			if n := strings.Count(r.out, "\x1b[?1049l"); n != 1 {
				t.Errorf("left the alternate screen %d times, want 1", n)
			}
		})
	}
}

// TestPTYCancelDuringARunningPhase covers the case an operator hits most: a
// long phase is running, nothing is reading the keyboard, and they press
// Ctrl-C. The signal variant proves the handler itself works, so a failure in
// the key variant can only be about how the key reaches it.
func TestPTYCancelDuringARunningPhase(t *testing.T) {
	reachRunningPhase := func(t *testing.T, r *runner) {
		r.await(t, "Start a fresh setup?", 20*time.Second)
		r.send("y")
		r.await(t, "[running]  test-sleep", 20*time.Second)
		time.Sleep(300 * time.Millisecond)
	}

	t.Run("ctrl-c", func(t *testing.T) {
		p := openPTY(t, 24, 80)
		r := setupRunner(t, p, []string{"GUACDEPLOY_TEST_SLEEP_PHASE=8"}, func(t *testing.T, r *runner) {
			reachRunningPhase(t, r)
			r.send("\x03")
			time.Sleep(2 * time.Second)
			if r.proc != nil {
				r.proc.Signal(syscall.SIGKILL) // never hang the suite
			}
		}).run(t)

		if diff := termiosDiff(r.before, r.after); len(diff) > 0 {
			t.Errorf("terminal settings were not restored: %s", strings.Join(diff, "; "))
		}
		if r.code != 130 {
			t.Errorf("Ctrl-C during a running phase exited %d, want 130", r.code)
		}
		if n := strings.Count(stripANSI(r.out), cancelNotice); n != 1 {
			t.Errorf("the cancellation notice appeared %d times, want 1", n)
		}
	})

	// Suspending or quitting through the terminal would leave the screen on
	// the alternate buffer in raw mode with nothing left running to put it
	// back, so both characters are switched off. If either still worked, the
	// Ctrl-C that follows could not be acted on.
	t.Run("suspend-and-quit-are-off", func(t *testing.T) {
		p := openPTY(t, 24, 80)
		r := setupRunner(t, p, []string{"GUACDEPLOY_TEST_SLEEP_PHASE=8"}, func(t *testing.T, r *runner) {
			reachRunningPhase(t, r)
			r.send("\x1a") // Ctrl-Z
			r.send("\x1c") // Ctrl-backslash
			time.Sleep(500 * time.Millisecond)
			r.send("\x03") // Ctrl-C
			time.Sleep(2 * time.Second)
			if r.proc != nil {
				r.proc.Signal(syscall.SIGKILL) // never hang the suite
			}
		}).run(t)

		if r.code != 130 {
			t.Errorf("after Ctrl-Z and Ctrl-backslash, Ctrl-C exited %d, want 130", r.code)
		}
		if diff := termiosDiff(r.before, r.after); len(diff) > 0 {
			t.Errorf("terminal settings were not restored: %s", strings.Join(diff, "; "))
		}
	})

	t.Run("signal", func(t *testing.T) {
		p := openPTY(t, 24, 80)
		r := setupRunner(t, p, []string{"GUACDEPLOY_TEST_SLEEP_PHASE=8"}, func(t *testing.T, r *runner) {
			reachRunningPhase(t, r)
			r.proc.Signal(syscall.SIGINT)
		}).run(t)

		if r.code != 130 {
			t.Errorf("a signal during a phase exited %d, want 130", r.code)
		}
		if diff := termiosDiff(r.before, r.after); len(diff) > 0 {
			t.Errorf("terminal settings were not restored: %s", strings.Join(diff, "; "))
		}
		if n := strings.Count(stripANSI(r.out), cancelNotice); n != 1 {
			t.Errorf("the cancellation notice appeared %d times, want 1", n)
		}
	})
}

// ---------------------------------------------------------------------------
// 4. Plain output, each condition proven on a real terminal.
// ---------------------------------------------------------------------------

// runSetup drives one complete setup with the test phase registry and returns
// everything the operator would see.
func runSetup(t *testing.T, term string, extraEnv []string, redirect bool, keys string) result {
	t.Helper()
	p := openPTY(t, 24, 80)
	p.muteEcho(t)
	env := append(extraEnv, "GUACDEPLOY_TEST_SLEEP_PHASE=1", "TERM="+term)

	r := &runner{
		pty: p, controlling: true,
		name: guacdeployBinary(t),
		args: []string{"setup", "--state-dir", t.TempDir()},
		env:  append(os.Environ(), env...),
		drive: func(t *testing.T, r *runner) {
			if keys != "" {
				time.Sleep(900 * time.Millisecond)
				r.send(keys)
			}
		},
	}
	if redirect {
		f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		r.stdout = f
	}
	out := r.run(t)
	if diff := termiosDiff(out.before, out.after); len(diff) > 0 {
		t.Errorf("terminal settings were not restored: %s", strings.Join(diff, "; "))
	}
	return out
}

func TestPTYPlainOutputConditions(t *testing.T) {
	// A full terminal gets the wizard, with colour.
	full := runSetup(t, "xterm-256color", nil, false, "y")
	if !strings.Contains(full.out, "\x1b[?1049h") {
		t.Fatal("a full terminal did not get the full-screen wizard")
	}
	if !colourSeq.MatchString(full.out) {
		t.Error("a full terminal got no colour at all")
	}

	// NO_COLOR keeps the wizard and removes only the colour.
	noColour := runSetup(t, "xterm-256color", []string{"NO_COLOR=1"}, false, "y")
	if !strings.Contains(noColour.out, "\x1b[?1049h") {
		t.Error("NO_COLOR wrongly disabled the wizard as well as the colour")
	}
	if colourSeq.MatchString(noColour.out) {
		t.Errorf("NO_COLOR still produced colour: %q", colourSeq.FindString(noColour.out))
	}

	// Each fallback, proven rather than assumed. A line-oriented prompt reads
	// a whole line, so these get "y\n".
	fallbacks := map[string]result{
		"stdout redirected to a file": runSetup(t, "xterm-256color", nil, true, "y\n"),
		"TERM=dumb":                   runSetup(t, "dumb", nil, false, "y\n"),
		"TERM unset":                  runSetup(t, "", nil, false, "y\n"),
	}
	for name, got := range fallbacks {
		if strings.ContainsRune(got.out, 0x1b) {
			t.Errorf("%s still produced control codes: %q", name, ansiSeq.FindString(got.out))
		}
		if !strings.Contains(got.out, "Phase test-sleep: complete.") {
			t.Errorf("%s did not produce the line-oriented phase output:\n%s", name, got.out)
		}
	}

	// The three fallbacks must agree with each other byte for byte.
	want := normalise(fallbacks["TERM=dumb"].out)
	for name, got := range fallbacks {
		if name == "TERM=dumb" {
			continue
		}
		if g := normalise(got.out); g != want {
			t.Errorf("%s differs from TERM=dumb:\n--- %s ---\n%s\n--- TERM=dumb ---\n%s", name, name, g, want)
		}
	}
}

func TestPTYNonInteractiveIsUntouched(t *testing.T) {
	p := openPTY(t, 24, 80)
	// A real terminal on every stream, but --non-interactive: no wizard, no
	// control codes, and nothing may wait for input.
	r := (&runner{
		pty: p, controlling: true,
		name: guacdeployBinary(t),
		args: []string{"setup", "--non-interactive", "--state-dir", t.TempDir()},
		env:  append(os.Environ(), "TERM=xterm-256color", "GUACDEPLOY_TEST_SLEEP_PHASE=1"),
	}).run(t)

	if strings.ContainsRune(r.out, 0x1b) {
		t.Errorf("unattended output carries control codes: %q", ansiSeq.FindString(r.out))
	}
	if r.code != 0 {
		t.Errorf("unattended setup exited %d, want 0:\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "Phase test-sleep: complete.") {
		t.Errorf("unattended setup did not report its phases:\n%s", r.out)
	}
	if diff := termiosDiff(r.before, r.after); len(diff) > 0 {
		t.Errorf("unattended setup changed the terminal settings: %s", strings.Join(diff, "; "))
	}
}
