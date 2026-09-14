package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

// journal records application events, not terminal input or subprocess output.
// Diagnostic files are private and retained after teardown for troubleshooting.
type journal struct {
	mu          sync.Mutex
	file        *os.File
	path, phase string
	err         error
	size        int
	secrets     []string
}

const maxLogBytes = 16 << 20

var escapeSequence = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)
var jwtValue = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
var credentialValue = regexp.MustCompile(`(?i)(bearer\s+|(?:access_token|refresh_token|client_secret|password|authorization)\s*[=:]\s*"?)[^\s",}]+`)

func cleanText(s string) string {
	s = escapeSequence.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// StartLog creates a distinct log for this invocation. Existing files and
// symbolic links are never followed or overwritten in the logs directory.
func (u *UI) StartLog(stateDir, command string) error {
	dir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create session log directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("session log directory must be a private directory (0700): %s", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := time.Now().UTC().Format("20060102T150405.000000000Z") + ".log"
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create session log: %w", err)
	}
	u.journal = &journal{file: f, path: filepath.Join(dir, name), phase: command}
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok && (strings.Contains(name, "TOKEN") || strings.Contains(name, "SECRET") || strings.Contains(name, "PASSWORD")) {
			u.Protect(value)
		}
	}
	u.record("INFO", "Session started: "+command)
	return nil
}

func (u *UI) LogPath() string {
	if u.journal == nil {
		return ""
	}
	return u.journal.path
}

// Protect adds a known secret to the in-memory redactor. It never writes it.
func (u *UI) Protect(s string) {
	if s == "" || u.journal == nil {
		return
	}
	j := u.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, existing := range j.secrets {
		if existing == s {
			return
		}
	}
	j.secrets = append(j.secrets, s)
}

func (u *UI) safe(s string) string {
	if j := u.journal; j != nil {
		j.mu.Lock()
		defer j.mu.Unlock()
		for _, secret := range j.secrets {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = credentialValue.ReplaceAllString(s, "${1}[redacted]")
	s = jwtValue.ReplaceAllString(s, "[redacted token]")
	if strings.Contains(s, "PRIVATE KEY-----") {
		return "[private key material omitted]"
	}
	return cleanText(s)
}

func (u *UI) record(level, message string) {
	j := u.journal
	if j == nil {
		return
	}
	message = u.safe(message)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil || j.err != nil {
		return
	}
	for _, line := range strings.Split(message, "\n") {
		entry := fmt.Sprintf("%s %-5s [%s] %s\n", time.Now().UTC().Format(time.RFC3339Nano), level, j.phase, line)
		if j.size+len(entry) > maxLogBytes {
			j.err = fmt.Errorf("session log reached its 16 MiB limit")
			return
		}
		n, err := j.file.WriteString(entry)
		j.size += n
		if err != nil {
			j.err = err
			return
		}
	}
}

// FinishLog is idempotent, including when a signal and normal exit race.
func (u *UI) FinishLog(err error) {
	if err != nil {
		u.record("ERROR", err.Error())
	} else {
		u.record("INFO", "Session finished")
	}
	j := u.journal
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return
	}
	if e := j.file.Sync(); e != nil && j.err == nil {
		j.err = e
	}
	if e := j.file.Close(); e != nil && j.err == nil {
		j.err = e
	}
	j.file = nil
	fmt.Fprintf(u.Out, "Session log: %s\n", j.path)
	if j.err != nil {
		fmt.Fprintf(u.Out, "Log incomplete: %v\n", j.err)
	}
}

// Transient shows an authorization challenge only while it is needed. It
// bypasses event history and the log. ClearTransient removes it after sign-in.
func (u *UI) Transient(format string, args ...any) {
	s := cleanText(fmt.Sprintf(format, args...))
	if w := u.wizard(); w != nil {
		w.mu.Lock()
		w.challenge = s
		w.mu.Unlock()
		w.redraw()
		return
	}
	fmt.Fprintln(u.Out, s)
}
func (u *UI) ClearTransient() {
	if w := u.wizard(); w != nil {
		w.mu.Lock()
		w.challenge = ""
		w.mu.Unlock()
		w.redraw()
	}
}
