package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// TestInterruptedSetupIsResumable exercises the acceptance criteria of
// issue #1 end to end: interrupt a running setup, verify retained state and
// a released lock, verify unattended refusal without --resume, then resume.
func TestInterruptedSetupIsResumable(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "guacdeploy")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()

	cmd := exec.Command(bin, "setup", "--non-interactive", "--state-dir", dir)
	cmd.Env = append(os.Environ(), "GUACDEPLOY_TEST_SLEEP_PHASE=30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Wait until the slow phase's intent is journalled, then interrupt.
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := state.Read(dir)
		if err == nil && st != nil {
			if p := st.Pending(); len(p) == 1 && p[0].Intent == "test-sleep" {
				break
			}
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("test-sleep intent never journalled")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 130 {
		t.Fatalf("interrupted exit: %v, want code 130", err)
	}

	// State retained, lock released.
	st, err := state.Read(dir)
	if err != nil || st == nil || len(st.Pending()) != 1 {
		t.Fatalf("state after interrupt: %+v, %v", st, err)
	}
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("lock not released after interrupt: %v", err)
	}
	s.Close()

	// Unattended without consent: exit 3, no waiting.
	out, err := exec.Command(bin, "setup", "--non-interactive", "--state-dir", dir).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 {
		t.Fatalf("unattended without --resume: %v, want code 3\n%s", err, out)
	}

	// Explicit resume completes the interrupted work.
	resume := exec.Command(bin, "setup", "--non-interactive", "--resume", "--state-dir", dir)
	resume.Env = append(os.Environ(), "GUACDEPLOY_TEST_SLEEP_PHASE=0")
	if out, err := resume.CombinedOutput(); err != nil {
		t.Fatalf("resume: %v\n%s", err, out)
	}
	st, _ = state.Read(dir)
	if len(st.Pending()) != 0 {
		t.Fatalf("pending after resume: %+v", st.Pending())
	}
}

// A live resume skipped stack-configure, so a check placed in that phase never
// ran and the certificate authority refused the run again. A malformed contact
// has to be caught where it is always seen: parsing the flag.
func TestSetupRefusesAContactTheCertificateAuthorityWillNot(t *testing.T) {
	dir := t.TempDir()
	if code := run([]string{"setup", "--non-interactive", "--state-dir", dir,
		"--acme-contact", "tel:+61000"}); code != 2 {
		t.Fatalf("want exit 2 for a usage error, got %d", code)
	}
	// Nothing may have been written: the refusal comes before the session runs.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("the refused run wrote %d entries into the state directory", len(entries))
	}
}
