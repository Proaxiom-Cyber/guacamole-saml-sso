package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// seedState creates a minimal deployment record so backup-key has a
// deployment to link the public key to.
func seedState(t *testing.T, dir string) {
	t.Helper()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Save(&state.State{DeploymentID: state.NewID(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

// testUI returns a UI whose hidden prompts answer from the given values in
// order, capturing output in out.
func testUI(t *testing.T, out *bytes.Buffer, secrets ...string) *ui.UI {
	t.Helper()
	i := 0
	return &ui.UI{Out: out, Secret: func(string) (string, error) {
		if i >= len(secrets) {
			t.Fatal("more hidden prompts than expected")
		}
		s := secrets[i]
		i++
		return s, nil
	}}
}

func TestBackupKeyGenerateAndVerify(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	const pass = "th3-passphrase-value"

	var out bytes.Buffer
	if err := backupKey(dir, false, testUI(t, &out, pass, pass)); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Public key recorded in state; no secrets in state.json or output.
	st, err := state.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub := st.Config["backup-public-key"]
	if !strings.HasPrefix(pub, "age1") {
		t.Fatalf("recorded public key = %q", pub)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"state.json": raw, "output": out.Bytes()} {
		if bytes.Contains(b, []byte("AGE-SECRET-KEY-")) {
			t.Errorf("%s contains the private key", name)
		}
		if bytes.Contains(b, []byte(pass)) {
			t.Errorf("%s contains the passphrase", name)
		}
	}

	// Output covers location, transfer instructions, responsibilities.
	path := backupKeyPath(dir)
	for _, want := range []string{path, "scp ", "BOTH", "does not prove", "--verify"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q", want)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("export not written: %v", err)
	}

	// Verify demonstrates recovery against the recorded public key.
	var vout bytes.Buffer
	if err := backupKey(dir, true, testUI(t, &vout, pass)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(vout.String(), "Recovery verified") {
		t.Errorf("verify output = %q", vout.String())
	}
	if err := backupKey(dir, true, testUI(t, &vout, "wrong")); err == nil {
		t.Fatal("verify with the wrong passphrase must fail")
	}

	// A second generation must refuse: it would orphan existing backups.
	if err := backupKey(dir, false, testUI(t, &out, pass, pass)); err == nil {
		t.Fatal("second generation must be refused")
	}
}

func TestBackupKeyRejectsBadPassphrases(t *testing.T) {
	dir := t.TempDir()
	seedState(t, dir)
	var out bytes.Buffer

	if err := backupKey(dir, false, testUI(t, &out, "one", "two")); err == nil {
		t.Fatal("mismatched confirmation must be rejected")
	}
	if err := backupKey(dir, false, testUI(t, &out, "")); err == nil {
		t.Fatal("empty passphrase must be rejected")
	}
	if _, err := os.Stat(backupKeyPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no export may exist after rejected passphrases")
	}
}

func TestBackupKeyNeedsStateAndTerminal(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer

	// Unattended: no hidden input available, so approval is required.
	err := backupKey(dir, false, &ui.UI{Out: &out})
	if !errors.Is(err, ui.ErrInputRequired) {
		t.Fatalf("unattended: %v, want ErrInputRequired", err)
	}

	// No deployment record: refuse with an explanation.
	err = backupKey(dir, false, testUI(t, &out, "p", "p"))
	if err == nil || !strings.Contains(err.Error(), "no deployment") {
		t.Fatalf("missing state: %v", err)
	}
}
