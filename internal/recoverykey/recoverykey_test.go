package recoverykey

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportRecoverRoundtrip(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recovery", "backup-key.age")
	if err := ExportEncrypted(id, "correct-horse", path); err != nil {
		t.Fatal(err)
	}

	// Owner-only permissions on file and parent directory.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("export mode = %o, want 600", got)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("export dir mode = %o, want 700", got)
	}

	// The plaintext private key must never be on disk.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("AGE-SECRET-KEY-")) {
		t.Fatal("export contains the private key in cleartext")
	}

	got, err := RecoverIdentity(path, "correct-horse")
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got.String() != id.String() || got.Recipient().String() != id.Recipient().String() {
		t.Fatal("recovered identity does not match the generated one")
	}

	if _, err := RecoverIdentity(path, "wrong"); err == nil {
		t.Fatal("wrong passphrase must fail")
	}

	// An existing export is never overwritten.
	if err := ExportEncrypted(id, "x", path); err == nil {
		t.Fatal("overwriting an existing export must fail")
	}
}

func TestEncryptToDecryptRoundtrip(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	// Encryption uses only the public key.
	if err := EncryptTo(id.Recipient().String(), strings.NewReader("backup bytes"), &ct); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct.Bytes(), []byte("backup bytes")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	var pt bytes.Buffer
	if err := Decrypt(id, &ct, &pt); err != nil {
		t.Fatal(err)
	}
	if pt.String() != "backup bytes" {
		t.Fatalf("roundtrip = %q", pt.String())
	}
}
