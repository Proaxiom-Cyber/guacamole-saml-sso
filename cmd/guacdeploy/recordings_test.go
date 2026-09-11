package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// --out is documented as a directory to write the recovered recording into,
// and the code used it as the file to write. An operator who followed the help
// was told their directory "already exists", which is true and useless.
func TestRecordingsRestoreAcceptsTheDirectoryItDocuments(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&state.State{DeploymentID: "d1"}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	src := filepath.Join(dir, "session-one.guac")
	content := []byte("recording bytes")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	man := backup.Manifest{
		ManifestVersion: 1, FormatVersion: 1, DeploymentID: "d1",
		File: "session-one.guac", Bytes: int64(len(content)),
		SHA256: hex.EncodeToString(sum[:]), Mode: "none", PublishedAt: time.Now().UTC(),
	}
	b, _ := json.Marshal(man)
	if err := os.WriteFile(src+backup.ManifestSuffix, b, 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "recovered")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	u, _ := cmdUI()
	if err := recordingsRestoreCmd(dir, src, outDir, "", u); err != nil {
		t.Fatalf("an existing directory must be written into, not refused: %v", err)
	}
	want := filepath.Join(outDir, "session-one.guac.playback")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("the recording was not written inside the directory: %v", err)
	}
	// The refusal to replace an existing file still applies to the result.
	if err := recordingsRestoreCmd(dir, src, outDir, "", u); err == nil {
		t.Fatal("a second run must refuse rather than replace the recovered file")
	}
}
