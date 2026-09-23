package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArchivePreservesHistoryAndRecoveryExport(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := &State{DeploymentID: "old", Config: map[string]string{}}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "recovery"), 0700); err != nil {
		t.Fatal(err)
	}
	// Public fixture text stands in for an encrypted recovery export.
	if err := os.WriteFile(filepath.Join(dir, "recovery", "backup-key.age"), []byte("encrypted fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := s.Archive(st)
	if err != nil {
		t.Fatal(err)
	}
	if active, err := s.Load(); err != nil || active != nil {
		t.Fatal("old deployment still active")
	}
	if old, err := Read(path); err != nil || old.DeploymentID != "old" {
		t.Fatal("lost audit record")
	}
	if _, err := os.Stat(filepath.Join(path, "recovery", "backup-key.age")); err != nil {
		t.Fatal("lost recovery export")
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery")); !os.IsNotExist(err) {
		t.Fatal("old recovery export blocks new setup")
	}
}
