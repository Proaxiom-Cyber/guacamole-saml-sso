package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	st := &State{DeploymentID: NewID(), CreatedAt: time.Now().UTC(), Config: map[string]string{"hostname": "h1"}}
	st.Actions = append(st.Actions, Action{ID: NewID(), Intent: "initialise-deployment", StartedAt: time.Now().UTC()})
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentID != st.DeploymentID || got.Config["hostname"] != "h1" || len(got.Actions) != 1 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version not stamped: %d", got.SchemaVersion)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadMissingReturnsNil(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Load()
	if err != nil || st != nil {
		t.Fatalf("want nil,nil got %v,%v", st, err)
	}
}

func TestLockExcludesSecondOpen(t *testing.T) {
	dir := t.TempDir()
	s1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	if _, err := Open(dir); err != ErrLocked {
		t.Fatalf("second open: want ErrLocked, got %v", err)
	}
	s1.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("open after release: %v", err)
	}
	s2.Close()
}

func TestTornTempFileDoesNotCorruptState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := &State{DeploymentID: NewID(), CreatedAt: time.Now().UTC()}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	// Simulate an interrupted later save: a partial temp file next to the
	// committed state must not affect reads.
	if err := os.WriteFile(filepath.Join(dir, "state-zzz.tmp"), []byte(`{"schema_v`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || got == nil || got.DeploymentID != st.DeploymentID {
		t.Fatalf("state corrupted by torn temp file: %v %v", got, err)
	}
}

func TestPendingDetection(t *testing.T) {
	now := time.Now().UTC()
	st := &State{Actions: []Action{
		{Intent: "a", StartedAt: now, FinishedAt: &now, Result: ResultOK},
		{Intent: "b", StartedAt: now}, // interrupted
		{Intent: "c", StartedAt: now, FinishedAt: &now, Result: ResultUncertain},
	}}
	p := st.Pending()
	if len(p) != 2 || p[0].Intent != "b" || p[1].Intent != "c" {
		t.Fatalf("pending = %+v", p)
	}
}

func TestDeleteRefusesWithCreatedResources(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := &State{DeploymentID: NewID(), Resources: []Resource{{ID: "r1", Provider: "cloudflare", Type: "dns-record"}}}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(st); err == nil || !strings.Contains(err.Error(), "teardown") {
		t.Fatalf("delete with resources: want teardown refusal, got %v", err)
	}
	st.Resources = nil
	if err := s.Delete(st); err != nil {
		t.Fatalf("delete without resources: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatal("state file still present after delete")
	}
}

func TestStateJSONNeverContainsSecretFieldNames(t *testing.T) {
	// The schema must not grow credential value fields. Guard the wire
	// format against the obvious names.
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := &State{DeploymentID: NewID()}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"password", "secret", "private_key", "token"} {
		if strings.Contains(strings.ToLower(string(b)), `"`+bad) {
			t.Fatalf("state wire format contains field %q", bad)
		}
	}
}
