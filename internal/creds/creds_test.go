package creds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvVarNaming(t *testing.T) {
	if v := (Spec{Name: "cloudflare-api-token"}).EnvVar(); v != "GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN" {
		t.Fatal(v)
	}
}

func TestEnvModeGetAndMissing(t *testing.T) {
	m := &Manager{Mode: ModeEnv}
	s := Spec{Name: "cloudflare-api-token", Purpose: "test"}
	if miss := m.Missing([]Spec{s}); len(miss) != 1 || !strings.Contains(miss[0], s.EnvVar()) {
		t.Fatalf("missing = %v", miss)
	}
	if _, err := m.Get(s); err == nil {
		t.Fatal("Get must fail when the variable is unset")
	}
	t.Setenv(s.EnvVar(), "v1")
	if v, err := m.Get(s); err != nil || v != "v1" {
		t.Fatalf("got %q, %v", v, err)
	}
	// Cached: later env change does not alter the session value.
	t.Setenv(s.EnvVar(), "v2")
	if v, _ := m.Get(s); v != "v1" {
		t.Fatalf("cache broken: %q", v)
	}
}

func TestFileModeStoreAndGet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	m := &Manager{Mode: ModeFile, Dir: dir}
	s := Spec{Name: "cloudflare-api-token"}

	createdDir, err := m.StoreFile(s, "value-x")
	if err != nil || !createdDir {
		t.Fatalf("store: %v createdDir=%v", err, createdDir)
	}
	if createdDir2, _ := m.StoreFile(s, "value-x"); createdDir2 {
		t.Fatal("second store must not claim directory creation")
	}
	if v, err := m.Get(s); err != nil || v != "value-x" {
		t.Fatalf("got %q, %v", v, err)
	}
	info, _ := os.Stat(filepath.Join(dir, s.Name))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", info.Mode().Perm())
	}
}

func TestPromptModeWithoutTerminal(t *testing.T) {
	m := &Manager{Mode: ModePrompt}
	if _, err := m.Get(Spec{Name: "x"}); !errors.Is(err, ErrUnattendedPrompt) {
		t.Fatalf("want ErrUnattendedPrompt, got %v", err)
	}
	m.ReadSecret = func(string) (string, error) { return "s3cret", nil }
	if v, err := m.Get(Spec{Name: "x"}); err != nil || v != "s3cret" {
		t.Fatalf("got %q, %v", v, err)
	}
}

func TestExplainCoversAllModes(t *testing.T) {
	for _, m := range AllModes {
		if e := Explain(m); e == "" || e == "unknown mode" {
			t.Fatalf("no explanation for %s", m)
		}
	}
}
