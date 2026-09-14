package stack

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestSchema(t *testing.T, cfg Config) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(cfg.InstallDir, "init"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.InstallDir, "init/001-initdb.sql"), []byte(goodSQL), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The database already exists, but the first-start scripts never made its
// tables. A normal Compose restart cannot recover this state.
func TestUpInitializesDatabaseBeforeApplicationHealth(t *testing.T) {
	cfg := testConfig(t)
	writeTestSchema(t, cfg)
	initialized := false
	startedApplication := false
	run := func(_ context.Context, stdin, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(stdin, "GUACDEPLOY_DATABASE_READY") {
			initialized = true
			return "GUACDEPLOY_DATABASE_READY\n", nil
		}
		if strings.Contains(joined, "up --detach --wait") {
			if !initialized {
				return "", errors.New(`relation "guacamole_entity" does not exist`)
			}
			startedApplication = true
		}
		return "ok", nil
	}
	if err := Up(context.Background(), run, cfg, testPassword, ""); err != nil {
		t.Fatal(err)
	}
	if !initialized || !startedApplication {
		t.Fatal("schema was not checked before application startup")
	}
}

func TestUpStopsBeforeApplicationsOnPartialDatabase(t *testing.T) {
	cfg := testConfig(t)
	writeTestSchema(t, cfg)
	startedApplication := false
	run := func(_ context.Context, stdin, name string, args ...string) (string, error) {
		if strings.Contains(stdin, "GUACDEPLOY_DATABASE_READY") {
			return "Database contains application objects. Repair stopped.", errors.New("exit status 3")
		}
		if strings.Contains(strings.Join(args, " "), "up --detach --wait") {
			startedApplication = true
		}
		return "ok", nil
	}
	err := Up(context.Background(), run, cfg, testPassword, "")
	if err == nil || startedApplication {
		t.Fatalf("partial database was allowed to start: %v", err)
	}
}
