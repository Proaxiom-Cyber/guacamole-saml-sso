package stack

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run explicitly with GUACDEPLOY_TEST_DOCKER=1 go test ./internal/stack -run TestDatabaseIntegration.
// Each fixture is isolated, publishes no port and creates its password only
// inside container tmpfs. Its container and anonymous data volume are removed.
func TestDatabaseIntegration(t *testing.T) {
	if os.Getenv("GUACDEPLOY_TEST_DOCKER") != "1" {
		t.Skip("set GUACDEPLOY_TEST_DOCKER=1 for real PostgreSQL tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name := fmt.Sprintf("guacdeploy-db-test-%d", time.Now().UnixNano())
	docker := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command failed: %v\n%s", err, out)
		}
		return string(out)
	}
	docker("run", "-d", "--name", name, "--network", "none", "--tmpfs", "/run/secrets:rw,noexec,nosuid,size=1m",
		"-e", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password", "-e", "POSTGRES_DB=guacamole_db",
		"-e", "POSTGRES_USER=guacamole_user", "-e", "PGDATA=/var/lib/postgresql/data/guacamole",
		"--entrypoint", "sh", "postgres:18-alpine", "-ec",
		`(umask 077; head -c 32 /dev/urandom | base64 > /run/secrets/postgres-password); exec docker-entrypoint.sh postgres`)
	t.Cleanup(func() {
		out, err := exec.Command("docker", "rm", "-fv", name).CombinedOutput()
		if err != nil {
			t.Errorf("fixture cleanup: %v %s", err, out)
		}
	})
	cfg := Config{InstallDir: t.TempDir(), AdminGroup: "Admin's group", OperatorGroup: "Operators", InitializeDatabase: true}
	if err := os.Mkdir(filepath.Join(cfg.InstallDir, "init"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := GenerateSchema(ctx, ExecOutRunner, cfg); err != nil {
		t.Fatal(err)
	}

	// Compose transport is replaced only to target this isolated database. The
	// production readiness check, SQL, transaction and credential delivery run unchanged.
	run := func(c context.Context, stdin, tool string, args ...string) (string, error) {
		for i, arg := range args {
			if arg == "up" {
				return "", nil
			}
			if arg == "exec" {
				cmd := exec.CommandContext(c, "docker", append([]string{"exec", "-i", name}, args[i+3:]...)...)
				cmd.Stdin = strings.NewReader(stdin)
				out, err := cmd.CombinedOutput()
				return string(out), err
			}
		}
		return "", fmt.Errorf("unexpected fixture command")
	}
	sql := func(query string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", name, "sh", "-c", databasePSQL, "test", "-Atq", "-f", "-")
		cmd.Stdin = strings.NewReader(query)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture SQL failed: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	bootstrap, err := databaseBootstrap(cfg)
	if err != nil {
		t.Fatal(err)
	}
	apply := func(script string) error { return startDatabase(ctx, run, cfg, false, script) }
	reset := func() { sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;") }
	noObjects := func() {
		t.Helper()
		if n := sql("SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace;"); n != "0" {
			t.Fatalf("application objects remain: %s", n)
		}
	}

	t.Run("fresh_database_and_repeat_preserve_data", func(t *testing.T) {
		if err := apply(bootstrap); err != nil {
			t.Fatal(err)
		}
		if got := sql("SELECT count(*) FROM guacamole_entity WHERE type='USER_GROUP';"); got != "2" {
			t.Fatal(got)
		}
		if got := sql("SELECT count(*) FROM guacamole_entity WHERE name='guacadmin';"); got != "0" {
			t.Fatal("default login remains")
		}
		sql("CREATE TABLE preserve_me (value text); INSERT INTO preserve_me VALUES ('retained');")
		if err := apply(bootstrap); err != nil {
			t.Fatal(err)
		}
		if got := sql("SELECT value FROM preserve_me;"); got != "retained" {
			t.Fatal("existing data changed")
		}
	})
	t.Run("legacy_empty_database_is_initialized", func(t *testing.T) {
		reset()
		if err := apply(bootstrap); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("partial_type_is_preserved", func(t *testing.T) {
		reset()
		sql("CREATE TYPE incomplete_import AS ENUM ('one');")
		err := apply(bootstrap)
		if err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("partial import accepted: %v", err)
		}
		if got := sql("SELECT count(*) FROM pg_type WHERE typname='incomplete_import';"); got != "1" {
			t.Fatal("partial object was removed")
		}
	})
	t.Run("sql_error_rolls_back_schema_and_groups", func(t *testing.T) {
		reset()
		broken := strings.Replace(bootstrap, "\\echo "+databaseReady, "SELECT 1/0;\n\\echo "+databaseReady, 1)
		if err := apply(broken); err == nil {
			t.Fatal("expected SQL failure")
		}
		noObjects()
		if err := apply(bootstrap); err != nil {
			t.Fatal("retry:", err)
		}
	})
	t.Run("interrupted_transaction_rolls_back_and_resumes", func(t *testing.T) {
		reset()
		blocked := strings.Replace(bootstrap, "\\echo "+databaseReady, "SELECT pg_sleep(30);\n\\echo "+databaseReady, 1)
		done := make(chan error, 1)
		go func() { done <- apply(blocked) }()
		found := false
		for i := 0; i < 100; i++ {
			if sql("SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND state='active' AND query='SELECT pg_sleep(30);';") != "0" {
				found = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !found {
			t.Fatal("bootstrap did not reach interruption point")
		}
		sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND state='active' AND query='SELECT pg_sleep(30);';")
		if err := <-done; err == nil {
			t.Fatal("interruption succeeded unexpectedly")
		}
		noObjects()
		if err := apply(bootstrap); err != nil {
			t.Fatal("resume:", err)
		}
	})
	t.Run("completed_deployment_never_reinitializes_missing_data", func(t *testing.T) {
		reset()
		checkCfg := cfg
		checkCfg.InitializeDatabase = false
		check, err := databaseBootstrap(checkCfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(check); err == nil || !strings.Contains(err.Error(), "disabled") {
			t.Fatalf("missing data was replaced: %v", err)
		}
		noObjects()
	})
	t.Run("complete_schema_without_groups_requires_review", func(t *testing.T) {
		reset()
		b, err := os.ReadFile(filepath.Join(cfg.InstallDir, "init/001-initdb.sql"))
		if err != nil {
			t.Fatal(err)
		}
		sql(string(b))
		if err := apply(bootstrap); err == nil || !strings.Contains(err.Error(), "authorization groups") {
			t.Fatalf("incomplete groups accepted: %v", err)
		}
	})
}
