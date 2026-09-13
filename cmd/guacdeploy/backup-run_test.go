package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// scheduledRun sets up a deployment with a backup destination, as the
// installed timer would find one.
func scheduledRun(t *testing.T) schedule.Options {
	t.Helper()
	dir := t.TempDir()
	id := seedDeployment(t, dir, "pass-phrase-for-the-test")
	dest := filepath.Join(dir, "backups")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	return schedule.Options{StateDir: dir, Dest: dest, Keep: 2, Exe: os.Args[0], DeploymentID: id}
}

// seedBackup publishes an earlier valid backup, with the completion
// manifest that makes retention count it. Backup names carry a one-second
// timestamp, so earlier runs are simulated rather than taken back to back:
// a real schedule is daily.
func seedBackup(t *testing.T, o schedule.Options, stamp string) string {
	t.Helper()
	body := "-- guacdeploy backup format=1 guacamole=1.6.0 mode=none\n" + cmdFakeDump
	content := body + fmt.Sprintf("-- guacdeploy dump complete sha256:%x\n", sha256.Sum256([]byte(body)))
	name := "guacdeploy-db-" + stamp + ".sql"
	if err := os.WriteFile(filepath.Join(o.Dest, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := json.Marshal(backup.Manifest{
		ManifestVersion: backup.ManifestVersion, FormatVersion: backup.FormatVersion,
		DeploymentID: o.DeploymentID, File: name, Bytes: int64(len(content)),
		SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content))), Mode: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup.ManifestPath(o.Dest, name), m, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestBackupRunPublishesThenExpires(t *testing.T) {
	o := scheduledRun(t)
	oldest := seedBackup(t, o, "20260101T000000Z")
	seedBackup(t, o, "20260102T000000Z")

	var calls []recorded
	if err := backupRunCmd(context.Background(), fakeDocker(&calls), o, ui.New(false)); err != nil {
		t.Fatal(err)
	}

	names, err := schedule.List(o.Dest, o.DeploymentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("kept %v, want two backups at keep 2", names)
	}
	for _, n := range names {
		if n == oldest {
			t.Errorf("the oldest backup %s was not expired", oldest)
		}
	}

	s, err := schedule.ReadStatus(o.StateDir)
	if err != nil || s == nil {
		t.Fatalf("no last-run record: %v", err)
	}
	if s.Result != "ok" || s.Published == "" {
		t.Errorf("last run = %+v", s)
	}
	if s.Destination != o.Dest {
		t.Errorf("destination = %q, want %q", s.Destination, o.Dest)
	}
	if len(s.Removed) != 1 || !strings.HasSuffix(s.Removed[0], oldest) {
		t.Errorf("Removed = %v, want %s", s.Removed, oldest)
	}
	// The record must be readable without the deployment lock: that is how
	// the timer's result is shown after a reboot.
	if out := schedule.Summary(o.StateDir); !strings.Contains(out, o.Dest) {
		t.Errorf("summary does not show the destination:\n%s", out)
	}
}

func TestBackupRunFailsWithoutDeletingOrHoldingTheLock(t *testing.T) {
	o := scheduledRun(t)
	for _, s := range []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z"} {
		seedBackup(t, o, s)
	}
	before, _ := schedule.List(o.Dest, o.DeploymentID)
	if len(before) != 3 {
		t.Fatalf("setup left %v", before)
	}

	failDump := func(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
		if strings.Contains(strings.Join(args, " "), "pg_dump") {
			return "", "pg_dump: error: connection refused", errors.New("exit status 1")
		}
		return "", "", nil
	}
	if err := backupRunCmd(context.Background(), failDump, o, ui.New(false)); err == nil {
		t.Fatal("a failed export returned success; the timer would report a good run")
	}

	// Three valid backups with retention set to two: a run that pruned on
	// failure would have deleted one.
	after, _ := schedule.List(o.Dest, o.DeploymentID)
	if len(after) != len(before) {
		t.Errorf("a failed run changed the backup set: %v -> %v", before, after)
	}
	s, _ := schedule.ReadStatus(o.StateDir)
	if s == nil || s.Result != "failed" || len(s.Removed) != 0 {
		t.Errorf("failure not recorded cleanly: %+v", s)
	}
	if !strings.Contains(s.Error, "not published") {
		t.Errorf("status does not explain the failure: %q", s.Error)
	}
	if s.Kept != 3 {
		t.Errorf("Kept = %d, want the three untouched backups", s.Kept)
	}

	// The deployment lock must be released, or the next nightly run and
	// every interactive command would block behind a failed backup.
	store, err := state.Open(o.StateDir)
	if err != nil {
		t.Fatalf("the deployment lock was not released after a failed run: %v", err)
	}
	store.Close()
}

func TestBackupRunRefusesWithoutDestination(t *testing.T) {
	o := scheduledRun(t)
	o.Dest = ""
	var calls []recorded
	if err := backupRunCmd(context.Background(), fakeDocker(&calls), o, ui.New(false)); err == nil {
		t.Fatal("a scheduled run without a destination was accepted")
	}
	if len(calls) != 0 {
		t.Errorf("commands ran without a destination: %v", calls)
	}
}
