package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"
)

func TestTeardownWithoutADeploymentSaysSo(t *testing.T) {
	u, out := cmdUI()
	if err := teardownCmd(context.Background(), t.TempDir(), false, false, u); err != nil {
		t.Fatalf("no deployment is not an error: %v", err)
	}
	if !strings.Contains(out.String(), "nothing to tear down") {
		t.Errorf("unhelpful output:\n%s", out)
	}
}

// The command takes the deployment lock, presents the plan, and stops an
// unattended run before removing anything. Nothing here reaches a provider.
func TestTeardownUnattendedNeedsConsent(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{DeploymentID: "d1", Resources: []state.Resource{{
		ID: "r1", Provider: "cloudflare", Type: "dns-record",
		ProviderID: "rec1", Name: "guac.example.com", Ownership: "marker comment",
	}}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	u, _ := cmdUI()
	if err := teardownCmd(context.Background(), dir, false, false, u); !errors.Is(err, state.ErrLocked) {
		t.Fatalf("teardown must take the deployment lock, got %v", err)
	}
	store.Close()

	u, out := cmdUI()
	err = teardownCmd(context.Background(), dir, false, false, u)
	if !errors.Is(err, teardown.ErrApprovalRequired) {
		t.Fatalf("want ErrApprovalRequired, got %v", err)
	}
	if !strings.Contains(out.String(), "guac.example.com") {
		t.Errorf("the plan was not presented:\n%s", out)
	}

	after, err := state.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Resources) != 1 {
		t.Error("a refused teardown changed the deployment record")
	}
}

// With nothing left recorded, the deployment record goes, so setup starts
// clean. With something still recorded, it stays, so setup cannot build over
// a deployment that was not fully removed.
func TestTeardownRemovesTheRecordOnlyWhenEmpty(t *testing.T) {
	write := func(t *testing.T, res []state.Resource) string {
		t.Helper()
		dir := t.TempDir()
		store, err := state.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if err := store.Save(&state.State{DeploymentID: "d1", Resources: res}); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	dir := write(t, nil)
	u, out := cmdUI()
	if err := teardownCmd(context.Background(), dir, true, false, u); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	st, err := state.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Error("the record survived a teardown that left nothing recorded")
	}
	if !strings.Contains(out.String(), "starts a new deployment from clean") {
		t.Errorf("the clean restart was not reported:\n%s", out)
	}

	// Packages remain installed, but their record becomes archived history.
	dir = write(t, []state.Resource{{
		ID: "r-pkg", Provider: "host", Type: "package",
		Name: "docker-ce", Ownership: "installed by this deployment",
	}})
	u, out = cmdUI()
	if err := teardownCmd(context.Background(), dir, true, false, u); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	if st, err = state.Read(dir); err != nil || st != nil {
		t.Fatalf("the completed deployment was not retired: %v", err)
	}
	if !strings.Contains(out.String(), "archived") {
		t.Errorf("the kept record was not explained:\n%s", out)
	}
}

// installDirOf reads the installation directory from the record rather than
// assuming the default, because an operator can install elsewhere.
func TestInstallDirComesFromTheRecord(t *testing.T) {
	st := &state.State{Resources: []state.Resource{
		{Provider: "docker", Type: "container", Name: "guacamole-nginx-1"},
		{Provider: "host", Type: "config-directory", Name: "/srv/guac"},
	}}
	if got := installDirOf(st); got != "/srv/guac" {
		t.Errorf("want /srv/guac, got %q", got)
	}
	if got := installDirOf(&state.State{}); got != "" {
		t.Errorf("want empty for a record with no installation directory, got %q", got)
	}
}

func TestCompletedCleanupAllowsFreshSetupWithRetainedHostPackages(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{DeploymentID: "old", Config: map[string]string{}, Resources: []state.Resource{{ID: "pkg", Provider: "host", Type: "package", Name: "docker-ce", Ownership: "installed by deployment"}}, Actions: []state.Action{{ID: "interrupted", Intent: "credential-check"}}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	store.Close()
	u, out := cmdUI()
	if err := teardownCmd(context.Background(), dir, true, true, u); err != nil {
		t.Fatal(err)
	}
	if err := session.Run(context.Background(), session.Options{StateDir: dir, UI: u, Phases: []session.Phase{}}); err != nil {
		t.Fatalf("fresh setup after successful cleanup failed: %v\n%s", err, out.String())
	}
	next, err := state.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if next.DeploymentID == "old" {
		t.Fatal("cleanup resumed the old deployment")
	}
}

func TestRetainedBackupDoesNotBecomeInterruptedSetup(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{DeploymentID: "retained", Config: map[string]string{"backup-dest": t.TempDir()}, Actions: []state.Action{{ID: "a", Intent: "credential-check"}}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	store.Close()
	u, out := cmdUI()
	if err := teardownCmd(context.Background(), dir, true, false, u); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = session.Run(context.Background(), session.Options{StateDir: dir, UI: u, Phases: []session.Phase{}})
	if err == nil || strings.Contains(err.Error(), "interrupted work exists") || !strings.Contains(err.Error(), "retained data") {
		t.Fatalf("wrong post-teardown behavior: %v", err)
	}
	if st, err := state.Read(dir); err != nil || st == nil {
		t.Fatal("retained data lost its record")
	}
}

func TestTeardownDeletesDataBeforeRetiringItsParentDirectory(t *testing.T) {
	dir := t.TempDir()
	install := filepath.Join(t.TempDir(), "guacamole")
	if err := os.MkdirAll(filepath.Join(install, "recordings"), 0700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := &state.State{DeploymentID: "old", Config: map[string]string{}, Resources: []state.Resource{
		{ID: "config", Provider: "host", Type: "config-directory", Name: install, Ownership: "rendered by deployment"},
	}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	store.Close()
	u, out := cmdUI()
	if err := teardownCmd(context.Background(), dir, true, true, u); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(install); !os.IsNotExist(err) {
		t.Fatalf("empty installation directory survived teardown: %v\n%s", err, out.String())
	}
	if st, err := state.Read(dir); err != nil || st != nil {
		t.Fatalf("active deployment survived full teardown: %v", err)
	}
}
