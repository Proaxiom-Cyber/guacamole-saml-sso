package main

import (
	"context"
	"errors"
	"strings"
	"testing"

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

	// A package this deployment installed is kept on purpose, so the record
	// is kept with it.
	dir = write(t, []state.Resource{{
		ID: "r-pkg", Provider: "host", Type: "package",
		Name: "docker-ce", Ownership: "installed by this deployment",
	}})
	u, out = cmdUI()
	if err := teardownCmd(context.Background(), dir, true, false, u); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	if st, err = state.Read(dir); err != nil || st == nil {
		t.Fatalf("the record was removed while something is still recorded: %v", err)
	}
	if !strings.Contains(out.String(), "will not build a new deployment over them") {
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
