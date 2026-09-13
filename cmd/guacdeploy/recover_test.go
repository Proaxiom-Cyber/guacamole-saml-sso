package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// Recovery rebuilds a lost host's record on a replacement. Running it where a
// deployment already lives would replace the record of the deployment
// actually running there, so it refuses before reading anything.
func TestRecoverRefusesWhereADeploymentAlreadyRuns(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&state.State{DeploymentID: "live-one"}); err != nil {
		t.Fatal(err)
	}
	store.Close()

	file := filepath.Join(dir, "backup.sql")
	if err := os.WriteFile(file, []byte("-- not even read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := cmdUI()
	err = recoverCmd(context.Background(), dir, file, "", true, u)
	if err == nil {
		t.Fatal("recovery ran on a host that already has a deployment")
	}
	if !strings.Contains(err.Error(), "live-one") || !strings.Contains(err.Error(), "replacement host") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
}

// An unattended run cannot answer a hidden prompt, so it must say what to set
// rather than wait or, worse, carry on without asking a provider anything.
func TestRecoverUnattendedNamesTheCredentialsItNeeds(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "backup.sql")
	// A plaintext dump, so the passphrase prompt is not the thing being
	// tested here; the provider credentials are.
	if err := os.WriteFile(file, []byte("-- guacdeploy backup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", "")
	t.Setenv("GUACDEPLOY_GRAPH_TOKEN", "")
	u, _ := cmdUI()
	u.Interactive = false
	err := recoverCmd(context.Background(), dir, file, "", true, u)
	if err == nil {
		t.Fatal("an unattended recovery with no credentials must stop")
	}
	// Whatever it stops on, it must name something the operator can act on.
	if !strings.Contains(err.Error(), "GUACDEPLOY_") && !strings.Contains(err.Error(), "backup") {
		t.Fatalf("the error names nothing actionable: %v", err)
	}
}
