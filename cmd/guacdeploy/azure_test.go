package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// newDeployment writes a minimal deployment record and returns its state
// directory.
func newDeployment(t *testing.T, config map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(&state.State{DeploymentID: state.NewID(), Config: config}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAzureUploadRefusesAnUnconfiguredDeployment(t *testing.T) {
	var out bytes.Buffer
	u := &ui.UI{Out: &out}

	err := azureUploadCmd(context.Background(), newDeployment(t, nil), t.TempDir(), u)
	if err == nil || !strings.Contains(err.Error(), "no Azure Blob destination is configured") {
		t.Fatalf("err = %v", err)
	}

	// With no deployment at all, the message says so rather than failing on
	// a missing destination.
	err = azureUploadCmd(context.Background(), t.TempDir(), t.TempDir(), u)
	if err == nil || !strings.Contains(err.Error(), "no deployment exists") {
		t.Fatalf("err = %v", err)
	}
}

func TestAzureUploadNeedsALocalDestinationToCopyFrom(t *testing.T) {
	dir := newDeployment(t, map[string]string{
		"azure-subscription-id": "sub", "azure-account": "acct",
		"azure-container": "guacdeploy", "azure-account-id": "/subscriptions/sub",
		"azure-blob-endpoint": "https://acct.blob.core.windows.net",
	})
	err := azureUploadCmd(context.Background(), dir, "", &ui.UI{Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "--dest") {
		t.Fatalf("err = %v; a scheduled upload must never fall back to a guessed source", err)
	}
}

func TestAzureStatusWithoutAnyRun(t *testing.T) {
	var out bytes.Buffer
	if err := azureStatusCmd(t.TempDir(), &ui.UI{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No Azure upload has run yet") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestAzureDestinationComesFromNonSecretStateOnly(t *testing.T) {
	st := &state.State{Config: map[string]string{
		"azure-subscription-id": "sub-1", "azure-resource-group": "rg",
		"azure-account": "acct", "azure-container": "c",
		"azure-account-id": "/subscriptions/sub-1", "azure-blob-endpoint": "https://acct.blob.core.windows.net",
	}}
	d := azureDestinationFrom(st)
	if !d.Configured() || d.Account != "acct" || d.ResourceGroup != "rg" {
		t.Fatalf("destination = %+v", d)
	}
	for k := range st.Config {
		if strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "token") {
			t.Fatalf("state config key %q looks like a credential; secrets belong in the credential store", k)
		}
	}
}

// The two Azure retention rules are separate, and only one of them can be
// switched off. Leaving the backup count out must mean the default of seven,
// because remote backups accumulating for ever is the defect it closes.
func TestAzureBackupKeepDefaultsRatherThanKeepingForEver(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        int
		wantErr     bool
	}{
		{name: "absent means the package default", value: "", want: 0},
		{name: "an explicit count is honoured", value: "3", want: 3},
		{name: "zero is refused, not read as for ever", value: "0", wantErr: true},
		{name: "a negative count is refused", value: "-1", wantErr: true},
		{name: "nonsense is refused rather than ignored", value: "lots", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &state.State{Config: map[string]string{azureBackupKeepConfig: tc.value}}
			got, err := azureBackupKeep(st)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%q was accepted", tc.value)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
