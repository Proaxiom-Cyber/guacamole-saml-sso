//go:build linux

package session

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// Driven through a real PTY by the credential-navigation regression probe.
// It exercises only menus, with a fake detector and no credentials or cloud calls.
func TestCredentialNavigationPTYHelper(t *testing.T) {
	if os.Getenv("GUACDEPLOY_CREDENTIAL_NAV_TEST") != "1" {
		t.Skip("PTY helper")
	}
	u := ui.New(true)
	if !u.StartWizard() {
		t.Fatal("requires a terminal")
	}
	u.PhaseList([]string{"host-preflight", "credential-mode", "credential-check"})
	u.PhaseDone("host-preflight")
	u.PhaseStart("credential-mode")
	d, _ := sealingHost(t, new([]string))
	o := Options{CredDetector: d}
	st := &state.State{Config: map[string]string{"os": "rocky 10"}}
	if err := o.credentialMode(context.Background(), st, u); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "CREDENTIAL_SELECTION_FINISHED:"+st.Config["credential-mode"])
}
