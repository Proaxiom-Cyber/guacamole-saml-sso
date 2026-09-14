package session

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// Exercise selection followed by the same live-directory validation used by
// sign-in. DNS ownership does not establish Microsoft tenant membership.
func TestEntraTenantIndependentOfCloudflare(t *testing.T) {
	for _, tc := range []struct{ name, zone, saved, input string }{
		{"different domains", "slqaccess.qld.gov.au", "", "\nslq.qld.gov.au\n"},
		{"correct unverified resume", "slqaccess.qld.gov.au", "slqaccess.qld.gov.au", "slq.qld.gov.au\n"},
		{"same domain", "slq.qld.gov.au", "", "slq.qld.gov.au\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GUACDEPLOY_ENTRA_TENANT_ID", "")
			u, _ := testUI(true, tc.input)
			st := &state.State{Config: map[string]string{"cloudflare-zone-name": tc.zone, "entra-login-tenant": tc.saved}}
			o := Options{}
			if err := o.selectEntraTenant(st, u); err != nil {
				t.Fatal(err)
			}
			c := &entra.Client{Token: func(context.Context) (string, error) { return "opaque-fixture", nil }, Do: func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet {
					t.Fatal("tenant validation attempted a mutation")
				}
				body := `{"value":[]}`
				if r.URL.Path == "/v1.0/organization" {
					body = `{"value":[{"id":"tenant-fixture","verifiedDomains":[{"name":"slq.qld.gov.au"}]}]}`
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			}}
			if _, _, err := c.CheckDeviceCodeToken(context.Background(), o.EntraTenant); err != nil {
				t.Fatalf("selected %q instead of the operator's Microsoft tenant: %v", o.EntraTenant, err)
			}
			if st.Config["cloudflare-zone-name"] != tc.zone || st.Config["entra-login-tenant"] != "slq.qld.gov.au" {
				t.Fatal("selection changed DNS or lost the corrected tenant")
			}
		})
	}
}

func TestEntraTenantExplicitEnvironmentCorrectsUnverifiedResume(t *testing.T) {
	t.Setenv("GUACDEPLOY_ENTRA_TENANT_ID", "slq.qld.gov.au")
	u, _ := testUI(false, "")
	st := &state.State{Config: map[string]string{"entra-login-tenant": "slqaccess.qld.gov.au"}}
	o := Options{}
	if err := o.selectEntraTenant(st, u); err != nil {
		t.Fatal(err)
	}
	if o.EntraTenant != "slq.qld.gov.au" {
		t.Fatalf("explicit tenant ignored: %s", o.EntraTenant)
	}
}

func TestEntraTenantKeepsVerifiedBinding(t *testing.T) {
	t.Setenv("GUACDEPLOY_ENTRA_TENANT_ID", "other.example")
	u, _ := testUI(true, "other.example\n")
	st := &state.State{Config: map[string]string{"entra-tenant-id": "verified-tenant", "entra-login-tenant": "old.example"}}
	o := Options{}
	if err := o.selectEntraTenant(st, u); err != nil {
		t.Fatal(err)
	}
	if o.EntraTenant != "verified-tenant" {
		t.Fatal("resume replaced a verified tenant")
	}
}

func TestEntraTenantRepromptsInvalidInput(t *testing.T) {
	t.Setenv("GUACDEPLOY_ENTRA_TENANT_ID", "")
	u, _ := testUI(true, "https://slq.qld.gov.au\nslq.qld.gov.au\n")
	o := Options{}
	if err := o.selectEntraTenant(&state.State{}, u); err != nil {
		t.Fatal(err)
	}
	if o.EntraTenant != "slq.qld.gov.au" {
		t.Fatal("valid correction was not accepted")
	}
}
