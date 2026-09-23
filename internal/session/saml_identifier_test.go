package session

import (
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"testing"
)

func TestStackConfigCarriesSavedSAMLIdentifier(t *testing.T) {
	st := &state.State{Config: map[string]string{"guac-hostname": "guacamole.slqaccess.qld.gov.au", "saml-entity-id": "api://app-id", "entra-tenant-id": "different-tenant"}}
	cfg := (&Options{}).stackConfig(st)
	if cfg.SAMLEntityID != "api://app-id" || cfg.Hostname != "guacamole.slqaccess.qld.gov.au" {
		t.Fatalf("identifier and hostname were conflated: %#v", cfg)
	}
}
