package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
)

// Explicitly enabled read-only live probe. It never writes credentials to disk.
func TestLiveHostedOAuth(t *testing.T) {
	if os.Getenv("GUACDEPLOY_LIVE_OAUTH") != "1" {
		t.Skip("explicit live test only")
	}
	config := OAuthConfig{ClientID: os.Getenv("GUACDEPLOY_TEST_CLIENT_ID"), RelayURL: os.Getenv("GUACDEPLOY_TEST_RELAY")}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	value, err := config.AuthorizeHosted(ctx, func(address string) error { t.Log("Approve in a separate browser:", address); return nil })
	if err != nil {
		t.Fatal(err)
	}
	var original oauthCredential
	if json.Unmarshal([]byte(strings.TrimPrefix(value, oauthPrefix)), &original) != nil {
		t.Fatal("invalid credential")
	}
	tokens := []oauthCredential{original}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 60*time.Second)
		defer done()
		for _, c := range tokens {
			for _, item := range []struct{ token, hint string }{{c.Refresh, "refresh_token"}, {c.Access, "access_token"}} {
				form := url.Values{"client_id": {c.ClientID}, "token": {item.token}, "token_type_hint": {item.hint}}
				status, e := oauthRequest(cleanup, oauthHTTP(nil), "POST", "https://dash.cloudflare.com/oauth2/revoke", "", "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
				if e != nil || status != 200 {
					t.Error("Revocation failed", item.hint, status)
				} else {
					t.Log("Revoked", item.hint, status)
				}
			}
		}
	}()
	client := Client{Token: func(context.Context) (string, error) { return original.Access, nil }}
	for _, path := range []string{"/accounts?per_page=1", "/zones/bd33a2e2c0b9cdb67ca10cfdbed00a00", "/zones/bd33a2e2c0b9cdb67ca10cfdbed00a00/dns_records?per_page=1", "/accounts/7c3fbcc2ed71191b09eed3e3a827ea4c/cfd_tunnel?per_page=1", "/accounts/7c3fbcc2ed71191b09eed3e3a827ea4c/access/apps?per_page=1", "/accounts/7c3fbcc2ed71191b09eed3e3a827ea4c/access/identity_providers?per_page=1", "/accounts/7c3fbcc2ed71191b09eed3e3a827ea4c/access/organizations"} {
		if e := client.do(ctx, "GET", path, nil, nil); e != nil {
			t.Fatal("Resource read failed", path)
		}
		t.Log("Read passed", path)
	}
	original.Expires = time.Now().Add(-time.Minute)
	m := &creds.Manager{Mode: creds.ModePrompt}
	spec := creds.Spec{Name: "cloudflare-api-token"}
	m.Remember(spec, original.encode())
	_, err = CredentialTokenSource(m, spec, nil)(ctx)
	if err != nil {
		t.Fatal("Refresh failed")
	}
	updated, _ := m.Get(spec)
	var next oauthCredential
	_ = json.Unmarshal([]byte(strings.TrimPrefix(updated, oauthPrefix)), &next)
	tokens = append(tokens, next)
	if next.Access == "" || next.Refresh == "" {
		t.Fatal("Refresh returned empty tokens")
	}
	t.Log("Refresh passed")
}
