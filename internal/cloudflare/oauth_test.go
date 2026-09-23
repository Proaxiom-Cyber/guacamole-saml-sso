package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
)

type oauthTransport func(*http.Request) (*http.Response, error)

func (f oauthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func oauthResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestManualOAuthPKCEAndRefresh(t *testing.T) {
	var challenge string
	calls := 0
	h := &http.Client{Transport: oauthTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != tokenURL || r.Method != "POST" {
			t.Fatal("unexpected endpoint")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		calls++
		if calls == 1 {
			hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(hash[:]) != challenge || r.Form.Get("code") != "fixture-code" || r.Form.Get("redirect_uri") != OAuthRedirectURI {
				t.Fatal("PKCE exchange not bound to approval")
			}
			return oauthResponse(`{"access_token":"fixture-access","refresh_token":"fixture-refresh","token_type":"bearer","expires_in":1}`), nil
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "fixture-refresh" {
			t.Fatal("incorrect refresh credential")
		}
		return oauthResponse(`{"access_token":"next-access","refresh_token":"next-refresh","token_type":"bearer","expires_in":3600}`), nil
	})}
	c := OAuthConfig{ClientID: "fixture-client", HTTP: h}
	value, err := c.Authorize(context.Background(), func(address string) (string, error) {
		u, _ := url.Parse(address)
		q := u.Query()
		challenge = q.Get("code_challenge")
		if q.Get("code_challenge_method") != "S256" || q.Get("response_mode") != "query" {
			t.Fatal("incorrect authorization request")
		}
		return OAuthRedirectURI + "?" + url.Values{"state": {q.Get("state")}, "code": {"fixture-code"}}.Encode(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := creds.Spec{Name: "cloudflare-api-token"}
	sealed := map[string]string{}
	m := &creds.Manager{Mode: creds.ModeHostKey, Dir: t.TempDir(), Run: func(_ context.Context, input, _ string, args ...string) (string, string, error) {
		if args[0] == "encrypt" {
			id := fmt.Sprintf("opaque-%d", len(sealed))
			sealed[id] = input
			return id, "", nil
		}
		return sealed[input], "", nil
	}}
	m.Remember(spec, value)
	source := CredentialTokenSource(m, spec, h)
	token, err := source(context.Background())
	if err != nil || token != "next-access" {
		t.Fatalf("refresh failed: %v", err)
	}
	_, err = source(context.Background())
	if err != nil || calls != 2 {
		t.Fatal("fresh token was not cached")
	}
	b, err := os.ReadFile(m.Path(spec))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "refresh") || strings.Contains(string(b), "access") {
		t.Fatal("plaintext credential written")
	}
	fresh := &creds.Manager{Mode: m.Mode, Dir: m.Dir, Run: m.Run}
	token, err = CredentialTokenSource(fresh, spec, h)(context.Background())
	if err != nil || token != "next-access" || calls != 2 {
		t.Fatal("rotated credential did not survive a new process")
	}
}

func TestManualReturnRejectsWrongOrAmbiguousAddress(t *testing.T) {
	for _, raw := range []string{
		"https://localhost:18977/callback?state=s&code=secret",
		"http://localhost:18977.evil.test/callback?state=s&code=secret",
		"http://user@localhost:18977/callback?state=s&code=secret",
		OAuthRedirectURI + "?state=wrong&code=secret",
		OAuthRedirectURI + "?state=s&state=s&code=secret",
		OAuthRedirectURI + "?state=s&code=secret&code=other",
		OAuthRedirectURI + "?state=s&code=secret#fragment",
		OAuthRedirectURI + "?state=s&error=denied",
		OAuthRedirectURI + "?state=s",
		"%invalid-secret",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := returnedCode(raw, "s")
			if err == nil {
				t.Fatal("accepted invalid return")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error disclosed input")
			}
		})
	}
}

func TestOAuthCancellationAndLegacyToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	c := OAuthConfig{ClientID: "fixture", HTTP: &http.Client{Transport: oauthTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, fmt.Errorf("fixture-secret") })}}
	_, err := c.Authorize(ctx, func(string) (string, error) { return "", nil })
	if err == nil || calls != 0 {
		t.Fatal("cancelled sign-in made request")
	}
	m := &creds.Manager{Mode: creds.ModePrompt}
	spec := creds.Spec{Name: "cloudflare-api-token"}
	m.Remember(spec, "existing-api-token")
	token, err := CredentialTokenSource(m, spec, c.HTTP)(context.Background())
	if err != nil || token != "existing-api-token" || calls != 0 {
		t.Fatal("legacy token changed")
	}
	expired := oauthCredential{ClientID: "fixture", Access: "a", Refresh: "r", Expires: time.Now().Add(-time.Hour)}
	m.Remember(spec, expired.encode())
	_, err = CredentialTokenSource(m, spec, c.HTTP)(context.Background())
	if err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("provider error leaked")
	}
}
