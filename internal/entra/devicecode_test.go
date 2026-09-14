package entra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type deviceTransport func(*http.Request) (*http.Response, error)

func (f deviceTransport) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestDeviceCodeSDKAuthenticatesAndCachesInMemory(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	const token = "access-fixture-not-for-a-real-service"
	const device = "private-device-fixture"
	const refresh = "refresh-fixture-not-for-a-real-service"
	base := "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
	prompts, tokenRequests := 0, 0
	do := deviceTransport(func(r *http.Request) (*http.Response, error) {
		var result any
		switch {
		case strings.HasSuffix(r.URL.Path, "/discovery/instance"):
			result = map[string]any{"tenant_discovery_endpoint": "https://login.microsoftonline.com/" + tenant + "/v2.0/.well-known/openid-configuration", "metadata": []any{map[string]any{"preferred_network": "login.microsoftonline.com", "preferred_cache": "login.microsoftonline.com", "aliases": []string{"login.microsoftonline.com"}}}}
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			result = map[string]any{"authorization_endpoint": base + "authorize", "token_endpoint": base + "token", "device_authorization_endpoint": base + "devicecode", "issuer": "https://login.microsoftonline.com/" + tenant + "/v2.0", "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys"}
		case strings.HasSuffix(r.URL.Path, "/devicecode"):
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("client_id") != GraphCLIClientID {
				t.Fatal("wrong public sign-in client")
			}
			for _, permission := range append(append([]string{}, RequiredPermissions...), "Organization.Read.All") {
				if !strings.Contains(r.Form.Get("scope"), "https://graph.microsoft.com/"+permission) {
					t.Fatalf("scope missing: %s", permission)
				}
			}
			result = map[string]any{"device_code": device, "user_code": "USER-CODE", "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900, "interval": 1}
		case strings.HasSuffix(r.URL.Path, "/token"):
			tokenRequests++
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("device_code") != device || r.Form.Get("grant_type") != "device_code" {
				t.Fatalf("unexpected grant on request %d: %s", tokenRequests, r.Form.Get("grant_type"))
			}
			id := jwt(t, map[string]any{"tid": tenant, "oid": "user1", "sub": "user1", "preferred_username": "admin@example.test", "aud": GraphCLIClientID, "iss": "https://login.microsoftonline.com/" + tenant + "/v2.0", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
			info := base64.RawURLEncoding.EncodeToString([]byte(`{"uid":"user1","utid":"` + tenant + `"}`))
			var scopes []string
			for _, p := range append(append([]string{}, RequiredPermissions...), "Organization.Read.All") {
				scopes = append(scopes, "https://graph.microsoft.com/"+p)
			}
			result = map[string]any{"access_token": token, "refresh_token": refresh, "id_token": id, "client_info": info, "token_type": "Bearer", "expires_in": 3600, "scope": strings.Join(scopes, " ")}
		default:
			t.Fatalf("unexpected identity request: %s", r.URL.Path)
		}
		body, _ := json.Marshal(result)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})
	source, err := DeviceCodeTokenSource(DeviceCodeOptions{TenantID: tenant, Transport: do, Prompt: func(_ context.Context, url, code string) error {
		prompts++
		if url != "https://microsoft.com/devicelogin" || code != "USER-CODE" {
			t.Fatal("wrong user instruction")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := source(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != token {
			t.Fatal("token was not returned in memory")
		}
	}
	if prompts != 1 || tokenRequests != 1 {
		t.Fatalf("sign-in not reused: prompts=%d token requests=%d", prompts, tokenRequests)
	}
}

func TestDeviceCodeErrorsDoNotExposeProtocolSecrets(t *testing.T) {
	for _, err := range []error{errors.New("response: access_token=fixture-secret"), errors.New("AADSTS53003 response: refresh_token=fixture-secret")} {
		got := safeSignInError(err)
		if strings.Contains(got.Error(), "fixture-secret") {
			t.Fatal("SDK response reached error output")
		}
	}
	if !errors.Is(safeSignInError(fmt.Errorf("wrapped: %w", context.Canceled)), context.Canceled) {
		t.Fatal("cancellation was lost")
	}
}
