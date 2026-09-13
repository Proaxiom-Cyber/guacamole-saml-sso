package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// deviceSecret is the code the identity platform hands back to start the flow.
// It is a credential for the length of the flow, so it must not appear in any
// error, any rendered struct, or anything serialised.
const deviceSecret = "DEVICE-CODE-SECRET-must-never-appear"

const (
	accessToken  = "ACCESS-TOKEN-must-never-appear"
	refreshToken = "REFRESH-TOKEN-must-never-appear"
	clientSecret = "CLIENT-SECRET-must-never-appear"
)

// fakeLogin answers the identity platform's two endpoints from a script of
// replies, and records the form values it was sent.
type fakeLogin struct {
	t *testing.T

	device  *http.Response
	replies []*http.Response // consumed in order by the token endpoint
	forms   []map[string]string
	slept   time.Duration
}

func (f *fakeLogin) do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	form := map[string]string{}
	for _, pair := range strings.Split(string(body), "&") {
		if k, v, ok := strings.Cut(pair, "="); ok {
			form[k] = v
		}
	}
	f.forms = append(f.forms, form)
	if strings.HasSuffix(req.URL.Path, "/devicecode") {
		return f.device, nil
	}
	if len(f.replies) == 0 {
		f.t.Fatalf("the token endpoint was called more times than the test scripted")
	}
	r := f.replies[0]
	f.replies = f.replies[1:]
	return r, nil
}

func oauthError(code string) *http.Response {
	return httpResponse(http.StatusBadRequest,
		`{"error":"`+code+`","error_description":"AADSTS70016: the description\r\nTrace ID: abc"}`, nil)
}

func tokenReply(access, refresh string, expiresIn int) *http.Response {
	return httpResponse(http.StatusOK, fmt.Sprintf(
		`{"access_token":"%s","refresh_token":"%s","expires_in":%d,"token_type":"Bearer"}`,
		access, refresh, expiresIn), nil)
}

func newApp(f *fakeLogin) App {
	return App{TenantID: "contoso.example", ClientID: "client-abc", Login: "https://login.test",
		Do: f.do, Sleep: func(d time.Duration) { f.slept += d }}
}

// TestDeviceCodeFlowPollsThroughPendingAndSlowDown is the whole guided
// sign-in: the administrator is shown a code, the platform says "not yet",
// then says "slow down", then issues the tokens.
func TestDeviceCodeFlowPollsThroughPendingAndSlowDown(t *testing.T) {
	f := &fakeLogin{t: t,
		device: httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`","user_code":"KTQ7X9YR",
			"verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5,
			"message":"To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code KTQ7X9YR."}`, nil),
		replies: []*http.Response{
			oauthError("authorization_pending"),
			oauthError("slow_down"),
			oauthError("authorization_pending"),
			tokenReply(accessToken, refreshToken, 3600),
		},
	}
	a := newApp(f)

	dc, err := a.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dc.UserCode != "KTQ7X9YR" || dc.VerificationURL != "https://microsoft.com/devicelogin" {
		t.Fatalf("device code = %+v", dc)
	}
	if !strings.Contains(dc.Message, "KTQ7X9YR") {
		t.Fatalf("message = %q", dc.Message)
	}
	if shown := fmt.Sprintf("%+v", *dc); strings.Contains(shown, deviceSecret) {
		t.Fatalf("formatting a DeviceCode exposes the device code: %s", shown)
	}
	if b, _ := json.Marshal(dc); strings.Contains(string(b), deviceSecret) {
		t.Fatalf("a DeviceCode serialises its device code: %s", b)
	}

	s, err := a.CompleteSignIn(context.Background(), dc)
	if err != nil {
		t.Fatal(err)
	}
	// Three polls waited: 5s, then 10s after slow_down, then 10s.
	if f.slept != 25*time.Second {
		t.Fatalf("slept %v; slow_down must add five seconds to the interval", f.slept)
	}
	if len(f.forms) != 5 {
		t.Fatalf("%d identity-platform calls, want 5", len(f.forms))
	}
	for _, form := range f.forms[1:] {
		if form["grant_type"] != "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" {
			t.Fatalf("poll used grant_type %q", form["grant_type"])
		}
	}

	// The management token came from the sign-in itself and is cached, so no
	// further call is needed for that scope.
	tok, err := s.TokenSource()(context.Background(), ScopeManagement)
	if err != nil {
		t.Fatal(err)
	}
	if tok != accessToken {
		t.Fatalf("management token = %q", tok)
	}

	// The storage token is redeemed from the refresh token: one sign-in, two
	// planes.
	f.replies = []*http.Response{tokenReply("STORAGE-TOKEN", "", 3600)}
	tok, err = s.TokenSource()(context.Background(), ScopeStorage)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "STORAGE-TOKEN" {
		t.Fatalf("storage token = %q", tok)
	}
	last := f.forms[len(f.forms)-1]
	if last["grant_type"] != "refresh_token" {
		t.Fatalf("storage token was not fetched with the refresh token: %v", last)
	}
	if !strings.Contains(last["scope"], "storage.azure.com") {
		t.Fatalf("storage token was requested for scope %q", last["scope"])
	}
}

func TestDeviceCodeFlowReportsRefusalAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		code, want string
	}{
		{"authorization_declined", "authorization_declined"},
		{"expired_token", "expired_token"},
		{"bad_verification_code", "bad_verification_code"},
	} {
		f := &fakeLogin{t: t,
			device:  httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`","user_code":"AAA","verification_uri":"https://x","expires_in":900,"interval":1}`, nil),
			replies: []*http.Response{oauthError(tc.code)},
		}
		a := newApp(f)
		dc, err := a.StartSignIn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.CompleteSignIn(context.Background(), dc)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v", tc.code, err)
		}
		if strings.Contains(err.Error(), deviceSecret) {
			t.Fatalf("%s: the error carries the device code: %v", tc.code, err)
		}
		if strings.Contains(err.Error(), "Trace ID") {
			t.Fatalf("%s: the error was not trimmed to the useful line: %v", tc.code, err)
		}
	}
}

func TestDeviceCodeFlowStopsWhenTheCodeExpires(t *testing.T) {
	f := &fakeLogin{t: t,
		device: httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`","user_code":"AAA","verification_uri":"https://x","expires_in":1,"interval":1}`, nil),
		replies: []*http.Response{
			oauthError("authorization_pending"), oauthError("authorization_pending"),
		},
	}
	a := newApp(f)
	dc, err := a.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dc.ExpiresAt = time.Now().Add(-time.Second) // the administrator walked away
	if _, err := a.CompleteSignIn(context.Background(), dc); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeviceCodeFlowStopsOnCancellation(t *testing.T) {
	f := &fakeLogin{t: t,
		device:  httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`","user_code":"AAA","verification_uri":"https://x","expires_in":900,"interval":1}`, nil),
		replies: []*http.Response{oauthError("authorization_pending")},
	}
	a := newApp(f)
	dc, err := a.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.Sleep = func(time.Duration) { cancel() }
	if _, err := a.CompleteSignIn(ctx, dc); err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestSignInWithoutARefreshTokenIsRefused(t *testing.T) {
	f := &fakeLogin{t: t,
		device:  httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`","user_code":"AAA","verification_uri":"https://x","expires_in":900,"interval":1}`, nil),
		replies: []*http.Response{tokenReply(accessToken, "", 3600)},
	}
	a := newApp(f)
	dc, _ := a.StartSignIn(context.Background())
	_, err := a.CompleteSignIn(context.Background(), dc)
	if err == nil || !strings.Contains(err.Error(), "refresh token") {
		t.Fatalf("err = %v; without one the storage plane is unreachable from this sign-in", err)
	}
}

func TestStartSignInRequestsOfflineAccessAndTheManagementScope(t *testing.T) {
	f := &fakeLogin{t: t,
		device: httpResponse(http.StatusOK, `{"device_code":"d","user_code":"AAA","verification_uri":"https://x","expires_in":900,"interval":5}`, nil),
	}
	a := newApp(f)
	if _, err := a.StartSignIn(context.Background()); err != nil {
		t.Fatal(err)
	}
	scope := f.forms[0]["scope"]
	if !strings.Contains(scope, "offline_access") || !strings.Contains(scope, "management.azure.com") {
		t.Fatalf("device-code scope = %q", scope)
	}
	if f.forms[0]["client_id"] != "client-abc" {
		t.Fatalf("client_id = %q", f.forms[0]["client_id"])
	}
}

func TestDefaultClientAndTenantAreUsedWhenUnset(t *testing.T) {
	var a App
	if a.clientID() != AzureCLIClientID {
		t.Fatalf("default client ID = %q", a.clientID())
	}
	if a.tenant() != "organizations" {
		t.Fatalf("default tenant = %q", a.tenant())
	}
	if got := a.endpoint("token"); got != defaultLogin+"/organizations/oauth2/v2.0/token" {
		t.Fatalf("endpoint = %q", got)
	}
}

// --- unattended path -------------------------------------------------------

func TestServicePrincipalSignsInUnattendedAndCachesPerScope(t *testing.T) {
	f := &fakeLogin{t: t, replies: []*http.Response{
		tokenReply("MGMT-TOKEN", "", 3600),
		tokenReply("STORAGE-TOKEN", "", 3600),
	}}
	reads := 0
	p := &ServicePrincipal{
		App: App{TenantID: "contoso.example", ClientID: "app-123", Login: "https://login.test", Do: f.do},
		Secret: func() (string, error) {
			reads++
			return clientSecret, nil
		},
	}
	src := p.TokenSource()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		tok, err := src(ctx, ScopeManagement)
		if err != nil {
			t.Fatal(err)
		}
		if tok != "MGMT-TOKEN" {
			t.Fatalf("management token = %q", tok)
		}
	}
	tok, err := src(ctx, ScopeStorage)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "STORAGE-TOKEN" {
		t.Fatalf("storage token = %q", tok)
	}
	if len(f.forms) != 2 {
		t.Fatalf("%d sign-ins for two scopes and four calls; the cache is not working", len(f.forms))
	}
	if reads != 2 {
		t.Fatalf("the client secret was read %d times; it must be fetched at the point of use, once per sign-in", reads)
	}
	if f.forms[0]["grant_type"] != "client_credentials" {
		t.Fatalf("unattended grant = %q", f.forms[0]["grant_type"])
	}
}

func TestServicePrincipalNeedsItsOwnIdentityAndSecret(t *testing.T) {
	p := &ServicePrincipal{App: App{Login: "https://login.test"}}
	if _, err := p.TokenSource()(context.Background(), ScopeStorage); err == nil ||
		!strings.Contains(err.Error(), "tenant ID") {
		t.Fatalf("err = %v; the Azure CLI client ID must never be a silent default for unattended sign-in", err)
	}

	p = &ServicePrincipal{App: App{TenantID: "t", ClientID: "c", Login: "https://login.test"}}
	if _, err := p.TokenSource()(context.Background(), ScopeStorage); err == nil ||
		!strings.Contains(err.Error(), ClientSecretCredential) {
		t.Fatalf("err = %v", err)
	}
}

// TestNoSignInValueLeaksIntoAnErrorOrAStruct covers every credential this
// package handles: the device code, the access token, the refresh token, and
// the unattended client secret.
func TestNoSignInValueLeaksIntoAnErrorOrAStruct(t *testing.T) {
	secrets := []string{deviceSecret, accessToken, refreshToken, clientSecret}

	f := &fakeLogin{t: t,
		device:  httpResponse(http.StatusOK, `{"device_code":"`+deviceSecret+`","user_code":"AAA","verification_uri":"https://x","expires_in":900,"interval":1}`, nil),
		replies: []*http.Response{tokenReply(accessToken, refreshToken, 3600)},
	}
	a := newApp(f)
	dc, err := a.StartSignIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.CompleteSignIn(context.Background(), dc)
	if err != nil {
		t.Fatal(err)
	}

	// A Session holds live tokens and must expose none of them, however it is
	// formatted or serialised.
	rendered := fmt.Sprintf("%v %+v", s, s)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(rendered, secret) {
			t.Fatalf("formatting a Session exposes %q", secret)
		}
		if strings.Contains(string(b), secret) {
			t.Fatalf("serialising a Session exposes %q: %s", secret, b)
		}
	}

	// A failing refresh must not put the refresh token into the error.
	f.replies = []*http.Response{oauthError("invalid_grant")}
	_, err = s.TokenSource()(context.Background(), ScopeStorage)
	if err == nil {
		t.Fatal("a refused refresh returned no error")
	}
	for _, secret := range secrets {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refresh error exposes %q: %v", secret, err)
		}
	}

	// The same for the unattended path.
	f2 := &fakeLogin{t: t, replies: []*http.Response{oauthError("invalid_client")}}
	p := &ServicePrincipal{
		App:    App{TenantID: "t", ClientID: "c", Login: "https://login.test", Do: f2.do},
		Secret: func() (string, error) { return clientSecret, nil },
	}
	_, err = p.TokenSource()(context.Background(), ScopeStorage)
	if err == nil {
		t.Fatal("a refused client-credentials sign-in returned no error")
	}
	if strings.Contains(err.Error(), clientSecret) {
		t.Fatalf("the sign-in error exposes the client secret: %v", err)
	}
	if pb, _ := json.Marshal(p); strings.Contains(string(pb), clientSecret) {
		t.Fatalf("serialising a ServicePrincipal exposes the client secret: %s", pb)
	}
}

func TestStaticTokensFromEnvReadsOneVariablePerScope(t *testing.T) {
	t.Setenv(ManagementTokenEnv, "mgmt")
	t.Setenv(StorageTokenEnv, "")
	src := StaticTokensFromEnv()
	if tok, err := src(context.Background(), ScopeManagement); err != nil || tok != "mgmt" {
		t.Fatalf("tok = %q, err = %v", tok, err)
	}
	_, err := src(context.Background(), ScopeStorage)
	if err == nil || !strings.Contains(err.Error(), StorageTokenEnv) {
		t.Fatalf("err = %v; a missing storage token must name the variable to set", err)
	}
}

func TestExpiredCacheEntryIsRefetched(t *testing.T) {
	var c tokenCache
	calls := 0
	fetch := func(context.Context, string) (string, time.Duration, error) {
		calls++
		return fmt.Sprintf("token-%d", calls), time.Minute, nil // shorter than expiryMargin
	}
	for i := 0; i < 2; i++ {
		if _, err := c.get(context.Background(), ScopeStorage, fetch); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("%d fetches; a token inside the expiry margin must not be reused", calls)
	}
}
