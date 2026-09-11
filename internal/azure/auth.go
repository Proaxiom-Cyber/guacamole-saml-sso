package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource supplies a bearer token for one scope. The two Azure planes are
// different resources, so the scope is a parameter: a management token is
// rejected by Blob storage and the other way round.
//
// A TokenSource is called for every request. Implementations here cache until
// shortly before expiry, so a long run does not re-authenticate per blob. No
// implementation writes a token anywhere.
type TokenSource func(ctx context.Context, scope string) (string, error)

// Environment variables StaticTokensFromEnv reads. They exist for live
// verification against a real subscription without first registering a
// service principal: `az account get-access-token` can fill both. They are
// not an unattended mechanism — the tokens expire in about an hour.
const (
	ManagementTokenEnv = "GUACDEPLOY_AZURE_MANAGEMENT_TOKEN"
	StorageTokenEnv    = "GUACDEPLOY_AZURE_STORAGE_TOKEN"
)

// StaticTokensFromEnv reads one environment variable per scope on every call.
func StaticTokensFromEnv() TokenSource {
	return func(_ context.Context, scope string) (string, error) {
		name := ManagementTokenEnv
		if scope == ScopeStorage {
			name = StorageTokenEnv
		}
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty: supply an access token for %s", name, scope)
		}
		return v, nil
	}
}

// defaultLogin is the Microsoft identity platform endpoint.
const defaultLogin = "https://login.microsoftonline.com"

// AzureCLIClientID is the Microsoft-published public client the Azure CLI
// uses. It is the default ClientID for guided sign-in because it already has
// the device-code flow enabled and is pre-consented in every tenant for both
// Azure Resource Manager and Azure Storage, so a first guided sign-in needs
// no application registration and no administrator consent.
//
// It is a default, not a requirement. An organisation that wants its own
// audit trail, its own Conditional Access policy, or its own consent record
// should register a public client with the device-code flow enabled and set
// ClientID to it. The status report shows which client ID was used.
const AzureCLIClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

// App is the Entra application used to sign in. It is shared by both paths:
// guided device-code sign-in and the unattended service principal.
type App struct {
	// TenantID is the directory to sign in to. "organizations" (the default)
	// accepts any work or school account, which is the only kind that can
	// hold an Azure subscription.
	TenantID string
	// ClientID defaults to AzureCLIClientID for the guided path. The
	// unattended path must set the registered application's own ID.
	ClientID string

	// Login overrides the identity endpoint, for sovereign clouds and tests.
	Login string
	// Do sends one HTTP request. nil means http.DefaultClient.Do.
	Do func(*http.Request) (*http.Response, error)
	// Sleep waits between device-code polls. nil means time.Sleep; tests
	// replace it so the polling loop costs nothing.
	Sleep func(time.Duration)
}

func (a App) tenant() string {
	if a.TenantID == "" {
		return "organizations"
	}
	return a.TenantID
}

func (a App) clientID() string {
	if a.ClientID == "" {
		return AzureCLIClientID
	}
	return a.ClientID
}

func (a App) endpoint(path string) string {
	base := a.Login
	if base == "" {
		base = defaultLogin
	}
	return strings.TrimSuffix(base, "/") + "/" + a.tenant() + "/oauth2/v2.0/" + path
}

func (a App) sleep(d time.Duration) {
	if a.Sleep != nil {
		a.Sleep(d)
		return
	}
	time.Sleep(d)
}

// tokenResponse is the identity platform's reply. It is never returned to a
// caller, never logged, and never serialised: the values leave this file only
// through a TokenSource, which hands one access token to one request.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

// post sends one form-encoded request to the identity platform and decodes
// the reply. Errors carry the OAuth error code and the endpoint, never the
// form values: the form can hold a device code, a refresh token, or a client
// secret, so it is never included in an error.
func (a App) post(ctx context.Context, path string, form url.Values) (tokenResponse, error) {
	var tr tokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(path), strings.NewReader(form.Encode()))
	if err != nil {
		return tr, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	do := a.Do
	if do == nil {
		do = http.DefaultClient.Do
	}
	resp, err := do(req)
	if err != nil {
		return tr, fmt.Errorf("sign-in request to the %s endpoint failed: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tr, fmt.Errorf("sign-in response from the %s endpoint could not be read: %v", path, err)
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return tr, fmt.Errorf("sign-in response from the %s endpoint is not readable JSON (status %d)", path, resp.StatusCode)
	}
	if tr.Error != "" {
		return tr, fmt.Errorf("sign-in failed at the %s endpoint: %s (%s)", path, firstLine(tr.Description), tr.Error)
	}
	if resp.StatusCode >= 400 {
		return tr, fmt.Errorf("sign-in request to the %s endpoint returned status %d", path, resp.StatusCode)
	}
	if tr.AccessToken == "" {
		return tr, fmt.Errorf("the %s endpoint returned no access token", path)
	}
	return tr, nil
}

// firstLine trims the identity platform's multi-line descriptions, which
// carry a correlation ID and a timestamp after the sentence that matters.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// DeviceCode is a started guided sign-in. Show UserCode and VerificationURL
// to the administrator, then call CompleteSignIn.
//
// The device code itself is unexported: it is a credential for the duration
// of the flow, so it cannot be printed by a caller formatting this struct and
// cannot be serialised by encoding/json.
type DeviceCode struct {
	UserCode        string
	VerificationURL string
	Message         string // the identity platform's own instruction text
	ExpiresAt       time.Time

	deviceCode string
	interval   time.Duration
}

// String renders a DeviceCode without its device code.
//
// This is not decoration. fmt prints unexported struct fields, so any
// "%+v" of a struct holding a credential would put it in a log line. A
// String method is what stops that, for every verb fmt routes through it.
func (d DeviceCode) String() string {
	return fmt.Sprintf("device sign-in: enter code %s at %s (expires %s)",
		d.UserCode, d.VerificationURL, d.ExpiresAt.UTC().Format(time.RFC3339))
}

// StartSignIn begins the device-code flow for one scope.
//
// offline_access is requested alongside it so the reply carries a refresh
// token: one sign-in then covers both planes, because CompleteSignIn redeems
// that refresh token for a storage token as well. Asking the administrator to
// read a code off the screen twice for one setup is not acceptable, and the
// identity platform does not issue one access token for two resources.
func (a App) StartSignIn(ctx context.Context) (*DeviceCode, error) {
	form := url.Values{
		"client_id": {a.clientID()},
		"scope":     {"offline_access " + ScopeManagement},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint("devicecode"), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	do := a.Do
	if do == nil {
		do = http.DefaultClient.Do
	}
	resp, err := do(req)
	if err != nil {
		return nil, fmt.Errorf("starting Azure sign-in failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("starting Azure sign-in failed: %v", err)
	}
	var dc struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Message         string `json:"message"`
		Error           string `json:"error"`
		Description     string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, fmt.Errorf("the device-code response is not readable JSON (status %d)", resp.StatusCode)
	}
	if dc.Error != "" {
		return nil, fmt.Errorf("starting Azure sign-in failed: %s (%s)", firstLine(dc.Description), dc.Error)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return nil, fmt.Errorf("the device-code response is incomplete (status %d)", resp.StatusCode)
	}
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expires := time.Duration(dc.ExpiresIn) * time.Second
	if expires <= 0 {
		expires = 15 * time.Minute
	}
	return &DeviceCode{
		UserCode:        dc.UserCode,
		VerificationURL: dc.VerificationURI,
		Message:         dc.Message,
		ExpiresAt:       time.Now().Add(expires),
		deviceCode:      dc.DeviceCode,
		interval:        interval,
	}, nil
}

// Session is a completed guided sign-in. The tokens are unexported, so
// encoding/json writes an empty object and no caller can format one into a
// log line. A Session is in-memory only and is never persisted.
type Session struct {
	app     App
	refresh string
	cache   tokenCache
}

// String renders a Session without its tokens, for the same reason
// DeviceCode.String exists: fmt prints unexported fields.
func (s *Session) String() string {
	return fmt.Sprintf("azure sign-in as application %s in tenant %s", s.app.clientID(), s.app.tenant())
}

// CompleteSignIn polls until the administrator finishes signing in.
//
// The identity platform answers the poll with an OAuth error until then:
// authorization_pending means keep waiting, slow_down means keep waiting and
// add five seconds to the interval. Anything else ends the flow, including
// expired_token and authorization_declined, which are reported as themselves
// rather than as a timeout.
func (a App) CompleteSignIn(ctx context.Context, dc *DeviceCode) (*Session, error) {
	if dc == nil || dc.deviceCode == "" {
		return nil, fmt.Errorf("no sign-in was started")
	}
	interval := dc.interval
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		form := url.Values{
			"client_id":   {a.clientID()},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dc.deviceCode},
		}
		tr, err := a.post(ctx, "token", form)
		switch {
		case err == nil:
			s := &Session{app: a, refresh: tr.RefreshToken}
			s.cache.put(ScopeManagement, tr.AccessToken, time.Duration(tr.ExpiresIn)*time.Second)
			if s.refresh == "" {
				return nil, fmt.Errorf("Azure sign-in returned no refresh token, so the storage plane cannot be reached from the same sign-in; register a public client with offline_access and set its client ID")
			}
			return s, nil
		case tr.Error == "authorization_pending":
		case tr.Error == "slow_down":
			interval += 5 * time.Second
		default:
			return nil, err
		}
		if time.Now().After(dc.ExpiresAt) {
			return nil, fmt.Errorf("Azure sign-in was not completed before the code expired; start setup again")
		}
		a.sleep(interval)
	}
}

// TokenSource returns the token seam for this signed-in administrator. It
// redeems the refresh token for whichever scope is asked for, so the same
// sign-in serves both the management plane and Blob storage.
//
// This is the guided path only. It is tied to the administrator's own
// session: see ServicePrincipal for why scheduled uploads must not use it.
func (s *Session) TokenSource() TokenSource {
	return func(ctx context.Context, scope string) (string, error) {
		return s.cache.get(ctx, scope, func(ctx context.Context, scope string) (string, time.Duration, error) {
			tr, err := s.app.post(ctx, "token", url.Values{
				"client_id":     {s.app.clientID()},
				"grant_type":    {"refresh_token"},
				"refresh_token": {s.refresh},
				"scope":         {scope},
			})
			if err != nil {
				return "", 0, err
			}
			if tr.RefreshToken != "" {
				s.refresh = tr.RefreshToken // the platform rotates it
			}
			return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
		})
	}
}

// ClientSecretCredential is the credential name the unattended service
// principal's secret is stored under, through the deployment's selected
// credential protection (internal/creds). The value never enters this
// package's state, the status file, or any error.
const ClientSecretCredential = "azure-client-secret"

// ServicePrincipal is the unattended path: a registered application signing
// in with its own client secret.
//
// Why this mechanism. A scheduled upload runs from a systemd timer with no
// administrator present, and the specification requires authentication
// "independent of the administrator's interactive session". Three candidates
// were considered:
//
//   - Managed identity. Not available. This host runs on Proxmox, not in
//     Azure, so there is no instance metadata endpoint to get a token from.
//     Claiming otherwise would produce a deployment whose backups stop the
//     first night.
//   - The administrator's refresh token, kept on the host. Rejected. It is
//     the administrator's own session by definition: it dies when the account
//     changes password, is disabled, hits a Conditional Access policy, or
//     simply goes 90 days without use, and every upload then runs as a person
//     rather than as the deployment. That is the dependency the specification
//     names.
//   - A service principal with a client secret, stored through the
//     deployment's selected credential protection. Chosen.
//
// What it costs, honestly. The secret is a bearer credential on the host: it
// is only as protected as the selected credential mode, and owner-only
// plaintext is one of the approved modes. It expires on the schedule the
// application registration sets (Entra's default is 6 to 24 months) and
// nothing here renews it, so an unrotated secret eventually stops the
// scheduled upload — which is why the status report shows the last result and
// the operator guide must say to rotate it. A certificate credential would be
// better (no shared secret, and it could be bound to the TPM) and is the
// upgrade path; it needs certificate plumbing this slice does not have.
//
// The principal needs one role on the container: Storage Blob Data
// Contributor. It needs no management-plane role at all for uploads, so the
// unattended identity stays narrower than the administrator's.
type ServicePrincipal struct {
	App

	// Secret returns the client secret for one sign-in. It is a function so
	// the value is fetched at the point of use from the deployment's
	// credential store and is never held in a field, a log line, or state.
	Secret func() (string, error)

	cache tokenCache
}

// TokenSource returns the unattended token seam.
func (p *ServicePrincipal) TokenSource() TokenSource {
	return func(ctx context.Context, scope string) (string, error) {
		return p.cache.get(ctx, scope, func(ctx context.Context, scope string) (string, time.Duration, error) {
			if p.ClientID == "" || p.TenantID == "" {
				return "", 0, fmt.Errorf("unattended Azure sign-in needs the tenant ID and the application (client) ID")
			}
			if p.Secret == nil {
				return "", 0, fmt.Errorf("unattended Azure sign-in needs the %s credential; it is not available in this credential mode", ClientSecretCredential)
			}
			secret, err := p.Secret()
			if err != nil {
				return "", 0, fmt.Errorf("the %s credential could not be read: %w", ClientSecretCredential, err)
			}
			tr, err := p.post(ctx, "token", url.Values{
				"client_id":     {p.ClientID},
				"client_secret": {secret},
				"grant_type":    {"client_credentials"},
				"scope":         {scope},
			})
			if err != nil {
				return "", 0, err
			}
			return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
		})
	}
}

// tokenCache holds one token per scope until shortly before it expires.
type tokenCache struct {
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	value   string
	expires time.Time
}

// expiryMargin is how long before real expiry a cached token is discarded, so
// a token cannot lapse between the check and the request reaching Azure.
const expiryMargin = 2 * time.Minute

func (c *tokenCache) put(scope, value string, lifetime time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens == nil {
		c.tokens = map[string]cachedToken{}
	}
	c.tokens[scope] = cachedToken{value: value, expires: time.Now().Add(lifetime)}
}

func (c *tokenCache) get(ctx context.Context, scope string, fetch func(context.Context, string) (string, time.Duration, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[scope]; ok && time.Now().Before(t.expires.Add(-expiryMargin)) {
		return t.value, nil
	}
	value, lifetime, err := fetch(ctx, scope)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("no access token was issued for %s", scope)
	}
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	if c.tokens == nil {
		c.tokens = map[string]cachedToken{}
	}
	c.tokens[scope] = cachedToken{value: value, expires: time.Now().Add(lifetime)}
	return value, nil
}
