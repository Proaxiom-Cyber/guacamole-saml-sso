package cloudflare

// OAuth accepts the returned localhost URL through hidden input. No listener is needed.
import (
	"bytes"
	"context"

	"crypto/rand"

	"crypto/sha256"
	"encoding/base64"

	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
)

// Release builds may supply these public settings with -ldflags. No secrets.
var OAuthClientID = "ee7531ced85aebf5179fe7b428cc5b87"

const oauthPrefix = "guacdeploy-cloudflare-oauth-v1:"
const tokenURL = "https://dash.cloudflare.com/oauth2/token"

// OAuthConfig contains only public configuration. HTTP is an optional test transport.
type OAuthConfig struct {
	ClientID     string
	RelayURL     string
	PollInterval time.Duration // tests; default five seconds
	HTTP         *http.Client
}

func (c OAuthConfig) Validate() error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(c.ClientID) {
		return errors.New("Cloudflare sign-in needs a registered client ID")
	}
	return nil
}

func oauthHTTP(c *http.Client) *http.Client {
	h := http.Client{Timeout: 25 * time.Second}
	if c != nil {
		h = *c
		if h.Timeout == 0 {
			h.Timeout = 25 * time.Second
		}
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &h
}

// Never return raw transport/provider errors: these can contain codes or credentials.
func oauthRequest(ctx context.Context, h *http.Client, method, target, bearer, content string, body []byte, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("Cloudflare sign-in request could not be created")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if content != "" {
		req.Header.Set("Content-Type", content)
	}
	res, err := h.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, errors.New("Cloudflare sign-in connection failed; try again")
	}
	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 && res.StatusCode != 202 && out != nil {
		if json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(out) != nil {
			return res.StatusCode, errors.New("Cloudflare sign-in returned an invalid response")
		}
	}
	return res.StatusCode, nil
}

type oauthCredential struct {
	ClientID string    `json:"client_id"`
	Access   string    `json:"access_token"`
	Refresh  string    `json:"refresh_token"`
	Expires  time.Time `json:"expires"`
}

func (c oauthCredential) encode() string  { b, _ := json.Marshal(c); return oauthPrefix + string(b) }
func IsOAuthCredential(value string) bool { return strings.HasPrefix(value, oauthPrefix) }

type tokenResponse struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Type    string `json:"token_type"`
	Expires int64  `json:"expires_in"`
}

func exchange(ctx context.Context, h *http.Client, form url.Values) (oauthCredential, error) {
	var r tokenResponse
	status, err := oauthRequest(ctx, h, "POST", tokenURL, "", "application/x-www-form-urlencoded", []byte(form.Encode()), &r)
	if err != nil {
		return oauthCredential{}, err
	}
	if status != 200 {
		return oauthCredential{}, errors.New("Cloudflare sign-in or refresh failed; run setup and connect Cloudflare again")
	}
	if r.Access == "" || r.Refresh == "" || !strings.EqualFold(r.Type, "bearer") || r.Expires < 1 || r.Expires > 86400 {
		return oauthCredential{}, errors.New("Cloudflare returned incomplete sign-in credentials")
	}
	return oauthCredential{ClientID: form.Get("client_id"), Access: r.Access, Refresh: r.Refresh, Expires: time.Now().Add(time.Duration(r.Expires) * time.Second)}, nil
}

// OAuthRedirectURI is registered once for the client. It is not a hosted service.
const OAuthRedirectURI = "http://localhost:18977/callback"

// Authorize displays the public login URL and reads the returned address through
// readReturn. The caller must use hidden input and must not log either address.
func (c OAuthConfig) Authorize(ctx context.Context, readReturn func(string) (string, error)) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if readReturn == nil {
		return "", errors.New("Cloudflare sign-in needs a hidden input prompt")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	random := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	verifier, state := random(), random()
	challenge := sha256.Sum256([]byte(verifier))
	auth := url.Values{"client_id": {c.ClientID}, "redirect_uri": {OAuthRedirectURI}, "response_type": {"code"}, "response_mode": {"query"}, "scope": {"argotunnel.write access.write access-acct.write dns.write zone.read offline_access"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	returned, err := readReturn("https://dash.cloudflare.com/oauth2/auth?" + auth.Encode())
	if err != nil {
		return "", errors.New("Cloudflare sign-in stopped; deployment progress is retained")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	code, err := returnedCode(returned, state)
	if err != nil {
		return "", err
	}
	credential, err := exchange(ctx, oauthHTTP(c.HTTP), url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "redirect_uri": {OAuthRedirectURI}, "code": {code}, "code_verifier": {verifier}})
	if err != nil {
		return "", err
	}
	return credential.encode(), nil
}

func returnedCode(raw, state string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.Host != "localhost:18977" || u.Path != "/callback" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("paste the complete localhost address returned after Cloudflare approval")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["state"]) != 1 || q.Get("state") != state {
		return "", errors.New("the returned address does not match this Cloudflare sign-in; start sign-in again")
	}
	if q.Get("error") != "" {
		return "", errors.New("Cloudflare access was not approved")
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return "", errors.New("the returned address has no Cloudflare authorization code")
	}
	return q.Get("code"), nil
}

// CredentialTokenSource accepts existing API tokens and encrypted OAuth bundles.
// Callers must hold the deployment lock while refreshing a saved credential.
func CredentialTokenSource(m *creds.Manager, spec creds.Spec, h *http.Client) TokenSource {
	var mu sync.Mutex
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		value, err := m.Get(spec)
		if err != nil {
			return "", err
		}
		if !IsOAuthCredential(value) {
			return value, nil
		}
		if m.Mode == creds.ModeFile {
			return "", errors.New("Cloudflare browser sign-in requires sealed credentials; plaintext storage is not supported")
		}
		var c oauthCredential
		if json.Unmarshal([]byte(strings.TrimPrefix(value, oauthPrefix)), &c) != nil || c.Access == "" || c.Refresh == "" || c.ClientID == "" {
			return "", errors.New("saved Cloudflare sign-in is invalid; connect Cloudflare again in setup")
		}
		if m.Protect != nil {
			m.Protect(c.Access)
			m.Protect(c.Refresh)
		}
		if time.Now().Add(time.Minute).Before(c.Expires) {
			return c.Access, nil
		}
		next, err := exchange(ctx, oauthHTTP(h), url.Values{"grant_type": {"refresh_token"}, "client_id": {c.ClientID}, "refresh_token": {c.Refresh}})
		if err != nil {
			return "", err
		}
		if m.Protect != nil {
			m.Protect(next.Access)
			m.Protect(next.Refresh)
		}
		encoded := next.encode()
		if creds.Persistent(m.Mode) {
			if _, err = m.Store(ctx, spec, encoded); err != nil {
				return "", errors.New("cannot save refreshed Cloudflare sign-in; reconnect Cloudflare in setup")
			}
		}
		m.Remember(spec, encoded)
		return next.Access, nil
	}
}
