package cloudflare

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// OAuthRelayURL is public release configuration, not a customer deployment URL.
var OAuthRelayURL = "https://guacdeploy-cloudflare-auth.8bitnetworks.workers.dev"

func (c OAuthConfig) ValidateHosted() error {
	if err := c.Validate(); err != nil {
		return err
	}
	u, err := url.Parse(c.RelayURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("Cloudflare sign-in needs a valid HTTPS callback service origin")
	}
	return nil
}

// AuthorizeHosted polls the relay using a credential that never enters a URL.
// Only the installer can decrypt the code or exchange it using the PKCE verifier.
func (c OAuthConfig) AuthorizeHosted(ctx context.Context, show func(string) error) (string, error) {
	if err := c.ValidateHosted(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	h := oauthHTTP(c.HTTP)
	origin := strings.TrimRight(c.RelayURL, "/")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", errors.New("cannot create Cloudflare sign-in key")
	}
	random := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	verifier, poll := random(), random()
	challenge := sha256.Sum256([]byte(verifier))
	hash := sha256.Sum256([]byte(poll))
	body, _ := json.Marshal(map[string]any{"challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "poll_hash": hex.EncodeToString(hash[:]), "public_key": map[string]string{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}})
	var session struct {
		ID       string `json:"id"`
		ClientID string `json:"client_id"`
	}
	status, err := oauthRequest(ctx, h, "POST", origin+"/sessions", "", "application/json", body, &session)
	if err != nil {
		return "", err
	}
	if status != 201 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(session.ID) || session.ClientID != c.ClientID {
		return "", errors.New("Cloudflare callback service is unavailable or configured for a different client; use manual return")
	}
	pollURL := origin + "/poll/" + session.ID
	defer func() {
		clean, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = oauthRequest(clean, h, "DELETE", pollURL, poll, "", nil, nil)
	}()
	if show == nil {
		return "", errors.New("Cloudflare sign-in needs a link display")
	}
	if err = show(origin + "/start/" + session.ID); err != nil {
		return "", errors.New("Cloudflare sign-in stopped")
	}
	interval := c.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
		var envelope oauthEnvelope
		status, err = oauthRequest(ctx, h, "GET", pollURL, poll, "", nil, &envelope)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			continue
		}
		if status == 202 || status == http.StatusTooManyRequests || status >= 500 {
			continue
		}
		if status != 200 {
			return "", errors.New("Cloudflare approval expired or was cancelled; try again or use manual return")
		}
		code, err := envelope.code(key)
		if err != nil {
			return "", err
		}
		credential, err := exchange(ctx, h, url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "redirect_uri": {origin + "/callback"}, "code": {code}, "code_verifier": {verifier}})
		if err != nil {
			return "", err
		}
		return credential.encode(), nil
	}
}

type oauthEnvelope struct {
	Key  string `json:"key"`
	IV   string `json:"iv"`
	Data string `json:"data"`
}

func (e oauthEnvelope) code(key *rsa.PrivateKey) (string, error) {
	invalid := errors.New("Cloudflare returned an invalid encrypted approval")
	wrapped, a := base64.StdEncoding.DecodeString(e.Key)
	iv, b := base64.StdEncoding.DecodeString(e.IV)
	data, c := base64.StdEncoding.DecodeString(e.Data)
	if a != nil || b != nil || c != nil {
		return "", invalid
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return "", invalid
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", invalid
	}
	gcm, _ := cipher.NewGCM(block)
	if len(iv) != gcm.NonceSize() {
		return "", invalid
	}
	plain, err := gcm.Open(nil, iv, data, nil)
	if err != nil {
		return "", invalid
	}
	var answer struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(plain, &answer) != nil {
		return "", invalid
	}
	if answer.Code == "" {
		return "", errors.New("Cloudflare access was not approved")
	}
	return answer.Code, nil
}
