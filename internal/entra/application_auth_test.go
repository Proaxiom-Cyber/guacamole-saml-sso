package entra

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestApplicationSDKCertificateAndSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"certificate", "secret"} {
		t.Run(mode, func(t *testing.T) {
			const tenant = "11111111-2222-3333-4444-555555555555"
			const client = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
			base := "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/"
			calls := 0
			o := ApplicationOptions{TenantID: tenant, ClientID: client}
			if mode == "certificate" {
				o.Certificate, o.Signer = cert, key
			} else {
				o.Secret = "fixture-client-secret"
			}
			o.Transport = deviceTransport(func(r *http.Request) (*http.Response, error) {
				var body any
				switch {
				case strings.HasSuffix(r.URL.Path, "/discovery/instance"):
					body = map[string]any{"tenant_discovery_endpoint": "https://login.microsoftonline.com/" + tenant + "/v2.0/.well-known/openid-configuration", "metadata": []any{map[string]any{"preferred_network": "login.microsoftonline.com", "preferred_cache": "login.microsoftonline.com", "aliases": []string{"login.microsoftonline.com"}}}}
				case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
					body = map[string]any{"authorization_endpoint": base + "authorize", "token_endpoint": base + "token", "issuer": "https://login.microsoftonline.com/" + tenant + "/v2.0"}
				case strings.HasSuffix(r.URL.Path, "/token"):
					calls++
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != client || !strings.Contains(r.Form.Get("scope"), "https://graph.microsoft.com/.default") {
						t.Fatalf("incorrect app token request: grant=%q client=%q scope=%q", r.Form.Get("grant_type"), r.Form.Get("client_id"), r.Form.Get("scope"))
					}
					if mode == "secret" {
						if r.Form.Get("client_secret") != o.Secret || r.Form.Get("client_assertion") != "" {
							t.Fatal("wrong client secret request")
						}
					} else {
						if r.Form.Get("client_secret") != "" || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
							t.Fatal("wrong certificate request")
						}
						parts := strings.Split(r.Form.Get("client_assertion"), ".")
						if len(parts) != 3 {
							t.Fatal("malformed assertion")
						}
						var header map[string]string
						var claims map[string]any
						h, _ := base64.RawURLEncoding.DecodeString(parts[0])
						p, _ := base64.RawURLEncoding.DecodeString(parts[1])
						sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
						if json.Unmarshal(h, &header) != nil || json.Unmarshal(p, &claims) != nil {
							t.Fatal("invalid assertion JSON")
						}
						thumb := sha256.Sum256(cert.Raw)
						if header["alg"] != "PS256" || header["x5t#S256"] != base64.RawURLEncoding.EncodeToString(thumb[:]) || claims["aud"] != base+"token" || claims["iss"] != client || claims["sub"] != client || claims["jti"] == "" {
							t.Fatal("incorrect assertion identity")
						}
						if claims["exp"].(float64)-claims["nbf"].(float64) > 360 {
							t.Fatal("assertion lifetime too long")
						}
						digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
						if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
							t.Fatal(err)
						}
					}
					body = map[string]any{"access_token": "app-token-fixture", "token_type": "Bearer", "expires_in": 3600}
				default:
					t.Fatalf("unexpected auth endpoint: %s", r.URL.Path)
				}
				b, _ := json.Marshal(body)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b))), Request: r}, nil
			})
			source, err := ApplicationTokenSource(o)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				token, err := source(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if token != "app-token-fixture" {
					t.Fatal("missing token")
				}
			}
			if calls != 1 {
				t.Fatal("SDK did not reuse its memory cache")
			}
		})
	}
}

func TestApplicationErrorsRedactCredentials(t *testing.T) {
	for _, s := range []string{"client_secret=fixture-secret", "AADSTS700027 client_assertion=fixture-secret"} {
		if strings.Contains(safeApplicationError(errors.New(s)).Error(), "fixture-secret") {
			t.Fatal("credential leaked")
		}
	}
	if !errors.Is(safeApplicationError(context.Canceled), context.Canceled) {
		t.Fatal("cancel lost")
	}
}
