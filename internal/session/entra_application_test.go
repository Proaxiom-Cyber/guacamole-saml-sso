package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entracert"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

func TestInstallerAppGuidedChecksRetriesAndPreservesOwnership(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	const clientID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"certificate", "secret"} {
		t.Run(method, func(t *testing.T) {
			t.Setenv(entra.DefaultTokenEnv, "")
			dir := t.TempDir()
			steps := "a\nc\nc\nc\nc\n"
			if method == "secret" {
				steps = "s\nc\nc\nc\n"
			}
			u, out := testUI(true, steps+tenant+"\n"+clientID+"\nr\n\n\n")
			secrets := 0
			u.Secret = func(string) (string, error) { secrets++; return "secret-fixture", nil }
			st := &state.State{DeploymentID: "deployment", Config: map[string]string{"entra-tenant-id": tenant}}
			calls, validations, journals := 0, 0, 0
			payload, _ := json.Marshal(map[string]any{"tid": tenant, "roles": append(append([]string{}, entra.RequiredPermissions...), "Organization.Read.All"), "exp": time.Now().Add(time.Hour).Unix()})
			token := "fixture." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
			o := &Options{StateDir: dir, UI: u, entraState: st, EntraTenant: tenant,
				journalIntent: func(string) error { journals++; return nil },
				EntraCertificate: func(_ context.Context, gotDir, dep string, _ entracert.Open) (entracert.Material, error) {
					if journals == 0 {
						t.Fatal("generated key before recording intent")
					}
					if gotDir != filepath.Join(dir, "credentials") || dep != st.DeploymentID {
						t.Fatal("wrong certificate binding")
					}
					return entracert.Material{Certificate: cert, Signer: key, PublicPath: filepath.Join(gotDir, entracert.PublicName)}, nil
				},
				EntraApplicationToken: func(auth entra.ApplicationOptions) (entra.TokenSource, error) {
					calls++
					if auth.TenantID != tenant || auth.ClientID != clientID {
						t.Fatal("wrong app IDs")
					}
					if method == "certificate" && (auth.Signer == nil || auth.Certificate == nil || auth.Secret != "") {
						t.Fatal("certificate fallback to secret")
					}
					if method == "secret" && (auth.Secret != "secret-fixture" || auth.Signer != nil) {
						t.Fatal("secret not supplied in memory")
					}
					attempt := calls
					return func(context.Context) (string, error) {
						if attempt == 1 {
							return "", errors.New("installer app authentication failed; check certificate upload or client secret")
						}
						return token, nil
					}, nil
				},
				Entra: &entra.Client{Do: func(r *http.Request) (*http.Response, error) {
					validations++
					if r.Method != "GET" {
						t.Fatal("validation mutated Graph")
					}
					if r.Header.Get("Authorization") != "Bearer "+token {
						t.Fatal("wrong token")
					}
					body := `{"value":[]}`
					if strings.HasSuffix(r.URL.Path, "/organization") {
						body = `{"value":[{"id":"` + tenant + `","verifiedDomains":[]}]}`
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				}},
			}
			c, err := o.entraClient()
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				got, err := c.Token(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if got != token {
					t.Fatal("missing authenticated token")
				}
			}
			if calls != 2 || validations != 2 {
				t.Fatal("retry or memory reuse failed")
			}
			if method == "certificate" && secrets != 0 {
				t.Fatal("certificate asked for secret")
			}
			if method == "secret" && secrets != 2 {
				t.Fatal("secret retry did not ask again")
			}
			if st.Config["entra-auth-method"] != method || st.Config["entra-installer-client-id"] != clientID {
				t.Fatal("nonsecret references not recorded")
			}
			for _, r := range st.Resources {
				if r.Provider == "entra" {
					t.Fatal("manually created app treated as owned")
				}
			}
			b, _ := json.Marshal(st)
			for _, secret := range []string{token, "secret-fixture"} {
				if strings.Contains(string(b)+out.String(), secret) {
					t.Fatal("credential leaked")
				}
			}
			if !strings.Contains(out.String(), "Application permissions (not Delegated)") {
				t.Fatal("ambiguous permission instructions")
			}
		})
	}
}

func TestInstallerCertificateUnavailableOffersSecret(t *testing.T) {
	u, _ := testUI(true, "c\nc\ns\nq\n")
	st := &state.State{DeploymentID: "dep", Config: map[string]string{}}
	o := &Options{UI: u, StateDir: t.TempDir(), entraState: st, journalIntent: func(string) error { return nil }, EntraCertificate: func(context.Context, string, string, entracert.Open) (entracert.Material, error) {
		return entracert.Material{}, errors.New("no TPM")
	}}
	_, err := o.manualEntraToken("certificate")(context.Background())
	if err == nil || !strings.Contains(err.Error(), "progress is retained") {
		t.Fatal("secret fallback not offered")
	}
}

func TestInstallerCertificateNotCreatedDuringTeardown(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(false, "")
	st := &state.State{DeploymentID: "dep", Config: map[string]string{"entra-auth-method": "certificate"}}
	_, err := EntraClientForOperation(st, dir, u).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no installer certificate exists") {
		t.Fatal("missing certificate was not explained")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("teardown generated a credential")
	}
}
