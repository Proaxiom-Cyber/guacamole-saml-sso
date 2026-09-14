package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entracert"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

func TestRecommendedEntraPathCombinesSignInAndHostCertificate(t *testing.T) {
	t.Setenv(entra.DefaultTokenEnv, "")
	const tenant = "11111111-2222-3333-4444-555555555555"
	const clientID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	permissions := append(append([]string{}, entra.RequiredPermissions...), "Organization.Read.All")
	makeToken := func(application bool) string {
		claims := map[string]any{"tid": tenant, "exp": time.Now().Add(time.Hour).Unix()}
		if application {
			claims["roles"] = permissions
		} else {
			claims["scp"] = strings.Join(permissions, " ")
		}
		payload, _ := json.Marshal(claims)
		return "fixture." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	}
	adminToken, appToken := makeToken(false), makeToken(true)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Raw: []byte("public-certificate-fixture"), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	u, out := testUI(true, "d\nc\n")
	u.Secret = func(string) (string, error) { t.Fatal("combined path requested a secret"); return "", nil }
	st := &state.State{DeploymentID: "deployment", Config: map[string]string{}}
	generated, journals, mutations, factories := false, 0, 0, 0
	o := &Options{StateDir: t.TempDir(), UI: u, entraState: st, EntraTenant: tenant,
		journalIntent: func(string) error { journals++; return nil },
		EntraCertificate: func(context.Context, string, string, entracert.Open) (entracert.Material, error) {
			if journals == 0 {
				t.Fatal("key generated before intent was saved")
			}
			generated = true
			return entracert.Material{Certificate: cert, Signer: key}, nil
		},
		EntraDeviceToken: func(entra.DeviceCodeOptions) (entra.TokenSource, error) {
			return func(context.Context) (string, error) {
				if !generated {
					t.Fatal("administrator authorization preceded host key generation")
				}
				return adminToken, nil
			}, nil
		},
		EntraApplicationToken: func(a entra.ApplicationOptions) (entra.TokenSource, error) {
			factories++
			if mutations != 6 || a.TenantID != tenant || a.ClientID != clientID || a.Signer != key || a.Certificate != cert || a.Secret != "" {
				t.Fatal("installer identity did not receive the registered host certificate")
			}
			return func(context.Context) (string, error) { return appToken, nil }, nil
		},
	}
	o.Entra = &entra.Client{Do: func(r *http.Request) (*http.Response, error) {
		path := strings.TrimPrefix(r.URL.Path, "/v1.0")
		body := any(map[string]any{"value": []any{}})
		if r.Method == "GET" {
			switch path {
			case "/organization":
				body = map[string]any{"value": []any{map[string]any{"id": tenant}}}
			case "/servicePrincipals":
				roles := []any{}
				for _, p := range permissions {
					roles = append(roles, map[string]any{"id": p, "value": p, "isEnabled": true, "allowedMemberTypes": []string{"Application"}})
				}
				body = map[string]any{"value": []any{map[string]any{"id": "graph-sp", "appRoles": roles}}}
			case "/applications", "/servicePrincipals/installer-sp/appRoleAssignments":
			default:
				t.Fatalf("unexpected read %s", path)
			}
		} else {
			if r.Method != "POST" || st.Config["entra-installer-pending"] == "" || r.Header.Get("Authorization") != "Bearer "+adminToken {
				t.Fatal("mutation lacked journaled administrator authorization")
			}
			mutations++
			switch path {
			case "/applications":
				var request entra.InstallerApplication
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				if request.Notes != entra.InstallerMarker(st.DeploymentID) || len(request.KeyCredentials) != 1 || request.KeyCredentials[0].Key != base64.StdEncoding.EncodeToString(cert.Raw) {
					t.Fatal("ownership or certificate missing from registration")
				}
				body = map[string]string{"id": "app-object", "appId": clientID}
			case "/servicePrincipals":
				body = map[string]string{"id": "installer-sp"}
			case "/servicePrincipals/graph-sp/appRoleAssignedTo":
				body = map[string]string{"id": "grant"}
			default:
				t.Fatalf("unexpected mutation %s", path)
			}
		}
		encoded, _ := json.Marshal(body)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
	}}
	c, err := o.guidedEntraClient()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := c.Token(context.Background())
		if err != nil || got != appToken {
			t.Fatalf("combined flow did not return the installer identity: %v", err)
		}
	}
	if mutations != 6 || factories != 1 || st.Config["entra-auth-method"] != "certificate" || st.Config["entra-installer-pending"] != "" {
		t.Fatal("registration repeated or resume state was lost")
	}
	if strings.Count(out.String(), "Installer identity steps completed: 4/4") != 1 {
		t.Fatal("completion progress was absent or repeated for cached authentication")
	}
	owned := 0
	for _, r := range st.Resources {
		if r.Provider == "entra" && r.Ownership != "" {
			owned++
		}
	}
	if owned != 2 {
		t.Fatal("installer app and service principal were not recorded for teardown")
	}
	record, _ := json.Marshal(st)
	for _, token := range []string{adminToken, appToken} {
		if strings.Contains(string(record)+out.String(), token) {
			t.Fatal("token reached state or output")
		}
	}
}

func TestAutomaticEntraPreservesDevicePolicyError(t *testing.T) {
	u, out := testUI(true, "c\n")
	want := errors.New("device-code flow is blocked by tenant policy")
	o := &Options{StateDir: t.TempDir(), UI: u, entraState: &state.State{DeploymentID: "deployment", Config: map[string]string{}}, journalIntent: func(string) error { return nil }, EntraCertificate: func(context.Context, string, string, entracert.Open) (entracert.Material, error) {
		return entracert.Material{}, nil
	}}
	_, err := o.automaticInstallerToken(func(context.Context) (string, error) { return "", want })(context.Background())
	if strings.Contains(out.String(), "steps completed: 4/4") {
		t.Fatal("failed authorization reported complete progress")
	}
	if !errors.Is(err, want) {
		t.Fatalf("policy failure was replaced by an unrelated token error: %v", err)
	}
}
