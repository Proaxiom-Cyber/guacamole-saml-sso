package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

func TestGuidedEntraClientDoesNotRequireExternalToken(t *testing.T) {
	t.Setenv(entra.DefaultTokenEnv, "")
	u, _ := testUI(true, "")
	o := &Options{UI: u}
	client, err := o.entraClient()
	if err != nil || client == nil {
		t.Fatalf("guided setup requires an external Graph token instead of offering Microsoft sign-in: %v", err)
	}
}

func TestGuidedEntraResumeAuthenticatesBeforePlanning(t *testing.T) {
	t.Setenv(entra.DefaultTokenEnv, "")
	dir := t.TempDir()
	u, out := testUI(true, "r\n\n")
	now := time.Now().UTC()
	st := &state.State{DeploymentID: "existing-deployment", Config: map[string]string{"guac-hostname": "guac.demo-customer.com.au", "cloudflare-zone-name": "demo-customer.com.au", "admin-group": "Guacamole Administrators", "operator-group": "Guacamole Operators"}, Actions: []state.Action{{ID: state.NewID(), Intent: "stack-up", StartedAt: now, FinishedAt: &now, Result: state.ResultOK}, {ID: state.NewID(), Intent: "entra-signin", StartedAt: now, FinishedAt: &now, Result: state.ResultFailed}}}
	seed(t, dir, st)
	const tenant = "11111111-2222-3333-4444-555555555555"
	payload, _ := json.Marshal(map[string]string{"tid": tenant, "scp": strings.Join(entra.RequiredPermissions, " ")})
	token := "fixture." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	prompts, planned := 0, false
	o := Options{StateDir: dir, UI: u, Entra: &entra.Client{Do: func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("mutation before test plan boundary")
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("Graph did not receive the signed-in token")
		}
		body := `{"value":[]}`
		status := 200
		if r.URL.Query().Get("$filter") != "" {
			planned = true
			status = 400
			body = `{"error":{"code":"TestPlanBoundary","message":"plan reached"}}`
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	}}, EntraDeviceToken: func(o entra.DeviceCodeOptions) (entra.TokenSource, error) {
		if o.TenantID != "demo-customer.com.au" || o.ClientID != entra.GraphCLIClientID {
			t.Fatal("wrong sign-in authority or client")
		}
		return func(ctx context.Context) (string, error) {
			if prompts == 0 {
				prompts++
				if err := o.Prompt(ctx, "https://microsoft.com/devicelogin", "TEST-CODE"); err != nil {
					return "", err
				}
			}
			return token, nil
		}, nil
	}}
	o.Phases = []Phase{{Name: "entra-signin", Run: o.entraSignin}}
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "TestPlanBoundary") || !planned || prompts != 1 {
		t.Fatalf("resume did not reach the plan after sign-in: %v", err)
	}
	got, _ := state.Read(dir)
	if got.DeploymentID != st.DeploymentID || got.Config["entra-tenant-id"] != tenant || got.Config["entra-login-tenant"] != "demo-customer.com.au" {
		t.Fatal("resume lost deployment or tenant binding")
	}
	if len(got.Actions) != 3 {
		t.Fatal("completed stack work repeated")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw)+out.String(), token) {
		t.Fatal("token leaked into state or output")
	}
	if !strings.Contains(out.String(), "TEST-CODE") || !strings.Contains(out.String(), "microsoft.com/devicelogin") {
		t.Fatal("sign-in instructions not displayed")
	}
}

func TestGuidedEntraRetryAndQuit(t *testing.T) {
	for _, retry := range []bool{true, false} {
		t.Run(map[bool]string{true: "retry", false: "quit"}[retry], func(t *testing.T) {
			t.Setenv(entra.DefaultTokenEnv, "")
			input := "q\n"
			if retry {
				input = "r\n"
			}
			u, _ := testUI(true, input)
			attempts := 0
			o := Options{UI: u, EntraDeviceToken: func(entra.DeviceCodeOptions) (entra.TokenSource, error) {
				attempts++
				return func(context.Context) (string, error) {
					if attempts == 1 {
						return "", errors.New("Microsoft sign-in expired")
					}
					return "accepted-fixture", nil
				}, nil
			}}
			client, err := o.entraClient()
			if err != nil {
				t.Fatal(err)
			}
			token, err := client.Token(context.Background())
			if retry && (err != nil || token != "accepted-fixture" || attempts != 2) {
				t.Fatal("sign-in retry did not continue")
			}
			if !retry && (err == nil || token != "" || attempts != 1) {
				t.Fatal("quit did not stop sign-in")
			}
		})
	}
}

func TestEntraResumeRefusesDifferentTenantBeforeMutation(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"tid": "different-tenant", "scp": strings.Join(entra.RequiredPermissions, " ")})
	token := "fixture." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
	u, _ := testUI(true, "")
	reads := 0
	o := Options{Entra: &entra.Client{Token: func(context.Context) (string, error) { return token, nil }, Do: func(r *http.Request) (*http.Response, error) {
		if r.Method != "GET" {
			t.Fatal("cross-tenant mutation")
		}
		reads++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"value":[]}`)), Header: make(http.Header)}, nil
	}}}
	st := &state.State{Config: map[string]string{"entra-tenant-id": "original-tenant"}}
	err := o.entraSignin(context.Background(), st, u)
	if err == nil || !strings.Contains(err.Error(), "different tenant") || reads != 1 {
		t.Fatalf("wrong tenant was not refused before planning: %v", err)
	}
	if st.Config["entra-tenant-id"] != "original-tenant" {
		t.Fatal("saved tenant changed")
	}
}
