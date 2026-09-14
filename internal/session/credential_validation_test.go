package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

type credentialTransport func(*http.Request) (*http.Response, error)

func (f credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Existing session tests use fake credentials and must never contact Cloudflare.
func acceptedCredentialClient() *cloudflare.Client {
	return &cloudflare.Client{HTTP: &http.Client{Transport: credentialTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"success":true,"result":[]}`))}, nil
	})}}
}

func TestInvalidCloudflareTokenStopsAtCredentialEntry(t *testing.T) {
	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", "invalid-fixture-token")
	checks := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks++
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`)
	}))
	defer srv.Close()
	u, out := testUI(false, "")
	o := Options{StateDir: t.TempDir(), CredSpecs: []creds.Spec{creds.Required[0]}, Cloudflare: &cloudflare.Client{Base: srv.URL}}
	st := &state.State{Config: map[string]string{"credential-mode": creds.ModeEnv}}
	err := o.credentialCheck(context.Background(), st, u)
	if err == nil || checks == 0 {
		t.Fatal("credential entry accepted an invalid token without checking Cloudflare; setup can install Docker before discovering the rejection")
	}
	if strings.Contains(err.Error()+out.String(), "invalid-fixture-token") {
		t.Fatal("token appeared in error or output")
	}
}

// A fake seal keeps only an opaque blob on disk. Fixture values stay in memory.
func credentialSeal(t *testing.T) (creds.Runner, map[string]string, *[]string) {
	t.Helper()
	values := map[string]string{}
	var sealed []string
	run := func(_ context.Context, input, _ string, args ...string) (string, string, error) {
		switch args[0] {
		case "encrypt":
			id := fmt.Sprintf("opaque-blob-%d", len(values))
			values[id] = input
			sealed = append(sealed, input)
			return id, "", nil
		case "decrypt":
			return values[input], "", nil
		}
		return "", "", errors.New("unexpected fixture command")
	}
	return run, values, &sealed
}

func tokenCheckingServer(t *testing.T) (*cloudflare.Client, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if r.Method != "GET" || strings.Contains(r.URL.Path, "/tokens/verify") {
			t.Error("credential check must use read-only product APIs for both token types")
		}
		if r.Header.Get("Authorization") != "Bearer accepted-fixture" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`)
			return
		}
		if r.URL.Path == "/zones" && r.URL.Query().Get("name") == "demo-customer.com.au" {
			fmt.Fprint(w, `{"success":true,"result":[{"id":"zone1","name":"demo-customer.com.au","account":{"id":"acct1","name":"Demo Customer"}}]}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	}))
	t.Cleanup(srv.Close)
	return &cloudflare.Client{Base: srv.URL}, &calls
}

func TestCloudflareEntryRetriesBeforeSealing(t *testing.T) {
	for _, mode := range []string{creds.ModeTPM, creds.ModeHostKey, creds.ModePrompt} {
		t.Run(mode, func(t *testing.T) {
			client, calls := tokenCheckingServer(t)
			run, _, sealed := credentialSeal(t)
			u, out := testUI(true, "r\n")
			inputs := []string{"rejected-fixture", "  accepted-fixture\n"}
			prompts := 0
			u.Secret = func(string) (string, error) {
				if prompts >= len(inputs) {
					t.Fatal("unexpected repeated secret prompt")
				}
				v := inputs[prompts]
				prompts++
				return v, nil
			}
			o := Options{StateDir: t.TempDir(), Cloudflare: client, CredsRun: run, CredSpecs: []creds.Spec{creds.Required[0]}}
			st := &state.State{Config: map[string]string{"credential-mode": mode}}
			if err := o.credentialCheck(context.Background(), st, u); err != nil {
				t.Fatal(err)
			}
			if prompts != 2 || len(*calls) != 2 {
				t.Fatal("entry did not validate each candidate")
			}
			if mode != creds.ModePrompt && (len(*sealed) != 1 || (*sealed)[0] != "accepted-fixture") {
				t.Fatal("rejected token was sealed or replacement was not sealed")
			}
			// Later phases reuse the accepted value without another secret prompt.
			if err := o.cloudflareClient(st, u).CheckToken(context.Background()); err != nil {
				t.Fatal(err)
			}
			if prompts != 2 {
				t.Fatal("accepted token was requested again")
			}
			for _, v := range inputs {
				if strings.Contains(out.String(), strings.TrimSpace(v)) {
					t.Fatal("token appeared in output")
				}
			}
		})
	}
}

func TestResumeReplacesRejectedSealedTokenWithoutRepeatingCompletedWork(t *testing.T) {
	client, _ := tokenCheckingServer(t)
	run, _, sealed := credentialSeal(t)
	dir := t.TempDir()
	m := &creds.Manager{Mode: creds.ModeTPM, Dir: filepath.Join(dir, "credentials"), Run: run}
	for _, s := range creds.Required {
		value := "rejected-fixture"
		if s.Generate {
			value = "database-fixture"
		}
		if _, err := m.Store(context.Background(), s, value); err != nil {
			t.Fatal(err)
		}
	}
	st := &state.State{DeploymentID: "original-deployment", Config: map[string]string{"credential-mode": creds.ModeTPM, "guac-hostname": "guac.demo-customer.com.au"}}
	for _, s := range creds.Required {
		recordCredentialResource(st, "credential-sealed", filepath.Base(m.Path(s)))
	}
	recordCredentialResource(st, "credential-dir", m.Dir)
	now := time.Now().UTC()
	for _, name := range []string{"initialise-deployment", "host-preflight", "credential-mode", "credential-check", "host-dependencies", "stack-configure"} {
		st.Actions = append(st.Actions, state.Action{ID: state.NewID(), Intent: name, StartedAt: now, FinishedAt: &now, Result: state.ResultOK})
	}
	st.Actions = append(st.Actions, state.Action{ID: state.NewID(), Intent: "cloudflare-select", StartedAt: now, FinishedAt: &now, Result: state.ResultFailed})
	seed(t, dir, st)
	u, out := testUI(true, "r\nr\n")
	u.Secret = func(string) (string, error) { return "accepted-fixture", nil }
	o := Options{StateDir: dir, UI: u, Cloudflare: client, CredsRun: run}
	all := Phases(&o)
	for i, p := range all {
		if p.Name == "cloudflare-select" {
			o.Phases = all[:i+1]
			break
		}
	}
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("resume: %v", err)
	}
	got, err := state.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentID != st.DeploymentID || len(got.Resources) != len(st.Resources) {
		t.Fatal("resume replaced deployment identity or duplicated resources")
	}
	if len(*sealed) != 3 || (*sealed)[2] != "accepted-fixture" {
		t.Fatal("resume did not replace only the Cloudflare credential")
	}
	if got.Config["cloudflare-zone-id"] != "zone1" {
		t.Fatal("resume did not reach zone selection")
	}
	for _, name := range []string{"host-dependencies", "stack-configure"} {
		count := 0
		for _, a := range got.Actions {
			if a.Intent == name {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("repeated completed phase %s", name)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	for _, v := range []string{"rejected-fixture", "accepted-fixture", "database-fixture"} {
		if strings.Contains(string(raw)+out.String(), v) {
			t.Fatal("credential leaked into state or output")
		}
	}
}

func TestCloudflareTemporaryFailureRetriesWithoutReplacingToken(t *testing.T) {
	client, calls := tokenCheckingServer(t)
	requests := 0
	realClient := http.DefaultClient
	client.HTTP = &http.Client{Transport: credentialTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return nil, errors.New("connection unavailable")
		}
		return realClient.Do(r)
	})}
	u, out := testUI(true, "r\n")
	prompts := 0
	u.Secret = func(string) (string, error) { prompts++; return "accepted-fixture", nil }
	o := Options{StateDir: t.TempDir(), Cloudflare: client, CredSpecs: []creds.Spec{creds.Required[0]}}
	st := &state.State{Config: map[string]string{"credential-mode": creds.ModePrompt}}
	if err := o.credentialCheck(context.Background(), st, u); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || requests != 2 || len(*calls) != 1 || strings.Contains(out.String(), "rejected") {
		t.Fatal("connection failure was treated as a rejected token")
	}
}

func TestQuitKeepsPreviousSealedToken(t *testing.T) {
	client, _ := tokenCheckingServer(t)
	run, _, sealed := credentialSeal(t)
	dir := t.TempDir()
	m := &creds.Manager{Mode: creds.ModeTPM, Dir: filepath.Join(dir, "credentials"), Run: run}
	if _, err := m.Store(context.Background(), creds.Required[0], "rejected-fixture"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.Path(creds.Required[0]))
	u, _ := testUI(true, "q\n")
	u.Secret = func(string) (string, error) { t.Fatal("quit must not prompt for a replacement"); return "", nil }
	o := Options{StateDir: dir, Cloudflare: client, CredsRun: run, CredSpecs: []creds.Spec{creds.Required[0]}}
	st := &state.State{Config: map[string]string{"credential-mode": creds.ModeTPM}}
	if err := o.credentialCheck(context.Background(), st, u); err == nil {
		t.Fatal("quit continued setup")
	}
	after, _ := os.ReadFile(m.Path(creds.Required[0]))
	if string(before) != string(after) || len(*sealed) != 1 {
		t.Fatal("quit overwrote the saved credential")
	}
}
