package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const (
	tenantID      = "11111111-2222-3333-4444-555555555555"
	idpID         = "99999999-8888-7777-6666-555555555555"
	adminGroupID  = "aaaa0000-0000-0000-0000-000000000001"
	operGroupID   = "aaaa0000-0000-0000-0000-000000000002"
	authDomain    = "demo-customer.cloudflareaccess.com"
	wantAppName   = "Guacamole " + host + " (" + wantMarker + ")"
	wantPolicyNam = "Guacamole operators (" + wantMarker + ")"
)

// hostnameRT routes the unauthenticated hostname probe to a handler, so the
// enforcement check runs through the same injectable HTTP seam as the API.
// Everything addressed elsewhere is a normal API call to the fake server.
type hostnameRT struct {
	t  *testing.T
	fn func(*http.Request) *http.Response
}

func (rt hostnameRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != host {
		return http.DefaultTransport.RoundTrip(r)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		rt.t.Errorf("the hostname probe must be unauthenticated, got Authorization %q", got)
	}
	return rt.fn(r), nil
}

// probeResponse builds a bare response for the hostname probe.
func probeResponse(status int, location string) *http.Response {
	h := http.Header{}
	if location != "" {
		h.Set("Location", location)
	}
	return &http.Response{StatusCode: status, Header: h, Body: http.NoBody}
}

func (f *fake) probe(fn func(*http.Request) *http.Response) {
	f.client.HTTP = &http.Client{Transport: hostnameRT{t: f.t, fn: fn}}
}

func allowGroups() Allow {
	return Allow{IdPID: idpID, Groups: []string{adminGroupID, operGroupID}}
}

func TestPreflightAccess(t *testing.T) {
	f := newFake(t)
	f.mux["GET /accounts/acct1/access/organizations"] = ok(map[string]string{"auth_domain": authDomain, "name": "Demo Customer"})
	f.mux["GET /accounts/acct1/access/identity_providers"] = ok([]any{})
	f.mux["GET /accounts/acct1/access/apps"] = ok([]any{})
	if err := f.client.PreflightAccess(context.Background(), "acct1"); err != nil {
		t.Fatalf("PreflightAccess: %v", err)
	}

	// A missing Apps and Policies read scope is reported by name.
	f.mux["GET /accounts/acct1/access/apps"] = fail(403, 9109, "Unauthorized to access requested resource")
	err := f.client.PreflightAccess(context.Background(), "acct1")
	if err == nil || !strings.Contains(err.Error(), "Access Apps and Policies Read") {
		t.Fatalf("want Apps and Policies Read failure, got %v", err)
	}
	noSecret(t, err)

	// An account without Zero Trust set up is reported as that, not as a
	// permission problem.
	f.mux["GET /accounts/acct1/access/apps"] = ok([]any{})
	f.mux["GET /accounts/acct1/access/organizations"] = ok(map[string]string{})
	err = f.client.PreflightAccess(context.Background(), "acct1")
	if err == nil || !strings.Contains(err.Error(), "no Zero Trust organization") {
		t.Fatalf("want missing-organization failure, got %v", err)
	}
	noSecret(t, err)
}

func TestIdentityProviderSelection(t *testing.T) {
	f := newFake(t)
	f.mux["GET /accounts/acct1/access/identity_providers"] = ok([]map[string]any{
		{"id": "otp1", "name": "One-time PIN", "type": "onetimepin"},
		{"id": idpID, "name": "Entra ID", "type": "azureAD", "config": map[string]any{
			"directory_id": tenantID, "client_id": "cid", "client_secret": testAPIToken,
		}},
	})
	idps, err := f.client.IdentityProviders(context.Background(), "acct1")
	if err != nil {
		t.Fatalf("IdentityProviders: %v", err)
	}
	// The provider config holds an OAuth client secret; it must not survive
	// into the values the parent journals.
	b, _ := json.Marshal(idps)
	if strings.Contains(string(b), testAPIToken) || strings.Contains(string(b), "client_secret") {
		t.Fatalf("identity provider values carry provider config secrets: %s", b)
	}

	idp, found := FindEntraIdP(idps, tenantID)
	if !found || idp.ID != idpID || idp.DirectoryID != tenantID {
		t.Fatalf("FindEntraIdP = %+v, %v", idp, found)
	}
	if _, found := FindEntraIdP(idps, "00000000-0000-0000-0000-000000000000"); found {
		t.Fatal("a different tenant must not match the Entra identity provider")
	}
	if _, found := FindEntraIdP(idps, ""); found {
		t.Fatal("an unknown tenant must not match any identity provider")
	}
}

func TestPlanAccessRefusesEmptyAllowList(t *testing.T) {
	p := newFake(t).prov()
	if _, err := p.PlanAccess(Allow{}); !errors.Is(err, ErrNoAllowList) {
		t.Fatalf("want ErrNoAllowList, got %v", err)
	}
	// Groups without the identity provider they belong to are refused too.
	if _, err := p.PlanAccess(Allow{Groups: []string{adminGroupID}}); err == nil {
		t.Fatal("want an error for group rules with no identity provider")
	}
}

func TestApplyAccessHappyPath(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	f.mux["GET /accounts/acct1/access/apps"] = func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("name") != "":
			if got := r.URL.Query().Get("name"); got != wantAppName {
				t.Errorf("marker lookup name = %q, want %q", got, wantAppName)
			}
			if got := r.URL.Query().Get("exact"); got != "true" {
				t.Errorf("marker lookup exact = %q", got)
			}
		case r.URL.Query().Get("domain") != host:
			t.Errorf("hostname lookup domain = %q", r.URL.Query().Get("domain"))
		}
		ok([]any{})(w, r)
	}
	f.mux["POST /accounts/acct1/access/apps"] = ok(map[string]any{
		"id": "app1", "name": wantAppName, "domain": host, "type": "self_hosted", "aud": "aud-tag",
	})
	f.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]any{})
	f.mux["POST /accounts/acct1/access/apps/app1/policies"] = ok(map[string]any{
		"id": "pol1", "name": wantPolicyNam, "decision": "allow",
		"include": []map[string]any{
			{"azureAD": map[string]any{"id": adminGroupID, "identity_provider_id": idpID}},
		},
	})

	plan, err := p.PlanAccess(allowGroups())
	if err != nil {
		t.Fatalf("PlanAccess: %v", err)
	}
	app, pol, err := p.ApplyAccess(context.Background(), plan)
	if err != nil {
		t.Fatalf("ApplyAccess: %v", err)
	}
	if app.ID != "app1" || app.Name != wantAppName || pol.ID != "pol1" {
		t.Fatalf("app = %+v, policy = %+v", app, pol)
	}

	// The application creation body carries the marker in the name, covers
	// the hostname, and is a self-hosted application bound to the one Entra
	// identity provider.
	var appBody map[string]any
	if err := json.Unmarshal(f.lastBody["POST /accounts/acct1/access/apps"], &appBody); err != nil {
		t.Fatalf("app create body: %v", err)
	}
	if appBody["name"] != wantAppName {
		t.Fatalf("app create name = %v, want the marker name %q", appBody["name"], wantAppName)
	}
	if !strings.Contains(appBody["name"].(string), wantMarker) {
		t.Fatalf("the marker must be set inside the creation body: %v", appBody["name"])
	}
	if appBody["domain"] != host || appBody["type"] != "self_hosted" {
		t.Fatalf("app create body = %v", appBody)
	}
	if appBody["app_launcher_visible"] != false || appBody["auto_redirect_to_identity"] != true {
		t.Fatalf("app create body = %v", appBody)
	}
	idps, _ := appBody["allowed_idps"].([]any)
	if len(idps) != 1 || idps[0] != idpID {
		t.Fatalf("allowed_idps = %v, want only the Entra identity provider", appBody["allowed_idps"])
	}

	// The policy creation body allows exactly the two Entra groups.
	var polBody struct {
		Name       string           `json:"name"`
		Decision   string           `json:"decision"`
		Precedence int              `json:"precedence"`
		Include    []map[string]any `json:"include"`
	}
	if err := json.Unmarshal(f.lastBody["POST /accounts/acct1/access/apps/app1/policies"], &polBody); err != nil {
		t.Fatalf("policy create body: %v", err)
	}
	if polBody.Name != wantPolicyNam || polBody.Decision != "allow" || polBody.Precedence != 1 {
		t.Fatalf("policy create body = %+v", polBody)
	}
	if len(polBody.Include) != 2 {
		t.Fatalf("allow-list = %v, want the two Entra groups", polBody.Include)
	}
	for i, want := range []string{adminGroupID, operGroupID} {
		rule, okRule := polBody.Include[i]["azureAD"].(map[string]any)
		if !okRule || rule["id"] != want || rule["identity_provider_id"] != idpID {
			t.Fatalf("include[%d] = %v", i, polBody.Include[i])
		}
	}
}

func TestPlanAccessEmailFallback(t *testing.T) {
	p := newFake(t).prov()
	plan, err := p.PlanAccess(Allow{Emails: []string{"ops@example.com"}})
	if err != nil {
		t.Fatalf("PlanAccess: %v", err)
	}
	// With no identity provider bound, the account's providers all apply and
	// the chooser must not be skipped.
	if len(plan.App.AllowedIdPs) != 0 || plan.App.AutoRedirectToIdentity {
		t.Fatalf("app plan = %+v", plan.App)
	}
	rule, okRule := plan.Policy.Include[0]["email"].(map[string]any)
	if len(plan.Policy.Include) != 1 || !okRule || rule["email"] != "ops@example.com" {
		t.Fatalf("allow-list = %v", plan.Policy.Include)
	}
}

func TestApplyAccessLostResponseReconcile(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	// The application and its policy already exist under the marker name:
	// adopt both, create neither.
	f.mux["GET /accounts/acct1/access/apps"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != wantAppName {
			t.Errorf("the marker lookup must run before any retry-create, got %s", r.URL.RawQuery)
		}
		ok([]map[string]any{{"id": "app1", "name": wantAppName, "domain": host, "aud": "aud-tag"}})(w, r)
	}
	f.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]map[string]any{
		{"id": "pol1", "name": wantPolicyNam, "decision": "allow", "include": []map[string]any{
			{"azureAD": map[string]any{"id": adminGroupID, "identity_provider_id": idpID}},
		}},
	})

	plan, err := p.PlanAccess(allowGroups())
	if err != nil {
		t.Fatalf("PlanAccess: %v", err)
	}
	app, pol, err := p.ApplyAccess(context.Background(), plan)
	if err != nil {
		t.Fatalf("ApplyAccess reconcile: %v", err)
	}
	if app.ID != "app1" || pol.ID != "pol1" {
		t.Fatalf("adopted app = %+v, policy = %+v", app, pol)
	}
	if f.hits["POST /accounts/acct1/access/apps"] != 0 {
		t.Fatal("reconcile must not duplicate the Access application")
	}
	if f.hits["POST /accounts/acct1/access/apps/app1/policies"] != 0 {
		t.Fatal("reconcile must not duplicate the Access policy")
	}
}

func TestApplyAccessNameOnlyMatchRequiresReview(t *testing.T) {
	other := "Guacamole " + host + " (guacdeploy:ffffffffffffffffffffffffffffffff)"

	// Same hostname, this tool's naming convention, another deployment ID.
	f := newFake(t)
	p := f.prov()
	f.mux["GET /accounts/acct1/access/apps"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "" {
			ok([]any{})(w, r) // no marker match
			return
		}
		ok([]map[string]any{{"id": "appX", "name": other, "domain": host}})(w, r)
	}
	_, _, err := applyPlan(t, p, allowGroups())
	if !errors.Is(err, ErrRequiresReview) {
		t.Fatalf("want ErrRequiresReview, got %v", err)
	}
	if f.hits["POST /accounts/acct1/access/apps"] != 0 {
		t.Fatal("ambiguity must not create a duplicate")
	}
	noSecret(t, err)

	// The marker name alone is never enough: the same name on another
	// hostname is a broken linkage, not this deployment's application.
	f2 := newFake(t)
	p2 := f2.prov()
	f2.mux["GET /accounts/acct1/access/apps"] = ok([]map[string]any{
		{"id": "appY", "name": wantAppName, "domain": "other.example.com"},
	})
	_, _, err = applyPlan(t, p2, allowGroups())
	if !errors.Is(err, ErrRequiresReview) {
		t.Fatalf("want ErrRequiresReview for a marker name on another hostname, got %v", err)
	}
	if f2.hits["POST /accounts/acct1/access/apps"] != 0 {
		t.Fatal("a broken linkage must not create a duplicate")
	}
	noSecret(t, err)
}

func TestApplyAccessPreExistingApp(t *testing.T) {
	f := newFake(t)
	p := f.prov()
	f.mux["GET /accounts/acct1/access/apps"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "" {
			ok([]any{})(w, r)
			return
		}
		ok([]map[string]any{
			// The domain filter matches substrings, so a different hostname
			// can come back; it must not be mistaken for a conflict.
			{"id": "appZ", "name": "Other team console", "domain": "old-" + host},
			{"id": "appW", "name": "Existing console", "domain": "https://" + host + "/",
				"session_duration": "730h", "allowed_idps": []string{"otp1"},
				"auto_redirect_to_identity": false},
		})(w, r)
	}
	_, _, err := applyPlan(t, p, allowGroups())
	if !errors.Is(err, ErrPreExisting) {
		t.Fatalf("want ErrPreExisting, got %v", err)
	}
	if f.hits["POST /accounts/acct1/access/apps"] != 0 {
		t.Fatal("a pre-existing application must not be overwritten or duplicated")
	}
	var pre *PreExistingApp
	if !errors.As(err, &pre) {
		t.Fatalf("want a *PreExistingApp carrying the original values, got %T", err)
	}
	if pre.AppID != "appW" {
		t.Fatalf("pre-existing app = %+v", pre)
	}
	originals := map[string]string{}
	for _, ch := range pre.Changes {
		originals[ch.Field] = string(ch.Original)
	}
	for field, want := range map[string]string{
		"accessApplication.session_duration":          `"730h"`,
		"accessApplication.allowed_idps":              `["otp1"]`,
		"accessApplication.auto_redirect_to_identity": `false`,
	} {
		if originals[field] != want {
			t.Fatalf("original %s = %s, want %s", field, originals[field], want)
		}
	}
	noSecret(t, err)
}

func TestVerifyAccess(t *testing.T) {
	f := newFake(t)
	p := f.prov()
	f.mux["GET /accounts/acct1/access/apps/app1"] = ok(map[string]any{
		"id": "app1", "name": wantAppName, "domain": host, "aud": "aud-tag",
	})
	f.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]map[string]any{
		{"id": "pol1", "name": wantPolicyNam, "decision": "allow", "include": []map[string]any{
			{"azureAD": map[string]any{"id": adminGroupID, "identity_provider_id": idpID}},
			{"azureAD": map[string]any{"id": operGroupID, "identity_provider_id": idpID}},
		}},
	})
	f.mux["GET /accounts/acct1/access/organizations"] = ok(map[string]string{"auth_domain": authDomain})
	f.probe(func(r *http.Request) *http.Response {
		if r.URL.String() != "https://"+host+"/" {
			t.Errorf("probe URL = %s", r.URL)
		}
		return probeResponse(302, "https://"+authDomain+"/cdn-cgi/access/login/"+host+"?kid=abc")
	})

	v, err := p.VerifyAccess(context.Background(), "app1")
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if v.PolicyID != "pol1" || v.AllowRules != 2 || v.AuthDomain != authDomain {
		t.Fatalf("verification = %+v", v)
	}
	if !strings.Contains(v.Challenge, authDomain) || !strings.Contains(v.Challenge, "302") {
		t.Fatalf("challenge evidence = %q", v.Challenge)
	}

	// The origin answering directly means Access is not enforcing.
	f.probe(func(*http.Request) *http.Response { return probeResponse(200, "") })
	_, err = p.VerifyAccess(context.Background(), "app1")
	if err == nil || !strings.Contains(err.Error(), "not protected") {
		t.Fatalf("want an unprotected-hostname failure, got %v", err)
	}
	noSecret(t, err)

	// So does a redirect somewhere that is not the Access login.
	f.probe(func(*http.Request) *http.Response { return probeResponse(302, "https://login.example.com/") })
	_, err = p.VerifyAccess(context.Background(), "app1")
	if err == nil || !strings.Contains(err.Error(), "not protected") {
		t.Fatalf("want a wrong-redirect failure, got %v", err)
	}
	noSecret(t, err)

	// An application with no allow policy leaves nobody able to sign in.
	f.probe(func(*http.Request) *http.Response {
		return probeResponse(302, "https://"+authDomain+"/cdn-cgi/access/login/"+host)
	})
	f.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]any{})
	if _, err := p.VerifyAccess(context.Background(), "app1"); err == nil ||
		!strings.Contains(err.Error(), "no allow policy") {
		t.Fatalf("want a missing-policy failure, got %v", err)
	}

	// An application that no longer covers the hostname fails verification.
	f.mux["GET /accounts/acct1/access/apps/app1"] = ok(map[string]any{
		"id": "app1", "name": wantAppName, "domain": "other.example.com",
	})
	if _, err := p.VerifyAccess(context.Background(), "app1"); err == nil ||
		!strings.Contains(err.Error(), "not protected") {
		t.Fatalf("want a domain-mismatch failure, got %v", err)
	}
}

func TestDeleteAccessAppRefusesUnmarked(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	f.mux["GET /accounts/acct1/access/apps/appX"] = ok(map[string]any{
		"id": "appX", "name": "Someone else's console", "domain": host,
	})
	err := p.DeleteAccessApp(context.Background(), "appX")
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("want ErrNotOwned, got %v", err)
	}
	if f.hits["DELETE /accounts/acct1/access/apps/appX"] != 0 {
		t.Fatal("an unmarked Access application must not be deleted")
	}

	// The marker name alone does not authorise deletion: the application must
	// still secure this deployment's hostname.
	f.mux["GET /accounts/acct1/access/apps/appY"] = ok(map[string]any{
		"id": "appY", "name": wantAppName, "domain": "other.example.com",
	})
	err = p.DeleteAccessApp(context.Background(), "appY")
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("want ErrNotOwned for a broken linkage, got %v", err)
	}
	if f.hits["DELETE /accounts/acct1/access/apps/appY"] != 0 {
		t.Fatal("an application on another hostname must not be deleted")
	}

	// A marker-verified application does get deleted.
	f.mux["GET /accounts/acct1/access/apps/app1"] = ok(map[string]any{
		"id": "app1", "name": wantAppName, "domain": host,
	})
	f.mux["DELETE /accounts/acct1/access/apps/app1"] = ok(map[string]string{"id": "app1"})
	if err := p.DeleteAccessApp(context.Background(), "app1"); err != nil {
		t.Fatalf("DeleteAccessApp: %v", err)
	}
	if f.hits["DELETE /accounts/acct1/access/apps/app1"] != 1 {
		t.Fatal("the marker-verified delete did not happen")
	}
}

func TestAccessNeverLeaksTheAPIToken(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	// A failing call whose raw response body contains the token must not
	// surface the body: errors carry status and API messages only.
	f.mux["GET /accounts/acct1/access/apps/app1"] = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		if _, err := w.Write([]byte("gateway dump: auth " + testAPIToken)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := p.VerifyAccess(context.Background(), "app1")
	if err == nil {
		t.Fatal("want error")
	}
	noSecret(t, err)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("want APIError 500, got %v", err)
	}

	// Nothing the parent journals has a field that could carry a token.
	plan, err := p.PlanAccess(allowGroups())
	if err != nil {
		t.Fatalf("PlanAccess: %v", err)
	}
	for _, v := range []any{
		plan.App, plan.Policy,
		AccessApp{ID: "app1", Name: wantAppName, Domain: host, AUD: "aud-tag"},
		AccessPolicy{ID: "pol1", Name: wantPolicyNam, Decision: "allow"},
		AccessVerification{AppID: "app1", AuthDomain: authDomain, Challenge: "HTTP 302 to " + authDomain},
		IdentityProvider{ID: idpID, Name: "Entra ID", Type: "azureAD", DirectoryID: tenantID},
	} {
		b, _ := json.Marshal(v)
		if strings.Contains(strings.ToLower(string(b)), "token") || strings.Contains(strings.ToLower(string(b)), "secret") {
			t.Fatalf("%T marshals a secret-shaped field: %s", v, b)
		}
	}
}

// applyPlan plans and applies in one step, for tests that only care about the
// apply outcome.
func applyPlan(t *testing.T, p *Provisioner, allow Allow) (AccessApp, AccessPolicy, error) {
	t.Helper()
	plan, err := p.PlanAccess(allow)
	if err != nil {
		t.Fatalf("PlanAccess: %v", err)
	}
	return p.ApplyAccess(context.Background(), plan)
}
