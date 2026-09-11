package entra

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fake routes Graph and metadata calls by "METHOD /path". No real tenant is
// ever contacted: an unrouted call fails the test, which also proves that no
// unplanned creation happens.
type fake struct {
	t      *testing.T
	calls  []string
	routes map[string]func(t *testing.T, req *http.Request) *http.Response
}

func (f *fake) do(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path
	f.calls = append(f.calls, key)
	h, ok := f.routes[key]
	if !ok {
		f.t.Fatalf("unexpected call: %s (query %q)", key, req.URL.RawQuery)
	}
	return h(f.t, req), nil
}

func (f *fake) count(key string) int {
	n := 0
	for _, c := range f.calls {
		if c == key {
			n++
		}
	}
	return n
}

func jsonResp(status int, v any) *http.Response {
	var body []byte
	if v != nil {
		body, _ = json.Marshal(v)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}
}

func rawResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func graphErr(status int, code, msg string) *http.Response {
	return jsonResp(status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func readBody(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	return m
}

func jwt(t *testing.T, claims map[string]any) string {
	t.Helper()
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(p) + ".sig"
}

func newClient(f *fake, token string) *Client {
	return &Client{
		Token: func(context.Context) (string, error) { return token, nil },
		Do:    f.do,
	}
}

var testCfg = Config{
	Hostname:      "guac.example.com",
	DeploymentID:  "dep1",
	AdminGroup:    "Guacamole Administrators",
	OperatorGroup: "Guacamole Operators",
}

const testMarker = "guacdeploy:dep1"

// desiredApp is a full application record already in the desired state,
// carrying this deployment's marker.
func desiredApp() map[string]any {
	return map[string]any{
		"id": "obj-1", "appId": "app-1",
		"displayName":           "Guacamole (guac.example.com)",
		"notes":                 testMarker,
		"tags":                  []string{testMarker},
		"identifierUris":        []string{"https://guac.example.com/guacamole"},
		"web":                   map[string]any{"redirectUris": []string{"https://guac.example.com/guacamole/"}},
		"groupMembershipClaims": "ApplicationGroup",
		"optionalClaims": map[string]any{"saml2Token": []map[string]any{
			{"name": "groups", "additionalProperties": []string{"cloud_displayname"}},
		}},
	}
}

func groupsByFilter(byName map[string]any) func(*testing.T, *http.Request) *http.Response {
	return func(t *testing.T, req *http.Request) *http.Response {
		filter := req.URL.Query().Get("$filter")
		for name, v := range byName {
			if strings.Contains(filter, name) {
				return jsonResp(200, map[string]any{"value": []any{v}})
			}
		}
		return jsonResp(200, map[string]any{"value": []any{}})
	}
}

func TestCheckPermissionsPass(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
	}}
	tok := jwt(t, map[string]any{"scp": strings.Join(RequiredPermissions, " ")})
	p, err := newClient(f, tok).CheckPermissions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !p.ReadOK || !p.ClaimsChecked || !p.MutationOK {
		t.Fatalf("expected all checks to pass: %+v", p)
	}
}

func TestCheckPermissionsFail(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return graphErr(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
		},
	}}
	tok := jwt(t, map[string]any{"scp": "User.Read", "roles": []string{"Organization.Read.All"}})
	p, err := newClient(f, tok).CheckPermissions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.ReadOK || !strings.Contains(p.ReadDetail, "Authorization_RequestDenied") {
		t.Fatalf("read check should fail with the Graph error: %+v", p)
	}
	if !p.ClaimsChecked || p.MutationOK || !strings.Contains(p.MutationDetail, "Application.ReadWrite.All") {
		t.Fatalf("mutation check should name the missing permission: %+v", p)
	}
}

func TestCheckPermissionsOpaqueToken(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
	}}
	p, err := newClient(f, "opaque-token-value").CheckPermissions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.ClaimsChecked || p.MutationOK {
		t.Fatalf("an opaque token must skip the mutation check, not guess: %+v", p)
	}
}

func TestApplyFreshProvisioning(t *testing.T) {
	tok := jwt(t, map[string]any{"scp": "Application.ReadWrite.All"})
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
		"GET /v1.0/groups": groupsByFilter(nil),
		"GET /v1.0/organization": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]string{{"id": "tenant-1"}}})
		},
		"POST /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if b["notes"] != testMarker {
				t.Fatalf("creation body must carry the marker in notes, got %v", b["notes"])
			}
			if tags, _ := b["tags"].([]any); len(tags) != 1 || tags[0] != testMarker {
				t.Fatalf("creation body must carry the marker in tags, got %v", b["tags"])
			}
			if uris, _ := b["identifierUris"].([]any); len(uris) != 1 || uris[0] != "https://guac.example.com/guacamole" {
				t.Fatalf("entity ID wrong: %v", b["identifierUris"])
			}
			web, _ := b["web"].(map[string]any)
			if ru, _ := web["redirectUris"].([]any); len(ru) != 1 || ru[0] != "https://guac.example.com/guacamole/" {
				t.Fatalf("reply URL wrong: %v", web)
			}
			if b["groupMembershipClaims"] != "ApplicationGroup" {
				t.Fatalf("groupMembershipClaims wrong: %v", b["groupMembershipClaims"])
			}
			if !strings.Contains(string(mustJSON(b["optionalClaims"])), "cloud_displayname") {
				t.Fatalf("groups claim must emit display names: %v", b["optionalClaims"])
			}
			return jsonResp(201, map[string]string{"id": "obj-1", "appId": "app-1"})
		},
		"GET /v1.0/servicePrincipals": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
		"POST /v1.0/servicePrincipals": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if b["appId"] != "app-1" {
				t.Fatalf("service principal must link to the created app: %v", b)
			}
			return jsonResp(201, map[string]string{"id": "sp-1"})
		},
		"PATCH /v1.0/servicePrincipals/sp-1": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if th, ok := b["preferredTokenSigningKeyThumbprint"]; ok {
				if th != "TT" {
					t.Fatalf("wrong thumbprint: %v", th)
				}
			} else if b["preferredSingleSignOnMode"] != "saml" || b["appRoleAssignmentRequired"] != true {
				t.Fatalf("service principal must be SAML with assignment required: %v", b)
			}
			return jsonResp(204, nil)
		},
		"POST /v1.0/servicePrincipals/sp-1/addTokenSigningCertificate": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(201, map[string]string{"thumbprint": "TT"})
		},
		"GET /v1.0/servicePrincipals/sp-1/appRoleAssignedTo": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
		"POST /v1.0/groups": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if b["description"] != testMarker {
				t.Fatalf("created group must carry the marker in description: %v", b)
			}
			if b["securityEnabled"] != true || b["mailEnabled"] != false {
				t.Fatalf("created group must be a security group: %v", b)
			}
			if b["displayName"] == "Guacamole Administrators" {
				return jsonResp(201, map[string]string{"id": "g-admin"})
			}
			return jsonResp(201, map[string]string{"id": "g-op"})
		},
		"POST /v1.0/servicePrincipals/sp-1/appRoleAssignedTo": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if b["resourceId"] != "sp-1" || b["appRoleId"] != nilRoleID {
				t.Fatalf("assignment wrong: %v", b)
			}
			if p := b["principalId"]; p != "g-admin" && p != "g-op" {
				t.Fatalf("assignment must target a created group: %v", p)
			}
			return jsonResp(201, map[string]string{"id": "as-1"})
		},
	}}
	c := newClient(f, tok)

	plan, err := c.Plan(context.Background(), testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan.App != nil {
		t.Fatal("fresh tenant must plan an application creation")
	}
	types := map[string]int{}
	for _, cr := range plan.Creations {
		types[cr.Type]++
	}
	if types["application"] != 1 || types["service-principal"] != 1 || types["group"] != 2 ||
		types["app-role-assignment"] != 2 || types["token-signing-certificate"] != 1 {
		t.Fatalf("unexpected creation intents: %v", plan.Creations)
	}

	res, err := c.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !res.App.CreatedApp || !res.App.CreatedSP || res.App.SPObjectID != "sp-1" {
		t.Fatalf("unexpected applied app: %+v", res.App)
	}
	want := "https://login.microsoftonline.com/tenant-1/federationmetadata/2007-06/federationmetadata.xml?appid=app-1"
	if res.MetadataURL != want {
		t.Fatalf("metadata URL:\n got %s\nwant %s", res.MetadataURL, want)
	}
	if !strings.Contains(res.App.Evidence, testMarker) {
		t.Fatalf("ownership evidence must name the marker: %q", res.App.Evidence)
	}
	if len(res.Groups) != 2 || !res.Groups[0].Created || !res.Groups[1].Created {
		t.Fatalf("both groups should be created: %+v", res.Groups)
	}
	if len(res.Changes) != 0 {
		t.Fatalf("fresh creation must report no pre-existing changes: %+v", res.Changes)
	}
	if n := f.count("POST /v1.0/applications"); n != 1 {
		t.Fatalf("exactly one application creation expected, got %d", n)
	}
	// The token must not leak into evidence or the metadata URL.
	for _, s := range []string{res.App.Evidence, res.Groups[0].Evidence, res.Groups[1].Evidence, res.MetadataURL} {
		if strings.Contains(s, tok) {
			t.Fatalf("token leaked into recorded evidence: %q", s)
		}
	}
}

func TestLostResponseThenResumeDoesNotDuplicate(t *testing.T) {
	tok := "opaque-secret-token"
	// First run: the application creation response is lost (502 mid-create).
	f1 := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
		"GET /v1.0/groups": groupsByFilter(nil),
		"GET /v1.0/organization": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]string{{"id": "tenant-1"}}})
		},
		"POST /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return graphErr(502, "BadGateway", "upstream error")
		},
	}}
	c1 := newClient(f1, tok)
	plan, err := c1.Plan(context.Background(), testCfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c1.Apply(context.Background(), plan)
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("a lost creation response must return ErrUncertain, got %v", err)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatalf("token leaked into error: %v", err)
	}

	// Resume: the marker query finds the application the lost request
	// created, and no second application is ever created (the fake has no
	// POST /applications route, so an attempt would fail the test).
	marked := desiredApp()
	f2 := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{marked}})
		},
		"GET /v1.0/servicePrincipals": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]any{{
				"id": "sp-1", "preferredSingleSignOnMode": "saml",
				"appRoleAssignmentRequired":          true,
				"preferredTokenSigningKeyThumbprint": "TT",
			}}})
		},
		"GET /v1.0/groups": groupsByFilter(map[string]any{
			"Guacamole Administrators": map[string]string{"id": "g-a", "displayName": "Guacamole Administrators", "description": testMarker},
			"Guacamole Operators":      map[string]string{"id": "g-o", "displayName": "Guacamole Operators", "description": testMarker},
		}),
		"GET /v1.0/organization": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]string{{"id": "tenant-1"}}})
		},
		"GET /v1.0/servicePrincipals/sp-1/appRoleAssignedTo": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]string{{"principalId": "g-a"}, {"principalId": "g-o"}}})
		},
	}}
	c2 := newClient(f2, tok)
	cfg := testCfg
	cfg.AfterUncertainCreate = true
	plan2, err := c2.Plan(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan2.App == nil || !plan2.App.ProvenOurs {
		t.Fatalf("resume must adopt the marked application as proven ours: %+v", plan2.App)
	}
	for _, cr := range plan2.Creations {
		if cr.Type == "application" {
			t.Fatal("resume must not plan a duplicate application creation")
		}
	}
	res, err := c2.Apply(context.Background(), plan2)
	if err != nil {
		t.Fatal(err)
	}
	if res.App.CreatedApp || f2.count("POST /v1.0/applications") != 0 {
		t.Fatal("resume created a duplicate application")
	}
	if res.MetadataURL == "" || res.App.AppID != "app-1" {
		t.Fatalf("resume must still produce the sign-in configuration: %+v", res)
	}
}

func TestAmbiguousMatchRequiresReview(t *testing.T) {
	unmarked := desiredApp()
	delete(unmarked, "notes")
	unmarked["tags"] = []string{}
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{unmarked}})
		},
	}}
	cfg := testCfg
	cfg.AfterUncertainCreate = true
	_, err := newClient(f, "tok").Plan(context.Background(), cfg)
	if !errors.Is(err, ErrRequiresReview) {
		t.Fatalf("a name-only match after an uncertain create must require review, got %v", err)
	}

	// Several applications with the matching name always require review.
	f2 := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{desiredApp(), desiredApp()}})
		},
	}}
	_, err = newClient(f2, "tok").Plan(context.Background(), testCfg)
	if !errors.Is(err, ErrRequiresReview) {
		t.Fatalf("multiple name matches must require review, got %v", err)
	}
}

func TestPreExistingAppChangesReturnOriginals(t *testing.T) {
	existing := map[string]any{
		"id": "obj-1", "appId": "app-1",
		"displayName":    "Guacamole (guac.example.com)",
		"identifierUris": []string{},
		"web":            map[string]any{"redirectUris": []string{"https://old.example.com/cb"}},
	}
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{existing}})
		},
		"GET /v1.0/servicePrincipals": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]any{{
				"id": "sp-1", "preferredSingleSignOnMode": "",
				"appRoleAssignmentRequired":          false,
				"preferredTokenSigningKeyThumbprint": "TT",
				"appRoles":                           []map[string]string{{"id": "role-1"}},
			}}})
		},
		"GET /v1.0/groups": groupsByFilter(map[string]any{
			"Guacamole Administrators": map[string]string{"id": "g-a", "displayName": "Guacamole Administrators", "description": "made by HR"},
			"Guacamole Operators":      map[string]string{"id": "g-o", "displayName": "Guacamole Operators", "description": ""},
		}),
		"GET /v1.0/organization": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]string{{"id": "tenant-1"}}})
		},
		"PATCH /v1.0/applications/obj-1": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if _, ok := b["notes"]; ok {
				t.Fatal("a pre-existing application must never be stamped with an ownership marker")
			}
			if _, ok := b["tags"]; ok {
				t.Fatal("a pre-existing application must never be stamped with an ownership tag")
			}
			if b["groupMembershipClaims"] != "ApplicationGroup" {
				t.Fatalf("patch must converge groupMembershipClaims: %v", b)
			}
			return jsonResp(204, nil)
		},
		"PATCH /v1.0/servicePrincipals/sp-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(204, nil)
		},
		"GET /v1.0/servicePrincipals/sp-1/appRoleAssignedTo": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{}})
		},
		"POST /v1.0/servicePrincipals/sp-1/appRoleAssignedTo": func(t *testing.T, r *http.Request) *http.Response {
			b := readBody(t, r)
			if b["appRoleId"] != "role-1" {
				t.Fatalf("assignment must use the application's own app role: %v", b)
			}
			return jsonResp(201, map[string]string{"id": "as-1"})
		},
	}}
	c := newClient(f, "tok")

	plan, err := c.Plan(context.Background(), testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if plan.App == nil || plan.App.ProvenOurs {
		t.Fatalf("the unmarked application must be reported as pre-existing: %+v", plan.App)
	}
	if len(plan.Changes) == 0 {
		t.Fatal("plan must list the pending changes for approval")
	}

	res, err := c.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	byField := map[string]FieldChange{}
	for _, ch := range res.Changes {
		byField[ch.Field] = ch
	}
	ru, ok := byField["application.web.redirectUris"]
	if !ok || !strings.Contains(string(ru.Original), "old.example.com") {
		t.Fatalf("original reply URL must be recorded for SettingChange: %+v", res.Changes)
	}
	if ch, ok := byField["servicePrincipal.appRoleAssignmentRequired"]; !ok || string(ch.Original) != "false" {
		t.Fatalf("original appRoleAssignmentRequired must be recorded: %+v", res.Changes)
	}
	if !strings.Contains(res.App.Evidence, "pre-existing") {
		t.Fatalf("evidence must state the app is pre-existing: %q", res.App.Evidence)
	}
	for _, g := range res.Groups {
		if g.Created || !strings.Contains(g.Evidence, "pre-existing") {
			t.Fatalf("pre-existing groups must be reused unchanged: %+v", g)
		}
	}
}

func TestPreExistingAppWithOtherEntityIDRequiresReview(t *testing.T) {
	other := desiredApp()
	delete(other, "notes")
	other["tags"] = []string{}
	other["identifierUris"] = []string{"https://other.example.com/sso"}
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []any{other}})
		},
	}}
	_, err := newClient(f, "tok").Plan(context.Background(), testCfg)
	if !errors.Is(err, ErrRequiresReview) {
		t.Fatalf("an application serving another entity ID must require review, got %v", err)
	}
}

func TestCleanupRefusesUnmarked(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications/obj-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"id": "obj-1", "displayName": "Guacamole (guac.example.com)"})
		},
		"GET /v1.0/groups/g-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"id": "g-1", "displayName": "Guacamole Operators", "description": "made by HR"})
		},
	}}
	c := newClient(f, "tok")
	if err := c.CleanupApp(context.Background(), testCfg, "obj-1"); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("cleanup must refuse an unmarked application, got %v", err)
	}
	if err := c.CleanupGroup(context.Background(), testCfg, "g-1"); !errors.Is(err, ErrNotOwned) {
		t.Fatalf("cleanup must refuse an unmarked group, got %v", err)
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "DELETE") {
			t.Fatalf("nothing may be deleted without a verified marker: %v", f.calls)
		}
	}
}

func TestCleanupDeletesMarked(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications/obj-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, desiredApp())
		},
		"DELETE /v1.0/applications/obj-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(204, nil)
		},
		"GET /v1.0/groups/g-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"id": "g-1", "displayName": "Guacamole Operators", "description": testMarker})
		},
		"DELETE /v1.0/groups/g-1": func(t *testing.T, r *http.Request) *http.Response {
			return jsonResp(204, nil)
		},
		"GET /v1.0/applications/gone": func(t *testing.T, r *http.Request) *http.Response {
			return graphErr(404, "Request_ResourceNotFound", "Resource not found.")
		},
	}}
	c := newClient(f, "tok")
	if err := c.CleanupApp(context.Background(), testCfg, "obj-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.CleanupGroup(context.Background(), testCfg, "g-1"); err != nil {
		t.Fatal(err)
	}
	if f.count("DELETE /v1.0/applications/obj-1") != 1 || f.count("DELETE /v1.0/groups/g-1") != 1 {
		t.Fatalf("marked resources must be deleted: %v", f.calls)
	}
	// Already gone counts as removed.
	if err := c.CleanupApp(context.Background(), testCfg, "gone"); err != nil {
		t.Fatal(err)
	}
}

const sampleMetadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant-1/"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`

func TestVerifyMetadata(t *testing.T) {
	url := MetadataURL("tenant-1", "app-1")
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /tenant-1/federationmetadata/2007-06/federationmetadata.xml": func(t *testing.T, r *http.Request) *http.Response {
			if r.Header.Get("Authorization") != "" {
				t.Fatal("the public metadata fetch must not send the token")
			}
			if r.URL.Query().Get("appid") != "app-1" {
				t.Fatalf("metadata URL must carry the appid: %s", r.URL)
			}
			return rawResp(200, sampleMetadata)
		},
	}}
	entityID, err := newClient(f, "tok").VerifyMetadata(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	if entityID != "https://sts.windows.net/tenant-1/" {
		t.Fatalf("wrong entityID: %s", entityID)
	}
}

func TestVerifyMetadataFailure(t *testing.T) {
	cases := map[string]*http.Response{
		"an error page":  rawResp(404, "Not Found"),
		"not XML":        rawResp(200, "AADSTS700016: application not found"),
		"not SAML":       rawResp(200, "<html><body>sign in</body></html>"),
		"empty entityID": rawResp(200, `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`),
	}
	for name, resp := range cases {
		f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
			"GET /tenant-1/federationmetadata/2007-06/federationmetadata.xml": func(t *testing.T, r *http.Request) *http.Response {
				return resp
			},
		}}
		if _, err := newClient(f, "tok").VerifyMetadata(context.Background(), MetadataURL("tenant-1", "app-1")); err == nil {
			t.Fatalf("%s must fail verification", name)
		}
	}
}

func TestTokenNeverInErrorsOrDetails(t *testing.T) {
	const secret = "sup3r-secret-token-value"
	deny := func(t *testing.T, r *http.Request) *http.Response {
		return graphErr(403, "Authorization_RequestDenied", "Insufficient privileges.")
	}
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications":       deny,
		"GET /v1.0/organization":       deny,
		"GET /v1.0/applications/obj-1": deny,
	}}
	c := newClient(f, secret)
	ctx := context.Background()

	var outputs []string
	p, err := c.CheckPermissions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, p.ReadDetail, p.MutationDetail)
	if _, err := c.Plan(ctx, testCfg); err != nil {
		outputs = append(outputs, err.Error())
	}
	if _, err := c.Apply(ctx, &Plan{Config: testCfg}); err != nil {
		outputs = append(outputs, err.Error())
	}
	if err := c.CleanupApp(ctx, testCfg, "obj-1"); err != nil {
		outputs = append(outputs, err.Error())
	}
	if len(outputs) < 5 {
		t.Fatalf("expected every call to fail and report: %q", outputs)
	}
	for _, s := range outputs {
		if strings.Contains(s, secret) {
			t.Fatalf("token leaked: %q", s)
		}
	}
}

// TestTenantIDComesFromTheTokenClaim keeps the tool from demanding a
// permission it does not need. The tenant ID is in the token's own `tid`
// claim, so reading it there means an operator never has to grant
// Organization.Read.All just to let the tool learn its own tenant.
func TestTenantIDComesFromTheTokenClaim(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"tid":"3e1d3820-e8e4-467c-b404-8e9fe76e0d92","roles":["Application.ReadWrite.All"]}`))
	tok := "header." + payload + ".signature"

	got, ok := tokenTenantID(tok)
	if !ok || got != "3e1d3820-e8e4-467c-b404-8e9fe76e0d92" {
		t.Fatalf("tokenTenantID = %q, %v", got, ok)
	}
	// An opaque token has no claim to read; the caller falls back.
	if _, ok := tokenTenantID("opaque-token"); ok {
		t.Fatal("an opaque token must not yield a tenant ID")
	}
	// The permission that only existed for this lookup is no longer demanded.
	for _, p := range RequiredPermissions {
		if p == "Organization.Read.All" {
			t.Fatal("Organization.Read.All is still required even though the tenant ID comes from the token")
		}
	}
}
