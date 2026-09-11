package entra

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	testAppObjectID = "11111111-1111-1111-1111-111111111111"
	testSPObjectID  = "22222222-2222-2222-2222-222222222222"
	testAppID       = "33333333-3333-3333-3333-333333333333"
)

func newAccessor(f *fake) SettingAccessor {
	return SettingAccessor{Client: newClient(f, "test-token")}
}

// spRoutes answers the appId lookup and the service principal lookup that a
// servicePrincipal target recorded against an application object ID needs.
func spRoutes(sp map[string]any) map[string]func(*testing.T, *http.Request) *http.Response {
	return map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications/" + testAppObjectID: func(_ *testing.T, _ *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"appId": testAppID})
		},
		"GET /v1.0/servicePrincipals": func(_ *testing.T, _ *http.Request) *http.Response {
			return jsonResp(200, map[string]any{"value": []map[string]any{
				{"id": testSPObjectID, "preferredSingleSignOnMode": sp["preferredSingleSignOnMode"],
					"appRoleAssignmentRequired": sp["appRoleAssignmentRequired"]},
			}})
		},
	}
}

func TestSettingAccessorGetNestedApplicationField(t *testing.T) {
	var gotQuery string
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications/" + testAppObjectID: func(_ *testing.T, req *http.Request) *http.Response {
			gotQuery = req.URL.RawQuery
			return jsonResp(200, map[string]any{
				"web": map[string]any{"redirectUris": []string{"https://old.example/"}},
			})
		},
	}}
	got, err := newAccessor(f).Get(context.Background(),
		"application/"+testAppObjectID+"/application.web.redirectUris")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `["https://old.example/"]` {
		t.Fatalf("the nested value must be returned, got %s", got)
	}
	if !strings.Contains(gotQuery, "select=web") {
		t.Errorf("the read must $select only the property it needs, got %q", gotQuery)
	}
}

// A property Graph does not return is unset, which is JSON null, not an
// error: an application with no identifier URIs must still be comparable.
func TestSettingAccessorGetAbsentPropertyIsNull(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"GET /v1.0/applications/" + testAppObjectID: func(_ *testing.T, _ *http.Request) *http.Response {
			return jsonResp(200, map[string]any{})
		},
	}}
	got, err := newAccessor(f).Get(context.Background(),
		"application/"+testAppObjectID+"/application.identifierUris")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "null" {
		t.Fatalf("an absent property reads as null, got %s", got)
	}
}

// The session records service principal fields against the application
// object ID. The accessor must resolve the service principal through the
// appId, which is the only link between the two.
func TestSettingAccessorGetServicePrincipalFieldViaApplication(t *testing.T) {
	routes := spRoutes(map[string]any{"preferredSingleSignOnMode": "saml", "appRoleAssignmentRequired": true})
	routes["GET /v1.0/servicePrincipals/"+testSPObjectID] = func(_ *testing.T, _ *http.Request) *http.Response {
		return jsonResp(200, map[string]any{"preferredSingleSignOnMode": "saml"})
	}
	f := &fake{t: t, routes: routes}
	got, err := newAccessor(f).Get(context.Background(),
		"application/"+testAppObjectID+"/servicePrincipal.preferredSingleSignOnMode")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"saml"` {
		t.Fatalf("got %s", got)
	}
}

func TestSettingAccessorSetApplicationFieldPatchBody(t *testing.T) {
	var body map[string]any
	var path string
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"PATCH /v1.0/applications/" + testAppObjectID: func(t *testing.T, req *http.Request) *http.Response {
			path, body = req.URL.Path, readBody(t, req)
			return jsonResp(204, nil)
		},
	}}
	err := newAccessor(f).Set(context.Background(),
		"application/"+testAppObjectID+"/application.web.redirectUris",
		json.RawMessage(`["https://old.example/"]`))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1.0/applications/"+testAppObjectID {
		t.Fatalf("wrong resource patched: %s", path)
	}
	web, ok := body["web"].(map[string]any)
	if !ok {
		t.Fatalf("redirectUris must be nested under web, got %v", body)
	}
	uris, ok := web["redirectUris"].([]any)
	if !ok || len(uris) != 1 || uris[0] != "https://old.example/" {
		t.Fatalf("the recorded original must be sent verbatim, got %v", web)
	}
	if len(body) != 1 {
		t.Fatalf("only the restored field may be patched, got %v", body)
	}
}

// A recorded null for a collection is Graph's way of saying "unset". Graph
// rejects null on a write, so the restore must send the empty collection.
func TestSettingAccessorSetNullCollectionBecomesEmpty(t *testing.T) {
	var body map[string]any
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"PATCH /v1.0/applications/" + testAppObjectID: func(t *testing.T, req *http.Request) *http.Response {
			body = readBody(t, req)
			return jsonResp(204, nil)
		},
	}}
	err := newAccessor(f).Set(context.Background(),
		"application/"+testAppObjectID+"/application.optionalClaims.saml2Token",
		json.RawMessage(`null`))
	if err != nil {
		t.Fatal(err)
	}
	oc, ok := body["optionalClaims"].(map[string]any)
	if !ok {
		t.Fatalf("saml2Token must be nested under optionalClaims, got %v", body)
	}
	claims, ok := oc["saml2Token"].([]any)
	if !ok || len(claims) != 0 {
		t.Fatalf("a recorded null must restore as the empty collection, got %v", oc["saml2Token"])
	}
}

// preferredSingleSignOnMode is a nullable string. It was recorded as "" by
// the Go zero value, and Graph will not accept that on a write.
func TestSettingAccessorSetEmptyStringBecomesNull(t *testing.T) {
	var body map[string]any
	var path string
	routes := spRoutes(map[string]any{"preferredSingleSignOnMode": "saml", "appRoleAssignmentRequired": true})
	routes["PATCH /v1.0/servicePrincipals/"+testSPObjectID] = func(t *testing.T, req *http.Request) *http.Response {
		path, body = req.URL.Path, readBody(t, req)
		return jsonResp(204, nil)
	}
	f := &fake{t: t, routes: routes}

	err := newAccessor(f).Set(context.Background(),
		"application/"+testAppObjectID+"/servicePrincipal.preferredSingleSignOnMode",
		json.RawMessage(`""`))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1.0/servicePrincipals/"+testSPObjectID {
		t.Fatalf("the service principal must be patched, not the application: %s", path)
	}
	v, ok := body["preferredSingleSignOnMode"]
	if !ok || v != nil {
		t.Fatalf("an empty nullable string must be sent as null, got %#v", body)
	}
}

func TestSettingAccessorSetServicePrincipalBoolean(t *testing.T) {
	var body map[string]any
	routes := spRoutes(map[string]any{"preferredSingleSignOnMode": "saml", "appRoleAssignmentRequired": true})
	routes["PATCH /v1.0/servicePrincipals/"+testSPObjectID] = func(t *testing.T, req *http.Request) *http.Response {
		body = readBody(t, req)
		return jsonResp(204, nil)
	}
	f := &fake{t: t, routes: routes}

	err := newAccessor(f).Set(context.Background(),
		"servicePrincipal/"+testSPObjectID+"/servicePrincipal.appRoleAssignmentRequired",
		json.RawMessage(`false`))
	if err != nil {
		t.Fatal(err)
	}
	if body["appRoleAssignmentRequired"] != false {
		t.Fatalf("the recorded original must be sent, got %v", body)
	}
	// A direct service principal target needs no appId lookup.
	if f.count("GET /v1.0/applications/"+testAppObjectID) != 0 {
		t.Errorf("a servicePrincipal target must not read the application: %v", f.calls)
	}
}

// An unmapped field is refused before any request goes out, rather than
// guessed at: writing the wrong Graph property would be worse than stopping.
func TestSettingAccessorRefusesUnknownField(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{}}
	a := newAccessor(f)
	target := "application/" + testAppObjectID + "/application.signInAudience"

	if _, err := a.Get(context.Background(), target); err == nil {
		t.Fatal("an unmapped field must not be read")
	}
	if err := a.Set(context.Background(), target, json.RawMessage(`"AzureADMyOrg"`)); err == nil {
		t.Fatal("an unmapped field must not be written")
	}
	if len(f.calls) != 0 {
		t.Fatalf("nothing may be sent for an unmapped field: %v", f.calls)
	}
}

func TestSettingAccessorRefusesMismatchedTarget(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{}}
	a := newAccessor(f)

	// An application field recorded against a service principal object.
	err := a.Set(context.Background(),
		"servicePrincipal/"+testSPObjectID+"/application.identifierUris",
		json.RawMessage(`[]`))
	if err == nil || !strings.Contains(err.Error(), "application field") {
		t.Fatalf("a mismatched target must be refused clearly, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("nothing may be sent: %v", f.calls)
	}
}

func TestSettingAccessorRefusesMalformedTarget(t *testing.T) {
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{}}
	if _, err := newAccessor(f).Get(context.Background(), "application.identifierUris"); err == nil {
		t.Fatal("a target without <kind>/<objectID>/<field> must be refused")
	}
}

// Errors from a restore must never carry the bearer token.
func TestSettingAccessorErrorsHoldNoToken(t *testing.T) {
	const token = "eyJ-secret-bearer-token"
	f := &fake{t: t, routes: map[string]func(*testing.T, *http.Request) *http.Response{
		"PATCH /v1.0/applications/" + testAppObjectID: func(_ *testing.T, _ *http.Request) *http.Response {
			return graphErr(403, "Authorization_RequestDenied", "Insufficient privileges")
		},
	}}
	a := SettingAccessor{Client: newClient(f, token)}
	err := a.Set(context.Background(),
		"application/"+testAppObjectID+"/application.groupMembershipClaims",
		json.RawMessage(`"SecurityGroup"`))
	if err == nil {
		t.Fatal("a 403 must surface")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("the token must never reach an error: %v", err)
	}
}
