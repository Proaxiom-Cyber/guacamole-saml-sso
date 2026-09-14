package entra

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type installerFixture struct {
	t                  *testing.T
	app                *InstallerApplication
	cert               *x509.Certificate
	grants             []map[string]string
	creates, failAt    int
	applyBeforeFailure bool
}

func (f *installerFixture) response(body any) (*http.Response, error) {
	b, _ := json.Marshal(body)
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(b)))}, nil
}
func (f *installerFixture) do(r *http.Request) (*http.Response, error) {
	f.t.Helper()
	path := strings.TrimPrefix(r.URL.Path, "/v1.0")
	var body any
	if r.Method == "GET" {
		switch {
		case path == "/applications":
			list := []any{}
			if f.app != nil {
				list = append(list, f.app)
			}
			body = map[string]any{"value": list}
		case path == "/applications/app-object":
			body = f.app
		case path == "/servicePrincipals/installer-sp":
			body = map[string]any{"id": f.app.SPID, "appId": f.app.AppID, "tags": f.app.Tags}
		case path == "/servicePrincipals" && strings.Contains(r.URL.Query().Get("$filter"), graphAppID):
			roles := []any{}
			for _, v := range append(append([]string{}, RequiredPermissions...), "Organization.Read.All") {
				roles = append(roles, map[string]any{"id": v, "value": v, "isEnabled": true, "allowedMemberTypes": []string{"Application"}})
			}
			body = map[string]any{"value": []any{map[string]any{"id": "graph-sp", "appRoles": roles}}}
		case path == "/servicePrincipals":
			list := []any{}
			if f.app != nil && f.app.SPID != "" {
				list = append(list, map[string]string{"id": f.app.SPID})
			}
			body = map[string]any{"value": list}
		case strings.HasSuffix(path, "/appRoleAssignments"):
			body = map[string]any{"value": f.grants}
		default:
			f.t.Fatalf("unexpected read: %s", r.URL)
		}
		return f.response(body)
	}
	if r.Method != "POST" {
		f.t.Fatalf("unexpected mutation: %s", r.Method)
	}
	f.creates++
	lost := f.failAt == f.creates
	if lost && !f.applyBeforeFailure {
		return nil, io.ErrUnexpectedEOF
	}
	var input map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		f.t.Fatal(err)
	}
	switch path {
	case "/applications":
		b, _ := json.Marshal(input)
		f.app = &InstallerApplication{}
		json.Unmarshal(b, f.app)
		f.app.ID = "app-object"
		f.app.AppID = "app-client"
		body = f.app
	case "/servicePrincipals":
		f.app.SPID = "installer-sp"
		body = map[string]string{"id": f.app.SPID}
	case "/servicePrincipals/graph-sp/appRoleAssignedTo":
		assignment := map[string]string{}
		for _, name := range []string{"appRoleId", "resourceId", "principalId"} {
			var value string
			json.Unmarshal(input[name], &value)
			assignment[name] = value
		}
		f.grants = append(f.grants, assignment)
		body = assignment
	default:
		f.t.Fatalf("unexpected mutation: %s", path)
	}
	if lost {
		return nil, io.ErrUnexpectedEOF
	}
	return f.response(body)
}

func newInstallerFixture(t *testing.T) *installerFixture {
	return &installerFixture{t: t, cert: &x509.Certificate{Raw: []byte("public-certificate-fixture"), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}}
}

func TestInstallerWaitsForNewPrincipalReplication(t *testing.T) {
	old := replicationPoll
	replicationPoll = time.Millisecond
	t.Cleanup(func() { replicationPoll = old })
	for _, operation := range []string{"read grants", "grant permission"} {
		t.Run(operation, func(t *testing.T) {
			f := newInstallerFixture(t)
			attempts := 0
			c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: func(r *http.Request) (*http.Response, error) {
				match := r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/appRoleAssignments")
				if operation == "grant permission" {
					match = r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/appRoleAssignedTo")
				}
				if match {
					attempts++
					if attempts == 1 {
						return rawResp(404, `{"error":{"code":"Request_ResourceNotFound","message":"new principal has not replicated"}}`), nil
					}
				}
				return f.do(r)
			}}
			app, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
			if err != nil {
				t.Fatalf("new principal replication stopped registration: %v", err)
			}
			if attempts < 2 || app.SPID != "installer-sp" || f.creates != 6 || len(f.grants) != 4 {
				t.Fatal("retry lost or duplicated registration work")
			}
		})
	}
}

func TestInstallerDoesNotRetryPermissionDenial(t *testing.T) {
	f := newInstallerFixture(t)
	attempts := 0
	c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/appRoleAssignments") {
			attempts++
			return rawResp(403, `{"error":{"code":"Authorization_RequestDenied","message":"missing permission"}}`), nil
		}
		return f.do(r)
	}}
	_, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
	if err == nil || attempts != 1 || f.creates != 2 || len(f.grants) != 0 {
		t.Fatal("permission denial was retried or ignored")
	}
}

func TestInstallerReplicationWaitHonorsCancellation(t *testing.T) {
	f := newInstallerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/appRoleAssignments") {
			cancel()
			return rawResp(404, `{"error":{"code":"Request_ResourceNotFound","message":"not replicated"}}`), nil
		}
		return f.do(r)
	}}
	_, err := c.EnsureInstaller(ctx, "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
	if !errors.Is(err, context.Canceled) || f.creates != 2 {
		t.Fatalf("cancelled registration continued: %v", err)
	}
}
func TestInstallerRegistrationResumesEveryLostMutation(t *testing.T) {
	for fail := 1; fail <= 6; fail++ {
		t.Run(string(rune('0'+fail)), func(t *testing.T) {
			f := newInstallerFixture(t)
			f.failAt = fail
			f.applyBeforeFailure = true
			c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: f.do}
			pending := ""
			saved := InstallerApplication{}
			checkpoint := func(p string, app InstallerApplication) error { pending = p; saved = app; return nil }
			_, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, saved, pending, checkpoint)
			if !errors.Is(err, ErrUncertain) || pending == "" {
				t.Fatalf("lost response did not retain intent: %v", err)
			}
			f.failAt = 0
			app, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, saved, pending, checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			if f.creates != 6 || len(f.grants) != 4 || app.ID != saved.ID || app.SPID == "" || pending != "" {
				t.Fatalf("resume duplicated or lost work: creates=%d grants=%d pending=%s", f.creates, len(f.grants), pending)
			}
			if f.app.Notes != InstallerMarker("deployment") {
				t.Fatal("ownership was not in create request")
			}
			decoded, _ := base64.StdEncoding.DecodeString(f.app.KeyCredentials[0].Key)
			if string(decoded) != string(f.cert.Raw) {
				t.Fatal("public certificate missing from create request")
			}
		})
	}
}
func TestInstallerNeverRetriesAnUnobservedCreate(t *testing.T) {
	f := newInstallerFixture(t)
	f.failAt = 1
	c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: f.do}
	pending := ""
	save := func(p string, _ InstallerApplication) error { pending = p; return nil }
	c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", save)
	_, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, pending, save)
	if !errors.Is(err, ErrUncertain) || f.creates != 1 {
		t.Fatalf("unobserved create retried: %v, %d", err, f.creates)
	}
}
func TestInstallerRefusesForeignAppAndCertificateDrift(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		t.Run(map[bool]string{true: "foreign ownership", false: "certificate drift"}[foreign], func(t *testing.T) {
			f := newInstallerFixture(t)
			marker := InstallerMarker("deployment")
			if foreign {
				marker = "another-deployment"
			}
			f.app = &InstallerApplication{ID: "app-object", AppID: "app-client", Notes: marker, Tags: []string{marker}}
			c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: f.do}
			_, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
			if !errors.Is(err, ErrRequiresReview) || f.creates != 0 {
				t.Fatalf("modified foreign or changed identity: %v", err)
			}
		})
	}
}

func TestInstallerRecordedIDsSurviveStaleDirectorySearch(t *testing.T) {
	f := newInstallerFixture(t)
	c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: f.do}
	saved, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c.Do = func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && (r.URL.Path == "/v1.0/applications" || (r.URL.Path == "/v1.0/servicePrincipals" && !strings.Contains(r.URL.Query().Get("$filter"), graphAppID))) {
			return rawResp(200, `{"value":[]}`), nil
		}
		return f.do(r)
	}
	again, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, saved, "", func(string, InstallerApplication) error { return nil })
	if err != nil || again.ID != saved.ID || again.SPID != saved.SPID || f.creates != 6 {
		t.Fatalf("stale search lost or duplicated recorded registration: %v (%d writes)", err, f.creates)
	}
}

func TestInstallerRecordedPrincipalCannotBeReplaced(t *testing.T) {
	for _, condition := range []string{"missing", "different app", "different owner"} {
		t.Run(condition, func(t *testing.T) {
			f := newInstallerFixture(t)
			c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: f.do}
			saved, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.Do = func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" && r.URL.Path == "/v1.0/servicePrincipals/installer-sp" {
					if condition == "missing" {
						cancel()
						return rawResp(404, `{"error":{"code":"Request_ResourceNotFound"}}`), nil
					}
					appID, marker := "app-client", InstallerMarker("deployment")
					if condition == "different app" {
						appID = "another-app"
					} else {
						marker = "another-owner"
					}
					return f.response(map[string]any{"id": "installer-sp", "appId": appID, "tags": []string{marker}})
				}
				return f.do(r)
			}
			_, err = c.EnsureInstaller(ctx, "deployment", f.cert, saved, "", func(string, InstallerApplication) error { return nil })
			if err == nil || f.creates != 6 {
				t.Fatalf("recorded principal was replaced or accepted: %v (%d writes)", err, f.creates)
			}
		})
	}
}

func TestInstallerReconcilesConflictingGrantWithoutRepeatingIt(t *testing.T) {
	old := replicationPoll
	replicationPoll = time.Millisecond
	t.Cleanup(func() { replicationPoll = old })
	f := newInstallerFixture(t)
	c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: f.do}
	saved, err := c.EnsureInstaller(context.Background(), "deployment", f.cert, InstallerApplication{}, "", func(string, InstallerApplication) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	reads, conflicts := 0, 0
	c.Do = func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/appRoleAssignments") {
			reads++
			if reads <= 2 {
				return rawResp(200, `{"value":[]}`), nil
			}
		}
		if r.Method == "POST" {
			conflicts++
			return rawResp(400, `{"error":{"code":"Request_MultipleObjectsWithSameKeyValue","message":"EntitlementGrant entry already exists."}}`), nil
		}
		return f.do(r)
	}
	_, err = c.EnsureInstaller(context.Background(), "deployment", f.cert, saved, "", func(string, InstallerApplication) error { return nil })
	if err != nil || conflicts != 4 || f.creates != 6 || reads < 3 {
		t.Fatalf("stale permission listing did not reconcile: %v (conflicts=%d reads=%d)", err, conflicts, reads)
	}
}

func TestInstallerGrantConflictNeedsTheExactPermission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	c := &Client{Token: func(context.Context) (string, error) { return "fixture", nil }, Do: func(r *http.Request) (*http.Response, error) {
		reads++
		cancel()
		return rawResp(200, `{"value":[{"appRoleId":"wanted-role","resourceId":"another-resource"},{"appRoleId":"another-role","resourceId":"wanted-resource"}]}`), nil
	}}
	err := c.waitInstallerGrant(ctx, "principal", "wanted-resource", "wanted-role")
	if !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatalf("accepted a different grant or ignored cancellation: %v", err)
	}
}
