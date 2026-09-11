package azure

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
)

// testToken is the sentinel every fake token source returns. No test may ever
// find it in an error, a rendered report, or a file on disk.
const testToken = "SENTINEL-ACCESS-TOKEN-must-never-appear"

const (
	testSub        = "11111111-2222-3333-4444-555555555555"
	testAccountID  = "/subscriptions/" + testSub + "/resourceGroups/rg-backups/providers/Microsoft.Storage/storageAccounts/acctbackups"
	testDeployment = "deadbeefdeadbeefdeadbeefdeadbeef"
)

func testTokens(ctx context.Context, scope string) (string, error) { return testToken, nil }

func testDestination() Destination {
	return Destination{
		SubscriptionID: testSub,
		ResourceGroup:  "rg-backups",
		Account:        "acctbackups",
		Container:      "guacdeploy",
		AccountID:      testAccountID,
		BlobEndpoint:   "https://acctbackups.blob.core.windows.net",
	}
}

// --- HTTP fake -------------------------------------------------------------

func httpResponse(status int, body string, hdr http.Header) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{
		StatusCode:    status,
		Header:        hdr,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// blobStore is an in-memory stand-in for one container. It behaves like the
// Blob service for the handful of operations this package uses, and carries
// the knobs the completeness tests need.
type blobStore struct {
	t *testing.T

	blobs map[string]storedBlob
	calls []string // "METHOD path" of every data-plane request

	// Knobs.
	denyList   bool            // List Blobs returns 403
	denyPut    bool            // every Put Blob returns 403
	denyHead   bool            // Get Blob Properties returns 403
	failPut    map[string]bool // these blob names fail to write
	truncate   map[string]int  // store only this many bytes of these blobs
	corruptMD5 map[string]bool // report a different Content-MD5 on read-back
	omitMD5    map[string]bool // report no Content-MD5 at all, as a blob written in blocks does
	denyDelete bool
}

type storedBlob struct {
	content []byte
	md5     string
	meta    map[string]string
}

func newBlobStore(t *testing.T) *blobStore {
	return &blobStore{t: t, blobs: map[string]storedBlob{},
		failPut: map[string]bool{}, truncate: map[string]int{},
		corruptMD5: map[string]bool{}, omitMD5: map[string]bool{}}
}

// blobName extracts the blob name from a data-plane URL: the path after the
// container segment.
func blobName(u string) string {
	i := strings.Index(u, ".blob.core.windows.net/")
	if i < 0 {
		return ""
	}
	rest := u[i+len(".blob.core.windows.net/"):]
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		rest = rest[:q]
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	name, err := unescapeBlobPath(parts[1])
	if err != nil {
		return parts[1]
	}
	return name
}

func unescapeBlobPath(p string) (string, error) {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		v, err := decodePathSegment(s)
		if err != nil {
			return "", err
		}
		segs[i] = v
	}
	return strings.Join(segs, "/"), nil
}

func decodePathSegment(s string) (string, error) {
	// url.PathUnescape without importing net/url twice over; the names used
	// here contain no escapes, so this is a straight pass-through guard.
	if strings.ContainsRune(s, '%') {
		return "", fmt.Errorf("unexpected escape in %q", s)
	}
	return s, nil
}

func (s *blobStore) serve(req *http.Request) (*http.Response, error) {
	raw := req.URL.String()
	s.calls = append(s.calls, req.Method+" "+req.URL.Path)

	if req.Header.Get("x-ms-version") != BlobAPIVersion {
		s.t.Errorf("blob request %s %s is missing x-ms-version %s (got %q)",
			req.Method, req.URL.Path, BlobAPIVersion, req.Header.Get("x-ms-version"))
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+testToken {
		s.t.Errorf("blob request %s %s has Authorization %q", req.Method, req.URL.Path, got)
	}

	if req.URL.RawQuery != "" && strings.Contains(req.URL.RawQuery, "comp=list") {
		return s.list(req)
	}
	name := blobName(raw)
	switch req.Method {
	case http.MethodPut:
		return s.put(req, name)
	case http.MethodHead:
		return s.head(name)
	case http.MethodGet:
		return s.get(name)
	case http.MethodDelete:
		return s.del(name)
	}
	return httpResponse(http.StatusMethodNotAllowed, "", nil), nil
}

func (s *blobStore) list(req *http.Request) (*http.Response, error) {
	if s.denyList {
		return httpResponse(http.StatusForbidden,
			`<?xml version="1.0"?><Error><Code>AuthorizationPermissionMismatch</Code><Message>This request is not authorized to perform this operation using this permission.</Message></Error>`,
			http.Header{"X-Ms-Error-Code": {"AuthorizationPermissionMismatch"}}), nil
	}
	prefix := req.URL.Query().Get("prefix")
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for name, blob := range s.blobs {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		fmt.Fprintf(&b, `<Blob><Name>%s</Name><Properties><Content-Length>%d</Content-Length><Content-MD5>%s</Content-MD5></Properties></Blob>`,
			name, len(blob.content), blob.md5)
	}
	b.WriteString(`</Blobs></EnumerationResults>`)
	return httpResponse(http.StatusOK, b.String(), nil), nil
}

func (s *blobStore) put(req *http.Request, name string) (*http.Response, error) {
	if s.denyPut || s.failPut[name] {
		return httpResponse(http.StatusForbidden,
			`<?xml version="1.0"?><Error><Code>AuthorizationPermissionMismatch</Code><Message>This request is not authorized to perform this operation using this permission.</Message></Error>`,
			http.Header{"X-Ms-Error-Code": {"AuthorizationPermissionMismatch"}}), nil
	}
	body, _ := io.ReadAll(req.Body)
	sent := req.Header.Get("Content-MD5")
	if sent == "" {
		s.t.Errorf("Put Blob for %s sent no Content-MD5; a truncated body would not be detected", name)
	}
	if want := md5Base64(body); sent != want {
		// Exactly what the service does: reject a body that does not match.
		return httpResponse(http.StatusBadRequest,
			`<?xml version="1.0"?><Error><Code>Md5Mismatch</Code><Message>The MD5 value specified in the request did not match with the MD5 value calculated by the server.</Message></Error>`,
			http.Header{"X-Ms-Error-Code": {"Md5Mismatch"}}), nil
	}
	if req.Header.Get("x-ms-blob-type") != "BlockBlob" {
		s.t.Errorf("Put Blob for %s did not set x-ms-blob-type", name)
	}
	stored := body
	if n, ok := s.truncate[name]; ok && n < len(body) {
		stored = body[:n]
	}
	meta := map[string]string{}
	for k, v := range req.Header {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-ms-meta-") {
			meta[strings.TrimPrefix(lk, "x-ms-meta-")] = v[0]
		}
	}
	s.blobs[name] = storedBlob{content: stored, md5: md5Base64(stored), meta: meta}
	return httpResponse(http.StatusCreated, "", nil), nil
}

func (s *blobStore) head(name string) (*http.Response, error) {
	if s.denyHead {
		return httpResponse(http.StatusForbidden, "", http.Header{"X-Ms-Error-Code": {"AuthorizationPermissionMismatch"}}), nil
	}
	blob, ok := s.blobs[name]
	if !ok {
		return httpResponse(http.StatusNotFound, "", http.Header{"X-Ms-Error-Code": {"BlobNotFound"}}), nil
	}
	hdr := http.Header{
		"Content-Length": {fmt.Sprint(len(blob.content))},
		"Content-Md5":    {blob.md5},
		"Last-Modified":  {time.Now().UTC().Format(http.TimeFormat)},
	}
	if s.corruptMD5[name] {
		hdr.Set("Content-Md5", md5Base64([]byte("something else entirely")))
	}
	if s.omitMD5[name] {
		hdr.Del("Content-Md5")
	}
	for k, v := range blob.meta {
		hdr.Set("x-ms-meta-"+k, v)
	}
	r := httpResponse(http.StatusOK, "", hdr)
	r.ContentLength = int64(len(blob.content))
	return r, nil
}

func (s *blobStore) get(name string) (*http.Response, error) {
	blob, ok := s.blobs[name]
	if !ok {
		return httpResponse(http.StatusNotFound,
			`<?xml version="1.0"?><Error><Code>BlobNotFound</Code><Message>The specified blob does not exist.</Message></Error>`,
			http.Header{"X-Ms-Error-Code": {"BlobNotFound"}}), nil
	}
	return httpResponse(http.StatusOK, string(blob.content), nil), nil
}

func (s *blobStore) del(name string) (*http.Response, error) {
	if s.denyDelete {
		return httpResponse(http.StatusForbidden, "", http.Header{"X-Ms-Error-Code": {"AuthorizationPermissionMismatch"}}), nil
	}
	if _, ok := s.blobs[name]; !ok {
		return httpResponse(http.StatusNotFound, "", http.Header{"X-Ms-Error-Code": {"BlobNotFound"}}), nil
	}
	delete(s.blobs, name)
	return httpResponse(http.StatusAccepted, "", nil), nil
}

// armReply is one canned management-plane answer. It is stored as data, not
// as a built *http.Response, because a response body can only be read once
// and a route is hit more than once in these tests.
type armReply struct {
	status int
	body   string
}

func armOK(body string) armReply { return armReply{http.StatusOK, body} }

func armForbidden(what string) armReply {
	return armReply{http.StatusForbidden,
		`{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization to perform action over ` + what + `."}}`}
}

// armResponder answers management-plane calls from a path-fragment table.
type armResponder struct {
	t     *testing.T
	table map[string]armReply // matched by "contains"
	calls []string
}

func (a *armResponder) serve(req *http.Request) (*http.Response, error) {
	a.calls = append(a.calls, req.Method+" "+req.URL.Path)
	if got := req.Header.Get("Authorization"); got != "Bearer "+testToken {
		a.t.Errorf("management request %s has Authorization %q", req.URL.Path, got)
	}
	for frag, reply := range a.table {
		if strings.Contains(req.URL.Path+"?"+req.URL.RawQuery, frag) {
			return httpResponse(reply.status, reply.body, nil), nil
		}
	}
	return httpResponse(http.StatusNotFound, `{"error":{"code":"NotFound","message":"no fake route"}}`, nil), nil
}

// newClient wires a client whose requests go to the ARM table or the blob
// store, by host.
func newClient(arm *armResponder, blobs *blobStore) *Client {
	return &Client{Token: testTokens, Do: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "management.azure.com") {
			if arm == nil {
				return httpResponse(http.StatusNotFound, `{"error":{"code":"NotFound"}}`, nil), nil
			}
			return arm.serve(req)
		}
		if blobs == nil {
			return httpResponse(http.StatusNotFound, "", nil), nil
		}
		return blobs.serve(req)
	}}
}

// --- local published files -------------------------------------------------

// publishLocal writes a file and the completion manifest internal/backup
// publishes beside it, so the uploader sees exactly what a real run produces.
func publishLocal(t *testing.T, dir, name string, content []byte, deploymentID string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	m := backup.Manifest{
		ManifestVersion: backup.ManifestVersion, FormatVersion: backup.FormatVersion,
		DeploymentID: deploymentID, File: name, Bytes: int64(len(content)),
		SHA256: hex.EncodeToString(sum[:]), Mode: "age", PublishedAt: time.Now().UTC(),
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup.ManifestPath(dir, name), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func md5B64(b []byte) string {
	sum := md5.Sum(b)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// --- discovery and selection ----------------------------------------------

func subscriptionsReply() armReply {
	return armOK(`{"value":[
		{"subscriptionId":"` + testSub + `","displayName":"Production","state":"Enabled"},
		{"subscriptionId":"99999999-0000-0000-0000-000000000000","displayName":"Sandbox","state":"Enabled"}]}`)
}

func accountsReply() armReply {
	return armOK(`{"value":[
		{"id":"` + testAccountID + `","name":"acctbackups","location":"australiaeast",
		 "properties":{"primaryEndpoints":{"blob":"https://acctbackups.blob.core.windows.net/"}}},
		{"id":"/subscriptions/` + testSub + `/resourceGroups/other/providers/Microsoft.Storage/storageAccounts/acctother",
		 "name":"acctother","location":"australiaeast",
		 "properties":{"primaryEndpoints":{"blob":"https://acctother.blob.core.windows.net/"}}}]}`)
}

func containersReply(names ...string) armReply {
	var items []string
	for _, n := range names {
		items = append(items, `{"name":"`+n+`"}`)
	}
	return armOK(`{"value":[` + strings.Join(items, ",") + `]}`)
}

func TestSubscriptionsAndStorageAccountsAreListed(t *testing.T) {
	arm := &armResponder{t: t, table: map[string]armReply{
		"/subscriptions?":             subscriptionsReply(),
		"storageAccounts?api-version": accountsReply(),
	}}
	c := newClient(arm, nil)

	subs, err := c.Subscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 || subs[0].ID != testSub || subs[0].Name != "Production" {
		t.Fatalf("subscriptions = %+v", subs)
	}

	accounts, err := c.StorageAccounts(context.Background(), testSub)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 2 || accounts[0].Name != "acctbackups" {
		t.Fatalf("accounts = %+v", accounts)
	}
	if got := accounts[0].ResourceGroup(); got != "rg-backups" {
		t.Fatalf("resource group = %q, want rg-backups", got)
	}
}

func TestResolveSelectsExistingAccountAndContainer(t *testing.T) {
	arm := &armResponder{t: t, table: map[string]armReply{
		"/blobServices/default/containers": containersReply("guacdeploy", "other"),
		"storageAccounts?api-version":      accountsReply(),
	}}
	c := newClient(arm, nil)

	d, err := c.Resolve(context.Background(), testSub, "ACCTBACKUPS", "guacdeploy")
	if err != nil {
		t.Fatal(err)
	}
	if d.Account != "acctbackups" || d.Container != "guacdeploy" {
		t.Fatalf("destination = %+v", d)
	}
	if d.AccountID != testAccountID {
		t.Fatalf("account ID = %q", d.AccountID)
	}
	if d.ResourceGroup != "rg-backups" {
		t.Fatalf("resource group = %q", d.ResourceGroup)
	}
	if d.BlobEndpoint != "https://acctbackups.blob.core.windows.net" {
		t.Fatalf("blob endpoint = %q", d.BlobEndpoint)
	}
	if !d.Configured() {
		t.Fatal("a resolved destination reports itself unconfigured")
	}
	if got := d.Prefix(testDeployment); got != "guacdeploy/"+testDeployment+"/" {
		t.Fatalf("prefix = %q", got)
	}
}

func TestResolveRefusesMissingAccountAndContainerWithoutCreatingAnything(t *testing.T) {
	arm := &armResponder{t: t, table: map[string]armReply{
		"/blobServices/default/containers": containersReply("somethingelse"),
		"storageAccounts?api-version":      accountsReply(),
	}}
	c := newClient(arm, nil)

	_, err := c.Resolve(context.Background(), testSub, "no-such-account", "guacdeploy")
	if err == nil || !strings.Contains(err.Error(), "does not create storage accounts") {
		t.Fatalf("missing account error = %v", err)
	}
	if !strings.Contains(err.Error(), "acctbackups") {
		t.Fatalf("the error should name the accounts that do exist: %v", err)
	}

	_, err = c.Resolve(context.Background(), testSub, "acctbackups", "no-such-container")
	if err == nil || !strings.Contains(err.Error(), "does not create containers") {
		t.Fatalf("missing container error = %v", err)
	}
	if !strings.Contains(err.Error(), "somethingelse") {
		t.Fatalf("the error should name the containers that do exist: %v", err)
	}

	for _, call := range arm.calls {
		if !strings.HasPrefix(call, "GET ") {
			t.Fatalf("selection made a non-GET management call: %s", call)
		}
	}
}

// --- permission checks -----------------------------------------------------

func permissionsReply(actions, notActions []string) armReply {
	q := func(ss []string) string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, `"`+s+`"`)
		}
		return strings.Join(out, ",")
	}
	return armOK(`{"value":[{"actions":[` + q(actions) + `],"notActions":[` + q(notActions) + `],"dataActions":[],"notDataActions":[]}]}`)
}

// armForChecks answers the account GET and the effective-permissions GET.
func armForChecks(t *testing.T, account, permissions armReply) *armResponder {
	return &armResponder{t: t, table: map[string]armReply{
		"Microsoft.Authorization/permissions": permissions,
		"storageAccounts/acctbackups?":        account,
	}}
}

func TestPermissionChecksAllPass(t *testing.T) {
	arm := armForChecks(t, armOK(`{"id":"`+testAccountID+`","name":"acctbackups"}`),
		permissionsReply([]string{"Microsoft.Authorization/*"}, nil))
	blobs := newBlobStore(t)
	c := newClient(arm, blobs)

	p, err := c.CheckPermissions(context.Background(), testDestination(), testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Management.OK || !p.BlobData.OK || !p.RoleAssignment.OK {
		t.Fatalf("checks = %+v", p)
	}
	if err := p.Err(); err != nil {
		t.Fatalf("Err() = %v", err)
	}
	if len(blobs.blobs) != 0 {
		t.Fatalf("the write probe was left behind: %v", blobs.blobs)
	}
}

// TestManagementDeniedIsReportedAlone is the case the specification calls out:
// the checks are separate, so a management failure must not be reported as a
// blob-access failure, and must not hide a working blob path.
func TestManagementDeniedIsReportedAlone(t *testing.T) {
	arm := armForChecks(t, armForbidden("Microsoft.Storage/storageAccounts/read"),
		permissionsReply([]string{"Microsoft.Authorization/roleAssignments/write"}, nil))
	c := newClient(arm, newBlobStore(t))

	p, err := c.CheckPermissions(context.Background(), testDestination(), testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if p.Management.OK {
		t.Fatal("management check passed although the account read was denied")
	}
	if !p.BlobData.OK {
		t.Fatalf("blob data check failed although blobs were readable and writable: %s", p.BlobData.Detail)
	}
	if !p.RoleAssignment.OK {
		t.Fatalf("role assignment check failed although the action is granted: %s", p.RoleAssignment.Detail)
	}
	if !strings.Contains(p.Management.Fix, "Reader") || !strings.Contains(p.Management.Fix, "acctbackups") {
		t.Fatalf("management fix is not actionable: %q", p.Management.Fix)
	}
}

// TestBlobWriteDeniedIsReportedSpecifically is the operator the issue names:
// they can see the account and list blobs, and cannot write one. They must be
// told that, and told the role, not given a generic failure.
func TestBlobWriteDeniedIsReportedSpecifically(t *testing.T) {
	arm := armForChecks(t, armOK(`{"name":"acctbackups"}`),
		permissionsReply([]string{"Microsoft.Authorization/roleAssignments/write"}, nil))
	blobs := newBlobStore(t)
	blobs.denyPut = true
	c := newClient(arm, blobs)

	p, err := c.CheckPermissions(context.Background(), testDestination(), testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Management.OK {
		t.Fatalf("management check failed although the account is readable: %s", p.Management.Detail)
	}
	if p.BlobData.OK {
		t.Fatal("blob data check passed although writing a blob was denied")
	}
	if !strings.Contains(p.BlobData.Detail, "can be listed") || !strings.Contains(p.BlobData.Detail, "writing one failed") {
		t.Fatalf("the detail does not distinguish read from write: %q", p.BlobData.Detail)
	}
	if !strings.Contains(p.BlobData.Fix, "Storage Blob Data Contributor") {
		t.Fatalf("blob fix is not actionable: %q", p.BlobData.Fix)
	}
	if p.OK() {
		t.Fatal("Preflight.OK() is true although blobs cannot be written")
	}
	if err := p.Err(); err == nil || !strings.Contains(err.Error(), "Storage Blob Data Contributor") {
		t.Fatalf("Err() = %v", err)
	}
}

func TestBlobReadDeniedIsReportedSeparatelyFromWrite(t *testing.T) {
	arm := armForChecks(t, armOK(`{"name":"acctbackups"}`),
		permissionsReply(nil, nil))
	blobs := newBlobStore(t)
	blobs.denyList = true
	c := newClient(arm, blobs)

	p, _ := c.CheckPermissions(context.Background(), testDestination(), testDeployment)
	if p.BlobData.OK {
		t.Fatal("blob data check passed although listing was denied")
	}
	if !strings.Contains(p.BlobData.Detail, "cannot be listed") {
		t.Fatalf("detail = %q", p.BlobData.Detail)
	}
	if len(blobs.blobs) != 0 {
		t.Fatal("a write probe was attempted after the read check failed")
	}
}

func TestRoleAssignmentCheckFailsAloneAndDoesNotBlockUploads(t *testing.T) {
	arm := armForChecks(t, armOK(`{"name":"acctbackups"}`),
		permissionsReply([]string{"Microsoft.Storage/*"}, nil))
	c := newClient(arm, newBlobStore(t))

	p, _ := c.CheckPermissions(context.Background(), testDestination(), testDeployment)
	if p.RoleAssignment.OK {
		t.Fatal("role assignment check passed although the action is not granted")
	}
	if !strings.Contains(p.RoleAssignment.Fix, "User Access Administrator") {
		t.Fatalf("role fix is not actionable: %q", p.RoleAssignment.Fix)
	}
	if !p.OK() {
		t.Fatal("a missing role-assignment permission must not block uploads")
	}
	if err := p.Err(); err != nil {
		t.Fatalf("Err() = %v; role assignment is advisory", err)
	}
}

func TestRoleAssignmentDeniedByNotActions(t *testing.T) {
	arm := armForChecks(t, armOK(`{"name":"acctbackups"}`),
		permissionsReply([]string{"*"}, []string{"Microsoft.Authorization/*/Write"}))
	c := newClient(arm, newBlobStore(t))

	p, _ := c.CheckPermissions(context.Background(), testDestination(), testDeployment)
	if p.RoleAssignment.OK {
		t.Fatal("a notActions entry that removes roleAssignments/write was ignored")
	}
}

func TestMatchAction(t *testing.T) {
	cases := []struct {
		pattern, action string
		want            bool
	}{
		{"*", roleAssignmentWrite, true},
		{"Microsoft.Authorization/*", roleAssignmentWrite, true},
		{"microsoft.authorization/roleassignments/write", roleAssignmentWrite, true},
		{"Microsoft.Authorization/*/write", roleAssignmentWrite, true},
		{"Microsoft.Storage/*", roleAssignmentWrite, false},
		{"Microsoft.Authorization/roleAssignments/read", roleAssignmentWrite, false},
		{"Microsoft.Authorization/roleDefinitions/*", roleAssignmentWrite, false},
	}
	for _, c := range cases {
		if got := matchAction(c.pattern, c.action); got != c.want {
			t.Errorf("matchAction(%q, %q) = %v, want %v", c.pattern, c.action, got, c.want)
		}
	}
}

func TestCheckPermissionsNeedsADeploymentID(t *testing.T) {
	c := newClient(nil, nil)
	if _, err := c.CheckPermissions(context.Background(), testDestination(), ""); err == nil {
		t.Fatal("a permission check with no deployment ID was allowed to write a probe")
	}
}

// --- ownership-scoped deletion --------------------------------------------

func TestDeleteRefusesBlobsThisDeploymentDoesNotOwn(t *testing.T) {
	d := testDestination()
	blobs := newBlobStore(t)
	c := newClient(nil, blobs)
	ctx := context.Background()

	mine := d.Prefix(testDeployment) + "db/mine.sql.age"
	theirs := d.Prefix("0000other0000") + "db/theirs.sql.age"
	unmarked := d.Prefix(testDeployment) + "db/unmarked.sql.age"

	body := []byte("x")
	if err := c.PutBlob(ctx, d, mine, body, md5B64(body), map[string]string{ownerMetadata: testDeployment}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutBlob(ctx, d, theirs, body, md5B64(body), map[string]string{ownerMetadata: "0000other0000"}); err != nil {
		t.Fatal(err)
	}
	if err := c.PutBlob(ctx, d, unmarked, body, md5B64(body), nil); err != nil {
		t.Fatal(err)
	}

	// Another deployment's object: outside our prefix, so it is refused
	// before a single request is made about it.
	err := c.DeleteOwnedBlob(ctx, d, theirs, testDeployment)
	if err == nil || !strings.Contains(err.Error(), "outside this deployment's prefix") {
		t.Fatalf("deleting another deployment's blob = %v", err)
	}
	// An unmarked object inside our prefix: the marker is read back and does
	// not match, so it stays.
	err = c.DeleteOwnedBlob(ctx, d, unmarked, testDeployment)
	if err == nil || !strings.Contains(err.Error(), ErrNotOwned.Error()) {
		t.Fatalf("deleting an unmarked blob = %v", err)
	}
	if len(blobs.blobs) != 3 {
		t.Fatalf("a refused deletion removed something: %v", blobs.blobs)
	}
	// Our own, marked object: removed.
	if err := c.DeleteOwnedBlob(ctx, d, mine, testDeployment); err != nil {
		t.Fatal(err)
	}
	if _, ok := blobs.blobs[mine]; ok {
		t.Fatal("our own marked blob was not deleted")
	}
	if _, ok := blobs.blobs[theirs]; !ok {
		t.Fatal("another deployment's blob disappeared")
	}
}

func TestDeleteNeedsADeploymentID(t *testing.T) {
	c := newClient(nil, newBlobStore(t))
	err := c.deleteBlob(context.Background(), testDestination(), "guacdeploy//db/x", "")
	if err == nil || !strings.Contains(err.Error(), "deployment ID") {
		t.Fatalf("deleteBlob with no deployment ID = %v", err)
	}
}

// --- structural guarantees -------------------------------------------------

// packageFuncsUsing returns the names of the functions in this package whose
// bodies mention the given selector, e.g. http.MethodDelete.
func packageFuncsUsing(t *testing.T, pkg, sel string) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, p := range pkgs {
		for _, file := range p.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch e := n.(type) {
					case *ast.SelectorExpr:
						if id, ok := e.X.(*ast.Ident); ok && id.Name == pkg && e.Sel.Name == sel {
							found = append(found, fn.Name.Name)
						}
					case *ast.Ident:
						if pkg == "" && e.Name == sel {
							found = append(found, fn.Name.Name)
						}
					}
					return true
				})
				return true
			})
		}
	}
	return found
}

// TestNoContainerOrAccountDeletionPathExists is a structural guarantee, not a
// behaviour test. "Preserve remote backups and their supporting storage
// resources during ordinary teardown" (specification) cannot be proved by
// exercising an operation that must not exist, so the package source is
// checked instead: exactly one function issues a DELETE and it deletes a blob,
// and the management plane is reached through exactly two helpers, one of which
// only reads and the other of which only writes with PUT. So no container and
// no storage account can be removed from here, whether this deployment created
// it or not.
//
// The allow-list grew by one name when issue #18 added creation: armPut. That
// is the point of checking it — adding a management-plane write has to be a
// deliberate, visible change to this test, not something that arrives with a
// feature.
func TestNoContainerOrAccountDeletionPathExists(t *testing.T) {
	deleters := packageFuncsUsing(t, "http", "MethodDelete")
	if len(deleters) != 1 || deleters[0] != "deleteBlob" {
		t.Fatalf("functions issuing DELETE = %v; only deleteBlob may, and it deletes one marker-verified blob", deleters)
	}
	armUsers := packageFuncsUsing(t, "", "armBase")
	sort.Strings(armUsers)
	if len(armUsers) != 2 || armUsers[0] != "armGet" || armUsers[1] != "armPut" {
		t.Fatalf("functions reaching Azure Resource Manager = %v; only the read-only armGet and the PUT-only armPut helpers may", armUsers)
	}
	posters := packageFuncsUsing(t, "http", "MethodPost")
	for _, fn := range posters {
		if fn != "StartSignIn" && fn != "post" {
			t.Fatalf("%s issues a POST; only the sign-in endpoints may", fn)
		}
	}
	for _, file := range sourceFiles(t) {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"DeleteContainer", "deleteContainer", "DeleteAccount", "deleteAccount",
			"DeleteStorageAccount", "deleteStorageAccount", "DeleteResourceGroup", "deleteResourceGroup"} {
			if strings.Contains(string(body), forbidden) {
				t.Fatalf("%s contains %q: deleting a container, a storage account or a resource group is out of scope here, and stays out of scope — it holds backups", file, forbidden)
			}
		}
	}
}

func sourceFiles(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			out = append(out, e.Name())
		}
	}
	return out
}
