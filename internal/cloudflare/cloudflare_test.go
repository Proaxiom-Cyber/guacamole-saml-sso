package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testAPIToken  = "sekrit-api-token-value"
	connToken     = "sekrit-connector-token-value"
	depID         = "aabbccddeeff00112233445566778899"
	host          = "guac.example.com"
	wantTunnelNam = "guacdeploy-guac.example.com-" + depID
	wantMarker    = "guacdeploy:" + depID
)

// fake is the HTTP seam: an httptest server routing "METHOD /path" to a
// handler that returns a Cloudflare envelope.
type fake struct {
	t        *testing.T
	mux      map[string]http.HandlerFunc
	hits     map[string]int
	server   *httptest.Server
	client   *Client
	lastBody map[string][]byte
}

func newFake(t *testing.T) *fake {
	f := &fake{t: t, mux: map[string]http.HandlerFunc{}, hits: map[string]int{}, lastBody: map[string][]byte{}}
	// Reading the zone is a benign lookup any phase may make to learn the
	// authoritative nameservers; a test that cares routes it itself.
	f.mux["GET /zones/zone1"] = ok(map[string]any{"id": "zone1", "name": "example.com"})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAPIToken {
			t.Errorf("Authorization header = %q", got)
		}
		key := r.Method + " " + r.URL.Path
		h, ok := f.mux[key]
		if !ok {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
			return
		}
		f.hits[key]++
		b, _ := io.ReadAll(r.Body)
		f.lastBody[key] = b
		h(w, r)
	}))
	t.Cleanup(f.server.Close)
	f.client = &Client{
		Base:  f.server.URL,
		Token: func(ctx context.Context) (string, error) { return testAPIToken, nil },
	}
	return f
}

func ok(result any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
	}
}

func fail(status, code int, msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"errors":  []map[string]any{{"code": code, "message": msg}},
			"result":  nil,
		})
	}
}

func (f *fake) prov() *Provisioner {
	return &Provisioner{Client: f.client, AccountID: "acct1", ZoneID: "zone1", Hostname: host, DeploymentID: depID}
}

// noSecret asserts the API token and connector token never leak into errors.
func noSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{testAPIToken, connToken} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks a secret: %v", err)
		}
	}
}

func TestVerifyToken(t *testing.T) {
	f := newFake(t)
	f.mux["GET /user/tokens/verify"] = ok(map[string]string{"id": "tok1", "status": "active"})
	if err := f.client.VerifyToken(context.Background()); err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	f.mux["GET /user/tokens/verify"] = ok(map[string]string{"id": "tok1", "status": "disabled"})
	err := f.client.VerifyToken(context.Background())
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("want disabled-status error, got %v", err)
	}
	noSecret(t, err)

	f.mux["GET /user/tokens/verify"] = fail(401, 1000, "Invalid API Token")
	err = f.client.VerifyToken(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Fatalf("want APIError 401 with message, got %v", err)
	}
	noSecret(t, err)
}

func TestPreflight(t *testing.T) {
	f := newFake(t)
	f.mux["GET /user/tokens/verify"] = ok(map[string]string{"status": "active"})
	f.mux["GET /zones/zone1"] = ok(map[string]string{"id": "zone1"})
	f.mux["GET /zones/zone1/dns_records"] = ok([]any{})
	f.mux["GET /accounts/acct1/cfd_tunnel"] = ok([]any{})
	if err := f.client.Preflight(context.Background(), "acct1", "zone1"); err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	// A missing DNS read scope is reported by name.
	f.mux["GET /zones/zone1/dns_records"] = fail(403, 9109, "Unauthorized to access requested resource")
	err := f.client.Preflight(context.Background(), "acct1", "zone1")
	if err == nil || !strings.Contains(err.Error(), "DNS Read") {
		t.Fatalf("want DNS Read failure, got %v", err)
	}
	noSecret(t, err)
}

func TestZoneSelection(t *testing.T) {
	f := newFake(t)
	f.mux["GET /zones"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "example.com" {
			t.Errorf("zone list name filter = %q", got)
		}
		ok([]map[string]any{{
			"id": "zone1", "name": "example.com", "status": "active",
			"account": map[string]string{"id": "acct1", "name": "Demo Customer"},
		}})(w, r)
	}
	zones, err := f.client.ZonesByName(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ZonesByName: %v", err)
	}
	if len(zones) != 1 || zones[0].ID != "zone1" || zones[0].Account.ID != "acct1" || zones[0].Account.Name != "Demo Customer" {
		t.Fatalf("zones = %+v", zones)
	}

	f.mux["GET /accounts"] = ok([]map[string]string{{"id": "acct1", "name": "Demo Customer"}})
	accts, err := f.client.Accounts(context.Background())
	if err != nil || len(accts) != 1 || accts[0].ID != "acct1" {
		t.Fatalf("Accounts = %+v, %v", accts, err)
	}
}

func TestTunnelAndDNSHappyPath(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	f.mux["GET /accounts/acct1/cfd_tunnel"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("include_prefix"); got != "guacdeploy-"+host+"-" {
			t.Errorf("tunnel list include_prefix = %q", got)
		}
		if got := r.URL.Query().Get("is_deleted"); got != "false" {
			t.Errorf("tunnel list is_deleted = %q", got)
		}
		ok([]any{})(w, r)
	}
	f.mux["POST /accounts/acct1/cfd_tunnel"] = ok(map[string]string{"id": "tun1", "name": wantTunnelNam})

	tun, err := p.ApplyTunnel(context.Background())
	if err != nil {
		t.Fatalf("ApplyTunnel: %v", err)
	}
	if tun.ID != "tun1" || tun.Name != wantTunnelNam {
		t.Fatalf("tunnel = %+v", tun)
	}
	var createBody map[string]string
	json.Unmarshal(f.lastBody["POST /accounts/acct1/cfd_tunnel"], &createBody)
	if createBody["name"] != wantTunnelNam || createBody["config_src"] != "cloudflare" {
		t.Fatalf("tunnel create body = %v", createBody)
	}

	// Ingress: https://nginx:443, SNI = hostname, TLS verification stays ON.
	f.mux["PUT /accounts/acct1/cfd_tunnel/tun1/configurations"] = ok(map[string]any{})
	if err := p.ConfigureIngress(context.Background(), "tun1"); err != nil {
		t.Fatalf("ConfigureIngress: %v", err)
	}
	var cfg struct {
		Config struct {
			Ingress []struct {
				Hostname      string `json:"hostname"`
				Service       string `json:"service"`
				OriginRequest *struct {
					OriginServerName string `json:"originServerName"`
					NoTLSVerify      *bool  `json:"noTLSVerify"`
				} `json:"originRequest"`
			} `json:"ingress"`
		} `json:"config"`
	}
	raw := f.lastBody["PUT /accounts/acct1/cfd_tunnel/tun1/configurations"]
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("ingress body: %v", err)
	}
	in := cfg.Config.Ingress
	if len(in) != 2 || in[0].Hostname != host || in[0].Service != "https://nginx:443" || in[1].Service != "http_status:404" {
		t.Fatalf("ingress rules = %s", raw)
	}
	or := in[0].OriginRequest
	if or == nil || or.OriginServerName != host {
		t.Fatalf("originRequest = %s", raw)
	}
	if or.NoTLSVerify == nil || *or.NoTLSVerify != false {
		t.Fatalf("noTLSVerify must be present and false (TLS verification enabled): %s", raw)
	}

	// Connector token: returned for in-memory use, absent from evidence.
	f.mux["GET /accounts/acct1/cfd_tunnel/tun1/token"] = ok(connToken)
	tok, err := p.TunnelToken(context.Background(), "tun1")
	if err != nil || tok != connToken {
		t.Fatalf("TunnelToken = %q, %v", tok, err)
	}
	if b, _ := json.Marshal(tun); strings.Contains(string(b), connToken) {
		t.Fatalf("tunnel evidence contains the connector token: %s", b)
	}

	// DNS: proxied CNAME to <tunnel-id>.cfargotunnel.com with marker comment.
	f.mux["GET /zones/zone1/dns_records"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != host {
			t.Errorf("dns list name filter = %q", got)
		}
		ok([]any{})(w, r)
	}
	f.mux["POST /zones/zone1/dns_records"] = ok(map[string]any{
		"id": "rec1", "type": "CNAME", "name": host,
		"content": "tun1.cfargotunnel.com", "proxied": true, "comment": wantMarker,
	})
	plan := p.PlanDNS(tun.ID)
	rec, err := p.ApplyDNS(context.Background(), plan)
	if err != nil {
		t.Fatalf("ApplyDNS: %v", err)
	}
	if rec.ID != "rec1" || rec.Comment != wantMarker {
		t.Fatalf("record = %+v", rec)
	}
	var dnsBody map[string]any
	json.Unmarshal(f.lastBody["POST /zones/zone1/dns_records"], &dnsBody)
	want := map[string]any{
		"type": "CNAME", "name": host, "content": "tun1.cfargotunnel.com",
		"proxied": true, "ttl": float64(1), "comment": wantMarker,
	}
	for k, v := range want {
		if dnsBody[k] != v {
			t.Fatalf("dns create body[%s] = %v, want %v (body %v)", k, dnsBody[k], v, dnsBody)
		}
	}
	if b, _ := json.Marshal(rec); strings.Contains(string(b), connToken) {
		t.Fatalf("record evidence contains the connector token: %s", b)
	}
}

func TestApplyDNSPreExistingConflict(t *testing.T) {
	f := newFake(t)
	p := f.prov()
	f.mux["GET /zones/zone1/dns_records"] = ok([]map[string]any{{
		"id": "old1", "type": "A", "name": host, "content": "203.0.113.7", "comment": "",
	}})
	_, err := p.ApplyDNS(context.Background(), p.PlanDNS("tun1"))
	if !errors.Is(err, ErrPreExisting) {
		t.Fatalf("want ErrPreExisting, got %v", err)
	}
	if f.hits["POST /zones/zone1/dns_records"] != 0 {
		t.Fatal("conflict must not create or overwrite")
	}
	noSecret(t, err)
}

func TestLostResponseReconcile(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	// The tunnel already exists under the marker name: adopt, never re-create.
	f.mux["GET /accounts/acct1/cfd_tunnel"] = ok([]map[string]string{{"id": "tun1", "name": wantTunnelNam}})
	tun, err := p.ApplyTunnel(context.Background())
	if err != nil || tun.ID != "tun1" {
		t.Fatalf("ApplyTunnel reconcile = %+v, %v", tun, err)
	}
	if f.hits["POST /accounts/acct1/cfd_tunnel"] != 0 {
		t.Fatal("reconcile must not duplicate the tunnel")
	}

	// The record already carries the marker comment: adopt, never re-create.
	f.mux["GET /zones/zone1/dns_records"] = ok([]map[string]any{{
		"id": "rec1", "type": "CNAME", "name": host,
		"content": "tun1.cfargotunnel.com", "proxied": true, "comment": wantMarker,
	}})
	rec, err := p.ApplyDNS(context.Background(), p.PlanDNS("tun1"))
	if err != nil || rec.ID != "rec1" {
		t.Fatalf("ApplyDNS reconcile = %+v, %v", rec, err)
	}
	if f.hits["POST /zones/zone1/dns_records"] != 0 {
		t.Fatal("reconcile must not duplicate the record")
	}
}

func TestNameOnlyMatchRequiresReview(t *testing.T) {
	f := newFake(t)
	p := f.prov()
	// Same hostname prefix, different deployment ID: never adopted.
	other := "guacdeploy-" + host + "-ffffffffffffffffffffffffffffffff"
	f.mux["GET /accounts/acct1/cfd_tunnel"] = ok([]map[string]string{{"id": "tunX", "name": other}})
	_, err := p.ApplyTunnel(context.Background())
	if !errors.Is(err, ErrRequiresReview) {
		t.Fatalf("want ErrRequiresReview, got %v", err)
	}
	if f.hits["POST /accounts/acct1/cfd_tunnel"] != 0 {
		t.Fatal("ambiguity must not create a duplicate")
	}
	noSecret(t, err)
}

func TestCleanupRefusesUnmarkedResources(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	f.mux["GET /accounts/acct1/cfd_tunnel/tunX"] = ok(map[string]string{"id": "tunX", "name": "someone-elses-tunnel"})
	err := p.DeleteTunnel(context.Background(), "tunX")
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("want ErrNotOwned, got %v", err)
	}
	if f.hits["DELETE /accounts/acct1/cfd_tunnel/tunX"] != 0 {
		t.Fatal("unmarked tunnel must not be deleted")
	}

	f.mux["GET /zones/zone1/dns_records/recX"] = ok(map[string]any{
		"id": "recX", "type": "CNAME", "name": host, "comment": "unrelated",
	})
	err = p.DeleteRecord(context.Background(), "recX")
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("want ErrNotOwned, got %v", err)
	}
	if f.hits["DELETE /zones/zone1/dns_records/recX"] != 0 {
		t.Fatal("unmarked record must not be deleted")
	}

	// Marker-verified resources do get deleted.
	f.mux["GET /accounts/acct1/cfd_tunnel/tun1"] = ok(map[string]string{"id": "tun1", "name": wantTunnelNam})
	f.mux["DELETE /accounts/acct1/cfd_tunnel/tun1"] = ok(map[string]string{"id": "tun1"})
	if err := p.DeleteTunnel(context.Background(), "tun1"); err != nil {
		t.Fatalf("DeleteTunnel: %v", err)
	}
	f.mux["GET /zones/zone1/dns_records/rec1"] = ok(map[string]any{"id": "rec1", "name": host, "comment": wantMarker})
	f.mux["DELETE /zones/zone1/dns_records/rec1"] = ok(map[string]string{"id": "rec1"})
	if err := p.DeleteRecord(context.Background(), "rec1"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if f.hits["DELETE /accounts/acct1/cfd_tunnel/tun1"] != 1 || f.hits["DELETE /zones/zone1/dns_records/rec1"] != 1 {
		t.Fatal("marker-verified deletes did not happen")
	}
}

func TestConnectorTokenNeverLeaks(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	// A failing token fetch whose raw response body contains the secret must
	// not surface the body: errors carry status and API messages only.
	f.mux["GET /accounts/acct1/cfd_tunnel/tun1/token"] = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprintf(w, "gateway dump: %s / auth %s", connToken, testAPIToken)
	}
	_, err := p.TunnelToken(context.Background(), "tun1")
	if err == nil {
		t.Fatal("want error")
	}
	noSecret(t, err)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("want APIError 500, got %v", err)
	}

	// Evidence and plan structs have no field that could carry the token.
	for _, v := range []any{Tunnel{ID: "t", Name: "n"}, Record{ID: "r"}, p.PlanTunnel(), p.PlanDNS("tun1")} {
		b, _ := json.Marshal(v)
		if strings.Contains(strings.ToLower(string(b)), "token") {
			t.Fatalf("%T marshals a token-shaped field: %s", v, b)
		}
	}
}
