// Package cloudflare provisions the deployment's Cloudflare Tunnel, DNS
// record and Cloudflare Access protection through the v4 API.
//
// # Cloudflare Access identity model
//
// Access sits in front of the deployment hostname, so an anonymous request
// never reaches Guacamole at all. Guacamole still runs its own Entra SAML
// sign-in behind it (issue #6), so an operator signs in twice: once to
// Cloudflare Access, once to Guacamole. That is the point — the two are
// independent gates, and the console is not exposed while either one is
// being changed.
//
// This package discovers an Access identity provider; it never creates one.
// The preferred identity model is the account's existing Entra-backed
// ("azureAD") Access identity provider, matched by the tenant ID that
// internal/entra recorded, with an allow-list naming the exact administrator
// and operator group object IDs that internal/entra created. Reusing those
// groups means Access and Guacamole authorise the same people from the same
// directory objects, and adding an operator is one Entra group membership.
//
// Creating the identity provider was rejected, not overlooked. An Access
// azureAD provider needs an OIDC client ID and client secret, which the SAML
// application from issue #6 does not have: it would mean a second Entra
// application registration and a new long-lived secret for this tool to
// hold. Worse, an Access identity provider is account-wide, shared by every
// application in the account, so ADR 0002 would forbid ever deleting it at
// teardown — the tool would create a resource it could never clean up. So
// when the account has no Entra-backed provider, the fallback is an explicit
// list of operator email addresses instead, and setting up the identity
// provider stays a one-off account decision for a person.
//
// Either way the allow-list is explicit. PlanAccess refuses an empty one
// with ErrNoAllowList; this package has no "allow everyone" rule.
//
// # Ownership markers
//
// The public cfd_tunnel create API accepts only name, config_src and
// tunnel_secret — no writable tags or metadata — so the tunnel's ownership
// marker is the deployment ID embedded in the tunnel name:
// "guacdeploy-<hostname>-<deployment-id>". The deployment ID is 128 random
// bits, so a name carrying it cannot match by accident. DNS records support
// comments, so the record's marker is the comment "guacdeploy:<deployment-id>".
//
// The Access application has the same problem as the tunnel and no better
// answer: its API has no writable comment, note or description field, and
// its tags are a separate account-level resource with its own lifecycle. So
// the marker is again in the name (AccessAppName), and because a name alone
// is only half a proof, adoption and deletion also require the application's
// domain to still cover this deployment's hostname. The Access policy lives
// under the application, so its ownership follows the application's, and it
// carries the marker in its own name as well.
//
// # Reconciliation
//
// Plan methods return exactly what Apply will send, so the caller can journal
// intent and a correlation ID first. Apply methods query for the marker before
// any create: a retry after a lost response adopts the resource this
// deployment already created instead of duplicating it. A match on name alone
// (marker absent or different) never establishes ownership; it returns
// ErrRequiresReview (tunnels) or ErrPreExisting (DNS) for the caller to
// resolve — nothing is overwritten silently.
//
// # Deletion
//
// Delete methods re-fetch the resource and refuse with ErrNotOwned unless the
// marker is present. Zone preservation is structural: this package has no
// zone deletion, so a zone that now carries unrelated records is preserved
// because only marker-owned tunnels, records and Access applications are
// ever eligible. Unrelated Access applications in the same account are
// preserved for the same structural reason.
//
// # Origin TLS
//
// The tunnel ingress routes the hostname to https://nginx:443 with SNI set to
// the deployment hostname and certificate verification enabled
// (noTLSVerify=false, per the specification). Until the Let's Encrypt origin
// certificate lands (issue #9), nginx serves a temporary self-signed
// certificate, so cloudflared refuses the origin and the public hostname
// returns an error. That is expected; do not disable verification to hide it.
// Remotely-managed configuration cannot supply a custom CA bundle
// (originRequest.caPool is a connector-local file path), so the fix is the
// origin certificate, not a CA override.
//
// # Secrecy
//
// The connector token returned by TunnelToken is a secret for in-memory use
// only (the stack's TUNNEL_TOKEN override). It never appears in Tunnel or
// Record values, plans, or errors, and this package logs nothing.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// DefaultBase is the Cloudflare v4 API endpoint.
const DefaultBase = "https://api.cloudflare.com/client/v4"

// Conditions the caller must resolve; none of them is retried internally.
var (
	// ErrRequiresReview: a tunnel matches this deployment's name prefix but
	// not its marker. Ownership was not established; review is required.
	ErrRequiresReview = errors.New("name-only match requires review; a matching name alone never establishes ownership")
	// ErrPreExisting: a DNS record already occupies the hostname without
	// this deployment's marker. It is never overwritten without approval.
	ErrPreExisting = errors.New("a pre-existing DNS record occupies this hostname; approval is required, it will not be overwritten")
	// ErrNotOwned: a delete target does not carry this deployment's marker.
	ErrNotOwned = errors.New("resource does not carry this deployment's ownership marker; refusing to delete")
)

// TokenSource supplies the API token per request. The parent feeds it from
// the creds manager ("cloudflare-api-token"); the value stays in memory.
type TokenSource func(ctx context.Context) (string, error)

// Client is a minimal Cloudflare v4 API client.
type Client struct {
	// AuthorityNameServers are the zone's authoritative nameservers. A
	// verification probe uses them when the deployment host's own resolver
	// cannot see the zone, which happens whenever that resolver is
	// authoritative for the same domain internally.
	AuthorityNameServers []string

	HTTP  *http.Client // injectable seam; nil means http.DefaultClient
	Base  string       // "" means DefaultBase
	Token TokenSource  // required
}

// APIError reports a failed call: method, path, HTTP status, and Cloudflare's
// error messages. Request bodies, response bodies and the token never appear.
type APIError struct {
	Method, Path string
	Status       int
	Messages     []string
}

func (e *APIError) Error() string {
	msg := "unreadable response body"
	if len(e.Messages) > 0 {
		b, _ := json.Marshal(e.Messages)
		msg = string(b)
	}
	return fmt.Sprintf("cloudflare API %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, msg)
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

// do sends one request and decodes the envelope result into out (may be nil).
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	base := c.Base
	if base == "" {
		base = DefaultBase
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	token, err := c.Token(ctx)
	if err != nil {
		return fmt.Errorf("cloudflare API token is not available: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare API %s %s: %w", method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	var env envelope
	decodeErr := json.NewDecoder(resp.Body).Decode(&env)
	if decodeErr != nil || !env.Success || resp.StatusCode >= 400 {
		e := &APIError{Method: method, Path: req.URL.Path, Status: resp.StatusCode}
		for _, m := range env.Errors {
			e.Messages = append(e.Messages, fmt.Sprintf("%s (code %d)", m.Message, m.Code))
		}
		return e
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare API %s %s: unexpected result shape: %w", method, req.URL.Path, err)
		}
	}
	return nil
}

// VerifyToken checks that the token is valid and active
// (GET /user/tokens/verify). It proves nothing about permissions.
func (c *Client) VerifyToken(ctx context.Context) error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, "GET", "/user/tokens/verify", nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return fmt.Errorf("cloudflare API token status is %q, not active", r.Status)
	}
	return nil
}

// Preflight proves the token works and holds the read permissions this
// package needs, without mutating anything:
//
//	GET /user/tokens/verify                     — token is valid and active
//	GET /zones/{zone}                           — Zone : Zone : Read
//	GET /zones/{zone}/dns_records?per_page=1    — Zone : DNS : Read
//	GET /accounts/{acct}/cfd_tunnel?per_page=1  — Account : Cloudflare Tunnel : Read
//
// The mutation permissions (Zone : DNS : Edit, Account : Cloudflare Tunnel :
// Edit) have no read-only proof: the v4 API offers no dry run, and a probe
// write would create real resources. They are proven by the first Apply,
// which surfaces HTTP 403 as an APIError naming the failed endpoint.
func (c *Client) Preflight(ctx context.Context, accountID, zoneID string) error {
	if err := c.VerifyToken(ctx); err != nil {
		return err
	}
	checks := []struct{ what, path string }{
		{"read the zone (Zone Read)", "/zones/" + zoneID},
		{"read DNS records (DNS Read)", "/zones/" + zoneID + "/dns_records?per_page=1"},
		{"list Cloudflare Tunnels (Cloudflare Tunnel Read)", "/accounts/" + accountID + "/cfd_tunnel?per_page=1&is_deleted=false"},
	}
	for _, ck := range checks {
		if err := c.do(ctx, "GET", ck.path, nil, nil); err != nil {
			return fmt.Errorf("token cannot %s: %w", ck.what, err)
		}
	}
	return nil
}

// Account is one Cloudflare account the token can see.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Accounts lists the accounts the token can see (GET /accounts).
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	var a []Account
	// ponytail: first page (50) only; paginate when a token sees more accounts
	err := c.do(ctx, "GET", "/accounts?per_page=50", nil, &a)
	return a, err
}

// Zone is one zone the token can see, with the account that owns it.
type Zone struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	Account Account `json:"account"`
	// NameServers are the zone's authoritative nameservers. A DNS-01
	// pre-check must ask these, not the deployment host's resolver, which
	// may be authoritative for the same domain internally and never see a
	// record published at Cloudflare.
	NameServers []string `json:"name_servers"`
}

// ZonesByName lists the zones with exactly this name — the apex the parent
// derived from the deployment hostname. The module only reports what was
// found; the caller approves the selection. More than one result means the
// token spans accounts holding duplicate zones: that choice is the caller's.
func (c *Client) ZonesByName(ctx context.Context, name string) ([]Zone, error) {
	var z []Zone
	err := c.do(ctx, "GET", "/zones?name="+url.QueryEscape(name)+"&per_page=50", nil, &z)
	// Remember the authority so a later probe can resolve a hostname this
	// host's own resolver cannot see.
	if err == nil && len(z) == 1 {
		c.AuthorityNameServers = z[0].NameServers
	}
	return z, err
}

// Provisioner binds a client to one deployment's account, zone and hostname.
type Provisioner struct {
	Client       *Client
	AccountID    string
	ZoneID       string
	Hostname     string // full deployment hostname, e.g. guac.example.com
	DeploymentID string // state.State.DeploymentID
	// Resolve answers "what does this name resolve to", for WaitResolvable.
	// nil means this host's resolver first, then the zone's authority.
	Resolve func(ctx context.Context, host string) ([]string, error)
}

// marker is the DNS ownership marker carried in the record comment.
func (p *Provisioner) marker() string { return "guacdeploy:" + p.DeploymentID }

// TunnelName carries the ownership marker: the deployment ID is embedded in
// the name because the tunnel API supports no other durable marker.
func (p *Provisioner) TunnelName() string {
	return "guacdeploy-" + p.Hostname + "-" + p.DeploymentID
}

func (p *Provisioner) tunnelPrefix() string { return "guacdeploy-" + p.Hostname + "-" }

// Tunnel is evidence the caller may journal; it never carries the connector token.
type Tunnel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TunnelPlan is exactly the create request ApplyTunnel sends. Journal it,
// with a correlation ID, before calling ApplyTunnel.
type TunnelPlan struct {
	Name      string `json:"name"`
	ConfigSrc string `json:"config_src"` // "cloudflare": remotely managed
}

// PlanTunnel describes the tunnel ApplyTunnel would create.
func (p *Provisioner) PlanTunnel() TunnelPlan {
	return TunnelPlan{Name: p.TunnelName(), ConfigSrc: "cloudflare"}
}

// ApplyTunnel reconciles, then creates. It lists live tunnels whose names
// match this deployment's hostname prefix; a tunnel carrying the full marker
// name is adopted (a lost create response is recovered, never duplicated), a
// prefix match without the marker returns ErrRequiresReview, and only when
// nothing matches is the tunnel created.
func (p *Provisioner) ApplyTunnel(ctx context.Context) (Tunnel, error) {
	var found []Tunnel
	path := "/accounts/" + p.AccountID + "/cfd_tunnel?is_deleted=false&per_page=50&include_prefix=" +
		url.QueryEscape(p.tunnelPrefix())
	if err := p.Client.do(ctx, "GET", path, nil, &found); err != nil {
		return Tunnel{}, err
	}
	for _, t := range found {
		if t.Name == p.TunnelName() {
			return t, nil // marker verified: the name carries this deployment's ID
		}
	}
	if len(found) > 0 {
		return Tunnel{}, fmt.Errorf("tunnel %q matches hostname %s but not this deployment's marker: %w",
			found[0].Name, p.Hostname, ErrRequiresReview)
	}
	var t Tunnel
	if err := p.Client.do(ctx, "POST", "/accounts/"+p.AccountID+"/cfd_tunnel", p.PlanTunnel(), &t); err != nil {
		return Tunnel{}, err
	}
	return t, nil
}

type originRequest struct {
	OriginServerName string `json:"originServerName"`
	// NoTLSVerify is always sent, always false: certificate verification
	// between the tunnel and origin stays enabled (specification). See the
	// package comment for behaviour before issue #9 issues the origin cert.
	NoTLSVerify bool `json:"noTLSVerify"`
}

type ingressRule struct {
	Hostname      string         `json:"hostname,omitempty"`
	Service       string         `json:"service"`
	OriginRequest *originRequest `json:"originRequest,omitempty"`
}

// ConfigureIngress sets the remotely-managed tunnel configuration: the
// deployment hostname routes to https://nginx:443 with SNI (originServerName)
// set to the hostname and TLS verification enabled; everything else gets 404.
// The PUT replaces the whole configuration, so re-running it is idempotent.
func (p *Provisioner) ConfigureIngress(ctx context.Context, tunnelID string) error {
	body := map[string]any{"config": map[string]any{"ingress": []ingressRule{
		{
			Hostname:      p.Hostname,
			Service:       "https://nginx:443",
			OriginRequest: &originRequest{OriginServerName: p.Hostname, NoTLSVerify: false},
		},
		{Service: "http_status:404"},
	}}}
	return p.Client.do(ctx, "PUT", "/accounts/"+p.AccountID+"/cfd_tunnel/"+tunnelID+"/configurations", body, nil)
}

// TunnelToken fetches the connector token — the stack's TUNNEL_TOKEN secret.
// It is for in-memory use only: pass it to stack.Up, which writes it to an
// owner-only file on memory-backed storage for the connector to read; never
// journal, log, persist, or place it in command arguments.
func (p *Provisioner) TunnelToken(ctx context.Context, tunnelID string) (string, error) {
	var tok string
	if err := p.Client.do(ctx, "GET", "/accounts/"+p.AccountID+"/cfd_tunnel/"+tunnelID+"/token", nil, &tok); err != nil {
		return "", err
	}
	return tok, nil
}

// Record is evidence the caller may journal; it holds no secrets.
type Record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

// DNSPlan is exactly the create request ApplyDNS sends. Journal it, with a
// correlation ID, before calling ApplyDNS.
type DNSPlan struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"` // 1 = automatic, required for proxied records
	Comment string `json:"comment"`
}

// PlanDNS describes the proxied CNAME ApplyDNS would create: the deployment
// hostname pointing at <tunnel-id>.cfargotunnel.com, with the ownership
// marker in the record comment.
func (p *Provisioner) PlanDNS(tunnelID string) DNSPlan {
	return DNSPlan{
		Type:    "CNAME",
		Name:    p.Hostname,
		Content: tunnelID + ".cfargotunnel.com",
		Proxied: true,
		TTL:     1,
		Comment: p.marker(),
	}
}

// ApplyDNS reconciles, then creates. It lists the records at the hostname; a
// record whose comment carries the marker is adopted (a lost create response
// is recovered, never duplicated), any other record at the name returns
// ErrPreExisting for caller approval — it is never overwritten — and only
// when the name is free is the record created.
func (p *Provisioner) ApplyDNS(ctx context.Context, plan DNSPlan) (Record, error) {
	var existing []Record
	path := "/zones/" + p.ZoneID + "/dns_records?per_page=50&name=" + url.QueryEscape(plan.Name)
	if err := p.Client.do(ctx, "GET", path, nil, &existing); err != nil {
		return Record{}, err
	}
	for _, r := range existing {
		if r.Comment == p.marker() {
			// ponytail: adopt on marker; content drift after a tunnel
			// recreation is fixed by DeleteRecord + re-apply, add PATCH
			// when that path is actually exercised.
			return r, nil
		}
	}
	if len(existing) > 0 {
		return Record{}, fmt.Errorf("%s record %q (content %s) exists without this deployment's marker: %w",
			existing[0].Type, existing[0].Name, existing[0].Content, ErrPreExisting)
	}
	var r Record
	if err := p.Client.do(ctx, "POST", "/zones/"+p.ZoneID+"/dns_records", plan, &r); err != nil {
		return Record{}, err
	}
	return r, nil
}

// DeleteTunnel removes the tunnel only after re-fetching it and verifying its
// name carries this deployment's marker; anything else is ErrNotOwned.
func (p *Provisioner) DeleteTunnel(ctx context.Context, tunnelID string) error {
	var t Tunnel
	if err := p.Client.do(ctx, "GET", "/accounts/"+p.AccountID+"/cfd_tunnel/"+tunnelID, nil, &t); err != nil {
		return err
	}
	if t.Name != p.TunnelName() {
		return fmt.Errorf("tunnel %s is named %q, not this deployment's %q: %w", tunnelID, t.Name, p.TunnelName(), ErrNotOwned)
	}
	return p.Client.do(ctx, "DELETE", "/accounts/"+p.AccountID+"/cfd_tunnel/"+tunnelID+"?cascade=true", nil, nil)
}

// DeleteRecord removes one DNS record only after re-fetching it and verifying
// the marker comment; anything else is ErrNotOwned. This package deletes
// single owned records and has no zone deletion at all, so a zone that now
// carries unrelated records is preserved structurally.
func (p *Provisioner) DeleteRecord(ctx context.Context, recordID string) error {
	var r Record
	if err := p.Client.do(ctx, "GET", "/zones/"+p.ZoneID+"/dns_records/"+recordID, nil, &r); err != nil {
		return err
	}
	if r.Comment != p.marker() {
		return fmt.Errorf("DNS record %s (%s) does not carry marker %q: %w", recordID, r.Name, p.marker(), ErrNotOwned)
	}
	return p.Client.do(ctx, "DELETE", "/zones/"+p.ZoneID+"/dns_records/"+recordID, nil, nil)
}
