package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	// accessSelfHosted is the Access application type for a hostname served
	// by our own origin (the tunnel), as opposed to a SaaS application.
	accessSelfHosted = "self_hosted"
	// accessSessionDuration is sent explicitly so the plan equals the request
	// and a pre-existing application's original value is comparable.
	accessSessionDuration = "24h"
)

// ErrNoAllowList: an Access policy was planned with nothing in its
// allow-list. Access has no "allow everyone" in this package: a policy with
// an empty include list is refused rather than created.
var ErrNoAllowList = errors.New("the Access allow-list is empty; name the Entra groups or operator email addresses that may sign in")

// PreExistingApp reports an Access application that already covers this
// deployment's hostname without this deployment's ownership marker. It
// unwraps to ErrPreExisting, so errors.Is keeps working, and carries the
// original values of the fields this package would have set, ready for the
// parent to journal as SettingChange entries before anyone changes them by
// hand. This package never changes them itself.
type PreExistingApp struct {
	AppID   string
	Name    string
	Domain  string
	Changes []FieldChange
}

func (e *PreExistingApp) Error() string {
	return fmt.Sprintf("Access application %q (id %s) already covers %s without this deployment's marker: %v",
		e.Name, e.AppID, e.Domain, ErrPreExisting)
}

func (e *PreExistingApp) Unwrap() error { return ErrPreExisting }

// FieldChange records the original and intended value of one field on a
// pre-existing resource, ready for a state.SettingChange entry. The shape
// matches internal/entra's FieldChange so the parent maps both the same way.
type FieldChange struct {
	Field    string
	Original json.RawMessage
	Applied  json.RawMessage
}

func rawJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // static shapes only
	}
	return b
}

// AccessOrg is the account's Zero Trust organization. AuthDomain is the team
// domain (for example "example.cloudflareaccess.com") that an unauthenticated
// request is challenged against; nothing here is secret.
type AccessOrg struct {
	AuthDomain string `json:"auth_domain"`
	Name       string `json:"name"`
}

// AccessOrganization reads the account's Zero Trust organization. Access
// applications cannot exist without one, so a failure here means Zero Trust
// was never set up on the account, not that a permission is missing.
func (c *Client) AccessOrganization(ctx context.Context, accountID string) (AccessOrg, error) {
	var o AccessOrg
	if err := c.do(ctx, "GET", "/accounts/"+accountID+"/access/organizations", nil, &o); err != nil {
		return AccessOrg{}, err
	}
	if o.AuthDomain == "" {
		return AccessOrg{}, errors.New("this account has no Zero Trust organization (no team domain); set one up before protecting the hostname with Access")
	}
	return o, nil
}

// PreflightAccess proves the token holds the Access read permissions this
// package needs, without mutating anything. Run it after Preflight, which
// already proved the token is valid and active.
//
//	GET /accounts/{acct}/access/organizations        — Access : Organizations,
//	    Identity Providers, and Groups : Read, and proof that a Zero Trust
//	    organization (team domain) exists at all
//	GET /accounts/{acct}/access/identity_providers   — same permission, and the
//	    list this package picks the Entra identity provider from
//	GET /accounts/{acct}/access/apps?per_page=1      — Access : Apps and
//	    Policies : Read
//
// Reading applications proves the read half of the permission that also
// governs policies: Cloudflare grants both under one "Access: Apps and
// Policies" permission, so there is no separate policy read check.
//
// The mutation permission (Access : Apps and Policies : Edit) has no
// read-only proof: the v4 API offers no dry run, and a probe write would
// create a real Access application. It is proven by the first ApplyAccess,
// which surfaces HTTP 403 as an APIError naming the failed endpoint.
func (c *Client) PreflightAccess(ctx context.Context, accountID string) error {
	if _, err := c.AccessOrganization(ctx, accountID); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			return fmt.Errorf("token cannot read the Zero Trust organization (Access Organizations Read): %w", err)
		}
		return err // the account has no Zero Trust organization; not a permission problem
	}
	checks := []struct{ what, path string }{
		{"list Access identity providers (Access Organizations, Identity Providers, and Groups Read)",
			"/accounts/" + accountID + "/access/identity_providers"},
		{"list Access applications (Access Apps and Policies Read)",
			"/accounts/" + accountID + "/access/apps?per_page=1"},
	}
	for _, ck := range checks {
		if err := c.do(ctx, "GET", ck.path, nil, nil); err != nil {
			return fmt.Errorf("token cannot %s: %w", ck.what, err)
		}
	}
	return nil
}

// IdentityProvider is one Access identity provider, reduced to the fields
// this package needs. An identity provider's config holds an OAuth client
// secret; only the directory ID is decoded out of it, so no secret ever
// enters this struct, the evidence the parent journals, or an error.
type IdentityProvider struct {
	ID   string
	Name string
	Type string // "azureAD" for Microsoft Entra ID
	// DirectoryID is the Entra tenant ID the provider authenticates against
	// ("" for provider types that have no directory).
	DirectoryID string
}

// IdentityProviders lists the account's Access identity providers.
func (c *Client) IdentityProviders(ctx context.Context, accountID string) ([]IdentityProvider, error) {
	var raw []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Config struct {
			DirectoryID string `json:"directory_id"`
		} `json:"config"`
	}
	if err := c.do(ctx, "GET", "/accounts/"+accountID+"/access/identity_providers?per_page=50", nil, &raw); err != nil {
		return nil, err
	}
	idps := make([]IdentityProvider, 0, len(raw))
	for _, r := range raw {
		idps = append(idps, IdentityProvider{ID: r.ID, Name: r.Name, Type: r.Type, DirectoryID: r.Config.DirectoryID})
	}
	return idps, nil
}

// FindEntraIdP picks the Access identity provider bound to the Entra tenant
// that internal/entra provisioned into, matching on the tenant ID rather
// than on a name. It reports false when the account has no such provider;
// the caller then falls back to an email allow-list. See the package comment
// for why this package discovers an identity provider and never creates one.
func FindEntraIdP(idps []IdentityProvider, tenantID string) (IdentityProvider, bool) {
	if tenantID == "" {
		return IdentityProvider{}, false
	}
	for _, i := range idps {
		if i.Type == "azureAD" && strings.EqualFold(i.DirectoryID, tenantID) {
			return i, true
		}
	}
	return IdentityProvider{}, false
}

// Allow is the explicit allow-list for the Access policy. It is never
// implicitly "everyone": PlanAccess refuses an Allow with no rules.
type Allow struct {
	// IdPID is the Access identity provider UUID from FindEntraIdP. It is
	// required for Groups, and when set it is the only identity provider the
	// application offers.
	IdPID string
	// Groups are Entra group object IDs — the administrator and operator
	// groups internal/entra created for this deployment.
	Groups []string
	// Emails are individual operator addresses, for an account with no
	// Entra-backed Access identity provider.
	Emails []string
}

// include builds the policy's include rules in the shapes the Access API
// defines: {"azureAD":{"id","identity_provider_id"}} and {"email":{"email"}}.
func (a Allow) include() ([]map[string]any, error) {
	if len(a.Groups) > 0 && a.IdPID == "" {
		return nil, errors.New("an Entra group allow-list needs the Access identity provider ID; none was found for this tenant")
	}
	var rules []map[string]any
	for _, g := range a.Groups {
		rules = append(rules, map[string]any{"azureAD": map[string]any{"id": g, "identity_provider_id": a.IdPID}})
	}
	for _, e := range a.Emails {
		rules = append(rules, map[string]any{"email": map[string]any{"email": e}})
	}
	if len(rules) == 0 {
		return nil, ErrNoAllowList
	}
	return rules, nil
}

// AccessAppName carries the ownership marker: the Access application API has
// no writable comment, note or description field, and its tags are a separate
// account-level resource, so the marker lives in the application name. The
// deployment ID is 128 random bits, so a name carrying it cannot collide by
// accident — but a name is still only half the proof, so adoption also
// requires the application's domain to cover this deployment's hostname.
func (p *Provisioner) AccessAppName() string {
	return "Guacamole " + p.Hostname + " (" + p.marker() + ")"
}

func (p *Provisioner) accessNamePrefix() string { return "Guacamole " + p.Hostname + " (guacdeploy:" }

// AccessPolicyName carries the same marker. The policy is created under the
// application, so its ownership follows the application's.
func (p *Provisioner) AccessPolicyName() string {
	return "Guacamole operators (" + p.marker() + ")"
}

// AccessApp is evidence the caller may journal. AUD is the application's
// audience tag, the public identifier that appears in Access JWTs.
type AccessApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	AUD    string `json:"aud"`
}

// AccessPolicy is evidence the caller may journal: the decision and the
// allow-list that was actually stored.
type AccessPolicy struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Decision string           `json:"decision"`
	Include  []map[string]any `json:"include"`
}

// AccessAppPlan is exactly the application create request ApplyAccess sends.
type AccessAppPlan struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
	// SessionDuration is how long an Access session lasts before the operator
	// signs in again.
	SessionDuration string `json:"session_duration"`
	// AppLauncherVisible is false: this is an administration console, not an
	// application to advertise in the account's App Launcher.
	AppLauncherVisible bool `json:"app_launcher_visible"`
	// AllowedIdPs restricts sign-in to the Entra identity provider when one
	// was found; omitted, the account's whole identity provider list applies.
	AllowedIdPs []string `json:"allowed_idps,omitempty"`
	// AutoRedirectToIdentity skips the identity provider chooser, and is only
	// valid with exactly one allowed identity provider.
	AutoRedirectToIdentity bool `json:"auto_redirect_to_identity"`
}

// AccessPolicyPlan is exactly the policy create request ApplyAccess sends.
type AccessPolicyPlan struct {
	Name       string           `json:"name"`
	Decision   string           `json:"decision"`
	Include    []map[string]any `json:"include"`
	Precedence int              `json:"precedence"`
}

// AccessPlan is what ApplyAccess would create. Journal it, with a
// correlation ID, before calling ApplyAccess.
type AccessPlan struct {
	App    AccessAppPlan
	Policy AccessPolicyPlan
}

// PlanAccess describes the Access application and policy ApplyAccess would
// create for this deployment's hostname. It contacts nothing. An allow-list
// with no rules is refused with ErrNoAllowList rather than turned into an
// application anybody can reach.
func (p *Provisioner) PlanAccess(allow Allow) (AccessPlan, error) {
	rules, err := allow.include()
	if err != nil {
		return AccessPlan{}, err
	}
	app := AccessAppPlan{
		Name:               p.AccessAppName(),
		Domain:             p.Hostname,
		Type:               accessSelfHosted,
		SessionDuration:    accessSessionDuration,
		AppLauncherVisible: false,
	}
	if allow.IdPID != "" {
		app.AllowedIdPs = []string{allow.IdPID}
		app.AutoRedirectToIdentity = true
	}
	return AccessPlan{
		App: app,
		Policy: AccessPolicyPlan{
			Name:       p.AccessPolicyName(),
			Decision:   "allow",
			Include:    rules,
			Precedence: 1,
		},
	}, nil
}

// accessAppRecord is one Access application as the API returns it, with the
// fields needed for marker checks and for recording a pre-existing
// application's original values.
type accessAppRecord struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Domain                 string   `json:"domain"`
	Type                   string   `json:"type"`
	AUD                    string   `json:"aud"`
	SessionDuration        string   `json:"session_duration"`
	AllowedIdPs            []string `json:"allowed_idps"`
	AutoRedirectToIdentity bool     `json:"auto_redirect_to_identity"`
}

func (r accessAppRecord) app() AccessApp {
	return AccessApp{ID: r.ID, Name: r.Name, Domain: r.Domain, AUD: r.AUD}
}

// accessHost reduces an Access application domain to its hostname. The API
// accepts a bare hostname, a hostname with a path, or a full URL, so the
// comparison has to be made on the host part alone.
func accessHost(domain string) string {
	d := strings.TrimSpace(domain)
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?"); i >= 0 {
		d = d[:i]
	}
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

// covers reports whether this application secures the deployment hostname.
// ponytail: exact host match only; an account-wide wildcard application
// (*.example.com) is not detected as covering the hostname. Add wildcard
// matching if a lab run ever shows one shadowing the deployment.
func (p *Provisioner) covers(r accessAppRecord) bool {
	return accessHost(r.Domain) == strings.ToLower(p.Hostname)
}

func (c *Client) listAccessApps(ctx context.Context, accountID, query string) ([]accessAppRecord, error) {
	var apps []accessAppRecord
	// ponytail: first page (50) only; paginate when an account holds more
	// applications than that on one hostname, which it cannot usefully do.
	err := c.do(ctx, "GET", "/accounts/"+accountID+"/access/apps?per_page=50&"+query, nil, &apps)
	return apps, err
}

// ApplyAccess reconciles, then creates. Two reads come before any write:
//
//  1. Marker lookup — applications named exactly AccessAppName(). One whose
//     domain also covers the hostname is adopted, which is how a create whose
//     response was lost is recovered instead of duplicated. A marker name on
//     some other domain, or more than one match, is ErrRequiresReview: the
//     name is only half the proof and the linkage failed.
//  2. Hostname lookup — applications already covering the hostname. One
//     following this package's naming convention with another deployment's ID
//     is ErrRequiresReview. Any other is a *PreExistingApp (ErrPreExisting)
//     carrying the original values of the fields this package would have set.
//     Nothing is ever overwritten: this package has no path that changes an
//     application it does not own.
//
// The policy is created under the application and reconciled the same way, by
// its marker name. Between the two creates the application exists with no
// policy, which Access treats as deny-all, so a lost response never leaves
// the hostname open.
func (p *Provisioner) ApplyAccess(ctx context.Context, plan AccessPlan) (AccessApp, AccessPolicy, error) {
	app, err := p.applyAccessApp(ctx, plan.App)
	if err != nil {
		return AccessApp{}, AccessPolicy{}, err
	}
	pol, err := p.applyAccessPolicy(ctx, app.ID, plan.Policy)
	if err != nil {
		return app, AccessPolicy{}, err
	}
	return app, pol, nil
}

func (p *Provisioner) applyAccessApp(ctx context.Context, plan AccessAppPlan) (AccessApp, error) {
	found, err := p.Client.listAccessApps(ctx, p.AccountID,
		"name="+url.QueryEscape(p.AccessAppName())+"&exact=true")
	if err != nil {
		return AccessApp{}, err
	}
	// The name filter is re-applied here: adoption must never depend on the
	// server having honoured a query parameter.
	var marked []accessAppRecord
	for _, a := range found {
		if a.Name == p.AccessAppName() {
			marked = append(marked, a)
		}
	}
	switch {
	case len(marked) == 1 && p.covers(marked[0]):
		// ponytail: adopt on marker; drift in session duration or allowed
		// identity providers is not corrected here. Add a PUT when a lab run
		// shows the fields actually drifting.
		return marked[0].app(), nil
	case len(marked) == 1:
		return AccessApp{}, fmt.Errorf("Access application %q carries this deployment's marker but secures %q, not %s: %w",
			marked[0].Name, marked[0].Domain, p.Hostname, ErrRequiresReview)
	case len(marked) > 1:
		return AccessApp{}, fmt.Errorf("%d Access applications are named %q: %w",
			len(marked), p.AccessAppName(), ErrRequiresReview)
	}

	onHost, err := p.Client.listAccessApps(ctx, p.AccountID, "domain="+url.QueryEscape(p.Hostname))
	if err != nil {
		return AccessApp{}, err
	}
	var covering []accessAppRecord
	for _, a := range onHost {
		// The domain filter matches substrings; the host must match exactly.
		if p.covers(a) {
			covering = append(covering, a)
		}
	}
	// A stale application of this tool's own is the more specific condition,
	// so look for one across all of them before reporting a foreign app.
	for _, a := range covering {
		if strings.HasPrefix(a.Name, p.accessNamePrefix()) {
			return AccessApp{}, fmt.Errorf("Access application %q secures %s under this tool's naming convention but with another deployment's ID: %w",
				a.Name, p.Hostname, ErrRequiresReview)
		}
	}
	if len(covering) > 0 {
		a := covering[0]
		return AccessApp{}, &PreExistingApp{
			AppID: a.ID, Name: a.Name, Domain: a.Domain,
			Changes: []FieldChange{
				{"accessApplication.session_duration", rawJSON(a.SessionDuration), rawJSON(plan.SessionDuration)},
				{"accessApplication.allowed_idps", rawJSON(a.AllowedIdPs), rawJSON(plan.AllowedIdPs)},
				{"accessApplication.auto_redirect_to_identity", rawJSON(a.AutoRedirectToIdentity), rawJSON(plan.AutoRedirectToIdentity)},
			},
		}
	}

	var created accessAppRecord
	if err := p.Client.do(ctx, "POST", "/accounts/"+p.AccountID+"/access/apps", plan, &created); err != nil {
		return AccessApp{}, err
	}
	return created.app(), nil
}

func (p *Provisioner) accessPolicies(ctx context.Context, appID string) ([]AccessPolicy, error) {
	var pols []AccessPolicy
	err := p.Client.do(ctx, "GET", "/accounts/"+p.AccountID+"/access/apps/"+appID+"/policies", nil, &pols)
	return pols, err
}

func (p *Provisioner) applyAccessPolicy(ctx context.Context, appID string, plan AccessPolicyPlan) (AccessPolicy, error) {
	existing, err := p.accessPolicies(ctx, appID)
	if err != nil {
		return AccessPolicy{}, err
	}
	for _, pol := range existing {
		if pol.Name == p.AccessPolicyName() {
			return pol, nil // marker verified under our application: adopt
		}
	}
	var created AccessPolicy
	if err := p.Client.do(ctx, "POST", "/accounts/"+p.AccountID+"/access/apps/"+appID+"/policies", plan, &created); err != nil {
		return AccessPolicy{}, err
	}
	return created, nil
}

// DeleteAccessApp removes the Access application only after re-fetching it
// and verifying both halves of its ownership marker: the name carries this
// deployment's ID, and the application still secures this deployment's
// hostname. Anything else is ErrNotOwned and is left alone.
//
// The policy is scoped to the application, so it is removed with it; it has
// no independent lifecycle and needs no separate delete. Unrelated Access
// applications and the zone itself are untouched — this package has no
// deletion for either.
func (p *Provisioner) DeleteAccessApp(ctx context.Context, appID string) error {
	var app accessAppRecord
	if err := p.Client.do(ctx, "GET", "/accounts/"+p.AccountID+"/access/apps/"+appID, nil, &app); err != nil {
		return err
	}
	if app.Name != p.AccessAppName() {
		return fmt.Errorf("Access application %s is named %q, not this deployment's %q: %w",
			appID, app.Name, p.AccessAppName(), ErrNotOwned)
	}
	if !p.covers(app) {
		return fmt.Errorf("Access application %s carries this deployment's marker but secures %q, not %s: %w",
			appID, app.Domain, p.Hostname, ErrNotOwned)
	}
	return p.Client.do(ctx, "DELETE", "/accounts/"+p.AccountID+"/access/apps/"+appID, nil, nil)
}

// dialViaAuthority dials normally, and on a lookup failure resolves the
// name at the zone's authoritative nameservers instead. A proxied record's
// authority is Cloudflare itself, so this asks the same servers the rest of
// the internet would.
func (c *Client) dialViaAuthority(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return nil, err
	}
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, err
	}
	ips, resolveErr := c.resolveAtAuthority(ctx, host)
	if resolveErr != nil || len(ips) == 0 {
		return nil, fmt.Errorf("%v (and the zone's authority could not be asked either: %v)", err, resolveErr)
	}
	for _, ip := range ips {
		if conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(ip, port)); dialErr == nil {
			return conn, nil
		}
	}
	return nil, err
}

// resolveAtAuthority returns the addresses the zone's authoritative
// nameservers give for a name.
func (c *Client) resolveAtAuthority(ctx context.Context, host string) ([]string, error) {
	if len(c.AuthorityNameServers) == 0 {
		return nil, errors.New("no authoritative nameservers are known for this zone")
	}
	for _, ns := range c.AuthorityNameServers {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, net.JoinHostPort(ns, "53"))
		}}
		if addrs, err := r.LookupHost(ctx, host); err == nil && len(addrs) > 0 {
			return addrs, nil
		}
	}
	return nil, errors.New("the zone's authoritative nameservers did not answer for " + host)
}

// ensureAuthority fills in the zone's authoritative nameservers when they
// are not already known. A failure is not fatal: the probe simply falls
// back to this host's resolver, and its error explains what it asked.
func (p *Provisioner) ensureAuthority(ctx context.Context) {
	if len(p.Client.AuthorityNameServers) > 0 || p.ZoneID == "" {
		return
	}
	var z Zone
	if err := p.Client.do(ctx, "GET", "/zones/"+p.ZoneID, nil, &z); err == nil {
		p.Client.AuthorityNameServers = z.NameServers
	}
}
