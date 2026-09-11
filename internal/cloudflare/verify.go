package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// ErrAllowsEveryone: the stored Access policy would admit anybody who can
// reach the hostname. It is the one drift worth catching above all others, so
// it is a sentinel of its own and is never reported as a verified allow-list.
var ErrAllowsEveryone = errors.New("the stored Access policy admits everyone; the hostname is open to any identity the provider will authenticate")

// SignInNotProven is the claim this package deliberately does not make.
// Everything VerifyAccess proves is configuration read back from the API plus
// the challenge an anonymous request receives. Whether an allowed operator can
// actually sign in, and a denied one cannot, is a separate test with a real
// user in a browser.
const SignInNotProven = "no user sign-in was demonstrated: this verification covers configuration and the anonymous challenge only, not an allowed or denied SAML login"

// AccessExpectation is what the stored Access configuration is compared
// against: the allow-list this deployment applied, and the Entra tenant whose
// identity provider the group rules must be bound to.
//
// Pass the same Allow that was given to PlanAccess. Without an expectation
// VerifyAccess still refuses an empty or everyone allow-list, but it cannot
// tell that the stored rules are the ones this deployment applied, and its
// evidence says so rather than implying more.
type AccessExpectation struct {
	Allow Allow
	// EntraTenantID is Config["entra-tenant-id"]. It is required when the
	// allow-list names Entra groups, and unused for the email fallback.
	EntraTenantID string
}

// AccessVerification is proof the hostname is protected, for the caller to
// journal. It holds no secrets, and each boolean names exactly one claim so
// that evidence for one is never read as evidence for another.
type AccessVerification struct {
	AppID      string
	Domain     string // the domain read back from the API
	AUD        string // the application's audience tag, read back from the API
	PolicyID   string
	AllowRules int    // how many include rules the stored allow-list has
	IdPID      string // the identity provider the stored group rules bind to
	AuthDomain string // the team domain the challenge pointed at
	Challenge  string // the observed response

	// AppVerified: the application read back from the API carries this
	// deployment's marker, still covers the hostname, and has an audience tag.
	AppVerified bool
	// PolicyMatchesAllowList: the application has exactly one policy, it is
	// this deployment's, it decides "allow", and its stored include rules are
	// the allow-list that was applied. False when no expectation was supplied.
	PolicyMatchesAllowList bool
	// IdPBoundToTenant: the identity provider the stored group rules name is
	// the account's Entra provider for this deployment's tenant. False for an
	// email allow-list, which has no identity-provider binding.
	IdPBoundToTenant bool
	// ChallengeVerified: an anonymous request to the hostname was redirected
	// to this application's own Access login, for this hostname, carrying this
	// application's audience tag and an unauthenticated status.
	ChallengeVerified bool
}

// String reports what was verified and what was not, and ends by saying what
// is still unproven. Nothing here may be read as a successful sign-in.
func (v AccessVerification) String() string {
	say := func(done bool, yes, no string) string {
		if done {
			return yes
		}
		return no
	}
	return strings.Join([]string{
		say(v.AppVerified,
			fmt.Sprintf("application %s (audience %s) secures %s", v.AppID, v.AUD, v.Domain),
			fmt.Sprintf("application %s was not verified", v.AppID)),
		say(v.PolicyMatchesAllowList,
			fmt.Sprintf("policy %s allows exactly the %d rules this deployment applied", v.PolicyID, v.AllowRules),
			fmt.Sprintf("policy %s has %d allow rules, not compared with the applied allow-list", v.PolicyID, v.AllowRules)),
		say(v.IdPBoundToTenant,
			"those rules are bound to the deployment's Entra identity provider "+v.IdPID,
			"no Entra identity-provider binding was verified"),
		say(v.ChallengeVerified,
			fmt.Sprintf("an anonymous request was challenged by this application's own Access login at %s (%s)", v.AuthDomain, v.Challenge),
			"no Access challenge was verified"),
		SignInNotProven,
	}, "; ")
}

// VerifyAccess proves the application is configured as this deployment
// applied it and is actually challenging anonymous requests. It re-reads the
// application and its policies, compares the stored allow-list with the one
// that was applied, and then makes one unauthenticated request to
// https://<hostname>/ through the same injectable HTTP seam.
//
// At most one expectation may be given; it is the Allow that was passed to
// PlanAccess plus the Entra tenant ID. It is optional only so that a caller
// that has not been wired for it still compiles — pass it.
//
// The probe sends no Authorization header: it must look exactly like an
// anonymous visitor's request, and the API token has no business leaving the
// API endpoint. Redirects are not followed, because the redirect itself is the
// evidence: it must be this application's own Access login for this hostname,
// not merely some address under cloudflareaccess.com. A page from the origin
// means the request got past Access and is a failure.
//
// This check works before the origin certificate exists (issue #9): Access
// challenges the request before it is ever routed to the origin.
//
// What this does NOT prove is SignInNotProven. A reachable login page is not a
// login, and no code in this package may report one.
func (p *Provisioner) VerifyAccess(ctx context.Context, appID string, expect ...AccessExpectation) (AccessVerification, error) {
	var v AccessVerification
	if len(expect) > 1 {
		return v, errors.New("VerifyAccess takes at most one expectation")
	}
	// Learn the zone's authority now rather than relying on an earlier
	// phase having recorded it: a resumed run skips the phase that
	// selected the zone, and the probe would then have no way to resolve a
	// hostname this host's resolver cannot see.
	p.ensureAuthority(ctx)
	var app accessAppRecord
	if err := p.Client.do(ctx, "GET", "/accounts/"+p.AccountID+"/access/apps/"+appID, nil, &app); err != nil {
		return v, err
	}
	v.AppID, v.Domain, v.AUD = app.ID, app.Domain, app.AUD
	if app.Name != p.AccessAppName() {
		return v, fmt.Errorf("Access application %s is named %q, not this deployment's %q: %w",
			appID, app.Name, p.AccessAppName(), ErrNotOwned)
	}
	if !p.covers(app) {
		return v, fmt.Errorf("Access application %s secures %q, not %s: the hostname is not protected", appID, app.Domain, p.Hostname)
	}
	if app.AUD == "" {
		return v, fmt.Errorf("Access application %s has no audience tag, so a login redirect cannot be tied to it", appID)
	}
	v.AppVerified = true

	pols, err := p.accessPolicies(ctx, appID)
	if err != nil {
		return v, err
	}
	pol, err := p.ownPolicy(appID, pols)
	if err != nil {
		return v, err
	}
	v.PolicyID, v.AllowRules = pol.ID, len(pol.Include)

	if len(expect) == 1 {
		want, err := expect[0].Allow.include()
		if err != nil {
			return v, fmt.Errorf("the applied allow-list cannot be rebuilt for comparison: %w", err)
		}
		if err := compareAllowList(v.PolicyID, pol.Include, want); err != nil {
			return v, err
		}
		v.PolicyMatchesAllowList = true
		idp, err := p.verifyIdP(ctx, pol, expect[0])
		if err != nil {
			return v, err
		}
		v.IdPID, v.IdPBoundToTenant = idp, idp != ""
	}

	org, err := p.Client.AccessOrganization(ctx, p.AccountID)
	if err != nil {
		return v, err
	}
	v.AuthDomain = org.AuthDomain
	challenge, err := p.Client.accessChallenge(ctx, p.Hostname, org.AuthDomain, app.AUD)
	if err != nil {
		return v, err
	}
	v.Challenge, v.ChallengeVerified = challenge, true
	return v, nil
}

// ownPolicy picks this deployment's policy out of the application's stored
// policies and refuses everything that could widen who may sign in: a second
// policy (Access evaluates them all, so an extra one can only add access), a
// decision other than "allow", an empty allow-list, and an "everyone" rule.
func (p *Provisioner) ownPolicy(appID string, pols []AccessPolicy) (AccessPolicy, error) {
	var mine []AccessPolicy
	for _, pol := range pols {
		if pol.Name == p.AccessPolicyName() {
			mine = append(mine, pol)
		}
	}
	switch {
	case len(mine) == 0:
		return AccessPolicy{}, fmt.Errorf("Access application %s has no allow policy named %q: nobody can sign in",
			appID, p.AccessPolicyName())
	case len(mine) > 1:
		return AccessPolicy{}, fmt.Errorf("Access application %s has %d policies named %q: %w",
			appID, len(mine), p.AccessPolicyName(), ErrRequiresReview)
	case len(pols) > 1:
		var others []string
		for _, pol := range pols {
			if pol.Name != p.AccessPolicyName() {
				others = append(others, fmt.Sprintf("%q (%s)", pol.Name, pol.Decision))
			}
		}
		return AccessPolicy{}, fmt.Errorf("Access application %s also carries policy %s, which can widen who may sign in: %w",
			appID, strings.Join(others, ", "), ErrRequiresReview)
	}
	pol := mine[0]
	if pol.Decision != "allow" {
		return AccessPolicy{}, fmt.Errorf("Access policy %s decides %q, not \"allow\": the allow-list is not in force", pol.ID, pol.Decision)
	}
	if len(pol.Include) == 0 {
		return AccessPolicy{}, fmt.Errorf("Access policy %s has an empty allow-list: %w", pol.ID, ErrNoAllowList)
	}
	for _, rule := range pol.Include {
		if _, open := rule["everyone"]; open {
			return AccessPolicy{}, fmt.Errorf("Access policy %s includes an \"everyone\" rule: %w", pol.ID, ErrAllowsEveryone)
		}
	}
	return pol, nil
}

// compareAllowList asserts the stored include rules are exactly the rules that
// were applied — same rules, same count. An extra stored rule is a widening
// and fails here even when every applied rule is present.
func compareAllowList(policyID string, stored, want []map[string]any) error {
	got, expected := ruleKeys(stored), ruleKeys(want)
	if !slices.Equal(got, expected) {
		return fmt.Errorf("Access policy %s allows [%s], not the applied allow-list [%s]: the stored allow-list is not the one this deployment applied",
			policyID, strings.Join(got, ", "), strings.Join(expected, ", "))
	}
	return nil
}

// ruleKeys renders include rules as sorted comparable strings. The rendering
// is deliberately readable, because it is what an operator is shown when the
// comparison fails.
func ruleKeys(rules []map[string]any) []string {
	keys := make([]string, 0, len(rules))
	for _, rule := range rules {
		keys = append(keys, ruleKey(rule))
	}
	sort.Strings(keys)
	return keys
}

func ruleKey(rule map[string]any) string {
	names := make([]string, 0, len(rule))
	for k := range rule {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		inner, _ := rule[name].(map[string]any)
		switch name {
		case "azureAD":
			parts = append(parts, fmt.Sprintf("Entra group %v via identity provider %v", inner["id"], inner["identity_provider_id"]))
		case "email":
			parts = append(parts, fmt.Sprintf("email %v", inner["email"]))
		default:
			// Any other rule type is compared on its whole body: this package
			// never applies one, so any difference at all must fail.
			b, _ := json.Marshal(rule[name])
			parts = append(parts, name+" "+string(b))
		}
	}
	return strings.Join(parts, "+")
}

// verifyIdP confirms the identity provider the stored group rules name is the
// account's Entra provider for this deployment's tenant, read back from the
// API rather than assumed from the plan. It returns "" when the allow-list is
// the email fallback, which has no identity-provider binding to verify.
//
// It runs only after compareAllowList, which has already proven every stored
// group rule names want.Allow.IdPID — a rule pointing at another directory is
// not the applied allow-list and fails there. What is left to prove is that
// this identity provider is still the one bound to the deployment's tenant.
func (p *Provisioner) verifyIdP(ctx context.Context, pol AccessPolicy, want AccessExpectation) (string, error) {
	usesGroups := false
	for _, rule := range pol.Include {
		if _, isGroup := rule["azureAD"]; isGroup {
			usesGroups = true
			break
		}
	}
	if !usesGroups {
		return "", nil // email allow-list
	}
	if want.EntraTenantID == "" {
		return "", errors.New("the allow-list names Entra groups but no Entra tenant ID was supplied, so the identity-provider binding cannot be verified")
	}
	idps, err := p.Client.IdentityProviders(ctx, p.AccountID)
	if err != nil {
		return "", err
	}
	idp, found := FindEntraIdP(idps, want.EntraTenantID)
	if !found {
		return "", fmt.Errorf("no Access identity provider is bound to Entra tenant %s, so the stored allow-list cannot be checked against this deployment's directory", want.EntraTenantID)
	}
	if idp.ID != want.Allow.IdPID {
		return "", fmt.Errorf("identity provider %s is the one bound to Entra tenant %s, but the stored allow-list uses %s",
			idp.ID, want.EntraTenantID, want.Allow.IdPID)
	}
	return idp.ID, nil
}

// probeClient builds the HTTP client the challenge probe uses. It exists as
// its own function so a test can assert on the client the probe really makes,
// rather than on a copy of it.
//
// Redirects are not followed: the redirect is the evidence. The injected seam
// wins when one is set. Otherwise proxy and certificate trust are deliberately
// left as the defaults — the specification requires configured proxies and the
// host's trust store to be respected, and TLS verification against the
// hostname is what makes this probe evidence at all.
//
// Only the address dialled changes: the deployment host's resolver may be
// authoritative for this domain internally and answer NXDOMAIN for a name
// published at Cloudflare. That is a split-horizon resolver, not an
// unprotected hostname, so dialViaAuthority falls back to the addresses the
// zone's own authority gives. The certificate is still checked for the
// hostname in the URL.
func (c *Client) probeClient() *http.Client {
	httpc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if c.HTTP != nil {
		httpc.Transport, httpc.Timeout = c.HTTP.Transport, c.HTTP.Timeout
	}
	if httpc.Transport == nil {
		httpc.Transport = &http.Transport{
			Proxy:       http.ProxyFromEnvironment,
			DialContext: c.dialViaAuthority,
		}
	}
	return httpc
}

// accessLoginPath is the Access login endpoint for one protected hostname.
func accessLoginPath(hostname string) string {
	return "/cdn-cgi/access/login/" + strings.ToLower(hostname)
}

// accessChallenge makes one unauthenticated request to the hostname and
// reports the Access challenge it produced. Redirects are not followed: the
// redirect itself is the evidence, and it has to be the login for this
// application and this hostname. Matching the team domain alone would accept a
// redirect to some other Access application in the same account.
func (c *Client) accessChallenge(ctx context.Context, hostname, authDomain, aud string) (string, error) {
	target := "https://" + hostname + "/"
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.probeClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s to check that Access is enforcing: %v", target, err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
		return "", fmt.Errorf("%s answered HTTP %d with no Access challenge: the hostname is not protected", target, resp.StatusCode)
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("%s redirected to an unparsable location: %v", target, err)
	}
	if !strings.EqualFold(u.Host, authDomain) {
		return "", fmt.Errorf("%s redirected to %s, not the Access login at %s: the hostname is not protected", target, u.Host, authDomain)
	}
	if got := strings.ToLower(strings.TrimSuffix(u.Path, "/")); got != accessLoginPath(hostname) {
		return "", fmt.Errorf("%s redirected to %s, which is not the Access login for %s: another application's login is not proof that this hostname is protected",
			target, got, hostname)
	}
	if kid := u.Query().Get("kid"); !strings.EqualFold(kid, aud) {
		return "", fmt.Errorf("%s redirected to an Access login for audience %q, not this application's %q: that is a different Access application",
			target, kid, aud)
	}
	meta, err := decodeAccessMeta(u.Query().Get("meta"))
	if err != nil {
		return "", fmt.Errorf("%s redirected to %s but %v", target, u.Host, err)
	}
	if !strings.EqualFold(meta.Hostname, hostname) {
		return "", fmt.Errorf("%s redirected to an Access login describing hostname %q, not %s", target, meta.Hostname, hostname)
	}
	if !slices.ContainsFunc(meta.audiences(), func(a string) bool { return strings.EqualFold(a, aud) }) {
		return "", fmt.Errorf("%s redirected to an Access login describing audience %v, not this application's %q",
			target, meta.audiences(), aud)
	}
	if !strings.EqualFold(meta.AuthStatus, "NONE") {
		return "", fmt.Errorf("%s redirected to an Access login reporting auth_status %q: the probe was not anonymous, so it is no evidence about an anonymous visitor",
			target, meta.AuthStatus)
	}
	return fmt.Sprintf("HTTP %d to the Access login for %s at %s, audience %s, auth_status %s",
		resp.StatusCode, hostname, u.Host, aud, meta.AuthStatus), nil
}

// accessMeta is the payload of the JWT Access puts in the login redirect's
// "meta" parameter.
//
// Its signature is NOT verified, and cannot be: this probe is anonymous and
// holds no key for the team domain. The payload is therefore read as a
// description of the redirect and never as identity — it only has to agree
// with what the Cloudflare API already told us about the application. Nothing
// in it is trusted on its own, and no claim in it grants anything.
type accessMeta struct {
	Hostname string `json:"hostname"`
	// AUD follows JWT: either one string or a list of them.
	AUD        any    `json:"aud"`
	AuthStatus string `json:"auth_status"`
}

func decodeAccessMeta(token string) (accessMeta, error) {
	var m accessMeta
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[1] == "" {
		return m, errors.New("the Access login redirect carries no readable meta token, so it cannot be tied to this application")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return m, fmt.Errorf("the Access login redirect's meta token is not readable: %v", err)
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return m, fmt.Errorf("the Access login redirect's meta token is not readable: %v", err)
	}
	return m, nil
}

func (m accessMeta) audiences() []string {
	switch a := m.AUD.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, v := range a {
			out = append(out, fmt.Sprintf("%v", v))
		}
		return out
	}
	return nil
}
