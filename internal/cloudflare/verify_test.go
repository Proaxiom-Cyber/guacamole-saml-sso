package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// appAUD is the audience tag the API reports for this deployment's Access
// application. The login redirect has to carry this exact value; another
// application in the same account carries a different one.
const (
	appAUD   = "1a2b3c4d5e6f00112233445566778899aabbccddeeff00112233445566778899"
	otherAUD = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
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

// redirectTo replies to the probe with one Access login redirect.
func (f *fake) redirectTo(location string) {
	f.probe(func(*http.Request) *http.Response { return probeResponse(302, location) })
}

// metaToken builds the JWT Access puts in the login redirect's meta
// parameter. The signature is deliberately junk: the production code must not
// verify it (it cannot) and must read the payload as a description only.
func metaToken(t *testing.T, hostname, aud, status string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hostname": hostname, "aud": aud, "auth_status": status, "redirect_url": "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc(payload) + ".signature-not-verified"
}

// loginRedirect is the live deployment's observed challenge: a redirect to the
// team domain's login endpoint for this hostname, carrying the application's
// audience tag as kid and a meta token describing an anonymous request.
func loginRedirect(t *testing.T, domain, hostname, aud string) string {
	t.Helper()
	return "https://" + domain + "/cdn-cgi/access/login/" + hostname +
		"?kid=" + aud + "&meta=" + metaToken(t, hostname, aud, "NONE") + "&redirect_url=%2F"
}

func groupRule(groupID, idp string) map[string]any {
	return map[string]any{"azureAD": map[string]any{"id": groupID, "identity_provider_id": idp}}
}

func emailRule(addr string) map[string]any {
	return map[string]any{"email": map[string]any{"email": addr}}
}

// policies replies to the policy read with one stored policy carrying these
// include rules, named and decided as this deployment applies them.
func (f *fake) policies(include ...map[string]any) {
	f.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]map[string]any{
		{"id": "pol1", "name": wantPolicyNam, "decision": "allow", "include": include},
	})
}

func expectGroups() AccessExpectation {
	return AccessExpectation{Allow: allowGroups(), EntraTenantID: tenantID}
}

// verifyFake is a deployment that verifies: the application carries the
// marker and the hostname, its one policy allows exactly the two Entra groups
// that were applied, the account's Entra provider is the one they bind to, and
// an anonymous request is challenged by this application's own login.
func verifyFake(t *testing.T) (*fake, *Provisioner) {
	t.Helper()
	f := newFake(t)
	p := f.prov()
	f.mux["GET /accounts/acct1/access/apps/app1"] = ok(map[string]any{
		"id": "app1", "name": wantAppName, "domain": host, "aud": appAUD,
	})
	f.policies(groupRule(adminGroupID, idpID), groupRule(operGroupID, idpID))
	f.mux["GET /accounts/acct1/access/organizations"] = ok(map[string]string{"auth_domain": authDomain})
	f.mux["GET /accounts/acct1/access/identity_providers"] = ok([]map[string]any{
		{"id": "otp1", "name": "One-time PIN", "type": "onetimepin"},
		{"id": idpID, "name": "Entra ID", "type": "azureAD",
			"config": map[string]any{"directory_id": tenantID, "client_secret": testAPIToken}},
	})
	f.redirectTo(loginRedirect(t, authDomain, host, appAUD))
	return f, p
}

func TestVerifyAccess(t *testing.T) {
	f, p := verifyFake(t)
	f.probe(func(r *http.Request) *http.Response {
		if r.URL.String() != "https://"+host+"/" {
			t.Errorf("probe URL = %s", r.URL)
		}
		return probeResponse(302, loginRedirect(t, authDomain, host, appAUD))
	})

	v, err := p.VerifyAccess(context.Background(), "app1", expectGroups())
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !v.AppVerified || !v.PolicyMatchesAllowList || !v.IdPBoundToTenant || !v.ChallengeVerified {
		t.Fatalf("verification = %+v", v)
	}
	if v.PolicyID != "pol1" || v.AllowRules != 2 || v.AuthDomain != authDomain || v.AUD != appAUD || v.IdPID != idpID {
		t.Fatalf("verification = %+v", v)
	}
	if !strings.Contains(v.Challenge, "302") || !strings.Contains(v.Challenge, authDomain) {
		t.Fatalf("challenge evidence = %q", v.Challenge)
	}
}

// TestVerifyAccessRejectsAnotherApplicationsLogin is the gap this package had:
// a redirect was accepted on a bare ".cloudflareaccess.com" suffix, which any
// Access application in any account produces. The challenge only proves this
// hostname is protected if it is the login for this application and hostname.
func TestVerifyAccessRejectsAnotherApplicationsLogin(t *testing.T) {
	otherHost := "other.example.com"
	for _, tc := range []struct{ name, location, want string }{
		{"another account's team domain",
			loginRedirect(t, "someone-else.cloudflareaccess.com", host, appAUD),
			"not the Access login at"},
		{"another application's hostname",
			loginRedirect(t, authDomain, otherHost, appAUD),
			"not the Access login for"},
		{"another application's audience tag",
			"https://" + authDomain + "/cdn-cgi/access/login/" + host + "?kid=" + otherAUD +
				"&meta=" + metaToken(t, host, appAUD, "NONE"),
			"different Access application"},
		{"a meta token describing another hostname",
			"https://" + authDomain + "/cdn-cgi/access/login/" + host + "?kid=" + appAUD +
				"&meta=" + metaToken(t, otherHost, appAUD, "NONE"),
			"describing hostname"},
		{"a meta token describing another audience",
			"https://" + authDomain + "/cdn-cgi/access/login/" + host + "?kid=" + appAUD +
				"&meta=" + metaToken(t, host, otherAUD, "NONE"),
			"describing audience"},
		{"a meta token reporting an authenticated session",
			"https://" + authDomain + "/cdn-cgi/access/login/" + host + "?kid=" + appAUD +
				"&meta=" + metaToken(t, host, appAUD, "ACTIVE"),
			"auth_status"},
		{"no meta token at all",
			"https://" + authDomain + "/cdn-cgi/access/login/" + host + "?kid=" + appAUD,
			"no readable meta token"},
		{"somewhere else entirely",
			"https://login.example.com/", "not the Access login at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, p := verifyFake(t)
			f.redirectTo(tc.location)
			v, err := p.VerifyAccess(context.Background(), "app1", expectGroups())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a rejection mentioning %q, got %v", tc.want, err)
			}
			if v.ChallengeVerified {
				t.Fatal("a rejected challenge must not be reported as verified")
			}
			noSecret(t, err)
		})
	}

	// The origin answering directly means Access is not enforcing at all.
	f, p := verifyFake(t)
	f.probe(func(*http.Request) *http.Response { return probeResponse(200, "") })
	if _, err := p.VerifyAccess(context.Background(), "app1", expectGroups()); err == nil ||
		!strings.Contains(err.Error(), "not protected") {
		t.Fatalf("want an unprotected-hostname failure, got %v", err)
	}
}

// TestVerifyAccessRejectsAWidenedAllowList covers the drift that matters:
// anything stored under our own application that lets in more people than the
// allow-list this deployment applied.
func TestVerifyAccessRejectsAWidenedAllowList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		include []map[string]any
		want    string
		is      error
	}{
		{"an everyone rule",
			[]map[string]any{{"everyone": map[string]any{}}},
			"everyone", ErrAllowsEveryone},
		{"an everyone rule beside the applied groups",
			[]map[string]any{groupRule(adminGroupID, idpID), groupRule(operGroupID, idpID), {"everyone": map[string]any{}}},
			"everyone", ErrAllowsEveryone},
		{"an empty include set",
			[]map[string]any{}, "empty allow-list", ErrNoAllowList},
		{"an extra group nobody applied",
			[]map[string]any{groupRule(adminGroupID, idpID), groupRule(operGroupID, idpID),
				groupRule("cccc0000-0000-0000-0000-000000000009", idpID)},
			"not the applied allow-list", nil},
		{"one of the applied groups missing",
			[]map[string]any{groupRule(adminGroupID, idpID)},
			"not the applied allow-list", nil},
		{"a different group entirely",
			[]map[string]any{groupRule(adminGroupID, idpID), groupRule("cccc0000-0000-0000-0000-000000000009", idpID)},
			"not the applied allow-list", nil},
		{"an email rule nobody applied",
			[]map[string]any{groupRule(adminGroupID, idpID), groupRule(operGroupID, idpID), emailRule("anyone@example.com")},
			"not the applied allow-list", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, p := verifyFake(t)
			f.policies(tc.include...)
			v, err := p.VerifyAccess(context.Background(), "app1", expectGroups())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a rejection mentioning %q, got %v", tc.want, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("want %v, got %v", tc.is, err)
			}
			if v.PolicyMatchesAllowList {
				t.Fatal("a rejected allow-list must not be reported as matching")
			}
			noSecret(t, err)
		})
	}

	// A second policy on our own application can only add access, so it stops
	// verification even though ours is still correct.
	f, p := verifyFake(t)
	f.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]map[string]any{
		{"id": "pol1", "name": wantPolicyNam, "decision": "allow",
			"include": []map[string]any{groupRule(adminGroupID, idpID), groupRule(operGroupID, idpID)}},
		{"id": "pol2", "name": "Temporary contractor access", "decision": "allow",
			"include": []map[string]any{{"everyone": map[string]any{}}}},
	})
	_, err := p.VerifyAccess(context.Background(), "app1", expectGroups())
	if !errors.Is(err, ErrRequiresReview) || !strings.Contains(err.Error(), "Temporary contractor access") {
		t.Fatalf("want a second-policy review failure, got %v", err)
	}

	// A policy that no longer decides "allow" leaves the allow-list inert.
	f2, p2 := verifyFake(t)
	f2.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]map[string]any{
		{"id": "pol1", "name": wantPolicyNam, "decision": "bypass",
			"include": []map[string]any{groupRule(adminGroupID, idpID)}},
	})
	if _, err := p2.VerifyAccess(context.Background(), "app1", expectGroups()); err == nil ||
		!strings.Contains(err.Error(), "not in force") {
		t.Fatalf("want a decision failure, got %v", err)
	}

	// And an application with no policy of ours at all.
	f3, p3 := verifyFake(t)
	f3.mux["GET /accounts/acct1/access/apps/app1/policies"] = ok([]any{})
	if _, err := p3.VerifyAccess(context.Background(), "app1", expectGroups()); err == nil ||
		!strings.Contains(err.Error(), "no allow policy") {
		t.Fatalf("want a missing-policy failure, got %v", err)
	}
}

func TestVerifyAccessRejectsAWrongIdentityProvider(t *testing.T) {
	otherIdP := "00000000-1111-2222-3333-444444444444"

	// The stored rules bind to an identity provider this deployment never
	// applied: the same group object ID in a different directory is a
	// different set of people, so it is not the applied allow-list.
	f, p := verifyFake(t)
	f.policies(groupRule(adminGroupID, otherIdP), groupRule(operGroupID, otherIdP))
	v0, err := p.VerifyAccess(context.Background(), "app1", expectGroups())
	if err == nil || !strings.Contains(err.Error(), "not the applied allow-list") {
		t.Fatalf("want an identity-provider rejection, got %v", err)
	}
	if v0.IdPBoundToTenant {
		t.Fatal("a rejected identity provider must not be reported as bound")
	}
	noSecret(t, err)

	// The account's Entra provider for this tenant is not the one the stored
	// rules use, so the allow-list authorises the wrong directory.
	f2, p2 := verifyFake(t)
	f2.mux["GET /accounts/acct1/access/identity_providers"] = ok([]map[string]any{
		{"id": otherIdP, "name": "Entra ID", "type": "azureAD",
			"config": map[string]any{"directory_id": tenantID}},
	})
	_, err = p2.VerifyAccess(context.Background(), "app1", expectGroups())
	if err == nil || !strings.Contains(err.Error(), "bound to Entra tenant") {
		t.Fatalf("want a tenant-binding rejection, got %v", err)
	}

	// No Entra provider for the tenant at all.
	f3, p3 := verifyFake(t)
	f3.mux["GET /accounts/acct1/access/identity_providers"] = ok([]any{})
	_, err = p3.VerifyAccess(context.Background(), "app1", expectGroups())
	if err == nil || !strings.Contains(err.Error(), "no Access identity provider is bound") {
		t.Fatalf("want a missing-provider rejection, got %v", err)
	}

	// Group rules with no tenant to check them against are not verifiable, and
	// must not pass as if they were.
	f4, p4 := verifyFake(t)
	_ = f4
	v, err := p4.VerifyAccess(context.Background(), "app1", AccessExpectation{Allow: allowGroups()})
	if err == nil || !strings.Contains(err.Error(), "no Entra tenant ID was supplied") {
		t.Fatalf("want a missing-tenant rejection, got %v", err)
	}
	if v.IdPBoundToTenant {
		t.Fatal("an unverifiable binding must not be reported as verified")
	}
}

func TestVerifyAccessEmailAllowList(t *testing.T) {
	f, p := verifyFake(t)
	f.policies(emailRule("ops@example.com"))
	v, err := p.VerifyAccess(context.Background(), "app1",
		AccessExpectation{Allow: Allow{Emails: []string{"ops@example.com"}}})
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !v.PolicyMatchesAllowList || !v.ChallengeVerified {
		t.Fatalf("verification = %+v", v)
	}
	// An email allow-list has no identity-provider binding, so none is claimed.
	if v.IdPBoundToTenant || v.IdPID != "" {
		t.Fatalf("an email allow-list must claim no identity-provider binding: %+v", v)
	}
	if !strings.Contains(v.String(), "no Entra identity-provider binding was verified") {
		t.Fatalf("summary = %q", v.String())
	}
}

// TestVerifyAccessWithoutAnExpectation pins what an unwired caller gets: the
// checks that need no input still run, and the evidence says plainly that the
// stored allow-list was never compared with the applied one.
func TestVerifyAccessWithoutAnExpectation(t *testing.T) {
	f, p := verifyFake(t)
	v, err := p.VerifyAccess(context.Background(), "app1")
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	if !v.AppVerified || !v.ChallengeVerified {
		t.Fatalf("verification = %+v", v)
	}
	if v.PolicyMatchesAllowList || v.IdPBoundToTenant {
		t.Fatalf("nothing was compared, so nothing may be claimed: %+v", v)
	}
	if !strings.Contains(v.String(), "not compared with the applied allow-list") {
		t.Fatalf("summary = %q", v.String())
	}

	// An everyone rule is still caught without an expectation: it is the one
	// condition that must never be reported as verified.
	f.policies(map[string]any{"everyone": map[string]any{}})
	if _, err := p.VerifyAccess(context.Background(), "app1"); !errors.Is(err, ErrAllowsEveryone) {
		t.Fatalf("want ErrAllowsEveryone, got %v", err)
	}
	f.policies()
	if _, err := p.VerifyAccess(context.Background(), "app1"); !errors.Is(err, ErrNoAllowList) {
		t.Fatalf("want ErrNoAllowList, got %v", err)
	}
}

// TestVerificationNeverClaimsASignIn is the honesty check. A reachable login
// page is not a login, and nothing this package reports may read as one.
func TestVerificationNeverClaimsASignIn(t *testing.T) {
	_, p := verifyFake(t)
	v, err := p.VerifyAccess(context.Background(), "app1", expectGroups())
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}
	summary := v.String()
	if !strings.Contains(summary, SignInNotProven) {
		t.Fatalf("the summary must say what is unproven: %q", summary)
	}
	for _, claim := range []string{"signed in", "logged in", "sign-in succeeded", "authenticated successfully"} {
		if strings.Contains(strings.ToLower(summary), claim) {
			t.Fatalf("the summary claims a sign-in (%q): %q", claim, summary)
		}
	}
	if strings.Contains(strings.ToLower(SignInNotProven), "successful login") {
		t.Fatalf("the constant reads as a claim: %q", SignInNotProven)
	}
}

// TestChallengeProbeKeepsProxyAndTLSVerification pins two properties of
// the verification probe. It must honour a configured proxy, because the
// specification requires it and a deployment behind one would otherwise
// fail for the wrong reason. And it must keep TLS verification against the
// hostname: an unverified handshake would make the probe worthless as
// evidence that the right hostname is protected.
func TestChallengeProbeKeepsProxyAndTLSVerification(t *testing.T) {
	c := &Client{}
	// The client the probe really builds, not a copy of it: a copy would keep
	// passing after the real one changed.
	httpc := c.probeClient()
	tr, isTransport := httpc.Transport.(*http.Transport)
	if !isTransport {
		t.Fatalf("the probe transport is %T", httpc.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("the probe ignores a configured proxy")
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the probe disables certificate verification, so it proves nothing")
	}
	if tr.DialContext == nil {
		t.Fatal("the probe cannot resolve through the zone's authority, so a split-horizon resolver fails it")
	}
	if httpc.CheckRedirect == nil {
		t.Fatal("the probe follows redirects, so the challenge itself is never seen")
	}
	// An injected seam is used as it is, transport and timeout both.
	injected := &http.Client{Transport: &http.Transport{}, Timeout: 9}
	seam := (&Client{HTTP: injected}).probeClient()
	if seam.Transport != injected.Transport || seam.Timeout != injected.Timeout {
		t.Fatal("the probe ignores the injected HTTP seam")
	}

	// With no authority known, the failure explains itself rather than
	// silently succeeding.
	_, err := c.resolveAtAuthority(context.Background(), "guac.example.com")
	if err == nil || !strings.Contains(err.Error(), "no authoritative nameservers") {
		t.Fatalf("want an explanatory error, got %v", err)
	}
}

// TestVerifyLearnsTheAuthorityOnAResumedRun pins a live failure: on a
// resumed deployment the phase that selected the zone is skipped, so
// nothing had recorded the zone's nameservers and the probe had no way to
// resolve a hostname this host's resolver cannot see. Verification must
// learn the authority itself.
func TestVerifyLearnsTheAuthorityOnAResumedRun(t *testing.T) {
	f := newFake(t)
	f.mux["GET /zones/zone1"] = ok(map[string]any{
		"id": "zone1", "name": "example.com",
		"name_servers": []any{"ns1.example.invalid", "ns2.example.invalid"},
	})
	p := f.prov()
	if len(p.Client.AuthorityNameServers) != 0 {
		t.Fatal("precondition: the authority should be unknown")
	}
	p.ensureAuthority(context.Background())
	if len(p.Client.AuthorityNameServers) != 2 {
		t.Fatalf("the authority was not learned: %v", p.Client.AuthorityNameServers)
	}
	// Already known: no second lookup, and the value is left alone.
	p.Client.AuthorityNameServers = []string{"kept"}
	p.ensureAuthority(context.Background())
	if len(p.Client.AuthorityNameServers) != 1 || p.Client.AuthorityNameServers[0] != "kept" {
		t.Fatalf("a known authority was overwritten: %v", p.Client.AuthorityNameServers)
	}
}

// The live defect: the record was published and Access was verified against
// it in the same breath, before the zone's authority served it. The wait
// belongs between the two, and it must succeed as soon as an answer appears.
func TestWaitResolvableReturnsAsSoonAsTheRecordIsAnswered(t *testing.T) {
	asked := 0
	p := &Provisioner{
		Client:   &Client{},
		Hostname: "guac.example.com",
		Resolve: func(context.Context, string) ([]string, error) {
			asked++
			if asked < 3 {
				return nil, errors.New("no such host")
			}
			return []string{"104.21.0.1"}, nil
		},
	}
	if err := p.WaitResolvable(context.Background(), time.Second, time.Millisecond); err != nil {
		t.Fatalf("a record that appears on the third ask must satisfy the wait: %v", err)
	}
	if asked != 3 {
		t.Fatalf("want three lookups, got %d", asked)
	}
}

// A hostname that never resolves is reported, with what was asked, rather
// than waited on for ever or passed to the probe as if it were fine.
func TestWaitResolvableReportsAHostnameThatNeverAppears(t *testing.T) {
	p := &Provisioner{
		Client:   &Client{AuthorityNameServers: []string{"cash.ns.cloudflare.com"}},
		Hostname: "guac.example.com",
		Resolve: func(context.Context, string) ([]string, error) {
			return nil, errors.New("no such host")
		},
	}
	err := p.WaitResolvable(context.Background(), 10*time.Millisecond, time.Millisecond)
	if err == nil {
		t.Fatal("a hostname that never resolves must be reported")
	}
	for _, want := range []string{"was published but is not answered yet", "cash.ns.cloudflare.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not say %q: %v", want, err)
		}
	}
}
