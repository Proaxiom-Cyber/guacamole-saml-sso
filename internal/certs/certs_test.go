package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

const testHost = "guac.example.com"

// --- a certificate authority for the fake ACME server ------------------

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test ACME CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{key: key, cert: cert, der: der}
}

// issueFor signs a leaf certificate for the CSR's subject.
func (ca *testCA) issueFor(csrDER []byte, notAfter time.Time) ([][]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return [][]byte{der, ca.der}, nil
}

// --- a fake ACME client ------------------------------------------------

// fakeACME drives the issuance flow without an ACME server. Failures are
// injected per step so the cleanup and "keep the existing certificate"
// guarantees can be exercised at each one.
type fakeACME struct {
	ca       *testCA
	notAfter time.Time

	authzStatus string // "" means pending
	challenges  []*acme.Challenge

	failRegister, failAuthorizeOrder, failAccept error
	failWaitAuthz, failWaitOrder, failCreateCert error

	registered, accepted, created int
	lastCSR                       []byte
}

func (f *fakeACME) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	f.registered++
	if f.failRegister != nil {
		return nil, f.failRegister
	}
	return &acme.Account{URI: "https://acme.test/acct/1", Status: acme.StatusValid}, nil
}

func (f *fakeACME) GetReg(context.Context, string) (*acme.Account, error) {
	return &acme.Account{URI: "https://acme.test/acct/1", Status: acme.StatusValid}, nil
}

func (f *fakeACME) AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error) {
	if f.failAuthorizeOrder != nil {
		return nil, f.failAuthorizeOrder
	}
	return &acme.Order{URI: "https://acme.test/order/1", FinalizeURL: "https://acme.test/order/1/finalize",
		AuthzURLs: []string{"https://acme.test/authz/1"}}, nil
}

func (f *fakeACME) GetAuthorization(_ context.Context, url string) (*acme.Authorization, error) {
	chals := f.challenges
	if chals == nil {
		chals = []*acme.Challenge{{Type: "http-01", Token: "wrong"}, {Type: "dns-01", Token: "tok", URI: "https://acme.test/chal/1"}}
	}
	st := f.authzStatus
	if st == "" {
		st = acme.StatusPending
	}
	return &acme.Authorization{URI: url, Status: st, Identifier: acme.AuthzID{Type: "dns", Value: testHost}, Challenges: chals}, nil
}

func (f *fakeACME) DNS01ChallengeRecord(token string) (string, error) {
	return "dns01-for-" + token, nil
}

func (f *fakeACME) Accept(_ context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	f.accepted++
	if f.failAccept != nil {
		return nil, f.failAccept
	}
	return chal, nil
}

func (f *fakeACME) WaitAuthorization(_ context.Context, url string) (*acme.Authorization, error) {
	if f.failWaitAuthz != nil {
		return nil, f.failWaitAuthz
	}
	return &acme.Authorization{URI: url, Status: acme.StatusValid}, nil
}

func (f *fakeACME) WaitOrder(_ context.Context, url string) (*acme.Order, error) {
	if f.failWaitOrder != nil {
		return nil, f.failWaitOrder
	}
	return &acme.Order{URI: url, Status: acme.StatusReady}, nil
}

func (f *fakeACME) CreateOrderCert(_ context.Context, _ string, csr []byte, _ bool) ([][]byte, string, error) {
	f.created++
	f.lastCSR = csr
	if f.failCreateCert != nil {
		return nil, "", f.failCreateCert
	}
	notAfter := f.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	chain, err := f.ca.issueFor(csr, notAfter)
	return chain, "https://acme.test/cert/1", err
}

// --- a fake DNS-01 solver ----------------------------------------------

type fakeSolver struct {
	presented  []string
	cleaned    int
	presentErr error
	cleanErr   error
}

func (s *fakeSolver) Present(_ context.Context, value string) error {
	s.presented = append(s.presented, value)
	return s.presentErr
}

func (s *fakeSolver) CleanUp(context.Context) error {
	s.cleaned++
	return s.cleanErr
}

// --- harness -----------------------------------------------------------

type harness struct {
	o      Options
	acme   *fakeACME
	solver *fakeSolver
	ca     *testCA
	ran    [][]string // commands the reload seam was asked to run
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	install := filepath.Join(dir, "opt")
	stateDir := filepath.Join(dir, "state")
	for _, d := range []string{filepath.Join(install, "nginx", "certs"), stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h := &harness{ca: newTestCA(t), solver: &fakeSolver{}}
	h.acme = &fakeACME{ca: h.ca}
	h.o = Options{
		Hostname: testHost, InstallDir: install, StateDir: stateDir,
		DirectoryURL: "https://acme.test/directory",
		DNS:          h.solver,
		Run: func(_ context.Context, _, name string, args ...string) (string, string, error) {
			h.ran = append(h.ran, append([]string{name}, args...))
			return "", "", nil
		},
		newACME: func(crypto.Signer, string, *http.Client) acmeClient { return h.acme },
	}
	return h
}

// writeLeaf installs a certificate that the test CA issued, expiring at
// notAfter, as if an earlier renewal had put it there.
func (h *harness) writeLeaf(t *testing.T, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: testHost}, DNSNames: []string{testHost}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := h.ca.issueFor(csr, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	if err := install(h.o, chain, key); err != nil {
		t.Fatal(err)
	}
}

// writeSelfSigned installs the placeholder internal/stack renders.
func (h *harness) writeSelfSigned(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: testHost},
		DNSNames: []string{testHost}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := install(h.o, [][]byte{der}, key); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- issuance ----------------------------------------------------------

func TestIssueInstallsTheChainAndAnOwnerOnlyKey(t *testing.T) {
	h := newHarness(t)

	got, err := Issue(context.Background(), h.o)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got.Subject != "CN="+testHost {
		t.Errorf("subject = %q", got.Subject)
	}
	if got.SelfSigned {
		t.Error("an issued certificate must not report as self-signed")
	}
	if got.Issuer != "CN=Test ACME CA" {
		t.Errorf("issuer = %q", got.Issuer)
	}
	if got.AccountURL != "https://acme.test/acct/1" {
		t.Errorf("account URL = %q", got.AccountURL)
	}

	// The whole chain lands, not just the leaf: cloudflared needs the
	// intermediate to build a path to a public root.
	if n := strings.Count(readFile(t, h.o.CertPath()), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("installed chain holds %d certificates, want 2", n)
	}
	fi, err := os.Stat(h.o.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(h.o.AccountKeyPath()); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("ACME account key mode = %v, want 0600", fi.Mode().Perm())
	}
	// No temporary file is left behind for anything to read.
	if _, err := os.Stat(h.o.KeyPath() + ".new"); !os.IsNotExist(err) {
		t.Error("a temporary key file was left in the certificate directory")
	}
}

func TestIssuedValuesHoldNoKeyMaterial(t *testing.T) {
	h := newHarness(t)
	got, err := Issue(context.Background(), h.o)
	if err != nil {
		t.Fatal(err)
	}
	// A distinctive slice of the real key, long enough that a match cannot
	// be coincidence.
	keyPEM := readFile(t, h.o.KeyPath())
	blk, _ := pem.Decode([]byte(keyPEM))
	if blk == nil {
		t.Fatal("the installed key is not PEM")
	}
	secret := strings.SplitN(strings.TrimSpace(keyPEM), "\n", 2)[1][:40]
	acctSecret := strings.SplitN(strings.TrimSpace(readFile(t, h.o.AccountKeyPath())), "\n", 2)[1][:40]

	s := Status{Certificate: got.Certificate, AccountURL: got.AccountURL, Result: ResultOK}
	if err := WriteStatus(h.o.StateDir, s); err != nil {
		t.Fatal(err)
	}
	for what, text := range map[string]string{
		"the returned value": fmt.Sprintf("%+v", got),
		"the status record":  readFile(t, StatusPath(h.o.StateDir)),
		"the status summary": s.Summary(),
	} {
		for _, sec := range []string{secret, acctSecret, "PRIVATE KEY"} {
			if strings.Contains(text, sec) {
				t.Errorf("%s carries key material", what)
			}
		}
	}
	if fi, err := os.Stat(StatusPath(h.o.StateDir)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("status file mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestIssueRemovesTheChallengeRecordOnSuccess(t *testing.T) {
	h := newHarness(t)
	if _, err := Issue(context.Background(), h.o); err != nil {
		t.Fatal(err)
	}
	if h.solver.cleaned != 1 {
		t.Errorf("challenge cleaned up %d times, want 1", h.solver.cleaned)
	}
	if want := []string{"dns01-for-tok"}; len(h.solver.presented) != 1 || h.solver.presented[0] != want[0] {
		t.Errorf("presented %v, want %v", h.solver.presented, want)
	}
}

// The challenge record must go away whatever fails, because a stale
// _acme-challenge record is a standing authorisation to issue a certificate
// for this hostname.
func TestIssueRemovesTheChallengeRecordOnEveryFailure(t *testing.T) {
	boom := errors.New("boom")
	for name, setup := range map[string]func(*harness){
		"the record cannot be published": func(h *harness) { h.solver.presentErr = boom },
		"the challenge is refused":       func(h *harness) { h.acme.failAccept = boom },
		"validation fails":               func(h *harness) { h.acme.failWaitAuthz = boom },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			setup(h)
			if _, err := Issue(context.Background(), h.o); err == nil {
				t.Fatal("Issue succeeded although the step failed")
			}
			if h.solver.cleaned != 1 {
				t.Errorf("challenge cleaned up %d times, want 1", h.solver.cleaned)
			}
		})
	}
}

func TestIssueReportsAFailedCleanUpAlongsideTheRealFailure(t *testing.T) {
	h := newHarness(t)
	h.acme.failWaitAuthz = errors.New("the authority did not validate")
	h.solver.cleanErr = errors.New("the record could not be removed")

	_, err := Issue(context.Background(), h.o)
	if err == nil {
		t.Fatal("Issue succeeded although validation failed")
	}
	for _, want := range []string{"did not validate", "could not be removed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestIssueCleansUpEvenWhenTheContextIsCancelled(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.solver.presentErr = context.Canceled
	cancel()

	if _, err := Issue(ctx, h.o); err == nil {
		t.Fatal("Issue succeeded on a cancelled context")
	}
	if h.solver.cleaned != 1 {
		t.Errorf("challenge cleaned up %d times on cancellation, want 1", h.solver.cleaned)
	}
}

func TestIssueSkipsAnAuthorizationThatIsAlreadyValid(t *testing.T) {
	h := newHarness(t)
	h.acme.authzStatus = acme.StatusValid
	if _, err := Issue(context.Background(), h.o); err != nil {
		t.Fatal(err)
	}
	if len(h.solver.presented) != 0 {
		t.Error("a valid authorization was solved again")
	}
}

func TestIssueRefusesWhenNoDNSChallengeIsOffered(t *testing.T) {
	h := newHarness(t)
	h.acme.challenges = []*acme.Challenge{{Type: "http-01", Token: "tok"}}
	_, err := Issue(context.Background(), h.o)
	if err == nil || !strings.Contains(err.Error(), "dns-01") {
		t.Fatalf("error = %v, want a dns-01 complaint", err)
	}
}

func TestIssueReusesOneACMEAccountKey(t *testing.T) {
	h := newHarness(t)
	if _, err := Issue(context.Background(), h.o); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, h.o.AccountKeyPath())
	if _, err := Issue(context.Background(), h.o); err != nil {
		t.Fatal(err)
	}
	if readFile(t, h.o.AccountKeyPath()) != first {
		t.Error("the second issuance replaced the ACME account key")
	}
}

func TestIssueUsesTheProductionDirectoryByDefault(t *testing.T) {
	o := Options{Hostname: testHost, InstallDir: "/tmp/x", StateDir: "/tmp/y"}
	if err := o.defaults(); err != nil {
		t.Fatal(err)
	}
	if o.DirectoryURL != acme.LetsEncryptURL {
		t.Errorf("default directory = %q, want Let's Encrypt production", o.DirectoryURL)
	}
	if !strings.Contains(StagingDirectory, "staging") {
		t.Errorf("staging directory = %q", StagingDirectory)
	}
}

// A live run created a Cloudflare tunnel and rendered the whole stack before
// the certificate authority refused the contact it had been given. The check
// costs nothing at the start, and a bare email address is what an operator
// obviously means.
func TestNormaliseContact(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		wantErr        string
	}{
		{name: "empty stays empty: the contact is optional", in: "", want: ""},
		{name: "a bare address gets the scheme it needs",
			in: "ops@example.com", want: "mailto:ops@example.com"},
		{name: "an address that already has the scheme is kept",
			in: "mailto:ops@example.com", want: "mailto:ops@example.com"},
		{name: "surrounding space does not make it a different address",
			in: "  ops@example.com  ", want: "mailto:ops@example.com"},
		{name: "the scheme is matched without regard to case",
			in: "MAILTO:ops@example.com", want: "mailto:ops@example.com"},
		{name: "another scheme is refused, naming the one that works",
			in: "tel:+61000", wantErr: "only mailto"},
		{name: "something that is not an address at all is refused",
			in: "ops", wantErr: "not an email address"},
		{name: "an address with no local part is refused",
			in: "@example.com", wantErr: "not an email address"},
		{name: "an address with no domain is refused",
			in: "ops@", wantErr: "not an email address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormaliseContact(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("%q was accepted, and would have failed at the certificate authority", tc.in)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("the error does not say %q: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
