// Package certs issues and renews the nginx origin certificate: a Let's
// Encrypt certificate for the deployment hostname, proved by an ACME DNS-01
// challenge in Cloudflare DNS.
//
// # Which certificate this is
//
// Two different certificates protect one hostname, and they are not
// interchangeable:
//
//   - The browser-facing certificate is Cloudflare's. Cloudflare issues,
//     serves and renews it at the edge. This tool never touches it.
//   - The origin certificate is this one. It lives in the deployment at
//     nginx/certs/fullchain.pem, nginx serves it on 443, and the only client
//     that ever sees it is cloudflared inside the same stack. cloudflared
//     verifies it against the public roots with the deployment hostname as
//     the server name, because the tunnel ingress sets noTLSVerify=false
//     (specification: "Keep certificate verification enabled between the
//     tunnel and origin").
//
// Until this package runs, nginx serves the temporary self-signed
// certificate internal/stack wrote, cloudflared refuses the origin, and the
// public hostname returns an origin-TLS error. Verify reports exactly that
// distinction, and Renew replaces the self-signed certificate on its first
// successful run.
//
// # Failure never weakens TLS
//
// Nothing in this package can disable certificate verification, and nothing
// here writes noTLSVerify. A failed renewal leaves the installed certificate
// exactly where it is — new files are written only after a complete chain is
// in hand, through a temporary file and a rename — records the failure, and
// exits nonzero. The worst case is an expired origin certificate and a
// visibly broken hostname, never a silently unverified one.
//
// # Secrecy
//
// The ACME account key and the certificate key are generated in memory. The
// certificate key is written to nginx/certs/privkey.pem with owner-only
// permissions because nginx must read it; the account key is written to the
// state directory with owner-only permissions so renewal reuses one ACME
// account. Neither ever enters a returned value, the last-run record,
// deployment state, an error, or any log line. The only account detail that
// leaves this package is the account URL, which is a non-secret reference.
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// ACME directories. Production is the default; staging issues untrusted
// certificates against far larger rate limits, which is what a rehearsal on
// the test platform wants.
const (
	ProductionDirectory = acme.LetsEncryptURL
	StagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// DefaultRenewBefore is how long before expiry a certificate is renewed.
// Let's Encrypt certificates last 90 days, so 30 leaves two further daily
// attempts a week for a fortnight before anything expires.
const DefaultRenewBefore = 30 * 24 * time.Hour

// Solver presents and removes the DNS-01 challenge record.
// *cloudflare.DNS01 implements it.
type Solver interface {
	// Present publishes the challenge value and waits until it resolves.
	Present(ctx context.Context, value string) error
	// CleanUp removes the challenge records this deployment created, and
	// only those. It is called on every path, success and failure alike.
	CleanUp(ctx context.Context) error
}

// Runner executes a command, returning stdout and stderr separately. Same
// shape as schedule.Runner and backup.Runner.
type Runner func(ctx context.Context, stdin, name string, args ...string) (stdout, stderr string, err error)

// ExecRunner is the real command seam.
func ExecRunner(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errs strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	return out.String(), errs.String(), err
}

// Options configures issuance, renewal and reporting for one deployment.
type Options struct {
	Hostname   string // the deployment hostname, also the certificate subject
	InstallDir string // stack installation directory, e.g. /opt/guacamole
	StateDir   string // holds the ACME account key and the last-run record

	// DirectoryURL selects the CA; "" means ProductionDirectory. Set it to
	// StagingDirectory to rehearse without spending a production rate limit.
	DirectoryURL string
	// Contact is an optional operator address registered with the ACME
	// account, e.g. "mailto:ops@example.com". Let's Encrypt uses it for
	// expiry warnings only.
	Contact string
	// RenewBefore is the remaining lifetime at which Renew acts; 0 means
	// DefaultRenewBefore.
	RenewBefore time.Duration

	DNS  Solver       // required for issuance
	Run  Runner       // command seam for the nginx reload; nil means ExecRunner
	HTTP *http.Client // ACME transport; nil means the default

	// VerifyAddr is the origin address Verify dials; "" means
	// 127.0.0.1:443.
	VerifyAddr string

	// Now supplies the current time; nil means time.Now. Tests set it to
	// drive the renewal decision.
	Now func() time.Time

	// newACME builds the ACME client. It exists so tests can drive the
	// issuance flow without an ACME server; *acme.Client is the only real
	// implementation.
	newACME func(key crypto.Signer, directoryURL string, hc *http.Client) acmeClient
}

// acmeClient is the part of *acme.Client this package uses.
type acmeClient interface {
	Register(ctx context.Context, a *acme.Account, prompt func(tosURL string) bool) (*acme.Account, error)
	GetReg(ctx context.Context, url string) (*acme.Account, error)
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	DNS01ChallengeRecord(token string) (string, error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error)
}

func (o *Options) defaults() error {
	if o.Hostname == "" || o.InstallDir == "" || o.StateDir == "" {
		return errors.New("the origin certificate needs a hostname, an installation directory and a state directory")
	}
	if o.DirectoryURL == "" {
		o.DirectoryURL = ProductionDirectory
	}
	if o.RenewBefore == 0 {
		o.RenewBefore = DefaultRenewBefore
	}
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.VerifyAddr == "" {
		o.VerifyAddr = "127.0.0.1:443"
	}
	if o.newACME == nil {
		o.newACME = func(key crypto.Signer, dir string, hc *http.Client) acmeClient {
			return &acme.Client{Key: key, DirectoryURL: dir, HTTPClient: hc, UserAgent: "guacdeploy"}
		}
	}
	return nil
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// CertPath and KeyPath are the files nginx reads, as internal/stack renders
// them. Issue replaces both.
func (o Options) CertPath() string {
	return filepath.Join(o.InstallDir, "nginx", "certs", "fullchain.pem")
}
func (o Options) KeyPath() string {
	return filepath.Join(o.InstallDir, "nginx", "certs", "privkey.pem")
}

// AccountKeyPath is the ACME account key: owner-only, in the state
// directory, outside the stack's bind-mounted certificate directory.
func (o Options) AccountKeyPath() string { return filepath.Join(o.StateDir, "acme-account.key") }

// Certificate is non-secret evidence about an installed certificate.
type Certificate struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
}

// Issued is what a successful issuance produced. It carries no key material.
type Issued struct {
	Certificate
	AccountURL   string
	DirectoryURL string
}

// Inspect reads the leaf certificate at path. It never reads the key.
func Inspect(path string) (Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Certificate{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return Certificate{}, fmt.Errorf("%s does not start with a PEM certificate", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("%s is not a readable certificate: %w", path, err)
	}
	return Certificate{
		Subject:    c.Subject.String(),
		Issuer:     c.Issuer.String(),
		Serial:     c.SerialNumber.String(),
		NotAfter:   c.NotAfter.UTC(),
		SelfSigned: c.Issuer.String() == c.Subject.String(),
	}, nil
}

// Issue obtains a certificate for the deployment hostname and installs it,
// replacing whatever is there — including the temporary self-signed
// certificate internal/stack wrote.
//
// Nothing is written until the CA has returned a complete chain, so a
// failure at any earlier step leaves the installed certificate untouched.
func Issue(ctx context.Context, o Options) (Issued, error) {
	if err := o.defaults(); err != nil {
		return Issued{}, err
	}
	if o.DNS == nil {
		return Issued{}, errors.New("issuing a certificate needs a DNS-01 solver")
	}
	accountKey, err := loadOrCreateAccountKey(o.AccountKeyPath())
	if err != nil {
		return Issued{}, err
	}
	client := o.newACME(accountKey, o.DirectoryURL, o.HTTP)

	acct := &acme.Account{}
	if o.Contact != "" {
		acct.Contact = []string{o.Contact}
	}
	reg, err := client.Register(ctx, acct, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		reg, err = client.GetReg(ctx, "")
	}
	if err != nil {
		return Issued{}, fmt.Errorf("register with the certificate authority at %s: %w", o.DirectoryURL, err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(o.Hostname))
	if err != nil {
		return Issued{}, fmt.Errorf("request a certificate for %s: %w", o.Hostname, err)
	}
	for _, url := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, url)
		if err != nil {
			return Issued{}, err
		}
		if authz.Status == acme.StatusValid {
			continue // a still-valid authorization from an earlier order
		}
		if err := solveDNS01(ctx, o, client, authz); err != nil {
			return Issued{}, err
		}
	}
	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return Issued{}, fmt.Errorf("the certificate authority did not accept the order for %s: %w", o.Hostname, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Issued{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: o.Hostname}, DNSNames: []string{o.Hostname},
	}, key)
	if err != nil {
		return Issued{}, err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return Issued{}, fmt.Errorf("collect the certificate for %s: %w", o.Hostname, err)
	}
	if len(chain) == 0 {
		return Issued{}, fmt.Errorf("the certificate authority returned an empty chain for %s", o.Hostname)
	}
	if err := install(o, chain, key); err != nil {
		return Issued{}, err
	}
	info, err := Inspect(o.CertPath())
	if err != nil {
		return Issued{}, err
	}
	return Issued{Certificate: info, AccountURL: reg.URI, DirectoryURL: o.DirectoryURL}, nil
}

// solveDNS01 publishes the challenge record, accepts the challenge and waits
// for the CA's answer.
//
// The challenge record is removed on every path. The deferred cleanup is
// registered before the record is created, so a failed creation, a failed
// visibility wait, a rejected challenge and a cancelled context all clean up
// too. A stale _acme-challenge record is not litter: it is a standing
// authorisation to issue a certificate for this hostname.
func solveDNS01(ctx context.Context, o Options, c acmeClient, authz *acme.Authorization) (err error) {
	var chal *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			chal = ch
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("the certificate authority offered no dns-01 challenge for %s", authz.Identifier.Value)
	}
	value, err := c.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	defer func() {
		// Cleanup must run even when ctx is already cancelled, otherwise
		// cancelling setup leaves the record behind.
		if cerr := o.DNS.CleanUp(context.WithoutCancel(ctx)); cerr != nil {
			err = errors.Join(err, fmt.Errorf("remove the DNS-01 challenge record: %w", cerr))
		}
	}()
	if err := o.DNS.Present(ctx, value); err != nil {
		return err
	}
	if _, err := c.Accept(ctx, chal); err != nil {
		return fmt.Errorf("submit the dns-01 challenge for %s: %w", authz.Identifier.Value, err)
	}
	if _, err := c.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("the certificate authority did not validate %s: %w", authz.Identifier.Value, err)
	}
	return nil
}

// install writes the key and the chain, key first and both through a
// temporary file and a rename, so nginx never reads a half-written file and
// never sees a chain whose key has not landed yet.
func install(o Options, chain [][]byte, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	var certPEM []byte
	for _, b := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	if err := writeAtomic(o.KeyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	// The certificate is public; nginx reads it as a non-root container user
	// through the bind mount, exactly as internal/stack renders it.
	return writeAtomic(o.CertPath(), certPEM, 0o644)
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile does not apply mode to an existing file left by an
	// interrupted earlier run.
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// loadOrCreateAccountKey returns the deployment's ACME account key, creating
// it on first use. Reusing one account key across renewals keeps one ACME
// account per deployment, so the recorded account URL stays true and repeated
// renewals do not register a new account each time.
func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("%s is not a readable ACME account key", path)
		}
		key, err := x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s is not a readable ACME account key: %w", path, err)
		}
		return key, nil
	case !os.IsNotExist(err):
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// NormaliseContact turns an operator address into the form ACME accepts, or
// explains why it cannot.
//
// ACME takes a URI, and Let's Encrypt supports only the mailto scheme. An
// operator who passes a bare address means the obvious thing, so it is
// accepted and given the scheme. Anything else is refused here, where it costs
// nothing, rather than at account registration — a live run reached that
// registration only after creating a Cloudflare tunnel and rendering the
// stack, and failed with the CA's own wording:
//
//	400 urn:ietf:params:acme:error:unsupportedContact: Error validating
//	contact(s) :: only contact scheme 'mailto:' is supported
func NormaliseContact(contact string) (string, error) {
	c := strings.TrimSpace(contact)
	if c == "" {
		return "", nil // optional: the account is registered without one
	}
	if scheme, rest, ok := strings.Cut(c, ":"); ok && !strings.Contains(scheme, "@") {
		if !strings.EqualFold(scheme, "mailto") {
			return "", fmt.Errorf("the certificate account contact %q uses the %q scheme; the certificate authority accepts only mailto, so pass an email address", contact, scheme)
		}
		c = "mailto:" + strings.TrimSpace(rest)
	} else {
		c = "mailto:" + c
	}
	addr := strings.TrimPrefix(c, "mailto:")
	if at := strings.Index(addr, "@"); at <= 0 || at == len(addr)-1 || strings.ContainsAny(addr, " \t") {
		return "", fmt.Errorf("the certificate account contact %q is not an email address; the certificate authority uses it to warn about expiry", contact)
	}
	return c, nil
}
