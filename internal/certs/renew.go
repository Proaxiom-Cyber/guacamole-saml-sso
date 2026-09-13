package certs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Renewal results.
const (
	ResultOK      = "ok"
	ResultSkipped = "skipped" // still fresh; nothing was done
	ResultFailed  = "failed"
)

// Status is the last renewal result. It holds the certificate's public
// details, paths and error text only. No key material and no credential ever
// passes through it: the ACME account key and the certificate key never
// leave Issue, and the Cloudflare token lives in the caller's TokenSource.
type Status struct {
	Certificate
	Ran        time.Time `json:"ran"`
	Result     string    `json:"result"`
	Hostname   string    `json:"hostname"`
	Reason     string    `json:"reason,omitempty"` // why renewal ran, or did not
	Directory  string    `json:"directory,omitempty"`
	AccountURL string    `json:"account_url,omitempty"`
	Reloaded   bool      `json:"reloaded,omitempty"`
	OnCalendar string    `json:"on_calendar,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// StatusPath is the last-run file, beside the state file but not in it: the
// deployment record is the session's schema and a daily timer must not churn
// it, and the timer writes this file without taking the deployment lock.
func StatusPath(stateDir string) string { return filepath.Join(stateDir, "cert-status.json") }

// WriteStatus saves the last-run record with owner-only permissions.
func WriteStatus(stateDir string, s Status) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(StatusPath(stateDir), append(b, '\n'), 0o600)
}

// ReadStatus returns the last-run record, or nil when renewal has never run.
func ReadStatus(stateDir string) (*Status, error) {
	b, err := os.ReadFile(StatusPath(stateDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is not readable JSON: %w", StatusPath(stateDir), err)
	}
	return &s, nil
}

// Renew issues a new certificate when the installed one is missing, is still
// the temporary self-signed placeholder, or expires within RenewBefore. A
// certificate with more life than that is left alone and reported as
// skipped.
//
// A failure at any point keeps the installed certificate: Issue writes
// nothing until the CA has returned a complete chain. The failure is
// recorded and returned, so the caller exits nonzero. Nothing here disables
// certificate verification, and no failure path is allowed to.
func Renew(ctx context.Context, o Options) (Status, error) {
	if err := o.defaults(); err != nil {
		return Status{}, err
	}
	s := Status{Ran: o.now().UTC(), Hostname: o.Hostname, Directory: o.DirectoryURL}

	current, err := Inspect(o.CertPath())
	switch {
	case err != nil:
		s.Reason = "no readable certificate is installed"
	case current.SelfSigned:
		s.Reason = "the installed certificate is the temporary self-signed one"
		s.Certificate = current
	case !pairMatches(o.CertPath(), o.KeyPath()):
		// The certificate and the private key are written as two separate
		// renames, so a crash between them leaves a mismatched pair. nginx
		// refuses to start on one, which is an outage that no amount of
		// waiting fixes. Treat it as a reason to re-issue rather than as a
		// healthy certificate.
		s.Reason = "the installed certificate and private key do not match"
		s.Certificate = current
	case current.NotAfter.After(o.now().Add(o.RenewBefore)):
		s.Result, s.Certificate = ResultSkipped, current
		s.Reason = fmt.Sprintf("%s remaining, more than the %s renewal window",
			until(current.NotAfter, o.now()), o.RenewBefore.Round(time.Hour))
		return s, WriteStatus(o.StateDir, s)
	default:
		s.Certificate = current
		s.Reason = fmt.Sprintf("%s remaining, inside the %s renewal window",
			until(current.NotAfter, o.now()), o.RenewBefore.Round(time.Hour))
	}

	iss, err := Issue(ctx, o)
	if err != nil {
		// The installed certificate is untouched; s.Certificate still
		// describes it, so the record shows what is actually being served.
		s.Result, s.Error = ResultFailed, err.Error()
		if werr := WriteStatus(o.StateDir, s); werr != nil {
			return s, fmt.Errorf("%v (and the status file could not be written: %v)", err, werr)
		}
		return s, err
	}
	s.Result, s.Certificate, s.AccountURL = ResultOK, iss.Certificate, iss.AccountURL

	// The certificate is installed either way. A failed reload means nginx
	// keeps serving the previous certificate — still verified, just old — so
	// the result stays "ok" and the reload failure is recorded and returned,
	// which exits nonzero and puts it in front of the administrator.
	rerr := reload(ctx, o)
	s.Reloaded = rerr == nil
	if errors.Is(rerr, errNoReloadNeeded) {
		// Expected during setup: the certificate is in place before the
		// stack starts, which is the whole point of installing it first.
		s.Reason += "; nginx was not running yet, so it will serve this certificate from its first start"
		rerr = nil
	} else if rerr != nil {
		s.Error = rerr.Error()
	}
	if werr := WriteStatus(o.StateDir, s); werr != nil {
		return s, werr
	}
	return s, rerr
}

// reload asks the running nginx to re-read its certificate files.
//
// "nginx -s reload" rather than a container restart: nginx starts new
// workers and lets the old ones finish, so established Guacamole sessions
// (long-lived WebSocket tunnels) survive the renewal, while a restart drops
// every one of them. The compose invocation matches internal/backup's, which
// also reaches into a running container without the in-memory secret
// override — none is needed here, and the renewal unit deliberately holds no
// database password.
func reload(ctx context.Context, o Options) error {
	args := []string{"compose",
		"--project-directory", o.InstallDir,
		"--env-file", filepath.Join(o.InstallDir, ".env"),
		"-f", filepath.Join(o.InstallDir, "compose.yaml"),
		"exec", "-T", "nginx", "nginx", "-s", "reload"}
	out, errOut, err := o.Run(ctx, "", "docker", args...)
	if err == nil {
		return nil
	}
	// A certificate can legitimately be issued before the stack starts:
	// setup installs it first precisely so nginx serves the real one from
	// its first start, and the tunnel never has to accept an unverified
	// origin. There is nothing to reload then, and calling that a failure
	// would fail the whole deployment over an expected condition. A reload
	// failure while nginx IS running is a real problem, because the old
	// certificate stays in use.
	if !nginxRunning(ctx, o) {
		return errNoReloadNeeded
	}
	return fmt.Errorf("the new certificate is installed but nginx did not reload, so it is still serving the previous one: %v\n%s",
		err, strings.TrimSpace(errOut+out))
}

// errNoReloadNeeded reports that nginx was not running, so the freshly
// installed certificate will simply be read when it starts.
var errNoReloadNeeded = errors.New("nginx is not running yet, so it will read the new certificate when it starts")

// nginxRunning reports whether the stack's nginx container is up.
func nginxRunning(ctx context.Context, o Options) bool {
	out, _, err := o.Run(ctx, "", "docker", "compose",
		"--project-directory", o.InstallDir,
		"--env-file", filepath.Join(o.InstallDir, ".env"),
		"-f", filepath.Join(o.InstallDir, "compose.yaml"),
		"ps", "--status", "running", "--format", "{{.Name}}", "nginx")
	return err == nil && strings.TrimSpace(out) != ""
}

// Verify makes the check cloudflared makes: a TLS handshake with the origin,
// using the deployment hostname as the server name and certificate
// verification enabled against the host's trust store.
//
// This is the origin certificate only. The browser-facing certificate is
// Cloudflare's, is served at the edge, and is not involved here.
// Verification is never disabled — a self-signed or expired origin
// certificate is meant to fail this check, because it fails the tunnel too.
func Verify(ctx context.Context, o Options) error {
	if err := o.defaults(); err != nil {
		return err
	}
	d := &tls.Dialer{Config: &tls.Config{ServerName: o.Hostname, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", o.VerifyAddr)
	if err != nil {
		return fmt.Errorf("the origin certificate at %s is not accepted for %s, which is what cloudflared will see: %w",
			o.VerifyAddr, o.Hostname, err)
	}
	return conn.Close()
}

// Summary renders the last-run record for an operator. It names which
// certificate this is, because the hostname has two and only one of them is
// this tool's.
func (s Status) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Origin certificate (nginx; Cloudflare serves the separate browser-facing certificate)\n")
	fmt.Fprintf(&b, "Hostname:           %s\n", s.Hostname)
	if s.Subject != "" {
		fmt.Fprintf(&b, "Subject:            %s\n", s.Subject)
		fmt.Fprintf(&b, "Issuer:             %s\n", s.Issuer)
	}
	if s.SelfSigned {
		fmt.Fprintf(&b, "                    temporary self-signed certificate; the tunnel will refuse this origin\n")
	}
	if !s.NotAfter.IsZero() {
		fmt.Fprintf(&b, "Expires:            %s (%s remaining)\n",
			s.NotAfter.Format(time.RFC3339), until(s.NotAfter, time.Now()))
	}
	fmt.Fprintf(&b, "Last renewal:       %s  %s\n", s.Ran.Format(time.RFC3339), s.Result)
	if s.Reason != "" {
		fmt.Fprintf(&b, "Reason:             %s\n", s.Reason)
	}
	if s.OnCalendar != "" {
		fmt.Fprintf(&b, "Schedule:           %s\n", s.OnCalendar)
	}
	if s.Result == ResultOK {
		fmt.Fprintf(&b, "nginx reloaded:     %t\n", s.Reloaded)
	}
	if s.Error != "" {
		fmt.Fprintf(&b, "Failure:            %s\n", strings.TrimSpace(s.Error))
		fmt.Fprintf(&b, "                    The previous certificate is still installed and TLS verification stays on.\n")
	}
	return b.String()
}

// Report renders the current certificate and the last renewal result. It
// reads the certificate file directly, so it is useful before renewal has
// ever run. It holds no secrets and takes no lock.
func Report(stateDir, installDir, hostname string) string {
	o := Options{StateDir: stateDir, InstallDir: installDir, Hostname: hostname}
	s, err := ReadStatus(stateDir)
	if err != nil {
		return fmt.Sprintf("The certificate renewal record is unreadable: %v\n", err)
	}
	if s == nil {
		s = &Status{Hostname: hostname, Result: "not yet run"}
	}
	// The file on disk wins over the record: an administrator may have
	// replaced it, and the record is only ever as fresh as the last run.
	if info, err := Inspect(o.CertPath()); err == nil {
		s.Certificate = info
	}
	return s.Summary()
}

func until(t, now time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		return "expired"
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// pairMatches reports whether the installed certificate and private key
// belong together. A mismatch means nginx will refuse to start, so renewal
// treats it as work to do rather than as a certificate in good standing.
// An unreadable pair is reported as mismatched: the caller's other checks
// already cover a missing certificate, and re-issuing is the safe answer.
func pairMatches(certPath, keyPath string) bool {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return false
	}
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	return err == nil
}
