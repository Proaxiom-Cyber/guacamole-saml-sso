package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestRenewSkipsACertificateThatIsStillFresh(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.writeLeaf(t, now.Add(60*24*time.Hour))
	before := readFile(t, h.o.CertPath())
	h.o.Now = fixedNow(now)

	s, err := Renew(context.Background(), h.o)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if s.Result != ResultSkipped {
		t.Errorf("result = %q, want %q", s.Result, ResultSkipped)
	}
	if h.acme.created != 0 {
		t.Error("a fresh certificate was renewed anyway")
	}
	if readFile(t, h.o.CertPath()) != before {
		t.Error("a skipped renewal changed the installed certificate")
	}
	if got, err := ReadStatus(h.o.StateDir); err != nil || got == nil || got.Result != ResultSkipped {
		t.Errorf("recorded status = %+v, err = %v", got, err)
	}
}

func TestRenewIssuesWhenTheCertificateIsNearExpiry(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.writeLeaf(t, now.Add(10*24*time.Hour))
	before := readFile(t, h.o.CertPath())
	h.o.Now = fixedNow(now)

	s, err := Renew(context.Background(), h.o)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if s.Result != ResultOK {
		t.Fatalf("result = %q (%s)", s.Result, s.Error)
	}
	if h.acme.created != 1 {
		t.Errorf("certificates issued = %d, want 1", h.acme.created)
	}
	if readFile(t, h.o.CertPath()) == before {
		t.Error("the installed certificate was not replaced")
	}
	if !s.Reloaded {
		t.Error("nginx was not reloaded after a successful renewal")
	}
	wantCmd := "docker compose --project-directory " + h.o.InstallDir +
		" --env-file " + h.o.InstallDir + "/.env -f " + h.o.InstallDir +
		"/compose.yaml exec -T nginx nginx -s reload"
	if len(h.ran) != 1 || strings.Join(h.ran[0], " ") != wantCmd {
		t.Errorf("ran %v, want %q", h.ran, wantCmd)
	}
}

func TestRenewReplacesTheTemporarySelfSignedCertificate(t *testing.T) {
	h := newHarness(t)
	h.writeSelfSigned(t)
	// Far from expiry: it is replaced because it is self-signed, not
	// because it is old. The tunnel refuses a self-signed origin.
	h.o.Now = fixedNow(time.Now())

	s, err := Renew(context.Background(), h.o)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if s.Result != ResultOK || s.SelfSigned {
		t.Fatalf("status = %+v", s)
	}
	if h.acme.created != 1 {
		t.Error("the self-signed placeholder was left in place")
	}
}

func TestRenewIssuesWhenNoCertificateIsInstalled(t *testing.T) {
	h := newHarness(t)
	s, err := Renew(context.Background(), h.o)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if s.Result != ResultOK || h.acme.created != 1 {
		t.Fatalf("status = %+v, issued = %d", s, h.acme.created)
	}
}

// The whole point of the failure path: the deployment keeps serving a
// verified certificate, and the run exits nonzero so the failure is seen.
func TestRenewFailureKeepsTheInstalledCertificateAndFails(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	h.writeLeaf(t, now.Add(5*24*time.Hour))
	beforeCert, beforeKey := readFile(t, h.o.CertPath()), readFile(t, h.o.KeyPath())
	h.o.Now = fixedNow(now)
	h.acme.failCreateCert = errors.New("the authority refused to issue")

	s, err := Renew(context.Background(), h.o)
	if err == nil {
		t.Fatal("Renew reported success although issuance failed")
	}
	if s.Result != ResultFailed {
		t.Errorf("result = %q, want %q", s.Result, ResultFailed)
	}
	if readFile(t, h.o.CertPath()) != beforeCert || readFile(t, h.o.KeyPath()) != beforeKey {
		t.Error("a failed renewal changed the installed certificate")
	}
	rec, rerr := ReadStatus(h.o.StateDir)
	if rerr != nil || rec == nil || rec.Result != ResultFailed || !strings.Contains(rec.Error, "refused to issue") {
		t.Errorf("recorded status = %+v, err = %v", rec, rerr)
	}
	// The record still describes the certificate that is actually served.
	if rec.NotAfter.Truncate(time.Second) != now.Add(5*24*time.Hour).UTC().Truncate(time.Second) {
		t.Errorf("the record does not describe the certificate still in place: %v", rec.NotAfter)
	}
	if len(h.ran) != 0 {
		t.Error("nginx was reloaded after a failed renewal")
	}
	if !strings.Contains(s.Summary(), "verification stays on") {
		t.Errorf("the failure summary does not say TLS verification stays on:\n%s", s.Summary())
	}
}

func TestRenewReportsAReloadFailureAndKeepsTheNewCertificate(t *testing.T) {
	h := newHarness(t)
	h.o.Now = fixedNow(time.Now())
	h.o.Run = func(context.Context, string, string, ...string) (string, string, error) {
		return "", "no such service: nginx", errors.New("exit status 1")
	}

	s, err := Renew(context.Background(), h.o)
	if err == nil {
		t.Fatal("a failed reload was not reported")
	}
	// The certificate really is installed, so the result is not a failure;
	// the reload problem is recorded and returned instead.
	if s.Result != ResultOK || s.Reloaded {
		t.Errorf("status = %+v", s)
	}
	if _, err := Inspect(h.o.CertPath()); err != nil {
		t.Errorf("the new certificate was not installed: %v", err)
	}
}

func TestRenewNeedsADNSSolverBeforeItTouchesAnything(t *testing.T) {
	h := newHarness(t)
	h.o.DNS = nil
	if _, err := Renew(context.Background(), h.o); err == nil {
		t.Fatal("Renew ran without a DNS-01 solver")
	}
}

// Verify must fail on an origin serving a certificate the host does not
// trust, because that is exactly what cloudflared does. It never skips
// verification to make the check pass.
func TestVerifyRejectsAnUntrustedOriginCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: testHost},
		DNSNames: []string{testHost}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()

	o := Options{Hostname: testHost, InstallDir: t.TempDir(), StateDir: t.TempDir(), VerifyAddr: ln.Addr().String()}
	err = Verify(context.Background(), o)
	if err == nil {
		t.Fatal("Verify accepted a certificate the host does not trust")
	}
	if !strings.Contains(err.Error(), "cloudflared") {
		t.Errorf("the failure does not explain what it means: %v", err)
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Errorf("Verify did not fail on certificate verification: %v", err)
	}
}

func TestVerifyDefaultsToTheLocalOriginPort(t *testing.T) {
	o := Options{Hostname: testHost, InstallDir: "/tmp/x", StateDir: "/tmp/y"}
	if err := o.defaults(); err != nil {
		t.Fatal(err)
	}
	if _, port, _ := net.SplitHostPort(o.VerifyAddr); port != "443" {
		t.Errorf("VerifyAddr = %q", o.VerifyAddr)
	}
}

func TestReportNamesBothCertificatesAndSurvivesAnAbsentRecord(t *testing.T) {
	h := newHarness(t)
	h.writeSelfSigned(t)
	got := Report(h.o.StateDir, h.o.InstallDir, testHost)
	for _, want := range []string{"Origin certificate", "browser-facing", "self-signed", "not yet run"} {
		if !strings.Contains(got, want) {
			t.Errorf("report does not mention %q:\n%s", want, got)
		}
	}
}
