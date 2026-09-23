package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/certs"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// State keys this command reads. Non-secret references only.
const (
	acmeDirectoryConfig = "acme-directory-url"
	acmeContactConfig   = "acme-contact"
	acmeAccountConfig   = "acme-account-url"
)

// renewCertCmd is what the installed timer calls, and what an administrator
// runs by hand to force a check. It renews the origin certificate when it is
// missing, still self-signed, or inside the renewal window, and does nothing
// otherwise.
//
// Everything it needs comes from the deployment record, so the unit file
// carries only --state-dir. It takes the deployment lock for the run, so a
// renewal cannot race a setup or a teardown.
//
// A failure returns an error, which main maps to exit 1. It never disables
// certificate verification, and the previous certificate stays installed.
func renewCertCmd(ctx context.Context, stateDir string, u *ui.UI) error {
	store, err := state.Open(stateDir)
	if err != nil {
		return err
	}
	defer store.Close()
	st, err := store.Load()
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s; there is no certificate to renew", stateDir)
	}
	o, err := certOptions(stateDir, st)
	if err != nil {
		return err
	}
	s, err := certs.Renew(ctx, o)
	u.Say("%s", s.Summary())
	if err != nil {
		return err
	}
	// Record the account reference once, so the deployment record names the
	// ACME account this host owns. The account key stays in the state
	// directory and never enters the record.
	if s.AccountURL != "" && st.Config[acmeAccountConfig] != s.AccountURL {
		if st.Config == nil {
			st.Config = map[string]string{}
		}
		st.Config[acmeAccountConfig] = s.AccountURL
		if err := store.Save(st); err != nil {
			return err
		}
	}
	return nil
}

// certStatusCmd shows the installed certificate and the last renewal result.
func certStatusCmd(stateDir string, u *ui.UI) error {
	st, err := state.Read(stateDir)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s", stateDir)
	}
	u.Say("%s", certs.Report(stateDir, installDirFrom(st), st.Config["guac-hostname"]))
	return nil
}

// certOptions builds the renewal configuration from the deployment record.
func certOptions(stateDir string, st *state.State) (certs.Options, error) {
	host := st.Config["guac-hostname"]
	zone, account := st.Config["cloudflare-zone-id"], st.Config["cloudflare-account-id"]
	if host == "" || zone == "" || account == "" {
		return certs.Options{}, fmt.Errorf("the deployment record has no hostname or Cloudflare zone yet; run setup before renewing the certificate")
	}
	token, err := cloudflareToken(stateDir, st)
	if err != nil {
		return certs.Options{}, err
	}
	p := &cloudflare.Provisioner{
		Client:       &cloudflare.Client{Token: token},
		AccountID:    account,
		ZoneID:       zone,
		Hostname:     host,
		DeploymentID: st.DeploymentID,
	}
	return certs.Options{
		Hostname:     host,
		InstallDir:   installDirFrom(st),
		StateDir:     stateDir,
		DirectoryURL: st.Config[acmeDirectoryConfig],
		Contact:      st.Config[acmeContactConfig],
		DNS:          &cloudflare.DNS01{P: p},
		Run:          certs.ExecRunner,
		VerifyAddr:   "127.0.0.1:" + port(st),
	}, nil
}

func port(st *state.State) string {
	if p := st.Config["https-port"]; p != "" {
		return p
	}
	return "443"
}

// cloudflareToken resolves the Cloudflare API token the way the recorded
// credential mode says to, for in-memory use only.
//
// Prompt mode cannot work here: an installed timer has no terminal. That is
// the specification's own point — "A prompt-only mode cannot provide
// unattended reboot recovery by itself" — so it fails with an instruction
// rather than hanging.
func cloudflareToken(stateDir string, st *state.State) (cloudflare.TokenSource, error) {
	mode := st.Config["credential-mode"]
	if mode == creds.ModePrompt {
		return nil, fmt.Errorf("the deployment uses prompt-mode credentials, which an unattended renewal cannot read: run `guacdeploy renew-cert` by hand with %s set, or move the deployment to env or file credentials",
			cloudflareSpec().EnvVar())
	}
	m := &creds.Manager{Mode: mode, Dir: filepath.Join(stateDir, "credentials")}
	return cloudflare.CredentialTokenSource(m, cloudflareSpec(), nil), nil
}

func cloudflareSpec() creds.Spec {
	for _, s := range creds.Required {
		if s.Name == "cloudflare-api-token" {
			return s
		}
	}
	return creds.Spec{Name: "cloudflare-api-token"}
}
