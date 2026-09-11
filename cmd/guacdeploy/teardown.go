package main

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/settings"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// teardownCmd shows the removal plan and, once approved, removes what this
// deployment created.
//
// It takes the deployment lock for the whole run, because it writes both at
// the providers and in the deployment record. Only one mutating operation
// may run against a deployment at a time.
//
// consent is the explicit command-line approval an unattended run needs.
// deleteData is the separate, explicit intent for permanent deletion of the
// database, the recordings and the local backups; without it they are kept.
func teardownCmd(ctx context.Context, stateDir string, consent, deleteData bool, u *ui.UI) error {
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
		u.Say("No deployment exists on this host. There is nothing to tear down.")
		return nil
	}

	reg := settingsRegistry()
	plan := teardown.BuildPlan(st, settings.List(ctx, st, reg), deleteData)

	ops := teardown.DefaultOps(teardown.HostOptions{
		DeploymentID: st.DeploymentID,
		StateDir:     stateDir,
		InstallDir:   installDirOf(st),
	})
	teardownProviders(&ops, st, stateDir, u)

	if _, err = teardown.Run(ctx, st, plan, ops, u, teardown.Options{
		Consent:  consent,
		Registry: reg,
		Save:     func() error { return store.Save(st) },
	}); err != nil {
		return err
	}

	// Starting over requires cleanup first. The record goes only when
	// nothing this deployment created is recorded any more; anything still
	// in it — kept data, an installed package — is what setup will see and
	// refuse to build over.
	if len(st.Resources) == 0 {
		if err := store.Delete(st); err != nil {
			return err
		}
		u.Say("The deployment record is removed. Setup starts a new deployment from clean.")
		return nil
	}
	u.Say("The deployment record is kept: %d item(s) listed above are still recorded, so setup will not build a new deployment over them.", len(st.Resources))
	return nil
}

// installDirOf returns the installation directory from the deployment
// record. The record is authoritative: the directory this deployment
// rendered into is the one it recorded, not a default guessed at here.
func installDirOf(st *state.State) string {
	for _, r := range st.Resources {
		if r.Provider == "host" && r.Type == "config-directory" {
			return r.Name
		}
	}
	return ""
}

// teardownProviders fills in the provider half of the removal seam. Each
// delete re-verifies its own ownership marker at deletion time and refuses
// with ErrNotOwned otherwise, which teardown reports as retained.
func teardownProviders(ops *teardown.Ops, st *state.State, stateDir string, u *ui.UI) {
	m := &creds.Manager{
		Mode:       st.Config["credential-mode"],
		Dir:        filepath.Join(stateDir, "credentials"),
		ReadSecret: u.SecretReader(),
	}
	cf := &cloudflare.Provisioner{
		Client: &cloudflare.Client{Token: func(context.Context) (string, error) {
			for _, s := range creds.Required {
				if s.Name == "cloudflare-api-token" {
					return m.Get(s) // in-memory only; never journalled
				}
			}
			return "", errors.New("no cloudflare-api-token credential is configured")
		}},
		AccountID:    st.Config["cloudflare-account-id"],
		ZoneID:       st.Config["cloudflare-zone-id"],
		Hostname:     st.Config["guac-hostname"],
		DeploymentID: st.DeploymentID,
	}
	ops.DeleteDNSRecord = cf.DeleteRecord
	ops.DeleteAccessApp = cf.DeleteAccessApp
	ops.DeleteTunnel = cf.DeleteTunnel

	// Removing the application removes its service principal and role
	// assignments with it, so neither is ever deleted separately.
	ec := &entra.Client{Token: entra.StaticTokenFromEnv(entra.DefaultTokenEnv)}
	ecfg := entra.Config{DeploymentID: st.DeploymentID, Hostname: st.Config["guac-hostname"]}
	ops.DeleteEntraApp = func(ctx context.Context, id string) error {
		return ec.CleanupApp(ctx, ecfg, id)
	}
	ops.DeleteEntraGroup = func(ctx context.Context, id string) error {
		return ec.CleanupGroup(ctx, ecfg, id)
	}
}
