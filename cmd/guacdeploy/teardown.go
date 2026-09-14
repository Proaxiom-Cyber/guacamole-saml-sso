package main

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
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

	ops := teardown.DefaultOps(teardown.HostOptions{
		DeploymentID: st.DeploymentID,
		StateDir:     stateDir,
		InstallDir:   installDirOf(st),
	})
	cf, ec := teardownProviders(&ops, st, stateDir, u)
	reg := settingsRegistry(ec)

	// Reconcile before planning. A phase that created resources and then
	// failed before recording them leaves nothing in the deployment record,
	// so a plan built from the record alone would miss them and the run
	// would report a completeness it has not earned. Reconcile asks each
	// provider by this deployment's exact ownership marker and records what
	// it can prove; a name-only match is reported for review, never adopted.
	rec := teardown.Reconcile(ctx, st, teardown.Finders{
		"entra":      findEntra(ec, st),
		"cloudflare": findCloudflare(cf),
	})
	plan := teardown.BuildPlan(st, settings.List(ctx, st, reg), deleteData)
	plan.Reconciled = rec

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
func teardownProviders(ops *teardown.Ops, st *state.State, stateDir string, u *ui.UI) (*cloudflare.Provisioner, *entra.Client) {
	m := &creds.Manager{
		Mode:       st.Config["credential-mode"],
		Dir:        filepath.Join(stateDir, "credentials"),
		ReadSecret: u.SecretReader(), Protect: u.Protect,
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
	ec := session.EntraClientForOperation(st, stateDir, u)
	ecfg := entra.Config{DeploymentID: st.DeploymentID, Hostname: st.Config["guac-hostname"]}
	ops.DeleteInstallerIdentity = func(ctx context.Context, id string) error { return ec.CleanupInstaller(ctx, st.DeploymentID, id) }
	ops.DeleteEntraApp = func(ctx context.Context, id string) error {
		return ec.CleanupApp(ctx, ecfg, id)
	}
	ops.DeleteEntraGroup = func(ctx context.Context, id string) error {
		return ec.CleanupGroup(ctx, ecfg, id)
	}
	return cf, ec
}

// findEntra queries the tenant by this deployment's ownership marker. Plan
// is the same marker query resume uses and creates nothing, so it is safe
// to call from a teardown.
func findEntra(ec *entra.Client, st *state.State) teardown.Finder {
	return func(ctx context.Context) (teardown.Found, error) {
		// AfterUncertainCreate stays false: this is a query, not a resume,
		// so a name-only match should come back as unowned rather than as
		// an error.
		p, err := ec.Plan(ctx, entra.Config{
			Hostname: st.Config["guac-hostname"], DeploymentID: st.DeploymentID,
			AdminGroup: st.Config["admin-group"], OperatorGroup: st.Config["operator-group"],
		})
		if err != nil {
			return teardown.Found{}, err // including ErrRequiresReview: a person decides
		}
		var f teardown.Found
		if st.Config["entra-installer-pending"] != "" || st.Config["entra-installer-client-id"] != "" {
			app, err := ec.FindInstaller(ctx, st.DeploymentID)
			if err != nil {
				return f, err
			}
			if app != nil {
				for _, r := range []struct{ kind, id string }{{"installer-application", app.ID}, {"installer-service-principal", app.SPID}} {
					if r.id != "" {
						f.Owned = append(f.Owned, state.Resource{Provider: "entra", Type: r.kind, ProviderID: r.id, Name: app.DisplayName, Ownership: "marker " + entra.InstallerMarker(st.DeploymentID) + " on the installer application"})
					}
				}
			}
		}
		if p.App != nil {
			r := state.Resource{Provider: "entra", Type: "application",
				ProviderID: p.App.ObjectID, Name: p.App.DisplayName}
			if !p.App.ProvenOurs {
				f.Unowned = append(f.Unowned, r)
			} else {
				r.Ownership = "marker " + p.App.Marker + " in the application notes and tags"
				f.Owned = append(f.Owned, r)
				if p.SP != nil {
					f.Owned = append(f.Owned, state.Resource{Provider: "entra",
						Type: "service-principal", ProviderID: p.SP.ObjectID,
						Name:      p.App.DisplayName,
						Ownership: "service principal of the marked application"})
				}
			}
		}
		for _, g := range p.Groups {
			r := state.Resource{Provider: "entra", Type: "group",
				ProviderID: g.ObjectID, Name: g.Name}
			if !g.ProvenOurs {
				f.Unowned = append(f.Unowned, r)
				continue
			}
			r.Ownership = "marker " + entra.Marker(st.DeploymentID) + " in the group description"
			f.Owned = append(f.Owned, r)
		}
		return f, nil
	}
}

// findCloudflare lists what this deployment's naming could refer to and
// keeps ownership separate from the name match.
func findCloudflare(cf *cloudflare.Provisioner) teardown.Finder {
	return func(ctx context.Context) (teardown.Found, error) {
		found, err := cf.FindOwned(ctx)
		if err != nil {
			return teardown.Found{}, err
		}
		var f teardown.Found
		for _, r := range found {
			res := state.Resource{Provider: "cloudflare", Type: r.Type,
				ProviderID: r.ID, Name: r.Name}
			if !r.Ours {
				f.Unowned = append(f.Unowned, res)
				continue
			}
			res.Ownership = r.Ownership
			f.Owned = append(f.Owned, res)
		}
		return f, nil
	}
}
