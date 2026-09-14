package main

import (
	"context"
	"fmt"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/settings"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// settingsRegistry is the provider accessors this command can restore
// through. The Entra accessor is always registered: a missing Graph token
// then shows up as a named read failure per setting, which is the truth,
// rather than as "this provider cannot be restored".
//
// Cloudflare has no entry because internal/cloudflare never changes a
// pre-existing setting; see internal/settings/WIRING.md.
func settingsRegistry(client *entra.Client) settings.Registry {
	return settings.Registry{
		"entra": entra.SettingAccessor{
			Client: client,
		},
	}
}

// settingsCmd shows, and on --restore offers to restore, the pre-existing
// settings this deployment changed. Listing reads state without the
// deployment lock; restoring takes the lock, because it writes both to the
// provider and to the state record.
func settingsCmd(ctx context.Context, stateDir string, restore bool, u *ui.UI) error {
	if !restore {
		st, err := state.Read(stateDir)
		if err != nil {
			return err
		}
		if st == nil {
			u.Say("No deployment exists on this host.")
			return nil
		}
		settings.Report(u, settings.List(ctx, st, settingsRegistry(session.EntraClientForOperation(st, stateDir, u))))
		return nil
	}

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
		return fmt.Errorf("no deployment exists in %s; there are no settings to restore", stateDir)
	}
	return settings.Restore(ctx, st, settingsRegistry(session.EntraClientForOperation(st, stateDir, u)), u, func() error { return store.Save(st) })
}
