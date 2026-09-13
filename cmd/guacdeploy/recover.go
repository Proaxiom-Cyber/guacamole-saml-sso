package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recover"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// recoverCmd rebuilds the deployment record on a replacement host from a
// backup, after asking each provider what of the lost deployment is still
// there.
//
// It creates nothing, changes nothing at any provider and deletes nothing.
// What it writes is the deployment record that the ordinary setup run then
// works from: resources the ownership marker proves are still ours are
// adopted rather than created a second time, and anything ambiguous stops
// the run for a person to look at.
func recoverCmd(ctx context.Context, stateDir, file, keyExport string, yes bool, u *ui.UI) error {
	if file == "" {
		return errors.New("recovery needs --file: the backup to rebuild this deployment from")
	}
	store, err := state.Open(stateDir)
	if err != nil {
		return err
	}
	defer store.Close()
	// Recovery targets a fresh host. Running it over a live deployment would
	// replace the record of the deployment actually running here.
	if st, err := store.Load(); err != nil {
		return err
	} else if st != nil {
		return fmt.Errorf("this host already runs deployment %s; recovery targets a replacement host with no deployment of its own", st.DeploymentID)
	}

	if keyExport == "" {
		keyExport = filepath.Join(stateDir, "recovery", "backup-key.age")
	}
	src := recover.Source{BackupFile: file, KeyExport: keyExport, GuacVersion: stack.GuacVersion}
	raw, readErr := os.ReadFile(file)
	if readErr != nil {
		return fmt.Errorf("the backup could not be read: %w", readErr)
	}
	if backup.Encrypted(raw) {
		// Through the hidden prompt only: a passphrase given as a flag lands
		// in shell history and in the process list.
		if !u.Interactive {
			return fmt.Errorf("%w: this backup is encrypted and its passphrase can only be given at a prompt", teardown.ErrApprovalRequired)
		}
		if src.Passphrase, err = u.SecretReader()("Backup key passphrase"); err != nil {
			return err
		}
	}
	l, err := recover.Load(src)
	if err != nil {
		return err
	}

	st := l.Snapshot.State
	cf, ec, err := recoverProviders(st, u)
	if err != nil {
		return err
	}
	rep := recover.Reconcile(ctx, l, teardown.Finders{
		"entra":      findEntra(ec, st),
		"cloudflare": findCloudflare(cf),
	})
	rep.Print(u)
	if err := rep.RequiresReview(); err != nil {
		return err
	}
	if !yes {
		ok, err := u.Confirm("Write this deployment record to this host?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("recovery not approved; nothing was written and nothing at any provider was changed")
		}
	}
	rec, err := recover.Restore(l, rep, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := store.Save(rec); err != nil {
		return err
	}
	u.Say("Deployment record written for %s.", rec.DeploymentID)
	u.Say("Run 'guacdeploy setup' next: it re-supplies the credentials, creates only what is genuinely gone, and starts the stack.")
	u.Say("The database is restored separately with 'guacdeploy restore --file %s' once the stack is running.", file)
	return nil
}

// recoverProviders builds the two read-only provider clients recovery needs.
//
// The lost host's credentials died with it, and a sealed credential cannot be
// decrypted on a replacement host at all, so the Cloudflare token is supplied
// again for this run only: from the environment for an unattended run, and
// otherwise at a hidden prompt. Nothing is stored here — setup stores it, the
// way the operator chooses.
func recoverProviders(st *state.State, u *ui.UI) (*cloudflare.Provisioner, *entra.Client, error) {
	spec := creds.Spec{Name: "cloudflare-api-token", Purpose: "asking Cloudflare what of this deployment is still there"}
	token := os.Getenv(spec.EnvVar())
	if token == "" {
		if !u.Interactive {
			return nil, nil, fmt.Errorf("recovery needs the Cloudflare API token to ask what still exists: set %s and run again", spec.EnvVar())
		}
		var err error
		if token, err = u.SecretReader()(fmt.Sprintf("Enter %s (%s)", spec.Name, spec.Purpose)); err != nil {
			return nil, nil, err
		}
	}
	if os.Getenv(entra.DefaultTokenEnv) == "" {
		return nil, nil, fmt.Errorf("recovery needs a Microsoft Graph token to ask what still exists in the tenant: set %s and run again. Required permissions: %s",
			entra.DefaultTokenEnv, strings.Join(entra.RequiredPermissions, ", "))
	}
	cf := &cloudflare.Provisioner{
		Client:       &cloudflare.Client{Token: func(context.Context) (string, error) { return token, nil }},
		AccountID:    st.Config["cloudflare-account-id"],
		ZoneID:       st.Config["cloudflare-zone-id"],
		Hostname:     st.Config["guac-hostname"],
		DeploymentID: st.DeploymentID,
	}
	return cf, &entra.Client{Token: entra.StaticTokenFromEnv(entra.DefaultTokenEnv)}, nil
}
