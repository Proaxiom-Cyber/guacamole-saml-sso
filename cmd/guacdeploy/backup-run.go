package main

import (
	"context"
	"fmt"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// backupRunCmd is what the installed timer calls. It backs up, then expires
// old backups, then records the outcome; a failed backup expires nothing and
// exits nonzero.
//
// It never prompts and never needs the recovery passphrase: the export uses
// the recorded public key only. Unlike backupCmd it takes an explicit
// destination with no default, because the schedule always records one and a
// silent fallback to local storage is exactly what the specification forbids.
func backupRunCmd(ctx context.Context, run backup.Runner, o schedule.Options, u *ui.UI) error {
	if o.Dest == "" {
		return fmt.Errorf("a scheduled backup needs --dest")
	}
	store, err := state.Open(o.StateDir)
	if err != nil {
		return err
	}
	defer store.Close()
	st, err := store.Load()
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s; there is nothing to back up", o.StateDir)
	}

	s, err := schedule.RunBackup(ctx, o, func(ctx context.Context) (string, error) {
		return backup.Backup(ctx, backup.Options{
			Run: run, InstallDir: installDirFrom(st), Dest: o.Dest,
			Plaintext: o.Plaintext, PublicKey: st.Config[backupPublicKeyConfig],
			GuacVersion: stack.GuacVersion,
		}, st)
	})
	u.Say("%s", s.Summary())
	return err
}

// backupStatusCmd shows the destination and the last scheduled run.
func backupStatusCmd(stateDir string, u *ui.UI) error {
	u.Say("%s", schedule.Summary(stateDir))
	return nil
}
