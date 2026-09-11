package main

import (
	"context"
	"fmt"
	"path/filepath"

	"filippo.io/age"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// recordingsRunCmd backs up the completed recordings and records the
// outcome.
//
// It reads the deployment record without taking the mutation lock. It only
// reads, and the nightly database backup holds that lock for its whole run;
// competing for it would make one of the two runs fail for no reason.
func recordingsRunCmd(stateDir, recordingsDir, dest string, plaintext bool, u *ui.UI) error {
	st, err := state.Read(stateDir)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s; there are no recordings to manage", stateDir)
	}
	if recordingsDir == "" {
		recordingsDir = recording.Dir(installDirFrom(st))
	}
	rep, err := recording.Run(recording.Options{
		Dir: recordingsDir, Dest: dest, StateDir: stateDir,
		DeploymentID: st.DeploymentID,
		Plaintext:    plaintext, PublicKey: st.Config[backupPublicKeyConfig],
	})
	u.Say("%s", rep.Summary())
	return err
}

// recordingsStatusCmd shows the last recording run.
func recordingsStatusCmd(stateDir string, u *ui.UI) error {
	u.Say("%s", recording.Summary(stateDir))
	return nil
}

// recordingsEnableCmd turns session recording on for every connection, or
// for one named connection. It is how an operator gets recording onto the
// connections they already have, and onto each new one they create in the
// web interface.
func recordingsEnableCmd(ctx context.Context, run backup.Runner, stateDir, connection string, u *ui.UI) error {
	st, err := state.Read(stateDir)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s", stateDir)
	}
	if err := recording.Enable(ctx, run, installDirFrom(st), connection); err != nil {
		return err
	}
	if connection == "" {
		u.Say("Session recording is on for every connection.")
	} else {
		u.Say("Session recording is on for %q.", connection)
	}
	u.Say("Recordings are written to %s and are complete when the session ends.", recording.Dir(installDirFrom(st)))
	return nil
}

// recordingsRestoreCmd writes one backed-up recording back out as a playable
// file. It verifies the completion record first, so a truncated or foreign
// copy is refused before anything is written.
func recordingsRestoreCmd(stateDir, file, out, identityFile string, u *ui.UI) error {
	if file == "" {
		return fmt.Errorf("restoring a recording needs --file, the published copy in the backup destination")
	}
	st, err := state.Read(stateDir)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s", stateDir)
	}
	dir, name := filepath.Split(file)
	if out == "" {
		out = name + ".playback"
	}
	var id *age.X25519Identity
	if filepath.Ext(name) == ".age" {
		if identityFile != "" {
			id, err = readIdentityFile(identityFile)
		} else {
			id, err = recoverIdentityInteractively(stateDir, u)
		}
		if err != nil {
			return err
		}
	}
	if err := recording.Restore(filepath.Clean(dir), name, out, id, st.DeploymentID); err != nil {
		return err
	}
	u.Say("Recording written to %s. Play it back with the Guacamole session recording player.", out)
	return nil
}
