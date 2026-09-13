package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// installDirFrom finds the recorded installation directory, which setup
// journals as the host config-directory resource.
func installDirFrom(st *state.State) string {
	for _, r := range st.Resources {
		if r.Provider == "host" && r.Type == "config-directory" && r.Name != "" {
			return r.Name
		}
	}
	return "/opt/guacamole"
}

// backupCmd exports the database into dest. It holds the deployment lock
// for the whole run, so no deployment mutation can change ownership state
// between the metadata snapshot and the export.
func backupCmd(ctx context.Context, run backup.Runner, stateDir, dest string, plaintext bool, u *ui.UI) error {
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
		return fmt.Errorf("no deployment exists in %s; there is nothing to back up", stateDir)
	}

	if dest == "" {
		// The default destination lives under the state directory and is
		// ours to create. An explicit --dest must already exist: it may be
		// a mount point, and a missing mount must fail, not be recreated
		// as a local directory.
		dest = filepath.Join(stateDir, "backups")
		if err := os.MkdirAll(dest, 0o700); err != nil {
			return err
		}
	}

	path, err := backup.Backup(ctx, backup.Options{
		Run: run, InstallDir: installDirFrom(st), Dest: dest,
		Plaintext: plaintext, PublicKey: st.Config[backupPublicKeyConfig],
		GuacVersion: stack.GuacVersion,
	}, st)
	if err != nil {
		u.Say("Backup not published.")
		return err
	}
	u.Say("Backup published: %s", path)
	u.Say("Completion manifest: %s (copy it with the backup; it holds no secrets)",
		backup.ManifestPath(filepath.Split(path)))
	if plaintext {
		u.Say("This backup is NOT encrypted. You chose --plaintext; protect the file yourself.")
	}
	return nil
}
