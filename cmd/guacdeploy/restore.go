package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// restoreCmd replaces the database from a backup file. The file is fully
// validated (decryption, format and version compatibility, completion
// marker) before any database command runs, and the operator consents
// before anything is replaced. Restore does not stop the guacamole
// container: the operator accepts downtime and restarts the stack after a
// successful restore so the application reconnects cleanly.
func restoreCmd(ctx context.Context, run backup.Runner, stateDir, file, identityFile string, yes bool, u *ui.UI) error {
	if file == "" {
		return fmt.Errorf("restore needs --file PATH (a guacdeploy backup file)")
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
		return fmt.Errorf("no deployment exists in %s; V1 restore targets the deployed stack on this host", stateDir)
	}

	if err := checkManifest(file); err != nil {
		return fmt.Errorf("restore refused, the database was not changed: %w", err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var id *age.X25519Identity
	if backup.Encrypted(raw) {
		if identityFile != "" {
			id, err = readIdentityFile(identityFile)
		} else {
			id, err = recoverIdentityInteractively(stateDir, u)
		}
		if err != nil {
			return err
		}
	}

	sql, info, err := backup.Validate(raw, id, stack.GuacVersion)
	if err != nil {
		return fmt.Errorf("restore refused, the database was not changed: %w", err)
	}

	if !yes {
		ok, err := u.Confirm(fmt.Sprintf(
			"Replace ALL data in guacamole_db with the backup %s (Guacamole %s)? Current data is lost and connected users are interrupted.",
			file, info.GuacVersion))
		if errors.Is(err, ui.ErrInputRequired) {
			return fmt.Errorf("%w: unattended restore replaces the whole database; add --yes to consent", session.ErrApprovalRequired)
		}
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("restore cancelled; the database was not changed")
		}
	}

	if err := backup.Apply(ctx, backup.Options{Run: run, InstallDir: installDirFrom(st)}, sql); err != nil {
		return err
	}
	u.Say("Restore complete from %s.", file)
	u.Say("Restart the stack so Guacamole reconnects cleanly:")
	u.Say("  docker compose --project-directory %s restart", installDirFrom(st))
	return nil
}

// checkManifest verifies a backup against the completion manifest published
// beside it, when there is one. A mismatch means the file is truncated,
// corrupt, or not the file the manifest describes, and restore refuses
// before touching the database.
//
// A missing manifest is not an error: an administrator copying a backup off
// the host (which the specification tells them to do) may bring only the
// backup file, and a replacement host must still be able to restore it. The
// completion marker inside the backup still proves the dump is whole.
//
// Ownership is deliberately not checked. A replacement host has its own
// deployment ID, and refusing to restore another deployment's backup would
// break exactly the recovery case this command exists for.
func checkManifest(file string) error {
	dir, name := filepath.Split(file)
	if _, err := backup.ReadManifest(dir, name); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := backup.VerifyPublished(dir, name, ""); err != nil {
		return fmt.Errorf("the backup does not match its completion manifest (%s): %w", backup.ManifestPath(dir, name), err)
	}
	return nil
}

// recoverIdentityInteractively decrypts the passphrase-encrypted key
// export written by 'guacdeploy backup-key'. The passphrase is read with
// hidden input and never echoed, logged, or stored.
func recoverIdentityInteractively(stateDir string, u *ui.UI) (*age.X25519Identity, error) {
	secret := u.SecretReader()
	if secret == nil {
		return nil, fmt.Errorf("%w: decrypting the backup reads the recovery passphrase with hidden input; run from a terminal, or pass --identity-file", ui.ErrInputRequired)
	}
	pass, err := secret("Backup key passphrase")
	if err != nil {
		return nil, err
	}
	return recoverykey.RecoverIdentity(backupKeyPath(stateDir), pass)
}

// readIdentityFile parses a standard age identity file ('#' comment lines,
// one AGE-SECRET-KEY- line). It exists for automation and tests; the
// interactive path recovers the identity from the passphrase-encrypted
// export instead, so no plaintext private key needs to be on disk. A file
// used here must be owner-only and removed after the restore.
func readIdentityFile(path string) (*age.X25519Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return age.ParseX25519Identity(line)
		}
	}
	return nil, fmt.Errorf("%s contains no age identity (no AGE-SECRET-KEY- line)", path)
}
