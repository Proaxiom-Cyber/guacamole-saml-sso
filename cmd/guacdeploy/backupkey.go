package main

import (
	"fmt"
	"path/filepath"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// backupPublicKeyConfig is the state Config key holding the backup public
// key. Public keys are not secret; the private key is never stored in state.
const backupPublicKeyConfig = "backup-public-key"

// backupKeyPath is where the passphrase-encrypted private-key export lives.
func backupKeyPath(stateDir string) string {
	return filepath.Join(stateDir, "recovery", "backup-key.age")
}

// backupKey generates the backup key pair and writes the encrypted
// private-key export, or with verify demonstrates recovery from the export.
// Guided only: setting or checking the passphrase needs hidden interactive
// input, so unattended runs stop with ErrInputRequired (exit 3).
func backupKey(stateDir string, verify bool, u *ui.UI) error {
	secret := u.SecretReader()
	if secret == nil {
		return fmt.Errorf("%w: backup-key reads a passphrase with hidden input; run it from an interactive terminal", ui.ErrInputRequired)
	}
	path := backupKeyPath(stateDir)
	if verify {
		return verifyBackupKey(stateDir, path, secret, u)
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
		return fmt.Errorf("no deployment exists in %s; run guacdeploy setup first so the public key can be recorded against the deployment", stateDir)
	}
	if existing := st.Config[backupPublicKeyConfig]; existing != "" {
		return fmt.Errorf("a backup key is already recorded (public key %s); a new key would orphan backups made for it. Move %s aside deliberately before generating another", existing, path)
	}

	pass, err := secret("Backup key passphrase")
	if err != nil {
		return err
	}
	if pass == "" {
		return fmt.Errorf("empty passphrase rejected: recovery would depend on an unprotected export")
	}
	confirm, err := secret("Confirm passphrase")
	if err != nil {
		return err
	}
	if confirm != pass {
		return fmt.Errorf("passphrases do not match; nothing was generated")
	}

	id, err := recoverykey.Generate()
	if err != nil {
		return err
	}
	if err := recoverykey.ExportEncrypted(id, pass, path); err != nil {
		return err
	}
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	st.Config[backupPublicKeyConfig] = id.Recipient().String()
	if err := store.Save(st); err != nil {
		return err
	}

	u.Say("Backup key generated. Public key, recorded in the deployment state:")
	u.Say("  %s", id.Recipient().String())
	u.Say("")
	u.Say("Encrypted private-key export written to:")
	u.Say("  %s", path)
	u.Say("")
	u.Say("Copy the export to a workstation. Run on the workstation (the command")
	u.Say("contains no secrets; fill in the placeholders):")
	u.Say("  scp <admin-user>@<this-vm-address>:%s .", path)
	u.Say("  # or with sftp: sftp <admin-user>@<this-vm-address>, then: get %s", path)
	u.Say("")
	u.Say("Recovery needs BOTH the exported file and the passphrase you set.")
	u.Say("You are responsible for copying the file off this VM and storing the")
	u.Say("file and the passphrase safely, in separate places. The tool does not")
	u.Say("delete the export; remove it from the VM yourself after your copy is")
	u.Say("confirmed. Showing these instructions does not prove a copy was made")
	u.Say("or that the backup is recoverable. Run 'guacdeploy backup-key --verify'")
	u.Say("to prove the export decrypts with your passphrase.")
	return nil
}

// verifyBackupKey demonstrates recovery: it decrypts the export with the
// passphrase and checks the derived public key against the recorded one.
// Read-only, so it takes no state lock.
func verifyBackupKey(stateDir, path string, secret func(string) (string, error), u *ui.UI) error {
	st, err := state.Read(stateDir)
	if err != nil {
		return err
	}
	if st == nil || st.Config[backupPublicKeyConfig] == "" {
		return fmt.Errorf("no backup public key is recorded in %s; run guacdeploy backup-key first", stateDir)
	}
	pass, err := secret("Backup key passphrase")
	if err != nil {
		return err
	}
	id, err := recoverykey.RecoverIdentity(path, pass)
	if err != nil {
		return err
	}
	if got, want := id.Recipient().String(), st.Config[backupPublicKeyConfig]; got != want {
		return fmt.Errorf("the export at %s decrypts, but its key does not match the recorded public key %s", path, want)
	}
	u.Say("Recovery verified: the export at %s decrypts with this passphrase and matches the recorded public key.", path)
	return nil
}
