// Package recoverykey generates and exports the backup recovery key pair.
//
// It wraps filippo.io/age. The specification requires one supported
// cryptographic default, and age v1 is the audited standard for exactly this
// shape: X25519 recipients for backup encryption, scrypt passphrase
// encryption for the private-key export. Scheduled backups use only the
// public key; recovery needs the exported private key and its passphrase.
package recoverykey

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// Generate creates a new X25519 identity in memory. Callers must never
// write the plaintext private key to disk; use ExportEncrypted.
func Generate() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// ExportEncrypted writes the identity's private key to path, encrypted with
// an scrypt passphrase. The file is created 0600 and the parent directory
// 0700. An existing file is never overwritten: replacing an export while
// backups still depend on its key would orphan them.
func ExportEncrypted(id *age.X25519Identity, passphrase, path string) error {
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key export: %w", err)
	}
	if err := func() error {
		w, err := age.Encrypt(f, r)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, id.String()+"\n"); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		return f.Sync()
	}(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("write key export: %w", err)
	}
	return f.Close()
}

// RecoverIdentity decrypts an ExportEncrypted file back to a usable
// identity. This is the recovery path: it needs both the export file and
// the passphrase.
func RecoverIdentity(path, passphrase string) (*age.X25519Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sid, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(f, sid)
	if err != nil {
		return nil, fmt.Errorf("decrypt key export (wrong passphrase, or a damaged file): %w", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read key export: %w", err)
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(b)))
}

// EncryptTo encrypts src to dst for the backup public key. Only the public
// key is needed, so scheduled backups never touch the private key.
func EncryptTo(recipientPubKey string, src io.Reader, dst io.Writer) error {
	r, err := age.ParseX25519Recipient(recipientPubKey)
	if err != nil {
		return fmt.Errorf("parse backup public key: %w", err)
	}
	w, err := age.Encrypt(dst, r)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	return w.Close()
}

// Decrypt decrypts data produced by EncryptTo, using a recovered identity.
func Decrypt(id *age.X25519Identity, src io.Reader, dst io.Writer) error {
	r, err := age.Decrypt(src, id)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}
