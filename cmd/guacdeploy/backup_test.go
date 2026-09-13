package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

const cmdFakeDump = "--\n-- PostgreSQL database dump\n--\nCREATE TABLE guacamole_entity ();\n"

type recorded struct {
	args  []string
	stdin string
}

func fakeDocker(calls *[]recorded) func(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	return func(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
		*calls = append(*calls, recorded{args, stdin})
		if strings.Contains(strings.Join(args, " "), "pg_dump") {
			return cmdFakeDump, "", nil
		}
		return "", "", nil
	}
}

// seedDeployment writes a deployment record with a recorded backup public
// key and the passphrase-encrypted private-key export, as backup-key would.
// It returns the deployment ID, which retention scopes itself to.
func seedDeployment(t *testing.T, dir, passphrase string) string {
	t.Helper()
	id, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverykey.ExportEncrypted(id, passphrase, backupKeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := &state.State{DeploymentID: state.NewID(), CreatedAt: time.Now().UTC(),
		Config: map[string]string{backupPublicKeyConfig: id.Recipient().String()}}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	return st.DeploymentID
}

func TestBackupRestoreCommandsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	const pass = "restore-passphrase-value"
	seedDeployment(t, dir, pass)

	var bcalls []recorded
	var out bytes.Buffer
	if err := backupCmd(context.Background(), fakeDocker(&bcalls), dir, "", false, &ui.UI{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Backup published: ") {
		t.Fatalf("output = %q", out.String())
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "backups", "guacdeploy-db-*.sql.age"))
	if len(matches) != 1 {
		t.Fatalf("published backups = %v", matches)
	}

	// Guided restore: passphrase via hidden input, consent via prompt.
	var rcalls []recorded
	var rout bytes.Buffer
	u := &ui.UI{In: bufio.NewReader(strings.NewReader("y\n")), Out: &rout, Interactive: true,
		Secret: func(string) (string, error) { return pass, nil }}
	if err := restoreCmd(context.Background(), fakeDocker(&rcalls), dir, matches[0], "", false, u); err != nil {
		t.Fatal(err)
	}
	if len(rcalls) != 2 || !strings.Contains(rcalls[0].stdin, "DROP SCHEMA public CASCADE") {
		t.Fatalf("restore commands = %+v", rcalls)
	}
	if !strings.Contains(rcalls[1].stdin, "guacamole_entity") {
		t.Fatal("restore did not replay the dump")
	}
	if !strings.Contains(rout.String(), "Restore complete") {
		t.Fatalf("output = %q", rout.String())
	}

	// No passphrase or key material in any output or in files other than
	// the dump itself.
	for name, b := range map[string][]byte{"backup output": out.Bytes(), "restore output": rout.Bytes()} {
		if bytes.Contains(b, []byte(pass)) || bytes.Contains(b, []byte("AGE-SECRET-KEY-")) {
			t.Errorf("%s contains secret material", name)
		}
	}
	stateRaw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if bytes.Contains(stateRaw, []byte(pass)) {
		t.Error("state.json contains the passphrase")
	}
}

func TestRestoreFailedValidationIssuesNoDatabaseCommands(t *testing.T) {
	dir := t.TempDir()
	seedDeployment(t, dir, "p")
	bad := filepath.Join(dir, "bad.sql")
	if err := os.WriteFile(bad, []byte("-- guacdeploy backup format=1 guacamole=1.6.0 mode=none\ntruncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []recorded
	err := restoreCmd(context.Background(), fakeDocker(&calls), dir, bad, "", true, &ui.UI{Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "the database was not changed") {
		t.Fatalf("err = %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("failed validation issued %d database commands, want 0", len(calls))
	}
}

func TestRestoreUnattendedNeedsYes(t *testing.T) {
	dir := t.TempDir()
	seedDeployment(t, dir, "p")

	var bcalls []recorded
	var out bytes.Buffer
	if err := backupCmd(context.Background(), fakeDocker(&bcalls), dir, "", true, &ui.UI{Out: &out}); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "backups", "guacdeploy-db-*.sql"))
	if len(matches) != 1 {
		t.Fatalf("published backups = %v", matches)
	}

	var calls []recorded
	err := restoreCmd(context.Background(), fakeDocker(&calls), dir, matches[0], "", false, &ui.UI{Out: &out})
	if !errors.Is(err, session.ErrApprovalRequired) {
		t.Fatalf("err = %v, want ErrApprovalRequired without --yes", err)
	}
	if len(calls) != 0 {
		t.Fatal("a restore without consent must not touch the database")
	}

	if err := restoreCmd(context.Background(), fakeDocker(&calls), dir, matches[0], "", true, &ui.UI{Out: &out}); err != nil {
		t.Fatalf("with --yes: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("consented restore commands = %d, want 2", len(calls))
	}
}

// TestRestoreRefusesAManifestMismatch covers a backup that is internally
// valid — right header, right version, intact completion marker — but is no
// longer the file that was published under that name. Only the completion
// manifest can tell, and restore must refuse before touching the database.
func TestRestoreRefusesAManifestMismatch(t *testing.T) {
	dir := t.TempDir()
	seedDeployment(t, dir, "p")
	var out bytes.Buffer
	var bcalls []recorded
	if err := backupCmd(context.Background(), fakeDocker(&bcalls), dir, "", true, &ui.UI{Out: &out}); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "backups", "guacdeploy-db-*.sql"))
	if len(matches) != 1 {
		t.Fatalf("published backups = %v", matches)
	}

	// Replace the published file with a different, perfectly valid backup:
	// a whole dump swapped in under a name that already has a manifest.
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(raw), "\n")
	body := head + "\n" + strings.Replace(cmdFakeDump, "guacamole_entity", "guacamole_other", 1)
	swapped := body + fmt.Sprintf("-- guacdeploy dump complete sha256:%x\n", sha256.Sum256([]byte(body)))
	if err := os.WriteFile(matches[0], []byte(swapped), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []recorded
	err = restoreCmd(context.Background(), fakeDocker(&calls), dir, matches[0], "", true, &ui.UI{Out: &out})
	if err == nil {
		t.Fatal("restore accepted a backup that does not match its manifest")
	}
	for _, want := range []string{"the database was not changed", "manifest"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a refused restore issued %d database commands, want 0", len(calls))
	}

	// With no manifest at all the same file restores: an administrator may
	// copy only the backup off the host, and a replacement host must still
	// be able to use it.
	if err := os.Remove(backup.ManifestPath(filepath.Split(matches[0]))); err != nil {
		t.Fatal(err)
	}
	if err := restoreCmd(context.Background(), fakeDocker(&calls), dir, matches[0], "", true, &ui.UI{Out: &out}); err != nil {
		t.Fatalf("a backup copied without its manifest was refused: %v", err)
	}
}

func TestRestoreEncryptedWithIdentityFile(t *testing.T) {
	dir := t.TempDir()
	const pass = "another-passphrase"
	seedDeployment(t, dir, pass)

	var bcalls []recorded
	var out bytes.Buffer
	if err := backupCmd(context.Background(), fakeDocker(&bcalls), dir, "", false, &ui.UI{Out: &out}); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "backups", "guacdeploy-db-*.sql.age"))

	// Recover the identity the way a replacement host would, then hand it
	// to restore as a standard age identity file.
	id, err := recoverykey.RecoverIdentity(backupKeyPath(dir), pass)
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(idFile, []byte("# test identity\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var calls []recorded
	if err := restoreCmd(context.Background(), fakeDocker(&calls), dir, matches[0], idFile, true, &ui.UI{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("restore commands = %d, want 2", len(calls))
	}
}
