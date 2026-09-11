package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

const fakeDump = "--\n-- PostgreSQL database dump\n--\nCREATE TABLE guacamole_entity ();\nINSERT INTO guacdeploy_metadata VALUES (1);\n"

type call struct {
	args  []string
	stdin string
}

// fake is the docker seam: it answers psql and pg_dump compose exec calls.
type fake struct {
	calls    []call
	failDump bool
	failPsql bool
}

func (f *fake) run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	f.calls = append(f.calls, call{args, stdin})
	joined := name + " " + strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "pg_dump"):
		if f.failDump {
			return "", "pg_dump: error: connection to server failed", errors.New("exit status 1")
		}
		return fakeDump, "", nil
	case strings.Contains(joined, "psql"):
		if f.failPsql {
			return "", "psql: error: something broke", errors.New("exit status 1")
		}
		return "", "", nil
	}
	return "", "", errors.New("unexpected command: " + joined)
}

func testState() *state.State {
	return &state.State{DeploymentID: "dep-123", Config: map[string]string{"guac-hostname": "guac.example.com"}}
}

func opts(f *fake, dest, pubKey string, plaintext bool) Options {
	return Options{Run: f.run, InstallDir: "/opt/guacamole", Dest: dest,
		Plaintext: plaintext, PublicKey: pubKey, GuacVersion: "1.6.0"}
}

func TestBackupSnapshotBeforeExport(t *testing.T) {
	f := &fake{}
	id, _ := recoverykey.Generate()
	dest := t.TempDir()
	if _, err := Backup(context.Background(), opts(f, dest, id.Recipient().String(), false), testState()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls = %d, want snapshot then export", len(f.calls))
	}
	snap := f.calls[0]
	if !strings.Contains(strings.Join(snap.args, " "), "psql") {
		t.Fatalf("first call is not psql: %v", snap.args)
	}
	for _, want := range []string{"CREATE TABLE IF NOT EXISTS guacdeploy_metadata", "INSERT INTO guacdeploy_metadata", "dep-123"} {
		if !strings.Contains(snap.stdin, want) {
			t.Errorf("snapshot SQL missing %q", want)
		}
	}
	if !strings.Contains(strings.Join(f.calls[1].args, " "), "pg_dump") {
		t.Fatalf("second call is not pg_dump: %v", f.calls[1].args)
	}
	if !strings.Contains(strings.Join(f.calls[1].args, " "), "--format=plain") {
		t.Errorf("export must use plain format")
	}
}

func TestBackupPublishOnlyAfterSuccess(t *testing.T) {
	dest := t.TempDir()
	earlier := filepath.Join(dest, "guacdeploy-db-20250101T000000Z.sql.age")
	if err := os.WriteFile(earlier, []byte("earlier backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := recoverykey.Generate()
	f := &fake{failDump: true}
	_, err := Backup(context.Background(), opts(f, dest, id.Recipient().String(), false), testState())
	if err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("err = %v, want a not-published failure", err)
	}
	entries, _ := os.ReadDir(dest)
	for _, e := range entries {
		if e.Name() != filepath.Base(earlier) && !strings.HasPrefix(e.Name(), ".partial-") {
			t.Errorf("unexpected published file after failure: %s", e.Name())
		}
	}
	if b, _ := os.ReadFile(earlier); string(b) != "earlier backup" {
		t.Error("an earlier finished backup was altered by a failed run")
	}
}

func TestBackupEncryptedByDefaultAndPlaintextOnlyWithFlag(t *testing.T) {
	id, _ := recoverykey.Generate()

	dest := t.TempDir()
	path, err := Backup(context.Background(), opts(&fake{}, dest, id.Recipient().String(), false), testState())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".sql.age") {
		t.Fatalf("default backup name = %s, want .sql.age", path)
	}
	raw, _ := os.ReadFile(path)
	if !Encrypted(raw) {
		t.Fatal("default backup is not age-encrypted")
	}
	if strings.Contains(string(raw), "guacamole_entity") {
		t.Fatal("encrypted backup leaks dump content")
	}

	dest2 := t.TempDir()
	path2, err := Backup(context.Background(), opts(&fake{}, dest2, "", true), testState())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path2, ".sql") || strings.HasSuffix(path2, ".sql.age") {
		t.Fatalf("plaintext backup name = %s, want .sql", path2)
	}
	raw2, _ := os.ReadFile(path2)
	if !strings.Contains(string(raw2), "mode=none") || !strings.Contains(string(raw2), "guacamole_entity") {
		t.Fatal("plaintext backup content is wrong")
	}
}

func TestBackupRefusesEncryptedWithoutKey(t *testing.T) {
	f := &fake{}
	_, err := Backup(context.Background(), opts(f, t.TempDir(), "", false), testState())
	if err == nil || !strings.Contains(err.Error(), "backup-key") {
		t.Fatalf("err = %v, want a pointer at guacdeploy backup-key", err)
	}
	if len(f.calls) != 0 {
		t.Fatal("a refused backup must not touch the database")
	}
}

func TestBackupMissingDestinationFailsBeforeExport(t *testing.T) {
	id, _ := recoverykey.Generate()
	f := &fake{}
	_, err := Backup(context.Background(), opts(f, filepath.Join(t.TempDir(), "missing-mount"), id.Recipient().String(), false), testState())
	if err == nil || !strings.Contains(err.Error(), "nothing was exported") {
		t.Fatalf("err = %v, want a visible destination failure", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("missing destination must fail before any export; %d commands ran", len(f.calls))
	}
}

func TestValidateRejectsTruncatedOrAltered(t *testing.T) {
	dest := t.TempDir()
	path, err := Backup(context.Background(), opts(&fake{}, dest, "", true), testState())
	if err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(path)

	cases := map[string][]byte{
		"truncated":  good[:len(good)/2],
		"no marker":  []byte(strings.Join(strings.Split(strings.TrimSpace(string(good)), "\n")[:3], "\n") + "\n"),
		"altered":    []byte(strings.Replace(string(good), "guacamole_entity", "guacamole_evil", 1)),
		"not a dump": []byte("hello world\n"),
	}
	for name, raw := range cases {
		if _, _, err := Validate(raw, nil, "1.6.0"); err == nil {
			t.Errorf("%s: Validate accepted a bad backup", name)
		}
	}
	if _, _, err := Validate(good, nil, "1.6.0"); err != nil {
		t.Errorf("Validate rejected a good backup: %v", err)
	}
	if _, _, err := Validate(good, nil, "9.9.9"); err == nil {
		t.Error("Validate accepted a Guacamole version mismatch")
	}
}

func TestRoundtripEncryptedBackupRestore(t *testing.T) {
	id, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	f := &fake{}
	path, err := Backup(context.Background(), opts(f, dest, id.Recipient().String(), false), testState())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypted content needs the identity; without it validation fails
	// and, by construction, no database command can run.
	if _, _, err := Validate(raw, nil, "1.6.0"); err == nil {
		t.Fatal("Validate decrypted without the identity")
	}
	sql, info, err := Validate(raw, id, "1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode != "age" || info.GuacVersion != "1.6.0" || info.FormatVersion != FormatVersion {
		t.Fatalf("info = %+v", info)
	}
	if !strings.Contains(sql, "guacamole_entity") {
		t.Fatal("validated SQL lost the dump content")
	}

	rf := &fake{}
	if err := Apply(context.Background(), Options{Run: rf.run, InstallDir: "/opt/guacamole"}, sql); err != nil {
		t.Fatal(err)
	}
	if len(rf.calls) != 2 {
		t.Fatalf("restore calls = %d, want schema reset then dump replay", len(rf.calls))
	}
	if !strings.Contains(rf.calls[0].stdin, "DROP SCHEMA public CASCADE") || !strings.Contains(rf.calls[0].stdin, "CREATE SCHEMA public") {
		t.Errorf("first restore command is not the schema reset: %q", rf.calls[0].stdin)
	}
	if rf.calls[1].stdin != sql {
		t.Error("the replayed SQL differs from the validated dump")
	}
	for _, c := range rf.calls {
		if !strings.Contains(strings.Join(c.args, " "), "ON_ERROR_STOP=1") {
			t.Error("restore psql must run with ON_ERROR_STOP=1")
		}
	}
}
