package backup

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
	if _, err := os.Stat(ManifestPath(dest, filepath.Base(earlier))); !os.IsNotExist(err) {
		t.Error("a failed run wrote a manifest")
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

// TestBackupsInSameInstantNeverOverwrite pins the reliability case: two
// successful backups taken at the identical timestamp must both survive
// under distinct names. A silent overwrite here would destroy a good
// backup, which retention could never recover.
func TestBackupsInSameInstantNeverOverwrite(t *testing.T) {
	f := &fake{}
	id, _ := recoverykey.Generate()
	dest := t.TempDir()
	frozen := time.Date(2026, 9, 11, 10, 48, 26, 0, time.UTC)

	o := opts(f, dest, id.Recipient().String(), false)
	o.Now = func() time.Time { return frozen }

	first, err := Backup(context.Background(), o, testState())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Backup(context.Background(), o, testState())
	if err != nil {
		t.Fatalf("second backup in the same instant failed: %v", err)
	}
	if second == first {
		t.Fatalf("second backup reused the first name %s", first)
	}
	// The first backup must be untouched, byte for byte.
	againBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatalf("first backup disappeared: %v", err)
	}
	if string(againBytes) != string(firstBytes) {
		t.Fatal("first backup was overwritten by the second")
	}

	// Exactly two published backups, no leftover partials.
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	var published, partials int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".partial-") {
			partials++
			continue
		}
		if strings.HasSuffix(e.Name(), ManifestSuffix) {
			continue
		}
		published++
	}
	if published != 2 || partials != 0 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("want 2 published and 0 partial, got %d/%d: %v", published, partials, names)
	}
}

// TestFailedBackupLeavesEarlierBackupsIntact proves a failing attempt
// neither publishes nor disturbs an existing successful backup.
func TestFailedBackupLeavesEarlierBackupsIntact(t *testing.T) {
	id, _ := recoverykey.Generate()
	dest := t.TempDir()
	frozen := time.Date(2026, 9, 11, 10, 48, 26, 0, time.UTC)

	good := &fake{}
	o := opts(good, dest, id.Recipient().String(), false)
	o.Now = func() time.Time { return frozen }
	first, err := Backup(context.Background(), o, testState())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(first)

	bad := &fake{failDump: true}
	o2 := opts(bad, dest, id.Recipient().String(), false)
	o2.Now = func() time.Time { return frozen }
	if _, err := Backup(context.Background(), o2, testState()); err == nil {
		t.Fatal("failing export must not publish a backup")
	}

	after, err := os.ReadFile(first)
	if err != nil || string(after) != string(before) {
		t.Fatal("the earlier successful backup was damaged by a failed attempt")
	}
	var published int
	entries, _ := os.ReadDir(dest)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".partial-") && !strings.HasSuffix(e.Name(), ManifestSuffix) {
			published++
		}
	}
	if published != 1 {
		t.Fatalf("want exactly 1 published backup, got %d", published)
	}
}

// TestPublishWritesACheckableCompletionManifest covers the evidence a
// scheduled run has to work from. It holds only the public key, so it
// cannot decrypt a backup to check it; the manifest lets it re-hash and
// length-check the ciphertext instead, and tells it which deployment the
// backup belongs to.
func TestPublishWritesACheckableCompletionManifest(t *testing.T) {
	id, _ := recoverykey.Generate()
	dest := t.TempDir()
	path, err := Backup(context.Background(), opts(&fake{}, dest, id.Recipient().String(), false), testState())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(path)

	m, err := VerifyPublished(dest, name, "dep-123")
	if err != nil {
		t.Fatalf("a freshly published backup does not verify: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Bytes != int64(len(raw)) {
		t.Errorf("manifest records %d bytes, file is %d", m.Bytes, len(raw))
	}
	if m.File != name || m.DeploymentID != "dep-123" || m.Mode != "age" {
		t.Errorf("manifest = %+v", m)
	}
	if m.ManifestVersion != ManifestVersion || m.FormatVersion != FormatVersion {
		t.Errorf("manifest versions = %d/%d", m.ManifestVersion, m.FormatVersion)
	}

	// Truncation and alteration are both caught, without any key.
	for what, content := range map[string][]byte{
		"truncated": raw[:len(raw)/2],
		"extended":  append(append([]byte{}, raw...), 'x'),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPublished(dest, name, "dep-123"); err == nil {
			t.Errorf("a %s backup verified against its manifest", what)
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Ownership scoping: the same backup is not another deployment's to
	// count or expire, and "" means "do not check", for restore.
	if _, err := VerifyPublished(dest, name, "dep-other"); err == nil {
		t.Error("a backup verified as belonging to another deployment")
	}
	if _, err := VerifyPublished(dest, name, ""); err != nil {
		t.Errorf("an unscoped check refused a good backup: %v", err)
	}

	// A backup with no manifest is not verifiable, and the caller must be
	// able to tell that apart from a mismatch.
	if err := os.Remove(ManifestPath(dest, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(dest, name); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing manifest reports %v, want a not-exist error", err)
	}
}

func TestManifestHoldsNoSecrets(t *testing.T) {
	id, _ := recoverykey.Generate()
	dest := t.TempDir()
	st := testState()
	st.Config["backup-public-key"] = id.Recipient().String()
	path, err := Backup(context.Background(), opts(&fake{}, dest, id.Recipient().String(), false), st)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ManifestPath(dest, filepath.Base(path)))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{id.String(), "AGE-SECRET-KEY-", "guacamole_entity", "hunter2"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the manifest leaks %q", secret)
		}
	}
	// Fail loudly if a field that could hold a secret is ever added.
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"manifest_version": true, "format_version": true,
		"deployment_id": true, "file": true, "bytes": true, "sha256": true,
		"mode": true, "published_at": true}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("unexpected field %q in the manifest; check it cannot hold a secret", k)
		}
	}
}

// TestPublishFallsBackToCopyWhereLinkIsUnsupported covers the destination
// the specification calls supported: an existing mounted share. Many
// SMB/CIFS mounts reject link(2), which failed the whole publish there.
// The fallback must keep both guarantees: never overwrite a published
// backup, never lose the export.
func TestPublishFallsBackToCopyWhereLinkIsUnsupported(t *testing.T) {
	realLink := linkFile
	t.Cleanup(func() { linkFile = realLink })
	var attempts int
	linkFile = func(oldname, newname string) error {
		attempts++
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EPERM}
	}

	id, _ := recoverykey.Generate()
	dest := t.TempDir()
	frozen := time.Date(2026, 9, 11, 10, 48, 26, 0, time.UTC)
	o := opts(&fake{}, dest, id.Recipient().String(), false)
	o.Now = func() time.Time { return frozen }

	first, err := Backup(context.Background(), o, testState())
	if err != nil {
		t.Fatalf("publishing to a filesystem without hard links failed: %v", err)
	}
	if attempts == 0 {
		t.Fatal("the link path was never attempted")
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPublished(dest, filepath.Base(first), "dep-123"); err != nil {
		t.Fatalf("the copied backup does not verify: %v", err)
	}

	// Same instant again: the first backup must survive untouched and the
	// second must take the next free name.
	second, err := Backup(context.Background(), o, testState())
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatalf("the copy fallback overwrote %s", first)
	}
	if !strings.HasSuffix(second, "-1.sql.age") {
		t.Errorf("second published name = %s, want the next free -N name", second)
	}
	again, err := os.ReadFile(first)
	if err != nil || string(again) != string(firstBytes) {
		t.Fatal("the first backup was altered by the second publish")
	}

	// Two backups, two manifests, and no partial left behind.
	var published, partials, manifests int
	entries, _ := os.ReadDir(dest)
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), ".partial-"):
			partials++
		case strings.HasSuffix(e.Name(), ManifestSuffix):
			manifests++
		default:
			published++
		}
	}
	if published != 2 || manifests != 2 || partials != 0 {
		t.Fatalf("published/manifests/partials = %d/%d/%d, want 2/2/0", published, manifests, partials)
	}
}

// TestFailedCopyPublishLeavesNoPublishedFile proves the fallback's failure
// path. A copy that dies part way must not leave a reserved or half-written
// file under a published name, where retention would have to reason about
// it.
func TestFailedCopyPublishLeavesNoPublishedFile(t *testing.T) {
	realLink := linkFile
	t.Cleanup(func() { linkFile = realLink })
	linkFile = func(string, string) error { return syscall.ENOTSUP }

	dest := t.TempDir()
	missing := filepath.Join(dest, ".partial-gone")
	_, err := publishNonDestructively(dest, missing, "guacdeploy-db-20260911T104826.000Z", ".sql.age")
	if err == nil {
		t.Fatal("publishing a missing export reported success")
	}
	entries, _ := os.ReadDir(dest)
	for _, e := range entries {
		t.Errorf("a failed publish left %s behind", e.Name())
	}
}
