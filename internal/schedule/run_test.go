package schedule

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
)

const testDump = "--\n-- PostgreSQL database dump\n--\nCREATE TABLE guacamole_entity ();\n"

// completeBackup builds a file that satisfies the internal/backup completion
// contract: header line, dump, and the sha256 end marker over both.
func completeBackup() string {
	body := "-- guacdeploy backup format=1 guacamole=1.6.0 mode=none\n" + testDump
	return body + fmt.Sprintf("-- guacdeploy dump complete sha256:%x\n", sha256.Sum256([]byte(body)))
}

// writePlaintext publishes a valid plaintext backup at the given timestamp.
func writePlaintext(t *testing.T, dir, stamp string) string {
	t.Helper()
	name := "guacdeploy-db-" + stamp + ".sql"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(completeBackup()), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// writeEncrypted publishes a real age-encrypted backup.
func writeEncrypted(t *testing.T, dir, stamp string) string {
	t.Helper()
	id, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	name := "guacdeploy-db-" + stamp + ".sql.age"
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := recoverykey.EncryptTo(id.Recipient().String(), strings.NewReader(completeBackup()), f); err != nil {
		t.Fatal(err)
	}
	return name
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func remaining(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func has(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestPruneKeepsNewestValidBackups(t *testing.T) {
	dir := t.TempDir()
	stamps := []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z",
		"20260104T000000Z", "20260105T000000Z"}
	for _, s := range stamps {
		writePlaintext(t, dir, s)
	}

	removed, err := Prune(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed %d files, want 3: %v", len(removed), removed)
	}
	left := remaining(t, dir)
	if len(left) != 2 {
		t.Fatalf("kept %v, want the two newest", left)
	}
	for _, want := range []string{"guacdeploy-db-20260105T000000Z.sql", "guacdeploy-db-20260104T000000Z.sql"} {
		if !has(left, want) {
			t.Errorf("newest backup %s was deleted; kept %v", want, left)
		}
	}
	// The oldest must be gone, and it must be the ones reported.
	for _, r := range removed {
		if _, err := os.Stat(r); !os.IsNotExist(err) {
			t.Errorf("%s reported removed but still present", r)
		}
	}
}

func TestPruneHonoursConfiguredRetention(t *testing.T) {
	for _, keep := range []int{1, 3, 7} {
		dir := t.TempDir()
		for i := 1; i <= 9; i++ {
			writePlaintext(t, dir, fmt.Sprintf("2026010%dT000000Z", i))
		}
		if _, err := Prune(dir, keep); err != nil {
			t.Fatal(err)
		}
		if left := remaining(t, dir); len(left) != keep {
			t.Errorf("keep=%d left %d files: %v", keep, len(left), left)
		}
	}
}

func TestPruneUnderRetentionDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	writePlaintext(t, dir, "20260101T000000Z")
	writePlaintext(t, dir, "20260102T000000Z")
	removed, err := Prune(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("removed %v with fewer backups than the retention count", removed)
	}
	if left := remaining(t, dir); len(left) != 2 {
		t.Errorf("left = %v, want both backups", left)
	}
}

func TestPruneIgnoresPartialAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	good := []string{
		writePlaintext(t, dir, "20260108T000000Z"),
		writePlaintext(t, dir, "20260109T000000Z"),
	}
	// A failed export in progress or abandoned. Older than everything, so a
	// retention that counted it would expire a real backup in its place.
	write(t, dir, ".partial-guacdeploy-db-20260101T000000Z.sql", completeBackup())
	// Published name, truncated content: the completion marker is missing.
	write(t, dir, "guacdeploy-db-20260102T000000Z.sql",
		"-- guacdeploy backup format=1 guacamole=1.6.0 mode=none\n"+testDump)
	// Published name, marker present but content altered afterwards.
	write(t, dir, "guacdeploy-db-20260103T000000Z.sql",
		strings.Replace(completeBackup(), "guacamole_entity", "tampered_entity", 1))
	// Not a guacdeploy backup at all.
	write(t, dir, "guacdeploy-db-20260104T000000Z.sql", "DROP TABLE everything;\n")
	// Unrelated files in a shared destination directory.
	write(t, dir, "notes.txt", "hello")
	write(t, dir, "guacdeploy-db-bogus.sql", completeBackup())

	names, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("List counted %v as valid, want only the two complete backups", names)
	}

	// keep=1 must expire exactly one file: the older *valid* backup. If any
	// partial or invalid file had been counted, a valid backup would die in
	// its place.
	removed, err := Prune(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || filepath.Base(removed[0]) != good[0] {
		t.Fatalf("removed %v, want only %s", removed, good[0])
	}
	left := remaining(t, dir)
	if !has(left, good[1]) {
		t.Errorf("newest valid backup was deleted; left %v", left)
	}
	for _, kept := range []string{".partial-guacdeploy-db-20260101T000000Z.sql",
		"guacdeploy-db-20260102T000000Z.sql", "guacdeploy-db-20260103T000000Z.sql",
		"guacdeploy-db-20260104T000000Z.sql", "notes.txt", "guacdeploy-db-bogus.sql"} {
		if !has(left, kept) {
			t.Errorf("retention deleted %s, which it does not own", kept)
		}
	}
}

func TestPruneCountsEncryptedBackups(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z"} {
		writeEncrypted(t, dir, s)
	}
	// An encrypted file cannot be verified without the recovery key, so the
	// published name plus the age header is the evidence. A file whose name
	// claims encryption but holds plaintext is not accepted.
	write(t, dir, "guacdeploy-db-20260104T000000Z.sql.age", completeBackup())

	names, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 {
		t.Fatalf("List = %v, want the three real encrypted backups", names)
	}
	removed, err := Prune(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || filepath.Base(removed[0]) != "guacdeploy-db-20260101T000000Z.sql.age" {
		t.Errorf("removed %v, want the oldest encrypted backup", removed)
	}
}

func TestPruneNeverEmptiesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	writePlaintext(t, dir, "20260101T000000Z")

	// Zero and negative retention are refused outright: there is no
	// configuration that expires every backup.
	for _, keep := range []int{0, -1, -7} {
		if _, err := Prune(dir, keep); err == nil {
			t.Errorf("keep=%d was accepted", keep)
		}
	}
	if left := remaining(t, dir); len(left) != 1 {
		t.Fatalf("left = %v, want the only backup untouched", left)
	}

	// Even at the minimum, the newest survives.
	removed, err := Prune(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("removed %v from a directory holding one backup", removed)
	}
}

func TestRequireMountRejectsAnUnmountedDirectory(t *testing.T) {
	// A mount point that exists but holds no mount is on the same device as
	// its parent. Writing there silently fills local storage.
	dir := filepath.Join(t.TempDir(), "share")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := RequireMount(dir)
	if err == nil {
		t.Fatal("an unmounted mount-point directory was accepted")
	}
	if !strings.Contains(err.Error(), "not a mount point") {
		t.Errorf("error does not explain the missing mount: %v", err)
	}
	if err := RequireMount(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing destination was accepted")
	}
}

// runOptions builds options for RunBackup with a real destination.
func runOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	o := Options{
		Run: (&fakeSystemd{}).run, DeploymentID: "dep-123",
		StateDir: filepath.Join(root, "state"), Dest: filepath.Join(root, "backups"),
		UnitDir: filepath.Join(root, "units"), RuntimeDir: filepath.Join(root, "runtime"),
		Exe: filepath.Join(root, "guacdeploy"), Keep: 2,
	}
	if err := os.WriteFile(o.Exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{o.StateDir, o.Dest} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func TestRunBackupFailureDeletesNothing(t *testing.T) {
	o := runOptions(t)
	// More backups present than retention allows: a run that pruned on
	// failure would delete some of them.
	for _, s := range []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z",
		"20260104T000000Z", "20260105T000000Z"} {
		writePlaintext(t, o.Dest, s)
	}
	before := remaining(t, o.Dest)

	s, err := RunBackup(context.Background(), o, func(context.Context) (string, error) {
		return "", errors.New("database export failed, backup not published: exit status 1")
	})
	if err == nil {
		t.Fatal("a failed backup returned success")
	}
	if s.Result != "failed" {
		t.Errorf("Result = %q, want failed", s.Result)
	}
	if len(s.Removed) != 0 {
		t.Errorf("a failed run reported deletions: %v", s.Removed)
	}
	after := remaining(t, o.Dest)
	if len(after) != len(before) {
		t.Fatalf("a failed backup expired older backups: %v -> %v", before, after)
	}
	for _, n := range before {
		if !has(after, n) {
			t.Errorf("%s was deleted by a failed run", n)
		}
	}

	// The failure is still reported, with the destination and the reason.
	got, err := ReadStatus(o.StateDir)
	if err != nil || got == nil {
		t.Fatalf("no status recorded for the failed run: %v", err)
	}
	if got.Result != "failed" || !strings.Contains(got.Error, "not published") {
		t.Errorf("status does not explain the failure: %+v", got)
	}
	if got.Destination != o.Dest {
		t.Errorf("status destination = %q, want %q", got.Destination, o.Dest)
	}
	if got.Kept != 5 {
		t.Errorf("status counted %d valid backups, want 5", got.Kept)
	}
}

func TestRunBackupMissingMountDeletesNothingAndExportsNothing(t *testing.T) {
	o := runOptions(t)
	o.RequireMount = true
	writePlaintext(t, o.Dest, "20260101T000000Z")

	called := false
	s, err := RunBackup(context.Background(), o, func(context.Context) (string, error) {
		called = true
		return "", nil
	})
	if err == nil {
		t.Fatal("a missing mount was accepted")
	}
	if called {
		t.Error("the export ran despite the missing mount")
	}
	if s.Result != "failed" || len(s.Removed) != 0 {
		t.Errorf("status = %+v, want a failure with no deletions", s)
	}
	if left := remaining(t, o.Dest); !has(left, "guacdeploy-db-20260101T000000Z.sql") {
		t.Errorf("the existing backup was disturbed: %v", left)
	}
}

func TestRunBackupSuccessPrunesAndReports(t *testing.T) {
	o := runOptions(t) // Keep: 2
	for _, s := range []string{"20260101T000000Z", "20260102T000000Z"} {
		writePlaintext(t, o.Dest, s)
	}

	s, err := RunBackup(context.Background(), o, func(context.Context) (string, error) {
		name := writePlaintext(t, o.Dest, "20260103T000000Z")
		return filepath.Join(o.Dest, name), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Result != "ok" {
		t.Errorf("Result = %q, want ok", s.Result)
	}
	if !strings.HasSuffix(s.Published, "guacdeploy-db-20260103T000000Z.sql") {
		t.Errorf("Published = %q", s.Published)
	}
	if len(s.Removed) != 1 || !strings.HasSuffix(s.Removed[0], "guacdeploy-db-20260101T000000Z.sql") {
		t.Errorf("Removed = %v, want the oldest backup", s.Removed)
	}
	if s.Kept != 2 {
		t.Errorf("Kept = %d, want 2", s.Kept)
	}

	// The summary names the destination and the run outcome, which is the
	// whole point of the record.
	out := Summary(o.StateDir)
	for _, want := range []string{o.Dest, "ok", "guacdeploy-db-20260103T000000Z.sql", "guacdeploy-db-20260101T000000Z.sql"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestStatusFileIsOwnerOnlyAndHoldsNoSecrets(t *testing.T) {
	o := runOptions(t)
	secrets := []string{"hunter2", "AGE-SECRET-KEY-1ABCDEF", "passphrase"}
	if _, err := RunBackup(context.Background(), o, func(context.Context) (string, error) {
		name := writePlaintext(t, o.Dest, "20260103T000000Z")
		return filepath.Join(o.Dest, name), nil
	}); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(StatusPath(o.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("status file mode = %v, want 0600", fi.Mode().Perm())
	}
	raw, err := os.ReadFile(StatusPath(o.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(raw), s) {
			t.Errorf("status file leaked %q", s)
		}
	}
	// The record is paths, counts and outcomes only. Fail loudly if a field
	// that could hold a credential is ever added.
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"ran": true, "result": true, "destination": true,
		"published": true, "error": true, "removed": true, "kept": true,
		"keep": true, "on_calendar": true, "require_mount": true}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("unexpected field %q in the status file; check it cannot hold a secret", k)
		}
	}
}

func TestSummaryBeforeAnyRun(t *testing.T) {
	out := Summary(t.TempDir())
	if !strings.Contains(out, "No scheduled backup has run yet") {
		t.Errorf("summary before the first run = %q", out)
	}
	s, err := ReadStatus(t.TempDir())
	if err != nil || s != nil {
		t.Errorf("ReadStatus = %v, %v; want nil, nil", s, err)
	}
}

// TestRetentionRecognisesCurrentBackupNames guards the seam between
// internal/backup's non-overwriting publish and retention. Millisecond
// timestamps and the "-N" collision suffix must count as published
// backups; if they did not, retention would silently stop pruning and
// backups would grow without limit.
func TestRetentionRecognisesCurrentBackupNames(t *testing.T) {
	dir := t.TempDir()
	current := []string{
		"guacdeploy-db-20260911T104826.000Z.sql",
		"guacdeploy-db-20260911T104826.000Z-1.sql",
		"guacdeploy-db-20260102T000000Z.sql", // written by an earlier version
	}
	for _, n := range current {
		write(t, dir, n, completeBackup())
		if !Valid(dir, n) {
			t.Errorf("published backup %s not recognised by retention", n)
		}
	}
	got, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(current) {
		t.Fatalf("List returned %d backups, want %d: %v", len(got), len(current), got)
	}

	// A partial of the current shape stays invisible to retention.
	partial := ".partial-guacdeploy-db-20260911T104826.000Z-123456.sql"
	write(t, dir, partial, completeBackup())
	if Valid(dir, partial) {
		t.Fatal("a .partial- file must never count as a published backup")
	}
}
