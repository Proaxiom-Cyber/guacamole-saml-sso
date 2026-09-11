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

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
)

const testDump = "--\n-- PostgreSQL database dump\n--\nCREATE TABLE guacamole_entity ();\n"

// testDeployment is the deployment that owns the backups in these tests.
// It matches runOptions, so retention scoping works in both.
const testDeployment = "dep-123"

// completeBackup builds a file that satisfies the internal/backup completion
// contract: header line, dump, and the sha256 end marker over both.
func completeBackup() string {
	body := "-- guacdeploy backup format=1 guacamole=1.6.0 mode=none\n" + testDump
	return body + fmt.Sprintf("-- guacdeploy dump complete sha256:%x\n", sha256.Sum256([]byte(body)))
}

// manifest publishes the completion manifest for an existing file, as
// internal/backup does after publishing a backup.
func manifest(t *testing.T, dir, name, deploymentID string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	mode := "none"
	if strings.HasSuffix(name, ".age") {
		mode = "age"
	}
	b, err := json.MarshalIndent(backup.Manifest{
		ManifestVersion: backup.ManifestVersion, FormatVersion: backup.FormatVersion,
		DeploymentID: deploymentID, File: name, Bytes: int64(len(raw)),
		SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Mode: mode,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup.ManifestPath(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writePlaintext publishes a valid plaintext backup at the given timestamp.
func writePlaintext(t *testing.T, dir, stamp string) string {
	t.Helper()
	return writeNamed(t, dir, "guacdeploy-db-"+stamp+".sql", completeBackup())
}

// writeNamed publishes a backup under an exact name, with its manifest.
func writeNamed(t *testing.T, dir, name, content string) string {
	t.Helper()
	write(t, dir, name, content)
	manifest(t, dir, name, testDeployment)
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
	if err := recoverykey.EncryptTo(id.Recipient().String(), strings.NewReader(completeBackup()), f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	manifest(t, dir, name, testDeployment)
	return name
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// remaining lists what is left in dir, without the completion manifests:
// every published backup has one, and counting them would double every
// assertion about how many files survive.
func remaining(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), backup.ManifestSuffix) {
			continue
		}
		names = append(names, e.Name())
	}
	return names
}

// manifests lists the completion manifests left in dir.
func manifests(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), backup.ManifestSuffix) {
			names = append(names, e.Name())
		}
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

	removed, err := Prune(dir, 2, testDeployment)
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
		if _, err := Prune(dir, keep, testDeployment); err != nil {
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
	removed, err := Prune(dir, 7, testDeployment)
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

	names, err := List(dir, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("List counted %v as valid, want only the two complete backups", names)
	}

	// keep=1 must expire exactly one file: the older *valid* backup. If any
	// partial or invalid file had been counted, a valid backup would die in
	// its place.
	removed, err := Prune(dir, 1, testDeployment)
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

	names, err := List(dir, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 {
		t.Fatalf("List = %v, want the three real encrypted backups", names)
	}
	removed, err := Prune(dir, 2, testDeployment)
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
		if _, err := Prune(dir, keep, testDeployment); err == nil {
			t.Errorf("keep=%d was accepted", keep)
		}
	}
	if left := remaining(t, dir); len(left) != 1 {
		t.Fatalf("left = %v, want the only backup untouched", left)
	}

	// Even at the minimum, the newest survives.
	removed, err := Prune(dir, 1, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("removed %v from a directory holding one backup", removed)
	}
}

func TestRequireMountRejectsAnUnmountedDirectory(t *testing.T) {
	// A mount point that exists but holds no mount is on the same device as
	// the deployment's own storage. Writing there silently fills local disk.
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	dir := filepath.Join(root, "share")
	for _, d := range []string{stateDir, dir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	err := RequireMount(stateDir, dir)
	if err == nil {
		t.Fatal("an unmounted mount-point directory was accepted")
	}
	if !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("error does not explain the missing mount: %v", err)
	}
	if err := RequireMount(stateDir, filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing destination was accepted")
	}
}

// fakeMounts replaces the device lookup so a test can simulate a share
// being mounted, unmounted, and replaced. A unit test cannot mount
// anything; every path is a real directory, only the device is simulated.
//
// devices maps a path prefix to the device of everything at or below it.
// The longest matching prefix wins, so a mount inside a mount works.
func fakeMounts(t *testing.T, devices map[string]uint64) {
	t.Helper()
	real := statDev
	t.Cleanup(func() { statDev = real })
	statDev = func(path string) (uint64, error) {
		if _, err := os.Stat(path); err != nil {
			return 0, err
		}
		path = filepath.Clean(path)
		best, dev := -1, uint64(1) // 1 is the host's own filesystem
		for prefix, d := range devices {
			if (path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator))) && len(prefix) > best {
				best, dev = len(prefix), d
			}
		}
		return dev, nil
	}
}

// mountedShare builds a state directory and a backup destination that is a
// subfolder inside a mounted share, the shape an administrator actually
// uses. It returns the state directory, the share's mount point, and the
// destination.
func mountedShare(t *testing.T) (stateDir, mount, dest string) {
	t.Helper()
	root := t.TempDir()
	stateDir = filepath.Join(root, "state")
	mount = filepath.Join(root, "mnt", "share")
	dest = filepath.Join(mount, "guacamole", "db")
	for _, d := range []string{stateDir, dest} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fakeMounts(t, map[string]uint64{mount: 2})
	return stateDir, mount, dest
}

// TestRequireMountAcceptsASubfolderInsideAMount pins the destination shape
// the specification calls a supported destination: "existing mounted
// shares". Comparing the destination with its immediate parent rejected
// every subfolder of a share, which left --require-mount unusable on a real
// share and pushed administrators to turn it off.
func TestRequireMountAcceptsASubfolderInsideAMount(t *testing.T) {
	stateDir, mount, dest := mountedShare(t)

	if err := RequireMount(stateDir, dest); err != nil {
		t.Fatalf("a subfolder inside a mounted share was rejected: %v", err)
	}
	// The approved mount is recorded, and the record names the mount point
	// rather than the destination.
	rec, err := readMountRecord(stateDir)
	if err != nil || rec == nil {
		t.Fatalf("the approved mount was not recorded: %v", err)
	}
	if rec.MountPoint != mount {
		t.Errorf("recorded mount point %q, want %q", rec.MountPoint, mount)
	}
	if rec.Marker == "" {
		t.Error("the record holds no share marker, so a replaced share could not be detected")
	}
	// A repeat run is happy with what it approved.
	if err := RequireMount(stateDir, dest); err != nil {
		t.Fatalf("the approved mount was rejected on the next run: %v", err)
	}
}

func TestRequireMountFailsWhenTheMountDisappears(t *testing.T) {
	stateDir, mount, dest := mountedShare(t)
	if err := RequireMount(stateDir, dest); err != nil {
		t.Fatal(err)
	}

	// The share is gone: the directory tree is still there, all on the
	// host's own filesystem, and the marker went with the share.
	fakeMounts(t, nil)
	if err := os.Remove(filepath.Join(dest, mountMarkerFile)); err != nil {
		t.Fatal(err)
	}
	err := RequireMount(stateDir, dest)
	if err == nil {
		t.Fatal("a vanished mount was accepted; the backup would land on local disk")
	}
	for _, want := range []string{mount, "not mounted", "nothing was exported"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestRequireMountFailsWhenTheMountIsReplaced(t *testing.T) {
	stateDir, _, dest := mountedShare(t)
	if err := RequireMount(stateDir, dest); err != nil {
		t.Fatal(err)
	}

	// Something else is mounted at the same place: still a mount, still the
	// same paths, but not the filesystem the backups were approved for.
	if err := os.Remove(filepath.Join(dest, mountMarkerFile)); err != nil {
		t.Fatal(err)
	}
	err := RequireMount(stateDir, dest)
	if err == nil {
		t.Fatal("a replaced share was accepted as the approved one")
	}
	if !strings.Contains(err.Error(), "not mounted") || !strings.Contains(err.Error(), MountRecordPath(stateDir)) {
		t.Errorf("error does not explain the replacement or how to approve the new share: %v", err)
	}
}

func TestRequireMountRecordHoldsNoSecrets(t *testing.T) {
	stateDir, _, dest := mountedShare(t)
	if err := RequireMount(stateDir, dest); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(MountRecordPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"dest": true, "mount_point": true, "marker": true}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("unexpected field %q in the mount record; check it cannot hold a secret", k)
		}
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
		writeNamed(t, dir, n, completeBackup())
		if !Valid(dir, n, testDeployment) {
			t.Errorf("published backup %s not recognised by retention", n)
		}
	}
	got, err := List(dir, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(current) {
		t.Fatalf("List returned %d backups, want %d: %v", len(got), len(current), got)
	}

	// A partial of the current shape stays invisible to retention.
	partial := ".partial-guacdeploy-db-20260911T104826.000Z-123456.sql"
	write(t, dir, partial, completeBackup())
	if Valid(dir, partial, testDeployment) {
		t.Fatal("a .partial- file must never count as a published backup")
	}
}

// TestListOrdersByTimestampThenCollisionSuffix pins the order retention
// depends on. Sorting the names as text got it wrong twice:
//
//   - at one timestamp the unsuffixed name sorted ahead of its "-1"
//     sibling, although publish takes the unsuffixed name first and only
//     then "-1", so "-1" is the newer backup;
//   - "-10" sorted between "-1" and "-2", because 10 is not text-greater
//     than 2.
//
// Either mistake expires a newer backup and keeps an older one.
func TestListOrdersByTimestampThenCollisionSuffix(t *testing.T) {
	dir := t.TempDir()
	// Deliberately written in a shuffled order, so nothing here can pass by
	// accident of directory order.
	for _, n := range []string{
		"guacdeploy-db-20260911T104826.000Z-2.sql",
		"guacdeploy-db-20260101T000000Z.sql",
		"guacdeploy-db-20260911T104826.000Z.sql",
		"guacdeploy-db-20260911T104826.000Z-10.sql",
		"guacdeploy-db-20260911T104826.000Z-1.sql",
		"guacdeploy-db-20260910T235959.999Z.sql",
	} {
		writeNamed(t, dir, n, completeBackup())
	}

	want := []string{
		"guacdeploy-db-20260911T104826.000Z-10.sql",
		"guacdeploy-db-20260911T104826.000Z-2.sql",
		"guacdeploy-db-20260911T104826.000Z-1.sql",
		"guacdeploy-db-20260911T104826.000Z.sql",
		"guacdeploy-db-20260910T235959.999Z.sql",
		"guacdeploy-db-20260101T000000Z.sql",
	}
	got, err := List(dir, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("List order is wrong.\n got: %v\nwant: %v", got, want)
	}

	// The order is not decoration: retention keeps names[:keep].
	removed, err := Prune(dir, 3, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	left := remaining(t, dir)
	for _, n := range want[:3] {
		if !has(left, n) {
			t.Errorf("retention expired %s, one of the three newest backups; removed %v", n, removed)
		}
	}
	for _, n := range want[3:] {
		if has(left, n) {
			t.Errorf("retention kept %s, which is older than the three newest", n)
		}
	}
	// Each expired backup takes its manifest with it.
	if left := manifests(t, dir); len(left) != 3 {
		t.Errorf("manifests left = %v, want one for each kept backup", left)
	}
}

// TestValidRejectsATruncatedEncryptedBackup is the case the completion
// manifest exists for. A scheduled run holds only the public key, so it
// cannot decrypt a backup to check it. Without the manifest, any file with
// an age header under a published name counted as a good backup, so a
// half-written export could displace a real one and then be expired in its
// place.
func TestValidRejectsATruncatedEncryptedBackup(t *testing.T) {
	dir := t.TempDir()
	good := writeEncrypted(t, dir, "20260101T000000Z")
	half := writeEncrypted(t, dir, "20260102T000000Z")

	// Cut the newer backup in half after publication, leaving its age
	// header, exactly as an interrupted write to a share would.
	path := filepath.Join(dir, half)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	if Valid(dir, half, testDeployment) {
		t.Fatal("a truncated encrypted backup counted as a complete backup")
	}
	names, err := List(dir, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != good {
		t.Fatalf("List = %v, want only the complete backup %s", names, good)
	}

	// Retention keeps one backup: the truncated file must neither count as
	// that one nor be deleted, because a damaged backup is still evidence
	// and is not retention's to throw away.
	removed, err := Prune(dir, 1, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("retention deleted %v; only complete backups of this deployment may be expired", removed)
	}
	if left := remaining(t, dir); !has(left, good) || !has(left, half) {
		t.Errorf("left %v, want both files", left)
	}
}

// TestRetentionPreservesOtherDeploymentsBackups covers a shared
// destination, which the specification allows: "Destinations are local
// directories, existing mounted shares, or Azure Blob". Another
// deployment's backups must never be counted as ours, and never expired.
func TestRetentionPreservesOtherDeploymentsBackups(t *testing.T) {
	dir := t.TempDir()
	ours := []string{
		writePlaintext(t, dir, "20260108T000000Z"),
		writePlaintext(t, dir, "20260109T000000Z"),
	}
	// Another deployment writing into the same share, complete and valid,
	// just not ours. Older than ours, so a retention that counted them
	// would expire them first.
	var theirs []string
	for _, stamp := range []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z"} {
		name := "guacdeploy-db-" + stamp + ".sql"
		write(t, dir, name, completeBackup())
		manifest(t, dir, name, "dep-someone-else")
		theirs = append(theirs, name)
	}
	// A backup with no manifest at all: written by an older version of this
	// tool, or copied in by hand. Unverifiable, so preserved.
	orphan := "guacdeploy-db-20260104T000000Z.sql"
	write(t, dir, orphan, completeBackup())

	names, err := List(dir, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("List = %v, want only this deployment's two backups", names)
	}

	removed, err := Prune(dir, 1, testDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || filepath.Base(removed[0]) != ours[0] {
		t.Fatalf("removed %v, want only our own older backup %s", removed, ours[0])
	}
	left := remaining(t, dir)
	for _, n := range append(theirs, orphan, ours[1]) {
		if !has(left, n) {
			t.Errorf("retention deleted %s, which it does not own", n)
		}
	}
	for _, n := range theirs {
		if !has(manifests(t, dir), n+backup.ManifestSuffix) {
			t.Errorf("retention deleted the manifest of %s, which it does not own", n)
		}
	}
}
