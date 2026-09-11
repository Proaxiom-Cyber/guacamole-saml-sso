package recording

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
)

const deployment = "dep-1"

// write creates a recording of n bytes with the given age, and returns its path.
func write(t *testing.T, dir, name string, n int, age time.Duration) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

// idOf is the device and inode of a path, for building a fake open set.
func idOf(t *testing.T, path string) FileID {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := fileID(fi)
	if !ok {
		t.Fatal("no file identity on this platform")
	}
	return id
}

// openSet returns an OpenFiles reporting exactly these paths as held open.
func openSet(t *testing.T, paths ...string) OpenFiles {
	t.Helper()
	ids := map[FileID]struct{}{}
	for _, p := range paths {
		ids[idOf(t, p)] = struct{}{}
	}
	return func() (map[FileID]struct{}, error) { return ids, nil }
}

func keypair(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id, id.Recipient().String()
}

// setup makes a recordings directory and a backup destination.
func setup(t *testing.T) (dir, dest string) {
	t.Helper()
	root := t.TempDir()
	dir, dest = filepath.Join(root, "recordings"), filepath.Join(root, "backups")
	for _, p := range []string{dir, dest} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, dest
}

func names(recs []Recording) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Name)
	}
	return out
}

// A recording guacd still holds open is never complete, however old it is.
func TestActiveRecordingIsNeverComplete(t *testing.T) {
	dir, _ := setup(t)
	old := write(t, dir, "old", 10, 48*time.Hour)
	done := write(t, dir, "done", 10, time.Hour)

	recs, err := Scan(dir, openSet(t, old))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(recs); got[0] != "old" || got[1] != "done" {
		t.Fatalf("want oldest first, got %v", got)
	}
	if !recs[0].Active {
		t.Fatal("a recording held open must be active, even when it is the oldest file")
	}
	if recs[1].Active {
		t.Fatalf("%s is held open by nobody and must be complete", done)
	}
}

// A file whose identity cannot be read is treated as active: unknown must
// never mean complete.
func TestScanFailsClosedWhenOpenFilesCannotBeRead(t *testing.T) {
	dir, _ := setup(t)
	write(t, dir, "a", 10, time.Hour)
	_, err := Scan(dir, func() (map[FileID]struct{}, error) { return nil, os.ErrPermission })
	if err == nil {
		t.Fatal("Scan must fail when it cannot tell which recordings are being written")
	}
	if !strings.Contains(err.Error(), "no recording was treated as complete") {
		t.Fatalf("the failure must say nothing was treated as complete: %v", err)
	}
}

// Backup copies completed recordings only, and reports the active ones as
// excluded rather than silently dropping them.
func TestBackupIncludesOnlyCompletedRecordings(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 100, 2*time.Hour)
	active := write(t, dir, "inprogress", 100, time.Minute)
	_, pub := keypair(t)

	rep, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: pub, Open: openSet(t, active)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Included) != 1 || rep.Included[0] != "finished" {
		t.Fatalf("included = %v, want [finished]", rep.Included)
	}
	if len(rep.Active) != 1 || rep.Active[0] != "inprogress" {
		t.Fatalf("active = %v, want [inprogress]", rep.Active)
	}
	if len(rep.Failed) != 0 {
		t.Fatalf("failed = %v, want none", rep.Failed)
	}
	copies := DestDir(dest)
	if _, err := backup.VerifyPublished(copies, "finished"+Ext+".age", deployment); err != nil {
		t.Fatalf("the published copy must verify against its completion record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(copies, "inprogress"+Ext+".age")); !os.IsNotExist(err) {
		t.Fatal("an active recording must never be copied")
	}
}

// A second run does not copy the same recording again, and says so.
func TestBackupDoesNotRepeatAPublishedCopy(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 100, 2*time.Hour)
	_, pub := keypair(t)
	o := Options{Dir: dir, Dest: dest, DeploymentID: deployment, PublicKey: pub,
		Open: func() (map[FileID]struct{}, error) { return nil, nil }}

	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Included) != 0 {
		t.Fatalf("included = %v on the second run, want none", rep.Included)
	}
	if len(rep.AlreadyBackedUp) != 1 {
		t.Fatalf("already backed up = %v, want [finished]", rep.AlreadyBackedUp)
	}
}

// A copy that fails part way publishes nothing, records no completion, and
// is never reported as included.
func TestPartialCopyIsNeverPublishedOrReportedComplete(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 100, 2*time.Hour)

	// An unusable public key fails inside the encrypting copy, after the
	// destination name has been claimed.
	rep, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: "age1notakey", Open: func() (map[FileID]struct{}, error) { return nil, nil }})
	if err == nil {
		t.Fatal("a failed copy must fail the run")
	}
	if rep.Result != "failed" {
		t.Fatalf("result = %q, want failed", rep.Result)
	}
	if len(rep.Included) != 0 {
		t.Fatalf("included = %v, want none: a failed copy is not complete", rep.Included)
	}
	if len(rep.Failed) != 1 || rep.Failed[0].Name != "finished" {
		t.Fatalf("failed = %v, want the one recording", rep.Failed)
	}
	copies := DestDir(dest)
	ents, err := os.ReadDir(copies)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Fatalf("nothing may be left under a published name, found %s", e.Name())
	}
}

// A published copy whose completion record is missing does not count, and
// the next run publishes the recording again without overwriting it.
func TestCopyWithoutCompletionRecordDoesNotCount(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 100, 2*time.Hour)
	copies := DestDir(dest)
	if err := os.MkdirAll(copies, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(copies, "finished"+Ext+".age")
	if err := os.WriteFile(orphan, []byte("half a copy"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, pub := keypair(t)
	rep, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: pub, Open: func() (map[FileID]struct{}, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Included) != 1 {
		t.Fatalf("included = %v, want the recording published again", rep.Included)
	}
	if got, err := os.ReadFile(orphan); err != nil || string(got) != "half a copy" {
		t.Fatal("the earlier file must not be overwritten")
	}
	if _, err := backup.VerifyPublished(copies, "finished-1"+Ext+".age", deployment); err != nil {
		t.Fatalf("the new copy must be published under a free name: %v", err)
	}
}

// A copy belonging to another deployment is not counted as ours.
func TestForeignCopyIsNotCountedAsBackedUp(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 100, 2*time.Hour)
	_, pub := keypair(t)
	o := Options{Dir: dir, Dest: dest, DeploymentID: deployment, PublicKey: pub,
		Open: func() (map[FileID]struct{}, error) { return nil, nil }}
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	o.DeploymentID = "someone-else"
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.AlreadyBackedUp) != 0 {
		t.Fatalf("another deployment's copy must not count as ours: %v", rep.AlreadyBackedUp)
	}
}

// A published recording restores byte for byte through the selected
// encryption mode, and a foreign or damaged copy is refused.
func TestRestoreRoundTripAndRefusal(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 512, 2*time.Hour)
	id, pub := keypair(t)
	if _, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: pub, Open: func() (map[FileID]struct{}, error) { return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	copies, name := DestDir(dest), "finished"+Ext+".age"
	out := filepath.Join(t.TempDir(), "playback")
	if err := Restore(copies, name, out, id, deployment); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.Repeat("x", 512) {
		t.Fatalf("restored %d bytes, want the original 512", len(got))
	}
	if err := Restore(copies, name, filepath.Join(t.TempDir(), "x"), id, "someone-else"); err == nil {
		t.Fatal("restoring another deployment's copy must be refused")
	}
	if err := os.WriteFile(filepath.Join(copies, name), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(copies, name, filepath.Join(t.TempDir(), "y"), id, deployment); err == nil {
		t.Fatal("restoring a copy that does not match its completion record must be refused")
	}
}

// The recordings directory is created with the mode a container bind mount
// needs, and given to the guacd account.
func TestEnsureDirsModeAndOwner(t *testing.T) {
	install := t.TempDir()
	var gotUID, gotGID int
	chownDir = func(_ string, uid, gid int) error { gotUID, gotGID = uid, gid; return nil }
	defer func() { chownDir = os.Chown }()

	if err := EnsureDirs(install); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(Dir(install))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o, want 755 so the container can read the bind mount", fi.Mode().Perm())
	}
	if gotUID != GuacdUID || gotGID != GuacdGID {
		t.Fatalf("chown to %d:%d, want the guacd container account %d:%d", gotUID, gotGID, GuacdUID, GuacdGID)
	}
	// A failed chown must fail loudly: guacd would otherwise be unable to
	// write, and sessions would run unrecorded without any error.
	chownDir = func(string, int, int) error { return os.ErrPermission }
	if err := EnsureDirs(install); err == nil {
		t.Fatal("EnsureDirs must fail when the directory cannot be given to guacd")
	}
}

// The connection parameters name the guacd container path and the history
// identifier, and nothing that could become a stored target credential.
func TestEnableSQLSetsOnlyRecordingParameters(t *testing.T) {
	sql := EnableSQL("")
	for _, want := range []string{"'recording-path', '" + ContainerPath + "'",
		"'recording-name', '${HISTORY_UUID}'", "'create-recording-path', 'true'",
		"ON CONFLICT (connection_id, parameter_name)"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("EnableSQL is missing %q:\n%s", want, sql)
		}
	}
	for _, forbidden := range []string{"password", "private-key", "passphrase", "username"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("EnableSQL must not touch %q; it would break the no-stored-credentials model:\n%s", forbidden, sql)
		}
	}
	if strings.Contains(sql, "WHERE") {
		t.Fatal("with no connection name, every connection must be updated")
	}

	named := EnableSQL("Server's box")
	if !strings.Contains(named, "WHERE c.connection_name = 'Server''s box'") {
		t.Fatalf("a connection name must be quoted as a literal:\n%s", named)
	}
}

func noneOpen() (map[FileID]struct{}, error) { return nil, nil }

// The run needs the deployment ID: without it nothing could be recognised
// as this deployment's copy, and every deletion would look like a loss.
func TestRunNeedsDeploymentID(t *testing.T) {
	dir, _ := setup(t)
	if _, err := Run(Options{Dir: dir, Open: noneOpen}); err == nil {
		t.Fatal("a run without a deployment ID must be refused")
	}
}

// A missing destination directory fails visibly instead of being redirected
// into local storage, and deletes nothing.
func TestMissingDestinationFailsVisibly(t *testing.T) {
	dir, _ := setup(t)
	write(t, dir, "old", 100, time.Hour)
	_, pub := keypair(t)
	rep, err := Run(Options{Dir: dir, Dest: filepath.Join(t.TempDir(), "not-mounted"),
		DeploymentID: deployment, PublicKey: pub, Open: noneOpen})
	if err == nil {
		t.Fatal("a missing destination must fail")
	}
	if !strings.Contains(rep.Error, "is the mount present?") {
		t.Fatalf("the failure must name the missing mount: %q", rep.Error)
	}
}

// The last-run record is owner-only and carries file names and counts, never
// a key or a passphrase.
func TestReportFileIsOwnerOnlyAndHoldsNoSecrets(t *testing.T) {
	dir, dest := setup(t)
	stateDir := t.TempDir()
	write(t, dir, "old", 100, time.Hour)
	id, pub := keypair(t)

	if _, err := Run(Options{Dir: dir, Dest: dest, StateDir: stateDir,
		DeploymentID: deployment, PublicKey: pub, Open: noneOpen}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(ReportPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}
	b, err := os.ReadFile(ReportPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{id.String(), "AGE-SECRET-KEY"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("the last-run record must never hold key material")
		}
	}
	got, err := ReadReport(stateDir)
	if err != nil || got == nil || len(got.Included) != 1 {
		t.Fatalf("the record must read back: %v %v", got, err)
	}
}

// A copy whose completion record cannot be written is not a backup: it is
// reported as a failure, never as included, and it does not verify.
func TestCopyWithoutAWritableManifestIsNotComplete(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "finished", 100, 2*time.Hour)
	copies := DestDir(dest)
	// A directory where the completion record belongs makes writing it fail
	// after the copy itself has succeeded.
	if err := os.MkdirAll(backup.ManifestPath(copies, "finished"+Ext+".age"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, pub := keypair(t)

	rep, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: pub, Open: noneOpen})
	if err == nil {
		t.Fatal("a copy with no completion record must fail the run")
	}
	if len(rep.Included) != 0 {
		t.Fatalf("included = %v, want none: without a completion record it is not a backup", rep.Included)
	}
	if len(rep.Failed) != 1 || rep.Failed[0].Name != "finished" {
		t.Fatalf("failed = %v, want the one recording", rep.Failed)
	}
	if _, err := backup.VerifyPublished(copies, "finished"+Ext+".age", deployment); err == nil {
		t.Fatal("the leftover copy must not verify as a complete backup")
	}
}
