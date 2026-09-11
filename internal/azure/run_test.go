package azure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
)

func recBlob(name string) string {
	return testDestination().Prefix(testDeployment) + AreaRecordings + "/" + name
}

// TestFailedUploadLeavesTheLocalBackupPublished: the upload is a copy of
// something already published locally. A failure to copy must not reach back
// and disturb what the backup itself produced.
func TestFailedUploadLeavesTheLocalBackupPublished(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	blobs.denyPut = true

	before := listDir(t, dest)
	if _, err := Upload(context.Background(), newClient(nil, blobs), uploadOptions(dest, stateDir)); err == nil {
		t.Fatal("a denied upload reported success")
	}
	if got := listDir(t, dest); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Fatalf("the local destination changed: %v -> %v", before, got)
	}
	for _, name := range []string{dbBackup1, dbBackup2} {
		if _, err := backup.VerifyPublished(dest, name, testDeployment); err != nil {
			t.Fatalf("%s is no longer a published backup after a failed upload: %v", name, err)
		}
	}
	if _, err := backup.VerifyPublished(recording.DestDir(dest), rec1, testDeployment); err != nil {
		t.Fatalf("the local recording copy did not survive a failed upload: %v", err)
	}
}

// TestDatabaseAndRecordingOutcomesDoNotContaminateEachOther: one failing
// recording must not make the database result look worse, or the reverse.
func TestDatabaseAndRecordingOutcomesDoNotContaminateEachOther(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	blobs.failPut[recBlob(rec1)] = true

	rep, err := Upload(context.Background(), newClient(nil, blobs), uploadOptions(dest, stateDir))
	if err == nil {
		t.Fatal("a failed recording upload reported success")
	}
	if len(rep.Database.Uploaded) != 2 || len(rep.Database.Failed) != 0 {
		t.Fatalf("the recording failure reached the database result: %+v", rep.Database)
	}
	if len(rep.Recordings.Uploaded) != 0 || len(rep.Recordings.Failed) != 1 {
		t.Fatalf("recordings = %+v", rep.Recordings)
	}
	s := Summary(stateDir)
	if !strings.Contains(s, "Database backups:     2 uploaded") || !strings.Contains(s, "Recordings:           0 uploaded") {
		t.Fatalf("the status output does not report the two apart:\n%s", s)
	}
}

// --- coordination with the local storage budget -----------------------------

// activeFiles returns an OpenFiles seam that reports the named files as still
// being written, the way guacd holding a live session's recording open does.
func activeFiles(t *testing.T, paths ...string) recording.OpenFiles {
	t.Helper()
	ids := map[recording.FileID]struct{}{}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Skip("this platform does not expose device and inode numbers")
		}
		ids[recording.FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}] = struct{}{}
	}
	return func() (map[recording.FileID]struct{}, error) { return ids, nil }
}

// writeRecording writes one local recording of n bytes with the given age.
func writeRecording(t *testing.T, dir, name string, n int, age time.Duration) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBudgetDeletesAfterAFailedUploadAndTheLossIsReported is the interaction
// the specification states twice: "Apply local recording retention
// independently of upload success" and "the local storage budget takes
// priority over preserving unbacked recordings ... report deletions of
// recordings without a confirmed remote copy".
//
// It runs the real local cleanup, then the real upload against a container
// that refuses the copy, and checks both halves: the recording is gone locally
// anyway, and the Azure report names it as deleted with no confirmed remote
// copy.
func TestBudgetDeletesAfterAFailedUploadAndTheLossIsReported(t *testing.T) {
	stateDir, dest := t.TempDir(), t.TempDir()
	recDir := t.TempDir()
	oldest := writeRecording(t, recDir, "aaaa-oldest", 800, 2*time.Hour)
	writeRecording(t, recDir, "bbbb-newest", 800, time.Minute)

	// Budget fits one recording, so the oldest completed one goes.
	recRep, err := recording.Run(recording.Options{
		Dir: recDir, Dest: dest, StateDir: stateDir, DeploymentID: testDeployment,
		Budget: 1000, Plaintext: true,
		Open: func() (map[recording.FileID]struct{}, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recRep.Deleted) != 1 || recRep.Deleted[0] != "aaaa-oldest" {
		t.Fatalf("local cleanup deleted %v", recRep.Deleted)
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Fatal("the oldest recording survived a run over budget")
	}

	// The container refuses the copy of the recording that was just deleted.
	blobs := newBlobStore(t)
	blobs.failPut[recBlob("aaaa-oldest.guac")] = true
	rep, err := Upload(context.Background(), newClient(nil, blobs), uploadOptions(dest, stateDir))
	if err == nil {
		t.Fatal("a failed recording upload reported success")
	}

	if len(rep.DeletedWithoutRemoteCopy) != 1 || rep.DeletedWithoutRemoteCopy[0] != "aaaa-oldest" {
		t.Fatalf("deleted without remote copy = %v", rep.DeletedWithoutRemoteCopy)
	}
	if rep.CleanupRan.IsZero() {
		t.Fatal("the report does not say which cleanup run it refers to")
	}
	if !strings.Contains(rep.Summary(), "LOST:                 aaaa-oldest") {
		t.Fatalf("the summary does not name the lost recording:\n%s", rep.Summary())
	}

	// And the same run reports the recording that did reach the container as
	// held, so the loss line is about the copy, not about every deletion.
	if len(rep.Recordings.Uploaded) != 1 || rep.Recordings.Uploaded[0] != "bbbb-newest.guac" {
		t.Fatalf("recordings uploaded = %v", rep.Recordings.Uploaded)
	}
}

// TestADeletedRecordingWithAConfirmedRemoteCopyIsNotReportedLost is the other
// half: the budget deleted it, but the container holds a complete copy, so
// nothing was lost and nothing is reported as lost.
func TestADeletedRecordingWithAConfirmedRemoteCopyIsNotReportedLost(t *testing.T) {
	stateDir, dest, recDir := t.TempDir(), t.TempDir(), t.TempDir()
	writeRecording(t, recDir, "aaaa-oldest", 800, 2*time.Hour)
	writeRecording(t, recDir, "bbbb-newest", 800, time.Minute)

	if _, err := recording.Run(recording.Options{
		Dir: recDir, Dest: dest, StateDir: stateDir, DeploymentID: testDeployment,
		Budget: 1000, Plaintext: true,
		Open: func() (map[recording.FileID]struct{}, error) { return nil, nil },
	}); err != nil {
		t.Fatal(err)
	}

	rep, err := Upload(context.Background(), newClient(nil, newBlobStore(t)), uploadOptions(dest, stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.DeletedWithoutRemoteCopy) != 0 {
		t.Fatalf("a recording with a confirmed remote copy was reported lost: %v", rep.DeletedWithoutRemoteCopy)
	}
	if strings.Contains(rep.Summary(), "LOST:") {
		t.Fatalf("the summary claims a loss:\n%s", rep.Summary())
	}
}

// TestAnActiveRecordingIsNeverUploaded: a session still being written is not
// copied locally and so cannot reach Azure. The check is on the blob store,
// because that is where it would show up if the rule ever broke.
func TestAnActiveRecordingIsNeverUploaded(t *testing.T) {
	stateDir, dest, recDir := t.TempDir(), t.TempDir(), t.TempDir()
	live := writeRecording(t, recDir, "live-session", 400, time.Minute)
	writeRecording(t, recDir, "finished-session", 400, time.Hour)

	recRep, err := recording.Run(recording.Options{
		Dir: recDir, Dest: dest, StateDir: stateDir, DeploymentID: testDeployment,
		Budget: 100, Plaintext: true, Open: activeFiles(t, live),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(recRep.Active) != 1 || recRep.Active[0] != "live-session" {
		t.Fatalf("active = %v", recRep.Active)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("an active recording was deleted by the storage budget")
	}

	blobs := newBlobStore(t)
	rep, err := Upload(context.Background(), newClient(nil, blobs), uploadOptions(dest, stateDir))
	if err != nil {
		t.Fatal(err)
	}
	for name := range blobs.blobs {
		if strings.Contains(name, "live-session") {
			t.Fatalf("a recording still being written reached Azure as %s", name)
		}
	}
	if len(rep.Recordings.Uploaded) != 1 || !strings.HasPrefix(rep.Recordings.Uploaded[0], "finished-session") {
		t.Fatalf("recordings uploaded = %v", rep.Recordings.Uploaded)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			out = append(out, strings.TrimPrefix(path, dir))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
