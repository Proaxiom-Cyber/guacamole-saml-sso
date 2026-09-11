package azure

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
)

// expireNow is the fixed clock every retention test runs against. Second
// resolution, because Last-Modified has no more than that.
var expireNow = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func expireOptions(days int) ExpireOptions {
	return ExpireOptions{Destination: testDestination(), DeploymentID: testDeployment,
		Days: days, Now: func() time.Time { return expireNow }}
}

// putRemote places one object in the fake container the way UploadPublished
// leaves it: the blob, its completion manifest, and the ownership marker on
// both. owner "" writes an object with no marker at all, which is what an
// unrelated object in a shared container looks like.
func putRemote(s *blobStore, name, owner string, at time.Time) {
	meta := map[string]string{sha256Metadata: "unused-by-retention"}
	if owner != "" {
		meta[ownerMetadata] = owner
	}
	body := []byte("remote copy of " + name)
	s.blobs[name] = storedBlob{content: body, md5: md5Base64(body), meta: meta, modified: at.UTC()}
	m := []byte(`{"deployment_id":"` + owner + `"}`)
	s.blobs[name+backup.ManifestSuffix] = storedBlob{content: m, md5: md5Base64(m), meta: meta, modified: at.UTC()}
}

func recBlob(name string) string {
	return testDestination().Prefix(testDeployment) + AreaRecordings + "/" + name
}

func dbBlob(name string) string {
	return testDestination().Prefix(testDeployment) + AreaDatabase + "/" + name
}

func held(s *blobStore, name string) bool {
	_, ok := s.blobs[name]
	return ok
}

// TestExpireRemovesOnlyThisDeploymentsOldRecordings is the whole of issue #20
// in one run: an old recording of this deployment goes with its completion
// manifest, a recent one stays, a database backup older than the period is
// untouched, and objects this deployment cannot prove are its own are left
// exactly where they are.
func TestExpireRemovesOnlyThisDeploymentsOldRecordings(t *testing.T) {
	blobs := newBlobStore(t)
	old, recent := expireNow.AddDate(0, 0, -40), expireNow.AddDate(0, 0, -3)

	putRemote(blobs, recBlob("old.guac.age"), testDeployment, old)
	putRemote(blobs, recBlob("recent.guac.age"), testDeployment, recent)
	// A database backup far older than the recording period. Database backups
	// keep their own retention of the last seven successful backups and are
	// never expired by age.
	putRemote(blobs, dbBlob(dbBackup1), testDeployment, expireNow.AddDate(0, 0, -400))
	// An object under this deployment's recordings prefix carrying no marker:
	// ownership cannot be verified, so it stays.
	putRemote(blobs, recBlob("unmarked.guac.age"), "", old)
	// An object marked as another deployment's, in the same container.
	putRemote(blobs, recBlob("theirs.guac.age"), "0000other0000", old)
	// Another deployment's own prefix entirely.
	theirs := "guacdeploy/0000other0000/recordings/theirs.guac.age"
	putRemote(blobs, theirs, "0000other0000", old)

	c := newClient(nil, blobs)
	rep, err := Expire(context.Background(), c, expireOptions(30))
	if err != nil {
		t.Fatal(err)
	}

	if len(rep.Removed) != 1 || rep.Removed[0] != recBlob("old.guac.age") {
		t.Fatalf("removed = %v", rep.Removed)
	}
	if held(blobs, recBlob("old.guac.age")) || held(blobs, recBlob("old.guac.age")+backup.ManifestSuffix) {
		t.Fatal("an expired recording or its completion manifest survived")
	}
	if rep.Kept != 1 {
		t.Fatalf("kept = %d, want the one recent recording", rep.Kept)
	}
	for _, name := range []string{
		recBlob("recent.guac.age"),
		dbBlob(dbBackup1), dbBlob(dbBackup1) + backup.ManifestSuffix,
		recBlob("unmarked.guac.age"), recBlob("theirs.guac.age"), theirs,
	} {
		if !held(blobs, name) {
			t.Fatalf("%s was deleted; only this deployment's expired recordings may be", name)
		}
	}
	if len(rep.NotOwned) != 2 {
		t.Fatalf("not owned = %v, want the unmarked object and the other deployment's", rep.NotOwned)
	}
	if len(rep.Failed) != 0 {
		t.Fatalf("failed = %+v", rep.Failed)
	}
	if !strings.Contains(rep.Summary(), "never expired by age") {
		t.Fatalf("the summary does not state the database rule:\n%s", rep.Summary())
	}
}

// TestExpireNeverListsTheDatabaseArea proves the database rule structurally
// rather than by outcome: the run makes exactly one listing, and it is scoped
// to the recordings prefix, so a database backup is not skipped by a filter
// that could be edited away — it is never seen.
func TestExpireNeverListsTheDatabaseArea(t *testing.T) {
	blobs := newBlobStore(t)
	putRemote(blobs, dbBlob(dbBackup1), testDeployment, expireNow.AddDate(0, 0, -400))
	c := newClient(nil, blobs)

	rep, err := Expire(context.Background(), c, expireOptions(1))
	if err != nil {
		t.Fatal(err)
	}
	if want := testDestination().Prefix(testDeployment) + "recordings/"; rep.Prefix != want {
		t.Fatalf("prefix = %q, want %q", rep.Prefix, want)
	}
	for _, call := range blobs.calls {
		if strings.HasPrefix(call, "DELETE ") {
			t.Fatalf("a delete was issued with only database backups present: %s", call)
		}
	}
	if !held(blobs, dbBlob(dbBackup1)) {
		t.Fatal("a database backup older than the recording period was deleted")
	}
}

// TestExpireAgeBoundary checks the edge the administrator actually chose: a
// copy exactly at the boundary is kept, one second past it goes.
func TestExpireAgeBoundary(t *testing.T) {
	blobs := newBlobStore(t)
	cutoff := expireNow.AddDate(0, 0, -30)
	putRemote(blobs, recBlob("at-the-boundary.guac.age"), testDeployment, cutoff)
	putRemote(blobs, recBlob("one-second-older.guac.age"), testDeployment, cutoff.Add(-time.Second))
	putRemote(blobs, recBlob("one-second-younger.guac.age"), testDeployment, cutoff.Add(time.Second))

	rep, err := Expire(context.Background(), newClient(nil, blobs), expireOptions(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 || rep.Removed[0] != recBlob("one-second-older.guac.age") {
		t.Fatalf("removed = %v; only a copy strictly older than the cutoff may go", rep.Removed)
	}
	if !held(blobs, recBlob("at-the-boundary.guac.age")) {
		t.Fatal("a copy exactly at the retention boundary was deleted")
	}
	if rep.Kept != 2 {
		t.Fatalf("kept = %d", rep.Kept)
	}
}

// TestExpireWalksEveryPage is why listAll exists. The oldest recordings sort
// first and would sit on the first page here, but a container is not always
// so kind: this fills more than one page and checks that an old recording
// behind a continuation marker still expires.
func TestExpireWalksEveryPage(t *testing.T) {
	blobs := newBlobStore(t)
	old := expireNow.AddDate(0, 0, -40)
	// listPageSize entries of recent recordings sort ahead of the old one, so
	// the old one can only be found by following the marker.
	for i := 0; i < listPageSize; i++ {
		putRemote(blobs, recBlob(fmt.Sprintf("aaa-%04d.guac.age", i)), testDeployment, expireNow)
	}
	putRemote(blobs, recBlob("zzz-old.guac.age"), testDeployment, old)

	rep, err := Expire(context.Background(), newClient(nil, blobs), expireOptions(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 || rep.Removed[0] != recBlob("zzz-old.guac.age") {
		t.Fatalf("removed = %v; the recording behind the continuation marker was missed", rep.Removed)
	}
	if rep.Kept != listPageSize {
		t.Fatalf("kept = %d, want %d", rep.Kept, listPageSize)
	}
}

// TestExpireReportsAFailedDeletionAndLeavesTheRecording covers the acceptance
// criterion "report failed expiration operations".
func TestExpireReportsAFailedDeletionAndLeavesTheRecording(t *testing.T) {
	blobs := newBlobStore(t)
	putRemote(blobs, recBlob("old.guac.age"), testDeployment, expireNow.AddDate(0, 0, -40))
	blobs.denyDelete = true

	rep, err := Expire(context.Background(), newClient(nil, blobs), expireOptions(30))
	if err == nil {
		t.Fatal("a run that removed nothing it was asked to remove reported success")
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("removed = %v", rep.Removed)
	}
	if len(rep.Failed) != 1 || rep.Failed[0].Name != recBlob("old.guac.age") {
		t.Fatalf("failed = %+v", rep.Failed)
	}
	if !held(blobs, recBlob("old.guac.age")) {
		t.Fatal("the recording went even though its manifest could not be removed")
	}
	if !strings.Contains(rep.Error, "left in place") {
		t.Fatalf("the recorded error does not say the recording stayed: %s", rep.Error)
	}
}

// TestExpireLeavesAnOrphanBlobsAgeToDecide covers the blob left behind when an
// upload failed after the bytes but before the completion manifest: it is not
// a complete copy, nothing counts it, and retention still clears it by age
// rather than leaving it in the container for ever.
func TestExpireRemovesAnOldOrphanWithNoManifest(t *testing.T) {
	blobs := newBlobStore(t)
	putRemote(blobs, recBlob("orphan.guac.age"), testDeployment, expireNow.AddDate(0, 0, -40))
	delete(blobs.blobs, recBlob("orphan.guac.age")+backup.ManifestSuffix)

	rep, err := Expire(context.Background(), newClient(nil, blobs), expireOptions(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 {
		t.Fatalf("removed = %v", rep.Removed)
	}
	if held(blobs, recBlob("orphan.guac.age")) {
		t.Fatal("an expired orphan blob stayed")
	}
}

// TestExpireLeavesARecordingWhoseAgeIsUnknown: an unknown age is not an
// expired recording. Deleting on a guess is the one mistake that cannot be
// undone.
func TestExpireLeavesARecordingWhoseAgeIsUnknown(t *testing.T) {
	blobs := newBlobStore(t)
	name := recBlob("no-date.guac.age")
	putRemote(blobs, name, testDeployment, expireNow.AddDate(0, 0, -40))
	b := blobs.blobs[name]
	b.modified = time.Time{}
	blobs.blobs[name] = b
	// A Last-Modified the service never sent, simulated by an unparseable one.
	blobs.badDate[name] = true

	rep, err := Expire(context.Background(), newClient(nil, blobs), expireOptions(30))
	if err == nil {
		t.Fatal("a recording of unknown age was passed over silently")
	}
	if len(rep.Removed) != 0 || !held(blobs, name) {
		t.Fatal("a recording whose age could not be read was deleted")
	}
	if len(rep.Failed) != 1 || !strings.Contains(rep.Failed[0].Reason, "age is unknown") {
		t.Fatalf("failed = %+v", rep.Failed)
	}
}

func TestExpireRefusesAPeriodItCannotTrust(t *testing.T) {
	blobs := newBlobStore(t)
	putRemote(blobs, recBlob("old.guac.age"), testDeployment, expireNow.AddDate(0, 0, -400))
	c := newClient(nil, blobs)

	for _, days := range []int{0, -1} {
		if _, err := Expire(context.Background(), c, expireOptions(days)); err == nil {
			t.Fatalf("a retention period of %d days was accepted", days)
		}
	}
	if _, err := Expire(context.Background(), c, ExpireOptions{Destination: testDestination(), Days: 30}); err == nil {
		t.Fatal("expiry with no deployment ID was allowed")
	}
	o := expireOptions(30)
	o.Destination = Destination{}
	if _, err := Expire(context.Background(), c, o); err == nil {
		t.Fatal("expiry with no destination was allowed")
	}
	if len(blobs.calls) != 0 {
		t.Fatalf("a refused run still talked to Azure: %v", blobs.calls)
	}
	if !held(blobs, recBlob("old.guac.age")) {
		t.Fatal("a refused run deleted something")
	}
}

func TestExpireLeaksNoCredential(t *testing.T) {
	blobs := newBlobStore(t)
	putRemote(blobs, recBlob("old.guac.age"), testDeployment, expireNow.AddDate(0, 0, -40))
	blobs.denyDelete = true

	rep, err := Expire(context.Background(), newClient(nil, blobs), expireOptions(30))
	if err == nil {
		t.Fatal("expected a failure to inspect")
	}
	for _, text := range []string{err.Error(), rep.Summary(), rep.Error} {
		for _, secret := range []string{testToken, "Bearer ", clientSecret, refreshToken} {
			if strings.Contains(text, secret) {
				t.Fatalf("%q leaked into: %s", secret, text)
			}
		}
	}
}
