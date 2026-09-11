package azure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
)

const otherDeployment = "0000other0000"

func pruneOptions(keep int) PruneOptions {
	return PruneOptions{Destination: testDestination(), DeploymentID: testDeployment,
		Keep: keep, Now: func() time.Time { return expireNow }}
}

// putRemoteBackup places one database backup in the fake container exactly as
// UploadPublished leaves it: the blob with the ownership and SHA-256 metadata,
// then the completion manifest blob carrying the local manifest bytes.
//
// owner "" writes an object with no ownership marker at all, which is what an
// unrelated object in a shared container looks like.
func putRemoteBackup(s *blobStore, name, owner string, publishedAt time.Time) {
	body := []byte("remote backup of " + name)
	sum := sha256.Sum256(body)
	base := name[strings.LastIndexByte(name, '/')+1:]
	m := backup.Manifest{
		ManifestVersion: backup.ManifestVersion, FormatVersion: backup.FormatVersion,
		DeploymentID: owner, File: base, Bytes: int64(len(body)),
		SHA256: hex.EncodeToString(sum[:]), Mode: "age", PublishedAt: publishedAt.UTC(),
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	mb = append(mb, '\n')
	meta := map[string]string{sha256Metadata: m.SHA256}
	if owner != "" {
		meta[ownerMetadata] = owner
	}
	s.blobs[name] = storedBlob{content: body, md5: md5Base64(body), meta: meta}
	s.blobs[name+backup.ManifestSuffix] = storedBlob{content: mb, md5: md5Base64(mb), meta: meta}
}

// putBackups places n verified backups of this deployment and returns their
// blob names oldest first.
//
// Name order deliberately runs opposite to age order: "backup-00" is the
// oldest and carries the earliest publication time, and the listing returns
// them in name order. A run that trusted the order it was given, or that
// ordered by name, would therefore remove the newest backups instead of the
// oldest ones, and every count test here would catch it.
func putBackups(s *blobStore, n int) []string {
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = dbBlob(fmt.Sprintf("backup-%02d.sql.age", i))
		putRemoteBackup(s, names[i], testDeployment, expireNow.AddDate(0, 0, -(n-1-i)))
	}
	return names
}

// TestPruneKeepsTheLastSuccessfulBackups is the count rule itself: the newest
// Keep backups stay, everything older goes, and the administrator's number is
// honoured. Seven is the specification's default and the case that must remove
// nothing.
func TestPruneKeepsTheLastSuccessfulBackups(t *testing.T) {
	cases := []struct {
		name        string
		have, keep  int
		wantRemoved int
	}{
		{"exactly seven, the default, removes nothing", 7, 7, 0},
		{"eight loses only the oldest", 8, 7, 1},
		{"fewer than the count removes nothing", 3, 7, 0},
		{"none at all", 0, 7, 0},
		{"a configured three", 9, 3, 6},
		{"a configured one", 4, 1, 3},
		{"zero means the default of seven", 8, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blobs := newBlobStore(t)
			names := putBackups(blobs, c.have)

			rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(c.keep))
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Removed) != c.wantRemoved {
				t.Fatalf("removed %v, want %d of them", rep.Removed, c.wantRemoved)
			}
			if want := c.have - c.wantRemoved; rep.Kept != want {
				t.Fatalf("kept = %d, want %d", rep.Kept, want)
			}
			if len(rep.Failed) != 0 || len(rep.NotOwned) != 0 || rep.Withheld != "" {
				t.Fatalf("report = %+v", rep)
			}
			// The oldest go, with their completion manifests, and the newest
			// stay. names is oldest first.
			for i, n := range names {
				gone := i < c.wantRemoved
				if held(blobs, n) == gone {
					t.Fatalf("%s (age rank %d of %d): held = %v, want %v", n, i, c.have, !gone, !gone)
				}
				if held(blobs, n+backup.ManifestSuffix) == gone {
					t.Fatalf("the completion manifest for %s did not follow its backup", n)
				}
			}
			if c.keep == 0 && rep.Keep != schedule.DefaultKeep {
				t.Fatalf("an unset retention reported %d, not the default %d", rep.Keep, schedule.DefaultKeep)
			}
		})
	}
}

// TestPruneCountsOnlyAVerifiedBackup walks every way a remote copy can fail to
// prove it is a complete backup. Each case is the oldest of eight objects, so
// the arithmetic is the discriminator: counted, it would be the one removed;
// not counted, seven backups remain and nothing is removed at all.
func TestPruneCountsOnlyAVerifiedBackup(t *testing.T) {
	cases := []struct {
		name, want string
		break_     func(s *blobStore, blob string)
	}{
		{"no completion manifest", "no completion manifest", func(s *blobStore, blob string) {
			delete(s.blobs, blob+backup.ManifestSuffix)
		}},
		{"an unreadable completion manifest", "not a readable completion manifest", func(s *blobStore, blob string) {
			b := []byte("{not json")
			s.blobs[blob+backup.ManifestSuffix] = storedBlob{content: b, md5: md5Base64(b),
				meta: map[string]string{ownerMetadata: testDeployment}}
		}},
		{"a manifest version this tool does not understand", "manifest version", func(s *blobStore, blob string) {
			rewriteManifest(s, blob, func(m *backup.Manifest) { m.ManifestVersion = backup.ManifestVersion + 1 })
		}},
		{"a manifest for another file", "completion manifest for", func(s *blobStore, blob string) {
			rewriteManifest(s, blob, func(m *backup.Manifest) { m.File = "something-else.sql.age" })
		}},
		{"a manifest with no content hash", "no content hash", func(s *blobStore, blob string) {
			rewriteManifest(s, blob, func(m *backup.Manifest) { m.SHA256 = "" })
		}},
		{"a blob that is shorter than its manifest", "bytes in the container", func(s *blobStore, blob string) {
			rewriteManifest(s, blob, func(m *backup.Manifest) { m.Bytes = m.Bytes + 99 })
		}},
		{"a blob whose SHA-256 does not match its manifest", "does not match the SHA-256", func(s *blobStore, blob string) {
			b := s.blobs[blob]
			b.meta[sha256Metadata] = strings.Repeat("0", 64)
			s.blobs[blob] = b
		}},
		{"a manifest with no publication time", "no publication time", func(s *blobStore, blob string) {
			rewriteManifest(s, blob, func(m *backup.Manifest) { m.PublishedAt = time.Time{} })
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blobs := newBlobStore(t)
			names := putBackups(blobs, 8)
			c.break_(blobs, names[0])

			rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Removed) != 0 {
				t.Fatalf("removed %v; a copy that is not a verified backup was counted as one of the seven", rep.Removed)
			}
			if rep.Kept != 7 {
				t.Fatalf("kept = %d, want the seven verified backups", rep.Kept)
			}
			if !held(blobs, names[0]) {
				t.Fatalf("%s was deleted although this run could not prove it is a backup", names[0])
			}
			if len(rep.Failed) != 1 || rep.Failed[0].Name != names[0] {
				t.Fatalf("failed = %+v", rep.Failed)
			}
			if !strings.Contains(rep.Failed[0].Reason, c.want) {
				t.Fatalf("the reason does not say what is wrong (%q): %s", c.want, rep.Failed[0].Reason)
			}
		})
	}
}

// rewriteManifest edits one remote completion manifest in place, leaving its
// ownership marker alone.
func rewriteManifest(s *blobStore, blob string, edit func(*backup.Manifest)) {
	key := blob + backup.ManifestSuffix
	var m backup.Manifest
	if err := json.Unmarshal(s.blobs[key].content, &m); err != nil {
		panic(err)
	}
	edit(&m)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	s.blobs[key] = storedBlob{content: b, md5: md5Base64(b), meta: s.blobs[key].meta}
}

// TestPruneNeverLeavesTheDatabaseArea is the namespace boundary, proved on the
// requests actually issued rather than on the report. A recording and another
// deployment's objects are in the same container; this rule must never list,
// read or delete one of them.
func TestPruneNeverLeavesTheDatabaseArea(t *testing.T) {
	blobs := newBlobStore(t)
	putBackups(blobs, 8)

	// A recording of this deployment, in the sibling area. Recordings expire
	// by age under their own rule and this count must not reach them.
	putRemoteBackup(blobs, recBlob("old.guac.age"), testDeployment, expireNow.AddDate(0, 0, -400))
	// Another deployment's database backups, under its own prefix.
	theirs := testDestination().Prefix(otherDeployment) + AreaDatabase + "/backup-00.sql.age"
	putRemoteBackup(blobs, theirs, otherDeployment, expireNow.AddDate(0, 0, -400))

	rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
	if err != nil {
		t.Fatal(err)
	}
	if want := testDestination().Prefix(testDeployment) + "db/"; rep.Prefix != want {
		t.Fatalf("prefix = %q, want %q", rep.Prefix, want)
	}
	for _, call := range blobs.calls {
		if strings.Contains(call, AreaRecordings+"/") {
			t.Fatalf("a request was issued against the recordings area: %s", call)
		}
		if strings.Contains(call, otherDeployment) {
			t.Fatalf("a request was issued against another deployment's prefix: %s", call)
		}
	}
	for _, n := range []string{recBlob("old.guac.age"), recBlob("old.guac.age") + backup.ManifestSuffix, theirs} {
		if !held(blobs, n) {
			t.Fatalf("%s was deleted; only this deployment's own expired backups may be", n)
		}
	}
	if len(rep.Removed) != 1 || len(rep.Failed) != 0 || len(rep.NotOwned) != 0 {
		t.Fatalf("report = %+v", rep)
	}
}

// TestPruneLeavesAnObjectItCannotProveIsOurs is the ownership boundary. A
// matching name inside this deployment's own prefix is never enough: the
// marker is read back from the service, and an object without it, or with
// somebody else's, is reported and left exactly where it is.
func TestPruneLeavesAnObjectItCannotProveIsOurs(t *testing.T) {
	blobs := newBlobStore(t)
	good := putBackups(blobs, 7)
	old := expireNow.AddDate(0, 0, -400)

	// No marker at all.
	unmarked := dbBlob("unmarked.sql.age")
	putRemoteBackup(blobs, unmarked, "", old)
	// Marked as another deployment's, in our prefix.
	foreign := dbBlob("foreign.sql.age")
	putRemoteBackup(blobs, foreign, otherDeployment, old)
	// Our marker, but the completion manifest names somebody else. The two
	// have to agree before the object is ours to count or remove.
	mixed := dbBlob("mixed.sql.age")
	putRemoteBackup(blobs, mixed, testDeployment, old)
	mb, _ := json.Marshal(backup.Manifest{ManifestVersion: backup.ManifestVersion,
		DeploymentID: otherDeployment, File: "mixed.sql.age", Bytes: 1, SHA256: "x", PublishedAt: old})
	blobs.blobs[mixed+backup.ManifestSuffix] = storedBlob{content: mb, md5: md5Base64(mb),
		meta: map[string]string{ownerMetadata: testDeployment}}
	// The other way round: a perfectly good completion manifest naming us, on
	// a blob the service says belongs to somebody else. The marker read back
	// from the service decides, not the manifest and not the name. It is dated
	// newer than every real backup, so counting it would evict the oldest one.
	spoofed := dbBlob("spoofed.sql.age")
	putRemoteBackup(blobs, spoofed, testDeployment, expireNow.AddDate(0, 0, 1))
	sb := blobs.blobs[spoofed]
	sb.meta = map[string]string{ownerMetadata: otherDeployment, sha256Metadata: sb.meta[sha256Metadata]}
	blobs.blobs[spoofed] = sb

	rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NotOwned) != 4 {
		t.Fatalf("not owned = %v, want the unmarked, foreign, mixed and spoofed objects", rep.NotOwned)
	}
	for _, n := range append([]string{unmarked, foreign, mixed, spoofed}, good...) {
		if !held(blobs, n) {
			t.Fatalf("%s was deleted although this deployment cannot prove it owns it", n)
		}
	}
	// None of the four counted, so the seven good backups are untouched.
	if len(rep.Removed) != 0 || rep.Kept != 7 {
		t.Fatalf("an object this deployment does not own displaced a backup: %+v", rep)
	}
	for _, call := range blobs.calls {
		if strings.HasPrefix(call, "DELETE ") {
			t.Fatalf("a delete was issued with only owned backups inside the count: %s", call)
		}
	}
}

// TestPruneFailedUploadsDoNotEvictGoodBackups is the failure the supervisor
// named: seven uploads that stop between the bytes and the completion manifest
// must not push seven good backups out of retention. They are not backups, so
// they never enter the count.
func TestPruneFailedUploadsDoNotEvictGoodBackups(t *testing.T) {
	blobs := newBlobStore(t)
	good := putBackups(blobs, 7)

	// Seven newer objects with no completion manifest: exactly what an upload
	// leaves when it fails after writing the blob.
	var orphans []string
	for i := 0; i < 7; i++ {
		n := dbBlob(fmt.Sprintf("zz-failed-%02d.sql.age", i))
		putRemoteBackup(blobs, n, testDeployment, expireNow)
		delete(blobs.blobs, n+backup.ManifestSuffix)
		orphans = append(orphans, n)
	}

	rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("removed %v; seven failed uploads evicted good backups", rep.Removed)
	}
	if rep.Kept != 7 {
		t.Fatalf("kept = %d, want the seven good backups", rep.Kept)
	}
	for _, n := range append(append([]string{}, good...), orphans...) {
		if !held(blobs, n) {
			t.Fatalf("%s was removed", n)
		}
	}
	if len(rep.Failed) != 7 {
		t.Fatalf("failed = %+v, want the seven objects that are not backups", rep.Failed)
	}
	if !strings.Contains(rep.Failed[0].Reason, "no completion manifest") {
		t.Fatalf("the report does not say why the object is not a backup: %s", rep.Failed[0].Reason)
	}
	// A copy that is provably not a backup is a fact about the container, not
	// a failure of this run: retention must keep working while one sits there.
	if rep.Error != "" {
		t.Fatalf("an unfinished upload failed the whole retention run: %s", rep.Error)
	}
}

// TestPruneRemovesNothingWhenAnObjectCannotBeChecked: one object this run
// could not read is enough to stop it removing anything. A count taken from a
// partial reading is not a count, and the copies in the container are all that
// is left of a backup the local retention has already pruned.
func TestPruneRemovesNothingWhenAnObjectCannotBeChecked(t *testing.T) {
	for _, c := range []struct{ name, blocked string }{
		{"the blob's properties", "backup-03.sql.age"},
		{"the completion manifest", "backup-03.sql.age" + backup.ManifestSuffix},
	} {
		t.Run(c.name, func(t *testing.T) {
			blobs := newBlobStore(t)
			names := putBackups(blobs, 12)
			// A manifest is fetched with GET, the blob itself read with HEAD.
			if strings.HasSuffix(c.blocked, backup.ManifestSuffix) {
				blobs.failGet[dbBlob(c.blocked)] = true
			} else {
				blobs.failHead[dbBlob(c.blocked)] = true
			}

			rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
			if err == nil {
				t.Fatal("a run that could not check every object reported success")
			}
			if len(rep.Removed) != 0 {
				t.Fatalf("removed %v although one object could not be checked", rep.Removed)
			}
			if rep.Withheld == "" || !strings.Contains(rep.Withheld, "removed nothing") {
				t.Fatalf("the report does not say why nothing was removed: %+v", rep)
			}
			for _, n := range names {
				if !held(blobs, n) {
					t.Fatalf("%s was removed by a run that could not read the whole prefix", n)
				}
			}
			for _, call := range blobs.calls {
				if strings.HasPrefix(call, "DELETE ") {
					t.Fatalf("a run that withheld pruning still deleted something: %s", call)
				}
			}
		})
	}
}

// TestPruneRemovesNothingWhenTheListingFails: without the listing there is no
// count, and a rule that deletes on an unknown count deletes the wrong things.
func TestPruneRemovesNothingWhenTheListingFails(t *testing.T) {
	blobs := newBlobStore(t)
	names := putBackups(blobs, 20)
	blobs.denyList = true

	rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
	if err == nil {
		t.Fatal("a run whose listing failed reported success")
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("removed = %v", rep.Removed)
	}
	if !strings.Contains(rep.Error, "nothing was removed") {
		t.Fatalf("the recorded error does not say nothing was removed: %s", rep.Error)
	}
	for _, n := range names {
		if !held(blobs, n) {
			t.Fatalf("%s was removed although the container could not be listed", n)
		}
	}
	for _, call := range blobs.calls {
		if strings.HasPrefix(call, "DELETE ") {
			t.Fatalf("a run whose listing failed deleted something: %s", call)
		}
	}
}

// TestPruneReportsAFailedDeletionAndLeavesTheBackup: a deletion the service
// refuses leaves the backup in place, is named, and fails the run. Both halves
// of the two-step removal are covered, because they fail differently: the
// completion manifest goes first, so a refusal there leaves the backup whole,
// and a refusal on the blob afterwards leaves it behind with no manifest.
func TestPruneReportsAFailedDeletionAndLeavesTheBackup(t *testing.T) {
	cases := []struct {
		name          string
		refuse        func(blob string) string
		manifestStays bool
	}{
		{"the completion manifest cannot be removed",
			func(blob string) string { return blob + backup.ManifestSuffix }, true},
		{"the backup itself cannot be removed",
			func(blob string) string { return blob }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blobs := newBlobStore(t)
			names := putBackups(blobs, 8)
			blobs.failDelete[c.refuse(names[0])] = true

			rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
			if err == nil {
				t.Fatal("a run that removed nothing it was asked to remove reported success")
			}
			if len(rep.Removed) != 0 {
				t.Fatalf("removed = %v; nothing was actually removed", rep.Removed)
			}
			if len(rep.Failed) != 1 || rep.Failed[0].Name != names[0] {
				t.Fatalf("failed = %+v", rep.Failed)
			}
			if !held(blobs, names[0]) {
				t.Fatalf("%s went although its deletion was refused", names[0])
			}
			if held(blobs, names[0]+backup.ManifestSuffix) != c.manifestStays {
				t.Fatalf("the completion manifest for %s: held = %v, want %v",
					names[0], !c.manifestStays, c.manifestStays)
			}
			if !strings.Contains(rep.Error, "left in place") {
				t.Fatalf("the recorded error does not say the backup stayed: %s", rep.Error)
			}
			// The other seven are still there: one refusal does not cascade.
			for _, n := range names[1:] {
				if !held(blobs, n) {
					t.Fatalf("%s was removed; only backups beyond the count may be", n)
				}
			}
		})
	}
}

// TestPruneRefusesARetentionItCannotTrust: below one backup the run is
// refused, not read as "delete everything", exactly as the recording period is.
func TestPruneRefusesARetentionItCannotTrust(t *testing.T) {
	blobs := newBlobStore(t)
	names := putBackups(blobs, 8)
	c := newClient(nil, blobs)

	for _, keep := range []int{-1, -7} {
		if _, err := PruneBackups(context.Background(), c, pruneOptions(keep)); err == nil {
			t.Fatalf("a retention of %d backups was accepted", keep)
		}
	}
	if _, err := PruneBackups(context.Background(), c, PruneOptions{Destination: testDestination(), Keep: 7}); err == nil {
		t.Fatal("pruning with no deployment ID was allowed")
	}
	o := pruneOptions(7)
	o.Destination = Destination{}
	if _, err := PruneBackups(context.Background(), c, o); err == nil {
		t.Fatal("pruning with no destination was allowed")
	}
	if len(blobs.calls) != 0 {
		t.Fatalf("a refused run still talked to Azure: %v", blobs.calls)
	}
	for _, n := range names {
		if !held(blobs, n) {
			t.Fatalf("a refused run deleted %s", n)
		}
	}
}

// TestPruneAndExpireDoNotReachEachOthersObjects: the two rules are separate and
// stay separate. Running both leaves each rule's own objects exactly as that
// rule decided, and neither touches the other's area.
func TestPruneAndExpireDoNotReachEachOthersObjects(t *testing.T) {
	blobs := newBlobStore(t)
	dbNames := putBackups(blobs, 8)
	putRemoteBackup(blobs, recBlob("old.guac.age"), testDeployment, expireNow)
	ageBlob(t, blobs, recBlob("old.guac.age"), expireNow.AddDate(0, 0, -40))
	putRemoteBackup(blobs, recBlob("recent.guac.age"), testDeployment, expireNow)
	c := newClient(nil, blobs)

	// The recording rule: the old recording goes, and every database backup
	// stays, however old it is.
	er, err := Expire(context.Background(), c, expireOptions(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(er.Removed) != 1 || er.Removed[0] != recBlob("old.guac.age") {
		t.Fatalf("expire removed %v", er.Removed)
	}
	for _, n := range dbNames {
		if !held(blobs, n) {
			t.Fatalf("the recording age rule removed the database backup %s", n)
		}
	}

	// The database rule: the oldest backup goes, and the recent recording
	// stays, whatever the count of recordings is.
	pr, err := PruneBackups(context.Background(), c, pruneOptions(7))
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.Removed) != 1 || pr.Removed[0] != dbNames[0] {
		t.Fatalf("prune removed %v, want the oldest backup %s", pr.Removed, dbNames[0])
	}
	if !held(blobs, recBlob("recent.guac.age")) {
		t.Fatal("the database count rule removed a recording")
	}
	if !strings.Contains(pr.Summary(), "Recordings expire by age") {
		t.Fatalf("the summary does not keep the two rules apart:\n%s", pr.Summary())
	}
	if !strings.Contains(er.Summary(), "never expired by age") {
		t.Fatalf("the recording summary no longer states the database rule:\n%s", er.Summary())
	}
}

func TestPruneLeaksNoCredential(t *testing.T) {
	blobs := newBlobStore(t)
	putBackups(blobs, 8)
	blobs.denyDelete = true

	rep, err := PruneBackups(context.Background(), newClient(nil, blobs), pruneOptions(7))
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
