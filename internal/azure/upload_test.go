package azure

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
)

const (
	dbBackup1 = "guacdeploy-db-20260101T120000.000Z.sql.age"
	dbBackup2 = "guacdeploy-db-20260102T120000.000Z.sql.age"
	rec1      = "a1b2c3d4-0000-0000-0000-00000000cafe.guac.age"
)

// localDest builds a local published destination holding two database
// backups and one recording copy, exactly as internal/backup and
// internal/recording publish them.
func localDest(t *testing.T) string {
	t.Helper()
	dest := t.TempDir()
	publishLocal(t, dest, dbBackup1, []byte("age-encryption.org/v1\nfirst backup\n"), testDeployment)
	publishLocal(t, dest, dbBackup2, []byte("age-encryption.org/v1\nsecond backup\n"), testDeployment)
	publishLocal(t, recording.DestDir(dest), rec1, []byte("age-encryption.org/v1\nrecording\n"), testDeployment)
	return dest
}

func uploadOptions(dest, stateDir string) Options {
	return Options{Dest: dest, StateDir: stateDir, DeploymentID: testDeployment,
		Destination: testDestination(), ClientID: "app-123", AuthMode: "service-principal",
		Now: func() time.Time { return time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC) }}
}

func TestUploadCopiesDatabaseAndRecordingsAndReportsThemSeparately(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	c := newClient(nil, blobs)

	rep, err := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Result != "ok" {
		t.Fatalf("result = %s: %s", rep.Result, rep.Error)
	}
	if len(rep.Database.Uploaded) != 2 {
		t.Fatalf("database uploaded = %v", rep.Database.Uploaded)
	}
	if len(rep.Recordings.Uploaded) != 1 || rep.Recordings.Uploaded[0] != rec1 {
		t.Fatalf("recordings uploaded = %v", rep.Recordings.Uploaded)
	}

	prefix := testDestination().Prefix(testDeployment)
	for _, want := range []string{
		prefix + "db/" + dbBackup1,
		prefix + "db/" + dbBackup1 + backup.ManifestSuffix,
		prefix + "db/" + dbBackup2,
		prefix + "recordings/" + rec1,
		prefix + "recordings/" + rec1 + backup.ManifestSuffix,
	} {
		if _, ok := blobs.blobs[want]; !ok {
			t.Fatalf("blob %s was not written; store holds %v", want, blobNames(blobs))
		}
	}
	// Every object carries this deployment's ownership marker, so remote
	// retention can scope itself later without guessing from names.
	for name, b := range blobs.blobs {
		if b.meta[ownerMetadata] != testDeployment {
			t.Fatalf("blob %s has owner metadata %q", name, b.meta[ownerMetadata])
		}
	}

	// The uploaded bytes are the local bytes.
	local, err := os.ReadFile(filepath.Join(dest, dbBackup1))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(blobs.blobs[prefix+"db/"+dbBackup1].content); got != string(local) {
		t.Fatalf("uploaded content = %q", got)
	}

	// The remote manifest is the local manifest, so retrieval can be proved
	// without any key.
	var remote backup.Manifest
	if err := json.Unmarshal(blobs.blobs[prefix+"db/"+dbBackup1+backup.ManifestSuffix].content, &remote); err != nil {
		t.Fatal(err)
	}
	if remote.DeploymentID != testDeployment || remote.File != dbBackup1 {
		t.Fatalf("remote manifest = %+v", remote)
	}

	done, err := c.RemoteComplete(context.Background(), testDestination(), dest, dbBackup1, testDeployment, AreaDatabase)
	if err != nil || !done {
		t.Fatalf("RemoteComplete = %v, %v", done, err)
	}
}

func TestSecondRunSkipsWhatIsAlreadyComplete(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	c := newClient(nil, blobs)
	o := uploadOptions(dest, stateDir)

	if _, err := Upload(context.Background(), c, o); err != nil {
		t.Fatal(err)
	}
	writes := countPuts(blobs)
	rep, err := Upload(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Database.Uploaded) != 0 || len(rep.Database.AlreadyThere) != 2 {
		t.Fatalf("second run: uploaded %v, already there %v", rep.Database.Uploaded, rep.Database.AlreadyThere)
	}
	if len(rep.Recordings.AlreadyThere) != 1 {
		t.Fatalf("second run: recordings already there = %v", rep.Recordings.AlreadyThere)
	}
	if got := countPuts(blobs); got != writes {
		t.Fatalf("the second run wrote %d blobs; complete copies must be skipped", got-writes)
	}
}

// TestTruncatedUploadIsNeverCountedComplete is the completeness contract. The
// blob lands short; no completion manifest may follow it, the run must fail,
// and nothing may report the copy as held.
func TestTruncatedUploadIsNeverCountedComplete(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	prefix := testDestination().Prefix(testDeployment)
	blobs.truncate[prefix+"db/"+dbBackup1] = 5
	c := newClient(nil, blobs)

	rep, err := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	if err == nil {
		t.Fatal("a truncated upload was reported as success")
	}
	if rep.Result != "failed" {
		t.Fatalf("result = %s", rep.Result)
	}
	if len(rep.Database.Failed) != 1 || rep.Database.Failed[0].Name != dbBackup1 {
		t.Fatalf("failed = %+v", rep.Database.Failed)
	}
	for _, name := range rep.Database.Uploaded {
		if name == dbBackup1 {
			t.Fatal("a truncated file appears in Uploaded")
		}
	}
	if _, ok := blobs.blobs[prefix+"db/"+dbBackup1+backup.ManifestSuffix]; ok {
		t.Fatal("a completion manifest was written for a truncated blob")
	}
	done, err := c.RemoteComplete(context.Background(), testDestination(), dest, dbBackup1, testDeployment, AreaDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("a truncated blob is counted as a complete remote copy")
	}
	if !strings.Contains(rep.Database.Failed[0].Reason, "does not count") {
		t.Fatalf("the failure does not say the copy does not count: %s", rep.Database.Failed[0].Reason)
	}

	// The other backup and the recording still went, and are reported apart.
	if len(rep.Database.Uploaded) != 1 || rep.Database.Uploaded[0] != dbBackup2 {
		t.Fatalf("one failure stopped the rest: uploaded = %v", rep.Database.Uploaded)
	}
	if len(rep.Recordings.Uploaded) != 1 {
		t.Fatalf("a database failure blocked the recordings: %+v", rep.Recordings)
	}
}

// TestShortUploadWithNoContentHashIsStillCaught covers the case where the
// content hash cannot help: Get Blob Properties returns no Content-MD5 for a
// blob the service did not hash, and then only the length check stands
// between a short blob and a completion manifest.
func TestShortUploadWithNoContentHashIsStillCaught(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	prefix := testDestination().Prefix(testDeployment)
	blobs.truncate[prefix+"db/"+dbBackup1] = 5
	blobs.omitMD5[prefix+"db/"+dbBackup1] = true
	c := newClient(nil, blobs)

	rep, err := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	if err == nil {
		t.Fatal("a short blob with no content hash was reported as success")
	}
	if len(rep.Database.Failed) != 1 || rep.Database.Failed[0].Name != dbBackup1 {
		t.Fatalf("failed = %+v", rep.Database.Failed)
	}
	if !strings.Contains(rep.Database.Failed[0].Reason, "uploaded as 5 bytes") {
		t.Fatalf("the failure does not name the short length: %s", rep.Database.Failed[0].Reason)
	}
	if _, ok := blobs.blobs[prefix+"db/"+dbBackup1+backup.ManifestSuffix]; ok {
		t.Fatal("a completion manifest was written for a short blob")
	}
}

func TestCorruptedUploadIsNeverCountedComplete(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	prefix := testDestination().Prefix(testDeployment)
	blobs.corruptMD5[prefix+"db/"+dbBackup1] = true
	c := newClient(nil, blobs)

	rep, err := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	if err == nil {
		t.Fatal("a blob whose content hash does not match was reported as success")
	}
	if _, ok := blobs.blobs[prefix+"db/"+dbBackup1+backup.ManifestSuffix]; ok {
		t.Fatal("a completion manifest was written for a corrupt blob")
	}
	if len(rep.Database.Failed) != 1 {
		t.Fatalf("failed = %+v", rep.Database.Failed)
	}
}

// TestTamperedLocalFileIsNeverUploaded proves the first step of the contract:
// a local file that no longer matches its own manifest never reaches Azure.
func TestTamperedLocalFileIsNeverUploaded(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, dbBackup1), []byte("age-encryption.org/v1\nnot what the manifest says\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blobs := newBlobStore(t)
	c := newClient(nil, blobs)

	rep, _ := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	prefix := testDestination().Prefix(testDeployment)
	if _, ok := blobs.blobs[prefix+"db/"+dbBackup1]; ok {
		t.Fatal("a file that does not match its manifest was uploaded")
	}
	// internal/schedule's listing already refuses it, so it is not even
	// offered for upload; either way it must not appear as uploaded.
	for _, n := range rep.Database.Uploaded {
		if n == dbBackup1 {
			t.Fatal("a tampered file appears in Uploaded")
		}
	}

	// Direct call against a fresh container, to prove the guard is in the
	// uploader and not only in the listing it happened to be given.
	fresh := newBlobStore(t)
	_, err := newClient(nil, fresh).UploadPublished(context.Background(), testDestination(), dest, dbBackup1, testDeployment, AreaDatabase)
	if err == nil || !strings.Contains(err.Error(), "not a complete backup of this deployment") {
		t.Fatalf("err = %v", err)
	}
	if len(fresh.blobs) != 0 {
		t.Fatalf("bytes were sent for a file that failed its local check: %v", blobNames(fresh))
	}
}

func TestUploadRefusesAnotherDeploymentsBackup(t *testing.T) {
	dest := t.TempDir()
	publishLocal(t, dest, dbBackup1, []byte("someone else's backup\n"), "0000other0000")
	blobs := newBlobStore(t)
	c := newClient(nil, blobs)

	_, err := c.UploadPublished(context.Background(), testDestination(), dest, dbBackup1, testDeployment, AreaDatabase)
	if err == nil || !strings.Contains(err.Error(), "not a complete backup of this deployment") {
		t.Fatalf("err = %v", err)
	}
	if len(blobs.blobs) != 0 {
		t.Fatal("another deployment's backup was uploaded")
	}

	// And the run as a whole leaves it alone rather than failing.
	rep, err := Upload(context.Background(), c, uploadOptions(dest, t.TempDir()))
	if err != nil {
		t.Fatalf("a shared destination holding a foreign backup failed the run: %v", err)
	}
	if len(rep.Database.Uploaded) != 0 || len(rep.Database.Failed) != 0 {
		t.Fatalf("report = %+v", rep.Database)
	}
}

func TestUploadWithoutADestinationFailsVisibly(t *testing.T) {
	o := uploadOptions(t.TempDir(), t.TempDir())
	o.Destination = Destination{}
	rep, err := Upload(context.Background(), newClient(nil, newBlobStore(t)), o)
	if err == nil || !strings.Contains(err.Error(), "no Azure destination is configured") {
		t.Fatalf("err = %v", err)
	}
	if rep.Result != "failed" {
		t.Fatalf("result = %s", rep.Result)
	}
}

func TestUploadNeedsADeploymentID(t *testing.T) {
	o := uploadOptions(t.TempDir(), t.TempDir())
	o.DeploymentID = ""
	if _, err := Upload(context.Background(), newClient(nil, newBlobStore(t)), o); err == nil {
		t.Fatal("an upload with no deployment ID was allowed")
	}
}

func TestRemoteCompleteRejectsAMismatchedRemoteManifest(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	c := newClient(nil, blobs)
	if _, err := Upload(context.Background(), c, uploadOptions(dest, stateDir)); err != nil {
		t.Fatal(err)
	}
	prefix := testDestination().Prefix(testDeployment)
	key := prefix + "db/" + dbBackup1 + backup.ManifestSuffix

	// A manifest describing a different deployment must not count as ours.
	var m backup.Manifest
	if err := json.Unmarshal(blobs.blobs[key].content, &m); err != nil {
		t.Fatal(err)
	}
	m.DeploymentID = "0000other0000"
	b, _ := json.Marshal(m)
	blobs.blobs[key] = storedBlob{content: b, md5: md5B64(b), meta: blobs.blobs[key].meta}

	done, err := c.RemoteComplete(context.Background(), testDestination(), dest, dbBackup1, testDeployment, AreaDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if done {
		t.Fatal("a manifest naming another deployment was accepted as our complete copy")
	}
}

func TestStatusFileIsOwnerOnlyAndHoldsNoSecrets(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	c := newClient(nil, newBlobStore(t))
	rep, err := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	if err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(ReportPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("status file mode = %v", fi.Mode().Perm())
	}
	raw, err := os.ReadFile(ReportPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testToken, "Bearer ", clientSecret, refreshToken} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the status file contains %q", secret)
		}
		if strings.Contains(rep.Summary(), secret) {
			t.Fatalf("the rendered summary contains %q", secret)
		}
	}

	back, err := ReadReport(stateDir)
	if err != nil || back == nil {
		t.Fatalf("ReadReport = %v, %v", back, err)
	}
	if back.Destination.Account != "acctbackups" || back.Destination.Container != "guacdeploy" {
		t.Fatalf("round-tripped destination = %+v", back.Destination)
	}

	s := Summary(stateDir)
	for _, want := range []string{"acctbackups", "guacdeploy", "service-principal", "app-123", "2 uploaded"} {
		if !strings.Contains(s, want) {
			t.Fatalf("the summary does not show %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "never deletes the\ncontainer") {
		t.Fatalf("the summary does not state the teardown guarantee:\n%s", s)
	}
}

func TestSummaryWithoutAnyRun(t *testing.T) {
	if got := Summary(t.TempDir()); !strings.Contains(got, "No Azure upload has run yet") {
		t.Fatalf("summary = %q", got)
	}
	r := Report{}
	if got := r.Summary(); !strings.Contains(got, "not configured") {
		t.Fatalf("summary = %q", got)
	}
}

func TestNoTokenReachesAnErrorOrTheStatusFile(t *testing.T) {
	dest, stateDir := localDest(t), t.TempDir()
	blobs := newBlobStore(t)
	blobs.denyPut = true
	c := newClient(nil, blobs)

	rep, err := Upload(context.Background(), c, uploadOptions(dest, stateDir))
	if err == nil {
		t.Fatal("a denied upload returned no error")
	}
	raw, rerr := os.ReadFile(ReportPath(stateDir))
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, text := range []string{err.Error(), rep.Summary(), string(raw)} {
		if strings.Contains(text, testToken) {
			t.Fatalf("the access token leaked into: %s", text)
		}
	}
	if !strings.Contains(err.Error(), "AuthorizationPermissionMismatch") {
		t.Fatalf("the error drops the service's own code: %v", err)
	}
}

func blobNames(s *blobStore) []string {
	var out []string
	for n := range s.blobs {
		out = append(out, n)
	}
	return out
}

func countPuts(s *blobStore) int {
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, "PUT ") {
			n++
		}
	}
	return n
}
