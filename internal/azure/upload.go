package azure

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
)

// sha256Metadata carries the local completion manifest's SHA-256 on the blob
// itself, so a remote copy can be checked without fetching it back.
const sha256Metadata = "guacdeploy_sha256"

// Areas inside this deployment's prefix. Database backups and recordings are
// kept apart because they have different retention rules: database backups
// keep the last seven successful ones, recordings expire by age (issue #20),
// and "Do not apply this rule to unrelated objects or database backups"
// (specification, "Remote recording retention").
const (
	AreaDatabase   = "db"
	AreaRecordings = "recordings"
)

// BlobName is where one published file goes inside the container.
func BlobName(d Destination, deploymentID, area, name string) string {
	return d.Prefix(deploymentID) + area + "/" + name
}

// UploadPublished uploads one published file and then its completion
// manifest, in that order, and returns the blob name.
//
// # How a partial upload is made impossible to mistake for a complete one
//
// Azure Blob storage has no rename, so the "temporary name, then commit"
// shape used for local files is not available. The guarantee comes from the
// same completion contract internal/backup already defines, applied remotely:
//
//  1. The local file is verified against its local manifest first
//     (backup.VerifyPublished), so an unfinished local export is never
//     uploaded at all.
//  2. The blob is written with Content-MD5. The service compares the body it
//     received against that hash and rejects the request with 400 if they
//     differ, so a truncated or corrupted body never becomes a blob.
//  3. The blob is read back with Get Blob Properties and its length and
//     Content-MD5 are compared with the local manifest. A short or altered
//     blob fails here.
//  4. Only then is the completion manifest blob written, carrying exactly the
//     local manifest bytes: the deployment ID, the file name, the byte count,
//     and the SHA-256.
//
// A remote copy counts as complete only when step 4's manifest exists and
// matches (RemoteComplete). So a failure at any earlier step leaves a blob
// with no manifest, which is never counted as a backup and never deleted —
// exactly what a crash between the two local steps leaves behind, and safe
// for the same reason.
func (c *Client) UploadPublished(ctx context.Context, d Destination, dir, name, deploymentID, area string) (string, error) {
	if !d.Configured() {
		return "", fmt.Errorf("no Azure destination is configured; nothing was uploaded")
	}
	if deploymentID == "" {
		return "", fmt.Errorf("an upload needs the deployment ID to mark and scope its objects")
	}
	m, err := backup.VerifyPublished(dir, name, deploymentID)
	if err != nil {
		return "", fmt.Errorf("%s is not a complete backup of this deployment, so it was not uploaded: %w", name, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	// Re-checking against the manifest here is not redundant with
	// VerifyPublished: these are the exact bytes being sent, read after it.
	if int64(len(content)) != m.Bytes {
		return "", fmt.Errorf("%s changed while it was being read (%d bytes, manifest records %d); nothing was uploaded", name, len(content), m.Bytes)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return "", fmt.Errorf("%s does not match the SHA-256 in its manifest; nothing was uploaded", name)
	}

	blob := BlobName(d, deploymentID, area, name)
	meta := map[string]string{ownerMetadata: deploymentID, sha256Metadata: m.SHA256}
	if err := c.PutBlob(ctx, d, blob, content, md5Base64(content), meta); err != nil {
		return "", fmt.Errorf("uploading %s failed, so no completion manifest was written and the copy does not count: %w", name, err)
	}

	props, err := c.HeadBlob(ctx, d, blob)
	if err != nil {
		return "", fmt.Errorf("%s was uploaded but could not be read back, so no completion manifest was written and the copy does not count: %w", name, err)
	}
	if props.Bytes != m.Bytes {
		return "", fmt.Errorf("%s uploaded as %d bytes but the manifest records %d: the upload is incomplete, no completion manifest was written, and the copy does not count", name, props.Bytes, m.Bytes)
	}
	if props.ContentMD5 != "" && props.ContentMD5 != md5Base64(content) {
		return "", fmt.Errorf("%s does not match its content hash after upload: the upload is corrupt, no completion manifest was written, and the copy does not count", name)
	}

	manifestBytes, err := os.ReadFile(backup.ManifestPath(dir, name))
	if err != nil {
		return "", fmt.Errorf("%s was uploaded but its local completion manifest could not be read, so the copy does not count: %w", name, err)
	}
	if err := c.PutBlob(ctx, d, blob+backup.ManifestSuffix, manifestBytes, md5Base64(manifestBytes), meta); err != nil {
		return "", fmt.Errorf("%s was uploaded but its completion manifest could not be written, so the copy does not count: %w", name, err)
	}
	return blob, nil
}

// RemoteComplete reports whether a complete, matching copy of dir/name is
// already in the container. It is the read side of the completion contract
// and needs no key: the manifest blob is compared with the local manifest,
// and the blob itself is length-checked against it.
//
// This is also the retrieval proof an operator can ask for: it fetches a
// remote object back and shows it matches what was published locally.
func (c *Client) RemoteComplete(ctx context.Context, d Destination, dir, name, deploymentID, area string) (bool, error) {
	local, err := backup.VerifyPublished(dir, name, deploymentID)
	if err != nil {
		return false, err
	}
	blob := BlobName(d, deploymentID, area, name)
	var remote backup.Manifest
	if err := c.readManifestBlob(ctx, d, blob+backup.ManifestSuffix, &remote); err != nil {
		if NotFound(err) {
			return false, nil
		}
		return false, err
	}
	if remote.DeploymentID != local.DeploymentID || remote.File != local.File ||
		remote.Bytes != local.Bytes || remote.SHA256 != local.SHA256 {
		return false, nil
	}
	props, err := c.HeadBlob(ctx, d, blob)
	if err != nil {
		if NotFound(err) {
			return false, nil
		}
		return false, err
	}
	if props.Bytes != local.Bytes {
		return false, nil
	}
	if props.ContentSHA256 != "" && props.ContentSHA256 != local.SHA256 {
		return false, nil
	}
	return true, nil
}

func md5Base64(b []byte) string {
	sum := md5.Sum(b)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Options configures one upload run.
type Options struct {
	Dest         string // local published backup destination root
	StateDir     string // where the last-run record is written
	DeploymentID string
	Destination  Destination

	// ClientID and AuthMode are recorded in the status report so an operator
	// can see which application signed in and how. Neither is a secret.
	ClientID string
	AuthMode string

	// OnCalendar is the installed schedule, recorded for the status report.
	OnCalendar string

	// Now supplies the run timestamp; nil means time.Now.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Failure is one file that could not be uploaded. It is never reported as
// uploaded, and never reported as complete.
type Failure struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Outcome is the result for one kind of content.
type Outcome struct {
	// Uploaded is every file this run copied and completed. A name reaches
	// it only after its completion manifest blob is written.
	Uploaded []string `json:"uploaded,omitempty"`
	// AlreadyThere is every file whose remote copy was already complete and
	// still matches.
	AlreadyThere []string `json:"already_there,omitempty"`
	// Failed is every file whose upload failed. Nothing was completed for
	// these.
	Failed []Failure `json:"failed,omitempty"`
}

// Report is the result of one upload run, and the destination it used.
// Database and recording results are kept apart deliberately: "Report
// database and recording results separately" (specification).
//
// It holds names, counts, and error text. No token, client secret, refresh
// token, or account key passes through this package, so none can reach here;
// TestReportHoldsNoSecrets fails if a field is ever added that could.
type Report struct {
	Ran         time.Time   `json:"ran"`
	Result      string      `json:"result"` // "ok" or "failed"
	Destination Destination `json:"destination"`
	Prefix      string      `json:"prefix"`
	ClientID    string      `json:"client_id,omitempty"` // which application signed in; not a secret
	AuthMode    string      `json:"auth_mode,omitempty"` // "device-code" or "service-principal"

	Database   Outcome `json:"database"`
	Recordings Outcome `json:"recordings"`

	Error      string `json:"error,omitempty"`
	OnCalendar string `json:"on_calendar,omitempty"`
}

// Upload copies this deployment's complete local backups and recording copies
// into the container, and records the outcome either way.
//
// It uploads from the local published destination rather than exporting
// again: the local publish already carries the completion proof, so the
// upload is a copy of something known to be whole, and a database export
// never happens twice. Files already complete in the container are skipped,
// so a run after an outage catches up rather than re-sending everything.
//
// A failed recording upload does not stop the database result being recorded,
// and neither result is ever merged into the other.
func Upload(ctx context.Context, c *Client, o Options) (Report, error) {
	rep := Report{Ran: o.now().UTC(), Result: "ok", Destination: o.Destination,
		ClientID: o.ClientID, AuthMode: o.AuthMode, OnCalendar: o.OnCalendar}
	if o.DeploymentID == "" {
		return rep, fmt.Errorf("an Azure upload needs the deployment ID to mark and scope its objects")
	}
	rep.Prefix = o.Destination.Prefix(o.DeploymentID)
	if !o.Destination.Configured() {
		return o.fail(rep, fmt.Errorf("no Azure destination is configured; nothing was uploaded"))
	}
	if o.Dest == "" {
		return o.fail(rep, fmt.Errorf("an Azure upload needs the local backup destination to copy from"))
	}

	dbNames, err := schedule.List(o.Dest, o.DeploymentID)
	if err != nil {
		return o.fail(rep, fmt.Errorf("the local backup destination %s could not be read: %w", o.Dest, err))
	}
	dbErr := c.uploadAll(ctx, o, o.Dest, dbNames, AreaDatabase, &rep.Database)

	recDir := recording.DestDir(o.Dest)
	recNames, err := completeRecordings(recDir, o.DeploymentID)
	if err != nil {
		return o.fail(rep, fmt.Errorf("the local recording copies in %s could not be read: %w", recDir, err))
	}
	recErr := c.uploadAll(ctx, o, recDir, recNames, AreaRecordings, &rep.Recordings)

	switch {
	case dbErr != nil && recErr != nil:
		return o.fail(rep, fmt.Errorf("%v; and %v", dbErr, recErr))
	case dbErr != nil:
		return o.fail(rep, dbErr)
	case recErr != nil:
		return o.fail(rep, recErr)
	}
	if err := WriteReport(o.StateDir, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

func (o Options) fail(rep Report, err error) (Report, error) {
	rep.Result, rep.Error = "failed", err.Error()
	if werr := WriteReport(o.StateDir, rep); werr != nil {
		return rep, fmt.Errorf("%v (and the status file could not be written: %v)", err, werr)
	}
	return rep, err
}

// uploadAll uploads one area's files, recording each result separately. One
// failure does not stop the rest: every file is attempted, and the first
// failure is returned so the run exits nonzero.
func (c *Client) uploadAll(ctx context.Context, o Options, dir string, names []string, area string, out *Outcome) error {
	var firstErr error
	for _, name := range names {
		done, err := c.RemoteComplete(ctx, o.Destination, dir, name, o.DeploymentID, area)
		if err == nil && done {
			out.AlreadyThere = append(out.AlreadyThere, name)
			continue
		}
		if err != nil && ctx.Err() != nil {
			return err
		}
		if _, err := c.UploadPublished(ctx, o.Destination, dir, name, o.DeploymentID, area); err != nil {
			out.Failed = append(out.Failed, Failure{Name: name, Reason: err.Error()})
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", area, err)
			}
			continue
		}
		out.Uploaded = append(out.Uploaded, name)
	}
	if firstErr != nil {
		done := len(out.Uploaded) + len(out.AlreadyThere)
		return fmt.Errorf("%d of %d %s files could not be uploaded, so this upload is not complete; first failure: %w",
			len(out.Failed), len(out.Failed)+done, area, firstErr)
	}
	return nil
}

// completeRecordings lists the recording copies in dir that are complete and
// belong to this deployment. A missing directory means recordings were never
// backed up locally, which is not a failure.
func completeRecordings(dir, deploymentID string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), backup.ManifestSuffix) {
			continue
		}
		if _, err := backup.VerifyPublished(dir, e.Name(), deploymentID); err != nil {
			continue // incomplete, or another deployment's copy: not ours to upload
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// ReportPath is the last-run record, beside the scheduled backup's and the
// recording run's, and for the same reason: the deployment record is the
// parent's schema and a nightly timer must not churn it.
func ReportPath(stateDir string) string { return filepath.Join(stateDir, "azure-status.json") }

// WriteReport saves the last-run record with owner-only permissions, through
// a temporary file and a rename.
func WriteReport(stateDir string, rep Report) error {
	if stateDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	path := ReportPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReadReport returns the last-run record, or nil when no run has happened.
func ReadReport(stateDir string) (*Report, error) {
	b, err := os.ReadFile(ReportPath(stateDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s is not readable JSON: %w", ReportPath(stateDir), err)
	}
	return &r, nil
}

// Summary renders the last-run record for an operator: where backups go, and
// what the last run did. Database and recording counts are shown apart, and a
// failed upload is named, because that is the line an administrator acts on.
func (r Report) Summary() string {
	var b strings.Builder
	d := r.Destination
	if !d.Configured() {
		return "Azure Blob destination: not configured.\n"
	}
	fmt.Fprintf(&b, "Azure destination:    %s/%s (subscription %s, resource group %s)\n",
		d.Account, d.Container, d.SubscriptionID, d.ResourceGroup)
	fmt.Fprintf(&b, "Object prefix:        %s\n", r.Prefix)
	if r.AuthMode != "" {
		fmt.Fprintf(&b, "Sign-in:              %s (application %s)\n", r.AuthMode, r.ClientID)
	}
	if r.OnCalendar != "" {
		fmt.Fprintf(&b, "Schedule:             %s\n", r.OnCalendar)
	}
	fmt.Fprintf(&b, "Last run:             %s  %s\n", r.Ran.Format(time.RFC3339), r.Result)
	fmt.Fprintf(&b, "Database backups:     %d uploaded, %d already held, %d failed\n",
		len(r.Database.Uploaded), len(r.Database.AlreadyThere), len(r.Database.Failed))
	fmt.Fprintf(&b, "Recordings:           %d uploaded, %d already held, %d failed\n",
		len(r.Recordings.Uploaded), len(r.Recordings.AlreadyThere), len(r.Recordings.Failed))
	for _, f := range r.Database.Failed {
		fmt.Fprintf(&b, "Upload failed (db):   %s: %s\n", f.Name, firstLine(f.Reason))
	}
	for _, f := range r.Recordings.Failed {
		fmt.Fprintf(&b, "Upload failed (rec):  %s: %s\n", f.Name, firstLine(f.Reason))
	}
	if r.Error != "" {
		fmt.Fprintf(&b, "Reason:               %s\n", firstLine(r.Error))
	}
	b.WriteString("Remote copies and the container survive teardown; this tool never deletes the\ncontainer or the storage account.\n")
	return b.String()
}

// Summary reads the last-run record and renders it, for the status command.
func Summary(stateDir string) string {
	r, err := ReadReport(stateDir)
	if err != nil {
		return fmt.Sprintf("Azure upload status is unreadable: %v\n", err)
	}
	if r == nil {
		return "No Azure upload has run yet.\n"
	}
	return r.Summary()
}
