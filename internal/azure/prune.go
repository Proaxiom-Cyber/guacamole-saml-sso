package azure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
)

// errIncomplete means a remote object under the database prefix is provably
// not a complete backup: no completion manifest, an unreadable one, or one
// that does not describe the blob beside it. It is the residue an upload
// leaves when it stops between the bytes and the manifest.
//
// It is deliberately different from "this run could not tell". A copy that is
// provably incomplete is a fact about the container: it is never counted as
// one of the retained backups, never deleted, and does not stop the run
// pruning the backups it *can* account for. A copy this run could not check at
// all stops the run pruning anything — see PruneBackups.
var errIncomplete = errors.New("the remote copy is not a complete backup")

// PruneOptions configures one remote database-backup retention run.
//
// "Offer daily scheduling and retain the last seven successful backups by
// default. Make schedule and retention configurable. Failed backups must not
// trigger deletion of older backups" (specification, backup section), and
// "Database backups retain the separate default of seven successful backups"
// (specification, "Remote recording retention").
//
// This is a count, not an age, and it is a different rule from ExpireOptions.
// Neither reaches the other's objects: this one lists only the database area
// and that one lists only the recordings area.
type PruneOptions struct {
	Destination  Destination
	DeploymentID string

	// Keep is how many of the most recent successful backups stay in the
	// container. Zero means the specification's default of seven —
	// schedule.DefaultKeep, the same constant local retention keeps, so the
	// two cannot drift apart. Below one the run is refused rather than
	// treated as "delete everything", exactly as ExpireOptions.Days is.
	Keep int

	// Now supplies the run timestamp; nil means time.Now.
	Now func() time.Time
}

func (o PruneOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// PruneReport is the result of one remote database-backup retention run.
// Every object the run looked at ends in exactly one of Removed, Kept,
// NotOwned or Failed, so the four account for the whole of the database area.
//
// A completion manifest is not one of those objects: it is part of the backup
// it describes, and it is removed with it.
type PruneReport struct {
	Ran  time.Time `json:"ran"`
	Keep int       `json:"keep"`
	// Prefix is the only path this run can reach: this deployment's database
	// area. Recordings live under a sibling prefix and are never listed, so
	// the count rule cannot reach them.
	Prefix string `json:"prefix"`

	// Removed is every backup deleted, with its completion manifest.
	Removed []string `json:"removed,omitempty"`
	// Kept counts the verified backups retained: the newest Keep of them, or
	// all of them when the container holds no more than Keep.
	Kept int `json:"kept"`
	// NotOwned is every object in the prefix whose ownership marker is
	// missing or names another deployment. It is neither counted nor deleted.
	NotOwned []string `json:"not_owned,omitempty"`
	// Failed is every object the run could not remove, and every object it
	// could not count as a backup. None of them is deleted, and none of them
	// displaces a backup that is.
	Failed []Failure `json:"failed,omitempty"`

	// Withheld says why this run removed nothing at all. It is set when the
	// run could not check every object, because a run that cannot prove what
	// it holds must not start removing things.
	Withheld string `json:"withheld,omitempty"`

	Error string `json:"error,omitempty"`
}

// PruneBackups keeps this deployment's last Keep successful database backups
// in Azure and removes the older ones, and nothing else.
//
// # What it can reach
//
// Only `guacdeploy/<deployment-id>/db/`. The listing is taken under that
// prefix, so a recording is not merely skipped, it is never seen: recordings
// keep their own separate retention by age (Expire), and this count is not
// applied to them. Every deletion then goes through DeleteOwnedBlob, which
// refuses a name outside this deployment's prefix and reads the
// guacdeploy_deployment marker back from the service before deleting. An
// object whose marker is missing or names someone else is left in place and
// reported, never deleted. A matching name alone never establishes ownership.
//
// # What it cannot reach
//
// There is no container or storage account deletion path in this package and
// there will not be one: "Preserve remote backups and their supporting storage
// resources during ordinary teardown" (specification).
// TestNoContainerOrAccountDeletionPathExists holds the package to that, and
// this function adds no new DELETE — it calls the one that already exists.
//
// Preserving remote backups during *teardown* is not a retention policy. The
// policy is the specification's own: the last seven successful backups, made
// configurable. Reading the teardown sentence as "remote backups are kept for
// ever" is what let them accumulate without limit (issue #20).
//
// # What counts as one of the seven
//
// Only a copy this run can prove is a complete backup of this deployment,
// using the evidence RemoteComplete uses when the local file is no longer
// there: the blob carries this deployment's ownership marker, its completion
// manifest blob exists and decodes, that manifest names this deployment and
// this file, and the blob's own length and SHA-256 metadata match it. A copy
// that fails any of those is neither counted nor deleted.
//
// The body is not fetched back and re-hashed. The Content-MD5 check belongs to
// the write: Put Blob compares the body it receives against the header and
// rejects a mismatch, and UploadPublished then reads the blob back and
// compares its length and Content-MD5 before writing the manifest at all. So a
// manifest exists only for a body the service already accepted and confirmed.
// Downloading every backup every night to repeat that would cost the whole
// container in transfer and prove nothing the write did not.
//
// # Why a failed upload cannot evict a good backup
//
// An upload that stops after the bytes and before the manifest leaves a blob
// with no manifest. It is not a backup, so it never enters the count, so it
// can never push a real backup out of it. Seven failed uploads in a row leave
// seven objects the run reports and leaves alone, and the seven good backups
// stay exactly where they are.
//
// And when the run cannot check an object at all — the service refused the
// read, or the connection failed — it removes nothing this run and says so in
// Withheld. An unknown object might be a backup or might not, and pruning on a
// count taken from an incomplete reading is how good backups disappear.
func PruneBackups(ctx context.Context, c *Client, o PruneOptions) (PruneReport, error) {
	if o.Keep == 0 {
		o.Keep = schedule.DefaultKeep
	}
	rep := PruneReport{Ran: o.now().UTC(), Keep: o.Keep}
	if o.DeploymentID == "" {
		return rep, fmt.Errorf("pruning remote backups needs the deployment ID to prove which objects are this deployment's own; nothing was removed")
	}
	if !o.Destination.Configured() {
		return rep, fmt.Errorf("no Azure destination is configured; nothing was removed")
	}
	if o.Keep < 1 {
		return rep, fmt.Errorf("remote backup retention must keep at least one backup, got %d; nothing was removed", o.Keep)
	}
	rep.Prefix = o.Destination.Prefix(o.DeploymentID) + AreaDatabase + "/"

	blobs, err := c.listAll(ctx, o.Destination, rep.Prefix)
	if err != nil {
		err = fmt.Errorf("the backups in %s could not be listed, so nothing was removed: %w", rep.Prefix, err)
		rep.Error = err.Error()
		return rep, err
	}

	var firstErr error
	note := func(name string, err error) {
		rep.Failed = append(rep.Failed, Failure{Name: name, Reason: err.Error()})
		if firstErr == nil {
			firstErr = err
		}
	}

	var complete []remoteBackup
	unchecked := 0
	for _, b := range blobs {
		// A completion manifest is part of the backup it describes, not a
		// backup of its own. It is removed with its backup, never alone.
		if strings.HasSuffix(b.Name, backup.ManifestSuffix) {
			continue
		}
		// Defence in depth. The listing is already scoped to the database
		// prefix, so this cannot fire; it exists so that a future change to
		// the listing cannot quietly widen what retention deletes.
		if !strings.HasPrefix(b.Name, rep.Prefix) {
			continue
		}
		m, err := c.verifiedBackup(ctx, o.Destination, b.Name, o.DeploymentID)
		switch {
		case errors.Is(err, ErrNotOwned):
			rep.NotOwned = append(rep.NotOwned, b.Name)
		case errors.Is(err, errIncomplete):
			// A fact about the container, not a failure of this run: it is
			// reported, left alone, and never counted. It does not stop the
			// backups this run *can* account for being pruned, or an upload
			// that died halfway would suspend retention for ever.
			rep.Failed = append(rep.Failed, Failure{Name: b.Name, Reason: err.Error()})
		case err != nil:
			unchecked++
			note(b.Name, err)
		default:
			complete = append(complete, remoteBackup{name: b.Name, at: m.PublishedAt.UTC()})
		}
	}

	// Newest first, by when the backup was published locally rather than by
	// when its copy reached Azure. A catch-up upload of an old backup must not
	// count as the newest one, and Last-Modified is the recording rule's
	// clock, which this rule deliberately does not share. The name is a
	// tie-break so the order is total and stable.
	sort.Slice(complete, func(i, j int) bool {
		if !complete[i].at.Equal(complete[j].at) {
			return complete[i].at.After(complete[j].at)
		}
		return complete[i].name > complete[j].name
	})

	rep.Kept = len(complete)
	if unchecked > 0 {
		rep.Withheld = fmt.Sprintf("%d object(s) in %s could not be checked, so this run removed nothing and every older backup was preserved", unchecked, rep.Prefix)
	} else if len(complete) > o.Keep {
		rep.Kept = o.Keep
		for _, b := range complete[o.Keep:] {
			// The completion manifest goes first. Between the two deletions
			// the backup correctly stops counting as a complete copy, which is
			// the honest order: the reverse would leave a manifest describing
			// a blob that is already gone, and a later blob landing on that
			// name would inherit completion evidence it never earned.
			if err := c.DeleteOwnedBlob(ctx, o.Destination, b.name+backup.ManifestSuffix, o.DeploymentID); err != nil && !NotFound(err) {
				if errors.Is(err, ErrNotOwned) {
					rep.NotOwned = append(rep.NotOwned, b.name)
					continue
				}
				note(b.name, fmt.Errorf("the completion manifest for %s could not be removed, so the backup was left in place: %w", b.name, err))
				continue
			}
			if err := c.DeleteOwnedBlob(ctx, o.Destination, b.name, o.DeploymentID); err != nil {
				if errors.Is(err, ErrNotOwned) {
					rep.NotOwned = append(rep.NotOwned, b.name)
					continue
				}
				note(b.name, fmt.Errorf("removing the expired backup %s failed: %w", b.name, err))
				continue
			}
			rep.Removed = append(rep.Removed, b.name)
		}
	}

	if firstErr != nil {
		err := fmt.Errorf("%d of this deployment's remote backups could not be accounted for or removed and were left in place; first failure: %w", len(rep.Failed), firstErr)
		rep.Error = err.Error()
		return rep, err
	}
	return rep, nil
}

// remoteBackup is one verified backup copy and the instant that orders it.
type remoteBackup struct {
	name string
	at   time.Time // the completion manifest's PublishedAt
}

// verifiedBackup proves one remote object is a complete database backup of
// this deployment, and returns its completion manifest.
//
// It is the read side of the same completion contract RemoteComplete checks,
// with the local file's half of the evidence unavailable: a backup old enough
// to be pruned remotely has usually been pruned locally already. What is left
// is still the whole of what the upload wrote — the ownership marker, the
// manifest blob, and the length and SHA-256 the read-back check confirmed
// before that manifest was written.
//
// The three outcomes are kept apart on purpose:
//
//   - ErrNotOwned: the object is not this deployment's. Never counted, never
//     deleted, reported.
//   - errIncomplete: the object is provably not a complete backup. Never
//     counted, never deleted, reported, and it does not stop the run.
//   - any other error: this run could not tell. The caller then removes
//     nothing at all, because a count taken from a partial reading is not a
//     count.
func (c *Client) verifiedBackup(ctx context.Context, d Destination, name, deploymentID string) (backup.Manifest, error) {
	var m backup.Manifest
	props, err := c.HeadBlob(ctx, d, name)
	if err != nil {
		if NotFound(err) {
			// Listed a moment ago and gone now. Nothing to count and nothing
			// to remove; the next run sees the container as it then is.
			return m, fmt.Errorf("%w: %s is no longer in the container", errIncomplete, name)
		}
		return m, fmt.Errorf("%s could not be read back from the service, so this run cannot tell whether it is a complete backup: %w", name, err)
	}
	if props.Owner != deploymentID {
		return m, fmt.Errorf("%w: %s is marked %q, not %q; it is neither counted as one of this deployment's backups nor removed",
			ErrNotOwned, name, props.Owner, deploymentID)
	}

	if err := c.readManifestBlob(ctx, d, name+backup.ManifestSuffix, &m); err != nil {
		if NotFound(err) {
			return m, fmt.Errorf("%w: %s has no completion manifest, so it is what an upload that did not finish leaves behind; it was left in place and is not one of the retained backups", errIncomplete, name)
		}
		var se *Error
		if errors.As(err, &se) {
			return m, fmt.Errorf("the completion manifest for %s could not be read, so this run cannot tell whether it is a complete backup: %w", name, err)
		}
		// Not a service failure: the manifest is there and does not decode.
		return m, fmt.Errorf("%w: %s: %v", errIncomplete, name, err)
	}

	base := name[strings.LastIndexByte(name, '/')+1:]
	switch {
	case m.ManifestVersion != backup.ManifestVersion:
		return m, fmt.Errorf("%w: %s carries manifest version %d, which this tool does not understand (supported: %d)", errIncomplete, name, m.ManifestVersion, backup.ManifestVersion)
	case m.DeploymentID != deploymentID:
		return m, fmt.Errorf("%w: the completion manifest for %s names deployment %q, not %q; it is neither counted nor removed",
			ErrNotOwned, name, m.DeploymentID, deploymentID)
	case m.File != base:
		return m, fmt.Errorf("%w: %s carries a completion manifest for %q", errIncomplete, name, m.File)
	case m.SHA256 == "":
		return m, fmt.Errorf("%w: the completion manifest for %s records no content hash", errIncomplete, name)
	case m.Bytes != props.Bytes:
		return m, fmt.Errorf("%w: %s is %d bytes in the container but its completion manifest records %d", errIncomplete, name, props.Bytes, m.Bytes)
	case props.ContentSHA256 != "" && props.ContentSHA256 != m.SHA256:
		return m, fmt.Errorf("%w: %s does not match the SHA-256 in its completion manifest", errIncomplete, name)
	case m.PublishedAt.IsZero():
		// Without it there is no way to say which backups are the newest, and
		// guessing an order is how the wrong one gets deleted.
		return m, fmt.Errorf("%w: the completion manifest for %s records no publication time, so it cannot be placed in order", errIncomplete, name)
	}
	return m, nil
}

// Summary renders one remote backup retention run for an operator.
func (r PruneReport) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Azure database backup retention: keep the last %d successful backups (removed %d, kept %d)\n",
		r.Keep, len(r.Removed), r.Kept)
	if r.Withheld != "" {
		fmt.Fprintf(&b, "Nothing removed:      %s\n", r.Withheld)
	}
	for _, n := range r.NotOwned {
		fmt.Fprintf(&b, "Left in place:        %s does not carry this deployment's marker\n", n)
	}
	for _, f := range r.Failed {
		fmt.Fprintf(&b, "Not counted:          %s: %s\n", f.Name, firstLine(f.Reason))
	}
	b.WriteString("Only a verified complete backup counts towards the retained backups, so a failed\nupload never removes a good one. Recordings expire by age under their own rule.\n")
	return b.String()
}
