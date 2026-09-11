package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
)

// ExpireOptions configures one remote recording retention run.
//
// "Ask the administrator how many days to retain recordings in Azure.
// Automatically remove only this deployment's recordings after the selected
// period. Do not apply this rule to unrelated objects or database backups"
// (specification, "Remote recording retention").
type ExpireOptions struct {
	Destination  Destination
	DeploymentID string

	// Days is the retention period the administrator chose. A recording is
	// removed once its copy in the container is older than this. Below one
	// day the run is refused rather than treated as "expire everything".
	Days int

	// Now supplies the run timestamp; nil means time.Now.
	Now func() time.Time
}

func (o ExpireOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// ExpireReport is the result of one remote retention run. Every recording the
// run looked at ends in exactly one of Removed, Kept, NotOwned or Failed, so
// the four counts account for the whole of the recordings area.
type ExpireReport struct {
	Ran    time.Time `json:"ran"`
	Days   int       `json:"days"`
	Cutoff time.Time `json:"cutoff"`
	// Prefix is the only path this run can reach: this deployment's
	// recordings area. Database backups live under a sibling prefix and are
	// never listed, so the recording rule cannot reach them.
	Prefix string `json:"prefix"`

	// Removed is every recording blob deleted, with its completion manifest.
	Removed []string `json:"removed,omitempty"`
	// Kept counts the recordings still inside the retention period.
	Kept int `json:"kept"`
	// NotOwned is every object past the period whose ownership marker is
	// missing or names another deployment. It is left in place.
	NotOwned []string `json:"not_owned,omitempty"`
	// Failed is every recording past the period that could not be removed,
	// including one whose age the service did not report. It is left in place.
	Failed []Failure `json:"failed,omitempty"`

	Error string `json:"error,omitempty"`
}

// Expire removes this deployment's Azure recording copies that are older than
// the selected retention period, and nothing else.
//
// # What it can reach
//
// Only `guacdeploy/<deployment-id>/recordings/`. The listing is taken under
// that prefix, so a database backup is not merely skipped, it is never seen:
// database backups keep their own separate retention of the last seven
// successful backups, and the recording age rule is not applied to them
// (specification). Every deletion then goes through DeleteOwnedBlob, which
// refuses a name outside this deployment's prefix and reads the
// guacdeploy_deployment marker back from the service before deleting. An
// object whose marker is missing or names someone else is left in place and
// reported, never deleted.
//
// # What it cannot reach
//
// There is no container or storage account deletion path in this package and
// there will not be one: "Preserve remote backups and their supporting storage
// resources during ordinary teardown" (specification).
// TestNoContainerOrAccountDeletionPathExists holds the package to that, and
// this function adds no new DELETE — it calls the one that already exists.
//
// # Age
//
// Age is the service's own Last-Modified on the copy in the container, so it
// is how long the recording has been in Azure rather than when the session
// happened. A copy exactly at the boundary is kept: only a copy strictly older
// than the cutoff is removed.
func Expire(ctx context.Context, c *Client, o ExpireOptions) (ExpireReport, error) {
	rep := ExpireReport{Ran: o.now().UTC(), Days: o.Days}
	if o.DeploymentID == "" {
		return rep, fmt.Errorf("expiring recordings needs the deployment ID to prove which objects are this deployment's own; nothing was expired")
	}
	if !o.Destination.Configured() {
		return rep, fmt.Errorf("no Azure destination is configured; nothing was expired")
	}
	if o.Days < 1 {
		return rep, fmt.Errorf("a remote recording retention period of at least one day is required, got %d; nothing was expired", o.Days)
	}
	rep.Prefix = o.Destination.Prefix(o.DeploymentID) + AreaRecordings + "/"
	rep.Cutoff = rep.Ran.AddDate(0, 0, -o.Days)

	blobs, err := c.listAll(ctx, o.Destination, rep.Prefix)
	if err != nil {
		rep.Error = err.Error()
		return rep, fmt.Errorf("the recordings in %s could not be listed, so nothing was expired: %w", rep.Prefix, err)
	}

	var firstErr error
	note := func(name string, err error) {
		rep.Failed = append(rep.Failed, Failure{Name: name, Reason: err.Error()})
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, b := range blobs {
		// A completion manifest is removed with the recording it describes,
		// never on its own: on its own it would leave a blob that no longer
		// counts as a complete copy but still occupies the container.
		if strings.HasSuffix(b.Name, backup.ManifestSuffix) {
			continue
		}
		// Defence in depth. The listing is already scoped to the recordings
		// prefix, so this cannot fire; it exists so that a future change to
		// the listing cannot quietly widen what expiry deletes.
		if !strings.HasPrefix(b.Name, rep.Prefix) {
			continue
		}
		at, err := time.Parse(http.TimeFormat, b.LastModified)
		if err != nil {
			// An age that cannot be read is not an expired recording. Leaving
			// it is the safe direction: the alternative is deleting a
			// recording whose age nothing established.
			note(b.Name, fmt.Errorf("%s has no readable Last-Modified (%q), so its age is unknown and it was left in place", b.Name, b.LastModified))
			continue
		}
		if !at.UTC().Before(rep.Cutoff) {
			rep.Kept++
			continue
		}

		// The completion manifest goes first. Between the two deletions the
		// recording no longer counts as a complete remote copy, which is the
		// honest order: the reverse would leave a manifest describing a blob
		// that is already gone. A manifest that is not there — an orphan left
		// by an upload that failed after the blob but before the manifest — is
		// not an error, and this is what eventually clears that orphan.
		if err := c.DeleteOwnedBlob(ctx, o.Destination, b.Name+backup.ManifestSuffix, o.DeploymentID); err != nil && !NotFound(err) {
			if errors.Is(err, ErrNotOwned) {
				rep.NotOwned = append(rep.NotOwned, b.Name)
				continue
			}
			note(b.Name, fmt.Errorf("the completion manifest for %s could not be removed, so the recording was left in place: %w", b.Name, err))
			continue
		}
		if err := c.DeleteOwnedBlob(ctx, o.Destination, b.Name, o.DeploymentID); err != nil {
			if errors.Is(err, ErrNotOwned) {
				rep.NotOwned = append(rep.NotOwned, b.Name)
				continue
			}
			note(b.Name, fmt.Errorf("expiring %s failed: %w", b.Name, err))
			continue
		}
		rep.Removed = append(rep.Removed, b.Name)
	}

	if firstErr != nil {
		err := fmt.Errorf("%d of this deployment's expired recordings could not be removed and were left in place; first failure: %w", len(rep.Failed), firstErr)
		rep.Error = err.Error()
		return rep, err
	}
	return rep, nil
}

// Summary renders one retention run for an operator.
func (r ExpireReport) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Azure recording retention: %d days (removed %d, kept %d)\n", r.Days, len(r.Removed), r.Kept)
	for _, n := range r.NotOwned {
		fmt.Fprintf(&b, "Left in place:        %s is past the retention period but does not carry this deployment's marker\n", n)
	}
	for _, f := range r.Failed {
		fmt.Fprintf(&b, "Expiry failed:        %s: %s\n", f.Name, firstLine(f.Reason))
	}
	b.WriteString("Database backups keep their own separate retention and are never expired by age.\n")
	return b.String()
}
