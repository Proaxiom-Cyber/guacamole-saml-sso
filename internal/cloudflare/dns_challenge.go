package cloudflare

// ACME DNS-01 challenge records.
//
// Issuing the origin certificate (issue #9) proves control of the deployment
// hostname by publishing a TXT record at _acme-challenge.<hostname>. The
// record is created with the same ownership marker as every other DNS record
// this package writes — the comment "guacdeploy:<deployment-id>" — and it is
// removed through the same marker-verified DeleteRecord. A record this
// deployment did not create is never touched, on any path.
//
// A stale challenge record is not litter, it is a standing authorisation to
// issue a certificate for this hostname, so cleanup runs on failure as well
// as on success. The caller (internal/certs) defers it before the record is
// created, so even a failed creation or a failed visibility wait is cleaned
// up.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// Challenge record defaults.
const (
	// DefaultChallengeTimeout bounds the wait for the new record to become
	// visible. Cloudflare publishes in seconds; two minutes is slack, not an
	// expectation.
	DefaultChallengeTimeout = 2 * time.Minute
	// DefaultChallengeInterval is the visibility poll interval.
	DefaultChallengeInterval = 5 * time.Second
	// challengeTTL is the shortest TTL Cloudflare accepts for an
	// unproxied record. The record lives for one validation only.
	challengeTTL = 60
)

// DNS01 presents and removes the ACME DNS-01 challenge record for one
// deployment hostname. It satisfies the solver interface internal/certs
// expects, so that package needs no Cloudflare import.
type DNS01 struct {
	P *Provisioner

	// LookupTXT resolves TXT records; nil means this host's resolver. It is
	// a field so tests can drive the visibility wait without DNS.
	LookupTXT func(ctx context.Context, name string) ([]string, error)

	// Timeout and Interval bound the visibility wait; zero means the
	// DefaultChallenge… values above.
	Timeout  time.Duration
	Interval time.Duration
}

// Name is the challenge record name, _acme-challenge.<hostname>.
func (d *DNS01) Name() string { return "_acme-challenge." + d.P.Hostname }

// Present creates the challenge TXT record carrying value and waits until
// this host can resolve it.
//
// It creates rather than reconciles. A foreign _acme-challenge record at the
// same name is left in place beside ours: DNS-01 validation accepts the
// hostname when any TXT record at the name matches, so another ACME client's
// record neither blocks this one nor becomes ours to delete.
func (d *DNS01) Present(ctx context.Context, value string) error {
	plan := DNSPlan{
		Type:    "TXT",
		Name:    d.Name(),
		Content: value,
		TTL:     challengeTTL,
		Comment: d.P.marker(),
	}
	var r Record
	if err := d.P.Client.do(ctx, "POST", "/zones/"+d.P.ZoneID+"/dns_records", plan, &r); err != nil {
		return fmt.Errorf("create the DNS-01 challenge record %s: %w", d.Name(), err)
	}
	return d.waitVisible(ctx, value)
}

// waitVisible polls until the challenge value resolves. A timeout fails the
// issuance rather than asking the CA to validate a record nothing can see: a
// failed validation is charged against Let's Encrypt's failed-validation
// rate limit, an unattempted one is not.
func (d *DNS01) waitVisible(ctx context.Context, value string) error {
	lookup := d.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	timeout, interval := d.Timeout, d.Interval
	if timeout == 0 {
		timeout = DefaultChallengeTimeout
	}
	if interval == 0 {
		interval = DefaultChallengeInterval
	}
	deadline := time.Now().Add(timeout)
	var last string
	for {
		vals, err := lookup(ctx, d.Name())
		if err != nil {
			last = err.Error()
		} else {
			last = fmt.Sprintf("%q", vals)
			for _, v := range vals {
				if v == value {
					return nil
				}
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("the DNS-01 challenge record %s was created but did not resolve on this host within %s (last answer: %s)",
				d.Name(), timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// CleanUp removes every TXT record at the challenge name that carries this
// deployment's ownership marker, and leaves every other record exactly where
// it is. Each delete goes through DeleteRecord, which re-fetches the record
// and refuses with ErrNotOwned unless the marker is still present, so an
// unmarked record cannot be removed even if the listing were wrong.
//
// Missing records are not an error, so cleanup is repeatable.
func (d *DNS01) CleanUp(ctx context.Context) error {
	var existing []Record
	path := "/zones/" + d.P.ZoneID + "/dns_records?per_page=50&type=TXT&name=" + url.QueryEscape(d.Name())
	if err := d.P.Client.do(ctx, "GET", path, nil, &existing); err != nil {
		return fmt.Errorf("list the DNS-01 challenge records at %s: %w", d.Name(), err)
	}
	var errs []error
	for _, r := range existing {
		if r.Comment != d.P.marker() {
			continue // someone else's record: never ours to delete
		}
		if err := d.P.DeleteRecord(ctx, r.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
