package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const challengeName = "_acme-challenge." + host

// solver builds a DNS01 whose visibility wait is driven by lookup rather
// than by DNS.
func (f *fake) solver(lookup func(context.Context, string) ([]string, error)) *DNS01 {
	return &DNS01{P: f.prov(), LookupTXT: lookup, Timeout: 50 * time.Millisecond, Interval: time.Millisecond}
}

func TestPresentCreatesMarkedChallengeRecordAndWaitsForIt(t *testing.T) {
	f := newFake(t)
	f.mux["POST /zones/zone1/dns_records"] = ok(map[string]any{"id": "txt1"})

	// The record is invisible on the first lookup and visible on the second,
	// so the wait has to actually poll.
	calls := 0
	d := f.solver(func(context.Context, string) ([]string, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return []string{"other-record", "challenge-value"}, nil
	})

	if err := d.Present(context.Background(), "challenge-value"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if calls < 2 {
		t.Errorf("Present did not wait for the record to resolve (%d lookups)", calls)
	}

	var got DNSPlan
	if err := json.Unmarshal(f.lastBody["POST /zones/zone1/dns_records"], &got); err != nil {
		t.Fatal(err)
	}
	want := DNSPlan{Type: "TXT", Name: challengeName, Content: "challenge-value", TTL: 60, Comment: wantMarker}
	if got != want {
		t.Errorf("created record = %+v, want %+v", got, want)
	}
	if got.Proxied {
		t.Error("the challenge record must not be proxied")
	}
}

func TestPresentFailsWhenTheRecordNeverResolves(t *testing.T) {
	f := newFake(t)
	f.mux["POST /zones/zone1/dns_records"] = ok(map[string]any{"id": "txt1"})
	d := f.solver(func(context.Context, string) ([]string, error) { return []string{"something-else"}, nil })

	err := d.Present(context.Background(), "challenge-value")
	if err == nil {
		t.Fatal("Present accepted a record that never resolved")
	}
	if !strings.Contains(err.Error(), challengeName) {
		t.Errorf("error does not name the record: %v", err)
	}
	noSecret(t, err)
}

// listTXT serves the challenge-name listing.
func (f *fake) listTXT(records ...map[string]any) {
	f.mux["GET /zones/zone1/dns_records"] = func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != challengeName {
			t := f.t
			t.Errorf("listed name = %q, want %q", got, challengeName)
		}
		ok(records)(w, r)
	}
}

func TestCleanUpDeletesOnlyMarkedChallengeRecords(t *testing.T) {
	f := newFake(t)
	mine := map[string]any{"id": "mine", "type": "TXT", "name": challengeName, "comment": wantMarker}
	theirs := map[string]any{"id": "theirs", "type": "TXT", "name": challengeName, "comment": "someone else's ACME client"}
	f.listTXT(mine, theirs)
	f.mux["GET /zones/zone1/dns_records/mine"] = ok(mine)
	f.mux["DELETE /zones/zone1/dns_records/mine"] = ok(map[string]any{"id": "mine"})
	// No handler for "theirs": the fake fails the test if it is requested at
	// all, so an unmarked record is not even re-fetched, let alone deleted.

	d := f.solver(nil)
	if err := d.CleanUp(context.Background()); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if f.hits["DELETE /zones/zone1/dns_records/mine"] != 1 {
		t.Error("CleanUp did not delete this deployment's challenge record")
	}
}

func TestCleanUpRefusesARecordThatLostItsMarker(t *testing.T) {
	f := newFake(t)
	// The listing claims the marker, the authoritative re-fetch does not:
	// DeleteRecord must refuse rather than trust the listing.
	f.listTXT(map[string]any{"id": "drift", "type": "TXT", "name": challengeName, "comment": wantMarker})
	f.mux["GET /zones/zone1/dns_records/drift"] = ok(map[string]any{
		"id": "drift", "type": "TXT", "name": challengeName, "comment": "guacdeploy:some-other-deployment"})

	err := f.solver(nil).CleanUp(context.Background())
	if !errors.Is(err, ErrNotOwned) {
		t.Fatalf("CleanUp error = %v, want ErrNotOwned", err)
	}
	if f.hits["DELETE /zones/zone1/dns_records/drift"] != 0 {
		t.Error("CleanUp deleted a record that does not carry this deployment's marker")
	}
}

func TestCleanUpWithNothingToRemoveSucceeds(t *testing.T) {
	f := newFake(t)
	f.listTXT()
	if err := f.solver(nil).CleanUp(context.Background()); err != nil {
		t.Fatalf("CleanUp on an empty name: %v", err)
	}
}
