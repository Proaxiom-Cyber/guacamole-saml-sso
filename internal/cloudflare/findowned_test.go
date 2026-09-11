package cloudflare

import (
	"context"
	"testing"
)

// TestFindOwnedSeparatesOursFromMerelyNamed pins the rule that makes this
// lookup safe to hand to teardown: a name match alone never establishes
// ownership. A tunnel or record belonging to another deployment, or to
// somebody else entirely, must come back listed but not ours, so teardown
// reports it for review instead of deleting it.
func TestFindOwnedSeparatesOursFromMerelyNamed(t *testing.T) {
	f := newFake(t)
	p := f.prov()

	f.mux["GET /accounts/acct1/cfd_tunnel"] = ok([]any{
		map[string]any{"id": "t-ours", "name": p.TunnelName()},
		map[string]any{"id": "t-other", "name": p.tunnelPrefix() + "someone-elses-deployment"},
	})
	f.mux["GET /zones/zone1/dns_records"] = ok([]any{
		map[string]any{"id": "r-ours", "name": p.Hostname, "comment": p.marker()},
		map[string]any{"id": "r-foreign", "name": p.Hostname, "comment": "set up by hand"},
	})
	f.mux["GET /accounts/acct1/access/apps"] = ok([]any{
		map[string]any{"id": "a-ours", "name": p.AccessAppName(), "domain": p.Hostname},
		map[string]any{"id": "a-other", "name": p.accessNamePrefix() + "another)", "domain": p.Hostname},
	})

	found, err := p.FindOwned(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ours, named := map[string]bool{}, map[string]bool{}
	for _, r := range found {
		named[r.ID] = true
		if r.Ours {
			ours[r.ID] = true
		}
	}
	for _, id := range []string{"t-ours", "r-ours", "a-ours"} {
		if !ours[id] {
			t.Errorf("%s carries this deployment's marker but was not judged ours", id)
		}
	}
	for _, id := range []string{"t-other", "r-foreign", "a-other"} {
		if !named[id] {
			t.Errorf("%s was not listed at all, so teardown could not report it for review", id)
		}
		if ours[id] {
			t.Errorf("%s matches only by name and must never be judged ours", id)
		}
	}
}
