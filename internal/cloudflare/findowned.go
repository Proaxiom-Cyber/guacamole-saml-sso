package cloudflare

import (
	"context"
	"net/url"
	"strings"
)

// OwnedResource is one resource at Cloudflare that matches this deployment's
// naming. Ours reports whether the ownership marker proves it is this
// deployment's; a name match alone never does, which is why the two are
// separate fields rather than a filtered list.
type OwnedResource struct {
	Type      string // "tunnel", "dns-record", "access-application"
	ID, Name  string
	Ours      bool
	Ownership string // the evidence, for the deployment record
}

// FindOwned lists the resources at Cloudflare that this deployment's naming
// could refer to, each with whether its ownership marker proves it ours.
//
// It only reads. Teardown calls it to reconcile a phase that failed before
// it could record what it created: the resource exists, nothing in the
// deployment record mentions it, and without this the teardown would report
// completeness while it was still there.
//
// Every marker test here is the one this package's own Apply and Delete
// paths already use — the tunnel name, the DNS record comment, and the
// Access application name together with the hostname-coverage check — so a
// resource judged ours here is judged ours identically at deletion time.
// The Access policy is not listed: it is removed with its application and is
// never deleted separately.
func (p *Provisioner) FindOwned(ctx context.Context) ([]OwnedResource, error) {
	var out []OwnedResource

	var tunnels []Tunnel
	path := "/accounts/" + p.AccountID + "/cfd_tunnel?is_deleted=false&per_page=50&include_prefix=" +
		url.QueryEscape(p.tunnelPrefix())
	if err := p.Client.do(ctx, "GET", path, nil, &tunnels); err != nil {
		return nil, err
	}
	for _, t := range tunnels {
		out = append(out, OwnedResource{Type: "tunnel", ID: t.ID, Name: t.Name,
			Ours:      t.Name == p.TunnelName(),
			Ownership: "deployment ID embedded in the tunnel name"})
	}

	var records []Record
	if err := p.Client.do(ctx, "GET", "/zones/"+p.ZoneID+"/dns_records?per_page=50&name="+
		url.QueryEscape(p.Hostname), nil, &records); err != nil {
		return out, err
	}
	for _, r := range records {
		out = append(out, OwnedResource{Type: "dns-record", ID: r.ID, Name: r.Name,
			Ours:      r.Comment == p.marker(),
			Ownership: "record comment carries this deployment's marker"})
	}

	apps, err := p.Client.listAccessApps(ctx, p.AccountID, "")
	if err != nil {
		return out, err
	}
	for _, a := range apps {
		if !strings.HasPrefix(a.Name, p.accessNamePrefix()) && !p.covers(a) {
			continue // nothing to do with this deployment's hostname
		}
		out = append(out, OwnedResource{Type: "access-application", ID: a.ID, Name: a.Name,
			Ours:      a.Name == p.AccessAppName() && p.covers(a),
			Ownership: "deployment ID in the application name, verified against the hostname"})
	}
	return out, nil
}
