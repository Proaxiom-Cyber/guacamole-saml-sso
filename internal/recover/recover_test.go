package recover

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"
)

const (
	depID    = "0123456789abcdef0123456789abcdef"
	guacVer  = "1.5.5"
	hostname = "guac.example.com"
)

// --- fixtures -----------------------------------------------------------

// lostHost is the deployment record the lost host would have snapshotted
// into its last backup.
func lostHost() *state.State {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &state.State{
		SchemaVersion: state.SchemaVersion,
		DeploymentID:  depID,
		CreatedAt:     created,
		Config: map[string]string{
			"guac-hostname":          hostname,
			"credential-mode":        creds.ModeTPM,
			"cloudflare-tunnel-id":   "tun-old",
			"cloudflare-zone-id":     "zone-1",
			"entra-tenant-id":        "tenant-1",
			"backup-dest":            "/var/backups/guacdeploy",
			"backup-public-key":      "age1qqqq",
			"azure-account":          "recstore",
			"azure-container":        "recordings",
			"saml-metadata-url":      "https://login.microsoftonline.com/tenant-1/federationmetadata.xml",
			"an-escaped-value":       `C:\path\to	thing`,
			"cloudflare-record-id":   "rec-1",
			"cloudflare-access-app":  "app-1",
			"entra-admin-group-name": "Guacamole Admins",
		},
		Resources: []state.Resource{
			{ID: "r1", Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-old",
				Name: "guacdeploy-" + hostname + "-" + depID, Ownership: "created by this deployment", CreatedAt: created},
			{ID: "r2", Provider: "cloudflare", Type: "dns-record", ProviderID: "rec-1",
				Name: hostname, Ownership: "created by this deployment; marker in the record comment", CreatedAt: created},
			{ID: "r3", Provider: "cloudflare", Type: "access-application", ProviderID: "app-1",
				Name: "Guacamole " + hostname + " (guacdeploy:" + depID + ")", Ownership: "created by this deployment", CreatedAt: created},
			{ID: "r4", Provider: "cloudflare", Type: "access-policy", ProviderID: "pol-1",
				Name: "guacdeploy:" + depID, Ownership: "scoped to the Access application", CreatedAt: created},
			{ID: "r5", Provider: "entra", Type: "application", ProviderID: "eapp-1",
				Name: "Guacamole " + hostname, Ownership: "created by this deployment; marker in notes and tags", CreatedAt: created},
			{ID: "r6", Provider: "entra", Type: "service-principal", ProviderID: "esp-1",
				Name: "Guacamole " + hostname, Ownership: "created with its application", CreatedAt: created},
			{ID: "r7", Provider: "entra", Type: "group", ProviderID: "grp-1",
				Name: "Guacamole Admins", Ownership: "created by this deployment; marker in description", CreatedAt: created},
			{ID: "r8", Provider: "host", Type: "config-directory", Name: "/opt/guacamole",
				Ownership: "rendered by this deployment", CreatedAt: created},
			{ID: "r9", Provider: "docker", Type: "container", Name: "guacamole",
				Ownership: "started by this deployment", CreatedAt: created},
		},
		Changes: []state.SettingChange{{
			ID: "c1", Provider: "entra", Target: "application/eapp-1/notes",
			Original: json.RawMessage(`null`), Applied: json.RawMessage(`"guacdeploy:` + depID + `"`),
		}},
		Actions: []state.Action{{
			// A real phase intent, one internal/teardown's creators map knows
			// creates at Cloudflare. Deliberately unfinished: the host died
			// mid-flight, so what it created is unknown until Cloudflare is
			// asked.
			ID: "a1", Intent: "cloudflare-tunnel", StartedAt: created,
			Detail: "will create in Cloudflare: tunnel, ingress configuration",
		}},
	}
}

// lostHostMidEntra is the failure that actually bit us in the lab: the Entra
// phase created an application, its service principal and a group, then
// failed before a single resource ID reached the record. Nothing in
// st.Resources mentions any of them, and only the journal says they may
// exist.
func lostHostMidEntra() *state.State {
	st := lostHost()
	var kept []state.Resource
	for _, r := range st.Resources {
		if r.Provider != "entra" {
			kept = append(kept, r)
		}
	}
	st.Resources = kept
	st.Actions = []state.Action{{
		ID: "a2", Intent: "entra-signin", StartedAt: st.CreatedAt,
		Detail: "will create in Entra: application, service principal, groups",
	}}
	return st
}

// entraOrphans is what a marker sweep finds after that failure.
func entraOrphans() teardown.Found {
	return teardown.Found{Owned: []state.Resource{
		{Provider: "entra", Type: "application", ProviderID: "eapp-1", Name: "Guacamole " + hostname,
			Ownership: "marker " + Marker(depID) + " in the application notes and tags"},
		{Provider: "entra", Type: "service-principal", ProviderID: "esp-1", Name: "Guacamole " + hostname,
			Ownership: "service principal of the marked application"},
		{Provider: "entra", Type: "group", ProviderID: "grp-1", Name: "Guacamole Admins",
			Ownership: "marker " + Marker(depID) + " in the group description"},
	}}
}

// escapeCopy spells one value the way pg_dump writes a COPY text field.
func escapeCopy(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}

type metaRow struct {
	id      int
	schema  int
	takenAt string
	st      *state.State
}

// dumpWith builds a plain-format pg_dump body carrying the metadata table,
// exactly as internal/backup's snapshot then pg_dump would produce it.
func dumpWith(t *testing.T, rows []metaRow, copyHeader string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n\n")
	b.WriteString("CREATE TABLE public.guacamole_connection (connection_id integer NOT NULL);\n\n")
	if copyHeader == "" {
		copyHeader = "COPY public." + MetadataTable + " (id, schema_version, taken_at, state) FROM stdin;"
	}
	b.WriteString(copyHeader + "\n")
	for _, r := range rows {
		raw, err := json.Marshal(r.st)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%d\t%d\t%s\t%s\n", r.id, r.schema, r.takenAt, escapeCopy(string(raw)))
	}
	b.WriteString("\\.\n\n\n--\n-- PostgreSQL database dump complete\n--\n")
	return b.String()
}

type backupOpts struct {
	format     int
	guac       string
	rows       []metaRow
	copyHeader string
	noMetadata bool
	encryptTo  string // age recipient; "" writes plaintext
	truncate   bool
}

// writeBackup produces a file in the exact shape internal/backup publishes.
func writeBackup(t *testing.T, dir string, o backupOpts) string {
	t.Helper()
	if o.format == 0 {
		o.format = 1
	}
	if o.guac == "" {
		o.guac = guacVer
	}
	if o.rows == nil && !o.noMetadata {
		o.rows = []metaRow{{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03.456789+00", st: lostHost()}}
	}
	mode := "none"
	if o.encryptTo != "" {
		mode = "age"
	}
	dump := "--\n-- PostgreSQL database dump\n--\n\nSET statement_timeout = 0;\n"
	if !o.noMetadata {
		dump = dumpWith(t, o.rows, o.copyHeader)
	}
	body := fmt.Sprintf("-- guacdeploy backup format=%d guacamole=%s mode=%s\n", o.format, o.guac, mode) + dump
	content := body + fmt.Sprintf("-- guacdeploy dump complete sha256:%x\n", sha256.Sum256([]byte(body)))
	if o.truncate {
		content = body // no completion marker
	}

	path := filepath.Join(dir, "guacdeploy-db-20260910T010203.000Z.sql")
	if o.encryptTo != "" {
		path += ".age"
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := recoverykey.EncryptTo(o.encryptTo, strings.NewReader(content), f); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sweeper returns a teardown.Finder answering with one fixed result and
// counting its calls. It is the same seam teardown reconciliation uses: one
// marker query per provider, never per resource.
func sweeper(found teardown.Found, err error, calls *int) teardown.Finder {
	return func(context.Context) (teardown.Found, error) {
		if calls != nil {
			*calls++
		}
		return found, err
	}
}

// cloudflarePresent is everything the lost host recorded at Cloudflare,
// still there and marker-verified.
func cloudflarePresent() teardown.Found {
	return teardown.Found{Owned: []state.Resource{
		{Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-old",
			Name: "guacdeploy-" + hostname + "-" + depID, Ownership: "deployment ID embedded in the tunnel name"},
		{Provider: "cloudflare", Type: "dns-record", ProviderID: "rec-1", Name: hostname,
			Ownership: "record comment carries this deployment's marker"},
		{Provider: "cloudflare", Type: "access-application", ProviderID: "app-1",
			Name:      "Guacamole " + hostname + " (guacdeploy:" + depID + ")",
			Ownership: "deployment ID in the application name, verified against the hostname"},
	}}
}

// allPresent wires both providers to "everything is still there, and every
// ownership marker verifies".
func allPresent(calls *int) teardown.Finders {
	return teardown.Finders{
		"cloudflare": sweeper(cloudflarePresent(), nil, calls),
		"entra":      sweeper(entraOrphans(), nil, calls),
	}
}

// with returns a copy of f with one provider replaced.
func with(f teardown.Finders, provider string, one teardown.Finder) teardown.Finders {
	out := teardown.Finders{}
	for k, v := range f {
		out[k] = v
	}
	if one == nil {
		delete(out, provider)
	} else {
		out[provider] = one
	}
	return out
}

// without drops one resource from a provider's answer, so the sweep reports
// it as gone.
func without(found teardown.Found, typ string) teardown.Found {
	var out teardown.Found
	for _, r := range found.Owned {
		if r.Type != typ {
			out.Owned = append(out.Owned, r)
		}
	}
	out.Unowned = found.Unowned
	return out
}

func loadFrom(t *testing.T, path string) Loaded {
	t.Helper()
	l, err := Load(Source{BackupFile: path, GuacVersion: guacVer})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return l
}

func itemFor(t *testing.T, rep Report, key string) Item {
	t.Helper()
	for _, it := range rep.Items {
		if Key(it.Resource) == key {
			return it
		}
	}
	t.Fatalf("no item for %s", key)
	return Item{}
}

// --- the record travels inside the backup -------------------------------

func TestLoadRestoresTheEmbeddedRecord(t *testing.T) {
	dir := t.TempDir()
	l := loadFrom(t, writeBackup(t, dir, backupOpts{}))

	st := l.Snapshot.State
	if st.DeploymentID != depID {
		t.Errorf("deployment identity = %q, want %q", st.DeploymentID, depID)
	}
	if got := len(st.Resources); got != 9 {
		t.Errorf("resources = %d, want 9", got)
	}
	if st.Config["guac-hostname"] != hostname {
		t.Errorf("configuration reference lost: %q", st.Config["guac-hostname"])
	}
	if st.Resources[0].ProviderID != "tun-old" {
		t.Errorf("resource identifier lost: %q", st.Resources[0].ProviderID)
	}
	if st.Resources[0].Ownership == "" {
		t.Error("ownership evidence lost")
	}
	if len(st.Changes) != 1 || st.Changes[0].Target != "application/eapp-1/notes" {
		t.Errorf("recorded setting changes lost: %+v", st.Changes)
	}
	if want := `C:\path\to` + "\t" + `thing`; st.Config["an-escaped-value"] != want {
		t.Errorf("COPY escaping mangled a value: %q, want %q", st.Config["an-escaped-value"], want)
	}
	if l.Info.GuacVersion != guacVer || l.Info.Mode != "none" {
		t.Errorf("backup info = %+v", l.Info)
	}
	if want := time.Date(2026, 9, 10, 1, 2, 3, 456789000, time.UTC); !l.Snapshot.TakenAt.Equal(want) {
		t.Errorf("taken at = %v, want %v", l.Snapshot.TakenAt, want)
	}
}

func TestLoadTakesTheNewestSnapshotRow(t *testing.T) {
	older, newer := lostHost(), lostHost()
	older.Config["guac-hostname"] = "stale.example.com"
	newer.Config["guac-hostname"] = "current.example.com"
	// Written out of order on purpose: the serial id decides, not position.
	path := writeBackup(t, t.TempDir(), backupOpts{rows: []metaRow{
		{id: 7, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: newer},
		{id: 3, schema: state.SchemaVersion, takenAt: "2026-08-01 01:02:03+00", st: older},
	}})
	if got := loadFrom(t, path).Snapshot.State.Config["guac-hostname"]; got != "current.example.com" {
		t.Errorf("took snapshot %q, want the newest row", got)
	}
}

func TestBackupWithoutADeploymentRecord(t *testing.T) {
	for name, o := range map[string]backupOpts{
		"no metadata table": {noMetadata: true},
		"empty table":       {rows: []metaRow{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(Source{BackupFile: writeBackup(t, t.TempDir(), o), GuacVersion: guacVer})
			if !errors.Is(err, ErrNoRecord) {
				t.Fatalf("err = %v, want ErrNoRecord", err)
			}
		})
	}
}

// --- refused before anything is altered ---------------------------------

func TestIncompatibleBackupRefusedBeforeAnyChange(t *testing.T) {
	newerRecord := lostHost()
	newerRecord.SchemaVersion = state.SchemaVersion + 1

	cases := map[string]backupOpts{
		"newer backup format":     {format: 99},
		"other Guacamole version": {guac: "0.9.0"},
		"truncated dump":          {truncate: true},
		"newer record schema": {rows: []metaRow{
			{id: 1, schema: state.SchemaVersion + 1, takenAt: "2026-09-10 01:02:03+00", st: lostHost()}}},
		"newer schema inside the record": {rows: []metaRow{
			{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: newerRecord}}},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			_, err := Load(Source{BackupFile: writeBackup(t, t.TempDir(), o), GuacVersion: guacVer})
			if !errors.Is(err, ErrIncompatible) {
				t.Fatalf("err = %v, want ErrIncompatible", err)
			}
			// Nothing may have been asked of any provider, because Load
			// returned before a plan could exist.
			if calls != 0 {
				t.Errorf("%d provider call(s) made on a refused backup", calls)
			}
		})
	}
}

func TestRefusedBackupReachesNoProviderAndNoRecord(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	if _, err := Load(Source{BackupFile: writeBackup(t, dir, backupOpts{format: 99}), GuacVersion: guacVer}); err == nil {
		t.Fatal("a format-99 backup loaded")
	}
	store, err := state.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Error("a refused backup left a deployment record behind")
	}
	if calls != 0 {
		t.Error("a refused backup reached a provider")
	}
}

// --- the encrypted backup and its passphrase ----------------------------

func TestEncryptedBackupNeedsTheKeyExportAndPassphrase(t *testing.T) {
	dir := t.TempDir()
	id, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(dir, "key", "backup-key.age")
	const pass = "correct horse battery staple"
	if err := recoverykey.ExportEncrypted(id, pass, export); err != nil {
		t.Fatal(err)
	}
	file := writeBackup(t, dir, backupOpts{encryptTo: id.Recipient().String()})

	t.Run("no key at all", func(t *testing.T) {
		_, err := Load(Source{BackupFile: file, GuacVersion: guacVer})
		if !errors.Is(err, ErrKeyRequired) {
			t.Fatalf("err = %v, want ErrKeyRequired", err)
		}
	})
	t.Run("export but no passphrase", func(t *testing.T) {
		_, err := Load(Source{BackupFile: file, KeyExport: export, GuacVersion: guacVer})
		if !errors.Is(err, ErrKeyRequired) {
			t.Fatalf("err = %v, want ErrKeyRequired", err)
		}
		// The missing half is named, rather than reported as a failed
		// decryption the operator would go hunting for.
		if !strings.Contains(err.Error(), "no passphrase was supplied") {
			t.Errorf("error does not say the passphrase is missing: %v", err)
		}
	})
	t.Run("wrong passphrase says so plainly", func(t *testing.T) {
		_, err := Load(Source{BackupFile: file, KeyExport: export, Passphrase: "nearly right", GuacVersion: guacVer})
		if !errors.Is(err, ErrKeyRequired) {
			t.Fatalf("err = %v, want ErrKeyRequired", err)
		}
		if !strings.Contains(err.Error(), "wrong passphrase") {
			t.Errorf("error does not name the likely cause: %v", err)
		}
		if strings.Contains(err.Error(), pass) {
			t.Fatal("the passphrase is in the error text")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other, err := recoverykey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		_, err = Load(Source{BackupFile: file, Identity: other, GuacVersion: guacVer})
		if !errors.Is(err, ErrKeyRequired) {
			t.Fatalf("err = %v, want ErrKeyRequired", err)
		}
	})
	t.Run("right passphrase recovers the record", func(t *testing.T) {
		l, err := Load(Source{BackupFile: file, KeyExport: export, Passphrase: pass, GuacVersion: guacVer})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if l.Snapshot.State.DeploymentID != depID {
			t.Errorf("deployment identity = %q", l.Snapshot.State.DeploymentID)
		}
		if l.Info.Mode != "age" {
			t.Errorf("mode = %q, want age", l.Info.Mode)
		}
	})
}

// --- reconciliation -----------------------------------------------------

func TestMarkerMatchesBothProviders(t *testing.T) {
	if got, want := Marker(depID), entra.Marker(depID); got != want {
		t.Errorf("Marker = %q, entra.Marker = %q", got, want)
	}
	p := &cloudflare.Provisioner{DeploymentID: depID, Hostname: hostname}
	if got := p.PlanDNS("tun-1").Comment; got != Marker(depID) {
		t.Errorf("cloudflare DNS marker = %q, Marker = %q", got, Marker(depID))
	}
}

func TestReconcileAppliesTheMarkerRules(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	base := allPresent(nil)

	unowned := teardown.Found{Unowned: []state.Resource{
		{Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-x",
			Name: "guacdeploy-" + hostname + "-" + depID},
	}}

	cases := []struct {
		name  string
		found teardown.Found
		err   error
		want  Disposition
		says  string
	}{
		{"marker verified", cloudflarePresent(), nil, Adopt, "not created again"},
		{"gone", without(cloudflarePresent(), "tunnel"), nil, Recreate, "gone at the provider"},
		{"name matches, no marker", unowned, nil, Review, "name alone never establishes ownership"},
		{"provider could not be asked", teardown.Found{}, errors.New("429 rate limited"), Review, "Nothing is recreated"},
		{"no query wired", teardown.Found{}, nil, Review, "neither recreated nor removed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			one := sweeper(c.found, c.err, nil)
			if c.name == "no query wired" {
				one = nil
			}
			it := itemFor(t, Reconcile(context.Background(), l, with(base, "cloudflare", one)), "cloudflare/tunnel")
			if it.Disposition != c.want {
				t.Fatalf("disposition = %q, want %q (%s)", it.Disposition, c.want, it.Detail)
			}
			if !strings.Contains(it.Detail, c.says) {
				t.Errorf("detail does not say %q: %s", c.says, it.Detail)
			}
			if c.want == Recreate && it.ProviderID != "" {
				t.Errorf("a recreated resource kept the dead identifier %q", it.ProviderID)
			}
		})
	}
}

func TestRenamedResourceIsAdoptedNotRecreated(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	// Same tunnel, same identifier, renamed at the provider. The marker is
	// what proves ownership, so it must be recognised rather than recreated
	// beside itself.
	renamed := teardown.Found{Owned: []state.Resource{
		{Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-old",
			Name: "guacdeploy-renamed-by-hand", Ownership: "deployment ID embedded in the tunnel name"},
	}}
	it := itemFor(t, Reconcile(context.Background(), l, with(allPresent(nil), "cloudflare",
		sweeper(renamed, nil, nil))), "cloudflare/tunnel")
	if it.Disposition != Adopt {
		t.Fatalf("disposition = %q, want adopt; a renamed tunnel would be created twice", it.Disposition)
	}
	if it.ProviderID != "tun-old" {
		t.Errorf("adopted identifier = %q", it.ProviderID)
	}
}

func TestUnwiredProviderIsReviewedNotRecreated(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	it := itemFor(t, Reconcile(context.Background(), l, with(allPresent(nil), "entra", nil)), "entra/group")
	if it.Disposition != Review {
		t.Fatalf("disposition = %q, want review", it.Disposition)
	}
	if !strings.Contains(it.Detail, "neither recreated nor removed") {
		t.Errorf("detail = %s", it.Detail)
	}
}

func TestPresentResourcesAreNeverRecreated(t *testing.T) {
	calls := 0
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	rep := Reconcile(context.Background(), l, allPresent(&calls))

	if calls != 2 {
		t.Errorf("%d provider queries, want one marker sweep per provider (2)", calls)
	}
	if got := len(rep.Of(Recreate)); got != 0 {
		t.Fatalf("%d resource(s) would be created again while still present", got)
	}
	if got := len(rep.Of(Adopt)); got != 5 {
		t.Errorf("adopted %d, want 5", got)
	}
	if got := len(rep.Of(WithParent)); got != 2 {
		t.Errorf("with-parent %d, want 2 (the Access policy and the service principal)", got)
	}
	if got := len(rep.Of(Rebuild)); got != 2 {
		t.Errorf("host-local %d, want 2", got)
	}
	if err := rep.RequiresReview(); err != nil {
		t.Errorf("a fully marker-verified deployment needs review: %v", err)
	}

	st, err := Restore(l, rep, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range st.Pending() {
		if strings.HasPrefix(a.Intent, "recover:recreate:") {
			t.Errorf("journalled an intent to create %q, which is still present", a.Intent)
		}
	}
}

func TestChildResourcesFollowTheirParent(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	rep := Reconcile(context.Background(), l, allPresent(nil))
	for _, key := range []string{"cloudflare/access-policy", "entra/service-principal"} {
		if it := itemFor(t, rep, key); it.Disposition != WithParent {
			t.Errorf("%s disposition = %q, want with-parent", key, it.Disposition)
		}
	}
}

func TestDNSRecordFollowsTheTunnelActuallyInUse(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))

	t.Run("tunnel recreated, record re-pointed not duplicated", func(t *testing.T) {
		rep := Reconcile(context.Background(), l, with(allPresent(nil), "cloudflare",
			sweeper(without(cloudflarePresent(), "tunnel"), nil, nil)))
		it := itemFor(t, rep, "cloudflare/dns-record")
		if it.Disposition != Adopt || !it.Retarget {
			t.Fatalf("record disposition = %q, retarget = %v; want adopt and re-point", it.Disposition, it.Retarget)
		}
		if got := len(rep.Of(Recreate)); got != 1 {
			t.Errorf("%d resources to create; only the tunnel should be", got)
		}
	})
	t.Run("tunnel adopted, record left alone", func(t *testing.T) {
		it := itemFor(t, Reconcile(context.Background(), l, allPresent(nil)), "cloudflare/dns-record")
		if it.Retarget {
			t.Error("re-pointed a record at a tunnel that never changed")
		}
	})
}

// --- the journal's unfinished creation intents --------------------------

// TestUnfinishedCloudIntentIsReconciledNotDropped is the lab failure: the
// Entra phase created an application, its service principal and a group,
// then failed before any of them reached the record. Only the journal knows
// they may exist. Dropping it recreates them.
func TestUnfinishedCloudIntentIsReconciledNotDropped(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{rows: []metaRow{
		{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: lostHostMidEntra()}}}))
	if got := len(l.Snapshot.State.Resources); got != 6 {
		t.Fatalf("fixture records %d resources; it must record no Entra resource at all", got)
	}

	rep := Reconcile(context.Background(), l, allPresent(nil))

	if len(rep.Obligations) != 1 || rep.Obligations[0].Intent != "entra-signin" {
		t.Fatalf("obligations = %+v, want the unfinished entra-signin phase", rep.Obligations)
	}
	if !rep.Obligations[0].Answered {
		t.Fatalf("the obligation is unanswered though Entra was asked: %s", rep.Obligations[0].Detail)
	}

	var recovered []string
	for _, it := range rep.Items {
		if it.Recovered {
			if it.Disposition != Adopt {
				t.Errorf("%s disposition = %q, want adopt", it, it.Disposition)
			}
			recovered = append(recovered, it.Resource.Type)
		}
	}
	want := []string{"application", "service-principal", "group"}
	if strings.Join(recovered, ",") != strings.Join(want, ",") {
		t.Fatalf("recovered %v, want %v: a phase that failed before saving left all three", recovered, want)
	}
	if got := len(rep.Of(Recreate)); got != 0 {
		t.Errorf("%d resource(s) would be created again beside the ones already in the tenant", got)
	}
	if err := rep.RequiresReview(); err != nil {
		t.Fatalf("an answered obligation stops the recovery: %v", err)
	}

	st, err := Restore(l, rep, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range want {
		var found bool
		for _, r := range st.Resources {
			if r.Provider == "entra" && r.Type == typ {
				found = true
				if r.ID == "" {
					t.Errorf("recovered %s has no record identifier", typ)
				}
				if r.Ownership == "" {
					t.Errorf("recovered %s has no ownership evidence", typ)
				}
			}
		}
		if !found {
			t.Errorf("recovered %s never reached the record; teardown would miss it", typ)
		}
	}

	// The evidence is carried forward, and it is not carried forward as work
	// that can never finish.
	var reconciled bool
	for _, a := range st.Actions {
		if a.Intent == "recover:reconciled:entra-signin" {
			reconciled = true
			if a.FinishedAt == nil || a.Result != state.ResultOK {
				t.Errorf("the reconciled intent is journalled unfinished: %+v", a)
			}
			if !strings.Contains(a.Detail, "entra") {
				t.Errorf("the reconciled intent does not say what was found: %s", a.Detail)
			}
		}
	}
	if !reconciled {
		t.Fatal("the unfinished entra-signin intent was dropped; the only evidence of the orphans is gone")
	}
	for _, a := range st.Pending() {
		if a.Intent == "entra-signin" {
			t.Error("the lost host's unfinished intent was carried over as pending; it could never resolve")
		}
	}
}

// TestUnqueryableProviderPreventsAnAllClear covers the intent that has no
// state.Resources entry at all: nothing in the resource list would ever ask
// about that provider, so only the journal can force the question, and an
// unanswerable provider must stop the recovery.
func TestUnqueryableProviderPreventsAnAllClear(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{rows: []metaRow{
		{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: lostHostMidEntra()}}}))

	for name, f := range map[string]teardown.Finders{
		"provider errors":   with(allPresent(nil), "entra", sweeper(teardown.Found{}, errors.New("no Graph token on this host"), nil)),
		"no query is wired": with(allPresent(nil), "entra", nil),
	} {
		t.Run(name, func(t *testing.T) {
			rep := Reconcile(context.Background(), l, f)

			// No Entra resource is in the record, so no item can raise the
			// alarm. Only the journal can, which is the whole point.
			if got := len(rep.Of(Review)); got != 0 {
				t.Fatalf("%d review item(s); this case must be carried by the journal alone", got)
			}

			un := rep.Unanswered()
			if len(un) != 1 || un[0].Intent != "entra-signin" {
				t.Fatalf("unanswered = %+v, want the entra-signin phase", un)
			}
			if !strings.Contains(un[0].Detail, Marker(depID)) {
				t.Errorf("the operator is not told what to look for: %s", un[0].Detail)
			}

			err := rep.RequiresReview()
			if !errors.Is(err, ErrReviewRequired) {
				t.Fatalf("RequiresReview = %v; an unreachable provider passed as an all-clear", err)
			}
			if !strings.Contains(err.Error(), "entra-signin") {
				t.Errorf("the error does not name the unchecked intent: %v", err)
			}
			if got := len(rep.Of(Recreate)); got != 0 {
				t.Errorf("%d resource(s) would be created on an unanswered question", got)
			}
			if _, err := Restore(l, rep, time.Now()); !errors.Is(err, ErrReviewRequired) {
				t.Fatalf("Restore = %v, want ErrReviewRequired", err)
			}
		})
	}
}

// TestPartialAnswerIsNotTreatedAsAnAnswer covers the shape
// cloudflare.FindOwned really returns: some resources listed, then an error
// on a later call. Half a sweep proves nothing about the half that failed,
// so nothing is adopted from it and the recovery still stops.
func TestPartialAnswerIsNotTreatedAsAnAnswer(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{rows: []metaRow{
		{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: lostHostMidEntra()}}}))
	partial := sweeper(entraOrphans(), errors.New("HTTP 503 on the second page"), nil)
	rep := Reconcile(context.Background(), l, with(allPresent(nil), "entra", partial))

	for _, it := range rep.Items {
		if it.Recovered {
			t.Errorf("adopted %s out of a query that failed partway", it)
		}
	}
	if len(rep.Unanswered()) != 1 {
		t.Fatalf("unanswered = %+v, want the entra-signin phase", rep.Unanswered())
	}
	if err := rep.RequiresReview(); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("RequiresReview = %v, want ErrReviewRequired", err)
	}
}

func TestNameOnlyOrphanIsNeitherAdoptedNorRecreated(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{rows: []metaRow{
		{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: lostHostMidEntra()}}}))
	strangers := teardown.Found{Unowned: []state.Resource{
		{Provider: "entra", Type: "application", ProviderID: "eapp-9", Name: "Guacamole " + hostname},
	}}
	rep := Reconcile(context.Background(), l, with(allPresent(nil), "entra", sweeper(strangers, nil, nil)))

	var seen int
	for _, it := range rep.Items {
		if it.Recovered {
			seen++
			if it.Disposition != Review {
				t.Errorf("a name-only match was classified %q", it.Disposition)
			}
			if !strings.Contains(it.Detail, "name alone never establishes ownership") {
				t.Errorf("detail = %s", it.Detail)
			}
		}
	}
	if seen != 1 {
		t.Fatalf("%d orphans reported, want 1", seen)
	}
	if err := rep.RequiresReview(); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("RequiresReview = %v; recovery would proceed onto a name something else holds", err)
	}
}

// --- what cannot travel -------------------------------------------------

func TestSealedCredentialIsReportedUnrecoverableNotRegenerated(t *testing.T) {
	for _, mode := range []string{creds.ModeTPM, creds.ModeHostKey} {
		t.Run(mode, func(t *testing.T) {
			st := lostHost()
			st.Config["credential-mode"] = mode
			rep := Report{Needs: needs(st)}

			var token Need
			for _, n := range rep.Needs {
				if n.Name == "cloudflare-api-token" {
					token = n
				}
			}
			if token.Name == "" {
				t.Fatal("the API token is not named at all")
			}
			if !token.Operator {
				t.Fatal("a sealed credential is treated as something recovery can obtain by itself")
			}
			if !strings.Contains(token.Why, "cannot be recovered") {
				t.Errorf("the report does not say plainly that it cannot be recovered: %s", token.Why)
			}
			if !strings.Contains(token.Why, creds.Describe(mode).ReplacementHost) {
				t.Errorf("the report drops the mode's own replacement-host explanation: %s", token.Why)
			}
			for _, n := range rep.Automatic() {
				if n.Name == "cloudflare-api-token" {
					t.Fatal("a sealed credential is listed as regenerated")
				}
			}
		})
	}
}

func TestGeneratedCredentialIsRegeneratedWithItsReason(t *testing.T) {
	rep := Report{Needs: needs(lostHost())}
	var pw Need
	for _, n := range rep.Automatic() {
		if n.Name == "postgres-password" {
			pw = n
		}
	}
	if pw.Name == "" {
		t.Fatal("the database password is not listed as regenerated")
	}
	if !strings.Contains(pw.Why, "carries no role password") {
		t.Errorf("no reason given for why a new value is safe: %s", pw.Why)
	}
}

func TestReportNamesExactlyWhatTheOperatorMustSupply(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	rep := Reconcile(context.Background(), l, allPresent(nil))

	var got []string
	for _, n := range rep.OperatorNeeds() {
		got = append(got, n.Name)
		if n.Why == "" {
			t.Errorf("%s is named with no explanation", n.Name)
		}
	}
	want := []string{
		"cloudflare-api-token",
		"session recordings",
		"verify Entra sign-in and one representative connection",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("operator must supply %v, want %v", got, want)
	}

	var auto []string
	for _, n := range rep.Automatic() {
		auto = append(auto, n.Name)
	}
	wantAuto := []string{"postgres-password", "tunnel connector token", "nginx origin certificate"}
	if strings.Join(auto, "|") != strings.Join(wantAuto, "|") {
		t.Errorf("recovery obtains %v, want %v", auto, wantAuto)
	}
}

func TestRecordingsWithoutARemoteDestinationAreReportedGone(t *testing.T) {
	st := lostHost()
	delete(st.Config, "azure-container")
	for _, n := range needs(st) {
		if n.Name == "session recordings" {
			if !strings.Contains(n.Why, "are gone") {
				t.Errorf("recordings loss is not stated: %s", n.Why)
			}
			return
		}
	}
	t.Fatal("recordings are not mentioned")
}

// --- the record written on the replacement host -------------------------

func TestRestoreKeepsIdentityAndJournalsIntent(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	// The tunnel died with the host; everything else is still there.
	rep := Reconcile(context.Background(), l, with(allPresent(nil), "cloudflare",
		sweeper(without(cloudflarePresent(), "tunnel"), nil, nil)))

	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	st, err := Restore(l, rep, now)
	if err != nil {
		t.Fatal(err)
	}

	if st.DeploymentID != depID {
		t.Fatalf("deployment identity = %q; a new one would orphan every surviving marker", st.DeploymentID)
	}
	if !st.CreatedAt.Equal(l.Snapshot.State.CreatedAt) {
		t.Error("creation time not carried over")
	}
	if len(st.Resources) != len(l.Snapshot.State.Resources) {
		t.Errorf("resources = %d, want %d", len(st.Resources), len(l.Snapshot.State.Resources))
	}
	if len(st.Changes) != 1 {
		t.Error("recorded setting changes dropped; teardown could no longer offer the restore")
	}
	if st.Config["recovered-from"] == "" || st.Config["recovered-at"] != "2026-09-11T12:00:00Z" {
		t.Errorf("recovery not recorded: %v", st.Config)
	}
	if st.Config["guac-hostname"] != hostname {
		t.Error("configuration references lost")
	}

	byID := map[string]state.Resource{}
	for _, r := range st.Resources {
		byID[r.ID] = r
	}
	if got := byID["r1"].ProviderID; got != "" {
		t.Errorf("the lost tunnel kept identifier %q", got)
	}
	if got := byID["r2"].ProviderID; got != "rec-1" {
		t.Errorf("adopted record identifier = %q", got)
	}
	if !strings.Contains(byID["r2"].Ownership, "re-verified") {
		t.Errorf("adoption evidence not recorded: %q", byID["r2"].Ownership)
	}

	var pending []string
	for _, a := range st.Pending() {
		pending = append(pending, a.Intent)
	}
	want := "recover:recreate:cloudflare/tunnel:guacdeploy-" + hostname + "-" + depID
	if len(pending) != 1 || pending[0] != want {
		t.Fatalf("pending intents = %v, want exactly [%s]", pending, want)
	}
	if st.Actions[0].Intent != "recover:restore" || st.Actions[0].Result != state.ResultOK {
		t.Errorf("the restore itself is not journalled: %+v", st.Actions[0])
	}
	// The lost host's unfinished cloudflare-tunnel intent is evidence, not
	// work: carried over answered, never as something still pending.
	var reconciled bool
	for _, a := range st.Actions {
		if a.Intent == "recover:reconciled:cloudflare-tunnel" {
			reconciled = true
		}
		if a.Intent == "cloudflare-tunnel" {
			t.Error("the lost host's unfinished intent was carried over as itself; it would never resolve")
		}
		if a.CorrelationID == "" {
			t.Errorf("%s has no correlation identifier", a.Intent)
		}
	}
	if !reconciled {
		t.Error("the unfinished cloudflare-tunnel intent was dropped instead of reconciled")
	}
}

func TestRestoreRefusesWhileAnythingNeedsReview(t *testing.T) {
	l := loadFrom(t, writeBackup(t, t.TempDir(), backupOpts{}))
	strangers := teardown.Found{Unowned: []state.Resource{
		{Provider: "entra", Type: "application", ProviderID: "eapp-9", Name: "Guacamole " + hostname},
	}}
	rep := Reconcile(context.Background(), l, with(allPresent(nil), "entra", sweeper(strangers, nil, nil)))

	if err := rep.RequiresReview(); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("RequiresReview = %v, want ErrReviewRequired", err)
	}
	st, err := Restore(l, rep, time.Now())
	if !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("Restore = %v, want ErrReviewRequired", err)
	}
	if st != nil {
		t.Error("Restore returned a record to save despite unresolved ambiguity")
	}
}

func TestSnapshotIsSelectedByIDNotRowOrder(t *testing.T) {
	sql := dumpWith(t, []metaRow{
		{id: 2, schema: state.SchemaVersion, takenAt: `\N`, st: lostHost()},
		{id: 1, schema: state.SchemaVersion, takenAt: "2026-01-01 00:00:00+00", st: &state.State{DeploymentID: "older"}},
	}, "")
	snap, err := ExtractSnapshot(sql)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State.DeploymentID != depID {
		t.Errorf("deployment identity = %q, want the highest-id row", snap.State.DeploymentID)
	}
	if !snap.TakenAt.IsZero() {
		t.Errorf("an unreadable timestamp should not be invented: %v", snap.TakenAt)
	}
}

func TestExtractSnapshotReadsUnqualifiedAndReorderedColumns(t *testing.T) {
	raw, err := json.Marshal(lostHost())
	if err != nil {
		t.Fatal(err)
	}
	sql := "COPY " + MetadataTable + " (state, id, schema_version) FROM stdin;\n" +
		escapeCopy(string(raw)) + "\t4\t1\n\\.\n"
	snap, err := ExtractSnapshot(sql)
	if err != nil {
		t.Fatal(err)
	}
	if snap.State.DeploymentID != depID {
		t.Errorf("deployment identity = %q", snap.State.DeploymentID)
	}
}

func TestRecordWithoutADeploymentIdentityIsRefused(t *testing.T) {
	st := lostHost()
	st.DeploymentID = ""
	sql := dumpWith(t, []metaRow{{id: 1, schema: state.SchemaVersion, takenAt: "2026-09-10 01:02:03+00", st: st}}, "")
	if _, err := ExtractSnapshot(sql); !errors.Is(err, ErrIncompatible) {
		t.Fatalf("err = %v, want ErrIncompatible", err)
	}
}
