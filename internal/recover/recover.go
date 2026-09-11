// Package recover brings one lost deployment back on a replacement Rocky
// Linux 10 VM. The operator has three things and nothing else: a backup
// file, the passphrase-encrypted recovery key export, and its passphrase.
// The host, its credentials and its certificate are gone.
//
// The rules come from docs/v1-specification.md:
//
//   - "Validate backup format and version compatibility before altering the
//     target database." Load does the whole check — decryption, format,
//     Guacamole version, completion marker, then the embedded deployment
//     record's schema version — and issues no database command at all.
//   - "Setup accepts a backup and requests credentials that cannot be
//     recovered on the replacement." Credential values are never in a backup
//     by construction, and a TPM- or host-key-sealed copy cannot be opened on
//     another machine even if it were. Needs names every one of them.
//   - "Reconcile restored ownership metadata with current cloud resources
//     before acting." Reconcile classifies every recorded resource against
//     what the provider actually reports, and Report.Print says so before
//     anything is created. "A matching name alone never establishes
//     ownership. Ambiguous results require review."
//
// Ownership metadata is both halves of the restored record: the recorded
// resources, and the journal. A phase that failed before it could save
// created resources that no recorded resource mentions, and they are still
// at the provider carrying this deployment's marker. Reconcile asks by
// marker through internal/teardown's Finder seam, so it sees both, and an
// unfinished intent whose provider cannot be asked stops the recovery
// instead of passing as "nothing found".
//
// The deployment ID is kept, not minted. Every surviving cloud resource
// carries the marker built from it, so a new ID would turn the whole
// deployment into unowned strangers and duplicate all of it.
//
// This package creates nothing and deletes nothing. It reads a backup,
// asks providers read-only questions, reports, and returns the deployment
// record to persist. Recreating what is genuinely absent is the caller's
// existing provisioning path, driven by the journalled intents Restore
// leaves behind. See WIRING.md.
package recover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// Errors a caller distinguishes. Every one of them means nothing on this
// host and nothing at any provider was changed.
var (
	// ErrKeyRequired: the backup is encrypted and the key export, the
	// passphrase, or both are missing or wrong.
	ErrKeyRequired = errors.New("the backup is encrypted: recovery needs the recovery key export and its passphrase")

	// ErrIncompatible: the file is not a backup this tool can restore, or
	// its format, Guacamole version or record schema is one this tool does
	// not understand. Refused before any database command.
	ErrIncompatible = errors.New("the backup is not compatible with this tool")

	// ErrNoRecord: a valid backup that carries no deployment record, so
	// there is nothing to reconcile against the cloud.
	ErrNoRecord = errors.New("the backup carries no deployment record")

	// ErrReviewRequired: something recorded is still present at its provider
	// without this deployment's ownership marker. It is never adopted and
	// never deleted; a person decides.
	ErrReviewRequired = errors.New("restored ownership metadata needs review before anything is created or changed")
)

// Marker is the ownership marker one deployment stamps on the cloud
// resources it creates.
//
// It is spelled here rather than imported because both providers build the
// same string in their own way — internal/entra as a notes/tags/description
// value, internal/cloudflare inside a tunnel or Access application name —
// and neither exposes a single shared constant. TestMarkerMatchesBothProviders
// fails if this ever drifts from either of them.
func Marker(deploymentID string) string { return "guacdeploy:" + deploymentID }

// Key is the "<provider>/<type>" lookup key for one recorded resource.
func Key(r state.Resource) string { return r.Provider + "/" + r.Type }

// --- reading the deployment record back out of the backup ---------------

// MetadataTable is the table internal/backup snapshots the deployment
// record into before every export.
const MetadataTable = "guacdeploy_metadata"

// Snapshot is the versioned deployment record carried inside a backup.
type Snapshot struct {
	SchemaVersion int
	TakenAt       time.Time // zero when the export's timestamp did not parse
	State         *state.State
}

// Source is what an operator brings to the replacement VM.
type Source struct {
	BackupFile string
	// KeyExport is the passphrase-encrypted recovery key export written by
	// 'guacdeploy backup-key' on the lost host, with Passphrase.
	KeyExport  string
	Passphrase string
	// Identity is an already-recovered key, for automation and tests. It
	// replaces KeyExport and Passphrase.
	Identity *age.X25519Identity
	// GuacVersion is the Guacamole version this tool pins. A backup from a
	// different one is refused rather than replayed.
	GuacVersion string
}

// Loaded is a validated backup and the record inside it.
type Loaded struct {
	File     string
	Info     backup.Info
	Snapshot Snapshot
	// SQL is the validated dump, ready for backup.Apply once the plan is
	// approved. A database export can contain saved connection credentials,
	// so it is never logged, journalled or written anywhere but the target
	// database.
	SQL string
}

// Load validates a backup completely and reads the deployment record out of
// it. It touches no database and queries no provider.
//
// Order matters: decrypt, then format and version, then the record's schema
// version. Every refusal happens before anything could be altered.
func Load(src Source) (Loaded, error) {
	raw, err := os.ReadFile(src.BackupFile)
	if err != nil {
		return Loaded{}, err
	}

	content := raw
	if backup.Encrypted(raw) {
		id, err := identity(src)
		if err != nil {
			return Loaded{}, err
		}
		var out strings.Builder
		if err := recoverykey.Decrypt(id, bytes.NewReader(raw), &out); err != nil {
			return Loaded{}, fmt.Errorf("%w: %s did not decrypt with that key (wrong passphrase or key export, or a damaged file): %v",
				ErrKeyRequired, filepath.Base(src.BackupFile), err)
		}
		content = []byte(out.String())
	}

	sql, info, err := backup.Validate(content, nil, src.GuacVersion)
	if err != nil {
		return Loaded{}, fmt.Errorf("%w: %v. Nothing was changed", ErrIncompatible, err)
	}
	snap, err := ExtractSnapshot(sql)
	if err != nil {
		return Loaded{}, err
	}
	return Loaded{File: src.BackupFile, Info: info, Snapshot: snap, SQL: sql}, nil
}

// identity recovers the backup key from the export and passphrase.
func identity(src Source) (*age.X25519Identity, error) {
	if src.Identity != nil {
		return src.Identity, nil
	}
	switch {
	case src.KeyExport == "":
		return nil, fmt.Errorf("%w: point recovery at the export written by 'guacdeploy backup-key' on the lost host", ErrKeyRequired)
	case src.Passphrase == "":
		return nil, fmt.Errorf("%w: no passphrase was supplied for %s", ErrKeyRequired, filepath.Base(src.KeyExport))
	}
	id, err := recoverykey.RecoverIdentity(src.KeyExport, src.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyRequired, err)
	}
	return id, nil
}

// copyRE matches the pg_dump COPY block for the metadata table. pg_dump
// writes plain-format dumps with COPY, not INSERT, and schema-qualifies the
// table; both spellings are accepted.
var copyRE = regexp.MustCompile(`(?m)^COPY\s+(?:[^\s.(]+\.)?` + MetadataTable + `\s*\(([^)]*)\)\s+FROM stdin;$`)

// ExtractSnapshot reads the newest deployment record out of a validated
// dump. The metadata table accumulates one row per backup, so the highest
// serial id is the record this backup was taken with.
func ExtractSnapshot(sql string) (Snapshot, error) {
	m := copyRE.FindStringSubmatchIndex(sql)
	if m == nil {
		return Snapshot{}, fmt.Errorf("%w: it has no %s table, so it was taken by a tool that did not snapshot deployment ownership. Restore it onto an existing deployment instead", ErrNoRecord, MetadataTable)
	}
	cols := map[string]int{}
	for i, c := range strings.Split(sql[m[2]:m[3]], ",") {
		cols[strings.TrimSpace(c)] = i
	}
	for _, want := range []string{"id", "schema_version", "state"} {
		if _, ok := cols[want]; !ok {
			return Snapshot{}, fmt.Errorf("%w: its %s table has no %s column", ErrIncompatible, MetadataTable, want)
		}
	}

	best, bestID := Snapshot{}, -1
	for _, line := range strings.Split(sql[m[1]:], "\n") {
		if line == `\.` {
			break // end of the COPY block
		}
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < len(cols) {
			continue // not a data row of this block
		}
		id, err := strconv.Atoi(unescape(f[cols["id"]]))
		if err != nil || id <= bestID {
			continue
		}
		sv, err := strconv.Atoi(unescape(f[cols["schema_version"]]))
		if err != nil {
			continue
		}
		var st state.State
		if err := json.Unmarshal([]byte(unescape(f[cols["state"]])), &st); err != nil {
			return Snapshot{}, fmt.Errorf("%w: the deployment record in row %d is not readable JSON: %v", ErrIncompatible, id, err)
		}
		best, bestID = Snapshot{SchemaVersion: sv, State: &st}, id
		if i, ok := cols["taken_at"]; ok && i < len(f) {
			best.TakenAt = parseStamp(unescape(f[i]))
		}
	}
	if bestID < 0 {
		return Snapshot{}, fmt.Errorf("%w: its %s table is empty", ErrNoRecord, MetadataTable)
	}

	// Version compatibility, checked before the record is used for anything.
	if best.SchemaVersion > state.SchemaVersion {
		return Snapshot{}, fmt.Errorf("%w: its deployment record is schema %d, newer than this tool supports (%d). Recover with the tool version that wrote it",
			ErrIncompatible, best.SchemaVersion, state.SchemaVersion)
	}
	if best.State.SchemaVersion > state.SchemaVersion {
		return Snapshot{}, fmt.Errorf("%w: the deployment record inside it declares schema %d, newer than this tool supports (%d)",
			ErrIncompatible, best.State.SchemaVersion, state.SchemaVersion)
	}
	if best.State.DeploymentID == "" {
		return Snapshot{}, fmt.Errorf("%w: its deployment record has no deployment identity, so no ownership marker can be checked against the cloud", ErrIncompatible)
	}
	return best, nil
}

// unescape decodes one PostgreSQL COPY text field.
func unescape(f string) string {
	if f == `\N` || !strings.ContainsRune(f, '\\') {
		return f
	}
	var b strings.Builder
	for i := 0; i < len(f); i++ {
		if f[i] != '\\' || i+1 >= len(f) {
			b.WriteByte(f[i])
			continue
		}
		i++
		switch f[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		default: // covers \\ and any other escaped literal
			b.WriteByte(f[i])
		}
	}
	return b.String()
}

// parseStamp reads a COPY timestamptz. It is display only: the record is
// selected by serial id, so an unparsed stamp costs a line of the report and
// never a recovery.
func parseStamp(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999-07", "2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05-07", time.RFC3339Nano,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// --- reconciling the restored record against the real cloud -------------

// Disposition is what recovery will do with one recorded resource.
type Disposition string

const (
	// Adopt: still present and the ownership marker verifies. Reused as it
	// is. Nothing is created, so nothing is duplicated.
	Adopt Disposition = "adopt"
	// Recreate: absent at the provider. Created again by the caller's
	// provisioning, after Restore journals the intent.
	Recreate Disposition = "recreate"
	// Review: present without this deployment's marker, or the provider
	// could not be asked. Never adopted, never deleted, never recreated —
	// recreating on an unanswered question is how duplicates are made.
	Review Disposition = "review"
	// Rebuild: host-local, not a cloud resource. The replacement VM builds
	// it from the restored record; no duplicate is possible.
	Rebuild Disposition = "rebuild"
	// WithParent: no lifecycle of its own. Its ownership follows its parent
	// and it is never queried or created separately.
	WithParent Disposition = "with-parent"
)

// Obligation is a journalled phase from the lost host that intended to
// create provider resources and whose latest attempt did not succeed.
//
// It is the half of the truth the recorded resource list cannot hold. A
// phase creates several resources and can fail before any of them is saved:
// entra.Apply creates an application, a service principal, two groups and
// their role assignments, and an error partway through returns with no
// resource ID in the record. Those resources are still in the tenant, still
// carrying this deployment's marker, and a recovery that ignored them would
// create a second set beside them. That is the failure teardown already had
// to fix, and dropping the journal on a replacement host brings it back.
//
// internal/teardown.Obligations decides which intents these are, from its
// own map of which phase creates at which provider. Nothing here keeps a
// second copy of that list.
type Obligation struct {
	Intent   string
	Provider string
	// Result is the journalled result of the latest attempt on the lost
	// host: failed, uncertain, or interrupted.
	Result string
	// Answered is whether the provider could be asked at all. An
	// unanswered obligation stops the recovery; it is not an empty answer.
	Answered bool
	// Detail is what reconciliation determined, or why it could not.
	Detail string
}

// sweep is one provider's answer to "what of this deployment's is there?",
// or the reason there is no answer.
type sweep struct {
	found teardown.Found
	err   error
	wired bool
}

// withParent are the recorded resources whose ownership follows a parent.
var withParent = map[string]string{
	"cloudflare/access-policy": "scoped to the Access application; recovered with it, never queried or created separately",
	"entra/service-principal":  "follows its application's appId; recovered with the application, never created separately",
}

// Item is one line of the reconciliation.
type Item struct {
	Resource    state.Resource
	Disposition Disposition
	// ProviderID is the identifier confirmed live, for an adopted resource.
	ProviderID string
	Detail     string
	// Retarget marks an adopted DNS record whose tunnel is being recreated:
	// the record is updated in place to the new tunnel, never duplicated.
	Retarget bool
	// Recovered marks a resource the provider reported that the record did
	// not hold: a phase on the lost host created it and failed before
	// saving it. It goes into the record so recovery does not create a
	// second one.
	Recovered bool
}

func (i Item) String() string {
	if i.Resource.ProviderID != "" {
		return fmt.Sprintf("%s %s (%s)", i.Resource.Type, i.Resource.Name, i.Resource.ProviderID)
	}
	return fmt.Sprintf("%s %s", i.Resource.Type, i.Resource.Name)
}

// Need is something the backup cannot carry. Operator marks the ones only a
// person can provide.
type Need struct {
	Name     string
	Why      string
	Operator bool
}

// Report is the whole recovery proposal. Building it changes nothing.
type Report struct {
	DeploymentID string
	Hostname     string
	BackupFile   string
	TakenAt      time.Time
	Items        []Item
	Needs        []Need
	// Obligations are the lost host's unfinished creation intents, and what
	// asking the provider made of each one.
	Obligations []Obligation
}

// Reconcile classifies the restored record against what the providers
// actually report. It is read only at every provider and writes nothing.
//
// It asks each provider once, by this deployment's ownership marker, through
// internal/teardown's Finder seam — the same query, the same marker
// conventions and the same "a name match alone establishes nothing" rule
// that teardown reconciliation uses, so a resource judged ours here is
// judged ours identically there.
//
// One sweep per provider answers two questions the recorded resource list
// cannot answer by itself: which recorded resources are still there, and
// what a failed phase created and never saved. Both matter on a replacement
// host, because either one recreated blindly is a duplicate.
func Reconcile(ctx context.Context, l Loaded, find teardown.Finders) Report {
	st := l.Snapshot.State
	rep := Report{
		DeploymentID: st.DeploymentID,
		Hostname:     st.Config["guac-hostname"],
		BackupFile:   filepath.Base(l.File),
		TakenAt:      l.Snapshot.TakenAt,
		Needs:        needs(st),
	}

	// Ask every provider the record mentions, and every provider an
	// unfinished phase may have created at. The second set is the one that
	// matters here: such a phase can have left a resource with no entry in
	// the record at all, so nothing in st.Resources would ever ask about it.
	var order []string
	asked := map[string]*sweep{}
	ask := func(provider string) *sweep {
		s, seen := asked[provider]
		if seen {
			return s
		}
		s = &sweep{}
		if f := find[provider]; f != nil {
			s.wired = true
			s.found, s.err = f(ctx)
		}
		asked[provider] = s
		order = append(order, provider)
		return s
	}
	for _, r := range st.Resources {
		if r.Provider != "host" && r.Provider != "docker" {
			ask(r.Provider)
		}
	}
	obligations := teardown.Obligations(st)
	for _, ob := range obligations {
		ask(ob.Provider)
	}

	for _, r := range st.Resources {
		rep.Items = append(rep.Items, classify(r, st.DeploymentID, asked[r.Provider]))
	}

	// What the providers hold that the record does not. A phase that failed
	// before it could save is the reason this is not always empty.
	for _, provider := range order {
		s := asked[provider]
		if !s.wired || s.err != nil {
			continue
		}
		for _, res := range s.found.Owned {
			if _, ok := match(res, st.Resources); ok {
				continue // already in the record, already classified above
			}
			if res.Ownership == "" {
				res.Ownership = "found at the provider by this deployment's ownership marker"
			}
			rep.Items = append(rep.Items, Item{Resource: res, Disposition: Adopt, Recovered: true,
				ProviderID: res.ProviderID,
				Detail: "found at " + provider + " carrying marker " + Marker(st.DeploymentID) +
					", and missing from the record because a phase failed before it could be saved. It goes into the record as it is, so recovery does not create a second one"})
		}
		for _, res := range s.found.Unowned {
			if _, ok := match(res, st.Resources); ok {
				continue
			}
			rep.Items = append(rep.Items, Item{Resource: res, Disposition: Review, Recovered: true,
				ProviderID: res.ProviderID,
				Detail:     "found at " + provider + " under this deployment's naming but carrying no ownership marker. A matching name alone never establishes ownership, so it is neither adopted nor removed, and this deployment cannot be brought back onto a name something else holds"})
		}
	}

	for _, ob := range obligations {
		rep.Obligations = append(rep.Obligations, answer(ob, asked[ob.Provider], rep.Items, st.DeploymentID))
	}

	// The DNS record must end up pointing at whichever tunnel is actually in
	// use. A surviving record still names the tunnel that died with the
	// host, so it is updated rather than joined by a second record.
	if has(rep.Items, "cloudflare/tunnel", Recreate) {
		for i, it := range rep.Items {
			if Key(it.Resource) == "cloudflare/dns-record" && it.Disposition == Adopt {
				rep.Items[i].Retarget = true
				rep.Items[i].Detail = "kept and re-pointed: it carries this deployment's marker, but names the tunnel that was lost. The record is updated to the new tunnel, never duplicated"
			}
		}
	}
	return rep
}

func has(items []Item, key string, d Disposition) bool {
	for _, it := range items {
		if Key(it.Resource) == key && it.Disposition == d {
			return true
		}
	}
	return false
}

// classify applies the ownership rules to one recorded resource. The rules
// are the specification's: a verified marker adopts, an absent resource is
// recreated, and everything else — a name match without the marker, a
// provider that cannot be asked, a provider with no query wired — is review.
func classify(r state.Resource, deploymentID string, s *sweep) Item {
	it := Item{Resource: r, ProviderID: r.ProviderID}

	if detail, ok := withParent[Key(r)]; ok {
		it.Disposition, it.Detail = WithParent, detail
		return it
	}
	if r.Provider == "host" || r.Provider == "docker" {
		it.Disposition = Rebuild
		it.Detail = "on this host, not in the cloud: setup builds it again on the replacement VM from the restored record"
		return it
	}

	switch {
	case s == nil || !s.wired:
		it.Disposition = Review
		it.Detail = fmt.Sprintf("no %s query is wired into this run, so whether it still exists cannot be established here. It is neither recreated nor removed", r.Provider)
	case s.err != nil:
		it.Disposition = Review
		it.Detail = fmt.Sprintf("%s could not be asked: %v. Nothing is recreated while that is unknown, because a duplicate would be the result", r.Provider, s.err)
	default:
		if live, ok := match(r, s.found.Owned); ok {
			it.Disposition = Adopt
			it.ProviderID = live.ProviderID
			it.Detail = "still there and proven ours by this deployment's ownership marker: reused as it is, not created again"
			if live.Ownership != "" {
				it.Detail = "still there and proven ours: " + live.Ownership + ". Reused as it is, not created again"
			}
			return it
		}
		if live, ok := match(r, s.found.Unowned); ok {
			it.Disposition = Review
			it.ProviderID = live.ProviderID
			it.Detail = fmt.Sprintf("something is there under this name, but it carries no %s ownership marker. A matching name alone never establishes ownership, so it is neither adopted nor removed",
				Marker(deploymentID))
			if r.Ownership != "" {
				it.Detail += ". The lost host recorded it as: " + r.Ownership
			}
			return it
		}
		it.Disposition = Recreate
		it.ProviderID = ""
		it.Detail = "gone at the provider: created again, with the intent journalled first"
	}
	return it
}

// match finds r in a provider's answer. The identifier decides when both
// sides have one, so a resource renamed at the provider but still carrying
// the marker is recognised rather than recreated beside itself. Otherwise it
// is the provider/type/name identity state.EnsureResource already uses.
func match(r state.Resource, list []state.Resource) (state.Resource, bool) {
	if r.ProviderID != "" {
		for _, e := range list {
			if e.ProviderID == r.ProviderID {
				return e, true
			}
		}
	}
	for _, e := range list {
		if e.Provider == r.Provider && e.Type == r.Type && e.Name == r.Name {
			return e, true
		}
	}
	return state.Resource{}, false
}

// answer says what asking the provider made of one unfinished creation
// intent. A provider that could not be asked leaves it unanswered, which
// stops the recovery: an unreachable provider is uncertain work, not proof
// that the phase created nothing.
func answer(ob teardown.Obligation, s *sweep, items []Item, deploymentID string) Obligation {
	o := Obligation{Intent: ob.Intent, Provider: ob.Provider, Result: ob.Result}
	lead := fmt.Sprintf("the %s phase on the lost host ended %s, so it may have created resources at %s that never reached the record",
		ob.Intent, ob.Result, ob.Provider)
	switch {
	case s == nil || !s.wired:
		o.Detail = lead + fmt.Sprintf(". No %s query is wired into this run, so that cannot be checked. Wire one, or check %s by hand for resources carrying marker %s, before recovering again",
			ob.Provider, ob.Provider, Marker(deploymentID))
	case s.err != nil:
		o.Detail = lead + fmt.Sprintf(". %s could not be asked: %v. Check it for resources carrying marker %s before recovering again",
			ob.Provider, s.err, Marker(deploymentID))
	default:
		o.Answered = true
		var recovered int
		for _, it := range items {
			if it.Recovered && it.Disposition == Adopt && it.Resource.Provider == ob.Provider {
				recovered++
			}
		}
		switch recovered {
		case 0:
			o.Detail = lead + fmt.Sprintf(". %s was asked, and holds nothing of this deployment's that the record was missing", ob.Provider)
		default:
			o.Detail = lead + fmt.Sprintf(". %s was asked: %d resource(s) it created are listed above and go into the record, so they are not created a second time", ob.Provider, recovered)
		}
	}
	return o
}

// Unanswered is the unfinished creation intents whose provider could not be
// asked. Each one is work that may be sitting at a provider right now.
func (r Report) Unanswered() []Obligation {
	var out []Obligation
	for _, o := range r.Obligations {
		if !o.Answered {
			out = append(out, o)
		}
	}
	return out
}

// needs lists what a backup cannot carry. Credential values are excluded
// from deployment state by construction, so none of them is in there, and a
// sealed copy would not open on this machine anyway.
func needs(st *state.State) []Need {
	mode := st.Config["credential-mode"]
	sealed := mode == creds.ModeTPM || mode == creds.ModeHostKey

	var out []Need
	for _, s := range creds.Required {
		n := Need{Name: s.Name, Operator: true,
			Why: s.Purpose + ": no credential value is ever written to deployment state or to a backup, so it is supplied again here"}
		switch {
		case s.Generate:
			n.Operator = false
			n.Why = s.Purpose + ": generated fresh on this host. A database export carries no role password — the new PostgreSQL container creates the role from whatever value is chosen here — so a new value restores a working deployment and loses nothing"
		case sealed:
			n.Why += ". The copy on the lost host was sealed to that machine and cannot be recovered here. " +
				"Asked whether " + mode + " mode survives a replacement host, the tool answers: " +
				creds.Describe(mode).ReplacementHost
		}
		out = append(out, n)
	}

	out = append(out,
		Need{Name: "tunnel connector token", Operator: false,
			Why: "fetched fresh from Cloudflare for whichever tunnel is in use, adopted or new. The token is never journalled or backed up, and fetching it again creates no tunnel"},
		Need{Name: "nginx origin certificate", Operator: false,
			Why: "re-issued through Let's Encrypt with Cloudflare DNS validation, not restored. Its private key was only ever on the lost host: a backup must not carry a private key, and certificate files without their key are useless. Re-issue needs only the Cloudflare API token supplied above. The old certificate stays valid until it expires but cannot be used by anyone without that key. Let's Encrypt allows five identical certificates per week, which one recovery is well inside"},
	)

	if c := st.Config["azure-container"]; c != "" {
		out = append(out, Need{Name: "session recordings", Operator: true,
			Why: fmt.Sprintf("recordings are not in a database backup. Those already uploaded to %s/%s are still there and are retrieved with the documented procedure. Any recording that was never uploaded existed only on the lost host and is gone",
				st.Config["azure-account"], c)})
	} else {
		out = append(out, Need{Name: "session recordings", Operator: true,
			Why: "recordings are not in a database backup and this deployment recorded no remote destination, so recordings held on the lost host are gone. New sessions record normally once the stack is running"})
	}

	out = append(out, Need{Name: "verify Entra sign-in and one representative connection", Operator: true,
		Why: "a recovery is only proven by a person signing in through Entra and opening one connection on the replacement VM. Nothing here checks that"})
	return out
}

// Of returns the items with one disposition, in recorded order.
func (r Report) Of(d Disposition) []Item {
	var out []Item
	for _, it := range r.Items {
		if it.Disposition == d {
			out = append(out, it)
		}
	}
	return out
}

// OperatorNeeds is exactly what a person must still supply or do.
func (r Report) OperatorNeeds() []Need {
	var out []Need
	for _, n := range r.Needs {
		if n.Operator {
			out = append(out, n)
		}
	}
	return out
}

// Automatic is what recovery obtains for itself, and why that is not a loss.
func (r Report) Automatic() []Need {
	var out []Need
	for _, n := range r.Needs {
		if !n.Operator {
			out = append(out, n)
		}
	}
	return out
}

// RequiresReview reports the ambiguity that stops a recovery. Explicit
// consent does not override it.
//
// Two things stop it, and the second is the one a resource list cannot see:
// an unfinished creation intent whose provider could not be asked. Treating
// that as "nothing found" is how a recovery creates a second Entra
// application beside the one the failed phase already made.
func (r Report) RequiresReview() error {
	rv, un := r.Of(Review), r.Unanswered()
	if len(rv) == 0 && len(un) == 0 {
		return nil
	}
	var parts []string
	if len(rv) > 0 {
		var names []string
		for _, it := range rv {
			names = append(names, it.String())
		}
		parts = append(parts, fmt.Sprintf("%d resource(s) could not be shown to be this deployment's own work: %s",
			len(rv), strings.Join(names, ", ")))
	}
	if len(un) > 0 {
		var intents []string
		for _, o := range un {
			intents = append(intents, o.Intent+" at "+o.Provider)
		}
		parts = append(parts, fmt.Sprintf("%d unfinished creation intent(s) could not be checked at their provider: %s",
			len(un), strings.Join(intents, ", ")))
	}
	return fmt.Errorf("%w: %s. Nothing was created, changed or removed",
		ErrReviewRequired, strings.Join(parts, "; and "))
}

// Print shows the classification before anything happens.
func (r Report) Print(u *ui.UI) {
	u.Say("Recovery plan for deployment %s onto this replacement host.", r.DeploymentID)
	u.Say("Deployment record read from %s%s. Nothing has been created, changed or removed yet.",
		r.BackupFile, stamp(r.TakenAt))

	var adopted, recovered []Item
	for _, it := range r.Of(Adopt) {
		if it.Recovered {
			recovered = append(recovered, it)
			continue
		}
		adopted = append(adopted, it)
	}
	section(u, "Still in the cloud and proven ours by its ownership marker. Reused, not created again:", adopted)
	section(u, "At a provider, carrying this deployment's marker, and missing from the record: a phase on the lost host created these and failed before it could save them. Adopted, not created a second time:", recovered)
	section(u, "Gone, and created again after the intent is journalled:", r.Of(Recreate))
	section(u, "On this host rather than in the cloud. Setup builds these again:", r.Of(Rebuild))
	section(u, "Recovered with their parent, never separately:", r.Of(WithParent))

	if len(r.Obligations) > 0 {
		u.Say("")
		u.Say("The lost host left unfinished work at a provider. Each one was checked before anything else:")
		for _, o := range r.Obligations {
			status := "ANSWERED"
			if !o.Answered {
				status = "NOT ANSWERED"
			}
			u.Say("  %s (%s)", o.Intent, status)
			u.Say("       %s", o.Detail)
		}
	}

	if rv := r.Of(Review); len(rv) > 0 {
		u.Say("")
		u.Say("NEEDS REVIEW. Recovery stops until a person has looked at these. None is adopted, recreated or removed:")
		for _, it := range rv {
			u.Say("  %s", it)
			u.Say("       %s", it.Detail)
		}
	}

	if ops := r.OperatorNeeds(); len(ops) > 0 {
		u.Say("")
		u.Say("You must still supply or do these. None of them is in the backup:")
		for _, n := range ops {
			u.Say("  %s", n.Name)
			u.Say("       %s", n.Why)
		}
	}
	if auto := r.Automatic(); len(auto) > 0 {
		u.Say("")
		u.Say("Recovery obtains these itself:")
		for _, n := range auto {
			u.Say("  %s — %s", n.Name, n.Why)
		}
	}
}

func section(u *ui.UI, title string, items []Item) {
	if len(items) == 0 {
		return
	}
	u.Say("")
	u.Say("%s", title)
	for _, it := range items {
		u.Say("  %s", it)
		u.Say("       %s", it.Detail)
	}
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return ", taken " + t.Format(time.RFC3339)
}

// --- the record to persist on the replacement host ----------------------

// Restore returns the deployment record for the replacement host, ready to
// save under the deployment lock. It writes nothing itself.
//
// It refuses while anything needs review: the ambiguity is resolved by a
// person first, so no wiring can step past it.
//
// The deployment identity, the configuration references, the resource
// identifiers and the recorded setting changes all come back. Adopted
// resources take the identifier the provider just confirmed. A resource
// that is gone keeps its record but loses its stale identifier and gains a
// journalled, unfinished intent, so state.Pending drives the caller's
// provisioning and a second interruption still cannot duplicate it.
//
// The lost host's unfinished creation intents are carried over as answered
// entries, one per obligation, recording what asking the provider found.
// They must not be dropped: a phase that failed before saving can have left
// a marked resource at a provider, and that evidence is the only thing
// standing between a recovery and a duplicate. They must not be carried over
// unfinished either — the original phase did not succeed, and a pending
// intent naming a machine that no longer exists can never resolve — so each
// becomes a finished "recover:reconciled:<intent>" entry that says what was
// determined and keeps the original phase name inside it.
//
// A pending intent that creates nothing at any provider is not carried over.
// The host it ran on is gone, so there is nothing left to reconcile; the
// restore entry records how many there were.
//
// Recorded setting changes are kept: the objects they changed are
// pre-existing ones that outlived the host, and internal/settings
// drift-checks each against the live value before it offers to restore
// anything.
func Restore(l Loaded, rep Report, now time.Time) (*state.State, error) {
	if err := rep.RequiresReview(); err != nil {
		return nil, err
	}
	old := l.Snapshot.State
	st := &state.State{
		SchemaVersion: state.SchemaVersion,
		DeploymentID:  old.DeploymentID,
		CreatedAt:     old.CreatedAt,
		Config:        map[string]string{},
		Changes:       old.Changes,
	}
	for k, v := range old.Config {
		st.Config[k] = v
	}
	st.Config["recovered-at"] = now.UTC().Format(time.RFC3339)
	st.Config["recovered-from"] = rep.BackupFile

	corr := state.NewID()
	finished := now.UTC()
	var adopted, recovered, recreate int
	for _, it := range rep.Items {
		r := it.Resource
		switch it.Disposition {
		case Adopt:
			adopted++
			r.ProviderID = it.ProviderID
			if it.Recovered {
				recovered++
				r.CorrelationID = corr
				if r.CreatedAt.IsZero() {
					r.CreatedAt = finished
				}
			}
			r.Ownership = strings.TrimSuffix(r.Ownership, ".") +
				"; marker re-verified on this replacement host at " + finished.Format(time.RFC3339)
		case Recreate:
			recreate++
			r.ProviderID = ""
			r.CorrelationID = corr
			st.Actions = append(st.Actions, state.Action{
				ID: state.NewID(), CorrelationID: corr, StartedAt: finished,
				Intent: "recover:recreate:" + Key(r) + ":" + r.Name,
			})
		}
		// EnsureResource gives a recovered resource the identifier it never
		// got, and refuses to record the same provider/type/name twice.
		st.EnsureResource(r)
	}

	// Every obligation the lost host left, and what was made of it. Restore
	// refuses while any is unanswered, so each one here has an answer.
	for _, o := range rep.Obligations {
		st.Actions = append(st.Actions, state.Action{
			ID: state.NewID(), CorrelationID: corr,
			Intent:    "recover:reconciled:" + o.Intent,
			StartedAt: finished, FinishedAt: &finished, Result: state.ResultOK,
			Detail: o.Detail,
		})
	}

	// Pending intents that create nothing at a provider die with the host.
	dropped := len(old.Pending()) - len(rep.Obligations)
	if dropped < 0 {
		dropped = 0
	}

	// The restore itself, journalled ahead of everything above so the record
	// says where this deployment came from.
	st.Actions = append([]state.Action{{
		ID: state.NewID(), CorrelationID: corr, Intent: "recover:restore",
		StartedAt: finished, FinishedAt: &finished, Result: state.ResultOK,
		Detail: fmt.Sprintf("recovered onto a replacement host from %s: %d resource(s) adopted on a verified ownership marker (%d of them found at a provider and missing from the record), %d to create again, %d unfinished creation intent(s) reconciled, %d host-local pending intent(s) not carried over",
			rep.BackupFile, adopted, recovered, recreate, len(rep.Obligations), dropped),
	}}, st.Actions...)
	return st, nil
}
