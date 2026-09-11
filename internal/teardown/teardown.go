// Package teardown plans and runs the guided removal of one deployment.
//
// The rules come from docs/v1-specification.md, "Teardown contract":
//
//   - Present eligible resources and their dependencies before removing
//     anything, and take approval first. An unattended run stops with an
//     approval-required error unless explicit consent was given on the
//     command line, and anything ambiguous stops the run even then.
//   - Only resources this deployment created are eligible. Deployment state
//     records nothing else — a pre-existing application or group is never
//     written to it — and every provider delete re-verifies its ownership
//     marker at deletion time. A refusal is reported as retained, never as
//     success.
//   - The recorded resources are not the whole truth, so the journal is read
//     as well: a phase that intended to create things and did not succeed is
//     reconciled against its provider by this deployment's ownership marker
//     before anything is reported. See reconcile.go.
//   - Preserve created resources that now support unrelated use. This tool
//     creates no DNS zone, no Access organisation and no Entra tenant, so
//     the specification's worked example — a created zone holding unrelated
//     records — cannot arise here: internal/cloudflare deletes single owned
//     records and has no zone deletion at all. The rule does apply to the
//     installation directory, and that is where it is implemented: the
//     rendered files go, and the directory itself stays whenever anything
//     else is still in it.
//   - Preserve database data, recordings and backups by default. Permanent
//     deletion needs explicit, separate intent, and the plan shows exactly
//     what that would destroy before anything happens.
//   - Report retained items and incomplete cleanup at the end, and keep
//     enough state to retry. A failed delete leaves its resource recorded,
//     so a later run tries again.
//
// Restoring changed pre-existing settings is internal/settings' job, not
// this package's. It runs first, because a restore needs the object it
// changes to still exist.
package teardown

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/settings"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// ErrApprovalRequired means removal was reached in a run that cannot ask a
// person. Nothing has been removed. cmd maps it to exit 3, alongside
// session.ErrApprovalRequired, settings.ErrApprovalRequired and
// ui.ErrInputRequired.
var ErrApprovalRequired = errors.New("interactive approval required")

// ErrReviewRequired means the deployment record holds something this
// package cannot classify as the deployment's own work. Explicit consent
// does not override it: an ambiguous result is reviewed by a person.
var ErrReviewRequired = errors.New("deployment record needs review before teardown")

// ErrIncomplete means the run finished with residue: something eligible was
// not removed. Teardown is never reported as complete while that is true.
var ErrIncomplete = errors.New("teardown is incomplete")

// Kind groups recorded resources into the removal steps, and Order is the
// sequence the contract requires.
type Kind string

const (
	KindDNSRecord  Kind = "dns-record"
	KindAccessApp  Kind = "access-application"
	KindTunnel     Kind = "tunnel"
	KindEntraApp   Kind = "entra-application"
	KindEntraGroup Kind = "entra-group"
	KindHostUnit   Kind = "host-unit"
	KindContainer  Kind = "container"
	KindCredential Kind = "credential"
	KindConfigDir  Kind = "config-directory"
	KindData       Kind = "data"
	KindHostChange Kind = "host-change"
)

// Order is the removal order.
//
// The Cloudflare connector is stopped before any of it (see Plan.Connectors)
// so the tunnel has no active connections when it is deleted. Then the DNS
// record stops sending traffic at the tunnel, then the Access application
// that fronts it, then the tunnel itself. Entra comes next, because nothing
// local depends on it. Host units go before the containers so no timer fires
// against a half-removed stack, the containers go before the credentials
// they were started with, and those go before the rendered configuration.
// Data is last, and only ever with explicit intent.
var Order = []Kind{
	KindDNSRecord, KindAccessApp, KindTunnel,
	KindEntraApp, KindEntraGroup,
	KindHostUnit, KindContainer, KindCredential, KindConfigDir,
	KindData, KindHostChange,
}

// Action is what the plan will do with one recorded resource.
type Action string

const (
	// ActionRemove means eligible: deleted once approved.
	ActionRemove Action = "remove"
	// ActionWithParent means it has no independent lifecycle and is removed
	// by its parent's delete. Deleting it separately is never attempted.
	ActionWithParent Action = "with-parent"
	// ActionPreserve means kept on purpose: data by default, or something
	// that now supports unrelated use.
	ActionPreserve Action = "preserve"
	// ActionReview means ownership cannot be established from the record.
	// A matching name alone never establishes ownership, so it is never
	// offered and it stops the run.
	ActionReview Action = "review"
)

// Item is one line of the plan.
type Item struct {
	Kind     Kind
	Resource state.Resource
	Action   Action
	// Destructive marks data, recordings and backups: removing one destroys
	// content permanently, so it needs its own explicit intent.
	Destructive bool
	// Detail says what will happen, or why the item is not being removed.
	Detail string
}

func (i Item) String() string {
	if i.Resource.ProviderID != "" {
		return fmt.Sprintf("%s %s (%s)", i.Resource.Type, i.Resource.Name, i.Resource.ProviderID)
	}
	return fmt.Sprintf("%s %s", i.Resource.Type, i.Resource.Name)
}

// Plan is the full removal proposal for one deployment. Building it changes
// nothing, locally or at any provider.
type Plan struct {
	DeploymentID string
	// Connectors are the cloudflared containers to stop before anything is
	// deleted. They are removed later, with the rest of the stack.
	Connectors []string
	Items      []Item
	// Settings are the pre-existing settings this deployment changed that
	// have not been restored yet, already classified by internal/settings.
	Settings []settings.Entry
	// Reconciled is what asking the providers about the journal's failed
	// creation phases produced. Its adopted resources are already in the
	// record, and so already in Items; its name-only matches and its
	// uncertain work are reported and never acted on. See reconcile.go.
	Reconciled Reconciliation
}

func (p Plan) filter(a Action) []Item {
	var out []Item
	for _, k := range Order {
		for _, it := range p.Items {
			if it.Kind == k && it.Action == a {
				out = append(out, it)
			}
		}
	}
	return out
}

// Removable is every eligible item, in removal order.
func (p Plan) Removable() []Item { return p.filter(ActionRemove) }

// Review is everything that stops the run until a person has looked at it.
func (p Plan) Review() []Item { return p.filter(ActionReview) }

// Preserved is everything kept on purpose.
func (p Plan) Preserved() []Item { return p.filter(ActionPreserve) }

// Destroys is the subset of Removable whose removal destroys content
// permanently. The plan always shows these before anything happens.
func (p Plan) Destroys() []Item {
	var out []Item
	for _, it := range p.Removable() {
		if it.Destructive {
			out = append(out, it)
		}
	}
	return out
}

// keepData returns the plan with every destructive removal demoted back to
// preserved, for an operator who approves the teardown but not the deletion.
func (p Plan) keepData() Plan {
	items := make([]Item, len(p.Items))
	copy(items, p.Items)
	for i, it := range items {
		if it.Action == ActionRemove && it.Destructive {
			items[i].Action = ActionPreserve
			items[i].Detail = "kept: permanent deletion was not approved"
		}
	}
	p.Items = items
	return p
}

// classify maps one recorded resource onto a removal step. Every provider
// and type this tool records has an entry; anything else is ambiguous by
// construction and goes to review rather than being guessed at.
func classify(r state.Resource) (Kind, Action, string) {
	switch r.Provider + "/" + r.Type {
	case "cloudflare/dns-record":
		return KindDNSRecord, ActionRemove, "delete this record only; the zone and every unrelated record in it are untouched"
	case "cloudflare/access-application":
		return KindAccessApp, ActionRemove, "delete this Access application only; the Access organisation and unrelated applications are untouched"
	case "cloudflare/access-policy":
		return KindAccessApp, ActionWithParent, "scoped to the Access application; removed with it, never deleted separately"
	case "cloudflare/tunnel":
		return KindTunnel, ActionRemove, "delete the tunnel after its connector has stopped"
	case "entra/application":
		return KindEntraApp, ActionRemove, "delete the application; Entra's soft delete keeps it recoverable for 30 days"
	case "entra/service-principal":
		return KindEntraApp, ActionWithParent, "removed with its application, together with its role assignments; never deleted separately"
	case "entra/group":
		return KindEntraGroup, ActionRemove, "delete the group; group membership is not changed anywhere else"
	case "host/systemd-unit":
		return KindHostUnit, ActionRemove, "stop and remove the unit, and the deployment-owned binary copy it calls"
	case "docker/container":
		return KindContainer, ActionRemove, "stop and remove the container with the rest of the stack"
	case "host/credential-dir":
		return KindCredential, ActionRemove, "remove the credential files this deployment wrote, and the directory if nothing else is in it"
	case "host/credential-file", "host/credential-sealed":
		return KindCredential, ActionWithParent, "removed with the credential directory that holds it"
	case "host/config-directory":
		return KindConfigDir, ActionRemove, "remove the files this deployment rendered; the directory itself stays if anything else is still in it"
	case "host/recovery-key-export":
		// Never deleted, and never merely "unknown". It is the only thing
		// that can read this deployment's encrypted backups, and those
		// backups outlive the deployment by design. Deleting it with the
		// deployment would quietly destroy every backup's readability.
		return KindHostChange, ActionPreserve, "kept: it is the only key that can read this deployment's encrypted backups, which teardown preserves. Delete it yourself once you are sure no backup needs it"
	case "host/data-directory":
		return KindData, ActionPreserve, "the Guacamole database, preserved by default"
	case "host/package":
		// The contract's own rule: a created resource that now supports
		// unrelated use is preserved. Removing a package this deployment
		// happened to install first would take it from everything else on
		// the host that has since come to rely on it.
		return KindHostChange, ActionPreserve, "installed by this deployment and kept: the rest of this host may depend on it now. Remove it by hand if you are sure"
	case "host/service-enablement":
		return KindHostChange, ActionPreserve, "left enabled: anything else on this host that uses it would stop with it"
	}
	return KindData, ActionReview, fmt.Sprintf("no removal is defined for a %s %s", r.Provider, r.Type)
}

// BuildPlan classifies the deployment record into an ordered removal plan.
// It reads state and the already-classified setting entries; it calls no
// provider and changes nothing.
//
// deleteData is the separate, explicit intent the contract requires for
// permanent deletion. Without it the data, the recordings and the local
// backups are listed as preserved. With it they are listed as removals,
// each marked destructive, so the plan shows exactly what would be lost.
func BuildPlan(st *state.State, pending []settings.Entry, deleteData bool) Plan {
	if st == nil {
		return Plan{}
	}
	p := Plan{DeploymentID: st.DeploymentID, Settings: pending}

	var installDir string
	for _, r := range st.Resources {
		k, a, detail := classify(r)
		if r.Ownership == "" && a != ActionReview {
			// A matching name alone never establishes ownership, and this
			// record carries no other evidence either.
			a = ActionReview
			detail = "no ownership evidence is recorded for it"
		}
		it := Item{Kind: k, Resource: r, Action: a, Detail: detail}
		if k == KindData {
			it.Destructive = true
			if deleteData && a == ActionPreserve {
				it.Action, it.Detail = ActionRemove, "PERMANENTLY DELETE the Guacamole database, including every connection, user grant and session history"
			}
		}
		if k == KindConfigDir {
			installDir = r.Name
		}
		if k == KindContainer && strings.Contains(r.Name, "cloudflared") {
			p.Connectors = append(p.Connectors, r.Name)
		}
		p.Items = append(p.Items, it)
	}

	// Recordings and local backups are not recorded as resources, because
	// nothing about them is provider state. They are still content this
	// teardown could destroy, so the plan has to show them either way.
	if installDir != "" {
		p.Items = append(p.Items, dataItem(filepath.Join(installDir, "recordings"),
			"recordings-directory", "session recordings held on this host", deleteData))
	}
	if dest := st.Config["backup-dest"]; dest != "" {
		p.Items = append(p.Items, dataItem(dest, "backup-directory",
			"database backups held on this host", deleteData))
	}
	if st.Config["azure-container"] != "" {
		p.Items = append(p.Items, Item{
			Kind: KindData, Action: ActionPreserve, Destructive: true,
			Resource: state.Resource{Provider: "azure", Type: "blob-prefix",
				Name: st.Config["azure-account"] + "/" + st.Config["azure-container"]},
			Detail: "remote backups are never removed by teardown, with or without explicit deletion intent",
		})
	}
	return p
}

// dataItem builds one preserved-by-default content item. It carries no
// resource ID, because nothing in the deployment record points at it and
// removing it changes no record.
func dataItem(path, typ, what string, deleteData bool) Item {
	it := Item{
		Kind:        KindData,
		Destructive: true,
		Action:      ActionPreserve,
		Resource:    state.Resource{Provider: "host", Type: typ, Name: path},
		Detail:      what + ", preserved by default",
	}
	if deleteData {
		it.Action = ActionRemove
		it.Detail = "PERMANENTLY DELETE " + what
	}
	return it
}

// Report prints the plan. It changes nothing and is safe to call on its own.
func (p Plan) Report(u *ui.UI) {
	u.Say("Teardown plan for deployment %s. Nothing has been removed yet.", p.DeploymentID)

	if len(p.Connectors) > 0 {
		u.Say("")
		u.Say("First, before anything is deleted:")
		for _, c := range p.Connectors {
			u.Say("  stop the Cloudflare connector %s, so the tunnel has no active connections", c)
		}
	}

	if rm := p.Removable(); len(rm) > 0 {
		u.Say("")
		u.Say("Then remove, in this order:")
		for i, it := range rm {
			u.Say("  %d. %s", i+1, it)
			u.Say("       %s", it.Detail)
			if it.Resource.Ownership != "" {
				u.Say("       created by this deployment: %s", it.Resource.Ownership)
			}
		}
	} else {
		u.Say("")
		u.Say("Nothing recorded by this deployment is eligible for removal.")
	}

	if d := p.Destroys(); len(d) > 0 {
		u.Say("")
		u.Say("PERMANENT DELETION was asked for. These are destroyed and cannot be recovered:")
		for _, it := range d {
			u.Say("  %s", it.Resource.Name)
			u.Say("       %s", it.Detail)
		}
	}

	if wp := p.filter(ActionWithParent); len(wp) > 0 {
		u.Say("")
		u.Say("Removed as a dependency of something above, never deleted separately:")
		for _, it := range wp {
			u.Say("  %s — %s", it, it.Detail)
		}
	}

	if pr := p.Preserved(); len(pr) > 0 {
		u.Say("")
		u.Say("Kept:")
		for _, it := range pr {
			u.Say("  %s — %s", it, it.Detail)
		}
	}

	if rv := p.Review(); len(rv) > 0 {
		u.Say("")
		u.Say("NOT eligible, and teardown stops until a person has looked at them:")
		for _, it := range rv {
			u.Say("  %s — %s", it, it.Detail)
		}
	}

	p.Reconciled.report(u.Say)

	u.Say("")
	u.Say("Pre-existing resources are never offered here: this deployment records only what it created.")
	settings.Report(u, p.Settings)
}

// Ops is the removal seam, one function per step. A nil function is not a
// silent skip: the step is reported as retained, saying no removal is
// implemented, and the run does not claim to be complete.
type Ops struct {
	StopConnector    func(ctx context.Context, container string) error
	DeleteDNSRecord  func(ctx context.Context, providerID string) error
	DeleteAccessApp  func(ctx context.Context, providerID string) error
	DeleteTunnel     func(ctx context.Context, providerID string) error
	DeleteEntraApp   func(ctx context.Context, providerID string) error
	DeleteEntraGroup func(ctx context.Context, providerID string) error
	// RemoveHostUnits removes every unit at once and returns the paths it
	// removed, because the units share one binary copy whose removal must
	// come after all of them. See HostUnits.
	RemoveHostUnits func(ctx context.Context) (removed []string, err error)
	// RemoveContainers takes the whole stack down in one call.
	RemoveContainers func(ctx context.Context) error
	// ContainersPresent reports which of these container names still exist
	// after that call. A nil seam leaves the removal step's own account of
	// itself as the only evidence, which is how a still-present path was
	// once reported as removed; see hostUnitOutcomes.
	ContainersPresent func(ctx context.Context, names []string) (present []string, err error)
	// RemoveRendered removes what this deployment rendered into dir and
	// returns whatever else is still there, so a directory that now holds
	// unrelated content is preserved rather than deleted.
	RemoveRendered func(ctx context.Context, dir string) (leftover []string, err error)
	// RemoveCredentials removes the named credential files from dir, and
	// returns whatever else is still there, on the same rule.
	RemoveCredentials func(ctx context.Context, dir string, names []string) (leftover []string, err error)
	// RemoveTree permanently deletes one content directory.
	RemoveTree func(ctx context.Context, path string) error
}

// Outcome statuses.
const (
	// StatusRemoved: gone, and no longer in the deployment record.
	StatusRemoved = "removed"
	// StatusPreserved: kept on purpose. Not residue.
	StatusPreserved = "preserved"
	// StatusRetained: eligible, but the provider refused at deletion time
	// because the ownership marker no longer proves it is ours, or no
	// removal is implemented. Residue, and never success.
	StatusRetained = "retained"
	// StatusFailed: the delete was attempted and errored. Residue. The
	// resource stays in the record so a later run can try again.
	StatusFailed = "failed"
	// StatusUncertain: a phase that intended to create resources did not
	// succeed, and its provider could not be asked what it left behind.
	// Residue by construction — nothing proves there is nothing there — so
	// the teardown is not reported complete and the record is kept.
	StatusUncertain = "uncertain"
)

// Outcome is what happened to one item.
type Outcome struct {
	Item   Item
	Status string
	Detail string
}

// Result is the end-of-run report.
type Result struct {
	Outcomes []Outcome
	// Notes are things worth saying that are not residue, such as a
	// connector that was already stopped.
	Notes []string
	// Unrestored are pre-existing settings still waiting for a person.
	Unrestored []settings.Entry
	// Unowned are resources found at a provider that match this
	// deployment's naming but carry no ownership marker. Nothing was done
	// to them and nothing will be; they are reported for review. They are
	// not residue: they were never this deployment's.
	Unowned []state.Resource
}

func (r Result) with(status string) []Outcome {
	var out []Outcome
	for _, o := range r.Outcomes {
		if o.Status == status {
			out = append(out, o)
		}
	}
	return out
}

// Residue is everything eligible that is still there, and everything that
// could not be shown to be gone. Uncertain work counts: the specification
// forbids reporting a complete teardown with unexplained residue, and work
// nobody could check is exactly that.
func (r Result) Residue() []Outcome {
	out := append(r.with(StatusRetained), r.with(StatusFailed)...)
	return append(out, r.with(StatusUncertain)...)
}

// Complete reports whether the teardown left no residue. Items preserved on
// purpose do not make it incomplete; they are explained in the report.
func (r Result) Complete() bool {
	return len(r.Residue()) == 0 && len(r.Unrestored) == 0
}

// Report prints what happened.
func (r Result) Report(u *ui.UI) {
	u.Say("")
	if rm := r.with(StatusRemoved); len(rm) > 0 {
		u.Say("Removed:")
		for _, o := range rm {
			u.Say("  %s", o.Item)
		}
	}
	if pr := r.with(StatusPreserved); len(pr) > 0 {
		u.Say("Kept, as planned:")
		for _, o := range pr {
			u.Say("  %s — %s", o.Item, o.Detail)
		}
	}
	for _, n := range r.Notes {
		u.Say("Note: %s", n)
	}
	if len(r.Unowned) > 0 {
		u.Say("Found by name only and left untouched, because nothing proves they are this deployment's:")
		for _, res := range r.Unowned {
			u.Say("  %s %s %s — review by hand", res.Provider, res.Type, res.Name)
		}
	}
	if res := r.Residue(); len(res) > 0 {
		u.Say("Still present, or not shown to be gone:")
		for _, o := range res {
			u.Say("  %s (%s) — %s", o.Item, o.Status, o.Detail)
		}
		u.Say("The deployment record is kept, so running teardown again retries each of them.")
	}
	for _, e := range r.Unrestored {
		u.Say("Not restored: %s — restoring a pre-existing setting needs interactive approval.", e.Change.Target)
	}
	if r.Complete() {
		u.Say("Teardown is complete. Nothing eligible is outstanding.")
	} else {
		u.Say("Teardown is NOT complete. The items above are still there.")
	}
}

// Options configures one run.
type Options struct {
	// Consent is the explicit command-line consent an unattended run needs.
	// It does not override ambiguity and it does not permit deletion.
	Consent bool
	// Registry is the provider accessors internal/settings restores through.
	Registry settings.Registry
	// Save persists the deployment record; called after every removal, so
	// an interruption never loses the fact that something is already gone.
	// It may be nil in tests.
	Save func() error
}

// Run presents the plan, takes approval, and removes what was approved.
//
// It writes nothing until approval is given: an unattended run without
// consent, a declined prompt, and anything needing review all return with
// every resource untouched.
func Run(ctx context.Context, st *state.State, plan Plan, ops Ops, u *ui.UI, o Options) (Result, error) {
	plan.Report(u)

	if rv := plan.Review(); len(rv) > 0 {
		var names []string
		for _, it := range rv {
			names = append(names, it.String())
		}
		return Result{}, fmt.Errorf("%w: %d recorded resource(s) cannot be shown to be this deployment's own work: %s. Nothing was removed",
			ErrReviewRequired, len(rv), strings.Join(names, ", "))
	}

	if len(plan.Removable()) == 0 {
		u.Say("")
		u.Say("There is nothing to remove.")
		// "Nothing recorded" is not the same as "nothing there". Work a
		// provider could not confirm is still outstanding, and saying the
		// teardown is complete here is the defect this guards against.
		res := plan.Reconciled.seed()
		res.Report(u)
		if !res.Complete() {
			return res, incomplete(res)
		}
		return res, nil
	}

	switch {
	case !u.Interactive && !o.Consent:
		return Result{}, fmt.Errorf("%w: teardown would remove %d resource(s) listed above. Re-run on a terminal, or pass explicit consent. Nothing was removed",
			ErrApprovalRequired, len(plan.Removable()))
	case !u.Interactive:
		u.Say("")
		u.Say("Continuing without prompts: explicit consent was given on the command line.")
	default:
		ok, err := u.Confirm(fmt.Sprintf("Remove the %d resource(s) listed above?", len(plan.Removable())))
		if err != nil {
			return Result{}, err
		}
		if !ok {
			u.Say("Nothing was removed.")
			return Result{}, nil
		}
		if len(plan.Destroys()) > 0 {
			ok, err := u.Confirm("Permanently delete the data listed above? It cannot be recovered.")
			if err != nil {
				return Result{}, err
			}
			if !ok {
				u.Say("The data is kept. Everything else still goes.")
				plan = plan.keepData()
			}
		}
	}

	// Restoring a changed pre-existing setting comes before any delete: the
	// restore writes to the object, so the object has to still exist.
	res := plan.Reconciled.seed()
	if len(plan.Settings) > 0 {
		if u.Interactive {
			if err := settings.Restore(ctx, st, o.Registry, u, o.Save); err != nil {
				return res, err
			}
		}
		for _, e := range plan.Settings {
			if e.Index < len(st.Changes) && st.Changes[e.Index].RestoredAt != nil {
				continue // restored just now
			}
			if e.Status == settings.StatusDrifted {
				// The current value was preserved. That is the correct
				// outcome, not residue, so it is reported and not counted.
				res.Notes = append(res.Notes,
					fmt.Sprintf("%s was left as it is: it changed after this tool applied its value", e.Change.Target))
				continue
			}
			res.Unrestored = append(res.Unrestored, e)
		}
	}

	for _, c := range plan.Connectors {
		if ops.StopConnector == nil {
			res.Notes = append(res.Notes, "no way to stop connector "+c+"; the tunnel delete cascades its connections")
			continue
		}
		if err := ops.StopConnector(ctx, c); err != nil {
			// Best effort by design: a connector that is already gone is
			// the state we wanted. Said out loud rather than swallowed.
			res.Notes = append(res.Notes, fmt.Sprintf("stopping connector %s reported: %v. The tunnel delete cascades its connections, so removal continued", c, err))
		}
	}

	for _, k := range Order {
		step := runStep(ctx, k, plan, ops)
		res.Outcomes = append(res.Outcomes, step...)
		// Drop what is gone before the next step, and persist it, so an
		// interruption never leaves a removed resource recorded as present,
		// and a failed one stays recorded for the next run to retry.
		for _, out := range step {
			if out.Status == StatusRemoved {
				dropResource(st, out.Item.Resource.ID)
			}
		}
		if o.Save != nil {
			if err := o.Save(); err != nil {
				return res, err
			}
		}
	}
	for _, it := range plan.Preserved() {
		res.Outcomes = append(res.Outcomes, Outcome{Item: it, Status: StatusPreserved, Detail: it.Detail})
	}

	res.Report(u)
	if !res.Complete() {
		return res, incomplete(res)
	}
	return res, nil
}

// incomplete is the one error a run with residue ends with.
func incomplete(res Result) error {
	return fmt.Errorf("%w: %d item(s) are still present or could not be checked, and %d pre-existing setting(s) are not restored",
		ErrIncomplete, len(res.Residue()), len(res.Unrestored))
}

// runStep removes everything in one step of the order, and then accounts
// for the dependencies that step removed with it.
func runStep(ctx context.Context, k Kind, plan Plan, ops Ops) []Outcome {
	out := removeStep(ctx, k, plan, ops)

	// A dependency has no delete of its own: the parent's delete took it.
	// Account for it only when nothing of this step was left behind, so a
	// parent that is still there never makes its dependency look gone.
	for _, o := range out {
		if o.Status == StatusRetained || o.Status == StatusFailed {
			return out
		}
	}
	for _, it := range plan.filter(ActionWithParent) {
		if it.Kind == k {
			out = append(out, Outcome{Item: it, Status: StatusRemoved, Detail: it.Detail})
		}
	}
	return out
}

func removeStep(ctx context.Context, k Kind, plan Plan, ops Ops) []Outcome {
	var items []Item
	for _, it := range plan.Removable() {
		if it.Kind == k {
			items = append(items, it)
		}
	}
	if len(items) == 0 {
		return nil
	}

	switch k {
	case KindHostUnit:
		return hostUnitOutcomes(ctx, items, ops)
	case KindContainer:
		return containerOutcomes(ctx, items, ops)
	case KindCredential:
		if ops.RemoveCredentials == nil {
			return bulk(items, errNotImplemented)
		}
		return dirOutcomes(items, func(dir string) ([]string, error) {
			return ops.RemoveCredentials(ctx, dir, credentialNames(plan))
		})
	case KindConfigDir:
		if ops.RemoveRendered == nil {
			return bulk(items, errNotImplemented)
		}
		return dirOutcomes(items, func(dir string) ([]string, error) {
			return ops.RemoveRendered(ctx, dir)
		})
	}

	var one func(context.Context, string) error
	switch k {
	case KindDNSRecord:
		one = ops.DeleteDNSRecord
	case KindAccessApp:
		one = ops.DeleteAccessApp
	case KindTunnel:
		one = ops.DeleteTunnel
	case KindEntraApp:
		one = ops.DeleteEntraApp
	case KindEntraGroup:
		one = ops.DeleteEntraGroup
	case KindData:
		one = ops.RemoveTree
	}

	var out []Outcome
	for _, it := range items {
		if one == nil {
			out = append(out, Outcome{Item: it, Status: StatusRetained,
				Detail: "no removal is implemented for it in this run"})
			continue
		}
		target := it.Resource.ProviderID
		if k == KindData {
			target = it.Resource.Name
		}
		out = append(out, outcome(it, one(ctx, target)))
	}
	return out
}

// hostUnitOutcomes removes every unit in one call, because they share one
// binary copy that must outlive all of them.
//
// Every path is then re-checked on disk, and that check — not the removal
// step's own account of itself — decides what is reported as removed. A live
// teardown listed the shared binary /usr/local/lib/guacdeploy/guacdeploy
// under "Removed" while it was still on the host, because a nil error was
// read as "all of them went": each package here removes only what still
// carries this deployment's marker, and each leaves the shared binary alone
// while another unit still calls it, both without an error. The filesystem
// is the only thing that knows.
func hostUnitOutcomes(ctx context.Context, items []Item, ops Ops) []Outcome {
	if ops.RemoveHostUnits == nil {
		return bulk(items, errNotImplemented)
	}
	removed, err := ops.RemoveHostUnits(ctx)
	gone := map[string]bool{}
	for _, p := range removed {
		gone[p] = true
	}
	var out []Outcome
	for _, it := range items {
		path := it.Resource.Name
		switch {
		case !onDisk(path):
			// Absent is removed, whether this run took it or an earlier one
			// did. That is what makes a second run safe.
			out = append(out, Outcome{Item: it, Status: StatusRemoved})
		case err != nil:
			out = append(out, outcome(it, err))
		case gone[path]:
			out = append(out, Outcome{Item: it, Status: StatusRetained,
				Detail: "the removal step reported removing it, but " + path + " is still on this host"})
		default:
			out = append(out, Outcome{Item: it, Status: StatusRetained,
				Detail: "the removal step reported no error, but " + path + " is still on this host"})
		}
	}
	return out
}

// containerOutcomes takes the stack down in one call and then asks the
// container runtime which of the recorded names are still there, on the same
// rule as hostUnitOutcomes: the removal step's own account of itself is not
// evidence. "docker compose down" exits 0 for a project it can see, so a
// container this deployment created under a project name the current
// configuration no longer produces — an installation directory renamed
// between runs — is left running and reported as removed.
func containerOutcomes(ctx context.Context, items []Item, ops Ops) []Outcome {
	if ops.RemoveContainers == nil {
		return bulk(items, errNotImplemented)
	}
	err := ops.RemoveContainers(ctx)
	if ops.ContainersPresent == nil {
		return bulk(items, err)
	}
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Resource.Name)
	}
	present, checkErr := ops.ContainersPresent(ctx, names)
	if checkErr != nil {
		// Unanswerable is never evidence of removal. It is residue, so the
		// run reports what to check instead of claiming completeness.
		var out []Outcome
		for _, it := range items {
			out = append(out, Outcome{Item: it, Status: StatusUncertain,
				Detail: fmt.Sprintf("the removal step reported %v, but whether %s is still running could not be checked: %v",
					result(err), it.Resource.Name, checkErr)})
		}
		return out
	}
	still := map[string]bool{}
	for _, n := range present {
		still[n] = true
	}
	var out []Outcome
	for _, it := range items {
		switch {
		case !still[it.Resource.Name]:
			// Gone is removed, whether this run took it or an earlier one
			// did. That is what makes a second run safe.
			out = append(out, Outcome{Item: it, Status: StatusRemoved})
		case err != nil:
			out = append(out, outcome(it, err))
		default:
			out = append(out, Outcome{Item: it, Status: StatusRetained,
				Detail: "the removal step reported no error, but container " + it.Resource.Name + " is still on this host"})
		}
	}
	return out
}

// result words a removal step's own outcome for a report that cannot rely on
// it either way.
func result(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}

// onDisk reports whether the path is still there. Anything other than a
// plain "it is not there" counts as still there: a stat this process cannot
// answer is never evidence that something was removed.
func onDisk(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, os.ErrNotExist)
}

// credentialNames is the credential files recorded under the credential
// directory. Their names are recorded, not their paths, because the file
// name depends on the credential mode.
func credentialNames(plan Plan) []string {
	var out []string
	for _, it := range plan.Items {
		if it.Resource.Provider == "host" &&
			(it.Resource.Type == "credential-file" || it.Resource.Type == "credential-sealed") {
			out = append(out, it.Resource.Name)
		}
	}
	return out
}

// dirOutcomes removes a created directory's own content and preserves the
// directory itself when it now holds something else. This is the
// specification's "preserve a created resource that now supports unrelated
// use", in the two places in this codebase where it can happen: the
// installation directory and the credential directory. A created DNS zone,
// the specification's own worked example, cannot arise here at all —
// internal/cloudflare creates no zone and has no zone deletion.
func dirOutcomes(items []Item, remove func(dir string) ([]string, error)) []Outcome {
	var out []Outcome
	for _, it := range items {
		leftover, err := remove(it.Resource.Name)
		switch {
		case err != nil:
			out = append(out, outcome(it, err))
		case len(leftover) > 0:
			sort.Strings(leftover)
			out = append(out, Outcome{Item: it, Status: StatusPreserved,
				Detail: fmt.Sprintf("the rendered files are gone; %s stays because it still holds %s",
					it.Resource.Name, strings.Join(leftover, ", "))})
		default:
			// Removal is taken from the operation that performed it:
			// removeIfEmpty removes the directory itself and returns that
			// os.Remove's error, so a directory reported gone here is gone.
			out = append(out, Outcome{Item: it, Status: StatusRemoved})
		}
	}
	return out
}

var errNotImplemented = errors.New("no removal is implemented for it in this run")

func call0(ctx context.Context, f func(context.Context) error) error {
	if f == nil {
		return errNotImplemented
	}
	return f(ctx)
}

// bulk applies one result to every item of a step.
func bulk(items []Item, err error) []Outcome {
	out := make([]Outcome, 0, len(items))
	for _, it := range items {
		out = append(out, outcome(it, err))
	}
	return out
}

// outcome turns one delete result into a reportable outcome. A provider that
// refuses because its ownership marker no longer proves the resource is ours
// is retained, never a success and never a plain failure.
func outcome(it Item, err error) Outcome {
	switch {
	case err == nil:
		return Outcome{Item: it, Status: StatusRemoved}
	case errors.Is(err, errNotImplemented):
		return Outcome{Item: it, Status: StatusRetained, Detail: err.Error()}
	case NotOwned(err):
		return Outcome{Item: it, Status: StatusRetained,
			Detail: "left in place: it no longer carries this deployment's ownership marker: " + err.Error()}
	}
	return Outcome{Item: it, Status: StatusFailed, Detail: err.Error()}
}

// NotOwned reports whether a provider refused a delete because the target is
// not this deployment's to remove.
func NotOwned(err error) bool {
	return errors.Is(err, entra.ErrNotOwned) || errors.Is(err, cloudflare.ErrNotOwned)
}

// dropResource removes one resource from the record by ID. Items with no ID
// are content, not recorded resources, and change nothing here.
func dropResource(st *state.State, id string) {
	if id == "" {
		return
	}
	out := st.Resources[:0]
	for _, r := range st.Resources {
		if r.ID != id {
			out = append(out, r)
		}
	}
	st.Resources = out
}
