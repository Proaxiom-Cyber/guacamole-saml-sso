package teardown

// Reconciliation is the other half of "only what this deployment created".
//
// state.Resources is what was *recorded*, and a phase can create several
// cloud resources and then fail before any of them is saved: entra.Apply
// creates an application, a service principal, a signing certificate, two
// groups and two role assignments, and an error partway through returns
// without one resource ID reaching the record. Treating the resource list as
// the whole truth is how a real lab teardown reported "Teardown is complete.
// Nothing eligible is outstanding." while an Entra application, its service
// principal and a group were still in the tenant.
//
// The journal is the missing half. runPhases writes a state.Action per phase
// before the work, so a phase whose latest attempt is failed, uncertain or
// interrupted is a reconciliation obligation: it intended to create things,
// and what it actually created is unknown until a provider is asked.
//
// The rules for asking:
//
//   - Ask by this deployment's exact ownership marker, using the marker
//     conventions the provider packages already implement. Nothing here
//     invents a second convention.
//   - Marker-verified is eligible for removal, and goes into the record so
//     the plan shows it, the operator approves it, and a retry still has it.
//   - A name match without the marker is never touched. It is reported for
//     review, and it does not stop the teardown of everything else: it was
//     never this deployment's to begin with.
//   - A provider that cannot be asked at all — no credential, no network, an
//     API error — is uncertain work. It is reported with what to check, and
//     the teardown is not complete while it stands.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// Found is one provider's answer to "what of this deployment's is there?".
// A Finder never deletes and never creates; building it is a query.
type Found struct {
	// Owned are the resources whose ownership marker proves they are this
	// deployment's. Only these are eligible for removal.
	Owned []state.Resource
	// Unowned are resources that match this deployment's naming but carry
	// no marker. They are never removed and always reported.
	Unowned []state.Resource
}

// Finder queries one provider by this deployment's ownership marker. An
// error means the provider could not be asked; it is not an empty answer.
type Finder func(ctx context.Context) (Found, error)

// Finders is one Finder per provider, keyed the way the deployment record
// keys providers: "entra", "cloudflare". See WIRING.md for what the command
// passes and how each one checks its marker.
type Finders map[string]Finder

// creators maps a journalled phase intent onto the provider it creates at.
// A phase that is not listed here creates nothing a provider can be asked
// about, so a failed attempt at it leaves no provider residue.
//
// The Azure destination is deliberately absent: it is a separate command,
// not a session phase, so nothing journals an intent for it and there is no
// obligation to find. Add "azure-destination": "azure" here on the day it
// is journalled, and a Finder for it in WIRING.md.
var creators = map[string]string{
	"entra-signin":      "entra",
	"cloudflare-tunnel": "cloudflare",
	"cloudflare-dns":    "cloudflare",
	"cloudflare-access": "cloudflare",
}

// Obligation is a phase that intended to create provider resources and whose
// latest attempt did not succeed. What it created is unknown until the
// provider is asked, so it is never skipped.
type Obligation struct {
	Intent   string
	Provider string
	// Result is the journalled result of the latest attempt: failed,
	// uncertain, or interrupted when the run never got to write one.
	Result string
	// Detail is the journalled detail. It holds the creation intent the
	// phase wrote before the work ("will create in Entra: ...") whenever the
	// run was interrupted; a phase that returned an error overwrites it with
	// that error, which is why the phase name, not this text, decides that
	// there is an obligation.
	Detail string
}

// what describes what the obligation may have left behind, preferring the
// phase's own journalled creation intent when it survived.
func (o Obligation) what() string {
	if strings.HasPrefix(o.Detail, "will create") || strings.HasPrefix(o.Detail, "will issue") {
		return o.Detail
	}
	return "resources at " + o.Provider
}

// Obligations returns the journal's reconciliation obligations: the phases
// whose latest attempt did not succeed and that create provider resources.
// It reads the journal and changes nothing.
func Obligations(st *state.State) []Obligation {
	if st == nil {
		return nil
	}
	var out []Obligation
	for _, a := range st.Pending() {
		p, ok := creators[a.Intent]
		if !ok {
			continue
		}
		res := a.Result
		if a.FinishedAt == nil {
			res = "interrupted"
		}
		out = append(out, Obligation{Intent: a.Intent, Provider: p, Result: res, Detail: a.Detail})
	}
	return out
}

// Uncertainty is work that could not be checked. It is residue until it can
// be: a teardown is never reported complete while one stands.
type Uncertainty struct {
	Intent   string
	Provider string
	Detail   string
}

// Reconciliation is what asking the providers produced.
type Reconciliation struct {
	// Adopted are marker-verified resources that were not in the record.
	// They are in it now, so the plan offers them and a retry keeps them.
	Adopted []state.Resource
	// Unowned are name-only matches. Never removed, always reported.
	Unowned []state.Resource
	// Uncertain is work no provider could confirm either way.
	Uncertain []Uncertainty
}

// Empty reports whether reconciliation found nothing worth saying.
func (r Reconciliation) Empty() bool {
	return len(r.Adopted) == 0 && len(r.Unowned) == 0 && len(r.Uncertain) == 0
}

// Reconcile asks each provider that a failed phase creates at what of this
// deployment's is still there, and records what the ownership marker proves.
//
// It never deletes, it never resets the deployment record, and it never acts
// on a name match. A provider it cannot ask becomes uncertain work, which
// keeps the teardown from being reported complete and keeps the record for
// the next attempt.
func Reconcile(ctx context.Context, st *state.State, find Finders) Reconciliation {
	var rec Reconciliation
	asked := map[string]bool{}
	failed := map[string]error{}
	for _, ob := range Obligations(st) {
		f := find[ob.Provider]
		if f == nil {
			rec.Uncertain = append(rec.Uncertain, ob.uncertain(
				fmt.Sprintf("no %s query is wired into this run", ob.Provider)))
			continue
		}
		if !asked[ob.Provider] {
			asked[ob.Provider] = true
			got, err := f(ctx)
			if err != nil {
				failed[ob.Provider] = err
			} else {
				rec.adopt(st, got)
			}
		}
		if err := failed[ob.Provider]; err != nil {
			rec.Uncertain = append(rec.Uncertain, ob.uncertain(err.Error()))
		}
	}
	return rec
}

// uncertain builds the actionable status for work that could not be checked.
func (o Obligation) uncertain(why string) Uncertainty {
	return Uncertainty{
		Intent:   o.Intent,
		Provider: o.Provider,
		Detail: fmt.Sprintf("the %s phase ended %s, so it may have left %s; %s could not be checked: %s. "+
			"Check %s for resources carrying this deployment's ownership marker, then run teardown again",
			o.Intent, o.Result, o.what(), o.Provider, why, o.Provider),
	}
}

// adopt records the marker-verified resources and keeps the name-only
// matches for the report.
func (r *Reconciliation) adopt(st *state.State, got Found) {
	now := time.Now().UTC()
	for _, res := range got.Owned {
		if recorded(st, res) {
			continue // already in the record; the plan already offers it
		}
		if res.Ownership == "" {
			res.Ownership = "found at the provider by this deployment's ownership marker"
		}
		if res.CorrelationID == "" {
			res.CorrelationID = st.DeploymentID
		}
		if res.CreatedAt.IsZero() {
			res.CreatedAt = now
		}
		st.EnsureResource(res)
		r.Adopted = append(r.Adopted, res)
	}
	r.Unowned = append(r.Unowned, got.Unowned...)
}

// recorded reports whether the record already holds this resource, on the
// same provider/type/name identity state.EnsureResource uses.
func recorded(st *state.State, r state.Resource) bool {
	for _, e := range st.Resources {
		if e.Provider == r.Provider && e.Type == r.Type && e.Name == r.Name {
			return true
		}
	}
	return false
}

// outcome turns uncertain work into a reportable outcome. It carries no
// Kind: it is not a removal step, it is work that could not be accounted
// for, and it counts as residue.
//
// The detail is deliberately short here. The full explanation — what the
// phase may have left, why the provider could not be asked, and what to do
// about it — is printed once in its own section; repeating the whole
// sentence in the residue list made the same paragraph appear twice and
// buried the list it belongs to.
func (u Uncertainty) outcome() Outcome {
	return Outcome{
		Item: Item{
			Action:   ActionReview,
			Resource: state.Resource{Provider: u.Provider, Type: "unreconciled-phase", Name: u.Intent},
		},
		Status: StatusUncertain,
		Detail: "could not be checked; see above",
	}
}

// seed starts the run's result from what reconciliation already knows, so
// uncertain work and name-only matches are reported whether or not anything
// turns out to be removable.
func (r Reconciliation) seed() Result {
	res := Result{Unowned: r.Unowned}
	for _, u := range r.Uncertain {
		res.Outcomes = append(res.Outcomes, u.outcome())
	}
	return res
}

// report prints what asking the providers found, as part of the plan.
func (r Reconciliation) report(say func(string, ...any)) {
	if len(r.Adopted) > 0 {
		say("")
		say("Found at the provider and missing from the deployment record, because a phase failed before it could be saved.")
		say("Each one carries this deployment's ownership marker, so each one is eligible:")
		for _, res := range r.Adopted {
			say("  %s %s (%s) — %s", res.Provider, res.Type, res.Name, res.Ownership)
		}
	}
	if len(r.Unowned) > 0 {
		say("")
		say("Found by name only, and NEVER touched: nothing proves they are this deployment's. Review them by hand:")
		for _, res := range r.Unowned {
			say("  %s %s %s", res.Provider, res.Type, res.Name)
		}
	}
	if len(r.Uncertain) > 0 {
		say("")
		say("Could NOT be checked, so this teardown cannot be reported complete:")
		for _, u := range r.Uncertain {
			say("  %s — %s", u.Intent, u.Detail)
		}
	}
}
