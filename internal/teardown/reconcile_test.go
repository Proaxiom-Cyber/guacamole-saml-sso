package teardown

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// halfDone is the live lab sequence: the phase created resources at the
// provider and then failed, so the journal holds a failed attempt and
// state.Resources holds nothing at all.
func halfDone(intent, detail, result string) *state.State {
	started := time.Now().UTC().Add(-time.Minute)
	finished := started.Add(30 * time.Second)
	st := &state.State{
		DeploymentID: "dep1",
		Config: map[string]string{
			"guac-hostname": "guac.example.com",
			"admin-group":   "Guacamole Administrators",
		},
		Actions: []state.Action{
			{ID: "a0", Intent: "stack-up", CorrelationID: "c0", StartedAt: started,
				FinishedAt: &finished, Result: state.ResultOK},
			{ID: "a1", Intent: intent, CorrelationID: "c1", StartedAt: started,
				FinishedAt: &finished, Result: result, Detail: detail},
		},
	}
	return st
}

// entraResidue is what the tenant actually held after that failure: the
// application, its service principal and the administrators group, each
// carrying this deployment's marker, plus a group that only shares a name.
func entraResidue() Found {
	marker := "guacdeploy:dep1"
	return Found{
		Owned: []state.Resource{
			{Provider: "entra", Type: "application", ProviderID: "app-obj",
				Name: "Guacamole guac.example.com", Ownership: "marker " + marker + " in notes and tags"},
			{Provider: "entra", Type: "service-principal", ProviderID: "sp-obj",
				Name: "Guacamole guac.example.com", Ownership: "service principal of the marked application"},
			{Provider: "entra", Type: "group", ProviderID: "grp-obj",
				Name: "Guacamole Administrators", Ownership: "marker " + marker + " in the group description"},
		},
		Unowned: []state.Resource{
			{Provider: "entra", Type: "group", ProviderID: "other-grp", Name: "Guacamole Administrators"},
		},
	}
}

// runReconciled is the wiring WIRING.md asks the command for: reconcile the
// journal against the providers, then plan, then run.
func runReconciled(t *testing.T, st *state.State, rec *recorder, find Finders, answers string, o Options) (Result, error, string) {
	t.Helper()
	u, out := testUI(answers)
	r := Reconcile(context.Background(), st, find)
	plan := BuildPlan(st, nil, false)
	plan.Reconciled = r
	res, err := Run(context.Background(), st, plan, rec.ops(), u, o)
	return res, err, out.String()
}

// The defect, exactly as the lab produced it. entra.Apply created the
// application, the service principal and a group; the phase then failed and
// nothing reached state.Resources. Teardown must find them through the
// journalled intent and the ownership marker, remove exactly those, and
// leave the same-named group that carries no marker alone.
func TestFailedEntraPhaseLeavesNoUnrecordedResidue(t *testing.T) {
	st := halfDone("entra-signin", "the sign-in configuration could not be verified: 404", state.ResultFailed)
	if len(st.Resources) != 0 {
		t.Fatal("the fixture must start with nothing recorded")
	}
	// Without reconciliation there is nothing to remove at all: this is the
	// exact state that reported a complete teardown on the lab.
	if len(BuildPlan(st, nil, false).Removable()) != 0 {
		t.Fatal("the fixture is wrong: the record is supposed to be empty")
	}

	rec := newRecorder()
	find := Finders{"entra": func(context.Context) (Found, error) { return entraResidue(), nil }}
	res, err, out := runReconciled(t, st, rec, find, "", Options{Consent: true})
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	if !res.Complete() {
		t.Fatalf("teardown did not finish: %+v", res.Residue())
	}

	// Exactly the marker-verified resources, and the service principal goes
	// with its application rather than separately.
	for _, want := range []string{"entra-app:app-obj", "entra-group:grp-obj"} {
		rec.index(t, want)
	}
	for _, c := range rec.calls {
		if strings.Contains(c, "other-grp") {
			t.Errorf("a name-only match was deleted: %s", c)
		}
		if c == "entra-app:sp-obj" {
			t.Error("the service principal was deleted separately")
		}
	}
	if len(rec.calls) != 2 {
		t.Errorf("want two provider deletes, got %v", rec.calls)
	}

	// The name-only match is reported for review, in the plan and again at
	// the end, and it is never offered for removal.
	if !strings.Contains(out, "review by hand") || strings.Count(out, "other-grp")+strings.Count(out, "Guacamole Administrators") == 0 {
		t.Errorf("the name-only match was not reported for review:\n%s", out)
	}
	if len(res.Unowned) != 1 || res.Unowned[0].ProviderID != "other-grp" {
		t.Errorf("want the unmarked group reported, got %+v", res.Unowned)
	}
	if len(st.Resources) != 0 {
		t.Errorf("removed resources are still recorded: %+v", st.Resources)
	}
}

// The same failure with a provider that cannot be answered for. Nothing is
// removed, the work is reported as uncertain with what to check, and the run
// never claims a complete teardown.
func TestUnqueryableProviderIsUncertainNotComplete(t *testing.T) {
	for _, tc := range []struct {
		name string
		find Finders
		want string
	}{
		{"no credential wired", Finders{}, "no entra query is wired into this run"},
		{"the API refused", Finders{"entra": func(context.Context) (Found, error) {
			return Found{}, errors.New("Graph returned 403 Insufficient privileges")
		}}, "403"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := halfDone("entra-signin", "will create in Entra: application Guacamole, group Guacamole Administrators", state.ResultUncertain)
			rec := newRecorder()
			res, err, out := runReconciled(t, st, rec, tc.find, "", Options{Consent: true})

			if !errors.Is(err, ErrIncomplete) {
				t.Fatalf("want ErrIncomplete, got %v", err)
			}
			if res.Complete() {
				t.Fatal("the run claimed completeness with work it could not check")
			}
			if strings.Contains(out, "Teardown is complete") {
				t.Errorf("the report claimed a complete teardown:\n%s", out)
			}
			if len(rec.calls) != 0 {
				t.Errorf("nothing may be removed on an unchecked provider: %v", rec.calls)
			}
			if got := res.Residue(); len(got) != 1 || got[0].Status != StatusUncertain {
				t.Fatalf("want one uncertain outcome, got %+v", got)
			}
			for _, want := range []string{"entra-signin", tc.want, "run teardown again"} {
				if !strings.Contains(out, want) {
					t.Errorf("the status does not say %q:\n%s", want, out)
				}
			}
			// Enough state to retry: the journal keeps the attempt.
			if len(st.Actions) != 2 {
				t.Error("the journal was reset on a failed query")
			}
		})
	}
}

// The same treatment for a Cloudflare phase: an interrupted tunnel phase
// records nothing, so the tunnel is found by its marker name and the
// prefix-only match beside it is left alone.
func TestFailedCloudflarePhaseIsReconciled(t *testing.T) {
	st := halfDone("cloudflare-tunnel", "will create Cloudflare tunnel guacdeploy-guac.example.com-dep1", state.ResultFailed)
	rec := newRecorder()
	find := Finders{"cloudflare": func(context.Context) (Found, error) {
		return Found{
			Owned: []state.Resource{{Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-9",
				Name: "guacdeploy-guac.example.com-dep1", Ownership: "deployment ID embedded in the tunnel name"}},
			Unowned: []state.Resource{{Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-other",
				Name: "guacdeploy-guac.example.com-someone-else"}},
		}, nil
	}}
	res, err, out := runReconciled(t, st, rec, find, "", Options{Consent: true})
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	rec.index(t, "tunnel:tun-9")
	for _, c := range rec.calls {
		if strings.Contains(c, "tun-other") {
			t.Errorf("a prefix-only match was deleted: %s", c)
		}
	}
	if len(res.Unowned) != 1 {
		t.Errorf("want the unmarked tunnel reported, got %+v", res.Unowned)
	}
	if !strings.Contains(out, "guacdeploy-guac.example.com-someone-else") {
		t.Error("the unmarked tunnel was not reported")
	}
	if !res.Complete() {
		t.Errorf("teardown did not finish: %+v", res.Residue())
	}

	// And with nothing wired for Cloudflare, the same phase is uncertain.
	st2 := halfDone("cloudflare-dns", "will create DNS record guac.example.com -> tun.cfargotunnel.com", state.ResultUncertain)
	rec2 := newRecorder()
	_, err2, out2 := runReconciled(t, st2, rec2, nil, "", Options{Consent: true})
	if !errors.Is(err2, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err2)
	}
	if !strings.Contains(out2, "cloudflare-dns") || strings.Contains(out2, "Teardown is complete") {
		t.Errorf("the unchecked DNS phase was not reported as outstanding:\n%s", out2)
	}
}

// An adopted resource that a provider then refuses to delete stays in the
// record, so the next run retries it instead of losing it again.
func TestAdoptedResourceSurvivesAFailedDelete(t *testing.T) {
	st := halfDone("entra-signin", "boom", state.ResultFailed)
	rec := newRecorder()
	rec.fail["entra-group:grp-obj"] = errors.New("Graph returned 503")
	find := Finders{"entra": func(context.Context) (Found, error) { return entraResidue(), nil }}
	if _, err, _ := runReconciled(t, st, rec, find, "", Options{Consent: true}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	var left []string
	for _, r := range st.Resources {
		left = append(left, r.Type)
	}
	if len(left) != 1 || left[0] != "group" {
		t.Fatalf("want only the failed group left in the record, got %v", left)
	}
}

// A phase that succeeded is not an obligation, and a deployment with no
// failed creation phase never asks a provider anything.
func TestSuccessfulPhasesAreNotReconciled(t *testing.T) {
	st := fullState()
	fin := time.Now().UTC()
	st.Actions = []state.Action{
		{ID: "a1", Intent: "entra-signin", StartedAt: fin, FinishedAt: &fin, Result: state.ResultOK},
		{ID: "a2", Intent: "host-preflight", StartedAt: fin, FinishedAt: &fin, Result: state.ResultFailed},
	}
	asked := false
	find := Finders{"entra": func(context.Context) (Found, error) { asked = true; return Found{}, nil }}
	if r := Reconcile(context.Background(), st, find); !r.Empty() {
		t.Fatalf("want nothing to reconcile, got %+v", r)
	}
	if asked {
		t.Error("a completed phase made teardown query the provider")
	}
}

// A later attempt that succeeded settles the intent, even though an earlier
// attempt at it failed.
func TestOnlyTheLatestAttemptDecides(t *testing.T) {
	fin := time.Now().UTC()
	st := halfDone("entra-signin", "boom", state.ResultFailed)
	st.Actions = append(st.Actions, state.Action{
		ID: "a2", Intent: "entra-signin", StartedAt: fin, FinishedAt: &fin, Result: state.ResultOK})
	if got := Obligations(st); len(got) != 0 {
		t.Fatalf("a settled intent is not an obligation: %+v", got)
	}
}

// Removed means gone. A step that reports a removal without the path
// disappearing is caught, reported as retained with the reason, and the
// resource stays recorded for the next run.
//
// This is the second live defect: the report listed
// systemd-unit /usr/local/lib/guacdeploy/guacdeploy under "Removed:" and the
// file was still there after the reboot.
func TestRemovedOnlyWhenTheFileIsActuallyGone(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "guacdeploy")
	if err := os.WriteFile(unit, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := &state.State{DeploymentID: "dep1", Resources: []state.Resource{{
		ID: "r-unit", Provider: "host", Type: "systemd-unit", Name: unit,
		Ownership: "installed by this deployment",
	}}}

	// The removal step claims it removed the path. It did not.
	ops := Ops{RemoveHostUnits: func(context.Context) ([]string, error) { return []string{unit}, nil }}
	u, out := testUI("")
	res, err := Run(context.Background(), st, BuildPlan(st, nil, false), ops, u, Options{Consent: true})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if strings.Contains(out.String(), "Removed:") {
		t.Errorf("a path that is still on this host was reported as removed:\n%s", out.String())
	}
	if got := res.Residue(); len(got) != 1 || got[0].Status != StatusRetained {
		t.Fatalf("want one retained outcome, got %+v", got)
	}
	if !strings.Contains(out.String(), "is still on this host") {
		t.Error("the false claim was not explained")
	}
	if !has(st, "r-unit") {
		t.Error("a path that is still there was dropped from the record")
	}

	// With the file actually gone, the same step reports removal.
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	u2, out2 := testUI("")
	res2, err2 := Run(context.Background(), st, BuildPlan(st, nil, false), ops, u2, Options{Consent: true})
	if err2 != nil {
		t.Fatalf("teardown failed: %v", err2)
	}
	if !res2.Complete() || !strings.Contains(out2.String(), "Removed:") {
		t.Errorf("a genuinely removed path was not reported as removed:\n%s", out2.String())
	}
	if has(st, "r-unit") {
		t.Error("the removed unit is still recorded")
	}
}

// A unit file that this deployment never wrote is left in place by the
// removal step, which reports the refusal. The path is still there, so it is
// retained with the provider's own reason, not counted as removed.
func TestRefusedUnitIsRetainedWithItsReason(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "guacdeploy-backup.timer")
	if err := os.WriteFile(unit, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := &state.State{DeploymentID: "dep1", Resources: []state.Resource{{
		ID: "r-unit", Provider: "host", Type: "systemd-unit", Name: unit, Ownership: "installed by this deployment",
	}}}
	ops := Ops{RemoveHostUnits: func(context.Context) ([]string, error) {
		return nil, errors.New("left in place, not written by this deployment: " + unit)
	}}
	u, out := testUI("")
	res, err := Run(context.Background(), st, BuildPlan(st, nil, false), ops, u, Options{Consent: true})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if got := res.Residue(); len(got) != 1 || got[0].Status != StatusFailed {
		t.Fatalf("want the refusal reported as residue, got %+v", got)
	}
	if !strings.Contains(out.String(), "not written by this deployment") {
		t.Error("the refusal reason was not reported")
	}
}
