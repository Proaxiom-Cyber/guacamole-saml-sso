package teardown

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/settings"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func testUI(answers string) (*ui.UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui.UI{
		In:          bufio.NewReader(strings.NewReader(answers)),
		Out:         out,
		Interactive: answers != "",
	}, out
}

// fullState is one complete deployment record, as the setup session writes
// it. Pre-existing resources are absent by construction: the session never
// records one.
func fullState() *state.State {
	now := time.Now().UTC()
	st := &state.State{
		DeploymentID: "dep1",
		Config: map[string]string{
			"guac-hostname": "guac.example.com",
			"backup-dest":   "/srv/backups",
		},
	}
	for _, r := range []state.Resource{
		{ID: "r-cfg", Provider: "host", Type: "config-directory", Name: "/opt/guacamole", Ownership: "rendered by this deployment"},
		{ID: "r-data", Provider: "host", Type: "data-directory", Name: "/opt/guacamole/data", Ownership: "created by this deployment"},
		{ID: "r-cd", Provider: "docker", Type: "container", Name: "guacamole-cloudflared-1", Ownership: "created by this deployment"},
		{ID: "r-ng", Provider: "docker", Type: "container", Name: "guacamole-nginx-1", Ownership: "created by this deployment"},
		{ID: "r-app", Provider: "entra", Type: "application", ProviderID: "app-obj", Name: "Guacamole", Ownership: "creation response"},
		{ID: "r-sp", Provider: "entra", Type: "service-principal", ProviderID: "sp-obj", Name: "Guacamole", Ownership: "creation response"},
		{ID: "r-grp", Provider: "entra", Type: "group", ProviderID: "grp-obj", Name: "Guacamole Administrators", Ownership: "marker in description"},
		{ID: "r-tun", Provider: "cloudflare", Type: "tunnel", ProviderID: "tun-1", Name: "guacdeploy-guac-dep1", Ownership: "deployment ID in the name"},
		{ID: "r-rec", Provider: "cloudflare", Type: "dns-record", ProviderID: "rec-1", Name: "guac.example.com", Ownership: "marker comment"},
		{ID: "r-acc", Provider: "cloudflare", Type: "access-application", ProviderID: "acc-1", Name: "Guacamole guac (guacdeploy:dep1)", Ownership: "deployment ID in the name"},
		{ID: "r-pol", Provider: "cloudflare", Type: "access-policy", ProviderID: "pol-1", Name: "Guacamole guac", Ownership: "policy of the owned application"},
		{ID: "r-unit", Provider: "host", Type: "systemd-unit", Name: "/etc/systemd/system/guacdeploy-backup.timer", Ownership: "installed by this deployment"},
		{ID: "r-cdir", Provider: "host", Type: "credential-dir", Name: "/var/lib/guacdeploy/credentials", Ownership: "created by this deployment"},
		{ID: "r-cfile", Provider: "host", Type: "credential-file", Name: "cloudflare-api-token", Ownership: "written by this deployment"},
		{ID: "r-pkg", Provider: "host", Type: "package", Name: "docker-ce", Ownership: "installed by this deployment"},
		{ID: "r-svc", Provider: "host", Type: "service-enablement", Name: "docker", Ownership: "enabled by this deployment"},
	} {
		r.CreatedAt = now
		st.Resources = append(st.Resources, r)
	}
	return st
}

// recorder is the fake removal seam. Every call is logged in order, so the
// teardown order can be asserted directly.
type recorder struct {
	calls []string
	fail  map[string]error
}

func newRecorder() *recorder { return &recorder{fail: map[string]error{}} }

func (r *recorder) log(op, target string) error {
	r.calls = append(r.calls, op+":"+target)
	return r.fail[op+":"+target]
}

func (r *recorder) ops() Ops {
	one := func(op string) func(context.Context, string) error {
		return func(_ context.Context, t string) error { return r.log(op, t) }
	}
	return Ops{
		StopConnector:    one("stop"),
		DeleteDNSRecord:  one("dns"),
		DeleteAccessApp:  one("access"),
		DeleteTunnel:     one("tunnel"),
		DeleteEntraApp:   one("entra-app"),
		DeleteEntraGroup: one("entra-group"),
		RemoveTree:       one("tree"),
		RemoveHostUnits: func(context.Context) ([]string, error) {
			return []string{"/etc/systemd/system/guacdeploy-backup.timer"}, r.log("units", "")
		},
		RemoveContainers: func(context.Context) error { return r.log("containers", "") },
		RemoveRendered: func(_ context.Context, dir string) ([]string, error) {
			return nil, r.log("rendered", dir)
		},
		RemoveCredentials: func(_ context.Context, dir string, names []string) ([]string, error) {
			return nil, r.log("creds", dir+" "+strings.Join(names, ","))
		},
	}
}

func (r *recorder) index(t *testing.T, call string) int {
	t.Helper()
	for i, c := range r.calls {
		if c == call {
			return i
		}
	}
	t.Fatalf("call %q never happened; calls were %v", call, r.calls)
	return -1
}

func run(t *testing.T, st *state.State, rec *recorder, answers string, o Options, deleteData bool) (Result, error, string) {
	t.Helper()
	u, out := testUI(answers)
	plan := BuildPlan(st, nil, deleteData)
	res, err := Run(context.Background(), st, plan, rec.ops(), u, o)
	return res, err, out.String()
}

func has(st *state.State, id string) bool {
	for _, r := range st.Resources {
		if r.ID == id {
			return true
		}
	}
	return false
}

// The plan offers only what this deployment created. A pre-existing
// resource is never in the record, so it cannot be offered; a recorded
// resource with no ownership evidence is not offered either, and stops the
// run instead of being guessed at.
func TestPlanOffersOnlyCreatedResources(t *testing.T) {
	st := fullState()
	st.Resources = append(st.Resources, state.Resource{
		ID: "r-unknown", Provider: "entra", Type: "group",
		ProviderID: "other-grp", Name: "Existing Group", // no Ownership
	})

	plan := BuildPlan(st, nil, false)

	for _, it := range plan.Removable() {
		if it.Resource.ID == "r-unknown" {
			t.Fatal("a resource with no ownership evidence was offered for removal")
		}
	}
	if got := len(plan.Review()); got != 1 {
		t.Fatalf("want 1 item needing review, got %d", got)
	}
	if plan.Review()[0].Resource.ID != "r-unknown" {
		t.Fatalf("wrong item under review: %v", plan.Review()[0])
	}

	rec := newRecorder()
	u, out := testUI("y\ny\n")
	_, err := Run(context.Background(), st, plan, rec.ops(), u, Options{})
	if !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("want ErrReviewRequired, got %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("ambiguity must remove nothing, but calls were %v", rec.calls)
	}
	if !strings.Contains(out.String(), "Existing Group") {
		t.Error("the ambiguous resource was not shown to the operator")
	}
}

// Explicit consent does not override ambiguity.
func TestConsentDoesNotOverrideAmbiguity(t *testing.T) {
	st := fullState()
	st.Resources = append(st.Resources, state.Resource{
		ID: "r-unknown", Provider: "cloudflare", Type: "tunnel", ProviderID: "t9", Name: "someone else's",
	})
	rec := newRecorder()
	_, err, _ := run(t, st, rec, "", Options{Consent: true}, false)
	if !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("want ErrReviewRequired even with consent, got %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("nothing may be removed, but calls were %v", rec.calls)
	}
}

// An unattended run without consent stops before removing anything.
func TestUnattendedWithoutConsentRemovesNothing(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	res, err, out := run(t, st, rec, "", Options{}, false)

	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("want ErrApprovalRequired, got %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("nothing may be removed, but calls were %v", rec.calls)
	}
	if len(st.Resources) != len(fullState().Resources) {
		t.Fatalf("the record was changed: %d resources left", len(st.Resources))
	}
	if res.Complete() && len(res.Outcomes) > 0 {
		t.Error("a refused run must not report outcomes")
	}
	if !strings.Contains(out, "Nothing has been removed yet") {
		t.Error("the plan was not presented before stopping")
	}
}

// A declined prompt removes nothing either.
func TestDeclinedApprovalRemovesNothing(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	_, err, _ := run(t, st, rec, "n\n", Options{}, false)
	if err != nil {
		t.Fatalf("declining is not an error: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("nothing may be removed, but calls were %v", rec.calls)
	}
}

// The connector stops before the tunnel it serves is dismantled, and the
// DNS record, Access application and tunnel go in that order.
func TestRemovalOrder(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	_, err, _ := run(t, st, rec, "", Options{Consent: true}, false)
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}

	order := []string{
		"stop:guacamole-cloudflared-1",
		"dns:rec-1",
		"access:acc-1",
		"tunnel:tun-1",
		"entra-app:app-obj",
		"entra-group:grp-obj",
		"units:",
		"containers:",
		"creds:/var/lib/guacdeploy/credentials cloudflare-api-token",
		"rendered:/opt/guacamole",
	}
	prev := -1
	for _, c := range order {
		i := rec.index(t, c)
		if i <= prev {
			t.Fatalf("%s ran out of order; calls were %v", c, rec.calls)
		}
		prev = i
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "entra-app:sp-obj") {
			t.Error("the service principal was deleted separately; it is removed with its application")
		}
		if strings.HasPrefix(c, "access:pol-1") {
			t.Error("the Access policy was deleted separately; it is removed with its application")
		}
	}
}

// A dependency has no delete of its own. It leaves the record when its
// parent goes, and it stays when the parent stays, so a complete teardown
// never leaves a phantom behind and an incomplete one never lies.
func TestDependenciesLeaveTheRecordWithTheirParent(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	if _, err, _ := run(t, st, rec, "", Options{Consent: true}, false); err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	for _, id := range []string{"r-sp", "r-pol", "r-cfile"} {
		if has(st, id) {
			t.Errorf("%s outlived the parent that removed it", id)
		}
	}

	// With the parent retained, the dependency stays recorded too.
	st = fullState()
	rec = newRecorder()
	rec.fail["entra-app:app-obj"] = fmt.Errorf("%w: not ours", entra.ErrNotOwned)
	if _, err, _ := run(t, st, rec, "", Options{Consent: true}, false); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if !has(st, "r-sp") {
		t.Error("the service principal was dropped although its application is still there")
	}
}

// Packages and service enablement this deployment made are created
// resources that now support unrelated use. They are kept, and said so.
func TestInstalledPackagesArePreserved(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	res, err, out := run(t, st, rec, "", Options{Consent: true}, true)
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	if !has(st, "r-pkg") || !has(st, "r-svc") {
		t.Error("a preserved host change was dropped from the record")
	}
	for _, c := range rec.calls {
		if strings.Contains(c, "docker-ce") {
			t.Errorf("an installed package was removed: %s", c)
		}
	}
	if !strings.Contains(out, "the rest of this host may depend on it now") {
		t.Error("the kept package was not explained")
	}
	if !res.Complete() {
		t.Errorf("a deliberately kept host change made teardown incomplete: %+v", res.Residue())
	}
}

// Data, recordings and backups survive an ordinary teardown, and the plan
// says so.
func TestDataSurvivesOrdinaryTeardown(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	res, err, out := run(t, st, rec, "", Options{Consent: true}, false)
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "tree:") {
			t.Fatalf("content was deleted without explicit intent: %s", c)
		}
	}
	if !has(st, "r-data") {
		t.Error("the data directory was dropped from the record")
	}
	for _, want := range []string{"/opt/guacamole/data", "/opt/guacamole/recordings", "/srv/backups"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s was not shown as kept", want)
		}
	}
	if !res.Complete() {
		t.Error("preserved content must not make teardown incomplete")
	}
}

// Explicit intent destroys content, and only after the plan has shown
// exactly what it destroys.
func TestExplicitIntentDestroysAndShowsFirst(t *testing.T) {
	st := fullState()
	st.Config["azure-account"] = "acct"
	st.Config["azure-container"] = "backups"
	rec := newRecorder()
	_, err, out := run(t, st, rec, "", Options{Consent: true}, true)
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}

	shown := strings.Index(out, "PERMANENT DELETION")
	if shown < 0 {
		t.Fatal("the plan did not show what permanent deletion destroys")
	}
	warning := out[shown:]
	for _, want := range []string{"/opt/guacamole/data", "/opt/guacamole/recordings", "/srv/backups"} {
		if !strings.Contains(warning, want) {
			t.Errorf("%s was not listed under the permanent-deletion heading", want)
		}
		rec.index(t, "tree:"+want) // and it was actually deleted
	}
	if has(st, "r-data") {
		t.Error("the deleted data directory is still in the record")
	}
	// Remote backups are preserved whatever the intent: internal/azure has
	// no teardown at all.
	for _, c := range rec.calls {
		if strings.Contains(c, "acct/backups") {
			t.Errorf("a remote backup was removed: %s", c)
		}
	}
	if !strings.Contains(out, "remote backups are never removed") {
		t.Error("the preserved remote backups were not reported")
	}
}

// An operator who approves the teardown but declines the deletion keeps the
// content and loses everything else.
func TestDecliningDeletionKeepsContent(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	// yes to the teardown, no to the permanent deletion.
	_, err, _ := run(t, st, rec, "y\nn\n", Options{}, true)
	if err != nil {
		t.Fatalf("teardown failed: %v", err)
	}
	for _, c := range rec.calls {
		if strings.HasPrefix(c, "tree:") {
			t.Fatalf("content was deleted after the deletion was declined: %s", c)
		}
	}
	rec.index(t, "dns:rec-1") // the rest still went
	if has(st, "r-rec") {
		t.Error("a removed record is still in the deployment record")
	}
}

// A provider that refuses because the marker no longer proves ownership is
// reported as retained, never as success, and the resource stays recorded.
func TestNotOwnedIsRetainedNotSuccess(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	rec.fail["dns:rec-1"] = fmt.Errorf("record rec-1 does not carry marker: %w", cloudflare.ErrNotOwned)
	rec.fail["entra-group:grp-obj"] = fmt.Errorf("%w: group %q", entra.ErrNotOwned, "Guacamole Administrators")

	res, err, out := run(t, st, rec, "", Options{Consent: true}, false)

	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if res.Complete() {
		t.Fatal("the run claimed a complete teardown with residue left")
	}
	if got := len(res.Residue()); got != 2 {
		t.Fatalf("want 2 retained items, got %d: %+v", got, res.Residue())
	}
	for _, o := range res.Residue() {
		if o.Status != StatusRetained {
			t.Errorf("%v: want %s, got %s", o.Item, StatusRetained, o.Status)
		}
	}
	if !has(st, "r-rec") || !has(st, "r-grp") {
		t.Error("a retained resource was dropped from the record")
	}
	if !strings.Contains(out, "Teardown is NOT complete") {
		t.Error("the report claimed success")
	}
	if !strings.Contains(out, "ownership marker") {
		t.Error("the report did not explain why the resources were left")
	}
}

// A failed delete leaves the resource recorded, so a second run retries it
// and can finish.
func TestFailedDeleteIsRetryable(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	rec.fail["tunnel:tun-1"] = errors.New("Cloudflare returned 500")

	res, err, _ := run(t, st, rec, "", Options{Consent: true}, false)
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if got := res.Residue(); len(got) != 1 || got[0].Status != StatusFailed {
		t.Fatalf("want one failed outcome, got %+v", got)
	}
	if !has(st, "r-tun") {
		t.Fatal("the failed resource was dropped, so it can never be retried")
	}
	if has(st, "r-rec") {
		t.Error("a successful removal was not dropped from the record")
	}

	// Second run: the provider answers this time.
	rec2 := newRecorder()
	res2, err2, _ := run(t, st, rec2, "", Options{Consent: true}, false)
	if err2 != nil {
		t.Fatalf("the retry failed: %v", err2)
	}
	rec2.index(t, "tunnel:tun-1")
	if !res2.Complete() {
		t.Fatalf("the retry did not finish: %+v", res2.Residue())
	}
	if has(st, "r-tun") {
		t.Error("the retried resource is still recorded")
	}
}

// A missing removal function is residue with a reason, never a silent skip
// reported as success.
func TestMissingOpIsNotSilentSuccess(t *testing.T) {
	st := fullState()
	u, _ := testUI("")
	plan := BuildPlan(st, nil, false)
	res, err := Run(context.Background(), st, plan, Ops{}, u, Options{Consent: true})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if res.Complete() {
		t.Fatal("a run with no removal functions claimed success")
	}
	if len(st.Resources) != len(fullState().Resources) {
		t.Error("resources were dropped without being removed")
	}
}

// A drifted setting is preserved, reported, and never written.
func TestDriftedSettingIsPreserved(t *testing.T) {
	st := fullState()
	restored := false
	st.Changes = []state.SettingChange{{
		ID: "c1", Provider: "entra", Target: "application/app-obj/application.notes",
		Original: json.RawMessage(`"before"`), Applied: json.RawMessage(`"ours"`),
	}}
	acc := &fakeAccessor{current: json.RawMessage(`"somebody else's"`), onSet: func() { restored = true }}
	reg := settings.Registry{"entra": acc}

	rec := newRecorder()
	u, out := testUI("y\n")
	plan := BuildPlan(st, settings.List(context.Background(), st, reg), false)
	res, err := Run(context.Background(), st, plan, rec.ops(), u, Options{Registry: reg})
	if err != nil {
		t.Fatalf("drift is not an error: %v", err)
	}
	if restored {
		t.Fatal("a drifted setting was written back")
	}
	if st.Changes[0].RestoredAt != nil {
		t.Fatal("a drifted setting was marked restored")
	}
	if len(res.Unrestored) != 0 {
		t.Errorf("drift is preserved on purpose, not outstanding work: %+v", res.Unrestored)
	}
	if !res.Complete() {
		t.Error("preserving a drifted setting must not make teardown incomplete")
	}
	if !strings.Contains(out.String(), "CONFLICT") {
		t.Error("the conflict was not reported")
	}
}

// An unattended run never restores a pre-existing setting: that needs a
// person. It is reported as outstanding rather than skipped quietly.
func TestUnattendedDoesNotRestoreSettings(t *testing.T) {
	st := fullState()
	st.Changes = []state.SettingChange{{
		ID: "c1", Provider: "entra", Target: "application/app-obj/application.notes",
		Original: json.RawMessage(`"before"`), Applied: json.RawMessage(`"ours"`),
	}}
	acc := &fakeAccessor{current: json.RawMessage(`"ours"`), onSet: func() {
		t.Fatal("an unattended run restored a pre-existing setting without approval")
	}}
	reg := settings.Registry{"entra": acc}

	rec := newRecorder()
	u, out := testUI("")
	plan := BuildPlan(st, settings.List(context.Background(), st, reg), false)
	res, err := Run(context.Background(), st, plan, rec.ops(), u, Options{Consent: true, Registry: reg})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("want ErrIncomplete while a setting is unrestored, got %v", err)
	}
	if len(res.Unrestored) != 1 {
		t.Fatalf("want the setting reported as unrestored, got %+v", res.Unrestored)
	}
	if !strings.Contains(out.String(), "needs interactive approval") {
		t.Error("the unrestored setting was not explained")
	}
}

type fakeAccessor struct {
	current json.RawMessage
	onSet   func()
}

func (f *fakeAccessor) Get(context.Context, string) (json.RawMessage, error) { return f.current, nil }
func (f *fakeAccessor) Set(_ context.Context, _ string, v json.RawMessage) error {
	f.onSet()
	f.current = v
	return nil
}

// The installation directory is a created resource that can end up holding
// unrelated content. Only the rendered files go; the directory stays.
func TestRenderedFilesGoButSharedDirectoryStays(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "guacamole")
	for _, p := range []string{"init", "nginx/certs", "data", "somebody-elses"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"compose.yaml", ".env", "nginx/certs/fullchain.pem", "somebody-elses/notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	leftover, err := RemoveRendered(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(leftover) != 2 {
		t.Fatalf("want data and somebody-elses preserved, got %v", leftover)
	}
	for _, gone := range []string{"compose.yaml", ".env", "init", "nginx"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "somebody-elses/notes.txt")); err != nil {
		t.Error("unrelated content was destroyed")
	}

	// With nothing else in it, the directory itself goes.
	os.RemoveAll(filepath.Join(dir, "data"))
	os.RemoveAll(filepath.Join(dir, "somebody-elses"))
	leftover, err = RemoveRendered(context.Background(), dir)
	if err != nil || len(leftover) != 0 {
		t.Fatalf("want the empty directory removed, got %v %v", leftover, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("the empty installation directory was not removed")
	}
}

// A teardown whose config directory is shared reports it as kept, not as
// residue: preserving unrelated use is the correct outcome.
func TestSharedConfigDirectoryIsPreservedNotResidue(t *testing.T) {
	st := fullState()
	rec := newRecorder()
	ops := rec.ops()
	ops.RemoveRendered = func(_ context.Context, dir string) ([]string, error) {
		rec.log("rendered", dir)
		return []string{"data", "recordings"}, nil
	}
	u, out := testUI("")
	plan := BuildPlan(st, nil, false)
	res, err := Run(context.Background(), st, plan, ops, u, Options{Consent: true})
	if err != nil {
		t.Fatalf("a preserved directory is not an error: %v", err)
	}
	if !res.Complete() {
		t.Fatalf("preserving a shared directory made teardown incomplete: %+v", res.Residue())
	}
	if !strings.Contains(out.String(), "still holds data, recordings") {
		t.Errorf("the preserved directory was not explained:\n%s", out.String())
	}
}

func TestSafePathRefusesTopLevel(t *testing.T) {
	for _, p := range []string{"/", "/opt", "relative/path", ""} {
		if err := RemoveTree(context.Background(), p); err == nil {
			t.Errorf("RemoveTree(%q) was allowed", p)
		}
	}
}
