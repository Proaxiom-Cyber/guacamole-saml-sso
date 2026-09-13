package settings

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// fakeAccessor stands in for a provider. Every write is recorded, so a test
// can prove that nothing was written as easily as that something was.
type fakeAccessor struct {
	get    map[string]json.RawMessage
	getErr error
	setErr error
	writes []write
}

type write struct {
	target string
	value  string
}

func (f *fakeAccessor) Get(_ context.Context, target string) (json.RawMessage, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.get[target]
	if !ok {
		return nil, errors.New("no such target: " + target)
	}
	return v, nil
}

func (f *fakeAccessor) Set(_ context.Context, target string, value json.RawMessage) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.writes = append(f.writes, write{target, string(value)})
	return nil
}

// testUI answers prompts from answers and captures everything printed.
func testUI(answers string) (*ui.UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui.UI{
		In:          bufio.NewReader(strings.NewReader(answers)),
		Out:         out,
		Interactive: answers != "",
	}, out
}

func unattendedUI() (*ui.UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui.UI{In: bufio.NewReader(strings.NewReader("")), Out: out, Interactive: false}, out
}

const target = "application/app-1/application.groupMembershipClaims"

func oneChange(applied, original string) *state.State {
	return &state.State{Changes: []state.SettingChange{{
		ID: "c1", Provider: "entra", Target: target,
		Original: json.RawMessage(original), Applied: json.RawMessage(applied),
	}}}
}

// A live value that differs only in key order and whitespace is the same
// value. Graph re-serialises what it returns, so byte comparison would call
// every legitimate restore a conflict.
func TestJSONMatchIgnoresKeyOrderAndWhitespace(t *testing.T) {
	applied := `{"name":"groups","additionalProperties":["cloud_displayname"],"essential":false}`
	live := "{\n  \"essential\" : false,\n\t\"additionalProperties\": [ \"cloud_displayname\" ],\n \"name\":\"groups\"\n}"
	st := oneChange(applied, `null`)
	acc := &fakeAccessor{get: map[string]json.RawMessage{target: json.RawMessage(live)}}

	entries := List(context.Background(), st, Registry{"entra": acc})
	if len(entries) != 1 || entries[0].Status != StatusRestorable {
		t.Fatalf("reordered identical JSON must be restorable, got %+v", entries)
	}
	if len(acc.writes) != 0 {
		t.Fatalf("List must never write: %+v", acc.writes)
	}
}

func TestJSONMatchRejectsDifferentValues(t *testing.T) {
	for _, c := range []struct{ applied, live string }{
		{`["a"]`, `["b"]`},
		{`{"a":1}`, `{"a":1,"b":2}`},
		{`true`, `false`},
		{`"saml"`, `null`},
		{`[1,2]`, `[2,1]`}, // arrays are ordered; order is meaning
	} {
		if jsonEqual(json.RawMessage(c.applied), json.RawMessage(c.live)) {
			t.Errorf("%s and %s must not compare equal", c.applied, c.live)
		}
	}
}

func TestRestoreWritesOriginalAfterApproval(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	acc := &fakeAccessor{get: map[string]json.RawMessage{target: json.RawMessage(`"ApplicationGroup"`)}}
	u, out := testUI("y\n")

	saves := 0
	if err := Restore(context.Background(), st, Registry{"entra": acc}, u, func() error { saves++; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(acc.writes) != 1 || acc.writes[0].target != target || acc.writes[0].value != `"SecurityGroup"` {
		t.Fatalf("the original value must be written back once: %+v", acc.writes)
	}
	if st.Changes[0].RestoredAt == nil {
		t.Fatal("a successful write must set RestoredAt")
	}
	if saves != 1 {
		t.Fatalf("state must be saved once after the write, saved %d times", saves)
	}
	// The operator must see what they are approving before they answer.
	for _, want := range []string{target, `"ApplicationGroup"`, `"SecurityGroup"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the approval prompt must show %s:\n%s", want, out)
		}
	}
}

func TestRestoreDeclinedWritesNothing(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	acc := &fakeAccessor{get: map[string]json.RawMessage{target: json.RawMessage(`"ApplicationGroup"`)}}
	u, _ := testUI("n\n")

	if err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil); err != nil {
		t.Fatal(err)
	}
	if len(acc.writes) != 0 {
		t.Fatalf("a declined restore must write nothing: %+v", acc.writes)
	}
	if st.Changes[0].RestoredAt != nil {
		t.Fatal("a declined restore must leave RestoredAt unset")
	}
}

func TestUnattendedStopsWithApprovalSentinel(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	acc := &fakeAccessor{get: map[string]json.RawMessage{target: json.RawMessage(`"ApplicationGroup"`)}}
	u, out := unattendedUI()

	err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil)
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("unattended must stop with ErrApprovalRequired, got %v", err)
	}
	if !strings.Contains(err.Error(), target) {
		t.Errorf("the error must name what is pending: %v", err)
	}
	if len(acc.writes) != 0 {
		t.Fatalf("unattended must write nothing: %+v", acc.writes)
	}
	if st.Changes[0].RestoredAt != nil {
		t.Fatal("unattended must leave RestoredAt unset")
	}
	if !strings.Contains(out.String(), target) {
		t.Errorf("unattended must still report what is pending:\n%s", out)
	}
}

// The drifted setting sits beside a restorable one, so the run really does
// enter the approval loop. Approving the restorable one must not carry the
// drifted one along with it.
func TestDriftPreservesCurrentValue(t *testing.T) {
	const other = "application/app-1/application.identifierUris"
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	st.Changes = append(st.Changes, state.SettingChange{
		ID: "c2", Provider: "entra", Target: other,
		Original: json.RawMessage(`[]`), Applied: json.RawMessage(`["https://a/guacamole"]`),
	})
	acc := &fakeAccessor{get: map[string]json.RawMessage{
		target: json.RawMessage(`"All"`), // somebody changed it after this tool did
		other:  json.RawMessage(`["https://a/guacamole"]`),
	}}
	u, out := testUI("y\ny\n")

	if err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil); err != nil {
		t.Fatalf("drift is reported, not an error: %v", err)
	}
	for _, w := range acc.writes {
		if w.target == target {
			t.Fatalf("a drifted setting must never be written: %+v", w)
		}
	}
	if len(acc.writes) != 1 {
		t.Fatalf("the undrifted setting must still be restored: %+v", acc.writes)
	}
	if st.Changes[0].RestoredAt != nil {
		t.Fatal("a drifted setting must stay unrestored, never silently marked done")
	}
	if st.Changes[1].RestoredAt == nil {
		t.Fatal("the undrifted setting must be marked restored")
	}
	s := out.String()
	if !strings.Contains(s, "CONFLICT") {
		t.Errorf("drift must be reported as a conflict:\n%s", s)
	}
	for _, want := range []string{`"All"`, `"ApplicationGroup"`, `"SecurityGroup"`} {
		if !strings.Contains(s, want) {
			t.Errorf("the conflict report must show %s (current, applied and original):\n%s", want, s)
		}
	}
}

func TestDriftedEntryIsOfferedAgainNextRun(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	acc := &fakeAccessor{get: map[string]json.RawMessage{target: json.RawMessage(`"All"`)}}
	u, _ := unattendedUI()
	if err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil); err != nil {
		t.Fatal(err)
	}
	if got := List(context.Background(), st, Registry{"entra": acc}); len(got) != 1 {
		t.Fatalf("a drifted entry must still be listed on the next run, got %d", len(got))
	}
}

func TestUnknownProviderIsReportedNotSkipped(t *testing.T) {
	st := &state.State{Changes: []state.SettingChange{{
		ID: "c1", Provider: "cloudflare", Target: "accessApplication/a-1/accessApplication.session_duration",
		Original: json.RawMessage(`"24h"`), Applied: json.RawMessage(`"8h"`),
	}}}
	u, out := testUI("y\n")

	if err := Restore(context.Background(), st, Registry{}, u, nil); err != nil {
		t.Fatal(err)
	}
	if st.Changes[0].RestoredAt != nil {
		t.Fatal("a provider with no accessor must never be marked restored")
	}
	s := out.String()
	if !strings.Contains(s, "cannot be restored automatically") {
		t.Errorf("an unknown provider must say so:\n%s", s)
	}
	for _, want := range []string{`"24h"`, `"8h"`} {
		if !strings.Contains(s, want) {
			t.Errorf("the recorded values must still be printed (%s):\n%s", want, s)
		}
	}
}

func TestUnreadableProviderIsReportedNotRestored(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	acc := &fakeAccessor{getErr: errors.New("graph GET /applications/app-1 failed: Forbidden (Authorization_RequestDenied)")}
	u, out := testUI("y\n")

	if err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil); err != nil {
		t.Fatal(err)
	}
	if len(acc.writes) != 0 || st.Changes[0].RestoredAt != nil {
		t.Fatal("an unreadable setting must not be written or marked restored")
	}
	if !strings.Contains(out.String(), "Authorization_RequestDenied") {
		t.Errorf("the read failure must be reported:\n%s", out)
	}
}

func TestRestoredAtSetOnlyOnSuccessfulWrite(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	acc := &fakeAccessor{
		get:    map[string]json.RawMessage{target: json.RawMessage(`"ApplicationGroup"`)},
		setErr: errors.New("graph PATCH /applications/app-1 failed: Forbidden (Authorization_RequestDenied)"),
	}
	u, _ := testUI("y\n")

	err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil)
	if err == nil {
		t.Fatal("a failed write must return an error")
	}
	if !strings.Contains(err.Error(), target) {
		t.Errorf("the error must name the setting: %v", err)
	}
	if st.Changes[0].RestoredAt != nil {
		t.Fatal("a failed write must leave RestoredAt unset")
	}
}

func TestRestoredEntryIsNotOfferedAgain(t *testing.T) {
	st := oneChange(`"ApplicationGroup"`, `"SecurityGroup"`)
	done := time.Now().UTC()
	st.Changes[0].RestoredAt = &done
	acc := &fakeAccessor{getErr: errors.New("Get must not be called for a restored entry")}
	u, out := testUI("y\n")

	if got := List(context.Background(), st, Registry{"entra": acc}); len(got) != 0 {
		t.Fatalf("a restored entry must not be listed: %+v", got)
	}
	if err := Restore(context.Background(), st, Registry{"entra": acc}, u, nil); err != nil {
		t.Fatal(err)
	}
	if len(acc.writes) != 0 {
		t.Fatalf("a restored entry must not be written again: %+v", acc.writes)
	}
	if !strings.Contains(out.String(), "No pre-existing settings are waiting") {
		t.Errorf("nothing pending must be said plainly:\n%s", out)
	}
}

func TestListOnNilStateIsEmpty(t *testing.T) {
	if got := List(context.Background(), nil, Registry{}); got != nil {
		t.Fatalf("no deployment means nothing pending: %+v", got)
	}
}
