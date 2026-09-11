package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func testUI(interactive bool, input string) (*ui.UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui.UI{In: bufio.NewReader(strings.NewReader(input)), Out: out, Interactive: interactive}, out
}

// seed writes a state file directly, releasing the lock afterwards.
func seed(t *testing.T, dir string, st *state.State) {
	t.Helper()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func pendingState() *state.State {
	return &state.State{
		DeploymentID: state.NewID(),
		CreatedAt:    time.Now().UTC(),
		Actions:      []state.Action{{ID: state.NewID(), Intent: "initialise-deployment", StartedAt: time.Now().UTC()}},
	}
}

func completeState() *state.State {
	now := time.Now().UTC()
	return &state.State{
		DeploymentID: state.NewID(),
		CreatedAt:    now,
		Actions:      []state.Action{{ID: state.NewID(), Intent: "initialise-deployment", StartedAt: now, FinishedAt: &now, Result: state.ResultOK}},
	}
}

func TestUnattendedFreshSetupCompletesWithoutPrompts(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u}); err != nil {
		t.Fatalf("unattended fresh setup: %v (output: %s)", err, out.String())
	}
	st, err := state.Read(dir)
	if err != nil || st == nil {
		t.Fatalf("no state after setup: %v", err)
	}
	if len(st.Pending()) != 0 {
		t.Fatalf("pending work after clean run: %+v", st.Pending())
	}
	if st.Config["hostname"] == "" {
		t.Fatal("hostname not recorded")
	}
}

func TestUnattendedPendingRequiresExplicitResume(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, pendingState())

	u, _ := testUI(false, "")
	err := Run(context.Background(), Options{StateDir: dir, UI: u})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("want ErrApprovalRequired, got %v", err)
	}

	u2, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Resume: true}); err != nil {
		t.Fatalf("unattended --resume: %v", err)
	}
	st, _ := state.Read(dir)
	if len(st.Pending()) != 0 {
		t.Fatalf("pending after resume: %+v", st.Pending())
	}
}

func TestGuidedResumeShowsInterruptedWorkAndResumes(t *testing.T) {
	dir := t.TempDir()
	st := pendingState()
	seed(t, dir, st)

	u, out := testUI(true, "r\n")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u}); err != nil {
		t.Fatalf("guided resume: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "did not finish") || !strings.Contains(text, "initialise-deployment") {
		t.Fatalf("interrupted work not shown:\n%s", text)
	}
	got, _ := state.Read(dir)
	if got.DeploymentID != st.DeploymentID {
		t.Fatal("resume replaced the deployment identity")
	}
	if len(got.Pending()) != 0 {
		t.Fatalf("pending after resume: %+v", got.Pending())
	}
}

func TestGuidedCleanupRemovesRecordWithoutResources(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, pendingState())

	u, _ := testUI(true, "c\n")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatal("state file still present after cleanup")
	}
}

func TestGuidedCleanupRefusedWhenResourcesExist(t *testing.T) {
	dir := t.TempDir()
	st := pendingState()
	st.Resources = []state.Resource{{ID: "r1", Provider: "cloudflare", Type: "dns-record", CreatedAt: time.Now().UTC()}}
	seed(t, dir, st)

	u, _ := testUI(true, "c\n")
	err := Run(context.Background(), Options{StateDir: dir, UI: u})
	if err == nil || !strings.Contains(err.Error(), "teardown") {
		t.Fatalf("want teardown refusal, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "state.json")); statErr != nil {
		t.Fatal("state file was removed despite created resources")
	}
}

func TestExistingCompleteDeploymentIsExplainedNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	st := completeState()
	seed(t, dir, st)

	// Guided: explanation, exit clean, nothing changed.
	u, out := testUI(true, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u}); err != nil {
		t.Fatalf("guided on existing: %v", err)
	}
	if !strings.Contains(out.String(), "does not overwrite") {
		t.Fatalf("no explanation shown:\n%s", out.String())
	}
	got, _ := state.Read(dir)
	if got.DeploymentID != st.DeploymentID {
		t.Fatal("existing deployment was replaced")
	}

	// Unattended: nonzero with explanation, no prompt.
	u2, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2}); err == nil {
		t.Fatal("unattended on existing deployment must fail")
	}
}

func TestFailedPhaseRetainsCompletedWorkAndResumes(t *testing.T) {
	dir := t.TempDir()
	boom := errors.New("boom")
	fail := true
	phases := []Phase{
		SetupPhases[0],
		{Name: "flaky", Run: func(context.Context, *state.State, *ui.UI) error {
			if fail {
				return boom
			}
			return nil
		}},
	}

	u, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Phases: phases}); !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	st, _ := state.Read(dir)
	if len(st.Pending()) != 1 || st.Pending()[0].Intent != "flaky" {
		t.Fatalf("pending = %+v", st.Pending())
	}

	fail = false
	u2, out := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Resume: true, Phases: phases}); err != nil {
		t.Fatalf("resume after failure: %v", err)
	}
	if !strings.Contains(out.String(), "initialise-deployment: already complete") {
		t.Fatalf("completed phase was re-run:\n%s", out.String())
	}
}

func TestQuitRetainsInterruptedWork(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, pendingState())
	u, _ := testUI(true, "q\n")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u}); err != nil {
		t.Fatalf("quit: %v", err)
	}
	st, _ := state.Read(dir)
	if st == nil || len(st.Pending()) != 1 {
		t.Fatal("interrupted work not retained after quit")
	}
}
