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

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func testUI(interactive bool, input string) (*ui.UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui.UI{In: bufio.NewReader(strings.NewReader(input)), Out: out, Interactive: interactive}, out
}

// fakeHost is a healthy Rocky Linux 10 host with Docker and Compose present.
func fakeHost(t *testing.T) *host.Probes {
	t.Helper()
	osr := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osr, []byte("ID=\"rocky\"\nVERSION_ID=\"10.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &host.Probes{
		OSReleasePath: osr,
		InstallDirs:   []string{filepath.Join(t.TempDir(), "absent")},
		Geteuid:       func() int { return 0 },
		LookPath:      func(string) (string, error) { return "/usr/bin/docker", nil },
		Run: func(context.Context, string, ...string) (string, error) {
			return "Docker version 27.0", nil
		},
		Dial: func(context.Context, string) error { return nil },
	}
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
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)}); err != nil {
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
	err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)})
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("want ErrApprovalRequired, got %v", err)
	}

	u2, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Resume: true, Host: fakeHost(t)}); err != nil {
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
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)}); err != nil {
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
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)}); err != nil {
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
	err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)})
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
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)}); err != nil {
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
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Host: fakeHost(t)}); err == nil {
		t.Fatal("unattended on existing deployment must fail")
	}
}

func TestFailedPhaseRetainsCompletedWorkAndResumes(t *testing.T) {
	dir := t.TempDir()
	boom := errors.New("boom")
	fail := true
	phases := []Phase{
		Phases(&Options{})[0],
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

// bareHost is a healthy Rocky host with no Docker installed. Run calls are
// recorded so tests can check the installation plan executed.
func bareHost(t *testing.T, calls *[]string) *host.Probes {
	t.Helper()
	p := fakeHost(t)
	installed := false
	p.LookPath = func(string) (string, error) {
		if installed {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("not found")
	}
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		if name == "dnf" {
			installed = true
		}
		return "ok", nil
	}
	return p
}

func TestUnattendedMissingDependenciesRequireConsent(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	h := bareHost(t, &calls)

	u, _ := testUI(false, "")
	err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: h})
	if !errors.Is(err, ErrApprovalRequired) || !strings.Contains(err.Error(), "--install-dependencies") {
		t.Fatalf("want approval-required naming the flag, got %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("commands ran without consent: %v", calls)
	}

	// Explicit consent resumes and installs, recording host changes.
	u2, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Host: h, Resume: true, InstallDependencies: true}); err != nil {
		t.Fatalf("consented install: %v", err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "dnf -y install") {
		t.Fatalf("install plan did not run: %v", calls)
	}
	st, _ := state.Read(dir)
	if len(st.Resources) == 0 {
		t.Fatal("installed dependencies were not recorded as host changes")
	}
	var service bool
	for _, r := range st.Resources {
		if r.Provider != "host" {
			t.Fatalf("unexpected resource provider: %+v", r)
		}
		if r.Type == "service-enablement" && r.Name == "docker" {
			service = true
		}
	}
	if !service {
		t.Fatalf("docker service enablement not recorded: %+v", st.Resources)
	}
}

func TestGuidedDependencyDeclineStopsSetup(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	h := bareHost(t, &calls)

	// y = start fresh setup, n = decline dependency installation.
	u, _ := testUI(true, "y\nn\n")
	err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: h})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("want decline error, got %v", err)
	}
	if strings.Contains(strings.Join(calls, "\n"), "dnf") {
		t.Fatalf("dnf ran despite decline: %v", calls)
	}
}

func TestQuitRetainsInterruptedWork(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, pendingState())
	u, _ := testUI(true, "q\n")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Host: fakeHost(t)}); err != nil {
		t.Fatalf("quit: %v", err)
	}
	st, _ := state.Read(dir)
	if st == nil || len(st.Pending()) != 1 {
		t.Fatal("interrupted work not retained after quit")
	}
}
