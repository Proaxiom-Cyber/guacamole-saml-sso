package session

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
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

// core trims the registry to end at host-dependencies, keeping these tests
// focused on session mechanics; stack phases have their own tests.
func core(o Options) Options {
	if o.Phases != nil {
		return o
	}
	all := Phases(&o)
	for i, p := range all {
		if p.Name == "host-dependencies" {
			o.Phases = all[:i+1]
			break
		}
	}
	return o
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
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
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}}))
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("want ErrApprovalRequired, got %v", err)
	}

	u2, _ := testUI(false, "")
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u2, Resume: true, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
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
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}}))
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u2, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err == nil {
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Phases: phases})); !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	st, _ := state.Read(dir)
	if len(st.Pending()) != 1 || st.Pending()[0].Intent != "flaky" {
		t.Fatalf("pending = %+v", st.Pending())
	}

	fail = false
	u2, out := testUI(false, "")
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u2, Resume: true, Phases: phases})); err != nil {
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
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: h, CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}}))
	if !errors.Is(err, ErrApprovalRequired) || !strings.Contains(err.Error(), "--install-dependencies") {
		t.Fatalf("want approval-required naming the flag, got %v", err)
	}
	for _, c := range calls {
		// modprobe -n is a read-only probe; mutating commands must not run.
		if strings.HasPrefix(c, "dnf") || strings.HasPrefix(c, "systemctl") {
			t.Fatalf("mutating command ran without consent: %v", calls)
		}
	}

	// Explicit consent resumes and installs, recording host changes.
	u2, _ := testUI(false, "")
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u2, Host: h, Resume: true, InstallDependencies: true, CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
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
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: h, CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}}))
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
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv, CredSpecs: []creds.Spec{}})); err != nil {
		t.Fatalf("quit: %v", err)
	}
	st, _ := state.Read(dir)
	if st == nil || len(st.Pending()) != 1 {
		t.Fatal("interrupted work not retained after quit")
	}
}

func TestGuidedFileModeStoresOwnerOnlyAndKeepsSecretsOut(t *testing.T) {
	dir := t.TempDir()
	// y = fresh setup, f = file mode, y = approve plaintext exception.
	u, out := testUI(true, "y\nf\ny\n")
	const secret = "sekret-value-1234"
	u.Secret = func(string) (string, error) { return secret, nil }

	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t)}))
	if err != nil {
		t.Fatalf("guided file-mode setup: %v", err)
	}
	st, _ := state.Read(dir)
	if st.Config["credential-mode"] != creds.ModeFile {
		t.Fatalf("mode not recorded: %+v", st.Config)
	}
	if !strings.Contains(out.String(), "Credential storage method: file") {
		t.Fatalf("chosen method not shown:\n%s", out.String())
	}

	credFile := filepath.Join(dir, "credentials", "cloudflare-api-token")
	info, err := os.Stat(credFile)
	if err != nil {
		t.Fatalf("credential file missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode %v, want 0600", info.Mode().Perm())
	}
	dinfo, _ := os.Stat(filepath.Join(dir, "credentials"))
	if dinfo.Mode().Perm() != 0o700 {
		t.Fatalf("credential dir mode %v, want 0700", dinfo.Mode().Perm())
	}

	// The secret must not appear in state, output, or resource records.
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), secret) || strings.Contains(out.String(), secret) {
		t.Fatal("secret value leaked into state or output")
	}
	var dirRec, fileRec bool
	for _, r := range st.Resources {
		if r.Type == "credential-dir" {
			dirRec = true
		}
		if r.Type == "credential-file" && r.Name == "cloudflare-api-token" {
			fileRec = true
		}
	}
	if !dirRec || !fileRec {
		t.Fatalf("owned credential material not recorded for teardown: %+v", st.Resources)
	}
}

func TestUnattendedRequiresCredentialModeFlag(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(false, "")
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t)}))
	if !errors.Is(err, ErrApprovalRequired) || !strings.Contains(err.Error(), "--credentials") {
		t.Fatalf("want approval-required naming --credentials, got %v", err)
	}
}

func TestUnattendedPromptModeRejected(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(false, "")
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModePrompt}))
	if err == nil || !strings.Contains(err.Error(), "unattended") {
		t.Fatalf("want unattended rejection, got %v", err)
	}
}

func TestEnvModeMissingCredentialNamesVariableAndResumes(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(false, "")
	err := Run(context.Background(), core(Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv}))
	if err == nil || !strings.Contains(err.Error(), "GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN") {
		t.Fatalf("want instruction naming the variable, got %v", err)
	}

	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", "tok-abc123")
	t.Setenv("GUACDEPLOY_CRED_POSTGRES_PASSWORD", "pg-pass-1")
	u2, out := testUI(false, "")
	if err := Run(context.Background(), core(Options{StateDir: dir, UI: u2, Host: fakeHost(t), CredentialMode: creds.ModeEnv, Resume: true})); err != nil {
		t.Fatalf("resume with variable set: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), "tok-abc123") || strings.Contains(out.String(), "tok-abc123") {
		t.Fatal("credential value leaked")
	}
}

// stackRunner fakes docker for the stack phases and records every call.
type stackCall struct {
	stdin string
	args  []string
}

func stackRunner(calls *[]stackCall) stack.Runner {
	return func(_ context.Context, stdin, name string, args ...string) (string, error) {
		*calls = append(*calls, stackCall{stdin: stdin, args: append([]string{name}, args...)})
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "initdb.sh"):
			return "CREATE TABLE guacamole_entity (x int);\nCREATE TABLE guacamole_user_group (y int);\n", nil
		case strings.Contains(joined, "ps"):
			return "guacamole-guacd-1\nguacamole-postgres-1\nguacamole-guacamole-1\nguacamole-nginx-1\n", nil
		default:
			return "ok", nil
		}
	}
}

func TestStackPhasesFullPipelineUnattended(t *testing.T) {
	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", "cf-token")
	const dbPassword = "pa$s-Xy1-secret"
	t.Setenv("GUACDEPLOY_CRED_POSTGRES_PASSWORD", dbPassword)

	dir := t.TempDir()
	install := filepath.Join(t.TempDir(), "opt-guacamole")
	var calls []stackCall
	u, out := testUI(false, "")
	opts := Options{
		StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv,
		Hostname: "guac.example.test", AdminGroup: "GuacAdmins", OperatorGroup: "GuacOperators",
		InstallDir: install, StackRun: stackRunner(&calls),
		StackRunOut: func(_ context.Context, name string, args ...string) (string, string, error) {
			return "CREATE TABLE guacamole_entity (x int);\nCREATE TABLE guacamole_user_group (y int);\n", "", nil
		},
		ProbeCheck: func(context.Context, stack.Config) error { return nil },
	}
	// Sign-in provisioning has its own tests; this one covers the local stack.
	opts.Phases = withoutPhases(Phases(&opts),
		"cloudflare-select", "cloudflare-tunnel", "cloudflare-dns",
		"cloudflare-connect", "entra-signin", "cloudflare-access")
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("full pipeline: %v\n%s", err, out.String())
	}

	// Rendered assets.
	for _, f := range []string{"compose.yaml", ".env", "init/001-initdb.sql", "init/002-groups.sh",
		"nginx/templates/guacamole.conf.template", "nginx/certs/fullchain.pem", "nginx/certs/privkey.pem"} {
		if _, err := os.Stat(filepath.Join(install, f)); err != nil {
			t.Fatalf("missing rendered file %s: %v", f, err)
		}
	}
	env, _ := os.ReadFile(filepath.Join(install, ".env"))
	if strings.Contains(string(env), dbPassword) {
		t.Fatal("password leaked into .env")
	}

	// Password travels via stdin only, escaped for Compose.
	var sawUp bool
	for _, c := range calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, " up ") || strings.HasSuffix(joined, " up") || strings.Contains(joined, "up --detach") {
			sawUp = true
			if !strings.Contains(c.stdin, "pa$$s-Xy1-secret") {
				t.Fatalf("stdin override missing escaped password: %q", c.stdin)
			}
		}
		for _, a := range c.args {
			if strings.Contains(a, dbPassword) {
				t.Fatalf("password in argv: %v", c.args)
			}
		}
	}
	if !sawUp {
		t.Fatalf("compose up never ran: %+v", calls)
	}

	// Resources and secret-free state.
	st, _ := state.Read(dir)
	types := map[string]int{}
	for _, r := range st.Resources {
		types[r.Type]++
	}
	if types["config-directory"] != 1 || types["data-directory"] != 1 || types["container"] != 4 {
		t.Fatalf("resource records: %+v", st.Resources)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), dbPassword) || strings.Contains(out.String(), dbPassword) {
		t.Fatal("password leaked into state or output")
	}
	if len(st.Pending()) != 0 {
		t.Fatalf("pending after full run: %+v", st.Pending())
	}
}

func TestUnattendedStackNeedsExplicitConfig(t *testing.T) {
	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", "cf-token")
	t.Setenv("GUACDEPLOY_CRED_POSTGRES_PASSWORD", "pw")
	dir := t.TempDir()
	u, _ := testUI(false, "")
	opts := Options{
		StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeEnv,
		InstallDir: filepath.Join(t.TempDir(), "opt"),
		StackRun:   stackRunner(&[]stackCall{}),
		StackRunOut: func(_ context.Context, name string, args ...string) (string, string, error) {
			return "CREATE TABLE guacamole_entity (x int);\n", "", nil
		},
	}
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "--hostname") {
		t.Fatalf("want explicit-config error, got %v", err)
	}
}

func TestFileModeGeneratesMachineCredential(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(false, "")
	opts := Options{
		StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeFile,
		CredSpecs: []creds.Spec{{Name: "postgres-password", Purpose: "db", Generate: true}},
	}
	opts = core(opts)
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("file-mode generation: %v\n%s", err, out.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "credentials", "postgres-password"))
	if err != nil {
		t.Fatalf("generated credential missing: %v", err)
	}
	v := strings.TrimSpace(string(b))
	if len(v) != 64 {
		t.Fatalf("unexpected generated secret length %d", len(v))
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), v) || strings.Contains(out.String(), v) {
		t.Fatal("generated secret leaked")
	}
}

// TestAlwaysPhaseRerunsOnResume pins the repair path found on the live
// Rocky host: rendering is idempotent and also fixes configuration written
// by an older version, so a completed render must NOT be skipped on
// resume. Skipping it left a host with unreadable bind-mount directories
// broken forever, because the journal said the work was done.
func TestAlwaysPhaseRerunsOnResume(t *testing.T) {
	dir := t.TempDir()
	var renders, onces int
	phases := []Phase{
		{Name: "once", Run: func(context.Context, *state.State, *ui.UI) error { onces++; return nil }},
		{Name: "render", Always: true, Run: func(context.Context, *state.State, *ui.UI) error { renders++; return nil }},
		{Name: "flaky", Run: func(context.Context, *state.State, *ui.UI) error {
			if renders < 2 {
				return errors.New("boom")
			}
			return nil
		}},
	}

	u, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Phases: phases}); err == nil {
		t.Fatal("first run should fail at the flaky phase")
	}
	if renders != 1 || onces != 1 {
		t.Fatalf("after first run renders=%d onces=%d", renders, onces)
	}

	u2, out := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Resume: true, Phases: phases}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if renders != 2 {
		t.Fatalf("Always phase did not re-run on resume: renders=%d", renders)
	}
	if onces != 1 {
		t.Fatalf("ordinary completed phase re-ran: onces=%d", onces)
	}
	if !strings.Contains(out.String(), "once: already complete") {
		t.Fatalf("ordinary phase should have been skipped:\n%s", out.String())
	}
}

// TestSAMLGroupAttributeNeverSilentlyDefaults pins the integration gap the
// Entra module flagged: Entra names the groups claim with a full URI, so
// leaving the compose default "groups" in place means group membership
// never reaches Guacamole and every sign-in lands with no permissions.
func TestSAMLGroupAttributeNeverSilentlyDefaults(t *testing.T) {
	// No SAML configured: nothing to set, and no SAML block is rendered.
	if got := samlGroupAttribute(&state.State{Config: map[string]string{}}); got != "" {
		t.Fatalf("without SAML want empty, got %q", got)
	}
	// SAML configured by the Entra slice: the claim URI must be used.
	withSAML := &state.State{Config: map[string]string{"saml-metadata-url": "https://login.example/metadata"}}
	if got := samlGroupAttribute(withSAML); got != entra.GroupClaimAttribute {
		t.Fatalf("with SAML want the Entra claim URI, got %q", got)
	}
	// An explicitly recorded attribute always wins (another identity provider).
	explicit := &state.State{Config: map[string]string{
		"saml-metadata-url":    "https://idp.example/metadata",
		"saml-group-attribute": "memberOf",
	}}
	if got := samlGroupAttribute(explicit); got != "memberOf" {
		t.Fatalf("explicit attribute ignored, got %q", got)
	}

	// And it must actually reach the rendered .env.
	dir := t.TempDir()
	if err := stack.Render(stack.Config{
		InstallDir: dir, Hostname: "guac.example.test",
		SAMLMetadataURL:    "https://login.example/metadata",
		SAMLGroupAttribute: samlGroupAttribute(withSAML),
	}); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "SAML_GROUP_ATTRIBUTE="+entra.GroupClaimAttribute) {
		t.Fatalf("rendered .env does not carry the Entra claim URI:\n%s", env)
	}
}

func withoutPhases(all []Phase, names ...string) []Phase {
	drop := map[string]bool{}
	for _, n := range names {
		drop[n] = true
	}
	var out []Phase
	for _, p := range all {
		if !drop[p.Name] {
			out = append(out, p)
		}
	}
	return out
}

// TestEntraPhaseWithoutTokenSaysWhatIsMissing keeps the failure actionable:
// the operator must learn which variable to set and which permissions it
// needs, not just that a phase failed.
func TestEntraPhaseWithoutTokenSaysWhatIsMissing(t *testing.T) {
	t.Setenv(entra.DefaultTokenEnv, "")
	o := &Options{}
	_, err := o.entraClient()
	if err == nil {
		t.Fatal("a missing Graph token must be reported")
	}
	for _, want := range []string{entra.DefaultTokenEnv, "Application.ReadWrite.All"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error does not mention %q: %v", want, err)
		}
	}
}

// TestUncertainResultIsJournalledAndDrivesReconciliation pins the
// reconciliation contract: when a create request is sent and the response is
// lost, the attempt must be recorded as uncertain (not merely failed), and
// the next run must know to query by ownership marker before retrying, so a
// duplicate cloud resource is never created.
func TestUncertainResultIsJournalledAndDrivesReconciliation(t *testing.T) {
	dir := t.TempDir()
	phases := []Phase{{Name: "entra-signin", Run: func(context.Context, *state.State, *ui.UI) error {
		return fmt.Errorf("%w: creating the application", ErrUncertain)
	}}}

	u, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Phases: phases}); err == nil {
		t.Fatal("phase should have failed")
	}
	st, _ := state.Read(dir)
	last := st.Actions[len(st.Actions)-1]
	if last.Result != state.ResultUncertain {
		t.Fatalf("result = %q, want %q", last.Result, state.ResultUncertain)
	}
	if !lastAttemptUncertain(st, "entra-signin") {
		t.Fatal("the next run would not reconcile before retrying creation")
	}
	// An ordinary failure must NOT look uncertain.
	if lastAttemptUncertain(&state.State{Actions: []state.Action{
		{Intent: "entra-signin", Result: state.ResultFailed},
	}}, "entra-signin") {
		t.Fatal("a plain failure must not trigger reconciliation")
	}
}

// TestIntentIsJournalledBeforeTheWork proves a phase can persist what it is
// about to do before doing it, which is what makes a lost response
// recoverable, and that each attempt carries a correlation identifier.
func TestIntentIsJournalledBeforeTheWork(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(false, "")
	opts := &Options{StateDir: dir, UI: u}
	opts.Phases = []Phase{{Name: "risky", Run: func(context.Context, *state.State, *ui.UI) error {
		if opts.journalIntent == nil {
			return errors.New("phases were given no way to journal intent")
		}
		if err := opts.journalIntent("will create application guac-test"); err != nil {
			return err
		}
		return errors.New("response lost after journalling")
	}}}

	if err := Run(context.Background(), *opts); err == nil {
		t.Fatal("phase should have failed")
	}
	st, _ := state.Read(dir)
	last := st.Actions[len(st.Actions)-1]
	if last.CorrelationID == "" {
		t.Fatal("no correlation identifier recorded for reconciliation")
	}
	if last.Intent != "risky" || last.Result != state.ResultFailed {
		t.Fatalf("unexpected journal entry: %+v", last)
	}
}

// TestApexDerivation covers the zone guess and its override, because a
// wrong apex sends the deployment at somebody else's zone.
func TestApexDerivation(t *testing.T) {
	for in, want := range map[string]string{
		"guac.example.com": "example.com",
		"a.b.c.example.co": "example.co",
		"example.com":      "example.com",
		"localhost":        "localhost",
	} {
		if got := apexOf(in); got != want {
			t.Errorf("apexOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAccessAllowListNeverEmpty pins the rule that Access is never opened
// to everyone: with no Entra groups and no explicit emails the phase must
// stop and ask rather than publish a permissive application.
func TestAccessAllowListNeverEmpty(t *testing.T) {
	if got := nonEmpty("", ""); len(got) != 0 {
		t.Fatalf("empty group IDs must not become allow-list entries: %v", got)
	}
	if got := nonEmpty("gid-admin", ""); len(got) != 1 || got[0] != "gid-admin" {
		t.Fatalf("nonEmpty dropped a real group: %v", got)
	}
	if got := splitList(" a@example.com , b@example.com "); len(got) != 2 || got[0] != "a@example.com" {
		t.Fatalf("splitList = %v", got)
	}
	if got := splitList("   "); got != nil {
		t.Fatalf("blank list must be nil, got %v", got)
	}
}

// TestNoPublicConnectorWhenProtectionIsIncomplete is the exposure guard.
// Publishing DNS or starting the cloudflared connector before SAML sign-in
// and a verified Access policy exist would leave a reachable Guacamole
// origin with nothing in front of it. The phase order must make that
// impossible, and a failure in sign-in or Access must stop before
// publication.
func TestNoPublicConnectorWhenProtectionIsIncomplete(t *testing.T) {
	order := []string{}
	for _, p := range Phases(&Options{}) {
		order = append(order, p.Name)
	}
	idx := func(name string) int {
		for i, n := range order {
			if n == name {
				return i
			}
		}
		t.Fatalf("phase %q missing from the registry: %v", name, order)
		return -1
	}
	// Everything that protects the service must come before publication.
	for _, protector := range []string{"entra-signin", "cloudflare-access"} {
		for _, publisher := range []string{"cloudflare-dns", "cloudflare-connect"} {
			if idx(protector) > idx(publisher) {
				t.Fatalf("%s runs after %s: a failure would leave an unprotected origin reachable", protector, publisher)
			}
		}
	}

	// A failure in sign-in must stop before any publication phase runs.
	dir := t.TempDir()
	ran := map[string]bool{}
	var phases []Phase
	for _, p := range Phases(&Options{}) {
		name := p.Name
		switch name {
		case "entra-signin":
			phases = append(phases, Phase{Name: name, Run: func(context.Context, *state.State, *ui.UI) error {
				ran[name] = true
				return errors.New("no Graph token")
			}})
		case "cloudflare-dns", "cloudflare-connect":
			phases = append(phases, Phase{Name: name, Run: func(context.Context, *state.State, *ui.UI) error {
				ran[name] = true
				return nil
			}})
		default:
			phases = append(phases, Phase{Name: name, Run: func(context.Context, *state.State, *ui.UI) error {
				ran[name] = true
				return nil
			}})
		}
	}
	u, _ := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Phases: phases}); err == nil {
		t.Fatal("sign-in failure should stop the session")
	}
	if !ran["entra-signin"] {
		t.Fatal("the sign-in phase never ran")
	}
	if ran["cloudflare-dns"] || ran["cloudflare-connect"] {
		t.Fatal("the deployment was published despite sign-in failing")
	}
	st, _ := state.Read(dir)
	if strings.Contains(st.Config["compose-profiles"], "cloudflare") {
		t.Fatal("the cloudflared connector profile was enabled despite sign-in failing")
	}
}

// TestConnectorRefusesWithoutVerifiedAccess guards the same rule at the
// phase itself, not just at the ordering: even if the phase were reached
// out of order, it must refuse to publish without a verified Access
// application.
func TestConnectorRefusesWithoutVerifiedAccess(t *testing.T) {
	o := &Options{}
	st := &state.State{Config: map[string]string{"guac-hostname": "guac.example.test"}}
	u, _ := testUI(false, "")
	err := o.cloudflareConnect(context.Background(), st, u)
	if err == nil || !strings.Contains(err.Error(), "Access application") {
		t.Fatalf("want refusal naming the missing Access application, got %v", err)
	}
	if strings.Contains(st.Config["compose-profiles"], "cloudflare") {
		t.Fatal("the connector profile was enabled by a refused publication")
	}
}
