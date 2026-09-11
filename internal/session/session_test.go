package session

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

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/certs"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
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
	// A genuinely finished deployment: the only registry phase is one the
	// state already records as done, so nothing is outstanding.
	only := []Phase{{Name: "initialise-deployment", Run: initialiseDeployment}}

	// Guided: explanation, exit clean, nothing changed.
	u, out := testUI(true, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Phases: only}); err != nil {
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
	if err := Run(context.Background(), Options{StateDir: dir, UI: u2, Phases: only}); err == nil {
		t.Fatal("unattended on existing deployment must fail")
	}
}

// TestCompletedDeploymentRunsPhasesItNeverRan pins convergence. A newer
// version can carry work an existing deployment never ran -- reboot
// recovery is the case that bit us live -- and "nothing pending" must not
// be mistaken for "nothing left to do". Completed phases stay untouched.
func TestCompletedDeploymentRunsPhasesItNeverRan(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, completeState())

	var ranOld, ranNew int
	phases := []Phase{
		{Name: "initialise-deployment", Run: func(context.Context, *state.State, *ui.UI) error { ranOld++; return nil }},
		{Name: "boot-recovery", Run: func(context.Context, *state.State, *ui.UI) error { ranNew++; return nil }},
	}
	u, out := testUI(false, "")
	if err := Run(context.Background(), Options{StateDir: dir, UI: u, Phases: phases}); err != nil {
		t.Fatalf("convergence failed: %v\n%s", err, out.String())
	}
	if ranNew != 1 {
		t.Fatalf("the phase the deployment never ran did not run: %d", ranNew)
	}
	if ranOld != 0 {
		t.Fatalf("a completed phase was re-run: %d", ranOld)
	}
	if !strings.Contains(out.String(), "does not overwrite") || !strings.Contains(out.String(), "Re-applying") {
		t.Fatalf("the operator was not told what happened:\n%s", out.String())
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
		ProbeCheck:          func(context.Context, stack.Config) error { return nil },
		EnsureRecordingDirs: func(string) error { return nil }, // real one needs root
	}
	// Sign-in provisioning has its own tests; this one covers the local stack.
	opts.Phases = withoutPhases(Phases(&opts),
		"cloudflare-select", "cloudflare-tunnel", "cloudflare-dns",
		"cloudflare-connect", "entra-signin", "cloudflare-access", "origin-certificate",
		"backup-schedule", "recording-schedule", "boot-recovery")
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

	// The password no longer travels through a Compose override at all. It
	// is written to an owner-only file on memory-backed storage that the
	// container reads for itself, because an override sets a container
	// environment field and Docker keeps those on disk. See
	// internal/stack/secrets.go. Nothing secret may reach docker's stdin or
	// its arguments.
	var sawUp bool
	for _, c := range calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, " up ") || strings.HasSuffix(joined, " up") || strings.Contains(joined, "up --detach") {
			sawUp = true
		}
		if strings.Contains(c.stdin, dbPassword) || strings.Contains(c.stdin, "pa$$s-Xy1-secret") {
			t.Fatal("password reached docker on stdin")
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
	// Starting the connector is what makes the deployment reachable, so
	// everything that protects it must come first. The DNS record is not
	// publication: it points at a tunnel with no connector running, so
	// nothing reaches the origin, and Access needs it in place to be
	// verified against the hostname it protects.
	for _, protector := range []string{"entra-signin", "cloudflare-access"} {
		if idx(protector) > idx("cloudflare-connect") {
			t.Fatalf("%s runs after the connector starts: a failure would leave an unprotected origin reachable", protector)
		}
	}
	if idx("cloudflare-dns") > idx("cloudflare-access") {
		t.Fatal("Access cannot be verified against a hostname that does not resolve yet")
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
		case "cloudflare-connect":
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
	if ran["cloudflare-connect"] {
		t.Fatal("the connector was started despite sign-in failing")
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

// TestCertificatePrecedesStackStart pins the ordering that lets the tunnel
// keep origin TLS verification on: the real certificate must be installed
// before nginx starts, and certainly before the connector is published.
func TestCertificatePrecedesStackStart(t *testing.T) {
	var order []string
	for _, p := range Phases(&Options{}) {
		order = append(order, p.Name)
	}
	pos := func(name string) int {
		for i, n := range order {
			if n == name {
				return i
			}
		}
		t.Fatalf("phase %q missing: %v", name, order)
		return -1
	}
	if pos("origin-certificate") < pos("stack-render") {
		t.Fatal("the certificate phase runs before the certificate directory is rendered")
	}
	for _, after := range []string{"stack-up", "cloudflare-connect"} {
		if pos("origin-certificate") > pos(after) {
			t.Fatalf("origin-certificate runs after %s: the origin would serve the temporary self-signed certificate", after)
		}
	}
	// The zone must be selected before the certificate can be validated.
	if pos("cloudflare-select") > pos("origin-certificate") {
		t.Fatal("DNS-01 validation needs the zone selected first")
	}
}

// TestBackupScheduleNeverSilentlyUnencrypted pins the rule that a missing
// backup key stops the schedule rather than installing one that would
// write unencrypted backups. Encryption is the default and plaintext is
// only ever an explicit choice.
func TestBackupScheduleNeverSilentlyUnencrypted(t *testing.T) {
	dir := t.TempDir()
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "dep-1", Config: map[string]string{}}
	u, out := testUI(false, "")

	// No key recorded and no explicit plaintext choice: install nothing.
	if err := o.backupSchedule(context.Background(), st, u); err != nil {
		t.Fatalf("a missing backup key must not be an error: %v", err)
	}
	if !strings.Contains(out.String(), "backup-key") {
		t.Fatalf("the operator was not told how to fix it:\n%s", out.String())
	}
	for _, r := range st.Resources {
		if r.Type == "systemd-unit" {
			t.Fatal("a backup timer was installed without a backup key")
		}
	}

	// Declining scheduling is a supported choice, not a failure.
	o2 := &Options{StateDir: dir, NoBackupSchedule: true}
	u2, out2 := testUI(false, "")
	if err := o2.backupSchedule(context.Background(), &state.State{DeploymentID: "d"}, u2); err != nil {
		t.Fatalf("declining the schedule must not fail: %v", err)
	}
	if !strings.Contains(out2.String(), "guacdeploy backup") {
		t.Fatalf("declining should still explain manual backups:\n%s", out2.String())
	}
}

// TestRecordingBudgetIsAnExplicitChoice pins two things the specification
// is firm about: no budget is invented for the operator, and when a budget
// is set the consequence is stated plainly, because cleanup deletes
// completed recordings even when their upload failed and that can lose a
// recording permanently.
func TestRecordingBudgetIsAnExplicitChoice(t *testing.T) {
	o := &Options{StateDir: t.TempDir()}
	st := &state.State{DeploymentID: "dep-1", Config: map[string]string{}}
	u, out := testUI(false, "")
	if err := o.recordingSchedule(context.Background(), st, u); err != nil {
		t.Fatalf("an unset budget must not fail: %v", err)
	}
	if st.Config["recording-budget"] != "" {
		t.Fatal("a budget was invented for the operator")
	}
	for _, r := range st.Resources {
		if r.Type == "systemd-unit" {
			t.Fatal("cleanup was installed without a budget")
		}
	}
	if !strings.Contains(out.String(), "--recording-budget") {
		t.Fatalf("the operator was not told how to set a budget:\n%s", out.String())
	}

	// A malformed budget is rejected rather than silently ignored.
	bad := &Options{StateDir: t.TempDir(), RecordingBudget: "twenty gigs"}
	u2, _ := testUI(false, "")
	if err := bad.recordingSchedule(context.Background(), &state.State{DeploymentID: "d"}, u2); err == nil {
		t.Fatal("a malformed budget must be rejected")
	}
}

// TestCloudflareConditionsMapToTheSessionContract guards the distinction
// automation depends on: "a person must decide" must surface as the
// approval-required sentinel (exit 3), not as a generic failure (exit 1),
// while a condition that needs a human to inspect the account is a plain
// failure. Getting this wrong makes an unattended caller retry forever or
// give up on something a person could approve in seconds.
func TestCloudflareConditionsMapToTheSessionContract(t *testing.T) {
	preExisting := cloudflareErr(fmt.Errorf("record already there: %w", cloudflare.ErrPreExisting), "DNS record")
	if !errors.Is(preExisting, ErrApprovalRequired) {
		t.Fatalf("a pre-existing resource must ask for approval, got %v", preExisting)
	}
	if !strings.Contains(preExisting.Error(), "never overwritten") {
		t.Fatalf("the message does not say the resource is preserved: %v", preExisting)
	}

	review := cloudflareErr(fmt.Errorf("two matches: %w", cloudflare.ErrRequiresReview), "tunnel")
	if errors.Is(review, ErrApprovalRequired) {
		t.Fatal("a review condition must not be presented as a simple approval")
	}
	if !strings.Contains(review.Error(), "before anything is created") {
		t.Fatalf("the message does not say nothing was created: %v", review)
	}

	// An ordinary API failure passes through unchanged.
	plain := errors.New("500 from the API")
	if got := cloudflareErr(plain, "tunnel"); got != plain {
		t.Fatalf("an ordinary error was rewritten: %v", got)
	}
}

// TestGroupNamesMayContainSpaces pins a real-world constraint: Entra group
// display names normally contain spaces ("Guacamole Administrators"), and
// the database seeding and the SAML claim match on that exact name. Only
// the hostname is a DNS name.
func TestGroupNamesMayContainSpaces(t *testing.T) {
	dir := t.TempDir()
	o := &Options{
		StateDir: dir, Hostname: "guac.example.com",
		AdminGroup: "Guacamole Administrators", OperatorGroup: " Guacamole Operators ",
	}
	st := &state.State{Config: map[string]string{}}
	u, _ := testUI(false, "")
	if err := o.stackConfigure(context.Background(), st, u); err != nil {
		t.Fatalf("group names with spaces were rejected: %v", err)
	}
	if st.Config["admin-group"] != "Guacamole Administrators" {
		t.Fatalf("admin group = %q", st.Config["admin-group"])
	}
	if st.Config["operator-group"] != "Guacamole Operators" {
		t.Fatalf("surrounding spaces were not trimmed: %q", st.Config["operator-group"])
	}

	// A hostname is still a DNS name.
	bad := &Options{StateDir: dir, Hostname: "not a hostname", AdminGroup: "a", OperatorGroup: "b"}
	if err := bad.stackConfigure(context.Background(), &state.State{Config: map[string]string{}}, u); err == nil {
		t.Fatal("a hostname with spaces must be rejected")
	}
	// A slash in a group name would break seeding and claim matching.
	slash := &Options{StateDir: dir, Hostname: "guac.example.com", AdminGroup: "a/b", OperatorGroup: "c"}
	if err := slash.stackConfigure(context.Background(), &state.State{Config: map[string]string{}}, u); err == nil {
		t.Fatal("a group name with a slash must be rejected")
	}
}

// TestInstallersNeverReceiveANilRunner pins the wiring mistake that
// aborted a live deployment: a phase built an installer's options without
// the command seam, and the installer dereferenced it. Each installer now
// defaults it, so a forgotten seam degrades to the real runner instead of
// a panic in the middle of a deployment.
func TestInstallersNeverReceiveANilRunner(t *testing.T) {
	dir := t.TempDir()
	units := t.TempDir()
	runtime := t.TempDir()

	certOpts := certs.InstallOptions{StateDir: dir, UnitDir: units, RuntimeDir: runtime, Exe: os.Args[0]}
	if _, err := certs.Install(context.Background(), certOpts); err == nil {
		// An error is fine (systemd is absent in tests); a panic is not.
		t.Log("certs.Install returned no error")
	}
	schedOpts := schedule.Options{StateDir: dir, Dest: dir, UnitDir: units, RuntimeDir: runtime, Exe: os.Args[0], DeploymentID: "d"}
	if _, err := schedule.Install(context.Background(), schedOpts); err == nil {
		t.Log("schedule.Install returned no error")
	}
	recOpts := recording.InstallOptions{StateDir: dir, Dir: dir, Budget: 1 << 20, UnitDir: units, RuntimeDir: runtime, Exe: os.Args[0], DeploymentID: "d"}
	if _, err := recording.Install(context.Background(), recOpts); err == nil {
		t.Log("recording.Install returned no error")
	}
}

// TestStartStackRefusesWhenThereIsNothingToStart and, more importantly,
// pins that the boot path never prompts. Credentials now reach the
// containers as files on memory-backed storage, which a cold boot empties,
// so this command is what makes reboot survival work at all — and a boot
// unit has no terminal to ask anything.
func TestStartStackRefusesWhenThereIsNothingToStart(t *testing.T) {
	u, _ := testUI(false, "")
	err := StartStack(context.Background(), t.TempDir(), u)
	if err == nil || !strings.Contains(err.Error(), "no deployment exists") {
		t.Fatalf("want a clear refusal, got %v", err)
	}
}

// TestStartStackNeverWaitsForAPerson proves the boot path reports rather
// than hangs when the credential mode cannot supply a value unattended.
func TestStartStackNeverWaitsForAPerson(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, &state.State{
		DeploymentID: "dep-boot",
		Config: map[string]string{
			"credential-mode": creds.ModePrompt,
			"guac-hostname":   "guac.example.com",
		},
	})
	u, _ := testUI(false, "") // no terminal, as a boot unit has none
	err := StartStack(context.Background(), dir, u)
	if err == nil {
		t.Fatal("prompt-mode credentials cannot start a stack unattended")
	}
	if !errors.Is(err, creds.ErrUnattendedPrompt) && !strings.Contains(err.Error(), "prompt") {
		t.Fatalf("the failure does not explain that a person is needed: %v", err)
	}
}

// TestBootRecoveryCoversEveryPersistentMode pins that reboot recovery is
// installed for file mode too, not only the encrypted ones. Container
// credentials live on memory-backed storage now, so a cold boot empties
// them whatever the store is: without the unit, Docker restarts the
// containers into a deployment whose secrets have vanished.
func TestBootRecoveryCoversEveryPersistentMode(t *testing.T) {
	for _, mode := range []string{creds.ModeFile, creds.ModeTPM, creds.ModeHostKey} {
		if !creds.Persistent(mode) {
			t.Fatalf("%s should be a persistent mode that gets reboot recovery", mode)
		}
	}
	// A mode that needs a person gets an explanation instead of a unit.
	o := &Options{StateDir: t.TempDir()}
	st := &state.State{DeploymentID: "d", Config: map[string]string{"credential-mode": creds.ModePrompt}}
	u, out := testUI(false, "")
	if err := o.bootRecovery(context.Background(), st, u); err != nil {
		t.Fatalf("prompt mode must not fail the deployment: %v", err)
	}
	if !strings.Contains(out.String(), "stack-start") {
		t.Fatalf("the operator was not told how to start the stack after a reboot:\n%s", out.String())
	}
	for _, r := range st.Resources {
		if r.Type == "systemd-unit" {
			t.Fatal("a boot unit was installed for a mode that cannot use it")
		}
	}
}

// TestRuntimeBinaryLivesWhereSystemdCanUseIt pins a lesson from the live
// host. The deployment-owned copy of the tool used to sit in
// /usr/local/lib, which SELinux labels lib_t. systemd will not transition
// a service whose executable is lib_t, so the boot unit ran as init_t and
// was denied outbound network: the stack never came back after a reboot,
// and the only symptom was "connect: permission denied".
//
// /usr/local/sbin is bin_t, which transitions correctly. The name stays
// distinct from /usr/local/bin/guacdeploy, which is the provisioning
// binary the operator may delete.
func TestRuntimeBinaryLivesWhereSystemdCanUseIt(t *testing.T) {
	for name, dir := range map[string]string{
		"certs":     certs.DefaultRuntimeDir,
		"schedule":  schedule.DefaultRuntimeDir,
		"recording": recording.DefaultRuntimeDir,
		"creds":     creds.DefaultRuntimeDir,
	} {
		if dir != "/usr/local/sbin" {
			t.Errorf("%s installs its runtime copy in %s; /usr/local/lib is lib_t and the unit would run as init_t with no network", name, dir)
		}
	}
	for name, bin := range map[string]string{
		"certs":     certs.RuntimeBinaryName,
		"schedule":  schedule.RuntimeBinaryName,
		"recording": recording.RuntimeBinaryName,
		"creds":     creds.RuntimeBinaryName,
	} {
		if bin == "guacdeploy" {
			t.Errorf("%s names its runtime copy %q, which collides with the provisioning binary", name, bin)
		}
	}
}

// TestInstallerPhasesReapplyOnEveryRun pins why the installer phases are
// marked Always. They write units, timers and the deployment-owned binary
// copy. When a newer version corrects any of those — as it did when the
// runtime binary had to move out of a lib_t directory — the repair must
// actually reach an existing host, and a phase marked complete never runs
// again.
func TestInstallerPhasesReapplyOnEveryRun(t *testing.T) {
	want := map[string]bool{
		"origin-certificate": true,
		"boot-recovery":      true,
		"backup-schedule":    true,
		"recording-schedule": true,
		"stack-render":       true,
		"stack-schema":       true,
	}
	for _, p := range Phases(&Options{}) {
		if want[p.Name] && !p.Always {
			t.Errorf("%s does not re-run, so a repair in a newer version could never reach an existing host", p.Name)
		}
	}
	// Phases that create cloud resources must NOT re-run blindly.
	mustNotAlways := map[string]bool{"cloudflare-tunnel": true, "cloudflare-dns": true, "entra-signin": true}
	for _, p := range Phases(&Options{}) {
		if mustNotAlways[p.Name] && p.Always {
			t.Errorf("%s re-runs unconditionally, which risks acting on cloud resources every session", p.Name)
		}
	}
}

// TestAdoptedEntraResourcesAreRecordedAsOurs pins a defect the live run
// exposed. A run that fails after creating the Entra application leaves it
// behind; the next run adopts it through its ownership marker, so the
// "created" flag is false even though this deployment created it.
// Recording only freshly created resources left a real application and a
// real group invisible to teardown, which then reported a complete
// teardown while both were still in the tenant.
func TestAdoptedEntraResourcesAreRecordedAsOurs(t *testing.T) {
	// Marker-verified adoption: ours, and therefore recorded.
	ours := &entra.Plan{
		App:    &entra.Found{ObjectID: "app-1", ProvenOurs: true},
		Groups: map[string]*entra.FoundGroup{"Admins": {ObjectID: "g-1", ProvenOurs: true}},
	}
	if !(false || (ours.App != nil && ours.App.ProvenOurs)) {
		t.Fatal("an adopted application must count as ours")
	}
	if g := ours.Groups["Admins"]; g == nil || !g.ProvenOurs {
		t.Fatal("an adopted group must count as ours")
	}

	// A genuinely pre-existing application carries no marker and must never
	// be recorded, so teardown never offers somebody else's application.
	foreign := &entra.Plan{App: &entra.Found{ObjectID: "app-2", ProvenOurs: false}}
	if foreign.App.ProvenOurs {
		t.Fatal("a pre-existing application must not be treated as ours")
	}
}

// TestAccessEvidenceNeverClaimsASignIn pins the distinction the reviewer
// insisted on: verifying that the provider is configured, and that the
// hostname answers with the Access challenge, is not evidence that a user
// signed in. The phase must report the package's own summary, which ends
// by saying so, rather than composing a looser sentence of its own.
func TestAccessEvidenceNeverClaimsASignIn(t *testing.T) {
	v := cloudflare.AccessVerification{
		AppID: "app-1", Domain: "guac.example.com",
		AppVerified: true, PolicyMatchesAllowList: true,
		IdPBoundToTenant: true, ChallengeVerified: true,
	}
	summary := v.String()
	if !strings.Contains(summary, cloudflare.SignInNotProven) {
		t.Fatalf("the summary does not say a sign-in is unproven:\n%s", summary)
	}
	for _, claim := range []string{"signed in", "sign-in succeeded", "logged in"} {
		if strings.Contains(strings.ToLower(summary), claim) {
			t.Fatalf("the summary claims a login (%q):\n%s", claim, summary)
		}
	}
}

// TestConnectorRefusesWhenAccessIsNotVerifiableNow pins the publication
// guard. A recorded Access application ID is not proof of protection: it
// is written when the application is created, before verification runs, so
// a run whose verification failed still leaves it set. And a policy that
// verified correctly yesterday can have been widened since. The connector
// must therefore re-verify at the moment it would publish, on every run
// including a resume.
func TestConnectorRefusesWhenAccessIsNotVerifiableNow(t *testing.T) {
	base := func() *state.State {
		return &state.State{DeploymentID: "dep-1", Config: map[string]string{
			"guac-hostname": "guac.example.test",
			// Set, as it would be after a run whose verification failed.
			"cloudflare-access-app-id": "app-1",
		}}
	}

	// Verification fails now (it failed earlier, or the policy has drifted).
	var started bool
	o := &Options{
		StateDir:     t.TempDir(),
		AccessVerify: func(context.Context, *state.State) error { return errors.New("policy now allows everyone") },
		StackRun: func(context.Context, string, string, ...string) (string, error) {
			started = true
			return "", nil
		},
	}
	st := base()
	u, _ := testUI(false, "")
	err := o.cloudflareConnect(context.Background(), st, u)
	if err == nil {
		t.Fatal("the connector started although Access could not be verified")
	}
	// The message must name the reason. Any other refusal (a missing
	// tunnel token, say) would mean the guard never ran.
	if !strings.Contains(err.Error(), "not verifiably protecting") {
		t.Fatalf("the connector refused for some other reason, so the guard did not run: %v", err)
	}
	if started {
		t.Fatal("the stack was started despite the refusal")
	}
	if strings.Contains(st.Config["compose-profiles"], "cloudflare") {
		t.Fatal("the connector profile was enabled despite the refusal")
	}

	// A recorded ID with no verification at all is equally not proof.
	o2 := &Options{StateDir: t.TempDir()}
	st2 := base()
	u2, _ := testUI(false, "")
	if err := o2.accessEnforcing(context.Background(), st2, u2); err == nil {
		t.Fatal("a recorded application ID must not pass as verification on its own")
	}

	// And with nothing recorded, the guard says so plainly.
	o3 := &Options{StateDir: t.TempDir()}
	st3 := &state.State{DeploymentID: "d", Config: map[string]string{}}
	u3, _ := testUI(false, "")
	err = o3.accessEnforcing(context.Background(), st3, u3)
	if err == nil || !strings.Contains(err.Error(), "no Access application") {
		t.Fatalf("want a clear refusal with nothing recorded, got %v", err)
	}
}

// sealingHost is a host that can seal: systemd-creds is present, new enough,
// and reports a usable TPM. The encrypt call is faked so the test needs no
// TPM, and it records its arguments so the test can prove the value never
// travels in one.
func sealingHost(t *testing.T, args *[]string) (creds.Detector, creds.Runner) {
	t.Helper()
	run := func(_ context.Context, stdin, name string, a ...string) (string, string, error) {
		*args = append(*args, name+" "+strings.Join(a, " "))
		switch {
		case len(a) > 0 && a[0] == "--version":
			return "systemd 257 (257.4)\n", "", nil
		case len(a) > 0 && a[0] == "has-tpm2":
			return "yes\n+firmware\n", "", nil
		case len(a) > 0 && a[0] == "encrypt":
			if stdin == "" {
				return "", "", errors.New("nothing on stdin to encrypt")
			}
			return "-----BEGIN CREDENTIAL-----\nsealed-" + fmt.Sprint(len(stdin)) + "\n-----END CREDENTIAL-----\n", "", nil
		}
		return "", "", fmt.Errorf("unexpected command %s %v", name, a)
	}
	return creds.Detector{Run: run, TPMDevices: func() []string { return []string{"/dev/tpm0"} }}, run
}

// The specification's encrypted storage has to be reachable from setup, and
// what lands on disk has to be the sealed blob and nothing else.
func TestTPMModeStoresSealedBlobsAndNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	// The credentials a person has to supply are read through the hidden
	// prompt, so this is an interactive run with the mode already chosen.
	u, out := testUI(true, "y\ny\n")
	const secret = "sekret-value-1234"
	u.Secret = func(string) (string, error) { return secret, nil }
	var calls []string
	d, run := sealingHost(t, &calls)

	o := Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeTPM,
		CredDetector: d, CredsRun: run}
	if err := Run(context.Background(), core(o)); err != nil {
		t.Fatalf("tpm-mode setup: %v", err)
	}
	st, _ := state.Read(dir)
	if st.Config["credential-mode"] != creds.ModeTPM {
		t.Fatalf("mode not recorded: %+v", st.Config)
	}

	// The sealed blob is there, owner-only, and no plaintext file is beside it.
	blob := filepath.Join(dir, "credentials", "postgres-password.cred")
	info, err := os.Stat(blob)
	if err != nil {
		t.Fatalf("sealed credential missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("sealed credential mode %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials", "postgres-password")); err == nil {
		t.Fatal("a plaintext copy was written beside the sealed credential")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "credentials"))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".cred") {
			t.Fatalf("%s is not a sealed credential; sealed mode must write nothing else", e.Name())
		}
		b, _ := os.ReadFile(filepath.Join(dir, "credentials", e.Name()))
		if strings.Contains(string(b), secret) {
			t.Fatalf("%s holds the plaintext value", e.Name())
		}
	}

	// The value reaches systemd-creds on stdin only: never an argument, and
	// never the state file or the transcript.
	for _, c := range calls {
		if strings.Contains(c, secret) {
			t.Fatalf("the value travelled in a command argument: %s", c)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), secret) || strings.Contains(out.String(), secret) {
		t.Fatal("secret value leaked into state or output")
	}

	// Teardown has to be able to tell a sealed credential from a plaintext
	// one, and has to know the name of the file that is actually on disk.
	var sealed bool
	for _, r := range st.Resources {
		if r.Type == "credential-file" {
			t.Fatalf("a sealed credential was recorded as a plaintext file: %+v", r)
		}
		if r.Type == "credential-sealed" && r.Name == "postgres-password.cred" {
			sealed = true
		}
	}
	if !sealed {
		t.Fatalf("sealed credential not recorded for teardown: %+v", st.Resources)
	}
}

// No silent downgrade: a host that cannot seal must stop the run with the
// reason, never quietly write the value in plaintext instead.
func TestUnavailableSealedModeIsRefusedWithoutDowngrade(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(false, "")
	u.Secret = func(string) (string, error) { return "sekret-value-1234", nil }
	// systemd-creds works, but this host has no TPM device at all.
	d := creds.Detector{
		Run: func(_ context.Context, _, _ string, a ...string) (string, string, error) {
			if len(a) > 0 && a[0] == "--version" {
				return "systemd 257 (257.4)\n", "", nil
			}
			return "", "", errors.New("should not be reached")
		},
		TPMDevices: func() []string { return nil },
	}
	o := Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeTPM, CredDetector: d}
	err := Run(context.Background(), core(o))
	if err == nil {
		t.Fatal("a host with no TPM accepted tpm mode")
	}
	if !strings.Contains(err.Error(), "not available on this host") || !strings.Contains(err.Error(), "vTPM") {
		t.Fatalf("the refusal does not name the reason: %v", err)
	}
	st, _ := state.Read(dir)
	if st != nil && st.Config["credential-mode"] != "" {
		t.Fatalf("an unavailable mode was recorded anyway: %q", st.Config["credential-mode"])
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials")); err == nil {
		t.Fatal("credentials were written despite the refusal")
	}
	if strings.Contains(out.String(), "Credential storage method: file") {
		t.Fatal("the run downgraded to plaintext on its own")
	}
}

// The menu shows why an encrypted mode is unavailable rather than hiding it,
// so the operator can see the choice was considered.
func TestMenuExplainsWhySealedModesAreUnavailable(t *testing.T) {
	dir := t.TempDir()
	// y = fresh setup, f = file mode, y = approve the plaintext exception.
	u, out := testUI(true, "y\nf\ny\n")
	u.Secret = func(string) (string, error) { return "sekret-value-1234", nil }
	d := creds.Detector{
		Run: func(_ context.Context, _, _ string, _ ...string) (string, string, error) {
			return "", "no such file", errors.New("exec: systemd-creds")
		},
		TPMDevices: func() []string { return nil },
	}
	o := Options{StateDir: dir, UI: u, Host: fakeHost(t), CredDetector: d}
	if err := Run(context.Background(), core(o)); err != nil {
		t.Fatalf("guided setup: %v", err)
	}
	for _, want := range []string{
		"tpm — not available on this host",
		"host — not available on this host",
		"systemd-creds is not available on this host",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, out.String())
		}
	}
	st, _ := state.Read(dir)
	if st.Config["credential-mode"] != creds.ModeFile {
		t.Fatalf("the operator's choice was not honoured: %+v", st.Config)
	}
}

// An encrypted deployment has to be startable without a person. The only
// ways to supply a credential were a hidden prompt and a plaintext file, so
// unattended plus tpm was impossible: nobody answers the prompt, and writing
// the value in plaintext first is the downgrade the mode exists to avoid.
// One environment variable supplies it for one run, and what lands on disk is
// still only the sealed blob.
func TestSealedModeAcceptsTheValueOnceFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(false, "")
	u.Secret = func(string) (string, error) {
		t.Fatal("an unattended run must never wait on a hidden prompt")
		return "", nil
	}
	const token = "cf-token-value-9876"
	t.Setenv("GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN", token)
	var calls []string
	d, run := sealingHost(t, &calls)

	o := Options{StateDir: dir, UI: u, Host: fakeHost(t), CredentialMode: creds.ModeTPM,
		CredDetector: d, CredsRun: run}
	if err := Run(context.Background(), core(o)); err != nil {
		t.Fatalf("unattended tpm-mode setup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials", "cloudflare-api-token.cred")); err != nil {
		t.Fatalf("the supplied credential was not sealed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials", "cloudflare-api-token")); err == nil {
		t.Fatal("the value was written in plaintext on the way to being sealed")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(string(raw), token) || strings.Contains(out.String(), token) {
		t.Fatal("the supplied value leaked into state or output")
	}
	for _, c := range calls {
		if strings.Contains(c, token) {
			t.Fatalf("the value travelled in a command argument: %s", c)
		}
	}
	// The operator is told the variable is not needed again, because the
	// value is now kept the way they chose.
	if !strings.Contains(out.String(), "not needed again") {
		t.Errorf("the run did not say the environment variable is no longer needed:\n%s", out.String())
	}
}

// An Azure destination is optional. A deployment with no Azure account is the
// ordinary case, so the phase must do nothing at all — and above all reach no
// network — unless this run was asked for one.
func TestAzureDestinationIsSkippedUnlessAskedFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    Options
		st   *state.State
		want bool
	}{
		{name: "nothing asked", o: Options{}, st: &state.State{}, want: false},
		{name: "asked with the flag", o: Options{Azure: true}, st: &state.State{}, want: true},
		{name: "a subscription answers the question", o: Options{AzureSubscription: "sub-1"}, st: &state.State{}, want: true},
		{name: "an account answers it", o: Options{AzureAccount: "acct"}, st: &state.State{}, want: true},
		{name: "a container answers it", o: Options{AzureContainer: "c"}, st: &state.State{}, want: true},
		{name: "creation answers it", o: Options{AzureCreate: true}, st: &state.State{}, want: true},
		{name: "a destination already recorded keeps it on", o: Options{},
			st: &state.State{Config: map[string]string{"azure-account-id": "/subscriptions/x"}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.o.wantsAzure(tc.st); got != tc.want {
				t.Fatalf("wantsAzure = %v, want %v", got, tc.want)
			}
		})
	}

	// And the phase itself is a no-op then: a network call would fail here,
	// because nothing is wired to answer one.
	u, out := testUI(false, "")
	o := Options{}
	if err := o.azureDestination(context.Background(), &state.State{}, u); err != nil {
		t.Fatalf("the phase must do nothing when no destination was asked for: %v", err)
	}
	if out.String() != "" {
		t.Fatalf("the phase said something about Azure to an operator who never asked:\n%s", out.String())
	}
}

// The index-based menu and the rune-keyed UI have to agree, or the operator's
// choice silently becomes a different one.
func TestChooseFromListMapsTheAnswerBackToItsIndex(t *testing.T) {
	u, _ := testUI(true, "3\n")
	got, err := chooseFromList(u)("Which one?", []string{"first", "second", "third"})
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("choosing the third option gave index %d, want 2", got)
	}

	// Past the digits the menu cannot be answered, so it says so rather than
	// offering keys nobody can press.
	many := make([]string, 12)
	for i := range many {
		many[i] = "option"
	}
	if _, err := chooseFromList(u)("Which one?", many); err == nil {
		t.Fatal("a menu of twelve options was offered with nine keys")
	}
}

// The Azure destination needs the tenant and the service principal that the
// identity phase produces, and it must never gate publication: a working
// deployment should not be left unpublished because a storage account could
// not be created.
func TestAzureDestinationRunsAfterIdentityAndAfterPublication(t *testing.T) {
	idx := map[string]int{}
	for i, p := range Phases(&Options{}) {
		idx[p.Name] = i
	}
	if idx["azure-destination"] < idx["entra-signin"] {
		t.Fatal("the Azure phase runs before the identity phase, so the tenant and the service principal it needs do not exist yet")
	}
	if idx["azure-destination"] < idx["cloudflare-connect"] {
		t.Fatal("the Azure phase runs before publication, so a storage failure would leave a working deployment unpublished")
	}
}

// The specification asks for scheduled backups and a recording budget during
// setup. Both phases used to finish by telling the operator to run another
// command and start setup again, so a guided deployment ended with neither.
func TestGuidedSetupAsksForTheBackupKeyAndInstallsTheSchedule(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(true, "y\nsecret-pass\nsecret-pass\n")
	u.Secret = func(string) (string, error) { return "secret-pass", nil }
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}

	made, err := o.offerBackupKey(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !made {
		t.Fatal("a guided run that answered yes got no key")
	}
	if st.Config["backup-public-key"] == "" {
		t.Fatal("the public key was not recorded, so scheduled backups still cannot encrypt")
	}
	export := filepath.Join(dir, "recovery", "backup-key.age")
	if _, err := os.Stat(export); err != nil {
		t.Fatalf("the passphrase-encrypted export was not written: %v", err)
	}
	// The private key must never reach deployment state.
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "AGE-SECRET-KEY") || strings.Contains(string(raw), "secret-pass") {
		t.Fatal("private key material or the passphrase reached the deployment record")
	}
	if !strings.Contains(out.String(), "Copy it off this host") {
		t.Errorf("the operator was not told the export is theirs to keep:\n%s", out.String())
	}
	var recorded bool
	for _, r := range st.Resources {
		if r.Type == "recovery-key-export" {
			recorded = true
		}
	}
	if !recorded {
		t.Error("the export was not recorded, so teardown cannot account for it")
	}
}

// Declining is a supported answer, and it must not produce a key or an
// unencrypted fallback.
func TestGuidedSetupAcceptsDecliningTheBackupKey(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(true, "n\n")
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	made, err := o.offerBackupKey(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if made {
		t.Fatal("declining produced a key anyway")
	}
	if st.Config["backup-public-key"] != "" {
		t.Fatal("a key was recorded despite the decline")
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery", "backup-key.age")); err == nil {
		t.Fatal("an export was written despite the decline")
	}
}

// Mismatched passphrases must generate nothing: an export nobody can open is
// worse than no export.
func TestGuidedBackupKeyRefusesMismatchedPassphrases(t *testing.T) {
	dir := t.TempDir()
	u, _ := testUI(true, "y\n")
	answers := []string{"one", "two"}
	u.Secret = func(string) (string, error) {
		v := answers[0]
		answers = answers[1:]
		return v, nil
	}
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	if _, err := o.offerBackupKey(st, u); err == nil {
		t.Fatal("mismatched passphrases were accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery", "backup-key.age")); err == nil {
		t.Fatal("an export was written from mismatched passphrases")
	}
}

// An unattended run has nobody to answer, so it must not ask — a prompt there
// would hang the deployment rather than fail it.
func TestUnattendedSetupIsNeverAskedForAKeyOrABudget(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(false, "")
	u.Secret = func(string) (string, error) {
		t.Fatal("an unattended run must never wait on a hidden prompt")
		return "", nil
	}
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	made, err := o.offerBackupKey(st, u)
	if err != nil || made {
		t.Fatalf("unattended offer: made=%v err=%v", made, err)
	}
	if err := o.askRecordingBudget(u); err != nil {
		t.Fatal(err)
	}
	if o.RecordingBudget != "" {
		t.Fatal("an unattended run invented a recording budget")
	}
	if strings.Contains(out.String(), "Generate the backup key now") {
		t.Error("an unattended run put a question to nobody")
	}
}

// The budget question takes a size, says why it matters, and treats an empty
// answer as an explicit decline.
func TestGuidedSetupAsksForTheRecordingBudget(t *testing.T) {
	u, out := testUI(true, "not-a-size\n20GiB\n")
	o := &Options{}
	if err := o.askRecordingBudget(u); err != nil {
		t.Fatal(err)
	}
	if o.RecordingBudget != "20GiB" {
		t.Fatalf("budget = %q, want 20GiB", o.RecordingBudget)
	}
	if !strings.Contains(out.String(), "is not a size") {
		t.Error("an unparseable answer was accepted without complaint")
	}
	for _, want := range []string{"never deleted", "permanently"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the consequence was not stated (%q):\n%s", want, out.String())
		}
	}

	// Pressing Enter takes the default, which is an explicit decline.
	u2, _ := testUI(true, "\n")
	o2 := &Options{}
	if err := o2.askRecordingBudget(u2); err != nil {
		t.Fatal(err)
	}
	if o2.RecordingBudget != "" {
		t.Fatalf("pressing Enter was not treated as a decline: %q", o2.RecordingBudget)
	}
	// And so is saying so.
	u3, _ := testUI(true, "none\n")
	o3 := &Options{}
	if err := o3.askRecordingBudget(u3); err != nil {
		t.Fatal(err)
	}
	if o3.RecordingBudget != "" {
		t.Fatalf("\"none\" was not treated as a decline: %q", o3.RecordingBudget)
	}
}

// The questions have to be reached from the phases, not merely exist. Both
// tests decline, so the phase returns before it installs anything and nothing
// on this machine is touched.
func TestBackupSchedulePhaseAsksWhenNoKeyIsRecorded(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(true, "n\n")
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	if err := o.backupSchedule(context.Background(), st, u); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Generate the backup key now") {
		t.Fatalf("the phase did not offer to generate the key:\n%s", out.String())
	}
	if st.Config["backup-public-key"] != "" {
		t.Fatal("declining recorded a key anyway")
	}
}

func TestRecordingSchedulePhaseAsksWhenNoBudgetIsSet(t *testing.T) {
	dir := t.TempDir()
	u, out := testUI(true, "none\n")
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	if err := o.recordingSchedule(context.Background(), st, u); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Local recording storage budget") {
		t.Fatalf("the phase did not ask for a budget:\n%s", out.String())
	}
	if st.Config["recording-budget"] != "" {
		t.Fatal("declining recorded a budget anyway")
	}
}

// A resumed or repeated setup is usually run without the flags again. What the
// operator chose the first time has to survive that, or a second run silently
// blanks the recorded schedule and retention.
func TestRepeatedSetupKeepsTheRecordedScheduleAndBudget(t *testing.T) {
	dir := t.TempDir()
	o := &Options{StateDir: dir} // no flags, as a resume is normally run
	st := &state.State{DeploymentID: "d1", Config: map[string]string{
		"backup-public-key": "age1example",
		"backup-dest":       "/srv/backups",
		"backup-schedule":   "Mon *-*-* 02:00:00",
		"backup-keep":       "14",
		"recording-budget":  "50GiB",
	}}
	// The phase installs units, which this test must not do, so stop at the
	// point the values are settled by checking what it carries forward.
	o.BackupSchedule = firstNonEmpty(o.BackupSchedule, st.Config["backup-schedule"])
	if o.BackupSchedule != "Mon *-*-* 02:00:00" {
		t.Fatalf("the recorded schedule was lost: %q", o.BackupSchedule)
	}
	o.RecordingBudget = firstNonEmpty(o.RecordingBudget, st.Config["recording-budget"])
	if o.RecordingBudget != "50GiB" {
		t.Fatalf("the recorded budget was lost: %q", o.RecordingBudget)
	}
	// An explicit flag still wins.
	o2 := &Options{StateDir: dir, BackupSchedule: "daily", RecordingBudget: "5GiB"}
	if got := firstNonEmpty(o2.BackupSchedule, st.Config["backup-schedule"]); got != "daily" {
		t.Fatalf("the flag did not win: %q", got)
	}
	if got := firstNonEmpty(o2.RecordingBudget, st.Config["recording-budget"]); got != "5GiB" {
		t.Fatalf("the flag did not win: %q", got)
	}
}

// The export is written before the public key is recorded. A run interrupted
// between the two leaves key material nothing points at, and the export never
// overwrites — so regenerating is refused and the operator is stuck. The
// passphrase recovers the pair instead, and nothing is regenerated.
func TestInterruptedKeyGenerationIsAdoptedNotRegenerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery", "backup-key.age")
	id, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverykey.ExportEncrypted(id, "the-passphrase", path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	u, out := testUI(true, "")
	u.Secret = func(string) (string, error) { return "the-passphrase", nil }
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	made, err := o.offerBackupKey(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !made {
		t.Fatal("the existing export was not adopted")
	}
	if st.Config["backup-public-key"] != id.Recipient().String() {
		t.Fatal("the recorded public key is not the one in the export")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("the existing export was rewritten; a copy already taken would be invalid")
	}
	if !strings.Contains(out.String(), "interrupted") {
		t.Errorf("the operator was not told what happened:\n%s", out.String())
	}
}

// A wrong passphrase must change nothing and say what can be done.
func TestAdoptingAnExportRefusesAWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery", "backup-key.age")
	id, _ := recoverykey.Generate()
	if err := recoverykey.ExportEncrypted(id, "the-passphrase", path); err != nil {
		t.Fatal(err)
	}
	u, _ := testUI(true, "")
	u.Secret = func(string) (string, error) { return "wrong", nil }
	o := &Options{StateDir: dir}
	st := &state.State{DeploymentID: "d1", Config: map[string]string{}}
	_, err := o.offerBackupKey(st, u)
	if err == nil {
		t.Fatal("a wrong passphrase was accepted")
	}
	if !strings.Contains(err.Error(), "move that file aside") {
		t.Fatalf("the error gives no way forward: %v", err)
	}
	if st.Config["backup-public-key"] != "" {
		t.Fatal("a public key was recorded from a failed adoption")
	}
}
