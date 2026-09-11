package azure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
)

// fakeHost is a unit directory that already holds an installed backup
// schedule, plus the deployment-owned runtime binary its units call.
type fakeHost struct {
	unitDir    string
	runtimeDir string
	stateDir   string
	dest       string
	ran        []string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{unitDir: t.TempDir(), runtimeDir: t.TempDir(), stateDir: t.TempDir(), dest: t.TempDir()}
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(h.unitDir, schedule.ServiceUnit),
		"# guacdeploy deployment="+testDeployment+"\n[Service]\nType=oneshot\nExecStart=/x backup-run\n")
	write(filepath.Join(h.runtimeDir, schedule.RuntimeBinaryName), "#!/bin/true\n")
	return h
}

func (h *fakeHost) options() UnitOptions {
	return UnitOptions{
		Run: func(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
			h.ran = append(h.ran, strings.Join(append([]string{name}, args...), " "))
			return "", "", nil
		},
		DeploymentID: testDeployment, StateDir: h.stateDir, Dest: h.dest,
		UnitDir: h.unitDir, RuntimeDir: h.runtimeDir,
	}
}

// TestInstallUploadExtendsTheBackupTimer is the wiring issue #19 asks for: the
// timer that takes the local backup uploads afterwards, from the
// deployment-owned binary, with no credential anywhere on the command line.
func TestInstallUploadExtendsTheBackupTimer(t *testing.T) {
	h := newFakeHost(t)
	in, err := InstallUpload(context.Background(), h.options())
	if err != nil {
		t.Fatal(err)
	}
	if !in.Changed {
		t.Fatal("the first install reported no change")
	}
	body, err := os.ReadFile(in.DropInPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	// It lands in the backup service's drop-in directory, so it runs on that
	// timer and after that backup, not on a second timer at a guessed hour.
	if dir := filepath.Base(filepath.Dir(in.DropInPath)); dir != schedule.ServiceUnit+".d" {
		t.Fatalf("drop-in directory = %s", dir)
	}
	if first, _, _ := strings.Cut(got, "\n"); first != "# guacdeploy deployment="+testDeployment {
		t.Fatalf("the drop-in carries no ownership marker: %q", first)
	}
	// The command calls the deployment-owned runtime copy, which is what lets
	// the schedule survive a reboot after the provisioning binary is deleted.
	wantExec := "ExecStart=" + filepath.Join(h.runtimeDir, schedule.RuntimeBinaryName) +
		" azure-upload --state-dir " + h.stateDir + " --dest " + h.dest
	if !strings.Contains(got, wantExec) {
		t.Fatalf("drop-in does not run the upload from the runtime binary:\n%s", got)
	}
	if !strings.Contains(got, "[Service]") {
		t.Fatalf("the drop-in has no [Service] section, so systemd would ignore it:\n%s", got)
	}
	if strings.Contains(got, "/usr/local/bin/guacdeploy ") {
		t.Fatal("the drop-in calls the provisioning binary, which the operator may delete")
	}
	for _, secret := range []string{testToken, clientSecret, refreshToken, "--client-secret", "password"} {
		if strings.Contains(got, secret) {
			t.Fatalf("the unit contains %q; the client secret is read from the credential store at the point of use", secret)
		}
	}
	if len(h.ran) != 1 || h.ran[0] != "systemctl daemon-reload" {
		t.Fatalf("commands run = %v", h.ran)
	}
}

func TestInstallUploadIsIdempotent(t *testing.T) {
	h := newFakeHost(t)
	if _, err := InstallUpload(context.Background(), h.options()); err != nil {
		t.Fatal(err)
	}
	h.ran = nil
	in, err := InstallUpload(context.Background(), h.options())
	if err != nil {
		t.Fatal(err)
	}
	if in.Changed {
		t.Fatal("a repeated install rewrote the drop-in")
	}
	if len(h.ran) != 0 {
		t.Fatalf("a repeated install churned systemd: %v", h.ran)
	}
}

// TestInstallUploadRefusesWithoutTheBackupSchedule: a drop-in for a unit that
// does not exist is a silent no-op, and "uploads are scheduled" that never run
// is the worst answer available.
func TestInstallUploadRefusesWithoutTheBackupSchedule(t *testing.T) {
	h := newFakeHost(t)
	if err := os.Remove(filepath.Join(h.unitDir, schedule.ServiceUnit)); err != nil {
		t.Fatal(err)
	}
	_, err := InstallUpload(context.Background(), h.options())
	if err == nil || !strings.Contains(err.Error(), "install the backup schedule first") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(h.options().DropInPath()); serr == nil {
		t.Fatal("a drop-in was written for a service that does not exist")
	}
}

func TestInstallUploadRefusesWithoutTheRuntimeBinary(t *testing.T) {
	h := newFakeHost(t)
	if err := os.Remove(filepath.Join(h.runtimeDir, schedule.RuntimeBinaryName)); err != nil {
		t.Fatal(err)
	}
	_, err := InstallUpload(context.Background(), h.options())
	if err == nil || !strings.Contains(err.Error(), "after a reboot") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallUploadRefusesPathsSystemdCannotQuote(t *testing.T) {
	h := newFakeHost(t)
	o := h.options()
	o.Dest = "/mnt/back ups"
	if _, err := InstallUpload(context.Background(), o); err == nil {
		t.Fatal("a destination with a space was scheduled")
	}
}

func TestUninstallUploadRemovesOnlyThisDeploymentsDropIn(t *testing.T) {
	h := newFakeHost(t)
	o := h.options()
	if _, err := InstallUpload(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	removed, err := UninstallUpload(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != o.DropInPath() {
		t.Fatalf("removed = %v", removed)
	}
	// Repeatable: a second teardown is not a failure.
	if removed, err := UninstallUpload(context.Background(), o); err != nil || removed != nil {
		t.Fatalf("second uninstall = %v, %v", removed, err)
	}
	// The backup service itself is untouched: it belongs to another package.
	if _, err := os.Stat(filepath.Join(h.unitDir, schedule.ServiceUnit)); err != nil {
		t.Fatalf("the backup service was removed by the Azure teardown: %v", err)
	}

	// A same-named drop-in written by something else stays, and is named.
	if err := os.MkdirAll(filepath.Dir(o.DropInPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.DropInPath(), []byte("# somebody else\n[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err = UninstallUpload(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "not written by this deployment") {
		t.Fatalf("err = %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v", removed)
	}
	if _, err := os.Stat(o.DropInPath()); err != nil {
		t.Fatal("a drop-in written by something else was deleted")
	}
}
