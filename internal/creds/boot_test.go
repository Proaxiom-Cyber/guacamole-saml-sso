package creds

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemctl records systemctl calls.
type fakeSystemctl struct {
	argv [][]string
	fail map[string]error
}

func (f *fakeSystemctl) run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	f.argv = append(f.argv, append([]string{name}, args...))
	return "", "", f.fail[strings.Join(args, " ")]
}

func (f *fakeSystemctl) ran(want string) bool {
	for _, c := range f.argv {
		if strings.Join(c, " ") == want {
			return true
		}
	}
	return false
}

func bootFixture(t *testing.T) (BootOptions, *fakeSystemctl) {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(root, "guacdeploy-downloaded")
	if err := os.WriteFile(exe, []byte("#!/bin/true\nbinary-v1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeSystemctl{}
	return BootOptions{
		Run: f.run, DeploymentID: "dep-1", Mode: ModeTPM,
		StateDir:   filepath.Join(root, "state"),
		UnitDir:    filepath.Join(root, "units"),
		RuntimeDir: filepath.Join(root, "runtime"),
		Exe:        exe,
	}, f
}

func TestInstallBootCopiesTheBinaryAndCallsIt(t *testing.T) {
	o, f := bootFixture(t)
	in, err := InstallBoot(context.Background(), o)
	if err != nil || !in.Changed {
		t.Fatalf("InstallBoot: %v changed=%v", err, in.Changed)
	}

	// The unit must call the deployment-owned copy, never the downloaded
	// binary: that one may be deleted the moment setup finishes.
	unit, err := os.ReadFile(in.ServicePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	if !strings.HasPrefix(text, "# guacdeploy deployment=dep-1\n") {
		t.Fatalf("the unit must carry the ownership marker first: %q", text)
	}
	if !strings.Contains(text, "ExecStart="+o.RuntimePath()+" "+BootCommand+" --state-dir "+o.StateDir+"\n") {
		t.Fatalf("unexpected ExecStart: %q", text)
	}
	if strings.Contains(text, o.Exe) {
		t.Fatal("the unit points at the provisioning binary, which may be deleted")
	}
	for _, want := range []string{"Type=oneshot", "After=docker.service", "WantedBy=multi-user.target"} {
		if !strings.Contains(text, want) {
			t.Errorf("the unit is missing %q", want)
		}
	}

	// The copy is real and executable.
	copied, err := os.ReadFile(in.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(o.Exe)
	if string(copied) != string(src) {
		t.Fatal("the installed runtime binary does not match the source")
	}
	fi, _ := os.Stat(in.RuntimePath)
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("the installed runtime binary is not executable: %v", fi.Mode())
	}
	// It is the same path internal/schedule uses, so a host that installs
	// both ends up with one binary.
	if def := (BootOptions{RuntimeDir: DefaultRuntimeDir}).RuntimePath(); def != "/usr/local/lib/guacdeploy/guacdeploy" {
		t.Fatalf("the default runtime path moved: %s", def)
	}

	if !f.ran("systemctl daemon-reload") || !f.ran("systemctl enable "+BootUnit) {
		t.Fatalf("systemd was not told about the unit: %v", f.argv)
	}
	// enable --now would restart a stack that is already running.
	if f.ran("systemctl enable --now " + BootUnit) {
		t.Fatal("InstallBoot must not start the unit during setup")
	}

	// No credential anywhere near the unit or the command line.
	for _, s := range append([]string{text}, joinAll(f.argv)...) {
		for _, bad := range []string{"password", "PASSWORD", "token"} {
			if strings.Contains(s, bad) {
				t.Fatalf("a credential-shaped word reached systemd: %q", s)
			}
		}
	}
}

func TestInstallBootIsIdempotent(t *testing.T) {
	o, f := bootFixture(t)
	if _, err := InstallBoot(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	before := len(f.argv)
	in, err := InstallBoot(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if in.Changed {
		t.Fatal("a repeated install must report no change")
	}
	// One call only: enable. No daemon-reload, because nothing changed.
	if got := f.argv[before:]; len(got) != 1 || strings.Join(got[0], " ") != "systemctl enable "+BootUnit {
		t.Fatalf("a repeated install churned systemd: %v", got)
	}
	// A new binary version is installed over the old one.
	if err := os.WriteFile(o.Exe, []byte("binary-v2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	in, err = InstallBoot(context.Background(), o)
	if err != nil || !in.Changed {
		t.Fatalf("an updated binary must be reinstalled: %v changed=%v", err, in.Changed)
	}
	if b, _ := os.ReadFile(in.RuntimePath); string(b) != "binary-v2\n" {
		t.Fatalf("the runtime copy was not refreshed: %q", b)
	}
}

// A boot unit for a mode that cannot decrypt without a person would fail at
// every boot. Refuse it at install time and say what does work.
func TestInstallBootRefusesModesThatCannotRecoverUnattended(t *testing.T) {
	for _, mode := range []string{ModePrompt, ModeEnv, "", "nonsense"} {
		o, f := bootFixture(t)
		o.Mode = mode
		_, err := InstallBoot(context.Background(), o)
		if err == nil {
			t.Fatalf("mode %q must be refused", mode)
		}
		if !strings.Contains(err.Error(), ModeTPM) || !strings.Contains(err.Error(), ModeHostKey) {
			t.Errorf("the refusal must name the modes that work: %v", err)
		}
		if len(f.argv) != 0 {
			t.Errorf("a refused install touched systemd: %v", f.argv)
		}
		if _, statErr := os.Stat(o.ServicePath()); statErr == nil {
			t.Error("a refused install wrote a unit")
		}
	}
	// Every persistent mode is accepted.
	for _, mode := range []string{ModeTPM, ModeHostKey, ModeFile} {
		o, _ := bootFixture(t)
		o.Mode = mode
		if _, err := InstallBoot(context.Background(), o); err != nil {
			t.Errorf("mode %q must be able to recover after a reboot: %v", mode, err)
		}
	}
}

func TestInstallBootRefusesUnquotablePaths(t *testing.T) {
	o, _ := bootFixture(t)
	o.StateDir = filepath.Join(t.TempDir(), "state dir")
	if _, err := InstallBoot(context.Background(), o); err == nil {
		t.Fatal("a path systemd cannot express must be refused, not silently mangled")
	}
	o2, _ := bootFixture(t)
	o2.StateDir = ""
	if _, err := InstallBoot(context.Background(), o2); err == nil {
		t.Fatal("a missing state directory must be refused")
	}
}

func TestInstallBootReportsAFailedEnable(t *testing.T) {
	o, f := bootFixture(t)
	f.fail = map[string]error{"enable " + BootUnit: errors.New("exit status 1")}
	if _, err := InstallBoot(context.Background(), o); err == nil {
		t.Fatal("a failed enable must be reported, not swallowed")
	}
}

func TestUninstallBootRemovesOnlyItsOwnFiles(t *testing.T) {
	o, f := bootFixture(t)
	if _, err := InstallBoot(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	removed, err := UninstallBoot(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want the unit and the runtime copy", removed)
	}
	if _, err := os.Stat(o.ServicePath()); !os.IsNotExist(err) {
		t.Fatal("the unit is still installed")
	}
	if _, err := os.Stat(o.RuntimePath()); !os.IsNotExist(err) {
		t.Fatal("the runtime copy is still installed")
	}
	if !f.ran("systemctl disable --now " + BootUnit) {
		t.Fatalf("the unit was not stopped: %v", f.argv)
	}
	// Repeatable: a second teardown is not an error.
	if removed, err := UninstallBoot(context.Background(), o); err != nil || len(removed) != 0 {
		t.Fatalf("a repeated teardown must be a no-op: %v %v", removed, err)
	}
}

func TestUninstallBootLeavesForeignUnitsAndSharedRuntime(t *testing.T) {
	o, _ := bootFixture(t)
	if _, err := InstallBoot(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// Another deployment's unit with the same name.
	if err := os.WriteFile(o.ServicePath(), []byte("# guacdeploy deployment=someone-else\n[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The backup timer installed by internal/schedule calls the same
	// runtime binary.
	backup := filepath.Join(o.UnitDir, "guacdeploy-backup.service")
	if err := os.WriteFile(backup, []byte("[Service]\nExecStart="+o.RuntimePath()+" backup-run\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	removed, err := UninstallBoot(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), o.ServicePath()) {
		t.Fatalf("a unit written by another deployment must be reported: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("nothing should have been removed, got %v", removed)
	}
	if _, statErr := os.Stat(o.ServicePath()); statErr != nil {
		t.Fatal("another deployment's unit was deleted")
	}
	if _, statErr := os.Stat(o.RuntimePath()); statErr != nil {
		t.Fatal("the runtime binary the backup timer still calls was deleted")
	}
	// Once the backup unit is gone, the shared binary goes too.
	os.Remove(backup)
	os.Remove(o.ServicePath())
	if removed, err := UninstallBoot(context.Background(), o); err != nil || len(removed) != 1 {
		t.Fatalf("the runtime copy should be removed once unused: %v %v", removed, err)
	}
}

func joinAll(argv [][]string) []string {
	out := make([]string, 0, len(argv))
	for _, c := range argv {
		out = append(out, strings.Join(c, " "))
	}
	return out
}
