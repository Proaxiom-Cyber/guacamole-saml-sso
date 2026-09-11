package schedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemd records every command instead of running it.
type fakeSystemd struct {
	calls    []string
	badCal   bool
	failures map[string]bool
}

func (f *fakeSystemd) run(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	joined := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, joined)
	if f.badCal && strings.HasPrefix(joined, "systemd-analyze calendar") {
		return "", "Failed to parse calendar specification", errors.New("exit status 1")
	}
	if f.failures[joined] {
		return "", "unit failed", errors.New("exit status 1")
	}
	return "", "", nil
}

func (f *fakeSystemd) ran(want string) bool {
	for _, c := range f.calls {
		if c == want {
			return true
		}
	}
	return false
}

// testOptions builds an installable deployment entirely under t.TempDir.
func testOptions(t *testing.T, f *fakeSystemd) Options {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(root, "guacdeploy")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho provisioning binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return Options{
		Run: f.run, DeploymentID: "dep-123",
		StateDir: filepath.Join(root, "state"), Dest: filepath.Join(root, "backups"),
		UnitDir: filepath.Join(root, "units"), RuntimeDir: filepath.Join(root, "runtime"),
		Exe: exe,
	}
}

func TestInstallWritesUnitsAndRuntimeCopy(t *testing.T) {
	f := &fakeSystemd{}
	o := testOptions(t, f)
	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Changed {
		t.Error("first install reported no change")
	}

	// The unit must call the deployment-owned copy, never the provisioning
	// binary: deleting what the administrator downloaded must not break the
	// schedule.
	svc, err := os.ReadFile(in.ServicePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(svc), o.Exe) {
		t.Errorf("service calls the provisioning binary %s:\n%s", o.Exe, svc)
	}
	if !strings.Contains(string(svc), "ExecStart="+o.RuntimePath()+" backup-run") {
		t.Errorf("service does not call the installed runtime:\n%s", svc)
	}
	for _, want := range []string{"--state-dir " + o.StateDir, "--dest " + o.Dest, "--keep 7", "Type=oneshot"} {
		if !strings.Contains(string(svc), want) {
			t.Errorf("service missing %q:\n%s", want, svc)
		}
	}

	runtime, err := os.ReadFile(o.RuntimePath())
	if err != nil {
		t.Fatalf("runtime copy missing: %v", err)
	}
	src, _ := os.ReadFile(o.Exe)
	if string(runtime) != string(src) {
		t.Error("runtime copy does not match the source binary")
	}
	fi, err := os.Stat(o.RuntimePath())
	if err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("runtime copy is not executable: %v %v", fi.Mode(), err)
	}

	// The provisioning binary can now go away without affecting the unit.
	if err := os.Remove(o.Exe); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(o.RuntimePath()); err != nil {
		t.Errorf("removing the provisioning binary broke the installed runtime: %v", err)
	}

	if !f.ran("systemctl daemon-reload") {
		t.Error("no daemon-reload after writing units")
	}
	if !f.ran("systemctl enable --now " + TimerUnit) {
		t.Errorf("timer not enabled and started: %v", f.calls)
	}
}

func TestTimerCarriesConfiguredSchedule(t *testing.T) {
	f := &fakeSystemd{}
	o := testOptions(t, f)
	o.OnCalendar = "Mon *-*-* 02:30:00"
	o.Keep = 14
	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(in.TimerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(timer), "OnCalendar=Mon *-*-* 02:30:00") {
		t.Errorf("timer does not carry the configured schedule:\n%s", timer)
	}
	// Persistent catches up a run missed while the host was down, so a
	// reboot does not silently skip a night.
	if !strings.Contains(string(timer), "Persistent=true") {
		t.Errorf("timer is not persistent across downtime:\n%s", timer)
	}
	if !strings.Contains(string(timer), "WantedBy=timers.target") {
		t.Errorf("timer cannot be enabled:\n%s", timer)
	}
	svc, _ := os.ReadFile(in.ServicePath)
	if !strings.Contains(string(svc), "--keep 14") {
		t.Errorf("service does not carry the configured retention:\n%s", svc)
	}
	if in.Keep != 14 || in.OnCalendar != "Mon *-*-* 02:30:00" {
		t.Errorf("Installed reports %d / %q", in.Keep, in.OnCalendar)
	}
}

func TestInstallDefaultsToDailySeven(t *testing.T) {
	f := &fakeSystemd{}
	in, err := Install(context.Background(), testOptions(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if in.OnCalendar != "daily" || in.Keep != 7 {
		t.Errorf("defaults = %q / %d, want daily / 7", in.OnCalendar, in.Keep)
	}
	timer, _ := os.ReadFile(in.TimerPath)
	if !strings.Contains(string(timer), "OnCalendar=daily") {
		t.Errorf("default schedule is not daily:\n%s", timer)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	f := &fakeSystemd{}
	o := testOptions(t, f)
	first, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	svcBefore, _ := os.ReadFile(first.ServicePath)

	f.calls = nil
	second, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Error("second identical install reported a change")
	}
	if f.ran("systemctl daemon-reload") {
		t.Errorf("unchanged install still reloaded systemd: %v", f.calls)
	}
	// enable --now still runs: it repairs a timer stopped by hand.
	if !f.ran("systemctl enable --now " + TimerUnit) {
		t.Error("unchanged install did not re-assert the timer")
	}
	svcAfter, _ := os.ReadFile(second.ServicePath)
	if string(svcBefore) != string(svcAfter) {
		t.Error("second install rewrote the service unit")
	}

	// A changed schedule is a change again.
	o.OnCalendar = "hourly"
	third, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !third.Changed {
		t.Error("changing the schedule reported no change")
	}
}

func TestInstallRejectsInvalidSchedule(t *testing.T) {
	f := &fakeSystemd{badCal: true}
	o := testOptions(t, f)
	o.OnCalendar = "every other tuesday"
	if _, err := Install(context.Background(), o); err == nil {
		t.Fatal("an unparseable schedule was accepted")
	}
	if _, err := os.Stat(o.ServicePath()); !os.IsNotExist(err) {
		t.Error("units were written despite an invalid schedule")
	}
}

func TestInstallRejectsUnquotablePathsAndZeroRetention(t *testing.T) {
	f := &fakeSystemd{}
	o := testOptions(t, f)
	o.Dest = filepath.Join(t.TempDir(), "back ups")
	if _, err := Install(context.Background(), o); err == nil {
		t.Error("a destination with a space was accepted into ExecStart")
	}

	o = testOptions(t, f)
	o.Keep = -1
	if _, err := Install(context.Background(), o); err == nil {
		t.Error("negative retention was accepted")
	}
}

func TestUninstallRemovesOnlyThisDeploymentsUnits(t *testing.T) {
	f := &fakeSystemd{}
	o := testOptions(t, f)
	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	// A neighbouring unit in the same directory must survive.
	other := filepath.Join(o.UnitDir, "something-else.service")
	if err := os.WriteFile(other, []byte("[Service]\nExecStart=/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f.calls = nil
	removed, err := Uninstall(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{in.ServicePath, in.TimerPath, in.RuntimePath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived uninstall", p)
		}
	}
	if len(removed) != 3 {
		t.Errorf("removed = %v, want service, timer and runtime copy", removed)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("uninstall removed an unrelated unit: %v", err)
	}
	if !f.ran("systemctl disable --now " + TimerUnit) {
		t.Errorf("timer was not stopped and disabled: %v", f.calls)
	}

	// Repeat teardown is not an error.
	again, err := Uninstall(context.Background(), o)
	if err != nil || len(again) != 0 {
		t.Errorf("second uninstall = %v, %v; want no work and no error", again, err)
	}
}

func TestUninstallLeavesUnitsFromAnotherDeployment(t *testing.T) {
	f := &fakeSystemd{}
	o := testOptions(t, f)
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// Same names, different owner: a rebuilt deployment, or a hand-written
	// unit. Neither is ours to delete.
	foreign := o
	foreign.DeploymentID = "someone-else"

	removed, err := Uninstall(context.Background(), foreign)
	if err == nil {
		t.Fatal("uninstall silently accepted units it did not write")
	}
	for _, p := range []string{o.ServicePath(), o.TimerPath()} {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("uninstall removed a unit owned by another deployment: %s", p)
		}
		for _, r := range removed {
			if r == p {
				t.Errorf("%s reported as removed", p)
			}
		}
	}
}

// The guard has to reach the unit, not just the options. A repeat setup that
// dropped it would rewrite this ExecStart without --require-mount, and the
// scheduled backup would then accept a destination that is no longer on the
// share.
func TestInstalledUnitCarriesTheMountGuard(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "guacdeploy")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	install := func(requireMount bool) string {
		name := "off"
		if requireMount {
			name = "on"
		}
		units := filepath.Join(dir, "units", name)
		if err := os.MkdirAll(units, 0o755); err != nil {
			t.Fatal(err)
		}
		in, err := Install(context.Background(), Options{
			Run:          func(context.Context, string, string, ...string) (string, string, error) { return "", "", nil },
			DeploymentID: "d1", StateDir: dir, Dest: filepath.Join(dir, "backups"),
			RequireMount: requireMount,
			UnitDir:      units, RuntimeDir: filepath.Join(dir, "sbin"), Exe: exe,
		})
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(in.ServicePath)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if !strings.Contains(install(true), "--require-mount") {
		t.Error("the approved mount guard is not in the installed unit")
	}
	if strings.Contains(install(false), "--require-mount") {
		t.Error("the guard appeared without being asked for")
	}
}
