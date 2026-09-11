package certs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testDeploymentID = "aabbccddeeff00112233445566778899"

type recorder struct {
	ran  [][]string
	fail map[string]error
}

func (r *recorder) run(_ context.Context, _, name string, args ...string) (string, string, error) {
	cmd := append([]string{name}, args...)
	r.ran = append(r.ran, cmd)
	return "", "", r.fail[strings.Join(cmd, " ")]
}

func (r *recorder) did(cmd string) bool {
	for _, c := range r.ran {
		if strings.Join(c, " ") == cmd {
			return true
		}
	}
	return false
}

func newInstallOptions(t *testing.T, r *recorder) InstallOptions {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "guacdeploy-downloaded")
	if err := os.WriteFile(exe, []byte("#!/bin/true\nthe provisioning binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return InstallOptions{
		Run: r.run, DeploymentID: testDeploymentID,
		StateDir:   filepath.Join(dir, "state"),
		UnitDir:    filepath.Join(dir, "units"),
		RuntimeDir: filepath.Join(dir, "runtime"),
		Exe:        exe,
	}
}

func TestInstallPointsTheUnitsAtTheDeploymentOwnedCopy(t *testing.T) {
	r := &recorder{}
	o := newInstallOptions(t, r)
	o.OnCalendar = "*-*-* 03:17:00"

	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !in.Changed {
		t.Error("the first install reported no change")
	}

	service := readFile(t, in.ServicePath)
	timer := readFile(t, in.TimerPath)

	// The unit must call the copy, never the downloaded binary, which the
	// administrator is free to delete the moment setup finishes.
	if !strings.Contains(service, "ExecStart="+o.RuntimePath()+" renew-cert --state-dir "+o.StateDir+"\n") {
		t.Errorf("ExecStart does not call the deployment-owned copy:\n%s", service)
	}
	if strings.Contains(service, o.Exe) {
		t.Errorf("the unit refers to the provisioning binary:\n%s", service)
	}
	if got, err := os.ReadFile(o.RuntimePath()); err != nil {
		t.Fatalf("the runtime copy was not installed: %v", err)
	} else if string(got) != readFile(t, o.Exe) {
		t.Error("the runtime copy does not match the running executable")
	}

	if !strings.Contains(timer, "OnCalendar=*-*-* 03:17:00\n") {
		t.Errorf("the timer does not carry the configured schedule:\n%s", timer)
	}
	// Persistent=true is what makes the renewal survive a host being off
	// over its scheduled time.
	if !strings.Contains(timer, "Persistent=true") {
		t.Errorf("the timer is not persistent:\n%s", timer)
	}
	for _, unit := range []string{service, timer} {
		if !strings.HasPrefix(unit, "# guacdeploy deployment="+testDeploymentID+"\n") {
			t.Errorf("the unit carries no ownership marker:\n%s", unit)
		}
	}
	if !r.did("systemctl enable --now " + TimerUnit) {
		t.Errorf("the timer was not enabled: %v", r.ran)
	}
	if !r.did("systemd-analyze calendar *-*-* 03:17:00") {
		t.Errorf("the schedule expression was not checked: %v", r.ran)
	}
}

func TestInstallDefaultsToADailyCheck(t *testing.T) {
	r := &recorder{}
	in, err := Install(context.Background(), newInstallOptions(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if in.OnCalendar != "daily" {
		t.Errorf("default schedule = %q", in.OnCalendar)
	}
	if !strings.Contains(readFile(t, in.TimerPath), "OnCalendar=daily\n") {
		t.Error("the timer does not carry the default schedule")
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	r := &recorder{}
	o := newInstallOptions(t, r)
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	r.ran = nil
	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if in.Changed {
		t.Error("a repeated install rewrote the units")
	}
	if r.did("systemctl daemon-reload") {
		t.Error("a repeated install reloaded systemd for no reason")
	}
	// enable --now still runs: it repairs a timer stopped by hand.
	if !r.did("systemctl enable --now " + TimerUnit) {
		t.Error("a repeated install did not re-enable the timer")
	}
}

func TestInstallRefusesAnInvalidSchedule(t *testing.T) {
	r := &recorder{fail: map[string]error{"systemd-analyze calendar every tuesday": errors.New("bad")}}
	o := newInstallOptions(t, r)
	o.OnCalendar = "every tuesday"
	if _, err := Install(context.Background(), o); err == nil {
		t.Fatal("Install accepted a schedule systemd cannot parse")
	}
	if _, err := os.Stat(o.TimerPath()); !os.IsNotExist(err) {
		t.Error("a timer was written for an invalid schedule")
	}
}

func TestUninstallRemovesOnlyThisDeploymentsUnits(t *testing.T) {
	r := &recorder{}
	o := newInstallOptions(t, r)
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// Something else replaces the service unit with its own.
	if err := os.WriteFile(o.ServicePath(), []byte("# someone else's unit\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	removed, err := Uninstall(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), o.ServicePath()) {
		t.Fatalf("Uninstall did not report the foreign unit: %v", err)
	}
	if len(removed) != 1 || removed[0] != o.TimerPath() {
		t.Errorf("removed = %v, want only the timer", removed)
	}
	if _, err := os.Stat(o.ServicePath()); err != nil {
		t.Error("Uninstall removed a unit this deployment did not write")
	}
	// The runtime copy belongs to internal/schedule's teardown: the backup
	// timer calls the same binary.
	if _, err := os.Stat(o.RuntimePath()); err != nil {
		t.Error("Uninstall removed the shared runtime binary")
	}
}

func TestUninstallIsRepeatable(t *testing.T) {
	r := &recorder{}
	o := newInstallOptions(t, r)
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(context.Background(), o); err != nil {
		t.Fatalf("a second Uninstall failed: %v", err)
	}
}

func TestInstallRefusesPathsSystemdCannotQuote(t *testing.T) {
	r := &recorder{}
	o := newInstallOptions(t, r)
	o.StateDir = "/var/lib/guac deploy"
	if _, err := Install(context.Background(), o); err == nil {
		t.Fatal("Install accepted a path with a space in it")
	}
}
