package recording

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Cleanup deletes the oldest completed recordings first, and stops as soon
// as usage is back within budget.
func TestCleanupDeletesOldestCompletedFirst(t *testing.T) {
	dir, _ := setup(t)
	write(t, dir, "oldest", 100, 72*time.Hour)
	write(t, dir, "middle", 100, 48*time.Hour)
	write(t, dir, "newest", 100, 24*time.Hour)

	rep, err := Run(Options{Dir: dir, DeploymentID: deployment, Budget: 250, Open: noneOpen})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Deleted, []string{"oldest"}) {
		t.Fatalf("deleted = %v, want only the oldest", rep.Deleted)
	}
	for _, keep := range []string{"middle", "newest"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("%s must survive: %v", keep, err)
		}
	}
	if rep.UsedAfter != 200 {
		t.Fatalf("used after = %d, want 200", rep.UsedAfter)
	}
}

// The budget takes priority over preserving unbacked recordings: a failed
// upload does not stop the deletion, and the loss is reported.
func TestCleanupDeletesEvenWhenTheUploadFailed(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "oldest", 100, 72*time.Hour)
	write(t, dir, "newest", 100, 24*time.Hour)

	rep, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: "age1notakey", Budget: 150, Open: noneOpen})
	if err == nil {
		t.Fatal("a failed upload must fail the run")
	}
	if len(rep.Included) != 0 {
		t.Fatalf("included = %v, want none: nothing was uploaded", rep.Included)
	}
	if !reflect.DeepEqual(rep.Deleted, []string{"oldest"}) {
		t.Fatalf("deleted = %v, want the oldest deleted despite the failed upload", rep.Deleted)
	}
	if !reflect.DeepEqual(rep.Lost, []string{"oldest"}) {
		t.Fatalf("lost = %v, want the deletion reported as unrecoverable", rep.Lost)
	}
	if _, err := os.Stat(filepath.Join(dir, "oldest")); !os.IsNotExist(err) {
		t.Fatal("the oldest recording must be gone")
	}
}

// A deletion whose copy is confirmed in the destination is not a loss.
func TestConfirmedCopyIsNotReportedAsLost(t *testing.T) {
	dir, dest := setup(t)
	write(t, dir, "oldest", 100, 72*time.Hour)
	write(t, dir, "newest", 100, 24*time.Hour)
	_, pub := keypair(t)

	rep, err := Run(Options{Dir: dir, Dest: dest, DeploymentID: deployment,
		PublicKey: pub, Budget: 150, Open: noneOpen})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Deleted, []string{"oldest"}) {
		t.Fatalf("deleted = %v, want the oldest", rep.Deleted)
	}
	if len(rep.Lost) != 0 {
		t.Fatalf("lost = %v, want none: the copy is published and verifies", rep.Lost)
	}
}

// Active recordings are never deleted, and cleanup stops once no completed
// recording is left even though usage is still over budget.
func TestCleanupNeverDeletesActiveAndStopsWhenNoneLeft(t *testing.T) {
	dir, _ := setup(t)
	active := write(t, dir, "recording-now", 100, 72*time.Hour)
	write(t, dir, "done", 100, 24*time.Hour)

	rep, err := Run(Options{Dir: dir, DeploymentID: deployment, Budget: 1,
		Open: openSet(t, active)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep.Deleted, []string{"done"}) {
		t.Fatalf("deleted = %v, want only the completed recording", rep.Deleted)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatalf("the active recording must survive: %v", err)
	}
	if rep.UsedAfter <= rep.Budget {
		t.Fatal("this run must end over budget, because only an active recording is left")
	}
	if rep.Result != "ok" {
		t.Fatalf("result = %q: staying over budget on active recordings is not a failure", rep.Result)
	}
}

// With no budget configured nothing is ever deleted.
func TestNoBudgetDeletesNothing(t *testing.T) {
	dir, _ := setup(t)
	write(t, dir, "old", 1000, 72*time.Hour)
	rep, err := Run(Options{Dir: dir, DeploymentID: deployment, Open: noneOpen})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Deleted) != 0 {
		t.Fatalf("deleted = %v, want none", rep.Deleted)
	}
}

// The operator summary names every loss and states the quota caveat.
func TestSummaryNamesLossesAndTheQuotaCaveat(t *testing.T) {
	s := Report{Dir: "/opt/guacamole/recordings", Budget: 20e9, Ran: time.Now(),
		Result: "ok", Deleted: []string{"a", "b"}, Lost: []string{"b"}}.Summary()
	if !strings.Contains(s, "LOST:") || !strings.Contains(s, "b was deleted") {
		t.Fatalf("a loss must be named:\n%s", s)
	}
	if !strings.Contains(s, "not a hard filesystem quota") {
		t.Fatalf("the summary must state that cleanup is not a quota:\n%s", s)
	}
}

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]int64{
		"20GB": 20e9, "20G": 20e9, "500MB": 500e6, "10GiB": 10 << 30,
		"1KiB": 1024, "4096": 4096, "1.5GB": 15e8, " 2TB ": 2e12, "700b": 700,
	} {
		got, err := ParseBytes(in)
		if err != nil {
			t.Fatalf("ParseBytes(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseBytes(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"", "lots", "0", "-5GB", "GB"} {
		if _, err := ParseBytes(in); err == nil {
			t.Fatalf("ParseBytes(%q) must be refused", in)
		}
	}
}

// --- the installed schedule ---

func fakeRunner(calls *[][]string) func(context.Context, string, string, ...string) (string, string, error) {
	return func(_ context.Context, _, name string, args ...string) (string, string, error) {
		*calls = append(*calls, append([]string{name}, args...))
		return "", "", nil
	}
}

func installOpts(t *testing.T, calls *[][]string) InstallOptions {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(root, "guacdeploy-downloaded")
	if err := os.WriteFile(exe, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return InstallOptions{
		Run: fakeRunner(calls), DeploymentID: deployment,
		StateDir: "/var/lib/guacdeploy", Dir: "/opt/guacamole/recordings",
		Dest: "/mnt/backups", Budget: 20e9,
		UnitDir: filepath.Join(root, "units"), RuntimeDir: filepath.Join(root, "runtime"), Exe: exe,
	}
}

// The units call the deployment-owned binary copy, not the binary the
// administrator happened to run setup from.
func TestInstalledUnitsCallTheDeploymentOwnedCopy(t *testing.T) {
	var calls [][]string
	o := installOpts(t, &calls)
	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if in.RuntimePath != filepath.Join(o.RuntimeDir, RuntimeBinaryName) {
		t.Fatalf("runtime path = %s", in.RuntimePath)
	}
	copied, err := os.ReadFile(in.RuntimePath)
	if err != nil || string(copied) != "binary" {
		t.Fatalf("the running executable must be copied to the runtime path: %v", err)
	}
	svc, err := os.ReadFile(in.ServicePath)
	if err != nil {
		t.Fatal(err)
	}
	want := "ExecStart=" + in.RuntimePath + " recordings-run --state-dir /var/lib/guacdeploy" +
		" --recordings-dir /opt/guacamole/recordings --budget 20000000000 --dest /mnt/backups\n"
	if !strings.Contains(string(svc), want) {
		t.Fatalf("service ExecStart wrong:\nwant %q\ngot\n%s", want, svc)
	}
	if strings.Contains(string(svc), o.Exe) {
		t.Fatal("the unit must not point at the provisioning binary the administrator ran")
	}
	for _, want := range []string{"# guacdeploy deployment=" + deployment, "Type=oneshot", "Requires=docker.service"} {
		if !strings.Contains(string(svc), want) {
			t.Fatalf("service is missing %q:\n%s", want, svc)
		}
	}

	timer, err := os.ReadFile(in.TimerPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# guacdeploy deployment=" + deployment,
		"OnCalendar=hourly", "Persistent=true", "Unit=" + ServiceUnit, "WantedBy=timers.target"} {
		if !strings.Contains(string(timer), want) {
			t.Fatalf("timer is missing %q:\n%s", want, timer)
		}
	}

	var enabled bool
	for _, c := range calls {
		if reflect.DeepEqual(c, []string{"systemctl", "enable", "--now", TimerUnit}) {
			enabled = true
		}
	}
	if !enabled {
		t.Fatalf("the timer must be enabled and started: %v", calls)
	}
}

// Installing twice rewrites nothing.
func TestInstallIsIdempotent(t *testing.T) {
	var calls [][]string
	o := installOpts(t, &calls)
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	in, err := Install(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if in.Changed {
		t.Fatal("a repeated install with the same options must change nothing")
	}
}

// A schedule that can neither back up nor delete is a configuration mistake,
// not a silent no-op timer.
func TestInstallRefusesAScheduleThatDoesNothing(t *testing.T) {
	var calls [][]string
	o := installOpts(t, &calls)
	o.Dest, o.Budget = "", 0
	if _, err := Install(context.Background(), o); err == nil {
		t.Fatal("a schedule with no budget and no destination must be refused")
	}
}

// Uninstall removes this deployment's units and leaves anything else alone.
func TestUninstallLeavesForeignUnits(t *testing.T) {
	var calls [][]string
	o := installOpts(t, &calls)
	if _, err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.TimerPath(), []byte("# someone else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err := Uninstall(context.Background(), o)
	if err == nil {
		t.Fatal("a foreign unit must be reported")
	}
	if !reflect.DeepEqual(removed, []string{o.ServicePath()}) {
		t.Fatalf("removed = %v, want only our own service", removed)
	}
	if _, err := os.Stat(o.TimerPath()); err != nil {
		t.Fatal("a unit written by something else must stay")
	}
	// The runtime binary copy is shared with the backup schedule and is not
	// ours to delete here.
	if _, err := os.Stat(o.RuntimePath()); err != nil {
		t.Fatal("the shared runtime copy must not be removed by the recording teardown")
	}
}
