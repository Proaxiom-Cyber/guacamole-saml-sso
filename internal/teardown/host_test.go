package teardown

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
)

// The backup schedule goes last, because its Uninstall deletes the binary
// copy every unit calls. Anything else last would take the binary out from
// under a unit that is still installed.
func TestHostUnitsRemovesBinaryLast(t *testing.T) {
	unitDir, runtimeDir := t.TempDir(), t.TempDir()
	marker := "# guacdeploy deployment=dep1\n[Unit]\n"
	units := []string{
		"guacdeploy-renewcert.timer", "guacdeploy-renewcert.service",
		"guacdeploy-recordings.timer", "guacdeploy-recordings.service",
		"guacdeploy-backup.timer", "guacdeploy-backup.service",
	}
	for _, u := range units {
		if err := os.WriteFile(filepath.Join(unitDir, u), []byte(marker), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(runtimeDir, schedule.RuntimeBinaryName)
	if err := os.WriteFile(binary, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}

	var disabled []string
	run := func(_ context.Context, _, name string, args ...string) (string, string, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "disable" {
			// The binary must still be there while any unit is being
			// disabled: a unit that still exists must still be runnable.
			if _, err := os.Stat(binary); err != nil {
				t.Errorf("the shared binary was already gone when %v was disabled", args)
			}
			disabled = append(disabled, args[len(args)-1])
		}
		return "", "", nil
	}

	removed, err := HostUnits(context.Background(), HostOptions{
		Run: run, DeploymentID: "dep1", StateDir: t.TempDir(),
		UnitDir: unitDir, RuntimeDir: runtimeDir,
	})
	if err != nil {
		t.Fatalf("HostUnits: %v", err)
	}

	want := []string{"guacdeploy-renewcert.timer", "guacdeploy-recordings.timer", "guacdeploy-backup.timer"}
	if strings.Join(disabled, ",") != strings.Join(want, ",") {
		t.Fatalf("units were stopped in the wrong order: %v", disabled)
	}
	for _, u := range units {
		if _, err := os.Stat(filepath.Join(unitDir, u)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed", u)
		}
	}
	if _, err := os.Stat(binary); !os.IsNotExist(err) {
		t.Error("the deployment-owned binary copy was not removed")
	}
	if len(removed) != len(units)+1 {
		t.Errorf("want %d paths reported removed, got %v", len(units)+1, removed)
	}
}

// The credential files go, whichever spelling the mode used, and the
// directory survives if something else is in it.
func TestRemoveCredentials(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"cloudflare-api-token", "postgres-password.cred", "operator-notes"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	names := []string{"cloudflare-api-token", "postgres-password"}
	leftover, err := RemoveCredentials(context.Background(), dir, names)
	if err != nil {
		t.Fatal(err)
	}
	if len(leftover) != 1 || leftover[0] != "operator-notes" {
		t.Fatalf("want the unrelated file preserved, got %v", leftover)
	}
	for _, gone := range []string{"cloudflare-api-token", "postgres-password.cred"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed", gone)
		}
	}

	os.Remove(filepath.Join(dir, "operator-notes"))
	if leftover, err = RemoveCredentials(context.Background(), dir, names); err != nil || len(leftover) != 0 {
		t.Fatalf("want the empty directory removed, got %v %v", leftover, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("the empty credential directory was not removed")
	}
}

// A credential name is a plain file name. Anything else is refused rather
// than joined onto the directory and deleted.
func TestRemoveCredentialsRefusesAPath(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"../../etc/passwd", "a/b", ""} {
		if _, err := RemoveCredentials(context.Background(), filepath.Join(dir, "credentials"), []string{n}); err == nil {
			t.Errorf("credential name %q was accepted", n)
		}
	}
}

// A second run is not a failure: every missing unit is already removed.
func TestHostUnitsIsRepeatable(t *testing.T) {
	run := func(context.Context, string, string, ...string) (string, string, error) { return "", "", nil }
	removed, err := HostUnits(context.Background(), HostOptions{
		Run: run, DeploymentID: "dep1", StateDir: t.TempDir(),
		UnitDir: t.TempDir(), RuntimeDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("a repeat run must not fail: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("nothing was there, but %v was reported removed", removed)
	}
}
