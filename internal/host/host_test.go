package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeOSRelease(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func goodProbes(t *testing.T) *Probes {
	t.Helper()
	return &Probes{
		OSReleasePath: writeOSRelease(t, "ID=\"rocky\"\nVERSION_ID=\"10.0\"\nNAME=\"Rocky Linux\"\n"),
		InstallDirs:   []string{filepath.Join(t.TempDir(), "absent")},
		Geteuid:       func() int { return 0 },
		LookPath:      func(string) (string, error) { return "/usr/bin/docker", nil },
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			return "Docker version 27.0", nil
		},
		Dial: func(context.Context, string) error { return nil },
	}
}

func TestGatherParsesOSReleaseAndProbes(t *testing.T) {
	f, err := goodProbes(t).Gather(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.OSID != "rocky" || f.VersionID != "10.0" || !f.Root || f.DockerPath == "" || !f.ComposeOK || f.Podman || f.ExistingInstall != "" || len(f.Unreachable) != 0 {
		t.Fatalf("facts: %+v", f)
	}
	if err := Preflight(f); err != nil {
		t.Fatalf("preflight on good host: %v", err)
	}
	if deps := MissingDependencies(f); deps != nil {
		t.Fatalf("no deps should be missing: %v", deps)
	}
}

func TestGatherProgressCountsActualChecksIncludingFailures(t *testing.T) {
	p := goodProbes(t)
	checks := 0
	p.Dial = func(context.Context, string) error { checks++; return errors.New("offline fixture") }
	p.Progress = func(_ string, completed, total int) {
		if completed != checks || total != len(setupEndpoints) {
			t.Fatalf("reported %d/%d after %d actual checks", completed, total, checks)
		}
	}
	f, err := p.Gather(context.Background())
	if err != nil || len(f.Unreachable) != checks || checks != len(setupEndpoints) {
		t.Fatal("failed checks were hidden")
	}
}

func TestPreflightRejections(t *testing.T) {
	base := func() *Facts {
		return &Facts{OSID: "rocky", VersionID: "10.0", Root: true, KernelNetfilterOK: true}
	}
	cases := []struct {
		name string
		mut  func(*Facts)
		want string
	}{
		{"wrong-os", func(f *Facts) { f.OSID = "ubuntu"; f.VersionID = "24.04" }, "unsupported platform"},
		{"old-rocky", func(f *Facts) { f.VersionID = "9.4" }, "unsupported platform"},
		{"missing-os-release", func(f *Facts) { f.OSID = ""; f.VersionID = "" }, "unsupported platform"},
		{"not-root", func(f *Facts) { f.Root = false }, "sudo"},
		{"existing-install", func(f *Facts) { f.ExistingInstall = "/opt/guacamole" }, "does not adopt or overwrite"},
		{"podman", func(f *Facts) { f.Podman = true }, "Podman"},
		{"offline", func(f *Facts) { f.Unreachable = []string{"download.docker.com:443"} }, "unreachable"},
		{"no-netfilter", func(f *Facts) { f.KernelNetfilterOK = false }, "netfilter"},
	}
	for _, c := range cases {
		f := base()
		c.mut(f)
		err := Preflight(f)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want mention of %q", c.name, err, c.want)
		}
	}
}

func TestGatherDetectsPodmanAndMissingDocker(t *testing.T) {
	p := goodProbes(t)
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "--version" {
			return "podman version 5.0 (podman-docker)", nil
		}
		return "", errors.New("no compose")
	}
	f, err := p.Gather(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !f.Podman || f.ComposeOK {
		t.Fatalf("facts: %+v", f)
	}

	p2 := goodProbes(t)
	p2.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	f2, err := p2.Gather(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f2.DockerPath != "" || f2.ComposeOK {
		t.Fatalf("facts: %+v", f2)
	}
	if deps := MissingDependencies(f2); len(deps) == 0 {
		t.Fatal("missing docker must require installation")
	}
}

func TestInstallDependenciesRunsPlanAndVerifies(t *testing.T) {
	var calls []string
	p := goodProbes(t)
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "ok", nil
	}
	if err := p.InstallDependencies(context.Background(), []string{"docker-ce", "docker-compose-plugin"}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"config-manager --add-repo", "dnf -y install docker-ce docker-compose-plugin", "systemctl enable --now docker", "docker compose version"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing step %q in:\n%s", want, joined)
		}
	}
}

func TestInstallDependenciesSurfacesFailure(t *testing.T) {
	p := goodProbes(t)
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" {
			return "unit not found", errors.New("exit 1")
		}
		return "ok", nil
	}
	err := p.InstallDependencies(context.Background(), []string{"docker-ce"})
	if err == nil || !strings.Contains(err.Error(), "systemctl") {
		t.Fatalf("want systemctl failure surfaced, got %v", err)
	}
}

func TestComposeCommandAvailability(t *testing.T) {
	for _, tc := range []struct {
		name       string
		docker     bool
		plugin     bool
		standalone bool
		want       []string
	}{
		{"plugin", true, true, false, nil},
		{"both commands", true, true, true, nil},
		{"standalone only", true, false, true, []string{"docker-compose-plugin"}},
		{"docker without compose", true, false, false, []string{"docker-compose-plugin"}},
		{"no docker", false, false, false, []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := goodProbes(t)
			p.LookPath = func(name string) (string, error) {
				if name == "docker" && tc.docker || name == "docker-compose" && tc.standalone {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			}
			p.Run = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "docker-compose" {
					t.Fatal("standalone Compose must not be used as a plugin fallback")
				}
				if name == "docker" && strings.Join(args, " ") == "compose version" && !tc.plugin {
					return "docker: 'compose' is not a docker command", errors.New("exit 1")
				}
				return "ok", nil
			}
			f, err := p.Gather(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if f.ComposeOK != tc.plugin {
				t.Fatalf("ComposeOK = %v, want %v", f.ComposeOK, tc.plugin)
			}
			if got := MissingDependencies(f); !slices.Equal(got, tc.want) {
				t.Fatalf("dependencies = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInstallComposePluginLeavesDockerServiceUnchanged(t *testing.T) {
	p := goodProbes(t)
	var calls []string
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "systemctl" {
			t.Fatal("installing only Compose must not enable or start the pre-existing Docker service")
		}
		return "ok", nil
	}
	if err := p.InstallDependencies(context.Background(), []string{"docker-compose-plugin"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(calls, "dnf -y install docker-compose-plugin") || calls[len(calls)-1] != "docker compose version" {
		t.Fatalf("plugin installation was not verified: %v", calls)
	}
}

func TestInstallDependenciesRejectsUnavailableComposePlugin(t *testing.T) {
	p := goodProbes(t)
	p.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "docker" && strings.Join(args, " ") == "compose version" {
			return "plugin unavailable", errors.New("exit 1")
		}
		return "ok", nil
	}
	err := p.InstallDependencies(context.Background(), []string{"docker-compose-plugin"})
	if err == nil || !strings.Contains(err.Error(), "docker compose is still unavailable") {
		t.Fatalf("a successful package install must not hide a broken plugin: %v", err)
	}
}
