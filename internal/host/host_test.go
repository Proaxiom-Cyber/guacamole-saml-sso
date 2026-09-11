package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestPreflightRejections(t *testing.T) {
	base := func() *Facts {
		return &Facts{OSID: "rocky", VersionID: "10.0", Root: true}
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
