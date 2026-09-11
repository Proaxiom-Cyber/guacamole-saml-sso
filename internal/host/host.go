// Package host checks and prepares the Rocky Linux 10 host. All probes and
// commands go through injectable seams so behaviour is testable off-target;
// the real seams run dnf, systemctl, and outbound TLS dials.
package host

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Probes are the seams to the real host. Zero fields get defaults.
type Probes struct {
	OSReleasePath string
	InstallDirs   []string // existing-installation markers
	Geteuid       func() int
	LookPath      func(file string) (string, error)
	Run           func(ctx context.Context, name string, args ...string) (string, error)
	Dial          func(ctx context.Context, hostport string) error
}

func (p *Probes) defaults() {
	if p.OSReleasePath == "" {
		p.OSReleasePath = "/etc/os-release"
	}
	if p.InstallDirs == nil {
		p.InstallDirs = []string{"/opt/guacamole"}
	}
	if p.Geteuid == nil {
		p.Geteuid = os.Geteuid
	}
	if p.LookPath == nil {
		p.LookPath = exec.LookPath
	}
	if p.Run == nil {
		p.Run = func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return string(out), err
		}
	}
	if p.Dial == nil {
		p.Dial = func(ctx context.Context, hostport string) error {
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
			conn, err := d.DialContext(ctx, "tcp", hostport)
			if err == nil {
				conn.Close()
			}
			return err
		}
	}
}

// Endpoints the host must reach during setup. The full runtime allowlist is
// documented with the release work; these are what host preparation needs.
var setupEndpoints = []string{
	"mirrors.rockylinux.org:443", // dnf mirrors
	"download.docker.com:443",    // Docker RHEL repository
	"registry-1.docker.io:443",   // container images
}

// Facts is what one gathering pass observed.
type Facts struct {
	OSID            string
	VersionID       string
	Root            bool
	ExistingInstall string // first marker path found, empty if none
	DockerPath      string
	Podman          bool
	ComposeOK       bool
	Unreachable     []string
}

// Gather observes the host without changing it.
func (p *Probes) Gather(ctx context.Context) (*Facts, error) {
	p.defaults()
	f := &Facts{Root: p.Geteuid() == 0}

	b, err := os.ReadFile(p.OSReleasePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", p.OSReleasePath, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			f.OSID = v
		case "VERSION_ID":
			f.VersionID = v
		}
	}

	for _, dir := range p.InstallDirs {
		if _, err := os.Stat(dir); err == nil {
			f.ExistingInstall = dir
			break
		}
	}

	if path, err := p.LookPath("docker"); err == nil {
		f.DockerPath = path
		if out, err := p.Run(ctx, "docker", "--version"); err == nil && strings.Contains(strings.ToLower(out), "podman") {
			f.Podman = true
		}
		if _, err := p.Run(ctx, "docker", "compose", "version"); err == nil {
			f.ComposeOK = true
		}
	}

	for _, ep := range setupEndpoints {
		if err := p.Dial(ctx, ep); err != nil {
			f.Unreachable = append(f.Unreachable, ep)
		}
	}
	return f, nil
}

// Preflight rejects unsupported platforms and existing installations before
// any mutation. Errors are explanations, not stack traces.
func Preflight(f *Facts) error {
	if f.OSID != "rocky" || !strings.HasPrefix(f.VersionID, "10") {
		return fmt.Errorf("unsupported platform: this tool supports Rocky Linux 10, found %s %s", orUnknown(f.OSID), orUnknown(f.VersionID))
	}
	if !f.Root {
		return errors.New("root privileges are required: run with sudo")
	}
	if f.ExistingInstall != "" {
		return fmt.Errorf("an existing installation was found at %s; this tool does not adopt or overwrite existing deployments. Remove it manually or use a clean host", f.ExistingInstall)
	}
	if f.Podman {
		return errors.New("the docker command runs Podman (podman-docker) on this host; this deployment is only verified with Docker. Use a host with Docker or remove podman-docker")
	}
	if len(f.Unreachable) > 0 {
		return fmt.Errorf("required endpoints are unreachable: %s. Fix outbound connectivity (TCP 443) and resume", strings.Join(f.Unreachable, ", "))
	}
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// MissingDependencies lists what dependency installation would add.
func MissingDependencies(f *Facts) []string {
	if f.DockerPath != "" && f.ComposeOK {
		return nil
	}
	// Docker's RHEL repository set, per the Rocky installation guidance the
	// shell setup already followed.
	return []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}
}

// InstallDependencies performs the approved installation and verifies the
// result. Callers obtained approval first.
func (p *Probes) InstallDependencies(ctx context.Context, pkgs []string) error {
	p.defaults()
	steps := [][]string{
		{"dnf", "-y", "install", "dnf-plugins-core"},
		{"dnf", "config-manager", "--add-repo", "https://download.docker.com/linux/rhel/docker-ce.repo"},
		append([]string{"dnf", "-y", "install"}, pkgs...),
		{"systemctl", "enable", "--now", "docker"},
	}
	for _, s := range steps {
		if out, err := p.Run(ctx, s[0], s[1:]...); err != nil {
			return fmt.Errorf("%s failed: %v\n%s", strings.Join(s, " "), err, strings.TrimSpace(out))
		}
	}
	// Check the actual result, not the exit codes alone.
	if out, err := p.Run(ctx, "docker", "compose", "version"); err != nil {
		return fmt.Errorf("docker compose is still unavailable after installation: %v\n%s", err, strings.TrimSpace(out))
	}
	return nil
}
