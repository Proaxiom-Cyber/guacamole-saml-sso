package certs

// Renewal that outlives the provisioning binary.
//
// "Install renewal independently of the provisioning binary" (specification).
// The provisioning binary is whatever the administrator downloaded and ran;
// it may sit in a home directory or a temporary directory and may be deleted
// the moment setup finishes. A unit pointing at that path breaks on the next
// reboot.
//
// So this follows internal/schedule exactly: Install copies the running
// executable to the same deployment-owned runtime path,
// /usr/local/lib/guacdeploy/guacdeploy, and the unit calls that copy. There
// is one convention on the host, not two — the backup timer and the renewal
// timer run the same installed binary, and installing it twice is a no-op
// because the copy is content-compared first.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Unit names and defaults. One deployment per host, so the names are fixed.
const (
	ServiceUnit = "guacdeploy-renewcert.service"
	TimerUnit   = "guacdeploy-renewcert.timer"

	DefaultUnitDir = "/etc/systemd/system"
	// /usr/local/sbin, not /usr/local/lib: SELinux labels /usr/local/lib
	// as lib_t, and systemd will not transition a service whose executable
	// is lib_t, so the unit runs as init_t and is denied outbound network.
	// /usr/local/sbin is bin_t, which transitions correctly. The distinct
	// file name keeps this deployment-owned copy separate from the
	// provisioning binary the launcher installs as /usr/local/bin/guacdeploy.
	DefaultRuntimeDir = "/usr/local/sbin"
	// RuntimeBinaryName keeps the deployment-owned copy distinct from the
	// provisioning binary at /usr/local/bin/guacdeploy, which the operator
	// may delete at any time.
	RuntimeBinaryName = "guacdeploy-runtime"
	// DefaultOnCalendar runs daily. A daily check with a 30-day renewal
	// window gives a failing renewal thirty further attempts before the
	// certificate expires.
	DefaultOnCalendar = "daily"
)

// InstallOptions configures the installed renewal timer.
type InstallOptions struct {
	Run          Runner
	DeploymentID string // written into each unit as the ownership marker
	StateDir     string // passed to the scheduled command
	OnCalendar   string // systemd calendar expression, default "daily"

	UnitDir    string // default /etc/systemd/system
	RuntimeDir string // deployment-owned; default /usr/local/lib/guacdeploy
	Exe        string // source binary, default the running executable
}

func (o *InstallOptions) defaults() error {
	// A nil runner is the caller forgetting a seam, not a request to
	// crash: default it the way every other entry point does.
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.OnCalendar == "" {
		o.OnCalendar = DefaultOnCalendar
	}
	if o.UnitDir == "" {
		o.UnitDir = DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = DefaultRuntimeDir
	}
	if o.Exe == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("find the running executable to install: %w", err)
		}
		o.Exe = exe
	}
	if o.StateDir == "" {
		return fmt.Errorf("installing renewal needs a state directory")
	}
	// systemd's ExecStart has its own quoting rules. Rather than implement
	// them, refuse the paths that would need them.
	for _, p := range []string{o.StateDir, o.UnitDir, o.RuntimeDir, o.Exe} {
		if strings.ContainsAny(p, " \t\n\"'\\") {
			return fmt.Errorf("path %q contains whitespace or quotes, which cannot be scheduled safely", p)
		}
	}
	if strings.ContainsAny(o.OnCalendar, "\n\r") {
		return fmt.Errorf("the schedule expression must be a single line")
	}
	return nil
}

// RuntimePath is the deployment-owned binary the units call.
func (o InstallOptions) RuntimePath() string { return filepath.Join(o.RuntimeDir, RuntimeBinaryName) }

// ServicePath and TimerPath are the installed unit files.
func (o InstallOptions) ServicePath() string { return filepath.Join(o.UnitDir, ServiceUnit) }
func (o InstallOptions) TimerPath() string   { return filepath.Join(o.UnitDir, TimerUnit) }

// marker is the first line of every unit this deployment writes. Uninstall
// removes a unit only when this line matches, so a same-named unit written
// by anything else is left alone.
func (o InstallOptions) marker() string {
	return "# guacdeploy deployment=" + o.DeploymentID
}

// execStart carries only the state directory. Everything else the renewal
// needs — hostname, installation directory, CA directory, credential mode —
// comes from the deployment record, which is authoritative and which an
// operator can change without rewriting a unit file.
func (o InstallOptions) execStart() string {
	return o.RuntimePath() + " renew-cert --state-dir " + o.StateDir
}

func (o InstallOptions) service() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
[Unit]
Description=guacdeploy origin certificate renewal
Documentation=https://github.com/Proaxiom-Cyber/guacamole-saml-sso
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=` + o.execStart() + `
`
}

func (o InstallOptions) timer() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
[Unit]
Description=guacdeploy origin certificate renewal

[Timer]
OnCalendar=` + o.OnCalendar + `
Persistent=true
RandomizedDelaySec=3600
Unit=` + ServiceUnit + `

[Install]
WantedBy=timers.target
`
}

// Installed reports what Install put on the host.
type Installed struct {
	RuntimePath string
	ServicePath string
	TimerPath   string
	OnCalendar  string
	Changed     bool // false when everything was already correct
}

// Install writes the runtime binary copy and both units, then enables and
// starts the timer. It is idempotent: running it again with the same options
// rewrites nothing and reports Changed false.
func Install(ctx context.Context, o InstallOptions) (Installed, error) {
	if err := o.defaults(); err != nil {
		return Installed{}, err
	}
	in := Installed{RuntimePath: o.RuntimePath(), ServicePath: o.ServicePath(),
		TimerPath: o.TimerPath(), OnCalendar: o.OnCalendar}

	// Catch a bad calendar expression here. systemd accepts an invalid
	// OnCalendar by refusing to load the timer, which fails silently as
	// "the certificate is never renewed".
	if _, stderr, err := o.Run(ctx, "", "systemd-analyze", "calendar", o.OnCalendar); err != nil {
		return in, fmt.Errorf("%q is not a valid systemd schedule: %v\n%s", o.OnCalendar, err, strings.TrimSpace(stderr))
	}

	copied, err := installRuntime(o.Exe, o.RuntimePath())
	if err != nil {
		return in, err
	}
	in.Changed = copied

	for path, content := range map[string]string{o.ServicePath(): o.service(), o.TimerPath(): o.timer()} {
		wrote, err := writeIfChanged(path, content, 0o644)
		if err != nil {
			return in, err
		}
		in.Changed = in.Changed || wrote
	}

	if in.Changed {
		if _, stderr, err := o.Run(ctx, "", "systemctl", "daemon-reload"); err != nil {
			return in, fmt.Errorf("systemctl daemon-reload: %v\n%s", err, strings.TrimSpace(stderr))
		}
	}
	// enable --now is idempotent and cheap, so it runs every time: it also
	// repairs a timer an administrator stopped or disabled by hand.
	if _, stderr, err := o.Run(ctx, "", "systemctl", "enable", "--now", TimerUnit); err != nil {
		return in, fmt.Errorf("enable the certificate renewal timer: %v\n%s", err, strings.TrimSpace(stderr))
	}
	return in, nil
}

// Uninstall stops and removes the renewal schedule. It removes only files
// carrying this deployment's marker; anything else with the same name is
// reported and left in place. Missing files are not an error.
//
// It does not remove the runtime binary copy: internal/schedule's backup
// timer calls the same copy, and removing it here would break that timer.
// Teardown removes it once, through internal/schedule's Uninstall.
func Uninstall(ctx context.Context, o InstallOptions) (removed []string, err error) {
	if o.UnitDir == "" {
		o.UnitDir = DefaultUnitDir
	}
	// Best effort: the timer may already be gone, which is not a failure.
	o.Run(ctx, "", "systemctl", "disable", "--now", TimerUnit)

	var foreign []string
	for _, path := range []string{o.TimerPath(), o.ServicePath()} {
		b, readErr := os.ReadFile(path)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return removed, readErr
		}
		first, _, _ := strings.Cut(string(b), "\n")
		if strings.TrimSpace(first) != o.marker() {
			foreign = append(foreign, path)
			continue
		}
		if err := os.Remove(path); err != nil {
			return removed, err
		}
		removed = append(removed, path)
	}
	if len(removed) > 0 {
		o.Run(ctx, "", "systemctl", "daemon-reload")
	}
	if len(foreign) > 0 {
		return removed, fmt.Errorf("left in place, not written by this deployment: %s", strings.Join(foreign, ", "))
	}
	return removed, nil
}

// installRuntime copies src to dst unless dst already has the same content.
// The copy goes through a temporary file and a rename: writing directly over
// a binary that is currently executing fails with ETXTBSY on Linux.
//
// This is the same routine as internal/schedule's, deliberately duplicated
// rather than exported from there: both install the same binary to the same
// path, so a second copy is a no-op, and neither package depends on the
// other.
func installRuntime(src, dst string) (bool, error) {
	want, err := os.ReadFile(src)
	if err != nil {
		return false, fmt.Errorf("read the guacdeploy binary at %s: %w", src, err)
	}
	if got, err := os.ReadFile(dst); err == nil && sha256.Sum256(got) == sha256.Sum256(want) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, want, 0o755); err != nil {
		return false, fmt.Errorf("install the guacdeploy runtime at %s: %w", dst, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("install the guacdeploy runtime at %s: %w", dst, err)
	}
	return true, nil
}

func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if got, err := os.ReadFile(path); err == nil && string(got) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}
