// Package schedule installs the recurring database backup as a systemd
// timer and service, and owns backup retention and last-run reporting.
//
// "Installed backup and renewal routines operate without the provisioning
// binary" (specification, architecture boundaries). The provisioning binary
// is whatever the administrator downloaded and ran; it may live in a home
// directory or a temporary directory and may be deleted the moment setup
// finishes. A unit pointing at that path would break on the next reboot.
//
// So Install copies the running executable to a deployment-owned runtime
// path (/usr/local/lib/guacdeploy/guacdeploy by default) and the unit calls
// that copy. The installed routine then depends on nothing but itself, the
// state directory, and Docker. The copy, the service, and the timer are all
// created resources and Uninstall removes them.
//
// This package is self-contained: it imports internal/backup (for the
// published-backup contract) and nothing else from the deployment. The
// parent wires it into the phase registry; see WIRING.md.
package schedule

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Unit names. One deployment per host, so the names are fixed.
const (
	ServiceUnit = "guacdeploy-backup.service"
	TimerUnit   = "guacdeploy-backup.timer"

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
	DefaultOnCalendar = "daily"
	DefaultKeep       = 7
)

// Runner executes a command, returning stdout and stderr separately. Same
// shape as backup.Runner so one fake serves both in tests.
type Runner func(ctx context.Context, stdin, name string, args ...string) (stdout, stderr string, err error)

// ExecRunner is the real command seam.
func ExecRunner(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errs strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	return out.String(), errs.String(), err
}

// Options configures the installed schedule.
type Options struct {
	Run          Runner
	DeploymentID string // written into each unit as the ownership marker
	StateDir     string // passed to the scheduled command
	Dest         string // backup destination directory
	OnCalendar   string // systemd calendar expression, default "daily"
	Keep         int    // successful backups to retain, default 7
	Plaintext    bool   // explicit choice; encryption is the default
	RequireMount bool   // destination must be on an approved mounted share

	UnitDir    string // default /etc/systemd/system
	RuntimeDir string // deployment-owned; default /usr/local/lib/guacdeploy
	Exe        string // source binary, default the running executable
}

func (o *Options) defaults() error {
	// A nil runner is a caller that forgot the seam, not a request to
	// crash mid-deployment.
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.OnCalendar == "" {
		o.OnCalendar = DefaultOnCalendar
	}
	if o.Keep == 0 {
		o.Keep = DefaultKeep
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
	if o.Keep < 1 {
		return fmt.Errorf("retention must keep at least one backup, got %d", o.Keep)
	}
	if o.StateDir == "" || o.Dest == "" {
		return fmt.Errorf("scheduling needs a state directory and a backup destination")
	}
	// systemd's ExecStart has its own quoting rules. Rather than implement
	// them, refuse the paths that would need them: a deployment directory
	// with a space or a quote in it is a configuration mistake, not a case
	// to support.
	for _, p := range []string{o.StateDir, o.Dest, o.UnitDir, o.RuntimeDir, o.Exe} {
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
func (o Options) RuntimePath() string { return filepath.Join(o.RuntimeDir, RuntimeBinaryName) }

// ServicePath and TimerPath are the installed unit files.
func (o Options) ServicePath() string { return filepath.Join(o.UnitDir, ServiceUnit) }
func (o Options) TimerPath() string   { return filepath.Join(o.UnitDir, TimerUnit) }

// marker is the first line of every unit this deployment writes. Uninstall
// removes a unit only when this line matches, so a same-named unit written
// by anything else is left alone.
func (o Options) marker() string {
	return "# guacdeploy deployment=" + o.DeploymentID
}

func (o Options) execStart() string {
	args := []string{o.RuntimePath(), "backup-run",
		"--state-dir", o.StateDir,
		"--dest", o.Dest,
		"--keep", fmt.Sprint(o.Keep)}
	if o.Plaintext {
		args = append(args, "--plaintext")
	}
	if o.RequireMount {
		args = append(args, "--require-mount")
	}
	return strings.Join(args, " ")
}

func (o Options) service() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
[Unit]
Description=guacdeploy scheduled Guacamole database backup
Documentation=https://github.com/Proaxiom-Cyber/guacamole-saml-sso
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=` + o.execStart() + `
`
}

func (o Options) timer() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
[Unit]
Description=guacdeploy scheduled Guacamole database backup

[Timer]
OnCalendar=` + o.OnCalendar + `
Persistent=true
RandomizedDelaySec=900
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
	Keep        int
	Changed     bool // false when everything was already correct
}

// Install writes the runtime binary copy and both units, then enables and
// starts the timer. It is idempotent: running it again with the same
// options rewrites nothing and reports Changed false, so a resumed or
// repeated setup does not churn systemd.
func Install(ctx context.Context, o Options) (Installed, error) {
	if err := o.defaults(); err != nil {
		return Installed{}, err
	}
	in := Installed{RuntimePath: o.RuntimePath(), ServicePath: o.ServicePath(),
		TimerPath: o.TimerPath(), OnCalendar: o.OnCalendar, Keep: o.Keep}

	// Catch a bad calendar expression here. systemd accepts an invalid
	// OnCalendar by refusing to load the timer, which fails silently as
	// "backups never run".
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
		return in, fmt.Errorf("enable the backup timer: %v\n%s", err, strings.TrimSpace(stderr))
	}
	return in, nil
}

// Uninstall stops and removes the schedule. It removes only files carrying
// this deployment's marker; anything else with the same name is reported
// and left in place. Missing files are not an error, so teardown is
// repeatable.
func Uninstall(ctx context.Context, o Options) (removed []string, err error) {
	if o.UnitDir == "" {
		o.UnitDir = DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = DefaultRuntimeDir
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

	// The runtime directory is deployment-owned by construction (see the
	// package comment), so its guacdeploy copy is ours to delete. Removing
	// the directory itself fails harmlessly when something else put a file
	// there.
	if err := os.Remove(o.RuntimePath()); err == nil {
		removed = append(removed, o.RuntimePath())
		os.Remove(o.RuntimeDir)
	} else if !os.IsNotExist(err) {
		return removed, err
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
// The copy goes through a temporary file and a rename: writing directly
// over a binary that is currently executing fails with ETXTBSY on Linux.
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
