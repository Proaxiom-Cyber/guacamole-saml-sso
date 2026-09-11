package creds

// Reboot recovery. Acceptance criterion A11: "Persistent credential modes
// support reboot without retaining the provisioning binary."
//
// The provisioning binary is whatever the administrator downloaded and ran.
// It may sit in a home directory or a temporary directory and may be deleted
// the moment setup finishes, so a unit that points at it breaks on the next
// reboot. internal/schedule already solved this for the backup timer: it
// copies the running executable to a deployment-owned runtime path and the
// unit calls that copy. This package follows the same convention and uses
// the same path, so a host that installs both ends up with one binary. The
// copy is content-compared, so whichever package installs it second does
// nothing.
//
// The unit calls `guacdeploy stack-start --state-dir DIR`, which reads the
// deployment record, decrypts the credential into memory, and hands it to
// the stack through the existing in-memory Compose stdin override. The
// credential never reaches a file, an argument, or the unit.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// BootUnit starts the stack after a reboot.
	BootUnit = "guacdeploy-stack.service"
	// BootCommand is the subcommand the unit calls. The parent adds it;
	// see WIRING.md.
	BootCommand = "stack-start"

	DefaultUnitDir    = "/etc/systemd/system"
	DefaultRuntimeDir = "/usr/local/lib/guacdeploy"
)

// BootOptions configures the installed boot unit.
type BootOptions struct {
	Run          Runner
	DeploymentID string // written into the unit as the ownership marker
	Mode         string // the selected credential mode
	StateDir     string // passed to the boot command

	UnitDir    string // default /etc/systemd/system
	RuntimeDir string // deployment-owned; default /usr/local/lib/guacdeploy
	Exe        string // source binary, default the running executable
}

func (o *BootOptions) defaults() error {
	if o.Run == nil {
		o.Run = ExecRunner
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
		return fmt.Errorf("the boot unit needs a state directory")
	}
	// systemd's ExecStart has its own quoting rules. Refuse the paths that
	// would need them rather than implement them.
	for _, p := range []string{o.StateDir, o.UnitDir, o.RuntimeDir, o.Exe} {
		if strings.ContainsAny(p, " \t\n\"'\\") {
			return fmt.Errorf("path %q contains whitespace or quotes, which cannot be installed as a unit safely", p)
		}
	}
	return nil
}

// RuntimePath is the deployment-owned binary the unit calls.
func (o BootOptions) RuntimePath() string { return filepath.Join(o.RuntimeDir, "guacdeploy") }

// ServicePath is the installed unit file.
func (o BootOptions) ServicePath() string { return filepath.Join(o.UnitDir, BootUnit) }

func (o BootOptions) marker() string { return "# guacdeploy deployment=" + o.DeploymentID }

func (o BootOptions) service() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
[Unit]
Description=guacdeploy Guacamole stack start after reboot
Documentation=https://github.com/Proaxiom-Cyber/guacamole-saml-sso
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + o.RuntimePath() + ` ` + BootCommand + ` --state-dir ` + o.StateDir + `

[Install]
WantedBy=multi-user.target
`
}

// BootInstalled reports what InstallBoot put on the host.
type BootInstalled struct {
	RuntimePath string
	ServicePath string
	Changed     bool // false when everything was already correct
}

// InstallBoot installs the runtime binary copy and the boot unit, then
// enables it. It is idempotent.
//
// It refuses the modes that cannot recover unattended. Prompt mode needs a
// person. Env mode needs something to inject the variables, and the only
// way this tool could do that is to write them to disk in plaintext, which
// is the silent downgrade the specification forbids. Both refusals name the
// modes that do work.
func InstallBoot(ctx context.Context, o BootOptions) (BootInstalled, error) {
	if !Persistent(o.Mode) {
		return BootInstalled{}, fmt.Errorf(
			"credential mode %q cannot provide unattended reboot recovery: %s Choose %s, %s or %s",
			o.Mode, Describe(o.Mode).UnattendedReboot, ModeTPM, ModeHostKey, ModeFile)
	}
	if err := o.defaults(); err != nil {
		return BootInstalled{}, err
	}
	in := BootInstalled{RuntimePath: o.RuntimePath(), ServicePath: o.ServicePath()}

	copied, err := installRuntime(o.Exe, o.RuntimePath())
	if err != nil {
		return in, err
	}
	wrote, err := writeIfChanged(o.ServicePath(), o.service(), 0o644)
	if err != nil {
		return in, err
	}
	in.Changed = copied || wrote

	if in.Changed {
		if _, stderr, err := o.Run(ctx, "", "systemctl", "daemon-reload"); err != nil {
			return in, fmt.Errorf("systemctl daemon-reload: %v\n%s", err, strings.TrimSpace(stderr))
		}
	}
	// enable, not enable --now: the stack is already running at this point
	// in setup, and starting the unit here would restart it for nothing.
	// The unit is idempotent, so a later manual start is harmless.
	if _, stderr, err := o.Run(ctx, "", "systemctl", "enable", BootUnit); err != nil {
		return in, fmt.Errorf("enable the boot unit: %v\n%s", err, strings.TrimSpace(stderr))
	}
	return in, nil
}

// UninstallBoot disables and removes the boot unit. It removes the unit only
// when the file carries this deployment's marker, so a same-named unit
// written by anything else is reported and left in place. Missing files are
// not an error, so teardown is repeatable.
//
// The runtime binary is shared with internal/schedule, so it is removed only
// when no other guacdeploy unit still calls it.
func UninstallBoot(ctx context.Context, o BootOptions) (removed []string, err error) {
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.UnitDir == "" {
		o.UnitDir = DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = DefaultRuntimeDir
	}
	// Best effort: the unit may already be gone, which is not a failure.
	o.Run(ctx, "", "systemctl", "disable", "--now", BootUnit)

	var foreign []string
	b, readErr := os.ReadFile(o.ServicePath())
	switch {
	case os.IsNotExist(readErr):
	case readErr != nil:
		return removed, readErr
	default:
		first, _, _ := strings.Cut(string(b), "\n")
		if strings.TrimSpace(first) != o.marker() {
			foreign = append(foreign, o.ServicePath())
		} else {
			if err := os.Remove(o.ServicePath()); err != nil {
				return removed, err
			}
			removed = append(removed, o.ServicePath())
		}
	}

	if !runtimeStillUsed(o.UnitDir, o.RuntimePath()) {
		if err := os.Remove(o.RuntimePath()); err == nil {
			removed = append(removed, o.RuntimePath())
			os.Remove(o.RuntimeDir) // fails harmlessly when not empty
		} else if !os.IsNotExist(err) {
			return removed, err
		}
	}

	if len(removed) > 0 {
		o.Run(ctx, "", "systemctl", "daemon-reload")
	}
	if len(foreign) > 0 {
		return removed, fmt.Errorf("left in place, not written by this deployment: %s", strings.Join(foreign, ", "))
	}
	return removed, nil
}

// runtimeStillUsed reports whether some other installed unit calls the
// shared runtime binary. internal/schedule installs the same binary for the
// backup timer; removing it here would break that timer on the next run.
func runtimeStillUsed(unitDir, runtime string) bool {
	for _, pattern := range []string{"guacdeploy-*.service", "guacdeploy-*.timer"} {
		paths, _ := filepath.Glob(filepath.Join(unitDir, pattern))
		for _, p := range paths {
			if filepath.Base(p) == BootUnit {
				continue
			}
			if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), runtime) {
				return true
			}
		}
	}
	return false
}

// installRuntime copies src to dst unless dst already has the same content.
// The copy goes through a temporary file and a rename: writing directly over
// a binary that is currently executing fails with ETXTBSY on Linux.
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
