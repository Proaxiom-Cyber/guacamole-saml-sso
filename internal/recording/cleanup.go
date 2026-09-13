package recording

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
)

// Unit names. One deployment per host, so the names are fixed.
const (
	ServiceUnit = "guacdeploy-recordings.service"
	TimerUnit   = "guacdeploy-recordings.timer"

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

	// DefaultOnCalendar is hourly, not daily. Scheduled cleanup is not a
	// hard quota, and the interval is the size of the overshoot the
	// administrator has to tolerate, so the default keeps it small.
	DefaultOnCalendar = "hourly"
)

// cleanUp deletes the oldest completed recordings until local usage is back
// within budget, or no completed recording is left.
//
// Active recordings are never deleted, and they still count towards usage:
// that is why the budget is not a hard quota, and why active recordings
// alone can hold the directory over it. Upload success is not a condition
// for deletion; a deletion with no confirmed copy is recorded in Lost.
func (o Options) cleanUp(recs []Recording, backedUp map[string]bool, rep *Report) error {
	if o.Budget <= 0 {
		return nil // no budget configured: nothing is ever deleted
	}
	used := rep.UsedBefore
	for _, r := range recs {
		if used <= o.Budget {
			break
		}
		if r.Active {
			continue
		}
		if err := os.Remove(r.Path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			rep.UsedAfter = used
			return fmt.Errorf("delete recording %s to stay within the storage budget: %w", r.Path, err)
		}
		used -= r.Size
		rep.Deleted = append(rep.Deleted, r.Name)
		if !backedUp[r.Name] {
			rep.Lost = append(rep.Lost, r.Name)
		}
	}
	rep.UsedAfter = used
	return nil
}

// ParseBytes reads a storage budget written the way an administrator writes
// one: "20GB", "500M", "10GiB", or a plain number of bytes. Decimal suffixes
// are powers of 1000 and "i" suffixes are powers of 1024, as printed.
func ParseBytes(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("a storage budget is required, for example 20GB")
	}
	upper := strings.TrimSuffix(strings.ToUpper(t), "B")
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{
		{"TI", 1 << 40}, {"GI", 1 << 30}, {"MI", 1 << 20}, {"KI", 1 << 10},
		{"T", 1e12}, {"G", 1e9}, {"M", 1e6}, {"K", 1e3},
	} {
		if strings.HasSuffix(upper, u.suffix) {
			upper, mult = strings.TrimSuffix(upper, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(upper), 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a storage budget; use a number with an optional unit, for example 20GB", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("a storage budget must be greater than zero, got %q", s)
	}
	v := int64(n * float64(mult))
	if v <= 0 {
		return 0, fmt.Errorf("%q is smaller than one byte", s)
	}
	return v, nil
}

// FormatBytes prints a byte count the way ParseBytes reads one back.
func FormatBytes(n int64) string {
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%.1fTB", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1fGB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fMB", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fkB", float64(n)/1e3)
	}
	return fmt.Sprintf("%dB", n)
}

// InstallOptions configures the installed recording timer and service.
type InstallOptions struct {
	Run          backup.Runner
	DeploymentID string
	StateDir     string
	Dir          string // local recordings directory
	Dest         string // backup destination root; "" backs nothing up
	Budget       int64
	Plaintext    bool
	OnCalendar   string

	UnitDir    string // default /etc/systemd/system
	RuntimeDir string // deployment-owned; default /usr/local/sbin
	Exe        string // source binary, default the running executable
}

func (o *InstallOptions) defaults() error {
	// A nil runner is a caller that forgot the seam, not a request to
	// crash mid-deployment.
	if o.Run == nil {
		o.Run = backup.ExecRunner
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
	if o.StateDir == "" || o.Dir == "" {
		return fmt.Errorf("scheduling needs a state directory and a recordings directory")
	}
	if o.Budget < 0 {
		return fmt.Errorf("a storage budget cannot be negative, got %d", o.Budget)
	}
	if o.Budget == 0 && o.Dest == "" {
		return fmt.Errorf("the recording schedule would do nothing: it has neither a storage budget nor a backup destination")
	}
	// systemd's ExecStart has its own quoting rules. Rather than implement
	// them, refuse the paths that would need them.
	for _, p := range []string{o.StateDir, o.Dir, o.Dest, o.UnitDir, o.RuntimeDir, o.Exe} {
		if strings.ContainsAny(p, " \t\n\"'\\") {
			return fmt.Errorf("path %q contains whitespace or quotes, which cannot be scheduled safely", p)
		}
	}
	if strings.ContainsAny(o.OnCalendar, "\n\r") {
		return fmt.Errorf("the schedule expression must be a single line")
	}
	return nil
}

// RuntimePath is the deployment-owned binary the units call. It is the same
// path internal/schedule installs, for the same reason: the provisioning
// binary the administrator ran may be deleted the moment setup finishes, so
// a unit that pointed at it would break on the next reboot.
func (o InstallOptions) RuntimePath() string { return filepath.Join(o.RuntimeDir, RuntimeBinaryName) }

// ServicePath and TimerPath are the installed unit files.
func (o InstallOptions) ServicePath() string { return filepath.Join(o.UnitDir, ServiceUnit) }
func (o InstallOptions) TimerPath() string   { return filepath.Join(o.UnitDir, TimerUnit) }

// marker is the first line of every unit this deployment writes. Uninstall
// removes a unit only when this line matches.
func (o InstallOptions) marker() string {
	return "# guacdeploy deployment=" + o.DeploymentID
}

func (o InstallOptions) execStart() string {
	args := []string{o.RuntimePath(), "recordings-run",
		"--state-dir", o.StateDir,
		"--recordings-dir", o.Dir,
		"--budget", strconv.FormatInt(o.Budget, 10)}
	if o.Dest != "" {
		args = append(args, "--dest", o.Dest)
	}
	if o.Plaintext {
		args = append(args, "--plaintext")
	}
	return strings.Join(args, " ")
}

func (o InstallOptions) service() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
[Unit]
Description=guacdeploy recording backup and local storage budget
Documentation=https://github.com/Proaxiom-Cyber/guacamole-saml-sso
After=docker.service
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
Description=guacdeploy recording backup and local storage budget

[Timer]
OnCalendar=` + o.OnCalendar + `
Persistent=true
RandomizedDelaySec=300
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
	Budget      int64
	Changed     bool // false when everything was already correct
}

// Install writes the runtime binary copy and both units, then enables and
// starts the timer. It is idempotent: the same options twice rewrite
// nothing and report Changed false.
func Install(ctx context.Context, o InstallOptions) (Installed, error) {
	if err := o.defaults(); err != nil {
		return Installed{}, err
	}
	in := Installed{RuntimePath: o.RuntimePath(), ServicePath: o.ServicePath(),
		TimerPath: o.TimerPath(), OnCalendar: o.OnCalendar, Budget: o.Budget}

	// systemd accepts an invalid OnCalendar by refusing to load the timer,
	// which fails silently as "cleanup never runs". Catch it here.
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
	if _, stderr, err := o.Run(ctx, "", "systemctl", "enable", "--now", TimerUnit); err != nil {
		return in, fmt.Errorf("enable the recording timer: %v\n%s", err, strings.TrimSpace(stderr))
	}
	return in, nil
}

// Uninstall stops and removes the recording schedule. It removes only files
// carrying this deployment's marker; anything else with the same name is
// reported and left in place. Missing files are not an error.
//
// It never deletes a recording, locally or in the backup destination.
func Uninstall(ctx context.Context, o InstallOptions) (removed []string, err error) {
	if o.UnitDir == "" {
		o.UnitDir = DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = DefaultRuntimeDir
	}
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

	// The runtime binary copy is shared with the backup schedule, so it is
	// left in place here. internal/schedule.Uninstall owns it, and removing
	// it from under a still-installed backup timer would break that timer.
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
// ponytail: this and writeIfChanged are copies of the unexported helpers in
// internal/schedule, because this slice may not edit that package. When both
// land on the same branch, export them there and delete these.
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
