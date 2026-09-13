package azure

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
)

// DropInName is the file the Azure upload adds to the scheduled backup's
// service. The numeric prefix is the systemd convention for drop-in ordering.
const DropInName = "10-azure-upload.conf"

// UnitOptions configures the scheduled upload. It carries no credential: the
// unattended service principal's client secret is read at the point of use
// from the deployment's credential store, never from a command line, an
// environment file, or a unit.
type UnitOptions struct {
	Run          schedule.Runner
	DeploymentID string // written into the drop-in as the ownership marker
	StateDir     string // passed to the scheduled command
	Dest         string // the local published backup destination it copies from

	UnitDir    string // default /etc/systemd/system
	RuntimeDir string // deployment-owned; default /usr/local/sbin
}

func (o *UnitOptions) defaults() error {
	if o.Run == nil {
		o.Run = schedule.ExecRunner
	}
	if o.UnitDir == "" {
		o.UnitDir = schedule.DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = schedule.DefaultRuntimeDir
	}
	if o.DeploymentID == "" {
		return fmt.Errorf("the scheduled Azure upload needs the deployment ID to mark the unit it writes")
	}
	if o.StateDir == "" || o.Dest == "" {
		return fmt.Errorf("the scheduled Azure upload needs a state directory and the local backup destination it copies from")
	}
	// systemd's ExecStart has its own quoting rules. Rather than implement
	// them, refuse the paths that would need them, exactly as
	// internal/schedule does for the same line.
	for _, p := range []string{o.StateDir, o.Dest, o.UnitDir, o.RuntimeDir} {
		if strings.ContainsAny(p, " \t\n\"'\\") {
			return fmt.Errorf("path %q contains whitespace or quotes, which cannot be scheduled safely", p)
		}
	}
	return nil
}

// RuntimePath is the deployment-owned binary the drop-in calls. It is the copy
// internal/schedule installs, not the provisioning binary: "Installed backup
// and renewal routines operate without the provisioning binary"
// (specification), and the administrator is free to delete what they
// downloaded the moment setup finishes.
func (o UnitOptions) RuntimePath() string {
	return filepath.Join(o.RuntimeDir, schedule.RuntimeBinaryName)
}

// ServicePath is the scheduled backup's service unit, which this extends.
func (o UnitOptions) ServicePath() string {
	return filepath.Join(o.UnitDir, schedule.ServiceUnit)
}

// DropInPath is the file this package writes.
func (o UnitOptions) DropInPath() string {
	return filepath.Join(o.UnitDir, schedule.ServiceUnit+".d", DropInName)
}

func (o UnitOptions) marker() string {
	return "# guacdeploy deployment=" + o.DeploymentID
}

func (o UnitOptions) execStart() string {
	return strings.Join([]string{o.RuntimePath(), "azure-upload",
		"--state-dir", o.StateDir,
		"--dest", o.Dest}, " ")
}

// dropIn is the unit fragment. ExecStart= in a drop-in is appended to the
// list the service already has, and the backup service is Type=oneshot, which
// runs its ExecStart lines one after another in order. So the upload runs on
// the same timer as the backup and always after it — it cannot copy a backup
// that has not been taken yet, which is the whole reason for extending that
// service rather than installing a second timer at a guessed later hour.
func (o UnitOptions) dropIn() string {
	return o.marker() + `
# Written by guacdeploy. Edits are replaced on the next run.
# Runs after the scheduled database backup, on the same timer: this uploads
# what that backup published, and the completed recording copies beside it.
[Service]
ExecStart=` + o.execStart() + `
`
}

// InstalledUpload reports what InstallUpload put on the host.
type InstalledUpload struct {
	DropInPath  string
	RuntimePath string
	ExecStart   string
	Changed     bool // false when the drop-in was already correct
}

// InstallUpload makes the scheduled backup timer upload as well.
//
// It adds one drop-in to the backup service rather than installing a timer of
// its own. That is not only less to remove later: it is the ordering
// guarantee. The upload copies files the backup has just published, so a
// separate timer would have to be set to a later hour and hope, while a second
// ExecStart on a Type=oneshot service runs when the first has finished.
//
// It refuses when the backup schedule is not installed, because a drop-in for
// a unit that does not exist is a silent no-op — "backups upload" that never
// runs. The parent installs the backup schedule first; see WIRING.md.
func InstallUpload(ctx context.Context, o UnitOptions) (InstalledUpload, error) {
	if err := o.defaults(); err != nil {
		return InstalledUpload{}, err
	}
	in := InstalledUpload{DropInPath: o.DropInPath(), RuntimePath: o.RuntimePath(), ExecStart: o.execStart()}

	if _, err := os.Stat(o.ServicePath()); err != nil {
		return in, fmt.Errorf("the scheduled backup service %s is not installed, so there is no timer for the Azure upload to run on; install the backup schedule first: %w", o.ServicePath(), err)
	}
	if _, err := os.Stat(o.RuntimePath()); err != nil {
		return in, fmt.Errorf("the deployment-owned runtime binary %s is missing, so the scheduled upload would not run after a reboot: %w", o.RuntimePath(), err)
	}

	wrote, err := writeIfChanged(o.DropInPath(), o.dropIn(), 0o644)
	if err != nil {
		return in, err
	}
	in.Changed = wrote
	if wrote {
		if _, stderr, err := o.Run(ctx, "", "systemctl", "daemon-reload"); err != nil {
			return in, fmt.Errorf("systemctl daemon-reload: %v\n%s", err, strings.TrimSpace(stderr))
		}
	}
	return in, nil
}

// UninstallUpload removes the drop-in, leaving the backup timer itself alone.
//
// It removes the file only when it carries this deployment's marker, the same
// rule internal/schedule and internal/recording apply to their units. It
// deletes nothing in Azure: the container, the storage account and every blob
// survive teardown, and there is no code path here that could remove them.
func UninstallUpload(ctx context.Context, o UnitOptions) (removed []string, err error) {
	if o.UnitDir == "" {
		o.UnitDir = schedule.DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = schedule.DefaultRuntimeDir
	}
	path := o.DropInPath()
	b, readErr := os.ReadFile(path)
	if os.IsNotExist(readErr) {
		return nil, nil // already gone; teardown is repeatable
	}
	if readErr != nil {
		return nil, readErr
	}
	first, _, _ := strings.Cut(string(b), "\n")
	if strings.TrimSpace(first) != o.marker() {
		return nil, fmt.Errorf("left in place, not written by this deployment: %s", path)
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	os.Remove(filepath.Dir(path)) // fails harmlessly when another drop-in is there
	if o.Run != nil {
		o.Run(ctx, "", "systemctl", "daemon-reload")
	}
	return []string{path}, nil
}

// writeIfChanged writes content unless the file already has it.
//
// ponytail: a copy of the unexported helper in internal/schedule and
// internal/recording, because this slice may not edit either package. When all
// three land on the same branch, export one and delete the other two.
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
