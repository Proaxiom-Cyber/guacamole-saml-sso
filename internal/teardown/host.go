package teardown

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/certs"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
)

// Runner is the command seam, the same shape internal/backup,
// internal/certs and internal/schedule use, so one fake serves them all.
type Runner func(ctx context.Context, stdin, name string, args ...string) (stdout, stderr string, err error)

// ExecRunner is the real command seam.
func ExecRunner(ctx context.Context, stdin, name string, args ...string) (string, string, error) {
	return certs.ExecRunner(ctx, stdin, name, args...)
}

// HostOptions describes this host's half of the deployment.
type HostOptions struct {
	Run          Runner
	DeploymentID string
	StateDir     string
	InstallDir   string
	UnitDir      string // default /etc/systemd/system
	RuntimeDir   string // default /usr/local/sbin
}

func (o *HostOptions) defaults() {
	if o.Run == nil {
		o.Run = ExecRunner
	}
	if o.UnitDir == "" {
		o.UnitDir = certs.DefaultUnitDir
	}
	if o.RuntimeDir == "" {
		o.RuntimeDir = certs.DefaultRuntimeDir
	}
}

// HostUnits stops and removes this deployment's systemd units, and last of
// all the deployment-owned binary copy that the units call.
//
// The order inside this function is load-bearing. internal/schedule's
// Uninstall deletes the shared binary copy unconditionally; internal/certs
// and internal/recording deliberately leave it alone, because removing it
// from under a still-installed timer would break that timer. So the backup
// schedule goes last, when nothing else calls the binary any more.
//
// Each package removes a unit file only while it still carries this
// deployment's marker, so a same-named unit written by anything else is
// reported and left in place. A missing unit is already removed, not a
// failure, which is what makes a second run safe.
func HostUnits(ctx context.Context, o HostOptions) (removed []string, err error) {
	o.defaults()
	var errs []error
	add := func(r []string, e error) {
		removed = append(removed, r...)
		if e != nil {
			errs = append(errs, e)
		}
	}
	// The boot unit goes first: it is what would restart the stack after a
	// reboot, so it must stop before anything it depends on is removed. It
	// shares the binary copy with the others and has its own guard, so
	// removing it here never takes that copy away from a unit still
	// installed.
	add(creds.UninstallBoot(ctx, creds.BootOptions{
		Run: creds.Runner(o.Run), DeploymentID: o.DeploymentID, StateDir: o.StateDir,
		UnitDir: o.UnitDir, RuntimeDir: o.RuntimeDir,
	}))
	add(certs.Uninstall(ctx, certs.InstallOptions{
		Run: certs.Runner(o.Run), DeploymentID: o.DeploymentID, StateDir: o.StateDir,
		UnitDir: o.UnitDir, RuntimeDir: o.RuntimeDir,
	}))
	add(recording.Uninstall(ctx, recording.InstallOptions{
		Run: backup.Runner(o.Run), DeploymentID: o.DeploymentID, StateDir: o.StateDir,
		UnitDir: o.UnitDir, RuntimeDir: o.RuntimeDir,
	}))
	add(schedule.Uninstall(ctx, schedule.Options{
		Run: schedule.Runner(o.Run), DeploymentID: o.DeploymentID, StateDir: o.StateDir,
		UnitDir: o.UnitDir, RuntimeDir: o.RuntimeDir,
	}))
	return removed, errors.Join(errs...)
}

// rendered is what internal/stack writes under the installation directory.
// Everything else there belongs to somebody else.
var rendered = []string{"compose.yaml", ".env", "init", "nginx"}

// RemoveRendered removes the files this deployment rendered into dir and
// reports whatever is still there afterwards. The directory itself is
// removed only when it is empty, so a directory that now holds unrelated
// content — the data and the recordings, for a start — is preserved.
func RemoveRendered(ctx context.Context, dir string) (leftover []string, err error) {
	if err := safePath(dir); err != nil {
		return nil, err
	}
	for _, name := range rendered {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	return removeIfEmpty(dir)
}

// RemoveCredentials removes the credential files this deployment wrote and
// then the directory, if nothing else is in it. Both spellings go: the
// plain file of file mode and the sealed .cred of the encrypted modes,
// because the mode can have been changed since.
//
// Nothing here reads a credential value. The files are removed, never
// opened.
func RemoveCredentials(ctx context.Context, dir string, names []string) (leftover []string, err error) {
	if err := safePath(dir); err != nil {
		return nil, err
	}
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, `/\`) || strings.Contains(n, "..") {
			return nil, fmt.Errorf("refusing to delete credential %q: it is not a plain file name", n)
		}
		for _, p := range []string{filepath.Join(dir, n), filepath.Join(dir, n+".cred")} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		}
	}
	return removeIfEmpty(dir)
}

// removeIfEmpty removes dir when nothing is left in it, and otherwise
// reports what is.
func removeIfEmpty(dir string) (leftover []string, err error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // already gone
	}
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		leftover = append(leftover, e.Name())
	}
	if len(leftover) == 0 {
		return nil, os.Remove(dir)
	}
	return leftover, nil
}

// RemoveTree permanently deletes one content directory. Only the explicit
// deletion intent in the plan ever reaches it.
func RemoveTree(ctx context.Context, path string) error {
	if err := safePath(path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// safePath refuses the paths a mistake would turn into a disaster. Every
// path here comes from the deployment record, which this tool wrote, so
// this guards against a corrupted or hand-edited record, not against an
// attacker with write access to it.
func safePath(p string) error {
	c := filepath.Clean(p)
	if !filepath.IsAbs(c) {
		return fmt.Errorf("refusing to delete %q: it is not an absolute path", p)
	}
	if strings.Count(strings.Trim(c, string(filepath.Separator)), string(filepath.Separator)) < 1 {
		return fmt.Errorf("refusing to delete %q: it is a top-level directory", p)
	}
	return nil
}

// DefaultOps is the host half of the removal seam, ready to run. The
// provider deletes need credentials, so the command supplies those.
func DefaultOps(o HostOptions) Ops {
	o.defaults()
	return Ops{
		StopConnector: func(ctx context.Context, container string) error {
			_, stderr, err := o.Run(ctx, "", "docker", "stop", container)
			if err != nil {
				return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr))
			}
			return nil
		},
		RemoveHostUnits: func(ctx context.Context) ([]string, error) {
			return HostUnits(ctx, o)
		},
		RemoveContainers: func(ctx context.Context) error {
			// The rendered configuration still exists here: containers are
			// removed before it, exactly so this call has a compose file.
			// No credential override is needed, because the compose file
			// defaults every secret it interpolates.
			_, stderr, err := o.Run(ctx, "", "docker", "compose",
				"--project-directory", o.InstallDir,
				"--env-file", filepath.Join(o.InstallDir, ".env"),
				"-f", filepath.Join(o.InstallDir, "compose.yaml"),
				"down", "--remove-orphans")
			if err != nil {
				return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr))
			}
			// The containers are gone, so their credential files on
			// memory-backed storage have no reader left. Remove them here
			// rather than waiting for a reboot to clear the tmpfs.
			return stack.RemoveRuntimeSecrets(stack.Config{InstallDir: o.InstallDir})
		},
		ContainersPresent: func(ctx context.Context, names []string) ([]string, error) {
			// Ask by name rather than by project: the point of the check is
			// to catch a container this deployment created that the current
			// compose project no longer covers.
			stdout, stderr, err := o.Run(ctx, "", "docker", "ps", "--all", "--format", "{{.Names}}")
			if err != nil {
				return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr))
			}
			running := map[string]bool{}
			for _, line := range strings.Split(stdout, "\n") {
				if n := strings.TrimSpace(line); n != "" {
					running[n] = true
				}
			}
			var present []string
			for _, n := range names {
				if running[n] {
					present = append(present, n)
				}
			}
			return present, nil
		},
		RemoveRendered:    RemoveRendered,
		RemoveCredentials: RemoveCredentials,
		RemoveTree:        RemoveTree,
	}
}
