package stack

// Credential delivery into the containers.
//
// The problem this file solves: Docker persists a container's environment in
// its own metadata (/var/lib/docker/containers/<id>/config.v2.json). Handing a
// password to a container as an environment field therefore writes a plaintext
// copy of it to disk, where it stays for the life of the container and is
// re-read on every boot because the services carry "restart: always". That
// copy exists even when the deployment's own credential store is sealed to the
// TPM, so the specification's "no unapproved persistent plaintext copies"
// cannot be met while any credential travels that way.
//
// Every one of the three pinned images can read a credential from a file
// instead, so none of them needs an environment variable:
//
//   - postgres:18-alpine — docker-entrypoint.sh defines file_env() and calls
//     "file_env 'POSTGRES_PASSWORD'", so POSTGRES_PASSWORD_FILE names a file to
//     read. The image sets no USER, and file_env runs in docker_setup_env()
//     before "exec gosu postgres", so the file is read as root and can be
//     root-owned and mode 0600. file_env uses $(< file), which drops trailing
//     newlines.
//
//   - guacamole/guacamole:1.6.0 — the image Dockerfile sets
//     ENABLE_FILE_ENVIRONMENT_PROPERTIES=true, and 1.6.0's
//     GuacamoleServletContextListener registers
//     SystemFileEnvironmentGuacamoleProperties when that property is true. That
//     source resolves any Guacamole property from the file named by
//     <PROPERTY>_FILE, so postgresql-password comes from
//     POSTGRESQL_PASSWORD_FILE. It reads the file verbatim, so the file must
//     carry no trailing newline. The image runs as USER guacamole, uid and gid
//     1001.
//
//   - cloudflare/cloudflared — "tunnel run" accepts --token-file, bound to
//     TUNNEL_TOKEN_FILE, and reads it with os.ReadFile plus strings.TrimSpace.
//     The flag has been in the image since April 2025. The image is distroless
//     and runs as USER 65532:65532.
//
// The files live on tmpfs under /run, are owner-only, and are written at start
// time. They are deliberately not removed after start: postgres and cloudflared
// re-read them every time a container restarts, so removing them would break
// the restart policy. A cold boot empties the tmpfs instead, and the boot unit
// installed by internal/creds writes them again before it starts the stack.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runtimeSecret is one credential delivered to one container as a file.
//
// UID is the account the pinned image runs as. The container must be able to
// read its own file and nothing else may, so the file and its directory belong
// to that account. A pinned image that changes its user fails loudly — the
// container cannot read the file and exits — rather than quietly starting
// without a credential.
type runtimeSecret struct {
	Service string // compose service, and the sub-directory name on the host
	File    string // file name, inside the directory and under /run/secrets
	UID     int
	Label   string // what to call it in a message; never the value
}

var runtimeSecrets = []runtimeSecret{
	{Service: "postgres", File: "postgres-password", UID: 0, Label: "the database password"},
	{Service: "guacamole", File: "postgresql-password", UID: 1001, Label: "the database password"},
	{Service: "cloudflared", File: "tunnel-token", UID: 65532, Label: "the Cloudflare tunnel token"},
}

// value picks which of the two credentials this secret carries.
func (s runtimeSecret) value(password, tunnelToken string) string {
	if s.Service == "cloudflared" {
		return tunnelToken
	}
	return password
}

func (s runtimeSecret) dir(cfg Config) string {
	return filepath.Join(cfg.RuntimeSecretsDir, s.Service)
}

func (s runtimeSecret) path(cfg Config) string {
	return filepath.Join(s.dir(cfg), s.File)
}

// runtimeSecretsDir chooses where the credential files are written when the
// caller names no directory.
//
// On a deployment host the answer is always DefaultRuntimeSecretsDir. The tool
// runs as root there — the host preflight requires it and Docker needs it —
// and only root can create a directory under /run. An unprivileged run is a
// development run or the test suite, and it gets the memory-backed directory
// the same host already offers to ordinary accounts. checkMemoryBacked applies
// to whichever directory is chosen, so neither can put a decrypted credential
// on storage that survives a reboot.
func runtimeSecretsDir() string {
	if os.Geteuid() == 0 {
		return DefaultRuntimeSecretsDir
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "guacdeploy", "secrets")
	}
	name := fmt.Sprintf("guacdeploy-secrets-%d", os.Geteuid())
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		return filepath.Join("/dev/shm", name)
	}
	return filepath.Join(os.TempDir(), name)
}

// writeRuntimeSecrets fills the memory-backed directory the containers read.
//
// It reports fresh=true when any file had to be created rather than rewritten.
// That is the cold-boot signal: /run was empty, so Docker's own restart policy
// has already started the containers against an empty mount and they are
// running without a credential. Compose sees no configuration change and would
// leave them exactly as they are, so Up recreates them in that case.
func writeRuntimeSecrets(cfg Config, password, tunnelToken string) (fresh bool, err error) {
	root := cfg.RuntimeSecretsDir
	// 0711: each service's own directory below is owner-only, and the
	// container accounts need to traverse this one to reach theirs. Docker
	// creates a missing bind-mount source itself, as mode 0755 root, so the
	// mode is repaired rather than assumed.
	if err := os.MkdirAll(root, 0o711); err != nil {
		return false, fmt.Errorf("create the runtime credential directory %s: %w", root, err)
	}
	if err := os.Chmod(root, 0o711); err != nil {
		return false, err
	}
	if err := checkMemoryBacked(root); err != nil {
		return false, err
	}
	for _, s := range runtimeSecrets {
		v := s.value(password, tunnelToken)
		if v == "" {
			// No Cloudflare profile, for instance. Leave nothing behind.
			os.Remove(s.path(cfg))
			continue
		}
		if _, statErr := os.Stat(s.path(cfg)); statErr != nil {
			fresh = true
		}
		if err := os.MkdirAll(s.dir(cfg), 0o700); err != nil {
			return fresh, fmt.Errorf("create the runtime credential directory %s: %w", s.dir(cfg), err)
		}
		if err := os.Chmod(s.dir(cfg), 0o700); err != nil {
			return fresh, err
		}
		// No trailing newline: Guacamole reads the file verbatim, and a
		// newline would become part of the password.
		if err := os.WriteFile(s.path(cfg), []byte(v), 0o600); err != nil {
			return fresh, fmt.Errorf("write the runtime credential for the %s service: %w", s.Service, err)
		}
		if err := os.Chmod(s.path(cfg), 0o600); err != nil { // repair an earlier file
			return fresh, err
		}
		if err := own(s.dir(cfg), s.UID); err != nil {
			return fresh, err
		}
		if err := own(s.path(cfg), s.UID); err != nil {
			return fresh, err
		}
	}
	return fresh, nil
}

// RemoveRuntimeSecrets deletes the runtime credential files. Teardown should
// call it after the containers are gone: a cold boot would clear the tmpfs
// anyway, but a host that is torn down and left running should not keep the
// credentials in memory until someone reboots it.
func RemoveRuntimeSecrets(cfg Config) error {
	cfg.defaults()
	return os.RemoveAll(cfg.RuntimeSecretsDir)
}

// own gives one runtime path to the account its container runs as. Only root
// may change ownership; an unprivileged run (the test suite) leaves the path
// owned by the caller, which is still owner-only.
func own(path string, uid int) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if err := os.Chown(path, uid, uid); err != nil {
		return fmt.Errorf("give %s to uid %d, the account its container runs as: %w", path, uid, err)
	}
	return nil
}

// memoryBackedFS are the filesystem types whose contents are held in memory
// only, so that a cold boot leaves nothing on disk.
var memoryBackedFS = map[string]bool{"tmpfs": true, "ramfs": true}

// checkMemoryBacked refuses to write a decrypted credential anywhere that
// survives a reboot. Without this check, a host that mounted /run differently
// would turn every credential mode into the plaintext file mode silently,
// which is exactly the downgrade the specification forbids.
//
// On a host with no /proc/mounts — a development machine or the test suite —
// there is nothing to check and nothing to protect. The deployment host is
// Linux, where /proc/mounts always exists.
func checkMemoryBacked(path string) error {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}
	fstype, found := mountFSType(string(b), path)
	if !found {
		return fmt.Errorf("cannot tell which filesystem holds %s; deployment credentials may only be written to memory-backed storage such as tmpfs", path)
	}
	if !memoryBackedFS[fstype] {
		return fmt.Errorf("%s is on a %q filesystem, which survives a reboot; deployment credentials may only be written to memory-backed storage such as tmpfs", path, fstype)
	}
	return nil
}

// mountFSType returns the filesystem type of the longest mount point that
// contains path, given the contents of /proc/mounts.
func mountFSType(mounts, path string) (fstype string, found bool) {
	best := ""
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		mp := f[1]
		under := mp == path || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/")
		if under && (!found || len(mp) >= len(best)) {
			best, fstype, found = mp, f[2], true
		}
	}
	return fstype, found
}

// CheckDelivery performs the specification's "check container delivery" step
// for a running stack: it proves that each credential reached its container
// and that no plaintext copy of it was left anywhere that survives a reboot.
//
// It searches the rendered compose file, the rendered .env, and Docker's own
// stored container metadata — the same Config.Env that Docker keeps in
// /var/lib/docker/containers/<id>/config.v2.json, read back through
// "docker inspect" — for each credential value. It then checks that the
// runtime file holds the value, is owner-only, and is on memory-backed
// storage.
//
// Nothing here prints, logs, or returns a credential. A finding names the
// credential and where it was found, never its value.
func CheckDelivery(ctx context.Context, run Runner, cfg Config, password, tunnelToken string) error {
	cfg.defaults()
	var found []string

	// 1. Nothing secret in anything guacdeploy rendered to persistent disk.
	for _, name := range []string{"compose.yaml", ".env"} {
		b, err := os.ReadFile(filepath.Join(cfg.InstallDir, name))
		if err != nil {
			return fmt.Errorf("read the rendered %s: %w", name, err)
		}
		for _, s := range runtimeSecrets {
			if v := s.value(password, tunnelToken); v != "" && strings.Contains(string(b), v) {
				found = append(found, fmt.Sprintf("%s appears in the rendered %s", s.Label, name))
			}
		}
	}

	// 2. Nothing secret in Docker's own container metadata.
	out, err := run(ctx, "", "docker", cfg.composeArgs("ps", "--quiet")...)
	if err != nil {
		return fmt.Errorf("list the stack's containers: %v\n%s", err, tail(out))
	}
	if ids := containerIDs(out); len(ids) > 0 {
		meta, err := run(ctx, "", "docker", append([]string{"inspect"}, ids...)...)
		if err != nil {
			return fmt.Errorf("read the stored container metadata: %v\n%s", err, tail(meta))
		}
		for _, s := range runtimeSecrets {
			if v := s.value(password, tunnelToken); v != "" && strings.Contains(meta, v) {
				found = append(found, fmt.Sprintf(
					"%s appears in the stored metadata of the %s container, which Docker keeps on disk and re-reads on every boot",
					s.Label, s.Service))
			}
		}
	}

	// 3. The runtime files: delivered, owner-only, and not on persistent
	// storage.
	for _, s := range runtimeSecrets {
		v := s.value(password, tunnelToken)
		if v == "" {
			continue
		}
		info, err := os.Stat(s.path(cfg))
		if err != nil {
			found = append(found, fmt.Sprintf("%s was not delivered: there is no runtime file at %s", s.Label, s.path(cfg)))
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			found = append(found, fmt.Sprintf("the runtime file %s is mode %04o, not owner-only", s.path(cfg), perm))
		}
		b, err := os.ReadFile(s.path(cfg))
		if err != nil || string(b) != v {
			found = append(found, fmt.Sprintf("the runtime file %s does not hold %s", s.path(cfg), s.Label))
		}
	}
	if err := checkMemoryBacked(cfg.RuntimeSecretsDir); err != nil {
		found = append(found, err.Error())
	}

	if len(found) > 0 {
		return fmt.Errorf("credential delivery check failed:\n  %s", strings.Join(found, "\n  "))
	}
	return nil
}

// containerIDs picks container IDs out of "docker compose ps --quiet" output,
// which can also carry warnings.
func containerIDs(out string) []string {
	var ids []string
	for _, f := range strings.Fields(out) {
		if len(f) < 12 || strings.TrimLeft(f, "0123456789abcdef") != "" {
			continue
		}
		ids = append(ids, f)
	}
	return ids
}
