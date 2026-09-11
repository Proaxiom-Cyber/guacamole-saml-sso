// Package backup exports and restores the Guacamole database through the
// running stack's postgres container. The export uses PostgreSQL's
// database-aware pg_dump, never a copy of the running data directory.
// Backups are encrypted with the recorded backup public key by default;
// plaintext is an explicit caller choice, never a fallback.
//
// Coordination: the caller must hold the deployment lock (state.Open) for
// the whole backup or restore, so no deployment mutation runs while the
// metadata snapshot and export are taken. The command layer does this.
//
// Roles: the dump references guacamole_user. The postgres container creates
// that role from its POSTGRES_USER environment at first start, and in the
// official image that role is the cluster superuser, so schema reset and
// restore need no separate role work.
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
)

// FormatVersion is the backup file format this tool writes and restores.
const FormatVersion = 1

// Runner executes a command, returning stdout and stderr separately.
//
// stack.Runner returns combined output, which suits docker compose
// lifecycle commands but not an export: a warning on stderr would land
// inside the captured dump. The dump format is plain SQL (--format=plain),
// not pg_dump's custom binary format, because the dump travels through Go
// strings and is validated line by line at restore time; binary data
// through a string seam is fragile, and custom format buys nothing for one
// small database. The matching restore is psql with ON_ERROR_STOP=1.
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

// Options configures one backup or restore against the running stack.
type Options struct {
	Run         Runner
	InstallDir  string // compose project directory, e.g. /opt/guacamole
	Dest        string // backup destination directory
	Plaintext   bool   // explicit choice; encryption is the default
	PublicKey   string // age recipient from state Config, required unless Plaintext
	GuacVersion string // pinned Guacamole version, recorded in the backup header

	// Now supplies the backup timestamp; nil means time.Now. Tests set it
	// to a fixed instant to exercise the name-collision guard.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// composeArgs targets the running stack's compose project. No credential
// override is needed: psql and pg_dump run inside the postgres container
// over its local socket, which the official image trusts.
func (o Options) composeArgs(rest ...string) []string {
	return append([]string{"compose",
		"--project-directory", o.InstallDir,
		"--env-file", filepath.Join(o.InstallDir, ".env"),
		"-f", filepath.Join(o.InstallDir, "compose.yaml")}, rest...)
}

func (o Options) psql(ctx context.Context, stdin string) (string, string, error) {
	return o.Run(ctx, stdin, "docker", o.composeArgs("exec", "-T", "postgres",
		"psql", "-v", "ON_ERROR_STOP=1", "-q", "-U", "guacamole_user", "-d", "guacamole_db")...)
}

// Backup snapshots deployment metadata into the database, exports the
// database, and publishes the (by default encrypted) backup file into
// o.Dest. It returns the published path. On any failure only a
// .partial-... file can remain; a final backup name appears only after a
// complete, verified export, so retention can never mistake a partial
// export for a valid backup.
//
// Each published backup gets a non-secret completion Manifest beside it,
// written after the backup file (see publishManifest). That manifest is
// how a scheduled run — which holds no private key — proves a backup is
// complete and belongs to this deployment.
func Backup(ctx context.Context, o Options, st *state.State) (string, error) {
	mode := "age"
	ext := ".sql.age"
	if o.Plaintext {
		mode, ext = "none", ".sql"
	} else {
		if o.PublicKey == "" {
			return "", fmt.Errorf("refusing an encrypted backup: no backup public key is recorded; run 'guacdeploy backup-key' first, or choose --plaintext deliberately")
		}
		if _, err := age.ParseX25519Recipient(o.PublicKey); err != nil {
			return "", fmt.Errorf("the recorded backup public key is not usable: %w", err)
		}
	}

	// The destination must already exist: a missing directory or mount
	// fails visibly here, before any export, and is never redirected.
	if fi, err := os.Stat(o.Dest); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("backup destination %s is not an existing directory (is the mount present?); nothing was exported", o.Dest)
	}

	// Millisecond resolution makes same-name runs vanishingly unlikely, and
	// publishNonDestructively below still refuses to overwrite if one ever
	// does collide. The partial gets a random suffix so a retry started in
	// the same millisecond cannot fail on, or clobber, an earlier partial.
	base := "guacdeploy-db-" + o.now().UTC().Format("20060102T150405.000Z")
	f, err := os.CreateTemp(o.Dest, ".partial-"+base+"-*"+ext)
	if err != nil {
		return "", fmt.Errorf("backup destination %s is not writable: %w; nothing was exported", o.Dest, err)
	}
	partial := f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return "", err
	}
	// On failure the .partial file stays behind as evidence of the failed
	// attempt; its dot-name never matches a published backup, so earlier
	// finished backups and retention are unaffected.

	// Metadata snapshot before export: the deployment state (which holds
	// no credential values by construction) goes into the database as a
	// versioned row, so the export carries authoritative ownership state.
	stateJSON, err := json.Marshal(st)
	if err != nil {
		f.Close()
		return "", err
	}
	snapshot := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS guacdeploy_metadata (id serial primary key, schema_version int, taken_at timestamptz, state jsonb);\n"+
			"INSERT INTO guacdeploy_metadata (schema_version, taken_at, state) VALUES (%d, now(), '%s'::jsonb);\n",
		state.SchemaVersion, strings.ReplaceAll(string(stateJSON), "'", "''"))
	if _, stderr, err := o.psql(ctx, snapshot); err != nil {
		f.Close()
		return "", fmt.Errorf("metadata snapshot failed, backup not published: %v\n%s", err, tail(stderr))
	}

	dump, stderr, err := o.Run(ctx, "", "docker", o.composeArgs("exec", "-T", "postgres",
		"pg_dump", "-U", "guacamole_user", "-d", "guacamole_db", "--format=plain")...)
	if err != nil {
		f.Close()
		return "", fmt.Errorf("database export failed, backup not published: %v\n%s", err, tail(stderr))
	}
	if !strings.Contains(dump, "PostgreSQL database dump") {
		f.Close()
		return "", fmt.Errorf("the export does not look like a pg_dump result; backup not published")
	}

	if !strings.HasSuffix(dump, "\n") {
		dump += "\n"
	}
	body := fmt.Sprintf("-- guacdeploy backup format=%d guacamole=%s mode=%s\n", FormatVersion, o.GuacVersion, mode) + dump
	content := body + fmt.Sprintf("-- guacdeploy dump complete sha256:%x\n", sha256.Sum256([]byte(body)))

	if o.Plaintext {
		_, err = f.WriteString(content)
	} else {
		err = recoverykey.EncryptTo(o.PublicKey, strings.NewReader(content), f)
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		f.Close()
		return "", fmt.Errorf("writing the backup failed, backup not published: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("writing the backup failed, backup not published: %w", err)
	}
	final, err := publishNonDestructively(o.Dest, partial, base, ext)
	if err != nil {
		return "", err
	}
	if err := publishManifest(o.Dest, final, mode, st.DeploymentID); err != nil {
		return "", err
	}
	if d, err := os.Open(o.Dest); err == nil {
		d.Sync()
		d.Close()
	}
	return final, nil
}

// linkFile is os.Link, replaced in tests to exercise the copy fallback.
var linkFile = os.Link

// publishNonDestructively gives the finished partial its published name
// without ever overwriting an earlier backup. On a collision the next free
// "-N" name is used, and the partial is removed only once the published
// file is complete, so a failure here leaves the export on disk rather
// than losing it.
//
// Two paths, same guarantee:
//
//   - A hard link (os.Link) where the filesystem supports one: local disk,
//     NFS, and most other POSIX mounts. It fails atomically when the target
//     exists, so the final name is claimed or nothing happens.
//   - Reserve-then-copy where it does not: many SMB/CIFS mounts reject
//     link(2) with EPERM or EOPNOTSUPP, which used to fail the whole
//     publish on exactly the mounted share the specification calls a
//     supported destination. O_CREATE|O_EXCL claims the final name
//     atomically, the bytes are copied and fsynced into it, and a copy that
//     fails removes the reserved file so no half-written backup can sit
//     under a published name.
//
// The fallback latches for the rest of the loop: a filesystem that cannot
// link the first name cannot link the next one either.
func publishNonDestructively(dest, partial, base, ext string) (string, error) {
	copyMode := false
	for i := 0; i <= 100; i++ {
		final := filepath.Join(dest, base+ext)
		if i > 0 {
			final = filepath.Join(dest, fmt.Sprintf("%s-%d%s", base, i, ext))
		}
		if !copyMode {
			err := linkFile(partial, final)
			if err == nil {
				os.Remove(partial)
				return final, nil
			}
			if errors.Is(err, os.ErrExist) {
				continue // the name is taken by an earlier backup
			}
			if !linkUnsupported(err) {
				return "", fmt.Errorf("publishing the backup failed: %w; the export is kept at %s", err, partial)
			}
			copyMode = true
		}
		err := copyReserved(partial, final)
		if err == nil {
			os.Remove(partial)
			return final, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return "", fmt.Errorf("publishing the backup failed: %w; the export is kept at %s", err, partial)
	}
	return "", fmt.Errorf("publishing the backup failed: too many backups share the name %s%s; the export is kept at %s", base, ext, partial)
}

// linkUnsupported reports whether err means "this filesystem does not do
// hard links", rather than "this particular link failed". ENOTSUP and
// EOPNOTSUPP are the same value on Linux, so these are tested with
// errors.Is rather than a switch.
func linkUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EMLINK) ||
		errors.Is(err, errors.ErrUnsupported)
}

// copyReserved claims final with O_EXCL and copies partial into it. An
// existing final returns os.ErrExist untouched, for the collision loop. A
// failed copy removes the reserved file, so a published name never holds a
// half-written backup.
func copyReserved(partial, final string) error {
	dst, err := os.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = func() error {
		defer dst.Close()
		src, err := os.Open(partial)
		if err != nil {
			return err
		}
		defer src.Close()
		if _, err := io.Copy(dst, src); err != nil {
			return err
		}
		return dst.Sync()
	}()
	if err != nil {
		os.Remove(final)
		return err
	}
	return nil
}

// ManifestVersion is the completion-manifest format this tool writes.
const ManifestVersion = 1

// ManifestSuffix is appended to a published backup's name to get its
// manifest. It cannot match a published backup name itself, so a manifest
// is never mistaken for a backup.
const ManifestSuffix = ".manifest.json"

// Manifest is the completion record published beside every backup. It is
// the evidence a scheduled run can check without the recovery key: a
// scheduled backup holds only the public key by design (specification:
// "Scheduled backups use only the public key and require no recovery
// passphrase"), so the ciphertext cannot be decrypted or validated, but it
// can be re-hashed and length-checked against this record.
//
// It carries NO secrets: a format version, the deployment that owns the
// backup, the published file name, its byte length, a SHA-256 of exactly
// the published bytes, the encryption mode, and the time. No passphrase,
// no private key, no credential value, and no plaintext database content.
// TestManifestHoldsNoSecrets fails if that ever changes.
type Manifest struct {
	ManifestVersion int       `json:"manifest_version"`
	FormatVersion   int       `json:"format_version"`
	DeploymentID    string    `json:"deployment_id"`
	File            string    `json:"file"`
	Bytes           int64     `json:"bytes"`
	SHA256          string    `json:"sha256"`
	Mode            string    `json:"mode"` // "age" or "none"
	PublishedAt     time.Time `json:"published_at"`
}

// ManifestPath is the manifest beside the published backup dir/name.
func ManifestPath(dir, name string) string {
	return filepath.Join(dir, name+ManifestSuffix)
}

// publishManifest writes the completion manifest for an already-published
// backup.
//
// Ordering, deliberately: the backup file is published first and the
// manifest second. A backup is counted as complete only when its manifest
// verifies, so a crash between the two steps leaves a backup that no run
// counts and no run deletes — it is preserved, exactly like a backup
// belonging to another deployment. The reverse order could not give that:
// a manifest written first would describe a file that does not exist yet,
// and a later backup landing on that name would inherit someone else's
// completion evidence. Losing a little disk to an orphan beats counting an
// unfinished export as a good backup.
func publishManifest(dest, final, mode, deploymentID string) error {
	name := filepath.Base(final)
	n, sum, err := hashFile(final)
	if err != nil {
		return fmt.Errorf("the backup is published at %s but could not be read back to complete it: %w", final, err)
	}
	b, err := json.MarshalIndent(Manifest{
		ManifestVersion: ManifestVersion, FormatVersion: FormatVersion,
		DeploymentID: deploymentID, File: name, Bytes: n, SHA256: sum,
		Mode: mode, PublishedAt: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dest, ".partial-manifest-*")
	if err != nil {
		return manifestFailure(final, err)
	}
	tmp := f.Name()
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, ManifestPath(dest, name))
	}
	if err != nil {
		os.Remove(tmp)
		return manifestFailure(final, err)
	}
	return nil
}

func manifestFailure(final string, err error) error {
	return fmt.Errorf("the backup is published at %s but its completion manifest could not be written: %w; retention will preserve the file and will not count it as a backup", final, err)
}

// ReadManifest returns the manifest published beside dir/name. A missing
// manifest returns an error satisfying errors.Is(err, fs.ErrNotExist), so
// callers can tell "not published by this tool" from "does not match".
func ReadManifest(dir, name string) (Manifest, error) {
	b, err := os.ReadFile(ManifestPath(dir, name))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("%s is not a readable backup manifest: %w", ManifestPath(dir, name), err)
	}
	return m, nil
}

// VerifyPublished proves dir/name is a complete backup by re-hashing and
// length-checking it against its manifest. It needs no key of any kind.
//
// deploymentID scopes the check to one deployment: a shared destination can
// hold another deployment's backups, and those must never be counted or
// expired here. Pass "" to skip the ownership check, which restore does
// deliberately — a replacement host has its own deployment ID and must
// still be able to restore the backup it was given.
//
// The manifest is integrity evidence, not authentication: anything that can
// rewrite a backup can rewrite its manifest. It catches the failures that
// actually happen — a truncated write, a half-copied file, a foreign file
// under a matching name — which is what retention needs.
func VerifyPublished(dir, name, deploymentID string) (Manifest, error) {
	m, err := ReadManifest(dir, name)
	if err != nil {
		return Manifest{}, err
	}
	if m.ManifestVersion != ManifestVersion {
		return m, fmt.Errorf("%s has manifest version %d, which this tool does not understand (supported: %d)", name, m.ManifestVersion, ManifestVersion)
	}
	if m.File != name {
		return m, fmt.Errorf("%s carries a manifest for %q; the file or its manifest was renamed", name, m.File)
	}
	if deploymentID != "" && m.DeploymentID != deploymentID {
		return m, fmt.Errorf("%s belongs to deployment %s, not %s", name, m.DeploymentID, deploymentID)
	}
	n, sum, err := hashFile(filepath.Join(dir, name))
	if err != nil {
		return m, err
	}
	if n != m.Bytes {
		return m, fmt.Errorf("%s is %d bytes but its manifest records %d; the backup is truncated or was replaced", name, n, m.Bytes)
	}
	if sum != m.SHA256 {
		return m, fmt.Errorf("%s does not match the SHA-256 in its manifest; the backup is corrupt or was altered", name)
	}
	return m, nil
}

// hashFile streams the file, returning its length and SHA-256.
func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// Info describes a validated backup file.
type Info struct {
	FormatVersion int
	GuacVersion   string
	Mode          string // "age" or "none"
}

var headerRE = regexp.MustCompile(`^-- guacdeploy backup format=(\d+) guacamole=(\S+) mode=(age|none)$`)

const markerPrefix = "-- guacdeploy dump complete sha256:"

// Encrypted reports whether raw is an age-encrypted backup, by content.
func Encrypted(raw []byte) bool {
	return strings.HasPrefix(string(raw), "age-encryption.org/v1")
}

// Validate checks a backup file completely before any database command may
// run: decryption (when encrypted), the header's format and Guacamole
// version, and the end marker whose sha256 proves the dump is not
// truncated or altered. It returns the SQL to feed to psql. Validate
// issues no commands and touches no database.
func Validate(raw []byte, id *age.X25519Identity, guacVersion string) (string, Info, error) {
	content := string(raw)
	if Encrypted(raw) {
		if id == nil {
			return "", Info{}, fmt.Errorf("the backup is encrypted; recovery needs the backup key")
		}
		var out strings.Builder
		if err := recoverykey.Decrypt(id, strings.NewReader(content), &out); err != nil {
			return "", Info{}, fmt.Errorf("decrypt backup (wrong key, or a damaged file): %w", err)
		}
		content = out.String()
	}

	nl := strings.IndexByte(content, '\n')
	if nl < 0 {
		return "", Info{}, fmt.Errorf("not a guacdeploy backup: no header line")
	}
	m := headerRE.FindStringSubmatch(content[:nl])
	if m == nil {
		return "", Info{}, fmt.Errorf("not a guacdeploy backup: unrecognised header %q", content[:nl])
	}
	info := Info{GuacVersion: m[2], Mode: m[3]}
	fmt.Sscan(m[1], &info.FormatVersion)
	if info.FormatVersion != FormatVersion {
		return "", Info{}, fmt.Errorf("backup format %d is not supported by this tool (supported: %d)", info.FormatVersion, FormatVersion)
	}
	if guacVersion != "" && info.GuacVersion != guacVersion {
		return "", Info{}, fmt.Errorf("the backup is from Guacamole %s but this deployment runs %s; restore it with a matching tool version", info.GuacVersion, guacVersion)
	}

	trimmed := strings.TrimSuffix(content, "\n")
	last := strings.LastIndexByte(trimmed, '\n')
	if !strings.HasSuffix(content, "\n") || last < 0 {
		return "", Info{}, fmt.Errorf("the backup is truncated: no completion marker")
	}
	body, marker := content[:last+1], trimmed[last+1:]
	if !strings.HasPrefix(marker, markerPrefix) {
		return "", Info{}, fmt.Errorf("the backup is truncated or incomplete: the completion marker is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(body))); got != strings.TrimPrefix(marker, markerPrefix) {
		return "", Info{}, fmt.Errorf("the backup content does not match its completion marker; it is truncated or altered")
	}
	return content, info, nil
}

// Apply replaces the database content with a Validate-returned dump. The
// public schema is dropped and recreated, then the dump replays under
// ON_ERROR_STOP. The running guacamole container is not stopped: callers
// must have the operator's acceptance of downtime, and the stack should be
// restarted afterwards so the application reconnects cleanly.
func Apply(ctx context.Context, o Options, sql string) error {
	if _, stderr, err := o.psql(ctx, "DROP SCHEMA public CASCADE;\nCREATE SCHEMA public;\n"); err != nil {
		return fmt.Errorf("resetting the database schema failed: %v\n%s", err, tail(stderr))
	}
	if _, stderr, err := o.psql(ctx, sql); err != nil {
		return fmt.Errorf("restoring the dump failed: %v\n%s", err, tail(stderr))
	}
	return nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if lines := strings.Split(s, "\n"); len(lines) > 12 {
		return strings.Join(lines[len(lines)-12:], "\n")
	}
	return s
}
