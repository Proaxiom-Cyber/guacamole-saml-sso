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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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

	name := "guacdeploy-db-" + time.Now().UTC().Format("20060102T150405Z") + ext
	partial := filepath.Join(o.Dest, ".partial-"+name)
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("backup destination %s is not writable: %w; nothing was exported", o.Dest, err)
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
	final := filepath.Join(o.Dest, name)
	if err := os.Rename(partial, final); err != nil {
		return "", fmt.Errorf("publishing the backup failed: %w", err)
	}
	if d, err := os.Open(o.Dest); err == nil {
		d.Sync()
		d.Close()
	}
	return final, nil
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
