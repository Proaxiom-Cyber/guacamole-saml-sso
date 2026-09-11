// Package recording turns on Guacamole session recording, backs up
// completed recordings beside the database backup, and keeps the local
// recordings directory inside the administrator's storage budget.
//
// Three facts shape everything here.
//
// First, guacd writes the recording, not the web application. The recording
// path in a connection's parameters is resolved inside the guacd container,
// so it is the container path (ContainerPath), never a host path.
//
// Second, a recording is only complete when its session ends. guacd appends
// to the file for the whole session, so a file that is still open is an
// active recording and must never be backed up, counted as backed up, or
// deleted. Completeness is decided by OpenFiles; see its documentation for
// why "still held open" was chosen over a quiet period.
//
// Third, the local storage budget wins over preserving unbacked recordings
// (specification, "Local recording retention"). Cleanup deletes the oldest
// completed recordings even when their upload failed, and reports every
// deletion that had no confirmed remote copy, because that deletion can
// permanently lose a recording.
//
// This package is self-contained: it imports internal/backup (for the
// published-completion contract it reuses) and internal/recoverykey (for the
// selected encryption mode) and nothing else from the deployment. The parent
// wires it in; see WIRING.md.
package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recoverykey"
)

// FormatVersion is the recording-backup format this tool writes.
const FormatVersion = 1

const (
	// DirName is the recordings directory under the installation directory,
	// and the subdirectory of the backup destination that receives copies.
	DirName = "recordings"

	// ContainerPath is where the recordings directory is mounted inside both
	// guacd (read-write) and the Guacamole web application (read-only). A
	// connection's recording-path parameter is resolved by guacd, so this is
	// the value that goes into the database.
	ContainerPath = "/recordings"

	// Ext marks a published recording copy. It cannot collide with a
	// database backup name or with a completion manifest, so one destination
	// can hold all three.
	Ext = ".guac"

	// GuacdUID and GuacdGID are the user the guacamole/guacd image runs as.
	// The image drops to this account, so a bind mount it must write into
	// has to be owned by it.
	GuacdUID = 1000
	GuacdGID = 1000
)

// Dir is the recordings directory under the installation directory.
func Dir(installDir string) string { return filepath.Join(installDir, DirName) }

// DestDir is the recordings subdirectory of a backup destination.
func DestDir(dest string) string { return filepath.Join(dest, DirName) }

// chownDir is os.Chown, replaced in tests: a unit test does not run as root
// and cannot give a directory away to another user.
var chownDir = os.Chown

// EnsureDirs creates the recordings directory under installDir, ready for
// guacd to write into.
//
// Mode 0755 follows the convention stack.Render uses for every bind mount a
// container reads: a bind mount exposes the directory's own mode to the
// container, and the container processes are not root. Confidentiality does
// not come from this mode — it comes from the installation root, which
// Render creates 0750, so no other host account can even traverse into here.
// The mode also keeps SELinux out of the picture as a permissions question:
// the compose file labels the mount, and a 0755 directory needs no extra
// host rule.
//
// Ownership is the part a read-only mount does not need: guacd writes here,
// and the guacamole/guacd image runs as uid 1000, so a root-owned directory
// would leave guacd unable to create a single recording — while the session
// itself still succeeds. That is a silent failure, which is why this is an
// explicit step rather than something Docker is left to do. Docker creates a
// missing bind-mount source as root-owned 0755, which is exactly that
// failure.
//
// It is idempotent: a directory already owned by the guacd account is left
// alone, so a re-run that is not root still succeeds.
func EnsureDirs(installDir string) error {
	p := Dir(installDir)
	if err := os.MkdirAll(p, 0o755); err != nil {
		return fmt.Errorf("create the recordings directory %s: %w", p, err)
	}
	if err := os.Chmod(p, 0o755); err != nil { // repair an earlier render
		return fmt.Errorf("set permissions on the recordings directory %s: %w", p, err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == GuacdUID {
		return nil
	}
	if err := chownDir(p, GuacdUID, GuacdGID); err != nil {
		return fmt.Errorf("give the recordings directory %s to the guacd container account (uid %d): %w; without it guacd cannot write recordings and sessions would be unrecorded without failing", p, GuacdUID, err)
	}
	return nil
}

// Params are the connection parameters that turn recording on. They are
// Guacamole connection parameters, not credentials: recording-path and
// recording-name say where guacd writes, create-recording-path lets guacd
// create the per-deployment directory. Nothing here is, or can become, a
// target password or private key, so the "no stored target credentials"
// model is unchanged.
//
// recording-name is ${HISTORY_UUID} because that is the token Guacamole
// substitutes with the connection-history identifier. Naming the file after
// it is what lets a recording be matched back to the session that produced
// it, in the database and in the web interface.
func Params() map[string]string {
	return map[string]string{
		"recording-path":        ContainerPath,
		"recording-name":        "${HISTORY_UUID}",
		"create-recording-path": "true",
	}
}

// EnableSQL returns the statement that turns recording on for every
// connection, or for one named connection when connection is not empty.
//
// It touches only the three recording parameters. It never reads, writes or
// copies a password, a private key, or any other connection parameter, so
// running it cannot introduce a stored target credential.
//
// Existing connections are updated in place, which is the answer to "how do
// I get recording on the connections I already have": the parameters live in
// the database, not in a rendered file, so there is nothing to re-render.
func EnableSQL(connection string) string {
	var b strings.Builder
	b.WriteString("INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)\nSELECT c.connection_id, p.name, p.value\nFROM guacamole_connection c\nCROSS JOIN (VALUES\n")
	names := make([]string, 0, len(Params()))
	for k := range Params() {
		names = append(names, k)
	}
	sort.Strings(names)
	for i, n := range names {
		sep := ","
		if i == len(names)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "    (%s, %s)%s\n", quote(n), quote(Params()[n]), sep)
	}
	b.WriteString(") AS p(name, value)\n")
	if connection != "" {
		fmt.Fprintf(&b, "WHERE c.connection_name = %s\n", quote(connection))
	}
	b.WriteString("ON CONFLICT (connection_id, parameter_name)\nDO UPDATE SET parameter_value = EXCLUDED.parameter_value;\n")
	return b.String()
}

// quote renders a SQL string literal, doubling any embedded quote. A
// connection name comes from the operator, so it is never pasted in raw.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Enable applies EnableSQL through the running stack's postgres container.
// It creates the recordings directory first, so an operator who enables
// recording on a deployment set up before this slice does not end up with
// connections that record into a directory guacd cannot write.
func Enable(ctx context.Context, run backup.Runner, installDir, connection string) error {
	if err := EnsureDirs(installDir); err != nil {
		return err
	}
	_, stderr, err := run(ctx, EnableSQL(connection), "docker", "compose",
		"--project-directory", installDir,
		"--env-file", filepath.Join(installDir, ".env"),
		"-f", filepath.Join(installDir, "compose.yaml"),
		"exec", "-T", "postgres",
		"psql", "-v", "ON_ERROR_STOP=1", "-q", "-U", "guacamole_user", "-d", "guacamole_db")
	if err != nil {
		return fmt.Errorf("enabling session recording failed: %v\n%s", err, strings.TrimSpace(stderr))
	}
	return nil
}

// FileID identifies a file by device and inode, independently of any path.
// That is what makes the open-file check work across a container boundary:
// guacd sees the recording as /recordings/<uuid> in its own mount namespace
// and this process sees it as <install-dir>/recordings/<uuid>, but both are
// the same inode.
type FileID struct{ Dev, Ino uint64 }

// OpenFiles reports every file some process on this host currently holds
// open. It is the completeness test, and it is a variable-shaped seam so a
// unit test can decide which recordings are active without running guacd.
//
// Why "still held open" rather than "unchanged for a quiet period": the
// question that matters is whether guacd is still writing, and this answers
// it directly instead of guessing from a proxy. A quiet period misjudges the
// one case that loses evidence — a long idle session that writes nothing for
// the whole period is declared complete, backed up half-finished, and then
// eligible for deletion while it is still recording. An open descriptor
// cannot be idle away.
//
// The ceiling, stated plainly: it requires the writer to run on this host
// and /proc to be readable, which holds for the V1 deployment (guacd is a
// container on the same host, and the cleanup timer runs as root). Where it
// does not hold, ProcOpenFiles returns an error and Scan fails rather than
// guessing — nothing is backed up and nothing is deleted, which is the safe
// direction. A recording left open by a crashed guacd never becomes
// complete; it is preserved, and the operator guide says how to clear it.
type OpenFiles func() (map[FileID]struct{}, error)

// ProcOpenFiles is the real completeness seam: every open descriptor of
// every process on this host, as device and inode pairs.
//
// This process is skipped. It opens each recording itself while copying one
// to the backup destination, and counting that would make a recording look
// active for exactly as long as it takes to back it up.
func ProcOpenFiles() (map[FileID]struct{}, error) {
	const proc = "/proc"
	procs, err := os.ReadDir(proc)
	if err != nil {
		return nil, fmt.Errorf("%s is not readable, so there is no way to tell which recordings are still being written: %w", proc, err)
	}
	self := strconv.Itoa(os.Getpid())
	out := map[FileID]struct{}{}
	seen := 0
	for _, p := range procs {
		if !p.IsDir() || p.Name() == self {
			continue
		}
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		seen++
		fdDir := filepath.Join(proc, p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // the process exited, or holds no inspectable descriptors
		}
		for _, fd := range fds {
			// Stat follows the descriptor link to the file itself, so the
			// path it resolves to inside another mount namespace does not
			// matter: the device and inode are the same file.
			fi, err := os.Stat(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if id, ok := fileID(fi); ok {
				out[id] = struct{}{}
			}
		}
	}
	if seen == 0 {
		return nil, fmt.Errorf("%s lists no processes, so there is no way to tell which recordings are still being written", proc)
	}
	return out, nil
}

func fileID(fi os.FileInfo) (FileID, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return FileID{}, false
	}
	return FileID{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}

// Recording is one file in the local recordings directory.
type Recording struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
	Active  bool // guacd is still writing it
}

// Scan lists the local recordings, oldest first, marking the active ones.
//
// A file whose identity cannot be established is marked active. Unknown must
// never mean complete: a complete recording is copied away and then becomes
// eligible for deletion, and neither may happen to a session in progress.
func Scan(dir string, open OpenFiles) ([]Recording, error) {
	if open == nil {
		open = ProcOpenFiles
	}
	ids, err := open()
	if err != nil {
		return nil, fmt.Errorf("%w; no recording was treated as complete, so none was backed up or deleted", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read the recordings directory %s: %w", dir, err)
	}
	var recs []Recording
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue // it went away between the listing and the stat
		}
		r := Recording{Name: e.Name(), Path: filepath.Join(dir, e.Name()),
			Size: fi.Size(), ModTime: fi.ModTime()}
		id, ok := fileID(fi)
		_, held := ids[id]
		r.Active = !ok || held
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool {
		if !recs[i].ModTime.Equal(recs[j].ModTime) {
			return recs[i].ModTime.Before(recs[j].ModTime)
		}
		return recs[i].Name < recs[j].Name
	})
	return recs, nil
}

// ext is the published extension for the selected protection mode.
func ext(plaintext bool) string {
	if plaintext {
		return Ext
	}
	return Ext + ".age"
}

// publishedCopy returns the published copy of one recording in dest, if a
// complete one is already there.
//
// Names are enumerated rather than parsed. A published copy is
// "<name><ext>", and a collision takes "<name>-1<ext>" and onwards, exactly
// as internal/backup names a colliding backup. Parsing that suffix back out
// of a name is not safe here: a recording is named after its history UUID,
// and a UUID can end in "-000000000001", which no pattern can tell apart
// from a collision suffix. Enumerating asks the question the other way round
// and cannot be confused.
//
// present is one listing of dest, so this costs no syscalls per candidate.
// The loop stops at the first name that is not there, because publishing
// fills the names in order.
func publishedCopy(dest, name, e, deploymentID string, present map[string]bool) (string, bool) {
	for i := 0; i <= 100; i++ {
		cand := name + e
		if i > 0 {
			cand = fmt.Sprintf("%s-%d%s", name, i, e)
		}
		if !present[cand] {
			return "", false
		}
		if _, err := backup.VerifyPublished(dest, cand, deploymentID); err == nil {
			return cand, true
		}
	}
	return "", false
}

// publish copies one recording into dest under a name that is never already
// taken, then writes its completion manifest. It returns the published name.
//
// The bytes go straight into the final name, claimed with O_EXCL, rather
// than through a temporary file: the source is already a finished file on
// disk, so the two-step publish internal/backup needs (it builds its content
// in memory first) would only buy a second full copy of what can be a large
// recording. The guarantee is the same one, and comes from the manifest: a
// copy that fails removes the name it reserved, and a name that somehow
// survives a power loss carries no manifest, so it never verifies, is never
// counted as a backed-up copy, and never stops the next run from publishing.
// Nothing is ever overwritten.
func publish(src, dest, name, e, publicKey string, plaintext bool, deploymentID string, present map[string]bool) (string, error) {
	for i := 0; i <= 100; i++ {
		final := name + e
		if i > 0 {
			final = fmt.Sprintf("%s-%d%s", name, i, e)
		}
		path := filepath.Join(dest, final)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		err = func() error {
			defer f.Close()
			in, err := os.Open(src)
			if err != nil {
				return err
			}
			defer in.Close()
			if plaintext {
				_, err = io.Copy(f, in)
			} else {
				err = recoverykey.EncryptTo(publicKey, in, f)
			}
			if err != nil {
				return err
			}
			return f.Sync()
		}()
		if err != nil {
			os.Remove(path)
			return "", err
		}
		mode := "age"
		if plaintext {
			mode = "none"
		}
		if err := writeManifest(dest, final, mode, deploymentID); err != nil {
			// The copy is on disk but nothing records it as complete, so it
			// is not a backup: it will not verify, it is not reported as
			// included, and the next run publishes the recording again.
			return "", err
		}
		present[final] = true
		return final, nil
	}
	return "", fmt.Errorf("too many copies of %s already exist in %s", name, dest)
}

// writeManifest publishes the completion record beside a copied recording.
//
// It is the same contract internal/backup publishes beside a database
// backup, and it is read back with backup.VerifyPublished: the copy is
// counted as complete only when re-hashing and length-checking it against
// this record succeeds. The file is written after the copy, never before,
// for the reason internal/backup gives: a manifest written first would
// describe a file that does not exist yet.
//
// The copy is re-read rather than hashed on the way out, so the record
// describes the bytes that are actually on the destination.
func writeManifest(dest, final, mode, deploymentID string) error {
	n, sum, err := hashFile(filepath.Join(dest, final))
	if err != nil {
		return fmt.Errorf("the recording copy %s could not be read back to complete it: %w", final, err)
	}
	b, err := json.MarshalIndent(backup.Manifest{
		ManifestVersion: backup.ManifestVersion, FormatVersion: FormatVersion,
		DeploymentID: deploymentID, File: final, Bytes: n, SHA256: sum,
		Mode: mode, PublishedAt: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dest, ".partial-manifest-*")
	if err != nil {
		return err
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
		err = os.Rename(tmp, backup.ManifestPath(dest, final))
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("the recording copy %s has no completion record, so it does not count as backed up: %w", final, err)
	}
	return nil
}

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

// Restore writes one published recording copy back out as a playable file.
// It verifies the completion manifest first, so a copy that is truncated or
// does not belong to this deployment is refused before anything is written.
// id may be nil for a plaintext copy.
func Restore(dir, name, out string, id *age.X25519Identity, deploymentID string) error {
	if _, err := backup.VerifyPublished(dir, name, deploymentID); err != nil {
		return err
	}
	src, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w (an existing file is never replaced)", out, err)
	}
	defer dst.Close()
	if strings.HasSuffix(name, ".age") {
		if id == nil {
			return fmt.Errorf("%s is encrypted; recovery needs the backup key", name)
		}
		if err := recoverykey.Decrypt(id, src, dst); err != nil {
			os.Remove(out)
			return fmt.Errorf("decrypt %s (wrong key, or a damaged file): %w", name, err)
		}
	} else if _, err := io.Copy(dst, src); err != nil {
		os.Remove(out)
		return err
	}
	return dst.Sync()
}
