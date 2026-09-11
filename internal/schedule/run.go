package schedule

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
)

// publishedName matches a published backup exactly as internal/backup names
// one, and captures the parts that order it. A failed export leaves
// ".partial-guacdeploy-db-...", whose leading dot can never match, so an
// in-progress or abandoned export is invisible to retention by construction.
//
// The timestamp carries milliseconds, and a name collision appends "-N";
// both come from internal/backup's non-overwriting publish. The
// millisecond part stays optional so backups written by an earlier version
// (\d{8}T\d{6}Z) are still recognised, rather than silently becoming
// unprunable.
var publishedName = regexp.MustCompile(`^guacdeploy-db-(\d{8}T\d{6})(\.\d{3})?Z(?:-(\d+))?\.sql(?:\.age)?$`)

// published is a backup name parsed into the values that order it.
type published struct {
	name string
	at   time.Time
	seq  int // the "-N" collision suffix; 0 when there is none
}

// parsePublished reads the timestamp and collision suffix out of a name.
//
// Both have to be parsed rather than compared as text. Sorting the names
// themselves gets the order wrong twice: at an identical timestamp the
// unsuffixed name sorts before its "-1" sibling although the sibling is the
// newer backup (publish takes the unsuffixed name first and only then "-1"),
// and a text sort puts "-10" between "-1" and "-2". Either way retention
// would expire a newer backup and keep an older one.
func parsePublished(name string) (published, bool) {
	m := publishedName.FindStringSubmatch(name)
	if m == nil {
		return published{}, false
	}
	layout, stamp := "20060102T150405", m[1]
	if m[2] != "" {
		layout, stamp = "20060102T150405.000", m[1]+m[2]
	}
	at, err := time.Parse(layout, stamp)
	if err != nil {
		return published{}, false
	}
	seq := 0
	if m[3] != "" {
		if seq, err = strconv.Atoi(m[3]); err != nil {
			return published{}, false
		}
	}
	return published{name: name, at: at.UTC(), seq: seq}, true
}

// newer reports whether a is the more recent backup: later timestamp first,
// then the higher collision suffix, because publish only reaches "-N+1"
// after "-N" is taken.
//
// The tie-break is the name in reverse order. It is only reachable between a
// ".sql" and a ".sql.age" written in the same millisecond under the same
// suffix, which publish cannot produce in one run; it exists so the order is
// total and stable rather than dependent on directory order.
func (a published) newer(b published) bool {
	if !a.at.Equal(b.at) {
		return a.at.After(b.at)
	}
	if a.seq != b.seq {
		return a.seq > b.seq
	}
	return a.name > b.name
}

// Valid reports whether dir/name is a complete backup published by this
// deployment.
//
// The evidence is the completion manifest internal/backup publishes beside
// every backup: re-hashing and length-checking the file against it proves
// the export finished and was not truncated, corrupted, or replaced, and
// the deployment ID in it proves the backup is ours. None of that needs the
// recovery key, which a scheduled run deliberately does not hold.
//
// Anything that fails is not ours to touch: a backup from another
// deployment sharing the destination, a file with no manifest, a half-copied
// file. Prune only ever deletes what Valid accepts, so all of those are
// preserved.
func Valid(dir, name, deploymentID string) bool {
	if _, ok := parsePublished(name); !ok {
		return false
	}
	_, err := backup.VerifyPublished(dir, name, deploymentID)
	return err == nil
}

// List returns this deployment's valid published backups in dir, newest
// first, ordered by timestamp and then by collision suffix.
func List(dir, deploymentID string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var found []published
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p, ok := parsePublished(e.Name())
		if !ok {
			continue
		}
		if _, err := backup.VerifyPublished(dir, e.Name(), deploymentID); err != nil {
			continue
		}
		found = append(found, p)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].newer(found[j]) })
	names := make([]string, 0, len(found))
	for _, p := range found {
		names = append(names, p.name)
	}
	return names, nil
}

// Prune deletes valid backups beyond the newest keep, with each backup's
// manifest. It only ever considers files that passed Valid, so a partial
// export, a foreign deployment's backup, or anything else in a shared
// destination never displaces a real backup and is never deleted. It only
// ever deletes from position keep onwards, so keep backups always survive
// and the destination is never emptied. Callers must not run Prune after a
// failed backup: a failed export must not expire earlier ones.
func Prune(dir string, keep int, deploymentID string) ([]string, error) {
	if keep < 1 {
		return nil, fmt.Errorf("retention must keep at least one backup, got %d", keep)
	}
	names, err := List(dir, deploymentID)
	if err != nil {
		return nil, err
	}
	if len(names) <= keep {
		return nil, nil
	}
	var removed []string
	for _, n := range names[keep:] {
		p := filepath.Join(dir, n)
		if err := os.Remove(p); err != nil {
			return removed, fmt.Errorf("expire old backup %s: %w", p, err)
		}
		// The manifest goes with its backup. A manifest left behind would
		// describe a file that no longer exists.
		if err := os.Remove(backup.ManifestPath(dir, n)); err != nil && !os.IsNotExist(err) {
			return removed, fmt.Errorf("expire old backup manifest for %s: %w", p, err)
		}
		removed = append(removed, p)
	}
	return removed, nil
}

// statDev returns the filesystem device of path. It is a variable because a
// unit test cannot mount a share; the tests replace it to simulate a mount
// appearing, disappearing, and being replaced.
var statDev = func(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

// mountPointOf walks up from path to the directory where the filesystem
// changes: the mount point path sits on. That is the whole point of the
// walk — a backup destination is normally a subfolder inside a share
// (/mnt/backups/guacamole), not the mount point itself, and comparing only
// with the immediate parent rejected every such destination.
func mountPointOf(path string) (string, error) {
	path = filepath.Clean(path)
	dev, err := statDev(path)
	if err != nil {
		return "", err
	}
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return path, nil // the root of the tree
		}
		pdev, err := statDev(parent)
		if err != nil {
			return "", err
		}
		if pdev != dev {
			return path, nil
		}
		path = parent
	}
}

// mountMarkerFile identifies the filesystem the destination is on. It lives
// on the share itself, holds a random non-secret tag, and survives an
// ordinary unmount and remount — which the device number does not, so the
// device number is never recorded.
const mountMarkerFile = ".guacdeploy-backup-mount"

// mountRecord is the approved destination mount. Non-secret: two paths and
// a random tag.
type mountRecord struct {
	Dest       string `json:"dest"`
	MountPoint string `json:"mount_point"`
	Marker     string `json:"marker"`
}

// MountRecordPath is the approved-mount record, beside the last-run record.
func MountRecordPath(stateDir string) string {
	return filepath.Join(stateDir, "backup-mount.json")
}

// RequireMount checks that dest is still on the mounted share it was
// approved on. "A missing mount must fail visibly instead of redirecting
// output to local storage" (specification).
//
// The first checked run records the mount: the mount point dest sits inside,
// and a marker file written on the share. It refuses to record a destination
// on the same filesystem as the deployment's own state directory, because
// that is local storage, not a share — that is the case where the mount
// point directory exists but holds no mount.
//
// Every later run compares. The expected mount disappearing (dest is now on
// some other filesystem, usually the root one) and the expected mount being
// replaced (the marker on the share is gone or different) both fail here,
// before any export.
func RequireMount(stateDir, dest string) error {
	if fi, err := os.Stat(dest); err != nil || !fi.IsDir() {
		return fmt.Errorf("backup destination %s is not an existing directory: the expected share is not mounted; nothing was exported, and the backup was not redirected into local storage", dest)
	}
	mp, err := mountPointOf(dest)
	if err != nil {
		return fmt.Errorf("backup destination %s cannot be inspected: %w; nothing was exported", dest, err)
	}

	rec, err := readMountRecord(stateDir)
	if err != nil {
		return err
	}
	if rec == nil || rec.Dest != filepath.Clean(dest) {
		// No approved mount yet, or the administrator changed --dest: this
		// run approves what is there now.
		return recordMount(stateDir, filepath.Clean(dest), mp)
	}
	if mp != rec.MountPoint {
		return fmt.Errorf("backup destination %s is no longer inside the approved mount %s (it is now on %s): the expected share is not mounted; nothing was exported, and the backup was not redirected into local storage", dest, rec.MountPoint, mp)
	}
	got, err := os.ReadFile(filepath.Join(dest, mountMarkerFile))
	if err != nil || strings.TrimSpace(string(got)) != rec.Marker {
		return fmt.Errorf("the filesystem mounted at %s is not the one approved for backups: the %s marker is missing or different, so the expected share is not mounted; nothing was exported, and the backup was not redirected into local storage. If the share was replaced deliberately, delete %s to approve the new one",
			rec.MountPoint, mountMarkerFile, MountRecordPath(stateDir))
	}
	return nil
}

func recordMount(stateDir, dest, mountPoint string) error {
	sdev, err := statDev(stateDir)
	if err != nil {
		return fmt.Errorf("state directory %s cannot be inspected: %w; nothing was exported", stateDir, err)
	}
	ddev, err := statDev(dest)
	if err != nil {
		return fmt.Errorf("backup destination %s cannot be inspected: %w; nothing was exported", dest, err)
	}
	if sdev == ddev {
		return fmt.Errorf("backup destination %s is not a mount point and is not inside one: it is on the same filesystem as %s, so the expected share is not mounted; nothing was exported, and the backup was not redirected into local storage", dest, stateDir)
	}
	marker, err := readOrCreateMarker(dest)
	if err != nil {
		return fmt.Errorf("backup destination %s cannot be marked: %w; nothing was exported", dest, err)
	}
	b, err := json.MarshalIndent(mountRecord{Dest: dest, MountPoint: mountPoint, Marker: marker}, "", "  ")
	if err != nil {
		return err
	}
	path := MountRecordPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readMountRecord(stateDir string) (*mountRecord, error) {
	b, err := os.ReadFile(MountRecordPath(stateDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r mountRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s is not readable JSON: %w", MountRecordPath(stateDir), err)
	}
	return &r, nil
}

// readOrCreateMarker returns the share's tag, creating it when the share has
// none. An existing tag is kept, so two deployments writing to the same
// share agree on the same identity.
func readOrCreateMarker(dest string) (string, error) {
	path := filepath.Join(dest, mountMarkerFile)
	read := func() (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if s, err := read(); err == nil && s != "" {
		return s, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tag := hex.EncodeToString(buf)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return read() // another deployment marked the share first
	}
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(tag + "\n")
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return tag, nil
}

// Status is the last-run record. It holds paths, counts and error text only:
// no credential ever passes through this package, and the backup commands
// authenticate over the container's local socket rather than on a command
// line, so no failure message can carry one.
type Status struct {
	Ran          time.Time `json:"ran"`
	Result       string    `json:"result"` // "ok" or "failed"
	Destination  string    `json:"destination"`
	Published    string    `json:"published,omitempty"`
	Error        string    `json:"error,omitempty"`
	Removed      []string  `json:"removed,omitempty"`
	Kept         int       `json:"kept"`
	Keep         int       `json:"keep"`
	OnCalendar   string    `json:"on_calendar,omitempty"`
	RequireMount bool      `json:"require_mount,omitempty"`
}

// StatusPath is the last-run file, beside the state file but not in it: the
// deployment record is the parent's schema and is not churned by a nightly
// timer.
func StatusPath(stateDir string) string { return filepath.Join(stateDir, "backup-status.json") }

// WriteStatus saves the last-run record with owner-only permissions, through
// a temporary file and a rename so an interrupted write cannot leave an
// unreadable record.
func WriteStatus(stateDir string, s Status) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := StatusPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// ReadStatus returns the last-run record, or nil when no scheduled backup
// has run yet.
func ReadStatus(stateDir string) (*Status, error) {
	b, err := os.ReadFile(StatusPath(stateDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is not readable JSON: %w", StatusPath(stateDir), err)
	}
	return &s, nil
}

// Summary renders the last-run record for an operator.
func (s Status) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backup destination: %s\n", s.Destination)
	if s.OnCalendar != "" {
		fmt.Fprintf(&b, "Schedule:           %s (keep %d successful backups)\n", s.OnCalendar, s.Keep)
	}
	fmt.Fprintf(&b, "Last run:           %s  %s\n", s.Ran.Format(time.RFC3339), s.Result)
	if s.Published != "" {
		fmt.Fprintf(&b, "Published:          %s\n", s.Published)
	}
	if s.Error != "" {
		fmt.Fprintf(&b, "Reason:             %s\n", strings.TrimSpace(s.Error))
	}
	fmt.Fprintf(&b, "Valid backups kept: %d\n", s.Kept)
	for _, r := range s.Removed {
		fmt.Fprintf(&b, "Expired:            %s\n", r)
	}
	return b.String()
}

// Summary reads the last-run record and renders it, for the status command.
func Summary(stateDir string) string {
	s, err := ReadStatus(stateDir)
	if err != nil {
		return fmt.Sprintf("Scheduled backup status is unreadable: %v\n", err)
	}
	if s == nil {
		return "No scheduled backup has run yet.\n"
	}
	return s.Summary()
}

// RunBackup is the whole scheduled run: check the destination, take the
// backup through do, then expire old backups, and record the outcome either
// way. do returns the published path.
//
// A failed backup performs no deletion at all: RunBackup records the failure
// and returns before Prune. Retention runs only after a published backup.
//
// A retention failure after a published backup keeps Result "ok", because
// the backup really is published, but it is recorded and returned so the run
// exits nonzero and the administrator sees it.
func RunBackup(ctx context.Context, o Options, do func(context.Context) (string, error)) (Status, error) {
	if err := o.defaults(); err != nil {
		return Status{}, err
	}
	// Retention is scoped to this deployment, so it needs the ID. Without
	// it nothing would verify as ours, retention would silently stop, and
	// backups would grow without limit.
	if o.DeploymentID == "" {
		return Status{}, fmt.Errorf("a scheduled backup needs the deployment ID to know which backups are its own")
	}
	s := Status{Ran: time.Now().UTC(), Destination: o.Dest, Keep: o.Keep,
		OnCalendar: o.OnCalendar, RequireMount: o.RequireMount}

	fail := func(err error) (Status, error) {
		s.Result = "failed"
		s.Error = err.Error()
		s.Kept = len(mustList(o.Dest, o.DeploymentID))
		if werr := WriteStatus(o.StateDir, s); werr != nil {
			return s, fmt.Errorf("%v (and the status file could not be written: %v)", err, werr)
		}
		return s, err
	}

	if o.RequireMount {
		if err := RequireMount(o.StateDir, o.Dest); err != nil {
			return fail(err)
		}
	}
	path, err := do(ctx)
	if err != nil {
		return fail(err)
	}

	s.Result, s.Published = "ok", path
	removed, perr := Prune(o.Dest, o.Keep, o.DeploymentID)
	s.Removed = removed
	s.Kept = len(mustList(o.Dest, o.DeploymentID))
	if perr != nil {
		s.Error = perr.Error()
	}
	if werr := WriteStatus(o.StateDir, s); werr != nil {
		return s, werr
	}
	return s, perr
}

func mustList(dir, deploymentID string) []string {
	names, _ := List(dir, deploymentID)
	return names
}
