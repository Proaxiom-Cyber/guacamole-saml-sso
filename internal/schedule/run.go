package schedule

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
)

// publishedName matches a published backup exactly as internal/backup names
// one. A failed export leaves ".partial-guacdeploy-db-...", whose leading dot
// can never match, so an in-progress or abandoned export is invisible to
// retention by construction.
//
// The timestamp carries milliseconds, and a name collision appends "-N";
// both come from internal/backup's non-overwriting publish. The
// millisecond part stays optional so backups written by an earlier version
// are still recognised, rather than silently becoming unprunable.
var publishedName = regexp.MustCompile(`^guacdeploy-db-\d{8}T\d{6}(\.\d{3})?Z(-\d+)?\.sql(\.age)?$`)

// Valid reports whether dir/name is a complete, published backup.
//
// Plaintext backups are checked in full with backup.Validate: the header and
// the sha256 completion marker prove the dump is neither truncated nor
// altered. Encrypted backups cannot be checked that way, because a scheduled
// run holds only the public key (specification: "Scheduled backups use only
// the public key and require no recovery passphrase"). For those, the
// evidence is the publish contract itself: internal/backup writes to
// ".partial-" and renames to the final name only after a complete, verified
// export, so a file under the published name exists only if the export
// finished. The age header is checked as a cheap guard against a truncated
// or foreign file sitting under a matching name.
//
// ponytail: reads the whole file to check it. The Guacamole database is
// small. Stream the header and tail instead if backups ever grow large.
func Valid(dir, name string) bool {
	if !publishedName.MatchString(name) {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return false
	}
	if strings.HasSuffix(name, ".age") {
		return backup.Encrypted(raw)
	}
	if backup.Encrypted(raw) {
		return false // encrypted content under a plaintext name: not what it claims
	}
	_, _, err = backup.Validate(raw, nil, "")
	return err == nil
}

// List returns the valid published backups in dir, newest first. The names
// carry a fixed-width UTC timestamp, so lexical order is chronological order.
func List(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && Valid(dir, e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// Prune deletes valid backups beyond the newest keep. It only ever considers
// files that passed Valid, so a partial export never displaces a real backup,
// and it only ever deletes from position keep onwards, so keep backups always
// survive and the destination is never emptied. Callers must not run Prune
// after a failed backup: a failed export must not expire earlier ones.
func Prune(dir string, keep int) ([]string, error) {
	if keep < 1 {
		return nil, fmt.Errorf("retention must keep at least one backup, got %d", keep)
	}
	names, err := List(dir)
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
		removed = append(removed, p)
	}
	return removed, nil
}

// RequireMount fails when dir is not itself a mount point. A share that is
// not mounted leaves its mount-point directory present but on the host's own
// filesystem, so a plain existence check would let the backup land silently
// in local storage. Comparing the device of dir with the device of its
// parent detects exactly that.
func RequireMount(dir string) error {
	var d, parent syscall.Stat_t
	if err := syscall.Stat(dir, &d); err != nil {
		return fmt.Errorf("backup destination %s cannot be inspected: %w; nothing was exported", dir, err)
	}
	if err := syscall.Stat(filepath.Dir(dir), &parent); err != nil {
		return fmt.Errorf("backup destination %s cannot be inspected: %w; nothing was exported", dir, err)
	}
	if d.Dev == parent.Dev {
		return fmt.Errorf("backup destination %s is not a mount point: the expected share is not mounted; nothing was exported, and the backup was not redirected into local storage", dir)
	}
	return nil
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
	s := Status{Ran: time.Now().UTC(), Destination: o.Dest, Keep: o.Keep,
		OnCalendar: o.OnCalendar, RequireMount: o.RequireMount}

	fail := func(err error) (Status, error) {
		s.Result = "failed"
		s.Error = err.Error()
		s.Kept = len(mustList(o.Dest))
		if werr := WriteStatus(o.StateDir, s); werr != nil {
			return s, fmt.Errorf("%v (and the status file could not be written: %v)", err, werr)
		}
		return s, err
	}

	if o.RequireMount {
		if err := RequireMount(o.Dest); err != nil {
			return fail(err)
		}
	}
	path, err := do(ctx)
	if err != nil {
		return fail(err)
	}

	s.Result, s.Published = "ok", path
	removed, perr := Prune(o.Dest, o.Keep)
	s.Removed = removed
	s.Kept = len(mustList(o.Dest))
	if perr != nil {
		s.Error = perr.Error()
	}
	if werr := WriteStatus(o.StateDir, s); werr != nil {
		return s, werr
	}
	return s, perr
}

func mustList(dir string) []string {
	names, _ := List(dir)
	return names
}
