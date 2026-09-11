package recording

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options configures one recording run: back up the completed recordings
// to the selected destination.
type Options struct {
	Dir          string // local recordings directory, <install-dir>/recordings
	Dest         string // backup destination root; "" backs nothing up
	StateDir     string // where the last-run record is written
	DeploymentID string
	Plaintext    bool // explicit choice; encryption is the default
	PublicKey    string

	// Open decides which recordings are still being written. nil means
	// ProcOpenFiles. Tests replace it.
	Open OpenFiles
	// Now supplies the run timestamp; nil means time.Now.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Failure is one recording that could not be copied. It is never reported as
// included, and never reported as complete.
type Failure struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Report is the result of one run. Database and recording results are kept
// apart deliberately: this record covers recordings only, and the scheduled
// database backup keeps its own (specification: "Report database and
// recording results separately").
type Report struct {
	Ran        time.Time `json:"ran"`
	Result     string    `json:"result"` // "ok" or "failed"
	Dir        string    `json:"dir"`
	Dest       string    `json:"dest,omitempty"`
	UsedBefore int64     `json:"used_before"`
	UsedAfter  int64     `json:"used_after"`

	// Included is every completed recording this run copied and completed.
	// A name reaches it only after its completion manifest is written.
	Included []string `json:"included,omitempty"`
	// AlreadyBackedUp is every completed recording whose copy was already
	// published and still verifies.
	AlreadyBackedUp []string `json:"already_backed_up,omitempty"`
	// Active is every recording excluded because guacd is still writing it.
	Active []string `json:"active,omitempty"`
	// Failed is every recording whose copy failed. Nothing was published
	// for these.
	Failed []Failure `json:"failed,omitempty"`

	Error      string `json:"error,omitempty"`
	OnCalendar string `json:"on_calendar,omitempty"`
}

// Run is the whole run: scan once, then back up every completed recording
// the destination does not already hold.
//
// Scanning once, before anything is copied, is what keeps an active
// recording active for the whole run.
func Run(o Options) (Report, error) {
	rep := Report{Ran: o.now().UTC(), Result: "ok", Dir: o.Dir, Dest: o.Dest}
	if o.DeploymentID == "" {
		return rep, fmt.Errorf("a recording run needs the deployment ID to know which copies are its own")
	}

	recs, err := Scan(o.Dir, o.Open)
	if err != nil {
		return o.fail(rep, err)
	}
	for _, r := range recs {
		rep.UsedBefore += r.Size
		if r.Active {
			rep.Active = append(rep.Active, r.Name)
		}
	}
	rep.UsedAfter = rep.UsedBefore

	if o.Dest != "" {
		if _, err := o.backUp(recs, &rep); err != nil {
			return o.fail(rep, err)
		}
	}
	if err := WriteReport(o.StateDir, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

func (o Options) fail(rep Report, err error) (Report, error) {
	rep.Result, rep.Error = "failed", err.Error()
	if werr := WriteReport(o.StateDir, rep); werr != nil {
		return rep, fmt.Errorf("%v (and the status file could not be written: %v)", err, werr)
	}
	return rep, err
}

// backUp copies every completed recording that does not already have a
// verified copy, and returns the set of recordings with a confirmed remote
// copy after this run. That set is what cleanup uses to decide whether a
// deletion loses a recording, so a failed copy never appears in it.
func (o Options) backUp(recs []Recording, rep *Report) (map[string]bool, error) {
	dest := DestDir(o.Dest)
	// The destination root must already exist: a missing directory or an
	// absent mount fails visibly here rather than being redirected into
	// local storage. Only the recordings subdirectory is created.
	if fi, err := os.Stat(o.Dest); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("backup destination %s is not an existing directory (is the mount present?); no recording was copied", o.Dest)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, err
	}
	if !o.Plaintext && o.PublicKey == "" {
		return nil, fmt.Errorf("refusing to copy recordings unencrypted: no backup public key is recorded; run 'guacdeploy backup-key' first, or choose plaintext deliberately")
	}

	present := map[string]bool{}
	ents, err := os.ReadDir(dest)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !e.IsDir() {
			present[e.Name()] = true
		}
	}

	e := ext(o.Plaintext)
	confirmed := map[string]bool{}
	var firstErr error
	for _, r := range recs {
		if r.Active {
			continue
		}
		if _, ok := publishedCopy(dest, r.Name, e, o.DeploymentID, present); ok {
			rep.AlreadyBackedUp = append(rep.AlreadyBackedUp, r.Name)
			confirmed[r.Name] = true
			continue
		}
		if _, err := publish(r.Path, dest, r.Name, e, o.PublicKey, o.Plaintext, o.DeploymentID, present); err != nil {
			rep.Failed = append(rep.Failed, Failure{Name: r.Name, Reason: err.Error()})
			if firstErr == nil {
				firstErr = fmt.Errorf("copying recording %s failed: %w", r.Name, err)
			}
			continue
		}
		rep.Included = append(rep.Included, r.Name)
		confirmed[r.Name] = true
	}
	if firstErr != nil {
		done := len(rep.Included) + len(rep.AlreadyBackedUp)
		return confirmed, fmt.Errorf("%d of %d completed recordings could not be copied, so this upload is not complete; first failure: %w",
			len(rep.Failed), len(rep.Failed)+done, firstErr)
	}
	return confirmed, nil
}

// ReportPath is the last-run record, beside the backup one and for the same
// reason: the deployment record is the parent's schema and an hourly timer
// must not churn it.
func ReportPath(stateDir string) string { return filepath.Join(stateDir, "recording-status.json") }

// WriteReport saves the last-run record with owner-only permissions, through
// a temporary file and a rename. The record holds file names, byte counts
// and error text only; no credential passes through this package.
func WriteReport(stateDir string, rep Report) error {
	if stateDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	path := ReportPath(stateDir)
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

// ReadReport returns the last-run record, or nil when no run has happened.
func ReadReport(stateDir string) (*Report, error) {
	b, err := os.ReadFile(ReportPath(stateDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s is not readable JSON: %w", ReportPath(stateDir), err)
	}
	return &r, nil
}

// Summary renders the last-run record for an operator. Backed-up and deleted
// counts are shown apart, and a lost recording is named, because that is the
// one line an administrator has to act on.
func (r Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Recordings directory: %s\n", r.Dir)
	if r.Dest != "" {
		fmt.Fprintf(&b, "Recording backups:    %s\n", DestDir(r.Dest))
	} else {
		fmt.Fprintf(&b, "Recording backups:    not configured\n")
	}
	fmt.Fprintf(&b, "Local usage:          %d bytes\n", r.UsedAfter)
	if r.OnCalendar != "" {
		fmt.Fprintf(&b, "Schedule:             %s\n", r.OnCalendar)
	}
	fmt.Fprintf(&b, "Last run:             %s  %s\n", r.Ran.Format(time.RFC3339), r.Result)
	fmt.Fprintf(&b, "Backed up this run:   %d (already held: %d)\n", len(r.Included), len(r.AlreadyBackedUp))
	fmt.Fprintf(&b, "Still recording:      %d (excluded; not backed up, not deleted)\n", len(r.Active))
	for _, f := range r.Failed {
		fmt.Fprintf(&b, "Copy failed:          %s: %s\n", f.Name, strings.TrimSpace(f.Reason))
	}
	if r.Error != "" {
		fmt.Fprintf(&b, "Reason:               %s\n", strings.TrimSpace(r.Error))
	}
	return b.String()
}

// Summary reads the last-run record and renders it, for the status command.
func Summary(stateDir string) string {
	r, err := ReadReport(stateDir)
	if err != nil {
		return fmt.Sprintf("Recording status is unreadable: %v\n", err)
	}
	if r == nil {
		return "No recording backup or cleanup run has happened yet.\n"
	}
	return r.Summary()
}
