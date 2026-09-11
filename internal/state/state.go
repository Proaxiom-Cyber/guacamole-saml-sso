// Package state owns the durable deployment record. Local state is
// authoritative and lives outside any repository. Credential values never
// belong here: the schema has no secret fields, and callers must only store
// references (names, IDs) to externally held credentials.
package state

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const SchemaVersion = 1

// DefaultDir returns the state directory: $GUACDEPLOY_STATE_DIR if set,
// otherwise /var/lib/guacdeploy. One deployment per host.
func DefaultDir() string {
	if d := os.Getenv("GUACDEPLOY_STATE_DIR"); d != "" {
		return d
	}
	return "/var/lib/guacdeploy"
}

// State is the full durable record for the one deployment on this host.
type State struct {
	SchemaVersion int               `json:"schema_version"`
	DeploymentID  string            `json:"deployment_id"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Config        map[string]string `json:"config,omitempty"` // non-secret references only
	Resources     []Resource        `json:"resources,omitempty"`
	Changes       []SettingChange   `json:"changes,omitempty"`
	Actions       []Action          `json:"actions,omitempty"`
}

// Resource is something this deployment created (or adopted with evidence).
// A matching name alone never establishes ownership.
type Resource struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"` // host, docker, entra, cloudflare, azure
	Type          string    `json:"type"`
	ProviderID    string    `json:"provider_id,omitempty"`
	Name          string    `json:"name,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Ownership     string    `json:"ownership,omitempty"` // evidence: marker/tag applied, creation response, ...
	CreatedAt     time.Time `json:"created_at"`
}

// SettingChange records original and applied values for a change to a
// pre-existing setting, so teardown can offer a drift-checked restore.
type SettingChange struct {
	ID         string          `json:"id"`
	Provider   string          `json:"provider"`
	Target     string          `json:"target"`
	Original   json.RawMessage `json:"original"`
	Applied    json.RawMessage `json:"applied"`
	RestoredAt *time.Time      `json:"restored_at,omitempty"`
}

// Action results.
const (
	ResultOK        = "ok"
	ResultFailed    = "failed"
	ResultUncertain = "uncertain" // request sent, response lost: query before retrying creation
)

// Action journals intent before work and the checked result after it.
type Action struct {
	ID            string     `json:"id"`
	Intent        string     `json:"intent"`
	CorrelationID string     `json:"correlation_id,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	Result        string     `json:"result,omitempty"`
	Detail        string     `json:"detail,omitempty"`
}

// Pending returns the intents whose latest attempt did not succeed:
// interrupted or uncertain work that resume must reconcile before anything
// new runs. Earlier attempts stay in the journal as history; only the most
// recent attempt per intent decides whether work is still pending.
func (s *State) Pending() []Action {
	latest := map[string]Action{}
	var order []string
	for _, a := range s.Actions {
		if _, seen := latest[a.Intent]; !seen {
			order = append(order, a.Intent)
		}
		latest[a.Intent] = a
	}
	var p []Action
	for _, intent := range order {
		a := latest[intent]
		if a.FinishedAt == nil || a.Result == ResultUncertain || a.Result == ResultFailed {
			p = append(p, a)
		}
	}
	return p
}

// NewID returns a random 128-bit hex identifier.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is not recoverable
	}
	return fmt.Sprintf("%x", b)
}

// ErrLocked means another mutating operation holds the deployment lock.
var ErrLocked = errors.New("another deployment operation is already running on this host")

// Store gives locked access to the state file. Only one Store may be open
// for mutation at a time; Open takes an exclusive flock for the process
// lifetime of the Store.
type Store struct {
	dir  string
	lock *os.File
}

// Open creates the state directory (0700) and takes the exclusive lock.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrLocked
	}
	return &Store{dir: dir, lock: f}, nil
}

// Close releases the lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close() // closing drops the flock
	s.lock = nil
	return err
}

func (s *Store) path() string { return filepath.Join(s.dir, "state.json") }

// Load returns the current state, or nil when no deployment exists.
func (s *Store) Load() (*State, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("state file %s is not readable JSON: %w", s.path(), err)
	}
	if st.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("state schema %d is newer than this tool supports (%d)", st.SchemaVersion, SchemaVersion)
	}
	return &st, nil
}

// Save writes atomically: temp file in the same directory, fsync, rename.
// An interruption at any point leaves either the old or the new state,
// never a partial record.
func (s *Store) Save(st *State) error {
	st.SchemaVersion = SchemaVersion
	st.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, "state-*.tmp")
	if err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path()); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}
	if d, err := os.Open(s.dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Read loads state without taking the mutation lock, for read-only display.
func Read(dir string) (*State, error) {
	s := &Store{dir: dir}
	return s.Load()
}

// Delete removes the state file. Callers must first check that no created
// resources remain; Delete refuses otherwise.
func (s *Store) Delete(st *State) error {
	if st != nil && len(st.Resources) > 0 {
		return errors.New("state still records created resources; run teardown instead")
	}
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
