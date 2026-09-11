// Package settings restores pre-existing provider settings that this
// deployment changed.
//
// The rule comes from the teardown contract: prompt before restoring a
// pre-existing setting; restore only while the current value still matches
// the value this tool applied; otherwise keep the current setting and report
// the conflict. A drifted setting is never written and never marked
// restored, so it is not silently retried later as if it were done.
//
// Nothing here knows any provider. Each provider registers an Accessor that
// reads and writes one recorded target; a provider with no accessor is
// reported as "cannot be restored automatically", never skipped and never
// marked restored.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// ErrApprovalRequired means a restoration was reached that only a person can
// approve, in a run that cannot ask. Unattended runs stop here having written
// nothing. cmd maps it to exit 3, alongside session.ErrApprovalRequired and
// ui.ErrInputRequired.
var ErrApprovalRequired = errors.New("interactive approval required")

// Reader reads the live value of one recorded setting target.
type Reader interface {
	Get(ctx context.Context, target string) (json.RawMessage, error)
}

// Writer writes one value back to a recorded setting target.
type Writer interface {
	Set(ctx context.Context, target string, value json.RawMessage) error
}

// Accessor is both halves for one provider.
type Accessor interface {
	Reader
	Writer
}

// Registry maps state.SettingChange.Provider to that provider's accessor.
type Registry map[string]Accessor

// Status classifies one pending change against its live value.
type Status string

const (
	// StatusRestorable means the live value still matches what this tool
	// applied, so restoring the original is safe once approved.
	StatusRestorable Status = "restorable"
	// StatusDrifted means the live value changed after this tool applied
	// its own. The live value is kept and nothing is written.
	StatusDrifted Status = "drifted"
	// StatusUnsupported means no accessor is registered for the provider.
	StatusUnsupported Status = "unsupported"
	// StatusUnreadable means the accessor could not read the live value.
	StatusUnreadable Status = "unreadable"
)

// Entry is one un-restored change with its live comparison.
type Entry struct {
	// Index is the position in state.State.Changes, so Restore can mark the
	// entry restored without searching for it again.
	Index   int
	Change  state.SettingChange
	Status  Status
	Current json.RawMessage // nil unless the live value was read
	Err     error           // why Status is unsupported or unreadable
}

// List inspects every un-restored change and classifies it. It reads from
// the providers and writes nothing, so it is safe to run at any time,
// including without the deployment lock.
func List(ctx context.Context, st *state.State, reg Registry) []Entry {
	if st == nil {
		return nil
	}
	var out []Entry
	for i, ch := range st.Changes {
		if ch.RestoredAt != nil {
			continue // already restored: never offered again
		}
		e := Entry{Index: i, Change: ch}
		acc, ok := reg[ch.Provider]
		switch {
		case !ok || acc == nil:
			e.Status = StatusUnsupported
			e.Err = fmt.Errorf("no accessor is registered for provider %q", ch.Provider)
		default:
			cur, err := acc.Get(ctx, ch.Target)
			if err != nil {
				e.Status, e.Err = StatusUnreadable, err
			} else {
				e.Current = cur
				if jsonEqual(cur, ch.Applied) {
					e.Status = StatusRestorable
				} else {
					e.Status = StatusDrifted
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// Report prints the pending changes and what can be done with each. It
// changes nothing, locally or at any provider.
func Report(u *ui.UI, entries []Entry) {
	if len(entries) == 0 {
		u.Say("No pre-existing settings are waiting to be restored.")
		return
	}
	u.Say("Pre-existing settings this deployment changed: %d not restored", len(entries))
	for _, e := range entries {
		u.Say("  %s (%s)", e.Change.Target, e.Change.Provider)
		u.Say("    applied by this tool: %s", e.Change.Applied)
		u.Say("    original value:       %s", e.Change.Original)
		switch e.Status {
		case StatusRestorable:
			u.Say("    current value:        %s", e.Current)
			u.Say("    restorable: the current value still matches what this tool applied")
		case StatusDrifted:
			u.Say("    current value:        %s", e.Current)
			u.Say("    CONFLICT: the setting changed after this tool applied its value.")
			u.Say("    The current value is kept. Nothing is written, and this stays unrestored.")
		default:
			u.Say("    cannot be restored automatically: %v", e.Err)
			u.Say("    Restore it by hand from the values above, if you want it back.")
		}
	}
}

// Restore offers every restorable change for approval and writes the
// original value back only on approval. Drifted, unreadable, and
// unsupported entries are reported and left alone.
//
// save persists state after each successful write, so an interruption never
// loses the record that a setting was already put back. It may be nil.
func Restore(ctx context.Context, st *state.State, reg Registry, u *ui.UI, save func() error) error {
	entries := List(ctx, st, reg)
	Report(u, entries)

	var pending []string
	for _, e := range entries {
		if e.Status == StatusRestorable {
			pending = append(pending, e.Change.Target)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if !u.Interactive {
		return fmt.Errorf("%w: %d pre-existing setting(s) can be restored but restoring needs approval: %s",
			ErrApprovalRequired, len(pending), strings.Join(pending, ", "))
	}

	for _, e := range entries {
		if e.Status != StatusRestorable {
			continue
		}
		u.Say("Target:  %s (%s)", e.Change.Target, e.Change.Provider)
		u.Say("Current: %s", e.Current)
		u.Say("Restore: %s", e.Change.Original)
		ok, err := u.Confirm("Restore this setting to its original value?")
		if err != nil {
			return err
		}
		if !ok {
			u.Say("Left as it is. %s stays unrestored.", e.Change.Target)
			continue
		}
		if err := reg[e.Change.Provider].Set(ctx, e.Change.Target, e.Change.Original); err != nil {
			return fmt.Errorf("restore %s: %w", e.Change.Target, err)
		}
		now := time.Now().UTC()
		st.Changes[e.Index].RestoredAt = &now
		if save != nil {
			if err := save(); err != nil {
				return err
			}
		}
		u.Say("Restored %s.", e.Change.Target)
	}
	return nil
}

// jsonEqual compares two recorded values by JSON meaning, not by bytes.
// Graph and other providers re-serialise what they return, so key order and
// whitespace differ from what was journalled; treating that as drift would
// refuse every legitimate restore.
func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false // unparseable on either side: never claim a match
	}
	return reflect.DeepEqual(x, y)
}
