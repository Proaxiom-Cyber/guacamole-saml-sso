package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// The recorded change is a Cloudflare one on purpose: no provider accessor is
// registered for it, so the command reaches no network in any test.
func settingsFixture(t *testing.T) (dir string, store *state.Store, st *state.State) {
	t.Helper()
	dir = t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st = &state.State{DeploymentID: "d1", Changes: []state.SettingChange{{
		ID: "c1", Provider: "cloudflare",
		Target:   "accessApplication/a1/accessApplication.session_duration",
		Original: json.RawMessage(`"24h"`), Applied: json.RawMessage(`"8h"`),
	}}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	return dir, store, st
}

func cmdUI() (*ui.UI, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui.UI{In: bufio.NewReader(strings.NewReader("")), Out: out, Interactive: false}, out
}

func TestSettingsListNeedsNoLockAndRestoreTakesIt(t *testing.T) {
	dir, store, _ := settingsFixture(t)
	u, out := cmdUI()

	// Listing works while another operation holds the deployment lock.
	if err := settingsCmd(context.Background(), dir, false, u); err != nil {
		t.Fatalf("--list must not need the lock: %v", err)
	}
	if !strings.Contains(out.String(), `"24h"`) {
		t.Errorf("the pending change must be listed:\n%s", out)
	}

	// Restoring writes, so it must refuse while the lock is held.
	if err := settingsCmd(context.Background(), dir, true, u); !errors.Is(err, state.ErrLocked) {
		t.Fatalf("--restore must take the deployment lock, got %v", err)
	}
	store.Close()

	// With the lock free, an unrestorable provider is reported, not restored.
	if err := settingsCmd(context.Background(), dir, true, u); err != nil {
		t.Fatal(err)
	}
	after, err := state.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Changes[0].RestoredAt != nil {
		t.Fatal("nothing was restorable, so nothing may be marked restored")
	}
	if !strings.Contains(out.String(), "cannot be restored automatically") {
		t.Errorf("the operator must be told why:\n%s", out)
	}
}

func TestSettingsWithNoDeployment(t *testing.T) {
	dir := t.TempDir()
	u, out := cmdUI()
	if err := settingsCmd(context.Background(), dir, false, u); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No deployment exists") {
		t.Errorf("listing with no deployment must say so:\n%s", out)
	}
	if err := settingsCmd(context.Background(), dir, true, u); err == nil {
		t.Fatal("restoring with no deployment must fail")
	}
}
