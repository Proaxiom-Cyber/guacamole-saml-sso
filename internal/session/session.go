// Package session runs the deployment session: the guided wizard entry, the
// unattended entry, and the resume/cleanup offer for interrupted work.
// It journals intent before each phase and the checked result after it, so
// an interruption at any point leaves a resumable record.
package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// ErrApprovalRequired means unattended operation reached a decision that
// needs interactive approval. Callers exit nonzero without waiting for input.
var ErrApprovalRequired = errors.New("interactive approval required")

// Phase is one unit of setup work. Phases must be idempotent: resume re-runs
// the first phase without a successful journal entry.
type Phase struct {
	Name string
	Run  func(ctx context.Context, st *state.State, u *ui.UI) error
}

// SetupPhases is the ordered registry. Later tickets append their phases
// (host preparation, credentials, stack, integrations) here.
var SetupPhases = []Phase{
	{Name: "initialise-deployment", Run: initialiseDeployment},
}

func initialiseDeployment(ctx context.Context, st *state.State, u *ui.UI) error {
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	st.Config["hostname"] = host
	st.Config["platform"] = runtime.GOOS + "/" + runtime.GOARCH
	u.Say("Deployment %s initialised on %s.", st.DeploymentID, host)
	return nil
}

// Options selects the session behaviour.
type Options struct {
	StateDir string
	UI       *ui.UI
	Resume   bool // unattended only: explicit consent to continue interrupted work
	Phases   []Phase
}

func (o *Options) phases() []Phase {
	if o.Phases != nil {
		return o.Phases
	}
	return SetupPhases
}

// Run is the setup entry point for both guided and unattended modes.
func Run(ctx context.Context, opts Options) error {
	store, err := state.Open(opts.StateDir)
	if err != nil {
		return err
	}
	defer store.Close()

	st, err := store.Load()
	if err != nil {
		return err
	}
	u := opts.UI

	switch {
	case st == nil:
		if u.Interactive {
			ok, err := u.Confirm("No deployment exists on this host. Start a fresh setup?")
			if err != nil {
				return err
			}
			if !ok {
				u.Say("Nothing changed.")
				return nil
			}
		}
		st = &state.State{DeploymentID: state.NewID(), CreatedAt: time.Now().UTC()}
		if err := store.Save(st); err != nil {
			return err
		}
		return runPhases(ctx, store, st, u, opts.phases())

	case len(st.Pending()) > 0:
		showInterrupted(u, st)
		if !u.Interactive {
			if opts.Resume {
				return runPhases(ctx, store, st, u, opts.phases())
			}
			return fmt.Errorf("%w: interrupted work exists; pass --resume to continue it, or run interactively to choose resume or cleanup", ErrApprovalRequired)
		}
		k, err := u.Choose("What do you want to do?", []ui.Choice{
			{Key: 'r', Label: "Resume the interrupted work"},
			{Key: 'c', Label: "Clean up and remove the interrupted deployment record"},
			{Key: 'q', Label: "Quit and decide later"},
		})
		if err != nil {
			return err
		}
		switch k {
		case 'r':
			return runPhases(ctx, store, st, u, opts.phases())
		case 'c':
			return cleanup(store, st, u)
		default:
			u.Say("Nothing changed. Interrupted work is retained.")
			return nil
		}

	default:
		u.Say("A completed deployment already exists on this host (deployment %s, created %s).",
			st.DeploymentID, st.CreatedAt.Format(time.RFC3339))
		u.Say("This tool manages one deployment per host and does not overwrite it.")
		u.Say("Run teardown first to start over. Existing installations from the old scripts are not adopted.")
		if !u.Interactive {
			return errors.New("existing deployment present; teardown is required before a new setup")
		}
		return nil
	}
}

func showInterrupted(u *ui.UI, st *state.State) {
	u.Say("An earlier deployment session on this host did not finish.")
	u.Say("Deployment %s, created %s.", st.DeploymentID, st.CreatedAt.Format(time.RFC3339))
	for _, a := range st.Pending() {
		res := a.Result
		if res == "" {
			res = "interrupted"
		}
		u.Say("  - %s (started %s): %s", a.Intent, a.StartedAt.Format(time.RFC3339), res)
	}
	u.Say("Completed work is retained and will not be repeated.")
}

func cleanup(store *state.Store, st *state.State, u *ui.UI) error {
	if len(st.Resources) > 0 {
		u.Say("This deployment created %d resource(s); guided teardown must remove them first.", len(st.Resources))
		return errors.New("created resources exist; cleanup requires teardown")
	}
	if err := store.Delete(st); err != nil {
		return err
	}
	u.Say("Deployment record removed. No created resources existed. Run setup again for a fresh start.")
	return nil
}

// runPhases executes the registry, skipping phases with a successful journal
// entry, journalling intent before each run and the result after it.
func runPhases(ctx context.Context, store *state.Store, st *state.State, u *ui.UI, phases []Phase) error {
	done := map[string]bool{}
	for _, a := range st.Actions {
		if a.FinishedAt != nil && a.Result == state.ResultOK {
			done[a.Intent] = true
		}
	}
	for _, p := range phases {
		if done[p.Name] {
			u.Say("Phase %s: already complete, skipping.", p.Name)
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		act := state.Action{ID: state.NewID(), Intent: p.Name, CorrelationID: state.NewID(), StartedAt: time.Now().UTC()}
		st.Actions = append(st.Actions, act)
		if err := store.Save(st); err != nil {
			return err
		}
		err := p.Run(ctx, st, u)
		now := time.Now().UTC()
		last := &st.Actions[len(st.Actions)-1]
		last.FinishedAt = &now
		if err != nil {
			last.Result = state.ResultFailed
			last.Detail = err.Error()
			if saveErr := store.Save(st); saveErr != nil {
				return saveErr
			}
			u.Say("Phase %s failed: %v", p.Name, err)
			u.Say("Completed work is retained. Run setup again to resume or clean up.")
			return err
		}
		last.Result = state.ResultOK
		if err := store.Save(st); err != nil {
			return err
		}
		u.Say("Phase %s: complete.", p.Name)
	}
	u.Say("Session complete. Deployment %s.", st.DeploymentID)
	return nil
}

// Status prints the deployment record without taking the mutation lock.
func Status(dir string, u *ui.UI) error {
	st, err := state.Read(dir)
	if err != nil {
		return err
	}
	if st == nil {
		u.Say("No deployment exists on this host.")
		return nil
	}
	u.Say("Deployment %s", st.DeploymentID)
	u.Say("Created:  %s", st.CreatedAt.Format(time.RFC3339))
	u.Say("Updated:  %s", st.UpdatedAt.Format(time.RFC3339))
	for k, v := range st.Config {
		u.Say("Config:   %s = %s", k, v)
	}
	u.Say("Resources: %d created", len(st.Resources))
	for _, a := range st.Actions {
		res := a.Result
		if a.FinishedAt == nil {
			res = "interrupted"
		}
		u.Say("Action:   %s → %s", a.Intent, res)
	}
	if p := st.Pending(); len(p) > 0 {
		u.Say("Interrupted work exists. Run setup to resume or clean up.")
	}
	return nil
}
