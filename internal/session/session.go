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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/stack"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// ErrApprovalRequired means unattended operation reached a decision that
// needs interactive approval. Callers exit nonzero without waiting for input.
var ErrApprovalRequired = errors.New("interactive approval required")

// ErrUncertain means a mutating request was sent and its response was lost,
// so whether the resource exists is unknown. The phase result is journalled
// as uncertain, and the next run queries before retrying any creation
// rather than risking a duplicate.
var ErrUncertain = errors.New("uncertain result: a request was sent but the response was lost")

// Phase is one unit of setup work. Phases must be idempotent: resume re-runs
// the first phase without a successful journal entry.
type Phase struct {
	Name string
	Run  func(ctx context.Context, st *state.State, u *ui.UI) error

	// Always re-runs the phase on resume even when an earlier attempt
	// succeeded. Only for phases that write desired state and are safe to
	// repeat: skipping those would leave a host repaired by a later tool
	// version still broken, because the journal says the work is done.
	Always bool
}

// Phases builds the ordered registry for one session. Later tickets append
// their phases (stack, integrations) here. Credential-storage choices come
// before host mutations, matching the installation flow.
func Phases(opts *Options) []Phase {
	return []Phase{
		{Name: "initialise-deployment", Run: initialiseDeployment},
		{Name: "host-preflight", Run: opts.hostPreflight},
		{Name: "credential-mode", Run: opts.credentialMode},
		{Name: "credential-check", Run: opts.credentialCheck},
		{Name: "host-dependencies", Run: opts.hostDependencies},
		{Name: "stack-configure", Run: opts.stackConfigure},
		// Rendering is idempotent and also repairs configuration written by
		// an earlier version, so it re-runs on every resume.
		{Name: "stack-render", Run: opts.stackRender, Always: true},
		// Schema generation is idempotent: it re-reads the published file,
		// keeps it when it is valid, and regenerates only when it is
		// missing or corrupt. It re-runs so a schema written by an earlier
		// version gets repaired instead of skipped for ever.
		{Name: "stack-schema", Run: opts.stackSchema, Always: true},
		{Name: "stack-up", Run: opts.stackUp},
		{Name: "entra-signin", Run: opts.entraSignin},
		{Name: "stack-health", Run: opts.stackHealth},
	}
}

func (o *Options) installDir() string {
	if o.InstallDir != "" {
		return o.InstallDir
	}
	return "/opt/guacamole"
}

func (o *Options) stackRun() stack.Runner {
	if o.StackRun != nil {
		return o.StackRun
	}
	return stack.ExecRunner
}

func (o *Options) stackRunOut() stack.OutRunner {
	if o.StackRunOut != nil {
		return o.StackRunOut
	}
	return stack.ExecOutRunner
}

func (o *Options) stackConfig(st *state.State) stack.Config {
	return stack.Config{
		InstallDir:      o.installDir(),
		Hostname:        st.Config["guac-hostname"],
		AdminGroup:      st.Config["admin-group"],
		OperatorGroup:   st.Config["operator-group"],
		SAMLMetadataURL: st.Config["saml-metadata-url"],
		// Entra's groups claim is a full URI. Fall back to it whenever a
		// metadata URL exists but nothing recorded the attribute, so the
		// compose default "groups" can never silently apply to Entra.
		SAMLGroupAttribute: samlGroupAttribute(st),
		ComposeProfiles:    st.Config["compose-profiles"],
	}
}

// samlGroupAttribute returns the SAML group attribute for the rendered
// .env: whatever the identity slice recorded, else Entra's claim URI once
// SAML is configured, else empty (no SAML block is rendered).
func samlGroupAttribute(st *state.State) string {
	if v := st.Config["saml-group-attribute"]; v != "" {
		return v
	}
	if st.Config["saml-metadata-url"] != "" {
		return entra.GroupClaimAttribute
	}
	return ""
}

func (o *Options) stackConfigure(ctx context.Context, st *state.State, u *ui.UI) error {
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	items := []struct {
		key, flag, prompt, def string
	}{
		{"guac-hostname", o.Hostname, "Public hostname for this deployment (for example guac.example.com)", ""},
		{"admin-group", o.AdminGroup, "Identity-provider group for administrators", "Guacamole Administrators"},
		{"operator-group", o.OperatorGroup, "Identity-provider group for operators", "Guacamole Operators"},
	}
	for _, it := range items {
		v := st.Config[it.key]
		if v == "" {
			v = it.flag
		}
		if v == "" {
			if !u.Interactive {
				return errors.New("unattended setup needs explicit configuration: pass --hostname, --admin-group, and --operator-group")
			}
			var err error
			v, err = u.Line(it.prompt, it.def)
			if err != nil {
				return err
			}
		}
		if strings.ContainsAny(v, " /") || v == "" {
			return fmt.Errorf("%s %q is not valid: use a bare DNS name or group name without spaces or slashes", it.key, v)
		}
		st.Config[it.key] = v
	}
	u.Say("Configuration: hostname %s, administrator group %q, operator group %q.",
		st.Config["guac-hostname"], st.Config["admin-group"], st.Config["operator-group"])
	return nil
}

func (o *Options) stackRender(ctx context.Context, st *state.State, u *ui.UI) error {
	cfg := o.stackConfig(st)
	if err := stack.Render(cfg); err != nil {
		return err
	}
	now := time.Now().UTC()
	st.EnsureResource(state.Resource{
		Provider: "host", Type: "config-directory", Name: cfg.InstallDir,
		Ownership: "rendered by this deployment", CreatedAt: now,
	})
	st.EnsureResource(state.Resource{
		// Data survives ordinary teardown; permanent deletion needs
		// explicit intent (spec: teardown contract).
		Provider: "host", Type: "data-directory", Name: filepath.Join(cfg.InstallDir, "data"),
		Ownership: "created by this deployment; preserved by default at teardown", CreatedAt: now,
	})
	u.Say("Stack configuration rendered under %s (a temporary self-signed certificate serves until the origin certificate is issued).", cfg.InstallDir)
	return nil
}

func (o *Options) stackSchema(ctx context.Context, st *state.State, u *ui.UI) error {
	if err := stack.GenerateSchema(ctx, o.stackRunOut(), o.stackConfig(st)); err != nil {
		return err
	}
	u.Say("Database schema generated from guacamole/guacamole:%s and validated.", stack.GuacVersion)
	return nil
}

// stackSecrets resolves the credentials the stack needs at start time.
func (o *Options) stackSecrets(st *state.State, u *ui.UI) (password, tunnelToken string, err error) {
	m := o.manager(st, u)
	for _, s := range o.credSpecs() {
		switch s.Name {
		case "postgres-password":
			if password, err = m.Get(s); err != nil {
				return "", "", err
			}
		}
	}
	// Tunnel token arrives with the Cloudflare slice; empty until then.
	return password, "", nil
}

func (o *Options) stackUp(ctx context.Context, st *state.State, u *ui.UI) error {
	password, token, err := o.stackSecrets(st, u)
	if err != nil {
		return err
	}
	cfg := o.stackConfig(st)
	u.Say("Starting the Guacamole stack (guacd, PostgreSQL, Guacamole, nginx) and waiting for container health.")
	if err := stack.Up(ctx, o.stackRun(), cfg, password, token); err != nil {
		return err
	}
	names, err := stack.Containers(ctx, o.stackRun(), cfg, password, token)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, n := range names {
		st.EnsureResource(state.Resource{
			Provider: "docker", Type: "container", Name: n,
			Ownership: "created by this deployment", CreatedAt: now,
		})
	}
	u.Say("Containers healthy: %s.", strings.Join(names, ", "))
	return nil
}

func (o *Options) stackHealth(ctx context.Context, st *state.State, u *ui.UI) error {
	cfg := o.stackConfig(st)
	if o.ProbeCheck != nil {
		if err := o.ProbeCheck(ctx, cfg); err != nil {
			return err
		}
	} else if err := (stack.Probe{}).Check(ctx, cfg); err != nil {
		return err
	}
	u.Say("Guacamole answers through nginx: https://%s/ (representative local connection checked).", cfg.Hostname)
	u.Say("Sign-in requires the identity-provider configuration from the Entra slice; local containers restart automatically with Docker after reboot.")
	return nil
}

func (o *Options) credentialMode(ctx context.Context, st *state.State, u *ui.UI) error {
	mode := o.CredentialMode
	if mode == "" {
		if !u.Interactive {
			return fmt.Errorf("%w: no credential mode selected; pass --credentials prompt|env|file", ErrApprovalRequired)
		}
		u.Say("Choose how this deployment receives credentials:")
		for _, m := range creds.Modes {
			u.Say("  %s — %s", m, creds.Explain(m))
		}
		k, err := u.Choose("Credential mode?", []ui.Choice{
			{Key: 'p', Label: "Hidden prompts"},
			{Key: 'e', Label: "Environment variables"},
			{Key: 'f', Label: "Owner-only plaintext files (explicit approval required)"},
		})
		if err != nil {
			return err
		}
		mode = map[rune]string{'p': creds.ModePrompt, 'e': creds.ModeEnv, 'f': creds.ModeFile}[k]
		if mode == creds.ModeFile {
			ok, err := u.Confirm("Plaintext storage is an approved exception, protected only by file permissions. Select it?")
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("plaintext storage not approved; run setup again to choose another mode")
			}
		}
	}
	switch mode {
	case creds.ModePrompt, creds.ModeEnv, creds.ModeFile:
	default:
		return fmt.Errorf("unknown credential mode %q; valid modes: prompt, env, file", mode)
	}
	if mode == creds.ModePrompt && !u.Interactive {
		return errors.New("prompt-mode credentials cannot support unattended operation; choose env or file")
	}
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	st.Config["credential-mode"] = mode
	u.Say("Credential storage method: %s. %s", mode, creds.Explain(mode))
	return nil
}

func (o *Options) manager(st *state.State, u *ui.UI) *creds.Manager {
	return &creds.Manager{
		Mode:       st.Config["credential-mode"],
		Dir:        filepath.Join(o.StateDir, "credentials"),
		ReadSecret: u.SecretReader(),
	}
}

func (o *Options) credSpecs() []creds.Spec {
	if o.CredSpecs != nil {
		return o.CredSpecs
	}
	return creds.Required
}

func (o *Options) credentialCheck(ctx context.Context, st *state.State, u *ui.UI) error {
	m := o.manager(st, u)
	if m.Mode == creds.ModeFile {
		for _, s := range o.credSpecs() {
			if _, err := os.Stat(filepath.Join(m.Dir, s.Name)); err == nil {
				continue
			}
			var v string
			switch {
			case s.Generate:
				v = creds.NewSecret()
				u.Say("Generated %s in memory and storing it in the approved credential directory.", s.Name)
			case u.Interactive:
				var err error
				v, err = u.SecretReader()(fmt.Sprintf("Enter %s (%s)", s.Name, s.Purpose))
				if err != nil {
					return err
				}
			default:
				continue // reported by Missing below with instructions
			}
			createdDir, err := m.StoreFile(s, v)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			if createdDir {
				st.Resources = append(st.Resources, state.Resource{
					ID: state.NewID(), Provider: "host", Type: "credential-dir", Name: m.Dir,
					Ownership: "created by this deployment", CreatedAt: now,
				})
			}
			st.Resources = append(st.Resources, state.Resource{
				ID: state.NewID(), Provider: "host", Type: "credential-file", Name: s.Name,
				Ownership: "written by this deployment", CreatedAt: now,
			})
		}
	}
	missing := m.Missing(o.credSpecs())
	if len(missing) > 0 {
		return fmt.Errorf("credentials are not available yet:\n  %s\nSupply them and resume", strings.Join(missing, "\n  "))
	}
	if m.Mode == creds.ModePrompt {
		u.Say("Credentials will be requested with hidden prompts when needed. Nothing is stored on disk.")
	} else {
		u.Say("All required credentials are available via the %s method.", m.Mode)
	}
	return nil
}

func (o *Options) probes() *host.Probes {
	if o.Host == nil {
		o.Host = &host.Probes{}
	}
	return o.Host
}

func (o *Options) hostPreflight(ctx context.Context, st *state.State, u *ui.UI) error {
	f, err := o.probes().Gather(ctx)
	if err != nil {
		return err
	}
	if err := host.Preflight(f); err != nil {
		return err
	}
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	st.Config["os"] = f.OSID + " " + f.VersionID
	u.Say("Host checks passed: %s, root privileges, no existing installation, required endpoints reachable.", st.Config["os"])
	return nil
}

func (o *Options) hostDependencies(ctx context.Context, st *state.State, u *ui.UI) error {
	f, err := o.probes().Gather(ctx)
	if err != nil {
		return err
	}
	missing := host.MissingDependencies(f)
	if len(missing) == 0 {
		u.Say("Docker and the Compose plugin are already present. They are pre-existing and will not be offered for removal at teardown.")
		return nil
	}
	u.Say("Missing dependencies: %s", strings.Join(missing, ", "))
	u.Say("Plan: add Docker's RHEL repository, install the packages with dnf, then enable and start the docker service.")
	if u.Interactive {
		ok, err := u.Confirm("Install these dependencies now?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("dependency installation declined; setup cannot continue without Docker")
		}
	} else if !o.InstallDependencies {
		return fmt.Errorf("%w: missing dependencies (%s) need approval; pass --install-dependencies to consent", ErrApprovalRequired, strings.Join(missing, ", "))
	}
	if err := o.probes().InstallDependencies(ctx, missing); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, pkg := range missing {
		st.Resources = append(st.Resources, state.Resource{
			ID: state.NewID(), Provider: "host", Type: "package", Name: pkg,
			Ownership: "installed by this deployment", CreatedAt: now,
		})
	}
	st.Resources = append(st.Resources, state.Resource{
		ID: state.NewID(), Provider: "host", Type: "service-enablement", Name: "docker",
		Ownership: "enabled by this deployment", CreatedAt: now,
	})
	u.Say("Dependencies installed and recorded as host changes made by this deployment.")
	return nil
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
	StateDir            string
	UI                  *ui.UI
	Resume              bool   // unattended only: explicit consent to continue interrupted work
	InstallDependencies bool   // unattended only: explicit consent to install missing dependencies
	CredentialMode      string // explicit credential mode; guided asks when empty
	Hostname            string // explicit configuration; guided asks when empty
	AdminGroup          string
	OperatorGroup       string
	InstallDir          string // default /opt/guacamole
	CredSpecs           []creds.Spec
	Host                *host.Probes
	StackRun            stack.Runner    // injectable for tests
	StackRunOut         stack.OutRunner // injectable for tests
	Entra               *entra.Client   // injectable for tests; nil builds one from the environment token

	// journalIntent persists what the running phase is about to do, before
	// it does it. runPhases sets it; phases call it before any cloud
	// creation so a lost response can be reconciled on resume.
	journalIntent func(detail string) error
	ProbeCheck    func(context.Context, stack.Config) error // injectable for tests
	Phases        []Phase
}

func (o *Options) phases() []Phase {
	if o.Phases != nil {
		return o.Phases
	}
	return Phases(o)
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
		return runPhases(ctx, store, st, u, &opts, opts.phases())

	case len(st.Pending()) > 0:
		showInterrupted(u, st)
		if !u.Interactive {
			if opts.Resume {
				return runPhases(ctx, store, st, u, &opts, opts.phases())
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
			return runPhases(ctx, store, st, u, &opts, opts.phases())
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
func runPhases(ctx context.Context, store *state.Store, st *state.State, u *ui.UI, opts *Options, phases []Phase) error {
	done := map[string]bool{}
	for _, a := range st.Actions {
		if a.FinishedAt != nil && a.Result == state.ResultOK {
			done[a.Intent] = true
		}
	}
	for _, p := range phases {
		if done[p.Name] && !p.Always {
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
		// Let the phase persist what it is about to do, before it does
		// it, so a lost response is reconcilable on the next run.
		if opts != nil {
			opts.journalIntent = func(detail string) error {
				a := &st.Actions[len(st.Actions)-1]
				a.Detail = detail
				return store.Save(st)
			}
		}
		err := p.Run(ctx, st, u)
		if opts != nil {
			opts.journalIntent = nil
		}
		now := time.Now().UTC()
		last := &st.Actions[len(st.Actions)-1]
		last.FinishedAt = &now
		if err != nil {
			last.Result = state.ResultFailed
			if errors.Is(err, ErrUncertain) {
				// The request was sent and the answer lost: the resource
				// may exist. Record that so the next run queries by
				// ownership marker before retrying any creation.
				last.Result = state.ResultUncertain
			}
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

// entraSignin provisions the Entra application, service principal and
// groups that carry sign-in, then re-renders and restarts the stack so
// Guacamole comes up with SAML enabled.
//
// Ordering matters: intent is journalled before any creation, so a lost
// response can be reconciled on the next run instead of creating a
// duplicate. A pre-existing application is never changed without
// interactive approval.
func (o *Options) entraSignin(ctx context.Context, st *state.State, u *ui.UI) error {
	c, err := o.entraClient()
	if err != nil {
		return err
	}

	cfg := entra.Config{
		Hostname:      st.Config["guac-hostname"],
		DeploymentID:  st.DeploymentID,
		AdminGroup:    st.Config["admin-group"],
		OperatorGroup: st.Config["operator-group"],
		// Resume after a lost creation response: a name match without our
		// marker must be reviewed by a person, not adopted or duplicated.
		AfterUncertainCreate: lastAttemptUncertain(st, "entra-signin"),
	}

	pf, err := c.CheckPermissions(ctx)
	if err != nil {
		return fmt.Errorf("checking Entra permissions failed: %w", err)
	}
	if !pf.ReadOK {
		return fmt.Errorf("the Entra token cannot read applications: %s", pf.ReadDetail)
	}
	if pf.ClaimsChecked && !pf.MutationOK {
		return fmt.Errorf("the Entra token is missing required permissions: %s (needs %s)",
			pf.MutationDetail, strings.Join(entra.RequiredPermissions, ", "))
	}
	if !pf.ClaimsChecked {
		u.Say("Entra token permissions could not be checked in advance (opaque token); the first change is the proof.")
	}

	plan, err := c.Plan(ctx, cfg)
	if err != nil {
		if errors.Is(err, entra.ErrRequiresReview) {
			return fmt.Errorf("Entra needs review before anything is created or changed: %w", err)
		}
		return err
	}

	// Journal intent before any creation.
	if len(plan.Creations) > 0 && o.journalIntent != nil {
		var names []string
		for _, cr := range plan.Creations {
			names = append(names, cr.Type+" "+cr.Name)
		}
		if err := o.journalIntent("will create in Entra: " + strings.Join(names, ", ")); err != nil {
			return err
		}
		u.Say("Entra changes planned: %s", strings.Join(names, ", "))
	}

	// A pre-existing application is only changed after approval.
	if plan.App != nil && !plan.App.ProvenOurs && len(plan.Changes) > 0 {
		u.Say("An existing Entra application %q (object %s) would be changed:", plan.App.DisplayName, plan.App.ObjectID)
		for _, ch := range plan.Changes {
			u.Say("  %s: %s -> %s", ch.Field, string(ch.Original), string(ch.Applied))
		}
		if !u.Interactive {
			return fmt.Errorf("%w: changing the pre-existing Entra application needs interactive approval", ErrApprovalRequired)
		}
		ok, err := u.Confirm("Apply these changes to the existing application?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("changes to the existing Entra application were declined")
		}
	}

	res, err := c.Apply(ctx, plan)
	if err != nil {
		if errors.Is(err, entra.ErrUncertain) {
			// Journal as uncertain: the next run queries by marker first.
			return fmt.Errorf("%w: %v", ErrUncertain, err)
		}
		if errors.Is(err, entra.ErrRequiresReview) {
			return fmt.Errorf("Entra needs review: %w", err)
		}
		return err
	}

	now := time.Now().UTC()
	if res.App.CreatedApp {
		st.EnsureResource(state.Resource{
			Provider: "entra", Type: "application", ProviderID: res.App.ObjectID,
			Name: res.App.DisplayName, Ownership: res.App.Evidence,
			CorrelationID: cfg.DeploymentID, CreatedAt: now,
		})
	}
	if res.App.CreatedSP {
		st.EnsureResource(state.Resource{
			Provider: "entra", Type: "service-principal", ProviderID: res.App.SPObjectID,
			Name: res.App.DisplayName, Ownership: res.App.Evidence, CreatedAt: now,
		})
	}
	for _, g := range res.Groups {
		if !g.Created {
			continue // pre-existing: never recorded, never offered at teardown
		}
		st.EnsureResource(state.Resource{
			Provider: "entra", Type: "group", ProviderID: g.ObjectID,
			Name: g.Name, Ownership: g.Evidence, CreatedAt: now,
		})
	}
	for _, ch := range res.Changes {
		st.Changes = append(st.Changes, state.SettingChange{
			ID: state.NewID(), Provider: "entra",
			Target:   "application/" + res.App.ObjectID + "/" + ch.Field,
			Original: ch.Original, Applied: ch.Applied,
		})
	}

	entityID, err := c.VerifyMetadata(ctx, res.MetadataURL)
	if err != nil {
		return fmt.Errorf("the sign-in configuration could not be verified: %w", err)
	}
	if o.journalIntent != nil {
		if err := o.journalIntent("verified identity provider " + entityID); err != nil {
			return err
		}
	}

	st.Config["saml-metadata-url"] = res.MetadataURL
	st.Config["entra-tenant-id"] = res.TenantID
	// Cloudflare Access needs the group object IDs; without them its
	// allow-list silently degrades to email addresses.
	for _, g := range res.Groups {
		switch g.Name {
		case st.Config["admin-group"]:
			st.Config["entra-admin-group-id"] = g.ObjectID
		case st.Config["operator-group"]:
			st.Config["entra-operator-group-id"] = g.ObjectID
		}
	}
	u.Say("Entra sign-in configured. Identity provider verified: %s", entityID)

	// Re-render and restart so the SAML block reaches Guacamole.
	cfgStack := o.stackConfig(st)
	if err := stack.Render(cfgStack); err != nil {
		return err
	}
	password, token, err := o.stackSecrets(st, u)
	if err != nil {
		return err
	}
	u.Say("Restarting the stack so Guacamole picks up SAML sign-in.")
	return stack.Up(ctx, o.stackRun(), cfgStack, password, token)
}

// entraClient builds the Graph client, or explains what is missing.
func (o *Options) entraClient() (*entra.Client, error) {
	if o.Entra != nil {
		return o.Entra, nil
	}
	if os.Getenv(entra.DefaultTokenEnv) == "" {
		return nil, fmt.Errorf("Entra sign-in needs a Microsoft Graph token: set %s and resume. Required permissions: %s",
			entra.DefaultTokenEnv, strings.Join(entra.RequiredPermissions, ", "))
	}
	return &entra.Client{Token: entra.StaticTokenFromEnv(entra.DefaultTokenEnv)}, nil
}

// lastAttemptUncertain reports whether the most recent attempt at an intent
// ended with a lost response.
func lastAttemptUncertain(st *state.State, intent string) bool {
	uncertain := false
	for _, a := range st.Actions {
		if a.Intent == intent {
			uncertain = a.Result == state.ResultUncertain
		}
	}
	return uncertain
}
