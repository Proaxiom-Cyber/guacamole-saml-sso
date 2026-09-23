package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func (o *Options) configureReview(ctx context.Context, st *state.State, u *ui.UI) error {
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	if st.Config["setup-plan-approved"] == "true" {
		o.loadApprovedPlan(st)
		return nil
	}
	if !u.Interactive {
		return nil
	}
	// Old deployments must retain their existing configuration. This wizard does
	// not turn Back into rollback, nor change resources from a previous installer.
	for _, a := range st.Actions {
		switch a.Intent {
		case "host-dependencies", "stack-configure", "cloudflare-tunnel", "stack-render":
			u.Say("Existing deployment configuration is retained. Editable setup is available for a fresh deployment.")
			return nil
		}
	}
	draft := map[string]string{}
	if raw := st.Config["setup-draft"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &draft); err != nil {
			return fmt.Errorf("read saved setup answers: %w", err)
		}
	}
	defaults := map[string]string{"prefix": "guacamole", "admin-group": firstNonEmpty(o.AdminGroup, "Guacamole Administrators"), "operator-group": firstNonEmpty(o.OperatorGroup, "Guacamole Operators"), "recording-budget": firstNonEmpty(o.RecordingBudget, "none"), "backup-mode": "encrypted", "backup-dest": firstNonEmpty(o.BackupDest, filepath.Join(o.StateDir, "backups")), "backup-schedule": firstNonEmpty(o.BackupSchedule, "daily"), "backup-keep": "7"}
	if o.NoBackupSchedule {
		defaults["backup-mode"] = "none"
	}
	if o.BackupPlaintext {
		defaults["backup-mode"] = "plaintext"
	}
	if o.BackupKeep > 0 {
		defaults["backup-keep"] = strconv.Itoa(o.BackupKeep)
	}
	for k, v := range defaults {
		if draft[k] == "" {
			draft[k] = v
		}
	}
	u.Say("Prepare your deployment. Back edits answers; Deploy applies them. Credential preparation is already complete. No deployment services or cloud resources are created by these questions.")
	zones, err := o.cloudflareClient(st, u).AccessibleZones(ctx)
	if err != nil {
		return fmt.Errorf("list accessible Cloudflare domains: %w", err)
	}
	if len(zones) == 0 {
		return errors.New("no active Cloudflare domains are visible to these credentials; grant Zone Read access to the intended domain")
	}
	save := func() error {
		b, err := json.Marshal(draft)
		if err != nil {
			return err
		}
		st.Config["setup-draft"] = string(b)
		if o.journalIntent != nil {
			return o.journalIntent("saved editable setup answers; deployment not approved")
		}
		return nil
	}
	field := func(key, prompt string) error {
		v, err := u.BackLine(prompt, draft[key])
		if err == nil {
			draft[key] = v
		}
		return err
	}
	steps := []struct {
		name string
		run  func() error
	}{
		{"Cloudflare domain", func() error {
			labels := []string{}
			for _, z := range zones {
				labels = append(labels, z.Name+" — "+z.Account.Name)
			}
			i, err := chooseSetupItem(u, "Choose an active domain accessible to your Cloudflare credentials", labels, "Host the website under this active Cloudflare domain. The selected account manages its DNS. Your Microsoft Entra tenant can use a different domain.")
			if err != nil {
				return err
			}
			z := zones[i]
			if draft["cloudflare-zone-id"] != z.ID && (draft["entra-login-tenant"] == "" || draft["entra-login-tenant"] == draft["cloudflare-zone-name"]) {
				draft["entra-login-tenant"] = ""
				draft["entra-discovered-tenant-id"] = ""
			}
			draft["cloudflare-zone-id"], draft["cloudflare-zone-name"] = z.ID, z.Name
			draft["cloudflare-account-id"], draft["cloudflare-account-name"] = z.Account.ID, z.Account.Name
			return nil
		}},
		{"Website hostname", func() error {
			if err := field("prefix", "Website name under "+draft["cloudflare-zone-name"]+" (for example guacamole)"); err != nil {
				return err
			}
			if !validDNSPrefix(draft["prefix"]) {
				return errors.New("use DNS labels with letters, digits or hyphens; no spaces or URL")
			}
			draft["guac-hostname"] = draft["prefix"] + "." + draft["cloudflare-zone-name"]
			if len(draft["guac-hostname"]) > 253 {
				return errors.New("the full hostname must be at most 253 characters")
			}
			return nil
		}},
		{"Microsoft tenant", func() error {
			if draft["entra-login-tenant"] == "" {
				draft["entra-login-tenant"] = firstNonEmpty(o.EntraTenant, draft["cloudflare-zone-name"])
			}
			if err := field("entra-login-tenant", "Microsoft Entra verified domain. This can differ from the website domain; no tenant ID is needed."); err != nil {
				return err
			}
			discover := o.DiscoverTenant
			if discover == nil {
				discover = discoverTenantID
			}
			u.Say("Looking up the Microsoft tenant for %s.", draft["entra-login-tenant"])
			id, err := discover(ctx, draft["entra-login-tenant"])
			if err != nil {
				return err
			}
			draft["entra-discovered-tenant-id"] = id
			u.Say("Microsoft tenant found: %s. Sign-in will verify access before Microsoft resources are created.", id)
			return nil
		}},
		{"Access groups", func() error {
			for _, k := range []string{"admin-group", "operator-group"} {
				if err := field(k, "Entra "+k+" name"); err != nil {
					return err
				}
				if strings.Contains(draft[k], "/") {
					return errors.New("group names cannot contain a slash")
				}
			}
			return nil
		}},
		{"Recording storage", func() error {
			mounts, err := o.recordingMounts(ctx)
			if err != nil {
				return err
			}
			if len(mounts) == 0 {
				return errors.New("no writable supported filesystem is mounted; connect storage to the host first")
			}
			labels := []string{}
			for _, m := range mounts {
				labels = append(labels, fmt.Sprintf("%s — %s (%s)", m.Target, m.Source, m.FSType))
			}
			i, err := chooseSetupItem(u, "Choose connected recording storage. Unmounted drives and shares are not offered.", labels, "Store recordings in a dedicated directory on this mounted filesystem. The source and filesystem type are shown in the choice. Setup checks it again before starting services. Network shares must remain mounted and reachable.")
			if err != nil {
				return err
			}
			m := mounts[i]
			path := filepath.Join(m.Target, "guacamole-recordings")
			if m.Target == "/" {
				path = filepath.Join(o.installDir(), "recordings")
			}
			probe := *o
			probe.RecordingDir = path
			tmp := &state.State{Config: map[string]string{}}
			if err := probe.selectRecordingLocation(tmp, &ui.UI{Out: io.Discard}); err != nil {
				return err
			}
			draft["recording-dir"] = path
			draft["recording-mount-target"] = m.Target
			draft["recording-mount-source"] = m.Source
			draft["recording-mount-type"] = m.FSType
			return nil
		}},
		{"Recording budget", func() error {
			if err := field("recording-budget", "Recording budget, such as 20GiB, or none. Oldest completed recordings are deleted when over budget, even without a backup."); err != nil {
				return err
			}
			if draft["recording-budget"] != "none" {
				if _, err := recording.ParseBytes(draft["recording-budget"]); err != nil {
					return err
				}
			}
			return nil
		}},
		{"Backups", func() error {
			i, err := chooseSetupItem(u, "Scheduled backups", []string{"Encrypted backups (recommended)", "Plaintext backups — explicit unencrypted storage", "No scheduled backups"}, "Encrypt scheduled backups using the deployment public key. Keep the passphrase-protected private key export off this host for recovery.", "Write backups without encryption. Anyone who can read a backup can access its contents, which may include saved connection credentials.", "Do not install an automatic backup schedule. You must arrange backups separately to recover data after host loss.")
			if err != nil {
				return err
			}
			draft["backup-mode"] = []string{"encrypted", "plaintext", "none"}[i]
			if i == 2 {
				o.backupPassphrase = ""
				return nil
			}
			if err := field("backup-dest", "Backup directory"); err != nil {
				return err
			}
			if !filepath.IsAbs(draft["backup-dest"]) {
				return errors.New("use an absolute backup directory")
			}
			if err := field("backup-schedule", "Backup schedule (systemd calendar, for example daily)"); err != nil {
				return err
			}
			if err := field("backup-keep", "Successful backups to retain"); err != nil {
				return err
			}
			n, err := strconv.Atoi(draft["backup-keep"])
			if err != nil || n < 1 {
				return errors.New("retain at least one successful backup")
			}
			if i == 0 {
				pass, err := u.BackHiddenLine("Recovery key passphrase. The encrypted export is created after Deploy.")
				if err != nil {
					return err
				}
				confirm, err := u.BackHiddenLine("Confirm recovery key passphrase")
				if err != nil {
					return err
				}
				if pass == "" || pass != confirm {
					return errors.New("enter matching, non-empty recovery passphrases")
				}
				o.backupPassphrase = pass
			} else {
				o.backupPassphrase = ""
			}
			return nil
		}},
	}
	for index := 0; ; {
		if err := ctx.Err(); err != nil {
			return err
		}
		if index < len(steps) {
			u.Say("Configure %d/%d: %s", index+1, len(steps), steps[index].name)
			err := steps[index].run()
			if saveErr := save(); saveErr != nil {
				return saveErr
			}
			if errors.Is(err, ui.ErrBack) {
				index = max(0, index-1)
				continue
			}
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, ui.ErrInputRequired) {
					return err
				}
				if action, choiceErr := u.Choose("Check this answer\n\n"+u.ErrorText(err), []ui.Choice{{Key: 'r', Label: "Edit this section", Description: "Correct the current answers and validate them again. Deployment changes are not applied by this choice."}, {Key: 'b', Label: "Back to previous section", Description: "Review or edit the previous set of answers. Going back does not undo resources already created."}}); choiceErr != nil {
					return choiceErr
				} else if action == 'b' {
					index = max(0, index-1)
				}
				continue
			}
			index++
			continue
		}
		summary := fmt.Sprintf("Review before deployment\n\nWebsite: %s\nCloudflare: %s / %s\nEntra domain: %s\nDiscovered tenant: %s\nGroups: %s / %s\nRecordings: %s\nRecording budget: %s\nBackups: %s; %s; %s; retain %s\n\nDeploy installs missing dependencies and creates the configured services and cloud resources. Sign-in and approval for changes to pre-existing resources can still be required. Back edits answers; it does not undo deployed resources.", draft["guac-hostname"], draft["cloudflare-account-name"], draft["cloudflare-zone-name"], draft["entra-login-tenant"], draft["entra-discovered-tenant-id"], draft["admin-group"], draft["operator-group"], draft["recording-dir"], draft["recording-budget"], draft["backup-mode"], draft["backup-dest"], draft["backup-schedule"], draft["backup-keep"])
		choices := []ui.Choice{{Key: 'p', Label: "Deploy this configuration", Description: "Apply the reviewed configuration, install missing dependencies and create deployment resources. Later failures retain progress for recovery."}, {Key: 'b', Label: "Back to previous section", Description: "Review or edit the previous set of answers. Going back does not undo resources already created."}, {Key: 'q', Label: "Save answers and finish later", Description: "Save the draft answers without applying the deployment plan. Continue setup later to review and deploy."}}
		for i, s := range steps {
			choices = append(choices, ui.Choice{Key: rune('1' + i), Label: "Edit " + s.name, Description: "Return to " + s.name + " and change the draft answers before deployment. Other answers are retained."})
		}
		choice, err := u.Choose(summary, choices)
		if err != nil {
			return err
		}
		if choice == 'q' {
			return context.Canceled
		}
		if choice == 'b' {
			index = len(steps) - 1
			continue
		}
		if choice >= '1' && choice < rune('1'+len(steps)) {
			index = int(choice - '1')
			continue
		}
		if choice != 'p' {
			continue
		}
		if err := o.validateRecordingMount(ctx, &state.State{Config: draft}); err != nil {
			u.Say("%s", err)
			index = 4
			continue
		}
		for k, v := range draft {
			st.Config[k] = v
		}
		st.Config["setup-plan-approved"] = "true"
		delete(st.Config, "setup-draft")
		o.loadApprovedPlan(st)
		return nil
	}
}

func validDNSPrefix(s string) bool {
	if len(s) == 0 || len(s) > 190 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func chooseSetupItem(u *ui.UI, prompt string, labels []string, descriptions ...string) (int, error) {
	page := 0
	for {
		start := page * 7
		end := min(start+7, len(labels))
		choices := []ui.Choice{}
		for i := start; i < end; i++ {
			description := ""
			if len(descriptions) == 1 {
				description = descriptions[0]
			} else if i < len(descriptions) {
				description = descriptions[i]
			}
			choices = append(choices, ui.Choice{Key: rune('1' + i - start), Label: labels[i], Description: description})
		}
		if end < len(labels) {
			choices = append(choices, ui.Choice{Key: 'n', Label: "Next page", Description: "Show the next available choices without selecting an item."})
		}
		if page > 0 {
			choices = append(choices, ui.Choice{Key: 'p', Label: "Previous page", Description: "Show the previous choices without changing your selection."})
		}
		choices = append(choices, ui.Choice{Key: 'b', Label: "Back to previous section", Description: "Review or edit the previous set of answers. Going back does not undo resources already created."})
		k, err := u.Choose(prompt, choices)
		if err != nil {
			return 0, err
		}
		switch k {
		case 'b':
			return 0, ui.ErrBack
		case 'n':
			page++
		case 'p':
			page--
		default:
			return start + int(k-'1'), nil
		}
	}
}
func (o *Options) loadApprovedPlan(st *state.State) {
	c := st.Config
	o.Hostname = c["guac-hostname"]
	o.Zone = c["cloudflare-zone-name"]
	o.AdminGroup = c["admin-group"]
	o.OperatorGroup = c["operator-group"]
	o.EntraTenant = c["entra-discovered-tenant-id"]
	o.RecordingDir = c["recording-dir"]
	o.RecordingBudget = c["recording-budget"]
	if o.RecordingBudget == "none" {
		o.RecordingBudget = ""
	}
	o.NoBackupSchedule = c["backup-mode"] == "none"
	o.BackupPlaintext = c["backup-mode"] == "plaintext"
	o.BackupDest = c["backup-dest"]
	o.BackupSchedule = c["backup-schedule"]
	o.BackupKeep, _ = strconv.Atoi(c["backup-keep"])
}
func (o *Options) validateRecordingMount(ctx context.Context, st *state.State) error {
	target := st.Config["recording-mount-target"]
	if target == "" {
		return nil
	}
	mounts, err := o.recordingMounts(ctx)
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if m.Target == target && m.Source == st.Config["recording-mount-source"] && m.FSType == st.Config["recording-mount-type"] {
			return nil
		}
	}
	return fmt.Errorf("selected recording storage at %s is no longer mounted as selected. Reconnect it before continuing", target)
}
