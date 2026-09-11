// Command guacdeploy is the single entry point for the Guacamole deployment
// lifecycle: guided setup, unattended setup, status, and (in later slices)
// teardown, backup, and restore.
//
// Exit codes: 0 success, 1 failure, 2 usage, 3 interactive approval
// required, 130 cancelled by the user.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/backup"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/recording"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/schedule"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/settings"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/teardown"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const usage = `Usage: guacdeploy [command] [flags]

Commands:
  setup    Start or resume the deployment (default)
  status   Show the deployment record
  backup-key  Generate the backup recovery key (guided only); --verify demonstrates recovery
  backup   Export the database, encrypted with the backup key, into a directory
  restore  Replace the database from a backup file (asks for consent)
  recordings-run    Back up completed recordings, then enforce the storage budget
  recordings-status Show recording backup and cleanup results
  recordings-enable Turn on recording for a connection
  recordings-restore Recover one recording from a backup
  settings    Show (--list) or restore (--restore) changes made to pre-existing settings
  backup-run  Take the scheduled backup, then expire old backups
  backup-status Show the scheduled backup destination and last-run result
  azure-upload  Copy published backups and completed recordings to Azure Blob
  azure-status  Show the Azure destination and the last upload result
  teardown    Remove what this deployment created, after showing the plan
  stack-start Start the stack after a reboot (used by the installed boot unit)
  renew-cert  Renew the origin certificate now (used by the installed timer)
  cert-status Show the origin certificate and its last renewal result
  version  Print the tool version

Flags for setup:
  --non-interactive        Never prompt; exit 3 where approval is required
  --resume                 Non-interactive only: consent to continue interrupted work
  --install-dependencies   Non-interactive only: consent to install missing dependencies
  --credentials MODE       Credential mode: tpm, host, env, prompt or file
  --hostname NAME          Public hostname for the deployment
  --admin-group NAME       Identity-provider group for administrators
  --operator-group NAME    Identity-provider group for operators
  --zone NAME              Cloudflare zone name (default: the hostname's apex)
  --access-emails LIST     Cloudflare Access allow-list when Entra groups are unavailable
  --acme-contact ADDR      Operator address for the certificate account
  --backup-schedule EXPR   Schedule for backups, a systemd OnCalendar expression (default daily)
  --backup-keep N          Successful backups to retain (default 7)
  --backup-dest DIR        Scheduled backup destination directory
  --require-mount          The backup destination must sit on an approved mounted share
  --no-backup-schedule     Do not install the scheduled backup timer
  --recording-budget SIZE  Local recording storage budget, for example 20GiB
  --state-dir DIR          Override the state directory (default ` + "/var/lib/guacdeploy" + `)

Flags for backup:
  --dest DIR               Destination directory (default <state-dir>/backups)
  --plaintext              Explicitly write an unencrypted backup

Flags for restore:
  --file PATH              Backup file to restore (required)
  --identity-file PATH     age identity file instead of the passphrase prompt
  --yes                    Unattended consent to replace the database

Flags for azure-upload:
  --dest DIR               The local published backup directory to copy from (required)

Flags for teardown:
  --yes                    Unattended consent to remove the listed resources
  --delete-data            Also delete the database, recordings and backups

Flags for settings:
  --list                   Show pending restorations; changes nothing
  --restore                Restore approved settings that have not drifted

Flags for backup-run:
  --dest DIR               Destination directory (required)
  --keep N                 Successful backups to retain (default 7)
  --plaintext              Explicitly write an unencrypted backup
  --require-mount          Fail unless the destination is on the approved mounted share

Flags for the recordings commands:
  --recording-budget SIZE  Storage budget enforced by recordings-run
  --recordings-dir DIR     Recordings directory (default <install-dir>/recordings)
  --dest DIR               Backup destination root for recordings-run
  --connection NAME        recordings-enable: connection to record
  --file PATH              recordings-restore: backup file holding the recording
  --out DIR                recordings-restore: where to write the recovered recording
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	cmd := "setup"
	if len(args) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	nonInteractive := fs.Bool("non-interactive", false, "never prompt")
	resume := fs.Bool("resume", false, "non-interactive: continue interrupted work")
	installDeps := fs.Bool("install-dependencies", false, "non-interactive: consent to install missing dependencies")
	credMode := fs.String("credentials", "", "credential mode: tpm, host, env, prompt or file")
	hostname := fs.String("hostname", "", "public hostname for the deployment")
	adminGroup := fs.String("admin-group", "", "identity-provider group for administrators")
	operatorGroup := fs.String("operator-group", "", "identity-provider group for operators")
	zone := fs.String("zone", "", "Cloudflare zone name (default: the hostname's apex)")
	accessEmails := fs.String("access-emails", "", "comma-separated Cloudflare Access allow-list, used when Entra groups are unavailable")
	acmeContact := fs.String("acme-contact", "", "operator address for the certificate account, e.g. mailto:ops@example.com")
	backupSchedule := fs.String("backup-schedule", "", "systemd OnCalendar expression for scheduled backups (default daily)")
	backupKeep := fs.Int("backup-keep", 0, "successful backups to retain (default 7)")
	backupDest := fs.String("backup-dest", "", "scheduled backup destination directory")
	requireMount := fs.Bool("require-mount", false, "the backup destination must sit on an approved mounted share")
	noBackupSchedule := fs.Bool("no-backup-schedule", false, "do not install the scheduled backup timer")
	keep := fs.Int("keep", 0, "backup-run: successful backups to retain (default 7)")
	recordingBudget := fs.String("recording-budget", "", "local recording storage budget, e.g. 20GiB")
	recordingsDir := fs.String("recordings-dir", "", "recordings directory (default <install-dir>/recordings)")
	connection := fs.String("connection", "", "recordings-enable: connection name to record")
	out := fs.String("out", "", "recordings-restore: directory to write the recovered recording into")
	list := fs.Bool("list", false, "settings: show pending restorations without changing anything")
	restore := fs.Bool("restore", false, "settings: restore approved pre-existing settings")
	verify := fs.Bool("verify", false, "backup-key: demonstrate recovery from the existing export")
	dest := fs.String("dest", "", "backup: destination directory (default <state-dir>/backups)")
	plaintext := fs.Bool("plaintext", false, "backup: explicitly write an unencrypted backup")
	file := fs.String("file", "", "restore: backup file to restore")
	identityFile := fs.String("identity-file", "", "restore: age identity file instead of the passphrase prompt")
	yes := fs.Bool("yes", false, "restore/teardown: unattended consent")
	deleteData := fs.Bool("delete-data", false, "teardown: also delete the database, recordings and backups")
	stateDir := fs.String("state-dir", state.DefaultDir(), "state directory")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	u := ui.New(!*nonInteractive)
	defer u.RestoreTerminal()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig // fires only on a real signal; leaks harmlessly on normal exit
		cancel()
		u.RestoreTerminal()
		fmt.Fprintln(os.Stderr, "\nCancelled. Completed work is saved; run guacdeploy again to resume or clean up.")
		os.Exit(130)
	}()

	var err error
	switch cmd {
	case "setup":
		opts := session.Options{
			StateDir: *stateDir, UI: u, Resume: *resume,
			InstallDependencies: *installDeps, CredentialMode: *credMode,
			Hostname: *hostname, AdminGroup: *adminGroup, OperatorGroup: *operatorGroup,
			Zone: *zone, AccessEmails: *accessEmails, ACMEContact: *acmeContact,
			BackupDest: *backupDest, BackupSchedule: *backupSchedule, BackupKeep: *backupKeep,
			BackupPlaintext: *plaintext, BackupRequireMount: *requireMount,
			NoBackupSchedule: *noBackupSchedule, RecordingBudget: *recordingBudget,
		}
		if s := os.Getenv("GUACDEPLOY_TEST_SLEEP_PHASE"); s != "" {
			// Test hook: replace the registry with a slow phase so session
			// interruption is testable end to end on any development host.
			// No effect unless the variable is set.
			secs, _ := strconv.Atoi(s)
			opts.Phases = []session.Phase{
				{Name: "initialise-deployment", Run: session.Phases(&opts)[0].Run},
				{Name: "test-sleep", Run: func(ctx context.Context, _ *state.State, _ *ui.UI) error {
					select {
					case <-time.After(time.Duration(secs) * time.Second):
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}},
			}
		}
		err = session.Run(ctx, opts)
	case "status":
		err = session.Status(*stateDir, u)
	case "backup-key":
		err = backupKey(*stateDir, *verify, u)
	case "backup":
		err = backupCmd(ctx, backup.ExecRunner, *stateDir, *dest, *plaintext, u)
	case "restore":
		err = restoreCmd(ctx, backup.ExecRunner, *stateDir, *file, *identityFile, *yes, u)
	case "backup-run":
		err = backupRunCmd(ctx, backup.ExecRunner, schedule.Options{
			StateDir: *stateDir, Dest: *dest, Keep: *keep,
			Plaintext: *plaintext, RequireMount: *requireMount,
		}, u)
	case "backup-status":
		err = backupStatusCmd(*stateDir, u)
	case "recordings-run":
		var budget int64
		if *recordingBudget != "" {
			if budget, err = recording.ParseBytes(*recordingBudget); err != nil {
				break
			}
		}
		err = recordingsRunCmd(*stateDir, *recordingsDir, *dest, budget, *plaintext, u)
	case "recordings-status":
		err = recordingsStatusCmd(*stateDir, u)
	case "recordings-enable":
		err = recordingsEnableCmd(ctx, backup.ExecRunner, *stateDir, *connection, u)
	case "recordings-restore":
		err = recordingsRestoreCmd(*stateDir, *file, *out, *identityFile, u)
	case "settings":
		if !*list && !*restore {
			fmt.Fprintln(os.Stderr, "guacdeploy settings: pass --list or --restore")
			return 2
		}
		err = settingsCmd(ctx, *stateDir, *restore, u)
	case "teardown":
		err = teardownCmd(ctx, *stateDir, *yes, *deleteData, u)
	case "azure-upload":
		err = azureUploadCmd(ctx, *stateDir, *dest, u)
	case "azure-status":
		err = azureStatusCmd(*stateDir, u)
	case "stack-start":
		err = stackStartCmd(ctx, *stateDir, u)
	case "renew-cert":
		err = renewCertCmd(ctx, *stateDir, u)
	case "cert-status":
		err = certStatusCmd(*stateDir, u)
	case "version":
		u.Say("guacdeploy %s", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch {
	case err == nil:
		return 0
	case errors.Is(err, session.ErrApprovalRequired), errors.Is(err, ui.ErrInputRequired),
		errors.Is(err, settings.ErrApprovalRequired),
		errors.Is(err, teardown.ErrApprovalRequired), errors.Is(err, teardown.ErrReviewRequired):
		fmt.Fprintf(os.Stderr, "guacdeploy: %v\n", err)
		return 3
	case errors.Is(err, context.Canceled):
		return 130
	default:
		fmt.Fprintf(os.Stderr, "guacdeploy: %v\n", err)
		return 1
	}
}
