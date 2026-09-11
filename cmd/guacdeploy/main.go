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
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
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
  version  Print the tool version

Flags for setup:
  --non-interactive        Never prompt; exit 3 where approval is required
  --resume                 Non-interactive only: consent to continue interrupted work
  --install-dependencies   Non-interactive only: consent to install missing dependencies
  --credentials MODE       Credential mode: prompt, env, or file
  --hostname NAME          Public hostname for the deployment
  --admin-group NAME       Identity-provider group for administrators
  --operator-group NAME    Identity-provider group for operators
  --state-dir DIR          Override the state directory (default ` + "/var/lib/guacdeploy" + `)

Flags for backup:
  --dest DIR               Destination directory (default <state-dir>/backups)
  --plaintext              Explicitly write an unencrypted backup

Flags for restore:
  --file PATH              Backup file to restore (required)
  --identity-file PATH     age identity file instead of the passphrase prompt
  --yes                    Unattended consent to replace the database
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
	credMode := fs.String("credentials", "", "credential mode: prompt, env, or file")
	hostname := fs.String("hostname", "", "public hostname for the deployment")
	adminGroup := fs.String("admin-group", "", "identity-provider group for administrators")
	operatorGroup := fs.String("operator-group", "", "identity-provider group for operators")
	verify := fs.Bool("verify", false, "backup-key: demonstrate recovery from the existing export")
	dest := fs.String("dest", "", "backup: destination directory (default <state-dir>/backups)")
	plaintext := fs.Bool("plaintext", false, "backup: explicitly write an unencrypted backup")
	file := fs.String("file", "", "restore: backup file to restore")
	identityFile := fs.String("identity-file", "", "restore: age identity file instead of the passphrase prompt")
	yes := fs.Bool("yes", false, "restore: unattended consent to replace the database")
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
	case "version":
		u.Say("guacdeploy %s", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch {
	case err == nil:
		return 0
	case errors.Is(err, session.ErrApprovalRequired), errors.Is(err, ui.ErrInputRequired):
		fmt.Fprintf(os.Stderr, "guacdeploy: %v\n", err)
		return 3
	case errors.Is(err, context.Canceled):
		return 130
	default:
		fmt.Fprintf(os.Stderr, "guacdeploy: %v\n", err)
		return 1
	}
}
