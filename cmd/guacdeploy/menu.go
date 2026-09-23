package main

import (
	"bytes"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/session"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func mainMenu(u *ui.UI, stateDir string) (string, error) {
	for {
		choice, err := u.Choose("Guacamole deployment\n\nChoose what you want to do on this host.\nRemoval always shows a plan before asking for confirmation.", []ui.Choice{
			{Key: 's', Label: "Set up or resume a deployment", Description: "Start guided setup or continue saved work. You can review configuration before deployment changes are applied."},
			{Key: 'v', Label: "View deployment status", Description: "Read the saved deployment status on this host. This does not change services or cloud resources."},
			{Key: 't', Label: "Remove deployment", Description: "Review resources owned by this deployment and choose what to preserve. Nothing is removed until you approve the removal plan."},
			{Key: 'q', Label: "Exit", Description: "Leave the menu and review the final summary before returning to the shell."},
		})
		if err != nil {
			return "", err
		}
		switch choice {
		case 's':
			return "setup", nil
		case 't':
			return "teardown", nil
		case 'q':
			return "", nil
		case 'v':
			var report bytes.Buffer
			err := session.Status(stateDir, &ui.UI{Out: &report})
			if err != nil {
				report.WriteString(u.ErrorText(err))
			}
			if _, err = u.Choose("Deployment status\n\n"+report.String(), []ui.Choice{{Key: 'b', Label: "Back to main menu", Description: "Return to the available deployment actions. This does not change the deployment."}}); err != nil {
				return "", err
			}
		}
	}
}
