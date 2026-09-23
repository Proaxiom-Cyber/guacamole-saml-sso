package main

import (
	"context"
	"errors"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/host"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// Retry starts a new operation against saved state; it never bypasses ownership
// checks or repeats a cloud mutation directly.
func runWithRecovery(ctx context.Context, u *ui.UI, command string, run func() error) error {
	for {
		err := run()
		if err == nil || !u.Interactive || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return err
		}
		title, guidance := recoveryGuidance(err)
		resume := "sudo /usr/local/bin/guacdeploy " + command
		prompt := title + "\n\n" + guidance + "\n\nCompleted work is saved.\nContinue later with:\n" + resume
		choices := []ui.Choice{{Key: 'r', Label: "Retry from saved progress", Description: "Try the operation again using saved state. Resolve the reported problem first; retrying alone may produce the same error."}, {Key: 'v', Label: "View technical details", Description: "Read the full error and session log location. This does not retry or change anything."}, {Key: 'q', Label: "Save and exit", Description: "Finish this run and retain recorded progress. Resume later from this host; this does not remove deployment resources."}}
		if strings.Contains(strings.ToLower(err.Error()), "ratelimited") {
			choices = []ui.Choice{{Key: 'v', Label: "View the certificate authority response and retry time", Description: "Read why issuance was refused and when another attempt is allowed. This does not request another certificate."}, {Key: 'q', Label: "Save progress and finish", Description: "Finish this run and retain recorded progress. Resume later from this host; this does not remove deployment resources."}}
		}
		if errors.Is(err, host.ErrRebootRequired) {
			prompt += "\n\nAfter leaving this screen, run: sudo reboot\nReconnect over SSH, then run the command above."
			choices = []ui.Choice{{Key: 'q', Label: "Return to the shell to reboot", Description: "Finish this session so you can restart the host. This choice does not reboot it automatically. Reconnect and resume after reboot."}, {Key: 'v', Label: "View technical details", Description: "Read the full error and session log location. This does not retry or change anything."}}
		}
		for {
			choice, inputErr := u.Choose(prompt, choices)
			if inputErr != nil {
				return inputErr
			}
			if choice == 'q' {
				u.Summary(title+". Progress is saved.", "Continue with: "+resume)
				return err
			}
			if choice == 'r' {
				break
			}
			if choice == 'v' {
				_, inputErr = u.Choose("Technical details\n\n"+u.ErrorText(err)+"\n\nSession log: "+u.LogPath(), []ui.Choice{{Key: 'b', Label: "Back to recovery options", Description: "Return to the choices for handling this error. No operation is retried yet."}})
				if inputErr != nil {
					return inputErr
				}
			}
		}
	}
}

func recoveryGuidance(err error) (string, string) {
	if errors.Is(err, host.ErrRebootRequired) {
		return "Reboot required", "The required kernel packages are installed. Restart the host to load the kernel and modules before setup can continue."
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "ratelimited") || strings.Contains(text, "too many certificates") {
		return "Certificate issuance limit reached", "The certificate authority has temporarily refused another certificate. View technical details for its retry time. Retrying now will not help. Keep this deployment and resume after that time; do not remove it to retry. Completed work is saved."
	}
	if strings.Contains(text, "hostnamenotonverifieddomain") || (strings.Contains(text, "identifieruris") && strings.Contains(text, "verified domain")) {
		return "Entra rejected the application identifier", "Entra refused the SAML application identifier under its domain policy. Keep the website and tenant settings unchanged. Use a current installer that supports separate website and application identifiers. Review the technical details before retrying."
	}
	if strings.Contains(text, "identifieruris") && strings.Contains(text, "already exists") {
		return "Entra application already exists", "Another Entra application uses this site's identifier URI. Review that application in Entra before retrying. Do not delete an application used by another deployment."
	}
	if strings.Contains(text, "pre-existing") && strings.Contains(text, "access application") {
		return "Cloudflare Access application already exists", "An existing Access application covers this hostname. Review it in Cloudflare Zero Trust and resolve the conflict, then retry. The installer will not overwrite it."
	}
	if strings.Contains(text, "pre-existing") && strings.Contains(text, "dns") {
		return "DNS record already exists", "An existing DNS record uses this hostname. Review it in Cloudflare DNS and resolve the conflict, then retry. The installer will not overwrite it."
	}
	return "This step needs attention", "The operation stopped. Review the details to identify the cause, resolve it, then retry. Keep the session log if you need help."
}
