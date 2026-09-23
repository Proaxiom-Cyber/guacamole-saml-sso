package session

import "github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"

var credentialHelp = map[string]string{
	creds.ModeTPM:     "Recommended when available. Credentials are encrypted with systemd using both this host's key and its Trusted Platform Module (TPM). Services can restart without a password prompt. A disk copy alone cannot unlock them. Root on this host can access them; a virtual TPM also trusts the hypervisor. Supply credentials again on a replacement host.",
	creds.ModeHostKey: "Credentials are encrypted using a key stored on this host. Services can restart unattended. This does not use a TPM: someone who obtains both the disk and its key can recover the credentials. Supply credentials again on a replacement host.",
	creds.ModeEnv:     "Read credentials from the process environment. The installer does not save them. You must supply them each run, and arrange a separate way to supply them after reboot. Useful for automation that already manages secrets.",
	creds.ModePrompt:  "Ask for credentials with hidden prompts when needed. Nothing is saved. Someone must provide the credentials after a reboot, so services cannot recover unattended with this option alone.",
	creds.ModeFile:    "Save credentials as plaintext files readable only by their owner. This is an explicit exception with no encryption. Services can restart unattended, but anyone who can copy or read the files has the credentials. Choose this only when that trade-off is acceptable.",
}
