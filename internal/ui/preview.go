package ui

import (
	"context"
	"fmt"
	"time"
)

// Preview exercises the real terminal components with labelled example data.
// It performs no network calls, credential operations or deployment changes.
func (u *UI) Preview(ctx context.Context) error {
	defer u.Summary("Preview closed. No deployment resources were changed.")
	names := []string{"host-preflight", "credential-mode", "host-dependencies", "stack-configure", "cloudflare-tunnel", "stack-up", "entra-signin", "cloudflare-access", "cloudflare-connect"}
	u.PhaseList(names)
	for _, name := range names[:6] {
		u.PhaseSkipped(name)
	}
	u.PhaseStart("entra-signin")
	u.Say("PREVIEW ONLY. Example deployment: guac.example.com. No resources will be created.")
	for {
		c, err := u.Choose("Connect Microsoft Entra\n\nMicrosoft sign-in authorizes setup. The host certificate authenticates the installer.\nThe recommended path does both, without copying a certificate or a token.", []Choice{{'d', "Connect with Microsoft: device code + host certificate"}, {'a', "Device code blocked: register the installer app yourself"}, {'p', "Preview task progress and logo animation"}, {'e', "Preview a recoverable failure"}, {'q', "Close preview"}})
		if err != nil {
			return err
		}
		if c == 'q' {
			return nil
		}
		if c == 'p' {
			u.PhaseStart("host-preflight")
			for i := 0; i <= 3; i++ {
				u.TaskProgress("PREVIEW: network checks completed", i, 3)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Second):
				}
			}
			u.PhaseDone("host-preflight")
			u.PhaseStart("entra-signin")
			continue
		}
		if c == 'e' {
			u.PhaseFailed("entra-signin", fmt.Errorf("Microsoft sign-in was blocked by tenant policy. Use manual app registration to continue"))
			c, err = u.Choose("Progress is saved. Choose the manual registration path, or try sign-in again.", []Choice{{'c', "Back to sign-in choices"}, {'q', "Close preview"}})
			if err != nil {
				return err
			}
			if c == 'q' {
				return nil
			}
			u.PhaseStart("entra-signin")
			continue
		}
		if c == 'a' {
			_, err = u.Choose("Register the installer app in your browser\n\nOpen https://entra.microsoft.com\nGo to App registrations > New registration.\nName: Guacamole Installer\nChoose Accounts in this organizational directory only.\nLeave Redirect URI empty, then select Register.\n\nNext: grant application permissions and upload this host's public certificate.", []Choice{{'c', "Back to preview"}})
			if err != nil {
				return err
			}
			continue
		}
		u.Say("PREVIEW: the host certificate is ready. Waiting for administrator authorization.")
		u.Transient("PREVIEW ONLY — do not sign in\n\nYour browser will open Microsoft's device sign-in page.\nA temporary code will appear here.\n\nThis screen continues after Microsoft accepts the sign-in.")
		select {
		case <-ctx.Done():
			u.ClearTransient()
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
		u.ClearTransient()
		u.Say("PREVIEW: certificate registered. Installer identity verified.")
		u.PhaseDone("entra-signin")
		c, err = u.Choose("Microsoft Entra connected\n\nThe host can now authenticate with its TPM certificate.\nThe private key stays in the TPM.\n\nIn a real deployment, setup now configures Guacamole sign-in and access groups.", []Choice{{'r', "Replay preview"}, {'q', "Close preview"}})
		if err != nil {
			return err
		}
		if c == 'q' {
			return nil
		}
		u.PhaseStart("entra-signin")
	}
}
