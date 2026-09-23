package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func (o *Options) checkCloudflareCredential(ctx context.Context, st *state.State, u *ui.UI, m *creds.Manager, spec creds.Spec) error {
	var value string
	stored := false
	if creds.Persistent(m.Mode) {
		_, err := os.Stat(m.Path(spec))
		stored = err == nil
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot read the Cloudflare credential file: %w", err)
		}
	}
	var err error
	browser := o.CloudflareAuth == "browser" || o.CloudflareAuth == "manual"
	manual := o.CloudflareAuth == "manual"
	if o.CloudflareAuth != "" && o.CloudflareAuth != "browser" && o.CloudflareAuth != "token" && o.CloudflareAuth != "manual" {
		return errors.New("Cloudflare authentication must be browser, manual, or token")
	}
	config := o.cloudflareOAuthConfig()
	if !stored && os.Getenv(spec.EnvVar()) == "" && u.Interactive && o.CloudflareAuth == "" && config.Validate() == nil && (m.Mode == creds.ModeTPM || m.Mode == creds.ModeHostKey) {
		choice, e := u.Choose("Connect Cloudflare", []ui.Choice{{Key: 'b', Label: "Sign in with Cloudflare (recommended)", Description: "Approve access in your browser on another device. Setup waits for the authorization to return automatically."}, {Key: 'm', Label: "Sign in with manual return", Description: "Approve access in your browser, then return the result manually to this terminal. Use this if automatic return is unavailable."}, {Key: 't', Label: "Use an API token", Description: "Provide an existing Cloudflare API token through a hidden prompt. Setup checks access before saving it with your selected protection method."}})
		if e != nil {
			return e
		}
		browser = choice == 'b' || choice == 'm'
		manual = choice == 'm'
	}
	switch {
	case browser:
		if !u.Interactive {
			return errors.New("Cloudflare browser approval needs an interactive setup session; the browser can be on another device")
		}
		if m.Mode != creds.ModeTPM && m.Mode != creds.ModeHostKey {
			return errors.New("Cloudflare browser sign-in needs sealed credentials for renewal; resume with --credentials tpm or --credentials host")
		}
		if config.RelayURL != "" && !manual {
			value, err = config.AuthorizeHosted(ctx, func(address string) error {
				u.Transient("Open this address on your computer or phone:\n%s\n\nApprove Cloudflare access. Setup continues automatically.\nNo browser is needed on this server.", address)
				return nil
			})
			u.ClearTransient()
			if err != nil && ctx.Err() == nil {
				u.Say("%s", err)
				choice, e := u.Choose("Cloudflare sign-in", []ui.Choice{{Key: 'm', Label: "Use manual return instead", Description: "Continue browser authorization with a manual return to this terminal instead of waiting for automatic return."}, {Key: 'q', Label: "Stop and keep progress", Description: "Finish this run and retain recorded progress. Resume later from this host; this does not remove deployment resources."}})
				if e != nil {
					return e
				}
				if choice == 'q' {
					return err
				}
				value = ""
			}
		}
		if value == "" && ctx.Err() == nil {
			value, err = config.Authorize(ctx, func(address string) (string, error) {
				u.Transient("Open this address on your computer or phone:\n%s\n\nApprove Cloudflare access. A localhost connection error is expected.\nCopy the full address from your browser, then paste it below.", address)
				return u.SecretReader()("Paste returned localhost address (hidden)")
			})
		}

		u.ClearTransient()

	case stored, !creds.Persistent(m.Mode):
		value, err = m.Get(spec)
	case os.Getenv(spec.EnvVar()) != "":
		value = os.Getenv(spec.EnvVar())
		u.Say("Taking %s from %s. After validation, it will use the %s method; the environment variable is not needed again.", spec.Name, spec.EnvVar(), m.Mode)
	case u.Interactive:
		value, err = u.SecretReader()("Enter Cloudflare API token (Zone Read, DNS Edit, Tunnel Edit and Access Edit)")
	default:
		return fmt.Errorf("Cloudflare API token is missing. Supply %s and resume setup", spec.EnvVar())
	}
	if err != nil {
		return err
	}
	if cloudflare.IsOAuthCredential(value) && m.Mode == creds.ModeFile {
		return errors.New("Cloudflare browser sign-in cannot use plaintext credential storage")
	}
	changed := !stored || browser
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		value = strings.TrimSpace(value)
		u.Say("Checking Cloudflare access...")
		// Copy the transport seam, but always test the candidate value, not
		// the previous token cached by a client or a credential manager.
		client := cloudflare.Client{}
		if o.Cloudflare != nil {
			client = *o.Cloudflare
		}
		candidate := &creds.Manager{Mode: creds.ModePrompt, Protect: u.Protect}
		if stored && !browser && cloudflare.IsOAuthCredential(value) {
			candidate = m
		}
		candidate.Remember(spec, value)
		client.Token = cloudflare.CredentialTokenSource(candidate, spec, config.HTTP)
		checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if value == "" {
			err = &cloudflare.APIError{Status: http.StatusUnauthorized}
		} else {
			err = client.CheckToken(checkCtx)
		}
		cancel()
		if err == nil {
			value, _ = candidate.Get(spec)
			if cloudflare.IsOAuthCredential(value) {
				changed = true
			}
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if cloudflare.IsOAuthCredential(value) {
			return errors.New("Cloudflare sign-in could not be validated. Check the connection, then resume setup. To replace the sign-in, use --cloudflare-auth browser")
		}
		var apiErr *cloudflare.APIError
		rejected := errors.As(err, &apiErr) && (apiErr.Status == http.StatusBadRequest || apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden)
		message := "Cloudflare could not be reached or returned a temporary error. The token has not been replaced."
		if rejected {
			message = "Cloudflare rejected this token or denied Zone Read access. Check the token, its expiry, permissions and IP restrictions. Use an API token, not the Global API Key."
		}
		// Do not pass a provider response into the transcript or state. It
		// can contain supplied input. Give a bounded, actionable diagnostic.
		u.Say("%s", message)
		if !u.Interactive || m.Mode == creds.ModeEnv {
			if stored {
				return fmt.Errorf("%s Run setup interactively and choose Resume to replace the saved token", message)
			}
			return fmt.Errorf("%s Supply a valid %s and resume setup", message, spec.EnvVar())
		}
		label := "Retry the connection with the same token"
		if rejected {
			label = "Enter a replacement API token"
		}
		choice, chooseErr := u.Choose("Cloudflare token check", []ui.Choice{{Key: 'r', Label: label, Description: "Provide or retry a Cloudflare token and check its access before continuing. Fix expired credentials or missing permissions first."}, {Key: 'q', Label: "Quit and keep deployment progress", Description: "Finish this run and retain recorded progress. Resume later from this host; this does not remove deployment resources."}})
		if chooseErr != nil {
			return chooseErr
		}
		if choice == 'q' {
			return errors.New("Cloudflare token check stopped. Deployment progress is retained; run setup again and choose Resume")
		}
		if rejected {
			value, err = u.SecretReader()("Enter replacement Cloudflare API token")
			if err != nil {
				return err
			}
			changed = true
		}
	}
	if creds.Persistent(m.Mode) && changed {
		createdDir, err := m.Store(ctx, spec, value)
		if err != nil {
			return err
		}
		if createdDir {
			recordCredentialResource(st, "credential-dir", m.Dir)
		}
		kind := "credential-sealed"
		if m.Mode == creds.ModeFile {
			kind = "credential-file"
		}
		if !stored {
			recordCredentialResource(st, kind, filepath.Base(m.Path(spec)))
		}
	}
	m.Remember(spec, value)
	u.Say("Cloudflare access and the Zone Read check passed. Setup will check the selected zone and service permissions next.")
	return nil
}

func recordCredentialResource(st *state.State, kind, name string) {
	for _, r := range st.Resources {
		if r.Provider == "host" && r.Type == kind && r.Name == name {
			return
		}
	}
	st.Resources = append(st.Resources, state.Resource{ID: state.NewID(), Provider: "host", Type: kind, Name: name, Ownership: "written by this deployment", CreatedAt: time.Now().UTC()})
}

func (o *Options) cloudflareOAuthConfig() cloudflare.OAuthConfig {
	c := o.CloudflareOAuth
	if c.RelayURL == "" {
		c.RelayURL = os.Getenv("GUACDEPLOY_CLOUDFLARE_OAUTH_RELAY")
	}
	if c.RelayURL == "" {
		c.RelayURL = cloudflare.OAuthRelayURL
	}
	if c.ClientID == "" {
		c.ClientID = os.Getenv("GUACDEPLOY_CLOUDFLARE_OAUTH_CLIENT_ID")
	}
	if c.ClientID == "" {
		c.ClientID = cloudflare.OAuthClientID
	}
	return c
}
