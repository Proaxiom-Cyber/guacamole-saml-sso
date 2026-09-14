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
	switch {
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
	changed := !stored
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		value = strings.TrimSpace(value)
		u.Say("Checking the Cloudflare API token...")
		// Copy the transport seam, but always test the candidate value, not
		// the previous token cached by a client or a credential manager.
		client := cloudflare.Client{}
		if o.Cloudflare != nil {
			client = *o.Cloudflare
		}
		client.Token = func(context.Context) (string, error) { return value, nil }
		checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if value == "" {
			err = &cloudflare.APIError{Status: http.StatusUnauthorized}
		} else {
			err = client.CheckToken(checkCtx)
		}
		cancel()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
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
		choice, chooseErr := u.Choose("Cloudflare token check", []ui.Choice{{Key: 'r', Label: label}, {Key: 'q', Label: "Quit and keep deployment progress"}})
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
	u.Say("Cloudflare accepted the token and the Zone Read check passed. Setup will check the selected zone and service permissions next.")
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
