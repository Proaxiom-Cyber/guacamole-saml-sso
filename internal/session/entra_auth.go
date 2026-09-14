package session

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

func (o *Options) selectEntraTenant(st *state.State, u *ui.UI) error {
	if o.EntraTenant == "" {
		o.EntraTenant = st.Config["entra-tenant-id"]
	}
	if o.EntraTenant == "" {
		o.EntraTenant = st.Config["entra-login-tenant"]
	}
	if o.EntraTenant == "" {
		o.EntraTenant = os.Getenv("GUACDEPLOY_ENTRA_TENANT_ID")
	}
	if o.EntraTenant == "" {
		u.Say("Sign in to the Microsoft tenant that will own this deployment's application and groups.")
		var err error
		o.EntraTenant, err = u.Line("Microsoft tenant ID or verified domain", st.Config["cloudflare-zone-name"])
		if err != nil {
			return err
		}
	}
	o.EntraTenant = strings.TrimSpace(o.EntraTenant)
	if strings.ContainsAny(o.EntraTenant, "/\\?# \t\r\n") || o.EntraTenant == "" {
		return errors.New("enter a Microsoft tenant ID or verified domain, without a URL or spaces")
	}
	if st.Config == nil {
		st.Config = map[string]string{}
	}
	st.Config["entra-login-tenant"] = o.EntraTenant
	u.Say("Microsoft sign-in tenant: %s. This sign-in needs administrator consent for application, group, role assignment and organization permissions.", o.EntraTenant)
	return nil
}

func (o *Options) guidedEntraClient() (*entra.Client, error) {
	newSource := o.EntraDeviceToken
	if newSource == nil {
		newSource = entra.DeviceCodeTokenSource
	}
	clientID := o.EntraClientID
	if clientID == "" {
		clientID = os.Getenv("GUACDEPLOY_ENTRA_CLIENT_ID")
	}
	if clientID == "" {
		clientID = entra.GraphCLIClientID
	}
	u := o.UI
	u.Say("Microsoft sign-in uses public client %s. Access and refresh tokens stay in memory for this run.", clientID)
	options := entra.DeviceCodeOptions{TenantID: o.EntraTenant, ClientID: clientID, Prompt: func(ctx context.Context, verificationURL, code string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u.Say("Open %s on your computer or phone.", verificationURL)
		u.Say("Enter sign-in code: %s", code)
		u.Say("Sign in as an administrator of the selected tenant and review the permissions. Waiting for Microsoft sign-in; Ctrl+C cancels.")
		return nil
	}}
	source, err := newSource(options)
	if err != nil {
		return nil, err
	}
	c := &entra.Client{Token: func(ctx context.Context) (string, error) {
		for {
			token, err := source(ctx)
			if err == nil {
				return token, nil
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			u.Say("%s", err)
			choice, chooseErr := u.Choose("Microsoft sign-in", []ui.Choice{{Key: 'r', Label: "Retry Microsoft sign-in"}, {Key: 'q', Label: "Quit and keep deployment progress"}})
			if chooseErr != nil {
				return "", chooseErr
			}
			if choice == 'q' {
				return "", errors.New("Microsoft sign-in stopped. Deployment progress is retained; run setup again and choose Resume")
			}
			source, err = newSource(options)
			if err != nil {
				return "", err
			}
		}
	}}
	if o.Entra != nil {
		c.Do = o.Entra.Do
	}
	o.Entra = c
	return c, nil
}
