package session

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

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
	options := entra.DeviceCodeOptions{TenantID: o.EntraTenant, ClientID: clientID, Prompt: func(ctx context.Context, verificationURL, code string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		u.Say("Open %s on your computer or phone.", verificationURL)
		u.Say("Enter sign-in code: %s", code)
		u.Say("Sign in as an administrator of the selected tenant and review the permissions. Waiting for Microsoft sign-in; Ctrl+C cancels.")
		return nil
	}}
	// Select on first use, so callers can construct a client without prompting.
	// A browser token is supplied by Graph Explorer; it needs no callback server.
	var source entra.TokenSource
	browser := false
	c := &entra.Client{Token: func(ctx context.Context) (string, error) {
		for {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if source == nil {
				choice, err := u.Choose("Microsoft sign-in method", []ui.Choice{
					{Key: 'd', Label: "Device code: sign in with a short code"},
					{Key: 'b', Label: "Browser: Graph Explorer, then paste an access token"},
					{Key: 'q', Label: "Quit and keep deployment progress"},
				})
				if err != nil {
					return "", err
				}
				switch choice {
				case 'q':
					return "", entraSignInStopped()
				case 'b':
					browser = true
					source = o.browserEntraToken()
				default:
					u.Say("Microsoft sign-in uses public client %s. Access and refresh tokens stay in memory for this run.", clientID)
					source, err = newSource(options)
					if err != nil {
						return "", err
					}
				}
			}
			token, err := source(ctx)
			if err == nil {
				return token, nil
			}
			if browser {
				return "", err // Browser input handles correction; blank input or cancellation stops.
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			u.Say("%s", err)
			choice, chooseErr := u.Choose("Microsoft sign-in", []ui.Choice{{Key: 'r', Label: "Retry Microsoft sign-in"}, {Key: 'b', Label: "Use Graph Explorer in a browser instead"}, {Key: 'q', Label: "Quit and keep deployment progress"}})
			if chooseErr != nil {
				return "", chooseErr
			}
			if choice == 'q' {
				return "", entraSignInStopped()
			}
			if choice == 'b' {
				browser = true
				source = o.browserEntraToken()
			} else {
				source, err = newSource(options)
				if err != nil {
					return "", err
				}
			}
		}
	}}
	if o.Entra != nil {
		c.Do = o.Entra.Do
	}
	o.Entra = c
	return c, nil
}

func entraSignInStopped() error {
	return errors.New("Microsoft sign-in stopped. Deployment progress is retained; run setup again and choose Resume")
}

func (o *Options) browserEntraToken() entra.TokenSource {
	u := o.UI
	introduced := false
	var cached string
	var expires time.Time
	boundTenant := o.EntraTenant
	return func(ctx context.Context) (string, error) {
		for {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if !introduced {
				// Keep each instruction on screen until the operator is ready.
				// A stream of status lines disappears from a small wizard window.
				steps := []string{
					"Open https://developer.microsoft.com/graph/graph-explorer\nSign in as an administrator. Select tenant " + o.EntraTenant + ".",
					"Under your profile, choose Consent to permissions.\nGrant these delegated permissions:\n" + strings.Join(entra.RequiredPermissions, "\n") + "\nOrganization.Read.All\nThen open the Access token tab and copy the token.",
				}
				for _, step := range steps {
					choice, err := u.Choose(step, []ui.Choice{{Key: 'c', Label: "Continue"}, {Key: 'q', Label: "Quit and keep deployment progress"}})
					if err != nil {
						return "", err
					}
					if choice == 'q' {
						return "", entraSignInStopped()
					}
				}
				u.Say("The browser token stays in memory for this run. Tenant policy still applies.")
				introduced = true
			}
			if cached != "" && (expires.IsZero() || expires.After(time.Now().Add(time.Minute))) {
				return cached, nil
			}
			if cached != "" {
				u.Say("The browser token will expire shortly. Copy a fresh access token from Graph Explorer to continue.")
				cached = ""
			}
			token, err := u.SecretReader()("Paste Microsoft Graph access token (hidden; leave blank to stop)")
			if err != nil {
				return "", err
			}
			token = strings.TrimSpace(token)
			if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
				token = strings.TrimSpace(token[7:])
			}
			if token == "" {
				return "", entraSignInStopped()
			}
			u.Say("Checking Microsoft Graph access, permissions and the selected tenant...")
			probe := &entra.Client{Token: func(context.Context) (string, error) { return token, nil }}
			if o.Entra != nil {
				probe.Do = o.Entra.Do
			}
			tenant, expiry, err := probe.CheckBrowserToken(ctx, boundTenant)
			if err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				u.Say("%s", err)
				continue
			}
			cached, expires, boundTenant = token, expiry, tenant
			u.Say("Microsoft Graph accepted the token for the selected tenant. Continuing setup.")
			return cached, nil
		}
	}
}
