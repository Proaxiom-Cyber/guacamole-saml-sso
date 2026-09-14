package session

import (
	"context"
	"crypto/sha1" // Entra's portal displays this public certificate identifier.
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entracert"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
	"github.com/google/uuid"
)

// EntraClientForOperation lets teardown use the same installer identity. It
// acquires credentials lazily and never creates a certificate during teardown.
func EntraClientForOperation(st *state.State, stateDir string, u *ui.UI) *entra.Client {
	o := &Options{StateDir: stateDir, UI: u, entraState: st, EntraTenant: st.Config["entra-tenant-id"]}
	return &entra.Client{Token: func(ctx context.Context) (string, error) {
		c, err := o.entraClient()
		if err != nil {
			return "", err
		}
		return c.Token(ctx)
	}}
}

func (o *Options) manualEntraToken(method string) entra.TokenSource {
	var source entra.TokenSource
	return func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if source != nil {
			return source(ctx)
		}
		st, u := o.entraState, o.UI
		if st == nil {
			return "", errors.New("installer app authentication needs a deployment record; run setup and choose Resume")
		}
		if st.Config == nil {
			st.Config = map[string]string{}
		}
		interactive := u != nil && u.Interactive
		step := func(message string) error {
			if !interactive {
				return nil
			}
			choice, err := u.Choose(message, []ui.Choice{{Key: 'c', Label: "Continue"}, {Key: 'q', Label: "Quit and keep deployment progress"}})
			if err != nil {
				return err
			}
			if choice == 'q' {
				return entraSignInStopped()
			}
			return nil
		}
		if err := step("Open your installer app in https://entra.microsoft.com\nIf you need to create one: App registrations > New registration\nName: Guacamole Installer\nChoose Accounts in this organizational directory only.\nLeave Redirect URI empty, then select Register.\nThis app provisions Guacamole. It is separate from the Guacamole sign-in app.\nThe installer will not delete this manually created app."); err != nil {
			return "", err
		}
		if err := step("In the installer app, select API permissions > Add a permission.\nChoose Microsoft Graph > Application permissions (not Delegated).\nAdd these four permissions:\n" + strings.Join(entra.RequiredPermissions, "\n") + "\nOrganization.Read.All\nSelect Grant admin consent for your tenant.\nA Privileged Role Administrator or Global Administrator can grant this consent."); err != nil {
			return "", err
		}
		var material entracert.Material
		if method == "certificate" {
			if o.StateDir == "" {
				return "", errors.New("the installer certificate needs a state directory")
			}
			dir := filepath.Join(o.StateDir, "credentials")
			_, existingErr := os.Lstat(filepath.Join(dir, entracert.BlobName))
			if errors.Is(existingErr, os.ErrNotExist) {
				// Setup journals the files before generating the key. Other
				// operations only reuse it, and cannot mutate state here.
				if o.journalIntent == nil {
					return "", errors.New("no installer certificate exists on this host; run setup to generate one, or choose client secret")
				}
				if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
					recordCredentialResource(st, "credential-dir", dir)
				}
				recordCredentialResource(st, "credential-file", entracert.BlobName)
				recordCredentialResource(st, "credential-file", entracert.PublicName)
				if err := o.journalIntent("generate a TPM installer key and export its public certificate"); err != nil {
					return "", err
				}
			}
			prepare := o.EntraCertificate
			if prepare == nil {
				prepare = entracert.Prepare
			}
			var err error
			material, err = prepare(ctx, dir, st.DeploymentID, nil)
			if err != nil {
				if !interactive {
					return "", err
				}
				u.Say("%s", err)
				choice, chooseErr := u.Choose("Installer certificate unavailable", []ui.Choice{{Key: 's', Label: "Use a client secret instead"}, {Key: 'q', Label: "Quit and keep deployment progress"}})
				if chooseErr != nil {
					return "", chooseErr
				}
				if choice == 'q' {
					return "", entraSignInStopped()
				}
				method = "secret"
			} else {
				thumb := sha1.Sum(material.Certificate.Raw)
				if err := step(fmt.Sprintf("Copy this public certificate to your workstation:\n%s\n\nFrom your workstation, use your server login:\nssh <user>@<server> 'sudo cat %s' > guacdeploy-installer.cer\n\nOnly the public certificate is copied. The private key remains in the TPM.", material.PublicPath, material.PublicPath)); err != nil {
					return "", err
				}
				if err := step(fmt.Sprintf("Public certificate: %s\nIn Entra, open Certificates & secrets > Certificates > Upload certificate.\nUpload this .cer file, then select Add.\nThumbprint: %X\nExpires: %s\nOnly this public certificate is exported. The private key remains in the TPM.\nOn a replacement VM, generate and upload a new certificate.", material.PublicPath, thumb, material.Certificate.NotAfter.Format("2006-01-02"))); err != nil {
					return "", err
				}
			}
		}
		if method == "secret" {
			if err := step("In the installer app, select Certificates & secrets > Client secrets.\nCreate a secret, or use an existing secret value from your vault.\nCopy the Value, not the Secret ID.\nThe installer asks for it at a hidden prompt and keeps it in memory for this run.\nKeep your own copy for future setup or teardown runs."); err != nil {
				return "", err
			}
		}
		tenant := st.Config["entra-installer-tenant-id"]
		if tenant == "" {
			tenant = st.Config["entra-tenant-id"]
		}
		if tenant == "" {
			tenant = os.Getenv("GUACDEPLOY_ENTRA_TENANT_ID")
		}
		clientID := st.Config["entra-installer-client-id"]
		if clientID == "" {
			clientID = os.Getenv("GUACDEPLOY_ENTRA_CLIENT_ID")
		}
		newSource := o.EntraApplicationToken
		if newSource == nil {
			newSource = entra.ApplicationTokenSource
		}
		for {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			var err error
			if interactive {
				tenant, err = u.Line("Directory (tenant) ID from the installer app Overview", tenant)
				if err != nil {
					return "", err
				}
				clientID, err = u.Line("Application (client) ID from the installer app Overview", clientID)
				if err != nil {
					return "", err
				}
			}
			tenant, clientID = strings.TrimSpace(tenant), strings.TrimSpace(clientID)
			tenantUUID, tenantErr := uuid.Parse(tenant)
			clientUUID, clientErr := uuid.Parse(clientID)
			if tenantErr != nil || clientErr != nil {
				err = errors.New("enter the two IDs from Overview; each must be a GUID, not a domain, object ID or URL")
			} else {
				tenant, clientID = tenantUUID.String(), clientUUID.String()
				if prior := st.Config["entra-tenant-id"]; prior != "" && !strings.EqualFold(prior, tenant) {
					err = errors.New("this deployment already belongs to a different tenant; use its original tenant ID")
				}
			}
			var candidate entra.TokenSource
			var token string
			if err == nil {
				auth := entra.ApplicationOptions{TenantID: tenant, ClientID: clientID}
				if method == "certificate" {
					auth.Certificate, auth.Signer = material.Certificate, material.Signer
				} else {
					auth.Secret = os.Getenv("GUACDEPLOY_ENTRA_CLIENT_SECRET")
					if interactive {
						auth.Secret, err = u.SecretReader()("Installer app client secret Value (hidden; leave blank to stop)")
					}
					if err != nil {
						return "", err
					}
					if auth.Secret == "" {
						return "", errors.New("installer client secret was not supplied; deployment progress is retained")
					}
				}
				candidate, err = newSource(auth)
				if err == nil {
					if interactive {
						u.Say("Checking installer app authentication, application permissions and tenant...")
					}
					checkCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
					token, err = candidate(checkCtx)
					if err == nil {
						probe := &entra.Client{Token: func(context.Context) (string, error) { return token, nil }}
						if o.Entra != nil {
							probe.Do = o.Entra.Do
						}
						expected := o.EntraTenant
						if expected == "" {
							expected = tenant
						}
						err = probe.CheckApplicationAccess(checkCtx, expected)
					}
					cancel()
				}
			}
			if err == nil {
				st.Config["entra-installer-tenant-id"], st.Config["entra-installer-client-id"] = tenant, clientID
				st.Config["entra-auth-method"] = method
				if o.journalIntent != nil {
					if err = o.journalIntent("installer app authentication checked; continuing with the existing deployment"); err != nil {
						return "", err
					}
				}
				source = candidate
				if interactive {
					u.Say("Installer app access verified. Continuing setup. The manually created app remains under your control.")
				}
				return token, nil
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if !interactive {
				return "", err
			}
			u.Say("%s", err)
			choice, chooseErr := u.Choose("Correct the installer app settings in Entra, then retry.", []ui.Choice{{Key: 'r', Label: "Retry and check the IDs and credential"}, {Key: 'q', Label: "Quit and keep deployment progress"}})
			if chooseErr != nil {
				return "", chooseErr
			}
			if choice == 'q' {
				return "", entraSignInStopped()
			}
		}
	}
}
