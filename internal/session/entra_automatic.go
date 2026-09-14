package session

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/entra"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// automaticInstallerToken uses the administrator's device-code authorization
// to register a TPM certificate, then continues using the installer identity.
func (o *Options) automaticInstallerToken(administrator entra.TokenSource) entra.TokenSource {
	var source entra.TokenSource
	return func(ctx context.Context) (string, error) {
		if source != nil {
			return source(ctx)
		}
		st, u := o.entraState, o.UI
		if st == nil || o.journalIntent == nil {
			return "", errors.New("automatic installer registration is available during setup only")
		}
		if st.Config == nil {
			st.Config = map[string]string{}
		}
		choice, err := u.Choose("Set up this host's installer identity\n\n1. Generate a private key inside this host's TPM.\n2. Sign in to Microsoft on your computer with a short code.\n3. Register the public certificate and grant these application permissions:\n"+strings.Join(entra.RequiredPermissions, "\n")+"\nOrganization.Read.All\n\nUse a Privileged Role Administrator or Global Administrator.\nThese tenant-wide permissions let this host provision and remove its Entra resources.\nThe private key stays in the TPM. No certificate transfer is needed.", []ui.Choice{{Key: 'c', Label: "Authorize setup and register the certificate"}, {Key: 'q', Label: "Stop and keep progress"}})
		if err != nil {
			return "", err
		}
		if choice == 'q' {
			return "", entraSignInStopped()
		}
		u.Say("Generating or opening the installer key in this host's TPM...")
		material, err := o.prepareInstallerCertificate(ctx)
		if err != nil {
			return "", err
		}
		u.Say("Host certificate ready. Waiting for administrator authorization.")
		admin := &entra.Client{Token: func(ctx context.Context) (string, error) {
			token, err := administrator(ctx)
			u.Protect(token)
			return token, err
		}}
		if o.Entra != nil {
			admin.Do = o.Entra.Do
		}
		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		// Preserve the device-flow error (including a tenant-policy block)
		// instead of replacing it with a generic pasted-token diagnostic.
		if _, err := admin.Token(checkCtx); err != nil {
			cancel()
			u.ClearTransient()
			return "", err
		}
		tenant, _, err := admin.CheckDeviceCodeToken(checkCtx, o.EntraTenant)
		cancel()
		u.ClearTransient()
		if err != nil {
			return "", err
		}
		if prior := st.Config["entra-tenant-id"]; prior != "" && !strings.EqualFold(prior, tenant) {
			return "", errors.New("the authorized tenant differs from this deployment's tenant")
		}
		st.Config["entra-tenant-id"] = tenant
		checkpoint := func(pending string, app entra.InstallerApplication) error {
			st.Config["entra-installer-pending"] = pending
			st.Config["entra-installer-tenant-id"] = tenant
			if app.AppID != "" {
				st.Config["entra-installer-client-id"] = app.AppID
			}
			record := func(kind, id string) {
				if id == "" {
					return
				}
				for _, r := range st.Resources {
					if r.Provider == "entra" && r.Type == kind && r.ProviderID == id {
						return
					}
				}
				st.Resources = append(st.Resources, state.Resource{ID: state.NewID(), Provider: "entra", Type: kind, ProviderID: id, Name: entra.InstallerName(st.DeploymentID), Ownership: "marker " + entra.InstallerMarker(st.DeploymentID) + " on the installer application", CreatedAt: time.Now().UTC()})
			}
			record("installer-application", app.ID)
			record("installer-service-principal", app.SPID)
			return o.journalIntent("installer certificate registration: " + pending)
		}
		u.Say("Administrator authorized the selected tenant. Registering the host certificate...")
		applyCtx, applyCancel := context.WithTimeout(ctx, 2*time.Minute)
		app, err := admin.EnsureInstaller(applyCtx, st.DeploymentID, material.Certificate, st.Config["entra-installer-pending"], checkpoint)
		applyCancel()
		if err != nil {
			return "", err
		}
		factory := o.EntraApplicationToken
		if factory == nil {
			factory = entra.ApplicationTokenSource
		}
		candidate, err := factory(entra.ApplicationOptions{TenantID: tenant, ClientID: app.AppID, Certificate: material.Certificate, Signer: material.Signer})
		if err != nil {
			return "", err
		}
		// Persist the registration before checking the new identity. Directory
		// replication may delay its first token; resume reuses the same identity.
		st.Config["entra-auth-method"] = "certificate"
		if err = checkpoint("", app); err != nil {
			return "", err
		}
		u.Say("Certificate registered. Checking the installer identity and its permissions...")
		probe := &entra.Client{Token: candidate, Do: admin.Do}
		verifyCtx, verifyCancel := context.WithTimeout(ctx, 45*time.Second)
		defer verifyCancel()
		if err = probe.CheckApplicationAccess(verifyCtx, tenant); err != nil {
			return "", err
		}
		source = candidate
		u.Say("Microsoft Entra connected. This host can authenticate with its TPM certificate on future runs.")
		return source(ctx)
	}
}
