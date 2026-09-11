package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/azure"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/creds"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/state"
	"github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/ui"
)

// State Config keys for the Azure Blob destination. Every one of them is a
// non-secret reference, as deployment state requires. The client secret is
// not here: it lives in the deployment's credential store under
// azure.ClientSecretCredential.
const (
	azureSubscriptionConfig  = "azure-subscription-id"
	azureResourceGroupConfig = "azure-resource-group"
	azureAccountConfig       = "azure-account"
	azureContainerConfig     = "azure-container"
	azureAccountIDConfig     = "azure-account-id"
	azureBlobEndpointConfig  = "azure-blob-endpoint"
	azureTenantConfig        = "azure-tenant-id"
	azureClientIDConfig      = "azure-client-id"
)

// azureDestinationFrom rebuilds the selected destination from the deployment
// record. The account's ARM resource ID and blob endpoint are recorded at
// selection time, so a scheduled run needs no management-plane call to find
// them again — and needs no management-plane permission at all.
func azureDestinationFrom(st *state.State) azure.Destination {
	return azure.Destination{
		SubscriptionID: st.Config[azureSubscriptionConfig],
		ResourceGroup:  st.Config[azureResourceGroupConfig],
		Account:        st.Config[azureAccountConfig],
		Container:      st.Config[azureContainerConfig],
		AccountID:      st.Config[azureAccountIDConfig],
		BlobEndpoint:   st.Config[azureBlobEndpointConfig],
	}
}

// azureUploadCmd is what the installed timer calls: copy this deployment's
// complete local backups and recording copies into the configured container,
// then record the outcome.
//
// It signs in as the unattended service principal, not as the administrator:
// "Scheduled uploads require unattended authentication independent of the
// administrator's interactive session" (specification). The client secret is
// read at the point of use from the deployment's selected credential
// protection and is never held in state, in the status file, or in a log
// line. See internal/azure/WIRING.md for why a service principal was chosen
// over a stored refresh token, and why managed identity is not available on
// this host.
//
// It reads the deployment record without taking the mutation lock, like the
// recording run and for the same reason: it only reads, and the nightly
// database backup holds that lock for its whole run.
func azureUploadCmd(ctx context.Context, stateDir, dest string, u *ui.UI) error {
	st, err := state.Read(stateDir)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no deployment exists in %s; there is nothing to upload", stateDir)
	}
	d := azureDestinationFrom(st)
	if !d.Configured() {
		return fmt.Errorf("no Azure Blob destination is configured for this deployment; run setup and select an existing storage account and container")
	}
	if dest == "" {
		return fmt.Errorf("an Azure upload needs --dest: the local backup destination it copies from")
	}

	m := &creds.Manager{Mode: st.Config["credential-mode"], Dir: filepath.Join(stateDir, "credentials")}
	principal := &azure.ServicePrincipal{
		App: azure.App{
			TenantID: st.Config[azureTenantConfig],
			ClientID: st.Config[azureClientIDConfig],
		},
		Secret: func() (string, error) {
			return m.Get(creds.Spec{
				Name:    azure.ClientSecretCredential,
				Purpose: "unattended Azure Blob uploads",
			})
		},
	}
	c := &azure.Client{Token: principal.TokenSource()}

	rep, err := azure.Upload(ctx, c, azure.Options{
		Dest: dest, StateDir: stateDir, DeploymentID: st.DeploymentID, Destination: d,
		ClientID: st.Config[azureClientIDConfig], AuthMode: "service-principal",
		OnCalendar: st.Config["azure-upload-schedule"],
	})
	u.Say("%s", rep.Summary())
	return err
}

// azureStatusCmd shows the configured destination and the last upload result.
func azureStatusCmd(stateDir string, u *ui.UI) error {
	u.Say("%s", azure.Summary(stateDir))
	return nil
}
