package entra

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const graphAppID = "00000003-0000-0000-c000-000000000000"

// InstallerApplication belongs to provisioning, separate from the SAML app.
// Its certificate contains public material only.
type InstallerApplication struct {
	ID             string   `json:"id"`
	AppID          string   `json:"appId"`
	DisplayName    string   `json:"displayName"`
	Notes          string   `json:"notes"`
	Tags           []string `json:"tags"`
	SPID           string   `json:"-"`
	KeyCredentials []struct {
		Key string `json:"key"`
	} `json:"keyCredentials"`
}

func InstallerMarker(deploymentID string) string { return Marker(deploymentID) + ":installer" }
func InstallerName(deploymentID string) string   { return "Guacamole Installer (" + deploymentID + ")" }

// collection follows Graph pagination only within the expected Graph API.
func (c *Client) collection(ctx context.Context, path string) ([]json.RawMessage, error) {
	return c.collectionUsing(ctx, path, c.call)
}

func (c *Client) collectionUsing(ctx context.Context, path string, request func(context.Context, string, string, any) (json.RawMessage, error)) ([]json.RawMessage, error) {
	var result []json.RawMessage
	for pages := 0; path != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Graph listing exceeded 100 pages; review the tenant before continuing")
		}
		b, err := request(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value []json.RawMessage `json:"value"`
			Next  string            `json:"@odata.nextLink"`
		}
		if err = json.Unmarshal(b, &page); err != nil {
			return nil, errors.New("Graph returned an unreadable resource list")
		}
		result = append(result, page.Value...)
		path = ""
		if page.Next != "" {
			if !strings.HasPrefix(page.Next, graphBase+"/") {
				return nil, errors.New("Graph returned an unexpected pagination address")
			}
			path = strings.TrimPrefix(page.Next, graphBase)
		}
	}
	return result, nil
}
func (c *Client) FindInstaller(ctx context.Context, deploymentID string) (*InstallerApplication, error) {
	name := InstallerName(deploymentID)
	records, err := c.collection(ctx, "/applications?$filter="+url.QueryEscape("displayName eq '"+strings.ReplaceAll(name, "'", "''")+"'")+"&$select=id,appId,displayName,notes,tags")
	if err != nil {
		return nil, err
	}
	if len(records) > 1 {
		return nil, fmt.Errorf("%w: more than one installer app matches this deployment", ErrRequiresReview)
	}
	if len(records) == 0 {
		return nil, nil
	}
	var app InstallerApplication
	if err = json.Unmarshal(records[0], &app); err != nil || app.ID == "" || app.AppID == "" {
		return nil, errors.New("Graph returned an incomplete installer app")
	}
	marker := InstallerMarker(deploymentID)
	if app.Notes != marker || !slices.Contains(app.Tags, marker) {
		return nil, fmt.Errorf("%w: matching installer app is not owned by this deployment", ErrRequiresReview)
	}
	sps, err := c.collection(ctx, "/servicePrincipals?$filter="+url.QueryEscape("appId eq '"+app.AppID+"'")+"&$select=id")
	if err != nil {
		return nil, err
	}
	if len(sps) > 1 {
		return nil, fmt.Errorf("%w: installer app has multiple service principals", ErrRequiresReview)
	}
	if len(sps) == 1 {
		var sp struct {
			ID string `json:"id"`
		}
		if err = json.Unmarshal(sps[0], &sp); err != nil || sp.ID == "" {
			return nil, errors.New("Graph returned an incomplete installer service principal")
		}
		app.SPID = sp.ID
	}
	return &app, nil
}

// recordedInstaller reads acknowledged identifiers directly. Directory search can
// omit a newly created object; that is never permission to create a replacement.
func (c *Client) recordedInstaller(ctx context.Context, deploymentID string, known InstallerApplication) (*InstallerApplication, error) {
	b, err := c.callFresh(ctx, http.MethodGet, "/applications/"+url.PathEscape(known.ID)+"?$select=id,appId,displayName,notes,tags", nil)
	if err != nil {
		return nil, err
	}
	var app InstallerApplication
	if json.Unmarshal(b, &app) != nil || app.ID != known.ID || app.AppID == "" || (known.AppID != "" && app.AppID != known.AppID) {
		return nil, fmt.Errorf("%w: recorded installer application identifiers do not match", ErrRequiresReview)
	}
	marker := InstallerMarker(deploymentID)
	if app.Notes != marker || !slices.Contains(app.Tags, marker) {
		return nil, ErrNotOwned
	}
	if known.SPID != "" {
		b, err = c.callFresh(ctx, http.MethodGet, "/servicePrincipals/"+url.PathEscape(known.SPID)+"?$select=id,appId,tags", nil)
		if err != nil {
			return nil, err
		}
		var sp struct {
			ID, AppID string
			Tags      []string
		}
		if json.Unmarshal(b, &sp) != nil || sp.ID != known.SPID || sp.AppID != app.AppID || !slices.Contains(sp.Tags, marker) {
			return nil, fmt.Errorf("%w: recorded installer service principal does not match", ErrRequiresReview)
		}
		app.SPID = sp.ID
	} else {
		// A request without an acknowledged ID still needs collection recovery.
		current, err := c.FindInstaller(ctx, deploymentID)
		if err != nil {
			return nil, err
		}
		if current != nil && current.ID == app.ID {
			app.SPID = current.SPID
		}
	}
	return &app, nil
}

// EnsureInstaller is called only after explicit consent to the listed application
// permissions. Checkpoint persists intent BEFORE every mutation, and identifiers
// after it. Pending records a previous request without an acknowledged response.
// A negative read cannot prove such a request failed, so it never blindly retries.
func (c *Client) EnsureInstaller(ctx context.Context, deploymentID string, cert *x509.Certificate, known InstallerApplication, pending string, checkpoint func(string, InstallerApplication) error) (InstallerApplication, error) {
	var zero InstallerApplication
	if cert == nil || checkpoint == nil || deploymentID == "" {
		return zero, errors.New("installer registration requires a certificate and an intent journal")
	}
	var found *InstallerApplication
	var err error
	if known.ID != "" {
		found, err = c.recordedInstaller(ctx, deploymentID, known)
	} else {
		found, err = c.FindInstaller(ctx, deploymentID)
	}
	if err != nil {
		return zero, err
	}
	app := zero
	if found != nil {
		app = *found
	}
	if pending == "application" && found == nil {
		return app, fmt.Errorf("%w: the earlier installer app request has no visible result; wait and resume, or review it in Entra", ErrUncertain)
	}
	// Resolve role identifiers from this tenant's Microsoft Graph service principal.
	roles, err := c.collection(ctx, "/servicePrincipals?$filter="+url.QueryEscape("appId eq '"+graphAppID+"'")+"&$select=id,appRoles")
	if err != nil {
		return app, err
	}
	if len(roles) != 1 {
		return app, errors.New("cannot identify the Microsoft Graph service principal")
	}
	var graph struct {
		ID    string `json:"id"`
		Roles []struct {
			ID, Value          string
			IsEnabled          bool
			AllowedMemberTypes []string
		} `json:"appRoles"`
	}
	if err = json.Unmarshal(roles[0], &graph); err != nil {
		return app, err
	}
	if graph.ID == "" {
		return app, errors.New("Microsoft Graph service principal is missing its identifier")
	}
	required := append(append([]string{}, RequiredPermissions...), "Organization.Read.All")
	roleIDs := map[string]string{}
	access := []map[string]string{}
	for _, name := range required {
		for _, r := range graph.Roles {
			if r.Value == name && r.IsEnabled && slices.Contains(r.AllowedMemberTypes, "Application") {
				roleIDs[name] = r.ID
			}
		}
		if roleIDs[name] == "" {
			return app, fmt.Errorf("Microsoft Graph does not expose the required application permission %s", name)
		}
		access = append(access, map[string]string{"id": roleIDs[name], "type": "Role"})
	}
	if app.ID == "" {
		if pending != "" {
			return app, fmt.Errorf("%w: installer application is missing after an interrupted registration", ErrRequiresReview)
		}
		marker := InstallerMarker(deploymentID)
		body := map[string]any{"displayName": InstallerName(deploymentID), "signInAudience": "AzureADMyOrg", "notes": marker, "tags": []string{marker},
			"requiredResourceAccess": []any{map[string]any{"resourceAppId": graphAppID, "resourceAccess": access}},
			"keyCredentials":         []any{map[string]any{"type": "AsymmetricX509Cert", "usage": "Verify", "key": base64.StdEncoding.EncodeToString(cert.Raw), "displayName": "Guacdeploy host TPM", "startDateTime": cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"), "endDateTime": cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")}}}
		if err = checkpoint("application", app); err != nil {
			return app, err
		}
		b, err := c.call(ctx, http.MethodPost, "/applications", body)
		if err != nil {
			return app, installerMutationError(err, app, checkpoint)
		}
		if err = json.Unmarshal(b, &app); err != nil || app.ID == "" || app.AppID == "" {
			return app, fmt.Errorf("%w: installer app creation returned incomplete identifiers", ErrUncertain)
		}
		if err = checkpoint("", app); err != nil {
			return app, err
		}
	} else {
		b, err := c.call(ctx, http.MethodGet, "/applications/"+url.PathEscape(app.ID)+"?$select=keyCredentials", nil)
		if err != nil {
			return app, err
		}
		var keys InstallerApplication
		if err = json.Unmarshal(b, &keys); err != nil {
			return app, err
		}
		match := false
		for _, k := range keys.KeyCredentials {
			der, e := base64.StdEncoding.DecodeString(k.Key)
			if e == nil && bytes.Equal(der, cert.Raw) {
				match = true
			}
		}
		if !match {
			return app, fmt.Errorf("%w: installer app does not hold this host's certificate; no credentials were replaced", ErrRequiresReview)
		}
		if pending == "application" {
			if err = checkpoint("", app); err != nil {
				return app, err
			}
		}
	}
	createdPrincipal := false
	if app.SPID == "" {
		if pending == "service-principal" {
			return app, fmt.Errorf("%w: the earlier installer service principal request is not visible; wait and resume", ErrUncertain)
		}
		if err = checkpoint("service-principal", app); err != nil {
			return app, err
		}
		b, err := c.createSP(ctx, app.AppID, InstallerMarker(deploymentID))
		if err != nil {
			return app, installerMutationError(err, app, checkpoint)
		}
		var sp struct {
			ID string `json:"id"`
		}
		if err = json.Unmarshal(b, &sp); err != nil || sp.ID == "" {
			return app, fmt.Errorf("%w: installer service principal response is incomplete", ErrUncertain)
		}
		app.SPID = sp.ID
		createdPrincipal = true
		if err = checkpoint("", app); err != nil {
			return app, err
		}
	}
	// Entra can acknowledge creation before another replica can resolve the
	// principal. Retry only explicit replication refusals for this new object;
	// an uncertain POST is still journalled and must be reconciled on resume.
	request := c.call
	if createdPrincipal {
		request = c.callFresh
	}
	granted, err := c.collectionUsing(ctx, "/servicePrincipals/"+url.PathEscape(app.SPID)+"/appRoleAssignments?$select=appRoleId,resourceId", request)
	if err != nil {
		return app, err
	}
	existing := map[string]bool{}
	for _, raw := range granted {
		var r struct {
			AppRoleID  string `json:"appRoleId"`
			ResourceID string `json:"resourceId"`
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			return app, err
		}
		if r.ResourceID == graph.ID {
			existing[r.AppRoleID] = true
		}
	}
	for _, name := range required {
		id := roleIDs[name]
		if existing[id] {
			continue
		}
		if pending == "permission:"+name {
			return app, fmt.Errorf("%w: the earlier %s consent request is not visible; wait and resume", ErrUncertain, name)
		}
		if err = checkpoint("permission:"+name, app); err != nil {
			return app, err
		}
		_, err = request(ctx, http.MethodPost, "/servicePrincipals/"+url.PathEscape(graph.ID)+"/appRoleAssignedTo", map[string]string{"principalId": app.SPID, "resourceId": graph.ID, "appRoleId": id})
		var conflict *GraphError
		if errors.As(err, &conflict) && conflict.Code == "Request_MultipleObjectsWithSameKeyValue" {
			// A stale list can omit an existing grant. Confirm this exact grant
			// with reads only; never treat a generic conflict as success.
			err = c.waitInstallerGrant(ctx, app.SPID, graph.ID, id)
		}
		if err != nil {
			return app, installerMutationError(err, app, checkpoint)
		}
		if err = checkpoint("", app); err != nil {
			return app, err
		}
	}
	return app, checkpoint("", app)
}

func (c *Client) waitInstallerGrant(ctx context.Context, principal, resource, role string) error {
	deadline := time.Now().Add(ReplicationWait)
	for {
		rows, err := c.collection(ctx, "/servicePrincipals/"+url.PathEscape(principal)+"/appRoleAssignments?$select=appRoleId,resourceId")
		if err != nil {
			return err
		}
		for _, raw := range rows {
			var grant struct{ AppRoleID, ResourceID string }
			if err := json.Unmarshal(raw, &grant); err != nil {
				return err
			}
			if grant.AppRoleID == role && grant.ResourceID == resource {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w: Entra reports an existing permission grant, but it is not readable yet; wait and resume", ErrUncertain)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(replicationPoll):
		}
	}
}

func (c *Client) CleanupInstaller(ctx context.Context, deploymentID, id string) error {
	b, err := c.call(ctx, http.MethodGet, "/applications/"+url.PathEscape(id)+"?$select=id,notes,tags", nil)
	var ge *GraphError
	if errors.As(err, &ge) && ge.Status == 404 {
		return nil
	}
	if err != nil {
		return err
	}
	var app InstallerApplication
	if err = json.Unmarshal(b, &app); err != nil {
		return err
	}
	marker := InstallerMarker(deploymentID)
	if app.Notes != marker || !slices.Contains(app.Tags, marker) {
		return ErrNotOwned
	}
	_, err = c.call(ctx, http.MethodDelete, "/applications/"+url.PathEscape(id), nil)
	return err
}

func installerMutationError(err error, app InstallerApplication, checkpoint func(string, InstallerApplication) error) error {
	var ge *GraphError
	if errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500 {
		if saved := checkpoint("", app); saved != nil {
			return saved
		}
	}
	return err
}
