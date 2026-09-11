// Package azure connects this deployment's backups to Azure Blob storage
// that already exists. It signs in, finds the subscription, storage account
// and container the administrator names, checks three different permissions
// separately, and uploads published backups so a remote copy is only ever
// counted as complete when it is whole.
//
// It creates nothing in Azure. There is no code path here that creates a
// storage account or a container, and no code path that deletes one:
// creation is a separate slice (issue #18), and "Preserve remote backups and
// their supporting storage resources during ordinary teardown"
// (specification, "Azure Blob destination") means teardown must leave the
// container alone. Every management-plane call this package makes is a GET —
// see armGet, which is the only ARM helper — so it cannot create or delete a
// management-plane resource even by mistake.
//
// # No SDK
//
// The Azure SDK is very large and this package needs six REST calls. They go
// over the same injectable HTTP seam internal/cloudflare and internal/entra
// use: a Do field, nil meaning http.DefaultClient. Every Blob REST request
// sends x-ms-version: 2021-08-06 (BlobAPIVersion), which supports everything
// used here — Put Blob with Content-MD5 validation, Get Blob Properties, List
// Blobs, Delete Blob — and is old enough to be accepted by every storage
// account in service.
//
// # Two planes, two tokens
//
// Reading the account and its containers is a management-plane operation
// (Azure Resource Manager, https://management.azure.com). Reading and writing
// blobs is a data-plane operation (https://<account>.blob.core.windows.net)
// and needs a token for a different resource. They are different permissions
// and this package checks them separately, because an operator who can see
// the account but cannot write blobs must be told exactly that. TokenSource
// therefore takes the scope it is being asked for.
//
// # Secrets
//
// No token, client secret, or refresh token is ever logged, returned in an
// error, stored in a returned struct field that can be serialised, or written
// to the status file. Errors carry the method, the URL path, the HTTP status,
// and the service's own error code and message, never a header.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	armBase = "https://management.azure.com"

	// Management-plane API versions, pinned so a service change cannot alter
	// behaviour under the tool.
	armSubscriptionsAPI = "2022-12-01" // Subscriptions - List
	armStorageAPI       = "2023-05-01" // Storage Accounts - List, Blob Containers - List
	armAuthorizationAPI = "2022-04-01" // Permissions - List For Resource

	// BlobAPIVersion is the x-ms-version sent on every Blob REST request.
	BlobAPIVersion = "2021-08-06"
)

// Token scopes. The two planes are separate resources and need separate
// tokens; a token for one is rejected by the other.
const (
	ScopeManagement = "https://management.azure.com/.default"
	ScopeStorage    = "https://storage.azure.com/.default"
)

// Client talks to Azure Resource Manager and Blob storage.
type Client struct {
	// Token supplies a bearer token for one scope. Guided runs wire a
	// device-code session; scheduled runs wire a service principal. This
	// package never stores the value it returns.
	Token TokenSource

	// Do sends one HTTP request. nil means http.DefaultClient.Do. Tests
	// replace it to fake every Azure call.
	Do func(*http.Request) (*http.Response, error)
}

func (c *Client) send(req *http.Request) (*http.Response, error) {
	if c.Do != nil {
		return c.Do(req)
	}
	return http.DefaultClient.Do(req)
}

// Error is a non-2xx Azure response, from either plane. It never contains a
// token: only the method, the URL path, the status, and the service's own
// error code and message.
type Error struct {
	Status  int
	Code    string
	Message string
	Method  string
	Path    string
}

func (e *Error) Error() string {
	if e.Code == "" && e.Message == "" {
		return fmt.Sprintf("azure %s %s returned status %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("azure %s %s failed: %s (%s)", e.Method, e.Path, e.Message, e.Code)
}

// Denied reports whether err is an authorization failure (401 or 403), which
// is the answer a permission check needs to tell "you may not" from "it is
// broken".
func Denied(err error) bool {
	var e *Error
	return errors.As(err, &e) &&
		(e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden)
}

// NotFound reports whether err is a 404.
func NotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// armGet performs one management-plane GET. It is the only ARM helper in this
// package, and it takes no body and no method: ARM is used to look at
// existing resources and nothing else, so creating or deleting one is not
// expressible here. Creation belongs to issue #18 and must add its own,
// separately reviewed, helper.
func (c *Client) armGet(ctx context.Context, path string) (json.RawMessage, error) {
	tok, err := c.Token(ctx, ScopeManagement)
	if err != nil {
		return nil, fmt.Errorf("acquire an Azure management token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, armBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.send(req)
	if err != nil {
		// Transport errors name the URL, never the headers.
		return nil, fmt.Errorf("azure GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("azure GET %s: %v", path, err)
	}
	if resp.StatusCode >= 400 {
		return nil, armError(http.MethodGet, path, resp.StatusCode, body)
	}
	return body, nil
}

// armError decodes the ARM error envelope, which is {"error":{"code","message"}}.
func armError(method, path string, status int, body []byte) *Error {
	e := &Error{Status: status, Method: method, Path: path}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil {
		e.Code, e.Message = env.Error.Code, env.Error.Message
	}
	return e
}

// Subscription is one subscription the signed-in identity can see.
type Subscription struct {
	ID    string `json:"subscriptionId"`
	Name  string `json:"displayName"`
	State string `json:"state"`
}

// Subscriptions lists the subscriptions the token can see, for the guided
// selection step. An identity with no subscriptions gets an empty list and no
// error; that is a real answer, and the caller reports it.
func (c *Client) Subscriptions(ctx context.Context) ([]Subscription, error) {
	raw, err := c.armGet(ctx, "/subscriptions?api-version="+armSubscriptionsAPI)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []Subscription `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the subscription list is not readable JSON: %w", err)
	}
	return out.Value, nil
}

// StorageAccount is one existing storage account.
type StorageAccount struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		PrimaryEndpoints struct {
			Blob string `json:"blob"`
		} `json:"primaryEndpoints"`
	} `json:"properties"`
}

// ResourceGroup returns the resource group from the account's resource ID.
// The ID is the authority for this: the group is not a separate field on the
// account, and guessing it from a name would be exactly the "matching name
// establishes ownership" mistake the specification forbids.
func (a StorageAccount) ResourceGroup() string {
	parts := strings.Split(strings.Trim(a.ID, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

// StorageAccounts lists the existing storage accounts in one subscription.
func (c *Client) StorageAccounts(ctx context.Context, subscriptionID string) ([]StorageAccount, error) {
	if subscriptionID == "" {
		return nil, fmt.Errorf("a subscription is needed before storage accounts can be listed")
	}
	raw, err := c.armGet(ctx, "/subscriptions/"+subscriptionID+
		"/providers/Microsoft.Storage/storageAccounts?api-version="+armStorageAPI)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []StorageAccount `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the storage account list is not readable JSON: %w", err)
	}
	return out.Value, nil
}

// Containers lists the containers in one storage account, through the
// management plane.
//
// The management plane is used here rather than the data plane's List
// Containers deliberately: selecting a container during setup is a management
// question, it works for an administrator who holds Reader on the account and
// no data role yet, and it keeps the "can I see the account" permission
// cleanly separate from "can I write blobs", which CheckPermissions tests on
// its own.
func (c *Client) Containers(ctx context.Context, accountID string) ([]string, error) {
	if accountID == "" {
		return nil, fmt.Errorf("a storage account is needed before containers can be listed")
	}
	raw, err := c.armGet(ctx, accountID+"/blobServices/default/containers?api-version="+armStorageAPI)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the container list is not readable JSON: %w", err)
	}
	names := make([]string, 0, len(out.Value))
	for _, v := range out.Value {
		names = append(names, v.Name)
	}
	return names, nil
}

// Destination is the selected, existing place backups are uploaded to. Every
// field is a non-secret reference; the whole struct is safe in deployment
// state and in the status file.
type Destination struct {
	SubscriptionID string `json:"subscription_id"`
	ResourceGroup  string `json:"resource_group"`
	Account        string `json:"account"`
	Container      string `json:"container"`
	AccountID      string `json:"account_id"`    // full ARM resource ID
	BlobEndpoint   string `json:"blob_endpoint"` // https://<account>.blob.core.windows.net
}

// Configured reports whether an Azure destination has been selected.
func (d Destination) Configured() bool {
	return d.Account != "" && d.Container != "" && d.BlobEndpoint != ""
}

// Prefix is where one deployment's objects live inside the container. It
// scopes everything this package writes, lists, and may delete to this
// deployment, so a container shared with another deployment — or with
// anything else at all — is never touched outside this path.
func (d Destination) Prefix(deploymentID string) string {
	return "guacdeploy/" + deploymentID + "/"
}

// Resolve selects an existing subscription, storage account, and container by
// explicit configuration. It creates nothing: a missing account or container
// is an error naming what does exist, never a creation.
//
// Selection is by name because that is what an administrator has, but the
// account's own resource ID — returned by Azure, not built from the name — is
// what every later management call uses.
func (c *Client) Resolve(ctx context.Context, subscriptionID, account, container string) (Destination, error) {
	if subscriptionID == "" || account == "" || container == "" {
		return Destination{}, fmt.Errorf("an Azure destination needs a subscription, a storage account, and a container")
	}
	accounts, err := c.StorageAccounts(ctx, subscriptionID)
	if err != nil {
		return Destination{}, err
	}
	var found *StorageAccount
	for i := range accounts {
		if strings.EqualFold(accounts[i].Name, account) {
			found = &accounts[i]
			break
		}
	}
	if found == nil {
		return Destination{}, fmt.Errorf("storage account %q does not exist in subscription %s, or this identity cannot see it%s; this tool does not create storage accounts",
			account, subscriptionID, availableAccounts(accounts))
	}

	d := Destination{
		SubscriptionID: subscriptionID,
		ResourceGroup:  found.ResourceGroup(),
		Account:        found.Name,
		Container:      container,
		AccountID:      found.ID,
		BlobEndpoint:   strings.TrimSuffix(found.Properties.PrimaryEndpoints.Blob, "/"),
	}
	if d.BlobEndpoint == "" {
		// Sovereign clouds use a different suffix, so the endpoint is taken
		// from the account whenever Azure supplies one. This fallback is the
		// public-cloud form, and it is the only place a name becomes a URL.
		d.BlobEndpoint = "https://" + found.Name + ".blob.core.windows.net"
	}

	names, err := c.Containers(ctx, found.ID)
	if err != nil {
		return d, fmt.Errorf("storage account %s was found, but its containers could not be listed: %w", found.Name, err)
	}
	for _, n := range names {
		if strings.EqualFold(n, container) {
			d.Container = n
			return d, nil
		}
	}
	return d, fmt.Errorf("container %q does not exist in storage account %s%s; this tool does not create containers",
		container, found.Name, availableContainers(names))
}

func availableAccounts(accounts []StorageAccount) string {
	if len(accounts) == 0 {
		return " (this subscription has no storage accounts this identity can see)"
	}
	names := make([]string, 0, len(accounts))
	for _, a := range accounts {
		names = append(names, a.Name)
	}
	return " (visible accounts: " + strings.Join(names, ", ") + ")"
}

func availableContainers(names []string) string {
	if len(names) == 0 {
		return " (the account has no containers)"
	}
	return " (existing containers: " + strings.Join(names, ", ") + ")"
}
