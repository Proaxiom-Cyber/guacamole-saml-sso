package azure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Management-plane API versions for creation, pinned like the read versions.
const (
	armResourceGroupsAPI = "2021-04-01" // Resource Groups - Create Or Update, List
)

// The ownership marker. One key carries it everywhere this package writes it:
//
//	resource group   -> resource tag             (tags are the marker Azure supports here)
//	storage account  -> resource tag
//	blob container   -> properties.metadata      (containers are ARM proxy resources and
//	                                              carry no tags; metadata is what they have)
//	blob             -> x-ms-meta-<key>          (issue #17, unchanged)
//	role assignment  -> nothing                  (no tag, no metadata, no description field)
//
// The key is ownerMetadata ("guacdeploy_deployment"), reused deliberately: blob
// metadata names must be valid C# identifiers, container metadata names have the
// same rule, and resource tag names allow that spelling too, so one name works
// on all four and an operator looking at the portal sees the same key
// everywhere.
//
// A role assignment has nowhere to put a marker. Its ownership evidence is
// instead its deterministic name (see roleAssignmentName): the name is derived
// from the scope, the principal and the role definition, so this deployment
// recreates exactly the same assignment and never makes a second one.

// Conditions the caller must resolve. None is retried internally.
var (
	// ErrNameTaken: the storage account name is in use somewhere else in
	// Azure. Storage account names are globally unique, so this may be
	// another subscription or another tenant entirely. It is NOT an
	// ownership conflict and says nothing about who owns that account.
	ErrNameTaken = errors.New("the storage account name is already taken elsewhere in Azure")

	// ErrRequiresReview: a resource matches by name but does not carry this
	// deployment's marker. A matching name alone never establishes
	// ownership, so nothing is adopted, changed or duplicated.
	ErrRequiresReview = errors.New("name-only match requires review; a matching name alone never establishes ownership")

	// ErrApprovalRequired: the plan reuses a pre-existing resource group.
	// Reuse is allowed, but only when the administrator approves it.
	ErrApprovalRequired = errors.New("reusing a pre-existing resource group needs approval")
)

// DefaultContainer is the container name used when the operator names none.
// It matches the blob prefix this package already writes under, so a container
// dedicated to the tool reads the same way in the portal.
const DefaultContainer = "guacdeploy"

// AccountName derives this deployment's storage account name candidate.
//
// Storage account names are the hardest name in Azure: 3 to 24 characters,
// lowercase letters and digits only, and globally unique across every tenant.
// A hostname cannot be used as it stands (dots and hyphens are not allowed),
// and a name that is merely descriptive would collide with somebody else's
// account in another tenant.
//
// So the candidate is "gd" + up to 14 characters of the hostname's letters and
// digits + 8 hex characters of SHA-256 over the deployment ID. That is at most
// 24 characters, deterministic (the same deployment derives the same name on
// every run, which is what makes a retry after a lost response hit the same
// resource instead of making a second one), and recognisable to an operator.
// The deployment ID is 128 random bits, so the suffix makes an accidental
// collision with another deployment's account implausible — but not
// impossible, because the name space is global and somebody else's account may
// already hold it. ApplyCreate reports that case as ErrNameTaken, which is a
// different thing from an ownership conflict.
//
// The operator can always supply a name instead (CreateConfig.Account).
func AccountName(hostname, deploymentID string) string {
	h := lowerAlnum(hostname)
	if len(h) > 14 {
		h = h[:14]
	}
	sum := sha256.Sum256([]byte(deploymentID))
	return "gd" + h + hex.EncodeToString(sum[:])[:8]
}

// ResourceGroupName derives the resource group name candidate. Resource group
// names are far more forgiving than account names: up to 90 characters of
// letters, digits, and "-._()". The hostname goes in as it is read, with the
// dots turned into hyphens.
func ResourceGroupName(hostname, deploymentID string) string {
	h := lowerAlnumDash(hostname)
	if h == "" {
		sum := sha256.Sum256([]byte(deploymentID))
		h = hex.EncodeToString(sum[:])[:8]
	}
	name := "guacdeploy-" + h
	if len(name) > 90 {
		name = name[:90]
	}
	return strings.TrimRight(name, "-.")
}

func lowerAlnum(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func lowerAlnumDash(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// ValidateAccountName reports whether a name is a legal storage account name,
// with the rule spelled out rather than "invalid name".
func ValidateAccountName(name string) error {
	if len(name) < 3 || len(name) > 24 {
		return fmt.Errorf("storage account name %q is %d characters; Azure requires 3 to 24", name, len(name))
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("storage account name %q contains %q; Azure allows lowercase letters and digits only, with no hyphens or dots", name, string(r))
		}
	}
	return nil
}

// ValidateContainerName reports whether a name is a legal blob container name.
func ValidateContainerName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return fmt.Errorf("container name %q is %d characters; Azure requires 3 to 63", name, len(name))
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return fmt.Errorf("container name %q contains %q; Azure allows lowercase letters, digits and hyphens only", name, string(r))
		}
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("container name %q starts or ends with a hyphen; Azure does not allow that", name)
	}
	if strings.Contains(name, "--") {
		return fmt.Errorf("container name %q has two hyphens together; Azure does not allow that", name)
	}
	return nil
}

// ValidateResourceGroupName reports whether a name is a legal resource group
// name.
func ValidateResourceGroupName(name string) error {
	if name == "" || len(name) > 90 {
		return fmt.Errorf("resource group name %q is %d characters; Azure requires 1 to 90", name, len(name))
	}
	if strings.HasSuffix(name, ".") {
		return fmt.Errorf("resource group name %q ends with a period; Azure does not allow that", name)
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			strings.ContainsRune("-._()", r)) {
			return fmt.Errorf("resource group name %q contains %q; Azure allows letters, digits and the characters -._() only", name, string(r))
		}
	}
	return nil
}

// CreateConfig is what the administrator chose when they asked for storage to
// be created rather than reused.
type CreateConfig struct {
	SubscriptionID string // required
	Location       string // required: Azure has no default region
	DeploymentID   string // required: the ownership marker's value
	Hostname       string // deployment hostname, for deriving readable names

	// Empty names are derived from Hostname and DeploymentID. A supplied
	// name is used as it is given, after validation.
	ResourceGroup string
	Account       string
	Container     string

	// ApproveExistingResourceGroup lets ApplyCreate put the account into a
	// resource group that already exists and is not this deployment's own.
	// Without it the plan stops with ErrApprovalRequired: reusing somebody
	// else's resource group is a decision for a person.
	ApproveExistingResourceGroup bool
}

// resolved fills in the derived names and validates everything.
func (cfg CreateConfig) resolved() (CreateConfig, error) {
	var missing []string
	for _, f := range []struct{ name, v string }{
		{"SubscriptionID", cfg.SubscriptionID},
		{"Location", cfg.Location},
		{"DeploymentID", cfg.DeploymentID},
	} {
		if f.v == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("creating Azure storage needs %s; there is no default location and nothing is guessed", strings.Join(missing, ", "))
	}
	if cfg.ResourceGroup == "" {
		cfg.ResourceGroup = ResourceGroupName(cfg.Hostname, cfg.DeploymentID)
	}
	if cfg.Account == "" {
		cfg.Account = AccountName(cfg.Hostname, cfg.DeploymentID)
	}
	if cfg.Container == "" {
		cfg.Container = DefaultContainer
	}
	if err := ValidateResourceGroupName(cfg.ResourceGroup); err != nil {
		return cfg, err
	}
	if err := ValidateAccountName(cfg.Account); err != nil {
		return cfg, err
	}
	if err := ValidateContainerName(cfg.Container); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Creation is one intended cloud creation, for the caller to journal with a
// correlation identifier before ApplyCreate runs. Types: resource-group,
// storage-account, blob-container, role-assignment.
type Creation struct {
	Type string
	Name string
}

// Found is an existing Azure resource this plan plans around.
type Found struct {
	Name       string
	ID         string // ARM resource ID, as Azure returned it
	Marker     string // the guacdeploy marker found on it, "" when absent
	ProvenOurs bool   // the marker is this deployment's ID
}

// CreatePlan is what ApplyCreate would do. The caller journals Creations with a
// correlation identifier before calling ApplyCreate, exactly as it does for
// internal/entra and internal/cloudflare.
//
// A nil ResourceGroup, Account or Container means ApplyCreate creates it. A
// non-nil one that is ProvenOurs was created by an earlier run of this
// deployment and is adopted with evidence. A non-nil ResourceGroup that is not
// ProvenOurs is pre-existing and needs approval.
type CreatePlan struct {
	Config        CreateConfig
	ResourceGroup *Found
	Account       *Found
	Container     *Found
	Creations     []Creation
}

// AccountID is the ARM resource ID the plan will create or adopt. For an
// adopted account it is the ID Azure returned; for one not yet created it is
// built from the subscription, the resource group and the name, because a
// resource that does not exist has no ID to read.
func (p *CreatePlan) AccountID() string {
	if p.Account != nil {
		return p.Account.ID
	}
	return accountResourceID(p.Config.SubscriptionID, p.Config.ResourceGroup, p.Config.Account)
}

// NeedsApproval reports whether the plan reuses a pre-existing resource group
// that the administrator has not approved.
func (p *CreatePlan) NeedsApproval() bool {
	return p.ResourceGroup != nil && !p.ResourceGroup.ProvenOurs && !p.Config.ApproveExistingResourceGroup
}

// Summary renders the subscription and every proposed resource for the
// administrator to read before anything is created.
func (p *CreatePlan) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Subscription:   %s\n", p.Config.SubscriptionID)
	fmt.Fprintf(&b, "Location:       %s\n", p.Config.Location)
	line := func(kind, name string, f *Found) {
		switch {
		case f == nil:
			fmt.Fprintf(&b, "%-15s %s (create, tagged %s=%s)\n", kind+":", name, ownerMetadata, p.Config.DeploymentID)
		case f.ProvenOurs:
			fmt.Fprintf(&b, "%-15s %s (already created by this deployment; nothing to do)\n", kind+":", f.Name)
		default:
			fmt.Fprintf(&b, "%-15s %s (pre-existing, not created by this deployment; reuse needs approval)\n", kind+":", f.Name)
		}
	}
	line("Resource group", p.Config.ResourceGroup, p.ResourceGroup)
	line("Storage account", p.Config.Account, p.Account)
	line("Container", p.Config.Container, p.Container)
	b.WriteString("Teardown:       none of this is removed by ordinary teardown; it holds backups.\n")
	return b.String()
}

// PlanCreate reports what creation would do, after querying Azure for what is
// already there.
//
// The query is by ownership marker first and by name second, which is the order
// the specification requires: "After a lost response, query before retrying
// creation... A matching name alone never establishes ownership."
//
// There is no separate "resume" mode. The marker is written in the same request
// that creates the resource, so anything this deployment created carries it,
// and a name-only match is never this deployment's half-landed creation. It is
// somebody else's resource, and the answer is review either way.
func (c *Client) PlanCreate(ctx context.Context, cfg CreateConfig) (*CreatePlan, error) {
	cfg, err := cfg.resolved()
	if err != nil {
		return nil, err
	}
	p := &CreatePlan{Config: cfg}

	if p.ResourceGroup, err = c.findResourceGroup(ctx, cfg); err != nil {
		return nil, err
	}
	if p.ResourceGroup != nil && p.ResourceGroup.ProvenOurs {
		// An adopted group may be named differently from the candidate if
		// the hostname changed between runs. The marker decides, not the
		// name, so the plan follows the group we actually own.
		p.Config.ResourceGroup = p.ResourceGroup.Name
	} else {
		p.Creations = append(p.Creations, Creation{Type: "resource-group", Name: cfg.ResourceGroup})
	}

	if p.Account, err = c.findAccount(ctx, cfg); err != nil {
		return nil, err
	}
	if p.Account != nil {
		p.Config.Account = p.Account.Name
	} else {
		p.Creations = append(p.Creations, Creation{Type: "storage-account", Name: p.Config.Account})
	}

	if p.Account != nil {
		if p.Container, err = c.findContainer(ctx, p.Account.ID, p.Config); err != nil {
			return nil, err
		}
		if p.Container != nil {
			p.Config.Container = p.Container.Name
		}
	}
	if p.Container == nil {
		p.Creations = append(p.Creations, Creation{Type: "blob-container", Name: p.Config.Container})
	}
	return p, nil
}

// resourceGroupRecord is one resource group as ARM returns it.
type resourceGroupRecord struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
}

// findResourceGroup looks for this deployment's resource group by marker, then
// by the planned name.
func (c *Client) findResourceGroup(ctx context.Context, cfg CreateConfig) (*Found, error) {
	// By marker. The tag filter is server-side, so a subscription with
	// thousands of groups still answers with ours.
	q := url.Values{
		"api-version": {armResourceGroupsAPI},
		"$filter":     {fmt.Sprintf("tagName eq '%s' and tagValue eq '%s'", ownerMetadata, cfg.DeploymentID)},
	}
	raw, err := c.armGet(ctx, "/subscriptions/"+cfg.SubscriptionID+"/resourcegroups?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var list struct {
		Value []resourceGroupRecord `json:"value"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("the resource group list is not readable JSON: %w", err)
	}
	// The filter is applied by the service, but it is checked again here:
	// the marker is the evidence of ownership and it is read from the
	// resource itself, never assumed from the query.
	var owned []resourceGroupRecord
	for _, g := range list.Value {
		if g.Tags[ownerMetadata] == cfg.DeploymentID {
			owned = append(owned, g)
		}
	}
	if len(owned) > 1 {
		return nil, fmt.Errorf("%w: %d resource groups carry this deployment's marker (%s); only a person can say which one is right",
			ErrRequiresReview, len(owned), joinNames(owned))
	}
	if len(owned) == 1 {
		return &Found{Name: owned[0].Name, ID: owned[0].ID, Marker: cfg.DeploymentID, ProvenOurs: true}, nil
	}

	// By name. A group that exists under the planned name is pre-existing:
	// it may be created and reused with approval, never adopted silently.
	raw, err = c.armGet(ctx, "/subscriptions/"+cfg.SubscriptionID+"/resourcegroups/"+
		url.PathEscape(cfg.ResourceGroup)+"?api-version="+armResourceGroupsAPI)
	if NotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var g resourceGroupRecord
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("the resource group is not readable JSON: %w", err)
	}
	return &Found{Name: g.Name, ID: g.ID, Marker: g.Tags[ownerMetadata]}, nil
}

func joinNames(groups []resourceGroupRecord) string {
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// findAccount looks for this deployment's storage account by marker, then by
// the planned name.
//
// A name match without the marker is never adopted and never written over: the
// account may be an unrelated one in this subscription, and a storage account
// holds somebody's data.
func (c *Client) findAccount(ctx context.Context, cfg CreateConfig) (*Found, error) {
	accounts, err := c.StorageAccounts(ctx, cfg.SubscriptionID)
	if err != nil {
		return nil, err
	}
	var owned []StorageAccount
	for _, a := range accounts {
		if a.Tags[ownerMetadata] == cfg.DeploymentID {
			owned = append(owned, a)
		}
	}
	if len(owned) > 1 {
		names := make([]string, 0, len(owned))
		for _, a := range owned {
			names = append(names, a.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w: %d storage accounts carry this deployment's marker (%s); only a person can say which one is right",
			ErrRequiresReview, len(owned), strings.Join(names, ", "))
	}
	if len(owned) == 1 {
		return &Found{Name: owned[0].Name, ID: owned[0].ID, Marker: cfg.DeploymentID, ProvenOurs: true}, nil
	}
	for _, a := range accounts {
		if strings.EqualFold(a.Name, cfg.Account) {
			return nil, fmt.Errorf("%w: storage account %q already exists in subscription %s and does not carry this deployment's marker %s=%s. It was not adopted and nothing was written to it. Either approve it by hand, or choose another account name",
				ErrRequiresReview, a.Name, cfg.SubscriptionID, ownerMetadata, cfg.DeploymentID)
		}
	}
	return nil, nil
}

// containerRecord is one blob container as the management plane returns it.
type containerRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Metadata map[string]string `json:"metadata"`
	} `json:"properties"`
}

// containerRecords lists the containers in one storage account with their
// metadata, which is where a container carries its ownership marker.
func (c *Client) containerRecords(ctx context.Context, accountID string) ([]containerRecord, error) {
	if accountID == "" {
		return nil, fmt.Errorf("a storage account is needed before containers can be listed")
	}
	raw, err := c.armGet(ctx, accountID+"/blobServices/default/containers?api-version="+armStorageAPI)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []containerRecord `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the container list is not readable JSON: %w", err)
	}
	return out.Value, nil
}

// findContainer looks for this deployment's container by marker, then by the
// planned name.
func (c *Client) findContainer(ctx context.Context, accountID string, cfg CreateConfig) (*Found, error) {
	list, err := c.containerRecords(ctx, accountID)
	if err != nil {
		return nil, err
	}
	var owned []containerRecord
	for _, v := range list {
		if v.Properties.Metadata[ownerMetadata] == cfg.DeploymentID {
			owned = append(owned, v)
		}
	}
	if len(owned) > 1 {
		names := make([]string, 0, len(owned))
		for _, v := range owned {
			names = append(names, v.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w: %d containers carry this deployment's marker (%s); only a person can say which one is right",
			ErrRequiresReview, len(owned), strings.Join(names, ", "))
	}
	if len(owned) == 1 {
		return &Found{Name: owned[0].Name, ID: owned[0].ID, Marker: cfg.DeploymentID, ProvenOurs: true}, nil
	}
	for _, v := range list {
		if strings.EqualFold(v.Name, cfg.Container) {
			return nil, fmt.Errorf("%w: container %q already exists in storage account %s and does not carry this deployment's marker %s=%s. It was not adopted and nothing was written to it. Either approve it by hand, or choose another container name",
				ErrRequiresReview, v.Name, cfg.Account, ownerMetadata, cfg.DeploymentID)
		}
	}
	return nil, nil
}

// ApplyCreate creates what PlanCreate found missing and returns the selected
// destination.
//
// Every creation is a PUT to a resource ID this package derives from the plan.
// ARM addresses a resource by its ID, and the names in the plan are
// deterministic, so a retry after a lost response writes to the same resource
// ID and cannot produce a second resource group, account or container. The
// marker is in the same request, so a resource that exists after a lost
// response is provably this deployment's own on the next PlanCreate.
//
// It never writes to a resource the plan found without this deployment's
// marker. PlanCreate has already refused that case; this is the second guard.
func (c *Client) ApplyCreate(ctx context.Context, plan *CreatePlan) (Destination, error) {
	if plan == nil {
		return Destination{}, fmt.Errorf("there is no creation plan to apply")
	}
	if plan.NeedsApproval() {
		return Destination{}, fmt.Errorf("%w: resource group %s exists and was not created by this deployment. Approve reuse (CreateConfig.ApproveExistingResourceGroup) or choose another resource group name",
			ErrApprovalRequired, plan.ResourceGroup.Name)
	}
	cfg := plan.Config

	if plan.ResourceGroup == nil {
		if err := c.createResourceGroup(ctx, cfg); err != nil {
			return Destination{}, err
		}
	}

	account := plan.Account
	if account == nil {
		if err := c.createAccount(ctx, cfg); err != nil {
			return Destination{}, err
		}
	}

	// The account is read back from Azure whether it was created now or
	// adopted. Its own resource ID and blob endpoint are the authority for
	// everything later: sovereign clouds do not use the public-cloud blob
	// suffix, a name is not a resource ID, and an adopted account may sit in
	// a different resource group from the one this plan would have created.
	got, err := c.getAccount(ctx, plan.AccountID(), account == nil)
	if err != nil {
		return Destination{}, err
	}
	d := Destination{
		SubscriptionID: cfg.SubscriptionID,
		ResourceGroup:  got.ResourceGroup(),
		Account:        got.Name,
		Container:      cfg.Container,
		AccountID:      got.ID,
		BlobEndpoint:   strings.TrimSuffix(got.Properties.PrimaryEndpoints.Blob, "/"),
	}
	if d.BlobEndpoint == "" {
		d.BlobEndpoint = "https://" + got.Name + ".blob.core.windows.net"
	}

	if plan.Container == nil {
		if err := c.createContainer(ctx, got.ID, cfg); err != nil {
			return d, err
		}
	}
	return d, nil
}

// accountResourceID builds the ARM resource ID of an account that may not
// exist yet. It is the one place in this package where a name becomes a
// resource ID, and it is only legitimate because creation has to address a
// resource that has no ID to read. Every later call uses the ID Azure returns.
func accountResourceID(subscriptionID, resourceGroup, account string) string {
	return "/subscriptions/" + subscriptionID + "/resourceGroups/" + resourceGroup +
		"/providers/Microsoft.Storage/storageAccounts/" + account
}

func (c *Client) createResourceGroup(ctx context.Context, cfg CreateConfig) error {
	body := map[string]any{
		"location": cfg.Location,
		"tags":     map[string]string{ownerMetadata: cfg.DeploymentID},
	}
	err := c.armPut(ctx, "/subscriptions/"+cfg.SubscriptionID+"/resourcegroups/"+
		url.PathEscape(cfg.ResourceGroup)+"?api-version="+armResourceGroupsAPI, body)
	if err != nil {
		return fmt.Errorf("resource group %s could not be created in subscription %s: %w",
			cfg.ResourceGroup, cfg.SubscriptionID, err)
	}
	return nil
}

// createAccount creates the storage account.
//
// The settings are deliberate and not configurable: locally redundant standard
// storage (the backups are a copy of data that also lives on the host),
// StorageV2 with the hot tier, HTTPS only, TLS 1.2 as the floor, no anonymous
// blob access, and shared key access turned off. The last one matters: this
// tool authenticates with Microsoft Entra tokens and never uses an account
// key, so leaving key access on would leave a second, stronger credential
// lying about that nothing here needs.
func (c *Client) createAccount(ctx context.Context, cfg CreateConfig) error {
	body := map[string]any{
		"location": cfg.Location,
		"sku":      map[string]string{"name": "Standard_LRS"},
		"kind":     "StorageV2",
		"tags":     map[string]string{ownerMetadata: cfg.DeploymentID},
		"properties": map[string]any{
			"accessTier":               "Hot",
			"allowBlobPublicAccess":    false,
			"allowSharedKeyAccess":     false,
			"minimumTlsVersion":        "TLS1_2",
			"supportsHttpsTrafficOnly": true,
		},
	}
	path := accountResourceID(cfg.SubscriptionID, cfg.ResourceGroup, cfg.Account) + "?api-version=" + armStorageAPI
	err := c.armPut(ctx, path, body)
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusConflict {
		// Storage account names are globally unique. A conflict here is
		// somebody else's account, possibly in another tenant — it is not
		// an ownership match and says nothing about who holds it.
		return fmt.Errorf("%w: %q. Azure reported %s. Choose another storage account name (CreateConfig.Account); a name in use elsewhere is not evidence that this deployment owns it",
			ErrNameTaken, cfg.Account, e.Message)
	}
	if err != nil {
		return fmt.Errorf("storage account %s could not be created: %w", cfg.Account, err)
	}
	return nil
}

// getAccount reads the account back. Creation is asynchronous — ARM answers
// the PUT before the account exists — so a just-created account is polled until
// Azure reports provisioning finished.
func (c *Client) getAccount(ctx context.Context, accountID string, justCreated bool) (StorageAccount, error) {
	deadline := time.Now().Add(5 * time.Minute)
	for attempt := 0; ; attempt++ {
		raw, err := c.armGet(ctx, accountID+"?api-version="+armStorageAPI)
		if err == nil {
			var a StorageAccount
			if err := json.Unmarshal(raw, &a); err != nil {
				return a, fmt.Errorf("the storage account is not readable JSON: %w", err)
			}
			if !justCreated || strings.EqualFold(a.Properties.ProvisioningState, "Succeeded") {
				return a, nil
			}
		} else if !justCreated || !NotFound(err) {
			return StorageAccount{}, err
		}
		if time.Now().After(deadline) {
			return StorageAccount{}, fmt.Errorf("storage account %s was requested but Azure had not finished creating it after 5 minutes; the request was sent, so query before creating it again", accountID)
		}
		c.nap(10 * time.Second)
	}
}

// createContainer creates the blob container.
//
// The marker goes in the container's metadata. Blob containers are ARM proxy
// resources: they have no tags, and metadata is the only key-value store they
// carry. publicAccess is None, so no blob in it is readable anonymously.
func (c *Client) createContainer(ctx context.Context, accountID string, cfg CreateConfig) error {
	body := map[string]any{
		"properties": map[string]any{
			"publicAccess": "None",
			"metadata":     map[string]string{ownerMetadata: cfg.DeploymentID},
		},
	}
	path := accountID + "/blobServices/default/containers/" + url.PathEscape(cfg.Container) +
		"?api-version=" + armStorageAPI
	if err := c.armPut(ctx, path, body); err != nil {
		return fmt.Errorf("container %s could not be created in storage account %s: %w",
			cfg.Container, cfg.Account, err)
	}
	return nil
}

// armPut performs one management-plane PUT. It is the only management-plane
// write in this package, and it is a PUT: it can create or update a resource
// and it cannot delete one. Together with armGet it is the whole of this
// package's management-plane surface, which is what makes "no container or
// storage account is ever deleted from here" a structural fact rather than a
// promise. TestNoContainerOrAccountDeletionPathExists holds it to that.
// It returns no body: creation is asynchronous, so the reply to a PUT says
// little, and every caller reads the resource back through armGet instead.
func (c *Client) armPut(ctx context.Context, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	tok, err := c.Token(ctx, ScopeManagement)
	if err != nil {
		return fmt.Errorf("acquire an Azure management token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, armBase+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(payload))
	resp, err := c.send(req)
	if err != nil {
		// Transport errors name the URL, never the headers or the body.
		return fmt.Errorf("azure PUT %s: %v", path, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("azure PUT %s: %v", path, err)
	}
	if resp.StatusCode >= 400 {
		return armError(http.MethodPut, path, resp.StatusCode, got)
	}
	return nil
}
