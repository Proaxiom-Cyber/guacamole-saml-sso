package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Setup is the guided choice of an Azure Blob destination: sign in, pick a
// subscription, reuse or create the storage, prove the permissions, and hand
// the parent everything it has to record.
//
// Every primitive it uses already exists in this package. What this file adds
// is the order they go in, the questions between them, and the refusals: no
// creation without approval, no destination recorded without blob data access
// proved by a real write.
//
// # Nothing here has been run against Azure
//
// No live Azure sign-in has ever been made in this project. Every path in this
// file is exercised by unit tests against a fake HTTP transport and nothing
// else. A device-code flow completed by a person, a real subscription listing,
// a real storage account creation, a real role assignment taking effect —
// none of it has been demonstrated. Live verification is still required before
// this is accepted (specification acceptance A18).
//
// # Secrets
//
// The device code's user code and verification URL are shown to the
// administrator because the flow cannot work otherwise. Nothing else leaves:
// the device code itself, the access token and the refresh token stay inside
// DeviceCode and Session, which have String methods for exactly this reason.
// No Result field holds a credential, and none is written to any error here.

// Setup drives the guided Azure destination flow and returns what the parent
// must persist.
//
// An Azure destination is optional. An administrator who declines gets a
// Result with Configured false and a Reason, and no error: choosing a local
// destination is not a failure.
//
// Result.Created is filled in even when Setup returns an error. A resource
// that was created must be recorded whether or not the rest of the flow
// finished, or teardown's ownership record is a lie.
func Setup(ctx context.Context, o SetupOptions) (Result, error) {
	if err := o.defaults(); err != nil {
		return Result{}, err
	}
	var res Result

	// The offer is only put when nothing has already answered it. An operator
	// who named a subscription, an account, a container or --azure-create on
	// the command line has chosen Azure already.
	if !o.preselected() {
		yes, err := o.Confirm("Upload backups to Azure Blob storage? It is optional: local directories and mounted shares work without it.")
		if err != nil {
			return res, err
		}
		if !yes {
			return o.declined(&res, "the administrator did not choose Azure Blob storage"), nil
		}
	}

	c, err := o.signIn(ctx)
	if err != nil {
		return res, err
	}

	sub, err := o.subscription(ctx, c)
	if err != nil {
		return res, err
	}
	res.SubscriptionID = sub.ID

	d, err := o.destination(ctx, c, sub, &res)
	if err != nil {
		return res, err
	}
	if res.Reason != "" {
		// Creation was the only route left and it was declined. That is a
		// choice, not a failure.
		return res, nil
	}
	res.Destination = d

	// Permissions, against storage that now exists. All three checks run and
	// all three are shown: "can see the account but cannot write blobs" is the
	// common half-configured case and it has its own fix.
	pre, err := c.CheckPermissions(ctx, d, o.DeploymentID)
	if err != nil {
		return res, err
	}
	res.Preflight = pre
	o.Say("%s", strings.TrimRight(pre.Summary(), "\n"))
	if !pre.Management.OK {
		return res, fmt.Errorf("the Azure destination was not recorded: %w", pre.Err())
	}

	if err := o.grantUploaderRole(ctx, c, d, &res); err != nil {
		return res, err
	}

	// Blob data access is the one permission a backup cannot do without, and
	// the only evidence accepted for it is a write that actually happened:
	// either the administrator's own probe, or the unattended uploader's probe
	// after the role took effect. Nothing else counts.
	switch {
	case res.RoleEffective != nil && res.RoleEffective.OK:
		res.BlobDataProvenBy = "the unattended uploader, by a real write after the role took effect"
	case pre.BlobData.OK:
		res.BlobDataProvenBy = "the signed-in administrator, by a real write"
	default:
		return res, fmt.Errorf("the Azure destination was not recorded: blob data access to container %s in storage account %s has not been proved. %s. To fix: %s",
			d.Container, d.Account, o.unprovenDetail(res, pre), o.unprovenFix(res, pre))
	}

	res.Configured = true
	o.Say("Azure destination ready: container %s in storage account %s (%s). Blob data access proved by %s.",
		d.Container, d.Account, d.BlobEndpoint, res.BlobDataProvenBy)
	return res, nil
}

// SetupOptions is what the guided flow needs. Every question is asked through
// a function field, so the flow runs in a test with no terminal and, with
// every answer supplied ahead of it, in an unattended run with no questions
// at all.
type SetupOptions struct {
	// App is the guided sign-in. ClientID defaults to the Azure CLI public
	// client, which is pre-consented in every tenant, so a first sign-in needs
	// no application registration.
	App App

	// DeploymentID is required: it is the ownership marker written on
	// everything this run creates, and the prefix everything is written under.
	DeploymentID string
	// Hostname is used only to derive readable names for created resources.
	Hostname string

	// Answers supplied ahead of the run, from the command line. An empty field
	// is asked for through the seam below.
	SubscriptionID string
	Account        string
	Container      string

	// Create asks for storage to be created rather than selected. The flow
	// also reaches creation when the administrator picks it from the menu.
	Create        bool
	Location      string // required to create; Azure has no default region
	ResourceGroup string
	// ApproveExistingResourceGroup pre-approves reuse of a resource group that
	// already exists and is not this deployment's own. Without it — and
	// without an interactive approval — creation stops.
	ApproveExistingResourceGroup bool

	// UploaderObjectID is the unattended service principal's object ID (the
	// enterprise application's object ID, not the application ID). When it is
	// empty no role is granted, and the result says plainly that scheduled
	// uploads will fail until somebody grants it.
	UploaderObjectID string
	// Uploader is a Client signed in as that service principal. It is the only
	// thing that can prove the granted role works, because the role is granted
	// to it and not to the administrator. nil means the grant is not verified,
	// which is reported and never treated as proof.
	Uploader *Client
	// RoleWait tunes the poll that waits for the role to take effect. The zero
	// value polls every 10 seconds for 5 minutes.
	RoleWait RoleWait

	// The interaction seam. Say is required: the device sign-in code has to
	// reach a person. The three question seams default to refusing, so an
	// unattended run that reaches a question it was not given the answer to
	// stops rather than answering on the administrator's behalf.
	Say     func(format string, args ...any)
	Ask     func(prompt, def string) (string, error)
	Confirm func(question string) (bool, error)
	Choose  func(prompt string, options []string) (int, error)

	// Journal records the intended creations before anything is created in
	// Azure. It is the parent's journal — a state.Action with a correlation
	// identifier — and creation does not start until it returns. Creating
	// without it is refused: an intent that is not on disk before the request
	// is sent cannot be reconciled after a lost response.
	Journal func(creations []Creation) error

	// Do sends one HTTP request to Azure. nil means http.DefaultClient. Tests
	// replace it; App.Do is the separate seam for the identity platform.
	Do func(*http.Request) (*http.Response, error)
	// Sleep waits between polls of an asynchronous creation. nil means
	// time.Sleep.
	Sleep func(time.Duration)
}

// Created is one resource, with the ownership evidence the parent records in
// its deployment state. The Result keeps created and reused resources in
// separate lists so the caller never has to work out which is which: teardown
// removes nothing in Azure either way, but the record of what this deployment
// made has to be honest.
type Created struct {
	Type       string `json:"type"` // resource-group, storage-account, blob-container, role-assignment
	Name       string `json:"name"`
	ProviderID string `json:"provider_id"` // ARM resource ID
	Ownership  string `json:"ownership"`   // how ownership is evidenced, for the record
}

// Result is what the guided flow decided.
type Result struct {
	// Configured is the only flag the parent may test before recording the
	// destination. It is true only when storage was selected or created AND
	// blob data access was proved by a real write.
	Configured bool `json:"configured"`
	// Reason says why no destination was configured. It is empty when one was.
	Reason string `json:"reason,omitempty"`

	SubscriptionID string      `json:"subscription_id,omitempty"`
	Destination    Destination `json:"destination"`
	// Location is the region storage was created in. It is empty on the reuse
	// path, where the region is the existing account's and nothing chose it.
	Location string `json:"location,omitempty"`

	// Created is what this run made. Record one state.Resource each.
	Created []Created `json:"created,omitempty"`
	// Reused is what this run found and used without creating it.
	Reused []Created `json:"reused,omitempty"`
	// Planned is the intent that was journalled before creation started.
	Planned []Creation `json:"planned,omitempty"`

	// Preflight is the administrator's three permission checks.
	Preflight Preflight `json:"preflight"`
	// RoleAssignment is the uploader's granted role, nil when none was granted.
	RoleAssignment *RoleAssignment `json:"role_assignment,omitempty"`
	// RoleEffective is the proof that the granted role works, nil when no role
	// was granted. A non-nil check that is not OK means the role was granted
	// and had not taken effect yet.
	RoleEffective *Check `json:"role_effective,omitempty"`
	// BlobDataProvenBy names the identity whose real write proved blob data
	// access. It is empty when no destination was configured.
	BlobDataProvenBy string `json:"blob_data_proven_by,omitempty"`
}

func (o *SetupOptions) declined(res *Result, reason string) Result {
	res.Reason = "no destination configured: " + reason
	o.Say("No Azure destination configured: %s. Backups stay in the local destination only.", reason)
	return *res
}

func (o *SetupOptions) defaults() error {
	if o.DeploymentID == "" {
		return fmt.Errorf("the guided Azure destination needs the deployment ID: it is the ownership marker written on everything this run creates")
	}
	if o.Say == nil {
		return fmt.Errorf("the guided Azure destination needs somewhere to show the device sign-in code; supply SetupOptions.Say")
	}
	if o.Confirm == nil {
		o.Confirm = func(q string) (bool, error) { return false, noInteraction(q) }
	}
	if o.Choose == nil {
		o.Choose = func(q string, _ []string) (int, error) { return 0, noInteraction(q) }
	}
	if o.Ask == nil {
		o.Ask = func(q, _ string) (string, error) { return "", noInteraction(q) }
	}
	return nil
}

// noInteraction is what an unsupplied question seam answers with. It never
// guesses: an unattended run that reaches a question it was not given the
// answer to stops and names the question.
func noInteraction(question string) error {
	return fmt.Errorf("this run cannot ask %q: no interactive seam was supplied. Supply the answer on the command line, or run setup interactively", question)
}

// preselected reports whether Azure was already chosen on the command line.
func (o *SetupOptions) preselected() bool {
	return o.Create || o.SubscriptionID != "" || o.Account != "" || o.Container != ""
}

// pick asks one multiple-choice question and refuses an answer that is not one
// of the options offered.
func (o *SetupOptions) pick(prompt string, options []string) (int, error) {
	i, err := o.Choose(prompt, options)
	if err != nil {
		return 0, err
	}
	if i < 0 || i >= len(options) {
		return 0, fmt.Errorf("the answer to %q was option %d, which is not one of the %d offered", prompt, i, len(options))
	}
	return i, nil
}

// signIn runs the device-code flow and returns a client for both planes.
//
// The message the administrator reads is DeviceCode.String(), which renders
// the user code and the verification URL and leaves out the device code. The
// Session is never shown, never returned and never stored.
func (o *SetupOptions) signIn(ctx context.Context) (*Client, error) {
	dc, err := o.App.StartSignIn(ctx)
	if err != nil {
		return nil, err
	}
	o.Say("%s", dc)
	sess, err := o.App.CompleteSignIn(ctx, dc)
	if err != nil {
		return nil, err
	}
	return &Client{Token: sess.TokenSource(), Do: o.Do, Sleep: o.Sleep}, nil
}

// subscription selects the subscription to put the storage in.
func (o *SetupOptions) subscription(ctx context.Context, c *Client) (Subscription, error) {
	subs, err := c.Subscriptions(ctx)
	if err != nil {
		return Subscription{}, err
	}
	if len(subs) == 0 {
		return Subscription{}, fmt.Errorf("the signed-in account can see no Azure subscriptions. That is what this sign-in returned, not a permission this tool can grant: either the account holds no role on any subscription in this directory, or it signed in to a directory that has none. Sign in with an account that can see the subscription the backups should go to, or choose a destination other than Azure")
	}
	if o.SubscriptionID != "" {
		for _, s := range subs {
			if strings.EqualFold(s.ID, o.SubscriptionID) {
				return s, nil
			}
		}
		return Subscription{}, fmt.Errorf("subscription %s is not one of the %d this account can see (%s)",
			o.SubscriptionID, len(subs), subscriptionNames(subs))
	}
	if len(subs) == 1 {
		// Asking a question with one answer is not a choice, it is a delay.
		o.Say("Using the only subscription this account can see: %s (%s).", subs[0].Name, subs[0].ID)
		return subs[0], nil
	}
	labels := make([]string, 0, len(subs))
	for _, s := range subs {
		labels = append(labels, fmt.Sprintf("%s (%s)", s.Name, s.ID))
	}
	i, err := o.pick("Which subscription should hold the backup storage?", labels)
	if err != nil {
		return Subscription{}, err
	}
	return subs[i], nil
}

func subscriptionNames(subs []Subscription) string {
	names := make([]string, 0, len(subs))
	for _, s := range subs {
		names = append(names, s.Name+" "+s.ID)
	}
	return strings.Join(names, ", ")
}

// createOption is the last entry of the storage account menu.
const createOption = "Create new storage for this deployment"

// destination selects existing storage or creates it.
func (o *SetupOptions) destination(ctx context.Context, c *Client, sub Subscription, res *Result) (Destination, error) {
	if !o.Create {
		accounts, err := c.StorageAccounts(ctx, sub.ID)
		if err != nil {
			return Destination{}, err
		}
		account, err := o.account(sub, accounts, res)
		if err != nil {
			return Destination{}, err
		}
		if account != nil {
			return o.reuse(ctx, c, sub, *account, res)
		}
		if res.Reason != "" {
			return Destination{}, nil // creation was offered and declined
		}
		// The menu chose creation instead, and set o.Create.
	}
	return o.create(ctx, c, sub, res)
}

// reuse selects a container in an existing account and resolves it.
func (o *SetupOptions) reuse(ctx context.Context, c *Client, sub Subscription, account StorageAccount, res *Result) (Destination, error) {
	container, err := o.container(ctx, c, account)
	if err != nil {
		return Destination{}, err
	}

	// Resolve is the selection primitive: it reads the account's own resource
	// ID and blob endpoint back from Azure and creates nothing.
	d, err := c.Resolve(ctx, sub.ID, account.Name, container.Name)
	if err != nil {
		return Destination{}, err
	}
	res.Reused = append(res.Reused,
		Created{Type: "storage-account", Name: d.Account, ProviderID: d.AccountID,
			Ownership: ownershipOf(account.Tags[ownerMetadata], o.DeploymentID, tagOwnership(o.DeploymentID))},
		Created{Type: "blob-container", Name: d.Container, ProviderID: d.ContainerScope(),
			Ownership: ownershipOf(container.Properties.Metadata[ownerMetadata], o.DeploymentID, containerOwnership(o.DeploymentID))})
	return d, nil
}

// account picks the storage account, or sends the flow to creation. A nil
// account with no error means creation was chosen or declined; res says which.
func (o *SetupOptions) account(sub Subscription, accounts []StorageAccount, res *Result) (*StorageAccount, error) {
	if o.Account != "" {
		for i := range accounts {
			if strings.EqualFold(accounts[i].Name, o.Account) {
				return &accounts[i], nil
			}
		}
		return nil, fmt.Errorf("storage account %q does not exist in subscription %s, or this identity cannot see it%s; this tool does not create a storage account on the reuse path. Ask for creation instead if it should make one of its own",
			o.Account, sub.ID, availableAccounts(accounts))
	}

	// An account this deployment already created is used again rather than
	// offered as one option among many: creating a second one would leave two
	// accounts carrying the same marker, which is a case only a person can
	// resolve.
	for i := range accounts {
		if accounts[i].Tags[ownerMetadata] == o.DeploymentID {
			o.Say("Using storage account %s, which this deployment created earlier (%s=%s).",
				accounts[i].Name, ownerMetadata, o.DeploymentID)
			return &accounts[i], nil
		}
	}

	if len(accounts) == 0 {
		o.Say("Subscription %s has no storage accounts this account can see.", sub.ID)
		yes, err := o.Confirm("Create a storage account and container for this deployment?")
		if err != nil {
			return nil, err
		}
		if !yes {
			o.declined(res, "there was no storage account to reuse and creation was declined")
			return nil, nil
		}
		o.Create = true
		return nil, nil
	}

	labels := make([]string, 0, len(accounts)+1)
	for _, a := range accounts {
		labels = append(labels, fmt.Sprintf("%s (resource group %s, %s)", a.Name, a.ResourceGroup(), a.Location))
	}
	labels = append(labels, createOption)
	i, err := o.pick("Which storage account should hold the backups?", labels)
	if err != nil {
		return nil, err
	}
	if i == len(accounts) {
		o.Create = true
		return nil, nil
	}
	return &accounts[i], nil
}

// container picks the container inside a selected account. It never offers
// creation: creating a container inside an account this deployment does not
// own is not a path this package has — PlanCreate refuses a storage account
// that matches by name without this deployment's marker, which is the same
// rule that stops a name match being treated as ownership.
func (o *SetupOptions) container(ctx context.Context, c *Client, account StorageAccount) (containerRecord, error) {
	records, err := c.containerRecords(ctx, account.ID)
	if err != nil {
		return containerRecord{}, err
	}
	if o.Container != "" {
		for _, r := range records {
			if strings.EqualFold(r.Name, o.Container) {
				return r, nil
			}
		}
		// Resolve produces the error, naming the containers that do exist.
		return containerRecord{Name: o.Container}, nil
	}
	for _, r := range records {
		if r.Properties.Metadata[ownerMetadata] == o.DeploymentID {
			o.Say("Using container %s in storage account %s, which this deployment created earlier (%s=%s).",
				r.Name, account.Name, ownerMetadata, o.DeploymentID)
			return r, nil
		}
	}
	if len(records) == 0 {
		return containerRecord{}, fmt.Errorf("storage account %s has no containers this identity can see, and this tool does not create a container inside a storage account it did not create. Create one in the Azure portal and run setup again, or ask for creation so the tool makes a storage account and container of its own",
			account.Name)
	}
	labels := make([]string, 0, len(records))
	for _, r := range records {
		labels = append(labels, r.Name)
	}
	i, err := o.pick(fmt.Sprintf("Which container in storage account %s should hold the backups?", account.Name), labels)
	if err != nil {
		return containerRecord{}, err
	}
	return records[i], nil
}

// create plans the creation, shows it, takes the approvals, checks the
// permissions, journals the intent, and only then creates anything.
//
// The order is the one internal/azure/WIRING.md sets out and it is not
// interchangeable: the administrator sees the plan before any of it happens,
// the intent reaches the parent's journal before the first write leaves, and a
// pre-existing resource group is never reused without somebody saying so.
func (o *SetupOptions) create(ctx context.Context, c *Client, sub Subscription, res *Result) (Destination, error) {
	if o.Location == "" {
		loc, err := o.Ask("Azure region for the created storage, for example australiaeast (there is no default)", "")
		if err != nil {
			return Destination{}, err
		}
		o.Location = strings.TrimSpace(loc)
	}
	plan, err := c.PlanCreate(ctx, CreateConfig{
		SubscriptionID:               sub.ID,
		Location:                     o.Location,
		DeploymentID:                 o.DeploymentID,
		Hostname:                     o.Hostname,
		ResourceGroup:                o.ResourceGroup,
		Account:                      o.Account,
		Container:                    o.Container,
		ApproveExistingResourceGroup: o.ApproveExistingResourceGroup,
	})
	if err != nil {
		return Destination{}, err
	}

	// The plan is shown before anything is created. This is the whole of the
	// "show the subscription and the proposed resources first" step.
	o.Say("%s", strings.TrimRight(plan.Summary(), "\n"))
	res.Planned = plan.Creations
	res.Location = plan.Config.Location

	if len(plan.Creations) > 0 {
		if o.Journal == nil {
			return Destination{}, fmt.Errorf("creating Azure storage needs SetupOptions.Journal: %d resources would be created, and the intent has to be on disk with a correlation identifier before the first request is sent, or a lost response cannot be reconciled", len(plan.Creations))
		}
		if err := o.Journal(plan.Creations); err != nil {
			return Destination{}, fmt.Errorf("the creation intent could not be journalled, so nothing was sent to Azure: %w", err)
		}
	}

	if plan.NeedsApproval() {
		o.Say("Resource group %s already exists and was not created by this deployment. It would be reused as it is: nothing is written to it and it is not tagged.",
			plan.ResourceGroup.Name)
		yes, err := o.Confirm(fmt.Sprintf("Reuse the existing resource group %s?", plan.ResourceGroup.Name))
		if err != nil {
			return Destination{}, err
		}
		if !yes {
			return Destination{}, fmt.Errorf("%w: reusing resource group %s was declined and nothing was created. Choose another resource group name and run setup again",
				ErrApprovalRequired, plan.ResourceGroup.Name)
		}
		plan.Config.ApproveExistingResourceGroup = true
	}

	checks, err := c.CheckCreatePermissions(ctx, plan)
	if err != nil {
		return Destination{}, err
	}
	o.Say("%s", strings.TrimRight(checks.Summary(), "\n"))
	if err := checks.Err(); err != nil {
		return Destination{}, fmt.Errorf("nothing was created: %w", err)
	}

	d, err := c.ApplyCreate(ctx, plan)
	if err != nil {
		// Whether the request landed is unknown. The journalled intent is what
		// the next run reconciles against, by marker.
		return d, err
	}
	o.record(plan, d, res)
	return d, nil
}

// record sorts the planned resources into what this run created and what it
// found, so the caller never has to reconstruct it.
func (o *SetupOptions) record(plan *CreatePlan, d Destination, res *Result) {
	creating := map[string]bool{}
	for _, cr := range plan.Creations {
		creating[cr.Type] = true
	}
	groupID := "/subscriptions/" + plan.Config.SubscriptionID + "/resourceGroups/" + plan.Config.ResourceGroup
	if plan.ResourceGroup != nil {
		groupID = plan.ResourceGroup.ID
	}
	add := func(kind, name, id, ownership string, found *Found) {
		item := Created{Type: kind, Name: name, ProviderID: id, Ownership: ownership}
		if creating[kind] {
			res.Created = append(res.Created, item)
			return
		}
		if found != nil {
			item.Ownership = ownershipOf(found.Marker, o.DeploymentID, ownership)
		}
		res.Reused = append(res.Reused, item)
	}
	add("resource-group", plan.Config.ResourceGroup, groupID, tagOwnership(o.DeploymentID), plan.ResourceGroup)
	add("storage-account", d.Account, d.AccountID, tagOwnership(o.DeploymentID), plan.Account)
	add("blob-container", d.Container, d.ContainerScope(), containerOwnership(o.DeploymentID), plan.Container)
}

// grantUploaderRole gives the unattended service principal its one data role
// and then proves it works.
func (o *SetupOptions) grantUploaderRole(ctx context.Context, c *Client, d Destination, res *Result) error {
	if o.UploaderObjectID == "" {
		o.Say("No unattended uploader was named, so no role was granted. Scheduled uploads fail until a service principal holds %s on container %s.",
			UploaderRole, d.Container)
		return nil
	}
	ra, err := c.AssignUploaderRole(ctx, d, o.UploaderObjectID)
	if err != nil {
		return err
	}
	res.RoleAssignment = &ra
	if ra.Created {
		res.Created = append(res.Created, Created{
			Type: "role-assignment", Name: ra.Name,
			ProviderID: ra.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + ra.Name,
			Ownership:  roleOwnership,
		})
		o.Say("Granted %s on container %s to the unattended uploader. A role assignment is eventually consistent: it can take several minutes to take effect, so this now waits for a real write to succeed rather than assuming it.",
			UploaderRole, d.Container)
	} else {
		o.Say("%s on container %s was already in place for the unattended uploader.", UploaderRole, d.Container)
	}

	k := WaitRoleEffective(ctx, o.Uploader, d, o.DeploymentID, o.RoleWait)
	res.RoleEffective = &k
	o.Say("%-20s %s", "uploader role:", k.Detail)
	return nil
}

// unprovenDetail says which evidence was looked for and what came back.
func (o *SetupOptions) unprovenDetail(res Result, pre Preflight) string {
	switch {
	case res.RoleEffective != nil:
		return "the administrator's own write probe failed (" + pre.BlobData.Detail +
			") and the unattended uploader's did too (" + res.RoleEffective.Detail + ")"
	case o.UploaderObjectID != "":
		return "the administrator's own write probe failed (" + pre.BlobData.Detail + ")"
	default:
		return "the administrator's own write probe failed (" + pre.BlobData.Detail +
			"), and no unattended uploader was named, so there was no second identity to prove it with"
	}
}

func (o *SetupOptions) unprovenFix(res Result, pre Preflight) string {
	if res.RoleEffective != nil && res.RoleEffective.Fix != "" {
		return res.RoleEffective.Fix
	}
	return pre.BlobData.Fix
}

// Ownership evidence, spelled the way internal/azure/WIRING.md records it.
func tagOwnership(deploymentID string) string {
	return "tag " + ownerMetadata + "=" + deploymentID
}

func containerOwnership(deploymentID string) string {
	return "container metadata " + ownerMetadata + "=" + deploymentID
}

const roleOwnership = "deterministic name from scope, principal and role"

// ownershipOf describes a resource this run did not create. A marker that
// matches is evidence; anything else is not, and says so rather than claiming
// an ownership a matching name never establishes.
func ownershipOf(marker, deploymentID, evidence string) string {
	if marker != "" && marker == deploymentID {
		return evidence + " (created by an earlier run of this deployment)"
	}
	return "pre-existing; not created by this deployment"
}
