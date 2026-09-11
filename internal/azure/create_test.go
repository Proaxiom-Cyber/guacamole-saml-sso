package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// --- a stateful management-plane fake --------------------------------------
//
// armResponder (azure_test.go) answers reads from a fixed table, which is all
// the reuse path needs. Creation writes, so this one keeps state: a PUT changes
// what the next GET returns, exactly as ARM does. That is what makes "a lost
// response does not create a duplicate" a real test rather than a mock
// assertion.

type armState struct {
	t *testing.T

	sub        string
	groups     map[string]*resourceGroupRecord        // by lowercase name
	accounts   map[string]*StorageAccount             // by lowercase name
	containers map[string]map[string]*containerRecord // account -> container
	roles      map[string]map[string]any              // assignment name -> properties
	calls      []string                               // "METHOD path" of every call
	bodies     map[string][]map[string]any            // "METHOD path" -> decoded bodies

	// Knobs.
	actions       []string        // effective permissions returned at any scope
	notActions    []string        //
	permissionErr int             // non-zero: permissions queries fail with this status
	subErr        int             // non-zero: reading the subscription fails with this status
	takenGlobally map[string]bool // account names held by somebody else, elsewhere in Azure
	pending       int             // account GETs that report "Creating" before "Succeeded"
	loseResponse  string          // path fragment of one PUT whose response is lost
	ignoreFilter  bool            // the resource group list ignores $filter and returns everything
	roleConflict  string          // code returned by a role assignment PUT, "" for success
	roleDenied    bool            // role assignment PUT returns 403
}

func newARM(t *testing.T) *armState {
	return &armState{
		t: t, sub: testSub,
		groups:     map[string]*resourceGroupRecord{},
		accounts:   map[string]*StorageAccount{},
		containers: map[string]map[string]*containerRecord{},
		roles:      map[string]map[string]any{},
		bodies:     map[string][]map[string]any{},
		actions:    []string{"*"},
	}
}

// existingAccount adds an account that is already in the subscription.
func (a *armState) existingAccount(name, group string, tags map[string]string) *StorageAccount {
	acc := &StorageAccount{
		ID: "/subscriptions/" + a.sub + "/resourceGroups/" + group +
			"/providers/Microsoft.Storage/storageAccounts/" + name,
		Name: name, Location: "australiaeast", Tags: tags,
	}
	acc.Properties.PrimaryEndpoints.Blob = "https://" + name + ".blob.core.windows.net/"
	acc.Properties.ProvisioningState = "Succeeded"
	a.accounts[strings.ToLower(name)] = acc
	return acc
}

func (a *armState) existingGroup(name string, tags map[string]string) {
	a.groups[strings.ToLower(name)] = &resourceGroupRecord{
		ID: "/subscriptions/" + a.sub + "/resourceGroups/" + name, Name: name,
		Location: "australiaeast", Tags: tags,
	}
}

func (a *armState) existingContainer(account, name string, meta map[string]string) {
	acc := a.accounts[strings.ToLower(account)]
	if acc == nil {
		a.t.Fatalf("existingContainer: no account %q", account)
	}
	if a.containers[strings.ToLower(account)] == nil {
		a.containers[strings.ToLower(account)] = map[string]*containerRecord{}
	}
	rec := &containerRecord{ID: acc.ID + "/blobServices/default/containers/" + name, Name: name}
	rec.Properties.Metadata = meta
	a.containers[strings.ToLower(account)][strings.ToLower(name)] = rec
}

func (a *armState) countCalls(method, fragment string) int {
	n := 0
	for _, c := range a.calls {
		if strings.HasPrefix(c, method+" ") && strings.Contains(strings.ToLower(c), strings.ToLower(fragment)) {
			n++
		}
	}
	return n
}

// countExact counts calls to exactly one path. A resource's own path is a
// prefix of its children's, so "how many times was the account created" cannot
// be answered by a substring: the container's path contains the account's.
func (a *armState) countExact(method, path string) int {
	n := 0
	for _, c := range a.calls {
		if strings.EqualFold(c, method+" "+path) {
			n++
		}
	}
	return n
}

// bodyOf returns the first decoded body of the PUT to exactly one path.
func (a *armState) bodyOf(path string) map[string]any {
	for key, list := range a.bodies {
		if strings.EqualFold(key, "PUT "+path) {
			return list[0]
		}
	}
	a.t.Fatalf("no PUT body recorded for %q; recorded: %v", path, a.calls)
	return nil
}

func armJSON(status int, v any) *http.Response {
	body, _ := json.Marshal(v)
	return httpResponse(status, string(body), http.Header{"Content-Type": {"application/json"}})
}

func armErr(status int, code, message string) *http.Response {
	return armJSON(status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (a *armState) serve(req *http.Request) (*http.Response, error) {
	if got := req.Header.Get("Authorization"); got != "Bearer "+testToken {
		a.t.Errorf("management request %s has Authorization %q", req.URL.Path, got)
	}
	key := req.Method + " " + req.URL.Path
	a.calls = append(a.calls, key)
	p := strings.ToLower(req.URL.Path)

	var body map[string]any
	if req.Body != nil && req.Method == http.MethodPut {
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			a.t.Fatalf("PUT %s has an unreadable body: %v", req.URL.Path, err)
		}
		a.bodies[key] = append(a.bodies[key], body)
	}

	resp, err := a.route(req, p, body)
	if err != nil || resp == nil {
		return resp, err
	}
	if req.Method == http.MethodPut && a.loseResponse != "" && strings.Contains(p, strings.ToLower(a.loseResponse)) {
		// The write landed; the answer never arrived. This is the case the
		// specification calls a lost response.
		a.loseResponse = ""
		return nil, fmt.Errorf("connection reset by peer")
	}
	return resp, nil
}

func (a *armState) route(req *http.Request, p string, body map[string]any) (*http.Response, error) {
	switch {
	case strings.Contains(p, "/providers/microsoft.authorization/roleassignments/"):
		return a.roleAssignment(req, p, body)
	case strings.HasSuffix(p, "/providers/microsoft.authorization/permissions"):
		if a.permissionErr != 0 {
			return armErr(a.permissionErr, "AuthorizationFailed", "not permitted to read permissions"), nil
		}
		return armJSON(http.StatusOK, map[string]any{"value": []map[string]any{
			{"actions": a.actions, "notActions": a.notActions},
		}}), nil
	case strings.Contains(p, "/blobservices/default/containers"):
		return a.container(req, p, body)
	case strings.Contains(p, "/providers/microsoft.storage/storageaccounts"):
		return a.account(req, p, body)
	case strings.Contains(p, "/resourcegroups"):
		return a.resourceGroup(req, p, body)
	case p == "/subscriptions/"+strings.ToLower(a.sub):
		if a.subErr != 0 {
			return armErr(a.subErr, "AuthorizationFailed", "the subscription is not visible"), nil
		}
		return armJSON(http.StatusOK, map[string]any{"subscriptionId": a.sub, "displayName": "Test", "state": "Enabled"}), nil
	}
	return armErr(http.StatusNotFound, "NotFound", "no fake route for "+p), nil
}

func (a *armState) resourceGroup(req *http.Request, p string, body map[string]any) (*http.Response, error) {
	name := ""
	if i := strings.Index(p, "/resourcegroups/"); i >= 0 {
		name = p[i+len("/resourcegroups/"):]
	}
	if name == "" { // list, always with the marker filter
		filter := req.URL.Query().Get("$filter")
		if a.ignoreFilter {
			filter = ""
		}
		var out []*resourceGroupRecord
		for _, g := range a.groups {
			if filter == "" || matchesTagFilter(filter, g.Tags) {
				out = append(out, g)
			}
		}
		return armJSON(http.StatusOK, map[string]any{"value": out}), nil
	}
	if req.Method == http.MethodPut {
		tags := map[string]string{}
		for k, v := range mapOf(body["tags"]) {
			tags[k] = fmt.Sprint(v)
		}
		a.groups[name] = &resourceGroupRecord{
			ID: "/subscriptions/" + a.sub + "/resourceGroups/" + name, Name: name,
			Location: fmt.Sprint(body["location"]), Tags: tags,
		}
		return armJSON(http.StatusCreated, a.groups[name]), nil
	}
	if g, ok := a.groups[name]; ok {
		return armJSON(http.StatusOK, g), nil
	}
	return armErr(http.StatusNotFound, "ResourceGroupNotFound", "Resource group '"+name+"' could not be found."), nil
}

// matchesTagFilter understands the one filter shape this package sends:
// tagName eq 'x' and tagValue eq 'y'.
func matchesTagFilter(filter string, tags map[string]string) bool {
	var name, value string
	fmt.Sscanf(strings.ReplaceAll(filter, "'", ""), "tagName eq %s and tagValue eq %s", &name, &value)
	return name != "" && tags[name] == value
}

// groupFromPath returns the resource group segment of a lowercased ARM path.
func groupFromPath(p string) string {
	i := strings.Index(p, "/resourcegroups/")
	if i < 0 {
		return ""
	}
	rest := p[i+len("/resourcegroups/"):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func (a *armState) account(req *http.Request, p string, body map[string]any) (*http.Response, error) {
	i := strings.Index(p, "/storageaccounts")
	rest := strings.TrimPrefix(p[i+len("/storageaccounts"):], "/")
	if rest == "" { // subscription-wide list
		var out []*StorageAccount
		for _, acc := range a.accounts {
			out = append(out, acc)
		}
		return armJSON(http.StatusOK, map[string]any{"value": out}), nil
	}
	name := rest
	if req.Method == http.MethodPut {
		if a.takenGlobally[name] {
			return armErr(http.StatusConflict, "StorageAccountAlreadyTaken",
				"The storage account named "+name+" is already taken."), nil
		}
		group := groupFromPath(p)
		tags := map[string]string{}
		for k, v := range mapOf(body["tags"]) {
			tags[k] = fmt.Sprint(v)
		}
		acc := a.existingAccount(name, group, tags)
		if a.pending > 0 {
			acc.Properties.ProvisioningState = "Creating"
		}
		return httpResponse(http.StatusAccepted, "", nil), nil
	}
	acc, ok := a.accounts[name]
	// A resource is addressed by its whole ID. Asking for the right name in
	// the wrong resource group is a 404 in Azure, and it is one here, so a
	// constructed ID cannot pass for the ID Azure returned.
	if !ok || !strings.EqualFold(groupFromPath(p), groupFromPath(strings.ToLower(acc.ID))) {
		return armErr(http.StatusNotFound, "ResourceNotFound", "The storage account was not found."), nil
	}
	if a.pending > 0 {
		a.pending--
		if a.pending == 0 {
			acc.Properties.ProvisioningState = "Succeeded"
		}
	}
	return armJSON(http.StatusOK, acc), nil
}

func (a *armState) container(req *http.Request, p string, body map[string]any) (*http.Response, error) {
	j := strings.Index(p, "/storageaccounts/")
	account := p[j+len("/storageaccounts/"):]
	account = account[:strings.Index(account, "/")]
	k := strings.Index(p, "/blobservices/default/containers")
	rest := strings.TrimPrefix(p[k+len("/blobservices/default/containers"):], "/")
	if rest == "" {
		out := []*containerRecord{}
		for _, c := range a.containers[account] {
			out = append(out, c)
		}
		return armJSON(http.StatusOK, map[string]any{"value": out}), nil
	}
	if req.Method == http.MethodPut {
		meta := map[string]string{}
		for key, v := range mapOf(mapOf(body["properties"])["metadata"]) {
			meta[key] = fmt.Sprint(v)
		}
		a.existingContainer(account, rest, meta)
		return armJSON(http.StatusCreated, a.containers[account][rest]), nil
	}
	if c, ok := a.containers[account][rest]; ok {
		return armJSON(http.StatusOK, c), nil
	}
	return armErr(http.StatusNotFound, "ContainerNotFound", "The container was not found."), nil
}

func (a *armState) roleAssignment(req *http.Request, p string, body map[string]any) (*http.Response, error) {
	name := p[strings.LastIndex(p, "/")+1:]
	if req.Method != http.MethodPut {
		if props, ok := a.roles[name]; ok {
			return armJSON(http.StatusOK, map[string]any{"name": name, "properties": props}), nil
		}
		return armErr(http.StatusNotFound, "RoleAssignmentNotFound", "not found"), nil
	}
	if a.roleDenied {
		return armErr(http.StatusForbidden, "AuthorizationFailed",
			"The client does not have authorization to perform action 'Microsoft.Authorization/roleAssignments/write'."), nil
	}
	if a.roleConflict != "" {
		return armErr(http.StatusConflict, a.roleConflict, "The role assignment already exists."), nil
	}
	a.roles[name] = mapOf(body["properties"])
	return armJSON(http.StatusCreated, map[string]any{"name": name, "properties": a.roles[name]}), nil
}

// newCreateClient wires a client whose management calls reach the stateful fake
// and whose polls cost nothing.
func newCreateClient(arm *armState, blobs *blobStore) *Client {
	c := &Client{Token: testTokens, Sleep: func(_ time.Duration) {}}
	c.Do = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "management.azure.com") {
			return arm.serve(req)
		}
		if blobs == nil {
			return httpResponse(http.StatusNotFound, "", nil), nil
		}
		return blobs.serve(req)
	}
	return c
}

func testCreateConfig() CreateConfig {
	return CreateConfig{
		SubscriptionID: testSub,
		Location:       "australiaeast",
		DeploymentID:   testDeployment,
		Hostname:       "guac.example.com",
	}
}

// --- names -----------------------------------------------------------------

func TestAccountNameIsLegalAndDeterministic(t *testing.T) {
	got := AccountName("guac.example.com", testDeployment)
	if err := ValidateAccountName(got); err != nil {
		t.Fatalf("derived account name %q is not legal: %v", got, err)
	}
	if again := AccountName("guac.example.com", testDeployment); again != got {
		t.Fatalf("the derived name is not deterministic: %q then %q", got, again)
	}
	if other := AccountName("guac.example.com", "ffffffffffffffffffffffffffffffff"); other == got {
		t.Fatal("two deployments derived the same account name; the suffix does not depend on the deployment ID")
	}
	// A long hostname must still fit the 24-character ceiling.
	long := AccountName("a-very-long-hostname-indeed.example.com", testDeployment)
	if err := ValidateAccountName(long); err != nil {
		t.Fatalf("a long hostname produced an illegal name %q: %v", long, err)
	}
	// An empty hostname must still produce a legal name.
	if err := ValidateAccountName(AccountName("", testDeployment)); err != nil {
		t.Fatalf("an empty hostname produced an illegal name: %v", err)
	}
}

func TestNameValidationNamesTheRule(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"account too short", ValidateAccountName("ab"), "3 to 24"},
		{"account uppercase", ValidateAccountName("GuacBackups"), "lowercase"},
		{"account hyphen", ValidateAccountName("guac-backups"), "lowercase"},
		{"container double hyphen", ValidateContainerName("guac--deploy"), "two hyphens"},
		{"container trailing hyphen", ValidateContainerName("guacdeploy-"), "hyphen"},
		{"container uppercase", ValidateContainerName("Guacdeploy"), "lowercase"},
		{"group trailing period", ValidateResourceGroupName("rg-guac."), "period"},
		{"group too long", ValidateResourceGroupName(strings.Repeat("a", 91)), "1 to 90"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.err == nil {
				t.Fatal("the name was accepted; it is not legal in Azure")
			}
			if !strings.Contains(c.err.Error(), c.want) {
				t.Fatalf("error %q does not say why (%q)", c.err, c.want)
			}
		})
	}
	for _, ok := range []string{"guacdeploy", "gd-backups-01", "abc"} {
		if err := ValidateContainerName(ok); err != nil {
			t.Fatalf("container name %q should be legal: %v", ok, err)
		}
	}
}

func TestCreateNeedsLocationAndSubscription(t *testing.T) {
	_, err := (&Client{Token: testTokens}).PlanCreate(context.Background(), CreateConfig{DeploymentID: testDeployment})
	if err == nil {
		t.Fatal("a plan without a subscription or a location was accepted")
	}
	for _, want := range []string{"SubscriptionID", "Location"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name the missing %s", err, want)
		}
	}
}

// --- plan and create -------------------------------------------------------

func TestPlanCreateShowsSubscriptionAndProposedResources(t *testing.T) {
	arm := newARM(t)
	c := newCreateClient(arm, nil)
	plan, err := c.PlanCreate(context.Background(), testCreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Creations) != 3 {
		t.Fatalf("Creations = %v; a fresh subscription needs a group, an account and a container journalled", plan.Creations)
	}
	for i, want := range []string{"resource-group", "storage-account", "blob-container"} {
		if plan.Creations[i].Type != want {
			t.Fatalf("Creations[%d].Type = %q, want %q", i, plan.Creations[i].Type, want)
		}
		if plan.Creations[i].Name == "" {
			t.Fatalf("Creations[%d] has no name to journal", i)
		}
	}
	s := plan.Summary()
	for _, want := range []string{testSub, "australiaeast", plan.Config.Account, plan.Config.Container,
		plan.Config.ResourceGroup, ownerMetadata, testDeployment, "Teardown"} {
		if !strings.Contains(s, want) {
			t.Fatalf("the summary shown before creation does not mention %q:\n%s", want, s)
		}
	}
	if arm.countCalls("PUT", "") != 0 {
		t.Fatalf("planning wrote to Azure: %v", arm.calls)
	}
}

func TestApplyCreateCarriesTheOwnershipMarker(t *testing.T) {
	arm := newARM(t)
	c := newCreateClient(arm, nil)
	ctx := context.Background()
	plan, err := c.PlanCreate(ctx, testCreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.ApplyCreate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}

	accountPath := accountResourceID(testSub, plan.Config.ResourceGroup, plan.Config.Account)
	groupPath := "/subscriptions/" + testSub + "/resourcegroups/" + plan.Config.ResourceGroup

	// The resource group and the account carry the marker as a resource tag.
	for _, path := range []string{groupPath, accountPath} {
		tags := mapOf(arm.bodyOf(path)["tags"])
		if tags[ownerMetadata] != testDeployment {
			t.Fatalf("the create request for %s carries tags %v, not the ownership marker %s=%s",
				path, tags, ownerMetadata, testDeployment)
		}
	}
	// The container carries it as container metadata: an ARM container has
	// no tags at all, so metadata is what it has.
	props := mapOf(arm.bodyOf(accountPath + "/blobServices/default/containers/" + plan.Config.Container)["properties"])
	if meta := mapOf(props["metadata"]); meta[ownerMetadata] != testDeployment {
		t.Fatalf("the container create request carries metadata %v, not the ownership marker", meta)
	}
	if props["publicAccess"] != "None" {
		t.Fatalf("the container was created with publicAccess %v; backups must not be anonymously readable", props["publicAccess"])
	}
	// The account is created with shared key access off: this tool
	// authenticates with Entra tokens and never uses an account key.
	accProps := mapOf(arm.bodyOf(accountPath)["properties"])
	if accProps["allowSharedKeyAccess"] != false || accProps["allowBlobPublicAccess"] != false {
		t.Fatalf("the account was created with %v; shared key and public blob access must both be off", accProps)
	}

	if !d.Configured() {
		t.Fatalf("the destination is not usable: %+v", d)
	}
	if d.Account != plan.Config.Account || d.Container != plan.Config.Container {
		t.Fatalf("destination = %+v, does not match the plan", d)
	}
	if d.BlobEndpoint != "https://"+plan.Config.Account+".blob.core.windows.net" {
		t.Fatalf("blob endpoint %q was not taken from the account Azure returned", d.BlobEndpoint)
	}
	if d.ResourceGroup != plan.Config.ResourceGroup {
		t.Fatalf("resource group %q does not come from the account's own resource ID", d.ResourceGroup)
	}
}

func TestAccountCreationIsPolledUntilProvisioned(t *testing.T) {
	arm := newARM(t)
	arm.pending = 3 // the first three reads report "Creating"
	c := newCreateClient(arm, nil)
	ctx := context.Background()
	plan, err := c.PlanCreate(ctx, testCreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyCreate(ctx, plan); err != nil {
		t.Fatal(err)
	}
	accountPath := accountResourceID(testSub, plan.Config.ResourceGroup, plan.Config.Account)
	if got := arm.countExact("GET", accountPath); got != 3 {
		t.Fatalf("the account was read back %d times, want 3; creation is asynchronous and must be polled until Azure reports it provisioned", got)
	}
}

// TestLostCreateResponseMakesNoDuplicate is the reconciliation case the
// specification names: "After a lost response, query before retrying creation.
// ... Do not create duplicates merely because the previous response was lost."
func TestLostCreateResponseMakesNoDuplicate(t *testing.T) {
	arm := newARM(t)
	arm.loseResponse = "/storageaccounts/" // the account write lands; the answer does not
	c := newCreateClient(arm, nil)
	ctx := context.Background()

	plan, err := c.PlanCreate(ctx, testCreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyCreate(ctx, plan); err == nil {
		t.Fatal("the lost response was reported as success")
	}

	// Resume: plan again, exactly as the caller does after journalling the
	// action as uncertain.
	plan2, err := c.PlanCreate(ctx, testCreateConfig())
	if err != nil {
		t.Fatalf("the resume plan failed instead of reconciling by marker: %v", err)
	}
	for _, cr := range plan2.Creations {
		if cr.Type == "storage-account" {
			t.Fatalf("the resume plan would create the storage account again: %v", plan2.Creations)
		}
	}
	if plan2.Account == nil || !plan2.Account.ProvenOurs {
		t.Fatalf("the account created before the lost response was not recognised as this deployment's own: %+v", plan2.Account)
	}
	if _, err := c.ApplyCreate(ctx, plan2); err != nil {
		t.Fatal(err)
	}
	accountPath := accountResourceID(testSub, plan.Config.ResourceGroup, plan.Config.Account)
	if got := arm.countExact("PUT", accountPath); got != 1 {
		t.Fatalf("the storage account was created %d times across a lost response and a resume; it must be created once", got)
	}
	if len(arm.accounts) != 1 {
		t.Fatalf("%d storage accounts exist after the resume; a lost response must not duplicate one", len(arm.accounts))
	}
}

// TestMarkerNotNameIdentifiesOurResources: the marker is the evidence, so a
// resource this deployment owns is adopted even when the derived name has
// changed (a renamed host), and a resource with the right name and no marker is
// not.
func TestMarkerNotNameIdentifiesOurResources(t *testing.T) {
	arm := newARM(t)
	arm.existingGroup("some-other-name", map[string]string{ownerMetadata: testDeployment})
	// The account this deployment owns sits in a third group, which is what
	// an account moved after creation looks like. Its own resource ID is the
	// authority, not the group the plan would otherwise have used.
	arm.existingAccount("gdoldname0deadbeef", "third-group", map[string]string{ownerMetadata: testDeployment})
	arm.existingContainer("gdoldname0deadbeef", "archive", map[string]string{ownerMetadata: testDeployment})

	c := newCreateClient(arm, nil)
	ctx := context.Background()
	plan, err := c.PlanCreate(ctx, testCreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Creations) != 0 {
		t.Fatalf("Creations = %v; everything already carries this deployment's marker", plan.Creations)
	}
	if plan.Config.ResourceGroup != "some-other-name" || plan.Config.Account != "gdoldname0deadbeef" || plan.Config.Container != "archive" {
		t.Fatalf("the plan followed the derived names instead of the marked resources: %+v", plan.Config)
	}
	d, err := c.ApplyCreate(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if arm.countCalls("PUT", "") != 0 {
		t.Fatalf("resources this deployment already owns were written to again: %v", arm.calls)
	}
	if d.ResourceGroup != "third-group" || d.AccountID != plan.Account.ID {
		t.Fatalf("destination = %+v; it must come from the account's own resource ID", d)
	}
}

func TestNameOnlyMatchRequiresReview(t *testing.T) {
	cfg := testCreateConfig()
	account := AccountName(cfg.Hostname, cfg.DeploymentID)

	t.Run("storage account", func(t *testing.T) {
		arm := newARM(t)
		arm.existingAccount(account, "someone-elses-rg", map[string]string{"owner": "finance"})
		_, err := newCreateClient(arm, nil).PlanCreate(context.Background(), cfg)
		if !errors.Is(err, ErrRequiresReview) {
			t.Fatalf("err = %v, want ErrRequiresReview: a matching name alone never establishes ownership", err)
		}
		if errors.Is(err, ErrNameTaken) {
			t.Fatal("a name match inside this subscription was reported as a globally taken name")
		}
		if arm.countCalls("PUT", "") != 0 {
			t.Fatalf("something was written despite the ambiguity: %v", arm.calls)
		}
	})

	t.Run("container", func(t *testing.T) {
		arm := newARM(t)
		arm.existingAccount(account, ResourceGroupName(cfg.Hostname, cfg.DeploymentID),
			map[string]string{ownerMetadata: testDeployment})
		arm.existingContainer(account, DefaultContainer, map[string]string{"owner": "finance"})
		_, err := newCreateClient(arm, nil).PlanCreate(context.Background(), cfg)
		if !errors.Is(err, ErrRequiresReview) {
			t.Fatalf("err = %v, want ErrRequiresReview for a container that matches by name only", err)
		}
	})

	t.Run("two resources carry our marker", func(t *testing.T) {
		arm := newARM(t)
		arm.existingGroup("one", map[string]string{ownerMetadata: testDeployment})
		arm.existingGroup("two", map[string]string{ownerMetadata: testDeployment})
		_, err := newCreateClient(arm, nil).PlanCreate(context.Background(), cfg)
		if !errors.Is(err, ErrRequiresReview) {
			t.Fatalf("err = %v, want ErrRequiresReview: an ambiguous result is for a person to resolve", err)
		}
	})
}

// TestPreExistingResourceGroupNeedsApproval: reuse is allowed by the
// specification, silent reuse is not.
func TestPreExistingResourceGroupNeedsApproval(t *testing.T) {
	cfg := testCreateConfig()
	arm := newARM(t)
	// The marker query is answered by a service that returns everything: the
	// evidence of ownership has to be read from the resource, never assumed
	// from the query that returned it.
	arm.ignoreFilter = true
	arm.existingGroup(ResourceGroupName(cfg.Hostname, cfg.DeploymentID), map[string]string{"cost-centre": "ops"})
	c := newCreateClient(arm, nil)
	ctx := context.Background()

	plan, err := c.PlanCreate(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.NeedsApproval() {
		t.Fatal("a pre-existing resource group was planned for reuse without approval")
	}
	if !strings.Contains(plan.Summary(), "pre-existing") {
		t.Fatalf("the summary does not tell the administrator the group is pre-existing:\n%s", plan.Summary())
	}
	if _, err := c.ApplyCreate(ctx, plan); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("err = %v, want ErrApprovalRequired", err)
	}
	if arm.countCalls("PUT", "") != 0 {
		t.Fatalf("something was created before approval: %v", arm.calls)
	}

	cfg.ApproveExistingResourceGroup = true
	plan, err = c.PlanCreate(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyCreate(ctx, plan); err != nil {
		t.Fatalf("an approved pre-existing group was still refused: %v", err)
	}
	group := "/subscriptions/" + testSub + "/resourcegroups/" + plan.Config.ResourceGroup
	if arm.countExact("PUT", group) != 0 {
		t.Fatalf("the pre-existing resource group was written to: %v", arm.calls)
	}
	account := accountResourceID(testSub, plan.Config.ResourceGroup, plan.Config.Account)
	if arm.countExact("PUT", account) != 1 {
		t.Fatalf("the account was not created into the approved group: %v", arm.calls)
	}
}

// TestOwnershipIsReadFromTheResourceNotTheQuery: the marker query is a filter,
// not proof. A service that answers with more than it was asked for must not
// make an unrelated resource this deployment's own.
func TestOwnershipIsReadFromTheResourceNotTheQuery(t *testing.T) {
	arm := newARM(t)
	arm.ignoreFilter = true
	arm.existingGroup("unrelated-rg", map[string]string{"cost-centre": "ops"})
	c := newCreateClient(arm, nil)

	plan, err := c.PlanCreate(context.Background(), testCreateConfig())
	if err != nil {
		t.Fatal(err)
	}
	if plan.ResourceGroup != nil {
		t.Fatalf("an unrelated resource group was adopted: %+v", plan.ResourceGroup)
	}
	if plan.Config.ResourceGroup == "unrelated-rg" {
		t.Fatal("the plan would put this deployment's storage into somebody else's resource group")
	}
}

// TestGloballyTakenAccountNameIsNotAnOwnershipConflict: storage account names
// are unique across all of Azure, so "taken" may mean another tenant entirely.
func TestGloballyTakenAccountNameIsNotAnOwnershipConflict(t *testing.T) {
	cfg := testCreateConfig()
	arm := newARM(t)
	arm.takenGlobally = map[string]bool{strings.ToLower(AccountName(cfg.Hostname, cfg.DeploymentID)): true}
	c := newCreateClient(arm, nil)
	ctx := context.Background()

	plan, err := c.PlanCreate(ctx, cfg)
	if err != nil {
		t.Fatalf("planning failed before the name could be tried: %v", err)
	}
	_, err = c.ApplyCreate(ctx, plan)
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("err = %v, want ErrNameTaken", err)
	}
	if errors.Is(err, ErrRequiresReview) {
		t.Fatal("a globally taken name was reported as an ownership conflict; they are different conditions")
	}
	if !strings.Contains(err.Error(), "another storage account name") && !strings.Contains(err.Error(), "Choose another storage account name") {
		t.Fatalf("error %q does not tell the operator what to do about it", err)
	}

	// The operator supplies a name instead, and creation proceeds.
	cfg.Account = "guacbackupschosen"
	plan, err = c.PlanCreate(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyCreate(ctx, plan); err != nil {
		t.Fatalf("an operator-supplied account name was refused: %v", err)
	}
}

func TestOperatorSuppliedNamesAreValidated(t *testing.T) {
	cfg := testCreateConfig()
	cfg.Account = "Not A Legal Account Name"
	if _, err := (&Client{Token: testTokens}).PlanCreate(context.Background(), cfg); err == nil {
		t.Fatal("an illegal operator-supplied account name was accepted")
	}
}

// TestNoTokenLeaksFromCreation: the bearer token must not reach an error, a
// rendered summary, or anything the caller journals.
func TestNoTokenLeaksFromCreation(t *testing.T) {
	cfg := testCreateConfig()
	arm := newARM(t)
	arm.takenGlobally = map[string]bool{strings.ToLower(AccountName(cfg.Hostname, cfg.DeploymentID)): true}
	arm.permissionErr = http.StatusForbidden
	c := newCreateClient(arm, nil)
	ctx := context.Background()

	var texts []string
	plan, err := c.PlanCreate(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, plan.Summary())
	if _, err := c.ApplyCreate(ctx, plan); err != nil {
		texts = append(texts, err.Error())
	}
	checks, err := c.CheckCreatePermissions(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, checks.Summary())
	if _, err := c.AssignUploaderRole(ctx, Destination{}, ""); err != nil {
		texts = append(texts, err.Error())
	}
	journalled, err := json.Marshal(plan.Creations)
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, string(journalled))
	blob, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	texts = append(texts, string(blob))

	for _, s := range texts {
		if strings.Contains(s, testToken) {
			t.Fatalf("the access token appears in output: %s", s)
		}
	}
}
