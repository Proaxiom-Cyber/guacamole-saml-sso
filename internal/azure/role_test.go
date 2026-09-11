package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// planWithGroup returns a plan whose resource group already exists, which is
// the case where Azure can report effective permissions.
func planWithGroup(t *testing.T, arm *armState) (*Client, *CreatePlan) {
	t.Helper()
	cfg := testCreateConfig()
	arm.existingGroup(ResourceGroupName(cfg.Hostname, cfg.DeploymentID),
		map[string]string{ownerMetadata: testDeployment})
	c := newCreateClient(arm, nil)
	plan, err := c.PlanCreate(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, plan
}

// TestCreateManagementCheckIsIndependent exercises the management check on its
// own, passing and failing, with the resource group in place so Azure can
// answer.
func TestCreateManagementCheckIsIndependent(t *testing.T) {
	cases := []struct {
		name       string
		actions    []string
		notActions []string
		status     int
		wantOK     bool
		wantDetail string
		wantFix    string
	}{
		{name: "owner", actions: []string{"*"}, wantOK: true},
		{name: "storage account contributor", actions: []string{"Microsoft.Storage/*"}, wantOK: true},
		{
			name:       "may create an account but not a container",
			actions:    []string{"Microsoft.Storage/storageAccounts/write"},
			wantDetail: containerWrite,
			wantFix:    "Contributor",
		},
		{
			name:       "denied by notActions",
			actions:    []string{"*"},
			notActions: []string{"Microsoft.Storage/storageAccounts/write"},
			wantDetail: accountWrite,
			wantFix:    "Contributor",
		},
		{
			name:       "permissions cannot be read",
			status:     http.StatusForbidden,
			wantDetail: "effective permissions",
			wantFix:    "Contributor",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arm := newARM(t)
			arm.actions, arm.notActions, arm.permissionErr = tc.actions, tc.notActions, tc.status
			c, plan := planWithGroup(t, arm)
			checks, err := c.CheckCreatePermissions(context.Background(), plan)
			if err != nil {
				t.Fatal(err)
			}
			k := checks.Management
			if k.OK != tc.wantOK {
				t.Fatalf("management OK = %v, want %v (%s)", k.OK, tc.wantOK, k.Detail)
			}
			if k.Name != CheckManagement {
				t.Fatalf("check name = %q", k.Name)
			}
			if tc.wantOK {
				if err := checks.Err(); err != nil {
					t.Fatalf("creation was blocked by %v", err)
				}
				return
			}
			if !strings.Contains(k.Detail, tc.wantDetail) {
				t.Fatalf("detail %q does not say what is missing (%q)", k.Detail, tc.wantDetail)
			}
			if !strings.Contains(k.Fix, tc.wantFix) {
				t.Fatalf("fix %q does not name the role that would fix it (%q)", k.Fix, tc.wantFix)
			}
			if checks.Err() == nil {
				t.Fatal("a failed management check did not block creation")
			}
		})
	}
}

// TestCreateManagementCheckWithoutAResourceGroup covers the case Azure cannot
// answer: there is no effective-permissions API above a resource group, so the
// check proves what it can and says what it cannot.
func TestCreateManagementCheckWithoutAResourceGroup(t *testing.T) {
	t.Run("subscription visible", func(t *testing.T) {
		arm := newARM(t)
		c := newCreateClient(arm, nil)
		plan, err := c.PlanCreate(context.Background(), testCreateConfig())
		if err != nil {
			t.Fatal(err)
		}
		checks, err := c.CheckCreatePermissions(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if !checks.Management.OK {
			t.Fatalf("management = %+v; the subscription is readable", checks.Management)
		}
		if !strings.Contains(checks.Management.Detail, "does not exist yet") {
			t.Fatalf("detail %q hides that the create right could not be tested", checks.Management.Detail)
		}
		if !checks.RoleAssignment.Pending {
			t.Fatalf("role assignment = %+v; it cannot be answered before the group exists", checks.RoleAssignment)
		}
		if !strings.Contains(checks.Summary(), "pending") {
			t.Fatalf("the summary reports an untested check as passed or failed:\n%s", checks.Summary())
		}
	})

	t.Run("subscription not visible", func(t *testing.T) {
		arm := newARM(t)
		arm.subErr = http.StatusForbidden
		c := newCreateClient(arm, nil)
		plan, err := c.PlanCreate(context.Background(), testCreateConfig())
		if err != nil {
			t.Fatal(err)
		}
		checks, err := c.CheckCreatePermissions(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if checks.Management.OK {
			t.Fatal("the management check passed with an unreadable subscription")
		}
		if !strings.Contains(checks.Management.Fix, "Contributor") {
			t.Fatalf("fix %q does not name the role", checks.Management.Fix)
		}
	})
}

// TestRoleAssignmentCheckIsSeparateFromManagement: the right to create storage
// and the right to grant a role are different rights, and an operator holding
// one and not the other must be told which.
func TestRoleAssignmentCheckIsSeparateFromManagement(t *testing.T) {
	t.Run("may grant roles but may not create storage", func(t *testing.T) {
		arm := newARM(t)
		arm.actions = []string{roleAssignmentWrite}
		c, plan := planWithGroup(t, arm)
		checks, err := c.CheckCreatePermissions(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if checks.Management.OK {
			t.Fatal("the management check passed without any storage write action")
		}
		if !checks.RoleAssignment.OK {
			t.Fatalf("role assignment = %+v; the identity does hold %s", checks.RoleAssignment, roleAssignmentWrite)
		}
	})

	t.Run("may create storage but may not grant roles", func(t *testing.T) {
		arm := newARM(t)
		arm.actions = []string{"Microsoft.Storage/*"}
		c, plan := planWithGroup(t, arm)
		checks, err := c.CheckCreatePermissions(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if !checks.Management.OK {
			t.Fatalf("management = %+v", checks.Management)
		}
		if checks.RoleAssignment.OK {
			t.Fatal("the role assignment check passed without roleAssignments/write")
		}
		if !strings.Contains(checks.RoleAssignment.Fix, "User Access Administrator") ||
			!strings.Contains(checks.RoleAssignment.Fix, UploaderRole) {
			t.Fatalf("fix %q does not name the role to grant or the role to be granted", checks.RoleAssignment.Fix)
		}
		// Not being able to grant the role does not stop creation:
		// somebody else can make the assignment.
		if err := checks.Err(); err != nil {
			t.Fatalf("a failed role assignment check blocked creation: %v", err)
		}
	})

	t.Run("blob data is never reported as passed before it exists", func(t *testing.T) {
		arm := newARM(t)
		c, plan := planWithGroup(t, arm)
		checks, err := c.CheckCreatePermissions(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if checks.BlobData.OK || !checks.BlobData.Pending {
			t.Fatalf("blob data = %+v; nothing has written a blob at this point", checks.BlobData)
		}
		if !strings.Contains(checks.BlobData.Detail, UploaderRole) {
			t.Fatalf("detail %q does not say what blob access is waiting on", checks.BlobData.Detail)
		}
	})
}

// --- granting the role -----------------------------------------------------

func TestAssignUploaderRoleGrantsOneRoleOnTheContainer(t *testing.T) {
	arm := newARM(t)
	c := newCreateClient(arm, nil)
	d := testDestination()

	ra, err := c.AssignUploaderRole(context.Background(), d, "principal-object-id")
	if err != nil {
		t.Fatal(err)
	}
	if !ra.Created {
		t.Fatal("the assignment reports it was already in place")
	}
	if ra.Scope != testAccountID+"/blobServices/default/containers/guacdeploy" {
		t.Fatalf("scope = %q; the role must be granted on the container, not the account or the subscription", ra.Scope)
	}
	if !strings.HasSuffix(ra.RoleDefinitionID, UploaderRoleID) {
		t.Fatalf("role definition = %q, want %s (%s)", ra.RoleDefinitionID, UploaderRoleID, UploaderRole)
	}
	props := mapOf(arm.bodyOf(ra.Scope + "/providers/Microsoft.Authorization/roleAssignments/" + ra.Name)["properties"])
	if props["principalId"] != "principal-object-id" || props["principalType"] != "ServicePrincipal" {
		t.Fatalf("the request granted %v", props)
	}
	if len(arm.roles) != 1 {
		t.Fatalf("%d role assignments were made; the uploader needs exactly one", len(arm.roles))
	}
}

// TestAssignUploaderRoleIsIdempotent: the assignment name is derived, so a
// retry after a lost response addresses the same assignment, and Azure's
// "already exists" is the answer, not a failure.
func TestAssignUploaderRoleIsIdempotent(t *testing.T) {
	arm := newARM(t)
	c := newCreateClient(arm, nil)
	d := testDestination()
	ctx := context.Background()

	first, err := c.AssignUploaderRole(ctx, d, "principal-object-id")
	if err != nil {
		t.Fatal(err)
	}
	arm.roleConflict = "RoleAssignmentExists"
	second, err := c.AssignUploaderRole(ctx, d, "principal-object-id")
	if err != nil {
		t.Fatalf("a repeat grant was reported as a failure: %v", err)
	}
	if second.Name != first.Name {
		t.Fatalf("the assignment name is not deterministic: %q then %q", first.Name, second.Name)
	}
	if second.Created {
		t.Fatal("a repeat grant reported that it created the assignment")
	}
	if len(arm.roles) != 1 {
		t.Fatalf("%d role assignments exist after a retry; there must be one", len(arm.roles))
	}
	// A different principal gets a different assignment, so the name is
	// derived from the inputs rather than fixed.
	other, err := c.AssignUploaderRole(ctx, d, "another-principal")
	if err != nil {
		t.Fatal(err)
	}
	if other.Name == first.Name {
		t.Fatal("two principals derived the same role assignment name")
	}
}

func TestAssignUploaderRoleReportsWhatIsMissing(t *testing.T) {
	arm := newARM(t)
	arm.roleDenied = true
	c := newCreateClient(arm, nil)
	_, err := c.AssignUploaderRole(context.Background(), testDestination(), "principal-object-id")
	if err == nil {
		t.Fatal("a denied grant was reported as success")
	}
	for _, want := range []string{"User Access Administrator", UploaderRole} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("the access token appears in the error")
	}

	if _, err := c.AssignUploaderRole(context.Background(), testDestination(), ""); err == nil {
		t.Fatal("a grant without a principal object ID was accepted")
	}
	if _, err := c.AssignUploaderRole(context.Background(), Destination{}, "p"); err == nil {
		t.Fatal("a grant without a destination was accepted")
	}
}

// --- proving the role took effect ------------------------------------------

// flipAfter makes the data plane refuse everything until the nth listing, which
// is how an assignment that has not replicated yet behaves.
func flipAfter(t *testing.T, store *blobStore, n int) *Client {
	t.Helper()
	store.denyList, store.denyPut = true, true
	c := newCreateClient(newARM(t), store)
	inner := c.Do
	seen := 0
	c.Do = func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.RawQuery, "comp=list") {
			seen++
			if seen >= n {
				store.denyList, store.denyPut = false, false
			}
		}
		return inner(req)
	}
	return c
}

func TestWaitRoleEffectivePollsUntilTheRoleLands(t *testing.T) {
	store := newBlobStore(t)
	c := flipAfter(t, store, 3)
	var slept []time.Duration

	k := WaitRoleEffective(context.Background(), c, testDestination(), testDeployment,
		RoleWait{Within: time.Minute, Interval: 5 * time.Second, Sleep: func(d time.Duration) { slept = append(slept, d) }})
	if !k.OK {
		t.Fatalf("the role never registered as effective: %+v", k)
	}
	if len(slept) != 2 {
		t.Fatalf("waited %d times between polls, want 2 before the third attempt worked", len(slept))
	}
	if !strings.Contains(k.Detail, UploaderRole) || !strings.Contains(k.Detail, "in effect") {
		t.Fatalf("detail %q does not report what became effective", k.Detail)
	}
	if k.Name != CheckBlobData {
		t.Fatalf("check name = %q; the evidence is a real blob write, so it is the blob data check", k.Name)
	}
	if len(store.blobs) != 0 {
		t.Fatalf("the write probe left %d blobs behind: %v", len(store.blobs), store.blobs)
	}
}

func TestWaitRoleEffectiveReportsARoleThatNeverLands(t *testing.T) {
	store := newBlobStore(t)
	store.denyList, store.denyPut = true, true
	c := newCreateClient(newARM(t), store)

	// Real but tiny waits: the deadline is wall-clock, so a fake sleep would
	// spin for the whole window instead of shortening the test.
	polls := 0
	w := RoleWait{Within: 30 * time.Millisecond, Interval: 5 * time.Millisecond,
		Sleep: func(d time.Duration) { polls++; time.Sleep(d) }}
	k := WaitRoleEffective(context.Background(), c, testDestination(), testDeployment, w)
	if k.OK {
		t.Fatal("a role that never took effect was reported as effective")
	}
	if polls == 0 {
		t.Fatal("the check gave up without polling; role assignments are eventually consistent")
	}
	for _, want := range []string{UploaderRole, w.within().String(), "had not taken effect"} {
		if !strings.Contains(k.Detail, want) {
			t.Fatalf("detail %q does not mention %q", k.Detail, want)
		}
	}
	if !strings.Contains(k.Fix, "Azure portal") {
		t.Fatalf("fix %q does not tell the operator where to look", k.Fix)
	}
	if strings.Contains(k.Detail+k.Fix, testToken) {
		t.Fatal("the access token appears in the check")
	}
	blob, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), testToken) {
		t.Fatal("the access token appears in the persisted check")
	}
}

func TestWaitRoleEffectiveNeedsTheUploadersOwnClient(t *testing.T) {
	k := WaitRoleEffective(context.Background(), nil, testDestination(), testDeployment, RoleWait{})
	if k.OK {
		t.Fatal("the role was reported effective without any evidence")
	}
	if !strings.Contains(k.Detail, "service principal") {
		t.Fatalf("detail %q does not say what is missing", k.Detail)
	}
}
