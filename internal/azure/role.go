package azure

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// UploaderRole is the one role the unattended uploader needs, and the only
// role this package ever assigns. It is granted on the container, not on the
// account and not on the subscription, so the scheduled upload can write this
// deployment's backups and reach nothing else in Azure.
const (
	UploaderRole   = "Storage Blob Data Contributor"
	UploaderRoleID = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
)

// Management-plane actions checked before creation. They are the exact actions
// the creation calls need, so a failed check names the missing right rather
// than "access denied".
const (
	accountWrite   = "Microsoft.Storage/storageAccounts/write"
	containerWrite = "Microsoft.Storage/storageAccounts/blobServices/containers/write"
)

// ContainerScope is the ARM scope of the container, which is where the
// uploader's role assignment goes.
func (d Destination) ContainerScope() string {
	if d.AccountID == "" || d.Container == "" {
		return ""
	}
	return d.AccountID + "/blobServices/default/containers/" + d.Container
}

// RoleAssignment is the uploader's granted role, as non-secret references.
type RoleAssignment struct {
	Name             string `json:"name"`  // the assignment's own name, a GUID
	Scope            string `json:"scope"` // the container
	PrincipalID      string `json:"principal_id"`
	RoleDefinitionID string `json:"role_definition_id"`
	// Created is false when an equivalent assignment was already in place,
	// which is what a retry after a lost response finds.
	Created bool `json:"created"`
}

// AssignUploaderRole grants the unattended service principal Storage Blob Data
// Contributor on the container.
//
// The assignment's name is derived from the scope, the principal and the role
// definition (roleAssignmentName), so it is the same on every run. That is the
// whole reconciliation story for role assignments: they carry no tag, no
// metadata and no description, so there is nowhere to put an ownership marker,
// and a deterministic name is the evidence instead. A retry after a lost
// response addresses the same assignment and cannot make a second one. Azure
// answers a repeat with 409 RoleAssignmentExists, which is reported here as
// "already in place", not as a failure — that is also the answer when somebody
// granted the role by hand before setup ran.
func (c *Client) AssignUploaderRole(ctx context.Context, d Destination, principalObjectID string) (RoleAssignment, error) {
	scope := d.ContainerScope()
	if scope == "" {
		return RoleAssignment{}, fmt.Errorf("granting the uploader its role needs the container's resource ID; select or create the destination first")
	}
	if principalObjectID == "" {
		return RoleAssignment{}, fmt.Errorf("granting the uploader its role needs the service principal's object ID (the enterprise application's object ID, not the application ID)")
	}
	ra := RoleAssignment{
		Scope:       scope,
		PrincipalID: principalObjectID,
		RoleDefinitionID: "/subscriptions/" + d.SubscriptionID +
			"/providers/Microsoft.Authorization/roleDefinitions/" + UploaderRoleID,
	}
	ra.Name = roleAssignmentName(scope, principalObjectID, UploaderRoleID)

	body := map[string]any{"properties": map[string]any{
		"roleDefinitionId": ra.RoleDefinitionID,
		"principalId":      principalObjectID,
		"principalType":    "ServicePrincipal",
	}}
	err := c.armPut(ctx, scope+"/providers/Microsoft.Authorization/roleAssignments/"+ra.Name+
		"?api-version="+armAuthorizationAPI, body)
	switch {
	case err == nil:
		ra.Created = true
		return ra, nil
	case roleAlreadyAssigned(err):
		return ra, nil
	default:
		return RoleAssignment{}, fmt.Errorf("%s could not be granted to principal %s on container %s: %w. The identity making the grant needs User Access Administrator or Owner on storage account %s",
			UploaderRole, principalObjectID, d.Container, err, d.Account)
	}
}

// roleAlreadyAssigned reports whether the failure means the same principal
// already holds the same role at the same scope.
func roleAlreadyAssigned(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict &&
		strings.EqualFold(e.Code, "RoleAssignmentExists")
}

// roleAssignmentName derives the assignment's name. Azure requires a GUID, and
// deriving it from the scope, the principal and the role makes the whole
// operation idempotent: the same three inputs always address the same
// assignment.
//
// It is a hash, not a random identifier, so the bits that mark a UUID's version
// and variant are set by hand. Azure only requires a well-formed GUID; this
// keeps it well formed.
func roleAssignmentName(scope, principalID, roleDefinitionID string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(scope) + "|" + principalID + "|" + roleDefinitionID))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RoleWait tunes the poll in WaitRoleEffective. The zero value polls every 10
// seconds for 5 minutes.
type RoleWait struct {
	Within   time.Duration
	Interval time.Duration
	Sleep    func(time.Duration) // nil means time.Sleep; tests replace it
}

func (w RoleWait) within() time.Duration {
	if w.Within > 0 {
		return w.Within
	}
	return 5 * time.Minute
}

func (w RoleWait) interval() time.Duration {
	if w.Interval > 0 {
		return w.Interval
	}
	return 10 * time.Second
}

func (w RoleWait) sleep(d time.Duration) {
	if w.Sleep != nil {
		w.Sleep(d)
		return
	}
	time.Sleep(d)
}

// WaitRoleEffective proves the granted role actually works, by polling until
// the uploader can write a blob.
//
// Role assignments are eventually consistent. Azure records the assignment
// straight away and the blob service starts honouring it some time later —
// usually seconds, occasionally minutes. So a successful PUT of the assignment
// is not proof that the nightly upload will work, and this does not treat it as
// proof.
//
// The evidence is a real write by the identity that was granted the role:
// uploader must be a Client signed in as the service principal, not as the
// administrator. It runs the same probe the reuse path uses — a blob written
// under this deployment's own prefix, read back, then removed — and returns the
// same blob data access Check, so a caller reports one thing either way.
//
// When the role never lands, the Check says so with the deadline and the role,
// and the deployment is left with a working setup whose scheduled upload will
// fail. That is reported, never assumed away.
func WaitRoleEffective(ctx context.Context, uploader *Client, d Destination, deploymentID string, w RoleWait) Check {
	k := Check{Name: CheckBlobData}
	if uploader == nil {
		k.Detail = "the granted role was not verified: no client signed in as the unattended service principal was supplied"
		k.Fix = "verify the role by running the blob data check with the service principal's own credentials before relying on scheduled uploads"
		return k
	}
	if !d.Configured() || deploymentID == "" {
		k.Detail = "the granted role was not verified: the destination and the deployment ID are needed for the write probe"
		return k
	}
	deadline := time.Now().Add(w.within())
	for attempt := 1; ; attempt++ {
		k = uploader.checkBlobData(ctx, d, deploymentID)
		if k.OK {
			k.Detail = fmt.Sprintf("%s on container %s is in effect for the unattended uploader: %s (after %d attempt(s))",
				UploaderRole, d.Container, k.Detail, attempt)
			return k
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			k.Detail = fmt.Sprintf("%s was granted on container %s but had not taken effect after %s: %s",
				UploaderRole, d.Container, w.within(), k.Detail)
			k.Fix = fmt.Sprintf("check in the Azure portal that the unattended service principal holds %s on container %s; role assignments are usually in effect within a few minutes, and scheduled uploads fail until it is",
				UploaderRole, d.Container)
			return k
		}
		w.sleep(w.interval())
	}
}

// CreateChecks holds the three permission checks the creation path needs, kept
// apart for the same reason CheckPermissions keeps its three apart: they are
// three different rights, an operator hits them one at a time, and a single
// "access denied" sends them to the wrong place.
//
//	Management      may I create the resource group, storage account and
//	                container? A management-plane right (Contributor).
//	RoleAssignment  may I grant the uploader its data role? A different
//	                right again (User Access Administrator or Owner), held
//	                by neither of the others.
//	BlobData        can the uploader write a blob? A data-plane right that
//	                does not exist until the role assignment above is made
//	                and has taken effect, so it is "pending" here and is
//	                answered by WaitRoleEffective afterwards.
type CreateChecks struct {
	Management     Check `json:"management"`
	RoleAssignment Check `json:"role_assignment"`
	BlobData       Check `json:"blob_data"`
}

// OK reports whether creation may proceed. Only the management check blocks it:
// without the right to assign roles somebody else can still make the
// assignment, and blob data access does not exist yet.
func (p CreateChecks) OK() bool { return p.Management.OK }

// Err returns the blocking failure as an actionable error, or nil.
func (p CreateChecks) Err() error {
	if !p.Management.OK {
		return fmt.Errorf("%s check failed: %s. %s", p.Management.Name, p.Management.Detail, p.Management.Fix)
	}
	return nil
}

// Summary renders all three checks for an operator.
func (p CreateChecks) Summary() string {
	var b strings.Builder
	for _, c := range []Check{p.Management, p.RoleAssignment, p.BlobData} {
		mark := "FAILED"
		switch {
		case c.OK:
			mark = "ok"
		case c.Pending:
			mark = "pending"
		}
		fmt.Fprintf(&b, "%-20s %-7s %s\n", c.Name+":", mark, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&b, "%-20s %-7s %s\n", "", "", "To fix: "+c.Fix)
		}
	}
	return b.String()
}

// CheckCreatePermissions runs the creation path's permission checks. Every
// check runs even when an earlier one failed, so one pass tells the
// administrator everything that has to be granted.
//
// It returns an error only when a check could not be carried out at all. A
// denied permission is a result, not an error.
func (c *Client) CheckCreatePermissions(ctx context.Context, plan *CreatePlan) (CreateChecks, error) {
	if plan == nil {
		return CreateChecks{}, fmt.Errorf("there is no creation plan to check permissions against")
	}
	var scope string
	if plan.ResourceGroup != nil {
		scope = plan.ResourceGroup.ID
	}
	return CreateChecks{
		Management:     c.checkCreateManagement(ctx, plan, scope),
		RoleAssignment: c.checkCreateRoleAssignment(ctx, plan, scope),
		BlobData:       pendingBlobData(plan),
	}, nil
}

// checkCreateManagement reports whether the signed-in identity may create the
// storage account and the container.
//
// When the resource group already exists, the evidence is Azure's own answer:
// Permissions - List For Resource Group returns the caller's allowed and denied
// actions at that scope, and the two actions creation needs are looked for by
// name.
//
// When the resource group does not exist there is no such answer to be had.
// Azure reports effective permissions for an existing resource or resource
// group only; there is no subscription-scope equivalent. So the check proves
// what it can — that the subscription is visible to this identity — and says
// plainly that the right to create the group itself is proved by the creation.
// It is not reported as a pass that was never tested.
func (c *Client) checkCreateManagement(ctx context.Context, plan *CreatePlan, scope string) Check {
	k := Check{Name: CheckManagement}
	cfg := plan.Config
	if scope == "" {
		if _, err := c.armGet(ctx, "/subscriptions/"+cfg.SubscriptionID+"?api-version="+armSubscriptionsAPI); err != nil {
			k.Detail = fmt.Sprintf("subscription %s cannot be read: %v", cfg.SubscriptionID, err)
			k.Fix = fmt.Sprintf("assign the Contributor role on subscription %s to the signed-in identity; creating a resource group, a storage account and a container are all management-plane rights",
				cfg.SubscriptionID)
			return k
		}
		k.OK = true
		k.Detail = fmt.Sprintf("subscription %s can be read. Resource group %s does not exist yet, and Azure reports effective permissions only for a resource group that does, so the right to create it is proved by the creation itself",
			cfg.SubscriptionID, cfg.ResourceGroup)
		k.Fix = fmt.Sprintf("if creation is refused, assign the Contributor role on subscription %s to the signed-in identity", cfg.SubscriptionID)
		return k
	}

	raw, err := c.armGet(ctx, scope+"/providers/Microsoft.Authorization/permissions?api-version="+armAuthorizationAPI)
	if err != nil {
		k.Detail = fmt.Sprintf("the effective permissions on resource group %s could not be read: %v", cfg.ResourceGroup, err)
		k.Fix = fmt.Sprintf("assign the Contributor role on resource group %s to the signed-in identity", cfg.ResourceGroup)
		return k
	}
	for _, action := range []string{accountWrite, containerWrite} {
		allowed, err := permits(raw, action)
		if err != nil {
			k.Detail = err.Error()
			k.Fix = "check the role assignments on the resource group by hand in the Azure portal before creating storage"
			return k
		}
		if !allowed {
			k.Detail = fmt.Sprintf("the signed-in identity does not hold %s on resource group %s", action, cfg.ResourceGroup)
			k.Fix = fmt.Sprintf("assign the Contributor role (or Storage Account Contributor) on resource group %s to the signed-in identity", cfg.ResourceGroup)
			return k
		}
	}
	k.OK = true
	k.Detail = fmt.Sprintf("the signed-in identity can create a storage account and a container in resource group %s", cfg.ResourceGroup)
	return k
}

// checkCreateRoleAssignment reports whether the signed-in identity could grant
// the unattended service principal its data role. It is the same question
// checkRoleAssignment asks of an existing account, asked at the resource group
// instead, because the account may not exist yet.
func (c *Client) checkCreateRoleAssignment(ctx context.Context, plan *CreatePlan, scope string) Check {
	k := Check{Name: CheckRoleAssignment}
	fix := fmt.Sprintf("assign the User Access Administrator or Owner role on resource group %s to the identity that has to grant the unattended service principal its %s role; without it, someone with that role has to make the assignment instead",
		plan.Config.ResourceGroup, UploaderRole)
	if scope == "" {
		k.Pending = true
		k.Detail = fmt.Sprintf("resource group %s does not exist yet, so Azure cannot report whether this identity may assign roles in it; it is answered once the group is created",
			plan.Config.ResourceGroup)
		k.Fix = fix
		return k
	}
	raw, err := c.armGet(ctx, scope+"/providers/Microsoft.Authorization/permissions?api-version="+armAuthorizationAPI)
	if err != nil {
		k.Detail = fmt.Sprintf("the effective permissions on resource group %s could not be read: %v", plan.Config.ResourceGroup, err)
		k.Fix = fix
		return k
	}
	allowed, err := permits(raw, roleAssignmentWrite)
	if err != nil {
		k.Detail = err.Error()
		k.Fix = "check the role assignment by hand in the Azure portal before relying on unattended uploads"
		return k
	}
	if !allowed {
		k.Detail = fmt.Sprintf("the signed-in identity does not hold %s on resource group %s", roleAssignmentWrite, plan.Config.ResourceGroup)
		k.Fix = fix
		return k
	}
	k.OK = true
	k.Detail = fmt.Sprintf("the signed-in identity can assign roles in resource group %s, so it can grant the unattended service principal %s on the container",
		plan.Config.ResourceGroup, UploaderRole)
	return k
}

// pendingBlobData states what blob data access is waiting on. It is never
// reported as a pass: nothing has written a blob at this point.
func pendingBlobData(plan *CreatePlan) Check {
	return Check{
		Name:    CheckBlobData,
		Pending: true,
		Detail: fmt.Sprintf("container %s does not hold the uploader's role yet, so blob data access cannot be proved before creation; it is proved by a real write after %s is granted",
			plan.Config.Container, UploaderRole),
		Fix: fmt.Sprintf("after creation, grant %s on the container to the unattended service principal and confirm it has taken effect", UploaderRole),
	}
}
