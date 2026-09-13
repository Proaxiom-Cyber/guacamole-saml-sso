package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Check is the result of one permission check.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Fix names the role that would make a failed check pass. It is empty
	// when the check passed.
	Fix string `json:"fix,omitempty"`
	// Pending means the check could not be carried out yet, because what it
	// tests does not exist so far. It is not a pass and it is not a failure:
	// reporting "FAILED" for something nobody has tried would send an
	// administrator to fix a permission that is not missing. Only the
	// creation path sets it (see CreateChecks); the reuse path's three
	// checks all run against resources that already exist.
	Pending bool `json:"pending,omitempty"`
}

// Preflight holds the three permission checks the specification requires to
// be separate: "Check management permissions separately from blob data access
// and role assignment."
//
// They really are three different permissions, and an operator hits them one
// at a time. Reader on the storage account lets you list the account and its
// containers and gives you no access to a single blob. Storage Blob Data
// Contributor lets you write blobs and does not let you see the account in
// the portal's resource list. User Access Administrator lets you grant the
// unattended service principal its role and does neither of the others. A
// single "access denied" would send an administrator to the wrong place every
// time, so each check runs on its own, all three always run, and each failure
// names the role that fixes it.
type Preflight struct {
	Management     Check `json:"management"`
	BlobData       Check `json:"blob_data"`
	RoleAssignment Check `json:"role_assignment"`
}

// Check names.
const (
	CheckManagement     = "resource management"
	CheckBlobData       = "blob data access"
	CheckRoleAssignment = "role assignment"
)

// OK reports whether backups can be uploaded now. Role assignment is
// deliberately not part of it: it is needed only to grant the unattended
// service principal its role, which someone else may have done already or may
// do for the administrator.
func (p Preflight) OK() bool { return p.Management.OK && p.BlobData.OK }

// Err returns the first blocking failure as an actionable error, or nil.
func (p Preflight) Err() error {
	for _, c := range []Check{p.Management, p.BlobData} {
		if !c.OK {
			return fmt.Errorf("%s check failed: %s. %s", c.Name, c.Detail, c.Fix)
		}
	}
	return nil
}

// Summary renders all three checks for an operator.
func (p Preflight) Summary() string {
	var b strings.Builder
	for _, c := range []Check{p.Management, p.BlobData, p.RoleAssignment} {
		mark := "FAILED"
		if c.OK {
			mark = "ok"
		}
		fmt.Fprintf(&b, "%-20s %-7s %s\n", c.Name+":", mark, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&b, "%-20s %-7s %s\n", "", "", "To fix: "+c.Fix)
		}
	}
	return b.String()
}

// CheckPermissions runs all three checks against an already-selected
// destination. Every check runs even when an earlier one failed, so one pass
// tells the administrator everything that has to be granted rather than one
// thing at a time.
//
// It returns an error only when a check could not be carried out at all. A
// denied permission is a result, not an error.
func (c *Client) CheckPermissions(ctx context.Context, d Destination, deploymentID string) (Preflight, error) {
	if !d.Configured() {
		return Preflight{}, fmt.Errorf("no Azure destination is selected; there is nothing to check")
	}
	if deploymentID == "" {
		return Preflight{}, fmt.Errorf("the permission check needs the deployment ID: its write probe is written and removed under this deployment's own prefix")
	}
	return Preflight{
		Management:     c.checkManagement(ctx, d),
		BlobData:       c.checkBlobData(ctx, d, deploymentID),
		RoleAssignment: c.checkRoleAssignment(ctx, d),
	}, nil
}

// checkManagement proves the identity can see the storage account itself.
func (c *Client) checkManagement(ctx context.Context, d Destination) Check {
	k := Check{Name: CheckManagement}
	if _, err := c.armGet(ctx, d.AccountID+"?api-version="+armStorageAPI); err != nil {
		k.Detail = err.Error()
		switch {
		case NotFound(err):
			k.Fix = fmt.Sprintf("check that storage account %s still exists in subscription %s; this tool does not create storage accounts",
				d.Account, d.SubscriptionID)
		default:
			k.Fix = fmt.Sprintf("assign the Reader role on storage account %s (or on its resource group %s) to the signed-in identity",
				d.Account, d.ResourceGroup)
		}
		return k
	}
	k.OK = true
	k.Detail = fmt.Sprintf("the storage account %s can be read through Azure Resource Manager", d.Account)
	return k
}

// checkBlobData proves the identity can read and write blobs in the
// container, which is a different permission from seeing the account.
//
// Read is a listing restricted to this deployment's prefix. Write is a real
// write: a probe blob under this deployment's own prefix, read back, then
// removed with the same marker check every deletion here uses. Only a real
// write can prove a write is permitted — a listing succeeds for Storage Blob
// Data Reader, which cannot upload a single backup.
//
// Read and write are reported apart. "Can list but cannot write" is the
// common half-configured case, and it gets its own message and its own role.
func (c *Client) checkBlobData(ctx context.Context, d Destination, deploymentID string) Check {
	k := Check{Name: CheckBlobData}
	prefix := d.Prefix(deploymentID)
	if _, err := c.ListBlobs(ctx, d, prefix, 1); err != nil {
		k.Detail = fmt.Sprintf("blobs in container %s cannot be listed: %v", d.Container, err)
		if NotFound(err) {
			k.Fix = fmt.Sprintf("check that container %s exists in storage account %s; this tool does not create containers", d.Container, d.Account)
		} else {
			k.Fix = fmt.Sprintf("assign the Storage Blob Data Contributor role on container %s in storage account %s to the identity that runs the upload (Reader on the account is not enough: it grants no blob access at all)",
				d.Container, d.Account)
		}
		return k
	}

	probe := prefix + "permission-probe"
	content := []byte("guacdeploy write probe\n")
	if err := c.PutBlob(ctx, d, probe, content, md5Base64(content), map[string]string{ownerMetadata: deploymentID}); err != nil {
		k.Detail = fmt.Sprintf("blobs in container %s can be listed, but writing one failed: %v", d.Container, err)
		k.Fix = fmt.Sprintf("assign the Storage Blob Data Contributor role on container %s in storage account %s to the identity that runs the upload; Storage Blob Data Reader can list blobs but cannot upload a backup",
			d.Container, d.Account)
		return k
	}
	if _, err := c.HeadBlob(ctx, d, probe); err != nil {
		k.Detail = fmt.Sprintf("a probe blob was written to container %s but could not be read back: %v", d.Container, err)
		k.Fix = fmt.Sprintf("assign the Storage Blob Data Contributor role on container %s in storage account %s to the identity that runs the upload", d.Container, d.Account)
		return k
	}
	k.OK = true
	k.Detail = fmt.Sprintf("blobs under %s in container %s can be listed, written, and read back", prefix, d.Container)
	if err := c.DeleteOwnedBlob(ctx, d, probe, deploymentID); err != nil {
		// Not a failure of the check: the write worked, which is what was
		// being asked. The leftover is named so it does not become a mystery
		// object in someone else's container.
		k.Detail += fmt.Sprintf("; the probe blob %s could not be removed (%v) and can be deleted by hand", probe, err)
	}
	return k
}

// roleAssignmentWrite is the action needed to grant a role, which is what an
// administrator setting up the unattended service principal has to do.
const roleAssignmentWrite = "Microsoft.Authorization/roleAssignments/write"

// checkRoleAssignment reports whether the signed-in identity could grant the
// unattended service principal its Storage Blob Data Contributor role on this
// account.
//
// The evidence is the Permissions - List For Resource API, which returns the
// caller's own allowed and denied actions at a scope. That is a real answer
// from Azure rather than a guess from token claims, and it needs no
// speculative write.
//
// A failure here does not stop backups: it means somebody else has to make
// the role assignment. That is why it is reported separately and is not part
// of Preflight.OK.
func (c *Client) checkRoleAssignment(ctx context.Context, d Destination) Check {
	k := Check{Name: CheckRoleAssignment}
	raw, err := c.armGet(ctx, d.AccountID+"/providers/Microsoft.Authorization/permissions?api-version="+armAuthorizationAPI)
	if err != nil {
		k.Detail = fmt.Sprintf("the effective permissions on %s could not be read: %v", d.Account, err)
		k.Fix = fmt.Sprintf("assign the User Access Administrator or Owner role on storage account %s to the identity that has to grant the unattended service principal its Storage Blob Data Contributor role; without it, someone with that role has to make the assignment instead", d.Account)
		return k
	}
	allowed, err := permits(raw, roleAssignmentWrite)
	if err != nil {
		k.Detail = err.Error()
		k.Fix = "check the role assignment by hand in the Azure portal before relying on unattended uploads"
		return k
	}
	if !allowed {
		k.Detail = fmt.Sprintf("the signed-in identity does not hold %s on storage account %s", roleAssignmentWrite, d.Account)
		k.Fix = fmt.Sprintf("assign the User Access Administrator or Owner role on storage account %s to the identity that has to grant the unattended service principal its Storage Blob Data Contributor role; without it, someone with that role has to make the assignment instead", d.Account)
		return k
	}
	k.OK = true
	k.Detail = fmt.Sprintf("the signed-in identity can assign roles on storage account %s, so it can grant the unattended service principal blob data access", d.Account)
	return k
}

// permits decodes the effective-permissions reply and reports whether one
// action is allowed and not denied. Azure returns one entry per role the caller
// holds at the scope, so any entry granting the action is enough, and a
// notActions entry on that same role takes it away again — which is how a
// denied action is expressed.
func permits(raw []byte, action string) (bool, error) {
	var out struct {
		Value []struct {
			Actions    []string `json:"actions"`
			NotActions []string `json:"notActions"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, fmt.Errorf("the effective permissions reply is not readable JSON: %w", err)
	}
	for _, p := range out.Value {
		if matchesAction(p.Actions, action) && !matchesAction(p.NotActions, action) {
			return true, nil
		}
	}
	return false, nil
}

// matchesAction reports whether any pattern covers action. Azure action
// patterns use "*" as a wildcard for any run of characters, so "*",
// "Microsoft.Authorization/*" and the exact action all match.
func matchesAction(patterns []string, action string) bool {
	for _, p := range patterns {
		if matchAction(p, action) {
			return true
		}
	}
	return false
}

// matchAction matches one wildcard pattern, case-insensitively as Azure
// treats resource provider actions. It walks the pattern segment by segment
// rather than building a regular expression, so a pattern from the service
// can never be a regular-expression injection.
func matchAction(pattern, action string) bool {
	pattern, action = strings.ToLower(pattern), strings.ToLower(action)
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == action
	}
	if !strings.HasPrefix(action, parts[0]) {
		return false
	}
	rest := action[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(rest, parts[i])
		if j < 0 {
			return false
		}
		rest = rest[j+len(parts[i]):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}
