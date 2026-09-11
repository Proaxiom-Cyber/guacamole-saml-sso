package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	// spTagSSO makes the service principal appear as a non-gallery
	// single-sign-on enterprise application in the portal, as the
	// "Create your own application" template would.
	spTagSSO = "WindowsAzureActiveDirectoryCustomSingleSignOnApplication"
	// nilRoleID is Graph's "default" app role for applications that define
	// no roles of their own, which a directly created application does not.
	nilRoleID = "00000000-0000-0000-0000-000000000000"
	// GroupClaimAttribute is the SAML attribute name Entra gives the groups
	// claim. The stack's SAML_GROUP_ATTRIBUTE must be set to this value.
	GroupClaimAttribute = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
)

// Config identifies one deployment's Entra sign-in.
type Config struct {
	Hostname      string // public hostname; entity ID becomes https://<hostname>/guacamole
	DeploymentID  string // ownership marker value, from state.State.DeploymentID
	AdminGroup    string // display name of the administrator group
	OperatorGroup string // display name of the operator group
	// AfterUncertainCreate marks a resume after a creation request whose
	// response was lost (an action journalled ResultUncertain). Plan then
	// treats a name match without our marker as ErrRequiresReview instead
	// of a reusable pre-existing resource: it may be our half-landed
	// creation or somebody else's application, and only a person can tell.
	AfterUncertainCreate bool
}

func (cfg Config) validate() error {
	var missing []string
	for _, f := range []struct{ name, v string }{
		{"Hostname", cfg.Hostname}, {"DeploymentID", cfg.DeploymentID},
		{"AdminGroup", cfg.AdminGroup}, {"OperatorGroup", cfg.OperatorGroup},
	} {
		if f.v == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("entra config is incomplete: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Found is an existing application for this hostname's display name.
type Found struct {
	ObjectID    string
	AppID       string
	DisplayName string
	Marker      string // the guacdeploy marker found on it, "" when absent
	ProvenOurs  bool   // marker matches this deployment's ID
}

// FoundSP is the existing service principal for a found application.
type FoundSP struct {
	ObjectID                  string
	SingleSignOnMode          string
	AppRoleAssignmentRequired bool
	SigningKeyThumbprint      string
	AppRoleID                 string // first defined app role, else nilRoleID
}

// FoundGroup is an existing group matching a configured display name.
type FoundGroup struct {
	ObjectID   string
	Name       string
	ProvenOurs bool // description carries this deployment's marker
}

// Creation is one intended cloud creation, for the caller to journal before
// Apply runs. Entries are what Apply may create: every step queries first,
// so an entry can turn out to be a no-op on resume.
type Creation struct {
	Type string // application, service-principal, token-signing-certificate, group, app-role-assignment
	Name string
}

// FieldChange records the original and applied value of one field Apply
// changes on a pre-existing resource, ready for a SettingChange journal
// entry. Field names: "application.identifierUris",
// "application.web.redirectUris", "application.groupMembershipClaims",
// "application.optionalClaims.saml2Token",
// "servicePrincipal.preferredSingleSignOnMode",
// "servicePrincipal.appRoleAssignmentRequired".
type FieldChange struct {
	Field    string
	Original json.RawMessage
	Applied  json.RawMessage
}

// Plan is what Apply would do. The caller journals Creations (with a
// correlation identifier) before Apply, and must obtain interactive
// approval when App is a pre-existing application (App != nil and not
// ProvenOurs) with pending Changes.
type Plan struct {
	Config    Config
	App       *Found                 // nil: Apply creates the application
	SP        *FoundSP               // nil: Apply creates or finds it
	Groups    map[string]*FoundGroup // by display name; absent name: Apply creates it
	Creations []Creation
	Changes   []FieldChange // fields Apply will change on pre-existing resources
}

type appRecord struct {
	ID             string   `json:"id"`
	AppID          string   `json:"appId"`
	DisplayName    string   `json:"displayName"`
	Notes          string   `json:"notes"`
	Tags           []string `json:"tags"`
	IdentifierUris []string `json:"identifierUris"`
	Web            struct {
		RedirectUris []string `json:"redirectUris"`
	} `json:"web"`
	GroupMembershipClaims string `json:"groupMembershipClaims"`
	OptionalClaims        struct {
		Saml2Token []struct {
			Name                 string   `json:"name"`
			AdditionalProperties []string `json:"additionalProperties"`
		} `json:"saml2Token"`
	} `json:"optionalClaims"`
}

func (a *appRecord) marker() string {
	if strings.HasPrefix(a.Notes, "guacdeploy:") {
		return a.Notes
	}
	for _, t := range a.Tags {
		if strings.HasPrefix(t, "guacdeploy:") {
			return t
		}
	}
	return ""
}

func (a *appRecord) hasGroupNameClaim() bool {
	for _, cl := range a.OptionalClaims.Saml2Token {
		if cl.Name == "groups" && slices.Contains(cl.AdditionalProperties, "cloud_displayname") {
			return true
		}
	}
	return false
}

func odataQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // static shapes only
	}
	return b
}

// Plan looks up the tenant's current resources for this hostname and
// returns what Apply would create or change. It creates nothing.
func (c *Client) Plan(ctx context.Context, cfg Config) (*Plan, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	p := &Plan{Config: cfg, Groups: map[string]*FoundGroup{}}
	marker := Marker(cfg.DeploymentID)

	app, err := c.lookupApp(ctx, cfg)
	if err != nil {
		return nil, err
	}
	switch {
	case app == nil:
		// AfterUncertainCreate with no match: the query-before-retry ran
		// and found nothing, so creating again is the documented recovery.
		// ponytail: no delayed-visibility wait loop here; resume is a human
		// action minutes after the lost response. Add a re-query delay if a
		// lab run ever shows a duplicate.
		p.Creations = append(p.Creations,
			Creation{Type: "application", Name: AppDisplayName(cfg.Hostname)},
			Creation{Type: "service-principal", Name: AppDisplayName(cfg.Hostname)})
	case app.marker() == marker:
		p.App = &Found{ObjectID: app.ID, AppID: app.AppID, DisplayName: app.DisplayName,
			Marker: app.marker(), ProvenOurs: true}
	default:
		if cfg.AfterUncertainCreate {
			return nil, fmt.Errorf("%w: application %q exists but does not carry marker %s; it may be this deployment's half-recorded creation or an unrelated application", ErrRequiresReview, app.DisplayName, marker)
		}
		// Pre-existing. Refuse when it serves another entity ID: reusing it
		// would break whatever it currently signs in.
		if len(app.IdentifierUris) > 0 && !slices.Equal(app.IdentifierUris, []string{EntityID(cfg.Hostname)}) {
			return nil, fmt.Errorf("%w: application %q has entity ID(s) %v, not %s; refusing to repurpose it", ErrRequiresReview, app.DisplayName, app.IdentifierUris, EntityID(cfg.Hostname))
		}
		p.App = &Found{ObjectID: app.ID, AppID: app.AppID, DisplayName: app.DisplayName, Marker: app.marker()}
	}

	if p.App != nil {
		p.Changes = appChanges(app, cfg)
		sp, err := c.lookupSP(ctx, p.App.AppID)
		if err != nil {
			return nil, err
		}
		p.SP = sp
		if sp == nil {
			p.Creations = append(p.Creations, Creation{Type: "service-principal", Name: p.App.DisplayName})
		} else {
			p.Changes = append(p.Changes, spChanges(sp)...)
		}
	}
	if p.SP == nil || p.SP.SigningKeyThumbprint == "" {
		p.Creations = append(p.Creations, Creation{Type: "token-signing-certificate", Name: "CN=" + cfg.Hostname})
	}

	for _, name := range []string{cfg.AdminGroup, cfg.OperatorGroup} {
		g, err := c.lookupGroup(ctx, name, cfg)
		if err != nil {
			return nil, err
		}
		if g == nil {
			p.Creations = append(p.Creations, Creation{Type: "group", Name: name})
		} else {
			p.Groups[name] = g
		}
		p.Creations = append(p.Creations, Creation{Type: "app-role-assignment", Name: name})
	}
	return p, nil
}

func (c *Client) lookupApp(ctx context.Context, cfg Config) (*appRecord, error) {
	q := url.Values{
		"$filter": {"displayName eq " + odataQuote(AppDisplayName(cfg.Hostname))},
		"$select": {"id,appId,displayName,notes,tags,identifierUris,web,groupMembershipClaims,optionalClaims"},
	}
	out, err := c.call(ctx, http.MethodGet, "/applications?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Value []appRecord `json:"value"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("decode application list: %v", err)
	}
	switch len(list.Value) {
	case 0:
		return nil, nil
	case 1:
		return &list.Value[0], nil
	default:
		return nil, fmt.Errorf("%w: %d applications are named %q; a name match alone never establishes ownership", ErrRequiresReview, len(list.Value), AppDisplayName(cfg.Hostname))
	}
}

func (c *Client) lookupSP(ctx context.Context, appID string) (*FoundSP, error) {
	q := url.Values{
		"$filter": {"appId eq " + odataQuote(appID)},
		"$select": {"id,preferredSingleSignOnMode,appRoleAssignmentRequired,preferredTokenSigningKeyThumbprint,appRoles"},
	}
	out, err := c.call(ctx, http.MethodGet, "/servicePrincipals?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Value []struct {
			ID                                 string `json:"id"`
			PreferredSingleSignOnMode          string `json:"preferredSingleSignOnMode"`
			AppRoleAssignmentRequired          bool   `json:"appRoleAssignmentRequired"`
			PreferredTokenSigningKeyThumbprint string `json:"preferredTokenSigningKeyThumbprint"`
			AppRoles                           []struct {
				ID string `json:"id"`
			} `json:"appRoles"`
		} `json:"value"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("decode service principal list: %v", err)
	}
	if len(list.Value) == 0 {
		return nil, nil
	}
	v := list.Value[0]
	sp := &FoundSP{ObjectID: v.ID, SingleSignOnMode: v.PreferredSingleSignOnMode,
		AppRoleAssignmentRequired: v.AppRoleAssignmentRequired,
		SigningKeyThumbprint:      v.PreferredTokenSigningKeyThumbprint, AppRoleID: nilRoleID}
	if len(v.AppRoles) > 0 {
		sp.AppRoleID = v.AppRoles[0].ID
	}
	return sp, nil
}

func (c *Client) lookupGroup(ctx context.Context, name string, cfg Config) (*FoundGroup, error) {
	q := url.Values{
		"$filter": {"displayName eq " + odataQuote(name)},
		"$select": {"id,displayName,description"},
	}
	out, err := c.call(ctx, http.MethodGet, "/groups?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
		} `json:"value"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("decode group list: %v", err)
	}
	switch len(list.Value) {
	case 0:
		return nil, nil
	case 1:
		g := list.Value[0]
		ours := g.Description == Marker(cfg.DeploymentID)
		if cfg.AfterUncertainCreate && !ours {
			return nil, fmt.Errorf("%w: group %q exists but does not carry marker %s", ErrRequiresReview, name, Marker(cfg.DeploymentID))
		}
		return &FoundGroup{ObjectID: g.ID, Name: g.DisplayName, ProvenOurs: ours}, nil
	default:
		return nil, fmt.Errorf("%w: %d groups are named %q", ErrRequiresReview, len(list.Value), name)
	}
}

// desiredOptionalClaims makes the SAML token carry a groups claim with group
// display names (cloud_displayname), not object IDs: the local database
// authorises by the names seeded at schema time. The claim entry keeps no
// "source" field; with one, Entra discards the change without an error.
func desiredOptionalClaims() map[string]any {
	return map[string]any{"saml2Token": []map[string]any{{
		"name": "groups", "additionalProperties": []string{"cloud_displayname"},
	}}}
}

func appChanges(a *appRecord, cfg Config) []FieldChange {
	var ch []FieldChange
	if !slices.Equal(a.IdentifierUris, []string{EntityID(cfg.Hostname)}) {
		ch = append(ch, FieldChange{"application.identifierUris",
			mustJSON(a.IdentifierUris), mustJSON([]string{EntityID(cfg.Hostname)})})
	}
	if !slices.Equal(a.Web.RedirectUris, []string{ReplyURL(cfg.Hostname)}) {
		ch = append(ch, FieldChange{"application.web.redirectUris",
			mustJSON(a.Web.RedirectUris), mustJSON([]string{ReplyURL(cfg.Hostname)})})
	}
	// "ApplicationGroup" emits only groups assigned to the application, so
	// the claim stays small in a large tenant and never hits the SAML
	// groups-overage limit.
	if a.GroupMembershipClaims != "ApplicationGroup" {
		ch = append(ch, FieldChange{"application.groupMembershipClaims",
			mustJSON(a.GroupMembershipClaims), mustJSON("ApplicationGroup")})
	}
	if !a.hasGroupNameClaim() {
		ch = append(ch, FieldChange{"application.optionalClaims.saml2Token",
			mustJSON(a.OptionalClaims.Saml2Token), mustJSON(desiredOptionalClaims()["saml2Token"])})
	}
	return ch
}

func spChanges(sp *FoundSP) []FieldChange {
	var ch []FieldChange
	if sp.SingleSignOnMode != "saml" {
		ch = append(ch, FieldChange{"servicePrincipal.preferredSingleSignOnMode",
			mustJSON(sp.SingleSignOnMode), mustJSON("saml")})
	}
	if !sp.AppRoleAssignmentRequired {
		ch = append(ch, FieldChange{"servicePrincipal.appRoleAssignmentRequired",
			mustJSON(false), mustJSON(true)})
	}
	return ch
}

// Applied is the application and service principal after Apply, with
// ownership evidence for the resource journal.
type Applied struct {
	ObjectID    string
	AppID       string
	SPObjectID  string
	DisplayName string
	CreatedApp  bool
	CreatedSP   bool
	Evidence    string // for state.Resource.Ownership
}

// AppliedGroup is one group after Apply.
type AppliedGroup struct {
	Name     string
	ObjectID string
	Created  bool
	Evidence string
}

// Result is what Apply did, for the caller to record.
type Result struct {
	TenantID    string
	MetadataURL string // for the stack's SAML_IDP_METADATA_URL
	App         Applied
	Groups      []AppliedGroup
	// Changes echoes the pre-existing-resource changes Apply made (from the
	// approved plan), for SettingChange journal entries. Empty when the
	// application was created by, or already proven owned by, this
	// deployment.
	Changes []FieldChange
}

// Apply performs the plan: it creates what Plan found missing, converges the
// SAML configuration, and returns identifiers, ownership evidence, and the
// federation metadata URL. The caller must have journalled plan.Creations
// (with a correlation identifier) first, and obtained approval for
// plan.Changes on a pre-existing application. An ErrUncertain return means
// a creation request's response was lost: journal the action as uncertain
// and re-run Plan with AfterUncertainCreate on resume.
func (c *Client) Apply(ctx context.Context, plan *Plan) (*Result, error) {
	cfg := plan.Config
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	marker := Marker(cfg.DeploymentID)
	res := &Result{}

	// The tenant ID is in the token's own `tid` claim, so the ordinary
	// path needs no directory read at all. /organization is the fallback
	// for a token this tool cannot inspect, and it is the only reason
	// Organization.Read.All would ever be required.
	if tok, err := c.Token(ctx); err == nil {
		if tid, ok := tokenTenantID(tok); ok {
			res.TenantID = tid
		}
	}
	if res.TenantID == "" {
		out, err := c.call(ctx, http.MethodGet, "/organization?%24select=id", nil)
		if err != nil {
			return nil, fmt.Errorf("could not read the tenant ID: the token carries no tid claim and reading /organization failed (that fallback needs Organization.Read.All): %w", err)
		}
		var org struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
		}
		if json.Unmarshal(out, &org) != nil || len(org.Value) == 0 {
			return nil, fmt.Errorf("could not read the tenant ID from /organization")
		}
		res.TenantID = org.Value[0].ID
	}

	// Application. The marker travels in the creation body itself, so a
	// lost response still leaves a marked application to reconcile against.
	if plan.App == nil {
		body := map[string]any{
			"displayName":           AppDisplayName(cfg.Hostname),
			"notes":                 marker,
			"tags":                  []string{marker},
			"identifierUris":        []string{EntityID(cfg.Hostname)},
			"web":                   map[string]any{"redirectUris": []string{ReplyURL(cfg.Hostname)}},
			"groupMembershipClaims": "ApplicationGroup",
			"optionalClaims":        desiredOptionalClaims(),
		}
		out, err := c.call(ctx, http.MethodPost, "/applications", body)
		if err != nil {
			return nil, err
		}
		var created struct {
			ID    string `json:"id"`
			AppID string `json:"appId"`
		}
		if err := json.Unmarshal(out, &created); err != nil {
			return nil, fmt.Errorf("decode created application: %v", err)
		}
		res.App = Applied{ObjectID: created.ID, AppID: created.AppID,
			DisplayName: AppDisplayName(cfg.Hostname), CreatedApp: true,
			Evidence: "created by this deployment; marker " + marker + " in notes and tags from the creation request"}
	} else {
		res.App = Applied{ObjectID: plan.App.ObjectID, AppID: plan.App.AppID, DisplayName: plan.App.DisplayName}
		if plan.App.ProvenOurs {
			res.App.Evidence = "adopted with verified marker " + marker + " in notes/tags"
		} else {
			res.App.Evidence = "pre-existing application reused with approval; no ownership marker (never eligible for cleanup)"
			res.Changes = plan.Changes
		}
		if patch := appPatchBody(plan.Changes); len(patch) > 0 {
			// Never PATCH notes or tags here: a pre-existing application
			// must not be stamped with an ownership marker it did not earn.
			if _, err := c.call(ctx, http.MethodPatch, "/applications/"+res.App.ObjectID, patch); err != nil {
				return nil, err
			}
		}
	}

	// Service principal. Its appId links it to the marked application, so
	// it needs no marker of its own; query-first keeps re-runs from
	// creating a duplicate.
	var err error
	sp := plan.SP
	if sp == nil {
		sp, err = c.lookupSP(ctx, res.App.AppID)
		if err != nil {
			return nil, err
		}
	}
	if sp == nil {
		out, err := c.call(ctx, http.MethodPost, "/servicePrincipals", map[string]any{
			"appId": res.App.AppID,
			"tags":  []string{spTagSSO, marker},
		})
		if err != nil {
			return nil, err
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(out, &created); err != nil {
			return nil, fmt.Errorf("decode created service principal: %v", err)
		}
		sp = &FoundSP{ObjectID: created.ID, AppRoleID: nilRoleID}
		res.App.CreatedSP = true
		// Entra is eventually consistent: a service principal accepted by
		// the create call is not immediately addressable everywhere, and
		// the very next write returns Request_ResourceNotFound. Wait for
		// the directory to catch up rather than fail a deployment over a
		// delay the specification tells us to expect.
		if err := c.waitVisible(ctx, "/servicePrincipals/"+created.ID); err != nil {
			return nil, err
		}
	}
	res.App.SPObjectID = sp.ObjectID

	spPatch := map[string]any{}
	if sp.SingleSignOnMode != "saml" {
		spPatch["preferredSingleSignOnMode"] = "saml"
	}
	if !sp.AppRoleAssignmentRequired {
		// Only the assigned groups may sign in.
		spPatch["appRoleAssignmentRequired"] = true
	}
	if len(spPatch) > 0 {
		if _, err := c.call(ctx, http.MethodPatch, "/servicePrincipals/"+sp.ObjectID, spPatch); err != nil {
			return nil, err
		}
	}

	// Token signing certificate: Entra signs SAML responses with it, and
	// the federation metadata is not usable without one.
	if sp.SigningKeyThumbprint == "" {
		out, err := c.call(ctx, http.MethodPost, "/servicePrincipals/"+sp.ObjectID+"/addTokenSigningCertificate",
			map[string]any{"displayName": "CN=" + cfg.Hostname})
		if err != nil {
			return nil, err
		}
		var cert struct {
			Thumbprint string `json:"thumbprint"`
		}
		if err := json.Unmarshal(out, &cert); err != nil || cert.Thumbprint == "" {
			return nil, fmt.Errorf("token signing certificate was created but returned no thumbprint")
		}
		if _, err := c.call(ctx, http.MethodPatch, "/servicePrincipals/"+sp.ObjectID,
			map[string]any{"preferredTokenSigningKeyThumbprint": cert.Thumbprint}); err != nil {
			return nil, err
		}
	}

	// Groups, then their assignment to the application.
	assigned, err := c.assignedPrincipals(ctx, sp.ObjectID)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{cfg.AdminGroup, cfg.OperatorGroup} {
		g := plan.Groups[name]
		ag := AppliedGroup{Name: name}
		if g == nil {
			out, err := c.call(ctx, http.MethodPost, "/groups", map[string]any{
				"displayName":     name,
				"mailNickname":    mailNickname(name),
				"mailEnabled":     false,
				"securityEnabled": true,
				"description":     marker,
			})
			if err != nil {
				return nil, err
			}
			var created struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(out, &created); err != nil {
				return nil, fmt.Errorf("decode created group: %v", err)
			}
			ag.ObjectID, ag.Created = created.ID, true
			// The role assignment below references this group by ID, and
			// Entra rejects a reference to an object it has not yet
			// replicated ("Not a valid reference update"). Wait for it.
			if err := c.waitVisible(ctx, "/groups/"+created.ID); err != nil {
				return nil, err
			}
			ag.Evidence = "created empty by this deployment; marker " + marker + " in description; add members in Entra ID"
		} else {
			ag.ObjectID = g.ObjectID
			if g.ProvenOurs {
				ag.Evidence = "adopted with verified marker " + marker + " in description"
			} else {
				ag.Evidence = "pre-existing group reused unchanged (never eligible for cleanup)"
			}
		}
		if !assigned[ag.ObjectID] {
			if _, err := c.call(ctx, http.MethodPost, "/servicePrincipals/"+sp.ObjectID+"/appRoleAssignedTo",
				map[string]any{"principalId": ag.ObjectID, "resourceId": sp.ObjectID, "appRoleId": sp.AppRoleID}); err != nil {
				return nil, err
			}
		}
		res.Groups = append(res.Groups, ag)
	}

	res.MetadataURL = MetadataURL(res.TenantID, res.App.AppID)
	return res, nil
}

// appPatchBody turns approved application FieldChanges into one PATCH body.
func appPatchBody(changes []FieldChange) map[string]any {
	body := map[string]any{}
	for _, ch := range changes {
		switch ch.Field {
		case "application.identifierUris":
			body["identifierUris"] = json.RawMessage(ch.Applied)
		case "application.web.redirectUris":
			body["web"] = map[string]any{"redirectUris": json.RawMessage(ch.Applied)}
		case "application.groupMembershipClaims":
			body["groupMembershipClaims"] = json.RawMessage(ch.Applied)
		case "application.optionalClaims.saml2Token":
			// Graph PATCH merges nested complex types, so idToken and
			// accessToken claims on a pre-existing application survive.
			body["optionalClaims"] = map[string]any{"saml2Token": json.RawMessage(ch.Applied)}
		}
	}
	return body
}

// assignedPrincipals returns the principal IDs already assigned to the
// service principal.
// ponytail: reads one page (Graph default 100); paginate if a tenant ever
// assigns more than 100 principals to this application.
func (c *Client) assignedPrincipals(ctx context.Context, spID string) (map[string]bool, error) {
	out, err := c.call(ctx, http.MethodGet, "/servicePrincipals/"+spID+"/appRoleAssignedTo", nil)
	if err != nil {
		return nil, err
	}
	var list struct {
		Value []struct {
			PrincipalID string `json:"principalId"`
		} `json:"value"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("decode app role assignments: %v", err)
	}
	set := map[string]bool{}
	for _, v := range list.Value {
		set[v.PrincipalID] = true
	}
	return set, nil
}

func mailNickname(name string) string {
	nick := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		}
		return -1
	}, name)
	if nick == "" {
		nick = "guacdeploy"
	}
	return nick
}

// CleanupApp deletes the application only when the ownership marker is
// verified at deletion time; the service principal and its role assignments
// are removed with it. The deletion is Entra's standard soft delete (30-day
// deleted-items retention). A missing application is treated as already
// removed. Unmarked applications return ErrNotOwned.
func (c *Client) CleanupApp(ctx context.Context, cfg Config, appObjectID string) error {
	out, err := c.call(ctx, http.MethodGet, "/applications/"+appObjectID+"?%24select=id,displayName,notes,tags", nil)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var a appRecord
	if err := json.Unmarshal(out, &a); err != nil {
		return fmt.Errorf("decode application: %v", err)
	}
	if a.marker() != Marker(cfg.DeploymentID) {
		return fmt.Errorf("%w: application %q (marker %q)", ErrNotOwned, a.DisplayName, a.marker())
	}
	_, err = c.call(ctx, http.MethodDelete, "/applications/"+appObjectID, nil)
	return err
}

// CleanupGroup deletes a group only when its description carries this
// deployment's marker, verified at deletion time. Pre-existing (unmarked)
// groups return ErrNotOwned; a missing group is already removed.
func (c *Client) CleanupGroup(ctx context.Context, cfg Config, groupObjectID string) error {
	out, err := c.call(ctx, http.MethodGet, "/groups/"+groupObjectID+"?%24select=id,displayName,description", nil)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var g struct {
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(out, &g); err != nil {
		return fmt.Errorf("decode group: %v", err)
	}
	if g.Description != Marker(cfg.DeploymentID) {
		return fmt.Errorf("%w: group %q", ErrNotOwned, g.DisplayName)
	}
	_, err = c.call(ctx, http.MethodDelete, "/groups/"+groupObjectID, nil)
	return err
}
