package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SettingAccessor reads and writes the individual fields that Apply changed
// on a pre-existing application or service principal, so a restore can
// compare the live value with the recorded one and, after approval, put the
// original back. It satisfies the settings package's Reader and Writer.
//
// A target is the string journalled in state.SettingChange.Target:
// "<kind>/<objectID>/<field>", where kind is "application" or
// "servicePrincipal" and field is one of the FieldChange names. The field
// name, not the kind, decides which Graph resource is touched. A
// servicePrincipal field recorded against an application object ID (the
// shape the session writes today) resolves through the application's appId,
// which is the only link between an application and its service principal.
//
// The bearer token never leaves Client.call, so it cannot reach a target, a
// value, or an error from here.
type SettingAccessor struct{ Client *Client }

// graphField maps a recorded field name to the Graph property to $select and
// the path to the value inside the response. A field absent from this map is
// one this tool cannot read back or write, and is reported as such instead
// of being guessed at.
var graphField = map[string][]string{
	"application.identifierUris":                 {"identifierUris"},
	"application.web.redirectUris":               {"web", "redirectUris"},
	"application.groupMembershipClaims":          {"groupMembershipClaims"},
	"application.optionalClaims.saml2Token":      {"optionalClaims", "saml2Token"},
	"servicePrincipal.preferredSingleSignOnMode": {"preferredSingleSignOnMode"},
	"servicePrincipal.appRoleAssignmentRequired": {"appRoleAssignmentRequired"},
}

// Get reads the live value of one recorded target.
func (a SettingAccessor) Get(ctx context.Context, target string) (json.RawMessage, error) {
	kind, id, field, err := parseSettingTarget(target)
	if err != nil {
		return nil, err
	}
	path, ok := graphField[field]
	if !ok {
		return nil, fmt.Errorf("setting %q is not one this tool reads from Graph", field)
	}
	res, err := a.resourcePath(ctx, kind, id, field)
	if err != nil {
		return nil, err
	}
	out, err := a.Client.call(ctx, http.MethodGet, res+"?%24select="+path[0], nil)
	if err != nil {
		return nil, err
	}
	return dig(out, path)
}

// Set writes one value back to a recorded target. The value comes from the
// journal, so it is sent as recorded except where Graph will not accept that
// spelling on a write; see restoreValue.
func (a SettingAccessor) Set(ctx context.Context, target string, value json.RawMessage) error {
	kind, id, field, err := parseSettingTarget(target)
	if err != nil {
		return err
	}
	prop, ok := graphField[field]
	if !ok {
		return fmt.Errorf("setting %q cannot be written back: this tool has no Graph mapping for it", field)
	}
	res, err := a.resourcePath(ctx, kind, id, field)
	if err != nil {
		return err
	}
	value = restoreValue(field, value)

	var body map[string]any
	if strings.HasPrefix(field, "application.") {
		// Reuse the exact body shape Apply sends, so a restore writes the
		// same nesting that the change was made with.
		body = appPatchBody([]FieldChange{{Field: field, Applied: value}})
	} else {
		body = map[string]any{prop[0]: value}
	}
	if len(body) == 0 {
		return fmt.Errorf("setting %q produced an empty Graph patch; refusing to send it", field)
	}
	_, err = a.Client.call(ctx, http.MethodPatch, res, body)
	return err
}

func parseSettingTarget(target string) (kind, objectID, field string, err error) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("setting target %q is not <kind>/<objectID>/<field>", target)
	}
	return parts[0], parts[1], parts[2], nil
}

// resourcePath returns the Graph path of the resource that owns field.
func (a SettingAccessor) resourcePath(ctx context.Context, kind, id, field string) (string, error) {
	switch {
	case strings.HasPrefix(field, "application."):
		if kind != "application" {
			return "", fmt.Errorf("setting target names a %s object but %q is an application field", kind, field)
		}
		return "/applications/" + id, nil
	case strings.HasPrefix(field, "servicePrincipal."):
		switch kind {
		case "servicePrincipal":
			return "/servicePrincipals/" + id, nil
		case "application":
			spID, err := a.spForApp(ctx, id)
			if err != nil {
				return "", err
			}
			return "/servicePrincipals/" + spID, nil
		}
		return "", fmt.Errorf("setting target names a %s object but %q is a service principal field", kind, field)
	}
	return "", fmt.Errorf("setting %q belongs to no Graph resource this tool manages", field)
}

// spForApp finds the service principal of an application by its appId.
func (a SettingAccessor) spForApp(ctx context.Context, appObjectID string) (string, error) {
	out, err := a.Client.call(ctx, http.MethodGet, "/applications/"+appObjectID+"?%24select=appId", nil)
	if err != nil {
		return "", err
	}
	var app struct {
		AppID string `json:"appId"`
	}
	if err := json.Unmarshal(out, &app); err != nil || app.AppID == "" {
		return "", fmt.Errorf("application %s returned no appId, so its service principal cannot be located", appObjectID)
	}
	sp, err := a.Client.lookupSP(ctx, app.AppID)
	if err != nil {
		return "", err
	}
	if sp == nil {
		return "", fmt.Errorf("no service principal exists for application %s", appObjectID)
	}
	return sp.ObjectID, nil
}

// dig walks a JSON object along path. A missing or null step is the JSON
// null value, which is what Graph means by "this property is not set".
func dig(doc json.RawMessage, path []string) (json.RawMessage, error) {
	null := json.RawMessage("null")
	cur := doc
	for _, key := range path {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(cur, &m); err != nil {
			return nil, fmt.Errorf("graph response is not an object at %q: %v", key, err)
		}
		v, ok := m[key]
		if !ok {
			return null, nil
		}
		cur = v
	}
	return cur, nil
}

// restoreValue spells a recorded value the way Graph accepts it on a write.
// Graph reports an unset collection as JSON null but rejects null for a
// collection property; the empty collection is how a collection is cleared.
// The two nullable strings take null, never the empty string.
func restoreValue(field string, v json.RawMessage) json.RawMessage {
	switch strings.TrimSpace(string(v)) {
	case "null", "":
		switch field {
		case "application.identifierUris", "application.web.redirectUris",
			"application.optionalClaims.saml2Token":
			return json.RawMessage("[]")
		}
	case `""`:
		switch field {
		case "application.groupMembershipClaims", "servicePrincipal.preferredSingleSignOnMode":
			return json.RawMessage("null")
		}
	}
	return v
}
