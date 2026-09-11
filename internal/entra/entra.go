// Package entra provisions Microsoft Entra ID sign-in for one Guacamole
// deployment through Microsoft Graph.
//
// Intent before creation: Plan reports what Apply would create or change.
// The caller persists that intent with a correlation identifier, then calls
// Apply, which performs the work and returns created identifiers plus
// ownership evidence.
//
// Ownership marker: an application created by this package carries
// "guacdeploy:<deployment-id>" in both its `notes` field (human-visible in
// the portal) and its `tags` list, written in the creation request body
// itself. So an application whose creation response was lost still carries
// the marker, and reconciliation can prove ownership. A created group
// carries the same marker in its `description` field, because groups have
// no notes or tags. A matching display name alone never establishes
// ownership. The service principal needs no marker of its own: its appId
// links it uniquely to the marked application.
//
// Group claim choice: the SAML groups claim emits group display names, not
// object IDs, because the local database authorises by the display names
// seeded at schema time. See desiredOptionalClaims.
package entra

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const graphBase = "https://graph.microsoft.com/v1.0"

// DefaultTokenEnv is the environment variable StaticTokenFromEnv reads for
// unattended and test runs.
const DefaultTokenEnv = "GUACDEPLOY_GRAPH_TOKEN"

// TokenSource supplies a Microsoft Graph bearer token for one call. The
// parent wires a device-code or environment-based source; this package
// never stores, logs, or embeds the value in errors or evidence.
type TokenSource func(ctx context.Context) (string, error)

// StaticTokenFromEnv returns a TokenSource that reads the named environment
// variable on each call, for unattended and test use.
func StaticTokenFromEnv(envVar string) TokenSource {
	return func(context.Context) (string, error) {
		v := strings.TrimSpace(os.Getenv(envVar))
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty: supply a Microsoft Graph access token", envVar)
		}
		return v, nil
	}
}

// Client is a minimal Microsoft Graph client.
type Client struct {
	Token TokenSource
	// Do sends one HTTP request. nil means http.DefaultClient.Do. Tests
	// replace it to fake every Graph and metadata call.
	Do func(*http.Request) (*http.Response, error)
}

func (c *Client) send(req *http.Request) (*http.Response, error) {
	if c.Do != nil {
		return c.Do(req)
	}
	return http.DefaultClient.Do(req)
}

// ErrUncertain means a mutating request was sent but no usable response came
// back: the work may or may not have happened. Callers journal the action as
// uncertain and reconcile on the next run with Plan and
// Config.AfterUncertainCreate, which queries by the ownership marker before
// any retry of creation.
var ErrUncertain = errors.New("request sent but the response was lost")

// ErrRequiresReview means the tenant holds a resource that matches by name
// but is not proven ours (or the match is not unique). The tool must neither
// adopt it nor create a duplicate; a person has to review the tenant.
var ErrRequiresReview = errors.New("requires review")

// ErrNotOwned means a cleanup target does not carry this deployment's
// ownership marker, so it is not eligible for deletion.
var ErrNotOwned = errors.New("resource does not carry this deployment's ownership marker")

// GraphError is a non-2xx Graph response. It never contains the token.
type GraphError struct {
	Status  int
	Code    string
	Message string
	Method  string
	Path    string
}

func (e *GraphError) Error() string {
	if e.Code == "" && e.Message == "" {
		return fmt.Sprintf("graph %s %s returned status %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("graph %s %s failed: %s (%s)", e.Method, e.Path, e.Message, e.Code)
}

// call performs one Graph request. path starts with "/" and may carry an
// encoded query. Transport failures and 5xx responses on mutating methods
// wrap ErrUncertain, because the request may have been applied. Errors never
// contain the bearer token: only method, path, status, and the Graph error
// body appear.
func (c *Client) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	tok, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire Graph token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, graphBase+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	mutating := method != http.MethodGet
	resp, err := c.send(req)
	if err != nil {
		// Transport errors name the URL, never the headers, so the token
		// cannot pass through them.
		if mutating {
			return nil, fmt.Errorf("%w: graph %s %s: %v", ErrUncertain, method, path, err)
		}
		return nil, fmt.Errorf("graph %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		if mutating {
			return nil, fmt.Errorf("%w: graph %s %s: %v", ErrUncertain, method, path, err)
		}
		return nil, fmt.Errorf("graph %s %s: %v", method, path, err)
	}
	if resp.StatusCode >= 400 {
		ge := &GraphError{Status: resp.StatusCode, Method: method, Path: path}
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(out, &e) == nil {
			ge.Code, ge.Message = e.Error.Code, e.Error.Message
		}
		if resp.StatusCode >= 500 && mutating {
			return nil, fmt.Errorf("%w: %v", ErrUncertain, ge)
		}
		return nil, ge
	}
	return out, nil
}

// isNotFound reports whether err is a Graph 404.
func isNotFound(err error) bool {
	var ge *GraphError
	return errors.As(err, &ge) && ge.Status == http.StatusNotFound
}

// Derived names. The entity ID has no trailing slash (Entra rejects one,
// IdentifierUrisEndsWithSlash); the reply URL has one. They differ on purpose.
func EntityID(hostname string) string { return "https://" + hostname + "/guacamole" }
func ReplyURL(hostname string) string { return EntityID(hostname) + "/" }
func AppDisplayName(hostname string) string {
	return "Guacamole (" + hostname + ")"
}

// Marker is the ownership marker value for one deployment.
func Marker(deploymentID string) string { return "guacdeploy:" + deploymentID }

// MetadataURL is the federation metadata URL for the stack's
// SAML_IDP_METADATA_URL.
func MetadataURL(tenantID, appID string) string {
	return "https://login.microsoftonline.com/" + tenantID +
		"/federationmetadata/2007-06/federationmetadata.xml?appid=" + appID
}

// RequiredPermissions are the Graph permissions Apply needs, delegated
// (`scp`) or application (`roles`).
var RequiredPermissions = []string{
	"Application.ReadWrite.All",       // create and configure the application and service principal
	"Group.ReadWrite.All",             // create the administrator and operator groups
	"AppRoleAssignment.ReadWrite.All", // assign the groups to the application
}

// Preflight is the result of CheckPermissions. Read and mutation checks are
// separate: the read check is live evidence, the mutation check is advisory.
type Preflight struct {
	ReadOK     bool
	ReadDetail string
	// ClaimsChecked is false when the token is not an inspectable JWT
	// (an opaque token): the mutation check is then skipped, not guessed.
	ClaimsChecked  bool
	MutationOK     bool
	MutationDetail string
}

// CheckPermissions checks what the token can actually do, before anything
// is created.
//
// Read: a live GET /applications?$top=1 proves the token can read
// applications right now.
//
// Mutation: Graph offers no dry run for creation, so the only pre-creation
// evidence is the token's own claims. The payload is decoded without
// signature verification (the token is used, not trusted as identity) and
// each RequiredPermissions entry is looked for in `scp` and `roles`. This
// proves consent was granted but cannot prove Conditional Access policy,
// directory-role limits, or revocation since issue: the first real mutation
// remains the proof, which is why Apply journals intent first and
// reconciles lost responses.
func (c *Client) CheckPermissions(ctx context.Context) (Preflight, error) {
	var p Preflight
	if _, err := c.call(ctx, http.MethodGet, "/applications?%24select=id&%24top=1", nil); err != nil {
		p.ReadDetail = err.Error()
	} else {
		p.ReadOK = true
		p.ReadDetail = "GET /applications succeeded: the token can read applications"
	}

	tok, err := c.Token(ctx)
	if err != nil {
		return p, fmt.Errorf("acquire Graph token: %w", err)
	}
	granted, ok := tokenPermissions(tok)
	if !ok {
		p.MutationDetail = "token is not an inspectable JWT; mutation permissions cannot be checked before the first create"
		return p, nil
	}
	p.ClaimsChecked = true
	var missing []string
	for _, want := range RequiredPermissions {
		if !granted[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		p.MutationDetail = "token claims lack: " + strings.Join(missing, ", ")
		return p, nil
	}
	p.MutationOK = true
	p.MutationDetail = "token claims grant " + strings.Join(RequiredPermissions, ", ") +
		" (advisory: claims cannot prove Conditional Access or directory-role limits)"
	return p, nil
}

// tokenTenantID returns the `tid` claim: the tenant the token was issued
// for. Reading it here means the tool does not need Organization.Read.All
// merely to learn its own tenant, which is a permission an operator would
// otherwise have to grant for nothing. Only the tenant ID, a non-secret
// identifier, leaves this function.
func tokenTenantID(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", false
	}
	var claims struct {
		TID string `json:"tid"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.TID == "" {
		return "", false
	}
	return claims.TID, true
}

// tokenPermissions decodes the JWT payload and returns the union of `scp`
// scopes and `roles`. Only permission names leave this function; the token
// itself never enters any returned value.
func tokenPermissions(tok string) (map[string]bool, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	var claims struct {
		Scp   string   `json:"scp"`
		Roles []string `json:"roles"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil, false
	}
	set := map[string]bool{}
	for _, s := range strings.Fields(claims.Scp) {
		set[s] = true
	}
	for _, r := range claims.Roles {
		set[r] = true
	}
	return set, true
}

const samlMetadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"

// VerifyMetadata fetches the federation metadata URL and checks that it
// parses as SAML metadata: an EntityDescriptor in the SAML metadata
// namespace with a non-empty entityID. It returns that entityID (the
// identity provider's, of the form https://sts.windows.net/<tenant>/) as
// verification evidence. The document is public; no Authorization header is
// sent.
func (c *Client) VerifyMetadata(ctx context.Context, metadataURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.send(req)
	if err != nil {
		return "", fmt.Errorf("fetch federation metadata: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", fmt.Errorf("read federation metadata: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("federation metadata fetch returned status %d", resp.StatusCode)
	}
	var md struct {
		XMLName  xml.Name
		EntityID string `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal(body, &md); err != nil {
		return "", fmt.Errorf("federation metadata is not XML: %v", err)
	}
	if md.XMLName.Space != samlMetadataNS || md.XMLName.Local != "EntityDescriptor" {
		return "", fmt.Errorf("federation metadata is not a SAML EntityDescriptor (got %s %s)", md.XMLName.Space, md.XMLName.Local)
	}
	if md.EntityID == "" {
		return "", errors.New("federation metadata has no entityID")
	}
	return md.EntityID, nil
}

// DefaultReplicationWait bounds how long the tool waits for a freshly
// created directory object to become addressable.
const DefaultReplicationWait = 90 * time.Second

// ReplicationWait is the bound used by waitVisible; a variable so tests do
// not sleep.
var ReplicationWait = DefaultReplicationWait

// replicationPoll is how long to wait between attempts while the directory
// catches up. A variable for the same reason.
var replicationPoll = 2 * time.Second

// waitVisible polls a freshly created object until Graph can read it.
//
// Entra is eventually consistent. A create call returns an object ID, and a
// write against that ID moments later can still fail with
// Request_ResourceNotFound because the directory has not replicated. That
// is a delay, not an error, so the tool waits for it instead of failing a
// deployment; if it never appears, the error says so plainly.
func (c *Client) waitVisible(ctx context.Context, path string) error {
	deadline := time.Now().Add(ReplicationWait)
	var last error
	for {
		if _, err := c.call(ctx, http.MethodGet, path, nil); err == nil {
			return nil
		} else {
			last = err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%s was created but did not become readable within %s, so the directory has not replicated it: %w",
				path, ReplicationWait, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(replicationPoll):
		}
	}
}
