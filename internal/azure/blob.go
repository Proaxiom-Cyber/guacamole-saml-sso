package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MaxSingleUpload is the largest blob this package will write.
//
// ponytail: one Put Blob per file, capped at 256 MiB. Put Blob accepts more
// in current service versions, but a single request has to be retried whole,
// and a Guacamole database export is a few megabytes. A recording larger than
// this fails with a message naming the ceiling rather than being silently
// truncated or half-uploaded. Upgrade path when recordings get big: Put Block
// plus Put Block List, whose uncommitted blocks are invisible until the block
// list is committed, which keeps the same completeness guarantee.
const MaxSingleUpload = 256 << 20

// ownerMetadata is the blob metadata key carrying the deployment that wrote
// the blob. Storage metadata names must be valid C# identifiers, so this is
// underscored rather than hyphenated. It is the ownership marker: nothing is
// deleted here without reading it back first.
const ownerMetadata = "guacdeploy_deployment"

// ErrNotOwned means a blob does not carry this deployment's ownership marker,
// so it is not eligible for deletion. The same name as internal/entra and
// internal/cloudflare use, for the same reason.
var ErrNotOwned = errors.New("blob does not carry this deployment's ownership marker")

// blobURL builds the data-plane URL for one blob, escaping each path segment
// but keeping the "/" separators that make the prefix a folder in the portal.
func (d Destination) blobURL(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return d.BlobEndpoint + "/" + url.PathEscape(d.Container) + "/" + strings.Join(parts, "/")
}

// blobRequest builds an authorized data-plane request with the headers every
// Blob REST call needs.
func (c *Client) blobRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	tok, err := c.Token(ctx, ScopeStorage)
	if err != nil {
		return nil, fmt.Errorf("acquire an Azure storage token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("x-ms-version", BlobAPIVersion)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	return req, nil
}

// blobError decodes a Blob REST failure. The service reports the machine-
// readable code in the x-ms-error-code header and repeats it in an XML body.
func blobError(method, rawURL string, resp *http.Response, body []byte) *Error {
	e := &Error{Status: resp.StatusCode, Method: method, Path: pathOf(rawURL), Code: resp.Header.Get("x-ms-error-code")}
	var doc struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(body, &doc) == nil {
		if e.Code == "" {
			e.Code = doc.Code
		}
		e.Message = firstLine(doc.Message)
	}
	if e.Message == "" {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return e
}

// pathOf keeps the host and path of a URL for error messages and drops any
// query. No URL here carries a credential (there are no shared-access
// signatures in this package), but a query adds noise to an operator message.
func pathOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host + u.Path
	}
	return rawURL
}

// blobDo sends one data-plane request and returns the body of a 2xx reply.
func (c *Client) blobDo(req *http.Request) ([]byte, http.Header, error) {
	resp, err := c.send(req)
	if err != nil {
		return nil, nil, fmt.Errorf("azure %s %s: %v", req.Method, pathOf(req.URL.String()), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("azure %s %s: %v", req.Method, pathOf(req.URL.String()), err)
	}
	if resp.StatusCode >= 400 {
		return nil, resp.Header, blobError(req.Method, req.URL.String(), resp, body)
	}
	return body, resp.Header, nil
}

// BlobProperties is what Get Blob Properties tells us about a blob: enough to
// prove an upload arrived whole.
type BlobProperties struct {
	Name          string
	Bytes         int64
	ContentMD5    string // base64, as the service returns it
	Owner         string // the deployment that wrote it, from blob metadata
	LastModified  string
	ContentSHA256 string // the local manifest's SHA-256, carried as metadata
}

// PutBlob writes one blob whole, with the service checking the body against
// contentMD5 as it arrives.
//
// Content-MD5 is not decoration. Put Blob compares the hash it computes
// against this header and fails the request with 400 when they differ
// (documented under Put Blob), so a body corrupted or truncated in transit
// never becomes a blob at all. MD5 is used because it is the integrity
// mechanism the Blob service implements; the authoritative content hash stays
// SHA-256, carried in the completion manifest and in blob metadata.
func (c *Client) PutBlob(ctx context.Context, d Destination, name string, content []byte, contentMD5 string, meta map[string]string) error {
	if int64(len(content)) > MaxSingleUpload {
		return fmt.Errorf("%s is %d bytes, above the %d-byte single-request upload limit this tool supports; it was not uploaded",
			name, len(content), int64(MaxSingleUpload))
	}
	req, err := c.blobRequest(ctx, http.MethodPut, d.blobURL(name), bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(content))
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-MD5", contentMD5)
	for k, v := range meta {
		req.Header.Set("x-ms-meta-"+k, v)
	}
	_, _, err = c.blobDo(req)
	return err
}

// HeadBlob reads one blob's properties and metadata. A missing blob returns
// an error for which NotFound reports true.
func (c *Client) HeadBlob(ctx context.Context, d Destination, name string) (BlobProperties, error) {
	req, err := c.blobRequest(ctx, http.MethodHead, d.blobURL(name), nil)
	if err != nil {
		return BlobProperties{}, err
	}
	resp, err := c.send(req)
	if err != nil {
		return BlobProperties{}, fmt.Errorf("azure HEAD %s: %v", pathOf(req.URL.String()), err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10)) // a HEAD reply has no body; drain anything a proxy adds
	if resp.StatusCode >= 400 {
		return BlobProperties{}, blobError(http.MethodHead, req.URL.String(), resp, nil)
	}
	p := BlobProperties{
		Name:          name,
		ContentMD5:    resp.Header.Get("Content-MD5"),
		Owner:         resp.Header.Get("x-ms-meta-" + ownerMetadata),
		LastModified:  resp.Header.Get("Last-Modified"),
		ContentSHA256: resp.Header.Get("x-ms-meta-" + sha256Metadata),
	}
	// Content-Length is the blob's length on a HEAD reply. net/http parses it
	// into ContentLength, but a fake or a proxy may only set the header.
	p.Bytes = resp.ContentLength
	if p.Bytes <= 0 {
		if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
			p.Bytes = n
		}
	}
	return p, nil
}

// GetBlob reads one blob whole. It is used for completion manifests, which
// are small; it is not a restore path.
func (c *Client) GetBlob(ctx context.Context, d Destination, name string) ([]byte, error) {
	req, err := c.blobRequest(ctx, http.MethodGet, d.blobURL(name), nil)
	if err != nil {
		return nil, err
	}
	body, _, err := c.blobDo(req)
	return body, err
}

// ListBlobs returns the names of this deployment's blobs under prefix,
// newest-first ordering being irrelevant here because callers match by name.
// It lists at most max entries and does not follow continuation markers: the
// callers are a permission check and a "what is already there" lookup, and
// neither needs the whole container.
//
// ponytail: no pagination. Add marker following when remote retention (issue
// #20) needs to walk every recording.
func (c *Client) ListBlobs(ctx context.Context, d Destination, prefix string, max int) ([]BlobProperties, error) {
	q := url.Values{
		"restype":    {"container"},
		"comp":       {"list"},
		"prefix":     {prefix},
		"maxresults": {strconv.Itoa(max)},
	}
	rawURL := d.BlobEndpoint + "/" + url.PathEscape(d.Container) + "?" + q.Encode()
	req, err := c.blobRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	body, _, err := c.blobDo(req)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Blobs struct {
			Blob []struct {
				Name       string `xml:"Name"`
				Properties struct {
					ContentLength int64  `xml:"Content-Length"`
					ContentMD5    string `xml:"Content-MD5"`
					LastModified  string `xml:"Last-Modified"`
				} `xml:"Properties"`
			} `xml:"Blob"`
		} `xml:"Blobs"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the blob listing is not readable XML: %w", err)
	}
	out := make([]BlobProperties, 0, len(doc.Blobs.Blob))
	for _, b := range doc.Blobs.Blob {
		out = append(out, BlobProperties{
			Name: b.Name, Bytes: b.Properties.ContentLength,
			ContentMD5: b.Properties.ContentMD5, LastModified: b.Properties.LastModified,
		})
	}
	return out, nil
}

// deleteBlob removes one blob, and only after reading its ownership marker
// back from the service.
//
// This is the only function in this package that issues a DELETE, and it
// deletes a blob and nothing else. There is deliberately no container or
// storage-account deletion anywhere here: "Preserve remote backups and their
// supporting storage resources during ordinary teardown" (specification), and
// a container this tool did not create is not this tool's to remove.
// TestNoContainerOrAccountDeletionPath fails if a second DELETE ever appears.
//
// The marker check is what scopes deletion to this deployment. A blob whose
// metadata names another deployment, or carries no marker at all, returns
// ErrNotOwned and is left alone — the same rule the local retention in
// internal/schedule applies to a shared directory.
func (c *Client) deleteBlob(ctx context.Context, d Destination, name, deploymentID string) error {
	if deploymentID == "" {
		return fmt.Errorf("deleting a blob needs the deployment ID to prove the blob is this deployment's own")
	}
	props, err := c.HeadBlob(ctx, d, name)
	if err != nil {
		return err
	}
	if props.Owner != deploymentID {
		return fmt.Errorf("%w: %s is marked %q, not %q; it was left in place", ErrNotOwned, name, props.Owner, deploymentID)
	}
	req, err := c.blobRequest(ctx, http.MethodDelete, d.blobURL(name), nil)
	if err != nil {
		return err
	}
	_, _, err = c.blobDo(req)
	return err
}

// DeleteOwnedBlob removes one blob belonging to this deployment, refusing
// anything that does not carry this deployment's marker. Remote retention by
// age is a separate slice (issue #20); this exists so the permission probe can
// clean up after itself, and so that slice has a safe primitive to build on.
func (c *Client) DeleteOwnedBlob(ctx context.Context, d Destination, name, deploymentID string) error {
	if !strings.HasPrefix(name, d.Prefix(deploymentID)) {
		return fmt.Errorf("%w: %s is outside this deployment's prefix %s; it was left in place",
			ErrNotOwned, name, d.Prefix(deploymentID))
	}
	return c.deleteBlob(ctx, d, name, deploymentID)
}

// readManifestBlob fetches and decodes a completion manifest blob.
func (c *Client) readManifestBlob(ctx context.Context, d Destination, name string, into any) error {
	body, err := c.GetBlob(ctx, d, name)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s is not a readable completion manifest: %w", name, err)
	}
	return nil
}
