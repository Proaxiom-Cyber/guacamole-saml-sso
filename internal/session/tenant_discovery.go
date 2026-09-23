package session

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Tenant discovery is public metadata, not authentication. Sign-in still verifies
// the selected tenant and permissions before any Microsoft resource is created.
func discoverTenantID(ctx context.Context, domain string) (string, error) {
	if !validEntraTenant(domain) {
		return "", fmt.Errorf("enter a verified Microsoft domain")
	}
	if id, err := uuid.Parse(domain); err == nil {
		return id.String(), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://login.microsoftonline.com/"+url.PathEscape(domain)+"/v2.0/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Microsoft tenant discovery could not connect: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("Microsoft did not recognise %s as a tenant domain (HTTP %d). Use a verified Entra domain; it may differ from the website domain", domain, res.StatusCode)
	}
	var metadata struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&metadata); err != nil {
		return "", err
	}
	return tenantIDFromIssuer(metadata.Issuer)
}
func tenantIDFromIssuer(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host != "login.microsoftonline.com" {
		return "", fmt.Errorf("Microsoft returned an unexpected tenant issuer")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[1] != "v2.0" {
		return "", fmt.Errorf("Microsoft returned an unexpected tenant issuer")
	}
	id, err := uuid.Parse(parts[0])
	if err != nil {
		return "", fmt.Errorf("Microsoft did not return a specific tenant ID")
	}
	return id.String(), nil
}
