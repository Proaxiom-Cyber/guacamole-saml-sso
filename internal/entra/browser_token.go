package entra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// CheckBrowserToken checks a pasted token through read-only Graph requests.
// The selected tenant is checked against live organization data, including
// verified domains. Neither transport errors nor Graph response bodies reach
// the prompt: either can contain a malformed credential supplied by the user.
func (c *Client) CheckBrowserToken(ctx context.Context, expectedTenant string) (tenant string, expires time.Time, err error) {
	token, err := c.Token(ctx)
	if err != nil {
		return "", time.Time{}, errors.New("could not read the pasted access token")
	}
	if token == "" || len(token) > 128*1024 || strings.ContainsFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", time.Time{}, errors.New("paste only the access token from Graph Explorer's Access token tab")
	}
	expires = accessTokenExpiry(token)
	if !expires.IsZero() && !expires.After(time.Now().Add(time.Minute)) {
		return "", time.Time{}, errors.New("this access token has expired or will expire shortly; sign in again and copy a fresh token")
	}
	pf, err := c.CheckPermissions(ctx)
	if ctx.Err() != nil {
		return "", time.Time{}, ctx.Err()
	}
	if err != nil || !pf.ReadOK {
		return "", time.Time{}, errors.New("Microsoft Graph did not accept the token for application reads; check sign-in, Application.ReadWrite.All consent, network access and tenant policy")
	}
	if pf.ClaimsChecked && !pf.MutationOK {
		return "", time.Time{}, fmt.Errorf("the token is missing permissions: %s; grant consent in Graph Explorer and copy a fresh token", pf.MutationDetail)
	}
	out, err := c.call(ctx, http.MethodGet, "/organization?%24select=id,verifiedDomains", nil)
	if ctx.Err() != nil {
		return "", time.Time{}, ctx.Err()
	}
	if err != nil {
		return "", time.Time{}, errors.New("Microsoft Graph could not verify the tenant; grant Organization.Read.All in Graph Explorer and check network access and tenant policy")
	}
	var org struct {
		Value []struct {
			ID              string `json:"id"`
			VerifiedDomains []struct {
				Name string `json:"name"`
			} `json:"verifiedDomains"`
		} `json:"value"`
	}
	if json.Unmarshal(out, &org) != nil || len(org.Value) != 1 || org.Value[0].ID == "" {
		return "", time.Time{}, errors.New("Microsoft Graph did not return a unique tenant; check the directory selected in Graph Explorer")
	}
	tenant = org.Value[0].ID
	match := expectedTenant == "" || strings.EqualFold(expectedTenant, tenant)
	for _, domain := range org.Value[0].VerifiedDomains {
		match = match || strings.EqualFold(expectedTenant, domain.Name)
	}
	if !match {
		return "", time.Time{}, errors.New("this token belongs to a different tenant; switch to the selected directory in Graph Explorer and copy a new token")
	}
	return tenant, expires, nil
}

// Expiry is only a hint for asking for a fresh token before the next request.
// Live Graph requests, not decoded claims, establish whether it is accepted.
func accessTokenExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}
