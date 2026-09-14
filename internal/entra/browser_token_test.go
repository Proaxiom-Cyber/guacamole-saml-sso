package entra

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestBrowserTokenValidation(t *testing.T) {
	for _, name := range []string{"domain", "tenant-id", "opaque", "wrong-tenant", "missing-permissions", "expired", "malformed", "rejected", "network", "organization-denied"} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{"scp": strings.Join(RequiredPermissions, " "), "exp": time.Now().Add(time.Hour).Unix()}
			if name == "missing-permissions" {
				claims["scp"] = "Application.ReadWrite.All"
			}
			if name == "expired" {
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			}
			token := jwt(t, claims)
			if name == "opaque" {
				token = "opaque-fixture"
			}
			if name == "malformed" {
				token = "fixture\r\ninvalid-header"
			}
			expected := "CUSTOMER.EXAMPLE"
			if name == "tenant-id" {
				expected = "tenant-fixture"
			}
			if name == "wrong-tenant" {
				expected = "another.example"
			}
			calls := 0
			c := &Client{Token: func(context.Context) (string, error) { return token, nil }, Do: func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" {
					t.Fatal("validation made a mutation")
				}
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Fatal("wrong token sent")
				}
				if name == "network" {
					return nil, errors.New("fixture transport reflected " + token)
				}
				if name == "rejected" {
					return graphErr(401, "InvalidAuthenticationToken", "fixture response reflected "+token), nil
				}
				if r.URL.Path == "/v1.0/organization" {
					if name == "organization-denied" {
						return graphErr(403, "Denied", token), nil
					}
					return rawResp(200, `{"value":[{"id":"tenant-fixture","verifiedDomains":[{"name":"customer.example"}]}]}`), nil
				}
				return rawResp(200, `{"value":[]}`), nil
			}}
			tenant, expiry, err := c.CheckBrowserToken(context.Background(), expected)
			ok := name == "domain" || name == "tenant-id" || name == "opaque"
			if ok {
				if err != nil || tenant != "tenant-fixture" || calls != 2 {
					t.Fatalf("valid token refused: %v", err)
				}
				if name != "opaque" && expiry.IsZero() {
					t.Fatal("expiry not retained")
				}
			} else if err == nil {
				t.Fatal("invalid token accepted")
			}
			if err != nil && strings.Contains(err.Error(), token) {
				t.Fatal("token leaked through validation error")
			}
			if (name == "malformed" || name == "expired") && calls != 0 {
				t.Fatal("invalid input sent to Graph")
			}
		})
	}
}

func TestBrowserTokenCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{Token: func(context.Context) (string, error) { return "opaque-fixture", nil }, Do: func(r *http.Request) (*http.Response, error) {
		cancel()
		return nil, ctx.Err()
	}}
	_, _, err := c.CheckBrowserToken(ctx, "customer.example")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
