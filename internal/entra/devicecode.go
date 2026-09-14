package entra

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// GraphCLIClientID is the public Microsoft Graph Command Line Tools client
// used by the original installer. A tenant can supply its own public client.
const GraphCLIClientID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

type DeviceCodeOptions struct {
	TenantID  string
	ClientID  string
	Prompt    func(context.Context, string, string) error // verification URL and user code only
	Transport policy.Transporter                          // test seam; nil uses Microsoft's HTTPS endpoints
}

// DeviceCodeTokenSource uses Microsoft's SDK for polling, cancellation,
// in-memory caching and refresh. No persistent cache or SDK logger is installed.
func DeviceCodeTokenSource(o DeviceCodeOptions) (TokenSource, error) {
	if o.ClientID == "" {
		o.ClientID = GraphCLIClientID
	}
	if o.Prompt == nil {
		return nil, errors.New("Microsoft sign-in requires an interactive prompt")
	}
	credential, err := azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
		ClientOptions: azcore.ClientOptions{Transport: o.Transport},
		TenantID:      o.TenantID, ClientID: o.ClientID,
		UserPrompt: func(ctx context.Context, m azidentity.DeviceCodeMessage) error {
			return o.Prompt(ctx, m.VerificationURL, m.UserCode)
		},
	})
	if err != nil {
		return nil, errors.New("cannot start Microsoft sign-in; check the tenant ID and public client ID")
	}
	scopes := make([]string, 0, len(RequiredPermissions)+1)
	for _, permission := range RequiredPermissions {
		scopes = append(scopes, "https://graph.microsoft.com/"+permission)
	}
	// Graph access tokens can be opaque. Organization Read is needed for
	// the live tenant lookup when no readable tid claim is available.
	scopes = append(scopes, "https://graph.microsoft.com/Organization.Read.All")
	return func(ctx context.Context) (string, error) {
		token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
		if err != nil {
			return "", safeSignInError(err)
		}
		return token.Token, nil
	}, nil
}

var aadErrorCode = regexp.MustCompile(`AADSTS[0-9]+`)

// SDK errors can include full HTTP responses. Only a Microsoft error code
// reaches the transcript; tokens and protocol device codes never do.
func safeSignInError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("Microsoft sign-in timed out. Retry to get a new sign-in code")
	}
	code := aadErrorCode.FindString(err.Error())
	if code != "" {
		return fmt.Errorf("Microsoft sign-in failed (%s). Check the browser result, administrator consent and tenant sign-in policy", code)
	}
	return errors.New("Microsoft sign-in did not complete. Check the browser result and network connection, then retry for a new code")
}
