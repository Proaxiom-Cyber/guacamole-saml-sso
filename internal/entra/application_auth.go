package entra

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
)

// ApplicationOptions authenticates the manually registered installer identity,
// not the SAML application this tool provisions. Secrets and token caches remain
// in memory. A certificate signer can keep its private key inside a TPM.
type ApplicationOptions struct {
	TenantID, ClientID string
	Secret             string
	Certificate        *x509.Certificate
	Signer             crypto.Signer
	Transport          policy.Transporter
}

func ApplicationTokenSource(o ApplicationOptions) (TokenSource, error) {
	tenant, err := uuid.Parse(o.TenantID)
	if err != nil {
		return nil, errors.New("enter the Directory (tenant) ID from the installer app's Overview page")
	}
	client, err := uuid.Parse(o.ClientID)
	if err != nil {
		return nil, errors.New("enter the Application (client) ID from the installer app's Overview page")
	}
	o.TenantID, o.ClientID = tenant.String(), client.String()
	var credential azcore.TokenCredential
	if o.Certificate != nil && o.Signer != nil && o.Secret == "" {
		if _, ok := o.Signer.Public().(*rsa.PublicKey); !ok {
			return nil, errors.New("the installer certificate needs an RSA signing key")
		}
		a, _ := x509.MarshalPKIXPublicKey(o.Signer.Public())
		b, _ := x509.MarshalPKIXPublicKey(o.Certificate.PublicKey)
		if string(a) != string(b) {
			return nil, errors.New("the installer certificate does not match its signing key")
		}
		credential, err = azidentity.NewClientAssertionCredential(o.TenantID, o.ClientID, func(ctx context.Context) (string, error) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return applicationAssertion(o, time.Now())
		}, &azidentity.ClientAssertionCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: o.Transport}})
	} else if o.Secret != "" && o.Certificate == nil && o.Signer == nil {
		credential, err = azidentity.NewClientSecretCredential(o.TenantID, o.ClientID, o.Secret,
			&azidentity.ClientSecretCredentialOptions{ClientOptions: azcore.ClientOptions{Transport: o.Transport}})
	} else {
		return nil, errors.New("supply either an installer certificate or a client secret")
	}
	if err != nil {
		return nil, errors.New("cannot configure installer app authentication; check the tenant ID and client ID")
	}
	return func(ctx context.Context) (string, error) {
		token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://graph.microsoft.com/.default"}})
		if err != nil {
			return "", safeApplicationError(err)
		}
		return token.Token, nil
	}, nil
}

// Follow Microsoft's certificate-credentials format. The assertion is short
// lived and signed with PS256. Its signature does not expose the private key.
func applicationAssertion(o ApplicationOptions, now time.Time) (string, error) {
	if now.Before(o.Certificate.NotBefore) || !now.Add(time.Minute).Before(o.Certificate.NotAfter) {
		return "", errors.New("the installer certificate is outside its validity period")
	}
	thumbprint := sha256.Sum256(o.Certificate.Raw)
	header, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": base64.RawURLEncoding.EncodeToString(thumbprint[:])})
	claims, _ := json.Marshal(map[string]any{
		"aud": "https://login.microsoftonline.com/" + o.TenantID + "/oauth2/v2.0/token",
		"iss": o.ClientID, "sub": o.ClientID, "jti": uuid.NewString(),
		"nbf": now.Add(-30 * time.Second).Unix(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := o.Signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return "", errors.New("the TPM could not sign the installer authentication request")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func safeApplicationError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("installer app authentication timed out; check network access and retry")
	}
	code := aadErrorCode.FindString(err.Error())
	if code != "" {
		code = " (" + code + ")"
	}
	return fmt.Errorf("installer app authentication failed%s; check the tenant ID, client ID, certificate or secret, expiry, admin consent and workload identity policy", code)
}

// CheckApplicationAccess validates application roles and binds the app to the
// live selected tenant before any mutation. No provider error body is printed.
func (c *Client) CheckApplicationAccess(ctx context.Context, expectedTenant string) error {
	_, _, err := c.checkTokenAccess(ctx, expectedTenant, "in the installer app's API permissions, grant admin consent, then retry")
	return err
}
