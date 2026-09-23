# Cloudflare sign-in

The installer normally uses Proaxiom Cyber's shared callback service. You approve
access on your computer or phone, then setup continues automatically. The server
needs outbound HTTPS only; it needs no browser or listening port.

## Administrator steps

1. Start setup with sealed credentials: `--credentials tpm` or `--credentials host`.
2. Choose **Sign in with Cloudflare**.
3. Open the displayed link on your computer or phone.
4. Sign in, select the Cloudflare account, and approve access.
5. Return to the installer. Setup continues without a pasted address.

For manual return, choose **Sign in with manual return** or pass
`--cloudflare-auth manual`. This also works when the shared service is unavailable.
After approval, the browser shows an expected localhost connection error. Copy
its full address and paste it into the installer's hidden prompt.
Do not paste that returned address into chat, a ticket, or a shell command.

The installer checks the address and state before exchanging the code. It checks
Zone Read access before saving the credentials. Cloudflare sign-in credentials
use the selected systemd-creds encryption method. They do not enter deployment
state or plaintext credential files.

Setup, certificate renewal, and teardown accept the stored OAuth credential.
They refresh access when needed and save the rotated credential before use.
These operations hold the deployment lock. Encrypted credential replacement uses
an atomic rename. If refresh fails, reconnect through setup:

```sh
guacdeploy setup --cloudflare-auth browser
```

A revoked grant or a lost rotated credential requires another approval. The
application reports the failure instead of falling back to another credential.
Existing API-token deployments retain their current credential path. Recovery
on a replacement host still asks for an API token before setup.

## Release configuration

The app includes the public Proaxiom Cyber OAuth client ID and callback service
address. Publisher verification is complete. The callback Worker runs in 8Bit's
Workers Free account; the OAuth registration belongs to Proaxiom.
See the [service configuration](../services/cloudflare-auth/README.md).

Configure `GUACDEPLOY_CLOUDFLARE_OAUTH_CLIENT_ID` with the public client identifier,
or embed the identifier in the release with the Go linker variable
`github.com/Proaxiom-Cyber/guacamole-saml-sso/internal/cloudflare.OAuthClientID`.
The identifier is not a secret. Do not configure a client secret.
Override the service origin with `GUACDEPLOY_CLOUDFLARE_OAUTH_RELAY` when using
another registered service. The service and client identifiers must match.

Register these client properties:

| Property | Value |
|---|---|
| Redirect URIs | Shared service origin plus `/callback`; `http://localhost:18977/callback` |
| Grant types | `authorization_code`, `refresh_token` |
| Response type | `code` |
| Token endpoint authentication | `none` |
| Scopes | `argotunnel.write access.write access-acct.write dns.write zone.read offline_access` |

A private client works only for members of its developer account. For customer
accounts, the publisher must register a public client and verify the publisher
domain. No callback service needs to run at that domain.

When no client ID is configured, setup retains API-token entry. Explicit
`--cloudflare-auth browser` reports the missing registration. Browser approval
requires interactive setup, even though the browser runs on another device.

## Validation

The live manual-return and shared-service tests passed code exchange, seven API read checks, refresh,
and revocation. Automated tests cover PKCE binding, wrong and duplicate state,
incorrect redirect addresses, duplicate codes, cancellation, encrypted refresh,
and existing API tokens. Deployment writes with OAuth remain to be tested.

See the [shared-service test report](research/2026-09-15-cloudflare-shared-service-test.md)
for the Linux test, free hosting checks, and retained resources.
