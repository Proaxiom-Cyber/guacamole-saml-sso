# Cloudflare OAuth tests

Test date: 14 September 2026. These tests follow the
[documentation research](2026-09-14-cloudflare-token-onboarding.md).

Follow-up: the [hosted callback test](2026-09-14-cloudflare-hosted-callback-test.md)
passed with a browser-free Linux client and outbound HTTPS only.

The later [manual-return test](2026-09-15-cloudflare-manual-return-test.md) also
passed and removes the hosted callback service requirement.

## Current result

Our own OAuth client is the best fit among the options tested for interactive
setup. Browser consent, PKCE token exchange, all required read endpoints,
refresh, and revocation passed. Cloudflare issued a one-hour access token.

The current `/user/tokens/verify` preflight failed for the OAuth token while the
resource API calls passed. The installer must validate OAuth through an
appropriate resource request instead of treating it as a user API token.

The published `cf` release does not provide the device-login and keychain
features found in the repository's main branch. Do not choose that route from
source inspection alone.

## Tests completed

| Test | Observed result |
|---|---|
| Authenticated `GET /oauth/scopes` | HTTP 200, success, 385 scopes |
| Match deployment permissions | All five exact scopes present |
| Inspect token-management scopes | No user or account API-token management scope present; only Access service-token scopes |
| List OAuth clients in Proaxiom | HTTP 200; no clients before the test |
| Create temporary private PKCE client | HTTP 200, success |
| Register `http://127.0.0.1:18976/callback` | Accepted |
| Register token authentication method `none` | Accepted; no client secret required |
| Register authorization-code and refresh grants | Accepted; Cloudflare added `offline_access` |
| Open authorization request | Cloudflare redirected the browser to its sign-in page |
| Authorize Proaxiom private client from 8Bit user | Rejected: only members of the developer account can authorize a private client |
| Repeat registration in 8Bit Networks | HTTP 200; browser reached consent with 8Bit Networks selected |
| Request device authorization for this client | HTTP 403, no device code; response did not provide a parsed OAuth error |
| Inspect published `cf@0.10.0` | Its authentication bundle has no device-login or keyring options |
| Run `cf@0.10.0 auth login --help` | Lists force, browser, and scopes options; no device or keyring option |
| Run `cf@0.10.0 auth --help` | No token-export command |
| Consent for the private 8Bit client | Passed after the user approved it |
| PKCE code exchange through Python urllib | HTTP 403; no token issued |
| PKCE code exchange through Node.js fetch | HTTP 200; access and refresh tokens issued; `expires_in=3600` |
| Refresh through Node.js fetch | HTTP 200; access and refresh tokens returned |
| Revoke refresh and access tokens | Both endpoints returned HTTP 200 |
| Delete both temporary clients | HTTP 200; replacement client lookup returned HTTP 404 |
| Go standard HTTP client with an invalid test client | HTTP 401 with JSON `invalid_client`; the request reached OAuth processing |

The device endpoint's HTTP 403 does not identify the rejection layer. Treat the
documented third-party device-grant exclusion as the supported product contract.

## Exact deployment scopes

The live catalog returned these names and IDs:

| Permission | OAuth scope |
|---|---|
| Cloudflare Tunnel Write | `argotunnel.write` |
| Access: Apps and Policies Write | `access.write` |
| Access: Organizations, Identity Providers, and Groups Write | `access-acct.write` |
| DNS Write | `dns.write` |
| Zone Read | `zone.read` |

Cloudflare accepted these IDs in the client registration. This proves that the
client can request them. It does not yet prove access through a user grant.

The catalog also contains zone-level Access scopes. The test uses account-level
`access.write`, matching the deployment's account-level Access endpoints.

## Published CLI versus source

The npm registry resolved `cf` to version `0.10.0`. Its package requires Node.js
22 or later. We installed that exact release into a temporary directory with
installation scripts disabled, then ran its help commands.

The earlier research found device login in Cloudflare's main-branch authentication
source. The published package lacks that interface. A main-branch feature is not
a usable released dependency until the package provides it.

Sources: [official CLI announcement](https://blog.cloudflare.com/cf-cli-local-explorer/),
[published package metadata](https://registry.npmjs.org/cf/0.10.0),
[main-branch authentication source](https://github.com/cloudflare/workers-sdk/blob/main/packages/workers-auth/src/cf/index.ts).

## Completed browser test

A local test process held the PKCE verifier and state in memory. It listened only
on `127.0.0.1`, suppressed HTTP request logs, and redirected the callback to a
clean completion page. It did not print authorization codes or tokens.

The following requests used the issued OAuth access token, not the administrative
API token used to register the client:

| Request | HTTP status | Result |
|---|---|---|
| `/user/tokens/verify` | 401 | Error code 1000 |
| List accounts | 200 | Success |
| Find the 8Bit zone by name | 200 | Success |
| Read the zone | 200 | Success |
| List DNS records | 200 | Success |
| List tunnels | 200 | Success |
| List Access applications | 200 | Success |
| List Access identity providers | 200 | Success |
| Read the Access organization | 200 | Success |

Responses stayed in memory. Output contained status, success flags, error codes,
and the token lifetime. The process requested token revocation before exit.

Temporary client: `guacdeploy OAuth probe 2026-09-14`.
Initial Proaxiom client ID: `cde91f99a340405f8633cdc0112180d0`.
Cloudflare confirmed deletion of that client with HTTP 200.

Replacement client ID: `05af34def1d9b9c8bb1b2878be264a73`.
Account: 8Bit Networks. Visibility: private. Callback port: 18977.
Cloudflare confirmed deletion with HTTP 200. A subsequent lookup returned HTTP
404. Both local callback processes stopped. No token or verifier remains in a
test file.

The first attempt exposed a real onboarding constraint: private applications
require membership in the developer account. A client for customers must use
public visibility and complete publisher domain verification.

No deployment resources, DNS records, tunnels, or Access configuration changed.
The temporary OAuth registrations were the only Cloudflare resources created.

## HTTP transport finding

The initial Python token exchange received a non-JSON HTTP 403. A comparison
using an invalid non-secret code reproduced that result through Python urllib.
Node.js fetch received the expected JSON `invalid_grant` error instead.

The next real code exchange used Node.js fetch and succeeded. Cloudflare's own
authentication source uses Node.js fetch through Undici. The precise cause of
the Python rejection remains undiagnosed; it is not evidence of scope rejection.

A Go standard-library request also reached OAuth processing and returned JSON
`invalid_client` for a deliberately invalid client. This supports a native Go
implementation, but does not replace an end-to-end Go PKCE test.

Source: [Cloudflare token exchange implementation](https://github.com/cloudflare/workers-sdk/blob/main/packages/workers-auth/src/token-exchange.ts).

## Decision boundary

Choose a native PKCE flow for the next implementation test. It can request the
five exact scopes without a shared client secret or a Node.js runtime dependency.
Register a public client with a verified publisher domain for customer use.

Before release, test isolated resource creation and cleanup with the OAuth token.
These tests verified reads under write scopes, not write operations. Also test
remote callback delivery, resource restrictions, and expiry handling in Go.

Keep certificate renewal separate: the catalog provides no documented route to
mint an account-owned API token through OAuth. Refresh success proves the
mechanism, not a durable credential lifecycle independent of the user.

References: [OAuth client registration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/),
[OAuth scope API](https://developers.cloudflare.com/api/resources/iam/),
[OAuth endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/).
