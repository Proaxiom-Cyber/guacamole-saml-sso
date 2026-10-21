# Cloudflare hosted callback test

Test date: 14 September 2026. Follow-up to the
[OAuth tests](2026-09-14-cloudflare-oauth-tests.md).

## Result

The hosted callback test passed. A Go client in a Linux container completed
Cloudflare OAuth with outbound HTTPS only. The user approved access in the
in-app browser on the Mac. The Linux client had no browser or listening port.

This supports an installer flow that displays a link for use on another device.
The user signs in and approves the requested permissions. The installer then
continues without requiring the user to create or copy an API token.

## Flow tested

1. The installer creates a PKCE verifier, polling credential, and RSA key in memory.
2. It sends the challenge, polling credential hash, and public key to the relay.
3. The user opens the session link and approves Cloudflare access.
4. Cloudflare posts the authorization code to the hosted callback.
5. The relay encrypts the code for the installer and stores the encrypted result.
6. The installer polls over HTTPS and decrypts the result in memory.
7. It exchanges the code with Cloudflare, tests API access, and refreshes the token.
8. It revokes the original and refreshed access and refresh tokens.

The relay does not receive the PKCE verifier, private key, or issued OAuth tokens.
It handles the authorization code in memory before encryption. Sessions expire
after ten minutes. Polling requires a separate credential. Successful delivery
deletes the stored session. This is a custom relay around authorization-code
OAuth, not Cloudflare's device authorization grant.

## Observed results

| Check | Result |
|---|---|
| Wrong polling credential | Rejected with HTTP 403 |
| Pending session | HTTP 202 |
| Invalid callback state, synthetic test | HTTP 400 |
| Duplicate callback, synthetic test | HTTP 409 |
| Encrypted delivery and decryption | Passed on macOS and Linux |
| Poll after successful delivery | HTTP 410 |
| Native Go authorization-code exchange | HTTP 200 |
| Access token lifetime | 3,599 seconds; refresh token present |
| Account selection API | HTTP 200, success |
| Zone API | HTTP 200, success |
| DNS API | HTTP 200, success |
| Tunnel API | HTTP 200, success |
| Access applications API | HTTP 200, success |
| Access identity providers API | HTTP 200, success |
| Access organization API | HTTP 200, success |
| Token refresh | HTTP 200 |
| Revoke both refresh and both access tokens | Four HTTP 200 responses |
| Linux process exit | Successful |

The Linux container had a read-only filesystem, no published ports, no container
logging, and equal memory and memory-swap limits. Socket inspection showed an
outbound HTTPS connection and no listening sockets. This was a local Linux
container, not a deployment to a remote server.

## Limits and production work

The test used a private OAuth client in 8Bit Networks. A login outside that
developer account failed. Customer onboarding needs a public OAuth client and
the associated domain verification. We did not test public client registration.

The five deployment scopes plus refresh access worked for resource reads.
We did not create DNS records, tunnels, or Access resources with the OAuth token.
The actual installer still needs OAuth support and a resource-based preflight;
the earlier OAuth test failed the existing user-token verification endpoint.

Production also needs relay abuse controls, failure recovery, and a reliable
session delivery protocol. The prototype deletes the envelope when it serves
the successful poll; a lost response can require the user to start again.
The relay and its callback domain become maintained service dependencies.

This test does not solve unattended credential retention or prove that OAuth
can mint an account-owned API token. Tokens remained in memory during the test.
The project must resolve that separate requirement before production use.

## Cleanup and artifacts

All four token revocation requests returned HTTP 200. We deleted the temporary
OAuth client and Worker; subsequent lookups returned HTTP 404. A deletion
migration removed the temporary Durable Object namespace. The namespace list
contained no remaining namespace for the test Worker.

The test changed no deployment DNS, Tunnel, or Access configuration. Source
remains in [worker.mjs](probes/hosted-oauth/worker.mjs) and
[client.go](probes/hosted-oauth/client.go). These are experimental probes, not
installer integration. The old authorization links no longer work.

## Documentation

- [Create an OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)
- [Integrate with Cloudflare OAuth](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/)
- [Worker upload metadata](https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/)
- [Worker API and namespace deletion migrations](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/)
