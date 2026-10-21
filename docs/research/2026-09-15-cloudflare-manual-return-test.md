# Cloudflare manual-return test

Test date: 15 September 2026.

## Result

The test passed with no callback service and no listening port. The administrator
approved access in a separate browser. After the localhost connection error, they
copied the complete returned address into a hidden terminal prompt.

The Go client validated the redirect address and state, then exchanged the code
with PKCE. The verifier, authorization code, and issued tokens stayed in memory.
The test wrote only its public authorization link and non-secret results to disk.

| Check | Result |
|---|---|
| Authorization-code exchange | HTTP 200 |
| Account selection | HTTP 200, success |
| Zone read | HTTP 200, success |
| DNS read | HTTP 200, success |
| Tunnel read | HTTP 200, success |
| Access applications read | HTTP 200, success |
| Access identity providers read | HTTP 200, success |
| Access organization read | HTTP 200, success |
| Token refresh | HTTP 200 |
| Both access tokens and both refresh tokens revoked | Four HTTP 200 responses |
| Temporary OAuth client deleted | HTTP 200; subsequent lookup HTTP 404 |

This test ran the native Go client on macOS. The earlier hosted-callback test
verified native Go exchange and refresh inside Linux. We did not run the
manual-return interaction on a remote Linux host or create deployment resources.

## Integration decision

Use a registered localhost redirect URI and hidden manual return. The installer
requires neither a browser nor a public callback service. The administrator's
computer or phone supplies the browser. A connection error after approval is
expected because no callback listener runs.

The current redirect URI is `http://localhost:18977/callback`. It belongs to the
OAuth client registration, not to the customer's Guacamole hostname.

Cloudflare still requires a registered OAuth client. A private client serves
members of its developer account. A public client serves other accounts and
requires publisher-domain verification. That publisher URL is not a callback
service or a customer deployment address.

Sources:

- [Third-party client registration](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)
- [Documented remote-login return procedure](https://developers.cloudflare.com/workers/wrangler/commands/general/#use-wrangler-login-on-a-remote-machine)

The hidden-paste probe is [client.go](probes/manual-oauth/client.go).
