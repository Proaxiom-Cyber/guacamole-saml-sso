# Proaxiom Cyber Cloudflare sign-in service

This Worker relays browser approval to a Guacamole installer over outbound HTTPS.
The installer can run on a server without a browser or an inbound port.

## Deployed resources

- Worker: `guacdeploy-cloudflare-auth`
- Hosting account: 8Bit Networks, Workers Free
- Service: `https://guacdeploy-cloudflare-auth.8bitnetworks.workers.dev`
- OAuth publisher: Proaxiom Cyber, in the Proaxiom Cloudflare account
- Verified publisher domain: `proaxiom.com`
- Public resource identifiers: [deployment.json](deployment.json)

Hosting and publisher accounts are separate because Proaxiom has Workers Paid.
Do not upgrade the hosting account or move this service to a paid account without
approval. The free plan rejects excess operations instead of billing overages.
The account's free allowance is shared with its other Workers.

## Protocol

The installer creates a random polling credential, PKCE verifier, and RSA private
key in memory. It sends the public key, verifier challenge, and polling credential
hash to `POST /sessions`. The service returns a public session link.

The browser opens `/start/{id}`. Cloudflare posts approval to `/callback` using
`form_post`, which keeps the authorization code out of the callback URL. The
Worker encrypts the code with AES-GCM and wraps the key with RSA-OAEP SHA-256.
Only that encrypted envelope enters Durable Object storage.

The installer calls `GET /poll/{id}` with its polling credential in a header.
It decrypts the result and exchanges the code directly with Cloudflare. Repeated
polls can retrieve the same encrypted envelope until the installer acknowledges
receipt with `DELETE /poll/{id}`. Deletion also cancels a pending session.

The service never receives the installer private key, PKCE verifier, or issued
access and refresh tokens. An expiry alarm deletes abandoned sessions after ten
minutes. No request logs, analytics scripts, or tail consumers are configured.
Cloudflare retains its own platform metadata under its service terms.

## Limits and failure behaviour

- Session creation: ten requests per minute per source IP and Cloudflare location.
- Payload size: 16 KiB, enforced while reading the body.
- Session lifetime: ten minutes.
- Installer polling: every five seconds; about 120 polls for a full timeout.
- Storage: SQLite-backed Durable Objects, supported on Workers Free.
- Lost poll response: the installer can retrieve the encrypted result again.
- Service unavailable: the installer offers manual return.

IP limits can affect administrators behind the same NAT. They reduce casual
abuse but do not guarantee availability under attack. Free-plan limits still
apply to rejected requests. This is not a paid service with an uptime guarantee.
No application timer or long-lived socket keeps a Durable Object active.

## Deployment and tests

Run `node --test services/cloudflare-auth/worker.test.mjs` from the repository.
Run `go test ./...` for the installer tests. The live OAuth test is opt-in and
requires administrator approval; normal tests make no live OAuth requests.

Run `python3 services/cloudflare-auth/deploy.py` on the administrator's Mac.
The script reads the existing Keychain credential into memory, checks the account
subscription, and uploads the Worker. It refuses a Workers paid subscription.
The script writes no secret to disk, shell arguments, or the environment.

The deployment manifest contains public identifiers only. The OAuth client has
no client secret. Both hosted and localhost redirect URIs belong to that client.
Changing the OAuth registration requires the Proaxiom account credential, while
Worker updates use the 8Bit account credential.
