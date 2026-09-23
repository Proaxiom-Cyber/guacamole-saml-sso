# Shared Cloudflare sign-in service test

Test date: 15 September 2026.

## Result

The shared service passed a live sign-in test using the app's Go OAuth code in a
Linux container. The administrator approved the public Proaxiom Cyber OAuth app
for 8Bit Networks. No address was copied back into the installer.

The test completed in 135.86 seconds, including the administrator's approval.
All seven API reads passed: account selection, zone, DNS, Tunnel, Access
applications, Access identity providers, and Access organization. Refresh passed.
Revocation of both access tokens and both refresh tokens returned HTTP 200.

The container had a read-only filesystem, no published ports, no container log
storage, and equal memory and memory-swap limits. Socket inspection showed an
outbound HTTPS connection and no listening socket. This was a local Linux
container, not a remote host deployment.

## Hosting and registration

The user required Workers Free with enforced usage limits. Proaxiom already had
Workers Paid, so the service runs in the connected 8Bit Networks account.
Cloudflare explicitly identified that account as Free during deployment. We did
not add or upgrade a paid subscription.

- Service: `https://guacdeploy-cloudflare-auth.8bitnetworks.workers.dev`
- OAuth client: Proaxiom Cyber — Guacamole Deployer
- OAuth account: Proaxiom
- Visibility: public
- Publisher domain: `proaxiom.com`, verified through a new TXT record
- Resource identifiers: [deployment.json](../../services/cloudflare-auth/deployment.json)

The registration accepts the shared HTTPS callback and the localhost redirect
used by manual return. The app includes both public configuration values. A
customer does not need a callback hostname or its own OAuth registration.

These are retained service resources. The live test tokens were revoked; the
shared OAuth client, Worker, and publisher verification record remain in place.

## Checks

| Check | Result |
|---|---|
| Worker health and logo endpoints | HTTP 200 |
| Live encrypted delivery using synthetic data | Passed |
| Wrong polling credential | Rejected |
| Repeat delivery after a lost response | Same encrypted envelope |
| Delete acknowledgement | Session removed; subsequent poll HTTP 410 |
| Public app approval from another account | Passed |
| Actual app code: hosted exchange, reads, refresh | Passed on Linux |
| Original and refreshed credentials revoked | Four HTTP 200 responses |
| Complete Go suite | Passed |
| Worker tests | Passed |

Worker tests also cover cancellation before approval, expiry, invalid state,
payload limits, and rate limits. Go tests cover PKCE binding, service response
validation, polling retries, cleanup, and existing manual-return authentication.

## Free-tier scope and remaining limits

Workers Free allows 100,000 daily Worker requests. SQLite-backed Durable Objects
also have free compute and storage limits. A full ten-minute sign-in timeout uses
about 120 polls at the configured five-second interval, plus setup and cleanup.
The free allowance belongs to the account and is shared with its other Workers.

Sources: [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
and [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/).

The live tests ran within enforced Free-plan limits without resource-limit errors.
We did not measure CPU percentiles, run a load test, or demonstrate availability
under attack. Anonymous creation is limited per IP and Cloudflare location, but
rejected traffic still counts toward platform limits. If the service reaches a
free limit or becomes unavailable, setup offers manual return.

We did not create customer DNS records, tunnels, or Access applications with the
OAuth grant. Those deployment writes still need a separate live deployment test.
The local app changes are tested but have not been published as a release.
