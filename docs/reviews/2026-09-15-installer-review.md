# Installer review — 15 September 2026

The installer now has a Proaxiom terminal interface, clearer task guidance, and
independent Cloudflare and Entra domain selection. Live testing also found and fixed
several cloud propagation failures.

The signed review build is [v0.1.8-rc.4](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/tag/v0.1.8-rc.4).
The published launcher verified and installed it on Rocky. Main and the stable
release remain unchanged.

To install this review version on the test VM:

```sh
curl -fsSLO https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/get-guacdeploy.sh
sh get-guacdeploy.sh --install-only v0.1.8-rc.4
guacdeploy preview
```

The preview changes no deployment resources. Run `sudo guacdeploy` when you want
to use the setup wizard. Keep the version argument: the default downloads stable.

## Start with the visuals

- [Watch the 13-second walkthrough](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/installer-walkthrough.mp4).
- [Microsoft connection screen](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/installer-connect.png).
- [Logo activity and measured task progress](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/installer-progress.png).
- [Compact terminal](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/installer-compact.png).
- [Light terminal](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/installer-light.png).
- [Manual Entra registration guidance](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/releases/download/v0.1.8-rc.4/installer-manual-entra.png).

These captures show the actual `guacdeploy preview` process with labelled example
data. They do not show a customer deployment or a completed browser sign-in.

The five-bar logo indicates activity. The current action uses the Proaxiom navy
colour. Task bars count completed checks or steps; they do not estimate time.
Animation stops while the user answers a question. Small terminals use a compact
header. Plain text, ASCII, and reduced-motion options remain available.

Each task explains its purpose. The current question and controls stay visible.
Tab opens details and timestamped history. Setup writes a private, redacted session
log and prints its path when it exits.

## What the live tests proved

The tests used the authorized Rocky Linux 10.2 test VM on PVE01. SELinux stayed
enforcing. The VM had Docker and the Compose plugin from the earlier installation.
These were fresh deployments, not installations on a newly built operating system.

| Test | Result |
| --- | --- |
| Independent domains | Entra `demotestcustomer.onmicrosoft.com` and Cloudflare `demo-customer.com.au` completed setup together. Customer SLQ resources were not accessed. |
| Invalid Cloudflare token | Setup stopped at credential validation. Supplying a valid token on resume continued the deployment. |
| Resume | The initial resume retained the same 30 resource IDs. A later failed Access check resumed and published the deployment. |
| Complete teardown | Owned cloud and host resources were removed. Data and recordings were preserved. |
| Interrupted Entra setup | Teardown found marked app resources that had not reached the saved resource list and removed them. |
| TPM installer identity | A new key was generated in the VM TPM. App registration, permissions, repeated registration, authentication, and verified cleanup passed. |
| Encrypted backup | Hidden passphrase entry, encrypted export, key verification, and database backup passed. |
| Wrong passphrase | Restore failed and left the database unchanged. |
| Valid restore | Restore recovered the original test row. Disposable test keys, backups, and rows were removed afterwards. |
| Final clean deployment | All setup phases completed in one run after the propagation fixes. |

The final clean deployment ID is `2d17a2ea7ff1e48278bfb00cf6dded7a`.
The test endpoint is `https://guac.demo-customer.com.au/`.

## Fixes from the tests

- Entra tenant selection no longer defaults to the Cloudflare zone. Resume permits
  correction of an unverified selection and preserves the verified tenant binding.
- The installer reads recorded Entra object IDs directly when directory searches
  have not caught up. It does not infer that a missing search result permits a
  replacement object.
- New service-principal reads and writes tolerate explicit replication refusals.
  A conflicting permission grant must be read back as the exact intended grant.
- Cloudflare Access checks wait for temporary edge errors. They still reject an
  unprotected response or a login for another application. The connector stays
  stopped until protection is verified.
- Resume guidance now describes the files being refreshed. It no longer tells the
  user to tear down a deployment while continuing that deployment.

## Automated coverage and limits

Go tests and vet pass. Race checks pass for the changed UI, Cloudflare, Entra, and
session packages. Linux terminal tests cover cancellation, resize, paste, keyboard
input, and terminal restoration. The release pipeline passed, including database recovery and fresh-stack container
integration tests. The published binary passed the Rocky terminal checks: cancellation, signals,
resize, pasted input, plain output, and terminal restoration. All six preview
interaction tests also passed. The launcher reported `Verified OK`; the installed
binary matched the published SHA-256 digest.

Provider-response tests cover lost mutation responses, permission denials,
replication delays, tenant mismatch, and blocked device-code authorization. The
live certificate test used the approved test installer identity to authorize app
creation. It did not complete the human device-code browser flow. No allowed or
denied user SAML sign-in is claimed.

## HA research

Read the [HA report](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/blob/codex/entra-browser-signin/docs/research/2026-09-14-guacamole-ha.md)
for the proposed topology, primary sources, and test evidence.
Two Guacamole instances can use a shared database, but their authentication tokens
remain local to each process. Losing an instance requires a new sign-in and remote
connection. A shared database does not preserve an active remote session.

The initial isolated tests demonstrated streaming replication, potential data loss
with asynchronous failover, and blocked writes without the required synchronous
standby. Automatic failover needs independent arbitration and verified fencing.
A second isolated experiment used two PostgreSQL nodes with Patroni and three
etcd voters. It observed automatic promotion after 25.19 seconds. Losing two voters
made both databases read-only and prevented another promotion. This test killed
containers; it did not prove fencing of a frozen or isolated host. HA remains
outside supported V1. All experimental containers and networks were removed.

## Lab state

The earlier deployments' data and encrypted recovery files remain in root-only
archive directories on the test VM. The current deployment has no production
backup recovery key: the backup test used and removed disposable material. A user
must generate a new recovery key before relying on scheduled backups.

The installed review binary is `v0.1.8-rc.4`. The lab containers restarted after
reboot with SELinux enforcing. The original VM boot configuration has been restored;
the temporary test ISO is detached. The earlier encrypted data archives remain.
