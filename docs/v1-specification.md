# Guacamole deployment tool: V1 specification

Status: V1 product decisions approved by Cameron, 11 September 2026.

This specification translates the agreed [scope](v1-scope-and-backlog.md) into
behaviour and acceptance criteria. It does not authorise deployment or cloud changes.
The target is readiness next week, subject to the release checks below.

## Outcome

An IT administrator runs one download command on a new server and completes a
guided Guacamole deployment. The administrator needs no repository checkout, Go
installation, or source-code edits. The same tool supports resume, teardown,
backup, and restore.

V1 supports Rocky Linux 10 on Intel and AMD 64-bit VMs, with one deployment per host.
Guacamole, Entra sign-in, and Cloudflare access form the supported integration set.
Deployments can serve temporary projects or ongoing operations.

## Architecture boundaries

The download launcher selects and verifies a released Go binary before execution.
The Go application owns the wizard, non-interactive commands, workflow, and local
state. Separate modules own host preparation, identity, networking, certificates,
credential access, and database operations.

Integration modules expose checks, actions, and cleanup through the common workflow.
They do not implement independent prompt or state systems. V1 does not need a plugin
framework. The existing container deployment is the starting architecture.

Installed backup and renewal routines operate without the provisioning binary.
The tool records those routines and schedules as created resources.

## Installation flow

1. Check platform, privileges, connectivity, account permissions, and existing state.
2. Offer fresh setup or restore. Detect incomplete setup before offering fresh creation.
3. Collect configuration and credential-storage choices.
4. Show missing dependencies, proposed resource creation, reuse, and host changes.
5. Ask before installing dependencies or changing pre-existing resources.
6. Record action intent, perform actions, and check actual results.
7. Configure services, certificate renewal, and selected backup scheduling.
8. Check service health and present access details, backup destination, and next steps.

Existing installations from the old scripts are not eligible for automatic adoption.
An existing local deployment must trigger an explanation instead of an overwrite.

## Terminal and automation behaviour

The guided mode uses a full-screen terminal wizard with keyboard navigation,
consistent visual hierarchy, phase status, and an explicit cancel action.
Colour is supplementary: text identifies success, failure, and required action.
Errors explain the failed action, retained work, and available recovery choices.
The interface restores terminal settings on normal exit and handled interruption.

Non-interactive operations use explicit configuration and readable output. They do
not wait for input. Required interactive approval produces a nonzero exit and a
clear explanation. In particular, changes to pre-existing resources always require
interactive approval. Exact command names and exit codes are implementation choices.

## Persistent state and reconciliation

Local state is authoritative and lives outside any repository. It contains a schema
version, deployment identity, configuration references, resource identifiers,
ownership evidence, dependencies, action intent, and action results.
It also records original and applied values for changes to pre-existing settings.
Credential values do not belong in this state.

State writes must survive interruption without leaving an unreadable partial record.
Only one mutating operation may run against a deployment at a time.

Before cloud creation, persist intent and a correlation identifier. Where supported,
attach a deployment ownership marker. Request read permissions to inspect actual
resources. After a lost response, query before retrying creation. Account for delayed
visibility and distinguish desired-state checks from proof of ownership.

A matching name alone never establishes ownership. Ambiguous results require review.
Do not create duplicates merely because the previous response was lost.

After failure, retain state and completed work. On the next interactive run, show a
summary and offer resume or guided cleanup. Starting over requires cleanup first.
Non-interactive resume selection needs an explicit command contract before release.

## Teardown contract

Teardown presents eligible resources and their dependencies before removal.
Only resources created by this deployment are eligible for deletion.
Preserve pre-existing resources and created resources that now support unrelated use.
For example, preserve a created DNS zone with unrelated records while removing only
eligible deployment records.

Prompt before restoring a pre-existing setting. Restore only when the current value
still matches the value applied by the tool. Otherwise retain the current setting
and report the conflict. Apply the same rule to host configuration.

Preserve database data, recordings, and backups by default. Permanent deletion needs
explicit intent. Show retained items and incomplete cleanup at the end. Keep enough
state to retry failed cleanup. Do not report complete teardown with unexplained residue.

Preserve dependencies that have become shared. Exact dependency detection and APIs
without supported inverse operations require implementation review before use.

## Credentials and TLS

Offer TPM-backed systemd encryption as the preferred persistent mode, host-key
encryption where supported, and explicitly selected owner-only plaintext storage.
Also accept process environment input and interactive prompts. Plaintext storage
is an approved exception for this project. Never select it as a silent fallback.

Show supported options and the selected protection level. Keep secrets out of logs,
command histories, ownership state, and source control. Persistent plaintext files
use owner-only access. Treat their parent directory and runtime copies accordingly.

Document virtual TPM and hypervisor trust, backup implications, and replacement-host
recovery. A prompt-only mode cannot provide unattended reboot recovery by itself.
Check container delivery and reboot behaviour for each persistent mode.

Use Let's Encrypt with Cloudflare DNS validation for the NGINX origin certificate.
Install renewal independently of the provisioning binary. Clean up challenge records
created by renewal. Keep certificate verification enabled between the tunnel and origin.
Cloudflare manages the separate browser-facing certificate.

## Backup and restore

Provide manual database backups and optional scheduled backups. Use PostgreSQL's
database-aware export rather than an ordinary copy of a running data directory.
Provide a matching restore operation and account for required database roles.

Destinations are local directories, existing mounted shares, or Azure Blob.
Do not configure NFS or SMB mounts in V1. Check the expected external mount before writing. A missing
mount must fail visibly instead of redirecting output to local storage.

Publish a backup as complete only after successful export. Retention must not mistake
a partial export for a valid backup. Show destination and last-run results.
Encrypt backups by default. Keep the recovery key separately from the VM so that
replacement-host recovery does not depend on its TPM. Offer plaintext backups only
as an explicit choice. Offer daily scheduling and retain the last seven successful
backups by default. Make schedule and retention configurable. Failed backups must
not trigger deletion of older backups.

Generate the backup key pair in memory on the server. Prompt for an administrator
passphrase with hidden input and confirmation. Write only a passphrase-encrypted
private-key export with owner-only permissions. Never display or log the private key
or passphrase. Use one supported cryptographic default.

Show the encrypted export location and instructions for downloading it over SSH.
Provide a transfer-command example with placeholders where connection details are
unknown. The command contains no secrets and runs on the destination workstation.
Explain that both the encrypted file and its passphrase are required for recovery.
Administrators are responsible for copying the file off the VM and storing it safely.
Do not claim that displaying instructions proves successful export or recoverability.
Do not automatically remove the encrypted export before administrator confirmation.
Scheduled backups use only the public key and require no recovery passphrase.
V1 includes no workstation key-generation tooling, client-side key-generation guides,
or vault integration. Document recovery and export cleanup without promising removal
from snapshots or backups.

Before backup, copy a versioned snapshot of authoritative deployment metadata into
a separate database area. Include the snapshot in the database export. Coordinate
this with deployment mutations to avoid inconsistent ownership information.

Restore supports the original host and a replacement VM. Setup accepts a backup and
requests credentials that cannot be recovered on the replacement. Validate backup
format and version compatibility before altering the target database.

Reconcile restored ownership metadata with current cloud resources before acting.
Database exports can contain sensitive application data, including saved connection
credentials. Excluding deployment credentials from metadata does not remove this risk.
Include completed recordings in V1 backup coverage. Record which recordings each
backup operation includes, excludes, or loses to retention. Report database and
recording results separately. Never label a partial recording upload as complete.

## Azure Blob destination

Recording backups are required in V1. Support Azure Blob as an optional destination
alongside local directories and existing mounted shares. Provide guided device-code
sign-in and subscription selection. Allow selection of an existing storage account
and container, or approved creation of those resources through Azure management APIs.
Check management permissions separately from blob data access and role assignment.
Scheduled uploads require unattended authentication independent of the administrator's
interactive session. The precise credential mechanism remains an implementation decision.

Upload completed recordings and database backups using the selected encryption mode.
Apply local recording retention independently of upload success. Preserve remote
backups and their supporting storage resources during ordinary teardown. Provide a
documented procedure to retrieve archived recordings. Transparent playback directly
from Azure is not a V1 requirement.

## Local recording retention

During setup, ask the administrator for a local recording storage budget. Install
scheduled cleanup independently of the provisioning binary. When usage exceeds the
budget, delete the oldest completed recordings until usage returns within budget
or no completed recordings remain. Upload success is not a condition for deletion.
The local storage budget takes priority over preserving unbacked recordings.

Show this policy during setup and report deletions of recordings without a confirmed
remote copy. Such deletion can permanently lose a recording. Coordinate cleanup and
uploads to avoid reporting an incomplete upload as successful. Do not delete active
recordings. Scheduled cleanup is not a hard filesystem quota: active recordings and
the interval between runs can temporarily exceed the budget. Behaviour when active
recordings alone exhaust available space requires an implementation decision.

## Remote recording retention

Ask the administrator how many days to retain recordings in Azure. Automatically
remove only this deployment's recordings after the selected period. Do not apply
this rule to unrelated objects or database backups. Database backups retain the
separate default of seven successful backups. Local recording cleanup remains
based on its storage budget, independent of remote retention and upload success.

## Release and host compatibility

GitHub builds, tests, and publishes versioned Linux releases. Sign releases and verify
the approved publisher identity before executing downloads. Sigstore is the proposed
signing mechanism. Resolve verifier distribution and initial trust before release.

Test on Rocky Linux 10 with SELinux enforcing. Do not disable host security controls.
Respect configured proxies and certificate trust. Application allowlisting may need
administrator approval outside the tool, which cannot approve its own execution.

The README lists supported versions, CPU requirements, privileges, account permissions,
VM resources, DNS, time, storage, and optional TPM requirements. List verified network
destinations, ports, protocols, and purpose for setup and runtime separately.
Distinguish prerequisites the user supplies from dependencies installed by the tool.

## Acceptance criteria

| ID | Required evidence |
|---|---|
| A1 | Install on a clean supported VM without a checkout or Go runtime. |
| A2 | Entra login and a representative Guacamole connection succeed through Cloudflare. |
| A3 | Installed dependencies and existing resources appear correctly in the action summary. |
| A4 | Interrupt after cloud creation but before recording success. Resume without duplicates. |
| A5 | Ambiguous ownership prompts for review and prevents speculative deletion. |
| A6 | Teardown preserves pre-existing and later-shared resources. |
| A7 | Changed pre-existing settings restore only after approval and only without later drift. |
| A8 | Non-interactive commands stop at required approvals and never hang for input. |
| A9 | Cancellation preserves recoverable state and restores the terminal. |
| A10 | Data and backups survive ordinary teardown. Explicit deletion follows the displayed plan. |
| A11 | Persistent credential modes support reboot without retaining the provisioning binary. |
| A12 | Certificate renewal succeeds and reports failure without disabling TLS checks. |
| A13 | Manual and scheduled backups succeed. Missing mounts and partial exports fail visibly. |
| A14 | Restore on a fresh VM recovers the database and metadata, followed by access checks. |
| A15 | Altered artifacts and signatures from an unapproved identity fail verification. |
| A16 | The full installation works with SELinux enforcing. README prerequisites match observed access. |
| A17 | Generate an encrypted key export without printing secrets. Decrypt a backup with the exported key on a replacement host. |
| A18 | Select existing Azure storage and create new storage in separate tests. Check unattended upload and retrieval. |
| A19 | Upload completed recordings and report partial or failed transfers. |
| A20 | Exceed the local recording budget. Delete oldest completed files even after failed uploads, while preserving active recordings. |
| A21 | Expire Azure recordings by the selected age without deleting unrelated objects or applying recording rules to database backups. |
| A22 | Failed database backups preserve earlier successful backups. Successful backups follow configured retention. |
| A23 | Teardown preserves remote backup data and supporting storage resources. |

## Deferred work

The backlog contains automated upgrades, automatic share setup, corporate certificate
workflows, optional Cloudflare, other distributions, ARM, remote deployment management,
and alternative integrations. AWS S3 and Cloudflare R2 are on the backlog for later
versions without a fixed release commitment. Windows has higher future priority than macOS.
Apple signing and notarization have no committed release. Offline installation and
old-script adoption are outside V1. Multiple deployments per host are outside the
product scope agreed for this iteration.

## Delivery gates and unresolved decisions

First prove fresh deployment, interrupted resume, and safe teardown on Rocky Linux.
Then prove credential delivery, renewal, scheduled backup, and replacement restore.
Complete the wizard, signed releases, and documentation against those behaviours.
The next-week target is not a confirmed estimate until an implementation breakdown
and representative integration tests support it.

Resolve these items before their related implementation gate:

- Rocky Linux minor release, CPU baseline, runtime, and pinned component versions.
- State location, format, locking, and provider-specific ownership markers.
- Exact API scopes and handling of resources without supported deletion APIs.
- Credential delivery, backup encryption implementation, recovery-key handling,
  recording consistency, and unattended Azure authentication.
- Explicit non-interactive resume behaviour.
- Signing trust bootstrap, destination allowlist, and minimum VM resources.

These checks refine the agreed scope. They do not authorise adding features or
silently removing acceptance criteria to meet the deadline.

## Implementation tracker and test platform

The approved implementation tickets are published in
[GitHub Issues](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/issues).
Tickets use the `ready-for-agent` label and native blocking relationships.

Prepare a resettable Rocky Linux 10 AMD64 test VM on PVE01, with SELinux enforcing,
SSH access, TPM and non-TPM test coverage, reboot tests, and replacement-host recovery.
The test platform can be prepared alongside the deployment-session foundation.
See [the test-platform ticket](https://github.com/Proaxiom-Cyber/guacamole-saml-sso/issues/25).
