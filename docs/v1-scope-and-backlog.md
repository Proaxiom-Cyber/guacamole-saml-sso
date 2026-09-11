# V1 scope and backlog

This document consolidates the design interview on 11 September 2026. It records
the latest decisions and replaces earlier scope choices where they conflict.
The target is readiness next week. This is a delivery target, not a validated
estimate. Product implementation has not been authorised by this scope review.

## Purpose and platform

- Deploy Guacamole for IT administrators familiar with DNS, Cloudflare, and Entra.
- Support temporary project access and durable installations.
- Run on the installation host. Support one deployment per host.
- Target Rocky Linux 10 on Intel and AMD 64-bit VMs only in V1.
- Use a compiled Go binary and a small download launcher. Require no repository
  checkout or Go installation.
- Install missing dependencies after presenting the required host changes.
- Require Cloudflare and Entra in V1. Use separate integration modules to allow
  future alternatives without a general plugin framework.
- Require internet access. Offline installation is outside V1.
- Start with new installations. Do not adopt installations from the old scripts.

## User experience

- Provide a polished full-screen terminal wizard with keyboard controls, progress,
  useful error details, and an explicit cancel action.
- Also provide subcommands and non-interactive operation.
- Restore the terminal on exit. Provide plain output where rich output is unsuitable.
- Check prerequisites before creating deployment resources.
- Document required destinations, ports, protocols, and their purposes in the README.
- Distinguish installation downloads from ongoing runtime connections.
- Document privileges, VM resources, accounts, permissions, DNS, storage, and TPM options.
- Respect existing proxy and certificate trust settings. Do not disable certificate
  checks to resolve connectivity failures.

## State, resume, and teardown

- Keep authoritative local state outside a repository checkout. Exact location and
  schema remain implementation decisions.
- Record resource identifiers, creation versus reuse, completed steps, and changes
  to pre-existing settings. Keep credential values separate from ownership state.
- After failure, show completed work and ask before resuming. Offer guided cleanup.
- Request read permissions to compare actual cloud resources with the desired state.
- Record creation intent before each cloud request. Attach a deployment identifier
  where the resource API supports an appropriate ownership marker.
- After interruption, query the provider before retrying creation. Check both desired
  settings and ownership. A matching name or configuration alone does not prove ownership.
- Present ambiguous ownership for administrator review. Do not guess or delete the
  resource. Account for delayed visibility before treating a resource as absent.
- Starting over requires cleanup first. Retain ownership records until cleanup completes.
- Offer deletion only for resources the tool created.
- Preserve created resources that now serve unrelated uses. For example, preserve a
  DNS zone with unrelated records while offering removal of deployment-owned records.
- Prompt before changing pre-existing resources, including restoration during teardown.
- Restore an original setting only when its current value still matches the tool's
  change. Otherwise preserve it and report the conflict.
- Non-interactive runs stop before changes that require these interactive prompts.
- Preserve application data, recordings, and backups by default. Permanent deletion
  requires an explicit choice. Non-interactive teardown also requires explicit deletion intent.
- Preserve installed dependencies that have become shared.

## Credentials and certificates

- Prefer encrypted systemd credentials backed by a TPM, subject to platform and
  container integration checks. Recommend a virtual TPM without requiring one.
- Offer host-key encryption where supported, process environment input, and prompts.
- Offer explicitly selected plaintext credential storage with owner-only permissions.
  Cameron approved this project-specific exception to the general no-plaintext rule.
- Show the selected storage method. Do not silently downgrade protection.
- Keep credential files separate from resource state and exclude them from version control.
- Document virtual TPM, hypervisor, backup, and recovery assumptions.
- Use automatic Let's Encrypt issuance and renewal in V1, with Cloudflare DNS validation.
- Leave renewal functionality on the host after the provisioning binary is removed.
- Treat Cloudflare's browser-facing certificate and the NGINX origin certificate separately.
- Test with SELinux enforcing. Accommodate host policy rather than disabling it.

## Backup and recovery

- Provide manual and scheduled PostgreSQL backups, using database-aware exports.
- Offer daily backups and retain seven successful backups by default. Both settings
  are configurable. Failed backups do not trigger deletion of older backups.
- Encrypt backups by default, with a recovery key kept separately from the VM.
  Offer plaintext backups only as an explicit choice.
- Generate backup keys on the server and save only a passphrase-encrypted private-key
  export. Show its location and SSH transfer instructions without displaying secrets.
  Administrators handle off-VM transfer and safekeeping. Scheduled backups use the
  public key only. Omit workstation key-generation tooling and guides from V1.
- Support local directories and existing mounted shares. Administrators configure mounts.
- Show the backup destination and failures. A missing external mount must not cause
  an unnoticed backup into its local mount-point directory.
- Leave a backup routine and operating-system schedule on the host. Neither depends
  on retaining the provisioning binary.
- Preserve backups during normal teardown. Remove schedules created by the tool.
- Include deployment metadata in a separate database area. Copy authoritative local
  state there before backup. Do not copy deployment credential-store values there.
- Support restore on the original host and on a replacement VM.
- Offer restore during setup. Request credentials again where needed.
- Check restored resource metadata against current cloud resources before acting.
- Account for database roles and test restoration. Recordings require separate coverage.

## Distribution

- Keep the GitHub build-and-release pipeline in V1.
- Sign Linux releases and check signatures before running downloaded binaries.
- Bind verification to the approved publisher and release workflow.
- Sigstore identity-based signing is the recommended implementation, pending review
  of launcher verification and its initial trust requirements.
- Document additional administrator approval on hosts with application allowlisting.

## Backlog

- Deployed upgrade helper, database migration automation, and rollback automation.
- Automatic NFS or SMB connection, mount configuration, and share credential management.
- Corporate CA signing requests, certificate import, and certificate replacement flow.
- Optional Cloudflare and direct internal access.
- Other Linux distributions, including Ubuntu, and ARM processors.
- Windows support, ahead of macOS in future priority. Neither has a target release.
- macOS support, Apple signing, and notarization. No version commitment.
- Alternative networking and identity integrations, including possible Active Directory use.
- Remote deployment management and a reusable provisioning framework.

## Delivery assessment

The narrower platform and deferred features reduce scope. The complete V1 still
requires substantial new behaviour beyond the current scripts. Readiness next week
needs an implementation breakdown and access to a representative test VM and test
cloud accounts. The interview alone does not establish schedule feasibility.

Recommended implementation order:

1. Prove one fresh Rocky Linux deployment with the existing integration combination.
2. Add durable state, interruption recovery, and ownership-aware teardown.
3. Prove each retained credential mode and certificate renewal after reboot.
4. Prove scheduled backup and replacement-VM restore.
5. Complete the terminal wizard, signed distribution, and prerequisite documentation.

Release checks must include real failure paths:

- Interrupt setup after cloud creation, then resume without duplicate resources.
- Reject or report uncertain ownership rather than delete by a matching name.
- Preserve pre-existing resources, later-shared resources, data, and backups.
- Check prompts and non-interactive stopping rules.
- Restart services and scheduled jobs after reboot without the provisioning binary.
- Fail a backup clearly when its external mount disappears.
- Restore a backup onto a fresh VM and check login and a Guacamole connection.
- Reject altered downloads and signatures from the wrong publisher identity.
- Complete deployment with SELinux enforcing.

## Remaining implementation questions

- Exact Rocky Linux 10 minor release, CPU baseline, container runtime, and image versions.
- Credential delivery into containers without unapproved persistent plaintext copies.
- Backup encryption implementation and recovery-key handling. Database exports can contain sensitive
  application data even when deployment credentials remain outside the metadata.
- Scope and consistency of recording backups and restore validation.
- Behaviour for cloud resources whose APIs lack a supported inverse operation.
- Exact endpoint allowlist, permissions, and initial signing-verifier trust.
- Non-interactive behaviour for interrupted runs that require a resume decision.

These are open checks, not permission to expand V1. Any proposed scope reduction
still requires Cameron's decision.

## Storage scope update

Recording backups are required in V1. Support Azure Blob as an optional destination
alongside local directories and existing mounted shares. Provide guided device-code
sign-in and subscription selection. Allow selection of an existing storage account
and container, or approved creation of those resources through Azure management APIs.
Check management permissions separately from blob data access and role assignment.
Scheduled uploads require unattended authentication independent of the administrator's
interactive session. The precise credential mechanism remains an implementation decision.

Upload completed recordings and encrypted database backups. Apply the local recording retention policy independently of upload success. Preserve remote backups and the storage resources needed to
hold them during ordinary teardown. Define restore/playback behaviour before implementation. The seven-successful-backup default does not yet
establish a recording retention policy.

AWS S3 and Cloudflare R2 are outside V1. Add them to the backlog for the next few
versions without committing either to a specific release.

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
