# Test platform: Rocky Linux 10 VM on PVE01

This document describes the test VM for deployment-tool integration tests (issue #25).
Development and cross-compilation stay on the Mac. The VM only runs test deployments.

## VM identity and resources

| Item | Value |
|---|---|
| VM ID / name | 133 / `slq-guac-test` |
| Node | pve01 (Proxmox VE 9.1.6) |
| OS | Rocky Linux 10.2 (Red Quartz), kernel 6.12.0-211.16.1.el10_2.0.1.x86_64 |
| Image | Rocky-10-GenericCloud-Base.latest.x86_64.qcow2, downloaded 2026-09-11, stored on pve01 as `/var/lib/vz/template/iso/Rocky-10-GenericCloud-Base-20260526.x86_64.img` |
| Image SHA256 | `9fc9e9ff16888bb68ac39b0392e25c9c92684d50c85f1cce6ab549363bbc4b48` |
| CPU | 2 cores, type `host` (AMD Ryzen 9 3950X passthrough; x86-64-v3 confirmed with `ld.so --help`) |
| Memory | 4096 MB |
| Disk | scsi0 32 GB thin on `local-lvm`, root grown by cloud-init |
| Firmware | OVMF (UEFI, q35), secure boot keys not enrolled |
| vTPM | `tpmstate0: local-lvm:vm-133-disk-1,version=v2.0` → `/dev/tpm0`, TPM 2.0 |
| SELinux | Enforcing (Rocky default, not changed) |
| Guest agent | qemu-guest-agent (ships in the image). `FILTER_RPC_ARGS=""` set in `/etc/sysconfig/qemu-ga` so `guest-exec` works. SELinux still restricts its operations. |

## Network boundaries

- NIC: virtio on bridge **vmbr1** — the lab guest network `192.168.25.0/24`.
  vmbr0 is not the guest network; a VM on vmbr0 gets no DHCP lease.
- Address: DHCP from pfSense (192.168.25.1). Current lease: `192.168.25.140`.
  The lease can change; resolve the current address with
  `ssh pve01-root 'qm agent 133 network-get-interfaces'`.
- Outbound: NAT through pfSense. DNS and NTP come from DHCP. Verified: DNS resolution,
  chrony synchronized, HTTPS to Rocky mirrors.
- Inbound: only from the lab subnet. From the Mac, the subnet is reachable over
  Tailscale (subnet route for 192.168.25.0/24). No public exposure.

## Access and remaining SSH requirement

Use the existing `pve01-root` host access and the guest agent for permitted operations:

```
ssh pve01-root 'qm guest exec 133 -- /usr/bin/id -u'
```

The guest agent runs as root, but SELinux restricts what it can access. For example,
it cannot edit the guest's SSH authorization files. Do not disable SELinux to work
around those restrictions.

Direct SSH access still needs a Secure Enclave-backed key and verification. This
requirement remains open in issue #25. No guest password has been configured.

The first platform agent created a file-based private key at
`~/.ssh/slq-guac-test`. This broke the global SSH-key rule. The supervisor revoked
that key in the current VM, its cloud-init source, and the clean reset snapshot.
The supervisor then deleted the new key pair from the Mac. Other SSH keys and VM129
were preserved. Keeping a private key only on the Mac did not satisfy the rule.

## Reset procedure (clean baseline)

Snapshot `clean-baseline` is the reset point: Rocky installed, SELinux enforcing,
guest-exec enabled, and nothing deployed. It was replaced on 2026-09-11 to remove
the agent-created SSH authorization. Cloud-init can run again on the next boot,
using the corrected configuration without that key.

```
ssh pve01-root 'qm rollback 133 clean-baseline && qm start 133'
```

Verified: the snapshot on lvmthin **includes the vTPM state disk**
(`snap_vm-133-disk-1_clean-baseline` exists), so rollback restores TPM state too.
Snapshots were taken without RAM state; after rollback the VM boots fresh.

**Rollback is not cleanup of external resources.** Restoring the VM snapshot does NOT
remove anything a test created in Azure, Entra ID, or Cloudflare. Clean those up
through the deployment tool's own teardown or by hand in the tenant.

## Rebuild and replacement-VM recovery

The previous rebuild instructions reused the rejected file-based SSH key. They
have been removed. Issue #25 must provide and test a replacement procedure with
approved access before this platform is complete.

Use a new VM ID and name for replacement-VM tests. Preserve VM133 and all unrelated
lab resources. The source image remains available on PVE01 at the path above.
Check that the node has approximately 4 GB of free memory and space for a 32 GB
thin disk before creating another VM.

## Testing without TPM

Use a separate VM without a TPM to test the fallback credential path. Its build
and access procedure still needs verification under issue #25. Do not remove
VM133's TPM. Delete only the additional VM created for that test after it finishes.

## Lab prerequisites

- Tailscale up on the Mac with the 192.168.25.0/24 subnet route
  (`~/.local/bin/lab-access status --fresh` → `vpn-ready` or `local`).
- SSH host alias `pve01-root` for root on pve01.
- pve-cam-lab MCP for read/inspect and guest-exec operations. Note: the MCP token
  cannot allocate ISO/template content on storage (403 Datastore.AllocateTemplate);
  image downloads go over `ssh pve01-root`.
- Secure Enclave-backed guest SSH access, once configured and verified.

## Remaining test-account requirements (not created by this platform)

Integration tests of the deployment tool still need, per later tickets:

- An Entra ID test tenant (Demo Customer) app registration or Graph token with rights
  to create the SAML enterprise app, and test user accounts for SSO login.
- Cloudflare test zone API credentials if the tool manages DNS/tunnel records.
- All such credentials live in the macOS Keychain and are referenced at runtime;
  none are stored in this repo, on the VM, or in the lab.

Again: VM snapshot rollback never cleans up what tests created in Azure, Entra, or
Cloudflare. Track and remove those resources separately.

## Platform findings from live runs

- The GenericCloud image ships `kernel-modules-core` only. The first
  `dnf update` installs a newer kernel with the full `kernel-modules`
  package. Until the VM reboots into that kernel, Docker cannot load
  `xt_addrtype` and fails to start. guacdeploy preflight now detects this
  and asks for a reboot-and-resume. After a rollback to `clean-baseline`,
  expect one update-and-reboot before deploying.
