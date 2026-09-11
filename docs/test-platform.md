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
| Guest agent | qemu-guest-agent (ships in the image). `FILTER_RPC_ARGS=""` set in `/etc/sysconfig/qemu-ga` so `guest-exec` works. The agent runs SELinux-confined; use SSH for privileged operations. |

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

## SSH access pattern (no secrets in this repo)

- Dedicated keypair on the Mac: `~/.ssh/slq-guac-test` (ed25519, created for this VM).
  The private key never leaves the Mac. Only the public key is installed in the VM
  through cloud-init (`qm set 133 --sshkeys`).
- Login: `ssh -i ~/.ssh/slq-guac-test rocky@<current-ip>`. User `rocky` has
  passwordless sudo (cloud image default). No passwords are set anywhere.

## Reset procedure (clean baseline)

Snapshot `clean-baseline` (2026-09-11) is the reset point: cloud-init done, SELinux
enforcing, guest-exec enabled, SSH key installed, nothing deployed.

```
ssh pve01-root 'qm rollback 133 clean-baseline && qm start 133'
```

Verified: the snapshot on lvmthin **includes the vTPM state disk**
(`snap_vm-133-disk-1_clean-baseline` exists), so rollback restores TPM state too.
Snapshots were taken without RAM state; after rollback the VM boots fresh.

**Rollback is not cleanup of external resources.** Restoring the VM snapshot does NOT
remove anything a test created in Azure, Entra ID, or Cloudflare. Clean those up
through the deployment tool's own teardown or by hand in the tenant.

## Rebuild from scratch / replacement-VM recovery

The same procedure creates a fresh replacement VM without touching VM 133 or any other
lab resource. Pick a free ID with `ssh pve01-root 'pvesh get /cluster/nextid'` and a
new name. The source image is already on pve01 (path above).

```
scp ~/.ssh/slq-guac-test.pub pve01-root:/tmp/key.pub
ssh pve01-root 'set -e
  ID=<free-id>
  qm create $ID --name slq-guac-test2 --ostype l26 --machine q35 --bios ovmf \
    --cpu host --cores 2 --memory 4096 --scsihw virtio-scsi-single \
    --net0 virtio,bridge=vmbr1 --agent enabled=1 --serial0 socket --vga serial0
  qm set $ID --efidisk0 local-lvm:1,efitype=4m,pre-enrolled-keys=0
  qm set $ID --tpmstate0 local-lvm:1,version=v2.0
  qm set $ID --scsi0 local-lvm:0,import-from=/var/lib/vz/template/iso/Rocky-10-GenericCloud-Base-20260526.x86_64.img,discard=on
  qm disk resize $ID scsi0 32G
  qm set $ID --ide2 local-lvm:cloudinit
  qm set $ID --boot order=scsi0
  qm set $ID --ciuser rocky --ciupgrade 0 --sshkeys /tmp/key.pub --ipconfig0 ip=dhcp
  qm start $ID'
```

After first boot, enable guest-exec once:

```
ssh -i ~/.ssh/slq-guac-test rocky@<new-ip> \
  'sudo sed -i "s/^FILTER_RPC_ARGS=.*/FILTER_RPC_ARGS=\"\"/" /etc/sysconfig/qemu-ga \
   && sudo systemctl restart qemu-guest-agent'
```

This is the exact command sequence that built VM 133, so it is verified by
construction. Capacity check first: the node must have ~4 GB memory free
(`free -g` on pve01) and `local-lvm` must have room for a 32 GB thin disk.

## Testing without TPM

Cheapest repeatable option: run the rebuild script above for a second VM and **omit
the `--tpmstate0` line**. The VM then has no `/dev/tpm0` and the tool's non-TPM
credential path can be tested. Delete that VM afterwards (`qm destroy <id>` — only the
VM you created). Do not remove the TPM from VM 133; keep 133 as the TPM platform.

## Lab prerequisites

- Tailscale up on the Mac with the 192.168.25.0/24 subnet route
  (`~/.local/bin/lab-access status --fresh` → `vpn-ready` or `local`).
- SSH host alias `pve01-root` for root on pve01.
- pve-cam-lab MCP for read/inspect and guest-exec operations. Note: the MCP token
  cannot allocate ISO/template content on storage (403 Datastore.AllocateTemplate);
  image downloads go over `ssh pve01-root`.
- Keypair `~/.ssh/slq-guac-test` present on the Mac.

## Remaining test-account requirements (not created by this platform)

Integration tests of the deployment tool still need, per later tickets:

- An Entra ID test tenant (Demo Customer) app registration or Graph token with rights
  to create the SAML enterprise app, and test user accounts for SSO login.
- Cloudflare test zone API credentials if the tool manages DNS/tunnel records.
- All such credentials live in the macOS Keychain and are referenced at runtime;
  none are stored in this repo, on the VM, or in the lab.

Again: VM snapshot rollback never cleans up what tests created in Azure, Entra, or
Cloudflare. Track and remove those resources separately.
