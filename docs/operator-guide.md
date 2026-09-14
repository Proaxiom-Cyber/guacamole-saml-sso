# Operator guide

This guide grows with each delivered slice. It currently covers the
deployment session commands. The full terminal experience and the complete
guide arrive with the final wizard work.

## Install

Install `guacdeploy` from a signed release with the launcher script. See the
install section of the README for the command, and
[release-and-verification.md](release-and-verification.md) for what the
launcher verifies and which network destinations it uses.

## Commands

| Command | Purpose |
|---|---|
| `guacdeploy` or `guacdeploy setup` | Start a fresh deployment, or resume or clean up an interrupted one |
| `guacdeploy setup --non-interactive` | Unattended setup. Never waits for input |
| `guacdeploy setup --non-interactive --resume` | Unattended consent to continue interrupted work |
| `guacdeploy setup --non-interactive --install-dependencies` | Unattended consent to install missing dependencies |
| `guacdeploy status` | Show the deployment record without changing anything |
| `guacdeploy backup-key` | Generate the backup key pair and write the encrypted private-key export |
| `guacdeploy backup-key --verify` | Prove the export decrypts and matches the recorded public key |
| `guacdeploy backup` | Export the database, encrypted, into a directory |
| `guacdeploy restore --file PATH` | Replace the database from a backup file, after validation and consent |
| `guacdeploy version` | Print the tool version |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Failure. The message names the failed action |
| 2 | Usage error |
| 3 | Interactive approval required. Unattended mode stops here instead of prompting |
| 130 | Cancelled by the operator. Completed work is saved |

## Interrupted work

Setup records what it intends to do before it does it, and the checked
result afterwards. If a session is interrupted, the next interactive run
shows the interrupted work and offers resume or cleanup. Cleanup removes
only a record that created no resources; anything more requires teardown.

Only one mutating operation can run at a time on a host. A second
invocation reports that an operation is already running.

## Host preparation

Setup checks the host before it changes anything: Rocky Linux 10 on Intel
or AMD 64-bit, root privileges, no existing installation, and outbound
TCP 443 to `mirrors.rockylinux.org`, `download.docker.com`, and
`registry-1.docker.io`. Unsupported platforms, hosts where the `docker`
command runs Podman, and hosts with an existing installation are rejected
with an explanation. Nothing is adopted or overwritten.

Some Rocky cloud images lack the kernel modules Docker needs. Setup offers to
install `kernel`, `kernel-modules`, and `kernel-modules-extra` before it requests
credentials. It asks for approval, or requires `--install-dependencies` in an
unattended run. If the next boot kernel has the modules but the running kernel
does not, setup stops and saves progress. Run `sudo reboot`, reconnect, then run
`sudo guacdeploy` and choose Resume. Setup checks again before it continues.
Kernel packages remain with the host during teardown.

If Docker is missing, setup offers to install it from Docker's RHEL repository,
then enable and start its service. If Docker exists but Compose is unavailable,
setup offers to install only `docker-compose-plugin`. This leaves the existing
Docker service settings unchanged. Setup asks before installing. Unattended runs
need `--install-dependencies`. Setup records the installed packages and any
service enablement it performs. Pre-existing Docker is never offered for removal
at teardown.

### Compose command compatibility

This installer uses `docker compose` for setup and teardown. The separate
`docker-compose` executable does not satisfy that requirement. Docker recommends
the [Compose plugin](https://docs.docker.com/compose/install/linux/) and retains
the [standalone installation](https://docs.docker.com/compose/install/standalone/)
for backward compatibility. The command spelling alone does not identify the
Compose version.

Setup runs `docker compose version` before installing dependencies and again
after installation. If the second check fails, setup stops before starting the
stack. It does not fall back to `docker-compose` or depend on a shell alias.

For diagnosis, run these checks with the same privileges as the installer:

```sh
sudo docker --version
sudo docker compose version
```

A plugin installed only under your user account can be unavailable to `sudo`.
Docker documents separate user and system installation paths. Use the packaged
plugin for this deployment, and make sure the existing Docker service is running.

## The Guacamole stack

Setup renders the container configuration under `/opt/guacamole` and starts
four containers: guacd, PostgreSQL, the Guacamole web application, and
nginx. The database schema is generated from the pinned Guacamole image and
validated before use. nginx serves HTTPS with a temporary self-signed
certificate until the origin certificate is issued. Setup checks container
health and then checks that Guacamole answers through nginx.

Setup starts PostgreSQL first and waits for an authenticated TCP connection.
It then checks the database against the generated schema. During unfinished
setup, an empty database receives the schema and authorization groups in one
transaction. An interrupted or failed import rolls back. Resume can retry it.
Guacamole starts only after the database check succeeds.

A complete database keeps its data and groups. A partial schema stops setup
for review. Setup does not delete the database directory or overwrite a partial
import. After setup completes, the boot command checks the schema but cannot
initialize a replacement database if application data is missing.

This recovery also covers earlier installer versions that created the PostgreSQL
data directory without importing the Guacamole tables. Install the current release
and choose **Resume**. No manual SQL import is needed when the database is empty.
The first-start scripts no longer control initialization. Public schema files are
mounted at `/opt/guacdeploy-init` inside the PostgreSQL container.

Unattended runs supply `--hostname`, `--admin-group`, and
`--operator-group`. No credential is given to a container as an environment
variable. Docker keeps a container's environment in its own metadata on disk
and re-reads it on every boot, so an environment variable is a permanent
plaintext copy of the credential. Each credential is written instead to an
owner-only file under `/run/guacdeploy/secrets`, which is memory-backed: the
container reads the file itself, and a reboot leaves nothing behind. The
`guacdeploy-stack.service` boot unit writes the files again and restarts the
containers after each boot. Containers restart automatically with Docker
after a reboot. The database
data directory is recorded as data to preserve: ordinary teardown keeps it,
and only an explicit deletion request removes it.

## Credentials

Setup asks how the deployment receives credentials, shows what each choice
protects them with, and lists a mode this host cannot do with the reason:

- **tpm** — sealed by `systemd-creds` with the host key and the TPM together
  (`--with-key=host+tpm2`), so both the TPM and a root-only host secret are
  needed to read the value back. Preferred where a TPM exists. On a virtual
  machine the hypervisor holds the TPM's secrets, so a compromised hypervisor
  can read them, and a sealed credential cannot be decrypted on a replacement
  host.
- **host** — sealed by `systemd-creds` with the host key alone
  (`--with-key=host`), for a host with no usable TPM. Also bound to this
  machine.
- **prompt** — hidden interactive prompts at the moment of use. Nothing is
  stored on disk. This mode cannot support unattended operation.
- **env** — `GUACDEPLOY_CRED_*` environment variables supplied to each
  invocation. Unattended operation works when the caller injects them.
- **file** — owner-only plaintext files under the state directory's
  `credentials/` folder. This is an approved exception for this project
  and is never chosen silently: selecting it requires explicit approval
  (guided confirmation or the explicit `--credentials file` flag).

Unattended runs select the mode with `--credentials tpm|host|env|prompt|file`.
A mode this host cannot do is refused with the reason — no TPM device, systemd
older than 250, or a TPM the firmware or driver cannot use — and setup stops
there. It never answers an unavailable encrypted mode by writing the value in
plaintext instead. Choose another mode yourself.
Setup checks the Cloudflare API token as soon as you supply it, before saving it
or installing Docker. The check uses a read-only zone request and accepts user
and account API tokens. A rejected token opens a hidden replacement prompt.
A connection error offers a retry with the same token. Quit retains your progress.

Resume repeats the credential check, including sessions from older releases.
If a saved token fails, choose replacement to validate and save a new token with
the same storage method. The database password and completed setup work remain.
Unattended runs stop with instructions to supply the token again. Environment mode
uses `GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN` and does not save a replacement.

Setup names what to supply when a required credential is missing.
Credential values never appear in
deployment state, logs, or command arguments. Files written by the tool
are recorded as material owned by this deployment, so teardown can offer
their removal; files you placed yourself are pre-existing and stay.

## Recovering onto a replacement host

When the host is lost, `guacdeploy recover --file <backup>` rebuilds the
deployment record on a replacement machine. It reads the backup, asks
Cloudflare and Entra what of the lost deployment is still there, and writes
the record that an ordinary `guacdeploy setup` then works from.

It creates nothing, changes nothing at any provider and deletes nothing.
Each resource is looked up by this deployment's ownership marker, so one
that survived is adopted rather than created a second time, and one that
only matches by name is reported for a person to look at rather than
touched. A provider that cannot be asked stops the run: recreating on an
unanswered question is how a duplicate tunnel gets made.

The credentials died with the host, so recovery asks for the Cloudflare API
token again, at a hidden prompt or from `GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN`,
and offers the Microsoft authentication choices described below. On a replacement
VM, use the installer app's client secret, device sign-in, or a supplied Graph
token for recovery. The old TPM signing key cannot work on the new VM. A credential
sealed to the old host's TPM cannot be decrypted on a replacement at all;
that is the point of the mode, and it is why the guide says to keep an
independent record of anything you cannot recreate.

The database is restored separately, with `guacdeploy restore`, once the
stack is running.

## Backup recovery key

**Setup offers this.** A guided run asks whether to enable scheduled
backups and, if you accept, generates the key and installs the schedule in
the same session — you do not have to run another command and start setup
again. It asks for the recording storage budget in the same run. Declining
either is a supported answer and leaves nothing installed; an unattended
run is never asked, and uses the flags instead.

Backups are encrypted with a key pair. `guacdeploy backup-key` generates
the pair in memory on the server. Only the public key is stored, in the
deployment record; scheduled backups need nothing else. The private key is
written once, as a passphrase-encrypted export with owner-only permissions:
`/var/lib/guacdeploy/recovery/backup-key.age`.

The command is guided only. It asks for the passphrase twice with hidden
input and rejects an empty one. Unattended runs stop with exit code 3. A
deployment record must exist first.

Copy the export to a workstation with the shown `scp` command and store it
away from the VM. Recovery needs both the file and the passphrase; keep
them in separate places. The tool never deletes the export; remove it from
the VM yourself once your copy is confirmed. The shown instructions do not
prove that a copy was made.

Run `guacdeploy backup-key --verify` to prove recovery: it decrypts the
export with your passphrase and checks that the result matches the
recorded public key.

## Database backup and restore

`guacdeploy backup` exports the database with PostgreSQL's `pg_dump`
through the running stack. It never copies the data directory. Before the
export, it writes a versioned snapshot of the deployment record into the
database, so the backup carries the ownership state. The deployment lock
is held for the whole run.

Backups are encrypted with the recorded backup public key. Run
`guacdeploy backup-key` once first. `--plaintext` writes an unencrypted
file; that is always an explicit choice.

The default destination is `/var/lib/guacdeploy/backups`. Pass `--dest
DIR` for another directory, such as a mounted share. That directory must
already exist. A missing directory or mount fails visibly; the tool never
redirects the backup to another place.

A backup is written as a hidden `.partial-` file first and published as
`guacdeploy-db-<timestamp>.sql.age` (or `.sql`) only after a complete
export. A failed run leaves only the `.partial-` file and never touches
earlier backups. On success the command prints the published path; on
failure it prints that the backup was not published.

Each backup gets a completion manifest beside it,
`<backup name>.manifest.json`. It records the format version, the
deployment ID, the file name, the byte length, and a SHA-256 of the
published file. It holds no secrets and no database content. Copy it with
the backup. The manifest is what lets the scheduled backup prove a file
is complete without the recovery key.

The manifest is written after the backup file, never before. If the host
stops between the two steps, the backup stays on the share and retention
preserves it, but does not count it.

`guacdeploy restore --file PATH` replaces the whole database with a
backup. It first validates the file completely: the completion manifest
when one is beside the file, then decryption, the format and Guacamole
version in the header, and the completion marker that proves the dump is
not truncated. A file that fails validation causes no database change. A
backup copied without its manifest still restores. For an encrypted
backup, the command asks for the recovery passphrase and decrypts the key
export at
`/var/lib/guacdeploy/recovery/backup-key.age`; `--identity-file PATH`
accepts a standard age identity file instead, for automation. Protect
such a file with owner-only permissions and remove it after use.

Restore replaces all current data and interrupts connected users. The
guided command shows what will be replaced and asks for consent.
Unattended restore requires `--yes`. Accept the downtime before you run
it, and restart the stack afterwards so Guacamole reconnects:
`docker compose --project-directory /opt/guacamole restart`.

The database dump can contain sensitive application data, such as saved
connection credentials. Treat plaintext backups accordingly.

## Scheduled backups

Setup installs a daily backup timer after the stack is running. Change
the schedule with `--backup-schedule`, how many successful backups to
keep with `--backup-keep` (seven by default), and where they go with
`--backup-dest`. Use `--require-mount` when the destination must sit on a
mounted share: a missing or replaced mount then fails visibly instead of
writing to local disk. `--no-backup-schedule` declines scheduling; manual
backups still work.

Scheduled backups encrypt with the recorded backup public key and never
need the recovery passphrase. If no key exists yet, setup does not
install the timer and says so, rather than installing one that would
write unencrypted backups. Generate a key with `guacdeploy backup-key`,
then run setup again.

The schedule is a systemd timer, `guacdeploy-backup.timer`, with a
service that runs `guacdeploy backup-run`. The service calls a copy of
the tool kept at `/usr/local/sbin/guacdeploy-runtime`, so you can delete
the binary you downloaded and the backup keeps running across reboots.
The timer is persistent: if the host is off at the scheduled time, the
backup runs at the next start. A failed backup never expires an earlier
good one.

`guacdeploy backup-status` shows the destination and the last result.
`guacdeploy backup-run` performs the scheduled backup immediately.

To examine the schedule:

```
systemctl list-timers guacdeploy-backup.timer
systemctl status guacdeploy-backup.service
journalctl -u guacdeploy-backup.service
```

## State

The deployment record lives in `/var/lib/guacdeploy/`. It never contains
credential values. Do not edit it by hand.

## Entra sign-in

Setup provisions the Entra application, service principal and the two
groups that carry sign-in, then restarts Guacamole with SAML enabled.

Guided setup asks for the Microsoft tenant ID or a verified domain. It then offers
an installer app with a certificate or client secret, device-code sign-in, or
Graph Explorer. The installer app path does not depend on Graph Explorer or device
codes. You supply the tenant ID and client ID. The installer obtains and renews
its own short-lived access tokens internally.

### Manually registered installer app

Use a dedicated app for provisioning. This is separate from the Guacamole SAML
app that setup creates. The installer does not claim ownership of your manually
registered app and does not delete it during teardown.

1. Open [Microsoft Entra admin center](https://entra.microsoft.com).
2. Select **App registrations > New registration**. Name it **Guacamole Installer**.
3. Select **Accounts in this organizational directory only**. Leave **Redirect URI**
   empty, then select **Register**.
4. Select **API permissions > Add a permission > Microsoft Graph > Application
   permissions**. Add `Application.ReadWrite.All`, `Group.ReadWrite.All`,
   `AppRoleAssignment.ReadWrite.All`, and `Organization.Read.All`.
5. Select **Grant admin consent** for your tenant. Use a Privileged Role Administrator
   or Global Administrator account. These permissions permit tenant-wide application,
   group, and app-role management; they are not limited to this deployment.
6. Complete one credential option below.
7. From **Overview**, enter **Directory (tenant) ID** and **Application (client) ID**
   into the installer. Do not use the app's Object ID.

An existing installer app can use the same procedure from step 4. The wizard keeps
each instruction on screen until you choose Continue. Microsoft documents the
[admin consent requirements](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent).

**Certificate option.** Choose **Installer app: generate a TPM certificate**.
The host needs an accessible TPM 2.0 resource-manager device, `/dev/tpmrm0`, with
empty owner authorization. The installer creates a non-exportable RSA signing key
inside that TPM. It does not install a TPM utility or export a plaintext private key.
It writes the public certificate to:

```text
/var/lib/guacdeploy/credentials/entra-installer.cer
```

Copy this public file to your workstation. For example, use your normal SSH login
and run this command on the workstation:

```sh
ssh rocky@YOUR-SERVER 'sudo cat /var/lib/guacdeploy/credentials/entra-installer.cer' > guacdeploy-installer.cer
```

If sudo requires a terminal for its password prompt, use `ssh -t` instead. This
copies the public certificate only. In the app registration, select **Certificates
& secrets > Certificates > Upload certificate**. Upload `guacdeploy-installer.cer`
and select **Add**. Check its thumbprint against the wizard.

The public certificate is valid for one year. Resume reuses it. The TPM-wrapped
key blob is `entra-installer.tpm`, under the same owner-only directory. A copied
disk cannot use the key on another TPM. Root on the running host can use it to sign;
a virtual TPM also trusts the hypervisor and its VM backups. This differs from the
general `tpm` credential mode, which decrypts software secrets into memory.

On a replacement VM, generate a new certificate during setup and upload it to the
same installer app. The previous key cannot migrate. Automatic certificate rotation
is not included. Use the client-secret option if the certificate expires or the TPM
is unavailable, then arrange certificate replacement. Ordinary teardown removes
the local certificate and wrapped key after Entra cleanup. Remove the unused
certificate registration from the installer app yourself.

Microsoft documents [certificate upload and authentication](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).

**Client-secret option.** Choose **Installer app: enter a client secret**. In Entra,
select **Certificates & secrets > Client secrets > New client secret**. Paste the
secret's **Value**, not its Secret ID, at the hidden prompt. The installer keeps
this value in memory for the current run. Store your own copy in your vault.
Subsequent setup, recovery, or teardown runs ask for it again.

Both options check authentication, available application-permission claims, and
the live tenant before any Entra change. Rejected credentials return to a retry
choice. Correct the app settings or IDs, then retry. Workload identity policies
still apply. This path changes the authentication method; it does not disable
customer policy. Opaque tokens do not expose permission claims, so a later
operation can still report a missing permission.

### Device-code sign-in

For device-code sign-in, setup shows a Microsoft sign-in URL and a short code.
Open the URL on your computer or phone,
enter the code, and sign in with an administrator account for that tenant.
Review and approve the requested permissions in Microsoft's browser flow.
Setup continues after sign-in. It does not require Azure CLI or PowerShell.

The default device-code application is Microsoft Graph Command Line Tools
(`14d82eec-204b-4c2f-b7e8-296a70dab67e`). Set the non-secret
`GUACDEPLOY_ENTRA_CLIENT_ID` to use your own public client with device-code
authentication enabled. `GUACDEPLOY_ENTRA_TENANT_ID` supplies a tenant without
the initial prompt. A recorded deployment tenant takes precedence on resume.

Sign-in requests Application.ReadWrite.All, Group.ReadWrite.All,
AppRoleAssignment.ReadWrite.All and Organization.Read.All. Access and refresh
tokens stay in process memory. Setup stores only the tenant identifiers.
If device-code sign-in fails, retry, select an installer app, use Graph Explorer,
or quit and retain progress.
Resume asks you to sign in again and refuses a different tenant before it makes
Entra changes. Tenant consent and sign-in policies still apply.

### Browser fallback when device codes are blocked

Choose **Browser: Graph Explorer, then paste an access token**. The wizard keeps
each instruction on screen until you choose Continue.

Graph Explorer provides the sign-in token. The installer makes the API calls.
You do not need to enter a query or select **Run query** in Graph Explorer.

1. Open [Microsoft Graph Explorer](https://developer.microsoft.com/graph/graph-explorer)
   on your computer. Sign in as an administrator and select the deployment's tenant.
2. Scroll to the top of Graph Explorer. Open your profile avatar at the top right.
   Choose **Consent to permissions**. Find each permission and choose **Consent**.
   Grant these delegated permissions: `Application.ReadWrite.All`, `Group.ReadWrite.All`,
   `AppRoleAssignment.ReadWrite.All`, and `Organization.Read.All`.
3. Open the **Access token** tab beside **Modify Permissions** and copy the token.
4. In the installer, choose Continue and paste the token at the hidden prompt.

This fallback requires one manual paste. It does not require an SSH tunnel,
local callback, Azure CLI, or an environment variable. The installer holds the token
in memory. It does not save the token in files, deployment state, or logs.

Before continuing, the installer checks application reads, available permission
claims, and the tenant's ID or verified domain through Microsoft Graph. A rejected
token returns to the hidden prompt. A token that will expire shortly requires a
fresh copy. Leave the prompt empty to stop and keep deployment progress.

Graph Explorer sign-in and consent must be allowed by the customer's policies.
Policies can also restrict use of its token from the server. This fallback does not
disable those policies. For opaque tokens, Graph does not expose permission claims
or expiry to the installer. A later rejection can require a fresh token on resume;
the installer does not replay a failed creation request automatically.

Microsoft documents [Graph Explorer consent and the Access token tab](https://learn.microsoft.com/en-us/graph/graph-explorer/graph-explorer-features).

If the permissions panel shows **Retry again** with no results, its permission
catalogue may be unavailable. Use the manually registered installer app path.

### Unattended sign-in

Unattended setup continues to accept a Microsoft Graph token through
`GUACDEPLOY_GRAPH_TOKEN`. An explicitly supplied token takes precedence over
the guided sign-in flow. Setup never writes the token to state or logs.

After a successful guided installer-app sign-in, state retains the authentication
method, tenant ID, and client ID. An unattended resume or teardown can reuse the
local TPM certificate. For the client-secret method, inject
`GUACDEPLOY_ENTRA_CLIENT_SECRET` into that process from your credential manager.
The installer does not save it. Do not put its value in a command line or env file.
Initial certificate generation and manual app preparation use the guided flow.

The flow uses Microsoft's [Azure Identity SDK](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#DeviceCodeCredential)
and [device authorization protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code).

Setup checks what the token can actually do before it creates anything.
It records what it intends to create before creating it. If a creation
request is sent and the answer is lost, the attempt is recorded as
uncertain and the next run searches by ownership marker before retrying,
so a second application is never created.

An application that already exists and does not carry this deployment's
marker is never changed without approval: setup shows each field with its
current and proposed value and asks. Unattended runs stop with exit
code 3. A name that matches without the marker is reported for review and
is never adopted.

Groups that already existed are reused and are never offered for removal
at teardown. Only the application, service principal and groups this
deployment created are recorded as its own.

## Cloudflare tunnel, DNS and Access

Setup finds the most specific visible Cloudflare zone for the hostname by querying
its parent names. This includes domains such as `demo-customer.com.au` and
delegated subdomains. Use `--zone` to select an exact zone name.
It checks the API token's read access before creating anything. The zone
itself is always pre-existing and is never removed by teardown.

The initial token check proves authentication and Zone Read access. The selected
zone checks cover DNS and Tunnel read access. Write permissions still need the
documented DNS, Tunnel and Access scopes; a read check cannot prove write access.
Cloudflare documents [account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/)
and the [zone list API](https://developers.cloudflare.com/api/resources/zones/methods/list/).

Three resources are created, one per phase, each recorded with ownership
evidence: a remotely managed tunnel whose name carries the deployment
identifier, a proxied CNAME whose record comment carries the same marker,
and a Cloudflare Access application in front of the hostname.

The tunnel reaches nginx with origin certificate verification enabled.
Until the origin certificate is issued, the public hostname returns a
Cloudflare origin-TLS error, because nginx still serves the temporary
self-signed certificate. Verification is never disabled to hide that.

The connector token is fetched when the stack starts and written to
`/run/guacdeploy/secrets/cloudflared/tunnel-token`, an owner-only file on
memory-backed storage that cloudflared reads for itself through
`TUNNEL_TOKEN_FILE`. It is never written to the deployment record, `.env`,
logs, command arguments, or the container's stored environment, so rotating
it in Cloudflare needs no local change.

A DNS record that already occupies the hostname without this
deployment's marker is never overwritten: setup stops and asks.
Unattended runs exit with code 3.

Access allows the Entra administrator and operator groups when an Access
identity provider is bound to the same tenant; otherwise it falls back to
`--access-emails`. It never publishes an application that allows
everyone. Once Access is on, the public hostname answers with the Access
challenge, so setup checks health against the local origin instead.

**The deployment is published last.** The tunnel is created early, but no
connector runs and no DNS record exists until sign-in is configured and
the Access policy is verified. If any earlier phase fails, the service
stays unreachable from the internet rather than reachable without
protection. The connector refuses to start at all unless a verified
Access application already covers the hostname.

## Origin certificate

Setup issues a Let's Encrypt certificate for the deployment hostname and
installs it for nginx before the stack starts, so the tunnel never has to
accept an unverified origin. Validation uses DNS-01 through Cloudflare,
because port 443 is reachable only through the tunnel, which refuses an
unverified origin. Challenge records are always removed afterwards,
including when issuance fails, and a record without this deployment's
marker is never deleted.

Renewal is installed as a systemd timer that runs daily and renews when
less than 30 days remain. It calls a copy of the tool kept under
`/usr/local/sbin/guacdeploy-runtime`, so renewal keeps working after the
downloaded binary is gone. A successful renewal reloads nginx, which
keeps established sessions alive. A failed renewal keeps the existing
certificate, reports the failure and exits nonzero; certificate
verification is never disabled to work around it.

`guacdeploy cert-status` shows the certificate and the last renewal
result. `guacdeploy renew-cert` renews immediately.

If the deployment uses prompt-mode credentials, setup does not install
the timer: a timer has no terminal to ask for a passphrase. Renew
manually, or deploy with the env or file credential mode.

## Session recordings

guacd writes session recordings into `/opt/guacamole/recordings`, which
setup creates and gives to the guacd container account before the
containers start. Without that step guacd cannot write and sessions would
run unrecorded without failing. The web application mounts the same
directory read-only, so it can play a recording back but can never alter
or delete session evidence.

Turn recording on for a connection with
`guacdeploy recordings-enable --connection NAME`.

A recording is complete only when no process still holds it open. An
active recording is never copied and never deleted.

`--recording-budget` sets the local storage budget, for example
`--recording-budget 20GiB`, and installs scheduled cleanup. Setup does
not invent a budget: without the flag no cleanup is installed and
recordings accumulate until the disk fills.

When usage exceeds the budget, cleanup deletes the oldest completed
recordings until usage is back within it. **Upload success is not a
condition for deletion**: the budget takes priority, so a recording with
no confirmed remote copy can be lost permanently. Every such deletion is
reported. Cleanup is not a hard quota — active recordings and the gap
between runs can take usage over the budget temporarily.

`guacdeploy recordings-status` shows the last backup and cleanup result.
`guacdeploy recordings-run` performs both immediately.
`guacdeploy recordings-restore` recovers one recording from a backup.

## Restoring changes to pre-existing settings

When setup changes a setting on a resource it did not create, it records
the original and the applied value before making the change.

`guacdeploy settings --list` shows what is pending and changes nothing.
Each entry is one of: restorable, drifted, unsupported, or unreadable.

`guacdeploy settings --restore` restores the originals, but only after
you approve each one and only when the current value still matches what
this deployment applied. A setting that has drifted since — someone else
changed it — is preserved exactly as it is, reported with both values,
and never overwritten. Unattended runs never restore; they stop with exit
code 3 and name what is waiting.

## Credential delivery to the containers, and reboots

Credentials reach the containers as files, not as environment variables.
Docker records a container's environment in its own metadata and keeps it
on disk, so an environment variable would leave a plaintext copy of the
database password and the tunnel token on the disk even when the
deployment's credential store is sealed to the TPM.

Each credential is written to an owner-only file on memory-backed storage
under `/run/guacdeploy/secrets`, and each service reads only its own file.
Nothing but the path appears in the compose file or in Docker's metadata.

Memory-backed storage is empty after a cold boot, so the stack cannot
simply restart itself. `guacdeploy stack-start` repopulates the files and
starts the stack, and the boot unit installed with a persistent
credential mode calls it. A deployment using prompt-mode credentials
cannot start unattended, and the command says so instead of waiting.

## Teardown

`guacdeploy teardown` shows every resource this deployment created, with
its dependencies, and removes them only after you approve. Unattended
runs need `--yes`, and anything ambiguous still stops.

Only resources this deployment created are ever offered. Each provider
re-checks its ownership marker at the moment of deletion, so a resource
that lost the marker, or never had it, is reported as retained rather
than removed — and the run is not reported as complete.

The order matters and is fixed: the boot unit stops first, so nothing can
restart the stack mid-teardown; then the connector, the DNS record, the
Access application and the tunnel; then the Entra application and groups;
then the host timers and the deployment-owned binary copy; then the
containers, their runtime credential files, and the rendered
configuration.

Changed pre-existing settings are restored first, because restoring a
field needs the object that carries it to still exist. A setting that has
drifted since is preserved and reported.

**Data, recordings and backups are kept.** Ordinary teardown never
deletes them, and neither remote backups nor the storage holding them are
touched. `--delete-data` removes them, and only after the plan has shown
exactly what would go.

Anything that could not be removed is listed at the end and stays in the
record, so a later run can try again. Teardown is never reported complete
while residue remains.

## Azure Blob as a backup destination

Azure Blob is an optional destination alongside a local directory and an
existing mounted share. The deployment can reuse storage you already have
or create it, and scheduled uploads authenticate as a service principal
so they do not depend on your interactive session.

`guacdeploy azure-upload --dest DIR` copies the published backups and the
completed recordings from that local directory to the configured
container. It reports the database and the recordings separately, and it
never counts a partial upload as complete: a copy is only complete once
its length and hash have been read back and its completion manifest
written.

`guacdeploy azure-status` shows the configured destination and the last
upload result.

Two separate retention rules apply in Azure, and they never reach each
other's objects.

- **Recordings are expired by age**, when a retention period is
  configured. Without one, nothing is expired.
- **Database backups keep the last seven successful backups**, or the
  number in `azure-backup-retention-count`. Only a backup whose copy in
  the container is verified complete counts towards the seven, so seven
  failed uploads cannot push seven good backups out of retention, and an
  object that cannot be checked is neither counted nor removed. There is
  no setting for "keep every backup for ever".

An object is removed only when the ownership marker read back from the
service proves it is this deployment's. Ordinary teardown removes nothing
from Azure and never deletes a container or a storage account.

**Choosing the destination during setup.** `guacdeploy setup --azure` offers
it: you sign in with a device code, pick a subscription, then select an
existing storage account and container or ask for new ones with
`--azure-create --azure-location <region>`. `--azure-subscription`,
`--azure-account` and `--azure-container` answer those questions ahead of
time. Nothing is created before the intent is written to the deployment
record, and no destination is recorded until a real write has proved that
blob data access works — a granted role takes minutes to take effect, and
the run waits for it rather than assuming.

Without any of those flags the phase does nothing: a deployment with no
Azure account is the ordinary case.

**Not proven against real Azure.** Every Azure path in this tool is tested
against a fake identity platform and a fake management plane. No device
code has been entered by a person, no real subscription listed, no storage
account created, and no role assignment watched taking effect.
