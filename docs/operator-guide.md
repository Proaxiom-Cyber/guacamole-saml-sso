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

If Docker or the Compose plugin is missing, setup shows the installation
plan (Docker's RHEL repository via dnf, then enable and start the docker
service) and asks before installing. Unattended runs need
`--install-dependencies`. Installed packages and the service enablement
are recorded as changes made by this deployment. Docker that was already
present is pre-existing and is never offered for removal at teardown.

## The Guacamole stack

Setup renders the container configuration under `/opt/guacamole` and starts
four containers: guacd, PostgreSQL, the Guacamole web application, and
nginx. The database schema is generated from the pinned Guacamole image and
validated before use. nginx serves HTTPS with a temporary self-signed
certificate until the origin certificate is issued. Setup checks container
health and then checks that Guacamole answers through nginx.

Unattended runs supply `--hostname`, `--admin-group`, and
`--operator-group`. The database password travels to Compose through an
in-memory override, never through a rendered file or a command argument.
Containers restart automatically with Docker after a reboot. The database
data directory is recorded as data to preserve: ordinary teardown keeps it,
and only an explicit deletion request removes it.

## Credentials

Setup asks how the deployment receives credentials and shows the choice:

- **prompt** — hidden interactive prompts at the moment of use. Nothing is
  stored on disk. This mode cannot support unattended operation.
- **env** — `GUACDEPLOY_CRED_*` environment variables supplied to each
  invocation. Unattended operation works when the caller injects them.
- **file** — owner-only plaintext files under the state directory's
  `credentials/` folder. This is an approved exception for this project
  and is never chosen silently: selecting it requires explicit approval
  (guided confirmation or the explicit `--credentials file` flag).

Unattended runs select the mode with `--credentials prompt|env|file`.
Setup checks that required credentials are available and names exactly
what to supply when one is missing. Credential values never appear in
deployment state, logs, or command arguments. Files written by the tool
are recorded as material owned by this deployment, so teardown can offer
their removal; files you placed yourself are pre-existing and stay.

## Backup recovery key

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

Setup can install a daily backup. It keeps the last seven successful
backups. Both the schedule and the retention count are configurable.

The schedule is a systemd timer, `guacdeploy-backup.timer`, and a service,
`guacdeploy-backup.service`. The service runs `guacdeploy backup-run`.

The scheduled backup does not need the binary you downloaded to install
the deployment. Setup copies that binary to
`/usr/local/lib/guacdeploy/guacdeploy` and the service calls the copy. You
can delete the binary you downloaded. The backup continues to run after a
reboot.

A scheduled backup uses the backup public key only. It never needs the
recovery passphrase.

The timer is persistent. If the host is off at the scheduled time, the
backup runs at the next start.

Use these commands to examine the schedule:

```
systemctl list-timers guacdeploy-backup.timer
systemctl status guacdeploy-backup.service
journalctl -u guacdeploy-backup.service
```

### Retention

Retention runs only after a backup is published. A failed backup deletes
nothing. Earlier successful backups always stay.

Retention counts only complete backups of this deployment. For each file
it reads the completion manifest, then measures and re-hashes the file
against it. A truncated, damaged, or replaced file does not match and is
not counted. This needs no recovery key, so the scheduled backup can
check an encrypted file it cannot decrypt.

Retention deletes only files that pass this check, with their manifests.
Everything else stays: a `.partial-` file from a failed export, a backup
that another deployment wrote into the same share, a backup with no
manifest, and any unrelated file.

Retention keeps the newest backups by the time in the name. Where two
backups share a timestamp, the one with the higher `-N` suffix is the
newer, because the tool only uses `-2` after `-1` is taken.

Retention always keeps at least one backup. A retention count of zero is
refused.

### Results of the last run

```
guacdeploy backup-status
```

This shows the destination, the schedule, the retention count, the time
and result of the last run, the published file or the reason for the
failure, how many backups are held, and which files retention removed.
It reads `/var/lib/guacdeploy/backup-status.json`, which contains no
credentials.

### Destinations on a mounted share

Give `--dest` a directory on the share. The directory must exist. It can
be the mount point or any subfolder inside it, such as
`/mnt/backups/guacamole`.

Add `--require-mount` for a destination on a share. The first checked run
approves what it finds: it records the mount point the destination sits
inside, in `/var/lib/guacdeploy/backup-mount.json`, and writes a marker
file, `.guacdeploy-backup-mount`, on the share. The record and the marker
hold no secrets. A destination on the same filesystem as
`/var/lib/guacdeploy` is refused, because that is local storage, not a
share.

Every later run compares against the record. The run fails, and exports
nothing, when the destination is no longer inside the approved mount, or
when the marker on the share is missing or different. Both mean the
expected share is not mounted. Without this option, a directory that
exists but holds no mount accepts the backup into local storage, which
fills the system disk and gives no warning.

To approve a replacement share, delete
`/var/lib/guacdeploy/backup-mount.json`. The next run records the new
share.

The tool publishes a backup with a hard link where the filesystem
supports one. Many SMB/CIFS shares do not. On those it reserves the
published name, then copies the file into it. Both ways refuse to
overwrite an existing backup, and both keep the `.partial-` export if
publication fails.

## State

The deployment record lives in `/var/lib/guacdeploy/`. It never contains
credential values. Do not edit it by hand.
