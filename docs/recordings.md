# Session recordings

Guacamole records a session as a file. `guacd` writes the file while the session runs and
closes it when the session ends. The recordings live on the deployment host, are copied
to the backup destination when they are complete, and are deleted when the local
directory goes over its storage budget.

This page tells an operator how to turn recording on, how to get a recording back, and
what the storage budget does and does not promise.

## Where recordings are

| Place | Path |
|---|---|
| On the host | `/opt/guacamole/recordings` |
| Inside guacd (read and write) | `/recordings` |
| Inside the web application (read only) | `/recordings` |
| Backup copies | `<backup destination>/recordings` |

The directory on the host belongs to the `guacd` container account (uid 1000) and has
mode 0755. `guacd` must be able to write into it. The installation directory above it is
mode 0750, so no other account on the host can read the recordings.

## Turn recording on

Connections are created by an operator in the web interface, and recording is a
connection setting stored in the database. Run this after you add a connection:

```bash
sudo guacdeploy recordings-enable
```

That turns recording on for **every** connection. For one connection:

```bash
sudo guacdeploy recordings-enable --connection "Build server"
```

It sets three connection parameters and nothing else:

| Parameter | Value | Why |
|---|---|---|
| `recording-path` | `/recordings` | Where guacd writes. This is guacd's own path, not a host path. |
| `recording-name` | `${HISTORY_UUID}` | Names the file after the session history entry, so a recording can be matched back to the session that made it. |
| `create-recording-path` | `true` | Lets guacd create the directory if it is missing. |

It never reads or writes a password or a private key. Connections still hold no target
credential: Guacamole asks the person for one at connect time.

**Run `recordings-enable` again after you add each new connection.** A connection created
in the web interface has no recording parameters until you do.

## Active, completed, failed and backed up

These four states are different things, and the tool keeps them apart.

| State | What it means | How the tool decides |
|---|---|---|
| **Active** | The session is still running and guacd is still writing the file. | Some process on this host holds the file open. |
| **Completed** | The session ended and the file is final. | No process holds the file open. |
| **Failed** | A copy to the backup destination did not finish. | The copy is reported in `Copy failed:` and nothing is published under its name. |
| **Backed up** | A copy exists in the destination and matches its completion record. | The copy re-hashes and length-checks against its `.manifest.json` sidecar. |

An active recording is **never** copied and **never** deleted. Only a completed recording
can be backed up, and only a completed recording can be deleted for the budget.

The open-file test is why the tool does not guess from timestamps. A person can leave a
session connected and idle for an hour. Nothing is written in that hour, so a
"has not changed recently" rule would call the recording finished, copy half of it, and
then delete it while the session was still going.

## Retrieve a recording

A completed recording on the host is already a playable file. Copy it off with `scp`.

A backed-up copy is encrypted by default, so it needs to be written back out first:

```bash
sudo guacdeploy recordings-restore --file /mnt/backups/recordings/<uuid>.guac.age
```

It checks the completion record before it writes anything, so a truncated copy, a copy
that does not match its record, or a copy belonging to another deployment is refused. It
never overwrites an existing output file. It asks for the backup recovery passphrase; use
`--identity-file` for an unattended run.

Play the result with the Apache Guacamole session recording player, or convert it with
`guacenc`, which ships in the guacd image:

```bash
docker compose exec guacd guacenc /recordings/<uuid>
```

An operator can also play a recording back from the session history in the web interface,
because the web application is given the same directory read-only.

## The local storage budget

Setup asks how much local disk session recordings may use. A scheduled job checks that
budget, by default every hour. It runs from a systemd timer and needs no downloaded
provisioning binary: setup installs its own copy at
`/usr/local/sbin/guacdeploy-runtime`, which the unit calls.

```
guacdeploy-recordings.timer     when to run
guacdeploy-recordings.service   what to run
```

Each run does two things, in this order:

1. Copy every completed recording that is not already in the backup destination.
2. Delete the oldest completed recordings until local usage is back within budget.

### What the budget promises, and what it does not

**A failed copy does not stop a deletion.** The budget takes priority over keeping an
unbacked recording. If the destination is not mounted, or a copy fails, the oldest
completed recordings are still deleted when the directory is over budget.

Every deletion of a recording with no confirmed backup copy is reported:

```
LOST:                 3f2a... was deleted to stay within the storage budget and has no
                      confirmed backup copy; it cannot be recovered
```

Act on that line. It means a recording is gone for good. The usual causes are a
destination share that is not mounted and a budget that is too small for the volume of
sessions.

**Scheduled cleanup is not a hard filesystem quota.** Three things can put the directory
over the budget:

- Active recordings are never deleted, and they still take space. Enough concurrent
  sessions can hold the directory over the budget on their own.
- The directory grows between runs. The budget is checked on the timer, not on every
  write.
- If every remaining recording is active, cleanup stops. That is not a failure, and the
  run still reports success.

Size the disk with room above the budget. The budget limits what is kept, not what can
be written.

## Check the last run

```bash
sudo guacdeploy recordings-status
```

It shows the recordings directory, the destination, the budget and current usage, the
last run and its result, how many recordings were copied, how many are still recording,
any failed copy, how many were deleted, and any loss.

Database backup results are reported separately, by `guacdeploy backup-status`. A
successful database backup says nothing about recordings, and the reverse is also true.

## When something is wrong

**No recordings appear at all.** Check that the connection has the recording parameters
(`recordings-enable`), and that `/opt/guacamole/recordings` is owned by uid 1000:

```bash
ls -ld /opt/guacamole/recordings
sudo guacdeploy recordings-enable
```

A root-owned directory is the usual cause. guacd cannot write into it, and the session
still works, so nothing tells you until you look for the file.

**A recording never becomes complete.** A file held open by a crashed or wedged guacd
stays active for ever, so it is never copied and never deleted. Restart guacd:

```bash
cd /opt/guacamole && docker compose restart guacd
```

**The run fails with "there is no way to tell which recordings are still being written".**
The job could not read `/proc`. It refuses to guess, so it backs nothing up and deletes
nothing. Run it as root.

**A copy has no completion record.** A copy whose `.manifest.json` could not be written is
kept but never counted as a backup, and the recording is copied again under the next free
name. Remove the unverifiable copy by hand once you have a good one.
