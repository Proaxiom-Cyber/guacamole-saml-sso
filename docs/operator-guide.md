# Operator guide

This guide grows with each delivered slice. It currently covers the
deployment session commands. The full terminal experience and the complete
guide arrive with the final wizard work.

## Commands

| Command | Purpose |
|---|---|
| `guacdeploy` or `guacdeploy setup` | Start a fresh deployment, or resume or clean up an interrupted one |
| `guacdeploy setup --non-interactive` | Unattended setup. Never waits for input |
| `guacdeploy setup --non-interactive --resume` | Unattended consent to continue interrupted work |
| `guacdeploy setup --non-interactive --install-dependencies` | Unattended consent to install missing dependencies |
| `guacdeploy status` | Show the deployment record without changing anything |
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

## State

The deployment record lives in `/var/lib/guacdeploy/`. It never contains
credential values. Do not edit it by hand.
