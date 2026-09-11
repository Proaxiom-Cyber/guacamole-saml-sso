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

## State

The deployment record lives in `/var/lib/guacdeploy/`. It never contains
credential values. Do not edit it by hand.
