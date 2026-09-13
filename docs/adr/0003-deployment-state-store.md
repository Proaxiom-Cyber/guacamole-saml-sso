# Store deployment state in one locked JSON file under /var/lib/guacdeploy

Local state is authoritative and lives outside any repository, in
`/var/lib/guacdeploy/state.json` (override: `GUACDEPLOY_STATE_DIR`, used by
tests). The format is versioned JSON with a `schema_version` field. One
deployment per host means one file; no database is needed.

Writes go to a temporary file in the same directory, then fsync and rename,
so an interruption leaves the old or the new record, never a partial one.
A `lock` file with an exclusive non-blocking `flock` allows one mutating
operation at a time; the kernel releases the lock on any process exit,
including a crash. Read-only display bypasses the lock.

Credential values never enter this state. The schema has no secret fields;
a test guards the wire format against credential field names. The state
records intent before actions and checked results after them, with a
correlation identifier per attempt. Pending work is judged by the latest
attempt per intent, so the journal keeps failed and interrupted attempts as
history.
