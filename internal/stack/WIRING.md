# Credential delivery into the containers

This slice closes acceptance criterion 2 of issue #5: "prove actual container credential
delivery without unapproved persistent plaintext copies".

## The gap

`stack.override()` handed the database password and the Cloudflare tunnel token to the
containers as **environment fields**, through an in-memory Compose override. Docker records
a container's environment in its own metadata, at
`/var/lib/docker/containers/<id>/config.v2.json`, and keeps it for the life of the
container. So a plaintext copy of both credentials landed on persistent disk **even when
the deployment's own credential store was sealed to the TPM**, and the services carry
`restart: always`, so Docker re-read that copy on every boot. Nothing in this repository
managed, encrypted, or removed it.

The credential store was doing its job. The last hop was undoing it.

## What each pinned image supports

None of the three images needs an environment variable. Every one of them can read the
credential from a file.

| Image | Mechanism | Evidence |
|---|---|---|
| `postgres:18-alpine` | `POSTGRES_PASSWORD_FILE` | `docker-entrypoint.sh` defines `file_env()` and `docker_setup_env()` calls `file_env 'POSTGRES_PASSWORD'`. The image sets no `USER`, and `docker_setup_env` runs before `exec gosu postgres`, so the file is read as root. `file_env` uses `$(< file)`, which strips trailing newlines. |
| `guacamole/guacamole:1.6.0` | `POSTGRESQL_PASSWORD_FILE` | The image `Dockerfile` at tag 1.6.0 sets `ENV ENABLE_FILE_ENVIRONMENT_PROPERTIES=true` and `USER guacamole` (uid/gid 1001). `GuacamoleServletContextListener` at the same tag registers `SystemFileEnvironmentGuacamoleProperties` when that property is true, and that source resolves any property from `$<PROPERTY>_FILE`. It reads the file with `Files.asCharSource(...).read()`, **verbatim**, so the file must carry no trailing newline. |
| `cloudflare/cloudflared:latest` | `TUNNEL_TOKEN_FILE` | `cmd/cloudflared/tunnel/subcommands.go` defines `--token-file` with `EnvVars: []string{"TUNNEL_TOKEN_FILE"}`, and `runCommand` reads it with `os.ReadFile` plus `strings.TrimSpace`. Added 2025-04-01, so present in every release since 2025.4. The image is distroless and runs as `USER 65532:65532`. |

The `guacamole-docker` README at 1.6.0 documents `POSTGRESQL_PASSWORD_FILE`, but the 1.6.0
container entrypoint does **not** set `enable-file-environment-properties` itself — that
landed after 1.6.0, in GUACAMOLE-2119. The image Dockerfile's `ENV` is what makes it work
at 1.6.0. The rendered compose file sets `ENABLE_FILE_ENVIRONMENT_PROPERTIES: "true"`
explicitly anyway, because if it were ever false the web application would silently ignore
`POSTGRESQL_PASSWORD_FILE`, the postgresql extension would fail to load, and Guacamole
would keep serving pages while every sign-in failed.

## What replaced it

`stack.Up` writes each credential to an owner-only file on memory-backed storage before it
starts the stack, and the compose file names those files. See `internal/stack/secrets.go`.

```
/run/guacdeploy/secrets            0711 root       (traversable: the container accounts
  postgres/                        0700 uid 0       need to reach their own directory,
    postgres-password              0600 uid 0       and nothing may list this one)
  guacamole/                       0700 uid 1001
    postgresql-password            0600 uid 1001
  cloudflared/                     0700 uid 65532
    tunnel-token                   0600 uid 65532
```

Each directory is bind-mounted read-only into its own service at `/run/secrets`. Only the
path appears in the compose file and in Docker's metadata. The uid is the account the
pinned image runs as; a future image that changes its user fails loudly, because the
container cannot read its own file and exits.

Three consequences worth knowing:

- **The Compose override is gone.** `override()` was deleted and `composeArgs` no longer
  passes `-f -`, so nothing travels to docker on stdin either. `Up` and `Containers` keep
  their signatures; `Containers` no longer reads its `password` and `tunnelToken`
  arguments.
- **The postgres health check reads the file.** It could not keep using
  `$POSTGRES_PASSWORD`: the entrypoint exports that inside its own process tree, and the
  container environment no longer carries it.
- **The files are not removed after start.** postgres and cloudflared re-read them every
  time a container restarts, so removing them would break the restart policy. A cold boot
  empties the tmpfs instead.

## Lifecycle

**Cold boot.** `/run` is tmpfs, so the files are gone. Docker starts before anything else
and restarts the containers itself, because of `restart: always`, against bind-mount
sources it creates as empty root-owned directories. postgres and cloudflared then exit and
retry; Guacamole is the dangerous one, because it keeps serving pages with its postgresql
extension unloaded. The `guacdeploy-stack.service` unit that `creds.InstallBoot` already
installs runs `guacdeploy stack-start`, which calls `stack.Up`: `Up` sees that it had to
**create** the files rather than rewrite them, takes the directories back to the right
owner and mode, and adds `--force-recreate` so every container is replaced against the now
populated mounts. Compose would otherwise see no configuration change and leave them
running and broken. On a first install there is nothing to recreate and the flag does
nothing.

So the boot unit is no longer a convenience. Without it, a rebooted host comes up with no
credentials. `creds.InstallBoot` refuses `prompt` and `env` mode for exactly that reason,
and that refusal is now load-bearing.

**`docker compose up` recreate.** The mounts are directories at stable paths, so a
recreated container re-reads the same files. `Up` rewrites the contents on every call.

**Teardown.** Call `stack.RemoveRuntimeSecrets(cfg)` after the containers are gone. A cold
boot would clear the tmpfs anyway, but a host that is torn down and left running should not
keep the credentials in memory until someone reboots it.

## Checking delivery, without printing a credential

`stack.CheckDelivery(ctx, run, cfg, password, tunnelToken)` is the specification's "check
container delivery and reboot behaviour for each persistent mode" step. It:

1. searches the rendered `compose.yaml` and `.env` for each credential value;
2. reads Docker's stored container metadata back through `docker inspect` — the same
   `Config.Env` Docker keeps in `config.v2.json` — and searches that;
3. checks that each runtime file holds the value, is mode 0600, and is on a memory-backed
   filesystem.

A finding names the credential and where it was found. It never contains the value, and a
test fails if it ever does.

**Wiring it in (the parent's call).** One line in `internal/session`, after `stackUp` has
run and reported healthy containers:

```go
if err := stack.CheckDelivery(ctx, o.stackRun(), cfg, password, token); err != nil {
        return err
}
```

`stackUp` already holds `password` and `token` from `o.stackSecrets(st, u)`, so nothing new
has to be fetched. Add it as its own phase if you want it in the journal.

**Running it live, by hand.** This prints variable *names* only, never values, so it is
safe in a transcript:

```
sudo docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' guacamole-postgres-1 | cut -d= -f1
sudo docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' guacamole-guacamole-1 | cut -d= -f1
sudo docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' guacamole-cloudflared-1 | cut -d= -f1
```

Expect `POSTGRES_PASSWORD_FILE`, `POSTGRESQL_PASSWORD_FILE` and `TUNNEL_TOKEN_FILE`, and no
`POSTGRES_PASSWORD`, `POSTGRESQL_PASSWORD` or `TUNNEL_TOKEN`. Then confirm the storage:

```
sudo findmnt -no FSTYPE /run/guacdeploy/secrets     # tmpfs
sudo ls -ln /run/guacdeploy/secrets/*/              # 0600, owned by 0, 1001 and 65532
```

Reboot the host and repeat both. The files must reappear and the stack must answer.

## What the parent still has to change

1. **`internal/session/session_test.go` is already changed here**, and it is the one file
   in a package I was told not to touch. `TestStackPhasesFullPipelineUnattended` asserted
   that the escaped password reaches docker on stdin, which is precisely the behaviour this
   slice removes; the assertion now checks the opposite — that no credential reaches stdin
   or argv. Nothing in `session.go` was touched, and no signature changed.
2. **`internal/cloudflare`** still describes the old mechanism: `cloudflare.go` lines 87 and
   376 and `internal/cloudflare/WIRING.md` line 107 all say the token is delivered "through
   the in-memory Compose override as `TUNNEL_TOKEN`". Only the comments are wrong; the code
   is correct. `TunnelToken` returns the value in memory and `stack.Up` takes it from there.
3. **`stack-start`** still does not exist. `internal/creds/WIRING.md` section 5 has the
   fifteen lines; it now matters more than it did, because it is what repopulates the tmpfs
   after a reboot.
4. **Teardown** should call `stack.RemoveRuntimeSecrets(cfg)`.

## Residual exposure, stated plainly

- **No image requires an environment variable.** All three read a file. Nothing secret
  remains in Docker's stored container metadata.
- **The postgres container's own process environment holds the password at runtime.**
  `file_env` exports `POSTGRES_PASSWORD` inside the container before it starts PostgreSQL,
  so it is visible in `/proc/<pid>/environ` to root on the host for as long as the container
  runs. That is process memory, not disk, and it does not survive a restart of the
  container. The same is true of any password a process is given by any means.
- **PostgreSQL stores its own verifier for the password** in the data directory, which is
  persistent. It is a SCRAM-SHA-256 verifier, not the password, and it predates this slice.
- **`/run` is assumed to be tmpfs and the assumption is checked.** `writeRuntimeSecrets`
  reads `/proc/mounts` and refuses to write anywhere that is not `tmpfs` or `ramfs`. A host
  that mounted `/run` differently fails with a named error instead of quietly turning every
  credential mode into the plaintext file mode.
- **An unprivileged run uses a different directory.** Only root can create a directory under
  `/run`, and only root can deploy, so a non-root run — development and the test suite —
  gets `$XDG_RUNTIME_DIR`, `/dev/shm`, or the temporary directory, in that order. The
  memory-backed check applies to whichever is chosen. This has no effect on a deployment
  host, where the tool always runs as root.
- **`cloudflare/cloudflared` is pinned to `latest`, a moving tag.** `--token-file` has been
  there since April 2025, and the container's uid is checked only implicitly: if a future
  image runs as a different account it cannot read its own token file and exits with
  "Failed to read token file". That is a loud failure, not a silent one, but it is a
  failure waiting on a tag nobody controls. Pinning the image is a separate decision.

## Tests

`go test ./internal/stack/` covers: the rendered compose carries no credential as an
environment field and wires up all three file mechanisms; `Up` writes the files verbatim
with no trailing newline, mode 0600, in 0700 directories under a 0711 root; `Up` repairs
directories Docker created for itself on a cold boot; the cold boot recreates the containers
and a warm start does not; an empty tunnel token writes no file; `CheckDelivery` accepts a
clean stack and reports a credential in Docker's metadata, a credential in the rendered
compose file, an undelivered credential, and a world-readable runtime file, without ever
printing a value; the mount-point resolution behind the memory-backed check.

Ten mutations of the load-bearing logic were each checked to turn a test red: reinstating
`POSTGRES_PASSWORD` as an environment field, appending a newline to the credential file,
writing it mode 0644, dropping `--force-recreate`, skipping the Docker metadata scan,
putting the value into a finding, matching mount points without a path boundary, writing an
empty tunnel token, and omitting either directory-mode repair.

**No test has started a container.** Live verification on the Rocky Linux test platform is
outstanding: a real `docker compose up` with all three images, the `docker inspect` check
above, a reboot with the boot unit in place, and a reboot with the boot unit deliberately
disabled to confirm the failure is visible rather than silent.
