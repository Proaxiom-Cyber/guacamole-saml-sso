# Wiring internal/certs into the session

This slice issues and renews the **origin** certificate: the Let's Encrypt certificate
nginx serves on 443, proved by an ACME DNS-01 challenge in Cloudflare DNS. Cloudflare
keeps managing the separate browser-facing certificate at the edge; nothing here touches
it.

New files:

| File | What it holds |
|---|---|
| `internal/certs/certs.go` | `Issue`, `Inspect`, the ACME flow, file installation |
| `internal/certs/renew.go` | `Renew`, `Verify`, `Status`, `Report`, the nginx reload |
| `internal/certs/install.go` | `Install` / `Uninstall` of the systemd timer and service |
| `internal/cloudflare/dns_challenge.go` | `DNS01`: the challenge record, its wait, its cleanup |
| `cmd/guacdeploy/renewcert.go` | `renewCertCmd`, `certStatusCmd` |

Nothing under `internal/session`, `internal/stack`, `internal/host`, `internal/creds`,
`internal/backup`, `internal/schedule`, `internal/entra`, or `cmd/guacdeploy/main.go`
was modified. `internal/cloudflare/cloudflare.go` was not modified either — the
challenge solver is a new type in a new file in that package, reusing the existing
client, marker and `DeleteRecord`.

`go.mod` moved `golang.org/x/crypto` from indirect to direct. No new dependency was
added and `go.sum` is unchanged.

## The one line main.go needs

```go
case "renew-cert":
        err = renewCertCmd(ctx, *stateDir, u)
case "cert-status":
        err = certStatusCmd(*stateDir, u)
```

No new flags. `--state-dir` already exists, and both functions live in
`cmd/guacdeploy/renewcert.go`. The existing exit-code mapping needs no change:
`renewCertCmd` returns a plain error, so a failed renewal exits 1.

Usage text:

```
  renew-cert   Renew the origin certificate if it is near expiry (the timer calls this)
  cert-status  Show the origin certificate and the last renewal result
```

## Phase placement

One new phase, `origin-certificate`, in specification step 7 ("Configure services,
certificate renewal, and selected backup scheduling"). It must run:

- **after** `cloudflare-select` — it needs `cloudflare-zone-id` and
  `cloudflare-account-id`;
- **after** `stack-render` — it replaces the temporary self-signed certificate that
  `stack.Render` wrote into `nginx/certs/`;
- **before** the final health check, and before any check of the public hostname,
  because until this phase succeeds cloudflared refuses the origin and the public
  hostname returns an origin-TLS error.

```go
p := &cloudflare.Provisioner{Client: cf, AccountID: st.Config["cloudflare-account-id"],
        ZoneID: st.Config["cloudflare-zone-id"], Hostname: st.Config["guac-hostname"],
        DeploymentID: st.DeploymentID}

o := certs.Options{
        Hostname:     st.Config["guac-hostname"],
        InstallDir:   installDir,
        StateDir:     stateDir,
        DirectoryURL: st.Config["acme-directory-url"], // "" means production
        Contact:      st.Config["acme-contact"],       // optional "mailto:…"
        DNS:          &cloudflare.DNS01{P: p},
        Run:          certs.ExecRunner,
        VerifyAddr:   "127.0.0.1:" + httpsPort,
}
s, err := certs.Renew(ctx, o)   // issues on the first run; skips a fresh certificate
u.Say("%s", s.Summary())
```

`Renew` is the right call for setup as well as for the timer. On a first run there is
only the self-signed placeholder, so it issues; on a resumed or repeated setup with a
good certificate it reports `skipped` and touches nothing. That makes the phase
idempotent for free.

Then prove the result, which is acceptance criterion A12's first half:

```go
if err := certs.Verify(ctx, o); err != nil {
        // The origin certificate is not one cloudflared will accept.
}
```

`Verify` dials nginx on this host with the deployment hostname as the server name and
**certificate verification enabled** — the same check cloudflared makes, because the
tunnel ingress sets `noTLSVerify=false`. It is not `stack.Probe`, which skips
verification on purpose for the local liveness check. Do not swap one for the other.

Install the timer in the same phase:

```go
in, err := certs.Install(ctx, certs.InstallOptions{
        Run: certs.ExecRunner, DeploymentID: st.DeploymentID,
        StateDir: stateDir, OnCalendar: st.Config["cert-schedule"], // "" means daily
})
```

`UnitDir`, `RuntimeDir` and `Exe` stay zero in real runs; tests inject them.

## State keys

Non-secret references only.

| Key | Value | Written by |
|---|---|---|
| `acme-directory-url` | CA directory; empty or absent means Let's Encrypt production | setup (only when staging is chosen) |
| `acme-contact` | optional `mailto:` address for CA expiry warnings | setup |
| `acme-account-url` | the ACME account this deployment owns | `renewCertCmd`, after a successful renewal |
| `cert-schedule` | the `OnCalendar` expression actually installed | setup, from `Installed.OnCalendar` |

The ACME **account key** is a file, `<state-dir>/acme-account.key` (0600), not a state
value. State holds the account URL only.

## Created resources

```go
now := time.Now().UTC()
st.EnsureResource(state.Resource{Provider: "letsencrypt", Type: "certificate",
        Name: s.Subject, CorrelationID: corrID,
        Ownership: "issued by this deployment through ACME DNS-01; expires " + s.NotAfter.Format(time.RFC3339),
        CreatedAt: now})
for _, r := range []struct{ typ, name string }{
        {"systemd-timer", in.TimerPath},
        {"systemd-service", in.ServicePath},
} {
        st.EnsureResource(state.Resource{Provider: "host", Type: r.typ, Name: r.name,
                CorrelationID: corrID,
                Ownership: "file written by this deployment, first line marks deployment ID",
                CreatedAt: now})
}
```

Record the expiry in `Ownership` (or re-record the resource on each renewal if the
schema later grows a field for it). The runtime binary copy is **not** recorded here:
`internal/schedule` already records `/usr/local/sbin/guacdeploy-runtime` as a created
resource, and there is only one copy.

## Teardown

```go
removed, err := certs.Uninstall(ctx, certs.InstallOptions{
        Run: certs.ExecRunner, DeploymentID: st.DeploymentID})
```

It disables and stops the renewal timer and removes the two units, marker-checked
exactly as `internal/schedule` does: a same-named unit written by anything else is left
in place and named in the returned error. A non-nil error with a non-empty `removed`
means some units went and others were left — report both.

`certs.Uninstall` deliberately does **not** remove the runtime binary copy. The backup
timer calls the same copy, and `schedule.Uninstall` removes it. Order teardown so
`schedule.Uninstall` runs at or after `certs.Uninstall`.

Nothing revokes the certificate and nothing deletes its files. A certificate is not a
cloud resource that costs anything or blocks anything, the private key stays on a host
that is being destroyed, and revoking one an administrator may still want during a
rebuild is not this tool's call. The challenge records are already gone: `DNS01.CleanUp`
runs on every issuance path.

## Decisions worth knowing

**ACME library: `golang.org/x/crypto/acme`.** It was already in the module graph as an
indirect dependency, and the whole flow is ~120 lines against it. `lego` would add a
large dependency tree (and its own DNS-provider registry, DNS resolver and storage
model) to reach the same three API calls. `certbot` would add a Python runtime to a
single-binary tool.

**DNS-01, not HTTP-01 or TLS-ALPN-01.** Port 443 on the origin is reachable only
through the tunnel, which will not pass a challenge to an origin whose certificate it
refuses — the chicken-and-egg this slice exists to break. DNS-01 needs no inbound
reachability at all, and the Cloudflare token the deployment already holds can write the
record.

**Staging vs production.** Production (`certs.ProductionDirectory`) is the default,
because a staging certificate is untrusted and cloudflared would refuse the origin, so a
deployment issued against staging is a broken deployment. `certs.StagingDirectory` is
one recorded state value away (`acme-directory-url`) for rehearsals on the test
platform, where the point is to exercise the flow repeatedly without spending the
production "5 certificates per exact hostname per week" limit. A staging run leaves
`Verify` failing, correctly.

**`nginx -s reload`, not a container restart.** nginx starts new workers and lets the
old ones finish, so established Guacamole sessions — long-lived WebSocket tunnels —
survive the renewal; a restart drops every one of them. The command is
`docker compose --project-directory … exec -T nginx nginx -s reload`, the same shape
`internal/backup` already uses to reach into a running container. It needs no in-memory
secret override, which matters because the renewal unit deliberately holds no database
password.

**One ACME account, reused.** The account key is generated in memory on first issuance
and written to `<state-dir>/acme-account.key` with owner-only permissions. Without it,
every renewal would register a new ACME account and the recorded `acme-account-url`
would be stale the moment it was written.

**The unit carries only `--state-dir`.** Hostname, installation directory, CA directory
and credential mode all come from the deployment record, which is authoritative and
which an operator can change without rewriting a unit file. Same reasoning as
`backupRunCmd` taking the deployment ID from the record.

**Credential mode decides whether renewal can run unattended.** `renewCertCmd` resolves
the Cloudflare API token through `creds.Manager` in the recorded mode. File mode works
unattended. Env mode works only if something injects
`GUACDEPLOY_CRED_CLOUDFLARE_API_TOKEN` into the unit's environment. **Prompt mode cannot
work at all** — an installed timer has no terminal — and `renewCertCmd` says so and
fails rather than hanging. Setup should warn when it installs the renewal timer for a
prompt-mode deployment; the specification already makes this point
("A prompt-only mode cannot provide unattended reboot recovery by itself").

## Behaviour the parent must not undo

- **Failure never disables TLS verification.** No code in this slice writes
  `noTLSVerify` or sets `InsecureSkipVerify`. A failed renewal keeps the installed
  certificate, records the failure, and exits nonzero. The worst case is an expired
  origin certificate and a visibly broken hostname — never a silently unverified one.
  Do not "fix" a failing `Verify` by turning verification off anywhere.
- **Nothing is written until the CA returns a complete chain.** `Issue` generates the
  certificate key, builds the CSR and only then writes, key first, each through a
  temporary file and a rename. That is what makes "a failed renewal leaves the existing
  certificate untouched" true rather than hoped for.
- **The challenge record is always removed.** `solveDNS01` defers cleanup *before* the
  record is created, so a failed creation, a failed visibility wait, a rejected
  challenge and a cancelled context all clean up, and cleanup runs on a context derived
  with `context.WithoutCancel`. A stale `_acme-challenge` record is not litter: it is a
  standing authorisation to issue a certificate for this hostname.
- **Cleanup never touches an unmarked record.** `DNS01.CleanUp` lists the TXT records at
  `_acme-challenge.<hostname>`, skips any whose comment is not
  `guacdeploy:<deployment-id>`, and deletes the rest through the existing
  `DeleteRecord`, which re-fetches and refuses with `ErrNotOwned` if the marker is gone.
  Another ACME client's record at the same name is left in place — DNS-01 accepts the
  hostname when any TXT record matches, so it neither blocks this deployment nor becomes
  ours.
- **Key material never leaves the package.** Not in `Issued`, not in `Status`, not in
  `state.json`, not in an error, not in a log line.
  `TestIssuedValuesHoldNoKeyMaterial` fails if that changes.
- **`Verify` is not `stack.Probe`.** `stack.Probe` skips verification deliberately, for
  a local liveness check. `Verify` must keep it on.

## Status output

`session.Status` should append:

```go
u.Say("%s", certs.Report(stateDir, installDir, st.Config["guac-hostname"]))
```

`Report` reads `<state-dir>/cert-status.json` (0600) and the certificate file itself, so
it works before renewal has ever run. It prints the subject, issuer, expiry and days
remaining, the last renewal time and result, and — when the placeholder is still there —
that this is the temporary self-signed certificate the tunnel will refuse. The header
line names which certificate this is, so an operator reading it does not confuse the
origin certificate with Cloudflare's edge certificate.

The record holds paths, certificate details and error text only. No credential and no
key material passes through it.

## Known limits

- One hostname per deployment, so one authorization per order. Wildcards are not V1.
- The visibility wait uses this host's resolver (`net.DefaultResolver.LookupTXT`), not
  the zone's authoritative nameservers. On a host behind a resolver that will not see
  the new record, issuance fails at the wait rather than at the CA. Failing there is the
  safe direction: an attempted validation the CA rejects counts against Let's Encrypt's
  failed-validation rate limit, and an unattempted one does not.
- `DNS01.CleanUp` reads the first 50 records at the challenge name. More than 50 TXT
  records at `_acme-challenge.<hostname>` is not a case this handles.
- Renewal is not rate-limit aware. A hostname that keeps failing will retry daily. Let's
  Encrypt's failed-validation limit is per hostname per hour, so a daily retry cannot
  reach it, but a repeatedly *succeeding* renewal loop (a broken clock, say) could reach
  the 5-per-week duplicate-certificate limit. The 30-day window makes that unreachable
  in practice.
- Live issuance against a real zone is not covered by these tests. Everything here runs
  against injected seams — a faked `acme.Client` and a fake Cloudflare API — so the
  logic is proven and the integration is not. That is what the Rocky test platform run
  is for.
