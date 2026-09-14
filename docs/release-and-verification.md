# Release and verification

This document describes how guacdeploy releases are built, signed, and verified.
The rule is simple: the launcher refuses to install any binary that fails checksum
or signature verification.

With terminal input and output, the launcher starts the setup wizard after installation.
It uses `sudo` for a normal login. Use `--install-only` to return to the shell instead.
Without a terminal, the launcher installs the binary and prints the next command.

## How a release is cut

Tags with a prerelease suffix, such as `v1.0.0-rc.1`, publish a GitHub prerelease.
They do not replace the latest stable release. To test one, download its launcher
from `/releases/download/<tag>/get-guacdeploy.sh` and pass the same tag to the script.
The verification checks are the same for stable releases and prereleases.

Push a version tag, for example `v1.0.0`, to `Proaxiom-Cyber/guacamole-saml-sso`.
The `release` workflow (`.github/workflows/release.yml`) then:

1. Runs `go vet ./...` and `go test ./...`. A failure stops the release.
2. Builds `guacdeploy_linux_amd64` with `CGO_ENABLED=0`, `-trimpath`, and the tag
   stamped into `guacdeploy version`.
3. Writes `SHA256SUMS` for the binary and the launcher script.
4. Signs `SHA256SUMS` with Sigstore keyless signing (`cosign sign-blob`), using the
   workflow's GitHub Actions OIDC identity. The signature bundle is
   `SHA256SUMS.sigstore.json`.
5. Publishes a GitHub Release with the binary, `SHA256SUMS`, the signature bundle,
   and `get-guacdeploy.sh`.

No signing key exists to store or to leak. The signing certificate is issued to the
workflow identity at build time and expires minutes later. The signature stays valid
because the bundle proves the signing time.

## Publisher identity binding

The launcher accepts a signature only when the certificate inside the bundle matches
both of:

| Field | Required value |
|---|---|
| Certificate identity | `https://github.com/Proaxiom-Cyber/guacamole-saml-sso/.github/workflows/release.yml@refs/tags/v...` |
| Certificate OIDC issuer | `https://token.actions.githubusercontent.com` |

This binds every release to one repository, one workflow file, and a version tag.
A signature from any other repository, workflow, person, or key fails verification,
even when the signature itself is cryptographically valid.

Why `cosign sign-blob` instead of GitHub artifact attestations: verifying an
attestation needs the `gh` CLI, and `gh attestation verify` needs a GitHub API
token. A fresh Rocky Linux server has neither, and a deployment tool must not
require a GitHub account. Cosign is one static binary and verifies without any
account or token.

## Trust bootstrap

Verification cannot verify its own starting point. The first run trusts exactly
three things. Check them once, then every later download is verified.

1. **TLS to github.com** delivers the launcher script itself. Fetch it from the
   repository or a release page and read it before you run it.
2. **The cosign pin inside the launcher.** If no `cosign` is on `PATH`, the launcher
   downloads cosign 3.1.3 and compares it to a SHA-256 digest recorded in the
   launcher. Cross-check that digest against the checksum file that the sigstore
   project publishes with the cosign release. If your host already has an approved
   cosign on `PATH`, the launcher uses it and downloads nothing.
3. **The Sigstore trust root.** Cosign ships with an embedded TUF root and updates
   it from the Sigstore CDN. This is how it validates the certificate chain.

## Launcher destination allowlist

The launcher and its verifier connect only to these destinations. All connections
are outbound HTTPS on TCP 443. The launcher runs at install time only; it has no
runtime destinations. `curl` honours the standard proxy variables, and the launcher
does not disable certificate checks.

| Host | Purpose |
|---|---|
| `github.com` | Resolve the latest release tag; start asset downloads |
| `objects.githubusercontent.com` | GitHub release asset storage (redirect target) |
| `release-assets.githubusercontent.com` | GitHub release asset storage (redirect target) |
| `tuf-repo-cdn.sigstore.dev` | Sigstore TUF trust root updates for cosign |

## Hardened hosts

The tool cannot approve its own execution. On a host with application allowlisting
(for example `fapolicyd` on Rocky Linux), an administrator must permit
`/usr/local/bin/guacdeploy`, and the cosign verifier if it is kept, before they can
run. Do this through your normal change process, outside the tool.

Keep SELinux enforcing. The launcher runs `restorecon` on the installed binary so it
gets the correct file context. Do not disable SELinux or certificate checks to make
installation work; a failure there is a signal, not an obstacle.

## Verify by hand

The launcher does all of this for you. To check a release independently:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp \
    '^https://github\.com/Proaxiom-Cyber/guacamole-saml-sso/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## Test status

`tests/launcher_test.sh` exercises the launcher against a local fixture: an altered
binary, a missing signature bundle, a corrupt bundle, and a bundle signed by a
different identity are all rejected, and nothing is installed. The end-to-end proof
against a real published release (acceptance A15) needs the first version tag push
and is still open.
