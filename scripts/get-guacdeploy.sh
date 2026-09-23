#!/bin/sh
# get-guacdeploy.sh - download, verify, and install the guacdeploy binary.
#
# The script downloads a released guacdeploy binary for Linux x86_64, checks
# its SHA-256 checksum, and checks the Sigstore signature on the checksum
# file. The signature must come from this repository's release workflow,
# signed through GitHub Actions OIDC. The script refuses to install anything
# that fails either check. See docs/release-and-verification.md.
#
# Usage: sh get-guacdeploy.sh [--install-only] [version]
#   version   Release tag, for example v1.0.0. Default: the latest release.
#   --install-only   Install without starting the guided wizard.
# A terminal run starts the wizard after verification and installation.
# Without terminal input and output, the launcher only installs the binary.
#
# Environment:
#   GUACDEPLOY_BASE_URL     Download base for a mirror or a test fixture.
#                           Default: https://github.com/Proaxiom-Cyber/guacamole-saml-sso
#                           Verification runs the same for every source.
#   GUACDEPLOY_INSTALL_DIR  Install destination. Default: /usr/local/bin
#
# Requirements: curl, sha256sum (or shasum), and outbound HTTPS to the
# destinations listed in docs/release-and-verification.md. No Go toolchain.

set -eu

REPO_URL="${GUACDEPLOY_BASE_URL:-https://github.com/Proaxiom-Cyber/guacamole-saml-sso}"
INSTALL_DIR="${GUACDEPLOY_INSTALL_DIR:-/usr/local/bin}"
ASSET="guacdeploy_linux_amd64"

# The verifier is cosign, pinned by version and SHA-256. This pin is the
# initial trust anchor: cross-check it against
# https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt
COSIGN_VERSION="v3.1.3"
COSIGN_SHA256="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"

# Only this publisher identity may sign a release: this repository's release
# workflow, running for a version tag, authenticated by GitHub Actions OIDC.
CERT_IDENTITY_RE='^https://github\.com/Proaxiom-Cyber/guacamole-saml-sso/\.github/workflows/release\.yml@refs/tags/v'
CERT_ISSUER="https://token.actions.githubusercontent.com"

die() { echo "get-guacdeploy: ERROR: $*" >&2; exit 1; }

version=latest
version_set=0
install_only=0
for arg do
  case "$arg" in
    --install-only) install_only=1 ;;
    latest|v[0-9]*)
      [ "$version_set" -eq 0 ] || die "specify only one release tag"
      version="$arg"
      version_set=1
      ;;
    *) die "usage: sh get-guacdeploy.sh [--install-only] [version]" ;;
  esac
done

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
  else shasum -a 256 "$1"; fi | awk '{print $1}'
}

fetch() { curl -fsSL --retry 2 -o "$2" "$1"; }

[ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ] ||
  die "unsupported platform $(uname -s)/$(uname -m); guacdeploy V1 supports Linux x86_64 only"

command -v curl >/dev/null 2>&1 || die "curl is required"

tmp=$(mktemp -d) || die "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT

# Resolve "latest" to a concrete tag through the release redirect.
if [ "$version" = "latest" ]; then
  effective=$(curl -fsSLI --retry 2 -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest") ||
    die "cannot resolve the latest release from $REPO_URL"
  version="${effective##*/}"
  case "$version" in
    v[0-9]*) ;;
    *) die "cannot parse a release tag from $effective" ;;
  esac
fi

dl="$REPO_URL/releases/download/$version"
echo "get-guacdeploy: downloading guacdeploy $version"
fetch "$dl/$ASSET" "$tmp/$ASSET" || die "download failed: $dl/$ASSET"
fetch "$dl/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $dl/SHA256SUMS"
fetch "$dl/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json" ||
  die "signature bundle missing: $dl/SHA256SUMS.sigstore.json. Refusing to install an unsigned release."

# Check 1: the binary must match the released checksum file.
want=$(awk -v f="$ASSET" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || die "SHA256SUMS has no entry for $ASSET"
got=$(sha256_of "$tmp/$ASSET")
[ "$got" = "$want" ] ||
  die "checksum mismatch for $ASSET: the downloaded file does not match SHA256SUMS. Refusing to install."

# Check 2: the checksum file must carry a valid Sigstore signature from the
# approved publisher identity. Use cosign from PATH if the administrator has
# an approved copy; otherwise download the pinned verifier and check its
# digest before running it.
if command -v cosign >/dev/null 2>&1; then
  COSIGN=cosign
else
  echo "get-guacdeploy: downloading pinned verifier cosign $COSIGN_VERSION"
  fetch "$COSIGN_URL" "$tmp/cosign" || die "download failed: $COSIGN_URL"
  got=$(sha256_of "$tmp/cosign")
  [ "$got" = "$COSIGN_SHA256" ] ||
    die "the downloaded cosign does not match the pinned SHA-256. Refusing to use it."
  chmod 0755 "$tmp/cosign"
  COSIGN="$tmp/cosign"
fi

"$COSIGN" verify-blob \
  --bundle "$tmp/SHA256SUMS.sigstore.json" \
  --certificate-identity-regexp "$CERT_IDENTITY_RE" \
  --certificate-oidc-issuer "$CERT_ISSUER" \
  "$tmp/SHA256SUMS" >/dev/null ||
  die "Sigstore verification failed: SHA256SUMS is not signed by the approved release workflow of Proaxiom-Cyber/guacamole-saml-sso. Refusing to install."

use_sudo=0
if [ "$INSTALL_DIR" = /usr/local/bin ] && [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 ||
    die "sudo is required to install to $INSTALL_DIR. Run as root, or set GUACDEPLOY_INSTALL_DIR."
  echo "get-guacdeploy: using sudo to install the verified binary to $INSTALL_DIR"
  use_sudo=1
fi

install_command() {
  if [ "$use_sudo" -eq 1 ]; then sudo -- "$@"
  else "$@"; fi
}

install_command mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR"
install_command install -m 0755 "$tmp/$ASSET" "$INSTALL_DIR/guacdeploy" ||
  die "cannot install to $INSTALL_DIR. Run as root, or set GUACDEPLOY_INSTALL_DIR."
if command -v restorecon >/dev/null 2>&1; then
  install_command restorecon "$INSTALL_DIR/guacdeploy" || true
fi

echo "get-guacdeploy: verified and installed guacdeploy $version to $INSTALL_DIR/guacdeploy"
if [ "$install_only" -eq 1 ] || [ ! -t 0 ] || [ ! -t 1 ]; then
  echo "get-guacdeploy: next step: run '$INSTALL_DIR/guacdeploy' as root"
  exit 0
fi

echo "get-guacdeploy: opening the deployment menu"
# exec preserves the terminal and the wizard's exit status. Remove downloads
# first: replacing this shell does not run its EXIT trap.
rm -rf "$tmp"
trap - EXIT
if [ "$(id -u)" -eq 0 ]; then
  exec "$INSTALL_DIR/guacdeploy"
fi
command -v sudo >/dev/null 2>&1 || die "sudo is required to start the setup wizard"
exec sudo -- "$INSTALL_DIR/guacdeploy"
