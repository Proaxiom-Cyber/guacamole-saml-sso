#!/bin/bash
# launcher_test.sh - exercises scripts/get-guacdeploy.sh against a local
# file:// release fixture. No network access is needed.
#
# Test doubles, declared here and nowhere in production code:
#   - uname shim: reports Linux/x86_64 so the launcher runs on a dev Mac.
#   - cosign shim: stands in for Sigstore verification, because a bundle
#     signed by the real release workflow cannot exist until the first tag
#     push (acceptance A15). The shim asserts the launcher passes the
#     identity-binding flags, then accepts or rejects per COSIGN_SHIM_MODE.
#   - Real-cosign cases: if a real cosign binary is on PATH or named by
#     COSIGN_BIN, two extra cases run real verification with the production
#     flags: a corrupt bundle and a bundle signed by a different, keyed,
#     non-approved identity. Both must be rejected.
#
# Usage: bash tests/launcher_test.sh

set -u

here=$(cd "$(dirname "$0")" && pwd)
launcher="$here/../scripts/get-guacdeploy.sh"
tag="v9.9.9-test"
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- fixture release tree, served over file:// ---
rel="$tmp/root/releases/download/$tag"
mkdir -p "$rel" "$tmp/bin" "$tmp/shim"
printf 'fake guacdeploy binary contents\n' > "$rel/guacdeploy_linux_amd64"
(cd "$rel" && shasum -a 256 guacdeploy_linux_amd64 | awk '{print $1 "  guacdeploy_linux_amd64"}' > SHA256SUMS)
printf '{"not":"a real sigstore bundle"}\n' > "$rel/SHA256SUMS.sigstore.json"

# --- shims ---
cat > "$tmp/shim/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in -s) echo Linux ;; -m) echo x86_64 ;; *) exec /usr/bin/uname "$@" ;; esac
EOF
cat > "$tmp/shim/cosign" <<'EOF'
#!/bin/sh
# Test shim for tests/launcher_test.sh. Never installed anywhere.
[ "${1:-}" = "verify-blob" ] || { echo "cosign shim: unexpected subcommand: ${1:-}" >&2; exit 2; }
case "$*" in
  *--bundle*--certificate-identity-regexp*--certificate-oidc-issuer\ https://token.actions.githubusercontent.com*) ;;
  *) echo "cosign shim: launcher did not pass the identity-binding flags: $*" >&2; exit 2 ;;
esac
if [ "${COSIGN_SHIM_MODE:-pass}" = "pass" ]; then exit 0; fi
echo "cosign shim: signature rejected (simulated wrong identity / bad signature)" >&2
exit 1
EOF
chmod +x "$tmp/shim/uname" "$tmp/shim/cosign"

run_launcher() { # run_launcher <install-subdir> [env VAR=... pairs]
  local dest="$tmp/$1"; shift
  mkdir -p "$dest"
  env "$@" PATH="$tmp/shim:$PATH" \
    GUACDEPLOY_BASE_URL="file://$tmp/root" \
    GUACDEPLOY_INSTALL_DIR="$dest" \
    sh "$launcher" "$tag" >"$tmp/out" 2>&1
}

check() { # check <name> <expected: ok|reject> <rc> <install-subdir> [required-message]
  local name=$1 expected=$2 rc=$3 dest="$tmp/$4" msg=${5:-}
  local verdict="PASS"
  if [ "$expected" = ok ]; then
    [ "$rc" -eq 0 ] || verdict="FAIL (exit $rc)"
    [ -x "$dest/guacdeploy" ] || verdict="FAIL (not installed)"
    cmp -s "$dest/guacdeploy" "$rel/guacdeploy_linux_amd64" || verdict="FAIL (installed bytes differ)"
  else
    [ "$rc" -ne 0 ] || verdict="FAIL (accepted, exit 0)"
    [ ! -e "$dest/guacdeploy" ] || verdict="FAIL (installed despite rejection)"
    if [ -n "$msg" ] && ! grep -q "$msg" "$tmp/out"; then verdict="FAIL (message '$msg' missing)"; fi
  fi
  [ "$verdict" = PASS ] || { fails=$((fails + 1)); sed 's/^/    | /' "$tmp/out"; }
  echo "$verdict: $name"
}

# 1. Intact release, verifier accepts -> installed.
run_launcher bin1; check "intact release installs" ok $? bin1

# A normal login uses sudo only for the final installation. The shim redirects
# the default destination into the fixture; this test never writes to the host.
mkdir -p "$tmp/elevate"
cat > "$tmp/elevate/id" <<'EOF'
#!/bin/sh
echo 1000
EOF
cat > "$tmp/elevate/install" <<'EOF'
#!/bin/sh
for arg do destination=$arg; done
[ "$destination" != /usr/local/bin/guacdeploy ] || exit 92
exec /usr/bin/install "$@"
EOF
cat > "$tmp/elevate/sudo" <<'EOF'
#!/bin/sh
[ "$1" = -- ] || exit 90
shift
case "$1" in
  mkdir) mkdir -p "$SUDO_TEST_DEST" ;;
  install) install -m 0755 "$4" "$SUDO_TEST_DEST/guacdeploy" ;;
  restorecon) exit 0 ;;
  *) exit 91 ;;
esac
EOF
chmod +x "$tmp/elevate/id" "$tmp/elevate/install" "$tmp/elevate/sudo"
env PATH="$tmp/elevate:$tmp/shim:$PATH" \
  SUDO_TEST_DEST="$tmp/bin-sudo" \
  GUACDEPLOY_BASE_URL="file://$tmp/root" \
  GUACDEPLOY_INSTALL_DIR=/usr/local/bin \
  sh "$launcher" "$tag" >"$tmp/out" 2>&1
check "normal login installs through sudo" ok $? bin-sudo

# 2. Altered artifact -> checksum reject, nothing installed.
printf 'tampered bytes\n' >> "$rel/guacdeploy_linux_amd64"
run_launcher bin2; check "altered artifact rejected" reject $? bin2 "checksum mismatch"
# restore the fixture binary to match SHA256SUMS again
printf 'fake guacdeploy binary contents\n' > "$rel/guacdeploy_linux_amd64"

# 3. Missing signature bundle -> reject before any verification.
mv "$rel/SHA256SUMS.sigstore.json" "$tmp/bundle.saved"
run_launcher bin3; check "missing signature bundle rejected" reject $? bin3 "signature bundle missing"
mv "$tmp/bundle.saved" "$rel/SHA256SUMS.sigstore.json"

# 4. Verifier rejects (bad signature or another identity) -> nothing installed.
run_launcher bin4 COSIGN_SHIM_MODE=fail
check "signature rejected by verifier" reject $? bin4 "Sigstore verification failed"

# 5+6. Real cosign, production flags, offline reject paths.
real_cosign="${COSIGN_BIN:-$(command -v cosign || true)}"
if [ -n "$real_cosign" ]; then
  cp "$real_cosign" "$tmp/shim/cosign" # replace the shim with the real verifier

  # 5. Corrupt bundle -> real cosign rejects.
  run_launcher bin5; check "real cosign rejects corrupt bundle" reject $? bin5 "Sigstore verification failed"

  # 6. Bundle validly signed by a different, keyed, non-approved identity.
  (cd "$tmp" && COSIGN_PASSWORD='' "$real_cosign" generate-key-pair >/dev/null 2>&1 &&
    "$real_cosign" signing-config create --out empty-sc.json >/dev/null 2>&1 &&
    COSIGN_PASSWORD='' "$real_cosign" sign-blob --yes --signing-config empty-sc.json \
      --key cosign.key --bundle "$rel/SHA256SUMS.sigstore.json" \
      "$rel/SHA256SUMS" >/dev/null 2>&1)
  if [ -s "$rel/SHA256SUMS.sigstore.json" ] && grep -q messageSignature "$rel/SHA256SUMS.sigstore.json"; then
    run_launcher bin6; check "real cosign rejects another identity" reject $? bin6 "Sigstore verification failed"
  else
    echo "SKIP: real cosign could not produce a keyed bundle offline"
  fi
else
  echo "SKIP: no real cosign binary found (set COSIGN_BIN); shim covered the reject path"
fi

[ "$fails" -eq 0 ] && echo "launcher_test: all checks passed" || echo "launcher_test: $fails check(s) FAILED"
exit "$((fails > 0))"
