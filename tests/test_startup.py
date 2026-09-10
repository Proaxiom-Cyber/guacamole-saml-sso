"""Offline checks: fake credentials, mocked services, and no Docker daemon calls."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'fixture-only: spaces "quotes" \\ $dollar ${NOT_A_VARIABLE} $$'
TOKEN = 'fixture-only-tunnel-$value'


class StartupTests(unittest.TestCase):
    def run_shell(self, body, *, password=None, stdin="", **extra_env):
        # Do not inherit credentials, shell startup files, or Docker connection settings.
        env = {
            "PATH": os.environ["PATH"],
            "TASK_ROOT": str(ROOT),
            "GUAC_HOSTNAME": "guacamole.example.test",
            **extra_env,
        }
        if password is not None:
            env["POSTGRES_PASSWORD"] = password
        return subprocess.run(
            ["bash", "-c", """
set -euo pipefail
source "$TASK_ROOT/lib/startup.sh"
note() { :; }
ok() { printf '%s\n' "$1"; }
die() { printf '%s\n' "$1" >&2; exit 1; }
env_get() {
  case "$1" in
    POSTGRES_PASSWORD_CMD) printf '%s' "${FIXTURE_PASSWORD_CMD:-}" ;;
    COMPOSE_PROFILES) printf '%s' "${FIXTURE_PROFILES:-}" ;;
    HTTPS_PORT) printf '%s' "${FIXTURE_PORT:-443}" ;;
  esac
}
""" + body],
            cwd=ROOT,
            env=env,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_credentials_hidden(self, result):
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_reuses_supplied_password(self):
        result = self.run_shell(
            'get_database_password; [[ "$DB_PASSWORD" == "$POSTGRES_PASSWORD" ]]',
            password=PASSWORD,
        )
        self.assert_success(result)
        self.assert_credentials_hidden(result)

    def test_secret_command_from_configuration(self):
        result = self.run_shell('''
fixture_password() { printf '%s' "$FIXTURE_PASSWORD"; }
get_database_password
[[ "$DB_PASSWORD" == "$FIXTURE_PASSWORD" ]]
''', FIXTURE_PASSWORD_CMD="fixture_password", FIXTURE_PASSWORD=PASSWORD)
        self.assert_success(result)
        self.assert_credentials_hidden(result)

    def test_failed_secret_command_does_not_fall_back_to_new_password(self):
        result = self.run_shell('''
fixture_password() { printf '%s' "$FIXTURE_PASSWORD" >&2; return 1; }
get_database_password
''', FIXTURE_PASSWORD_CMD="fixture_password", FIXTURE_PASSWORD=PASSWORD)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("password command failed", result.stderr)
        self.assert_credentials_hidden(result)

    def test_empty_secret_command_is_rejected(self):
        result = self.run_shell('''
fixture_password() { :; }
get_database_password
''', FIXTURE_PASSWORD_CMD="fixture_password")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("password is empty", result.stderr)

    def test_masked_prompt_preserves_password(self):
        result = self.run_shell('''
get_database_password
[[ "$DB_PASSWORD" == "$FIXTURE_PASSWORD" ]]
''', stdin=PASSWORD + "\n" + PASSWORD + "\n", FIXTURE_PASSWORD=PASSWORD)
        self.assert_success(result)
        self.assert_credentials_hidden(result)

    def test_prompt_rejects_mismatched_confirmation(self):
        result = self.run_shell(
            'get_database_password', stdin=PASSWORD + "\ndifferent-fixture\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not match", result.stderr)
        self.assert_credentials_hidden(result)

    def test_missing_password_stops(self):
        result = self.run_shell('get_database_password')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Supply a database password", result.stderr)

    def test_compose_receives_credentials_only_on_stdin(self):
        result = self.run_shell('''
DB_PASSWORD="$POSTGRES_PASSWORD"
TUNNEL_TOKEN_OUT="$FIXTURE_TOKEN"
docker() {
  [[ "$*" == 'compose --env-file .env -f docker-compose.yaml -f - up --detach --wait --wait-timeout 180' ]]
  python3 -c '
import json, os, sys
data = json.load(sys.stdin)["services"]
password = os.environ["POSTGRES_PASSWORD"].replace("$", "$$")
token = os.environ["FIXTURE_TOKEN"].replace("$", "$$")
assert data["postgres"]["environment"]["POSTGRES_PASSWORD"] == password
assert data["guacamole"]["environment"]["POSTGRESQL_PASSWORD"] == password
assert data["cloudflared"]["environment"]["TUNNEL_TOKEN"] == token
'
}
runtime_compose up --detach --wait --wait-timeout 180
''', password=PASSWORD, FIXTURE_TOKEN=TOKEN, FIXTURE_PROFILES="cloudflare")
        self.assert_success(result)
        self.assert_credentials_hidden(result)

    def test_cloudflare_profile_requires_tunnel_token(self):
        result = self.run_shell('''
DB_PASSWORD="$POSTGRES_PASSWORD"
docker() { exit 99; }
runtime_compose up
''', password=PASSWORD, FIXTURE_PROFILES="cloudflare")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not return a tunnel token", result.stderr)

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is not installed")
    def test_compose_interpolation_preserves_credentials_in_both_profiles(self):
        # `config` parses files locally. It does not call the Docker daemon.
        with tempfile.TemporaryDirectory(prefix="guac-compose-check-") as config_dir:
            for profile in ("", "cloudflare"):
                with self.subTest(profile=profile):
                    result = self.run_shell('''
DB_PASSWORD="$POSTGRES_PASSWORD"
TUNNEL_TOKEN_OUT="$FIXTURE_TOKEN"
docker() {
  shift
  shift 2
  command docker compose --env-file "$TASK_ROOT/.env.example" "$@"
}
runtime_compose config --format json
''', password=PASSWORD, FIXTURE_TOKEN=TOKEN if profile else "",
                        FIXTURE_PROFILES=profile, DOCKER_CONFIG=config_dir,
                        SAML_IDP_METADATA_URL="https://idp.example.test/metadata")
                    self.assert_success(result)
                    services = json.loads(result.stdout)["services"]
                    # Compose's config renderer doubles literal dollars for reuse
                    # as a Compose file. Undo that output escaping for comparison.
                    for service, key in (("postgres", "POSTGRES_PASSWORD"),
                                         ("guacamole", "POSTGRESQL_PASSWORD")):
                        self.assertEqual(
                            services[service]["environment"][key].replace("$$", "$"),
                            PASSWORD,
                        )
                    self.assertEqual(
                        services["guacamole"]["depends_on"]["postgres"]["condition"],
                        "service_healthy",
                    )
                    self.assertIn("--host=127.0.0.1",
                                  services["postgres"]["healthcheck"]["test"][1])
                    if profile:
                        self.assertEqual(
                            services["cloudflared"]["environment"]["TUNNEL_TOKEN"]
                            .replace("$$", "$"), TOKEN,
                        )
                        self.assertEqual(
                            services["cloudflared"]["healthcheck"]["test"][-1], "ready"
                        )
                    else:
                        self.assertNotIn("cloudflared", services)

    def test_start_waits_before_showing_status(self):
        result = self.run_shell('''
runtime_compose() { printf 'compose %s\n' "$*"; }
wait_for_guacamole() { printf 'web responds\n'; }
start_stack
''')
        self.assert_success(result)
        self.assertEqual(result.stdout.splitlines(), [
            "compose up --detach --wait --wait-timeout 180",
            "web responds",
            "compose ps",
            "services started; Guacamole responds through nginx",
        ])

    def test_failed_health_check_stops_before_web_check(self):
        result = self.run_shell('''
runtime_compose() { return 1; }
wait_for_guacamole() { printf 'unexpected-web-check\n'; }
start_stack
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not become healthy", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_failed_web_check_does_not_report_success(self):
        result = self.run_shell('''
runtime_compose() { :; }
wait_for_guacamole() { return 1; }
start_stack
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not respond through nginx", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_web_check_uses_local_nginx_and_configured_port(self):
        result = self.run_shell('''
curl() {
  [[ "$*" == *'--noproxy *'* ]]
  [[ "$*" == *'--resolve guacamole.example.test:8443:127.0.0.1'* ]]
  [[ "${@: -1}" == 'https://guacamole.example.test:8443/guacamole/' ]]
  printf '302'
}
wait_for_guacamole
''', FIXTURE_PORT="8443")
        self.assert_success(result)

    def test_web_check_rejects_proxy_errors(self):
        result = self.run_shell('''
curl() { printf '502'; }
sleep() { SECONDS=$((SECONDS + 121)); }
wait_for_guacamole
''')
        self.assertNotEqual(result.returncode, 0)

    def test_web_check_reports_progress_while_nginx_is_unavailable(self):
        result = self.run_shell('''
note() { printf '%s\\n' "$1"; }
curl() { printf '000'; }
sleep() { SECONDS=$((SECONDS + 30)); }
wait_for_guacamole
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Checking https://guacamole.example.test:443/guacamole/", result.stdout)
        self.assertIn("up to 120 seconds", result.stdout)
        self.assertIn("Still waiting", result.stdout)
        self.assertIn("HTTP 000", result.stdout)


if __name__ == "__main__":
    unittest.main()
