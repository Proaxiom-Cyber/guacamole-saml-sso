#!/usr/bin/env python3
"""Exercise the real launcher in a terminal with a local release fixture."""

import errno
import hashlib
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time
import unittest


LAUNCHER = Path(__file__).resolve().parents[1] / "scripts/get-guacdeploy.sh"


class LauncherTerminalTests(unittest.TestCase):
    def run_launcher(self, *, terminal=True, uid=1000, install_only=False,
                     wizard_status=0, verify_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release/releases/download/v9.9.9-test"
            shim = root / "shim"
            staging = root / "staging"
            destination = root / "installed"
            for path in (release, shim, staging):
                path.mkdir(parents=True)

            def executable(path, content):
                path.write_text(content)
                path.chmod(0o755)

            binary = release / "guacdeploy_linux_amd64"
            executable(binary, "#!/bin/sh\necho WIZARD_STARTED\n"
                       "test -t 0 && test -t 1 || exit 99\n"
                       "exit \"$LAUNCH_TEST_WIZARD_STATUS\"\n")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            (release / "SHA256SUMS").write_text(
                f"{digest}  guacdeploy_linux_amd64\n")
            (release / "SHA256SUMS.sigstore.json").write_text("{}\n")
            executable(shim / "uname", "#!/bin/sh\ncase $1 in\n"
                       "-s) echo Linux ;; -m) echo x86_64 ;; esac\n")
            executable(shim / "id", "#!/bin/sh\necho \"$LAUNCH_TEST_UID\"\n")
            executable(shim / "cosign", "#!/bin/sh\n"
                       "exit \"$LAUNCH_TEST_VERIFY_STATUS\"\n")
            executable(shim / "sudo", "#!/bin/sh\n"
                       "echo SUDO_LAUNCH\n"
                       "test \"$1\" = -- || exit 98\nshift\nexec \"$@\"\n")
            env = dict(os.environ,
                       PATH=f"{shim}:/usr/bin:/bin:/usr/sbin:/sbin",
                       TMPDIR=str(staging),
                       GUACDEPLOY_BASE_URL=(root / "release").as_uri(),
                       GUACDEPLOY_INSTALL_DIR=str(destination),
                       LAUNCH_TEST_UID=str(uid),
                       LAUNCH_TEST_WIZARD_STATUS=str(wizard_status),
                       LAUNCH_TEST_VERIFY_STATUS=str(verify_status))
            command = ["sh", str(LAUNCHER)]
            if install_only:
                command.append("--install-only")
            command.append("v9.9.9-test")
            if terminal:
                master, slave = pty.openpty()
                process = subprocess.Popen(command, stdin=slave, stdout=slave,
                                           stderr=slave, env=env)
                os.close(slave)
                output = bytearray()
                deadline = time.monotonic() + 15
                try:
                    while True:
                        if time.monotonic() > deadline:
                            process.kill()
                            self.fail("launcher did not finish")
                        if select.select([master], [], [], 0.1)[0]:
                            try:
                                block = os.read(master, 65536)
                            except OSError as error:
                                if error.errno == errno.EIO:
                                    break
                                raise
                            if not block:
                                break
                            output.extend(block)
                        elif process.poll() is not None:
                            break
                    status = process.wait(timeout=5)
                finally:
                    os.close(master)
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                output = output.decode(errors="replace")
            else:
                result = subprocess.run(command, input="", capture_output=True,
                                        text=True, env=env, timeout=15)
                status, output = result.returncode, result.stdout + result.stderr
            self.assertEqual(list(staging.iterdir()), [], output)
            return status, output, (destination / "guacdeploy").exists()

    def test_terminal_launches_with_sudo_and_preserves_exit_status(self):
        status, output, installed = self.run_launcher(wizard_status=37)
        self.assertTrue(installed, output)
        self.assertEqual(status, 37, output)
        self.assertEqual(output.count("WIZARD_STARTED"), 1, output)
        self.assertIn("SUDO_LAUNCH", output)

    def test_root_terminal_launches_without_sudo(self):
        status, output, installed = self.run_launcher(uid=0)
        self.assertEqual(status, 0, output)
        self.assertTrue(installed, output)
        self.assertIn("WIZARD_STARTED", output)
        self.assertNotIn("SUDO_LAUNCH", output)

    def test_install_only_keeps_terminal_at_shell(self):
        status, output, installed = self.run_launcher(install_only=True)
        self.assertEqual(status, 0, output)
        self.assertTrue(installed, output)
        self.assertNotIn("WIZARD_STARTED", output)
        self.assertNotIn("SUDO_LAUNCH", output)
        self.assertIn("next step", output)

    def test_without_terminal_only_installs(self):
        status, output, installed = self.run_launcher(terminal=False)
        self.assertEqual(status, 0, output)
        self.assertTrue(installed, output)
        self.assertNotIn("WIZARD_STARTED", output)
        self.assertIn("next step", output)

    def test_invalid_signature_never_installs_or_launches(self):
        status, output, installed = self.run_launcher(verify_status=1)
        self.assertNotEqual(status, 0, output)
        self.assertFalse(installed, output)
        self.assertNotIn("WIZARD_STARTED", output)
        self.assertNotIn("SUDO_LAUNCH", output)


if __name__ == "__main__":
    unittest.main()
