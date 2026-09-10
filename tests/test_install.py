"""Exercise the installer in a temporary folder without root or live services."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def test_install_copies_nginx_template_on_fresh_install_and_update(self):
        with tempfile.TemporaryDirectory(prefix="guac-install-check-") as temporary:
            work = Path(temporary)
            source = work / "source"
            installed = work / "installed"
            source.mkdir()
            for name in (
                "setup.sh", "connectdb.sh", "destroy.sh", "docker-compose.yaml",
                ".env.example", "README.md", "LICENSE", "lib",
                "init/002-groups.sh", "nginx/templates",
            ):
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                if (ROOT / name).is_dir():
                    shutil.copytree(ROOT / name, destination)
                else:
                    shutil.copy2(ROOT / name, destination)

            # Relocate only the destination. Run the real install-only path.
            setup = source / "setup.sh"
            setup.write_text(setup.read_text().replace(
                "INSTALL_DIR=/opt/guacamole", f"INSTALL_DIR='{installed}'", 1
            ))
            tools = work / "bin"
            tools.mkdir()
            # Simulate root only inside this temporary installer fixture.
            # Ownership changes are not needed to check copied files.
            for name, body in (
                ("id", '#!/bin/sh\nprintf "0\\n"\n'),
                ("chown", '#!/bin/sh\nexit 0\n'),
            ):
                command = tools / name
                command.write_text(body)
                command.chmod(0o755)
            env = {"PATH": f"{tools}:{os.environ['PATH']}"}
            template = "nginx/templates/guacamole.conf.template"

            for run in ("fresh install", "update"):
                with self.subTest(run=run):
                    result = subprocess.run(
                        ["bash", str(setup), "--install-only"], env=env,
                        text=True, capture_output=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(
                        (installed / template).is_file(),
                        "The installed nginx template is missing; HTTPS cannot start.",
                    )
                    self.assertEqual(
                        (installed / template).read_bytes(),
                        (source / template).read_bytes(),
                    )
                # An update must repair the empty folder from an older installer.
                (installed / template).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
