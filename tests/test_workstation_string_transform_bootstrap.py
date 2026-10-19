import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bootstrap_workstation_string_decryptor as bootstrap


class StringTransformBootstrapTests(unittest.TestCase):
    def _git(self, *args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True).stdout.strip()

    def test_materializes_exact_pinned_blobs_and_is_idempotent(self):
        if not shutil.which("git"):
            self.skipTest("Git is required for bootstrap tests")
        with tempfile.TemporaryDirectory(prefix="string-transform-bootstrap-") as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            self._git("init", cwd=source)
            self._git("config", "user.name", "Fixture", cwd=source)
            self._git("config", "user.email", "fixture@example.invalid", cwd=source)
            (source / ".gitattributes").write_text("*.py text eol=crlf\n", encoding="ascii")
            (source / "transform.py").write_bytes(b"VALUE = 'blob-bytes'\n")
            (source / "tables.py").write_bytes(b"TABLE = (1, 2, 3)\n")
            (source / "LICENSE").write_bytes(b"MIT fixture license\n")
            self._git("add", ".", cwd=source)
            self._git("commit", "-m", "fixture", cwd=source)
            commit = self._git("rev-parse", "HEAD", cwd=source)
            spec = {
                "schema": 1,
                "repository": str(source),
                "base_commit": commit,
                "license": "MIT",
                "license_path": "LICENSE",
                "license_sha256": hashlib.sha256(b"MIT fixture license\n").hexdigest(),
                "files": {
                    "transform.py": hashlib.sha256(b"VALUE = 'blob-bytes'\n").hexdigest(),
                    "tables.py": hashlib.sha256(b"TABLE = (1, 2, 3)\n").hexdigest(),
                },
                "transform": "fixture",
            }
            manifest = root / "pin.json"
            manifest.write_text(json.dumps(spec), encoding="utf-8")
            destination = root / "installed"
            old_manifest = bootstrap.MANIFEST
            bootstrap.MANIFEST = manifest
            try:
                first = bootstrap.bootstrap(destination)
                self.assertEqual(first["commit"], commit)
                portable = destination / "portable"
                self.assertEqual(hashlib.sha256((portable / "transform.py").read_bytes()).hexdigest(),
                                 spec["files"]["transform.py"])
                # The checkout is forced to CRLF while the Git blob and
                # portable copy remain LF, reproducing Windows autocrlf drift.
                self._git("checkout", "--force", commit, cwd=destination)
                self.assertNotEqual((destination / "transform.py").read_bytes(),
                                    (portable / "transform.py").read_bytes())
                second = bootstrap.bootstrap(destination)
                self.assertEqual(second["commit"], commit)
            finally:
                bootstrap.MANIFEST = old_manifest


if __name__ == "__main__":
    unittest.main()
