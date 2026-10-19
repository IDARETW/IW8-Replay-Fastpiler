import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "tools" / "bootstrap_workstation_dxbc.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_workstation_dxbc", BOOTSTRAP)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class SourcePackageTests(unittest.TestCase):
    def test_real_package_manifest_and_members_validate(self):
        result = bootstrap.verify_source_package(expected_manifest_sha256=None)
        self.assertEqual(result["manifest"]["upstream"]["commit"], bootstrap.UPSTREAM_COMMIT)
        self.assertGreaterEqual(len(result["files"]), 12)

    def test_source_drift_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dxbc-package-drift-") as temp:
            clone = Path(temp) / "package"
            shutil.copytree(bootstrap.PACKAGE, clone)
            member = clone / "D3D_Shaders" / "Assembler.cpp"
            member.write_bytes(member.read_bytes() + b"\n// drift\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                bootstrap.verify_source_package(clone, expected_manifest_sha256=None)

    def test_manifest_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory(prefix="dxbc-package-path-") as temp:
            clone = Path(temp) / "package"
            shutil.copytree(bootstrap.PACKAGE, clone)
            manifest_path = clone / "source-package-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["path"] = "../outside.txt"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe source-package path"):
                bootstrap.verify_source_package(clone, expected_manifest_sha256=None)

    def test_duplicate_manifest_members_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dxbc-package-duplicate-") as temp:
            clone = Path(temp) / "package"
            shutil.copytree(bootstrap.PACKAGE, clone)
            manifest_path = clone / "source-package-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append(dict(manifest["files"][0]))
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate source-package entry"):
                bootstrap.verify_source_package(clone, expected_manifest_sha256=None)


if __name__ == "__main__":
    unittest.main()
