import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import export_workstation


class ManagedSourceExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "source-workstation").mkdir()

    def unit(self, kind="cpp", source="src/workstation_fn_fixture.cpp"):
        path = self.root / source
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"int NativeFunction() { return 1; }\n" if kind == "cpp" else b".text\nret\n")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"kind": kind, "source": source, "function_id": "fn_fixture",
                "symbol": "NativeFunction", "revision": digest, "sha256": digest}

    def write_units(self, rows):
        (self.root / "source-workstation/units.json").write_text(json.dumps({
            "schema": 1, "image_sha256": "a" * 64, "units": rows}))

    def test_preserves_cpp_assembly_and_new_helper_bindings_without_editor_cache(self):
        cpp = self.unit()
        assembly = self.unit("assembly", "source-workstation/assembly/fn_second.s")
        helper = self.unit(source="src/workstation_user_helper.cpp")
        self.write_units([cpp, assembly])
        (self.root / "source-workstation/user-functions.json").write_text(json.dumps({
            "schema": 1, "image_sha256": "a" * 64,
            "functions": {"user_helper": {"name": "NewHelper", "path": helper["source"],
                "revision": helper["revision"], "sha256": helper["sha256"]}}}))
        files = {p.as_posix() for p in export_workstation.managed_source_files(self.root)}
        self.assertEqual(files, {cpp["source"], assembly["source"], helper["source"],
            "source-workstation/units.json", "source-workstation/user-functions.json"})

    def test_stale_or_missing_authored_source_rejects_export(self):
        row = self.unit()
        self.write_units([row])
        (self.root / row["source"]).write_text("changed")
        with self.assertRaisesRegex(ValueError, "revision no longer matches"):
            export_workstation.managed_source_files(self.root)
        (self.root / row["source"]).unlink()
        with self.assertRaisesRegex(ValueError, "revision no longer matches"):
            export_workstation.managed_source_files(self.root)

    def test_mapping_cannot_export_unrelated_files(self):
        row = self.unit()
        for escape in ("../outside.cpp", "src/../outside.cpp", "/outside.cpp",
                       "Z:/outside.cpp", "assets/private.cpp", "src/private.ff"):
            with self.subTest(escape=escape):
                self.write_units([dict(row, source=escape)])
                with self.assertRaisesRegex(ValueError, "escapes"):
                    export_workstation.managed_source_files(self.root)

    def test_empty_project_needs_no_managed_mappings(self):
        self.assertEqual(export_workstation.managed_source_files(self.root), [])


if __name__ == "__main__":
    unittest.main()
