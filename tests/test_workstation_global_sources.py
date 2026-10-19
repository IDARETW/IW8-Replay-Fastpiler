import hashlib
import json
import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_global_sources import GlobalSourceWorkspace, apply_global_overrides


class GlobalSourceWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.root = base / "project"
        self.cache = base / "cache"
        generated = self.root / "generated"
        generated.mkdir(parents=True)
        self.exe = base / "game_dx12_ship_replay.exe"
        self.exe.write_bytes(b"pinned test Replay image")
        self.image_sha256 = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.exe_md5 = hashlib.md5(self.exe.read_bytes()).hexdigest()
        data = b"\x11\x22\x33\x44\x00\x00\x00\x00"
        (generated / "data.bin").write_bytes(data)
        (generated / "reloc.bin").write_bytes(b"")
        (generated / "metadata.bin").write_bytes(b"")
        section = {"name": ".data", "rva": 0x1000, "raw_size": len(data),
                   "virtual_size": 0x100, "file": "data.bin",
                   "sha256": hashlib.sha256(data).hexdigest()}
        manifest = {"input_sha256": self.image_sha256, "image_base": 0x140000000,
                    "optional": {"FileAlignment": 512},
                    "sections": [section], "directories": [{"rva": 0, "size": 0} for _ in range(6)],
                    "fixups_file": "reloc.bin", "fixups_sha256": hashlib.sha256(b"").hexdigest(),
                    "metadata": {"file": "metadata.bin", "sha256": hashlib.sha256(b"").hexdigest()}}
        (generated / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        identity = "sym_0123456789abcdef"
        catalog = {"image_sha256": self.image_sha256,
                   "functions": [], "symbols": [{"id": identity, "name": identity,
                       "rva": 0x1000, "aliases": [], "kind": "data-address"}]}
        (generated / "function-catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
        self.identity = identity
        self.sqlite = base / "analysis.sqlite"
        db = sqlite3.connect(self.sqlite)
        try:
            db.executescript("""
                CREATE TABLE replay_global_inventory_meta(id INTEGER PRIMARY KEY, scope TEXT, executable_md5 TEXT, total INTEGER);
                CREATE TABLE replay_global_inventory(rva INTEGER PRIMARY KEY, address TEXT, name TEXT, segment TEXT);
                CREATE TABLE replay_ida_types(rva INTEGER, locator TEXT, entity_kind TEXT, type_name TEXT);
            """)
            db.execute("INSERT INTO replay_global_inventory_meta VALUES (1,?,?,1)",
                       ("ida-data-heads-v1", self.exe_md5))
            db.execute("INSERT INTO replay_global_inventory VALUES (?,?,?,?)",
                       (0x1000, str(0x140001000), "g_test", ".data"))
            db.execute("INSERT INTO replay_ida_types VALUES (?,?,?,?)",
                       (0x1000, "address", "global", "_BYTE[8]"))
            db.commit()
        finally:
            db.close()
        self.workspace = GlobalSourceWorkspace(self.root, self.cache, self.sqlite, self.exe)

    def tearDown(self):
        self.temp.cleanup()

    def test_typed_global_revision_and_cpp_materialization(self):
        item = self.workspace.get_source(self.identity)
        self.assertTrue(item["editable"])
        self.assertTrue(item["compilable"])
        self.assertEqual(item["language"], "json")
        self.assertEqual(item["storage"], "initialized")
        self.assertEqual(item["values"], [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0])
        changed = self.workspace.save_source(self.identity, [1, 2, 3, 4, 5, 6, 7, 8], item["revision"])
        self.assertNotEqual(changed["revision"], item["revision"])
        self.assertEqual(changed["estimated_file_growth_bytes"], 0)
        source = self.workspace.render_cpp(self.identity)
        self.assertIn(f"unsigned char {self.identity}[8]", source)
        self.assertIn("sizeof(" + self.identity + ") == 8", source)

    def test_opaque_global_name_uses_stable_identity_and_preserves_database_label(self):
        db = sqlite3.connect(self.sqlite)
        try:
            db.execute("UPDATE replay_global_inventory SET name='qword_140001000'")
            db.commit()
        finally:
            db.close()
        workspace = GlobalSourceWorkspace(self.root, self.cache, self.sqlite, self.exe)
        item = workspace.get_source(self.identity)
        listed = workspace.list_editable()
        self.assertEqual(item["name"], "gl_140001000")
        self.assertEqual(item["provenance"]["database_name"], "qword_140001000")
        self.assertEqual(listed[0]["name"], "gl_140001000")

    def test_restore_global_edit_archives_revision_and_checks_conflicts(self):
        original = self.workspace.get_source(self.identity)
        changed = self.workspace.save_source(
            self.identity,
            json.dumps({"type_name": "_BYTE[8]", "values": [1, 2, 3, 4, 5, 6, 7, 8]}),
            original["revision"])
        with self.assertRaises(ValueError):
            self.workspace.restore_source(self.identity, original["revision"])
        restored = self.workspace.restore_source(self.identity, changed["revision"])
        self.assertTrue(restored["restored"])
        self.assertTrue(Path(restored["archived"]).is_file())
        self.assertEqual(restored["values"], original["values"])
        self.assertFalse((self.cache / "globals" / f"{self.identity}.json").exists())

    def test_type_extent_is_enforced(self):
        item = self.workspace.get_source(self.identity)
        with self.assertRaises(ValueError):
            self.workspace.save_source(self.identity, [1], item["revision"])
        with self.assertRaises(ValueError):
            self.workspace.save_source(self.identity, [256] * 8, item["revision"])

    def test_unsized_or_relocated_global_is_not_editable(self):
        db = sqlite3.connect(self.sqlite)
        try:
            db.execute("UPDATE replay_ida_types SET type_name='_QWORD[]'")
            db.commit()
        finally:
            db.close()
        workspace = GlobalSourceWorkspace(self.root, self.cache, self.sqlite, self.exe)
        self.assertEqual(workspace.list_editable(), [])

    def test_loader_relocated_global_is_not_editable(self):
        generated = self.root / "generated"
        payload = struct.pack("<IIH", 0x1000, 10, 0xA000)
        (generated / "pe-reloc.bin").write_bytes(payload)
        manifest_path = generated / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sections"].append({"name": ".reloc", "rva": 0x2000, "raw_size": len(payload),
                                     "virtual_size": len(payload), "file": "pe-reloc.bin",
                                     "sha256": hashlib.sha256(payload).hexdigest()})
        manifest["directories"][5] = {"rva": 0x2000, "size": len(payload)}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        workspace = GlobalSourceWorkspace(self.root, self.cache, self.sqlite, self.exe)
        self.assertEqual(workspace.list_editable(), [])

    def test_decimal_string_content_preserves_full_qword_range(self):
        db = sqlite3.connect(self.sqlite)
        try:
            db.execute("UPDATE replay_ida_types SET type_name='_QWORD[1]'")
            db.commit()
        finally:
            db.close()
        workspace = GlobalSourceWorkspace(self.root, self.cache, self.sqlite, self.exe)
        current = workspace.get_source(self.identity)
        self.assertEqual(current["values"], ["1144201745"])
        self.assertTrue(current["compilable"])
        content = json.dumps({"type_name": "_QWORD[1]", "values": ["18446744073709551615"]})
        changed = workspace.save_source(self.identity, content, current["revision"])
        self.assertEqual(changed["values"], ["18446744073709551615"])
        patches = workspace.load_build_overrides()
        self.assertEqual(patches[0]["data"], b"\xff" * 8)

    def test_build_patches_initialized_global_in_mapped_section(self):
        current = self.workspace.get_source(self.identity)
        content = json.dumps({"type_name": "_BYTE[8]", "values": [9, 8, 7, 6, 5, 4, 3, 2]})
        self.workspace.save_source(self.identity, content, current["revision"])
        patches = self.workspace.load_build_overrides()

        class Shift:
            @staticmethod
            def map(rva):
                return rva + 0x1000

        sections = [{"name": ".data", "rva": 0x2000, "raw_size": 8,
                     "virtual_size": 0x100, "data": bytearray(b"\x11\x22\x33\x44\0\0\0\0")}]
        result = apply_global_overrides(sections, patches, Shift(), [])
        self.assertEqual(sections[0]["data"], bytearray([9, 8, 7, 6, 5, 4, 3, 2]))
        self.assertEqual(result[0]["mapped_rva"], 0x2000)
        self.assertTrue(result[0]["in_place"])

    def test_build_patches_nonzero_bss_and_accounts_for_file_growth(self):
        generated = self.root / "generated"
        (generated / "data.bin").write_bytes(b"")
        manifest_path = generated / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sections"][0]["raw_size"] = 0
        manifest["sections"][0]["sha256"] = hashlib.sha256(b"").hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        workspace = GlobalSourceWorkspace(self.root, self.cache, self.sqlite, self.exe)
        current = workspace.get_source(self.identity)
        content = json.dumps({"type_name": "_BYTE[8]", "values": [1, 0, 0, 0, 0, 0, 0, 0]})
        saved = workspace.save_source(self.identity, content, current["revision"])
        self.assertEqual(saved["estimated_file_growth_bytes"], 512)
        patches = workspace.load_build_overrides()
        self.assertEqual(patches[0]["estimated_file_growth_bytes"], 512)

        class Shift:
            @staticmethod
            def map(rva):
                return rva + 0x1000

        sections = [{"name": ".data", "rva": 0x2000, "raw_size": 0,
                     "virtual_size": 0x100, "data": bytearray()}]
        result = apply_global_overrides(sections, patches, Shift(), [])
        self.assertEqual(sections[0]["data"], bytearray(b"\x01\0\0\0\0\0\0\0"))
        self.assertEqual(result[0]["section_growth"], 8)
        self.assertEqual(result[0]["estimated_file_growth_bytes"], 512)


if __name__ == "__main__":
    unittest.main()
