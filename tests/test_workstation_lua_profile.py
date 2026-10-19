import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.make_replay_lua_acts_profile import (
    BINDINGS,
    CATALOG,
    EXPECTED_IMAGE_SHA256,
    build_profile,
)
from tools.source_catalog import stable_id


class ReplayLuaProfileTests(unittest.TestCase):
    def setUp(self):
        if not CATALOG.is_file():
            self.skipTest('Run owner-input analysis preparation before the target Lua profile tests')
        self.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.temp = tempfile.TemporaryDirectory()
        self.catalog_path = Path(self.temp.name) / "function-catalog.json"

    def tearDown(self):
        self.temp.cleanup()

    def write_catalog(self, catalog):
        self.catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        return self.catalog_path

    def test_profile_uses_stable_ids_and_current_hash_provenance(self):
        # Name and whole-database hashes may change while the recovered
        # function identities and target image remain the same.
        changed = copy.deepcopy(self.catalog)
        changed["database_sha256"] = "f" * 64
        wanted = set(BINDINGS.values())
        for row in changed["functions"]:
            if row.get("id") in wanted:
                row["name"] = "renamed_by_sqlite"
        path = self.write_catalog(changed)
        profile_path, profile = build_profile(path, Path(r"D:\acts\acts.exe"))
        self.assertEqual(profile_path, Path(r"D:\acts\replay120_lua_native.json"))
        self.assertEqual(profile["__provenance"]["image_sha256"], EXPECTED_IMAGE_SHA256)
        self.assertEqual(profile["__provenance"]["database_sha256"], "f" * 64)
        self.assertEqual(profile["__provenance"]["catalog_sha256"],
                         __import__("hashlib").sha256(path.read_bytes()).hexdigest())
        self.assertEqual(set(profile["scans"]["lua"]), set(BINDINGS))
        for acts_name, function_id in BINDINGS.items():
            rows = [row for row in changed["functions"] if row.get("id") == function_id]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["id"], stable_id(EXPECTED_IMAGE_SHA256, row["rva"]))
            self.assertEqual(profile["scans"]["lua"][acts_name], {
                "type": "Offset", "scan": f"0x{row['rva']:x}"
            })
            self.assertEqual(profile["__provenance"]["bindings"][acts_name]["catalog_name"],
                             "renamed_by_sqlite")
        self.assertNotIn("lua_tolstring", profile["scans"]["lua"])

    def test_changed_target_image_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        changed["image_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned Replay image"):
            build_profile(self.write_catalog(changed), Path("acts.exe"))

    def test_changed_stable_id_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        row = next(row for row in changed["functions"]
                   if row.get("id") == next(iter(BINDINGS.values())))
        row["id"] = "fn_0000000000000000"
        with self.assertRaisesRegex(ValueError, "stable function ID"):
            build_profile(self.write_catalog(changed), Path("acts.exe"))

    def test_changed_rva_with_old_id_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        row = next(row for row in changed["functions"]
                   if row.get("id") == next(iter(BINDINGS.values())))
        row["rva"] += 1
        with self.assertRaisesRegex(ValueError, "stable ID/RVA mismatch"):
            build_profile(self.write_catalog(changed), Path("acts.exe"))

    def test_duplicate_stable_id_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        row = next(row for row in changed["functions"]
                   if row.get("id") == next(iter(BINDINGS.values())))
        changed["functions"].append(copy.deepcopy(row))
        with self.assertRaisesRegex(ValueError, "Expected one catalog row"):
            build_profile(self.write_catalog(changed), Path("acts.exe"))

    def test_missing_stable_id_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        function_id = next(iter(BINDINGS.values()))
        changed["functions"] = [row for row in changed["functions"]
                                if row.get("id") != function_id]
        with self.assertRaisesRegex(ValueError, "Expected one catalog row"):
            build_profile(self.write_catalog(changed), Path("acts.exe"))


if __name__ == "__main__":
    unittest.main()
