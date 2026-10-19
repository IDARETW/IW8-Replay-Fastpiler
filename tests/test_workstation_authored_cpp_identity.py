import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build
sys.path.insert(0, str(ROOT / "tools"))
import coff
import workstation_sources as workstation_sources_module
from workstation_sources import SourceWorkspace


class AuthoredCppIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="workstation-cpp-identity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.cache = Path(self.temp.name) / "cache"
        generated = self.root / "generated"
        generated.mkdir(parents=True)
        self.image = "a" * 64
        (generated / "manifest.json").write_text(json.dumps({
            "input_sha256": self.image, "image_base": 0x140000000}), encoding="utf-8")
        self.rows = [
            {"id": "fn_0123456789abcdef", "name": "CurrentMeaningful", "rva": 0x1000,
             "aliases": ["CurrentMeaningful", "OldMeaningful"]},
            {"id": "fn_fedcba9876543210", "name": "9-opaque-label", "rva": 0x2000,
             "aliases": ["9-opaque-label"]},
        ]
        (generated / "function-catalog.json").write_text(json.dumps({
            "image_sha256": self.image, "functions": self.rows, "symbols": []}), encoding="utf-8")
        self.sqlite = Path(self.temp.name) / "analysis.sqlite"
        with closing(sqlite3.connect(self.sqlite)) as db:
            db.execute("CREATE TABLE functions (address TEXT, name TEXT, pseudocode TEXT)")
            db.executemany("INSERT INTO functions VALUES (?, ?, ?)", [
                ("0x140001000", "CurrentMeaningful", "first pseudocode"),
                ("0x140002000", "9-opaque-label", "pseudocode"),
            ])
            db.commit()
        self.workspace = SourceWorkspace(self.root, self.cache, self.sqlite)

    def test_unique_sqlite_name_saves_and_exports_identity_symbol_and_revision(self):
        code = "int CurrentMeaningful() { return 7; }\n"
        opened = self.workspace.get_source("CurrentMeaningful", "cpp")
        self.assertEqual(opened["symbol"], "CurrentMeaningful")
        self.assertEqual(opened["source"], "src/workstation_fn_0123456789abcdef.cpp")
        saved = self.workspace.create_source("CurrentMeaningful", "cpp", code)
        document = self.workspace.build_source_units()
        self.assertIn({"source": "src/workstation_fn_0123456789abcdef.cpp",
                       "symbol": "CurrentMeaningful", "function_id": "fn_0123456789abcdef"},
                      document["units"])
        state = json.loads(self.workspace.manifest_path.read_text(encoding="utf-8"))
        record = state["sources"]["fn_0123456789abcdef"]["cpp"]
        self.assertEqual(record["function_id"], "fn_0123456789abcdef")
        self.assertEqual(record["symbol"], "CurrentMeaningful")
        self.assertEqual(record["revision"], hashlib.sha256(code.encode()).hexdigest())
        persisted = json.loads(self.workspace.units_path.read_text(encoding="utf-8"))
        cpp_unit = next(unit for unit in persisted["units"] if unit.get("kind") == "cpp")
        self.assertEqual(cpp_unit["function_id"], "fn_0123456789abcdef")
        self.assertEqual(cpp_unit["sha256"], saved["revision"])
        updated = self.workspace.save_source(saved["id"], code.replace("7", "8"), saved["revision"], "cpp")
        self.assertNotEqual(updated["revision"], saved["revision"])
        self.assertEqual(self.workspace.build_source_units()["units"], document["units"])

    def test_legacy_source_units_without_image_hash_and_fresh_workspace_merge(self):
        baseline = self.root / "source-units.json"
        baseline.write_text(json.dumps({"schema": 1, "units": [], "imports": []}), encoding="utf-8")
        code = "int CurrentMeaningful() { return 9; }\n"
        saved = self.workspace.create_source("CurrentMeaningful", "cpp", code)

        # A new workspace/cache instance must still get the persisted binding
        # from source-workstation/units.json; the editor cache is not compiler input.
        fresh = SourceWorkspace(self.root, self.cache.parent / "fresh-cache", self.sqlite)
        document = fresh.build_source_units()
        self.assertEqual(document["units"], [{
            "source": "src/workstation_fn_0123456789abcdef.cpp",
            "symbol": "CurrentMeaningful",
            "function_id": "fn_0123456789abcdef",
        }])
        self.assertNotIn("image_sha256", json.loads(baseline.read_text(encoding="utf-8")))
        self.assertEqual(saved["symbol"], "CurrentMeaningful")

    def test_fresh_cache_reopens_lists_saves_and_removes_persisted_catalog_cpp(self):
        initial = "int CurrentMeaningful() { return 21; }\n"
        saved = self.workspace.create_source("CurrentMeaningful", "cpp", initial)
        fresh = SourceWorkspace(self.root, self.cache.parent / "empty-editor-cache", self.sqlite)

        opened = fresh.get_source(saved["id"], "cpp")
        self.assertEqual(opened["content"], initial)
        self.assertEqual(opened["revision"], saved["revision"])
        self.assertEqual(opened["source"], "src/workstation_fn_0123456789abcdef.cpp")
        hydrated = fresh._state()["sources"][saved["id"]]["cpp"]
        self.assertEqual(hydrated["path"], opened["source"])
        self.assertEqual(hydrated["revision"], saved["revision"])
        listing, _ = fresh.list_sources()
        row = next(item for item in listing if item["id"] == saved["id"])
        self.assertTrue(row["has_cpp"], "portable source-workstation binding appears without cache state")

        updated = fresh.save_source(saved["id"], initial.replace("21", "22"),
                                    opened["revision"], "cpp")
        self.assertEqual(updated["content"], initial.replace("21", "22"))
        self.assertNotEqual(updated["revision"], opened["revision"])

        # A second empty cache must be able to remove the persisted compiler
        # binding without relying on the first editor cache's active-state row.
        remover = SourceWorkspace(self.root, self.cache.parent / "empty-removal-cache", self.sqlite)
        removed = remover.remove_source(saved["id"], updated["revision"], "cpp")
        self.assertEqual(removed["removed_revision"], updated["revision"])
        self.assertFalse((self.root / "src/workstation_fn_0123456789abcdef.cpp").exists())
        units = json.loads(self.workspace.units_path.read_text(encoding="utf-8"))["units"]
        self.assertFalse(any(unit.get("kind") == "cpp" and unit.get("function_id") == saved["id"]
                             for unit in units))
        listing, _ = remover.list_sources()
        row = next(item for item in listing if item["id"] == saved["id"])
        self.assertFalse(row["has_cpp"])

    def test_empty_cache_restores_user_helper_metadata_for_list_get_save_and_remove(self):
        original = "int ReopenedHelper(int value) { return value + 1; }\n"
        created = self.workspace.create_source("ReopenedHelper", "cpp", original)
        fresh = SourceWorkspace(self.root, self.cache.parent / "empty-helper-cache", self.sqlite)

        listing, _ = fresh.list_sources(query="ReopenedHelper")
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["id"], created["id"])
        self.assertTrue(listing[0]["has_cpp"])
        opened = fresh.get_source(created["id"], "cpp")
        self.assertEqual(opened["content"], original)
        self.assertEqual(opened["revision"], created["revision"])

        updated = fresh.save_source(created["id"], original.replace("+ 1", "+ 2"),
                                    opened["revision"], "cpp")
        self.assertEqual(updated["content"], original.replace("+ 1", "+ 2"))
        removed = fresh.remove_source(created["id"], updated["revision"], "cpp")
        self.assertEqual(removed["removed_revision"], updated["revision"])
        self.assertFalse((self.root / "src" / f"workstation_{created['id']}.cpp").exists())
        users = json.loads(self.workspace.user_functions_path.read_text(encoding="utf-8"))
        self.assertNotIn(created["id"], users["functions"])
        listing, _ = fresh.list_sources(query="ReopenedHelper")
        self.assertEqual(listing, [])

    def test_empty_cache_reopens_lists_and_removes_persisted_assembly(self):
        identity = self.rows[0]["id"]
        relative = Path("source-workstation/assembly") / f"{identity}.s"
        content = (f".intel_syntax noprefix\n.text\n.globl {identity}\n"
                   f"{identity}:\n  ret\n")
        source = self.root / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(content, encoding="utf-8", newline="\n")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.workspace.units_path.parent.mkdir(parents=True, exist_ok=True)
        self.workspace.units_path.write_text(json.dumps({"schema": 1, "image_sha256": self.image,
            "units": [{"function_id": identity, "kind": "assembly", "source": relative.as_posix(),
                       "sha256": digest, "revision": digest, "language": "x86_64-coff-asm"}]}),
            encoding="utf-8")
        fresh = SourceWorkspace(self.root, self.cache.parent / "empty-assembly-cache", self.sqlite)

        opened = fresh.get_source(identity, "assembly")
        self.assertEqual(opened["content"], content)
        self.assertEqual(opened["revision"], digest)
        hydrated = fresh._state()["sources"][identity]["assembly"]
        self.assertEqual(hydrated["path"], relative.as_posix())
        self.assertEqual(hydrated["revision"], digest)
        listing, _ = fresh.list_sources()
        row = next(item for item in listing if item["id"] == identity)
        self.assertTrue(row["has_assembly_edit"])
        removed = fresh.remove_source(identity, digest, "assembly")
        self.assertEqual(removed["removed_revision"], digest)
        self.assertFalse(source.exists())
        units = json.loads(self.workspace.units_path.read_text(encoding="utf-8"))["units"]
        self.assertFalse(any(unit.get("kind") == "assembly" and unit.get("function_id") == identity
                             for unit in units))

    def test_unsafe_or_opaque_name_uses_address_alias_without_manual_binding(self):
        identity = "fn_fedcba9876543210"
        opened = self.workspace.get_source(identity, "cpp")
        self.assertEqual(opened["symbol"], "func_140002000")
        saved = self.workspace.create_source(identity, "cpp", f"int {identity}() {{ return 1; }}\n")
        self.assertEqual(saved["id"], identity)
        self.assertTrue(any(row["function_id"] == identity and row["symbol"] == identity
                            for row in self.workspace.build_source_units()["units"]))

    def test_renamed_alias_selects_current_unique_name(self):
        saved = self.workspace.create_source("OldMeaningful", "cpp",
                                              "int CurrentMeaningful() { return 2; }\n")
        unit = next(row for row in self.workspace.build_source_units()["units"]
                    if row["function_id"] == saved["id"])
        self.assertEqual(unit["symbol"], "CurrentMeaningful")

    def test_saved_symbol_survives_sqlite_rename_and_revision_updates(self):
        original = "int CurrentMeaningful() { return 2; }\n"
        saved = self.workspace.create_source("CurrentMeaningful", "cpp", original)
        with closing(sqlite3.connect(self.sqlite)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("UPDATE functions SET name=? WHERE address=?", ("RenamedInDatabase", "0x140001000"))
            db.commit()
        reopened = self.workspace.get_source(saved["id"], "cpp")
        self.assertEqual(reopened["name"], "RenamedInDatabase")
        self.assertEqual(reopened["symbol"], "CurrentMeaningful")
        updated = self.workspace.save_source(saved["id"], original.replace("return 2", "return 3"),
                                             saved["revision"], "cpp")
        unit = next(row for row in self.workspace.build_source_units()["units"]
                    if row["function_id"] == saved["id"])
        self.assertEqual(unit["symbol"], "CurrentMeaningful")
        self.assertEqual(updated["symbol"], "CurrentMeaningful")

    def test_remove_catalog_cpp_binding_removes_persisted_build_unit(self):
        code = "int CurrentMeaningful() { return 5; }\n"
        saved = self.workspace.create_source("CurrentMeaningful", "cpp", code)
        self.assertTrue(any(unit.get("kind") == "cpp"
                            for unit in json.loads(self.workspace.units_path.read_text())["units"]))
        self.workspace.remove_source(saved["id"], saved["revision"], "cpp")
        units = json.loads(self.workspace.units_path.read_text(encoding="utf-8"))["units"]
        self.assertFalse(any(unit.get("kind") == "cpp" for unit in units))
        self.assertEqual(self.workspace.build_source_units()["units"], [])

    def test_stale_persisted_source_fails_even_when_explicitly_mapped(self):
        source = "int CurrentMeaningful() { return 5; }\n"
        saved = self.workspace.create_source("CurrentMeaningful", "cpp", source)
        relative = "src/workstation_fn_0123456789abcdef.cpp"
        (self.root / "source-units.json").write_text(json.dumps({
            "schema": 1,
            "units": [{"source": relative, "symbol": "CurrentMeaningful",
                       "function_id": "fn_0123456789abcdef"}],
            "imports": [],
        }), encoding="utf-8")
        (self.root / relative).write_text(source + "// changed behind the revision\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source revision/hash mismatch"):
            self.workspace.build_source_units()
        self.assertEqual(saved["symbol"], "CurrentMeaningful")

    def test_duplicate_persisted_cpp_identity_is_rejected(self):
        self.workspace.create_source("CurrentMeaningful", "cpp",
                                     "int CurrentMeaningful() { return 5; }\n")
        document = json.loads(self.workspace.units_path.read_text(encoding="utf-8"))
        cpp_unit = next(unit for unit in document["units"] if unit.get("kind") == "cpp")
        document["units"].append(dict(cpp_unit))
        self.workspace.units_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate persisted catalog C\\+\\+ identity"):
            self.workspace.build_source_units()

    def test_build_units_uses_pinned_catalog_rows_for_symbol_ownership(self):
        self.workspace.create_source("CurrentMeaningful", "cpp",
                                     "int CurrentMeaningful() { return 6; }\n")
        catalog = json.loads((self.root / "generated" / "function-catalog.json").read_text())
        catalog["functions"][1]["aliases"].append("CurrentMeaningful")
        with self.assertRaisesRegex(ValueError, "claimed by another catalog function"):
            self.workspace.build_source_units(catalog)
        self.assertIn(
            {"source": "src/workstation_fn_0123456789abcdef.cpp",
             "symbol": "CurrentMeaningful", "function_id": "fn_0123456789abcdef"},
            self.workspace.build_source_units()["units"],
        )

    def test_saved_symbol_rename_conflict_with_another_catalog_owner_fails(self):
        saved = self.workspace.create_source("CurrentMeaningful", "cpp",
                                              "int CurrentMeaningful() { return 2; }\n")
        catalog_path = self.root / "generated" / "function-catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["functions"].append({"id": "fn_1111111111111111", "name": "OtherFunction",
                                      "rva": 0x3000, "aliases": ["CurrentMeaningful"]})
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        self.workspace._catalog = None
        self.workspace._sorted_catalog_rows = None
        with self.assertRaisesRegex(ValueError, "claimed by another"):
            self.workspace.build_source_units()
        self.assertEqual(saved["id"], "fn_0123456789abcdef")

    def test_stable_id_symbol_survives_later_meaningful_sqlite_name(self):
        identity = "fn_fedcba9876543210"
        source = f"int {identity}() {{ return 1; }}\n"
        saved = self.workspace.create_source(identity, "cpp", source)
        with closing(sqlite3.connect(self.sqlite)) as db:
            db.execute("UPDATE functions SET name=? WHERE address=?", ("MeaningfulLater", "0x140002000"))
            db.commit()
        reopened = self.workspace.get_source(identity, "cpp")
        self.assertEqual(reopened["name"], "MeaningfulLater")
        self.assertEqual(reopened["symbol"], identity)
        unit = next(row for row in self.workspace.build_source_units()["units"]
                    if row["function_id"] == identity)
        self.assertEqual(unit["symbol"], identity)
        self.assertEqual(saved["revision"], reopened["revision"])

    def test_sqlite_change_counter_invalidates_name_cache_when_stat_is_unchanged(self):
        fixed = self.sqlite.stat()

        def stable_stat(path, *args, **kwargs):
            if path == self.sqlite:
                return fixed
            raise FileNotFoundError(path)

        with patch.object(Path, "stat", stable_stat):
            before = self.workspace._entry_names()
            self.assertEqual(before[f"{0x2000:x}"], "9-opaque-label")
            signature_before = workstation_sources_module._sqlite_file_signature(self.sqlite)
            with closing(sqlite3.connect(self.sqlite)) as db:
                db.execute("UPDATE functions SET name=? WHERE address=?",
                           ("MeaningfulLater", "0x140002000"))
                db.commit()
            after = self.workspace._entry_names()
            signature_after = workstation_sources_module._sqlite_file_signature(self.sqlite)
        self.assertEqual(after[f"{0x2000:x}"], "MeaningfulLater")
        self.assertNotEqual(signature_before, signature_after)

    def test_name_and_pseudocode_cache_refresh_with_frozen_stat_metadata(self):
        fixed = self.sqlite.stat()

        def stable_stat(path, *args, **kwargs):
            if path == self.sqlite:
                return fixed
            raise FileNotFoundError(path)

        with patch.object(Path, "stat", stable_stat):
            self.assertEqual(self.workspace._entry_names()[f"{0x2000:x}"], "9-opaque-label")
            self.assertEqual(self.workspace._entry_text()[f"{0x2000:x}"]["pseudocode"], "pseudocode")
            with closing(sqlite3.connect(self.sqlite)) as db:
                db.execute("UPDATE functions SET name=?, pseudocode=? WHERE address=?",
                           ("MeaningfulLater", "new pseudocode", "0x140002000"))
                db.commit()
            self.assertEqual(self.workspace._entry_names()[f"{0x2000:x}"], "MeaningfulLater")
            self.assertEqual(self.workspace._entry_text()[f"{0x2000:x}"]["pseudocode"],
                             "new pseudocode")

    def test_wal_name_and_pseudocode_cache_refresh_with_frozen_stat_metadata(self):
        writer = sqlite3.connect(self.sqlite)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(), "wal")
        writer.commit()
        reader = sqlite3.connect(self.sqlite)
        self.addCleanup(reader.close)
        reader.execute("BEGIN")
        reader.execute("SELECT name FROM functions LIMIT 1").fetchone()
        wal = Path(str(self.sqlite) + "-wal")
        shm = Path(str(self.sqlite) + "-shm")
        self.assertTrue(wal.is_file())
        self.assertTrue(shm.is_file())
        self.workspace._entry_names()
        self.workspace._entry_text()
        frozen = {path: path.stat() for path in (self.sqlite, wal, shm)}

        def stable_stat(path, *args, **kwargs):
            if path in frozen:
                return frozen[path]
            raise FileNotFoundError(path)

        with patch.object(Path, "stat", stable_stat):
            writer.execute("UPDATE functions SET name=?, pseudocode=? WHERE address=?",
                           ("MeaningfulLater", "new pseudocode", "0x140002000"))
            writer.commit()
            self.assertEqual(self.workspace._entry_names()[f"{0x2000:x}"], "MeaningfulLater")
            self.assertEqual(self.workspace._entry_text()[f"{0x2000:x}"]["pseudocode"],
                             "new pseudocode")

    def test_duplicate_names_use_address_aliases_and_explicit_identity_conflicts_fail(self):
        self.rows[1].update(name="CurrentMeaningful", aliases=["CurrentMeaningful"])
        (self.root / "generated" / "function-catalog.json").write_text(json.dumps({
            "image_sha256": self.image, "functions": self.rows, "symbols": []}), encoding="utf-8")
        self.workspace._catalog = None
        self.workspace._sorted_catalog_rows = None
        for identity in ("fn_0123456789abcdef", "fn_fedcba9876543210"):
            opened = self.workspace.get_source(identity, "cpp")
            row = next(row for row in self.rows if row["id"] == identity)
            self.assertEqual(opened["symbol"], f"func_{0x140000000 + row['rva']:X}")

        source_units = self.root / "source-units.json"
        source_units.write_text(json.dumps({"schema": 1, "image_sha256": self.image,
            "units": [
                {"source": "src/a.cpp", "symbol": "same_symbol", "function_id": "fn_a"},
                {"source": "src/b.cpp", "symbol": "same_symbol", "function_id": "fn_b"}],
            "imports": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "multiple catalog functions"):
            self.workspace.build_source_units()

    def test_plain_cpp_helper_and_caller_share_compiler_linkage_without_extern_c(self):
        clang = build._find_llvm_bin() / "clang++.exe"
        helper = self.root / "src" / "helper.cpp"
        caller = self.root / "src" / "caller.cpp"
        helper.parent.mkdir(parents=True)
        helper.write_text("int NewHelper(int value) { return value + 1; }\n", encoding="utf-8")
        caller.write_text("int NewHelper(int); int Caller() { return NewHelper(4); }\n", encoding="utf-8")
        objects = []
        for source in (helper, caller):
            target = source.with_suffix(".obj")
            subprocess.run([str(clang), "--target=x86_64-pc-windows-msvc", "-c", str(source),
                            "-o", str(target), "-O0", "-std=c++20"], check=True,
                           capture_output=True, text=True)
            objects.append(coff.read(target))
        helper_names = {symbol["name"] for symbol in objects[0]["symbols"].values()
                        if symbol["section"] > 0 and symbol["storage"] == 2}
        caller_undefined = {symbol["name"] for symbol in objects[1]["symbols"].values()
                            if symbol["section"] == 0 and symbol["storage"] == 2}
        self.assertIn("?NewHelper@@YAHH@Z", helper_names)
        self.assertIn("?NewHelper@@YAHH@Z", caller_undefined)


if __name__ == "__main__":
    unittest.main()
