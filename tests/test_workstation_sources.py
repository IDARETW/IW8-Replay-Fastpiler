import json
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_sources import SourceWorkspace


class SourceWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "project"
        self.cache = Path(self.temp.name) / "cache"
        generated = self.root / "generated"
        generated.mkdir(parents=True)
        image = "a" * 64
        (generated / "manifest.json").write_text(json.dumps({"input_sha256": image, "image_base": 0x140000000}), encoding="utf-8")
        (generated / "function-catalog.json").write_text(json.dumps({
            "schema": 3, "image_sha256": image,
            "functions": [{"id": "fn_0123456789abcdef", "name": "opaque", "rva": 0x1000, "aliases": []}],
            "symbols": [{"id": "sym_0123456789abcdef", "name": "sym_0123456789abcdef", "rva": 0x2000, "aliases": [], "kind": "data-address"}],
        }), encoding="utf-8")
        db = Path(self.temp.name) / "analysis.sqlite"
        conn = sqlite3.connect(db)
        try:
            conn.execute("CREATE TABLE functions (address TEXT, assembly TEXT, clean_assembly TEXT, pseudocode TEXT, clean_pseudo TEXT, prototype TEXT, name TEXT)")
            conn.execute("INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?, ?)",
                         ("0x140001000", "IDA listing", "clean asm", "pseudocode only", "clean pseudo", "void fake()", "sub_140001000"))
            conn.execute("CREATE TABLE replay_ida_function_text (function_rva TEXT, pseudocode TEXT)")
            conn.execute("INSERT INTO replay_ida_function_text VALUES (?, ?)", ("0x1000", "override pseudo"))
            conn.commit()
        finally:
            conn.close()
        self.workspace = SourceWorkspace(self.root, self.cache, db)

    def tearDown(self):
        self.temp.cleanup()

    def test_named_catalog_and_pseudocode_separation(self):
        items, total = self.workspace.list_sources("opaque", kind="function")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], "fn_0123456789abcdef")
        pseudo = self.workspace.get_source(items[0]["id"], "pseudocode")
        self.assertEqual(pseudo["content"], "override pseudo")
        self.assertFalse(pseudo["editable"])
        self.assertFalse(pseudo["compilable"])
        self.assertIn("not source C++", pseudo["provenance"]["note"])
        self.assertEqual(self.workspace._catalog_symbol(0x2000), "sym_0123456789abcdef")

    def test_fresh_baseline_quarantine_hides_legacy_function_but_keeps_global_rows(self):
        self.workspace._rows()  # Prime the pre-migration names and catalog.
        with closing(sqlite3.connect(self.workspace.sqlite_path)) as db:
            db.execute('CREATE TABLE replay_function_quarantine(function_id INTEGER PRIMARY KEY,address TEXT,reason TEXT,evidence_json TEXT)')
            db.execute('INSERT INTO replay_function_quarantine VALUES(1,?,?,?)',
                       ('0x140001000', 'interior label in fresh function', '{}'))
            db.commit()
        functions, count = self.workspace.list_source_rows('', 'function')
        self.assertEqual((functions, count), ([], 0))
        symbols, count = self.workspace.list_source_rows('', 'symbol')
        self.assertEqual(count, 1)
        self.assertEqual(symbols[0]['id'], 'sym_0123456789abcdef')

    def test_full_source_rows_match_paginated_api_and_build_inventory_once(self):
        self.workspace.create_source("workstation_helper", "cpp",
                                     'extern "C" int workstation_helper() { return 3; }\n')
        for kind in (None, "function", "symbol"):
            full_rows, full_total = self.workspace.list_source_rows("", kind)
            self.assertEqual(full_total, len(full_rows))
            paged = []
            offset = 0
            while offset < full_total:
                page, total = self.workspace.list_sources("", offset, 1, kind)
                self.assertEqual(total, full_total)
                self.assertTrue(page)
                paged.extend(page)
                offset += len(page)
            self.assertEqual(paged, full_rows)

        calls = 0
        original_rows = self.workspace._rows

        def counted_rows():
            nonlocal calls
            calls += 1
            return original_rows()

        self.workspace._rows = counted_rows
        rows, total = self.workspace.list_source_rows("", "function")
        self.assertEqual(calls, 1)
        self.assertEqual(len(rows), total)

    def test_functions_without_kind_are_excluded_from_symbol_inventory(self):
        functions, _ = self.workspace.list_source_rows("", "function")
        symbols, _ = self.workspace.list_source_rows("", "symbol")
        self.assertEqual([row["id"] for row in functions], ["fn_0123456789abcdef"])
        self.assertEqual([row["id"] for row in symbols], ["sym_0123456789abcdef"])
        self.assertTrue({row["id"] for row in functions}.isdisjoint(
            row["id"] for row in symbols))

    def test_cpp_revision_and_safe_remove(self):
        code = "extern \"C\" int fn_0123456789abcdef() { return 7; }\n"
        saved = self.workspace.create_source("fn_0123456789abcdef", "cpp", code)
        self.assertTrue(saved["compilable"])
        with self.assertRaises(ValueError):
            self.workspace.save_source(saved["id"], code + "// changed\n", "stale", "cpp")
        removed = self.workspace.remove_source(saved["id"], saved["revision"], "cpp")
        self.assertTrue(Path(removed["archived"]).is_file())
        self.assertFalse((self.root / "src" / f"workstation_{saved['id']}.cpp").exists())

    def test_edit_existing_bound_cpp_uses_open_revision(self):
        src = self.root / "src"
        src.mkdir()
        path = src / "existing.cpp"
        original = 'extern "C" int bound_symbol() { return 1; }\n'
        path.write_text(original, encoding="utf-8")
        units = {"schema": 1, "image_sha256": "a" * 64,
                 "units": [{"source": "src/existing.cpp", "symbol": "bound_symbol", "function_id": "fn_0123456789abcdef"}]}
        (self.root / "source-units.json").write_text(json.dumps(units), encoding="utf-8")
        opened = self.workspace.get_source("fn_0123456789abcdef", "cpp")
        self.assertEqual(opened["revision"], hashlib.sha256(original.encode()).hexdigest())
        updated = self.workspace.save_source(opened["id"], original.replace("return 1", "return 2"), opened["revision"], "cpp")
        self.assertIn("return 2", path.read_text(encoding="utf-8"))
        self.assertNotEqual(updated["revision"], opened["revision"])

    def test_assembly_source_requires_stable_definition(self):
        self.workspace._assembly_source = lambda row: {"id": row["id"], "name": row["name"], "variant": "assembly",
            "language": "x86_64-coff-asm", "content": "", "revision": "base", "editable": True, "compilable": True,
            "provenance": {"basis": "test PE layout"}}
        self.workspace._validate_assembly_candidate = lambda identity, content: {"symbol": identity, "code_size": 1}
        bad = ".intel_syntax noprefix\n.text\n.globl fn_other\nfn_other:\nret\n"
        with self.assertRaises(ValueError):
            self.workspace.create_source("opaque", "assembly", bad)
        good = (".intel_syntax noprefix\n.text\n.globl fn_0123456789abcdef\n.seh_proc fn_0123456789abcdef\n"
                "fn_0123456789abcdef:\n.seh_endprologue\nret\n.seh_endproc\n")
        saved = self.workspace.create_source("opaque", "assembly", good)
        self.assertEqual(saved["content"], good)
        self.assertTrue(saved["compilable"])
        self.assertTrue((self.root / "source-workstation" / "units.json").is_file())

    def test_new_cpp_function_has_no_native_address_claim(self):
        code = 'extern "C" int workstation_helper() { return 3; }\n'
        saved = self.workspace.create_source("workstation_helper", "cpp", code)
        self.assertTrue(saved["id"].startswith("user_"))
        self.assertTrue((self.root / "source-workstation" / "user-functions.json").is_file())
        self.assertIsNone(next(item for item in self.workspace.list_sources(query="workstation_helper")[0]
                               if item["id"] == saved["id"])["rva"])
        revised = self.workspace.save_source(saved["id"], code.replace("return 3", "return 4"), saved["revision"], "cpp")
        self.assertNotEqual(revised["revision"], saved["revision"])
        with self.assertRaises(ValueError):
            self.workspace.save_source(saved["id"], code, saved["revision"], "cpp")
        removed = self.workspace.remove_source(saved["id"], revised["revision"], "cpp")
        self.assertTrue(Path(removed["archived"]).is_file())
        users = json.loads((self.root / "source-workstation" / "user-functions.json").read_text())
        self.assertEqual(users["functions"], {})

    def test_autogenerated_sqlite_names_display_as_opaque_and_refresh(self):
        catalog_path = self.root / "generated" / "function-catalog.json"
        catalog = json.loads(catalog_path.read_text())
        catalog["functions"][0]["name"] = "sub_140001000"
        catalog["functions"][0]["aliases"] = ["sub_140001000"]
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        self.workspace._catalog = None
        self.workspace._sorted_catalog_rows = None

        items, _ = self.workspace.list_sources(kind="function")
        self.assertEqual(items[0]["name"], "func_140001000")
        self.assertIn("sub_140001000", items[0]["aliases"])

        db = sqlite3.connect(self.workspace.sqlite_path)
        try:
            db.execute("UPDATE functions SET name=?", ("BetterNativeName",))
            db.commit()
        finally:
            db.close()
        refreshed, _ = self.workspace.list_sources("BetterNativeName", kind="function")
        self.assertEqual(refreshed[0]["name"], "BetterNativeName")

    def test_wal_only_name_and_text_edits_invalidate_caches_with_fixed_main_mtime(self):
        db_path = self.workspace.sqlite_path
        setup = sqlite3.connect(db_path)
        try:
            self.assertEqual(setup.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower(), "wal")
            setup.commit()
        finally:
            setup.close()

        initial = self.workspace._entry_names()
        initial_text = self.workspace._entry_text()
        self.assertEqual(initial[f"{0x1000:x}"], "sub_140001000")
        self.assertEqual(initial_text[f"{0x1000:x}"]["clean_pseudo"], "clean pseudo")
        main_before = db_path.stat()

        writer = sqlite3.connect(db_path)
        try:
            self.assertEqual(writer.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
            writer.execute("UPDATE functions SET name=?, clean_assembly=?, clean_pseudo=?",
                           ("WalRenamedFunction", "wal assembly", "wal pseudocode"))
            writer.commit()
            wal_path = Path(str(db_path) + "-wal")
            self.assertTrue(wal_path.is_file())
            self.assertGreater(wal_path.stat().st_size, 0)
            main_after = db_path.stat()
            self.assertEqual((main_before.st_size, main_before.st_mtime_ns),
                             (main_after.st_size, main_after.st_mtime_ns))

            self.assertEqual(self.workspace._entry_names()[f"{0x1000:x}"], "WalRenamedFunction")
            text = self.workspace._entry_text()[f"{0x1000:x}"]
            self.assertEqual(text["clean_assembly"], "wal assembly")
            self.assertEqual(text["clean_pseudo"], "wal pseudocode")
        finally:
            writer.close()

    def test_build_compile_reports_external_fixture_path(self):
        from build import compile_one
        source = Path(self.temp.name) / "outside_source.cpp"
        target = Path(self.temp.name) / "outside_source.obj"
        source.write_text('extern "C" int fixture() { return 1; }\n', encoding="utf-8")
        record = compile_one(source, target, cpp=True)
        self.assertEqual(Path(record["source"]), source.resolve())
        self.assertEqual(Path(record["object"]), target.resolve())


if __name__ == "__main__":
    unittest.main()
