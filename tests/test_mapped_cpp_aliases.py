import hashlib
import collections
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build
import coff
import mapped_cpp_aliases
import source_catalog


CLANG = build.LLVM / "clang++.exe"


class MappedCppAliasTests(unittest.TestCase):
    def test_automatic_cpp_aliases_exclude_retired_function_identities(self):
        catalog = {'image_base': 0x140000000,
                   'functions': [{'id': 'fn_live', 'name': 'sub_140001000', 'rva': 0x1000, 'aliases': []},
                                 {'id': 'fn_retired', 'name': 'OldFalseEntry', 'rva': 0x1100,
                                  'aliases': [], 'quarantined': True}],
                   'symbols': [{'id': 'sym_data', 'name': 'dword_140002000', 'rva': 0x2000,
                                'kind': 'data-address', 'aliases': []}]}
        candidates, unique = mapped_cpp_aliases._catalog_alias_rows(catalog)
        self.assertEqual(unique['func_140001000']['id'], 'fn_live')
        self.assertEqual(unique['gl_140002000']['id'], 'sym_data')
        self.assertNotIn('fn_retired', candidates)
        self.assertNotIn('OldFalseEntry', unique)
        self.assertNotIn('func_140001100', candidates)

    def _compile(self, source_text, basename="mapped", headers=None):
        temp = tempfile.TemporaryDirectory(prefix="mapped-cpp-alias-", dir=ROOT)
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name)
        source = folder / f"{basename}.cpp"
        target = folder / f"{basename}.obj"
        dependencies = []
        for header_name, header_text in (headers or {}).items():
            header = folder / header_name
            header.write_text(header_text, encoding="utf-8")
            dependencies.append({"path": str(header), "sha256": hashlib.sha256(header.read_bytes()).hexdigest()})
        source.write_text(source_text, encoding="utf-8")
        command = [str(CLANG), "--target=x86_64-pc-windows-msvc", "-c", str(source), "-o", str(target),
                   "-ffunction-sections", "-fdata-sections", "-fno-inline", "-O0", "-std=c++20",
                   "-I", str(folder)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        obj = coff.read(target)
        record = {"source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "object": str(target), "object_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                  "compiler": {"path": str(CLANG), "sha256": hashlib.sha256(CLANG.read_bytes()).hexdigest()},
                  "command": command, "dependencies": dependencies}
        return folder, record, obj

    def test_generated_function_and_global_aliases_bind_real_cpp_imports(self):
        folder, record, obj = self._compile(
            'int func_140001000(int); extern int gl_140002000;\n'
            'int Caller() { return func_140001000(7) + gl_140002000; }\n', basename='automatic_cpp_imports')
        catalog = {'image_sha256': 'e' * 64, 'image_base': 0x140000000,
                   'functions': [{'id': 'fn_native', 'name': 'sub_140001000', 'rva': 0x1000, 'aliases': []}],
                   'symbols': [{'id': 'sym_native', 'name': 'dword_140002000', 'rva': 0x2000,
                                'kind': 'data-address', 'aliases': []}]}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            {'schema': 1, 'units': [], 'imports': []}, [record], [obj], ROOT, catalog_document=catalog)
        self.assertEqual({entry['native_alias'] for entry in aliases}, {'func_140001000', 'gl_140002000'})
        path = folder / 'catalog.json'
        path.write_text(json.dumps(catalog), encoding='utf8')
        native = source_catalog.unique_alias_targets(catalog)
        source_catalog.resolve({'input_sha256': catalog['image_sha256']}, native, [obj], path, resolved)
        import cpp_symbol_preflight
        audit = cpp_symbol_preflight.audit_objects([obj], native, catalog, 0x4000)
        self.assertGreaterEqual(audit['relocations_checked'], 2)
        self.assertEqual(audit['unresolved'], [])

    def test_plain_definition_with_declaration_and_internal_call_maps_exact_coff_name(self):
        folder, record, obj = self._compile(
            "void EngineReplacement();\n"
            "void EngineReplacement() {}\n"
            "void InternalCaller() { EngineReplacement(); }\n")
        authored_bytes = Path(record["source"]).read_bytes()
        unit = {"source": str(record["source"]), "symbol": "EngineReplacement", "function_id": "fn_native"}
        source_doc = {"schema": 1, "units": [unit], "imports": [], "other_contract_field": "keep"}
        mapped_doc, aliases = mapped_cpp_aliases.resolve_units(source_doc, [record], [obj], ROOT)
        self.assertEqual(len(aliases), 1)
        mangled = aliases[0]["coff_symbol"]
        self.assertEqual(mapped_doc["units"][0]["symbol"], mangled)
        self.assertEqual(mapped_doc["other_contract_field"], "keep")
        self.assertEqual(mapped_doc["imports"], [{"symbol": "EngineReplacement", "symbol_id": "fn_native"}])
        self.assertEqual(Path(record["source"]).read_bytes(), authored_bytes)
        self.assertNotIn(b'extern "C"', authored_bytes)
        self.assertTrue(mangled.startswith("?EngineReplacement@@"))
        caller_folder, caller_record, caller_obj = self._compile(
            'void EngineReplacement();\n'
            "void ExternalCaller() { EngineReplacement(); }\n", basename="external_caller")
        self.assertNotEqual(caller_folder, folder)
        catalog_path = folder / "catalog.json"
        catalog_path.write_text(json.dumps({
            "image_sha256": "a" * 64,
            "functions": [{"id": "fn_native", "rva": 0x1800}],
            "symbols": [],
        }), encoding="utf-8")
        native = {}
        source_catalog.resolve({"input_sha256": "a" * 64}, native, [obj, caller_obj],
                               catalog_path=catalog_path, document=mapped_doc)
        self.assertEqual(native[mangled], 0x1800)
        self.assertEqual(native["EngineReplacement"], 0x1800)
        self.assertEqual(native["?EngineReplacement@@YAXXZ"], 0x1800)
        references = {obj["symbols"][index]["name"]
                      for section in obj["sections"] for _offset, index, _kind in section["relocations"]}
        self.assertIn(mangled, references)

        manifest = {
            "sections": [{"name": ".text", "rva": 0x1000, "virtual_size": 0x1000},
                         {"name": ".rdata", "rva": 0x3000},
                         {"name": ".data", "rva": 0x4000, "virtual_size": 0x100},
                         {"name": ".pdata", "rva": 0x5000}],
            "optional": {"SizeOfImage": 0x6000, "SectionAlignment": 0x1000},
            "replacements": [{"symbol": mangled, "begin": 0x1800, "end": 0x1810}],
            "image_base": 0x140000000,
        }

        class IdentityLayout:
            @staticmethod
            def map(value):
                return value

        symbols, placements, _sections, _tail, _bss = build.place_cpp(
            [obj, caller_obj], native, manifest, IdentityLayout(), False)
        self.assertEqual(symbols[mangled], 0x1800)
        self.assertTrue(any(row["symbol"] == mangled and row["placement"] == "original_function"
                            for row in placements))
        caller_symbol = next(symbol for symbol in caller_obj["symbols"].values()
                             if symbol["name"].startswith("?ExternalCaller@@") and symbol["section"] > 0)
        caller_section = caller_obj["sections"][caller_symbol["section"] - 1]
        stats = collections.defaultdict(int)
        relocated = build.relocate(caller_obj, caller_section, symbols, manifest, stats, set())
        call_refs = [(offset, kind) for offset, index, kind in caller_section["relocations"]
                     if caller_obj["symbols"][index]["name"] == mangled]
        self.assertTrue(call_refs, [caller_obj["symbols"][index]["name"]
                                    for _offset, index, _kind in caller_section["relocations"]])
        for offset, kind in call_refs:
            displacement = int.from_bytes(relocated[offset:offset + 4], "little", signed=True)
            self.assertEqual(caller_section["rva"] + offset + 4 + kind - 4 + displacement, 0x1800)

    def test_plain_cpp_import_is_resolved_by_ast_name_and_relocated(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(7); }\n',
            basename="import_caller", headers={"engine_decl.h": "void EngineImport(int);\n"})
        source_doc = {"schema": 1, "units": [],
                      "imports": [{"symbol": "EngineImport", "symbol_id": "fn_import"}],
                      "additional_metadata": {"preserve": True}}
        mapped_doc, aliases = mapped_cpp_aliases.resolve_units(source_doc, [record], [obj], ROOT)
        self.assertEqual(mapped_doc["additional_metadata"], {"preserve": True})
        imported = next(item for item in mapped_doc["imports"] if item["symbol"].startswith("?EngineImport@@"))
        self.assertEqual(imported["symbol_id"], "fn_import")
        self.assertEqual(len(aliases), 1)
        self.assertEqual(aliases[0]["mapping_kind"], "cpp-import")

        catalog_path = _folder / "catalog.json"
        catalog_path.write_text(json.dumps({
            "image_sha256": "b" * 64,
            "functions": [{"id": "fn_import", "rva": 0x2222}],
            "symbols": [],
        }), encoding="utf-8")
        native = {}
        source_catalog.resolve({"input_sha256": "b" * 64}, native, [obj],
                               catalog_path=catalog_path, document=mapped_doc)
        decorated = imported["symbol"]
        self.assertEqual(native["EngineImport"], 0x2222)
        self.assertEqual(native[decorated], 0x2222)
        manifest = {
            "sections": [{"name": ".text", "rva": 0x1000, "virtual_size": 0x1000},
                         {"name": ".rdata", "rva": 0x3000},
                         {"name": ".data", "rva": 0x4000, "virtual_size": 0x100},
                         {"name": ".pdata", "rva": 0x5000}],
            "optional": {"SizeOfImage": 0x6000, "SectionAlignment": 0x1000},
            "replacements": [], "image_base": 0x140000000,
        }

        class IdentityLayout:
            @staticmethod
            def map(value):
                return value

        symbols, _placements, _sections, _tail, _bss = build.place_cpp(
            [obj], native, manifest, IdentityLayout(), False)
        caller = next(symbol for symbol in obj["symbols"].values()
                      if symbol["name"].startswith("?ImportedCaller@@") and symbol["section"] > 0)
        section = obj["sections"][caller["section"] - 1]
        stats = collections.defaultdict(int)
        relocated = build.relocate(obj, section, symbols, manifest, stats, set())
        call_refs = [(offset, kind) for offset, index, kind in section["relocations"]
                     if obj["symbols"][index]["name"] == decorated]
        self.assertTrue(call_refs)
        for offset, kind in call_refs:
            displacement = int.from_bytes(relocated[offset:offset + 4], "little", signed=True)
            self.assertEqual(section["rva"] + offset + 4 + kind - 4 + displacement, 0x2222)

    def test_namespaced_replacement_uses_exact_ast_identity(self):
        _folder, record, obj = self._compile(
            "namespace Replay { void EngineReplacement() {} }\n", basename="namespaced")
        unit = {"source": record["source"], "symbol": "EngineReplacement", "function_id": "fn_native"}
        mapped_doc, aliases = mapped_cpp_aliases.resolve_units(
            {"schema": 1, "units": [unit], "imports": []}, [record], [obj], ROOT)
        exact_name = aliases[0]["coff_symbol"]
        self.assertIn("@Replay@@", exact_name)
        self.assertEqual(mapped_doc["units"][0]["symbol"], exact_name)

    def test_namespaced_cpp_import_fails_without_catalog_namespace_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { Replay::EngineImport(7); }\n',
            basename="namespaced_import",
            headers={"engine_decl.h": "namespace Replay { void EngineImport(int); }\n"})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "fn_import"}]}
        with self.assertRaisesRegex(ValueError, r"Namespace-scoped C\+\+ function import"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT)

    def test_plain_cpp_global_import_uses_exact_var_decl_and_coff_name(self):
        _folder, record, obj = self._compile(
            '#include "engine_global.h"\n'
            'int ReadNativeGlobal() { return NativeGlobal; }\n'
            'int ReadLocalShadow() { int NativeGlobal = 2; return NativeGlobal; }\n',
            basename="global_caller", headers={"engine_global.h": "extern int NativeGlobal;\n"})
        catalog = {"image_sha256": "d" * 64, "functions": [],
                   "symbols": [{"id": "fn_global", "rva": 0x3100,
                                "name": "NativeGlobal", "aliases": []}]}
        document = {"schema": 1, "units": [], "imports": []}
        mapped_doc, aliases = mapped_cpp_aliases.resolve_units(
            document, [record], [obj], ROOT, catalog_document=catalog)
        decorated = "?NativeGlobal@@3HA"
        self.assertIn({"symbol": decorated, "symbol_id": "fn_global"}, mapped_doc["imports"])
        self.assertEqual(aliases[0]["coff_symbol"], decorated)
        self.assertEqual(aliases[0]["entity_kind"], "variable")

        catalog_path = _folder / "catalog.json"
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        native = {}
        source_catalog.resolve({"input_sha256": "d" * 64}, native, [obj],
                               catalog_path=catalog_path, document=mapped_doc)
        self.assertEqual(native["NativeGlobal"], 0x3100)
        self.assertEqual(native[decorated], 0x3100)
        manifest = {
            "sections": [{"name": ".text", "rva": 0x1000, "virtual_size": 0x1000},
                         {"name": ".rdata", "rva": 0x3000},
                         {"name": ".data", "rva": 0x4000, "virtual_size": 0x100},
                         {"name": ".pdata", "rva": 0x5000}],
            "optional": {"SizeOfImage": 0x6000, "SectionAlignment": 0x1000},
            "replacements": [], "image_base": 0x140000000,
        }

        class IdentityLayout:
            @staticmethod
            def map(value):
                return value

        symbols, _placements, _sections, _tail, _bss = build.place_cpp(
            [obj], native, manifest, IdentityLayout(), False)
        caller = next(symbol for symbol in obj["symbols"].values()
                      if symbol["name"].startswith("?ReadNativeGlobal@@") and symbol["section"] > 0)
        section = obj["sections"][caller["section"] - 1]
        stats = collections.defaultdict(int)
        relocated = build.relocate(obj, section, symbols, manifest, stats, set())
        references = [(offset, kind) for offset, index, kind in section["relocations"]
                      if obj["symbols"][index]["name"] == decorated]
        self.assertTrue(references)
        for offset, kind in references:
            displacement = int.from_bytes(relocated[offset:offset + 4], "little", signed=True)
            self.assertEqual(section["rva"] + offset + 4 + kind - 4 + displacement, 0x3100)

    def test_catalog_name_supplies_plain_cpp_function_import_without_manual_row(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(7); }\n',
            basename="inferred_import", headers={"engine_decl.h": "void EngineImport(int);\n"})
        catalog = {"image_sha256": "e" * 64,
                   "functions": [{"id": "fn_import", "rva": 0x2320,
                                  "name": "EngineImport", "aliases": []}],
                   "symbols": []}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            {"schema": 1, "units": [], "imports": []}, [record], [obj], ROOT,
            catalog_document=catalog)
        decorated = "?EngineImport@@YAXH@Z"
        self.assertIn({"symbol": "EngineImport", "symbol_id": "fn_import"}, resolved["imports"])
        self.assertIn({"symbol": decorated, "symbol_id": "fn_import"}, resolved["imports"])
        self.assertEqual(aliases[0]["mapping_kind"], "catalog-cpp-import")

        catalog_path = _folder / "catalog.json"
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        native = {}
        source_catalog.resolve({"input_sha256": "e" * 64}, native, [obj],
                               catalog_path=catalog_path, document=resolved)
        self.assertEqual(native[decorated], 0x2320)

    def test_ambiguous_catalog_name_does_not_guess_cpp_import_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(7); }\n',
            basename="ambiguous_catalog_import", headers={"engine_decl.h": "void EngineImport(int);\n"})
        catalog = {"image_sha256": "f" * 64,
                   "functions": [{"id": "fn_import_a", "rva": 0x2320,
                                  "name": "EngineImport", "aliases": []},
                                 {"id": "fn_import_b", "rva": 0x2340,
                                  "name": "EngineImport", "aliases": []}],
                   "symbols": []}
        with self.assertRaisesRegex(ValueError, r"Ambiguous catalog alias for C\+\+ import"):
            mapped_cpp_aliases.resolve_units({"schema": 1, "units": [], "imports": []},
                                             [record], [obj], ROOT, catalog_document=catalog)

    def test_stable_catalog_id_can_be_the_plain_cpp_import_name(self):
        identity = "fn_0123456789abcdef"
        _folder, record, obj = self._compile(
            f'#include "engine_decl.h"\nvoid ImportedCaller() {{ {identity}(); }}\n',
            basename="stable_id_import",
            headers={"engine_decl.h": f"void {identity}();\n"})
        catalog = {"image_sha256": "1" * 64,
                   "functions": [{"id": identity, "rva": 0x2380,
                                  "name": "CurrentFriendlyName", "aliases": []}],
                   "symbols": []}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            {"schema": 1, "units": [], "imports": []}, [record], [obj], ROOT,
            catalog_document=catalog)
        decorated = next(symbol["name"] for symbol in obj["symbols"].values()
                         if identity in symbol["name"] and symbol["section"] == 0)
        self.assertIn({"symbol": identity, "symbol_id": identity}, resolved["imports"])
        self.assertIn({"symbol": decorated, "symbol_id": identity}, resolved["imports"])
        self.assertEqual(aliases[0]["coff_symbol"], decorated)

    def test_ast_function_kind_cannot_bind_to_catalog_data_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(7); }\n',
            basename="kind_mismatch", headers={"engine_decl.h": "void EngineImport(int);\n"})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "sym_data"}]}
        catalog = {"image_sha256": "2" * 64, "functions": [],
                   "symbols": [{"id": "sym_data", "rva": 0x4400,
                                "name": "EngineImport", "aliases": []}]}
        with self.assertRaisesRegex(ValueError, "AST kind conflicts with catalog identity"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT, catalog_document=catalog)

    def test_plain_c_function_import_cannot_bind_to_data_address_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(); }\n',
            basename="plain_c_function_kind",
            headers={"engine_decl.h": 'extern "C" void EngineImport();\n'})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "sym_data"}]}
        catalog = {"image_sha256": "3" * 64, "functions": [],
                   "symbols": [{"id": "sym_data", "rva": 0x4500,
                                "name": "EngineImport", "kind": "data-address", "aliases": []}]}
        with self.assertRaisesRegex(ValueError, "AST kind conflicts with catalog identity"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT, catalog_document=catalog)

    def test_plain_c_variable_import_cannot_bind_to_function_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nint ReadImportedGlobal() { return EngineGlobal; }\n',
            basename="plain_c_variable_kind",
            headers={"engine_decl.h": 'extern "C" int EngineGlobal;\n'})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineGlobal", "symbol_id": "fn_global"}]}
        catalog = {"image_sha256": "4" * 64,
                   "functions": [{"id": "fn_global", "rva": 0x4600,
                                  "name": "EngineGlobal", "aliases": []}],
                   "symbols": []}
        with self.assertRaisesRegex(ValueError, "AST kind conflicts with catalog identity"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT, catalog_document=catalog)

    def test_plain_c_import_kind_matches_catalog_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(); }\n',
            basename="plain_c_function_valid",
            headers={"engine_decl.h": 'extern "C" void EngineImport();\n'})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "fn_import"}]}
        catalog = {"image_sha256": "5" * 64,
                   "functions": [{"id": "fn_import", "rva": 0x4700,
                                  "name": "EngineImport", "aliases": []}],
                   "symbols": []}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            doc, [record], [obj], ROOT, catalog_document=catalog)
        self.assertEqual(resolved, doc)
        self.assertEqual(aliases, [])  # Existing C linkage stays byte-for-byte unchanged.

    def test_function_import_may_use_a_catalog_code_label_identity(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(); }\n',
            basename="function_code_label_import",
            headers={"engine_decl.h": 'extern "C" void EngineImport();\n'})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "sym_code"}]}
        catalog = {"image_sha256": "7" * 64, "functions": [],
                   "symbols": [{"id": "sym_code", "rva": 0x4800,
                                "name": "EngineImport", "kind": "code-label", "aliases": []}]}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            doc, [record], [obj], ROOT, catalog_document=catalog)
        self.assertEqual(resolved, doc)
        self.assertEqual(aliases, [])

    def test_implicit_plain_c_function_cannot_bind_to_data_address_alias(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { NativeDataAlias(); }\n',
            basename="implicit_c_function_kind",
            headers={"engine_decl.h": 'extern "C" void NativeDataAlias();\n'})
        doc = {"schema": 1, "units": [], "imports": []}
        catalog = {"image_sha256": "8" * 64, "functions": [],
                   "symbols": [{"id": "sym_data", "rva": 0x4900,
                                "name": "OtherName", "kind": "data-address",
                                "aliases": ["NativeDataAlias"]}]}
        with self.assertRaisesRegex(ValueError, "AST kind conflicts with catalog identity"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT, catalog_document=catalog)

    def test_implicit_plain_c_function_catalog_alias_is_validated_without_rebinding(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { NativeFunctionAlias(); }\n',
            basename="implicit_c_function_valid",
            headers={"engine_decl.h": 'extern "C" void NativeFunctionAlias();\n'})
        doc = {"schema": 1, "units": [], "imports": []}
        catalog = {"image_sha256": "9" * 64,
                   "functions": [{"id": "fn_native", "rva": 0x4A00,
                                  "name": "OtherName", "aliases": ["NativeFunctionAlias"]}],
                   "symbols": []}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            doc, [record], [obj], ROOT, catalog_document=catalog)
        self.assertEqual(resolved, doc)
        self.assertEqual(aliases, [])

    def test_implicit_plain_c_variable_data_alias_is_validated_without_rebinding(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nint ReadNativeGlobal() { return NativeGlobalAlias; }\n',
            basename="implicit_c_variable_valid",
            headers={"engine_decl.h": 'extern "C" int NativeGlobalAlias;\n'})
        doc = {"schema": 1, "units": [], "imports": []}
        catalog = {"image_sha256": "a" * 64, "functions": [],
                   "symbols": [{"id": "sym_native", "rva": 0x4B00,
                                "name": "OtherName", "kind": "data-address",
                                "aliases": ["NativeGlobalAlias"]}]}
        resolved, aliases = mapped_cpp_aliases.resolve_units(
            doc, [record], [obj], ROOT, catalog_document=catalog)
        self.assertEqual(resolved, doc)
        self.assertEqual(aliases, [])

    def test_c_data_definition_cannot_replace_a_native_function(self):
        _folder, record, obj = self._compile(
            'extern "C" { int EngineReplacement = 7; }\n',
            basename="c_data_replacement")
        unit = {"source": record["source"], "symbol": "EngineReplacement",
                "function_id": "fn_native"}
        with self.assertRaisesRegex(ValueError, "not an external function in executable text"):
            mapped_cpp_aliases.resolve_units(
                {"schema": 1, "units": [unit], "imports": []}, [record], [obj], ROOT)

        catalog_path = Path(record["source"]).with_name("catalog.json")
        catalog_path.write_text(json.dumps({"image_sha256": "6" * 64,
                                            "functions": [{"id": "fn_native", "rva": 0x1800}],
                                            "symbols": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not define an executable function"):
            source_catalog.resolve({"input_sha256": "6" * 64}, {},
                                   [dict(obj, path=record["object"], source_path=record["source"])],
                                   catalog_path=catalog_path,
                                   document={"units": [unit], "imports": []})

        manifest = {
            "sections": [{"name": ".text", "rva": 0x1000, "virtual_size": 0x100},
                         {"name": ".rdata", "rva": 0x2000},
                         {"name": ".data", "rva": 0x3000, "virtual_size": 0x100},
                         {"name": ".pdata", "rva": 0x4000}],
            "optional": {"SizeOfImage": 0x5000, "SectionAlignment": 0x1000},
            "replacements": [{"symbol": "EngineReplacement", "begin": 0x1800, "end": 0x1810}],
            "image_base": 0x140000000,
        }

        class IdentityLayout:
            @staticmethod
            def map(value):
                return value

        with self.assertRaisesRegex(ValueError, "external function in executable text"):
            build.place_cpp([obj], {}, manifest, IdentityLayout(), False)

    def test_nonexecutable_text_section_cannot_supply_a_function(self):
        _folder, record, obj = self._compile(
            'extern "C" void EngineReplacement() { }\n',
            basename="nonexecutable_text_replacement")
        unit = {"source": record["source"], "symbol": "EngineReplacement",
                "function_id": "fn_native"}
        function = next(symbol for symbol in obj["symbols"].values()
                        if symbol["name"] == "EngineReplacement" and symbol["section"] > 0)
        text_section = obj["sections"][function["section"] - 1]
        self.assertEqual(text_section["name"].split("$")[0], ".text")
        self.assertTrue(text_section["flags"] & 0x20)
        text_section["flags"] &= ~0x20000000

        with self.assertRaisesRegex(ValueError, "not an external function in executable text"):
            mapped_cpp_aliases.resolve_units(
                {"schema": 1, "units": [unit], "imports": []}, [record], [obj], ROOT)

        catalog_path = Path(record["source"]).with_name("nonexecutable-catalog.json")
        catalog_path.write_text(json.dumps({"image_sha256": "7" * 64,
                                            "functions": [{"id": "fn_native", "rva": 0x1900}],
                                            "symbols": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not define an executable function"):
            source_catalog.resolve({"input_sha256": "7" * 64}, {},
                                   [dict(obj, path=record["object"], source_path=record["source"])],
                                   catalog_path=catalog_path,
                                   document={"units": [unit], "imports": []})

        manifest = {
            "sections": [{"name": ".text", "rva": 0x1000, "virtual_size": 0x100},
                         {"name": ".rdata", "rva": 0x2000},
                         {"name": ".data", "rva": 0x3000, "virtual_size": 0x100},
                         {"name": ".pdata", "rva": 0x4000}],
            "optional": {"SizeOfImage": 0x5000, "SectionAlignment": 0x1000},
            "replacements": [{"symbol": "EngineReplacement", "begin": 0x1900, "end": 0x1910}],
            "image_base": 0x140000000,
        }

        class IdentityLayout:
            @staticmethod
            def map(value):
                return value

        with self.assertRaisesRegex(ValueError, "external function in executable text"):
            build.place_cpp([obj], {}, manifest, IdentityLayout(), False)

    def test_overloaded_import_fails_closed_even_if_one_overload_is_called(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid ImportedCaller() { EngineImport(7); }\n',
            basename="ambiguous_import",
            headers={"engine_decl.h": "void EngineImport(int);\nvoid EngineImport(float);\n"})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "fn_import"}]}
        with self.assertRaisesRegex(ValueError, r"Imported C\+\+ function is overloaded or ambiguous"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT)

    def test_macro_pasted_header_only_import_is_found_from_coff_candidate(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nint CallHeaderHelper() { return HeaderHelper(); }\n',
            basename="macro_import",
            headers={"engine_decl.h":
                     "#define JOIN(a, b) a##b\n"
                     "#define IMPORT_NAME JOIN(Engine, Import)\n"
                     "int IMPORT_NAME(int);\n"
                     "inline int HeaderHelper() { return IMPORT_NAME(5); }\n"})
        self.assertNotIn("EngineImport", Path(record["source"]).read_text(encoding="utf-8"))
        self.assertTrue(any("EngineImport" in symbol["name"] and symbol["section"] == 0
                            for symbol in obj["symbols"].values()))
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "EngineImport", "symbol_id": "fn_import"}]}
        mapped_doc, aliases = mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT)
        exact_name = next(symbol["name"] for symbol in obj["symbols"].values()
                          if "EngineImport" in symbol["name"] and symbol["section"] == 0)
        self.assertIn({"symbol": exact_name, "symbol_id": "fn_import"}, mapped_doc["imports"])
        self.assertEqual(aliases[0]["coff_symbol"], exact_name)

    def test_tls_global_import_fails_closed(self):
        _folder, record, obj = self._compile(
            '#include "engine_global.h"\nint ReadNativeGlobal() { return NativeGlobal; }\n',
            basename="tls_global", headers={"engine_global.h": "extern thread_local int NativeGlobal;\n"})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "NativeGlobal", "symbol_id": "fn_global"}]}
        with self.assertRaisesRegex(ValueError, "TLS variable requires an explicit TLS binding"):
            mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT)

    def test_dllimport_global_keeps_imp_symbol_unmodified(self):
        _folder, record, obj = self._compile(
            '#include "engine_global.h"\nint ReadNativeGlobal() { return NativeGlobal; }\n',
            basename="dllimport_global",
            headers={"engine_global.h": "__declspec(dllimport) extern int NativeGlobal;\n"})
        doc = {"schema": 1, "units": [],
               "imports": [{"symbol": "NativeGlobal", "symbol_id": "fn_global"}]}
        mapped, aliases = mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT)
        self.assertEqual(mapped, doc)
        self.assertEqual(aliases, [])
        self.assertTrue(any("__imp_" in symbol["name"] and "NativeGlobal" in symbol["name"]
                            for symbol in obj["symbols"].values()))

    def test_real_build_call_shape_preserves_imports_document(self):
        _folder, record, obj = self._compile("void EngineReplacement() {}\n")
        unit = {"source": str(record["source"]), "symbol": "EngineReplacement", "function_id": "fn_native"}
        document = {"schema": 1, "units": [unit],
                    "imports": [{"symbol": "ExistingNative", "symbol_id": "fn_existing"}],
                    "compiler_profile": "pinned"}
        resolved_units_doc, aliases = mapped_cpp_aliases.resolve_units(document, [record], [obj], ROOT)
        self.assertIn("compiler_profile", resolved_units_doc)
        self.assertEqual(resolved_units_doc["imports"][0], document["imports"][0])
        catalog_path = _folder / "catalog.json"
        catalog_path.write_text(json.dumps({
            "image_sha256": "c" * 64,
            "functions": [{"id": "fn_native", "rva": 0x1800},
                          {"id": "fn_existing", "rva": 0x2300}],
            "symbols": [],
        }), encoding="utf-8")
        native = {}
        source_catalog.resolve({"input_sha256": "c" * 64}, native, [obj],
                               catalog_path=catalog_path, document=resolved_units_doc)
        self.assertEqual(native["ExistingNative"], 0x2300)
        self.assertEqual(native[aliases[0]["coff_symbol"]], 0x1800)

    def test_root_relative_compile_record_is_independent_of_process_cwd(self):
        folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid EngineReplacement() {}\n',
            basename="relative_record", headers={"engine_decl.h": "void EngineReplacement();\n"})
        relative = lambda path: Path(path).resolve().relative_to(ROOT).as_posix()
        record["source"] = relative(record["source"])
        record["object"] = relative(record["object"])
        record["dependencies"] = [dict(item, path=relative(item["path"]))
                                  for item in record["dependencies"]]
        record["command"] = [relative(arg) if arg in (str(folder / "relative_record.cpp"),
                                                     str(folder / "relative_record.obj"),
                                                     str(folder)) else arg
                             for arg in record["command"]]
        unit = {"source": record["source"], "symbol": "EngineReplacement", "function_id": "fn_native"}
        original_cwd = Path.cwd()
        unrelated_cwd = Path(tempfile.gettempdir()).resolve()
        self.assertNotEqual(unrelated_cwd, ROOT)
        try:
            os.chdir(unrelated_cwd)
            mapped, aliases = mapped_cpp_aliases.resolve_units(
                {"schema": 1, "units": [unit], "imports": []}, [record], [obj], ROOT)
        finally:
            os.chdir(original_cwd)
        self.assertEqual(len(aliases), 1)
        self.assertTrue(mapped["units"][0]["symbol"].startswith("?EngineReplacement@@"))

    def test_existing_c_linkage_definition_stays_unchanged(self):
        _folder, record, obj = self._compile('extern "C" void EngineReplacement() {}\n')
        unit = {"source": record["source"], "symbol": "EngineReplacement", "function_id": "fn_native"}
        doc = {"schema": 1, "units": [unit], "imports": []}
        mapped, aliases = mapped_cpp_aliases.resolve_units(doc, [record], [obj], ROOT)
        self.assertEqual(mapped, doc)
        self.assertEqual(aliases, [])

    def test_overload_set_fails_closed(self):
        _folder, record, obj = self._compile("void EngineReplacement() {}\nvoid EngineReplacement(int) {}\n")
        with self.assertRaisesRegex(ValueError, "overloaded or has ambiguous"):
            mapped_cpp_aliases.resolve_definition(record, "EngineReplacement", obj)

    def test_member_function_fails_closed(self):
        _folder, record, obj = self._compile("struct Widget { void EngineReplacement() {} };\n")
        with self.assertRaisesRegex(ValueError, "member function"):
            mapped_cpp_aliases.resolve_definition(record, "EngineReplacement", obj)

    def test_function_template_fails_closed(self):
        _folder, record, obj = self._compile(
            "template<class T> void EngineReplacement(T) {}\n")
        with self.assertRaisesRegex(ValueError, "template"):
            mapped_cpp_aliases.resolve_definition(record, "EngineReplacement", obj)

    def test_internal_linkage_fails_closed(self):
        _folder, record, obj = self._compile("static void EngineReplacement() {}\n")
        with self.assertRaisesRegex(ValueError, "no external free-function definition|internal linkage"):
            mapped_cpp_aliases.resolve_definition(record, "EngineReplacement", obj)

    def test_header_overload_makes_replacement_ambiguous(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid EngineReplacement() {}\n',
            basename="ambiguous_header",
            headers={"engine_decl.h": "void EngineReplacement();\nvoid EngineReplacement(int);\n"})
        unit = {"source": record["source"], "symbol": "EngineReplacement", "function_id": "fn_native"}
        with self.assertRaisesRegex(ValueError, "Header declaration makes mapped function name ambiguous"):
            mapped_cpp_aliases.resolve_units({"schema": 1, "units": [unit], "imports": []},
                                             [record], [obj], ROOT)

    def test_ast_boundary_rechecks_header_dependency_hash(self):
        _folder, record, obj = self._compile(
            '#include "engine_decl.h"\nvoid EngineReplacement() {}\n',
            basename="header_drift", headers={"engine_decl.h": "void EngineReplacement();\n"})
        unit = {"source": record["source"], "symbol": "EngineReplacement", "function_id": "fn_native"}
        real_run = mapped_cpp_aliases.subprocess.run

        def mutate_after_ast(*args, **kwargs):
            result = real_run(*args, **kwargs)
            header = Path(record["dependencies"][0]["path"])
            header.write_text("void EngineReplacement(int);\n", encoding="utf-8")
            return result

        with mock.patch.object(mapped_cpp_aliases.subprocess, "run", side_effect=mutate_after_ast):
            with self.assertRaisesRegex(ValueError, "header dependency changed after AST extraction"):
                mapped_cpp_aliases.resolve_units({"schema": 1, "units": [unit], "imports": []},
                                                 [record], [obj], ROOT)


if __name__ == "__main__":
    unittest.main()
