import unittest

from tools.cpp_symbol_preflight import SymbolPreflightError, audit_objects, unique_catalog_bindings


def obj(symbols, relocations):
    return {"path": "fixture.obj", "symbols": symbols,
            "sections": [{"name": ".text", "data": bytearray(32), "relocations": relocations}]}


class CatalogBindingTests(unittest.TestCase):
    def test_unique_function_and_data_aliases_bind_by_kind(self):
        catalog = {"functions": [{"id": "fn_a", "name": "native_fn", "rva": 0x1000,
                                  "aliases": ["native_fn", "mangled_fn"]}],
                   "symbols": [{"id": "sym_b", "name": "native_data", "kind": "data-address",
                                "rva": 0x2000, "aliases": ["native_data"]}]}
        bindings, problems = unique_catalog_bindings(catalog, {})
        self.assertEqual(bindings, {"fn_a": 0x1000, "native_fn": 0x1000, "mangled_fn": 0x1000,
                                    "sym_b": 0x2000, "native_data": 0x2000})
        self.assertEqual(problems, [])

    def test_function_data_collision_at_same_address_is_not_unique(self):
        catalog = {"functions": [{"id": "fn_a", "name": "shared", "rva": 0x1000, "aliases": ["shared"]}],
                   "symbols": [{"id": "sym_a", "name": "shared", "kind": "data-address",
                                "rva": 0x1000, "aliases": ["shared"]}]}
        bindings, problems = unique_catalog_bindings(catalog, {})
        self.assertNotIn("shared", bindings)
        self.assertEqual(problems[0]["symbol"], "shared")
        self.assertEqual({row["kind"] for row in problems[0]["candidates"]}, {"function", "data-address"})

    def test_existing_conflicting_native_alias_is_reported(self):
        catalog = {"functions": [{"id": "fn_a", "name": "native_fn", "rva": 0x1000,
                                  "aliases": ["native_fn"]}], "symbols": []}
        bindings, problems = unique_catalog_bindings(catalog, {"native_fn": 0x2000})
        self.assertNotIn("native_fn", bindings)
        self.assertIn("conflicts", problems[0]["reason"])


class CoffPreflightTests(unittest.TestCase):
    def test_accepts_object_definition_common_weak_and_unique_native_alias(self):
        symbols = {
            0: {"name": "defined", "value": 0, "section": 1, "kind": 0x20, "storage": 2},
            1: {"name": "tentative", "value": 8, "section": 0, "kind": 0, "storage": 2},
            2: {"name": "weak_missing", "value": 0, "section": 0, "kind": 0, "storage": 105,
                "weak": {"fallback": 3, "search": 3}},
            3: {"name": "defined", "value": 0, "section": 1, "kind": 0x20, "storage": 2},
            4: {"name": "native_fn", "value": 0, "section": 0, "kind": 0, "storage": 2},
        }
        value = obj(symbols, [(0, 0, 4), (4, 1, 1), (8, 2, 4), (12, 4, 4)])
        catalog = {"functions": [{"id": "fn_a", "name": "native_fn", "rva": 0x1000,
                                  "aliases": ["native_fn"]}], "symbols": []}
        result = audit_objects([value], {}, catalog, 0x10000)
        self.assertEqual(result["relocations_checked"], 4)
        self.assertEqual(result["weak_fallbacks_used"][0]["fallback"], "defined")
        self.assertEqual(result["common_symbols_used"][0]["size"], 8)
        self.assertEqual(result["unresolved"], [])

    def test_import_thunk_is_not_guessed_from_function_name(self):
        value = obj({0: {"name": "__imp_native_fn", "value": 0, "section": 0,
                         "kind": 0, "storage": 2}}, [(0, 0, 1)])
        catalog = {"functions": [{"id": "fn_a", "name": "native_fn", "rva": 0x1000,
                                  "aliases": ["native_fn"]}], "symbols": []}
        with self.assertRaisesRegex(SymbolPreflightError, "__imp_native_fn"):
            audit_objects([value], {}, catalog, 0x10000)

    def test_reports_unresolved_crt_symbol_with_object_location(self):
        value = obj({0: {"name": "memcmp", "value": 0, "section": 0, "kind": 0, "storage": 2}},
                    [(8, 0, 4)])
        with self.assertRaisesRegex(SymbolPreflightError, r"memcmp.*fixture\.obj:\.text\+0x8"):
            audit_objects([value], {}, {"functions": [], "symbols": []}, 0x10000)

    def test_rejects_out_of_image_raw_rva(self):
        value = obj({0: {"name": "replay_rva_00010000", "value": 0, "section": 0,
                         "kind": 0, "storage": 2}}, [(0, 0, 4)])
        with self.assertRaisesRegex(SymbolPreflightError, "outside SizeOfImage"):
            audit_objects([value], {}, {"functions": [], "symbols": []}, 0x10000)


if __name__ == "__main__":
    unittest.main()
