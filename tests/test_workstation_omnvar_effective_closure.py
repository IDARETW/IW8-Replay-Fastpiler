from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from workstation_fastfiles import _validate_omnvar_effective_closure  # noqa: E402


def definition(name: str, value: str) -> list[str]:
    return [name, "1", "", "c", "i", value, "-10", "10", "", "", "", "", "", ""]


def include(path: str) -> list[str]:
    return ["include", path, *("" for _ in range(12))]


class EffectiveOmnvarClosureTests(unittest.TestCase):
    def fixture(self):
        root_rows = [include("omnvars/mp/included8.csv"),
                     include("omnvars/mp/included20.csv"), definition("root_value", "1")]
        included8_rows = [["included8_value", "1", "", "c", "i", "2", "-10", "10"]]
        included20_rows = [["included20_value", "1", "", "g", "i", "2", "-10", "10",
                            "", "opaque9", "", "", "", "comment", "tail14", "tail15",
                            "tail16", "tail17", "tail18", "tail19"]]
        closure = {
            "status": "native-body-trace-bound",
            "source_body_sha256": "a" * 64,
            "source_trace_sha256": "b" * 64,
            "native_walk_key": "c" * 64,
            "tables": [
                {"asset_index": 10, "name": "omnvars/mp/omnvars.csv", "row_count": 3,
                 "include_paths": ["omnvars/mp/included8.csv", "omnvars/mp/included20.csv"],
                 "definition_names": ["root_value"]},
                {"asset_index": 20, "name": "omnvars/mp/included8.csv", "row_count": 1,
                 "include_paths": [], "definition_names": ["included8_value"]},
                {"asset_index": 30, "name": "omnvars/mp/included20.csv", "row_count": 1,
                 "include_paths": [], "definition_names": ["included20_value"]},
            ],
            "include_edges": [
                {"source_asset_index": 10, "source_name": "omnvars/mp/omnvars.csv",
                 "include_path": "omnvars/mp/included8.csv", "target_asset_index": 20,
                 "target_name": "omnvars/mp/included8.csv"},
                {"source_asset_index": 10, "source_name": "omnvars/mp/omnvars.csv",
                 "include_path": "omnvars/mp/included20.csv", "target_asset_index": 30,
                 "target_name": "omnvars/mp/included20.csv"},
            ],
        }
        return closure, {10: root_rows, 20: included8_rows, 30: included20_rows}

    def test_composes_root_and_included_table_revisions(self):
        closure, source_rows = self.fixture()
        edited_root = [list(source_rows[10][0]), list(source_rows[10][1]),
                       definition("root_value", "3")]
        edited_include = [["included8_value", "1", "", "c", "i", "4", "-10", "10"]]
        edited_include20 = [["included20_value", "1", "", "g", "i", "4", "-10", "10",
                             "", "opaque9", "", "", "", "comment", "tail14", "tail15",
                             "tail16", "tail17", "tail18", "tail19"]]
        result = _validate_omnvar_effective_closure(
            closure, source_rows,
            {10: {"revision": "1" * 64, "rows": edited_root},
             20: {"revision": "2" * 64, "rows": edited_include},
             30: {"revision": "3" * 64, "rows": edited_include20}})
        self.assertEqual(result["status"], "effective-native-bound-closure-validated")
        self.assertEqual([row["asset_index"] for row in result["staged_table_validations"]], [10, 20, 30])
        by_index = {row["asset_index"]: row for row in result["tables"]}
        self.assertNotEqual(by_index[10]["source_rows_sha256"], by_index[10]["effective_rows_sha256"])
        self.assertNotEqual(by_index[20]["source_rows_sha256"], by_index[20]["effective_rows_sha256"])
        self.assertNotEqual(by_index[30]["source_rows_sha256"], by_index[30]["effective_rows_sha256"])
        self.assertEqual(by_index[20]["source_column_count"], 8)
        self.assertEqual(by_index[30]["source_column_count"], 20)
        self.assertEqual(result["effective_root_validation"]["operation"], "edit-or-no-op")

    def test_included_member_cannot_change_definition_count(self):
        closure, source_rows = self.fixture()
        edited_include = [["replacement_value", "1", "", "c", "i", "4", "-10", "10"]]
        with self.assertRaisesRegex(ValueError, "aggregate definition/scope counts"):
            _validate_omnvar_effective_closure(
                closure, source_rows,
                {20: {"revision": "2" * 64, "rows": edited_include}})

    def test_included_extension_columns_are_opaque_and_immutable(self):
        closure, source_rows = self.fixture()
        edited = [list(source_rows[30][0])]
        edited[0][14] = "changed"
        with self.assertRaisesRegex(ValueError, "opaque native extension columns"):
            _validate_omnvar_effective_closure(
                closure, source_rows,
                {30: {"revision": "3" * 64, "rows": edited}})

    def test_staged_table_must_be_a_native_closure_member(self):
        closure, source_rows = self.fixture()
        with self.assertRaisesRegex(ValueError, "outside the resolved include closure"):
            _validate_omnvar_effective_closure(
                closure, source_rows,
                {40: {"revision": "4" * 64, "rows": [definition("other", "5")]}})


if __name__ == "__main__":
    unittest.main()
