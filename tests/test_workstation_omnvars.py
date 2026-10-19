from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from workstation_omnvars import (  # noqa: E402
    OmnvarValidationError,
    validate_omnvar_mp_edit,
    validate_omnvar_mp_rows,
)


def row(name="example", **changes):
    values = [name, "1", "", "c", "i", "0", "-10", "10", "", "", "", "", "", ""]
    columns = {
        "name": 0, "flag1": 1, "flag2": 2, "scope": 3, "type": 4,
        "initial": 5, "minimum": 6, "maximum": 7, "flag8": 8,
        "opaque9": 9, "flag10": 10, "flag11": 11, "flag12": 12,
        "comment": 13,
    }
    for key, value in changes.items():
        values[columns[key]] = value
    return values


def source_rows():
    return [
        ["include", "omnvars/omnvars_shared_mp_cp.csv", *([""] * 12)],
        ["include", "omnvars/mp/omnvars_brcircle.csv", *([""] * 12)],
        row(),
        row("float_probe", type="f", initial="1.25", flag10="1"),
        row("bool_probe", type="b", initial="1", minimum="", maximum=""),
        row("time_probe", type="t", initial="0", minimum="", maximum=""),
        row("ncs_probe", type="s", initial="ui_probe", minimum="", maximum=""),
        row("empty_default", type="n", initial="", minimum="", maximum=""),
        row("fixed_default", type="e", initial="", minimum="", maximum=""),
    ]


class WorkstationOmnvarTests(unittest.TestCase):
    def test_valid_supported_types_and_columns(self):
        result = validate_omnvar_mp_rows(source_rows())
        self.assertEqual(result["column_count"], 14)
        self.assertEqual(result["definition_count"], 7)
        self.assertFalse(result["runtime_omnvar_definition_support_claimed"])

    def test_native_bound_include_member_uses_actual_relative_asset_identity(self):
        original = [row("included_value")]
        edited = [row("included_value", initial="3")]
        result = validate_omnvar_mp_edit(
            original, edited, asset_path="omnvars/mp/omnvars_brcircle.csv",
            included_definition_names=[], native_include_member=True)
        self.assertEqual(result["asset_path"], "omnvars/mp/omnvars_brcircle.csv")
        with self.assertRaisesRegex(OmnvarValidationError, "safe relative path"):
            validate_omnvar_mp_rows(original, asset_path="omnvars/../outside.csv",
                                    native_include_member=True)
        with self.assertRaisesRegex(OmnvarValidationError, "root is not an included-table identity"):
            validate_omnvar_mp_rows(original, asset_path="omnvars/mp/omnvars.csv",
                                    native_include_member=True)

    def test_all_ten_native_type_dispatch_codes_are_exercised(self):
        rows = source_rows() + [
            row("a_code", type="a", initial="0"),
            row("d_code", type="d", initial="0.25"),
            row("e_code", type="e", initial=""),
            row("p_code", type="p", initial="-1"),
        ]
        result = validate_omnvar_mp_rows(rows, client_limit=12)
        self.assertEqual(result["type_codes"], list("abdefinpst"))

    def test_native_interpolation_type_byte_rules(self):
        for kind in "defipt":
            candidate = row(f"interpolation_{kind}", type=kind, initial="0")
            if kind in "def":
                candidate[5] = "0.25"
            if kind == "i":
                candidate[6], candidate[7] = "-1", "1"
            if kind == "p":
                candidate[5] = "-1"
            candidate[8] = "1"
            rows = source_rows() + [candidate]
            validate_omnvar_mp_rows(rows, client_limit=12)

    def test_add_edit_remove_definition_rows_keep_include_prefix(self):
        original = source_rows()
        added = original + [row("added_probe", comment="# editor note")]
        with self.assertRaisesRegex(OmnvarValidationError, "include definition names are required"):
            validate_omnvar_mp_edit(original, added)
        with self.assertRaisesRegex(OmnvarValidationError, r"row 10, column 0.*aggregate definition/scope counts"):
            validate_omnvar_mp_edit(original, added, included_definition_names=["shared_probe"])
        edited = [list(item) for item in original]
        edited[2][5] = "1"
        self.assertEqual(validate_omnvar_mp_edit(original, edited)["operation"], "edit-or-no-op")
        removed = original[:3] + original[4:]
        with self.assertRaisesRegex(OmnvarValidationError, r"row 4, column 0.*aggregate definition/scope counts"):
            validate_omnvar_mp_edit(original, removed)

    def test_comment_only_edit_and_unchanged_legacy_ncs_rows_remain_valid(self):
        original = source_rows()
        edited = [list(item) for item in original]
        edited[6][13] = "# display label note"
        self.assertEqual(validate_omnvar_mp_edit(original, edited)["operation"], "edit-or-no-op")
        self.assertFalse(validate_omnvar_mp_edit(original, original)["runtime_execution_context_complete"])

    def test_scope_and_archive_pmove_spectate_flag_changes_require_context(self):
        cases = ((3, "g", "column 3"), (2, "1", "column 2"),
                 (10, "0", "column 10"), (12, "1", "column 12"))
        for index, value, expected in cases:
            original = source_rows()
            edited = [list(item) for item in original]
            # Column 10 is already set on a valid float row; toggle it off.
            row_index = 3 if index == 10 else 2
            edited[row_index][index] = value
            if index == 10:
                edited[row_index][10] = ""
            with self.subTest(column=index), self.assertRaisesRegex(OmnvarValidationError, expected):
                validate_omnvar_mp_edit(original, edited)

    def test_new_changed_or_retyped_ncs_defaults_require_context(self):
        original = source_rows()
        edited = [list(item) for item in original]
        edited[6][5] = "ui_new_default"
        with self.assertRaisesRegex(OmnvarValidationError, r"row 7, column 5.*NCS default"):
            validate_omnvar_mp_edit(original, edited)

        edited = [list(item) for item in original]
        edited[6][4] = "f"
        edited[6][5] = "0.5"
        with self.assertRaisesRegex(OmnvarValidationError, r"row 7, column 4.*NCS type"):
            validate_omnvar_mp_edit(original, edited)

        new_ncs = original + [row("new_lui", type="s", initial="ui_new", minimum="", maximum="")]
        with self.assertRaisesRegex(OmnvarValidationError, r"row 10, column 5.*NCS default"):
            validate_omnvar_mp_edit(original, new_ncs, included_definition_names=["unrelated"])

    def test_changed_include_is_rejected_with_row_and_column(self):
        original = source_rows()
        edited = [list(item) for item in original]
        edited[0][1] = "omnvars/other.csv"
        with self.assertRaisesRegex(OmnvarValidationError, r"row 1, column 0.*include directives are read-only"):
            validate_omnvar_mp_edit(original, edited)

    def test_include_after_definition_is_rejected(self):
        rows = [row(), source_rows()[0]]
        with self.assertRaisesRegex(OmnvarValidationError, r"row 2, column 0.*must precede"):
            validate_omnvar_mp_rows(rows)

    def test_unknown_target_path_scope_and_type_fail_closed(self):
        with self.assertRaisesRegex(OmnvarValidationError, "only 'omnvars/mp/omnvars.csv' is proven"):
            validate_omnvar_mp_rows(source_rows(), asset_path="omnvars/sp/omnvars.csv")
        for mutation, expected in (({"scope": "x"}, "column 3"), ({"type": "z"}, "column 4")):
            bad = source_rows()
            bad[2] = row("bad", **mutation)
            with self.assertRaisesRegex(OmnvarValidationError, expected):
                validate_omnvar_mp_rows(bad)

    def test_duplicate_native_name_key_fails(self):
        rows = source_rows() + [row("example")]
        with self.assertRaisesRegex(OmnvarValidationError, r"native Omnvar name hash collides with row 3"):
            validate_omnvar_mp_rows(rows)
        # Native hashes the byte sequence as byte + 33 * previous modulo 2^32;
        # these distinct names produce the same key.
        rows = source_rows() + [row("Aa")]
        rows[2] = row("B@")
        with self.assertRaisesRegex(OmnvarValidationError, r"native Omnvar name hash collides with row 3"):
            validate_omnvar_mp_rows(rows)

    def test_added_names_are_checked_against_loaded_include_definitions(self):
        original = source_rows()
        edited = original + [row("shared_probe")]
        with self.assertRaisesRegex(OmnvarValidationError, "collides with included definition"):
            validate_omnvar_mp_edit(original, edited, included_definition_names=["shared_probe"])

    def test_integer_bounds_and_value_are_checked(self):
        for mutations, column in (({"initial": "11"}, "column 5"), ({"minimum": "11"}, "column 6"),
                                  ({"maximum": "10", "minimum": "11"}, "column 6")):
            rows = source_rows()
            rows[2] = row("bad_int", **mutations)
            with self.assertRaisesRegex(OmnvarValidationError, column):
                validate_omnvar_mp_rows(rows)

    def test_type_initial_values_and_required_integer_range(self):
        rows = source_rows()
        rows[2] = row("bool_bad", type="b", initial="2", minimum="", maximum="")
        with self.assertRaisesRegex(OmnvarValidationError, r"column 5.*boolean initial"):
            validate_omnvar_mp_rows(rows)
        rows = source_rows()
        rows[2] = row("float_bad", type="f", initial="nan")
        with self.assertRaisesRegex(OmnvarValidationError, r"column 5.*finite decimal float"):
            validate_omnvar_mp_rows(rows)
        rows = source_rows()
        rows[2] = row("float_overflow", type="f", initial="1e39")
        with self.assertRaisesRegex(OmnvarValidationError, r"column 5.*native 32-bit float range"):
            validate_omnvar_mp_rows(rows)
        rows = source_rows()
        rows[2] = row("int_missing_range", initial="0", minimum="", maximum="")
        with self.assertRaisesRegex(OmnvarValidationError, "column 6"):
            validate_omnvar_mp_rows(rows)

    def test_native_flag_combinations_are_checked(self):
        cases = [
            (row("bad_time_flag", type="t", initial="0", minimum="", maximum="", flag10="1"), "flag 0x10 requires"),
            (row("bad_change_flag", flag1="0", flag11="1"), "flag 0x40 requires"),
            (row("bad_scope_flag", scope="g", flag12="1"), "flag 0x80 requires client scope"),
            (row("bad_flag_pair", flag2="1", flag12="1"), "cannot be combined"),
            (row("bad_archive_scope", scope="g", flag2="1"), "flag 0x04 requires client scope"),
            (row("bad_flag_pair2", type="b", initial="1", flag8="1"), "flag 0x08 is incompatible"),
            (row("bad_notify_interpolation", type="n", initial="0", flag8="1"), "notify userType"),
            (row("bad_float_pair", type="f", initial="0.5", flag8="1", flag10="1"), "cannot be combined"),
        ]
        for bad, message in cases:
            with self.subTest(name=bad[0]):
                rows = source_rows()
                rows[2] = bad
                with self.assertRaisesRegex(OmnvarValidationError, message):
                    validate_omnvar_mp_rows(rows)

    def test_client_dependent_type_p_requires_explicit_limit_for_changes(self):
        original = source_rows() + [row("client_index", type="p", initial="-1", minimum="", maximum="")]
        self.assertEqual(validate_omnvar_mp_edit(original, original)["operation"], "edit-or-no-op")
        changed = [list(item) for item in original]
        changed[-1][5] = "0"
        with self.assertRaisesRegex(OmnvarValidationError, r"column 5.*client limit"):
            validate_omnvar_mp_edit(original, changed)
        self.assertEqual(
            validate_omnvar_mp_edit(original, changed, client_limit=12)["operation"],
            "edit-or-no-op",
        )
        changed[-1][5] = "12"
        with self.assertRaisesRegex(OmnvarValidationError, r"column 5.*must be -1 through 11"):
            validate_omnvar_mp_edit(original, changed, client_limit=12)

    def test_opaque_columns_are_preserved_for_existing_rows(self):
        original = source_rows()
        original[2][9] = "opaque"
        self.assertTrue(validate_omnvar_mp_rows(original)["opaque_columns"])
        edited = [list(item) for item in original]
        edited[2][9] = "changed"
        with self.assertRaisesRegex(OmnvarValidationError, r"column 9.*must be preserved"):
            validate_omnvar_mp_edit(original, edited)

    def test_exact_width_and_empty_name_errors_are_located(self):
        rows = source_rows()
        rows[2] = rows[2][:-1]
        with self.assertRaisesRegex(OmnvarValidationError, r"row 3, column 13.*exactly 14"):
            validate_omnvar_mp_rows(rows)
        rows = source_rows()
        rows[2][0] = ""
        with self.assertRaisesRegex(OmnvarValidationError, r"row 3, column 0.*name must be non-empty"):
            validate_omnvar_mp_rows(rows)


if __name__ == "__main__":
    unittest.main()
