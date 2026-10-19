from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_scriptstring_table import (  # noqa: E402
    _encode_prefix,
    merge_scriptstring_prefix,
    merge_scriptstring_prefixes,
    parse_scriptstring_list,
    rebase_packed_scriptstring_prefix,
    shift_stream_coordinate,
    splice_scriptstring_prefix,
)


def _body(strings: list[str], payload: bytes | None = None,
          explicit_null: bool = True) -> bytes:
    count = len(strings) + int(explicit_null)
    # XAssetList: string count, reserved, inline string token, one XAsset row,
    # reserved, inline XAsset-array token.
    string_token = (0xFFFFFFFFFFFFFFFE if strings else
                    (0 if not explicit_null else 0xFFFFFFFFFFFFFFFE))
    root = struct.pack("<IIQIIQ", count, 0, string_token,
                       1, 0, 0xFFFFFFFFFFFFFFFE)
    tokens = ((struct.pack("<Q", 0) if explicit_null else b"") +
              (struct.pack(f"<{len(strings)}Q", *([0xFFFFFFFFFFFFFFFE] * len(strings)))
               if strings else b""))
    encoded = b"".join(value.encode("utf-8") + b"\0" for value in strings)
    row = struct.pack("<IIQ", 8, 0, 0xFFFFFFFFFFFFFFFE) if payload is None else payload
    return root + tokens + encoded + row


class ScriptStringPrefixTests(unittest.TestCase):
    def test_trace_coordinate_shift_rebases_global_and_asset_local_tokens(self):
        self.assertEqual(shift_stream_coordinate(5, 0x200,
            insertion_stream=5, insertion_offset=0x100, delta=0x60), 0x260)
        self.assertEqual(shift_stream_coordinate(1, 0x200,
            insertion_stream=5, insertion_offset=0x100, delta=0x60), 0x200)
        global_token = (5 << 32) | (0x220 + 1)
        new_token, new_target = rebase_packed_scriptstring_prefix(global_token,
            target_stream=5, target_offset=0x220, asset_base=None,
            insertion_stream=5, insertion_offset=0x100, delta=0x60)
        self.assertEqual(new_token, (5 << 32) | 0x281)
        self.assertEqual(new_target, 0x280)
        local_token = (0x15 << 32) | (0x220 - 0x200 + 1)
        new_token, new_target = rebase_packed_scriptstring_prefix(local_token,
            target_stream=5, target_offset=0x220, asset_base=0x200,
            insertion_stream=5, insertion_offset=0x100, delta=0x60)
        self.assertEqual(new_token, local_token)
        self.assertEqual(new_target, 0x280)

    def test_pointer_relocation_rejects_unproved_classes_and_overflow(self):
        with self.assertRaisesRegex(ValueError, "not supported"):
            rebase_packed_scriptstring_prefix((0x25 << 32) | 0x101,
                target_stream=5, target_offset=0x100, asset_base=None,
                insertion_stream=5, insertion_offset=0x80, delta=8)
        with self.assertRaisesRegex(ValueError, "64-bit range"):
            shift_stream_coordinate(5, 0xFFFFFFFFFFFFFFFF,
                insertion_stream=5, insertion_offset=0, delta=1)
        local = (0x15 << 32) | 0x11
        with self.assertRaisesRegex(ValueError, "asset-relative"):
            rebase_packed_scriptstring_prefix(local, target_stream=5,
                target_offset=0x110, asset_base=None, insertion_stream=5,
                insertion_offset=0x100, delta=16)
    def test_parse_and_rebuild_preserve_source_prefix(self):
        body = _body(["tag_origin", "wheel_01"])
        parsed = parse_scriptstring_list(body)
        self.assertEqual(parsed.values, (None, "tag_origin", "wheel_01"))
        self.assertEqual(parsed.asset_table_offset, 32 + 3 * 8 + len(b"tag_origin\0wheel_01\0"))
        plan = merge_scriptstring_prefix(body, body)
        self.assertEqual(plan.values, parsed.values)
        self.assertEqual(plan.source_id_map, (None, 1, 2))
        self.assertEqual(plan.prefix, body[:parsed.asset_table_offset])
        rebuilt, _ = splice_scriptstring_prefix(body, body)
        self.assertEqual(rebuilt, body)

    def test_union_preserves_target_ids_and_deduplicates_source_by_text(self):
        target = _body(["tag_origin", "common_only"])
        source = _body(["tag_origin", "skateboard", "wheel_01", "skateboard"])
        plan = merge_scriptstring_prefix(target, source)
        self.assertEqual(plan.values, (None, "tag_origin", "common_only", "skateboard", "wheel_01"))
        self.assertEqual(plan.target_id_map, (0, 1, 2))
        self.assertEqual(plan.source_id_map, (None, 1, 3, 4, 3))
        self.assertEqual(plan.new_asset_table_offset - plan.old_asset_table_offset,
                         2 * 8 + len(b"skateboard\0wheel_01\0"))
        rebuilt, _ = splice_scriptstring_prefix(target, source)
        self.assertEqual(parse_scriptstring_list(rebuilt).values, plan.values)

    def test_source_null_and_common_no_null_slots_map_by_physical_index(self):
        target = _body(["tag_origin", "trim_char_f_1_1", "trim_char_x_1_1"],
                       explicit_null=False)
        source = _body(["tag_origin", "wheel_01"], explicit_null=True)
        plan = merge_scriptstring_prefix(target, source)
        self.assertEqual(plan.values,
                         ("tag_origin", "trim_char_f_1_1", "trim_char_x_1_1", "wheel_01"))
        self.assertEqual(plan.target_id_map, (0, 1, 2))
        self.assertEqual(plan.source_id_map, (None, 0, 3))
        self.assertEqual(plan.table_shift, 8 + len(b"wheel_01\0"))

    def test_multiple_sources_keep_declared_intern_order_and_independent_maps(self):
        target = _body(["tag_origin", "trim_char_f_1_1", "trim_char_x_1_1"],
                       explicit_null=False)
        model = _body(["tag_origin", "tag_skateboard", "j_skate_wheel_01",
                       "j_skate_wheel_02", "j_skate_wheel_03", "j_skate_wheel_04"])
        anim = _body(["tag_origin", "tag_sync", "j_skate_wheel_01", "end"])
        plan = merge_scriptstring_prefixes(target, [model, anim])
        self.assertEqual(plan.values, (
            "tag_origin", "trim_char_f_1_1", "trim_char_x_1_1", "tag_skateboard",
            "j_skate_wheel_01", "j_skate_wheel_02", "j_skate_wheel_03",
            "j_skate_wheel_04", "tag_sync", "end"))
        self.assertEqual(plan.source_id_maps[0], (None, 0, 3, 4, 5, 6, 7))
        self.assertEqual(plan.source_id_maps[1], (None, 0, 8, 4, 9))

    def test_zero_string_tables_remain_zero_count(self):
        body = _body([])
        parsed = parse_scriptstring_list(body)
        self.assertEqual(parsed.count, 1)
        self.assertEqual(parsed.values, (None,))
        # A table without an explicit null slot keeps its first string at index 0.
        no_null = _body(["tag_origin", "common_only"], explicit_null=False)
        self.assertEqual(parse_scriptstring_list(no_null).values,
                         ("tag_origin", "common_only"))
        # A genuinely empty list has no physical slots.
        empty = struct.pack("<IIQIIQ", 0, 0, 0, 1, 0, 0xFFFFFFFFFFFFFFFE) + struct.pack("<IIQ", 8, 0, 0xFFFFFFFFFFFFFFFE)
        self.assertEqual(parse_scriptstring_list(empty).values, ())
        plan = merge_scriptstring_prefix(empty, empty)
        self.assertEqual(plan.source_id_map, ())
        self.assertEqual(plan.values, ())

    def test_rejects_nonzero_null_id_and_malformed_utf8(self):
        body = bytearray(_body(["valid"]))
        struct.pack_into("<Q", body, 32, 0xFFFFFFFFFFFFFFFE)
        with self.assertRaises(ValueError):
            parse_scriptstring_list(bytes(body))
        body = bytearray(_body(["valid"]))
        body[32 + 2 * 8] = 0xFF
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            parse_scriptstring_list(bytes(body))

    def test_rejects_empty_or_embedded_nul_values(self):
        with self.assertRaisesRegex(ValueError, "unexpectedly empty"):
            merge_scriptstring_prefix(_body(["ok"]), _body([""]))
        with self.assertRaisesRegex(ValueError, "embedded NUL"):
            _encode_prefix(_body(["ok"])[:32], (None, "a\0b"))


if __name__ == "__main__":
    unittest.main()
