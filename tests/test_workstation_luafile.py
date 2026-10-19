from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tools.workstation_luafile import (
    inspect_luafile, luafile_compiler_input_name, replace_luafile_same_extent,
    replace_luafiles_inline_children,
)
from tools.workstation_luajit_chunk import split_luajit_file_payload
from tools.workstation_fastfiles import ZoneBody


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "evidence" / "workstation-luafile-cod-native-trace.json"


class WorkstationLuaFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RECEIPT.is_file():
            raise unittest.SkipTest("pinned Replay LuaFile trace receipt is unavailable")
        cls.receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        cls.body_path = Path(cls.receipt["source_body"]["path"])
        if not cls.body_path.is_file():
            raise unittest.SkipTest("decoded Replay code_post_gfx body is unavailable")
        cls.body = cls.body_path.read_bytes()
        cls.asset = cls.receipt["asset"]
        cls.trace_asset = dict(cls.asset, xasset_index=cls.asset["xasset_index"])

    def test_native_cod_luafile_root_name_and_stream5_child_are_trace_owned(self):
        asset = self.asset
        layout, bytecode = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        self.assertEqual(layout.root_archive_offset, 30_548_001)
        self.assertEqual(layout.root_stream, 1)
        self.assertEqual(layout.root_stream_offset, 0)
        self.assertEqual(layout.bytecode_stream, 5)
        self.assertEqual(layout.bytecode_stream_offset & 0xF, 0)
        self.assertEqual(layout.bytecode_bytes, 787)
        self.assertTrue(bytecode.endswith(b"\0"))

    def test_compiler_temp_name_is_safe_stable_and_bound_to_canonical_asset(self):
        name = "ui/frontend/mainmenuoffline.lua"
        compiler_name = luafile_compiler_input_name(name)
        self.assertRegex(compiler_name, r"^lua_[0-9a-f]{16}$")
        self.assertEqual(compiler_name, luafile_compiler_input_name(name))
        self.assertNotEqual(compiler_name, luafile_compiler_input_name("ui/frontend/other.lua"))

    def test_same_extent_replacement_preserves_asset_inventory_and_body_extent(self):
        asset = self.asset
        layout, original = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        replacement = bytearray(original)
        replacement[-2] ^= 1
        updated, proof = replace_luafile_same_extent(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            bytes(replacement), expected_body_sha256=self.receipt["source_body"]["sha256"])
        self.assertEqual(len(updated), len(self.body))
        self.assertEqual(updated[:layout.bytecode_archive_offset],
                         self.body[:layout.bytecode_archive_offset])
        self.assertEqual(proof["status"], "same-extent-luafile-replacement-ready")
        self.assertTrue(proof["xasset_table_unchanged"])

    def test_noop_same_extent_replacement_preserves_full_body_bytes(self):
        asset = self.asset
        _, original = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        updated, proof = replace_luafile_same_extent(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            original, expected_body_sha256=self.receipt["source_body"]["sha256"])
        self.assertEqual(proof["output_body_sha256"], proof["source_body_sha256"])
        self.assertEqual(updated, self.body)

    def test_stale_trace_cannot_be_reused_for_a_second_pending_edit(self):
        asset = self.asset
        _, original = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        first = bytearray(original)
        first[-2] ^= 1
        updated, _ = replace_luafile_same_extent(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            bytes(first), expected_body_sha256=self.receipt["source_body"]["sha256"])
        second = bytearray(original)
        second[-3] ^= 1
        with self.assertRaisesRegex(ValueError, "different decoded source body"):
            replace_luafile_same_extent(
                updated, asset["xasset_index"], asset["name"], self.trace_asset,
                bytes(second), expected_body_sha256=self.receipt["source_body"]["sha256"])

    def test_rejects_growth_without_relocation_trace(self):
        asset = self.asset
        _, original = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        with self.assertRaisesRegex(ValueError, "trace"):
            from tools.workstation_luafile import replace_luafile_inline_child
            replace_luafile_inline_child(
                self.body, asset["xasset_index"], asset["name"], self.trace_asset,
                original + b"\x00", self.receipt["source_body"]["sha256"])

    def test_luafile_batch_semantic_noop_preserves_exact_body(self):
        asset = self.asset
        _, original = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        updated, proof = replace_luafiles_inline_children(
            self.body,
            [dict(asset_index=asset["xasset_index"], asset_name=asset["name"],
                  trace_asset=self.trace_asset, payload=original)],
            self.receipt["source_body"]["sha256"])
        self.assertEqual(updated, self.body)
        self.assertEqual(proof["status"], "semantic-noop-luafile-batch")
        self.assertEqual(proof["output_body_sha256"], proof["source_body_sha256"])

    def test_luafile_batch_explicitly_rejects_mixed_scriptfile_edit(self):
        asset = self.asset
        _, original = inspect_luafile(
            self.body, asset["xasset_index"], asset["name"], self.trace_asset,
            expected_body_sha256=self.receipt["source_body"]["sha256"])
        with self.assertRaisesRegex(ValueError, "mixed ScriptFile/LuaFile batches"):
            replace_luafiles_inline_children(
                self.body,
                [dict(asset_index=asset["xasset_index"], asset_name=asset["name"],
                      type_id=62, trace_asset=self.trace_asset, payload=original),
                 dict(asset_index=1443, asset_name="scripts/test.gsc", type_id=52,
                      trace_asset={}, payload=b"")],
                self.receipt["source_body"]["sha256"])

    def test_growth_relocation_has_full_replay_reader_receipt(self):
        proof_path = ROOT / "evidence" / "workstation-luafile-growth-v3" / \
            "code_post_gfx-luafile-relocation.json"
        if not proof_path.is_file():
            self.skipTest("native full-zone LuaFile growth run is not installed")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["status"], "native-full-zone-luafile-growth-pass")
        self.assertEqual(proof["relocation"]["asset_index"], 2711)
        self.assertEqual(proof["relocation"]["asset_name"], "luashared/cod.lua")
        self.assertEqual(proof["relocation"]["packed_stream5_aliases_rebased"], 12)
        self.assertEqual(proof["relocation"][
            "packed_stream5_tag15_asset_relative_validated"], 54741)
        self.assertEqual(proof["native_reader"]["complete"], True)
        self.assertEqual(proof["native_reader"]["success"], True)
        self.assertEqual(proof["native_reader"]["tested"], 6012)
        self.assertEqual(proof["native_reader"]["failed"], 0)
        self.assertEqual(proof["native_reader"]["unavailable"], 0)
        self.assertEqual(proof["native_reader"]["serialized_bytes_read"],
                         proof["relocated_body"]["bytes"])
        self.assertEqual(proof["relocation"]["stream_reservation_deltas"][1], 0)
        self.assertEqual(proof["relocation"]["stream_reservation_deltas"][5], 416)
        self.assertEqual(proof["output_fastfile"]["stream_reservation_sizes"][1],
                         proof["native_reader"]["trace_summary"][
                             "max_destination_offsets"]["1"])
        self.assertEqual(proof["output_fastfile"]["stream_reservation_sizes"][5],
                         proof["native_reader"]["trace_summary"][
                             "max_destination_offsets"]["5"])

        body_path = Path(proof["relocated_body"]["path"])
        body = body_path.read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         proof["relocated_body"]["sha256"])
        inventory = ZoneBody.parse(body)
        self.assertEqual(inventory.assets, ZoneBody.parse(self.body).assets)
        root_at = proof["relocation"]["root_archive_offset"]
        bytecode_size = int.from_bytes(body[root_at + 8:root_at + 12], "little", signed=True)
        child_at = proof["relocation"]["bytecode_archive_offset"]
        bytecode = body[child_at:child_at + bytecode_size]
        self.assertEqual(bytecode_size, proof["replacement"]["bytes"])
        self.assertEqual(hashlib.sha256(bytecode).hexdigest(),
                         proof["replacement"]["sha256"])
        self.assertTrue(bytecode.endswith(b"\0"))
        parsed = split_luajit_file_payload(bytecode)
        self.assertTrue(parsed.chunk.endswith(b"\0"))
        self.assertTrue(parsed.trailing_native_nul)

    def test_shrink_relocation_has_full_replay_reader_receipt(self):
        proof_path = ROOT / "evidence" / "workstation-luafile-shrink" / \
            "code_post_gfx-luafile-relocation.json"
        if not proof_path.is_file():
            self.skipTest("native full-zone LuaFile shrink run is not installed")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["status"], "native-full-zone-luafile-growth-pass")
        self.assertEqual(proof["replacement"]["bytes"], 202)
        self.assertEqual(proof["relocation"]["old_bytecode_bytes"], 787)
        self.assertEqual(proof["relocation"]["new_bytecode_bytes"], 202)
        self.assertEqual(proof["relocation"]["stream_reservation_deltas"][5], -576)
        self.assertEqual(proof["relocation"]["packed_stream5_aliases_rebased"], 12)
        self.assertEqual(proof["relocation"][
            "packed_stream5_tag15_asset_relative_validated"], 54741)
        self.assertEqual(proof["native_reader"]["complete"], True)
        self.assertEqual(proof["native_reader"]["success"], True)
        self.assertEqual(proof["native_reader"]["tested"], 6012)
        self.assertEqual(proof["native_reader"]["failed"], 0)
        self.assertEqual(proof["native_reader"]["serialized_bytes_read"],
                         proof["relocated_body"]["bytes"])

    def test_multi_luafile_growth_and_shrink_one_trace_passes_native_reader(self):
        proof_path = ROOT / "evidence" / "workstation-luafile-batch" / \
            "code_post_gfx-luafile-batch-relocation.json"
        if not proof_path.is_file():
            self.skipTest("native multi-LuaFile full-zone batch run is not installed")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertEqual(proof["status"], "native-full-zone-luafile-batch-pass")
        self.assertEqual([row["asset_index"] for row in proof["edits"]], [2711, 2712])
        self.assertEqual([row["asset_name"] for row in proof["edits"]],
                         ["luashared/cod.lua", "luashared/csvutils.lua"])
        relocation = proof["relocation"]
        self.assertEqual(relocation["physical_extent_delta"], -51046)
        self.assertEqual(relocation["stream5_extent_delta"], -51072)
        self.assertEqual(relocation["packed_stream5_tag5_absolute_validated"], 383702)
        self.assertEqual(relocation["packed_stream5_tag15_asset_relative_validated"], 54741)
        self.assertEqual(relocation["packed_stream5_aliases_rebased"], 12)
        self.assertEqual(len(relocation["stream_reservation_sizes"]), 11)
        self.assertEqual(relocation["stream_reservation_deltas"][1], 0)
        self.assertEqual(relocation["stream_reservation_deltas"][5], -51072)
        reader = proof["native_reader"]
        self.assertEqual(reader["complete"], True)
        self.assertEqual(reader["success"], True)
        self.assertEqual(reader["tested"], 6012)
        self.assertEqual(reader["failed"], 0)
        self.assertEqual(reader["unavailable"], 0)
        self.assertEqual(reader["serialized_bytes_read"], proof["edited_body"]["bytes"])
        self.assertFalse(proof["mixed_scriptfile_luafile_edits_supported"])


if __name__ == "__main__":
    unittest.main()
