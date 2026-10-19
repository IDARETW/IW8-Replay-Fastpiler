"""Unit checks for the LuaFile append/remove pointer relocation primitive."""
from __future__ import annotations

import struct
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_luafile_operations import (  # noqa: E402
    LUA_FILE_ROOT_SIZE, XASSET_ROW_SIZE, _manifest,
    _map_deleted_xasset_table_target, _rebase_aliases, _trace_contract,
    remove_existing_luafile_row)


class LuaFileOperationRelocationTests(unittest.TestCase):
    def _final_luafile_fixture(self, *, tail=b"", foreign_span=None,
                               rebase_side_effect=None):
        retained = SimpleNamespace(type_id=20, pointer_token=0x1234)
        removed = SimpleNamespace(type_id=62, pointer_token=0x5678)
        body = SimpleNamespace(source_sha256="body", assets=[retained, removed],
                               asset_table_offset=16, first_payload_offset=64)
        layout = SimpleNamespace(root_archive_offset=64,
            name_archive_offset=64 + LUA_FILE_ROOT_SIZE, name_bytes=5,
            bytecode_archive_offset=64 + LUA_FILE_ROOT_SIZE + 5,
            bytecode_bytes=4, root_stream=1, root_stream_offset=0x20)
        payload_end = layout.bytecode_archive_offset + layout.bytecode_bytes
        body_data = bytearray(payload_end)
        struct.pack_into("<I", body_data, body.asset_table_offset + XASSET_ROW_SIZE, 62)
        body_data.extend(tail)
        spans = [
            {"archive_offset": layout.root_archive_offset, "size": LUA_FILE_ROOT_SIZE,
             "destination_stream_location": {"stream": 1, "offset": 0x20}},
            {"origin": "string_data", "archive_offset": layout.name_archive_offset,
             "size": layout.name_bytes,
             "destination_stream_location": {"stream": 5, "offset": 0x100}},
            {"archive_offset": layout.bytecode_archive_offset,
             "size": layout.bytecode_bytes,
             "destination_stream_location": {"stream": 5, "offset": 0x105}},
        ]
        trace_asset = {"xasset_index": 1, "type_id": 62, "name": "ui/last.lua",
                       "read_spans": spans}
        intervals = [
            {"owner": 1, "archive": layout.root_archive_offset,
             "size": LUA_FILE_ROOT_SIZE},
            {"owner": 1, "archive": layout.name_archive_offset,
             "size": layout.name_bytes},
            {"owner": 1, "archive": layout.bytecode_archive_offset,
             "size": layout.bytecode_bytes},
        ]
        if foreign_span:
            intervals.append(foreign_span)
        table_alloc = {"size": len(body.assets) * XASSET_ROW_SIZE, "end": 48}
        trace_contract = ( {}, {}, intervals, [], table_alloc, {}, 0, {}, {}, {} )
        reparsed = SimpleNamespace(assets=[retained])
        parse = patch("workstation_luafile_operations.ZoneBody.parse",
                      side_effect=[body, reparsed])
        return body_data, trace_asset, layout, trace_contract, parse, rebase_side_effect

    def test_existing_row_writer_removes_final_luafile_only_at_exact_eof(self):
        body_data, trace_asset, layout, trace_contract, parse, rebase_side_effect = \
            self._final_luafile_fixture()
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            manifest = Path(directory) / "manifest.json"
            trace.write_bytes(b"trace\n")
            manifest.write_bytes(b"manifest\n")
            with parse, \
                 patch("workstation_luafile_operations.inspect_luafile",
                       return_value=(layout, b"code")), \
                 patch("workstation_luafile_operations._trace_contract",
                       return_value=trace_contract), \
                 patch("workstation_luafile_operations._rebase_aliases",
                       return_value=(bytes(body_data), {"packed_alias_fields_rebased": 0})):
                result, receipt = remove_existing_luafile_row(
                    bytes(body_data), 1, "ui/last.lua", trace_asset, "body",
                    trace, manifest)
        self.assertEqual(len(result), len(body_data) - LUA_FILE_ROOT_SIZE - 5 - 4 - XASSET_ROW_SIZE)
        self.assertEqual(receipt["operation"], "remove_existing")
        self.assertEqual(receipt["source_asset_count"], 2)
        self.assertEqual(receipt["output_asset_count"], 1)

    def test_final_luafile_rejects_unowned_bytes_after_extent(self):
        body_data, trace_asset, layout, trace_contract, parse, _ = \
            self._final_luafile_fixture(tail=b"unowned")
        with parse, \
             patch("workstation_luafile_operations.inspect_luafile",
                   return_value=(layout, b"code")), \
             patch("workstation_luafile_operations._trace_contract",
                   return_value=trace_contract):
            with self.assertRaisesRegex(ValueError, "exact serialized EOF"):
                remove_existing_luafile_row(
                    bytes(body_data), 1, "ui/last.lua", trace_asset, "body",
                    "unused-trace", "unused-manifest")

    def test_final_luafile_rejects_shared_tail_bytes(self):
        foreign = {"owner": 0, "archive": 84, "size": 2}
        body_data, trace_asset, layout, trace_contract, parse, _ = \
            self._final_luafile_fixture(foreign_span=foreign)
        with parse, \
             patch("workstation_luafile_operations.inspect_luafile",
                   return_value=(layout, b"code")), \
             patch("workstation_luafile_operations._trace_contract",
                   return_value=trace_contract), \
             patch("workstation_luafile_operations._rebase_aliases",
                   return_value=(bytes(body_data), {"packed_alias_fields_rebased": 0})):
            with self.assertRaisesRegex(ValueError, "shared with another native XAsset"):
                remove_existing_luafile_row(
                    bytes(body_data), 1, "ui/last.lua", trace_asset, "body",
                    "unused-trace", "unused-manifest")

    def test_final_luafile_rejects_inbound_alias(self):
        body_data, trace_asset, layout, trace_contract, parse, _ = \
            self._final_luafile_fixture()
        with parse, \
             patch("workstation_luafile_operations.inspect_luafile",
                   return_value=(layout, b"code")), \
             patch("workstation_luafile_operations._trace_contract",
                   return_value=trace_contract), \
             patch("workstation_luafile_operations._rebase_aliases",
                   side_effect=ValueError("inbound packed alias targets removed LuaFile bytes")):
            with self.assertRaisesRegex(ValueError, "inbound packed alias"):
                remove_existing_luafile_row(
                    bytes(body_data), 1, "ui/last.lua", trace_asset, "body",
                    "unused-trace", "unused-manifest")

    def test_complete_trace_must_match_native_manifest_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "trace.jsonl"
            manifest_path = root / "manifest.json"
            trace.write_bytes(b"native trace\n")
            manifest = {
                "profile": "replay-1.20", "xfile_version": 0xFF7,
                "complete": True, "success": True,
                "tested": 2, "top_level_index": 2,
                "serialized_bytes_read": 4, "stream_trace_events": 0,
                "stream_trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(_manifest(trace, manifest_path, b"body")["stream_trace_events"], 0)
            trace.write_bytes(b"tampered trace\n")
            with self.assertRaisesRegex(ValueError, "manifest hash"):
                _manifest(trace, manifest_path, b"body")

    def test_absolute_pointer_and_field_relocate_once(self):
        body = bytearray(0x200)
        original = (5 << 32) | (0x180 + 1)
        struct.pack_into("<Q", body, 0x100, original)
        intervals = [dict(owner=3, stream=1, start=0x20, end=0x28,
                          archive=0x100, size=8, sequence=1)]
        aliases = [(3, original, 1, 0x20, 5, 0x180, 44)]
        changed, report = _rebase_aliases(bytes(body), intervals, aliases,
                                          0x100, 0x80, 16, {})
        self.assertEqual(struct.unpack_from("<Q", changed, 0x100)[0],
                         (5 << 32) | (0x190 + 1))
        self.assertEqual(report["packed_alias_fields_rebased"], 1)

    def test_asset_relative_target_and_base_shift_cancel(self):
        body = bytes(0x100)
        raw = (0x15 << 32) | (0x28 + 1)
        intervals = []
        aliases = [(7, raw, 1, 0x20, 5, 0x128, 88)]
        changed, report = _rebase_aliases(body, intervals, aliases,
                                          0x100, 0x80, 16, {7: 0x100})
        self.assertEqual(changed, body)
        self.assertEqual(report["packed_alias_fields_rebased"], 0)

    def test_remove_rejects_inbound_pointer_to_deleted_child(self):
        raw = (5 << 32) | (0x220 + 1)
        aliases = [(1, raw, 1, 0x20, 5, 0x220, 91)]
        with self.assertRaisesRegex(ValueError, "inbound packed alias"):
            _rebase_aliases(bytes(0x100), [], aliases, 0x100, 0x80, 16,
                            {}, inverse=True,
                            removed_stream_ranges=((5, 0x220, 0x230),))

    def test_unsupported_tag_targeting_moved_stream_fails_closed(self):
        raw = (0x44 << 32) | 0x221
        aliases = [(1, raw, 1, 0x20, 5, 0x220, 92)]
        with self.assertRaisesRegex(ValueError, "unsupported packed pointer tag"):
            _rebase_aliases(bytes(0x100), [], aliases, 0x100, 0x80, 16, {})

    def test_sorted_interval_index_finds_owner_among_large_trace(self):
        body = bytearray(0x4000)
        spans = [dict(owner=2, stream=1, start=i * 8, end=i * 8 + 8,
                      archive=0x100 + i * 8, size=8, sequence=i)
                 for i in range(500)]
        target = spans[417]
        raw = (5 << 32) | (0x181 + 1)
        struct.pack_into("<Q", body, target["archive"], raw)
        aliases = [(2, raw, 1, target["start"], 5, 0x181, 99)]
        changed, report = _rebase_aliases(bytes(body), spans, aliases,
                                          0x100, 0x80, 16, {})
        self.assertEqual(struct.unpack_from("<Q", changed, target["archive"])[0],
                         (5 << 32) | (0x191 + 1))
        self.assertEqual(report["packed_alias_fields_rebased"], 1)

    def test_reused_scratch_field_uses_latest_prior_load_and_rejects_partial_overwrite(self):
        body = bytearray(0x100)
        raw = (5 << 32) | (0x181 + 1)
        struct.pack_into("<Q", body, 0x40, raw)
        spans = [dict(owner=2, stream=1, start=0x20, end=0x28,
                      archive=0x10, size=8, sequence=1),
                 dict(owner=2, stream=1, start=0x20, end=0x28,
                      archive=0x40, size=8, sequence=20),
                 # This later reuse is after the callback and cannot own its field.
                 dict(owner=2, stream=1, start=0x20, end=0x28,
                      archive=0x70, size=8, sequence=40)]
        aliases = [(2, raw, 1, 0x20, 5, 0x181, 30)]
        changed, report = _rebase_aliases(bytes(body), spans, aliases,
                                          0x100, 0x80, 16, {})
        self.assertEqual(struct.unpack_from("<Q", changed, 0x40)[0],
                         (5 << 32) | (0x191 + 1))
        self.assertEqual(changed[0x10:0x18], bytes(8))
        self.assertEqual(changed[0x70:0x78], bytes(8))
        self.assertEqual(report["packed_alias_fields_rebased"], 1)

        partial = spans + [dict(owner=2, stream=1, start=0x24, end=0x2C,
                                archive=0x90, size=8, sequence=25)]
        with self.assertRaisesRegex(ValueError, "partially overwritten"):
            _rebase_aliases(bytes(body), partial, aliases, 0x100, 0x80, 16, {})

    def test_db_insert_pointer_gap_uses_replayed_align_coordinate_not_table_delta(self):
        body = bytearray(256)
        pointer = (5 << 32) | (200 + 1)
        struct.pack_into("<Q", body, 32, pointer)

        def op(sequence, operation, before_block, before_offset,
               after_block, after_offset, *, value=0, size=0, input_before=40,
               xasset_index=0):
            return dict(kind="stream_operation", sequence=sequence,
                operation=operation, block_before=before_block,
                offset_before=before_offset, input_before=input_before,
                block_after=after_block, offset_after=after_offset,
                input_after=input_before + size, value=value, size=size,
                physical_input_bytes=size if operation == "load" else 0,
                xasset_index=xasset_index, type_id=9 if xasset_index is not None else None)

        events = [
            op(0, "load", 5, 0, 5, 32, size=32, input_before=0, xasset_index=None),
            dict(kind="begin_asset_call", sequence=1, xasset_index=0),
            op(2, "load", 1, 0, 1, 8, size=8, input_before=32),
            op(3, "load", 5, 32, 5, 96, size=64, input_before=40),
            op(4, "align", 5, 96, 5, 128, value=31),
            op(5, "load", 5, 128, 5, 200, size=72, input_before=104),
            op(6, "align", 5, 200, 5, 200, value=7),
            op(7, "pop", 5, 208, 0, 0),
            dict(kind="packed_resolve", sequence=8, raw_token=pointer,
                 field_stream_location=dict(stream=1, offset=0),
                 resolved_target_stream_location=dict(stream=5, offset=200),
                 xasset_index=0, type_id=9),
        ]
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.jsonl"
            manifest = Path(directory) / "manifest.json"
            trace_bytes = "".join(json.dumps(event) + "\n" for event in events).encode()
            trace.write_bytes(trace_bytes)
            manifest.write_text(json.dumps(dict(profile="replay-1.20",
                xfile_version=0xFF7, complete=True, success=True, tested=1,
                top_level_index=1, serialized_bytes_read=len(body),
                stream_trace_events=len(events),
                stream_trace_sha256=hashlib.sha256(trace_bytes).hexdigest())),
                encoding="utf-8")
            fake_body = SimpleNamespace(asset_table_offset=0,
                                        assets=[SimpleNamespace(type_id=9),
                                                SimpleNamespace(type_id=9)])
            with patch("workstation_luafile_operations.ZoneBody.parse",
                       return_value=fake_body):
                contract = _trace_contract(bytes(body), trace, manifest,
                                           table_row_delta=16)
        target_maps = [value for key, value in contract[7].items()
                       if key[:3] == (0, 1, 0)]
        self.assertEqual(set(target_maps), {200})
        self.assertTrue(any(gap["source_start"] == 200 and
                            gap["source_end"] == 208 and
                            gap["relocated_start"] == 200
                            for gap in contract[-1]["logical_gap_mappings"]))

    def test_existing_row_delete_shifts_absolute_target_across_table_and_child(self):
        body = bytearray(0x200)
        raw = (5 << 32) | (0x301)
        struct.pack_into("<Q", body, 0x100, raw)
        spans = [dict(owner=7, stream=1, start=0x40, end=0x48,
                      archive=0x100, size=8, sequence=1)]
        aliases = [(7, raw, 1, 0x40, 5, 0x300, 5)]
        changed, report = _rebase_aliases(
            bytes(body), spans, aliases, 0x100, 0x80, -16, {},
            removed_stream_ranges=((5, 0x200, 0x280),),
            logical_delete_ranges=((5, 0x200, 0x280),))
        self.assertEqual(struct.unpack_from("<Q", changed, 0x100)[0],
                         (5 << 32) | (0x271))
        self.assertEqual(report["packed_alias_fields_rebased"], 1)

    def test_unresolved_absolute_alias_into_later_table_row_moves_back_one_row(self):
        table_start, asset_count, removed_index = 0x2020, 6012, 4781
        before = table_start + 100 * 16 + 8
        removed = table_start + removed_index * 16 + 8
        after = table_start + 5585 * 16 + 8
        self.assertEqual(_map_deleted_xasset_table_target(before, table_start,
                         asset_count, removed_index), (True, before))
        self.assertEqual(_map_deleted_xasset_table_target(removed, table_start,
                         asset_count, removed_index), (True, None))
        self.assertEqual(_map_deleted_xasset_table_target(after, table_start,
                         asset_count, removed_index), (True, after - 16))
        self.assertEqual(_map_deleted_xasset_table_target(table_start - 8, table_start,
                         asset_count, removed_index), (False, None))

    def test_existing_row_delete_rebases_asset_relative_base_delta(self):
        body = bytearray(0x200)
        old_base, old_target = 0x180, 0x300
        raw = (0x15 << 32) | (old_target - old_base + 1)
        struct.pack_into("<Q", body, 0x100, raw)
        spans = [dict(owner=7, stream=1, start=0x40, end=0x48,
                      archive=0x100, size=8, sequence=1)]
        aliases = [(7, raw, 1, 0x40, 5, old_target, 5)]
        changed, report = _rebase_aliases(
            bytes(body), spans, aliases, 0x100, 0x80, -16, {7: old_base},
            removed_stream_ranges=((5, 0x200, 0x280),),
            logical_delete_ranges=((5, 0x200, 0x280),))
        expected_low = (old_target - 16 - 0x80) - (old_base - 16) + 1
        self.assertEqual(struct.unpack_from("<Q", changed, 0x100)[0],
                         (0x15 << 32) | expected_low)
        self.assertEqual(report["packed_alias_fields_rebased"], 1)

    def test_existing_row_delete_rejects_reference_into_removed_name_or_bytecode(self):
        for target in (0x200, 0x27F):
            raw = (5 << 32) | (target + 1)
            aliases = [(7, raw, 1, 0x40, 5, target, 5)]
            with self.subTest(target=target), self.assertRaisesRegex(
                    ValueError, "inbound packed alias"):
                _rebase_aliases(bytes(0x100), [], aliases, 0x100, 0x80, -16, {},
                                removed_stream_ranges=((5, 0x200, 0x280),),
                                logical_delete_ranges=((5, 0x200, 0x280),))


if __name__ == "__main__":
    unittest.main()
