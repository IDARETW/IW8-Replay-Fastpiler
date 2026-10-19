from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_zone_merge import (  # noqa: E402
    _map_target,
    _native_stream_reservations,
    _rebase_source_pointer,
    _require_mergeable_script_strings,
    _simulate_appended_zone,
    _validate_walk,
    _validate_asset_identity_sets,
    _validate_native_reread_manifest,
    merge_complete_zone,
    write_and_verify_replay_zone,
)
from workstation_fastfiles import ZoneBody  # noqa: E402


class ZoneMergeRelocationTests(unittest.TestCase):
    def test_native_stream_reservations_round_highwaters_to_allocation_units(self):
        self.assertEqual(
            _native_stream_reservations([0, 1, 16, 17, 0, 0, 0, 0, 0, 0, 0]),
            [0, 16, 16, 32, 0, 0, 0, 0, 0, 0, 0])
        with self.assertRaisesRegex(ValueError, "exactly 11"):
            _native_stream_reservations([0] * 10)
        with self.assertRaisesRegex(ValueError, "non-negative"):
            _native_stream_reservations([0] * 10 + [-1])

    def test_output_reader_gate_requires_full_count_and_exact_eof(self):
        manifest = {
            "complete": True, "success": True, "profile": "replay-1.20",
            "xfile_version": 0xFF7, "tested": 7, "top_level_index": 7,
            "failed": 0, "unavailable": 0, "serialized_bytes_read": 0x1234,
        }
        _validate_native_reread_manifest(manifest, 7, 0x1234)
        for changes in (
                {"tested": 6}, {"top_level_index": 6}, {"failed": 1},
                {"unavailable": 1}, {"serialized_bytes_read": 0x1233},
                {"complete": False}, {"success": False}, {"xfile_version": 4085}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "complete output count"):
                _validate_native_reread_manifest({**manifest, **changes}, 7, 0x1234)

    def test_output_reader_gate_preserves_raw_count_with_explicit_reference_rows(self):
        reference = dict(index=0, type_id=9, name=",model_reference",
                         pointer_token=0xFFFFFFFFFFFFFFFD)
        manifest = {
            "complete": True, "success": True, "profile": "replay-1.20",
            "xfile_version": 0xFF7, "tested": 0, "top_level_index": 1,
            "failed": 0, "unavailable": 0, "serialized_bytes_read": 48,
            "reference_only_rows": [reference],
        }
        _validate_native_reread_manifest(manifest, 1, 48, [reference])
        with self.assertRaisesRegex(ValueError, "complete output count"):
            _validate_native_reread_manifest(
                {**manifest, "tested": 1}, 1, 48, [reference])
        with self.assertRaisesRegex(ValueError, "complete output count"):
            _validate_native_reread_manifest(manifest, 1, 48, [])

    def test_map_target_requires_one_owned_span(self):
        segments = {5: [(0x100, 0x120, 0x500), (0x140, 0x150, 0x700)]}
        self.assertEqual(_map_target(segments, 5, 0x118), 0x518)
        with self.assertRaisesRegex(ValueError, "no unique owned"):
            _map_target(segments, 5, 0x120)
        with self.assertRaisesRegex(ValueError, "no unique owned"):
            _map_target({5: [(0x100, 0x120, 0x500), (0x110, 0x130, 0x800)]},
                        5, 0x118)

    def test_global_and_asset_local_pointer_tokens_rebase_from_trace_offsets(self):
        segments = {5: [(0x100, 0x120, 0x220)]}
        old_bases, new_bases = {4: 0x100}, {4: 0x210}
        global_reference = {
            "owner": 4, "raw": (5 << 32) | (0x110 + 1),
            "target_stream": 5, "target_offset": 0x110,
        }
        local_reference = {
            "owner": 4, "raw": (0x15 << 32) | (0x110 - 0x100 + 1),
            "target_stream": 5, "target_offset": 0x110,
        }
        self.assertEqual(_rebase_source_pointer(
            global_reference, segments, old_bases, new_bases),
            ((5 << 32) | 0x231, 0x230))
        self.assertEqual(_rebase_source_pointer(
            local_reference, segments, old_bases, new_bases),
            ((0x15 << 32) | 0x21, 0x230))
        with self.assertRaisesRegex(ValueError, "asset-relative base"):
            _rebase_source_pointer(local_reference, segments, {}, new_bases)
        with self.assertRaisesRegex(ValueError, "not supported"):
            _rebase_source_pointer({**global_reference,
                "raw": (0x25 << 32) | 0x111}, segments, old_bases, new_bases)

    def test_nonempty_source_scriptstring_table_is_rejected(self):
        source = ZoneBody(b"", 1, 32, 48, (), "0" * 64)
        with self.assertRaisesRegex(ValueError, "ScriptStrings; merging"):
            _require_mergeable_script_strings(source)
        _require_mergeable_script_strings(ZoneBody(b"", 0, 32, 32, (), "0" * 64))

    def test_name_collisions_and_duplicate_rows_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "type/name collisions"):
            _validate_asset_identity_sets(
                [{"type_id": 8, "name": "shared/model"}],
                [{"type_id": 8, "name": "shared/model"}])
        with self.assertRaisesRegex(ValueError, "duplicate type/name"):
            _validate_asset_identity_sets(
                [{"type_id": 8, "name": "duplicate"},
                 {"type_id": 8, "name": "duplicate"}], [])
        # Same string under another XAsset type is a distinct native identity.
        self.assertEqual(_validate_asset_identity_sets(
            [{"type_id": 8, "name": "shared/name"}],
            [{"type_id": 9, "name": "shared/name"}]), [])

    def test_source_stream_splice_rebases_alignment_and_asset_local_base(self):
        with tempfile.TemporaryDirectory() as td:
            trace = Path(td) / "trace.jsonl"
            events = [
                {"sequence": 0, "kind": "stream_operation", "operation": "load",
                 "block_before": 5, "offset_before": 0, "block_after": 5,
                 "offset_after": 0x100, "physical_input_bytes": 0x100},
                {"sequence": 1, "kind": "begin_asset_call", "xasset_index": 0},
                {"sequence": 2, "kind": "stream_operation", "operation": "load",
                 "block_before": 5, "offset_before": 0x100, "block_after": 5,
                 "offset_after": 0x118, "physical_input_bytes": 0x18},
                {"sequence": 3, "kind": "stream_operation", "operation": "align",
                 "block_before": 5, "offset_before": 0x118, "block_after": 5,
                 "offset_after": 0x120, "value": 0xF},
                {"sequence": 4, "kind": "stream_operation", "operation": "string",
                 "block_before": 5, "offset_before": 0x120, "block_after": 5,
                 "offset_after": 0x126, "physical_input_bytes": 0},
            ]
            trace.write_text("".join(json.dumps(row) + "\n" for row in events),
                             encoding="utf-8")
            segments, old_bases, new_bases, highwaters = _simulate_appended_zone(
                trace, {5: 0x500}, {5: 0x500}, 1)
        self.assertEqual(old_bases[0], 0x100)
        self.assertEqual(new_bases[0], 0x500)
        self.assertEqual(_map_target(segments, 5, 0x110), 0x510)
        self.assertEqual(highwaters[5], 0x526)

    def test_cross_block_pop_preserves_hidden_insert_slot_highwater(self):
        with tempfile.TemporaryDirectory() as td:
            trace = Path(td) / "trace.jsonl"
            events = [
                {"sequence": 0, "kind": "stream_operation", "operation": "load",
                 "block_before": 5, "offset_before": 0, "block_after": 5,
                 "offset_after": 0x100, "physical_input_bytes": 0x100},
                {"sequence": 1, "kind": "begin_asset_call", "xasset_index": 0},
                {"sequence": 2, "kind": "insert_pointer_slot",
                 "inserted_stream_location": {"stream": 5, "offset": 0x100}},
                # DB_InsertPointer advanced block 5 from 0x100 to 0x108 between
                # explicit operations; the pop exposes that new cursor.
                {"sequence": 3, "kind": "stream_operation", "operation": "pop",
                 "block_before": 5, "offset_before": 0x108, "block_after": 1,
                 "offset_after": 0},
            ]
            trace.write_text("".join(json.dumps(row) + "\n" for row in events))
            _, _, _, highwaters = _simulate_appended_zone(
                trace, {5: 0x500, 1: 0}, {5: 0x500, 1: 0}, 1)
        self.assertEqual(highwaters[5], 0x508)

    def test_invalid_collision_policy_fails_before_trace_access(self):
        import hashlib
        source, target = b"a", b"b"
        with self.assertRaisesRegex(ValueError, "collision_policy='reject'"):
            merge_complete_zone(source, target, source_trace_path="missing-source",
                source_manifest_path="missing-source-manifest", target_trace_path="missing-target",
                target_manifest_path="missing-target-manifest", source_asset_rows=[],
                target_asset_rows=[], expected_source_sha256=hashlib.sha256(source).hexdigest(),
                expected_target_sha256=hashlib.sha256(target).hexdigest(), collision_policy="replace")

    def test_body_hash_drift_fails_before_trace_access(self):
        import hashlib
        source, target = b"source", b"target"
        with self.assertRaisesRegex(ValueError, "body hash differs"):
            merge_complete_zone(source, target, source_trace_path="missing-source",
                source_manifest_path="missing-source-manifest", target_trace_path="missing-target",
                target_manifest_path="missing-target-manifest", source_asset_rows=[],
                target_asset_rows=[], expected_source_sha256=hashlib.sha256(source).hexdigest(),
                expected_target_sha256="0" * 64)

    def test_manifest_cannot_be_paired_with_a_different_trace_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trace = root / "stream-trace.jsonl"
            alternate = root / "other-trace.jsonl"
            journal = root / "assets.jsonl"
            manifest = root / "manifest.json"
            trace.write_text("{}\n", encoding="utf-8")
            alternate.write_text("{}\n", encoding="utf-8")
            journal.write_text("", encoding="utf-8")
            manifest.write_text(json.dumps({
                "profile": "replay-1.20", "xfile_version": 0xFF7,
                "complete": True, "success": True, "failed": 0,
                "unavailable": 0, "tested": 0, "top_level_index": 0,
                "serialized_bytes_read": 0, "stream_trace": trace.name,
                "journal": journal.name,
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not the trace named"):
                _validate_walk(b"", alternate, manifest)

    def test_walk_accounts_for_exact_reference_only_table_rows(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            trace = root / "stream-trace.jsonl"
            journal = root / "assets.jsonl"
            manifest = root / "manifest.json"
            trace.write_text("", encoding="utf-8")
            journal.write_text("", encoding="utf-8")
            token = 0xFFFFFFFFFFFFFFFD
            body = (struct.pack("<IIQIIQ", 0, 0, 0, 1, 0, 0xFFFFFFFFFFFFFFFE) +
                    struct.pack("<IIQ", 9, 0, token))
            reference = dict(index=0, type_id=9, name=",model_reference",
                             pointer_token=token)
            manifest.write_text(json.dumps({
                "profile": "replay-1.20", "xfile_version": 0xFF7,
                "complete": True, "success": True, "failed": 0,
                "unavailable": 0, "tested": 0, "top_level_index": 1,
                "serialized_bytes_read": len(body), "stream_trace": trace.name,
                "journal": journal.name, "reference_only_rows": [reference],
            }), encoding="utf-8")
            walk, _, pins = _validate_walk(body, trace, manifest)
            self.assertEqual(walk["tested"], 0)
            self.assertEqual(pins["native_tested"], 0)
            self.assertEqual(pins["journal_rows"], [{**reference, "status": "reference"}])

            bad = json.loads(manifest.read_text(encoding="utf-8"))
            bad["reference_only_rows"][0]["pointer_token"] = 0
            manifest.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "indexed comma-name"):
                _validate_walk(body, trace, manifest)

    def test_native_writer_refuses_outputs_in_source_game_tree(self):
        with tempfile.TemporaryDirectory() as td:
            zone = Path(td) / "game" / "zone"
            zone.mkdir(parents=True)
            source = zone / "common.ff"
            source.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "outside the source zone directory"):
                write_and_verify_replay_zone(b"", [], [], target_source_fastfile=source,
                    acts_path=Path(td) / "acts.exe", replay_executable=Path(td) / "replay.exe",
                    output_fastfile=zone / "merged.ff")
            with self.assertRaisesRegex(ValueError, "outside the source game directory"):
                write_and_verify_replay_zone(b"", [], [], target_source_fastfile=source,
                    acts_path=Path(td) / "acts.exe", replay_executable=Path(td) / "replay.exe",
                    output_fastfile=zone.parent / "merged.ff")


if __name__ == "__main__":
    unittest.main()
