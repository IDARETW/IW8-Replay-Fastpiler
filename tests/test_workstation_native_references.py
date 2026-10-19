from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_native_references import normalize_native_inventory


REFERENCE = 0xFFFFFFFFFFFFFFFD
INLINE = 0xFFFFFFFFFFFFFFFE


def _fixture(name: bytes = b",external\0"):
    ordinary = b"ordinary\0"
    root0 = 64
    name0 = root0 + 16
    root1 = name0 + len(name)
    name1 = root1 + 16
    body = bytearray(name1 + len(ordinary))
    struct.pack_into("<IIQIIQ", body, 0, 0, 0, 0, 2, 0, INLINE)
    struct.pack_into("<IIQ", body, 32, 11, 0, REFERENCE)
    struct.pack_into("<IIQ", body, 48, 9, 0, REFERENCE)
    struct.pack_into("<Q", body, root0, INLINE)
    body[name0:name0 + len(name)] = name
    struct.pack_into("<Q", body, root1, INLINE)
    body[name1:name1 + len(ordinary)] = ordinary
    events = []

    def add(event):
        event["sequence"] = len(events)
        events.append(event)

    for index, start, asset_name, type_id in ((0, root0, name, 11),
                                               (1, root1, ordinary, 9)):
        root_end = start + 16
        name_end = root_end + len(asset_name)
        add({"kind": "xasset_begin", "xasset_index": index, "type_id": type_id,
             "pointer_token": REFERENCE, "serialized_input_cursor": start})
        add({"kind": "begin_asset_call", "xasset_index": index, "type_id": type_id,
             "root_stream_location": {"stream": 1, "offset": 0}})
        add({"kind": "load_stream_call", "xasset_index": index, "type_id": type_id,
             "loader_start_arg": 0, "at_start": True, "size": 16,
             "destination_stream_location": {"stream": 1, "offset": 0},
             "serialized_input_cursor": start})
        add({"kind": "stream_operation", "operation": "load", "xasset_index": index,
             "type_id": type_id, "block_before": 1, "offset_before": 0,
             "block_after": 1, "offset_after": 16, "input_before": start,
             "input_after": root_end, "size": 16, "physical_input_bytes": 16})
        add({"kind": "string_call", "xasset_index": index, "type_id": type_id,
             "field_stream_location": {"stream": 1, "offset": 0},
             "serialized_input_cursor": root_end})
        add({"kind": "stream_operation", "operation": "string", "xasset_index": index,
             "type_id": type_id, "input_before": root_end, "size": len(asset_name),
             "physical_input_bytes": 0})
        add({"kind": "stream_operation", "operation": "load", "xasset_index": index,
             "type_id": type_id, "block_before": 5, "offset_before": 100,
             "block_after": 5, "offset_after": 100 + len(asset_name),
             "input_before": root_end, "input_after": name_end,
             "size": len(asset_name), "physical_input_bytes": len(asset_name)})
        if index != 0:
            add({"kind": "asset_root_link", "xasset_index": index, "type_id": type_id,
                 "root_bytes": 16, "root_stream_location": {"stream": 1, "offset": 0},
                 "root_archive_input_cursor": name_end})
        add({"kind": "xasset_end", "xasset_index": index, "type_id": type_id})
    return bytes(body), events


class WorkstationNativeReferenceTests(unittest.TestCase):
    def run_fixture(self, *, name: bytes = b",external\0", rows=None, events=None,
                    manifest_overrides=None):
        body, generated_events = _fixture(name)
        events = generated_events if events is None else events
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            trace = root / "trace.jsonl"
            trace.write_text("".join(json.dumps(event) + "\n" for event in events),
                             encoding="utf-8")
            manifest = dict(profile="replay-1.20", xfile_version=4087,
                            complete=True, success=True, failed=0, unavailable=0,
                            tested=1, top_level_index=2, serialized_bytes_read=len(body))
            manifest.update(manifest_overrides or {})
            raw_rows = rows if rows is not None else [
                {"type": "other", "type_id": 9, "name": "ordinary"}]
            return normalize_native_inventory(body, trace, manifest, raw_rows)

    def test_derives_reference_and_interleaves_raw_rows_without_rewriting_them(self):
        result = self.run_fixture()
        self.assertEqual(result["raw_tested_count"], 1)
        self.assertEqual(result["normalized_inventory_count"], 2)
        self.assertEqual(result["reference_only_rows"][0]["name"], ",external")
        self.assertEqual(result["reference_only_rows"][0]["type_id"], 11)
        self.assertIsNone(result["reference_only_rows"][0]["root_link_sequence"])
        self.assertEqual([row["name"] for row in result["normalized_rows"]],
                         [",external", "ordinary"])
        self.assertEqual(result["normalized_rows"][1]["index"], 1)

    def test_rejects_non_comma_root_names(self):
        with self.assertRaisesRegex(ValueError, "does not reconcile"):
            self.run_fixture(name=b"external\0")

    def test_rejects_empty_comma_reference_basename(self):
        with self.assertRaisesRegex(ValueError, "empty comma-reference basename"):
            self.run_fixture(name=b",\0")

    def test_rejects_raw_journal_identity_mismatch(self):
        with self.assertRaisesRegex(ValueError, "journal identity/order"):
            self.run_fixture(rows=[{"type_id": 9, "name": "wrong"}])

    def test_rejects_trace_sequence_gap(self):
        _, events = _fixture()
        events[3]["sequence"] = 30
        with self.assertRaisesRegex(ValueError, "sequence breaks"):
            self.run_fixture(events=events)

    def test_rejects_missing_table_callback(self):
        _, events = _fixture()
        events.pop()
        with self.assertRaisesRegex(ValueError, "does not cover every XAsset"):
            self.run_fixture(events=events)

    def test_rejects_boolean_trace_index_and_sequence(self):
        _, events = _fixture()
        events[0]["sequence"] = False
        with self.assertRaisesRegex(ValueError, "sequence breaks"):
            self.run_fixture(events=events)
        _, events = _fixture()
        events[0]["xasset_index"] = False
        with self.assertRaisesRegex(ValueError, "out-of-range"):
            self.run_fixture(events=events)

    def test_rejects_callback_order_and_overlap(self):
        _, events = _fixture()
        index1_begin = next(event for event in events
                            if event.get("kind") == "xasset_begin" and
                            event.get("xasset_index") == 1)
        index1_end = next(event for event in events
                          if event.get("kind") == "xasset_end" and
                          event.get("xasset_index") == 1)
        events.remove(index1_begin)
        events.remove(index1_end)
        events = [index1_begin, index1_end, *events]
        for sequence, event in enumerate(events):
            event["sequence"] = sequence
        with self.assertRaisesRegex(ValueError, "table index order"):
            self.run_fixture(events=events)

        _, events = _fixture()
        index1_begin = next(event for event in events
                            if event.get("kind") == "xasset_begin" and
                            event.get("xasset_index") == 1)
        events.remove(index1_begin)
        index0_end = next(i for i, event in enumerate(events)
                          if event.get("kind") == "xasset_end" and
                          event.get("xasset_index") == 0)
        events.insert(index0_end, index1_begin)
        for sequence, event in enumerate(events):
            event["sequence"] = sequence
        with self.assertRaisesRegex(ValueError, "callback ranges overlap"):
            self.run_fixture(events=events)

    def test_rejects_boolean_root_size_and_manifest_trace_count_mismatch(self):
        _, events = _fixture()
        events[2]["size"] = True
        with self.assertRaisesRegex(ValueError, "invalid traced root extent"):
            self.run_fixture(events=events)
        _, events = _fixture()
        with self.assertRaisesRegex(ValueError, "event count differs"):
            self.run_fixture(events=events, manifest_overrides={"stream_trace_events": 999})


if __name__ == "__main__":
    unittest.main()
