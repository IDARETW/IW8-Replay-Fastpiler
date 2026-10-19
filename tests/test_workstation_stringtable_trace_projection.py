from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_omnvar_includes import (  # noqa: E402
    project_type54_packed_resolution,
    read_type54_packed_resolutions,
)
from workstation_trace_index import build_read_span_index  # noqa: E402


class StringTableTraceProjectionTests(unittest.TestCase):
    def test_complete_index_preserves_exact_packed_root_callback_only(self):
        root_location = {"stream": 1, "offset": 0}
        root_event = {
            "sequence": 1, "kind": "packed_resolve", "xasset_index": 0,
            "type_id": 54, "raw_token": 0x500000101,
            "field_stream_location": root_location,
            "resolved_target_stream_location": {"stream": 5, "offset": 100},
        }
        child_event = {
            "sequence": 2, "kind": "packed_resolve", "xasset_index": 0,
            "type_id": 54, "raw_token": 0x500000102,
            "field_stream_location": {"stream": 5, "offset": 24},
            "resolved_target_stream_location": {"stream": 5, "offset": 200},
        }
        events = [
            {"sequence": 0, "kind": "xasset_begin", "xasset_index": 0,
             "asset_type": 54, "root_stream_location": root_location,
             "serialized_input_cursor": 0},
            root_event,
            child_event,
            {"sequence": 3, "kind": "xasset_end", "xasset_index": 0,
             "serialized_input_cursor": 0},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace, manifest = root / "trace.jsonl", root / "manifest.json"
            trace.write_text("".join(json.dumps(event, separators=(",", ":")) + "\n"
                                     for event in events), encoding="utf-8")
            manifest.write_text(json.dumps({
                "stream_trace_events": len(events), "tested": 1, "top_level_index": 1,
                "reference_only_rows": [], "serialized_bytes_read": 0,
            }), encoding="utf-8")

            indexed = build_read_span_index(trace, manifest, body_size=0)
            projected = indexed["assets"][0]["root_name_resolution_events"]
            resolutions = read_type54_packed_resolutions(trace, {0}, len(events))[0]

        self.assertEqual(project_type54_packed_resolution(root_event), root_event)
        self.assertEqual(projected, [root_event, child_event])
        self.assertEqual(projected, resolutions)

    def test_projection_ignores_non_type54_and_malformed_owner(self):
        self.assertIsNone(project_type54_packed_resolution({
            "kind": "packed_resolve", "type_id": 12, "xasset_index": 0,
        }))
        self.assertIsNone(project_type54_packed_resolution({
            "kind": "packed_resolve", "type_id": 54, "xasset_index": True,
        }))


if __name__ == "__main__":
    unittest.main()
