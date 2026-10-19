from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_stringtable import (  # noqa: E402
    _map_replaced_table_target,
    replace_stringtable_rows,
)


class NoopStringTableReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.trace = self.root / "stream-trace.jsonl"
        self.manifest = self.root / "manifest.json"
        self.body = b"decoded-body-fixture"
        self.rows = [["key", "value"]]
        self.trace.write_text(
            json.dumps(dict(kind="xasset_begin", sequence=0, xasset_index=0,
                            asset_type=54, root_stream_location={"stream": 1, "offset": 0})) + "\n" +
            json.dumps(dict(kind="xasset_end", sequence=1, xasset_index=0,
                            serialized_input_cursor=0)) + "\n",
            encoding="utf-8")
        self.write_manifest()
        self.layout = SimpleNamespace(rows=1, columns=2, dictionary_count=2)

    def write_manifest(self, **overrides):
        manifest = dict(
            profile="replay-1.20", xfile_version=0xFF7, complete=True, success=True,
            failed=0, unavailable=0,
            stream_trace_events=2, stream_trace_enabled=True, tested=1,
            top_level_index=1, reference_only_rows=[], serialized_bytes_read=len(self.body))
        manifest.update(overrides)
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

    def invoke(self):
        with mock.patch("workstation_stringtable.inspect_stringtable",
                        return_value=(self.layout, self.rows)):
            return replace_stringtable_rows(
                self.body, 0, "omnvars/mp/omnvars.csv",
                {"xasset_index": 0, "type_id": 54, "name": "omnvars/mp/omnvars.csv"},
                self.rows, self.rows, hashlib.sha256(self.body).hexdigest(),
                self.trace, self.manifest)

    def test_noop_preserves_exact_body_and_standard_reservation_receipt(self):
        output, receipt = self.invoke()
        self.assertEqual(output, self.body)
        self.assertEqual(receipt["status"], "no-op-stringtable-edit")
        self.assertEqual(receipt["stream_reservation_deltas"],
                         {str(block): 0 for block in range(1, 6)})
        self.assertEqual(receipt["old_stream_high_waters"], {})
        self.assertEqual(receipt["new_stream_high_waters"], {})
        self.assertEqual(receipt["new_stream5_high_water"], 0)
        self.assertEqual(receipt["full_native_trace_events"], 2)

    def test_incomplete_walk_is_rejected_even_for_noop(self):
        self.write_manifest(complete=False)
        with self.assertRaisesRegex(ValueError, "complete successful native stream trace"):
            self.invoke()

    def test_failed_or_unavailable_counts_must_be_exact_integer_zero(self):
        for field, value in (("failed", 1), ("failed", False),
                             ("unavailable", 1), ("unavailable", False)):
            with self.subTest(field=field, value=value):
                self.write_manifest(**{field: value})
                with self.assertRaisesRegex(ValueError, "complete successful native stream trace"):
                    self.invoke()

    def test_highwaters_reject_invalid_stream_ids_and_negative_values(self):
        from workstation_trace_index import build_read_span_index

        for highwaters in ({-1: 4}, {11: 4}, {5: -1}, {True: 4}):
            with self.subTest(highwaters=highwaters):
                with mock.patch("workstation_trace_index.build_read_span_index",
                                return_value=dict(status="native-read-spans-indexed",
                                                  event_count=2, xasset_count=1,
                                                  assets=[dict(index=0, type_id=54,
                                                               read_spans=[])],
                                                  preamble_spans=[],
                                                  physical_load_count_by_stream={},
                                                  physical_load_bytes_by_stream={},
                                                  string_data_spans=[],
                                                  max_destination_offsets=highwaters)):
                    with self.assertRaisesRegex(ValueError, "invalid stream high-water"):
                        self.invoke()

    def test_trace_sequence_or_table_coverage_mismatch_is_rejected(self):
        self.trace.write_text(
            json.dumps(dict(kind="xasset_begin", sequence=0, xasset_index=0, asset_type=54,
                            root_stream_location={"stream": 1, "offset": 0})) + "\n" +
            json.dumps(dict(kind="xasset_end", sequence=2, xasset_index=0,
                            serialized_input_cursor=0)) + "\n",
            encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "sequence discontinuity"):
            self.invoke()

    def test_removed_dictionary_target_is_rejected_only_when_referenced(self):
        old_start, old_end = 100, 160
        preserved = {112: 212}
        removed = {128}
        # An unused removed value is not queried during replacement mapping.
        self.assertIsNone(_map_replaced_table_target(99, old_start, old_end,
                                                     preserved, removed))
        self.assertEqual(_map_replaced_table_target(112, old_start, old_end,
                                                    preserved, removed), 212)
        with self.assertRaisesRegex(ValueError, "targets removed StringTable dictionary string"):
            _map_replaced_table_target(128, old_start, old_end, preserved, {128})
        with self.assertRaisesRegex(ValueError, "non-string bytes"):
            _map_replaced_table_target(140, old_start, old_end, preserved, set())
        self.assertIsNone(_map_replaced_table_target(old_end, old_start, old_end,
                                                     preserved, set()))


if __name__ == "__main__":
    unittest.main()
