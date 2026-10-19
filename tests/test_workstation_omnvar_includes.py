from __future__ import annotations

import csv
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_omnvar_includes import (  # noqa: E402
    OmnvarIncludeError,
    bind_omnvar_include_closure,
    discover_omnvar_include_closure,
    read_type54_packed_resolutions,
)


def _csv_bytes(rows):
    import io
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(rows)
    return stream.getvalue().encode("utf-8")


class IncludeResolverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.body = b"synthetic decoded body for binding seam"
        self.body_sha = hashlib.sha256(self.body).hexdigest()
        self.walk = "a" * 64
        self.rows = {
            "omnvars/mp/omnvars.csv": [
                ["include", "omnvars/omnvars_shared_mp_cp.csv", *([""] * 12)],
                ["include", "omnvars/mp/omnvars_brcircle.csv", *([""] * 12)],
                ["root_value", "1", "", "c", "i", "0", "0", "1", "", "", "", "", "", ""],
            ],
            "omnvars/omnvars_shared_mp_cp.csv": [["shared_value", "1", "", "g", "b", "1"]],
            "omnvars/mp/omnvars_brcircle.csv": [["circle_value", "1", "", "c", "t", "0"]],
        }
        native_rows = [
            {"index": i, "type_id": 54, "name": name, "status": "loaded"}
            for i, name in enumerate(self.rows)
        ]
        items = []
        for rank, (name, rows) in enumerate(self.rows.items()):
            payload = _csv_bytes(rows)
            rel = f"payloads/{rank:06d}.csv"
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            items.append(dict(rank=rank, asset_index=rank, type_id=54, name=name,
                              payload_relative_path=rel, payload_bytes=len(payload),
                              payload_sha256=hashlib.sha256(payload).hexdigest()))
        self.native_rows = native_rows
        self.export_index = dict(type_id=54, body_sha256=self.body_sha,
                                 native_walk_key=self.walk, items=items)

    def tearDown(self):
        self.temp.cleanup()

    def discover(self, root_rows=None, *, max_assets=32, max_depth=8):
        return discover_omnvar_include_closure(
            "omnvars/mp/omnvars.csv", self.rows["omnvars/mp/omnvars.csv"] if root_rows is None else root_rows,
            native_rows=self.native_rows, export_root=self.root,
            export_index=self.export_index, expected_body_sha256=self.body_sha,
            expected_native_walk_key=self.walk, max_assets=max_assets, max_depth=max_depth)

    def test_recursive_closure_keeps_native_row_identity_and_order(self):
        result = self.discover()
        self.assertEqual([row["name"] for row in result["tables"]], list(self.rows))
        self.assertEqual([edge["target_name"] for edge in result["include_edges"]],
                         ["omnvars/omnvars_shared_mp_cp.csv", "omnvars/mp/omnvars_brcircle.csv"])
        self.assertEqual([row["asset_index"] for row in result["tables"]], [0, 1, 2])

    def test_discovery_must_be_native_bound_before_names_are_used(self):
        discovered = self.discover()
        traces = {i: {"index": i, "root_archive_offset": i * 100,
                      "end_cursor": i * 100 + 48, "physical_read_count": 1}
                  for i in range(3)}

        class Layout:
            def __init__(self, offset):
                self.root_archive_offset = offset
                self.archive_end = offset + 48
                self.source_record_sha256 = f"{offset:064x}"
                self.name_pointer_mode = "inline"
                self.name_pointer_token = 0xFFFFFFFFFFFFFFFE
                self.name_target_archive_offset = offset + 48
                self.name_target_event_sequence = 3
                self.packed_dictionary_references = ()

        def inspect(body, index, name, trace, rows, expected_body_sha256=None,
                    global_string_data_spans=None, require_packed_dictionary_proof=False):
            self.assertEqual(body, self.body)
            self.assertEqual(expected_body_sha256, self.body_sha)
            self.assertEqual(trace["name"], name)
            return Layout(index * 100), rows

        bound = bind_omnvar_include_closure(
            discovered, body_data=self.body, body_sha256=self.body_sha,
            trace_sha256="b" * 64, trace_assets=traces, global_string_data_spans=[],
            packed_resolutions={index: [] for index in traces},
            inspect_stringtable=inspect)
        self.assertEqual(bound["status"], "native-body-trace-bound")
        self.assertEqual(bound["included_definition_names"], ["shared_value", "circle_value"])
        self.assertTrue(all(table["trace_asset_sha256"] for table in bound["tables"]))

    def test_csv_mutation_cannot_survive_payload_hash_check(self):
        item = self.export_index["items"][1]
        (self.root / item["payload_relative_path"]).write_text("other\n", encoding="utf-8")
        with self.assertRaisesRegex(OmnvarIncludeError, "payload hash changed"):
            self.discover()

    def test_root_text_must_match_native_export_payload(self):
        edited = [list(row) for row in self.rows["omnvars/mp/omnvars.csv"]]
        edited[-1][0] = "forged_root"
        with self.assertRaisesRegex(OmnvarIncludeError, "differs from its hash-pinned"):
            self.discover(edited)

    def test_ambiguous_native_name_is_rejected(self):
        self.native_rows.append({"index": 3, "type_id": 54,
                                 "name": "omnvars/omnvars_shared_mp_cp.csv", "status": "loaded"})
        self.export_index["items"].append(dict(
            rank=3, asset_index=3, type_id=54, name="omnvars/omnvars_shared_mp_cp.csv",
            payload_relative_path="payloads/000001.csv", payload_bytes=self.export_index["items"][1]["payload_bytes"],
            payload_sha256=self.export_index["items"][1]["payload_sha256"]))
        with self.assertRaisesRegex(OmnvarIncludeError, "ambiguous native"):
            self.discover()

    def test_missing_include_is_rejected(self):
        self.rows["omnvars/mp/omnvars.csv"][0][1] = "omnvars/not_loaded.csv"
        self._rewrite_root_payload()
        with self.assertRaisesRegex(OmnvarIncludeError, "missing native"):
            self.discover()

    def test_cycle_and_duplicate_includes_are_rejected(self):
        self.rows["omnvars/omnvars_shared_mp_cp.csv"] = [[
            "include", "omnvars/mp/omnvars.csv", *([""] * 12)]]
        self._rewrite_payload(1)
        with self.assertRaisesRegex(OmnvarIncludeError, "cycle"):
            self.discover()

        self.rows["omnvars/omnvars_shared_mp_cp.csv"] = [["shared_value", "1", "", "g", "b", "1"]]
        self._rewrite_payload(1)
        self.rows["omnvars/mp/omnvars.csv"].insert(1, list(self.rows["omnvars/mp/omnvars.csv"][0]))
        self._rewrite_root_payload()
        with self.assertRaisesRegex(OmnvarIncludeError, "duplicate include"):
            self.discover()

    def test_bounds_and_unsafe_paths_fail_closed(self):
        with self.assertRaisesRegex(OmnvarIncludeError, "asset count exceeds"):
            self.discover(max_assets=2)
        with self.assertRaisesRegex(OmnvarIncludeError, "depth exceeds"):
            self.discover(max_depth=0)
        self.rows["omnvars/mp/omnvars.csv"][0][1] = "../outside.csv"
        self._rewrite_root_payload()
        with self.assertRaisesRegex(OmnvarIncludeError, "unsafe"):
            self.discover()

    def test_binding_requires_each_trace_owned_table(self):
        discovered = self.discover()
        traces = {0: {"index": 0}}
        with self.assertRaisesRegex(OmnvarIncludeError, "omits included"):
            bind_omnvar_include_closure(
                discovered, body_data=self.body, body_sha256=self.body_sha,
                trace_sha256="b" * 64, trace_assets=traces, global_string_data_spans=[],
                packed_resolutions={index: [] for index in traces},
                inspect_stringtable=lambda *args, **kwargs: self.fail("must not inspect incomplete set"))

    def test_packed_resolution_projection_requires_complete_ordered_trace(self):
        events = [
            {"sequence": 0, "kind": "xasset_begin", "xasset_index": 2},
            {"sequence": 1, "kind": "packed_resolve", "xasset_index": 2,
             "type_id": 54, "raw_token": (5 << 32) | 33,
             "field_stream_location": {"stream": 1, "offset": 0},
             "resolved_target_stream_location": {"stream": 5, "offset": 32}},
            {"sequence": 2, "kind": "xasset_end", "xasset_index": 2},
        ]
        path = self.root / "trace.jsonl"
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        result = read_type54_packed_resolutions(path, {2, 9}, 3)
        self.assertEqual(len(result[2]), 1)
        self.assertEqual(result[9], [])
        broken = [dict(event) for event in events]
        broken[-1]["sequence"] = 8
        path.write_text("".join(json.dumps(event) + "\n" for event in broken), encoding="utf-8")
        with self.assertRaisesRegex(OmnvarIncludeError, "sequence is discontinuous"):
            read_type54_packed_resolutions(path, {2}, 3)
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        with self.assertRaisesRegex(OmnvarIncludeError, "event count differs"):
            read_type54_packed_resolutions(path, {2}, 2)

    def _rewrite_payload(self, rank):
        item = self.export_index["items"][rank]
        payload = _csv_bytes(self.rows[item["name"]])
        (self.root / item["payload_relative_path"]).write_bytes(payload)
        item["payload_bytes"] = len(payload)
        item["payload_sha256"] = hashlib.sha256(payload).hexdigest()

    def _rewrite_root_payload(self):
        self._rewrite_payload(0)


if __name__ == "__main__":
    unittest.main()
