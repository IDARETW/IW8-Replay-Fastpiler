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
    _resolve_packed_dictionary_string,
    _resolve_stringtable_name,
    _serialize_record,
    replace_stringtable_rows,
)
from workstation_asset_codecs import (  # noqa: E402
    _stringtable_hash,
    encode_stringtable_sections,
)
import struct


def root_trace(index: int, token: int, target: int, begin: int = 50, end: int = 80,
               field: dict | None = None) -> dict:
    field = field or {"stream": 1, "offset": 0}
    event = dict(kind="packed_resolve", sequence=begin + 2, xasset_index=index,
                 type_id=54, raw_token=token, field_stream_location=field,
                 resolved_target_stream_location={"stream": 5, "offset": target})
    return dict(read_spans=[], begin_sequence=begin, end_sequence=end, index=index,
                root_stream_location=field, root_name_resolution_events=[event])


class SharedStringTableNameTests(unittest.TestCase):
    def test_inline_name_keeps_existing_representation(self):
        name = "inline/table.csv"
        raw = name.encode() + b"\0"
        body = bytearray(128)
        body[48:48 + len(raw)] = raw
        span = dict(origin="string_data", archive_offset=48, size=len(raw),
                    destination_stream_location={"stream": 5, "offset": 100},
                    event_sequence=11)
        trace = dict(read_spans=[span], begin_sequence=10)
        resolved, mode, sequence = _resolve_stringtable_name(
            0xFFFFFFFFFFFFFFFE, name, 0, 10, bytes(body), trace, None)
        self.assertIs(resolved, span)
        self.assertEqual((mode, sequence), ("inline", 11))

    def test_packed_name_must_resolve_to_prior_exact_stream5_string(self):
        name = "omnvars/shared.csv"
        raw = name.encode() + b"\0"
        body = bytearray(128)
        body[12:12 + len(raw)] = raw
        global_span = dict(origin="string_data", archive_offset=12, size=len(raw),
                           destination_stream_location={"stream": 5, "offset": 0x240},
                           event_sequence=44)
        trace = root_trace(7, (5 << 32) | (0x240 + 1), 0x240)
        token = (5 << 32) | (0x240 + 1)
        resolved, mode, sequence = _resolve_stringtable_name(
            token, name, 80, 51, bytes(body), trace, [global_span])
        self.assertIs(resolved, global_span)
        self.assertEqual((mode, sequence), ("packed-shared-stream5", 44))

    def test_wrong_target_bytes_and_non_stream5_target_are_rejected(self):
        name = "omnvars/shared.csv"
        body = bytearray(128)
        raw = name.encode() + b"\0"
        body[12:12 + len(raw)] = b"x" * (len(raw) - 1) + b"\0"
        span = dict(origin="string_data", archive_offset=12, size=len(raw),
                    destination_stream_location={"stream": 5, "offset": 0x240},
                    event_sequence=44)
        token = (5 << 32) | 0x241
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            _resolve_stringtable_name(token, name, 80, 51, bytes(body),
                                      root_trace(7, token, 0x240), [span])
        span["destination_stream_location"]["stream"] = 1
        with self.assertRaisesRegex(ValueError, "found 0"):
            _resolve_stringtable_name(token, name, 80, 51, bytes(body),
                                      root_trace(7, token, 0x240), [span])

    def test_missing_truncated_future_and_ambiguous_packed_targets_fail(self):
        name = "shared.csv"
        body = bytearray(64)
        body[8:19] = b"shared.csv\0"
        span = dict(origin="string_data", archive_offset=8, size=11,
                    destination_stream_location={"stream": 5, "offset": 0x80},
                    event_sequence=4)
        token = (5 << 32) | 0x81
        trace = root_trace(3, token, 0x80, begin=5, end=9)
        with self.assertRaisesRegex(ValueError, "complete native string-data"):
            _resolve_stringtable_name(token, name, 32, 6, bytes(body), trace, None)
        with self.assertRaisesRegex(ValueError, "earlier shared"):
            _resolve_stringtable_name((5 << 32) | 1, name, 32, 6, bytes(body),
                                      root_trace(3, (5 << 32) | 1, 0, begin=5, end=9), [span])
        future = dict(span, event_sequence=5)
        with self.assertRaisesRegex(ValueError, "earlier shared"):
            _resolve_stringtable_name(token, name, 32, 6, bytes(body),
                                      root_trace(3, token, 0x80, begin=5, end=9), [future])
        with self.assertRaisesRegex(ValueError, "found 2"):
            _resolve_stringtable_name(token, name, 32, 6, bytes(body),
                                      root_trace(3, token, 0x80, begin=5, end=9), [span, dict(span)])

    def test_packed_name_requires_exact_owner_field_and_pointee_callback(self):
        name = "shared.csv"
        raw = name.encode() + b"\0"
        body = bytearray(64)
        body[8:8 + len(raw)] = raw
        span = dict(origin="string_data", archive_offset=8, size=len(raw),
                    destination_stream_location={"stream": 5, "offset": 0x80},
                    event_sequence=4)
        token = (5 << 32) | 0x81
        trace = root_trace(3, token, 0x80, begin=5, end=9)
        event = trace["root_name_resolution_events"][0]
        event["resolved_target_stream_location"] = {"stream": 5, "offset": 0x88}
        with self.assertRaisesRegex(ValueError, "matching root-name packed_resolve"):
            _resolve_stringtable_name(token, name, 32, 6, bytes(body), trace, [span])

    def test_packed_dictionary_binds_exact_slot_callback_and_target_bytes(self):
        value = "shared_dictionary_value"
        allocation = b"prefix:" + value.encode() + b"\0"
        body = bytearray(160)
        body[24:24 + len(allocation)] = allocation
        stream_start, displacement = 0x300, len(b"prefix:")
        target_offset = stream_start + displacement
        token = (5 << 32) | (target_offset + 1)
        owner, dictionary_index = 11, 4
        slot = {"stream": 5, "offset": 0x900 + dictionary_index * 8}
        event = dict(kind="packed_resolve", sequence=80, xasset_index=owner,
                     type_id=54, raw_token=token, field_stream_location=slot,
                     resolved_target_stream_location={"stream": 5, "offset": target_offset})
        span = dict(origin="string_data", archive_offset=24, size=len(allocation),
                    destination_stream_location={"stream": 5, "offset": stream_start},
                    event_sequence=42)
        proof = _resolve_packed_dictionary_string(
            dictionary_index=dictionary_index, token=token, expected_value=value,
            pointer_stream_offset=0x900, owner_index=owner, begin_sequence=70,
            end_sequence=100, resolution_events=[event],
            global_string_data_spans=[span], body_data=bytes(body))
        self.assertEqual(proof["target_archive_offset"], 24 + displacement)
        self.assertEqual(proof["resolution_event_sequence"], 80)

    def test_corrupt_packed_dictionary_target_rejected_even_when_csv_hash_matches(self):
        expected = "expected_dictionary_value"
        # This is the exact hash section the CSV encoder accepts for the
        # semantic table, while the packed pointer resolves elsewhere.
        encoded = encode_stringtable_sections("t.csv", [[expected]])
        self.assertEqual(encoded["hashes"], struct.pack("<I", _stringtable_hash(expected)))
        actual = b"different_dictionary_value\0"
        body = bytearray(128)
        body[16:16 + len(actual)] = actual
        stream_start = 0x700
        token = (5 << 32) | (stream_start + 1)
        event = dict(kind="packed_resolve", sequence=20, xasset_index=5,
                     type_id=54, raw_token=token,
                     field_stream_location={"stream": 5, "offset": 0x400},
                     resolved_target_stream_location={"stream": 5, "offset": stream_start})
        span = dict(origin="string_data", archive_offset=16, size=len(actual),
                    destination_stream_location={"stream": 5, "offset": stream_start},
                    event_sequence=9)
        with self.assertRaisesRegex(ValueError, "exact target string allocation"):
            _resolve_packed_dictionary_string(
                dictionary_index=0, token=token, expected_value=expected,
                pointer_stream_offset=0x400, owner_index=5, begin_sequence=10,
                end_sequence=30, resolution_events=[event],
                global_string_data_spans=[span], body_data=bytes(body))

    def test_packed_dictionary_rejects_wrong_slot_event_and_missing_target_span(self):
        value = "value"
        raw = value.encode() + b"\0"
        body = bytearray(64)
        body[8:8 + len(raw)] = raw
        target_offset = 0x220
        token = (5 << 32) | (target_offset + 1)
        event = dict(kind="packed_resolve", sequence=20, xasset_index=6,
                     type_id=54, raw_token=token,
                     field_stream_location={"stream": 5, "offset": 0x508},
                     resolved_target_stream_location={"stream": 5, "offset": target_offset})
        span = dict(origin="string_data", archive_offset=8, size=len(raw),
                    destination_stream_location={"stream": 5, "offset": target_offset},
                    event_sequence=12)
        common = dict(dictionary_index=1, token=token, expected_value=value,
                      pointer_stream_offset=0x500, owner_index=6, begin_sequence=10,
                      end_sequence=30, resolution_events=[event],
                      global_string_data_spans=[span], body_data=bytes(body))
        with self.assertRaisesRegex(ValueError, "packed_resolve callback"):
            _resolve_packed_dictionary_string(**{**common, "pointer_stream_offset": 0x600})
        with self.assertRaisesRegex(ValueError, "exact target string allocation"):
            _resolve_packed_dictionary_string(**{**common, "global_string_data_spans": []})

    def test_packed_dictionary_rejects_later_reused_stream_allocation(self):
        value = "reused_offset_value"
        raw = value.encode() + b"\0"
        body = bytearray(64)
        body[8:8 + len(raw)] = raw
        target_offset = 0x220
        token = (5 << 32) | (target_offset + 1)
        event = dict(kind="packed_resolve", sequence=20, xasset_index=6,
                     type_id=54, raw_token=token,
                     field_stream_location={"stream": 5, "offset": 0x508},
                     resolved_target_stream_location={"stream": 5, "offset": target_offset})
        # The same logical cursor may be reused later in another allocation.
        # Bytes and address alone cannot prove that this later allocation was
        # live when the pointer callback ran.
        later = dict(origin="string_data", archive_offset=8, size=len(raw),
                     destination_stream_location={"stream": 5, "offset": target_offset},
                     event_sequence=21)
        with self.assertRaisesRegex(ValueError, "exact target string allocation"):
            _resolve_packed_dictionary_string(
                dictionary_index=1, token=token, expected_value=value,
                pointer_stream_offset=0x500, owner_index=6, begin_sequence=10,
                end_sequence=30, resolution_events=[event],
                global_string_data_spans=[later], body_data=bytes(body))

        missing_sequence = dict(later)
        missing_sequence.pop("event_sequence")
        with self.assertRaisesRegex(ValueError, "exact target string allocation"):
            _resolve_packed_dictionary_string(
                dictionary_index=1, token=token, expected_value=value,
                pointer_stream_offset=0x500, owner_index=6, begin_sequence=10,
                end_sequence=30, resolution_events=[event],
                global_string_data_spans=[missing_sequence], body_data=bytes(body))

    def test_packed_dictionary_rejects_prior_reuse_before_callback(self):
        value = "expected_before_reuse"
        expected = value.encode() + b"\0"
        replacement = b"wrong_before_reuse\0"
        body = bytearray(128)
        body[8:8 + len(expected)] = expected
        body[48:48 + len(replacement)] = replacement
        target_offset = 0x220
        token = (5 << 32) | (target_offset + 1)
        event = dict(kind="packed_resolve", sequence=20, xasset_index=6,
                     type_id=54, raw_token=token,
                     field_stream_location={"stream": 5, "offset": 0x508},
                     resolved_target_stream_location={"stream": 5, "offset": target_offset})
        old = dict(origin="string_data", archive_offset=8, size=len(expected),
                   destination_stream_location={"stream": 5, "offset": target_offset},
                   event_sequence=10)
        reused = dict(origin="string_data", archive_offset=48, size=len(replacement),
                      destination_stream_location={"stream": 5, "offset": target_offset},
                      event_sequence=19)
        with self.assertRaisesRegex(ValueError, "one unambiguous.*found 2"):
            _resolve_packed_dictionary_string(
                dictionary_index=1, token=token, expected_value=value,
                pointer_stream_offset=0x500, owner_index=6, begin_sequence=11,
                end_sequence=30, resolution_events=[event],
                global_string_data_spans=[old, reused], body_data=bytes(body))

    def test_packed_name_rejects_prior_reuse_before_callback(self):
        name = "shared.csv"
        expected = name.encode() + b"\0"
        replacement = b"other.csv\0"
        body = bytearray(96)
        body[8:8 + len(expected)] = expected
        body[48:48 + len(replacement)] = replacement
        target_offset = 0x240
        token = (5 << 32) | (target_offset + 1)
        trace = root_trace(7, token, target_offset, begin=50, end=80)
        old = dict(origin="string_data", archive_offset=8, size=len(expected),
                   destination_stream_location={"stream": 5, "offset": target_offset},
                   event_sequence=44)
        # Reuse occurs after the owning asset begins but before its packed
        # root-name callback at sequence 52.
        reused = dict(origin="string_data", archive_offset=48, size=len(replacement),
                      destination_stream_location={"stream": 5, "offset": target_offset},
                      event_sequence=51)
        with self.assertRaisesRegex(ValueError, "one unambiguous.*found 2"):
            _resolve_stringtable_name(token, name, 80, 51, bytes(body), trace,
                                      [old, reused])

    def test_packed_shared_name_stays_shared_when_serializing_table(self):
        name_token = (5 << 32) | 0x1235
        layout = SimpleNamespace(
            name_pointer_mode="packed-shared-stream5", name_pointer_token=name_token,
            asset_name="shared.csv", name_stream_offset=0x1234, root_archive_offset=0,
            cells_stream_offset=0x2000)
        record, emitted = _serialize_record(bytes(48), layout, [["key", "value"]])
        self.assertEqual(int.from_bytes(record[:8], "little"), name_token)
        self.assertEqual(len(record), 48 + len(emitted["sections"]["cells"]) +
                         len(emitted["sections"]["hashes"]) +
                         len(emitted["sections"]["dictionary"]) * 8 +
                         sum(len(value.encode("utf-8")) + 1
                             for value in emitted["sections"]["dictionary"]))
        self.assertNotIn(b"shared.csv\0", record)
        self.assertEqual(emitted["stream5_start"], 0x2000)

    def test_replacement_writer_reparses_body_through_fastfiles_zonebody(self):
        body = b"ABCDEFGH"
        body_sha = hashlib.sha256(body).hexdigest()
        layout = SimpleNamespace(
            asset_index=0, asset_name="fixture.csv", name_pointer_mode="inline",
            root_archive_offset=0, archive_end=1, source_body_sha256=body_sha,
            source_record_sha256="a" * 64, rows=1, columns=1, dictionary_count=1,
            name_stream_offset=50, name_bytes=len(b"fixture.csv"),
            cells_stream_offset=62, cells_bytes=2,
            hashes_stream_offset=68, hashes_bytes=4,
            pointers_stream_offset=20, pointers_bytes=8,
            inline_dictionary_strings=((0, 0, 10, 3),),
            dictionary_values=("old",))
        record = b"Z"
        emitted = dict(sections={"rows": 1, "columns": 1, "dictionary": ["old"]}, stream5_end=101,
                       new_string_offsets={"old": 100}, record_sha256="b" * 64)
        events = [
            {"sequence": 0, "kind": "xasset_begin", "xasset_index": 0},
            {"sequence": 1, "kind": "stream_operation", "operation": "load",
             "block_before": 5, "block_after": 5, "offset_before": 0,
             "offset_after": 1, "size": 1, "physical_input_bytes": 1,
             "input_before": 0, "xasset_index": 0},
            {"sequence": 2, "kind": "xasset_end", "xasset_index": 0},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace_path = root / "trace.jsonl"
            trace_path.write_text("".join(json.dumps(event) + "\n" for event in events),
                                  encoding="utf-8")
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(dict(
                profile="replay-1.20", xfile_version=0xFF7, complete=True,
                success=True, stream_trace_events=len(events), tested=1,
                top_level_index=1, serialized_bytes_read=len(body),
                stream_trace_enabled=True)), encoding="utf-8")

            fake_zone_body = type("FakeZoneBody", (), {
                "parse": staticmethod(lambda _data: SimpleNamespace(assets=("same",)))})
            stream_index = dict(
                status="native-read-spans-indexed", body_size=len(body),
                event_count=len(events), xasset_count=1,
                preamble_spans=[],
                assets=[dict(index=0, type_id=54, root_name_resolution_events=[], read_spans=[
                    dict(origin="unclassified_load", archive_offset=0, size=1,
                         destination_stream_location={"stream": 5, "offset": 0},
                         event_sequence=1)])],
                physical_load_count_by_stream={5: 1},
                physical_load_bytes_by_stream={5: 1}, string_data_spans=[])
            with (mock.patch("workstation_trace_index.build_read_span_index",
                             return_value=stream_index),
                  mock.patch("workstation_stringtable._serialize_record",
                             return_value=(record, emitted)),
                  mock.patch("workstation_stringtable.inspect_stringtable") as inspect,
                  mock.patch("workstation_fastfiles.ZoneBody", fake_zone_body, create=True)):
                inspect.return_value = (layout, [["old"]])
                output, receipt = replace_stringtable_rows(
                    body, 0, "fixture.csv", {"root_name_resolution_events": []}, [["old"]], [["new"]],
                    body_sha, trace_path, manifest_path)
                self.assertEqual(inspect.call_args.kwargs["global_string_data_spans"], [])
        self.assertEqual(output, b"ZBCDEFGH")
        self.assertEqual(receipt["status"], "trace-relocated-stringtable-ready")
        self.assertTrue(receipt["xasset_table_unchanged"])


if __name__ == "__main__":
    unittest.main()
