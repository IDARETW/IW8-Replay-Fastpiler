"""Focused fail-closed tests for the native same-extent asset adapters."""
from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from workstation_native_asset_edits import (
    read_inline_shader,
    read_resident_image,
    replace_inline_shader,
    replace_resident_image,
)


def shader_fixture(type_id=14):
    stage = {14: 1, 15: 3, 16: 4, 17: 0}[type_id]
    chunk = b"SHEX" + struct.pack("<IIII", 12, (stage << 16) | 0x50, 3, 0)
    program = bytearray(b"DXBC" + bytes(20) + bytes(8) + struct.pack("<I", 36) + chunk)
    struct.pack_into("<I", program, 24, len(program))
    struct.pack_into("<I", program, 28, 1)
    root = bytearray(40)
    struct.pack_into("<Q", root, 0, 0xFFFFFFFFFFFFFFFE)
    struct.pack_into("<I", root, 32, len(program))
    struct.pack_into("<I", root, 36, 0 if type_id in (15, 16) else 0x12345678)
    name = b"test-vs\0"
    debug_name = b"prepass.hlsl\0"
    if type_id in (15, 16):
        struct.pack_into("<QQ", root, 8, 0x0000000500000081, 0)
        struct.pack_into("<Q", root, 24, 0xFFFFFFFFFFFFFFFE)
    program_at = 40 + len(name)
    debug_at = program_at + len(program)
    body = bytearray(bytes(root) + name + bytes(program) + debug_name)
    row = dict(index=4, type_id=type_id, name="test-vs")
    spans = [
        dict(origin="load_stream_call", reader_start_arg=0, archive_offset=0, size=40),
        dict(origin="string_data", archive_offset=40, size=len(name), event_sequence=3),
        dict(origin="load_stream_call", reader_start_arg=0,
             archive_offset=program_at, size=len(program)),
    ]
    indexed_string_spans = []
    packed_events = []
    if type_id in (15, 16):
        indexed_string_spans.append(dict(origin="string_data", archive_offset=debug_at,
                                         size=len(debug_name), event_sequence=5,
                                         destination_stream_location={"stream": 5, "offset": 128}))
        packed_events.append(dict(kind="packed_resolve", sequence=10,
                                  xasset_index=4, type_id=type_id,
                                  raw_token=0x0000000500000081,
                                  field_stream_location={"stream": 1, "offset": 8},
                                  resolved_target_stream_location={"stream": 5, "offset": 128}))
    trace = dict(index=4, type_id=type_id, begin_cursor=0, end_cursor=len(body),
                 begin_sequence=1, end_sequence=20,
                 root_stream_location={"stream": 1, "offset": 0},
                 read_spans=spans, packed_pointer_events=packed_events,
                 indexed_string_data_spans=indexed_string_spans,
                 indexed_physical_spans=[*spans, *indexed_string_spans])
    return bytes(body), row, trace


def compute_shader_fixture():
    type_id = 12
    stage = 5
    chunk = b"SHEX" + struct.pack("<IIII", 12, (stage << 16) | 0x50, 3, 0)
    program = bytearray(b"DXBC" + bytes(20) + bytes(8) + struct.pack("<I", 36) + chunk)
    struct.pack_into("<I", program, 24, len(program))
    struct.pack_into("<I", program, 28, 1)
    root = bytearray(40)
    struct.pack_into("<Q", root, 0, 0xFFFFFFFFFFFFFFFE)
    struct.pack_into("<Q", root, 8, 0x0000001500000001)
    struct.pack_into("<Q", root, 24, 0xFFFFFFFFFFFFFFFE)
    struct.pack_into("<I", root, 32, len(program))
    struct.pack_into("<I", root, 36, 0x12345678)
    name = b"cs_fence.hlsl/cs_nop\0"
    program_at = len(root) + len(name)
    debug_at = program_at + len(program)
    body = bytes(root) + name + bytes(program) + name
    row = dict(index=4, type_id=type_id, name="cs_fence.hlsl/cs_nop")
    trace = dict(index=4, type_id=type_id, begin_cursor=0, end_cursor=len(body),
                 begin_sequence=1, end_sequence=20,
                 root_stream_location={"stream": 1, "offset": 0},
                 read_spans=[
                     dict(origin="load_stream_call", reader_start_arg=0,
                          archive_offset=0, size=40,
                          destination_stream_location={"stream": 1, "offset": 0}),
                     dict(origin="string_data", archive_offset=40, size=len(name), event_sequence=3),
                     dict(origin="load_stream_call", reader_start_arg=0,
                          archive_offset=program_at, size=len(program),
                          destination_stream_location={"stream": 5, "offset": 256}),
                 ],
                 packed_pointer_events=[dict(
                     kind="packed_resolve", sequence=10, xasset_index=4, type_id=12,
                     raw_token=0x0000001500000001,
                     field_stream_location={"stream": 1, "offset": 8},
                     resolved_target_stream_location={"stream": 5, "offset": 128})],
                 indexed_string_data_spans=[dict(
                    origin="string_data", archive_offset=debug_at, size=len(name), event_sequence=5,
                     destination_stream_location={"stream": 5, "offset": 128})],
                 indexed_physical_spans=[
                     *[dict(span) for span in [
                         dict(origin="load_stream_call", archive_offset=0, size=40,
                              destination_stream_location={"stream": 1, "offset": 0}, event_sequence=2),
                         dict(origin="string_data", archive_offset=40, size=len(name), event_sequence=3,
                              destination_stream_location={"stream": 5, "offset": 100}),
                         dict(origin="load_stream_call", archive_offset=program_at, size=len(program),
                              destination_stream_location={"stream": 5, "offset": 256}, event_sequence=7),
                     ]],
                     dict(origin="string_data", archive_offset=debug_at, size=len(name), event_sequence=5,
                          destination_stream_location={"stream": 5, "offset": 128})])
    return body, row, trace


def image_fixture():
    root = bytearray(232)
    struct.pack_into("<Q", root, 0, 0xFFFFFFFFFFFFFFFE)
    struct.pack_into("<I", root, 20, 7)
    struct.pack_into("<I", root, 24, 3)
    struct.pack_into("<I", root, 28, 16)
    struct.pack_into("<4H", root, 36, 1, 1, 1, 1)
    root[48] = 1
    struct.pack_into("<Q", root, 224, 0xFFFFFFFFFFFFFFFE)
    name = b"$black\0"
    pixels = b"\x00\x00\x00\xff" + b"\0" * 12
    body = bytes(root) + name + pixels
    row = dict(index=8, type_id=19, name="$black")
    trace = dict(index=8, type_id=19, begin_cursor=0, end_cursor=len(body),
                 read_spans=[
                     dict(origin="load_stream_call", reader_start_arg=0,
                          archive_offset=0, size=232),
                     dict(origin="string_data", archive_offset=232, size=len(name)),
                     dict(origin="load_stream_call", reader_start_arg=0,
                          archive_offset=239, size=16),
                 ])
    return body, row, trace


class NativeAssetEditTests(unittest.TestCase):
    def test_compute_shader_requires_complete_unique_child_ownership(self):
        body, row, trace = compute_shader_fixture()
        digest = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, "complete native trace index"):
            read_inline_shader(body, row, trace, digest)
        parsed = read_inline_shader(body, row, trace, digest, trace_assets=[trace])
        self.assertEqual(parsed["type_id"], 12)
        self.assertEqual(parsed["debug_name"], row["name"])
        output, receipt = replace_inline_shader(body, row, trace, digest,
                                                parsed["program"], trace_assets=[trace])
        self.assertEqual(output, body)
        self.assertEqual(receipt["type_id"], 12)
        duplicate = dict(trace, index=5, read_spans=[dict(trace["read_spans"][2])])
        with self.assertRaisesRegex(ValueError, "shared or lacks unique whole-zone"):
            read_inline_shader(body, row, trace, digest, trace_assets=[trace, duplicate])

    def test_compute_packed_name_must_precede_callback_in_trace(self):
        body, row, trace = compute_shader_fixture()
        digest = hashlib.sha256(body).hexdigest()
        stale = dict(trace)
        stale["indexed_string_data_spans"] = [dict(
            trace["indexed_string_data_spans"][0], event_sequence=11)]
        with self.assertRaisesRegex(ValueError, "not live before its owner callback"):
            read_inline_shader(body, row, stale, digest, trace_assets=[stale])
        prior_owner = dict(trace)
        prior_owner["indexed_string_data_spans"] = [dict(
            trace["indexed_string_data_spans"][0], event_sequence=0)]
        prior_owner["indexed_physical_spans"] = [
            *trace["indexed_physical_spans"][:-1],
            dict(trace["indexed_physical_spans"][-1], event_sequence=0)]
        self.assertEqual(read_inline_shader(body, row, prior_owner, digest,
                                            trace_assets=[prior_owner])["debug_name"], row["name"])
        overlap = dict(trace)
        overlap["indexed_string_data_spans"] = [
            trace["indexed_string_data_spans"][0],
            dict(trace["indexed_string_data_spans"][0],
                 destination_stream_location={"stream": 5, "offset": 127},
                 event_sequence=6)]
        overlap["indexed_physical_spans"] = [
            *trace["indexed_physical_spans"],
            dict(origin="load_stream_call",
                 archive_offset=trace["indexed_string_data_spans"][0]["archive_offset"] + 1,
                 size=len(row["name"]) + 1,
                 destination_stream_location={"stream": 5, "offset": 127}, event_sequence=6)]
        with self.assertRaisesRegex(ValueError, "overlaps another physical allocation"):
            read_inline_shader(body, row, overlap, digest, trace_assets=[overlap])
        future = dict(trace)
        future["indexed_physical_spans"] = [
            *trace["indexed_physical_spans"],
            dict(origin="load_stream_call",
                 archive_offset=trace["indexed_string_data_spans"][0]["archive_offset"] + 1,
                 size=len(row["name"]) + 1,
                 destination_stream_location={"stream": 5, "offset": 127}, event_sequence=12)]
        with self.assertRaisesRegex(ValueError, "overlaps another physical allocation"):
            read_inline_shader(body, row, future, digest, trace_assets=[future])

    def test_pixelshader_uses_the_same_trace_owned_dxbc_contract(self):
        body, row, trace = shader_fixture(17)
        digest = hashlib.sha256(body).hexdigest()
        parsed = read_inline_shader(body, row, trace, digest)
        self.assertEqual(parsed["type_id"], 17)
        output, receipt = replace_inline_shader(body, row, trace, digest, parsed["program"])
        self.assertEqual(output, body)
        self.assertEqual(receipt["type_id"], 17)

    def test_shader_adapter_reads_and_replaces_only_equal_dxbc_extent(self):
        body, row, trace = shader_fixture()
        digest = hashlib.sha256(body).hexdigest()
        parsed = read_inline_shader(body, row, trace, digest)
        changed = bytearray(parsed["program"])
        changed[-1] = 1
        output, receipt = replace_inline_shader(body, row, trace, digest, bytes(changed))
        self.assertEqual(len(output), len(body))
        start = parsed["program_archive_offset"]
        end = start + len(parsed["program"])
        self.assertEqual(output[:start], body[:start])
        self.assertEqual(output[end:], body[end:])
        self.assertEqual(receipt["replacement_size"], len(parsed["program"]))
        with self.assertRaisesRegex(ValueError, "retain the original bytecode extent"):
            replace_inline_shader(body, row, trace, digest, bytes(changed) + b"\0")

    def test_shader_adapter_rejects_body_revision_mismatch(self):
        body, row, trace = shader_fixture()
        with self.assertRaisesRegex(ValueError, "body changed"):
            read_inline_shader(body, row, trace, "0" * 64)

    def test_hull_and_domain_use_the_typed_40_byte_root_and_packed_hlsl_name(self):
        for type_id, expected in ((15, "prepass.hlsl"), (16, "prepass.hlsl")):
            with self.subTest(type_id=type_id):
                body, row, trace = shader_fixture(type_id)
                parsed = read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest())
                self.assertEqual(parsed["debug_name"], expected)
                self.assertEqual(parsed["type_id"], type_id)
                output, receipt = replace_inline_shader(
                    body, row, trace, hashlib.sha256(body).hexdigest(), parsed["program"])
                self.assertEqual(output, body)
                self.assertEqual(receipt["debug_name"], expected)

    def test_shader_reader_rejects_missing_or_mismatched_packed_source_pointer(self):
        body, row, trace = shader_fixture(15)
        digest = hashlib.sha256(body).hexdigest()
        trace["packed_pointer_events"] = []
        with self.assertRaisesRegex(ValueError, "packed-resolve event"):
            read_inline_shader(body, row, trace, digest)
        body, row, trace = shader_fixture(16)
        digest = hashlib.sha256(body).hexdigest()
        trace["packed_pointer_events"][0]["resolved_target_stream_location"] = {
            "stream": 5, "offset": 127}
        with self.assertRaisesRegex(ValueError, "does not resolve into stream 5"):
            read_inline_shader(body, row, trace, digest)

    def test_shader_replacement_must_keep_native_stage(self):
        body, row, trace = shader_fixture(15)
        wrong_stage, _, _ = shader_fixture(16)
        layout = read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest())
        wrong_program = read_inline_shader(wrong_stage,
                                           dict(row, type_id=16),
                                           dict(trace, type_id=16,
                                                packed_pointer_events=[dict(
                                                    trace["packed_pointer_events"][0], type_id=16)]),
                                           hashlib.sha256(wrong_stage).hexdigest())["program"]
        with self.assertRaisesRegex(ValueError, "stage differs"):
            replace_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest(), wrong_program)

    def test_native_shader_reader_rejects_dxbc_from_the_wrong_stage(self):
        body, row, trace = shader_fixture(16)
        wrong_row = dict(row, type_id=15)
        wrong_trace = dict(trace, type_id=15,
                           packed_pointer_events=[dict(trace["packed_pointer_events"][0], type_id=15)])
        with self.assertRaisesRegex(ValueError, "stage does not match"):
            read_inline_shader(body, wrong_row, wrong_trace, hashlib.sha256(body).hexdigest())

    def test_codec_failure_is_read_only_and_preserves_exact_diagnostic(self):
        from workstation_asset_codecs import disassemble_native_shader
        body, _, _ = shader_fixture(16)
        program_at = 40 + len(b"test-vs\0")
        size = struct.unpack_from("<I", body, 32)[0]
        program = body[program_at:program_at + size]
        diagnostic = "DXBC disassemble failed (1): Assembly verification pass failed: size mismatch in section SHEX"
        with patch("workstation_asset_codecs.disassemble_dxbc", side_effect=RuntimeError(diagnostic)):
            result = disassemble_native_shader(program, 16, asset_name="domain-fixture")
        self.assertFalse(result["editable"])
        self.assertIsNone(result["assembly"])
        self.assertEqual(result["codec_error"], diagnostic)

    def test_shared_null_hull_domain_aliases_are_read_only(self):
        from workstation_native_asset_edits import read_native_shader
        for type_id in (15, 16):
            with self.subTest(type_id=type_id):
                body, row, trace = shader_fixture(type_id)
                shared_name = b"null_vshsds.hlsl\0"
                layout = read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest())
                program = layout["program"]
                data = bytearray(40 + len(program) + len(shared_name))
                data[:40] = body[:40]
                data[40:40 + len(program)] = program
                data[40 + len(program):] = shared_name
                token = 0x0000000500000081
                struct.pack_into("<QQ", data, 0, token, token)
                struct.pack_into("<Q", data, 24, 0xFFFFFFFFFFFFFFFE)
                trace["read_spans"] = [
                    dict(origin="load_stream_call", reader_start_arg=0,
                         archive_offset=0, size=40),
                    dict(origin="load_stream_call", reader_start_arg=0,
                         archive_offset=40, size=len(program)),
                ]
                trace["indexed_string_data_spans"] = [dict(
                    origin="string_data", archive_offset=40 + len(program),
                    size=len(shared_name), event_sequence=5,
                    destination_stream_location={"stream": 5, "offset": 128})]
                trace["indexed_physical_spans"] = [*trace["read_spans"],
                                                   *trace["indexed_string_data_spans"]]
                trace["packed_pointer_events"] = [
                    dict(trace["packed_pointer_events"][0], sequence=10,
                         field_stream_location={"stream": 1, "offset": 0}),
                    dict(trace["packed_pointer_events"][0], sequence=11,
                         field_stream_location={"stream": 1, "offset": 8}),
                ]
                row = dict(row, name="null_vshsds.hlsl")
                result = read_native_shader(bytes(data), row, trace,
                                            hashlib.sha256(data).hexdigest())
                self.assertFalse(result["editable"])
                self.assertEqual(result["status"], "read-only-shared-null-shader")

    def test_trace_index_retains_owner_local_packed_shader_callbacks(self):
        from workstation_trace_index import build_read_span_index
        events = [
            dict(kind="xasset_begin", xasset_index=0, asset_type=15,
                 serialized_input_cursor=0, root_stream_location={"stream": 1, "offset": 0},
                 sequence=0),
            dict(kind="packed_resolve", xasset_index=0, type_id=15, sequence=1,
                 raw_token=0x0000000500000081,
                 field_stream_location={"stream": 1, "offset": 8},
                 resolved_target_stream_location={"stream": 5, "offset": 128}),
            dict(kind="xasset_end", xasset_index=0, asset_type=15,
                 serialized_input_cursor=0, sequence=2),
        ]
        manifest = dict(profile="replay-1.20", xfile_version=4087,
                        complete=True, success=True, tested=1,
                        top_level_index=1, reference_only_rows=[],
                        serialized_bytes_read=0, stream_trace_events=len(events),
                        failed=0, unavailable=0)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trace = root / "stream-trace.jsonl"
            manifest_path = root / "manifest.json"
            trace.write_text("".join(json.dumps(event) + "\n" for event in events),
                             encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            index = build_read_span_index(trace, manifest_path, 0, selected_assets={0})
        self.assertEqual(index["assets"][0]["packed_pointer_events"], [
            {key: events[1].get(key) for key in (
                "sequence", "kind", "xasset_index", "type_id", "raw_token",
                "field_stream_location", "resolved_target_stream_location")}
        ])

    def test_resident_image_adapter_reads_and_replaces_same_pixel_extent(self):
        body, row, trace = image_fixture()
        digest = hashlib.sha256(body).hexdigest()
        parsed = read_resident_image(body, row, trace, digest)
        self.assertEqual(parsed["dimensions"], (1, 1, 1, 1))
        changed = bytes([1]) + parsed["payload"][1:]
        output, receipt = replace_resident_image(body, row, trace, digest, changed)
        self.assertEqual(len(output), len(body))
        self.assertEqual(output[:239], body[:239])
        self.assertEqual(receipt["replacement_size"], 16)
        with self.assertRaisesRegex(ValueError, "retain the traced pixel extent"):
            replace_resident_image(body, row, trace, digest, changed + b"\0")

    def test_resident_image_adapter_rejects_streamed_root(self):
        body, row, trace = image_fixture()
        changed = bytearray(body)
        changed[50] = 1
        with self.assertRaisesRegex(ValueError, "streamed/XPak"):
            read_resident_image(bytes(changed), row, trace,
                                hashlib.sha256(changed).hexdigest())

    def test_resident_image_adapter_accepts_inline_minus1_name_when_trace_matches(self):
        body, row, trace = image_fixture()
        changed = bytearray(body)
        struct.pack_into("<Q", changed, 0, 0xFFFFFFFFFFFFFFFF)
        digest = hashlib.sha256(changed).hexdigest()
        parsed = read_resident_image(bytes(changed), row, trace, digest)
        self.assertEqual(parsed["name"], "$black")
        self.assertEqual(parsed["payload"], body[239:255])

    def test_resident_image_adapter_rejects_ambiguous_equal_size_reads(self):
        body, row, trace = image_fixture()
        trace["read_spans"].append(dict(origin="load_stream_call", reader_start_arg=0,
                                        archive_offset=239, size=16))
        with self.assertRaisesRegex(ValueError, "unique resident pixel child"):
            read_resident_image(body, row, trace, hashlib.sha256(body).hexdigest())


if __name__ == "__main__":
    unittest.main()
