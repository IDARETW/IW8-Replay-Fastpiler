import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_asset_codecs import capability_report, dxbc_native_shader_type, _dxbc_tool_stem
from workstation_native_asset_edits import read_inline_shader


def fixture(stage=5):
    name = b"cs_probe.hlsl\0"
    version = (stage << 16) | 0x50
    chunk = b"SHEX" + struct.pack("<IIII", 12, version, 3, 0)
    program = bytearray(b"DXBC" + bytes(20) + bytes(8) + struct.pack("<I", 36) + chunk)
    struct.pack_into("<I", program, 24, len(program))
    struct.pack_into("<I", program, 28, 1)
    root = bytearray(40)
    struct.pack_into("<QQQQII", root, 0,
                     0xFFFFFFFFFFFFFFFE, 0x0000001500000001, 0,
                     0xFFFFFFFFFFFFFFFE, len(program), 0x12345678)
    program_at = 40 + len(name)
    body = bytes(root) + name + bytes(program)
    row = {"index": 4, "type_id": 12, "name": "cs_probe.hlsl"}
    spans = [
        {"origin": "load_stream_call", "reader_start_arg": 0,
         "archive_offset": 0, "size": 40,
         "destination_stream_location": {"stream": 1, "offset": 0}},
        {"origin": "string_data", "archive_offset": 40, "size": len(name),
         "event_sequence": 3,
         "destination_stream_location": {"stream": 5, "offset": 100}},
        {"origin": "load_stream_call", "reader_start_arg": 0,
         "archive_offset": program_at, "size": len(program),
         "destination_stream_location": {"stream": 5, "offset": 128}},
    ]
    trace = {
        "index": 4, "type_id": 12, "begin_cursor": 0, "end_cursor": len(body),
        "begin_sequence": 1, "end_sequence": 20,
        "root_stream_location": {"stream": 1, "offset": 0},
        "read_spans": spans,
        "packed_pointer_events": [{
            "kind": "packed_resolve", "sequence": 10, "xasset_index": 4, "type_id": 12,
            "raw_token": 0x0000001500000001,
            "field_stream_location": {"stream": 1, "offset": 8},
            "resolved_target_stream_location": {"stream": 5, "offset": 100},
        }],
        "indexed_string_data_spans": [spans[1]],
        "indexed_physical_spans": spans,
    }
    return body, row, trace


class ComputeShaderRootTests(unittest.TestCase):
    def test_namespaced_native_identity_gets_a_private_safe_tool_stem(self):
        stem = _dxbc_tool_stem("cs_fence.hlsl/cs_nop")
        self.assertTrue(stem.startswith("shader_"))
        self.assertNotIn("/", stem)
        self.assertNotIn("\\", stem)
        self.assertEqual(stem, _dxbc_tool_stem("cs_fence.hlsl/cs_nop"))

    def test_stage_five_type_twelve_is_a_typed_compute_shader_capability(self):
        body, _, trace = fixture()
        span = trace["read_spans"][2]
        program = body[span["archive_offset"]:span["archive_offset"] + span["size"]]
        self.assertEqual(dxbc_native_shader_type(program), 12)
        shader = capability_report()["shader"]
        self.assertEqual(shader["native_types"]["12"], "compute")
        self.assertIn("unique whole-zone physical child ownership", shader["typed_root_layout"])

    def test_compute_root_requires_exact_owner_callback_and_exclusive_child(self):
        body, row, trace = fixture()
        result = read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest(), [trace])
        self.assertEqual((result["type_id"], result["name"], result["debug_name"]),
                         (12, "cs_probe.hlsl", "cs_probe.hlsl"))
        self.assertEqual(result["program"], body[result["program_archive_offset"]:
                                                  result["program_archive_offset"] + len(result["program"])])

    def test_compute_rejects_missing_or_wrong_owner_callback(self):
        body, row, trace = fixture()
        digest = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, "packed-resolve event"):
            read_inline_shader(body, row, dict(trace, packed_pointer_events=[]), digest, [trace])
        bad = dict(trace)
        bad["packed_pointer_events"] = [dict(trace["packed_pointer_events"][0],
                                               field_stream_location={"stream": 1, "offset": 0})]
        with self.assertRaisesRegex(ValueError, "packed-resolve event"):
            read_inline_shader(body, row, bad, digest, [bad])

    def test_compute_rejects_shared_child_and_missing_whole_zone_context(self):
        body, row, trace = fixture()
        digest = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(ValueError, "complete native trace index"):
            read_inline_shader(body, row, trace, digest)
        other = dict(trace, index=9, type_id=14)
        with self.assertRaisesRegex(ValueError, "shared"):
            read_inline_shader(body, row, trace, digest, [trace, other])

    def test_compute_rejects_wrong_stage_and_incompatible_root_layout(self):
        body, row, trace = fixture(stage=4)
        with self.assertRaisesRegex(ValueError, "stage does not match"):
            read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest(), [trace])
        body, row, trace = fixture()
        changed = bytearray(body)
        struct.pack_into("<Q", changed, 24, 0)
        changed = bytes(changed)
        with self.assertRaisesRegex(ValueError, "40-byte layout"):
            read_inline_shader(changed, row, trace, hashlib.sha256(changed).hexdigest(), [trace])


if __name__ == "__main__":
    unittest.main()
