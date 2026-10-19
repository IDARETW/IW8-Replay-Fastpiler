from __future__ import annotations
import hashlib
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_native_asset_edits import INLINE, read_inline_shader


def _program(stage: int) -> bytes:
    chunk = b"SHEX" + struct.pack("<IIII", 12, (stage << 16) | 0x50, 3, 0)
    result = bytearray(b"DXBC" + bytes(20) + bytes(8) + struct.pack("<I", 36) + chunk)
    struct.pack_into("<I", result, 24, len(result))
    struct.pack_into("<I", result, 28, 1)
    return bytes(result)


def _fixture(type_id=15, identity=0x12345678):
    name = "fixture_shader"
    debug = b"fixture.hlsl\0"
    program = _program(3 if type_id == 15 else 4)
    body = bytearray(256)
    token = (5 << 32) | 25
    struct.pack_into("<QQQQII", body, 0, INLINE, token, 0, INLINE,
                     len(program), identity)
    name_offset, program_offset, debug_offset = 64, 112, 40
    body[name_offset:name_offset + len(name) + 1] = name.encode() + b"\0"
    body[program_offset:program_offset + len(program)] = program
    body[debug_offset:debug_offset + len(debug)] = debug
    debug_span = {"origin": "string_data", "event_sequence": 3, "archive_offset": debug_offset,
                  "size": len(debug), "destination_stream_location": {"stream": 5, "offset": 24}}
    trace = {
        "index": 42, "type_id": type_id, "root_stream_location": {"stream": 1, "offset": 0},
        "begin_sequence": 1, "end_sequence": 7,
        "read_spans": [
            {"origin": "load_stream_call", "reader_start_arg": 0, "event_sequence": 2,
             "destination_stream_location": {"stream": 1, "offset": 0},
             "archive_offset": 0, "size": 40},
            debug_span,
            {"origin": "string_data", "archive_offset": name_offset, "event_sequence": 4,
             "destination_stream_location": {"stream": 5, "offset": 0},
             "size": len(name) + 1},
            {"origin": "load_stream_call", "reader_start_arg": 0, "event_sequence": 6,
             "archive_offset": program_offset, "size": len(program),
             "destination_stream_location": {"stream": 5, "offset": 48}},
        ],
        "indexed_string_data_spans": [debug_span],
        "packed_pointer_events": [{
            "kind": "packed_resolve", "xasset_index": 42, "type_id": type_id, "sequence": 5,
            "raw_token": token, "field_stream_location": {"stream": 1, "offset": 8},
            "resolved_target_stream_location": {"stream": 5, "offset": 24},
        }],
    }
    trace["indexed_physical_spans"] = trace["read_spans"]
    return bytes(body), {"index": 42, "type_id": type_id, "name": name}, trace, program


class ShaderStageGrowthLayoutTests(unittest.TestCase):
    def test_type15_and_type16_accept_allocated_program_identity(self):
        for type_id in (15, 16):
            with self.subTest(type_id=type_id):
                identity = 0xA15E0000 + type_id
                body, row, trace, program = _fixture(type_id, identity)
                codec = SimpleNamespace(dxbc_native_shader_type=lambda payload: type_id)
                with mock.patch.dict(sys.modules, {"workstation_asset_codecs": codec}):
                    detail = read_inline_shader(body, row, trace,
                        hashlib.sha256(body).hexdigest())
                self.assertEqual(detail["program_identity"], identity)
                self.assertEqual(detail["program"], program)
                self.assertEqual(len(detail["root_bytes"]), 40)

    def test_zero_source_identity_remains_valid(self):
        body, row, trace, _ = _fixture(15, 0)
        with mock.patch.dict(sys.modules, {"workstation_asset_codecs":
                                           SimpleNamespace(dxbc_native_shader_type=lambda _: 15)}):
            detail = read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest())
        self.assertEqual(detail["program_identity"], 0)

    def test_nonidentity_root_fields_remain_strict(self):
        for offset, value in ((16, 1), (24, 0x1234), (32, 999)):
            with self.subTest(offset=offset):
                body, row, trace, _ = _fixture(15, 7)
                changed = bytearray(body)
                struct.pack_into("<Q" if offset in (16, 24) else "<I", changed, offset, value)
                with mock.patch.dict(sys.modules, {"workstation_asset_codecs":
                        SimpleNamespace(dxbc_native_shader_type=lambda _: 15)}):
                    with self.assertRaises(ValueError):
                        read_inline_shader(bytes(changed), row, trace,
                                           hashlib.sha256(changed).hexdigest())

    def test_packed_debug_name_alias_still_requires_exact_trace_target(self):
        body, row, trace, _ = _fixture(16, 0xCAFE)
        trace["packed_pointer_events"][0]["resolved_target_stream_location"] = {
            "stream": 5, "offset": 25}
        with mock.patch.dict(sys.modules, {"workstation_asset_codecs":
                SimpleNamespace(dxbc_native_shader_type=lambda _: 16)}):
            with self.assertRaisesRegex(ValueError, "does not resolve into stream 5"):
                read_inline_shader(body, row, trace, hashlib.sha256(body).hexdigest())


if __name__ == "__main__":
    unittest.main()
