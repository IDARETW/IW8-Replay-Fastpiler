from __future__ import annotations

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from extract_reference_root_identities import extract


class ReferenceRootIdentityTests(unittest.TestCase):
    def test_extracts_exact_inline_name_from_typed_root_extent(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            body = bytearray(200)
            struct.pack_into("<Q", body, 32, 0xFFFFFFFFFFFFFFFE)
            body[48:54] = b",name\0"
            body_path = root / "body.dec"
            body_path.write_bytes(body)
            events = [
                {"kind": "xasset_begin", "xasset_index": 0, "type_id": 9,
                 "pointer_token": 0xFFFFFFFFFFFFFFFD, "serialized_input_cursor": 32},
                {"kind": "load_stream_call", "xasset_index": 0, "at_start": True,
                 "size": 16},
                {"kind": "string_call", "xasset_index": 0,
                 "serialized_input_cursor": 48},
            ]
            trace = root / "trace.jsonl"
            trace.write_text("".join(json.dumps(row) + "\n" for row in events))
            result = extract(body_path, trace, [0])
        self.assertEqual(result["references"][0]["name"], ",name")
        self.assertEqual(result["references"][0]["root_size"], 16)


if __name__ == "__main__":
    unittest.main()
