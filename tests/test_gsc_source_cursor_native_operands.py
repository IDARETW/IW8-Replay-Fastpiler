import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import trace_gscbin_source_cursor as TRACE



def make_body(code: bytes, source: bytes) -> bytes:
    compressed = zlib.compress(source)
    return (struct.pack("<4I", 0x435347, len(compressed), len(source), len(code)) +
            compressed + code)


def one_function_source(code_size: int, payload: bytes = b"") -> bytes:
    # A nonzero name token makes the header exactly size+4 bytes.
    return struct.pack("<II", code_size, 0x204) + payload


class NativeCursorOpcodeTests(unittest.TestCase):
    def walk(self, code: bytes, source: bytes):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "probe.gscbin"
            blob = make_body(code, source)
            path.write_bytes(blob)
            return TRACE.trace(path, len(code), strict=True)

    def test_opcode_145_consumes_two_strings_and_eight_byte_operand(self):
        code = b"\0\x91" + bytes(range(8))
        source = one_function_source(len(code) - 1, b"\0anim_tree\0")
        events = self.walk(code, source)
        row = next(event for event in events if event.get("opcode") == "0x91")
        self.assertEqual(row["first_string"]["string"], "")
        self.assertEqual(row["second_string"]["string"], "anim_tree")
        self.assertEqual(row["next_pc"], "0xa")
        self.assertEqual(row["source_after"], hex(len(source)))

    def test_opcode_145_rejects_unterminated_second_string(self):
        code = b"\0\x91" + bytes(8)
        source = one_function_source(len(code) - 1, b"first\0unterminated")
        with self.assertRaisesRegex(ValueError, "Unterminated source string"):
            self.walk(code, source)

    def test_switch_case_below_native_threshold_consumes_source_string(self):
        code = b"\0\x56\x01\x00" + struct.pack("<I", 0x7FFFF) + bytes(3)
        source = one_function_source(len(code) - 1, b"case_label\0")
        events = self.walk(code, source)
        switch = next(event for event in events if event.get("opcode") == "0x56")
        self.assertEqual(switch["cases"][0]["string"], "case_label")

    def test_switch_case_at_native_threshold_does_not_consume_string(self):
        code = b"\0\x56\x01\x00" + struct.pack("<I", 0x80000) + bytes(3)
        source = one_function_source(len(code) - 1)
        events = self.walk(code, source)
        switch = next(event for event in events if event.get("opcode") == "0x56")
        self.assertEqual(switch["cases"], [])

    def test_switch_case_at_native_threshold_rejects_unowned_string(self):
        code = b"\0\x56\x01\x00" + struct.pack("<I", 0x80000) + bytes(3)
        source = one_function_source(len(code) - 1, b"not_a_native_case_name\0")
        with self.assertRaisesRegex(ValueError, "consume both buffers"):
            self.walk(code, source)

    def test_invalid_function_boundary_remains_rejected(self):
        code = b"\0\x91" + bytes(8)
        source = one_function_source(8, b"\0first\0second\0")
        with self.assertRaisesRegex(ValueError, "instruction boundary"):
            self.walk(code, source)


if __name__ == "__main__":
    unittest.main()
