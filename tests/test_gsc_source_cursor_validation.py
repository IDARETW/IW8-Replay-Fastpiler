"""Publication-grade bounds and token provenance for Replay GSC source walks."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from trace_gscbin_source_cursor import trace


def source_header(size, name=b"custom_probe"):
    return struct.pack("<II", size, 0) + name + b"\0"


class GscSourceCursorValidationTests(unittest.TestCase):
    def walk(self, code, source, *, limit=None, strict=True):
        compressed = zlib.compress(source)
        blob = struct.pack("<4I", 0x435347, len(compressed), len(source), len(code))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.gscbin"
            path.write_bytes(blob + compressed + code)
            return trace(path, len(code) if limit is None else limit, strict=strict)

    def test_complete_multiple_function_source(self):
        events = self.walk(b";K;;K;;", source_header(3) + source_header(3, b"second"))
        self.assertEqual(events[-1]["next_pc"], "0x7")
        self.assertEqual([row["function_at"] for row in events if "function_at" in row], ["0x1", "0x4"])

    def test_rejects_unconsumed_source(self):
        with self.assertRaisesRegex(ValueError, "consume both buffers"):
            self.walk(b";K;;", source_header(3) + b"unowned\0")

    def test_rejects_overlong_function_extent(self):
        with self.assertRaisesRegex(ValueError, "function extent"):
            self.walk(b";K;;", source_header(4))

    def test_rejects_function_end_inside_instruction(self):
        with self.assertRaisesRegex(ValueError, "instruction boundary"):
            self.walk(b";K\x01\x00", source_header(2))

    def test_rejects_zero_sized_function(self):
        with self.assertRaisesRegex(ValueError, "function extent"):
            self.walk(b";K;;", source_header(0))

    def test_strict_mode_rejects_partial_diagnostic_limit(self):
        with self.assertRaisesRegex(ValueError, "complete bytecode"):
            self.walk(b";K;;", source_header(3), limit=2)

    def test_diagnostic_mode_keeps_partial_walk(self):
        events = self.walk(b";K;;", source_header(3), limit=2, strict=False)
        self.assertEqual(events[-1]["next_pc"], "0x2")

    def test_rejects_truncated_operand(self):
        with self.assertRaisesRegex(ValueError, "overruns"):
            self.walk(b";\x04\x01", source_header(2))

    def test_rejects_unsupported_opcode(self):
        with self.assertRaisesRegex(ValueError, "Unsupported Replay opcode"):
            self.walk(b";\xff", source_header(1))

    def test_reports_embedded_canonical_token(self):
        code = b";K\x04" + struct.pack("<I", 17) + b";"
        events = self.walk(code, source_header(len(code) - 1))
        token = next(row["canonical_token"] for row in events if "canonical_token" in row)
        self.assertEqual(token, {"id": "0x11", "bytecode_offset": "0x3"})

    def test_reports_zero_inline_source_token(self):
        code = b";K\x04" + struct.pack("<I", 0xE2C1) + b";"
        events = self.walk(code, source_header(len(code) - 1) + struct.pack("<I", 0) + b"custom_field\0")
        token = next(row["token"] for row in events if "token" in row)
        self.assertEqual(token["id"], "0x0")
        self.assertEqual(token["string"], "custom_field")
        self.assertFalse(any("canonical_token" in row for row in events))

    def test_opcode_145_consumes_its_eight_byte_operand(self):
        code = b";K\x91" + b"\0" * 8 + b";"
        events = self.walk(code, source_header(len(code) - 1) + b"\0animation\0")
        self.assertEqual(next(row["next_pc"] for row in events if row.get("opcode") == "0x91"), "0xb")

    def test_rejects_truncated_source_token(self):
        with self.assertRaisesRegex(ValueError, "Truncated GSC source token"):
            self.walk(b";K;;", struct.pack("<I", 3) + b"\0\0")

    def test_rejects_unterminated_source_name(self):
        with self.assertRaisesRegex(ValueError, "Unterminated source string"):
            self.walk(b";K;;", struct.pack("<II", 3, 0) + b"missing_terminator")


if __name__ == "__main__":
    unittest.main()
