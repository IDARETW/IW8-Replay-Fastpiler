from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from workstation_image_crud import _verify_retained_body_bytes  # noqa: E402


class ResidentImageRetainedByteAuditTests(unittest.TestCase):
    def setUp(self):
        self.source = bytes((i * 17) & 0xFF for i in range(96))

    def test_append_allows_only_row_count_and_relocated_alias_bytes(self):
        candidate = bytearray(self.source)
        candidate[64:64] = b"R" * 16
        candidate[16:20] = b"NUM!"
        candidate[88:96] = b"ALIAS!!!"
        proof = _verify_retained_body_bytes(self.source, bytes(candidate),
            first_payload_offset=64, alias_offsets=[72], operation="append",
            expected_candidate_bytes=len(candidate))
        self.assertEqual(proof["status"], "retained-body-bytes-pass")
        candidate[24] ^= 1
        with self.assertRaisesRegex(ValueError, "retained body byte changed"):
            _verify_retained_body_bytes(self.source, bytes(candidate),
                first_payload_offset=64, alias_offsets=[72], operation="append",
                expected_candidate_bytes=len(candidate))

    def test_remove_compares_only_retained_prefix_and_shifted_pre_tail_bytes(self):
        candidate = bytearray(self.source[:48] + self.source[64:80])
        candidate[16:20] = b"NUM!"
        candidate[52:60] = b"ALIAS!!!"
        proof = _verify_retained_body_bytes(self.source, bytes(candidate),
            first_payload_offset=64, alias_offsets=[68], operation="remove",
            expected_candidate_bytes=64, removed_root_offset=80)
        self.assertEqual(proof["status"], "retained-body-bytes-pass")
        candidate[21] ^= 1
        with self.assertRaisesRegex(ValueError, "retained body byte changed"):
            _verify_retained_body_bytes(self.source, bytes(candidate),
                first_payload_offset=64, alias_offsets=[68], operation="remove",
                expected_candidate_bytes=64, removed_root_offset=80)


if __name__ == "__main__":
    unittest.main()
