import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from layout import Layout


class WorkstationInteriorReferenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "sections": [
                {"rva": 0x1000, "raw_size": 0x1000, "virtual_size": 0x1000},
                {"rva": 0x2000, "raw_size": 0x1000, "virtual_size": 0x1000},
            ],
            "optional": {"SectionAlignment": 16, "SizeOfImage": 0x3000},
            "replacements": [{"begin": 0x1100, "end": 0x1110, "symbol": "fn_0123456789abcdef"}],
            "short_references": [],
        }
        self.layout = Layout(self.manifest, {"fn_0123456789abcdef": 0x20}, bytearray(0x1000))

    def test_replaced_interior_requires_and_uses_emitted_label_map(self):
        with self.assertRaisesRegex(ValueError, "no emitted instruction label"):
            self.layout.resolve(0x1104)
        self.layout.add_interior_rvas([(0x1104, 0x110a, "fn_0123456789abcdef")])
        self.assertEqual(self.layout.resolve(0x1104), 0x110a)
        self.assertEqual(self.layout.resolve(0x1100), 0x1100)

    def test_interior_mapping_rejects_wrong_owner_and_out_of_extent_target(self):
        with self.assertRaisesRegex(ValueError, "no live replacement owner"):
            self.layout.add_interior_rvas([(0x1104, 0x110a, "fn_fedcba9876543210")])
        with self.assertRaisesRegex(ValueError, "outside bounded code"):
            self.layout.add_interior_rvas([(0x1104, 0x1120, "fn_0123456789abcdef")])


if __name__ == "__main__":
    unittest.main()
