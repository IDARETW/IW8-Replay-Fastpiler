import collections
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build
from layout import Layout, encode_relative_table


def shifted_layout(short_references=()):
    manifest = {
        "sections": [
            {"name": ".text", "rva": 0x1000, "raw_size": 0x1000, "virtual_size": 0x1000},
            {"name": ".data", "rva": 0x2000, "raw_size": 0x1000, "virtual_size": 0x1000},
        ],
        "optional": {"SectionAlignment": 16, "SizeOfImage": 0x4000},
        "replacements": [{"begin": 0x1100, "end": 0x1110, "symbol": "fn", "retired": False}],
        "short_references": list(short_references),
    }
    native_text = bytearray(0x1000)
    for site, _target in short_references:
        native_text[site - 0x1000] = 0x70  # Jcc rel8 at the referenced native RVA
    layout = Layout(manifest, {"fn": 0x30}, native_text)
    layout.add_interior_rvas([(0x1104, 0x1108, "fn")])
    return manifest, layout


class RelativeTableEncodingTests(unittest.TestCase):
    @staticmethod
    def decode(item, encoded, origin):
        value = int.from_bytes(encoded, "little", signed=item.get("signed", True))
        distance = value << item["shift"]
        return origin - distance if item["subtract"] else origin + distance

    def test_signed_and_unsigned_shifted_entries_round_trip_independently(self):
        cases = [
            ({"width": 2, "shift": 2, "signed": False, "subtract": False}, 0x1800, 0x1000, b"\x00\x02"),
            # Signed negative displacement: -16 / 4 = -4, encoded as 0xfffc.
            ({"width": 2, "shift": 2, "signed": True, "subtract": False}, 0x0FF0, 0x1000, b"\xfc\xff"),
            ({"width": 2, "shift": 2, "signed": True, "subtract": True}, 0x0FF0, 0x1000, b"\x04\x00"),
        ]
        for item, target, origin, expected in cases:
            with self.subTest(item=item):
                encoded = encode_relative_table(item, target, origin)
                self.assertEqual(encoded, expected)
                self.assertEqual(self.decode(item, encoded, origin), target)

    def test_rejects_unaligned_shift_and_signed_overflow(self):
        with self.assertRaisesRegex(ValueError, "not representable"):
            encode_relative_table({"width": 2, "shift": 2, "signed": True, "subtract": False},
                                  0x1003, 0x1000)
        with self.assertRaisesRegex(ValueError, "out of range"):
            encode_relative_table({"width": 1, "shift": 0, "signed": True, "subtract": False},
                                  0x1080, 0x1000)
        unsigned = {"width": 1, "shift": 0, "signed": False, "subtract": False}
        self.assertEqual(encode_relative_table(unsigned, 0x10FF, 0x1000), b"\xff")
        with self.assertRaisesRegex(ValueError, "out of range"):
            encode_relative_table(unsigned, 0x1100, 0x1000)
        with self.assertRaisesRegex(ValueError, "out of range"):
            encode_relative_table(unsigned, 0x0FFF, 0x1000)


class UnwindRelocationTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.layout = shifted_layout([(0x1200, 0x1300)])
        self.assertEqual(self.layout.widened[0x1200]["size"], 2)
        self.assertEqual(self.layout.map(0x1202), 0x1232)

    @staticmethod
    def read_info(version=1):
        # Two real unwind operations. ALLOC_LARGE / OpInfo 0 consumes one
        # operand slot, which is data and must not be adjusted as CodeOffset.
        return bytes([version, 5, 3, 0, 2, 0, 5, 1, 0x34, 0x12])

    def reader(self, raw):
        def read(at, size):
            self.assertEqual(at, 0x4000 if at < 0x4004 else 0x4004)
            start = at - 0x4000
            return raw[start:start + size]
        return read

    def test_expanded_short_branch_adjusts_real_prologue_offsets(self):
        raw = self.read_info()
        writes = self.layout.unwind_offsets([(0x1200, 0x1250, 0x4000)], self.reader(raw))
        self.assertEqual(writes, {0x4001: 21, 0x4004: 18, 0x4006: 21})
        self.assertNotIn(0x4008, writes)  # ALLOC_LARGE's operand is not a CodeOffset

    def test_version_two_unwind_info_fails_closed_when_branch_widens(self):
        with self.assertRaisesRegex(ValueError, "version-2 unwind function"):
            self.layout.unwind_offsets([(0x1200, 0x1250, 0x4000)],
                                       self.reader(self.read_info(version=2)))

    def test_shared_unwind_info_cannot_be_rewritten_for_only_one_function(self):
        # The same UNWIND_INFO describes both functions. Only the first
        # prologue crosses this layout insertion, so changing the shared bytes
        # would make the second function's offsets wrong.
        entries = [(0x1200, 0x1250, 0x4000), (0x1300, 0x1350, 0x4000)]
        with self.assertRaisesRegex(ValueError, "(?i)shared native unwind info"):
            self.layout.unwind_offsets(entries, self.reader(self.read_info()))

    def test_shared_unwind_info_is_allowed_when_all_owners_shift_equally(self):
        _manifest, layout = shifted_layout([(0x1200, 0x1300), (0x1300, 0x1400)])
        entries = [(0x1200, 0x1250, 0x4000), (0x1300, 0x1350, 0x4000)]
        writes = layout.unwind_offsets(entries, self.reader(self.read_info()))
        self.assertEqual(writes, {0x4001: 21, 0x4004: 18, 0x4006: 21})


class CoffRelocationAfterShiftTests(unittest.TestCase):
    def test_data_and_interior_code_relocations_use_layout_targets(self):
        manifest, layout = shifted_layout([(0x1200, 0x1300)])
        manifest.update(image_base=0x140000000,
                        native_symbol_rvas={"native_interior": 0x1104},
                        linked_sections=[{"name": ".rdata", "rva": 0x5000, "virtual_size": 0x100}])
        symbols = {
            0: {"name": "replay_rva_00003020", "section": 0, "value": 0},
            1: {"name": "replay_rva_00001120", "section": 0, "value": 0},
            2: {"name": "native_interior", "section": 0, "value": 0},
            3: {"name": "local_rdata", "section": 1, "value": 0x20},
            4: {"name": "replay_rva_00003020", "section": 0, "value": 0},
        }
        data = bytearray(32)
        struct.pack_into("<q", data, 0, 0)   # ADDR64 image VA
        struct.pack_into("<i", data, 8, 0)   # REL32 to a shifted native RVA
        struct.pack_into("<i", data, 12, 0)  # REL32 to a labeled replacement interior
        struct.pack_into("<i", data, 16, 4)  # ADDR32NB addend
        struct.pack_into("<i", data, 20, 4)  # SECREL addend
        section = {"name": ".rdata", "rva": 0x5000, "data": data,
                   "relocations": [(0, 0, 1), (8, 1, 4), (12, 2, 4), (16, 4, 3), (20, 3, 11)]}
        obj = {"path": "relocation-fixture.obj", "symbols": symbols, "sections": [section]}
        base_relocations = set()
        relocated = build.relocate(obj, section, {"native_interior": 0x1104}, manifest,
                                   collections.defaultdict(int), base_relocations, layout)

        # Pin the independently derived synthetic mappings so expected bytes
        # do not merely repeat Layout.resolve, which the relocation code uses.
        self.assertEqual(layout.resolve(0x3020), 0x3050)
        self.assertEqual(layout.resolve(0x1120), 0x1140)
        self.assertEqual(layout.resolve(0x1104), 0x1108)
        self.assertEqual(layout.resolve(0x3024), 0x3054)
        self.assertEqual(struct.unpack_from("<Q", relocated, 0)[0], manifest["image_base"] + 0x3050)
        self.assertEqual(struct.unpack_from("<i", relocated, 8)[0], 0x1140 - (0x5008 + 4))
        self.assertEqual(struct.unpack_from("<i", relocated, 12)[0], 0x1108 - (0x500C + 4))
        self.assertEqual(struct.unpack_from("<I", relocated, 16)[0], 0x3054)
        self.assertEqual(struct.unpack_from("<I", relocated, 20)[0], 0x24)
        self.assertEqual(base_relocations, {0x5000})


if __name__ == "__main__":
    unittest.main()
