"""Differential checks for the native backend's address and relocation domains."""
import collections
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build import LLVM, relocate
from layout import Layout
from native_linker import NativeLinker


class NativeLinkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Loaded Windows DLLs remain open until this test process exits.
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.output = Path(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.manifest = {'image_base': 0x140000000, 'optional': {'SizeOfImage': 0x8000, 'SectionAlignment': 0x1000},
            'sections': [{'rva': 0x1000, 'raw_size': 0x1000, 'virtual_size': 0x1000}, {'rva': 0x2000}],
            'replacements': [{'begin': 0x1100, 'end': 0x1104, 'symbol': 'Replacement'}], 'short_references': []}
        self.layout = Layout(self.manifest, {'Replacement': 8}, bytes(0x1000))
        self.layout.add_interior_rvas([(0x1102, 0x1102, 'Replacement')])
        self.engine = NativeLinker(self.layout, self.manifest, self.output, LLVM, compare=True)
        self.sections = [{'rva': 0x1000, 'virtual_size': 0x2000}, {'rva': 0x3000, 'virtual_size': 0x1000},
                         {'rva': 0x4000, 'virtual_size': 0x1000}]
        self.manifest['linked_sections'] = self.sections
        self.engine.update_sections(self.sections)

    def tearDown(self):
        self.engine.close()

    def apply(self, kinds, symbol=None, addend=0, symbols=None, original_rva=0x1800):
        symbol = symbol or {'name': 'replay_rva_00001300', 'section': 0, 'value': 0}
        data = bytearray(8 * len(kinds))
        relocations = []
        for n, kind in enumerate(kinds):
            width = 8 if kind == 1 else 2 if kind == 10 else 4
            data[n * 8:n * 8 + width] = addend.to_bytes(width, 'little', signed=kind != 10)
            relocations.append((n * 8, 0, kind))
        section = {'name': '.text', 'rva': original_rva, 'original_rva': original_rva,
                   'data': data, 'relocations': relocations}
        obj = {'path': 'fixture.obj', 'sections': [section], 'symbols': {0: symbol}}
        counts, bases = collections.Counter(), set()
        result = self.engine.relocate(obj, section, symbols or {}, self.manifest, counts, bases,
                                      self.layout, reference=relocate)
        return result, counts, bases

    def test_all_relative_kinds_shifted_targets_sections_and_loader_relocations(self):
        result, counts, bases = self.apply([1, 3, 4, 5, 6, 7, 8, 9, 10, 11], addend=2)
        self.assertEqual(sum(counts.values()), 10)
        self.assertEqual(struct.unpack_from('<Q', result)[0], 0x140002302)
        self.assertEqual(bases, {0x2800})
        self.assertEqual(struct.unpack_from('<H', result, 64)[0], 3)
        self.assertEqual(struct.unpack_from('<I', result, 72)[0], 0x1302)

    def test_absolute_addr32_and_unsigned_addr64(self):
        symbol = {'name': 'Absolute', 'section': -1, 'value': 0xffffffff}
        result, _, bases = self.apply([2], symbol)
        self.assertEqual(result[:4], b'\xff' * 4)
        result, _, _ = self.apply([1], symbol, (1 << 63) - 1)
        self.assertEqual(struct.unpack_from('<Q', result)[0], (1 << 63) + 0xfffffffe)
        self.assertFalse(bases)

    def test_interior_label_usage_is_retained_and_unknown_interior_is_rejected(self):
        mapped = {'name': 'replay_rva_00001102', 'section': 0, 'value': 0}
        self.apply([3], mapped)
        # Exercise the receipt path without Python comparison recording the use.
        self.layout.interior_uses.clear()
        self.engine.sync_interior_uses()
        self.assertIn(0x1102, self.layout.interior_uses)
        unknown = dict(mapped, name='replay_rva_00001101')
        with self.assertRaisesRegex(ValueError, 'interior'):
            self.apply([3], unknown)

    def test_overflow_missing_symbol_and_replaced_sites_fail_or_skip(self):
        with self.assertRaisesRegex(ValueError, 'REL32'):
            self.apply([4], {'name': 'Far', 'section': 0, 'value': 0}, symbols={'Far': 1 << 40})
        with self.assertRaisesRegex(ValueError, 'relocation overflow'):
            self.apply([2])
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            self.apply([3], {'name': 'Missing', 'section': 0, 'value': 0})
        _, counts, _ = self.apply([3], original_rva=0x1100)
        self.assertFalse(counts)

    def test_weak_external_and_selected_comdat_targets(self):
        section = {'name': '.text', 'rva': 0x4000, 'data': bytearray(8), 'relocations': [(0, 0, 1)]}
        chosen = {'rva': 0x4100}
        discarded = {'rva': 0x4200, 'discarded': True, 'selected': chosen}
        obj = {'path': 'comdat.obj', 'sections': [section, discarded], 'symbols': {
            0: {'name': 'Weak', 'section': 0, 'value': 0, 'weak': {'fallback': 1}},
            1: {'name': 'Selected', 'section': 2, 'value': 3}}}
        data = self.engine.relocate(obj, section, {}, self.manifest, collections.Counter(), set(),
                                   self.layout, reference=relocate)
        self.assertEqual(struct.unpack('<Q', data)[0], 0x140004103)
        chosen['original_rva'] = 0x1300
        data = self.engine.relocate(obj, section, {}, self.manifest, collections.Counter(), set(),
                                   self.layout, reference=relocate)
        self.assertEqual(struct.unpack('<Q', data)[0], 0x140002303)

    def test_native_data_and_metadata_fixups_with_retired_fields(self):
        sections = [{'rva': 0x3000, 'data': bytearray(32)}]
        refs = struct.pack('<IIIIII', 0x2000, 0x1300, 8, 0x2008, 0x1300, 4)
        self.assertEqual(self.engine.references(sections, refs), (1, 1, 2))
        self.assertEqual(struct.unpack_from('<Q', sections[0]['data'])[0], 0x140002300)
        self.assertEqual(self.engine.references(sections, refs, True, {0x2008}), (1, 0, 1))
        self.assertEqual(struct.unpack_from('<Q', sections[0]['data'])[0], 0x2300)

    def test_retired_code_and_truncated_relocation_sites_are_rejected(self):
        self.layout.replacements[0]['retired'] = True
        self.layout.interior_rvas.clear()
        self.engine.update_sections(self.sections)
        with self.assertRaisesRegex(ValueError, 'retired'):
            self.apply([3], {'name': 'replay_rva_00001100', 'section': 0, 'value': 0})
        section = {'name': '.text', 'rva': 0x4000, 'data': bytearray(4), 'relocations': [(0, 0, 1)]}
        obj = {'path': 'truncated.obj', 'sections': [section], 'symbols': {
            0: {'name': 'Absolute', 'section': -1, 'value': 1}}}
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.engine.relocate(obj, section, {}, self.manifest, collections.Counter(), set(),
                                 self.layout, reference=relocate)


if __name__ == '__main__':
    unittest.main()
