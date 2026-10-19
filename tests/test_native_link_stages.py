"""C++ link stages against the old linker and malformed binary inputs."""
import copy
import ctypes
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build import LLVM, place_cpp, serialize_image, python_loader_tables
from native_linker import NativeStages, NativeLayout, NativeLinker, Wire
from layout import Layout


class NativeStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.stages = NativeStages(Path(cls.temp.name), LLVM, compare=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        optional = dict(ImageBase=0x140000000, SizeOfUninitializedData=0,
                        MajorOperatingSystemVersion=6, MinorOperatingSystemVersion=0,
                        MajorImageVersion=0, MinorImageVersion=0,
                        MajorSubsystemVersion=6, MinorSubsystemVersion=0,
                        Reserved1=0, Subsystem=3, DllCharacteristics=0x8160,
                        SizeOfStackReserve=0x100000, SizeOfStackCommit=0x1000,
                        SizeOfHeapReserve=0x100000, SizeOfHeapCommit=0x1000,
                        LoaderFlags=0)
        optional.update(SizeOfImage=0x6000, AddressOfEntryPoint=0x1800, BaseOfCode=0x1000,
                        SectionAlignment=0x1000, FileAlignment=0x200)
        self.manifest = dict(image_base=optional['ImageBase'], optional=optional, timestamp=123,
            characteristics=0x22, input_sha256='01' * 32,
            replacements=[dict(begin=0x1100, end=0x1104, symbol='Replacement')], short_references=[],
            sections=[dict(name=name, rva=rva, raw_size=0x1000, virtual_size=0x1000, flags=flags)
                      for name, rva, flags in [('.text', 0x1000, 0x60000020), ('.rdata', 0x2000, 0x40000040),
                                               ('.data', 0x3000, 0xc0000040), ('.pdata', 0x4000, 0x40000040),
                                               ('.reloc', 0x5000, 0x42000040)]],
            directories=[dict(rva=0, size=0) for _ in range(16)])
        self.text = bytearray(0x1000)
        self.layout = NativeLayout(self.manifest, {'Replacement': 8}, self.text, self.stages)
        self.engine = NativeLinker(self.layout, self.manifest, Path(self.temp.name), LLVM, compare=True)
        self.layout.engine = self.engine

    def tearDown(self):
        self.engine.close()

    def test_placement_retains_entry_and_places_new_code_writable_and_bss(self):
        self.manifest['sections'][2]['virtual_size'] = 0x800
        objects = [dict(path='test.obj', sections=[
            dict(name='.text', data=bytearray(8), flags=0x60000020),
            dict(name='.text$helper', data=bytearray(32), flags=0x60500020),
            dict(name='.data', data=bytearray(16), flags=0xc0500040),
            dict(name='.bss', data=bytearray(16), flags=0xc0500080)], symbols={
                0: dict(name='Replacement', section=1, storage=2, kind=0x20, value=0),
                1: dict(name='Helper', section=2, storage=2, kind=0x20, value=0),
                2: dict(name='Global', section=3, storage=2, kind=0, value=0),
                3: dict(name='Zero', section=4, storage=2, kind=0, value=0)})]
        symbols, _, extras, _, _ = self.engine.place(objects, {'Replacement': 0x1100}, False, place_cpp)
        self.assertEqual(symbols['Replacement'], 0x1100)
        self.assertEqual(objects[0]['sections'][3]['placement'], 'native_bss_tail')
        self.assertEqual([s['name'] for s in extras], ['.cpp', '.rwcpp'])
        self.assertNotEqual(symbols['Helper'], symbols['Global'])
        objects[0]['sections'][0]['flags'] |= 0x00500000
        self.manifest['replacements'][0]['begin'] = 0x1101
        with self.assertRaisesRegex(ValueError, 'alignment'):
            self.engine.place(objects, {'Replacement': 0x1101}, False, place_cpp)

    def test_short_branches_relax_and_preserve_loop_flags(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['replacements'][0].update(begin=0x1100, end=0x1104)
        manifest['short_references'] = [(0x10f0, 0x1170), (0x10e0, 0x1170)]
        text = bytearray(self.text)
        text[0xf0:0xf2] = b'\x75\x7e'
        text[0xe0:0xe2] = b'\xe2\x7e'
        layout = NativeLayout(manifest, {'Replacement': 8}, text, self.stages)
        engine = NativeLinker(layout, manifest, Path(self.temp.name), LLVM, compare=True)
        try:
            layout.engine = engine
            linked = layout.copy_text(text)
            layout.branches(linked, manifest)
            self.assertEqual(linked[0xe0:0xe5], b'\xe2\x02\xeb\x05\xe9')
            at = layout.map(0x10f0) - 0x1000
            self.assertEqual(linked[at:at + 2], b'\x0f\x85')
        finally:
            engine.close()

    def test_layout_rejects_overlaps_and_truncated_prefixes(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['replacements'].append(dict(begin=0x1102, end=0x1110, symbol='Other'))
        with self.assertRaisesRegex(ValueError, 'overlap'):
            NativeLayout(manifest, {'Replacement': 8, 'Other': 8}, self.text, self.stages)
        manifest = copy.deepcopy(self.manifest)
        manifest['short_references'] = [(0x1fff, 0x1000)]
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            NativeLayout(manifest, {'Replacement': 8}, self.text, self.stages)

    def test_loader_tables_retain_unwind_and_relocate_data_pointers(self):
        manifest = self.manifest
        manifest['directories'][3] = dict(rva=0x4000, size=36)
        manifest['directories'][5] = dict(rva=0x5000, size=12)
        original = struct.pack('<9I', 0x1100, 0x1104, 0x2100, 0x1800, 0x1820, 0x2200, 0x1900, 0x1900, 0x2300)
        compiled = struct.pack('<III', 0x1100, 0x1108, 0x3100)
        sections = [dict(s, rva=self.layout.map(s['rva']), data=bytearray(s['raw_size'])) for s in manifest['sections']]
        sections[0]['virtual_size'] = 0x2000
        sections[3]['data'][:36] = original
        sections[4]['data'][:12] = struct.pack('<IIHH', 0x3000, 12, 0xa010, 0)
        expected_sections = copy.deepcopy(sections)
        expected_manifest = copy.deepcopy(manifest)
        python_loader_tables(expected_manifest, expected_sections, original, compiled, {0x7010}, self.layout)
        removed, retained, directories, linked = self.engine.tables(sections, original, compiled, {0x7010})
        self.assertEqual(removed, 1)
        self.assertEqual(retained, [(0x1800, 0x1820, 0x2200), (0x1900, 0x1900, 0x2300)])
        self.assertEqual(directories, expected_manifest['directories'])
        for actual, expected in zip(linked, expected_sections):
            self.assertEqual(actual['data'], expected['data'])
        with self.assertRaisesRegex(ValueError, 'Invalid compiled runtime function range'):
            self.engine.tables(sections, original, struct.pack('<III', 0x1100, 0x1100, 0x3100), {0x7010})
        with self.assertRaisesRegex(ValueError, 'Invalid native runtime function range'):
            self.engine.retained_unwind(struct.pack('<III', 0x1821, 0x1820, 0x2200))
        manifest['directories'] = directories
        image = self.stages.serialize_image(manifest, linked, serialize_image)
        self.assertEqual(image[:2], b'MZ')
        bad = copy.deepcopy(linked)
        bad[1]['rva'] = bad[0]['rva']
        with self.assertRaisesRegex(ValueError, 'Overlapping'):
            self.stages.serialize_image(manifest, bad, serialize_image)

    def test_switch_table_signed_scaled_and_unrepresentable_encodings(self):
        for width in (1, 2, 4, 8):
            row = dict(target=0x1800, base=0x1700, width=width, shift=4, subtract=True, signed=True)
            self.assertEqual(int.from_bytes(self.engine.relative_table(row), 'little', signed=True), -16)
        row = dict(target=0x1801, base=0x1700, width=4, shift=4, subtract=False)
        with self.assertRaisesRegex(ValueError, 'representable'):
            self.engine.relative_table(row)

    def test_unwind_adjusts_operation_offsets_but_preserves_operand_slots(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['replacements'] = []
        manifest['short_references'] = [(0x1010, 0x1800)]
        text = bytearray(self.text)
        text[0x10:0x12] = b'\xeb\x00'
        # Use small insertion granularity so the widened prologue stays <=255.
        manifest['optional']['SectionAlignment'] = 16
        layout = NativeLayout(manifest, {}, text, self.stages)
        engine = NativeLinker(layout, manifest, Path(self.temp.name), LLVM, compare=True)
        try:
            layout.engine = engine
            metadata = bytes([1, 40, 3, 0, 24, 1, 7, 0, 8, 0])
            def read(rva, size):
                return metadata[rva - 0x2200:rva - 0x2200 + size]
            writes = layout.unwind_offsets([(0x1000, 0x1100, 0x2200)], read)
            self.assertEqual(writes, {0x2201: 56, 0x2204: 40})
        finally:
            engine.close()

    def test_bad_stage_records_fail_without_crossing_the_abi(self):
        wire = Wire(b'\0')
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            self.stages.stage(1, wire)
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            self.engine.stage(99, Wire())
        output, size = ctypes.c_void_p(1), ctypes.c_uint64(1)
        error = ctypes.create_string_buffer(256)
        okay = self.stages.library.replay_linker_stage(None, 1, None, 10,
            ctypes.byref(output), ctypes.byref(size), error, len(error))
        self.assertFalse(okay)
        self.assertIsNone(output.value)
        self.assertEqual(size.value, 0)

    def test_comdat_largest_selects_associated_unwind_and_rejects_cycles(self):
        def obj(size, path):
            return dict(path=path, timestamp=1, sections=[
                dict(name='.text$fn', number=1, flags=0x60001020, data=bytearray(size),
                     aux=dict(selection=6, associated=0), relocations=[]),
                dict(name='.pdata', number=2, flags=0x40001040, data=bytearray(12),
                     aux=dict(selection=5, associated=1), relocations=[])], symbols={
                0: dict(name='Template', value=0, section=1, storage=2, kind=0x20)})
        objects = [obj(4, 'small.obj'), obj(16, 'large.obj')]
        self.stages.select_comdats(objects)
        self.assertTrue(objects[0]['sections'][0]['discarded'])
        self.assertTrue(objects[0]['sections'][1]['discarded'])
        self.assertIs(objects[0]['sections'][0]['selected'], objects[1]['sections'][0])
        broken = obj(4, 'cycle.obj')
        broken['sections'][0]['aux'] = dict(selection=5, associated=2)
        with self.assertRaisesRegex(ValueError, 'Cyclic'):
            self.stages.select_comdats([broken])
        mismatched = [obj(4, 'a.obj'), obj(4, 'b.obj')]
        for row in mismatched:
            row['sections'][0]['aux']['selection'] = 4
        mismatched[1]['sections'][0]['data'][0] = 1
        with self.assertRaisesRegex(ValueError, 'EXACT_MATCH'):
            self.stages.select_comdats(mismatched)

    def test_common_storage_coalesces_largest_declaration_and_strong_wins(self):
        def obj(size, path):
            return dict(path=path, sections=[], symbols={
                0: dict(name='Common', section=0, value=size, kind=0, storage=2),
                1: dict(name='Existing', section=0, value=8, kind=0, storage=2)})
        objects = [obj(3, 'first.obj'), obj(17, 'second.obj')]
        self.stages.allocate_common(objects, {'Existing': 0x3000})
        self.assertEqual(len(objects[0]['sections'][0]['data']), 17)
        self.assertEqual(objects[0]['sections'][0]['flags'] >> 20 & 15, 5)
        self.assertFalse(objects[1]['sections'])
        self.assertEqual(objects[0]['symbols'][1]['value'], 0)


if __name__ == '__main__':
    unittest.main()
