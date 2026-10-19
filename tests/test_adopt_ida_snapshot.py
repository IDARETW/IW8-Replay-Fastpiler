from pathlib import Path
import json
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import adopt_ida_snapshot as snapshot


class SnapshotAdoptionTests(unittest.TestCase):
    def fixture(self, root):
        raw = bytearray(0x600)
        raw[:2] = b'MZ'
        struct.pack_into('<I', raw, 0x3c, 0x80)
        raw[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<HHIIIHH', raw, 0x84, 0x8664, 2, 0, 0, 0, 0xf0, 0x22)
        optional = 0x98
        struct.pack_into('<H', raw, optional, 0x20b)
        struct.pack_into('<II', raw, optional + 16, 0x1000, 0x1000)
        struct.pack_into('<QII', raw, optional + 24, 0x140000000, 0x1000, 0x200)
        struct.pack_into('<II', raw, optional + 56, 0x3000, 0x200)
        struct.pack_into('<I', raw, optional + 108, 16)
        for index, (name, rva, offset, flags) in enumerate((
                (b'.text', 0x1000, 0x200, 0x60000020), (b'.data', 0x2000, 0x400, 0xc0000040))):
            struct.pack_into('<8sIIIIIIHHI', raw, optional + 0xf0 + 40 * index,
                             name, 0x200, rva, 0x200, offset, 0, 0, 0, 0, flags)
        raw[0x200] = 0xc3
        struct.pack_into('<I', raw, 0x400, 0x1000)
        exe, idb = root / 'input.exe', root / 'fresh.i64'
        exe.write_bytes(raw)
        idb.write_bytes(b'Closed IDB fingerprint fixture')
        stage = root / 'snapshot'
        stage.mkdir()
        md5 = snapshot.digest(exe, 'md5')
        code = dict(input_md5=md5, image_base=0x140000000, text_start=0x1000, text_end=0x2000,
                    instruction_count=1, instruction_bytes=1, noncode_bytes=0xfff)
        references = dict(input_md5=md5, image_base=0x140000000, image_size=0x3000,
                          processor='metapc', data_rvas=1, immediate_rvas=0, switch_elements=0)
        (stage / 'code-items.bin').write_bytes(struct.pack('<IB', 0x1000, 1))
        (stage / 'noncode-items.bin').write_bytes(struct.pack('<IIB', 0x1001, 0xfff, 0))
        (stage / 'ida-rva-fixups.bin').write_bytes(struct.pack('<III', 0x2000, 0x1000, 4))
        for name, value in (('ida-code-report.json', code), ('ida-reference-report.json', references),
                            ('ida-immediate-references.json', []), ('ida-switch-references.json', [])):
            (stage / name).write_text(json.dumps(value))
        receipt = dict(status='complete', processor='metapc', bitness=2, input_md5=md5,
                       input_sha256=snapshot.digest(exe), image_base=0x140000000,
                       idb_path=str(idb), idb_sha256=snapshot.digest(idb),
                       outputs={n: dict(bytes=(stage / n).stat().st_size, sha256=snapshot.digest(stage / n))
                                for n in snapshot.FILES})
        (stage / 'snapshot-receipt.json').write_text(json.dumps(receipt))
        return stage, exe, idb

    def test_native_image_fields_and_closed_database_fingerprints_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, exe, idb = self.fixture(root)
            result = snapshot.validate(stage, exe, idb)
            self.assertEqual(result['status'], 'validated')
            self.assertEqual(result['data_rvas'], 1)
            idb.write_bytes(b'Changed after snapshot')
            with self.assertRaisesRegex(ValueError, 'IDB fingerprint'):
                snapshot.validate(stage, exe, idb)

    def test_late_snapshot_change_rolls_back_every_replaced_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, exe, idb = self.fixture(root)
            result = snapshot.validate(stage, exe, idb)
            generated = root / 'generated'
            generated.mkdir()
            original = {n: ('Previous input: ' + n).encode() for n in snapshot.FILES}
            for name, content in original.items():
                (generated / name).write_bytes(content)
            (stage / snapshot.FILES[-1]).write_text('Changed after validation')
            backup = root / 'backup'
            with self.assertRaisesRegex(ValueError, 'changed during adoption'):
                snapshot.adopt(stage, generated, backup, result)
            self.assertEqual({n: (generated / n).read_bytes() for n in snapshot.FILES}, original)
            self.assertEqual({n: (backup / n).read_bytes() for n in snapshot.FILES}, original)

    def test_terminal_unowned_evidence_is_image_validated_and_adopted_with_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, exe, idb = self.fixture(root)
            raw = bytes(4)
            span = dict(begin=0x1001, end=0x1005, raw_hex=raw.hex(),
                        sha256=__import__('hashlib').sha256(raw).hexdigest())
            document = dict(schema=1, input_sha256=snapshot.digest(exe),
                            input_md5=snapshot.digest(exe, 'md5'),
                            entries=[dict(rva=0x1001, chunks=[[0x1001, 0x1005]],
                                          spans=[span], relocation_semantics='unproven')])
            name = snapshot.native_unproven.FILE
            (stage / name).write_text(json.dumps(document))
            receipt_path = stage / 'snapshot-receipt.json'
            receipt = json.loads(receipt_path.read_text())
            receipt['outputs'][name] = dict(bytes=(stage / name).stat().st_size,
                                            sha256=snapshot.digest(stage / name))
            receipt_path.write_text(json.dumps(receipt))
            result = snapshot.validate(stage, exe, idb)
            self.assertEqual(result['terminal_unowned_entries'], 1)
            snapshot.adopt(stage, root / 'generated', root / 'backup', result)
            self.assertEqual((root / 'generated' / name).read_bytes(), (stage / name).read_bytes())

    def test_loader_pointer_into_unproven_bytes_prevents_adoption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage, exe, idb = self.fixture(root)
            image = bytearray(exe.read_bytes())
            # DIR64 at .data+0x10 points into the proposed opaque text span.
            struct.pack_into('<II', image, 0x98 + 112 + 5 * 8, 0x2040, 12)
            struct.pack_into('<Q', image, 0x410, 0x140001001)
            struct.pack_into('<IIHH', image, 0x440, 0x2000, 12, 0xa010, 0)
            exe.write_bytes(image)
            raw = bytes(4)
            span = dict(begin=0x1001, end=0x1005, raw_hex=raw.hex(),
                        sha256=__import__('hashlib').sha256(raw).hexdigest())
            name = snapshot.native_unproven.FILE
            (stage / name).write_text(json.dumps(dict(
                schema=1, input_sha256=snapshot.digest(exe),
                input_md5=snapshot.digest(exe, 'md5'), entries=[dict(
                    rva=0x1001, chunks=[[0x1001, 0x1005]], spans=[span],
                    relocation_semantics='unproven')])))
            for report_name in ('ida-code-report.json', 'ida-reference-report.json'):
                path = stage / report_name
                report = json.loads(path.read_text())
                report['input_md5'] = snapshot.digest(exe, 'md5')
                path.write_text(json.dumps(report))
            receipt_path = stage / 'snapshot-receipt.json'
            receipt = json.loads(receipt_path.read_text())
            receipt.update(input_md5=snapshot.digest(exe, 'md5'), input_sha256=snapshot.digest(exe))
            receipt['outputs'] = {n: dict(bytes=(stage / n).stat().st_size,
                                           sha256=snapshot.digest(stage / n))
                                  for n in (*snapshot.FILES, name)}
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'native loader pointer target'):
                snapshot.validate(stage, exe, idb)


if __name__ == '__main__':
    unittest.main()
