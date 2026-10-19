from pathlib import Path
import hashlib
import json
import sys
import struct
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_unproven
from layout import Layout


class TerminalUnownedTests(unittest.TestCase):
    def callback_fixture(self, strength=2):
        at, first = 0x1080, 0x2200
        raw = (bytes.fromhex('415052514883ec20ff15') + struct.pack('<i', first-at-14) +
               bytes.fromhex('4883c420595a4158ff25') + struct.pack('<i', first+8-at-28) + b'\xcc'*4)
        spans = native_unproven.Spans([dict(begin=at, end=at+32, raw=raw)], 1)
        manifest = dict(sections=[dict(rva=0x1000, flags=0x60000020, virtual_size=0x200),
                                  dict(rva=0x2000, flags=0xc0000040, virtual_size=0x1000)])
        code = dict(original_rva=0x1000, data=bytes.fromhex('488d0d00000000'), relocations=[(3, 0, 4)])
        obj = dict(symbols={0:dict(name='replay_rva_00001080')})
        lengths, confidence = bytearray(0x200), bytearray(0x200)
        lengths[0], confidence[0] = 7, strength
        return spans, manifest, {'fixture': (obj, code)}, lengths, confidence

    def test_callback_requires_strong_external_reference_and_zero_pointer_slots(self):
        spans, manifest, objects, lengths, confidence = self.callback_fixture(1)
        self.assertEqual(spans.prove_callback_thunks(manifest, objects, lengths, confidence,
                                                   lambda at,size: b'\0'*size), [])
        confidence[0] = 2
        with self.assertRaisesRegex(ValueError, 'not zero-initialized'):
            spans.prove_callback_thunks(manifest, objects, lengths, confidence, lambda at,size: b'\1'*size)
        proof = spans.prove_callback_thunks(manifest, objects, lengths, confidence, lambda at,size: b'\0'*size)
        self.assertEqual(proof[0]['producers'], [0x1000])
        self.assertEqual(len(proof[0]['references']), 2)

    def test_callback_only_certified_displacements_may_change(self):
        spans, manifest, objects, lengths, confidence = self.callback_fixture()
        spans.prove_callback_thunks(manifest, objects, lengths, confidence, lambda at,size: b'\0'*size)
        class Mapping:
            def map(self, at): return at if at < 0x2000 else at+0x1000
            def resolve(self, at): return self.map(at)
        mapping = Mapping()
        text = bytearray(0x200)
        text[0x80:0xa0] = spans.rows[0]['raw']
        for ref in spans.callback_thunks[0]['references']:
            site = 0x1080+ref['offset']
            struct.pack_into('<i', text, site-0x1000, mapping.resolve(ref['target'])-site-4)
        spans.verify_bytes(text, 0x1000, mapping)
        text[0x80] ^= 1
        with self.assertRaisesRegex(ValueError, 'changed terminal unowned'):
            spans.verify_bytes(text, 0x1000, mapping)

    def fixture(self, root):
        raw = bytes.fromhex('4883ec18a7b34a9beb17')
        span = dict(begin=0x1080, end=0x1080 + len(raw), raw_hex=raw.hex(),
                    sha256=hashlib.sha256(raw).hexdigest())
        doc = dict(schema=1, input_sha256='a' * 64, input_md5='b' * 32,
                   entries=[dict(rva=0x1080, chunks=[[span['begin'], span['end']]],
                                 spans=[span], relocation_semantics='unproven')])
        path = root / native_unproven.FILE
        path.write_text(json.dumps(doc))
        return path, doc, raw

    def load(self, root, read=None):
        return native_unproven.load(root, 'a' * 64, 'b' * 32, 0x1000, 0x1200, read)

    def layout(self, begin):
        manifest = dict(replacements=[dict(begin=begin, end=begin + 4, symbol='edit')],
                        sections=[dict(rva=0x1000, raw_size=0x200, virtual_size=0x200),
                                  dict(rva=0x2000)], optional=dict(SectionAlignment=16),
                        short_references=[])
        return Layout(manifest, {'edit': 24}, bytes(0x200))

    def test_image_and_span_bytes_are_verified_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, doc, raw = self.fixture(root)
            spans = self.load(root, lambda at, size: raw)
            self.assertTrue(spans.overlaps(0x107f, 0x1081))
            self.assertFalse(spans.overlaps(0x107f, 0x1080))
            self.assertEqual(sum(spans.mask(0x1000, 0x200)), len(raw))
            with self.assertRaisesRegex(ValueError, 'original native image'):
                self.load(root, lambda at, size: b'\0' * size)
            doc['input_sha256'] = 'c' * 64
            path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'another native image'):
                self.load(root)

    def test_unknown_bytes_cannot_move_or_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            spans = self.load(root)
            spans.verify_layout(self.layout(0x1100))
            with self.assertRaisesRegex(ValueError, 'moves terminal unowned'):
                spans.verify_layout(self.layout(0x1020))
            with self.assertRaisesRegex(ValueError, 'replacement overlaps'):
                spans.verify_layout(self.layout(0x1082))

    def test_final_reassembled_and_linked_bytes_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, raw = self.fixture(root)
            spans = self.load(root)
            text = bytearray(0x200)
            text[0x80:0x80 + len(raw)] = raw
            self.assertEqual(spans.verify_bytes(text, 0x1000)['bytes'], len(raw))
            text[0x84] ^= 1
            with self.assertRaisesRegex(ValueError, 'changed terminal unowned'):
                spans.verify_bytes(text, 0x1000)

    def test_overlap_and_proven_owner_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, doc, _ = self.fixture(root)
            doc['entries'][0]['containing_proven_owner'] = {'rva': 0x1000}
            path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'proven native ownership'):
                self.load(root)
            with self.assertRaisesRegex(ValueError, 'overlap'):
                native_unproven.Spans([dict(begin=1, end=4), dict(begin=3, end=5)])

    def test_region_preserves_whole_payload_beyond_guessed_entry_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, doc, raw = self.fixture(root)
            payload = b'\xcc' * 4 + raw + b'\xcc' * 12
            doc['regions'] = [dict(begin=0x107c, end=0x107c + len(payload), raw_hex=payload.hex(),
                sha256=hashlib.sha256(payload).hexdigest(), relocation_semantics='unproven',
                proof=dict(kind='encoded_address_unwind_gap'))]
            path.write_text(json.dumps(doc))
            spans = self.load(root)
            self.assertEqual(len(spans.rows), 1)
            self.assertEqual(sum(spans.mask(0x1000, 0x200)), len(payload))
            altered = bytes([payload[0] ^ 1]) + payload[1:]
            region = doc['regions'][0]
            region['raw_hex'] = altered.hex()
            region['sha256'] = hashlib.sha256(altered).hexdigest()
            path.write_text(json.dumps(doc))
            # The first byte is outside the entry chunk, but still verified.
            with self.assertRaisesRegex(ValueError, 'original native image'):
                self.load(root, lambda at,size: payload[at-0x107c:at-0x107c+size])
            region['raw_hex'] = payload.hex()
            region['sha256'] = hashlib.sha256(payload).hexdigest()
            region['begin'] = 0x1081
            region['end'] = 0x1081 + len(payload)
            path.write_text(json.dumps(doc))
            with self.assertRaisesRegex(ValueError, 'conflicts with its protected region'):
                self.load(root)


if __name__ == '__main__':
    unittest.main()
