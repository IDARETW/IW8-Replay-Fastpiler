import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from workstation_asset_codecs import (
    _stringtable_hash, decode_stringtable_sections, encode_stringtable_sections,
)


class StringTableNativeHashTests(unittest.TestCase):
    def test_signed_utf8_bytes_match_replay_c_locale_hash(self):
        # Replay's original machine code sign-extends each char before
        # tolower. The native table corpus independently confirms the rule.
        expected = {
            '': 0, 'A': 0x61, 'a': 0x61, 'Cafe': 0x002E799D,
            'Caf\u00e9': 0x05A0A60E, '\u00e9': 0xFFFFF846,
            '\u00c9': 0xFFFFF826, '\ufeff': 0xFFFFB793,
            '\u00ff': 0xFFFFF85C, '\u0080': 0xFFFFF7FE,
        }
        for value, native_hash in expected.items():
            with self.subTest(value=value):
                self.assertEqual(_stringtable_hash(value), native_hash)

    def test_serialized_dictionary_preserves_nonascii_case(self):
        values = ['\u00e9', '\u00c9', '\ufeff', '\u00e9']
        encoded = encode_stringtable_sections('authored/hash.csv', [values])
        self.assertEqual(encoded['dictionary'], ['\u00e9', '\u00c9', '\ufeff'])
        self.assertEqual(encoded['hashes'], struct.pack('<3I', 0xFFFFF846, 0xFFFFF826, 0xFFFFB793))
        self.assertEqual(decode_stringtable_sections(
            'authored/hash.csv', encoded['header'], encoded['cells'],
            encoded['hashes'], encoded['dictionary']), [values])

    def test_old_unsigned_hash_is_rejected_for_native_dictionary(self):
        encoded = encode_stringtable_sections('authored/hash.csv', [['\u00e9']])
        old_unsigned_hash = struct.pack('<I', 0xC3 * 31 + 0xA9)
        with self.assertRaisesRegex(ValueError, 'hash'):
            decode_stringtable_sections('authored/hash.csv', encoded['header'],
                                        encoded['cells'], old_unsigned_hash,
                                        encoded['dictionary'])


if __name__ == '__main__':
    unittest.main()
