"""Resident alignment regressions from a full native StringTable reread.

Only authored CSV values are used. The section addresses reproduce the traced
2/4/8-byte allocation boundaries that exposed a four-byte alias displacement.
"""
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from workstation_stringtable import _serialize_record


class StringTableAlignmentTests(unittest.TestCase):
    def test_dictionary_growth_crosses_pointer_alignment_boundary(self):
        layout = SimpleNamespace(root_archive_offset=0, name_pointer_mode='inline',
                                 asset_name='omnvars/mp/omnvars.csv', name_stream_offset=13630180)
        rows = [[f'value{(r * 14 + c) % 291}' for c in range(14)] for r in range(219)]
        record, emitted = _serialize_record(bytes(48), layout, rows)
        self.assertEqual(emitted['stream5_sections'],
                         dict(cells=13630204, hashes=13636336,
                              pointers=13637504, strings=13639832))
        self.assertEqual(emitted['new_string_offsets']['value0'], 13639832)
        self.assertEqual(struct.unpack_from('<III', record, 8), (14, 219, 291))
        # Resident padding must not appear in the fastfile byte stream.
        archive_strings = 48 + 23 + 6132 + 1164 + 2328
        self.assertEqual(record[archive_strings:archive_strings + 7], b'value0\0')
        self.assertEqual(len(record) - archive_strings,
                         emitted['stream5_end'] - 13639832)

    def test_hash_and_pointer_padding_are_independent(self):
        layout = SimpleNamespace(root_archive_offset=0, name_pointer_mode='inline',
                                 asset_name='abc', name_stream_offset=0)
        record, emitted = _serialize_record(bytes(48), layout, [['a']])
        self.assertEqual(emitted['stream5_sections'],
                         dict(cells=4, hashes=8, pointers=16, strings=24))
        self.assertEqual(emitted['stream5_end'], 26)
        self.assertEqual(emitted['new_string_offsets'], {'a': 24})
        self.assertEqual(len(record), 48 + 4 + 2 + 4 + 8 + 2)

    def test_name_alignment_does_not_inject_archive_padding(self):
        layout = SimpleNamespace(root_archive_offset=0, name_pointer_mode='inline',
                                 asset_name='abcd', name_stream_offset=0)
        record, emitted = _serialize_record(bytes(48), layout, [['a']])
        self.assertEqual(emitted['stream5_sections'],
                         dict(cells=6, hashes=8, pointers=16, strings=24))
        self.assertEqual(record[48:55], b'abcd\0\0\0')
        self.assertEqual(len(record), 48 + 5 + 2 + 4 + 8 + 2)


if __name__ == '__main__':
    unittest.main()
