from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.workstation_image_resize import _validate_scratch_schedules


class ImageResizeTraceTests(unittest.TestCase):
    def _fixture(self, root: Path, *, destination=32, native_end=True, scoped=True):
        owner = 7
        events = [
            {'kind': 'xasset_begin', 'xasset_index': owner, 'sequence': 0},
            {'kind': 'load_stream_call', 'xasset_index': owner, 'sequence': 1,
             'loader_start_arg': 0, 'at_start': True, 'size': 16,
             'destination_stream_location': {'stream': 1, 'offset': destination}},
            {'kind': 'stream_operation', 'xasset_index': owner if scoped else 8, 'sequence': 2,
             'operation': 'load', 'input_before': 0, 'input_after': 16,
             'physical_input_bytes': 16, 'block_before': 1, 'offset_before': 32,
             'block_after': 1, 'offset_after': 48},
            {'kind': 'stream_operation', 'xasset_index': owner, 'sequence': 3,
             'operation': 'pop', 'input_before': 16, 'input_after': 16,
             'physical_input_bytes': 0, 'block_before': 1, 'offset_before': 48,
             'block_after': 1, 'offset_after': 0},
        ]
        if native_end:
            events.append({'kind': 'stream_operation', 'xasset_index': owner,
                'sequence': len(events), 'operation': 'end_asset', 'input_before': 16,
                'input_after': 16, 'physical_input_bytes': 0, 'block_before': 1,
                'offset_before': 0, 'block_after': 1, 'offset_after': 0})
        events.append({'kind': 'xasset_end', 'xasset_index': owner, 'sequence': len(events)})
        trace = root / 'trace.jsonl'
        raw = b''.join((json.dumps(row) + '\n').encode() for row in events)
        trace.write_bytes(raw)
        manifest = root / 'manifest.json'
        manifest.write_text(json.dumps({'profile': 'replay-1.20', 'xfile_version': 0xff7,
            'complete': True, 'success': True, 'failed': 0, 'unavailable': 0,
            'tested': 1, 'top_level_index': 1, 'serialized_bytes_read': 16,
            'stream_trace_events': len(events), 'stream_trace_sha256': hashlib.sha256(raw).hexdigest()}))
        edits = {owner: {'stream_offset': 32, 'current': {
            'payload_archive_offset': 0, 'total_size': 16}}}
        return trace, manifest, edits

    def test_accepts_exact_pixel_load_reset_and_native_end(self):
        with tempfile.TemporaryDirectory() as directory:
            trace, manifest, edits = self._fixture(Path(directory))
            offsets, digest, count = _validate_scratch_schedules(trace, manifest, 16, 1, edits)
            self.assertEqual(offsets[1], 48)
            self.assertEqual(count, 6)
            self.assertEqual(digest, json.loads(manifest.read_text())['stream_trace_sha256'])

    def test_rejects_load_call_with_wrong_scratch_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            trace, manifest, edits = self._fixture(Path(directory), destination=31)
            with self.assertRaisesRegex(ValueError, 'scratch destination'):
                _validate_scratch_schedules(trace, manifest, 16, 1, edits)

    def test_rejects_reset_without_native_end_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            trace, manifest, edits = self._fixture(Path(directory), native_end=False)
            with self.assertRaisesRegex(ValueError, 'restored before asset end'):
                _validate_scratch_schedules(trace, manifest, 16, 1, edits)

    def test_rejects_pixel_operation_outside_its_owner_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            trace, manifest, edits = self._fixture(Path(directory), scoped=False)
            with self.assertRaisesRegex(ValueError, 'active XAsset scope'):
                _validate_scratch_schedules(trace, manifest, 16, 1, edits)


if __name__ == '__main__':
    unittest.main()
