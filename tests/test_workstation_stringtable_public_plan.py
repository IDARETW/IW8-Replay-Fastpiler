"""Keep public plan identities usable at the StringTable packaging boundary."""
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import workstation_fastfiles as fastfiles


class SnapshotReached(Exception):
    pass


class StringTablePublicPlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.zone = 'a' * 64
        self.cache = self.root / self.zone
        self.pending = self.cache / 'pending-edits/0/current.json'
        self.pending.parent.mkdir(parents=True)
        self.pending.write_text('{}')
        self.source = self.root / 'zone.ff'
        self.source.write_bytes(b'source')
        self.trace = self.root / 'trace.jsonl'
        self.trace.write_text('trace')
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_text('{}')
        sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        self.profile = dict(sha256=sha(self.source), patches=[])
        self.walk = dict(identity=dict(source_sha256=sha(self.source), patch_sha256s=[]),
                         stream_trace_enabled=True, stream_trace_sha256=sha(self.trace),
                         manifest_sha256=sha(self.manifest))
        self.body = SimpleNamespace(assets=[SimpleNamespace(type_id=54)])
        # This is the public plan shape: no internal pending_path is present.
        self.edit = dict(asset_id=self.zone + ':0', revision='b' * 64,
                         type='stringtable', name='table.csv')
        self.workspace = fastfiles.FastfileWorkspace.__new__(fastfiles.FastfileWorkspace)
        for name, replacement in (
            ('source_profile', lambda path: self.profile),
            ('_read_native_rows', lambda *args, **kwargs: (
                self.walk, [dict(type_id=54, name='table.csv')])),
            ('_native_walk_artifact', lambda walk, key: (
                self.trace if key == 'stream_trace_relative_path' else self.manifest)),
        ):
            handle = patch.object(fastfiles, name, replacement)
            handle.start()
            self.addCleanup(handle.stop)

    def invoke(self):
        return self.workspace._build_stringtable_replacement(
            self.zone, self.cache, dict(source=dict(path=str(self.source))),
            self.body, dict(edits=[self.edit]), self.root / 'output.ff', 10)

    def test_public_plan_resolves_native_cache_row_before_snapshot_validation(self):
        with patch.object(fastfiles, '_validate_pending_snapshot',
                          side_effect=SnapshotReached) as validate:
            with self.assertRaises(SnapshotReached):
                self.invoke()
        validate.assert_called_once_with(self.cache, 0, self.edit['asset_id'], self.body)

    def test_mismatched_legacy_listing_path_cannot_select_another_pending_record(self):
        other = self.root / 'other.json'
        other.write_text('{}')
        self.edit['pending_path'] = str(other)
        with patch.object(fastfiles, '_validate_pending_snapshot') as validate:
            with self.assertRaisesRegex(ValueError, 'differs from its selected native row'):
                self.invoke()
        validate.assert_not_called()

    def test_changed_active_revision_is_rejected_at_build_boundary(self):
        active = dict(revision='c' * 64, name='table.csv')
        with patch.object(fastfiles, '_validate_pending_snapshot',
                          return_value=(self.pending, active, self.root / 'payload')):
            with self.assertRaisesRegex(ValueError, 'revision changed after preflight'):
                self.invoke()
        self.assertFalse((self.root / 'output.ff').exists())


if __name__ == '__main__':
    unittest.main()
