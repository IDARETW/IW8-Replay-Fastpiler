"""Compiled output may be reopened only through the bounded unsigned IWC path."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from workstation_fastfiles import (
    ZoneBody, make_replay_header_only_patch, pack_replay_uncompressed, source_profile,
)
from workstation_localize_crud import (
    _read_compiled_intermediate, plan_localize_crud, remove_localize_asset,
)


def _localize_workspace_snapshot():
    inline = 0xFFFFFFFFFFFFFFFE
    body = struct.pack('<IIQIIQ', 0, 0, 0, 2, 0, inline) + b''.join(
        struct.pack('<IIQ', 41, 0, inline) for _ in range(2))
    native = [dict(type_id=41, name='test/a'), dict(type_id=41, name='test/b')]
    profile = dict(sha256='a' * 64, patches=[])
    identity = dict(source_fastfile_sha256=profile['sha256'])
    snapshot = (Path('cache'), {}, ZoneBody.parse(body), Path('source.ff'), profile,
                {'walk_key': 'walk'}, native, identity)
    return snapshot, native


class CompiledLocalizeIntermediateTests(unittest.TestCase):
    def test_unsigned_native_intermediate_and_receipt_binding(self):
        body = struct.pack('<IIQIIQ', 0, 0, 0, 0, 0, 0)
        reservations = [len(body), 0, 0, 0, 0, 64, 0, 0, 0, 0, 0]
        packed = pack_replay_uncompressed(body, reservations)
        expected = hashlib.sha256(packed).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'native.ff'
            path.write_bytes(packed)
            template = bytearray(0x148)
            template[:8] = b'IWffd100'
            struct.pack_into('<II', template, 8, 6, 4)
            path.with_suffix('.fp').write_bytes(
                make_replay_header_only_patch(bytes(template), packed))
            profile = source_profile(path)
            self.assertEqual(profile['input_format'], 'replay120-iwc-uncompressed-v1')
            self.assertFalse(profile['signature_verified'])
            self.assertEqual(_read_compiled_intermediate(path, expected), (body, reservations))
            with self.assertRaisesRegex(ValueError, 'writer receipt'):
                _read_compiled_intermediate(path, '0' * 64)
            damaged = bytearray(packed)
            struct.pack_into('<I', damaged, 0x8c, len(body) + 1)
            path.write_bytes(damaged)
            with self.assertRaisesRegex(ValueError, 'body header'):
                _read_compiled_intermediate(path, hashlib.sha256(damaged).hexdigest())


class FinalLocalizeRowPreflightTests(unittest.TestCase):
    def test_public_remove_stages_original_final_row_after_identity_check(self):
        snapshot, native = _localize_workspace_snapshot()

        class Workspace:
            def get_asset(self, asset_id):
                return dict(type_id=41, type='localize', revision=7,
                            name='test/b', content='value-b')

        workspace = Workspace()
        with patch('workstation_localize_crud._inputs', return_value=snapshot), \
             patch('workstation_localize_crud._stage', return_value={'operation_id': 'op-r-1'}) as stage:
            result = remove_localize_asset(workspace, 'zone:1', 7)
        self.assertEqual(result['status'], 'native-localize-removal-staged')
        self.assertFalse(result['editable'])
        stage.assert_called_once_with(workspace, 'zone', 'remove', 'test/b', 'value-b', 1)

    def test_public_remove_rejects_stale_final_row_identity(self):
        snapshot, _ = _localize_workspace_snapshot()

        class Workspace:
            def get_asset(self, asset_id):
                return dict(type_id=41, type='localize', revision=7,
                            name='test/stale', content='value-b')

        with patch('workstation_localize_crud._inputs', return_value=snapshot), \
             patch('workstation_localize_crud._stage') as stage:
            with self.assertRaisesRegex(ValueError, 'source XAsset identity'):
                remove_localize_asset(Workspace(), 'zone:1', 7)
        stage.assert_not_called()

    def test_preflight_accepts_final_row_removal_for_native_writer_gate(self):
        snapshot, native = _localize_workspace_snapshot()
        operation = dict(operation='remove', operation_id='op-r-1', revision=7,
                         index=1, name='test/b')
        pending = [dict(type='localize', operation='remove', operation_id='op-r-1', revision=7)]

        class Workspace:
            pass

        with patch('workstation_localize_crud._inputs', return_value=snapshot), \
             patch('workstation_localize_crud.operations', return_value=[operation]):
            plan = plan_localize_crud(Workspace(), 'zone', pending)
        self.assertEqual(plan['rows_removed'], 1)
        self.assertEqual(plan['final_xasset_count'], len(native) - 1)


if __name__ == '__main__':
    unittest.main()
