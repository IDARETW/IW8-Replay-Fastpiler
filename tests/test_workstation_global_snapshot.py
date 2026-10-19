"""Global initializer files stay bound to the dispatched job snapshot."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from workstation.project import Project


PACKAGE_TOOLS = (
    'workstation_fastfiles.py', 'workstation_asset_codecs.py', 'workstation_lua_compile.py',
    'workstation_trace_index.py', 'verify_replay_lua_native_compile.py',
    'make_replay_lua_acts_profile.py', 'analyze_workstation_asset_spans.py',
    'repack_workstation_scriptfile.py', 'roundtrip_replay_fastfile.py',
    'workstation_luafile.py', 'repack_workstation_luafile.py',
    'repack_workstation_luafile_batch.py', 'workstation_mixed_script_luafile.py',
    'repack_workstation_mixed_script_luafile.py', 'repack_workstation_scriptfiles.py',
    'inspect_frontend_asset_table.py', 'frontend_catalog.py', 'workstation_stringtable.py',
    'workstation_native_asset_edits.py', 'workstation_localize.py',
    'workstation_native_child_relocation.py', 'workstation_shader_growth.py',
    'workstation_shader_identity.py', 'workstation_image_resize.py',
    'workstation_variable_native_edits.py', 'workstation_localize_inventory.py',
    'workstation_localize_crud.py', 'workstation_asset_operations.py',
    'workstation_luafile_operations.py', 'workstation_luafile_crud.py',
    'workstation_luajit_chunk.py', 'workstation_soundbank.py',
    'workstation_sab_drafts.py', 'workstation_sab_editor.py',
    'build_skate_selected_subset.py', 'workstation_skate_subset.py',
    'workstation_zone_merge.py', 'workstation_scriptstring_table.py',
    'build_skate_images.py', 'c3s5_world_image_zone.cpp')


class GlobalInputSnapshotTests(unittest.TestCase):
    def test_edit_add_and_remove_during_asset_packaging_fail_against_dispatch_snapshot(self):
        for change in ('edit', 'add', 'remove'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'src').mkdir()
                (root / 'tools').mkdir()
                (root / 'workstation').mkdir()
                (root / 'src/main.cpp').write_text('int main() { return 0; }\n')
                for name in PACKAGE_TOOLS:
                    (root / 'tools' / name).write_text('# fixture\n')
                (root / 'workstation/soundbanks.py').write_text('# fixture\n')
                (root / 'workstation/skate_packaging.py').write_text('# fixture\n')
                acts = root / 'acts.exe'
                acts.write_bytes(b'fixture reader')
                (root / 'replay120_lua_native.json').write_text('{}\n')
                (root / 'acts-common.dll').write_bytes(b'fixture common')
                globals_dir = root / 'cache/globals'
                globals_dir.mkdir(parents=True)
                initializer = globals_dir / 'sym_initial.json'
                original = b'{"value":1}\n'
                if change in ('edit', 'remove'):
                    initializer.write_bytes(original)
                paths = dict(tools={}, proxy_source=None)

                with mock.patch('workstation.project.load_paths', return_value=paths), \
                     mock.patch('workstation.project.plan_skate_consolidation', return_value={'selected': True}), \
                     mock.patch('workstation.project.require_skate_plan'), \
                     mock.patch('workstation.project.provision_skate_plan', return_value={}), \
                     mock.patch('workstation.project.skate_build_command', return_value=['native-package-fixture']), \
                     mock.patch('workstation.project.skate_replacement_rows', return_value=[]), \
                     mock.patch('workstation.project.threading.Thread'):
                    project = Project(root, root / 'cache', root / 'game', root / 'db',
                                      acts=acts, codec_environment={})
                    job = project.start_build('current')
                    snapshot_path = project.jobs_dir / job['id'] / 'global-input-snapshot.json'
                    snapshot = json.loads(snapshot_path.read_text())
                    expected = ({'sym_initial.json': hashlib.sha256(original).hexdigest()}
                                if change in ('edit', 'remove') else {})
                    self.assertEqual(snapshot, expected)

                    calls = []

                    def package_then_change(arguments, **kwargs):
                        calls.append(list(arguments))
                        if 'native-package-fixture' in arguments:
                            if change == 'edit':
                                initializer.write_bytes(b'{"value":2}\n')
                            elif change == 'add':
                                (globals_dir / 'sym_added.json').write_bytes(b'{"value":3}\n')
                            else:
                                initializer.unlink()
                        return mock.Mock(returncode=0)

                    with mock.patch('workstation.project.subprocess.run', side_effect=package_then_change):
                        project._build(job)

                result = project.job(job['id'])
                self.assertEqual(result['status'], 'failed')
                self.assertIn('Global initializer inputs changed during asset packaging', result['error'])
                self.assertEqual(len(calls), 1)
                self.assertNotIn('build.py', [Path(call[1]).name for call in calls])
                self.assertEqual(result['artifacts'], [])
                self.assertFalse((root / 'output' / job['id']).exists())


if __name__ == '__main__':
    unittest.main()
