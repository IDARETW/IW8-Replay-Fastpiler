from pathlib import Path
import tempfile
import unittest

from workstation.backend_identity import BackendChangedError, BackendSnapshot


class BackendIdentityTests(unittest.TestCase):
    def test_changed_deleted_and_new_python_sources_require_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            path = root / 'tools/codec.py'
            path.write_text('VALUE = 1\n')
            snapshot = BackendSnapshot(root)
            snapshot.require_current()
            path.write_text('VALUE = 2\n')
            with self.assertRaisesRegex(BackendChangedError, 'restart the server'):
                snapshot.require_current()
            path.unlink()
            self.assertEqual(snapshot.status()['changed_files'], ['tools/codec.py'])
            path.write_text('VALUE = 1\n')
            snapshot.require_current()
            (root / 'tools/new_codec.py').write_text('VALUE = 3\n')
            self.assertEqual(snapshot.status()['changed_files'], ['tools/new_codec.py'])

    def test_ui_and_game_source_changes_do_not_invalidate_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'workstation/web').mkdir(parents=True)
            (root / 'src').mkdir()
            snapshot = BackendSnapshot(root)
            (root / 'workstation/web/app.js').write_text('const version = 2;\n')
            (root / 'src/Com_Example.cpp').write_text('int Com_Example() {return 7;}\n')
            snapshot.require_current()

    def test_nested_native_shader_modules_are_included(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools/dxbc').mkdir(parents=True)
            path = root / 'tools/dxbc/replay_draw_tables.py'
            path.write_text('SLOTS = [1, 2]\n')
            snapshot = BackendSnapshot(root)
            path.write_text('SLOTS = [2, 1]\n')
            self.assertEqual(snapshot.status()['changed_files'], ['tools/dxbc/replay_draw_tables.py'])


if __name__ == '__main__':
    unittest.main()
