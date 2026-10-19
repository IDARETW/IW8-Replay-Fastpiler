"""Compiler drift must stop dispatch/publication even for engine-only builds."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shutil
import tempfile
import unittest
from unittest import mock

from workstation.compiler_identity import compiler_snapshot, require_compiler_snapshot
from workstation.project import Project


class CompilerIdentityTests(unittest.TestCase):
    def test_frozen_snapshot_detects_nested_change_addition_and_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools/dxbc').mkdir(parents=True)
            path = root / 'tools/dxbc/writer.py'
            path.write_text('VERSION = 1\n')
            frozen = json.loads(json.dumps(compiler_snapshot(root)))
            require_compiler_snapshot(root, frozen)
            path.write_text('VERSION = 2\n')
            with self.assertRaisesRegex(RuntimeError, 'tools/dxbc/writer.py'):
                require_compiler_snapshot(root, frozen)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, 'changed after dispatch'):
                require_compiler_snapshot(root, frozen)
            path.write_text('VERSION = 1\n')
            (root / 'tools/new_helper.py').write_text('VERSION = 1\n')
            with self.assertRaisesRegex(RuntimeError, 'tools/new_helper.py'):
                require_compiler_snapshot(root, frozen)

    def test_static_ui_does_not_change_compiler_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = compiler_snapshot(root)
            (root / 'workstation/web').mkdir(parents=True)
            (root / 'workstation/web/app.js').write_text('const theme = "purple";\n')
            require_compiler_snapshot(root, frozen)

    def test_engine_worker_rejects_queued_compiler_change_before_any_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            source = root / 'tools/link.py'
            source.write_text('VERSION = 1\n')
            paths = dict(tools={}, proxy_source=None)
            with mock.patch('workstation.project.load_paths', return_value=paths), \
                 mock.patch('workstation.project.threading.Thread'):
                project = Project(root, root / 'cache', root / 'game', root / 'db',
                                  codec_environment={})
                job = project.start_build('engine')
                frozen = json.loads((project.jobs_dir / job['id'] /
                                     'compiler-implementation-snapshot.json').read_text())
                self.assertIn('tools/link.py', frozen['files'])
                source.write_text('VERSION = 2\n')
                with mock.patch('workstation.project.subprocess.run') as command:
                    project._build(job)
                    command.assert_not_called()
                result = project.job(job['id'])
                self.assertEqual(result['status'], 'failed')
                self.assertIn('changed after dispatch', result['error'])
                self.assertEqual(result['artifacts'], [])

    def test_engine_worker_does_not_publish_when_helper_changes_during_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'output').mkdir()
            source = root / 'tools/link.py'
            source.write_text('VERSION = 1\n')
            expected_hash = 'a' * 64
            paths = dict(tools={}, proxy_source=None)
            with mock.patch('workstation.project.load_paths', return_value=paths), \
                 mock.patch('workstation.project.threading.Thread'), \
                 mock.patch('workstation.project.digest', return_value=expected_hash):
                project = Project(root, root / 'cache', root / 'game', root / 'db',
                                  codec_environment={})
                job = project.start_build('engine')
                build = root / ('build-workstation-' + job['id'])

                def run_command(arguments, **kwargs):
                    name = Path(arguments[1]).name
                    if name == 'build.py':
                        build.mkdir()
                        (build / 'game_dx12_ship_replay_recompiled.exe').write_bytes(b'fixture-exe')
                        for receipt, payload in (
                            ('build-report.json', {'sha256': expected_hash}),
                            ('verification-report.json', {'sha256': expected_hash, 'unresolved_symbols': 0}),
                            ('relocation-audit.json', {'sha256': expected_hash, 'passed': True}),
                        ):
                            (build / receipt).write_text(json.dumps(payload))
                    elif name == 'verify.py':
                        source.write_text('VERSION = 2\n')
                    return mock.Mock(returncode=0)

                with mock.patch('workstation.project.subprocess.run', side_effect=run_command):
                    project._build(job)
                result = project.job(job['id'])
                self.assertEqual(result['status'], 'failed')
                self.assertIn('tools/link.py', result['error'])
                self.assertEqual(result['artifacts'], [])
                self.assertFalse((root / 'output' / job['id']).exists())

    def test_engine_worker_rechecks_authored_source_after_publication_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'src').mkdir()
            source = root / 'src/main.cpp'
            source.write_text('int main() { return 0; }\n')
            (root / 'tools/link.py').write_text('VERSION = 1\n')
            executable = b'final-copy-race-fixture'
            expected_hash = hashlib.sha256(executable).hexdigest()
            paths = dict(tools={}, proxy_source=None)
            with mock.patch('workstation.project.load_paths', return_value=paths), \
                 mock.patch('workstation.project.threading.Thread'):
                project = Project(root, root / 'cache', root / 'game', root / 'db',
                                  codec_environment={})
                job = project.start_build('engine')
                build = root / ('build-workstation-' + job['id'])

                def run_command(arguments, **kwargs):
                    if Path(arguments[1]).name == 'build.py':
                        build.mkdir()
                        (build / 'game_dx12_ship_replay_recompiled.exe').write_bytes(executable)
                        for receipt, payload in (
                            ('build-report.json', {'sha256': expected_hash}),
                            ('verification-report.json', {'sha256': expected_hash, 'unresolved_symbols': 0}),
                            ('relocation-audit.json', {'sha256': expected_hash, 'passed': True}),
                        ):
                            (build / receipt).write_text(json.dumps(payload))
                    return mock.Mock(returncode=0)

                real_copyfile = shutil.copyfile

                def copy_then_change_source(src, dst, *args, **kwargs):
                    result = real_copyfile(src, dst, *args, **kwargs)
                    if Path(dst).name == 'game_dx12_ship_replay.exe':
                        source.write_text('int main() { return 1; }\n')
                    return result

                with mock.patch('workstation.project.subprocess.run', side_effect=run_command), \
                     mock.patch('workstation.project.shutil.copyfile', side_effect=copy_then_change_source):
                    project._build(job)
                result = project.job(job['id'])
                self.assertEqual(result['status'], 'failed')
                self.assertIn('changed before publication: src/main.cpp', result['error'])
                self.assertEqual(result['artifacts'], [])
                self.assertFalse((root / 'output' / job['id']).exists())

    def test_current_worker_rejects_source_changed_before_compile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'tools').mkdir()
            source = root / 'src/main.cpp'
            source.write_text('int main() { return 0; }\n')
            paths = dict(tools={}, proxy_source=None)
            def change_source(_replacements):
                source.write_text('int main() { return 1; }\n')
            with mock.patch('workstation.project.load_paths', return_value=paths), \
                 mock.patch('workstation.project.threading.Thread'), \
                 mock.patch('workstation.project.require_unique_replacements', side_effect=change_source):
                project = Project(root, root / 'cache', root / 'game', root / 'db', codec_environment={})
                job = project.start_build('current')
                project._build(job)
                result = project.job(job['id'])
                self.assertEqual(result['status'], 'failed')
                self.assertIn('changed during asset packaging: src/main.cpp', result['error'])

    def test_first_engine_publication_creates_output_parent_after_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'src').mkdir()
            (root / 'src/UPPER.CPP').write_text('int main() { return 0; }\n')
            (root / 'tools/link.py').write_text('VERSION = 1\n')
            executable = b'fresh-workspace-verified-executable'
            expected_hash = hashlib.sha256(executable).hexdigest()
            paths = dict(tools={}, proxy_source=None)
            phases = []
            with mock.patch('workstation.project.load_paths', return_value=paths), \
                 mock.patch('workstation.project.threading.Thread'):
                project = Project(root, root / 'cache', root / 'game', root / 'db',
                                  codec_environment={})
                job = project.start_build('engine')
                build = root / ('build-workstation-' + job['id'])

                def run_command(arguments, **kwargs):
                    name = Path(arguments[1]).name
                    phases.append(name)
                    self.assertFalse((root / 'output').exists())
                    if name == 'build.py':
                        build.mkdir()
                        (build / 'game_dx12_ship_replay_recompiled.exe').write_bytes(executable)
                        for receipt, payload in (
                            ('build-report.json', {'sha256': expected_hash}),
                            ('verification-report.json', {'sha256': expected_hash, 'unresolved_symbols': 0}),
                            ('relocation-audit.json', {'sha256': expected_hash, 'passed': True}),
                        ):
                            (build / receipt).write_text(json.dumps(payload))
                    return mock.Mock(returncode=0)

                with mock.patch('workstation.project.subprocess.run', side_effect=run_command):
                    project._build(job)
                result = project.job(job['id'])
                self.assertEqual(result['status'], 'succeeded', result.get('error'))
                self.assertEqual(len(phases), 4)
                self.assertEqual(phases[-1], 'source_provenance.py')
                published = root / 'output' / job['id']
                self.assertEqual([path.name for path in published.iterdir()],
                                 ['game_dx12_ship_replay.exe'])
                self.assertEqual((published / 'game_dx12_ship_replay.exe').read_bytes(), executable)
                self.assertEqual(result['artifacts'][0]['sha256'], expected_hash)
                self.assertFalse((build / 'publication').exists())

    def test_engine_worker_rejects_new_mapping_file_during_publication_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'tools/link.py').write_text('VERSION = 1\n')
            executable = b'mapping-addition-race-fixture'
            expected_hash = hashlib.sha256(executable).hexdigest()
            paths = dict(tools={}, proxy_source=None)
            with mock.patch('workstation.project.load_paths', return_value=paths), \
                 mock.patch('workstation.project.threading.Thread'):
                project = Project(root, root / 'cache', root / 'game', root / 'db',
                                  codec_environment={})
                job = project.start_build('engine')
                build = root / ('build-workstation-' + job['id'])

                def run_command(arguments, **kwargs):
                    if Path(arguments[1]).name == 'build.py':
                        build.mkdir()
                        (build / 'game_dx12_ship_replay_recompiled.exe').write_bytes(executable)
                        for receipt, payload in (
                            ('build-report.json', {'sha256': expected_hash}),
                            ('verification-report.json', {'sha256': expected_hash, 'unresolved_symbols': 0}),
                            ('relocation-audit.json', {'sha256': expected_hash, 'passed': True}),
                        ):
                            (build / receipt).write_text(json.dumps(payload))
                    return mock.Mock(returncode=0)

                real_copyfile = shutil.copyfile

                def copy_then_add_mapping(src, dst, *args, **kwargs):
                    result = real_copyfile(src, dst, *args, **kwargs)
                    if Path(dst).name == 'game_dx12_ship_replay.exe':
                        (root / 'source-workstation').mkdir()
                        (root / 'source-workstation/units.json').write_text('{}\n')
                    return result

                with mock.patch('workstation.project.subprocess.run', side_effect=run_command), \
                     mock.patch('workstation.project.shutil.copyfile', side_effect=copy_then_add_mapping):
                    project._build(job)
                result = project.job(job['id'])
                self.assertEqual(result['status'], 'failed')
                self.assertIn('Compiler mapping file set changed before publication', result['error'])
                self.assertEqual(result['artifacts'], [])
                self.assertFalse((root / 'output' / job['id']).exists())


if __name__ == '__main__':
    unittest.main()
