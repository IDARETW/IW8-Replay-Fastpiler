"""Clean preparation must pin the image, reference and analysis seed bytes."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from prepare_workstation import prepare, digest, REQUIRED_PROXY_BINDING_NAMES, validate_proxy_pattern_seed


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.game = self.root / 'owner-game'
        self.game.mkdir()
        self.executable = self.game / 'game_dx12_ship_replay.exe'
        self.executable.write_bytes(b'owner-provided executable fixture')
        self.database = self.game / 'reference.sqlite'
        md5 = hashlib.md5(self.executable.read_bytes()).digest()
        with closing(sqlite3.connect(self.database)) as db:
            db.execute('CREATE TABLE program (md5sum)')
            db.execute('INSERT INTO program VALUES (?)', (md5,))
            db.commit()
        self.seed_root = self.root / 'analysis/replay120'
        self.seed_root.mkdir(parents=True)
        self.seed_file = self.seed_root / 'boundaries.bin'
        self.seed_file.write_bytes(b'analysis fixture')
        seed = {'schema': 1, 'profile': 'test', 'image_sha256': digest(self.executable),
                'image_md5': md5.hex(), 'files': {'boundaries.bin': digest(self.seed_file)}}
        (self.seed_root / 'seed.json').write_text(json.dumps(seed))

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_prepare_then_reuse_with_binary_sqlite_identity(self):
        result = prepare(self.root, self.game, self.database, recover=False)
        self.assertFalse(result['recovered'])
        self.assertEqual((self.root / 'generated/boundaries.bin').read_bytes(), self.seed_file.read_bytes())
        self.assertEqual(prepare(self.root, self.game, self.database, recover=False), result)

    def test_wrong_image_rejected_before_preparing_outputs(self):
        self.executable.write_bytes(b'wrong build')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            prepare(self.root, self.game, self.database, recover=False)
        self.assertFalse((self.root / 'generated').exists())

    def test_seed_corruption_and_existing_changed_analysis_are_preserved(self):
        self.seed_file.write_bytes(b'bad seed')
        with self.assertRaisesRegex(ValueError, 'seed hash mismatch'):
            prepare(self.root, self.game, self.database, recover=False)
        self.assertFalse((self.root / 'generated/boundaries.bin').exists())
        self.seed_file.write_bytes(b'analysis fixture')
        target = self.root / 'generated/boundaries.bin'
        target.write_bytes(b'owner edited analysis')
        with self.assertRaisesRegex(ValueError, 'Existing analysis input differs'):
            prepare(self.root, self.game, self.database, recover=False)
        self.assertEqual(target.read_bytes(), b'owner edited analysis')

    def test_selected_proxy_source_is_passed_to_recovery_and_full_seed_is_required(self):
        proxy = self.root / 'owner-proxy'
        proxy.mkdir()
        (proxy / 'proxy.cpp').write_text('int owner_proxy;\n')
        calls = []

        def run(command, *, cwd, check, env):
            calls.append((command, env.copy()))
            generated = self.root / 'generated'
            generated.mkdir(exist_ok=True)
            if Path(command[1]).name == 'recover.py':
                (generated / 'manifest.json').write_text('{}\n')
            else:
                (generated / 'proxy-patterns.json').write_text(
                    json.dumps([{'name': name} for name in sorted(REQUIRED_PROXY_BINDING_NAMES)]))

        with mock.patch('prepare_workstation.subprocess.run', side_effect=run):
            result = prepare(self.root, self.game, self.database, recover=True, proxy_source=proxy)
        self.assertEqual(result['proxy_source'], str(proxy.resolve()))
        self.assertEqual(result['proxy_bindings']['required_binding_count'], 10)
        self.assertEqual(len(calls), 2)
        for _, env in calls:
            self.assertEqual(env['REPLAY_PROXY_SOURCE'], str(proxy.resolve()))

    def test_selected_proxy_source_rejects_incomplete_generated_seed(self):
        seed = self.root / 'proxy-patterns.json'
        seed.write_text(json.dumps([{'name': 'engine_baseline'}]))
        with self.assertRaisesRegex(ValueError, 'missing required Replay bindings'):
            validate_proxy_pattern_seed(seed)

    def test_selected_proxy_source_must_exist_and_have_sources(self):
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            prepare(self.root, self.game, self.database, recover=False,
                    proxy_source=self.root / 'missing-proxy')
        empty = self.root / 'empty-proxy'
        empty.mkdir()
        with self.assertRaisesRegex(ValueError, r'no top-level C\+\+ sources'):
            prepare(self.root, self.game, self.database, recover=False, proxy_source=empty)


if __name__ == '__main__':
    unittest.main()
