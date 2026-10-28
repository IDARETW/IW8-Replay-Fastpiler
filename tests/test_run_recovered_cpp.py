import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
import run_recovered_cpp


class IsolatedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'project';self.game=Path(self.temp.name)/'game'
        self.build=self.root/'build-fixture';self.build.mkdir(parents=True);self.game.mkdir()
        self.exe=self.build/'game_dx12_ship_replay_recompiled.exe';self.exe.write_bytes(b'verified-fixture')
        self.digest=hashlib.sha256(self.exe.read_bytes()).hexdigest()
        (self.build/'build-report.json').write_text(json.dumps({'sha256':self.digest}))
        (self.build/'verification-report.json').write_text(json.dumps({'sha256':self.digest,'windows_sec_image_mapping':True}))
        (self.build/'quality-checks.json').write_text(json.dumps({'sha256':self.digest,'passed':True}))
        for folder in ('players','zone'):
            (self.game/folder).mkdir();(self.game/folder/'sample').write_bytes(b'original')
        (self.game/'library.dll').write_bytes(b'dll-fixture')
        (self.game/'settings.ini').write_text('original=true')
        self.fake=SimpleNamespace(root=self.root,paths={'game':self.game})
        self.proxy=self.root/'owner-proxy.dll';self.proxy.write_bytes(b'verified-proxy')
        self.patches=[patch.object(run_recovered_cpp,'Recovery',return_value=self.fake),
                      patch.object(run_recovered_cpp,'windows_compiler'),
                      patch.object(run_recovered_cpp,'validated_proxy',return_value=self.proxy),
                      patch('source_provenance.validate_report')]
        for item in self.patches:item.start()

    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        # Remove test junctions themselves before cleaning the temporary tree.
        for folder in self.game.glob('replay-compiler-cpp-*'):
            junction=folder/'zone'
            if junction.exists():junction.rmdir()
        self.temp.cleanup()

    def test_private_settings_and_dll_copies_preserve_original_files(self):
        receipt=run_recovered_cpp.stage(self.root,'build-fixture');folder=Path(receipt['folder'])
        (folder/'players/sample').write_bytes(b'changed')
        (folder/'settings.ini').write_text('changed=true')
        (folder/'library.dll').write_bytes(b'changed-dll')
        self.assertEqual((self.game/'players/sample').read_bytes(),b'original')
        self.assertEqual((self.game/'settings.ini').read_text(),'original=true')
        self.assertEqual((self.game/'library.dll').read_bytes(),b'dll-fixture')
        self.assertEqual((folder/'zone/sample').read_bytes(),b'original')
        with self.assertRaisesRegex(ValueError,'DLL changed'):
            run_recovered_cpp.stage(self.root,'build-fixture')

    def test_changed_executable_stops_before_creating_runtime(self):
        self.exe.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'verification'):
            run_recovered_cpp.stage(self.root,'build-fixture')
        self.assertFalse(list(self.game.glob('replay-compiler-cpp-*')))

    def test_changed_compilation_inputs_stop_before_creating_runtime(self):
        with patch('source_provenance.validate_report',side_effect=ValueError('header changed')):
            with self.assertRaisesRegex(ValueError,'header changed'):
                run_recovered_cpp.stage(self.root,'build-fixture')
        self.assertFalse(list(self.game.glob('replay-compiler-cpp-*')))

    def test_failed_or_stale_quality_checks_stop_before_creating_runtime(self):
        for quality in ({'sha256':self.digest,'passed':False},
                        {'sha256':'different-image','passed':True}):
            with self.subTest(quality=quality):
                (self.build/'quality-checks.json').write_text(json.dumps(quality))
                with self.assertRaisesRegex(ValueError,'quality checks'):
                    run_recovered_cpp.stage(self.root,'build-fixture')
                self.assertFalse(list(self.game.glob('replay-compiler-cpp-*')))

    def test_repeat_staging_reuses_verified_executable(self):
        first=run_recovered_cpp.stage(self.root,'build-fixture')
        second=run_recovered_cpp.stage(self.root,'build-fixture')
        self.assertEqual(first,second)
        self.assertEqual(len(list(self.game.glob('replay-compiler-cpp-*'))),1)


if __name__=='__main__':
    unittest.main()
