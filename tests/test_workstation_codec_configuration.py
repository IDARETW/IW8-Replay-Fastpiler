import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.workstation_asset_codecs import _codec_tool
from tools.workstation_lua_compile import compile_luajit_source_with_receipt


class DynamicCodecConfigurationTests(unittest.TestCase):
    def test_tools_are_selected_after_import_and_explicit_configured_paths_recheck_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, configured = root / 'old.exe', root / 'configured.exe'
            old.write_bytes(b'old'); configured.write_bytes(b'configured')
            with patch.dict(os.environ, {'REPLAY_DXBC_TOOL': str(configured),
                    'REPLAY_DXBC_TOOL_SHA256': hashlib.sha256(configured.read_bytes()).hexdigest()}):
                self.assertEqual(_codec_tool(None, 'REPLAY_DXBC_TOOL', old), configured)
                self.assertEqual(_codec_tool(configured, 'REPLAY_DXBC_TOOL', old), configured)
                configured.write_bytes(b'changed after setup')
                for selected in (None, configured):
                    with self.assertRaisesRegex(ValueError, 'setup receipt'):
                        _codec_tool(selected, 'REPLAY_DXBC_TOOL', old)

    def test_lua_receipt_cannot_name_a_profile_acts_will_not_load(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            acts, replay = root / 'acts.exe', root / 'replay.exe'
            acts.write_bytes(b'fixture'); replay.write_bytes(b'fixture')
            other = root / 'elsewhere'; other.mkdir()
            profile = other / 'replay120_lua_native.json'; profile.write_text('{}')
            with patch('tools.workstation_lua_compile.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError, 'beside the executable'):
                    compile_luajit_source_with_receipt('return 1', acts_exe=acts,
                        replay_executable=replay, profile_path=profile)
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
