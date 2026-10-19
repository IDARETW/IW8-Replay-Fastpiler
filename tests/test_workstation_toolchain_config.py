import hashlib
from pathlib import Path
import tempfile
import unittest
import json

from workstation.toolchain import resolve_codec_environment


class ToolchainConfigurationTests(unittest.TestCase):
    def test_native_image_writer_source_is_explicit_and_has_expected_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            zone = root / 'authoring'
            zone.mkdir()
            with self.assertRaisesRegex(ValueError, 'lacks the native IW8 writer'):
                resolve_codec_environment(root, root, tools={'zonetool_source': 'authoring'}, environment={})
            source = zone / 'src/zonetool/iw8/iw8_zone.cpp'
            source.parent.mkdir(parents=True)
            source.write_text('// test source')
            selected = resolve_codec_environment(root, root,
                tools={'zonetool_source': 'authoring'}, environment={})
            self.assertEqual(selected['REPLAY_ZONETOOL_SOURCE'], str(zone.resolve()))

    def test_relative_tool_and_explicit_environment_override_are_bound_to_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / 'first.exe', root / 'second.exe'
            first.write_bytes(b'first'); second.write_bytes(b'second')
            wanted = hashlib.sha256(first.read_bytes()).hexdigest()
            tools = {'luajit_decompiler': {'path': 'first.exe', 'sha256': wanted}}
            value = resolve_codec_environment(root, root / 'game', tools=tools, environment={})
            self.assertEqual(value['REPLAY_LUAJIT_DECOMPILER'], str(first))
            second_sha = hashlib.sha256(second.read_bytes()).hexdigest()
            value = resolve_codec_environment(root, root / 'game', tools=tools, environment={
                'REPLAY_LUAJIT_DECOMPILER': str(second), 'REPLAY_LUAJIT_DECOMPILER_SHA256': second_sha})
            self.assertEqual(value['REPLAY_LUAJIT_DECOMPILER_SHA256'], second_sha)
            first.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                resolve_codec_environment(root, root / 'game', tools=tools, environment={})

    def test_missing_and_unknown_tools_fail_before_server_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                resolve_codec_environment(root, root, tools={'dxbc': 'missing.exe'}, environment={})
            with self.assertRaises(ValueError):
                resolve_codec_environment(root, root, tools={'manual_rva': '0x1000'}, environment={})

    def test_owner_pack_and_transform_checkout_propagate_without_manual_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / 'owner-pack.json'
            pack.write_bytes(b'{}')
            checkout = root / 'transform'
            checkout.mkdir()
            value = resolve_codec_environment(root, root, tools={
                'script_source_pack': {'path': pack.name, 'sha256': hashlib.sha256(b'{}').hexdigest()},
                'script_string_decryptor': {'path': checkout.name}}, environment={})
            self.assertEqual(value['REPLAY_SCRIPT_SOURCE_PACK'], str(pack))
            self.assertEqual(value['REPLAY_SCRIPT_STRING_DECRYPTOR'], str(checkout))
            from workstation.toolchain import apply_codec_environment
            import os
            from unittest.mock import patch
            with patch.dict(os.environ, {}, clear=True):
                apply_codec_environment(value)
                self.assertEqual(os.environ['REPLAY_SCRIPT_SOURCE_PACK'], str(pack))
            with self.assertRaisesRegex(ValueError, 'bootstrap manifest'):
                resolve_codec_environment(root, root, tools={'script_string_decryptor': {
                    'path': checkout.name, 'sha256': '0' * 64}}, environment={})

    def test_lua_compiler_can_be_separate_from_native_fastfile_reader(self):
        from workstation.config import load_paths
        from workstation.toolchain import apply_codec_environment
        from unittest.mock import patch
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = root / 'reader-acts.exe'; reader.write_bytes(b'native reader')
            lua = root / 'lua-acts.exe'; lua.write_bytes(b'lua compiler')
            document = {'schema': 1, 'acts': str(reader), 'lua_acts': str(lua)}
            (root / 'replay-project.local.json').write_text(json.dumps(document), encoding='utf-8')
            paths = load_paths(root)
            self.assertEqual(paths['acts'], reader)
            self.assertEqual(paths['lua_acts'], lua)
            environment = resolve_codec_environment(root, root / 'game', paths['acts'],
                tools={}, environment={}, lua_acts=paths['lua_acts'])
            self.assertEqual(environment['REPLAY_ACTS'], str(reader))
            self.assertEqual(environment['REPLAY_ACTS_PROFILE'],
                             str(reader.with_name('replay120_lua_native.json')))
            self.assertEqual(environment['REPLAY_LUA_ACTS'], str(lua))
            self.assertEqual(environment['REPLAY_LUA_ACTS_PROFILE'],
                             str(lua.with_name('replay120_lua_native.json')))
            with patch.dict(os.environ, {}, clear=True):
                apply_codec_environment(environment)
                self.assertEqual(os.environ['REPLAY_ACTS'], str(reader))
                self.assertEqual(os.environ['REPLAY_LUA_ACTS'], str(lua))

    def test_selected_proxy_source_survives_config_and_worker_environment(self):
        from workstation.config import load_paths
        from workstation.toolchain import apply_codec_environment
        from unittest.mock import patch
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proxy = root / 'owner-proxy'; proxy.mkdir()
            (proxy / 'binding.cpp').write_text('source-derived binding fixture')
            (root / 'replay-project.local.json').write_text(json.dumps(
                {'schema': 1, 'proxy_source': 'owner-proxy'}))
            configuration = load_paths(root)
            self.assertEqual(configuration['proxy_source'], proxy)
            environment = resolve_codec_environment(root, root, environment={},
                                                    proxy_source=configuration['proxy_source'])
            worker_snapshot = json.loads(json.dumps(environment))
            with patch.dict(os.environ, {}, clear=True):
                apply_codec_environment(worker_snapshot)
                self.assertEqual(os.environ['REPLAY_PROXY_SOURCE'], str(proxy))
            with self.assertRaisesRegex(ValueError, 'proxy source'):
                resolve_codec_environment(root, root, environment={}, proxy_source='missing')


if __name__ == '__main__':
    unittest.main()
