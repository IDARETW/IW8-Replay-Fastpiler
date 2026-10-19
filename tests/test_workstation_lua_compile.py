from pathlib import Path
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import workstation_lua_compile as compiler


class CanonicalLuaCompilerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.acts = self.root / "acts.exe"
        self.replay = self.root / "replay.exe"
        self.profile = self.root / "replay120_lua_native.json"
        for path in (self.acts, self.replay, self.profile, self.root / "acts-common.dll"):
            path.write_bytes(b"fixture")
        self.native_profile = {"__provenance": {
            "image_sha256": compiler.REPLAY_LUA_IMAGE_SHA256,
            "bindings": {name: {"rva": 1, "function_id": name} for name in
                         ("lua_newstate", "lua_loadx", "lj_cf_string_dump", "writer_buf", "lua_pushboolean")}}}
        # One length-delimited prototype and the LuaJIT end marker. The codec's
        # structural check suffices here; real VM acceptance is a native test.
        self.chunk = b"\x1bLJ\x02\x0a\x04\0\0\0\0\0"

    def invoke(self, output, *, strip=False, mutate=False):
        self.command = None
        def run(command, **kwargs):
            self.command = command
            (Path(kwargs["cwd"]) / command[5]).write_bytes(output)
            if mutate:
                self.acts.write_bytes(b"changed compiler")
            return SimpleNamespace(returncode=0, stdout="native exact-byte reload passed", stderr="")
        with patch.object(compiler, "load_or_build_profile", return_value=(self.profile, self.native_profile)), \
             patch.object(compiler.subprocess, "run", side_effect=run):
            return compiler.compile_luajit_source_with_receipt(
                "return 1", acts_exe=self.acts, replay_executable=self.replay,
                profile_path=self.profile, asset_name="safe_name", strip=strip)

    def test_canonical_payload_is_returned_without_modification(self):
        payload, receipt = self.invoke(self.chunk)
        self.assertEqual(payload, self.chunk)
        self.assertEqual(receipt["result"]["native_payload_bytes"], len(self.chunk))
        self.assertEqual(receipt["result"]["native_lua_loadx_reload_bytes"], len(self.chunk))
        self.assertTrue(receipt["result"]["native_lua_loadx_reload_exact_output"])
        self.assertFalse(receipt["result"]["trailing_native_nul"])
        self.assertNotIn("--strip", self.command)
        self.assertEqual(receipt["compiler"]["dump_options"], {"strip": False, "compressed": False})
        self.assertNotIn("lua_pushboolean", receipt["compiler"]["api_bindings"])

    def test_old_compiler_extra_nul_is_rejected_even_with_success_exit(self):
        with self.assertRaisesRegex(ValueError, "after the LuaJIT end marker"):
            self.invoke(self.chunk + b"\0")

    def test_truncated_dump_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            self.invoke(self.chunk[:-1])

    def test_strip_is_a_native_compiler_option(self):
        payload, receipt = self.invoke(self.chunk, strip=True)
        self.assertIn("--strip", self.command)
        self.assertEqual(payload, self.chunk)
        self.assertTrue(receipt["result"]["stripped"])
        self.assertTrue(receipt["compiler"]["dump_options"]["strip"])
        self.assertIn("lua_pushboolean", receipt["compiler"]["api_bindings"])

    def test_tool_mutation_during_compile_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "inputs changed"):
            self.invoke(self.chunk, mutate=True)

    def test_stripped_receipt_staleness_checks_used_boolean_binding(self):
        from workstation_fastfiles import FastfileWorkspace, sha256_file
        import workstation_asset_codecs as codecs
        self.profile.write_text(json.dumps(self.native_profile), encoding="utf-8")
        _, receipt = self.invoke(self.chunk, strip=True)
        receipt["compiler"].update(tool_identity={"fixture": True},
            codec_module_path=str(Path(codecs.__file__).resolve()),
            codec_module_sha256=sha256_file(Path(codecs.__file__)))
        workspace = object.__new__(FastfileWorkspace)
        workspace.lua_acts_path = workspace.acts_path = self.acts
        workspace.replay_executable = self.replay
        with patch("workstation_fastfiles.acts_tool_identity", return_value={"fixture": True}):
            self.assertIsNone(workspace._compiler_identity_staleness({"compiler_receipt": receipt}, 62))
            del receipt["compiler"]["api_bindings"]["lua_pushboolean"]
            self.assertEqual(workspace._compiler_identity_staleness({"compiler_receipt": receipt}, 62),
                             "staged Lua compiler API bindings are stale")


if __name__ == "__main__":
    unittest.main()
