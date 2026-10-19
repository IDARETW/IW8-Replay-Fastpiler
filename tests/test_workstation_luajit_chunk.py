from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_luajit_chunk import split_luajit_file_payload


class LuaJitChunkBoundaryTests(unittest.TestCase):
    def test_lua_file_chunk_ending_at_zero_block_marker_is_not_stripped(self):
        path = ROOT / "scratch/autonomous-localplay-v2/native-payload-with-terminator.bin"
        if not path.is_file():
            self.skipTest("captured stock menu LuaFile payload is not present")
        payload = path.read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         "b6741bfb7ccbd76829529fb71afd092962e3341b6ea8925cd0b8f2223339cd88")
        parsed = split_luajit_file_payload(payload)
        self.assertEqual(parsed.chunk, payload)
        self.assertFalse(parsed.trailing_native_nul)
        self.assertTrue(parsed.stripped)
        self.assertEqual(parsed.prototype_count, 26)

    def test_acts_payload_drops_only_nul_after_structural_chunk_end(self):
        path = ROOT / "evidence/workstation-lua-native-compile/tiny-validated.luac"
        if not path.is_file():
            self.skipTest("ACTS-compiled Replay Lua fixture is not present")
        payload = path.read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         "15e238a8e4cde81cba82a3ef1de3f1820956b57b1f840ab26a693869fd131e6e")
        parsed = split_luajit_file_payload(payload)
        self.assertTrue(parsed.trailing_native_nul)
        self.assertEqual(parsed.chunk, payload[:-1])
        self.assertFalse(parsed.stripped)
        self.assertEqual(parsed.prototype_count, 2)

    def test_rejects_nonzero_bytes_after_the_chunk_end_marker(self):
        path = ROOT / "evidence/workstation-lua-native-compile/tiny-validated.luac"
        if not path.is_file():
            self.skipTest("ACTS-compiled Replay Lua fixture is not present")
        payload = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "after the LuaJIT end marker"):
            split_luajit_file_payload(payload + b"x")

    def test_decompiler_accepts_each_fixture_only_after_structural_split(self):
        from workstation_asset_codecs import decompile_luajit_bytecode

        fixtures = [
            ROOT / "scratch/autonomous-localplay-v2/native-payload-with-terminator.bin",
            ROOT / "evidence/workstation-lua-native-compile/tiny-validated.luac",
        ]
        if any(not path.is_file() for path in fixtures):
            self.skipTest("pinned stock and ACTS Lua fixtures are not both present")
        stock = split_luajit_file_payload(fixtures[0].read_bytes())
        acts = split_luajit_file_payload(fixtures[1].read_bytes())
        stock_source = decompile_luajit_bytecode(stock.chunk, name="mainmenuoffline")
        acts_source = decompile_luajit_bytecode(acts.chunk, name="tiny-validated")
        self.assertIn("local function var_0_4", stock_source)
        historical = ROOT / "evidence/workstation-luafile-decompiled-all/ui/frontend/mainmenuoffline.lua.363.lua"
        if historical.is_file():
            self.assertEqual(stock_source.encode("utf-8"),
                             historical.read_text(encoding="utf-8").encode("utf-8"))
        self.assertTrue(acts_source.strip())
        with self.assertRaisesRegex(ValueError, "truncated or oversized ULEB128"):
            decompile_luajit_bytecode(stock.chunk[:-1], name="mainmenuoffline-truncated")

    def test_decompiler_receives_structural_chunk_without_optional_file_nul(self):
        from workstation_asset_codecs import decompile_luajit_bytecode
        from workstation_luajit_chunk import split_luajit_file_payload

        fixture = ROOT / "scratch/autonomous-localplay-v2/native-payload-with-terminator.bin"
        if not fixture.is_file():
            self.skipTest("captured stock menu LuaFile payload is not present")
        payload = fixture.read_bytes()
        boundary = split_luajit_file_payload(payload)
        self.assertFalse(boundary.trailing_native_nul)
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "fake-decompiler.exe"
            fake.write_bytes(b"test executable placeholder")
            observed = {}

            def run(args, **kwargs):
                source = Path(args[1]).read_bytes()
                observed["bytes"] = source
                output_dir = Path(args[args.index("-o") + 1])
                (output_dir / "source.lua").write_text("return true\n", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch("workstation_asset_codecs.subprocess.run", side_effect=run):
                source = decompile_luajit_bytecode(payload, name="ui/frontend/mainmenuoffline.lua",
                                                   decompiler=fake)
            self.assertEqual(source, "return true\n")
            self.assertEqual(observed["bytes"], boundary.chunk)


if __name__ == "__main__":
    unittest.main()
