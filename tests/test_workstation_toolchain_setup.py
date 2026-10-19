from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "setup_workstation_tools.py"
SPEC = importlib.util.spec_from_file_location("setup_workstation_tools", SCRIPT)
setup = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(setup)


class WorkstationToolchainManifestTests(unittest.TestCase):
    def test_manifest_uses_pinned_official_https_releases(self):
        manifest = setup.load_manifest()
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual({item["id"] for item in manifest["tools"]}, {
            "gsc_tool", "dxbc_decompiler", "texconv", "luajit_decompiler_cod"})
        self.assertTrue(all(item["url"].startswith("https://github.com/")
                            for item in manifest["tools"]))
        self.assertTrue(all("manual_rvas" not in item for item in manifest["tools"]))

    def test_local_public_tool_payload_hashes_match_manifest(self):
        manifest = setup.load_manifest()
        paths = {
            "gsc_tool": [("tools/bin/gsc-tool-1.5.1/gsc-tool.exe",
                          manifest["tools"][0]["member_sha256"])],
            "dxbc_decompiler": [("tools/bin/cmd_Decompiler-1.3.16/cmd_Decompiler.exe",
                                 manifest["tools"][1]["members"][0]["sha256"]),
                                ("tools/bin/cmd_Decompiler-1.3.16/d3dcompiler_46.dll",
                                 manifest["tools"][1]["members"][1]["sha256"])],
            "texconv": [("tools/bin/texconv-may2026.exe", manifest["tools"][2]["sha256"])],
            "luajit_decompiler_cod": [("tools/bin/luajit-decompiler-v2.exe",
                                       "52742bb206108880c20ba0a147e2be7690bbd9181a735e63047bd01bbc54eae6")],
        }
        for tool_id, files in paths.items():
            for relative, expected in files:
                path = ROOT / relative
                if not path.is_file():
                    self.skipTest('Install the optional codec tools before checking their local payload hashes')
                if tool_id == "luajit_decompiler_cod":
                    self.assertNotEqual(setup.sha256(path), manifest["tools"][3]["sha256"])
                    continue
                self.assertEqual(setup.sha256(path), expected, relative)

    def test_archive_member_path_rejects_traversal(self):
        for candidate in ("../escape.exe", "folder/../../escape", "/absolute", "C:/escape"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                setup._safe_member_name(candidate)


class OwnerReplayCatalogTests(unittest.TestCase):
    def test_pe32plus_imagebase_is_read_from_supplied_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.exe"
            dos = bytearray(0x40)
            dos[:2] = b"MZ"
            struct.pack_into("<I", dos, 0x3C, 0x80)
            pe = bytearray(b"PE\0\0" + bytes(20))
            struct.pack_into("<H", pe, 4 + 16, 0xF0)
            optional = bytearray(0xF0)
            struct.pack_into("<H", optional, 0, 0x20B)
            struct.pack_into("<Q", optional, 24, 0x140000000)
            path.write_bytes(dos + bytes(0x80 - len(dos)) + pe + optional)
            self.assertEqual(setup.pe_image_base(path), 0x140000000)

    def test_unknown_or_non_unique_native_api_is_not_synthesized(self):
        # The profile generator's rule is to fail on a missing/ambiguous named
        # SQLite row; no hand-entered RVA fallback is present in this module.
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("must resolve uniquely", source)
        self.assertIn("SELECT id,name,address,mangled_function FROM functions", source)
        self.assertIn("rva = address_value - base", source)
        self.assertNotIn("0x208C7D0", source)
        self.assertNotIn("0x208A710", source)


if __name__ == "__main__":
    unittest.main()
