from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from tools.workstation_mixed_script_luafile import _shift_serialized_offset


ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "evidence" / "workstation-mixed-prototype" / \
    "native-proof" / "code_post_gfx-mixed-relocation.json"


class MixedScriptLuaRelocationTests(unittest.TestCase):
    def test_archive_cursor_rebase_respects_edit_boundaries(self):
        splices = [dict(bytecode_archive_offset=100, old_bytecode_bytes=50,
                        physical_extent_delta=-30)]
        self.assertEqual(_shift_serialized_offset(99, splices), 99)
        with self.assertRaisesRegex(ValueError, "intersects"):
            _shift_serialized_offset(100, splices)
        with self.assertRaisesRegex(ValueError, "intersects"):
            _shift_serialized_offset(149, splices)
        self.assertEqual(_shift_serialized_offset(150, splices), 120)
        self.assertEqual(_shift_serialized_offset(151, splices), 121)

    def test_real_mixed_stream5_stream6_transaction_passed_native_reader(self):
        if not PROOF.is_file():
            self.skipTest("mixed ScriptFile/LuaFile Replay proof is not installed")
        proof = json.loads(PROOF.read_text(encoding="utf-8"))
        self.assertEqual(proof["status"], "native-full-zone-mixed-scriptfile-luafile-pass")
        relocation = proof["relocation"]
        self.assertEqual(relocation["status"], "mixed-scriptfile-luafile-relocation-ready")
        self.assertEqual(relocation["scriptfile_proof"]["stream6_extent_delta"], -29)
        self.assertEqual(relocation["scriptfile_proof"]["new_stream6_high_water"], 50)
        self.assertEqual(relocation["luafile_proof"]["stream5_extent_delta"], 416)
        self.assertEqual(relocation["luafile_proof"]["packed_stream5_tag5_absolute_validated"], 383702)
        self.assertEqual(relocation["luafile_proof"]["packed_stream5_tag15_asset_relative_validated"], 54741)
        self.assertEqual(relocation["luafile_proof"]["packed_stream5_aliases_rebased"], 12)
        self.assertEqual(relocation["pointer_contracts"]["stream6_packed_targets"], 0)
        self.assertEqual(len(relocation["stream_reservation_sizes"]), 11)
        reader = proof["native_reader"]
        self.assertEqual(reader["complete"], True)
        self.assertEqual(reader["success"], True)
        self.assertEqual(reader["tested"], 6012)
        self.assertEqual(reader["failed"], 0)
        self.assertEqual(reader["unavailable"], 0)
        self.assertEqual(reader["serialized_bytes_read"], proof["edited_body"]["bytes"])


if __name__ == "__main__":
    unittest.main()
