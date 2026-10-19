from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from workstation_luafile_operations import _build_interval_index
from workstation_scriptfile_crud import _mapped_callback_target


class ScriptfileTemporalAliasAuditTests(unittest.TestCase):
    def test_reused_scratch_fields_keep_distinct_callback_targets(self):
        first, second = (5 << 32) | 101, (5 << 32) | 201
        body = struct.pack("<QQ", first, second)
        spans = [
            dict(owner=3, stream=1, start=0, end=8, archive=0, sequence=10),
            dict(owner=3, stream=1, start=0, end=8, archive=8, sequence=20),
        ]
        index = _build_interval_index(spans)
        targets = {(3, 1, 0, 0): 116, (3, 1, 0, 8): 216}
        field = dict(stream=1, offset=0)
        self.assertEqual(_mapped_callback_target(targets, 3,
            dict(field=field, sequence=11, raw=first), body, spans, index), 116)
        self.assertEqual(_mapped_callback_target(targets, 3,
            dict(field=field, sequence=21, raw=second), body, spans, index), 216)
        with self.assertRaisesRegex(ValueError, "token differs"):
            _mapped_callback_target(targets, 3,
                dict(field=field, sequence=21, raw=first), body, spans, index)


if __name__ == "__main__":
    unittest.main()
