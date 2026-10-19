from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from repack_workstation_scriptfiles import validate_scriptfile_native_identity
from workstation_fastfiles import ordered_asset_identity_sha256


class ScriptFilePublicationIdentityTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"type_id": 11, "name": "material/retained"},
            {"type_id": 52, "name": "scripts/edited.gsc"},
            {"type_id": 19, "name": "image/retained"},
        ]
        self.walk = {
            "walk_key": "1" * 64,
            "manifest_sha256": "2" * 64,
            "stream_trace_sha256": "3" * 64,
            "journal_sha256": "4" * 64,
        }
        self.span = {
            "native_walk_key": self.walk["walk_key"],
            "native_manifest_sha256": self.walk["manifest_sha256"],
            "stream_trace_sha256": self.walk["stream_trace_sha256"],
        }

    def test_accepts_exact_complete_source_identity(self):
        proof = validate_scriptfile_native_identity(
            self.span, self.walk, self.rows,
            {"journal_asset_identity_sha256": ordered_asset_identity_sha256(self.rows)})
        self.assertEqual(proof["source_journal_sha256"], self.walk["journal_sha256"])
        self.assertEqual(proof["ordered_asset_identity_sha256"],
                         ordered_asset_identity_sha256(self.rows))

    def test_rejects_retained_name_corruption_despite_valid_counts_types_and_eof(self):
        corrupted = [dict(row) for row in self.rows]
        corrupted[0]["name"] += "_corrupt_suffix"
        # These native facts deliberately remain valid. The name identity is
        # the additional publication gate that counts/type order cannot prove.
        output_native = {
            "manifest": {"complete": True, "success": True, "tested": 3,
                         "top_level_index": 3, "failed": 0, "unavailable": 0,
                         "serialized_bytes_read": 4096},
            "journal_asset_identity_sha256": ordered_asset_identity_sha256(corrupted),
        }
        with self.assertRaisesRegex(ValueError, "type/order/name identity"):
            validate_scriptfile_native_identity(
                self.span, self.walk, self.rows, output_native)

    def test_rejects_span_report_from_another_native_walk(self):
        stale = dict(self.span, native_manifest_sha256="9" * 64)
        with self.assertRaisesRegex(ValueError, "hash-validated source walk"):
            validate_scriptfile_native_identity(
                stale, self.walk, self.rows,
                {"journal_asset_identity_sha256": ordered_asset_identity_sha256(self.rows)})


if __name__ == "__main__":
    unittest.main()
