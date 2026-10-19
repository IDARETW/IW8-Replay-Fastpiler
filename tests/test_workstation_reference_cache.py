"""Reader evidence stays raw while table-index lookups include references."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from tools.workstation_fastfiles import (
    FastfileWorkspace, ZoneBody, _read_native_rows, _validate_native_walk_receipt,
    sha256_file, validate_native_walk_artifacts,
)
import workstation_native_references
from tests.test_workstation_native_references import _fixture


class NativeReferenceCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.walk = self.root / "native-walk" / "walk"
        self.native = self.walk / "native"
        self.native.mkdir(parents=True)
        data, events = _fixture()
        self.body = ZoneBody.parse(data)
        (self.root / "body.dec").write_bytes(data)
        trace = self.native / "stream-trace.jsonl"
        trace.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        self.raw_manifest = dict(profile="replay-1.20", xfile_version=4087,
            complete=True, success=True, failed=0, unavailable=0, tested=1,
            top_level_index=2, serialized_bytes_read=len(data))
        self.raw_rows = [{"type_id": self.body.assets[1].type_id, "type": "other", "name": "ordinary"}]
        self.inventory = workstation_native_references.normalize_native_inventory(
            data, trace, self.raw_manifest, self.raw_rows)
        self.manifest = dict(self.raw_manifest,
                             reference_only_rows=self.inventory["reference_only_rows"])
        self._json("manifest.json", self.raw_manifest)
        self._json("manifest-reference-accounted.json", self.manifest)
        self._json("normalized-inventory.json", self.inventory)
        (self.native / "assets.jsonl").write_text(json.dumps(self.raw_rows[0]) + "\n", encoding="utf-8")
        self.receipt = dict(status="native-zone-reader-pass", walk_key="walk",
            decoded_body_sha256=self.body.source_sha256, xasset_count=2,
            source_relative_path="sample.ff", identity={"source_name": "sample.ff"},
            manifest_relative_path="native/manifest-reference-accounted.json",
            raw_manifest_relative_path="native/manifest.json",
            journal_relative_path="native/assets.jsonl",
            normalized_inventory_relative_path="native/normalized-inventory.json",
            stream_trace_enabled=True, stream_trace_relative_path="native/stream-trace.jsonl",
            stream_trace_bytes=trace.stat().st_size,
            inventory_normalizer_sha256=sha256_file(Path(workstation_native_references.__file__)))
        self._save_receipt()

    def _json(self, name, value):
        (self.native / name).write_text(json.dumps(value), encoding="utf-8")

    def _save_receipt(self):
        for key, name in (("manifest", "manifest-reference-accounted.json"),
                          ("raw_manifest", "manifest.json"), ("journal", "assets.jsonl"),
                          ("normalized_inventory", "normalized-inventory.json"),
                          ("stream_trace", "stream-trace.jsonl")):
            self.receipt[key + "_sha256"] = sha256_file(self.native / name)
        (self.walk / "native-walk-receipt.json").write_text(json.dumps(self.receipt), encoding="utf-8")

    def validate(self):
        return _validate_native_walk_receipt(self.walk, "walk", self.body, Path("sample.ff"))

    def test_table_lookup_includes_reference_without_rewriting_raw_counts_or_journal(self):
        raw_manifest = (self.native / "manifest.json").read_bytes()
        raw_journal = (self.native / "assets.jsonl").read_bytes()
        self.validate()
        receipt, rows = _read_native_rows(self.root, self.body, require_trace=True)
        self.assertEqual([row["name"] for row in rows], [",external", "ordinary"])
        self.assertEqual(rows[1]["index"], 1)
        self.assertEqual(receipt["xasset_count"], 2)
        self.assertEqual((self.native / "manifest.json").read_bytes(), raw_manifest)
        self.assertEqual((self.native / "assets.jsonl").read_bytes(), raw_journal)
        self.assertEqual(self.manifest["tested"], 1)

    def test_normalized_retained_name_cannot_diverge_from_raw_journal(self):
        self.inventory["normalized_rows"][1]["name"] = "substituted"
        self._json("normalized-inventory.json", self.inventory)
        self._save_receipt()
        with self.assertRaisesRegex(ValueError, "changed a raw tested row"):
            self.validate()

    def test_reference_name_must_match_serialized_body(self):
        for row in (self.inventory["normalized_rows"][0], self.inventory["reference_only_rows"][0],
                    self.manifest["reference_only_rows"][0]):
            row["name"] = ",wrongref"
        self._json("normalized-inventory.json", self.inventory)
        self._json("manifest-reference-accounted.json", self.manifest)
        self._save_receipt()
        with self.assertRaisesRegex(ValueError, "exact serialized bytes"):
            self.validate()

    def test_count_rewriting_is_rejected(self):
        self.manifest["tested"] = 2
        self._json("manifest-reference-accounted.json", self.manifest)
        self._save_receipt()
        with self.assertRaisesRegex(ValueError, "raw walk evidence"):
            self.validate()

    def test_normalizer_drift_invalidates_cached_inventory(self):
        self.receipt["inventory_normalizer_sha256"] = "0" * 64
        self._save_receipt()
        with self.assertRaisesRegex(ValueError, "implementation or trace"):
            self.validate()

    def test_duplicate_and_boolean_reference_indices_are_rejected(self):
        for refs in ([self.manifest["reference_only_rows"][0]] * 2,
                     [dict(self.manifest["reference_only_rows"][0], index=False)]):
            with self.subTest(refs=refs), self.assertRaisesRegex(ValueError, "exact table identity"):
                validate_native_walk_artifacts(dict(self.manifest, reference_only_rows=refs),
                                               self.inventory["normalized_rows"], self.body)

    def test_reference_detail_is_read_only(self):
        workspace = object.__new__(FastfileWorkspace)
        snapshot = SimpleNamespace(
            cache_path=self.root,
            decode_receipt={"final_body_relative_path": "body.dec"},
            body=SimpleNamespace(assets=[SimpleNamespace(type_id=19)]),
            native_walk={"walk_key": "fixture"},
            native_rows=[{"status": "reference", "type": "image", "name": "external/image"}],
        )
        with patch.object(workspace, "_validated_asset_snapshot", return_value=snapshot):
            result = workspace.get_asset("a" * 64 + ":0")
        self.assertTrue(result["reference_only"])
        self.assertFalse(result["editable"])
        self.assertFalse(result["archive_writable"])
        self.assertIsNone(result["content"])

    def test_malformed_rows_and_boolean_native_counts_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_native_walk_artifacts(self.manifest, ["bad", {}], self.body)
        for key in ("failed", "unavailable", "tested", "top_level_index"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_native_walk_artifacts(dict(self.manifest, **{key: False}),
                                               self.inventory["normalized_rows"], self.body)


if __name__ == "__main__":
    unittest.main()
