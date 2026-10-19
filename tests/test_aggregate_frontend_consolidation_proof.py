from __future__ import annotations

import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MODULE_PATH = _HERE / "aggregate_frontend_consolidation_proof.py"
if not _MODULE_PATH.is_file():
    _MODULE_PATH = _HERE.parent / "tools" / "aggregate_frontend_consolidation_proof.py"
_SPEC = importlib.util.spec_from_file_location("aggregate_frontend_consolidation_proof", _MODULE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load the aggregation proof module for focused tests")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
canonical_identity_rows = _MODULE.canonical_identity_rows
validate_normalized_identities = _MODULE.validate_normalized_identities
verified_shader101_output_body_sha256 = _MODULE._verified_shader101_output_body_sha256


class CanonicalInventoryTests(unittest.TestCase):
    def test_rebuild_interleaves_reference_rows_at_exact_indices(self) -> None:
        raw = [
            {"type_id": 3, "name": "first", "status": "inventory"},
            {"type_id": 8, "name": "last", "status": "inventory"},
        ]
        reference = {
            "index": 1,
            "type_id": 11,
            "name": ",material_ref",
            "pointer_token": 0xFFFFFFFFFFFFFFFD,
            "status": "reference",
        }
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "assets.jsonl"
            journal.write_text("".join(json.dumps(row) + "\n" for row in raw), encoding="utf-8")
            rows = canonical_identity_rows(journal, [reference], 3)
        self.assertEqual(rows, [
            {"index": 0, "type_id": 3, "name": "first", "status": "inventory"},
            {"index": 1, "type_id": 11, "name": ",material_ref", "status": "reference"},
            {"index": 2, "type_id": 8, "name": "last", "status": "inventory"},
        ])

    def test_same_count_name_mutation_is_rejected(self) -> None:
        expected = [
            {"index": 0, "type_id": 3, "name": "first", "status": "inventory"},
            {"index": 1, "type_id": 8, "name": "second", "status": "inventory"},
        ]
        changed = [dict(row) for row in expected]
        changed[1]["name"] = "different-but-same-count"
        with self.assertRaisesRegex(ValueError, "row 1"):
            validate_normalized_identities(changed, expected)

    def test_duplicate_or_malformed_reference_slot_is_rejected(self) -> None:
        refs = [
            {"index": 0, "type_id": 11, "name": ",a", "pointer_token": 0xFFFFFFFFFFFFFFFD,
             "status": "reference"},
            {"index": 0, "type_id": 11, "name": ",b", "pointer_token": 0xFFFFFFFFFFFFFFFD,
             "status": "reference"},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "assets.jsonl"
            journal.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                canonical_identity_rows(journal, refs, 1)


class ShaderBodyProofTests(unittest.TestCase):
    def test_output_body_hash_comes_from_verified_native_decode_pin(self) -> None:
        digest = "a" * 64
        shader = {"output": {"body_sha256": digest, "body_bytes": 719985901}}
        pin = (digest, 719985901, {
            "method": "strict-native-iwc-decode",
            "decoded_body_sha256": digest,
            "fastfile_sha256": "b" * 64,
            "patch_sha256": "c" * 64,
        })
        self.assertEqual(verified_shader101_output_body_sha256(shader, pin), digest)

    def test_unbound_or_mismatched_shader_body_hash_is_rejected(self) -> None:
        digest = "a" * 64
        pin = (digest, 10, {
            "method": "strict-native-iwc-decode",
            "decoded_body_sha256": digest,
        })
        with self.assertRaisesRegex(ValueError, "not bound"):
            verified_shader101_output_body_sha256(
                {"output": {"body_sha256": "d" * 64, "body_bytes": 10}}, pin)
        with self.assertRaisesRegex(ValueError, "not bound"):
            verified_shader101_output_body_sha256(
                {"output": {"body_sha256": digest, "body_bytes": 11}}, pin)


if __name__ == "__main__":
    unittest.main()
