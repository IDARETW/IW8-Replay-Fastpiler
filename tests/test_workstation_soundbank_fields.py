from __future__ import annotations

import hashlib
import json
import math
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from workstation_soundbank import (ALIAS_SCALAR_FLOAT_OFFSETS, ALIAS_SIZE,
                                   replace_soundbank_alias_scalars,
                                   soundbank_edit_document,
                                   validate_soundbank_edit_document)


def _fixture(*, nonfinite_volume: bool = False):
    raw = bytearray((i * 37 + 11) & 0xff for i in range(ALIAS_SIZE))
    for field, value in (("volMin", 0.25), ("volMax", 1.0),
                         ("pitchMin", 0.8), ("pitchMax", 1.2)):
        struct.pack_into("<f", raw, ALIAS_SCALAR_FLOAT_OFFSETS[field], value)
    if nonfinite_volume:
        struct.pack_into("<I", raw, ALIAS_SCALAR_FLOAT_OFFSETS["volMax"], 0x7fc01234)
    raw = bytes(raw)
    body = bytearray(1024)
    start = 600
    body[start:start + ALIAS_SIZE] = raw
    body = bytes(body)
    alias = {
        "list_index": 0, "list_name": "weapons", "alias_index_in_list": 2,
        "alias_name": "rifle_fire", "asset_file_name": "weapons/rifle_fire.wav",
        "file_id": 0x12345678, "archive_offset": start,
        "scalar_fields": {}, "read_only_scalar_bits": {},
        "scalar_field_offsets": dict(ALIAS_SCALAR_FLOAT_OFFSETS),
        "raw_hex": raw.hex(), "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }
    receipt = {
        "schema": "replay120-typed-soundbank-alias-map-v1",
        "asset_type": 21, "asset_name": "code_post_gfx",
        "asset_archive_span": [500, 1000], "aliases": [alias],
        "provenance": {"source_body": {"sha256": hashlib.sha256(body).hexdigest(),
                                        "bytes": len(body)}},
    }
    receipt["source_identity_sha256"] = hashlib.sha256(json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return body, receipt


class WorkstationSoundBankScalarFieldTests(unittest.TestCase):
    def _document(self, receipt):
        return soundbank_edit_document(receipt)

    def test_same_extent_public_float_fields_preserve_every_other_byte(self):
        body, receipt = _fixture()
        document = self._document(receipt)
        alias = document["aliases"][0]
        self.assertEqual((alias["volMin"], alias["volMax"],
                          alias["pitchMin"], alias["pitchMax"]),
                         (0.25, 1.0, 0.800000011920929, 1.2000000476837158))
        alias["volMin"] = 0.5
        alias["pitchMax"] = 1.25
        changes = validate_soundbank_edit_document(json.dumps(document, allow_nan=False), receipt)
        updated, proof = replace_soundbank_alias_scalars(body, receipt, changes)
        self.assertEqual(len(updated), len(body))
        span = receipt["aliases"][0]["archive_offset"]
        changed_offsets = {write["archive_offset"] for write in proof["writes"]}
        expected = {span + ALIAS_SCALAR_FLOAT_OFFSETS["volMin"],
                    span + ALIAS_SCALAR_FLOAT_OFFSETS["pitchMax"]}
        self.assertEqual(changed_offsets, expected)
        for index, (old, new) in enumerate(zip(body, updated)):
            if not any(offset <= index < offset + 4 for offset in expected):
                self.assertEqual(new, old)
        self.assertEqual(struct.unpack_from("<f", updated, expected.pop())[0], 1.25)

    def test_unproven_parameter_words_are_visible_and_immutable(self):
        _body, receipt = _fixture()
        document = self._document(receipt)
        alias = document["aliases"][0]
        words = alias["nativeWordInspection"]["scalarWords"]
        self.assertEqual(len(words), 37)
        offsets = {int(offset): value for offset, value in words.items()}
        self.assertIn(44, offsets)
        self.assertIn(204, offsets)
        self.assertTrue({76, 80, 88, 92}.isdisjoint(offsets))
        self.assertIn("212", alias["nativeWordInspection"]["tailWords"])
        source = receipt["aliases"][0]
        raw = bytes.fromhex(source["raw_hex"])
        self.assertEqual(offsets[100], raw[100:104].hex())

        alias["nativeWordInspection"]["scalarWords"]["100"] = "00000000"
        with self.assertRaisesRegex(ValueError, "read-only native SoundBank words"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

    def test_staged_float_edit_validates_against_native_equivalent_readback(self):
        body, receipt = _fixture()
        document = self._document(receipt)
        document["aliases"][0]["volMin"] = 0.5
        document["aliases"][0]["pitchMax"] = 1.25
        content = json.dumps(document, allow_nan=False)
        changes = validate_soundbank_edit_document(content, receipt)
        updated, _proof = replace_soundbank_alias_scalars(body, receipt, changes)

        reread_receipt = json.loads(json.dumps(receipt))
        source = reread_receipt["aliases"][0]
        start = source["archive_offset"]
        raw = updated[start:start + ALIAS_SIZE]
        source["raw_hex"] = raw.hex()
        source["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        reread_receipt["provenance"]["source_body"]["sha256"] = hashlib.sha256(updated).hexdigest()
        receipt_payload = {key: value for key, value in reread_receipt.items()
                           if key != "source_identity_sha256"}
        reread_receipt["source_identity_sha256"] = hashlib.sha256(json.dumps(
            receipt_payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        self.assertEqual(validate_soundbank_edit_document(content, reread_receipt), [])

    def test_legacy_document_without_optional_word_inspection_still_validates(self):
        _body, receipt = _fixture()
        document = self._document(receipt)
        del document["aliases"][0]["nativeWordInspection"]
        changes = validate_soundbank_edit_document(json.dumps(document), receipt)
        self.assertEqual(changes, [])

    def test_immutable_alias_identity_and_float_domains_are_enforced(self):
        _body, receipt = _fixture()
        document = self._document(receipt)
        document["aliases"][0]["fileId"] += 1
        with self.assertRaisesRegex(ValueError, "identity/order"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

        document = self._document(receipt)
        document["aliases"][0]["listIndex"] = True
        with self.assertRaisesRegex(ValueError, "identity/order"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

        document = self._document(receipt)
        del document["aliases"][0]["assetFileName"]
        with self.assertRaisesRegex(ValueError, "identity/order"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

        document = self._document(receipt)
        document["aliases"][0]["volMin"] = -0.1
        with self.assertRaisesRegex(ValueError, "volume range"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

        document = self._document(receipt)
        document["aliases"][0]["pitchMax"] = 0.5
        with self.assertRaisesRegex(ValueError, "pitch range"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

        document = self._document(receipt)
        document["aliases"][0]["pitchMin"] = True
        with self.assertRaisesRegex(ValueError, "finite number"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

        document = self._document(receipt)
        document["aliases"][0]["pitchMin"] = math.nan
        with self.assertRaisesRegex(ValueError, "non-finite JSON"):
            validate_soundbank_edit_document(json.dumps(document), receipt)

    def test_nonfinite_source_field_is_visible_as_readonly_bits_and_preserved(self):
        body, receipt = _fixture(nonfinite_volume=True)
        document = self._document(receipt)
        alias = document["aliases"][0]
        self.assertIsNone(alias["volMax"])
        self.assertEqual(alias["readOnlyFieldBits"]["volMax"], "0x7fc01234")
        alias["pitchMin"] = 0.9
        changes = validate_soundbank_edit_document(json.dumps(document, allow_nan=False), receipt)
        updated, _proof = replace_soundbank_alias_scalars(body, receipt, changes)
        start = receipt["aliases"][0]["archive_offset"]
        offset = start + ALIAS_SCALAR_FLOAT_OFFSETS["volMax"]
        self.assertEqual(updated[offset:offset + 4], body[offset:offset + 4])
        with self.assertRaisesRegex(ValueError, "read-only"):
            document["aliases"][0]["volMax"] = 1.1
            validate_soundbank_edit_document(json.dumps(document, allow_nan=False), receipt)

    def test_low_level_writer_rechecks_range_and_receipt_identity(self):
        body, receipt = _fixture()
        source = receipt["aliases"][0]
        invalid = [{"list_index": source["list_index"],
                    "alias_index_in_list": source["alias_index_in_list"],
                    "archive_offset": source["archive_offset"],
                    "source_raw_sha256": source["raw_sha256"],
                    "fields": {"volMin": struct.pack("<f", -1.0).hex()}}]
        with self.assertRaisesRegex(ValueError, "written volume range"):
            replace_soundbank_alias_scalars(body, receipt, invalid)

        altered = dict(receipt)
        altered["asset_name"] = "different"
        with self.assertRaisesRegex(ValueError, "receipt was altered"):
            replace_soundbank_alias_scalars(body, altered, [])


if __name__ == "__main__":
    unittest.main()
