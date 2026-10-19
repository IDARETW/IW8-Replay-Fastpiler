"""A valid native load must not hide changed unedited Localize strings."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_localize_inventory import compare_localize_inventory, read_localize_inventory


class LocalizeInventoryTests(unittest.TestCase):
    def test_unedited_alias_corruption_and_reordered_keys_are_rejected(self):
        original = [dict(name="a", value="first"), dict(name="b", value="second")]
        good = [dict(name="a", value="grown first value"), dict(name="b", value="second")]
        proof = compare_localize_inventory(original, good, {"a": "grown first value"})
        self.assertEqual((proof["tested"], proof["retained"], proof["edited"]), (2, 2, 1))
        bad = [good[0], dict(name="b", value="first")]
        with self.assertRaisesRegex(ValueError, "value/order"):
            compare_localize_inventory(original, bad, {"a": "grown first value"})
        with self.assertRaisesRegex(ValueError, "value/order"):
            compare_localize_inventory(original, list(reversed(good)), {"a": "grown first value"})

    def test_remove_append_and_edit_are_all_accounted_for(self):
        original = [dict(name="a", value="first"), dict(name="b", value="second")]
        actual = [dict(name="b", value="B"), dict(name="new", value="new value")]
        proof = compare_localize_inventory(original, actual, {"b": "B"}, {"a"}, [("new", "new value")])
        self.assertEqual((proof["retained"], proof["removed"], proof["appended"]), (1, 1, 1))
        with self.assertRaisesRegex(ValueError, "collides"):
            compare_localize_inventory(original, actual, appended=[("b", "duplicate")])
        with self.assertRaisesRegex(ValueError, "missing source"):
            compare_localize_inventory(original, actual, removed={"missing"})

    def test_cached_payload_cannot_escape_or_change_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payload = json.dumps(dict(name="a", value="first")).encode()
            (root / "0.json").write_bytes(payload)
            row = dict(type_id=41, name="a", rank=0, asset_index=1,
                       payload_relative_path="0.json", payload_bytes=len(payload),
                       payload_sha256=hashlib.sha256(payload).hexdigest())
            native = [dict(type_id=14, name="shader"), dict(type_id=41, name="a")]
            self.assertEqual(read_localize_inventory(root, [row], native, cached=True)[0]["asset_index"], 1)
            for mutation in (dict(rank=1), dict(name="b"), dict(payload_relative_path="../0.json"),
                             dict(payload_sha256="0" * 64)):
                with self.assertRaises((ValueError, FileNotFoundError)):
                    read_localize_inventory(root, [{**row, **mutation}], native, cached=True)


if __name__ == "__main__":
    unittest.main()
