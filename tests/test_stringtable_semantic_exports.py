from __future__ import annotations

import csv
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from workstation_stringtable_semantics import compare_stringtable_exports  # noqa: E402


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


class StringTableSemanticExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source_root = root / "source"
        self.output_root = root / "output"
        self.source_root.mkdir()
        self.output_root.mkdir()
        self.edited_name = "omnvars/mp/omnvars.csv"
        self.expected_rows = [["name", "value"], ["changed", "2"]]
        output_csv = io.StringIO(newline="")
        csv.writer(output_csv, lineterminator="\n").writerows(self.expected_rows)
        self.source_payloads = {
            "code_post_gfx/retained_a.csv": b"retained-a\n",
            self.edited_name: b"name,value\nchanged,1\n",
            "code_post_gfx/retained_b.csv": b"retained-b\n",
        }
        self.output_payloads = dict(self.source_payloads)
        self.output_payloads[self.edited_name] = output_csv.getvalue().encode("utf-8")
        self.source_index = self.write_index(self.source_root, self.source_payloads,
                                             body="source-body", fastfile="source-ff",
                                             walk="source-walk")
        self.output_index = self.write_index(self.output_root, self.output_payloads,
                                             body="output-body", fastfile="output-ff",
                                             walk="output-walk")
        self.kwargs = dict(
            source_index_path=self.source_index, output_index_path=self.output_index,
            edited_name=self.edited_name, edited_asset_index=11,
            expected_rows=self.expected_rows,
            source_body_sha256=sha(b"source-body"), source_fastfile_sha256=sha(b"source-ff"),
            source_walk_key="source-walk", output_body_sha256=sha(b"output-body"),
            output_fastfile_sha256=sha(b"output-ff"), output_walk_key="output-walk")

    def write_index(self, root: Path, payloads: dict[str, bytes], *, body: str,
                    fastfile: str, walk: str) -> Path:
        items = []
        for rank, (name, data) in enumerate(payloads.items()):
            relative = Path("payloads") / f"{rank:03}.csv"
            path = root / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
            items.append(dict(rank=rank, asset_index=rank + 10, type_id=54, name=name,
                              payload_relative_path=relative.as_posix(), payload_bytes=len(data),
                              payload_sha256=sha(data)))
        index = dict(schema=1, type_id=54, type_name="stringtable",
                     body_sha256=sha(body.encode()), source_sha256=sha(fastfile),
                     native_walk_key=walk, acts_sha256="acts-pin", replay_executable_sha256="replay-pin",
                     items=items)
        path = root / "asset-payload-index.json"
        path.write_text(json.dumps(index), encoding="utf-8")
        return path

    def test_edited_rows_match_and_all_retained_payloads_are_byte_identical(self):
        proof = compare_stringtable_exports(**self.kwargs)
        self.assertEqual(proof["status"], "pass")
        self.assertEqual(proof["retained_payloads_checked"], 2)
        self.assertEqual(proof["edited_payloads_checked"], 1)

    def test_wrong_edited_csv_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "edited StringTable rows differ"):
            compare_stringtable_exports(**dict(self.kwargs,
                                                expected_rows=[["name", "value"], ["changed", "1"]]))

    def test_changed_retained_csv_is_rejected_even_with_self_consistent_index_hash(self):
        path = self.output_root / "payloads" / "002.csv"
        changed = b"different retained data\n"
        path.write_bytes(changed)
        index = json.loads(self.output_index.read_text(encoding="utf-8"))
        index["items"][2]["payload_bytes"] = len(changed)
        index["items"][2]["payload_sha256"] = sha(changed)
        self.output_index.write_text(json.dumps(index), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "retained StringTable payload changed"):
            compare_stringtable_exports(**self.kwargs)

    def test_order_count_identity_and_native_binding_changes_are_rejected(self):
        original = json.loads(self.output_index.read_text(encoding="utf-8"))
        variants = []
        reordered = dict(original, items=list(reversed(original["items"])))
        variants.append((reordered, "invalid identity fields"))
        short = dict(original, items=original["items"][:-1])
        variants.append((short, "row count"))
        wrong_owner = json.loads(json.dumps(original))
        wrong_owner["items"][0]["asset_index"] += 1
        variants.append((wrong_owner, "duplicate XAsset indices"))
        for document, message in variants:
            with self.subTest(message=message):
                self.output_index.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    compare_stringtable_exports(**self.kwargs)
        for key, argument in (("body_sha256", "output_body_sha256"),
                              ("source_sha256", "output_fastfile_sha256"),
                              ("native_walk_key", "output_walk_key")):
            document = json.loads(self.output_index.read_text(encoding="utf-8"))
            document[key] = "wrong-pin"
            self.output_index.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "does not match its pinned native source"):
                    compare_stringtable_exports(**self.kwargs)
            self.output_index.write_text(json.dumps(original), encoding="utf-8")

    def test_payload_hash_drift_is_rejected(self):
        (self.output_root / "payloads" / "000.csv").write_bytes(b"tamper")
        with self.assertRaisesRegex(ValueError, "payload hash/size mismatch"):
            compare_stringtable_exports(**self.kwargs)


if __name__ == "__main__":
    unittest.main()
