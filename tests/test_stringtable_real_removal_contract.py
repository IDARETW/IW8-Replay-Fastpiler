import csv
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
from workstation_stringtable import inspect_stringtable, replace_stringtable_rows


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class RealStringTableDictionaryRemovalIntegrationTests(unittest.TestCase):
    def test_unreferenced_removal_succeeds_and_retained_alias_removal_fails(self):
        receipt_text = os.environ.get("REPLAY_STRINGTABLE_REMOVAL_FIXTURE_RECEIPT")
        if not receipt_text:
            self.skipTest("requires an externally configured, hash-pinned complete native StringTable fixture receipt")
        fixture = json.loads(Path(receipt_text).read_text(encoding="utf-8"))
        self.assertEqual(fixture.get("schema"), "replay120-stringtable-native-noop-audit-v1")
        self.assertEqual(fixture.get("status"), "pass")
        body_path = Path(fixture["source_body_path"])
        trace_path = Path(fixture["trace_path"])
        manifest_path = Path(fixture["manifest_path"])
        export_index_path = Path(fixture["source_type54_export_index"])
        body = body_path.read_bytes()
        self.assertEqual(len(body), fixture["source_body_bytes"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), fixture["source_body_sha256"])
        self.assertEqual(sha256_file(trace_path), fixture["trace_sha256"])
        self.assertEqual(sha256_file(manifest_path), fixture["manifest_sha256"])
        self.assertEqual(sha256_file(export_index_path), fixture["source_type54_export_index_sha256"])
        export_root = export_index_path.parent.resolve()
        export_index = json.loads(export_index_path.read_text(encoding="utf-8"))
        payloads = {row["asset_index"]: row for row in export_index["items"]}
        cached_index_path = Path(fixture["read_span_index_path"])
        self.assertEqual(hashlib.sha256(cached_index_path.read_bytes()).hexdigest(), fixture["read_span_index_sha256"])
        cached_doc = json.loads(cached_index_path.read_text(encoding="utf-8"))
        cached_index = cached_doc["index"]
        assets = {row["index"]: row for row in cached_index["assets"]}

        def load_rows(asset_index):
            item = payloads[asset_index]
            path = (export_index_path.parent / item["payload_relative_path"]).resolve()
            path.relative_to(export_root)
            self.assertEqual(path.stat().st_size, item["payload_bytes"])
            self.assertEqual(sha256_file(path), item["payload_sha256"])
            with path.open("r", encoding="utf-8", newline="") as stream:
                rows = [list(row) for row in csv.reader(stream)]
            return item, rows

        for case in fixture["removal_cases"]:
            asset_index = case["asset_index"]
            asset_name = case["asset_name"]
            source_item, source_rows = load_rows(asset_index)
            self.assertEqual(source_item["name"], asset_name)
            self.assertEqual(source_item["payload_sha256"], case["payload_sha256"])
            self.assertEqual(assets[asset_index]["type_id"], 54)
            trace_asset = dict(assets[asset_index], xasset_index=asset_index,
                               type_id=54, name=asset_name)
            layout, decoded = inspect_stringtable(
                body, asset_index, asset_name, trace_asset, source_rows,
                expected_body_sha256=fixture["source_body_sha256"])
            matches = [(row_index, column_index)
                       for row_index, row in enumerate(decoded)
                       for column_index, value in enumerate(row)
                       if value == case["old_value"]]
            self.assertEqual(len(matches), 1)
            row_index, column_index = matches[0]
            old_start = next(stream_offset for dictionary_index, _, stream_offset, _
                             in layout.inline_dictionary_strings
                             if layout.dictionary_values[dictionary_index] == case["old_value"])
            self.assertEqual(old_start, case["old_dictionary_stream_offset"])
            edited_rows = [list(row) for row in decoded]
            edited_rows[row_index][column_index] = case["replacement_value"]

            args = (body, asset_index, asset_name, trace_asset, decoded, edited_rows,
                    fixture["source_body_sha256"], trace_path, manifest_path)
            self.assertIn(case["expect"], ("accept", "reject"))
            if case["expect"] == "accept":
                output, writer_receipt = replace_stringtable_rows(*args)
                self.assertEqual(hashlib.sha256(output).hexdigest(), case["output_body_sha256"])
                self.assertEqual(writer_receipt["status"], "trace-relocated-stringtable-ready")
                self.assertEqual(writer_receipt["full_native_trace_events"], fixture["full_trace_event_count"])
                self.assertEqual(writer_receipt["packed_stream5_aliases_scanned"], 438443)
            else:
                with self.assertRaisesRegex(ValueError, "retained packed reference targets removed StringTable dictionary string"):
                    replace_stringtable_rows(*args)


if __name__ == "__main__":
    unittest.main()

