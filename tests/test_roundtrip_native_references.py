from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from tools import roundtrip_replay_fastfile as roundtrip
from tools import workstation_trace_index
from tests.test_workstation_native_references import _fixture


class RoundtripNativeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.body, self.events = _fixture()
        self.native = self.root / "reader-fixture" / "mw19replay" / "global_stream_mp"
        self.native.mkdir(parents=True)
        self.trace = self.native / "stream-trace.jsonl"
        self.trace.write_text("".join(json.dumps(event) + "\n" for event in self.events),
                              encoding="utf-8")
        self.journal = self.native / "assets.jsonl"
        self.journal.write_text(json.dumps({"type_id": 9, "type": "other",
                                           "name": "ordinary"}) + "\n", encoding="utf-8")
        self.manifest = {
            "profile": "replay-1.20", "xfile_version": 4087,
            "complete": True, "success": True, "failed": 0, "unavailable": 0,
            "tested": 1, "top_level_index": 2, "loaded_assets": 1,
            "serialized_bytes_read": len(self.body), "journal": "assets.jsonl",
            "stream_trace": "stream-trace.jsonl", "stream_trace_events": len(self.events),
        }
        self.manifest_path = self.native / "manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.source = self.root / "source.ff"
        self.source.write_bytes(b"source")
        self.acts = self.root / "acts.exe"
        self.acts.write_bytes(b"acts")
        self.replay = self.root / "replay.exe"
        self.replay.write_bytes(b"replay")
        self.package = self.root / "output.ff"
        self.package.write_bytes(b"ff")

        def native_process(command, *_args, **_kwargs):
            reader_root = Path(command[command.index("-o") + 1])
            shutil.copytree(self.native.parent, reader_root / "mw19replay")
            return type("Completed", (), {"returncode": 0})()

        self.process_patch = patch.object(roundtrip.subprocess, "run", side_effect=native_process)
        self.process_patch.start()
        self.addCleanup(self.process_patch.stop)

    def _verify(self, *, trace=True, references=None):
        if self.output.exists():
            shutil.rmtree(self.output)
        self.output.mkdir()
        with patch.object(roundtrip, "acts_tool_identity", return_value={}), \
             patch.object(roundtrip, "source_profile", return_value={}), \
             patch.object(roundtrip, "_assert_run_inputs_unchanged"), \
             patch.object(workstation_trace_index, "build_read_span_index", return_value={
                 "event_count": len(self.events), "max_destination_offsets": {},
                 "physical_load_count_by_stream": {}, "physical_load_bytes_by_stream": {},
                 "packed_target_stream_counts": {},
             }):
            return roundtrip.verify_native(self.package, self.body, self.source,
                self.acts, self.replay, self.output, 5, trace=trace,
                reference_only_rows=references)

    def test_derives_references_from_output_trace_and_preserves_raw_artifacts(self):
        raw_manifest_before = self.manifest_path.read_bytes()
        raw_journal_before = self.journal.read_bytes()
        result = self._verify(trace=True)
        self.assertEqual([(row["index"], row["type_id"], row["name"], row["pointer_token"])
                          for row in result["reference_only_rows"]],
                         [(0, 11, ",external", 0xFFFFFFFFFFFFFFFD)])
        self.assertEqual(result["manifest"]["tested"], 1)
        self.assertEqual(result["manifest"]["top_level_index"], 2)
        self.assertEqual(result["normalized_table_count"], 2)
        self.assertNotEqual(result["journal_asset_identity_sha256"],
                            result["normalized_asset_identity_sha256"])
        self.assertTrue(result["raw_manifest_sha256"])
        self.assertTrue(Path(result["normalized_inventory_path"]).is_file())
        self.assertEqual(self.manifest_path.read_bytes(), raw_manifest_before)
        self.assertEqual(self.journal.read_bytes(), raw_journal_before)

    def test_caller_descriptors_must_match_trace_derived_identities(self):
        with self.assertRaisesRegex(ValueError, "differ from trace-derived"):
            self._verify(trace=True, references=[dict(index=0, type_id=11,
                name=",wrong", pointer_token=0xFFFFFFFFFFFFFFFD)])

    def test_reference_deficit_without_trace_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "require an output trace"):
            self._verify(trace=False)

    def test_empty_reference_list_does_not_require_trace_for_complete_journal(self):
        self.manifest["tested"] = 2
        self.manifest["loaded_assets"] = 2
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.journal.write_text("\n".join(json.dumps(row) for row in (
            {"type_id": 11, "type": "other", "name": ",external"},
            {"type_id": 9, "type": "other", "name": "ordinary"})) + "\n",
            encoding="utf-8")
        result = self._verify(trace=False, references=[])
        self.assertEqual(result["reference_only_rows"], [])
        self.assertEqual(result["normalized_table_count"], 2)

    def test_boolean_manifest_count_and_descriptor_identity_are_rejected(self):
        self.manifest["tested"] = True
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "requirements"):
            self._verify(trace=True)
        self.manifest["tested"] = 1
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "identity fields have invalid types"):
            self._verify(trace=True, references=[dict(index=False, type_id=11,
                name=",external", pointer_token=0xFFFFFFFFFFFFFFFD)])

    def test_candidate_package_mutation_during_reader_is_rejected(self):
        self.process_patch.stop()

        def mutate_candidate(command, *_args, **_kwargs):
            reader_root = Path(command[command.index("-o") + 1])
            shutil.copytree(self.native.parent, reader_root / "mw19replay")
            self.package.write_bytes(b"changed")
            return type("Completed", (), {"returncode": 0})()

        self.process_patch = patch.object(roundtrip.subprocess, "run", side_effect=mutate_candidate)
        self.process_patch.start()
        self.addCleanup(self.process_patch.stop)
        with self.assertRaisesRegex(ValueError, "changed the candidate FF"):
            self._verify(trace=True)


if __name__ == "__main__":
    unittest.main()
