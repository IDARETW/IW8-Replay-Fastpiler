"""Behavioral tests for the persistent, metadata-only fastfile index."""
from pathlib import Path
import json
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys_path = str(Path(__file__).resolve().parents[1] / "tools")
import sys
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)

import workstation_asset_metadata as metadata
from workstation_reader_identity import reader_code_identity


def asset_rows(*items):
    """Build an exact native snapshot, including reference and empty rows."""
    headers, native = [], []
    for index, item in enumerate(items):
        type_id, name, status = item
        headers.append(SimpleNamespace(index=index, type_id=type_id,
                                       pointer_token=0xFFFFFFFFFFFFFFFD if status == "reference"
                                       else 0xFFFFFFFFFFFFFFFE))
        native.append(dict(type="RawFile" if type_id == 51 else "LocalizeEntry",
                           name=name, status=status))
    return SimpleNamespace(
        body=SimpleNamespace(assets=headers, source_sha256="body-sha"),
        native_rows=native, zone_id="zone-fixture",
        source_profile=dict(profile="replay-1.20", source_identity="fixture"),
        native_walk=dict(walk_key="walk-fixture"))


class ArchiveFixture:
    def __init__(self, root, snapshots):
        self.cleanups = []
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.game_root = self.root / "game"
        self.game_root.mkdir()
        self.cache_root = self.root / "cache" / "fastfiles"
        self.cache_root.mkdir(parents=True)
        self.acts_path = self.root / "acts.exe"
        self.replay_executable = self.root / "replay.exe"
        self.lua_acts_path = None
        self.root.mkdir(exist_ok=True)
        self.acts_path.write_bytes(b"fixture acts")
        self.replay_executable.write_bytes(b"fixture replay")
        self.snapshots = snapshots
        self.extract_calls = []
        self.cache_reads = []
        self.fail = set()
        self.module_patch = mock.patch.object(metadata.fastfiles, "FastfileWorkspace",
                                               self.workspace_factory)
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)

    def _validated_asset_snapshot(self, cache_key, require_trace):
        self.cache_reads.append(cache_key)
        return self.snapshots[cache_key]

    def addCleanup(self, callback):
        # Make this fixture usable without deriving from unittest.TestCase.
        self.cleanups.append(callback)

    def cleanup(self):
        for callback in reversed(self.cleanups):
            callback()

    def workspace_factory(self, *args, **kwargs):
        fixture = self

        class Workspace:
            def __init__(self, *unused_args, **unused_kwargs):
                self.root = Path(args[0])
                self.cache_root = Path(args[1])
                self.game_root = Path(args[2])
                self.acts_path = kwargs['acts_path']
                self.replay_executable = kwargs['replay_executable']

            def extract(self, relative):
                fixture.extract_calls.append(relative)
                if relative in fixture.fail:
                    raise RuntimeError("fixture native reader failure")
                return {"zone_id": relative}

            def _validated_asset_snapshot(self, cache_key, require_trace):
                fixture.cache_reads.append(cache_key)
                return fixture.snapshots[cache_key]

        return Workspace()

class AssetMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.snapshots = {
            "a.ff": asset_rows((51, "config/Settings.cfg", "ok"),
                               (51, None, "ok"),
                               (41, ",zone_reference", "reference")),
            "nested/b.ff": asset_rows((51, "ui/雪、β.cfg", "ok"),),
            "cached.ff": asset_rows((54, "tables/cached.csv", "ok"),),
        }
        self.archives = ArchiveFixture(Path(self.temp.name) / "fixture", self.snapshots)
        self.addCleanup(self.archives.cleanup)
        self.game = self.archives.game_root
        self._reader_patch = mock.patch.object(metadata.AssetMetadataIndex,
                                               "_reader_identity", return_value={"test": "stable"})
        self._reader_patch.start()
        self.addCleanup(self._reader_patch.stop)

    def touch_ff(self, relative):
        path = self.game / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("fixture:" + relative).encode())
        return path

    def make_index(self):
        return metadata.AssetMetadataIndex(self.archives)

    def test_reader_closure_reuses_writer_only_change_but_tracks_reader_change(self):
        module = Path(self.temp.name) / "reader.py"
        local = Path(self.temp.name)
        helper = local / "helper.py"
        middle = local / "middle.py"
        middle.write_text("def parse(): return 2\n", encoding="utf-8")
        helper.write_text("from middle import parse\n", encoding="utf-8")

        def digest(body, middle_body=None):
            module.write_text(body, encoding="utf-8")
            if middle_body is not None:
                middle.write_text(middle_body, encoding="utf-8")
            return reader_code_identity(module, ("FastfileWorkspace.extract",), local)["sha256"]

        original = digest("from dataclasses import dataclass\nfrom helper import parse\nBOOT = 1\nclass Parsed:\n    @property\n    def value(self): return 2\n@dataclass\nclass Model:\n    def __post_init__(self): self.value = parse()\nclass FastfileWorkspace:\n    def extract(self):\n        model = Model()\n        parsed = Parsed()\n        return parse() + model.value + parsed.value\n    def write(self): return 1\n", "def parse(): return 2\n")
        writer_changed = digest("from dataclasses import dataclass\nfrom helper import parse\nBOOT = 1\nclass Parsed:\n    @property\n    def value(self): return 2\n@dataclass\nclass Model:\n    def __post_init__(self): self.value = parse()\nclass FastfileWorkspace:\n    def extract(self):\n        model = Model()\n        parsed = Parsed()\n        return parse() + model.value + parsed.value\n    def write(self): return 999\n", "def parse(): return 2\n")
        transitive_reader_changed = digest("from dataclasses import dataclass\nfrom helper import parse\nBOOT = 1\nclass Parsed:\n    @property\n    def value(self): return 2\n@dataclass\nclass Model:\n    def __post_init__(self): self.value = parse()\nclass FastfileWorkspace:\n    def extract(self):\n        model = Model()\n        parsed = Parsed()\n        return parse() + model.value + parsed.value\n    def write(self): return 999\n", "def parse(): return 3\n")
        initialization_changed = digest("from dataclasses import dataclass\nfrom helper import parse\nBOOT = 2\nclass Parsed:\n    @property\n    def value(self): return 2\n@dataclass\nclass Model:\n    def __post_init__(self): self.value = parse()\nclass FastfileWorkspace:\n    def extract(self):\n        model = Model()\n        parsed = Parsed()\n        return parse() + model.value + parsed.value\n    def write(self): return 999\n", "def parse(): return 3\n")
        self.assertEqual(original, writer_changed)
        self.assertNotEqual(writer_changed, transitive_reader_changed)
        self.assertNotEqual(transitive_reader_changed, initialization_changed)

    def test_only_exact_frozen_legacy_identity_can_be_aliased(self):
        index = object.__new__(metadata.AssetMetadataIndex)
        expected_modules = dict(metadata._READER_BASELINE["legacy_reader_modules"])
        expected_modules.pop("workstation_asset_metadata.py")
        index.identity = dict(game_root="G:/Game", acts_tool_identity={"sha256": "acts"},
                              replay_executable_sha256="exe",
                              reader_code={"sha256": metadata._READER_BASELINE["reader_code"]["sha256"]},
                              reader_modules=expected_modules)
        legacy = dict(game_root="G:/Game", acts_tool_identity={"sha256": "acts"},
                      replay_executable_sha256="exe",
                      reader_modules=dict(metadata._READER_BASELINE["legacy_reader_modules"]))
        self.assertTrue(index._legacy_identity_valid(legacy))
        changed = json.loads(json.dumps(legacy))
        changed["reader_modules"]["workstation_fastfiles.py"] = "0" * 64
        self.assertFalse(index._legacy_identity_valid(changed))
        index.identity["reader_code"]["sha256"] = "1" * 64
        self.assertFalse(index._legacy_identity_valid(legacy))

    def test_reader_drift_aborts_batch_without_recording_zone_unavailable(self):
        self.touch_ff("drift.ff")
        index = self.make_index()
        try:
            with mock.patch.object(index, "_index_one",
                                   side_effect=metadata.MetadataReaderDriftError("reader changed")):
                with self.assertRaises(metadata.MetadataReaderDriftError):
                    index.run_once()
            self.assertEqual(index.snapshot()["files"]["drift.ff"]["state"], "pending")
            self.assertEqual(index.snapshot()["counts"]["unavailable_fastfiles"], 0)
        finally:
            index.close()

    def prepopulate_decode_receipt(self, relative, cache_key):
        source = self.game / relative
        receipt_dir = self.archives.cache_root / source.stem / "prior-cache"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        (receipt_dir / "decode-receipt.json").write_text(json.dumps({
            "cache_key": cache_key, "source": {"path": str(source.resolve())}}), encoding="utf-8")

    def test_enumerates_all_fastfiles_without_extracting_for_listing_or_search(self):
        self.touch_ff("a.ff")
        self.touch_ff("nested/b.ff")
        self.touch_ff("not-a-fastfile.bin")
        index = self.make_index()
        try:
            snapshot = index.run_once(max_files=0)
            self.assertEqual(snapshot["counts"]["total_fastfiles"], 2)
            self.assertEqual(snapshot["counts"]["pending_fastfiles"], 2)
            self.assertEqual(set(snapshot["files"]), {"a.ff", "nested/b.ff"})
            self.assertEqual(index.search("cfg")["total"], 0)
            self.assertEqual(self.archives.extract_calls, [])
        finally:
            index.close()

    def test_cached_native_snapshot_builds_compact_shard_with_exact_rows(self):
        self.touch_ff("cached.ff")
        self.prepopulate_decode_receipt("cached.ff", "cached.ff")
        index = self.make_index()
        try:
            snapshot = index.run_once()
            self.assertTrue(snapshot["complete"])
            self.assertEqual(self.archives.extract_calls, [])
            self.assertEqual(self.archives.cache_reads, ["cached.ff"])
            row = snapshot["files"]["cached.ff"]
            shard = index.inventory("cached.ff")
            self.assertEqual(row["asset_count"], 1)
            self.assertEqual(len(shard["rows"]), 1)
            self.assertEqual(shard["rows"][0]["name"], "tables/cached.csv")
            self.assertTrue(shard["complete"])
            self.assertNotIn("payload", shard["rows"][0])
        finally:
            index.close()

    def test_shard_preserves_empty_and_reference_rows_and_exact_asset_count(self):
        self.touch_ff("a.ff")
        index = self.make_index()
        try:
            snapshot = index.run_once()
            shard = index.inventory("a.ff")
            self.assertEqual(snapshot["counts"]["native_asset_rows"], 3)
            self.assertEqual(snapshot["files"]["a.ff"]["asset_count"], 3)
            self.assertEqual([row["index"] for row in shard["rows"]], [0, 1, 2])
            self.assertEqual([row["name"] for row in shard["rows"]],
                             ["config/Settings.cfg", None, ",zone_reference"])
            self.assertTrue(shard["rows"][2]["reference_only"])
            self.assertEqual(shard["rows"][1]["status"], "ok")
        finally:
            index.close()

    def test_global_substring_search_handles_cfg_unicode_punctuation_and_short_queries(self):
        self.touch_ff("a.ff")
        self.touch_ff("nested/b.ff")
        index = self.make_index()
        try:
            index.run_once()
            for query, expected_path, expected_name in (
                    ("Settings", "a.ff", "config/Settings.cfg"),
                    ("雪、β", "nested/b.ff", "ui/雪、β.cfg"),
                    ("cfg", "nested/b.ff", "ui/雪、β.cfg"),
                    ("ui", "nested/b.ff", "ui/雪、β.cfg")):
                result = index.search(query, limit=100)
                self.assertGreaterEqual(result["total"], 1, query)
                self.assertTrue(any(item["relative_path"] == expected_path and
                                    item["name"] == expected_name for item in result["items"]), query)
            self.assertEqual(index.search("雪、β", limit=100)["total"], 1)
            cfg = index.search("cfg", limit=100)
            self.assertEqual(cfg["total"], 2)
            self.assertEqual({item["relative_path"] for item in cfg["items"]},
                             {"a.ff", "nested/b.ff"})
        finally:
            index.close()

    def test_restart_resumes_ready_shard_without_mutating_its_metadata(self):
        self.touch_ff("a.ff")
        first = self.make_index()
        try:
            first.run_once()
            row = first.snapshot()["files"]["a.ff"]
            shard_path = first.root / row["shard_relative_path"]
            before = (shard_path.read_bytes(), shard_path.stat().st_mtime_ns)
        finally:
            first.close()
        self.archives.extract_calls.clear()
        resumed = self.make_index()
        try:
            self.assertEqual(resumed.snapshot()["files"]["a.ff"]["state"], "ready")
            resumed.run_once()
            after_row = resumed.snapshot()["files"]["a.ff"]
            after_path = resumed.root / after_row["shard_relative_path"]
            self.assertEqual((after_path.read_bytes(), after_path.stat().st_mtime_ns), before)
            self.assertEqual(self.archives.extract_calls, [])
        finally:
            resumed.close()

    def test_source_fp_and_fc_changes_invalidate_cached_shard(self):
        source = self.touch_ff("a.ff")
        fp, fc = source.with_suffix(".fp"), source.with_suffix(".fc")
        fp.write_bytes(b"fp-one")
        fc.write_bytes(b"fc-one")
        index = self.make_index()
        try:
            index.run_once()
            old = index.snapshot()["files"]["a.ff"]["source_fingerprint"]
            self.archives.extract_calls.clear()
            fp.write_bytes(b"fp-changed-longer")
            changed = index.run_once(max_files=0)
            self.assertEqual(changed["files"]["a.ff"]["state"], "pending")
            self.assertNotEqual(changed["files"]["a.ff"]["source_fingerprint"], old)
            self.assertNotEqual(changed["files"]["a.ff"]["source_fingerprint"]["companions"][".fp"],
                                old["companions"][".fp"])
            fc.write_bytes(b"fc-changed-longer")
            changed = index.run_once()
            self.assertEqual(changed["files"]["a.ff"]["state"], "ready")
            self.assertEqual(self.archives.extract_calls, ["a.ff"])
            indexed_fp = changed["files"]["a.ff"]["source_fingerprint"]
            fc.write_bytes(b"fc-changed-again")
            pending = index.run_once(max_files=0)["files"]["a.ff"]
            self.assertEqual(pending["state"], "pending")
            self.assertNotEqual(pending["source_fingerprint"]["companions"][".fc"],
                                indexed_fp["companions"][".fc"])
        finally:
            index.close()

    def test_missing_search_database_is_rebuilt_from_immutable_shard(self):
        self.touch_ff("a.ff")
        index = self.make_index()
        try:
            index.run_once()
            shard = index.inventory("a.ff")
            index.database.unlink()
            self.archives.extract_calls.clear()
            index.run_once()
            self.assertEqual(self.archives.extract_calls, [])
            self.assertTrue(index.database.is_file())
            self.assertEqual(index.search("Settings")["total"], 1)
            self.assertEqual(index.inventory("a.ff"), shard)
        finally:
            index.close()

    def test_crash_interrupted_indexing_state_resumes_as_pending(self):
        self.touch_ff("a.ff")
        first = self.make_index()
        try:
            first.run_once(max_files=0)
            saved = first.snapshot()
            saved["files"]["a.ff"] = dict(state="indexing",
                source_fingerprint=metadata._fingerprint(self.game / "a.ff"))
            metadata._atomic_json(first.path, saved)
        finally:
            first.close()
        resumed = self.make_index()
        try:
            self.assertEqual(resumed.snapshot()["files"]["a.ff"]["state"], "pending")
            self.assertFalse(resumed.snapshot()["complete"])
            final = resumed.run_once()
            self.assertEqual(final["files"]["a.ff"]["state"], "ready")
            self.assertTrue(final["complete"])
        finally:
            resumed.close()

    def test_corrupt_display_manifest_rebuilds_from_current_native_evidence(self):
        self.touch_ff("a.ff")
        index = self.make_index()
        try:
            index.run_once()
            index.path.write_text('{"generation":', encoding="utf-8")
            self.assertIn("needs rebuilding", index.snapshot()["error"])
            self.archives.extract_calls.clear()
            rebuilt = index.run_once()
            self.assertTrue(rebuilt["complete"])
            self.assertIsNone(rebuilt["error"])
            self.assertEqual(self.archives.extract_calls, ["a.ff"])
            self.assertEqual(index.search("Settings")["total"], 1)
            self.assertEqual(json.loads(index.path.read_text())["files"]["a.ff"]["state"], "ready")
        finally:
            index.close()

    def test_native_reader_failure_persists_unavailable_state_and_diagnostic(self):
        self.touch_ff("a.ff")
        self.archives.fail.add("a.ff")
        index = self.make_index()
        try:
            result = index.run_once()
            entry = result["files"]["a.ff"]
            self.assertEqual(entry["state"], "unavailable")
            self.assertFalse(result["complete"])
            self.assertNotEqual(result["state"], "ready")
            self.assertIn("fixture native reader failure", entry["error"])
            diagnostic = index.root / entry["diagnostic_relative_path"]
            self.assertTrue(diagnostic.is_file())
            self.assertEqual(json.loads(diagnostic.read_text(encoding="utf-8"))["relative_path"], "a.ff")
            self.assertEqual(index.search("Settings")["total"], 0)
        finally:
            index.close()

    def test_valid_table_survives_native_reader_gap_and_opens_as_read_only_metadata(self):
        source = self.touch_ff("a.ff")
        self.archives.fail.add("a.ff")
        zone_id = "b" * 64
        table = dict(zone_id=zone_id, source_identity={"sha256": "source-fixture"},
            body_sha256="body-fixture", native_walk_key=None, reader_scope="xasset-table-only",
            native_reader_error="fixture native reader failure", rows=[
                dict(index=0, type_id=255, name=None, type_name=None, reference_only=None,
                     pointer_token="0xfffffffffffffffe", status="xasset-table-only-reader-unavailable")])
        index = self.make_index()
        try:
            with mock.patch.object(metadata.table_decode, "decode_table_only_metadata", return_value=table) as fallback:
                result = index.run_once()
            fallback.assert_called_once()
            self.assertTrue(result["complete"])
            self.assertFalse(result["native_names_complete"])
            self.assertEqual(result["state"], "partial")
            self.assertEqual(result["counts"]["table_only_fastfiles"], 1)
            self.assertEqual(result["counts"]["native_asset_rows"], 0)
            self.assertEqual(result["counts"]["asset_rows"], 1)
            self.assertEqual(index.search("255")["total"], 1)
            self.assertIsNone(index.search("255")["items"][0]["reference_only"])
            self.assertEqual(index.inventory("a.ff")["rows"], table["rows"])
            opened = index.read_only_asset(zone_id + ":0")
            self.assertEqual(opened["asset_id"], zone_id + ":0")
            self.assertFalse(opened["editable"])
            self.assertFalse(opened["archive_writable"])
            self.assertIn("fixture native reader failure", opened["content"])
            self.assertIsNone(index.read_only_asset(zone_id + ":00"))
            with self.assertRaisesRegex(ValueError, "outside"):
                index.read_only_asset(zone_id + ":1")
            resumed = self.make_index()
            self.addCleanup(resumed.close)
            self.assertEqual(resumed.read_only_asset(zone_id + ":0"), opened)
            source.write_bytes(b"source changed after table cache")
            self.assertIsNone(resumed.read_only_asset(zone_id + ":0"))
        finally:
            index.close()

    def test_invalid_table_fallback_cannot_turn_decode_failure_into_ready_metadata(self):
        self.touch_ff("a.ff")
        self.archives.fail.add("a.ff")
        index = self.make_index()
        try:
            with mock.patch.object(metadata.table_decode, "decode_table_only_metadata",
                                   side_effect=ValueError("FP chain identity mismatch")):
                result = index.run_once()
            self.assertFalse(result["complete"])
            entry = result["files"]["a.ff"]
            self.assertEqual(entry["state"], "unavailable")
            self.assertIn("fixture native reader failure", entry["error"])
            self.assertIn("FP chain identity mismatch", entry["error"])
            self.assertEqual(index.search("255")["total"], 0)
        finally:
            index.close()

    def test_relative_paths_and_reparse_sources_are_rejected(self):
        self.touch_ff("a.ff")
        index = self.make_index()
        try:
            for invalid in ("../outside.ff", "nested/../../outside.ff", "/outside.ff",
                            "C:/outside.ff", "a.txt", "nested//bad.ff"):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    index._source(invalid)
            source = self.game / "a.ff"
            original_lstat = Path.lstat

            def reparse_lstat(path):
                result = original_lstat(path)
                if path == source:
                    return SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                           st_file_attributes=0x400)
                return result

            with mock.patch.object(Path, "lstat", reparse_lstat):
                self.assertFalse(metadata._confined_file(source, self.game.resolve()))
        finally:
            index.close()

    def test_atomic_manifest_retries_windows_reader_contention_without_partial_data(self):
        target = Path(self.temp.name) / "atomic.json"
        metadata._atomic_json(target, {"generation": 1})
        real_replace = os.replace
        attempts = []

        def contended_replace(source, destination):
            attempts.append(destination)
            self.assertEqual(json.loads(target.read_text())["generation"], 1)
            if len(attempts) <= 2:
                raise PermissionError("a reader temporarily holds the manifest")
            return real_replace(source, destination)

        with mock.patch.object(metadata.os, "replace", side_effect=contended_replace), \
                mock.patch.object(metadata.time, "sleep") as wait:
            metadata._atomic_json(target, {"generation": 2})
        self.assertEqual(len(attempts), 3)
        self.assertEqual(wait.call_count, 2)
        self.assertEqual(json.loads(target.read_text()), {"generation": 2})

        with mock.patch.object(metadata.os, "replace", side_effect=PermissionError("persistent denial")) as replace, \
                mock.patch.object(metadata.time, "sleep"), self.assertRaises(PermissionError):
            metadata._atomic_json(target, {"generation": 3})
        self.assertEqual(replace.call_count, 6)
        self.assertEqual(json.loads(target.read_text()), {"generation": 2})
        self.assertFalse(list(target.parent.glob("atomic.json.*.tmp")))


if __name__ == "__main__":
    unittest.main()
