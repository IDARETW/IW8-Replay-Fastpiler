from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import workstation_fastfiles as fastfiles  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StringTableSemanticDispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "candidate.ff"
        self.output.write_bytes(b"candidate-ff")
        self.output.with_suffix(".fp").write_bytes(b"candidate-fp")
        self.raw_root = self.root / "native"
        self.raw_root.mkdir()
        (self.raw_root / "stream-trace.jsonl").write_bytes(b"trace")
        (self.raw_root / "assets.jsonl").write_bytes(b"journal")
        self.raw_manifest_path = self.raw_root / "manifest.json"
        self.raw_manifest_path.write_text(json.dumps(dict(
            stream_trace="stream-trace.jsonl", journal="assets.jsonl")), encoding="utf-8")
        self.native = dict(
            raw_manifest_path=str(self.raw_manifest_path),
            raw_manifest_sha256=sha(self.raw_manifest_path.read_bytes()),
            trace_summary=dict(stream_trace_sha256=sha(b"trace")),
            journal_sha256=sha(b"journal"),
            normalized_asset_identity_sha256="normalized-identity",
            manifest=dict(tested=746, top_level_index=746, serialized_bytes_read=1200),
            candidate_artifacts={
                ".ff": self.artifact(self.output),
                ".fp": self.artifact(self.output.with_suffix(".fp")),
                ".fc": dict(path=str(self.output.with_suffix(".fc").resolve()),
                             exists=False, bytes=None, sha256=None),
            })
        self.export_root = self.root / "candidate-export"
        self.export_root.mkdir()
        (self.root / "source-index.json").write_text("{}", encoding="utf-8")

    @staticmethod
    def artifact(path: Path) -> dict:
        return dict(path=str(path.resolve()), exists=True,
                    bytes=path.stat().st_size, sha256=sha(path.read_bytes()))

    def call(self, verification_path: Path, edited_name="omnvars/mp/omnvars.csv"):
        return fastfiles._export_and_compare_stringtable_semantics(
            native=self.native, output=self.output, updated=b"decoded-body",
            verification_path=verification_path, zone_id="code_post_gfx",
            native_rows=[{"type_id": 54, "name": edited_name}],
            acts_path=self.root / "acts.exe", replay_executable=self.root / "replay.exe",
            timeout=20, source_index_path=self.root / "source-index.json",
            source_body_sha256=sha(b"source-body"), source_fastfile_sha256=sha(b"source-ff"),
            source_walk_key="source-walk", edited_name=edited_name,
            edited_asset_index=2538, expected_rows=[["key", "value"]])

    def patched_exporter(self, seen_roots: list[Path], mutate=None):
        def export(_source, _zone_id, _body, cache_path, _walk, _rows, *_args, **_kwargs):
            seen_roots.append(Path(cache_path))
            if mutate is not None:
                mutate()
            return self.export_root, {"items": []}
        return export

    def test_semantic_export_uses_each_fresh_verification_root(self):
        roots = []
        with mock.patch.object(fastfiles, "source_profile", return_value={
                "sha256": sha(self.output.read_bytes()), "patches": []}), \
             mock.patch.object(fastfiles.ZoneBody, "parse", return_value=object()), \
             mock.patch.object(fastfiles, "_export_native_type",
                               side_effect=self.patched_exporter(roots)), \
             mock.patch("workstation_stringtable_semantics.compare_stringtable_exports",
                        return_value={"status": "pass"}):
            first = self.root / "verify-one"
            second = self.root / "verify-two"
            first.mkdir()
            second.mkdir()
            self.call(first)
            self.call(second)
        self.assertEqual(roots, [first, second])
        self.assertNotEqual(roots[0], roots[1])

    def test_semantic_export_accepts_non_omnvar_stringtable_identity(self):
        roots = []
        with mock.patch.object(fastfiles, "source_profile", return_value={
                "sha256": sha(self.output.read_bytes()), "patches": []}), \
             mock.patch.object(fastfiles.ZoneBody, "parse", return_value=object()), \
             mock.patch.object(fastfiles, "_export_native_type",
                               side_effect=self.patched_exporter(roots)), \
             mock.patch("workstation_stringtable_semantics.compare_stringtable_exports",
                        return_value={"status": "pass"}):
            self.call(self.root / "verify-generic", "code_post_gfx/test_table.csv")
        self.assertEqual(roots, [self.root / "verify-generic"])

    def test_semantic_helper_is_pinned_in_omnvar_module_identity_set(self):
        modules = fastfiles._omnvar_helper_module_identities()
        self.assertIn("semantic_export", modules)
        self.assertEqual(Path(modules["semantic_export"]["path"]).name,
                         "workstation_stringtable_semantics.py")
        self.assertEqual(modules["semantic_export"]["sha256"],
                         sha(Path(modules["semantic_export"]["path"]).read_bytes()))

    def test_changed_sidecar_during_export_is_rejected(self):
        roots = []
        with mock.patch.object(fastfiles, "source_profile", return_value={
                "sha256": sha(self.output.read_bytes()), "patches": []}), \
             mock.patch.object(fastfiles.ZoneBody, "parse", return_value=object()), \
             mock.patch.object(fastfiles, "_export_native_type", side_effect=self.patched_exporter(
                 roots, lambda: self.output.with_suffix(".fp").write_bytes(b"changed-fp"))), \
             mock.patch("workstation_stringtable_semantics.compare_stringtable_exports",
                        return_value={"status": "pass"}):
            with self.assertRaisesRegex(ValueError, "candidate .fp changed"):
                self.call(self.root / "verify")

    def test_candidate_ff_drift_before_export_is_rejected(self):
        self.output.write_bytes(b"changed-header-or-body")
        roots = []
        with mock.patch.object(fastfiles, "source_profile", return_value={
                "sha256": sha(self.output.read_bytes()), "patches": []}), \
             mock.patch.object(fastfiles.ZoneBody, "parse", return_value=object()), \
             mock.patch.object(fastfiles, "_export_native_type",
                               side_effect=self.patched_exporter(roots)):
            with self.assertRaisesRegex(ValueError, "candidate .ff changed"):
                self.call(self.root / "verify")
        self.assertEqual(roots, [])

    def test_new_fc_during_export_is_rejected(self):
        roots = []
        with mock.patch.object(fastfiles, "source_profile", return_value={
                "sha256": sha(self.output.read_bytes()), "patches": []}), \
             mock.patch.object(fastfiles.ZoneBody, "parse", return_value=object()), \
             mock.patch.object(fastfiles, "_export_native_type", side_effect=self.patched_exporter(
                 roots, lambda: self.output.with_suffix(".fc").write_bytes(b"unexpected-fc"))), \
             mock.patch("workstation_stringtable_semantics.compare_stringtable_exports",
                        return_value={"status": "pass"}):
            with self.assertRaisesRegex(ValueError, "candidate .fc existence changed"):
                self.call(self.root / "verify")

    def test_raw_manifest_hash_is_checked_before_export(self):
        self.raw_manifest_path.write_text('{"journal":"assets.jsonl"}', encoding="utf-8")
        roots = []
        with mock.patch.object(fastfiles, "_export_native_type",
                               side_effect=self.patched_exporter(roots)):
            with self.assertRaisesRegex(ValueError, "raw manifest hash differs"):
                self.call(self.root / "verify")
        self.assertEqual(roots, [])

    def test_raw_manifest_drift_during_export_is_rejected(self):
        roots = []
        with mock.patch.object(fastfiles, "source_profile", return_value={
                "sha256": sha(self.output.read_bytes()), "patches": []}), \
             mock.patch.object(fastfiles.ZoneBody, "parse", return_value=object()), \
             mock.patch.object(fastfiles, "_export_native_type", side_effect=self.patched_exporter(
                 roots, lambda: self.raw_manifest_path.write_text("{}", encoding="utf-8"))), \
             mock.patch("workstation_stringtable_semantics.compare_stringtable_exports",
                        return_value={"status": "pass"}):
            with self.assertRaisesRegex(RuntimeError, "artifacts changed during semantic export"):
                self.call(self.root / "verify")


if __name__ == "__main__":
    unittest.main()
