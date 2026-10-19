import os
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

TOOLS_ROOT = os.environ.get("REPLAY_FASTFILE_TOOLS_ROOT")
if TOOLS_ROOT:
    sys.path.insert(0, TOOLS_ROOT)
OVERLAY_TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(OVERLAY_TOOLS))

import roundtrip_replay_fastfile as reader
from roundtrip_replay_fastfile import _archive_reader_output, _create_shallow_reader_output


class ShallowNativeOutputTests(unittest.TestCase):
    def test_long_durable_root_uses_short_owned_reader_root_and_archives_tree(self):
        with tempfile.TemporaryDirectory(prefix="long-durable-output-") as parent:
            output_root = Path(parent)
            package = output_root / "code_post_gfx.ff"
            reader_root = _create_shallow_reader_output(package, 1)
            try:
                trace_path = reader_root / "mw19replay" / package.stem / "stream-trace.jsonl"
                self.assertLess(len(str(trace_path)), 240)
                trace_path.parent.mkdir(parents=True)
                trace_path.write_bytes(b"trace fixture\n")
                archived = _archive_reader_output(reader_root, output_root)
                self.assertEqual(archived, output_root / "mw19replay")
                self.assertEqual((archived / package.stem / "stream-trace.jsonl").read_bytes(), b"trace fixture\n")
                self.assertFalse((reader_root / "mw19replay").exists())
            finally:
                if reader_root.exists():
                    shutil.rmtree(reader_root)

    def test_archive_refuses_to_overwrite_existing_native_evidence(self):
        with tempfile.TemporaryDirectory(prefix="reader-archive-test-") as parent:
            root = Path(parent)
            reader_root = root / "short"
            output_root = root / "durable"
            source_tree = reader_root / "mw19replay"
            destination_tree = output_root / "mw19replay"
            source_tree.mkdir(parents=True)
            destination_tree.mkdir(parents=True)
            (source_tree / "new.json").write_text("new", encoding="utf-8")
            (destination_tree / "old.json").write_text("old", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                _archive_reader_output(reader_root, output_root)
            self.assertTrue((source_tree / "new.json").is_file())
            self.assertEqual((destination_tree / "old.json").read_text(encoding="utf-8"), "old")

    def test_archive_rejects_source_or_destination_symlink_escape(self):
        with tempfile.TemporaryDirectory(prefix="reader-escape-test-") as parent:
            root = Path(parent)
            reader_root = root / "short"
            output_root = root / "durable"
            outside = root / "outside"
            outside.mkdir()
            reader_root.mkdir()
            output_root.mkdir()
            try:
                (reader_root / "mw19replay").symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "escaped its owned temporary root"):
                _archive_reader_output(reader_root, output_root)
            (reader_root / "mw19replay").unlink()
            (output_root / "mw19replay").symlink_to(outside, target_is_directory=True)
            (reader_root / "mw19replay").mkdir()
            (reader_root / "mw19replay" / "trace.jsonl").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escaped its requested evidence root"):
                _archive_reader_output(reader_root, output_root)
            self.assertTrue((reader_root / "mw19replay" / "trace.jsonl").is_file())

    def _fake_reader_run(self, output_root, *, collide=False, error=None, returncode=0):
        def run(command, stdout, stderr, timeout, check):
            input_path = Path(command[-1])
            self.assertEqual(input_path.name, "candidate.ff")
            reader_root = Path(command[command.index("-o") + 1])
            self.assertLess(len(str(reader_root / "mw19replay" / "zone" / "stream-trace.jsonl")), 240)
            native_zone = reader_root / "mw19replay" / "zone"
            native_zone.mkdir(parents=True)
            manifest = {
                "complete": True, "success": True, "profile": "replay-1.20",
                "xfile_version": 0xFF7, "tested": 2, "failed": 0,
                "unavailable": 0, "top_level_index": 2,
                "serialized_bytes_read": 8, "loaded_assets": 2,
                "journal": "assets.jsonl",
            }
            (native_zone / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (native_zone / "assets.jsonl").write_text(
                '{"type_id":11,"name":"one"}\n{"type_id":11,"name":"two"}\n',
                encoding="utf-8")
            if collide:
                collision = output_root / "mw19replay"
                collision.mkdir(parents=True)
                (collision / "keep.json").write_text("preserve", encoding="utf-8")
            if error is not None:
                raise error
            return SimpleNamespace(returncode=returncode)
        return run

    def _run_mocked_verify(self, output_root, fake_run, *, long_input=False, include_fp=True):
        root = output_root.parent / "verify-inputs"
        root.mkdir(exist_ok=True)
        if long_input:
            root = root / ("deep-input-root-" + "x" * 74) / ("nested-owner-" + "y" * 68) / ("package-stage-" + "z" * 60)
            root.mkdir(parents=True)
        package = root / "candidate.ff"
        source = root / "source.ff"
        acts = root / "acts.exe"
        replay = root / "replay.exe"
        for path in (package, source, acts, replay):
            path.write_bytes(b"fixture")
        if long_input and include_fp:
            package.with_suffix(".fp").write_bytes(b"exact patch fixture")

        class FakeBody:
            assets = [SimpleNamespace(index=0, type_id=11), SimpleNamespace(index=1, type_id=11)]

        with (mock.patch.object(reader, "acts_tool_identity", return_value={"sha256": "a"}),
              mock.patch.object(reader, "source_profile", return_value={"sha256": "b"}),
              mock.patch.object(reader, "_assert_run_inputs_unchanged"),
              mock.patch.object(reader.ZoneBody, "parse", return_value=FakeBody()),
              mock.patch.object(reader.subprocess, "run", side_effect=fake_run)):
            return reader.verify_native(package, b"12345678", source, acts, replay,
                                        output_root, timeout=30)

    def test_verify_native_uses_short_reader_path_and_archives_to_long_evidence_root(self):
        with tempfile.TemporaryDirectory(prefix="long-cache-root-") as parent:
            output_root = Path(parent)
            for index in range(4):
                output_root = output_root / (f"nested-evidence-directory-{index}-" + "x" * 28)
            output_root.mkdir(parents=True)
            self.assertGreater(len(str(output_root / "mw19replay" / "zone" / "stream-trace.jsonl")), 240)
            native_output = self._fake_reader_run(output_root)
            fake_run = native_output
            result = self._run_mocked_verify(output_root, fake_run)
            self.assertEqual(result["manifest"]["tested"], 2)
            self.assertEqual(result["native_output_root"], str(output_root / "mw19replay"))
            self.assertTrue((output_root / "mw19replay" / "zone" / "manifest.json").is_file())
            invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
            self.assertEqual(invocation["status"], "archived")
            self.assertLess(invocation["expected_trace_path_length"], 240)
            self.assertGreaterEqual(invocation["required_free_bytes"], 2 * 1024 * 1024 * 1024)

    def test_long_input_is_staged_with_exact_basename_and_fp_then_cleaned(self):
        with tempfile.TemporaryDirectory(prefix="long-input-evidence-") as parent:
            output_root = Path(parent) / "verify"
            output_root.mkdir()
            observed = {}
            base_run = self._fake_reader_run(output_root)

            def run(command, **kwargs):
                staged = Path(command[-1])
                self.assertLess(len(str(staged)), 220)
                self.assertEqual(staged.name, "candidate.ff")
                self.assertEqual(staged.read_bytes(), b"fixture")
                self.assertEqual(staged.with_suffix(".fp").read_bytes(), b"exact patch fixture")
                observed["stage_root"] = staged.parent
                return base_run(command, **kwargs)

            result = self._run_mocked_verify(output_root, run, long_input=True)
            self.assertEqual(result["candidate_artifacts"][".ff"]["sha256"],
                             __import__("hashlib").sha256(b"fixture").hexdigest())
            self.assertFalse(observed["stage_root"].exists())
            invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
            self.assertEqual(invocation["input_staging"]["status"], "staged")
            self.assertTrue(invocation["input_staging"]["canonical_basename_preserved"])
            self.assertEqual(invocation["input_staging"]["files"][".fp"]["sha256"],
                             __import__("hashlib").sha256(b"exact patch fixture").hexdigest())
            self.assertEqual(invocation["staged_input_cleanup"], "removed")

    def test_long_input_rejects_new_sidecar_created_during_native_read(self):
        with tempfile.TemporaryDirectory(prefix="new-sidecar-evidence-") as parent:
            output_root = Path(parent) / "verify"
            output_root.mkdir()
            observed = {}
            base_run = self._fake_reader_run(output_root)

            def run(command, **kwargs):
                staged = Path(command[-1])
                observed["stage_root"] = staged.parent
                staged.with_suffix(".fp").write_bytes(b"unexpected patch")
                return base_run(command, **kwargs)

            try:
                with self.assertRaisesRegex(ValueError, "changed the private staged"):
                    self._run_mocked_verify(output_root, run, long_input=True, include_fp=False)
                invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
                self.assertEqual(invocation["input_stage_status"], "staged-input-changed")
                self.assertTrue(invocation["staged_inputs_after"][".fp"]["exists"])
                self.assertEqual(invocation["staged_inputs_after"][".fp"]["bytes"], len(b"unexpected patch"))
            finally:
                if observed.get("stage_root") and observed["stage_root"].exists():
                    shutil.rmtree(observed["stage_root"])

    def test_exit_zero_parsed_zero_without_manifest_gets_specific_diagnosis(self):
        with tempfile.TemporaryDirectory(prefix="parsed-zero-reader-") as parent:
            output_root = Path(parent) / "verify"
            output_root.mkdir()

            def parsed_zero(command, stdout, stderr, timeout, check):
                stdout.write("Atian tools dev-3.3.0 CLI\nParsed 0 (0x0) file(s)\n")
                return SimpleNamespace(returncode=0)

            with self.assertRaisesRegex(ValueError, "exited 0 but parsed 0 files"):
                self._run_mocked_verify(output_root, parsed_zero)
            invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
            self.assertEqual(invocation["status"], "reader-parsed-zero-no-manifest")
            self.assertIn("not consumed", invocation["diagnosis"])

    def test_timeout_preserves_and_archives_partial_native_output(self):
        with tempfile.TemporaryDirectory(prefix="timeout-output-") as parent:
            output_root = Path(parent) / "verify"
            output_root.mkdir()
            timeout = subprocess.TimeoutExpired(["acts"], 1)
            with self.assertRaises(subprocess.TimeoutExpired):
                self._run_mocked_verify(output_root, self._fake_reader_run(output_root, error=timeout))
            self.assertTrue((output_root / "mw19replay" / "zone" / "manifest.json").is_file())
            invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
            self.assertEqual(invocation["status"], "partial-archived")
            self.assertIn("TimeoutExpired", invocation["run_error"])

    def test_nonzero_reader_archives_output_and_records_failure_status(self):
        with tempfile.TemporaryDirectory(prefix="nonzero-reader-") as parent:
            output_root = Path(parent) / "verify"
            output_root.mkdir()
            with self.assertRaisesRegex(RuntimeError, "Replay reader returned 3"):
                self._run_mocked_verify(output_root,
                                        self._fake_reader_run(output_root, returncode=3))
            self.assertTrue((output_root / "mw19replay" / "zone" / "manifest.json").is_file())
            invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
            self.assertEqual(invocation["status"], "reader-failed-archived")
            self.assertEqual(invocation["return_code"], 3)

    def test_archive_collision_preserves_both_existing_and_partial_outputs(self):
        with tempfile.TemporaryDirectory(prefix="archive-collision-") as parent:
            output_root = Path(parent) / "verify"
            output_root.mkdir()
            with self.assertRaises(FileExistsError):
                self._run_mocked_verify(output_root,
                                        self._fake_reader_run(output_root, collide=True))
            self.assertEqual((output_root / "mw19replay" / "keep.json").read_text(encoding="utf-8"),
                             "preserve")
            invocation = json.loads((output_root / "reader-output-location.json").read_text(encoding="utf-8"))
            self.assertEqual(invocation["status"], "archive-failed")
            self.assertTrue(any(Path(invocation["temporary_output_root"]).glob("mw19replay/zone/manifest.json")))


if __name__ == "__main__":
    unittest.main()

