from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(1, str(ROOT / "tools"))

from workstation.config import load_paths
from workstation.project import Project
from tools import build as build_module


class WorkstationStorageRootTests(unittest.TestCase):
    def test_path_defaults_preserve_project_root_and_output_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = load_paths(root)
        self.assertEqual(paths["build_root"], root.resolve())
        self.assertEqual(paths["publication_root"], (root / "output").resolve())

    def test_relative_configured_build_and_publication_roots_resolve_under_project(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "replay-project.local.json").write_text(json.dumps({
                "schema": 1, "build_root": "scratch/build", "publication_root": "scratch/published"
            }), encoding="utf-8")
            paths = load_paths(root)
        self.assertEqual(paths["build_root"], (root / "scratch/build").resolve())
        self.assertEqual(paths["publication_root"], (root / "scratch/published").resolve())

    def test_build_output_root_flag_preserves_default_and_supports_external_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            project_root = Path(temp) / "project"
            external_root = Path(temp) / "D-stage"
            original_root = build_module.ROOT
            try:
                build_module.ROOT = project_root
                self.assertEqual(build_module.build_output_directory("build-job"),
                                 project_root / "build-job")
                self.assertEqual(build_module.build_output_directory("build-job", external_root),
                                 external_root.resolve() / "build-job")
            finally:
                build_module.ROOT = original_root

    def test_build_output_root_rejects_absolute_and_parent_escape_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "stage"
            absolute = Path(temp) / "outside"
            with self.assertRaisesRegex(ValueError, "within the configured output root"):
                build_module.build_output_directory(str(absolute), root)
            with self.assertRaisesRegex(ValueError, "within the configured output root"):
                build_module.build_output_directory("nested/../../outside", root)

    def test_build_output_root_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root, outside = base / "stage", base / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "escape"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks are unavailable on this host")
            with self.assertRaisesRegex(ValueError, "escapes the configured output root"):
                build_module.build_output_directory("escape/build-job", root)

    def test_external_build_record_paths_are_resolved_without_project_root_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            external = Path(temp) / "external-build"
            source, obj = external / "asm" / "example.asm", external / "example.obj"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"source")
            obj.write_bytes(b"object")
            original_root = build_module.ROOT
            try:
                build_module.ROOT = root
                self.assertEqual(build_module._resolve_build_record_path(str(source)), source.resolve())
                self.assertEqual(build_module._resolve_build_record_path(str(obj)), obj.resolve())
            finally:
                build_module.ROOT = original_root

    def test_external_source_path_can_be_used_for_unique_object_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            original_root = build_module.ROOT
            try:
                build_module.ROOT = Path(temp) / "project"
                external_source = Path(temp) / "D-stage" / "overlay" / "same.cpp"
                self.assertEqual(build_module._source_path_key(external_source),
                                 str(external_source.resolve()).replace("\\", "/"))
            finally:
                build_module.ROOT = original_root

    def test_dispatch_pins_storage_roots_and_worker_rehydrates_them(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            cache, game, database = Path(temp) / "cache", Path(temp) / "game", Path(temp) / "db.sqlite"
            build_root, publication_root = Path(temp) / "D-stage", Path(temp) / "D-publish"
            paths = dict(tools={}, proxy_source=None, build_root=build_root,
                         publication_root=publication_root)
            with mock.patch("workstation.project.load_paths", return_value=paths), \
                 mock.patch("workstation.project.threading.Thread"):
                project = Project(root, cache, game, database, codec_environment={})
                job = project.start_build("engine")
                directory = project.jobs_dir / job["id"]
                inputs = json.loads((directory / "worker-inputs.json").read_text())
                self.assertEqual(inputs["build_root"], str(build_root.resolve()))
                self.assertEqual(inputs["publication_root"], str(publication_root.resolve()))
                changed_config = dict(paths, build_root=Path(temp) / "changed", publication_root=Path(temp) / "changed-output")
                with mock.patch("workstation.project.load_paths", return_value=changed_config):
                    worker = Project(inputs["root"], inputs["cache"], inputs["game"], inputs["sqlite"],
                                     inputs.get("acts"), build_root=inputs["build_root"],
                                     publication_root=inputs["publication_root"], recover_jobs=False,
                                     codec_environment=inputs.get("codec_environment"))
                self.assertEqual(worker.build_root, build_root.resolve())
                self.assertEqual(worker.publication_root, publication_root.resolve())

    def test_external_build_and_atomic_publication_use_configured_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            build_root = Path(temp) / "D-build"
            publication_root = Path(temp) / "D-published"
            paths = dict(tools={}, proxy_source=None, build_root=build_root,
                         publication_root=publication_root)
            with mock.patch("workstation.project.load_paths", return_value=paths), \
                 mock.patch("workstation.project.threading.Thread"):
                project = Project(root, Path(temp) / "cache", Path(temp) / "game",
                                  Path(temp) / "db.sqlite", codec_environment={})
                job = project.start_build("engine")
                build_name = "build-workstation-" + job["id"]
                build = build_root / build_name
                exe = b"external-root-published-executable"
                exe_hash = hashlib.sha256(exe).hexdigest()

                def run_command(arguments, **kwargs):
                    command_path = Path(arguments[1])
                    if command_path.name == "build.py":
                        self.assertIn("--output-root", arguments)
                        self.assertEqual(Path(arguments[arguments.index("--output-root") + 1]), build_root.resolve())
                        self.assertEqual(arguments[arguments.index("--output") + 1], build_name)
                        build.mkdir(parents=True)
                        (build / "game_dx12_ship_replay_recompiled.exe").write_bytes(exe)
                        for name, payload in (
                            ("build-report.json", {"sha256": exe_hash}),
                            ("verification-report.json", {"sha256": exe_hash, "unresolved_symbols": 0}),
                            ("relocation-audit.json", {"sha256": exe_hash, "passed": True}),
                        ):
                            (build / name).write_text(json.dumps(payload), encoding="utf-8")
                    return mock.Mock(returncode=0)

                with mock.patch("workstation.project.subprocess.run", side_effect=run_command):
                    project._build(job)

                result = project.job(job["id"])
                output = publication_root / job["id"]
                self.assertEqual(result["status"], "succeeded", result.get("error"))
                self.assertEqual(Path(result["output_directory"]), output.resolve())
                self.assertEqual((output / "game_dx12_ship_replay.exe").read_bytes(), exe)
                self.assertEqual(result["artifacts"][0]["sha256"], exe_hash)
                self.assertEqual(output.drive, publication_root.drive)
                self.assertTrue(build.is_dir())
                self.assertFalse((root / "output").exists())
                self.assertFalse((publication_root / f".{job['id']}.pending").exists())


if __name__ == "__main__":
    unittest.main()
