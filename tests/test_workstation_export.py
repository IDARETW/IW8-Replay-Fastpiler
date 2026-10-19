import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "export_workstation.py"
PROJECT_ROOT = MODULE_PATH.parents[1]
SPEC = importlib.util.spec_from_file_location("export_workstation", MODULE_PATH)
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


class WorkstationExportTests(unittest.TestCase):
    def make_fixture(self, root: Path) -> None:
        for area in ("src", "tools", "tests", "workstation/web", "analysis/replay120",
                     "third_party/acts-patches"):
            (root / area).mkdir(parents=True, exist_ok=True)
        (root / "workstation/toolchain.py").write_bytes(
            (PROJECT_ROOT / "workstation/toolchain.py").read_bytes())
        for relative in exporter.ROOT_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        for relative in exporter.SEED_FILES:
            (root / "analysis/replay120" / relative).write_bytes(b"seed")
        (root / "analysis/replay120/proxy-signatures.json").write_text(
            json.dumps([{"source": "D:" + chr(92) + "private" + chr(92) + "checkout" + chr(92) + "game.h"}]) + "\n",
            encoding="utf-8")
        (root / "analysis/replay120/seed.json").write_text(json.dumps({
            "schema": 1, "files": {"proxy-signatures.json": "stale-private-hash"}}) + "\n",
            encoding="utf-8")
        (root / "third_party/acts-patches/acts-replay-workstation.patch").write_bytes(b"patch")
        (root / "third_party/acts-patches/manifest.json").write_text("{}\n", encoding="utf-8")
        for relative in exporter.PINNED_FILES:
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            source = PROJECT_ROOT / relative
            target = root / relative
            if source.is_file():
                target.write_bytes(source.read_bytes())
            else:
                target.write_text("toolchain pin\n", encoding="utf-8")
        for relative in exporter.class0_field_fixture_files(PROJECT_ROOT):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((PROJECT_ROOT / relative).read_bytes())
        source_package = PROJECT_ROOT / exporter.DXBC_SOURCE_PACKAGE_ROOT
        target_package = root / exporter.DXBC_SOURCE_PACKAGE_ROOT
        shutil.copytree(source_package, target_package)
        (root / "src" / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
        (root / "tools" / "recover.py").write_text("# source\n", encoding="utf-8")
        (root / "tools" / "workstation_lua_compile.py").write_text("# portable Lua compiler wrapper\n", encoding="utf-8")
        for name in exporter.TOOL_ENTRYPOINTS:
            path = root / "tools" / name
            if not path.exists():
                path.write_text("# portable entry point fixture\n", encoding="utf-8")
        for name in exporter.TOOL_SCRIPT_ENTRYPOINTS:
            path = root / "tools" / name
            if not path.exists():
                path.write_text("# portable script fixture\n", encoding="utf-8")
        for name in exporter.TOOL_SOURCE_ENTRYPOINTS:
            path = root / 'tools' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// portable native source fixture\n')
        for relative in exporter.PORTABLE_TEST_ENTRYPOINTS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("'use strict';\nprocess.stdout.write('portable restore test\\n');\n",
                            encoding='utf-8')
        (root / "workstation/web" / "index.html").write_text("<html></html>\n", encoding="utf-8")
        (root / "workstation/web/vendor").mkdir()
        (root / "workstation/web/vendor" / "private-editor.js").write_text("large vendor", encoding="utf-8")
        (root / "assets").mkdir()
        (root / "assets" / "private.ff").write_bytes(b"asset")
        (root / "generated").mkdir()
        (root / "generated" / "manifest.json").write_text("{}\n", encoding="utf-8")
        (root / "replay-project.local.json").write_text("{}\n", encoding="utf-8")
        (root / "tools/fixtures/private-decompiled.lua").write_text("private game source", encoding="utf-8")

    def test_exports_only_reviewed_source_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source, destination = base / "source", base / "export"
            source.mkdir()
            self.make_fixture(source)
            receipt = exporter.export_workstation(source, destination)
            files = {row["path"] for row in receipt["files"]}
            self.assertIn("src/main.cpp", files)
            self.assertIn("analysis/replay120/code-items.bin", files)
            self.assertIn("workstation/web/index.html", files)
            self.assertIn("third_party/acts-patches/acts-replay-workstation.patch", files)
            self.assertIn("tools/workstation_toolchain_manifest.json", files)
            self.assertIn("tools/workstation_script_string_manifest.json", files)
            self.assertIn("tools/workstation_gsc_fields.py", files)
            self.assertIn("tools/workstation_gsc_fields_class0.json", files)
            self.assertIn("tests/fixtures/scriptfile-class0/manifest.json", files)
            self.assertEqual(sum(path.startswith("tests/fixtures/scriptfile-class0/class0_probe_")
                                 and path.endswith(".gscbin") for path in files), 16)
            self.assertEqual(sum(path.startswith("tests/fixtures/scriptfile-class0/class0_probe_")
                                 and path.endswith(".gsc") for path in files), 16)
            self.assertIn("tools/workstation_script_source_pack.template.json", files)
            self.assertIn("tools/bootstrap_workstation_dxbc.py", files)
            self.assertIn("workstation/toolchain.py", files)
            self.assertIn("third_party/3dmigoto-dxbc-1.3.16/source-package-manifest.json", files)
            for relative in exporter.DXBC_SOURCE_PACKAGE_REQUIRED_FILES:
                self.assertIn(f"third_party/3dmigoto-dxbc-1.3.16/{relative}", files)
            self.assertIn("tests/synthetic_bootstrap_smoke.py", files)
            self.assertIn("tests/cli_strict_container.py", files)
            dxbc_download = next(row for row in receipt["downloads"]
                                 if row["name"] == "3Dmigoto DXBC source-built CLI")
            self.assertIn("only through explicit legacy selection", dxbc_download["source"])
            self.assertNotIn("public DXBC release remains the setup default", dxbc_download["source"])
            self.assertNotIn("fixtures/corpus318/fixture-receipt.json", files)
            self.assertNotIn("upstream/D3D_Shaders/Assembler.cpp", files)
            self.assertIn("tools/fixtures/replay120-lua-allocator-growth.lua", files)
            self.assertIn("tools/workstation_lua_compile.py", files)
            self.assertIn("tools/backend_tests.py", files)
            self.assertIn("tools/repack_workstation_luafile.py", files)
            self.assertIn("tools/native/replay_link_stages.hpp", files)
            self.assertIn("tests/test_workstation_restore_initializer.js", files)
            self.assertIn("tests/test_workstation_game_source_tree.js", files)
            self.assertIn("tests/test_workstation_tree_navigation.js", files)
            self.assertEqual(
                (destination / "tests/test_workstation_restore_initializer.js").read_bytes(),
                (source / "tests/test_workstation_restore_initializer.js").read_bytes())
            self.assertEqual(
                (destination / "tools/fixtures/replay120-lua-allocator-growth.lua").read_bytes(),
                (source / "tools/fixtures/replay120-lua-allocator-growth.lua").read_bytes())
            self.assertNotIn("tools/fixtures/private-decompiled.lua", files)
            self.assertNotIn("workstation/web/vendor/private-editor.js", files)
            self.assertFalse((destination / "assets/private.ff").exists())
            self.assertFalse((destination / "generated/manifest.json").exists())
            self.assertFalse((destination / "replay-project.local.json").exists())
            manifest = json.loads((destination / "EXPORT-MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["files"], receipt["files"])
            self.assertEqual(manifest["downloads"][1]["version"], "0.57.0")
            self.assertNotIn("source_root", manifest)
            portable_proxy = destination / "analysis/replay120/proxy-signatures.json"
            self.assertNotIn("private", portable_proxy.read_text(encoding="utf-8"))
            self.assertIn("game.h", portable_proxy.read_text(encoding="utf-8"))
            portable_seed = json.loads((destination / "analysis/replay120/seed.json").read_text())
            self.assertEqual(portable_seed["files"]["proxy-signatures.json"],
                             exporter.sha256(portable_proxy))
            self.assertEqual(manifest["structured_normalizations"][0]["field"], "source")
            self.assertEqual(manifest["structured_normalizations"][0]["rows"], 1)
            for row in manifest['files']:
                exported = destination / row['path']
                self.assertEqual(row['size'], exported.stat().st_size)
                self.assertEqual(row['sha256'], exporter.sha256(exported))

    def test_portable_tests_include_safe_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_fixture(root)
            (root / 'tools/safe_helper.py').write_text('def available(): return True\n')
            private_marker = "D:" + chr(92) + "mw124" + chr(92) + "checkout"
            self.assertTrue(exporter.contains_private_path(private_marker.encode()))
            (root / 'tools/local_diagnostic.py').write_text(
                'PATH = ' + repr(private_marker) + '\n')
            (root / 'tests/test_safe.py').write_text('from tools import safe_helper\n')
            (root / 'tests/test_local.py').write_text('from tools.local_diagnostic import PATH\n')
            (root / 'tests/native_harness.cpp').write_text('int main() { return 0; }\n')
            files = {path.as_posix() for path in exporter.collect_source_files(root)}
            self.assertIn('tests/test_safe.py', files)
            self.assertIn('tools/safe_helper.py', files)
            self.assertIn('tests/native_harness.cpp', files)
            self.assertNotIn('tests/test_local.py', files)
            self.assertNotIn('tools/local_diagnostic.py', files)

    def test_private_path_detector_handles_separator_and_quoted_root_forms(self):
        one = chr(92)
        paths = (
            'D:' + one + 'mw124',
            'D:' + '/' + 'mw124',
            'D:' + one * 2 + 'mw124',
            'E:' + one + 'replay-compiler',
            'C:' + one + 'Users' + one + 'generic-user',
        )
        for path in paths:
            with self.subTest(path_kind=path.split(':', 1)[0]):
                self.assertTrue(exporter.contains_private_path(path.encode()))
                self.assertTrue(exporter.contains_private_path(json.dumps(path).encode()))
                self.assertTrue(exporter.contains_private_path((path + one + 'child').encode()))


    def test_refuses_in_tree_and_nonempty_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            self.make_fixture(source)
            with self.assertRaisesRegex(ValueError, "outside the source tree"):
                exporter.export_workstation(source, source / "export")
            destination = base / "nonempty"
            destination.mkdir()
            (destination / "keep.txt").write_text("keep")
            with self.assertRaisesRegex(ValueError, "new or empty"):
                exporter.export_workstation(source, destination)

    def test_required_portable_node_regression_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_fixture(root)
            portable_test = root / "tests/test_workstation_restore_initializer.js"
            portable_test.unlink()
            with self.assertRaisesRegex(ValueError, "Required portable test is missing or linked"):
                exporter.collect_source_files(root)

            portable_test.write_text(
                "const path = 'D:" + chr(92) + "mw124" + chr(92) + "private';\n",
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Portable test embeds a private checkout path"):
                exporter.collect_source_files(root)

    def test_changed_pinned_dxbc_member_blocks_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            self.make_fixture(root)
            member = root / "third_party/3dmigoto-dxbc-1.3.16/D3D_Shaders/Assembler.cpp"
            member.write_bytes(member.read_bytes() + b"// tampered\n")
            with self.assertRaisesRegex(ValueError, "member is missing, linked, or changed"):
                exporter.collect_source_files(root)

    def test_changed_class0_authored_fixture_blocks_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            self.make_fixture(root)
            fixture = root / "tests/fixtures/scriptfile-class0/class0_probe_3.gsc"
            fixture.write_text("class0_probe_3() { self.other = 1; return; }\\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fixture bytes differ|not the pinned self-field"):
                exporter.class0_field_fixture_files(root)

    def test_changed_class0_contract_blocks_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            self.make_fixture(root)
            contract = root / "tools/workstation_gsc_fields_class0.json"
            contract.write_bytes(contract.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "generated field contract.*changed"):
                exporter.class0_field_fixture_files(root)

    def test_fixture_manifest_must_match_pinned_native_field_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            self.make_fixture(root)
            manifest = root / "tests/fixtures/scriptfile-class0/manifest.json"
            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["cases"][2]["token"] = "0x2c6"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fixture order or descriptor identity"):
                exporter.class0_field_fixture_files(root)


if __name__ == "__main__":
    unittest.main()
