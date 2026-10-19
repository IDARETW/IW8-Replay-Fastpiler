import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "setup_workstation_tools.py"
SPEC = importlib.util.spec_from_file_location("setup_workstation_tools", MODULE_PATH)
setup_tools = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup_tools)
TOOLCHAIN_SPEC = importlib.util.spec_from_file_location(
    "workstation_toolchain", ROOT / "workstation" / "toolchain.py")
toolchain = importlib.util.module_from_spec(TOOLCHAIN_SPEC)
TOOLCHAIN_SPEC.loader.exec_module(toolchain)
CODEC_SPEC = importlib.util.spec_from_file_location(
    "workstation_asset_codecs", ROOT / "tools" / "workstation_asset_codecs.py")
codecs = importlib.util.module_from_spec(CODEC_SPEC)
sys.modules[CODEC_SPEC.name] = codecs
CODEC_SPEC.loader.exec_module(codecs)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DxbcToolSelectionTests(unittest.TestCase):
    def make_root(self, root: Path) -> tuple[Path, Path]:
        manifest_source = ROOT / "tools" / "workstation_toolchain_manifest.json"
        manifest = json.loads(manifest_source.read_text(encoding="utf-8"))
        public = root / "tools/bin/cmd_Decompiler-1.3.16/cmd_Decompiler.exe"
        public.parent.mkdir(parents=True)
        public.write_bytes(b"public release fixture")
        public_hash = sha256(public)
        item = next(x for x in manifest["tools"] if x["id"] == "dxbc_decompiler")
        next(x for x in item["members"] if x["name"] == "cmd_Decompiler.exe")["sha256"] = public_hash

        source_package = ROOT / "third_party/3dmigoto-dxbc-1.3.16"
        target_package = root / "third_party/3dmigoto-dxbc-1.3.16"
        shutil.copytree(source_package, target_package)
        source_built = next(x for x in manifest["source_built"]
                            if x["id"] == "dxbc_decompiler_source")
        install = root / source_built["install_dir"]
        install.mkdir(parents=True)
        executable = install / "cmd_Decompiler.exe"
        executable.write_bytes(b"source-built fixture")
        receipt = {
            "schema": "replay120-dxbc-source-bootstrap-v1",
            "status": "pass",
            "source_package_manifest_sha256": source_built["source_package_manifest_sha256"],
            "source_patch_sha256": json.loads(
                (target_package / "source-package-manifest.json").read_text(encoding="utf-8")
            )["source_patch"]["sha256"],
            "executable": "cmd_Decompiler.exe",
            "output_sha256": sha256(executable),
        }
        (install / "bootstrap-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        tools = root / "tools"
        tools.mkdir(exist_ok=True)
        manifest_path = tools / "workstation_toolchain_manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, public

    def test_source_built_is_default_and_repeat_selection_is_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, public = self.make_root(root)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertIs(next(x for x in document["source_built"]
                               if x["id"] == "dxbc_decompiler_source")["install_default"], True)
            before = sha256(public)
            first = setup_tools.select_dxbc_tool(root, manifest_path=manifest)
            second = setup_tools.select_dxbc_tool(root, manifest_path=manifest)
            self.assertEqual(first, second)
            self.assertEqual(first["selection"], "source-built")
            self.assertEqual(first["source_package_manifest_sha256"],
                             "c3a4ff17cf7ab1ced0b0686d675a22d1109da2164f05a138b752efe248da400d")
            self.assertEqual(sha256(public), before)
            environment = toolchain.resolve_codec_environment(
                root, root / "game", tools={"dxbc": {"path": first["path"], "sha256": first["sha256"]}},
                environment={})
            self.assertEqual(environment["REPLAY_DXBC_TOOL"], first["path"])
            self.assertEqual(environment["REPLAY_DXBC_TOOL_SHA256"], first["sha256"])

    def test_explicit_source_build_selection_checks_receipt_and_preserves_public(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, public = self.make_root(root)
            before = sha256(public)
            first = setup_tools.select_dxbc_tool(root, use_source_built=True, manifest_path=manifest)
            second = setup_tools.select_dxbc_tool(root, use_source_built=True, manifest_path=manifest)
            self.assertEqual(first, second)
            self.assertEqual(first["selection"], "source-built")
            self.assertTrue(first["path"].endswith(".toolchains\\dxbc-compute-v1\\cmd_Decompiler.exe"))
            self.assertEqual(first["source_package_manifest_sha256"],
                             "c3a4ff17cf7ab1ced0b0686d675a22d1109da2164f05a138b752efe248da400d")
            self.assertEqual(sha256(public), before)
            environment = toolchain.resolve_codec_environment(
                root, root / "game", tools={"dxbc": {"path": first["path"], "sha256": first["sha256"]}},
                environment={})
            self.assertEqual(environment["REPLAY_DXBC_TOOL"], first["path"])
            self.assertEqual(environment["REPLAY_DXBC_TOOL_SHA256"], first["sha256"])

    def test_explicit_legacy_public_selection_is_hash_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, public = self.make_root(root)
            before = sha256(public)
            selected = setup_tools.select_dxbc_tool(root, use_source_built=False, manifest_path=manifest)
            self.assertEqual(selected["selection"], "public")
            self.assertEqual(selected["path"], str(public.resolve()))
            self.assertEqual(selected["sha256"], before)

    def test_changed_public_binary_is_not_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, public = self.make_root(root)
            public.write_bytes(b"changed public release fixture")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                setup_tools.select_dxbc_tool(root, use_source_built=False, manifest_path=manifest)

    def test_source_build_tamper_and_receipt_pin_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = self.make_root(root)
            executable = root / ".toolchains/dxbc-compute-v1/cmd_Decompiler.exe"
            executable.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                setup_tools.select_dxbc_tool(root, use_source_built=True, manifest_path=manifest)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest, _ = self.make_root(root)
            receipt_path = root / ".toolchains/dxbc-compute-v1/bootstrap-receipt.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["source_package_manifest_sha256"] = "0" * 64
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "receipt does not match"):
                setup_tools.select_dxbc_tool(root, use_source_built=True, manifest_path=manifest)

    def test_shader_capability_report_is_selected_tool_gated(self):
        shader = codecs.capability_report()["shader"]
        self.assertIn("configured, hash-verified DXBC tool", shader["reason"])
        self.assertIn("programs rejected by the configured DXBC round-trip tool", shader["read_only_cases"])
        self.assertNotIn("five otherwise stage-valid domain programs", shader["reason"])

    def test_setup_defaults_to_source_tool_and_preserves_explicit_legacy_choice(self):
        source = (ROOT / "setup-workstation.ps1").read_text(encoding="utf-8")
        self.assertIn("[switch]$UseLegacyPublicDxbc", source)
        self.assertIn("if ($UseLegacyPublicDxbc) { $dxbcSelectionArguments += '--use-public-dxbc' }", source)
        self.assertNotIn("UseSourceBuiltDxbc", source)
        self.assertIn("dxbc=@{path=$dxbcSelection.path; sha256=$dxbcSelection.sha256}", source)
        self.assertIn("Pinned codec tool installation failed.", source)
        self.assertIn(".toolchains\\dxbc-compute-v1", source)

    def test_bootstrap_invocation_passes_exact_destination_option(self):
        source = (ROOT / "setup-workstation.ps1").read_text(encoding="utf-8")
        compact = " ".join(source.split())
        expected = ("$dxbcBootstrapArguments = @((Join-Path $PSScriptRoot "
                    "'tools\\bootstrap_workstation_dxbc.py'), '--destination', $dxbcSource)")
        self.assertIn(expected, compact)
        self.assertIn("& $venvPython @dxbcBootstrapArguments", source)
        self.assertIn("if (-not $UseLegacyPublicDxbc) {", source)
        self.assertNotIn("bootstrap_workstation_dxbc.py') $dxbcSource", source)


if __name__ == "__main__":
    unittest.main()
