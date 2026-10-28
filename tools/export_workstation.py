"""Create a source-only workstation handoff with a strict path allowlist.

The Replay executable and SQLite are supplied separately by the recipient.
Derived outputs, caches, private evidence, assets and locally installed tools
are deliberately not exported.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_EXTENSIONS = {".py", ".cpp", ".c", ".h", ".hpp", ".ps1", ".html", ".css", ".js"}
EXCLUDED_DIRS = {
    ".git", ".venv", "__pycache__", "bin", "build", "dist", "node_modules",
    "vendor", "generated", "cache", "evidence", "assets", "output", "temp",
}
EXCLUDED_FILENAMES = {
    "replay-project.local.json", ".workstation-compiler.lock",
    "analysis.sqlite", "game_dx12_ship_replay.exe", "acts.exe",
}
ROOT_FILES = (
    ".gitignore", "README.md", "WORKSTATION.md", "requirements.txt",
    "source-units.json", "build.ps1", "setup-workstation.ps1",
    "start-workstation.ps1", "restart-workstation.ps1", "prepare-run.ps1",
)
OPTIONAL_DOCUMENTS = (
    "AGENTS.md", ".gitattributes", "CONTRIBUTING.md", "THIRD_PARTY_NOTICES.md",
    "docs/ARCHITECTURE.md", "src/.gitkeep",
    "CPP-RECOVERY.md", "ReplayCpp.code-workspace",
    "src/recovered/I_stricmp.cpp", "src/recovered/I_stristr.cpp",
    "src/recovered/Vec3Normalize.cpp", "src/recovered/ReplayUtilityLayouts.h",
)
SEED_FILES = (
    "seed.json", "code-items.bin", "noncode-items.bin", "ida-rva-fixups.bin",
    "ida-switch-references.json", "ida-immediate-references.json", "ida-code-report.json",
    "proxy-signatures.json",
)
PINNED_FILES = (
    "tests/workstation-one-run-checklist.txt",
    "tools/workstation_toolchain_manifest.json",
    "tools/workstation_script_string_manifest.json",
    "tools/workstation_gsc_fields_class0.json",
    "tools/workstation_reader_identity_baseline.json",
    "tests/fixtures/scriptfile-class0/manifest.json",
    "tools/workstation_script_source_pack.template.json",
    # Setup executes this target-Lua allocator regression before accepting
    # the compiler. Keep it explicit rather than exporting arbitrary Lua
    # assets or locally decompiled game scripts.
    "tools/fixtures/replay120-lua-allocator-growth.lua",
    # New setups use the source-built DXBC CLI. Export its pinned bootstrap and
    # portable tests without exporting game-derived shader fixtures.
    "tools/bootstrap_workstation_dxbc.py",
    "tests/test_bootstrap_workstation_dxbc.py",
    "tests/test_workstation_dxbc_tool_selection.py",
    "tests/synthetic_bootstrap_smoke.py",
    "tests/cli_strict_container.py",
)
DXBC_SOURCE_PACKAGE_ROOT = Path("third_party/3dmigoto-dxbc-1.3.16")
DXBC_SOURCE_PACKAGE_MANIFEST_SHA256 = "c3a4ff17cf7ab1ced0b0686d675a22d1109da2164f05a138b752efe248da400d"
DXBC_SOURCE_PACKAGE_REQUIRED_FILES = {
    "D3D_Shaders/Assembler.cpp", "D3D_Shaders/SignatureParser.cpp",
    "D3D_Shaders/stdafx.h", "D3D_Shaders/targetver.h", "log.h", "shader.h",
    "portable_dxbc_cli.cpp", "source-fix.patch", "LICENSE.GPL.txt",
    "LICENSE.MIT.txt", "COPYING.txt", "AUTHORS.txt", "README.md",
}
TOOL_ENTRYPOINTS = (
    'cpp_recovery.py',
    'setup_cpp_recovery.py',
    'test_cpp_recovery_pilot.py',
    'evaluate_striga.py',
    'run_recovered_cpp.py',
    'prepare_cpp_runtime_proxy.py',
    'probe_recovered_cpp_live.py',
    'backend_tests.py',
    'layout_tests.py',
    'image_reference_tests.py',
    'source_provenance_tests.py',
    'audit_relocations.py',
    'bootstrap_workstation_acts.py',
    'bootstrap_workstation_dxbc.py',
    'bootstrap_workstation_lua.py',
    'bootstrap_workstation_string_decryptor.py',
    'build.py',
    'export_workstation.py',
    'prepare_workstation.py',
    'proxy_patterns.py',
    'setup_workstation_tools.py',
    'run_compiler_locked.py',
    'workstation_build_job.py',
    'run_cpp_flow_recovery.py',
    'ida_recover_cpp_flow.py',
    'adopt_ida_snapshot.py',
    'setup_workstation_ui.py',
    'source_provenance.py',
    'stage_frontend_meshes.py',
    'verify.py',
    'verify_replay_lua_native_compile.py',
    'workstation_preflight.py',
    'workstation_gsc_fields.py',
    'workstation_lua_compile.py',
    'generate_workstation_reader_identity_baseline.py',
    'workstation_fastfiles.py',
    'workstation_global_sources.py',
    'workstation_sources.py',
    'workstation_zone_merge.py',
    'workstation_scriptstring_table.py',
    'repack_workstation_luafile.py',
    'repack_workstation_luafile_batch.py',
    'repack_workstation_mixed_script_luafile.py',
    'repack_workstation_scriptfile.py',
)
TOOL_SCRIPT_ENTRYPOINTS = ("prepare_run_custom_maps.ps1",)
TOOL_SOURCE_ENTRYPOINTS = (
    'native/replay_linker.cpp',
    'native/replay_link_stages.hpp',
    'native/README.md',
)
# This dependency-free Node regression protects initializer restore behavior
# and belongs in the portable handoff rather than the local diagnostic set.
PORTABLE_TEST_ENTRYPOINTS = (
    "tests/test_workstation_restore_initializer.js",
    "tests/test_workstation_asset_create_ui.js",
    "tests/test_workstation_asset_actions_ui.js",
    "tests/test_workstation_soundbank_ui.js",
    "tests/test_workstation_image_loading_ui.js",
    "tests/test_workstation_game_source_tree.js",
    "tests/test_workstation_tree_navigation.js",
)
PRIVATE_PATH_PATTERNS = (
    re.compile(
        rb"(?i)\b[a-z]:(?:[\\/]+)"
        rb"(?:users[\\/]+[^\\/\"'\r\n]+|mw124|replay-compiler)"
        rb"(?:[\\/]+|(?=[\"'\s]|$))"
    ),
)


def contains_private_path(data: bytes) -> bool:
    """Reject source/test fixtures that embed machine-local checkout paths."""
    return any(pattern.search(data) for pattern in PRIVATE_PATH_PATTERNS)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_reparse_or_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def _local_python_dependencies(root: Path, initial: list[Path]) -> set[Path]:
    """Resolve repo-local imports for the portable workstation entry points."""
    queued, result = list(initial), set()
    while queued:
        relative = queued.pop()
        if relative in result:
            continue
        source = root / relative
        if not source.is_file():
            raise ValueError(f"Required portable source is missing: {relative}")
        result.add(relative)
        if relative.suffix != ".py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(relative))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.level:
                    parent = relative.parent
                    for _ in range(node.level - 1):
                        parent = parent.parent
                    module = '.'.join((*parent.parts, node.module))
                else:
                    module = node.module
                names.append(module)
                names.extend(module + '.' + alias.name for alias in node.names
                             if alias.name != '*')
        for name in names:
            parts = name.split(".")
            candidates = [Path("tools") / f"{parts[0]}.py"]
            if parts[0] in ("workstation", "tools", "tests"):
                candidates.append(Path(*parts).with_suffix('.py'))
                candidates.append(Path(*parts) / '__init__.py')
            for candidate in candidates:
                if (root / candidate).is_file() and candidate not in result:
                    queued.append(candidate)
    return result


def managed_source_files(root: Path) -> list[Path]:
    """Keep editor-generated compile bindings and their exact authored inputs."""
    result = []
    for filename, member in (("units.json", "units"), ("user-functions.json", "functions")):
        relative = Path("source-workstation") / filename
        manifest = root / relative
        if not os.path.lexists(manifest):
            continue
        if any(is_reparse_or_link(root / Path(*relative.parts[:i]))
               for i in range(1, len(relative.parts) + 1)):
            raise ValueError(f"Managed source binding is linked: {relative}")
        raw = manifest.read_bytes()
        if contains_private_path(raw):
            raise ValueError(f"Managed source binding embeds a private path: {relative}")
        document = json.loads(raw)
        if document.get("schema") != 1 or not re.fullmatch(r"[0-9a-fA-F]{64}", document.get("image_sha256", "")):
            raise ValueError(f"Invalid managed source binding: {relative}")
        rows = document.get(member)
        if member == "functions":
            if not isinstance(rows, dict):
                raise ValueError("Managed user-function bindings must be an object")
            rows = list(rows.values())
        elif not isinstance(rows, list):
            raise ValueError("Managed source units must be a list")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Invalid managed source row")
            kind = row.get("kind") if member == "units" else "cpp"
            value = row.get("source") if member == "units" else row.get("path")
            if kind not in ("cpp", "assembly") or not isinstance(value, str):
                raise ValueError("Unsupported managed source kind or path")
            portable = PurePosixPath(value.replace("\\", "/"))
            if portable.is_absolute() or PureWindowsPath(value).drive or ".." in portable.parts:
                raise ValueError("Managed source path escapes its authored directory")
            source = Path(*portable.parts)
            parent = Path("src") if kind == "cpp" else Path("source-workstation/assembly")
            if not source.is_relative_to(parent) or source.suffix != (".cpp" if kind == "cpp" else ".s"):
                raise ValueError("Managed source path escapes its authored directory")
            if any(is_reparse_or_link(root / Path(*source.parts[:i]))
                   for i in range(1, len(source.parts) + 1)):
                raise ValueError(f"Managed source input is linked: {source}")
            path = root / source
            expected = row.get("sha256")
            if not path.is_file() or sha256(path) != expected or row.get("revision") != expected:
                raise ValueError(f"Managed source revision no longer matches: {source}")
            if contains_private_path(path.read_bytes()):
                raise ValueError(f"Managed source embeds a private path: {source}")
            result.append(source)
        result.append(relative)
    return result


def pinned_dxbc_source_files(root: Path) -> list[Path]:
    """Validate and return only the reviewed source-built DXBC package files."""
    package_root = root / DXBC_SOURCE_PACKAGE_ROOT
    manifest_relative = DXBC_SOURCE_PACKAGE_ROOT / "source-package-manifest.json"
    manifest_path = root / manifest_relative
    package_ancestors = [root / Path(*DXBC_SOURCE_PACKAGE_ROOT.parts[:index])
                         for index in range(1, len(DXBC_SOURCE_PACKAGE_ROOT.parts) + 1)]
    if (not manifest_path.is_file() or any(is_reparse_or_link(path) for path in package_ancestors) or
            not package_root.resolve(strict=True).is_relative_to(root.resolve(strict=True)) or
            is_reparse_or_link(manifest_path) or sha256(manifest_path) != DXBC_SOURCE_PACKAGE_MANIFEST_SHA256):
        raise ValueError("Pinned source-built DXBC package manifest is missing, linked, or changed")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("schema") != "replay120-dxbc-source-package-v1" or
            manifest.get("upstream", {}).get("commit") != "cbc4993ca67b6d639e06c578d4e3dc8b3780243f" or
            manifest.get("upstream", {}).get("tag") != "1.3.16"):
        raise ValueError("Source-built DXBC package upstream identity differs from the reviewed pin")
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise ValueError("Source-built DXBC package manifest has no member list")
    seen: set[str] = set()
    result = [manifest_relative]
    for row in rows:
        raw = row.get("path") if isinstance(row, dict) else None
        relative = PurePosixPath(raw or "")
        if (not raw or relative.is_absolute() or "\\" in raw or ":" in raw or
                any(part in ("", ".", "..") for part in relative.parts)):
            raise ValueError(f"Unsafe source-built DXBC package member: {raw!r}")
        key = relative.as_posix()
        if key in seen:
            raise ValueError(f"Duplicate source-built DXBC package member: {key}")
        seen.add(key)
        target_relative = DXBC_SOURCE_PACKAGE_ROOT / Path(*relative.parts)
        source = root / target_relative
        ancestors = [root / Path(*target_relative.parts[:index])
                     for index in range(1, len(target_relative.parts) + 1)]
        if (any(is_reparse_or_link(path) for path in ancestors) or
                not source.resolve(strict=True).is_relative_to(root.resolve(strict=True)) or
                not source.is_file() or sha256(source) != row.get("sha256")):
            raise ValueError(f"Source-built DXBC package member is missing, linked, or changed: {key}")
        if contains_private_path(source.read_bytes()):
            raise ValueError(f"Source-built DXBC package member embeds a private path: {key}")
        result.append(target_relative)
    if seen != DXBC_SOURCE_PACKAGE_REQUIRED_FILES:
        raise ValueError("Source-built DXBC package members differ from the reviewed allowlist")
    return result


def class0_field_fixture_files(root: Path) -> list[Path]:
    """Include only the authored source and compiler payloads pinned by manifest."""
    contract_relative = Path("tools/workstation_gsc_fields_class0.json")
    contract_path = root / contract_relative
    if (not contract_path.is_file() or is_reparse_or_link(contract_path) or
            sha256(contract_path) !=
            "d68b7e861a6baa3882d24b5b53b71980ea9aebf7d92ba88f1bc580ab3d125286"):
        raise ValueError("Class-0 generated field contract is missing, linked, or changed")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract_rows = contract.get("verified_fields")
    if not isinstance(contract_rows, list) or len(contract_rows) != 16:
        raise ValueError("Class-0 generated field contract has an unexpected row inventory")
    relative_manifest = Path("tests/fixtures/scriptfile-class0/manifest.json")
    manifest_path = root / relative_manifest
    if not manifest_path.is_file() or is_reparse_or_link(manifest_path):
        raise ValueError("Required class-0 authored fixture manifest is missing or linked")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if (manifest.get("schema") != "replay-scriptfile-class0-authored-fixtures-v1" or
            manifest.get("status") != "sixteen-compiler-probes-pinned" or
            manifest.get("field_contract_sha256") !=
            "d68b7e861a6baa3882d24b5b53b71980ea9aebf7d92ba88f1bc580ab3d125286" or
            manifest.get("compiler_probe_receipt_sha256") !=
            "b3e012c65b0b08888b270fe9ec6cbff47642d29c592d753e077a7252d07645a3" or
            manifest.get("compiled_operand_audit_sha256") !=
            "9597867502091c9ffe8448a2d97bd117d62d6ffc9ac9bd1fa781facbe6e93e04"):
        raise ValueError("Class-0 authored fixture provenance changed")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != 16:
        raise ValueError("Class-0 fixture manifest does not contain all 16 compiler probes")
    result = [contract_relative, relative_manifest]
    seen_names = set()
    for ordinal, (case, verified) in enumerate(zip(cases, contract_rows, strict=True), 1):
        if (not isinstance(case, dict) or not isinstance(verified, dict) or
                case.get("descriptor_row_index") != ordinal - 1 or
                verified.get("descriptor_row_index") != ordinal - 1 or
                case.get("field_name") != verified.get("name") or
                case.get("token") != hex(verified.get("compiler_dictionary_token", -1)) or
                case.get("payload_sha256") != verified.get("compiled_payload_sha256")):
            raise ValueError("Class-0 fixture order or descriptor identity changed")
        field_name, token = case.get("field_name"), case.get("token")
        if not isinstance(field_name, str) or not field_name.isidentifier() or field_name in seen_names:
            raise ValueError("Class-0 fixture field name is invalid or duplicated")
        if not isinstance(token, str) or not re.fullmatch(r"0x[0-9a-f]+", token):
            raise ValueError("Class-0 fixture token is malformed")
        expected_source = f"tests/fixtures/scriptfile-class0/class0_probe_{ordinal}.gsc"
        expected_payload = f"tests/fixtures/scriptfile-class0/class0_probe_{ordinal}.gscbin"
        if case.get("source_path") != expected_source or case.get("payload_path") != expected_payload:
            raise ValueError("Class-0 fixture path is outside the explicit allowlist")
        source_path, payload_path = root / expected_source, root / expected_payload
        if any(not path.is_file() or is_reparse_or_link(path) for path in (source_path, payload_path)):
            raise ValueError("Class-0 authored source or compiler payload is missing or linked")
        source_bytes, payload_bytes = source_path.read_bytes(), payload_path.read_bytes()
        if (sha256(source_path) != case.get("source_sha256") or
                sha256(payload_path) != case.get("payload_sha256")):
            raise ValueError("Class-0 authored fixture bytes differ from their pinned hashes")
        expected_source_text = (
            f"class0_probe_{ordinal}() {{ self.{field_name} = 1; return; }}\n"
        ).encode("utf-8")
        if source_bytes != expected_source_text:
            raise ValueError("Class-0 authored source is not the pinned self-field fixture")
        if not payload_bytes:
            raise ValueError("Class-0 compiled payload fixture is empty")
        seen_names.add(field_name)
        result.extend((Path(expected_source), Path(expected_payload)))
    return result


def collect_source_files(root: Path) -> list[Path]:
    """Enumerate the portable runtime/build closure without diagnostic utilities."""
    result: list[Path] = []
    for area in ("src", "workstation"):
        base = root / area
        if not base.is_dir() or is_reparse_or_link(base):
            raise ValueError(f"Required source directory is missing or linked: {area}")
        stack = [base]
        while stack:
            directory = stack.pop()
            for entry in os.scandir(directory):
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in EXCLUDED_DIRS or is_reparse_or_link(path):
                        continue
                    stack.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False) or is_reparse_or_link(path):
                    continue
                if path.name.casefold() in EXCLUDED_FILENAMES:
                    continue
                if path.suffix.casefold() not in SOURCE_EXTENSIONS:
                    continue
                relative = path.relative_to(root)
                # Do not export locally installed editor assets or test captures.
                if relative.parts[:3] == ("workstation", "web", "vendor"):
                    continue
                result.append(relative)
    result.extend(managed_source_files(root))
    result.extend(Path(name) for name in OPTIONAL_DOCUMENTS if (root / name).is_file())
    python_roots = [Path("tools") / name for name in TOOL_ENTRYPOINTS]
    python_roots += [path.relative_to(root) for path in (root / "workstation").glob("*.py")]
    result.extend(_local_python_dependencies(root, python_roots))
    result.extend(Path("tools") / name for name in TOOL_SCRIPT_ENTRYPOINTS)
    result.extend(Path("tools") / name for name in TOOL_SOURCE_ENTRYPOINTS)
    result.extend(pinned_dxbc_source_files(root))
    result.extend(class0_field_fixture_files(root))
    for test in (root / "tests").glob("test_*.py"):
        dependencies = _local_python_dependencies(root, [test.relative_to(root)])
        # Keep useful portable tests together with their source dependencies.
        # Local diagnostic suites whose dependency closure embeds private paths
        # stay in the development tree rather than exporting broken imports.
        if all(not contains_private_path((root / path).read_bytes()) for path in dependencies):
            result.extend(dependencies)
    if (root / 'tests/__init__.py').is_file():
        result.append(Path('tests/__init__.py'))
    for fixture in (root / 'tests').iterdir():
        if fixture.is_file() and fixture.suffix in ('.cpp', '.c', '.h', '.hpp'):
            data = fixture.read_bytes().lower()
            if not contains_private_path(data):
                result.append(fixture.relative_to(root))
    for relative_text in PORTABLE_TEST_ENTRYPOINTS:
        relative = Path(relative_text)
        test_path = root / relative
        if not test_path.is_file() or is_reparse_or_link(test_path):
            raise ValueError(f"Required portable test is missing or linked: {relative.as_posix()}")
        if contains_private_path(test_path.read_bytes()):
            raise ValueError(f"Portable test embeds a private checkout path: {relative.as_posix()}")
        result.append(relative)
    return sorted(result, key=lambda item: item.as_posix().casefold())


def export_workstation(source_root: Path, destination: Path) -> dict:
    source_root = source_root.resolve(strict=True)
    destination = destination.resolve()
    if destination == source_root or source_root in destination.parents:
        raise ValueError("Export destination must be outside the source tree")
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            raise ValueError("Export destination must be a new or empty directory")
    else:
        destination.mkdir(parents=True)

    files = collect_source_files(source_root)
    pinned = [Path(item) for item in ROOT_FILES]
    pinned += [Path("analysis/replay120") / item for item in SEED_FILES]
    pinned += [Path("third_party/acts-patches/acts-replay-workstation.patch"),
               Path("third_party/acts-patches/manifest.json")]
    pinned += [Path(item) for item in PINNED_FILES]
    for relative in pinned:
        source = source_root / relative
        if not source.is_file() or is_reparse_or_link(source):
            raise ValueError(f"Required allowlisted file missing or linked: {relative}")
        files.append(relative)
    files = sorted(set(files), key=lambda item: item.as_posix().casefold())

    copied = []
    for relative in files:
        source = source_root / relative
        if is_reparse_or_link(source):
            raise ValueError(f"Refusing linked source file: {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append({"path": relative.as_posix(), "size": target.stat().st_size,
                       "sha256": sha256(target)})

    # Source paths in this seed are diagnostic provenance, not compiler inputs.
    # Retain the declaring filename while removing the private checkout root,
    # then bind the portable seed manifest to the exact structured result.
    seed_path = destination / "analysis/replay120/seed.json"
    proxy_path = destination / "analysis/replay120/proxy-signatures.json"
    proxy_rows = json.loads(proxy_path.read_text(encoding="utf-8"))
    normalized_sources = 0
    for row in proxy_rows:
        source = row.get("source") if isinstance(row, dict) else None
        if isinstance(source, str) and ("\\" in source or "/" in source):
            row["source"] = source.replace("\\", "/").rsplit("/", 1)[-1]
            normalized_sources += 1
    proxy_path.write_text(json.dumps(proxy_rows, indent=2) + "\n", encoding="utf-8")
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    seed["files"]["proxy-signatures.json"] = sha256(proxy_path)
    seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
    for row in copied:
        if row["path"] in ("analysis/replay120/seed.json", "analysis/replay120/proxy-signatures.json"):
            normalized_path = destination / row['path']
            row.update(size=normalized_path.stat().st_size, sha256=sha256(normalized_path))

    receipt = {
        "schema": 1,
        "profile": "Replay workstation source export",
        "excluded": ["game executable/SQLite", "assets", "evidence", "generated outputs",
                     "builds", "caches", "local configuration", "vendored Monaco files"],
        "required_owner_inputs": ["matching Replay 1.20 executable", "matching Replay SQLite database",
                                  "LLVM/Clang", "Microsoft MASM", "Git, CMake and Visual Studio C++ tools for ACTS"],
        "optional_owner_inputs": [
            {"name": "Replay proxy source checkout",
             "required_for": "Rebuilding and deploying the game proxy; not required for engine-only workstation compilation",
             "setup_option": "setup-workstation.ps1 -ProxySource <directory>",
             "must_not_download": True},
            {"name": "IW8 ZoneTool source checkout/build",
             "required_for": "Optional fastfile asset authoring and inspection; not required for the compiler engine build",
             "used_by": "Some map/asset authoring helpers compile against ZoneTool writer sources or call its CLI",
             "must_not_download": True},
            {"name": "Replay Oodle decoder and sound-bank generator",
             "required_for": "Optional owner-local fastfile decoding and SAB authoring workflows",
             "configured_via": "setup-workstation.ps1 -SabGenerator and the owner tool configuration",
             "must_not_download": True},
        ],
        "structured_normalizations": [{
            "path": "analysis/replay120/proxy-signatures.json",
            "field": "source", "action": "retain declaring filename only",
            "rows": normalized_sources,
        }],
        "downloads": [
            {"name": "Python packages", "pin": "requirements.txt",
             "source": "PyPI; installed into the local virtual environment by setup-workstation.ps1"},
            {"name": "Monaco editor", "version": "0.57.0",
             "source": "https://registry.npmjs.org/monaco-editor/-/monaco-editor-0.57.0.tgz",
             "integrity_sha512_base64": "5BkI9KGoqrNvBGUe15/QlZq3OooZ8WLg1AxTpaqHRCP3HNpzPPZKE2EDz8M7c+VRmCeUw1Brp4cx/PWm3kI/5A==",
             "license": "MIT", "installed_by": "tools/setup_workstation_ui.py"},
            {"name": "Replay-compatible ACTS", "pin": "third_party/acts-patches/manifest.json",
             "source": "Pinned IDARETW fork commit plus submodule gitlinks; bootstrap retains ACTS and dependency license files"},
            {"name": "IW8 GSC encrypted-string transform source", "pin": "tools/workstation_script_string_manifest.json",
             "source": "Pinned MIT-licensed source commit; installed by tools/bootstrap_workstation_string_decryptor.py",
             "license": "MIT", "game assets included": False},
            {"name": "3Dmigoto DXBC source-built CLI", "pin": "third_party/3dmigoto-dxbc-1.3.16/source-package-manifest.json",
             "source": "Pinned source patch built locally by tools/bootstrap_workstation_dxbc.py; the public DXBC release is available only through explicit legacy selection",
             "license": "Retained upstream GPL/MIT notices; see the package license files", "game assets included": False},
        ],
        "files": copied,
    }
    (destination / "EXPORT-MANIFEST.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new or empty directory outside the source tree")
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    receipt = export_workstation(args.source_root, args.destination)
    print(json.dumps({"destination": str(args.destination.resolve()),
                      "files": len(receipt["files"]),
                      "bytes": sum(row["size"] for row in receipt["files"])}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"export failed: {error}", file=sys.stderr)
        raise SystemExit(2)
