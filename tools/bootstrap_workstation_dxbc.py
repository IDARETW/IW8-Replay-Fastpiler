"""Clean-build the pinned source DXBC CLI into a separate toolchain directory.

The portable bootstrap consumes only the authored/pinned source package and
synthetic tests. It does not require game-derived shader fixtures, a source
checkout, or pre-existing object files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "third_party" / "3dmigoto-dxbc-1.3.16"
EXPECTED_PACKAGE_MANIFEST_SHA256 = "c3a4ff17cf7ab1ced0b0686d675a22d1109da2164f05a138b752efe248da400d"
DEFAULT_DESTINATION = ROOT / ".toolchains" / "dxbc-compute-v1"
SOURCE_PATCH_SHA256 = "85c3d9a0ab9d1023da131bdf57576377503dfd0f0b823b17e21d6ef7fd3ef984"
UPSTREAM_COMMIT = "cbc4993ca67b6d639e06c578d4e3dc8b3780243f"
REQUIRED_PACKAGE_FILES = {
    "D3D_Shaders/Assembler.cpp", "D3D_Shaders/SignatureParser.cpp",
    "D3D_Shaders/stdafx.h", "D3D_Shaders/targetver.h", "log.h", "shader.h",
    "portable_dxbc_cli.cpp", "source-fix.patch", "LICENSE.GPL.txt",
    "LICENSE.MIT.txt", "COPYING.txt", "AUTHORS.txt", "README.md",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(raw: str) -> Path:
    posix = PurePosixPath(raw)
    if posix.is_absolute() or not posix.parts or any(part in ("", ".", "..") for part in posix.parts):
        raise ValueError(f"unsafe source-package path: {raw!r}")
    if "\\" in raw or ":" in raw:
        raise ValueError(f"unsafe source-package path: {raw!r}")
    return Path(*posix.parts)


def verify_source_package(package: Path = PACKAGE,
                          expected_manifest_sha256: str | None = EXPECTED_PACKAGE_MANIFEST_SHA256) -> dict:
    manifest_path = package / "source-package-manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    manifest_sha = sha256(manifest_path)
    if expected_manifest_sha256 and manifest_sha != expected_manifest_sha256:
        raise ValueError("DXBC source package manifest is not the reviewed pinned manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "replay120-dxbc-source-package-v1":
        raise ValueError("unsupported DXBC source package schema")
    upstream = manifest.get("upstream", {})
    if upstream.get("commit") != UPSTREAM_COMMIT or upstream.get("tag") != "1.3.16":
        raise ValueError("DXBC source package upstream identity differs from the pinned commit")
    patch = manifest.get("source_patch", {})
    if patch.get("path") != "source-fix.patch" or patch.get("sha256") != SOURCE_PATCH_SHA256:
        raise ValueError("DXBC source patch identity differs from the reviewed patch")
    rows = manifest.get("files")
    if not isinstance(rows, list):
        raise ValueError("DXBC source package has no file inventory")
    found: set[str] = set()
    checked = []
    for row in rows:
        relative = _safe_relative(row.get("path", ""))
        key = relative.as_posix()
        if key in found:
            raise ValueError(f"duplicate source-package entry: {key}")
        found.add(key)
        source = package / relative
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"source-package file is missing or is a link: {key}")
        actual = sha256(source)
        if actual != row.get("sha256"):
            raise ValueError(f"source-package SHA-256 mismatch: {key}")
        checked.append({"path": key, "sha256": actual})
    missing = REQUIRED_PACKAGE_FILES - found
    if missing:
        raise ValueError(f"source package omits required files: {sorted(missing)}")
    return {"manifest": manifest, "manifest_sha256": manifest_sha, "files": checked}


def find_vswhere() -> Path:
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if not program_files_x86:
        raise RuntimeError("ProgramFiles(x86) is unavailable; cannot locate Visual Studio Installer vswhere")
    path = Path(program_files_x86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not path.is_file():
        raise FileNotFoundError(f"Visual Studio Installer vswhere.exe not found: {path}")
    return path


def find_vs_installation(vswhere: Path) -> tuple[Path, dict]:
    command = [str(vswhere), "-latest", "-products", "*", "-requires",
               "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-format", "json"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"vswhere failed: {result.stderr.strip()[-2000:]}")
    rows = json.loads(result.stdout)
    if not rows:
        raise RuntimeError("No Visual Studio installation with x64 C++ tools was found")
    row = rows[0]
    installation = Path(row["installationPath"]).resolve(strict=True)
    vcvars = installation / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    if not vcvars.is_file():
        raise FileNotFoundError(f"x64 compiler environment script is missing: {vcvars}")
    return vcvars, row


def bootstrap(destination: Path = DEFAULT_DESTINATION) -> dict:
    package = verify_source_package()
    destination = destination.expanduser().resolve()
    if destination.exists():
        receipt_path = destination / "bootstrap-receipt.json"
        executable = destination / "cmd_Decompiler.exe"
        if not receipt_path.is_file() or not executable.is_file():
            raise FileExistsError(f"toolchain destination exists but is not a verified installation: {destination}")
        prior = json.loads(receipt_path.read_text(encoding="utf-8"))
        if (prior.get("source_package_manifest_sha256") == package["manifest_sha256"] and
                prior.get("output_sha256") == sha256(executable) and
                prior.get("executable") == "cmd_Decompiler.exe"):
            return prior | {"status": "already-verified", "destination": str(destination)}
        raise FileExistsError(f"refusing to replace a differing DXBC toolchain: {destination}")

    vswhere = find_vswhere()
    vcvars, vs_row = find_vs_installation(vswhere)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".dxbc-source-build-", dir=destination.parent) as temp_name:
        temp = Path(temp_name)
        build_dir = temp / "build"
        build_dir.mkdir()
        stage = temp / "stage"
        stage.mkdir()
        wrapper = temp / "build-clean.cmd"
        toolchain_text = temp / "toolchain.txt"
        compiler_log = temp / "compiler-version.txt"
        source_root = PACKAGE
        assembler_source = source_root / "D3D_Shaders" / "Assembler.cpp"
        signature_source = source_root / "D3D_Shaders" / "SignatureParser.cpp"
        executable = build_dir / "cmd_Decompiler.exe"
        wrapper.write_text(
            "@echo off\r\n"
            f'call "{vcvars}" >nul\r\n'
            "if errorlevel 1 exit /b %errorlevel%\r\n"
            f'echo WindowsSdkDir=%WindowsSdkDir%>"{toolchain_text}"\r\n'
            f'echo WindowsSDKVersion=%WindowsSDKVersion%>>"{toolchain_text}"\r\n'
            f'where cl.exe>>"{toolchain_text}"\r\n'
            f'cl.exe /Bv >"{compiler_log}" 2>&1\r\n'
            "cl.exe /nologo /EHsc /O2 /MT /DWIN32 /DNDEBUG /D_CONSOLE "
            f'/I"{source_root}" /I"{source_root / "D3D_Shaders"}" '
            f'"{source_root / "portable_dxbc_cli.cpp"}" '
            f'"{assembler_source}" '
            f'"{signature_source}" '
            f'/link d3dcompiler.lib /OUT:"{executable}"\r\n'
            "exit /b %errorlevel%\r\n", encoding="utf-8")
        build_result = subprocess.run(["cmd.exe", "/d", "/c", str(wrapper)],
                                      cwd=build_dir, capture_output=True, text=True, timeout=300, check=False)
        if build_result.returncode:
            raise RuntimeError(f"clean DXBC source build failed ({build_result.returncode}): "
                               f"{(build_result.stdout + build_result.stderr)[-6000:]}")
        if not executable.is_file():
            raise FileNotFoundError("clean source build completed without the CLI output")
        smoke = subprocess.run([sys.executable, str(ROOT / "tests" / "synthetic_bootstrap_smoke.py"),
                                "--cli", str(executable), "--output-dir", str(stage / "smoke")],
                               cwd=ROOT, capture_output=True, text=True, timeout=180, check=False)
        if smoke.returncode:
            raise RuntimeError(f"synthetic DXBC CLI smoke failed ({smoke.returncode}): "
                               f"{(smoke.stdout + smoke.stderr)[-6000:]}")
        smoke_result = json.loads(smoke.stdout)
        if smoke_result.get("status") != "pass" or smoke_result.get("container_cases") != 5:
            raise RuntimeError("synthetic DXBC smoke returned an incomplete proof")

        payload = temp / "payload"
        payload.mkdir()
        target_exe = payload / "cmd_Decompiler.exe"
        shutil.copy2(executable, target_exe)
        for name in ("LICENSE.GPL.txt", "LICENSE.MIT.txt", "COPYING.txt", "AUTHORS.txt"):
            shutil.copy2(PACKAGE / name, payload / name)
        toolchain_identity = {
            "vswhere_path": str(vswhere), "vswhere_sha256": sha256(vswhere),
            "installation_path": str(vs_row["installationPath"]),
            "installation_version": vs_row.get("installationVersion"),
            "vcvars64_path": str(vcvars), "vcvars64_sha256": sha256(vcvars),
            "compiler_version_output_sha256": sha256(compiler_log),
            "compiler_version_output": compiler_log.read_text(encoding="utf-8", errors="replace")[:12000],
            "windows_sdk_environment": toolchain_text.read_text(encoding="utf-8", errors="replace")[:4000],
        }
        d3dcompiler = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "d3dcompiler_47.dll"
        receipt = {
            "schema": "replay120-dxbc-source-bootstrap-v1", "status": "pass",
            "source_package_manifest_sha256": package["manifest_sha256"],
            "upstream": package["manifest"]["upstream"],
            "source_patch_sha256": package["manifest"]["source_patch"]["sha256"],
            "source_files": package["files"], "toolchain": toolchain_identity,
            "build": {"clean_temporary_directory": True,
                      "compile_flags": ["/EHsc", "/O2", "/MT", "/DWIN32", "/DNDEBUG", "/D_CONSOLE"],
                      "import_library": "d3dcompiler.lib"},
            "executable": "cmd_Decompiler.exe", "output_sha256": sha256(target_exe),
            "system_d3dcompiler_47": ({"path": str(d3dcompiler), "sha256": sha256(d3dcompiler)}
                                       if d3dcompiler.is_file() else None),
            "portable_smoke": smoke_result,
        }
        (payload / "bootstrap-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        (payload / "bootstrap-receipt.sha256").write_text(sha256(payload / "bootstrap-receipt.json") + "\n", encoding="ascii")
        payload.rename(destination)
    return receipt | {"destination": str(destination)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    try:
        receipt = bootstrap(args.destination)
    except Exception as exc:
        print(f"DXBC bootstrap failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": receipt.get("status"), "destination": receipt.get("destination"),
                      "executable": receipt.get("executable"), "output_sha256": receipt.get("output_sha256"),
                      "source_package_manifest_sha256": receipt.get("source_package_manifest_sha256")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
