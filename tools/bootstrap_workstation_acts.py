"""Fetch and build the pinned Replay-compatible ACTS CLI from source.

Without flags, this clones the exact reviewed fork commit and applies the
bundled seven-file patch. ``--submodules`` downloads the source dependencies;
``--build`` also configures the non-GPL CLI target with Qt/OpenCL disabled.
The checkout retains upstream and submodule license files. This script does
not copy game files, private data, or prebuilt ACTS binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "third_party/acts-patches/manifest.json"
PATCH_PATH = ROOT / "third_party/acts-patches/acts-replay-workstation.patch"


def run(args: list[str], cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(args, cwd=cwd, check=True, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        detail = (error.stdout or "")[-6000:]
        raise RuntimeError(f"command failed ({error.returncode}): {args!r}\n{detail}") from error
    return completed.stdout.strip()


def read_manifest() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    digest = hashlib.sha256(PATCH_PATH.read_bytes()).hexdigest()
    if digest != manifest.get("patch_sha256"):
        raise ValueError("Bundled ACTS patch hash does not match its manifest")
    if len(manifest.get("changed_paths", [])) != 7:
        raise ValueError("ACTS patch manifest must pin exactly seven changed paths")
    return manifest


def verify_patch_paths(manifest: dict) -> None:
    patch = PATCH_PATH.read_text(encoding="utf-8", errors="strict")
    paths = []
    for line in patch.splitlines():
        if line.startswith("diff --git a/"):
            before, after = line[len("diff --git a/"):].split(" b/", 1)
            if before != after:
                raise ValueError("ACTS patch contains a rename")
            paths.append(before)
    if paths != manifest["changed_paths"]:
        raise ValueError("ACTS patch paths differ from the seven reviewed paths")


def bootstrap(destination: Path, initialize_submodules: bool = False,
              build: bool = False, generator: str = "Visual Studio 17 2022",
              jobs: int = 2) -> dict:
    if jobs < 1 or jobs > 64:
        raise ValueError("Build job count must be between 1 and 64")
    manifest = read_manifest()
    verify_patch_paths(manifest)
    destination = destination.resolve()
    git = shutil.which("git")
    if not git:
        raise RuntimeError("Git is required to bootstrap ACTS")

    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        branch = manifest["repository_ref"].removeprefix("refs/heads/")
        run([git, "clone", "--filter=blob:none", "--single-branch", "--branch", branch,
             manifest["repository"], str(destination)])
    if not (destination / ".git").exists():
        raise ValueError("ACTS destination exists but is not a Git checkout")
    origin = run([git, "remote", "get-url", "origin"], destination).rstrip("/")
    expected_origin = manifest["repository"].rstrip("/")
    if origin.casefold() != expected_origin.casefold():
        raise ValueError(f"ACTS checkout origin differs from pinned repository: {origin}")

    head = run([git, "rev-parse", "HEAD"], destination)
    if head != manifest["base_commit"]:
        status = run([git, "status", "--porcelain", "--untracked-files=all"], destination)
        if status:
            raise ValueError("Refusing to move a dirty ACTS checkout to the pinned base commit")
        run([git, "fetch", "origin", manifest["base_commit"]], destination)
        run([git, "checkout", "--detach", manifest["base_commit"]], destination)
        head = run([git, "rev-parse", "HEAD"], destination)
    if head != manifest["base_commit"]:
        raise ValueError(f"ACTS base commit mismatch: {head}")

    already_applied = subprocess.run([git, "apply", "--reverse", "--check", str(PATCH_PATH)],
                                     cwd=destination, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL).returncode == 0
    if not already_applied:
        run([git, "apply", "--check", str(PATCH_PATH)], destination)
        run([git, "apply", str(PATCH_PATH)], destination)
    if initialize_submodules or build:
        run([git, "submodule", "update", "--init", "--recursive"], destination)

    result = {"repository": manifest["repository"], "base_commit": head,
              "repository_ref": manifest["repository_ref"],
              "canonical_upstream": manifest["canonical_upstream"],
              "provenance_note": manifest["provenance_note"],
              "patch_sha256": manifest["patch_sha256"],
              "changed_paths": manifest["changed_paths"],
              "patched": True, "submodules_initialized": bool(initialize_submodules or build),
              "license_note": manifest["license_note"],
              "retained_license_paths": manifest["license_files"],
              "build_prerequisites": manifest["build_prerequisites"],
              "submodule_revisions": run([git, "submodule", "status", "--recursive"], destination).splitlines()
              if initialize_submodules or build else [], "build": None}
    if build:
        cmake = shutil.which("cmake")
        if not cmake:
            raise RuntimeError("CMake is required for --build")
        build_dir = destination / "build-workstation"
        configure = [cmake, "-S", str(destination), "-B", str(build_dir), "-G", generator]
        if generator.casefold().startswith("visual studio"):
            configure += ["-A", "x64"]
        configure += ["-DNO_QT_BUILD=ON", "-DNO_OPEN_CL_BUILD=ON", "-DGPL_BUILD=OFF"]
        run(configure)
        run([cmake, "--build", str(build_dir), "--config", "Release",
             "--target", manifest["build"]["cmake_target"], "--parallel", str(jobs)])
        acts = destination / "build" / "bin" / "Release" / "acts.exe"
        if not acts.is_file():
            # Single-config generators place the binary directly under build/bin.
            acts = destination / "build" / "bin" / "acts.exe"
        if not acts.is_file():
            raise RuntimeError("ACTS build completed but acts.exe was not found")
        result["build"] = {"executable": str(acts), "sha256": hashlib.sha256(acts.read_bytes()).hexdigest(),
                            "cmake_generator": generator, "parallel_jobs": jobs, "gpl_build": False,
                            "cmake_configuration": {"NO_QT_BUILD": True, "NO_OPEN_CL_BUILD": True}}
    receipt = destination / "replay-workstation-bootstrap.json"
    receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    result["receipt"] = str(receipt)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="ACTS checkout destination")
    parser.add_argument("--submodules", action="store_true", help="initialize ACTS source submodules")
    parser.add_argument("--build", action="store_true", help="initialize dependencies and build native acts.exe")
    parser.add_argument("--generator", default="Visual Studio 17 2022")
    parser.add_argument("--jobs", type=int, default=2, help="parallel C++ build jobs (default: 2)")
    args = parser.parse_args()
    print(json.dumps(bootstrap(args.destination, args.submodules, args.build, args.generator, args.jobs), indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ACTS bootstrap failed: {error}", file=sys.stderr)
        raise SystemExit(2)
