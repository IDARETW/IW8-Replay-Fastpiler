"""Fetch the source-only IW8 GSC string transform at a reviewed commit."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools/workstation_script_string_manifest.json"


def _run(args: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return result.stdout.strip()


def _blob(git: str, checkout: Path, commit: str, relative: str) -> bytes:
    return subprocess.run([git, "-C", str(checkout), "show", f"{commit}:{relative}"],
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def bootstrap(destination: Path) -> dict:
    spec = json.loads(MANIFEST.read_text(encoding="utf-8"))
    destination = destination.resolve()
    git = shutil.which("git")
    if not git:
        raise RuntimeError("Git is required to obtain the pinned string transform source")
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        _run([git, "clone", "--filter=blob:none", "--no-checkout",
              spec["repository"], str(destination)])
    if not (destination / ".git").exists():
        raise ValueError("String transform destination exists but is not a Git checkout")
    origin = _run([git, "remote", "get-url", "origin"], destination).rstrip("/")
    if origin.casefold() != spec["repository"].rstrip("/").casefold():
        raise ValueError(f"String transform checkout origin differs from pin: {origin}")
    status = _run([git, "status", "--porcelain", "--untracked-files=all"], destination)
    generated = []
    for line in status.splitlines():
        path = line[3:].replace("\\", "/")
        if path == "replay-workstation-transform.json" or path.startswith("portable/"):
            continue
        generated.append(line)
    status = "\n".join(generated)
    head = _run([git, "rev-parse", "HEAD"], destination)
    if head != spec["base_commit"]:
        if status:
            raise ValueError("Refusing to change a dirty string transform checkout")
        _run([git, "fetch", "origin", spec["base_commit"]], destination)
        _run([git, "checkout", "--detach", spec["base_commit"]], destination)
    if _run([git, "rev-parse", "HEAD"], destination) != spec["base_commit"]:
        raise ValueError("String transform checkout did not reach the pinned commit")
    pinned_files = {**spec["files"], spec["license_path"]: spec["license_sha256"]}
    portable = destination / "portable"
    portable.mkdir(exist_ok=True)
    for relative, expected in pinned_files.items():
        blob = _blob(git, destination, spec["base_commit"], relative)
        if hashlib.sha256(blob).hexdigest() != expected:
            raise ValueError(f"Pinned string transform Git blob hash mismatch: {relative}")
        target = portable / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
    receipt = {"schema": 1, "repository": spec["repository"],
               "commit": spec["base_commit"], "license": spec["license"],
               "license_file": spec["license_path"],
               "source_files": spec["files"], "transform": spec["transform"],
               "portable_source_directory": str(portable),
               "destination": str(destination)}
    (destination / "replay-workstation-transform.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(bootstrap(args.destination), indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"String transform bootstrap failed: {error}", file=sys.stderr)
        raise SystemExit(2)
