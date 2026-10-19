"""Generate the reviewed display-reader identity contract from a source snapshot.

Example:
  python tools/generate_workstation_reader_identity_baseline.py \
    --snapshot-root D:/snapshots/source-export-iw8-assets-v3

The input snapshot is read-only. The output defaults to this checkout's
tools/workstation_reader_identity_baseline.json and contains hashes only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from workstation_reader_identity import reader_code_identity


READER_ENTRYPOINTS = (
    "source_profile", "decode_source_fastfile", "walk_native_fastfile",
    "FastfileWorkspace.__init__", "FastfileWorkspace._zone_path",
    "FastfileWorkspace.extract", "FastfileWorkspace._validated_asset_snapshot",
)
LEGACY_MODULES = (
    "workstation_fastfiles.py", "workstation_metadata_decode.py",
    "inspect_frontend_asset_table.py", "workstation_native_references.py",
    "frontend_catalog.py", "workstation_asset_metadata.py",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def generate(snapshot_root: Path) -> dict:
    snapshot_root = snapshot_root.resolve(strict=True)
    source_tools = snapshot_root / "tools"
    fastfiles = source_tools / "workstation_fastfiles.py"
    if not fastfiles.is_file() or fastfiles.is_symlink():
        raise ValueError("snapshot must contain a regular tools/workstation_fastfiles.py")
    for name in LEGACY_MODULES:
        member = source_tools / name
        if not member.is_file() or member.is_symlink():
            raise ValueError(f"snapshot is missing a regular tools/{name}")
    reader = reader_code_identity(fastfiles, READER_ENTRYPOINTS, source_tools)
    module_hashes = {name: sha256(source_tools / name) for name in LEGACY_MODULES}
    return {
        "schema": 1,
        "baseline_source_sha256": module_hashes["workstation_fastfiles.py"],
        "reader_entrypoints": sorted(READER_ENTRYPOINTS),
        "reader_code": reader,
        "legacy_reader_modules": module_hashes,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-root", type=Path, required=True,
                        help="existing frozen source-export root to read")
    parser.add_argument("--output", type=Path,
                        help="output JSON (default: this checkout's tools baseline file)")
    args = parser.parse_args(argv)
    output = args.output or Path(__file__).resolve().with_name("workstation_reader_identity_baseline.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    document = generate(args.snapshot_root)
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
                      encoding="utf-8", newline="\n")
    print(json.dumps({"output": str(output.resolve()),
                      "baseline_source_sha256": document["baseline_source_sha256"],
                      "reader_sha256": document["reader_code"]["sha256"],
                      "reachable_definitions": document["reader_code"]["reachable_definitions"],
                      "local_dependencies": sorted(document["reader_code"]["local_dependencies"])},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
