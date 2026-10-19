"""Generate a target-hash-checked ACTS offset profile for Replay's LuaJIT compiler."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "generated" / "function-catalog.json"
EXPECTED_IMAGE_SHA256 = "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
sys.path.insert(0, str(ROOT / "tools"))
from source_catalog import stable_id

# These are the compiler's proven direct API dependencies. The string-dump
# entry is a SQLite/callgraph-derived alias, rather than a guessed name.
BINDINGS = {
    "lua_newstate": "fn_c8ae7b2999396270",
    "lua_loadx": "fn_b418cc8e729eec35",
    "lj_cf_string_dump": "fn_e5d95dbb9c201196",
    "writer_buf": "fn_44ff01091ff269bb",
    # LuaJIT's string.dump strip argument is the second stack value. ACTS
    # pushes this through the target API rather than mutating the dump header.
    "lua_pushboolean": "fn_62f1863f254e576f",
}


def build_profile(catalog_path: Path, acts_exe: Path) -> tuple[Path, dict]:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    if catalog.get("image_sha256") != EXPECTED_IMAGE_SHA256:
        raise ValueError("Function catalog does not match the pinned Replay image")
    rows = catalog.get("functions")
    if not isinstance(rows, list):
        raise ValueError("Function catalog has no functions list")
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            continue
        by_id.setdefault(row["id"], []).append(row)
    scans = {}
    used = {}
    for acts_name, function_id in BINDINGS.items():
        matches = by_id.get(function_id, [])
        if len(matches) != 1:
            raise ValueError(
                f"Expected one catalog row for stable function ID {function_id}; found {len(matches)}"
            )
        row = matches[0]
        rva = row.get("rva")
        if not isinstance(rva, int) or isinstance(rva, bool) or rva <= 0:
            raise ValueError(f"Invalid catalog RVA for stable function ID {function_id}")
        if stable_id(EXPECTED_IMAGE_SHA256, rva) != function_id:
            raise ValueError(
                f"Catalog stable ID/RVA mismatch for {function_id} at RVA {rva:#x}"
            )
        scans[acts_name] = {"type": "Offset", "scan": f"0x{row['rva']:x}"}
        used[acts_name] = {
            "catalog_name": row.get("name", ""),
            "function_id": function_id,
            "rva": row["rva"],
        }
    profile = {
        "scans": {"lua": scans},
        "__provenance": {
            "target": "Call of Duty: Modern Warfare 2019 Replay 1.20",
            "image_sha256": EXPECTED_IMAGE_SHA256,
            "database_sha256": catalog.get("database_sha256"),
            "catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
            "bindings": used,
            "cod_lua_setxhash": {
                "status": "not bound or called; optional-until-proven for the plain-source compile path"
            },
        },
    }
    out = acts_exe.resolve().parent / "replay120_lua_native.json"
    return out, profile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--acts", type=Path, required=True,
                        help="setup-selected Replay-compatible ACTS executable")
    args = parser.parse_args()
    if not args.acts.is_file():
        raise FileNotFoundError(args.acts)
    out, profile = build_profile(args.catalog, args.acts)
    out.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"target image sha256 {profile['__provenance']['image_sha256']}")


if __name__ == "__main__":
    main()
