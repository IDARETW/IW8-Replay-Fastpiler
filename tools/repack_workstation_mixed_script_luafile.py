"""Build and full-Reader verify one mixed ScriptFile/LuaFile transaction."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from roundtrip_replay_fastfile import verify_native  # noqa: E402
from workstation_fastfiles import pack_replay_uncompressed, unpack_replay_uncompressed  # noqa: E402
from workstation_mixed_script_luafile import replace_mixed_script_luafile_batch  # noqa: E402
from workstation_trace_index import build_read_span_index  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(body_path: Path, source_fastfile: Path, trace_path: Path,
          manifest_path: Path, journal_path: Path, script_edits_path: Path,
          lua_edits_path: Path, acts: Path, replay: Path,
          output: Path, evidence_dir: Path, timeout: int = 1800) -> dict:
    body_data = body_path.read_bytes()
    source_sha = hashlib.sha256(body_data).hexdigest()
    journal = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
               if line.strip()]
    script_requests = json.loads(script_edits_path.read_text(encoding="utf-8"))
    lua_requests = json.loads(lua_edits_path.read_text(encoding="utf-8"))
    if not isinstance(script_requests, list) or not script_requests:
        raise ValueError("mixed package proof requires at least one ScriptFile request")
    if not isinstance(lua_requests, list) or not lua_requests:
        raise ValueError("mixed package proof requires at least one LuaFile request")

    all_scripts = [index for index, row in enumerate(journal) if row.get("type_id") == 52]
    lua_indices = [row.get("asset_index") for row in lua_requests]
    selected = sorted(set(all_scripts) | set(lua_indices))
    read_index = build_read_span_index(trace_path, manifest_path, len(body_data), selected)
    trace_rows = {row["index"]: row for row in read_index["assets"]}
    script_edits = []
    for request in script_requests:
        index, name = request["xasset_index"], request["name"]
        if not 0 <= index < len(journal) or journal[index].get("type_id") != 52 or \
                journal[index].get("name") != name:
            raise ValueError(f"ScriptFile request {index} does not match native journal identity")
        payload_path = Path(request["payload_path"]).resolve(strict=True)
        payload = payload_path.read_bytes()
        if sha256_file(payload_path) != request.get("payload_sha256"):
            raise ValueError("compiled ScriptFile payload hash differs from request")
        script_edits.append(dict(xasset_index=index, name=name, payload=payload))

    lua_edits = []
    for request in lua_requests:
        index, name = request["asset_index"], request["asset_name"]
        if not 0 <= index < len(journal) or journal[index].get("type_id") != 62 or \
                journal[index].get("name") != name or index not in trace_rows:
            raise ValueError(f"LuaFile request {index} does not match native journal/trace identity")
        payload_path = Path(request["payload_path"]).resolve(strict=True)
        payload = payload_path.read_bytes()
        if sha256_file(payload_path) != request.get("payload_sha256"):
            raise ValueError("compiled LuaFile payload hash differs from request")
        lua_edits.append(dict(asset_index=index, asset_name=name,
                              trace_asset=dict(xasset_index=index, type_id=62,
                                               name=name, read_spans=trace_rows[index]["read_spans"]),
                              payload=payload))

    updated, relocation = replace_mixed_script_luafile_batch(
        body_data, script_edits, lua_edits, source_sha, str(trace_path),
        str(manifest_path), read_index, journal)
    reservations = relocation["stream_reservation_sizes"]
    if len(reservations) != 11:
        raise AssertionError("combined relocator failed to return all stream reservations")
    packaged = pack_replay_uncompressed(updated, reservations, xfile_version=0xFF7)
    if unpack_replay_uncompressed(packaged) != updated:
        raise AssertionError("Replay IWC pack/unpack changed mixed-edited body")

    output, evidence_dir = output.resolve(), evidence_dir.resolve()
    if output == source_fastfile or source_fastfile in output.parents:
        raise ValueError("mixed output must not overwrite or reside under source fastfiles")
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    edited_body_path = evidence_dir / "code_post_gfx-mixed-edited.dec"
    proof_path = evidence_dir / "code_post_gfx-mixed-relocation.json"
    edited_body_path.write_bytes(updated)
    output.write_bytes(packaged)

    native = verify_native(output, updated, source_fastfile, acts, replay,
                           evidence_dir / "native-reader", timeout, trace=True)
    native_manifest = native["manifest"]
    if (native_manifest.get("complete") is not True or native_manifest.get("success") is not True or
            native_manifest.get("tested") != native_manifest.get("top_level_index") or
            native_manifest.get("failed") != 0 or native_manifest.get("unavailable") != 0 or
            native_manifest.get("serialized_bytes_read") != len(updated)):
        raise RuntimeError("Replay full-zone native reader rejected the mixed transaction")

    proof = dict(
        schema="replay120-mixed-scriptfile-luafile-full-zone-v1",
        status="native-full-zone-mixed-scriptfile-luafile-pass",
        source_body=dict(path=str(body_path.resolve()), bytes=len(body_data), sha256=source_sha),
        source_trace=dict(path=str(trace_path.resolve()), sha256=sha256_file(trace_path),
                          events=read_index["event_count"]),
        source_native_manifest=dict(path=str(manifest_path.resolve()),
                                    sha256=sha256_file(manifest_path)),
        script_requests=script_requests,
        lua_requests=lua_requests,
        relocation=relocation,
        edited_body=dict(path=str(edited_body_path), bytes=len(updated),
                         sha256=hashlib.sha256(updated).hexdigest()),
        fastfile=dict(path=str(output), bytes=len(packaged),
                      sha256=hashlib.sha256(packaged).hexdigest(),
                      stream_reservation_sizes=reservations),
        native_reader=dict(complete=native_manifest["complete"],
                           success=native_manifest["success"],
                           tested=native_manifest["tested"],
                           failed=native_manifest["failed"],
                           unavailable=native_manifest["unavailable"],
                           serialized_bytes_read=native_manifest["serialized_bytes_read"],
                           manifest_path=native.get("manifest_path"),
                           log_path=native.get("log_path")))
    proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--source-fastfile", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--script-edits", type=Path, required=True)
    parser.add_argument("--lua-edits", type=Path, required=True)
    parser.add_argument("--acts", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    result = build(args.body, args.source_fastfile, args.trace, args.manifest,
                   args.journal, args.script_edits, args.lua_edits,
                   args.acts, args.replay, args.output, args.evidence_dir, args.timeout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
