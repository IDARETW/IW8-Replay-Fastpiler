"""Apply and Replay-verify a multi-LuaFile edit transaction in one zone."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from roundtrip_replay_fastfile import verify_native  # noqa: E402
from workstation_fastfiles import (  # noqa: E402
    ACTS_DEFAULT, REPLAY_EXECUTABLE, pack_replay_uncompressed, unpack_replay_uncompressed,
)
from workstation_luafile import replace_luafiles_inline_children  # noqa: E402
from workstation_trace_index import build_read_span_index  # noqa: E402


DEFAULT_RECEIPT = ROOT / "evidence" / "workstation-luafile-cod-native-trace.json"
DEFAULT_SOURCE_FASTFILE = REPLAY_EXECUTABLE.parent / "zone" / "code_post_gfx.ff"
DEFAULT_ACTS = ACTS_DEFAULT
DEFAULT_REPLAY = REPLAY_EXECUTABLE


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(receipt_path: Path, body_path: Path, source_fastfile: Path,
          trace_path: Path, manifest_path: Path, journal_path: Path,
          edits_path: Path, acts: Path, replay: Path,
          output: Path, evidence_dir: Path, timeout: int = 1800) -> dict:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    body = body_path.read_bytes()
    body_sha = hashlib.sha256(body).hexdigest()
    if body_sha != receipt["source_body"]["sha256"]:
        raise ValueError("decoded source body differs from pinned LuaFile trace receipt")
    if sha256_file(trace_path) != receipt["stream_trace"]["sha256"]:
        raise ValueError("stream trace changed since the pinned LuaFile receipt")
    if sha256_file(manifest_path) != receipt["native_manifest"]["sha256"]:
        raise ValueError("native manifest changed since the pinned LuaFile receipt")

    requests = json.loads(edits_path.read_text(encoding="utf-8"))
    if not isinstance(requests, list) or len(requests) < 2:
        raise ValueError("batch test requires at least two LuaFile edits")
    indices = [row.get("asset_index") for row in requests]
    if any(not isinstance(index, int) for index in indices) or len(set(indices)) != len(indices):
        raise ValueError("LuaFile edit indices must be unique integers")

    body_bytes = len(body)
    index = build_read_span_index(trace_path, manifest_path, body_bytes,
                                  selected_assets=indices)
    if index.get("event_count") != receipt["stream_trace"]["event_count"]:
        raise ValueError("selected trace index did not consume the complete native event stream")
    journal = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
               if line.strip()]
    traced = {row["index"]: row for row in index["assets"]}
    edits = []
    for request in requests:
        asset_index = request["asset_index"]
        name = request["asset_name"]
        journal_row = journal[asset_index]
        if journal_row.get("type_id") != 62 or journal_row.get("name") != name:
            raise ValueError(f"selected row {asset_index} is not the requested native LuaFile")
        row = traced.get(asset_index)
        if row is None:
            raise ValueError(f"selected LuaFile {asset_index} lacks native physical spans")
        payload_path = Path(request["payload_path"]).resolve(strict=True)
        payload = payload_path.read_bytes()
        if sha256_file(payload_path) != request.get("payload_sha256"):
            raise ValueError(f"LuaFile edit payload changed after request was authored: {name}")
        edits.append(dict(asset_index=asset_index, asset_name=name,
                          trace_asset=dict(xasset_index=asset_index, type_id=62,
                                           name=name, read_spans=row["read_spans"]),
                          payload=payload,
                          payload_provenance=dict(path=str(payload_path), sha256=sha256_file(payload_path),
                                                  bytes=len(payload))))

    updated, relocation = replace_luafiles_inline_children(
        body, edits, body_sha, trace_path, manifest_path)
    reservations = relocation.get("stream_reservation_sizes")
    if not isinstance(reservations, list) or len(reservations) != 11:
        raise ValueError("LuaFile batch did not calculate all eleven stream reservations")
    packaged = pack_replay_uncompressed(updated, reservations, xfile_version=0xFF7)
    if unpack_replay_uncompressed(packaged) != updated:
        raise AssertionError("native IWC framing changed the relocated body")

    output, evidence_dir = output.resolve(), evidence_dir.resolve()
    if output == source_fastfile or source_fastfile in output.parents:
        raise ValueError("LuaFile output must not overwrite or reside beneath source fastfiles")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    edited_body_path = evidence_dir / "code_post_gfx-luafile-batch-edited.dec"
    proof_path = evidence_dir / "code_post_gfx-luafile-batch-relocation.json"
    edited_body_path.write_bytes(updated)
    output.write_bytes(packaged)

    native = verify_native(output, updated, source_fastfile, acts, replay,
                           evidence_dir / "native-reader", timeout, trace=True)
    native_summary = native["manifest"]
    if (native_summary.get("complete") is not True or native_summary.get("success") is not True or
            native_summary.get("tested") != native_summary.get("top_level_index") or
            native_summary.get("failed") != 0 or native_summary.get("unavailable") != 0 or
            native_summary.get("serialized_bytes_read") != len(updated)):
        raise RuntimeError("Replay full-zone reader did not validate the LuaFile batch")

    proof = dict(
        schema="replay120-luafile-batch-roundtrip-v1",
        status="native-full-zone-luafile-batch-pass",
        source_body=dict(path=str(body_path.resolve()), bytes=len(body), sha256=body_sha),
        source_trace=dict(path=str(trace_path.resolve()), sha256=sha256_file(trace_path),
                          events=receipt["stream_trace"]["event_count"]),
        source_native_manifest=dict(path=str(manifest_path.resolve()),
                                    sha256=sha256_file(manifest_path)),
        edits=[dict(asset_index=row["asset_index"], asset_name=row["asset_name"],
                    payload=row["payload_provenance"]) for row in edits],
        relocation=relocation,
        edited_body=dict(path=str(edited_body_path), bytes=len(updated),
                         sha256=hashlib.sha256(updated).hexdigest()),
        output_fastfile=dict(path=str(output), bytes=len(packaged),
                             sha256=hashlib.sha256(packaged).hexdigest(),
                             stream_reservation_sizes=reservations),
        native_reader=dict(complete=native_summary["complete"],
                           success=native_summary["success"],
                           tested=native_summary["tested"], failed=native_summary["failed"],
                           unavailable=native_summary["unavailable"],
                           serialized_bytes_read=native_summary["serialized_bytes_read"],
                           trace_summary=native_summary.get("trace_summary"),
                           manifest_path=native.get("manifest_path"),
                           log_path=native.get("log_path")),
        mixed_scriptfile_luafile_edits_supported=False,
        limitation=("This transaction batches LuaFiles sharing one original-body/full-zone trace. "
                    "ScriptFile plus LuaFile edits remain rejected until a unified cross-stream "
                    "stream-5/stream-6 relocator is implemented."))
    proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--source-fastfile", type=Path, default=DEFAULT_SOURCE_FASTFILE)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--edits", type=Path, required=True)
    parser.add_argument("--acts", type=Path, default=DEFAULT_ACTS)
    parser.add_argument("--replay", type=Path, default=DEFAULT_REPLAY)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    trace_path = args.trace or Path(receipt["stream_trace"]["path"])
    manifest_path = args.manifest or Path(receipt["native_manifest"]["path"])
    journal_path = args.journal or manifest_path.with_name("assets.jsonl")
    proof = build(args.receipt, args.body, args.source_fastfile,
                  trace_path, manifest_path, journal_path, args.edits,
                  args.acts, args.replay, args.output, args.evidence_dir, args.timeout)
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    main()
