"""Build and Replay-verify one trace-relocated LuaFile edit in a full zone."""
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
from workstation_luafile import replace_luafile_inline_child  # noqa: E402


DEFAULT_RECEIPT = ROOT / "evidence" / "workstation-luafile-cod-native-trace.json"
DEFAULT_EDIT = ROOT / "evidence" / "workstation-lua-native-compile" / "edited_source.luac"
DEFAULT_SOURCE_FF = REPLAY_EXECUTABLE.parent / "zone" / "code_post_gfx.ff"
DEFAULT_ACTS = ACTS_DEFAULT
DEFAULT_REPLAY = REPLAY_EXECUTABLE


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(receipt_path: Path, replacement_path: Path, source_fastfile: Path,
          acts: Path, replay: Path, output: Path, evidence_dir: Path,
          timeout: int = 1800) -> dict:
    receipt_path = receipt_path.resolve(strict=True)
    replacement_path = replacement_path.resolve(strict=True)
    source_fastfile = source_fastfile.resolve(strict=True)
    acts = acts.resolve(strict=True)
    replay = replay.resolve(strict=True)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    source = receipt["source_body"]
    body_path = Path(source["path"]).resolve(strict=True)
    body = body_path.read_bytes()
    if sha256_bytes(body) != source["sha256"]:
        raise ValueError("decoded LuaFile body differs from the pinned native trace receipt")
    asset = receipt["asset"]
    if asset.get("type_id") != 62 or asset.get("name") != "luashared/cod.lua":
        raise ValueError("trace receipt is not the pinned code.lua LuaFile fixture")
    trace_path = Path(receipt["stream_trace"]["path"]).resolve(strict=True)
    manifest_path = Path(receipt["native_manifest"]["path"]).resolve(strict=True)
    if sha256_file(trace_path) != receipt["stream_trace"]["sha256"]:
        raise ValueError("native trace file changed since its source receipt was written")
    if sha256_file(manifest_path) != receipt["native_manifest"]["sha256"]:
        raise ValueError("native trace manifest changed since its source receipt was written")

    replacement = replacement_path.read_bytes()
    updated, relocation = replace_luafile_inline_child(
        body, asset["xasset_index"], asset["name"],
        dict(asset, xasset_index=asset["xasset_index"]), replacement,
        source["sha256"], trace_path, manifest_path)
    reservations = relocation.get("stream_reservation_sizes")
    if not isinstance(reservations, list) or len(reservations) != 11:
        raise ValueError("LuaFile relocation did not calculate all eleven stream reservations")
    packaged = pack_replay_uncompressed(updated, reservations, xfile_version=0xFF7)
    if unpack_replay_uncompressed(packaged) != updated:
        raise AssertionError("native IWC framing changed the relocated body")

    output = output.resolve()
    evidence_dir = evidence_dir.resolve()
    if output == source_fastfile or source_fastfile in output.parents:
        raise ValueError("LuaFile output must not overwrite or reside under shipped source fastfiles")
    output.parent.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    body_output = evidence_dir / "code_post_gfx-luafile-edited.dec"
    receipt_output = evidence_dir / "code_post_gfx-luafile-relocation.json"
    body_output.write_bytes(updated)
    output.write_bytes(packaged)

    # Run the real Replay loader across every XAsset and compare the complete
    # native journal/serialized EOF against this relocated body.
    native = verify_native(output, updated, source_fastfile, acts, replay,
                           evidence_dir / "native-reader", timeout, trace=True)
    manifest = native["manifest"]
    proof = dict(
        schema="replay120-luafile-growth-roundtrip-v1",
        status="native-full-zone-luafile-growth-pass",
        native_trace_source_receipt=dict(path=str(receipt_path),
                                         sha256=sha256_file(receipt_path)),
        replacement=dict(path=str(replacement_path), bytes=len(replacement),
                         sha256=sha256_bytes(replacement)),
        relocated_body=dict(path=str(body_output), bytes=len(updated),
                            sha256=sha256_bytes(updated)),
        output_fastfile=dict(path=str(output), bytes=len(packaged),
                             sha256=sha256_bytes(packaged),
                             stream_reservation_sizes=reservations),
        relocation=relocation,
        native_reader=dict(manifest_path=native["manifest_path"],
                           complete=manifest.get("complete"),
                           success=manifest.get("success"),
                           tested=manifest.get("tested"),
                           failed=manifest.get("failed"),
                           unavailable=manifest.get("unavailable"),
                           top_level_index=manifest.get("top_level_index"),
                           serialized_bytes_read=manifest.get("serialized_bytes_read"),
                           trace_summary=native.get("trace_summary"),
                           log_path=native["log_path"],
                           log_sha256=native["log_sha256"]),
        target_image_sha256=native["replay_executable_sha256"],
        acts_tool_identity=native["acts_tool_identity"])
    receipt_output.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    return proof


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--replacement", type=Path, default=DEFAULT_EDIT)
    parser.add_argument("--source-fastfile", type=Path, default=DEFAULT_SOURCE_FF)
    parser.add_argument("--acts", type=Path, default=DEFAULT_ACTS)
    parser.add_argument("--replay", type=Path, default=DEFAULT_REPLAY)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "evidence" / "workstation-luafile-growth" /
                        "code_post_gfx-luafile-edit.ff")
    parser.add_argument("--evidence-dir", type=Path,
                        default=ROOT / "evidence" / "workstation-luafile-growth")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    result = build(args.trace_receipt, args.replacement, args.source_fastfile,
                   args.acts, args.replay, args.output, args.evidence_dir,
                   args.timeout)
    print(json.dumps({"status": result["status"],
                      "output_fastfile": result["output_fastfile"],
                      "native_reader": result["native_reader"]}, indent=2))


if __name__ == "__main__":
    main()
