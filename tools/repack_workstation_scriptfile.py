"""Repack one trace-owned inline ScriptFile edit and verify it natively.

Same-extent replacements preserve all offsets. Growth is currently supported
only for the proven code_post_gfx case where one ScriptFile owns the complete
stream-6 tail, both children are inline and traced, no packed target points to
stream 6, and no later stream-6 allocation exists. This is a bounded relocation
proof for that zone, not general arbitrary-zone relocation support.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from roundtrip_replay_fastfile import verify_native
from workstation_fastfiles import (
    ACTS_DEFAULT,
    DEFAULT_GSC_TOOL,
    REPLAY_EXECUTABLE,
    _assert_run_inputs_unchanged,
    acts_tool_identity,
    make_replay_header_only_patch,
    pack_replay_uncompressed,
    replace_scriptfile_inline_children,
    sha256_file,
    source_profile,
    unpack_replay_uncompressed,
    ZoneBody,
    _cache_receipt,
)
from workstation_asset_codecs import compile_scriptfile


def run(source: Path, cache_root: Path, zone_id: str, spans_path: Path,
        asset_index: int, source_text: Path, output: Path,
        acts: Path = ACTS_DEFAULT, replay: Path = REPLAY_EXECUTABLE,
        gsc_tool: Path = DEFAULT_GSC_TOOL, timeout: int = 1800) -> dict:
    source = source.resolve(strict=True)
    cache_root = cache_root.resolve(strict=True)
    spans_path = spans_path.resolve(strict=True)
    source_text = source_text.resolve(strict=True)
    acts, replay, gsc_tool = (acts.resolve(strict=True), replay.resolve(strict=True),
                              gsc_tool.resolve(strict=True))
    output = output.resolve()
    if output.exists() or output.with_suffix(".fp").exists() or output.with_suffix(".fc").exists():
        raise FileExistsError("output FF or patch sidecar already exists")
    matches = list(cache_root.glob(f"*/{zone_id}/decode-receipt.json"))
    if len(matches) != 1:
        raise ValueError("zone id does not identify exactly one decoded source receipt")
    cache_path = matches[0].parent
    receipt = _cache_receipt(cache_path, zone_id)
    profile = source_profile(source)
    tool_before = acts_tool_identity(acts)
    replay_hash = sha256_file(replay)
    if profile["sha256"] != receipt["source"]["sha256"] or [
            (row["extension"], row["sha256"]) for row in profile["patches"]
    ] != [(row["extension"], row["sha256"]) for row in receipt["source"]["patches"]]:
        raise ValueError("source/patch chain differs from the decoded receipt")
    body_path = cache_path / receipt["final_body_relative_path"]
    original = body_path.read_bytes()
    body = ZoneBody.parse(original)
    span_report = json.loads(spans_path.read_text(encoding="utf-8"))
    if (span_report.get("zone_id") != zone_id or
            span_report.get("source_body_sha256") != body.source_sha256 or
            span_report.get("source", {}).get("sha256") != profile["sha256"]):
        raise ValueError("typed trace report is not bound to the selected zone/body")
    trace_asset = next((row for row in span_report.get("selected_assets", [])
                        if row.get("xasset_index") == asset_index), None)
    if trace_asset is None:
        raise ValueError("asset is not covered by the selected typed trace report")
    asset_name = trace_asset.get("name")
    edited_source = source_text.read_text(encoding="utf-8")
    gsc_tool_hash = sha256_file(gsc_tool)
    replacement_gscbin = compile_scriptfile(edited_source, gsc_tool, str(asset_index))
    if sha256_file(gsc_tool) != gsc_tool_hash:
        raise RuntimeError("GSC compiler changed while compiling the asset")
    updated, edit_proof = replace_scriptfile_inline_children(
        original, asset_index, asset_name, trace_asset, replacement_gscbin,
        expected_body_sha256=body.source_sha256,
        trace_safety=span_report, allow_stream6_tail_growth=True)
    edited_body = ZoneBody.parse(updated)
    expected_extent = len(original) + edit_proof["stream6_extent_delta"]
    if len(updated) != expected_extent:
        raise AssertionError("serialized body extent does not match owned child delta")
    final_header = profile["final_header"]
    stream_sizes = list(final_header["block_sizes"])
    if edit_proof["stream6_extent_delta"]:
        observed_stream6 = span_report.get("global_max_destination_offsets", {})
        observed_stream6 = observed_stream6.get(6, observed_stream6.get("6"))
        if observed_stream6 != stream_sizes[6]:
            raise ValueError("source block-6 reservation differs from traced high-water mark")
        stream_sizes[6] = edit_proof["stream6_new_high_water"]
    packed = pack_replay_uncompressed(updated, stream_sizes,
                                      final_header["xfile_version"],
                                      profile["header"]["transient_type"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(packed)
    sidecars = []
    for patch_row in profile.get("patches", []):
        source_patch = Path(patch_row["path"]).resolve(strict=True)
        sidecar = output.with_suffix(patch_row["extension"])
        patch_bytes = make_replay_header_only_patch(source_patch.read_bytes(), packed)
        sidecar.write_bytes(patch_bytes)
        sidecars.append(dict(path=str(sidecar), bytes=len(patch_bytes),
                             sha256=sha256_file(sidecar),
                             replaces_stale_source_patch=str(source_patch)))
    with tempfile.TemporaryDirectory(prefix="rwt-scriptfile-") as temp:
        native = verify_native(output, updated, source, acts, replay,
                               Path(temp), timeout, trace=True)
        applied = native["manifest"].get("applied_patches", [])
        if [Path(item).suffix for item in applied] != [row["extension"] for row in profile.get("patches", [])]:
            raise ValueError("native reader did not apply the generated header-only patch chain")
        trace_summary = native.get("trace_summary")
        max_stream6 = trace_summary["max_destination_offsets"].get(
            6, trace_summary["max_destination_offsets"].get("6", 0))
        reserved_stream6 = stream_sizes[6]
        if max_stream6 != reserved_stream6:
            raise ValueError(f"edited Replay block-6 high-water {max_stream6} differs from reservation {reserved_stream6}")
        stream6_targets = trace_summary["packed_target_stream_counts"].get(
            6, trace_summary["packed_target_stream_counts"].get("6", 0))
        if stream6_targets:
            raise ValueError("edited zone introduced a packed reference into stream 6")
    _assert_run_inputs_unchanged(source, profile, acts, tool_before, replay, replay_hash)
    if sha256_file(gsc_tool) != gsc_tool_hash:
        raise RuntimeError("GSC compiler changed during native reader verification")
    output_body = unpack_replay_uncompressed(output.read_bytes())
    if output_body != updated:
        raise ValueError("emitted FF body differs from edited serialized body")
    extent_delta = edit_proof["stream6_extent_delta"]
    result = dict(schema=1,
                  status=("stream6-tail-growth-scriptfile-edit-native-reader-pass"
                          if extent_delta else "same-extent-scriptfile-edit-native-reader-pass"),
                  source_fastfile=str(source), source_fastfile_sha256=profile["sha256"],
                  source_body_sha256=body.source_sha256,
                  output_fastfile=str(output), output_fastfile_sha256=sha256_file(output),
                  output_body_sha256=hashlib.sha256(output_body).hexdigest(),
                  edited_payload_sha256=hashlib.sha256(replacement_gscbin).hexdigest(),
                  edited_payload_bytes=len(replacement_gscbin),
                  edited_source_sha256=hashlib.sha256(edited_source.encode("utf-8")).hexdigest(),
                  gsc_tool=dict(path=str(gsc_tool), sha256=gsc_tool_hash),
                  acts_tool_identity=tool_before,
                  replay_executable_sha256=replay_hash,
                  xasset_table_unchanged=edited_body.assets == body.assets,
                  body_extent_unchanged=len(updated) == len(original),
                  output_stream_reservations=stream_sizes,
                  edit=edit_proof, sidecars=sidecars, native_reader=native,
                  support_limit=("Same-extent ScriptFile replacement, or growth of the sole trace-proven stream-6 tail owner only; "
                                 "all other assets and packed pointers are byte-preserved."))
    result["native_reader"].pop("manifest_path", None)
    result["native_reader"].pop("log_path", None)
    receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
    receipt_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--zone-id", required=True)
    parser.add_argument("--span-report", type=Path, required=True)
    parser.add_argument("--asset-index", type=int, required=True)
    parser.add_argument("--source-text", type=Path, required=True)
    parser.add_argument("--acts", type=Path, default=ACTS_DEFAULT)
    parser.add_argument("--replay", type=Path, default=REPLAY_EXECUTABLE)
    parser.add_argument("--gsc-tool", type=Path, default=DEFAULT_GSC_TOOL)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    result = run(args.source, args.cache, args.zone_id, args.span_report,
                 args.asset_index, args.source_text, args.output,
                 args.acts, args.replay, args.gsc_tool, args.timeout)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
