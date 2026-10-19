"""Repack several staged ScriptFile edits from a trace-proven native zone."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from roundtrip_replay_fastfile import verify_native
from workstation_asset_codecs import compile_scriptfile
from workstation_fastfiles import (
    ACTS_DEFAULT,
    DEFAULT_GSC_TOOL,
    REPLAY_EXECUTABLE,
    _assert_run_inputs_unchanged,
    _cache_receipt,
    _read_native_rows,
    acts_tool_identity,
    make_replay_header_only_patch,
    pack_replay_uncompressed,
    replace_scriptfiles_inline_children,
    sha256_file,
    source_profile,
    unpack_replay_uncompressed,
    ZoneBody,
    ordered_asset_identity_sha256,
)


def validate_scriptfile_native_identity(span_report: dict, source_walk: dict,
                                        source_rows: list[dict], output_native: dict) -> dict:
    """Bind the output journal to the complete, hash-validated source walk."""
    expected_walk = {
        "native_walk_key": source_walk.get("walk_key"),
        "native_manifest_sha256": source_walk.get("manifest_sha256"),
        "stream_trace_sha256": source_walk.get("stream_trace_sha256"),
    }
    differences = {key: (span_report.get(key), value)
                   for key, value in expected_walk.items()
                   if span_report.get(key) != value}
    if differences:
        raise ValueError(f"ScriptFile span report differs from the hash-validated source walk: {differences}")
    source_journal_sha256 = source_walk.get("journal_sha256")
    if not isinstance(source_journal_sha256, str) or len(source_journal_sha256) != 64:
        raise ValueError("ScriptFile source walk omits its hash-bound native journal")
    expected_identity = ordered_asset_identity_sha256(source_rows)
    actual_identity = output_native.get("journal_asset_identity_sha256")
    if actual_identity != expected_identity:
        raise ValueError("ScriptFile replacement changed native XAsset type/order/name identity")
    return dict(source_native_walk_key=source_walk["walk_key"],
                source_native_manifest_sha256=source_walk["manifest_sha256"],
                source_stream_trace_sha256=source_walk["stream_trace_sha256"],
                source_journal_sha256=source_journal_sha256,
                ordered_asset_identity_sha256=expected_identity)


def run(source: Path, cache_root: Path, zone_id: str, span_report: dict,
        edits: list[dict], output: Path, acts: Path = ACTS_DEFAULT,
        replay: Path = REPLAY_EXECUTABLE,
        gsc_tool: Path = DEFAULT_GSC_TOOL, timeout: int = 1800) -> dict:
    source, cache_root = source.resolve(strict=True), cache_root.resolve(strict=True)
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
    if (profile["sha256"] != receipt["source"]["sha256"] or
            [(r["extension"], r["sha256"]) for r in profile["patches"]] !=
            [(r["extension"], r["sha256"]) for r in receipt["source"]["patches"]]):
        raise ValueError("source/patch chain differs from the decoded receipt")
    body_path = cache_path / receipt["final_body_relative_path"]
    original = body_path.read_bytes()
    body = ZoneBody.parse(original)
    if (span_report.get("zone_id") != zone_id or
            span_report.get("source_body_sha256") != body.source_sha256 or
            span_report.get("source", {}).get("sha256") != profile["sha256"]):
        raise ValueError("typed trace report is not bound to the selected zone/body")
    source_walk, source_rows = _read_native_rows(cache_path, body, require_trace=True)

    acts_before = acts_tool_identity(acts)
    replay_hash = sha256_file(replay)
    compiler_hash = sha256_file(gsc_tool)
    replacements = []
    for row in edits:
        index = row.get("xasset_index")
        source_text = row.get("content")
        if not isinstance(index, int) or not isinstance(source_text, str):
            raise ValueError("each staged ScriptFile edit needs an integer index and source text")
        payload = compile_scriptfile(source_text, gsc_tool, str(index))
        payload_hash = hashlib.sha256(payload).hexdigest()
        if row.get("edited_payload_sha256") != payload_hash:
            raise ValueError(f"ScriptFile {index} compiler output differs from the staged payload hash")
        replacements.append(dict(xasset_index=index, name=row.get("name"), payload=payload,
                                 edited_payload_sha256=payload_hash,
                                 edited_source_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest()))
    if sha256_file(gsc_tool) != compiler_hash:
        raise RuntimeError("GSC compiler changed while compiling staged assets")

    updated, edit_proof = replace_scriptfiles_inline_children(
        original, replacements, span_report, body.source_sha256)
    if len(updated) != len(original) + edit_proof["stream6_extent_delta"]:
        raise AssertionError("serialized body extent differs from cumulative child delta")
    final_header = profile["final_header"]
    stream_sizes = list(final_header["block_sizes"])
    old_stream6 = span_report.get("global_max_destination_offsets", {})
    old_stream6 = old_stream6.get(6, old_stream6.get("6"))
    if old_stream6 != stream_sizes[6]:
        raise ValueError("source block-6 reservation differs from trace high-water")
    stream_sizes[6] = edit_proof["new_stream6_high_water"]

    packed = pack_replay_uncompressed(updated, stream_sizes,
                                      final_header["xfile_version"],
                                      profile["header"]["transient_type"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(packed)
    sidecars = []
    for patch_row in profile.get("patches", []):
        source_patch = Path(patch_row["path"]).resolve(strict=True)
        sidecar = output.with_suffix(patch_row["extension"])
        sidecar.write_bytes(make_replay_header_only_patch(source_patch.read_bytes(), packed))
        sidecars.append(dict(path=str(sidecar), bytes=sidecar.stat().st_size,
                             sha256=sha256_file(sidecar),
                             replaces_stale_source_patch=str(source_patch)))
    with tempfile.TemporaryDirectory(prefix="rwt-scriptfiles-") as temp:
        native = verify_native(output, updated, source, acts, replay,
                               Path(temp), timeout, trace=True)
    retained_identity = validate_scriptfile_native_identity(
        span_report, source_walk, source_rows, native)
    applied = native["manifest"].get("applied_patches", [])
    if [Path(item).suffix for item in applied] != [row["extension"] for row in profile.get("patches", [])]:
        raise ValueError("native reader did not apply the generated patch chain")
    summary = native["trace_summary"]
    max_stream6 = summary["max_destination_offsets"].get(6, summary["max_destination_offsets"].get("6", 0))
    if max_stream6 != stream_sizes[6]:
        raise ValueError("native edited-zone stream-6 high-water differs from reservation")
    if summary["packed_target_stream_counts"].get(6, summary["packed_target_stream_counts"].get("6", 0)):
        raise ValueError("edited native zone introduced a packed stream-6 target")
    _assert_run_inputs_unchanged(source, profile, acts, acts_before, replay, replay_hash)
    if sha256_file(gsc_tool) != compiler_hash:
        raise RuntimeError("GSC compiler changed during native reader verification")
    output_body = unpack_replay_uncompressed(output.read_bytes())
    if output_body != updated:
        raise ValueError("emitted FF body differs from the edited serialized body")
    receipt = dict(schema=1, status="multi-scriptfile-edit-native-reader-pass",
                   source_fastfile=str(source), source_fastfile_sha256=profile["sha256"],
                   source_body_sha256=body.source_sha256,
                   output_fastfile=str(output), output_fastfile_sha256=sha256_file(output),
                   output_body_sha256=hashlib.sha256(output_body).hexdigest(),
                   edited_assets=[dict(xasset_index=row["xasset_index"], name=row["name"],
                                       edited_payload_sha256=row["edited_payload_sha256"],
                                       edited_source_sha256=row["edited_source_sha256"])
                                  for row in replacements],
                   output_stream_reservations=stream_sizes,
                   edit_proof=edit_proof, retained_asset_identity=retained_identity,
                   sidecars=sidecars, native_reader=native,
                   support_limit=("Only zones whose complete stream-6 allocation run is exclusively inline ScriptFile source/bytecode children, "
                                  "with no packed targets into stream 6, are relocatable by this writer."))
    receipt["native_reader"].pop("manifest_path", None)
    receipt["native_reader"].pop("log_path", None)
    receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt
