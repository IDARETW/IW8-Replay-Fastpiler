"""Prototype one-transaction ScriptFile + LuaFile stream relocation.

This adapter composes the proved type-62 block-5 relocator with the native
type-52 block-6 writer, rebasing ScriptFile archive spans after the LuaFile
splices. It requires a complete original-zone trace and rejects overlapping
physical ownership, unsupported pointer classes, and any unhandled stream
reservation changes.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any

try:
    from workstation_fastfiles import ZoneBody, replace_scriptfiles_inline_children
    from workstation_luafile import replace_luafiles_inline_children
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody, replace_scriptfiles_inline_children
    from tools.workstation_luafile import replace_luafiles_inline_children


def _shift_serialized_offset(offset: int, splice_rows: list[dict]) -> int:
    """Map one untouched serialized coordinate through ordered child splices."""
    if not isinstance(offset, int):
        raise ValueError("trace row has a noninteger serialized/archive coordinate")
    shifted = offset
    for splice in splice_rows:
        start = splice["bytecode_archive_offset"]
        end = start + splice["old_bytecode_bytes"]
        if start <= offset < end:
            raise ValueError("ScriptFile trace coordinate intersects a replaced LuaFile child")
        if offset >= end:
            shifted += splice["physical_extent_delta"]
    return shifted


def _adjust_script_trace_report(body_data: bytes, read_index: dict, journal: list[dict],
                                script_indices: list[int], splice_rows: list[dict],
                                new_body_size: int) -> dict:
    spans_by_index = {row["index"]: row for row in read_index["assets"]}
    selected = []
    empty_assets = []
    for index in script_indices:
        if not 0 <= index < len(journal) or index not in spans_by_index:
            raise ValueError(f"ScriptFile index {index} is missing from the complete selected trace")
        journal_row = journal[index]
        source_trace_row = spans_by_index[index]
        if journal_row.get("type_id") != 52 or source_trace_row.get("type_id") != 52:
            raise ValueError(f"XAsset row {index} is not a native ScriptFile")
        if not isinstance(journal_row.get("name"), str):
            raise ValueError(f"ScriptFile row {index} has no native name")
        row = {
            "xasset_index": index,
            "type_id": 52,
            "name": journal_row["name"],
            "serialized_cursor_begin": _shift_serialized_offset(
                source_trace_row["begin_cursor"], splice_rows),
            "serialized_cursor_end": _shift_serialized_offset(
                source_trace_row["end_cursor"], splice_rows),
            "read_spans": [],
            "physical_load_count_by_stream": source_trace_row["physical_load_count_by_stream"],
            "physical_load_bytes_by_stream": source_trace_row["physical_load_bytes_by_stream"],
        }
        for span in source_trace_row["read_spans"]:
            changed = dict(span)
            changed["archive_offset"] = _shift_serialized_offset(
                span["archive_offset"], splice_rows)
            changed["serialized_cursor"] = _shift_serialized_offset(
                span["serialized_cursor"], splice_rows)
            row["read_spans"].append(changed)
        stream6_children = [span for span in source_trace_row["read_spans"]
                            if span.get("origin") == "load_stream_call" and
                            span.get("reader_start_arg") == 0 and
                            span.get("destination_stream_location", {}).get("stream") == 6]
        root_reads = [span for span in source_trace_row["read_spans"]
                      if span.get("origin") == "load_stream_call" and
                      span.get("reader_start_arg") == 0 and span.get("size") == 40]
        if len(root_reads) != 1:
            raise ValueError(f"ScriptFile {index} needs exactly one 40-byte native root")
        root_at = root_reads[0]["archive_offset"]
        (name_token, compressed_len, source_len, bytecode_len, reserved,
         source_pointer, bytecode_pointer) = struct.unpack_from("<QiiiIQQ", body_data, root_at)
        if stream6_children:
            selected.append(row)
        else:
            if (compressed_len, source_len, bytecode_len, reserved,
                    source_pointer, bytecode_pointer) != (0, 0, 0, 0, 0, 0):
                raise ValueError(
                    f"ScriptFile {index} has no stream-6 children but is not the verified empty form")
            empty_assets.append(dict(xasset_index=index, name=row["name"],
                                     root_archive_offset=root_at,
                                     name_token=f"0x{name_token:016x}",
                                     zero_child_sizes=True, null_child_pointers=True))

    return dict(
        status="full-native-trace-selected-for-mixed-relocation",
        xasset_count=read_index["xasset_count"],
        serialized_bytes_read=new_body_size,
        selected_count=len(selected),
        selected_assets=selected,
        verified_empty_scriptfiles=empty_assets,
        global_max_destination_offsets=read_index["max_destination_offsets"],
        global_physical_load_count_by_stream=read_index["physical_load_count_by_stream"],
        global_physical_load_bytes_by_stream=read_index["physical_load_bytes_by_stream"],
        packed_target_stream_counts=read_index["packed_target_stream_counts"],
        packed_alias_token_highword_counts=read_index["packed_alias_token_highword_counts"],
    )


def replace_mixed_script_luafile_batch(
        body_data: bytes, script_edits: list[dict], lua_edits: list[dict],
        expected_body_sha256: str, trace_path: str, manifest_path: str,
        read_index: dict, journal: list[dict],
        stream_reservations: list[int] | None = None) -> tuple[bytes, dict]:
    """Relocate changed ScriptFiles and LuaFiles from one original trace.

    ``script_edits`` rows are ``{xasset_index, name, payload}``, where payload
    is a fully compiled native GSCBIN. ``lua_edits`` rows are the stable
    LuaFile batch schema ``{asset_index, asset_name, trace_asset, payload}``.
    ``read_index`` must be a full-zone :func:`build_read_span_index` result
    selected for every ScriptFile and each edited LuaFile. The function does
    not pack or launch the output; it returns a relocated XFile body plus a
    complete stream-reservation receipt.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("mixed edit transaction source body hash changed")
    if not script_edits or not lua_edits:
        raise ValueError("mixed transaction requires at least one ScriptFile and one LuaFile edit")
    if read_index.get("status") != "native-read-spans-indexed" or \
            read_index.get("xasset_count") != len(body.assets) or \
            read_index.get("serialized_bytes_read") != len(body_data):
        raise ValueError("mixed relocation requires a complete native full-zone read-span index")

    script_indices = [row.get("xasset_index") for row in script_edits]
    lua_indices = [row.get("asset_index") for row in lua_edits]
    if (any(not isinstance(index, int) for index in script_indices + lua_indices) or
            len(set(script_indices + lua_indices)) != len(script_indices) + len(lua_indices)):
        raise ValueError("mixed edit indices must be unique integers")
    for index in script_indices:
        if not 0 <= index < len(body.assets) or body.assets[index].type_id != 52:
            raise ValueError(f"mixed edit row {index} is not a ScriptFile XAsset")
    for index in lua_indices:
        if not 0 <= index < len(body.assets) or body.assets[index].type_id != 62:
            raise ValueError(f"mixed edit row {index} is not a LuaFile XAsset")

    selected_rows = {row["index"]: row for row in read_index.get("assets", [])}
    needed = set(script_indices) | set(lua_indices)
    if not needed.issubset(selected_rows):
        missing = sorted(needed - set(selected_rows))
        raise ValueError(f"full native index omits edited asset rows: {missing}")
    script_type_indices = sorted(index for index, asset in enumerate(body.assets)
                                 if asset.type_id == 52)
    if not set(script_type_indices).issubset(selected_rows):
        raise ValueError("read index must include every ScriptFile to prove complete stream-6 ownership")
    if read_index.get("packed_target_stream_counts", {}).get(6, 0):
        raise ValueError("mixed ScriptFile growth is unsupported while stream-6 packed targets exist")

    # Independently validate root/type ownership and produce one block-5
    # relocation map for all Lua children.
    updated, lua_proof = replace_luafiles_inline_children(
        body_data, lua_edits, expected_body_sha256, trace_path, manifest_path)
    splice_rows = lua_proof.get("edits", [])

    # Ensure typed physical children from the two asset families are disjoint.
    script_intervals = []
    for index in script_type_indices:
        row = selected_rows[index]
        for span in row.get("read_spans", []):
            dest = span.get("destination_stream_location", {})
            if (span.get("origin") == "load_stream_call" and span.get("reader_start_arg") == 0
                    and dest.get("stream") == 6 and span.get("size", 0) > 0):
                script_intervals.append((span["archive_offset"],
                                         span["archive_offset"] + span["size"], index))
    lua_intervals = [(item["bytecode_archive_offset"],
                      item["bytecode_archive_offset"] + item["old_bytecode_bytes"],
                      item["asset_index"]) for item in splice_rows]
    for script_start, script_end, script_index in script_intervals:
        for lua_start, lua_end, lua_index in lua_intervals:
            if script_start < lua_end and lua_start < script_end:
                raise ValueError(
                    f"ScriptFile {script_index} and LuaFile {lua_index} trace spans overlap")

    adjusted_report = _adjust_script_trace_report(
        body_data, read_index, journal, script_type_indices, splice_rows, len(updated))
    populated_script_indices = {row["xasset_index"]
                                for row in adjusted_report["selected_assets"]}
    if any(edit.get("xasset_index") not in populated_script_indices for edit in script_edits):
        raise ValueError("selected ScriptFile has no proven owned stream-6 children to replace")
    second, script_proof = replace_scriptfiles_inline_children(
        updated, script_edits, adjusted_report, hashlib.sha256(updated).hexdigest())
    reservations = lua_proof.get("stream_reservation_sizes")
    if reservations is None:
        if (not isinstance(stream_reservations, list) or len(stream_reservations) != 11 or
                any(not isinstance(size, int) or size < 0 for size in stream_reservations)):
            raise ValueError("same-extent LuaFile mixed edits require the original eleven stream reservations")
        reservations = list(stream_reservations)
        old_stream5 = read_index.get("max_destination_offsets", {}).get(5, 0)
        if reservations[5] < old_stream5:
            raise ValueError("original block-5 reservation is below the traced high-water")
    if not isinstance(reservations, list) or len(reservations) != 11:
        raise ValueError("LuaFile relocation did not return all eleven stream reservations")
    original_stream6 = read_index.get("max_destination_offsets", {}).get(6, 0)
    if script_proof.get("original_stream6_high_water") != original_stream6:
        raise ValueError("ScriptFile writer's original stream-6 high-water differs from full trace")
    reservations[6] = script_proof["new_stream6_high_water"]
    if (lua_proof.get("stream5_new_high_water") is not None and
            reservations[5] != lua_proof.get("stream5_new_high_water")):
        raise ValueError("combined block-5 high-water differs from LuaFile relocation proof")
    stream5_high_water = lua_proof.get("stream5_new_high_water",
                                       read_index.get("max_destination_offsets", {}).get(5, 0))

    result_body = ZoneBody.parse(second)
    if result_body.assets != body.assets:
        raise AssertionError("mixed transaction changed native XAsset table order or types")
    proof = dict(
        schema="replay120-mixed-scriptfile-luafile-relocation-v1",
        status="mixed-scriptfile-luafile-relocation-ready",
        source_body_sha256=expected_body_sha256,
        output_body_sha256=result_body.source_sha256,
        xasset_table_unchanged=True,
        scriptfile_proof=script_proof,
        empty_scriptfile_rows=adjusted_report["verified_empty_scriptfiles"],
        luafile_proof=lua_proof,
        stream_reservation_sizes=reservations,
        stream5_high_water=stream5_high_water,
        stream6_high_water=script_proof["new_stream6_high_water"],
        full_native_trace_events=read_index.get("event_count"),
        pointer_contracts=dict(
            stream5_tag5_absolute=lua_proof.get("packed_stream5_tag5_absolute_validated"),
            stream5_tag15_asset_relative=lua_proof.get("packed_stream5_tag15_asset_relative_validated"),
            stream5_aliases_rebased=lua_proof.get("packed_stream5_aliases_rebased"),
            stream6_packed_targets=0,
            stream6_ownership="all physical stream-6 reads are owned by ScriptFiles"),
    )
    return second, proof
