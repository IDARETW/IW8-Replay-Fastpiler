"""Trace-bound Replay RawFile row append and exclusive tail removal."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct
import tempfile
import zlib

try:
    from workstation_fastfiles import ZoneBody
    from workstation_luafile_operations import _trace_contract, _rebase_aliases
    from workstation_rawfile import INLINE, PTR_FOLLOWS, RAWFILE_ROOT_BYTES, _raw_bytes
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_luafile_operations import _trace_contract, _rebase_aliases
    from tools.workstation_rawfile import INLINE, PTR_FOLLOWS, RAWFILE_ROOT_BYTES, _raw_bytes


RAWFILE_TYPE_ID = 51
XASSET_ROW_BYTES = 16
XASSET_COUNT_OFFSET = 16


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_name(name: str) -> bytes:
    if (not isinstance(name, str) or not name or "\0" in name or
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}", name) or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("RawFile name must be a confined native path")
    encoded = name.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError("RawFile name exceeds the supported native path length")
    return encoded + b"\0"


def _table_contract(body: bytes, trace_path, manifest_path, row_delta: int,
                    removed_ranges=(), logical_delete_ranges=(), removed_owner=None,
                    *, expected_trace_sha256: str, expected_manifest_sha256: str):
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest_bytes = manifest_path.read_bytes()
    if _sha(manifest_bytes) != expected_manifest_sha256:
        raise ValueError("RawFile row manifest differs from the immutable native walk receipt")
    if _file_sha(trace_path) != expected_trace_sha256:
        raise ValueError("RawFile row trace differs from the immutable native walk receipt")
    # ACTS 1.20 manifests omit their trace digest. The walk receipt owns that
    # digest, so make a temporary adapter copy only for the older shared
    # ownership parser; the original manifest remains byte-for-byte untouched.
    manifest = __import__("json").loads(manifest_bytes)
    recorded_trace_sha = manifest.get("stream_trace_sha256")
    if recorded_trace_sha is not None and recorded_trace_sha != expected_trace_sha256:
        raise ValueError("RawFile manifest trace digest conflicts with its immutable walk receipt")
    normalized_path = manifest_path
    temp_dir = None
    if recorded_trace_sha is None:
        manifest["stream_trace_sha256"] = expected_trace_sha256
        temp_dir = tempfile.TemporaryDirectory(prefix="rawfile-trace-contract-")
        normalized_path = Path(temp_dir.name) / "manifest.json"
        normalized_path.write_text(__import__("json").dumps(manifest), encoding="utf-8")
    from workstation_luafile_operations import XASSET_ROW_SIZE
    try:
        values = _trace_contract(body, trace_path, normalized_path,
            removed_stream_ranges=tuple(removed_ranges),
            logical_delete_ranges=tuple(logical_delete_ranges),
            removed_owner=removed_owner, table_row_delta=row_delta)
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()
    (manifest, asset_bases, intervals, aliases, table, max_destinations,
     alias_count, relocated_targets, relocated_asset_bases, pointer_stats) = values
    # Preserve source-coordinate maxima while making the exact relocated
    # cursors available to append writers. A table-row splice can alter later
    # block-5 alignment, so source max + row size is not a reliable tail.
    pointer_stats = dict(pointer_stats,
        relocated_stream_max_destinations=pointer_stats.get("relocated_stream_max_destinations", {}),
        relocated_terminal_cursors=pointer_stats.get("relocated_terminal_cursors", {}))
    parsed = ZoneBody.parse(body)
    if (table.get("size") != len(parsed.assets) * XASSET_ROW_BYTES or
            table.get("archive") != parsed.asset_table_offset or
            table.get("archive", -1) + table.get("size", 0) != parsed.first_payload_offset):
        raise ValueError("native trace XAsset table allocation differs from the serialized table")
    return (manifest, asset_bases, intervals, aliases, table, max_destinations,
            alias_count, relocated_targets, relocated_asset_bases, pointer_stats)


def append_rawfile_tail(body_data: bytes, name: str, raw_content: bytes,
                        existing_names: set[str], final_native_row: dict,
                        final_trace_asset: dict, expected_body_sha256: str,
                        trace_path: str | Path, manifest_path: str | Path,
                        stream_reservations: list[int], *, compressed: bool = True,
                        expected_trace_sha256: str, expected_manifest_sha256: str):
    """Append one type-51 RawFile after a trace-proven exact source EOF.

    The new 24-byte root is AtStart/stream-1, followed by a pointer-follows
    XString and an inline stream-5 buffer. Table growth and existing packed
    block-5 pointers are rebased from the complete native trace.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("RawFile append trace belongs to another source body")
    name_bytes = _validate_name(name)
    if not isinstance(existing_names, set) or name in existing_names:
        raise ValueError("RawFile append name already exists in the native XAsset inventory")
    if not isinstance(raw_content, bytes):
        raise ValueError("RawFile append content must be exact bytes")
    if not isinstance(compressed, bool):
        raise ValueError("RawFile append compression selection must be boolean")
    if not body.assets:
        raise ValueError("RawFile append requires a trace-proven final source asset")
    final_index = len(body.assets) - 1
    if (final_native_row.get("index", final_native_row.get("xasset_index")) != final_index or
            final_native_row.get("type_id") != body.assets[final_index].type_id or
            final_trace_asset.get("index", final_trace_asset.get("xasset_index")) != final_index or
            final_trace_asset.get("type_id") != body.assets[final_index].type_id or
            final_trace_asset.get("name") != final_native_row.get("name") or
            final_trace_asset.get("end_cursor") != len(body_data)):
        raise ValueError("source final XAsset lacks its exact trace-owned serialized EOF boundary")
    spans = final_trace_asset.get("read_spans")
    if (not isinstance(spans, list) or not spans or
            max((span.get("archive_offset", -1) + span.get("size", 0)
                 for span in spans), default=-1) != len(body_data)):
        raise ValueError("source final XAsset trace does not cover the physical body tail")
    # The selected owner is independently parsed to ensure this is a real
    # recognized native row; payload ownership need not be RawFile-specific.
    if final_native_row.get("name") is not None and not isinstance(final_native_row.get("name"), str):
        raise ValueError("source final native row has an invalid name")
    if len(stream_reservations) != 11 or any(type(size) is not int or size < 0 for size in stream_reservations):
        raise ValueError("RawFile append requires eleven validated stream reservations")

    (manifest, asset_bases, intervals, aliases, table, max_destinations,
     alias_count, relocated_targets, relocated_asset_bases, pointer_stats) = _table_contract(
        body_data, trace_path, manifest_path, XASSET_ROW_BYTES,
        expected_trace_sha256=expected_trace_sha256,
        expected_manifest_sha256=expected_manifest_sha256)
    table_end = table["end"]
    physical_table_end = body.first_payload_offset
    if table["archive"] + table["size"] != physical_table_end:
        raise ValueError("native XAsset pointer array does not end at the first payload")
    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, table_end, physical_table_end,
        XASSET_ROW_BYTES, asset_bases, relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_asset_bases)

    payload = zlib.compress(raw_content) if compressed else raw_content
    if len(payload) > 0x7FFFFFFF or len(raw_content) > 0x7FFFFFFF:
        raise ValueError("RawFile buffer exceeds signed native length limits")
    comp_len = len(payload) if compressed else 0
    buffer_token = INLINE if payload else 0
    row = struct.pack("<IIQ", RAWFILE_TYPE_ID, 0, INLINE)
    updated = bytearray(rebased)
    struct.pack_into("<I", updated, XASSET_COUNT_OFFSET, len(body.assets) + 1)
    updated[physical_table_end:physical_table_end] = row
    root_archive = len(updated)
    root = struct.pack("<QiiQ", PTR_FOLLOWS, comp_len, len(raw_content), buffer_token)
    updated.extend(root)
    updated.extend(name_bytes)
    updated.extend(payload)
    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if (len(reparsed.assets) != len(body.assets) + 1 or
            reparsed.assets[-1].type_id != RAWFILE_TYPE_ID or
            [row.type_id for row in reparsed.assets[:-1]] != [row.type_id for row in body.assets]):
        raise AssertionError("RawFile append changed source XAsset order or failed to add type 51")

    relocated_maxima = pointer_stats["relocated_stream_max_destinations"]
    relocated_terminal = pointer_stats["relocated_terminal_cursors"]
    stream1_high = relocated_maxima.get(1)
    stream5_high = relocated_maxima.get(5)
    if (not isinstance(stream1_high, int) or stream1_high < 0 or
            not isinstance(stream5_high, int) or stream5_high != relocated_terminal.get(5)):
        raise ValueError("relocated RawFile stream-1 capacity or stream-5 EOF is unproven")
    new_reservations = list(stream_reservations)
    # RawFile roots are read AtStart into reused stream-1 scratch at offset 0;
    # stream-1's maximum can come from an unrelated larger root and is a
    # capacity requirement, not this appended root's destination offset.
    new_reservations[1] = max(new_reservations[1], stream1_high, RAWFILE_ROOT_BYTES)
    new_reservations[5] = max(new_reservations[5], stream5_high + len(name_bytes) + len(payload))
    return result, dict(schema="replay120-rawfile-row-append-v1",
        status="trace-owned-rawfile-row-append-candidate", operation="append",
        name=name, asset_index=len(body.assets), source_body_sha256=body.source_sha256,
        output_body_sha256=_sha(result), source_asset_count=len(body.assets),
        output_asset_count=len(reparsed.assets), source_final_asset_index=final_index,
        source_final_asset_type_id=body.assets[final_index].type_id,
        source_final_asset_end_cursor=final_trace_asset["end_cursor"],
        root_archive_offset=root_archive, root_stream_offset=0,
        root_bytes=RAWFILE_ROOT_BYTES, name_bytes=len(name_bytes),
        payload_bytes=len(payload), raw_bytes=len(raw_content), compressed=compressed,
        xasset_table_insert_offset=physical_table_end, xasset_row_bytes=XASSET_ROW_BYTES,
        stream_reservation_sizes=new_reservations,
        source_stream_max_destinations={str(key): value for key, value in max_destinations.items()},
        relocated_stream_terminal_cursors={str(key): value for key, value in relocated_terminal.items()},
        relocated_stream_max_destinations={str(key): value for key, value in relocated_maxima.items()},
        source_alias_event_count=alias_count, pointer_relocation=alias_receipt,
        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
        pointer_contract=pointer_stats)


def remove_final_rawfile_tail(body_data: bytes, asset_index: int, asset_name: str,
                              native_row: dict, trace_asset: dict,
                              expected_body_sha256: str,
                              trace_path: str | Path, manifest_path: str | Path, *,
                              expected_trace_sha256: str, expected_manifest_sha256: str):
    """Remove a final RawFile only when its complete root/name/buffer owns EOF."""
    from workstation_luafile_operations import _rebase_aliases

    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("RawFile removal trace belongs to another source body")
    if (type(asset_index) is not int or isinstance(asset_index, bool) or
            asset_index != len(body.assets) - 1 or body.assets[asset_index].type_id != RAWFILE_TYPE_ID):
        raise ValueError("RawFile row removal requires the exact final type-51 XAsset")
    native = dict(native_row, index=asset_index, name=asset_name)
    layout, _raw = _raw_bytes(body_data, trace_asset, native, expected_body_sha256)
    if layout.root_archive_offset + RAWFILE_ROOT_BYTES > len(body_data):
        raise ValueError("RawFile root is outside the serialized source body")
    name_token, compressed_len, raw_len, buffer_token = struct.unpack_from(
        "<QiiQ", body_data, layout.root_archive_offset)
    if name_token not in (PTR_FOLLOWS, INLINE):
        raise ValueError("tail RawFile removal requires its trace-owned inline XString")
    name_bytes = asset_name.encode("utf-8") + b"\0"
    name_at = layout.root_archive_offset + RAWFILE_ROOT_BYTES
    name_spans = [span for span in trace_asset.get("read_spans", [])
        if span.get("origin") == "string_data" and span.get("archive_offset") == name_at and
        span.get("size") == len(name_bytes)]
    if len(name_spans) != 1:
        raise ValueError("tail RawFile name lacks one exact physical owner")
    name_span = name_spans[0]
    name_dest = name_span.get("destination_stream_location")
    if (not isinstance(name_dest, dict) or name_dest.get("stream") != 5 or
            body_data[name_at:name_at + len(name_bytes)] != name_bytes):
        raise ValueError("tail RawFile name does not match its stream-5 trace allocation")
    root_spans = [span for span in trace_asset.get("read_spans", [])
        if span.get("origin") == "load_stream_call" and span.get("reader_start_arg") == 0 and
        span.get("archive_offset") == layout.root_archive_offset and
        span.get("size") == RAWFILE_ROOT_BYTES]
    if len(root_spans) != 1:
        raise ValueError("tail RawFile removal requires one exact 24-byte root read")
    root_dest = root_spans[0].get("destination_stream_location")
    if not isinstance(root_dest, dict) or root_dest.get("stream") != 1:
        raise ValueError("tail RawFile root is not a stream-1 allocation")
    payload_spans = [span for span in trace_asset.get("read_spans", [])
        if span.get("origin") == "load_stream_call" and span.get("reader_start_arg") == 0 and
        span.get("archive_offset") == layout.payload_archive_offset and
        span.get("size") == layout.payload_bytes and layout.payload_bytes > 0]
    if layout.payload_bytes and len(payload_spans) != 1:
        raise ValueError("tail RawFile buffer lacks one exact physical owner")
    expected_end = layout.payload_archive_offset + layout.payload_bytes if layout.payload_bytes else name_at + len(name_bytes)
    if (trace_asset.get("end_cursor") != expected_end or expected_end != len(body_data) or
            name_at + len(name_bytes) != (layout.payload_archive_offset if layout.payload_bytes else expected_end)):
        raise ValueError("RawFile root/name/buffer do not own the exact serialized body tail")
    if layout.payload_bytes and payload_spans[0].get("destination_stream_location", {}).get("stream") != 5:
        raise ValueError("tail RawFile buffer is not a stream-5 allocation")
    if layout.payload_bytes and buffer_token != INLINE:
        raise ValueError("tail RawFile buffer is not the supported inline pointer form")
    if not layout.payload_bytes and buffer_token not in (0, INLINE):
        raise ValueError("empty tail RawFile has an unsupported buffer pointer mode")
    table_row_at = body.asset_table_offset + asset_index * XASSET_ROW_BYTES
    root_range = (1, root_dest["offset"], root_dest["offset"] + RAWFILE_ROOT_BYTES)
    name_range = (5, name_dest["offset"], name_dest["offset"] + len(name_bytes))
    removed_ranges = [root_range, name_range]
    logical_delete = [name_range]
    if layout.payload_bytes:
        payload_dest = payload_spans[0].get("destination_stream_location")
        if not isinstance(payload_dest, dict) or payload_dest.get("stream") != 5:
            raise ValueError("tail RawFile payload lacks typed stream-5 ownership")
        child_range = (5, payload_dest["offset"], payload_dest["offset"] + layout.payload_bytes)
        removed_ranges.append(child_range)
        logical_delete.append(child_range)
    (manifest, asset_bases, intervals, aliases, table, _max_destinations,
     alias_count, relocated_targets, relocated_asset_bases, pointer_stats) = _table_contract(
        body_data, trace_path, manifest_path, -XASSET_ROW_BYTES,
        removed_ranges=removed_ranges, logical_delete_ranges=logical_delete,
        removed_owner=asset_index, expected_trace_sha256=expected_trace_sha256,
        expected_manifest_sha256=expected_manifest_sha256)

    physical_components = [root_spans[0], name_span] + payload_spans
    expected_owner_ranges = sorted((span.get("archive_offset"), span.get("archive_offset", -1) + span.get("size", 0))
        for span in physical_components)
    owner_ranges = sorted((span.get("archive"), span.get("archive", -1) + span.get("size", 0))
        for span in intervals if span.get("owner") == asset_index and
        span.get("archive", -1) < len(body_data) and span.get("archive", -1) + span.get("size", 0) > layout.root_archive_offset)
    if owner_ranges != expected_owner_ranges:
        raise ValueError("RawFile tail has missing, overlapping or extra trace-owned physical bytes")
    if table.get("size") != len(body.assets) * XASSET_ROW_BYTES:
        raise ValueError("native trace table count differs from RawFile removal body")
    table_end, physical_table_end = table["end"], body.first_payload_offset
    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, table_end, physical_table_end,
        XASSET_ROW_BYTES, asset_bases, inverse=True,
        removed_stream_ranges=tuple(removed_ranges),
        logical_delete_ranges=tuple(logical_delete),
        relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_asset_bases)
    updated = bytearray(rebased)
    del updated[layout.root_archive_offset:]
    del updated[table_row_at:table_row_at + XASSET_ROW_BYTES]
    struct.pack_into("<I", updated, XASSET_COUNT_OFFSET, asset_index)
    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if (len(reparsed.assets) != asset_index or
            [row.type_id for row in reparsed.assets] != [row.type_id for row in body.assets[:-1]]):
        raise AssertionError("RawFile tail removal changed retained XAsset order")
    return result, dict(schema="replay120-rawfile-row-remove-v1",
        status="trace-owned-exclusive-rawfile-tail-remove-candidate", operation="remove",
        name=asset_name, asset_index=asset_index, source_body_sha256=body.source_sha256,
        output_body_sha256=_sha(result), source_asset_count=len(body.assets),
        output_asset_count=len(reparsed.assets), removed_root_archive_offset=layout.root_archive_offset,
        removed_root_bytes=RAWFILE_ROOT_BYTES, removed_name_bytes=len(name_bytes),
        removed_payload_bytes=layout.payload_bytes, removed_table_row_archive_offset=table_row_at,
        source_alias_event_count=alias_count, pointer_contract=pointer_stats,
        alias_relocation=alias_receipt,
        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        stream_trace_sha256=_sha(Path(trace_path).read_bytes()))
