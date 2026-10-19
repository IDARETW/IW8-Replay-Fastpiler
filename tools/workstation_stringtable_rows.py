"""Trace-bound Replay 1.20 StringTable XAsset row insertion/removal."""
from __future__ import annotations

import hashlib
import csv
import io
from pathlib import Path
import struct
from types import SimpleNamespace

try:
    from workstation_fastfiles import ZoneBody
    from workstation_luafile_operations import _rebase_aliases, _trace_contract
    from workstation_stringtable import (STRINGTABLE_ROOT_BYTES, STRINGTABLE_TYPE_ID,
        _serialize_record, inspect_stringtable)
    from workstation_asset_codecs import encode_stringtable_sections
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_luafile_operations import _rebase_aliases, _trace_contract
    from tools.workstation_stringtable import (STRINGTABLE_ROOT_BYTES, STRINGTABLE_TYPE_ID,
        _serialize_record, inspect_stringtable)
    from tools.workstation_asset_codecs import encode_stringtable_sections

INLINE = 0xFFFFFFFFFFFFFFFE
PTR_FOLLOWS = 0xFFFFFFFFFFFFFFFF
XASSET_ROW_BYTES = 16
XASSET_COUNT_OFFSET = 16


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _trace_contract_from_receipt(body_data: bytes, trace_path: str | Path,
                                 manifest_path: str | Path, *,
                                 expected_trace_sha256: str,
                                 expected_manifest_sha256: str, **kwargs):
    """Use RawFile's validated adapter for ACTS manifests without trace SHA."""
    from workstation_rawfile_rows import _table_contract
    row_delta = kwargs.pop("table_row_delta", 0)
    removed_ranges = kwargs.pop("removed_stream_ranges", ())
    logical_delete_ranges = kwargs.pop("logical_delete_ranges", ())
    removed_owner = kwargs.pop("removed_owner", None)
    if kwargs:
        raise TypeError(f"unsupported StringTable ownership contract fields: {sorted(kwargs)}")
    return _table_contract(body_data, trace_path, manifest_path, row_delta,
        removed_ranges=removed_ranges, logical_delete_ranges=logical_delete_ranges,
        removed_owner=removed_owner, expected_trace_sha256=expected_trace_sha256,
        expected_manifest_sha256=expected_manifest_sha256)


def _owned_final_asset(body_data: bytes, index: int, trace_asset: dict,
                       expected_body_sha256: str, trace_path: str | Path,
                       manifest_path: str | Path, name: str,
                       rows: list[list[str]]):
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("StringTable row mutation trace belongs to another body")
    if (type(index) is not int or not 0 <= index < len(body.assets) or
            body.assets[index].type_id != STRINGTABLE_TYPE_ID or
            trace_asset.get("xasset_index") != index or
            trace_asset.get("type_id") != STRINGTABLE_TYPE_ID or
            trace_asset.get("name") != name):
        raise ValueError("StringTable removal no longer identifies its exact native row")
    if index != len(body.assets) - 1:
        raise ValueError("StringTable removal requires the final XAsset row")
    layout, actual_rows = inspect_stringtable(body_data, index, name, trace_asset,
        rows, expected_body_sha256)
    if actual_rows != rows or layout.name_pointer_mode != "inline":
        raise ValueError("StringTable removal requires its exact inline-name semantic layout")
    if layout.archive_end != len(body_data) or trace_asset.get("end_cursor") != len(body_data):
        raise ValueError("final StringTable does not own the exact serialized EOF")
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("StringTable removal lacks native physical read spans")
    root_spans = [span for span in spans if span.get("origin") == "load_stream_call" and
                  span.get("reader_start_arg") == 0 and
                  span.get("archive_offset") == layout.root_archive_offset and
                  span.get("size") == STRINGTABLE_ROOT_BYTES and
                  span.get("destination_stream_location", {}).get("stream") == 1]
    if len(root_spans) != 1:
        raise ValueError("StringTable root does not have one exact stream-1 physical span")
    record_spans = sorted((span for span in spans
        if span.get("origin") in ("load_stream_call", "string_data") and
        type(span.get("archive_offset")) is int and type(span.get("size")) is int and
        span["size"] > 0 and layout.root_archive_offset <= span["archive_offset"] < layout.archive_end),
        key=lambda span: span["archive_offset"])
    cursor = layout.root_archive_offset
    for span in record_spans:
        if span["archive_offset"] != cursor:
            raise ValueError("StringTable physical record contains gaps or unowned bytes")
        cursor += span["size"]
    if cursor != layout.archive_end:
        raise ValueError("StringTable physical spans do not cover its exact serialized record")
    child_locs = [span.get("destination_stream_location") for span in record_spans
                  if span is not root_spans[0]]
    if not child_locs or any(not isinstance(loc, dict) or loc.get("stream") != 5 or
                             type(loc.get("offset")) is not int for loc in child_locs):
        raise ValueError("StringTable name and sections are not fully owned in stream 5")
    root_loc = root_spans[0].get("destination_stream_location")
    child_start = layout.name_stream_offset
    child_end = max(loc["offset"] + span["size"] for span, loc in
                    zip((span for span in record_spans if span is not root_spans[0]), child_locs))
    if (not isinstance(root_loc, dict) or root_loc.get("stream") != 1 or
            type(root_loc.get("offset")) is not int or child_end <= child_start):
        raise ValueError("StringTable root/child destination ownership is malformed")
    return body, layout, root_spans[0], (1, root_loc["offset"], root_loc["offset"] + STRINGTABLE_ROOT_BYTES), \
        (5, child_start, child_end), record_spans


def append_stringtable_tail(body_data: bytes, name: str, rows: list[list[str]],
                            existing_names: set[str], expected_body_sha256: str,
                            trace_path: str | Path, manifest_path: str | Path,
                            final_trace_asset: dict, *,
                            expected_trace_sha256: str,
                            expected_manifest_sha256: str) -> tuple[bytes, dict]:
    """Append one inline type-54 table after the exact, traced serialized EOF."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("StringTable append trace belongs to another source body")
    if (not isinstance(name, str) or not name.endswith(".csv") or "\x00" in name or
            name.startswith("/") or name.endswith("/") or "\\" in name or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("StringTable append name must be a confined .csv asset path")
    if name in existing_names:
        raise ValueError("StringTable append name already exists in the native XAsset inventory")
    sections = encode_stringtable_sections(name, rows)
    if not body.assets:
        raise ValueError("cannot append a StringTable to an empty XAsset table")
    final_index = len(body.assets) - 1
    final_spans = final_trace_asset.get("read_spans")
    if (final_trace_asset.get("xasset_index") != final_index or
            final_trace_asset.get("type_id") != body.assets[-1].type_id or
            final_trace_asset.get("end_cursor") != len(body_data) or
            not isinstance(final_spans, list) or not final_spans or
            max(span.get("archive_offset", -1) + span.get("size", 0)
                for span in final_spans) != len(body_data)):
        raise ValueError("original final XAsset lacks an exact trace-owned serialized EOF boundary")

    manifest, bases, intervals, aliases, table_alloc, max_destinations, alias_count, \
        relocated_targets, relocated_bases, string_stats = _trace_contract_from_receipt(
            body_data, trace_path, manifest_path,
            expected_trace_sha256=expected_trace_sha256,
            expected_manifest_sha256=expected_manifest_sha256,
            table_row_delta=XASSET_ROW_BYTES)
    if (table_alloc.get("size") != len(body.assets) * XASSET_ROW_BYTES or
            table_alloc.get("archive") != body.asset_table_offset or
            table_alloc.get("archive", -1) + table_alloc.get("size", 0) != body.first_payload_offset):
        raise ValueError("native XAsset allocation differs from the exact source table")
    updated, alias_proof = _rebase_aliases(body_data, intervals, aliases,
        table_alloc["end"], body.first_payload_offset, XASSET_ROW_BYTES, bases,
        relocated_targets=relocated_targets, relocated_asset_bases=relocated_bases)
    updated = bytearray(updated)
    updated[body.first_payload_offset:body.first_payload_offset] = struct.pack(
        "<IIQ", STRINGTABLE_TYPE_ID, 0, INLINE)
    struct.pack_into("<I", updated, XASSET_COUNT_OFFSET, len(body.assets) + 1)
    root_at = len(updated)
    header = bytearray(STRINGTABLE_ROOT_BYTES)
    struct.pack_into("<QIII", header, 0, PTR_FOLLOWS, sections["columns"],
                     sections["rows"], len(sections["dictionary"]))
    for offset in (24, 32, 40):
        struct.pack_into("<Q", header, offset, INLINE)
    source_with_root = bytes(updated) + bytes(header)
    relocated_stream5 = string_stats["relocated_stream_max_destinations"].get(5)
    relocated_terminal5 = string_stats["relocated_terminal_cursors"].get(5)
    if (not isinstance(relocated_stream5, int) or
            relocated_stream5 != relocated_terminal5):
        raise ValueError("relocated native stream-5 cursor is not a proven EOF high-water mark")
    layout = SimpleNamespace(asset_name=name, root_archive_offset=root_at,
                             name_stream_offset=relocated_stream5,
                             name_pointer_mode="inline")
    record, emitted = _serialize_record(source_with_root, layout, rows)
    result = bytes(updated) + record
    reparsed = ZoneBody.parse(result)
    if (len(reparsed.assets) != len(body.assets) + 1 or
            reparsed.assets[:-1] != body.assets or
            reparsed.assets[-1].type_id != STRINGTABLE_TYPE_ID or
            reparsed.assets[-1].pointer_token != INLINE):
        raise AssertionError("StringTable append changed retained XAssets or failed to add its inline root")
    csv_stream = io.StringIO(newline="")
    csv.writer(csv_stream, lineterminator="\n").writerows(rows)
    return result, dict(schema="replay120-stringtable-row-append-v1",
        status="trace-owned-stringtable-append-candidate", operation="append", name=name,
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(result),
        source_asset_count=len(body.assets), output_asset_count=len(reparsed.assets),
        source_final_asset_index=final_index, source_final_asset_end_cursor=len(body_data),
        xasset_table_insert_offset=body.first_payload_offset, xasset_row_bytes=XASSET_ROW_BYTES,
        appended_root_archive_offset=root_at, appended_root_stream_offset=0,
        appended_root_bytes=STRINGTABLE_ROOT_BYTES, appended_record_bytes=len(record),
        appended_name_bytes=len(name.encode("utf-8")) + 1,
        appended_csv_sha256=_sha(csv_stream.getvalue().encode("utf-8")),
        appended_sections=emitted["stream5_sections"], appended_stream5_end=emitted["stream5_end"],
        source_native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        source_stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
        source_stream_max_destinations={str(key): value for key, value in max_destinations.items()},
        relocated_stream5_eof=relocated_stream5,
        relocated_stream5_highwater=relocated_stream5,
        source_alias_event_count=alias_count, alias_relocation=alias_proof)


def remove_existing_stringtable_row(body_data: bytes, asset_index: int,
                                    asset_name: str, trace_asset: dict,
                                    rows: list[list[str]], expected_body_sha256: str,
                                    trace_path: str | Path,
                                    manifest_path: str | Path, *,
                                    expected_trace_sha256: str,
                                    expected_manifest_sha256: str) -> tuple[bytes, dict]:
    """Remove one exact final StringTable with unique physical and pointer ownership."""
    body, layout, _root_span, root_range, child_range, record_spans = _owned_final_asset(
        body_data, asset_index, trace_asset, expected_body_sha256,
        trace_path, manifest_path, asset_name, rows)
    contract = _trace_contract_from_receipt(body_data, trace_path, manifest_path,
        expected_trace_sha256=expected_trace_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        removed_stream_ranges=(root_range, child_range),
        logical_delete_ranges=(child_range,), removed_owner=asset_index)
    (_manifest, bases, intervals, aliases, table_alloc, max_destinations,
     alias_count, relocated_targets, relocated_bases, _string_stats) = contract
    if (table_alloc.get("size") != len(body.assets) * XASSET_ROW_BYTES or
            table_alloc.get("archive") != body.asset_table_offset or
            table_alloc.get("archive", -1) + table_alloc.get("size", 0) != body.first_payload_offset):
        raise ValueError("native XAsset allocation differs from the exact source table")
    for span in intervals:
        if (span.get("owner") != asset_index and
                span.get("archive", -1) < layout.archive_end and
                span.get("archive", -1) + span.get("size", 0) > layout.root_archive_offset):
            raise ValueError("StringTable physical root/sections are shared with another XAsset")
    output, alias_proof = _rebase_aliases(body_data, intervals, aliases,
        table_alloc["end"], body.first_payload_offset, XASSET_ROW_BYTES, bases,
        inverse=True, removed_stream_ranges=(root_range, child_range),
        logical_delete_ranges=(child_range,), relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_bases)
    output = bytearray(output)
    row_at = body.asset_table_offset + asset_index * XASSET_ROW_BYTES
    del output[row_at:row_at + XASSET_ROW_BYTES]
    # The table splice precedes the serialized payload, so physical coordinates
    # after first_payload_offset move back by one 16-byte XAsset row.
    root_at = layout.root_archive_offset - XASSET_ROW_BYTES
    record_end = layout.archive_end - XASSET_ROW_BYTES
    if root_at < body.first_payload_offset - XASSET_ROW_BYTES or record_end > len(output):
        raise ValueError("StringTable record shifted outside the shortened body")
    del output[root_at:record_end]
    struct.pack_into("<I", output, XASSET_COUNT_OFFSET, len(body.assets) - 1)
    result = bytes(output)
    reparsed = ZoneBody.parse(result)
    if reparsed.assets != body.assets[:-1]:
        raise AssertionError("StringTable removal changed retained XAsset identities/order")
    return result, dict(schema="replay120-stringtable-row-remove-v1",
        status="native-trace-exclusive-final-stringtable-row-remove-candidate",
        operation="remove_existing", name=asset_name, removed_index=asset_index,
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(result),
        source_asset_count=len(body.assets), output_asset_count=len(reparsed.assets),
        removed_record_sha256=_sha(body_data[layout.root_archive_offset:layout.archive_end]),
        root_stream_range=root_range, child_stream_range=child_range,
        owned_physical_spans=[dict(archive_offset=span["archive_offset"], bytes=span["size"])
                              for span in record_spans],
        source_native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        source_stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
        packed_alias_event_count=alias_count, alias_relocation=alias_proof)

