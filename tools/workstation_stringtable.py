"""Typed Replay StringTable inspection, serialization, and block-5 relocation.

This module is intentionally isolated from the shared fastfile packager.  It
supports the observed Replay 1.20 StringTable layout (type 54, 48-byte root)
only when a complete native stream trace proves ownership and stream schedule.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from bisect import bisect_right
import json
from pathlib import Path
import struct
from typing import Any

from workstation_asset_codecs import (
    decode_stringtable_sections,
    encode_stringtable_sections,
)


STRINGTABLE_TYPE_ID = 54
STRINGTABLE_ROOT_BYTES = 48
INLINE_POINTERS = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE}


@dataclass(frozen=True)
class StringTableLayout:
    asset_index: int
    asset_name: str
    root_archive_offset: int
    archive_end: int
    root_stream_offset: int
    name_archive_offset: int
    name_stream_offset: int
    name_bytes: int
    columns: int
    rows: int
    dictionary_count: int
    cells_archive_offset: int
    cells_stream_offset: int
    cells_bytes: int
    hashes_archive_offset: int
    hashes_stream_offset: int
    hashes_bytes: int
    pointers_archive_offset: int
    pointers_stream_offset: int
    pointers_bytes: int
    pointer_tokens: tuple[int, ...]
    inline_dictionary_strings: tuple[tuple[int, int, int, int], ...]
    dictionary_values: tuple[str, ...]
    source_body_sha256: str
    source_record_sha256: str
    name_pointer_mode: str = "inline"
    name_pointer_token: int = 0
    name_target_archive_offset: int | None = None
    name_target_event_sequence: int | None = None
    packed_dictionary_references: tuple[dict[str, Any], ...] = ()


def _read_spans(trace_asset: dict) -> list[dict]:
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list) or not spans:
        raise ValueError("StringTable trace row has no native physical read spans")
    return spans


def _one(items: list[dict], label: str) -> dict:
    if len(items) != 1:
        raise ValueError(f"StringTable trace needs exactly one {label}; found {len(items)}")
    return items[0]


def _unique_prior_string_data_allocation(
        spans: list[dict], *, target_offset: int, byte_count: int,
        resolution_sequence: int, body_data: bytes, label: str) -> tuple[dict, int]:
    """Find the sole prior stream-5 allocation covering a pointer target.

    Logical stream offsets may be reused after native discard/rewind.  A byte
    match against any historical allocation does not prove which bytes the
    callback saw, so overlapping prior allocations fail closed unless the
    trace contains a single possible allocation for the complete target.
    """
    candidates: list[tuple[dict, int]] = []
    for span in spans:
        destination = span.get("destination_stream_location")
        start = destination.get("offset") if isinstance(destination, dict) else None
        size = span.get("size")
        archive_at = span.get("archive_offset")
        sequence = span.get("event_sequence")
        if (span.get("origin") != "string_data" or not isinstance(destination, dict) or
                destination.get("stream") != 5 or type(start) is not int or
                type(size) is not int or size <= 0 or type(sequence) is not int or
                sequence >= resolution_sequence or type(archive_at) is not int or
                archive_at < 0 or archive_at + size > len(body_data) or
                not start <= target_offset < start + size):
            continue
        candidates.append((span, target_offset - start))
    if len(candidates) != 1:
        raise ValueError(f"StringTable trace needs one unambiguous {label}; found {len(candidates)}")
    span, displacement = candidates[0]
    if displacement + byte_count > span["size"]:
        raise ValueError(f"StringTable trace {label} extends beyond its live allocation")
    return span, displacement


def validate_complete_stream5_allocations(trace_index: dict) -> dict[str, Any]:
    """Validate the complete native read-span projection for stream 5.

    The caller must supply an unfiltered ``build_read_span_index`` result.
    Every physical stream-5 read is considered, regardless of its origin
    label; otherwise an unclassified/non-string read could hide a cursor reuse
    that invalidates a historical StringTable target.
    """
    if not isinstance(trace_index, dict) or trace_index.get("status") != "native-read-spans-indexed":
        raise ValueError("StringTable requires a validated full native read-span index")
    assets = trace_index.get("assets")
    xasset_count = trace_index.get("xasset_count")
    if (not isinstance(assets, list) or type(xasset_count) is not int or
            len(assets) != xasset_count or
            {row.get("index") for row in assets if isinstance(row, dict)} != set(range(xasset_count))):
        raise ValueError("StringTable requires the unfiltered complete XAsset span index")
    spans: list[dict] = []
    owners = [(None, trace_index.get("preamble_spans", []))]
    owners.extend((asset.get("index"), asset.get("read_spans", [])) for asset in assets)
    for owner, owner_spans in owners:
        if not isinstance(owner_spans, list):
            raise ValueError("StringTable full native read-span index has malformed span rows")
        for span in owner_spans:
            if not isinstance(span, dict):
                raise ValueError("StringTable full native read-span index has a malformed physical span")
            destination = span.get("destination_stream_location")
            if not isinstance(destination, dict) or destination.get("stream") != 5:
                continue
            start, size = destination.get("offset"), span.get("size")
            archive_at, sequence = span.get("archive_offset"), span.get("event_sequence")
            if (type(start) is not int or start < 0 or type(size) is not int or size <= 0 or
                    type(archive_at) is not int or archive_at < 0 or
                    type(sequence) is not int or sequence < 0):
                raise ValueError("StringTable stream-5 physical allocation has invalid coordinates")
            spans.append(dict(owner=owner, origin=span.get("origin"), start=start,
                              end=start + size, size=size, archive_offset=archive_at,
                              sequence=sequence))
    spans.sort(key=lambda item: (item["start"], item["end"], item["sequence"]))
    previous = None
    for span in spans:
        if previous is not None and span["start"] < previous["end"]:
            raise ValueError(
                f"StringTable native stream-5 allocations overlap: sequence "
                f"{previous['sequence']} and {span['sequence']}")
        previous = span
    count_by_stream = trace_index.get("physical_load_count_by_stream")
    bytes_by_stream = trace_index.get("physical_load_bytes_by_stream")
    if (not isinstance(count_by_stream, dict) or not isinstance(bytes_by_stream, dict) or
            count_by_stream.get(5, 0) != len(spans) or
            bytes_by_stream.get(5, 0) != sum(span["size"] for span in spans)):
        raise ValueError("StringTable stream-5 span set differs from complete native physical-read totals")
    digest_rows = [{key: span[key] for key in
                    ("owner", "origin", "start", "end", "archive_offset", "sequence")}
                   for span in sorted(spans, key=lambda item: item["sequence"])]
    digest = hashlib.sha256(json.dumps(digest_rows, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")).hexdigest()
    return dict(schema="replay120-stringtable-stream5-allocation-context-v1",
                status="complete-disjoint-stream5-allocations",
                xasset_count=xasset_count, physical_span_count=len(spans),
                physical_bytes=sum(span["size"] for span in spans),
                max_stream5_offset=max((span["end"] for span in spans), default=0),
                spans_sha256=digest)


def _resolve_packed_dictionary_string(
        *, dictionary_index: int, token: int, expected_value: str,
        pointer_stream_offset: int, owner_index: int, begin_sequence: int,
        end_sequence: int, resolution_events: list[dict],
        global_string_data_spans: list[dict], body_data: bytes) -> dict[str, Any]:
    """Bind one packed dictionary entry to its exact native pointer slot and bytes."""
    if token >> 32 != 5 or token & 0xFFFFFFFF == 0:
        raise ValueError(f"packed StringTable dictionary pointer {dictionary_index} has unsupported encoding")
    target_offset = (token & 0xFFFFFFFF) - 1
    field_location = {"stream": 5, "offset": pointer_stream_offset + dictionary_index * 8}
    events = [event for event in resolution_events
              if event.get("kind") == "packed_resolve" and
              event.get("xasset_index") == owner_index and
              type(event.get("type_id")) is int and event.get("type_id") == STRINGTABLE_TYPE_ID and
              event.get("raw_token") == token and
              event.get("field_stream_location") == field_location and
              event.get("resolved_target_stream_location") == {"stream": 5, "offset": target_offset} and
              type(event.get("sequence")) is int and
              begin_sequence < event["sequence"] < end_sequence]
    resolve_event = _one(events, f"dictionary pointer {dictionary_index} native packed_resolve callback")

    wanted = expected_value.encode("utf-8") + b"\0"
    label = f"dictionary pointer {dictionary_index} exact target string allocation"
    span, displacement = _unique_prior_string_data_allocation(
        global_string_data_spans, target_offset=target_offset,
        byte_count=len(wanted), resolution_sequence=resolve_event["sequence"],
        body_data=body_data, label=label)
    archive_target = span["archive_offset"] + displacement
    if body_data[archive_target:archive_target + len(wanted)] != wanted:
        raise ValueError(f"StringTable trace {label} has mismatching target bytes")
    return dict(dictionary_index=dictionary_index, value=expected_value, raw_token=token,
                pointer_field_stream_location=field_location,
                target_stream_location={"stream": 5, "offset": target_offset},
                target_archive_offset=span["archive_offset"] + displacement,
                target_allocation_archive_offset=span["archive_offset"],
                target_allocation_size=span["size"],
                target_allocation_event_sequence=span.get("event_sequence"),
                resolution_event_sequence=resolve_event["sequence"])


def _trace_string(span: dict, body: bytes) -> str:
    at, size = span.get("archive_offset"), span.get("size")
    if not isinstance(at, int) or not isinstance(size, int) or size < 1 or at < 0 or at + size > len(body):
        raise ValueError("StringTable string span is outside the decoded body")
    raw = body[at:at + size]
    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
        raise ValueError("StringTable string span is not one NUL-terminated string")
    try:
        return raw[:-1].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("StringTable string is not UTF-8") from error


def _resolve_stringtable_name(name_token: int, asset_name: str, root_at: int,
                              root_event_sequence: int, body_data: bytes,
                              trace_asset: dict,
                              global_string_data_spans: list[dict] | None) -> tuple[dict, str, int | None]:
    """Resolve an inline name or prior shared stream-5 name allocation."""
    expected = asset_name.encode("utf-8") + b"\0"
    spans = trace_asset.get("read_spans", [])
    if name_token in INLINE_POINTERS:
        candidates = [span for span in spans
                      if span.get("origin") == "string_data" and
                      span.get("archive_offset") == root_at + STRINGTABLE_ROOT_BYTES and
                      span.get("size") == len(expected)]
        name_span = _one(candidates, "inline root name")
        actual = _trace_string(name_span, body_data)
        at = name_span["archive_offset"]
        if actual != asset_name or body_data[at:at + len(expected)] != expected:
            raise ValueError("inline StringTable root name differs from XAsset name")
        return name_span, "inline", name_span.get("event_sequence")

    if name_token >> 32 != 5:
        raise ValueError("StringTable name pointer is neither inline nor the proven stream-5 alias form")
    encoded_offset = name_token & 0xFFFFFFFF
    if encoded_offset == 0:
        raise ValueError("packed StringTable name pointer has no valid offset+1 payload")
    target_offset = encoded_offset - 1
    if not isinstance(global_string_data_spans, list):
        raise ValueError("packed StringTable name requires the complete native string-data span index")
    begin_sequence = trace_asset.get("begin_sequence")
    end_sequence = trace_asset.get("end_sequence")
    root_location = trace_asset.get("root_stream_location")
    if (not isinstance(begin_sequence, int) or not isinstance(end_sequence, int) or
            not isinstance(root_location, dict) or root_location.get("stream") != 1):
        raise ValueError("packed StringTable name lacks its bounded native root owner interval")
    resolutions = trace_asset.get("root_name_resolution_events")
    if not isinstance(resolutions, list):
        raise ValueError("packed StringTable name requires the exact native root-resolution callbacks")
    matching_resolutions = [event for event in resolutions
                            if event.get("kind") == "packed_resolve" and
                            event.get("xasset_index") == trace_asset.get("index") and
                            type(event.get("type_id")) is int and event.get("type_id") == STRINGTABLE_TYPE_ID and
                            event.get("raw_token") == name_token and
                            event.get("field_stream_location") == root_location and
                            event.get("resolved_target_stream_location") ==
                            {"stream": 5, "offset": target_offset} and
                            isinstance(event.get("sequence"), int) and
                            begin_sequence < event["sequence"] < end_sequence]
    _one(matching_resolutions, "matching root-name packed_resolve callback")
    name_label = "earlier shared stream-5 name target"
    name_span, displacement = _unique_prior_string_data_allocation(
        global_string_data_spans, target_offset=target_offset,
        byte_count=len(expected), resolution_sequence=matching_resolutions[0]["sequence"],
        body_data=body_data, label=name_label)
    if (displacement != 0 or name_span.get("size") != len(expected) or
            name_span.get("event_sequence", matching_resolutions[0]["sequence"]) >= begin_sequence):
        raise ValueError(f"StringTable trace {name_label} is not the proven prior exact name span")
    actual = _trace_string(name_span, body_data)
    at = name_span["archive_offset"]
    if actual != asset_name or body_data[at:at + len(expected)] != expected:
        raise ValueError("packed StringTable name target bytes differ from XAsset journal identity")
    if name_span.get("event_sequence", root_event_sequence) >= root_event_sequence:
        raise ValueError("packed StringTable name target was not loaded before the root")
    return name_span, "packed-shared-stream5", name_span["event_sequence"]


def inspect_stringtable(body_data: bytes, asset_index: int, asset_name: str,
                        trace_asset: dict, original_rows: list[list[str]],
                        expected_body_sha256: str | None = None,
                        global_string_data_spans: list[dict] | None = None,
                        require_packed_dictionary_proof: bool = False) -> tuple[StringTableLayout, list[list[str]]]:
    """Validate the complete observed root and its four child sections.

    Dictionary strings reached through global block-5 references are checked
    against the original ACTS semantic export by cell/hash bytes. Inline values
    are additionally checked byte-for-byte against that export.
    """
    from workstation_fastfiles import ZoneBody

    body = ZoneBody.parse(body_data)
    digest = body.source_sha256
    if expected_body_sha256 is not None and digest != expected_body_sha256:
        raise ValueError("StringTable trace belongs to another decoded source body")
    if not isinstance(asset_index, int) or not 0 <= asset_index < len(body.assets):
        raise ValueError("StringTable XAsset index is outside the asset table")
    if body.assets[asset_index].type_id != STRINGTABLE_TYPE_ID:
        raise ValueError("selected XAsset is not a Replay StringTable")
    if (trace_asset.get("xasset_index") != asset_index or
            trace_asset.get("type_id") != STRINGTABLE_TYPE_ID or
            trace_asset.get("name") != asset_name):
        raise ValueError("native trace row does not match this StringTable identity")

    spans = _read_spans(trace_asset)
    roots = [span for span in spans if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0 and span.get("size") == STRINGTABLE_ROOT_BYTES]
    root_span = _one(roots, "48-byte AtStart root read")
    root_at = root_span.get("archive_offset")
    root_dest = root_span.get("destination_stream_location")
    if (not isinstance(root_at, int) or root_at < 0 or root_at + 48 > len(body_data) or
            not isinstance(root_dest, dict) or root_dest.get("stream") != 1):
        raise ValueError("StringTable root span is not a bounded stream-1 root")
    name_token, columns, rows, dictionary_count = struct.unpack_from("<QIII", body_data, root_at)
    root_child_tokens = struct.unpack_from("<QQQ", body_data, root_at + 24)
    # Replay roots observed for this consumer keep the three section pointers
    # inline (-2). The name pointer may also be a tag-5 alias to an earlier
    # shared stream-5 string; resolve that only through the complete native
    # string-data index below.
    if any(token not in INLINE_POINTERS for token in root_child_tokens):
        raise ValueError("StringTable root section pointers are not the observed inline form")
    empty_table = columns == 0 and rows == 0 and dictionary_count == 0
    if ((not empty_table and (not columns or not rows or not dictionary_count)) or
            rows > 1_000_000 or columns > 65_535 or dictionary_count > 65_536):
        raise ValueError("StringTable dimensions or dictionary count are outside supported bounds")

    root_sequence = root_span.get("event_sequence")
    if not isinstance(root_sequence, int):
        raise ValueError("StringTable root lacks its native event sequence")
    name_span, name_pointer_mode, name_target_event_sequence = _resolve_stringtable_name(
        name_token, asset_name, root_at, root_sequence, body_data, trace_asset,
        global_string_data_spans)
    expected_name = asset_name.encode("utf-8") + b"\0"
    name_at = name_span["archive_offset"]
    name_dest = name_span.get("destination_stream_location")
    if not isinstance(name_dest, dict) or name_dest.get("stream") != 5:
        raise ValueError("StringTable name is not allocated in stream 5")

    if empty_table:
        if original_rows != [] or name_pointer_mode != "inline":
            raise ValueError("only an exact empty-row table with an inline name can use the empty-table adapter")
        operations = trace_asset.get("stream_operations")
        if not isinstance(operations, list):
            raise ValueError("empty StringTable requires owner-local native align/zero-load trace operations")
        ordered_ops = sorted((event for event in operations
                              if isinstance(event, dict) and
                              root_sequence <= event.get("sequence", -1) <= trace_asset.get("end_sequence", -1)),
                             key=lambda event: event.get("sequence", -1))
        root_loads = [event for event in ordered_ops
                      if event.get("operation") == "load" and
                      event.get("block_before") == 1 and event.get("size") == STRINGTABLE_ROOT_BYTES and
                      event.get("physical_input_bytes") == STRINGTABLE_ROOT_BYTES and
                      event.get("input_before") == root_at]
        name_strings = [event for event in ordered_ops
                        if event.get("operation") == "string" and
                        event.get("block_after") == 5 and
                        event.get("offset_after") == name_dest.get("offset") and
                        event.get("size") == len(expected_name)]
        name_loads = [event for event in ordered_ops
                      if event.get("operation") == "load" and
                      event.get("block_before") == 5 and
                      event.get("offset_before") == name_dest.get("offset") and
                      event.get("size") == len(expected_name) and
                      event.get("physical_input_bytes") == len(expected_name) and
                      event.get("input_before") == name_at]
        if len(root_loads) != 1 or len(name_strings) != 1 or len(name_loads) != 1:
            raise ValueError("empty StringTable trace does not uniquely prove its root and inline name reads")
        if not (root_loads[0]["sequence"] < name_strings[0]["sequence"] < name_loads[0]["sequence"]):
            raise ValueError("empty StringTable name does not follow its root in the native schedule")
        name_end_sequence = name_loads[0]["sequence"]
        section_aligns = [event for event in ordered_ops
                          if event.get("operation") == "align" and
                          event.get("block_before") == event.get("block_after") == 5 and
                          event.get("sequence", -1) > name_end_sequence]
        if [event.get("value") for event in section_aligns] != [1, 3, 7]:
            raise ValueError("empty StringTable trace does not prove the ordered 2/4/8 section alignments")
        stream_cursor = name_dest["offset"] + len(expected_name)
        section_offsets = []
        for event in section_aligns:
            mask = event["value"]
            if event.get("offset_before") != stream_cursor:
                raise ValueError("empty StringTable alignment anchor does not follow the previous native cursor")
            aligned = (stream_cursor + mask) & ~mask
            if event.get("offset_after") != aligned:
                raise ValueError("empty StringTable trace alignment result differs from its cursor/mask")
            section_offsets.append(aligned)
            stream_cursor = aligned
        trailing_section_reads = [event for event in ordered_ops
                                  if event.get("operation") in ("load", "take") and
                                  event.get("block_before") == 5 and
                                  event.get("sequence", -1) > name_end_sequence]
        if any(event.get("size") != 0 or event.get("physical_input_bytes") != 0 or
               event.get("offset_after") != event.get("offset_before")
               for event in trailing_section_reads):
            raise ValueError("empty StringTable unexpectedly owns nonzero section reads")
        if len(spans) != 2 or root_span not in spans or name_span not in spans:
            raise ValueError("empty StringTable owns unexpected physical root or child spans")
        archive_end = name_at + len(expected_name)
        if (trace_asset.get("end_cursor") != archive_end or
                root_at + STRINGTABLE_ROOT_BYTES != name_at):
            raise ValueError("empty StringTable root/name spans do not end at the native serialized cursor")
        record = body_data[root_at:archive_end]
        return StringTableLayout(
            asset_index=asset_index, asset_name=asset_name, root_archive_offset=root_at,
            archive_end=archive_end, root_stream_offset=root_dest["offset"],
            name_archive_offset=name_at, name_stream_offset=name_dest["offset"],
            name_bytes=len(expected_name), columns=0, rows=0, dictionary_count=0,
            cells_archive_offset=archive_end, cells_stream_offset=section_offsets[0], cells_bytes=0,
            hashes_archive_offset=archive_end, hashes_stream_offset=section_offsets[1], hashes_bytes=0,
            pointers_archive_offset=archive_end, pointers_stream_offset=section_offsets[2], pointers_bytes=0,
            pointer_tokens=(), inline_dictionary_strings=(), dictionary_values=(),
            source_body_sha256=digest, source_record_sha256=hashlib.sha256(record).hexdigest(),
            name_pointer_mode=name_pointer_mode, name_pointer_token=name_token,
            name_target_archive_offset=name_at,
            name_target_event_sequence=name_target_event_sequence), original_rows

    cells_bytes = rows * columns * 2
    hashes_bytes = dictionary_count * 4
    pointers_bytes = dictionary_count * 8
    # With an inline root name, Load_String consumes the bytes between the
    # root and the cell array. With a shared name alias it consumes no local
    # bytes, so the cell array starts immediately after the 48-byte root.
    cells_archive_start = (name_at + len(expected_name)
                           if name_pointer_mode == "inline" else root_at + STRINGTABLE_ROOT_BYTES)
    physical = [span for span in spans if span.get("origin") in ("load_stream_call", "string_data")]
    cell_span = _one([span for span in physical if span.get("reader_start_arg") == 0 and
                      span.get("size") == cells_bytes and span.get("archive_offset") == cells_archive_start],
                     "row-major u16 cell array")
    hash_span = _one([span for span in physical if span.get("reader_start_arg") == 0 and
                      span.get("size") == hashes_bytes and span.get("archive_offset") == cell_span["archive_offset"] + cells_bytes],
                     "u32 dictionary hash array")
    pointer_span = _one([span for span in physical if span.get("reader_start_arg") == 0 and
                         span.get("size") == pointers_bytes and span.get("archive_offset") == hash_span["archive_offset"] + hashes_bytes],
                        "qword dictionary pointer array")
    for label, span in (("cells", cell_span), ("hashes", hash_span), ("dictionary pointers", pointer_span)):
        destination = span.get("destination_stream_location")
        if not isinstance(destination, dict) or destination.get("stream") != 5:
            raise ValueError(f"StringTable {label} are not allocated in stream 5")
    expected_cells = ((name_dest["offset"] + len(expected_name) + 1) & ~1
                      if name_pointer_mode == "inline" else
                      cell_span["destination_stream_location"]["offset"])
    expected_hashes = (expected_cells + cells_bytes + 3) & ~3
    expected_pointers = (expected_hashes + hashes_bytes + 7) & ~7
    for label, span, expected in (("cells", cell_span, expected_cells),
                                  ("hashes", hash_span, expected_hashes),
                                  ("dictionary pointers", pointer_span, expected_pointers)):
        if span["destination_stream_location"].get("offset") != expected:
            raise ValueError(f"StringTable {label} do not follow the native 2/4/8-byte alignment schedule")

    pointer_tokens = struct.unpack_from(f"<{dictionary_count}Q", body_data, pointer_span["archive_offset"])
    if any(token not in INLINE_POINTERS and token >> 32 != 5 for token in pointer_tokens):
        raise ValueError("StringTable contains an unsupported packed dictionary-pointer tag")
    inline_indices = [index for index, token in enumerate(pointer_tokens) if token in INLINE_POINTERS]
    string_spans = sorted((span for span in spans if span.get("origin") == "string_data" and
                           span.get("archive_offset", -1) > pointer_span["archive_offset"]),
                          key=lambda span: span["archive_offset"])
    if len(string_spans) != len(inline_indices):
        raise ValueError("inline dictionary pointer count differs from traced string reads")
    inline_records: list[tuple[int, int, int, int]] = []
    for index, span in zip(inline_indices, string_spans):
        stream_location = span.get("destination_stream_location")
        if not isinstance(stream_location, dict) or stream_location.get("stream") != 5:
            raise ValueError("inline dictionary string is not allocated in stream 5")
        inline_records.append((index, span["archive_offset"], stream_location["offset"], span["size"]))

    cell_span_end = pointer_span["archive_offset"] + pointers_bytes
    string_spans_all = sorted((span for span in spans if span.get("origin") == "string_data"),
                              key=lambda span: span["archive_offset"])
    if name_pointer_mode == "inline":
        asset_name_span_index = next(i for i, span in enumerate(string_spans_all) if span is name_span)
        child_string_spans = [span for span in string_spans_all[asset_name_span_index + 1:]
                              if span["archive_offset"] >= cell_span_end]
    else:
        child_string_spans = [span for span in string_spans_all
                              if span["archive_offset"] >= cell_span_end]
    if len(child_string_spans) != len(inline_indices):
        raise ValueError("StringTable has unexpected inline child string reads")

    semantic = encode_stringtable_sections(asset_name, original_rows)
    if (semantic["rows"] != rows or semantic["columns"] != columns or
            len(semantic["dictionary"]) != dictionary_count):
        raise ValueError("original semantic table dimensions/dictionary count differ from native root")
    cells_at, hashes_at = cell_span["archive_offset"], hash_span["archive_offset"]
    if body_data[cells_at:cells_at + cells_bytes] != semantic["cells"]:
        raise ValueError("original semantic CSV cells differ from native row-major u16 section")
    if body_data[hashes_at:hashes_at + hashes_bytes] != semantic["hashes"]:
        raise ValueError("original semantic CSV dictionary differs from native u32 hash section")
    for index, span in zip(inline_indices, child_string_spans):
        actual = _trace_string(span, body_data)
        if actual != semantic["dictionary"][index]:
            raise ValueError(f"inline native dictionary entry {index} differs from semantic CSV")

    packed_indices = [index for index, token in enumerate(pointer_tokens)
                      if token not in INLINE_POINTERS]
    packed_dictionary_references: list[dict[str, Any]] = []
    if require_packed_dictionary_proof and packed_indices and (
            not isinstance(global_string_data_spans, list) or
            not isinstance(trace_asset.get("root_name_resolution_events"), list)):
        raise ValueError("Omnvar StringTable packed dictionary requires complete span and callback projections")
    if isinstance(global_string_data_spans, list) and isinstance(
            trace_asset.get("root_name_resolution_events"), list):
        begin_sequence, end_sequence = trace_asset.get("begin_sequence"), trace_asset.get("end_sequence")
        owner_index = trace_asset.get("index")
        pointer_stream = pointer_span["destination_stream_location"]["offset"]
        for dictionary_index in packed_indices:
            if not all(isinstance(value, int) and not isinstance(value, bool)
                       for value in (begin_sequence, end_sequence, owner_index)):
                raise ValueError("packed StringTable dictionary lacks bounded native owner coordinates")
            packed_dictionary_references.append(_resolve_packed_dictionary_string(
                dictionary_index=dictionary_index, token=pointer_tokens[dictionary_index],
                expected_value=semantic["dictionary"][dictionary_index],
                pointer_stream_offset=pointer_stream, owner_index=owner_index,
                begin_sequence=begin_sequence, end_sequence=end_sequence,
                resolution_events=trace_asset["root_name_resolution_events"],
                global_string_data_spans=global_string_data_spans, body_data=body_data))

    ordered_spans = sorted((span for span in physical if isinstance(span.get("archive_offset"), int) and
                            isinstance(span.get("size"), int) and span["size"] > 0),
                           key=lambda span: span["archive_offset"])
    owned = [span for span in ordered_spans if root_at <= span["archive_offset"] <
             max(item["archive_offset"] + item["size"] for item in ordered_spans)]
    cursor = root_at
    for span in owned:
        at, size = span["archive_offset"], span["size"]
        if at < root_at:
            continue
        if at != cursor:
            raise ValueError("StringTable archive children are not one contiguous serialized record")
        cursor += size
    if trace_asset.get("end_cursor") != cursor:
        raise ValueError("StringTable native end cursor differs from its bounded serialized record")

    dictionary = tuple(semantic["dictionary"])
    record = body_data[root_at:cursor]
    return StringTableLayout(
        asset_index=asset_index, asset_name=asset_name, root_archive_offset=root_at,
        archive_end=cursor, root_stream_offset=root_dest["offset"],
        name_archive_offset=name_at, name_stream_offset=name_dest["offset"],
        name_bytes=len(asset_name.encode("utf-8")) + 1, columns=columns, rows=rows,
        dictionary_count=dictionary_count, cells_archive_offset=cells_at,
        cells_stream_offset=cell_span["destination_stream_location"]["offset"],
        cells_bytes=cells_bytes, hashes_archive_offset=hashes_at,
        hashes_stream_offset=hash_span["destination_stream_location"]["offset"],
        hashes_bytes=hashes_bytes, pointers_archive_offset=pointer_span["archive_offset"],
        pointers_stream_offset=pointer_span["destination_stream_location"]["offset"],
        pointers_bytes=pointers_bytes, pointer_tokens=tuple(pointer_tokens),
        inline_dictionary_strings=tuple(inline_records), dictionary_values=dictionary,
        source_body_sha256=digest, source_record_sha256=hashlib.sha256(record).hexdigest(),
        name_pointer_mode=name_pointer_mode, name_pointer_token=name_token,
        name_target_archive_offset=name_at,
        name_target_event_sequence=name_target_event_sequence,
        packed_dictionary_references=tuple(packed_dictionary_references)), original_rows


def _serialize_record(source_body: bytes, layout: StringTableLayout,
                      rows: list[list[str]]) -> tuple[bytes, dict]:
    packed_name = getattr(layout, "name_pointer_mode", "inline") == "packed-shared-stream5"
    if getattr(layout, "name_pointer_mode", "inline") not in ("inline", "packed-shared-stream5"):
        raise ValueError("StringTable serialization encountered an unsupported root name mode")
    name_token = (getattr(layout, "name_pointer_token", None) if packed_name
                  else 0xFFFFFFFFFFFFFFFE)
    if packed_name and (type(name_token) is not int or name_token >> 32 != 5 or
                        type(getattr(layout, "name_stream_offset", None)) is not int or
                        type(getattr(layout, "cells_stream_offset", None)) is not int or
                        layout.name_stream_offset >= layout.cells_stream_offset):
        raise ValueError("packed StringTable root name lacks its exact stream-5 token")
    sections = encode_stringtable_sections(layout.asset_name, rows)
    header = bytearray(source_body[layout.root_archive_offset:
                                   layout.root_archive_offset + STRINGTABLE_ROOT_BYTES])
    struct.pack_into("<QIII", header, 0, name_token,
                     sections["columns"], sections["rows"], len(sections["dictionary"]))
    for offset in (24, 32, 40):
        struct.pack_into("<Q", header, offset, 0xFFFFFFFFFFFFFFFE)
    pointer_array = struct.pack(f"<{len(sections['dictionary'])}Q",
                                *([0xFFFFFFFFFFFFFFFE] * len(sections["dictionary"])))
    name = b"" if packed_name else layout.asset_name.encode("utf-8") + b"\0"
    strings = b"".join(value.encode("utf-8") + b"\0" for value in sections["dictionary"])
    record = bytes(header) + name + sections["cells"] + sections["hashes"] + pointer_array + strings
    # Native Load_StringTable aligns the u16 cells, u32 hashes, and pointer
    # array independently. This padding advances resident stream 5 only;
    # adding it to the serialized record would desynchronize archive reads.
    stream_start = layout.cells_stream_offset if packed_name else layout.name_stream_offset
    cells_start = (stream_start if packed_name else
                   (stream_start + len(name) + 1) & ~1)
    hashes_start = (cells_start + len(sections["cells"]) + 3) & ~3
    pointers_start = (hashes_start + len(sections["hashes"]) + 7) & ~7
    string_start = pointers_start + len(pointer_array)
    logical_end = string_start + len(strings)
    new_string_offsets = {value: string_start + sum(len(item.encode("utf-8")) + 1
                                                    for item in sections["dictionary"][:index])
                          for index, value in enumerate(sections["dictionary"])}
    return record, dict(sections=sections, stream5_start=stream_start,
                        stream5_end=logical_end, new_string_offsets=new_string_offsets,
                        stream5_sections=dict(cells=cells_start, hashes=hashes_start,
                                              pointers=pointers_start, strings=string_start),
                        record_sha256=hashlib.sha256(record).hexdigest())


def _validate_noop_native_trace(trace_path: str | Path, manifest_path: str | Path,
                                body_size: int, asset_index: int) -> tuple[int, dict[int, int], dict[str, Any]]:
    """Validate an unchanged table's complete trace and return event/highwater counts."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    references = manifest.get("reference_only_rows", [])
    tested, top_level = manifest.get("tested"), manifest.get("top_level_index")
    expected_events = manifest.get("stream_trace_events")
    failed, unavailable = manifest.get("failed"), manifest.get("unavailable")
    if (manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            type(failed) is not int or failed != 0 or
            type(unavailable) is not int or unavailable != 0 or
            type(expected_events) is not int or expected_events < 0 or
            type(tested) is not int or type(top_level) is not int or
            not isinstance(references, list) or tested + len(references) != top_level or
            manifest.get("serialized_bytes_read") != body_size or
            not (manifest.get("stream_trace_enabled") or manifest.get("stream_trace"))):
        raise ValueError("unchanged StringTable requires a complete successful native stream trace")

    # Reuse the same full-table event/EOF validator as native typed inspection;
    # a no-op edit must not bypass proof merely because it emits no new bytes.
    from workstation_trace_index import build_read_span_index
    index = build_read_span_index(trace_path, manifest_path, body_size)
    stream5_allocation_context = validate_complete_stream5_allocations(index)
    if (index.get("status") != "native-read-spans-indexed" or
            index.get("event_count") != expected_events or
            index.get("xasset_count") != top_level):
        raise ValueError("unchanged StringTable trace does not cover the complete native XAsset table")
    rows = index.get("assets")
    selected = [row for row in rows if row.get("index") == asset_index] if isinstance(rows, list) else []
    if (len(selected) != 1 or selected[0].get("type_id") != STRINGTABLE_TYPE_ID):
        raise ValueError("unchanged StringTable is absent from complete native trace")
    highwaters = index.get("max_destination_offsets")
    if (not isinstance(highwaters, dict) or
            any(type(key) is not int or not 0 <= key < 11 or
                type(value) is not int or value < 0
                for key, value in highwaters.items())):
        raise ValueError("unchanged StringTable trace has invalid stream high-water values")
    return expected_events, highwaters, stream5_allocation_context


class _IntervalIndex:
    """Compact, time-aware index over native physical stream allocations."""

    def __init__(self, intervals: list[dict]):
        self.by_stream: dict[int, list[dict]] = {}
        self.starts: dict[int, list[int]] = {}
        self.prefix_max_ends: dict[int, list[int]] = {}
        for item in intervals:
            self.by_stream.setdefault(item["stream"], []).append(item)
        for block, values in self.by_stream.items():
            values.sort(key=lambda item: (item["old_start"], item["sequence"]))
            self.starts[block] = [item["old_start"] for item in values]
            prefix: list[int] = []
            maximum = 0
            for item in values:
                maximum = max(maximum, item["old_end"])
                prefix.append(maximum)
            self.prefix_max_ends[block] = prefix

    def lookup(self, stream: int, offset: int, size: int = 1,
               sequence: int | None = None, owner: int | None = None) -> list[dict]:
        values = self.by_stream.get(stream, [])
        if not values:
            return []
        index = bisect_right(self.starts[stream], offset) - 1
        found: list[dict] = []
        while index >= 0 and self.prefix_max_ends[stream][index] > offset:
            item = values[index]
            if (item["old_start"] <= offset and offset + size <= item["old_end"] and
                    (sequence is None or item["sequence"] <= sequence) and
                    (owner is None or item["owner"] == owner)):
                found.append(item)
            index -= 1
        if found:
            latest = max(item["sequence"] for item in found)
            found = [item for item in found if item["sequence"] == latest]
        return found


def _map_replaced_table_target(old_offset: int, old_start: int, old_end: int,
                               preserved_targets: dict[int, int],
                               removed_string_targets: set[int]) -> int | None:
    """Map a target inside the replaced table, or fail only when it is used."""
    if not old_start <= old_offset < old_end:
        return None
    mapped = preserved_targets.get(old_offset)
    if mapped is not None:
        return mapped
    if old_offset in removed_string_targets:
        raise ValueError(
            f"retained packed reference targets removed StringTable dictionary string at {old_offset:#x}")
    raise ValueError(
        f"packed reference targets non-string bytes in replaced StringTable at {old_offset:#x}")


def replace_stringtable_rows(body_data: bytes, asset_index: int, asset_name: str,
                             trace_asset: dict, original_rows: list[list[str]],
                             replacement_rows: list[list[str]], expected_body_sha256: str,
                             trace_path: str | Path, manifest_path: str | Path,
                             full_trace_index: dict | None = None) -> tuple[bytes, dict]:
    """Rebuild one StringTable and relocate all native block-5 references.

    The rebuilt dictionary is emitted inline. Any outside packed reference to
    an old inline dictionary string must still find the same text in the new
    dictionary; otherwise the edit is rejected. Other global and asset-local
    stream-5 aliases are relocated from the full native event schedule.
    """
    from workstation_trace_index import build_read_span_index
    if full_trace_index is None:
        full_trace_index = build_read_span_index(trace_path, manifest_path, len(body_data))
    if (not isinstance(full_trace_index, dict) or
            full_trace_index.get("status") != "native-read-spans-indexed" or
            full_trace_index.get("body_size") != len(body_data) or
            not isinstance(full_trace_index.get("string_data_spans"), list)):
        raise ValueError("StringTable writer requires the complete native string-data span index")
    indexed_asset = next((item for item in full_trace_index.get("assets", [])
                          if item.get("index") == asset_index and item.get("type_id") == STRINGTABLE_TYPE_ID), None)
    if (indexed_asset is None or
            indexed_asset.get("root_name_resolution_events") !=
            trace_asset.get("root_name_resolution_events")):
        raise ValueError("StringTable writer trace projection differs from its complete native owner callbacks")
    layout, _ = inspect_stringtable(
        body_data, asset_index, asset_name, trace_asset, original_rows,
        expected_body_sha256,
        global_string_data_spans=full_trace_index["string_data_spans"])
    if replacement_rows == original_rows:
        body_hash = hashlib.sha256(body_data).hexdigest()
        event_count, highwaters, stream5_allocation_context = _validate_noop_native_trace(
            trace_path, manifest_path, len(body_data), asset_index)
        reservation_blocks = set(range(1, 6)) | set(highwaters)
        return body_data, dict(
            schema=1, status="no-op-stringtable-edit",
            asset_index=asset_index, asset_name=asset_name,
            source_body_sha256=body_hash, output_body_sha256=body_hash,
            old_dimensions=dict(rows=layout.rows, columns=layout.columns,
                                dictionary_count=layout.dictionary_count),
            new_dimensions=dict(rows=layout.rows, columns=layout.columns,
                                dictionary_count=layout.dictionary_count),
            archive_extent_delta=0, stream5_extent_delta=0,
            old_stream_high_waters=dict(sorted(highwaters.items())),
            new_stream_high_waters=dict(sorted(highwaters.items())),
            stream_reservation_deltas={str(block): 0 for block in sorted(reservation_blocks)},
            new_stream5_high_water=highwaters.get(5, 0),
            stream5_allocation_context=stream5_allocation_context,
            full_native_trace_events=event_count,
            packed_stream5_aliases_rebased=0, xasset_table_unchanged=True)
    stream5_allocation_context = validate_complete_stream5_allocations(full_trace_index)
    layout, _ = inspect_stringtable(
        body_data, asset_index, asset_name, trace_asset, original_rows,
        expected_body_sha256,
        global_string_data_spans=full_trace_index.get("string_data_spans", []))
    record, emitted = _serialize_record(body_data, layout, replacement_rows)
    body = bytearray(body_data)
    old_record = body_data[layout.root_archive_offset:layout.archive_end]
    if len(old_record) != layout.archive_end - layout.root_archive_offset:
        raise ValueError("StringTable replacement extent is outside the source body")
    extent_delta = len(record) - len(old_record)
    output = body_data[:layout.root_archive_offset] + record + body_data[layout.archive_end:]
    output = bytearray(output)

    # Map old inline dictionary strings to their replacement location by value.
    new_dict = emitted["sections"]["dictionary"]
    external_target_map: dict[int, int] = {}
    removed_string_targets: set[int] = set()
    for index, old_archive, old_stream, string_size in layout.inline_dictionary_strings:
        value = layout.dictionary_values[index]
        target = emitted["new_string_offsets"].get(value)
        if target is None:
            removed_string_targets.add(old_stream)
        else:
            external_target_map[old_stream] = target
    # Inline names are emitted at the table's current stream-5 cursor. Packed
    # names remain shared references to a separately owned, earlier string;
    # the complete alias replay relocates those fields when another edit moves
    # their target.
    if layout.name_pointer_mode == "inline":
        external_target_map[layout.name_stream_offset] = layout.name_stream_offset

    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_events = manifest.get("stream_trace_events")
    if (manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            not isinstance(expected_events, int) or manifest.get("tested") != manifest.get("top_level_index") or
            manifest.get("serialized_bytes_read") != len(body_data) or
            not manifest.get("complete") or not manifest.get("success") or
            not (manifest.get("stream_trace_enabled") or manifest.get("stream_trace"))):
        raise ValueError("StringTable growth requires a complete successful native stream trace")

    target_stream_old_start = (layout.cells_stream_offset
                               if layout.name_pointer_mode == "packed-shared-stream5"
                               else layout.name_stream_offset)
    target_stream_old_end = max(
        [layout.cells_stream_offset + layout.cells_bytes,
         layout.hashes_stream_offset + layout.hashes_bytes,
         layout.pointers_stream_offset + layout.pointers_bytes,
         *(old_stream + size for _, _, old_stream, size in layout.inline_dictionary_strings)],
        default=(layout.cells_stream_offset if layout.name_pointer_mode == "packed-shared-stream5"
                 else layout.name_stream_offset + layout.name_bytes))
    # Packed dictionary entries may point to earlier shared strings; the asset's
    # physically owned block-5 range still includes all array children and inline strings.
    target_stream_old_end = max(target_stream_old_end,
                                layout.pointers_stream_offset + layout.pointers_bytes)
    target_stream_new_end = emitted["stream5_end"]
    old_archive_start, old_archive_end = layout.root_archive_offset, layout.archive_end
    archive_delta = extent_delta
    stream_deltas: dict[int, int] = {}
    original_cursors: dict[int, int] = {}
    max_new: dict[int, int] = {}
    max_old: dict[int, int] = {}
    asset_bases: dict[int, int] = {}
    original_asset_bases: dict[int, int] = {}
    intervals: list[dict] = []
    pending_call: dict | None = None
    active_asset: int | None = None
    changed_asset_seen = False
    event_count = 0

    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            seq = event.get("sequence")
            if seq != event_count:
                raise ValueError(f"StringTable trace sequence breaks at event {event_count}")
            event_count += 1
            kind = event.get("kind")
            if kind == "xasset_begin":
                active_asset = event.get("xasset_index")
            elif kind == "begin_asset_call":
                owner = event.get("xasset_index")
                if isinstance(owner, int):
                    original_base = original_cursors.get(5)
                    if not isinstance(original_base, int):
                        raise ValueError(f"StringTable relocation has no block-5 base for asset {owner}")
                    original_asset_bases[owner] = original_base
                    asset_bases[owner] = original_base + stream_deltas.get(5, 0)
            elif kind == "xasset_end":
                if active_asset == asset_index:
                    if not changed_asset_seen:
                        raise ValueError("full trace did not reach the selected StringTable")
                    stream_deltas[5] = target_stream_new_end - target_stream_old_end
                    max_new[5] = max(max_new.get(5, 0), target_stream_new_end)
                active_asset = None
                pending_call = None
            elif kind == "load_stream_call":
                pending_call = event
            elif kind in ("packed_resolve", "packed_alias"):
                raw = event.get("raw_token")
                field = event.get("field_stream_location")
                target = event.get("resolved_target_stream_location")
                if isinstance(raw, int) and isinstance(field, dict):
                    if isinstance(target, dict) and isinstance(target.get("stream"), int):
                        block, offset = target["stream"], target.get("offset")
                    elif raw >> 32 == 5:
                        block, offset = 5, (raw & 0xFFFFFFFF) - 1
                    else:
                        block, offset = None, None

            if kind != "stream_operation":
                if pending_call and seq > pending_call.get("sequence", seq) + 1:
                    pending_call = None
                continue
            operation = event.get("operation")
            before_block, after_block = event.get("block_before"), event.get("block_after")
            before_offset, after_offset = event.get("offset_before"), event.get("offset_after")
            if not all(isinstance(value, int) for value in
                       (before_block, after_block, before_offset, after_offset)):
                pending_call = None
                continue
            original_cursors[after_block] = after_offset
            if before_block > 0:
                max_old[before_block] = max(max_old.get(before_block, 0), before_offset)
            if after_block > 0:
                max_old[after_block] = max(max_old.get(after_block, 0), after_offset)
            new_before = before_offset + stream_deltas.get(before_block, 0)

            if operation in ("load", "take"):
                size, physical = event.get("size"), event.get("physical_input_bytes")
                if not isinstance(size, int) or not isinstance(physical, int):
                    raise ValueError("trace read lacks byte accounting")
                if before_block == 0:
                    pending_call = None
                    continue
                old_advance = after_offset - before_offset
                if before_block == after_block and old_advance != size:
                    raise ValueError("trace read size differs from resident cursor advance")
                if physical and active_asset == asset_index and before_block == 5:
                    changed_asset_seen = True
                elif physical:
                    archive_start = event.get("input_before")
                    if not isinstance(archive_start, int):
                        raise ValueError("physical read has no archive input offset")
                    output_archive = archive_start + (archive_delta if archive_start >= old_archive_end else 0)
                    intervals.append(dict(owner=event.get("xasset_index"), stream=before_block,
                                          old_start=before_offset, old_end=before_offset + size,
                                          new_start=new_before, source_archive=archive_start,
                                          output_archive=output_archive, size=size, sequence=seq))
                new_after = (new_before + old_advance if before_block == after_block else
                             after_offset + stream_deltas.get(after_block, 0))
                stream_deltas[after_block] = new_after - after_offset
                if before_block > 0 and not (active_asset == asset_index and before_block == 5):
                    max_new[before_block] = max(max_new.get(before_block, 0), new_before)
                if after_block > 0 and not (active_asset == asset_index and after_block == 5):
                    max_new[after_block] = max(max_new.get(after_block, 0), new_after)
                pending_call = None
            elif operation == "align":
                mask = event.get("value")
                if not isinstance(mask, int) or mask < 0:
                    raise ValueError("trace alignment mask is invalid")
                if before_block == after_block:
                    new_after = (new_before + mask) & ~mask
                else:
                    new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                if before_block > 0 and not (active_asset == asset_index and before_block == 5):
                    max_new[before_block] = max(max_new.get(before_block, 0), new_before)
                if after_block > 0 and not (active_asset == asset_index and after_block == 5):
                    max_new[after_block] = max(max_new.get(after_block, 0), new_after)
                pending_call = None
            elif operation in ("push", "pop"):
                new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                if before_block > 0 and not (active_asset == asset_index and before_block == 5):
                    max_new[before_block] = max(max_new.get(before_block, 0), new_before)
                if after_block > 0 and not (active_asset == asset_index and after_block == 5):
                    max_new[after_block] = max(max_new.get(after_block, 0), new_after)
                pending_call = None
            else:
                new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                if before_block > 0 and not (active_asset == asset_index and before_block == 5):
                    max_new[before_block] = max(max_new.get(before_block, 0), new_before)
                if after_block > 0 and not (active_asset == asset_index and after_block == 5):
                    max_new[after_block] = max(max_new.get(after_block, 0), new_after)
                pending_call = None

    if event_count != expected_events or not changed_asset_seen:
        raise ValueError("full native trace ended early or omitted the selected StringTable")
    interval_index = _IntervalIndex(intervals)

    def map_target(old_offset: int, sequence: int) -> int:
        table_target = _map_replaced_table_target(old_offset, target_stream_old_start,
                                                  target_stream_old_end, external_target_map,
                                                  removed_string_targets)
        if table_target is not None:
            mapped = table_target
            return mapped
        matches = interval_index.lookup(5, old_offset, sequence=sequence)
        mapped = {item["new_start"] + old_offset - item["old_start"] for item in matches}
        if len(mapped) != 1:
            if old_offset < target_stream_old_start and not matches:
                return old_offset
            raise ValueError(f"stream-5 target {old_offset:#x} has {len(mapped)} relocated owners")
        return next(iter(mapped))

    def map_field(owner: int | None, field: dict, sequence: int) -> tuple[int, int]:
        block, offset = field.get("stream"), field.get("offset")
        if not isinstance(block, int) or not isinstance(offset, int):
            raise ValueError("packed alias field lacks stream/offset")
        matches = interval_index.lookup(block, offset, 8, sequence=sequence,
                                        owner=owner)
        unique = {(item["source_archive"] + offset - item["old_start"],
                   item["output_archive"] + offset - item["old_start"]) for item in matches}
        if len(unique) != 1:
            raise ValueError(f"packed field {owner}:{block}:{offset:#x} has {len(unique)} source owners")
        return next(iter(unique))

    patched: set[tuple[int | None, int, int]] = set()
    changed_aliases = 0
    aliases_scanned = 0
    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            alias_event = json.loads(line)
            if alias_event.get("kind") not in ("packed_resolve", "packed_alias"):
                continue
            raw = alias_event.get("raw_token")
            field = alias_event.get("field_stream_location")
            target = alias_event.get("resolved_target_stream_location")
            if not isinstance(raw, int) or not isinstance(field, dict):
                continue
            if isinstance(target, dict) and isinstance(target.get("stream"), int):
                block, offset = target["stream"], target.get("offset")
            elif raw >> 32 == 5:
                block, offset = 5, (raw & 0xFFFFFFFF) - 1
            else:
                continue
            if block != 5:
                continue
            if not isinstance(offset, int) or offset < 0:
                raise ValueError("packed stream-5 target has an invalid offset")
            aliases_scanned += 1
            owner = alias_event.get("xasset_index")
            if owner == asset_index:
                # The target asset's name and pointer sections were regenerated;
                # any old inline or shared-pointer words inside it are obsolete.
                continue
            tag = raw >> 32
            if tag == 5:
                if offset != (raw & 0xFFFFFFFF) - 1:
                    raise ValueError("tag-5 token does not match its absolute block-5 target")
                new_target = map_target(offset, alias_event["sequence"])
                new_raw = (raw & 0xFFFFFFFF00000000) | ((new_target + 1) & 0xFFFFFFFF)
            elif tag == 0x15:
                old_low = raw & 0xFFFFFFFF
                if old_low == 0:
                    raise ValueError("asset-local packed token has a zero low word")
                old_base = original_asset_bases.get(owner)
                new_base = asset_bases.get(owner)
                if old_base is None or new_base is None or offset != old_base + old_low - 1:
                    raise ValueError(f"tag-0x15 pointer does not match owner {owner} block-5 base")
                new_target = map_target(offset, alias_event["sequence"])
                new_low = new_target - new_base + 1
                if not 0 < new_low <= 0xFFFFFFFF:
                    raise ValueError("relocated asset-local packed token is out of range")
                new_raw = (raw & 0xFFFFFFFF00000000) | new_low
            else:
                raise ValueError(f"cannot re-encode moved packed-pointer tag {tag:#x}")
            if new_raw == raw:
                continue
            old_field, output_field = map_field(owner, field, alias_event["sequence"])
            if old_field < 0 or old_field + 8 > len(body_data) or struct.unpack_from("<Q", body_data, old_field)[0] != raw:
                raise ValueError("packed-reference source bytes differ from the complete trace")
            key = (owner, field.get("stream"), field.get("offset"))
            if key in patched:
                raise ValueError("trace contains duplicate writes for one packed-reference field")
            patched.add(key)
            if output_field < 0 or output_field + 8 > len(output):
                raise ValueError("relocated packed-reference field falls outside output body")
            struct.pack_into("<Q", output, output_field, new_raw)
            changed_aliases += 1

    # Import at the call site to avoid a module cycle: workstation_fastfiles
    # imports this writer only inside its StringTable edit path.
    from workstation_fastfiles import ZoneBody

    parsed_before, parsed_after = ZoneBody.parse(body_data), ZoneBody.parse(bytes(output))
    if parsed_before.assets != parsed_after.assets:
        raise AssertionError("StringTable edit changed the XAsset table")
    return bytes(output), dict(
        schema=1, status="trace-relocated-stringtable-ready",
        asset_index=asset_index, asset_name=asset_name,
        source_body_sha256=layout.source_body_sha256,
        output_body_sha256=hashlib.sha256(output).hexdigest(),
        old_record_sha256=layout.source_record_sha256,
        new_record_sha256=emitted["record_sha256"],
        old_dimensions=dict(rows=layout.rows, columns=layout.columns,
                            dictionary_count=layout.dictionary_count),
        new_dimensions=dict(rows=emitted["sections"]["rows"],
                            columns=emitted["sections"]["columns"],
                            dictionary_count=len(new_dict)),
        old_archive_extent=layout.archive_end - layout.root_archive_offset,
        new_archive_extent=len(record), archive_extent_delta=extent_delta,
        old_stream5_start=target_stream_old_start,
        old_stream5_end=target_stream_old_end,
        new_stream5_end=target_stream_new_end,
        stream5_extent_delta=target_stream_new_end - target_stream_old_end,
        old_stream_high_waters=dict(sorted(max_old.items())),
        new_stream_high_waters=dict(sorted(max_new.items())),
        stream_reservation_deltas={str(block): max_new.get(block, 0) - old
                                   for block, old in max_old.items()},
        new_stream5_high_water=max_new.get(5),
        packed_stream5_aliases_scanned=aliases_scanned,
        packed_stream5_aliases_rebased=changed_aliases,
        stream5_allocation_context=stream5_allocation_context,
        full_native_trace_events=event_count,
        xasset_table_unchanged=True,
        support_limit="Only trace-complete Replay type-54 StringTables with the proven root/child schedule are editable; packed targets into replaced non-string bytes and removed externally referenced inline strings are rejected.")
