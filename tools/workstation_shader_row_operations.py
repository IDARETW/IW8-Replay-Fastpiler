"""Trace-derived row append for inline Replay 1.20 stage shaders.

The first supported creation form is the native type-17 pixel shader root
observed in code_post_gfx.  Placement and stream alignment come from that
root's full native stream-operation schedule; this module does not guess a
padding or reservation value.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

try:
    from workstation_fastfiles import ZoneBody
    from workstation_luafile_operations import (_rebase_aliases, _trace_contract,
        XASSET_ROW_SIZE, XASSET_ARRAY_COUNT_OFFSET)
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_luafile_operations import (_rebase_aliases, _trace_contract,
        XASSET_ROW_SIZE, XASSET_ARRAY_COUNT_OFFSET)


PIXEL_SHADER_TYPE_ID = 17
INLINE_POINTER = 0xFFFFFFFFFFFFFFFE
SHADER_ROOT_SIZE = 40
SHADER_TYPES = {12, 14, 15, 16, 17}


def remove_final_shader_tail(body_data: bytes, asset_index: int, asset_name: str,
                             trace_asset: dict, expected_body_sha256: str,
                             trace_path: str | Path, manifest_path: str | Path,
                             *, trace_assets: list[dict] | None = None) -> tuple[bytes, dict]:
    """Remove only an exclusive final shader row whose trace-owned bytes end at EOF."""
    from workstation_native_asset_edits import read_inline_shader
    from workstation_luafile_operations import (_alias_field_archive, _build_interval_index,
        _rebase_aliases, _trace_contract, XASSET_ROW_SIZE, XASSET_ARRAY_COUNT_OFFSET)
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("shader removal trace belongs to another source body")
    if type(asset_index) is not int or not 0 <= asset_index < len(body.assets) or asset_index != len(body.assets)-1:
        raise ValueError("shader removal requires the exact final XAsset row")
    type_id = body.assets[asset_index].type_id
    if type_id not in SHADER_TYPES or trace_asset.get("index") != asset_index or trace_asset.get("type_id") != type_id or trace_asset.get("name") != asset_name:
        raise ValueError("shader removal row type/name/index differs from its trace")
    layout = read_inline_shader(body_data, dict(index=asset_index, type_id=type_id, name=asset_name),
                                trace_asset, expected_body_sha256, trace_assets=trace_assets)
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list): raise ValueError("shader removal row lacks trace spans")
    root_at = layout["root_archive_offset"]
    root_span = next((s for s in spans if s.get("origin") == "load_stream_call" and s.get("reader_start_arg") == 0 and s.get("archive_offset") == root_at and s.get("size") == 40), None)
    if root_span is None: raise ValueError("shader root span is not uniquely trace-owned")
    expected_name = asset_name.encode("utf-8") + b"\0"
    names = [s for s in spans if s.get("origin") == "string_data" and s.get("size") == len(expected_name) and
             type(s.get("archive_offset")) is int and body_data[s["archive_offset"]:s["archive_offset"]+s["size"]] == expected_name]
    programs = [s for s in spans if s.get("origin") == "load_stream_call" and s.get("reader_start_arg") == 0 and
                s.get("archive_offset") == layout["program_archive_offset"] and s.get("size") == len(layout["program"])]
    extras = [s for s in spans if s.get("origin") == "string_data" and s not in names]
    if len(names) != 1 or len(programs) != 1 or (type_id == 14 and len(extras) != 1) or (type_id != 14 and extras):
        raise ValueError("shader root/name/program children are not uniquely owned")
    owned = [root_span, names[0], *extras, programs[0]]
    physical_start = root_at
    physical_end = programs[0]["archive_offset"] + programs[0]["size"]
    if physical_end != len(body_data):
        raise ValueError("final shader row does not exclusively own the exact serialized EOF")
    ordered = sorted(owned, key=lambda s: s["archive_offset"])
    cursor = physical_start
    for span in ordered:
        start, end = span["archive_offset"], span["archive_offset"] + span["size"]
        if start < cursor or start > physical_end or end > physical_end:
            raise ValueError("shader child spans overlap or escape the final tail")
        if any(body_data[cursor:start]):
            raise ValueError("shader inter-child padding contains nonzero data")
        cursor = end
    if cursor != physical_end:
        raise ValueError("shader tail has unowned trailing bytes")
    root_dest = root_span.get("destination_stream_location")
    name_dest = names[0].get("destination_stream_location")
    program_dest = programs[0].get("destination_stream_location")
    if not all(isinstance(v, dict) for v in (root_dest, name_dest, program_dest)):
        raise ValueError("shader removal child lacks stream ownership")
    ranges = [(root_dest["stream"], root_dest["offset"], root_dest["offset"]+40),
              (name_dest["stream"], name_dest["offset"], name_dest["offset"]+len(expected_name)),
              (program_dest["stream"], program_dest["offset"], program_dest["offset"]+len(layout["program"]))]
    for extra in extras:
        d=extra.get("destination_stream_location")
        if not isinstance(d, dict): raise ValueError("vertex debug string lacks stream ownership")
        ranges.append((d["stream"], d["offset"], d["offset"]+extra["size"]))
    contract = _trace_contract(body_data, trace_path, manifest_path, removed_stream_ranges=tuple(ranges),
        logical_delete_ranges=tuple(r for r in ranges if r[0] != root_dest["stream"]),
        removed_owner=asset_index, table_row_delta=-XASSET_ROW_SIZE)
    (_manifest, bases, intervals, aliases, table_alloc, _max_destinations,
     alias_count, targets, relocated_bases, pointer_stats) = contract
    for span in intervals:
        if span.get("owner") != asset_index and span.get("archive", -1) < physical_end and span.get("archive", -1)+span.get("size",0)>physical_start:
            raise ValueError("shader root/name/program bytes are shared with another XAsset")
    owned_intervals=sorted((s.get("archive"),s.get("archive",-1)+s.get("size",0)) for s in intervals if s.get("owner")==asset_index and s.get("archive",-1)<physical_end and s.get("archive",-1)+s.get("size",0)>physical_start)
    physical_intervals=sorted((s["archive_offset"],s["archive_offset"]+s["size"]) for s in owned)
    if owned_intervals != physical_intervals:
        raise ValueError("shader physical tail has missing or extra owner spans")
    table_row = body.asset_table_offset + asset_index*XASSET_ROW_SIZE
    rebased, alias_receipt = _rebase_aliases(body_data, intervals, aliases, table_alloc["end"], body.first_payload_offset,
        -XASSET_ROW_SIZE, bases, removed_stream_ranges=tuple(ranges),
        logical_delete_ranges=tuple(r for r in ranges if r[0] != root_dest["stream"]),
        relocated_targets=targets, relocated_asset_bases=relocated_bases)
    result=bytearray(rebased)
    for start,end in sorted(((physical_start,physical_end),(table_row,table_row+XASSET_ROW_SIZE)),reverse=True): del result[start:end]
    struct.pack_into("<I",result,XASSET_ARRAY_COUNT_OFFSET,len(body.assets)-1)
    out=bytes(result); parsed=ZoneBody.parse(out)
    if [(r.type_id,r.pointer_token) for r in parsed.assets] != [(r.type_id,r.pointer_token) for r in body.assets[:-1]]:
        raise AssertionError("shader removal changed retained XAsset identities/order")
    return out,dict(schema="replay120-shader-row-remove-candidate-v1",status="native-trace-shader-row-remove-candidate",
        operation="remove",type_id=type_id,asset_name=asset_name,asset_index=asset_index,
        source_body_sha256=body.source_sha256,output_body_sha256=_sha(out),source_asset_count=len(body.assets),
        output_asset_count=len(parsed.assets),removed_tail_archive_range=[physical_start,physical_end],
        removed_stream_ranges=[list(row) for row in ranges],
        logical_delete_ranges=[list(row) for row in ranges if row[0] != root_dest["stream"]],
        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
        source_alias_events=alias_count,pointer_contract=pointer_stats,**alias_receipt)


def append_native_shader_tail(body_data: bytes, type_id: int, name: str, program: bytes,
                              program_identity: int, existing_names: set[str],
                              template_index: int, template_name: str,
                              template_trace_asset: dict, final_trace_asset: dict,
                              expected_body_sha256: str, trace_path: str | Path,
                              manifest_path: str | Path) -> tuple[bytes, dict]:
    """Append a typed shader using that stage's observed 40-byte trace layout.

    This supports only the five stage roots present in Replay's native reader.
    Child ordering, stream cursor, alignment, and template bytes are validated
    against the selected row's complete native schedule on every invocation.
    """
    if type_id not in SHADER_TYPES:
        raise ValueError("unsupported native shader stage type")
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("shader row trace belongs to a different source body")
    if (not isinstance(name, str) or not name or "\0" in name or "\\" in name or
            name.startswith("/") or name.endswith("/") or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("shader name is not a safe native asset name")
    if name in existing_names:
        raise ValueError("shader name already exists in the native inventory")
    if type(program_identity) is not int or not 0 <= program_identity <= 0xFFFFFFFF:
        raise ValueError("shader identity must be a uint32")
    if not isinstance(program, bytes) or len(program) < 32 or program[:4] != b"DXBC":
        raise ValueError("shader payload is not a DXBC container")
    if struct.unpack_from("<I", program, 24)[0] != len(program):
        raise ValueError("DXBC declared size differs from its byte length")
    from workstation_asset_codecs import dxbc_native_shader_type
    if dxbc_native_shader_type(program) != type_id:
        raise ValueError("DXBC stage does not match the requested native XAsset type")
    if (type(template_index) is not int or not 0 <= template_index < len(body.assets) or
            body.assets[template_index].type_id != type_id or
            template_trace_asset.get("index") != template_index or
            template_trace_asset.get("type_id") != type_id or
            template_name != template_trace_asset.get("name")):
        raise ValueError("shader template index/type/name does not match its trace row")
    spans = template_trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("shader template lacks native physical spans")
    roots = [s for s in spans if s.get("origin") == "load_stream_call" and
             s.get("reader_start_arg") == 0 and s.get("size") == SHADER_ROOT_SIZE]
    if len(roots) != 1:
        raise ValueError("shader template has no unique traced 40-byte root")
    root_at = roots[0].get("archive_offset")
    if type(root_at) is not int or root_at < 0 or root_at + SHADER_ROOT_SIZE > len(body_data):
        raise ValueError("shader template root falls outside the body")
    root = bytearray(body_data[root_at:root_at + SHADER_ROOT_SIZE])
    q0, q8, q16, q24 = struct.unpack_from("<QQQQ", root)
    # q0/q8 can contain packed aliases in real rows. Their acceptance is
    # constrained to observed encodings here and then checked against the
    # selected row's physical callback/alias contract below. Stage-specific
    # emitted values are written only where the stage layout reconstructs
    # them (compute, vertex, pixel); hull/domain preserve the rebased source.
    q8_shape_ok = (type_id == 12 and q8 == 0x0000001500000001) or (
        type_id in (14, 15, 16, 17) and
        (q8 in (INLINE_POINTER, 0xFFFFFFFFFFFFFFFF, 0x0000001500000001) or (q8 >> 32) == 5))
    if q0 not in (INLINE_POINTER, 0xFFFFFFFFFFFFFFFF) or not q8_shape_ok or q16 != 0 or q24 not in (0, INLINE_POINTER, 0xFFFFFFFFFFFFFFFF):
        raise ValueError("shader template root has an unsupported stage-specific pointer shape")
    template_name_bytes = template_name.encode("utf-8") + b"\0"
    name_spans = [s for s in spans if s.get("origin") == "string_data" and
                  s.get("size") == len(template_name_bytes) and
                  type(s.get("archive_offset")) is int and
                  body_data[s["archive_offset"]:s["archive_offset"] + s["size"]] == template_name_bytes]
    program_size = struct.unpack_from("<I", root, 32)[0]
    program_spans = [s for s in spans if s.get("origin") == "load_stream_call" and
                     s.get("size") == program_size and type(s.get("archive_offset")) is int and
                     body_data[s["archive_offset"]:s["archive_offset"] + 4] == b"DXBC"]
    if len(name_spans) != 1 or len(program_spans) != 1:
        raise ValueError("shader template lacks unique traced name and DXBC children")
    extra_spans = [s for s in spans if s.get("origin") == "string_data" and s not in name_spans]
    if (type_id == 14 and len(extra_spans) != 1) or (type_id != 14 and extra_spans):
        raise ValueError("shader template string children differ from its observed stage layout")
    extra_bytes = b""
    if extra_spans:
        extra = extra_spans[0]
        extra_at = extra.get("archive_offset")
        if type(extra_at) is not int or extra.get("size", 0) < 1:
            raise ValueError("vertex shader secondary inline string is malformed")
        extra_bytes = body_data[extra_at:extra_at + extra["size"]]
        if len(extra_bytes) != extra["size"] or not extra_bytes.endswith(b"\0"):
            raise ValueError("vertex shader secondary inline string is not terminated")
    if final_trace_asset.get("xasset_index") != len(body.assets) - 1 or final_trace_asset.get("end_cursor") != len(body_data):
        raise ValueError("source final XAsset lacks an exact serialized EOF boundary")
    final_spans = final_trace_asset.get("read_spans")
    if not isinstance(final_spans, list) or not final_spans or max(
            s.get("archive_offset", -1) + s.get("size", 0) for s in final_spans) != len(body_data):
        raise ValueError("source final XAsset does not own the serialized tail")
    (manifest, asset_bases, intervals, aliases, table_alloc, max_destinations,
     alias_event_count, relocated_targets, relocated_asset_bases, stats) = _trace_contract(
         body_data, trace_path, manifest_path, table_row_delta=XASSET_ROW_SIZE,
         schedule_asset_index=template_index)
    del manifest, alias_event_count
    cursors = stats.get("relocated_terminal_cursors")
    highwaters = stats.get("relocated_stream_max_destinations")
    schedule = stats.get("selected_asset_stream_schedule")
    if not isinstance(cursors, dict) or not isinstance(highwaters, dict) or not isinstance(schedule, list):
        raise ValueError("shader append requires replayed native stream cursors and schedule")
    name_dest = name_spans[0].get("destination_stream_location")
    program_dest = program_spans[0].get("destination_stream_location")
    if (not isinstance(name_dest, dict) or name_dest.get("stream") != 5 or type(name_dest.get("offset")) is not int or
            not isinstance(program_dest, dict) or program_dest.get("stream") != 5):
        raise ValueError("shader name/program lacks exact stream-5 destinations")
    string_events = [e for e in schedule if e.get("operation") == "string" and e.get("block_before") == 5]
    expected_strings = 2 if type_id == 14 else 1
    if len(string_events) != expected_strings:
        raise ValueError("shader schedule string count differs from its stage layout")
    name_start = cursors.get(5)
    if type(name_start) is not int or name_start < 0:
        raise ValueError("relocated stream-5 terminal cursor is invalid")
    name_bytes = name.encode("utf-8") + b"\0"
    stream_cursor = name_start + len(name_bytes)
    if type_id == 14:
        stream_cursor += len(extra_bytes)
    aligns = [e for e in schedule if e.get("operation") == "align" and e.get("block_before") == 5]
    if not aligns:
        raise ValueError("shader schedule has no stream-5 program alignment")
    align = aligns[-1]
    mask = align.get("value")
    if type(mask) is not int or mask < 0 or (mask + 1) & mask:
        raise ValueError("shader alignment mask or cursor is not trace-derived")
    program_start = (stream_cursor + mask) & ~mask
    if align.get("offset_after") != program_dest.get("offset"):
        raise ValueError("shader program destination differs from the selected trace alignment")
    if program_dest.get("offset") + program_size > max_destinations.get(5, 0):
        raise ValueError("shader program placement differs from the selected trace schedule")
    align_pos = schedule.index(align)
    load = next((e for e in schedule[align_pos + 1:] if e.get("operation") == "load" and
                 e.get("block_before") == 5 and e.get("offset_before") == program_dest.get("offset") and
                 e.get("size") == program_size), None)
    if load is None:
        raise ValueError("shader DXBC is not the scheduled stream-5 load")
    if table_alloc.get("size") != len(body.assets) * XASSET_ROW_SIZE or table_alloc.get("archive", -1) + table_alloc.get("size", -1) != body.first_payload_offset:
        raise ValueError("native XAsset pointer array does not end at its root-table boundary")
    rebased, alias_receipt = _rebase_aliases(body_data, intervals, aliases,
        table_alloc["end"], body.first_payload_offset, XASSET_ROW_SIZE, asset_bases,
        relocated_targets=relocated_targets, relocated_asset_bases=relocated_asset_bases)
    updated = bytearray(rebased)
    struct.pack_into("<I", updated, XASSET_ARRAY_COUNT_OFFSET, len(body.assets) + 1)
    updated[body.first_payload_offset:body.first_payload_offset] = struct.pack("<IIQ", type_id, 0, INLINE_POINTER)
    root_archive = len(updated)
    # Table insertion relocates existing physical roots and can rebase their
    # shared packed-name target. Copy the transformed template row, never the
    # stale pre-insertion bytes.
    relocated_template_at = root_at + XASSET_ROW_SIZE
    relocated_template_root = updated[relocated_template_at:relocated_template_at + SHADER_ROOT_SIZE]
    if len(relocated_template_root) != SHADER_ROOT_SIZE:
        raise ValueError("rebased shader template root is outside the candidate body")
    root = bytearray(relocated_template_root)
    struct.pack_into("<Q", root, 0, INLINE_POINTER)
    if type_id == 12:
        struct.pack_into("<Q", root, 8, 0x0000001500000001)
    elif type_id == 14:
        struct.pack_into("<Q", root, 8, 0xFFFFFFFFFFFFFFFF)
    elif type_id == 17:
        struct.pack_into("<Q", root, 8, (5 << 32) | (name_start + 1))
    struct.pack_into("<I", root, 32, len(program))
    struct.pack_into("<I", root, 36, program_identity)
    reservations = [0] * 11
    for sid, extent in highwaters.items():
        if type(sid) is int and 0 <= sid < len(reservations): reservations[sid] = extent
    # Stream 1 scratch is reused by native readers; its reservation must reach
    # the replayed terminal cursor, not merely the selected template's offset
    # (commonly zero). Preserve the greater observed high-water as well.
    s1_cursor = cursors.get(1, cursors.get("1", 0))
    s1_highwater = highwaters.get(1, highwaters.get("1", 0))
    if type(s1_cursor) is not int or type(s1_highwater) is not int:
        raise ValueError("native shader schedule lacks a valid stream-1 terminal reservation")
    reservations[1] = max(reservations[1], s1_cursor, s1_highwater)
    program_end = program_start + len(program)
    reservations[5] = max(reservations[5], program_end)
    updated.extend(root); updated.extend(name_bytes)
    if type_id == 14: updated.extend(extra_bytes)
    updated.extend(b"\0" * (program_start - (name_start + len(name_bytes) + len(extra_bytes))))
    updated.extend(program)
    result = bytes(updated)
    appended_q8 = struct.unpack_from("<Q", root, 8)[0]
    parsed = ZoneBody.parse(result)
    if len(parsed.assets) != len(body.assets) + 1 or parsed.assets[-1].type_id != type_id:
        raise AssertionError("shader append did not add exactly one typed row")
    return result, dict(schema=1, status="trace-native-shader-row-append-candidate", operation="append",
        type_id=type_id, name=name, asset_index=len(body.assets), source_body_sha256=body.source_sha256,
        output_body_sha256=_sha(result), template_asset_index=template_index,
        template_root_archive_offset=root_at, appended_root_archive_offset=root_archive,
        appended_name_bytes=len(name_bytes), secondary_string_bytes=len(extra_bytes),
        secondary_string_hex=extra_bytes.hex(),
        appended_program_bytes=len(program), program_identity=program_identity,
        packed_name_token=appended_q8,
        stream5_name_range=[name_start, name_start + len(name_bytes)],
        secondary_string_sha256=_sha(extra_bytes),
        stream5_program_range=[program_start, program_end], stream_reservation_highwaters=reservations,
        native_template_stream_schedule=schedule, **alias_receipt)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_pixel_shader_template_root(root: bytes) -> None:
    if len(root) != SHADER_ROOT_SIZE:
        raise ValueError("pixel shader template root is not the proven 40-byte layout")
    if struct.unpack_from("<QQ", root, 16) != (0, 0):
        raise ValueError("pixel shader template has unsupported root+16/root+24 storage references")


def append_pixel_shader_tail(body_data: bytes, name: str, program: bytes,
                             program_identity: int, existing_names: set[str],
                             template_index: int, template_name: str,
                             template_trace_asset: dict, final_trace_asset: dict,
                             expected_body_sha256: str, trace_path: str | Path,
                             manifest_path: str | Path) -> tuple[bytes, dict]:
    """Append one authored type-17 root after a native-proven EOF boundary."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("pixel shader row trace belongs to a different source body")
    if (not isinstance(name, str) or not name or "\0" in name or "\\" in name or
            name.startswith("/") or name.endswith("/") or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("pixel shader name is not a safe native asset name")
    if name in existing_names:
        raise ValueError("pixel shader name already exists in the native inventory")
    if type(program_identity) is not int or not 0 < program_identity <= 0xFFFFFFFF:
        raise ValueError("pixel shader identity must be an allocated nonzero uint32")
    if not isinstance(program, bytes) or len(program) < 32 or program[:4] != b"DXBC":
        raise ValueError("pixel shader payload is not a DXBC container")
    if struct.unpack_from("<I", program, 24)[0] != len(program):
        raise ValueError("pixel shader DXBC declared size differs from its byte length")
    from workstation_asset_codecs import dxbc_native_shader_type
    if dxbc_native_shader_type(program) != PIXEL_SHADER_TYPE_ID:
        raise ValueError("DXBC stage is not the observed native type-17 pixel stage")
    if (type(template_index) is not int or not 0 <= template_index < len(body.assets) or
            body.assets[template_index].type_id != PIXEL_SHADER_TYPE_ID or
            template_trace_asset.get("index") != template_index or
            template_trace_asset.get("type_id") != PIXEL_SHADER_TYPE_ID or
            template_name != template_trace_asset.get("name")):
        raise ValueError("pixel shader template index/type/name does not match its trace row")
    roots = [span for span in template_trace_asset.get("read_spans", [])
             if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0 and span.get("size") == SHADER_ROOT_SIZE]
    if len(roots) != 1:
        raise ValueError("pixel shader template has no unique traced 40-byte root")
    root_at = roots[0].get("archive_offset")
    if type(root_at) is not int or root_at < 0 or root_at + SHADER_ROOT_SIZE > len(body_data):
        raise ValueError("pixel shader template root falls outside the body")
    template_root = bytearray(body_data[root_at:root_at + SHADER_ROOT_SIZE])
    _validate_pixel_shader_template_root(template_root)
    if struct.unpack_from("<Q", template_root, 0)[0] not in (INLINE_POINTER, 0xFFFFFFFFFFFFFFFF):
        raise ValueError("pixel shader template name field is not inline")
    template_name_bytes = template_name.encode("utf-8") + b"\0"
    name_spans = [span for span in template_trace_asset.get("read_spans", [])
                  if span.get("origin") == "string_data" and span.get("size") == len(template_name_bytes)
                  and body_data[span.get("archive_offset", -1):span.get("archive_offset", -1) + len(template_name_bytes)] == template_name_bytes]
    program_size = struct.unpack_from("<I", template_root, 32)[0]
    program_spans = [span for span in template_trace_asset.get("read_spans", [])
                     if span.get("origin") == "load_stream_call" and
                     span.get("size") == program_size and
                     type(span.get("archive_offset")) is int and
                     body_data[span["archive_offset"]:span["archive_offset"] + 4] == b"DXBC"]
    if len(name_spans) != 1 or len(program_spans) != 1:
        raise ValueError("pixel shader template lacks unique traced name and DXBC children")
    if final_trace_asset.get("xasset_index") != len(body.assets) - 1 or \
            final_trace_asset.get("end_cursor") != len(body_data):
        raise ValueError("source final XAsset lacks an exact serialized EOF boundary")
    final_spans = final_trace_asset.get("read_spans")
    if not isinstance(final_spans, list) or not final_spans or max(
            span.get("archive_offset", -1) + span.get("size", 0) for span in final_spans) != len(body_data):
        raise ValueError("source final XAsset does not own the serialized tail")

    (manifest, asset_bases, intervals, aliases, table_alloc, max_destinations,
     alias_event_count, relocated_targets, relocated_asset_bases, stats) = _trace_contract(
        body_data, trace_path, manifest_path, table_row_delta=XASSET_ROW_SIZE,
        schedule_asset_index=template_index)
    del manifest, alias_event_count
    cursors = stats.get("relocated_terminal_cursors")
    highwaters = stats.get("relocated_stream_max_destinations")
    schedule = stats.get("selected_asset_stream_schedule")
    if not isinstance(cursors, dict) or not isinstance(highwaters, dict) or not isinstance(schedule, list):
        raise ValueError("pixel shader append requires replayed relocated stream cursors/schedule")
    name_stream = name_spans[0].get("destination_stream_location")
    if not isinstance(name_stream, dict) or name_stream.get("stream") != 5 or type(name_stream.get("offset")) is not int:
        raise ValueError("pixel shader name lacks an exact stream-5 destination")
    name_event = next((i for i, event in enumerate(schedule)
        if event.get("operation") == "string" and event.get("block_before") == 5 and
        event.get("offset_before") == name_stream["offset"] and event.get("size") == len(template_name_bytes)), None)
    if name_event is None:
        raise ValueError("pixel shader schedule lacks the template's exact name-string operation")
    name_load = next((event for event in schedule[name_event + 1:]
        if event.get("operation") == "load" and event.get("block_before") == 5), None)
    if name_load is None or name_load.get("offset_before") != name_stream["offset"] or name_load.get("size") != len(template_name_bytes):
        raise ValueError("pixel shader inline name does not match its traced load schedule")
    align = next((event for event in schedule[schedule.index(name_load) + 1:]
        if event.get("operation") == "align" and event.get("block_before") == 5), None)
    if not isinstance(align, dict):
        raise ValueError("pixel shader schedule has no name-to-DXBC alignment event")
    mask, before, after = align.get("value"), align.get("offset_before"), align.get("offset_after")
    if (type(mask) is not int or mask < 0 or (mask + 1) & mask or
            before != name_stream["offset"] + len(template_name_bytes) or
            after != ((before + mask) & ~mask)):
        raise ValueError("pixel shader name-to-DXBC alignment differs from the native schedule")
    program_load = next((event for event in schedule[schedule.index(align) + 1:]
        if event.get("operation") == "load" and event.get("block_before") == 5), None)
    program_dest = program_spans[0].get("destination_stream_location")
    if (not isinstance(program_load, dict) or not isinstance(program_dest, dict) or
            program_dest.get("stream") != 5 or after != program_dest.get("offset") or
            program_load.get("offset_before") != program_dest.get("offset") or
            program_load.get("size") != program_size):
        raise ValueError("pixel shader DXBC does not match the scheduled stream-5 load")
    if table_alloc.get("size") != len(body.assets) * XASSET_ROW_SIZE or \
            table_alloc.get("archive", -1) + table_alloc.get("size", -1) != body.first_payload_offset:
        raise ValueError("native XAsset pointer array does not end at its root-table boundary")

    rebased, alias_receipt = _rebase_aliases(body_data, intervals, aliases,
        table_alloc["end"], body.first_payload_offset, XASSET_ROW_SIZE, asset_bases,
        relocated_targets=relocated_targets, relocated_asset_bases=relocated_asset_bases)
    table_physical_end = body.first_payload_offset
    row = struct.pack("<IIQ", PIXEL_SHADER_TYPE_ID, 0, INLINE_POINTER)
    updated = bytearray(rebased)
    struct.pack_into("<I", updated, XASSET_ARRAY_COUNT_OFFSET, len(body.assets) + 1)
    updated[table_physical_end:table_physical_end] = row
    appended_root_at = len(updated)
    name_stream_start = cursors.get(5)
    if type(name_stream_start) is not int or name_stream_start < 0:
        raise ValueError("relocated stream-5 terminal cursor is invalid")
    # The native type-17 trace uses both an inline XString at root+0 and a
    # tag-5 packed source-name resolve at root+8. Bind both to the same newly
    # serialized authored name; retain all other root bytes from the trace.
    new_root = template_root
    struct.pack_into("<Q", new_root, 0, INLINE_POINTER)
    struct.pack_into("<Q", new_root, 8, (5 << 32) | (name_stream_start + 1))
    struct.pack_into("<I", new_root, 32, len(program))
    struct.pack_into("<I", new_root, 36, program_identity)
    name_bytes = name.encode("utf-8") + b"\0"
    program_stream_start = (name_stream_start + len(name_bytes) + mask) & ~mask
    program_stream_end = program_stream_start + len(program)
    stream5_required = max(highwaters.get(5, 0), program_stream_end)
    stream1_required = max(highwaters.get(1, 0), roots[0]["destination_stream_location"].get("offset", 0) + SHADER_ROOT_SIZE)
    # Preserve every stream that the source trace uses, including stream 6's
    # fixed shader allocator metadata.  The family-specific append only grows
    # streams 1 and 5; it must not silently zero other source reservations.
    reservations = [0] * 11
    for stream_id, extent in highwaters.items():
        if type(stream_id) is int and 0 <= stream_id < len(reservations):
            reservations[stream_id] = extent
    reservations[1] = max(reservations[1], stream1_required)
    reservations[5] = max(reservations[5], stream5_required)
    updated.extend(new_root)
    updated.extend(name_bytes)
    updated.extend(program)
    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if len(reparsed.assets) != len(body.assets) + 1 or reparsed.assets[-1].type_id != PIXEL_SHADER_TYPE_ID:
        raise AssertionError("pixel shader append did not add exactly one final type-17 row")
    return result, dict(schema=1, status="trace-native-type17-inline-row-append-candidate",
        operation="append", type_id=PIXEL_SHADER_TYPE_ID, name=name,
        asset_index=len(body.assets), source_body_sha256=body.source_sha256,
        output_body_sha256=_sha(result), source_asset_count=len(body.assets),
        output_asset_count=len(reparsed.assets), template_asset_index=template_index,
        template_root_archive_offset=root_at, appended_root_archive_offset=appended_root_at,
        appended_name_bytes=len(name_bytes), appended_program_bytes=len(program),
        program_identity=program_identity, packed_name_token=(5 << 32) | (name_stream_start + 1),
        stream5_name_range=[name_stream_start, name_stream_start + len(name_bytes)],
        stream5_alignment=dict(mask=mask, padding_bytes=program_stream_start - name_stream_start - len(name_bytes)),
        stream5_program_range=[program_stream_start, program_stream_end],
        stream_reservation_highwaters=reservations,
        native_template_stream_schedule=[{key: event.get(key) for key in
            ("operation", "block_before", "offset_before", "block_after", "offset_after", "value", "size")}
            for event in schedule],
        native_trace_sha256=_sha(Path(trace_path).read_bytes()),
        source_stream_max_destinations={str(key): value for key, value in max_destinations.items()},
        **alias_receipt)
