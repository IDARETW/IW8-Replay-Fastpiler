"""Trace-derived type-19 resident-image row append and exclusive tail removal."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import tempfile

from workstation_fastfiles import ZoneBody
from workstation_luafile_operations import _rebase_aliases, _trace_contract

IMAGE_TYPE_ID = 19
IMAGE_ROOT_BYTES = 232
XASSET_ROW_BYTES = 16
XASSET_COUNT_OFFSET = 16
INLINE = 0xFFFFFFFFFFFFFFFE
INLINE_ALT = 0xFFFFFFFFFFFFFFFF


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: str | Path) -> str:
    return _sha(Path(path).read_bytes())


def _trace_contract_from_receipt(body: bytes, trace_path: str | Path,
                                 manifest_path: str | Path, *,
                                 expected_trace_sha256: str,
                                 expected_manifest_sha256: str,
                                 table_row_delta: int = 0,
                                 schedule_asset_index: int | None = None,
                                 removed_stream_ranges=(), logical_delete_ranges=(),
                                 removed_owner=None):
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest_bytes = manifest_path.read_bytes()
    if _sha(manifest_bytes) != expected_manifest_sha256 or _file_sha(trace_path) != expected_trace_sha256:
        raise ValueError("resident-image trace or manifest differs from its immutable native receipt")
    manifest = json.loads(manifest_bytes)
    recorded = manifest.get("stream_trace_sha256")
    if recorded is not None and recorded != expected_trace_sha256:
        raise ValueError("resident-image manifest and walk receipt disagree on the trace digest")
    temp_dir = None
    contract_manifest = manifest_path
    if recorded is None:
        manifest["stream_trace_sha256"] = expected_trace_sha256
        temp_dir = tempfile.TemporaryDirectory(prefix="image-trace-contract-")
        contract_manifest = Path(temp_dir.name) / "manifest.json"
        contract_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        values = _trace_contract(body, trace_path, contract_manifest,
            removed_stream_ranges=tuple(removed_stream_ranges),
            logical_delete_ranges=tuple(logical_delete_ranges),
            removed_owner=removed_owner, table_row_delta=table_row_delta,
            schedule_asset_index=schedule_asset_index)
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()
    return values


def _validate_template(body_data: bytes, template_index: int, template_name: str,
                       template_trace_asset: dict, expected_body_sha256: str) -> tuple[bytes, dict]:
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("resident-image template belongs to a different decoded body")
    if (type(template_index) is not int or not 0 <= template_index < len(body.assets) or
            body.assets[template_index].type_id != IMAGE_TYPE_ID or
            template_trace_asset.get("index") != template_index or
            template_trace_asset.get("type_id") != IMAGE_TYPE_ID or
            template_trace_asset.get("name") != template_name):
        raise ValueError("resident-image template identity is not a native type-19 trace row")
    roots = [span for span in template_trace_asset.get("read_spans", [])
             if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0 and span.get("size") == IMAGE_ROOT_BYTES]
    if len(roots) != 1:
        raise ValueError("resident-image template has no unique 232-byte native root")
    span = roots[0]
    root_at = span.get("archive_offset")
    if type(root_at) is not int or root_at < 0 or root_at + IMAGE_ROOT_BYTES > len(body_data):
        raise ValueError("resident-image template root is outside the decoded body")
    root = body_data[root_at:root_at + IMAGE_ROOT_BYTES]
    name = template_name.encode("utf-8") + b"\0"
    total_size = struct.unpack_from("<I", root, 0x1C)[0]
    dims = struct.unpack_from("<4H", root, 0x24)
    name_token = struct.unpack_from("<Q", root, 0)[0]
    pixels_token = struct.unpack_from("<Q", root, 0xE0)[0]
    shape_flag_mask = 0x8000 | 0x10000 | 0x20000
    if (name_token not in (INLINE, INLINE_ALT) or pixels_token != INLINE or
            root[0x32] != 0 or any(root[0x38:0xD8]) or
            struct.unpack_from("<Q", root, 8)[0] != 0 or
            struct.unpack_from("<Q", root, 0xD8)[0] != 0 or
            struct.unpack_from("<I", root, 0x18)[0] & shape_flag_mask or
            dims[2:] != (1, 1) or
            not all(isinstance(value, int) and value > 0 for value in dims) or total_size <= 0):
        raise ValueError("resident-image template is not a plain inline root with null atlas/fallback/stream children")
    read_spans = template_trace_asset.get("read_spans", [])
    names = [item for item in read_spans if item.get("origin") == "string_data" and
             item.get("size") == len(name) and
             body_data[item.get("archive_offset", -1):item.get("archive_offset", -1) + len(name)] == name and
             item.get("destination_stream_location", {}).get("stream") == 5]
    payloads = [item for item in read_spans if item.get("origin") == "load_stream_call" and
                item.get("reader_start_arg") == 0 and item.get("size") == total_size and
                item.get("destination_stream_location", {}).get("stream") == 1]
    if len(names) != 1 or len(payloads) != 1:
        raise ValueError("resident-image template lacks unique stream-5 name and stream-1 pixel children")
    if (span.get("destination_stream_location") != {"stream": 1, "offset": 0} or
            payloads[0].get("destination_stream_location", {}).get("offset") !=
            ((IMAGE_ROOT_BYTES + 15) & ~15)):
        raise ValueError("resident-image template does not use the observed stream-1 root/pixel schedule")
    if (root_at + IMAGE_ROOT_BYTES != names[0]["archive_offset"] or
            names[0]["archive_offset"] + names[0]["size"] != payloads[0]["archive_offset"]):
        raise ValueError("resident-image template root/name/pixels are not one contiguous physical record")
    return root, dict(root_archive_offset=root_at, root_span=span,
                      name_span=names[0], payload_span=payloads[0],
                      format=struct.unpack_from("<I", root, 0x14)[0],
                      flags=struct.unpack_from("<I", root, 0x18)[0],
                      dimensions=dims, level_count=root[0x30], total_size=total_size,
                      name_pointer_token=name_token, pixel_pointer_token=pixels_token)


def append_resident_image_tail(body_data: bytes, name: str, payload: bytes,
                               format_id: int, dimensions: tuple[int, int, int, int],
                               mip_count: int, existing_names: set[str],
                               template_index: int, template_name: str,
                               template_trace_asset: dict, final_trace_asset: dict,
                               expected_body_sha256: str, trace_path: str | Path,
                               manifest_path: str | Path, stream_reservations: list[int], *,
                               expected_trace_sha256: str,
                               expected_manifest_sha256: str) -> tuple[bytes, dict]:
    """Append one image by copying a trace-proven compatible root and native schedule."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("resident-image append trace belongs to another source body")
    if (not isinstance(name, str) or not name or "\0" in name or "\\" in name or
            name.startswith("/") or name.endswith("/") or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("resident-image name must be a confined native asset path")
    name_bytes = name.encode("utf-8") + b"\0"
    if len(name_bytes) > 256 or name in existing_names:
        raise ValueError("resident-image name is too long or already exists in the native inventory")
    if (not isinstance(payload, bytes) or not payload or type(format_id) is not int or
            type(mip_count) is not int or len(dimensions) != 4 or
            any(type(value) is not int or value < 1 for value in dimensions) or
            len(stream_reservations) != 11):
        raise ValueError("resident-image payload or typed resource dimensions are invalid")
    template_root, template = _validate_template(body_data, template_index, template_name,
                                                 template_trace_asset, expected_body_sha256)
    if (format_id != template["format"] or dimensions[2:] != template["dimensions"][2:] or
            dimensions[2:] != (1, 1)):
        raise ValueError("resident-image append format/depth/array geometry differs from its proven native template")
    if final_trace_asset.get("index", final_trace_asset.get("xasset_index")) != len(body.assets) - 1 or \
            final_trace_asset.get("type_id") != body.assets[-1].type_id or \
            final_trace_asset.get("end_cursor") != len(body_data):
        raise ValueError("source final XAsset has no exact trace-owned EOF boundary")
    final_spans = final_trace_asset.get("read_spans")
    if (not isinstance(final_spans, list) or not final_spans or
            max((span.get("archive_offset", -1) + span.get("size", 0) for span in final_spans), default=-1) != len(body_data)):
        raise ValueError("source final XAsset trace does not cover physical EOF")
    if not body.assets:
        raise ValueError("resident-image append requires an existing trace-owned XAsset table")

    (manifest, bases, intervals, aliases, table, maxima, alias_count,
     relocated_targets, relocated_bases, stats) = _trace_contract_from_receipt(
        body_data, trace_path, manifest_path, expected_trace_sha256=expected_trace_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        table_row_delta=XASSET_ROW_BYTES, schedule_asset_index=template_index)
    schedule = stats.get("selected_asset_stream_schedule")
    highwaters = stats.get("relocated_stream_max_destinations")
    cursors = stats.get("relocated_terminal_cursors")
    if not isinstance(schedule, list) or not isinstance(highwaters, dict) or not isinstance(cursors, dict):
        raise ValueError("resident-image append requires the complete relocated template schedule")
    root_load = next((event for event in schedule if event.get("operation") == "load" and
                      event.get("block_before") == 1 and event.get("size") == IMAGE_ROOT_BYTES), None)
    align = next((event for event in schedule if event.get("operation") == "align" and
                  event.get("block_before") == 1 and event.get("offset_before") == IMAGE_ROOT_BYTES), None)
    payload_load = next((event for event in schedule if event.get("operation") == "load" and
                         event.get("block_before") == 1 and event.get("size") == template["total_size"]), None)
    name_string = next((event for event in schedule if event.get("operation") == "string" and
                        event.get("block_before") == 5 and event.get("size") == template["name_span"]["size"]), None)
    if (not root_load or root_load.get("offset_before") != 0 or
            not name_string or name_string.get("offset_before") != template["name_span"]["destination_stream_location"]["offset"] or
            not align or align.get("value") != 15 or align.get("offset_before") != IMAGE_ROOT_BYTES or
            align.get("offset_after") != 240 or not payload_load or payload_load.get("offset_before") != 240):
        raise ValueError("resident-image append source schedule differs from the observed 232-byte root/name/stream-1 pixel sequence")
    stream5_start = cursors.get(5)
    if type(stream5_start) is not int or highwaters.get(5) != stream5_start:
        raise ValueError("relocated resident-image name cursor is not the stream-5 EOF")
    table_end = table.get("end")
    if (table.get("size") != len(body.assets) * XASSET_ROW_BYTES or
            table.get("archive") != body.asset_table_offset or
            table.get("archive", -1) + table.get("size", 0) != body.first_payload_offset):
        raise ValueError("resident-image append native XAsset pointer array differs from exact table")
    rebased, alias_proof = _rebase_aliases(body_data, intervals, aliases,
        table_end, body.first_payload_offset, XASSET_ROW_BYTES, bases,
        relocated_targets=relocated_targets, relocated_asset_bases=relocated_bases)
    updated = bytearray(rebased)
    updated[body.first_payload_offset:body.first_payload_offset] = struct.pack(
        "<IIQ", IMAGE_TYPE_ID, 0, INLINE)
    struct.pack_into("<I", updated, XASSET_COUNT_OFFSET, len(body.assets) + 1)
    root_at = len(updated)
    root = bytearray(template_root)
    # Preserve the proven pointer modes and opaque bytes from the compatible
    # native root; change only the typed resource descriptor fields.
    struct.pack_into("<I", root, 0x14, format_id)
    # Pinned IW8 conversion source emits flags=0 for ordinary 2D resources,
    # 0x8000 for cubes, 0x10000 for 3D, and 0x20000 for arrays. This writer
    # authors only the first shape and does not propagate unrelated source bits.
    struct.pack_into("<I", root, 0x18, 0)
    struct.pack_into("<I", root, 0x1C, len(payload))
    struct.pack_into("<4H", root, 0x24, *dimensions)
    root[0x30] = mip_count
    updated.extend(root)
    updated.extend(name_bytes)
    updated.extend(payload)
    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if (len(reparsed.assets) != len(body.assets) + 1 or
            reparsed.assets[:-1] != body.assets or
            reparsed.assets[-1].type_id != IMAGE_TYPE_ID or
            reparsed.assets[-1].pointer_token != INLINE):
        raise AssertionError("resident-image append changed retained XAsset rows")
    pixel_start = ((IMAGE_ROOT_BYTES + 15) & ~15)
    required = list(stream_reservations)
    required[1] = max(required[1], highwaters.get(1, 0), pixel_start + len(payload))
    required[5] = max(required[5], stream5_start + len(name_bytes))
    return result, dict(schema="replay120-resident-image-row-append-v1",
        status="trace-owned-resident-image-row-append-candidate", operation="append",
        type_id=IMAGE_TYPE_ID, name=name, asset_index=len(body.assets),
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(result),
        source_asset_count=len(body.assets), output_asset_count=len(reparsed.assets),
        template_asset_index=template_index, template_name=template_name,
        template_root_archive_offset=template["root_archive_offset"],
        appended_root_archive_offset=root_at, appended_root_stream_offset=0,
        appended_root_bytes=IMAGE_ROOT_BYTES, appended_name_bytes=len(name_bytes),
        appended_payload_bytes=len(payload), appended_payload_sha256=_sha(payload),
        format=format_id, dimensions=list(dimensions), mip_count=mip_count,
        flags=struct.unpack_from("<I", root, 0x18)[0],
        source_template_flags=template["flags"],
        name_pointer_token=struct.unpack_from("<Q", root, 0)[0],
        pixel_pointer_token=struct.unpack_from("<Q", root, 0xE0)[0],
        stream5_name_range=[stream5_start, stream5_start + len(name_bytes)],
        stream1_pixel_range=[pixel_start, pixel_start + len(payload)],
        stream_reservation_sizes=required,
        native_template_schedule=schedule,
        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        stream_trace_sha256=_file_sha(trace_path), pointer_relocation=alias_proof,
        relocated_stream_max_destinations={str(key): value for key, value in highwaters.items()},
        relocated_terminal_cursors={str(key): value for key, value in cursors.items()},
        source_alias_event_count=alias_count,
        target_coordinate_fallbacks=stats.get("target_coordinate_fallbacks", []))


def remove_final_resident_image_tail(body_data: bytes, asset_index: int, asset_name: str,
                                     native_row: dict, trace_asset: dict,
                                     expected_body_sha256: str,
                                     trace_path: str | Path, manifest_path: str | Path, *,
                                     expected_trace_sha256: str,
                                     expected_manifest_sha256: str) -> tuple[bytes, dict]:
    """Remove only a final image whose 232-byte root, name and pixel child own EOF."""
    from workstation_native_asset_edits import read_resident_image
    body = ZoneBody.parse(body_data)
    if (body.source_sha256 != expected_body_sha256 or type(asset_index) is not int or
            asset_index != len(body.assets) - 1 or body.assets[asset_index].type_id != IMAGE_TYPE_ID or
            native_row.get("name") != asset_name or trace_asset.get("index") != asset_index or
            trace_asset.get("type_id") != IMAGE_TYPE_ID or trace_asset.get("name") != asset_name):
        raise ValueError("resident-image removal requires its exact final native type-19 row")
    current = read_resident_image(body_data, dict(native_row, index=asset_index), trace_asset,
                                  expected_body_sha256)
    root_span = next(span for span in trace_asset["read_spans"]
                     if span.get("archive_offset") == current["root_archive_offset"] and
                     span.get("size") == IMAGE_ROOT_BYTES)
    name_span = next(span for span in trace_asset["read_spans"]
                     if span.get("archive_offset") == current["name_archive_offset"] and
                     span.get("origin") == "string_data")
    pixel_span = next(span for span in trace_asset["read_spans"]
                      if span.get("archive_offset") == current["payload_archive_offset"] and
                      span.get("size") == len(current["payload"]))
    name_bytes = asset_name.encode("utf-8") + b"\0"
    owner_start, owner_end = current["root_archive_offset"], current["payload_archive_offset"] + len(current["payload"])
    if (name_span.get("size") != len(name_bytes) or
            body_data[current["name_archive_offset"]:current["name_archive_offset"]+len(name_bytes)] != name_bytes or
            current["root_archive_offset"] + IMAGE_ROOT_BYTES != current["name_archive_offset"] or
            current["name_archive_offset"] + len(name_bytes) != current["payload_archive_offset"] or
            owner_end != len(body_data) or trace_asset.get("end_cursor") != len(body_data)):
        raise ValueError("resident-image root/name/pixels do not uniquely own the exact physical EOF tail")
    physical = [span for span in trace_asset.get("read_spans", [])
                if span.get("origin") in ("load_stream_call", "string_data") and
                type(span.get("archive_offset")) is int and type(span.get("size")) is int and span["size"] > 0]
    expected_spans = sorted(((root_span["archive_offset"], root_span["size"]),
                             (name_span["archive_offset"], name_span["size"]),
                             (pixel_span["archive_offset"], pixel_span["size"])))
    actual_spans = sorted((span["archive_offset"], span["size"]) for span in physical)
    if actual_spans != expected_spans:
        raise ValueError("resident-image tail has additional or ambiguous physical owner spans")
    name_dest = name_span.get("destination_stream_location")
    pixel_dest = pixel_span.get("destination_stream_location")
    root_dest = root_span.get("destination_stream_location")
    if (not all(isinstance(dest, dict) and type(dest.get("stream")) is int and type(dest.get("offset")) is int
                for dest in (root_dest, name_dest, pixel_dest)) or
            (root_dest["stream"], root_dest["offset"]) != (1, 0) or
            name_dest["stream"] != 5 or pixel_dest["stream"] != 1):
        raise ValueError("resident-image tail child stream ownership differs from the native schedule")
    root_range = (root_dest["stream"], root_dest["offset"], root_dest["offset"] + IMAGE_ROOT_BYTES)
    name_range = (name_dest["stream"], name_dest["offset"], name_dest["offset"] + len(name_bytes))
    pixel_range = (pixel_dest["stream"], pixel_dest["offset"], pixel_dest["offset"] + len(current["payload"]))
    values = _trace_contract_from_receipt(body_data, trace_path, manifest_path,
        expected_trace_sha256=expected_trace_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        table_row_delta=-XASSET_ROW_BYTES,
        removed_stream_ranges=(root_range, name_range, pixel_range),
        # The pixel bytes live in stream-1 scratch storage and can be reused
        # by later assets. Only the stream-5 name range is globally removed.
        logical_delete_ranges=(name_range,), removed_owner=asset_index)
    (_manifest, bases, intervals, aliases, table, _maxima, alias_count,
     relocated_targets, relocated_bases, stats) = values
    if (table.get("size") != len(body.assets) * XASSET_ROW_BYTES or
            table.get("archive") != body.asset_table_offset or
            table.get("archive", -1) + table.get("size", 0) != body.first_payload_offset):
        raise ValueError("resident-image removal trace does not own the exact XAsset table")
    for span in intervals:
        if (span.get("owner") != asset_index and span.get("archive", -1) < owner_end and
                span.get("archive", -1) + span.get("size", 0) > owner_start):
            raise ValueError("resident-image root or child physical bytes are shared with another asset")
    rebased, alias_proof = _rebase_aliases(body_data, intervals, aliases,
        table["end"], body.first_payload_offset, XASSET_ROW_BYTES, bases,
        inverse=True, removed_stream_ranges=(root_range, name_range, pixel_range),
        # Stream-1 pixel data is scratch storage and may alias coordinates
        # replayed by other assets. Only stream-5 name coordinates are globally
        # deleted; physical pixel ownership is scoped to this removed owner.
        logical_delete_ranges=(name_range,),
        relocated_targets=relocated_targets, relocated_asset_bases=relocated_bases)
    output = bytearray(rebased)
    row_at = body.asset_table_offset + asset_index * XASSET_ROW_BYTES
    del output[row_at:row_at + XASSET_ROW_BYTES]
    shifted_start = current["root_archive_offset"] - XASSET_ROW_BYTES
    if shifted_start < body.first_payload_offset - XASSET_ROW_BYTES:
        raise ValueError("resident-image record shifted before the body payload region")
    del output[shifted_start:]
    struct.pack_into("<I", output, XASSET_COUNT_OFFSET, asset_index)
    result = bytes(output)
    reparsed = ZoneBody.parse(result)
    if reparsed.assets != body.assets[:-1]:
        raise AssertionError("resident-image removal changed retained XAsset order")
    return result, dict(schema="replay120-resident-image-row-remove-v1",
        status="trace-owned-exclusive-final-resident-image-remove-candidate", operation="remove",
        type_id=IMAGE_TYPE_ID, name=asset_name, removed_index=asset_index,
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(result),
        source_asset_count=len(body.assets), output_asset_count=len(reparsed.assets),
        removed_root_archive_offset=current["root_archive_offset"],
        removed_root_bytes=IMAGE_ROOT_BYTES, removed_name_bytes=len(name_bytes),
        removed_payload_bytes=len(current["payload"]), removed_payload_sha256=_sha(current["payload"]),
        removed_stream_ranges=[root_range, name_range, pixel_range],
        source_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        source_stream_trace_sha256=_file_sha(trace_path), source_alias_event_count=alias_count,
        alias_relocation=alias_proof,
        target_coordinate_fallbacks=stats.get("target_coordinate_fallbacks", []))
