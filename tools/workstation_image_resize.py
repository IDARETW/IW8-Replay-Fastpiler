"""Resize native resident images whose pixel scratch scope is trace-proven.

Replay loads these pixels into a nested temporary stream-1 allocation, uploads
them, and restores that cursor before the next XAsset. Pixel growth changes the
physical archive and scratch high-water mark, but no persistent stream address.
The writer requires that exact schedule rather than assuming every image has it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

try:
    from workstation_fastfiles import ZoneBody
    from workstation_native_asset_edits import read_resident_image
    from workstation_asset_codecs import _replay_chain_layout
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_native_asset_edits import read_resident_image
    from tools.workstation_asset_codecs import _replay_chain_layout


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _validate_scratch_schedules(trace_path, manifest_path, body_size, asset_count, edits):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if (manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 0xff7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
            manifest.get("tested") != asset_count or manifest.get("top_level_index") != asset_count or
            manifest.get("serialized_bytes_read") != body_size):
        raise ValueError("image resizing requires a complete native full-zone trace")
    states = {index: dict(seen=False, restored=False, native_ended=False, ended=False)
              for index in edits}
    cursor = count = 0
    active = None
    pending = None
    max_offsets = [0] * 11
    digest = hashlib.sha256()
    with Path(trace_path).open("rb") as stream:
        for line in stream:
            digest.update(line)
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("sequence") != count:
                raise ValueError("image native trace sequence is incomplete")
            count += 1
            kind = event.get("kind")
            owner = event.get("xasset_index")
            if active is not None and isinstance(owner, int) and owner != active:
                raise ValueError("image trace event owner differs from its active XAsset scope")
            if owner in edits and active != owner and kind != "xasset_begin":
                raise ValueError("image trace event lies outside its top-level XAsset scope")
            if kind == "xasset_begin":
                if active is not None:
                    raise ValueError("image trace contains nested top-level XAssets")
                active = owner
            if kind == "xasset_end":
                if active != owner:
                    raise ValueError("image trace XAsset owner is inconsistent")
                if owner in states:
                    state = states[owner]
                    if not state["seen"] or not state["restored"] or not state["native_ended"]:
                        raise ValueError("image pixel scratch cursor was not restored before asset end")
                    state["ended"] = True
                active = None
            if kind == "load_stream_call":
                pending = event
            if kind in ("packed_alias", "packed_resolve") and owner in edits:
                target = event.get("resolved_target_stream_location") or {}
                child = edits[owner]
                if (target.get("stream") == 1 and isinstance(target.get("offset"), int) and
                        child["stream_offset"] <= target["offset"] <
                        child["stream_offset"] + child["current"]["total_size"]):
                    raise ValueError("packed pointer refers to image scratch pixels")
            if kind != "stream_operation":
                continue
            operation = event.get("operation")
            before, after = event.get("input_before"), event.get("input_after")
            physical = event.get("physical_input_bytes")
            if not all(type(value) is int for value in (before, after, physical)):
                raise ValueError("image trace lacks physical cursor accounting")
            if before != cursor or after - before != physical or physical < 0:
                raise ValueError("image trace physical archive accounting is discontinuous")
            cursor = after
            for suffix in ("before", "after"):
                block, offset = event.get("block_" + suffix), event.get("offset_" + suffix)
                if type(block) is not int or type(offset) is not int or not 0 <= block < 11 or offset < 0:
                    raise ValueError("image trace has an invalid stream cursor")
                max_offsets[block] = max(max_offsets[block], offset)
            if owner in edits:
                edit, state = edits[owner], states[owner]
                current = edit["current"]
                if operation == "load" and before == current["payload_archive_offset"] and physical:
                    pending_destination = (pending or {}).get("destination_stream_location", {})
                    if (state["seen"] or physical != current["total_size"] or
                            event.get("block_before") != 1 or event.get("block_after") != 1 or
                            event.get("offset_before") != edit["stream_offset"] or
                            event.get("offset_after") != edit["stream_offset"] + physical or
                            pending is None or pending.get("sequence") != count - 2 or
                            pending.get("xasset_index") != owner or
                            pending.get("size") != physical or
                            pending.get("loader_start_arg") != 0 or pending.get("at_start") is not True):
                        raise ValueError("image pixels are not one exact native scratch read")
                    if (pending_destination.get("stream") != 1 or
                            pending_destination.get("offset") != edit["stream_offset"]):
                        raise ValueError("image pixel load call disagrees with its scratch destination")
                    state["seen"] = True
                elif state["seen"] and physical:
                    raise ValueError("image has physical child reads after its pixel payload")
                if state["seen"] and not state["restored"]:
                    if (operation == "pop" and event.get("block_after") == 1 and
                            event.get("offset_after") < edit["stream_offset"]):
                        state["restored"] = True
                    elif (operation not in ("load", "pop") or
                          operation == "load" and before != current["payload_archive_offset"]):
                        raise ValueError("image scratch lifetime contains an unsupported operation")
                if operation == "end_asset":
                    if (not state["restored"] or event.get("block_before") != 1 or
                            event.get("block_after") != 1 or
                            event.get("offset_before") >= edit["stream_offset"] or
                            event.get("offset_after") != event.get("offset_before")):
                        raise ValueError("image native asset ended before its pixel scratch reset")
                    state["native_ended"] = True
            pending = None
    if (active is not None or count != manifest.get("stream_trace_events") or cursor != body_size or
            not all(state["ended"] for state in states.values())):
        raise ValueError("image native trace did not finish all assets and the exact archive")
    trace_hash = digest.hexdigest()
    if manifest.get("stream_trace_sha256", trace_hash) != trace_hash:
        raise ValueError("image native trace digest differs from its manifest")
    return max_offsets, trace_hash, count


def resize_resident_images(body_data: bytes, requests: list[dict], expected_body_sha256: str,
                           trace_path: str | Path, manifest_path: str | Path) -> tuple[bytes, dict]:
    """Apply a batch of resized 2D images without changing persistent addresses.

    Requests contain asset_row, trace_asset, width, height, mip_count, payload.
    Format, flags and all other image fields retain their original values.
    A full native reread remains mandatory before publishing the returned bytes.
    """
    parsed = ZoneBody.parse(body_data)
    if parsed.source_sha256 != expected_body_sha256 or not requests:
        raise ValueError("image transaction has no edits or its source body changed")
    edits = {}
    for request in requests:
        current = read_resident_image(body_data, request["asset_row"], request["trace_asset"],
                                      expected_body_sha256)
        index = current["asset_index"]
        if index in edits or not 0 <= index < len(parsed.assets) or parsed.assets[index].type_id != 19:
            raise ValueError("image owner must be a unique native type-19 table row")
        root = current["root_bytes"]
        if (current["dimensions"][2:] != (1, 1) or current["flags"] & 0x40 or
                struct.unpack_from("<Q", root, 8)[0] or struct.unpack_from("<Q", root, 0xd8)[0]):
            raise ValueError("image resizing supports resident 2D images without atlas/fallback children")
        width, height, mips = (request[key] for key in ("width", "height", "mip_count"))
        if not all(type(value) is int for value in (width, height, mips)):
            raise ValueError("image dimensions and mip count must be integers")
        layout = _replay_chain_layout(width, height, mips, current["format"])
        payload = request["payload"]
        if not isinstance(payload, bytes) or len(payload) != sum(stride for _, stride in layout):
            raise ValueError("image payload does not match its native format and mip dimensions")
        original_layout = _replay_chain_layout(*current["dimensions"][:2], current["level_count"],
                                               current["format"])
        if current["total_size"] != sum(stride for _, stride in original_layout):
            raise ValueError("original image does not use the supported native mip strides")
        spans = [span for span in request["trace_asset"]["read_spans"]
                 if span.get("archive_offset") == current["payload_archive_offset"] and
                 span.get("size") == current["total_size"] and
                 span.get("origin") == "load_stream_call" and span.get("reader_start_arg") == 0]
        destination = spans[0].get("destination_stream_location", {}) if len(spans) == 1 else {}
        if destination.get("stream") != 1 or type(destination.get("offset")) is not int:
            raise ValueError("image pixels do not occupy a unique stream-1 scratch span")
        if current["payload_archive_offset"] + current["total_size"] != current["trace_end_cursor"]:
            raise ValueError("image pixels are not the asset's final serialized child")
        edits[index] = dict(current=current, stream_offset=destination["offset"],
                            width=width, height=height, mip_count=mips, payload=payload)
    offsets, trace_hash, event_count = _validate_scratch_schedules(
        trace_path, manifest_path, len(body_data), len(parsed.assets), edits)
    new_offsets = list(offsets)
    result = bytearray(body_data)
    receipts = []
    for index, edit in edits.items():
        current = edit["current"]
        root = current["root_archive_offset"]
        struct.pack_into("<I", result, root + 0x1c, len(edit["payload"]))
        struct.pack_into("<HH", result, root + 0x24, edit["width"], edit["height"])
        result[root + 0x30] = edit["mip_count"]
        changed = {offset for offset, (old, new) in enumerate(
            zip(current["root_bytes"], result[root:root + len(current["root_bytes"])], strict=True))
            if old != new}
        allowed = set(range(0x1c, 0x20)) | set(range(0x24, 0x28)) | {0x30}
        if not changed <= allowed:
            raise AssertionError("image resize changed opaque native root fields")
        new_offsets[1] = max(new_offsets[1], edit["stream_offset"] + len(edit["payload"]))
        receipts.append(dict(asset_index=index, name=current["name"], format=current["format"],
            old_dimensions=list(current["dimensions"][:2]), new_dimensions=[edit["width"], edit["height"]],
            old_mip_count=current["level_count"], new_mip_count=edit["mip_count"],
            old_payload_size=current["total_size"], new_payload_size=len(edit["payload"]),
            old_payload_sha256=current["payload_sha256"], new_payload_sha256=_sha(edit["payload"])))
    for edit in sorted(edits.values(), key=lambda item: item["current"]["payload_archive_offset"], reverse=True):
        current = edit["current"]
        at = current["payload_archive_offset"]
        result[at:at + current["total_size"]] = edit["payload"]
    result = bytes(result)
    if ZoneBody.parse(result).assets != parsed.assets:
        raise AssertionError("image resize changed the XAsset table")
    return result, dict(schema="replay120-resident-image-resize-v1", edits=receipts,
        source_body_sha256=expected_body_sha256, output_body_sha256=_sha(result),
        trace_sha256=trace_hash, full_native_trace_events=event_count,
        physical_extent_delta=len(result) - len(body_data), persistent_stream_offsets_unchanged=True,
        stream_reservation_sizes=new_offsets,
        stream_reservation_deltas=[new - old for old, new in zip(offsets, new_offsets)],
        publication_ready=False, remaining_gate="complete native archive reread and renderer test")
