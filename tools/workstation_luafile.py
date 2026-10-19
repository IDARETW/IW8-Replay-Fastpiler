"""Typed Replay LuaFile child spans and conservative native replacement.

The adapter consumes ACTS Replay stream traces and the decoded XFile body. It
does not infer ownership from LuaJIT chunk length alone: the root, inline name,
alignment, bytecode read, and XAsset boundary must all agree with the trace.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from bisect import bisect_right
import json
from pathlib import Path
import struct
from typing import Any

try:  # Support both `python tools/...` and `from tools...` imports.
    from workstation_fastfiles import ZoneBody
    from workstation_luajit_chunk import split_luajit_file_payload
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_luajit_chunk import split_luajit_file_payload


LUA_FILE_TYPE_ID = 62
LUA_FILE_ROOT_SIZE = 24
INLINE_POINTER = 0xFFFFFFFFFFFFFFFE


def luafile_compiler_input_name(asset_name: str) -> str:
    """Produce a deterministic single-component temporary compiler filename."""
    if not isinstance(asset_name, str) or not asset_name or "\x00" in asset_name:
        raise ValueError("LuaFile compiler input requires a nonempty native asset name")
    return "lua_" + hashlib.sha256(asset_name.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class LuaFileLayout:
    asset_index: int
    asset_name: str
    root_archive_offset: int
    root_stream: int
    root_stream_offset: int
    name_archive_offset: int
    name_bytes: int
    bytecode_archive_offset: int
    bytecode_stream: int
    bytecode_stream_offset: int
    bytecode_bytes: int
    stripping_type: int
    root_padding: bytes
    source_body_sha256: str
    bytecode_sha256: str


def _one(items: list[dict], what: str) -> dict:
    if len(items) != 1:
        raise ValueError(f"LuaFile trace requires exactly one {what}; found {len(items)}")
    return items[0]


def inspect_luafile(body_data: bytes, asset_index: int, asset_name: str,
                    trace_asset: dict, expected_body_sha256: str | None = None) -> tuple[LuaFileLayout, bytes]:
    """Validate one 24-byte LuaFile root and its exact inline children."""
    body = ZoneBody.parse(body_data)
    digest = body.source_sha256
    if expected_body_sha256 is not None and digest != expected_body_sha256:
        raise ValueError("LuaFile trace belongs to a different decoded source body")
    if not isinstance(asset_index, int) or not 0 <= asset_index < len(body.assets):
        raise ValueError("LuaFile asset index is outside the XAsset table")
    if body.assets[asset_index].type_id != LUA_FILE_TYPE_ID:
        raise ValueError("selected XAsset is not a LuaFile")
    if (trace_asset.get("xasset_index") != asset_index or
            trace_asset.get("type_id") != LUA_FILE_TYPE_ID or
            trace_asset.get("name") != asset_name):
        raise ValueError("native trace row does not match this LuaFile identity")
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("LuaFile trace row has no physical read spans")

    roots = [span for span in spans if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0 and span.get("size") == LUA_FILE_ROOT_SIZE]
    root_span = _one(roots, "24-byte root read")
    root_at = root_span.get("archive_offset")
    root_dest = root_span.get("destination_stream_location")
    if (not isinstance(root_at, int) or root_at < 0 or
            root_at + LUA_FILE_ROOT_SIZE > len(body_data) or
            not isinstance(root_dest, dict) or root_dest.get("stream") != 1):
        raise ValueError("LuaFile root span is outside the body or not the traced stream-1 root")
    name_token, bytecode_len, stripping_type, padding, buffer_token = struct.unpack_from(
        "<QiB3sQ", body_data, root_at)
    if name_token != INLINE_POINTER or buffer_token != INLINE_POINTER:
        raise ValueError("LuaFile is not the observed inline-name/inline-buffer form")
    if bytecode_len <= 5:
        raise ValueError("LuaFile bytecode is too short to contain a LuaJIT chunk")

    expected_name = asset_name.encode("utf-8") + b"\0"
    name_spans = [span for span in spans if span.get("origin") == "string_data" and
                  span.get("size") == len(expected_name) and
                  span.get("archive_offset") == root_at + LUA_FILE_ROOT_SIZE]
    name_span = _one(name_spans, "inline name string")
    name_at = name_span["archive_offset"]
    if body_data[name_at:name_at + len(expected_name)] != expected_name:
        raise ValueError("LuaFile inline name bytes differ from the native XAsset name")

    child_at = name_at + len(expected_name)
    children = [span for span in spans if span.get("origin") == "load_stream_call" and
                span.get("reader_start_arg") == 0 and span.get("size") == bytecode_len and
                span.get("archive_offset") == child_at]
    child_span = _one(children, "inline LuaJIT bytecode child")
    child_dest = child_span.get("destination_stream_location")
    if not isinstance(child_dest, dict) or child_dest.get("stream") != 5:
        raise ValueError("LuaFile bytecode is not the traced stream-5 child")
    if child_dest.get("offset", -1) & 0xF:
        raise ValueError("LuaFile stream-5 child is not 16-byte aligned")
    bytecode = body_data[child_at:child_at + bytecode_len]
    if len(bytecode) != bytecode_len or not bytecode.endswith(b"\0"):
        raise ValueError("LuaFile bytecode extent or native terminal byte is invalid")
    split_luajit_file_payload(bytecode)
    layout = LuaFileLayout(
        asset_index=asset_index, asset_name=asset_name,
        root_archive_offset=root_at, root_stream=root_dest["stream"],
        root_stream_offset=root_dest["offset"], name_archive_offset=name_at,
        name_bytes=len(expected_name), bytecode_archive_offset=child_at,
        bytecode_stream=child_dest["stream"], bytecode_stream_offset=child_dest["offset"],
        bytecode_bytes=bytecode_len, stripping_type=stripping_type,
        root_padding=padding, source_body_sha256=digest,
        bytecode_sha256=hashlib.sha256(bytecode).hexdigest())
    return layout, bytecode


def replace_luafile_same_extent(body_data: bytes, asset_index: int, asset_name: str,
                                trace_asset: dict, replacement: bytes,
                                expected_body_sha256: str | None = None) -> tuple[bytes, dict]:
    """Replace a LuaFile buffer only when its native serialized extent is unchanged."""
    layout, original = inspect_luafile(body_data, asset_index, asset_name,
                                       trace_asset, expected_body_sha256)
    if not isinstance(replacement, bytes) or not replacement.endswith(b"\0"):
        raise ValueError("replacement LuaFile payload must include the native NUL terminator")
    split_luajit_file_payload(replacement)
    if len(replacement) != layout.bytecode_bytes:
        raise ValueError("LuaFile replacement changes its stream-5 extent; relocation proof is required")
    updated = bytearray(body_data)
    updated[layout.bytecode_archive_offset:
            layout.bytecode_archive_offset + layout.bytecode_bytes] = replacement
    updated_body = bytes(updated)
    reparsed = ZoneBody.parse(updated_body)
    if reparsed.assets != ZoneBody.parse(body_data).assets or len(updated_body) != len(body_data):
        raise AssertionError("same-extent LuaFile replacement changed the XAsset table or body size")
    return updated_body, dict(
        schema=1, status="same-extent-luafile-replacement-ready",
        asset_index=asset_index, asset_name=asset_name,
        source_body_sha256=layout.source_body_sha256,
        output_body_sha256=hashlib.sha256(updated_body).hexdigest(),
        root_archive_offset=layout.root_archive_offset,
        root_stream_location=dict(stream=layout.root_stream, offset=layout.root_stream_offset),
        name_archive_offset=layout.name_archive_offset,
        bytecode_archive_offset=layout.bytecode_archive_offset,
        bytecode_stream_location=dict(stream=layout.bytecode_stream,
                                     offset=layout.bytecode_stream_offset),
        bytecode_bytes=len(replacement), stripping_type=layout.stripping_type,
        root_padding_hex=layout.root_padding.hex(),
        old_bytecode_sha256=layout.bytecode_sha256,
        new_bytecode_sha256=hashlib.sha256(replacement).hexdigest(),
        body_extent_unchanged=True, xasset_table_unchanged=True)


def _grow_stream5_with_trace(body_data: bytes,
                             layouts: dict[int, LuaFileLayout],
                             replacements: dict[int, bytes],
                             trace_path: str | Path,
                             manifest_path: str | Path) -> tuple[bytes, dict]:
    """Relocate stream-5 aliases once for a batch of inline LuaFile edits.

    The complete native trace is replayed to calculate alignment-aware new
    stream-5 destinations. Every packed pointer whose target moves is mapped
    back to its original serialized field and patched. Ambiguous allocations,
    unknown pointer tags, pointers into the replaced bytecode, or incomplete
    traces fail closed.
    """
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_events = manifest.get("stream_trace_events")
    if (manifest.get("profile") != "replay-1.20" or
            manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            not isinstance(expected_events, int) or
            manifest.get("tested") != manifest.get("top_level_index") or
            manifest.get("serialized_bytes_read") != len(body_data)):
        raise ValueError("LuaFile growth requires a complete native full-zone trace")

    changed_layouts = {index: layout for index, layout in layouts.items()
                       if replacements[index] != body_data[
                           layout.bytecode_archive_offset:
                           layout.bytecode_archive_offset + layout.bytecode_bytes]}
    if not changed_layouts:
        return body_data, dict(status="semantic-noop-luafile-batch",
                               source_body_sha256=hashlib.sha256(body_data).hexdigest(),
                               output_body_sha256=hashlib.sha256(body_data).hexdigest(),
                               edits=[], packed_stream5_aliases_rebased=0,
                               stream_reservation_sizes=None)
    changed_ranges = {
        index: (layout.bytecode_stream_offset,
                layout.bytecode_stream_offset + layout.bytecode_bytes)
        for index, layout in changed_layouts.items()
    }
    child_deltas = {index: len(replacements[index]) - layout.bytecode_bytes
                    for index, layout in changed_layouts.items()}
    stream_deltas: dict[int, int] = {}
    original_cursors: dict[int, int] = {}
    max_new_destination: dict[int, int] = {}
    max_old_destination: dict[int, int] = {}
    asset_bases: dict[int, int] = {}
    original_asset_bases: dict[int, int] = {}
    intervals: list[dict] = []
    aliases: list[dict] = []
    pending_call: dict | None = None
    active_asset: int | None = None
    changed_children_seen: set[int] = set()
    validated_absolute_aliases = 0
    validated_asset_relative_aliases = 0
    event_count = 0

    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            seq = event.get("sequence")
            if seq != event_count:
                raise ValueError(f"LuaFile growth trace sequence breaks at {event_count}")
            event_count += 1
            kind = event.get("kind")
            if kind == "xasset_begin":
                active_asset = event.get("xasset_index")
            elif kind == "begin_asset_call":
                owner = event.get("xasset_index")
                if isinstance(owner, int):
                    original_base = original_cursors.get(5)
                    if not isinstance(original_base, int):
                        raise ValueError(
                            f"LuaFile relocation has no stream-5 cursor at asset {owner} entry")
                    asset_bases[owner] = original_base + stream_deltas.get(5, 0)
                    original_asset_bases[owner] = original_base
            elif kind == "xasset_end":
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
                        target_block, target_offset = target["stream"], target.get("offset")
                    elif raw >> 32 == 5:
                        target_block, target_offset = 5, (raw & 0xFFFFFFFF) - 1
                    else:
                        target_block, target_offset = None, None
                    if target_block == 5:
                        if not isinstance(target_offset, int) or target_offset < 0:
                            raise ValueError("stream-5 packed alias has an invalid target offset")
                        aliases.append(dict(kind=kind, owner=event.get("xasset_index"), raw=raw,
                                            field=field, target=target_offset,
                                            sequence=seq))

            if kind != "stream_operation":
                if pending_call and seq > pending_call.get("sequence", seq) + 1:
                    pending_call = None
                continue

            operation = event.get("operation")
            before_block = event.get("block_before")
            after_block = event.get("block_after")
            before_offset = event.get("offset_before")
            after_offset = event.get("offset_after")
            if not all(isinstance(value, int) for value in
                       (before_block, after_block, before_offset, after_offset)):
                pending_call = None
                continue
            original_cursors[after_block] = after_offset
            if before_block > 0:
                max_old_destination[before_block] = max(
                    max_old_destination.get(before_block, 0), before_offset)
            if after_block > 0:
                max_old_destination[after_block] = max(
                    max_old_destination.get(after_block, 0), after_offset)
            new_before = before_offset + stream_deltas.get(before_block, 0)

            if operation in ("load", "take"):
                size = event.get("size")
                physical = event.get("physical_input_bytes")
                if not isinstance(size, int) or not isinstance(physical, int):
                    raise ValueError("stream read lacks size/physical-byte accounting")
                # Block 0 is the serialized input cursor, not an allocated
                # destination stream; its offset remains zero while input
                # advances through the XAssetList preamble.
                if before_block == 0:
                    pending_call = None
                    continue
                old_advance = after_offset - before_offset
                if before_block == after_block and old_advance != size:
                    raise ValueError(
                        f"stream read event {seq} size {size} differs from logical cursor "
                        f"advance {old_advance} in block {before_block} "
                        f"({before_offset:#x}->{after_offset:#x})")
                new_after = (new_before + old_advance if before_block == after_block
                             else after_offset + stream_deltas.get(after_block, 0))
                # The target read is identified by its archive cursor and
                # destination, both of which are captured for every body load.
                matched_edit = next((index for index, (old_start, _old_end)
                                     in changed_ranges.items()
                                     if active_asset == index and before_block == 5 and
                                     before_offset == old_start and
                                     physical == layouts[index].bytecode_bytes), None)
                if operation == "load" and matched_edit is not None and \
                        matched_edit not in changed_children_seen:
                    if pending_call is None or pending_call.get("loader_start_arg") != 0:
                        raise ValueError("LuaFile bytecode growth is not bound to its native AtStart call")
                    new_after = new_before + len(replacements[matched_edit])
                    changed_children_seen.add(matched_edit)
                if physical and before_block == after_block:
                    destination = (pending_call.get("destination_stream_location")
                                   if pending_call and
                                   pending_call.get("sequence") == seq - 1 and
                                   pending_call.get("at_start") else
                                   {"stream": before_block, "offset": before_offset})
                    if (not isinstance(destination, dict) or
                            destination.get("stream") != before_block or
                            destination.get("offset") != before_offset):
                        raise ValueError("physical allocation is not at the traced stream cursor")
                    intervals.append(dict(owner=event.get("xasset_index"),
                                          stream=before_block, old_start=before_offset,
                                          old_end=before_offset + size, new_start=new_before,
                                          archive_start=event.get("input_before"), size=size,
                                          sequence=seq))
                stream_deltas[after_block] = new_after - after_offset
                pending_call = None
            elif operation == "align":
                mask = event.get("value")
                if not isinstance(mask, int) or mask < 0:
                    raise ValueError("stream alignment call has an invalid mask")
                aligned = (new_before + mask) & ~mask
                if before_block == after_block:
                    new_after = aligned
                else:
                    new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                pending_call = None
            elif operation == "push":
                new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                pending_call = None
            elif operation == "pop":
                new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                pending_call = None
            else:
                new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
                pending_call = None

            # Capture destination reservations for every stream, including
            # zero-byte transitions and stream-4 calculated allocations.
            if before_block > 0:
                max_new_destination[before_block] = max(
                    max_new_destination.get(before_block, 0), new_before)
            if after_block > 0:
                max_new_destination[after_block] = max(
                    max_new_destination.get(after_block, 0), new_after)

    if event_count != expected_events or changed_children_seen != set(changed_layouts):
        raise ValueError("complete native trace did not include the target LuaFile child")

    stream5_intervals = sorted((item for item in intervals if item["stream"] == 5),
                               key=lambda item: item["old_start"])
    stream5_starts = [item["old_start"] for item in stream5_intervals]
    if any(left["old_end"] > right["old_start"]
           for left, right in zip(stream5_intervals, stream5_intervals[1:])):
        raise ValueError("native trace contains overlapping stream-5 physical allocations")

    def map_stream5_target(offset: int) -> int:
        if any(start <= offset < end for start, end in changed_ranges.values()):
            raise ValueError("packed pointer targets bytes replaced by a LuaFile edit")
        at = bisect_right(stream5_starts, offset) - 1
        if at < 0 or offset >= stream5_intervals[at]["old_end"]:
            raise ValueError(f"stream-5 target {offset:#x} has no owning allocation")
        allocation = stream5_intervals[at]
        return allocation["new_start"] + offset - allocation["old_start"]

    def map_field_location(owner: int | None, field: dict) -> int:
        block, offset = field.get("stream"), field.get("offset")
        if not isinstance(owner, int) or not isinstance(block, int) or not isinstance(offset, int):
            raise ValueError("packed alias does not identify a physical owner field")
        matches = [item for item in intervals
                   if item["owner"] == owner and item["stream"] == block and
                   item["old_start"] <= offset and offset + 8 <= item["old_end"]]
        if len(matches) != 1:
            raise ValueError(f"packed alias field {owner}:{block}:{offset:#x} has {len(matches)} owners")
        allocation = matches[0]
        # Alias patches are applied to the original-sized buffer before the
        # child splice; bytes after the child then move with the splice.
        return allocation["archive_start"] + offset - allocation["old_start"]

    changed = bytearray(body_data)
    patch_fields: set[tuple[int, int, int]] = set()
    patched_alias_count = 0
    for alias in aliases:
        old_target = alias["target"]
        raw = alias["raw"]
        token_tag = raw >> 32
        owner = alias["owner"]
        if token_tag == 0x15:
            old_base = original_asset_bases.get(owner)
            if old_base is None or old_target != old_base + (raw & 0xFFFFFFFF) - 1:
                raise ValueError(
                    f"tag-0x15 packed pointer does not match asset-local base for owner {owner}")
            validated_asset_relative_aliases += 1
        elif token_tag == 5:
            if old_target != (raw & 0xFFFFFFFF) - 1:
                raise ValueError("tag-5 packed pointer does not match its absolute block-5 target")
            validated_absolute_aliases += 1
        else:
            raise ValueError(f"unsupported packed stream-5 token tag {token_tag:#x}")
        new_target = map_stream5_target(old_target)
        if token_tag == 5:
            new_low = new_target + 1
        else:
            new_base = asset_bases.get(owner)
            if new_base is None:
                raise ValueError(f"tag-0x15 owner {owner} has no simulated block-5 base")
            new_low = new_target - new_base + 1
        if not 0 < new_low <= 0xFFFFFFFF:
            raise ValueError("relocated packed pointer does not fit its 32-bit offset field")
        if new_low == (raw & 0xFFFFFFFF):
            continue
        archive_field = map_field_location(alias["owner"], alias["field"])
        if archive_field + 8 > len(changed) or struct.unpack_from("<Q", changed, archive_field)[0] != raw:
            raise ValueError("packed alias source field bytes differ from native trace token")
        key = (alias["owner"], alias["field"]["stream"], alias["field"]["offset"])
        if key in patch_fields:
            raise ValueError("trace reports the same packed field more than once")
        patch_fields.add(key)
        relocated = (raw & 0xFFFFFFFF00000000) | new_low
        struct.pack_into("<Q", changed, archive_field, relocated)
        patched_alias_count += 1

    for index, layout in changed_layouts.items():
        struct.pack_into("<i", changed, layout.root_archive_offset + 8,
                         len(replacements[index]))
    # Splice children from highest archive offset down so all earlier source
    # offsets remain valid. Root length fields are already patched and move
    # with the serialized bytes if they follow a later asset's allocation.
    for index, layout in sorted(changed_layouts.items(),
                                key=lambda item: item[1].bytecode_archive_offset,
                                reverse=True):
        start = layout.bytecode_archive_offset
        end = start + layout.bytecode_bytes
        changed[start:end] = replacements[index]
    result = bytes(changed)
    if ZoneBody.parse(result).assets != ZoneBody.parse(body_data).assets:
        raise AssertionError("LuaFile growth changed the XAsset table")
    edits = [dict(asset_index=index, asset_name=layouts[index].asset_name,
                  root_archive_offset=layouts[index].root_archive_offset,
                  bytecode_archive_offset=layouts[index].bytecode_archive_offset,
                  old_bytecode_bytes=layouts[index].bytecode_bytes,
                  new_bytecode_bytes=len(replacements[index]),
                  physical_extent_delta=child_deltas[index],
                  old_bytecode_sha256=layouts[index].bytecode_sha256,
                  new_bytecode_sha256=hashlib.sha256(replacements[index]).hexdigest())
             for index in sorted(changed_layouts)]
    return result, dict(
        status="trace-relocated-luafile-batch-ready",
        edits=edits,
        physical_extent_delta=sum(child_deltas.values()),
        stream5_old_high_water=max_old_destination.get(5, 0),
        stream5_new_high_water=max_new_destination.get(5),
        stream5_extent_delta=(max_new_destination.get(5, 0) -
                              max_old_destination.get(5, 0)),
        stream_reservation_sizes=[max_new_destination.get(index, 0)
                                  for index in range(11)],
        stream_reservation_deltas=[max_new_destination.get(index, 0) -
                                  max_old_destination.get(index, 0)
                                  for index in range(11)],
        packed_stream5_aliases_scanned=len(aliases),
        packed_stream5_tag5_absolute_validated=validated_absolute_aliases,
        packed_stream5_tag15_asset_relative_validated=validated_asset_relative_aliases,
        packed_stream5_aliases_rebased=patched_alias_count,
        xasset_table_unchanged=True,
        full_native_trace_events=event_count)


def replace_luafile_inline_child(body_data: bytes, asset_index: int, asset_name: str,
                                 trace_asset: dict, replacement: bytes,
                                 expected_body_sha256: str,
                                 trace_path: str | Path | None = None,
                                 trace_manifest_path: str | Path | None = None) -> tuple[bytes, dict]:
    """Single-edit wrapper around :func:`replace_luafiles_inline_children`."""
    return replace_luafiles_inline_children(
        body_data,
        [dict(asset_index=asset_index, asset_name=asset_name,
              trace_asset=trace_asset, payload=replacement)],
        expected_body_sha256, trace_path, trace_manifest_path)


def replace_luafiles_inline_children(
        body_data: bytes, edits: list[dict], expected_body_sha256: str,
        trace_path: str | Path | None = None,
        trace_manifest_path: str | Path | None = None) -> tuple[bytes, dict]:
    """Apply one transaction of LuaFile edits against one original zone trace.

    Every edit is validated against the same source body and trace. A single
    stream simulation accounts for all changed children, downstream alignment,
    tag-5 aliases, and tag-0x15 asset-relative aliases. ScriptFile/LuaFile
    mixed edits remain unsupported because their independent stream-5/6
    relocation maps are not yet combined in one transaction.
    """
    if not isinstance(expected_body_sha256, str):
        raise ValueError("LuaFile batch requires the expected original body SHA-256")
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("LuaFile trace belongs to a different decoded source body")
    if not isinstance(edits, list) or not edits:
        raise ValueError("LuaFile batch must contain at least one edit")

    layouts: dict[int, LuaFileLayout] = {}
    replacements: dict[int, bytes] = {}
    for edit in edits:
        if not isinstance(edit, dict):
            raise TypeError("each LuaFile batch edit must be a mapping")
        if edit.get("type_id") not in (None, LUA_FILE_TYPE_ID):
            if edit.get("type_id") == 52:
                raise ValueError(
                    "mixed ScriptFile/LuaFile batches are unsupported: a unified stream-5/stream-6 "
                    "relocation schedule is not implemented")
            raise ValueError("LuaFile batch contains an edit for a different XAsset type")
        index = edit.get("asset_index")
        name = edit.get("asset_name", edit.get("name"))
        trace_asset = edit.get("trace_asset")
        payload = edit.get("payload", edit.get("replacement"))
        if not isinstance(index, int) or index in layouts:
            raise ValueError("LuaFile batch indices must be unique integers")
        if not 0 <= index < len(body.assets):
            raise ValueError("LuaFile batch index is outside the source XAsset table")
        if body.assets[index].type_id == 52:
            raise ValueError(
                "mixed ScriptFile/LuaFile batches are unsupported: a unified stream-5/stream-6 "
                "relocation schedule is not implemented")
        if body.assets[index].type_id != LUA_FILE_TYPE_ID:
            raise ValueError("LuaFile batch contains an edit for a different XAsset type")
        if not isinstance(name, str) or not isinstance(trace_asset, dict):
            raise ValueError("LuaFile edit lacks its exact name or native trace row")
        if not isinstance(payload, bytes) or not payload.endswith(b"\0"):
            raise ValueError("replacement LuaFile payload must include the native NUL terminator")
        if len(payload) < 7 or len(payload) > 0x7FFFFFFF:
            raise ValueError("replacement LuaFile bytecode length is outside the native signed range")
        split_luajit_file_payload(payload)
        layout, _original = inspect_luafile(
            body_data, index, name, trace_asset, expected_body_sha256)
        layouts[index] = layout
        replacements[index] = payload

    changed = {index: layout for index, layout in layouts.items()
               if replacements[index] != body_data[
                   layout.bytecode_archive_offset:
                   layout.bytecode_archive_offset + layout.bytecode_bytes]}
    if not changed:
        proof = dict(schema=1, status="semantic-noop-luafile-batch",
                     source_body_sha256=expected_body_sha256,
                     output_body_sha256=expected_body_sha256,
                     body_extent_unchanged=True, xasset_table_unchanged=True,
                     edits=[], mixed_scriptfile_edits_supported=False)
        return body_data, proof

    extent_changed = any(len(replacements[index]) != layout.bytecode_bytes
                         for index, layout in changed.items())
    if extent_changed and (trace_path is None or trace_manifest_path is None):
        raise ValueError("LuaFile growth/shrink batch requires a complete native stream trace")

    if extent_changed:
        updated, relocation = _grow_stream5_with_trace(
            body_data, layouts, replacements, trace_path, trace_manifest_path)
    else:
        updated_buffer = bytearray(body_data)
        for index, layout in changed.items():
            start = layout.bytecode_archive_offset
            updated_buffer[start:start + layout.bytecode_bytes] = replacements[index]
        updated = bytes(updated_buffer)
        relocation = dict(
            status="same-extent-luafile-batch-ready",
            edits=[dict(asset_index=index, asset_name=layouts[index].asset_name,
                        root_archive_offset=layouts[index].root_archive_offset,
                        bytecode_archive_offset=layouts[index].bytecode_archive_offset,
                        old_bytecode_bytes=layouts[index].bytecode_bytes,
                        new_bytecode_bytes=len(replacements[index]),
                        physical_extent_delta=0,
                        old_bytecode_sha256=layouts[index].bytecode_sha256,
                        new_bytecode_sha256=hashlib.sha256(replacements[index]).hexdigest())
                   for index in sorted(changed)],
            stream_reservation_sizes=None, stream_reservation_deltas=None,
            packed_stream5_aliases_rebased=0)

    proof = dict(schema=1, source_body_sha256=expected_body_sha256,
                 output_body_sha256=hashlib.sha256(updated).hexdigest(),
                 body_extent_unchanged=len(updated) == len(body_data),
                 mixed_scriptfile_edits_supported=False,
                 mixed_edit_restriction=("ScriptFile and LuaFile relocation maps have not been combined; "
                                         "submit those types in separate source-body transactions"),
                 **relocation)
    return updated, proof
