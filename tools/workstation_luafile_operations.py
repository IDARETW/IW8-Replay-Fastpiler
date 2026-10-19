"""Conservative append/remove operations for Replay LuaFile XAssets.

Only fully traced zones can be edited. Appends are placed after the proven
final serialized asset. A previously appended row can be removed only while it
is still final; an existing row can be removed only when its inline extents are
uniquely owned and every inbound packed reference can be safely rejected or
rebased. Ambiguous/shared ownership fails closed.
"""
from __future__ import annotations

import hashlib
import json
from bisect import bisect_right
from pathlib import Path
import struct

try:
    from workstation_fastfiles import ZoneBody
    from workstation_luafile import (INLINE_POINTER, LUA_FILE_ROOT_SIZE,
                                     inspect_luafile)
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_luafile import (INLINE_POINTER, LUA_FILE_ROOT_SIZE,
                                           inspect_luafile)


LUA_FILE_TYPE_ID = 62
XASSET_ROW_SIZE = 16
XASSET_LIST_ROOT_SIZE = 32
XASSET_ARRAY_COUNT_OFFSET = 16


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(trace_path: str | Path, manifest_path: str | Path, body: bytes) -> dict:
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("profile") != "replay-1.20" or
            manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("tested") != manifest.get("top_level_index") or
            manifest.get("serialized_bytes_read") != len(body) or
            not isinstance(manifest.get("stream_trace_events"), int)):
        raise ValueError("LuaFile row operation requires a complete native full-zone trace")
    trace_sha256 = manifest.get("stream_trace_sha256")
    if (not isinstance(trace_sha256, str) or len(trace_sha256) != 64 or
            _sha(trace_path.read_bytes()) != trace_sha256):
        raise ValueError("LuaFile row operation trace does not match its native manifest hash")
    return manifest


def _trace_contract(body: bytes, trace_path: str | Path, manifest_path: str | Path,
                    removed_stream_ranges: tuple[tuple[int, int, int], ...] = (),
                    logical_delete_ranges: tuple[tuple[int, int, int], ...] = (),
                    removed_owner: int | None = None,
                    table_row_delta: int = 0,
                    schedule_asset_index: int | None = None):
    """Replay cursors and retain physical ownership needed to rebase aliases."""
    manifest = _manifest(trace_path, manifest_path, body)
    expected = manifest["stream_trace_events"]
    cursors: dict[int, int] = {}
    stream_deltas: dict[int, int] = {}
    asset_bases: dict[int, int] = {}
    relocated_asset_bases: dict[int, int] = {}
    intervals: list[dict] = []
    logical_segments: list[tuple[int, int, int, int]] = []
    # Some native pointer slots are reserved by DB_InsertPointer without a
    # corresponding serialized load. Keep only gaps proved by consecutive
    # stream snapshots, along with their replayed coordinates and sequence.
    logical_gaps: list[tuple[int, int, int, int, int, int]] = []
    logical_cursors: dict[int, tuple[int, int, int, str, int | None]] = {}
    aliases: list[dict] = []
    string_refs: list[dict] = []
    table_allocations: list[dict] = []
    max_destinations: dict[int, int] = {}
    # Retain relocated coordinates independently from source destinations.
    # Table growth can change downstream alignment, so append placement must
    # use the replayed cursor rather than a guessed constant delta.
    relocated_stream_max_destinations: dict[int, int] = {}
    relocated_terminal_cursors: dict[int, int] = {}
    table_logical_end: int | None = None
    alias_events_seen = 0
    packed_pointer_classes: dict[str, int] = {}
    packed_pointer_targets_validated = 0
    target_coordinate_fallbacks: list[dict] = []
    pending_string_call: dict | None = None
    selected_asset_stream_schedule: list[dict] = []
    parsed_body = ZoneBody.parse(body)
    asset_table_offset = parsed_body.asset_table_offset
    count = 0
    with Path(trace_path).open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("sequence") != count:
                raise ValueError(f"native trace sequence breaks at event {count}")
            count += 1
            kind = event.get("kind")
            if kind == "begin_asset_call":
                owner = event.get("xasset_index")
                if isinstance(owner, int) and 5 in cursors:
                    asset_bases.setdefault(owner, cursors[5])
                    relocated_asset_bases.setdefault(owner,
                        cursors[5] + stream_deltas.get(5, 0))
            elif kind == "string_call":
                pending_string_call = event
            elif kind in ("packed_alias", "packed_resolve"):
                raw, field, target = (event.get("raw_token"),
                                      event.get("field_stream_location"),
                                      event.get("resolved_target_stream_location"))
                if isinstance(raw, int) and isinstance(field, dict):
                    alias_events_seen += 1
                    owner = event.get("xasset_index")
                    tag = raw >> 32
                    # Some native alias callbacks expose the field but omit the
                    # resolved target. For the verified packed formats the
                    # target is encoded unambiguously: tag 5 is absolute, and
                    # tag 0x15 is relative to the asset base captured at entry.
                    # Retain these rows so a table splice cannot leave a stale
                    # absolute pointer. Unknown/malformed classes fail closed.
                    if not isinstance(target, dict):
                        low = raw & 0xFFFFFFFF
                        if low == 0:
                            raise ValueError("packed pointer has an invalid zero offset")
                        if tag == 5:
                            target = {"stream": 5, "offset": low - 1}
                        elif tag == 0x15 and isinstance(owner, int) and owner in asset_bases:
                            target = {"stream": 5, "offset": asset_bases[owner] + low - 1}
                        else:
                            raise ValueError(f"unresolved packed pointer class {tag:#x} has no safe target")
                    target_stream, target_offset = target.get("stream"), target.get("offset")
                    packed_class = f"{tag:08x}"
                    packed_pointer_classes[packed_class] = packed_pointer_classes.get(packed_class, 0) + 1
                    if tag == 5:
                        if target_stream != 5 or (raw & 0xFFFFFFFF) - 1 != target_offset:
                            raise ValueError("traced tag-5 pointer disagrees with its absolute stream target")
                    elif tag == 0x15:
                        owner_base_for_check = asset_bases.get(owner) if isinstance(owner, int) else None
                        if (owner_base_for_check is None or target_stream != 5 or
                                target_offset != owner_base_for_check + (raw & 0xFFFFFFFF) - 1):
                            raise ValueError("traced tag-0x15 pointer disagrees with its asset-relative target")
                    else:
                        raise ValueError(f"unsupported packed pointer class {tag:#x} in native trace")
                    packed_pointer_targets_validated += 1
                    is_removed_target = (isinstance(target_stream, int) and
                        isinstance(target_offset, int) and any(
                            stream_id == target_stream and start <= target_offset < end
                            for stream_id, start, end in removed_stream_ranges))
                    if is_removed_target and owner == removed_owner:
                        continue
                    needs_absolute_rebase = (tag == 5 and target_stream == 5 and
                        isinstance(target_offset, int) and
                        ((table_row_delta != 0) or
                         (table_logical_end is not None and target_offset >= table_logical_end)))
                    table_start = table_allocations[0]["start"] if table_allocations else None
                    removed_table_start = (table_start + removed_owner * XASSET_ROW_SIZE
                                           if isinstance(table_start, int) and
                                           isinstance(removed_owner, int) else None)
                    needs_table_row_rebase = (
                        isinstance(removed_table_start, int) and
                        target_stream == 5 and isinstance(target_offset, int) and
                        target_offset >= removed_table_start + XASSET_ROW_SIZE and
                        table_start <= target_offset < table_logical_end)
                    owner_base = asset_bases.get(owner) if isinstance(owner, int) else None
                    target_shift = _coordinate_shift(target_stream, target_offset,
                        table_logical_end, table_row_delta, False, logical_delete_ranges)
                    base_shift = (_coordinate_shift(5, owner_base, table_logical_end,
                        table_row_delta, False, logical_delete_ranges) if owner_base is not None else 0)
                    needs_relative_rebase = (tag == 0x15 and target_stream == 5 and
                        (table_row_delta != 0 or owner_base is None or target_shift != base_shift))
                    if (is_removed_target or needs_absolute_rebase or needs_relative_rebase or
                            needs_table_row_rebase):
                        aliases.append((event.get("xasset_index"), raw, field.get("stream"),
                                        field.get("offset"), target_stream, target_offset,
                                        event["sequence"]))
            if kind != "stream_operation":
                continue
            operation = event.get("operation")
            before_block, before_offset = event.get("block_before"), event.get("offset_before")
            after_block, after_offset = event.get("block_after"), event.get("offset_after")
            if operation == "string":
                if pending_string_call is not None:
                    field = pending_string_call.get("field_stream_location")
                    if not isinstance(field, dict):
                        raise ValueError("XString call lacks a typed field location")
                    string_refs.append(dict(
                        owner=pending_string_call.get("xasset_index"),
                        field_stream=field.get("stream"), field_offset=field.get("offset"),
                        target_stream=before_block, target_offset=before_offset,
                        size=event.get("size"), sequence=pending_string_call.get("sequence")))
                pending_string_call = None
            elif pending_string_call is not None and event.get("sequence", 0) > pending_string_call.get("sequence", 0) + 1:
                # A string call must pair with its immediate native string operation.
                pending_string_call = None
            if not all(isinstance(x, int) for x in
                       (before_block, before_offset, after_block, after_offset)):
                raise ValueError(f"stream operation {event.get('sequence')} lacks coordinates")
            old_advance = (after_offset - before_offset
                           if before_block == after_block else 0)
            new_before = before_offset + stream_deltas.get(before_block, 0)
            owner = event.get("xasset_index")
            is_deleted_operation = removed_owner is not None and owner == removed_owner
            new_after = after_offset + stream_deltas.get(after_block, 0)
            previous_cursor = logical_cursors.get(before_block)
            if previous_cursor is not None:
                (old_cursor, relocated_cursor, _previous_sequence,
                 previous_operation, previous_alignment_mask) = previous_cursor
                if before_offset > old_cursor:
                    if (before_block == 5 and previous_operation == "align" and
                            previous_alignment_mask == 7 and operation == "pop" and
                            before_offset - old_cursor == 8):
                        logical_gaps.append((before_block, old_cursor, before_offset,
                                             relocated_cursor, new_before,
                                             event["sequence"]))
                    else:
                        # Preserve the evidence so an alias into this region
                        # cannot silently fall back to a guessed table delta.
                        logical_gaps.append((before_block, old_cursor, before_offset,
                                             relocated_cursor, new_before,
                                             -event["sequence"]))
            if operation in ("load", "take"):
                new_advance = old_advance
                if is_deleted_operation:
                    new_advance = 0
                elif (removed_owner is not None and owner is None and before_block == after_block == 5
                      and event.get("input_before") == asset_table_offset):
                    if old_advance != len(parsed_body.assets) * XASSET_ROW_SIZE:
                        raise ValueError("native XAsset table allocation has an unexpected stride")
                    row_start = before_offset + removed_owner * XASSET_ROW_SIZE
                    table_end = after_offset
                    # Record exact table-row mappings; references to the removed
                    # row are rejected later, while later rows move one stride.
                    if row_start > before_offset:
                        logical_segments.append((5, before_offset, row_start,
                                                 new_before))
                    if row_start + XASSET_ROW_SIZE < table_end:
                        logical_segments.append((5, row_start + XASSET_ROW_SIZE,
                            table_end, new_before + row_start + XASSET_ROW_SIZE - before_offset
                            - XASSET_ROW_SIZE))
                    new_advance -= XASSET_ROW_SIZE
                elif (table_row_delta and owner is None and before_block == after_block == 5
                      and event.get("input_before") == asset_table_offset):
                    if old_advance != len(parsed_body.assets) * XASSET_ROW_SIZE:
                        raise ValueError("native XAsset table allocation has an unexpected stride")
                    if table_row_delta % XASSET_ROW_SIZE:
                        raise ValueError("XAsset table delta is not a whole native row")
                    # Existing rows retain their logical coordinates. The added
                    # rows extend the table at its end; downstream align events
                    # are replayed from this enlarged stream-5 cursor.
                    logical_segments.append((5, before_offset, after_offset, new_before))
                    new_advance += table_row_delta
                if before_block == after_block:
                    new_after = new_before + new_advance
                if (before_block == after_block == 5 and old_advance > 0 and
                        new_advance == old_advance and not is_deleted_operation):
                    logical_segments.append((5, before_offset, after_offset, new_before))
            elif operation == "string":
                # String allocations are real block-5 address ranges even
                # though they are not Load_Stream reads. Their exact intervals
                # must participate in alias relocation; mapping them through a
                # neighboring typed load can shift a string pointer by the
                # wrong alignment padding.
                new_advance = 0 if is_deleted_operation else old_advance
                if before_block == after_block:
                    new_after = new_before + new_advance
                if (before_block == after_block == 5 and old_advance > 0 and
                        not is_deleted_operation):
                    logical_segments.append((5, before_offset, after_offset, new_before))
            elif operation == "align":
                mask = event.get("value")
                if not isinstance(mask, int) or mask < 0:
                    raise ValueError("native alignment operation has an invalid mask")
                if before_block == after_block:
                    new_after = (new_before if is_deleted_operation else
                                 (new_before + mask) & ~mask)
            elif operation == "push":
                new_after = after_offset + stream_deltas.get(after_block, 0)
            elif operation == "pop":
                new_after = after_offset + stream_deltas.get(after_block, 0)
            else:
                new_after = after_offset + stream_deltas.get(after_block, 0)
            if all(isinstance(x, int) for x in (after_block, after_offset)):
                cursors[after_block] = after_offset
                max_destinations[after_block] = max(max_destinations.get(after_block, 0), after_offset)
                relocated_stream_max_destinations[after_block] = max(
                    relocated_stream_max_destinations.get(after_block, 0), new_after)
                relocated_terminal_cursors[after_block] = new_after
            if isinstance(before_block, int) and isinstance(before_offset, int):
                max_destinations[before_block] = max(max_destinations.get(before_block, 0), before_offset)
                relocated_stream_max_destinations[before_block] = max(
                    relocated_stream_max_destinations.get(before_block, 0), new_before)
            if (schedule_asset_index is not None and
                    event.get("xasset_index") == schedule_asset_index and
                    kind == "stream_operation"):
                selected_asset_stream_schedule.append(dict(
                    operation=operation,
                    block_before=before_block, offset_before=before_offset,
                    block_after=after_block, offset_after=after_offset,
                    relocated_offset_before=new_before,
                    relocated_offset_after=new_after,
                    value=event.get("value"), size=event.get("size")))
            stream_deltas[after_block] = new_after - after_offset
            if before_block == after_block:
                logical_cursors[before_block] = (after_offset, new_after,
                    event["sequence"], operation,
                    event.get("value") if operation == "align" else None)
            else:
                logical_cursors[before_block] = (before_offset, new_before,
                    event["sequence"], operation,
                    event.get("value") if operation == "align" else None)
                logical_cursors[after_block] = (after_offset, new_after,
                    event["sequence"], operation,
                    event.get("value") if operation == "align" else None)
            if operation != "load" or event.get("physical_input_bytes", 0) <= 0:
                continue
            size = event.get("size")
            input_before = event.get("input_before")
            if not all(isinstance(x, int) for x in (before_block, before_offset, after_block,
                                                     after_offset, size, input_before)):
                raise ValueError(f"physical read {event.get('sequence')} lacks coordinates")
            if (before_block != after_block or after_offset - before_offset != size or
                    event.get("physical_input_bytes") != size):
                raise ValueError("LuaFile row operation encountered a non-inline physical allocation")
            owner = event.get("xasset_index")
            intervals.append(dict(owner=owner, stream=before_block,
                                  start=before_offset, end=before_offset + size,
                                  archive=input_before, size=size,
                                  sequence=event["sequence"]))
            # The XAsset pointer array is one block-5 allocation beginning at
            # the physical table start. Its logical end is the relocation pivot.
            if (owner is None and before_block == 5 and input_before == asset_table_offset):
                table_allocations.append(dict(start=before_offset, end=after_offset,
                                              size=size, archive=input_before))
                table_logical_end = after_offset
    if count != expected:
        raise ValueError("native trace event count differs from its full-zone manifest")
    if _sha(Path(trace_path).read_bytes()) != manifest["stream_trace_sha256"]:
        raise ValueError("native stream trace changed during LuaFile ownership analysis")
    if len(table_allocations) != 1:
        raise ValueError("native trace does not uniquely own the complete XAsset pointer array")
    interval_index = _build_interval_index(intervals)
    xstring_classes: dict[str, int] = {}
    xstring_relocated_fields: set[tuple] = set()

    grouped_segments: dict[int, list[tuple[int, int, int]]] = {}
    for stream_id, start, end, new_start in set(logical_segments):
        grouped_segments.setdefault(stream_id, []).append((start, end, new_start))
    segment_index = {}
    for stream_id, segments in grouped_segments.items():
        segments.sort(key=lambda value: (value[0], value[1]))
        prefix_max_end = []
        maximum = -1
        for _start, end, _new_start in segments:
            maximum = max(maximum, end)
            prefix_max_end.append(maximum)
        segment_index[stream_id] = ([value[0] for value in segments], segments, prefix_max_end)
    grouped_gaps: dict[int, list[tuple[int, int, int, int, int]]] = {}
    for gap_stream, start, end, new_start, new_end, gap_sequence in logical_gaps:
        grouped_gaps.setdefault(gap_stream, []).append(
            (start, end, new_start, new_end, gap_sequence))
    gap_index = {}
    for stream_id, gaps in grouped_gaps.items():
        gaps.sort(key=lambda value: (value[0], value[1], value[4]))
        prefix_max_end = []
        maximum = -1
        for _start, end, _new_start, _new_end, _sequence in gaps:
            maximum = max(maximum, end)
            prefix_max_end.append(maximum)
        gap_index[stream_id] = ([value[0] for value in gaps], gaps, prefix_max_end)
    mapped_cache: dict[tuple[int, int, int | None], int | None] = {}

    def map_retained_target(stream_id: int, offset: int,
                            sequence: int | None = None) -> int | None:
        key = (stream_id, offset, sequence)
        if key in mapped_cache:
            return mapped_cache[key]
        if (removed_owner is not None and stream_id == 5 and table_allocations):
            is_table, table_target = _map_deleted_xasset_table_target(
                offset, table_allocations[0]["start"], len(parsed_body.assets), removed_owner)
            if is_table:
                mapped_cache[key] = table_target
                return table_target
        group = segment_index.get(stream_id)
        matches = []
        if group is not None:
            starts, segments, prefix_max_end = group
            position = bisect_right(starts, offset) - 1
            cursor = position
            while cursor >= 0 and prefix_max_end[cursor] > offset:
                start, end, new_start = segments[cursor]
                if start <= offset < end:
                    matches.append(new_start + offset - start)
                cursor -= 1
        gap_matches = []
        gap_group = gap_index.get(stream_id)
        if gap_group is not None:
            gap_starts, gaps, gap_prefix_max_end = gap_group
            gap_position = bisect_right(gap_starts, offset) - 1
            gap_cursor = gap_position
            while gap_cursor >= 0 and gap_prefix_max_end[gap_cursor] > offset:
                start, end, new_start, new_end, gap_sequence = gaps[gap_cursor]
                gap_cursor -= 1
                if not start <= offset < end:
                    continue
                if gap_sequence < 0:
                    if sequence is None or sequence >= -gap_sequence:
                        raise ValueError("pointer target falls in an unproven native stream cursor gap")
                    continue
                if sequence is not None and sequence < gap_sequence:
                    continue
                relocated = new_start + (offset - start)
                # A zero-length replayed gap can still own its exact start token
                # (the aligned cursor absorbed the reserved slot); any later byte
                # in that source gap has no defensible destination.
                if relocated > new_end or (new_start == new_end and offset != start):
                    raise ValueError("native stream gap shrank across the pointer target")
                gap_matches.append(relocated)
        matches.extend(gap_matches)
        if not matches:
            mapped_cache[key] = None
            return None
        if len(set(matches)) != 1:
            raise ValueError("native trace maps a pointer target to ambiguous relocated coordinates")
        mapped_cache[key] = matches[0]
        return matches[0]

    relocated_targets = {}
    compatible_targets: dict[tuple[int, int, int], set[int]] = {}

    def record_relocated_target(key3, physical, target):
        key4 = (*key3, physical)
        prior = relocated_targets.get(key4)
        if prior is not None and prior != target:
            raise ValueError("one physical pointer field has conflicting native target mappings")
        relocated_targets[key4] = target
        compatible_targets.setdefault(key3, set()).add(target)

    for string_ref in string_refs:
        owner = string_ref["owner"]
        field_stream, field_offset = string_ref["field_stream"], string_ref["field_offset"]
        target_stream, target_offset = string_ref["target_stream"], string_ref["target_offset"]
        if not all(isinstance(value, int) for value in
                   (field_stream, field_offset, target_stream, target_offset)):
            raise ValueError("XString trace pair lacks owner or stream coordinates")
        compact = {"owner": owner, "field": {"stream": field_stream, "offset": field_offset}}
        at = _alias_field_archive(compact, intervals, body, interval_index,
                                  string_ref["sequence"])
        raw = struct.unpack_from("<Q", body, at)[0]
        tag = raw >> 32
        if raw == 0:
            string_class = "null"
        elif raw == 0xFFFFFFFFFFFFFFFF:
            string_class = "null_sentinel_ffffffff"
        elif raw == 0xFFFFFFFFFFFFFFFE:
            string_class = "inline_sentinel_fffffffe"
        else:
            string_class = f"packed_{tag:08x}"
        xstring_classes[string_class] = xstring_classes.get(string_class, 0) + 1
        old_base = asset_bases.get(owner)
        is_removed_target = any(stream_id == target_stream and start <= target_offset < end
                               for stream_id, start, end in removed_stream_ranges)
        if is_removed_target and owner == removed_owner:
            continue
        # XString null/inline sentinels are interpreted by Load_XString and
        # carry no relocatable numeric address. Their stream-operation target
        # is the current inline cursor, not a shared-reference edge.
        if raw in (0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE):
            continue
        if is_removed_target:
            raise ValueError("retained XString targets the removed image/name range")
        if tag == 5:
            if target_stream != 5 or (raw & 0xFFFFFFFF) - 1 != target_offset:
                raise ValueError("XString tag-5 bytes disagree with the native stream target")
        elif tag == 0x15:
            if old_base is None or target_stream != 5 or target_offset != old_base + (raw & 0xFFFFFFFF) - 1:
                raise ValueError("XString tag-0x15 bytes lack their native asset-local target")
        elif any(stream_id == target_stream and start <= target_offset < end
                 for stream_id, start, end in removed_stream_ranges):
            aliases.append((owner, raw, field_stream, field_offset, target_stream,
                            target_offset, string_ref["sequence"]))
            continue
        else:
            moved = (target_stream == 5 and table_logical_end is not None and
                     target_offset >= table_logical_end)
            moved |= any(stream_id == target_stream and target_offset >= end
                         for stream_id, _start, end in logical_delete_ranges)
            if moved:
                raise ValueError(f"unsupported XString pointer class {tag:#x} targets moved data")
            continue
        mapped_target = map_retained_target(target_stream, target_offset,
                                            string_ref["sequence"])
        if mapped_target is None:
            if (table_allocations and target_stream == 5 and
                    table_allocations[0]["start"] <= target_offset < table_logical_end):
                raise ValueError("XString targets an unmapped or deleted XAsset table row")
            if any(stream_id == target_stream and start <= target_offset < end
                   for stream_id, start, end in logical_delete_ranges):
                raise ValueError("XString targets a globally deleted logical range")
            shifted_target = target_offset + _coordinate_shift(
                target_stream, target_offset, table_logical_end, table_row_delta, False,
                logical_delete_ranges)
            if target_stream == 5:
                target_coordinate_fallbacks.append(dict(kind="xstring", owner=owner,
                    field_stream=field_stream, field_offset=field_offset, archive_offset=at,
                    pointer_tag=f"0x{tag:08x}", target_stream=target_stream,
                    source_target_offset=target_offset, relocated_target_offset=shifted_target,
                    table_logical_start=table_allocations[0]["start"] if table_allocations else None,
                    table_logical_end=table_logical_end, table_row_delta=table_row_delta,
                    logical_delete_ranges=[list(row) for row in logical_delete_ranges]))
            mapped_target = shifted_target
        record_relocated_target((owner, field_stream, field_offset), at, mapped_target)
        needs_absolute_rebase = (tag == 5 and target_stream == 5 and
            (table_row_delta != 0 or
             (table_logical_end is not None and target_offset >= table_logical_end)))
        target_shift = _coordinate_shift(target_stream, target_offset, table_logical_end,
            table_row_delta, False, logical_delete_ranges)
        base_shift = (_coordinate_shift(5, old_base, table_logical_end, table_row_delta, False,
            logical_delete_ranges) if old_base is not None else 0)
        needs_relative_rebase = (tag == 0x15 and target_stream == 5 and
                                 (table_row_delta != 0 or target_shift != base_shift))
        if is_removed_target or needs_absolute_rebase or needs_relative_rebase:
            xstring_relocated_fields.add((owner, field_stream, field_offset))             
            aliases.append((owner, raw, field_stream, field_offset, target_stream,
                            target_offset, string_ref["sequence"]))
    for owner, _raw, field_stream, field_offset, target_stream, target_offset, seq in aliases:
        compact = {"owner": owner, "field": {"stream": field_stream, "offset": field_offset}}
        at = _alias_field_archive(compact, intervals, body, interval_index, seq)
        if struct.unpack_from("<Q", body, at)[0] != _raw:
            raise ValueError("packed alias source bytes differ from the exact callback-owned native load")
        mapped_target = map_retained_target(target_stream, target_offset, seq)
        if mapped_target is not None:
            record_relocated_target((owner, field_stream, field_offset), at, mapped_target)
        elif (target_stream == 5 and
              table_allocations[0]["start"] <= target_offset < table_allocations[0]["end"]):
            raise ValueError("pointer targets the removed XAsset row or ambiguous table bytes")
        else:
            if target_stream != 5 or type(target_offset) is not int:
                raise ValueError("unmapped packed pointer target is outside the supported block-5 relocation")
            if any(stream_id == 5 and start <= target_offset < end
                   for stream_id, start, end in removed_stream_ranges):
                if owner != removed_owner:
                    raise ValueError("retained packed pointer targets the removed image/name range")
                continue
            if any(stream_id == 5 and start <= target_offset < end
                   for stream_id, start, end in logical_delete_ranges):
                raise ValueError("packed pointer targets a globally deleted logical range")
            shifted_target = target_offset + _coordinate_shift(
                target_stream, target_offset, table_logical_end, table_row_delta,
                False, logical_delete_ranges)
            if table_allocations and table_allocations[0]["start"] <= target_offset < table_logical_end:
                raise ValueError("packed pointer targets an unmapped or deleted XAsset table row")
            record_relocated_target((owner, field_stream, field_offset), at, shifted_target)
            target_coordinate_fallbacks.append(dict(kind="packed", owner=owner,
                field_stream=field_stream, field_offset=field_offset, archive_offset=at,
                pointer_tag=f"0x{_raw >> 32:08x}", target_stream=target_stream,
                source_target_offset=target_offset, relocated_target_offset=shifted_target,
                table_logical_start=table_allocations[0]["start"] if table_allocations else None,
                table_logical_end=table_logical_end,
                table_row_delta=table_row_delta,
                logical_delete_ranges=[list(row) for row in logical_delete_ranges]))
    for key3, targets in compatible_targets.items():
        if len(targets) == 1:
            relocated_targets[key3] = next(iter(targets))
    return (manifest, asset_bases, intervals, aliases, table_allocations[0],
            max_destinations, alias_events_seen, relocated_targets, relocated_asset_bases,
            dict(xstring_call_count=len(string_refs),
                 xstring_pointer_classes=xstring_classes,
                 xstring_relocated_fields=len(xstring_relocated_fields),
                 packed_reference_count=alias_events_seen,
                 packed_pointer_classes=packed_pointer_classes,
                 packed_targets_validated=packed_pointer_targets_validated,
                 target_coordinate_fallback_count=len(target_coordinate_fallbacks),
                 target_coordinate_fallbacks=target_coordinate_fallbacks,
                 logical_gap_mappings=[dict(stream=stream_id, source_start=start,
                     source_end=end, relocated_start=new_start, relocated_end=new_end,
                     sequence=sequence) for stream_id, start, end, new_start, new_end, sequence
                     in logical_gaps if sequence > 0],
                 relocated_stream_max_destinations=relocated_stream_max_destinations,
                 relocated_terminal_cursors=relocated_terminal_cursors,
                 selected_asset_stream_schedule=selected_asset_stream_schedule))


def _trace_asset(trace_path: str | Path, manifest_path: str | Path, body: bytes,
                 index: int, expected_type: int, name: str | None = None) -> dict:
    from workstation_trace_index import build_read_span_index
    indexed = build_read_span_index(trace_path, manifest_path, len(body), selected_assets={index})
    rows = [row for row in indexed["assets"] if row.get("index") == index]
    if len(rows) != 1:
        raise ValueError("full native trace does not uniquely contain the selected XAsset")
    row = rows[0]
    if row.get("type_id") != expected_type or (name is not None and row.get("name") != name):
        raise ValueError("native trace XAsset identity differs from the requested operation")
    return dict(xasset_index=index, type_id=expected_type,
                name=name if name is not None else row.get("name"),
                read_spans=row.get("read_spans", []),
                begin_cursor=row.get("begin_cursor"), end_cursor=row.get("end_cursor"),
                begin_sequence=row.get("begin_sequence"), end_sequence=row.get("end_sequence"))


def _build_interval_index(intervals: list[dict]) -> dict[tuple[int, int], tuple[list[int], list[dict], list[int]]]:
    """Index physical owners for alias-field lookup without O(aliases * reads)."""
    grouped: dict[tuple[int, int], list[dict]] = {}
    for span in intervals:
        owner, stream = span.get("owner"), span.get("stream")
        if not isinstance(stream, int):
            raise ValueError("native physical owner interval lacks stream")
        grouped.setdefault((owner, stream), []).append(span)
    result = {}
    for key, spans in grouped.items():
        spans.sort(key=lambda span: (span["start"], span["end"]))
        starts = [span["start"] for span in spans]
        prefix_max_end = []
        maximum = -1
        for span in spans:
            maximum = max(maximum, span["end"])
            prefix_max_end.append(maximum)
        result[key] = (starts, spans, prefix_max_end)
    return result


def _coordinate_shift(stream: int | None, offset: int | None,
                      table_logical_end: int | None, table_delta: int,
                      inverse: bool,
                      logical_delete_ranges: tuple[tuple[int, int, int], ...]) -> int:
    """Return the address delta applied to a surviving stream coordinate."""
    if not isinstance(stream, int) or not isinstance(offset, int):
        return 0
    delta = 0
    if stream == 5 and table_logical_end is not None and offset >= table_logical_end:
        delta += -table_delta if inverse else table_delta
    for range_stream, start, end in logical_delete_ranges:
        if stream == range_stream and offset >= end:
            delta -= end - start
    return delta


def _map_deleted_xasset_table_target(offset: int, table_start: int, asset_count: int,
                                     removed_index: int) -> tuple[bool, int | None]:
    """Map a stream-5 pointer into the XAsset row array across one row deletion."""
    table_end = table_start + asset_count * XASSET_ROW_SIZE
    if not table_start <= offset < table_end:
        return False, None
    deleted_start = table_start + removed_index * XASSET_ROW_SIZE
    deleted_end = deleted_start + XASSET_ROW_SIZE
    if deleted_start <= offset < deleted_end:
        return True, None
    return True, offset - XASSET_ROW_SIZE if offset >= deleted_end else offset


def _alias_field_archive(alias: dict, intervals: list[dict], body: bytes,
                         interval_index: dict | None = None,
                         callback_sequence: int | None = None) -> int:
    field = alias["field"]
    owner, block, offset = alias["owner"], field.get("stream"), field.get("offset")
    if not isinstance(block, int) or not isinstance(offset, int):
        raise ValueError("packed alias has no typed owner field location")
    index = interval_index if interval_index is not None else _build_interval_index(intervals)
    group = index.get((owner, block))
    if group is None:
        matches = []
    else:
        starts, spans, prefix_max_end = group
        position = bisect_right(starts, offset) - 1
        matches = []
        # Only walk intervals whose prefix can still reach this entire field.
        # Valid native schedules are non-overlapping; the backward walk also
        # preserves the old explicit ambiguity rejection for malformed traces.
        cursor = position
        while cursor >= 0 and prefix_max_end[cursor] >= offset + 8:
            span = spans[cursor]
            if span["start"] <= offset and offset + 8 <= span["end"]:
                matches.append(span)
            cursor -= 1
    if callback_sequence is not None:
        if isinstance(callback_sequence, bool) or not isinstance(callback_sequence, int):
            raise ValueError("packed alias callback has no valid native sequence")
        eligible = [span for span in matches
                    if isinstance(span.get("sequence"), int) and
                    span["sequence"] < callback_sequence]
        if not eligible:
            raise ValueError("packed alias callback has no earlier complete physical field load")
        latest_sequence = max(span["sequence"] for span in eligible)
        latest = [span for span in eligible if span["sequence"] == latest_sequence]
        if len(latest) != 1:
            raise ValueError("packed alias field has multiple latest physical owners before its callback")
        span = latest[0]
        if any(candidate.get("sequence", -1) > latest_sequence and
               candidate.get("sequence", -1) < callback_sequence and
               candidate["start"] < offset + 8 and candidate["end"] > offset
               for candidate in group[1] if candidate is not span):
            raise ValueError("packed alias field was partially overwritten before its callback")
    else:
        if len(matches) != 1:
            raise ValueError(f"packed alias field has {len(matches)} native physical owners")
        span = matches[0]
    physical = span["archive"] + offset - span["start"]
    if physical < 0 or physical + 8 > len(body):
        raise ValueError("packed alias field lies outside the relocated body")
    return physical


def _rebase_aliases(body: bytes, intervals: list[dict], aliases: list[dict],
                    table_logical_end: int, table_physical_end: int, delta: int,
                    asset_bases: dict[int, int], *, inverse: bool = False,
                    removed_stream_ranges: tuple[tuple[int, int, int], ...] = (),
                    logical_delete_ranges: tuple[tuple[int, int, int], ...] = (),
                    relocated_targets: dict | None = None,
                    relocated_asset_bases: dict | None = None) -> tuple[bytes, dict]:
    """Apply absolute/asset-relative pointer relocations for one table splice."""
    changed = bytearray(body)
    interval_index = _build_interval_index(intervals)
    patched = set()
    by_field = {}
    ignored = 0
    for alias in aliases:
        owner, raw, field_stream, field_offset, target_stream, target_offset, sequence = alias
        tag = raw >> 32
        if not isinstance(target_stream, int) or not isinstance(target_offset, int):
            raise ValueError("packed alias has an unresolved target")
        if any(stream == target_stream and start <= target_offset < end
               for stream, start, end in removed_stream_ranges):
            raise ValueError("inbound packed alias targets the LuaFile being removed")
        if any(stream == target_stream and start <= target_offset < end
               for stream, start, end in logical_delete_ranges):
            raise ValueError("packed alias targets a deleted LuaFile child range")
        compact_alias = {"owner": owner, "field": {"stream": field_stream, "offset": field_offset}}
        at = _alias_field_archive(compact_alias, intervals, body, interval_index, sequence)
        actual = struct.unpack_from("<Q", body, at)[0]
        if actual != raw:
            raise ValueError(
                f"packed alias source bytes differ from trace token at {at:#x} "
                f"(owner={owner}, trace={raw:#x}, body={actual:#x})")
        field_key = (owner, field_stream, field_offset, at)
        target_shift = _coordinate_shift(target_stream, target_offset,
                                         table_logical_end, delta, inverse,
                                         logical_delete_ranges)
        new_target = (relocated_targets.get(field_key,
                      relocated_targets.get(field_key[:3], target_offset + target_shift))
                      if relocated_targets is not None else target_offset + target_shift)
        old_base = asset_bases.get(owner)
        base_shift = (_coordinate_shift(5, old_base, table_logical_end, delta,
                                        inverse, logical_delete_ranges)
                      if old_base is not None else 0)
        if tag == 5:
            if target_stream != 5 or (raw & 0xFFFFFFFF) - 1 != target_offset:
                raise ValueError("tag-5 alias disagrees with its traced absolute block-5 target")
            new_low = new_target + 1
        elif tag == 0x15:
            if old_base is None or target_stream != 5 or target_offset != old_base + (raw & 0xFFFFFFFF) - 1:
                raise ValueError("tag-0x15 alias lacks its exact native asset-local base")
            new_base = (relocated_asset_bases.get(owner, old_base + base_shift)
                        if relocated_asset_bases is not None else old_base + base_shift)
            new_low = new_target - new_base + 1
        elif target_stream == 5 and (new_target != target_offset or base_shift):
            raise ValueError(f"unsupported packed pointer tag {tag:#x} targets moved block-5 data")
        else:
            ignored += 1
            continue
        if not 0 < new_low <= 0xFFFFFFFF:
            raise ValueError("relocated LuaFile pointer exceeds its 32-bit packed offset")
        key = at
        prior = by_field.get(key)
        if prior is not None:
            if prior != (at, raw, new_low):
                raise ValueError("duplicate trace aliases disagree about one physical source field")
            continue
        by_field[key] = (at, raw, new_low)
    for at, raw, low in by_field.values():
        if low != (raw & 0xFFFFFFFF):
            struct.pack_into("<Q", changed, at, (raw & 0xFFFFFFFF00000000) | low)
            patched.add(at)
    return bytes(changed), dict(packed_alias_events=len(aliases),
                                packed_alias_fields_rebased=len(patched),
                                packed_alias_archive_offsets=sorted(patched),
                                unsupported_unchanged_aliases=ignored)


def append_luafile_tail(body_data: bytes, name: str, payload: bytes,
                        existing_names: set[str], template_index: int,
                        template_name: str, template_trace_asset: dict,
                        final_trace_asset: dict, expected_body_sha256: str,
                        trace_path: str | Path, manifest_path: str | Path) -> tuple[bytes, dict]:
    """Append one inline LuaFile as a new final XAsset, rebasing moved aliases.

    Placement is limited to the observed inline LuaFile form and a source zone
    whose original final XAsset has an exact full-trace boundary at serialized
    EOF. The operation adds its row at the end of the existing pointer array,
    then serializes the new asset after the original final root.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("LuaFile append trace belongs to a different source body")
    if (not isinstance(name, str) or not name or "\x00" in name or
            name.startswith("/") or name.endswith("/") or "\\" in name or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("LuaFile append name is not a safe native asset name")
    if name in existing_names:
        raise ValueError("LuaFile append name already exists in the native XAsset inventory")
    if not isinstance(payload, bytes) or not payload.endswith(b"\0"):
        raise ValueError("LuaFile append payload must include the native trailing NUL")
    from workstation_asset_codecs import inspect_luajit_bytecode
    inspect_luajit_bytecode(payload[:-1])
    if not body.assets:
        raise ValueError("cannot append a LuaFile to an empty XAsset table")
    if isinstance(template_index, bool) or not isinstance(template_index, int) or \
            not 0 <= template_index < len(body.assets):
        raise ValueError("LuaFile append template index is outside the native XAsset table")
    if body.assets[template_index].type_id != LUA_FILE_TYPE_ID:
        raise ValueError("LuaFile append root template is not a native LuaFile")
    template, _ = inspect_luafile(body_data, template_index, template_name,
                                  template_trace_asset, expected_body_sha256)
    template_name_spans = [span for span in template_trace_asset.get("read_spans", [])
                           if span.get("origin") == "string_data" and
                           span.get("archive_offset") == template.name_archive_offset and
                           span.get("size") == template.name_bytes]
    if len(template_name_spans) != 1:
        raise ValueError("LuaFile template lacks one exact native name stream span")
    template_name_dest = template_name_spans[0].get("destination_stream_location")
    if (not isinstance(template_name_dest, dict) or template_name_dest.get("stream") != 5 or
            not isinstance(template_name_dest.get("offset"), int)):
        raise ValueError("LuaFile template name lacks native stream-5 destination evidence")
    final_index = len(body.assets) - 1
    if final_trace_asset.get("xasset_index") != final_index or \
            final_trace_asset.get("type_id") != body.assets[-1].type_id or \
            final_trace_asset.get("end_cursor") != len(body_data):
        raise ValueError("the original final XAsset lacks an exact serialized EOF boundary")
    final_spans = final_trace_asset.get("read_spans")
    if not isinstance(final_spans, list) or not final_spans:
        raise ValueError("original final XAsset has no trace-owned physical root span")
    if max(span.get("archive_offset", -1) + span.get("size", 0)
           for span in final_spans) != len(body_data):
        raise ValueError("original final XAsset does not own the serialized tail")

    (manifest, asset_bases, intervals, aliases, table_alloc, _max_destinations,
     alias_event_count, relocated_targets, relocated_asset_bases, xstring_stats) = _trace_contract(
        body_data, trace_path, manifest_path, table_row_delta=XASSET_ROW_SIZE,
        schedule_asset_index=template_index)
    relocated_cursors = xstring_stats.get("relocated_terminal_cursors")
    relocated_highwaters = xstring_stats.get("relocated_stream_max_destinations")
    if not isinstance(relocated_cursors, dict) or not isinstance(relocated_highwaters, dict):
        raise ValueError("LuaFile append requires replayed relocated stream cursors and high-waters")
    stream5_start = relocated_cursors.get(5)
    stream1_highwater = relocated_highwaters.get(1)
    stream5_highwater = relocated_highwaters.get(5)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in (stream5_start, stream1_highwater, stream5_highwater)):
        raise ValueError("LuaFile relocated stream contract has invalid cursor or high-water values")
    schedule = xstring_stats.get("selected_asset_stream_schedule")
    if not isinstance(schedule, list) or not schedule:
        raise ValueError("LuaFile append requires the selected template's traced stream schedule")
    name_stream_start = template_name_dest["offset"]
    name_event_index = next((i for i, event in enumerate(schedule)
        if event.get("operation") == "string" and event.get("block_before") == 5 and
        event.get("offset_before") == name_stream_start and
        event.get("size") == template.name_bytes), None)
    if name_event_index is None:
        raise ValueError("LuaFile template trace has no matching stream-5 name string event")
    name_load = next((event for event in schedule[name_event_index + 1:]
        if event.get("operation") == "load" and event.get("block_before") == 5), None)
    if (name_load is None or name_load.get("offset_before") != name_stream_start or
            name_load.get("size") != template.name_bytes):
        raise ValueError("LuaFile template name does not have the expected contiguous native load")
    name_load_pos = schedule.index(name_load)
    align_event = next((event for event in schedule[name_load_pos + 1:]
        if event.get("operation") == "align" and event.get("block_before") == 5), None)
    if align_event is None:
        raise ValueError("LuaFile template lacks a native stream-5 name-to-bytecode alignment event")
    align_mask = align_event.get("value")
    align_before, align_after = (align_event.get("offset_before"),
                                 align_event.get("offset_after"))
    if (isinstance(align_mask, bool) or not isinstance(align_mask, int) or align_mask < 0 or
            (align_mask + 1) & align_mask or align_before != name_stream_start + template.name_bytes or
            align_after != ((align_before + align_mask) & ~align_mask)):
        raise ValueError("LuaFile template has an unsupported name-to-bytecode alignment schedule")
    child_load = next((event for event in schedule[schedule.index(align_event) + 1:]
        if event.get("operation") == "load" and event.get("block_before") == 5), None)
    if (child_load is None or child_load.get("offset_before") != template.bytecode_stream_offset or
            child_load.get("size") != template.bytecode_bytes or
            align_after != template.bytecode_stream_offset):
        raise ValueError("LuaFile template bytecode load does not follow its traced name alignment")
    if table_alloc["size"] != len(body.assets) * XASSET_ROW_SIZE:
        raise ValueError("native XAsset pointer-array allocation differs from table count")
    table_logical_end = table_alloc["end"]
    table_physical_end = body.first_payload_offset
    if table_alloc["archive"] + table_alloc["size"] != table_physical_end:
        raise ValueError("native XAsset pointer-array does not end at the payload boundary")

    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, table_logical_end, table_physical_end,
        XASSET_ROW_SIZE, asset_bases,
        relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_asset_bases)
    # Insertion is after all original pointer rows and before the first root.
    row = struct.pack("<IIQ", LUA_FILE_TYPE_ID, 0, INLINE_POINTER)
    updated = bytearray(rebased)
    struct.pack_into("<I", updated, XASSET_ARRAY_COUNT_OFFSET, len(body.assets) + 1)
    updated[table_physical_end:table_physical_end] = row
    new_root_at = len(updated)
    root = struct.pack("<QiB3sQ", INLINE_POINTER, len(payload), template.stripping_type,
                       template.root_padding, INLINE_POINTER)
    name_bytes = len(name.encode("utf-8")) + 1
    name_stream_end = stream5_start + name_bytes
    bytecode_stream_start = (name_stream_end + align_mask) & ~align_mask
    stream5_end = bytecode_stream_start + len(payload)
    stream1_required = max(stream1_highwater,
                           template.root_stream_offset + len(root))
    stream5_required = max(stream5_highwater, stream5_end)
    stream_reservation_sizes = [0] * 11
    stream_reservation_sizes[1] = stream1_required
    stream_reservation_sizes[5] = stream5_required
    updated.extend(root)
    updated.extend(name.encode("utf-8") + b"\0")
    updated.extend(payload)
    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if len(reparsed.assets) != len(body.assets) + 1 or reparsed.assets[-1].type_id != LUA_FILE_TYPE_ID:
        raise AssertionError("LuaFile append did not add exactly one final type-62 XAsset")
    return result, dict(schema=1, status="native-trace-luafile-tail-append-candidate",
                        operation="append", name=name, asset_index=len(body.assets),
                        source_body_sha256=body.source_sha256,
                        output_body_sha256=_sha(result),
                        source_asset_count=len(body.assets), output_asset_count=len(reparsed.assets),
                        source_final_asset_index=final_index,
                        source_final_asset_type_id=body.assets[-1].type_id,
                        source_final_asset_end_cursor=final_trace_asset["end_cursor"],
                        xasset_table_physical_offset=body.asset_table_offset,
                        xasset_table_insert_offset=table_physical_end,
                        xasset_table_logical_end=table_logical_end,
                        xasset_row_bytes=XASSET_ROW_SIZE,
                        appended_root_archive_offset=new_root_at,
                        appended_root_bytes=len(root),
                        appended_name_bytes=name_bytes,
                        appended_bytecode_bytes=len(payload),
                        relocated_stream_terminal_cursors=relocated_cursors,
                        relocated_stream_max_destinations=relocated_highwaters,
                        appended_stream5_name_range=[stream5_start, name_stream_end],
                        appended_stream5_alignment=dict(mask=align_mask,
                            padding_bytes=bytecode_stream_start - name_stream_end),
                        appended_stream5_bytecode_range=[bytecode_stream_start, stream5_end],
                        native_template_stream_schedule=[
                            dict(operation=event.get("operation"),
                                 block_before=event.get("block_before"),
                                 offset_before=event.get("offset_before"),
                                 block_after=event.get("block_after"),
                                 offset_after=event.get("offset_after"),
                                 value=event.get("value"), size=event.get("size"))
                            for event in schedule],
                        stream_reservation_highwaters=stream_reservation_sizes,
                        template_asset_index=template_index,
                        template_stripping_type=template.stripping_type,
                        template_root_padding_hex=template.root_padding.hex(),
                        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
                        stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
                        source_stream_max_destinations={str(key): value for key, value in _max_destinations.items()},
                        **alias_receipt)


def remove_appended_luafile_tail(body_data: bytes, append_receipt: dict,
                                 trace_asset: dict, expected_body_sha256: str,
                                 trace_path: str | Path,
                                 manifest_path: str | Path) -> tuple[bytes, dict]:
    """Remove only a still-final LuaFile proven by this module's append receipt."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256 or append_receipt.get("output_body_sha256") != body.source_sha256:
        raise ValueError("LuaFile remove receipt does not identify this exact appended body")
    index = len(body.assets) - 1
    name = append_receipt.get("name")
    if (append_receipt.get("operation") != "append" or
            append_receipt.get("asset_index") != index or
            append_receipt.get("output_asset_count") != len(body.assets) or
            body.assets[index].type_id != LUA_FILE_TYPE_ID or
            trace_asset.get("xasset_index") != index or trace_asset.get("type_id") != LUA_FILE_TYPE_ID or
            trace_asset.get("name") != name):
        raise ValueError("LuaFile removal is limited to the previously appended final XAsset")
    layout, payload = inspect_luafile(body_data, index, name, trace_asset, body.source_sha256)
    if layout.bytecode_archive_offset + len(payload) != len(body_data):
        raise ValueError("appended LuaFile does not own the exact physical serialized tail")
    name_span = next(span for span in trace_asset["read_spans"]
                     if span.get("origin") == "string_data" and
                     span.get("archive_offset") == layout.name_archive_offset)
    name_dest = name_span.get("destination_stream_location")
    bytecode_span = next(span for span in trace_asset["read_spans"]
                         if span.get("archive_offset") == layout.bytecode_archive_offset and
                         span.get("size") == layout.bytecode_bytes)
    bytecode_dest = bytecode_span.get("destination_stream_location")
    removed_ranges = [(layout.root_stream, layout.root_stream_offset,
                       layout.root_stream_offset + LUA_FILE_ROOT_SIZE)]
    for dest, size in ((name_dest, layout.name_bytes), (bytecode_dest, layout.bytecode_bytes)):
        if not isinstance(dest, dict) or not isinstance(dest.get("stream"), int) or \
                not isinstance(dest.get("offset"), int):
            raise ValueError("appended LuaFile child lacks typed destination ownership")
        removed_ranges.append((dest["stream"], dest["offset"], dest["offset"] + size))
    (manifest, asset_bases, intervals, aliases, table_alloc, _max_destinations,
     alias_event_count, _relocated_targets, _relocated_asset_bases, _xstring_stats) = _trace_contract(
        body_data, trace_path, manifest_path, tuple(removed_ranges), removed_owner=index)
    if table_alloc["size"] != len(body.assets) * XASSET_ROW_SIZE:
        raise ValueError("native XAsset pointer-array allocation differs from appended table count")
    root_start = layout.root_stream_offset
    root_end = root_start + LUA_FILE_ROOT_SIZE
    for alias in aliases:
        target_stream, target_offset = alias[4], alias[5]
        if target_stream == layout.root_stream and root_start <= target_offset < root_end:
            raise ValueError("ambiguous inbound alias targets the LuaFile root stream range")
    old_table_logical_end = table_alloc["end"]
    table_physical_end = body.first_payload_offset
    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, old_table_logical_end, table_physical_end,
        XASSET_ROW_SIZE, asset_bases, inverse=True,
        removed_stream_ranges=tuple(removed_ranges))
    out = bytearray(rebased)
    # The final 16-byte pointer row is at the end of the table, before payloads.
    row_at = body.asset_table_offset + index * XASSET_ROW_SIZE
    del out[row_at:row_at + XASSET_ROW_SIZE]
    struct.pack_into("<I", out, XASSET_ARRAY_COUNT_OFFSET, index)
    # After removing the row, the appended asset payload is exactly the tail;
    # its archive start moved back by one row width.
    tail_start = layout.root_archive_offset - XASSET_ROW_SIZE
    if tail_start < 0 or tail_start > len(out):
        raise ValueError("appended LuaFile physical root is outside the shortened body")
    del out[tail_start:]
    result = bytes(out)
    reparsed = ZoneBody.parse(result)
    if len(reparsed.assets) != index or reparsed.assets != body.assets[:-1]:
        raise AssertionError("LuaFile removal changed a retained XAsset row")
    return result, dict(schema=1, status="native-trace-appended-luafile-tail-remove-candidate",
                        operation="remove_appended_tail", name=name, removed_index=index,
                        source_body_sha256=body.source_sha256,
                        output_body_sha256=_sha(result), source_asset_count=len(body.assets),
                        output_asset_count=len(reparsed.assets), removed_payload_sha256=_sha(payload),
                        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
                        stream_trace_sha256=_sha(Path(trace_path).read_bytes()), **alias_receipt)


def remove_existing_luafile_row(body_data: bytes, asset_index: int, asset_name: str,
                                trace_asset: dict, expected_body_sha256: str,
                                trace_path: str | Path, manifest_path: str | Path,
                                *, indexed_assets: list[dict] | None = None) -> tuple[bytes, dict]:
    """Remove one uniquely-owned LuaFile row and its inline payload.

    The proof is intentionally per-asset: the caller supplies the corresponding
    asset row from a complete native read-span index. Root/name/bytecode must
    form one contiguous physical allocation, child bytes must be owned only by
    this XAsset, and the full trace must show no inbound aliases into any
    removed stream range. References outside the removed range are relocated
    for both the table reservation shrink and the removed stream-5 allocation.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("LuaFile removal trace belongs to a different source body")
    if isinstance(asset_index, bool) or not isinstance(asset_index, int) or \
            not 0 <= asset_index < len(body.assets):
        raise ValueError("LuaFile removal index is outside the source XAsset table")
    if body.assets[asset_index].type_id != LUA_FILE_TYPE_ID:
        raise ValueError("selected XAsset is not a native LuaFile")
    if (trace_asset.get("xasset_index") != asset_index or
            trace_asset.get("type_id") != LUA_FILE_TYPE_ID or
            trace_asset.get("name") != asset_name):
        raise ValueError("native trace row identity differs from selected LuaFile")
    layout, payload = inspect_luafile(body_data, asset_index, asset_name,
                                      trace_asset, expected_body_sha256)
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("LuaFile trace row lacks physical ownership spans")
    name_span = next((span for span in spans if span.get("origin") == "string_data" and
                      span.get("archive_offset") == layout.name_archive_offset and
                      span.get("size") == layout.name_bytes), None)
    payload_span = next((span for span in spans if span.get("archive_offset") == layout.bytecode_archive_offset and
                         span.get("size") == layout.bytecode_bytes), None)
    root_span = next((span for span in spans if span.get("archive_offset") == layout.root_archive_offset and
                      span.get("size") == LUA_FILE_ROOT_SIZE), None)
    if not root_span or not name_span or not payload_span:
        raise ValueError("native trace does not uniquely own LuaFile root, name and bytecode spans")
    physical_start = layout.root_archive_offset
    physical_end = layout.bytecode_archive_offset + layout.bytecode_bytes
    if not (physical_start + LUA_FILE_ROOT_SIZE == layout.name_archive_offset and
            layout.name_archive_offset + layout.name_bytes == layout.bytecode_archive_offset and
            physical_end <= len(body_data)):
        raise ValueError("LuaFile physical root/name/bytecode are not one contiguous owned extent")
    if asset_index == len(body.assets) - 1 and physical_end != len(body_data):
        raise ValueError("final LuaFile row does not own the exact serialized EOF")

    name_dest = name_span.get("destination_stream_location")
    payload_dest = payload_span.get("destination_stream_location")
    root_dest = root_span.get("destination_stream_location")
    if not all(isinstance(value, dict) for value in (name_dest, payload_dest, root_dest)):
        raise ValueError("LuaFile owned spans lack typed destination coordinates")
    if (name_dest.get("stream") != 5 or payload_dest.get("stream") != 5 or
            not isinstance(name_dest.get("offset"), int) or
            not isinstance(payload_dest.get("offset"), int) or
            root_dest.get("stream") != layout.root_stream or
            root_dest.get("offset") != layout.root_stream_offset):
        raise ValueError("LuaFile child/root stream ownership differs from the proven native layout")
    stream5_start = name_dest["offset"]
    stream5_end = payload_dest["offset"] + layout.bytecode_bytes
    if stream5_end <= stream5_start:
        raise ValueError("LuaFile stream-5 allocation has an invalid extent")
    child_range = (5, stream5_start, stream5_end)
    root_range = (layout.root_stream, layout.root_stream_offset,
                  layout.root_stream_offset + LUA_FILE_ROOT_SIZE)

    (manifest, asset_bases, intervals, aliases, table_alloc, max_destinations,
     alias_count, relocated_targets, relocated_asset_bases, xstring_stats) = _trace_contract(
        body_data, trace_path, manifest_path,
        removed_stream_ranges=(child_range, root_range),
        logical_delete_ranges=(child_range,), removed_owner=asset_index)
    if table_alloc["size"] != len(body.assets) * XASSET_ROW_SIZE:
        raise ValueError("native XAsset pointer-array allocation differs from source table count")

    owned_spans = [span for span in intervals
                   if span["owner"] == asset_index and span["archive"] < physical_end and
                   span["archive"] + span["size"] > physical_start]
    if sorted((span["archive"], span["archive"] + span["size"]) for span in owned_spans) != [
            (physical_start, physical_start + LUA_FILE_ROOT_SIZE),
            (layout.name_archive_offset, layout.name_archive_offset + layout.name_bytes),
            (layout.bytecode_archive_offset, physical_end)]:
        raise ValueError("LuaFile physical ownership includes missing or extra reads")
    for span in intervals:
        if span["owner"] == asset_index:
            continue
        if span["archive"] < physical_end and span["archive"] + span["size"] > physical_start:
            raise ValueError("LuaFile physical bytes are shared with another native XAsset")

    # Any pointer into the scratch root range is ambiguous because stream 1 is
    # reused by asset readers; reject it, alongside references into stream-5
    # name/bytecode bytes. The trace contract retains these aliases for a hard
    # failure rather than assuming that a same-address root belongs to this row.
    row_archive = body.asset_table_offset + asset_index * XASSET_ROW_SIZE
    row = body_data[row_archive:row_archive + XASSET_ROW_SIZE]
    if len(row) != XASSET_ROW_SIZE or struct.unpack_from("<I", row)[0] != LUA_FILE_TYPE_ID:
        raise ValueError("selected LuaFile XAsset table row does not match its native type")
    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, table_alloc["end"], body.first_payload_offset,
        -XASSET_ROW_SIZE, asset_bases, removed_stream_ranges=(child_range, root_range),
        logical_delete_ranges=(child_range,), relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_asset_bases)
    out = bytearray(rebased)
    # Remove the tail-owned root/name/bytecode interval and the table row.
    for start, end in sorted(((physical_start, physical_end),
                             (row_archive, row_archive + XASSET_ROW_SIZE)), reverse=True):
        del out[start:end]
    struct.pack_into("<I", out, XASSET_ARRAY_COUNT_OFFSET, len(body.assets) - 1)
    result = bytes(out)
    retained = body.assets[:asset_index] + body.assets[asset_index + 1:]
    reparsed = ZoneBody.parse(result)
    source_rows = [(row.type_id, row.pointer_token) for row in retained]
    output_rows = [(row.type_id, row.pointer_token) for row in reparsed.assets]
    if output_rows != source_rows:
        raise AssertionError("LuaFile removal changed a retained XAsset row or its order")
    return result, dict(schema=1, status="native-trace-existing-luafile-row-remove-candidate",
                        operation="remove_existing", name=asset_name, asset_index=asset_index,
                        source_body_sha256=body.source_sha256,
                        output_body_sha256=_sha(result), source_asset_count=len(body.assets),
                        output_asset_count=len(reparsed.assets),
                        removed_root_archive_range=[physical_start, physical_end],
                        removed_root_bytes=LUA_FILE_ROOT_SIZE,
                        removed_name_bytes=layout.name_bytes,
                        removed_bytecode_bytes=layout.bytecode_bytes,
                        removed_stream5_range=[stream5_start, stream5_end],
                        removed_table_row_archive_range=[row_archive, row_archive + XASSET_ROW_SIZE],
                        source_stream_max_destinations={str(key): value
                                                        for key, value in max_destinations.items()},
                        xstring_reference_contract=xstring_stats,
                        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
                        stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
                        **alias_receipt)
