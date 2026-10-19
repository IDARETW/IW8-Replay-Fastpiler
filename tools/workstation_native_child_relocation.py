"""Typed, alignment-aware relocation of native stream-5 inline children.

An adapter supplies trace-owned child coordinates and the native root length
field. This primitive simulates the complete native read schedule and rebases
absolute and asset-relative pointers; it never derives ownership from a byte
pattern. Callers must reread the complete rebuilt zone before publication.
"""
from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import struct

try:
    from workstation_fastfiles import ZoneBody
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody


@dataclass(frozen=True)
class InlineChildLayout:
    asset_name: str
    root_archive_offset: int
    child_archive_offset: int
    child_stream_offset: int
    child_bytes: int
    child_sha256: str
    length_field_offset: int
    length_format: str
    allow_empty_insert: bool = False


def _validate_children(body, layouts, replacements):
    if not isinstance(body, bytes) or not layouts or set(layouts) != set(replacements):
        raise ValueError("inline child edit requires one payload per typed layout")
    ranges = []
    parsed = ZoneBody.parse(body)
    for index, layout in layouts.items():
        if type(index) is not int or not 0 <= index < len(parsed.assets):
            raise ValueError("inline child owner is outside the XAsset table")
        if not isinstance(layout, InlineChildLayout):
            raise TypeError("inline child layout must be typed")
        payload = replacements[index]
        if (not isinstance(payload, bytes) or (not payload and not layout.allow_empty_insert) or
                len(payload) > 0x7fffffff):
            raise ValueError("inline child replacement exceeds its native size range")
        start, size = layout.child_archive_offset, layout.child_bytes
        length_at = layout.root_archive_offset + layout.length_field_offset
        if (layout.length_format not in ("<i", "<I") or size < 0 or
                (size == 0 and not layout.allow_empty_insert) or
                start < parsed.first_payload_offset or start + size > len(body) or
                length_at < parsed.first_payload_offset or length_at + 4 > start or
                layout.child_stream_offset < 0):
            raise ValueError("inline child or root length field lies outside its proven extent")
        if struct.unpack_from(layout.length_format, body, length_at)[0] != size:
            raise ValueError("inline child length field differs from its native span")
        if hashlib.sha256(body[start:start + size]).hexdigest() != layout.child_sha256:
            raise ValueError("inline child bytes differ from their trace-bound identity")
        if size == 0 and (not layout.allow_empty_insert or layout.child_sha256 != hashlib.sha256(b"").hexdigest()):
            raise ValueError("empty inline-child insertion lacks a null-buffer source identity")
        ranges.append((start, start + size))
    ranges.sort()
    if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError("inline child edit ranges overlap")


def relocate_stream5_children(body_data: bytes,
                             layouts: dict[int, InlineChildLayout],
                             replacements: dict[int, bytes],
                             trace_path: str | Path,
                             manifest_path: str | Path) -> tuple[bytes, dict]:
    """Relocate stream-5 aliases once for a batch of inline inline child edits.

    The complete native trace is replayed to calculate alignment-aware new
    stream-5 destinations. Every packed pointer whose target moves is mapped
    back to its original serialized field and patched. Ambiguous allocations,
    unknown pointer tags, pointers into the replaced child, or incomplete
    traces fail closed.
    """
    _validate_children(body_data, layouts, replacements)
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_digest = manifest.get("stream_trace_sha256")
    if trace_digest is not None:
        digest = hashlib.sha256()
        with trace_path.open("rb") as trace_input:
            for chunk in iter(lambda: trace_input.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != trace_digest:
            raise ValueError("inline child native trace differs from its manifest digest")
    expected_events = manifest.get("stream_trace_events")
    if (manifest.get("profile") != "replay-1.20" or
            manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            not isinstance(expected_events, int) or
            manifest.get("tested") != manifest.get("top_level_index") or
            manifest.get("tested") != len(ZoneBody.parse(body_data).assets) or
            manifest.get("failed", 0) != 0 or manifest.get("unavailable", 0) != 0 or
            manifest.get("serialized_bytes_read") != len(body_data)):
        raise ValueError("inline child growth requires a complete native full-zone trace")

    changed_layouts = {index: layout for index, layout in layouts.items()
                       if replacements[index] != body_data[
                           layout.child_archive_offset:
                           layout.child_archive_offset + layout.child_bytes]}
    if not changed_layouts:
        return body_data, dict(status="semantic-noop-inline-child-batch",
                               source_body_sha256=hashlib.sha256(body_data).hexdigest(),
                               output_body_sha256=hashlib.sha256(body_data).hexdigest(),
                               edits=[], packed_stream5_aliases_rebased=0,
                               stream_reservation_sizes=None)
    changed_ranges = {
        index: (layout.child_stream_offset,
                layout.child_stream_offset + layout.child_bytes)
        for index, layout in changed_layouts.items()
    }
    child_deltas = {index: len(replacements[index]) - layout.child_bytes
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
                raise ValueError(f"inline child growth trace sequence breaks at {event_count}")
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
                            f"inline child relocation has no stream-5 cursor at asset {owner} entry")
                    asset_bases[owner] = original_base + stream_deltas.get(5, 0)
                    original_asset_bases[owner] = original_base
            elif kind == "xasset_end":
                ending_owner = event.get("xasset_index", active_asset)
                for index, layout in changed_layouts.items():
                    if layout.child_bytes != 0 or index != ending_owner:
                        continue
                    if not layout.allow_empty_insert or index in changed_children_seen:
                        raise ValueError("empty inline-child insertion has an invalid native owner")
                    if original_cursors.get(5) != layout.child_stream_offset:
                        raise ValueError("empty inline-child insertion is not at its exact stream-5 owner cursor")
                    stream_deltas[5] = stream_deltas.get(5, 0) + len(replacements[index])
                    # Earlier insertions may already have shifted this owner's
                    # original stream cursor. Report the cumulative new end.
                    max_new_destination[5] = max(max_new_destination.get(5, 0),
                        layout.child_stream_offset + stream_deltas[5])
                    changed_children_seen.add(index)
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
                                     layouts[index].child_bytes > 0 and
                                     before_offset == old_start and
                                     physical == layouts[index].child_bytes), None)
                if operation == "load" and matched_edit is not None and \
                        matched_edit not in changed_children_seen:
                    if pending_call is None or pending_call.get("loader_start_arg") != 0:
                        raise ValueError("inline child child growth is not bound to its native AtStart call")
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
        raise ValueError("complete native trace did not include the target inline child child")

    stream5_intervals = sorted((item for item in intervals if item["stream"] == 5),
                               key=lambda item: item["old_start"])
    stream5_starts = [item["old_start"] for item in stream5_intervals]
    if any(left["old_end"] > right["old_start"]
           for left, right in zip(stream5_intervals, stream5_intervals[1:])):
        raise ValueError("native trace contains overlapping stream-5 physical allocations")

    def map_stream5_target(offset: int) -> int:
        if any(start <= offset < end for start, end in changed_ranges.values()):
            raise ValueError("packed pointer targets bytes replaced by a inline child edit")
        at = bisect_right(stream5_starts, offset) - 1
        if at < 0 or offset >= stream5_intervals[at]["old_end"]:
            raise ValueError(f"stream-5 target {offset:#x} has no owning allocation")
        allocation = stream5_intervals[at]
        return allocation["new_start"] + offset - allocation["old_start"]

    # A whole zone can contain hundreds of thousands of reads and pointer
    # fields. Index by native owner/stream once; rescanning every allocation
    # for every alias makes otherwise bounded transactions quadratic.
    owner_intervals = {}
    for item in intervals:
        owner_intervals.setdefault((item["owner"], item["stream"]), []).append(item)
    field_index = {}
    for key, spans in owner_intervals.items():
        spans.sort(key=lambda item: item["old_start"])
        maxima, high = [], -1
        for item in spans:
            high = max(high, item["old_end"])
            maxima.append(high)
        field_index[key] = ([item["old_start"] for item in spans], spans, maxima)

    def map_field_location(owner: int | None, field: dict) -> int:
        block, offset = field.get("stream"), field.get("offset")
        if not isinstance(owner, int) or not isinstance(block, int) or not isinstance(offset, int):
            raise ValueError("packed alias does not identify a physical owner field")
        starts, spans, maxima = field_index.get((owner, block), ([], [], []))
        cursor = bisect_right(starts, offset) - 1
        matches = []
        while cursor >= 0 and maxima[cursor] >= offset + 8:
            item = spans[cursor]
            if item["old_start"] <= offset and offset + 8 <= item["old_end"]:
                matches.append(item)
            cursor -= 1
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
        struct.pack_into(layout.length_format, changed,
                         layout.root_archive_offset + layout.length_field_offset,
                         len(replacements[index]))
    # Splice children from highest archive offset down so all earlier source
    # offsets remain valid. Root length fields are already patched and move
    # with the serialized bytes if they follow a later asset's allocation.
    for index, layout in sorted(changed_layouts.items(),
                                key=lambda item: item[1].child_archive_offset,
                                reverse=True):
        start = layout.child_archive_offset
        end = start + layout.child_bytes
        changed[start:end] = replacements[index]
    result = bytes(changed)
    if ZoneBody.parse(result).assets != ZoneBody.parse(body_data).assets:
        raise AssertionError("inline child growth changed the XAsset table")
    edits = [dict(asset_index=index, asset_name=layouts[index].asset_name,
                  root_archive_offset=layouts[index].root_archive_offset,
                  child_archive_offset=layouts[index].child_archive_offset,
                  old_child_bytes=layouts[index].child_bytes,
                  new_child_bytes=len(replacements[index]),
                  physical_extent_delta=child_deltas[index],
                  old_child_sha256=layouts[index].child_sha256,
                  new_child_sha256=hashlib.sha256(replacements[index]).hexdigest())
             for index in sorted(changed_layouts)]
    return result, dict(
        status="trace-relocated-inline-child-batch-ready",
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

