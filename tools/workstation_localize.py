"""Typed Replay LocalizeEntry reads and bounded native-body edits.

The supported form is the observed Replay 1.20 type-41 record: a 16-byte
root containing two ordinary or shared-inline XString sentinels, followed by
key and value bytes on stream 5. Production value edits replay the complete
native stream trace, preserve other Localize keys sharing the old value, and
rebase supported packed references. Value edits preserve keys/names; append adds a native inline row
and delete removes one trace-owned inline row. Existing-row deletion is a
single operation tied to its exact body and full native trace; repeat only
after rereading/retracing the intermediate body. Multi-row atomic deletion is
not exposed.
"""
from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

try:
    from workstation_fastfiles import ZoneBody
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody


LOCALIZE_TYPE_ID = 41
LOCALIZE_ROOT_BYTES = 16
INLINE = 0xFFFFFFFFFFFFFFFE
SHARED_INLINE = 0xFFFFFFFFFFFFFFFF
LOCALIZE_ROOT_CALLER_RVA = 0xE047AD


@dataclass(frozen=True)
class LocalizeEntryLayout:
    asset_index: int
    asset_name: str
    root_archive_offset: int
    root_stream_offset: int
    key_archive_offset: int
    key_stream_offset: int
    key_bytes: int
    value_archive_offset: int
    value_stream_offset: int
    value_bytes: int
    archive_end: int
    source_body_sha256: str
    source_record_sha256: str


@dataclass(frozen=True, init=False)
class LocalizeReadContext:
    """Immutable parsed body reused while inspecting many Localize rows.

    The context is intentionally bound to the exact immutable bytes object;
    it cannot be reused for another body or a caller-provided hash.
    """
    __slots__ = ("body_data", "body")
    body_data: bytes
    body: Any

    def __init__(self, body_data: bytes):
        if type(body_data) is not bytes:
            raise TypeError("Localize read context requires immutable bytes")
        object.__setattr__(self, "body_data", body_data)
        object.__setattr__(self, "body", ZoneBody.parse(body_data))


def _read_text_span(body: bytes, span: dict, label: str) -> str:
    offset, size = span.get("archive_offset"), span.get("size")
    destination = span.get("destination_stream_location")
    if (not isinstance(offset, int) or not isinstance(size, int) or size < 1 or
            offset < 0 or offset + size > len(body) or not isinstance(destination, dict) or
            destination.get("stream") != 5):
        raise ValueError(f"Localize {label} span is invalid or not on stream 5")
    raw = body[offset:offset + size]
    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
        raise ValueError(f"Localize {label} is not exactly one NUL-terminated string")
    try:
        return raw[:-1].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"Localize {label} is not valid UTF-8") from error


def inspect_localize_entry(body_data: bytes, asset_index: int, asset_name: str,
                           trace_asset: dict, expected_body_sha256: str | None = None,
                           expected_key: str | None = None,
                           expected_value: str | None = None, *,
                           context: LocalizeReadContext | None = None) -> tuple[LocalizeEntryLayout, dict[str, str]]:
    """Validate one full native LocalizeEntry schedule and return editable text."""
    if context is None:
        body = ZoneBody.parse(body_data)
    else:
        if (type(context) is not LocalizeReadContext or type(body_data) is not bytes or
                context.body_data is not body_data):
            raise ValueError("Localize read context is not bound to this immutable body")
        body = context.body
    if expected_body_sha256 is not None and body.source_sha256 != expected_body_sha256:
        raise ValueError("Localize trace belongs to a different decoded body")
    if not isinstance(asset_index, int) or not 0 <= asset_index < len(body.assets):
        raise ValueError("Localize XAsset index is outside the source table")
    if body.assets[asset_index].type_id != LOCALIZE_TYPE_ID:
        raise ValueError("selected XAsset is not a LocalizeEntry")
    if body.assets[asset_index].pointer_token != INLINE:
        raise ValueError("Localize XAsset uses an unsupported non-inline root pointer")
    if (trace_asset.get("index", trace_asset.get("xasset_index")) != asset_index or
            trace_asset.get("type_id") != LOCALIZE_TYPE_ID or
            trace_asset.get("name") != asset_name):
        raise ValueError("native trace row does not match the requested Localize identity")
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("Localize trace row has no physical read spans")
    roots = [span for span in spans if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0 and span.get("size") == LOCALIZE_ROOT_BYTES]
    if len(roots) != 1:
        raise ValueError("Localize record requires one 16-byte AtStart root read")
    root = roots[0]
    root_at = root.get("archive_offset")
    root_location = root.get("destination_stream_location")
    if (not isinstance(root_at, int) or root_at < 0 or root_at + 16 > len(body_data) or
            not isinstance(root_location, dict) or root_location.get("stream") != 1):
        raise ValueError("Localize root is not a bounded stream-1 allocation")
    key_token, value_token = struct.unpack_from("<QQ", body_data, root_at)
    # Load_XString consumes owned bytes for both -2 (inline) and -1
    # (shared inline). The exact native read spans prove physical ownership;
    # packed aliases and null pointers do not have this two-child schedule.
    if key_token not in (INLINE, SHARED_INLINE) or value_token not in (INLINE, SHARED_INLINE):
        raise ValueError("Localize record uses a pointer form not yet supported by this adapter")
    children = sorted((span for span in spans if span.get("origin") == "string_data"),
                      key=lambda span: span.get("archive_offset", -1))
    if len(children) != 2:
        raise ValueError(f"Localize record requires exactly two native string reads, got {len(children)}")
    if children[0].get("archive_offset") != root_at + LOCALIZE_ROOT_BYTES:
        raise ValueError("Localize key does not immediately follow its root")
    if children[1].get("archive_offset") != children[0].get("archive_offset") + children[0].get("size", 0):
        raise ValueError("Localize value does not immediately follow its key")
    key = _read_text_span(body_data, children[0], "key")
    value = _read_text_span(body_data, children[1], "value")
    if key != asset_name:
        raise ValueError("Localize root key differs from its XAsset name")
    if expected_key is not None and key != expected_key:
        raise ValueError("Localize key differs from the semantic export")
    if expected_value is not None and value != expected_value:
        raise ValueError("Localize value differs from the semantic export")
    root_callers = [span.get("caller_rva") for span in spans
                    if span.get("reader_start_arg") == 0 and span.get("size") == 16]
    if root_callers != [LOCALIZE_ROOT_CALLER_RVA]:
        # Call-site identity is part of the captured native reader contract.
        raise ValueError(f"unexpected Localize root callsite: {root_callers!r}")
    key_bytes = children[0]["size"]
    value_bytes = children[1]["size"]
    end = children[1]["archive_offset"] + value_bytes
    if trace_asset.get("end_cursor") != end:
        raise ValueError("Localize native XAsset end cursor differs from its serialized record")
    layout = LocalizeEntryLayout(
        asset_index=asset_index, asset_name=asset_name,
        root_archive_offset=root_at, root_stream_offset=root_location["offset"],
        key_archive_offset=children[0]["archive_offset"],
        key_stream_offset=children[0]["destination_stream_location"]["offset"],
        key_bytes=key_bytes, value_archive_offset=children[1]["archive_offset"],
        value_stream_offset=children[1]["destination_stream_location"]["offset"],
        value_bytes=value_bytes, archive_end=end,
        source_body_sha256=body.source_sha256,
        source_record_sha256=hashlib.sha256(body_data[root_at:end]).hexdigest())
    return layout, {"key": key, "value": value}


def replace_localize_value_same_extent(body_data: bytes, asset_index: int, asset_name: str,
                                       trace_asset: dict, value: str,
                                       expected_body_sha256: str,
                                       expected_key: str | None = None,
                                       expected_value: str | None = None) -> tuple[bytes, dict]:
    """Replace a localized value without changing native allocation lengths."""
    layout, original = inspect_localize_entry(body_data, asset_index, asset_name,
                                              trace_asset, expected_body_sha256,
                                              expected_key, expected_value)
    if not isinstance(value, str) or "\0" in value:
        raise ValueError("Localize value must be NUL-free text")
    encoded = value.encode("utf-8") + b"\0"
    if len(encoded) != layout.value_bytes:
        raise ValueError("Localize value changes its native stream-5 extent; relocation is required")
    output = bytearray(body_data)
    start = layout.value_archive_offset
    output[start:start + layout.value_bytes] = encoded
    result = bytes(output)
    if ZoneBody.parse(result).assets != ZoneBody.parse(body_data).assets:
        raise AssertionError("same-extent Localize replacement changed XAsset inventory")
    return result, dict(schema=1, status="same-extent-localize-value-ready",
                        asset_index=asset_index, asset_name=asset_name,
                        source_body_sha256=expected_body_sha256,
                        output_body_sha256=hashlib.sha256(result).hexdigest(),
                        old_value=original["value"], new_value=value,
                        value_archive_offset=start, value_stream_offset=layout.value_stream_offset,
                        value_bytes=len(encoded), body_extent_unchanged=True,
                        xasset_table_unchanged=True)


def replace_localize_values_same_extent(body_data: bytes, edits: list[dict],
                                        expected_body_sha256: str) -> tuple[bytes, dict]:
    """Apply a nonoverlapping batch of same-extent Localize value edits.

    Each edit is a mapping with ``asset_index``, ``asset_name``, ``trace_asset``,
    and ``value``; optional ``expected_key`` and ``expected_value`` bind the
    semantic editor snapshot to the native source. All rows are inspected
    against the same immutable input body before any bytes are changed, so a
    batch cannot accidentally validate later rows against already-mutated data.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("Localize batch belongs to a different decoded source body")
    if not isinstance(edits, list) or not edits:
        raise ValueError("Localize batch requires at least one edit")
    indices: set[int] = set()
    writes: list[tuple[int, int, bytes, dict]] = []
    for edit in edits:
        if not isinstance(edit, dict):
            raise ValueError("Localize batch edit is not a mapping")
        asset_index = edit.get("asset_index")
        asset_name = edit.get("asset_name")
        trace_asset = edit.get("trace_asset")
        value = edit.get("value")
        if not isinstance(asset_index, int) or isinstance(asset_index, bool):
            raise ValueError("Localize batch has an invalid XAsset index")
        if asset_index in indices:
            raise ValueError(f"Localize batch repeats XAsset index {asset_index}")
        indices.add(asset_index)
        if not isinstance(asset_name, str) or not isinstance(trace_asset, dict):
            raise ValueError("Localize batch edit is missing its native identity/trace row")
        layout, original = inspect_localize_entry(
            body_data, asset_index, asset_name, trace_asset, expected_body_sha256,
            edit.get("expected_key"), edit.get("expected_value"))
        if not isinstance(value, str) or "\0" in value:
            raise ValueError("Localize value must be NUL-free text")
        encoded = value.encode("utf-8") + b"\0"
        if len(encoded) != layout.value_bytes:
            raise ValueError(
                f"Localize value for {asset_name!r} changes its native stream-5 extent; relocation is required")
        start, end = layout.value_archive_offset, layout.value_archive_offset + layout.value_bytes
        writes.append((start, end, encoded, dict(
            asset_index=asset_index, asset_name=asset_name,
            old_value=original["value"], new_value=value,
            value_archive_offset=start, value_stream_offset=layout.value_stream_offset,
            value_bytes=len(encoded), source_record_sha256=layout.source_record_sha256)))
    writes.sort(key=lambda row: row[0])
    if any(left[1] > right[0] for left, right in zip(writes, writes[1:])):
        raise ValueError("Localize batch contains overlapping native value spans")
    output = bytearray(body_data)
    for start, end, encoded, _receipt in writes:
        output[start:end] = encoded
    result = bytes(output)
    if (len(result) != len(body_data) or
            ZoneBody.parse(result).assets != body.assets):
        raise AssertionError("same-extent Localize batch changed body extent or XAsset inventory")
    return result, dict(
        schema=1, status="same-extent-localize-batch-ready",
        source_body_sha256=expected_body_sha256,
        output_body_sha256=hashlib.sha256(result).hexdigest(),
        body_extent_unchanged=True, xasset_table_unchanged=True,
        edit_count=len(writes), edits=[row[3] for row in writes])


def append_localize_entry(body_data: bytes, key: str, value: str,
                          stream_reservations: list[int],
                          stream_highwaters: dict[int, int],
                          expected_body_sha256: str,
                          trace_path: str | Path | None = None,
                          trace_manifest_path: str | Path | None = None) -> tuple[bytes, list[int], dict]:
    """Append one type-41 entry to both the native XAsset list and body tail.

    This form is intentionally restricted to append-only insertion. It adds
    one 16-byte XAsset-table row, one 16-byte stream-1 root, and two stream-5
    strings. Existing stream-5 coordinates are replayed through downstream
    alignment, and packed references are rebased from the complete trace.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("Localize append request belongs to a different source body")
    _validate_text(key, "key")
    _validate_text(value, "value")
    if len(stream_reservations) != 11 or any(not isinstance(size, int) or size < 0 for size in stream_reservations):
        raise ValueError("Localize append requires all eleven source stream reservations")
    stream1_end, stream5_end = stream_highwaters.get(1), stream_highwaters.get(5)
    if not isinstance(stream1_end, int) or not isinstance(stream5_end, int):
        raise ValueError("Localize append requires trace-proven stream-1 and stream-5 high-water marks")
    if stream1_end > stream_reservations[1] or stream5_end > stream_reservations[5]:
        raise ValueError("native stream high-water exceeds the stored reservation")
    table_at = body.asset_table_offset
    count = len(body.assets)
    root, reserved, name_ptr, string_count, reserved2, assets_ptr = struct.unpack_from("<IIQIIQ", body_data)
    del root, name_ptr, string_count, assets_ptr
    if reserved or reserved2:
        raise ValueError("XAssetList reserved fields are not zero")
    row_at = table_at + count * 16
    if row_at > len(body_data):
        raise ValueError("XAssetList row tail lies outside decoded body")
    row_bytes = struct.pack("<IIQ", LOCALIZE_TYPE_ID, 0, INLINE)
    rebased_body, pointer_receipt = _rebase_stream5_after_table_growth(
        body_data, trace_path, trace_manifest_path, table_growth=count * 16, delta=16)
    # The table grows in place; every following physical payload moves by 16.
    prefix = bytearray(rebased_body[:row_at] + row_bytes + rebased_body[row_at:])
    struct.pack_into("<I", prefix, 16, count + 1)
    root_at = len(prefix)
    key_bytes, value_bytes = key.encode("utf-8") + b"\0", value.encode("utf-8") + b"\0"
    prefix.extend(struct.pack("<QQ", INLINE, INLINE))
    prefix.extend(key_bytes)
    prefix.extend(value_bytes)
    updated = bytes(prefix)
    new_reservations = list(stream_reservations)
    root_stream_offset = 0  # Verified LocalizeEntry root scratch slot is reused per XAsset.
    contract = pointer_receipt.get("xstring_reference_contract")
    relocated_cursors = contract.get("relocated_terminal_cursors") if isinstance(contract, dict) else None
    relocated_highwaters = contract.get("relocated_stream_max_destinations") if isinstance(contract, dict) else None
    if not isinstance(relocated_cursors, dict) or not isinstance(relocated_highwaters, dict):
        raise ValueError("Localize append requires replayed relocated stream cursors and high-waters")
    relocated_stream5_end = relocated_cursors.get("5", relocated_cursors.get(5))
    relocated_stream1_highwater = relocated_highwaters.get("1", relocated_highwaters.get(1))
    relocated_stream5_highwater = relocated_highwaters.get("5", relocated_highwaters.get(5))
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in (relocated_stream5_end, relocated_stream1_highwater,
                         relocated_stream5_highwater)):
        raise ValueError("Localize relocated stream contract has invalid cursor or high-water values")
    if relocated_stream5_end < stream5_end:
        raise ValueError("Localize relocated stream-5 terminal cursor precedes source high-water")
    key_stream_offset = relocated_stream5_end
    value_stream_offset = key_stream_offset + len(key_bytes)
    new_reservations[1] = max(new_reservations[1], relocated_stream1_highwater,
                              root_stream_offset + LOCALIZE_ROOT_BYTES)
    new_reservations[5] = max(new_reservations[5], relocated_stream5_highwater,
                              relocated_stream5_end + len(key_bytes) + len(value_bytes))
    parsed = ZoneBody.parse(updated)
    if len(parsed.assets) != count + 1 or parsed.assets[-1].type_id != LOCALIZE_TYPE_ID:
        raise AssertionError("appended Localize XAsset row failed inventory validation")
    return updated, new_reservations, dict(schema=1, status="append-localize-tail-ready",
        asset_index=count, asset_name=key, source_body_sha256=expected_body_sha256,
        output_body_sha256=hashlib.sha256(updated).hexdigest(), root_archive_offset=root_at,
        root_stream_offset=root_stream_offset, key_stream_offset=key_stream_offset,
        value_stream_offset=value_stream_offset,
        root_bytes=LOCALIZE_ROOT_BYTES, key_bytes=len(key_bytes), value_bytes=len(value_bytes),
        xasset_rows_added=1, physical_extent_delta=16 + LOCALIZE_ROOT_BYTES + len(key_bytes) + len(value_bytes),
        stream_reservation_deltas=[0, new_reservations[1] - stream_reservations[1], 0, 0, 0,
                                   new_reservations[5] - stream_reservations[5], 0, 0, 0, 0, 0],
        stream5_table_growth_bytes=16, stream5_pointer_relocation=pointer_receipt,
        relocated_stream_cursors=relocated_cursors,
        relocated_stream_highwaters=relocated_highwaters,
        stream_reservation_sizes=new_reservations,
        existing_xasset_rows_preserved=True,
        existing_stream5_payload_offsets_rebased_by_table_growth=True)


def remove_appended_localize_entry(body_data: bytes, asset_index: int, asset_name: str,
                                   trace_asset: dict, expected_body_sha256: str,
                                   expected_stream1_root_offset: int,
                                   trace_path: str | Path | None = None,
                                   trace_manifest_path: str | Path | None = None) -> tuple[bytes, dict]:
    """Remove only the last XAsset when its Localize bytes own the exact body tail."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("Localize remove request belongs to a different body")
    if asset_index != len(body.assets) - 1:
        raise ValueError("only the final XAsset may be removed by this bounded operation")
    layout, semantic = inspect_localize_entry(body_data, asset_index, asset_name,
                                              trace_asset, expected_body_sha256)
    del semantic
    if layout.root_stream_offset != expected_stream1_root_offset or layout.archive_end != len(body_data):
        raise ValueError("Localize removal is not the proven appended root at the serialized body tail")
    rebased, pointer_receipt = _rebase_stream5_after_table_growth(
        body_data, trace_path, trace_manifest_path,
        table_growth=asset_index * 16, delta=-16)
    # Remove child/root data, then delete the final 16-byte XAsset table row.
    without_record = rebased[:layout.root_archive_offset]
    row_at = body.asset_table_offset + len(body.assets) * 16 - 16
    output = bytearray(without_record[:row_at] + without_record[row_at + 16:])
    struct.pack_into("<I", output, 16, len(body.assets) - 1)
    result = bytes(output)
    if ZoneBody.parse(result).assets != body.assets[:-1]:
        raise AssertionError("Localize tail removal changed retained XAsset order")
    return result, dict(schema=1, status="remove-appended-localize-tail-ready",
        asset_index=asset_index, asset_name=asset_name,
        source_body_sha256=expected_body_sha256,
        output_body_sha256=hashlib.sha256(result).hexdigest(),
        root_archive_offset=layout.root_archive_offset,
        physical_extent_delta=-(16 + LOCALIZE_ROOT_BYTES + layout.key_bytes + layout.value_bytes),
        xasset_rows_removed=1, retained_xasset_order_preserved=True,
        stream5_pointer_relocation=pointer_receipt)


def remove_localize_entry(body_data: bytes, asset_index: int, asset_name: str,
                          trace_asset: dict, expected_body_sha256: str,
                          expected_key: str, expected_value: str,
                          trace_path: str | Path,
                          trace_manifest_path: str | Path) -> tuple[bytes, dict]:
    """Remove one existing inline Localize row from a complete traced body.

    The whole native trace supplies packed-pointer targets and physical field
    owners. Pointers into the row, its root, or its strings reject the edit;
    successful rows are remapped across the XAsset-table and stream-5 splices.
    Repeated deletions must use a fresh native trace/body pair after each edit.
    The original stream reservations are retained as safe capacity headroom;
    the body and native read cursor shrink, but this helper does not claim a
    minimal reservation table.
    """
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("Localize deletion body identity mismatch")
    if not isinstance(asset_index, int) or isinstance(asset_index, bool) or not 0 <= asset_index < len(body.assets):
        raise ValueError("Localize deletion index is outside the XAsset table")
    layout, _semantic = inspect_localize_entry(
        body_data, asset_index, asset_name, trace_asset, expected_body_sha256,
        expected_key, expected_value)
    trace_path, trace_manifest_path = Path(trace_path), Path(trace_manifest_path)
    manifest = json.loads(trace_manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("tested") != manifest.get("top_level_index") or
            manifest.get("serialized_bytes_read") != len(body_data) or
            not isinstance(manifest.get("stream_trace_events"), int)):
        raise ValueError("Localize deletion requires a complete Replay 1.20 native trace")

    intervals: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    bases: dict[int, int] = {}
    new_bases: dict[int, int] = {}
    cursors: dict[int, int] = {}
    stream_deltas: dict[int, int] = {}
    table_start: int | None = None
    table_allocation_seen = False
    active_asset: int | None = None
    pending_call: dict | None = None
    event_count = 0
    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            seq = event.get("sequence")
            if seq != event_count:
                raise ValueError(f"Localize deletion trace sequence breaks at {event_count}")
            event_count += 1
            kind = event.get("kind")
            if kind == "xasset_begin":
                active_asset = event.get("xasset_index")
                entry = event.get("table_entry_stream_location")
                if table_start is None and isinstance(active_asset, int) and isinstance(entry, dict):
                    if entry.get("stream") != 5 or not isinstance(entry.get("offset"), int):
                        raise ValueError("Localize XAsset table is not in stream 5")
                    table_start = entry["offset"] - active_asset * 16
            elif kind == "begin_asset_call":
                owner = event.get("xasset_index")
                if isinstance(owner, int) and owner not in bases:
                    if not isinstance(cursors.get(5), int):
                        raise ValueError(f"Localize deletion has no stream-5 base for asset {owner}")
                    bases[owner] = cursors[5]
                    new_bases[owner] = cursors[5] + stream_deltas.get(5, 0)
            elif kind == "xasset_end":
                active_asset = None
                pending_call = None
            elif kind == "load_stream_call":
                pending_call = event
            elif kind in ("packed_resolve", "packed_alias"):
                raw = event.get("raw_token")
                field = event.get("field_stream_location")
                target = event.get("resolved_target_stream_location")
                if not isinstance(raw, int) or not isinstance(field, dict):
                    raise ValueError("packed pointer event lacks token/field ownership")
                if isinstance(target, dict) and isinstance(target.get("stream"), int) and \
                        isinstance(target.get("offset"), int):
                    target_stream, target_offset = target["stream"], target["offset"]
                elif raw >> 32 == 5:
                    target_stream, target_offset = 5, (raw & 0xFFFFFFFF) - 1
                else:
                    raise ValueError("packed pointer event lacks a resolved target")
                aliases.append(dict(owner=event.get("xasset_index"), raw=raw,
                                    field=field, target_stream=target_stream,
                                    target=target_offset, sequence=seq))

            if kind != "stream_operation":
                if pending_call and seq > pending_call.get("sequence", seq) + 2:
                    pending_call = None
                continue
            operation = event.get("operation")
            before_block, after_block = event.get("block_before"), event.get("block_after")
            before_offset, after_offset = event.get("offset_before"), event.get("offset_after")
            if not all(isinstance(value, int) for value in
                       (before_block, after_block, before_offset, after_offset)):
                pending_call = None
                continue
            new_before = before_offset + stream_deltas.get(before_block, 0)
            if operation in ("load", "take"):
                size, physical = event.get("size"), event.get("physical_input_bytes")
                if not isinstance(size, int) or not isinstance(physical, int):
                    raise ValueError("Localize deletion trace read lacks size accounting")
                old_advance = after_offset - before_offset
                table_read = (not table_allocation_seen and active_asset is None and
                              before_block == after_block == 5 and before_offset == 0 and
                              size == len(body.assets) * 16 and physical == size)
                deleted_string_read = (active_asset == asset_index and
                    before_block == after_block == 5 and operation == "load" and physical == size and
                    ((before_offset == layout.key_stream_offset and size == layout.key_bytes) or
                     (before_offset == layout.value_stream_offset and size == layout.value_bytes)))
                new_advance = size
                if table_read:
                    if table_allocation_seen:
                        raise ValueError("trace repeats the XAsset table stream allocation")
                    table_allocation_seen = True
                    new_advance -= 16
                elif deleted_string_read:
                    new_advance = 0
                new_after = (new_before + new_advance if before_block == after_block
                             else after_offset + stream_deltas.get(after_block, 0))
                if physical > 0:
                    destination = (pending_call.get("destination_stream_location")
                                   if pending_call and pending_call.get("sequence") == seq - 1 and
                                   pending_call.get("at_start") else
                                   {"stream": before_block, "offset": before_offset})
                    owner = event.get("xasset_index", active_asset)
                    if isinstance(destination, dict):
                        intervals.append(dict(owner=owner, stream=destination.get("stream"),
                                              start=destination.get("offset"),
                                              end=destination.get("offset", -1) + size,
                                              new_start=new_before, new_end=new_before + new_advance,
                                              archive=event.get("input_before"), size=size,
                                              table=table_read, removed=deleted_string_read))
                stream_deltas[after_block] = new_after - after_offset
            elif operation == "align":
                mask = event.get("value")
                if not isinstance(mask, int) or mask < 0:
                    raise ValueError("stream alignment has an invalid mask")
                new_after = ((new_before + mask) & ~mask if before_block == after_block
                             else after_offset + stream_deltas.get(after_block, 0))
                stream_deltas[after_block] = new_after - after_offset
            else:
                new_after = after_offset + stream_deltas.get(after_block, 0)
                stream_deltas[after_block] = new_after - after_offset
            cursors[after_block] = after_offset
            pending_call = None
    if event_count != manifest["stream_trace_events"] or table_start is None or not table_allocation_seen:
        raise ValueError("Localize deletion trace count/table base mismatch")

    key_bytes, value_bytes = layout.key_bytes, layout.value_bytes
    string_start, string_end = layout.key_stream_offset, layout.value_stream_offset + value_bytes
    if layout.value_stream_offset != string_start + key_bytes:
        raise ValueError("Localize key/value stream allocations are not adjacent")
    record_start, record_end = layout.root_archive_offset, layout.value_archive_offset + value_bytes
    if layout.root_archive_offset + LOCALIZE_ROOT_BYTES != layout.key_archive_offset or \
            layout.key_archive_offset + key_bytes != layout.value_archive_offset:
        raise ValueError("Localize root/key/value physical allocations are not contiguous")
    is_final_row = asset_index == len(body.assets) - 1
    if is_final_row:
        # A final-row deletion is safe only when this populated row owns the
        # complete serialized tail. Full EOF in the manifest alone does not
        # establish which asset owns the bytes at EOF.
        if record_end != len(body_data):
            raise ValueError("final Localize row does not own the exact serialized EOF")
        owned = [span for span in intervals if span.get("owner") == asset_index and
                 isinstance(span.get("archive"), int) and
                 span["archive"] < record_end and
                 span["archive"] + span.get("size", 0) > record_start]
        expected_owned = sorted((start, end) for start, end in (
            (layout.root_archive_offset, layout.root_archive_offset + LOCALIZE_ROOT_BYTES),
            (layout.key_archive_offset, layout.key_archive_offset + key_bytes),
            (layout.value_archive_offset, layout.value_archive_offset + value_bytes)))
        actual_owned = sorted((span["archive"], span["archive"] + span["size"])
                              for span in owned)
        if actual_owned != expected_owned:
            raise ValueError("final Localize row lacks exact trace ownership of root/key/value bytes")
        if any(span.get("owner") != asset_index and
               isinstance(span.get("archive"), int) and
               span["archive"] < record_end and
               span["archive"] + span.get("size", 0) > record_start
               for span in intervals):
            raise ValueError("final Localize tail bytes are shared with another native XAsset")

    row_start = table_start + asset_index * 16
    row_end = row_start + 16
    table_interval = next((span for span in intervals if span.get("table")), None)
    if table_interval is None or table_interval.get("start") != table_start:
        raise ValueError("native trace does not identify the stream-5 XAsset table allocation")

    def map_stream5(offset: int) -> int:
        if string_start <= offset < string_end:
            raise ValueError("packed pointer targets deleted Localize key/value bytes")
        if row_start <= offset < row_end:
            raise ValueError("packed pointer targets the XAsset row being removed")
        if table_interval["start"] <= offset < table_interval["end"]:
            table_delta = 16 if offset >= row_end else 0
            return table_interval["new_start"] + offset - table_interval["start"] - table_delta
        owners = [span for span in intervals if span.get("stream") == 5 and
                  not span.get("table") and not span.get("removed") and
                  isinstance(span.get("start"), int) and span["start"] <= offset < span["end"]]
        if len(owners) != 1:
            raise ValueError(f"stream-5 target {offset:#x} has {len(owners)} retained allocation owners")
        span = owners[0]
        return span["new_start"] + offset - span["start"]

    output = bytearray(body_data)
    intervals_by_owner_stream: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for span in intervals:
        if isinstance(span.get("owner"), int) and isinstance(span.get("stream"), int):
            intervals_by_owner_stream.setdefault((span["owner"], span["stream"]), []).append(span)
    patched_fields: set[tuple[int, int, int]] = set()
    patched = 0
    for alias in aliases:
        owner, raw, target_stream, target = (alias["owner"], alias["raw"],
                                             alias["target_stream"], alias["target"])
        if owner == asset_index:
            continue
        if target_stream != 5:
            raise ValueError(f"unsupported packed target stream {target_stream}; deletion is stream-5 bounded")
        tag = raw >> 32
        if tag == 5:
            if target != (raw & 0xFFFFFFFF) - 1:
                raise ValueError("tag-5 packed target disagrees with native resolution")
            new_low = map_stream5(target) + 1
        elif tag == 0x15:
            old_base = bases.get(owner)
            if old_base is None or target != old_base + (raw & 0xFFFFFFFF) - 1:
                raise ValueError(f"tag-0x15 packed target disagrees with asset base {owner}")
            new_base = new_bases.get(owner)
            if new_base is None:
                raise ValueError(f"tag-0x15 alias owner {owner} has no simulated post-delete base")
            new_low = map_stream5(target) - new_base + 1
        else:
            raise ValueError(f"unsupported packed pointer tag {tag:#x}")
        if not 0 < new_low <= 0xFFFFFFFF:
            raise ValueError("rebased packed target does not fit its 32-bit offset")
        if new_low == (raw & 0xFFFFFFFF):
            continue
        field = alias["field"]
        block, offset = field.get("stream"), field.get("offset")
        if not isinstance(block, int) or not isinstance(offset, int):
            raise ValueError("packed field lacks its stream location")
        owners = [span for span in intervals_by_owner_stream.get((owner, block), [])
                  if isinstance(span.get("start"), int) and span["start"] <= offset and
                  offset + 8 <= span["end"]]
        if len(owners) != 1:
            raise ValueError(f"packed field has {len(owners)} physical owners")
        archive_field = owners[0]["archive"] + offset - owners[0]["start"]
        field_id = owner, block, offset
        if field_id in patched_fields or archive_field < 0 or archive_field + 8 > len(output):
            raise ValueError("packed field ownership is repeated or outside decoded body")
        if struct.unpack_from("<Q", output, archive_field)[0] != raw:
            raise ValueError("packed field bytes differ from the native trace")
        struct.pack_into("<Q", output, archive_field,
                         (raw & 0xFFFFFFFF00000000) | new_low)
        patched_fields.add(field_id)
        patched += 1

    # Splice the XAsset row, then its contiguous root and stream-5 strings.
    physical_row_start = body.asset_table_offset + asset_index * 16
    physical_row_end = physical_row_start + 16
    without_row = output[:physical_row_start] + output[physical_row_end:]
    shifted_record_start = record_start - (16 if record_start >= physical_row_end else 0)
    shifted_record_end = record_end - (16 if record_end >= physical_row_end else 0)
    result_buffer = without_row[:shifted_record_start] + without_row[shifted_record_end:]
    struct.pack_into("<I", result_buffer, 16, len(body.assets) - 1)
    result = bytes(result_buffer)
    parsed = ZoneBody.parse(result)
    retained = body.assets[:asset_index] + body.assets[asset_index + 1:]
    if [(row.type_id, row.pointer_token) for row in parsed.assets] != \
            [(row.type_id, row.pointer_token) for row in retained]:
        raise AssertionError("Localize deletion changed retained XAsset identity/order")
    return result, dict(schema=1, status="trace-owned-localize-row-removal-ready",
        asset_index=asset_index, asset_name=asset_name, key=expected_key,
        source_body_sha256=expected_body_sha256, output_body_sha256=hashlib.sha256(result).hexdigest(),
        xasset_rows_removed=1, retained_xasset_order_preserved=True,
        root_archive_offset=record_start, root_and_strings_physical_bytes=record_end - record_start,
        physical_extent_delta=-(16 + record_end - record_start),
        stream5_table_bytes_removed=16, stream5_string_bytes_removed=key_bytes + value_bytes,
        stream5_logical_bytes_removed=16 + key_bytes + value_bytes,
        final_row_tail_ownership_verified=is_final_row,
        stream5_reservation_retained=True,
        stream5_pointer_relocation=dict(aliases_scanned=len(aliases), aliases_rebased=patched,
                                        fields_patched=len(patched_fields),
                                        full_trace_events=event_count),
        combination_limit="repeat only after native reread/retrace of each intermediate body; not a single batch API")


def _validate_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"Localize {label} must be nonempty NUL-free text")
    value.encode("utf-8")


def _rebase_stream5_after_table_growth(body_data: bytes, trace_path: str | Path | None,
                                      trace_manifest_path: str | Path | None,
                                      table_growth: int, delta: int) -> tuple[bytes, dict]:
    """Rebase full-zone tag-5/tag-0x15 references after XAsset-table growth.

    Physical field ownership and asset-local bases are reconstructed from the
    complete native trace. Missing or ambiguous ownership is a hard failure.
    """
    if not isinstance(trace_path, (str, Path)) or not isinstance(trace_manifest_path, (str, Path)):
        raise ValueError("Localize XAsset-table growth requires the complete native stream trace")
    trace_path, trace_manifest_path = Path(trace_path), Path(trace_manifest_path)
    manifest = json.loads(trace_manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("profile") != "replay-1.20" or manifest.get("complete") is not True or
            manifest.get("success") is not True or manifest.get("xfile_version") != 0xFF7 or
            manifest.get("serialized_bytes_read") != len(body_data) or
            manifest.get("tested") != manifest.get("top_level_index")):
        raise ValueError("Localize table growth requires a complete Replay 1.20 native trace")
    expected_events = manifest.get("stream_trace_events")
    if not isinstance(manifest.get("stream_trace_sha256"), str):
        raise ValueError("Localize table growth requires a trace-bound native manifest")
    if delta != 16:
        raise ValueError("Localize table shrink requires mapped-delete semantics")
    # A production append must replay the actual stream schedule.  A table row
    # changes the stream-5 cursor, but alignment, shared strings and reused
    # allocations mean that individual downstream coordinates do not all move
    # by the same delta.  The LuaFile row writer already owns the checked
    # segment mapper for this exact XAsset-table splice; reuse it here rather
    # than applying a global target >= table-end rule.
    if delta == 16 and isinstance(manifest.get("stream_trace_sha256"), str):
        try:
            from workstation_luafile_operations import _rebase_aliases, _trace_contract
        except ModuleNotFoundError:
            from tools.workstation_luafile_operations import _rebase_aliases, _trace_contract
        (checked_manifest, asset_bases, intervals, aliases, table_allocation,
         _max_destinations, alias_events_seen, relocated_targets,
         relocated_asset_bases, xstring_contract) = _trace_contract(
            body_data, trace_path, trace_manifest_path, table_row_delta=delta)
        body = ZoneBody.parse(body_data)
        if (table_allocation.get("size") != len(body.assets) * 16 or
                table_allocation.get("archive") != body.asset_table_offset or
                table_allocation.get("end") - table_allocation.get("start") != table_growth):
            raise ValueError("Localize native XAsset table allocation differs from the decoded body")
        rebased, alias_receipt = _rebase_aliases(
            body_data, intervals, aliases, table_allocation["end"],
            body.first_payload_offset, delta, asset_bases,
            relocated_targets=relocated_targets,
            relocated_asset_bases=relocated_asset_bases)
        return rebased, dict(
            status="full-native-trace-coordinate-map-rebase-pass",
            aliases_scanned=alias_events_seen,
            aliases_rebased=alias_receipt["packed_alias_fields_rebased"],
            tag5_or_tag15_fields_patched=alias_receipt["packed_alias_fields_rebased"],
            unsupported_unchanged_aliases=alias_receipt["unsupported_unchanged_aliases"],
            table_growth_stream_offset=table_allocation["end"], stream5_delta=delta,
            complete_trace_events=checked_manifest["stream_trace_events"],
            mapped_pointer_fields=len(relocated_targets),
            mapped_asset_bases=len(relocated_asset_bases),
            xstring_reference_contract=xstring_contract)
    raise AssertionError("Localize coordinate mapper returned without producing a result")

def _relocate_stream5_localize_values(body_data: bytes,
                             layouts: dict[int, Any],
                             replacements: dict[int, bytes],
                             trace_path: str | Path,
                             manifest_path: str | Path) -> tuple[bytes, dict]:
    """Relocate stream-5 aliases once for a batch of inline Localize value edits.

    The complete native trace is replayed to calculate alignment-aware new
    stream-5 destinations. Every packed pointer whose target moves is mapped
    back to its original serialized field and patched. Other Localize values
    sharing an edited string receive independent inline copies of their old
    text. Ambiguous allocations, unknown pointer tags, substring references,
    or incomplete traces fail closed.
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
        raise ValueError("Localize value growth requires a complete native full-zone trace")

    # Check physical and logical ranges before filtering no-op rows: two edits
    # may not claim the same serialized bytes even if one is a semantic no-op.
    def reject_overlaps(items: list[tuple[int, int, int]], label: str) -> None:
        ordered = sorted(items)
        for left, right in zip(ordered, ordered[1:]):
            if left[1] > right[0]:
                raise ValueError(f"overlapping Localize {label} spans: assets {left[2]} and {right[2]}")

    reject_overlaps([(layout.value_archive_offset,
                      layout.value_archive_offset + layout.value_bytes, index)
                     for index, layout in layouts.items()], "physical value")
    reject_overlaps([(layout.value_stream_offset,
                      layout.value_stream_offset + layout.value_bytes, index)
                     for index, layout in layouts.items()], "stream-5 value")

    changed_layouts = {index: layout for index, layout in layouts.items()
                       if replacements[index] != body_data[
                           layout.value_archive_offset:
                           layout.value_archive_offset + layout.value_bytes]}
    if not changed_layouts:
        return body_data, dict(status="semantic-noop-localize-variable-value-batch",
                               source_body_sha256=hashlib.sha256(body_data).hexdigest(),
                               output_body_sha256=hashlib.sha256(body_data).hexdigest(),
                               edits=[], packed_stream5_aliases_rebased=0,
                               stream_reservation_sizes=None)
    changed_ranges = {
        index: (layout.value_stream_offset,
                layout.value_stream_offset + layout.value_bytes)
        for index, layout in changed_layouts.items()
    }
    child_deltas = {index: len(replacements[index]) - layout.value_bytes
                    for index, layout in changed_layouts.items()}
    stream_deltas: dict[int, int] = {}
    original_cursors: dict[int, int] = {}
    max_new_destination: dict[int, int] = {}
    max_old_destination: dict[int, int] = {}
    asset_bases: dict[int, int] = {}
    original_asset_bases: dict[int, int] = {}
    intervals: list[dict] = []
    aliases: list[dict] = []
    preserved_values: list[dict] = []
    asset_end_cursors: dict[int, int] = {}
    source_assets = ZoneBody.parse(body_data).assets
    pending_call: dict | None = None
    pending_string: dict | None = None
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
                raise ValueError(f"Localize value growth trace sequence breaks at {event_count}")
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
                            f"Localize value relocation has no stream-5 cursor at asset {owner} entry")
                    asset_bases[owner] = original_base + stream_deltas.get(5, 0)
                    original_asset_bases[owner] = original_base
            elif kind == "xasset_end":
                owner = event.get("xasset_index")
                if isinstance(owner, int):
                    asset_end_cursors[owner] = event.get("serialized_input_cursor")
                active_asset = None
                pending_call = None
                pending_string = None
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
                        alias = dict(kind=kind, owner=event.get("xasset_index"), raw=raw,
                                     field=field, target=target_offset, sequence=seq)
                        shared_edit = next((index for index, (start, end) in changed_ranges.items()
                                            if start <= target_offset < end), None)
                        if shared_edit is None:
                            aliases.append(alias)
                        else:
                            owner = alias["owner"]
                            root = event.get("root_stream_location")
                            insertion = event.get("serialized_input_cursor")
                            # Only a typed Localize value resolving the entire
                            # original XString has a proven independent inline
                            # loading schedule. Keys and substring aliases keep
                            # the fail-closed contract.
                            if (kind != "packed_resolve" or
                                    target_offset != changed_ranges[shared_edit][0] or
                                    not isinstance(owner, int) or owner != active_asset or
                                    not 0 <= owner < len(source_assets) or
                                    source_assets[owner].type_id != LOCALIZE_TYPE_ID or
                                    source_assets[owner].pointer_token != INLINE or
                                    event.get("type_id") != LOCALIZE_TYPE_ID or
                                    owner in layouts or not isinstance(root, dict) or
                                    root.get("stream") != 1 or
                                    not isinstance(root.get("offset"), int) or
                                    field.get("stream") != 1 or
                                    field.get("offset") != root["offset"] + 8 or
                                    event.get("stream_block") != 5 or
                                    not isinstance(original_cursors.get(5), int) or
                                    not isinstance(insertion, int) or
                                    not 0 <= insertion <= len(body_data) or
                                    insertion < layouts[shared_edit].value_archive_offset +
                                    layouts[shared_edit].value_bytes):
                                raise ValueError(
                                    f"packed pointer targets changed Localize value {shared_edit}; "
                                    "substring or non-value alias semantics are unproven")
                            layout = layouts[shared_edit]
                            original_value = body_data[layout.value_archive_offset:
                                                       layout.value_archive_offset + layout.value_bytes]
                            preserved_values.append(dict(
                                **alias, root=root, archive_offset=insertion,
                                source_asset_index=shared_edit, value=original_value,
                                original_base=original_asset_bases.get(owner)))
                            # The old pointer consumed no input or stream space.
                            # Its new inline copy advances block 5 at this exact
                            # resolve call, before subsequent alignments.
                            stream_deltas[5] = stream_deltas.get(5, 0) + len(original_value)
                            max_new_destination[5] = max(
                                max_new_destination.get(5, 0),
                                original_cursors[5] + stream_deltas[5])

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
                                     physical == layouts[index].value_bytes), None)
                if operation == "load" and matched_edit is not None and \
                        matched_edit not in changed_children_seen:
                    string_read = pending_string
                    if (not isinstance(string_read, dict) or
                            string_read.get("owner") != matched_edit or
                            string_read.get("offset") != before_offset or
                            string_read.get("size") != layouts[matched_edit].value_bytes or
                            string_read.get("input_before") != event.get("input_before")):
                        raise ValueError("Localize value read is not paired with its traced native XString call")
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
                                          caller_rva=pending_call.get("caller_rva")
                                          if pending_call and pending_call.get("sequence") == seq - 1 else None,
                                          reader_start_arg=pending_call.get("loader_start_arg")
                                          if pending_call and pending_call.get("sequence") == seq - 1 else None,
                                          sequence=seq))
                stream_deltas[after_block] = new_after - after_offset
                pending_call = None
                pending_string = None
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
                if operation == "string":
                    pending_string = dict(owner=active_asset, offset=before_offset,
                                          size=event.get("size"), input_before=event.get("input_before"))
                else:
                    pending_string = None

            # Capture destination reservations for every stream, including
            # zero-byte transitions and stream-4 calculated allocations.
            if before_block > 0:
                max_new_destination[before_block] = max(
                    max_new_destination.get(before_block, 0), new_before)
            if after_block > 0:
                max_new_destination[after_block] = max(
                    max_new_destination.get(after_block, 0), new_after)

    if event_count != expected_events or changed_children_seen != set(changed_layouts):
        raise ValueError("complete native trace did not include the target Localize value child")

    stream5_intervals = sorted((item for item in intervals if item["stream"] == 5),
                               key=lambda item: item["old_start"])
    stream5_starts = [item["old_start"] for item in stream5_intervals]
    if any(left["old_end"] > right["old_start"]
           for left, right in zip(stream5_intervals, stream5_intervals[1:])):
        raise ValueError("native trace contains overlapping stream-5 physical allocations")

    def map_stream5_target(offset: int) -> int:
        for index, (start, end) in changed_ranges.items():
            if start <= offset < end:
                raise ValueError(
                    f"packed pointer targets changed Localize value {index}; "
                    "substring alias semantics are unproven")
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
    preserved_receipts: list[dict] = []
    for alias in preserved_values:
        owner, raw, target = alias["owner"], alias["raw"], alias["target"]
        if raw >> 32 == 5:
            valid_target = target == (raw & 0xFFFFFFFF) - 1
            validated_absolute_aliases += 1
        elif raw >> 32 == 0x15:
            base = alias["original_base"]
            valid_target = isinstance(base, int) and target == base + (raw & 0xFFFFFFFF) - 1
            validated_asset_relative_aliases += 1
        else:
            valid_target = False
        archive_field = map_field_location(owner, alias["field"])
        root_matches = [item for item in intervals
                        if item["owner"] == owner and item["stream"] == 1 and
                        item["old_start"] == alias["root"]["offset"] and item["size"] == 16 and
                        item["caller_rva"] == LOCALIZE_ROOT_CALLER_RVA and
                        item["reader_start_arg"] == 0]
        if (not valid_target or len(root_matches) != 1 or
                archive_field != root_matches[0]["archive_start"] + 8 or
                asset_end_cursors.get(owner) != alias["archive_offset"] or
                struct.unpack_from("<Q", changed, archive_field)[0] != raw):
            raise ValueError("shared Localize value lacks an exact root/token/final-child trace")
        key = (owner, alias["field"]["stream"], alias["field"]["offset"])
        if key in patch_fields:
            raise ValueError("trace reports the same packed field more than once")
        patch_fields.add(key)
        struct.pack_into("<Q", changed, archive_field, INLINE)
        preserved_receipts.append(dict(asset_index=owner,
                                        source_asset_index=alias["source_asset_index"],
                                        value_bytes=len(alias["value"]),
                                        archive_offset=alias["archive_offset"],
                                        value_sha256=hashlib.sha256(alias["value"]).hexdigest()))
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

    # Apply replacements and preserved-value insertions in original archive
    # coordinates. Pointer field patches move with their owning root bytes.
    splices = [(layout.value_archive_offset, layout.value_bytes, replacements[index])
               for index, layout in changed_layouts.items()]
    splices.extend((item["archive_offset"], 0, item["value"]) for item in preserved_values)
    ordered = sorted(splices, key=lambda item: item[0])
    if any(left[0] == right[0] or left[0] + left[1] > right[0]
           for left, right in zip(ordered, ordered[1:])):
        raise ValueError("Localize value edits and shared-value copies overlap")
    for start, size, replacement in reversed(ordered):
        changed[start:start + size] = replacement
    result = bytes(changed)
    if ZoneBody.parse(result).assets != ZoneBody.parse(body_data).assets:
        raise AssertionError("Localize value growth changed the XAsset table")
    edits = [dict(asset_index=index, asset_name=layouts[index].asset_name,
                  root_archive_offset=layouts[index].root_archive_offset,
                  value_archive_offset=layouts[index].value_archive_offset,
                  old_value_bytes=layouts[index].value_bytes,
                  new_value_bytes=len(replacements[index]),
                  physical_extent_delta=child_deltas[index],
                  old_value_sha256=layouts[index].value_sha256,
                  new_value_sha256=hashlib.sha256(replacements[index]).hexdigest())
             for index in sorted(changed_layouts)]
    return result, dict(
        status="trace-relocated-localize-variable-value-batch-ready",
        edits=edits,
        physical_extent_delta=sum(child_deltas.values()) +
                              sum(len(item["value"]) for item in preserved_values),
        stream5_old_high_water=max_old_destination.get(5, 0),
        stream5_new_high_water=max_new_destination.get(5),
        stream5_extent_delta=(max_new_destination.get(5, 0) -
                              max_old_destination.get(5, 0)),
        stream_reservation_sizes=[max_new_destination.get(index, 0)
                                  for index in range(11)],
        stream_reservation_deltas=[max_new_destination.get(index, 0) -
                                  max_old_destination.get(index, 0)
                                  for index in range(11)],
        packed_stream5_aliases_scanned=len(aliases) + len(preserved_values),
        packed_stream5_tag5_absolute_validated=validated_absolute_aliases,
        packed_stream5_tag15_asset_relative_validated=validated_asset_relative_aliases,
        packed_stream5_aliases_rebased=patched_alias_count,
        shared_localize_values_preserved=preserved_receipts,
        xasset_table_unchanged=True,
        full_native_trace_events=event_count)



def replace_localize_values_with_relocation(body_data: bytes, edits: list[dict],
                                             expected_body_sha256: str,
                                             trace_path: str | Path,
                                             manifest_path: str | Path) -> tuple[bytes, dict]:
    """Apply NUL-terminated UTF-8 value edits of any byte length.

    Each edit supplies asset_index, asset_name, trace_asset and value; optional
    expected_key/expected_value fields bind the edit to the typed source snapshot.
    """
    source = ZoneBody.parse(body_data)
    if source.source_sha256 != expected_body_sha256:
        raise ValueError("Localize edit batch belongs to a different decoded body")
    if not isinstance(edits, list) or not edits:
        raise ValueError("Localize relocation requires at least one edit")
    layouts: dict[int, Any] = {}
    replacements: dict[int, bytes] = {}
    edit_metadata: dict[int, dict] = {}
    for edit in edits:
        if not isinstance(edit, dict):
            raise ValueError("Localize edit must be a mapping")
        index = edit.get("asset_index")
        name = edit.get("asset_name")
        trace_asset = edit.get("trace_asset")
        value = edit.get("value")
        if not isinstance(index, int) or isinstance(index, bool) or index in layouts:
            raise ValueError("Localize edit index is invalid or repeated")
        if not isinstance(name, str) or not isinstance(trace_asset, dict):
            raise ValueError("Localize edit is missing its typed identity/trace row")
        if not isinstance(value, str) or "\0" in value:
            raise ValueError("Localize value must be NUL-free UTF-8 text")
        encoded = value.encode("utf-8") + b"\0"
        layout, semantic = inspect_localize_entry(
            body_data, index, name, trace_asset, expected_body_sha256,
            edit.get("expected_key"), edit.get("expected_value"))
        layouts[index] = SimpleNamespace(
            asset_index=index, asset_name=name,
            root_archive_offset=layout.root_archive_offset,
            value_archive_offset=layout.value_archive_offset,
            value_stream_offset=layout.value_stream_offset,
            value_bytes=layout.value_bytes,
            value_sha256=hashlib.sha256(
                body_data[layout.value_archive_offset:layout.value_archive_offset + layout.value_bytes]
            ).hexdigest())
        replacements[index] = encoded
        edit_metadata[index] = dict(old_value=semantic["value"], new_value=value,
                                    source_key=semantic["key"])
    updated, relocation = _relocate_stream5_localize_values(
        body_data, layouts, replacements, trace_path, manifest_path)
    if ZoneBody.parse(updated).assets != source.assets:
        raise AssertionError("Localize value relocation changed XAsset type/order/pointers")
    relocation["schema"] = 1
    relocation["status"] = ("semantic-noop-localize-batch" if updated == body_data else
                             "trace-relocated-localize-value-batch-ready")
    relocation["source_body_sha256"] = expected_body_sha256
    relocation["output_body_sha256"] = hashlib.sha256(updated).hexdigest()
    relocation["edit_count"] = len(edits)
    for row in relocation.get("edits", []):
        row.update(edit_metadata[row["asset_index"]])
    relocation["support_limit"] = (
        "ordinary/shared-inline type-41 LocalizeEntry values; other Localize values sharing "
        "edited text become independent inline copies; XAsset rows and keys remain unchanged")
    return updated, relocation
