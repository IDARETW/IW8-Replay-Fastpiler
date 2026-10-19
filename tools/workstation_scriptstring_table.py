"""Bounded Replay XAssetList ScriptString prefix parsing and interning.

This module only models the physical ScriptStringList prefix. It does not
rewrite typed ``scr_string_t`` fields or relocate the remainder of a zone;
callers must supply those typed field locations to a later relocation step.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
import hashlib

from inspect_frontend_asset_table import inspect as inspect_xasset_list

INLINE_TOKENS = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE}
NULL_TOKEN = 0


@dataclass(frozen=True)
class ScriptStringList:
    # `values` are physical serialized array slots; Replay lookup uses their
    # zero-based indices.
    count: int
    token: int
    tokens: tuple[int, ...]
    values: tuple[str | None, ...]
    names_end: int
    asset_table_offset: int
    prefix_bytes: bytes


@dataclass(frozen=True)
class ScriptStringMerge:
    values: tuple[str | None, ...]
    source_id_map: tuple[int | None, ...]
    source_id_maps: tuple[tuple[int | None, ...], ...]
    target_id_map: tuple[int, ...]
    prefix: bytes
    old_asset_table_offset: int
    new_asset_table_offset: int
    table_shift: int


def parse_scriptstring_list(body: bytes) -> ScriptStringList:
    """Parse the complete physical ScriptStringList prefix, preserving IDs."""
    table = inspect_xasset_list(body)
    count = table["script_string_count"]
    if len(body) < 32 + count * 8:
        raise ValueError("truncated ScriptStringList token array")
    _count, reserved0, token, _asset_count, reserved1, _assets = struct.unpack_from(
        "<IIQIIQ", body, 0)
    if reserved0 or reserved1:
        raise ValueError("unverified XAssetList reserved fields")
    tokens = struct.unpack_from(f"<{count}Q", body, 32) if count else ()
    cursor = 32 + count * 8
    values: list[str | None] = []
    for index, raw in enumerate(tokens):
        if raw == NULL_TOKEN:
            values.append(None)
            continue
        if raw not in INLINE_TOKENS:
            raise ValueError(f"ScriptString ID {index} uses an unsupported packed token")
        end = body.find(b"\0", cursor, table["asset_table_offset"])
        if end < 0:
            raise ValueError(f"ScriptString ID {index} has no bounded NUL terminator")
        encoded = body[cursor:end]
        try:
            value = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError(f"ScriptString ID {index} is not valid UTF-8") from error
        if not value:
            raise ValueError(f"ScriptString ID {index} is unexpectedly empty")
        values.append(value)
        cursor = end + 1
    if cursor != table["asset_table_offset"]:
        raise ValueError("ScriptString strings do not end at the physical XAsset table")
    if count == 0 and token not in (0, *INLINE_TOKENS):
        raise ValueError("empty ScriptStringList has an unsupported pointer token")
    return ScriptStringList(count, token, tuple(tokens), tuple(values), cursor,
                            table["asset_table_offset"], body[:cursor])


def _encode_prefix(root: bytes, values: tuple[str | None, ...]) -> bytes:
    if len(root) != 32:
        raise ValueError("XAssetList root must be exactly 32 bytes")
    count = len(values)
    if count > 0xFFFFFFFF:
        raise ValueError("ScriptString count exceeds the native 32-bit field")
    _old_count, reserved0, _old_token, asset_count, reserved1, asset_token = struct.unpack(
        "<IIQIIQ", root)
    if reserved0 or reserved1:
        raise ValueError("unverified XAssetList reserved fields")
    token = 0xFFFFFFFFFFFFFFFE if count else 0
    tokens = tuple(NULL_TOKEN if value is None else 0xFFFFFFFFFFFFFFFE
                   for value in values)
    result = bytearray(struct.pack("<IIQIIQ", count, 0, token,
                                   asset_count, 0, asset_token))
    if tokens:
        result.extend(struct.pack(f"<{len(tokens)}Q", *tokens))
    for index, value in enumerate(values):
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ValueError(f"ScriptString ID {index} must be a nonempty string")
        encoded = value.encode("utf-8", errors="strict")
        if b"\0" in encoded:
            raise ValueError(f"ScriptString ID {index} contains an embedded NUL")
        result.extend(encoded)
        result.append(0)
    return bytes(result)


def merge_scriptstring_prefix(target_body: bytes, source_body: bytes) -> ScriptStringMerge:
    """Intern one source list by exact UTF-8 text, preserving target indices."""
    return merge_scriptstring_prefixes(target_body, [source_body])


def merge_scriptstring_prefixes(target_body: bytes,
                                source_bodies: list[bytes]) -> ScriptStringMerge:
    """Intern ordered source lists after the target's existing physical slots.

    The returned prefix replaces the target prefix before its original XAsset
    table. Maps are physical source/target slot indices to output slot indices;
    null source slots map to ``None`` and must be rejected if referenced by a
    typed scr_string_t field. Source lists are processed in caller order, so
    callers can preserve a typed dependency plan's first-occurrence policy.
    """
    target = parse_scriptstring_list(target_body)
    values = list(target.values)
    first_id: dict[str, int] = {}
    for index, value in enumerate(values):
        if value is not None:
            first_id.setdefault(value, index)
    source_maps: list[tuple[int | None, ...]] = []
    for source_body in source_bodies:
        source = parse_scriptstring_list(source_body)
        source_map: list[int | None] = []
        for value in source.values:
            if value is None:
                source_map.append(None)
                continue
            output_id = first_id.get(value)
            if output_id is None:
                output_id = len(values)
                values.append(value)
                first_id[value] = output_id
            source_map.append(output_id)
        source_maps.append(tuple(source_map))
    if len(values) > 0xFFFFFFFF:
        raise ValueError("merged ScriptString count exceeds the native 32-bit field")
    prefix = _encode_prefix(target_body[:32], tuple(values))
    new_table_offset = len(prefix)
    return ScriptStringMerge(tuple(values),
                             source_maps[0] if len(source_maps) == 1 else (),
                             tuple(source_maps), tuple(range(target.count)), prefix,
                             target.asset_table_offset, new_table_offset,
                             new_table_offset - target.asset_table_offset)


def splice_scriptstring_prefix(target_body: bytes, source_body: bytes) -> tuple[bytes, ScriptStringMerge]:
    """Return target body with only its ScriptString prefix expanded.

    No XAsset table, child, cursor, or packed pointer is relocated here. This
    low-level operation is for proof fixtures; production use must pair it with
    typed string-ID rewrites and a full stream relocation pass.
    """
    merge = merge_scriptstring_prefix(target_body, source_body)
    target = parse_scriptstring_list(target_body)
    result = merge.prefix + target_body[target.asset_table_offset:]
    # Parse validates the rebuilt header/table extents; it does not claim that
    # payload offsets or pointer tokens have been relocated.
    rebuilt = parse_scriptstring_list(result)
    if rebuilt.values != merge.values or rebuilt.asset_table_offset != merge.new_asset_table_offset:
        raise AssertionError("rebuilt ScriptString prefix differs from its merge plan")
    return result, merge


def shift_stream_coordinate(stream: int, offset: int, *, insertion_stream: int,
                            insertion_offset: int, delta: int) -> int:
    """Shift one logical stream address across a trace-established insertion."""
    if (not all(isinstance(value, int) and not isinstance(value, bool)
                for value in (stream, offset, insertion_stream, insertion_offset, delta)) or
            stream < 0 or insertion_stream < 0 or offset < 0 or insertion_offset < 0 or
            delta < 0):
        raise ValueError("stream insertion coordinates must be nonnegative integers")
    if stream != insertion_stream or offset < insertion_offset:
        return offset
    shifted = offset + delta
    if shifted > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("relocated stream coordinate exceeds the native 64-bit range")
    return shifted


def rebase_packed_scriptstring_prefix(raw_token: int, *, target_stream: int,
                                      target_offset: int, asset_base: int | None,
                                      insertion_stream: int, insertion_offset: int,
                                      delta: int) -> tuple[int, int]:
    """Rebase a trace-validated tag-5 or asset-local tag-0x15 address.

    This operates only on a token whose old target and asset base were already
    proven by the native trace. It does not discover pointer fields or owners.
    """
    if not isinstance(raw_token, int) or not 0 <= raw_token <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("packed pointer token must be an unsigned 64-bit integer")
    if not isinstance(target_offset, int) or not 0 <= target_offset <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("packed pointer target offset is invalid")
    tag, low = raw_token >> 32, raw_token & 0xFFFFFFFF
    if tag == 5:
        if target_stream != 5 or low == 0 or low - 1 != target_offset:
            raise ValueError("tag-5 token does not match its traced absolute target")
        new_target = shift_stream_coordinate(target_stream, target_offset,
            insertion_stream=insertion_stream, insertion_offset=insertion_offset, delta=delta)
        new_low = new_target + 1
    elif tag == 0x15:
        if (target_stream != 5 or asset_base is None or
                not 0 <= asset_base <= 0xFFFFFFFFFFFFFFFF or low == 0 or
                target_offset != asset_base + low - 1):
            raise ValueError("tag-0x15 token lacks its traced asset-relative base/target")
        new_target = shift_stream_coordinate(target_stream, target_offset,
            insertion_stream=insertion_stream, insertion_offset=insertion_offset, delta=delta)
        new_base = shift_stream_coordinate(5, asset_base,
            insertion_stream=insertion_stream, insertion_offset=insertion_offset, delta=delta)
        new_low = new_target - new_base + 1
    else:
        raise ValueError(f"packed pointer tag {tag:#x} is not supported for prefix relocation")
    if not 0 < new_low <= 0xFFFFFFFF:
        raise ValueError("relocated packed pointer exceeds its 32-bit offset field")
    return (tag << 32) | new_low, new_target


def rewrite_scriptstring_fields(body: bytes, fields: list[dict]) -> tuple[bytes, dict]:
    """Rewrite explicitly owned scr_string_t arrays through an ID-slot map.

    Each field specification must include ``physical_start``, ``count``,
    ``stride`` (currently exactly 4), ``source_ids`` (the complete expected
    u32 vector), and ``slot_map`` (serialized source slot -> output slot or
    None). A null/unmapped slot is rejected if a field actually references it.
    Field ownership itself must come from the caller's typed native contract.
    """
    original = bytes(body)
    edits: list[tuple[int, int, bytes, dict]] = []
    for number, field in enumerate(fields):
        if not isinstance(field, dict):
            raise ValueError(f"ScriptString field {number} is not an object")
        start, count, stride = (field.get("physical_start"), field.get("count"),
                                field.get("stride"))
        source_ids, slot_map = field.get("source_ids"), field.get("slot_map")
        if (not isinstance(start, int) or isinstance(start, bool) or start < 0 or
                not isinstance(count, int) or isinstance(count, bool) or count < 0 or
                stride != 4 or not isinstance(source_ids, list) or
                len(source_ids) != count or not isinstance(slot_map, (list, tuple))):
            raise ValueError(f"ScriptString field {number} has an incomplete typed extent/map")
        extent = count * stride
        if start + extent > len(original):
            raise ValueError(f"ScriptString field {number} exceeds the source body")
        if any(not isinstance(value, int) or isinstance(value, bool) or
               not 0 <= value <= 0xFFFFFFFF for value in source_ids):
            raise ValueError(f"ScriptString field {number} has an invalid source ID")
        actual = list(struct.unpack_from(f"<{count}I", original, start)) if count else []
        if actual != source_ids:
            raise ValueError(f"ScriptString field {number} source bytes differ from its typed contract")
        mapped = []
        for source_id in source_ids:
            if source_id >= len(slot_map):
                raise ValueError(f"ScriptString field {number} references an unmapped source slot")
            target_id = slot_map[source_id]
            if target_id is None:
                raise ValueError(f"ScriptString field {number} references a null/unmapped source slot")
            if (not isinstance(target_id, int) or isinstance(target_id, bool) or
                    not 0 <= target_id <= 0xFFFFFFFF):
                raise ValueError(f"ScriptString field {number} maps to an invalid target slot")
            mapped.append(target_id)
        replacement = struct.pack(f"<{count}I", *mapped) if count else b""
        edits.append((start, start + extent, replacement, {
            "field": field.get("field", str(number)), "physical_start": start,
            "count": count, "source_ids": source_ids, "target_ids": mapped,
        }))
    edits.sort(key=lambda item: (item[0], item[1]))
    for prior, current in zip(edits, edits[1:]):
        if prior[1] > current[0]:
            raise ValueError("typed ScriptString field extents overlap")
    updated = bytearray(original)
    for start, end, replacement, _receipt in edits:
        updated[start:end] = replacement
    result = bytes(updated)
    return result, {
        "schema": "replay120-scriptstring-field-rewrite-v1",
        "source_body_sha256": hashlib.sha256(original).hexdigest(),
        "output_body_sha256": hashlib.sha256(result).hexdigest(),
        "fields": [item[3] for item in edits],
    }
