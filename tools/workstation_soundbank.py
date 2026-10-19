"""Typed, source-pinned reader for Replay 1.20 SoundBank alias identities.

The reader is observational: all unknown root and record bytes remain in the
receipt as raw hex. Asset names and file IDs are exposed only where native
trace field ownership resolves the exact serialized XString.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import struct
from typing import Any

import workstation_sab_editor as sab

ROOT_SIZE = 512
ALIAS_LIST_SIZE = 32
ALIAS_SIZE = 232
ALIAS_SCALAR_FLOAT_OFFSETS = {
    "volMin": 76,
    "volMax": 80,
    "pitchMin": 88,
    "pitchMax": 92,
}

# Replay's native 232-byte record extent is proven, but the parameter words
# other than the four established editable floats remain raw/unknown here.
ALIAS_SCALAR_REGION_OFFSET = 44
ALIAS_SCALAR_REGION_BYTES = 164
ALIAS_MASTER_WORD_OFFSETS = (212, 216, 220)
INLINE_SHARED = 0xFFFFFFFFFFFFFFFF
INLINE = 0xFFFFFFFFFFFFFFFE
_GLOBAL_STRING_CACHE: dict[tuple[str, int, int, str], dict[int, dict]] = {}


def _load_asset_events(trace_path: Path, asset_index: int) -> list[dict]:
    events = []
    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if f'"xasset_index":{asset_index}' not in line:
                continue
            row = json.loads(line)
            if row.get("xasset_index") != asset_index:
                continue
            events.append(row)
            if row.get("kind") == "xasset_end":
                break
    if (not events or events[0].get("kind") != "xasset_begin" or
            events[-1].get("kind") != "xasset_end" or
            events[0].get("type_id") != 21 or events[-1].get("type_id") != 21):
        raise ValueError("trace does not contain one complete selected type-21 asset group")
    return events


def _physical_loads(events: list[dict]) -> list[dict]:
    calls = {row["sequence"]: row for row in events if row.get("kind") == "load_stream_call"}
    result = []
    for row in events:
        if row.get("kind") != "stream_operation" or row.get("operation") != "load":
            continue
        size = row.get("physical_input_bytes", 0)
        if not size:
            continue
        call = calls.get(row.get("sequence", -1) - 1, {})
        result.append({"sequence": row["sequence"], "archive_offset": row["input_before"],
                       "size": size, "stream": row["block_after"],
                       "destination": call.get("destination_stream_location"),
                       "start_arg": call.get("loader_start_arg")})
    return result


def _snd_hash(value: str) -> int:
    result = 5381
    for byte in value.lower().encode("ascii"):
        result = (result * 65599 + byte) & 0xFFFFFFFF
    return result or 1


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path_sha(path: Path) -> str:
    return _sha(path.read_bytes())


def _json_sha(obj: Any) -> str:
    return _sha(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8"))


def _alias_scalar_values(raw: bytes) -> tuple[dict[str, float | None], dict[str, str]]:
    """Expose finite Replay float32 values without serializing NaN/Inf JSON."""
    if len(raw) != ALIAS_SIZE:
        raise ValueError("Replay SndAlias record must be exactly 232 bytes")
    values, read_only_bits = {}, {}
    for field, offset in ALIAS_SCALAR_FLOAT_OFFSETS.items():
        bits = struct.unpack_from("<I", raw, offset)[0]
        value = struct.unpack_from("<f", raw, offset)[0]
        if math.isfinite(value):
            values[field] = value
        else:
            values[field] = None
            read_only_bits[field] = f"0x{bits:08x}"
    return values, read_only_bits


def _alias_native_word_inspection(raw: bytes) -> dict[str, Any]:
    """Expose complete opaque parameter/tail words without assigning semantics."""
    if len(raw) != ALIAS_SIZE:
        raise ValueError("Replay SndAlias record must be exactly 232 bytes")
    editable_scalar_offsets = {
        offset for offset in ALIAS_SCALAR_FLOAT_OFFSETS.values()
        if ALIAS_SCALAR_REGION_OFFSET <= offset <
        ALIAS_SCALAR_REGION_OFFSET + ALIAS_SCALAR_REGION_BYTES
    }
    return {
        "scalarWords": {
            str(ALIAS_SCALAR_REGION_OFFSET + index * 4):
                raw[ALIAS_SCALAR_REGION_OFFSET + index * 4:
                    ALIAS_SCALAR_REGION_OFFSET + (index + 1) * 4].hex()
            for index in range(ALIAS_SCALAR_REGION_BYTES // 4)
            if ALIAS_SCALAR_REGION_OFFSET + index * 4 not in editable_scalar_offsets
        },
        "tailWords": {str(offset): raw[offset:offset + 4].hex()
                      for offset in ALIAS_MASTER_WORD_OFFSETS},
        "otherBytes": {
            "stereoSpreadMaxAngle": raw[208:209].hex(),
            "masterPriority": raw[209:210].hex(),
            "reserved210": raw[210:212].hex(),
            "maxDuration": raw[224:226].hex(),
            "reserved226": raw[226:232].hex(),
        },
    }


def soundbank_edit_document(bank_receipt: dict) -> dict:
    """Return the deliberately narrow public JSON surface for type-21 aliases."""
    if (bank_receipt.get("asset_type") != 21 or
            bank_receipt.get("schema") != "replay120-typed-soundbank-alias-map-v1"):
        raise ValueError("SoundBank editor requires one validated type-21 native receipt")
    aliases = []
    for row in bank_receipt.get("aliases", []):
        record = bytes.fromhex(row.get("raw_hex", ""))
        if len(record) != ALIAS_SIZE or _sha(record) != row.get("raw_sha256"):
            raise ValueError("SoundBank alias record differs from its native receipt")
        values, read_only_bits = _alias_scalar_values(record)
        alias = {
            "listIndex": row["list_index"],
            "listName": row["list_name"],
            "aliasIndex": row["alias_index_in_list"],
            "aliasName": row["alias_name"],
            "assetFileName": row["asset_file_name"],
            "fileId": row["file_id"],
            "nativeWordInspection": _alias_native_word_inspection(record),
            **values,
        }
        if read_only_bits:
            alias["readOnlyFieldBits"] = read_only_bits
        aliases.append(alias)
    return {"soundBank": bank_receipt["asset_name"], "aliases": aliases}


def validate_soundbank_edit_document(content: str, bank_receipt: dict) -> list[dict]:
    """Validate immutable alias identity and return only changed float32 words."""
    if not isinstance(content, str):
        raise ValueError("SoundBank editor content must be JSON text")

    def reject_constant(value: str):
        raise ValueError(f"non-finite JSON number {value} is not supported")

    try:
        document = json.loads(content, parse_constant=reject_constant)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError("SoundBank editor content is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {"soundBank", "aliases"}:
        raise ValueError("SoundBank document must contain only soundBank and aliases")
    if document["soundBank"] != bank_receipt.get("asset_name"):
        raise ValueError("SoundBank identity is immutable")
    source_rows = bank_receipt.get("aliases")
    edits = document["aliases"]
    if not isinstance(source_rows, list) or not isinstance(edits, list) or len(source_rows) != len(edits):
        raise ValueError("SoundBank alias count and order are immutable")
    identity_fields = ("listIndex", "listName", "aliasIndex", "aliasName", "assetFileName", "fileId")
    allowed_fields = (set(identity_fields) | set(ALIAS_SCALAR_FLOAT_OFFSETS) |
                      {"readOnlyFieldBits", "nativeWordInspection"})
    changed_rows = []
    for position, (source, edit) in enumerate(zip(source_rows, edits)):
        if not isinstance(edit, dict) or set(edit) - allowed_fields:
            raise ValueError(f"SoundBank alias row {position} contains unsupported fields")
        expected_identity = {
            "listIndex": source["list_index"], "listName": source["list_name"],
            "aliasIndex": source["alias_index_in_list"], "aliasName": source["alias_name"],
            "assetFileName": source["asset_file_name"], "fileId": source["file_id"],
        }
        if any(key not in edit or type(edit.get(key)) is not type(value) or edit.get(key) != value
               for key, value in expected_identity.items()):
            raise ValueError(f"SoundBank alias identity/order changed at row {position}")
        raw = bytes.fromhex(source.get("raw_hex", ""))
        if len(raw) != ALIAS_SIZE or _sha(raw) != source.get("raw_sha256"):
            raise ValueError("source SndAlias record does not match its native receipt")
        original, readonly = _alias_scalar_values(raw)
        if edit.get("readOnlyFieldBits", {}) != readonly:
            raise ValueError(f"read-only SoundBank float bits changed at row {position}")
        if ("nativeWordInspection" in edit and
                edit["nativeWordInspection"] != _alias_native_word_inspection(raw)):
            raise ValueError(f"read-only native SoundBank words changed at row {position}")
        values, bits, changed_fields = {}, {}, []
        for field, offset in ALIAS_SCALAR_FLOAT_OFFSETS.items():
            if field not in edit:
                raise ValueError(f"SoundBank alias row {position} omits {field}")
            value = edit[field]
            if field in readonly:
                if value is not None:
                    raise ValueError(f"non-finite source field {field} is read-only")
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f"{field} must be a finite number")
            try:
                packed = struct.pack("<f", float(value))
            except (OverflowError, struct.error) as error:
                raise ValueError(f"{field} is outside float32 range") from error
            value32 = struct.unpack("<f", packed)[0]
            if not math.isfinite(value32):
                raise ValueError(f"{field} is outside finite float32 range")
            bits[field] = packed
            values[field] = value32
            original_bits = raw[offset:offset + 4]
            if packed != original_bits:
                changed_fields.append(field)
        if changed_fields:
            volume_changed = any(field in changed_fields for field in ("volMin", "volMax"))
            pitch_changed = any(field in changed_fields for field in ("pitchMin", "pitchMax"))
            if volume_changed:
                if any(values.get(field) is None or values[field] < 0
                       for field in ("volMin", "volMax")) or values["volMin"] > values["volMax"]:
                    raise ValueError("changed volume range must be finite, nonnegative, and min <= max")
            if pitch_changed:
                if any(values.get(field) is None or values[field] <= 0
                       for field in ("pitchMin", "pitchMax")) or values["pitchMin"] > values["pitchMax"]:
                    raise ValueError("changed pitch range must be finite, positive, and min <= max")
            changed_rows.append({"list_index": source["list_index"],
                                 "alias_index_in_list": source["alias_index_in_list"],
                                 "archive_offset": source["archive_offset"],
                                 "source_raw_sha256": source["raw_sha256"],
                                 "fields": {field: bits[field].hex() for field in changed_fields}})
    return changed_rows


def replace_soundbank_alias_scalars(body: bytes, bank_receipt: dict,
                                    changes: list[dict]) -> tuple[bytes, dict]:
    """Patch only trace-owned same-extent public SndAlias float words."""
    identity_payload = dict(bank_receipt)
    identity = identity_payload.pop("source_identity_sha256", None)
    identity_payload.pop("sab_links", None)
    if not isinstance(identity, str) or _json_sha(identity_payload) != identity:
        raise ValueError("SoundBank receipt was altered after native trace validation")
    provenance = bank_receipt.get("provenance", {})
    body_identity = provenance.get("source_body", {})
    if (bank_receipt.get("asset_type") != 21 or body_identity.get("sha256") != _sha(body) or
            body_identity.get("bytes") != len(body)):
        raise ValueError("SoundBank scalar writer body differs from its native receipt")
    source_rows = bank_receipt.get("aliases", [])
    by_identity = {(row.get("list_index"), row.get("alias_index_in_list")): row
                   for row in source_rows}
    if len(by_identity) != len(source_rows):
        raise ValueError("SoundBank receipt contains duplicate alias identities")
    result = bytearray(body)
    writes, touched = [], set()
    for change in changes:
        key = (change.get("list_index"), change.get("alias_index_in_list"))
        source = by_identity.get(key)
        if source is None or source.get("archive_offset") != change.get("archive_offset"):
            raise ValueError("SoundBank edit no longer identifies one trace-owned alias row")
        raw = bytes.fromhex(source.get("raw_hex", ""))
        start = source["archive_offset"]
        if (len(raw) != ALIAS_SIZE or _sha(raw) != source.get("raw_sha256") or
                source.get("raw_sha256") != change.get("source_raw_sha256") or
                start < bank_receipt["asset_archive_span"][0] or
                start + ALIAS_SIZE > bank_receipt["asset_archive_span"][1] or
                bytes(body[start:start + ALIAS_SIZE]) != raw):
            raise ValueError("SoundBank alias archive ownership or bytes changed after native read")
        if key in touched:
            raise ValueError("SoundBank alias edit repeats one native record")
        touched.add(key)
        fields = change.get("fields")
        if not isinstance(fields, dict) or not fields or set(fields) - set(ALIAS_SCALAR_FLOAT_OFFSETS):
            raise ValueError("SoundBank edit contains unsupported scalar fields")
        proposed, changed_fields = _alias_scalar_values(raw)[0], set()
        for field, encoded in fields.items():
            if not isinstance(encoded, str) or len(encoded) != 8:
                raise ValueError(f"SoundBank {field} replacement is not one float32 word")
            word = bytes.fromhex(encoded)
            value = struct.unpack("<f", word)[0]
            if not math.isfinite(value):
                raise ValueError(f"SoundBank {field} replacement is not finite")
            offset = ALIAS_SCALAR_FLOAT_OFFSETS[field]
            if bytes(result[start + offset:start + offset + 4]) != raw[offset:offset + 4]:
                raise ValueError(f"SoundBank {field} source word changed after native read")
            if word == raw[offset:offset + 4]:
                raise ValueError(f"SoundBank {field} replacement does not change its source word")
            proposed[field] = value
            changed_fields.add(field)
            result[start + offset:start + offset + 4] = word
            writes.append({"list_index": key[0], "alias_index_in_list": key[1],
                           "field": field, "archive_offset": start + offset,
                           "source_bits": raw[offset:offset + 4].hex(),
                           "result_bits": word.hex()})
        if changed_fields & {"volMin", "volMax"}:
            if (any(proposed.get(field) is None or proposed[field] < 0
                    for field in ("volMin", "volMax")) or
                    proposed["volMin"] > proposed["volMax"]):
                raise ValueError("written volume range must be finite, nonnegative, and min <= max")
        if changed_fields & {"pitchMin", "pitchMax"}:
            if (any(proposed.get(field) is None or proposed[field] <= 0
                    for field in ("pitchMin", "pitchMax")) or
                    proposed["pitchMin"] > proposed["pitchMax"]):
                raise ValueError("written pitch range must be finite, positive, and min <= max")
    updated = bytes(result)
    if len(updated) != len(body):
        raise AssertionError("same-extent SoundBank scalar writer changed body length")
    if updated == body:
        raise ValueError("SoundBank edit does not change any supported scalar word")
    return updated, {"schema": "replay120-soundbank-alias-scalar-write-v1",
                     "asset_type": 21, "fields_written": len(writes), "writes": writes,
                     "body_bytes_preserved": True, "asset_roots_and_counts_unchanged": True}


def _global_string_index(trace_path: Path, body: bytes) -> dict[int, dict]:
    """Index native block-5 string allocations used by cross-asset aliases."""
    stat_result = trace_path.stat()
    cache_key = (str(trace_path.resolve()), stat_result.st_size,
                 stat_result.st_mtime_ns, _sha(body))
    cached = _GLOBAL_STRING_CACHE.get(cache_key)
    if cached is not None:
        return cached
    result = {}
    string_ops = []
    physical_reads = set()
    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if '"kind":"stream_operation"' not in line or '"operation":"string"' not in line:
                if '"kind":"stream_operation"' not in line or '"operation":"load"' not in line:
                    continue
                row = json.loads(line)
                if (row.get("kind") == "stream_operation" and row.get("operation") == "load" and
                        row.get("block_after") == 5 and row.get("physical_input_bytes", 0) > 0):
                    physical_reads.add((row.get("input_before"), row.get("physical_input_bytes")))
                continue
            row = json.loads(line)
            if row.get("kind") != "stream_operation":
                continue
            if row.get("operation") == "load":
                if row.get("block_after") == 5 and row.get("physical_input_bytes", 0) > 0:
                    physical_reads.add((row.get("input_before"), row.get("physical_input_bytes")))
                continue
            if row.get("operation") == "string" and row.get("block_after") == 5:
                string_ops.append(row)
    for row in string_ops:
        size, start = row.get("size"), row.get("input_before")
        if ((start, size) not in physical_reads or not isinstance(size, int) or size <= 0 or
                not isinstance(start, int) or start + size > len(body)):
            continue
        raw = body[start:start + size]
        if not raw.endswith(b"\0"):
            continue
        try:
            value = raw[:-1].decode("ascii")
        except UnicodeDecodeError:
            continue
        result[row["offset_before"]] = {
            "value": value, "archive_span": [start, start + size],
            "sha256": _sha(raw), "sequence": row.get("sequence"),
        }
    _GLOBAL_STRING_CACHE.clear()
    _GLOBAL_STRING_CACHE[cache_key] = result
    return result


def _read_string(events: list[dict], loads: list[dict], body: bytes,
                 field_location: dict, raw_token: int,
                 global_strings: dict[int, dict]) -> tuple[str | None, dict]:
    """Resolve one string token only through its exact native field event."""
    edge = next((row for row in events if row.get("kind") == "packed_resolve" and
                 row.get("field_stream_location") == field_location), None)
    call = next((row for row in events if row.get("kind") == "string_call" and
                 row.get("field_stream_location") == field_location), None)
    if raw_token == 0:
        if edge or call:
            raise ValueError("null string token unexpectedly has a native string edge")
        return None, {"kind": "null", "raw_token": raw_token}
    if call:
        operation = next((row for row in events if row.get("kind") == "stream_operation" and
                          row.get("operation") == "string" and
                          row["sequence"] > call["sequence"]), None)
        if not operation or not operation.get("size"):
            raise ValueError("native inline string call has no bounded string operation")
        candidates = [row for row in loads if row["archive_offset"] == operation["input_before"] and
                      row["size"] == operation["size"] and row["stream"] == 5]
        if len(candidates) != 1:
            raise ValueError("native inline string does not have one matching physical read")
        load = candidates[0]
        raw = body[load["archive_offset"]:load["archive_offset"] + load["size"]]
        if not raw.endswith(b"\0"):
            raise ValueError("native string read is not NUL terminated")
        return raw[:-1].decode("ascii"), {
            "kind": "native_inline_string", "raw_token": raw_token,
            "archive_span": [load["archive_offset"], load["archive_offset"] + load["size"]],
            "stream5_offset": operation["offset_before"],
            "string_sha256": _sha(raw),
        }
    if edge:
        target = edge.get("resolved_target_stream_location")
        if not isinstance(target, dict) or target.get("stream") != 5:
            raise ValueError("packed sound string does not resolve to stream 5")
        target_offset = target.get("offset")
        operation = next((row for row in events if row.get("kind") == "stream_operation" and
                          row.get("operation") == "string" and
                          row.get("block_after") == 5 and row.get("offset_before") == target_offset), None)
        # Shared packed XStrings may point at a string loaded by an earlier
        # field; in that case the exact target must match its captured start.
        if operation:
            candidates = [row for row in loads if row["archive_offset"] == operation["input_before"] and
                          row["size"] == operation["size"] and row["stream"] == 5]
            if len(candidates) != 1:
                raise ValueError("packed string target has no unique source read")
            load = candidates[0]
            raw = body[load["archive_offset"]:load["archive_offset"] + load["size"]]
            if not raw.endswith(b"\0"):
                raise ValueError("packed string target is not NUL terminated")
            return raw[:-1].decode("ascii"), {
                "kind": "packed_stream5_string", "raw_token": raw_token,
                "resolved_target": target,
                "archive_span": [load["archive_offset"], load["archive_offset"] + load["size"]],
                "string_sha256": _sha(raw),
            }
        if raw_token >> 32 == 0x5 and target_offset in global_strings:
            match = global_strings[target_offset]
            return match["value"], {
                "kind": "global_prior_string", "raw_token": raw_token,
                "resolved_target": target, "archive_span": match["archive_span"],
                "string_sha256": match["sha256"], "trace_sequence": match["sequence"],
            }
        # A local packed token can point at an earlier string without a new read.
        prior = [row for row in events if row.get("kind") == "stream_operation" and
                 row.get("operation") == "string" and row.get("block_after") == 5 and
                 row.get("offset_before") == target_offset]
        if not prior:
            raise ValueError("packed string target is not an exact trace-owned string start")
        op = prior[-1]
        candidates = [row for row in loads if row["archive_offset"] == op["input_before"] and
                      row["size"] == op["size"] and row["stream"] == 5]
        if len(candidates) != 1:
            raise ValueError("packed prior string has no unique physical extent")
        load = candidates[0]
        raw = body[load["archive_offset"]:load["archive_offset"] + load["size"]]
        if not raw.endswith(b"\0"):
            raise ValueError("packed prior string is not NUL terminated")
        return raw[:-1].decode("ascii"), {
            "kind": "packed_prior_string", "raw_token": raw_token,
            "resolved_target": target,
            "archive_span": [load["archive_offset"], load["archive_offset"] + load["size"]],
            "string_sha256": _sha(raw),
        }
    raise ValueError("non-null sound string token has no exact string or packed-reference owner")


def _root_fields(raw: bytes) -> dict:
    if len(raw) != ROOT_SIZE:
        raise ValueError("SoundBank root must be exactly 512 bytes")
    fields: dict[str, Any] = {"raw_hex": raw.hex()}
    for name, off in (("name", 0), ("zone", 8), ("gameLanguage", 16), ("soundLanguage", 24)):
        fields[name] = struct.unpack_from("<Q", raw, off)[0]
    for name, count_off, ptr_off in (
        ("aliases", 32, 40), ("aliasIndex", 32, 48), ("sendEffects", 56, 64),
        ("ducks", 304, 312), ("musicSets", 320, 328), ("weaponReflections", 336, 344),
        ("dopplerPresets", 352, 360), ("occlusionShapes", 368, 376),
        ("focusCones", 384, 392), ("volumeFalloffCurves", 400, 408),
        ("lowPassCurves", 416, 424), ("highPassCurves", 432, 440),
        ("reverbCurves", 448, 456), ("speakerMaps", 464, 472), ("futzs", 480, 488),
    ):
        fields[name] = {"count": struct.unpack_from("<I", raw, count_off)[0],
                        "token": struct.unpack_from("<Q", raw, ptr_off)[0],
                        "count_offset": count_off, "pointer_offset": ptr_off}
    fields["soundTable_raw_hex"] = raw[72:304].hex()
    fields["loadedStreamKey"] = struct.unpack_from("<Q", raw, 496)[0]
    fields["alwaysLoaded_raw_hex"] = raw[504:512].hex()
    return fields


def read_native_soundbank(*, body_path: str | Path, source_fastfile: str | Path,
                          manifest_path: str | Path, trace_path: str | Path,
                          asset_index: int, asset_name: str,
                          sab_base_path: str | Path | None = None,
                          sab_patch_path: str | Path | None = None) -> dict:
    """Read one type-21 SoundBank and all trace-owned alias records."""
    body_path, source_fastfile = Path(body_path), Path(source_fastfile)
    manifest_path, trace_path = Path(manifest_path), Path(trace_path)
    body = body_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_stat_before = trace_path.stat()
    manifest_stat_before = manifest_path.stat()
    if (not manifest.get("complete") or not manifest.get("success") or
            manifest.get("failed") != 0 or manifest.get("xfile_version") != 4087):
        raise ValueError("native walk manifest is incomplete or not Replay XFile 4087")
    if Path(manifest.get("fastfile", "")).resolve() != source_fastfile.resolve():
        raise ValueError("native walk manifest does not identify the supplied source fastfile")
    if Path(manifest.get("stream_trace", "")).name != trace_path.name:
        raise ValueError("native trace path does not match the manifest stream-trace name")
    if manifest.get("loaded_assets") != manifest.get("top_level_index"):
        raise ValueError("native walk did not consume the complete XAsset table")
    if not manifest.get("loaded_by_type", {}).get("soundbank", 0):
        raise ValueError("native walk manifest contains no SoundBank XAssets")

    events = _load_asset_events(trace_path, asset_index)
    loads = _physical_loads(events)
    if events[0].get("asset_name") not in (None, asset_name):
        raise ValueError("native trace asset name differs from the selected SoundBank")
    start, end = events[0]["serialized_input_cursor"], events[-1]["serialized_input_cursor"]
    if not (0 <= start < end <= len(body)):
        raise ValueError("SoundBank archive span is outside the decoded source body")
    intervals = sorted((r["archive_offset"], r["archive_offset"] + r["size"]) for r in loads)
    cursor = start
    for left, right in intervals:
        if left != cursor or right <= left:
            raise ValueError("native SoundBank reads have a gap, overlap, or invalid extent")
        cursor = right
    if cursor != end:
        raise ValueError("native read schedule does not cover the complete SoundBank source span")
    roots = [r for r in loads if r["archive_offset"] == start and r["stream"] == 1 and
             r["size"] == ROOT_SIZE and r["destination"] == {"stream": 1, "offset": 0}]
    if len(roots) != 1:
        raise ValueError("trace does not prove one 512-byte stream-1 SoundBank root")
    raw_root = body[start:start + ROOT_SIZE]
    root = _root_fields(raw_root)
    if root["name"] not in (INLINE, INLINE_SHARED):
        raise ValueError("SoundBank root name token is outside supported inline forms")
    global_strings = _global_string_index(trace_path, body)
    name, name_proof = _read_string(events, loads, body, {"stream": 1, "offset": 0}, root["name"], global_strings)
    if name != asset_name:
        raise ValueError("trace-owned SoundBank name differs from requested XAsset identity")
    root["strings"] = {"name": {"value": name, "proof": name_proof}}
    for field_name, offset in (("zone", 8), ("gameLanguage", 16), ("soundLanguage", 24)):
        token = root[field_name]
        value, proof = _read_string(events, loads, body, {"stream": 1, "offset": offset},
                                    token, global_strings)
        root["strings"][field_name] = {"value": value, "proof": proof}
    table_count = root["aliases"]["count"]
    if not 1 <= table_count <= 100_000:
        raise ValueError("SoundBank alias-list table count is outside validated bounds")
    table_size = table_count * ALIAS_LIST_SIZE
    tables = [r for r in loads if r["stream"] == 5 and r["size"] == table_size and
              r["destination"] and r["destination"].get("stream") == 5]
    if len(tables) != 1:
        raise ValueError("SoundBank alias-list table lacks a unique native physical array read")
    table = tables[0]
    table_raw = body[table["archive_offset"]:table["archive_offset"] + table_size]
    rows = []
    edges = {(r.get("field_stream_location", {}).get("stream"),
              r.get("field_stream_location", {}).get("offset")): r for r in events
             if r.get("kind") == "packed_resolve"}
    string_calls = {(r.get("field_stream_location", {}).get("stream"),
                     r.get("field_stream_location", {}).get("offset")): r for r in events
                    if r.get("kind") == "string_call"}
    # List-root call sequence is the native traversal boundary. Calls may be
    # packed references to prior names; both forms are explicit in the trace.
    anchors = []
    table_logical = table["destination"]["offset"]
    for i in range(table_count):
        dest = table_logical + i * ALIAS_LIST_SIZE
        token = struct.unpack_from("<Q", table_raw, i * ALIAS_LIST_SIZE)[0]
        anchor = string_calls.get((5, dest)) or edges.get((5, dest))
        if not anchor:
            raise ValueError(f"alias-list row {i} has no trace-owned name field visit")
        anchors.append((anchor["sequence"], i, dest, token))
    if anchors != sorted(anchors):
        raise ValueError("native alias-list walk order differs from serialized table order")

    used_record_spans: set[tuple[int, int]] = set()
    all_aliases = []
    alias_array_reads = []
    for pos, (anchor_seq, i, dest, name_token) in enumerate(anchors):
        off = i * ALIAS_LIST_SIZE
        list_raw = table_raw[off:off + ALIAS_LIST_SIZE]
        alias_list_id = struct.unpack_from("<I", list_raw, 8)[0]
        array_token = struct.unpack_from("<Q", list_raw, 16)[0]
        count, sequence = struct.unpack_from("<ii", list_raw, 24)
        if not 1 <= count <= 65535:
            raise ValueError(f"alias-list row {i} has unsupported alias count")
        list_name, list_name_proof = _read_string(events, loads, body,
            {"stream": 5, "offset": dest}, name_token, global_strings)
        if not list_name or _snd_hash(list_name) != alias_list_id:
            raise ValueError(f"alias-list row {i} name does not match its native stable list hash")
        next_seq = anchors[pos + 1][0] if pos + 1 < len(anchors) else events[-1]["sequence"]
        candidates = [r for r in loads if anchor_seq < r["sequence"] < next_seq and
                      r["stream"] == 5 and r["size"] == count * ALIAS_SIZE and
                      r["destination"] and r["destination"].get("stream") == 5]
        if array_token not in (INLINE, INLINE_SHARED):
            edge = edges.get((5, dest + 16))
            if not edge:
                raise ValueError(f"alias-list row {i} has an unowned non-inline alias-array token")
            target = edge.get("resolved_target_stream_location")
            candidates = [r for r in candidates if target == r["destination"]]
        if len(candidates) != 1:
            raise ValueError(f"alias-list row {i} has no unique trace-owned {count}x232 alias read")
        array = candidates[0]
        span = (array["archive_offset"], array["archive_offset"] + array["size"])
        if span in used_record_spans:
            raise ValueError("two alias-list rows share one archive child array")
        used_record_spans.add(span)
        alias_array_reads.append({"archive_span": list(span),
                                  "stream5_span": [array["destination"]["offset"],
                                                   array["destination"]["offset"] + array["size"]],
                                  "count": count, "stride": ALIAS_SIZE,
                                  "physical_read_sequence": array["sequence"]})
        array_logical = array["destination"]["offset"]
        for j in range(count):
            record_offset = array["archive_offset"] + j * ALIAS_SIZE
            record_logical = array_logical + j * ALIAS_SIZE
            rec = body[record_offset:record_offset + ALIAS_SIZE]
            name_raw = struct.unpack_from("<Q", rec, 0)[0]
            asset_name_raw = struct.unpack_from("<Q", rec, 24)[0]
            alias_id, secondary_id, file_id = struct.unpack_from("<III", rec, 32)
            alias_name, alias_name_proof = _read_string(events, loads, body,
                {"stream": 5, "offset": record_logical}, name_raw, global_strings)
            filename, filename_proof = _read_string(events, loads, body,
                {"stream": 5, "offset": record_logical + 24}, asset_name_raw, global_strings)
            if alias_id != alias_list_id:
                raise ValueError("SndAlias aliasId differs from its owning SndAliasList hash")
            if filename is not None and _snd_hash(filename) != file_id:
                raise ValueError("SndAlias fileId differs from the hash of its trace-owned filename")
            scalar_values, read_only_float_bits = _alias_scalar_values(rec)
            alias = {
                "list_index": i, "list_name": list_name, "list_id": alias_list_id,
                "list_sequence": sequence, "list_record_raw_hex": list_raw.hex(),
                "list_name_proof": list_name_proof,
                "alias_index_in_list": j, "archive_offset": record_offset,
                "stream5_offset": record_logical, "file_id": file_id,
                "alias_id": alias_id, "secondary_alias_id": secondary_id,
                "alias_name": alias_name, "asset_file_name": filename,
                "name_token": name_raw, "asset_file_name_token": asset_name_raw,
                "name_proof": alias_name_proof, "asset_file_name_proof": filename_proof,
                "scalar_fields": scalar_values,
                "read_only_scalar_bits": read_only_float_bits,
                "scalar_field_offsets": dict(ALIAS_SCALAR_FLOAT_OFFSETS),
                "raw_hex": rec.hex(), "raw_sha256": _sha(rec),
            }
            rows.append(alias)
            all_aliases.append(alias)

    if len(all_aliases) != sum(struct.unpack_from("<i", table_raw, i * ALIAS_LIST_SIZE + 24)[0]
                               for i in range(table_count)):
        raise ValueError("alias-list child counts do not match the full alias record inventory")
    if len({(x["archive_offset"], x["stream5_offset"]) for x in all_aliases}) != len(all_aliases):
        raise ValueError("duplicate alias archive/resident ownership detected")

    body_sha = _path_sha(body_path)
    ff_sha = _path_sha(source_fastfile)
    manifest_sha = _path_sha(manifest_path)
    trace_sha = _path_sha(trace_path)
    if (_sha(body) != body_sha or trace_path.stat().st_size != trace_stat_before.st_size or
            trace_path.stat().st_mtime_ns != trace_stat_before.st_mtime_ns or
            manifest_path.stat().st_size != manifest_stat_before.st_size or
            manifest_path.stat().st_mtime_ns != manifest_stat_before.st_mtime_ns):
        raise ValueError("SoundBank body, native trace, or manifest changed during typed reading")
    provenance = {
        "source_fastfile": {"path": str(source_fastfile.resolve()), "sha256": ff_sha},
        "source_body": {"path": str(body_path.resolve()), "sha256": body_sha, "bytes": len(body)},
        "native_manifest": {"path": str(manifest_path.resolve()), "sha256": manifest_sha},
        "native_trace": {"path": str(trace_path.resolve()), "sha256": trace_sha},
        "xfile_version": manifest["xfile_version"], "input_xfile_version": manifest.get("input_xfile_version"),
    }
    bank_receipt = {
        "schema": "replay120-typed-soundbank-alias-map-v1",
        "asset_index": asset_index, "asset_name": asset_name, "asset_type": 21,
        "asset_archive_span": [start, end], "asset_bytes": end - start,
        "root_archive_span": [start, start + ROOT_SIZE], "root": root,
        "root_name_proof": name_proof,
        "alias_list_table": {"archive_span": [table["archive_offset"], table["archive_offset"] + table_size],
                              "stream5_span": [table_logical, table_logical + table_size],
                              "count": table_count, "stride": ALIAS_LIST_SIZE,
                              "raw_sha256": _sha(table_raw), "raw_hex": table_raw.hex()},
        "alias_lists": [{"index": i, "name": next(x["list_name"] for x in rows if x["list_index"] == i),
                         "id": struct.unpack_from("<I", table_raw, i * 32 + 8)[0],
                         "alias_count": struct.unpack_from("<i", table_raw, i * 32 + 24)[0],
                         "sequence": struct.unpack_from("<i", table_raw, i * 32 + 28)[0],
                         "raw_hex": table_raw[i * 32:(i + 1) * 32].hex()}
                        for i in range(table_count)],
        "alias_child_arrays": alias_array_reads,
        "aliases": all_aliases,
        "schedule": {"trace_events": len(events), "physical_loads": len(loads),
                     "physical_read_bytes": sum(x["size"] for x in loads),
                     "aliases": len(all_aliases), "alias_list_records": table_count,
                     "alias_child_array_reads": len(alias_array_reads),
                     "alias_child_array_bytes": sum(x["archive_span"][1] - x["archive_span"][0]
                                                     for x in alias_array_reads),
                     "archive_reads_cover_span_exactly": True},
        "provenance": provenance,
    }
    bank_receipt["source_identity_sha256"] = _json_sha(bank_receipt)
    if sab_base_path is not None:
        if sab_patch_path is None:
            raise ValueError("patch SAB path is required when base SAB is supplied")
        bank_receipt["sab_links"] = list_resident_codec8_base_ids(
            bank_receipt, sab_base_path=sab_base_path, sab_patch_path=sab_patch_path)
    return bank_receipt


def list_resident_codec8_base_ids(bank_receipt: dict, *, sab_base_path: str | Path,
                                  sab_patch_path: str | Path) -> dict:
    """Return codec-8 base IDs that survive patch precedence and exact alias join."""
    identity_payload = dict(bank_receipt)
    identity = identity_payload.pop("source_identity_sha256", None)
    identity_payload.pop("sab_links", None)
    if not isinstance(identity, str) or _json_sha(identity_payload) != identity:
        raise ValueError("SoundBank alias receipt was altered after native source validation")
    base_path, patch_path = Path(sab_base_path), Path(sab_patch_path)
    base_data, patch_data = base_path.read_bytes(), patch_path.read_bytes()
    base, patch = sab.parse_sab(base_data), sab.parse_sab(patch_data)
    patch_ids = {row.file_id for row in patch.rows}
    alias_by_id: dict[int, list[dict]] = {}
    for alias in bank_receipt.get("aliases", []):
        alias_by_id.setdefault(alias["file_id"], []).append(alias)
    available, excluded = [], []
    for row in base.rows:
        aliases = alias_by_id.get(row.file_id, [])
        if row.codec != 8 or row.hybrid:
            excluded.append({"sab_index": row.index, "file_id": row.file_id,
                             "reason": "not-resident-codec8"})
        elif row.file_id in patch_ids:
            excluded.append({"sab_index": row.index, "file_id": row.file_id,
                             "reason": "shadowed-by-patch"})
        elif len(aliases) != 1:
            excluded.append({"sab_index": row.index, "file_id": row.file_id,
                             "reason": "missing-or-ambiguous-native-alias", "alias_matches": len(aliases)})
        else:
            alias = aliases[0]
            if not alias["asset_file_name"]:
                excluded.append({"sab_index": row.index, "file_id": row.file_id,
                                 "reason": "native-alias-has-no-proven-asset-filename"})
                continue
            alias_link = {key: alias[key] for key in (
                "list_index", "list_name", "alias_index_in_list", "alias_name",
                "asset_file_name", "alias_id", "secondary_alias_id", "archive_offset", "raw_sha256")}
            alias_link["file_id"] = row.file_id
            alias_link["source_identity_sha256"] = bank_receipt["source_identity_sha256"]
            available.append({"sab_index": row.index, "file_id": row.file_id,
                              "codec": row.codec,
                              "rate": row.rate, "channels": row.channels, "frames": row.frames,
                              "linked_alias": alias_link, "alias": alias_link})
    return {
        "schema": "replay120-sab-resident-codec8-alias-links-v1",
        "source_identity_sha256": bank_receipt["source_identity_sha256"],
        "base_sab": {"path": str(base_path.resolve()), "sha256": _sha(base_data),
                     "bytes": len(base_data), "entry_count": len(base.rows)},
        "patch_sab": {"path": str(patch_path.resolve()), "sha256": _sha(patch_data),
                      "bytes": len(patch_data), "entry_count": len(patch.rows)},
        "patch_shadow_ids": sorted(patch_ids),
        "available": available, "excluded": excluded,
        "available_file_ids": [row["file_id"] for row in available],
    }
