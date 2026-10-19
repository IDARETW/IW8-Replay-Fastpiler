"""Trace-bound import of a complete inline Replay XAsset zone into another zone.

This module intentionally handles only whole, self-contained source zones with
unique (type, name) identities and fully trace-owned serialized tails. It does
not replace existing identities or guess at dependency closure. The current
mesh-corpus experiment uses this as an isolated merge-core proof, not as a
frontend publication recipe.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import struct
from types import FunctionType

from workstation_fastfiles import (
    ZoneBody,
    make_replay_header_only_patch,
    pack_replay_uncompressed,
    sha256_file,
    source_profile,
    unpack_replay_uncompressed,
)
from workstation_luafile_operations import (
    XASSET_ROW_SIZE,
    _build_interval_index,
)
import workstation_luafile_operations as _luafile_ops

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_events(path: Path):
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid stream trace JSON at line {line_number}") from error
            yield row


def _validate_walk(body: bytes, trace_path: Path, manifest_path: Path) -> tuple[dict, Path, dict]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    manifest_root = manifest_path.resolve(strict=True).parent

    def child_path(key: str, fallback: str) -> Path:
        value = manifest.get(key, fallback)
        if not isinstance(value, str) or not value:
            raise ValueError(f"native manifest {key} path is invalid")
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"native manifest {key} path escapes its receipt directory")
        resolved = (manifest_root / relative).resolve(strict=True)
        if manifest_root not in resolved.parents:
            raise ValueError(f"native manifest {key} path resolves outside its receipt directory")
        return resolved

    expected_trace = child_path("stream_trace", "stream-trace.jsonl")
    if trace_path.resolve(strict=True) != expected_trace:
        raise ValueError("provided stream trace is not the trace named by its native manifest")
    journal_path = child_path("journal", "assets.jsonl")
    trace_hash = sha256_file(trace_path)
    tested = manifest.get("tested")
    top_level = manifest.get("top_level_index")
    references = manifest.get("reference_only_rows", [])
    if not isinstance(references, list):
        raise ValueError("native reference-only coverage must be an indexed list")
    if (manifest.get("profile") != "replay-1.20" or
            manifest.get("xfile_version") != 0xFF7 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
            not isinstance(tested, int) or isinstance(tested, bool) or
            not isinstance(top_level, int) or isinstance(top_level, bool) or
            tested + len(references) != top_level or
            manifest.get("serialized_bytes_read") != len(body)):
        raise ValueError("zone merge requires a complete Replay4087 full-zone native walk")
    embedded_hash = manifest.get("stream_trace_sha256")
    if embedded_hash is not None and embedded_hash != trace_hash:
        raise ValueError("native stream trace digest differs from its manifest")
    bound = dict(manifest, stream_trace_sha256=trace_hash)
    cache = Path(tempfile.gettempdir()) / "replay-zone-merge-bound-manifests"
    cache.mkdir(parents=True, exist_ok=True)
    key = _sha(manifest_bytes + bytes.fromhex(trace_hash))
    bound_path = cache / f"{key}.json"
    serialized = json.dumps(bound, separators=(",", ":")) + "\n"
    if bound_path.exists():
        if bound_path.read_text(encoding="utf-8") != serialized:
            raise ValueError("cached trace-bound manifest differs from its source inputs")
    else:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                             prefix=bound_path.name + ".",
                                             suffix=".tmp", dir=cache, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(serialized)
            temporary.replace(bound_path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    journal_bytes = journal_path.read_bytes()
    journal_rows = []
    for line_number, line in enumerate(journal_bytes.splitlines(), 1):
        if not line.strip():
            continue
        try:
            journal_rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid native asset journal JSON at line {line_number}") from error
    if len(journal_rows) != tested:
        raise ValueError("native asset journal count differs from raw tested count")
    layout = ZoneBody.parse(body)
    if top_level != len(layout.assets):
        raise ValueError("native walk coverage differs from the serialized XAsset table")
    reference_by_index = {}
    for row in references:
        if not isinstance(row, dict):
            raise ValueError("native reference-only row is malformed")
        index, type_id = row.get("index"), row.get("type_id")
        name, token = row.get("name"), row.get("pointer_token")
        if (not isinstance(index, int) or isinstance(index, bool) or
                index < 0 or index >= top_level or index in reference_by_index or
                not isinstance(type_id, int) or isinstance(type_id, bool) or
                not isinstance(name, str) or not name.startswith(",") or
                type(token) is not int or token != 0xFFFFFFFFFFFFFFFD):
            raise ValueError("native reference-only row lacks exact indexed comma-name evidence")
        header = layout.assets[index]
        if header.type_id != type_id or header.pointer_token != token:
            raise ValueError("native reference-only row differs from its serialized XAsset header")
        reference_by_index[index] = dict(row, status="reference")
    if references:
        native_rows = iter(journal_rows)
        covered = []
        for index in range(top_level):
            covered.append(reference_by_index[index] if index in reference_by_index else next(native_rows))
        try:
            next(native_rows)
        except StopIteration:
            pass
        else:
            raise ValueError("native asset journal has rows beyond accounted table coverage")
        journal_rows = covered
    return manifest, bound_path, dict(
        manifest_sha256=_sha(manifest_bytes), trace_sha256=trace_hash,
        journal_sha256=_sha(journal_bytes), journal_path=journal_path,
        journal_rows=journal_rows, native_tested=tested,
        reference_only_rows=references)


def _cursor_state_before_assets(trace_path: Path) -> tuple[dict[int, int], int]:
    cursors: dict[int, int] = {}
    sequence = 0
    for event in _read_events(trace_path):
        if event.get("sequence") != sequence:
            raise ValueError(f"native trace sequence breaks at event {sequence}")
        sequence += 1
        if event.get("kind") == "begin_asset_call":
            return cursors, sequence - 1
        if event.get("kind") == "stream_operation":
            block = event.get("block_after")
            offset = event.get("offset_after")
            if isinstance(block, int) and isinstance(offset, int):
                cursors[block] = offset
    raise ValueError("native trace contains no top-level asset call")


def _final_cursors(trace_path: Path) -> tuple[dict[int, int], int]:
    cursors: dict[int, int] = {}
    sequence = 0
    for event in _read_events(trace_path):
        if event.get("sequence") != sequence:
            raise ValueError(f"native trace sequence breaks at event {sequence}")
        sequence += 1
        if event.get("kind") == "stream_operation":
            block = event.get("block_after")
            offset = event.get("offset_after")
            if isinstance(block, int) and isinstance(offset, int):
                cursors[block] = offset
    return cursors, sequence


def _max_destinations(trace_path: Path) -> dict[int, int]:
    maxima: dict[int, int] = {}
    for event in _read_events(trace_path):
        if event.get("kind") != "stream_operation":
            continue
        for block_key, offset_key in (("block_before", "offset_before"),
                                      ("block_after", "offset_after")):
            block, offset = event.get(block_key), event.get(offset_key)
            if isinstance(block, int) and isinstance(offset, int):
                maxima[block] = max(maxima.get(block, 0), offset)
    return maxima


def _packed_references(trace_path: Path) -> tuple[list[dict], int]:
    """Retain every packed resolve, including fields not moved in source layout."""
    references = []
    event_count = 0
    for event in _read_events(trace_path):
        if event.get("kind") not in ("packed_alias", "packed_resolve"):
            continue
        event_count += 1
        field = event.get("field_stream_location")
        target = event.get("resolved_target_stream_location")
        raw = event.get("raw_token")
        owner = event.get("xasset_index")
        if (not isinstance(raw, int) or not isinstance(owner, int) or
                not isinstance(field, dict) or not isinstance(target, dict) or
                not all(isinstance(field.get(key), int) for key in ("stream", "offset")) or
                not all(isinstance(target.get(key), int) for key in ("stream", "offset"))):
            raise ValueError("packed pointer trace event lacks exact owner/field/target coordinates")
        references.append({
            "owner": owner, "raw": raw,
            "field_stream": field["stream"], "field_offset": field["offset"],
            "target_stream": target["stream"], "target_offset": target["offset"],
            "sequence": event.get("sequence"),
        })
    return references, event_count


def _simulate_appended_zone(trace_path: Path, target_cursors: dict[int, int],
                            target_highwaters: dict[int, int],
                            start_sequence: int) -> tuple[dict[int, list[tuple[int, int, int]]],
                                                         dict[int, int], dict[int, int], dict]:
    """Replay source operations after its XAsset table at destination cursors."""
    old_cursors, _ = _cursor_state_before_assets(trace_path)
    deltas = {block: target_cursors.get(block, 0) - old_cursors.get(block, 0)
              for block in set(target_cursors) | set(old_cursors)}
    source_cursors = dict(old_cursors)
    segments: dict[int, list[tuple[int, int, int]]] = {}
    asset_bases: dict[int, int] = {}
    relocated_asset_bases: dict[int, int] = {}
    highwaters = dict(target_highwaters)
    first_payload_seen = False
    sequence = 0
    begin = None
    for event in _read_events(trace_path):
        if sequence == start_sequence:
            begin = event
            first_payload_seen = True
        sequence += 1
        if not first_payload_seen:
            continue
        if event.get("kind") == "begin_asset_call":
            owner = event.get("xasset_index")
            if isinstance(owner, int):
                old_base = source_cursors.get(5)
                if old_base is None:
                    raise ValueError("candidate asset begins without a block-5 base")
                asset_bases.setdefault(owner, old_base)
                relocated_asset_bases.setdefault(owner, old_base + deltas.get(5, 0))
            continue
        if event.get("kind") == "insert_pointer_slot":
            location = event.get("inserted_stream_location") or {}
            block, offset = location.get("stream"), location.get("offset")
            if not isinstance(block, int) or not isinstance(offset, int):
                raise ValueError("candidate insert-pointer event lacks an exact stream location")
            relocated_end = offset + deltas.get(block, 0) + 8
            highwaters[block] = max(highwaters.get(block, 0), relocated_end)
            continue
        if event.get("kind") != "stream_operation":
            continue
        operation = event.get("operation")
        before_block, before_offset = event.get("block_before"), event.get("offset_before")
        after_block, after_offset = event.get("block_after"), event.get("offset_after")
        if not all(isinstance(v, int) for v in
                   (before_block, before_offset, after_block, after_offset)):
            raise ValueError("candidate stream operation lacks native cursor coordinates")
        if (before_block not in range(11) or after_block not in range(11) or
                not 0 <= before_offset <= 0xFFFFFFFFFFFFFFFF or
                not 0 <= after_offset <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("candidate stream operation has an invalid native stream coordinate")
        before_new = before_offset + deltas.get(before_block, 0)
        # Push/pop events expose cursor advances performed by helpers such as
        # DB_InsertPointer between explicit stream operations.  Preserve the
        # observed pre-transition cursor as a reservation high-water even when
        # the event switches to another block.
        highwaters[before_block] = max(highwaters.get(before_block, 0), before_new)
        old_advance = (after_offset - before_offset) if before_block == after_block else 0
        if old_advance < 0:
            raise ValueError("candidate stream operation moves a stream cursor backwards")
        if operation in ("load", "take", "string"):
            if before_block != after_block:
                raise ValueError("cross-block allocation is not supported by zone merge")
            after_new = before_new + old_advance
            if operation in ("load", "string") and old_advance > 0:
                if operation == "load" and event.get("physical_input_bytes", 0) != old_advance:
                    raise ValueError("candidate physical allocation differs from its typed cursor span")
                segments.setdefault(before_block, []).append(
                    (before_offset, after_offset, before_new))
        elif operation == "align":
            mask = event.get("value")
            if not isinstance(mask, int) or mask < 0 or before_block != after_block:
                raise ValueError("candidate alignment operation is malformed")
            after_new = (before_new + mask) & ~mask
        else:
            after_new = after_offset + deltas.get(after_block, 0)
        if not 0 <= after_new <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("relocated stream cursor exceeds the native 64-bit range")
        deltas[after_block] = after_new - after_offset
        source_cursors[after_block] = after_offset
        highwaters[after_block] = max(highwaters.get(after_block, 0), after_new)
    if begin is None:
        raise ValueError("candidate trace does not begin an asset after its table")
    return segments, asset_bases, relocated_asset_bases, highwaters


def _map_target(segments: dict[int, list[tuple[int, int, int]]], stream: int,
                offset: int) -> int:
    matches = [new_start + offset - start
               for start, end, new_start in segments.get(stream, [])
               if start <= offset < end]
    if len(set(matches)) != 1:
        raise ValueError("candidate packed target has no unique owned destination span")
    return matches[0]


def _rebase_source_pointer(reference: dict, segments: dict[int, list[tuple[int, int, int]]],
                           old_asset_bases: dict[int, int],
                           new_asset_bases: dict[int, int]) -> tuple[int, int]:
    """Return relocated token and target for a fully trace-owned pointer."""
    owner, raw = reference["owner"], reference["raw"]
    tag = raw >> 32
    target_stream, target_offset = reference["target_stream"], reference["target_offset"]
    low = raw & 0xFFFFFFFF
    if tag == 5:
        if target_stream != 5 or low == 0 or low - 1 != target_offset:
            raise ValueError("source tag-5 pointer disagrees with its traced absolute target")
        new_target = _map_target(segments, target_stream, target_offset)
        new_low = new_target + 1
    elif tag == 0x15:
        old_base, new_base = old_asset_bases.get(owner), new_asset_bases.get(owner)
        if (old_base is None or new_base is None or target_stream != 5 or low == 0 or
                target_offset != old_base + low - 1):
            raise ValueError("source tag-0x15 pointer lacks a proven asset-relative base")
        new_target = _map_target(segments, target_stream, target_offset)
        new_low = new_target - new_base + 1
    else:
        raise ValueError(f"source pointer class {tag:#x} is not supported for relocation")
    if not 0 < new_low <= 0xFFFFFFFF:
        raise ValueError("relocated source packed pointer exceeds its 32-bit field")
    return (raw & 0xFFFFFFFF00000000) | new_low, new_target


def _require_mergeable_script_strings(source: ZoneBody) -> None:
    """Reject XAsset-table merges that would change ScriptString identities.

    The current append-only implementation preserves the destination's global
    script-string table. It has no typed map for importing/reindexing source
    ScriptString IDs, so a nonempty source table cannot be merged safely.
    """
    if source.script_string_count:
        raise ValueError("source zone has ScriptStrings; merging their ID table is unsupported")


def _validate_asset_identity_sets(source_rows: list[dict], target_rows: list[dict]) -> list[tuple[int, str]]:
    for row in (*source_rows, *target_rows):
        if (not isinstance(row, dict) or not isinstance(row.get("type_id"), int) or
                not isinstance(row.get("name"), str)):
            raise ValueError("native asset identity row lacks a type ID or name")
    source_ids = [(row["type_id"], row["name"]) for row in source_rows]
    target_ids = [(row["type_id"], row["name"]) for row in target_rows]
    if len(source_ids) != len(set(source_ids)) or len(target_ids) != len(set(target_ids)):
        raise ValueError("duplicate type/name identities within a zone are ambiguous")
    collisions = sorted(set(source_ids) & set(target_ids))
    if collisions:
        raise ValueError(f"zone merge has {len(collisions)} type/name collisions; replacement is unsupported")
    return collisions


def _validate_native_reread_manifest(manifest: dict, expected_count: int,
                                     expected_body_bytes: int,
                                     reference_only_rows: list[dict] | None = None) -> None:
    """Require a complete successful full-table Replay reread of the output."""
    references = reference_only_rows or []
    if (manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("profile") != "replay-1.20" or
            manifest.get("xfile_version") != 0xFF7 or
            manifest.get("tested") != expected_count - len(references) or
            manifest.get("top_level_index") != expected_count or
            manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
            manifest.get("serialized_bytes_read") != expected_body_bytes or
            manifest.get("reference_only_rows", []) != references):
        raise ValueError("native Replay reread did not prove complete output count and exact EOF")


def _trace_helpers_with_sentinel_support():
    """Clone the shared analyzer with local sentinel handling, without mutation.

    Replay readers can report a repeated physical read of a pointer field. The
    only duplicates accepted here are identical inert inline string sentinels;
    packed pointers and differing bytes remain ambiguous. Cloned function
    globals keep concurrent Lua/zone writers isolated from this policy.
    """
    from bisect import bisect_right

    original_resolver = _luafile_ops._alias_field_archive

    def resolve(alias: dict, intervals: list[dict], body: bytes,
                interval_index: dict | None = None) -> int:
        try:
            return original_resolver(alias, intervals, body, interval_index)
        except ValueError as error:
            field = alias["field"]
            owner, block, offset = alias["owner"], field.get("stream"), field.get("offset")
            index = interval_index if interval_index is not None else _build_interval_index(intervals)
            group = index.get((owner, block))
            if group is None:
                raise error
            starts, spans, prefix_max_end = group
            position = bisect_right(starts, offset) - 1
            physicals = []
            cursor = position
            while cursor >= 0 and prefix_max_end[cursor] >= offset + 8:
                span = spans[cursor]
                if span["start"] <= offset and offset + 8 <= span["end"]:
                    physical = span["archive"] + offset - span["start"]
                    if 0 <= physical and physical + 8 <= len(body):
                        physicals.append(physical)
                cursor -= 1
            values = {struct.unpack_from("<Q", body, at)[0] for at in physicals}
            if physicals and values <= {0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE}:
                return min(physicals)
            raise error

    def clone(function):
        namespace = function.__globals__.copy()
        namespace["_alias_field_archive"] = resolve
        result = FunctionType(function.__code__, namespace, function.__name__,
                              function.__defaults__, function.__closure__)
        result.__kwdefaults__ = function.__kwdefaults__
        return result

    return clone(_luafile_ops._trace_contract), clone(_luafile_ops._rebase_aliases), resolve


def merge_complete_zone(source_body_data: bytes, target_body_data: bytes, *,
                        source_trace_path: str | Path,
                        source_manifest_path: str | Path,
                        target_trace_path: str | Path,
                        target_manifest_path: str | Path,
                        source_asset_rows: list[dict],
                        target_asset_rows: list[dict],
                        expected_source_sha256: str,
                        expected_target_sha256: str,
                        collision_policy: str = "reject") -> tuple[bytes, dict]:
    """Append a complete native zone's self-contained rows and serialized tail.

    The implementation requires exact full traces for both bodies, no identity
    collisions, an end-of-table insertion boundary, and pointer classes 5/0x15
    whose targets are all owned by the candidate's appended allocations.
    Replacement/deletion of existing assets is deliberately not implicit.
    """
    source_body = bytes(source_body_data)
    target_body = bytes(target_body_data)
    if _sha(source_body) != expected_source_sha256 or _sha(target_body) != expected_target_sha256:
        raise ValueError("zone merge body hash differs from its source receipt")
    if collision_policy != "reject":
        raise ValueError("only explicit collision_policy='reject' is currently implemented")
    source_path, target_path = Path(source_trace_path), Path(target_trace_path)
    source_manifest, target_manifest = Path(source_manifest_path), Path(target_manifest_path)
    source_walk, source_bound_manifest, source_pins = _validate_walk(
        source_body, source_path, source_manifest)
    target_walk, target_bound_manifest, target_pins = _validate_walk(
        target_body, target_path, target_manifest)
    src, dst = ZoneBody.parse(source_body), ZoneBody.parse(target_body)
    _require_mergeable_script_strings(src)
    if not src.assets or not dst.assets:
        raise ValueError("zone merge requires nonempty source and destination asset lists")
    if (source_walk.get("tested") != len(src.assets) or
            target_walk.get("tested") != len(dst.assets)):
        raise ValueError("native tested counts differ from the source/destination XAsset tables")
    if (len(source_asset_rows) != len(src.assets) or len(target_asset_rows) != len(dst.assets)):
        raise ValueError("native journals do not cover both complete XAsset tables")
    if source_asset_rows != source_pins["journal_rows"]:
        raise ValueError("source asset rows differ from the manifest-owned native journal")
    if target_asset_rows != target_pins["journal_rows"]:
        raise ValueError("destination asset rows differ from the manifest-owned native journal")
    for index, (header, row) in enumerate(zip(src.assets, source_asset_rows, strict=True)):
        if row.get("type_id") != header.type_id or not isinstance(row.get("name"), str):
            raise ValueError(f"source native row {index} differs from its XAsset header")
    for index, (header, row) in enumerate(zip(dst.assets, target_asset_rows, strict=True)):
        if row.get("type_id") != header.type_id or not isinstance(row.get("name"), str):
            raise ValueError(f"target native row {index} differs from its XAsset header")
    collisions = _validate_asset_identity_sets(source_asset_rows, target_asset_rows)
    total_asset_count = len(dst.assets) + len(src.assets)
    if total_asset_count > 0xFFFFFFFF:
        raise ValueError("merged XAsset count exceeds the native 32-bit table count")
    if source_walk.get("references", 0) != 0:
        raise ValueError("source zone has external XAsset references outside the complete imported table")
    if src.first_payload_offset != src.asset_table_offset + len(src.assets) * XASSET_ROW_SIZE:
        raise ValueError("source serialized tail does not begin immediately after its XAsset table")
    if dst.first_payload_offset != dst.asset_table_offset + len(dst.assets) * XASSET_ROW_SIZE:
        raise ValueError("destination serialized tail does not begin immediately after its XAsset table")

    # Bind unbound ACTS manifests to their exact traces for the shared validated
    # relocation analyzer. A sibling manifest is created only in caller-owned
    # scratch; source evidence is never changed.
    table_delta = len(src.assets) * XASSET_ROW_SIZE
    trace_contract, rebase_aliases, resolve_alias_field = _trace_helpers_with_sentinel_support()
    (target_contract, target_bases, target_intervals, target_aliases, target_table,
     target_highwaters, target_alias_count, target_relocated_targets,
     target_relocated_bases, _target_stats) = trace_contract(
        target_body, target_path, target_bound_manifest, table_row_delta=table_delta)
    if target_table["archive"] + target_table["size"] != dst.first_payload_offset:
        raise ValueError("destination trace XAsset allocation does not end at the payload boundary")
    if (target_table["archive"] != dst.asset_table_offset or
            target_table["size"] != len(dst.assets) * XASSET_ROW_SIZE):
        raise ValueError("destination trace does not own the complete destination XAsset pointer array")
    rebased_target, target_alias_receipt = rebase_aliases(
        target_body, target_intervals, target_aliases, target_table["end"],
        dst.first_payload_offset, table_delta, target_bases,
        relocated_targets=target_relocated_targets,
        relocated_asset_bases=target_relocated_bases)
    if target_alias_receipt.get("unsupported_unchanged_aliases") != 0:
        raise ValueError("destination zone contains packed pointer classes not proven across table insertion")

    # Compute source allocation addresses as if the candidate's complete root
    # schedule executes after the destination's existing last asset.
    source_cursors, first_asset_sequence = _cursor_state_before_assets(source_path)
    target_cursors, target_event_count = _final_cursors(target_path)
    target_highwaters = _max_destinations(target_path)
    target_cursors[5] = target_cursors.get(5, 0) + table_delta
    target_highwaters[5] = target_highwaters.get(5, 0) + table_delta
    if target_cursors[5] > 0xFFFFFFFFFFFFFFFF or target_highwaters[5] > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("destination stream-5 table extension exceeds the native 64-bit range")
    source_segments, source_bases, new_source_bases, highwaters = _simulate_appended_zone(
        source_path, target_cursors, target_highwaters,
        first_asset_sequence)
    (_source_contract, _unused_bases, source_intervals, _source_aliases,
     _source_table, _source_max, source_alias_count, _source_targets,
     _source_relocated_bases, _source_stats) = trace_contract(
        source_body, source_path, source_bound_manifest, table_row_delta=0)
    if (_source_table["archive"] != src.asset_table_offset or
            _source_table["size"] != len(src.assets) * XASSET_ROW_SIZE or
            _source_table["archive"] + _source_table["size"] != src.first_payload_offset):
        raise ValueError("source trace does not own the complete source XAsset pointer array")
    source_interval_index = _build_interval_index(source_intervals)
    all_source_references, source_reference_events = _packed_references(source_path)
    if source_reference_events != source_alias_count:
        raise ValueError("source packed-reference scan differs from typed trace contract")
    unique_source_references: dict[tuple[int, int, int], dict] = {}
    for reference in all_source_references:
        key = (reference["owner"], reference["field_stream"], reference["field_offset"])
        prior = unique_source_references.get(key)
        value = (reference["raw"], reference["target_stream"],
                 reference["target_offset"])
        if prior is not None and (prior["raw"], prior["target_stream"],
                                  prior["target_offset"]) != value:
            raise ValueError("repeated packed-reference events disagree about one field")
        unique_source_references.setdefault(key, reference)

    row_start = dst.first_payload_offset
    table_bytes = source_body[src.asset_table_offset:
                              src.asset_table_offset + len(src.assets) * XASSET_ROW_SIZE]
    if len(table_bytes) != table_delta:
        raise ValueError("candidate table byte extent differs from its typed XAsset count")
    merged = bytearray(rebased_target)
    struct.pack_into("<I", merged, 16, len(dst.assets) + len(src.assets))
    merged[row_start:row_start] = table_bytes
    source_tail_start = len(merged)
    source_tail = bytearray(source_body[src.first_payload_offset:])

    patched_alias_fields = set()
    for reference in unique_source_references.values():
        owner, raw = reference["owner"], reference["raw"]
        field_stream, field_offset = reference["field_stream"], reference["field_offset"]
        new_raw, _new_target = _rebase_source_pointer(
            reference, source_segments, source_bases, new_source_bases)
        field_desc = {"owner": owner, "field": {"stream": field_stream, "offset": field_offset}}
        source_archive = resolve_alias_field(field_desc, source_intervals,
                                             source_body, source_interval_index)
        field_at = source_archive - src.first_payload_offset
        if field_at < 0 or field_at + 8 > len(source_tail):
            raise ValueError("source packed pointer field lies outside its appended tail")
        if struct.unpack_from("<Q", source_tail, field_at)[0] != raw:
            raise ValueError("source packed pointer field bytes disagree with the native trace")
        if field_at in patched_alias_fields:
            continue
        struct.pack_into("<Q", source_tail, field_at,
                         new_raw)
        patched_alias_fields.add(field_at)

    merged.extend(source_tail)
    final_body = bytes(merged)
    if len(final_body) > 0xFFFFFFFF:
        raise ValueError("merged Replay body exceeds the native IWC 32-bit extent")
    if any(not 0 <= value <= 0xFFFFFFFFFFFFFFFF for value in highwaters.values()):
        raise ValueError("merged stream reservation exceeds the native 64-bit range")
    final_zone = ZoneBody.parse(final_body)
    if len(final_zone.assets) != total_asset_count:
        raise AssertionError("merged XAsset table count differs from imported rows")
    expected_types = [row["type_id"] for row in target_asset_rows + source_asset_rows]
    if [row.type_id for row in final_zone.assets] != expected_types:
        raise AssertionError("merged XAsset row order/types differ from append schedule")
    if target_event_count != target_walk.get("stream_trace_events"):
        raise ValueError("destination trace event count differs from its complete manifest")
    if first_asset_sequence is None:
        raise ValueError("candidate trace omitted its first asset-call boundary")
    receipt = dict(schema=1, status="trace-bound-native-zone-merge-candidate",
        source_body_sha256=src.source_sha256, target_body_sha256=dst.source_sha256,
        output_body_sha256=_sha(final_body), source_trace_sha256=source_pins["trace_sha256"],
        target_trace_sha256=target_pins["trace_sha256"],
        source_manifest_sha256=source_pins["manifest_sha256"],
        target_manifest_sha256=target_pins["manifest_sha256"],
        source_journal_sha256=source_pins["journal_sha256"],
        target_journal_sha256=target_pins["journal_sha256"],
        source_asset_count=len(src.assets), target_asset_count=len(dst.assets),
        output_asset_count=len(final_zone.assets), source_reference_count=source_walk.get("references", 0),
        identity_collisions=collisions, table_rows_added=len(src.assets),
        table_bytes_added=table_delta, output_table_offset=dst.asset_table_offset,
        output_payload_offset=dst.first_payload_offset + table_delta,
        source_payload_archive_offset=src.first_payload_offset,
        imported_tail_archive_offset=source_tail_start,
        packed_aliases_seen=source_alias_count,
        packed_alias_fields_seen=len(unique_source_references),
        packed_alias_fields_rebased=len(patched_alias_fields),
        target_alias_receipt=target_alias_receipt,
        target_stream_final_cursors={str(k): v for k, v in target_cursors.items()},
        target_stream_highwaters={str(k): v for k, v in target_highwaters.items()},
        merged_stream_highwaters={str(k): v for k, v in highwaters.items()},
        destination_policy="append-only; all (type,name) collisions reject; no existing roots are replaced",
        runtime_claim="none; requires full native reread and consumer/runtime checks")
    for path, expected_hash in (
            (source_path, source_pins["trace_sha256"]),
            (target_path, target_pins["trace_sha256"]),
            (source_manifest, source_pins["manifest_sha256"]),
            (target_manifest, target_pins["manifest_sha256"]),
            (source_pins["journal_path"], source_pins["journal_sha256"]),
            (target_pins["journal_path"], target_pins["journal_sha256"])):
        if sha256_file(path) != expected_hash:
            raise ValueError("native source/target trace, manifest, or journal changed during merge")
    return final_body, receipt


def _native_stream_reservations(highwaters: list[int] | tuple[int, ...]) -> list[int]:
    """Convert exact cursor high-waters to the native 16-byte block reservations.

    Stream traces describe the last byte addressed by loader operations.  The
    XFile header reserves each logical stream in 16-byte allocation units; a
    non-aligned high-water therefore needs terminal padding even though those
    padding bytes are not serialized in the body.
    """
    if len(highwaters) != 11:
        raise ValueError("Replay stream reservations must contain exactly 11 blocks")
    reservations = []
    for value in highwaters:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("Replay stream high-waters must be non-negative integers")
        if value > 0xFFFFFFFFFFFFFFF0:
            raise ValueError("Replay stream reservation exceeds the native 64-bit range")
        reservations.append((value + 15) & ~15)
    return reservations


def write_and_verify_replay_zone(body: bytes, stream_reservations: list[int] | tuple[int, ...],
                                 expected_asset_rows: list[dict], *,
                                 target_source_fastfile: str | Path,
                                 acts_path: str | Path,
                                 replay_executable: str | Path,
                                 output_fastfile: str | Path,
                                 reference_only_rows: list[dict] | None = None,
                                 timeout: int = 300) -> dict:
    """Write an isolated Replay FF/FP pair and require a full native reread.

    The output must be outside the source zone directory and both destination
    files must be new. This helper only emits the replacement FF and its
    required no-op FP; it never writes into the configured game zone. A
    successful native read proves serialized acceptance/count/order/EOF, not
    runtime activation or rendering.
    """
    source_path = Path(target_source_fastfile).resolve(strict=True)
    output_path = Path(output_fastfile).resolve()
    output_patch = output_path.with_suffix(".fp")
    if output_path == source_path or source_path.parent in output_path.parents:
        raise ValueError("zone-merge output must be outside the source zone directory")
    if source_path.parent.name.casefold() == "zone":
        game_root = source_path.parent.parent
        if output_path == game_root or game_root in output_path.parents:
            raise ValueError("zone-merge output must be outside the source game directory")
    if output_path.suffix.casefold() != ".ff":
        raise ValueError("zone-merge output path must use the .ff extension")
    if output_path.exists() or output_patch.exists():
        raise FileExistsError("zone-merge output FF/FP paths must both be new")
    profile = source_profile(source_path)
    if profile.get("final_header", {}).get("xfile_version") != 0xFF7:
        raise ValueError("native merge packaging requires a Replay4087 destination source")
    patches = profile.get("patches", [])
    if len(patches) != 1 or patches[0].get("extension") != ".fp":
        raise ValueError("native merge packaging requires one proven FP patch and no other sidecars")
    if source_profile(source_path) != profile:
        raise ValueError("destination FF/FP source identity changed during preflight")

    parsed = ZoneBody.parse(body)
    references = reference_only_rows or []
    reference_by_index = {}
    for row in references:
        if not isinstance(row, dict):
            raise ValueError("expected reference-only output row is malformed")
        index, type_id = row.get("index"), row.get("type_id")
        name, token = row.get("name"), row.get("pointer_token")
        if (not isinstance(index, int) or isinstance(index, bool) or
                index < 0 or index >= len(parsed.assets) or index in reference_by_index or
                not isinstance(type_id, int) or isinstance(type_id, bool) or
                not isinstance(name, str) or not name.startswith(",") or
                type(token) is not int or token != 0xFFFFFFFFFFFFFFFD):
            raise ValueError("expected reference-only row lacks exact indexed comma-name evidence")
        header = parsed.assets[index]
        if header.type_id != type_id or header.pointer_token != token:
            raise ValueError("expected reference-only row differs from the serialized output table")
        reference_by_index[index] = row
    if len(expected_asset_rows) != len(parsed.assets):
        raise ValueError("expected native identity rows do not cover the merged XAsset table")
    expected_identity = []
    for index, (header, row) in enumerate(zip(parsed.assets, expected_asset_rows, strict=True)):
        if row.get("type_id") != header.type_id or not isinstance(row.get("name"), str):
            raise ValueError(f"expected identity row {index} differs from the merged XAsset table")
        expected_identity.append((row["type_id"], row["name"]))
    if len(set(expected_identity)) != len(expected_identity):
        raise ValueError("merged zone contains duplicate native (type,name) identities")

    packaged_stream_reservations = _native_stream_reservations(stream_reservations)
    packed = pack_replay_uncompressed(
        bytes(body), packaged_stream_reservations, xfile_version=0xFF7,
        transient_type=profile["final_header"]["transient_type"])
    if unpack_replay_uncompressed(packed) != body:
        raise ValueError("IWC packer did not preserve the merged XFile body")
    patch_source = Path(patches[0]["path"]).resolve(strict=True)
    if sha256_file(patch_source) != patches[0].get("sha256"):
        raise ValueError("destination FP changed after source-profile capture")
    patch_bytes = make_replay_header_only_patch(patch_source.read_bytes(), packed)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="zone-merge-verify-", dir=output_path.parent) as temp_name:
        temp_root = Path(temp_name)
        temp_ff = temp_root / output_path.name
        temp_fp = temp_ff.with_suffix(".fp")
        temp_ff.write_bytes(packed)
        temp_fp.write_bytes(patch_bytes)
        from roundtrip_replay_fastfile import verify_native
        native = verify_native(temp_ff, bytes(body), source_path, Path(acts_path),
                               Path(replay_executable), temp_root / "native", timeout,
                               trace=bool(references), reference_only_rows=references)
        if source_profile(source_path) != profile:
            raise ValueError("destination FF/FP changed during native verification")
        if sha256_file(patch_source) != patches[0].get("sha256"):
            raise ValueError("destination FP changed during native verification")
        manifest = native["manifest"]
        _validate_native_reread_manifest(manifest, len(expected_identity), len(body), references)
        applied = manifest.get("applied_patches", [])
        if len(applied) != 1 or Path(applied[0]).resolve() != temp_fp.resolve():
            raise ValueError("native Replay reread did not apply the generated FP")
        manifest_path = Path(native["manifest_path"])
        journal_path = manifest_path.parent / manifest.get("journal", "assets.jsonl")
        rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        expected_tested = [identity for index, identity in enumerate(expected_identity)
                           if index not in reference_by_index]
        actual_identity = [(row.get("type_id"), row.get("name")) for row in rows]
        if len(rows) != len(expected_tested) or actual_identity != expected_tested:
            raise ValueError("native Replay reader changed merged XAsset identity/order")
        if manifest.get("serialized_bytes_read") != len(body):
            raise ValueError("native Replay reader did not consume the exact merged body")
        native_summary = {
            key: manifest.get(key) for key in (
                "complete", "success", "profile", "xfile_version", "tested", "failed",
                "unavailable", "top_level_index", "loaded_assets", "serialized_bytes_read")
        }
        native_summary["applied_patches"] = [Path(path).suffix for path in applied]
        native_summary["reference_only_rows"] = references
        native_summary["raw_journal_rows"] = len(rows)
        journal_hash = sha256_file(journal_path)
        log_hash = native["log_sha256"]

    if output_path.exists() or output_patch.exists():
        raise FileExistsError("zone-merge output path was created during native verification")
    temp_ff_path = output_path.with_name(output_path.name + ".verified.tmp")
    temp_fp_path = output_patch.with_name(output_patch.name + ".verified.tmp")
    try:
        temp_ff_path.write_bytes(packed)
        temp_fp_path.write_bytes(patch_bytes)
        if sha256_file(temp_ff_path) != _sha(packed) or sha256_file(temp_fp_path) != _sha(patch_bytes):
            raise ValueError("staged merge output failed its write/read hash check")
        os.rename(temp_ff_path, output_path)
        try:
            os.rename(temp_fp_path, output_patch)
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
    finally:
        temp_ff_path.unlink(missing_ok=True)
        temp_fp_path.unlink(missing_ok=True)
    return {
        "schema": 1,
        "status": "native-reader-pass-not-live-tested",
        "source_fastfile": str(source_path),
        "source_fastfile_sha256": sha256_file(source_path),
        "source_patch_sha256": sha256_file(patch_source),
        "body_sha256": _sha(bytes(body)),
        "body_bytes": len(body),
        "stream_highwaters": list(stream_reservations),
        "packaged_stream_reservations": packaged_stream_reservations,
        "ordered_asset_identity_count": len(expected_identity),
        "output_fastfile": str(output_path),
        "output_fastfile_sha256": sha256_file(output_path),
        "output_patch": str(output_patch),
        "output_patch_sha256": sha256_file(output_patch),
        "native_reader": native_summary,
        "native_journal_sha256": journal_hash,
        "native_log_sha256": log_hash,
        "acts_tool_identity": native["acts_tool_identity"],
        "replay_executable_sha256": native["replay_executable_sha256"],
        "runtime_claim": "native serialized reread only; no game launch or visual/runtime claim",
    }

