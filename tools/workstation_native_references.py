"""Derive reference-only XAsset identities from native Replay root reads.

The ACTS journal remains the raw native-tested journal. This module builds a
separate table-ordered inventory by joining that journal with indexed
reference roots whose name reads are directly visible in the native trace.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from inspect_frontend_asset_table import inspect as inspect_xasset_table

REFERENCE_ROOT_NAME_TYPES = frozenset({9, 11, 19, 58, 75, 77, 78})
REFERENCE_POINTER_TOKEN = 0xFFFFFFFFFFFFFFFD
INLINE_STRING_TOKEN = 0xFFFFFFFFFFFFFFFE
MAX_ROOT_NAME_BYTES = 4096


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _location(value: object, stream: int, offset: int) -> bool:
    return (isinstance(value, dict) and value.get("stream") == stream and
            value.get("offset") == offset)


def _trace_rows(path: Path, table_rows: list[dict]) -> tuple[dict[int, dict], dict[int, dict]]:
    """Validate trace order/callback coverage while retaining only root evidence."""
    count = len(table_rows)
    candidates = {
        row["index"] for row in table_rows
        if row["type_id"] in REFERENCE_ROOT_NAME_TYPES and
        int(row["pointer_token"], 16) == REFERENCE_POINTER_TOKEN
    }
    begins: dict[int, dict] = {}
    ends: dict[int, int] = {}
    root_evidence = {
        index: dict(root_loads=[], root_names=[], string_ops=[], name_loads=[], root_links=[])
        for index in candidates
    }
    expected_sequence = 0
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid trace JSON at line {line_number}") from error
            sequence = event.get("sequence")
            if (not isinstance(sequence, int) or isinstance(sequence, bool) or
                    sequence != expected_sequence):
                raise ValueError(f"native trace sequence breaks at event {expected_sequence}")
            expected_sequence += 1
            kind = event.get("kind")
            index = event.get("xasset_index")
            if kind in ("xasset_begin", "xasset_end"):
                if (not isinstance(index, int) or isinstance(index, bool) or
                        not 0 <= index < count):
                    raise ValueError(f"native trace {kind} has an out-of-range table index")
                if kind == "xasset_begin":
                    if index in begins:
                        raise ValueError(f"native trace repeats top-level XAsset begin {index}")
                    begins[index] = event
                else:
                    if index in ends:
                        raise ValueError(f"native trace repeats top-level XAsset end {index}")
                    ends[index] = event.get("sequence")
            if index not in root_evidence:
                continue
            evidence = root_evidence[index]
            if (kind == "load_stream_call" and event.get("at_start") is True and
                    _location(event.get("destination_stream_location"), 1, 0)):
                evidence["root_loads"].append(event)
            elif (kind == "string_call" and
                  _location(event.get("field_stream_location"), 1, 0)):
                evidence["root_names"].append(event)
            elif kind == "stream_operation":
                if event.get("operation") == "string":
                    evidence["string_ops"].append(event)
                elif event.get("operation") == "load":
                    evidence["name_loads"].append(event)
            elif (kind == "asset_root_link" and
                  _location(event.get("root_stream_location"), 1, 0)):
                evidence["root_links"].append(event)

    expected = set(range(count))
    if set(begins) != expected or set(ends) != expected:
        missing_begins = sorted(expected - set(begins))[:8]
        missing_ends = sorted(expected - set(ends))[:8]
        raise ValueError(f"native trace does not cover every XAsset callback: "
                         f"missing_begin={missing_begins} missing_end={missing_ends}")
    for row in table_rows:
        event = begins[row["index"]]
        if event.get("type_id", event.get("asset_type")) != row["type_id"]:
            raise ValueError(f"native trace type differs from table row {row['index']}")
        pointer = event.get("pointer_token")
        if (not isinstance(pointer, int) or isinstance(pointer, bool) or
                pointer != int(row["pointer_token"], 16)):
            raise ValueError(f"native trace pointer token differs from table row {row['index']}")
        end_sequence = ends[row["index"]]
        begin_sequence = event.get("sequence")
        if (not isinstance(begin_sequence, int) or isinstance(begin_sequence, bool) or
                not isinstance(end_sequence, int) or isinstance(end_sequence, bool) or
                end_sequence <= begin_sequence):
            raise ValueError(f"native trace XAsset end precedes begin at row {row['index']}")
    callback_ranges = sorted((begins[index]["sequence"], ends[index], index)
                             for index in range(count))
    if [index for _, index in sorted((begins[index]["sequence"], index)
                                      for index in range(count))] != list(range(count)):
        raise ValueError("native trace top-level XAsset callbacks do not follow table index order")
    if any(callback_ranges[i][1] >= callback_ranges[i + 1][0]
           for i in range(len(callback_ranges) - 1)):
        raise ValueError("native trace top-level XAsset callback ranges overlap")
    for index, per_asset in root_evidence.items():
        begin_sequence = begins[index]["sequence"]
        end_sequence = ends[index]
        if any(not isinstance(event.get("sequence"), int) or
               isinstance(event.get("sequence"), bool) or
               not begin_sequence <= event["sequence"] <= end_sequence
               for events in per_asset.values() for event in events):
            raise ValueError(f"native root evidence escapes callback bounds at table row {index}")
    return begins, root_evidence, expected_sequence


def _root_name(body: bytes, index: int, table_row: dict,
               begin: dict, evidence: dict) -> dict:
    if len(evidence["root_loads"]) != 1 or len(evidence["root_names"]) != 1 or \
            len(evidence["root_links"]) > 1:
        raise ValueError(f"root-name asset {index} lacks a unique top-level root/name trace")
    root_load = evidence["root_loads"][0]
    root_start = root_load.get("serialized_input_cursor")
    root_size = root_load.get("size")
    if (not isinstance(root_start, int) or isinstance(root_start, bool) or
            not isinstance(root_size, int) or isinstance(root_size, bool) or
            root_start < 0 or root_size < 8 or root_start + root_size > len(body) or
            root_load.get("loader_start_arg") != 0):
        raise ValueError(f"root-name asset {index} has an invalid traced root extent")
    root_op = [event for event in evidence["name_loads"]
               if event.get("input_before") == root_start and
               event.get("input_after") == root_start + root_size and
               event.get("size") == root_size and
               event.get("physical_input_bytes") == root_size and
               event.get("block_before") == 1 and event.get("offset_before") == 0 and
               event.get("block_after") == 1 and event.get("offset_after") == root_size]
    if len(root_op) != 1 or struct_qword(body, root_start) != INLINE_STRING_TOKEN:
        raise ValueError(f"root-name asset {index} lacks an exact inline-name root read")
    name_cursor = root_start + root_size
    name_calls = [event for event in evidence["root_names"]
                  if event.get("serialized_input_cursor") == name_cursor]
    string_ops = [event for event in evidence["string_ops"]
                  if event.get("input_before") == name_cursor and
                  isinstance(event.get("size"), int) and 1 < event["size"] <= MAX_ROOT_NAME_BYTES]
    if len(name_calls) != 1 or len(string_ops) != 1:
        raise ValueError(f"root-name asset {index} has no unique root-name string read")
    string_size = string_ops[0]["size"]
    name_loads = [event for event in evidence["name_loads"]
                  if event.get("input_before") == name_cursor and
                  event.get("input_after") == name_cursor + string_size and
                  event.get("size") == string_size and
                  event.get("physical_input_bytes") == string_size]
    if len(name_loads) != 1 or name_cursor + string_size > len(body):
        raise ValueError(f"root-name asset {index} name bytes lack an exact physical trace read")
    name_bytes = body[name_cursor:name_cursor + string_size]
    if name_bytes[-1:] != b"\0" or b"\0" in name_bytes[:-1]:
        raise ValueError(f"root-name asset {index} name is not one exact NUL-terminated string")
    try:
        name = name_bytes[:-1].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"root-name asset {index} name is not UTF-8") from error
    if name.startswith(",") and len(name) == 1:
        raise ValueError(f"reference root {index} has an empty comma-reference basename")
    link = evidence["root_links"][0] if evidence["root_links"] else None
    if link is not None and (link.get("root_bytes") != root_size or
                             not isinstance(link.get("root_archive_input_cursor"), int) or
                             link["root_archive_input_cursor"] < name_cursor + string_size or
                             link["root_archive_input_cursor"] > len(body)):
        raise ValueError(f"root-name asset {index} link does not cover the traced root and name")
    if (begin.get("type_id", begin.get("asset_type")) != table_row["type_id"] or
            begin.get("pointer_token") != REFERENCE_POINTER_TOKEN):
        raise ValueError(f"root-name asset {index} begin event differs from its table header")
    return dict(index=index, type_id=table_row["type_id"], name=name,
                pointer_token=REFERENCE_POINTER_TOKEN,
                root_size=root_size, root_archive_offset=root_start,
                name_archive_offset=name_cursor, name_bytes=string_size,
                root_load_sequence=root_load.get("sequence"),
                name_string_sequence=string_ops[0].get("sequence"),
                name_physical_load_sequence=name_loads[0].get("sequence"),
                root_link_sequence=link.get("sequence") if link else None,
                status=("reference" if name.startswith(",") else "native-tested"))


def struct_qword(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("qword read is outside the decoded body")
    return int.from_bytes(data[offset:offset + 8], "little")


def normalize_native_inventory(body: bytes, trace_path: str | Path,
                               manifest: dict, raw_journal_rows: list[dict]) -> dict:
    """Return trace-derived references plus a separate normalized table view.

    `raw_journal_rows` remains the ACTS-tested sequence and is never rewritten.
    Reference descriptors are derived automatically from serialized FD rows in
    the proven root-name asset types; caller-provided reference indices are not
    accepted.
    """
    table = inspect_xasset_table(body)
    table_rows = table["assets"]
    references_declared = manifest.get("reference_only_rows", [])
    if references_declared not in ([], None):
        raise ValueError("input manifest already has reference rows; derive them from trace instead")
    tested = manifest.get("tested")
    top_level = manifest.get("top_level_index")
    if (manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 4087 or
            manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
            not isinstance(tested, int) or isinstance(tested, bool) or
            not isinstance(top_level, int) or isinstance(top_level, bool) or
            top_level != len(table_rows) or tested != len(raw_journal_rows) or
            manifest.get("serialized_bytes_read") != len(body)):
        raise ValueError("raw native walk does not exactly cover its body, journal and EOF")
    trace_path = Path(trace_path).resolve(strict=True)
    begins, evidence, trace_event_count = _trace_rows(trace_path, table_rows)
    if ("stream_trace_events" in manifest and
            manifest.get("stream_trace_events") != trace_event_count):
        raise ValueError("native trace event count differs from its raw manifest")
    traced_roots = {}
    for row in table_rows:
        index = row["index"]
        if (row["type_id"] in REFERENCE_ROOT_NAME_TYPES and
                int(row["pointer_token"], 16) == REFERENCE_POINTER_TOKEN):
            traced_roots[index] = _root_name(body, index, row, begins[index], evidence[index])
    refs = {index: row for index, row in traced_roots.items()
            if row["name"].startswith(",")}
    if tested + len(refs) != top_level:
        raise ValueError(f"derived reference count does not reconcile full table coverage: "
                         f"tested={tested} references={len(refs)} top_level={top_level}")
    normalized = []
    raw_index = 0
    for table_row in table_rows:
        index = table_row["index"]
        if index in refs:
            normalized.append(refs[index])
            continue
        if raw_index >= len(raw_journal_rows):
            raise ValueError("raw native journal ended before normalized table coverage")
        source_row = raw_journal_rows[raw_index]
        raw_index += 1
        if (source_row.get("type_id") != table_row["type_id"] or
                not isinstance(source_row.get("name"), str) or
                source_row["name"].startswith(",")):
            raise ValueError(f"raw native journal identity/order differs at table index {index}")
        traced = traced_roots.get(index)
        if traced is not None and source_row["name"] != traced["name"]:
            raise ValueError(f"raw native journal identity/order name differs from root trace "
                             f"at table index {index}")
        normalized.append(dict(source_row, index=index,
                               pointer_token=table_row["pointer_token"],
                               status=source_row.get("status", "native-tested")))
    if raw_index != len(raw_journal_rows):
        raise ValueError("raw native journal contains rows beyond normalized table coverage")
    return dict(schema="replay120-native-normalized-inventory-v1",
                body_sha256=_sha(body), trace_sha256=_sha_file(trace_path),
                raw_tested_count=tested, normalized_inventory_count=len(normalized),
                reference_only_rows=[refs[index] for index in sorted(refs)],
                normalized_rows=normalized)

