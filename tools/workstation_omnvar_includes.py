"""Resolve Omnvar StringTable includes against native type-54 source rows.

Discovery uses ACTS CSV exports only to select candidate rows. A caller must
then bind every discovered table with ``inspect_stringtable`` before its
definition names are used for validation. The second phase ties CSV contents
to the exact decoded body, native XAsset journal, and complete stream trace.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
from collections.abc import Iterable
from typing import Any, Callable, Mapping, Sequence


class OmnvarIncludeError(ValueError):
    """An include chain is ambiguous, unsafe, incomplete, or not native-bound."""


def project_type54_packed_resolution(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return the exact compact callback record shared by all typed projections."""
    if (event.get("kind") not in ("packed_resolve", "packed_alias") or
            type(event.get("type_id")) is not int or event.get("type_id") != 54 or
            type(event.get("xasset_index")) is not int):
        return None
    return {key: event.get(key) for key in (
        "kind", "sequence", "xasset_index", "type_id", "raw_token",
        "field_stream_location", "resolved_target_stream_location")}


def read_type54_packed_resolutions(trace_path: str | Path, asset_indices: Iterable[int],
                                   expected_event_count: int) -> dict[int, list[dict[str, Any]]]:
    """Read exact type-54 packed callbacks from a complete ordered JSONL trace.

    The normal span index intentionally does not retain arbitrary alias events.
    This bounded projection keeps only callbacks for the include closure while
    validating sequence continuity and the full event count.
    """
    wanted = set(asset_indices)
    if any(not isinstance(index, int) or isinstance(index, bool) or index < 0 for index in wanted):
        raise OmnvarIncludeError("packed-resolution owner set contains an invalid asset index")
    if not isinstance(expected_event_count, int) or isinstance(expected_event_count, bool) or expected_event_count < 0:
        raise OmnvarIncludeError("native trace has an invalid expected event count")
    found: dict[int, list[dict[str, Any]]] = {index: [] for index in wanted}
    count = 0
    try:
        with Path(trace_path).open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                event = json.loads(line)
                if event.get("sequence") != count:
                    raise OmnvarIncludeError(f"native trace sequence is discontinuous at event {count}")
                count += 1
                projection = project_type54_packed_resolution(event)
                if projection is not None and projection["xasset_index"] in wanted:
                    found[projection["xasset_index"]].append(projection)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OmnvarIncludeError(f"cannot read complete native StringTable trace: {error}") from error
    if count != expected_event_count:
        raise OmnvarIncludeError("native trace event count differs from its complete-walk manifest")
    return found


def _canonical_sha(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _include_key(value: str) -> str:
    path = value.replace("\\", "/")
    if not path or path.startswith("/") or "\x00" in path:
        raise OmnvarIncludeError(f"invalid include asset path {value!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise OmnvarIncludeError(f"unsafe include asset path {value!r}")
    return "/".join(parts).casefold()


def _read_csv(path: Path) -> list[list[str]]:
    try:
        return list(csv.reader(io.StringIO(path.read_text(encoding="utf-8-sig"), newline="")))
    except (OSError, UnicodeError, csv.Error) as error:
        raise OmnvarIncludeError(f"cannot read native StringTable CSV {path.name}: {error}") from error


def _table_rows(rows: Sequence[Sequence[str]], asset_name: str) -> tuple[list[str], list[str]]:
    includes: list[str] = []
    definitions: list[str] = []
    definitions_started = False
    if not rows:
        raise OmnvarIncludeError(f"StringTable {asset_name!r} has no rows")
    for row_number, row in enumerate(rows, start=1):
        if not row or not row[0]:
            raise OmnvarIncludeError(f"StringTable {asset_name!r}, row {row_number}: blank name cell")
        if row[0] == "include":
            if definitions_started:
                raise OmnvarIncludeError(
                    f"StringTable {asset_name!r}, row {row_number}: include follows definition row")
            if len(row) < 2 or not row[1] or row[1].strip() != row[1]:
                raise OmnvarIncludeError(
                    f"StringTable {asset_name!r}, row {row_number}: malformed include path")
            if any(cell for cell in row[2:]):
                raise OmnvarIncludeError(
                    f"StringTable {asset_name!r}, row {row_number}: include row has extra values")
            includes.append(row[1])
        else:
            definitions_started = True
            try:
                row[0].encode("ascii")
            except UnicodeEncodeError as error:
                raise OmnvarIncludeError(
                    f"StringTable {asset_name!r}, row {row_number}: non-ASCII Omnvar name") from error
            definitions.append(row[0])
    return includes, definitions


def discover_omnvar_include_closure(
    root_name: str,
    root_rows: Sequence[Sequence[str]],
    *,
    native_rows: Sequence[Mapping[str, Any]],
    export_root: str | Path,
    export_index: Mapping[str, Any],
    expected_body_sha256: str,
    expected_native_walk_key: str,
    max_assets: int = 32,
    max_depth: int = 8,
) -> dict[str, Any]:
    """Discover each included type-54 row from a complete native export.

    The root content comes from the caller's ACTS export and is checked against
    the matching indexed payload. Every included payload is hash-checked and
    identity-joined to the ordered native journal. The result is provisional
    until ``bind_omnvar_include_closure`` proves each table against trace/body.
    """
    if (not isinstance(max_assets, int) or isinstance(max_assets, bool) or max_assets < 1 or
            not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0):
        raise ValueError("include limits must be non-negative integer bounds")
    if (export_index.get("type_id") != 54 or export_index.get("body_sha256") != expected_body_sha256 or
            export_index.get("native_walk_key") != expected_native_walk_key):
        raise OmnvarIncludeError("StringTable export index is not bound to the current native body/walk")
    root = Path(export_root).resolve(strict=True)
    items = export_index.get("items")
    if not isinstance(items, list):
        raise OmnvarIncludeError("StringTable export index has no ordered payload rows")
    expected = [(index, row) for index, row in enumerate(native_rows)
                if row.get("type_id") == 54 and row.get("status") != "reference"]
    if len(items) != len(expected):
        raise OmnvarIncludeError("StringTable export count differs from native type-54 journal rows")

    by_index: dict[int, dict[str, Any]] = {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for rank, ((asset_index, native), item) in enumerate(zip(expected, items, strict=True)):
        if (item.get("rank") != rank or item.get("asset_index") != asset_index or
                item.get("type_id") != 54 or item.get("name") != native.get("name") or
                not isinstance(native.get("name"), str) or not native.get("name")):
            raise OmnvarIncludeError(f"StringTable export row {rank} differs from native journal identity")
        relative = Path(str(item.get("payload_relative_path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise OmnvarIncludeError(f"StringTable export row {rank} has an unsafe payload path")
        payload_path = (root / relative).resolve(strict=True)
        if not payload_path.is_relative_to(root) or not payload_path.is_file():
            raise OmnvarIncludeError(f"StringTable export row {rank} payload escapes its export")
        payload_bytes = payload_path.read_bytes()
        payload_sha = hashlib.sha256(payload_bytes).hexdigest()
        if (len(payload_bytes) != item.get("payload_bytes") or
                payload_sha != item.get("payload_sha256")):
            raise OmnvarIncludeError(f"StringTable export row {rank} payload hash changed")
        entry = dict(asset_index=asset_index, type_id=54, name=native["name"],
                     native_status=native.get("status"), native_row_sha256=_canonical_sha(native),
                     payload_path=str(payload_path), payload_sha256=payload_sha,
                     rows=None, native_row=dict(native))
        by_index[asset_index] = entry
        by_name.setdefault(_include_key(native["name"]), []).append(entry)

    root_matches = by_name.get(_include_key(root_name), [])
    if len(root_matches) != 1:
        raise OmnvarIncludeError("Omnvar root must resolve to exactly one native type-54 export row")
    root_entry = root_matches[0]
    root_entry["rows"] = _read_csv(Path(root_entry["payload_path"]))
    if [list(row) for row in root_entry["rows"]] != [list(row) for row in root_rows]:
        raise OmnvarIncludeError("selected Omnvar CSV differs from its hash-pinned native export payload")

    visited: dict[str, dict[str, Any]] = {}
    active: list[str] = []
    include_edges: list[dict[str, Any]] = []

    def visit(entry: dict[str, Any], depth: int) -> None:
        key = _include_key(entry["name"])
        if key in active:
            chain = " -> ".join([*(active), key])
            raise OmnvarIncludeError(f"Omnvar include cycle: {chain}")
        if key in visited:
            raise OmnvarIncludeError(f"duplicate or multiply-reached included table {entry['name']!r}")
        if depth > max_depth:
            raise OmnvarIncludeError("Omnvar include depth exceeds the configured bound")
        if len(visited) >= max_assets:
            raise OmnvarIncludeError("Omnvar include asset count exceeds the configured bound")
        visited[key] = entry
        active.append(key)
        includes, definitions = _table_rows(entry["rows"], entry["name"])
        entry["include_paths"] = list(includes)
        entry["definition_names"] = list(definitions)
        seen_here: set[str] = set()
        for path in includes:
            target_key = _include_key(path)
            if target_key in seen_here:
                raise OmnvarIncludeError(f"duplicate include {path!r} in {entry['name']!r}")
            seen_here.add(target_key)
            candidates = by_name.get(target_key, [])
            if len(candidates) != 1:
                detail = "missing" if not candidates else "ambiguous"
                raise OmnvarIncludeError(f"{detail} native type-54 include target {path!r}")
            target = candidates[0]
            if target["asset_index"] == entry["asset_index"]:
                raise OmnvarIncludeError(f"StringTable {entry['name']!r} includes itself")
            if target["rows"] is None:
                target["rows"] = _read_csv(Path(target["payload_path"]))
            include_edges.append(dict(source_asset_index=entry["asset_index"],
                                      source_name=entry["name"], include_path=path,
                                      target_asset_index=target["asset_index"],
                                      target_name=target["name"]))
            visit(target, depth + 1)
        active.pop()

    visit(root_entry, 0)
    return dict(schema="replay120-omnvar-include-discovery-v1",
                status="provisional-native-type54-closure",
                expected_body_sha256=expected_body_sha256,
                expected_native_walk_key=expected_native_walk_key,
                export_index_sha256=_canonical_sha(export_index),
                tables=[visited[key] for key in visited],
                include_edges=include_edges,
                limits=dict(max_assets=max_assets, max_depth=max_depth))


def bind_omnvar_include_closure(
    discovery: Mapping[str, Any],
    *,
    body_data: bytes,
    body_sha256: str,
    trace_sha256: str,
    trace_assets: Mapping[int, Mapping[str, Any]],
    global_string_data_spans: list[dict],
    packed_resolutions: Mapping[int, Sequence[Mapping[str, Any]]],
    inspect_stringtable: Callable[..., tuple[Any, list[list[str]]]],
) -> dict[str, Any]:
    """Bind every provisional table to its exact trace-owned body record."""
    if hashlib.sha256(body_data).hexdigest() != body_sha256:
        raise OmnvarIncludeError("decoded source body hash changed during include validation")
    if (discovery.get("status") != "provisional-native-type54-closure" or
            discovery.get("expected_body_sha256") != body_sha256):
        raise OmnvarIncludeError("include discovery is not bound to the current decoded body")
    for item in discovery.get("tables", []):
        index = item.get("asset_index")
        if not isinstance(index, int) or isinstance(index, bool):
            raise OmnvarIncludeError("include table has an invalid native asset index")
        if not isinstance(trace_assets.get(index), Mapping):
            raise OmnvarIncludeError(f"complete trace omits included type-54 row {index}")
    tables: list[dict[str, Any]] = []
    all_names: list[str] = []
    for item in discovery.get("tables", []):
        index = item.get("asset_index")
        if not isinstance(index, int) or isinstance(index, bool):
            raise OmnvarIncludeError("include table has an invalid native asset index")
        trace = trace_assets.get(index)
        if not isinstance(trace, Mapping):
            raise OmnvarIncludeError(f"complete trace omits included type-54 row {index}")
        bound_trace = dict(trace)
        bound_trace.update(index=index, xasset_index=index, type_id=54, name=item["name"])
        bound_trace["root_name_resolution_events"] = list(packed_resolutions.get(index, []))
        try:
            layout, parsed_rows = inspect_stringtable(
                body_data, index, item["name"], bound_trace, item["rows"],
                expected_body_sha256=body_sha256,
                global_string_data_spans=global_string_data_spans,
                require_packed_dictionary_proof=True)
        except Exception as error:
            raise OmnvarIncludeError(
                f"native StringTable {item['name']!r} does not match its source CSV/body/trace: {error}") from error
        if [list(row) for row in parsed_rows] != [list(row) for row in item["rows"]]:
            raise OmnvarIncludeError(f"native StringTable {item['name']!r} returned different semantic rows")
        all_names.extend(item["definition_names"])
        tables.append(dict(asset_index=index, type_id=54, name=item["name"],
                           native_status=item.get("native_status"),
                           native_row_sha256=item["native_row_sha256"],
                           source_csv_sha256=item["payload_sha256"],
                           source_body_sha256=body_sha256,
                           root_archive_offset=layout.root_archive_offset,
                           archive_end=layout.archive_end,
                           name_pointer_mode=layout.name_pointer_mode,
                           name_pointer_token=layout.name_pointer_token,
                           name_target_archive_offset=layout.name_target_archive_offset,
                           name_target_event_sequence=layout.name_target_event_sequence,
                           packed_dictionary_references=list(layout.packed_dictionary_references),
                           root_name_resolution_events=list(bound_trace.get("root_name_resolution_events", [])),
                           source_record_sha256=layout.source_record_sha256,
                           trace_asset_sha256=_canonical_sha(bound_trace),
                           row_count=len(item["rows"]),
                           include_paths=list(item["include_paths"]),
                           definition_names=list(item["definition_names"])))
    return dict(schema="replay120-omnvar-native-include-closure-v1",
                status="native-body-trace-bound",
                source_body_sha256=body_sha256,
                source_trace_sha256=trace_sha256,
                native_walk_key=discovery["expected_native_walk_key"],
                export_index_sha256=discovery["export_index_sha256"],
                tables=tables,
                include_edges=list(discovery["include_edges"]),
                included_definition_names=[name for table in tables
                                           if table["asset_index"] != discovery["tables"][0]["asset_index"]
                                           for name in table["definition_names"]])
