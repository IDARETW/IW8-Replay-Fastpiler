"""Build a checked archive-to-resident read-span index from ACTS Replay traces.

This index records native physical reads and their destination stream offsets.
It deliberately does not call those reads complete asset layouts: scalar fields,
pointer semantics, sharing and alignment still need type-specific contracts.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Iterable
import uuid


_STREAM_METRICS = (
    "max_destination_offsets", "physical_load_count_by_stream",
    "physical_load_bytes_by_stream", "packed_target_stream_counts",
    "packed_alias_token_highword_counts",
)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _index_json(value: dict) -> bytes:
    # Preserve insertion order across JSON roundtrips, including stream keys
    # such as 2 and 10 that would sort differently after becoming strings.
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def build_read_span_index(trace_path: str | Path, manifest_path: str | Path,
                          body_size: int, selected_assets: Iterable[int] | None = None) -> dict:
    """Reuse a derived index only while its input and parser hashes match.

    The cache contains all owners, so changing the selected assets never
    weakens the complete trace validation. It lives beside the private native
    trace; no derived file is added to a game package.
    """
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    identity = dict(schema=1, body_size=body_size,
                    trace_sha256=_file_sha256(trace_path),
                    manifest_sha256=_file_sha256(manifest_path),
                    parser_sha256=_file_sha256(Path(__file__)))
    key = hashlib.sha256(_index_json(identity)).hexdigest()
    cache_path = trace_path.parent / f"read-span-index-{key}.json"
    result = None
    if cache_path.is_file():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            candidate = cached["index"]
            if (cached["identity"] == identity and
                    hashlib.sha256(_index_json(candidate)).hexdigest() == cached["index_sha256"]):
                result = candidate
                # JSON object keys are strings; preserve the native API's
                # integer stream keys on cache hits.
                for row in [result, *result["assets"]]:
                    for metric in _STREAM_METRICS:
                        if metric in row:
                            row[metric] = {int(k): v for k, v in row[metric].items()}
        except (OSError, ValueError, KeyError, TypeError):
            result = None
    if result is None:
        result = _build_read_span_index(trace_path, manifest_path, body_size)
        if (_file_sha256(trace_path) != identity["trace_sha256"] or
                _file_sha256(manifest_path) != identity["manifest_sha256"] or
                _file_sha256(Path(__file__)) != identity["parser_sha256"]):
            raise ValueError("native trace, manifest or index parser changed during indexing")
        temporary = cache_path.with_name(cache_path.name + f".{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_bytes(_index_json(dict(
                identity=identity, index=result,
                index_sha256=hashlib.sha256(_index_json(result)).hexdigest())))
            temporary.replace(cache_path)
        except OSError:
            # A read-only trace location still supports validated inspection.
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    # Keep one in-memory physical allocation view for typed adapters. This is
    # derived from the complete cached index, including preamble reads, and is
    # deliberately attached only after the serialized cache hash is checked.
    if "_all_physical_spans" not in result:
        result["_all_physical_spans"] = [
            span for owner in [{"read_spans": result.get("preamble_spans", [])},
                               *result.get("assets", [])]
            for span in owner.get("read_spans", [])
        ]
    if selected_assets is None:
        return result
    selected = set(selected_assets)
    return dict(result, assets=[row for row in result["assets"] if row["index"] in selected])


def _build_read_span_index(trace_path: str | Path, manifest_path: str | Path,
                          body_size: int, selected_assets: Iterable[int] | None = None) -> dict:
    trace_path, manifest_path = Path(trace_path), Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = manifest.get("stream_trace_events")
    if not isinstance(expected, int) or expected < 0 or body_size < 0:
        raise ValueError("invalid trace event count or decoded body size")
    selected = None if selected_assets is None else set(selected_assets)
    from workstation_omnvar_includes import project_type54_packed_resolution
    assets: list[dict] = []
    active: dict | None = None
    last_seq = 0
    event_count = 0
    physical_total = 0
    preamble_spans: list[dict] = []
    pending_call: dict | None = None
    pending_string: dict | None = None
    max_destination_offsets: dict[int, int] = {}
    physical_load_count_by_stream: dict[int, int] = {}
    physical_load_bytes_by_stream: dict[int, int] = {}
    packed_target_stream_counts: dict[int, int] = {}
    packed_alias_token_highword_counts: dict[int, int] = {}

    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            seq = event.get("sequence")
            if seq != event_count:
                raise ValueError(f"trace sequence discontinuity at event {event_count}")
            event_count += 1
            kind = event.get("kind")
            if kind == "stream_operation":
                for block, offset in ((event.get("block_before"), event.get("offset_before")),
                                      (event.get("block_after"), event.get("offset_after"))):
                    if isinstance(block, int) and isinstance(offset, int):
                        max_destination_offsets[block] = max(
                            max_destination_offsets.get(block, 0), offset)
                        if active is not None:
                            active["max_destination_offsets"][block] = max(
                                active["max_destination_offsets"].get(block, 0), offset)
                if (active is not None and active.get("type_id") == 54 and
                        event.get("xasset_index") == active.get("index")):
                    # Type-54 empty tables have no physical child spans. Keep
                    # their small owner-local schedule so typed inspection can
                    # derive the zero-length section anchors from native align
                    # and load callbacks instead of guessing archive offsets.
                    active["stream_operations"].append({key: event.get(key) for key in (
                        "sequence", "operation", "block_before", "offset_before",
                        "block_after", "offset_after", "value", "size",
                        "physical_input_bytes", "input_before", "input_after")})

            if kind in ("packed_resolve", "packed_alias"):
                target = event.get("resolved_target_stream_location")
                if isinstance(target, dict) and isinstance(target.get("stream"), int):
                    block = target["stream"]
                    packed_target_stream_counts[block] = packed_target_stream_counts.get(block, 0) + 1
                if kind == "packed_alias" and isinstance(event.get("raw_token"), int):
                    highword = event["raw_token"] >> 32
                    packed_alias_token_highword_counts[highword] = \
                        packed_alias_token_highword_counts.get(highword, 0) + 1
                if (active is not None and active.get("type_id") in (12, 14, 15, 16, 17, 19, 41, 51) and
                        event.get("xasset_index") == active["index"]):
                    # Keep a compact owner-local index for typed adapters that
                    # must bind a serialized pointer field to its exact native
                    # resolution callback. The source trace remains authoritative.
                    active["packed_pointer_events"].append({
                        key: event.get(key) for key in (
                            "sequence", "kind", "xasset_index", "type_id", "raw_token",
                            "field_stream_location", "resolved_target_stream_location")
                    })
                if active is not None and active.get("type_id") == 54:
                    # StringTable root names and dictionary entries may use
                    # packed aliases. Preserve only exact callbacks owned by
                    # this XAsset; inspect_stringtable verifies each field,
                    # token, destination, name allocation, and source bytes.
                    projection = project_type54_packed_resolution(event)
                    if (projection is not None and
                            projection["xasset_index"] == active["index"]):
                        active["root_name_resolution_events"].append(projection)

            if kind == "xasset_begin":
                if active is not None:
                    raise ValueError("nested XAsset begin before matching end")
                index = event.get("xasset_index")
                if not isinstance(index, int):
                    raise ValueError("XAsset begin has no integer index")
                active = dict(index=index, type_id=event.get("asset_type"),
                              begin_sequence=seq,
                              begin_cursor=event.get("serialized_input_cursor"),
                              root_stream_location=event.get("root_stream_location"),
                              read_spans=[], packed_pointer_events=[], stream_operations=[],
                              physical_load_count_by_stream={},
                              physical_load_bytes_by_stream={}, max_destination_offsets={})
                if active["type_id"] == 54:
                    active["root_name_resolution_events"] = []
                pending_call = pending_string = None
                continue

            if kind == "xasset_end":
                if active is None or event.get("xasset_index") != active["index"]:
                    raise ValueError("XAsset end does not match active owner")
                active["end_sequence"] = seq
                active["end_cursor"] = event.get("serialized_input_cursor")
                if selected is None or active["index"] in selected:
                    assets.append(active)
                active = None
                pending_call = pending_string = None
                continue

            if kind == "load_stream_call":
                if active is not None:
                    if event.get("xasset_index") != active["index"]:
                        raise ValueError("load call has incorrect XAsset owner")
                    pending_call = event
                continue

            if kind == "stream_operation" and event.get("operation") == "string":
                pending_string = dict(block=event.get("block_after"),
                                      offset=event.get("offset_after"),
                                      size=event.get("size"), sequence=seq)
                continue

            if kind != "stream_operation" or event.get("operation") not in ("load", "take"):
                # Calls that do not immediately materialize a physical load
                # must not be used to label a later unrelated read.
                if pending_call and seq > pending_call.get("sequence", seq) + 1:
                    pending_call = None
                continue

            if active is not None and event.get("xasset_index") != active["index"]:
                raise ValueError("physical load has incorrect XAsset owner")
            physical = event.get("physical_input_bytes")
            size = event.get("size")
            before = event.get("input_before")
            after = event.get("input_after")
            if not all(isinstance(v, int) for v in (physical, size, before, after)):
                raise ValueError(f"load event {seq} lacks integer span values")
            if after - before != physical or physical not in (0, size):
                raise ValueError(f"load event {seq} has inconsistent physical extent")
            physical_total += physical
            if event.get("operation") == "load" and physical:
                block = event.get("block_before")
                if isinstance(block, int):
                    physical_load_count_by_stream[block] = physical_load_count_by_stream.get(block, 0) + 1
                    physical_load_bytes_by_stream[block] = physical_load_bytes_by_stream.get(block, 0) + physical
                    if active is not None:
                        active["physical_load_count_by_stream"][block] = \
                            active["physical_load_count_by_stream"].get(block, 0) + 1
                        active["physical_load_bytes_by_stream"][block] = \
                            active["physical_load_bytes_by_stream"].get(block, 0) + physical
            if physical:
                # The decoded body starts at XFile offset zero; the initial
                # 32-byte Take is the XAssetList root and belongs in the span map.
                archive_offset = before
                if archive_offset < 0 or archive_offset + physical > body_size:
                    raise ValueError(f"load event {seq} falls outside decoded body")
                call = pending_call if pending_call and pending_call.get("sequence") == seq - 1 else None
                call_location = call.get("destination_stream_location") if call else None
                destination = (call_location if call_location and call.get("at_start") else
                               {"stream": event.get("block_before"),
                                "offset": event.get("offset_before")})
                origin = "load_stream_call" if call else "string_data" if (
                    pending_string and pending_string["block"] == event.get("block_before") and
                    pending_string["offset"] == event.get("offset_before") and
                    pending_string["size"] == size
                ) else "unclassified_load"
                span = dict(archive_offset=archive_offset, size=physical,
                            destination_stream_location=destination,
                            event_sequence=seq, serialized_cursor=before,
                            reader_start_arg=(call.get("loader_start_arg") if call else None),
                            caller_rva=(call.get("caller_rva") if call else None),
                            origin=origin)
                if active is None:
                    preamble_spans.append(span)
                elif selected is None or active["index"] in selected:
                    active["read_spans"].append(span)
            pending_call = None
            pending_string = None

    if event_count != expected:
        raise ValueError("trace event count differs from native manifest")
    if active is not None:
        raise ValueError("trace ended with an open XAsset")
    tested = manifest.get("tested")
    top_level = manifest.get("top_level_index")
    references = manifest.get("reference_only_rows", [])
    if (not isinstance(tested, int) or isinstance(tested, bool) or
            not isinstance(top_level, int) or isinstance(top_level, bool) or
            not isinstance(references, list)):
        raise ValueError("native manifest has invalid XAsset table coverage")
    reference_by_index = {}
    for reference in references:
        if not isinstance(reference, dict):
            raise ValueError("native reference-only row is malformed")
        index = reference.get("index")
        type_id = reference.get("type_id")
        name = reference.get("name")
        token = reference.get("pointer_token")
        if (not isinstance(index, int) or isinstance(index, bool) or
                not 0 <= index < top_level or index in reference_by_index or
                not isinstance(type_id, int) or isinstance(type_id, bool) or
                not isinstance(name, str) or not name.startswith(",") or
                type(token) is not int or token != 0xFFFFFFFFFFFFFFFD):
            raise ValueError("native reference-only row lacks exact indexed comma-name evidence")
        reference_by_index[index] = reference
    if tested + len(references) != top_level:
        raise ValueError("native tested assets plus indexed references do not cover the XAsset table")
    # Reference-only table rows still have native begin/end callbacks in the
    # trace, even though ACTS deliberately omits them from its tested journal.
    # Keep the raw tested count intact and require trace coverage for every
    # serialized table index instead of manufacturing journal rows.
    if len(assets) != top_level or {row["index"] for row in assets} != set(range(top_level)):
        raise ValueError("native trace callbacks do not cover every XAsset table row")
    assets_by_index = {row["index"]: row for row in assets}
    for index, reference in reference_by_index.items():
        if assets_by_index[index].get("type_id") != reference["type_id"]:
            raise ValueError("native reference-only descriptor differs from its traced XAsset type")
    if physical_total != manifest.get("serialized_bytes_read", 0):
        # Native Finish can consume trailing bytes without a callback.
        if physical_total > manifest.get("serialized_bytes_read", 0):
            raise ValueError("trace physical reads exceed native serialized EOF")
    string_data_spans = [
        {key: span.get(key) for key in
         ("origin", "archive_offset", "size", "destination_stream_location", "event_sequence")}
        for owner in [*assets, {"read_spans": preamble_spans}]
        for span in owner.get("read_spans", [])
        if span.get("origin") == "string_data"
    ]
    return dict(schema=1, status="native-read-spans-indexed",
                body_size=body_size, event_count=event_count,
                xasset_count=top_level,
                native_tested=tested,
                reference_only_rows=references,
                serialized_bytes_read=manifest.get("serialized_bytes_read"),
                physical_read_bytes=physical_total,
                max_destination_offsets=dict(sorted(max_destination_offsets.items())),
                physical_load_count_by_stream=dict(sorted(physical_load_count_by_stream.items())),
                physical_load_bytes_by_stream=dict(sorted(physical_load_bytes_by_stream.items())),
                packed_target_stream_counts=dict(sorted(packed_target_stream_counts.items())),
                packed_alias_token_highword_counts=dict(sorted(packed_alias_token_highword_counts.items())),
                unobserved_trailing_bytes=(manifest.get("serialized_bytes_read", 0) - physical_total),
                preamble_spans=preamble_spans,
                string_data_spans=string_data_spans, assets=assets)
