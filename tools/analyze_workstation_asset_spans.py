"""Extract bounded native physical-read spans for selected XAsset rows.

The report records evidence from a successful full-zone reader trace. It does
not claim that spans are sufficient to serialize/relocate an edited asset.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from workstation_fastfiles import ZoneBody, _read_native_rows, _cache_receipt
from workstation_trace_index import build_read_span_index


def analyze(cache_root: Path, zone_id: str, selected_types: set[int]) -> dict:
    matches = list(cache_root.glob(f"*/{zone_id}/decode-receipt.json"))
    if len(matches) != 1:
        raise ValueError("zone id must resolve to exactly one cached decode receipt")
    cache_path = matches[0].parent
    receipt = _cache_receipt(cache_path, zone_id)
    body = ZoneBody.parse((cache_path / receipt["final_body_relative_path"]).read_bytes())
    walk_dirs = list((cache_path / "native-walk").glob("*/native"))
    traced_walks = []
    for native_dir in walk_dirs:
        receipt_path = native_dir.parent / "native-walk-receipt.json"
        if not receipt_path.is_file():
            continue
        candidate_receipt = json.loads(receipt_path.read_text())
        if (candidate_receipt.get("status") == "native-zone-reader-pass" and
                candidate_receipt.get("stream_trace_enabled") and
                candidate_receipt.get("stream_trace_relative_path")):
            traced_walks.append((native_dir, candidate_receipt))
    if len(traced_walks) != 1:
        raise ValueError("zone must have exactly one successful trace-enabled native walk")
    native_dir, walk_receipt = traced_walks[0]
    manifest = json.loads((native_dir / "manifest.json").read_text())
    if manifest.get("stream_trace") != "stream-trace.jsonl":
        raise ValueError("native trace was not retained")
    _, rows = _read_native_rows(cache_path, body)
    selected = [i for i, row in enumerate(rows) if row.get("type_id") in selected_types]
    trace_index = build_read_span_index(native_dir / manifest["stream_trace"],
                                        native_dir / "manifest.json", len(body.data),
                                        selected_assets=selected)
    assets = []
    for index in selected:
        row = rows[index]
        trace_row = next((item for item in trace_index["assets"] if item["index"] == index), None)
        if trace_row is None:
            raise ValueError(f"selected native row {index} has no trace allocation boundary")
        roots = [span for span in trace_row["read_spans"]
                 if span["origin"] == "load_stream_call" and
                 span.get("reader_start_arg") == 0]
        assets.append(dict(xasset_index=index, type_id=row.get("type_id"),
                           type=row.get("type"), name=row.get("name"),
                           pointer_token=f"0x{body.assets[index].pointer_token:016x}",
                           begin_sequence=trace_row["begin_sequence"],
                           end_sequence=trace_row["end_sequence"],
                           serialized_cursor_begin=trace_row["begin_cursor"],
                           serialized_cursor_end=trace_row["end_cursor"],
                           physical_load_count_by_stream=trace_row["physical_load_count_by_stream"],
                           physical_load_bytes_by_stream=trace_row["physical_load_bytes_by_stream"],
                           max_destination_offsets=trace_row["max_destination_offsets"],
                           physical_read_bytes=sum(s["size"] for s in trace_row["read_spans"]),
                           top_level_root_reads=[dict(archive_offset=s["archive_offset"],
                                                      size=s["size"],
                                                      destination=s["destination_stream_location"],
                                                      caller_rva=s["caller_rva"])
                                                 for s in roots],
                           read_spans=trace_row["read_spans"]))
    return dict(schema=1, status="selected-assets-bounded-by-full-native-trace",
                zone_id=zone_id, source=receipt["source"],
                source_body_sha256=body.source_sha256,
                native_walk_key=walk_receipt["walk_key"],
                native_manifest_sha256=walk_receipt["manifest_sha256"],
                stream_trace_sha256=walk_receipt["stream_trace_sha256"],
                global_max_destination_offsets=trace_index["max_destination_offsets"],
                global_physical_load_count_by_stream=trace_index["physical_load_count_by_stream"],
                global_physical_load_bytes_by_stream=trace_index["physical_load_bytes_by_stream"],
                packed_target_stream_counts=trace_index["packed_target_stream_counts"],
                packed_alias_token_highword_counts=trace_index["packed_alias_token_highword_counts"],
                xasset_count=len(body.assets),
                serialized_bytes_read=walk_receipt["serialized_bytes_read"],
                selected_count=len(assets),
                selected_assets=assets,
                limitation="Trace spans prove physical reads and owner boundaries; they do not classify all pointer fields, aliases, shared ownership, or relocation fixups.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root", type=Path)
    parser.add_argument("zone_id")
    parser.add_argument("--type-id", type=int, action="append", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = analyze(args.cache_root, args.zone_id, set(args.type_id))
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
