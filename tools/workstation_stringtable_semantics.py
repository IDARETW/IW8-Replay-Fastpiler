"""Compare source and fresh-output native StringTable semantic exports."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_export(path: Path, *, expected_body_sha256: str,
                 expected_source_sha256: str, expected_walk_key: str,
                 label: str) -> tuple[dict, list[dict], dict[tuple[int, str], bytes],
                                      dict[tuple[int, str], Path]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if (document.get("schema") != 1 or document.get("type_id") != 54 or
            document.get("type_name") != "stringtable" or
            document.get("body_sha256") != expected_body_sha256 or
            document.get("source_sha256") != expected_source_sha256 or
            document.get("native_walk_key") != expected_walk_key):
        raise ValueError(f"{label} StringTable export index does not match its pinned native source")
    items = document.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError(f"{label} StringTable export index has no rows")
    root = path.parent.resolve(strict=True)
    contents: dict[tuple[int, str], bytes] = {}
    paths: dict[tuple[int, str], Path] = {}
    for rank, item in enumerate(items):
        if (not isinstance(item, dict) or type(item.get("rank")) is not int or
                item["rank"] != rank or type(item.get("asset_index")) is not int or
                type(item.get("type_id")) is not int or item["type_id"] != 54 or
                not isinstance(item.get("name"), str) or not item["name"]):
            raise ValueError(f"{label} StringTable export row {rank} has invalid identity fields")
        name = item["name"]
        identity = (item["asset_index"], name)
        if identity in contents:
            raise ValueError(f"{label} StringTable export has duplicate XAsset identity {identity!r}")
        relative = Path(item.get("payload_relative_path", ""))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"{label} StringTable payload path is unsafe")
        payload_path = (root / relative).resolve(strict=True)
        if not payload_path.is_relative_to(root):
            raise ValueError(f"{label} StringTable payload escapes its export directory")
        payload = payload_path.read_bytes()
        if (len(payload) != item.get("payload_bytes") or
                hashlib.sha256(payload).hexdigest() != item.get("payload_sha256")):
            raise ValueError(f"{label} StringTable payload hash/size mismatch for {name!r}")
        contents[identity] = payload
        paths[identity] = payload_path
    if len({item["asset_index"] for item in items}) != len(items):
        raise ValueError(f"{label} StringTable export has duplicate XAsset indices")
    return document, items, contents, paths


def compare_stringtable_exports(*, source_index_path: str | Path,
                                 output_index_path: str | Path,
                                 edited_name: str,
                                 edited_asset_index: int,
                                 expected_rows: list[list[str]],
                                 source_body_sha256: str,
                                 source_fastfile_sha256: str,
                                 source_walk_key: str,
                                 output_body_sha256: str,
                                 output_fastfile_sha256: str,
                                 output_walk_key: str) -> dict[str, Any]:
    """Require an exact unchanged export set plus one exact edited CSV.

    Both indices are produced by the same `_export_native_type` function. The
    expected walk keys are supplied by the already-validated native-reader
    receipts; this helper checks each index and every payload against those
    pins before comparing semantics.
    """
    source_index_path = Path(source_index_path).resolve(strict=True)
    output_index_path = Path(output_index_path).resolve(strict=True)
    if (not isinstance(expected_rows, list) or
            any(not isinstance(row, list) or any(not isinstance(cell, str) for cell in row)
                for row in expected_rows)):
        raise ValueError("expected edited StringTable rows must be arrays of strings")
    if type(edited_asset_index) is not int or edited_asset_index < 0:
        raise ValueError("edited StringTable XAsset index is invalid")
    expected_rows_hash = hashlib.sha256(json.dumps(
        expected_rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
    input_hashes = {str(path): _sha256(path) for path in (source_index_path, output_index_path)}
    source_doc, source_items, source_payloads, source_paths = _load_export(
        source_index_path, expected_body_sha256=source_body_sha256,
        expected_source_sha256=source_fastfile_sha256, expected_walk_key=source_walk_key,
        label="source")
    output_doc, output_items, output_payloads, output_paths = _load_export(
        output_index_path, expected_body_sha256=output_body_sha256,
        expected_source_sha256=output_fastfile_sha256, expected_walk_key=output_walk_key,
        label="fresh output")
    if (source_doc.get("acts_sha256") != output_doc.get("acts_sha256") or
            source_doc.get("replay_executable_sha256") != output_doc.get("replay_executable_sha256")):
        raise ValueError("source and output StringTable exports used different ACTS or Replay executable pins")
    if len(source_items) != len(output_items):
        raise ValueError("fresh StringTable export row count differs from the source")
    if sum((item["asset_index"], item["name"]) == (edited_asset_index, edited_name)
           for item in source_items) != 1:
        raise ValueError("edited StringTable XAsset identity is absent or ambiguous in source export")

    checked_retained = 0
    checked_edited = 0
    output_rows: list[dict[str, Any]] = []
    for rank, (source_item, output_item) in enumerate(zip(source_items, output_items, strict=True)):
        source_identity = tuple(source_item.get(key) for key in ("rank", "asset_index", "type_id", "name"))
        output_identity = tuple(output_item.get(key) for key in ("rank", "asset_index", "type_id", "name"))
        if source_identity != output_identity or source_identity[0] != rank:
            raise ValueError(f"fresh StringTable export changed ordered XAsset identity at rank {rank}")
        name = source_item["name"]
        identity = (source_item["asset_index"], name)
        source_bytes, output_bytes = source_payloads[identity], output_payloads[identity]
        if identity == (edited_asset_index, edited_name):
            try:
                actual_rows = list(csv.reader(io.StringIO(output_bytes.decode("utf-8-sig"), newline="")))
            except (UnicodeDecodeError, csv.Error) as error:
                raise ValueError("fresh edited StringTable payload is not valid UTF-8 CSV") from error
            if actual_rows != expected_rows:
                raise ValueError("fresh edited StringTable rows differ from the exact saved CSV")
            checked_edited += 1
            comparison = "edited-csv-equal"
        else:
            if output_bytes != source_bytes:
                raise ValueError(f"retained StringTable payload changed for {name!r}")
            checked_retained += 1
            comparison = "retained-bytes-equal"
        output_rows.append(dict(rank=rank, asset_index=source_identity[1], name=name,
                                comparison=comparison,
                                payload_sha256=output_item["payload_sha256"]))
    if checked_edited != 1:
        raise ValueError("fresh output did not contain exactly one edited StringTable")
    changed_paths = [str(path) for path, expected in
                     ((source_index_path, input_hashes[str(source_index_path)]),
                      (output_index_path, input_hashes[str(output_index_path)]),
                      *((path, source_item["payload_sha256"])
                        for source_item in source_items
                        for path in (source_paths[(source_item["asset_index"], source_item["name"])],)),
                      *((path, output_item["payload_sha256"])
                        for output_item in output_items
                        for path in (output_paths[(output_item["asset_index"], output_item["name"])],)))
                     if _sha256(path) != expected]
    if changed_paths:
        raise ValueError(f"StringTable export inputs changed during comparison: {changed_paths}")
    return dict(schema="replay120-stringtable-semantic-export-proof-v1", status="pass",
                source_index_sha256=input_hashes[str(source_index_path)],
                output_index_sha256=input_hashes[str(output_index_path)],
                source_body_sha256=source_body_sha256,
                source_fastfile_sha256=source_fastfile_sha256,
                source_native_walk_key=source_walk_key,
                output_body_sha256=output_body_sha256,
                output_fastfile_sha256=output_fastfile_sha256,
                output_native_walk_key=output_walk_key,
                acts_sha256=source_doc["acts_sha256"],
                replay_executable_sha256=source_doc["replay_executable_sha256"],
                edited_name=edited_name, edited_asset_index=edited_asset_index,
                expected_rows_sha256=expected_rows_hash,
                retained_payloads_checked=checked_retained, edited_payloads_checked=checked_edited,
                output_rows=output_rows)
