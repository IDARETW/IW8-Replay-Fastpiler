"""Shared semantic checks for typed Replay XAsset transaction writers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from workstation_localize import inspect_localize_entry
from workstation_luafile_crud import _bytecodes
from workstation_native_asset_edits import read_resident_image
from workstation_trace_index import build_read_span_index


def semantic_sha(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def identity(rows: list[dict]) -> list[tuple[int, str]]:
    result = []
    for row in rows:
        type_id, name = row.get("type_id"), row.get("name")
        if isinstance(type_id, bool) or not isinstance(type_id, int) or not isinstance(name, str) or not name:
            raise ValueError("native journal contains an invalid typed identity")
        result.append((type_id, name))
    return result


def trace_row(row: dict, index: int, trace_asset: dict) -> dict:
    return dict(index=index, xasset_index=index, type_id=row["type_id"], name=row["name"],
                **{key: trace_asset[key] for key in (
                    "read_spans", "begin_cursor", "end_cursor", "begin_sequence", "end_sequence"
                ) if key in trace_asset})


def typed_semantics(body: bytes, journal: list[dict], trace: Path,
                    manifest: Path, *, include_images: bool = True
                    ) -> tuple[dict[tuple[int, str], str], dict, dict[int, dict]]:
    """Return typed child digests; omitted images need a full retained-byte audit."""
    if type(include_images) is not bool:
        raise ValueError("image semantic coverage must be explicit")
    supported_types = (19, 41, 62) if include_images else (41, 62)
    selected = {index for index, row in enumerate(journal)
                if row.get("status") != "reference" and row.get("type_id") in supported_types}
    index = build_read_span_index(trace, manifest, len(body), selected_assets=selected)
    by_index = {row["index"]: row for row in index["assets"]}
    if set(by_index) != selected:
        raise ValueError("full native trace omitted a typed asset needed for semantic comparison")
    lua_spans = {i: by_index[i] for i, row in enumerate(journal)
                 if row.get("type_id") == 62 and row.get("status") != "reference"}
    lua_payloads = _bytecodes(body, journal, lua_spans)
    result: dict[tuple[int, str], str] = {}
    for asset_index, row in enumerate(journal):
        if row.get("status") == "reference" or row.get("type_id") not in supported_types:
            continue
        type_id, name = row["type_id"], row["name"]
        if type_id == 62:
            semantic = {"bytecode_sha256": lua_payloads[name]}
        elif type_id == 19:
            image = read_resident_image(body, dict(row, index=asset_index), by_index[asset_index],
                                        hashlib.sha256(body).hexdigest())
            semantic = dict(payload_sha256=image["payload_sha256"], format=image["format"],
                            flags=image["flags"], dimensions=list(image["dimensions"]),
                            level_count=image["level_count"], total_size=image["total_size"])
        elif type_id == 41:
            _layout, text = inspect_localize_entry(body, asset_index, name,
                trace_row(row, asset_index, by_index[asset_index]), hashlib.sha256(body).hexdigest())
            semantic = {"key": text["key"], "value": text["value"]}
        else:
            continue
        key = (type_id, name)
        if key in result:
            raise ValueError(f"duplicate typed identity prevents semantic comparison: {key!r}")
        result[key] = semantic_sha(semantic)
    return result, index, by_index


def state_rows(state: dict) -> list[dict]:
    return [dict(type_id=row["type_id"], name=row["name"],
                 payload_sha256=state["semantics"].get((row["type_id"], row["name"])))
            for row in state["journal"]]


def native_receipt(native: dict, package: Path, body: bytes, semantics: dict,
                   expected_identity: list[tuple[int, str]]) -> dict:
    manifest = native["manifest"]
    return dict(package_path=str(package), package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
                body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body),
                raw_manifest_path=native["raw_manifest_path"],
                raw_manifest_sha256=native["raw_manifest_sha256"],
                bound_manifest_path=native["manifest_path"],
                bound_manifest_sha256=hashlib.sha256(Path(native["manifest_path"]).read_bytes()).hexdigest(),
                trace_path=native["manifest_trace_binding"]["trace_path"],
                trace_sha256=native["manifest_trace_binding"]["trace_sha256"],
                trace_events=manifest.get("stream_trace_events"),
                complete=manifest.get("complete"), success=manifest.get("success"),
                tested=manifest.get("tested"), failed=manifest.get("failed"),
                unavailable=manifest.get("unavailable"),
                serialized_bytes_read=manifest.get("serialized_bytes_read"),
                exact_eof=manifest.get("serialized_bytes_read") == len(body),
                identity_order_exact=True, typed_semantic_payloads_exact=len(semantics),
                expected_asset_count=len(expected_identity))
