"""Ordered Localize semantics read back by the pinned native Replay exporter."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _payload_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("Localize semantic payload path is missing")
    candidate = Path(relative)
    path = (root / candidate).resolve(strict=True)
    if candidate.is_absolute() or ".." in candidate.parts or not path.is_relative_to(root.resolve()):
        raise ValueError("Localize semantic payload path escapes its export")
    return path


def read_localize_inventory(root: Path, rows: list[dict], native_rows: list[dict],
                            *, cached: bool = False) -> list[dict]:
    """Bind every exported key/value to its ordered top-level type-41 row.

    This deliberately checks the whole type inventory, including unedited
    entries. A successful native load alone cannot detect an incorrect alias
    which resolves to another valid string.
    """
    expected = [(i, row) for i, row in enumerate(native_rows) if row.get("type_id") == 41]
    if len(rows) != len(expected):
        raise ValueError("Localize semantic inventory has an unexpected row count")
    inventory, names = [], set()
    for rank, ((index, native), row) in enumerate(zip(expected, rows, strict=True)):
        name = native.get("name")
        if not isinstance(name, str) or name in names:
            raise ValueError("Localize semantic inventory has a missing or duplicate key")
        names.add(name)
        if row.get("type_id") != 41 or row.get("name") != name:
            raise ValueError(f"Localize semantic row {rank} differs from native XAsset order/name")
        if cached and (row.get("asset_index") != index or row.get("rank") != rank):
            raise ValueError("cached Localize semantic row differs from native XAsset index")
        path = _payload_path(root, row.get("payload_relative_path") if cached else row.get("file"))
        payload = path.read_bytes()
        if cached and (len(payload) != row.get("payload_bytes") or
                       hashlib.sha256(payload).hexdigest() != row.get("payload_sha256")):
            raise ValueError("cached Localize semantic payload differs from its hash/size")
        data = json.loads(payload)
        if data.get("name") != name or not isinstance(data.get("value"), str):
            raise ValueError("Localize semantic payload differs from its native key/value contract")
        value = data["value"]
        inventory.append(dict(asset_index=index, name=name, value=value,
                              value_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest()))
    return inventory


def compare_localize_inventory(original: list[dict], actual: list[dict],
                                edits: dict[str, str] | None = None,
                                removed: set[str] | None = None,
                                appended: list[tuple[str, str]] | None = None) -> dict:
    """Verify all retained values and order, plus explicitly authored changes."""
    edits, removed, appended = edits or {}, removed or set(), appended or []
    source_names = {row["name"] for row in original}
    if len(source_names) != len(original):
        raise ValueError("original Localize semantic inventory has duplicate keys")
    if not set(edits).issubset(source_names) or not removed.issubset(source_names):
        raise ValueError("Localize semantic operation refers to a missing source key")
    if set(edits) & removed:
        raise ValueError("Localize semantic operation both edits and removes a key")
    added_names = [name for name, _ in appended]
    if len(set(added_names)) != len(added_names) or set(added_names) & (source_names - removed):
        raise ValueError("Localize semantic append collides with an existing key")
    expected = [(row["name"], edits.get(row["name"], row["value"]))
                for row in original if row["name"] not in removed]
    expected.extend(appended)
    pairs = [(row["name"], row["value"]) for row in actual]
    if len(pairs) != len(expected):
        raise ValueError("Localize semantic readback differs from expected inventory size")
    for rank, (before, after) in enumerate(zip(expected, pairs, strict=True)):
        if before != after:
            raise ValueError(f"Localize semantic readback changed value/order at rank {rank}: {before[0]}")
    digest = hashlib.sha256(json.dumps(pairs, ensure_ascii=False,
                                       separators=(",", ":")).encode("utf-8")).hexdigest()
    return dict(status="pass", tested=len(actual), retained=len(original) - len(removed),
                edited=len(edits), removed=len(removed), appended=len(appended),
                ordered_key_value_sha256=digest)
