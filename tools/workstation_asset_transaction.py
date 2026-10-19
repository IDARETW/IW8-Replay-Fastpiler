"""Narrow sequential scheduler for mixed Replay asset mutations.

This module owns no fastfile parsing or writing.  Callers provide a native
reread callback and one writer callback per supported mutation kind.  Every
writer result is followed by a complete native reread before another mutation
may resolve its current row.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Callable, Iterable


SUPPORTED_KINDS = (
    "resident_image", "rawfile_replace", "soundbank_replace",
    "scriptfile_replace", "luafile_replace", "stringtable_replace", "shader_replace", "localize_replace",
    "localize_append", "luafile_append",
)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, order=True)
class AssetIdentity:
    type_id: int
    name: str
    occurrence: int


@dataclass(frozen=True)
class NativeAsset:
    identity: AssetIdentity
    index: int
    payload_sha256: str | None
    inbound: tuple[AssetIdentity, ...] = ()


def snapshot(rows: Iterable[dict]) -> tuple[NativeAsset, ...]:
    """Normalize one complete native walk without trusting stored row indices."""
    occurrences: dict[tuple[int, str], int] = {}
    assets = []
    for index, row in enumerate(rows):
        type_id, name = row.get("type_id"), row.get("name")
        payload_sha = row.get("payload_sha256")
        if (isinstance(type_id, bool) or not isinstance(type_id, int) or type_id < 0 or
                not isinstance(name, str) or not name or "\0" in name):
            raise ValueError("native snapshot contains an invalid asset identity")
        if payload_sha is not None and (not isinstance(payload_sha, str) or
                                        not re.fullmatch(r"[0-9a-f]{64}", payload_sha)):
            raise ValueError("native snapshot contains a malformed payload digest")
        if payload_sha is None:
            payload = row.get("payload")
            payload_sha = _digest(payload) if isinstance(payload, bytes) else None
        key = (type_id, name)
        occurrence = occurrences.get(key, 0)
        occurrences[key] = occurrence + 1
        inbound_rows = row.get("inbound", ())
        if not isinstance(inbound_rows, (list, tuple)):
            raise ValueError("native snapshot contains malformed inbound references")
        inbound_items = []
        for ref in inbound_rows:
            if not isinstance(ref, dict):
                raise ValueError("native snapshot contains malformed inbound references")
            ref_type, ref_name = ref.get("type_id"), ref.get("name")
            occurrence_ref = ref.get("occurrence", 0)
            if (isinstance(ref_type, bool) or not isinstance(ref_type, int) or ref_type < 0 or
                    not isinstance(ref_name, str) or not ref_name or "\0" in ref_name or
                    isinstance(occurrence_ref, bool) or not isinstance(occurrence_ref, int) or
                    occurrence_ref < 0):
                raise ValueError("native snapshot contains an invalid inbound identity")
            inbound_items.append(AssetIdentity(ref_type, ref_name, occurrence_ref))
        inbound = tuple(inbound_items)
        assets.append(NativeAsset(AssetIdentity(type_id, name, occurrence), index,
                                  payload_sha, inbound))
    identities = [row.identity for row in assets]
    if len(identities) != len(set(identities)):
        raise ValueError("native snapshot asset identity is ambiguous")
    return tuple(assets)


def _by_identity(rows: tuple[NativeAsset, ...]) -> dict[AssetIdentity, NativeAsset]:
    return {row.identity: row for row in rows}


def execute_transaction(mutations: list[dict], reread: Callable[[], Iterable[dict]],
                        writers: dict[str, Callable[[dict, int | None, tuple[NativeAsset, ...]], dict]]) -> dict:
    """Apply the supported mixed route with a complete reread after each step."""
    if not mutations:
        raise ValueError("asset transaction is empty")
    if any(not isinstance(row, dict) for row in mutations):
        raise ValueError("asset transaction mutations must be objects")
    kinds = [row.get("kind") for row in mutations]
    if any(not isinstance(kind, str) for kind in kinds):
        raise ValueError("asset transaction contains an invalid mutation kind")
    unsupported = sorted({str(kind) for kind in kinds if kind not in SUPPORTED_KINDS})
    if unsupported:
        raise ValueError("asset transaction contains unsupported mutations: " + ", ".join(unsupported))
    missing_writers = sorted(set(kinds) - writers.keys())
    if missing_writers:
        raise ValueError("asset transaction has no writer for: " + ", ".join(missing_writers))
    append_types = {"localize_append": 41, "luafile_append": 62}
    replacement_types = {"scriptfile_replace": 52, "luafile_replace": 62,
                         "stringtable_replace": 54}
    for mutation in mutations:
        kind = mutation["kind"]
        output_sha = mutation.get("output_payload_sha256")
        if not isinstance(output_sha, str) or re.fullmatch(r"[0-9a-f]{64}", output_sha) is None:
            raise ValueError(f"{kind} lacks its expected output payload digest")
        if kind in append_types:
            type_id, name = mutation.get("type_id"), mutation.get("name")
            if (isinstance(type_id, bool) or not isinstance(type_id, int) or
                    type_id != append_types[kind]):
                raise ValueError(f"{kind} uses the wrong native asset type")
            if (not isinstance(name, str) or
                    re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}", name) is None or
                    any(part in ("", ".", "..") for part in name.split("/"))):
                raise ValueError(f"{kind} lacks a valid native asset name")
        else:
            identity = mutation.get("identity")
            if not isinstance(identity, dict):
                raise ValueError(f"{kind} lacks immutable original asset identity")
            type_id, name = identity.get("type_id"), identity.get("name")
            occurrence = identity.get("occurrence", 0)
            if (isinstance(type_id, bool) or not isinstance(type_id, int) or
                    isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 0 or
                    not isinstance(name, str) or not name or "\0" in name):
                raise ValueError(f"{kind} has an invalid immutable original asset identity")
    for append_kind in ("localize_append", "luafile_append"):
        if kinds.count(append_kind) > 1:
            raise ValueError(f"narrow mixed route supports one {append_kind}")
    typed_targets = []
    expected_type = {"resident_image": 19, "rawfile_replace": 51, "soundbank_replace": 21,
                     "localize_replace": 41,
                     **replacement_types}
    shader_type_ids = {12, 14, 15, 16, 17}
    for mutation in mutations:
        if mutation["kind"] in expected_type:
            identity = mutation.get("identity") or {}
            if identity.get("type_id") != expected_type[mutation["kind"]]:
                raise ValueError(f'{mutation["kind"]} uses the wrong native asset type')
            typed_targets.append((identity.get("type_id"), identity.get("name"), identity.get("occurrence", 0)))
        elif mutation["kind"] == "shader_replace":
            identity = mutation.get("identity") or {}
            if identity.get("type_id") not in shader_type_ids:
                raise ValueError("shader_replace uses an unsupported native shader stage")
            typed_targets.append((identity.get("type_id"), identity.get("name"), identity.get("occurrence", 0)))
    if len(typed_targets) != len(set(typed_targets)):
        raise ValueError("asset transaction schedules the same original identity more than once")

    original = snapshot(reread())
    original_map = _by_identity(original)
    expected_order = [row.identity for row in original]
    expected_payloads = {row.identity: row.payload_sha256 for row in original if row.payload_sha256 is not None}
    def validate_state(rows, context):
        actual_order = [row.identity for row in rows]
        if actual_order != expected_order:
            missing = set(expected_order) - set(actual_order)
            inbound = sorted({row.identity for row in rows for ref in row.inbound if ref in missing})
            if missing:
                raise ValueError(f"{context} deleted retained assets {sorted(missing)}; inbound references {inbound}")
            raise ValueError(f"{context} changed retained native asset identity/order")
        actual = _by_identity(rows)
        changed = sorted(identity for identity, wanted in expected_payloads.items()
                         if actual[identity].payload_sha256 != wanted)
        if changed:
            raise ValueError(f"{context} payload digests differ for typed assets {changed}")
    # Existing children are edited before the table append.  A native reread
    # still follows every group, so the append never consumes stale trace data.
    ordered = sorted(enumerate(mutations), key=lambda item: (SUPPORTED_KINDS.index(item[1]["kind"]), item[0]))
    steps = []
    for sequence, (input_order, mutation) in enumerate(ordered):
        before = snapshot(reread())
        validate_state(before, "pre-step native reread")
        before_map = _by_identity(before)
        kind = mutation["kind"]
        if kind in ("localize_append", "luafile_append"):
            type_id = 41 if kind == "localize_append" else 62
            label = "Localize" if kind == "localize_append" else "LuaFile"
            if mutation.get("type_id") != type_id or not isinstance(mutation.get("name"), str):
                raise ValueError(f"{label} append lacks its typed name identity")
            key = (type_id, mutation["name"])
            occurrence = sum(identity.type_id == type_id and identity.name == mutation["name"]
                             for identity in before_map)
            target = AssetIdentity(type_id, mutation["name"], occurrence)
            current_index = None
            if occurrence:
                raise ValueError(f"{label} append identity already exists")
        else:
            target_data = mutation.get("identity")
            if not isinstance(target_data, dict):
                raise ValueError(f"{kind} lacks immutable original asset identity")
            target = AssetIdentity(target_data["type_id"], target_data["name"],
                                   target_data.get("occurrence", 0))
            if target not in original_map:
                raise ValueError(f"{kind} target is absent from the original native inventory")
            current = before_map.get(target)
            if current is None:
                inbound = [row.identity for row in before for ref in row.inbound if ref == target]
                suffix = f"; retained inbound references: {inbound}" if inbound else ""
                raise ValueError(f"{kind} target disappeared before its scheduled mutation{suffix}")
            current_index = current.index

        result = writers[kind](mutation, current_index, before)
        if not isinstance(result, dict):
            raise ValueError(f"{kind} writer did not return a receipt")
        after = snapshot(reread())
        output_sha = mutation["output_payload_sha256"]
        if kind in ("localize_append", "luafile_append"):
            expected_order.append(target)
            expected_payloads[target] = output_sha
        else:
            expected_payloads[target] = output_sha
        validate_state(after, "post-step native reread")
        steps.append({"sequence": sequence, "input_order": input_order, "kind": kind,
                      "identity": target.__dict__, "resolved_current_index": current_index,
                      "before_asset_count": len(before), "after_asset_count": len(after),
                      "writer": result})

    return {"schema": "replay120-supported-mixed-asset-transaction-v1",
            "supported_route": list(SUPPORTED_KINDS), "steps": steps,
            "original_asset_count": len(original), "final_asset_count": len(expected_order),
            "full_native_reread_after_each_mutation": True,
            "identity_rule": "type_id + name + original occurrence; resolve current index after every reread",
            "publication_ready": False}
