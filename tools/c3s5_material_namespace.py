"""Trace-bound, length-preserving namespace rewrite for source Material XStrings.

This module deliberately does not discover strings by searching bytes. Callers
must provide every relevant typed pointer event from a complete native trace.
The rewrite changes only the pointed-to string bytes, leaves pointer tokens and
archive extents untouched, and fails closed when a target is shared with an
unrelated field or any pointer addresses the interior of a renamed string.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Iterable


MATERIAL_NAME_ROLES = frozenset({"MaterialHandle", "MaterialAssetName"})


class NamespaceRewriteError(ValueError):
    pass


@dataclass(frozen=True)
class RenameRequest:
    original_name: str
    target_body_offset: int


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deterministic_name(original_name: str, occupied_names: Iterable[str]) -> str:
    """Return a collision-free namespace name with exactly the same UTF-8 size."""
    old = original_name.encode("utf-8")
    comma = b"," if old.startswith(b",") else b""
    base_name = old[len(comma):].decode("utf-8", errors="strict")
    occupied = {x.lstrip(",").casefold() for x in occupied_names}
    width = len(old) - len(comma)
    prefix = b"c3s5n/"
    if width < len(prefix) + 8:
        raise NamespaceRewriteError(
            f"name {original_name!r} is too short for a safe equal-length namespace"
        )
    for nonce in range(256):
        seed = base_name if nonce == 0 else f"{base_name}\0{nonce}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest().encode("ascii")
        needed = width - len(prefix)
        tail = (digest * ((needed + len(digest) - 1) // len(digest)))[:needed]
        candidate = (comma + prefix + tail).decode("ascii")
        candidate_base = candidate[len(comma.decode("ascii")):] if comma else candidate
        if candidate_base.casefold() not in occupied:
            return candidate
    raise NamespaceRewriteError(f"could not create unique namespace for {original_name!r}")


def _decode_cstring(body: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(body):
        raise NamespaceRewriteError(f"string target {offset:#x} lies outside source body")
    end = body.find(b"\0", offset)
    if end < 0:
        raise NamespaceRewriteError(f"string target {offset:#x} has no NUL terminator")
    try:
        return body[offset:end].decode("utf-8", errors="strict"), end
    except UnicodeDecodeError as exc:
        raise NamespaceRewriteError(f"string target {offset:#x} is not UTF-8") from exc


def rewrite_material_names(
    body: bytes,
    *,
    expected_body_sha256: str,
    rename_requests: list[RenameRequest],
    typed_pointer_events: list[dict[str, Any]],
    expected_pointer_event_count: int,
    occupied_names: Iterable[str],
    expected_trace_sha256: str,
    supplied_trace_sha256: str,
) -> tuple[bytes, dict[str, Any]]:
    """Rewrite material-name strings only when all typed owners are supplied.

    `typed_pointer_events` must be taken from the complete native read trace.
    Each event has `owner_type`, `owner_name`, `owner_asset_index`,
    `owner_field_offset`, `token`, and `resolved_target_body_offset`. Events
    may include unrelated pointer roles; any pointer landing inside a renamed
    string is checked and causes a rejection unless it is an approved Material
    name/handle field targeting the string start exactly.
    """
    if _sha(body) != expected_body_sha256:
        raise NamespaceRewriteError("source body SHA does not match the pinned trace source")
    if supplied_trace_sha256 != expected_trace_sha256:
        raise NamespaceRewriteError("trace SHA does not match the pinned ownership receipt")
    if len(typed_pointer_events) != expected_pointer_event_count:
        raise NamespaceRewriteError("typed pointer-event count does not match the full trace inventory")
    if not rename_requests:
        return body, {
            "changed": False,
            "source_body_sha256": expected_body_sha256,
            "output_body_sha256": expected_body_sha256,
            "trace_sha256": supplied_trace_sha256,
            "rewrites": [],
        }

    requests_by_offset: dict[int, str] = {}
    for req in rename_requests:
        if req.target_body_offset in requests_by_offset:
            if requests_by_offset[req.target_body_offset] != req.original_name:
                raise NamespaceRewriteError("two source names claim one trace target")
            continue
        requests_by_offset[req.target_body_offset] = req.original_name

    occupied = set(occupied_names)
    names: dict[str, str] = {}
    for name in requests_by_offset.values():
        if name not in names:
            base = name[1:] if name.startswith(",") else name
            if base not in names:
                names[base] = deterministic_name(base, occupied | set(names.values()))
            names[name] = "," + names[base] if name.startswith(",") else names[base]

    intervals: list[tuple[int, int, int, str]] = []
    for offset, expected_name in requests_by_offset.items():
        actual, end = _decode_cstring(body, offset)
        if actual != expected_name:
            raise NamespaceRewriteError(
                f"trace target {offset:#x} reads {actual!r}, expected {expected_name!r}"
            )
        intervals.append((offset, end + 1, offset, expected_name))
    intervals.sort()
    for previous, current in zip(intervals, intervals[1:]):
        if current[0] < previous[1]:
            raise NamespaceRewriteError("renamed source string allocations overlap")

    # A supplied global event set is required. A pointer landing anywhere in a
    # renamed string is ownership; substring aliases are rejected because
    # shortening/replacing the leading bytes could silently alter them.
    seen_owner_fields: set[int] = set()
    owners_by_target: dict[int, list[dict[str, Any]]] = {o: [] for o in requests_by_offset}
    for event in typed_pointer_events:
        target = event.get("resolved_target_body_offset")
        if target is None:
            continue
        for start, end, _, original_name in intervals:
            if start <= int(target) < end:
                role = event.get("owner_type")
                if int(target) != start:
                    raise NamespaceRewriteError(
                        f"packed pointer {event.get('token')} targets the interior of {original_name!r}"
                    )
                if role not in MATERIAL_NAME_ROLES:
                    raise NamespaceRewriteError(
                        f"unrelated {role!r} field aliases material name {original_name!r}"
                    )
                field_offset = event.get("owner_field_offset")
                token = event.get("token")
                if field_offset is None or token is None:
                    raise NamespaceRewriteError("typed material reference lacks its field token proof")
                field_offset = int(field_offset)
                if field_offset < 0 or field_offset + 8 > len(body):
                    raise NamespaceRewriteError("typed owner field lies outside the source body")
                raw_token = int.from_bytes(body[field_offset:field_offset + 8], "little")
                if raw_token != int(str(token), 0):
                    raise NamespaceRewriteError(
                        f"owner field {field_offset:#x} token differs from native trace"
                    )
                if field_offset in seen_owner_fields:
                    raise NamespaceRewriteError("duplicate owner field in pointer trace")
                seen_owner_fields.add(field_offset)
                owners_by_target[start].append(event)

    for offset, name in requests_by_offset.items():
        if not owners_by_target[offset]:
            raise NamespaceRewriteError(f"no typed incoming owner proves material string {name!r}")

    updated = bytearray(body)
    rewrites = []
    for offset, original_name in sorted(requests_by_offset.items()):
        replacement = names[original_name].encode("utf-8")
        old_bytes = original_name.encode("utf-8")
        if len(replacement) != len(old_bytes):
            raise NamespaceRewriteError("in-place namespace must preserve the exact string byte length")
        end = offset + len(old_bytes)
        if body[end:end + 1] != b"\0":
            raise NamespaceRewriteError("source name terminator moved since trace capture")
        updated[offset:offset + len(replacement)] = replacement
        rewrites.append({
            "old_name": original_name,
            "new_name": names[original_name],
            "target_body_offset": offset,
            "old_utf8_bytes": len(old_bytes),
            "new_utf8_bytes": len(replacement),
            "owner_count": len(owners_by_target[offset]),
            "owners": [{
                "owner_type": e["owner_type"],
                "owner_name": e.get("owner_name"),
                "owner_asset_index": e.get("owner_asset_index"),
                "owner_field_offset": e["owner_field_offset"],
                "token": e["token"],
            } for e in owners_by_target[offset]],
        })
    result = bytes(updated)
    if len(result) != len(body):
        raise AssertionError("in-place namespace rewrite changed body length")
    return result, {
        "changed": True,
        "source_body_sha256": expected_body_sha256,
        "output_body_sha256": _sha(result),
        "trace_sha256": supplied_trace_sha256,
        "body_length_preserved": len(result) == len(body),
        "rewrites": rewrites,
    }
