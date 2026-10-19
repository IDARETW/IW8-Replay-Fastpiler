"""Replay 1.20 shader program-identity inventory and allocation.

The 32-bit value at byte 36 of the 40-byte native shader root is an opaque
authored discriminator.  Replay does not derive it while loading DXBC.  This
module therefore inventories every trace-proven shader root and allocates a
new, deterministic discriminator for edited bytecode without pretending to
reproduce the original asset compiler's private algorithm.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

try:
    from workstation_fastfiles import ZoneBody
    from workstation_trace_index import build_read_span_index
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_trace_index import build_read_span_index


SHADER_TYPES = frozenset((14, 15, 16, 17))
IDENTITY_DOMAIN = b"replay120-shader-identity-v1\0"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_dxbc(program: bytes) -> None:
    if not isinstance(program, bytes) or len(program) < 32 or program[:4] != b"DXBC":
        raise ValueError("shader identity input is not a complete DXBC container")
    if struct.unpack_from("<I", program, 24)[0] != len(program):
        raise ValueError("DXBC declared size differs from its byte length")


def identity_digest(type_id: int, name: str, program: bytes, nonce: int) -> bytes:
    """Return the domain-separated digest used to mint an edited identity."""
    if type_id not in SHADER_TYPES:
        raise ValueError("Replay shader identity requires type 12, 14, 15, 16, or 17")
    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError("shader identity requires a nonempty NUL-free asset name")
    if type(nonce) is not int or not 0 <= nonce <= 0xFFFFFFFF:
        raise ValueError("shader identity nonce must be a uint32")
    _validate_dxbc(program)
    material = (IDENTITY_DOMAIN + struct.pack("<I", type_id) + name.encode("utf-8") +
                b"\0" + program + struct.pack("<I", nonce))
    return hashlib.sha256(material).digest()


def validate_inventory_set(inventories: list[dict], expected_replay_exe_sha256: str,
                           occupied_extra: set[int] | tuple[int, ...] | list[int] = ()) -> dict:
    """Validate complete image-bound receipts and return their occupied identities."""
    if not inventories:
        raise ValueError("shader identity validation requires a complete inventory set")
    expected = expected_replay_exe_sha256.lower()
    if len(expected) != 64:
        raise ValueError("expected Replay executable SHA-256 is required")
    occupied: set[int] = set()
    for value in occupied_extra:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("extra occupied shader identities must be uint32 values")
        occupied.add(value)
    inventory_hashes = []
    for inventory in inventories:
        if inventory.get("schema") != "replay120-shader-identity-inventory-v1":
            raise ValueError("unrecognized shader identity inventory schema")
        if inventory.get("status") != "complete-trace-proven-shader-root-inventory":
            raise ValueError("shader identity inventory is incomplete")
        if inventory.get("replay_executable_sha256", "").lower() != expected:
            raise ValueError("shader identity inventory belongs to another Replay image")
        records = inventory.get("shaders")
        if not isinstance(records, list) or inventory.get("shader_count") != len(records):
            raise ValueError("shader identity inventory count is inconsistent")
        claimed_hash = inventory.get("inventory_sha256")
        hash_input = {key: value for key, value in inventory.items() if key != "inventory_sha256"}
        actual_hash = hashlib.sha256(json.dumps(
            hash_input, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if claimed_hash != actual_hash:
            raise ValueError("shader identity inventory receipt hash is invalid")
        for record in records:
            value = record.get("program_identity")
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError("shader identity inventory contains an invalid identity")
            occupied.add(value)
        inventory_hashes.append(claimed_hash)
    return dict(replay_executable_sha256=expected, occupied=occupied,
                inventory_hashes=inventory_hashes)


def allocate_identity(type_id: int, name: str, program: bytes,
                      inventories: list[dict], expected_replay_exe_sha256: str,
                      occupied_extra: set[int] | tuple[int, ...] | list[int] = ()) -> dict:
    """Allocate a stable nonzero identity absent from all image-bound inventories."""
    validated = validate_inventory_set(inventories, expected_replay_exe_sha256, occupied_extra)
    expected = validated["replay_executable_sha256"]
    occupied = validated["occupied"]
    inventory_hashes = validated["inventory_hashes"]
    for nonce in range(0x100000000):
        digest = identity_digest(type_id, name, program, nonce)
        candidate = struct.unpack_from("<I", digest)[0]
        if candidate != 0 and candidate not in occupied:
            return dict(schema="replay120-edited-shader-identity-v1",
                        type_id=type_id, name=name, program_sha256=hashlib.sha256(program).hexdigest(),
                        identity=candidate, identity_hex=f"0x{candidate:08x}", nonce=nonce,
                        digest_sha256=digest.hex(), replay_executable_sha256=expected,
                        inventory_hashes=inventory_hashes,
                        allocation_rule="domain-separated SHA-256 low uint32; retry zero/collision")
    raise ValueError("all uint32 shader identities are occupied")


def allocate_identity_batch(edits: list[dict], inventories: list[dict],
                            expected_replay_exe_sha256: str,
                            occupied_extra: set[int] | tuple[int, ...] | list[int] = ()) -> list[dict]:
    """Allocate a batch in stable owner-key order, reserving each new identity."""
    if not isinstance(edits, list) or not edits:
        raise ValueError("shader identity batch requires one or more edits")
    normalized = []
    for edit in edits:
        if not isinstance(edit, dict):
            raise TypeError("each shader identity edit must be a mapping")
        owner = edit.get("owner_key")
        if not isinstance(owner, str) or not owner:
            raise ValueError("each shader identity edit requires a stable owner_key")
        normalized.append((owner, edit))
    if len({owner for owner, _ in normalized}) != len(normalized):
        raise ValueError("shader identity owner_key values must be unique")
    occupied = set(occupied_extra)
    receipts = []
    for owner, edit in sorted(normalized, key=lambda item: item[0]):
        receipt = allocate_identity(edit.get("type_id"), edit.get("name"), edit.get("program"),
                                    inventories, expected_replay_exe_sha256, occupied)
        receipt["owner_key"] = owner
        occupied.add(receipt["identity"])
        receipts.append(receipt)
    return receipts


def build_inventory(body_path: Path, journal_path: Path, trace_path: Path,
                    manifest_path: Path, replay_executable: Path, *,
                    normalized_rows: list[dict] | None = None) -> dict:
    """Inventory all type 14-17 root identities from a complete native trace."""
    paths = [Path(p).resolve(strict=True) for p in
             (body_path, journal_path, trace_path, manifest_path, replay_executable)]
    body_path, journal_path, trace_path, manifest_path, replay_executable = paths
    body = body_path.read_bytes()
    zone = ZoneBody.parse(body)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
    expected_assets = len(zone.assets)
    references = manifest.get("reference_only_rows", [])
    if not isinstance(references, list):
        raise ValueError("shader inventory reference descriptors are malformed")
    tested, top_level = manifest.get("tested"), manifest.get("top_level_index")
    exact_manifest = (
        manifest.get("profile") == "replay-1.20" and manifest.get("xfile_version") == 4087 and
        manifest.get("complete") is True and manifest.get("success") is True and
        manifest.get("failed") == 0 and manifest.get("unavailable") == 0 and
        type(tested) is int and tested >= 0 and
        type(top_level) is int and top_level == expected_assets and
        tested + len(references) == expected_assets and
        type(manifest.get("loaded_assets")) is int and manifest["loaded_assets"] >= tested and
        manifest.get("export_record_index") == manifest.get("loaded_assets") and
        manifest.get("serialized_bytes_read") == len(body))
    if not exact_manifest:
        raise ValueError("native manifest is not a complete successful Replay 1.20 exact-EOF walk")
    if len(rows) != tested:
        raise ValueError("native journal count differs from the manifest's tested row count")
    if references and normalized_rows is None:
        raise ValueError("reference-aware shader inventory requires trace-normalized table rows")
    inventory_rows = rows if normalized_rows is None else normalized_rows
    if not isinstance(inventory_rows, list) or len(inventory_rows) != expected_assets:
        raise ValueError("normalized native rows differ from the parsed XAsset table")
    reference_by_index = {}
    for descriptor in references:
        if not isinstance(descriptor, dict):
            raise ValueError("native reference descriptor is malformed")
        index = descriptor.get("index")
        if (type(index) is not int or not 0 <= index < expected_assets or index in reference_by_index or
                descriptor.get("pointer_token") != zone.assets[index].pointer_token):
            raise ValueError("native reference descriptor differs from its XAsset row")
        reference_by_index[index] = descriptor
    raw_index = 0
    for index, (native, serialized) in enumerate(zip(inventory_rows, zone.assets, strict=True)):
        if native.get("type_id") != serialized.type_id:
            raise ValueError(f"native journal type/order differs from XAsset row {index}")
        if native.get("index", index) != index:
            raise ValueError(f"normalized native row index differs at XAsset row {index}")
        if native.get("pointer_token") is not None and native.get("pointer_token") not in (
                serialized.pointer_token, hex(serialized.pointer_token)):
            raise ValueError(f"normalized native pointer token differs at XAsset row {index}")
        if index in reference_by_index:
            descriptor = reference_by_index[index]
            if (native.get("name") != descriptor.get("name") or
                    native.get("status") != "reference"):
                raise ValueError(f"normalized reference identity differs at XAsset row {index}")
        else:
            if raw_index >= len(rows):
                raise ValueError("native tested journal ended before normalized table rows")
            tested_row = rows[raw_index]
            raw_index += 1
            if (native.get("name") != tested_row.get("name") or
                    native.get("type_id") != tested_row.get("type_id")):
                raise ValueError(f"normalized row differs from tested native journal at XAsset row {index}")
    if raw_index != len(rows) or set(reference_by_index) != {row.get("index") for row in references}:
        raise ValueError("native journal and normalized reference rows do not cover the complete table")
    selected = [i for i, row in enumerate(inventory_rows) if row.get("type_id") in SHADER_TYPES]
    trace = build_read_span_index(trace_path, manifest_path, len(body), selected_assets=selected)
    by_index = {asset["index"]: asset for asset in trace["assets"]}
    if set(by_index) != set(selected):
        raise ValueError("complete native trace omitted one or more shader XAssets")
    shaders = []
    bound_names: set[str] = set()
    for index in selected:
        row, asset = inventory_rows[index], by_index[index]
        roots = [span for span in asset["read_spans"]
                 if span.get("origin") == "load_stream_call"
                 and span.get("reader_start_arg") == 0 and span.get("size") == 40]
        if len(roots) != 1:
            raise ValueError(f"shader XAsset {index} has no unique native 40-byte root")
        root_at = roots[0]["archive_offset"]
        root = body[root_at:root_at + 40]
        if len(root) != 40:
            raise ValueError(f"shader XAsset {index} root falls outside decoded body")
        size, identity = struct.unpack_from("<II", root, 32)
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"shader XAsset {index} has no stable native name")
        name_bytes = name.encode("utf-8") + b"\0"
        name_reads = []
        for span in asset["read_spans"]:
            at, count = span.get("archive_offset"), span.get("size")
            if type(at) is int and count == len(name_bytes) and body[at:at + count] == name_bytes:
                name_reads.append(span)
        name_token = struct.unpack_from("<Q", root, 0)[0]
        if len(name_reads) == 1:
            bound_names.add(name)
            name_binding = "owned-native-string-read"
            name_archive_offset = name_reads[0]["archive_offset"]
        elif not name_reads and name in bound_names and name_token not in (
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE):
            name_binding = "native-pointer-reuses-earlier-trace-bound-name"
            name_archive_offset = None
        else:
            raise ValueError(f"shader XAsset {index} name is not trace-bound or validly reused")
        program_candidates = []
        for span in asset["read_spans"]:
            at, count = span.get("archive_offset"), span.get("size")
            if type(at) is int and type(count) is int and count == size and count >= 32:
                child = body[at:at + count]
                if child[:4] == b"DXBC" and len(child) == count:
                    program_candidates.append(child)
        program_sha = (hashlib.sha256(program_candidates[0]).hexdigest()
                       if len(program_candidates) == 1 else None)
        shaders.append(dict(asset_index=index, type_id=row["type_id"], type=row.get("type"),
                            name=name, name_binding=name_binding,
                            name_archive_offset=name_archive_offset,
                            root_archive_offset=root_at,
                            program_size=size, program_identity=identity,
                            program_identity_hex=f"0x{identity:08x}",
                            inline_dxbc_sha256=program_sha,
                            inline_dxbc_unique=len(program_candidates) == 1))
    core = dict(schema="replay120-shader-identity-inventory-v1",
                status="complete-trace-proven-shader-root-inventory",
                zone_id=Path(manifest.get("fastfile", "unknown.ff")).stem,
                native_profile=manifest["profile"], xfile_version=manifest["xfile_version"],
                replay_executable_sha256=_sha256_file(replay_executable),
                body_sha256=hashlib.sha256(body).hexdigest(),
                journal_sha256=_sha256_file(journal_path), trace_sha256=_sha256_file(trace_path),
                manifest_sha256=_sha256_file(manifest_path), trace_event_count=trace["event_count"],
                xasset_count=trace["xasset_count"], shader_count=len(shaders), shaders=shaders)
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    core["inventory_sha256"] = hashlib.sha256(canonical).hexdigest()
    return core


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--replay-exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_inventory(args.body, args.journal, args.trace, args.manifest, args.replay_exe)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in
                      ("status", "shader_count", "inventory_sha256")}, indent=2))


if __name__ == "__main__":
    main()
