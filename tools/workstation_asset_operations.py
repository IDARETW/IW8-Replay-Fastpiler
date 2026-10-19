"""Immutable pending-operation storage for non-row-replacement asset edits.

The module deliberately does not interpret or execute operations.  It only
binds an append/remove request to its serialized payload and provenance so the
workspace dispatcher can validate it before packaging.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any


SCHEMA = 4
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^op-(?:a-(?:l-|s-|r-|t-|p-|i-)?[0-9a-f]{32}|r-[0-9]+)$")
_NATIVE_IDENTITY_FIELDS = (
    "body_sha256", "source_fastfile_sha256", "patch_sha256s",
    "native_walk_key", "native_manifest_sha256", "stream_trace_sha256",
    "writer_module_path", "writer_module_sha256",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_asset_identity(zone_id: str, type_id: int, name: str) -> str:
    """Build the type-qualified identity shared by newly staged native rows."""
    zone = _safe_component(zone_id, "zone id")
    if ":" in zone:
        raise ValueError("invalid zone id")
    asset_name = _safe_asset_name(name)
    if isinstance(type_id, bool) or not isinstance(type_id, int) or not 0 <= type_id <= 255:
        raise ValueError("invalid native asset type id")
    return f"{zone}:new-{type_id}-{_sha(asset_name.encode('utf-8'))[:32]}"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _revision(row: dict) -> str:
    # Paths and timestamps describe storage, not the requested semantic edit.
    basis = {key: value for key, value in row.items()
             if key not in {"revision", "edited_payload_path", "payload_path",
                            "created_at", "updated_at", "discarded_at"}}
    return _sha(_canonical(basis))


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _safe_cache(cache_path: str | Path, *, create: bool = False) -> Path:
    raw = Path(cache_path).expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    # Refuse symlink/junction components, including the cache itself.  resolve()
    # alone would silently accept a redirected operation store.
    current = Path(raw.anchor)
    for part in raw.parts[1:]:
        current = current / part
        if _is_link(current):
            raise ValueError("operation cache path contains a symlink or junction")
    if create:
        raw.mkdir(parents=True, exist_ok=True)
    return raw.resolve(strict=True)


def _inside(root: Path, path: Path) -> Path:
    lexical = Path(os.path.abspath(path))
    if not lexical.is_relative_to(root):
        raise ValueError("operation path escapes the cache")
    cursor = root
    for part in lexical.relative_to(root).parts:
        cursor = cursor / part
        if _is_link(cursor):
            raise ValueError("operation path contains a symlink or junction")
    resolved = lexical.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("operation path escapes the cache")
    return resolved


def _safe_component(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value in (".", "..") or "/" in value or "\\" in value:
        raise ValueError(f"invalid {label}")
    return value


def _safe_asset_name(value: Any) -> str:
    if (not isinstance(value, str) or not value or value.startswith("/") or
            value.endswith("/") or "\\" in value or "\x00" in value or
            any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("invalid operation name")
    return value


def _operation_id(operation: str, name: str, index: Any, type_id: int = 41) -> str:
    if operation == "append":
        prefix = {41: "op-a-", 51: "op-a-r-", 52: "op-a-s-", 54: "op-a-t-", 62: "op-a-l-", 12: "op-a-p-", 14: "op-a-p-", 15: "op-a-p-", 16: "op-a-p-", 17: "op-a-p-", 19: "op-a-i-"}.get(type_id)
        if prefix is None:
            raise ValueError("unsupported asset operation type")
        basis = name.encode("utf-8") if type_id in (41, 51, 52, 54, 62, 17) else f"{type_id}:{name}".encode("utf-8")
        return prefix + _sha(basis)[:32]
    if operation == "remove":
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("remove operation requires a nonnegative source index")
        return f"op-r-{index}"
    raise ValueError("unsupported asset operation")


def _validate_shape(row: dict, payload: bytes | None = None) -> None:
    if not isinstance(row, dict) or row.get("schema") != SCHEMA:
        raise ValueError("unsupported asset operation schema")
    supported_types = {41: "localize", 51: "rawfile", 52: "scriptfile", 54: "stringtable", 62: "luafile",
                       12: "computeshader", 14: "vertexshader", 15: "hullshader", 16: "domainshader", 17: "pixelshader", 19: "image"}
    if type(row.get("type_id")) is not int or row.get("type_id") not in supported_types or row.get("type") != supported_types[row.get("type_id")]:
        raise ValueError("unsupported asset operation type")
    operation = row.get("operation")
    name = _safe_asset_name(row.get("name"))
    zone = _safe_component(row.get("zone_id"), "zone id")
    asset_id = row.get("asset_id")
    if not isinstance(asset_id, str) or not asset_id.startswith(zone + ":"):
        raise ValueError("operation asset identity does not match its zone")
    index = row.get("index")
    xasset_index = row.get("xasset_index")
    if operation == "append":
        expected_id = new_asset_identity(zone, row["type_id"], name) if row["type_id"] in (12, 14, 15, 16, 17, 19) else zone + ":new-" + _sha(name.encode("utf-8"))[:32]
        legacy_pixel_id = zone + ":new-" + _sha(name.encode("utf-8"))[:32]
        if index is not None or xasset_index is not None or (asset_id != expected_id and not (row["type_id"] == 17 and asset_id == legacy_pixel_id)):
            raise ValueError("append operation identity is invalid")
        if row.get("operation_id") != _operation_id(operation, name, None, row["type_id"]):
            raise ValueError("append operation id is invalid")
    elif operation == "remove":
        if isinstance(index, bool) or not isinstance(index, int) or index < 0 or xasset_index != index:
            raise ValueError("remove operation source index is invalid")
        if asset_id != f"{zone}:{index}" or row.get("operation_id") != _operation_id(operation, name, index, row["type_id"]):
            raise ValueError("remove operation identity is invalid")
    else:
        raise ValueError("unsupported asset operation")

    content = row.get("content")
    if not isinstance(content, str):
        raise ValueError("operation content must be text")
    content_hash = row.get("content_sha256")
    if not isinstance(content_hash, str) or not _HEX.fullmatch(content_hash):
        raise ValueError("operation content hash is invalid")
    if _sha(content.encode("utf-8")) != content_hash:
        raise ValueError("operation content does not match its hash")

    payload_hash, payload_size = row.get("payload_sha256"), row.get("payload_bytes")
    if not isinstance(payload_hash, str) or not _HEX.fullmatch(payload_hash):
        raise ValueError("operation payload hash is invalid")
    if isinstance(payload_size, bool) or not isinstance(payload_size, int) or payload_size < 0:
        raise ValueError("operation payload size is invalid")
    payload_name = _safe_component(row.get("payload_name"), "payload name")
    if payload_name != f"{payload_hash}.payload":
        raise ValueError("operation payload name is not content-addressed")
    if payload is not None and (len(payload) != payload_size or _sha(payload) != payload_hash):
        raise ValueError("operation payload bytes do not match their metadata")

    source = row.get("native_source_identity")
    if not isinstance(source, dict):
        raise ValueError("operation native source identity is missing")
    for key in _NATIVE_IDENTITY_FIELDS:
        value = source.get(key)
        if key.endswith("sha256"):
            if not isinstance(value, str) or not _HEX.fullmatch(value):
                raise ValueError(f"operation source identity has invalid {key}")
        elif key == "patch_sha256s":
            if not isinstance(value, list) or any(not isinstance(item, str) or not _HEX.fullmatch(item) for item in value):
                raise ValueError("operation source patch hashes are invalid")
        elif not isinstance(value, str) or not value:
            raise ValueError(f"operation source identity is missing {key}")

    receipt = row.get("compiler_receipt")
    receipt_hash = row.get("compiler_receipt_sha256")
    if not isinstance(receipt, dict) or not isinstance(receipt_hash, str) or not _HEX.fullmatch(receipt_hash):
        raise ValueError("operation compiler receipt is missing")
    if _sha(_canonical(receipt)) != receipt_hash:
        raise ValueError("operation compiler receipt hash is invalid")
    if row["type_id"] == 51:
        editor_mode = row.get("editor_mode")
        if editor_mode not in ("text", "base64"):
            raise ValueError("RawFile operation editor mode is invalid")
        if operation == "append":
            result = receipt.get("result")
            if (receipt.get("schema") != "replay120-rawfile-row-receipt-v1" or
                    receipt.get("status") != "rawfile-row-operation-staged" or
                    receipt.get("asset_name") != name or receipt.get("operation") != "append" or
                    receipt.get("editor_mode") != editor_mode or
                    not isinstance(receipt.get("source"), dict) or
                    receipt["source"].get("sha256") != content_hash or
                    not isinstance(result, dict) or
                    result.get("native_payload_sha256") != payload_hash or
                    result.get("raw_bytes") != payload_size):
                raise ValueError("RawFile append receipt differs from its source text or native payload")
        else:
            if (receipt.get("schema") != "replay120-rawfile-row-receipt-v1" or
                    receipt.get("status") != "rawfile-row-removal-staged" or
                    receipt.get("asset_name") != name or receipt.get("operation") != "remove" or
                    receipt.get("editor_mode") != editor_mode or
                    receipt.get("source_index") != index or
                    receipt.get("source_body_sha256") != row.get("source_body_sha256") or
                    receipt.get("native_payload_sha256") != payload_hash):
                raise ValueError("RawFile removal receipt differs from its source row or payload")
    elif row["type_id"] == 52:
        if operation == "append":
            compiler = receipt.get("compiler")
            source_proof = receipt.get("source")
            result = receipt.get("result")
            string_ownership = receipt.get("string_ownership")
            expected_input = "script_" + _sha(name.encode("utf-8"))[:20]
            if (receipt.get("schema") != "replay120-gsc-compile-receipt-v1" or
                    receipt.get("status") != "gsc-tool-native-payload-pass" or
                    receipt.get("asset_name") != name or
                    not isinstance(source_proof, dict) or source_proof.get("sha256") != content_hash or
                    not isinstance(compiler, dict) or compiler.get("input_name") != expected_input or
                    not isinstance(result, dict) or
                    result.get("native_payload_sha256") != payload_hash or
                    result.get("payload_contract") != "Replay ScriptFile GSCBIN after Replay local-reference scaling" or
                    not isinstance(string_ownership, dict) or
                    string_ownership.get("policy") not in {
                        "typed-inline-only-v1",
                        "typed-class0-op18-field-subset-v1",
                    } or
                    string_ownership.get("complete_cursor") is not True or
                    string_ownership.get("nonzero_script_string_ids") != 0 or
                    type(string_ownership.get("cursor_event_count")) is not int or
                    type(string_ownership.get("bytecode_bytes")) is not int):
                raise ValueError("ScriptFile compiler receipt or inline string ownership is invalid")
            if string_ownership.get("policy") == "typed-class0-op18-field-subset-v1":
                accepted = string_ownership.get("accepted_field_events")
                if (not isinstance(string_ownership.get("field_contract_sha256"), str) or
                        not _HEX.fullmatch(string_ownership["field_contract_sha256"]) or
                        not isinstance(string_ownership.get("original_replay_sha256"), str) or
                        not _HEX.fullmatch(string_ownership["original_replay_sha256"]) or
                        not isinstance(string_ownership.get("compiler_sha256"), str) or
                        not _HEX.fullmatch(string_ownership["compiler_sha256"]) or
                        type(string_ownership.get("accepted_opcode_0x18_field_token_count")) is not int or
                        string_ownership["accepted_opcode_0x18_field_token_count"] < 1 or
                        not isinstance(accepted, list) or
                        len(accepted) != string_ownership["accepted_opcode_0x18_field_token_count"]):
                    raise ValueError("ScriptFile class-0 field ownership identity is incomplete")
                for event in accepted:
                    if (not isinstance(event, dict) or event.get("opcode") != "0x18" or
                            not isinstance(event.get("field_name"), str) or not event["field_name"] or
                            type(event.get("descriptor_row_index")) is not int or
                            not 0 <= event["descriptor_row_index"] < 16 or
                            not isinstance(event.get("pc"), str) or
                            not re.fullmatch(r"0x[0-9a-f]+", event["pc"]) or
                            not isinstance(event.get("bytecode_offset"), str) or
                            not re.fullmatch(r"0x[0-9a-f]+", event["bytecode_offset"]) or
                            not isinstance(event.get("token"), str) or
                            not re.fullmatch(r"0x[0-9a-f]+", event["token"]) or
                            int(event["token"], 16) == 0):
                        raise ValueError("ScriptFile class-0 field ownership event is malformed")
        elif (receipt.get("schema") != "replay120-gsc-existing-payload-remove-receipt-v1" or
                receipt.get("status") != "gsc-existing-payload-preserved-pass" or
                receipt.get("asset_name") != name or
                receipt.get("native_payload_sha256") != payload_hash or
                receipt.get("preservation") != "exact existing GSCBIN bytes" or
                type(receipt.get("source_index")) is not int or
                not isinstance(receipt.get("source_body_sha256"), str) or
                not _HEX.fullmatch(receipt["source_body_sha256"])):
            raise ValueError("ScriptFile existing-payload removal receipt is invalid")
    elif row["type_id"] in (12, 14, 15, 16, 17):
        if operation == "remove":
            if (receipt.get("schema") != "replay120-native-shader-row-remove-receipt-v1" or
                    receipt.get("status") != "native-shader-row-removal-staged" or
                    receipt.get("asset_name") != name or receipt.get("source_index") != index or
                    receipt.get("source_body_sha256") != row.get("source_body_sha256") or
                    receipt.get("native_payload_sha256") != payload_hash):
                raise ValueError("shader removal receipt differs from its exact source row or payload")
            if payload is not None and (not payload.startswith(b"DXBC") or _sha(payload) != receipt.get("native_payload_sha256")):
                raise ValueError("shader removal does not preserve its original DXBC bytes")
            writer = row.get("writer_identity")
            if not isinstance(writer, dict) or not isinstance(writer.get("path"), str) or not writer["path"] or not isinstance(writer.get("sha256"), str) or not _HEX.fullmatch(writer["sha256"]):
                raise ValueError("shader removal writer identity is invalid")
            revision = row.get("revision")
            if not isinstance(revision, str) or not _HEX.fullmatch(revision) or _revision(row) != revision:
                raise ValueError("shader removal revision does not match its immutable contents")
            return
        result = receipt.get("result")
        compiler = receipt.get("compiler")
        allocation = receipt.get("identity_allocation")
        stage_id = row["type_id"]
        legacy_pixel = stage_id == 17 and receipt.get("schema") == "replay120-pixelshader-row-append-receipt-v1"
        if (operation != "append" or
                receipt.get("schema") not in {"replay120-native-shader-row-append-receipt-v1",
                                                "replay120-pixelshader-row-append-receipt-v1"} or
                receipt.get("status") != "replay120-dxbc-assemble-pass" or
                receipt.get("asset_name") != name or
                (receipt.get("native_type_id", stage_id) != stage_id) or
                not isinstance(receipt.get("source"), dict) or
                receipt["source"].get("sha256") != content_hash or
                not isinstance(compiler, dict) or
                not isinstance(compiler.get("path"), str) or
                not isinstance(compiler.get("sha256"), str) or not _HEX.fullmatch(compiler["sha256"]) or
                (not legacy_pixel and (not isinstance(allocation, dict) or allocation.get("type_id") != stage_id or
                    allocation.get("name") != name or type(allocation.get("identity")) is not int or
                    not 0 <= allocation["identity"] <= 0xFFFFFFFF)) or
                not isinstance(result, dict) or result.get("native_payload_sha256") != payload_hash or
                result.get("native_type_id") != stage_id or
                (not legacy_pixel and result.get("program_identity") != allocation.get("identity"))):
            raise ValueError("shader append receipt differs from its source, compiler, DXBC or allocated identity")
    elif row["type_id"] == 19:
        result = receipt.get("result")
        source_proof = receipt.get("source")
        if operation == "append":
            compiler = receipt.get("compiler")
            if (receipt.get("schema") != "replay120-resident-image-row-append-receipt-v1" or
                    receipt.get("status") != "resident-image-dds-import-pass" or
                    receipt.get("asset_name") != name or
                    not isinstance(source_proof, dict) or source_proof.get("sha256") != content_hash or
                    not isinstance(compiler, dict) or not isinstance(compiler.get("path"), str) or
                    not isinstance(compiler.get("sha256"), str) or not _HEX.fullmatch(compiler["sha256"]) or
                    not isinstance(compiler.get("codec_module_sha256"), str) or
                    not _HEX.fullmatch(compiler["codec_module_sha256"]) or
                    not isinstance(result, dict) or result.get("native_payload_sha256") != payload_hash or
                    result.get("native_payload_bytes") != payload_size or result.get("native_type_id") != 19 or
                    not isinstance(result.get("format"), int) or
                    not isinstance(result.get("dimensions"), list) or len(result["dimensions"]) != 4 or
                    any(type(value) is not int or value < 1 for value in result["dimensions"]) or
                    type(result.get("mip_count")) is not int or result["mip_count"] < 1):
                raise ValueError("resident image append receipt differs from its source DDS or typed payload")
        elif (receipt.get("schema") != "replay120-resident-image-row-remove-receipt-v1" or
              receipt.get("status") != "resident-image-preserve-pass" or
              receipt.get("asset_name") != name or receipt.get("source_index") != index or
              receipt.get("source_body_sha256") != row.get("source_body_sha256") or
              not isinstance(source_proof, dict) or source_proof.get("sha256") != content_hash or
              not isinstance(result, dict) or result.get("native_payload_sha256") != payload_hash or
              result.get("native_payload_bytes") != payload_size):
            raise ValueError("resident image removal receipt differs from its source row or payload")
    writer = row.get("writer_identity")
    if not isinstance(writer, dict) or not isinstance(writer.get("path"), str) or not writer["path"]:
        raise ValueError("operation writer identity is missing")
    if not isinstance(writer.get("sha256"), str) or not _HEX.fullmatch(writer["sha256"]):
        raise ValueError("operation writer identity hash is invalid")
    revision = row.get("revision")
    if not isinstance(revision, str) or not _HEX.fullmatch(revision) or _revision(row) != revision:
        raise ValueError("operation revision does not match its immutable contents")


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
    except BaseException:
        try:
            Path(temporary).unlink(missing_ok=True)
        finally:
            raise


def _atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
    except BaseException:
        try:
            Path(temporary).unlink(missing_ok=True)
        finally:
            raise


def _operation_folder(cache: Path, zone_id: str, operation_id: str) -> Path:
    _safe_component(zone_id, "zone id")
    if cache.name != zone_id:
        raise ValueError("operation cache directory does not match its zone id")
    if not isinstance(operation_id, str) or not _SAFE_ID.fullmatch(operation_id):
        raise ValueError("invalid operation id")
    return cache / "pending-edits" / operation_id


def stage_operation(cache_path: str | Path, row: dict, payload: bytes,
                    expected_revision: str | None = None) -> dict:
    """Create or advance one immutable operation revision using CAS semantics."""
    if not isinstance(payload, bytes):
        raise TypeError("operation payload must be bytes")
    cache = _safe_cache(cache_path, create=True)
    candidate = dict(row)
    candidate.pop("revision", None)
    if "schema" in candidate and candidate["schema"] != SCHEMA:
        raise ValueError("unsupported asset operation schema")
    candidate["schema"] = SCHEMA
    name = _safe_asset_name(candidate.get("name"))
    operation = candidate.get("operation")
    candidate["operation_id"] = _operation_id(operation, name, candidate.get("index"),
                                               candidate.get("type_id", 41))
    digest = _sha(payload)
    candidate["payload_sha256"] = digest
    candidate["payload_bytes"] = len(payload)
    candidate["payload_name"] = f"{digest}.payload"
    # Compatibility with pending_snapshot, which discovers */pending-edits/*/current.json.
    candidate["edited_payload_path"] = candidate["payload_name"]
    candidate["edited_payload_sha256"] = digest
    candidate["edited_payload_bytes"] = len(payload)
    candidate["revision"] = _revision(candidate)
    _validate_shape(candidate, payload)

    folder = _operation_folder(cache, candidate["zone_id"], candidate["operation_id"])
    parent = folder.parent
    if parent.exists():
        _inside(cache, parent)
    if folder.exists() and _is_link(folder):
        raise ValueError("operation directory is a symlink or junction")
    folder.mkdir(parents=True, exist_ok=True)
    _inside(cache, folder)
    current_path = folder / "current.json"
    if _is_link(current_path):
        raise ValueError("operation current file is a symlink or junction")
    if current_path.exists():
        _inside(cache, current_path)
        current, _old_payload = validate_operation(cache, current_path,
                                                   candidate.get("native_source_identity"))
        if expected_revision is None or expected_revision != current.get("revision"):
            raise ValueError("stale operation revision conflict")
        if current.get("operation_id") != candidate["operation_id"]:
            raise ValueError("operation identity cannot change across revisions")
        identity_fields = ("operation", "type_id", "type", "name", "zone_id",
                           "asset_id", "index", "xasset_index")
        if any(current.get(key) != candidate.get(key) for key in identity_fields):
            raise ValueError("operation target identity cannot change across revisions")
    elif expected_revision is not None:
        raise ValueError("operation revision no longer exists")

    payload_path = folder / candidate["payload_name"]
    if _is_link(payload_path):
        raise ValueError("operation payload is a symlink or junction")
    if payload_path.exists():
        _inside(cache, payload_path)
        if payload_path.read_bytes() != payload:
            raise ValueError("content-addressed operation payload collision")
    else:
        _atomic_bytes(payload_path, payload)

    history_path = folder / f"{candidate['revision']}.json"
    if _is_link(history_path):
        raise ValueError("operation history is a symlink or junction")
    if history_path.exists():
        _inside(cache, history_path)
        prior = json.loads(history_path.read_text(encoding="utf-8"))
        if prior != candidate:
            raise ValueError("immutable operation revision collision")
    else:
        _atomic_json(history_path, candidate)
    _atomic_json(current_path, candidate)
    return candidate


def validate_operation(cache_path: str | Path, current_path: str | Path,
                       expected_source_identity: dict | None = None) -> tuple[dict, bytes]:
    """Validate current row, immutable history, source binding, and payload bytes."""
    cache = _safe_cache(cache_path)
    current = _inside(cache, Path(current_path))
    if current.name != "current.json" or current.parent.parent.name != "pending-edits":
        raise ValueError("operation current path is outside the operation store")
    folder = current.parent
    if not _SAFE_ID.fullmatch(folder.name) or folder.parent.name != "pending-edits":
        raise ValueError("operation folder identity is invalid")
    row = json.loads(current.read_text(encoding="utf-8"))
    payload_name = row.get("payload_name")
    _safe_component(payload_name, "payload name")
    payload_path = _inside(cache, folder / payload_name)
    payload = payload_path.read_bytes()
    _validate_shape(row, payload)
    if folder.name != row.get("operation_id"):
        raise ValueError("operation row is stored under the wrong identity")
    if folder.parent.parent.name != row.get("zone_id"):
        raise ValueError("operation row is stored under the wrong zone")
    immutable_path = _inside(cache, folder / f"{row['revision']}.json")
    if json.loads(immutable_path.read_text(encoding="utf-8")) != row:
        raise ValueError("current operation differs from immutable history")
    if expected_source_identity is not None and row.get("native_source_identity") != expected_source_identity:
        raise ValueError("operation source identity is stale")
    return row, payload


def discard_operation(cache_path: str | Path, operation_id: str, revision: str) -> dict:
    """Discard the current revision while retaining all immutable history."""
    cache = _safe_cache(cache_path)
    if not isinstance(operation_id, str) or not _SAFE_ID.fullmatch(operation_id):
        raise ValueError("invalid operation id")
    current_path = _inside(cache, cache / "pending-edits" / operation_id / "current.json")
    folder = current_path.parent
    row = json.loads(current_path.read_text(encoding="utf-8"))
    if row.get("revision") != revision:
        raise ValueError("stale operation revision conflict")
    validated, _payload = validate_operation(cache, current_path)
    if validated != row:
        raise ValueError("current operation changed during discard")
    discarded = folder / f"{revision}.discarded.json"
    marker = {"schema": SCHEMA, "operation_id": operation_id, "revision": revision,
              "discarded": True}
    if discarded.exists():
        if json.loads(_inside(cache, discarded).read_text(encoding="utf-8")) != marker:
            raise ValueError("operation discard history changed")
    else:
        _atomic_json(discarded, marker)
    current_path.unlink()
    return marker
