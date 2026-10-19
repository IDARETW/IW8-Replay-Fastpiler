"""Trace-bound create and final-row removal writers for Replay ScriptFile assets.

Append binds its compiler receipt to a typed inline template and exact EOF.
Removal accepts only an exclusive final XAsset with exact EOF ownership and
validates a fresh native reread before publication.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile

from workstation_fastfiles import ZoneBody, ordered_asset_identity_sha256
from workstation_luafile_operations import (
    INLINE_POINTER, XASSET_ARRAY_COUNT_OFFSET, XASSET_ROW_SIZE,
    _rebase_aliases, _trace_contract,
)
from workstation_asset_codecs import inspect_gscbin


SCRIPTFILE_TYPE_ID = 52
INLINE_CHILD_POINTER = 0xFFFFFFFFFFFFFFFE
SCRIPTFILE_NAME_INLINE = 0xFFFFFFFFFFFFFFFF
SCRIPTFILE_ROOT_SIZE = 40
SOURCE_TEXT_INLINE_ONLY = "typed-inline-only-v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_helper_sources_unchanged(before: dict[str, str], after: dict[str, str]) -> None:
    if before != after:
        raise ValueError("ScriptFile transaction helper sources changed before publication")


def _validate_active_removal_plan(plan: dict, staged: dict, source_body_sha256: str) -> None:
    """Check a removal against either a public zone plan or a direct proof."""
    planned = [row for row in plan.get("edits", []) if row.get("operation") == "remove"]
    proof = plan.get("proof", plan)
    proof_edits = [row for row in proof.get("edits", []) if row.get("operation") == "remove"]
    if (len(planned) != 1 or len(proof_edits) != 1 or
            planned[0].get("operation_id") != staged.get("operation_id") or
            planned[0].get("revision") != staged.get("revision") or
            (planned[0].get("index") is not None and
             planned[0].get("index") != staged.get("index")) or
            proof_edits[0].get("operation_id") != staged.get("operation_id") or
            proof_edits[0].get("revision") != staged.get("revision") or
            proof_edits[0].get("index") != staged.get("index") or
            proof.get("source_body_sha256") != source_body_sha256):
        raise ValueError("ScriptFile removal operation changed after preflight")


def _safe_name(name: str) -> None:
    if (not isinstance(name, str) or not name or "\x00" in name or
            name.startswith("/") or name.endswith("/") or "\\" in name or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("ScriptFile append name is not a safe native asset name")


def _native_scriptfile_name(value: str) -> str:
    """Normalize an editor filename to the Replay XAsset identity."""
    if (not isinstance(value, str) or not value or value.startswith("/") or
            value.endswith("/") or "\\" in value or "\x00" in value or
            any(part in ("", ".", "..") for part in value.split("/")) or
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}", value)):
        raise ValueError("Use a confined ScriptFile path with letters, digits, underscores, slashes, dots or hyphens")
    name = value
    _safe_name(name)
    if len(name.encode("utf-8")) > 255:
        raise ValueError("Native ScriptFile name exceeds the supported path length")
    return name


def _scriptfile_payload(body: bytes, row: dict, index: int,
                        expected_name: str) -> tuple[int, bytes]:
    """Recover a ScriptFile's exact GSCBIN from one complete trace-owned row."""
    if (row.get("xasset_index") != index or row.get("type_id") != SCRIPTFILE_TYPE_ID or
            row.get("name") != expected_name):
        raise ValueError("ScriptFile trace owner differs from the selected typed row")
    spans = row.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("ScriptFile trace row has no physical ownership spans")
    root_reads = sorted((span for span in spans if span.get("origin") == "load_stream_call" and
             span.get("reader_start_arg") == 0), key=lambda span: span.get("archive_offset", -1))
    if not root_reads or root_reads[0].get("size") != SCRIPTFILE_ROOT_SIZE:
        raise ValueError("ScriptFile trace does not begin with the 40-byte native root")
    root_at = root_reads[0].get("archive_offset")
    if type(root_at) is not int or root_at < 0 or root_at + SCRIPTFILE_ROOT_SIZE > len(body):
        raise ValueError("ScriptFile root span is outside the source body")
    (name_token, compressed_len, source_len, bytecode_len, reserved,
     compressed_token, bytecode_token) = struct.unpack_from("<QiiiIQQ", body, root_at)
    if (name_token != SCRIPTFILE_NAME_INLINE or reserved != 0 or
            compressed_token != INLINE_CHILD_POINTER or bytecode_token != INLINE_CHILD_POINTER or
            min(compressed_len, source_len, bytecode_len) <= 0):
        raise ValueError("ScriptFile template is outside the proven inline root contract")
    name_bytes = expected_name.encode("utf-8") + b"\0"
    name_spans = [span for span in spans if span.get("origin") == "string_data" and
                  span.get("archive_offset") == root_at + SCRIPTFILE_ROOT_SIZE and
                  span.get("size") == len(name_bytes)]
    if len(name_spans) != 1 or body[root_at + SCRIPTFILE_ROOT_SIZE:
                                   root_at + SCRIPTFILE_ROOT_SIZE + len(name_bytes)] != name_bytes:
        raise ValueError("ScriptFile template name is not an exact trace-owned inline string")
    child_at = root_at + SCRIPTFILE_ROOT_SIZE + len(name_bytes)
    children = [span for span in spans if span.get("origin") == "load_stream_call" and
                span.get("reader_start_arg") == 0 and
                isinstance(span.get("destination_stream_location"), dict) and
                span["destination_stream_location"].get("stream") == 6 and
                span.get("archive_offset", -1) >= child_at]
    children.sort(key=lambda span: span.get("archive_offset", -1))
    if (len(children) != 2 or children[0].get("archive_offset") != child_at or
            children[0].get("size") != compressed_len or
            children[1].get("archive_offset") != child_at + compressed_len or
            children[1].get("size") != bytecode_len):
        raise ValueError("ScriptFile template children do not match its contiguous stream-6 root lengths")
    first_dest = children[0]["destination_stream_location"].get("offset")
    second_dest = children[1]["destination_stream_location"].get("offset")
    if (type(first_dest) is not int or type(second_dest) is not int or
            second_dest != first_dest + compressed_len):
        raise ValueError("ScriptFile template children are not contiguous in stream 6")
    payload = struct.pack("<4I", 0x00435347, compressed_len, source_len, bytecode_len) + \
        body[child_at:child_at + compressed_len + bytecode_len]
    inspect_gscbin(payload)
    return root_at, payload


def remove_existing_scriptfile_row(body_data: bytes, asset_index: int, asset_name: str,
                                   trace_asset: dict, expected_body_sha256: str,
                                   trace_path: str | Path,
                                   manifest_path: str | Path,
                                   *, _contract_out: dict | None = None) -> tuple[bytes, dict]:
    """Remove one fully traced final inline ScriptFile and its stream-6 children.

    The 40-byte root, inline name, compressed source and bytecode must be one
    exclusive physical extent. The complete trace is replayed across every
    asset so inbound aliases into that extent reject, while surviving packed
    block-5 pointers are relocated across the table/name splices.
    """
    from workstation_luafile_operations import (
        _alias_field_archive, _build_interval_index, _rebase_aliases,
        _trace_contract,
    )
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("ScriptFile removal trace belongs to a different source body")
    if (isinstance(asset_index, bool) or not isinstance(asset_index, int) or
            not 0 <= asset_index < len(body.assets)):
        raise ValueError("ScriptFile removal index is outside the source XAsset table")
    if body.assets[asset_index].type_id != SCRIPTFILE_TYPE_ID:
        raise ValueError("selected XAsset is not a native ScriptFile")
    if asset_index != len(body.assets) - 1:
        raise ValueError("ScriptFile removal currently requires the exact final XAsset row")
    if asset_name == "$default":
        raise ValueError("the root-only $default ScriptFile sentinel is not removable")
    if (trace_asset.get("xasset_index") != asset_index or
            trace_asset.get("type_id") != SCRIPTFILE_TYPE_ID or
            trace_asset.get("name") != asset_name):
        raise ValueError("native trace row identity differs from selected ScriptFile")

    root_at, payload = _scriptfile_payload(body_data, trace_asset, asset_index, asset_name)
    payload_info = inspect_gscbin(payload)
    spans = trace_asset.get("read_spans")
    if not isinstance(spans, list):
        raise ValueError("ScriptFile trace row lacks physical ownership spans")
    root_spans = [span for span in spans if span.get("origin") == "load_stream_call" and
                  span.get("reader_start_arg") == 0 and span.get("archive_offset") == root_at and
                  span.get("size") == SCRIPTFILE_ROOT_SIZE]
    encoded_name = asset_name.encode("utf-8") + b"\0"
    name_archive = root_at + SCRIPTFILE_ROOT_SIZE
    name_spans = [span for span in spans if span.get("origin") == "string_data" and
                  span.get("archive_offset") == name_archive and
                  span.get("size") == len(encoded_name)]
    child_spans = sorted((span for span in spans if span.get("origin") == "load_stream_call" and
                  span.get("reader_start_arg") == 0 and
                  isinstance(span.get("destination_stream_location"), dict) and
                  span["destination_stream_location"].get("stream") == 6),
                  key=lambda span: span.get("archive_offset", -1))
    if (len(root_spans) != 1 or len(name_spans) != 1 or len(child_spans) != 2 or
            [span.get("size") for span in child_spans] !=
            [len(payload_info.compressed_source), len(payload_info.bytecode)]):
        raise ValueError("ScriptFile trace does not uniquely own its root, inline name and two stream-6 children")
    root_span, name_span = root_spans[0], name_spans[0]
    root_dest = root_span.get("destination_stream_location")
    name_dest = name_span.get("destination_stream_location")
    first_dest = child_spans[0].get("destination_stream_location")
    second_dest = child_spans[1].get("destination_stream_location")
    if (not all(isinstance(item, dict) for item in (root_dest, name_dest, first_dest, second_dest)) or
            root_dest.get("stream") != 1 or name_dest.get("stream") != 5 or
            first_dest.get("stream") != 6 or second_dest.get("stream") != 6 or
            second_dest.get("offset") != first_dest.get("offset") + len(payload_info.compressed_source) or
            child_spans[0].get("archive_offset") != name_archive + len(encoded_name) or
            child_spans[1].get("archive_offset") != child_spans[0].get("archive_offset") +
                len(payload_info.compressed_source)):
        raise ValueError("ScriptFile root/name/stream-6 children do not form the verified contiguous layout")
    physical_start = root_at
    physical_end = child_spans[1]["archive_offset"] + child_spans[1]["size"]
    if physical_end > len(body_data) or body_data[name_archive:name_archive + len(encoded_name)] != encoded_name:
        raise ValueError("ScriptFile removal extent or inline name is outside the source body")
    if physical_end != len(body_data):
        raise ValueError("final ScriptFile removal requires its trace-owned physical extent to reach exact EOF")
    table_row_archive = body.asset_table_offset + asset_index * XASSET_ROW_SIZE
    if (table_row_archive < 0 or table_row_archive + XASSET_ROW_SIZE > body.first_payload_offset or
            struct.unpack_from("<I", body_data, table_row_archive)[0] != SCRIPTFILE_TYPE_ID):
        raise ValueError("selected ScriptFile table row is outside the verified XAsset table")

    root_range = (root_dest["stream"], root_dest["offset"],
                  root_dest["offset"] + SCRIPTFILE_ROOT_SIZE)
    name_range = (name_dest["stream"], name_dest["offset"],
                  name_dest["offset"] + len(encoded_name))
    child_range = (6, first_dest["offset"],
                   second_dest["offset"] + len(payload_info.bytecode))
    removed_ranges = (root_range, name_range, child_range)
    contract = _trace_contract(body_data, trace_path, manifest_path,
                               removed_stream_ranges=removed_ranges,
                               logical_delete_ranges=(name_range, child_range),
                               removed_owner=asset_index, table_row_delta=-XASSET_ROW_SIZE)
    (_manifest, asset_bases, intervals, aliases, table_alloc, max_destinations,
     alias_count, relocated_targets, relocated_asset_bases, pointer_stats) = contract
    if _contract_out is not None:
        _contract_out.update(asset_bases=asset_bases, intervals=intervals, aliases=aliases,
            table_alloc=table_alloc, max_destinations=max_destinations,
            relocated_targets=relocated_targets, relocated_asset_bases=relocated_asset_bases,
            removed_ranges=removed_ranges, logical_delete_ranges=(name_range, child_range))
    if (table_alloc.get("size") != len(body.assets) * XASSET_ROW_SIZE or
            table_alloc.get("archive") != body.asset_table_offset or
            table_alloc.get("archive", -1) + table_alloc.get("size", 0) != body.first_payload_offset):
        raise ValueError("native XAsset table allocation differs from the selected body")

    expected_owned = sorted((span.get("archive"), span.get("archive", -1) + span.get("size", 0))
                            for span in intervals if span.get("owner") == asset_index and
                            isinstance(span.get("archive"), int) and
                            span["archive"] < physical_end and
                            span["archive"] + span.get("size", 0) > physical_start)
    expected_physical = sorted((span.get("archive_offset"),
                                span.get("archive_offset", -1) + span.get("size", 0))
                               for span in (root_span, name_span, *child_spans))
    if expected_owned != expected_physical:
        raise ValueError("ScriptFile trace ownership includes missing or extra bytes in its removal extent")
    for span in intervals:
        if span.get("owner") != asset_index and span.get("archive", -1) < physical_end and \
                span.get("archive", -1) + span.get("size", 0) > physical_start:
            raise ValueError("ScriptFile root/name/stream-6 bytes are shared with another XAsset")

    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, table_alloc["end"], body.first_payload_offset,
        -XASSET_ROW_SIZE, asset_bases, removed_stream_ranges=removed_ranges,
        logical_delete_ranges=(name_range, child_range),
        relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_asset_bases)
    output = bytearray(rebased)
    for start, end in sorted(((physical_start, physical_end),
                              (table_row_archive, table_row_archive + XASSET_ROW_SIZE)), reverse=True):
        del output[start:end]
    struct.pack_into("<I", output, XASSET_ARRAY_COUNT_OFFSET, len(body.assets) - 1)
    result = bytes(output)
    reparsed = ZoneBody.parse(result)
    retained = body.assets[:asset_index] + body.assets[asset_index + 1:]
    if len(reparsed.assets) != len(retained) or [
            (row.type_id, row.pointer_token) for row in reparsed.assets] != [
            (row.type_id, row.pointer_token) for row in retained]:
        raise AssertionError("ScriptFile removal changed a retained XAsset identity/order")
    return result, dict(schema="replay120-scriptfile-row-remove-candidate-v1",
        status="native-trace-scriptfile-row-remove-candidate", operation="remove",
        asset_name=asset_name, asset_index=asset_index,
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(result),
        source_asset_count=len(body.assets), output_asset_count=len(reparsed.assets),
        removed_root_archive_range=[physical_start, physical_end],
        removed_root_bytes=SCRIPTFILE_ROOT_SIZE, removed_name_bytes=len(encoded_name),
        removed_stream6_range=[child_range[1], child_range[2]],
        removed_stream6_bytes=child_range[2] - child_range[1],
        removed_table_row_archive_range=[table_row_archive, table_row_archive + XASSET_ROW_SIZE],
        source_stream_max_destinations={str(key): value for key, value in max_destinations.items()},
        source_alias_events=alias_count, pointer_contract=pointer_stats,
        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        stream_trace_sha256=_sha(Path(trace_path).read_bytes()), **alias_receipt)


def _validate_compiler_receipt(name: str, source_text: str, payload: bytes,
                               receipt: dict, *, replay_executable=None,
                               compiler_executable=None) -> dict:
    if not isinstance(receipt, dict) or receipt.get("schema") != "replay120-gsc-compile-receipt-v1" or \
            receipt.get("status") != "gsc-tool-native-payload-pass":
        raise ValueError("ScriptFile append requires the native GSC compiler receipt")
    source_record = receipt.get("source")
    compiler_record = receipt.get("compiler")
    result_record = receipt.get("result")
    if not all(isinstance(value, dict) for value in
               (source_record, compiler_record, result_record)):
        raise ValueError("ScriptFile compiler receipt omits source, compiler, or result provenance")
    source_sha = _sha(source_text.encode("utf-8"))
    payload_sha = _sha(payload)
    compiler_input_name = "script_" + _sha(name.encode("utf-8"))[:20]
    if (receipt.get("asset_name") != name or
            source_record.get("sha256") != source_sha or
            result_record.get("native_payload_sha256") != payload_sha or
            compiler_record.get("input_name") != compiler_input_name or
            result_record.get("payload_contract") !=
            "Replay ScriptFile GSCBIN after Replay local-reference scaling"):
        raise ValueError("ScriptFile compiler receipt does not bind this source, name, and GSCBIN payload")
    if compiler_executable is not None:
        from workstation_gsc_fields import _sha256_path
        if compiler_record.get("sha256") != _sha256_path(Path(compiler_executable).resolve(strict=True)):
            raise ValueError("ScriptFile compiler receipt is bound to a different configured GSC Tool")
    from workstation_gsc_fields import validate_ownership_receipt
    validate_ownership_receipt(receipt.get("string_ownership"), payload,
        replay_executable=replay_executable, compiler_executable=compiler_executable)
    inspect_gscbin(payload)
    return dict(source_sha256=source_sha, payload_sha256=payload_sha,
                compiler=compiler_record)


def _validate_inline_script_strings(payload: bytes, *, replay_executable=None,
                                    compiler_executable=None) -> dict:
    """Preserve inline receipts and allow only proof-bound opcode-0x18 fields."""
    from workstation_gsc_fields import validate_scriptfile_payload
    return validate_scriptfile_payload(payload, replay_executable=replay_executable,
                                       compiler_executable=compiler_executable)


def _scriptfile_field_executables(workspace, compiler=None):
    """Return explicit configured identities; never invent Replay/compiler defaults."""
    from workstation_fastfiles import DEFAULT_GSC_TOOL
    replay = getattr(workspace, "replay_executable", None)
    selected = compiler if compiler is not None else DEFAULT_GSC_TOOL
    tool = Path(selected).resolve(strict=True) if selected is not None and Path(selected).is_file() else None
    return replay, tool


def _operation_cache(workspace, zone_id: str, decode_cache: Path) -> Path:
    """Store staged operations beside the validated zone cache."""
    return decode_cache


def _workspace_inputs(workspace, zone_id: str, *, _snapshot=None):
    from workstation_fastfiles import (_read_native_rows, acts_tool_identity,
        sha256_file, source_profile)
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    if _snapshot is not None:
        if hasattr(workspace, "_require_asset_request_snapshot"):
            workspace._require_asset_request_snapshot(_snapshot, zone_id)
        if _snapshot.zone_id != zone_id or not _snapshot.native_walk or not _snapshot.native_rows:
            raise ValueError("ScriptFile operation requires this zone's complete native request snapshot")
        decode_cache, decode_receipt, body = (_snapshot.cache_path, _snapshot.decode_receipt,
                                             _snapshot.body)
        body_path, source = _snapshot.body_path, _snapshot.source_path
        profile, walk, native_rows = (_snapshot.source_profile, _snapshot.native_walk,
                                      _snapshot.native_rows)
    else:
        decode_cache, decode_receipt = workspace._validated_zone_receipt(zone_id)
        body_path = (decode_cache / decode_receipt["final_body_relative_path"]).resolve(strict=True)
        body = ZoneBody.parse(body_path.read_bytes())
        source = Path(decode_receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk, native_rows = _read_native_rows(decode_cache, body, require_trace=True)
    if any(row.get("extension") == ".fc" for row in profile.get("patches", [])):
        raise ValueError("ScriptFile row append does not support FC replacement chains")
    if (walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
            [row["sha256"] for row in profile.get("patches", [])] or
            not walk.get("stream_trace_enabled")):
        raise ValueError("ScriptFile native walk does not match the complete source FF/patch chain")
    import workstation_asset_codecs as codec
    import workstation_gsc_fields as field_policy
    import workstation_scriptfile_crud as transaction
    import workstation_asset_operations as operation_store
    import workstation_fastfiles as dispatcher
    paths = [Path(module.__file__).resolve(strict=True) for module in
             (transaction, operation_store, dispatcher, field_policy)]
    contract_path = Path(field_policy.CONTRACT_PATH).resolve(strict=True)
    identity = dict(body_sha256=body.source_sha256,
        source_fastfile_sha256=profile["sha256"],
        patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
        native_walk_key=walk["walk_key"],
        native_manifest_sha256=walk["manifest_sha256"],
        stream_trace_sha256=walk["stream_trace_sha256"],
        writer_module_path=str(paths[0]), writer_module_sha256=sha256_file(paths[0]),
        transaction_module_path=str(paths[0]), transaction_module_sha256=sha256_file(paths[0]),
        dispatcher_module_path=str(paths[2]), dispatcher_module_sha256=sha256_file(paths[2]),
        field_policy_module_path=str(paths[3]), field_policy_module_sha256=sha256_file(paths[3]),
        field_contract_path=str(contract_path), field_contract_sha256=sha256_file(contract_path))
    return (decode_cache, _operation_cache(workspace, zone_id, decode_cache), decode_receipt,
            body, body_path, source, profile, walk, native_rows, identity, codec)


def _operation_id(name: str) -> str:
    return "op-a-s-" + _sha(name.encode("utf-8"))[:32]


def _reject_cross_type_new_identity(zone_id: str, name: str,
                                    family_rows: list[dict]) -> None:
    asset_id = zone_id + ":new-" + _sha(name.encode("utf-8"))[:32]
    if any(row.get("operation") == "append" and row.get("asset_id") == asset_id
           for row in family_rows):
        raise ValueError("another pending asset type already owns this new-asset identity")


def operations(workspace, zone_id: str, *, _snapshot=None) -> list[dict]:
    from workstation_asset_operations import validate_operation
    (decode_cache, operation_cache, _receipt, body, _body_path, _source, _profile,
     _walk, native_rows, identity, _codec) = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    operation_cache.mkdir(parents=True, exist_ok=True)
    results = []
    for current_path in sorted(operation_cache.glob("pending-edits/op-*/current.json")):
        raw = json.loads(current_path.read_text(encoding="utf-8"))
        if raw.get("type_id") != SCRIPTFILE_TYPE_ID:
            continue
        row, payload = validate_operation(operation_cache, current_path, identity)
        if row.get("type") != "scriptfile" or row.get("zone_id") != zone_id or row.get("operation") not in ("append", "remove"):
            raise ValueError("ScriptFile operation has an unsupported type, zone, or mutation")
        _safe_name(row.get("name"))
        if _native_scriptfile_name(row["name"]) != row["name"]:
            raise ValueError("ScriptFile operation name is not in canonical native path form")
        if (row.get("source_body_sha256") != body.source_sha256 or
                row.get("content_sha256") != _sha(row["content"].encode("utf-8"))):
            raise ValueError("ScriptFile operation source text or body hash is stale")
        receipt = row["compiler_receipt"]
        if row["operation"] == "append":
            if (receipt.get("asset_name") != row["name"] or
                    receipt.get("source", {}).get("sha256") != row["content_sha256"] or
                    receipt.get("result", {}).get("native_payload_sha256") != row["payload_sha256"]):
                raise ValueError("ScriptFile compiler receipt differs from the staged source or payload")
            replay_path, compiler_path = _scriptfile_field_executables(workspace)
            cursor_policy = _validate_inline_script_strings(payload,
                replay_executable=replay_path, compiler_executable=compiler_path)
            if receipt.get("string_ownership") != cursor_policy:
                raise ValueError("ScriptFile compiler receipt lost its canonical string ownership proof")
            stale = workspace._compiler_identity_staleness(row, SCRIPTFILE_TYPE_ID)
            if stale:
                raise ValueError(stale)
            if any(native.get("type_id") == SCRIPTFILE_TYPE_ID and native.get("name") == row["name"]
                   for native in native_rows):
                raise ValueError("ScriptFile name already exists in the native source zone")
        else:
            index = row.get("index")
            if (type(index) is not int or not 0 <= index < len(native_rows) or
                    body.assets[index].type_id != SCRIPTFILE_TYPE_ID or
                    native_rows[index].get("name") != row["name"] or
                    row.get("asset_id") != f"{zone_id}:{index}" or
                    receipt.get("schema") != "replay120-gsc-existing-payload-remove-receipt-v1" or
                    receipt.get("status") != "gsc-existing-payload-preserved-pass" or
                    receipt.get("asset_name") != row["name"] or
                    receipt.get("source_body_sha256") != body.source_sha256 or
                    receipt.get("source_index") != index or
                    receipt.get("source_fastfile_sha256") != identity.get("source_fastfile_sha256") or
                    receipt.get("patch_sha256s") != identity.get("patch_sha256s") or
                    receipt.get("native_manifest_sha256") != identity.get("native_manifest_sha256") or
                    receipt.get("stream_trace_sha256") != identity.get("stream_trace_sha256") or
                    receipt.get("native_payload_sha256") != row["payload_sha256"]):
                raise ValueError("ScriptFile removal receipt or source-row identity is stale")
            if index != len(body.assets) - 1:
                raise ValueError("ScriptFile removal currently requires the exact final XAsset row")
            from workstation_fastfiles import _native_walk_artifact
            from workstation_trace_index import build_read_span_index
            trace_path = _native_walk_artifact(_walk, "stream_trace_relative_path")
            manifest_path = _native_walk_artifact(_walk, "manifest_relative_path")
            indexed = build_read_span_index(trace_path, manifest_path, len(body.data), selected_assets={index})
            trace_row = next((item for item in indexed["assets"] if item.get("index") == index), None)
            if trace_row is None:
                raise ValueError("ScriptFile removal row is absent from the current native trace")
            trace_row.update(xasset_index=index, name=row["name"])
            _, current_payload = _scriptfile_payload(body.data, trace_row, index, row["name"])
            if _sha(current_payload) != row["payload_sha256"]:
                raise ValueError("ScriptFile removal payload no longer matches its staged native row")
        row["pending_path"] = str(current_path)
        row["_payload"] = payload
        results.append(row)
    names = [(row["operation"], row["name"]) for row in results]
    if len(names) != len(set(names)) or sum(row["operation"] == "remove" for row in results) > 1:
        raise ValueError("duplicate ScriptFile operations or multiple removals are unsupported")
    return results


def remove_scriptfile_asset(workspace, asset_id: str, revision: str, *, _snapshot=None) -> dict:
    """Stage removal of one current final-row ScriptFile, preserving its GSCBIN."""
    from workstation_asset_operations import stage_operation
    from workstation_fastfiles import _native_walk_artifact
    from workstation_trace_index import build_read_span_index
    from workstation_fastfiles import sha256_file
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        zone_id = asset_id.rsplit(":", 1)[0]
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    opened = workspace.get_asset(asset_id)
    if (opened.get("type_id") != SCRIPTFILE_TYPE_ID or opened.get("type") != "scriptfile" or
            opened.get("revision") != revision or opened.get("pending_path")):
        raise ValueError("ScriptFile removal requires the current unstaged ScriptFile revision")
    zone_id = opened["zone_id"]
    (_cache, operation_cache, _decode_receipt, body, _body_path, _source, profile, walk,
     native_rows, identity, _codec) = _workspace_inputs(workspace, zone_id, _snapshot=_snapshot)
    index = opened.get("index")
    if (type(index) is not int or not 0 <= index < len(body.assets) or
            body.assets[index].type_id != SCRIPTFILE_TYPE_ID or
            native_rows[index].get("name") != opened["name"]):
        raise ValueError("selected ScriptFile no longer resolves to its exact typed source row")
    if index != len(body.assets) - 1:
        raise ValueError("ScriptFile removal currently requires the exact final XAsset row")
    if opened["name"] == "$default":
        raise ValueError("the root-only $default ScriptFile sentinel is not removable")
    trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
    indexed = build_read_span_index(trace_path, manifest_path, len(body.data), selected_assets={index})
    trace_row = next((item for item in indexed["assets"] if item.get("index") == index), None)
    if trace_row is None:
        raise ValueError("complete native trace does not contain the selected ScriptFile")
    trace_row.update(xasset_index=index, type_id=SCRIPTFILE_TYPE_ID, name=opened["name"])
    _, payload = _scriptfile_payload(body.data, trace_row, index, opened["name"])
    content = opened.get("content")
    if not isinstance(content, str):
        raise ValueError("ScriptFile removal requires the current readable source identity")
    content_sha = _sha(content.encode("utf-8"))
    payload_sha = _sha(payload)
    receipt = dict(schema="replay120-gsc-existing-payload-remove-receipt-v1",
        status="gsc-existing-payload-preserved-pass", asset_name=opened["name"],
        source_body_sha256=body.source_sha256, source_index=index,
        source_fastfile_sha256=profile["sha256"],
        patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
        native_manifest_sha256=sha256_file(manifest_path),
        stream_trace_sha256=sha256_file(trace_path), native_payload_sha256=payload_sha,
        native_payload_bytes=len(payload), preservation="exact existing GSCBIN bytes")
    from workstation_asset_operations import _operation_id
    operation_id = _operation_id("remove", opened["name"], index, SCRIPTFILE_TYPE_ID)
    row = dict(schema=4, operation="remove", operation_id=operation_id,
        asset_id=asset_id, zone_id=zone_id, type_id=SCRIPTFILE_TYPE_ID, type="scriptfile",
        name=opened["name"], index=index, xasset_index=index, content=content,
        language="gsc", source_body_sha256=body.source_sha256, content_sha256=content_sha,
        native_source_identity=identity, compiler_receipt=receipt,
        compiler_receipt_sha256=_sha(json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                                               ensure_ascii=False).encode("utf-8")),
        writer_identity=dict(path=identity["writer_module_path"], sha256=identity["writer_module_sha256"]))
    if _snapshot is not None:
        workspace._assert_asset_snapshot_current(_snapshot)
    # The caller revision pins the opened native asset; it is not a prior
    # staged-operation revision. A remove always creates the first operation
    # for this clean asset (pending assets were rejected above).
    staged = stage_operation(operation_cache, row, payload, None)
    return dict(**staged, status="native-scriptfile-remove-staged", editable=False,
        archive_writable=False, pending_path=str(operation_cache / "pending-edits" /
        operation_id / "current.json"),
        package_status="ScriptFile removal queued for exclusive native trace proof")


def create_scriptfile_asset(workspace, zone_id: str, name: str, content: str,
                            revision: str | None = None, *, _snapshot=None) -> dict:
    from workstation_asset_codecs import compile_scriptfile
    from workstation_fastfiles import DEFAULT_GSC_TOOL, acts_tool_identity, sha256_file
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    name = _native_scriptfile_name(name)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("GSC source must be nonempty text")
    inputs = _workspace_inputs(workspace, zone_id, _snapshot=_snapshot)
    _decode_cache, operation_cache, _receipt, body, _body_path, _source, _profile, _walk, native_rows, identity, codec = inputs
    existing = operations(workspace, zone_id, _snapshot=_snapshot)
    for module_name in ("workstation_localize_crud", "workstation_luafile_crud"):
        module = __import__(module_name, fromlist=["operations"])
        family_rows = module.operations(workspace, zone_id, _snapshot=_snapshot)
        for family_row in family_rows:
            _reject_cross_type_new_identity(zone_id, name, [family_row])
    if any(row.get("type_id") == SCRIPTFILE_TYPE_ID and row.get("name") == name for row in native_rows):
        raise ValueError("ScriptFile name already exists in the source zone")
    matches = [row for row in existing if row.get("name") == name]
    if matches:
        if len(matches) != 1 or revision is None or matches[0].get("revision") != revision:
            raise ValueError("ScriptFile revision conflict; reload before saving")
    elif revision is not None:
        raise ValueError("staged ScriptFile append no longer exists; reload before saving")
    tool = Path(DEFAULT_GSC_TOOL).resolve(strict=True)
    tool_sha, codec_path = sha256_file(tool), Path(codec.__file__).resolve(strict=True)
    codec_sha = sha256_file(codec_path)
    compiler_input_name = "script_" + _sha(name.encode("utf-8"))[:20]
    payload = compile_scriptfile(content, tool=tool, asset_name=compiler_input_name)
    replay_path = Path(workspace.replay_executable).resolve(strict=True)
    replay_sha = sha256_file(replay_path)
    string_ownership = _validate_inline_script_strings(payload,
        replay_executable=replay_path, compiler_executable=tool)
    from workstation_fastfiles import acts_tool_identity
    compiler = dict(path=str(tool), sha256=tool_sha, tool_identity=acts_tool_identity(tool),
        input_name=compiler_input_name,
        codec_module_path=str(codec_path), codec_module_sha256=codec_sha)
    if (sha256_file(tool) != tool_sha or sha256_file(codec_path) != codec_sha or
            sha256_file(replay_path) != replay_sha or
            acts_tool_identity(tool) != compiler["tool_identity"]):
        raise RuntimeError("Replay executable, GSC compiler, or codec changed during ScriptFile compilation")
    payload_digest = _sha(payload)
    compiler_receipt = dict(schema="replay120-gsc-compile-receipt-v1",
        status="gsc-tool-native-payload-pass", asset_name=name,
        source=dict(sha256=_sha(content.encode("utf-8")), utf8_bytes=len(content.encode("utf-8"))),
        compiler=compiler,
        result=dict(native_payload_sha256=payload_digest, native_payload_bytes=len(payload),
                    payload_contract="Replay ScriptFile GSCBIN after Replay local-reference scaling"),
        string_ownership=string_ownership)
    receipt_hash = _sha(__import__("json").dumps(compiler_receipt, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    row = dict(schema=4, operation="append", operation_id=_operation_id(name),
        asset_id=zone_id + ":new-" + _sha(name.encode("utf-8"))[:32], zone_id=zone_id,
        type_id=SCRIPTFILE_TYPE_ID, type="scriptfile", name=name, index=None,
        xasset_index=None, content=content, language="gsc", source_body_sha256=body.source_sha256,
        content_sha256=_sha(content.encode("utf-8")), native_source_identity=identity,
        compiler_receipt=compiler_receipt, compiler_receipt_sha256=receipt_hash,
        writer_identity=dict(path=identity["writer_module_path"], sha256=identity["writer_module_sha256"]))
    from workstation_asset_operations import stage_operation
    if _snapshot is not None:
        workspace._assert_asset_snapshot_current(_snapshot)
    staged = stage_operation(operation_cache, row, payload, revision)
    return dict(**staged, status="native-scriptfile-append-staged", editable=True,
        archive_writable=False, pending_path=str(operation_cache / "pending-edits" /
        staged["operation_id"] / "current.json"),
        package_status="ScriptFile append queued for a complete native reread")


def get_new_scriptfile_asset(workspace, asset_id: str, *, _snapshot=None) -> dict:
    zone_id, marker = asset_id.rsplit(":", 1)
    if not re.fullmatch(r"new-[0-9a-f]{32}", marker):
        raise ValueError("Malformed staged ScriptFile identity")
    rows = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
            if row.get("asset_id") == asset_id]
    if len(rows) != 1:
        raise KeyError(asset_id)
    row = rows[0]
    return dict(**{key: value for key, value in row.items() if not key.startswith("_")},
        editable=True, archive_writable=False, payload_format="Replay 1.20 GSCBIN",
        package_status="ScriptFile append queued for a complete native reread")


def plan_scriptfile_crud(workspace, zone_id: str, pending_rows: list[dict], *, _snapshot=None) -> dict:
    if not pending_rows or any(row.get("type") != "scriptfile" or row.get("operation") not in ("append", "remove")
                               for row in pending_rows):
        raise ValueError("ScriptFile operation route supports one append or one removal")
    if len(pending_rows) != 1:
        raise ValueError("ScriptFile transaction currently supports one operation at a time")
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    current = {row["operation_id"]: row for row in
               operations(workspace, zone_id, _snapshot=_snapshot)}
    requested = [row.get("operation_id") for row in pending_rows]
    if len(requested) != len(set(requested)) or set(requested) != set(current):
        raise ValueError("ScriptFile preflight must include every active operation exactly once")
    for row in pending_rows:
        active = current.get(row.get("operation_id"))
        if not active or active.get("revision") != row.get("revision"):
            raise ValueError("ScriptFile operation changed during preflight")
    (_cache, _ops, _receipt, body, _body_path, _source, profile, walk,
     native_rows, identity, _codec) = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    operations_by_id = {row["operation_id"]: row for row in current.values()}
    if len(current) != 1:
        raise ValueError("ScriptFile transaction supports one row operation at a time")
    operation = next(iter(current.values()))["operation"]
    if operation == "append" and not any(row.get("type_id") == SCRIPTFILE_TYPE_ID and row.get("status") != "reference"
                                          for row in native_rows):
        raise ValueError("ScriptFile append requires one retained inline ScriptFile root template")
    removal_proof = None
    if operation == "remove":
        row = next(iter(current.values()))
        from workstation_fastfiles import _native_walk_artifact
        from workstation_trace_index import build_read_span_index
        trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
        manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
        journal_path = _native_walk_artifact(walk, "journal_relative_path")
        from workstation_luafile_crud import _bind_native_manifest_to_trace
        index = row["index"]
        # ACTS stores the native manifest and trace as separate artifacts. The
        # removal contract requires an explicit digest binding, just like the
        # final writer, so create a short-lived derived manifest for preflight.
        with tempfile.TemporaryDirectory(prefix="replay-scriptfile-plan-") as temp_dir:
            bound_manifest = Path(temp_dir) / "manifest.trace-bound.json"
            _bind_native_manifest_to_trace(manifest_path, trace_path, len(body.data),
                                           bound_manifest, journal_path=journal_path)
            indexed = build_read_span_index(trace_path, bound_manifest, len(body.data),
                                            selected_assets={index})
            trace_row = next((item for item in indexed["assets"]
                              if item.get("index") == index), None)
            if trace_row is None:
                raise ValueError("complete native trace omits the ScriptFile removal target")
            trace_row.update(xasset_index=index, name=row["name"])
            candidate, removal_proof = remove_existing_scriptfile_row(body.data, index, row["name"],
                trace_row, body.source_sha256, trace_path, bound_manifest)
        if ZoneBody.parse(candidate).source_sha256 != removal_proof["output_body_sha256"]:
            raise AssertionError("ScriptFile removal preflight body receipt is inconsistent")
    planned = [dict(operation=row["operation"], operation_id=row["operation_id"],
            asset_id=row["asset_id"], revision=row["revision"], type="scriptfile", type_id=52,
            name=row["name"], index=row.get("index")) for row in current.values()]
    delta = -1 if operation == "remove" else 1
    return dict(source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
        native_source_identity=identity, native_walk_key=walk["walk_key"],
        original_xasset_count=len(body.assets), final_xasset_count=len(body.assets) + delta,
        operation_count=len(current), edits=planned,
        support="scriptfile-inline-row-append-native-transaction" if operation == "append"
                else "scriptfile-exclusive-final-row-removal-native-transaction",
        schedule="append one compiler-bound inline root, then complete native reread" if operation == "append"
                 else "remove one exclusive final typed row and stream-6 extent, then complete native reread",
        limits="One append or one removal; GSC is inline-only or uses only the pinned class-0 opcode 0x18 field subset; no general canonical-token or VM-execution claim" if operation == "append"
               else "One final inline ScriptFile row only; root/name/stream-6 bytes must be exclusive with no inbound references; rename and execution are not claimed",
        removal_writer_proof=removal_proof)


def _events_by_owner(trace_path: Path) -> dict[int | None, list[dict]]:
    from collections import defaultdict
    grouped = defaultdict(list)
    with trace_path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("kind") not in ("packed_alias", "packed_resolve"):
                continue
            field = event.get("field_stream_location")
            raw = event.get("raw_token")
            if not isinstance(field, dict) or type(raw) is not int:
                raise ValueError("native packed callback omitted its field coordinate or raw token")
            grouped[event.get("xasset_index")].append(dict(kind=event["kind"], raw=raw,
                field=field, target=event.get("resolved_target_stream_location"),
                sequence=event.get("sequence")))
    return grouped


def _infer_target(row: dict, bases: dict) -> tuple[int, int]:
    raw, owner = row["raw"], row.get("owner")
    tag, low = raw >> 32, raw & 0xFFFFFFFF
    if not low:
        raise ValueError("native packed pointer has a zero lowword")
    if tag == 5:
        return 5, low - 1
    if tag == 0x15 and type(owner) is int and owner in bases:
        return 5, bases[owner] + low - 1
    raise ValueError(f"native packed pointer tag {tag:#x} is outside the proven append remap")


def _mapped_callback_target(targets: dict, owner: int | None, event: dict,
                            source_body: bytes, source_intervals: list[dict],
                            interval_index: dict) -> int:
    """Resolve the target of the physical field live at this callback."""
    from workstation_luafile_operations import _alias_field_archive
    field = event["field"]
    sequence = event.get("sequence")
    if type(sequence) is not int:
        raise ValueError("retained packed callback lacks its exact native sequence")
    physical = _alias_field_archive(dict(owner=owner, field=field),
        source_intervals, source_body, interval_index, sequence)
    if struct.unpack_from("<Q", source_body, physical)[0] != event["raw"]:
        raise ValueError("retained callback token differs from its live source field")
    key = (owner, field.get("stream"), field.get("offset"), physical)
    target = targets.get(key, targets.get(key[:3]))
    if type(target) is not int:
        raise ValueError("retained callback lacks a trace-derived physical target map")
    return target


def _verify_retained_aliases(source_body: bytes, source_trace: Path, source_manifest: Path,
                             output_trace: Path, output_manifest: Path,
                             candidate_body: bytes) -> dict:
    from workstation_luafile_operations import _build_interval_index, _trace_contract
    source_contract = _trace_contract(source_body, source_trace, source_manifest,
                                      table_row_delta=XASSET_ROW_SIZE)
    _, source_bases, source_intervals, _, _, _, source_count, expected_targets, _, _ = source_contract
    interval_index = _build_interval_index(source_intervals)
    output_contract = _trace_contract(candidate_body, output_trace, output_manifest,
                                      table_row_delta=0)
    _, output_bases, _, _, _, _, output_count, _, _, _ = output_contract
    before_events, after_events = _events_by_owner(source_trace), _events_by_owner(output_trace)
    compared = 0
    for owner in before_events.keys() | after_events.keys():
        before, after = before_events.get(owner, []), after_events.get(owner, [])
        if len(before) != len(after):
            raise ValueError(f"retained owner {owner} changed its packed callback count")
        for ordinal, (old, new) in enumerate(zip(before, after)):
            compared += 1
            if old["kind"] != new["kind"]:
                raise ValueError(f"retained owner {owner} callback {ordinal} changed kind")
            target_offset = _mapped_callback_target(expected_targets, owner, old,
                source_body, source_intervals, interval_index)
            oldtarget = old.get("target")
            if isinstance(oldtarget, dict):
                old_stream = oldtarget.get("stream")
            else:
                old_stream, _ = _infer_target(dict(old, owner=owner), source_bases)
            newtarget = new.get("target")
            if isinstance(newtarget, dict):
                new_stream, new_offset = newtarget.get("stream"), newtarget.get("offset")
            else:
                new_stream, new_offset = _infer_target(dict(new, owner=owner), output_bases)
            if old_stream != 5 or new_stream != 5 or new_offset != target_offset:
                raise ValueError(f"retained owner {owner} callback {ordinal} target changed")
            tag = old["raw"] >> 32
            base = output_bases.get(owner) if type(owner) is int else None
            if tag == 5:
                expected_low = target_offset + 1
            elif tag == 0x15 and type(base) is int:
                expected_low = target_offset - base + 1
            else:
                raise ValueError("retained pointer base cannot be represented after table growth")
            if new["raw"] != (tag << 32) | (expected_low & 0xFFFFFFFF):
                raise ValueError(f"retained owner {owner} callback {ordinal} serialized token changed incorrectly")
    return dict(status="retained-alias-targets-pass", compared=compared,
        source_callbacks=source_count, output_callbacks=output_count,
        comparison="source owner and callback ordinal; expected trace-mapped target; candidate target and encoded token")


def _verify_removed_aliases(source_trace: Path, output_trace: Path,
                            removed_index: int, source_bases: dict,
                            expected_targets: dict, output_bases: dict, *,
                            source_body: bytes, source_intervals: list[dict]) -> dict:
    """Compare every retained callback by shifted owner and callback ordinal."""
    from workstation_luafile_operations import _build_interval_index
    interval_index = _build_interval_index(source_intervals)
    before_events, after_events = _events_by_owner(source_trace), _events_by_owner(output_trace)
    compared = 0
    for old_owner in before_events.keys() | {None}:
        if old_owner == removed_index:
            continue
        new_owner = (old_owner - 1 if type(old_owner) is int and old_owner > removed_index
                     else old_owner)
        before = before_events.get(old_owner, [])
        after = after_events.get(new_owner, [])
        if len(before) != len(after):
            raise ValueError(f"retained ScriptFile removal owner {old_owner} changed packed callback count")
        for ordinal, (old, new) in enumerate(zip(before, after)):
            compared += 1
            if old["kind"] != new["kind"] or old["raw"] >> 32 != new["raw"] >> 32:
                raise ValueError(f"retained owner {old_owner} callback {ordinal} changed pointer class")
            target_offset = _mapped_callback_target(expected_targets, old_owner, old,
                source_body, source_intervals, interval_index)
            old_target = old.get("target")
            if isinstance(old_target, dict):
                old_stream = old_target.get("stream")
            else:
                old_stream, _ = _infer_target(dict(old, owner=old_owner), source_bases)
            new_target = new.get("target")
            if isinstance(new_target, dict):
                new_stream, new_offset = new_target.get("stream"), new_target.get("offset")
            else:
                new_stream, new_offset = _infer_target(dict(new, owner=new_owner), output_bases)
            if old_stream != 5 or new_stream != 5 or new_offset != target_offset:
                raise ValueError(f"retained owner {old_owner} callback {ordinal} target moved incorrectly")
            tag = old["raw"] >> 32
            base = output_bases.get(new_owner) if type(new_owner) is int else None
            if tag == 5:
                expected_low = target_offset + 1
            elif tag == 0x15 and type(base) is int:
                expected_low = target_offset - base + 1
            else:
                raise ValueError("retained ScriptFile alias cannot be represented after row removal")
            if new["raw"] != (tag << 32) | (expected_low & 0xFFFFFFFF):
                raise ValueError(f"retained owner {old_owner} callback {ordinal} token is not rebased")
    return dict(status="retained-alias-targets-pass", compared=compared,
        source_callbacks=sum(map(len, before_events.values())),
        output_callbacks=sum(map(len, after_events.values())),
        comparison="source owner mapped around removed row; every callback ordinal compared by trace target and encoded token")


def _zero_root_sentinel(body: bytes, row: dict, index: int) -> dict:
    """Validate the exact native $default root-only row shape; never swallow arbitrary failures."""
    if (row.get("xasset_index") != index or row.get("type_id") != SCRIPTFILE_TYPE_ID or
            row.get("name") != "$default"):
        raise ValueError("ScriptFile zero-root sentinel identity differs from its typed row")
    spans = row.get("read_spans")
    if (not isinstance(spans, list) or len(spans) != 1 or
            spans[0].get("origin") != "load_stream_call" or
            spans[0].get("reader_start_arg") != 0 or spans[0].get("size") != SCRIPTFILE_ROOT_SIZE or
            row.get("root_stream_location") != {"stream": 1, "offset": 0} or
            row.get("packed_pointer_events") != [] or
            row.get("physical_load_count_by_stream") != {1: 1} or
            row.get("physical_load_bytes_by_stream") != {1: SCRIPTFILE_ROOT_SIZE}):
        raise ValueError("$default ScriptFile does not have the exact root-only 40-byte read")
    offset = spans[0].get("archive_offset")
    if type(offset) is not int or offset < 0 or offset + SCRIPTFILE_ROOT_SIZE > len(body):
        raise ValueError("$default ScriptFile root lies outside the serialized body")
    raw = body[offset:offset + SCRIPTFILE_ROOT_SIZE]
    name_token, compressed_len, source_len, bytecode_len, reserved, compressed_token, bytecode_token = \
        struct.unpack("<QiiiIQQ", raw)
    if (name_token >> 32 != 5 or (name_token & 0xffffffff) == 0 or compressed_len != 0 or
            source_len != 0 or bytecode_len != 0 or reserved != 0 or
            compressed_token != 0 or bytecode_token != 0):
        raise ValueError("$default ScriptFile root differs from the validated root-only sentinel layout")
    return dict(status="zero-root-sentinel", root_bytes=SCRIPTFILE_ROOT_SIZE,
        root_sha256=_sha(raw), root_bytes_hex=raw.hex(), packed_name_token=f"0x{name_token:016x}",
        root_stream_location=dict(row["root_stream_location"]), root_archive_offset=offset)


def _compare_zero_root_sentinels(source_report: dict, output_report: dict,
                                 relocated_targets: dict | None = None,
                                 *, removed_index: int | None = None,
                                 fallback_target_delta: int = XASSET_ROW_SIZE) -> dict:
    source = [row for row in source_report["rows"] if row.get("status") == "zero-root-sentinel"]
    output = [row for row in output_report["rows"] if row.get("status") == "zero-root-sentinel"]
    if len(source) != len(output):
        raise ValueError("native readback changed the number of validated $default sentinels")
    output_by_identity = {(row.get("type_id"), row.get("name")): row for row in output}
    if len(output_by_identity) != len(output):
        raise ValueError("native readback has duplicate $default sentinel identities")
    for before in source:
        after = output_by_identity.get((before.get("type_id"), before.get("name")))
        if after is None:
            raise ValueError("native readback lost a typed $default sentinel")
        source_raw = bytes.fromhex(before["root_bytes_hex"])
        output_raw = bytes.fromhex(after["root_bytes_hex"])
        source_token = int(before["packed_name_token"], 16)
        output_token = int(after["packed_name_token"], 16)
        old_index = before.get("index")
        expected_index = old_index - int(removed_index is not None and old_index > removed_index)
        root_location = before.get("root_stream_location")
        if (not isinstance(root_location, dict) or root_location.get("stream") != 1 or
                type(root_location.get("offset")) is not int):
            raise ValueError("source $default sentinel lacks a typed root field location")
        key = (old_index, 1, root_location["offset"])
        physical = before.get("root_archive_offset")
        mapped = (relocated_targets or {}).get((*key, physical),
            (relocated_targets or {}).get(key))
        if relocated_targets and type(mapped) is not int:
            raise ValueError("source $default sentinel lacks its physical name target mapping")
        expected_target = (mapped if type(mapped) is int else
                           (source_token & 0xffffffff) - 1 + fallback_target_delta)
        if (after.get("index") != expected_index or before.get("name") != after.get("name") or
                source_token >> 32 != output_token >> 32 or
                source_token >> 32 != 5 or (output_token & 0xffffffff) - 1 != expected_target or
                source_raw[8:] != output_raw[8:]):
            raise ValueError("native readback changed $default sentinel layout or mapped name target")
    return dict(status="zero-root-sentinels-pass", compared=len(source),
        invariant="same typed 40-byte root payload; name pointer follows native trace relocation mapping")


def _build_scriptfile_remove_transaction(workspace, zone_id: str, plan: dict,
                                         output: Path, work: Path, timeout: int,
                                         *, context: tuple) -> dict:
    from roundtrip_replay_fastfile import verify_native
    from workstation_fastfiles import (_native_walk_artifact, pack_replay_uncompressed,
        make_replay_header_only_patch, sha256_file, unpack_replay_uncompressed,
        ordered_asset_identity_sha256, source_profile)
    from workstation_luafile_crud import _bind_native_manifest_to_trace, _rows
    from workstation_luafile_operations import _trace_contract
    from workstation_trace_index import build_read_span_index
    (cache, _operation_cache_path, _decode_receipt, body, body_path, source, profile, walk,
     _native_rows, _identity, _codec) = context
    current_rows = operations(workspace, zone_id)
    if len(current_rows) != 1 or current_rows[0].get("operation") != "remove":
        raise ValueError("ScriptFile removal transaction requires exactly one active removal")
    staged = current_rows[0]
    _validate_active_removal_plan(plan, staged, body.source_sha256)
    index = staged["index"]
    trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
    raw_manifest = _native_walk_artifact(walk, "manifest_relative_path")
    journal_path = _native_walk_artifact(walk, "journal_relative_path")
    bound_source = work / "source-manifest.transaction-bound.json"
    _bind_native_manifest_to_trace(raw_manifest, trace_path, len(body.data), bound_source,
                                   journal_path=journal_path)
    source_rows = _rows(journal_path)
    indexed = build_read_span_index(trace_path, bound_source, len(body.data), selected_assets={index})
    trace_row = next((row for row in indexed["assets"] if row.get("index") == index), None)
    if trace_row is None:
        raise ValueError("full source trace omits the staged ScriptFile removal row")
    trace_row.update(xasset_index=index, name=staged["name"])
    body_bytes = body.data
    from workstation_fastfiles import acts_tool_identity
    helper_modules = {
        "scriptfile_writer": Path(__file__).resolve(),
        "fastfile_dispatcher": Path(__import__("workstation_fastfiles").__file__).resolve(),
        "asset_operations": Path(__import__("workstation_asset_operations").__file__).resolve(),
        "native_verifier": Path(__import__("roundtrip_replay_fastfile").__file__).resolve(),
        "native_zone_body": Path(__import__("workstation_native_asset_edits").__file__).resolve(),
        "gsc_codec": Path(__import__("workstation_asset_codecs").__file__).resolve(),
        "manifest_rows": Path(__import__("workstation_luafile_crud").__file__).resolve(),
        "lua_trace_contract": Path(__import__("workstation_luafile_operations").__file__).resolve(),
        "trace_index": Path(__import__("workstation_trace_index").__file__).resolve(),
        "typed_semantics": Path(__import__("workstation_asset_semantics").__file__).resolve(),
    }
    reader_path = Path(workspace.acts_path).resolve(strict=True)
    replay_path = Path(workspace.replay_executable).resolve(strict=True)
    protected = dict(reader=acts_tool_identity(reader_path), replay_sha256=sha256_file(replay_path),
        helper_sources={key: sha256_file(path) for key, path in helper_modules.items()})
    before = dict(body=body.source_sha256, source_ff=sha256_file(source), protected=protected,
        patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
        trace=sha256_file(trace_path), manifest=sha256_file(raw_manifest),
        journal=sha256_file(journal_path), writer=sha256_file(Path(__file__).resolve()),
        dispatcher=sha256_file(Path(__import__("workstation_fastfiles").__file__).resolve()))
    contract_map = {}
    candidate_body, writer_proof = remove_existing_scriptfile_row(
        body_bytes, index, staged["name"], trace_row, body.source_sha256,
        trace_path, bound_source, _contract_out=contract_map)
    sizes = list(profile["final_header"]["block_sizes"])
    # Keep the source reservations as conservative capacities. The append-only
    # writer's extra padding does not prove the native reservation attributable
    # to an arbitrary existing row.
    if len(sizes) <= 6:
        raise ValueError("source native header lacks stream-5/stream-6 reservations")
    package = pack_replay_uncompressed(candidate_body, sizes,
        xfile_version=profile["final_header"]["xfile_version"],
        transient_type=profile["header"]["transient_type"])
    if unpack_replay_uncompressed(package) != candidate_body:
        raise ValueError("ScriptFile removal package does not decode to the exact writer body")
    fp_template = Path(profile["patches"][0]["path"]).read_bytes()
    patch = make_replay_header_only_patch(fp_template, package)
    candidate_ff, candidate_fp = work / output.name, work / output.with_suffix(".fp").name
    candidate_ff.write_bytes(package)
    candidate_fp.write_bytes(patch)
    native = verify_native(candidate_ff, candidate_body, source, workspace.acts_path,
        workspace.replay_executable, work / "native-reader", timeout, trace=True)
    manifest = native["manifest"]
    parsed = ZoneBody.parse(candidate_body)
    refs = native.get("reference_only_rows", [])
    tested, top = manifest.get("tested"), manifest.get("top_level_index")
    if (manifest.get("complete") is not True or manifest.get("success") is not True or
            type(tested) is not int or type(top) is not int or tested + len(refs) != top or
            top != len(parsed.assets) or manifest.get("failed") != 0 or
            manifest.get("unavailable") != 0 or manifest.get("serialized_bytes_read") != len(candidate_body)):
        raise ValueError("native reader did not consume ScriptFile removal candidate through exact EOF")
    out_manifest = Path(native["manifest_path"]).resolve(strict=True)
    out_trace = out_manifest.parent / manifest.get("stream_trace", "stream-trace.jsonl")
    out_journal = out_manifest.parent / manifest.get("journal", "assets.jsonl")
    bound_output = work / "output-manifest.transaction-bound.json"
    _bind_native_manifest_to_trace(out_manifest, out_trace, len(candidate_body), bound_output,
                                   journal_path=out_journal)
    output_rows = _rows(out_journal)
    expected_rows = source_rows[:index] + source_rows[index + 1:]
    identity_rows = lambda rows: [(row.get("type_id"), row.get("name")) for row in rows]
    if identity_rows(output_rows) != identity_rows(expected_rows):
        raise ValueError("native ScriptFile removal changed retained typed identity or order")
    source_payloads, source_report = _payload_inventory(body_bytes, source_rows, trace_path, bound_source)
    output_payloads, output_report = _payload_inventory(candidate_body, output_rows, out_trace, bound_output)
    expected_payloads = dict(source_payloads)
    if expected_payloads.pop(staged["name"], None) != staged["payload_sha256"] or output_payloads != expected_payloads:
        raise ValueError("native ScriptFile removal changed or retained the removed GSCBIN payload")
    from workstation_asset_semantics import typed_semantics
    source_semantics, _source_semantic_index, _source_semantic_rows = typed_semantics(
        body_bytes, source_rows, trace_path, bound_source)
    output_semantics, _output_semantic_index, _output_semantic_rows = typed_semantics(
        candidate_body, output_rows, out_trace, bound_output)
    if output_semantics != source_semantics:
        raise ValueError("native ScriptFile removal changed a retained image, Localize or LuaFile semantic payload")
    sentinel_proof = _compare_zero_root_sentinels(source_report, output_report,
        contract_map["relocated_targets"], removed_index=index, fallback_target_delta=0)
    output_contract = _trace_contract(candidate_body, out_trace, bound_output)
    alias_proof = _verify_removed_aliases(trace_path, out_trace, index,
        contract_map["asset_bases"], contract_map["relocated_targets"], output_contract[1],
        source_body=body_bytes, source_intervals=contract_map["intervals"])
    after = dict(body=sha256_file(body_path), source_ff=sha256_file(source), protected=dict(
        reader=acts_tool_identity(Path(workspace.acts_path).resolve(strict=True)),
        replay_sha256=sha256_file(Path(workspace.replay_executable).resolve(strict=True)),
        helper_sources={key: sha256_file(path) for key, path in helper_modules.items()}),
        patch_sha256s=[row["sha256"] for row in source_profile(source).get("patches", [])],
        trace=sha256_file(trace_path), manifest=sha256_file(raw_manifest),
        journal=sha256_file(journal_path), writer=sha256_file(Path(__file__).resolve()),
        dispatcher=sha256_file(Path(__import__("workstation_fastfiles").__file__).resolve()))
    _assert_helper_sources_unchanged(before["protected"]["helper_sources"],
        after["protected"]["helper_sources"])
    active = operations(workspace, zone_id)
    if before != after or len(active) != 1 or active[0].get("revision") != staged["revision"]:
        raise ValueError("ScriptFile removal source, trace, writer or staged revision drifted before publication")
    final_fp = output.with_suffix(".fp")
    temp_ff, temp_fp = work / (output.name + ".verified.tmp"), work / (final_fp.name + ".verified.tmp")
    temp_ff.write_bytes(package)
    temp_fp.write_bytes(patch)
    if sha256_file(temp_ff) != _sha(package) or sha256_file(temp_fp) != _sha(patch):
        raise ValueError("verified ScriptFile removal package changed before publication")
    published = []
    try:
        temp_ff.replace(output)
        published.append(output)
        temp_fp.replace(final_fp)
        published.append(final_fp)
    except BaseException:
        for path in reversed(published):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return dict(status="scriptfile-remove-native-transaction-pass", zone_id=zone_id,
        support="scriptfile-exclusive-final-row-removal-native-transaction",
        output_fastfile=str(output), output_fastfile_sha256=sha256_file(output),
        sidecars=[dict(path=str(final_fp), sha256=sha256_file(final_fp))],
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(candidate_body),
        removed_name=staged["name"], removed_index=index,
        native_reader_tested=tested, native_reader_reference_rows=len(refs),
        native_reader_eof_bytes=manifest["serialized_bytes_read"],
        retained_identity_sha256=ordered_asset_identity_sha256(output_rows),
        retained_scriptfile_payload_count=len(output_payloads),
        retained_scriptfile_payloads_exact=True,
        retained_asset_semantic_families_exact=["ScriptFile GSCBIN", "image", "Localize", "LuaFile"],
        retained_asset_semantic_payload_count=len(output_payloads) + len(output_semantics),
        zero_root_sentinels=sentinel_proof,
        retained_alias_verification=alias_proof, writer_proof=writer_proof,
        native_manifest_sha256=sha256_file(out_manifest), native_trace_sha256=sha256_file(out_trace))


def _payload_inventory(body: bytes, rows: list[dict], trace_path: Path,
                       manifest_path: Path) -> tuple[dict[str, str], dict]:
    from workstation_trace_index import build_read_span_index
    selected = {index for index, row in enumerate(rows) if row.get("type_id") == SCRIPTFILE_TYPE_ID}
    spans = build_read_span_index(trace_path, manifest_path, len(body), selected_assets=selected)["assets"]
    by_index = {row["index"]: row for row in spans}
    if set(by_index) != selected:
        raise ValueError("native trace omitted a retained or appended ScriptFile root")
    payloads = {}
    statuses = []
    for index in sorted(selected):
        row = rows[index]
        trace_row = dict(by_index[index], xasset_index=index,
                         type_id=SCRIPTFILE_TYPE_ID, name=row.get("name"))
        if row.get("name") == "$default":
            sentinel = _zero_root_sentinel(body, trace_row, index)
            statuses.append(dict(index=index, name="$default", **sentinel))
            continue
        _root, payload = _scriptfile_payload(body, trace_row, index, row.get("name"))
        if row["name"] in payloads:
            raise ValueError("duplicate native ScriptFile names prevent typed payload comparison")
        payloads[row["name"]] = _sha(payload)
        statuses.append(dict(index=index, name=row["name"], status="payload-pass",
                             payload_sha256=_sha(payload)))
    return payloads, dict(rows=statuses, trace_index_count=len(by_index))


def build_workspace_scriptfile_crud(workspace, zone_id: str, plan: dict,
                                    output: Path, timeout: int) -> dict:
    from workstation_fastfiles import (DEFAULT_GSC_TOOL, _native_walk_artifact, pack_replay_uncompressed,
        make_replay_header_only_patch, sha256_file, acts_tool_identity, unpack_replay_uncompressed,
        source_profile)
    from roundtrip_replay_fastfile import verify_native
    from workstation_luafile_crud import _bind_native_manifest_to_trace
    from workstation_trace_index import build_read_span_index
    (cache, operation_cache, decode_receipt, body, body_path, source, profile, walk,
     native_rows, identity, codec) = _workspace_inputs(workspace, zone_id)
    active_rows = operations(workspace, zone_id)
    requested = {row["operation_id"]: row for row in plan.get("edits", [])}
    if len(active_rows) != 1 or set(requested) != {row["operation_id"] for row in active_rows} or any(
            requested[row["operation_id"]].get("revision") != row.get("revision") for row in active_rows):
        raise ValueError("ScriptFile operation set changed after preflight")
    staged = active_rows[0]
    output = Path(output).resolve()
    if output.suffix.casefold() != ".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("replacement FF output must be an .ff outside the game directory")
    final_fp = output.with_suffix(".fp")
    if output.exists() or final_fp.exists() or output.with_suffix(".fc").exists():
        raise FileExistsError("ScriptFile output or sidecar already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    work = output.parent / (output.stem + ".scriptfile-work")
    if work.exists():
        raise FileExistsError("ScriptFile transaction work directory already exists")
    work.mkdir()
    if staged.get("operation") == "remove":
        return _build_scriptfile_remove_transaction(
            workspace, zone_id, plan, output, work, timeout,
            context=(cache, operation_cache, decode_receipt, body, body_path,
                     source, profile, walk, native_rows, identity, codec))
    payload = staged["_payload"]
    replay_executable = Path(workspace.replay_executable).resolve(strict=True)
    compiler_executable = Path(DEFAULT_GSC_TOOL).resolve(strict=True)
    validated_ownership = _validate_inline_script_strings(payload,
        replay_executable=replay_executable, compiler_executable=compiler_executable)
    if staged["compiler_receipt"].get("string_ownership") != validated_ownership:
        raise ValueError("staged ScriptFile ownership proof no longer matches its configured tools")
    source_trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    source_manifest = _native_walk_artifact(walk, "manifest_relative_path")
    source_journal = _native_walk_artifact(walk, "journal_relative_path")
    bound_source_manifest = work / "source-manifest.transaction-bound.json"
    from workstation_luafile_crud import _bind_native_manifest_to_trace, _rows
    _bind_native_manifest_to_trace(source_manifest, source_trace, len(body_path.read_bytes()),
        bound_source_manifest, journal_path=source_journal)
    import workstation_gsc_fields as field_policy
    field_policy_module = Path(field_policy.__file__).resolve(strict=True)
    field_contract_file = Path(field_policy.CONTRACT_PATH).resolve(strict=True)
    source_rows = _rows(source_journal)
    script_rows = [(index, row) for index, row in enumerate(source_rows)
                   if row.get("type_id") == SCRIPTFILE_TYPE_ID and row.get("status") != "reference"]
    if not script_rows:
        raise ValueError("ScriptFile append has no inline source template")
    template_index, template_row = next(((i, row) for i, row in script_rows
                                         if row.get("name") != "$default"), (None, None))
    if template_row is None:
        raise ValueError("ScriptFile append has no non-sentinel inline source template")
    final_index = len(source_rows) - 1
    selected = {template_index, final_index}
    indexed = build_read_span_index(source_trace, bound_source_manifest,
        len(body_path.read_bytes()), selected_assets=selected)["assets"]
    span_by_index = {row["index"]: row for row in indexed}
    if set(span_by_index) != selected:
        raise ValueError("source trace omitted ScriptFile template or exact final-row owner")
    template_trace = dict(xasset_index=template_index, type_id=52, name=template_row["name"],
                          read_spans=span_by_index[template_index]["read_spans"])
    final_row = source_rows[final_index]
    final_trace = dict(xasset_index=final_index, type_id=final_row["type_id"],
        name=final_row.get("name"), end_cursor=span_by_index[final_index].get("end_cursor"),
        read_spans=span_by_index[final_index]["read_spans"])
    body_bytes = body_path.read_bytes()
    before_pins = dict(source_ff=sha256_file(source), body=_sha(body_bytes),
        source_fp=[row["sha256"] for row in profile.get("patches", [])],
        trace=sha256_file(source_trace), manifest=sha256_file(source_manifest),
        tool=acts_tool_identity(workspace.acts_path), codec=sha256_file(Path(codec.__file__)),
        replay_executable_sha256=sha256_file(replay_executable),
        gsc_compiler_sha256=sha256_file(compiler_executable),
        field_policy_module_sha256=sha256_file(field_policy_module),
        field_contract_file_sha256=sha256_file(field_contract_file),
        string_ownership_sha256=_sha(__import__("json").dumps(validated_ownership,
            sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
    candidate_body, writer_proof = append_scriptfile_tail(body_bytes, staged["name"], staged["content"],
        payload, staged["compiler_receipt"], {row.get("name") for row in source_rows
        if isinstance(row.get("name"), str)}, template_index, template_row["name"], template_trace,
        final_trace, body.source_sha256, source_trace, bound_source_manifest,
        replay_executable=replay_executable, compiler_executable=compiler_executable)
    info = inspect_gscbin(payload)
    sizes = list(profile["final_header"]["block_sizes"])
    sizes[5] += XASSET_ROW_SIZE + SCRIPTFILE_ROOT_SIZE + len(staged["name"].encode("utf-8")) + 1 + 64
    sizes[6] += len(info.compressed_source) + len(info.bytecode) + 64
    package = pack_replay_uncompressed(candidate_body, sizes,
        xfile_version=profile["final_header"]["xfile_version"],
        transient_type=profile["header"]["transient_type"])
    fp_template = Path(profile["patches"][0]["path"]).read_bytes()
    patch = make_replay_header_only_patch(fp_template, package)
    if unpack_replay_uncompressed(package) != candidate_body:
        raise ValueError("ScriptFile package does not decode to its serialized writer body")
    candidate_ff = work / output.name
    candidate_fp = work / final_fp.name
    candidate_ff.write_bytes(package)
    candidate_fp.write_bytes(patch)
    native = verify_native(candidate_ff, candidate_body, source, workspace.acts_path,
        workspace.replay_executable, work / "native-reader", timeout, trace=True)
    manifest = native["manifest"]
    candidate_zone = ZoneBody.parse(candidate_body)
    references = native.get("reference_only_rows", [])
    tested, top = manifest.get("tested"), manifest.get("top_level_index")
    if (manifest.get("complete") is not True or manifest.get("success") is not True or
            type(tested) is not int or type(top) is not int or tested + len(references) != top or
            top != len(candidate_zone.assets) or manifest.get("failed") != 0 or
            manifest.get("unavailable") != 0 or manifest.get("serialized_bytes_read") != len(candidate_body)):
        raise ValueError("native reader did not consume the complete ScriptFile candidate through exact EOF")
    out_manifest = Path(native["manifest_path"]).resolve(strict=True)
    out_trace = out_manifest.parent / manifest.get("stream_trace", "stream-trace.jsonl")
    out_journal = out_manifest.parent / manifest.get("journal", "assets.jsonl")
    bound_output_manifest = work / "output-manifest.transaction-bound.json"
    _bind_native_manifest_to_trace(out_manifest, out_trace, len(candidate_body),
        bound_output_manifest, journal_path=out_journal)
    output_rows = _rows(out_journal)
    if (len(output_rows) != len(source_rows) + 1 or [
            (row.get("type_id"), row.get("name")) for row in output_rows[:-1]] != [
            (row.get("type_id"), row.get("name")) for row in source_rows] or
            output_rows[-1].get("type_id") != SCRIPTFILE_TYPE_ID or output_rows[-1].get("name") != staged["name"]):
        raise ValueError("native reader changed a retained XAsset identity or order")
    source_payloads, source_payload_report = _payload_inventory(body_bytes, source_rows,
        source_trace, bound_source_manifest)
    output_payloads, output_payload_report = _payload_inventory(candidate_body, output_rows,
        out_trace, bound_output_manifest)
    expected_payloads = dict(source_payloads, **{staged["name"]: _sha(payload)})
    if output_payloads != expected_payloads:
        raise ValueError("native readback changed a retained or appended GSCBIN payload")
    sentinel_proof = _compare_zero_root_sentinels(source_payload_report, output_payload_report)
    alias_proof = _verify_retained_aliases(body_bytes, source_trace, bound_source_manifest,
        out_trace, bound_output_manifest, candidate_body)
    after_pins = dict(source_ff=sha256_file(source), body=_sha(body_path.read_bytes()),
        source_fp=[row["sha256"] for row in source_profile(source).get("patches", [])],
        trace=sha256_file(source_trace), manifest=sha256_file(source_manifest),
        tool=acts_tool_identity(workspace.acts_path), codec=sha256_file(Path(codec.__file__)),
        replay_executable_sha256=sha256_file(replay_executable),
        gsc_compiler_sha256=sha256_file(compiler_executable),
        field_policy_module_sha256=sha256_file(field_policy_module),
        field_contract_file_sha256=sha256_file(field_contract_file),
        string_ownership_sha256=_sha(__import__("json").dumps(
            _validate_inline_script_strings(staged["_payload"], replay_executable=replay_executable,
                compiler_executable=compiler_executable), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")))
    if before_pins != after_pins or operations(workspace, zone_id)[0]["revision"] != staged["revision"]:
        raise ValueError("ScriptFile source, compiler, trace, or staged operation drifted before publication")
    temp_ff = output.with_name(output.name + ".verified.tmp")
    temp_fp = final_fp.with_name(final_fp.name + ".verified.tmp")
    try:
        temp_ff.write_bytes(package)
        temp_fp.write_bytes(patch)
        if sha256_file(temp_ff) != _sha(package) or sha256_file(temp_fp) != _sha(patch):
            raise ValueError("verified ScriptFile package changed while staging publication")
        temp_ff.replace(output)
        temp_fp.replace(final_fp)
    except BaseException:
        temp_ff.unlink(missing_ok=True)
        temp_fp.unlink(missing_ok=True)
        if output.exists() and not final_fp.exists():
            output.unlink()
        raise
    return dict(status="scriptfile-append-native-transaction-pass", zone_id=zone_id,
        support="scriptfile-inline-row-append-native-transaction", output_fastfile=str(output),
        output_fastfile_sha256=sha256_file(output), sidecars=[dict(path=str(final_fp), sha256=sha256_file(final_fp))],
        source_body_sha256=body.source_sha256, output_body_sha256=_sha(candidate_body),
        appended_name=staged["name"], appended_payload_sha256=_sha(payload),
        native_reader_status=manifest.get("status"), native_reader_tested=tested,
        native_reader_reference_rows=len(references), native_reader_eof_bytes=manifest["serialized_bytes_read"],
        retained_payloads=source_payload_report, output_payloads=output_payload_report,
        zero_root_sentinels=sentinel_proof,
        alias_relocation=writer_proof["alias_relocation"], retained_alias_verification=alias_proof,
        writer_proof=writer_proof, compiler_receipt_sha256=staged["compiler_receipt_sha256"],
        string_ownership=staged["compiler_receipt"]["string_ownership"],
        native_manifest_sha256=sha256_file(out_manifest), native_trace_sha256=sha256_file(out_trace),
        native_journal_sha256=sha256_file(out_journal), publication_pins=after_pins)


def append_scriptfile_tail(body_data: bytes, name: str, source_text: str,
                           payload: bytes, compiler_receipt: dict,
                           existing_names: set[str], template_index: int,
                           template_name: str, template_trace_asset: dict,
                           final_trace_asset: dict, expected_body_sha256: str,
                           trace_path: str | Path, manifest_path: str | Path, *,
                           replay_executable=None, compiler_executable=None) -> tuple[bytes, dict]:
    """Append one compiled inline ScriptFile after a trace-proven exact EOF."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("ScriptFile append trace belongs to a different source body")
    _safe_name(name)
    if name in existing_names:
        raise ValueError("ScriptFile append name already exists in the native XAsset inventory")
    if not body.assets:
        raise ValueError("cannot append a ScriptFile to an empty XAsset table")
    if type(template_index) is not int or not 0 <= template_index < len(body.assets):
        raise ValueError("ScriptFile append template index is outside the native table")
    if body.assets[template_index].type_id != SCRIPTFILE_TYPE_ID:
        raise ValueError("ScriptFile append root template is not a native ScriptFile")
    compiler = _validate_compiler_receipt(name, source_text, payload, compiler_receipt,
        replay_executable=replay_executable, compiler_executable=compiler_executable)
    _scriptfile_payload(body_data, template_trace_asset, template_index, template_name)

    final_index = len(body.assets) - 1
    final_spans = final_trace_asset.get("read_spans")
    if (final_trace_asset.get("xasset_index") != final_index or
            final_trace_asset.get("type_id") != body.assets[-1].type_id or
            final_trace_asset.get("end_cursor") != len(body_data) or
            not isinstance(final_spans, list) or not final_spans or
            max(span.get("archive_offset", -1) + span.get("size", 0)
                for span in final_spans) != len(body_data)):
        raise ValueError("original final XAsset lacks an exact, trace-owned serialized EOF boundary")

    info = inspect_gscbin(payload)
    (manifest, asset_bases, intervals, aliases, table_alloc, max_destinations,
     alias_count, relocated_targets, relocated_asset_bases, xstring_stats) = _trace_contract(
        body_data, trace_path, manifest_path, table_row_delta=XASSET_ROW_SIZE)
    if (table_alloc.get("size") != len(body.assets) * XASSET_ROW_SIZE or
            table_alloc.get("archive", -1) + table_alloc.get("size", 0) != body.first_payload_offset):
        raise ValueError("native XAsset pointer-array allocation does not match the source table boundary")

    table_logical_end = table_alloc["end"]
    table_physical_end = body.first_payload_offset
    rebased, alias_receipt = _rebase_aliases(
        body_data, intervals, aliases, table_logical_end, table_physical_end,
        XASSET_ROW_SIZE, asset_bases, relocated_targets=relocated_targets,
        relocated_asset_bases=relocated_asset_bases)
    row = struct.pack("<IIQ", SCRIPTFILE_TYPE_ID, 0, INLINE_POINTER)
    updated = bytearray(rebased)
    struct.pack_into("<I", updated, XASSET_ARRAY_COUNT_OFFSET, len(body.assets) + 1)
    updated[table_physical_end:table_physical_end] = row
    new_root_at = len(updated)
    root = struct.pack("<QiiiIQQ", SCRIPTFILE_NAME_INLINE, len(info.compressed_source),
                       info.source_size, len(info.bytecode), 0,
                       INLINE_CHILD_POINTER, INLINE_CHILD_POINTER)
    name_bytes = name.encode("utf-8") + b"\0"
    updated.extend(root)
    updated.extend(name_bytes)
    updated.extend(info.compressed_source)
    updated.extend(info.bytecode)
    result = bytes(updated)
    reparsed = ZoneBody.parse(result)
    if (len(reparsed.assets) != len(body.assets) + 1 or
            reparsed.assets[-1].type_id != SCRIPTFILE_TYPE_ID or
            reparsed.assets[:-1] != body.assets):
        raise AssertionError("ScriptFile append did not preserve the ordered source table and add one type-52 row")
    return result, dict(schema="replay120-scriptfile-append-candidate-v1",
        status="trace-owned-scriptfile-append-candidate", operation="append",
        name=name, asset_index=len(body.assets), source_body_sha256=body.source_sha256,
        output_body_sha256=_sha(result), source_asset_count=len(body.assets),
        output_asset_count=len(reparsed.assets), source_final_asset_index=final_index,
        source_final_asset_type_id=body.assets[-1].type_id,
        source_final_asset_end_cursor=final_trace_asset["end_cursor"],
        xasset_table_physical_offset=body.asset_table_offset,
        xasset_table_insert_offset=table_physical_end,
        xasset_row_bytes=XASSET_ROW_SIZE, appended_root_archive_offset=new_root_at,
        appended_root_bytes=len(root), appended_name_bytes=len(name_bytes),
        appended_compressed_source_bytes=len(info.compressed_source),
        appended_bytecode_bytes=len(info.bytecode), compiler=compiler,
        native_manifest_sha256=_sha(Path(manifest_path).read_bytes()),
        stream_trace_sha256=_sha(Path(trace_path).read_bytes()),
        source_stream_max_destinations={str(key): value for key, value in max_destinations.items()},
        source_alias_event_count=alias_count, alias_relocation=alias_receipt,
        xstring_trace_summary=xstring_stats)


def compare_scriptfile_identity_and_payloads(source_rows: list[dict],
        output_rows: list[dict], source_payloads: dict[str, str],
        output_payloads: dict[str, str], appended_name: str,
        appended_payload_sha256: str) -> dict:
    """Require unchanged ordered rows and exact payload hashes for all GSC rows."""
    if len(output_rows) != len(source_rows) + 1:
        raise ValueError("native ScriptFile append did not produce exactly one extra XAsset row")
    expected = [(row.get("type_id"), row.get("name")) for row in source_rows]
    actual = [(row.get("type_id"), row.get("name")) for row in output_rows[:-1]]
    if expected != actual or output_rows[-1].get("type_id") != SCRIPTFILE_TYPE_ID or \
            output_rows[-1].get("name") != appended_name:
        raise ValueError("native ScriptFile append changed a retained XAsset identity or order")
    expected_payloads = dict(source_payloads)
    expected_payloads[appended_name] = appended_payload_sha256
    if output_payloads != expected_payloads:
        raise ValueError("native ScriptFile append changed a retained or appended GSCBIN payload")
    return dict(ordered_asset_identity_sha256=ordered_asset_identity_sha256(output_rows),
                source_row_count=len(source_rows), output_row_count=len(output_rows),
                retained_scriptfile_payloads_exact=len(source_payloads),
                appended_scriptfile_payload_exact=True)
