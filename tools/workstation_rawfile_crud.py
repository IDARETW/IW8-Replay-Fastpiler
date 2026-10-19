"""Revisioned RawFile row operations and native-verified append/remove builds."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re

import workstation_rawfile as rawfile
import workstation_rawfile_rows as row_writer
from workstation_fastfiles import (ZoneBody, make_replay_header_only_patch,
    pack_replay_uncompressed, sha256_file, source_profile, unpack_replay_uncompressed)
from workstation_rawfile_rows import append_rawfile_tail, remove_final_rawfile_tail


RAWFILE_TYPE_ID = 51


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inputs(workspace, zone_id, *, _snapshot=None):
    from workstation_fastfiles import _read_native_rows
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    if _snapshot is not None:
        if hasattr(workspace, "_require_asset_request_snapshot"):
            workspace._require_asset_request_snapshot(_snapshot, zone_id)
        if _snapshot.zone_id != zone_id or not _snapshot.native_walk or not _snapshot.native_rows:
            raise ValueError("RawFile row operations require the complete native zone snapshot")
        cache, receipt, body = _snapshot.cache_path, _snapshot.decode_receipt, _snapshot.body
        source, profile, walk, rows = (_snapshot.source_path, _snapshot.source_profile,
                                      _snapshot.native_walk, _snapshot.native_rows)
    else:
        cache, receipt = workspace._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache / receipt["final_body_relative_path"]).read_bytes())
        source = Path(receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk, rows = _read_native_rows(cache, body, require_trace=True)
    if any(row.get("extension") == ".fc" for row in profile.get("patches", [])):
        raise ValueError("RawFile row operations do not support FC replacement chains")
    if (not walk.get("stream_trace_enabled") or
            walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
            [row["sha256"] for row in profile.get("patches", [])]):
        raise ValueError("RawFile row operation native trace differs from the source FF/patch chain")
    row_writer_path = Path(row_writer.__file__).resolve(strict=True)
    transaction = Path(__file__).resolve(strict=True)
    import workstation_asset_operations as operation_store
    operation_path = Path(operation_store.__file__).resolve(strict=True)
    identity = dict(body_sha256=body.source_sha256,
        source_fastfile_sha256=profile["sha256"],
        patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
        native_walk_key=walk["walk_key"],
        native_manifest_sha256=walk["manifest_sha256"],
        stream_trace_sha256=walk["stream_trace_sha256"],
        writer_module_path=str(row_writer_path), writer_module_sha256=sha256_file(row_writer_path),
        transaction_module_path=str(transaction), transaction_module_sha256=sha256_file(transaction),
        operation_store_module_path=str(operation_path), operation_store_module_sha256=sha256_file(operation_path))
    return cache, receipt, body, source, profile, walk, rows, identity, _snapshot


def _asset_identity(zone_id, name):
    return f"{zone_id}:new-{_sha(name.encode('utf-8'))[:32]}"


def _check_cross_type_identity(workspace, zone_id, name, *, _snapshot=None):
    identity = _asset_identity(zone_id, name)
    for module_name in ("workstation_localize_crud", "workstation_luafile_crud",
                        "workstation_scriptfile_crud", "workstation_stringtable_crud"):
        module = __import__(module_name, fromlist=["operations"])
        for row in module.operations(workspace, zone_id, _snapshot=_snapshot):
            if row.get("operation") == "append" and row.get("asset_id") == identity:
                raise ValueError(f"pending {row.get('type')} append already owns this RawFile identity")


def operations(workspace, zone_id, *, _snapshot=None):
    from workstation_asset_operations import validate_operation
    cache, _receipt, body, _source, _profile, _walk, native_rows, identity, _snapshot = _inputs(
        workspace, zone_id, _snapshot=_snapshot)
    result = []
    for current in sorted(cache.glob("pending-edits/op-*/current.json")):
        try:
            candidate = json.loads(current.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise
        if candidate.get("type_id") != RAWFILE_TYPE_ID:
            continue
        row, payload = validate_operation(cache, current, identity)
        if (row.get("zone_id") != zone_id or row.get("type") != "rawfile" or
                row.get("source_body_sha256") != body.source_sha256 or
                _sha(row["content"].encode("utf-8")) != row.get("content_sha256")):
            raise ValueError("RawFile operation belongs to another zone/body or its content changed")
        if row.get("writer_identity") != dict(path=identity["writer_module_path"],
                                             sha256=identity["writer_module_sha256"]):
            raise ValueError("RawFile row writer identity is stale")
        stale = workspace._compiler_identity_staleness(row, RAWFILE_TYPE_ID)
        if stale:
            raise ValueError(stale)
        if row["operation"] == "append":
            mode = row["editor_mode"]
            expected = (row["content"].encode("utf-8") if mode == "text" else
                        base64.b64decode(row["content"], validate=True))
            if expected != payload:
                raise ValueError("RawFile append bytes differ from the staged text/base64 content")
        else:
            index = row.get("index")
            if (type(index) is not int or index != len(body.assets) - 1 or
                    native_rows[index].get("type_id") != RAWFILE_TYPE_ID or
                    native_rows[index].get("name") != row.get("name")):
                raise ValueError("RawFile removal no longer targets the exact final source XAsset")
        row["pending_path"] = str(current)
        row["_payload"] = payload
        result.append(row)
    append_names = [row["name"] for row in result if row["operation"] == "append"]
    remove_names = {row["name"] for row in result if row["operation"] == "remove"}
    if len(append_names) != len(set(append_names)):
        raise ValueError("duplicate staged RawFile append names")
    for name in append_names:
        if (any(row.get("type_id") == RAWFILE_TYPE_ID and row.get("name") == name
                for row in native_rows) and name not in remove_names):
            raise ValueError("RawFile append name already exists in the native source zone")
    return result


def _stage(workspace, zone_id, operation, name, content, payload, index=None,
           mode="text", expected_revision=None, *, _snapshot=None,
           removal_body_sha256=None):
    from workstation_asset_operations import stage_operation
    cache, _receipt, body, _source, _profile, _walk, _rows, identity, _snapshot = _inputs(
        workspace, zone_id, _snapshot=_snapshot)
    operation_hash = _sha(name.encode("utf-8"))
    operation_id = ("op-a-r-" + operation_hash[:32] if operation == "append" else f"op-r-{index}")
    asset_id = _asset_identity(zone_id, name) if operation == "append" else f"{zone_id}:{index}"
    content_hash = _sha(content.encode("utf-8"))
    payload_hash = _sha(payload)
    receipt = dict(schema="replay120-rawfile-row-receipt-v1",
        status="rawfile-row-operation-staged" if operation == "append" else "rawfile-row-removal-staged",
        asset_name=name, operation=operation, editor_mode=mode,
        source=dict(sha256=content_hash),
        compiler=dict(writer_module_path=str(Path(rawfile.__file__).resolve()),
                      writer_module_sha256=sha256_file(Path(rawfile.__file__).resolve())))
    if operation == "append":
        receipt["result"] = dict(native_payload_sha256=payload_hash, raw_bytes=len(payload))
    else:
        receipt.update(source_index=index, source_body_sha256=removal_body_sha256,
                       native_payload_sha256=payload_hash)
    row = dict(schema=4, operation=operation, operation_id=operation_id,
        asset_id=asset_id, zone_id=zone_id, type_id=RAWFILE_TYPE_ID, type="rawfile",
        name=name, index=index, xasset_index=index, content=content,
        editor_mode=mode, language="ini" if Path(name).suffix.lower() == ".cfg" else "plaintext",
        source_body_sha256=body.source_sha256, content_sha256=content_hash,
        native_source_identity=identity, compiler_receipt=receipt,
        compiler_receipt_sha256=_sha(json.dumps(receipt, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
        writer_identity=dict(path=identity["writer_module_path"], sha256=identity["writer_module_sha256"]))
    if _snapshot is not None:
        workspace._assert_asset_snapshot_current(_snapshot)
    staged = stage_operation(cache, row, payload, expected_revision)
    return dict(**staged, status=f"native-rawfile-{operation}-staged",
        editable=operation == "append", archive_writable=False,
        pending_path=str(cache / "pending-edits" / operation_id / "current.json"))


def create_rawfile_asset(workspace, zone_id, name, content, revision=None, *,
                         mode="text", _snapshot=None):
    if mode not in ("text", "base64") or not isinstance(content, str):
        raise ValueError("RawFile creation requires text or lossless base64 content")
    name_bytes = row_writer._validate_name(name)
    del name_bytes
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    _check_cross_type_identity(workspace, zone_id, name, _snapshot=_snapshot)
    _cache, _receipt, _body, _source, _profile, _walk, rows, _identity, _snapshot = _inputs(
        workspace, zone_id, _snapshot=_snapshot)
    if any(row.get("type_id") == RAWFILE_TYPE_ID and row.get("name") == name for row in rows):
        raise ValueError("RawFile name already exists in the native source zone")
    try:
        payload = content.encode("utf-8") if mode == "text" else base64.b64decode(content, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("RawFile base64 content is invalid") from error
    current = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
               if row.get("operation") == "append" and row.get("name") == name]
    if current:
        if len(current) != 1 or revision is None or current[0].get("revision") != revision:
            raise ValueError("RawFile staged revision conflict; reload before saving")
    elif revision is not None:
        raise ValueError("RawFile staged append no longer exists; reload before saving")
    return _stage(workspace, zone_id, "append", name, content, payload, mode=mode,
                  expected_revision=revision, _snapshot=_snapshot)


def remove_rawfile_asset(workspace, asset_id, revision):
    opened = workspace.get_asset(asset_id)
    if opened.get("type_id") != RAWFILE_TYPE_ID or opened.get("type") != "rawfile":
        raise ValueError("RawFile removal requires a native type-51 asset")
    if opened.get("revision") != revision:
        raise ValueError("Asset revision conflict; reload before removing")
    if opened.get("pending_path"):
        raise ValueError("Restore the active RawFile edit before removing this row")
    zone_id, index_text = asset_id.rsplit(":", 1)
    index = int(index_text)
    cache, _receipt, body, _source, _profile, walk, native_rows, _identity, _snapshot = _inputs(
        workspace, zone_id)
    if index != len(body.assets) - 1 or native_rows[index].get("name") != opened.get("name"):
        raise ValueError("RawFile removal is supported only for the final matching source row")
    from workstation_fastfiles import _native_walk_artifact
    from workstation_trace_index import build_read_span_index
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(walk, "manifest_relative_path")
    indexed = build_read_span_index(trace, manifest, len(body.data), selected_assets={index})
    rows = [row for row in indexed["assets"] if row.get("index") == index]
    if len(rows) != 1:
        raise ValueError("RawFile removal trace does not uniquely contain the final asset")
    owner = dict(rows[0], name=opened["name"], _all_physical_spans=indexed["_all_physical_spans"])
    native = dict(native_rows[index], index=index)
    _updated, proof = remove_final_rawfile_tail(body.data, index, opened["name"], native,
        owner, body.source_sha256, trace, manifest,
        expected_trace_sha256=walk["stream_trace_sha256"],
        expected_manifest_sha256=walk["manifest_sha256"])
    del proof
    decoded = rawfile.read_rawfile(body.data, native, owner, body.source_sha256)[1]
    payload = (decoded["content"].encode("utf-8") if decoded["mode"] == "text" else
               base64.b64decode(decoded["content"]))
    return _stage(workspace, zone_id, "remove", opened["name"], decoded["content"], payload,
        index=index, mode=decoded["mode"], expected_revision=None,
        removal_body_sha256=body.source_sha256)


def get_new_rawfile_asset(workspace, asset_id, *, _snapshot=None):
    zone_id, marker = asset_id.rsplit(":", 1)
    if not re.fullmatch(r"new-[0-9a-f]{32}", marker):
        raise ValueError("Malformed new RawFile identity")
    found = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
             if row.get("asset_id") == asset_id and row.get("operation") == "append"]
    if len(found) != 1:
        raise KeyError(asset_id)
    row = found[0]
    cache, *_ = _inputs(workspace, zone_id, _snapshot=_snapshot)
    public = {key: value for key, value in row.items() if not key.startswith("_")}
    return dict(**public, editable=True, archive_writable=False,
        payload_format="replay120-rawfile-inline-row-operation",
        package_status="RawFile row creation queued for a complete native zone rebuild and semantic reread")


def plan_rawfile_rows(workspace, zone_id, planned_rows, *, _snapshot=None):
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    cache, _receipt, body, _source, profile, walk, native_rows, identity, _snapshot = _inputs(
        workspace, zone_id, _snapshot=_snapshot)
    active = {row["operation_id"]: row for row in operations(workspace, zone_id, _snapshot=_snapshot)}
    edits = []
    for planned in planned_rows:
        if planned.get("type") != "rawfile" or planned.get("operation") not in ("append", "remove"):
            raise ValueError("RawFile row batch supports only one staged RawFile append or removal")
        row = active.get(planned.get("operation_id"))
        if not row or row.get("revision") != planned.get("revision"):
            raise ValueError("RawFile operation changed after preflight")
        edits.append(row)
    if len(edits) != 1:
        raise ValueError("RawFile row build requires exactly one append or removal per native reread")
    item = edits[0]
    return dict(source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
        native_source_identity=identity, operation=item["operation"], operation_id=item["operation_id"],
        revision=item["revision"], name=item["name"], index=item.get("index"),
        original_xasset_count=len(body.assets), final_xasset_count=len(body.assets) +
            (1 if item["operation"] == "append" else -1), rows_added=int(item["operation"] == "append"),
        rows_removed=int(item["operation"] == "remove"), schedule="one table mutation followed by complete native reread",
        final_semantic_check="every retained RawFile exact bytes plus appended or removed row identity")


def build_rawfile_row_transaction(workspace, zone_id, plan, output, timeout, *, _snapshot=None):
    """Package one RawFile append/remove and prove all retained RawFiles natively."""
    from workstation_fastfiles import (_assert_run_inputs_unchanged, _native_walk_artifact,
        acts_tool_identity, ordered_asset_identity_sha256)
    from workstation_trace_index import build_read_span_index
    from roundtrip_replay_fastfile import verify_native
    import workstation_asset_operations as operation_store

    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    cache, _receipt, body, source, profile, walk, native_rows, identity, _snapshot = _inputs(
        workspace, zone_id, _snapshot=_snapshot)
    planned = dict(type="rawfile", operation=plan.get("operation"),
                   operation_id=plan.get("operation_id"), revision=plan.get("revision"))
    checked_plan = plan_rawfile_rows(workspace, zone_id, [planned], _snapshot=_snapshot)
    if checked_plan != plan:
        raise ValueError("RawFile row build plan differs from its immutable source snapshot")
    operation_path = cache / "pending-edits" / plan["operation_id"] / "current.json"
    operation, raw_payload = operation_store.validate_operation(cache, operation_path, identity)
    if operation.get("revision") != plan["revision"]:
        raise ValueError("RawFile row operation changed during build")
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(walk, "manifest_relative_path")
    reservations = list(profile["final_header"]["block_sizes"])
    if operation["operation"] == "append":
        last_index = len(body.assets) - 1
        indexed = build_read_span_index(trace, manifest, len(body.data), selected_assets={last_index})
        final_rows = [row for row in indexed["assets"] if row.get("index") == last_index]
        if len(final_rows) != 1:
            raise ValueError("RawFile append has no unique native final-row trace")
        final_trace = dict(final_rows[0], name=native_rows[last_index].get("name"),
                           _all_physical_spans=indexed["_all_physical_spans"])
        updated, row_proof = append_rawfile_tail(body.data, operation["name"], raw_payload,
            {row.get("name") for row in native_rows if row.get("name")},
            dict(native_rows[last_index], index=last_index), final_trace, body.source_sha256,
            trace, manifest, reservations, compressed=True,
            expected_trace_sha256=walk["stream_trace_sha256"],
            expected_manifest_sha256=walk["manifest_sha256"])
        reservations = row_proof["stream_reservation_sizes"]
    else:
        index = operation["index"]
        indexed = build_read_span_index(trace, manifest, len(body.data), selected_assets={index})
        owner_rows = [row for row in indexed["assets"] if row.get("index") == index]
        if len(owner_rows) != 1:
            raise ValueError("RawFile removal has no unique native trace row")
        owner = dict(owner_rows[0], name=native_rows[index].get("name"),
                     _all_physical_spans=indexed["_all_physical_spans"])
        updated, row_proof = remove_final_rawfile_tail(body.data, index, operation["name"],
            dict(native_rows[index], index=index), owner, body.source_sha256, trace, manifest,
            expected_trace_sha256=walk["stream_trace_sha256"],
            expected_manifest_sha256=walk["manifest_sha256"])
    packed = pack_replay_uncompressed(updated, reservations,
        profile["final_header"]["xfile_version"], profile["header"]["transient_type"])
    if unpack_replay_uncompressed(packed) != updated:
        raise ValueError("RawFile row output framing differs from its serialized body")
    output = Path(output).resolve()
    if output.exists() or output.with_suffix(".fp").exists() or output.with_suffix(".fc").exists():
        raise FileExistsError("RawFile row output or patch sidecar already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    acts_before, replay_before = acts_tool_identity(workspace.acts_path), sha256_file(workspace.replay_executable)
    output.write_bytes(packed)
    sidecars = []
    try:
        for patch in profile.get("patches", []):
            target = output.with_suffix(patch["extension"])
            target.write_bytes(make_replay_header_only_patch(Path(patch["path"]).read_bytes(), packed))
            sidecars.append(dict(path=str(target), sha256=sha256_file(target), bytes=target.stat().st_size))
        reader_root = output.with_suffix(output.suffix + ".native-reader")
        native_read = verify_native(output, updated, source, workspace.acts_path,
            workspace.replay_executable, reader_root, timeout, trace=True)
        manifest_out = native_read["manifest"]
        if manifest_out.get("loaded_assets") != len(native_rows) + (1 if operation["operation"] == "append" else -1):
            raise ValueError("RawFile row native reread loaded a different top-level asset count")
        output_trace = Path(native_read["manifest_path"]).parent / manifest_out.get("stream_trace", "stream-trace.jsonl")
        output_index = build_read_span_index(output_trace, native_read["manifest_path"], len(updated))
        output_owner = {row["index"]: row for row in output_index["assets"]}
        expected_native = list(native_rows)
        if operation["operation"] == "append":
            expected_native.append(dict(type_id=RAWFILE_TYPE_ID, name=operation["name"]))
        else:
            expected_native = expected_native[:-1]
        output_identity = native_read.get("normalized_asset_identity_sha256")
        if not isinstance(output_identity, str):
            output_identity = native_read.get("journal_asset_identity_sha256")
        if output_identity != ordered_asset_identity_sha256(expected_native):
            raise ValueError("RawFile row native reread changed retained name/type/order identity")
        output_native = [dict(row, index=i) for i, row in enumerate(expected_native)]

        source_index = build_read_span_index(trace, manifest, len(body.data))
        source_owners = {row["index"]: dict(row, name=native_rows[row["index"]].get("name"),
            _all_physical_spans=source_index["_all_physical_spans"]) for row in source_index["assets"]}
        output_owners = {row["index"]: dict(row, name=output_native[row["index"]].get("name"),
            _all_physical_spans=output_index["_all_physical_spans"]) for row in output_index["assets"]}
        before_context, after_context = rawfile.RawFileReadContext(body.data), rawfile.RawFileReadContext(updated)
        semantic = []
        for index, native in enumerate(native_rows):
            if native.get("type_id") != RAWFILE_TYPE_ID or native.get("status") == "reference":
                continue
            if operation["operation"] == "remove" and index == operation["index"]:
                continue
            if index not in source_owners or index not in output_owners:
                raise ValueError("RawFile native reread lost a retained source owner")
            _, before = rawfile.read_rawfile(body.data, dict(native, index=index), source_owners[index],
                body.source_sha256, context=before_context)
            _, after = rawfile.read_rawfile(updated, dict(output_native[index], index=index), output_owners[index],
                after_context.sha256, context=after_context)
            before_bytes = (before["content"].encode("utf-8") if before["mode"] == "text" else
                            base64.b64decode(before["content"]))
            after_bytes = (after["content"].encode("utf-8") if after["mode"] == "text" else
                           base64.b64decode(after["content"]))
            if before_bytes != after_bytes:
                raise ValueError("RawFile row transaction changed a retained RawFile payload")
            semantic.append(dict(index=index, name=native.get("name"), sha256=_sha(after_bytes),
                                 status="retained-byte-identical"))
        if operation["operation"] == "append":
            index = len(native_rows)
            owner = output_owners.get(index)
            if owner is None:
                raise ValueError("native reread omitted the appended RawFile")
            _, after = rawfile.read_rawfile(updated, dict(index=index, type_id=RAWFILE_TYPE_ID,
                name=operation["name"]), owner, after_context.sha256, context=after_context)
            actual = after["content"].encode("utf-8") if after["mode"] == "text" else base64.b64decode(after["content"])
            if actual != raw_payload:
                raise ValueError("native reread RawFile bytes differ from the staged append payload")
            semantic.append(dict(index=index, name=operation["name"], sha256=_sha(actual),
                                 status="appended-bytes-exact"))
        _assert_run_inputs_unchanged(source, profile, workspace.acts_path, acts_before,
                                     workspace.replay_executable, replay_before)
        receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
        result = dict(schema="replay120-native-rawfile-row-transaction-v1",
            status="native-full-zone-rawfile-row-transaction-pass", operation=operation["operation"],
            name=operation["name"], source_body_sha256=body.source_sha256,
            output_body_sha256=_sha(updated), source_asset_count=len(body.assets),
            output_asset_count=len(ZoneBody.parse(updated).assets), row_proof=row_proof,
            source_native_identity_sha256=ordered_asset_identity_sha256(native_rows),
            output_native_identity_sha256=output_identity,
            output_fastfile=dict(path=str(output), sha256=sha256_file(output), bytes=output.stat().st_size),
            sidecars=sidecars, native_reader_status=manifest_out.get("status"),
            native_reader_loaded=manifest_out.get("loaded_assets"),
            native_reader_manifest_sha256=sha256_file(native_read["manifest_path"]),
            semantic_readback=dict(status="all-retained-rawfiles-byte-identical",
                                   rawfile_count=len(semantic), items=semantic))
        receipt_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result | {"receipt_path": str(receipt_path)}
    except Exception:
        output.unlink(missing_ok=True)
        for row in sidecars:
            Path(row["path"]).unlink(missing_ok=True)
        raise
