"""Revisioned StringTable CSV creation/cancellation and native row transactions."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from workstation_fastfiles import (ZoneBody, _native_walk_artifact, _read_native_rows,
    acts_tool_identity, make_replay_header_only_patch, ordered_asset_identity_sha256,
    pack_replay_uncompressed, sha256_file, source_profile, unpack_replay_uncompressed)
from workstation_asset_codecs import encode_stringtable_sections, parse_stringtable_csv
from workstation_trace_index import build_read_span_index
import workstation_asset_operations as operation_store
import workstation_fastfiles as dispatcher
import workstation_stringtable_rows as row_writer

STRINGTABLE_TYPE_ID = 54
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _workspace_inputs(workspace, zone_id: str, *, _snapshot=None):
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True)
    if _snapshot is not None:
        if hasattr(workspace, "_require_asset_request_snapshot"):
            workspace._require_asset_request_snapshot(_snapshot, zone_id)
        if (_snapshot.zone_id != zone_id or not _snapshot.native_walk or
                not _snapshot.native_rows or not _snapshot.native_walk.get("stream_trace_enabled")):
            raise ValueError("StringTable row operation requires a complete native trace snapshot")
        cache, receipt, body = _snapshot.cache_path, _snapshot.decode_receipt, _snapshot.body
        source, profile, walk, native = (_snapshot.source_path, _snapshot.source_profile,
            _snapshot.native_walk, _snapshot.native_rows)
    else:
        cache, receipt = workspace._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache / receipt["final_body_relative_path"]).read_bytes())
        source = Path(receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk, native = _read_native_rows(cache, body, require_trace=True)
    if any(item.get("extension") == ".fc" for item in profile.get("patches", [])):
        raise ValueError("StringTable row transactions do not support FC replacement chains")
    if (not walk.get("stream_trace_enabled") or
            walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
                [item["sha256"] for item in profile.get("patches", [])]):
        raise ValueError("StringTable walk differs from the complete current source FF/FP chain")
    paths = [Path(row_writer.__file__).resolve(strict=True),
             Path(operation_store.__file__).resolve(strict=True),
             Path(dispatcher.__file__).resolve(strict=True),
             Path(__file__).resolve(strict=True)]
    identity = dict(body_sha256=body.source_sha256,
        source_fastfile_sha256=profile["sha256"],
        patch_sha256s=[item["sha256"] for item in profile.get("patches", [])],
        native_walk_key=walk["walk_key"],
        native_manifest_sha256=walk["manifest_sha256"],
        stream_trace_sha256=walk["stream_trace_sha256"],
        writer_module_path=str(paths[0]), writer_module_sha256=sha256_file(paths[0]),
        transaction_module_path=str(paths[3]), transaction_module_sha256=sha256_file(paths[3]),
        dispatcher_module_path=str(paths[2]), dispatcher_module_sha256=sha256_file(paths[2]),
        operation_store_module_path=str(paths[1]), operation_store_module_sha256=sha256_file(paths[1]))
    return cache, receipt, body, source, profile, walk, native, identity


def operations(workspace, zone_id: str, *, _snapshot=None) -> list[dict]:
    cache, _receipt, body, _source, _profile, _walk, native, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    results = []
    for current in sorted(cache.glob("pending-edits/op-*/current.json")):
        if json.loads(current.read_text(encoding="utf-8")).get("type_id") != STRINGTABLE_TYPE_ID:
            continue
        row, payload = operation_store.validate_operation(cache, current, identity)
        if (row.get("type") != "stringtable" or row.get("zone_id") != zone_id or
                row.get("operation") not in ("append", "remove") or
                row.get("source_body_sha256") != body.source_sha256 or
                row.get("content_sha256") != _sha(row["content"].encode("utf-8")) or
                payload != row["content"].encode("utf-8")):
            raise ValueError("StringTable operation differs from its exact source CSV payload")
        receipt = row.get("compiler_receipt", {})
        if (receipt.get("schema") != "replay120-stringtable-row-operation-v1" or
                receipt.get("asset_name") != row.get("name") or
                receipt.get("operation") != row.get("operation") or
                receipt.get("source", {}).get("sha256") != row["content_sha256"] or
                receipt.get("result", {}).get("payload_sha256") != row.get("payload_sha256")):
            raise ValueError("StringTable operation recipe/CSV differs from its immutable receipt")
        parsed = parse_stringtable_csv(payload)
        if not parsed:
            raise ValueError("StringTable operation must contain a nonempty rectangular CSV")
        if row["operation"] == "append":
            if any(item.get("name") == row["name"] for item in native):
                raise ValueError("StringTable append name collides with an existing native asset")
        else:
            index = row.get("index")
            if (type(index) is not int or not 0 <= index < len(native) or
                    index != len(body.assets) - 1 or body.assets[index].type_id != STRINGTABLE_TYPE_ID or
                    native[index].get("name") != row["name"] or
                    row.get("asset_id") != f"{zone_id}:{index}"):
                raise ValueError("StringTable removal no longer identifies the exact final source row")
        row["pending_path"] = str(current)
        row["_payload"] = payload
        results.append(row)
    if len(results) > 1:
        raise ValueError("StringTable row operations currently support one active operation per zone")
    return results


def _stage(workspace, zone_id: str, operation: str, name: str, content: str,
           index: int | None = None, expected_revision: str | None = None, *, _snapshot=None):
    cache, _receipt, body, _source, _profile, _walk, _native, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    payload = content.encode("utf-8")
    rows = parse_stringtable_csv(payload)
    encode_stringtable_sections(name, rows)
    op_id = operation_store._operation_id(operation, name, index, STRINGTABLE_TYPE_ID)
    asset_id = (f"{zone_id}:new-{_sha(name.encode('utf-8'))[:32]}" if operation == "append"
                else f"{zone_id}:{index}")
    content_sha = _sha(payload)
    receipt = dict(schema="replay120-stringtable-row-operation-v1", status="stringtable-row-csv-pass",
        asset_name=name, operation=operation, source=dict(sha256=content_sha, utf8_bytes=len(payload)),
        compiler=dict(writer_module_path=identity["writer_module_path"],
                      writer_module_sha256=identity["writer_module_sha256"]),
        result=dict(payload_sha256=_sha(payload), payload_bytes=len(payload),
                    rows=len(rows), columns=len(rows[0])))
    row = dict(schema=4, operation=operation, operation_id=op_id, asset_id=asset_id,
        zone_id=zone_id, type_id=STRINGTABLE_TYPE_ID, type="stringtable", name=name,
        index=index, xasset_index=index, content=content, language="csv",
        source_body_sha256=body.source_sha256, content_sha256=content_sha,
        native_source_identity=identity, compiler_receipt=receipt,
        compiler_receipt_sha256=_sha(json.dumps(receipt, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
        writer_identity=dict(path=identity["writer_module_path"],
                             sha256=identity["writer_module_sha256"]))
    if _snapshot is not None:
        workspace._assert_asset_snapshot_current(_snapshot)
    return operation_store.stage_operation(cache, row, payload, expected_revision)


def create_stringtable_asset(workspace, zone_id: str, name: str, content: str,
                             revision: str | None = None, *, _snapshot=None) -> dict:
    if (not isinstance(name, str) or not _NAME.fullmatch(name) or
            any(part in ("", ".", "..") for part in name.split("/")) or
            not name.casefold().endswith(".csv")):
        raise ValueError("Use a confined StringTable .csv name with letters, digits, underscores, dots, slashes or hyphens")
    if not isinstance(content, str):
        raise ValueError("StringTable content must be CSV text")
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True)
    cache, _receipt, _body, _source, _profile, _walk, native, _identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    if any(item.get("name") == name for item in native):
        raise ValueError("StringTable name already exists in the native source zone")
    from workstation_rawfile_crud import operations as rawfile_operations
    new_identity = f"{zone_id}:new-{_sha(name.encode('utf-8'))[:32]}"
    if any(row.get("operation") == "append" and row.get("asset_id") == new_identity
           for row in rawfile_operations(workspace, zone_id, _snapshot=_snapshot)):
        raise ValueError("pending RawFile append already owns this StringTable identity")
    active = operations(workspace, zone_id, _snapshot=_snapshot)
    if any(row.get("name") == name for row in active):
        if revision is None or active[0].get("revision") != revision or active[0].get("operation") != "append":
            raise ValueError("StringTable asset revision conflict; reload before saving")
    elif revision is not None:
        raise ValueError("staged StringTable append no longer exists; reload before saving")
    staged = _stage(workspace, zone_id, "append", name, content,
                    expected_revision=revision, _snapshot=_snapshot)
    return {**staged, "status": "native-stringtable-append-staged", "type": "stringtable",
        "type_id": STRINGTABLE_TYPE_ID, "name": name, "content": content, "language": "csv", "extension": "csv",
        "editable": True, "archive_writable": False,
        "pending_path": str(cache / "pending-edits" / staged["operation_id"] / "current.json"),
        "package_status": "StringTable CSV append awaits a complete native package and semantic reread"}


def get_new_stringtable_asset(workspace, asset_id: str, *, _snapshot=None) -> dict:
    zone_id, marker = asset_id.rsplit(":", 1)
    if not re.fullmatch(r"new-[0-9a-f]{32}", marker):
        raise ValueError("Malformed new StringTable identity")
    found = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
             if row.get("asset_id") == asset_id and row.get("operation") == "append"]
    if len(found) != 1:
        raise KeyError(asset_id)
    row = found[0]
    return {**{key: value for key, value in row.items() if not key.startswith("_")},
        "editable": True, "archive_writable": False, "language": "csv", "extension": "csv",
        "payload_format": "Replay StringTable CSV row creation",
        "package_status": "StringTable creation is staged and cancellable until native package"}


def remove_stringtable_asset(workspace, asset_id: str, revision: str) -> dict:
    opened = workspace.get_asset(asset_id)
    if (opened.get("type_id") != STRINGTABLE_TYPE_ID or opened.get("type") != "stringtable" or
            opened.get("revision") != revision or opened.get("pending_path")):
        raise ValueError("StringTable removal requires the current unstaged source revision")
    if not opened.get("row_remove_supported"):
        raise ValueError(opened.get("row_remove_reason") or "StringTable row removal is not supported for this source")
    staged = _stage(workspace, opened["zone_id"], "remove", opened["name"], opened["content"],
                    opened["index"])
    return {**staged, "type": "stringtable", "type_id": STRINGTABLE_TYPE_ID,
        "status": "native-stringtable-removal-staged", "name": opened["name"], "content": opened["content"],
        "editable": False, "archive_writable": False, "row_remove_supported": False,
        "row_remove_reason": "Removal is already staged"}


def _trace_assets(walk, body_size: int):
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(walk, "manifest_relative_path")
    if (sha256_file(trace) != walk.get("stream_trace_sha256") or
            sha256_file(manifest) != walk.get("manifest_sha256")):
        raise ValueError("StringTable trace or manifest differs from its immutable native receipt")
    index = build_read_span_index(trace, manifest, body_size)
    return trace, manifest, index


def plan_stringtable_crud(workspace, zone_id: str, pending_rows: list[dict], *, _snapshot=None) -> dict:
    if len(pending_rows) != 1 or any(row.get("type") != "stringtable" or
        row.get("operation") not in ("append", "remove") for row in pending_rows):
        raise ValueError("StringTable supports one CSV append or one exclusive final-row removal per transaction")
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True)
    cache, _receipt, body, _source, profile, walk, native, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    active = operations(workspace, zone_id, _snapshot=_snapshot)
    if len(active) != 1 or active[0].get("revision") != pending_rows[0].get("revision"):
        raise ValueError("StringTable operation set changed since preflight")
    operation = active[0]
    rows = parse_stringtable_csv(operation["_payload"])
    proof = None
    if operation["operation"] == "append":
        _trace, _manifest, index = _trace_assets(walk, len(body.data))
        final = next((item for item in index["assets"] if item.get("index") == len(body.assets) - 1), None)
        if final is None:
            raise ValueError("complete native trace omits the current final XAsset")
        proof = dict(operation="append", csv_rows=len(rows), columns=len(rows[0]),
                     source_final_asset_index=len(body.assets) - 1,
                     source_final_asset_end_cursor=final.get("end_cursor"))
    else:
        index_num = operation["index"]
        _trace, _manifest, index = _trace_assets(walk, len(body.data))
        traced = next((item for item in index["assets"] if item.get("index") == index_num), None)
        if traced is None:
            raise ValueError("complete trace omits the final StringTable row")
        traced.update(xasset_index=index_num, type_id=STRINGTABLE_TYPE_ID, name=operation["name"])
        _, proof = row_writer.remove_existing_stringtable_row(body.data, index_num,
            operation["name"], traced, rows, body.source_sha256, _trace, _manifest,
            expected_trace_sha256=walk["stream_trace_sha256"],
            expected_manifest_sha256=walk["manifest_sha256"])
    return dict(source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
        native_source_identity=identity, native_walk_key=walk["walk_key"],
        original_xasset_count=len(body.assets), final_xasset_count=len(body.assets) +
            (1 if operation["operation"] == "append" else -1),
        operation_count=1, edits=[dict(operation=operation["operation"],
            operation_id=operation["operation_id"], asset_id=operation["asset_id"],
            revision=operation["revision"], type="stringtable", type_id=54,
            name=operation["name"], index=operation.get("index"))],
        support=("stringtable-csv-append-native-transaction" if operation["operation"] == "append"
                 else "stringtable-exclusive-final-row-removal-native-transaction"),
        limits="One CSV append or final-row removal; removal requires inline root name, exact physical EOF ownership, exclusive root/stream-5 children and no inbound aliases",
        writer_proof=proof)


def _semantic_export(workspace, fastfile: Path, native_rows: list[dict], proof_root: Path,
                     label: str, timeout: int) -> dict[tuple[int, str], bytes]:
    from workstation_fastfiles import source_profile
    proof_root.mkdir(parents=True, exist_ok=True)
    expected = [(index, row) for index, row in enumerate(native_rows)
                if row.get("type_id") == STRINGTABLE_TYPE_ID and row.get("status") != "reference"]
    acts_identity = acts_tool_identity(workspace.acts_path)
    replay_hash = sha256_file(workspace.replay_executable)
    with tempfile.TemporaryDirectory(prefix="rps-") as temp:
        root = Path(temp)
        if len(str(root)) > 80:
            raise ValueError("system temporary path is too long for safe native StringTable export")
        command = [str(workspace.acts_path), "--noUpdater", "fastfile", "-r", "mw19replay",
                   "-g", str(workspace.replay_executable), "-o", str(root), "-a", "stringtable",
                   "-l", str(fastfile)]
        log = proof_root / f"{label}-semantic-export.log"
        with log.open("w", encoding="utf-8") as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                    check=False, timeout=timeout)
        manifests = list(root.glob("mw19replay/*/manifest.json"))
        if result.returncode != 0 or len(manifests) != 1:
            raise ValueError(f"native StringTable semantic export failed; see {log}")
        manifest_path = manifests[0]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not manifest.get("complete") or not manifest.get("success") or
                manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
                manifest.get("tested") != len(expected)):
            raise ValueError("native StringTable semantic export did not cover its complete type inventory")
        journal_path = manifest_path.parent / manifest.get("journal", "assets.jsonl")
        exported = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
        if len(exported) != len(expected):
            raise ValueError("native StringTable semantic journal count differs from its ordered inventory")
        output_rows = {}
        payload_dir = proof_root / f"{label}-payloads"
        payload_dir.mkdir(exist_ok=True)
        for rank, ((asset_index, native), item) in enumerate(zip(expected, exported, strict=True)):
            if item.get("type_id") != 54 or item.get("name") != native.get("name"):
                raise ValueError("native StringTable semantic journal differs from XAsset order/name")
            relative = item.get("file")
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("native StringTable exporter returned an unsafe payload path")
            payload_path = (manifest_path.parent / relative).resolve(strict=True)
            if not payload_path.is_relative_to(manifest_path.parent.resolve(strict=True)):
                raise ValueError("native StringTable payload escaped its output directory")
            payload = payload_path.read_bytes()
            # Retained native tables are compared byte-for-byte below.  Do not
            # require stock payloads to satisfy the authored-editor CSV rules:
            # Replay legitimately contains empty StringTables, exported by
            # ACTS as a zero-byte CSV.  Newly authored rows still pass the
            # strict rectangular CSV parser at staging and are parsed again
            # when their native export is compared.
            target = payload_dir / f"{rank:05d}.csv"
            shutil.copy2(payload_path, target)
            if sha256_file(target) != _sha(payload):
                raise ValueError("durable StringTable semantic copy changed bytes")
            output_rows[(asset_index, native["name"])] = payload
        shutil.copy2(manifest_path, proof_root / f"{label}-semantic-manifest.json")
        shutil.copy2(journal_path, proof_root / f"{label}-semantic-assets.jsonl")
    if acts_tool_identity(workspace.acts_path) != acts_identity or sha256_file(workspace.replay_executable) != replay_hash:
        raise RuntimeError("ACTS or Replay executable changed during StringTable semantic export")
    return output_rows


def _compare_inventory(source_inventory, output_inventory, source_rows, output_rows,
                       operation: dict) -> dict:
    source_items = [(i, row["name"]) for i, row in enumerate(source_rows)
                    if row.get("type_id") == STRINGTABLE_TYPE_ID and row.get("status") != "reference"]
    output_items = [(i, row["name"]) for i, row in enumerate(output_rows)
                    if row.get("type_id") == STRINGTABLE_TYPE_ID and row.get("status") != "reference"]
    if operation["operation"] == "append":
        expected = source_items + [(len(source_rows), operation["name"])]
        if output_items != expected:
            raise ValueError("appended StringTable changed retained table identity/order")
        retained, removed = source_items, None
    else:
        removed = (operation["index"], operation["name"])
        expected = [item for item in source_items if item != removed]
        if output_items != expected:
            raise ValueError("StringTable removal changed retained table identity/order")
        retained = expected
    if any(source_inventory.get(key) != output_inventory.get(key) for key in retained):
        raise ValueError("StringTable row transaction changed retained CSV bytes")
    if operation["operation"] == "append":
        actual = output_inventory[(len(source_rows), operation["name"])]
        if parse_stringtable_csv(actual) != parse_stringtable_csv(operation["content"].encode("utf-8")):
            raise ValueError("native StringTable append differs from exact authored CSV cells")
    return dict(status="pass", operation=operation["operation"],
        source_table_count=len(source_items), output_table_count=len(output_items),
        retained_payloads_checked=len(retained), appended_csv_exact=operation["operation"] == "append",
        removed_table=removed)


def build_workspace_stringtable_crud(workspace, zone_id: str, plan: dict,
                                     output: str | Path, timeout: int = 1800,
                                     *, _snapshot=None) -> dict:
    from roundtrip_replay_fastfile import verify_native
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True)
    cache, decode_receipt, body, source, profile, walk, native_rows, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    active = operations(workspace, zone_id, _snapshot=_snapshot)
    if len(active) != 1 or active[0]["revision"] != plan["edits"][0]["revision"]:
        raise ValueError("StringTable operation changed after native preflight")
    operation = active[0]
    source_rows = parse_stringtable_csv(operation["_payload"])
    trace_path, manifest_path, span_index = _trace_assets(walk, len(body.data))
    if operation["operation"] == "append":
        final = next(row for row in span_index["assets"] if row.get("index") == len(body.assets) - 1)
        final.update(xasset_index=len(body.assets) - 1,
                     type_id=body.assets[-1].type_id,
                     name=native_rows[-1].get("name"))
        updated, writer = row_writer.append_stringtable_tail(body.data, operation["name"],
            source_rows, {row.get("name") for row in native_rows if row.get("name")},
            body.source_sha256, trace_path, manifest_path, final,
            expected_trace_sha256=walk["stream_trace_sha256"],
            expected_manifest_sha256=walk["manifest_sha256"])
    else:
        index = operation["index"]
        traced = next(row for row in span_index["assets"] if row.get("index") == index)
        traced.update(xasset_index=index, type_id=54, name=operation["name"])
        updated, writer = row_writer.remove_existing_stringtable_row(body.data, index,
            operation["name"], traced, source_rows, body.source_sha256, trace_path, manifest_path,
            expected_trace_sha256=walk["stream_trace_sha256"],
            expected_manifest_sha256=walk["manifest_sha256"])
    output = Path(output).resolve()
    if output.suffix.casefold() != ".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("StringTable row transaction output must be an .ff outside the shipped game tree")
    if output.exists() or output.with_suffix(".fp").exists() or output.with_suffix(".fc").exists():
        raise FileExistsError("StringTable transaction output or sidecar already exists")
    reservations = list(profile["final_header"]["block_sizes"])
    if operation["operation"] == "append":
        needed = [int(writer["appended_root_stream_offset"]) + 48,
                  int(writer["appended_stream5_end"])]
        reservations[1] = max(reservations[1], needed[0])
        reservations[5] = max(reservations[5], needed[1])
    packed = pack_replay_uncompressed(updated, reservations,
        profile["final_header"]["xfile_version"], profile["header"]["transient_type"])
    if unpack_replay_uncompressed(packed) != updated:
        raise AssertionError("StringTable row package framing changed the decoded body")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(packed)
    sidecars = []
    for patch in profile.get("patches", []):
        target = output.with_suffix(patch["extension"])
        target.write_bytes(make_replay_header_only_patch(Path(patch["path"]).read_bytes(), packed))
        sidecars.append(dict(path=str(target), sha256=sha256_file(target), bytes=target.stat().st_size,
                             replaces=str(patch["path"])))
    proof_root = output.with_suffix(output.suffix + ".stringtable-proof")
    proof_root.mkdir(exist_ok=False)
    native = verify_native(output, updated, source, workspace.acts_path,
        workspace.replay_executable, proof_root / "native-reader", timeout, trace=True)
    expected_native = ([*native_rows, dict(type_id=54, name=operation["name"])]
        if operation["operation"] == "append" else native_rows[:-1])
    identity_hash = native.get("normalized_asset_identity_sha256", native.get("journal_asset_identity_sha256"))
    if identity_hash != ordered_asset_identity_sha256(expected_native):
        raise ValueError("native StringTable row transaction changed ordered XAsset identities")
    manifest = native["manifest"]
    if (not manifest.get("complete") or not manifest.get("success") or manifest.get("failed") != 0 or
            manifest.get("unavailable") != 0 or manifest.get("serialized_bytes_read") != len(updated)):
        raise ValueError("native StringTable row transaction did not fully read the candidate body")
    source_semantic = _semantic_export(workspace, source, native_rows, proof_root, "source", timeout)
    output_semantic = _semantic_export(workspace, output, expected_native, proof_root, "output", timeout)
    comparison = _compare_inventory(source_semantic, output_semantic, native_rows,
                                    expected_native, operation)
    if operation["operation"] == "append":
        highwaters = native.get("trace_summary", {}).get("max_destination_offsets", {})
        if int(highwaters.get("1", highwaters.get(1, 0))) > reservations[1] or \
           int(highwaters.get("5", highwaters.get(5, 0))) != writer["appended_stream5_end"]:
            raise ValueError("native StringTable reader high-water differs from the appended typed schedule")
    receipt = dict(schema="replay120-stringtable-row-transaction-v1",
        status="native-full-zone-stringtable-row-transaction-pass", zone_id=zone_id,
        operation=dict(name=operation["name"], operation=operation["operation"],
            asset_id=operation["asset_id"], revision=operation["revision"],
            content_sha256=operation["content_sha256"], payload_sha256=operation["payload_sha256"]),
        source=dict(fastfile=str(source), fastfile_sha256=profile["sha256"],
            body_sha256=body.source_sha256, native_walk_key=walk["walk_key"],
            manifest_sha256=walk["manifest_sha256"], stream_trace_sha256=walk["stream_trace_sha256"]),
        writer=writer, semantic_inventory=comparison,
        output_fastfile=dict(path=str(output), sha256=sha256_file(output), bytes=output.stat().st_size,
                             reservations=reservations),
        sidecars=sidecars, native_reader=dict(return_code=native["return_code"],
            complete=manifest.get("complete"), success=manifest.get("success"),
            loaded_assets=manifest.get("loaded_assets"), tested=manifest.get("tested"),
            failed=manifest.get("failed"), unavailable=manifest.get("unavailable"),
            serialized_bytes_read=manifest.get("serialized_bytes_read"),
            journal_asset_identity_sha256=native["journal_asset_identity_sha256"],
            trace_summary=native.get("trace_summary")))
    receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return dict(schema=receipt["schema"], status=receipt["status"], zone_id=zone_id,
        edits=[dict(asset_id=operation["asset_id"], revision=operation["revision"])],
        output_fastfile=str(output), output_fastfile_sha256=receipt["output_fastfile"]["sha256"],
        sidecars=sidecars, receipt_path=str(receipt_path),
        native_reader_status=manifest.get("status"), native_reader_loaded=manifest.get("loaded_assets"),
        native_reader_tested=manifest.get("tested"), writer_proof=writer,
        semantic_inventory=comparison)
