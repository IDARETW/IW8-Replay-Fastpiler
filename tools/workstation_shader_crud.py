"""Conservative public staging and packaging for one native type-17 append."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import uuid

from workstation_asset_operations import stage_operation, validate_operation
from workstation_fastfiles import (ZoneBody, _native_walk_artifact, make_replay_header_only_patch,
    pack_replay_uncompressed, sha256_file, source_profile, unpack_replay_uncompressed)
from roundtrip_replay_fastfile import verify_native


TYPE_ID = 17
TYPE_NAME = "pixelshader"
STAGE_IDS = {"computeshader": 12, "vertexshader": 14, "hullshader": 15,
             "domainshader": 16, "pixelshader": 17}
STAGE_NAMES = {value: key for key, value in STAGE_IDS.items()}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reference_identities(rows: list[dict], body: bytes) -> list[dict]:
    assets = ZoneBody.parse(body).assets
    if len(rows) != len(assets):
        raise ValueError("normalized source identities differ from the XAsset table")
    result = []
    for index, row in enumerate(rows):
        if row.get("status") != "reference":
            continue
        asset = assets[index]
        if asset.pointer_token != 0xFFFFFFFFFFFFFFFD:
            raise ValueError("native reference status differs from the serialized pointer token")
        result.append(dict(index=index, type_id=asset.type_id, name=row.get("name"),
                           pointer_token=asset.pointer_token))
    return result


def _verified_native_rows(native: dict, body: bytes, expected_rows: list[dict],
                          expected_references: list[dict], trace_path: Path) -> list[dict]:
    """Validate full-table identities, including ACTS reference-only rows."""
    manifest = native.get("manifest")
    table = ZoneBody.parse(body).assets
    if not isinstance(manifest, dict):
        raise ValueError("native shader verification omitted its manifest")
    references = native.get("reference_only_rows", [])
    identity = lambda row: (row.get("index"), row.get("type_id"), row.get("name"), row.get("pointer_token"))
    if (not isinstance(references, list) or
            [identity(row) for row in references if isinstance(row, dict)] !=
                [identity(row) for row in expected_references] or
            len(references) != len(expected_references)):
        raise ValueError("native reread changed or omitted expected reference-only XAsset identities")
    tested = manifest.get("tested")
    if (manifest.get("complete") is not True or manifest.get("success") is not True or
            manifest.get("profile") != "replay-1.20" or manifest.get("xfile_version") != 4087 or
            manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
            manifest.get("top_level_index") != len(table) or
            type(tested) is not int or tested + len(references) != len(table) or
            type(manifest.get("loaded_assets")) is not int or manifest["loaded_assets"] < tested or
            manifest.get("export_record_index") != manifest.get("loaded_assets") or
            manifest.get("serialized_bytes_read") != len(body)):
        raise ValueError("native reread did not cover the exact shader table and serialized EOF")
    if manifest.get("reference_only_rows", []) != references:
        raise ValueError("native manifest reference identities differ from verify_native output")
    if references:
        normalized_path = native.get("normalized_inventory_path")
        normalized_hash = native.get("normalized_inventory_sha256")
        if not normalized_path or not isinstance(normalized_hash, str):
            raise ValueError("reference-aware native reread omitted its normalized inventory receipt")
        path = Path(normalized_path).resolve(strict=True)
        if hashlib.sha256(path.read_bytes()).hexdigest() != normalized_hash:
            raise ValueError("native normalized inventory hash changed")
        inventory = json.loads(path.read_text(encoding="utf-8"))
        if (inventory.get("schema") != "replay120-native-normalized-inventory-v1" or
                inventory.get("body_sha256") != _sha(body) or
                inventory.get("trace_sha256") != hashlib.sha256(trace_path.read_bytes()).hexdigest() or
                inventory.get("raw_tested_count") != tested or
                inventory.get("normalized_inventory_count") != len(table) or
                [identity(row) for row in inventory.get("reference_only_rows", [])] !=
                    [identity(row) for row in expected_references]):
            raise ValueError("native normalized inventory differs from its body, trace or expected references")
        rows = inventory.get("normalized_rows")
    else:
        manifest_path = Path(native["manifest_path"])
        journal_path = manifest_path.parent / manifest.get("journal", "assets.jsonl")
        rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not isinstance(rows, list) or len(rows) != len(table) or len(expected_rows) != len(table):
        raise ValueError("native reread rows differ from the complete XAsset table")
    actual = [dict(type_id=row.get("type_id"), name=row.get("name")) for row in rows]
    expected = [dict(type_id=row.get("type_id"), name=row.get("name")) for row in expected_rows]
    if actual != expected:
        raise ValueError("native reread changed retained ordered XAsset identities")
    for index, (row, asset) in enumerate(zip(rows, table, strict=True)):
        if row.get("index", index) != index or row.get("type_id") != asset.type_id:
            raise ValueError(f"native normalized XAsset row {index} differs from its serialized table row")
        if row.get("pointer_token") is not None and row.get("pointer_token") not in (
                asset.pointer_token, hex(asset.pointer_token)):
            raise ValueError(f"native normalized XAsset pointer token differs at row {index}")
    return rows


def _verify_removed_shader_callbacks(body: bytes, output_body: bytes,
                                    source_trace: Path, source_manifest: Path,
                                    output_trace: Path, output_manifest: Path,
                                    removed_index: int, writer_proof: dict) -> dict:
    from workstation_luafile_operations import (_alias_field_archive,
        _build_interval_index, _trace_contract)
    from workstation_scriptfile_crud import _events_by_owner, _infer_target
    removed_streams = tuple(tuple(row) for row in writer_proof.get("removed_stream_ranges", []))
    logical_ranges = tuple(tuple(row) for row in writer_proof.get("logical_delete_ranges", []))
    if not removed_streams or not logical_ranges:
        raise ValueError("shader removal writer omitted its exact deleted native stream ranges")
    source = _trace_contract(body, source_trace, source_manifest,
        removed_stream_ranges=removed_streams, logical_delete_ranges=logical_ranges,
        removed_owner=removed_index, table_row_delta=-16)
    output = _trace_contract(output_body, output_trace, output_manifest, table_row_delta=0)
    source_bases, intervals, target_map = source[1], source[2], source[7]
    output_bases, output_intervals = output[1], output[2]
    source_index = _build_interval_index(intervals)
    output_index = _build_interval_index(output_intervals)
    before, after = _events_by_owner(source_trace), _events_by_owner(output_trace)
    if after.get(removed_index):
        raise ValueError("removed final shader still produced native packed callbacks")
    compared = 0
    for owner in before.keys() | after.keys():
        old_rows = before.get(owner, [])
        if owner == removed_index:
            continue
        new_rows = after.get(owner, [])
        if len(old_rows) != len(new_rows):
            raise ValueError(f"retained native owner {owner} changed packed callback count during shader removal")
        for ordinal, (old, new) in enumerate(zip(old_rows, new_rows)):
            compared += 1
            if old["kind"] != new["kind"] or old["raw"] >> 32 != new["raw"] >> 32:
                raise ValueError(f"retained native owner {owner} callback {ordinal} changed pointer class")
            physical = _alias_field_archive(dict(owner=owner, field=old["field"]), intervals,
                body, source_index, old.get("sequence"))
            if struct.unpack_from("<Q", body, physical)[0] != old["raw"]:
                raise ValueError("shader removal source callback differs from its physical field")
            key = (owner, old["field"].get("stream"), old["field"].get("offset"), physical)
            target_offset = target_map.get(key, target_map.get(key[:3]))
            if type(target_offset) is not int:
                raise ValueError("retained shader-removal callback lacks a physical trace target")
            old_target = old.get("target")
            old_stream = old_target.get("stream") if isinstance(old_target, dict) else _infer_target(dict(old, owner=owner), source_bases)[0]
            new_target = new.get("target")
            if isinstance(new_target, dict):
                new_stream, new_offset = new_target.get("stream"), new_target.get("offset")
            else:
                new_stream, new_offset = _infer_target(dict(new, owner=owner), output_bases)
            if old_stream != 5 or new_stream != 5 or new_offset != target_offset:
                raise ValueError(f"retained shader-removal callback {ordinal} resolved to a different native target")
            output_physical = _alias_field_archive(dict(owner=owner, field=new["field"]),
                output_intervals, output_body, output_index, new.get("sequence"))
            if struct.unpack_from("<Q", output_body, output_physical)[0] != new["raw"]:
                raise ValueError("shader removal output callback differs from its physical field")
            tag = old["raw"] >> 32
            base = output_bases.get(owner) if type(owner) is int else None
            if tag == 5:
                expected_low = target_offset + 1
            elif tag == 0x15 and type(base) is int:
                expected_low = target_offset - base + 1
            else:
                raise ValueError("retained shader-removal pointer base is unsupported")
            if new["raw"] != (tag << 32) | (expected_low & 0xFFFFFFFF):
                raise ValueError(f"retained shader-removal callback {ordinal} was not rebased")
    return dict(status="retained-shader-removal-alias-targets-pass", compared=compared,
        removed_owner_callbacks=len(before.get(removed_index, [])))


def _publish_verified_files(outputs: list[tuple[Path, bytes, str]]) -> list[dict]:
    """Publish same-volume staged files without replacing racing destinations."""
    staged: list[tuple[Path, Path, str]] = []
    linked: list[tuple[Path, Path]] = []
    try:
        for target, data, expected_sha256 in outputs:
            target = Path(target).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            if _sha(data) != expected_sha256:
                raise ValueError(f"staged bytes do not match expected hash for {target.name}")
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.stage")
            staged.append((temporary, target, expected_sha256))
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                import os
                os.fsync(stream.fileno())
            if sha256_file(temporary) != expected_sha256:
                raise IOError(f"same-volume stage hash mismatch for {target.name}")
        import os
        for temporary, target, expected_sha256 in staged:
            # Hard-link creation is atomic and fails if target appeared after
            # validation; it never truncates or replaces a racing file.
            os.link(temporary, target)
            linked.append((temporary, target))
            if not os.path.samefile(temporary, target) or sha256_file(target) != expected_sha256:
                raise IOError(f"published file identity/hash mismatch for {target.name}")
        return [dict(path=str(target), sha256=sha256_file(target), bytes=target.stat().st_size)
                for _, target, _ in staged]
    except BaseException:
        import os
        for temporary, target in reversed(linked):
            try:
                if target.exists() and os.path.samefile(temporary, target):
                    target.unlink()
            except OSError:
                pass
        raise
    finally:
        for temporary, _, _ in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _inputs(workspace, zone_id: str, *, _snapshot=None):
    from workstation_fastfiles import _read_native_rows
    if _snapshot is None:
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    if (_snapshot.zone_id != zone_id or not _snapshot.native_walk or not _snapshot.native_rows or
            not _snapshot.native_walk.get("stream_trace_enabled")):
        raise ValueError("pixel shader row creation requires this zone's complete native trace")
    if hasattr(workspace, "_require_asset_request_snapshot"):
        workspace._require_asset_request_snapshot(_snapshot, zone_id)
    cache, body, walk = _snapshot.cache_path, _snapshot.body, _snapshot.native_walk
    source, profile, native_rows = _snapshot.source_path, _snapshot.source_profile, _snapshot.native_rows
    if any(patch.get("extension") == ".fc" for patch in profile.get("patches", [])):
        raise ValueError("pixel shader append does not support source FC patch chains")
    if (walk.get("identity", {}).get("body_sha256") != body.source_sha256 or
            walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
            [row["sha256"] for row in profile.get("patches", [])]):
        raise ValueError("pixel shader native trace differs from the current source FF/patch identity")
    import workstation_asset_codecs as codec
    import workstation_shader_row_operations as writer
    import workstation_shader_crud as transaction
    identity = dict(body_sha256=body.source_sha256, source_fastfile_sha256=profile["sha256"],
        patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
        native_walk_key=walk["walk_key"], native_manifest_sha256=walk["manifest_sha256"],
        stream_trace_sha256=walk["stream_trace_sha256"],
        codec_module_path=str(Path(codec.__file__).resolve()),
        codec_module_sha256=sha256_file(Path(codec.__file__)),
        writer_module_path=str(Path(writer.__file__).resolve()),
        writer_module_sha256=sha256_file(Path(writer.__file__)),
        transaction_module_path=str(Path(transaction.__file__).resolve()),
        transaction_module_sha256=sha256_file(Path(transaction.__file__)))
    return _snapshot, identity


def _tool(workspace):
    from workstation_asset_codecs import DEFAULT_DXBC_TOOL
    import os
    tool = Path(os.environ.get("REPLAY_DXBC_TOOL", str(DEFAULT_DXBC_TOOL))).expanduser().resolve(strict=True)
    return tool


def _allocate(workspace, snapshot, name: str, payload: bytes, type_id: int = TYPE_ID) -> dict:
    from workstation_fastfiles import _native_walk_artifact
    from workstation_shader_identity import allocate_identity, build_inventory, validate_inventory_set
    replay = Path(workspace.replay_executable).resolve(strict=True)
    replay_sha = sha256_file(replay)
    body_path = snapshot.cache_path / snapshot.decode_receipt["final_body_relative_path"]
    journal_path = _native_walk_artifact(snapshot.native_walk, "journal_relative_path")
    trace_path = _native_walk_artifact(snapshot.native_walk, "stream_trace_relative_path")
    manifest_path = _native_walk_artifact(snapshot.native_walk, "manifest_relative_path")
    inventory = build_inventory(body_path, journal_path, trace_path, manifest_path, replay)
    inventories = [inventory]
    fastfile_root = next((parent for parent in snapshot.cache_path.parents if parent.name == "fastfiles"), None)
    inventory_cache = fastfile_root / "_shader-identity-inventories" if fastfile_root else None
    if inventory_cache and inventory_cache.is_dir():
        for path in inventory_cache.glob("*.json"):
            try:
                candidate = json.loads(path.read_text(encoding="utf-8"))
                validate_inventory_set([candidate], replay_sha)
                if candidate.get("inventory_sha256") not in {r.get("inventory_sha256") for r in inventories}:
                    inventories.append(candidate)
            except (OSError, ValueError, TypeError, KeyError):
                continue
    if type_id == 12:
        raise ValueError("compute-shader identity is copied from its trace template; no allocator is proven")
    allocation = allocate_identity(type_id, name, payload, inventories, replay_sha)
    return allocation


def create_shader_asset(workspace, zone_id: str, name: str, content: str,
                        type_name: str, revision: str | None = None, *, _snapshot=None) -> dict:
    import workstation_asset_codecs as codec
    snapshot, source_identity = _inputs(workspace, zone_id, _snapshot=_snapshot)
    type_id = STAGE_IDS.get(type_name)
    if type_id is None:
        raise ValueError("unsupported native shader stage")
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}\.hlsl", name) or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("Shader names must be confined .hlsl paths")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Shader assembly must be nonempty text")
    if any(row.get("type_id") == type_id and row.get("name") == name
           for row in snapshot.native_rows):
        raise ValueError("Shader name already exists in the native source zone")
    from workstation_shader_crud import operations
    active = [row for row in operations(workspace, zone_id, _snapshot=snapshot)
              if row.get("operation") == "append" and row.get("type_id") == type_id and row.get("name") == name]
    if active:
        if len(active) != 1 or revision is None or active[0].get("revision") != revision:
            raise ValueError("Shader revision conflict; reload before saving")
    elif revision is not None:
        raise ValueError("staged shader append no longer exists; reload before saving")
    tool = _tool(workspace)
    tool_sha = sha256_file(tool)
    codec_sha = sha256_file(Path(codec.__file__))
    payload = codec.assemble_dxbc(content, tool=tool, asset_name=name)
    if codec.dxbc_native_shader_type(payload) != type_id:
        raise ValueError(f"DXBC assembler output does not match the requested {type_name} stage")
    if type_id == 12:
        template = next((i for i, row in enumerate(snapshot.native_rows) if row.get("type_id") == type_id), None)
        if template is None:
            raise ValueError("compute-shader creation requires a trace-owned type-12 root template")
        from workstation_trace_index import build_read_span_index
        from workstation_fastfiles import _native_walk_artifact
        spans = build_read_span_index(_native_walk_artifact(snapshot.native_walk, "stream_trace_relative_path"),
            _native_walk_artifact(snapshot.native_walk, "manifest_relative_path"), len(snapshot.body.data), selected_assets={template})
        root_span = next((s for s in spans["assets"][0]["read_spans"] if s.get("origin") == "load_stream_call" and
                          s.get("reader_start_arg") == 0 and s.get("size") == 40), None)
        if root_span is None: raise ValueError("compute template has no exact native root")
        root_at = root_span["archive_offset"]
        allocation = {"type_id": 12, "name": name,
            "identity": struct.unpack_from("<I", snapshot.body.data, root_at + 36)[0],
            "allocation_rule": "preserve trace-owned compute identity word"}
    else:
        allocation = _allocate(workspace, snapshot, name, payload, type_id)
    from workstation_shader_identity import allocate_identity
    # Allocation is recomputed from the same exact inventory set when saving;
    # the identity receipt is embedded in the immutable operation.
    compiler_receipt = dict(schema="replay120-native-shader-row-append-receipt-v1",
        status="replay120-dxbc-assemble-pass", asset_name=name, native_type_id=type_id,
        source={"sha256": _sha(content.encode("utf-8")), "utf8_bytes": len(content.encode("utf-8"))},
        compiler={"path": str(tool), "sha256": tool_sha,
                  "codec_module_path": str(Path(codec.__file__).resolve()),
                  "codec_module_sha256": codec_sha},
        identity_allocation=allocation,
        result={"native_payload_sha256": _sha(payload), "native_payload_bytes": len(payload),
                "native_type_id": type_id, "program_identity": allocation["identity"]})
    cache = snapshot.cache_path
    from workstation_asset_operations import _operation_id, new_asset_identity
    operation_id = _operation_id("append", name, None, type_id)
    asset_id = new_asset_identity(zone_id, type_id, name)
    compiler_bytes = json.dumps(compiler_receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    row = dict(schema=4, operation="append", operation_id=operation_id,
        asset_id=asset_id, zone_id=zone_id, type_id=type_id, type=type_name, name=name,
        index=None, xasset_index=None, content=content, language="dxbc-asm",
        source_body_sha256=snapshot.body.source_sha256, content_sha256=_sha(content.encode("utf-8")),
        native_source_identity=source_identity, compiler_receipt=compiler_receipt,
        compiler_receipt_sha256=_sha(compiler_bytes),
        writer_identity={"path": source_identity["writer_module_path"],
                         "sha256": source_identity["writer_module_sha256"]})
    workspace._assert_asset_snapshot_current(snapshot)
    staged = stage_operation(cache, row, payload, revision)
    return dict(**staged, status="native-pixelshader-append-staged" if type_id == 17 else "native-shader-append-staged", editable=True,
        archive_writable=False, payload_format=f"Replay type-{type_id} inline DXBC {type_name}",
        package_status="Shader append queued for complete native reread")


def create_pixel_shader_asset(workspace, zone_id: str, name: str, content: str,
                              revision: str | None = None, *, _snapshot=None) -> dict:
    return create_shader_asset(workspace, zone_id, name, content, "pixelshader", revision, _snapshot=_snapshot)


def remove_shader_asset(workspace, asset_id: str, revision: str) -> dict:
    from workstation_fastfiles import _native_walk_artifact, sha256_file
    from workstation_trace_index import build_read_span_index
    from workstation_native_asset_edits import read_inline_shader
    from workstation_asset_operations import _operation_id, stage_operation
    zone_id, sep, index_text = asset_id.rpartition(":")
    if not sep or not index_text.isdecimal(): raise ValueError("shader removal requires a native asset ID")
    snapshot, source_identity = _inputs(workspace, zone_id)
    index = int(index_text)
    if not 0 <= index < len(snapshot.body.assets): raise KeyError(asset_id)
    native = snapshot.native_rows[index]; type_id = snapshot.body.assets[index].type_id
    if type_id not in STAGE_NAMES or native.get("name") is None:
        raise ValueError("selected asset is not a named native shader")
    if index != len(snapshot.body.assets)-1:
        raise ValueError("shader removal requires the exact final XAsset row")
    if any(item.get("asset_id") == asset_id for item in operations(workspace, zone_id, _snapshot=snapshot)):
        raise ValueError("shader with a staged operation cannot be removed")
    current = workspace.get_asset(asset_id)
    if current.get("revision") != revision or current.get("name") != native.get("name") or current.get("type_id") != type_id:
        raise ValueError("shader removal revision or native identity changed")
    trace_path = _native_walk_artifact(snapshot.native_walk, "stream_trace_relative_path")
    manifest_path = _native_walk_artifact(snapshot.native_walk, "manifest_relative_path")
    indexed = build_read_span_index(trace_path, manifest_path, len(snapshot.body.data))
    trace_row = indexed["assets"][index]
    trace_row.update(index=index, xasset_index=index, type_id=type_id, name=native["name"])
    layout = read_inline_shader(snapshot.body.data, dict(index=index,type_id=type_id,name=native["name"]),
        trace_row, snapshot.body.source_sha256, trace_assets=indexed["assets"] if type_id == 12 else None)
    content = current.get("content")
    if not isinstance(content, str): raise ValueError("shader removal requires the current readable assembly revision")
    receipt = dict(schema="replay120-native-shader-row-remove-receipt-v1",status="native-shader-row-removal-staged",
        asset_name=native["name"],type_id=type_id,source_index=index,source_body_sha256=snapshot.body.source_sha256,
        source_fastfile_sha256=snapshot.source_profile["sha256"],stream_trace_sha256=sha256_file(trace_path),
        native_manifest_sha256=sha256_file(manifest_path),native_payload_sha256=_sha(layout["program"]))
    receipt_bytes=json.dumps(receipt,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    op_id=_operation_id("remove",native["name"],index,type_id)
    staged_row=dict(schema=4,operation="remove",operation_id=op_id,asset_id=asset_id,zone_id=zone_id,
        type_id=type_id,type=STAGE_NAMES[type_id],name=native["name"],index=index,xasset_index=index,
        content=content,language="dxbc-asm",source_body_sha256=snapshot.body.source_sha256,
        content_sha256=_sha(content.encode()),native_source_identity=source_identity,
        compiler_receipt=receipt,compiler_receipt_sha256=_sha(receipt_bytes),
        writer_identity=dict(path=source_identity["writer_module_path"],sha256=source_identity["writer_module_sha256"]))
    workspace._assert_asset_snapshot_current(snapshot)
    staged=stage_operation(snapshot.cache_path,staged_row,layout["program"],None)
    return dict(**staged,status="native-shader-remove-staged",editable=False,archive_writable=False,
        package_status="Shader removal queued for exclusive final-row trace proof")


def operations(workspace, zone_id: str, *, _snapshot=None) -> list[dict]:
    snapshot, identity = _inputs(workspace, zone_id, _snapshot=_snapshot)
    results = []
    paths = list(snapshot.cache_path.glob("pending-edits/op-a-p-*/current.json")) + list(snapshot.cache_path.glob("pending-edits/op-r-*/current.json"))
    for path in sorted(paths):
        raw = json.loads(path.read_text(encoding="utf-8"))
        type_id = raw.get("type_id")
        if type_id not in STAGE_NAMES:
            continue
        row, payload = validate_operation(snapshot.cache_path, path, identity)
        if row.get("type") != STAGE_NAMES[type_id] or row.get("zone_id") != zone_id or row.get("operation") not in ("append", "remove"):
            raise ValueError("staged shader operation has an unexpected identity")
        if row.get("operation") == "remove":
            if row.get("index") != len(snapshot.body.assets)-1 or snapshot.body.assets[row["index"]].type_id != type_id:
                raise ValueError("staged shader removal is no longer the exact final source row")
            row["pending_path"] = str(path)
            row["_payload"] = payload
            results.append(row)
            continue
        import workstation_asset_codecs as codec
        tool = _tool(workspace)
        receipt = row.get("compiler_receipt", {})
        compiler = receipt.get("compiler", {})
        if (compiler.get("path") != str(tool) or compiler.get("sha256") != sha256_file(tool) or
                compiler.get("codec_module_path") != str(Path(codec.__file__).resolve()) or
                compiler.get("codec_module_sha256") != sha256_file(Path(codec.__file__)) or
                codec.dxbc_native_shader_type(payload) != type_id):
            raise ValueError("staged shader compiler or DXBC identity is stale")
        row["pending_path"] = str(path)
        row["_payload"] = payload
        results.append(row)
    if len({(row["type_id"], row["name"]) for row in results}) != len(results):
        raise ValueError("duplicate staged shader append identities")
    return results


def get_new_pixel_shader_asset(workspace, asset_id: str, *, _snapshot=None) -> dict:
    zone_id, marker = asset_id.rsplit(":", 1)
    if not re.fullmatch(r"new-(?:(?:12|14|15|16|17)-)?[0-9a-f]{32}", marker):
        raise ValueError("malformed staged shader identity")
    rows = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
            if row.get("asset_id") == asset_id]
    if len(rows) != 1:
        raise KeyError(asset_id)
    row = rows[0]
    return dict(**{key: value for key, value in row.items() if not key.startswith("_")},
        editable=True, archive_writable=False,
        payload_format=f"Replay type-{row['type_id']} inline DXBC {row['type']}",
        package_status="Shader append queued for complete native reread")


def get_new_shader_asset(workspace, asset_id: str, *, _snapshot=None) -> dict:
    return get_new_pixel_shader_asset(workspace, asset_id, _snapshot=_snapshot)


def plan_pixelshader_crud(workspace, zone_id: str, pending_rows: list[dict], *, _snapshot=None) -> dict:
    if _snapshot is None:
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    active = {row["operation_id"]: row for row in operations(workspace, zone_id, _snapshot=_snapshot)}
    requested = [row.get("operation_id") for row in pending_rows]
    if len(requested) != 1 or len(set(requested)) != 1 or set(requested) != set(active):
        raise ValueError("shader row operations preflight supports one exact staged operation")
    submitted = pending_rows[0]
    row = active[requested[0]]
    if submitted.get("revision") != row.get("revision") or submitted.get("operation") != row.get("operation"):
        raise ValueError("shader operation changed during preflight")
    if row.get("operation") == "remove":
        if row.get("index") != len(_snapshot.body.assets)-1:
            raise ValueError("shader removal is not the exact final source row")
        return dict(source_body_sha256=_snapshot.body.source_sha256,
            native_walk_key=_snapshot.native_walk["walk_key"], original_xasset_count=len(_snapshot.body.assets),
            final_xasset_count=len(_snapshot.body.assets)-1, operation_count=1,
            edits=[dict(operation="remove", operation_id=row["operation_id"], asset_id=row["asset_id"],
                revision=row["revision"], type=row["type"], type_id=row["type_id"], name=row["name"], index=row["index"])],
            support="native-shader-exclusive-final-row-removal-transaction",
            limits="One trace-exclusive final type-12/14/15/16/17 shader row whose root, owned strings, DXBC and EOF extent are fully mapped")
    if row["name"] in {native.get("name") for native in _snapshot.native_rows
                        if native.get("type_id") == row["type_id"]}:
        raise ValueError("shader name already exists in the native source zone")
    return dict(source_body_sha256=_snapshot.body.source_sha256,
        native_walk_key=_snapshot.native_walk["walk_key"], original_xasset_count=len(_snapshot.body.assets),
        final_xasset_count=len(_snapshot.body.assets)+1, operation_count=1,
        edits=[dict(operation="append", operation_id=row["operation_id"], asset_id=row["asset_id"],
                    revision=row["revision"], type=row["type"], type_id=row["type_id"], name=row["name"])],
        support="pixelshader-row-append-native-transaction" if row["type_id"] == 17 else "native-shader-row-append-transaction",
        limits="One trace-supported type-12/14/15/16/17 inline-name 40-byte root using its exact native string/alignment/DXBC schedule")


def _select_shader_append_template(type_id: int, candidate_indices: list[int],
                                  native_rows: list[dict], span_by_index: dict,
                                  body_data: bytes) -> int:
    """Choose only a complete, source-observed append layout for this stage.

    Rows with a native type alone are not templates: select by the root's
    complete observed inline/sentinel shape and the ordered name, optional
    vertex secondary-string, and DXBC read schedule. Packed q8 aliases are
    accepted only for hull/domain templates, whose append writer preserves
    their trace-rebased value; they are not interpreted as scalar flags.
    """
    import struct
    from workstation_shader_row_operations import INLINE_POINTER, SHADER_ROOT_SIZE
    for index in candidate_indices:
        trace_row = span_by_index.get(index)
        if not isinstance(trace_row, dict) or trace_row.get("index") != index:
            continue
        native = native_rows[index]
        name = native.get("name")
        if not isinstance(name, str) or not name:
            continue
        spans = trace_row.get("read_spans")
        if not isinstance(spans, list):
            continue
        roots = [s for s in spans if s.get("origin") == "load_stream_call" and
                 s.get("reader_start_arg") == 0 and s.get("size") == SHADER_ROOT_SIZE]
        if len(roots) != 1:
            continue
        root_at = roots[0].get("archive_offset")
        if type(root_at) is not int or root_at < 0 or root_at + SHADER_ROOT_SIZE > len(body_data):
            continue
        q0, q8, q16, q24 = struct.unpack_from("<QQQQ", body_data, root_at)
        if q0 != INLINE_POINTER or q16 != 0 or q24 != INLINE_POINTER:
            continue
        if type_id == 12:
            q8_ok = q8 == 0x0000001500000001
        elif type_id == 14:
            q8_ok = q8 == 0xFFFFFFFFFFFFFFFF
        else:
            q8_ok = (q8 >> 32) == 5
        if not q8_ok:
            continue
        name_bytes = name.encode("utf-8") + b"\0"
        name_spans = [s for s in spans if s.get("origin") == "string_data" and
                      s.get("size") == len(name_bytes) and type(s.get("archive_offset")) is int and
                      body_data[s["archive_offset"]:s["archive_offset"] + s["size"]] == name_bytes]
        if len(name_spans) != 1:
            continue
        extras = [s for s in spans if s.get("origin") == "string_data" and s not in name_spans]
        if len(extras) != (1 if type_id == 14 else 0):
            continue
        if extras:
            extra = extras[0]
            extra_at = extra.get("archive_offset")
            if (type(extra_at) is not int or type(extra.get("size")) is not int or extra.get("size") < 1 or
                    extra_at < 0 or extra_at + extra["size"] > len(body_data) or
                    not body_data[extra_at:extra_at + extra["size"]].endswith(b"\0")):
                continue
        program_size = struct.unpack_from("<I", body_data, root_at + 32)[0]
        programs = [s for s in spans if s.get("origin") == "load_stream_call" and
                    s.get("reader_start_arg") == 0 and s.get("size") == program_size and
                    type(s.get("archive_offset")) is int and program_size >= 32 and
                    body_data[s["archive_offset"]:s["archive_offset"] + 4] == b"DXBC"]
        if len(programs) != 1:
            continue
        # The selected row's physical event order must match the stage's
        # observed schedule: root, primary name, optional vertex string,
        # then the native DXBC load.
        ordered = [s.get("event_sequence") for s in [roots[0], name_spans[0], *extras, programs[0]]]
        if any(type(seq) is not int for seq in ordered) or ordered != sorted(ordered):
            continue
        return index
    raise ValueError(f"source zone has no complete append-template schedule for shader type {type_id}")


def build_workspace_pixelshader_crud(workspace, zone_id: str, plan: dict, output: Path,
                                     timeout: int, *, _snapshot=None) -> dict:
    from workstation_trace_index import build_read_span_index
    from workstation_shader_row_operations import append_native_shader_tail
    if _snapshot is None:
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    rows = operations(workspace, zone_id, _snapshot=_snapshot)
    if len(rows) != 1 or len(plan.get("edits", [])) != 1 or rows[0]["revision"] != plan["edits"][0].get("revision"):
        raise ValueError("pixel shader append changed after preflight")
    operation = rows[0]
    stage_id = operation["type_id"]
    stage_name = operation["type"]
    workspace._assert_asset_snapshot_current(_snapshot)
    walk = _snapshot.native_walk
    trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
    journal_path = _native_walk_artifact(walk, "journal_relative_path")
    template_candidates = [i for i, row in enumerate(_snapshot.native_rows)
                           if row.get("type_id") == stage_id and row.get("status") != "reference"]
    if not template_candidates:
        raise ValueError(f"source zone has no fully traced type-{stage_id} root template")
    final_index = len(_snapshot.body.assets)-1
    spans = build_read_span_index(trace_path, manifest_path, len(_snapshot.body.data),
                                  selected_assets=sorted({*template_candidates, final_index}))
    span_by_index = {row["index"]: row for row in spans["assets"]}
    template_index = _select_shader_append_template(stage_id, template_candidates,
        _snapshot.native_rows, span_by_index, _snapshot.body.data)
    template = dict(span_by_index[template_index], name=_snapshot.native_rows[template_index]["name"],
                    xasset_index=template_index, type_id=stage_id)
    final = dict(span_by_index[final_index], name=_snapshot.native_rows[final_index].get("name"),
                 xasset_index=final_index, type_id=_snapshot.native_rows[final_index]["type_id"])
    identity = operation["compiler_receipt"]["identity_allocation"]["identity"]
    # ACTS keeps its native manifest and stream trace as separate artifacts.
    # Bind the exact trace digest before the low-level schedule replay; never
    # mutate the source manifest or treat its filename as trace identity.
    from workstation_luafile_crud import _bind_native_manifest_to_trace
    import os
    binding_root = Path(os.environ.get("TEMP", r"C:\\Temp")).resolve()
    binding_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shader-append-source-bind-", dir=binding_root) as temp:
        bound_manifest_path = Path(temp) / "source-manifest.trace-bound.json"
        source_binding = _bind_native_manifest_to_trace(manifest_path, trace_path,
            len(_snapshot.body.data), bound_manifest_path, journal_path=journal_path)
        if (source_binding.get("raw_manifest_sha256") != walk.get("manifest_sha256") or
                source_binding.get("trace_sha256") != walk.get("stream_trace_sha256")):
            raise ValueError("shader append source manifest/trace differs from the pinned native-walk receipt")
        bound_manifest = json.loads(bound_manifest_path.read_text(encoding="utf-8"))
        updated, writer_receipt = append_native_shader_tail(_snapshot.body.data, stage_id, operation["name"],
            operation["_payload"], identity, {r.get("name") for r in _snapshot.native_rows if r.get("type_id")==stage_id},
            template_index, _snapshot.native_rows[template_index]["name"], template, final,
            _snapshot.body.source_sha256, trace_path, bound_manifest_path)
        writer_receipt["source_manifest_binding"] = dict(
            raw_manifest_path=source_binding["raw_manifest_path"],
            raw_manifest_sha256=source_binding["raw_manifest_sha256"],
            accounted_manifest_sha256=source_binding["accounted_manifest_sha256"],
            bound_manifest_sha256=source_binding["bound_manifest_sha256"],
            trace_sha256=source_binding["trace_sha256"],
            manifest=bound_manifest)
    from workstation_shader_row_operations import INLINE_POINTER
    updated_zone = ZoneBody.parse(updated)
    if (len(updated_zone.assets) != len(_snapshot.body.assets) + 1 or
            updated_zone.assets[-1].type_id != stage_id or
            updated_zone.assets[-1].pointer_token != INLINE_POINTER):
        raise ValueError("pixel shader writer changed an unexpected XAsset row")
    root_at = writer_receipt.get("appended_root_archive_offset")
    if type(root_at) is not int or root_at < 0 or root_at + 40 > len(updated):
        raise ValueError("pixel shader writer did not return a valid typed-root location")
    root_bytes = updated[root_at:root_at+40]
    name_bytes = operation["name"].encode("utf-8") + b"\0"
    if stage_id == 12:
        expected_q8 = 0x0000001500000001
    elif stage_id == 14:
        expected_q8 = 0xFFFFFFFFFFFFFFFF
    elif stage_id == 17:
        expected_q8 = (5 << 32) | (writer_receipt["stream5_name_range"][0] + 1)
    else:
        # Hull/domain roots retain their source q8 alias after physical
        # table-growth rebasing; the low-level receipt reports that exact word.
        expected_q8 = writer_receipt.get("packed_name_token")
    secondary = bytes.fromhex(writer_receipt.get("secondary_string_hex", ""))
    name_end = root_at + 40 + len(name_bytes)
    name_stream_start = writer_receipt["stream5_name_range"][0]
    program_stream_start = writer_receipt["stream5_program_range"][0]
    if (type(name_stream_start) is not int or type(program_stream_start) is not int or
            program_stream_start < name_stream_start):
        raise ValueError("shader writer returned an invalid stream-5 name/program schedule")
    padding_at = name_end + len(secondary)
    program_end_stream = writer_receipt["stream5_program_range"][1]
    if type(program_end_stream) is not int or program_end_stream - program_stream_start != len(operation["_payload"]):
        raise ValueError("shader writer stream-5 program extent differs from the staged DXBC length")
    # DXBC is the serialized tail in this append layout. Verify it at that
    # physical archive range, then independently reconcile the preceding gap
    # against the stream-5 schedule (the two coordinate spaces are distinct).
    program_at = len(updated) - len(operation["_payload"])
    logical_gap = program_stream_start - name_stream_start - len(name_bytes) - len(secondary)
    archive_gap = program_at - padding_at
    if logical_gap < 0 or archive_gap != logical_gap:
        raise ValueError("shader writer archive padding differs from the trace-derived stream-5 schedule")
    if (struct.unpack_from("<Q", root_bytes, 0)[0] != INLINE_POINTER or
            struct.unpack_from("<Q", root_bytes, 8)[0] != expected_q8 or
            struct.unpack_from("<I", root_bytes, 32)[0] != len(operation["_payload"]) or
            struct.unpack_from("<I", root_bytes, 36)[0] != operation["compiler_receipt"]["identity_allocation"]["identity"] or
            updated[root_at+40:root_at+40+len(name_bytes)] != name_bytes or
            updated[name_end:name_end+len(secondary)] != secondary or
            updated[padding_at:program_at] != b"\0" * (program_at-padding_at) or
            updated[program_at:program_at+len(operation["_payload"])] != operation["_payload"]):
        raise ValueError("pixel shader writer output differs from the staged root/name/DXBC identity")
    profile = _snapshot.source_profile
    source_reservations = profile["final_header"].get("block_sizes", [])
    reservations = writer_receipt["stream_reservation_highwaters"]
    if len(source_reservations) != len(reservations):
        raise ValueError("pixel shader source header has an unexpected stream reservation count")
    reservations = [max(source, derived) for source, derived in zip(
        source_reservations, reservations, strict=True)]
    writer_receipt["stream_reservation_highwaters"] = reservations
    package = pack_replay_uncompressed(updated, reservations,
        xfile_version=profile["final_header"]["xfile_version"],
        transient_type=profile["header"]["transient_type"])
    output = Path(output).resolve()
    if output.exists() or output.suffix.casefold() != ".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("pixel shader output must be a new .ff outside the configured game directory")
    sidecar_targets = [output.with_suffix(patch["extension"]) for patch in profile.get("patches", [])]
    receipt_target = output.with_suffix(output.suffix + ".edit-receipt.json")
    if any(path.exists() for path in [*sidecar_targets, receipt_target]):
        raise FileExistsError("pixel shader output sidecar or receipt already exists")

    # Keep all candidate files private until native validation and identity
    # comparisons succeed. verify_native requires the canonical source basename.
    import os
    temp_root = Path(os.environ.get("TEMP", r"C:\\Temp")).resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pixelshader-stage-", dir=temp_root) as staging:
        stage = Path(staging)
        staged_ff = stage / _snapshot.source_path.name
        staged_ff.write_bytes(package)
        staged_body = stage / "candidate.dec"
        staged_body.write_bytes(updated)
        for patch in profile.get("patches", []):
            staged_ff.with_suffix(patch["extension"]).write_bytes(
                make_replay_header_only_patch(Path(patch["path"]).read_bytes(), package))
        staged_artifacts = {".ff": dict(path=staged_ff, sha256=sha256_file(staged_ff),
                                         bytes=staged_ff.stat().st_size)}
        for patch in profile.get("patches", []):
            artifact = staged_ff.with_suffix(patch["extension"])
            staged_artifacts[patch["extension"]] = dict(path=artifact,
                sha256=sha256_file(artifact), bytes=artifact.stat().st_size)
        native = verify_native(staged_ff, updated, _snapshot.source_path, workspace.acts_path,
            workspace.replay_executable, stage / "native-proof", timeout=timeout, trace=True)
        if any(sha256_file(item["path"]) != item["sha256"] for item in staged_artifacts.values()):
            raise ValueError("native verifier changed a staged FF or patch artifact")
        manifest = native.get("manifest", {})
        expected_count = len(_snapshot.body.assets) + 1
        if (not manifest.get("complete") or not manifest.get("success") or
                manifest.get("top_level_index") != expected_count or
                manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
                manifest.get("serialized_bytes_read") != len(updated)):
            raise ValueError("pixel shader append failed the complete exact-EOF Replay native reread")
        if len(_snapshot.native_rows) != len(_snapshot.body.assets):
            raise ValueError("shader append requires normalized source identities for the complete XAsset table")
        expected_rows = [dict(type_id=row.get("type_id"), name=row.get("name")) for row in _snapshot.native_rows]
        expected_rows.append(dict(type_id=stage_id, name=operation["name"]))
        expected_references = _reference_identities(_snapshot.native_rows, _snapshot.body.data)
        output_manifest_path = Path(native["manifest_path"])
        trace_output = output_manifest_path.parent / manifest.get("stream_trace", "stream-trace.jsonl")
        native_rows = _verified_native_rows(native, updated, expected_rows, expected_references, trace_output)
        journal_path = output_manifest_path.parent / manifest.get("journal", "assets.jsonl")
        from roundtrip_replay_fastfile import ordered_asset_identity_sha256
        identity_hash = native.get("normalized_asset_identity_sha256", native.get("journal_asset_identity_sha256"))
        if identity_hash != ordered_asset_identity_sha256(expected_rows):
            raise ValueError("normalized native inventory identity/order differs from the staged XAsset table")
        if stage_id != 14:
            packed_events = []
            with trace_output.open("r", encoding="utf-8") as stream:
                for line in stream:
                    event = json.loads(line)
                    if (event.get("kind") == "packed_resolve" and event.get("xasset_index") == expected_count - 1 and
                            event.get("field_stream_location") == {"stream": 1, "offset": 8}):
                        packed_events.append(event)
            token = struct.unpack_from("<Q", updated, root_at + 8)[0]
            if stage_id in (12, 17):
                expected_name_offset = writer_receipt["stream5_name_range"][0]
            else:
                expected_name_offset = (token & 0xFFFFFFFF) - 1
            if (len(packed_events) != 1 or packed_events[0].get("raw_token") != token or
                    packed_events[0].get("resolved_target_stream_location") !=
                    {"stream": 5, "offset": expected_name_offset}):
                raise ValueError("native trace did not resolve the appended stage pointer to its stage-owned/shared name")

        # Compare every retained shader's root identity and exact inline DXBC
        # digest using complete source and output trace inventories.
        from workstation_shader_identity import build_inventory
        body_path = _snapshot.cache_path / _snapshot.decode_receipt["final_body_relative_path"]
        source_inventory = build_inventory(body_path, _native_walk_artifact(_snapshot.native_walk, "journal_relative_path"),
            _native_walk_artifact(_snapshot.native_walk, "stream_trace_relative_path"),
            _native_walk_artifact(_snapshot.native_walk, "manifest_relative_path"), Path(workspace.replay_executable),
            normalized_rows=_snapshot.native_rows)
        output_inventory = build_inventory(staged_body, journal_path, trace_output,
            Path(native["manifest_path"]), Path(workspace.replay_executable), normalized_rows=native_rows)
        old_shaders = source_inventory["shaders"]
        new_shaders = output_inventory["shaders"]
        from workstation_luafile_operations import XASSET_ROW_SIZE
        table_boundary = _snapshot.body.first_payload_offset
        def relocate_inventory_row(row):
            expected = dict(row)
            for key in ("root_archive_offset", "name_archive_offset"):
                value = expected.get(key)
                if type(value) is int and value >= table_boundary:
                    expected[key] = value + XASSET_ROW_SIZE
            return expected
        expected_shader_count = len(old_shaders) + (stage_id != 12)
        if (len(new_shaders) != expected_shader_count or
                new_shaders[:len(old_shaders)] != [relocate_inventory_row(row) for row in old_shaders]):
            raise ValueError("native reread changed retained shader semantics or trace-mapped archive ownership")
        appended = None if stage_id == 12 else new_shaders[-1]
        if (stage_id != 12 and (appended.get("asset_index") != expected_count - 1 or appended.get("type_id") != stage_id or
                appended.get("name") != operation["name"] or appended.get("program_identity") != identity or
                appended.get("program_size") != len(operation["_payload"]) or
                appended.get("inline_dxbc_sha256") != _sha(operation["_payload"]) or
                appended.get("inline_dxbc_unique") is not True)):
            raise ValueError("native reread type-17 root or inline DXBC differs from the staged shader")

        if stage_id == 12:
            from workstation_native_asset_edits import read_inline_shader
            output_trace_row = next((r for r in native_rows if r.get("type_id") == 12 and r.get("name") == operation["name"]), None)
            trace_spans = build_read_span_index(trace_output, Path(native["manifest_path"]), len(updated), selected_assets={expected_count-1})
            appended = read_inline_shader(updated, dict(output_trace_row, index=expected_count-1),
                trace_spans["assets"][0], _sha(updated), trace_assets=trace_spans["assets"])
            if (appended.get("program_identity") != identity or
                    appended.get("program_sha256") != _sha(operation["_payload"])):
                raise ValueError("native reread compute root or inline DXBC differs from the staged shader")

        # Shared semantic checks cover the retained LuaFile, Localize, and
        # resident image families; packed callback events are rebound to the
        # candidate's actual trace so the relocation writer is independently
        # checked against native target ownership.
        from workstation_asset_semantics import typed_semantics
        from workstation_luafile_crud import _bind_native_manifest_to_trace
        source_journal = _native_walk_artifact(_snapshot.native_walk, "journal_relative_path")
        bound_source = stage / "source-manifest.shader-bound.json"
        bound_output = stage / "output-manifest.shader-bound.json"
        _bind_native_manifest_to_trace(Path(manifest_path), Path(trace_path),
            len(source_body_bytes := _snapshot.body.data), bound_source, journal_path=source_journal)
        _bind_native_manifest_to_trace(Path(native["manifest_path"]), trace_output,
            len(updated), bound_output, journal_path=journal_path)
        source_semantics, _, _ = typed_semantics(source_body_bytes, _snapshot.native_rows,
            Path(trace_path), bound_source)
        output_semantics, _, _ = typed_semantics(updated, native_rows, trace_output,
            bound_output)
        if source_semantics != output_semantics:
            raise ValueError("native append changed retained LuaFile, Localize, or image semantics")
        from workstation_luafile_operations import (_trace_contract, _alias_field_archive,
            XASSET_ARRAY_COUNT_OFFSET, XASSET_ROW_SIZE)
        source_contract = _trace_contract(source_body_bytes, Path(trace_path), bound_source,
            table_row_delta=XASSET_ROW_SIZE)
        output_contract = _trace_contract(updated, trace_output, bound_output, table_row_delta=0)
        source_bases, intervals, aliases = source_contract[1], source_contract[2], source_contract[3]
        output_bases = output_contract[1]
        interval_index = __import__("workstation_luafile_operations")._build_interval_index(intervals)
        from workstation_scriptfile_crud import _events_by_owner, _infer_target
        before_events = _events_by_owner(Path(trace_path))
        after_events = _events_by_owner(trace_output)
        compared_aliases = 0
        for owner, before in before_events.items():
            after = after_events.get(owner, [])
            if len(before) != len(after):
                raise ValueError(f"retained owner {owner} changed its packed callback count")
            for ordinal, (old, new) in enumerate(zip(before, after)):
                compared_aliases += 1
                if old["kind"] != new["kind"]:
                    raise ValueError(f"retained owner {owner} callback {ordinal} changed kind")
                field = old["field"]
                physical_field = _alias_field_archive(dict(owner=owner, field=field), intervals,
                    source_body_bytes, interval_index, old.get("sequence"))
                if struct.unpack_from("<Q", source_body_bytes, physical_field)[0] != old["raw"]:
                    raise ValueError(f"source callback {ordinal} differs from its live physical field")
                target_key = (owner, field.get("stream"), field.get("offset"), physical_field)
                target_offset = source_contract[7].get(target_key,
                    source_contract[7].get(target_key[:3]))
                if type(target_offset) is not int:
                    raise ValueError(f"source trace has no relocated target map for retained owner {owner}")
                old_target = old.get("target")
                old_stream = old_target.get("stream") if isinstance(old_target, dict) else _infer_target(dict(old, owner=owner), source_bases)[0]
                new_target = new.get("target")
                if isinstance(new_target, dict):
                    new_stream, new_offset = new_target.get("stream"), new_target.get("offset")
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
                    raise ValueError(f"retained owner {owner} callback {ordinal} token was not rebased")
        alias_proof = dict(status="retained-alias-targets-pass", compared=compared_aliases,
            appended_owner_callbacks=len(after_events.get(expected_count - 1, [])))
        allowed = set(range(XASSET_ARRAY_COUNT_OFFSET, XASSET_ARRAY_COUNT_OFFSET + 4))
        for alias in aliases:
            alias_at = _alias_field_archive({"owner": alias[0],
                "field": {"stream": alias[2], "offset": alias[3]}}, intervals,
                source_body_bytes, interval_index, alias[6])
            allowed.update(range(alias_at, alias_at + 8))
        compared_bytes = 0
        for source_at, value in enumerate(source_body_bytes):
            if source_at in allowed:
                continue
            output_at = source_at + (XASSET_ROW_SIZE if source_at >= table_boundary else 0)
            if output_at >= len(updated) or updated[output_at] != value:
                raise ValueError(f"append changed retained serialized byte outside table/alias mapping at {source_at:#x}")
            compared_bytes += 1
        workspace._assert_asset_snapshot_current(_snapshot)
        fresh_operations = operations(workspace, zone_id, _snapshot=_snapshot)
        if len(fresh_operations) != 1 or fresh_operations[0].get("revision") != operation["revision"]:
            raise ValueError("pixel shader pending revision changed before publication")
        current_tool = _tool(workspace)
        if (sha256_file(current_tool) != operation["compiler_receipt"]["compiler"]["sha256"] or
                sha256_file(Path(operation["native_source_identity"]["writer_module_path"])) !=
                    operation["native_source_identity"]["writer_module_sha256"] or
                sha256_file(Path(operation["native_source_identity"]["transaction_module_path"])) !=
                    operation["native_source_identity"]["transaction_module_sha256"]):
            raise ValueError("pixel shader compiler or writer changed before publication")

        # Build a JSON-safe receipt and pin staging hashes before any final
        # destination is created. Publish each path by exclusive same-volume
        # hard link so races cannot replace an existing user file.
        native_summary = {key: manifest.get(key) for key in
            ("status", "complete", "success", "loaded_assets", "tested", "failed", "unavailable", "serialized_bytes_read")}
        sidecar_receipts = [dict(path=str(output.with_suffix(ext)), sha256=item["sha256"], bytes=item["bytes"])
            for ext, item in staged_artifacts.items() if ext != ".ff"]
        safe_semantics = [dict(type_id=key[0], name=key[1], sha256=value)
            for key, value in sorted(source_semantics.items())]
        receipt = dict(schema="replay120-pixelshader-row-append-v2", status="native-pixelshader-row-append-pass",
            zone_id=zone_id, edits=[dict(asset_id=operation["asset_id"], revision=operation["revision"])],
            source=dict(fastfile_sha256=profile["sha256"], body_sha256=_snapshot.body.source_sha256,
                native_walk_key=walk["walk_key"], manifest_sha256=walk["manifest_sha256"],
                stream_trace_sha256=walk["stream_trace_sha256"]),
            output_fastfile=dict(path=str(output), sha256=staged_artifacts[".ff"]["sha256"],
                bytes=staged_artifacts[".ff"]["bytes"]),
            sidecars=sidecar_receipts, native_reader=native_summary,
            ordered_identity_sha256=identity_hash, retained_shader_count=len(old_shaders),
            appended_shader=appended, retained_typed_semantics=safe_semantics,
            retained_serialized_bytes=compared_bytes, alias_targets=alias_proof, writer=writer_receipt,
            native_trace_sha256=sha256_file(trace_output))
        receipt_bytes = (json.dumps(receipt, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        output_blobs = [(output, staged_ff.read_bytes(), staged_artifacts[".ff"]["sha256"])]
        for patch in profile.get("patches", []):
            item = staged_artifacts[patch["extension"]]
            output_blobs.append((output.with_suffix(patch["extension"]),
                item["path"].read_bytes(), item["sha256"]))
        output_blobs.append((receipt_target, receipt_bytes, _sha(receipt_bytes)))
        if any(sha256_file(item["path"]) != item["sha256"] for item in staged_artifacts.values()):
            raise ValueError("staged package or patch hash changed before publication")
        workspace._assert_asset_snapshot_current(_snapshot)
        fresh_operations = operations(workspace, zone_id, _snapshot=_snapshot)
        if len(fresh_operations) != 1 or fresh_operations[0].get("revision") != operation["revision"]:
            raise ValueError("pixel shader pending revision changed immediately before publication")
        current_tool = _tool(workspace)
        if (sha256_file(current_tool) != operation["compiler_receipt"]["compiler"]["sha256"] or
                sha256_file(Path(operation["native_source_identity"]["writer_module_path"])) !=
                    operation["native_source_identity"]["writer_module_sha256"] or
                sha256_file(Path(operation["native_source_identity"]["transaction_module_path"])) !=
                    operation["native_source_identity"]["transaction_module_sha256"]):
            raise ValueError("pixel shader compiler or writer changed immediately before publication")
        published = _publish_verified_files(output_blobs)
        published_sidecars = [item for item in published if Path(item["path"]) != receipt_target and
                               Path(item["path"]) != output]
        return dict(schema=receipt["schema"], status=receipt["status"], zone_id=zone_id,
            edits=receipt["edits"], output_fastfile=str(output), output_fastfile_sha256=receipt["output_fastfile"]["sha256"],
            sidecars=published_sidecars, receipt_path=str(receipt_target), native_reader=native_summary,
            appended_name=operation["name"], appended_program_identity=identity, writer=writer_receipt)


def build_workspace_shader_remove(workspace, zone_id: str, plan: dict, output: Path,
                                  timeout: int, *, _snapshot=None) -> dict:
    """Package and fully reread one exclusive final native shader removal."""
    from workstation_fastfiles import (_native_walk_artifact, pack_replay_uncompressed,
        make_replay_header_only_patch, sha256_file, unpack_replay_uncompressed)
    from workstation_trace_index import build_read_span_index
    from roundtrip_replay_fastfile import verify_native, ordered_asset_identity_sha256
    from workstation_shader_row_operations import remove_final_shader_tail
    if _snapshot is None: _snapshot=workspace._validated_asset_snapshot(zone_id,require_trace=True)
    active=operations(workspace,zone_id,_snapshot=_snapshot)
    if len(active)!=1 or active[0].get("operation")!="remove" or len(plan.get("edits",[]))!=1 or active[0].get("revision")!=plan["edits"][0].get("revision"):
        raise ValueError("shader removal changed after preflight")
    operation=active[0]; index=operation["index"]; stage_id=operation["type_id"]
    workspace._assert_asset_snapshot_current(_snapshot)
    walk=_snapshot.native_walk; body=_snapshot.body; profile=_snapshot.source_profile
    trace_path=_native_walk_artifact(walk,"stream_trace_relative_path")
    manifest_path=_native_walk_artifact(walk,"manifest_relative_path")
    source_journal=_native_walk_artifact(walk,"journal_relative_path")
    indexed=build_read_span_index(trace_path,manifest_path,len(body.data))
    trace_row=indexed["assets"][index]
    trace_row.update(index=index,xasset_index=index,type_id=stage_id,name=operation["name"])
    from workstation_native_asset_edits import read_inline_shader
    selected_layout=read_inline_shader(body.data,dict(index=index,type_id=stage_id,name=operation["name"]),
        trace_row,body.source_sha256,trace_assets=indexed["assets"] if stage_id==12 else None)
    if (_sha(selected_layout["program"])!=operation.get("payload_sha256") or
            operation.get("compiler_receipt",{}).get("native_payload_sha256")!=_sha(selected_layout["program"])):
        raise ValueError("staged shader removal payload differs from the exact source row")
    from workstation_luafile_crud import _bind_native_manifest_to_trace
    import os
    temp_root=Path(os.environ.get("TEMP",r"C:\Temp")).resolve();temp_root.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shader-remove-source-proof-",dir=temp_root) as binding_dir:
        bound_source_manifest=Path(binding_dir)/"source-manifest.trace-bound.json"
        source_binding=_bind_native_manifest_to_trace(manifest_path,trace_path,len(body.data),
            bound_source_manifest,journal_path=source_journal)
        if (source_binding.get("raw_manifest_sha256")!=walk.get("manifest_sha256") or
                source_binding.get("trace_sha256")!=walk.get("stream_trace_sha256")):
            raise ValueError("shader removal source manifest/trace differs from the pinned native-walk receipt")
        candidate_body,writer_proof=remove_final_shader_tail(body.data,index,operation["name"],trace_row,
            body.source_sha256,trace_path,bound_source_manifest,trace_assets=indexed["assets"])
    if _sha(candidate_body)==body.source_sha256 or len(ZoneBody.parse(candidate_body).assets)!=len(body.assets)-1:
        raise ValueError("shader removal writer did not remove exactly one row")
    output=Path(output).resolve()
    if output.exists() or output.suffix.casefold()!=".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("shader removal output must be a new .ff outside the configured game directory")
    sidecars=[output.with_suffix(row["extension"]) for row in profile.get("patches",[])]
    receipt_target=output.with_suffix(output.suffix+".edit-receipt.json")
    if any(path.exists() for path in [*sidecars,receipt_target]): raise FileExistsError("shader removal output sidecar exists")
    from workstation_fastfiles import acts_tool_identity
    acts_path=Path(workspace.acts_path).resolve(strict=True)
    replay_path=Path(workspace.replay_executable).resolve(strict=True)
    protected_acts=acts_tool_identity(acts_path); protected_replay=sha256_file(replay_path)
    with tempfile.TemporaryDirectory(prefix="shader-remove-stage-",dir=temp_root) as temp:
        work=Path(temp); staged_ff=work/_snapshot.source_path.name
        reservations=profile["final_header"].get("block_sizes",[])
        package=pack_replay_uncompressed(candidate_body,reservations,
            xfile_version=profile["final_header"]["xfile_version"],transient_type=profile["header"]["transient_type"])
        if unpack_replay_uncompressed(package)!=candidate_body: raise ValueError("shader removal package changed decoded body")
        staged_ff.write_bytes(package)
        (work/"candidate.dec").write_bytes(candidate_body)
        for patch in profile.get("patches",[]):
            staged_ff.with_suffix(patch["extension"]).write_bytes(
                make_replay_header_only_patch(Path(patch["path"]).read_bytes(),package))
        artifacts={".ff":dict(path=staged_ff,sha256=sha256_file(staged_ff),bytes=staged_ff.stat().st_size)}
        for patch in profile.get("patches",[]):
            p=staged_ff.with_suffix(patch["extension"]);artifacts[patch["extension"]]=dict(path=p,sha256=sha256_file(p),bytes=p.stat().st_size)
        native=verify_native(staged_ff,candidate_body,_snapshot.source_path,workspace.acts_path,
            workspace.replay_executable,work/"native-proof",timeout=timeout,trace=True)
        manifest=native.get("manifest",{}); expected=len(body.assets)-1
        if (not manifest.get("complete") or not manifest.get("success") or manifest.get("top_level_index")!=expected or
            manifest.get("failed")!=0 or manifest.get("unavailable")!=0 or
            manifest.get("serialized_bytes_read")!=len(candidate_body)):
            raise ValueError("shader removal failed complete exact-EOF native reread")
        out_manifest=Path(native["manifest_path"]);out_journal=out_manifest.parent/manifest.get("journal","assets.jsonl")
        expected_rows=[dict(type_id=r.get("type_id"),name=r.get("name")) for r in _snapshot.native_rows[:-1]]
        expected_references=_reference_identities(_snapshot.native_rows[:-1],candidate_body)
        out_trace=out_manifest.parent/manifest.get("stream_trace","stream-trace.jsonl")
        output_rows=_verified_native_rows(native,candidate_body,expected_rows,expected_references,out_trace)
        identity_hash=native.get("normalized_asset_identity_sha256",native.get("journal_asset_identity_sha256"))
        if identity_hash!=ordered_asset_identity_sha256(expected_rows): raise ValueError("shader removal identity hash differs")
        from workstation_shader_identity import build_inventory
        source_inventory=build_inventory(_snapshot.cache_path/_snapshot.decode_receipt["final_body_relative_path"],
            _native_walk_artifact(walk,"journal_relative_path"),trace_path,manifest_path,
            Path(workspace.replay_executable),normalized_rows=_snapshot.native_rows)
        output_inventory=build_inventory(work/"candidate.dec",out_journal,out_trace,out_manifest,
            Path(workspace.replay_executable),normalized_rows=output_rows)
        def semantic_rows(inv):
            return [(r.get("asset_index"),r.get("type_id"),r.get("name"),r.get("program_identity"),
                     r.get("program_size"),r.get("inline_dxbc_sha256")) for r in inv["shaders"]]
        expected_shaders=[x for x in semantic_rows(source_inventory) if x[0]!=index]
        if semantic_rows(output_inventory)!=expected_shaders:
            raise ValueError("shader removal changed retained native shader semantics or identities")
        from workstation_asset_semantics import typed_semantics
        from workstation_luafile_crud import _bind_native_manifest_to_trace
        bound_source=work/"source-bound.json";bound_output=work/"output-bound.json"
        _bind_native_manifest_to_trace(manifest_path,trace_path,len(body.data),bound_source,journal_path=source_journal)
        _bind_native_manifest_to_trace(out_manifest,out_trace,len(candidate_body),bound_output,journal_path=out_journal)
        alias_proof=_verify_removed_shader_callbacks(body.data,candidate_body,trace_path,bound_source,
            out_trace,bound_output,index,writer_proof)
        before_sem,_,_=typed_semantics(body.data,_snapshot.native_rows,trace_path,bound_source)
        after_sem,_,_=typed_semantics(candidate_body,output_rows,out_trace,bound_output)
        expected_sem={key:value for key,value in before_sem.items()
                      if key!=(stage_id,operation["name"])}
        if expected_sem!=after_sem: raise ValueError("shader removal changed retained typed asset semantics")
        receipt=dict(schema="replay120-native-shader-row-remove-v2",status="native-shader-row-remove-pass",
            zone_id=zone_id,edits=[dict(asset_id=operation["asset_id"],revision=operation["revision"])],
            source_body_sha256=body.source_sha256,output_fastfile=dict(path=str(output),sha256=artifacts[".ff"]["sha256"],bytes=artifacts[".ff"]["bytes"]),
            source_native_manifest_binding=source_binding,
            native_reader={k:manifest.get(k) for k in ("complete","success","loaded_assets","tested","failed","unavailable","serialized_bytes_read")},
            ordered_identity_sha256=identity_hash,retained_shader_count=len(expected_shaders),writer=writer_proof,
            retained_alias_targets=alias_proof,retained_typed_semantics="pass",
            native_trace_sha256=sha256_file(out_trace))
        receipt_bytes=(json.dumps(receipt,indent=2,ensure_ascii=False)+"\n").encode()
        blobs=[(output,staged_ff.read_bytes(),artifacts[".ff"]["sha256"])]
        for patch in profile.get("patches",[]):
            item=artifacts[patch["extension"]];blobs.append((output.with_suffix(patch["extension"]),item["path"].read_bytes(),item["sha256"]))
        blobs.append((receipt_target,receipt_bytes,_sha(receipt_bytes)))
        workspace._assert_asset_snapshot_current(_snapshot)
        current=operations(workspace,zone_id,_snapshot=_snapshot)
        if len(current)!=1 or current[0].get("revision")!=operation["revision"]: raise ValueError("shader removal revision changed before publication")
        if any(sha256_file(item["path"])!=item["sha256"] for item in artifacts.values()): raise ValueError("staged shader removal package changed")
        if acts_tool_identity(acts_path)!=protected_acts or sha256_file(replay_path)!=protected_replay:
            raise ValueError("native reader or Replay executable changed before shader publication")
        published=_publish_verified_files(blobs)
        return dict(schema=receipt["schema"],status=receipt["status"],zone_id=zone_id,
            edits=receipt["edits"],output_fastfile=str(output),output_fastfile_sha256=artifacts[".ff"]["sha256"],
            receipt_path=str(receipt_target),native_reader=receipt["native_reader"],writer=writer_proof)
