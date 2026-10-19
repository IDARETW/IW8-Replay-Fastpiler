"""Staging and native-verified LuaFile row transactions for FastfileWorkspace.

Each append/remove is applied through the isolated row writer and verified by a
fresh Replay native walk before the next operation is attempted.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

from roundtrip_replay_fastfile import ordered_asset_identity_sha256, verify_native
from workstation_fastfiles import (ZoneBody, make_replay_header_only_patch,
    pack_replay_uncompressed, sha256_file, source_profile)
from workstation_luafile import (INLINE_POINTER, LUA_FILE_ROOT_SIZE,
    luafile_compiler_input_name)
from workstation_luajit_chunk import split_luajit_file_payload
from workstation_luafile_operations import append_luafile_tail, remove_existing_luafile_row
from workstation_trace_index import build_read_span_index


def _workspace_inputs(workspace, zone_id: str, *, _snapshot=None):
    """Bind a staged Lua row operation to the current complete Replay walk."""
    from workstation_fastfiles import _read_native_rows
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    if _snapshot is not None:
        if hasattr(workspace, '_require_asset_request_snapshot'):
            workspace._require_asset_request_snapshot(_snapshot, zone_id)
        if _snapshot.zone_id != zone_id or not _snapshot.native_walk or not _snapshot.native_rows:
            raise ValueError("LuaFile operation requires this zone's complete native request snapshot")
        cache, receipt, body = _snapshot.cache_path, _snapshot.decode_receipt, _snapshot.body
        source, profile, walk, native_rows = (_snapshot.source_path, _snapshot.source_profile,
                                               _snapshot.native_walk, _snapshot.native_rows)
    else:
        cache, receipt = workspace._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache / receipt["final_body_relative_path"]).read_bytes())
        source = Path(receipt["source"]["path"]).resolve(strict=True)
        profile = source_profile(source)
        walk, native_rows = _read_native_rows(cache, body, require_trace=True)
    if any(row.get("extension") == ".fc" for row in profile.get("patches", [])):
        raise ValueError("LuaFile row operations do not support FC patch chains")
    if (walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
            [row["sha256"] for row in profile.get("patches", [])] or
            not walk.get("stream_trace_enabled")):
        raise ValueError("LuaFile operation walk does not match the source FF/patch chain")
    import workstation_luafile_operations as writer
    import workstation_fastfiles as dispatcher
    import workstation_luafile_crud as transaction
    writer_path = Path(writer.__file__).resolve(strict=True)
    dispatcher_path = Path(dispatcher.__file__).resolve(strict=True)
    transaction_path = Path(transaction.__file__).resolve(strict=True)
    identity = dict(body_sha256=body.source_sha256,
                    source_fastfile_sha256=profile["sha256"],
                    patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
                    native_walk_key=walk["walk_key"],
                    native_manifest_sha256=walk["manifest_sha256"],
                    stream_trace_sha256=walk["stream_trace_sha256"],
                    writer_module_path=str(writer_path),
                    writer_module_sha256=sha256_file(writer_path),
                    transaction_module_path=str(transaction_path),
                    transaction_module_sha256=sha256_file(transaction_path),
                    dispatcher_module_path=str(dispatcher_path),
                    dispatcher_module_sha256=sha256_file(dispatcher_path))
    return cache, receipt, body, source, profile, walk, native_rows, identity


def _operation_id(operation: str, name: str, index: int | None = None) -> str:
    return ("op-a-l-" + _sha(name.encode("utf-8"))[:32] if operation == "append"
            else f"op-r-{index}")


def operations(workspace, zone_id: str, *, _snapshot=None) -> list[dict]:
    """Return only current, source-bound LuaFile append/remove operations."""
    from workstation_asset_operations import validate_operation
    cache, _, body, _, _, walk, native_rows, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    results = []
    for current_path in sorted(cache.glob("pending-edits/op-*/current.json")):
        candidate = json.loads(current_path.read_text(encoding="utf-8"))
        if candidate.get("type_id") != 62:
            continue
        row, payload = validate_operation(cache, current_path, identity)
        if row.get("zone_id") != zone_id or row.get("type") != "luafile":
            raise ValueError("LuaFile operation identifies another zone or native type")
        if (row.get("source_body_sha256") != body.source_sha256 or
                not isinstance(row.get("content"), str) or
                _sha(row["content"].encode("utf-8")) != row.get("content_sha256")):
            raise ValueError("LuaFile operation source text/body changed")
        receipt = row.get("compiler_receipt", {})
        if (receipt.get("asset_name") != row.get("name") or
                receipt.get("source", {}).get("sha256") != row.get("content_sha256") or
                receipt.get("result", {}).get("native_payload_sha256") != row.get("payload_sha256")):
            raise ValueError("LuaFile operation compiler receipt differs from its staged source/payload")
        stale = workspace._compiler_identity_staleness(row, 62)
        if stale:
            raise ValueError(stale)
        if row["operation"] == "remove":
            index = row.get("index")
            if (not isinstance(index, int) or isinstance(index, bool) or
                    index < 0 or index >= len(native_rows) or
                    body.assets[index].type_id != 62 or native_rows[index].get("name") != row["name"]):
                raise ValueError("LuaFile removal no longer identifies a source asset")
        row["pending_path"] = str(current_path)
        row["_payload"] = payload
        results.append(row)
    removals = {row["name"] for row in results if row["operation"] == "remove"}
    appends = [row["name"] for row in results if row["operation"] == "append"]
    if len(appends) != len(set(appends)):
        raise ValueError("duplicate staged LuaFile append names")
    for name in appends:
        if (any(item.get("type_id") == 62 and item.get("name") == name for item in native_rows)
                and name not in removals):
            raise ValueError("appended LuaFile name already exists in the native source zone")
    return results


def _stage_operation(workspace, zone_id: str, operation: str, name: str,
                     content: str, payload: bytes, index: int | None,
                     compiler_receipt: dict, expected_revision: str | None = None,
                     *, _snapshot=None) -> dict:
    from workstation_asset_operations import stage_operation
    cache, _, body, _, _, _, _, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    operation_id = _operation_id(operation, name, index)
    asset_id = (f"{zone_id}:new-{_sha(name.encode('utf-8'))[:32]}" if operation == "append"
                else f"{zone_id}:{index}")
    compiler_bytes = json.dumps(compiler_receipt, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False).encode("utf-8")
    row = dict(schema=4, operation=operation, operation_id=operation_id,
               asset_id=asset_id, zone_id=zone_id, type_id=62, type="luafile", name=name,
               index=index, xasset_index=index, content=content, language="lua",
               source_body_sha256=body.source_sha256,
               content_sha256=_sha(content.encode("utf-8")),
               native_source_identity=identity,
               compiler_receipt=compiler_receipt,
               compiler_receipt_sha256=_sha(compiler_bytes),
               writer_identity=dict(path=identity["writer_module_path"],
                                    sha256=identity["writer_module_sha256"]))
    if _snapshot is not None:
        workspace._assert_asset_snapshot_current(_snapshot)
    staged = stage_operation(cache, row, payload, expected_revision)
    return dict(**staged, status=f"native-luafile-{operation}-staged", editable=operation == "append",
                archive_writable=False,
                pending_path=str(cache / "pending-edits" / operation_id / "current.json"))


def create_luafile_asset(workspace, zone_id: str, name: str, content: str,
                         revision: str | None = None, *, _snapshot=None) -> dict:
    import re
    from workstation_lua_compile import compile_luajit_source_with_receipt
    from workstation_fastfiles import acts_tool_identity
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    cache, _, _, _, _, _, native_rows, _identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}", name) or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("Use a confined LuaFile name with letters, digits, underscores, slashes, dots or hyphens")
    pending_rows = operations(workspace, zone_id, _snapshot=_snapshot)
    staged_appends = [row for row in pending_rows
                      if row.get("type_id") == 62 and row.get("name") == name and
                      row.get("operation") == "append"]
    if (any(row.get("type_id") == 62 and row.get("name") == name for row in native_rows)
            and name not in {row["name"] for row in pending_rows if row["operation"] == "remove"}):
        raise ValueError("LuaFile name already exists in the source zone without a staged removal")
    if staged_appends:
        if len(staged_appends) != 1:
            raise ValueError("staged LuaFile append identity is ambiguous")
        if revision is None or staged_appends[0].get("revision") != revision:
            raise ValueError("Asset revision conflict; reload before saving")
    elif revision is not None:
        raise ValueError("staged LuaFile append no longer exists; reload before saving")
    acts = Path(getattr(workspace, "lua_acts_path", workspace.acts_path)).resolve(strict=True)
    replay = workspace.replay_executable.resolve(strict=True)
    profile_name = "replay120_lua_native"
    profile = workspace._lua_compiler_profile_path(acts, profile_name)
    import workstation_asset_codecs as codec
    codec_path = Path(codec.__file__).resolve(strict=True)
    acts_identity = acts_tool_identity(acts)
    replay_sha, profile_sha, codec_sha = (sha256_file(replay), sha256_file(profile),
                                          sha256_file(codec_path))
    compiler_input_name = luafile_compiler_input_name(name)
    payload, compiler_receipt = compile_luajit_source_with_receipt(
        content, acts_exe=acts, replay_executable=replay, profile_path=profile,
        profile_name=profile_name, asset_name=compiler_input_name)
    compiler_receipt["asset_name"] = name
    compiler_receipt["compiler_input_name"] = compiler_input_name
    compiler_receipt["compiler"].update(
        tool_identity=acts_identity, codec_module_path=str(codec_path),
        codec_module_sha256=codec_sha)
    if (acts_tool_identity(acts) != acts_identity or sha256_file(replay) != replay_sha or
            sha256_file(profile) != profile_sha or sha256_file(codec_path) != codec_sha):
        raise RuntimeError("Lua compiler inputs changed during native bytecode compilation")
    return _stage_operation(workspace, zone_id, "append", name, content, payload, None,
                            compiler_receipt, revision, _snapshot=_snapshot)


def remove_luafile_asset(workspace, asset_id: str, revision: str) -> dict:
    opened = workspace.get_asset(asset_id)
    if opened.get("type_id") != 62 or opened.get("type") != "luafile":
        raise ValueError("Native row removal currently supports LuaFile assets only")
    if opened.get("revision") != revision:
        raise ValueError("Asset revision conflict; reload before removing")
    if opened.get("pending_path"):
        raise ValueError("Restore the active LuaFile edit before removing this asset")
    zone_id, index_text = asset_id.rsplit(":", 1)
    index = int(index_text)
    cache, _, body, _, _, walk, native_rows, _identity = _workspace_inputs(workspace, zone_id)
    # Native walk paths may be relative to the zone cache; resolve through receipt artifacts.
    from workstation_fastfiles import _native_walk_artifact
    trace_path = _native_walk_artifact(walk, "stream_trace_relative_path")
    manifest_path = _native_walk_artifact(walk, "manifest_relative_path")
    trace = _trace_asset(trace_path, manifest_path, body.data, index, 62, opened["name"])
    _, payload = __import__("workstation_luafile").inspect_luafile(
        body.data, index, opened["name"], trace, expected_body_sha256=body.source_sha256)
    import workstation_asset_codecs as codec
    lua_acts = Path(getattr(workspace, "lua_acts_path", workspace.acts_path)).resolve(strict=True)
    from workstation_lua_compile import compiler_module_identity
    profile = workspace._lua_compiler_profile_path(lua_acts, "replay120_lua_native")
    profile_data = json.loads(profile.read_text(encoding="utf-8"))
    provenance = profile_data.get("__provenance", {})
    bindings = provenance.get("bindings", {})
    required = {"lua_newstate", "lua_loadx", "lj_cf_string_dump", "writer_buf"}
    compiler_receipt = dict(schema="replay120-luajit-existing-payload-receipt-v1",
        status="target-lua-existing-payload-preserved-pass", asset_name=opened["name"],
        source={"sha256": _sha(opened["content"].encode("utf-8")),
                "utf8_bytes": len(opened["content"].encode("utf-8"))},
        compiler={"path": str(lua_acts),
                  "sha256": sha256_file(lua_acts),
                  "common_library_path": str(lua_acts.with_name("acts-common.dll")),
                  "common_library_sha256": sha256_file(lua_acts.with_name("acts-common.dll")),
                  "tool_identity": __import__("workstation_fastfiles").acts_tool_identity(lua_acts),
                  "profile_name": "replay120_lua_native", "profile_path": str(profile),
                  "profile_sha256": sha256_file(profile),
                  "profile_database_sha256": provenance.get("database_sha256"),
                  "profile_catalog_sha256": provenance.get("catalog_sha256") or provenance.get("compiler_catalog_sha256"),
                  "replay_executable_path": str(workspace.replay_executable.resolve()),
                  "replay_executable_sha256": sha256_file(workspace.replay_executable),
                  "api_bindings": {name: dict(bindings[name]) for name in sorted(required)},
                  "codec_module_path": str(Path(codec.__file__).resolve()),
                  "codec_module_sha256": sha256_file(Path(codec.__file__)),
                  **compiler_module_identity()},
        result={"native_payload_sha256": _sha(payload), "native_payload_bytes_including_nul": len(payload),
                "native_existing_reader": "pass"})
    return _stage_operation(workspace, zone_id, "remove", opened["name"], opened["content"],
                            payload, index, compiler_receipt, revision)


def get_new_luafile_asset(workspace, asset_id: str, *, _snapshot=None) -> dict:
    zone_id, marker = asset_id.rsplit(":", 1)
    if not re.fullmatch(r"new-[0-9a-f]{32}", marker):
        raise ValueError("Malformed staged LuaFile identity")
    rows = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
            if row.get("asset_id") == asset_id]
    if len(rows) != 1 or rows[0].get("operation") != "append":
        raise KeyError(asset_id)
    row = rows[0]
    return dict(**{key: value for key, value in row.items() if not key.startswith("_")},
                editable=True, archive_writable=False, payload_format="Replay LuaJIT v2 native LuaFile",
                package_status="LuaFile append queued for sequential full-zone native reread")


def plan_luafile_crud(workspace, zone_id: str, pending_rows: list[dict], *, _snapshot=None) -> dict:
    if any(row.get("type") != "luafile" or not row.get("operation") for row in pending_rows):
        raise ValueError("LuaFile row operations cannot be mixed with staged child replacements or other asset types")
    if _snapshot is None and hasattr(workspace, "_validated_asset_snapshot"):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    current_rows = {row["operation_id"]: row for row in
                    operations(workspace, zone_id, _snapshot=_snapshot)}
    requested_ids = [item.get("operation_id") for item in pending_rows]
    if len(requested_ids) != len(set(requested_ids)) or set(requested_ids) != set(current_rows):
        raise ValueError("LuaFile preflight must include each current staged operation exactly once")
    planned = []
    for item in pending_rows:
        current = current_rows.get(item.get("operation_id"))
        if not current or current.get("revision") != item.get("revision"):
            raise ValueError("LuaFile operation changed during preflight")
        planned.append(dict(operation=current["operation"], operation_id=current["operation_id"],
                            asset_id=current["asset_id"], revision=current["revision"],
                            type="luafile", type_id=62, name=current["name"],
                            index=current.get("index")))
    cache, _, body, source, profile, walk, native_rows, identity = _workspace_inputs(
        workspace, zone_id, _snapshot=_snapshot)
    removals = [row for row in planned if row["operation"] == "remove"]
    appends = [row for row in planned if row["operation"] == "append"]
    if len({row["name"] for row in removals}) != len(removals) or len({row["name"] for row in appends}) != len(appends):
        raise ValueError("LuaFile row operation names are duplicated")
    # Run the same identity/name/payload checks used by the native writer
    # during preflight. Do not defer duplicate-name or invalid-bytecode errors
    # until package creation.
    _plan(native_rows, [row["name"] for row in removals],
          [dict(name=row["name"], payload=current_rows[row["operation_id"]]["_payload"])
           for row in appends])
    surviving_lua = sum(1 for row in native_rows if row.get("type_id") == 62 and
                        row.get("name") not in {item["name"] for item in removals})
    if appends and not surviving_lua:
        raise ValueError("at least one surviving LuaFile is required as a native append template")
    return dict(source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
                native_source_identity=identity, native_walk_key=walk["walk_key"],
                original_xasset_count=len(body.assets),
                final_xasset_count=len(body.assets) + len(appends) - len(removals),
                operation_count=len(planned), edits=planned,
                support="luafile-sequential-native-row-operations",
                schedule="removals descending by current identity, then appends; full native walk after every table change",
                limits="Inline LuaFile rows only; no mixed child edits; shared/inbound references to removed extents fail closed; a final LuaFile row is removable only when its complete trace proves unique root/name/bytecode ownership through exact serialized EOF")


def build_workspace_luafile_crud(workspace, zone_id: str, plan: dict,
                                 output: Path, timeout: int) -> dict:
    cache, receipt, body, source, profile, walk, native_rows, identity = _workspace_inputs(workspace, zone_id)
    active = {row["operation_id"]: row for row in operations(workspace, zone_id)}
    planned = {row["operation_id"]: row for row in plan["edits"]}
    if set(active) != set(planned) or any(active[key]["revision"] != planned[key]["revision"] for key in active):
        raise ValueError("LuaFile operation set changed after preflight")
    removals = [row["name"] for row in active.values() if row["operation"] == "remove"]
    appends = [dict(name=row["name"], payload=row["_payload"])
               for row in active.values() if row["operation"] == "append"]
    from workstation_fastfiles import _native_walk_artifact
    result = build_luafile_crud(
        cache / receipt["final_body_relative_path"], source,
        _native_walk_artifact(walk, "manifest_relative_path"),
        _native_walk_artifact(walk, "stream_trace_relative_path"),
        removals, appends,
        next((row["name"] for row in native_rows if row.get("type_id") == 62), None),
        workspace.acts_path, workspace.replay_executable, output,
        output.with_suffix(output.suffix + ".crud-work"), timeout,
        expected_source_body_sha256=walk.get("identity", {}).get("body_sha256", body.source_sha256),
        expected_source_manifest_sha256=walk["manifest_sha256"],
        expected_source_trace_sha256=walk["stream_trace_sha256"])
    result["support"] = "LuaFile staged append/remove operations, sequential native reread"
    result["staged_operations"] = [dict(operation=row["operation"], name=row["name"],
                                         asset_id=row["asset_id"], revision=row["revision"])
                                    for row in active.values()]
    return result


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _bind_native_manifest_to_trace(manifest_path: Path, trace_path: Path,
                                   body_size: int, bound_path: Path,
                                   *, journal_path: Path | None = None,
                                   accounted_manifest_path: Path | None = None,
                                   normalized_inventory_sha256: str | None = None) -> dict:
    """Write a derived manifest that binds ACTS' separate trace by digest.

    Current Replay ACTS manifests do not carry ``stream_trace_sha256``. The
    strict low-level writer requires that binding, so preserve the raw ACTS
    manifest and create a sibling transaction manifest only after checking
    the complete native-walk fields, body size, and stable trace bytes.
    """
    manifest_path, trace_path = manifest_path.resolve(strict=True), trace_path.resolve(strict=True)
    raw_before = sha256_file(manifest_path)
    trace_before = sha256_file(trace_path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    accounted_path = (Path(accounted_manifest_path).resolve(strict=True)
                      if accounted_manifest_path is not None else manifest_path)
    accounted = json.loads(accounted_path.read_text(encoding="utf-8"))
    references = accounted.get("reference_only_rows", [])
    if not isinstance(references, list):
        raise ValueError("cannot bind malformed reference-only row descriptors")
    expected_accounted = dict(raw)
    if references:
        expected_accounted["reference_only_rows"] = references
    if accounted != expected_accounted:
        raise ValueError("accounted native manifest differs from the preserved raw manifest")
    tested, top_level = raw.get("tested"), raw.get("top_level_index")
    if (raw.get("profile") != "replay-1.20" or raw.get("xfile_version") != 0xFF7 or
            raw.get("complete") is not True or raw.get("success") is not True or
            type(tested) is not int or type(top_level) is not int or
            tested + len(references) != top_level or
            raw.get("failed") != 0 or raw.get("unavailable") != 0 or
            raw.get("serialized_bytes_read") != body_size or
            raw.get("stream_trace", "stream-trace.jsonl") != trace_path.name):
        raise ValueError("cannot bind an incomplete or differently sized ACTS native walk")
    embedded = raw.get("stream_trace_sha256")
    if embedded is not None and embedded != trace_before:
        raise ValueError("ACTS manifest's embedded stream-trace digest is stale")
    if sha256_file(manifest_path) != raw_before or sha256_file(trace_path) != trace_before:
        raise ValueError("native manifest or trace changed while binding its identity")
    bound = dict(accounted)
    bound["stream_trace_sha256"] = trace_before
    if normalized_inventory_sha256 is not None:
        bound["normalized_inventory_sha256"] = normalized_inventory_sha256
    if journal_path is not None:
        bound["journal"] = str(journal_path.resolve(strict=True))
    if bound_path.exists():
        raise FileExistsError(f"trace-bound manifest already exists: {bound_path}")
    bound_path.parent.mkdir(parents=True, exist_ok=True)
    bound_path.write_text(json.dumps(bound, indent=2) + "\n", encoding="utf-8")
    return dict(raw_manifest_path=str(manifest_path), raw_manifest_sha256=raw_before,
                accounted_manifest_path=str(accounted_path),
                accounted_manifest_sha256=sha256_file(accounted_path),
                bound_manifest_path=str(bound_path), bound_manifest_sha256=sha256_file(bound_path),
                trace_path=str(trace_path), trace_sha256=trace_before,
                normalized_inventory_sha256=normalized_inventory_sha256,
                body_bytes=body_size)


def _plan(rows: list[dict], removals: list[str], appends: list[dict]) -> list[dict]:
    if any(not isinstance(name, str) or not name for name in removals):
        raise ValueError("LuaFile removal names must be non-empty strings")
    if len(set(removals)) != len(removals):
        raise ValueError("LuaFile removal names must be unique")
    initial = {}
    for index, row in enumerate(rows):
        if row.get("type_id") == 62:
            initial.setdefault(row.get("name"), []).append(index)
    remove_ops = []
    for name in removals:
        matches = initial.get(name, [])
        if len(matches) != 1:
            raise ValueError(f"LuaFile removal must identify one unique source row: {name}")
        remove_ops.append(dict(operation="remove", name=name, source_index=matches[0]))
    remove_ops.sort(key=lambda op: op["source_index"], reverse=True)

    remaining = {name for name, indices in initial.items()
                 if len(indices) == 1 and name not in set(removals)}
    append_ops = []
    append_names = set()
    for row in appends:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            raise ValueError("each LuaFile append must provide a name and compiled bytecode")
        name, payload = row["name"], row.get("payload")
        if not isinstance(payload, bytes) or not payload.endswith(b"\0"):
            raise ValueError(f"LuaFile append payload must be native bytecode with trailing NUL: {name}")
        if not name or "\x00" in name or "\\" in name or any(part in ("", ".", "..")
                                                              for part in name.split("/")):
            raise ValueError(f"LuaFile append name is not a safe native path: {name!r}")
        split_luajit_file_payload(payload)
        if name in remaining or name in append_names:
            raise ValueError(f"LuaFile append name already exists after planned removals: {name}")
        append_names.add(name)
        append_ops.append(dict(operation="append", name=name, payload=payload,
                               payload_sha256=_sha(payload)))
    if not remove_ops and not append_ops:
        raise ValueError("LuaFile transaction has no row operations")
    return [*remove_ops, *append_ops]


def _span_rows(body: bytes, journal: list[dict], trace: Path, manifest: Path) -> tuple[dict, dict]:
    indices = {i for i, row in enumerate(journal)
               if row.get("type_id") == 62 and row.get("status") != "reference"}
    if not indices:
        raise ValueError("native trace contains no LuaFile assets")
    index = build_read_span_index(trace, manifest, len(body), selected_assets=indices)
    by_index = {row["index"]: row for row in index["assets"]}
    if set(by_index) != indices:
        raise ValueError("native trace index omitted LuaFile assets")
    return index, by_index


def _bytecodes(body: bytes, journal: list[dict], span_by_index: dict) -> dict[str, str]:
    result = {}
    for index, row in enumerate(journal):
        if row.get("type_id") != 62 or row.get("status") == "reference":
            continue
        name = row.get("name")
        trace_row = span_by_index[index]
        spans = trace_row.get("read_spans", [])
        roots = [span for span in spans if span.get("reader_start_arg") == 0 and
                 span.get("size") == LUA_FILE_ROOT_SIZE]
        if len(roots) != 1:
            raise ValueError(f"LuaFile lacks a unique typed root: {name}")
        root_at = roots[0].get("archive_offset")
        if not isinstance(root_at, int) or root_at + LUA_FILE_ROOT_SIZE > len(body):
            raise ValueError(f"LuaFile root extent is invalid: {name}")
        name_token, size, _strip, _padding, data_token = struct.unpack_from(
            "<QiB3sQ", body, root_at)
        if name_token != INLINE_POINTER or data_token != INLINE_POINTER:
            raise ValueError(f"LuaFile is not the supported inline form: {name}")
        name_at = root_at + LUA_FILE_ROOT_SIZE
        encoded_name = name.encode("utf-8") + b"\0"
        if body[name_at:name_at + len(encoded_name)] != encoded_name:
            raise ValueError(f"LuaFile name child differs from the native journal: {name}")
        bytecode_at = name_at + len(encoded_name)
        code_spans = [span for span in spans if span.get("archive_offset") == bytecode_at and
                      span.get("size") == size]
        if len(code_spans) != 1 or size == 0 or bytecode_at + size > len(body):
            raise ValueError(f"LuaFile bytecode is not a unique inline child: {name}")
        payload = body[bytecode_at:bytecode_at + size]
        if not payload.endswith(b"\0"):
            raise ValueError(f"LuaFile bytecode lacks its native terminator: {name}")
        split_luajit_file_payload(payload)
        if name in result:
            raise ValueError(f"duplicate LuaFile identity prevents exact payload comparison: {name}")
        result[name] = _sha(payload)
    return result


def _pack_and_walk(body: bytes, reservations: list[int], source_fastfile: Path,
                   acts: Path, replay: Path, step_dir: Path, label: str,
                   timeout: int, profile: dict, *, allow_no_lua: bool = False) -> tuple[Path, dict, list[dict], Path, Path,
                                                        dict, dict]:
    step_dir.mkdir(parents=True, exist_ok=True)
    package = pack_replay_uncompressed(body, reservations,
        xfile_version=profile["final_header"]["xfile_version"],
        transient_type=profile["header"]["transient_type"])
    package_path = step_dir / f"{label}.ff"
    package_path.write_bytes(package)
    for patch in profile["patches"]:
        patch_path = package_path.with_suffix(patch["extension"])
        patch_path.write_bytes(make_replay_header_only_patch(Path(patch["path"]).read_bytes(), package))
    native = verify_native(package_path, body, source_fastfile, acts, replay,
                           step_dir / "native-reader", timeout, trace=True)
    accounted_manifest_path = Path(native["manifest_path"])
    raw_manifest_path = Path(native.get("raw_manifest_path", native["manifest_path"]))
    manifest = native["manifest"]
    references = native.get("reference_only_rows", [])
    if not isinstance(references, list):
        raise ValueError("native intermediate reference coverage is malformed")
    tested, top_level = manifest.get("tested"), manifest.get("top_level_index")
    if (manifest.get("complete") is not True or manifest.get("success") is not True or
            type(tested) is not int or type(top_level) is not int or
            tested + len(references) != len(ZoneBody.parse(body).assets) or
            top_level != len(ZoneBody.parse(body).assets) or
            manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
            manifest.get("serialized_bytes_read") != len(body)):
        raise ValueError(f"native full-zone reread failed for intermediate {label}")
    raw_journal = _rows(raw_manifest_path.parent / manifest.get("journal", "assets.jsonl"))
    if len(raw_journal) != manifest.get("tested"):
        raise ValueError("raw native journal count differs from the native tested count")
    if references:
        normalized_path = Path(native["normalized_inventory_path"]).resolve(strict=True)
        normalized_sha = sha256_file(normalized_path)
        if normalized_sha != native.get("normalized_inventory_sha256"):
            raise ValueError("normalized native inventory changed after reference reconciliation")
        inventory = json.loads(normalized_path.read_text(encoding="utf-8"))
        journal = inventory.get("normalized_rows")
        if (not isinstance(journal, list) or len(journal) != len(ZoneBody.parse(body).assets) or
                native.get("normalized_asset_identity_sha256") != ordered_asset_identity_sha256(journal)):
            raise ValueError("normalized native inventory identity/order differs from the XAsset table")
    else:
        normalized_path = None
        normalized_sha = None
        journal = raw_journal
        if len(journal) != len(ZoneBody.parse(body).assets):
            raise ValueError("native intermediate inventory does not match its XAsset table")
    trace = accounted_manifest_path.parent / manifest.get("stream_trace", "stream-trace.jsonl")
    binding = _bind_native_manifest_to_trace(
        raw_manifest_path, trace, len(body),
        raw_manifest_path.with_name("manifest.transaction-bound.json"),
        journal_path=raw_manifest_path.parent / manifest.get("journal", "assets.jsonl"),
        accounted_manifest_path=(accounted_manifest_path if references else None),
        normalized_inventory_sha256=normalized_sha)
    manifest_path = Path(binding["bound_manifest_path"])
    native["manifest_path"] = str(manifest_path)
    native["manifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))
    native["raw_manifest_path"] = str(raw_manifest_path)
    native["raw_manifest_sha256"] = binding["raw_manifest_sha256"]
    native["manifest_trace_binding"] = binding
    native["normalized_rows"] = journal
    has_lua_rows = any(row.get("type_id") == 62 and row.get("status") != "reference"
                       for row in journal)
    if allow_no_lua and not has_lua_rows:
        # Mixed-family rereads need a complete trace even for zones that have
        # no LuaFile rows. The full native manifest/trace binding above is
        # still mandatory; only the Lua-specific subset index is empty.
        index = build_read_span_index(trace, manifest_path, len(body))
        spans = {}
    else:
        index, spans = _span_rows(body, journal, trace, manifest_path)
    payloads = _bytecodes(body, journal, spans)
    return package_path, native, journal, trace, manifest_path, index, payloads


def build_luafile_crud(source_body_path: Path, source_fastfile: Path,
                       source_manifest_path: Path, source_trace_path: Path,
                       removals: list[str], appends: list[dict], template_name: str | None,
                       acts: Path, replay: Path, output_fastfile: Path,
                       evidence_dir: Path, timeout: int = 1800,
                       expected_source_body_sha256: str | None = None,
                       expected_source_manifest_sha256: str | None = None,
                       expected_source_trace_sha256: str | None = None) -> dict:
    """Apply ordered LuaFile row operations with a new native walk per step.

    `appends` rows are `{name: str, payload: bytes}` where payload is already
    native LuaJIT bytecode with a valid prototype-end marker. Removals are source names;
    their indexes are re-resolved by unique name on each intermediate walk.
    """
    source_body_path, source_fastfile = source_body_path.resolve(strict=True), source_fastfile.resolve(strict=True)
    source_manifest_path, source_trace_path = source_manifest_path.resolve(strict=True), source_trace_path.resolve(strict=True)
    body = source_body_path.read_bytes()
    source_body_sha = _sha(body)
    if expected_source_body_sha256 is not None and source_body_sha != expected_source_body_sha256:
        raise ValueError("LuaFile CRUD source body differs from its validated native-walk receipt")
    profile = source_profile(source_fastfile)
    if any(row["extension"] == ".fc" for row in profile["patches"]):
        raise ValueError("LuaFile CRUD does not support source FC patch chains")
    manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    source_manifest_sha = sha256_file(source_manifest_path)
    source_trace_sha = sha256_file(source_trace_path)
    if (expected_source_manifest_sha256 is not None and
            source_manifest_sha != expected_source_manifest_sha256):
        raise ValueError("LuaFile CRUD ACTS manifest differs from its validated native-walk receipt")
    if expected_source_trace_sha256 is not None and source_trace_sha != expected_source_trace_sha256:
        raise ValueError("LuaFile CRUD stream trace differs from its validated native-walk receipt")
    if (manifest.get("profile") != "replay-1.20" or manifest.get("success") is not True or
            manifest.get("tested") != manifest.get("top_level_index") or
            manifest.get("serialized_bytes_read") != len(body)):
        raise ValueError("LuaFile CRUD requires a complete trace of the exact source body")
    initial_rows = _rows(source_manifest_path.parent / manifest.get("journal", "assets.jsonl"))
    source_table = ZoneBody.parse(body)
    if len(initial_rows) != len(source_table.assets):
        raise ValueError("source native journal does not cover its XAsset table")
    original_plan = _plan(initial_rows, removals, appends)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    source_binding = _bind_native_manifest_to_trace(
        source_manifest_path, source_trace_path, len(body),
        evidence_dir / "source-manifest.transaction-bound.json",
        journal_path=source_manifest_path.parent / manifest.get("journal", "assets.jsonl"))
    original_index, original_spans = _span_rows(
        body, initial_rows, source_trace_path, Path(source_binding["bound_manifest_path"]))
    expected_rows = list(initial_rows)
    expected_payloads = _bytecodes(body, initial_rows, original_spans)
    initial_payloads = dict(expected_payloads)
    original_body_sha = source_body_sha
    current_trace, current_manifest = source_trace_path, Path(source_binding["bound_manifest_path"])
    current_index = original_index
    current_reservations = [int(size) for size in profile["final_header"]["block_sizes"]]
    operation_log = []
    temp_root = evidence_dir / "intermediates"
    if temp_root.exists() or output_fastfile.exists():
        raise FileExistsError("LuaFile CRUD evidence or output path already exists")
    temp_root.mkdir(parents=True)

    for ordinal, operation in enumerate(original_plan):
        current = ZoneBody.parse(body)
        journal = expected_rows
        reservation_sizes = [max(current_reservations[i], int(current_index["max_destination_offsets"].get(
                            str(i), current_index["max_destination_offsets"].get(i, 0))))
                             for i in range(11)]
        if operation["operation"] == "remove":
            name = operation["name"]
            matches = [i for i, row in enumerate(journal)
                       if row.get("type_id") == 62 and row.get("name") == name]
            if len(matches) != 1:
                raise ValueError(f"intermediate native inventory no longer uniquely identifies {name}")
            selected = matches[0]
            span_row = current_index["assets"]
            trace_asset = next((dict(xasset_index=row["index"], type_id=62,
                                      name=name, **{key: row[key] for key in
                                      ("read_spans", "begin_cursor", "end_cursor",
                                       "begin_sequence", "end_sequence") if key in row})
                                for row in span_row if row.get("index") == selected), None)
            if trace_asset is None:
                raise ValueError(f"fresh trace omitted LuaFile removal target {name}")
            body, write_receipt = remove_existing_luafile_row(body, selected, name,
                trace_asset, current.source_sha256, current_trace, current_manifest,
                indexed_assets=span_row)
            del expected_rows[selected]
            expected_payloads.pop(name)
        else:
            name, payload = operation["name"], operation["payload"]
            existing_names = {row.get("name") for row in journal if isinstance(row.get("name"), str)}
            if name in existing_names:
                raise ValueError(f"append name appeared before scheduled append: {name}")
            current_lua = [(i, row) for i, row in enumerate(journal) if row.get("type_id") == 62]
            if not current_lua:
                raise ValueError("a LuaFile template is required for native row append")
            template = next(((i, row) for i, row in current_lua if row.get("name") == template_name), None)
            if template is None:
                template = current_lua[0]
            template_index, template_row = template
            final_index = len(journal) - 1
            template_trace = next((row for row in current_index["assets"]
                                   if row.get("index") == template_index), None)
            final_trace = next((row for row in current_index["assets"]
                                if row.get("index") == final_index), None)
            if template_trace is None or final_trace is None:
                # The index is selected for LuaFiles; append needs the final
                # asset boundary too, so request a second full typed index.
                all_index = build_read_span_index(current_trace, current_manifest, len(body))
                template_trace = next((row for row in all_index["assets"]
                                       if row.get("index") == template_index), template_trace)
                final_trace = next((row for row in all_index["assets"]
                                    if row.get("index") == final_index), None)
            if template_trace is None or final_trace is None:
                raise ValueError("fresh trace omitted LuaFile template or original final asset boundary")
            template_asset = dict(xasset_index=template_index, type_id=62,
                                  name=template_row["name"], read_spans=template_trace["read_spans"])
            final_row = journal[final_index]
            final_asset = dict(xasset_index=final_index, type_id=final_row["type_id"],
                               name=final_row.get("name"), read_spans=final_trace["read_spans"],
                               begin_cursor=final_trace.get("begin_cursor"),
                               end_cursor=final_trace.get("end_cursor"))
            body, write_receipt = append_luafile_tail(body, name, payload, existing_names,
                template_index, template_row["name"], template_asset, final_asset,
                current.source_sha256, current_trace, current_manifest)
            derived = write_receipt.get("stream_reservation_highwaters")
            if not isinstance(derived, list) or len(derived) != 11:
                raise ValueError("LuaFile append omitted its relocated stream reservation contract")
            reservation_sizes = [max(old, int(new)) for old, new in zip(reservation_sizes, derived)]
            expected_rows.append(dict(type_id=62, name=name))
            expected_payloads[name] = _sha(payload)

        step_dir = temp_root / f"{ordinal:04d}-{operation['operation']}-{operation['name'].replace('/', '_')}"
        package_path, native, readback_rows, current_trace, current_manifest, current_index, actual_payloads = _pack_and_walk(
            body, reservation_sizes, source_fastfile, acts, replay, step_dir,
            f"{ordinal:04d}-{operation['operation']}", timeout, profile)
        current_reservations = list(reservation_sizes)
        expected_identity = [(row.get("type_id"), row.get("name")) for row in expected_rows]
        actual_identity = [(row.get("type_id"), row.get("name")) for row in readback_rows]
        if actual_identity != expected_identity:
            mismatch = next((index for index, pair in enumerate(zip(expected_identity,
                actual_identity)) if pair[0] != pair[1]), None)
            raise ValueError("intermediate native read changed retained asset identity/order: "
                f"expected={len(expected_identity)} actual={len(actual_identity)} "
                f"first_mismatch={mismatch} "
                f"expected_row={expected_identity[mismatch] if mismatch is not None else None!r} "
                f"actual_row={actual_identity[mismatch] if mismatch is not None else None!r}")
        if actual_payloads != expected_payloads:
            raise ValueError("intermediate native read changed a retained/appended LuaFile payload")
        operation_log.append(dict(operation=operation["operation"], name=operation["name"],
            source_index=operation.get("source_index"), writer=write_receipt,
            raw_native_manifest_sha256=native.get("raw_manifest_sha256"),
            transaction_bound_manifest_sha256=sha256_file(Path(native["manifest_path"])),
            native_trace_sha256=native.get("manifest_trace_binding", {}).get("trace_sha256"),
            native_tested=native["manifest"]["tested"],
            identity_order_exact=True, luafile_payloads_exact=len(actual_payloads)))

    final_step = package_path
    if output_fastfile.exists() or output_fastfile.with_suffix(".fp").exists() or \
            output_fastfile.with_suffix(".fc").exists():
        raise FileExistsError("LuaFile CRUD output or patch sidecar already exists")
    if output_fastfile == source_fastfile or source_fastfile in output_fastfile.parents:
        raise ValueError("LuaFile CRUD output must not overwrite or reside under the source fastfile")
    output_fastfile.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(final_step, output_fastfile)
    output_sidecars = []
    for patch in profile["patches"]:
        source_sidecar = final_step.with_suffix(patch["extension"])
        destination = output_fastfile.with_suffix(patch["extension"])
        if not source_sidecar.is_file():
            raise ValueError("final LuaFile transaction omitted a source patch sidecar")
        shutil.copy2(source_sidecar, destination)
        output_sidecars.append(dict(path=str(destination), sha256=sha256_file(destination)))
    proof = dict(schema="replay120-luafile-crud-sequential-native-pass-v1", status="pass",
        source=dict(body_sha256=original_body_sha, source_fastfile_sha256=profile["sha256"],
                    source_fastfile_path=str(source_fastfile),
                    native_manifest_sha256=source_manifest_sha,
                    stream_trace_sha256=source_trace_sha,
                    transaction_bound_manifest_sha256=source_binding["bound_manifest_sha256"],
                    initial_assets=len(initial_rows), initial_luafiles=len(initial_payloads)),
        plan=[dict(operation=row["operation"], name=row["name"],
                   source_index=row.get("source_index"),
                   payload_sha256=row.get("payload_sha256")) for row in original_plan],
        steps=operation_log, final=dict(fastfile_path=str(output_fastfile),
            fastfile_sha256=sha256_file(output_fastfile), body_sha256=ZoneBody.parse(body).source_sha256,
            assets=len(expected_rows), luafiles=len(expected_payloads),
            identity_order_exact=True, payloads_exact=True, sidecars=output_sidecars),
        retained_identity_check="Every native intermediate journal was compared in order to the planned source inventory after each operation.",
        payload_check="Every retained LuaFile inline bytecode extent was compared by exact digest at every intermediate; appended bytecodes were checked against their authored payload.",
        limitations="Supports uniquely named, inline LuaFiles only. Each mutation requires a fresh native trace. Inbound/shared aliases into removed extents fail closed. A final LuaFile row is removable only when its complete native trace proves unique ownership through exact serialized EOF. Mixed ScriptFile/LuaFile transactions are not supported.")
    proof_path = output_fastfile.with_suffix(output_fastfile.suffix + ".crud-proof.json")
    proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    return proof
