"""Sequential native packaging for supported mixed asset families.

Existing family validators bind every draft to the original source. Writers
resolve each next target from a fresh complete native trace after a mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from workstation_asset_transaction import execute_transaction
from workstation_fastfiles import (
    ZoneBody, _native_walk_artifact, _read_native_rows, _validate_pending_snapshot,
    acts_tool_identity,
    make_replay_header_only_patch, sha256_file, source_profile, unpack_replay_uncompressed,
)
from workstation_localize import append_localize_entry
from workstation_localize_crud import _bind_native_manifest_to_trace, operations as localize_operations
from workstation_luafile_crud import _pack_and_walk
from workstation_luafile_crud import operations as luafile_operations
from workstation_luafile_operations import append_luafile_tail
from workstation_asset_semantics import (
    identity as _identity, native_receipt as _native_receipt,
    semantic_sha as _semantic_sha, state_rows as _state_rows,
    trace_row as _trace_row, typed_semantics as _typed_semantics,
)
from workstation_native_asset_edits import read_resident_image, replace_resident_image
from workstation_trace_index import build_read_span_index
from workstation_rawfile import RawFileReadContext, encode_rawfile, plan_rawfile_edits, read_rawfile, replace_rawfile_payload
from workstation_soundbank import (
    ALIAS_SIZE, read_native_soundbank, soundbank_edit_document, validate_soundbank_edit_document,
    replace_soundbank_alias_scalars,
)


_IMAGE_SUPPORT = "same-extent-native-shader-image-batch"
_LOCALIZE_SUPPORT = "localize-sequential-native-row-operations"
_LUAFILE_SUPPORT = "luafile-sequential-native-row-operations"
_RAWFILE_SUPPORT = "rawfile-full-trace-block5-relocation"
_SOUNDBANK_SUPPORT = "same-extent-soundbank-alias-scalars"


def _zone_plan(workspace, zone_id: str, rows: list[dict], support: str, *,
               _snapshot=None) -> dict:
    if _snapshot is None:
        result = workspace._plan_pending_rows(rows)
    else:
        result = workspace._plan_pending_rows(rows, _snapshots={zone_id: _snapshot})
    if result.get("status") != "ready" or result.get("invalid_edits"):
        raise ValueError("mixed asset preflight contains invalid pending rows")
    zones = [row for row in result.get("zones", []) if row.get("zone_id") == zone_id]
    if len(zones) != 1 or not zones[0].get("packageable") or zones[0].get("support") != support:
        reason = zones[0].get("reason") if zones else "family preflight omitted the requested zone"
        raise ValueError(f"mixed asset family is outside the proved route: {reason or support}")
    entry = zones[0]
    expected = sorted((row.get("asset_id"), row.get("revision")) for row in rows)
    actual = sorted((row.get("asset_id"), row.get("revision")) for row in entry.get("edits", []))
    if expected != actual:
        raise ValueError("mixed family plan omitted or substituted a pending revision")
    return entry


def _plan_mixed_content_replacements(workspace, zone_id: str,
                                    pending_rows: list[dict], *, _snapshot=None) -> dict:
    """Preflight a mixed batch of existing-content replacements only.

    Row creation/removal remains on its established transaction routes. Every
    replacement family is independently checked by the existing public
    preflight, then the unified transaction binds the exact same pending
    revisions to one source snapshot.
    """
    from workstation_fastfiles import SHADER_TYPE_IDS

    if any(row.get("operation") for row in pending_rows):
        raise ValueError("mixed content replacement route does not accept row append/removal operations")
    shader_types = set(SHADER_TYPE_IDS)
    allowed = {"image", "rawfile", "soundbank", "localize", "scriptfile", "luafile", "stringtable"} | shader_types
    if any(row.get("type") not in allowed for row in pending_rows):
        raise ValueError("mixed content replacement contains an unsupported asset family")
    groups = {
        "image": [row for row in pending_rows if row.get("type") == "image"],
        "rawfile": [row for row in pending_rows if row.get("type") == "rawfile"],
        "soundbank": [row for row in pending_rows if row.get("type") == "soundbank"],
        "localize": [row for row in pending_rows if row.get("type") == "localize"],
        "scriptfile": [row for row in pending_rows if row.get("type") == "scriptfile"],
        "luafile": [row for row in pending_rows if row.get("type") == "luafile"],
        "stringtable": [row for row in pending_rows if row.get("type") == "stringtable"],
        "shader": [row for row in pending_rows if row.get("type") in shader_types],
    }
    active = {name: rows for name, rows in groups.items() if rows}
    if len(active) < 2:
        raise ValueError("mixed content package requires at least two supported replacement families")

    support_by_family = {
        "image": _IMAGE_SUPPORT,
        "rawfile": _RAWFILE_SUPPORT,
        "soundbank": _SOUNDBANK_SUPPORT,
        "localize": "trace-relocated-localize-batch",
        "scriptfile": "scriptfile-inline-children-trace-owned",
        "luafile": "luafile-inline-child-full-trace-relocation",
        "stringtable": ("stringtable-full-trace-block5-relocation"
                        if len(groups["stringtable"]) == 1
                        else "stringtable-sequential-full-trace-relocation"),
        "shader": _IMAGE_SUPPORT,
    }
    plans = {family: _zone_plan(workspace, zone_id, rows, support_by_family[family],
                               _snapshot=_snapshot)
             for family, rows in active.items()}
    if plans.get("shader") and plans["shader"].get("support") != _IMAGE_SUPPORT:
        raise ValueError("mixed packages accept only same-extent shader replacements")
    if plans.get("image"):
        for item in plans["image"].get("proof", {}).get("edits", []):
            dimensions = item.get("typed_layout", {}).get("dimensions")
            if (not isinstance(dimensions, list) or len(dimensions) != 4 or
                    any(type(value) is not int or value < 1 for value in dimensions) or
                    dimensions[2:] != [1, 1]):
                raise ValueError("mixed content packages accept only same-layout resident 2D images")

    snapshot = _snapshot or workspace._validated_asset_snapshot(zone_id, require_trace=True)
    current_identity = (snapshot.body.source_sha256, snapshot.source_profile["sha256"],
                        snapshot.native_walk["walk_key"],
                        snapshot.native_walk["manifest_sha256"],
                        snapshot.native_walk["stream_trace_sha256"])
    for row in pending_rows:
        identity = row.get("native_source_identity", {})
        if (row.get("status") == "stale" or
                (identity.get("body_sha256"), identity.get("source_fastfile_sha256"),
                 identity.get("native_walk_key"), identity.get("native_manifest_sha256"),
                 identity.get("stream_trace_sha256")) != current_identity):
            raise ValueError("mixed replacement revisions do not share the current original body/native trace")
    edits = sorted((row.get("asset_id"), row.get("revision")) for row in pending_rows)
    return dict(schema="replay120-mixed-asset-crud-plan-v1", mode="content-replacements",
                zone_id=zone_id,
                edits=[dict(asset_id=asset_id, revision=revision) for asset_id, revision in edits],
                family_plans=plans, source_body_sha256=snapshot.body.source_sha256,
                source_fastfile_sha256=snapshot.source_profile["sha256"],
                native_walk_key=snapshot.native_walk["walk_key"],
                native_manifest_sha256=snapshot.native_walk["manifest_sha256"],
                stream_trace_sha256=snapshot.native_walk["stream_trace_sha256"],
                schedule=("existing content replacements only: resolve each immutable type/name/occurrence "
                          "against a fresh complete native trace; reread and compare retained semantics after every step"))


def plan_mixed_asset_crud(workspace, zone_id: str, pending_rows: list[dict], *,
                          _snapshot=None) -> dict:
    """Preflight a mixed transaction using each existing asset-family validator."""
    if not isinstance(zone_id, str) or not zone_id or not isinstance(pending_rows, list) or not pending_rows:
        raise ValueError("mixed asset preflight requires one zone and a nonempty pending row list")
    if any(row.get("zone_id") != zone_id for row in pending_rows):
        raise ValueError("mixed asset preflight rows must belong to one zone")
    from workstation_fastfiles import SHADER_TYPE_IDS
    content_types = {"localize", "scriptfile", "luafile", "stringtable"} | set(SHADER_TYPE_IDS)
    if any(row.get("type") in content_types for row in pending_rows) and not any(
            row.get("operation") for row in pending_rows):
        return _plan_mixed_content_replacements(workspace, zone_id, pending_rows,
                                                _snapshot=_snapshot)
    images = [row for row in pending_rows if row.get("type") == "image" and not row.get("operation")]
    rawfiles = [row for row in pending_rows if row.get("type") == "rawfile" and not row.get("operation")]
    soundbanks = [row for row in pending_rows if row.get("type") == "soundbank" and not row.get("operation")]
    localizes = [row for row in pending_rows if row.get("type") == "localize" and row.get("operation")]
    luafiles = [row for row in pending_rows if row.get("type") == "luafile" and row.get("operation")]
    families = [images, rawfiles, soundbanks, localizes, luafiles]
    if sum(map(len, families)) != len(pending_rows):
        raise ValueError("mixed transaction supports resident images, RawFile replacements, SoundBank aliases, and Localize/LuaFile appends")
    if sum(bool(rows) for rows in families) < 2 or len(localizes) > 1 or len(luafiles) > 1:
        raise ValueError("mixed transaction requires at least two supported families and at most one append per Localize/LuaFile family")
    if (any(row.get("operation") for row in images) or
            any(row.get("operation") != "append" for row in localizes + luafiles)):
        raise ValueError("mixed route supports image replacements and append-only Localize/LuaFile rows")

    image_plan = (_zone_plan(workspace, zone_id, images, _IMAGE_SUPPORT,
                            _snapshot=_snapshot) if images else None)
    if image_plan:
        image_proofs = image_plan.get("proof", {}).get("edits", [])
        if sorted((row.get("asset_id"), row.get("revision")) for row in image_proofs) != sorted(
                (row.get("asset_id"), row.get("revision")) for row in images):
            raise ValueError("mixed image preflight omitted its typed shape proof")
        for row in image_proofs:
            dimensions = row.get("typed_layout", {}).get("dimensions")
            if (not isinstance(dimensions, list) or len(dimensions) != 4 or
                    any(type(value) is not int or value < 1 for value in dimensions)):
                raise ValueError("mixed image preflight has no complete resident dimensions")
            if dimensions[2:] != [1, 1]:
                raise ValueError("Whole-resource DDS arrays and volumes require an image/shader-only package; their mixed-family contract is not yet supported")
    rawfile_plan = (_zone_plan(workspace, zone_id, rawfiles, _RAWFILE_SUPPORT,
                              _snapshot=_snapshot) if rawfiles else None)
    soundbank_plan = (_zone_plan(workspace, zone_id, soundbanks, _SOUNDBANK_SUPPORT,
                                _snapshot=_snapshot) if soundbanks else None)
    localize_plan = (_zone_plan(workspace, zone_id, localizes, _LOCALIZE_SUPPORT,
                               _snapshot=_snapshot) if localizes else None)
    luafile_plan = (_zone_plan(workspace, zone_id, luafiles, _LUAFILE_SUPPORT,
                              _snapshot=_snapshot) if luafiles else None)

    loc_rows = localize_operations(workspace, zone_id, _snapshot=_snapshot) if localizes else []
    lua_rows = luafile_operations(workspace, zone_id, _snapshot=_snapshot) if luafiles else []
    loc_by_id = {row["operation_id"]: row for row in loc_rows}
    lua_by_id = {row["operation_id"]: row for row in lua_rows}
    loc = loc_by_id.get(localizes[0].get("operation_id")) if localizes else None
    lua = lua_by_id.get(luafiles[0].get("operation_id")) if luafiles else None
    if ((localizes and (not loc or loc.get("operation") != "append" or loc.get("revision") != localizes[0].get("revision"))) or
            (luafiles and (not lua or lua.get("operation") != "append" or lua.get("revision") != luafiles[0].get("revision")))):
        raise ValueError("mixed transaction permits only the current Localize and LuaFile append revisions")
    snapshot = _snapshot or workspace._validated_asset_snapshot(zone_id, require_trace=True)
    return dict(schema="replay120-mixed-asset-crud-plan-v1", zone_id=zone_id,
                edits=[dict(asset_id=row.get("asset_id"), revision=row.get("revision"))
                       for row in pending_rows],
                family_plans=dict(image=image_plan, rawfile=rawfile_plan, soundbank=soundbank_plan,
                                  localize=localize_plan, luafile=luafile_plan),
                localize_operation_id=loc["operation_id"] if loc else None,
                luafile_operation_id=lua["operation_id"] if lua else None,
                source_body_sha256=snapshot.body.source_sha256,
                source_fastfile_sha256=snapshot.source_profile["sha256"],
                schedule="present families only: resident images, RawFile replacements, SoundBank aliases, Localize append, LuaFile append; full native reread/retrace after every mutation")


def _active_pending_rows(workspace, zone_id: str) -> list[dict]:
    result = workspace.list_pending_edits(zone_id, limit=1000)
    rows = list(result["items"])
    for offset in range(1000, result["total"], 1000):
        rows.extend(workspace.list_pending_edits(zone_id, offset=offset, limit=1000)["items"])
    return rows


def _publication_result(receipt: dict, edits: list[dict], final_ff: Path,
                        final_fp: Path, profile: dict, receipt_path: Path) -> dict:
    sidecars = ([dict(path=str(final_fp), sha256=sha256_file(final_fp), bytes=final_fp.stat().st_size,
                      replaces_stale_source_patch=(str(profile["patches"][0]["path"])
                                                   if profile["patches"] else None))]
                if final_fp.is_file() else [])
    return dict(status=receipt["status"], zone_id=receipt["zone_id"], edits=edits,
                output_fastfile=str(final_ff), output_fastfile_sha256=sha256_file(final_ff),
                sidecars=sidecars, receipt_path=str(receipt_path), proof=receipt)


def _copy_verified_package(package_ff: Path, final_ff: Path,
                           expected_ff_sha256: str,
                           expected_fp_sha256: str | None) -> tuple[str, str | None]:
    """Publish only the exact FF/FP pair already verified by the native reader."""
    package_fp = package_ff.with_suffix(".fp")
    final_fp = final_ff.with_suffix(".fp")
    owned = []

    def copy_exclusive(source, destination, expected):
        # Never replace a file that appeared after the caller's preflight.
        # Record only files actually created by this call for rollback.
        with source.open("rb") as original, destination.open("xb") as target:
            identity = os.fstat(target.fileno())
            record = [destination, identity.st_dev, identity.st_ino, None]
            owned.append(record)
            try:
                shutil.copyfileobj(original, target, length=1024 * 1024)
                target.flush()
                os.fsync(target.fileno())
            finally:
                current = os.fstat(target.fileno())
                record[3] = (current.st_size, current.st_mtime_ns)
        if sha256_file(source) != expected or sha256_file(destination) != expected:
            raise ValueError("published FF/FP bytes differ from the native-reread package")

    try:
        if final_ff.exists() or final_ff.is_symlink() or final_fp.exists() or final_fp.is_symlink():
            raise FileExistsError("publication FF or FP already exists")
        if sha256_file(package_ff) != expected_ff_sha256:
            raise ValueError("final staged FF changed after its native reread")
        if expected_fp_sha256 is None:
            if package_fp.exists():
                raise ValueError("final staged FP appeared after its native reread")
        elif not package_fp.is_file() or sha256_file(package_fp) != expected_fp_sha256:
            raise ValueError("final staged FP changed after its native reread")
        copy_exclusive(package_ff, final_ff, expected_ff_sha256)
        if expected_fp_sha256 is not None:
            copy_exclusive(package_fp, final_fp, expected_fp_sha256)
        elif final_fp.exists() or final_fp.is_symlink():
            raise FileExistsError("an unverified destination patch appeared during publication")
        actual_ff = sha256_file(final_ff)
        actual_fp = sha256_file(final_fp) if expected_fp_sha256 is not None else None
        if actual_ff != expected_ff_sha256 or actual_fp != expected_fp_sha256:
            raise ValueError("published FF/FP bytes differ from the native-reread package")
        return actual_ff, actual_fp
    except BaseException:
        for path, device, inode, metadata in reversed(owned):
            try:
                current = path.stat(follow_symlinks=False)
                if (stat.S_ISREG(current.st_mode) and
                        (current.st_dev, current.st_ino) == (device, inode) and
                        (current.st_size, current.st_mtime_ns) == metadata):
                    path.unlink()
            except FileNotFoundError:
                pass
        raise


def _load_image_payload(cache: Path, body: ZoneBody, row: dict,
                        native_row: dict, trace_asset: dict,
                        walk: dict, profile: dict, source: Path) -> tuple[bytes, dict]:
    asset_id = row.get("asset_id")
    try:
        index = int(asset_id.rsplit(":", 1)[1])
    except (AttributeError, IndexError, ValueError):
        index = None
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(body.assets):
        raise ValueError("mixed image row has an invalid source index")
    pending_path, pending, _payload = _validate_pending_snapshot(cache, index, row["asset_id"], body)
    if pending.get("revision") != row.get("revision") or pending.get("type") != "image":
        raise ValueError("mixed image revision differs from its immutable pending snapshot")
    source_identity = pending.get("native_source_identity", {})
    if (source_identity.get("body_sha256") != body.source_sha256 or
            source_identity.get("source_fastfile_sha256") != profile.get("sha256") or
            source_identity.get("native_walk_key") != walk.get("walk_key") or
            source_identity.get("native_manifest_sha256") != walk.get("manifest_sha256") or
            source_identity.get("stream_trace_sha256") != walk.get("stream_trace_sha256")):
        raise ValueError("mixed image was staged against another source/native trace")
    payload_path = pending_path.parent / pending["edited_payload_path"]
    payload = payload_path.read_bytes()
    compiler = pending.get("compiler_receipt")
    if not isinstance(compiler, dict):
        raise ValueError("mixed image compiler receipt is missing")
    encoded = json.dumps(compiler, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    if (sha256_file(payload_path) != pending.get("edited_payload_sha256") or
            hashlib.sha256(encoded).hexdigest() != pending.get("compiler_receipt_sha256") or
            compiler.get("status") != "replay120-resident-image-encode-pass" or
            compiler.get("asset_name") != row.get("name") or
            compiler.get("result", {}).get("native_payload_sha256") != pending.get("edited_payload_sha256")):
        raise ValueError("mixed image payload/compiler receipt changed after preflight")
    current = read_resident_image(body.data, dict(index=index, **native_row), trace_asset, body.source_sha256)
    result = compiler.get("result", {})
    if (result.get("width", current["dimensions"][0]) != current["dimensions"][0] or
            result.get("height", current["dimensions"][1]) != current["dimensions"][1] or
            result.get("mip_count", current["level_count"]) != current["level_count"] or
            len(payload) != len(current["payload"])):
        raise ValueError("mixed route refuses resized or variable-extent resident images")
    layout = dict(format=current["format"], flags=current["flags"],
                  dimensions=list(current["dimensions"]), level_count=current["level_count"],
                  total_size=current["total_size"])
    if source_identity.get("typed_layout") != dict(root_archive_offset=current["root_archive_offset"],
            name_archive_offset=current["name_archive_offset"], child_archive_offset=current["payload_archive_offset"],
            child_bytes=len(current["payload"]), format=current["format"],
            dimensions=list(current["dimensions"]), level_count=current["level_count"]):
        raise ValueError("mixed image layout differs from its staged trace-owned identity")
    return payload, dict(index=index, identity=dict(type_id=19, name=row["name"]),
                         original_payload_sha256=current["payload_sha256"],
                         replacement_payload_sha256=hashlib.sha256(payload).hexdigest(), layout=layout,
                         trace_asset=trace_asset, native_row=native_row)


def _rawfile_payload_rows(body: bytes, journal: list[dict], trace: Path,
                          manifest: Path) -> dict[tuple[int, str, int], bytes]:
    """Read every RawFile payload through the complete current native trace."""
    selected = {index for index, row in enumerate(journal) if row.get("type_id") == 51}
    if not selected:
        return {}
    indexed = build_read_span_index(trace, manifest, len(body), selected_assets=selected)
    spans = {row["index"]: dict(row, index=row["index"], type_id=51,
             name=journal[row["index"]].get("name"),
             _all_physical_spans=indexed["_all_physical_spans"]) for row in indexed["assets"]}
    context = RawFileReadContext(body)
    occurrences: dict[str, int] = {}
    payloads = {}
    for index in sorted(selected):
        row = journal[index]
        name = row.get("name")
        if not isinstance(name, str) or index not in spans:
            raise ValueError("complete native trace omits a RawFile identity")
        occurrence = occurrences.get(name, 0)
        occurrences[name] = occurrence + 1
        _layout, decoded = read_rawfile(body, dict(row, index=index), spans[index],
                                       hashlib.sha256(body).hexdigest(), context=context)
        raw = (decoded["content"].encode("utf-8") if decoded["mode"] == "text"
               else __import__("base64").b64decode(decoded["content"], validate=True))
        payloads[(51, name, occurrence)] = raw
    return payloads


def _transaction_rows(state: dict) -> list[dict]:
    """Add RawFile bytes and SoundBank fields to retained-payload checks."""
    rows = _state_rows(state)
    payloads = state.get("rawfile_payloads", {})
    banks = state.get("soundbank_receipts", {})
    occurrences: dict[tuple[int, str], int] = {}
    for index, row in enumerate(state["journal"]):
        type_id = row.get("type_id")
        if type_id not in (21, 51):
            continue
        name = row.get("name")
        identity = (type_id, name)
        occurrence = occurrences.get(identity, 0)
        occurrences[identity] = occurrence + 1
        key = (type_id, name, occurrence)
        if type_id == 51 and state.get("rawfile_strict"):
            payload = payloads.get(key)
            if payload is None:
                raise ValueError("RawFile payload snapshot is incomplete")
            rows[index]["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        elif type_id == 21 and state.get("soundbank_strict") and row.get("status") != "reference":
            if key not in banks:
                raise ValueError("SoundBank payload snapshot is incomplete")
            rows[index]["payload_sha256"] = _semantic_sha(soundbank_edit_document(banks[key]))
    return rows


def _soundbank_receipts(journal: list[dict], read) -> dict:
    """Bind each inline bank to its original occurrence in the whole inventory."""
    result, occurrences = {}, {}
    for index, row in enumerate(journal):
        if row.get("type_id") != 21:
            continue
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("SoundBank native identity is missing")
        occurrence = occurrences.get(name, 0)
        occurrences[name] = occurrence + 1
        if row.get("status") != "reference":
            result[(21, name, occurrence)] = read(index, row)
    return result


def build_workspace_mixed_asset_crud(workspace, zone_id: str, plan: dict,
                                     output: Path, timeout: int = 1800) -> dict:
    """Build the supported mixed transaction from current staged revisions."""
    proof = plan.get("proof", plan)
    if proof.get("schema") != "replay120-mixed-asset-crud-plan-v1" or proof.get("zone_id") != zone_id:
        raise ValueError("mixed transaction plan has the wrong schema or zone")
    pending = _active_pending_rows(workspace, zone_id)
    current_plan = plan_mixed_asset_crud(workspace, zone_id, pending)
    planned_snapshot = sorted((row["asset_id"], row["revision"]) for row in proof.get("edits", []))
    current_snapshot = sorted((row["asset_id"], row["revision"]) for row in current_plan["edits"])
    if planned_snapshot != current_snapshot:
        raise ValueError("mixed transaction pending revisions changed after preflight")
    output = Path(output).resolve()
    if output.suffix.casefold() != ".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("mixed replacement FF must be outside the configured game directory")
    if output.exists() or any(output.with_suffix(ext).exists() for ext in (".fp", ".fc")):
        raise FileExistsError("mixed replacement FF or patch sidecar already exists")

    cache, decode = workspace._validated_zone_receipt(zone_id)
    body = ZoneBody.parse((cache / decode["final_body_relative_path"]).read_bytes())
    source = Path(decode["source"]["path"]).resolve(strict=True)
    profile = source_profile(source)
    if output.stem != source.stem:
        raise ValueError("mixed replacement FF must retain the source fastfile stem")
    if (profile["sha256"] != proof.get("source_fastfile_sha256") or
            body.source_sha256 != proof.get("source_body_sha256")):
        raise ValueError("mixed transaction source FF/body changed after preflight")
    walk, journal = _read_native_rows(cache, body, require_trace=True)
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    raw_manifest = _native_walk_artifact(walk, "manifest_relative_path")
    run_dir = output.with_suffix(output.suffix + ".mixed-proof")
    run_dir.mkdir(parents=True, exist_ok=False)
    binding = _bind_native_manifest_to_trace(raw_manifest, trace, len(body.data),
        run_dir / "source-manifest.transaction-bound.json",
        journal_path=_native_walk_artifact(walk, "journal_relative_path"))
    current_manifest = Path(binding["bound_manifest_path"])
    semantics, trace_index, by_index = _typed_semantics(body.data, journal, trace, current_manifest)
    rawfile_indices = {row["index"] for row in pending if row.get("type") == "rawfile"}
    rawfile_edits = []
    if rawfile_indices:
        snapshot = workspace._validated_asset_snapshot(zone_id)
        if (snapshot.body.source_sha256 != body.source_sha256 or
                snapshot.source_profile.get("sha256") != profile.get("sha256") or
                snapshot.native_walk.get("walk_key") != walk.get("walk_key") or
                snapshot.native_walk.get("stream_trace_sha256") != walk.get("stream_trace_sha256")):
            raise ValueError("RawFile staged drafts and mixed build do not share the original validated snapshot")
        rawfile_rows = [row for row in pending if row.get("type") == "rawfile"]
        _updated_preview, _relocation_preview, rawfile_edits = plan_rawfile_edits(
            workspace, snapshot, rawfile_rows)
    original_identity = _identity(journal)
    expected_identity = list(original_identity)
    expected_semantics = dict(semantics)
    state = dict(body=body.data, journal=journal, trace=trace, manifest=current_manifest,
                 index=trace_index, by_index=by_index, semantics=semantics,
                 reservations=list(profile["final_header"]["block_sizes"]), steps=[])
    state["rawfile_strict"] = bool(rawfile_indices)
    state["rawfile_payloads"] = (_rawfile_payload_rows(state["body"], journal, trace, current_manifest)
                                 if rawfile_indices else {})
    expected_rawfile_payloads = dict(state["rawfile_payloads"])
    soundbank_rows = [row for row in pending if row.get("type") == "soundbank"]
    state["soundbank_strict"] = bool(soundbank_rows)
    bank_snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True) if soundbank_rows else None
    if bank_snapshot is not None and (bank_snapshot.body.source_sha256 != body.source_sha256 or
            bank_snapshot.source_profile["sha256"] != profile["sha256"] or
            bank_snapshot.native_walk.get("walk_key") != walk.get("walk_key")):
        raise ValueError("SoundBank drafts do not share the original mixed source snapshot")
    state["soundbank_receipts"] = (_soundbank_receipts(journal,
        lambda i, row: workspace._read_typed_soundbank(bank_snapshot, i, row))
        if soundbank_rows else {})
    expected_banks = {key: _semantic_sha(soundbank_edit_document(value))
                      for key, value in state["soundbank_receipts"].items()}
    reader = Path(workspace.acts_path).resolve(strict=True)
    replay = Path(workspace.replay_executable).resolve(strict=True)
    lua_compiler = Path(getattr(workspace, "lua_acts_path", workspace.acts_path)).resolve(strict=True)
    protected = dict(source_fastfile=profile["sha256"],
                     source_patches=tuple(row["sha256"] for row in profile["patches"]),
                     native_reader=acts_tool_identity(reader), lua_compiler=acts_tool_identity(lua_compiler),
                     replay_executable=sha256_file(replay))
    writer_paths = {
        "mixed_bridge": Path(__file__).resolve(strict=True),
        "asset_semantics": Path(__import__("workstation_asset_semantics").__file__).resolve(strict=True),
        "transaction_scheduler": Path(__import__("workstation_asset_transaction").__file__).resolve(strict=True),
        "localize_writer": Path(__import__("workstation_localize").__file__).resolve(strict=True),
        "lua_writer": Path(__import__("workstation_luafile_operations").__file__).resolve(strict=True),
        "image_writer": Path(__import__("workstation_native_asset_edits").__file__).resolve(strict=True),
        "rawfile_writer": Path(__import__("workstation_rawfile").__file__).resolve(strict=True),
        "rawfile_relocator": Path(__import__("workstation_native_child_relocation").__file__).resolve(strict=True),
        "soundbank_writer": Path(__import__("workstation_soundbank").__file__).resolve(strict=True),
    }
    protected["writer_sources"] = {key: sha256_file(path) for key, path in writer_paths.items()}

    def reread(label: str, writer_receipt: dict) -> dict:
        package, native, next_rows, next_trace, next_manifest, next_index, _payloads = _pack_and_walk(
            state["body"], state["reservations"], source, reader, replay,
            run_dir / "intermediates" / label, label, timeout, profile)
        actual_identity = _identity(next_rows)
        if actual_identity != expected_identity:
            raise ValueError(f"{label} native reread changed retained identity/order")
        next_semantics, actual_index, actual_by_index = _typed_semantics(
            state["body"], next_rows, next_trace, next_manifest)
        if next_semantics != expected_semantics:
            raise ValueError(f"{label} native reread changed a retained typed semantic payload")
        next_rawfile_payloads = (_rawfile_payload_rows(state["body"], next_rows, next_trace, next_manifest)
                                 if state["rawfile_strict"] else {})
        if state["rawfile_strict"] and next_rawfile_payloads != expected_rawfile_payloads:
            raise ValueError(f"{label} native reread changed retained or staged RawFile bytes")
        next_banks = {}
        if state["soundbank_strict"]:
            typed_body_path = package.parent / "typed-soundbank.body"
            typed_body_path.write_bytes(state["body"])
            next_banks = _soundbank_receipts(next_rows, lambda i, row: read_native_soundbank(
                body_path=typed_body_path, source_fastfile=package,
                manifest_path=next_manifest, trace_path=next_trace,
                asset_index=i, asset_name=row["name"]))
            actual_banks = {key: _semantic_sha(soundbank_edit_document(value))
                            for key, value in next_banks.items()}
            if actual_banks != expected_banks:
                raise ValueError(f"{label} native reread changed retained or staged SoundBank fields")
        state.update(journal=next_rows, trace=next_trace, manifest=next_manifest,
                     index=actual_index, by_index=actual_by_index, semantics=next_semantics,
                      rawfile_payloads=next_rawfile_payloads, soundbank_receipts=next_banks,
                      package=package, native=native)
        native_receipt = _native_receipt(native, package, state["body"], next_semantics, expected_identity)
        package_fp = package.with_suffix(".fp")
        native_receipt["package_fp_sha256"] = sha256_file(package_fp) if package_fp.is_file() else None
        state["steps"].append(dict(label=label, writer=writer_receipt, native=native_receipt))
        return {"writer": writer_receipt, "native": native_receipt}

    image_rows = (current_plan["family_plans"].get("image") or {}).get("edits", [])
    image_indices = {int(row["asset_id"].rsplit(":", 1)[1]) for row in image_rows}
    trace_index = build_read_span_index(trace, current_manifest, len(state["body"]),
                                       selected_assets=image_indices)
    image_spans = {row["index"]: row for row in trace_index["assets"]}
    mutations = []
    image_data = {}
    for row in image_rows:
        index = int(row["asset_id"].rsplit(":", 1)[1])
        traced = image_spans.get(index)
        if traced is None:
            raise ValueError("complete source trace omits a selected resident image")
        traced.update(index=index, type_id=19, name=row["name"])
        payload, details = _load_image_payload(cache, body, row, journal[index], traced,
                                               walk, profile, source)
        current = read_resident_image(body.data, dict(index=index, **journal[index]),
                                      traced, body.source_sha256)
        semantic = dict(payload_sha256=hashlib.sha256(payload).hexdigest(), format=current["format"],
                        flags=current["flags"], dimensions=list(current["dimensions"]),
                        level_count=current["level_count"], total_size=current["total_size"])
        identity = dict(type_id=19, name=row["name"],
            occurrence=sum(1 for old in journal[:index]
                           if old.get("type_id") == 19 and old.get("name") == row["name"]))
        mutations.append(dict(kind="resident_image", identity=identity,
                              output_payload_sha256=_semantic_sha(semantic)))
        image_data[(19, row["name"], identity["occurrence"])] = (payload, semantic)

    rawfile_expected_original = {}
    rawfile_replacements = {}
    for layout, raw, _payload_bytes, draft in rawfile_edits:
        index = layout.asset_index
        native_row = journal[index]
        name = native_row.get("name")
        occurrence = sum(1 for old in journal[:index]
                         if old.get("type_id") == 51 and old.get("name") == name)
        key = (51, name, occurrence)
        original_raw = state["rawfile_payloads"].get(key)
        if original_raw is None:
            raise ValueError("RawFile draft target is absent from the trace-owned payload snapshot")
        identity = dict(type_id=51, name=name, occurrence=occurrence)
        output_sha = hashlib.sha256(raw).hexdigest()
        mutations.append(dict(kind="rawfile_replace", identity=identity,
                              output_payload_sha256=output_sha))
        rawfile_expected_original[key] = original_raw
        rawfile_replacements[key] = dict(raw=raw, content=draft["content"],
                                         mode=draft["native_source_identity"]["typed_layout"]["editor_mode"],
                                         revision=draft["revision"], index=index)

    bank_replacements = {}
    for row in soundbank_rows:
        index = row["index"]
        native_row = journal[index]
        occurrence = sum(old.get("type_id") == 21 and old.get("name") == row["name"] for old in journal[:index])
        key = (21, row["name"], occurrence)
        receipt = state["soundbank_receipts"].get(key)
        if receipt is None or native_row.get("name") != row["name"]:
            raise ValueError("SoundBank edit is absent from the original typed inventory")
        _path, draft, _payload = _validate_pending_snapshot(cache, index, row["asset_id"], body)
        if draft.get("revision") != row["revision"]:
            raise ValueError("SoundBank revision changed after mixed preflight")
        changes = validate_soundbank_edit_document(draft["content"], receipt)
        preview, _writer = replace_soundbank_alias_scalars(body.data, receipt, changes)
        expected_receipt = dict(receipt, aliases=[dict(alias) for alias in receipt["aliases"]])
        for alias in expected_receipt["aliases"]:
            raw = preview[alias["archive_offset"]:alias["archive_offset"] + ALIAS_SIZE]
            alias.update(raw_hex=raw.hex(), raw_sha256=hashlib.sha256(raw).hexdigest())
        expected_sha = _semantic_sha(soundbank_edit_document(expected_receipt))
        bank_replacements[key] = dict(content=draft["content"], revision=draft["revision"],
                                      original_sha=expected_banks[key], expected_sha=expected_sha)
        mutations.append(dict(kind="soundbank_replace",
            identity=dict(type_id=21, name=row["name"], occurrence=occurrence),
            output_payload_sha256=expected_sha))

    loc_operation = None
    if current_plan["localize_operation_id"]:
        loc_operation = next(row for row in localize_operations(workspace, zone_id)
                             if row["operation_id"] == current_plan["localize_operation_id"])
        loc_semantic = _semantic_sha({"key": loc_operation["name"], "value": loc_operation["content"]})
        mutations.append(dict(kind="localize_append", type_id=41, name=loc_operation["name"],
                              output_payload_sha256=loc_semantic))
    lua_operation = None
    if current_plan["luafile_operation_id"]:
        lua_operation = next(row for row in luafile_operations(workspace, zone_id)
                             if row["operation_id"] == current_plan["luafile_operation_id"])
        lua_semantic = _semantic_sha({"bytecode_sha256": hashlib.sha256(lua_operation["_payload"]).hexdigest()})
        mutations.append(dict(kind="luafile_append", type_id=62, name=lua_operation["name"],
                              output_payload_sha256=lua_semantic))

    def image_writer(mutation, index, _before):
        if index is None:
            raise ValueError("resident image target was not resolved against the current native walk")
        trace_asset = state["by_index"].get(index)
        if trace_asset is None:
            raise ValueError("fresh native trace omitted a resident image target")
        row = state["journal"][index]
        occurrence = sum(1 for old in state["journal"][:index]
                         if old.get("type_id") == 19 and old.get("name") == row["name"])
        payload, _semantic = image_data[(19, row["name"], occurrence)]
        state["body"], writer = replace_resident_image(state["body"], dict(index=index, **row),
            trace_asset, hashlib.sha256(state["body"]).hexdigest(), payload)
        expected_semantics[(19, row["name"])] = mutation["output_payload_sha256"]
        return reread(f"01-resident-image-{index}", writer)

    def rawfile_writer(mutation, index, _before):
        if index is None:
            raise ValueError("RawFile target was not resolved against the current native walk")
        target = mutation["identity"]
        row = state["journal"][index]
        occurrence = sum(1 for old in state["journal"][:index]
                         if old.get("type_id") == 51 and old.get("name") == row.get("name"))
        key = (51, row.get("name"), occurrence)
        replacement = rawfile_replacements.get(key)
        if (row.get("type_id") != 51 or target.get("name") != row.get("name") or
                target.get("occurrence", 0) != occurrence or replacement is None):
            raise ValueError("resolved RawFile identity differs from its immutable staged draft")
        expected_raw = rawfile_expected_original[key]
        if state["rawfile_payloads"].get(key) != expected_raw:
            raise ValueError("RawFile content changed from the original staged pre-edit bytes")
        indexed = build_read_span_index(state["trace"], state["manifest"], len(state["body"]),
                                        selected_assets={index})
        matches = indexed["assets"]
        if len(matches) != 1:
            raise ValueError("current native trace does not uniquely resolve the RawFile target")
        traced = dict(matches[0], index=index, type_id=51, name=row["name"],
                      _all_physical_spans=indexed["_all_physical_spans"])
        context = RawFileReadContext(state["body"])
        _layout, current = read_rawfile(state["body"], dict(row, index=index), traced,
                                        hashlib.sha256(state["body"]).hexdigest(), context=context)
        current_raw = (current["content"].encode("utf-8") if current["mode"] == "text"
                       else __import__("base64").b64decode(current["content"], validate=True))
        if current_raw != expected_raw:
            raise ValueError("current trace-owned RawFile bytes differ from original pending source")
        state["body"], writer = replace_rawfile_payload(
            state["body"], dict(row, index=index), traced, replacement["content"],
            replacement["mode"], hashlib.sha256(state["body"]).hexdigest(),
            str(state["trace"]), str(state["manifest"]))
        relocation = writer.get("relocation", {})
        highwater = relocation.get("stream_reservation_sizes")
        if isinstance(highwater, list) and len(highwater) == len(state["reservations"]):
            state["reservations"] = [max(int(old), int(new))
                                      for old, new in zip(state["reservations"], highwater)]
        state["rawfile_payloads"] = dict(state["rawfile_payloads"])
        state["rawfile_payloads"][key] = replacement["raw"]
        expected_rawfile_payloads[key] = replacement["raw"]
        writer["staged_revision"] = replacement["revision"]
        writer["original_raw_sha256"] = hashlib.sha256(expected_raw).hexdigest()
        writer["replacement_raw_sha256"] = hashlib.sha256(replacement["raw"]).hexdigest()
        return reread(f"02-rawfile-replace-{index}", writer)

    def localize_writer(mutation, index, _before):
        if index is not None:
            raise ValueError("Localize append unexpectedly resolved an existing XAsset")
        state["body"], state["reservations"], writer = append_localize_entry(
            state["body"], loc_operation["name"], loc_operation["content"], state["reservations"],
            state["index"]["max_destination_offsets"], hashlib.sha256(state["body"]).hexdigest(),
            state["trace"], state["manifest"])
        derived = writer.get("stream_reservation_sizes")
        if not isinstance(derived, list) or len(derived) != len(state["reservations"]):
            raise ValueError("Localize append omitted its relocated stream reservation contract")
        state["reservations"] = [max(int(old), int(new))
                                  for old, new in zip(state["reservations"], derived)]
        expected_identity.append((41, loc_operation["name"]))
        expected_semantics[(41, loc_operation["name"])] = mutation["output_payload_sha256"]
        return reread("03-localize-append", writer)

    def soundbank_writer(mutation, index, _before):
        if index is None:
            raise ValueError("SoundBank target was not resolved from the current native inventory")
        target = mutation["identity"]
        key = (21, target["name"], target.get("occurrence", 0))
        current = state["soundbank_receipts"].get(key)
        replacement = bank_replacements[key]
        if current is None or current.get("asset_index") != index or (
                _semantic_sha(soundbank_edit_document(current)) != replacement["original_sha"]):
            raise ValueError("SoundBank target changed from its original staged fields")
        changes = validate_soundbank_edit_document(replacement["content"], current)
        state["body"], writer = replace_soundbank_alias_scalars(state["body"], current, changes)
        expected_banks[key] = replacement["expected_sha"]
        writer["staged_revision"] = replacement["revision"]
        return reread(f"03-soundbank-replace-{index}", writer)

    def lua_writer(mutation, index, _before):
        if index is not None:
            raise ValueError("LuaFile append unexpectedly resolved an existing XAsset")
        lua_rows = [(i, row) for i, row in enumerate(state["journal"]) if row["type_id"] == 62]
        if not lua_rows:
            raise ValueError("LuaFile append requires a surviving native template row")
        template_index, template_row = lua_rows[0]
        final_index = len(state["journal"]) - 1
        state["body"], writer = append_luafile_tail(state["body"], lua_operation["name"],
            lua_operation["_payload"], {row["name"] for row in state["journal"]},
            template_index, template_row["name"],
            _trace_row(template_row, template_index, state["by_index"][template_index]),
            _trace_row(state["journal"][final_index], final_index, state["by_index"][final_index]),
            hashlib.sha256(state["body"]).hexdigest(), state["trace"], state["manifest"])
        derived = writer.get("stream_reservation_highwaters")
        if not isinstance(derived, list) or len(derived) != len(state["reservations"]):
            raise ValueError("LuaFile append omitted its relocated stream reservation contract")
        state["reservations"] = [max(int(old), int(new))
                                  for old, new in zip(state["reservations"], derived)]
        expected_identity.append((62, lua_operation["name"]))
        expected_semantics[(62, lua_operation["name"])] = mutation["output_payload_sha256"]
        return reread("04-luafile-append", writer)

    transaction = execute_transaction(mutations, lambda: _transaction_rows(state), {
        "resident_image": image_writer, "rawfile_replace": rawfile_writer,
        "soundbank_replace": soundbank_writer,
        "localize_append": localize_writer,
        "luafile_append": lua_writer,
    })
    final_ff = output
    final_fp = output.with_suffix(".fp")
    final_pending = _active_pending_rows(workspace, zone_id)
    final_plan = plan_mixed_asset_crud(workspace, zone_id, final_pending)
    changed_pending = sorted((row.get("asset_id"), row.get("revision")) for row in final_plan["edits"])
    if changed_pending != current_snapshot:
        raise ValueError("mixed transaction pending snapshot changed during native packaging")
    final_cache, final_decode = workspace._validated_zone_receipt(zone_id)
    final_body = ZoneBody.parse((final_cache / final_decode["final_body_relative_path"]).read_bytes())
    final_walk, _final_rows = _read_native_rows(final_cache, final_body, require_trace=True)
    if (final_body.source_sha256 != body.source_sha256 or
            final_decode.get("cache_key") != decode.get("cache_key") or
            final_walk.get("walk_key") != walk.get("walk_key") or
            final_walk.get("stream_trace_sha256") != walk.get("stream_trace_sha256")):
        raise ValueError("source decode/native-walk receipt changed during mixed packaging")
    final_profile = source_profile(source)
    if (final_profile["sha256"] != profile["sha256"] or
            tuple(row["sha256"] for row in final_profile["patches"]) != protected["source_patches"] or
            acts_tool_identity(reader) != protected["native_reader"] or
            acts_tool_identity(lua_compiler) != protected["lua_compiler"] or
            sha256_file(replay) != protected["replay_executable"] or
            {key: sha256_file(path) for key, path in writer_paths.items()} != protected["writer_sources"]):
        raise ValueError("source FF/patch, writer, native reader, Lua compiler, or Replay executable changed during packaging")
    receipt = dict(schema="replay120-mixed-asset-crud-result-v1", status="native-mixed-asset-transaction-pass",
                   zone_id=zone_id, source_fastfile_sha256=profile["sha256"],
                   source_body_sha256=body.source_sha256,
                   transaction=transaction, steps=state["steps"],
                   output_fastfile=None,
                   output_fp=None,
                   protected_inputs_unchanged=True,
                   final=dict(assets=len(state["journal"]), typed_semantics=len(state["semantics"]),
                              rawfile_payloads=len(state["rawfile_payloads"]),
                              soundbank_documents=len(state["soundbank_receipts"]),
                              rawfile_payloads_exact=(state["rawfile_payloads"] == expected_rawfile_payloads),
                              soundbank_documents_exact=(
                                  {key: _semantic_sha(soundbank_edit_document(value))
                                   for key, value in state["soundbank_receipts"].items()} == expected_banks),
                              identity_order_exact=_identity(state["journal"]) == expected_identity,
                              exact_eof=state["native"]["manifest"].get("serialized_bytes_read") == len(state["body"]),
                              complete=state["native"]["manifest"].get("complete"),
                              success=state["native"]["manifest"].get("success"),
                              tested=state["native"]["manifest"].get("tested"),
                              failed=state["native"]["manifest"].get("failed"),
                              unavailable=state["native"]["manifest"].get("unavailable")),
                   live_game_tested=False)
    receipt_path = run_dir / "mixed-asset-crud-receipt.json"
    try:
        # Publish only after pending/source/patch/tool drift checks all pass.
        last_native = state["steps"][-1]["native"]
        output_ff_sha, output_fp_sha = _copy_verified_package(
            state["package"], final_ff, last_native["package_sha256"],
            last_native["package_fp_sha256"])
        receipt["output_fastfile"] = dict(path=str(final_ff), sha256=output_ff_sha)
        receipt["output_fp"] = (dict(path=str(final_fp), sha256=output_fp_sha)
                                if output_fp_sha is not None else None)
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    except Exception:
        for path in (final_ff, final_fp, receipt_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    return _publication_result(receipt, proof.get("edits", []), final_ff, final_fp, profile, receipt_path)
