"""Staging, planning and native packaging for owned Replay type-19 images.

New resources are authored as strict whole-resource 2D DDS. The native row
writer owns the XAsset insertion and trace-derived stream schedule.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
from contextlib import contextmanager

from workstation_asset_operations import (new_asset_identity, stage_operation,
                                           validate_operation)
from workstation_fastfiles import (ZoneBody, _native_walk_artifact,
    make_replay_header_only_patch, pack_replay_uncompressed,
    parse_image_dds_data_url, sha256_file,)
from roundtrip_replay_fastfile import verify_native

TYPE_ID = 19
TYPE_NAME = "image"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextmanager
def _preserved_private_stage(parent: Path):
    """Delete successful scratch work, but retain diagnostics after any failure."""
    parent = parent.resolve(strict=True)
    stage = Path(tempfile.mkdtemp(prefix="resident-image-stage-", dir=parent)).absolute()
    initial = stage.lstat()
    identity = (initial.st_dev, initial.st_ino)
    if (stage.parent.resolve(strict=True) != parent or stat.S_ISLNK(initial.st_mode) or
            bool(getattr(stage, "is_junction", lambda: False)())):
        raise ValueError("resident image temporary stage is not a fresh direct child of TEMP")
    try:
        yield stage
    except BaseException as exc:
        try:
            exc.add_note(f"Resident image native-stage artifacts retained at: {stage}")
        except AttributeError:
            pass
        raise
    else:
        current = stage.lstat()
        resolved = stage.resolve(strict=True)
        if (stage.parent.resolve(strict=True) != parent or resolved != stage or
                (current.st_dev, current.st_ino) != identity or
                stat.S_ISLNK(current.st_mode) or bool(getattr(stage, "is_junction", lambda: False)())):
            raise ValueError("refusing recursive cleanup because the private native stage path changed")
        shutil.rmtree(stage)


def _verify_retained_body_bytes(source: bytes, candidate: bytes, *,
                                first_payload_offset: int, alias_offsets: list[int],
                                operation: str, expected_candidate_bytes: int,
                                removed_root_offset: int | None = None) -> dict:
    """Require a pure XAsset-row/tail splice except count and traced pointer fields."""
    insert_size = 16
    count_range = range(16, 20)
    mutable = set(count_range)
    for offset in alias_offsets:
        if type(offset) is not int or offset < 0 or offset + 8 > len(source):
            raise ValueError("alias relocation proof contains an invalid source archive offset")
        mutable.update(range(offset, offset + 8))
    compared = 0
    if operation not in ("append", "remove"):
        raise ValueError("unknown retained-byte splice direction")
    if type(expected_candidate_bytes) is not int or len(candidate) != expected_candidate_bytes:
        raise ValueError("candidate body length differs from the exact row/resource splice extent")
    if operation == "remove":
        row_offset = first_payload_offset - insert_size
        if type(removed_root_offset) is not int or removed_root_offset < first_payload_offset:
            raise ValueError("image removal lacks a proven final root archive offset")
    for source_offset, byte in enumerate(source):
        if operation == "append":
            target_offset = source_offset if source_offset < first_payload_offset else source_offset + insert_size
        else:
            if source_offset >= removed_root_offset:
                continue
            if row_offset <= source_offset < first_payload_offset:
                continue
            target_offset = source_offset if source_offset < row_offset else source_offset - insert_size
        if source_offset in mutable:
            continue
        if target_offset >= len(candidate) or candidate[target_offset] != byte:
            raise ValueError(f"retained body byte changed outside the table splice at {source_offset:#x}")
        compared += 1
    return dict(status="retained-body-bytes-pass", source_bytes=len(source),
                candidate_bytes=len(candidate), compared_source_bytes=compared,
                ignored_count_field_bytes=len(count_range),
                ignored_traced_alias_field_bytes=8 * len(alias_offsets),
                table_splice_offset=first_payload_offset, table_splice_bytes=insert_size,
                removed_root_archive_offset=removed_root_offset)


def _source(workspace, zone_id: str, snapshot=None):
    snapshot = snapshot or workspace._validated_asset_snapshot(zone_id)
    if (snapshot.zone_id != zone_id or not snapshot.native_walk or
            not snapshot.native_walk.get("stream_trace_enabled") or
            len(snapshot.native_rows or []) != len(snapshot.body.assets)):
        raise ValueError("resident image row operation requires a complete native trace and inventory")
    workspace._require_asset_request_snapshot(snapshot, zone_id)
    profile, walk, body = snapshot.source_profile, snapshot.native_walk, snapshot.body
    if (walk.get("identity", {}).get("body_sha256") != body.source_sha256 or
            walk.get("identity", {}).get("source_sha256") != profile.get("sha256") or
            walk.get("identity", {}).get("patch_sha256s") !=
            [row["sha256"] for row in profile.get("patches", [])]):
        raise ValueError("resident image trace differs from current source FF/patch identity")
    if any(row.get("extension") == ".fc" for row in profile.get("patches", [])):
        raise ValueError("resident image row operations do not support source FC patch chains")
    from workstation_image_row_operations import append_resident_image_tail
    writer_path = Path(append_resident_image_tail.__code__.co_filename).resolve(strict=True)
    identity = dict(body_sha256=body.source_sha256,
        source_fastfile_sha256=profile["sha256"],
        patch_sha256s=[row["sha256"] for row in profile.get("patches", [])],
        native_walk_key=walk["walk_key"], native_manifest_sha256=walk["manifest_sha256"],
        stream_trace_sha256=walk["stream_trace_sha256"],
        writer_module_path=str(writer_path), writer_module_sha256=sha256_file(writer_path))
    return snapshot, identity


def _decode_authoring(workspace, content: str, snapshot) -> tuple[bytes, dict]:
    import workstation_asset_codecs as codec
    if not isinstance(content, str):
        raise ValueError("resident image creation requires a strict DDS data URL")
    templates = [i for i, row in enumerate(snapshot.native_rows)
                 if row.get("type_id") == TYPE_ID and row.get("status") != "reference"]
    if content.startswith("data:application/octet-stream;base64,"):
        dds = parse_image_dds_data_url(content)
        width, height, depth, elements, fmt, mips, payload = codec.import_dds_to_replay_image_resource(dds)
        if depth != 1 or elements != 1:
            raise ValueError("new resident image roots are currently restricted to native 2D resources")
        wanted_format = fmt
        editor_format = "dds-resource"
        content_hash = _sha(dds)
        requested_mips = None
    else:
        raise ValueError("resident image creation currently accepts strict DDS only")
    if not templates:
        raise ValueError("image creation requires a trace-owned resident type-19 format template")
    from workstation_trace_index import build_read_span_index
    from workstation_native_asset_edits import read_resident_image
    trace = _native_walk_artifact(snapshot.native_walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(snapshot.native_walk, "manifest_relative_path")
    indexed = build_read_span_index(trace, manifest, len(snapshot.body.data),
                                    selected_assets=set(templates))["assets"]
    spans_by_index = {item["index"]: item for item in indexed}
    template_choices = []
    for index in templates:
        row = snapshot.native_rows[index]
        trace_row = spans_by_index.get(index)
        if trace_row is None:
            continue
        try:
            candidate = read_resident_image(snapshot.body.data, dict(row, index=index),
                dict(trace_row, name=row.get("name"), type_id=TYPE_ID), snapshot.body.source_sha256)
        except (ValueError, KeyError, IndexError):
            continue
        root = candidate["root_bytes"]
        # Pinned Replay conversion code sets no GfxImageFlags for a plain 2D,
        # single-element resident resource; it uses 0x8000 for cube, 0x10000
        # for 3D, and 0x20000 for arrays. Other source bits are not carried to
        # the newly authored 2D descriptor.
        if (candidate["dimensions"][2:] != (1, 1) or
                candidate["flags"] & (0x8000 | 0x10000 | 0x20000) or
                struct.unpack_from("<Q", root, 8)[0] != 0 or
                struct.unpack_from("<Q", root, 0xD8)[0] != 0 or
                root[0x32] != 0 or any(root[0x38:0xD8])):
            continue
        if wanted_format is not None and candidate["format"] != wanted_format:
            continue
        template_choices.append((index, candidate))
    if not template_choices:
        raise ValueError("no trace-owned 2D image template has a compatible native format")
    template_index, layout = template_choices[0]
    if editor_format == "dds-resource":
        return payload, dict(format=fmt, dimensions=[width, height, depth, elements], mip_count=mips,
                             editor_format=editor_format, dds_sha256=content_hash,
                             template_asset_index=template_index,
                             template_flags=layout["flags"])
    raise AssertionError("strict DDS authoring branch was not selected")


def operations(workspace, zone_id: str, *, _snapshot=None) -> list[dict]:
    snapshot, identity = _source(workspace, zone_id, _snapshot)
    result = []
    paths = set(snapshot.cache_path.glob("pending-edits/op-a-i-*/current.json"))
    paths.update(snapshot.cache_path.glob("pending-edits/op-r-*/current.json"))
    for path in sorted(paths):
        try:
            header = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ValueError("resident image operation record is unreadable") from error
        if header.get("type_id") != TYPE_ID:
            continue
        row, payload = validate_operation(snapshot.cache_path, path, identity)
        if (row.get("zone_id") != zone_id or row.get("type_id") != TYPE_ID or
                row.get("type") != TYPE_NAME or row.get("source_body_sha256") != snapshot.body.source_sha256 or
                row.get("writer_identity") != dict(path=identity["writer_module_path"],
                                                    sha256=identity["writer_module_sha256"])):
            raise ValueError("resident image append belongs to another native source or writer")
        if row["operation"] == "append":
            dds = parse_image_dds_data_url(row["content"])
            from workstation_asset_codecs import import_dds_to_replay_image_resource
            *_, decoded = import_dds_to_replay_image_resource(dds)
            if decoded != payload:
                raise ValueError("resident image staged native bytes differ from its strict DDS source")
        elif (row["operation"] == "remove" and
              (row.get("index") != len(snapshot.body.assets)-1 or
               snapshot.native_rows[row["index"]].get("name") != row.get("name"))):
            raise ValueError("resident image removal no longer targets its exact final source row")
        row["pending_path"], row["_payload"] = str(path), payload
        result.append(row)
    names = [row["name"] for row in result if row["operation"] == "append"]
    if len(names) != len(set(names)):
        raise ValueError("duplicate pending resident image names")
    for name in names:
        if any(row.get("type_id") == TYPE_ID and row.get("name") == name
               for row in snapshot.native_rows):
            raise ValueError("resident image name already exists in the source zone")
    return result


def remove_resident_image_asset(workspace, asset_id: str, revision: str) -> dict:
    opened = workspace.get_asset(asset_id)
    if (opened.get("type_id") != TYPE_ID or opened.get("type") != TYPE_NAME or
            opened.get("row_remove_supported") is not True):
        raise ValueError(opened.get("row_remove_reason") or "resident image removal is unavailable for this row")
    if opened.get("revision") != revision:
        raise ValueError("Asset revision conflict; reload before removing")
    if opened.get("pending_path"):
        raise ValueError("Restore the active image edit before removing this row")
    zone_id, index_text = asset_id.rsplit(":", 1)
    index = int(index_text)
    snapshot, identity = _source(workspace, zone_id)
    if index != len(snapshot.body.assets)-1:
        raise ValueError("resident image removal is supported only for the final XAsset row")
    from workstation_trace_index import build_read_span_index
    trace = _native_walk_artifact(snapshot.native_walk, "stream_trace_relative_path")
    manifest = _native_walk_artifact(snapshot.native_walk, "manifest_relative_path")
    index_data = build_read_span_index(trace, manifest, len(snapshot.body.data), selected_assets={index})
    records = [item for item in index_data["assets"] if item.get("index") == index]
    if len(records) != 1:
        raise ValueError("resident image removal trace is not unique")
    owner = dict(records[0], name=opened["name"], xasset_index=index,
                  type_id=TYPE_ID, _all_physical_spans=index_data["_all_physical_spans"])
    from workstation_native_asset_edits import read_resident_image
    native = dict(snapshot.native_rows[index], index=index)
    layout = read_resident_image(snapshot.body.data, native, owner, snapshot.body.source_sha256)
    import workstation_asset_codecs as codec
    dds = codec.export_replay_image_resource_to_dds(*layout["dimensions"], layout["format"],
        layout["level_count"], layout["payload"], flags=layout["flags"])
    content = "data:application/octet-stream;base64," + base64.b64encode(dds).decode("ascii")
    writer_path = Path(__import__("workstation_image_row_operations").__file__).resolve(strict=True)
    from workstation_image_row_operations import append_resident_image_tail
    writer_path = Path(append_resident_image_tail.__code__.co_filename).resolve(strict=True)
    receipt = dict(schema="replay120-resident-image-row-remove-receipt-v1",
        status="resident-image-preserve-pass", asset_name=opened["name"], source_index=index,
        source_body_sha256=snapshot.body.source_sha256,
        source=dict(sha256=_sha(content.encode("utf-8"))),
        result=dict(native_payload_sha256=layout["payload_sha256"],
                    native_payload_bytes=len(layout["payload"]), native_type_id=TYPE_ID))
    row = dict(schema=4, operation="remove", operation_id=f"op-r-{index}",
        asset_id=asset_id, zone_id=zone_id, type_id=TYPE_ID, type=TYPE_NAME,
        name=opened["name"], index=index, xasset_index=index, content=content,
        language="image/dds-base64", source_body_sha256=snapshot.body.source_sha256,
        content_sha256=_sha(content.encode("utf-8")), native_source_identity=identity,
        compiler_receipt=receipt,
        compiler_receipt_sha256=_sha(json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=False).encode("utf-8")),
        writer_identity=dict(path=str(writer_path), sha256=sha256_file(writer_path)))
    workspace._assert_asset_snapshot_current(snapshot)
    return stage_operation(snapshot.cache_path, row, layout["payload"])


def create_resident_image_asset(workspace, zone_id: str, name: str, content: str,
                                revision: str | None = None, *, _snapshot=None) -> dict:
    from workstation_asset_operations import _safe_asset_name
    name = _safe_asset_name(name)
    snapshot, identity = _source(workspace, zone_id, _snapshot)
    if any(row.get("type_id") == TYPE_ID and row.get("name") == name
           for row in snapshot.native_rows):
        raise ValueError("resident image name already exists in the source zone")
    payload, layout = _decode_authoring(workspace, content, snapshot)
    active = [row for row in operations(workspace, zone_id, _snapshot=snapshot)
              if row.get("name") == name]
    if active:
        if len(active) != 1 or revision is None or active[0].get("revision") != revision:
            raise ValueError("resident image revision conflict; reload before saving")
    elif revision is not None:
        raise ValueError("resident image append no longer exists; reload before saving")
    writer_path = Path(identity["writer_module_path"])
    import workstation_asset_codecs as codec
    from workstation_asset_codecs import DEFAULT_TEXCONV_TOOL
    tool_path = Path(os.environ.get("REPLAY_TEXCONV", str(DEFAULT_TEXCONV_TOOL))).expanduser().resolve(strict=True)
    receipt = dict(schema="replay120-resident-image-row-append-receipt-v1",
        status="resident-image-dds-import-pass", asset_name=name,
        source=dict(sha256=_sha(content.encode("utf-8"))),
        compiler=dict(path=str(tool_path), sha256=sha256_file(tool_path),
                      codec_module_sha256=sha256_file(Path(codec.__file__)),
                      tool_invoked=False, operation="strict DDS decode; native resident layout validation"),
        result=dict(native_payload_sha256=_sha(payload), native_payload_bytes=len(payload),
                    native_type_id=TYPE_ID, **layout))
    row = dict(schema=4, operation="append", asset_id=new_asset_identity(zone_id, TYPE_ID, name),
        zone_id=zone_id, type_id=TYPE_ID, type=TYPE_NAME, name=name, index=None,
        xasset_index=None, content=content, language="image/dds-base64",
        source_body_sha256=snapshot.body.source_sha256,
        content_sha256=_sha(content.encode("utf-8")), native_source_identity=identity,
        compiler_receipt=receipt,
        compiler_receipt_sha256=_sha(json.dumps(receipt, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=False).encode("utf-8")),
        writer_identity=dict(path=str(writer_path), sha256=identity["writer_module_sha256"]))
    workspace._assert_asset_snapshot_current(snapshot)
    staged = stage_operation(snapshot.cache_path, row, payload, revision)
    return dict(**staged, status="native-resident-image-append-staged", editable=True,
        archive_writable=False, payload_format="Replay type-19 resident DDS image",
        package_status="Resident image row is staged for complete native reread")


def get_new_resident_image_asset(workspace, asset_id: str, *, _snapshot=None) -> dict:
    from workstation_asset_operations import new_asset_identity
    zone_id, marker = asset_id.rsplit(":", 1)
    if not marker.startswith("new-19-"):
        raise ValueError("Malformed new resident-image identity")
    rows = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
            if row.get("asset_id") == asset_id and row.get("operation") == "append"]
    if len(rows) != 1:
        raise KeyError(asset_id)
    row = rows[0]
    return {key: value for key, value in row.items() if not key.startswith("_")} | dict(
        editable=True, archive_writable=False, payload_format="Replay type-19 resident DDS image",
        package_status="Resident image append queued for complete native reread")


def plan_resident_image_crud(workspace, zone_id: str, pending_rows: list[dict], *, _snapshot=None) -> dict:
    snapshot = _snapshot or workspace._validated_asset_snapshot(zone_id)
    active = operations(workspace, zone_id, _snapshot=snapshot)
    if len(active) != 1 or len(pending_rows) != 1 or active[0]["operation_id"] != pending_rows[0].get("operation_id"):
        raise ValueError("resident image row management supports one exact staged type-19 operation")
    row = active[0]
    if (pending_rows[0].get("revision") != row.get("revision") or
            pending_rows[0].get("operation") != row.get("operation")):
        raise ValueError("resident image operation changed during preflight")
    if row["operation"] == "remove":
        index = row.get("index")
        if index != len(snapshot.body.assets)-1:
            raise ValueError("resident image removal requires the final source row")
    elif row["operation"] != "append":
        raise ValueError("unsupported resident image operation")
    count_delta = 1 if row["operation"] == "append" else -1
    return dict(source_body_sha256=snapshot.body.source_sha256,
        native_walk_key=snapshot.native_walk["walk_key"], original_xasset_count=len(snapshot.body.assets),
        final_xasset_count=len(snapshot.body.assets)+count_delta, operation_count=1,
        edits=[dict(operation=row["operation"], operation_id=row["operation_id"], asset_id=row["asset_id"],
                    revision=row["revision"], type=TYPE_NAME, type_id=TYPE_ID, name=row["name"])],
        support="resident-image-row-native-transaction",
        limits="Append uses one strict 2D resource in a trace-owned compatible inline template; removal supports only an exclusive physical final-row tail")


def build_workspace_resident_image_crud(workspace, zone_id: str, plan: dict, output: Path,
                                        timeout: int, *, _snapshot=None) -> dict:
    """Build and fully reread one appended image row, keeping artifacts private until verified."""
    from workstation_trace_index import build_read_span_index
    from workstation_image_row_operations import append_resident_image_tail
    snapshot = _snapshot or workspace._validated_asset_snapshot(zone_id)
    active = operations(workspace, zone_id, _snapshot=snapshot)
    if len(active) != 1 or len(plan.get("edits", [])) != 1 or active[0]["revision"] != plan["edits"][0].get("revision"):
        raise ValueError("resident image append changed after preflight")
    operation = active[0]
    workspace._assert_asset_snapshot_current(snapshot)
    trace = _native_walk_artifact(snapshot.native_walk, "stream_trace_relative_path")
    manifest_path = _native_walk_artifact(snapshot.native_walk, "manifest_relative_path")
    journal = _native_walk_artifact(snapshot.native_walk, "journal_relative_path")
    final_index = len(snapshot.body.assets)-1
    template_index = None
    selected = {final_index}
    if operation["operation"] == "append":
        templates = [i for i, row in enumerate(snapshot.native_rows)
                     if row.get("type_id") == TYPE_ID and row.get("status") != "reference"]
        template_index = int(operation["compiler_receipt"]["result"]["template_asset_index"])
        if template_index not in templates:
            raise ValueError("resident image template changed after staging")
        selected.add(template_index)
    spans = build_read_span_index(trace, manifest_path, len(snapshot.body.data), selected_assets=selected)
    by_index = {row["index"]: row for row in spans["assets"]}
    final = dict(by_index[final_index], name=snapshot.native_rows[final_index].get("name"),
                 xasset_index=final_index, type_id=snapshot.native_rows[final_index]["type_id"])
    if operation["operation"] == "append":
        template = dict(by_index[template_index], name=snapshot.native_rows[template_index]["name"],
                        xasset_index=template_index, type_id=TYPE_ID)
        result, writer_receipt = append_resident_image_tail(snapshot.body.data, operation["name"],
            operation["_payload"], operation["compiler_receipt"]["result"]["format"],
            tuple(operation["compiler_receipt"]["result"]["dimensions"]),
            operation["compiler_receipt"]["result"]["mip_count"],
            {row.get("name") for row in snapshot.native_rows if row.get("type_id") == TYPE_ID},
            template_index, snapshot.native_rows[template_index]["name"], template, final,
            snapshot.body.source_sha256, trace, manifest_path,
            snapshot.source_profile["final_header"]["block_sizes"],
            expected_trace_sha256=snapshot.native_walk["stream_trace_sha256"],
            expected_manifest_sha256=snapshot.native_walk["manifest_sha256"])
    elif operation["operation"] == "remove":
        from workstation_image_row_operations import remove_final_resident_image_tail
        image_row = dict(snapshot.native_rows[final_index], index=final_index)
        owner = dict(final, _all_physical_spans=spans["_all_physical_spans"])
        result, writer_receipt = remove_final_resident_image_tail(snapshot.body.data, final_index,
            operation["name"], image_row, owner, snapshot.body.source_sha256, trace, manifest_path,
            expected_trace_sha256=snapshot.native_walk["stream_trace_sha256"],
            expected_manifest_sha256=snapshot.native_walk["manifest_sha256"])
    else:
        raise ValueError("unsupported resident image operation")
    profile = snapshot.source_profile
    derived_reservations = writer_receipt.get("stream_reservation_sizes", profile["final_header"]["block_sizes"])
    reservations = [max(a, b) for a, b in zip(profile["final_header"]["block_sizes"],
                                              derived_reservations, strict=True)]
    package = pack_replay_uncompressed(result, reservations,
        xfile_version=profile["final_header"]["xfile_version"],
        transient_type=profile["header"]["transient_type"])
    output = Path(output).resolve()
    if output.exists() or output.suffix.casefold() != ".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("resident image output must be a new .ff outside the configured game directory")
    targets = [output, *(output.with_suffix(item["extension"]) for item in profile.get("patches", [])),
               output.with_suffix(output.suffix + ".edit-receipt.json")]
    if any(path.exists() for path in targets):
        raise FileExistsError("resident image output or sidecar already exists")
    import os
    temp = Path(os.environ.get("TEMP", r"C:\Temp")).resolve()
    temp.mkdir(parents=True, exist_ok=True)
    with _preserved_private_stage(temp) as stage:
        staged_ff = stage / snapshot.source_path.name
        staged_ff.write_bytes(package)
        staged_body = stage / "candidate.dec"
        staged_body.write_bytes(result)
        for patch in profile.get("patches", []):
            staged_ff.with_suffix(patch["extension"]).write_bytes(
                make_replay_header_only_patch(Path(patch["path"]).read_bytes(), package))
        staged_identity = {str(path): sha256_file(path) for path in [staged_ff,
            *(staged_ff.with_suffix(item["extension"]) for item in profile.get("patches", []))]}
        native = verify_native(staged_ff, result, snapshot.source_path, workspace.acts_path,
            workspace.replay_executable, stage / "native-proof", timeout=timeout, trace=True)
        if any(sha256_file(Path(path)) != digest for path, digest in staged_identity.items()):
            raise ValueError("native verifier changed a staged image FF or patch")
        manifest = native.get("manifest", {})
        expected_count = len(snapshot.body.assets) + (1 if operation["operation"] == "append" else -1)
        reference_count = sum(row.get("status") == "reference" for row in snapshot.native_rows)
        if operation["operation"] == "remove" and snapshot.native_rows[-1].get("status") == "reference":
            raise ValueError("reference-only resident image cannot be removed")
        loaded_assets = manifest.get("loaded_assets")
        if (not manifest.get("complete") or not manifest.get("success") or
                manifest.get("top_level_index") != expected_count or
                manifest.get("tested") != expected_count-reference_count or
                type(loaded_assets) is not int or loaded_assets < expected_count-reference_count or
                native.get("normalized_table_count") != expected_count or
                len(native.get("reference_only_rows", [])) != reference_count or
                manifest.get("failed") != 0 or manifest.get("unavailable") != 0 or
                manifest.get("serialized_bytes_read") != len(result)):
            # Preserve the exact failed native result outside the disposable
            # staging directory so the gate can be diagnosed without another
            # reader run. The private caller chose this output path; no source
            # or shared cache is modified.
            failure_dir = output.parent / (output.name + ".native-failure")
            source_manifest = Path(native.get("manifest_path", ""))
            if source_manifest.is_file():
                failure_dir.mkdir(parents=True, exist_ok=True)
                for filename in ("manifest.json", "assets.jsonl", "stream-trace.jsonl",
                                 "acts-native.log", "native-reader.log"):
                    candidate = source_manifest.parent / filename
                    if candidate.is_file():
                        shutil.copy2(candidate, failure_dir / filename)
            summary = {key: manifest.get(key) for key in
                       ("complete", "success", "loaded_assets", "tested", "top_level_index", "failed",
                        "unavailable", "serialized_bytes_read", "error")}
            summary["expected_loaded_assets"] = expected_count
            summary["expected_tested_assets"] = expected_count - reference_count
            summary["expected_reference_only"] = reference_count
            summary["normalized_table_count"] = native.get("normalized_table_count")
            summary["failure_evidence"] = str(failure_dir) if failure_dir.exists() else None
            raise ValueError("resident image row operation failed complete Replay native reread: " +
                             json.dumps(summary, sort_keys=True))
        journal_path = Path(native["manifest_path"]).parent / manifest.get("journal", "assets.jsonl")
        native_rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        expected = [dict(type_id=row.get("type_id"), name=row.get("name")) for row in snapshot.native_rows]
        if operation["operation"] == "append":
            expected.append(dict(type_id=TYPE_ID, name=operation["name"]))
        else:
            expected.pop()
        normalized_path = native.get("normalized_inventory_path")
        if reference_count and not normalized_path:
            raise ValueError("native reread omitted the normalized table inventory for reference-only rows")
        if normalized_path:
            normalized_bytes = Path(normalized_path).read_bytes()
            if hashlib.sha256(normalized_bytes).hexdigest() != native.get("normalized_inventory_sha256"):
                raise ValueError("native normalized table inventory changed after verification")
            inventory = json.loads(normalized_bytes)
            normalized_rows = inventory.get("normalized_rows")
            if (inventory.get("normalized_inventory_count") != expected_count or
                    not isinstance(normalized_rows, list) or len(normalized_rows) != expected_count):
                raise ValueError("native normalized inventory does not cover the complete decoded XAsset table")
            normalized_identity = [dict(type_id=row.get("type_id"), name=row.get("name"))
                                   for row in normalized_rows]
            normalized_positions = [row.get("index") for row in normalized_rows]
            actual_references = inventory.get("reference_only_rows", [])
            expected_references = [dict(index=i, type_id=snapshot.body.assets[i].type_id,
                name=snapshot.native_rows[i].get("name"),
                pointer_token=snapshot.body.assets[i].pointer_token)
                for i, row in enumerate(snapshot.native_rows) if row.get("status") == "reference"]
            actual_reference_identity = [dict(index=row.get("index"), type_id=row.get("type_id"),
                name=row.get("name"), pointer_token=row.get("pointer_token"))
                for row in actual_references]
            if actual_reference_identity != expected_references:
                raise ValueError("native reread reference-only identities differ from the exact retained table rows")
        else:
            normalized_rows = native_rows
            normalized_identity = [dict(type_id=row.get("type_id"), name=row.get("name"))
                                   for row in normalized_rows]
            normalized_positions = list(range(len(normalized_rows)))
        if normalized_identity != expected:
            raise ValueError("native reread changed retained XAsset order or appended image identity")
        if normalized_positions != list(range(expected_count)):
            raise ValueError("native normalized table order/index differs from the decoded XAsset table")
        from workstation_asset_semantics import typed_semantics
        trace_output = Path(native["manifest_path"]).parent / manifest.get("stream_trace", "stream-trace.jsonl")
        from workstation_luafile_crud import _bind_native_manifest_to_trace
        bound_src, bound_out = stage / "source-bound.json", stage / "output-bound.json"
        _bind_native_manifest_to_trace(manifest_path, trace, len(snapshot.body.data), bound_src, journal_path=journal)
        _bind_native_manifest_to_trace(Path(native["manifest_path"]), trace_output, len(result),
                                       bound_out, journal_path=journal_path)
        source_semantics, _, _ = typed_semantics(snapshot.body.data, snapshot.native_rows, trace, bound_src,
                                                  include_images=False)
        output_semantics, _, _ = typed_semantics(result, normalized_rows, trace_output, bound_out,
                                                  include_images=False)
        expected_source_semantics = dict(source_semantics)
        expected_output_semantics = dict(output_semantics)
        if expected_source_semantics != expected_output_semantics:
            raise ValueError("native image row operation changed retained typed asset semantics")
        if operation["operation"] == "append":
            from workstation_scriptfile_crud import _verify_retained_aliases
            alias_audit = _verify_retained_aliases(snapshot.body.data, trace, bound_src,
                trace_output, bound_out, result)
        else:
            from workstation_luafile_operations import _trace_contract
            from workstation_scriptfile_crud import _verify_removed_aliases
            removed_ranges = tuple(tuple(item) for item in writer_receipt["removed_stream_ranges"])
            src_contract = _trace_contract(snapshot.body.data, trace, bound_src,
                table_row_delta=-16, removed_stream_ranges=removed_ranges,
                logical_delete_ranges=(removed_ranges[1],), removed_owner=expected_count)
            out_contract = _trace_contract(result, trace_output, bound_out, table_row_delta=0)
            alias_audit = _verify_removed_aliases(trace, trace_output, expected_count,
                src_contract[1], src_contract[7], out_contract[1],
                source_body=snapshot.body.data, source_intervals=src_contract[2])
        retained_bytes = _verify_retained_body_bytes(snapshot.body.data, result,
            first_payload_offset=snapshot.body.first_payload_offset,
            alias_offsets=writer_receipt.get("pointer_relocation", writer_receipt.get("alias_relocation", {}))
                .get("packed_alias_archive_offsets", []), operation=operation["operation"],
            expected_candidate_bytes=(len(snapshot.body.data) + 16 +
                writer_receipt["appended_root_bytes"] + writer_receipt["appended_name_bytes"] +
                writer_receipt["appended_payload_bytes"] if operation["operation"] == "append" else
                writer_receipt["removed_root_archive_offset"] - 16),
            removed_root_offset=writer_receipt.get("removed_root_archive_offset"))
        if operation["operation"] == "append":
            from workstation_native_asset_edits import read_resident_image
            out_index = build_read_span_index(trace_output, native["manifest_path"], len(result),
                                               selected_assets={expected_count-1})
            out_spans = [item for item in out_index["assets"] if item.get("index") == expected_count-1]
            if len(out_spans) != 1:
                raise ValueError("native reread has no unique appended image trace record")
            appended_layout = read_resident_image(result, dict(native_rows[-1], index=expected_count-1),
                dict(out_spans[0], name=operation["name"], type_id=TYPE_ID), _sha(result))
            typed = operation["compiler_receipt"]["result"]
            if (appended_layout["payload"] != operation["_payload"] or
                    appended_layout["format"] != typed["format"] or
                    appended_layout["dimensions"] != tuple(typed["dimensions"]) or
                    appended_layout["level_count"] != typed["mip_count"]):
                raise ValueError("native reread image root/subresources differ from staged DDS")
        # Output is still private until every identity and semantic gate passes.
        from workstation_shader_crud import _publish_verified_files
        staged_outputs = [(output, staged_ff.read_bytes(), _sha(staged_ff.read_bytes()))]
        for patch in profile.get("patches", []):
            staged_patch = staged_ff.with_suffix(patch["extension"])
            staged_outputs.append((output.with_suffix(patch["extension"]), staged_patch.read_bytes(), sha256_file(staged_patch)))
        receipt = dict(schema="replay120-resident-image-row-native-package-v1",
            status="resident-image-row-native-package-pass", operation=operation["operation_id"],
            operation_kind=operation["operation"],
            source_body_sha256=snapshot.body.source_sha256, output_body_sha256=_sha(result),
            native_manifest_sha256=sha256_file(native["manifest_path"]),
            writer=writer_receipt, retained_alias_audit=alias_audit,
            retained_body_byte_audit=retained_bytes,
            native_counts={key: manifest.get(key) for key in
                ("loaded_assets", "tested", "reference_only", "failed", "unavailable", "serialized_bytes_read")})
        receipt_path = output.with_suffix(output.suffix + ".edit-receipt.json")
        receipt_bytes = json.dumps(receipt, sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        staged_outputs.append((receipt_path, receipt_bytes, _sha(receipt_bytes)))
        artifacts = _publish_verified_files(staged_outputs)
    return dict(status="resident-image-row-native-package-pass", output=str(output),
        output_sha256=sha256_file(output), writer=writer_receipt, native_counts=receipt["native_counts"],
        artifacts=artifacts)
