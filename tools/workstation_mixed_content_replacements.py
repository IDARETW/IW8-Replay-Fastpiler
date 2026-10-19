"""Sequential native transaction for fixed-layout mixed content replacements.

This route composes the existing typed writers; it does not admit CRUD,
variable-sized image/shader children, or any alternate source-freshness path.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import stat

from workstation_fastfiles import (
    ZoneBody, _native_walk_artifact, _read_native_rows, _validate_pending_snapshot,
    _export_native_type, _native_stringtable_export_rows,
    _validate_omnvar_effective_closure, _prepare_omnvar_mp_source_proof,
    _omnvar_validation_sha256,
    SHADER_TYPE_IDS, acts_tool_identity, source_profile, sha256_file,
)
from workstation_luafile_crud import _pack_and_walk, _bind_native_manifest_to_trace
from workstation_trace_index import build_read_span_index
from workstation_native_asset_edits import read_inline_shader, read_native_shader, replace_inline_shader, read_resident_image, replace_resident_image
from workstation_scriptfile_crud import _scriptfile_payload
from workstation_fastfiles import replace_scriptfiles_inline_children
from workstation_luafile import replace_luafiles_inline_children
from workstation_stringtable import inspect_stringtable, replace_stringtable_rows
from workstation_localize import (LOCALIZE_ROOT_CALLER_RVA, inspect_localize_entry,
    replace_localize_value_same_extent, replace_localize_values_with_relocation)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha(value: dict) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8"))


def _same_source(identity: dict, body: ZoneBody, profile: dict, walk: dict) -> bool:
    return (identity.get("body_sha256") == body.source_sha256 and
            identity.get("source_fastfile_sha256") == profile.get("sha256") and
            identity.get("native_walk_key") == walk.get("walk_key") and
            identity.get("native_manifest_sha256") == walk.get("manifest_sha256") and
            identity.get("stream_trace_sha256") == walk.get("stream_trace_sha256"))


def _trace_rows(trace: Path, manifest: Path, body_size: int, journal: list[dict]) -> tuple[dict, dict[int, dict]]:
    index = build_read_span_index(trace, manifest, body_size)
    by_index = {row["index"]: row for row in index["assets"]}
    if len(by_index) != len(journal):
        raise ValueError("complete native trace omitted one or more XAsset rows")
    for i, row in enumerate(journal):
        traced = by_index.get(i)
        if (traced is None or traced.get("type_id") != row.get("type_id")):
            raise ValueError("native trace type/index differs from the ordered journal")
        traced.update(index=i, xasset_index=i, type_id=row["type_id"], name=row["name"])
    return index, by_index


def _family_identity(journal: list[dict]) -> list[tuple[int, str]]:
    return [(row.get("type_id"), row.get("name")) for row in journal]


def _rawfile_semantics(body: bytes, journal: list[dict], trace: Path,
                       manifest: Path) -> dict[tuple[int, str, int], bytes]:
    from workstation_rawfile import RawFileReadContext, read_rawfile
    selected = {i for i, row in enumerate(journal)
                if row.get("type_id") == 51 and row.get("status") != "reference"}
    if not selected:
        return {}
    indexed = build_read_span_index(trace, manifest, len(body), selected_assets=selected)
    by_index = {row["index"]: row for row in indexed["assets"]}
    context = RawFileReadContext(body)
    occurrences = {}
    result = {}
    for i, row in enumerate(journal):
        if row.get("type_id") != 51:
            continue
        name = row.get("name")
        occurrence = occurrences.get(name, 0)
        occurrences[name] = occurrence + 1
        if row.get("status") == "reference":
            continue
        traced = by_index.get(i)
        if traced is None:
            raise ValueError("complete trace omits a retained RawFile")
        traced.update(index=i, type_id=51, name=name,
                      _all_physical_spans=indexed["_all_physical_spans"])
        _layout, value = read_rawfile(body, dict(row, index=i), traced, _sha(body), context=context)
        raw = (value["content"].encode("utf-8") if value["mode"] == "text"
               else base64.b64decode(value["content"], validate=True))
        result[(51, name, occurrence)] = raw
    return result


def _script_trace_report(index: dict, journal: list[dict], body_size: int) -> dict:
    selected = []
    for i, row in enumerate(journal):
        if row.get("type_id") != 52:
            continue
        asset = next((item for item in index["assets"] if item.get("index") == i), None)
        if asset is None:
            raise ValueError("complete trace omits a ScriptFile while building the ownership report")
        selected.append(dict(asset, xasset_index=i, type_id=52, name=row["name"]))
    return dict(xasset_count=len(journal), serialized_bytes_read=body_size,
        selected_count=len(selected), selected_assets=selected,
        global_max_destination_offsets=index.get("max_destination_offsets", {}),
        global_physical_load_count_by_stream=index.get("physical_load_count_by_stream", {}),
        global_physical_load_bytes_by_stream=index.get("physical_load_bytes_by_stream", {}),
        packed_target_stream_counts=index.get("packed_target_stream_counts", {}),
        packed_alias_token_highword_counts=index.get("packed_alias_token_highword_counts", {}))


def build_content_replacements(workspace, zone_id: str, plan: dict,
                               output: Path, timeout: int = 1800) -> dict:
    """Build a fixed-layout mixed replacement package with strict rereads."""
    from workstation_mixed_asset_crud import _active_pending_rows, _publication_result, _copy_verified_package
    from workstation_fastfiles import _pending_content_sha
    from workstation_rawfile import (RawFileReadContext, read_rawfile, replace_rawfile_payload,
                                     plan_rawfile_edits)
    from workstation_mixed_asset_crud import _rawfile_payload_rows, _soundbank_receipts
    from workstation_soundbank import (ALIAS_SIZE, read_native_soundbank,
        soundbank_edit_document, validate_soundbank_edit_document, replace_soundbank_alias_scalars)
    from workstation_asset_codecs import encode_stringtable_sections

    proof = plan.get("proof", plan)
    if proof.get("mode") != "content-replacements" or proof.get("schema") != "replay120-mixed-asset-crud-plan-v1" or proof.get("zone_id") != zone_id:
        raise ValueError("content replacement plan has the wrong schema, mode, or zone")
    pending = _active_pending_rows(workspace, zone_id)
    planned = sorted((row.get("asset_id"), row.get("revision")) for row in proof.get("edits", []))
    actual = sorted((row.get("asset_id"), row.get("revision")) for row in pending)
    if not pending or planned != actual or any(row.get("operation") for row in pending):
        raise ValueError("content replacement revisions changed or include unsupported CRUD")
    from workstation_mixed_asset_crud import plan_mixed_asset_crud
    current_plan = plan_mixed_asset_crud(workspace, zone_id, pending)
    if sorted((row.get("asset_id"), row.get("revision")) for row in current_plan.get("edits", [])) != planned:
        raise ValueError("family-specific preflight no longer matches the queued revisions")
    allowed = {"image", "rawfile", "soundbank", "localize", "scriptfile", "luafile", "stringtable", *SHADER_TYPE_IDS}
    if any(row.get("type") not in allowed for row in pending):
        raise ValueError("content replacement plan contains an unsupported family")

    output = Path(output).resolve()
    if output.suffix.casefold() != ".ff" or output.is_relative_to(workspace.game_root):
        raise ValueError("mixed replacement FF must be outside the configured game directory")
    if output.exists() or any(output.with_suffix(ext).exists() for ext in (".fp", ".fc")):
        raise FileExistsError("mixed replacement FF or sidecar already exists")

    cache, decode = workspace._validated_zone_receipt(zone_id)
    source = Path(decode["source"]["path"]).resolve(strict=True)
    profile = source_profile(source)
    body = ZoneBody.parse((cache / decode["final_body_relative_path"]).read_bytes())
    if (source.stem != output.stem or profile.get("sha256") != proof.get("source_fastfile_sha256") or
            body.source_sha256 != proof.get("source_body_sha256")):
        raise ValueError("source FF/body differs from the preflight identity")
    walk, journal = _read_native_rows(cache, body, require_trace=True)
    if (walk.get("walk_key") != proof.get("native_walk_key") or
            walk.get("manifest_sha256") != proof.get("native_manifest_sha256") or
            walk.get("stream_trace_sha256") != proof.get("stream_trace_sha256")):
        raise ValueError("source native walk/trace differs from preflight")
    trace = _native_walk_artifact(walk, "stream_trace_relative_path")
    raw_manifest = _native_walk_artifact(walk, "manifest_relative_path")
    run_dir = output.with_suffix(output.suffix + ".content-replacement-proof")
    run_dir.mkdir(parents=True, exist_ok=False)
    bound = _bind_native_manifest_to_trace(raw_manifest, trace, len(body.data),
        run_dir / "source-manifest.transaction-bound.json",
        journal_path=_native_walk_artifact(walk, "journal_relative_path"))
    manifest = Path(bound["bound_manifest_path"])
    reader = Path(workspace.acts_path).resolve(strict=True)
    replay = Path(workspace.replay_executable).resolve(strict=True)
    lua_compiler = Path(getattr(workspace, "lua_acts_path", workspace.acts_path)).resolve(strict=True)
    protected = dict(source_fastfile=profile["sha256"],
        source_patches=tuple(row["sha256"] for row in profile["patches"]),
        reader=acts_tool_identity(reader), lua_compiler=acts_tool_identity(lua_compiler),
        replay=sha256_file(replay))
    import workstation_asset_transaction, workstation_localize, workstation_native_asset_edits
    import workstation_scriptfile_crud, workstation_luafile, workstation_stringtable
    import workstation_rawfile, workstation_soundbank, workstation_asset_codecs
    import workstation_trace_index, workstation_mixed_asset_crud, workstation_luafile_crud
    import workstation_luafile_operations, workstation_native_child_relocation
    import workstation_asset_semantics, workstation_omnvars, workstation_omnvar_includes
    writer_paths = {"mixed_content": Path(__file__).resolve(strict=True),
        "mixed_dispatch": Path(workstation_mixed_asset_crud.__file__).resolve(strict=True),
        "fastfiles": Path(__import__("workstation_fastfiles").__file__).resolve(strict=True),
        "transaction": Path(workstation_asset_transaction.__file__).resolve(strict=True),
        "asset_semantics": Path(workstation_asset_semantics.__file__).resolve(strict=True),
        "localize": Path(workstation_localize.__file__).resolve(strict=True),
        "native_edits": Path(workstation_native_asset_edits.__file__).resolve(strict=True),
        "scriptfile": Path(workstation_scriptfile_crud.__file__).resolve(strict=True),
        "luafile": Path(workstation_luafile.__file__).resolve(strict=True),
        "luafile_crud": Path(workstation_luafile_crud.__file__).resolve(strict=True),
        "luafile_operations": Path(workstation_luafile_operations.__file__).resolve(strict=True),
        "stringtable": Path(workstation_stringtable.__file__).resolve(strict=True),
        "trace_index": Path(workstation_trace_index.__file__).resolve(strict=True),
        "native_child_relocation": Path(workstation_native_child_relocation.__file__).resolve(strict=True),
        "rawfile": Path(workstation_rawfile.__file__).resolve(strict=True),
        "soundbank": Path(workstation_soundbank.__file__).resolve(strict=True),
        "asset_codecs": Path(workstation_asset_codecs.__file__).resolve(strict=True),
        "omnvars": Path(workstation_omnvars.__file__).resolve(strict=True),
        "omnvar_includes": Path(workstation_omnvar_includes.__file__).resolve(strict=True)}
    protected["writer_sources"] = {name: sha256_file(path) for name, path in writer_paths.items()}
    original_identity = _family_identity(journal)
    selected_types = {19, 21, 41, 51, 52, 54, 62, *SHADER_TYPE_IDS.values()}
    expected_extra: dict[tuple[int, str, int], str] = {}
    replacement_data: dict[tuple[int, str, int], dict] = {}
    table_rows: dict[int, list[list[str]]] = {}
    table_names: dict[int, str] = {}

    # Establish an exact source semantic baseline for each supported family.
    initial_index, initial_by_index = _trace_rows(trace, manifest, len(body.data), journal)
    state = dict(body=body.data, journal=journal, trace=trace, manifest=manifest,
                 index=initial_index, by_index=initial_by_index,
                 reservations=list(profile["final_header"]["block_sizes"]), steps=[])
    table_indices = {i for i, row in enumerate(journal) if row.get("type_id") == 54 and row.get("status") != "reference"}
    if table_indices:
        export_root, export_index = _export_native_type(source, zone_id, body, cache, walk,
            journal, 54, "stringtable", reader, replay, timeout)
        table_rows = _native_stringtable_export_rows(export_root, export_index, table_indices)
        table_names = {i: journal[i]["name"] for i in table_indices}
    stringtable_plan = (proof.get("family_plans", {}).get("stringtable") or {})
    closure_contract = (stringtable_plan.get("proof") or {}).get("omnvar_closure")
    source_closure = None
    source_closure_rows = {}
    if closure_contract is not None:
        closure_indices = closure_contract.get("table_indices")
        root_index = closure_contract.get("root_index")
        effective_contract = closure_contract.get("effective_validation")
        if (not isinstance(closure_indices, list) or type(root_index) is not int or
                not isinstance(effective_contract, dict) or
                effective_contract.get("status") != "effective-native-bound-closure-validated"):
            raise ValueError("preflight Omnvar closure contract is malformed")
        source_closure_rows = _native_stringtable_export_rows(
            export_root, export_index, set(closure_indices))
        root_name = journal[root_index].get("name")
        closure_proof, _ = _prepare_omnvar_mp_source_proof(
            source=source, zone_id=zone_id, body=body, cache_path=cache,
            walk_receipt=walk, native_rows=journal, root_index=root_index,
            root_name=root_name, original_rows=source_closure_rows[root_index],
            export_root=export_root, export_index=export_index,
            trace_path=trace, manifest_path=manifest)
        source_closure = closure_proof.get("source_closure")
        if (sorted(item.get("asset_index") for item in source_closure.get("tables", [])) !=
                sorted(closure_indices) or
                _omnvar_validation_sha256(source_closure) != closure_contract.get("source_closure_sha256")):
            raise ValueError("current native Omnvar source closure differs from preflight")

    def typed_values(current_body: bytes, rows: list[dict], index: dict,
                     by_index: dict[int, dict], tables: dict[int, list[list[str]]]) -> dict:
        values = {}
        current_body_sha = _sha(current_body)
        from workstation_localize import LocalizeReadContext
        localize_context = LocalizeReadContext(current_body)
        # Build one exact physical-target index per complete native trace.
        # Pointer roots can move during an otherwise valid serialization, so
        # their stable target is the unique owning asset/span and its bytes,
        # never a raw body offset or a bag of possible destination matches.
        target_spans: dict[tuple[int, int], set[tuple[int, str, int, int, int, int, str]]] = {}
        def add_target_span(span: dict, owner_index: int, child_ordinal: int) -> None:
            location = span.get("destination_stream_location")
            start, size = span.get("archive_offset"), span.get("size")
            if (not isinstance(location, dict) or type(location.get("stream")) is not int or
                    type(location.get("offset")) is not int or type(start) is not int or
                    type(size) is not int or size <= 0 or start < 0 or start > len(current_body) - size):
                return
            record = (owner_index, str(span.get("origin")), size, start, child_ordinal,
                      span.get("event_sequence", -1), _sha(current_body[start:start + size]))
            target_spans.setdefault((location["stream"], location["offset"]), set()).add(record)
        for owner in index.get("assets", []):
            owner_index = owner.get("index")
            if type(owner_index) is int:
                for ordinal, span in enumerate(owner.get("read_spans", [])):
                    add_target_span(span, owner_index, ordinal)
        for ordinal, span in enumerate(index.get("preamble_spans", [])):
            add_target_span(span, -1, ordinal)
        def retained_root(type_id: int, traced: dict, root_at: int, root_size: int,
                          pointer_offsets: tuple[int, ...]) -> str:
            root = bytearray(current_body[root_at:root_at + root_size])
            root_location = traced.get("root_stream_location")
            events = traced.get("packed_pointer_events")
            targets = []

            def target_signature(event: dict) -> tuple:
                target = event.get("resolved_target_stream_location")
                if (not isinstance(target, dict) or type(target.get("stream")) is not int or
                        type(target.get("offset")) is not int or target["offset"] < 0):
                    raise ValueError("retained root callback has an invalid target")
                callback_seq = event.get("sequence")
                candidates = [item for item in target_spans.get(
                    (target["stream"], target["offset"]), set())
                    if type(callback_seq) is int and type(item[5]) is int and item[5] < callback_seq]
                candidate_ids = {(item[0], item[1], item[2], item[4], item[6]) for item in candidates}
                if len(candidate_ids) != 1:
                    raise ValueError("retained root callback target is missing or ambiguous in the full trace")
                owner_id, origin, size, child_ordinal, digest = next(iter(candidate_ids))
                return (target["stream"], owner_id, child_ordinal, origin, size, digest)

            for pointer_offset in pointer_offsets:
                token = struct.unpack_from("<Q", root, pointer_offset)[0]
                if token in (0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0):
                    targets.append((pointer_offset, "sentinel", token))
                    continue
                if not isinstance(root_location, dict) or not isinstance(events, list):
                    raise ValueError("retained root pointer lacks complete native callback context")
                root_stream = root_location.get("stream")
                if type(root_stream) is not int or type(root_location.get("offset")) is not int:
                    raise ValueError("retained root has an invalid stream location")
                field = {"stream": root_stream, "offset": root_location["offset"] + pointer_offset}
                matches = [event for event in events if event.get("kind") in ("packed_resolve", "packed_alias")
                    and event.get("xasset_index") == traced.get("index")
                    and event.get("type_id") == type_id and event.get("raw_token") == token
                    and event.get("field_stream_location") == field
                    and isinstance(event.get("resolved_target_stream_location"), dict)]
                if len(matches) != 1:
                    raise ValueError("retained root pointer has no unique exact native resolve")
                targets.append((pointer_offset, target_signature(matches[0])))
                struct.pack_into("<Q", root, pointer_offset, 0)

            if not isinstance(root_location, dict) or type(root_location.get("stream")) is not int or type(root_location.get("offset")) is not int:
                raise ValueError("retained root has no exact logical stream location")
            root_range = (root_location["stream"], root_location["offset"],
                          root_location["offset"] + root_size)
            span_pointer_offsets: dict[tuple[int, int], list[tuple[int, tuple]]] = {}
            for event in events or []:
                field = event.get("field_stream_location")
                if not isinstance(field, dict) or type(field.get("stream")) is not int or type(field.get("offset")) is not int:
                    continue
                if (field["stream"] == root_range[0] and
                        root_range[1] <= field["offset"] <= root_range[2] - 8):
                    root_pointer_offset = field["offset"] - root_range[1]
                    if root_pointer_offset not in pointer_offsets:
                        raise ValueError("retained typed root has an unclassified pointer field")
                    continue
                placements = []
                callback_sequence = event.get("sequence")
                if type(callback_sequence) is not int:
                    raise ValueError("nested retained pointer callback has no sequence identity")
                for span in traced.get("read_spans", []):
                    destination = span.get("destination_stream_location")
                    start, size = span.get("archive_offset"), span.get("size")
                    sequence = span.get("event_sequence")
                    if (not isinstance(destination, dict) or destination.get("stream") != field["stream"] or
                            type(destination.get("offset")) is not int or type(start) is not int or
                            type(size) is not int or size < 8 or type(sequence) is not int or
                            sequence >= callback_sequence):
                        continue
                    delta = field["offset"] - destination["offset"]
                    if 0 <= delta <= size - 8:
                        placements.append((start + delta, size, delta))
                unique_placements = set(placements)
                if not unique_placements:
                    continue
                if len(unique_placements) != 1:
                    raise ValueError("nested retained pointer has ambiguous physical ownership")
                physical, span_size, delta = next(iter(unique_placements))
                token = event.get("raw_token")
                if type(token) is not int or struct.unpack_from("<Q", current_body, physical)[0] != token:
                    raise ValueError("nested retained pointer bytes differ from their native callback")
                target = target_signature(event)
                span_key = (physical - delta, span_size)
                span_pointer_offsets.setdefault(span_key, []).append((delta, target))
            spans = []
            for span_ordinal, span in enumerate(traced.get("read_spans", [])):
                start, size = span.get("archive_offset"), span.get("size")
                if (type(start) is not int or type(size) is not int or size <= 0 or
                        start < 0 or start > len(current_body) - size):
                    raise ValueError("retained typed root has an invalid physical trace span")
                if start == root_at and size == root_size:
                    continue
                normalized = bytearray(current_body[start:start + size])
                pointer_targets = span_pointer_offsets.get((start, size), [])
                for pointer_offset, _target in pointer_targets:
                    normalized[pointer_offset:pointer_offset + 8] = b"\0" * 8
                spans.append((span_ordinal, span.get("origin"), size,
                              _sha(bytes(normalized)), pointer_targets))
            return _canonical_sha(dict(root_sha256=_sha(bytes(root)), pointer_targets=targets,
                                       spans=spans))

        from workstation_luafile_crud import _bytecodes
        all_lua_spans = {i: by_index[i] for i, row in enumerate(rows)
                         if row.get("type_id") == 62 and row.get("status") != "reference"}
        lua_payloads = _bytecodes(current_body, rows, all_lua_spans) if all_lua_spans else {}
        occurrences: dict[tuple[int, str], int] = {}
        for i, row in enumerate(rows):
            typ, name = row.get("type_id"), row.get("name")
            pair = (typ, name)
            occ = occurrences.get(pair, 0); occurrences[pair] = occ + 1
            key = (typ, name, occ)
            if row.get("status") == "reference" or typ not in selected_types:
                continue
            traced = by_index[i]
            if typ == 52:
                _root, payload = _scriptfile_payload(current_body, traced, i, name)
                values[key] = _sha(payload)
            elif typ == 62:
                values[key] = lua_payloads[name]
            elif typ == 54:
                expected_rows = tables.get(i)
                if expected_rows is None:
                    raise ValueError("StringTable semantic baseline is incomplete")
                layout, observed = inspect_stringtable(current_body, i, name, traced,
                    expected_rows, current_body_sha,
                    global_string_data_spans=index.get("string_data_spans", []),
                    require_packed_dictionary_proof=(name.replace("\\", "/").casefold() ==
                                                     "omnvars/mp/omnvars.csv"))
                values[key] = _canonical_sha({"rows": observed})
            elif typ == 19:
                # Editable mixed images are strictly resident 2D, but retained
                # type-19 rows may be streamed/array/volume resources. Preserve
                # those through their traced root shape and complete physical
                # children instead of forcing them through the resident editor.
                try:
                    image = read_resident_image(current_body, dict(row, index=i), traced, current_body_sha)
                except ValueError:
                    root_spans = [s for s in traced.get("read_spans", [])
                                  if s.get("origin") == "load_stream_call" and
                                  s.get("reader_start_arg") == 0 and s.get("size") == 232]
                    if len(root_spans) != 1:
                        raise ValueError("retained image lacks one exact native root span")
                    root_at = root_spans[0].get("archive_offset")
                    if type(root_at) is not int or not 0 <= root_at <= len(current_body) - 232:
                        raise ValueError("retained image root is outside the decoded body")
                    values[key] = retained_root(19, traced, root_at, 232, (0, 0xE0))
                else:
                    values[key] = _canonical_sha(dict(payload_sha256=image["payload_sha256"],
                        format=image["format"], flags=image["flags"], dimensions=list(image["dimensions"]),
                        level_count=image["level_count"], total_size=image["total_size"]))
            elif typ == 41:
                asset = localize_context.body.assets[i]
                if asset.pointer_token != 0xFFFFFFFFFFFFFFFE:
                    raise ValueError("retained LocalizeEntry has an unsupported XAsset root pointer")
                roots = [span for span in traced.get("read_spans", [])
                         if span.get("origin") == "load_stream_call" and
                         span.get("reader_start_arg") == 0 and span.get("size") == 16]
                if len(roots) != 1:
                    raise ValueError("retained LocalizeEntry lacks one exact 16-byte root span")
                root_location = roots[0].get("destination_stream_location")
                if (root_location != traced.get("root_stream_location") or
                        not isinstance(root_location, dict) or root_location.get("stream") != 1 or
                        roots[0].get("caller_rva") != LOCALIZE_ROOT_CALLER_RVA):
                    raise ValueError("retained LocalizeEntry root lacks the pinned stream-1 native callsite")
                root_at = roots[0].get("archive_offset")
                if type(root_at) is not int or not 0 <= root_at <= len(current_body) - 16:
                    raise ValueError("retained LocalizeEntry root is outside the decoded body")
                key_token, value_token = struct.unpack_from("<QQ", current_body, root_at)
                if key_token == 0xFFFFFFFFFFFFFFFE and value_token == 0xFFFFFFFFFFFFFFFE:
                    _layout, text = inspect_localize_entry(current_body, i, name, traced,
                        current_body_sha, context=localize_context)
                    values[key] = _canonical_sha({"key": text["key"], "value": text["value"]})
                else:
                    # Retained rows may alias a previously loaded value string
                    # or use a native null sentinel. Keep the complete root and
                    # child-byte semantics, normalizing only exact callback-
                    # proven pointer fields. This fallback never grants edit
                    # eligibility; the selected editable row still uses the
                    # strict inline-only Localize adapter above.
                    values[key] = retained_root(41, traced, root_at, 16, (0, 8))
            elif typ == 51:
                raw = state_rawfiles.get(key)
                if raw is None:
                    raise ValueError("RawFile semantic snapshot is incomplete")
                values[key] = _sha(raw)
            elif typ == 21:
                bank = state_banks.get(key)
                if bank is None:
                    raise ValueError("SoundBank semantic snapshot is incomplete")
                from workstation_soundbank import soundbank_edit_document
                values[key] = _canonical_sha(soundbank_edit_document(bank))
            elif typ in SHADER_TYPE_IDS.values():
                root_spans = [span for span in traced.get("read_spans", [])
                              if span.get("origin") == "load_stream_call" and span.get("size") == 40]
                if len(root_spans) != 1:
                    raise ValueError("shader has no unique trace-owned 40-byte root")
                root_at = root_spans[0].get("archive_offset")
                if type(root_at) is not int or not 0 <= root_at <= len(current_body) - 40:
                    raise ValueError("shader root span is outside the current body")
                try:
                    shader = read_native_shader(current_body, dict(row, index=i), traced,
                        current_body_sha, trace_assets=index["assets"])
                except ValueError:
                    values[key] = retained_root(typ, traced, root_at, 40, (0, 8, 24))
                    continue
                if shader.get("editable") is not False:
                    values[key] = shader["program_sha256"]
                else:
                    # Recognized shared null aliases are read-only and expose
                    # their exact shared program through the dedicated reader.
                    values[key] = _canonical_sha(dict(status=shader["status"],
                        retained_root=retained_root(typ, traced, root_at, 40, (0, 8, 24)),
                        program_sha256=shader["program_sha256"], debug_name=shader["debug_name"]))
        return values

    state_rawfiles = {}
    if any(row.get("type_id") == 51 for row in journal):
        state_rawfiles = _rawfile_semantics(body.data, journal, trace, manifest)
    state_banks = {}
    if any(row.get("type_id") == 21 for row in journal):
        source_snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True)
        if source_snapshot.body.source_sha256 != body.source_sha256 or source_snapshot.native_walk.get("walk_key") != walk.get("walk_key"):
            raise ValueError("SoundBank drafts differ from the shared mixed source snapshot")
        from workstation_mixed_asset_crud import _soundbank_receipts
        from workstation_soundbank import soundbank_edit_document
        state_banks = _soundbank_receipts(journal,
            lambda i, row: workspace._read_typed_soundbank(source_snapshot, i, row))
    expected_extra = typed_values(body.data, journal, initial_index, initial_by_index, table_rows)
    mutations = []
    staged_by_key = {}
    type_ids = {"localize": 41, "scriptfile": 52, "luafile": 62, "stringtable": 54,
                **SHADER_TYPE_IDS}
    rawfile_edits = []
    if any(row.get("type") == "rawfile" for row in pending):
        from workstation_rawfile import plan_rawfile_edits
        source_snapshot = workspace._validated_asset_snapshot(zone_id, require_trace=True)
        if (source_snapshot.body.source_sha256 != body.source_sha256 or
                source_snapshot.source_profile.get("sha256") != profile.get("sha256") or
                source_snapshot.native_walk.get("walk_key") != walk.get("walk_key")):
            raise ValueError("RawFile drafts differ from the shared mixed source snapshot")
        _, _, rawfile_edits = plan_rawfile_edits(workspace, source_snapshot,
            [row for row in pending if row.get("type") == "rawfile"])
    rawfile_staged = {}
    for layout, raw, _payload_bytes, draft in rawfile_edits:
        index = layout.asset_index
        name = journal[index].get("name")
        occurrence = sum(1 for prior in journal[:index]
                         if prior.get("type_id") == 51 and prior.get("name") == name)
        key = (51, name, occurrence)
        rawfile_staged[key] = dict(raw=raw, draft=draft, index=index)
    for row in pending:
        asset_id = row.get("asset_id")
        try: index = int(asset_id.rsplit(":", 1)[1])
        except (AttributeError, IndexError, ValueError) as error: raise ValueError("pending asset id is malformed") from error
        if not 0 <= index < len(journal) or journal[index].get("name") != row.get("name"):
            raise ValueError("staged replacement identity differs from native row")
        typ = type_ids.get(row["type"], 19 if row["type"] == "image" else 51 if row["type"] == "rawfile" else 21)
        if journal[index].get("type_id") != typ or body.assets[index].type_id != typ:
            raise ValueError("staged replacement type differs from original XAsset")
        _pending_path, draft, payload_path = _validate_pending_snapshot(cache, index, asset_id, body)
        if draft.get("revision") != row.get("revision") or not _same_source(draft.get("native_source_identity", {}), body, profile, walk):
            raise ValueError("staged replacement draft/source identity is stale")
        compiler = draft.get("compiler_receipt")
        if not isinstance(compiler, dict) or _canonical_sha(compiler) != draft.get("compiler_receipt_sha256"):
            raise ValueError("staged replacement compiler receipt is missing or changed")
        payload = payload_path.read_bytes()
        payload_sha = _sha(payload)
        if payload_sha != draft.get("edited_payload_sha256") or compiler.get("result", {}).get("native_payload_sha256") != payload_sha:
            raise ValueError("staged replacement payload differs from its compiler receipt")
        pair = (typ, row["name"])
        occurrence = sum(1 for previous in journal[:index]
                         if previous.get("type_id") == typ and previous.get("name") == row["name"])
        key = (typ, row["name"], occurrence)
        if key not in expected_extra and typ not in (19,):
            raise ValueError("target is not present as an inline trace-owned semantic asset")
        original_semantic = expected_extra.get(key)
        if typ == 41:
            desired = _canonical_sha({"key": row["name"], "value": draft.get("content")})
            replacement_data[key] = dict(content=draft["content"], revision=row["revision"], index=index)
            kind = "localize_replace"
        elif typ == 52:
            desired = payload_sha
            kind = "scriptfile_replace"
        elif typ == 62:
            desired = payload_sha
            kind = "luafile_replace"
        elif typ == 54:
            new_rows = list(csv.reader(io.StringIO(draft["content"], newline="")))
            sections = encode_stringtable_sections(row["name"], new_rows)
            if (sections["rows"] != compiler.get("input", {}).get("rows") or
                    sections["columns"] != compiler.get("input", {}).get("columns")):
                raise ValueError("staged StringTable CSV differs from compiled table dimensions")
            expected_sections = json.dumps(dict(schema=1, kind="stringtable-sections",
                name=sections["name"], rows=sections["rows"], columns=sections["columns"],
                header_base64=base64.b64encode(sections["header"]).decode("ascii"),
                cells_base64=base64.b64encode(sections["cells"]).decode("ascii"),
                hashes_base64=base64.b64encode(sections["hashes"]).decode("ascii"),
                dictionary=sections["dictionary"]), sort_keys=True, separators=(",", ":")).encode("utf-8")
            if payload != expected_sections:
                raise ValueError("staged StringTable binary sections differ from immutable CSV content")
            desired = _canonical_sha({"rows": new_rows})
            replacement_data[key] = dict(payload=payload, rows=new_rows, revision=row["revision"], index=index)
            kind = "stringtable_replace"
        elif typ in SHADER_TYPE_IDS.values():
            source_shader = read_inline_shader(body.data, dict(journal[index], index=index),
                initial_by_index[index], body.source_sha256, trace_assets=initial_index["assets"])
            expected_layout = dict(root_archive_offset=source_shader["root_archive_offset"],
                name_archive_offset=source_shader["name_archive_offset"],
                child_archive_offset=source_shader["program_archive_offset"],
                child_bytes=len(source_shader["program"]), debug_name=source_shader["debug_name"],
                debug_name_stream_location=source_shader["debug_name_stream_location"])
            if (draft.get("native_source_identity", {}).get("typed_layout") != expected_layout or
                    len(payload) != len(source_shader["program"])):
                raise ValueError("shader replacement changes the pinned source layout or child extent")
            from workstation_asset_codecs import dxbc_native_shader_type
            if dxbc_native_shader_type(payload) != typ:
                raise ValueError("compiled DXBC stage differs from its native XAsset type")
            desired = payload_sha
            kind = "shader_replace"
        elif typ == 19:
            from workstation_mixed_asset_crud import _load_image_payload
            if (not isinstance(draft.get("native_source_identity", {}).get("typed_layout", {}).get("dimensions"), list) or
                    draft["native_source_identity"]["typed_layout"]["dimensions"][2:] != [1, 1]):
                raise ValueError("mixed content replacement accepts only resident 2D images")
            payload, image_proof = _load_image_payload(cache, body, row, journal[index],
                initial_by_index[index], walk, profile, source)
            if len(payload) != image_proof["layout"]["total_size"]:
                raise ValueError("mixed image replacement changes the resident child extent")
            layout = image_proof["layout"]
            desired = _canonical_sha(dict(payload_sha256=_sha(payload), format=layout["format"],
                flags=layout["flags"], dimensions=list(layout["dimensions"]),
                level_count=layout["level_count"], total_size=layout["total_size"]))
            replacement_data[key] = dict(payload=payload, image_proof=image_proof,
                                          revision=row["revision"], index=index)
            kind = "resident_image"
        elif typ == 51:
            replacement = rawfile_staged.get(key)
            if replacement is None or replacement["draft"].get("revision") != row.get("revision"):
                raise ValueError("RawFile preflight omitted or changed a staged replacement")
            desired = _sha(replacement["raw"])
            replacement_data[key] = replacement
            kind = "rawfile_replace"
        elif typ == 21:
            if key not in state_banks:
                raise ValueError("SoundBank target is not a trace-owned inline alias set")
            from workstation_soundbank import validate_soundbank_edit_document, soundbank_edit_document
            changes = validate_soundbank_edit_document(draft.get("content"), state_banks[key])
            if not changes:
                raise ValueError("SoundBank staged document contains no supported field changes")
            expected_receipt = dict(state_banks[key], aliases=[dict(a) for a in state_banks[key]["aliases"]])
            preview, _ = replace_soundbank_alias_scalars(body.data, state_banks[key], changes)
            from workstation_soundbank import ALIAS_SIZE
            for alias in expected_receipt["aliases"]:
                raw_alias = preview[alias["archive_offset"]:alias["archive_offset"] + ALIAS_SIZE]
                alias.update(raw_hex=raw_alias.hex(), raw_sha256=_sha(raw_alias))
            desired = _canonical_sha(soundbank_edit_document(expected_receipt))
            replacement_data[key] = dict(content=draft["content"], draft=draft,
                expected_receipt=expected_receipt, desired=desired, index=index)
            kind = "soundbank_replace"
        else:
            # Legacy writer families are scheduled by the established executor
            # and use its stricter typed payload contracts.
            continue
        staged = dict(row=row, draft=draft, payload=payload,
                      desired=desired, original=original_semantic,
                      index=index, kind=kind)
        staged.update(replacement_data.get(key, {}))
        staged_by_key[key] = staged
        mutations.append(dict(kind=kind, identity=dict(type_id=typ, name=row["name"], occurrence=occurrence),
                              output_payload_sha256=desired))

    if closure_contract is not None:
        staged_closure = {}
        for key, staged in staged_by_key.items():
            if key[0] == 54 and key[2] >= 0 and key[1] is not None:
                index = staged["index"]
                if index in closure_contract["table_indices"]:
                    staged_closure[index] = dict(rows=staged["rows"], revision=staged["draft"]["revision"])
        effective = _validate_omnvar_effective_closure(source_closure,
            source_closure_rows, staged_closure)
        if effective.get("validation_sha256") != closure_contract["effective_validation"].get("validation_sha256"):
            raise ValueError("combined effective Omnvar closure differs from its staged batch proof")

    if not mutations:
        raise ValueError("content replacement plan contains no supported content replacements")

    def reread(label: str, writer: dict) -> dict:
        nonlocal state_banks, state_rawfiles
        package, native, next_rows, next_trace, next_manifest, next_index, _payloads = _pack_and_walk(
            state["body"], state["reservations"], source, reader, replay,
            run_dir / "intermediates" / label, label, timeout, profile,
            allow_no_lua=True)
        if _family_identity(next_rows) != original_identity:
            raise ValueError(f"{label} native reread changed asset identity/order")
        index, by_index = _trace_rows(next_trace, next_manifest, len(state["body"]), next_rows)
        if state_rawfiles:
            state_rawfiles = _rawfile_semantics(state["body"], next_rows, next_trace, next_manifest)
        if state_banks:
            typed_body_path = package.parent / "typed-soundbank.body"
            typed_body_path.write_bytes(state["body"])
            from workstation_soundbank import read_native_soundbank
            from workstation_mixed_asset_crud import _soundbank_receipts
            state_banks = _soundbank_receipts(next_rows, lambda i, row: read_native_soundbank(
                body_path=typed_body_path, source_fastfile=package,
                manifest_path=next_manifest, trace_path=next_trace,
                asset_index=i, asset_name=row["name"]))
        current = typed_values(state["body"], next_rows, index, by_index, table_rows)
        for key, expected in expected_extra.items():
            if current.get(key) != expected:
                raise ValueError(f"{label} changed retained typed payload {key}")
        state.update(journal=next_rows, trace=next_trace, manifest=next_manifest,
                     index=index, by_index=by_index, package=package, native=native)
        from workstation_asset_semantics import native_receipt
        native_proof = native_receipt(native, package, state["body"], current, _family_identity(next_rows))
        package_fp = package.with_suffix(".fp")
        native_proof["package_fp_sha256"] = sha256_file(package_fp) if package_fp.is_file() else None
        receipt = dict(label=label, writer=writer, native=native_proof,
            native_complete=native["manifest"].get("complete"),
            native_success=native["manifest"].get("success"),
            tested=native["manifest"].get("tested"), failed=native["manifest"].get("failed"),
            unavailable=native["manifest"].get("unavailable"),
            exact_eof=native["manifest"].get("serialized_bytes_read") == len(state["body"]))
        state["steps"].append(receipt)
        return receipt

    def write(mutation, current_index, _before):
        target = mutation["identity"]
        pair = (target["type_id"], target["name"])
        key = (target["type_id"], target["name"], target["occurrence"])
        staged = staged_by_key.get(key)
        if staged is None or staged["index"] != current_index:
            raise ValueError("fresh native resolution differs from immutable staged target")
        row = state["journal"][current_index]
        traced = state["by_index"][current_index]
        if target["type_id"] == 21:
            replacement = replacement_data[key]
            current_bank = state_banks.get(key)
            if current_bank is None or current_index != replacement["index"]:
                raise ValueError("SoundBank target no longer resolves to its staged alias identity")
            from workstation_soundbank import (soundbank_edit_document,
                validate_soundbank_edit_document, replace_soundbank_alias_scalars)
            if _canonical_sha(soundbank_edit_document(current_bank)) != expected_extra[key]:
                raise ValueError("SoundBank fields differ from the staged original aliases")
            changes = validate_soundbank_edit_document(replacement["content"], current_bank)
            state["body"], receipt = replace_soundbank_alias_scalars(state["body"], current_bank, changes)
            state_banks[key] = replacement["expected_receipt"]
        elif target["type_id"] == 51:
            from workstation_rawfile import RawFileReadContext, read_rawfile
            indexed = build_read_span_index(state["trace"], state["manifest"], len(state["body"]),
                                            selected_assets={current_index})
            if len(indexed["assets"]) != 1:
                raise ValueError("current trace omits or duplicates the RawFile target")
            current_trace = dict(indexed["assets"][0], index=current_index, type_id=51,
                                 name=target["name"], _all_physical_spans=indexed["_all_physical_spans"])
            context = RawFileReadContext(state["body"])
            _layout, current = read_rawfile(state["body"], dict(row, index=current_index),
                current_trace, _sha(state["body"]), context=context)
            current_raw = (current["content"].encode("utf-8") if current["mode"] == "text"
                           else base64.b64decode(current["content"], validate=True))
            if _sha(current_raw) != expected_extra[key]:
                raise ValueError("RawFile pre-edit bytes differ from original staged source")
            replacement = replacement_data[key]
            state["body"], receipt = replace_rawfile_payload(state["body"],
                dict(row, index=current_index), current_trace, replacement["draft"]["content"],
                replacement["draft"]["native_source_identity"]["typed_layout"]["editor_mode"],
                _sha(state["body"]), str(state["trace"]), str(state["manifest"]))
            derived = receipt.get("relocation", {}).get("stream_reservation_sizes")
            if isinstance(derived, list) and len(derived) == len(state["reservations"]):
                state["reservations"] = [max(int(a), int(b)) for a, b in zip(state["reservations"], derived)]
            state_rawfiles[key] = replacement["raw"]
        elif target["type_id"] == 41:
            _layout, text = inspect_localize_entry(state["body"], current_index,
                target["name"], traced, _sha(state["body"]))
            if _canonical_sha({"key": text["key"], "value": text["value"]}) != expected_extra[key]:
                raise ValueError("Localize pre-edit semantic value changed")
            value = staged["draft"].get("content")
            if not isinstance(value, str):
                raise ValueError("Localize replacement is not text")
            if len(value.encode("utf-8")) + 1 == _layout.value_bytes:
                state["body"], receipt = replace_localize_value_same_extent(
                    state["body"], current_index, target["name"], traced, value,
                    _sha(state["body"]), expected_key=target["name"], expected_value=text["value"])
            else:
                state["body"], receipt = replace_localize_values_with_relocation(
                    state["body"], [dict(asset_index=current_index, asset_name=target["name"],
                        trace_asset=traced, value=value, expected_key=target["name"],
                        expected_value=text["value"])], _sha(state["body"]),
                    state["trace"], state["manifest"])
            derived = receipt.get("stream_reservation_sizes")
            if isinstance(derived, list) and len(derived) == len(state["reservations"]):
                state["reservations"] = [max(int(a), int(b)) for a, b in zip(state["reservations"], derived)]
            else:
                deltas = receipt.get("stream_reservation_deltas", {})
                if deltas:
                    state["reservations"] = [int(size) + int(deltas.get(str(i), 0))
                                              for i, size in enumerate(state["reservations"])]
        elif target["type_id"] == 52:
            _root, current = _scriptfile_payload(state["body"], traced, current_index, target["name"])
            if _sha(current) != expected_extra[key]:
                raise ValueError("ScriptFile pre-edit payload changed")
            # ScriptFile's complete zone proof is reconstructed from this fresh trace.
            report = _script_trace_report(state["index"], state["journal"], len(state["body"]))
            state["body"], receipt = replace_scriptfiles_inline_children(state["body"],
                [dict(xasset_index=current_index, name=target["name"], payload=staged["payload"])],
                report, _sha(state["body"]))
            delta = receipt.get("stream6_extent_delta")
            if type(delta) is not int:
                raise ValueError("ScriptFile writer omitted its stream-6 extent contract")
            state["reservations"][6] += delta
        elif target["type_id"] == 62:
            lua_spans = {i: state["by_index"][i] for i, item in enumerate(state["journal"])
                         if item.get("type_id") == 62 and item.get("status") != "reference"}
            current = __import__("workstation_luafile_crud")._bytecodes(
                state["body"], state["journal"], lua_spans)[target["name"]]
            if current != expected_extra[key]:
                raise ValueError("LuaFile pre-edit bytecode changed")
            state["body"], receipt = replace_luafiles_inline_children(state["body"],
                [dict(type_id=62, asset_index=current_index, asset_name=target["name"],
                      trace_asset=traced, payload=staged["payload"])], _sha(state["body"]),
                state["trace"], state["manifest"])
            derived = receipt.get("stream_reservation_highwaters")
            if not isinstance(derived, list) or len(derived) != len(state["reservations"]):
                raise ValueError("LuaFile writer omitted its relocated reservation contract")
            state["reservations"] = [max(int(a), int(b)) for a, b in zip(state["reservations"], derived)]
        elif target["type_id"] == 54:
            original_rows = table_rows[current_index]
            state["body"], receipt = replace_stringtable_rows(state["body"], current_index,
                target["name"], traced, original_rows, staged["rows"], _sha(state["body"]),
                state["trace"], state["manifest"], full_trace_index=state["index"])
            deltas = receipt.get("stream_reservation_deltas", {})
            state["reservations"] = [int(size) + int(deltas.get(str(i), 0))
                                      for i, size in enumerate(state["reservations"])]
            if any(size < 0 for size in state["reservations"]):
                raise ValueError("StringTable relocation produced a negative stream reservation")
            table_rows[current_index] = staged["rows"]
        elif target["type_id"] == 19:
            layout = read_resident_image(state["body"], dict(row, index=current_index), traced,
                                         _sha(state["body"]))
            current_semantic = _canonical_sha(dict(payload_sha256=layout["payload_sha256"],
                format=layout["format"], flags=layout["flags"], dimensions=list(layout["dimensions"]),
                level_count=layout["level_count"], total_size=layout["total_size"]))
            if current_semantic != expected_extra[key] or len(layout["payload"]) != len(staged_by_key[key]["payload"]):
                raise ValueError("image pre-edit bytes/layout differ from staged source")
            state["body"], receipt = replace_resident_image(state["body"], dict(row, index=current_index),
                traced, _sha(state["body"]), staged_by_key[key]["payload"])
        else:
            layout = read_inline_shader(state["body"], dict(row, index=current_index), traced,
                _sha(state["body"]), trace_assets=state["index"]["assets"])
            if layout["program_sha256"] != expected_extra[key] or len(layout["program"]) != len(staged["payload"]):
                raise ValueError("shader pre-edit program/layout differs from staged source")
            state["body"], receipt = replace_inline_shader(state["body"],
                dict(row, index=current_index), traced, _sha(state["body"]), staged["payload"],
                trace_assets=state["index"]["assets"])
        expected_extra[key] = staged["desired"]
        receipt["staged_revision"] = staged["draft"]["revision"]
        return reread(f"step-{len(state['steps']) + 1:02d}-{target['type_id']}-{current_index}", receipt)

    from workstation_asset_transaction import execute_transaction
    def transaction_rows():
        occurrences = {}
        normalized = []
        for row in state["journal"]:
            typ, name = row["type_id"], row["name"]
            pair = (typ, name)
            occurrence = occurrences.get(pair, 0)
            occurrences[pair] = occurrence + 1
            normalized.append(dict(type_id=typ, name=name,
                payload_sha256=expected_extra.get((typ, name, occurrence))))
        return normalized

    transaction = execute_transaction(mutations, transaction_rows,
        {kind: write for kind in {item["kind"] for item in mutations}})
    final_pending = _active_pending_rows(workspace, zone_id)
    if sorted((row.get("asset_id"), row.get("revision")) for row in final_pending) != actual:
        raise ValueError("pending revisions changed while native package was being built")
    final_profile = source_profile(source)
    final_cache, final_decode = workspace._validated_zone_receipt(zone_id)
    final_body = ZoneBody.parse((final_cache / final_decode["final_body_relative_path"]).read_bytes())
    final_walk, _ = _read_native_rows(final_cache, final_body, require_trace=True)
    final_writer_hashes = {name: sha256_file(path) for name, path in writer_paths.items()}
    if (final_profile["sha256"] != protected["source_fastfile"] or
            tuple(row["sha256"] for row in final_profile["patches"]) != protected["source_patches"] or
            acts_tool_identity(reader) != protected["reader"] or acts_tool_identity(lua_compiler) != protected["lua_compiler"] or
            sha256_file(replay) != protected["replay"] or final_body.source_sha256 != body.source_sha256 or
            final_decode.get("cache_key") != decode.get("cache_key") or
            final_walk.get("walk_key") != walk.get("walk_key") or
            final_walk.get("stream_trace_sha256") != walk.get("stream_trace_sha256") or
            final_writer_hashes != protected["writer_sources"]):
        raise ValueError("source FF/patch chain, native reader, Lua compiler, or Replay executable changed")
    from workstation_mixed_asset_crud import plan_mixed_asset_crud
    final_preflight = plan_mixed_asset_crud(workspace, zone_id, final_pending)
    if sorted((row.get("asset_id"), row.get("revision")) for row in final_preflight.get("edits", [])) != actual:
        raise ValueError("final mixed preflight changed the original pending revision set")
    last = state["steps"][-1]
    package = state["package"]
    package_fp = package.with_suffix(".fp")
    receipt = dict(schema="replay120-mixed-content-replacement-result-v1",
        status="native-mixed-content-replacement-pass", zone_id=zone_id,
        source_fastfile_sha256=profile["sha256"], source_body_sha256=body.source_sha256,
        transaction=transaction, steps=state["steps"], final_native=last,
        protected_inputs_unchanged=True, full_native_reread_after_each_mutation=True,
        live_game_tested=False, output_fastfile=None, output_fp=None)
    receipt_path = run_dir / "mixed-content-replacement-receipt.json"
    final_fp = output.with_suffix(".fp")
    receipt_created = False
    receipt_identity = None
    published_identity = {}
    try:
        output_sha, fp_sha = _copy_verified_package(package, output,
            last["native"]["package_sha256"], last["native"]["package_fp_sha256"])
        # Record only the exact files just published. Rollback after a receipt
        # failure is allowed only while inode, metadata, and bytes still match.
        for path, digest in ((output, output_sha), (final_fp, fp_sha)):
            if digest is None:
                continue
            st = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or sha256_file(path) != digest:
                raise ValueError("published output identity changed before receipt creation")
            published_identity[path] = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, digest)
        receipt["output_fastfile"] = dict(path=str(output), sha256=output_sha)
        receipt["output_fp"] = dict(path=str(final_fp), sha256=fp_sha) if fp_sha else None
        with receipt_path.open("x", encoding="utf-8") as stream:
            receipt_created = True
            st = os.fstat(stream.fileno())
            receipt_identity = (st.st_dev, st.st_ino)
            stream.write(json.dumps(receipt, indent=2) + "\n")
            stream.flush()
            __import__("os").fsync(stream.fileno())
    except Exception:
        for path, expected in published_identity.items():
            try:
                st = path.stat(follow_symlinks=False)
                if (stat.S_ISREG(st.st_mode) and
                        (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == expected[:4] and
                        sha256_file(path) == expected[4]):
                    path.unlink()
            except FileNotFoundError:
                pass
        if receipt_created and receipt_identity is not None:
            try:
                st = receipt_path.stat(follow_symlinks=False)
                if stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == receipt_identity:
                    receipt_path.unlink()
            except FileNotFoundError:
                pass
        raise
    return _publication_result(receipt, proof.get("edits", []), output, final_fp, profile, receipt_path)
