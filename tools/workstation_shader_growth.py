"""Typed variable-length Replay SM5 shader archive transactions (XAsset 12, 14-17).

This is an offline writer. It updates the renderer's authored discriminator
using complete supplied native inventories. A native reread and renderer test
remain separate gates before this route is exposed for publication.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

try:
    from workstation_fastfiles import ZoneBody
    from workstation_native_asset_edits import read_inline_shader
    from workstation_native_child_relocation import InlineChildLayout, relocate_stream5_children
    from workstation_asset_codecs import _validate_dxbc, dxbc_native_shader_type
    from workstation_shader_identity import allocate_identity_batch, validate_inventory_set
except ModuleNotFoundError:
    from tools.workstation_fastfiles import ZoneBody
    from tools.workstation_native_asset_edits import read_inline_shader
    from tools.workstation_native_child_relocation import InlineChildLayout, relocate_stream5_children
    from tools.workstation_asset_codecs import _validate_dxbc, dxbc_native_shader_type
    from tools.workstation_shader_identity import allocate_identity_batch, validate_inventory_set


def replace_inline_shaders_with_relocation(
        body_data: bytes, edits: list[dict], expected_body_sha256: str,
        trace_path: str | Path, manifest_path: str | Path, *,
        identity_inventories: list[dict], replay_executable_sha256: str) -> tuple[bytes, dict]:
    """Rebuild traced DXBC children and rebase every affected stream-5 alias."""
    body = ZoneBody.parse(body_data)
    if body.source_sha256 != expected_body_sha256:
        raise ValueError("shader edit source body changed after native inspection")
    if not isinstance(edits, list) or not edits:
        raise ValueError("shader relocation requires one or more typed edits")
    compute_only = all(isinstance(edit, dict) and isinstance(edit.get('asset_row'), dict)
                       and edit['asset_row'].get('type_id') == 12 for edit in edits)
    if compute_only:
        # Type 12's root word at +36 has not been proven to be the graphics
        # program discriminator. Preserve it verbatim and do not require or
        # allocate a graphics identity inventory for a compute-only edit.
        inventory_rows = {}
    else:
        validate_inventory_set(identity_inventories, replay_executable_sha256)
        source_inventories = [inventory for inventory in identity_inventories
                              if inventory.get('body_sha256') == expected_body_sha256]
        if len(source_inventories) != 1:
            raise ValueError('shader growth requires one complete inventory of its exact source body')
        inventory_rows = {row['asset_index']: row for row in source_inventories[0]['shaders']}
    layouts, replacements, identities, identity_edits = {}, {}, [], []
    for edit in edits:
        if not isinstance(edit, dict):
            raise TypeError("each shader edit must be a mapping")
        row, trace, program = edit.get("asset_row"), edit.get("trace_asset"), edit.get("payload")
        if not isinstance(row, dict) or not isinstance(trace, dict) or not isinstance(program, bytes):
            raise ValueError("shader edit lacks its native row, trace, or compiled bytes")
        current = read_inline_shader(body_data, row, trace, expected_body_sha256,
                                     trace_assets=edit.get("trace_assets"))
        index = current["asset_index"]
        if index in layouts or not 0 <= index < len(body.assets):
            raise ValueError("shader edit owners must be unique valid XAsset rows")
        if body.assets[index].type_id != current["type_id"]:
            raise ValueError("shader native row differs from the serialized XAsset table")
        _validate_dxbc(program)
        if dxbc_native_shader_type(program) != current["type_id"]:
            raise ValueError("replacement DXBC shader stage differs from the native XAsset type")
        root = current["root_bytes"]
        old_identity = struct.unpack_from('<I', root, 36)[0]
        if current["type_id"] != 12:
            inventory_row = inventory_rows.get(index, {})
            if any(inventory_row.get(key) != value for key, value in {
                    'name': current['name'], 'type_id': current['type_id'],
                    'root_archive_offset': current['root_archive_offset'],
                    'program_identity': old_identity,
                    'inline_dxbc_sha256': current['program_sha256']}.items()):
                raise ValueError('edited shader differs from its complete source identity inventory')
        if struct.unpack_from("<Q", root, 24)[0] != 0xfffffffffffffffe:
            raise ValueError("shader program pointer is not the native inline -2 form")
        spans = [span for span in trace["read_spans"]
                 if span.get("archive_offset") == current["program_archive_offset"]
                 and span.get("size") == len(current["program"])
                 and span.get("origin") == "load_stream_call"
                 and span.get("reader_start_arg") == 0]
        if len(spans) != 1:
            raise ValueError("shader program has no unique native AtStart read")
        destination = spans[0].get("destination_stream_location")
        if (not isinstance(destination, dict) or destination.get("stream") != 5 or
                type(destination.get("offset")) is not int):
            raise ValueError("shader program does not occupy a traced stream-5 allocation")
        layouts[index] = InlineChildLayout(
            current["name"], current["root_archive_offset"],
            current["program_archive_offset"], destination["offset"],
            len(current["program"]), current["program_sha256"], 32, "<I")
        replacements[index] = program
        identity_record = dict(asset_index=index, name=current["name"],
                               type_id=current["type_id"], root_u32_36_before=old_identity)
        if current["type_id"] != 12:
            identity_record["old_program_identity"] = old_identity
        identities.append(identity_record)
        if program != current['program'] and current['type_id'] != 12:
            identity_edits.append(dict(owner_key=f'asset:{index:010d}', type_id=current['type_id'],
                                       name=current['name'], program=program))
    allocations = (allocate_identity_batch(identity_edits, identity_inventories,
                                           replay_executable_sha256) if identity_edits else [])
    output, receipt = relocate_stream5_children(
        body_data, layouts, replacements, trace_path, manifest_path)
    result = bytearray(output)
    for allocation in allocations:
        index = int(allocation['owner_key'].split(':')[1])
        root_at = layouts[index].root_archive_offset
        root_at += sum(len(replacements[owner]) - layout.child_bytes
                       for owner, layout in layouts.items() if layout.child_archive_offset < root_at)
        row = next(row for row in identities if row['asset_index'] == index)
        if struct.unpack_from('<I', result, root_at + 36)[0] != row['root_u32_36_before']:
            raise ValueError('relocated shader root identity differs before discriminator update')
        struct.pack_into('<I', result, root_at + 36, allocation['identity'])
        row['new_program_identity'] = allocation['identity']
        row['identity_allocation'] = allocation
    output = bytes(result)
    return output, dict(schema="replay120-variable-shader-offline-writer-v1",
                        source_body_sha256=expected_body_sha256,
                        output_body_sha256=hashlib.sha256(output).hexdigest(),
                        assets=identities, relocation=receipt,
                        publication_ready=False,
                        remaining_gate="native full-zone reread and live GPU/material test")
