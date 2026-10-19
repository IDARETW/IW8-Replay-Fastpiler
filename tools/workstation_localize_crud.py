"""Revisioned Localize row operations and a sequential native package schedule.

Every table-changing operation uses a native trace of its own input body.
Intermediate FFs and proofs stay in the build cache; only the final FF/patch
pair is returned to the workstation publisher.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from workstation_fastfiles import (
    ZoneBody, _assert_run_inputs_unchanged, _export_native_type, _native_walk_artifact,
    _read_native_rows, _validate_pending_snapshot, acts_tool_identity,
    make_replay_header_only_patch, ordered_asset_identity_sha256, pack_replay_uncompressed,
    sha256_file, source_profile, unpack_replay_uncompressed, _stream_header_details_from_bytes,
)
from workstation_localize_inventory import compare_localize_inventory, read_localize_inventory
from workstation_luafile_crud import _bind_native_manifest_to_trace


def _inputs(workspace, zone_id, *, _snapshot=None):
    if _snapshot is None and hasattr(workspace, '_validated_asset_snapshot'):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    if _snapshot is not None:
        if hasattr(workspace, '_require_asset_request_snapshot'):
            workspace._require_asset_request_snapshot(_snapshot, zone_id)
        if _snapshot.zone_id != zone_id or not _snapshot.native_walk or not _snapshot.native_rows:
            raise ValueError('Localize operation requires this zone complete native request snapshot')
        cache, receipt, body = _snapshot.cache_path, _snapshot.decode_receipt, _snapshot.body
        source, profile, walk, rows = (_snapshot.source_path, _snapshot.source_profile,
                                       _snapshot.native_walk, _snapshot.native_rows)
    else:
        cache, receipt = workspace._validated_zone_receipt(zone_id)
        body = ZoneBody.parse((cache / receipt['final_body_relative_path']).read_bytes())
        source = Path(receipt['source']['path']).resolve(strict=True)
        profile = source_profile(source)
        walk, rows = _read_native_rows(cache, body, require_trace=True)
    if any(row['extension'] == '.fc' for row in profile['patches']):
        raise ValueError('Localize row operations do not yet support FC patch chains')
    if (walk['identity']['source_sha256'] != profile['sha256'] or
            walk['identity']['patch_sha256s'] != [row['sha256'] for row in profile['patches']]):
        raise ValueError('Localize operation source differs from its pinned native walk')
    import workstation_localize
    writer = Path(workstation_localize.__file__).resolve(strict=True)
    identity = dict(body_sha256=body.source_sha256, source_fastfile_sha256=profile['sha256'],
                    patch_sha256s=[row['sha256'] for row in profile['patches']],
                    native_walk_key=walk['walk_key'], native_manifest_sha256=walk['manifest_sha256'],
                    stream_trace_sha256=walk['stream_trace_sha256'],
                    writer_module_path=str(writer), writer_module_sha256=sha256_file(writer))
    return cache, receipt, body, source, profile, walk, rows, identity


def _operation_id(operation, name, index=None):
    return 'op-a-' + hashlib.sha256(name.encode('utf-8')).hexdigest()[:32] if operation == 'append' else f'op-r-{index}'


def operations(workspace, zone_id, *, _snapshot=None):
    """Return source/tool-validated active row operations for one decoded zone."""
    from workstation_asset_operations import validate_operation
    cache, _, _, _, _, _, _, identity = _inputs(workspace, zone_id, _snapshot=_snapshot)
    result = []
    for current in sorted(cache.glob('pending-edits/op-*/current.json')):
        candidate = json.loads(current.read_text(encoding='utf-8'))
        if candidate.get('type_id') != 41:
            continue
        row, payload = validate_operation(cache, current, identity)
        if row['zone_id'] != zone_id:
            raise ValueError('Localize operation identifies another source zone')
        expected = dict(operation=row['operation'], name=row['name'], value=row['content'])
        receipt = row['compiler_receipt']
        if (json.loads(payload) != expected or receipt.get('asset_name') != row['name'] or
                receipt.get('operation') != row['operation'] or
                receipt.get('status') != 'replay120-localize-row-operation-staged' or
                receipt.get('source', {}).get('sha256') != row['content_sha256'] or
                receipt.get('result', {}).get('operation_payload_sha256') != row['edited_payload_sha256'] or
                row['writer_identity'] != dict(path=identity['writer_module_path'], sha256=identity['writer_module_sha256'])):
            raise ValueError('Localize operation payload/recipe differs from its staged source')
        result.append(row)
    return result


def _stage(workspace, zone_id, operation, name, value, index=None, expected_revision=None,
           *, _snapshot=None):
    from workstation_asset_operations import stage_operation
    cache, _, body, _, _, _, _, identity = _inputs(workspace, zone_id, _snapshot=_snapshot)
    operation_id = _operation_id(operation, name, index)
    asset_id = f'{zone_id}:new-{operation_id.removeprefix("op-a-")}' if operation == 'append' else f'{zone_id}:{index}'
    payload = json.dumps(dict(operation=operation, name=name, value=value),
                         ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    content_sha = hashlib.sha256(value.encode('utf-8')).hexdigest()
    payload_sha = hashlib.sha256(payload).hexdigest()
    compiler = dict(schema='replay120-localize-operation-recipe-v1',
                    status='replay120-localize-row-operation-staged', asset_name=name,
                    operation=operation, source=dict(sha256=content_sha),
                    compiler=dict(writer_module_path=identity['writer_module_path'],
                                  writer_module_sha256=identity['writer_module_sha256']),
                    result=dict(operation_payload_sha256=payload_sha))
    row = dict(schema=4, operation=operation, operation_id=operation_id,
               asset_id=asset_id, zone_id=zone_id, type_id=41, type='localize', name=name,
               index=index, xasset_index=index, content=value, language='plaintext',
               source_body_sha256=body.source_sha256, content_sha256=content_sha,
               native_source_identity=identity, compiler_receipt=compiler,
               compiler_receipt_sha256=hashlib.sha256(json.dumps(compiler, sort_keys=True,
                   separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest(),
               writer_identity=dict(path=identity['writer_module_path'], sha256=identity['writer_module_sha256']))
    if _snapshot is not None:
        workspace._assert_asset_snapshot_current(_snapshot)
    return stage_operation(cache, row, payload, expected_revision)


def create_localize_asset(workspace, zone_id, name, content, type='localize', revision=None,
                          *, _snapshot=None):
    if type != 'localize':
        raise ValueError('Native row creation currently supports Localize assets')
    from workstation_localize import _validate_text
    _validate_text(name, 'key')
    _validate_text(content, 'value')
    if (not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,255}', name) or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('Use a confined Localize key with letters, digits, underscores, slashes, dots or hyphens')
    if _snapshot is None and hasattr(workspace, '_validated_asset_snapshot'):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    _, _, _, _, _, _, native, _ = _inputs(workspace, zone_id, _snapshot=_snapshot)
    if any(row.get('type_id') == 41 and row.get('name') == name for row in native):
        raise ValueError('A Localize key with this name already exists in the source zone')
    row = _stage(workspace, zone_id, 'append', name, content, expected_revision=revision,
                 _snapshot=_snapshot)
    cache_path = (_snapshot.cache_path if _snapshot is not None else
                  workspace._validated_zone_receipt(zone_id)[0])
    return dict(**row, status='native-localize-append-staged', editable=True, pending_path=str(
        cache_path / 'pending-edits' / row['operation_id'] / 'current.json'))


def remove_localize_asset(workspace, asset_id, revision):
    opened = workspace.get_asset(asset_id)
    if opened.get('type_id') != 41 or opened.get('type') != 'localize':
        raise ValueError('Native row removal currently supports Localize assets')
    if opened.get('revision') != revision:
        raise ValueError('Asset revision conflict; reload before removing')
    if opened.get('pending_path'):
        raise ValueError('Restore the active value edit before removing this Localize row')
    zone_id, index_text = asset_id.rsplit(':', 1)
    index = int(index_text)
    _, _, body, _, _, _, native, _ = _inputs(workspace, zone_id)
    if (not 0 <= index < len(body.assets) or index >= len(native) or
            native[index].get('type_id') != 41 or native[index].get('name') != opened.get('name')):
        raise ValueError('Localize removal no longer matches its source XAsset identity')
    return dict(**_stage(workspace, zone_id, 'remove', opened['name'], opened['content'], index),
                status='native-localize-removal-staged', editable=False)


def get_new_localize_asset(workspace, asset_id, *, _snapshot=None):
    zone_id, marker = asset_id.rsplit(':', 1)
    if not re.fullmatch(r'new-[0-9a-f]{32}', marker):
        raise ValueError('Malformed new Localize asset identity')
    found = [row for row in operations(workspace, zone_id, _snapshot=_snapshot)
             if row['asset_id'] == asset_id]
    if len(found) != 1:
        raise KeyError(asset_id)
    row = found[0]
    cache = (_snapshot.cache_path if _snapshot is not None else
             workspace._validated_zone_receipt(zone_id)[0])
    return dict(**row, editable=True, archive_writable=False,
                payload_format='replay120-localize-inline-row-operation',
                pending_path=str(cache / 'pending-edits' / row['operation_id'] / 'current.json'),
                package_status='Native Localize row creation queued; Compile game resolves and verifies the full zone')


def plan_localize_crud(workspace, zone_id, pending_rows, *, _snapshot=None):
    if _snapshot is None and hasattr(workspace, '_validated_asset_snapshot'):
        _snapshot = workspace._validated_asset_snapshot(zone_id)
    cache, _, body, source, profile, walk, native, identity = _inputs(
        workspace, zone_id, _snapshot=_snapshot)
    op_rows = {row['operation_id']: row for row in
               operations(workspace, zone_id, _snapshot=_snapshot)}
    removes, appends, edits = [], [], []
    for listed in pending_rows:
        if listed.get('type') != 'localize':
            raise ValueError('Localize row operations currently compose with Localize value edits only')
        if listed.get('operation'):
            row = op_rows.get(listed.get('operation_id'))
            if not row or row['revision'] != listed['revision']:
                raise ValueError('Localize operation changed during preflight')
            if row['operation'] == 'append':
                if any(n.get('type_id') == 41 and n.get('name') == row['name'] for n in native):
                    raise ValueError('Appended Localize key already exists')
                appends.append(row['name'])
            else:
                index = row['index']
                if (type(index) is not int or not 0 <= index < len(native) or
                        native[index].get('type_id') != 41 or native[index].get('name') != row['name']):
                    raise ValueError('Localize removal no longer matches its source XAsset')
                removes.append(row['name'])
        else:
            index = listed['index']
            _, row, _ = _validate_pending_snapshot(cache, index, listed['asset_id'], body)
            if row['revision'] != listed['revision']:
                raise ValueError('Localize value edit changed during preflight')
            stale = workspace._staged_asset_staleness(row, body, index, native[index], walk, source)
            if stale:
                raise ValueError(stale)
            edits.append(row['name'])
    if len(set(appends)) != len(appends) or len(set(removes)) != len(removes) or set(removes) & set(edits):
        raise ValueError('Localize row schedule has conflicting create/remove/value operations')
    return dict(source_fastfile_sha256=profile['sha256'], source_body_sha256=body.source_sha256,
                native_source_identity=identity, original_xasset_count=len(body.assets),
                final_xasset_count=len(body.assets) + len(appends) - len(removes),
                value_edit_count=len(edits), rows_added=len(appends), rows_removed=len(removes),
                schedule='value batch, then removals, then appends; full native reread/retrace after each table change',
                final_semantic_check='every retained Localize value/order plus all authored operations')


def _semantic_export(workspace, path, native_rows, proof_root, timeout):
    """Use a short ACTS output root; retain proof logs, not temporary payloads."""
    proof_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rwcrud-') as temporary:
        root = Path(temporary)
        if len(str(root)) > 80:
            raise ValueError('System TEMP root is too long for safe ACTS Localize export')
        command = [str(workspace.acts_path), '--noUpdater', 'fastfile', '-r', 'mw19replay',
                   '-g', str(workspace.replay_executable), '-o', str(root), '-a', 'localize', '-l', str(path)]
        log = proof_root / 'semantic-export.log'
        with log.open('w', encoding='utf-8') as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                    check=False, timeout=timeout)
        manifests = list(root.glob('mw19replay/*/manifest.json'))
        if result.returncode or len(manifests) != 1:
            raise ValueError(f'Localize semantic export failed; see {log}')
        manifest_path = manifests[0]
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        expected = sum(row.get('type_id') == 41 for row in native_rows)
        if (not manifest.get('complete') or not manifest.get('success') or
                manifest.get('failed') != 0 or manifest.get('unavailable') != 0 or manifest.get('tested') != expected):
            raise ValueError('Localize semantic export did not cover the full current type inventory')
        journal = manifest_path.parent / manifest.get('journal', 'assets.jsonl')
        rows = [json.loads(line) for line in journal.read_text(encoding='utf-8').splitlines() if line.strip()]
        inventory = read_localize_inventory(manifest_path.parent, rows, native_rows)
        shutil.copy2(manifest_path, proof_root / 'semantic-manifest.json')
        return inventory, dict(manifest_sha256=sha256_file(proof_root / 'semantic-manifest.json'),
                               log_path=str(log), log_sha256=sha256_file(log), tested=expected,
                               temporary_payloads_cleaned=True)


def _read_native_result(native):
    manifest = native['manifest']
    manifest_path = Path(native['manifest_path'])
    root = manifest_path.parent
    journal_path = root / manifest['journal']
    trace_path = root / manifest['stream_trace']
    rows = [json.loads(line) for line in journal_path.read_text(encoding='utf-8').splitlines() if line.strip()]
    bound_path = manifest_path.with_name('manifest.transaction-bound.json')
    if not bound_path.exists():
        binding = _bind_native_manifest_to_trace(
            manifest_path, trace_path, manifest['serialized_bytes_read'], bound_path,
            journal_path=journal_path)
        bound_path = Path(binding['bound_manifest_path'])
    return rows, trace_path, bound_path


def _read_compiled_intermediate(path, expected_sha256):
    """Read a proof-owned emitted IWC file, not a signed owner source file."""
    packed = path.read_bytes()
    if hashlib.sha256(packed).hexdigest() != expected_sha256:
        raise ValueError('Compiled Localize intermediate differs from its native writer receipt')
    body = unpack_replay_uncompressed(packed)
    header = _stream_header_details_from_bytes(packed, 0)
    if header['decoded_size'] != len(body):
        raise ValueError('Compiled Localize intermediate decoded size differs from its body')
    return body, list(header['block_sizes'])


def build_localize_crud(workspace, zone_id, plan, output, timeout):
    from roundtrip_replay_fastfile import verify_native
    from workstation_asset_operations import validate_operation
    from workstation_localize import append_localize_entry, remove_localize_entry
    from workstation_trace_index import build_read_span_index

    cache, _, original, source, profile, walk, native_rows, identity = _inputs(workspace, zone_id)
    # Validate all operation and value snapshots before creating any outputs.
    validated_operations = {row['operation_id']: row for row in operations(workspace, zone_id)}
    op_rows, value_plan = [], []
    for planned in plan['edits']:
        if planned.get('operation'):
            current = cache / 'pending-edits' / planned['operation_id'] / 'current.json'
            row, _ = validate_operation(cache, current, identity)
            if row['revision'] != planned['revision'] or row != validated_operations.get(row['operation_id']):
                raise ValueError('Localize operation changed after its build snapshot')
            op_rows.append(row)
        else:
            value_plan.append(planned)
    root = output.with_suffix(output.suffix + '.crud-work')
    if root.exists() or output.exists() or output.with_suffix('.fp').exists() or output.with_suffix('.fc').exists():
        raise FileExistsError('Localize CRUD build output already exists')
    root.mkdir(parents=True)
    baseline_root, baseline_index = _export_native_type(source, zone_id, original, cache, walk, native_rows,
        41, 'localize', workspace.acts_path, workspace.replay_executable, timeout)
    baseline = read_localize_inventory(baseline_root, baseline_index['items'], native_rows, cached=True)
    source_values = {row['name']: row['value'] for row in baseline}
    body = original.data
    trace_path = _native_walk_artifact(walk, 'stream_trace_relative_path')
    raw_manifest_path = _native_walk_artifact(walk, 'manifest_relative_path')
    source_binding = _bind_native_manifest_to_trace(
        raw_manifest_path, trace_path, len(body), root / 'source-manifest.transaction-bound.json',
        journal_path=_native_walk_artifact(walk, 'journal_relative_path'))
    manifest_path = Path(source_binding['bound_manifest_path'])
    reservations = list(profile['final_header']['block_sizes'])
    expected_native = list(native_rows)
    edited_values, removed_names, appended_values, steps = {}, set(), [], []
    acts_before = acts_tool_identity(workspace.acts_path)
    replay_before = sha256_file(workspace.replay_executable)
    published = []
    try:
        if value_plan:
            first = root / 'values' / source.name
            result = workspace._build_localize_replacement(zone_id, cache,
                workspace._validated_zone_receipt(zone_id)[1], original, {'edits': value_plan}, first, timeout)
            body, reservations = _read_compiled_intermediate(first, result['output_fastfile_sha256'])
            manifests = list(first.with_suffix(first.suffix + '.native-reader').glob('mw19replay/*/manifest.json'))
            if len(manifests) != 1:
                raise ValueError('Value batch omitted its native trace for the subsequent row operations')
            manifest_path = manifests[0]
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            native_rows, trace_path, manifest_path = _read_native_result(
                {'manifest': manifest, 'manifest_path': str(manifest_path)})
            for planned in value_plan:
                _, row, _ = _validate_pending_snapshot(cache, int(planned['asset_id'].rsplit(':', 1)[1]), planned['asset_id'], original)
                edited_values[row['name']] = row['content']
            steps.append(dict(operation='value-batch', result=result))
        ordered = sorted(op_rows, key=lambda row: (row['operation'] != 'remove', row['operation_id']))
        last_ff, last_native, last_semantic = None, None, None
        for number, operation in enumerate(ordered):
            current_body = ZoneBody.parse(body)
            name = operation['name']
            selected_index = None
            if operation['operation'] == 'remove':
                matches = [i for i, row in enumerate(native_rows) if row.get('type_id') == 41 and row.get('name') == name]
                if len(matches) != 1:
                    raise ValueError('Removal key does not identify one current Localize row')
                selected_index = matches[0]
                span_index = build_read_span_index(trace_path, manifest_path, len(body), selected_assets={selected_index})
                traced = next(row for row in span_index['assets'] if row['index'] == selected_index)
                traced.update(index=selected_index, xasset_index=selected_index, type_id=41, name=name)
                body, writer = remove_localize_entry(body, selected_index, name, traced,
                    current_body.source_sha256, name, source_values[name], trace_path, manifest_path)
                removed_names.add(name)
                expected_native = [row for i, row in enumerate(native_rows) if i != selected_index]
            else:
                span_index = build_read_span_index(trace_path, manifest_path, len(body), selected_assets=set())
                highwaters = {int(key): value for key, value in span_index['max_destination_offsets'].items()}
                body, reservations, writer = append_localize_entry(body, name, operation['content'],
                    reservations, highwaters, current_body.source_sha256, trace_path, manifest_path)
                appended_values.append((name, operation['content']))
                expected_native = [*native_rows, dict(type_id=41, name=name)]
            step = root / f'{number:04d}-{operation["operation"]}'
            step.mkdir()
            path = step / source.name
            packed = pack_replay_uncompressed(body, reservations, profile['final_header']['xfile_version'],
                                              profile['header']['transient_type'])
            if unpack_replay_uncompressed(packed) != body:
                raise AssertionError('Localize row framing changed the authored body')
            path.write_bytes(packed)
            for patch in profile['patches']:
                path.with_suffix(patch['extension']).write_bytes(make_replay_header_only_patch(
                    Path(patch['path']).read_bytes(), packed))
            native = verify_native(path, body, source, workspace.acts_path, workspace.replay_executable,
                                   step / 'native-reader', timeout, trace=True)
            if native['journal_asset_identity_sha256'] != ordered_asset_identity_sha256(expected_native):
                raise ValueError('Localize row operation changed an unrelated XAsset identity/order')
            native_rows, trace_path, manifest_path = _read_native_result(native)
            actual, semantic_export = _semantic_export(workspace, path, native_rows, step / 'semantic-reader', timeout)
            comparison = compare_localize_inventory(baseline, actual, edited_values, removed_names, appended_values)
            _assert_run_inputs_unchanged(source, profile, workspace.acts_path, acts_before,
                                         workspace.replay_executable, replay_before)
            if sha256_file(Path(identity['writer_module_path'])) != identity['writer_module_sha256']:
                raise ValueError('Localize writer changed while compiling the row schedule')
            steps.append(dict(operation=operation['operation'], asset_id=operation['asset_id'],
                              revision=operation['revision'], name=name, input_current_index=selected_index,
                              writer=writer, native_reader=dict(loaded_assets=native['manifest']['loaded_assets'],
                                  tested=native['manifest']['tested'], failed=native['manifest']['failed'],
                                  unavailable=native['manifest']['unavailable'],
                                  journal_asset_identity_sha256=native['journal_asset_identity_sha256']),
                              semantic_readback=comparison, semantic_export=semantic_export))
            last_ff, last_native, last_semantic = path, native, comparison
        if last_ff is None:
            raise ValueError('Localize row schedule contains no create/remove operation')
        # Revalidate immutable operations/value edits before final publication.
        for row in op_rows:
            current, _ = validate_operation(cache, cache / 'pending-edits' / row['operation_id'] / 'current.json', identity)
            if current['revision'] != row['revision']:
                raise ValueError('Localize row operation changed during compilation')
        for planned in value_plan:
            _, current, _ = _validate_pending_snapshot(cache, int(planned['asset_id'].rsplit(':', 1)[1]), planned['asset_id'], original)
            if current['revision'] != planned['revision']:
                raise ValueError('Localize value edit changed during row compilation')
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(last_ff, output)
        published.append(output)
        sidecars = []
        for patch in profile['patches']:
            target = output.with_suffix(patch['extension'])
            shutil.copy2(last_ff.with_suffix(patch['extension']), target)
            published.append(target)
            sidecars.append(dict(path=str(target), sha256=sha256_file(target), bytes=target.stat().st_size))
        proof = dict(schema='replay120-localize-crud-package-v1', status='native-full-zone-localize-crud-package-pass',
                     source_identity=identity, baseline_export_key=baseline_index['export_key'],
                     output_fastfile=str(output), output_fastfile_sha256=sha256_file(output), sidecars=sidecars,
                     edits=[dict(asset_id=row['asset_id'], revision=row['revision']) for row in plan['edits']],
                     steps=steps, semantic_readback=last_semantic,
                     native_reader_status=last_native['manifest'].get('status'),
                     native_reader_loaded=last_native['manifest']['loaded_assets'],
                     support_limit='Localize inline UTF-8 rows; one native retrace per table change; final-row removal requires exact trace-owned EOF; inbound aliases to deleted rows/strings and shared tail bytes fail closed')
        receipt_path = output.with_suffix(output.suffix + '.edit-receipt.json')
        receipt_path.write_text(json.dumps(proof, indent=2) + '\n', encoding='utf-8')
        return dict(**proof, receipt_path=str(receipt_path), edit_proof=dict(steps=len(steps)))
    except Exception:
        for path in published:
            path.unlink(missing_ok=True)
        raise
