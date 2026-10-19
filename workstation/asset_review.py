"""Review all staged XAsset operations and separately stored resident audio drafts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlencode

from workstation.change_review import _insights


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + '\n'


def _invalid_id(path):
    return 'invalid-' + hashlib.sha256(str(path).encode()).hexdigest()


def _asset_rows(archives, zone=None, snapshots=None):
    snapshots, rows, offset = {} if snapshots is None else snapshots, [], 0
    while True:
        page = archives.list_pending_edits(zone_id=zone, offset=offset, limit=1000, _snapshots=snapshots)
        rows.extend(page['items'])
        offset += len(page['items'])
        if offset >= page['total']:
            return rows, snapshots
        if not page['items']:
            raise ValueError('Asset edit inventory ended before its reported total')


def _audio_rows(sounds):
    rows = []
    for path in sorted(sounds.drafts.root.glob('*/*/current.json')):
        try:
            preview = json.loads(path.read_text(encoding='utf-8'))
            current, record, wav = sounds.drafts._read_current(preview['zone_id'], preview['file_id'])
            if current.resolve() != path.resolve():
                raise ValueError('Audio draft does not belong to its storage key')
            rows.append(dict(id=f"{record['zone_id']}:{record['file_id']}", zone_id=record['zone_id'],
                file_id=record['file_id'], name=record['source_identity']['asset_file_name'],
                revision=record['revision'], status='staged', pending_path=str(current),
                edited_payload_bytes=len(wav), edited_payload_sha256=record['wav_sha256']))
        except (OSError, KeyError, TypeError, ValueError) as error:
            rows.append(dict(id=_invalid_id(path), name='Invalid audio draft', pending_path=str(path),
                             status='invalid', error=str(error)))
    return rows


def list_asset_changes(app):
    items, warnings = [], []
    archives = app.archives()
    try:
        rows, snapshots = _asset_rows(archives)
        for row in rows:
            identity = row.get('asset_id') if row.get('status') != 'invalid' else None
            identity = identity or _invalid_id(row['pending_path'])
            snapshot = snapshots.get(row.get('zone_id'))
            zone = Path(snapshot.decode_receipt['source']['path']).name if snapshot else row.get('zone_id', '')
            operation = row.get('operation') or 'replace'
            items.append(dict(key='asset:' + identity, kind='asset', id=identity,
                name=row.get('name') or 'Invalid asset draft', category='Asset changes',
                path=f"{zone or 'Unknown fastfile'}/{row.get('name') or identity}", zone=zone,
                zone_id=row.get('zone_id'), type=row.get('type'), operation=operation,
                status=row.get('status', 'staged'), error=row.get('error')))
    except (OSError, KeyError, TypeError, ValueError) as error:
        warnings.append('Fastfile edit inventory: ' + str(error))
    try:
        for row in _audio_rows(app.sounds()):
            items.append(dict(key='sound:' + row['id'], kind='sound', id=row['id'], name=row['name'],
                category='Audio changes', path=row['name'], zone_id=row.get('zone_id'),
                type='resident audio', operation='replace', status=row['status'], error=row.get('error')))
    except (OSError, KeyError, TypeError, ValueError) as error:
        warnings.append('Audio draft inventory: ' + str(error))
    return dict(items=items, warnings=warnings,
                note='Includes saved fastfile edits, asset additions/removals, and resident audio drafts across all zones.')


def _payload(asset):
    source = asset.get('source') or {}
    return dict(bytes=asset.get('edited_payload_bytes', asset.get('payload_bytes')),
                sha256=asset.get('edited_payload_sha256', asset.get('payload_sha256')),
                layout=source.get('typed_layout'))


def _field_changes(before, after, path='', result=None):
    result = [] if result is None else result
    if before == after or len(result) >= 200:
        return result
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys()):
            _field_changes(before.get(key), after.get(key), f'{path}.{key}' if path else key, result)
    elif isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            result.append(dict(path=path + '.length', before=len(before), after=len(after)))
        for index, (old, new) in enumerate(zip(before, after)):
            _field_changes(old, new, f'{path}[{index}]', result)
    else:
        result.append(dict(path=path or 'value', before=before, after=after))
    return result


def _result(current, original, operation, row=None):
    row = row or {}
    before = original.get('content') if original else ''
    after = current.get('content') if operation != 'remove' else ''
    language = (original or current).get('language', 'plaintext')
    binary = language.startswith('image/') or language in ('base64', 'binary') or current.get('editor_mode')=='base64' or current.get('extension')=='base64'
    original_payload = _payload(original) if original else None
    modified_payload = _payload(current) if operation != 'remove' else None
    # A staged summary retains sizes absent from the editable-content response.
    if modified_payload:
        for key, field in [('bytes', 'edited_payload_bytes'), ('sha256', 'edited_payload_sha256')]:
            if row.get(field) is not None:
                modified_payload[key] = row[field]
    insights = None
    if before is not None and after is not None:
        insights = dict(changed=before != after, binary=True) if binary else _insights(before, after, language)
        if language == 'json':
            try:
                insights['field_changes'] = _field_changes(json.loads(before or '{}'), json.loads(after or '{}'))
            except ValueError:
                pass
        elif language == 'csv':
            import csv
            import io
            insights['field_changes'] = _field_changes(list(csv.reader(io.StringIO(before))),
                                                       list(csv.reader(io.StringIO(after))))
    return dict(kind='asset', id=current.get('asset_id') or row.get('asset_id'), name=current.get('name') or row.get('name'),
                original=before, modified=after or '', language=language, operation=operation,
                baseline='New asset; absent from the original fastfile' if operation == 'append' else 'Original native asset from the pinned fastfile/patch chain',
                baseline_revision=original.get('revision') if original else None, revision=current.get('revision'),
                original_sha256=hashlib.sha256(before.encode()).hexdigest() if before is not None else None,
                modified_sha256=hashlib.sha256((after or '').encode()).hexdigest(),
                original_payload=original_payload, modified_payload=modified_payload,
                asset_type=current.get('type') or row.get('type'), zone_id=current.get('zone_id'),
                status='stale' if current.get('stale') else row.get('status', 'staged'),
                error=current.get('codec_error') or row.get('error'), insights=insights,
                provenance=current.get('source') or {}, compiler_receipt=current.get('compiler_receipt'),
                package_status=current.get('package_status'), reference_only=current.get('reference_only', False))


def get_asset_change(app, identity):
    archives = app.archives()
    # Invalid entries remain visible as diagnostic records, without claiming a baseline.
    if identity.startswith('invalid-'):
        rows, _ = _asset_rows(archives)
        row = next((row for row in rows if _invalid_id(row['pending_path']) == identity), None)
        if row is None:
            raise ValueError('Asset draft changed or was removed; refresh the review')
        return dict(kind='asset', id=identity, name='Invalid asset draft', language='json', original=None,
            modified=_json(row), baseline='Original unavailable; draft validation failed',
            status='invalid', error=row.get('error'), operation=row.get('operation', 'replace'))
    zone, separator, index = identity.rpartition(':')
    if not separator:
        raise ValueError('Invalid asset review identity')
    snapshot = archives._validated_asset_snapshot(zone)
    current = archives.get_asset(identity, _snapshot=snapshot)
    operation = current.get('operation') or ('append' if index.startswith('new-') else 'replace')
    original = None if operation == 'append' else archives.get_asset(identity, original=True, _snapshot=snapshot)
    row = {}
    if current.get('pending_path'):
        rows, _ = _asset_rows(archives, zone, {zone:snapshot})
        matches = [row for row in rows if row.get('asset_id') == identity]
        if len(matches) != 1:
            raise ValueError('Asset draft identity changed or is ambiguous; refresh the review')
        row = matches[0]
    return _result(current, original, operation, row)


def get_audio_change(app, identity):
    sounds = app.sounds()
    if identity.startswith('invalid-'):
        row = next((row for row in _audio_rows(sounds) if row['id'] == identity), None)
        if row is None:
            raise ValueError('Audio draft changed or was removed; refresh the review')
        return dict(kind='sound', id=identity, name=row['name'], language='json', original=None,
            modified=_json(row), baseline='Original unavailable; audio draft validation failed',
            status='invalid', error=row.get('error'), operation='replace')
    match = re.fullmatch(r'([0-9a-f]{64}):(\d+)', identity)
    if not match or int(match[2]) > 0xffffffff:
        raise ValueError('Invalid audio review identity')
    zone, file = match[1], int(match[2])
    _, draft, _ = sounds.drafts._read_current(zone, file)
    snapshot = sounds._zone_snapshot_by_id(zone)
    entries = [row for row in sounds._public_entries(snapshot) if row['file_id'] == file]
    if len(entries) != 1:
        raise ValueError('Audio draft has no unique native SoundBank owner')
    asset = entries[0]['asset_id']
    original = sounds.export_wav(zone, asset, file)
    sounds.export_draft_wav(zone, asset, file, draft['revision'])
    source = draft['source_identity']
    old = dict(rate=source['rate'], channels=source['channels'], frames=source['frames'],
               wav_bytes=original['wav_bytes'], wav_sha256=original['wav_sha256'])
    new = dict(draft['authored_dimensions'], wav_bytes=draft['wav_bytes'], wav_sha256=draft['wav_sha256'])
    for value in (old, new):
        value['duration_seconds'] = value['frames'] / value['rate']
    query = dict(zone=zone, asset=asset, file=file)
    before, after = _json(old), _json(new)
    return dict(kind='sound', id=identity, name=source['asset_file_name'], asset_id=asset, zone_id=zone,
        language='json', original=before, modified=after, baseline='Original resident audio from the pinned SAB bank',
        baseline_revision=original['wav_sha256'], revision=draft['revision'], operation='replace', status='staged',
        original_payload=dict(bytes=old['wav_bytes'], sha256=old['wav_sha256']),
        modified_payload=dict(bytes=new['wav_bytes'], sha256=new['wav_sha256']),
        original_audio='/api/sound/wav?' + urlencode(query),
        modified_audio='/api/sound/wav?' + urlencode(dict(query, draft=1, revision=draft['revision'])),
        provenance=source, insights=dict(_insights(before, after, 'json'), field_changes=_field_changes(old, new)))
