"""Snapshot and publish native zone replacements without losing staged edits."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PureWindowsPath


def require_unique_replacements(rows):
    """Reject Windows destination aliases before any package is copied."""
    seen = set()
    for row in rows:
        name = row.get('name')
        if (not isinstance(name, str) or not name.startswith('zone/') or '\\' in name or
                PureWindowsPath(name).drive or
                any(part in ('', '.', '..') or part.endswith((' ', '.')) or
                    any(character in part for character in ':<>"|?*\0')
                    for part in name.split('/'))):
            raise ValueError('Asset package has an invalid replacement path')
        key = name.casefold()
        if key in seen:
            raise ValueError('Multiple asset packages claim the same Windows replacement path; '
                             'merge the edits into the consolidated input before compiling')
        seen.add(key)


def file_hash(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def pending_snapshot(cache):
    """Include current revisions and their payloads; reject escaped cache paths."""
    cache = Path(cache).resolve()
    result = {}
    for current in sorted((cache / 'fastfiles').glob('**/pending-edits/*/current.json')):
        current = current.resolve()
        if not current.is_relative_to(cache):
            raise ValueError('Pending asset revision escapes the workstation cache')
        row = json.loads(current.read_text(encoding='utf-8'))
        relative = row.get('edited_payload_path', '')
        if not relative or Path(relative).name != relative or Path(relative).is_absolute():
            raise ValueError('Pending asset payload path is invalid')
        payload = (current.parent / relative).resolve()
        if not payload.is_relative_to(current.parent):
            raise ValueError('Pending asset payload escapes its revision folder')
        if file_hash(payload) != row.get('edited_payload_sha256'):
            raise ValueError('Pending asset payload changed after its editor compilation')
        revision = row.get('revision', '')
        if len(revision) != 64 or any(c not in '0123456789abcdef' for c in revision):
            raise ValueError('Pending asset revision is invalid')
        immutable = current.parent / (revision + '.json')
        if json.loads(immutable.read_text(encoding='utf-8')) != row:
            raise ValueError('Current asset revision differs from its immutable snapshot')
        for path in (current, payload, immutable):
            result[path.relative_to(cache).as_posix()] = file_hash(path)
    return result


def require_snapshot(cache, expected):
    if pending_snapshot(cache) != expected:
        raise ValueError('Staged asset revisions changed during compilation; rebuild before publication')


def pending_sound_snapshot(cache):
    """Pin authored WAVs and immutable SAB draft revisions independently of FF edits."""
    from tools.workstation_sab_drafts import SoundBankDraftStore
    return SoundBankDraftStore(cache).pending_snapshot()


def require_sound_snapshot(cache, expected):
    if pending_sound_snapshot(cache) != expected:
        raise ValueError('Staged sound revisions changed during compilation; rebuild before publication')


def sound_replacement_rows(result, zone_root):
    """Publish only the proof-owned base SAB at its native sibling path."""
    zone_root = Path(zone_root).resolve()
    source = Path(result['source_banks']['base_path']).resolve(strict=True)
    output = Path(result['output']['path']).resolve(strict=True)
    expected = result['output']['sha256']
    if (not source.is_relative_to(zone_root) or source.suffix.lower() != '.sabs' or
            source.name.startswith('patch_') or output.name != source.name or
            result.get('emitted_files') != [source.name] or result.get('patch_bank_emitted') is not False or
            result.get('native_aliases_revalidated') is not True or
            file_hash(source) != result['source_banks']['base_sha256'] or
            output == source or file_hash(output) != expected):
        raise ValueError('SAB output or native source differs from its verified package receipt')
    return [{'name': (Path('zone') / source.relative_to(zone_root)).as_posix(),
             'path': str(output), 'sha256': expected, 'bytes': output.stat().st_size}]


def replacement_rows(result, zone_root, source_path):
    """Map proof-owned output files to exactly their original game zone names."""
    zone_root, source = Path(zone_root).resolve(), Path(source_path).resolve()
    if not source.is_relative_to(zone_root) or source.suffix.lower() != '.ff':
        raise ValueError('Packaged source is outside the configured game zone folder')
    relative = source.relative_to(zone_root)
    outputs = [(Path(result['output_fastfile']), result['output_fastfile_sha256'])]
    outputs.extend((Path(row['path']), row['sha256']) for row in result.get('sidecars', []))
    rows, seen = [], set()
    for path, expected in outputs:
        if path.suffix.lower() not in ('.ff', '.fp', '.fc') or path.stem != source.stem:
            raise ValueError('Native writer emitted an unexpected replacement filename')
        name = (Path('zone') / relative.with_suffix(path.suffix.lower())).as_posix()
        if name in seen or file_hash(path) != expected:
            raise ValueError('Native replacement file differs from its verified writer receipt')
        seen.add(name)
        rows.append({'name': name, 'path': str(path.resolve()), 'sha256': expected,
                     'bytes': path.stat().st_size})
    return rows
