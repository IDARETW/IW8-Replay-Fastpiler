"""Read-only symbol context over the pinned catalog and Replay analysis database."""
from contextlib import closing
import json
import sqlite3

import source_catalog


def _catalog_index(sources, rows):
    cached = getattr(sources, '_context_catalog_index', None)
    if isinstance(cached, dict) and cached['rows'] is rows:
        return cached
    cached = {'rows': rows, 'by_id': {}, 'by_rva': {}, 'by_name': {}}
    from recovered_cpp_names import function_name, global_name
    base = _image_base(sources, sources._catalog)
    for row in rows:
        cached['by_id'][row['id']] = row
        cached['by_rva'].setdefault(row['rva'], []).append(row)
        automatic = (function_name if row.get('kind', 'function') == 'function' else global_name)(row['rva'], base)
        for name in {row['id'], row.get('name', ''), automatic, *row.get('aliases', [])} - {''}:
            cached['by_name'].setdefault(name, []).append(row)
    sources._context_catalog_index = cached
    return cached


def _image_base(sources, catalog):
    path = sources.generated / 'manifest.json'
    stat = path.stat()
    signature = (stat.st_size, stat.st_mtime_ns, getattr(stat, 'st_ctime_ns', None))
    cached = getattr(sources, '_context_manifest', None)
    if not isinstance(cached, dict) or cached['signature'] != signature:
        manifest = json.loads(path.read_text(encoding='utf-8'))
        if manifest.get('input_sha256') not in (None, catalog['image_sha256']):
            raise ValueError('Reference manifest belongs to another Replay image')
        cached = {'signature': signature, 'image_base': int(manifest['image_base'])}
        sources._context_manifest = cached
    return cached['image_base']


def inspect_symbol(sources, *, identity=None, query='', offset=0, limit=12):
    if offset < 0 or not 1 <= limit <= 40:
        raise ValueError('Invalid reference page range')
    if len(query) > 256:
        raise ValueError('Symbol lookup is too long')
    rows = sources._rows()
    catalog = sources._catalog
    index = _catalog_index(sources, rows)
    by_id, by_rva = index['by_id'], index['by_rva']
    bindings = {}
    units_path = sources.root / 'source-units.json'
    if units_path.is_file():
        document = json.loads(units_path.read_text(encoding='utf-8'))
        if document.get('image_sha256') not in (None, catalog['image_sha256']):
            raise ValueError('Source bindings belong to another Replay image')
        for entry in document.get('imports', []) + document.get('units', []):
            symbol = entry.get('symbol')
            target = entry.get('symbol_id') or entry.get('function_id')
            if symbol and target in by_id:
                bindings.setdefault(symbol, set()).add(target)
    for target, variants in sources._state().get('sources', {}).items():
        symbol = variants.get('cpp', {}).get('symbol')
        if symbol and target in by_id:
            bindings.setdefault(symbol, set()).add(target)
    if identity:
        candidates = [by_id[identity]] if identity in by_id else []
    else:
        candidates = list(index['by_name'].get(query, []))
        selected_ids = {row['id'] for row in candidates}
        candidates.extend(by_id[target] for target in sorted(bindings.get(query, set()) - selected_ids))

    def describe(row):
        return {'id': row['id'], 'name': sources._display_name(row),
                'kind': row.get('kind', 'function'), 'rva': row['rva'],
                'variant': 'cpp' if row.get('kind', 'function') == 'function' else 'assembly',
                'aliases': row.get('aliases', [])[:12]}

    result = {'query': query, 'matches': [describe(row) for row in candidates[:12]],
              'match_count': len(candidates), 'subject': None, 'groups': {},
              'image_sha256': catalog['image_sha256'],
              'basis': 'Replay SQLite analysis resolved against the pinned Replay catalog',
              'coverage': 'Recorded static references. Indirect calls and unrecorded references are not included.'}
    if len(candidates) != 1:
        return result
    subject = candidates[0]
    result['subject'] = describe(subject)
    result['subject']['bytes'] = subject.get('size')
    if not sources.sqlite_path.is_file():
        result['coverage'] = 'The analysis database is unavailable. Catalog identity is still resolved.'
        return result
    image_base = _image_base(sources, catalog)

    def referenced(rva, **extra):
        matches = by_rva.get(rva, [])
        functions = [row for row in matches if row.get('kind', 'function') == 'function']
        matches = functions or matches
        row = matches[0] if len(matches) == 1 else None
        return {**(describe(row) if row else {'id': None, 'name': f'Unmapped target {rva:#x}',
                                            'kind': 'unmapped', 'rva': rva}), **extra}

    with closing(sqlite3.connect(source_catalog.readonly_uri(sources.sqlite_path), uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        address = image_base + subject['rva']
        function = db.execute('SELECT id, prototype, prototype2, comment, size FROM functions WHERE address IN (?,?,?)',
                              (str(address), hex(address), f'{address:X}')).fetchone() if 'functions' in tables else None
        if function:
            result['subject'].update(prototype=function['prototype2'] or function['prototype'] or '',
                                     comment=function['comment'] or '', bytes=function['size'])
        if 'replay_ida_function_text' in tables:
            text = db.execute('SELECT prototype FROM replay_ida_function_text WHERE function_rva=?', (subject['rva'],)).fetchone()
            if text and text['prototype']:
                result['subject']['prototype'] = text['prototype']
        if function and 'callgraph' in tables:
            for direction in ('caller', 'callee'):
                total = db.execute('SELECT count(DISTINCT address) FROM callgraph WHERE func_id=? AND type=?',
                                   (function['id'], direction)).fetchone()[0]
                peers = db.execute('SELECT DISTINCT address FROM callgraph WHERE func_id=? AND type=? ORDER BY address LIMIT ? OFFSET ?',
                                   (function['id'], direction, limit, offset)).fetchall()
                items = []
                for peer in peers:
                    try:
                        rva = int(peer['address'], 0) - image_base
                    except (ValueError, TypeError):
                        continue
                    items.append(referenced(rva, relation=direction))
                result['groups'][direction] = {'items': items, 'total': total, 'offset': offset, 'limit': limit}
        if 'replay_crossref_function_references' in tables:
            for direction, column, target in [('inbound', 'target_rva', 'owner_rva'), ('outbound', 'owner_rva', 'target_rva')]:
                total = db.execute(f'SELECT count(*) FROM replay_crossref_function_references WHERE {column}=?', (subject['rva'],)).fetchone()[0]
                peers = db.execute(f'SELECT owner_rva, site_rva, target_rva, kind, decoded FROM replay_crossref_function_references WHERE {column}=? ORDER BY site_rva LIMIT ? OFFSET ?',
                                   (subject['rva'], limit, offset)).fetchall()
                result['groups'][direction] = {'items': [referenced(peer[target], relation=peer['kind'],
                    site_rva=peer['site_rva'], instruction=peer['decoded']) for peer in peers],
                    'total': total, 'offset': offset, 'limit': limit}
    return result
