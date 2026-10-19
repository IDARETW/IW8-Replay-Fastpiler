"""Maintain source associations by recovered function identity, never RVA/layout.

The full catalog comes from the pinned analysis export. `bind` chooses a
catalog name or opaque ID; compilation derives addresses and ownership. A
source unit must still provide real C++ with a correct ABI: binary recovery
cannot invent reliable parameter types from an arbitrary descriptive name.
"""
import argparse
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
import sqlite3
from contextlib import closing

ROOT=Path(__file__).resolve().parents[1]


def database_path():
    """Resolve the read-only analysis database from workstation configuration."""
    configured = os.environ.get('REPLAY_SQLITE')
    if configured:
        return Path(configured).expanduser().resolve()
    game_root = Path(os.environ.get('REPLAY_GAME_ROOT', r'E:\IW8\Builds\1.20-replay')).expanduser()
    return (game_root / 'game_dx12_ship_replay.exe.sqlite').resolve()


def readonly_uri(path):
    return Path(path).resolve().as_uri() + '?mode=ro'


def backup_readonly_database(source_path, destination_path):
    """Take one transactionally consistent SQLite backup and return its digest."""
    source_path, destination_path = Path(source_path).resolve(), Path(destination_path).resolve()
    with closing(sqlite3.connect(readonly_uri(source_path), uri=True)) as source:
        with closing(sqlite3.connect(str(destination_path))) as destination:
            source.backup(destination, pages=8192, sleep=0.01)
    with destination_path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def stable_id(image_hash, rva):
    return 'fn_'+hashlib.sha256(f'{image_hash}:{rva:08x}'.encode()).hexdigest()[:16]


def symbol_id(image_hash, rva):
    return 'sym_'+hashlib.sha256(f'{image_hash}:{rva:08x}'.encode()).hexdigest()[:16]


def parse_integer(value, field):
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f'Invalid SQLite {field}: {value!r}') from error


def function_quarantine(db, image_base):
    """Read inactive legacy entries without dropping their relational IDs."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='replay_function_quarantine'").fetchone():
        return {}
    rows = {}
    for identity, address, reason in db.execute('SELECT function_id,address,reason FROM replay_function_quarantine'):
        rows[identity] = {'rva': parse_integer(address, 'quarantined function address') - image_base,
                          'reason': str(reason)}
    return rows


def decompiler_function_names(db, image_hash, expected_md5):
    """Keep exported token ownership separate from live/historical aliases."""
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='replay_ida_export_function_names'").fetchone():
        return {}
    if not expected_md5:
        raise ValueError('Decompiler name provenance requires the pinned executable MD5')
    names, seen = {}, set()
    for rva, name, md5, sha256, idb_sha256, idb_path in db.execute(
            'SELECT function_rva,name,input_md5,image_sha256,idb_sha256,idb_path '
            'FROM replay_ida_export_function_names'):
        if str(md5).lower() != expected_md5.lower() or str(sha256).lower() != image_hash.lower():
            raise ValueError('Decompiler name provenance belongs to another executable')
        if not re.fullmatch('[0-9a-fA-F]{64}', str(idb_sha256)) or not idb_path:
            raise ValueError('Decompiler name provenance has no closed IDB identity')
        rva = parse_integer(rva, 'decompiler function RVA')
        if not name or name in seen or rva in names:
            raise ValueError('Decompiler name provenance is ambiguous')
        names[rva] = dict(decompiler_name=name, decompiler_idb_sha256=idb_sha256)
        seen.add(name)
    return names


def _read_sqlite_catalog(database, image_base, image_hash, expected_md5, image_size=None, progress=None):
    """Read only identity-bearing names and addresses from the analysis DB."""
    started = time.monotonic()
    last_progress = started
    records, snapshot_rows, by_database_id = [], [], {}
    seen_rvas = set()
    with closing(sqlite3.connect(readonly_uri(database), uri=True)) as db:
        db.execute('BEGIN')
        programs = db.execute('SELECT processor,md5sum FROM program').fetchall()
        if len(programs) != 1:
            raise ValueError('SQLite program identity is missing or ambiguous')
        processor, md5sum = programs[0]
        if processor.casefold() != 'pc64':
            raise ValueError(f'Unexpected SQLite processor identity: {processor!r}')
        actual_md5 = md5sum.hex() if isinstance(md5sum, bytes) else str(md5sum).lower()
        if actual_md5 != expected_md5.lower():
            raise ValueError('SQLite program MD5 does not match recovered Replay image metadata')
        quarantine = function_quarantine(db, image_base)
        export_names = decompiler_function_names(db, image_hash, expected_md5)
        cursor = db.execute('SELECT id,name,address,mangled_function,rva FROM functions ORDER BY id')
        for identity, name, address, mangled, stored_rva in cursor:
            absolute = parse_integer(address, 'function address')
            rva = absolute - image_base
            if stored_rva not in (None, '') and parse_integer(stored_rva, 'function RVA') != rva:
                raise ValueError(f'SQLite address/RVA disagreement for function row {identity}')
            if rva < 0 or (image_size is not None and rva >= image_size) or rva in seen_rvas:
                raise ValueError(f'SQLite function RVA is invalid or duplicated: {rva:#x}')
            seen_rvas.add(rva)
            if identity in by_database_id:
                raise ValueError(f'Duplicate SQLite function identity: {identity}')
            record = dict(id=stable_id(image_hash, rva), database_id=identity,
                          name=name or '', sqlite_name=name or '', rva=rva,
                          aliases=sorted({item for item in (name, mangled) if item}))
            snapshot_rows.append(dict(database_id=identity, name=name or '', address=absolute,
                                      mangled_function=mangled or '', rva=rva))
            if rva in export_names:
                record.update(export_names[rva])
                snapshot_rows[-1].update(export_names[rva])
            if identity in quarantine:
                if quarantine[identity]['rva'] != rva:
                    raise ValueError(f'Quarantine address disagrees with function identity {identity}')
                record.update(quarantined=True, quarantine_reason=quarantine[identity]['reason'])
                snapshot_rows[-1]['quarantined'] = True
                snapshot_rows[-1]['quarantine_reason'] = quarantine[identity]['reason']
            by_database_id[identity] = rva
            records.append(record)
            now = time.monotonic()
            if progress and (len(records) % 100000 == 0 or now - last_progress >= 2.0):
                progress(len(records), now - started)
                last_progress = now
        if export_names.keys() - seen_rvas:
            raise ValueError('Decompiler name provenance refers to an absent function')
    return records, by_database_id, snapshot_rows


def merge_catalog_rows(previous, fresh):
    """Refresh names while preserving stable identities and recovered aliases."""
    previous = previous or {'functions': [], 'symbols': []}
    old_by_db = {row['database_id']: row for row in previous.get('functions', [])
                 if 'database_id' in row}
    fresh_ids = {row['database_id'] for row in fresh}
    if old_by_db.keys() - fresh_ids:
        raise ValueError('SQLite function identities disappeared; refusing to rebuild catalog')
    for row in fresh:
        old = old_by_db.get(row['database_id'])
        if old and (old['rva'] != row['rva'] or old['id'] != row['id']):
            raise ValueError(f'SQLite function identity moved: database row {row["database_id"]}')
        if old:
            aliases = set(old.get('aliases', [])) | set(row.get('aliases', []))
            # Current useful labels become primary; retain any prior verified label.
            current_name = row['name']
            old_name = old.get('name', '')
            row['aliases'] = sorted(alias for alias in aliases if alias)
            row['name'] = current_name if current_name and not _is_opaque_name(current_name) else (
                old_name if old_name and not _is_opaque_name(old_name) else current_name or old_name or row['id'])
            row['aliases'] = sorted(set(row['aliases']) | ({row['name']} if row['name'] else set()))
            if old.get('symbol_history'):
                row['symbol_history'] = old['symbol_history']
    by_id = {row['id']: row for row in fresh}
    by_rva = {row['rva']: row for row in fresh}
    for old in previous.get('functions', []):
        if old['id'] in by_id:
            row = by_id[old['id']]
            if old['rva'] != row['rva']:
                raise ValueError('Stable function identity moved during catalog refresh')
            row['aliases'] = sorted(set(row.get('aliases', [])) | set(old.get('aliases', [])))
            if _is_opaque_name(row.get('name', '')) and not _is_opaque_name(old.get('name', '')):
                row['name'] = old['name']
            if old.get('symbol_history'):
                row['symbol_history'] = old['symbol_history']
            continue
        if old['rva'] in by_rva:
            row = by_rva[old['rva']]
            row['aliases'] = sorted(set(row.get('aliases', [])) | set(old.get('aliases', [])))
            if _is_opaque_name(row.get('name', '')) and not _is_opaque_name(old.get('name', '')):
                row['name'] = old['name']
        else:
            fresh.append(old)
    return fresh, previous.get('symbols', [])


def merge_catalog_symbols(functions, fresh, previous, image_base):
    """Reconcile derived address roles after same-image decoding improves.

    These roles describe instruction heads, not declared storage types. A new
    function entry supersedes its former address label while retaining aliases
    and history. Arbitrary typed-symbol role changes remain an error.
    """
    from recovered_cpp_names import global_name
    owners = {row['rva']: row for row in functions if not row.get('quarantined')}
    old_by_id = {row['id']: row for row in previous}
    old_by_rva = {row['rva']: row for row in previous}
    inferred = {'code-label', 'data-address'}
    fresh_rvas = {row['rva'] for row in fresh}
    result = []
    seen = set()
    for row in [*fresh, *(old for old in previous if old['rva'] not in fresh_rvas)]:
        old = old_by_id.get(row['id']) or old_by_rva.get(row['rva'])
        if old and old['rva'] != row['rva']:
            raise ValueError('Stable address-symbol identity moved during catalog refresh')
        owner = owners.get(row['rva'])
        if owner:
            if row.get('kind') not in inferred:
                raise ValueError(f'Typed symbol overlaps a function entry at {row["rva"]:#x}')
            aliases = {row['id'], row.get('name', ''), *row.get('aliases', []),
                       global_name(row['rva'], image_base)} - {''}
            owner['aliases'] = sorted(set(owner.get('aliases', [])) | aliases)
            history = owner.setdefault('symbol_history', [])
            entry = {key: row[key] for key in ('id', 'rva', 'kind')}
            entry['aliases'] = sorted(aliases)
            if entry not in history:
                history.append(entry)
            continue
        if old:
            row = dict(row)
            row['aliases'] = sorted(set(row.get('aliases', [])) | set(old.get('aliases', [])))
            if not row['aliases'] and old.get('name'):
                row['aliases'].append(old['name'])
            if row.get('kind') != old.get('kind') and not {row.get('kind'), old.get('kind')} <= inferred:
                raise ValueError(f'Typed symbol kind changed at {row["rva"]:#x}')
            history = list(old.get('classification_history', [old.get('kind')]))
            if row.get('kind') not in history:
                history.append(row['kind'])
            if len(history) > 1:
                row['classification_history'] = history
        if row['rva'] in seen:
            raise ValueError(f'Duplicate address-symbol ownership at {row["rva"]:#x}')
        seen.add(row['rva'])
        result.append(row)
    return result


def _is_opaque_name(name):
    from recovered_cpp_names import is_generated_name
    return (is_generated_name(name) or bool(re.fullmatch(r'(?:0x)?[0-9a-fA-F]{8,16}', name or ''))
            or (name or '').startswith(('fn_', 'sym_')))


def logical_snapshot_document(image_hash, image_base, expected_md5, source_rows):
    """Return the location-independent content document and its logical hash."""
    document = dict(schema=1, snapshot_kind='sqlite-logical-catalog-v1',
                    image_sha256=image_hash, image_base=image_base,
                    program=dict(processor='pc64', md5sum=expected_md5.lower()),
                    function_count=len(source_rows), functions=source_rows)
    raw = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    return document, hashlib.sha256(raw).hexdigest()


def unique_alias_targets(catalog):
    """Return unambiguous aliases, preferring one exact SQLite-name owner.

    Refreshed catalogs preserve historical aliases. A legacy alias can collide
    with a different function's current SQLite name; in that case only the
    unique row whose raw ``sqlite_name`` equals the alias owns it. Old
    catalogs without raw SQLite-name provenance remain fail-closed for
    ambiguous aliases.
    """
    candidates = {}
    for group in ('functions', 'symbols'):
        for row in catalog.get(group, []):
            if row.get('quarantined'):
                continue
            for alias in set(row.get('aliases', [])) | {row.get('name', '')}:
                if alias:
                    candidates.setdefault(alias, {})[(group, row['id'])] = row

    resolved = {}
    for alias, rows_by_identity in candidates.items():
        rows = list(rows_by_identity.items())
        groups = {group for (group, _identity), _row in rows}
        if len(groups) > 1:
            continue
        rvas = {int(row['rva']) for _, row in rows}
        if len(rvas) == 1:
            resolved[alias] = next(iter(rvas))
            continue

        # Only a function with an explicit raw SQLite name can own an
        # ambiguous historical spelling. A data-symbol collision is not a
        # legacy function alias and therefore keeps the name unresolved.
        if groups != {'functions'}:
            continue
        owners = [row for (_group, _identity), row in rows
                  if row.get('sqlite_name') == alias]
        if len(owners) == 1:
            resolved[alias] = int(owners[0]['rva'])
    from recovered_cpp_names import automatic_aliases
    for alias, rva in automatic_aliases(catalog).items():
        if alias in resolved and resolved[alias] != rva:
            raise ValueError(f'Automatic C++ alias conflicts with catalog identity: {alias}')
        resolved[alias] = rva
    return resolved


def refresh(output, image_base, image_hash, native, destination, previous_catalog=None):
    """Create a build-owned catalog snapshot from current SQLite names.

    The source DB is opened read-only. Its executable MD5 must match the
    recovery report; row IDs/RVAs must match the previous generated catalog.
    """
    output = Path(output)
    destination = Path(destination)
    database = database_path()
    m = json.loads((output / 'manifest.json').read_text())
    image_report = json.loads((output / 'ida-code-report.json').read_text())
    if image_report.get('image_base') != image_base:
        raise ValueError('SQLite name catalog image base does not match recovered layout')
    expected_md5 = image_report['input_md5']
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rows_path = destination.parent / 'sqlite-function-names.json'
    snapshot_started = time.monotonic()
    print(f'SQLite logical catalog snapshot: reading {database}', flush=True)
    records, by_database_id, source_rows = _read_sqlite_catalog(
        database, image_base, image_hash, expected_md5, m['optional']['SizeOfImage'],
        progress=lambda count, elapsed: print(
            f'SQLite logical catalog snapshot: {count} functions scanned ({elapsed:.1f}s)', flush=True))
    logical_document, logical_digest = logical_snapshot_document(
        image_hash, image_base, expected_md5, source_rows)
    rows_document = dict(schema=2, snapshot_kind='sqlite-logical-catalog-v1',
                         image_sha256=image_hash, image_base=image_base,
                         program=dict(processor='pc64', md5sum=expected_md5.lower()),
                         function_count=len(source_rows),
                         database_program_md5=expected_md5.lower(),
                         logical_snapshot_sha256=logical_digest,
                         provenance=dict(source_database=str(database)),
                         functions=source_rows)
    rows_data = (json.dumps(rows_document, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    rows_path.write_bytes(rows_data)
    print(f'SQLite logical catalog snapshot complete: {len(source_rows)} functions, '
          f'{time.monotonic() - snapshot_started:.1f}s, logical_sha256={logical_digest}', flush=True)
    rows_digest = hashlib.sha256(rows_path.read_bytes()).hexdigest()
    if previous_catalog is None:
        previous_path = output / 'function-catalog.json'
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else None
    else:
        previous = previous_catalog
    if previous and previous.get('image_sha256') != image_hash:
        raise ValueError('Previous function catalog belongs to a different Replay image')
    old_by_db = {row['database_id']: row for row in (previous or {}).get('functions', [])
                 if 'database_id' in row}
    sqlite_names_added = sum(1 for row in records
                             if row['name'] and row['name'] not in old_by_db.get(row['database_id'], {}).get('aliases', []))
    sqlite_mangled_added = sum(1 for row in records
                               if len(row['aliases']) > (1 if row['name'] else 0) and
                               any(alias not in old_by_db.get(row['database_id'], {}).get('aliases', [])
                                   for alias in row['aliases'] if alias != row['name']))
    records, preserved_symbols = merge_catalog_rows(previous, records)
    # Include PE-recovered entries absent from the IDA function table too.
    from native_functions import FunctionIndex
    sources=[(s,(output/s['file']).read_bytes()) for s in m['sections'] if 'file' in s]
    def read_data(at,size):
        for s,data in sources:
            offset=at-s['rva']
            if 0<=offset and offset+size<=len(data):return data[offset:offset+size]
        raise ValueError(f'Uninitialized metadata at {at:#x}')
    index=FunctionIndex(m,read_data,(output/'instruction-lengths.bin').read_bytes())
    known={r['rva'] for r in records}
    references, calls = set(native.values()), set()
    for source in sorted((output/'asm').glob('*.s')):
        content=source.read_bytes()
        references.update(int(v,16) for v in re.findall(rb'replay_rva_([0-9a-fA-F]{8})',content))
        calls.update(int(v,16) for v in re.findall(rb'\bcall replay_rva_([0-9a-fA-F]{8})',content))
    for entry in sorted(set(index.roots)|{r for r in calls if index.head(r)}):
        if entry not in known:
            identity=stable_id(image_hash,entry)
            records.append(dict(id=identity,name=identity,rva=entry,aliases=[]))
    aliases={}
    for name,rva in native.items():aliases.setdefault(rva,[]).append(name)
    for row in records:
        row['aliases']=sorted(set(row['aliases'])|set(aliases.get(row['rva'],[])))
    function_entries={r['rva'] for r in records if not r.get('quarantined')}
    symbols=[]
    for rva in sorted(references-function_entries):
        if not 0 <= rva < m['optional']['SizeOfImage']:
            raise ValueError(f'Recovered catalog reference outside image: {rva:#x}')
        identity=symbol_id(image_hash,rva)
        names=sorted(aliases.get(rva,[]))
        section=next((s['name'] for s in m['sections'] if s['rva']<=rva<s['rva']+max(s['raw_size'],s['virtual_size'])),None)
        symbols.append(dict(id=identity,name=names[0] if names else identity,rva=rva,aliases=names,
                            kind='code-label' if index.head(rva) else 'data-address',section=section))
    symbols = merge_catalog_symbols(records, symbols, preserved_symbols, image_base)
    result=dict(schema=5,image_sha256=image_hash,image_base=image_base,
                database_snapshot_kind='sqlite-logical-catalog-v1',
                database_logical_snapshot_sha256=logical_digest,
                database_snapshot_sha256=rows_digest,
                database_program_md5=expected_md5.lower(),database_function_count=len(by_database_id),
                sqlite_names_added_as_aliases=sqlite_names_added,
                sqlite_mangled_alias_rows_added=sqlite_mangled_added,
                functions=records,symbols=symbols)
    temporary = destination.with_suffix(destination.suffix + '.tmp')
    temporary.write_text(json.dumps(result,indent=2)+'\n', encoding='utf-8')
    temporary.replace(destination)
    return result, dict(path=str(database), snapshot_kind='sqlite-logical-catalog-v1',
                        logical_snapshot_sha256=logical_digest, snapshot_sha256=rows_digest,
                        catalog_rows_path=str(rows_path), catalog_rows_sha256=rows_digest,
                        program_md5=expected_md5.lower(), function_count=len(by_database_id),
                        names_added_as_aliases=sqlite_names_added,
                        mangled_alias_rows_added=sqlite_mangled_added)


def validate_database_snapshot(expected):
    path = Path(expected['catalog_rows_path'])
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected['catalog_rows_sha256']:
        raise ValueError('Build-owned SQLite function-name snapshot changed during compilation')


def export(output, image_base, image_hash, native):
    """Compatibility wrapper for recovery-time catalog generation."""
    result, _ = refresh(output, image_base, image_hash, native, Path(output) / 'function-catalog.json')
    return result


def _source_path_identity(value):
    """Normalize a source path for exact COFF-object ownership matching."""
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return os.path.normcase(str(path.resolve())).casefold()


def is_executable_function_definition(obj, symbol):
    """Recognize one external COFF function in an executable text section."""
    section_number = symbol.get('section', 0)
    sections = obj.get('sections', [])
    if (symbol.get('storage') != 2 or not isinstance(section_number, int) or
            section_number <= 0 or section_number > len(sections) or
            not symbol.get('kind', 0) & 0x20):
        return False
    section = sections[section_number-1]
    return (section.get('name', '').split('$')[0] == '.text' and
            bool(section.get('flags', 0) & 0x20) and
            bool(section.get('flags', 0) & 0x20000000))


def resolve(manifest, native, objects, catalog_path=None, document=None):
    path=Path(catalog_path) if catalog_path else ROOT/'generated/function-catalog.json'
    catalog=json.loads(path.read_text())
    if catalog['image_sha256']!=manifest['input_sha256']:
        raise ValueError('Function catalog belongs to a different original executable')
    by_id={r['id']:r for r in catalog['functions']}
    document=document if document is not None else json.loads((ROOT/'source-units.json').read_text())
    units=document['units']
    associations={}
    compiled_by_stem={}
    compiled_by_source={}
    for obj in objects:
        compiled_by_stem.setdefault(Path(obj['path']).stem.casefold(), []).append(obj)
        source_path=obj.get('source_path')
        if source_path is not None:
            if not isinstance(source_path, str) or not source_path:
                raise ValueError('Compiled object has malformed source_path provenance')
            compiled_by_source.setdefault(_source_path_identity(source_path), []).append(obj)
    for unit in units:
        identity=unit['function_id'];symbol=unit['symbol'];source=Path(unit['source'])
        if identity not in by_id:
            raise ValueError(f'Missing recovered function identity: {identity}')
        if by_id[identity].get('quarantined'):
            raise ValueError(f'Recovered function identity is quarantined after fresh native analysis: {identity}')
        exact=compiled_by_source.get(_source_path_identity(source), [])
        if len(exact)>1:
            raise ValueError(f'Duplicate compiled objects claim source unit: {source}')
        if exact:
            obj=exact[0]
        else:
            candidates=compiled_by_stem.get(source.stem.casefold(), [])
            if not candidates:
                raise ValueError(f'Missing compiled source unit: {source}')
            if len(candidates)>1:
                raise ValueError(f'Ambiguous compiled source unit basename: {source}')
            obj=candidates[0]
            if obj.get('source_path') is not None:
                raise ValueError(f'Compiled object source provenance mismatch: {source}')
        definitions=[s for s in obj['symbols'].values() if s['name']==symbol and s['section']>0 and s['storage']==2]
        if len(definitions)!=1:
            raise ValueError(f'Source unit no longer defines its catalog function: {source} -> {symbol}')
        definition = definitions[0]
        # Parsed COFF objects carry both the symbol function-type bit and its
        # owning section. Do not let an external data object satisfy a function
        # replacement merely because its name matches the mapped unit.
        if not is_executable_function_definition(obj, definition):
            raise ValueError(f'Source unit does not define an executable function: {source} -> {symbol}')
        rva=by_id[identity]['rva']
        if symbol in native and native[symbol]!=rva:
            raise ValueError(f'Conflicting recovered alias: {symbol}')
        if symbol in associations:
            raise ValueError(f'Duplicate source association: {symbol}')
        associations[symbol]=rva
    all_ids={r['id']:r for r in catalog['functions']+catalog.get('symbols',[])}
    for item in document.get('imports',[]):
        name=item['symbol'];identity=item['symbol_id']
        if identity not in all_ids:
            raise ValueError(f'Missing recovered import identity: {identity}')
        if all_ids[identity].get('quarantined'):
            raise ValueError(f'Recovered import identity is quarantined after fresh native analysis: {identity}')
        rva=all_ids[identity]['rva']
        if (name in native and native[name]!=rva) or (name in associations and associations[name]!=rva):
            raise ValueError(f'Conflicting recovered import alias: {name}')
        associations[name]=rva
    native.update(associations)
    return units


def compose_source_profile(profile_path, manifest, baseline_units, baseline_catalog_path, root=ROOT):
    """Validate and compose an opt-in diagnostic overlay without editing defaults."""
    profile_path = Path(profile_path)
    if not profile_path.is_absolute():
        profile_path = root / profile_path
    profile_path = profile_path.resolve()
    profile = json.loads(profile_path.read_text(encoding='utf-8'))
    if profile.get('schema') != 1 or not profile.get('profile_id'):
        raise ValueError('Unsupported or unnamed source profile')
    if profile.get('source_image_sha256') != manifest['input_sha256'] or profile.get('image_base') != manifest['image_base']:
        raise ValueError('Source profile belongs to a different Replay image/layout')
    base_path = root / 'source-units.json'
    if hashlib.sha256(base_path.read_bytes()).hexdigest() != profile.get('base_source_units_sha256'):
        raise ValueError('Source profile baseline bindings changed; regenerate the profile')
    catalog_path = Path(baseline_catalog_path)
    catalog_digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    baseline_catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
    if baseline_catalog.get('image_sha256') != manifest['input_sha256']:
        raise ValueError('Source profile baseline catalog belongs to a different Replay image')
    function_rows = baseline_catalog.get('functions', [])
    symbol_rows = baseline_catalog.get('symbols', [])
    rows_by_id = {row['id']: row for row in function_rows + symbol_rows}
    if len(rows_by_id) != len(function_rows) + len(symbol_rows):
        raise ValueError('Source profile baseline catalog has duplicate stable IDs')
    for row in function_rows:
        if row['id'] != stable_id(manifest['input_sha256'], row['rva']):
            raise ValueError(f'Function catalog identity/RVA mismatch: {row["id"]}')
    for row in symbol_rows:
        if row['id'] != symbol_id(manifest['input_sha256'], row['rva']):
            raise ValueError(f'Symbol catalog identity/RVA mismatch: {row["id"]}')
    function_ids = {row['id'] for row in function_rows}
    symbol_ids = {row['id'] for row in symbol_rows}
    referenced_ids = {row.get('function_id') for row in profile.get('replacement_units', [])}
    referenced_ids.update(row.get('symbol_id') for row in profile.get('imports', []))
    for identity in referenced_ids:
        row = rows_by_id.get(identity)
        if row is None:
            raise ValueError(f'Source profile refers to a missing catalog identity: {identity}')
        if row.get('quarantined'):
            raise ValueError(f'Source profile refers to a quarantined function identity: {identity}')
        expected = stable_id(manifest['input_sha256'], row['rva']) if identity in function_ids else symbol_id(manifest['input_sha256'], row['rva'])
        if row['id'] != expected:
            raise ValueError(f'Source profile catalog identity is not stable for this image: {identity}')
    for unit in profile.get('replacement_units', []):
        if unit.get('function_id') not in function_ids:
            raise ValueError(f'Source profile replacement is not a function identity: {unit.get("function_id")}')
    for item in profile.get('imports', []):
        kind = item.get('catalog_kind')
        identity = item.get('symbol_id')
        if kind == 'function' and identity not in function_ids:
            raise ValueError(f'Source profile function import has the wrong catalog identity: {item.get("symbol")}')
        if kind == 'symbol' and identity not in symbol_ids:
            raise ValueError(f'Source profile data import has the wrong catalog identity: {item.get("symbol")}')
        if kind not in (None, 'function', 'symbol'):
            raise ValueError(f'Unsupported source profile import kind: {kind}')
    if profile.get('base_loader_source_sha256'):
        loader = root / 'src' / 'Load_XAsset.cpp'
        normalized_loader = loader.read_text(encoding='utf-8').encode('utf-8')
        if hashlib.sha256(normalized_loader).hexdigest() != profile['base_loader_source_sha256']:
            raise ValueError('Source profile loader baseline changed')
    source_hashes = profile.get('source_sha256', {})
    overlay_units = profile.get('replacement_units')
    if not isinstance(overlay_units, list) or not overlay_units:
        raise ValueError('Source profile has no replacement units')
    units = [dict(item) for item in baseline_units.get('units', [])]
    by_identity = {unit['function_id']: index for index, unit in enumerate(units)}
    seen_profile_ids = set()
    overlay_sources = set()
    for unit in overlay_units:
        if not {'source', 'symbol', 'function_id'} <= unit.keys():
            raise ValueError('Malformed source profile replacement unit')
        if Path(unit['source']).suffix not in ('.cpp', '.c'):
            raise ValueError('Diagnostic source profile replacement units must be C++ translation units')
        if unit['function_id'] in seen_profile_ids:
            raise ValueError('Duplicate function identity in source profile')
        seen_profile_ids.add(unit['function_id'])
        source = (root / unit['source']).resolve()
        if not source.is_relative_to(root.resolve()) or not source.is_file():
            raise ValueError(f'Source profile path is missing or escapes project: {source}')
        relative = source.relative_to(root.resolve()).as_posix()
        expected = source_hashes.get(relative)
        if not expected or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Source profile source hash mismatch: {relative}')
        overlay_sources.add(source)
        if unit['function_id'] in by_identity:
            units[by_identity[unit['function_id']]] = dict(unit)
        else:
            units.append(dict(unit))
            by_identity[unit['function_id']] = len(units) - 1
    for relative, expected in source_hashes.items():
        support = (root / relative).resolve()
        if not support.is_relative_to(root.resolve()) or not support.is_file():
            raise ValueError(f'Source profile support file is missing or escapes project: {relative}')
        if hashlib.sha256(support.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Source profile support hash mismatch: {relative}')
    imports = [dict(item) for item in baseline_units.get('imports', [])]
    imports_by_name = {item['symbol']: item['symbol_id'] for item in imports}
    for item in profile.get('imports', []):
        name, identity = item.get('symbol'), item.get('symbol_id')
        if not name or not identity:
            raise ValueError('Malformed source profile import')
        existing = imports_by_name.get(name)
        if existing is not None and existing != identity:
            raise ValueError(f'Source profile import conflicts with baseline binding: {name}')
        if existing is None:
            imports.append(dict(symbol=name, symbol_id=identity))
            imports_by_name[name] = identity
    required_defines = set(profile.get('required_defines', []))
    supported_defines = {'REPLAY_COMPILER_FRONTEND_PROBE'}
    if required_defines - supported_defines:
        raise ValueError('Source profile requires unsupported compiler defines: ' + ', '.join(sorted(required_defines-supported_defines)))
    composed = dict(baseline_units)
    composed['units'] = units
    composed['imports'] = imports
    composed_by_identity = {unit['function_id']: unit for unit in units}
    superseded_sources = set()
    for unit in baseline_units.get('units', []):
        replacement = composed_by_identity[unit['function_id']]
        original = (root / unit['source']).resolve()
        if original != (root / replacement['source']).resolve():
            superseded_sources.add(original)
    # One object owns its whole translation unit. Dropping it must not silently
    # drop another replacement still bound to that file.
    for unit in units:
        if (root / unit['source']).resolve() in superseded_sources:
            raise ValueError('Source profile replaces only part of a baseline translation unit: ' + unit['source'])
    return composed, dict(path=str(profile_path), sha256=hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                          profile_id=profile['profile_id'], replacement_count=len(overlay_units),
                          pinned_catalog_sha256=profile.get('function_catalog_sha256'),
                          baseline_catalog_sha256=catalog_digest,
                          catalog_digest_matches_profile=(profile.get('function_catalog_sha256') == catalog_digest),
                          catalog_identity_rows_validated=True,
                          source_paths=sorted(str(path) for path in overlay_sources),
                          superseded_sources=sorted(str(path) for path in superseded_sources),
                          support_paths=sorted(str((root / path).resolve()) for path in source_hashes),
                          required_defines=sorted(required_defines), required_linked_globals=profile.get('required_linked_globals', []))


def bind(identity, source, symbol):
    catalog=json.loads((ROOT/'generated/function-catalog.json').read_text())
    rows=[r for r in catalog['functions'] if identity in (r['id'],r['name']) or identity in r['aliases']]
    if len(rows)!=1:
        raise ValueError('Function name is unknown or ambiguous; choose its unique catalog ID')
    if rows[0].get('quarantined'):
        raise ValueError('This legacy function entry is quarantined after fresh native analysis')
    source=(ROOT/source).resolve()
    if not source.is_relative_to(ROOT/'src') or source.suffix not in ('.cpp', '.c') or not source.is_file():
        raise ValueError('Select an existing C++ source under src')
    path=ROOT/'source-units.json';document=json.loads(path.read_text())
    if any(u['function_id']==rows[0]['id'] or u['symbol']==symbol for u in document['units']):
        raise ValueError('Function/source symbol already has an association')
    document['units'].append(dict(source=source.relative_to(ROOT).as_posix(),symbol=symbol,function_id=rows[0]['id']))
    path.write_text(json.dumps(document,indent=2)+'\n')
    print(f'Bound {symbol} to {rows[0]["name"]} ({rows[0]["id"]}); compile to derive layout')


def bind_import(identity,symbol):
    catalog=json.loads((ROOT/'generated/function-catalog.json').read_text())
    rows=[r for r in catalog['functions']+catalog.get('symbols',[]) if identity in (r['id'],r['name']) or identity in r['aliases']]
    if len(rows)!=1:
        raise ValueError('Dependency name is unknown or ambiguous; choose its catalog ID')
    if rows[0].get('quarantined'):
        raise ValueError('This legacy dependency entry is quarantined after fresh native analysis')
    path=ROOT/'source-units.json';document=json.loads(path.read_text())
    imports=document.setdefault('imports',[])
    if any(i['symbol']==symbol for i in imports):
        raise ValueError('Import alias already exists')
    imports.append(dict(symbol=symbol,symbol_id=rows[0]['id']))
    path.write_text(json.dumps(document,indent=2)+'\n')
    print(f'Bound native dependency {symbol} to {rows[0]["id"]}')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
    p=subs.add_parser('bind');p.add_argument('function');p.add_argument('--source',type=Path,required=True);p.add_argument('--symbol',required=True)
    p=subs.add_parser('bind-import');p.add_argument('identity');p.add_argument('--symbol',required=True)
    p=subs.add_parser('list');p.add_argument('query',nargs='?',default='');p.add_argument('--kind',choices=('function','symbol','all'),default='function')
    args=parser.parse_args()
    if args.command=='bind':bind(args.function,args.source,args.symbol)
    elif args.command=='bind-import':bind_import(args.identity,args.symbol)
    else:
        doc=json.loads((ROOT/'generated/function-catalog.json').read_text())
        rows=(doc['functions'] if args.kind in ('function','all') else [])+(doc.get('symbols',[]) if args.kind in ('symbol','all') else [])
        for row in rows:
            if row.get('quarantined'):
                continue
            if args.query.casefold() in (row['id']+' '+row['name']+' '+' '.join(row['aliases'])).casefold():
                print(row['id'],row['name'])
