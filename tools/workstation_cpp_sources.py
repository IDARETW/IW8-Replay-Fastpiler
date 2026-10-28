"""Persistent, image-scoped C++ recovery index; the analysis database stays read-only.

Generation and compiler acceptance are separate. An incomplete decompilation is
editable recovery work, never an automatically installed native replacement.
"""
from __future__ import annotations

from contextlib import closing
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time

import source_catalog
import recovered_cpp_names
from recovered_cpp_flow import FlowRecovery, IMPLEMENTATION as FLOW_IMPLEMENTATION

GENERATOR = 5
# Pin the implementation actually loaded by this process. A file edited while
# the server runs must not masquerade as a newly loaded recovery implementation.
IMPLEMENTATION = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
NAMING_IMPLEMENTATION = hashlib.sha256(Path(recovered_cpp_names.__file__).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def compiler_path():
    compiler_root = Path(os.environ.get('REPLAY_LLVM_ROOT', r'C:\Program Files\LLVM'))
    compiler = compiler_root / 'bin' / 'clang.exe'
    if not compiler.is_file():
        compiler = compiler_root / 'clang.exe'
    executable = str(compiler) if compiler.is_file() else shutil.which('clang')
    if not executable:
        raise ValueError('LLVM clang is required for source validation')
    return Path(executable).resolve()


@functools.lru_cache(maxsize=4)
def _compiler_digest(path, size, modified):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compiler_identity():
    compiler = compiler_path()
    stat = compiler.stat()
    return {'path': str(compiler),
            'sha256': _compiler_digest(str(compiler), stat.st_size, stat.st_mtime_ns)}


def compile_check(root, content, symbol, language='cpp', source_path=None):
    """Compile a real AMD64 COFF object, check ownership, retain no project edits."""
    import coff
    compiler = compiler_identity()
    with tempfile.TemporaryDirectory(prefix='replay-source-check-') as directory:
        path = Path(directory) / ('candidate.c' if language == 'c' else 'candidate.cpp')
        obj = Path(directory) / 'candidate.obj'
        path.write_text(content, encoding='utf-8', newline='\n')
        command = [compiler['path'], '--target=x86_64-pc-windows-msvc', '-x', 'c' if language == 'c' else 'c++',
                   '-std=c17' if language == 'c' else '-std=c++20', '-c', str(path),
                   '-o', str(obj), '-O2', '-ffreestanding', '-fno-stack-protector',
                   '-funwind-tables', '-ffunction-sections', '-fdata-sections',
                    '-Wall', '-Wextra', '-Werror', '-ffp-contract=off', '-I', str(Path(root) / 'src')]
        if source_path is not None:
            command += ['-I', str(Path(source_path).resolve().parent)]
        if language != 'c':
            command += ['-fno-exceptions', '-fno-rtti']
        # The same include snapshot is checked before and after compilation.
        # This includes standard and transitive headers, just like the build.
        import source_provenance
        dependency_file = Path(directory) / 'candidate.d'
        dependency_command = command + ['-M', '-MF', str(dependency_file), '-MT', 'replay_deps', '-Wno-unused-command-line-argument']
        dependency_result = subprocess.run(dependency_command, capture_output=True, text=True, timeout=30)
        if dependency_result.returncode:
            return {'compiled': False, 'diagnostics': (dependency_result.stdout + dependency_result.stderr)[:24000],
                    'language': language, 'target': 'x86_64-pc-windows-msvc'}
        dependencies = source_provenance.snapshots(source_provenance.parse_dependencies(dependency_file.read_text()))
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        diagnostics = (result.stdout + result.stderr).replace(str(path), 'candidate').strip()
        if result.returncode:
            return {'compiled': False, 'diagnostics': diagnostics[:24000],
                    'language': language, 'target': 'x86_64-pc-windows-msvc'}
        parsed = coff.read(obj)
        if dependencies != source_provenance.snapshots(source_provenance.parse_dependencies(dependency_file.read_text())):
            raise ValueError('Included headers changed during source validation; retry')
        if compiler_identity() != compiler:
            raise ValueError('Compiler changed during validation; check the current source again')
        coff_symbol = symbol
        if language != 'c':
            # Reuse the linker resolver: do not guess MSVC decorated names.
            from mapped_cpp_aliases import resolve_definition
            record = {'source': str(path), 'source_sha256': digest(content),
                      'object': str(obj), 'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
                       'compiler': compiler, 'command': command, 'dependencies': dependencies}
            try:
                definition = resolve_definition(record, symbol, parsed, Path(root))
            except ValueError as error:
                return {'compiled': False, 'diagnostics': str(error), 'language': language,
                        'target': 'x86_64-pc-windows-msvc'}
            if definition:
                coff_symbol = definition['coff_symbol']
        definitions = [s for s in parsed['symbols'].values()
                       if s['name'] == coff_symbol and s['section'] > 0 and s['storage'] == 2]
        if len(definitions) != 1:
            return {'compiled': False, 'diagnostics': 'The object must define the selected catalog symbol exactly once.',
                    'language': language, 'target': 'x86_64-pc-windows-msvc'}
        entry = definitions[0]
        section = parsed['sections'][entry['section'] - 1]
        if not section['flags'] & 0x20:
            raise ValueError('Selected symbol did not compile into executable code')
        return {'compiled': True, 'diagnostics': diagnostics, 'language': language,
                'target': 'x86_64-pc-windows-msvc', 'symbol': symbol, 'coff_symbol': coff_symbol,
                'compiler': compiler,
                 'dependencies': [item for item in dependencies if Path(item['path']) != path],
                'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
                'code_hex': section['data'][entry['value']:].hex(),
                'relocations': len(section['relocations']),
                'note': 'Object compilation proves compiler acceptance. ABI, linked references and runtime behavior require separate verification.'}


def render_cpp(identity, name, prototype, body, native=b'', symbol=None):
    """Keep recovered identifiers; only normalize nonsemantic IDA annotations."""
    symbol = symbol or identity
    primitive = r'(?:void|bool|char|signed char|unsigned char|short|unsigned short|int|unsigned int|long|unsigned long|__int64|unsigned __int64)'
    proto = str(prototype or '').strip().rstrip(';')
    match = re.fullmatch(rf'({primitive})\s+(?:(__fastcall|__cdecl)\s+)?([A-Za-z_]\w*)\s*\(\s*(?:void)?\s*\)', proto)
    # Exact native leaves need neither guessed globals nor guessed call types.
    constant = None
    if native in (b'\x33\xc0\xc3', b'\x31\xc0\xc3'):
        constant = 0
    elif len(native) == 6 and native[0] == 0xb8 and native[-1] == 0xc3:
        constant = int.from_bytes(native[1:5], 'little')
    if match and ((match[1] == 'void' and native == b'\xc3') or
                  (match[1] in ('int', 'unsigned int', '__int64', 'unsigned __int64', 'bool') and constant is not None)):
        return_type = match[1]
        expression = '' if return_type == 'void' else f'  return {constant}u;\n'
        if return_type == 'bool':
            # No silent conversion of a noncanonical BOOL/integer result.
            if constant not in (0, 1):
                match = None
            else:
                expression = f'  return {constant};\n'
        if match:
            code = f'extern "C" {return_type} {symbol}()\n{{\n{expression}}}\n'
            return code, 'native-leaf-candidate', [], True
    blockers = ['Recovered behavior and ABI have not been proven; native replacement is blocked.']
    if not body:
        blockers.append('The database has no recovered function body.')
    if not proto:
        blockers.append('The database has no recovered function signature.')
    if body and (recovered_cpp_names.count_jumpouts(body + proto) or
                 re.search(r'\b(?:__usercall|__userpurge)\b', recovered_cpp_names.code_text(body + proto))):
        blockers.append('Recovery contains an unresolved jump or custom calling convention.')
    # clean_pseudo is a similarity digest and can collapse many variables to vXXX.
    # Use the original body; never renumber an already-colliding cleaned body.
    source = str(body or '')
    source = re.sub(r'(?<=[(,])\s*[A-Za-z_]\w*\s*:(?!:)', ' ', source)
    source = re.sub(r'\b(?:__ptr64|__noreturn)\b', '', source)
    # IDA override types often omit the identifier: "void __fastcall(int a1)".
    # Bind the type without mistaking __fastcall for the function's name.
    unnamed = re.search(r'\b(__fastcall|__cdecl|__stdcall)\s*(?=\()', proto)
    if unnamed:
        proto = proto[:unnamed.end()] + ' ' + symbol + proto[unnamed.end():]
        opening = source.find('{')
        if opening >= 0:
            definition_name = re.search(r'\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$', source[:opening])
            if definition_name:
                old_name = definition_name[1]
                source = recovered_cpp_names.rename_identifier(source, old_name, symbol)
    signature = re.search(r'\b([A-Za-z_]\w*)\s*\(', proto)
    if signature:
        old_name = signature[1]
        proto = proto[:signature.start(1)] + symbol + proto[signature.end(1):]
        source = recovered_cpp_names.rename_identifier(source, old_name, symbol)
    else:
        blockers.append('The signature cannot be bound to a C++ identifier without recovery work.')
    # Diaphora/IDA exports can contain either a complete function definition or
    # only its body. Retain the recovered definition exactly once; prototype
    # disagreement is recovery evidence, not permission to invent arguments.
    opening = source.find('{')
    definition = source[:opening] if opening >= 0 else ''
    has_definition = bool(re.search(r'\b' + re.escape(symbol) + r'\s*\([^;{}]*\)\s*$', definition))
    if has_definition:
        clean_definition = re.sub(r'//[^\n]*|/\*.*?\*/', '', definition, flags=re.DOTALL)
        if re.sub(r'\s+', '', clean_definition) != re.sub(r'\s+', '', proto):
            blockers.append('The recovered definition and database prototype disagree; resolve the signature before compilation.')
    # Recovery diagnostics belong in the editor metadata, not the source text.
    code = 'extern "C"\n'
    if not has_definition:
        code += (proto + '\n' if proto else '/* Recover the C++ signature for ' + symbol + ' here. */\n')
    code += source + '\n' if source else '/* Recover the native function body here. */\n'
    return code, 'recovery-required', blockers, False


class CppSourceIndex:
    def __init__(self, sources):
        self.sources = sources
        self.path = sources.cache_root / 'generated-cpp.sqlite'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.native_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.worker = None
        self.flow_worker = None
        self.flow_retry_at = 0
        self.manifest = json.loads((sources.generated / 'manifest.json').read_text())
        catalog = sources._catalog or sources._load_catalog()
        self.image = catalog['image_sha256']
        self.rows = {row['id']: row for row in sources._rows() if row.get('kind', 'function') == 'function'}
        self.rvas = {row['rva']: row for row in self.rows.values()}
        self.symbols = sources.cpp_symbols(self.rows.values())
        self.namer = recovered_cpp_names.CppNames(sources._rows(), self.symbols, self.manifest['image_base'])
        self.naming_rows = sources._rows()
        self.flow = FlowRecovery(sources.root, self.image)
        self.flow.sync()
        self.leaf_checks = {}
        import coff
        self.object_reader_hash = hashlib.sha256(Path(coff.__file__).read_bytes()).hexdigest()
        self.addresses = None
        self.native_image = None
        self.native_sections = []
        self.signature = None
        self.progress = {'state': 'waiting', 'indexed': 0, 'total': len(self.rows), 'error': None}
        with closing(self.connect()) as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS recovered_cpp (
                    id TEXT PRIMARY KEY, input_hash TEXT NOT NULL, image_hash TEXT NOT NULL,
                    content TEXT NOT NULL, status TEXT NOT NULL, diagnostics TEXT NOT NULL,
                    updated REAL NOT NULL, generation INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS recovered_cpp_counts ON recovered_cpp(image_hash,generation,status);
            ''')
            db.commit()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        db.row_factory = sqlite3.Row
        # This is a disposable derived index. WAL/NORMAL keeps whole-row
        # publication atomic without flushing the disk for every generated row.
        db.execute('PRAGMA synchronous=NORMAL')
        return db

    def _verify_database(self, db):
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        expected = (self.sources._catalog or self.sources._load_catalog()).get('database_program_md5')
        if expected and 'program' in tables:
            values = db.execute('SELECT md5sum FROM program').fetchall()
            hashes = {value[0].hex() if isinstance(value[0], bytes) else str(value[0]).lower() for value in values}
            if hashes != {expected.lower()}:
                raise ValueError('C++ recovery database belongs to another executable')
        return tables

    def _native(self, row, size):
        if not 0 < size <= 6:
            return b''
        with self.native_lock:
            return self._native_locked(row, size)

    def _native_locked(self, row, size):
        if self.native_image is None:
            config_path = self.sources.root / 'replay-project.local.json'
            cfg = json.loads(config_path.read_text()) if config_path.is_file() else {}
            game = Path(os.environ.get('REPLAY_GAME_ROOT') or cfg.get('game') or self.sources.sqlite_path.parent)
            exe = game / 'game_dx12_ship_replay.exe'
            if not exe.is_file():
                self.native_image = b''
                return b''
            raw = exe.read_bytes()
            if hashlib.sha256(raw).hexdigest() != self.image:
                raise ValueError('Native leaf recovery executable hash differs from the pinned image')
            pe = struct.unpack_from('<I', raw, 0x3c)[0]
            if raw[pe:pe+4] != b'PE\0\0':
                raise ValueError('Invalid native executable')
            count, optional_size = struct.unpack_from('<H', raw, pe + 6)[0], struct.unpack_from('<H', raw, pe + 20)[0]
            for n in range(count):
                at = pe + 24 + optional_size + n * 40
                _virtual_size, rva, raw_size, offset = struct.unpack_from('<IIII', raw, at + 8)
                self.native_sections.append((rva, raw_size, offset))
            self.native_image = raw
        for rva, raw_size, offset in self.native_sections:
            relative = row['rva'] - rva
            if 0 <= relative and relative + size <= raw_size:
                return self.native_image[offset+relative:offset+relative+size]
        return b''

    def _read(self, db, row, tables):
        columns = {r[1] for r in db.execute('PRAGMA table_info(functions)')}
        selected = [c for c in ('name', 'prototype', 'prototype2', 'pseudocode', 'size') if c in columns]
        value = None
        # The recovered catalog carries SQLite's indexed primary key. Verify
        # its native address before using it; old catalogs retain the fallback.
        if 'id' in columns and row.get('database_id') is not None:
            found = db.execute('SELECT address,' + ','.join(selected) + ' FROM functions WHERE id=?',
                               (row['database_id'],)).fetchone()
            if found and source_catalog.parse_integer(found[0], 'address') - self.manifest['image_base'] == row['rva']:
                value = found[1:]
        if value is None and self.addresses is None:
            addresses = {}
            for (address,) in db.execute('SELECT address FROM functions'):
                try:
                    rva = source_catalog.parse_integer(address, 'address') - self.manifest['image_base']
                except ValueError:
                    continue
                addresses[rva] = address
            self.addresses = addresses
        address = self.addresses.get(row['rva']) if self.addresses is not None else None
        if value is None and address is None:
            found = db.execute('SELECT address FROM functions WHERE address IN (?,?,?)',
                               (str(self.manifest['image_base'] + row['rva']),
                                hex(self.manifest['image_base'] + row['rva']),
                                f"0x{self.manifest['image_base'] + row['rva']:X}")).fetchone()
            address = found[0] if found else None
        if value is None:
            value = db.execute('SELECT ' + ','.join(selected) + ' FROM functions WHERE address=?', (address,)).fetchone() if address is not None else None
        result = dict(zip(selected, value)) if value is not None else {}
        if 'replay_ida_function_text' in tables:
            override = db.execute(self._override_query(db, tables) + ' WHERE t.function_rva IN (?,?)',
                                  (row['rva'], hex(row['rva']))).fetchone()
            if override:
                self._apply_override(result, override)
        if 'replay_function_export_queue' in tables:
            queued = db.execute('SELECT * FROM replay_function_export_queue WHERE function_rva IN (?,?)',
                                (row['rva'], hex(row['rva']))).fetchone()
            if queued:
                keys = [column[1] for column in db.execute('PRAGMA table_info(replay_function_export_queue)')]
                result['export_queue'] = dict(zip(keys, queued))
        return result

    @staticmethod
    def _override_query(db, tables):
        columns = {r[1] for r in db.execute('PRAGMA table_info(replay_ida_function_text)')}
        joined = 'event_id' in columns and 'replay_ida_events' in tables
        return ('SELECT t.function_rva,t.pseudocode,' + ('t.prototype' if 'prototype' in columns else 'NULL') +
                (',e.payload FROM replay_ida_function_text t LEFT JOIN replay_ida_events e ON e.event_id=t.event_id'
                 if joined else ',NULL FROM replay_ida_function_text t'))

    def _apply_override(self, data, override):
        rva, body, proto, payload = override
        if body:
            data['pseudocode'] = body
            data['live_text_override'] = True
        if proto:
            data['prototype'] = proto
        if not body or not payload:
            return
        event = json.loads(payload)
        expected = (self.sources._catalog or self.sources._load_catalog()).get('database_program_md5')
        # The event and text row commit together. A later prototype-only event
        # cannot lend another body's counter ownership to the retained text.
        if (expected and event.get('input_md5') == expected and event.get('kind') == 'text'
                and event.get('rva') == source_catalog.parse_integer(rva, 'override RVA')
                and event.get('pseudocode') == body and event.get('prototype') == data.get('prototype')):
            data['reference_names'] = event.get('reference_names') or {}

    def fingerprint(self):
        return digest(json.dumps([GENERATOR, IMPLEMENTATION, self.object_reader_hash,
                                  NAMING_IMPLEMENTATION, FLOW_IMPLEMENTATION, self.flow.baseline,
                                  compiler_identity()], sort_keys=True))

    def _store(self, db, row, data, fingerprint=None):
        recovery = self.flow.get(row['rva'], data)
        if recovery:
            data = dict(data, pseudocode=recovery['pseudocode'])
            # Hex-Rays' type string omits the function identifier. Use the
            # complete recovered definition for the corresponding signature.
            definition = recovery['pseudocode'].split('{', 1)[0].strip()
            data['prototype'] = re.sub(r'//[^\n]*|/\*.*?\*/', '', definition, flags=re.S).strip()
        name = data.get('name') or row.get('name') or row['id']
        native = self._native(row, int(data.get('size') or 0))
        fingerprint = fingerprint or self.fingerprint()
        symbol = self.symbols.get(row['id'], row['id'])
        # Private recovery records belong to their own IDB name generation.
        # Fresh Diaphora tokens use its verified export map, never old aliases.
        live_override = bool(data.get('live_text_override')) and not recovery
        naming = dict(use_export_names=bool(row.get('decompiler_name')) and not recovery and not live_override,
                      reference_names=recovery.get('reference_names') if recovery else data.get('reference_names'),
                      allow_counter_aliases=not live_override and not recovery)
        prototype = self.namer.rewrite(str(data.get('prototype') or ''), **naming)
        body = self.namer.rewrite(str(data.get('pseudocode') or ''), **naming)
        raw = json.dumps([fingerprint, self.image, row['id'], symbol, name, prototype, body, native.hex(),
                          data.get('export_queue'), live_override], ensure_ascii=False)
        input_hash = digest(raw)
        previous = db.execute('SELECT * FROM recovered_cpp WHERE id=? AND image_hash=? AND generation=?',
                              (row['id'], self.image, GENERATOR)).fetchone()
        if previous is not None and previous['input_hash'] == input_hash:
            return dict(previous, symbol=symbol)
        content, status, diagnostics, eligible = render_cpp(row['id'], str(name), prototype, body, native, symbol)
        if 'func_unresolved_nullsub_' in body or 'func_unresolved_j_nullsub_' in body:
            diagnostics.append('This IDA text has no matching native reference identity for a generated counter name; refresh its pseudocode in the updated naming plugin or private recovery worker.')
        if data.get('export_queue') and not body:
            queued = data['export_queue']
            detail = 'Native C++ recovery is queued: ' + str(queued.get('reason') or queued.get('status'))
            diagnostics.append(detail)
        if eligible:
            # Identical leaf bodies have no relocations or address-dependent
            # state. Reuse their actual object-byte check within this process.
            key = fingerprint + content.replace(symbol, 'replay_leaf')
            checked = self.leaf_checks.get(key)
            if checked is None:
                checked = compile_check(self.sources.root, content, symbol, 'cpp')
                self.leaf_checks[key] = checked
            same_bytes = checked.get('code_hex') == native.hex()
            equivalent_zero = native.hex() in ('33c0c3', '31c0c3') and checked.get('code_hex') in ('33c0c3', '31c0c3')
            if checked['compiled'] and (same_bytes or equivalent_zero) and checked['relocations'] == 0:
                status = 'byte-equivalent-leaf' if same_bytes else 'instruction-equivalent-leaf'
                diagnostics = ['C++ compiled to the identical complete native leaf bytes.' if same_bytes else
                               'Both complete native leaves are xor eax,eax; ret. Operand-direction encodings differ; register and flag effects are identical.']
            else:
                status = 'recovery-required'
                diagnostics = [checked['diagnostics'] or 'Generated C++ object differs from the native leaf.']
        if recovery:
            diagnostics.append('Native control flow was regenerated from verified instructions and function ownership; recovered types and ABI still require validation.')
        record = (row['id'], input_hash, self.image, content, status, json.dumps(diagnostics), time.time(), GENERATOR)
        db.execute('INSERT OR REPLACE INTO recovered_cpp VALUES (?,?,?,?,?,?,?,?)', record)
        return dict(zip(('id','input_hash','image_hash','content','status','diagnostics','updated','generation'), record), symbol=symbol)

    def get(self, row):
        # Only one indexed source row is read on an open, even during indexing.
        with self.lock, closing(sqlite3.connect(source_catalog.readonly_uri(self.sources.sqlite_path), uri=True)) as source:
            source.execute('BEGIN')
            tables = self._verify_database(source)
            value = self._read(source, row, tables)
            self.flow.sync()
            self.symbols[row['id']] = self.sources.cpp_symbols([row])[row['id']]
            rows = self.sources._rows()
            if rows is not self.naming_rows:
                self.symbols = self.sources.cpp_symbols(self.rows.values())
                self.namer = recovered_cpp_names.CppNames(rows, self.symbols, self.manifest['image_base'])
                self.naming_rows = rows
            with closing(self.connect()) as cache:
                record = self._store(cache, row, value)
                cache.commit()
        native_recovery = self.flow.get(row['rva'], value)
        display_row = dict(row, name=value.get('name') or row.get('name', ''))
        return {'id': row['id'], 'name': self.sources._display_name(display_row),
                'variant': 'cpp', 'language': 'cpp', 'content': record['content'],
                'revision': digest(record['content']), 'symbol': record['symbol'],
                'source': f"src/workstation_{row['id']}.cpp", 'editable': True,
                'compilable': record['status'] in ('byte-equivalent-leaf', 'instruction-equivalent-leaf'),
                'recovery': {'status': record['status'], 'diagnostics': json.loads(record['diagnostics']),
                             'input_hash': record['input_hash'], 'generated_at': record['updated']},
                'provenance': {'basis': 'Indexed recovered C++', 'generator': GENERATOR,
                               'control_flow': ({'status': native_recovery['status'],
                                                 'native_spans': native_recovery.get('repaired_native_spans', []),
                                                 'source_hash': native_recovery['source_hash']} if native_recovery else None),
                               'export_queue': value.get('export_queue'),
                               'database_image_sha256': self.image,
                               'abi_confidence': record['status'] if record['status'] in ('byte-equivalent-leaf', 'instruction-equivalent-leaf') else 'recovery incomplete; replacement blocked'}}

    def refresh(self):
        from workstation_sources import _sqlite_file_signature
        signature = _sqlite_file_signature(self.sources.sqlite_path)
        fingerprint = self.fingerprint()
        self.flow.sync()
        stamp = digest(repr(signature) + fingerprint + repr(self.flow.signature))
        self.rows = {row['id']: row for row in self.sources._rows() if row.get('kind', 'function') == 'function'}
        self.rvas = {row['rva']: row for row in self.rows.values()}
        self.symbols = self.sources.cpp_symbols(self.rows.values())
        self.namer = recovered_cpp_names.CppNames(self.sources._rows(), self.symbols, self.manifest['image_base'])
        self.naming_rows = self.sources._rows()
        self.progress['total'] = len(self.rows)
        with closing(self.connect()) as cache:
            completed = cache.execute("SELECT value FROM meta WHERE key='complete_signature'").fetchone()
            count = cache.execute('SELECT count(*) FROM recovered_cpp WHERE image_hash=? AND generation=?', (self.image, GENERATOR)).fetchone()[0]
            if completed and completed[0] == stamp and count == len(self.rows):
                self.signature = signature
                self.progress.update(state='ready', indexed=len(self.rows), error=None)
                return
        self.progress.update(state='indexing', indexed=0, error=None)
        with closing(sqlite3.connect(source_catalog.readonly_uri(self.sources.sqlite_path), uri=True)) as source:
            source.execute('BEGIN')
            tables = self._verify_database(source)
            columns = {r[1] for r in source.execute('PRAGMA table_info(functions)')}
            selected = [c for c in ('address', 'name', 'prototype', 'pseudocode', 'size') if c in columns]
            overrides = {}
            export_queue = {}
            if 'replay_function_export_queue' in tables:
                queue_columns = [column[1] for column in source.execute('PRAGMA table_info(replay_function_export_queue)')]
                for values in source.execute('SELECT * FROM replay_function_export_queue'):
                    queued = dict(zip(queue_columns, values))
                    export_queue[source_catalog.parse_integer(queued['function_rva'], 'queued function RVA')] = queued
            if 'replay_ida_function_text' in tables:
                for rva, body, proto, payload in source.execute(self._override_query(source, tables)):
                    overrides[source_catalog.parse_integer(rva, 'override RVA')] = (rva, body, proto, payload)
            addresses = {}
            seen = set()
            with closing(self.connect()) as cache:
                for values in source.execute('SELECT ' + ','.join(selected) + ' FROM functions'):
                    if self.stop_event.is_set():
                        return
                    data = dict(zip(selected, values))
                    try:
                        rva = source_catalog.parse_integer(data['address'], 'address') - self.manifest['image_base']
                    except ValueError:
                        continue
                    addresses[rva] = data['address']
                    row = self.rvas.get(rva)
                    if row is None:
                        continue
                    if rva in overrides:
                        self._apply_override(data, overrides[rva])
                    if rva in export_queue:
                        data['export_queue'] = export_queue[rva]
                    # Background rendering and compiler subprocesses must not
                    # hold the foreground-open lock. Separate connections and
                    # atomic WAL rows allow readers to proceed independently.
                    self._store(cache, row, data, fingerprint)
                    seen.add(row['id'])
                    self.progress['indexed'] = len(seen)
                    # Each row is an atomic WAL publication, including on opens.
                    if len(seen) % 100 == 0:
                        cache.commit()
                for row in self.rows.values():
                    if self.stop_event.is_set():
                        return
                    if row['id'] not in seen:
                        self._store(cache, row, {}, fingerprint)
                # A baseline migration can retire false function entries.
                # Derived rows for those entries must not inflate readiness or
                # recovery counts after they leave the active source catalog.
                cache.execute('CREATE TEMP TABLE active_cpp_rows(id TEXT PRIMARY KEY)')
                cache.executemany('INSERT INTO active_cpp_rows VALUES(?)', ((identity,) for identity in self.rows))
                cache.execute('DELETE FROM recovered_cpp WHERE id NOT IN (SELECT id FROM active_cpp_rows)')
                cache.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('complete_signature', stamp))
                cache.commit()
                with self.lock:
                    self.addresses = addresses
        self.signature = signature
        self.progress.update(state='ready', indexed=len(self.rows), completed_at=time.time())

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        def run():
            while not self.stop_event.is_set():
                try:
                    self.refresh()
                    self.start_flow_recovery()
                except Exception as error:
                    self.progress.update(state='error', error=str(error))
                self.stop_event.wait(10)
        self.worker = threading.Thread(target=run, name='Replay-CPP-index', daemon=True)
        self.worker.start()

    def start_flow_recovery(self):
        config = self.sources.root / 'replay-project.local.json'
        settings = json.loads(config.read_text()).get('cpp_recovery', {}) if config.is_file() else {}
        if not settings.get('enabled') or time.monotonic() < self.flow_retry_at:
            return
        if self.flow_worker and self.flow_worker.poll() is None:
            return
        self.flow_retry_at = time.monotonic() + 60
        log = self.flow.directory / 'worker.log'
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open('a', encoding='utf-8') as stream:
            flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            self.flow_worker = subprocess.Popen(
                [sys.executable, '-B', str(self.sources.root / 'tools' / 'run_cpp_flow_recovery.py'),
                 '--root', str(self.sources.root)], cwd=self.sources.root,
                stdout=stream, stderr=stream, creationflags=flags)

    def status(self):
        with closing(self.connect()) as cache:
            counts = dict(cache.execute('SELECT status,count(*) FROM recovered_cpp WHERE image_hash=? AND generation=? GROUP BY status', (self.image, GENERATOR)))
        return {**self.progress, 'counts': counts, 'generator': GENERATOR,
                'control_flow': self.flow.status(),
                'poll_seconds': 10, 'image_sha256': self.image,
                'language': 'cpp', 'note': 'Cached recovery is not proof of full native C++ reconstruction.'}

    def close(self):
        self.stop_event.set()
        if self.worker:
            self.worker.join(timeout=3)
