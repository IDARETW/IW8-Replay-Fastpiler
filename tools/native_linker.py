"""Versioned binary bridge to Replay's C++ source linker.

Python discovers recovered source identities and invokes compilers. C++ plans
placement/relaxation, resolves symbols, relocates code/data, rebuilds PE loader
tables and emits the executable. Python is an explicit differential oracle.
"""
from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import time

from source_provenance import snapshots, parse_dependencies

SOURCE = Path(__file__).parent / 'native' / 'replay_linker.cpp'
LIBRARIES = {}  # Windows keeps loaded DLLs open; retain each build-owned library.


class SectionView(ctypes.Structure):
    _fields_ = [('rva', ctypes.c_uint64), ('size', ctypes.c_uint64), ('data', ctypes.c_void_p)]


def build_library(output, llvm):
    source, compiler = SOURCE.resolve(), (Path(llvm) / 'clang++.exe').resolve()
    target = Path(output).resolve() / 'replay-linker.dll'
    key = str(target)
    cached = LIBRARIES.get(key)
    if cached:
        library, identity = cached
        if (snapshots([Path(row['path']) for row in identity['inputs']]) != identity['inputs'] or
                hashlib.sha256(target.read_bytes()).hexdigest() != identity['sha256']):
            raise RuntimeError('Loaded C++ linker backend changed; start a fresh build directory')
        return library, identity
    args = [str(compiler), '--target=x86_64-pc-windows-msvc', '-std=c++20', '-O2',
            '-shared', '-fno-rtti', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(target),
            '-Wl,/NOIMPLIB']
    dependency_file = target.with_suffix('.d')
    dependency_args = [arg for index, arg in enumerate(args)
                       if arg != '-o' and (index == 0 or args[index - 1] != '-o')]
    dependency_args += ['-M', '-MT', 'replay_deps', '-MF', str(dependency_file), '-Wno-unused-command-line-argument']
    result = subprocess.run(dependency_args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Cannot discover C++ linker backend headers:\n' + result.stderr)
    paths = sorted(set([source, compiler, Path(__file__).resolve()] + parse_dependencies(dependency_file.read_text())))
    inputs = snapshots(paths)
    args += ['-MD', '-MT', 'replay_deps', '-MF', str(dependency_file)]
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('C++ linker backend compilation failed:\n' + result.stdout + result.stderr)
    after_paths = sorted(set([source, compiler, Path(__file__).resolve()] + parse_dependencies(dependency_file.read_text())))
    if after_paths != paths or snapshots(paths) != inputs:
        raise RuntimeError('C++ linker backend inputs changed during compilation')
    identity = {'language': 'cpp', 'abi': 1, 'source': str(source), 'inputs': inputs,
                'library': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                'command': args}
    library = ctypes.CDLL(str(target))
    library.replay_linker_abi.restype = ctypes.c_uint32
    if library.replay_linker_abi() != 1:
        raise RuntimeError('C++ linker backend ABI differs')
    library.replay_linker_create.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64]
    library.replay_linker_create.restype = ctypes.c_void_p
    library.replay_linker_destroy.argtypes = [ctypes.c_void_p]
    library.replay_linker_destroy.restype = None
    library.replay_linker_interior_uses.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    library.replay_linker_interior_uses.restype = ctypes.c_uint64
    library.replay_linker_relocate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
        ctypes.c_int64, ctypes.c_int64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    library.replay_linker_relocate.restype = ctypes.c_int
    library.replay_linker_references.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
        ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint64,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
    library.replay_linker_references.restype = ctypes.c_int
    library.replay_linker_stages_abi.restype = ctypes.c_uint32
    if library.replay_linker_stages_abi() != 1:
        raise RuntimeError('C++ linker stage ABI differs')
    library.replay_linker_stage.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_void_p, ctypes.c_uint64]
    library.replay_linker_stage.restype = ctypes.c_int
    library.replay_linker_release.argtypes = [ctypes.c_void_p]
    library.replay_linker_release.restype = None
    identity['stages_abi'] = 1
    LIBRARIES[str(target)] = (library, identity)
    return library, identity


class NativeLinker:
    def __init__(self, layout, manifest, output, llvm, compare=False):
        self.library, self.identity = build_library(output, llvm)
        self.layout, self.manifest = layout, manifest
        self.compare = compare
        self.handle = None
        self.symbol_cache = {}
        self.target_cache = {}
        self.bound_symbols = None
        self.error = ctypes.create_string_buffer(2048)
        self.metrics = {'coff_calls': 0, 'coff_relocations': 0, 'reference_calls': 0,
                        'native_seconds': 0.0, 'reference_seconds': 0.0, 'compared': compare}
        self.update_sections([])

    def close(self):
        if self.handle:
            self.sync_interior_uses()
            self.library.replay_linker_destroy(self.handle)
            self.handle = None

    def sync_interior_uses(self):
        if not self.handle:
            return
        used = (ctypes.c_uint64 * len(self.layout.interior_rvas))()
        count = self.library.replay_linker_interior_uses(self.handle, used, len(used))
        if count > len(used):
            raise ValueError('Native instruction label receipt exceeds its proven mapping set')
        for rva in used[:count]:
            self.layout.interior_uses[rva] = self.layout.interior_rvas[rva]

    def update_sections(self, sections):
        layout, manifest = self.layout, self.manifest
        replacements = sorted(layout.replacements, key=lambda item: item['begin'])
        interiors = sorted(layout.interior_rvas.items())
        plan = bytearray(struct.pack('<8sIqqqqIIII', b'RPLAYLNK', 1, manifest['image_base'],
            manifest['optional']['SizeOfImage'], layout.data_start, layout.section_delta,
            len(layout.points), len(replacements), len(interiors), len(sections)))
        for point, delta in zip(layout.points, layout.deltas[1:]):
            plan.extend(struct.pack('<qq', point, delta))
        for item in replacements:
            plan.extend(struct.pack('<qqI', item['begin'], item['end'], bool(item.get('retired'))))
        for original, item in interiors:
            plan.extend(struct.pack('<qq', original, item['mapped_rva']))
        for section in sections:
            plan.extend(struct.pack('<qq', section['rva'], section['virtual_size']))
        handle = self.library.replay_linker_create(bytes(plan), len(plan), self.error, len(self.error))
        if not handle:
            raise ValueError(self.error.value.decode('utf-8', 'replace'))
        self.close()
        self.handle = handle
        self.bound_symbols = None
        self.target_cache.clear()

    def _python_targets(self, obj, symbols):
        # Resolve a COFF symbol once per object, rather than once per use.
        # Unreferenced unresolved declarations remain legal, as in COFF.
        stamp = tuple((s.get('rva'), s.get('original_rva'), s.get('discarded'),
                       s.get('selected', {}).get('rva'), s.get('selected', {}).get('original_rva')) for s in obj['sections'])
        cached = self.symbol_cache.get(id(obj))
        if cached is not None and cached[0] == stamp and cached[2] is obj:
            return cached[1]
        targets = bytearray((max(obj['symbols'], default=-1) + 1) * 16)
        for index, original in obj['symbols'].items():
            symbol, visited = original, set()
            cursor = index
            while 'weak' in symbol and symbol['name'] not in symbols:
                if cursor in visited:
                    symbol = None
                    break
                visited.add(cursor)
                cursor = symbol['weak']['fallback']
                symbol = obj['symbols'][cursor]
            if symbol is None:
                continue
            flags = 1
            if symbol['section'] > 0:
                defined = obj['sections'][symbol['section'] - 1]
                if defined.get('discarded'):
                    defined = defined.get('selected')
                if defined is None:
                    continue
                value = defined.get('original_rva', defined.get('rva'))
                if value is None:
                    continue
                value += symbol['value']
                flags |= 4 if 'original_rva' in defined else 0
            elif symbol['section'] == -1:
                value = symbol['value']
                flags |= 2
            else:
                name = symbol['name']
                if name.startswith('replay_rva_'):
                    value = int(name[11:], 16)
                    if not 0 <= value < self.manifest['optional']['SizeOfImage']:
                        continue
                    flags |= 4
                elif name in symbols:
                    original_rvas = self.manifest.get('native_symbol_rvas', {})
                    if name in original_rvas:
                        value = original_rvas[name]
                        flags |= 4
                    else:
                        value = symbols[name]
                else:
                    continue
            struct.pack_into('<qI4x', targets, index * 16, value, flags)
        result = bytes(targets)
        self.symbol_cache[id(obj)] = (stamp, result, obj)
        return result

    def stage(self, number, wire):
        return call_stage(self.library, number, wire, self.handle, self.metrics)

    def _targets(self, obj, symbols):
        if self.bound_symbols is not symbols:
            wire = Wire()
            wire.bindings(self.manifest.get('native_symbol_rvas', {}))
            wire.bindings(symbols)
            self.stage(9, wire)
            self.bound_symbols = symbols
            self.target_cache.clear()
        stamp = tuple((s.get('rva'), s.get('original_rva'), s.get('discarded'),
                       s.get('selected', {}).get('rva'), s.get('selected', {}).get('original_rva')) for s in obj['sections'])
        cached = self.target_cache.get(id(obj))
        if cached and cached[0] == stamp and cached[2] is obj:
            return cached[1]
        wire = Wire()
        wire.put('I', len(obj['sections']))
        for section in obj['sections']:
            wire.put('qqqqI', section.get('rva', -1), section.get('original_rva', -1),
                     section.get('selected', {}).get('rva', -1), section.get('selected', {}).get('original_rva', -1),
                     bool(section.get('discarded')))
        wire.put('I', len(obj['symbols']))
        for index, symbol in obj['symbols'].items():
            wire.put('I', index)
            wire.text(symbol['name'])
            wire.put('qii', symbol['value'], symbol['section'], symbol.get('weak', {}).get('fallback', -1))
        result = self.stage(3, wire)
        if self.compare and result != self._python_targets(obj, symbols):
            raise ValueError(f"Native/Python symbol-resolution parity failed: {obj['path']}")
        self.target_cache[id(obj)] = (stamp, result, obj)
        return result

    def place(self, objects, native, grow, reference):
        from coff import align
        import copy
        expected_objects = copy.deepcopy(objects) if self.compare else None
        manifest, layout = self.manifest, self.layout
        text = manifest['sections'][0]
        data = next(s for s in manifest['sections'] if s['name'] == '.data')
        wire = Wire()
        wire.put('IqqqqqQ', grow, align(layout.map(text['rva'] + text['virtual_size']), 16),
                 layout.map(manifest['sections'][1]['rva']), layout.map(manifest['optional']['SizeOfImage']),
                 align(layout.map(data['rva'] + data['virtual_size']), 8),
                 layout.map(next(s['rva'] for s in manifest['sections'] if s['rva'] > data['rva'])),
                 manifest['optional']['SectionAlignment'])
        wire.replacements(manifest['replacements'], layout.sizes)
        wire.bindings(native)
        flat = [s for obj in objects for s in obj['sections']]
        wire.put('I', len(flat))
        for obj in objects:
            for index, section in enumerate(obj['sections'], 1):
                wire.text(section['name'])
                wire.put('QII', len(section['data']), section['flags'], bool(section.get('discarded')))
                definitions = [s for s in obj['symbols'].values() if s['section'] == index and s['storage'] == 2]
                wire.put('I', len(definitions))
                for symbol in definitions:
                    wire.text(symbol['name'])
                    wire.put('QI', symbol['value'], symbol.get('kind', 0))
        result = Wire(self.stage(2, wire))
        tail, bss_tail, appended, code_size, data_rva, writable_size = result.take('qqqQQQ')
        if result.take('I') != len(flat):
            raise ValueError('Native placement returned a different section count')
        modes = ('', 'original_function', 'text_tail', 'new_code', 'native_bss_tail', 'new_data')
        for section in flat:
            rva, mode, owner = result.take('qIi')
            if mode:
                section.update(rva=rva, placement=modes[mode])
                if owner >= 0:
                    row = manifest['replacements'][owner]
                    section.update(replacement_owner=row['symbol'], replacement_begin=row['begin'], replacement_end=row['end'])
        result.finish()
        symbols = {name: layout.map(value) for name, value in native.items()}
        placements = []
        for obj in objects:
            for symbol in obj['symbols'].values():
                if symbol['section'] > 0 and symbol['storage'] == 2:
                    section = obj['sections'][symbol['section'] - 1]
                    if 'placement' in section and not section.get('discarded'):
                        rva = section['rva'] + symbol['value']
                        symbols[symbol['name']] = rva
                        placements.append(dict(symbol=symbol['name'], rva=rva,
                                               size=len(section['data']), placement=section['placement']))
        extras = []
        if code_size:
            extras.append(dict(name='.cpp', rva=appended, virtual_size=code_size, flags=0x60000020, data=bytearray(code_size)))
        if writable_size:
            extras.append(dict(name='.rwcpp', rva=data_rva, virtual_size=writable_size, flags=0xc0000040, data=bytearray(writable_size)))
        actual = symbols, placements, extras, tail, bss_tail
        if self.compare:
            expected = reference(expected_objects, native, manifest, layout, grow)
            if actual != expected or objects != expected_objects:
                raise ValueError('Native/Python placement parity failed')
        return actual

    def tables(self, sections, original_unwind, compiled_unwind, base_relocations):
        wire = Wire()
        wire.put('I', self.manifest['optional']['SectionAlignment'])
        wire.directories(self.manifest['directories'])
        wire.sections(sections)
        wire.bytes(original_unwind)
        wire.bytes(compiled_unwind)
        wire.put('I', len(base_relocations))
        for at in sorted(base_relocations):
            wire.put('Q', at)
        result = Wire(self.stage(4, wire))
        removed = result.take('I')
        retained = [result.take('III') for _ in range(result.take('I'))]
        directories = result.read_directories()
        linked = result.read_sections()
        result.finish()
        return removed, retained, directories, linked

    def retained_unwind(self, data):
        wire = Wire()
        wire.bytes(data)
        result = Wire(self.stage(11, wire))
        removed = result.take('I')
        retained = [result.take('III') for _ in range(result.take('I'))]
        result.finish()
        return removed, retained

    def relative_table(self, item):
        wire = Wire()
        wire.put('qqIIII', item['target'], item['base'], item.get('width', 4), item['shift'],
                 item['subtract'], item.get('signed', True))
        result = self.stage(5, wire)
        if self.compare:
            from layout import encode_relative_table
            expected = encode_relative_table(item, self.layout.resolve(item['target']), self.layout.map(item['base']))
            if result != expected:
                raise ValueError('Native/Python switch-table parity failed')
        return result

    def relocate(self, obj, section, symbols, manifest, statistics, base_relocations, layout=None, *, reference=None):
        if layout is not self.layout or manifest is not self.manifest:
            raise ValueError('Native linker ownership/layout context differs')
        targets = self._targets(obj, symbols)
        started = time.perf_counter()
        relocations = section.get('relocation_bytes')
        if relocations is None:
            relocations = b''.join(struct.pack('<IIH', *r) for r in section['relocations'])
        data = bytearray(section['data'])
        buffer = (ctypes.c_ubyte * len(data)).from_buffer(data)
        counters = (ctypes.c_uint64 * 12)()
        base_sites = (ctypes.c_uint64 * (len(relocations) // 10))()
        base_count = ctypes.c_uint64()
        okay = self.library.replay_linker_relocate(self.handle, buffer, len(data), section['rva'],
            section.get('original_rva', -1), relocations, len(relocations), targets, len(targets),
            counters, base_sites, ctypes.byref(base_count), self.error, len(self.error))
        if not okay:
            raise ValueError(f"{obj['path']}:{section['name']}: {self.error.value.decode('utf-8', 'replace')}")
        counts = {f'coff_type_{k}': counters[k] for k in range(1, 12) if counters[k]}
        bases = set(base_sites[:base_count.value])
        self.metrics['native_seconds'] += time.perf_counter() - started
        self.metrics['coff_calls'] += 1
        self.metrics['coff_relocations'] += sum(counts.values())
        if self.compare:
            from collections import Counter
            expected_counts, expected_bases = Counter(), set()
            started = time.perf_counter()
            expected = reference(obj, section, symbols, manifest, expected_counts, expected_bases, layout)
            self.metrics['reference_seconds'] += time.perf_counter() - started
            if data != expected or counts != dict(expected_counts) or bases != expected_bases:
                raise ValueError(f"Native/Python relocation parity failed for {obj['path']}:{section['name']}")
        statistics.update(counts)
        base_relocations.update(bases)
        return data

    def references(self, sections, references, metadata=False, skipped=()):
        started = time.perf_counter()
        buffers = [(ctypes.c_ubyte * len(s['data'])).from_buffer(s['data']) for s in sections]
        views = (SectionView * len(sections))(*(SectionView(s['rva'], len(s['data']), ctypes.cast(b, ctypes.c_void_p))
                  for s, b in zip(sections, buffers)))
        skip_values = sorted(skipped)
        skips = (ctypes.c_uint64 * len(skip_values))(*skip_values)
        counters = (ctypes.c_uint64 * 3)()
        expected = None
        if self.compare:
            expected = [dict(s, data=bytearray(s['data'])) for s in sections]
        okay = self.library.replay_linker_references(self.handle, views, len(sections), references,
            len(references), metadata, skips, len(skips), counters, self.error, len(self.error))
        if not okay:
            raise ValueError(self.error.value.decode('utf-8', 'replace'))
        self.metrics['native_seconds'] += time.perf_counter() - started
        self.metrics['reference_calls'] += 1
        if expected is not None:
            from build import write_rva
            started = time.perf_counter()
            counts = [0, 0, 0]
            skipped = set(skipped)
            for at, target, width in struct.iter_unpack('<III', references):
                if self.layout.replaced(at) or at in skipped:
                    continue
                resolved = self.layout.resolve(target)
                value = resolved + (self.manifest['image_base'] if not metadata and width == 8 else 0)
                write_rva(expected, self.layout.map(at), value.to_bytes(width, 'little'))
                counts[width != 8] += 1
                counts[2] += resolved != target
            self.metrics['reference_seconds'] += time.perf_counter() - started
            if counts != list(counters) or any(a['data'] != b['data'] for a, b in zip(sections, expected)):
                raise ValueError('Native/Python initialized-data relocation parity failed')
        return tuple(counters)


class Wire:
    """Length-delimited, little-endian ABI records; no JSON in the link path."""
    def __init__(self, data=b''):
        self.data = bytearray(data)
        self.at = 0

    def put(self, format, *values):
        self.data.extend(struct.pack('<' + format, *values))

    def take(self, format):
        values = struct.unpack_from('<' + format, self.data, self.at)
        self.at += struct.calcsize('<' + format)
        return values[0] if len(values) == 1 else values

    def bytes(self, data):
        self.put('Q', len(data))
        self.data.extend(data)

    def read_bytes(self):
        size = self.take('Q')
        if size > len(self.data) - self.at:
            raise ValueError('Truncated native linker output')
        data = self.data[self.at:self.at + size]
        self.at += size
        return data

    def text(self, value):
        self.bytes(value.encode('utf-8'))

    def replacements(self, rows, sizes):
        self.put('I', len(rows))
        for row in rows:
            self.put('qqQI', row['begin'], row['end'], sizes.get(row['symbol'], 0), bool(row.get('retired')))
            self.text(row['symbol'])

    def bindings(self, values):
        self.put('I', len(values))
        for name, value in values.items():
            self.text(name)
            self.put('q', value)

    def sections(self, sections):
        self.put('I', len(sections))
        for section in sections:
            self.text(section.get('name', ''))
            self.put('III', section['rva'], section['virtual_size'], section.get('flags', 0))
            self.bytes(section['data'])

    def read_sections(self):
        result = []
        for _ in range(self.take('I')):
            name = self.read_bytes().decode('utf-8')
            rva, size, flags = self.take('III')
            result.append(dict(name=name, rva=rva, virtual_size=size, flags=flags, data=self.read_bytes()))
        return result

    def directories(self, directories):
        self.put('I', len(directories))
        for row in directories:
            self.put('II', row['rva'], row['size'])

    def read_directories(self):
        return [dict(zip(('rva', 'size'), self.take('II'))) for _ in range(self.take('I'))]

    def finish(self):
        if self.at != len(self.data):
            raise ValueError('Trailing native linker output')


def call_stage(library, number, wire, handle=None, metrics=None):
    error = ctypes.create_string_buffer(2048)
    result, size = ctypes.c_void_p(), ctypes.c_uint64()
    started = time.perf_counter()
    okay = library.replay_linker_stage(handle, number, bytes(wire.data), len(wire.data),
        ctypes.byref(result), ctypes.byref(size), error, len(error))
    if not okay:
        raise ValueError(error.value.decode('utf-8', 'replace'))
    try:
        output = ctypes.string_at(result, size.value)
    finally:
        library.replay_linker_release(result)
    if metrics is not None:
        metrics['native_seconds'] += time.perf_counter() - started
        calls = metrics.setdefault('stage_calls', {})
        calls[str(number)] = calls.get(str(number), 0) + 1
    return output


class NativeStages:
    def __init__(self, output, llvm, compare=False):
        self.library, self.identity = build_library(output, llvm)
        self.compare = compare
        self.metrics = {'native_seconds': 0.0, 'stage_calls': {}}

    def stage(self, number, wire):
        return call_stage(self.library, number, wire, metrics=self.metrics)

    def select_comdats(self, objects):
        import copy
        from coff import select_comdats
        expected = copy.deepcopy(objects) if self.compare else None
        wire = Wire()
        wire.put('I', len(objects))
        flat = [s for obj in objects for s in obj['sections']]
        for obj in objects:
            wire.text(obj['path'])
            wire.put('II', obj.get('timestamp', 0), len(obj['sections']))
            for section in obj['sections']:
                aux = section.get('aux', {})
                wire.put('III', section['flags'], aux.get('selection', 0), aux.get('associated', 0))
                wire.bytes(section['data'])
                wire.put('I', len(section['relocations']))
                for at, symbol, kind in section['relocations']:
                    wire.put('III', at, symbol, kind)
            wire.put('I', len(obj['symbols']))
            for index, symbol in obj['symbols'].items():
                wire.put('I', index)
                wire.text(symbol['name'])
                wire.put('IiI', symbol['value'], symbol['section'], symbol['storage'])
        result = Wire(self.stage(12, wire))
        if result.take('I') != len(flat):
            raise ValueError('Native COMDAT selection returned a different section count')
        for section in flat:
            discarded, selected = result.take('Ii')
            if discarded:
                section['discarded'] = True
            if selected >= 0:
                section['selected'] = flat[selected]
        result.finish()
        if self.compare:
            select_comdats(expected)
            if objects != expected:
                raise ValueError('Native/Python COMDAT selection parity failed')

    def allocate_common(self, objects, native):
        import copy
        from coff import allocate_common
        expected = copy.deepcopy(objects) if self.compare else None
        wire = Wire()
        wire.bindings(native)
        wire.put('I', len(objects))
        for obj in objects:
            wire.put('I', len(obj['symbols']))
            for index, symbol in obj['symbols'].items():
                wire.put('I', index)
                wire.text(symbol['name'])
                section = symbol['section']
                discarded = section > 0 and bool(obj['sections'][section - 1].get('discarded'))
                wire.put('QiII', symbol['value'], section, symbol['storage'], discarded)
        result = Wire(self.stage(13, wire))
        for _ in range(result.take('I')):
            obj = objects[result.take('I')]
            name = result.read_bytes().decode('utf-8')
            size, flags = result.take('QI')
            number = len(obj['sections']) + 1
            obj['sections'].append(dict(name='.bss', data=bytearray(size), flags=flags, relocations=[], number=number))
            obj['symbols'][max(obj['symbols'], default=-1) + 1] = dict(name=name, value=0, section=number, kind=0, storage=2)
        for _ in range(result.take('I')):
            obj, index = result.take('II')
            objects[obj]['symbols'][index]['value'] = 0
        result.finish()
        if self.compare:
            allocate_common(expected, native)
            if objects != expected:
                raise ValueError('Native/Python common-symbol allocation parity failed')

    def serialize_image(self, manifest, sections, reference):
        import compiler_identity
        wire = Wire()
        wire.put('IH', manifest['timestamp'], manifest['characteristics'])
        wire.bytes(compiler_identity.encode(manifest, 0))
        old = manifest['optional']
        optional = bytearray(112)
        struct.pack_into('<HBBIIIIIQII', optional, 0, 0x20b, 22, 1, 0, 0,
            old['SizeOfUninitializedData'], manifest.get('linked_entry_rva', old['AddressOfEntryPoint']),
            old['BaseOfCode'], old['ImageBase'], old['SectionAlignment'], old['FileAlignment'])
        for field, at in (('MajorOperatingSystemVersion', 40), ('MinorOperatingSystemVersion', 42),
                          ('MajorImageVersion', 44), ('MinorImageVersion', 46),
                          ('MajorSubsystemVersion', 48), ('MinorSubsystemVersion', 50)):
            struct.pack_into('<H', optional, at, old[field])
        struct.pack_into('<IIIIHHQQQQII', optional, 52, old['Reserved1'], 0, 0, 0,
            old['Subsystem'], old['DllCharacteristics'], old['SizeOfStackReserve'], old['SizeOfStackCommit'],
            old['SizeOfHeapReserve'], old['SizeOfHeapCommit'], old['LoaderFlags'], 16)
        wire.bytes(optional)
        wire.directories(manifest['directories'])
        wire.sections(sections)
        result = self.stage(6, wire)
        if self.compare and result != reference(manifest, sections):
            raise ValueError('Native/Python PE serialization parity failed')
        # Keep raw extents in the driver's section records for existing tools.
        for index, section in enumerate(sections):
            size, at = struct.unpack_from('<II', result, 0x98 + 240 + index * 40 + 16)
            section.update(raw_size=size, raw_at=at)
        return result


from layout import Layout


class NativeLayout(Layout):
    """Python-facing layout receipt; the native planner computes its values."""
    def __init__(self, manifest, sizes, native_text, stages):
        self.replacements, self.sizes = manifest['replacements'], sizes
        self.text_start, self.data_start = manifest['sections'][0]['rva'], manifest['sections'][1]['rva']
        self.granularity = manifest['optional'].get('SectionAlignment', 16)
        self.interior_rvas, self.interior_uses = {}, {}
        self.engine = None
        wire = Wire()
        text = manifest['sections'][0]
        wire.put('qqQQ', self.text_start, self.data_start, max(text['raw_size'], text['virtual_size']), self.granularity)
        wire.replacements(self.replacements, sizes)
        wire.put('I', len(manifest['short_references']))
        for site, target in manifest['short_references']:
            wire.put('qq', site, target)
        wire.bytes(native_text)
        result = Wire(stages.stage(1, wire))
        self.section_delta = result.take('q')
        self.events = dict(result.take('qq') for _ in range(result.take('I')))
        self.points = sorted(self.events)
        self.deltas = [0]
        for point in self.points:
            self.deltas.append(self.deltas[-1] + self.events[point])
        self.widened = {}
        for _ in range(result.take('I')):
            site, target, size, opcode = result.take('qqII')
            self.widened[site] = dict(target=target, size=size, opcode=opcode, prefix=bytes(result.read_bytes()))
        result.finish()
        self.compare = stages.compare
        if self.compare:
            expected = Layout(manifest, sizes, native_text)
            if any(getattr(self, key) != getattr(expected, key) for key in
                   ('events', 'points', 'deltas', 'widened', 'section_delta')):
                raise ValueError('Native/Python layout planning parity failed')

    def copy_text(self, data):
        wire = Wire()
        wire.put('III', 0, self.text_start, self.granularity)
        wire.bytes(data)
        result = bytearray(self.engine.stage(7, wire))
        if self.compare and result != super().copy_text(data):
            raise ValueError('Native/Python text layout parity failed')
        return result

    def branches(self, text, manifest):
        wire = Wire()
        wire.put('III', 1, self.text_start, self.granularity)
        wire.bytes(text)
        wire.put('I', len(manifest['short_references']))
        for site, target in manifest['short_references']:
            wide = self.widened.get(site, {})
            wire.put('qqII', site, target, wide.get('size', 0), wide.get('opcode', 0))
            wire.bytes(wide.get('prefix', b''))
        result = self.engine.stage(7, wire)
        if self.compare:
            expected = bytearray(text)
            super().branches(expected, manifest)
            if result != expected:
                raise ValueError('Native/Python branch relaxation parity failed')
        text[:] = result

    def unwind_offsets(self, entries, read):
        wire = Wire()
        wire.put('I', len(entries))
        windows = {}
        for entry in entries:
            wire.put('III', *entry)
            begin, end, info = entry
            if any(begin < point <= end for point in self.points) and info not in windows:
                header = read(info, 4)
                data = header + read(info + 4, header[2] * 2)
                windows[info] = dict(name='', rva=info, virtual_size=len(data), data=data)
        wire.sections(list(windows.values()))
        result = Wire(self.engine.stage(8, wire))
        writes = dict(result.take('IB') for _ in range(result.take('I')))
        result.finish()
        if self.compare and writes != super().unwind_offsets(entries, read):
            raise ValueError('Native/Python unwind relaxation parity failed')
        return writes
