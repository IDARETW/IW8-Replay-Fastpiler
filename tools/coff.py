"""Checked AMD64 COFF/bigobj reader and deterministic COMDAT selection.
Auxiliary records control selection of function bodies and associated unwind
metadata; relocation-bearing template instances must be selected together.
"""
from pathlib import Path
import struct

BIGOBJ_CLASS = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
RELOCATION_WIDTH = {0: 0, 1: 8, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4,
                    7: 4, 8: 4, 9: 4, 10: 2, 11: 4}


def read(path):
    raw = Path(path).read_bytes()

    def take(at, size):
        if at < 0 or size < 0 or at + size > len(raw):
            raise ValueError(f'Truncated COFF record in {path}: {at:#x}+{size:#x}')
        return raw[at:at+size]

    big = take(0, 4) == b'\0\0\xff\xff'
    if big:
        header = take(0, 56)
        version, machine = struct.unpack_from('<HH', header, 4)
        if version < 2 or header[12:28] != BIGOBJ_CLASS:
            raise ValueError(f'Unsupported bigobj/import object: {path}')
        count, symbols_at, symbol_count = struct.unpack_from('<III', header, 44)
        header_size, symbol_size, symbol_format = 56, 20, '<8sIiHBB'
        timestamp = struct.unpack_from('<I', header, 8)[0]
    else:
        machine, count, timestamp, symbols_at, symbol_count, optional, _ = struct.unpack('<HHIIIHH', take(0, 20))
        if optional:
            raise ValueError(f'Expected a relocatable object: {path}')
        header_size, symbol_size, symbol_format = 20, 18, '<8sIhHBB'
    if machine != 0x8664:
        raise ValueError(f'Expected AMD64 COFF: {path}')
    take(header_size, count * 40)
    strings_at = symbols_at + symbol_count * symbol_size
    strings = b''
    if symbols_at:
        take(symbols_at, symbol_count * symbol_size)
        string_size = struct.unpack('<I', take(strings_at, 4))[0]
        if string_size < 4:
            raise ValueError('Invalid COFF string table size')
        strings = take(strings_at, string_size)
    elif symbol_count:
        raise ValueError('COFF symbol table has no file offset')

    def name(field, section=False):
        offset = None
        if field[:4] == b'\0' * 4:
            offset = struct.unpack_from('<I', field, 4)[0]
            if offset == 0:
                return ''
        elif section and field.startswith(b'/'):
            try:
                offset = int(field[1:].rstrip(b'\0'))
            except ValueError as error:
                raise ValueError('Unsupported COFF section-name encoding') from error
        if offset is None:
            return field.rstrip(b'\0').decode('utf-8')
        if not 4 <= offset < len(strings) or b'\0' not in strings[offset:]:
            raise ValueError('Invalid COFF string reference')
        return strings[offset:].split(b'\0', 1)[0].decode('utf-8')

    sections = []
    for i in range(count):
        label, _, _, size, data_at, rel_at, _, rel_count, _, flags = struct.unpack(
            '<8sIIIIIIHHI', take(header_size + i*40, 40))
        if ((flags >> 20) & 15) == 15:
            raise ValueError('Reserved COFF section alignment')
        if size and not data_at and not flags & 0x80:
            raise ValueError('Initialized COFF section has no data')
        if flags & 0x1000000:
            if rel_count != 0xffff:
                raise ValueError('Invalid extended COFF relocation count')
            total, symbol, kind = struct.unpack('<IIH', take(rel_at, 10))
            if total < 1 or symbol or kind:
                raise ValueError('Invalid COFF relocation overflow record')
            rel_count, rel_at = total-1, rel_at+10
        if rel_count and not rel_at:
            raise ValueError('COFF relocations have no file offset')
        relocation_bytes = take(rel_at, rel_count*10)
        relocations = list(struct.iter_unpack('<IIH', relocation_bytes))
        sections.append(dict(name=name(label, True), data=bytearray(take(data_at, size)) if data_at else bytearray(size),
                             flags=flags, relocations=relocations, relocation_bytes=relocation_bytes, number=i+1))
    symbols = {}
    index = 0
    while index < symbol_count:
        label, value, section, kind, storage, auxiliary = struct.unpack(
            symbol_format, take(symbols_at+index*symbol_size, symbol_size))
        if not big and section < -2:
            section &= 0xffff  # Standard COFF reserves only 0xffff/0xfffe.
        if index+1+auxiliary > symbol_count or section > count or section < -2:
            raise ValueError('Invalid COFF symbol/auxiliary range')
        symbol = dict(name=name(label), value=value, section=section, kind=kind, storage=storage)
        if section > 0 and storage == 2 and kind & 0x20 and value > len(sections[section-1]['data']):
            raise ValueError('COFF symbol extends beyond its section')
        aux = take(symbols_at+(index+1)*symbol_size, auxiliary*symbol_size)
        if storage == 105:
            if auxiliary != 1 or section != 0:
                raise ValueError('Invalid weak external record')
            symbol['weak'] = dict(zip(('fallback', 'search'), struct.unpack_from('<II', aux)))
        if storage == 3 and section > 0 and auxiliary and kind == 0:
            length, rels, lines, checksum, associated, selection = struct.unpack_from('<IHHIHB', aux)
            if big:
                associated |= struct.unpack_from('<H', aux, 16)[0] << 16
            sections[section-1]['aux'] = dict(length=length, checksum=checksum, associated=associated, selection=selection)
        symbols[index] = symbol
        index += 1+auxiliary
    for symbol in symbols.values():
        if 'weak' in symbol and (symbol['weak']['fallback'] not in symbols or symbol['weak']['search'] not in (1, 2, 3)):
            raise ValueError('Invalid or unsupported weak external fallback')
    for section in sections:
        if section['flags'] & 0x1000:
            aux = section.get('aux', {})
            if aux.get('selection') not in range(1, 8):
                raise ValueError('COMDAT selection record missing or invalid')
            if aux['selection'] == 5 and (not 1 <= aux['associated'] <= count or aux['associated'] == section['number']):
                raise ValueError('Invalid associative COMDAT parent')
        for offset, symbol, kind in section['relocations']:
            if kind not in RELOCATION_WIDTH:
                raise ValueError(f'Unsupported AMD64 relocation {kind} in {path}')
            if kind == 0:
                continue
            if symbol not in symbols or offset+RELOCATION_WIDTH[kind] > len(section['data']):
                raise ValueError('Invalid COFF relocation site or symbol index')
    return dict(path=str(path), timestamp=timestamp, sections=sections, symbols=symbols, bigobj=big)


def allocate_common(objects, native):
    """Coalesce tentative data definitions by largest size; strong wins."""
    strong = {}
    common = {}
    for obj in objects:
        for s in obj['symbols'].values():
            if s['storage'] != 2:
                continue
            if s['section'] > 0 and not obj['sections'][s['section']-1].get('discarded'):
                strong[s['name']] = s
            elif s['section'] == 0 and s['value']:
                common.setdefault(s['name'], []).append((obj, s))
    for name, declarations in common.items():
        if name not in strong and name not in native:
            obj = declarations[0][0]
            size = max(s['value'] for _, s in declarations)
            # COFF common symbols have no explicit alignment; Windows AMD64
            # common storage needs at most 16-byte natural alignment.
            alignment = min(16, 1 << (size-1).bit_length())
            flags = 0xc0000080 | (alignment.bit_length() << 20)
            obj['sections'].append(dict(name='.bss', data=bytearray(size), flags=flags,
                                        relocations=[], number=len(obj['sections'])+1))
            obj['symbols'][max(obj['symbols'], default=-1)+1] = dict(name=name, value=0,
                section=len(obj['sections']), kind=0, storage=2)
        for _, s in declarations:
            s['value'] = 0


def select_comdats(objects):
    """Select parent COMDATs, then discard associated metadata together."""
    groups = {}
    for obj in objects:
        for section in obj['sections']:
            if not section['flags'] & 0x1000 or section['aux']['selection'] == 5:
                continue
            names = [s['name'] for s in obj['symbols'].values()
                     if s['section'] == section['number'] and s['storage'] == 2 and s['value'] == 0]
            if not names and section['aux']['selection'] == 1:
                continue  # TU-local NODUPLICATES section has no global key.
            if len(names) != 1:
                raise ValueError(f'Ambiguous COMDAT key in {obj["path"]}: {names}')
            groups.setdefault(names[0], []).append((obj, section))

    def signature(obj, section):
        rows = []
        for at, index, kind in section['relocations']:
            s = obj['symbols'][index]
            identity = s['name']
            if s['section'] > 0 and s['storage'] != 2:
                target = obj['sections'][s['section']-1]
                keys = [v['name'] for v in obj['symbols'].values()
                        if v['section'] == s['section'] and v['storage'] == 2 and v['value'] == 0]
                identity = keys[0] if len(keys) == 1 else (obj['path'], target['number'])
            rows.append((at, kind, identity, s['value']))
        return bytes(section['data']), rows

    for key, entries in groups.items():
        mode = entries[0][1]['aux']['selection']
        if any(s['aux']['selection'] != mode for _, s in entries):
            raise ValueError(f'Conflicting COMDAT selection for {key}')
        winner = entries[0]
        if len(entries) > 1:
            if mode == 1:
                raise ValueError(f'Duplicate NODUPLICATES COMDAT: {key}')
            if mode == 3 and len({len(s['data']) for _, s in entries}) != 1:
                raise ValueError(f'COMDAT SAME_SIZE mismatch: {key}')
            if mode == 4 and any(signature(*e) != signature(*winner) for e in entries[1:]):
                raise ValueError(f'COMDAT EXACT_MATCH mismatch: {key}')
            if mode == 6:
                winner = max(entries, key=lambda e: len(e[1]['data']))
            if mode == 7:
                winner = max(entries, key=lambda e: e[0]['timestamp'])
            for obj, section in entries:
                if section is not winner[1]:
                    section['discarded'] = True
                    section['selected'] = winner[1]
    for obj in objects:
        def resolve(section, active):
            if section['number'] in active:
                raise ValueError('Cyclic associative COMDAT graph')
            aux = section.get('aux', {})
            if aux.get('selection') == 5:
                parent = obj['sections'][aux['associated']-1]
                resolve(parent, active | {section['number']})
                if parent.get('discarded'):
                    section['discarded'] = True
        for section in obj['sections']:
            resolve(section, set())


def align(value, alignment):
    if alignment <= 0 or alignment & (alignment-1):
        raise ValueError('Alignment must be a positive power of two')
    return (value + alignment - 1) & -alignment
