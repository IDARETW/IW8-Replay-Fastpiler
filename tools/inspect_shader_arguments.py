"""Read inline technique arguments from decoded PC IW8 techset streams."""
from pathlib import Path
import collections
import hashlib
import json
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
INLINE = {0xffffffffffffffff, 0xfffffffffffffffe}


def scan(path, root_size=184):
    if root_size not in (176,184):
        raise ValueError('Unverified serialized technique root size')
    data = path.read_bytes()
    techniques = {}
    for match in re.finditer(rb'TECHNIQUE_[A-Za-z0-9_ ]+\0', data):
        start = match.start() - root_size
        if start < 0:
            continue
        root = data[start:match.start()]
        if struct.unpack_from('<Q', root)[0] not in INLINE:
            continue
        if root_size == 176:
            # Diagnostic projection only: the serialized child fields at
            # [0x20,0xb0) occur eight bytes earlier in XFile 4289. This does
            # not establish how the shorter prefix maps to Replay metadata.
            root = root[:0x20] + bytes(8) + root[0x20:]
        at = match.end()
        if struct.unpack_from('<Q', root, 0x28)[0]:
            at += 16 * root[0x83] * root[0x0e]
        if struct.unpack_from('<Q', root, 0x50)[0] in INLINE:
            at += 16
        shaders = []
        for offset in (0x58, 0x60, 0x68, 0x70):
            if struct.unpack_from('<Q', root, offset)[0] not in INLINE:
                shaders.append(None)
                continue
            shader = data[at:at + 40]
            at += 40
            shader_name = None
            for field in (0, 8):
                if struct.unpack_from('<Q', shader, field)[0] in INLINE:
                    end = data.index(b'\0', at)
                    if field == 0:
                        shader_name = data[at:end].decode()
                    at = end + 1
            code_at, size = at, 0
            if struct.unpack_from('<Q', shader, 24)[0] in INLINE:
                size = struct.unpack_from('<I', shader, 32)[0]
                if data[at:at + 4] != b'DXBC':
                    raise ValueError((str(path), match.group(), hex(at), 'shader bytecode'))
                at += size
            shaders.append(dict(name=shader_name, code_offset=code_at, size=size))
        formats_at = at
        formats = []
        if struct.unpack_from('<Q', root, 0x88)[0]:
            formats = list(struct.iter_unpack('<5B', data[at:at + 5 * root[0x83]]))
            at += 5 * root[0x83]
        count = sum(root[0x78:0x7c])
        arguments = list(struct.iter_unpack('<BBHH', data[at:at + 6 * count]))
        shader_mask = 0x0f if root_size == 176 else 0x1e
        if any(t > 9 or flags & ~shader_mask for t, flags, _, _ in arguments):
            raise ValueError((str(path), match.group(), hex(at), arguments[:3]))
        name = match.group()[:-1].decode()
        row = dict(name=name, root_offset=start, arguments_offset=at,
                   counts=list(root[0x78:0x7c]), arguments=arguments,
                   formats_offset=formats_at, formats=formats, shaders=shaders)
        if root_size != 184: row['serialized_root_size'] = root_size
        if name in techniques and techniques[name]['arguments'] != arguments:
            raise ValueError((str(path), name, 'conflicting arguments'))
        techniques[name] = row
    return techniques


def main():
    versions = {}
    paths = {}
    for label, directory in (('replay', 'assets/replay120-techsets-decoded'),
                             ('mw131', 'assets/mw131-shader-decoded')):
        selected = list((ROOT / directory).glob('*.ff.dec'))
        if label == 'mw131':
            selected.append(ROOT / 'assets/mw131-decoded/techsets_mp_frontend7b.ff.dec')
        rows = {}
        paths[label] = []
        for path in selected:
            found = scan(path)
            paths[label].append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                     techniques=len(found)))
            for name, row in found.items():
                if name in rows and rows[name]['arguments'] != row['arguments']:
                    raise ValueError((label, name, 'cross-zone argument conflict'))
                rows[name] = row
        versions[label] = rows
    pairs = []
    mappings = collections.defaultdict(collections.Counter)
    for name in sorted(versions['replay'].keys() & versions['mw131'].keys()):
        before, after = versions['replay'][name], versions['mw131'][name]
        if before['counts'] != after['counts'] or len(before['arguments']) != len(after['arguments']):
            continue
        if any(a[:3] != b[:3] for a, b in zip(before['arguments'], after['arguments'])):
            continue
        changes = []
        for a, b in zip(before['arguments'], after['arguments']):
            mappings[b[0], b[3]][a[3]] += 1
            if a != b:
                changes.append(dict(type=b[0], source=b[3], replay=a[3]))
        pairs.append(dict(name=name, count=len(after['arguments']), changes=changes))
    result = dict(sources=paths, techniques={k: len(v) for k, v in versions.items()},
                  matched_techniques=pairs,
                  mappings=[dict(type=t, source=s, replay=dict(c)) for (t, s), c in sorted(mappings.items())],
                  source_arguments=[dict(type=t, indices=sorted({a[3] for row in versions['mw131'].values()
                                                               for a in row['arguments'] if a[0] == t}))
                                    for t in range(10)])
    (ROOT / 'evidence/mw131-shader-argument-comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(techniques=result['techniques'], paired=len(pairs), mappings=result['mappings'])))


if __name__ == '__main__':
    main()
