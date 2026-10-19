"""Walk 1.69 MaterialTechniqueSet assets in stream order for shader alias evidence.

The walker starts at the first structurally verified type-18 root and follows
the native Set -> pointer array -> Technique allocation order. It intentionally
does not infer a stream-5 base from decoded-file offsets.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from inspect_shader_arguments import ROOT, scan as scan_techniques
from verify_frontend_shaders import dxbc_stage

INLINE = {0xffffffffffffffff, 0xfffffffffffffffe}
SHADER_FIELDS = (0x50, 0x58, 0x60, 0x68)


class Walk:
    def __init__(self, data, cursor, base_alignment, root_size, expected_roots=None):
        self.data = data
        self.cursor = cursor
        self.base_alignments = {'0': 0, '1': 0, '5': base_alignment}
        self.root_size = root_size
        self.logical = {'0': 0, '1': 0, '5': 0}
        self.sets = []
        self.techniques = []
        self.pointer_fields = {}
        self.expected_roots = expected_roots or set()
        self.set_index = None
        self.asset_logical_base = 0
        self.last_logical_start = {}

    def read(self, size, alignment=1, stream='5'):
        mask = alignment - 1
        self.logical[stream] += (-(self.logical[stream] + self.base_alignments[stream])) & mask
        self.last_logical_start[stream] = self.logical[stream]
        if size < 0 or self.cursor + size > len(self.data):
            raise ValueError(f"read past EOF at {self.cursor:#x} size {size:#x}")
        at = self.cursor
        raw = self.data[at:at + size]
        self.cursor += size
        self.logical[stream] += size
        return raw, at

    def advance_logical(self, size, alignment=1, stream='5'):
        mask = alignment - 1
        self.logical[stream] += (-(self.logical[stream] + self.base_alignments[stream])) & mask
        at = self.logical[stream]
        self.logical[stream] += size
        return at

    def string(self, token, stream='5'):
        if not token or token not in INLINE:
            return None
        end = self.data.index(b'\0', self.cursor)
        raw, at = self.read(end + 1 - self.cursor, stream=stream)
        return raw[:-1].decode('utf-8', 'replace'), at

    def shader(self, stage, technique, technique_root_at, source_field_offset, field_at, token):
        pointer = dict(asset_index=self.set_index, local_offset=field_at - self.asset_logical_base,
                       stream_offset=field_at, source_field_file_offset=source_field_offset,
                       technique_root_file_offset=technique_root_at, stage=stage,
                       technique=technique, token=hex(token))
        self.pointer_fields[(self.set_index, pointer['local_offset'])] = pointer
        if token not in INLINE:
            return None
        # Replay's pointer wrapper switches to stream 1 for the 40-byte shader
        # root. The root loader then pushes stream 5 for names, load-def and
        # bytecode. Those child allocations advance the same stream-5 cursor
        # as the parent MaterialTechniqueSet.
        root, root_at = self.read(40, alignment=8, stream='1')
        name_token, debug_token, created, code_token, byte_count, _ = struct.unpack('<QQQQII', root)
        name = self.string(name_token, stream='5')
        debug = self.string(debug_token, stream='5')
        # The following 24-byte extension and 16-byte load-def are re-read
        # with streamStart=1, so native Load_Stream does not advance stream 5.
        code_at = None
        code_bytes = 0
        code_sha256 = None
        if code_token in INLINE and byte_count:
            code, code_at = self.read(byte_count, alignment=4, stream='5')
            if dxbc_stage(code) != stage:
                raise ValueError(f"{technique}: inline {stage} shader payload at {code_at:#x} has wrong DXBC stage")
            code_bytes = len(code)
            code_sha256 = hashlib.sha256(code).hexdigest()
        resolved = dict(stage=stage, name=name[0].lstrip(',') if name else None,
                         root_offset=root_at, code_pointer_token=hex(code_token), code_offset=code_at,
                         code_bytes=code_bytes, code_sha256=code_sha256)
        pointer['resolved_shader'] = resolved
        return resolved

    def technique(self, set_name, stage_slots):
        raw, root_at = self.read(self.root_size, alignment=8, stream='5')
        root_logical = self.last_logical_start['5']
        name_token = struct.unpack_from('<Q', raw)[0]
        name = self.string(name_token, stream='5')
        technique_name = name[0] if name else None
        if self.expected_roots and root_at not in self.expected_roots:
            raise ValueError(f"predicted technique root {root_at:#x} ({technique_name}) is absent from name scan")
        row = dict(name=technique_name, root_offset=root_at, set_name=set_name, shaders=[])
        # Constant-buffer definitions, state bits, and the four shader records.
        cbuf_offset = 0x28 if self.root_size == 184 else 0x20
        state_offset = 0x50 if self.root_size == 184 else 0x48
        cbuf = struct.unpack_from('<Q', raw, cbuf_offset)[0]
        if cbuf:
            count_offset = 0x83 if self.root_size == 184 else 0x7b
            count = raw[count_offset] * raw[0x0e]
            self.read(16 * count, alignment=8, stream='5')
        state = struct.unpack_from('<Q', raw, state_offset)[0]
        if state in INLINE:
            self.read(16, alignment=8, stream='5')
        shader_fields = SHADER_FIELDS if self.root_size == 176 else (0x58, 0x60, 0x68, 0x70)
        for slot, field in enumerate(shader_fields):
            token = struct.unpack_from('<Q', raw, field)[0]
            field_at = root_logical + field
            child = self.shader(stage_slots[slot], technique_name, root_at, root_at + field,
                                field_at, token)
            if child:
                row['shaders'].append(child)
        formats_offset = 0x88 if self.root_size == 184 else 0x80
        formats = struct.unpack_from('<Q', raw, formats_offset)[0]
        if formats:
            formats_count = raw[0x83] if self.root_size == 184 else raw[0x7b]
            _, formats_at = self.read(5 * formats_count, stream='5')
            row['formats_offset'] = formats_at
        counts_at = 0x78 if self.root_size == 184 else 0x70
        count = sum(raw[counts_at:counts_at + 4])
        if count:
            _, args_at = self.read(6 * count, alignment=2, stream='5')
            row['arguments_offset'] = args_at
        self.techniques.append(row)
        return row

    def techset(self, index, stage_slots):
        # The XAsset payload root is on stream 1 via the pointer wrapper.
        # Its stream-5 children begin after the root, within this asset scope.
        raw, root_at = self.read(64, stream='1')
        self.asset_logical_base = self.logical['5']
        self.set_index = index
        name_token = struct.unpack_from('<Q', raw)[0]
        if name_token == 0:
            raise ValueError(f"type-18 candidate at {root_at:#x} has null name token")
        name_block = name_token >> 32
        if name_token not in INLINE and (name_block not in range(0x10, 0x1b) or not (name_token & 0xffffffff)):
            raise ValueError(f"type-18 candidate at {root_at:#x} has unsupported name token {name_token:#x}")
        name = self.string(name_token, stream='5')
        set_name = name[0] if name else None
        masks = struct.unpack_from('<4Q', raw, 0x18)
        count = sum(m.bit_count() for m in masks)
        if count > 256:
            raise ValueError(f"type-18 candidate at {root_at:#x} has implausible technique count {count}")
        ptr_token = struct.unpack_from('<Q', raw, 0x38)[0]
        if ptr_token not in (0, *INLINE) and (ptr_token >> 32 not in range(0x10, 0x1b) or not (ptr_token & 0xffffffff)):
            raise ValueError(f"type-18 candidate at {root_at:#x} has unsupported technique-array token {ptr_token:#x}")
        row = dict(index=index, root_offset=root_at, name=set_name, mask_popcount=count,
                   ptr_token=hex(ptr_token), stream5_asset_base=self.asset_logical_base, techniques=[])
        if ptr_token in INLINE:
            pointers, ptr_at = self.read(count * 8, alignment=8, stream='5')
            values = list(struct.unpack('<' + 'Q' * count, pointers))
            row['pointer_array_offset'] = ptr_at
            for i, token in enumerate(values):
                if token in INLINE:
                    try:
                        technique = self.technique(set_name, stage_slots)
                    except Exception as exc:
                        raise ValueError(f"set {index} at {root_at:#x}, ptr {i}, cursor {self.cursor:#x}: {exc}") from exc
                    row['techniques'].append(technique)
                else:
                    row['techniques'].append(dict(pointer=hex(token), inline=False))
        self.sets.append(row)
        return row


def walk(scene, path, first_root, expected_sets, root_size, base_alignment, stage_slots):
    data = path.read_bytes()
    expected = {row['root_offset'] for row in scan_techniques(path, root_size).values()}
    walker = Walk(data, first_root, base_alignment, root_size, expected)
    for i in range(expected_sets):
        walker.techset(i, stage_slots)
    aliases = []
    for pointer in walker.pointer_fields.values():
        token = int(pointer['token'], 16)
        if token >> 32 != 0x15:
            continue
        target_offset = (token & 0xffffffff) - 1
        target = walker.pointer_fields.get((pointer['asset_index'], target_offset))
        row = dict(source=dict(pointer), target_local_offset=target_offset,
                   exact_prior_field=target is not None,
                   valid_same_stage_prior_field=bool(target and target['stage'] == pointer['stage']
                                                     and target_offset < pointer['local_offset']))
        if target:
            row['target_stage'] = target['stage']
            row['target_technique'] = target['technique']
            row['target_token'] = target['token']
            row['target_name'] = target.get('resolved_shader', {}).get('name')
            row['same_stage'] = target['stage'] == pointer['stage']
            row['target_precedes_source'] = target_offset < pointer['local_offset']
        aliases.append(row)
    def pointer_kind(text):
        token = int(text, 16)
        if token == 0:
            return 'null'
        if token in INLINE:
            return 'shared' if token == 0xffffffffffffffff else 'follows'
        block = token >> 32
        if block == 5:
            return 'block5_asset_pointer'
        if block == 0x15:
            return 'stream5_local_alias'
        return f'encoded_block_{block:x}'

    summary = dict(scene=scene, path=str(path), sha256=hashlib.sha256(data).hexdigest(),
                   sets=len(walker.sets), inline_techniques=len(walker.techniques),
                   shader_fields=len(walker.pointer_fields),
                   shader_pointer_modes=dict(Counter(pointer_kind(v['token']) for v in walker.pointer_fields.values())),
                   stream_aliases=len(aliases), exact_prior_field_aliases=sum(a['exact_prior_field'] for a in aliases),
                   valid_same_stage_prior_aliases=sum(a['valid_same_stage_prior_field'] for a in aliases),
                   start=hex(first_root), end=hex(walker.cursor),
                   initial_stream_alignment=walker.base_alignments['5'])
    summary['aliases'] = aliases
    return summary, walker


def main():
    specs = [
        ('c3s5', 'mp_frontendc3s5', 0x4f1e92, 197, 176, 3, (14, 15, 16, 17)),
        ('9b', 'mp_frontend9b', 0x49c82c, 159, 184, 0, (14, 15, 16, 17)),
    ]
    results = []
    for scene, stem, first, count, size, alignment, stages in specs:
        path = ROOT / f'assets/mw169-decoded/techsets_{stem}.ff.dec'
        try:
            summary, walker = walk(scene, path, first, count, size, alignment, stages)
        except Exception as exc:
            results.append(dict(scene=scene, path=str(path), expected_sets=count,
                                verified=False, failure=str(exc)))
            continue
        summary['verified'] = True
        summary['sets_detail'] = walker.sets
        summary['techniques_detail'] = [dict(name=t['name'], root_offset=t['root_offset'],
            set_name=t['set_name'], formats_offset=t.get('formats_offset'),
            arguments_offset=t.get('arguments_offset'), shaders=t['shaders']) for t in walker.techniques]
        summary['pointer_fields'] = [v for _, v in sorted(walker.pointer_fields.items())]
        results.append(summary)
    out = ROOT / 'evidence/mw169-current/shader-bindings/technique-set-walk.json'
    out.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps([{k:v for k,v in r.items() if k not in ('sets_detail','techniques_detail','pointer_fields','aliases')} for r in results], indent=2))


if __name__ == '__main__':
    main()
