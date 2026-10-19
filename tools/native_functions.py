"""Derive replacement ownership from recovered PE metadata and compiled objects.
Names are aliases. RVA identity works for unnamed functions and globals, and
no IDA function size or hand-maintained replacement extent is consulted.
"""
from bisect import bisect_right
import collections
import json
import re
import struct
import capstone


def original_rva(name, native):
    match = re.fullmatch(r'replay_rva_([0-9a-fA-F]{8})', name)
    return int(match[1], 16) if match else native.get(name)



class FunctionIndex:
    def __init__(self, manifest, read_data, lengths):
        self.manifest, self.lengths = manifest, lengths
        self.text = manifest['sections'][0]['rva']
        self.entries = set(manifest.get('function_entries', []))
        directory = manifest['directories'][3]
        rows = list(struct.iter_unpack('<III', read_data(directory['rva'], directory['size'])))
        self.rows = rows
        self.families = collections.defaultdict(list)
        self.parents = {}
        self.headers = {}

        def parent(row, active):
            begin, end, unwind = row
            if row in active:
                raise ValueError(f'Cyclic CHAININFO at {begin:#x}')
            if row in self.parents:
                return self.parents[row]
            header = read_data(unwind, 4)
            version, flags = header[0] & 7, header[0] >> 3
            if version not in (1, 2) or flags & ~7 or (flags & 4 and flags & 3):
                raise ValueError(f'Invalid native unwind header at {unwind:#x}')
            extra = unwind+4+((header[2]+1)&~1)*2
            self.headers[unwind] = (extra, flags)
            root = parent(struct.unpack('<III', read_data(extra, 12)), active | {row}) if flags & 4 else begin
            self.parents[row] = root
            return root

        previous = self.text
        for row in rows:
            begin, end, _ = row
            if begin < previous or end < begin:
                raise ValueError('Invalid native runtime-function ordering')
            previous = end
            root = parent(row, set())
            if end > begin:
                self.families[root].append((begin, end))
        self.roots = sorted(self.families)
        self.intervals = sorted((a, b, root) for root, spans in self.families.items() for a, b in spans)
        self.starts = [a for a, _, _ in self.intervals]

    def head(self, rva):
        offset = rva-self.text
        return 0 <= offset < len(self.lengths) and self.lengths[offset] not in (0, 255)

    def owner(self, rva):
        index = bisect_right(self.starts, rva)-1
        if index >= 0 and rva < self.intervals[index][1]:
            return self.intervals[index][2]
        return None

    def leaf(self, entry, text, branch_targets):
        """Prove a bounded leaf CFG; never use the next symbol as an extent.

        A branch into another known entry or unwind family is a tail transfer. An unresolved
        register jump has unknown ownership and requires further recovery.
        """
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        todo, decoded = [entry], {}
        while todo:
            at = todo.pop()
            if at in decoded:
                continue
            if at != entry and (at in self.entries or self.owner(at) is not None):
                continue
            if not self.head(at) or abs(at-entry) > 0x100000 or len(decoded) >= 100000:
                raise ValueError(f'Unproven leaf control flow from {entry:#x} at {at:#x}')
            size = self.lengths[at-self.text]
            item = next(decoder.disasm(text[at-self.text:at-self.text+size], at), None)
            if item is None or item.size > size:
                raise ValueError(f'Invalid reassembled instruction at {at:#x}')
            decoded[at] = at+size
            op = item.mnemonic.split()[-1]
            if op in ('ret', 'retf', 'iretq', 'ud2', 'int3'):
                continue
            if op.startswith(('j', 'loop')):
                target = branch_targets.get(at)
                if target is None:
                    if op == 'jmp' and 'rip' in item.op_str:
                        continue  # Import/vtable tail transfer, no local cases.
                    raise ValueError(f'Unresolved leaf dispatch at {at:#x}; recover its ownership first')
                if target < entry and target not in self.entries and self.owner(target) is None:
                    raise ValueError(f'Unowned backward tail from leaf {entry:#x}')
                todo.append(target)
                if op == 'jmp':
                    continue
            todo.append(at+size)
        spans = []
        for begin, end in sorted(decoded.items()):
            if spans and spans[-1][1] == begin:
                spans[-1][1] = end
            else:
                spans.append([begin, end])
        return spans

    def replacements(self, objects, native, text, branch_targets):
        requests = {}
        for obj in objects:
            for symbol in obj['symbols'].values():
                if symbol['section'] <= 0 or symbol['storage'] != 2:
                    continue
                section = obj['sections'][symbol['section']-1]
                if section.get('discarded'):
                    continue
                target = original_rva(symbol['name'], native)
                if target is None:
                    continue
                if not section['flags'] & 0x20:
                    raise ValueError(f'Native global redefinition requires an explicit data migration: {symbol["name"]}')
                if symbol['value'] or not self.head(target):
                    raise ValueError(f'Replacement is not a proven function entry: {symbol["name"]}')
                if target in requests:
                    raise ValueError(f'Multiple C++ definitions replace native entry {target:#x}')
                requests[target] = (symbol['name'], obj['path'], section)
        result = []
        for target, (name, source, section) in sorted(requests.items()):
            owner = self.owner(target)
            if owner is not None and owner != target:
                raise ValueError(f'{name} is an interior/shared unwind entry owned by {owner:#x}')
            spans = self.families.get(target) or self.leaf(target, text, branch_targets)
            merged = []
            for a, b in sorted(spans):
                if merged and merged[-1][1] == a:
                    merged[-1][1] = b
                else:
                    merged.append([a, b])
            for a, b in merged:
                result.append(dict(symbol=name if a == target else f'{name}$retired_{a:08x}',
                                   owner=name, begin=a, end=b, entry=target, retired=a != target,
                                   source=source, provenance='PE unwind family' if owner is not None else 'decoded leaf CFG'))
        return sorted(result, key=lambda r: r['begin'])

    def report(self, native):
        aliases = collections.defaultdict(list)
        for name, rva in native.items():
            if self.head(rva):
                aliases[rva].append(name)
        rows = []
        for entry in sorted(set(self.families) | set(aliases)):
            owner = self.owner(entry)
            rows.append(dict(identity=f'replay_rva_{entry:08x}', rva=entry, aliases=sorted(aliases[entry]),
                             owner=owner, chunks=self.families.get(entry, []),
                             status='unwind-family' if entry in self.families else 'interior-label' if owner is not None else 'leaf-candidate'))
        return dict(schema=2, input_sha256=self.manifest['input_sha256'], functions=rows,
                    runtime_ranges=len(self.rows), unwind_families=len(self.families),
                    unnamed_families=sum(not aliases[r] or all(n.startswith(('sub_', 'replay_rva_')) for n in aliases[r]) for r in self.families))


def branch_references(manifest, assembly_objects, lengths):
    """Read direct branch identities from source relocations, not guessed bytes."""
    targets = dict(manifest['short_references'])
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    text_start = manifest['sections'][0]['rva']
    for obj, section in assembly_objects.values():
        origin = section['original_rva']
        for offset, index, kind in section['relocations']:
            if not 4 <= kind <= 9:
                continue
            symbol = obj['symbols'][index]
            target = original_rva(symbol['name'], {})
            if target is None:
                continue
            head = origin+offset
            while head > origin and lengths[head-text_start] == 255:
                head -= 1
            size = lengths[head-text_start]
            i = next(decoder.disasm(section['data'][head-origin:head-origin+size], head), None)
            if i and i.mnemonic.split()[-1].startswith(('j', 'loop')):
                targets[head] = target+struct.unpack_from('<i', section['data'], offset)[0]
    return targets
