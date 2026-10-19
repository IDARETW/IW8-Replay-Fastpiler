"""Protect terminal unowned IDA entries without inventing code semantics.

An IDA decoder head is not a function-ownership proof. These spans are input
data with unknown execution/relocation semantics until further native review.
Encoded payload stays byte-for-byte at its original RVA. Independently proven
callback thunks may relocate only their certified RIP-relative operands.
"""
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct

FILE = 'terminal_unowned_spans.json'


class Spans:
    def __init__(self, rows=(), entries=0):
        self.rows = sorted(rows, key=lambda row: row['begin'])
        self.starts = [row['begin'] for row in self.rows]
        self.entries = entries
        self.callback_thunks = []
        previous = -1
        for row in self.rows:
            if row['begin'] < previous:
                raise ValueError('Terminal unowned spans overlap; review their native ownership')
            previous = row['end']

    def overlaps(self, begin, end):
        if end <= begin:
            return False
        index = bisect_right(self.starts, begin) - 1
        if index >= 0 and self.rows[index]['end'] > begin:
            return True
        index += 1
        return index < len(self.rows) and self.rows[index]['begin'] < end

    def contains(self, rva):
        return self.overlaps(rva, rva + 1)

    def mask(self, start, size):
        result = bytearray(size)
        for row in self.rows:
            begin, end = row['begin'] - start, row['end'] - start
            if not 0 <= begin < end <= size:
                raise ValueError('Terminal unowned span is outside the recovered text map')
            result[begin:end] = b'\1' * (end - begin)
        return result

    def verify_layout(self, layout):
        for row in self.rows:
            begin, end = row['begin'], row['end']
            if any(item['begin'] < end and item['end'] > begin for item in layout.replacements):
                raise ValueError(f'C++ replacement overlaps unproven native bytes at {begin:#x}')
            if (layout.map(begin) != begin or layout.map(end - 1) != end - 1 or
                    any(begin < point < end for point in layout.points)):
                raise ValueError(f'Build moves terminal unowned bytes at {begin:#x}; '
                                 'their relocation semantics must be recovered first')

    def prove_callback_thunks(self, manifest, assembly_objects, lengths, confidence, read_data):
        """Recognize an argument-preserving callback thunk, never arbitrary code.

        Require the complete instruction template and padding, adjacent writable
        zero-initialized pointer slots, and a strong external LEA reference.
        Only the two indirect-control-transfer displacement fields are mutable.
        """
        text_start = manifest['sections'][0]['rva']
        producers = {}
        for obj, code in assembly_objects.values():
            for offset, symbol_index, kind in code['relocations']:
                name = obj['symbols'][symbol_index]['name']
                match = re.fullmatch(r'replay_rva_([0-9a-fA-F]{8})', name)
                at = code['original_rva'] + offset - 3
                index = at - text_start
                prefix = code['data'][offset - 3:offset]
                if (kind != 4 or not match or offset < 3 or not 0 <= index < len(lengths) or
                        lengths[index] != 7 or confidence[index] != 2 or
                        len(prefix) != 3 or prefix[0] not in (0x48, 0x4c) or
                        prefix[1] != 0x8d or prefix[2] & 0xc7 != 5 or
                        self.overlaps(at, at + 7) or
                        struct.unpack_from('<i', code['data'], offset)[0] != 0):
                    continue
                producers.setdefault(int(match[1], 16), []).append(at)
        prefix = bytes.fromhex('415052514883ec20ff15')
        middle = bytes.fromhex('4883c420595a4158ff25')
        rows = []
        for region in self.rows:
            raw, offset = region['raw'], 0
            while True:
                offset = raw.find(prefix, offset)
                if offset < 0:
                    break
                rva = region['begin'] + offset
                body = raw[offset:offset + 32]
                offset += 1
                if (rva % 16 or len(body) != 32 or body[14:24] != middle or
                        body[28:] != b'\xcc' * 4 or rva not in producers):
                    continue
                first = rva + 14 + struct.unpack_from('<i', body, 10)[0]
                second = rva + 28 + struct.unpack_from('<i', body, 24)[0]
                sections = [s for s in manifest['sections'] if s['flags'] & 0x80000000 and
                            s['rva'] <= first and second + 8 <= s['rva'] + s['virtual_size']]
                if first % 8 or second != first + 8 or len(sections) != 1:
                    raise ValueError('Recognized callback thunk has invalid native pointer slots')
                if read_data(first, 16) != b'\0' * 16:
                    raise ValueError('Recognized callback thunk pointer slots are not zero-initialized')
                rows.append(dict(rva=rva, size=32, sha256=hashlib.sha256(body).hexdigest(),
                                 raw_hex=body.hex(), producers=sorted(producers[rva]),
                                 references=[dict(offset=10, target=first), dict(offset=24, target=second)],
                                 proof='complete callback instruction template; strong external LEA; adjacent writable zero pointer slots'))
        self.callback_thunks = rows
        return rows

    def verify_bytes(self, text, text_start, layout=None):
        for row in self.rows:
            blob = bytes(text[row['begin'] - text_start:row['end'] - text_start])
            expected = bytearray(row['raw'])
            if layout is not None:
                for thunk in self.callback_thunks:
                    if row['begin'] <= thunk['rva'] and thunk['rva'] + thunk['size'] <= row['end']:
                        for reference in thunk['references']:
                            site = thunk['rva'] + reference['offset']
                            value = layout.resolve(reference['target']) - (layout.map(site) + 4)
                            struct.pack_into('<i', expected, site - row['begin'], value)
            if blob != expected:
                raise ValueError(f'Build changed terminal unowned bytes at {row["begin"]:#x}')
        return dict(entries=self.entries, spans=len(self.rows),
                    bytes=sum(row['end'] - row['begin'] for row in self.rows),
                    status=('original_rvas_and_certified_callback_operands_verified'
                            if layout is not None and self.callback_thunks else 'original_rvas_and_exact_bytes_verified'),
                    certified_callback_thunks=len(self.callback_thunks),
                    certified_callback_operand_bytes=sum(len(r['references']) * 4 for r in self.callback_thunks),
                    relocation_semantics='unproven')


def load(root, input_sha256, input_md5, text_start, text_end, read=None):
    path = Path(root) / FILE
    if not path.exists():
        return Spans()
    document = json.loads(path.read_text(encoding='utf-8-sig'))
    if (document.get('schema') != 1 or document.get('input_sha256') != input_sha256 or
            str(document.get('input_md5', '')).lower() != input_md5.lower()):
        raise ValueError('Terminal unowned evidence belongs to another native image')
    if not isinstance(document.get('entries'), list):
        raise ValueError('Terminal unowned evidence has no explicit entry inventory')
    rows, identities = [], set()
    def checked_span(span):
        begin, end = span['begin'], span['end']
        if (not isinstance(begin, int) or isinstance(begin, bool) or
                not isinstance(end, int) or isinstance(end, bool) or
                not text_start <= begin < end <= text_end):
            raise ValueError('Terminal unowned span has an invalid native text extent')
        raw = bytes.fromhex(span['raw_hex'])
        digest = span['sha256']
        if (len(raw) != end - begin or not re.fullmatch('[0-9a-f]{64}', digest) or
                hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError('Terminal unowned span bytes do not match their receipt')
        if read is not None and read(begin, end - begin) != raw:
            raise ValueError('Terminal unowned span does not match the original native image')
        return dict(begin=begin, end=end, sha256=digest, raw=raw)

    regions = []
    if not isinstance(document.get('regions', []), list):
        raise ValueError('Terminal unowned regions have no explicit inventory')
    for region in document.get('regions', []):
        if (region.get('relocation_semantics') != 'unproven' or
                region.get('proof', {}).get('kind') != 'encoded_address_unwind_gap'):
            raise ValueError('Terminal unowned region has no native gap proof')
        regions.append(checked_span(region))
    # Validate regions independently before allowing entry chunks to share one.
    region_index = Spans(regions)
    rows.extend(regions)
    for entry in document['entries']:
        rva = entry['rva']
        if not isinstance(rva, int) or isinstance(rva, bool) or rva in identities:
            raise ValueError('Terminal unowned evidence has an invalid or duplicate identity')
        identities.add(rva)
        if entry.get('relocation_semantics') != 'unproven' or entry.get('containing_proven_owner'):
            raise ValueError('Terminal unowned evidence conflicts with proven native ownership')
        spans = entry.get('spans', [])
        if not spans or [[s['begin'], s['end']] for s in spans] != entry.get('chunks'):
            raise ValueError('Terminal unowned evidence has inconsistent native chunks')
        if not any(span['begin'] == rva for span in spans):
            raise ValueError('Terminal unowned evidence has no primary entry chunk')
        for span in spans:
            checked = checked_span(span)
            begin, end = checked['begin'], checked['end']
            if region_index.overlaps(begin, end):
                parent = next((row for row in regions if row['begin'] <= begin and end <= row['end']), None)
                if parent is None or parent['raw'][begin-parent['begin']:end-parent['begin']] != checked['raw']:
                    raise ValueError('Terminal unowned entry conflicts with its protected region')
            else:
                rows.append(dict(**checked, rva=rva))
    return Spans(rows, len(identities))
