"""Read the complete serialized XAssetList before any asset-reader adapters run.

A loader's exported CSV can stop at its first unsupported asset. It is not a
complete inventory unless its rows cover this source table.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

INLINE = {0xffffffffffffffff, 0xfffffffffffffffe}


def inspect(data):
    if len(data) < 32:
        raise ValueError('truncated XAssetList root')
    string_count, reserved0, strings, count, reserved1, assets = struct.unpack_from('<IIQIIQ', data)
    if reserved0 or reserved1:
        raise ValueError('unverified XAssetList reserved fields')
    if strings not in INLINE and not (strings == 0 and string_count == 0):
        raise ValueError('unsupported script-string array token')
    if assets not in INLINE and not (assets == 0 and count == 0):
        raise ValueError('unsupported XAsset array token')
    if string_count > (len(data) - 32) // 8:
        raise ValueError('script-string array exceeds file')
    at = 32 + string_count * 8
    for index in range(string_count):
        token = struct.unpack_from('<Q', data, 32 + index * 8)[0]
        if token in INLINE:
            try:
                at = data.index(b'\0', at) + 1
            except ValueError as error:
                raise ValueError('unterminated script string') from error
        elif token:
            raise ValueError('unverified packed script-string token')
    # Alignment advances the logical archive stream, not physical .dec bytes.
    table = at
    if count > (len(data) - table) // 16:
        raise ValueError('XAsset array exceeds file')
    rows = []
    for index in range(count):
        kind, reserved, pointer = struct.unpack_from('<IIQ', data, table + index * 16)
        if reserved or kind > 255:
            raise ValueError(f'unverified XAsset entry at index {index}')
        rows.append(dict(index=index, type_id=kind, pointer_token=hex(pointer)))
    return dict(script_string_count=string_count, asset_count=count,
                asset_table_offset=table, first_payload_offset=table + count * 16,
                type_counts=dict(sorted(Counter(r['type_id'] for r in rows).items())),
                assets=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.source.read_bytes()
    report = inspect(data)
    report.update(source=str(args.source.resolve()), source_sha256=hashlib.sha256(data).hexdigest())
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'assets'}))


if __name__ == '__main__':
    main()
