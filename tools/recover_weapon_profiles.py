"""Recover explicit, versioned weapon traversal plans from native-reader traces."""
from pathlib import Path
import hashlib
import json

import pefile
from trace_weapon_readers import trace, ORIGINAL, REFERENCE, ROOT

WEAPON = [
    (0x160, 0x168, None, None), (0x168, 0x170, None, None),
    (0x170, 0x178, None, None), (0x178, 0x180, None, None),
    (0x180, 0x188, None, None), (0x770, 0x790, None, None),
    (0x778, 0x798, None, None), (0xbe8, 0xc08, 0xbe4, 0xc04),
    (0xbf8, 0xc18, 0xbf0, 0xc10), (0xc18, 0xc38, 0x6224, 0x622c),
    (0xc20, 0xc40, 0x6226, 0x622e), (0xd10, 0xd28, None, None),
    (0xd18, 0xd30, None, None), (0x1230, 0x1248, 0x1228, 0x1240),
    (0x12b8, 0x12d0, 0x12b0, 0x12c8), (0x12c8, 0x12e0, 0x12c0, 0x12d8),
]
PARENT = [
    (8, 8, None, None), (0x20, 0x28, None, None),
    (0x110, 0x118, 0x10c, 0x110), (0x118, 0x120, 0x10c, 0x110),
    (0x128, 0x130, 0x120, 0x128), (0x138, 0x140, 0x130, 0x138),
    (0x228, 0x230, 0x224, 0x22c), (0x230, 0x238, 0x226, 0x22e),
]


def recover():
    paths = (ORIGINAL, REFERENCE)
    expected = ('68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0',
                'fb8339c58c2f4e991a7ceafdb97392f2b5032614f46fdfe09d031c139d2fe202')
    for path, sha in zip(paths, expected):
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha: raise ValueError('Native analysis input changed')
    images = [pefile.PE(str(path), fast_load=True) for path in paths]
    result = dict(replay_sha256=expected[0], reference_sha256=expected[1], records={})
    for name, fields in (('WeaponDef', WEAPON), ('WeaponCompleteDef', PARENT)):
        baseline = [trace(image, name, bool(which)) for which, image in enumerate(images)]
        owned = []
        for old, new, old_count, new_count in fields:
            traces = []
            for which, image in enumerate(images):
                offset = (old, new)[which]; count = (old_count, new_count)[which]
                overrides = [(offset, 2**64-2, 8)]
                if count is not None: overrides.append((count, 1, 2 if offset in (0xc18, 0xc20, 0xc38, 0xc40, 0x228, 0x230, 0x238) else 4))
                traces.append(trace(image, name, bool(which), overrides))
            owned.append(dict(replay_offset=old, mw131_offset=new, replay_count_offset=old_count,
                              mw131_count_offset=new_count, replay=traces[0], mw131=traces[1]))
        result['records'][name] = dict(baseline=dict(replay=baseline[0], mw131=baseline[1]), owned=owned)
    destination = ROOT / 'evidence/weapon-native-profile-traces.json'
    destination.write_text(json.dumps(result, indent=2) + '\n')
    for name, record in result['records'].items():
        print(name)
        baseline = record['baseline']['replay']
        keys = {e['call'] for e in baseline}
        for field in record['owned']:
            inserted = [e for e in field['replay'] if e['call'] not in keys or any(g != 'd120c00' for g in e['allocated']) and e['name'] != 'stream']
            print(hex(field['replay_offset']), '=>', hex(field['mw131_offset']),
                  [(e['call'],e['name'],e['cx'],e['dx'],e['allocated']) for e in inserted])
    return result


if __name__ == '__main__': recover()
