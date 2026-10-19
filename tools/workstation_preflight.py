"""Check the local Replay workstation's actual compiler inputs and tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game', type=Path, required=True)
    parser.add_argument('--sqlite', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    def check(name, path):
        path = Path(path) if path else None
        rows.append({'name': name, 'path': str(path) if path else None, 'ready': bool(path and path.is_file())})
    check('Replay executable', args.game / 'game_dx12_ship_replay.exe')
    check('Replay SQLite reference', args.sqlite)
    check('Recovered compiler manifest', ROOT / 'generated' / 'manifest.json')
    check('Function catalog', ROOT / 'generated' / 'function-catalog.json')
    llvm = Path(os.environ.get('REPLAY_LLVM_ROOT', r'C:\Program Files\LLVM\bin'))
    for tool in ('clang.exe', 'clang++.exe', 'llvm-readobj.exe'):
        check(tool, shutil.which(tool) or llvm / tool)
    try:
        from build import MASM
        check('Microsoft x64 assembler', MASM)
    except ImportError as error:
        rows.append({'name': 'Compiler dependencies', 'ready': False, 'error': str(error)})
    for module in ('pefile', 'capstone', 'unicorn'):
        try:
            __import__(module)
            rows.append({'name': module, 'ready': True})
        except ImportError:
            rows.append({'name': module, 'ready': False})
    print(json.dumps({'ready': all(row['ready'] for row in rows), 'checks': rows}, indent=2))
    return 0 if all(row['ready'] for row in rows) else 1


if __name__ == '__main__':
    sys.exit(main())
