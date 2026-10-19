"""Prepare a clean workstation from the owner's Replay image and analysis seeds.

Seeds contain analysis boundaries/references, not section data or assembled game
code. Recovery obtains bytes from the hash-pinned owner-provided executable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
from contextlib import closing
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def _validate_proxy_source(path):
    if path is None:
        return None
    source = Path(path).expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f'Configured Replay proxy source directory does not exist: {source}')
    if not any(source.glob('*.cpp')):
        raise ValueError(f'Configured Replay proxy source directory has no top-level C++ sources: {source}')
    return source


def validate_proxy_pattern_seed(path):
    path = Path(path)
    entries = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(entries, list):
        raise ValueError('Generated Replay proxy-pattern seed is not an entry list')
    names = {item.get('name') for item in entries if isinstance(item, dict)}
    return {'count': len(entries), 'required_binding_count': 0,
            'required_bindings': []}


def prepare(root, game, database, recover=True, proxy_source=None):
    root, game, database = Path(root).resolve(), Path(game).resolve(), Path(database).resolve()
    proxy_source = _validate_proxy_source(proxy_source or os.environ.get('REPLAY_PROXY_SOURCE'))
    executable = game / 'game_dx12_ship_replay.exe'
    seed_root = root / 'analysis/replay120'
    seed = json.loads((seed_root / 'seed.json').read_text(encoding='utf-8'))
    if seed.get('schema') != 1 or digest(executable) != seed['image_sha256']:
        raise ValueError('The supplied executable does not match the Replay 1.20 analysis profile')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        row = db.execute('SELECT md5sum FROM program').fetchone()
        identity = row[0] if row else None
        if isinstance(identity, bytes):
            identity = identity.hex() if len(identity) == 16 else identity.decode('ascii')
        if not isinstance(identity, str) or identity.casefold() != seed['image_md5']:
            raise ValueError('The SQLite reference belongs to a different game image')
    generated = root / 'generated'
    generated.mkdir(exist_ok=True)
    for name, expected in seed['files'].items():
        if Path(name).name != name:
            raise ValueError('Analysis seed file must have a flat relative name')
        source, target = seed_root / name, generated / name
        if digest(source) != expected:
            raise ValueError(f'Analysis seed hash mismatch: {name}')
        if target.exists():
            if digest(target) != expected:
                raise ValueError(f'Existing analysis input differs from the seed: {name}; preserve and review it before replacing')
        else:
            temporary = target.with_suffix(target.suffix + '.preparing')
            shutil.copyfile(source, temporary)
            if digest(temporary) != expected:
                raise ValueError(f'Copied analysis seed differs: {name}')
            temporary.replace(target)
    if recover and not (generated / 'manifest.json').exists():
        recovery_env = {**os.environ, 'REPLAY_GAME_ROOT': str(game),
                        'REPLAY_SQLITE': str(database)}
        if proxy_source is not None:
            recovery_env['REPLAY_PROXY_SOURCE'] = str(proxy_source)
        subprocess.run([sys.executable, str(root / 'tools/recover.py'), '--exe', str(executable)],
                       cwd=root, check=True, env=recovery_env)
    proxy_bindings = None
    if recover and proxy_source is not None:
        # Recovery may already exist from an engine-only setup. Re-export native
        # signatures from the explicitly selected proxy source instead of
        # silently retaining the smaller baseline registry.
        proxy_env = {**os.environ, 'REPLAY_GAME_ROOT': str(game),
                     'REPLAY_SQLITE': str(database),
                     'REPLAY_PROXY_SOURCE': str(proxy_source)}
        subprocess.run([sys.executable, str(root / 'tools/proxy_patterns.py'),
                        '--native', str(executable)], cwd=root, check=True, env=proxy_env)
        proxy_bindings = validate_proxy_pattern_seed(generated / 'proxy-patterns.json')
    elif recover and (generated / 'proxy-patterns.json').is_file():
        # Report the naturally selected engine-only seed when no adapted proxy
        # source was supplied; this is a distinct supported profile.
        entries = json.loads((generated / 'proxy-patterns.json').read_text(encoding='utf-8'))
        proxy_bindings = {'count': len(entries), 'required_binding_count': 0,
                          'required_bindings': [], 'profile': 'unvalidated-existing-seed'}
    return {'profile': seed['profile'], 'image_sha256': seed['image_sha256'],
            'analysis_inputs': len(seed['files']), 'recovered': (generated / 'manifest.json').is_file(),
            'proxy_source': str(proxy_source) if proxy_source is not None else None,
            'proxy_bindings': proxy_bindings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--game', type=Path, required=True)
    parser.add_argument('--sqlite', type=Path, required=True)
    parser.add_argument('--proxy-source', type=Path,
                        help='Owner-provided Replay proxy source directory; enables and validates its full source-derived signature set.')
    parser.add_argument('--seeds-only', action='store_true')
    args = parser.parse_args()
    print(json.dumps(prepare(args.root, args.game, args.sqlite, not args.seeds_only,
                             args.proxy_source), indent=2))


if __name__ == '__main__':
    main()
