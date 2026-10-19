"""Fetch current or pinned CASC frontend inputs and record per-file provenance.

This catalog describes source data. It does not declare a fastfile compatible
with Replay. Format adapters and native-game validation are separate gates.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def versions(text):
    lines = [line for line in text.splitlines() if line and not line.startswith('#')]
    if not lines:
        raise ValueError('Empty CASC versions document')
    names = [column.split('!')[0] for column in lines[0].split('|')]
    rows = [dict(zip(names, line.split('|'), strict=True)) for line in lines[1:]]
    matches = [row for row in rows if row.get('Region') == 'us']
    if len(matches) != 1:
        raise ValueError('No unique US CASC build identity')
    return matches[0]


def fastfile_header(raw):
    if len(raw) < 19 or raw[:8] not in (b'IWffa100', b'IWffc100'):
        raise ValueError('Unsupported or truncated frontend fastfile header')
    header, revision = struct.unpack_from('<II', raw, 8)
    return dict(magic=raw[:8].decode(), header_version=header, xfile_version=revision,
                compression=raw[16], encryption=raw[17], transient_type=raw[18])


def file_formats(path):
    with path.open('rb') as stream:
        raw = stream.read(4096)
    if path.suffix == '.ff':
        return dict(base=fastfile_header(raw))
    if path.suffix not in ('.fp', '.fc'):
        return {}
    if raw[:8] != b'IWffd100':
        raise ValueError(f'Unknown patch container: {path}')
    # IW patches contain the complete previous and target FF headers. Locate
    # their signatures in the bounded patch-header prefix, never in payloads.
    offsets = [m.start() for m in re.finditer(b'IWff[ac]100', raw)]
    if len(offsets) != 2 or offsets[0] != 56:
        raise ValueError(f'Unrecognized patch header pair: {path}: {offsets}')
    return dict(patch_version=struct.unpack_from('<I', raw, 8)[0],
                previous=fastfile_header(raw[offsets[0]:]),
                target=fastfile_header(raw[offsets[1]:]))


def make_catalog(cache, output, log, requested):
    opened = re.findall(r'^opened product=(\w+) build=(\d+) requested=(\w+)$', log, re.M)
    if len(opened) != 1 or opened[0][0] != 'odin':
        raise ValueError('Extraction did not identify one opened Odin build')
    product, build, selected = opened[0]
    if selected != (requested or 'latest'):
        raise ValueError('Extraction selection disagrees with request')
    version_bytes = (cache / 'versions').read_bytes()
    current = versions(version_bytes.decode('utf-8-sig'))
    receipts = re.findall(r'^selected build-config=([0-9a-f]{32}) root-ckey=([0-9a-f]{32}) '
                          r'encoding-ckey=([0-9a-f]{32}) endpoint-build-property=(\d+)$', log, re.M)
    if len(receipts) > 1:
        raise ValueError('Ambiguous selected CASC storage identity')
    actual_key = receipts[0][0] if receipts else None
    expected_key = requested or current['BuildConfig']
    if actual_key and actual_key != expected_key:
        raise ValueError('Opened CASC storage does not match the selected build config')
    if requested and not actual_key:
        raise ValueError('Historical extraction requires an actual selected build-config receipt')
    if not requested and int(current['BuildId']) != int(build):
        raise ValueError('Resolved latest build does not match cached versions receipt')
    if requested and current['BuildConfig'] != requested:
        # CascLib's BuildNumber property can retain the current endpoint's
        # number after a historical config-key override. It is not historical
        # provenance; only the actual selected configuration is authoritative.
        current = None
    rows = []
    with (output / 'casc-files.tsv').open(newline='', encoding='utf-8') as stream:
        manifest = list(csv.DictReader(stream, delimiter='\t'))
    seen = set()
    for item in manifest:
        relative = PurePosixPath(item['path'])
        if relative.is_absolute() or '..' in relative.parts or ':' in str(relative):
            raise ValueError('Manifest path escapes extraction root')
        path = (output / relative).resolve()
        if not path.is_relative_to(output.resolve()) or str(relative).casefold() in seen:
            raise ValueError('Escaping or duplicate extraction path')
        seen.add(str(relative).casefold())
        if path.stat().st_size != int(item['bytes']):
            raise ValueError(f'Extraction length changed: {path}')
        if not all(re.fullmatch('[0-9a-f]{32}', item[key]) for key in ('ckey', 'ekey')):
            raise ValueError('Invalid CASC content or encoding key')
        rows.append(dict(path=str(relative), bytes=path.stat().st_size, sha256=digest(path),
                         ckey=item['ckey'], ekey=item['ekey'], **file_formats(path)))
    if not rows:
        raise ValueError('Empty frontend extraction')
    by_name = {item['path']: item for item in rows}
    for item in rows:
        if 'previous' not in item:
            continue
        name = item['path'][:-3]
        prior = by_name.get(name + ('.fp' if item['path'].endswith('.fc') and name + '.fp' in by_name else '.ff'))
        if prior is None or item['previous'] != prior.get('target', prior.get('base')):
            raise ValueError(f'Patch chain header does not match its predecessor: {item["path"]}')
    scenes = sorted({Path(item['path']).stem for item in rows
                     if re.fullmatch(r'mp_frontend[a-z0-9]+\.ff', item['path'])})
    catalog = dict(schema=1, product=product, requested_build_key=requested,
                   endpoint_build_property=int(build),
                   resolved_build_number=int(current['BuildId']) if current else None,
                   resolved_build_key=actual_key or current['BuildConfig'],
                   selected_root_ckey=receipts[0][1] if receipts else None,
                   selected_encoding_ckey=receipts[0][2] if receipts else None,
                   release_version=current['VersionsName'] if current else None,
                   cdn_config=current['CDNConfig'] if current else None,
                   versions_sha256=hashlib.sha256(version_bytes).hexdigest(),
                   generated_utc=datetime.now(timezone.utc).isoformat(),
                   extraction='CascLib strict content validation and existing-file byte comparison',
                   compatibility='Source inventory only; no Replay compatibility assertion',
                   scenes=scenes, default_scene='mp_frontendc3s5' if 'mp_frontendc3s5' in scenes else None,
                   files=rows)
    temporary = output / 'frontend-source.json.part'
    temporary.write_text(json.dumps(catalog, indent=2) + '\n')
    temporary.replace(output / 'frontend-source.json')
    (output / 'resolved-versions.txt').write_bytes(version_bytes)
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build-key', help='Omit to ask CASC for the current online build')
    parser.add_argument('--mask', default='*mp_frontend*')
    parser.add_argument('--from-log', type=Path, help='Catalog an already completed strict extraction')
    args = parser.parse_args()
    if args.build_key and not re.fullmatch('[0-9a-fA-F]{32}', args.build_key):
        parser.error('build key must contain 32 hexadecimal digits')
    if args.from_log:
        log = args.from_log.read_text(encoding='utf-8-sig')
    else:
        args.output.mkdir(parents=True, exist_ok=True)
        log_path = args.output / 'extraction.log'
        command = [str(ROOT / 'tools/bin/casc_frontend.exe'), str(args.cache.resolve()),
                   str(args.output.resolve()), args.build_key or '--latest', args.mask]
        with log_path.open('w', encoding='utf-8') as stream:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        log = log_path.read_text()
    if not re.search(r'^extracted or verified [1-9][0-9]* matching files$', log, re.M):
        raise ValueError('No completed extraction receipt')
    result = make_catalog(args.cache, args.output, log, args.build_key)
    print(json.dumps({key: result[key] for key in ('release_version', 'resolved_build_key', 'scenes', 'default_scene')}))


if __name__ == '__main__':
    main()
