"""Validate and adopt one closed, same-build IDA native-analysis snapshot.

The compiler regenerates assembly when these inputs change. This deliberately
does not replace generated instruction lengths or source catalogs with IDA's
guesses; those are computed by the normal recovery sequence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path

import pefile
import native_unproven

FILES = (
    'code-items.bin', 'noncode-items.bin', 'ida-code-report.json',
    'ida-rva-fixups.bin', 'ida-immediate-references.json',
    'ida-switch-references.json', 'ida-reference-report.json',
)


def digest(path, algorithm='sha256'):
    value = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def records(path, layout):
    raw = Path(path).read_bytes()
    if len(raw) % struct.calcsize(layout):
        raise ValueError(f'Truncated native-analysis records: {path}')
    return struct.iter_unpack(layout, raw)


def validate(snapshot, exe, idb):
    snapshot, exe, idb = map(lambda p: Path(p).resolve(), (snapshot, exe, idb))
    receipt = json.loads((snapshot / 'snapshot-receipt.json').read_text(encoding='utf-8'))
    if receipt.get('status') != 'complete' or receipt.get('processor') != 'metapc' or receipt.get('bitness') != 2:
        raise ValueError('Native snapshot is not a completed metapc/x64 export')
    if Path(receipt['idb_path']).resolve() != idb:
        raise ValueError('Native snapshot belongs to a different fresh IDB')
    if any(idb.with_suffix(suffix).exists() for suffix in ('.id0', '.id1', '.id2')):
        raise ValueError('Close the fresh IDB before adopting its native snapshot')
    md5, sha256 = digest(exe, 'md5'), digest(exe)
    if receipt.get('input_md5') != md5 or receipt.get('input_sha256') != sha256:
        raise ValueError('Native snapshot executable fingerprint does not match')
    idb_hash = digest(idb)
    if receipt.get('idb_sha256') != idb_hash:
        raise ValueError('Closed fresh IDB fingerprint does not match the snapshot receipt')
    outputs = receipt.get('outputs', {})
    names = list(FILES)
    guard_name = native_unproven.FILE
    if guard_name in outputs:
        names.append(guard_name)
    elif (snapshot / guard_name).exists():
        raise ValueError('Terminal unowned evidence is missing from the native snapshot receipt')
    for name in names:
        path = snapshot / name
        expected = outputs.get(name, {})
        if not path.is_file() or expected.get('bytes') != path.stat().st_size or expected.get('sha256') != digest(path):
            raise ValueError(f'Native snapshot file fingerprint does not match: {name}')
    if any(snapshot.glob('*-error.txt')):
        raise ValueError('Native snapshot contains an export error')

    pe = pefile.PE(str(exe), fast_load=True)
    try:
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b:
            raise ValueError('Native snapshot requires the x64 PE32+ executable')
        text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
        start = text.VirtualAddress
        alignment = pe.OPTIONAL_HEADER.SectionAlignment
        mapped_size = max(text.Misc_VirtualSize, text.SizeOfRawData)
        end = start + ((mapped_size + alignment - 1) // alignment) * alignment
        following = [s.VirtualAddress for s in pe.sections if s.VirtualAddress > start]
        if following:
            end = min(end, min(following))
        base, image_size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
        unproven = native_unproven.load(snapshot, sha256, md5, start,
                                       start + text.SizeOfRawData, pe.get_data)
        if unproven.rows:
            pe.parse_data_directories(directories=[3, 5])
            for entry in getattr(pe, 'DIRECTORY_ENTRY_EXCEPTION', []):
                if unproven.overlaps(entry.struct.BeginAddress, entry.struct.EndAddress):
                    raise ValueError('Terminal unowned spans overlap a native unwind owner')
            for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
                for entry in block.entries:
                    width = 8 if entry.type == 10 else 4
                    if entry.type and unproven.overlaps(entry.rva, entry.rva + width):
                        raise ValueError('Terminal unowned spans contain a native loader relocation')
                    # A relocated pointer is native evidence of a referenced
                    # entry even when IDA failed to retain its data cross-ref.
                    # Only interpret the complete pointer relocation kinds;
                    # split HIGH/LOW fields do not encode an independent VA.
                    if entry.type in (3, 10):
                        raw = pe.get_data(entry.rva, width)
                        if len(raw) != width:
                            raise ValueError('Native loader pointer lies outside mapped image data')
                        target = int.from_bytes(raw, 'little') - base
                        if unproven.contains(target):
                            raise ValueError('Terminal unowned spans have a native loader pointer target')
        code_report = json.loads((snapshot / 'ida-code-report.json').read_text())
        refs_report = json.loads((snapshot / 'ida-reference-report.json').read_text())
        for report in (receipt, code_report, refs_report):
            if report.get('input_md5') != md5 or report.get('image_base') != base:
                raise ValueError('Native snapshot reports disagree on the source image')
        if (code_report.get('text_start'), code_report.get('text_end')) != (start, end):
            raise ValueError('Native snapshot text extent does not match the PE')
        if refs_report.get('image_size') != image_size or refs_report.get('processor') != 'metapc':
            raise ValueError('Native reference report has the wrong image layout')

        # Merge the two sorted streams without allocating one Python object for
        # every instruction. Together they must describe every text byte once.
        code = iter(records(snapshot / 'code-items.bin', '<IB'))
        data = iter(records(snapshot / 'noncode-items.bin', '<IIB'))
        c, d = next(code, None), next(data, None)
        position, count, code_bytes, data_bytes = start, 0, 0, 0
        while c is not None or d is not None:
            is_code = c is not None and (d is None or c[0] <= d[0])
            row = c if is_code else d
            at, size = row[:2]
            if at != position or size <= 0 or at + size > end:
                raise ValueError(f'Native text snapshot has a gap, overlap or invalid range at {at:#x}')
            if is_code:
                if size > 15:
                    raise ValueError(f'Invalid x64 instruction size at {at:#x}')
                count += 1
                code_bytes += size
                c = next(code, None)
            else:
                if row[2] not in (0, 2):
                    raise ValueError(f'Invalid native data classification at {at:#x}')
                data_bytes += size
                d = next(data, None)
            position += size
        if position != end or (count, code_bytes, data_bytes) != (
                code_report['instruction_count'], code_report['instruction_bytes'], code_report['noncode_bytes']):
            raise ValueError('Native text snapshot counts do not match its report')

        fixup_count = 0
        for at, target, width in records(snapshot / 'ida-rva-fixups.bin', '<III'):
            if width != 4 or not 0 <= at <= image_size - width or not 0 < target < image_size:
                raise ValueError(f'Invalid image-relative data field at {at:#x}')
            raw = pe.get_data(at, width)
            if len(raw) != width or int.from_bytes(raw, 'little') != target:
                raise ValueError(f'Image-relative field does not match the original PE at {at:#x}')
            fixup_count += 1
        immediate = json.loads((snapshot / 'ida-immediate-references.json').read_text())
        switches = json.loads((snapshot / 'ida-switch-references.json').read_text())
        for row in immediate:
            if not start <= row['rva'] < end or not 0 < row['target'] < image_size or row['kind'] not in ('immediate', 'displacement'):
                raise ValueError('Invalid image-relative instruction reference')
        for row in switches:
            if (not 0 <= row['at'] <= image_size - 4 or not 0 <= row['target'] < image_size or
                    not 0 <= row['base'] < image_size or not 0 <= row['shift'] <= 31):
                raise ValueError('Invalid image-relative switch reference')
        if (fixup_count, len(immediate), len(switches)) != (
                refs_report['data_rvas'], refs_report['immediate_rvas'], refs_report['switch_elements']):
            raise ValueError('Native reference counts do not match the report')
        return dict(schema=1, status='validated', input_sha256=sha256, input_md5=md5,
                    idb_path=str(idb), idb_sha256=idb_hash, snapshot=str(snapshot),
                    instruction_count=count, instruction_bytes=code_bytes,
                    data_rvas=fixup_count, immediate_rvas=len(immediate), switch_elements=len(switches),
                    terminal_unowned_entries=unproven.entries,
                    terminal_unowned_spans=len(unproven.rows),
                    files={name: outputs[name] for name in names})
    finally:
        pe.close()


def adopt(snapshot, destination, backup, result):
    snapshot, destination, backup = map(lambda p: Path(p).resolve(), (snapshot, destination, backup))
    if destination == snapshot or backup == destination or backup.is_relative_to(destination):
        raise ValueError('Snapshot, generated directory and backup directory must be distinct')
    if backup.exists():
        raise FileExistsError(f'Use a new native-analysis backup directory: {backup}')
    names = list(result['files'])
    if (destination / native_unproven.FILE).exists() and native_unproven.FILE not in names:
        raise ValueError('New snapshot omits the existing terminal unowned protection evidence')
    destination.mkdir(parents=True, exist_ok=True)
    backup.mkdir(parents=True)
    present = set()
    for name in names:
        path = destination / name
        if path.exists():
            shutil.copy2(path, backup / name)
            present.add(name)
    changed = []
    try:
        for name in names:
            target = destination / name
            temporary = target.with_name(target.name + '.baseline.tmp')
            if temporary.exists():
                raise FileExistsError(f'Previous native-analysis adoption left a temporary file: {temporary}')
            shutil.copy2(snapshot / name, temporary)
            if digest(temporary) != result['files'][name]['sha256']:
                raise ValueError(f'Native snapshot changed during adoption: {name}')
            temporary.replace(target)
            changed.append(name)
    except Exception:
        for name in changed:
            target = destination / name
            if name in present:
                shutil.copy2(backup / name, target)
            else:
                target.unlink()
        raise
    result = dict(result, status='adopted', destination=str(destination), backup=str(backup),
                  next_build_action='Regenerate native assembly and catalog through the normal compiler recovery sequence')
    (backup / 'adoption-receipt.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--idb', type=Path, required=True)
    parser.add_argument('--destination', type=Path, default=Path(__file__).resolve().parents[1] / 'generated')
    parser.add_argument('--backup', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    result = validate(args.snapshot, args.exe, args.idb)
    if args.apply:
        if args.backup is None:
            parser.error('--apply requires a new --backup directory')
        result = adopt(args.snapshot, args.destination, args.backup, result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
