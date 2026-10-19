"""Describe C++ recovery ownership from the pinned image and compiler analysis."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3

import pefile
import capstone

import native_functions
import source_catalog
from recovered_cpp_names import count_jumpouts


def recovery_reason(pseudocode, previous=None):
    """Select missing bodies and continuations, including legacy unscoped output."""
    if not str(pseudocode or '').strip():
        return 'missing-body'
    if count_jumpouts(pseudocode):
        return 'native-continuation'
    if previous and previous.get('status') == 'recovered' and 'reference_names' not in previous:
        return 'reference-provenance'
    return None


def pending_recovery(previous, decoder_sha256, generation=None):
    if not previous:
        return True
    body = str(previous.get('pseudocode') or '')
    if previous.get('status') == 'recovered' and body.strip() and not count_jumpouts(body):
        return 'reference_names' not in previous
    return (previous.get('decoder_sha256') != decoder_sha256 or
            (generation is not None and previous.get('recovery_generation') != generation))


def prepare(root: Path, output: Path, names: list[str] | None = None, pending=False, limit=None):
    if limit is not None and limit < 1:
        raise ValueError('Recovery request limit must be positive')
    config = json.loads((root / 'replay-project.local.json').read_text())
    settings = config.get('cpp_recovery', {})
    idb = Path(settings['idb']) if settings.get('idb') else None
    idb_identity = None
    if idb is not None and idb.is_file():
        info = idb.stat()
        idb_identity = [str(idb.resolve()), info.st_size, info.st_mtime_ns]
    helpers = ['prepare_cpp_flow_recovery.py', 'ida_recover_cpp_flow.py', 'run_cpp_flow_recovery.py']
    generation = hashlib.sha256(json.dumps([
        idb_identity, {name: hashlib.sha256((root / 'tools' / name).read_bytes()).hexdigest() for name in helpers},
        settings.get('clear_inferred_types', True), settings.get('function_timeout_seconds', 300),
    ], sort_keys=True).encode()).hexdigest()
    manifest = json.loads((root / 'generated/manifest.json').read_text())
    image_path = Path(config['game']) / 'game_dx12_ship_replay.exe'
    image = image_path.read_bytes()
    if hashlib.sha256(image).hexdigest() != manifest['input_sha256']:
        raise ValueError('C++ control-flow recovery image differs from compiler inputs')
    # FunctionIndex reads the native unwind directory directly. Parsing all
    # imports, resources and exception objects here adds work to every batch.
    pe = pefile.PE(data=image, fast_load=True)
    from recovered_cpp_flow import FlowRecovery
    recovery = FlowRecovery(root, manifest['input_sha256'])
    if pending:
        recovery.sync()
    lengths = (root / 'generated/instruction-lengths.bin').read_bytes()
    decoder_sha256 = hashlib.sha256(lengths).hexdigest()
    index = native_functions.FunctionIndex(manifest, pe.get_data, lengths)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    text = pe.get_data(index.text, len(lengths))

    class BranchTargets(dict):
        def get(self, at, default=None):
            if at not in self:
                item = next(decoder.disasm(pe.get_data(at, 15), at, count=1), None)
                self[at] = (item.operands[0].imm if item and item.operands and
                            item.operands[0].type == capstone.x86.X86_OP_IMM else None)
            return self[at]

    branches = BranchTargets()
    with sqlite3.connect(source_catalog.readonly_uri(Path(config['sqlite'])), uri=True) as db:
        db.execute('BEGIN')
        quarantine = {row['rva'] for row in source_catalog.function_quarantine(db, manifest['image_base']).values()}
        rows = db.execute('SELECT address,name,pseudocode,prototype FROM functions')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        overrides = ({source_catalog.parse_integer(rva, 'override RVA'): (body, proto)
                      for rva, body, proto in db.execute('SELECT function_rva,pseudocode,prototype FROM replay_ida_function_text')}
                     if 'replay_ida_function_text' in tables else {})
        requests = []
        for address, name, pseudo, proto in rows:
            rva = source_catalog.parse_integer(address, 'function address') - manifest['image_base']
            if rva in quarantine:
                continue
            override = overrides.get(rva)
            if override:
                pseudo, proto = override[0] or pseudo, override[1] or proto
            pseudo = pseudo or ''
            fingerprint = hashlib.sha256(json.dumps([proto, pseudo], ensure_ascii=False).encode()).hexdigest()
            previous = recovery.rows.get((rva, fingerprint))
            if recovery.baseline and previous and previous.get('baseline_idb_sha256') != recovery.baseline:
                previous = None
            reason = recovery_reason(pseudo, previous)
            if (names is not None and name not in names) or (names is None and reason is None):
                continue
            if pending and not pending_recovery(previous, decoder_sha256, generation):
                continue  # Revisit failures when native instruction recovery improves.
            owner = index.owner(rva)
            spans = index.families.get(owner, []) if owner == rva else []
            leaf_error = None
            if owner is None:
                try:
                    spans = index.leaf(rva, text, branches)
                except ValueError as error:
                    leaf_error = str(error)
            instructions = []
            ownership_error = leaf_error
            unclassified = []
            for begin, end in spans:
                at = begin
                while at < end:
                    size = lengths[at - index.text]
                    if size == 0:
                        # PE ranges can include padding, switch tables and
                        # unreachable bytes. They are not fabricated as code.
                        if unclassified and unclassified[-1][1] == at:
                            unclassified[-1][1] += 1
                        else:
                            unclassified.append([at, at+1])
                        at += 1
                        continue
                    if size == 255 or at + size > end:
                        ownership_error = f'Unproven compiler instruction boundary at {at:#x}'
                        break
                    instructions.append([at, size, pe.get_data(at, size).hex()])
                    at += size
                if ownership_error:
                    break
            if ownership_error:
                spans, instructions = [], []
            requests.append(dict(rva=rva, name=name, spans=spans, instructions=instructions,
                                 unclassified_ranges=unclassified,
                                 ownership_error=ownership_error,
                                 source_hash=fingerprint,
                                 recovery_reason=reason or 'explicit-request',
                                 type_hints=(previous or {}).get('type_hints', []),
                                 export_types=list((previous or {}).get('types', {})),
                                 old_jumpouts=count_jumpouts(pseudo)))
            if limit is not None and len(requests) >= limit:
                break
    document = dict(schema=1, image_sha256=manifest['input_sha256'], image_base=manifest['image_base'],
                    database_program_md5=json.loads((root / 'generated/ida-code-report.json').read_text())['input_md5'],
                    decoder_sha256=decoder_sha256,
                    recovery_generation=generation,
                    baseline_idb_sha256=recovery.baseline,
                    clear_inferred_types=config.get('cpp_recovery', {}).get('clear_inferred_types', True),
                    requests=requests)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document), encoding='utf-8')
    print(json.dumps(dict(requests=len(requests), owned=sum(bool(r['spans']) for r in requests),
                         instructions=sum(len(r['instructions']) for r in requests))))
    return document


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--name', action='append')
    parser.add_argument('--pending', action='store_true')
    args = parser.parse_args()
    prepare(args.root, args.output, args.name, args.pending)
