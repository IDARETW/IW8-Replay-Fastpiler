"""Recover native functions and validate editable C++ with Windows toolchains.

Backend output is evidence. Only a reviewed, tested candidate may be promoted
into the existing source workspace; compiling a candidate never proves its ABI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TARGET = 'x86_64-pc-windows-msvc'
FLAGS = ['--target=' + TARGET, '-std=c++20', '-O2', '-ffreestanding',
         '-fno-stack-protector', '-funwind-tables', '-ffunction-sections',
         '-fdata-sections', '-fno-exceptions', '-fno-rtti', '-ffp-contract=off',
         '-Wall', '-Wextra', '-Werror']
PILOT = [('Com_Memmove', None), ('Dvar_RegisterInt', None),
         ('DB_CheckXFileVersion', None), ('DB_PendingZones_QueueZoneSet', None),
         ('I_stricmp', 'fn_2a385ed3a736c866'),
         ('I_stristr', 'fn_98e4a70bc4c66c13'),
         ('Vec3Normalize', 'fn_62b1f5ea433e8291')]
PRECHECKS = ('backend_tests.py', 'layout_tests.py', 'image_reference_tests.py', 'source_provenance_tests.py')
# The boilerplate ships the generic image verifier and relocation audit.
# Game-specific asset/reader checks belong to their owner-supplied profiles.
POSTCHECKS = [('verify.py', []), ('audit_relocations.py', [])]


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        temp.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def run(command, cwd, timeout=180):
    """No shell and bounded output; keep the exact invocation for provenance."""
    started = time.time()
    try:
        result = subprocess.run([str(x) for x in command], cwd=cwd,
                                capture_output=True, text=True, errors='replace', timeout=timeout)
        return dict(command=list(map(str, command)), returncode=result.returncode,
                    seconds=round(time.time() - started, 3),
                    stdout=result.stdout[-24000:], stderr=result.stderr[-24000:])
    except subprocess.TimeoutExpired as error:
        return dict(command=list(map(str, command)), returncode=None, timeout=True,
                    seconds=round(time.time() - started, 3), stderr=str(error))


def windows_compiler():
    if os.name != 'nt':
        raise ValueError('C++ compilation and linking must run natively on Windows')
    from workstation_cpp_sources import compiler_path
    return compiler_path()


def require_promotion_evidence(root, row, image_hash, source, evidence):
    """Require current source, compiler and header identities at promotion."""
    if (evidence.get('image_sha256') != image_hash or evidence.get('function_id') != row['id'] or
        evidence.get('source_sha256') != sha(source) or not evidence.get('abi_review') or
        not evidence.get('differential', {}).get('passed') or evidence.get('differential', {}).get('cases',0)<1):
        raise ValueError('Promotion needs ABI review and passing differential evidence for this image, function and source')
    if evidence.get('compiler',{}).get('sha256') != sha(windows_compiler()):
        raise ValueError('Differential evidence used another compiler; rerun the behavior tests')
    for relative,digest in evidence.get('dependencies',{}).items():
        path=(Path(root)/relative).resolve()
        if not path.is_relative_to(Path(root).resolve()) or sha(path)!=digest:
            raise ValueError('Differential evidence has a changed local header dependency')
    for item in evidence.get('compilation_dependencies',[]):
        if sha(item['path'])!=item['sha256']:
            raise ValueError('Differential evidence has a changed compiler/header dependency')


def verify_build(root, output):
    """Retain the existing PowerShell build's complete post-link checks."""
    root,output=Path(root),Path(output)
    report=json.loads((output/'build-report.json').read_text())
    result=dict(schema=1,sha256=report['sha256'],passed=False,checks=[])
    try:
        for script,extra in POSTCHECKS:
            print('Verifying: '+script+' '+' '.join(extra),flush=True)
            command=[sys.executable,str(root/'tools'/script),'--build',str(output),*extra]
            process=subprocess.run(command,cwd=root)
            result['checks'].append(dict(script=script,arguments=extra,returncode=process.returncode))
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode,command)
        from source_provenance import validate_report
        validate_report(report)
        result['passed']=True
    finally:
        atomic_json(output/'quality-checks.json',result)
    return result


class Recovery:
    def __init__(self, root=ROOT):
        from workstation.config import load_paths
        self.root = Path(root).resolve()
        self.paths = load_paths(self.root)
        self.config = json.loads((self.root / 'replay-project.local.json').read_text(encoding='utf-8-sig'))
        self.manifest = json.loads((self.root / 'generated/manifest.json').read_text())
        self.catalog = json.loads((self.root / 'generated/function-catalog.json').read_text())
        if self.catalog['image_sha256'] != self.manifest['input_sha256']:
            raise ValueError('Catalog and recovered image disagree')
        self.image = self.paths['game'] / 'game_dx12_ship_replay.exe'
        self.directory = self.root / 'analysis/cpp-recovery'

    def resolve(self, identity):
        rows = [r for r in self.catalog['functions']
                if identity in (r['id'], r['name']) or identity in r.get('aliases', [])]
        if len(rows) != 1 or rows[0].get('quarantined'):
            raise ValueError('Unknown, ambiguous or quarantined function; select a stable function ID')
        from source_catalog import stable_id
        row = rows[0]
        if row['id'] != stable_id(self.catalog['image_sha256'], row['rva']):
            raise ValueError('Function identity is not stable for this image')
        return row

    def verify_image(self):
        if sha(self.image) != self.catalog['image_sha256']:
            raise ValueError('Original executable differs from the pinned Replay input')

    def spans(self, row):
        import capstone
        import native_functions
        import pefile
        pe = pefile.PE(str(self.image), fast_load=True)
        lengths = (self.root / 'generated/instruction-lengths.bin').read_bytes()
        manifest = dict(self.manifest, function_entries=[r['rva'] for r in self.catalog['functions']])
        index = native_functions.FunctionIndex(manifest, pe.get_data, lengths)
        if index.owner(row['rva']) not in (None, row['rva']):
            raise ValueError('Entry belongs to another native unwind family')
        if row['rva'] in index.families:
            return [list(s) for s in sorted(index.families[row['rva']])]
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        class Targets(dict):
            def get(self, at, default=None):
                ins = next(decoder.disasm(pe.get_data(at, 15), at, count=1), None)
                return ins.operands[0].imm if ins and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM else default
        return index.leaf(row['rva'], pe.get_data(index.text, len(lengths)), Targets())

    def recover(self, identity, backend='ida', timeout=180):
        import capstone
        import pefile
        from source_catalog import readonly_uri, parse_integer
        row = self.resolve(identity)
        self.verify_image()
        spans = self.spans(row)
        attempt = self.directory / row['id'] / backend / uuid.uuid4().hex
        attempt.mkdir(parents=True)
        record = dict(schema=1, function_id=row['id'], name=row['name'], rva=row['rva'],
                      image_sha256=self.catalog['image_sha256'], catalog_sha256=sha(self.root / 'generated/function-catalog.json'),
                      instruction_lengths_sha256=sha(self.root / 'generated/instruction-lengths.bin'),
                      native_spans=spans, backend=backend, status='recovery-required',
                      gates=dict(compilation=False, abi_review=False, differential=False, linking=False, runtime=False),
                      blockers=['Recovered behavior and ABI require validation.'])
        pe = pefile.PE(str(self.image), fast_load=True)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        lines = []
        for begin, end in spans:
            native = pe.get_data(begin, end-begin)
            (attempt / f'native-{begin:08x}.bin').write_bytes(native)
            lines.extend(f'{i.address:#x}: {i.mnemonic} {i.op_str}' for i in decoder.disasm(native, begin))
        (attempt / 'native.asm').write_text('\n'.join(lines) + '\n')
        try:
            if backend == 'ida':
                with sqlite3.connect(readonly_uri(self.paths['sqlite']), uri=True) as db:
                    db.execute('BEGIN')
                    if row.get('database_id') is not None:
                        found = db.execute('SELECT rva,prototype,pseudocode FROM functions WHERE id=?',(row['database_id'],)).fetchone()
                        data = [found[1:]] if found and parse_integer(found[0], 'rva') == row['rva'] else []
                    else:
                        data = db.execute('SELECT prototype,pseudocode FROM functions WHERE CAST(rva AS INTEGER)=?', (row['rva'],)).fetchall()
                    if len(data) != 1:
                        raise ValueError('No unique SQLite function body for this native identity')
                    proto, body = data[0]
                    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if 'replay_ida_function_text' in tables:
                        override = db.execute('SELECT prototype,pseudocode FROM replay_ida_function_text WHERE function_rva IN (?,?)', (row['rva'],hex(row['rva']))).fetchone()
                        if override:
                            proto, body = override
                    record['analysis_text_sha256'] = hashlib.sha256(json.dumps([proto, body]).encode()).hexdigest()
                (attempt / 'ida-reference.txt').write_text((proto or '') + '\n' + (body or ''), encoding='utf-8')
                if not body:
                    raise ValueError('IDA has no recovered body; run the existing private flow-recovery worker')
                from workstation_cpp_sources import render_cpp
                content, status, diagnostics, _ = render_cpp(row['id'], row['name'], proto, body, symbol=row['name'])
                (attempt / 'candidate.cpp').write_text(content, encoding='utf-8')
                record.update(status=status, blockers=diagnostics)
            elif backend == 'retdec':
                tool = Path(self.config.get('cpp_recovery', {}).get('retdec') or self.root / '.toolchains/retdec-v5.0/bin/retdec-decompiler.exe')
                if not tool.is_file():
                    raise ValueError('Native RetDec is not installed; run tools/setup_cpp_recovery.py')
                record['tool'] = dict(path=str(tool), sha256=sha(tool))
                support = tool.parent.parent / 'share/retdec'
                settings = json.loads((support/'decompiler-config.json').read_text())
                params = settings['decompParams']
                # Upstream's DSM pass prints the entire 98 MB image even when
                # decoding one function. Keep our bounded native.asm instead.
                params['llvmPasses'] = [p for p in params['llvmPasses'] if p != 'retdec-write-dsm']
                for key in ('staticSignPaths','libraryTypeInfoPaths','cryptoPatternPaths'):
                    params[key] = [str((support/p).resolve()) for p in params.get(key, [])]
                params['ordinalNumDirectory'] = str((support/params['ordinalNumDirectory']).resolve())
                params['staticSignPaths'] = []
                atomic_json(attempt/'backend-config.json', settings)
                # RetDec 5 ignores decompParams in --config. Its executable-
                # relative default configuration must therefore be isolated.
                host = self.root/'.toolchains/retdec-selective'
                host_tool = host/'bin'/tool.name
                host_tool.parent.mkdir(parents=True,exist_ok=True)
                for original in (tool, tool.parent/'libcrypto-1_1-x64.dll'):
                    target = host_tool.parent/original.name
                    if target.exists() and sha(target) != sha(original):
                        raise ValueError('Existing selective backend runtime differs: ' + str(target))
                    if not target.exists():
                        shutil.copy2(original,target)
                host_config = host/'share/retdec/decompiler-config.json'
                atomic_json(host_config, settings)
                record['tool'] = dict(path=str(host_tool),sha256=sha(host_tool),
                                      config_path=str(host_config),config_sha256=sha(host_config))
                command = [host_tool, self.image, '-o', attempt / 'candidate.c', '--select-decode-only',
                           '--disable-static-code-detection', '--select-ranges',
                           ','.join(f'{pe.OPTIONAL_HEADER.ImageBase+a:#x}-{pe.OPTIONAL_HEADER.ImageBase+b:#x}' for a,b in spans)]
                record['execution'] = run(command, self.root, timeout)
                if record['execution']['returncode'] != 0:
                    raise ValueError('RetDec failed or timed out; inspect execution diagnostics')
                if not (attempt/'candidate.c').is_file() or not (attempt/'candidate.ll').is_file():
                    raise ValueError('RetDec did not produce both C and lifted LLVM IR')
                record['status'] = 'recovered-reference'
            elif backend == 'revng':
                settings = self.config.get('cpp_recovery', {}).get('revng', {})
                distro, executable = settings.get('distro'), settings.get('executable')
                if not distro or not executable:
                    raise ValueError('Optional rev.ng requires configured WSL distro and absolute executable path; Windows builds do not depend on it')
                if not executable.startswith('/'):
                    raise ValueError('rev.ng executable must be an absolute Linux path')
                prefix = ['wsl.exe', '--distribution', distro, '--exec']
                def linux_path(path):
                    response = run(prefix + ['wslpath', '-a', str(path)], self.root, 20)
                    if response['returncode'] != 0:
                        raise ValueError('WSL path conversion failed: ' + response.get('stderr', ''))
                    return response['stdout'].strip()
                work, image = linux_path(attempt), linux_path(self.image)
                commands = [prefix + [executable, '-C', work, 'project', 'init', image]]
                key = f'{pe.OPTIONAL_HEADER.ImageBase + row["rva"]:#x}:Code_x86_64'
                for artifact, output in [('emit-tagless-c','candidate.c'), ('cleanup-ir','lifted.bc'),
                                         ('emit-tagless-helper-header','helpers.h'), ('emit-tagless-type-and-global-header','types-and-globals.h')]:
                    command = prefix + [executable, '-C', work, 'project', 'artifact', artifact, '-o', work+'/'+output]
                    if artifact in ('emit-tagless-c','cleanup-ir'):
                        command.append(key)
                    commands.append(command)
                record['executions'] = []
                for command in commands:
                    result = run(command, self.root, timeout)
                    record['executions'].append(result)
                    if result['returncode'] != 0:
                        raise ValueError('rev.ng analysis failed; inspect execution diagnostics')
                record['status'] = 'recovered-reference'
            else:
                raise ValueError('Unknown recovery backend')
        except (ValueError, OSError, sqlite3.Error) as error:
            record.update(status='blocked', blockers=[str(error)])
        if sha(self.image) != record['image_sha256']:
            record.update(status='blocked', blockers=['Original executable changed during recovery'])
        if record.get('tool') and sha(record['tool']['path']) != record['tool']['sha256']:
            record.update(status='blocked', blockers=['Recovery tool changed during analysis'])
        if record.get('tool', {}).get('config_path') and sha(record['tool']['config_path']) != record['tool']['config_sha256']:
            record.update(status='blocked', blockers=['Recovery backend configuration changed during analysis'])
        record['artifacts'] = {p.name: sha(p) for p in attempt.iterdir() if p.is_file()}
        atomic_json(attempt / 'record.json', record)
        return dict(record, record=str(attempt / 'record.json'))

    def validate(self, source, symbol):
        source = Path(source).resolve()
        if not source.is_relative_to(self.root) or source.suffix.lower() not in ('.cpp', '.c'):
            raise ValueError('Select a C/C++ source inside this project')
        from workstation_cpp_sources import compile_check
        compiler = windows_compiler()
        before = sha(source)
        checked = compile_check(self.root, source.read_text(encoding='utf-8'), symbol, 'c' if source.suffix == '.c' else 'cpp', source_path=source)
        if sha(source) != before:
            raise ValueError('Source changed while validating; retry')
        checked.update(source=str(source), source_sha256=before, compiler_path=str(compiler))
        return checked

    def workspace(self):
        """Emit commands matching real objects; add defaults only for new units."""
        compiler = windows_compiler()
        commands = {}
        reports = [p for p in (self.root/'build-cpp-recovery/build-report.json',self.root/'build/build-report.json') if p.exists()]
        report = max(reports,key=lambda p:p.stat().st_mtime_ns) if reports else None
        if report:
            for row in json.loads(report.read_text()).get('cpp', []):
                command = row.get('command')
                if command:
                    path = Path(row['source'])
                    path = path if path.is_absolute() else self.root / path
                    commands[str(path.resolve())] = dict(directory=str(self.root), file=str(path.resolve()), arguments=command)
        for source in sorted((self.root / 'src').rglob('*.cpp')):
            commands.setdefault(str(source.resolve()), dict(directory=str(self.root), file=str(source.resolve()),
                arguments=[str(compiler), *FLAGS, '-I', str(self.root/'src'), '-c', str(source), '-o', str(self.directory/'objects'/ (source.stem+'.obj'))]))
        atomic_json(self.root/'compile_commands.json', list(commands.values()))
        return dict(compilation_database=str(self.root/'compile_commands.json'), translation_units=len(commands), target=TARGET)

    def pilot(self):
        rows = []
        units = json.loads((self.root/'source-units.json').read_text())['units']
        for name, identity in PILOT:
            if identity:
                row = self.resolve(identity)
            else:
                bound = [u for u in units if u['symbol'] == name]
                if not bound:
                    rows.append(dict(name=name, status='control-reference', reason='Bridge source has no replacement binding'))
                    continue
                row = self.resolve(bound[0]['function_id'])
            rows.append(dict(name=name, function_id=row['id'], rva=row['rva']))
        atomic_json(self.directory/'pilot.json', dict(schema=1, image_sha256=self.catalog['image_sha256'], functions=rows))
        return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('recover'); p.add_argument('identity'); p.add_argument('--backend', choices=['ida','retdec','revng'], default='ida'); p.add_argument('--timeout', type=int, default=180)
    p = sub.add_parser('inspect'); p.add_argument('record', type=Path)
    p = sub.add_parser('validate'); p.add_argument('source', type=Path); p.add_argument('--symbol', required=True)
    p = sub.add_parser('reconcile'); p.add_argument('ticket', type=Path, nargs='?'); p.add_argument('--source', type=Path)
    p = sub.add_parser('checkout'); p.add_argument('identity')
    p = sub.add_parser('promote'); p.add_argument('identity'); p.add_argument('source', type=Path); p.add_argument('--evidence', type=Path, required=True)
    p = sub.add_parser('build'); p.add_argument('--output', default='build-cpp-recovery'); p.add_argument('--skip-assembly', action='store_true')
    p = sub.add_parser('verify'); p.add_argument('--output', default='build-cpp-recovery')
    sub.add_parser('workspace'); sub.add_parser('pilot'); sub.add_parser('status')
    args = parser.parse_args()
    try:
        recovery = Recovery(args.root)
        if args.command == 'recover':
            result = recovery.recover(args.identity, args.backend, args.timeout)
        elif args.command == 'validate':
            result = recovery.validate(args.source, args.symbol)
        elif args.command in ('checkout','reconcile','promote'):
            from workstation_sources import SourceWorkspace
            sources = SourceWorkspace(recovery.root, recovery.paths['cache']/'sources', recovery.paths['sqlite'])
            if args.command == 'checkout':
                result = sources.checkout_external(args.identity)
            elif args.command == 'reconcile':
                ticket = args.ticket
                if ticket is None:
                    if args.source is None:
                        raise ValueError('Select an edit ticket or --source file')
                    candidates = []
                    for path in (recovery.directory/'edits').glob('*.json'):
                        data = json.loads(path.read_text())
                        if not data.get('consumed') and (recovery.root/data['source']).resolve() == args.source.resolve():
                            candidates.append(path)
                    if not candidates:
                        raise ValueError('No edit ticket for this file; run checkout before editing')
                    ticket = max(candidates,key=lambda p:p.stat().st_mtime_ns)
                result = sources.reconcile_external(ticket)
            else:
                recovery.verify_image()
                evidence = json.loads(args.evidence.read_text())
                row = recovery.resolve(args.identity)
                require_promotion_evidence(recovery.root,row,recovery.catalog['image_sha256'],args.source,evidence)
                checked = recovery.validate(args.source, evidence['symbol'])
                if not checked['compiled']:
                    raise ValueError(checked['diagnostics'])
                baseline = sources.get_source(row['id'], 'cpp')
                result = sources.save_source(row['id'], args.source.read_text(), baseline['revision'], 'cpp')
        elif args.command == 'workspace':
            result = recovery.workspace()
        elif args.command == 'build':
            windows_compiler()
            if not args.output.startswith('build-') or Path(args.output).name != args.output:
                raise ValueError('Select a project-local build-* directory')
            from workstation.build_lock import compiler_lock
            with compiler_lock(recovery.root/'.workstation-compiler.lock'):
                for script in PRECHECKS:
                    print('Checking: '+script,flush=True)
                    subprocess.run([sys.executable,str(recovery.root/'tools'/script)],cwd=recovery.root,check=True)
                for pattern in ('test_cpp_recovery.py','test_run_recovered_cpp.py','test_workstation_cpp_sources.py','test_workstation_sources.py'):
                    subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p',pattern],cwd=recovery.root,check=True)
                command = [sys.executable,str(recovery.root/'tools/build.py'),'--output',args.output,'--grow']
                if args.skip_assembly:
                    command.append('--skip-assembly')
                subprocess.run(command,cwd=recovery.root,check=True)
                verify_build(recovery.root,recovery.root/args.output)
            result = dict(build=str(recovery.root/args.output),verified=True,deployed=False,runtime=False)
        elif args.command == 'verify':
            windows_compiler()
            if not args.output.startswith('build-') or Path(args.output).name!=args.output:
                raise ValueError('Select a project-local build-* directory')
            from workstation.build_lock import compiler_lock
            with compiler_lock(recovery.root/'.workstation-compiler.lock'):
                result=verify_build(recovery.root,recovery.root/args.output)
        elif args.command == 'pilot':
            result = recovery.pilot()
        elif args.command == 'inspect':
            result = json.loads(args.record.read_text())
            recovery.verify_image()
            if result.get('image_sha256') != recovery.catalog['image_sha256']:
                raise ValueError('Recovery record belongs to another executable')
            for name, digest in result['artifacts'].items():
                if Path(name).name != name:
                    raise ValueError('Recovery artifact name escapes its attempt directory')
                if sha(args.record.parent/name) != digest:
                    raise ValueError('Recovery artifact changed: ' + name)
        else:
            result = dict(target=TARGET, host=os.name, compiler=str(windows_compiler()),
                          retdec=(recovery.root/'.toolchains/retdec-v5.0/bin/retdec-decompiler.exe').exists(),
                          revng_configured=bool(recovery.config.get('cpp_recovery', {}).get('revng')),
                          records=[str(p) for p in recovery.directory.glob('fn_*/*/*/record.json')])
        print(json.dumps(result, indent=2))
        if isinstance(result, dict) and (result.get('status') == 'blocked' or result.get('compiled') is False):
            return 1
        return 0
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(json.dumps(dict(error=str(error)), indent=2), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
