"""Persistent project settings and serialized, verified compiler jobs."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from workstation.build_lock import ensure_compiler_idle
from workstation.asset_packaging import (pending_snapshot, require_snapshot, replacement_rows,
    pending_sound_snapshot, require_sound_snapshot, sound_replacement_rows, require_unique_replacements)
from workstation.config import load_paths
from workstation.compiler_identity import compiler_snapshot, require_compiler_snapshot
from workstation.toolchain import resolve_codec_environment


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    pending.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    pending.replace(path)


class Project:
    SOURCE_MAPPING_INPUTS = ('source-units.json', 'source-workstation/units.json',
                             'source-workstation/user-functions.json')

    def __init__(self, root, cache_root, game_root, sqlite_path, acts=None, *, lua_acts=None,
                 build_root=None, publication_root=None, recover_jobs=True, codec_environment=None):
        self.root, self.cache = Path(root).resolve(), Path(cache_root).resolve()
        self.game, self.sqlite = Path(game_root).resolve(), Path(sqlite_path).resolve()
        self.acts = Path(acts).resolve() if acts else None
        configured_paths = load_paths(self.root)
        self.build_root = Path(build_root or configured_paths.get('build_root') or self.root).resolve()
        self.publication_root = Path(publication_root or configured_paths.get('publication_root') or
                                     self.root / 'output').resolve()
        selected_lua_acts = lua_acts or configured_paths.get('lua_acts')
        self.codec_environment = (dict(codec_environment) if codec_environment is not None else
            resolve_codec_environment(self.root, self.game, self.acts, configured_paths['tools'],
                                      proxy_source=configured_paths['proxy_source'],
                                      lua_acts=selected_lua_acts))
        selected_lua_acts = (self.codec_environment.get('REPLAY_LUA_ACTS') or
                             selected_lua_acts or self.acts)
        self.lua_acts = Path(selected_lua_acts).resolve() if selected_lua_acts else None
        self.cache.mkdir(parents=True, exist_ok=True)
        self.mutation_lock = threading.RLock()
        self.job_lock = threading.Lock()
        self.active_job = None
        self.compiler_lock_path = self.root / '.workstation-compiler.lock'
        self.jobs_dir = self.cache / 'jobs'
        self.jobs_dir.mkdir(exist_ok=True)
        # A process interruption cannot leave a permanently running queue entry.
        try:
            ensure_compiler_idle(self.compiler_lock_path)
            compiler_running = False
        except ValueError:
            compiler_running = True
        for path in self.jobs_dir.glob('*/job.json') if recover_jobs else ():
            try:
                job = json.loads(path.read_text(encoding='utf-8'))
                if job['status'] in ('queued', 'running'):
                    if compiler_running:
                        self.active_job = job['id']
                        continue
                    job.update(status='interrupted', finished=time.time(), error='Workstation process stopped before verification completed')
                    atomic_json(path, job)
            except (ValueError, KeyError, OSError):
                continue

    def ensure_mutable(self):
        if self.active_job and self.job(self.active_job)['status'] not in ('queued', 'running'):
            self.active_job = None
        if self.active_job:
            raise ValueError('A compiler job owns the source snapshot. Wait for it to finish before saving edits.')
        ensure_compiler_idle(self.compiler_lock_path)

    def authored_files(self):
        rows = []
        for folder in ('src', 'source-workstation'):
            base = self.root / folder
            if not base.exists():
                continue
            for path in sorted(base.rglob('*')):
                if path.is_file() and path.suffix.casefold() in ('.c', '.cpp', '.h', '.hpp', '.s'):
                    rows.append({'path': path.relative_to(self.root).as_posix(), 'name': path.name,
                                 'bytes': path.stat().st_size, 'language': 'assembly' if path.suffix == '.s' else 'c' if path.suffix == '.c' else 'cpp'})
        return rows

    def source_input_snapshot(self):
        """Pin compiler-owned source roots, including headers/includes, at dispatch.

        Translation units and explicit assembly units are selected by build.py
        and source-workstation mapping files. Their local include files can use
        arbitrary suffixes, so pin the contents and file set of those authored
        roots rather than guessing header extensions here.
        """
        snapshot = {}
        for folder in ('src', 'source-workstation'):
            base = self.root / folder
            if not base.exists():
                continue
            for path in sorted(base.rglob('*')):
                if path.is_file():
                    resolved = path.resolve()
                    if not resolved.is_relative_to(self.root):
                        raise RuntimeError(f'Compiler source escapes the project root: {path}')
                    relative = path.relative_to(self.root).as_posix()
                    snapshot[relative] = digest(path)
        for relative in self.SOURCE_MAPPING_INPUTS:
            path = self.root / relative
            if path.is_file():
                snapshot[relative] = digest(path)
        return snapshot

    def global_input_snapshot(self):
        """Pin every global initializer file present when the job is queued."""
        return {path.name: digest(path) for path in (self.cache / 'globals').glob('sym_*.json')}

    def require_global_input_snapshot(self, snapshot, when):
        current = self.global_input_snapshot()
        if current != snapshot:
            raise RuntimeError(
                f'Global initializer inputs changed {when}. Rebuild before publication.')

    def require_source_input_snapshot(self, snapshot, when):
        for relative, expected in snapshot.items():
            path = self.root / relative
            if not path.is_file() or digest(path) != expected:
                raise RuntimeError(
                    f'Compilation inputs changed {when}: {relative}. Rebuild before publication.')
        pinned_sources = {relative for relative in snapshot
                          if relative.startswith(('src/', 'source-workstation/'))}
        pinned_mappings = set(self.SOURCE_MAPPING_INPUTS).intersection(snapshot)
        current_mappings = {relative for relative in self.SOURCE_MAPPING_INPUTS
                            if (self.root / relative).is_file()}
        if current_mappings != pinned_mappings:
            raise RuntimeError(
                f'Compiler mapping file set changed {when}. Rebuild before publication.')
        current_sources = set()
        for folder in ('src', 'source-workstation'):
            base = self.root / folder
            if base.exists():
                current_sources.update(path.relative_to(self.root).as_posix()
                                       for path in base.rglob('*') if path.is_file())
        if current_sources != pinned_sources:
            raise RuntimeError(
                f'The authored source file set changed {when}. Rebuild before publication.')

    def source_path(self, relative):
        path = (self.root / relative).resolve()
        if not any(path.is_relative_to(self.root / base) for base in ('src', 'source-workstation')):
            raise ValueError('Source file is outside the authored source directories')
        if path.suffix.casefold() not in ('.c', '.cpp', '.h', '.hpp', '.s'):
            raise ValueError('Unsupported source file extension')
        return path

    def read_file(self, relative):
        path = self.source_path(relative)
        return {'path': path.relative_to(self.root).as_posix(), 'name': path.name,
                'content': path.read_text(encoding='utf-8'), 'revision': digest(path), 'editable': True,
                'language': 'assembly' if path.suffix == '.s' else 'c' if path.suffix == '.c' else 'cpp', 'compilable': True,
                'provenance': {'basis': 'Authored project source; compiler dependency hashes are checked before publication'}}

    def save_file(self, relative, content, revision):
        self.ensure_mutable()
        path = self.source_path(relative)
        if not path.is_file() or digest(path) != revision:
            raise ValueError('Revision conflict; reload the source file')
        old = path.read_bytes()
        archive = self.cache / 'file-revisions' / hashlib.sha256(relative.encode()).hexdigest()
        archive.mkdir(parents=True, exist_ok=True)
        backup = archive / (hashlib.sha256(old).hexdigest() + path.suffix)
        if not backup.exists():
            backup.write_bytes(old)
        pending = path.with_name(path.name + '.tmp')
        pending.write_text(content, encoding='utf-8', newline='\n')
        pending.replace(path)
        return self.read_file(relative)

    def jobs(self):
        rows = []
        for path in self.jobs_dir.glob('*/job.json'):
            try:
                rows.append(json.loads(path.read_text(encoding='utf-8')))
            except (OSError, ValueError):
                continue
        return sorted(rows, key=lambda j: j['created'], reverse=True)

    def job(self, identity):
        if not re.fullmatch(r'[a-f0-9]{16}', identity):
            raise ValueError('Invalid job identity')
        return json.loads((self.jobs_dir / identity / 'job.json').read_text(encoding='utf-8'))

    def log(self, identity, offset=0):
        self.job(identity)
        path = self.jobs_dir / identity / 'compiler.log'
        with path.open('rb') as stream:
            stream.seek(max(0, offset))
            data = stream.read(128 * 1024)
            return {'text': data.decode('utf-8', errors='replace'), 'offset': stream.tell()}

    def start_build(self, profile='engine'):
        if profile not in ('current', 'engine'):
            raise ValueError('Unknown build profile')
        with self.mutation_lock, self.job_lock:
            self.ensure_mutable()
            implementation = compiler_snapshot(self.root)
            source_snapshot = self.source_input_snapshot()
            global_snapshot = self.global_input_snapshot()
            if profile == 'current' and self.acts is None and any((self.cache / 'fastfiles').glob('**/pending-edits/*/current.json')):
                raise ValueError('Saved asset edits require native fastfile packaging and a configured ACTS reader before a current game build can be published.')
            asset_snapshot = pending_snapshot(self.cache) if profile == 'current' else {}
            sound_snapshot = pending_sound_snapshot(self.cache) if profile == 'current' else {}
            asset_plan = {'zones': []}
            sound_plan = {'zones': []}
            if asset_snapshot:
                if self.acts is None:
                    raise ValueError('Saved asset edits require native fastfile packaging and a configured ACTS reader before a current game build can be published.')
                from workstation_fastfiles import FastfileWorkspace
                archives = FastfileWorkspace(self.root, self.cache / 'fastfiles', self.game / 'zone',
                    acts_path=self.acts, replay_executable=self.game / 'game_dx12_ship_replay.exe',
                    lua_acts_path=self.lua_acts)
                try:
                    asset_plan = archives.plan_pending_edits()
                    if asset_plan.get('status') != 'ready':
                        reasons = [row.get('reason') for row in asset_plan.get('zones', []) if not row.get('packageable')]
                        reasons += [row.get('reason') for row in asset_plan.get('invalid_edits', [])]
                        raise ValueError('; '.join(str(reason) for reason in reasons if reason) or 'Staged edits have no complete native writer plan')
                except Exception as error:
                    raise ValueError(f'Native fastfile packaging preflight failed: {error}') from error
                require_snapshot(self.cache, asset_snapshot)
            if sound_snapshot:
                if self.acts is None:
                    raise ValueError('Saved audio edits require a configured native ACTS reader before publication.')
                from workstation_fastfiles import FastfileWorkspace
                from workstation.soundbanks import SoundBankWorkspace
                archives = FastfileWorkspace(self.root, self.cache / 'fastfiles', self.game / 'zone',
                    acts_path=self.acts, replay_executable=self.game / 'game_dx12_ship_replay.exe',
                    lua_acts_path=self.lua_acts)
                sounds = SoundBankWorkspace(archives, self.cache)
                for zone_id in sorted({row['zone_id'] for row in sounds.drafts.list_drafts()}):
                    _, decoded = archives._validated_zone_receipt(zone_id)
                    relative = Path(decoded['source']['path']).resolve().relative_to(archives.game_root)
                    plan = sounds.plan_zone(relative)
                    if not plan['packageable']:
                        raise ValueError('Saved audio edits have no complete native alias package plan')
                    sound_plan['zones'].append(plan)
                require_sound_snapshot(self.cache, sound_snapshot)
            # Planning may inspect large native packages. Keep the user's
            # dispatch-time source revision as the build baseline and reject
            # any external edits made while that preflight was running.
            self.require_source_input_snapshot(source_snapshot, 'during dispatch preflight')
            self.require_global_input_snapshot(global_snapshot, 'during dispatch preflight')
            identity = uuid.uuid4().hex[:16]
            require_compiler_snapshot(self.root, implementation)
            job = {'id': identity, 'kind': 'compile', 'profile': profile, 'created': time.time(),
                   'status': 'queued', 'phase': 'Queued', 'artifacts': []}
            directory = self.jobs_dir / identity
            directory.mkdir()
            (directory / 'compiler.log').touch()
            atomic_json(directory / 'job.json', job)
            atomic_json(directory / 'compiler-implementation-snapshot.json', implementation)
            atomic_json(directory / 'source-input-snapshot.json', source_snapshot)
            atomic_json(directory / 'global-input-snapshot.json', global_snapshot)
            atomic_json(directory / 'asset-input-snapshot.json', asset_snapshot)
            atomic_json(directory / 'asset-package-plan.json', asset_plan)
            atomic_json(directory / 'sound-input-snapshot.json', sound_snapshot)
            atomic_json(directory / 'sound-package-plan.json', sound_plan)
            package_tools = ('workstation_fastfiles.py', 'workstation_asset_codecs.py', 'workstation_lua_compile.py', 'workstation_trace_index.py',
                             'verify_replay_lua_native_compile.py', 'make_replay_lua_acts_profile.py',
                             'analyze_workstation_asset_spans.py', 'repack_workstation_scriptfile.py', 'roundtrip_replay_fastfile.py',
                             'workstation_luafile.py', 'repack_workstation_luafile.py',
                             'repack_workstation_luafile_batch.py', 'workstation_mixed_script_luafile.py',
                             'repack_workstation_mixed_script_luafile.py', 'repack_workstation_scriptfiles.py',
                             'inspect_frontend_asset_table.py', 'frontend_catalog.py', 'workstation_stringtable.py',
                             'workstation_native_asset_edits.py', 'workstation_localize.py',
                             'workstation_native_child_relocation.py', 'workstation_shader_growth.py',
                             'workstation_shader_identity.py', 'workstation_image_resize.py',
                             'workstation_variable_native_edits.py',
                             'workstation_localize_inventory.py', 'workstation_localize_crud.py',
                             'workstation_asset_operations.py', 'workstation_luafile_operations.py',
                             'workstation_luafile_crud.py', 'workstation_luajit_chunk.py',
                             'workstation_soundbank.py',
                             'workstation_sab_drafts.py', 'workstation_sab_editor.py')
            atomic_json(directory / 'asset-tool-snapshot.json',
                        ({**{'tools/' + name: digest(self.root / 'tools' / name) for name in package_tools},
                          'workstation/soundbanks.py': digest(self.root / 'workstation/soundbanks.py'),
                         } if asset_snapshot or sound_snapshot else {}))
            lua_profile = (self.lua_acts.with_name('replay120_lua_native.json')
                           if self.lua_acts else None)
            lua_common = (self.lua_acts.with_name('acts-common.dll')
                          if self.lua_acts else None)
            atomic_json(directory / 'worker-inputs.json', {'root': str(self.root), 'cache': str(self.cache),
                'build_root': str(self.build_root), 'publication_root': str(self.publication_root),
                'game': str(self.game), 'sqlite': str(self.sqlite), 'acts': str(self.acts) if self.acts else None,
                'lua_acts': str(self.lua_acts) if self.lua_acts else None,
                'lua_acts_sha256': digest(self.lua_acts) if self.lua_acts else None,
                'lua_acts_common_sha256': digest(lua_common)
                    if lua_common and lua_common.is_file() else None,
                'lua_acts_profile': str(lua_profile) if lua_profile else None,
                'lua_acts_profile_sha256': digest(lua_profile)
                    if lua_profile and lua_profile.is_file() else None,
                'codec_environment': self.codec_environment})
            self.active_job = identity
            threading.Thread(target=self._dispatch_build, args=(job,), daemon=True).start()
            return job

    def _dispatch_build(self, job):
        directory = self.jobs_dir / job['id']
        command = [sys.executable, str(self.root / 'tools/run_compiler_locked.py'),
                   '--lock', str(self.compiler_lock_path), '--', sys.executable,
                   str(self.root / 'tools/workstation_build_job.py'), '--job', str(directory)]
        try:
            with (directory / 'compiler.log').open('ab', buffering=0) as log:
                result = subprocess.run(command, cwd=self.root, stdout=log, stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            latest = self.job(job['id'])
            if latest['status'] in ('queued', 'running', 'interrupted') or (result.returncode and latest['status'] != 'failed'):
                latest.update(status='failed', phase='Stopped', finished=time.time(),
                              error=f'Compiler worker stopped with exit code {result.returncode}; inspect compiler log')
                atomic_json(directory / 'job.json', latest)
        except Exception as error:
            latest = self.job(job['id'])
            latest.update(status='failed', phase='Stopped', finished=time.time(), error=str(error))
            atomic_json(directory / 'job.json', latest)
        finally:
            with self.mutation_lock, self.job_lock:
                self.active_job = None

    def _build(self, job):
        directory = self.jobs_dir / job['id']
        build_name = 'build-workstation-' + job['id']
        build = self.build_root / build_name
        def update(**fields):
            job.update(fields)
            atomic_json(directory / 'job.json', job)
        def run(arguments, phase):
            update(phase=phase)
            with (directory / 'compiler.log').open('ab', buffering=0) as log:
                log.write(('\n' + phase + '\n' + subprocess.list2cmdline(arguments) + '\n').encode())
                result = subprocess.run(arguments, cwd=self.root, stdout=log, stderr=subprocess.STDOUT,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                                        env={**os.environ, **self.codec_environment, 'REPLAY_GAME_ROOT': str(self.game), 'REPLAY_SQLITE': str(self.sqlite),
                                             'REPLAY_WORKSTATION_CACHE': str(self.cache)})
                if result.returncode:
                    raise RuntimeError(f'{phase} failed with exit code {result.returncode}; inspect compiler log')

        def require_publication_inputs(implementation, source_snapshot, global_snapshot,
                                       asset_snapshot, sound_snapshot, asset_tools, worker_inputs):
            """Recheck the job's original inputs at the publication boundary.

            These checks only hash the durable snapshots created for the job;
            they never re-plan or repackage assets after compilation.
            """
            require_compiler_snapshot(self.root, implementation)
            self.require_source_input_snapshot(source_snapshot, 'before publication')
            self.require_global_input_snapshot(global_snapshot, 'before publication')
            if job['profile'] == 'current':
                require_snapshot(self.cache, asset_snapshot)
                require_sound_snapshot(self.cache, sound_snapshot)
            for relative, expected in asset_tools.items():
                if digest(self.root / relative) != expected:
                    raise RuntimeError(
                        f'Asset compiler implementation changed before publication: {relative}')
            if self.lua_acts:
                lua_profile = self.lua_acts.with_name('replay120_lua_native.json')
                lua_common = self.lua_acts.with_name('acts-common.dll')
                current_lua_inputs = {
                    'lua_acts': str(self.lua_acts),
                    'lua_acts_sha256': digest(self.lua_acts),
                    'lua_acts_common_sha256': digest(lua_common) if lua_common.is_file() else None,
                    'lua_acts_profile': str(lua_profile),
                    'lua_acts_profile_sha256': digest(lua_profile) if lua_profile.is_file() else None,
                }
                if any(worker_inputs.get(key) != value for key, value in current_lua_inputs.items()):
                    raise RuntimeError('Selected Lua compiler/profile changed before publication')
            elif worker_inputs.get('lua_acts') is not None:
                raise RuntimeError('Lua compiler selection changed before publication')
        try:
            update(status='running', started=time.time(), build_directory=str(build))
            implementation = json.loads((directory / 'compiler-implementation-snapshot.json').read_text())
            require_compiler_snapshot(self.root, implementation)
            source_snapshot = json.loads((directory / 'source-input-snapshot.json').read_text())
            self.require_source_input_snapshot(source_snapshot, 'after dispatch')
            global_snapshot = json.loads((directory / 'global-input-snapshot.json').read_text())
            self.require_global_input_snapshot(global_snapshot, 'after dispatch')
            asset_snapshot = json.loads((directory / 'asset-input-snapshot.json').read_text())
            asset_plan = json.loads((directory / 'asset-package-plan.json').read_text())
            sound_snapshot = json.loads((directory / 'sound-input-snapshot.json').read_text())
            sound_plan = json.loads((directory / 'sound-package-plan.json').read_text())
            asset_tools = json.loads((directory / 'asset-tool-snapshot.json').read_text())
            worker_inputs = json.loads((directory / 'worker-inputs.json').read_text())
            if self.lua_acts:
                lua_profile = self.lua_acts.with_name('replay120_lua_native.json')
                lua_common = self.lua_acts.with_name('acts-common.dll')
                current_lua_inputs = {
                    'lua_acts': str(self.lua_acts),
                    'lua_acts_sha256': digest(self.lua_acts),
                    'lua_acts_common_sha256': digest(lua_common) if lua_common.is_file() else None,
                    'lua_acts_profile': str(lua_profile),
                    'lua_acts_profile_sha256': digest(lua_profile) if lua_profile.is_file() else None,
                }
                if any(worker_inputs.get(key) != value for key, value in current_lua_inputs.items()):
                    raise RuntimeError('Selected Lua compiler/profile changed after the worker snapshot')
            elif worker_inputs.get('lua_acts') is not None:
                raise RuntimeError('Lua compiler selection differs from the durable worker snapshot')
            for relative, expected in asset_tools.items():
                if digest(self.root / relative) != expected:
                    raise RuntimeError(f'Asset compiler implementation changed after preflight: {relative}')
            asset_replacements = []
            if job['profile'] == 'current':
                require_snapshot(self.cache, asset_snapshot)
                require_sound_snapshot(self.cache, sound_snapshot)
            if asset_snapshot:
                update(phase='Package and verify native fastfiles')
                from workstation_fastfiles import FastfileWorkspace
                archives = FastfileWorkspace(self.root, self.cache / 'fastfiles', self.game / 'zone',
                    acts_path=self.acts, replay_executable=self.game / 'game_dx12_ship_replay.exe',
                    lua_acts_path=self.lua_acts)
                for zone in asset_plan['zones']:
                    relative = Path(zone['relative_path'])
                    if relative.is_absolute() or '..' in relative.parts:
                        raise ValueError('Asset package plan contains an invalid zone path')
                    result = archives.build_fastfile_with_pending_edits(zone['zone_id'], build / 'packaged-assets' / relative,
                        expected_edits=zone['edits'])
                    asset_replacements.extend(replacement_rows(result, self.game / 'zone', self.game / 'zone' / relative))
                require_snapshot(self.cache, asset_snapshot)
                atomic_json(directory / 'asset-package-receipts.json', asset_replacements)
            if sound_snapshot:
                update(phase='Package and verify native audio banks')
                from workstation_fastfiles import FastfileWorkspace
                from workstation.soundbanks import SoundBankWorkspace
                archives = FastfileWorkspace(self.root, self.cache / 'fastfiles', self.game / 'zone',
                    acts_path=self.acts, replay_executable=self.game / 'game_dx12_ship_replay.exe',
                    lua_acts_path=self.lua_acts)
                sounds = SoundBankWorkspace(archives, self.cache)
                receipts = []
                for zone in sound_plan['zones']:
                    relative = Path(zone['relative_path'])
                    if relative.is_absolute() or '..' in relative.parts:
                        raise ValueError('Sound package plan contains an invalid zone path')
                    result = sounds.package_zone(relative, build / 'packaged-sounds' / relative.parent,
                        expected_snapshot=zone['pending_snapshot'])
                    asset_replacements.extend(sound_replacement_rows(result, self.game / 'zone'))
                    receipts.append(result)
                require_sound_snapshot(self.cache, sound_snapshot)
                atomic_json(directory / 'sound-package-receipts.json', receipts)
            require_unique_replacements(asset_replacements)
            # Packaging can take minutes; ensure the dispatch-time source set
            # is still the one about to enter the compiler.
            self.require_source_input_snapshot(source_snapshot, 'during asset packaging')
            self.require_global_input_snapshot(global_snapshot, 'during asset packaging')
            atomic_json(directory / 'input-snapshot.json', source_snapshot)
            # Each job compiles its own native objects and edited units; no unchecked
            # object reuse. The linker independently blocks original-image reads.
            args = [sys.executable, str(self.root / 'tools' / 'build.py'),
                    '--output-root', str(self.build_root), '--output', build_name]
            run(args, 'Compile and link source')
            checks = [('verify.py', []), ('audit_relocations.py', []), ('source_provenance.py', [])]
            for script, extra in checks:
                run([sys.executable, str(self.root / 'tools' / script), '--build', str(build), *extra], script)
            self.require_source_input_snapshot(source_snapshot, 'during compilation')
            self.require_global_input_snapshot(global_snapshot, 'during compilation')
            if job['profile'] == 'current':
                require_snapshot(self.cache, asset_snapshot)
                require_sound_snapshot(self.cache, sound_snapshot)
            for relative, expected in asset_tools.items():
                if digest(self.root / relative) != expected:
                    raise RuntimeError(f'Asset compiler implementation changed during the job: {relative}')
            report = json.loads((build / 'build-report.json').read_text())
            artifact = build / 'game_dx12_ship_replay_recompiled.exe'
            verification = json.loads((build / 'verification-report.json').read_text())
            audit = json.loads((build / 'relocation-audit.json').read_text())
            actual = digest(artifact)
            if actual != report['sha256'] or verification['sha256'] != actual or verification['unresolved_symbols'] != 0 or not audit['passed'] or audit['sha256'] != actual:
                raise RuntimeError('Compiler artifact and verification receipts disagree')
            output = self.publication_root / job['id']
            if output.exists():
                raise FileExistsError(f'Publication destination already exists: {output}')
            pending_output = self.publication_root / f'.{job["id"]}.pending'
            pending_output.parent.mkdir(parents=True, exist_ok=True)
            pending_output.mkdir(parents=True, exist_ok=False)
            target = pending_output / 'game_dx12_ship_replay.exe'
            shutil.copyfile(artifact, target)
            if digest(target) != actual:
                raise RuntimeError('Published replacement file hash differs')
            receipt = {'name': target.name, 'path': str(output / target.name), 'sha256': actual, 'bytes': target.stat().st_size}
            published = [receipt]
            require_unique_replacements(asset_replacements)
            for replacement in asset_replacements:
                destination = pending_output / replacement['name']
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(replacement['path'], destination)
                if digest(destination) != replacement['sha256']:
                    raise RuntimeError('Published native asset file differs from its verified receipt')
                published.append({**replacement, 'path': str(output / replacement['name'])})
            # Revalidate every original input after copying and immediately
            # before the single directory rename that publishes this job.
            require_publication_inputs(implementation, source_snapshot, global_snapshot,
                asset_snapshot, sound_snapshot, asset_tools, worker_inputs)
            # A source-only setup has no prior publication directory. Create
            # its parent only after verification; the complete job still moves
            # into place in one rename.
            output.parent.mkdir(parents=True, exist_ok=True)
            pending_output.rename(output)
            update(status='succeeded', phase='Verified replacements ready', finished=time.time(),
                   output_directory=str(output), artifacts=published,
                   asset_packaging='Verified native asset replacements included.' if asset_replacements else '')
        except Exception as error:
            update(status='failed', phase='Stopped', finished=time.time(), error=str(error))
        finally:
            with self.mutation_lock, self.job_lock:
                self.active_job = None
