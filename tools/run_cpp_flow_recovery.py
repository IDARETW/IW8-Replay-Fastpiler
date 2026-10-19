"""Incremental native C++ recovery using a private, reusable IDA database."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from prepare_cpp_flow_recovery import prepare
from recovered_cpp_flow import FlowRecovery


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def is_open(path):
    return any(path.with_suffix(suffix).exists() for suffix in ('.id0', '.id1', '.id2'))


def validate_snapshot_provenance(settings, request, receipt, original, original_stat):
    """Keep the worker's actual source separate from its approved epoch label."""
    approved = settings.get('baseline_idb_sha256')
    if not isinstance(approved, str) or len(approved) != 64 or any(
            value not in '0123456789abcdef' for value in approved):
        raise ValueError('C++ recovery requires the approved closed baseline IDB SHA-256')
    if (receipt.get('source_idb') != str(original.resolve()) or
            (receipt.get('source_bytes'), receipt.get('source_mtime_ns')) !=
            (original_stat.st_size, original_stat.st_mtime_ns)):
        raise ValueError('Private recovery snapshot has no matching closed-source provenance')
    if (receipt.get('source_idb_sha256') != approved or
            receipt.get('initial_private_idb_sha256') != approved or
            request.get('baseline_idb_sha256') != approved):
        raise ValueError('C++ recovery source snapshot differs from the approved analysis baseline')


def read_progress(path, offset, requests):
    """Read only complete append-only lines and validate their request owner."""
    latest = None
    if not path.is_file():
        return offset, latest
    with path.open('rb') as stream:
        stream.seek(offset)
        while True:
            start = stream.tell()
            line = stream.readline()
            if not line or not line.endswith(b'\n'):
                stream.seek(start)
                break
            row = json.loads(line)
            owner = requests.get(row.get('rva'))
            if owner is None or row.get('source_hash') != owner['source_hash']:
                raise ValueError('C++ recovery progress does not match a pinned native request')
            if row.get('phase') not in ('repair_start', 'repair_complete', 'analysis_start',
                                        'analysis_complete', 'decompile_start', 'record_complete'):
                raise ValueError('Unknown C++ recovery progress phase')
            latest = row
        return stream.tell(), latest


def interrupted_record(request, progress, message):
    if not progress or progress['phase'] not in ('repair_start', 'analysis_start', 'decompile_start'):
        return None
    owner = next(row for row in request['requests'] if row['rva'] == progress['rva'])
    return dict(rva=owner['rva'], name=owner['name'], image_sha256=request['image_sha256'],
                source_hash=owner['source_hash'], decoder_sha256=request.get('decoder_sha256'),
                recovery_generation=request.get('recovery_generation'),
                baseline_idb_sha256=request.get('baseline_idb_sha256'),
                source_idb_sha256=request.get('source_idb_sha256'),
                private_idb_input_sha256=request.get('private_idb_input_sha256'),
                status='error', error=message, recovery_phase=progress['phase'],
                recovery_reason=owner.get('recovery_reason'))


def committed_result_summary(path, request):
    """Account for complete, pinned records after the owned IDA process exits."""
    owners = {row['rva']: row for row in request['requests']}
    fields = ('image_sha256', 'decoder_sha256', 'recovery_generation',
              'baseline_idb_sha256', 'source_idb_sha256', 'private_idb_input_sha256')
    committed, counts, partial = set(), {}, 0
    with path.open('rb') as stream:
        for line in stream:
            if not line.endswith(b'\n'):
                partial = len(line)
                break  # Keep the committed prefix of an interrupted batch.
            row = json.loads(line)
            if not isinstance(row, dict) or type(row.get('rva')) is not int:
                raise ValueError('Invalid C++ recovery result identity')
            owner = owners.get(row.get('rva'))
            if (owner is None or row.get('source_hash') != owner['source_hash'] or
                    any(row.get(field) != request.get(field) for field in fields)):
                raise ValueError('C++ recovery result does not match a pinned request snapshot')
            if row['rva'] in committed:
                raise ValueError('C++ recovery emitted duplicate function results')
            status = row.get('status')
            if status not in ('recovered', 'continuation-required', 'error'):
                raise ValueError('Unknown C++ recovery result status')
            committed.add(row['rva'])
            counts[status] = counts.get(status, 0) + 1
    if not committed:
        raise ValueError('IDA produced no complete, pinned C++ recovery records')
    return dict(committed_records=len(committed), status_counts=counts,
                committed_rvas=sorted(committed),
                uncommitted_requests=len(owners) - len(committed), partial_tail_bytes=partial)


def append_interrupted_record(path, request, failure):
    """Preserve an incomplete tail before appending a watchdog result."""
    tail = None
    if path.is_file():
        try:
            if failure['rva'] in committed_result_summary(path, request)['committed_rvas']:
                return None  # The record was flushed before its progress line.
        except ValueError as error:
            if str(error) != 'IDA produced no complete, pinned C++ recovery records':
                raise
        with path.open('r+b') as stream:
            stream.seek(0, os.SEEK_END)
            size, boundary = stream.tell(), 0
            position = size
            while position:
                begin = max(0, position - 4096)
                stream.seek(begin)
                block = stream.read(position - begin)
                newline = block.rfind(b'\n')
                if newline >= 0:
                    boundary = begin + newline + 1
                    break
                position = begin
            if boundary < size:
                tail = path.with_name(path.name + '.uncommitted')
                stream.seek(boundary)
                with tail.open('xb') as evidence:
                    shutil.copyfileobj(stream, evidence)
                stream.truncate(boundary)
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(failure) + '\n')
    return str(tail) if tail else None


def preserve_unpacked_snapshot(copy, private_root, stamp):
    """Keep crash evidence outside the reusable IDB after its owned process exits."""
    copy, private_root = copy.resolve(), private_root.resolve()
    if copy.parent != private_root:
        raise ValueError('Private recovery IDB escaped its dedicated directory')
    sidecars = [copy.with_suffix(suffix) for suffix in ('.id0', '.id1', '.id2', '.nam', '.til')]
    sidecars = [path for path in sidecars if path.is_file()]
    if not sidecars:
        return None
    evidence = private_root / f'interrupted-{stamp}'
    evidence.mkdir()
    for path in sidecars:
        if path.resolve().parent != private_root:
            raise ValueError('Recovery sidecar escaped its dedicated directory')
        path.rename(evidence / path.name)
    return str(evidence)


def run(root):
    root = Path(root).resolve()
    config = json.loads((root / 'replay-project.local.json').read_text())
    settings = config.get('cpp_recovery', {})
    if not settings.get('enabled'):
        return
    ida = Path(settings['ida'])
    original = Path(settings['idb'])
    timeout = int(settings.get('function_timeout_seconds', 300))
    batch_limit = int(settings.get('batch_functions', 64))
    if timeout < 1 or batch_limit < 1:
        raise ValueError('C++ recovery timeout and batch size must be positive')
    directory = root / 'analysis' / 'cpp-flow'
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / 'worker.lock'
    # Kernel locks are released if the worker crashes; an orphaned marker
    # cannot permanently stop subsequent recovery.
    import msvcrt
    with lock_path.open('a+b') as lock:
        if lock.tell() == 0:
            lock.write(b'0')
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        try:
            # Cache each closed source IDB separately. A new baseline must
            # never inherit the older private database's decoding and types.
            if is_open(original):
                return
            original_stat = original.stat()
            key = hashlib.sha256(json.dumps([str(root), str(original.resolve()), original_stat.st_size,
                                             original_stat.st_mtime_ns]).encode()).hexdigest()[:16]
            private_root = Path(config.get('cache', directory)) / 'cpp-flow-private'
            private_root.mkdir(parents=True, exist_ok=True)
            copy = private_root / f'recovery-{key}.i64'
            snapshot_receipt = copy.with_suffix('.snapshot.json')
            if is_open(copy):
                return
            request = prepare(root, directory / 'pending-request.json', pending=True, limit=batch_limit)
            if not request['requests']:
                return
            current_stat = original.stat()
            if ((current_stat.st_size, current_stat.st_mtime_ns) !=
                    (original_stat.st_size, original_stat.st_mtime_ns) or
                    is_open(original)):
                return  # Retry from a consistent closed source after preparation.
            if not copy.is_file():
                before = original.stat()
                shutil.copy2(original, copy)
                source_hash, copy_hash = digest(original), digest(copy)
                after = original.stat()
                if ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or
                        source_hash != copy_hash or is_open(original)):
                    # The just-created copy is not adopted as a reusable IDB.
                    copy.rename(private_root / f'changed-source-{time.time_ns()}.i64')
                    raise ValueError('Source IDB changed or opened while taking the private snapshot')
                receipt = dict(source_idb=str(original.resolve()), source_idb_sha256=source_hash,
                               source_bytes=before.st_size, source_mtime_ns=before.st_mtime_ns,
                               initial_private_idb_sha256=copy_hash)
                temporary = snapshot_receipt.with_suffix('.json.tmp')
                temporary.write_text(json.dumps(receipt), encoding='utf-8')
                temporary.replace(snapshot_receipt)
            receipt = json.loads(snapshot_receipt.read_text(encoding='utf-8'))
            validate_snapshot_provenance(settings, request, receipt, original, original_stat)
            # A private IDB already open by a manual recovery pass must finish
            # before the incremental worker can adopt it.
            if is_open(copy):
                raise ValueError('Private IDB is currently open; recovery will retry later')
            stamp = time.time_ns()
            output = directory / f'{stamp}-result.jsonl'
            log = directory / f'{stamp}-ida.log'
            progress_path = directory / f'{stamp}-progress.jsonl'
            request['requests'] = request['requests'][:batch_limit]
            request['progress_path'] = str(progress_path)
            request['source_idb_sha256'] = receipt['source_idb_sha256']
            request['private_idb_input_sha256'] = digest(copy)
            (directory / 'pending-request.json').write_text(json.dumps(request), encoding='utf-8')
            script = root / 'tools' / 'ida_recover_cpp_flow.py'
            arguments = [str(ida), '-A', '-L' + str(log),
                         '-S' + f'"{script}" "{directory / "pending-request.json"}" "{output}"', str(copy)]
            # A recovery process must not auto-load the user's naming plugin:
            # its normal writeback worker can publish partially repaired code
            # from this disposable IDB into the canonical analysis database.
            # Naming inputs were already read from a consistent SQLite snapshot.
            profile = directory / 'ida-user-profile'
            profile.mkdir(exist_ok=True)
            environment = dict(os.environ, IDAUSR=str(profile))
            process = subprocess.Popen(arguments, cwd=root, creationflags=subprocess.CREATE_NO_WINDOW,
                                       env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            owners = {row['rva']: row for row in request['requests']}
            offset, observed, changed_at = 0, None, time.monotonic()
            timed_out = False
            try:
                while process.poll() is None:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
                    offset, progress = read_progress(progress_path, offset, owners)
                    if progress is not None:
                        observed, changed_at = progress, time.monotonic()
                    if process.poll() is None and time.monotonic() - changed_at >= timeout:
                        timed_out = True
                        process.kill()
                        process.wait()
                        break
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            # Capture the final committed progress line even on a fast exit.
            offset, progress = read_progress(progress_path, offset, owners)
            if progress is not None:
                observed = progress
            evidence = preserve_unpacked_snapshot(copy, private_root, stamp)
            message = (f'IDA recovery exceeded {timeout} seconds without progress' if timed_out else
                       f'IDA recovery exited {process.returncode} before committing this function')
            failure = interrupted_record(request, observed, message)
            output_summary, output_error, partial_evidence = None, None, None
            try:
                if failure:
                    partial_evidence = append_interrupted_record(output, request, failure)
                output_summary = committed_result_summary(output, request)
            except (OSError, ValueError) as error:
                output_error = str(error)
            (directory / f'{stamp}-attempt.json').write_text(json.dumps(dict(
                process_id=process.pid, exit_code=process.returncode, timed_out=timed_out,
                last_observed_function=observed, interrupted_snapshot=evidence,
                image_sha256=request['image_sha256'], source_idb=str(original),
                source_idb_sha256=request['source_idb_sha256'],
                private_idb_input_sha256=request['private_idb_input_sha256'],
                private_idb=str(copy), log=str(log), output=str(output),
                output_summary=output_summary, output_validation_error=output_error,
                uncommitted_tail_evidence=partial_evidence), indent=2), encoding='utf-8')
            # IDA can return 1 after successfully saving and exporting. The
            # actual pinned records, not that exit code, determine readiness.
            if output_error:
                raise ValueError(f'{output_error} (IDA exit {process.returncode}); see {log}')
            recovery = FlowRecovery(root, request['image_sha256'])
            recovery.sync()
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    run(args.root)
